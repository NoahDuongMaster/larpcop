mod config;
mod context;
mod files;
mod hook;
mod install;
mod report;
mod rules;
mod shell;
mod sync;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use context::Ctx;
use files::Scope;
use report::Format;
use std::path::PathBuf;
use std::process::ExitCode;

/// Enforces coding rules on any agent and any stack: one binary, used by
/// git hooks, CI and (optionally) agent-specific hooks.
#[derive(Parser)]
#[command(name = "agentkit", version)]
struct Cli {
    #[command(flatten)]
    global: Global,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args)]
struct Global {
    /// Standards enforced before the repo config (path or git URL[#ref]); a repo cannot opt out of them.
    #[arg(long, global = true, env = "AGENTKIT_EXTENDS", value_delimiter = ',')]
    extends: Vec<String>,
    /// Re-fetch git-hosted standards instead of using the cache.
    #[arg(long, global = true)]
    refresh: bool,
    /// Run as if started in DIR.
    #[arg(short = 'C', long = "dir", global = true, default_value = ".")]
    dir: PathBuf,
}

#[derive(Subcommand)]
enum Cmd {
    /// Check files against the rules. Exit 1 on any error-level violation, 3 on failure.
    Check {
        /// Files or directories (default: the whole project).
        paths: Vec<PathBuf>,
        /// Check the staged content (pre-commit).
        #[arg(long, conflicts_with_all = ["changed", "since", "paths"])]
        staged: bool,
        /// Check uncommitted and untracked files.
        #[arg(long, conflicts_with_all = ["since", "paths"])]
        changed: bool,
        /// Check files changed since REF (e.g. origin/main) — for pull requests.
        #[arg(long, value_name = "REF", conflicts_with = "paths")]
        since: Option<String>,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// List the effective rules and where they come from.
    Rules,
    /// Generate AGENTS.md, CLAUDE.md and agent hook settings from the rules.
    Sync {
        /// Do not write; exit 1 if any generated file is out of date (for CI).
        #[arg(long)]
        check: bool,
    },
    /// Install the git pre-commit hook.
    Install {
        /// Overwrite an existing pre-commit hook not managed by agentkit.
        #[arg(long)]
        force: bool,
    },
    /// Entry point for agent hook systems (reads the event from stdin).
    Hook {
        #[arg(value_enum)]
        agent: hook::Agent,
    },
}

fn run(cli: Cli) -> Result<u8> {
    let g = cli.global;
    let ctx = || Ctx::new(&g.dir, g.extends.clone(), g.refresh);
    match cli.cmd {
        Cmd::Check {
            paths,
            staged,
            changed,
            since,
            format,
        } => {
            let scope = match (staged, changed, since) {
                (true, _, _) => Scope::Staged,
                (_, true, _) => Scope::Changed,
                (_, _, Some(base)) => Scope::Since(base),
                _ if paths.is_empty() => Scope::All,
                _ => Scope::Paths(paths),
            };
            let outcome = ctx()?.check(&scope)?;
            print!("{}", report::render(&outcome, format));
            Ok(u8::from(outcome.errors() > 0))
        }
        Cmd::Rules => {
            let (cfg, engine) = ctx()?.load()?;
            println!(
                "root: {}\nsources: {}\n",
                cfg.root.display(),
                cfg.sources.join(" → ")
            );
            for r in engine.rules() {
                let lock = cfg
                    .locked
                    .get(&r.id)
                    .map_or(String::new(), |by| format!("  [locked by {by}]"));
                println!(
                    "{:<24} {:<7} {:<22} {}{lock}",
                    r.id,
                    r.level.as_str(),
                    r.scope,
                    r.message
                );
            }
            Ok(0)
        }
        Cmd::Sync { check } => {
            let (cfg, engine) = ctx()?.load()?;
            let changed = sync::run(&cfg, &engine.rules(), check)?;
            for path in &changed {
                println!(
                    "{} {}",
                    if check { "out of date:" } else { "updated:" },
                    path.display()
                );
            }
            if check && !changed.is_empty() {
                eprintln!(
                    "agentkit: generated files are stale; run `agentkit sync` and commit the result."
                );
                return Ok(1);
            }
            if changed.is_empty() {
                println!("agentkit: generated files are up to date.");
            }
            Ok(0)
        }
        Cmd::Install { force } => {
            let path = install::install(&ctx()?.root, force)?;
            println!("agentkit: installed {}", path.display());
            Ok(0)
        }
        Cmd::Hook { agent } => {
            let code = hook::run(agent, g.extends, g.refresh)?;
            Ok(u8::try_from(code).unwrap_or(1))
        }
    }
}

/// Exit 3 on internal failure: distinct from 1 (violations) and from 2, which
/// agent hook protocols reserve for "block and show the model".
fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("agentkit: error: {err:#}");
            ExitCode::from(3)
        }
    }
}

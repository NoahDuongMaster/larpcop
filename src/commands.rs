//! Command handlers. Exit codes: 0 ok, 1 violations/failures, 3 internal error.

use crate::baseline::{self, Baseline};
use crate::cli::{Cli, Cmd};
use crate::context::Ctx;
use crate::files::{self, Scope};
use crate::report::{self, Format};
use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use std::fs;
use std::path::{Path, PathBuf};

pub fn run(cli: Cli) -> Result<u8> {
    let g = cli.global;
    // One pool for the whole run: `--jobs` keeps a laptop usable while a
    // whole repository is checked.
    if let Some(jobs) = g.jobs {
        rayon::ThreadPoolBuilder::new()
            .num_threads(jobs.max(1))
            .build_global()
            .with_context(|| format!("applying --jobs {jobs}"))?;
    }
    let ctx = || Ctx::new(&g.dir, g.extends.clone(), g.refresh);
    match cli.cmd {
        Cmd::Check {
            scope,
            format,
            output,
        } => check(&ctx()?, &scope.scope(), format, &output),
        Cmd::Fix { scope, dry_run } => fix(&ctx()?, scope.scope(), dry_run),
        Cmd::Baseline { prune } => baseline(&ctx()?, prune),
        Cmd::Test {
            standards,
            require_all,
        } => test(&ctx, standards, require_all),
        Cmd::Metrics { scope, top, json } => metrics(&ctx()?, &scope.scope(), top, json),
        Cmd::Review {
            scope,
            format,
            no_cache,
        } => review(&ctx()?, &scope.scope(), format, no_cache),
        Cmd::Learn {
            instruction,
            reviews,
            out,
            attempts,
        } => crate::ai::learn::run(&ctx()?, instruction, reviews, out, attempts),
        Cmd::Dashboard { org, out, json } => dashboard(&ctx()?, org.as_deref(), &out, json),
        Cmd::Rules { for_path, json } => crate::inspect::rules(&ctx()?, for_path, json),
        Cmd::Stats { scope, top, json } => crate::inspect::stats(&ctx()?, scope.scope(), top, json),
        Cmd::Sync {
            check,
            managed,
            out,
            platform,
            bin,
        } => match (managed, out) {
            (true, Some(out)) => managed_policies(&out, platform, &bin, &g.extends),
            _ => sync(&ctx()?, check),
        },
        Cmd::Install { force } => {
            let path = crate::install::install(&ctx()?.root, force)?;
            println!("larpcop: installed {}", path.display());
            Ok(0)
        }
        Cmd::Mcp => {
            crate::mcp::serve(g.dir, g.extends)?;
            Ok(0)
        }
        Cmd::Lsp => {
            crate::lsp::serve(g.dir, g.extends)?;
            Ok(0)
        }
        Cmd::Org { cmd } => org(cmd),
        Cmd::Hook { agent } => {
            let code = crate::hook::run(agent, g.extends, g.refresh)?;
            Ok(u8::try_from(code).unwrap_or(1))
        }
    }
}

fn check(ctx: &Ctx, scope: &Scope, format: Format, output: &[String]) -> Result<u8> {
    let outcome = ctx.check(scope)?;
    for spec in output {
        let (fmt, path) = spec
            .split_once('=')
            .with_context(|| format!("--output expects FORMAT=FILE, got `{spec}`"))?;
        let fmt =
            Format::from_str(fmt, true).map_err(|e| anyhow::anyhow!("--output {spec}: {e}"))?;
        fs::write(path, report::render(&outcome, fmt)?)
            .with_context(|| format!("writing {path}"))?;
    }
    print!("{}", report::render(&outcome, format)?);
    Ok(u8::from(outcome.errors() > 0))
}

fn baseline(ctx: &Ctx, prune: bool) -> Result<u8> {
    let (cfg, engine) = ctx.load()?;
    let now = ctx.raw(&cfg, &engine, &Scope::All)?.0.violations;
    let next = match (prune, Baseline::load(&cfg.root, false)?) {
        (true, Some(known)) => known.prune(&now),
        (true, None) => bail!("no {} to prune", baseline::FILE),
        (false, _) => Baseline::of(&now),
    };
    next.write(&cfg.root)?;
    println!(
        "larpcop: {} now holds {} known violation(s).",
        baseline::FILE,
        next.len()
    );
    Ok(0)
}

fn test(
    ctx: &impl Fn() -> Result<Ctx>,
    standards: Option<PathBuf>,
    require_all: bool,
) -> Result<u8> {
    let defined = match standards {
        Some(dir) => crate::config::rules_of(&dir)?,
        None => {
            let ctx = ctx()?;
            let cfg = ctx.config()?;
            crate::rules::testing::Defined {
                rule_dirs: cfg.rule_dirs.clone(),
                taint: cfg.taint.clone(),
                text: cfg.text.clone(),
            }
        }
    };
    let report = crate::rules::testing::run(&defined)?;
    print!("{}", report.text);
    if !report.untested.is_empty() {
        println!("untested rule(s): {}", report.untested.join(", "));
    }
    let failed = report.failures > 0 || (require_all && !report.untested.is_empty());
    println!(
        "larpcop: {}",
        if failed {
            "✗ rule tests failed"
        } else {
            "✓ rule tests passed"
        }
    );
    Ok(u8::from(failed))
}

fn metrics(ctx: &Ctx, scope: &Scope, top: usize, json: bool) -> Result<u8> {
    let cfg = ctx.config()?;
    let exclude = files::globset(&cfg.exclude)?;
    let sources = files::collect(&cfg.root, scope, &exclude)?;
    let summary = crate::rules::metrics::summarize(&sources, top);
    if json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        print!("{}", crate::rules::metrics::render(&summary));
    }
    Ok(0)
}

fn review(ctx: &Ctx, scope: &Scope, format: Format, no_cache: bool) -> Result<u8> {
    let (files, violations) = crate::ai::review::review(ctx.config()?, scope, !no_cache)?;
    let outcome = crate::context::Outcome {
        files,
        violations,
        ..Default::default()
    };
    print!("{}", report::render(&outcome, format)?);
    Ok(0)
}

fn dashboard(ctx: &Ctx, org: Option<&str>, out: &Path, json: bool) -> Result<u8> {
    let d = crate::dashboard::build(ctx, org)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&d)?);
    } else {
        fs::write(out, crate::dashboard::render(&d))
            .with_context(|| format!("writing {}", out.display()))?;
        println!("larpcop: wrote {}", out.display());
    }
    Ok(0)
}

fn managed_policies(
    out: &Path,
    platform: Option<crate::sync::managed::Platform>,
    bin: &str,
    extends: &[String],
) -> Result<u8> {
    let opts = crate::sync::managed::Options {
        out,
        platform: platform.unwrap_or_else(crate::sync::managed::Platform::current),
        bin,
        extends,
    };
    for path in crate::sync::managed::write(&opts)? {
        println!("wrote {}", path.display());
    }
    Ok(0)
}

fn org(cmd: crate::cli::OrgCmd) -> Result<u8> {
    use crate::cli::OrgCmd;
    match cmd {
        OrgCmd::Status {
            owner,
            standards,
            json,
        } => {
            let rows = crate::org::status(&owner)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                print!("{}", crate::org::render(&rows, standards.as_deref()));
            }
            Ok(u8::from(rows.iter().any(|r| !r.enforced())))
        }
        OrgCmd::Setup {
            owner,
            standards,
            repos,
            workflow_ref,
            dry_run,
        } => {
            let plan = crate::org::Plan {
                owner: &owner,
                standards: &standards,
                only: &repos,
                workflow_ref: &workflow_ref,
                dry_run,
            };
            for line in crate::org::setup(&plan)? {
                println!("{line}");
            }
            Ok(0)
        }
    }
}

fn fix(ctx: &Ctx, scope: Scope, dry_run: bool) -> Result<u8> {
    if matches!(scope, Scope::Staged) {
        bail!("`fix --staged` would edit the worktree, not the index; use --changed");
    }
    let (cfg, engine) = ctx.load()?;
    let exclude = files::globset(&cfg.exclude)?;
    let sources = files::collect(&cfg.root, &scope, &exclude)?;
    let fixed = engine.fix(&sources);
    for (rel, text, n) in &fixed {
        if !dry_run {
            fs::write(cfg.root.join(rel), text).with_context(|| format!("writing {rel}"))?;
        }
        println!(
            "{} {rel} ({n} fix(es))",
            if dry_run { "would fix" } else { "fixed" }
        );
    }
    if dry_run {
        return Ok(u8::from(!fixed.is_empty()));
    }
    // The files changed, so they are read again; the rules are not parsed again.
    let outcome = ctx.check(&scope)?;
    print!("{}", report::render(&outcome, Format::Text)?);
    Ok(u8::from(outcome.errors() > 0))
}

fn sync(ctx: &Ctx, check: bool) -> Result<u8> {
    let (cfg, engine) = ctx.load()?;
    let changed = crate::sync::run(&cfg, &engine.rules(), check)?;
    for path in &changed {
        let verb = if check { "out of date:" } else { "updated:" };
        println!("{verb} {}", path.display());
    }
    if check && !changed.is_empty() {
        eprintln!("larpcop: generated files are stale; run `larpcop sync` and commit the result.");
        return Ok(1);
    }
    if changed.is_empty() {
        println!("larpcop: generated files are up to date.");
    }
    Ok(0)
}

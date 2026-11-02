//! Command-line interface definition.

use crate::files::Scope;
use crate::report::Format;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

/// Enforces coding rules on any agent and any stack: one binary, used by
/// git hooks, CI and (optionally) agent-specific hooks.
#[derive(Parser)]
#[command(name = "larpcop", version)]
pub struct Cli {
    #[command(flatten)]
    pub global: Global,
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Args)]
pub struct Global {
    /// Standards enforced before the repo config (path or git URL[#ref]); a repo cannot opt out of them.
    #[arg(long, global = true, env = "LARPCOP_EXTENDS", value_delimiter = ',')]
    pub extends: Vec<String>,
    /// Re-fetch git-hosted standards instead of using the cache.
    #[arg(long, global = true)]
    pub refresh: bool,
    /// Run as if started in DIR.
    #[arg(short = 'C', long = "dir", global = true, default_value = ".")]
    pub dir: PathBuf,
    /// Threads to check files with (default: every core). Lower it to keep the
    /// machine responsive: `LARPCOP_JOBS=2 larpcop check`.
    #[arg(long, global = true, env = "LARPCOP_JOBS", value_name = "N")]
    pub jobs: Option<usize>,
}

/// Which files a command covers.
#[derive(Args)]
pub struct ScopeArgs {
    /// Files or directories (default: the whole project).
    pub paths: Vec<PathBuf>,
    /// The staged content (pre-commit).
    #[arg(long, conflicts_with_all = ["changed", "since", "paths"])]
    pub staged: bool,
    /// Uncommitted and untracked files.
    #[arg(long, conflicts_with_all = ["since", "paths"])]
    pub changed: bool,
    /// Files changed since REF (e.g. origin/main) — for pull requests.
    #[arg(long, value_name = "REF", conflicts_with = "paths")]
    pub since: Option<String>,
}

impl ScopeArgs {
    pub fn scope(self) -> Scope {
        match (self.staged, self.changed, self.since) {
            (true, _, _) => Scope::Staged,
            (_, true, _) => Scope::Changed,
            (_, _, Some(base)) => Scope::Since(base),
            _ if self.paths.is_empty() => Scope::All,
            _ => Scope::Paths(self.paths),
        }
    }
}

#[derive(Subcommand)]
pub enum OrgCmd {
    /// Which repositories have the config and the CI gate, and on which standards.
    Status {
        owner: String,
        /// Standards every repository should extend (flags missing and outdated pins).
        #[arg(long)]
        standards: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Open one pull request per repository adding the config, the CI gate and the agent files.
    Setup {
        owner: String,
        /// Standards to enforce (git URL#tag).
        #[arg(long)]
        standards: String,
        /// Only these repositories (default: every non-archived, non-fork one).
        #[arg(long, value_delimiter = ',')]
        repos: Vec<String>,
        /// Tag of larpcop's reusable enforce workflow.
        #[arg(long, default_value = concat!("v", env!("CARGO_PKG_VERSION")))]
        workflow_ref: String,
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Check files against the rules. Exit 1 on any error-level violation, 3 on failure.
    Check {
        #[command(flatten)]
        scope: ScopeArgs,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
        /// Also write the report to FILE in this format (e.g. SARIF for code scanning).
        #[arg(long, value_name = "FORMAT=FILE")]
        output: Vec<String>,
    },
    /// Apply the `fix:` of every matching rule, then report what is left.
    Fix {
        #[command(flatten)]
        scope: ScopeArgs,
        /// Show which files would change without writing them.
        #[arg(long)]
        dry_run: bool,
    },
    /// Record today's violations as known, so a rule can be adopted on legacy code
    /// while anything new still fails. Reserved for humans.
    Baseline {
        /// Only drop entries that were fixed; never add new ones.
        #[arg(long)]
        prune: bool,
    },
    /// Run the rule fixtures in `rule-tests/` (valid, invalid and fixed cases).
    Test {
        /// A standards directory to test on its own (default: this project's rules).
        standards: Option<PathBuf>,
        /// Fail when a rule has no fixture.
        #[arg(long)]
        require_all: bool,
    },
    /// Size and cyclomatic complexity per function, most complex first.
    Metrics {
        #[command(flatten)]
        scope: ScopeArgs,
        /// How many functions to list.
        #[arg(long, default_value_t = 20)]
        top: usize,
        #[arg(long)]
        json: bool,
    },
    /// Judge the `llm` rules with a model. Findings are warnings only; on a diff,
    /// only changed lines are reported. Answers are cached per file content.
    Review {
        #[command(flatten)]
        scope: ScopeArgs,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
        /// Ask the model again instead of reusing cached answers.
        #[arg(long)]
        no_cache: bool,
    },
    /// Turn a standard written in words, or recurring review comments, into
    /// ast-grep rules with tests. Only rules that pass their tests are written.
    Learn {
        /// The standard, e.g. "never import from lodash; use native methods".
        #[arg(required_unless_present = "reviews")]
        instruction: Option<String>,
        /// Learn from the N latest pull request review comments (GitHub, via `gh`).
        #[arg(long, value_name = "N")]
        reviews: Option<usize>,
        /// Where to write rules/ and rule-tests/ (default: the repo's first rule dir's parent, or `.larpcop`).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Rounds of feedback on rules that fail their tests.
        #[arg(long, default_value_t = 3)]
        attempts: usize,
    },
    /// One HTML page: open violations per rule, baseline debt over time,
    /// complexity hotspots and, with --org, which repositories run the gate.
    Dashboard {
        /// Also list a GitHub user's or organization's repositories (via `gh`).
        #[arg(long, value_name = "OWNER")]
        org: Option<String>,
        #[arg(long, default_value = "larpcop-dashboard.html")]
        out: PathBuf,
        /// Print the data as JSON instead.
        #[arg(long)]
        json: bool,
    },
    /// List the effective rules and where they come from.
    Rules {
        /// Only the rules that apply to this file (its language, `files:` and
        /// `exclude:` globs) — what an agent needs for the file it is editing.
        #[arg(long = "for", value_name = "PATH")]
        for_path: Option<std::path::PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Which rules fire here, which caught nothing, which apply to no file.
    Stats {
        #[command(flatten)]
        scope: ScopeArgs,
        /// How many rules of the table to list.
        #[arg(long, default_value_t = 20)]
        top: usize,
        #[arg(long)]
        json: bool,
    },
    /// Generate AGENTS.md, CLAUDE.md and agent hook settings from the rules.
    Sync {
        /// Do not write; exit 1 if any generated file is out of date (for CI).
        #[arg(long, conflicts_with = "managed")]
        check: bool,
        /// Write machine-wide hook policies (for MDM) that force `--extends` everywhere.
        #[arg(long, requires = "out")]
        managed: bool,
        /// Root to write managed policies under (`/` installs them; a directory packages them).
        #[arg(long, value_name = "DIR")]
        out: Option<PathBuf>,
        /// Target OS of the managed machines.
        #[arg(long, value_enum)]
        platform: Option<crate::sync::managed::Platform>,
        /// Absolute path of larpcop on the managed machines.
        #[arg(long, default_value = "/usr/local/bin/larpcop")]
        bin: String,
    },
    /// Install the git pre-commit hook.
    Install {
        /// Overwrite an existing pre-commit hook not managed by larpcop.
        #[arg(long)]
        force: bool,
    },
    /// MCP server on stdio: rules for a file, check content before writing, fix.
    Mcp,
    /// Language server on stdio: diagnostics while typing, fixes as code actions.
    Lsp,
    /// Roll the standards out across a GitHub user's or organization's repositories.
    Org {
        #[command(subcommand)]
        cmd: OrgCmd,
    },
    /// Entry point for agent hook systems (reads the event from stdin).
    Hook {
        #[arg(value_enum)]
        agent: crate::hook::Agent,
    },
}

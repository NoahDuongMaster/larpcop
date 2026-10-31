//! Agent-agnostic detection of enforcement bypass attempts.
//! Adapters for any agent that exposes pre-tool hooks reuse these checks.
//!
//! Shell commands go through tree-sitter-bash (`shell_ast`): `cat cfg 2>/dev/null`
//! stays allowed while `bash -c 'rm .agentkit.yaml'` or `--no-ver""ify` do not.

use crate::shell_ast::{self, Command};
use std::path::{Path, PathBuf};

const NO_VERIFY: &str = "skipping git hooks (`--no-verify` / `git commit -n`) is not allowed.";
const HOOKS_PATH: &str = "changing git's hooks path is not allowed.";
const HOOK_RUNNERS: &str = "disabling hook runners is not allowed.";
const BASELINE_CMD: &str =
    "updating the baseline is reserved for humans: fix the violations instead.";

/// Edited in place or overwritten by these programs (any file argument).
const MUTATORS: [&str; 8] = [
    "rm", "mv", "tee", "truncate", "chmod", "chown", "unlink", "shred",
];
/// Write only their last argument.
const COPIERS: [&str; 4] = ["cp", "ln", "install", "rsync"];

/// Reason a path must not be changed by an agent, if any.
fn protected(path: &str) -> Option<&'static str> {
    let p = path.replace('\\', "/");
    let name = p.rsplit('/').next().unwrap_or(&p);
    if p.contains(".git/hooks") {
        return Some("modifying git hooks is not allowed.");
    }
    if name == ".agentkit.yaml" {
        return Some("changing .agentkit.yaml is reserved for humans.");
    }
    if name == crate::baseline::FILE {
        return Some("changing the baseline is reserved for humans: fix the violations instead.");
    }
    is_agent_config(&format!("/{p}"), name)
        .then_some("changing agent hook settings is reserved for humans.")
}

/// Hook configs `agentkit sync` generates: removing them would switch enforcement off.
fn is_agent_config(path: &str, name: &str) -> bool {
    let json = name.ends_with(".json");
    (path.contains("/.claude/") && name.starts_with("settings") && json)
        || (path.contains("/.cursor/") && name == "hooks.json")
        || (path.contains("/.codex/") && matches!(name, "hooks.json" | "config.toml"))
        || (path.contains("/.gemini/") && name == "settings.json")
        || (path.contains("/.github/hooks/") && json)
        || (path.contains("/.kiro/") && (name.ends_with(".kiro.hook") || json))
        || (path.contains("/.factory/") && matches!(name, "hooks.json" | "settings.json"))
        || (path.contains("/.windsurf/") && name == "hooks.json")
}

pub fn bash_bypass(command: &str) -> Option<String> {
    // Belt and braces: `$(echo --no-verify)` is opaque to the parser.
    if command.contains("--no-verify") {
        return Some(NO_VERIFY.into());
    }
    let script = shell_ast::parse(command);
    for (name, value) in script.assignments() {
        let off = matches!(value.as_str(), "0" | "false");
        if (matches!(name.as_str(), "HUSKY" | "LEFTHOOK") && off) || name == "SKIP" {
            return Some(HOOK_RUNNERS.into());
        }
    }
    if let Some(reason) = script.written.iter().find_map(|t| protected(t)) {
        return Some(reason.into());
    }
    script
        .commands
        .iter()
        .find_map(command_bypass)
        .map(Into::into)
}

fn command_bypass(cmd: &Command) -> Option<&'static str> {
    let (name, args) = cmd.words.split_first()?;
    let name = name.rsplit('/').next().unwrap_or(name);
    match name {
        "git" => git_bypass(args),
        "agentkit"
            if args.first().is_some_and(|a| a == "baseline")
                && !args.iter().any(|a| a == "--prune") =>
        {
            Some(BASELINE_CMD)
        }
        _ if MUTATORS.contains(&name) => args.iter().find_map(|a| protected(a)),
        _ if COPIERS.contains(&name) => args.last().and_then(|a| protected(a)),
        "sed" | "perl" if args.iter().any(|a| in_place(a)) => {
            args.iter().find_map(|a| protected(a))
        }
        "dd" => args
            .iter()
            .find_map(|a| a.strip_prefix("of=").and_then(protected)),
        _ => None,
    }
}

fn in_place(arg: &str) -> bool {
    arg.starts_with("--in-place")
        || (arg.starts_with('-') && !arg.starts_with("--") && arg.contains('i'))
}

fn git_bypass(args: &[String]) -> Option<&'static str> {
    // Global options come before the subcommand: `git -C dir -c k=v commit …`.
    let mut i = 0;
    while let Some(a) = args.get(i) {
        match a.as_str() {
            "-c" | "-C" | "--git-dir" | "--work-tree" => {
                if a == "-c"
                    && args
                        .get(i + 1)
                        .is_some_and(|kv| kv.contains("core.hooksPath"))
                {
                    return Some(HOOKS_PATH);
                }
                i += 2;
            }
            _ if a.starts_with('-') => i += 1,
            _ => break,
        }
    }
    let rest = &args[(i + 1).min(args.len())..];
    // git accepts unambiguous prefixes: `--no-veri` is `--no-verify`.
    if rest
        .iter()
        .any(|a| a.starts_with("--no-veri") && "--no-verify".starts_with(a.as_str()))
    {
        return Some(NO_VERIFY);
    }
    match args.get(i)?.as_str() {
        "commit" => rest
            .iter()
            .any(|a| a.starts_with('-') && !a.starts_with("--") && a.contains('n'))
            .then_some(NO_VERIFY),
        "config" => {
            let reads = rest
                .iter()
                .any(|a| matches!(a.as_str(), "--get" | "--get-all" | "--list" | "-l"));
            let names_it = rest
                .iter()
                .any(|a| a.eq_ignore_ascii_case("core.hooksPath"));
            let positional = rest.iter().filter(|a| !a.starts_with('-')).count();
            let unsets = rest.iter().any(|a| a.starts_with("--unset"));
            (names_it && !reads && (positional >= 2 || unsets)).then_some(HOOKS_PATH)
        }
        _ => None,
    }
}

/// Files an agent must not edit: the config, the hooks that enforce it, and rule files.
pub fn protected_path(path: &Path, rule_dirs: &[PathBuf]) -> Option<String> {
    let path = normalize(path);
    let text = path.to_string_lossy().replace('\\', "/");
    if let Some(reason) = protected(&text) {
        return Some(reason.into());
    }
    if rule_dirs
        .iter()
        .map(|d| normalize(d))
        .any(|d| path.starts_with(&d))
    {
        return Some(format!(
            "{} is an enforced rule file; changing it is reserved for humans.",
            path.display()
        ));
    }
    None
}

/// Canonical form even for files that do not exist yet (canonicalizes the parent).
fn normalize(path: &Path) -> PathBuf {
    if let Ok(p) = dunce::canonicalize(path) {
        return p;
    }
    match (
        path.parent().and_then(|p| dunce::canonicalize(p).ok()),
        path.file_name(),
    ) {
        (Some(parent), Some(name)) => parent.join(name),
        _ => path.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_bypasses() {
        for cmd in [
            "git commit --no-verify -m x",
            "git commit -nm 'x'",
            "git -c core.hooksPath=/dev/null commit -m x",
            "git config core.hooksPath /dev/null",
            "git config --unset core.hooksPath",
            "HUSKY=0 git commit -m x",
            "export HUSKY=0 && git commit -m x",
            "SKIP=lint git commit -m x",
            "rm .git/hooks/pre-commit",
            "sed -i 's/error/off/' .agentkit.yaml",
            "echo 'disable: [max-lines]' >> .agentkit.yaml",
            "cat x > ./.agentkit.yaml",
            "echo '{}' > .claude/settings.local.json",
            "mv /tmp/x .claude/settings.json",
            "rm .cursor/hooks.json",
            "echo '{}' > .codex/hooks.json",
            "sed -i 's/agentkit/true/' .gemini/settings.json",
            "cp /tmp/empty.json .github/hooks/agentkit.json",
            // Structural cases the old regexes missed:
            "bash -c 'rm -f .agentkit.yaml'",
            "sudo env SKIP=all git commit -m x",
            "git commit -m x --no-ver\"\"ify",
            "git push --no-veri",
            "echo x | tee -a .git/hooks/pre-push",
            "agentkit baseline",
            "echo '[]' > .agentkit-baseline.json",
        ] {
            assert!(bash_bypass(cmd).is_some(), "should block: {cmd}");
        }
    }

    #[test]
    fn allows_normal_commands() {
        for cmd in [
            "git commit -m 'add new feature'",
            "git commit --amend -m x",
            "cat .agentkit.yaml",
            // regression: stderr redirect next to a config read was blocked
            "git ls-files && cat .agentkit.yaml 2>/dev/null; ls -la src 2>/dev/null",
            "cat .claude/settings.json > /tmp/backup.json",
            "ls .git/hooks",
            "agentkit check --changed",
            "npm test",
            // Precision the parser adds over the old regexes:
            "git config --get core.hooksPath",
            "cp .agentkit.yaml /tmp/agentkit.yaml.bak",
            "echo 'never rm .agentkit.yaml' > notes.txt",
            "git commit -m 'run npm install'",
            "grep -rn HUSKY=0 docs/",
            "agentkit baseline --prune",
        ] {
            assert!(bash_bypass(cmd).is_none(), "should allow: {cmd}");
        }
    }
}

//! Agent-agnostic detection of enforcement bypass attempts.
//! Adapters for any agent that exposes pre-tool hooks reuse these checks.

use regex::Regex;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

struct Pattern {
    re: Regex,
    reason: &'static str,
}

fn pattern(re: &str, reason: &'static str) -> Pattern {
    Pattern {
        re: Regex::new(re).expect("static regex"),
        reason,
    }
}

/// A redirect into `target`, or a mutating command taking `target` as an argument
/// (same simple command). Reads such as `cat cfg 2>/dev/null` stay allowed.
fn writes_to(target: &str) -> String {
    let file = format!(r#"["']?[^\s;&|]*{target}"#);
    let mutators = r"\b(sed\s+-\w*i|perl\s+-\w*i|rm|mv|cp|tee|truncate|chmod|ln)\b";
    format!(r"(>{{1,2}}\s*{file})|({mutators}[^;&|\n]*{target})")
}

static BASH_RULES: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    vec![
        pattern(
            r"--no-verify\b",
            "skipping git hooks (`--no-verify`) is not allowed.",
        ),
        pattern(
            r"\bgit\b[^;&|\n]*\bcommit\b[^;&|\n]*\s-[A-Za-z]*n[A-Za-z]*\b",
            "skipping git hooks (`git commit -n`) is not allowed.",
        ),
        pattern(
            r"core\.hooksPath",
            "changing git's hooks path is not allowed.",
        ),
        pattern(
            r"\b(HUSKY|LEFTHOOK)=0\b|\bSKIP=",
            "disabling hook runners is not allowed.",
        ),
        pattern(
            &writes_to(r"\.git/hooks"),
            "modifying git hooks is not allowed.",
        ),
        pattern(
            &writes_to(r"\.agentkit\.yaml"),
            "changing .agentkit.yaml is reserved for humans.",
        ),
        pattern(
            &writes_to(AGENT_CONFIG_RE),
            "changing agent hook settings is reserved for humans.",
        ),
    ]
});

/// Hook configs `agentkit sync` generates: removing them would switch enforcement off.
const AGENT_CONFIG_RE: &str = r"\.(claude/settings[\w.-]*\.json|cursor/hooks\.json|codex/(hooks\.json|config\.toml)|gemini/settings\.json)";

fn is_agent_config(text: &str, name: &str) -> bool {
    (text.contains("/.claude/") && name.starts_with("settings") && name.ends_with(".json"))
        || (text.contains("/.cursor/") && name == "hooks.json")
        || (text.contains("/.codex/") && matches!(name, "hooks.json" | "config.toml"))
        || (text.contains("/.gemini/") && name == "settings.json")
}

pub fn bash_bypass(command: &str) -> Option<String> {
    BASH_RULES
        .iter()
        .find(|p| p.re.is_match(command))
        .map(|p| p.reason.to_string())
}

/// Files an agent must not edit: the config, the hooks that enforce it, and rule files.
pub fn protected_path(path: &Path, rule_dirs: &[PathBuf]) -> Option<String> {
    let path = normalize(path);
    let text = path.to_string_lossy().replace('\\', "/");
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if name == ".agentkit.yaml" {
        return Some("changing .agentkit.yaml is reserved for humans.".into());
    }
    if text.contains("/.git/hooks/") {
        return Some("modifying git hooks is not allowed.".into());
    }
    if is_agent_config(&text, &name) {
        return Some("changing agent hook settings is reserved for humans.".into());
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
            "HUSKY=0 git commit -m x",
            "rm .git/hooks/pre-commit",
            "sed -i 's/error/off/' .agentkit.yaml",
            "echo 'disable: [max-lines]' >> .agentkit.yaml",
            "cat x > ./.agentkit.yaml",
            "echo '{}' > .claude/settings.local.json",
            "mv /tmp/x .claude/settings.json",
            "rm .cursor/hooks.json",
            "echo '{}' > .codex/hooks.json",
            "sed -i 's/agentkit/true/' .gemini/settings.json",
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
        ] {
            assert!(bash_bypass(cmd).is_none(), "should allow: {cmd}");
        }
    }
}

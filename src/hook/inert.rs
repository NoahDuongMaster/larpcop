//! Commands that cannot run a project's dependencies: allowed even while a
//! lockfile holds versions that failed the dependency checks. Anything not
//! listed counts as running code (deny by default).

use crate::shell_ast::{Command, Script};

/// Programs that only read, move or fetch files.
const INERT: &[&str] = &[
    "git", "gh", "ls", "cat", "head", "tail", "less", "more", "grep", "egrep", "fgrep", "rg", "ag",
    "find", "fd", "wc", "sort", "uniq", "diff", "cmp", "comm", "echo", "printf", "pwd", "cd",
    "pushd", "popd", "mkdir", "rmdir", "rm", "mv", "cp", "ln", "touch", "chmod", "sed", "awk",
    "jq", "yq", "tree", "file", "stat", "which", "type", "true", "false", "test", "[", "sleep",
    "date", "basename", "dirname", "realpath", "readlink", "tr", "cut", "paste", "tee", "xxd",
    "od", "du", "df", "whoami", "id", "uname", "hostname", "printenv", "tar", "zip", "unzip",
    "gzip", "gunzip", "curl", "wget", "open", "larpcop", "exit", "export", "set", "unset",
];

/// True if any command in the script may execute project or dependency code.
pub fn runs_code(script: &Script) -> bool {
    script.commands.iter().any(|c| !inert(c))
}

fn inert(c: &Command) -> bool {
    let words: Vec<&str> = c.words.iter().map(String::as_str).collect();
    let Some(program) = words.first().map(|p| p.rsplit('/').next().unwrap_or(p)) else {
        return true; // bare assignments
    };
    let has = |flag: &str| {
        words
            .iter()
            .any(|w| *w == flag || w.starts_with(&format!("{flag}=")))
    };
    let sub = words.get(1).copied().unwrap_or("");
    match program {
        p if INERT.contains(&p) => true,
        "npm" | "pnpm" | "yarn" | "bun" => match sub {
            "view" | "info" | "show" | "ls" | "list" | "outdated" | "why" | "explain" | "audit"
            | "search" | "uninstall" | "remove" | "rm" | "un" | "pm" | "--version" | "-v" => true,
            "config" => words.get(2).is_some_and(|s| matches!(*s, "get" | "list")),
            "install" | "i" | "ci" | "add" | "" => {
                has("--ignore-scripts")
                    || has("--package-lock-only")
                    || has("--lockfile-only")
                    || has("--mode")
            }
            _ => false,
        },
        "cargo" => matches!(
            sub,
            "add"
                | "rm"
                | "remove"
                | "update"
                | "tree"
                | "metadata"
                | "search"
                | "info"
                | "fetch"
                | "generate-lockfile"
                | "fmt"
                | "locate-project"
                | "pkgid"
                | "--version"
                | "-V"
        ),
        // Go never runs dependency code to build: only `run`, `test`, `generate`, `tool` do.
        "go" | "gofmt" => !matches!(sub, "run" | "test" | "generate" | "tool"),
        "uv" => match sub {
            "lock" | "tree" | "version" | "--version" | "python" => true,
            "add" | "remove" => has("--no-sync") || has("--frozen"),
            "pip" => matches!(
                words.get(2).copied(),
                Some("list" | "show" | "freeze" | "tree")
            ),
            _ => false,
        },
        "poetry" => match sub {
            "lock" | "show" | "check" | "version" | "--version" | "env" | "config" => true,
            "add" | "remove" | "update" => has("--lock"),
            _ => false,
        },
        "pip" | "pip3" => matches!(sub, "list" | "show" | "freeze" | "--version" | "config"),
        "bundle" => match sub {
            "lock" | "outdated" | "list" | "info" | "show" | "check" | "config" | "--version" => {
                true
            }
            "add" => has("--skip-install"),
            _ => false,
        },
        "gem" => {
            matches!(
                sub,
                "list"
                    | "search"
                    | "info"
                    | "query"
                    | "spec"
                    | "specification"
                    | "which"
                    | "env"
                    | "--version"
            ) || (sub == "install" && has("--explain"))
        }
        "composer" => match sub {
            "show" | "outdated" | "why" | "why-not" | "validate" | "depends" | "licenses"
            | "--version" => true,
            "install" | "update" | "require" | "remove" => {
                has("--no-install") || (has("--no-scripts") && has("--no-plugins"))
            }
            _ => false,
        },
        "dotnet" => {
            matches!(sub, "list" | "restore" | "--version" | "--info" | "nuget")
                || (sub == "add" && words.contains(&"package"))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::runs_code;
    use crate::shell_ast::parse;

    #[test]
    fn deny_by_default() {
        for cmd in [
            "git status && cat Cargo.lock | grep serde",
            "cargo update -p serde --precise 1.0.200",
            "npm view zod time --json",
            "npm install --ignore-scripts",
            "poetry add requests --lock",
            "uv add httpx --no-sync",
            "go build ./... && go vet ./...",
            "bundle lock --update rack",
            "rg -n foo src | head",
        ] {
            assert!(!runs_code(&parse(cmd)), "{cmd}");
        }
        for cmd in [
            "cargo test",
            "npm test",
            "npm install",
            "go test ./...",
            "python -c 'import requests'",
            "make",
            "bundle exec rspec",
            "ls && ./gradlew build",
            "pytest -q",
            "node index.js",
            "sh ./script.sh",
        ] {
            assert!(runs_code(&parse(cmd)), "{cmd}");
        }
    }
}

//! Shell commands parsed with tree-sitter-bash. Quoting, pipes, lists, subshells,
//! `$(…)` and redirections are resolved structurally, where regexes over the raw
//! text both miss bypasses and block harmless commands.

use ast_grep_core::{Doc, Node};
use ast_grep_language::{LanguageExt, SupportLang};

/// One simple command, after unwrapping `sudo`/`env`/`command`/`nohup`/`time`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Command {
    /// `VAR=value` prefixes (and `env VAR=value …`).
    pub env: Vec<(String, String)>,
    /// Program name followed by its arguments, unquoted.
    pub words: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Script {
    pub commands: Vec<Command>,
    /// Files written through `>`, `>>`, `&>`, `>|`.
    pub written: Vec<String>,
    /// `export VAR=value` / `declare` assignments.
    pub exported: Vec<(String, String)>,
    /// Files written with known content: `cat > f <<EOF`, `tee f <<EOF`, `echo … > f`.
    pub file_writes: Vec<FileWrite>,
}

impl Script {
    /// Every variable the script sets, whether as a prefix or exported.
    pub fn assignments(&self) -> impl Iterator<Item = &(String, String)> {
        self.commands
            .iter()
            .flat_map(|c| c.env.iter())
            .chain(self.exported.iter())
    }
}

/// Wrappers whose arguments are themselves a command.
const WRAPPERS: [&str; 7] = ["sudo", "command", "exec", "nohup", "time", "env", "xargs"];
const SHELLS: [&str; 5] = ["sh", "bash", "zsh", "dash", "ksh"];

mod writes;
pub use writes::FileWrite;
use writes::file_writes;

pub fn parse(src: &str) -> Script {
    let mut script = Script::default();
    collect(src, &mut script, 0);
    script
}

fn collect(src: &str, script: &mut Script, depth: usize) {
    let grep = SupportLang::Bash.ast_grep(src);
    for node in grep.root().dfs() {
        match node.kind().as_ref() {
            "command" => {
                let cmd = unwrap(command(&node));
                // `bash -c '…'` and `eval …` run a script given as a string.
                if depth < 3
                    && let Some(inner) = nested_script(&cmd)
                {
                    collect(&inner, script, depth + 1);
                }
                script.commands.push(cmd);
            }
            "file_redirect" => script.written.extend(written_target(&node)),
            "redirected_statement" => script.file_writes.extend(file_writes(&node)),
            "declaration_command" => script.exported.extend(
                node.children()
                    .filter(|c| c.kind() == "variable_assignment")
                    .map(|a| assignment(&a)),
            ),
            _ => {}
        }
    }
}

pub(super) fn command<D: Doc>(node: &Node<D>) -> Command {
    let mut cmd = Command::default();
    for child in node.children().filter(|c| c.is_named()) {
        match child.kind().as_ref() {
            "variable_assignment" => cmd.env.push(assignment(&child)),
            "file_redirect" | "heredoc_redirect" | "herestring_redirect" => {}
            _ => cmd.words.push(text(&child)),
        }
    }
    cmd
}

/// `sudo -u x env A=1 git …` → `git …` with `A=1` in `env`.
pub(super) fn unwrap(mut cmd: Command) -> Command {
    loop {
        let Some(first) = cmd.words.first() else {
            return cmd;
        };
        if !WRAPPERS.contains(&first.as_str()) {
            return cmd;
        }
        cmd.words.remove(0);
        while let Some(w) = cmd.words.first() {
            if w.starts_with('-') {
                cmd.words.remove(0);
            } else if let Some((k, v)) = w.split_once('=')
                && is_name(k)
            {
                cmd.env.push((k.to_string(), v.to_string()));
                cmd.words.remove(0);
            } else {
                break;
            }
        }
    }
}

fn nested_script(cmd: &Command) -> Option<String> {
    let (name, args) = cmd.words.split_first()?;
    let name = name.rsplit('/').next().unwrap_or(name);
    if name == "eval" {
        return Some(args.join(" "));
    }
    if SHELLS.contains(&name) {
        let at = args
            .iter()
            .position(|a| a.starts_with('-') && a.contains('c'))?;
        return args.get(at + 1).cloned();
    }
    None
}

fn assignment<D: Doc>(node: &Node<D>) -> (String, String) {
    let name = node.field("name").map(|n| n.text().to_string());
    let value = node.field("value").map(|v| text(&v)).unwrap_or_default();
    (name.unwrap_or_default(), value)
}

pub(super) fn written_target<D: Doc>(node: &Node<D>) -> Option<String> {
    let op = node.children().find(|c| !c.is_named())?.text().to_string();
    let dest = node.children().filter(|c| c.is_named()).last()?;
    let writes = op.contains('>') && dest.kind() != "number" && dest.kind() != "file_descriptor";
    writes.then(|| text(&dest))
}

/// The value a shell word evaluates to, as far as it is static.
fn text<D: Doc>(node: &Node<D>) -> String {
    match node.kind().as_ref() {
        "string" => node
            .children()
            .filter(|c| c.kind() != "\"")
            .map(|c| text(&c))
            .collect(),
        "raw_string" => node.text().trim_matches('\'').to_string(),
        "concatenation" => node.children().map(|c| text(&c)).collect(),
        "word" | "string_content" => unescape(&node.text()),
        _ => node.text().to_string(),
    }
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.extend(chars.next()),
            _ => out.push(c),
        }
    }
    out
}

fn is_name(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(src: &str) -> Vec<Vec<String>> {
        parse(src).commands.into_iter().map(|c| c.words).collect()
    }

    #[test]
    fn resolves_quoting_lists_and_wrappers() {
        let s = parse(
            r#"HUSKY=0 git -c core.hooksPath=/dev/null commit -nm "x y" 2>&1 > .larpcop.yaml && export SKIP=lint"#,
        );
        assert_eq!(s.commands[0].env, [("HUSKY".into(), "0".into())]);
        assert_eq!(
            s.commands[0].words,
            [
                "git",
                "-c",
                "core.hooksPath=/dev/null",
                "commit",
                "-nm",
                "x y"
            ]
        );
        assert_eq!(s.written, [".larpcop.yaml"]);
        assert_eq!(s.exported, [("SKIP".into(), "lint".into())]);
        assert_eq!(
            words("sudo env A=1 git commit --no-ver\"\"ify"),
            [["git", "commit", "--no-verify"]]
        );
        assert_eq!(
            words("npm i a & pnpm add b | tee log"),
            [
                vec!["npm", "i", "a"],
                vec!["pnpm", "add", "b"],
                vec!["tee", "log"]
            ]
        );
        let nested = words(r#"bash -c 'rm -f .larpcop.yaml' ; eval "git commit -n""#);
        assert!(nested.contains(&vec!["rm".into(), "-f".into(), ".larpcop.yaml".into()]));
        assert!(nested.contains(&vec!["git".into(), "commit".into(), "-n".into()]));
        assert!(parse("ls 2>/dev/null >&2").written == ["/dev/null"]);
    }
}

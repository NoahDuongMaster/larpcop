//! Files a shell command writes with content known up front: `cat > f <<EOF`,
//! `tee f <<EOF`, `echo … > f`. Agents use these to create files without going
//! through their edit tools, so the hook checks the content here instead.

use super::{Script, command, unwrap, written_target};
use ast_grep_core::{Doc, Node};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileWrite {
    pub path: String,
    pub content: String,
    pub append: bool,
}

impl Script {
    /// Directory of the last `cd DIR` in the script: relative writes land there.
    pub fn cd(&self) -> Option<&str> {
        self.commands
            .iter()
            .rev()
            .find(|c| c.words.first().is_some_and(|w| w == "cd"))
            .and_then(|c| c.words.get(1))
            .map(String::as_str)
    }
}

/// What a redirected `cat`, `tee` or `echo` writes, where the content is static.
pub(super) fn file_writes<D: Doc>(stmt: &Node<D>) -> Vec<FileWrite> {
    // `cd x && echo hi > f` parses as a redirected list: the redirect belongs to
    // the list's last command.
    let body = stmt
        .children()
        .find(|c| c.is_named() && !c.kind().ends_with("redirect"));
    let Some(cmd) = body.and_then(|b| {
        if b.kind() == "command" {
            Some(b)
        } else {
            b.dfs().filter(|n| n.kind() == "command").last()
        }
    }) else {
        return Vec::new();
    };
    let cmd = unwrap(command(&cmd));
    let heredoc = stmt
        .dfs()
        .find(|n| n.kind() == "heredoc_body")
        .map(|n| n.text().to_string());
    let redirects: Vec<(String, bool)> = stmt
        .dfs()
        .filter(|n| n.kind() == "file_redirect")
        .filter_map(|r| {
            let append = r
                .children()
                .any(|c| !c.is_named() && c.text().contains(">>"));
            written_target(&r).map(|p| (p, append))
        })
        .collect();
    let (name, args) = match cmd.words.split_first() {
        Some((n, a)) => (n.as_str(), a),
        None => return Vec::new(),
    };
    let to = |targets: Vec<(String, bool)>, content: String| {
        targets
            .into_iter()
            .map(|(path, append)| FileWrite {
                path,
                content: content.clone(),
                append,
            })
            .collect()
    };
    match (name, heredoc) {
        ("cat", Some(body)) if args.is_empty() => to(redirects, body),
        ("tee", Some(body)) => {
            let append = args.iter().any(|a| a == "-a" || a == "--append");
            let paths = args.iter().filter(|a| !a.starts_with('-'));
            to(
                paths
                    .map(|p| (p.clone(), append))
                    .chain(redirects)
                    .collect(),
                body,
            )
        }
        ("echo", _) => {
            let flags = args
                .iter()
                .take_while(|a| matches!(a.as_str(), "-n" | "-e" | "-E"))
                .count();
            let newline = if args[..flags].iter().any(|a| a == "-n") {
                ""
            } else {
                "\n"
            };
            to(redirects, format!("{}{newline}", args[flags..].join(" ")))
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::parse;
    use super::*;

    #[test]
    fn file_writes_with_static_content() {
        let w = |src: &str| parse(src).file_writes;
        assert_eq!(
            w("cat > src/a.ts <<'EOF'\nconsole.log(1)\nEOF\n"),
            [FileWrite {
                path: "src/a.ts".into(),
                content: "console.log(1)\n".into(),
                append: false
            }]
        );
        assert!(w("cat <<EOF >> b.py\nprint(1)\nEOF\n")[0].append);
        assert_eq!(w("tee -a c.ts <<'X'\nlet a\nX\n")[0].path, "c.ts");
        assert_eq!(w("echo 'debugger;' > d.ts")[0].content, "debugger;\n");
        assert_eq!(w("cd x && echo -n hi > e.txt")[0].content, "hi");
        assert_eq!(parse("cd src && echo hi > e.txt").cd(), Some("src"));
        assert!(w("cat a.ts > b.ts").is_empty(), "content not known");
        assert!(w("npm test > log.txt").is_empty());
    }
}

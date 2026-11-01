//! Argument vectors that run a command string through a shell:
//! `subprocess.run(["sh", "-c", cmd])`, `new ProcessBuilder(list)` with
//! `list = ["bash", "-c", cmd]`. The rule's `shell_argv` names the calls,
//! what a shell is and the flags that make it run a string; the elements after
//! the flag are sinks. Lists built element by element are read too
//! (`args = []; args.append("sh"); …`), including `if`/`else` branches that
//! build them differently (`cmd.exe /c` on Windows, `sh -c` elsewhere): every
//! way the list can come out is checked. `vectors` says where a call takes
//! its vector, as `name:index` (an array argument: `execv:1`) or
//! `name:index..` (the arguments themselves: `execl:1..`); the first argument
//! otherwise.

use super::constant::{Env, Value, eval};
use super::kotlin::Part;
use super::scan::FileIndex;
use super::summary::{args, called_name, callee};
use crate::rules::complexity::is_function;
use ast_grep_core::{Doc, Node};
use regex::Regex;

pub(crate) struct ShellArgv {
    pub calls: Regex,
    pub vectors: std::collections::HashMap<String, (usize, bool)>,
    pub shells: Regex,
    pub flags: Regex,
}

/// Shells that join every word after the flag into the command line.
const JOINING: [&str; 3] = ["cmd", "powershell", "pwsh"];
/// The ways a list can come out, at most this many.
const WAYS: usize = 8;
const LITERALS: [&str; 5] = [
    "list",
    "array",
    "array_initializer",
    "array_creation_expression",
    "initializer_list",
];
const ADDS: [&str; 3] = ["append", "add", "push"];
const IFS: [&str; 2] = ["if_statement", "if_expression"];
/// Calls that make a list of their arguments.
const MAKERS: [&str; 6] = ["list", "ArrayList", "LinkedList", "asList", "of", "listOf"];
const LOOP_KINDS: [&str; 9] = [
    "for_statement",
    "for_in_statement",
    "enhanced_for_statement",
    "foreach_statement",
    "while_statement",
    "do_statement",
    "while",
    "until",
    "for",
];

impl ShellArgv {
    /// (call start, element) for each command element of a shell argv.
    pub(super) fn sinks<'a, D: Doc>(&self, index: &FileIndex<'a, D>) -> Vec<(usize, Node<'a, D>)> {
        let mut out = Vec::new();
        for call in index.calls() {
            let named = callee(call).or_else(|| called_name(call));
            if !named.is_some_and(|c| self.calls.is_match(&c)) {
                continue;
            }
            let Some(f) = call.ancestors().find(|a| is_function(a)) else {
                continue;
            };
            let env = Env::new(&f);
            let name = called_name(call).unwrap_or_default();
            let (at, spread) = self.vectors.get(&name).copied().unwrap_or((0, false));
            let all = args(call);
            // `execl(path, "sh", "-c", cmd, NULL)`: the arguments are the vector.
            if spread {
                let way: Vec<Node<D>> = all.into_iter().skip(at).map(unwrap).collect();
                out.extend(self.commands(call, way, &env));
                continue;
            }
            let Some(first) = all.into_iter().nth(at).map(unwrap) else {
                continue;
            };
            let ways = match first.kind().as_ref() {
                k if LITERALS.contains(&k) => vec![elements(&first)],
                k if super::flow::CALLS.contains(&k) && makes_list(&first) => {
                    vec![elements(&first)]
                }
                "identifier" => built(&f, &first.text(), call.range().start).unwrap_or_default(),
                _ => Vec::new(),
            };
            for way in ways {
                out.extend(self.commands(call, way, &env));
            }
        }
        out
    }

    /// The command elements of one way the vector comes out: those after the
    /// flag when it starts with a shell and that flag.
    fn commands<'a, D: Doc>(
        &self,
        call: &Node<'a, D>,
        way: Vec<Node<'a, D>>,
        env: &Env<'a, D>,
    ) -> Vec<(usize, Node<'a, D>)> {
        let text = |n: &Node<D>| match eval(n, env, 0) {
            Some(Value::Str(s)) => Some(s),
            _ => None,
        };
        let Some(shell) = way
            .first()
            .and_then(text)
            .filter(|s| self.shells.is_match(s))
        else {
            return Vec::new();
        };
        if !way
            .get(1)
            .and_then(text)
            .is_some_and(|s| self.flags.is_match(&s))
        {
            return Vec::new();
        }
        // `sh -c CMD a b`: the rest are `$0`, `$1`; `cmd /c` and
        // PowerShell join every word after the flag into the command.
        let joined = JOINING.iter().any(|j| shell.to_lowercase().contains(j));
        let take = if joined { usize::MAX } else { 1 };
        way.into_iter()
            .skip(2)
            .take(take)
            .map(|n| (call.range().start, n))
            .collect()
    }
}

/// `list(…)`, `new java.util.ArrayList<>(…)`, `Arrays.asList(…)`, `List.of(…)`.
fn makes_list<D: Doc>(call: &Node<D>) -> bool {
    let name = called_name(call).or_else(|| {
        let t = call.part("type")?.text().to_string();
        Some(t.split('<').next()?.rsplit('.').next()?.trim().to_string())
    });
    name.is_some_and(|c| MAKERS.contains(&c.as_str()))
}

fn unwrap<'a, D: Doc>(n: Node<'a, D>) -> Node<'a, D> {
    if matches!(n.kind().as_ref(), "argument" | "value_argument") {
        let inner = n.children().find(|c| c.is_named());
        return inner.unwrap_or(n);
    }
    n
}

/// The elements of a list literal, `new String[]{…}` or `Arrays.asList(…)`.
fn elements<'a, D: Doc>(n: &Node<'a, D>) -> Vec<Node<'a, D>> {
    if n.kind() == "array_creation_expression"
        && let Some(init) = n.children().find(|c| c.kind() == "array_initializer")
    {
        return elements(&init);
    }
    if super::flow::CALLS.contains(&n.kind().as_ref()) {
        return args(n).into_iter().map(unwrap).collect();
    }
    n.children()
        .filter(|c| c.is_named() && !c.kind().contains("comment"))
        .collect()
}

/// The ways `name` can come out before `at` in function `f`: from its
/// creation on, through appends and `if`/`else` branches. `None` when it is
/// changed some other way (a loop, a call it is passed to).
fn built<'a, D: Doc>(f: &Node<'a, D>, name: &str, at: usize) -> Option<Vec<Vec<Node<'a, D>>>> {
    let body = f.part("body")?;
    // Nothing is known of a list the function did not create.
    walk(&body, name, at, Vec::new())
}

fn walk<'a, D: Doc>(
    n: &Node<'a, D>,
    name: &str,
    at: usize,
    mut ways: Vec<Vec<Node<'a, D>>>,
) -> Option<Vec<Vec<Node<'a, D>>>> {
    if n.range().start >= at || !n.text().contains(name) {
        return Some(ways);
    }
    let kind = n.kind();
    if IFS.contains(&kind.as_ref()) {
        let branches: Vec<Node<D>> = ["consequence", "alternative"]
            .iter()
            .filter_map(|k| n.part(k))
            .collect();
        let mut out = Vec::new();
        if n.part("alternative").is_none() {
            out.extend(ways.clone());
        }
        for b in branches {
            out.extend(walk(&b, name, at, ways.clone())?);
        }
        out.truncate(WAYS);
        return Some(out);
    }
    if let Some((left, right)) = super::flow::assignment(n)
        && left.text() == name
    {
        let start = match right.kind().as_ref() {
            k if LITERALS.contains(&k) => elements(&right),
            k if super::flow::CALLS.contains(&k) && makes_list(&right) => elements(&right),
            _ => return None,
        };
        return Some(vec![start]);
    }
    if super::flow::CALLS.contains(&kind.as_ref())
        && let Some(c) = callee(n)
        && let Some((receiver, method)) = c.rsplit_once('.')
        && receiver == name
    {
        match method {
            m if ADDS.contains(&m) => {
                let value = args(n).into_iter().next().map(unwrap)?;
                ways.iter_mut().for_each(|w| w.push(value.clone()));
            }
            "extend" | "addAll" => {
                let more = elements(&args(n).into_iter().next().map(unwrap)?);
                ways.iter_mut().for_each(|w| w.extend(more.iter().cloned()));
            }
            _ => return None,
        }
        return Some(ways);
    }
    if LOOP_KINDS.contains(&kind.as_ref()) {
        return None;
    }
    for c in n.children().filter(|c| c.is_named()) {
        ways = walk(&c, name, at, ways)?;
    }
    Some(ways)
}

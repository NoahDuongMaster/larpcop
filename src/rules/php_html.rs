//! PHP files mixing HTML and code (`<html>…<?php … ?>…`): ast-grep parses
//! PHP with the PHP-only grammar, which reads the HTML as code and loses the
//! structure around it. Before parsing, the HTML between two pieces of code
//! becomes a comment `/*@…*/` of the same length (`?>` and the opening tag
//! give the room), so the code keeps its lines and columns and the page
//! stays readable to the checks that need it (`page_before`, contexts.rs);
//! `?>` ends a statement (`;`) as it does in PHP and `<?=` is an `echo`.
//! `?>` inside a string or a `/* */` comment does not close the code; inside
//! a `//` or `#` comment it does, as in PHP: the HTML after it is blanked
//! (spaces, newlines kept). HTML too long for its room is shortened where
//! contexts.rs does not read it; past that, the line's later columns shift.

use std::borrow::Cow;

/// Marks a comment holding the page's HTML.
const MARK: &str = "/*@";

/// The code of a PHP file, the HTML around it in comments.
pub fn code(content: &str) -> Cow<'_, str> {
    let starts_in_code = content.trim_start().starts_with("<?php");
    if starts_in_code && !content.contains("?>") {
        return Cow::Borrowed(content);
    }
    let mut out = String::with_capacity(content.len() + 16);
    let mut i = 0;
    // How the HTML at `i` was entered: file start, `?>`, `?>` in a line comment.
    let mut closed: Option<bool> = None;
    loop {
        let open = content[i..].find("<?").map(|p| i + p);
        let html = &content[i..open.unwrap_or(content.len())];
        let rest = open.map_or("", |at| &content[at..]);
        let tag = if rest.starts_with("<?php") {
            5
        } else if rest.starts_with("<?=") {
            3
        } else if open.is_some() {
            2
        } else {
            0
        };
        let next = rest[tag.min(rest.len())..].chars().next();
        page(html, closed, open.map(|_| (tag, tag == 3, next)), &mut out);
        let Some(at) = open else { break };
        let (end, close) = php(content, at + tag, &mut out);
        let Some(in_comment) = close else { break };
        closed = Some(in_comment);
        i = end;
    }
    Cow::Owned(out)
}

/// Writes HTML `html` (with the `?>` before it when `closed`, and the opening
/// tag after it: `(length, is <?=, character after it)`) at the same length.
fn page(
    html: &str,
    closed: Option<bool>,
    tag: Option<(usize, bool, Option<char>)>,
    out: &mut String,
) {
    let room = closed.map_or(0, |_| 2) + html.len() + tag.map_or(0, |t| t.0);
    let head = if closed.is_some() { ";" } else { "" };
    let echo = match tag {
        Some((_, true, next)) if next.is_some_and(char::is_whitespace) => "echo",
        Some((_, true, _)) => "echo ",
        _ => "",
    };
    let start = out.len();
    if tag.is_some() && closed != Some(true) {
        let body = html.replace("*/", "* ");
        let fixed = head.len() + MARK.len() + 2 + echo.len();
        // What still does not fit moves the rest of the line right: its
        // columns shift, its line does not.
        let (body, _) = shrink(body, (fixed + html.len()).saturating_sub(room));
        {
            out.push_str(head);
            out.push_str(MARK);
            out.push_str(&body);
            out.push_str("*/");
            out.push_str(echo);
            pad(out, start + room);
            return;
        }
    }
    out.push_str(if closed.is_some() { "; " } else { "" });
    let mut blanked = String::new();
    blank(html, &mut blanked);
    // `echo` is longer than `<?=`: blanks of the HTML give it room.
    let mut extra = echo.len().saturating_sub(3);
    blanked.retain(|c| {
        let drop = extra > 0 && c == ' ';
        extra -= usize::from(drop);
        !drop
    });
    out.push_str(&blanked);
    out.push_str(echo);
    pad(out, start + room);
}

/// Drops `excess` characters what contexts.rs reads does not need, from the
/// start: text between tags, then whole tags other than `script` and
/// `style` ones, then the name of an unfinished tag at the end, then
/// repeated spaces.
/// Line breaks stay. Returns the HTML and what is still in excess.
fn shrink(body: String, mut excess: usize) -> (String, usize) {
    if excess == 0 {
        return (body, 0);
    }
    // Text runs and tags (`<…>`; the last may be unfinished).
    let mut pieces: Vec<(String, bool)> = Vec::new();
    for c in body.chars() {
        let in_tag = pieces
            .last()
            .is_some_and(|(p, tag)| *tag && !p.ends_with('>'));
        match pieces.last_mut() {
            Some((p, tag)) if c != '<' && (in_tag || !*tag) => p.push(c),
            _ => pieces.push((c.to_string(), c == '<')),
        }
    }
    let lines = |s: &str| {
        s.chars()
            .filter(|c| matches!(c, '\n' | '\r'))
            .collect::<String>()
    };
    for (p, tag) in pieces.iter_mut().filter(|(_, tag)| !tag) {
        let _ = tag;
        p.retain(|c| {
            let drop = excess > 0 && !matches!(c, '\n' | '\r');
            excess -= usize::from(drop);
            !drop
        });
    }
    for (p, _) in pieces
        .iter_mut()
        .filter(|(p, tag)| *tag && p.ends_with('>'))
    {
        let name = p.trim_start_matches(['<', '/']).to_ascii_lowercase();
        if excess == 0 || name.starts_with("script") || name.starts_with("style") {
            continue;
        }
        let kept = lines(p);
        excess = excess.saturating_sub(p.len() - kept.len());
        *p = kept;
    }
    // An unfinished tag: its name (`<div class=` → `< class=`).
    if let Some((p, true)) = pieces.last_mut()
        && excess > 0
        && p.starts_with('<')
        && !p.ends_with('>')
    {
        let name: String = p[1..].chars().take_while(|c| !c.is_whitespace()).collect();
        let lower = name.trim_start_matches('/').to_ascii_lowercase();
        let attributes = p.len() > 1 + name.len();
        if attributes && !lower.starts_with("script") && !lower.starts_with("style") {
            let cut: String = name.chars().take(excess).collect();
            p.replace_range(1..1 + cut.len(), "");
            excess -= cut.chars().count();
        }
    }
    let mut out: String = pieces.into_iter().map(|(p, _)| p).collect();
    if excess > 0 {
        let mut prev = '\0';
        out.retain(|c| {
            let drop = excess > 0 && c == ' ' && prev == ' ';
            prev = c;
            excess -= usize::from(drop);
            !drop
        });
    }
    (out, excess)
}

fn pad(out: &mut String, to: usize) {
    while out.len() < to {
        out.push(' ');
    }
}

/// Copies PHP code from `i` up to its closing `?>`: where the HTML after it
/// starts, and whether the `?>` closed a line comment (`None`: no `?>`).
fn php(content: &str, mut i: usize, out: &mut String) -> (usize, Option<bool>) {
    let bytes = content.as_bytes();
    let start = i;
    let closes = |i: usize| bytes[i] == b'?' && bytes.get(i + 1) == Some(&b'>');
    let mut in_comment = false;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' | b'"' | b'`' => {
                let q = bytes[i];
                i += 1;
                while i < bytes.len() && bytes[i] != q {
                    i += if bytes[i] == b'\\' { 2 } else { 1 };
                }
                i += 1;
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i = content[i + 2..]
                    .find("*/")
                    .map_or(bytes.len(), |p| i + 2 + p + 2);
            }
            b'#' | b'/' if bytes[i] == b'#' || bytes.get(i + 1) == Some(&b'/') => {
                // A line comment ends at the line's end or at `?>`.
                while i < bytes.len() && bytes[i] != b'\n' && !closes(i) {
                    i += 1;
                }
                in_comment = i < bytes.len() && closes(i);
            }
            _ if closes(i) => {
                out.push_str(&content[start..i]);
                return (i + 2, Some(in_comment));
            }
            _ => {
                in_comment = false;
                i += 1;
            }
        }
    }
    let end = i.min(bytes.len());
    out.push_str(&content[start..end]);
    (end, None)
}

/// Spaces for everything but line breaks.
fn blank(text: &str, out: &mut String) {
    out.extend(
        text.chars()
            .map(|c| if c == '\n' || c == '\r' { c } else { ' ' }),
    );
}

/// The page's HTML before byte `at` of the code `code` returned.
pub fn page_before(code: &str, at: usize) -> String {
    let mut out = String::new();
    let mut i = 0;
    while let Some(p) = code[i..at.min(code.len())].find(MARK) {
        let s = i + p + MARK.len();
        let e = code[s..].find("*/").map_or(code.len(), |q| s + q);
        out.push_str(&code[s..e.min(at)]);
        i = e.min(at);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{code, page_before};

    #[test]
    fn html_around_php_becomes_comments() {
        let src =
            "<!-- x -->\n<script>\n<?php\n$a = \"?>\"; // c ?>\n<b><?= $a ?></b>\n<?php echo 1;\n";
        let out = code(src);
        assert_eq!(out.len(), src.len());
        assert_eq!(out.lines().count(), src.lines().count());
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "/*@<!-- x -->");
        assert_eq!(lines[1], "<script>");
        assert_eq!(lines[3], "$a = \"?>\"; // c ; ");
        assert_eq!(lines[4], "  echo $a ;/*@</b>");
        assert_eq!(lines[5], "*/  echo 1;");
        let at = out.find("echo $a").unwrap();
        assert_eq!(page_before(&out, at), "<!-- x -->\n<script>\n");
        assert!(matches!(
            code("<?php\necho 1;\n"),
            std::borrow::Cow::Borrowed(_)
        ));
        let tight = "<?php $a ?><p><?=$b?>";
        assert_eq!(code(tight), "/*@*/ $a ;/*@*/echo $b; ");
    }
}

//! Making an HTML run fit the room its comment has (php_html.rs).

/// Drops `excess` characters what contexts.rs reads does not need, from the
/// start: text between tags, then whole tags other than `script` and
/// `style` ones, then the name of an unfinished tag at the end, then
/// repeated spaces.
/// Line breaks stay. Returns the HTML and what is still in excess.
pub(super) fn shrink(body: String, mut excess: usize) -> (String, usize) {
    if excess == 0 {
        return (body, 0);
    }
    let mut pieces = pieces(&body);
    drop_text(&mut pieces, &mut excess);
    drop_tags(&mut pieces, &mut excess);
    drop_unfinished_tag_name(&mut pieces, &mut excess);
    let mut out: String = pieces.into_iter().map(|(p, _)| p).collect();
    drop_repeated_spaces(&mut out, &mut excess);
    (out, excess)
}

/// Text runs and tags (`<…>`; the last may be unfinished), each with whether
/// it is a tag.
fn pieces(body: &str) -> Vec<(String, bool)> {
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
    pieces
}

/// The text between tags, but its line breaks.
fn drop_text(pieces: &mut [(String, bool)], excess: &mut usize) {
    for (p, _) in pieces.iter_mut().filter(|(_, tag)| !tag) {
        p.retain(|c| {
            let drop = *excess > 0 && !matches!(c, '\n' | '\r');
            *excess -= usize::from(drop);
            !drop
        });
    }
}

/// The finished tags, but `script` and `style` ones and their line breaks.
fn drop_tags(pieces: &mut [(String, bool)], excess: &mut usize) {
    for (p, _) in pieces
        .iter_mut()
        .filter(|(p, tag)| *tag && p.ends_with('>'))
    {
        if *excess == 0 || is_script_or_style(p.trim_start_matches(['<', '/'])) {
            continue;
        }
        let kept: String = p.chars().filter(|c| matches!(c, '\n' | '\r')).collect();
        *excess = excess.saturating_sub(p.len() - kept.len());
        *p = kept;
    }
}

/// An unfinished tag at the end loses its name (`<div class=` → `< class=`).
fn drop_unfinished_tag_name(pieces: &mut [(String, bool)], excess: &mut usize) {
    if let Some((p, true)) = pieces.last_mut()
        && *excess > 0
        && p.starts_with('<')
        && !p.ends_with('>')
    {
        let name: String = p[1..].chars().take_while(|c| !c.is_whitespace()).collect();
        let attributes = p.len() > 1 + name.len();
        if attributes && !is_script_or_style(name.trim_start_matches('/')) {
            let cut: String = name.chars().take(*excess).collect();
            p.replace_range(1..1 + cut.len(), "");
            *excess -= cut.chars().count();
        }
    }
}

fn drop_repeated_spaces(out: &mut String, excess: &mut usize) {
    if *excess == 0 {
        return;
    }
    let mut prev = '\0';
    out.retain(|c| {
        let drop = *excess > 0 && c == ' ' && prev == ' ';
        prev = c;
        *excess -= usize::from(drop);
        !drop
    });
}

/// Does a tag name (after `<` and `/`) start with `script` or `style`?
fn is_script_or_style(name: &str) -> bool {
    let starts = |word: &str| {
        name.as_bytes()
            .get(..word.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(word.as_bytes()))
    };
    starts("script") || starts("style")
}

#[cfg(test)]
mod tests {
    use super::shrink;

    #[test]
    fn oversize_html_loses_text_then_tags_then_a_tag_name_then_spaces() {
        let shrunk = |html: &str, excess| shrink(html.to_string(), excess);
        assert_eq!(shrunk("<p>hello world</p>", 5), ("<p> world</p>".into(), 0));
        assert_eq!(shrunk("<i>a</i>", 4), ("</i>".into(), 0));
        // `script` and `style` tags stay, so what they cannot spare is left over.
        assert_eq!(
            shrunk("<script>a</script>", 100),
            ("<script></script>".into(), 99)
        );
        assert_eq!(shrunk("<div class=", 3), ("< class=".into(), 0));
        assert_eq!(shrunk("<script  x>", 1), ("<script x>".into(), 0));
        assert_eq!(shrunk("keep\n", 0), ("keep\n".into(), 0));
    }
}

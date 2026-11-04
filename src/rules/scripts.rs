//! `<script>` blocks of pages (HTML, PHP, JSP, ERB, Jinja and other
//! templates, Vue and Svelte components): the JavaScript rules check them as
//! a JavaScript file in which everything else is blank, so lines are the
//! page's (and columns too, but after a non-ASCII character on the line).
//! Server-side tags inside a script (`<?= … ?>`, `<%= … %>`, `{{ … }}`)
//! become a `0` as long as the tag when they print a value, blanks
//! otherwise; scripts of another type (`text/template`) are left out.

mod comments;

/// Appended to a page's path for its scripts' view (`page.php#script.js`).
pub const SUFFIX_JS: &str = "#script.js";
pub const SUFFIX_TS: &str = "#script.ts";

/// Page extensions whose `<script>` blocks are checked.
const PAGES: [&str; 26] = [
    "html",
    "htm",
    "xhtml",
    "php",
    "phtml",
    "jsp",
    "jspf",
    "asp",
    "aspx",
    "cshtml",
    "vbhtml",
    "erb",
    "ejs",
    "hbs",
    "handlebars",
    "mustache",
    "njk",
    "jinja",
    "jinja2",
    "j2",
    "twig",
    "liquid",
    "tpl",
    "gohtml",
    "vue",
    "svelte",
];

/// Script types that are JavaScript.
const JS_TYPES: [&str; 7] = [
    "",
    "text/javascript",
    "application/javascript",
    "module",
    "text/ecmascript",
    "application/ecmascript",
    "text/typescript",
];

/// The view of `content`'s scripts, and whether it is TypeScript; `None`
/// when `rel` is not a page or has no inline script.
pub fn view(rel: &str, content: &str) -> Option<(String, bool)> {
    let ext = rel.rsplit_once('.')?.1.to_ascii_lowercase();
    if !PAGES.contains(&ext.as_str()) {
        return None;
    }
    let mut php = matches!(ext.as_str(), "php" | "phtml").then(|| PhpScan::new(content));
    let mut comments = comments::CommentScan::new(content);
    // The scripts (from, to) are located before any copy of the page is made:
    // most pages have none.
    let mut scripts = Vec::new();
    let mut ts = false;
    let mut i = 0;
    while let Some(at) = find_ci(content, "<script", i) {
        let Some(tag_end) = tag_end(content, at) else {
            break;
        };
        // `<?php echo "<script>…" ?>`: a script in code is the code's business.
        if php.as_mut().is_some_and(|p| p.holds(at)) {
            i = tag_end;
            continue;
        }
        let attrs = content[at + 7..tag_end].to_ascii_lowercase();
        let close = find_ci(content, "</script", tag_end).unwrap_or(content.len());
        let kind = attribute(&attrs, "type").unwrap_or_default();
        if JS_TYPES.contains(&kind.as_str()) && !comments.holds(at) {
            let lang = attribute(&attrs, "lang").unwrap_or_default();
            ts |= kind == "text/typescript" || matches!(lang.as_str(), "ts" | "typescript");
            scripts.push((tag_end + 1, close));
        }
        i = close;
    }
    if scripts.is_empty() {
        return None;
    }
    let mut out: Vec<u8> = content
        .bytes()
        .map(|b| if b == b'\n' || b == b'\r' { b } else { b' ' })
        .collect();
    for (from, to) in scripts {
        copy(content, from, to, &mut out);
    }
    // Only ASCII bytes were blanked and whole scripts (cut at ASCII `>`,
    // `<`) copied: still UTF-8.
    let text = String::from_utf8(out).ok()?;
    Some((text, ts))
}

/// Where `needle` (lowercase ASCII, starting with `<`) first occurs in `text`
/// at or after `from`, in any case.
fn find_ci(text: &str, needle: &str, mut from: usize) -> Option<usize> {
    while let Some(p) = text[from..].find('<') {
        let at = from + p;
        if starts_with_ci(&text[at..], needle) {
            return Some(at);
        }
        from = at + 1;
    }
    None
}

/// Does `text` start with `prefix` (lowercase ASCII), in any case?
fn starts_with_ci(text: &str, prefix: &str) -> bool {
    text.as_bytes()
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
}

/// Where a tag opened at `at` ends (its `>`), quoted values skipped.
fn tag_end(content: &str, at: usize) -> Option<usize> {
    let bytes = content.as_bytes();
    let mut i = at + 1;
    let mut quote = None;
    while i < bytes.len() {
        match (bytes[i], quote) {
            (b'"' | b'\'', None) => quote = Some(bytes[i]),
            (q, Some(open)) if q == open => quote = None,
            (b'>', None) => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

/// The lower-cased value of attribute `name` in a tag's attributes.
fn attribute(attrs: &str, name: &str) -> Option<String> {
    let mut rest = attrs;
    while let Some(p) = rest.find(name) {
        let before = rest[..p].chars().last();
        let after = rest[p + name.len()..].trim_start();
        rest = &rest[p + name.len()..];
        if !before.is_none_or(char::is_whitespace) || !after.starts_with('=') {
            continue;
        }
        let value = after[1..].trim_start();
        let v = match value.chars().next() {
            Some(q @ ('"' | '\'')) => value[1..].split(q).next().unwrap_or_default(),
            _ => value
                .split(|c: char| c.is_whitespace() || c == '>')
                .next()?,
        };
        return Some(v.trim().to_string());
    }
    None
}

/// Tells whether positions, asked in increasing order, are inside PHP code
/// (after a `<?` not yet closed by `?>`), reading the page once: not from its
/// start for every question.
struct PhpScan<'c> {
    content: &'c str,
    /// Where the page is not read yet: after the last block that ended.
    from: usize,
    /// The block read last, if still open at the last question: where it
    /// ends (`Some(None)`: never).
    block: Option<Option<usize>>,
}

impl<'c> PhpScan<'c> {
    fn new(content: &'c str) -> Self {
        Self {
            content,
            from: 0,
            block: None,
        }
    }

    fn holds(&mut self, at: usize) -> bool {
        loop {
            let end = match self.block {
                Some(end) => end,
                None => {
                    let Some(p) = self.content[self.from..at].find("<?") else {
                        return false;
                    };
                    let end = php_close(self.content, self.from + p + 2);
                    self.block = Some(end);
                    end
                }
            };
            match end {
                Some(end) if end <= at => {
                    self.from = end;
                    self.block = None;
                }
                _ => return true,
            }
        }
    }
}

/// Where PHP code from `i` ends: after its `?>`, strings skipped.
fn php_close(content: &str, mut i: usize) -> Option<usize> {
    let bytes = content.as_bytes();
    while i < bytes.len() {
        match bytes[i] {
            q @ (b'\'' | b'"') => {
                i += 1;
                while i < bytes.len() && bytes[i] != q {
                    i += if bytes[i] == b'\\' { 2 } else { 1 };
                }
            }
            b'?' if bytes.get(i + 1) == Some(&b'>') => return Some(i + 2),
            _ => {}
        }
        i += 1;
    }
    None
}

/// Server-side tags: opening, closing, and the openings that print a value.
const TAGS: [(&str, &str, &[&str]); 4] = [
    ("<?", "?>", &["<?=", "<?php echo", "<?php print", "<? echo"]),
    ("<%", "%>", &["<%=", "<%-", "<%:", "<%#"]),
    ("{{", "}}", &["{{"]),
    ("{%", "%}", &[]),
];

/// Copies the script `content[from..to]` into `out`, server-side tags in it
/// replaced.
fn copy(content: &str, from: usize, to: usize, out: &mut [u8]) {
    let bytes = content.as_bytes();
    let mut i = from;
    while i < to {
        let tag = content
            .is_char_boundary(i)
            .then(|| {
                TAGS.iter()
                    .find(|(open, ..)| content[i..to].starts_with(open))
            })
            .flatten();
        let Some((open, close, prints)) = tag else {
            out[i] = bytes[i];
            i += 1;
            continue;
        };
        let end = if *open == "<?" {
            php_close(content, i + 2).map(|e| e - 2)
        } else {
            content[i + open.len()..to]
                .find(close)
                .map(|p| i + open.len() + p)
        };
        let Some(end) = end.filter(|e| *e < to) else {
            out[i] = bytes[i];
            i += 1;
            continue;
        };
        let stop = end + close.len();
        let head = &content[i..stop];
        if prints.iter().any(|p| starts_with_ci(head, p)) {
            out[i] = b'0';
        }
        // The rest stays blank, line breaks kept.
        i = stop;
    }
}

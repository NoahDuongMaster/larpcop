//! C and C++ object-like macros that only rename (`#define SYSTEM system`,
//! `#define COMMAND_ARG3 data`, `#define COMMAND_INT "sh"`), applied before
//! the file is parsed, so a rule sees the call or value the macro stands for.
//! Portability code picks a name per platform (`#ifdef _WIN32 … #else …`);
//! the last definition wins, which is the `#else` branch. Function-like macros
//! and macros whose body is more than one token are left alone. Each use is
//! replaced within its line, so line numbers stay what they were; only checks
//! read the expanded text (fixes edit the file as written).

use ast_grep_language::SupportLang;
use regex::Regex;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::LazyLock;

static DEFINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)[ \t]+([A-Za-z_]\w*|L?"(?:[^"\\\n]|\\.)*"|\d+)[ \t]*(?://.*|/\*.*\*/)?\r?$"#)
        .expect("valid regex")
});
/// Alias chains followed at most this deep (`EXECL` → `_execl`).
const DEPTH: usize = 5;

/// The text to parse: `content` with renaming macros applied, for C and C++;
/// for PHP, its code without the HTML around it.
pub fn expand(lang: SupportLang, content: &str) -> Cow<'_, str> {
    // PHP: the HTML around the code blanked (php_html.rs).
    if lang == SupportLang::Php {
        return super::php_html::code(content);
    }
    if !matches!(lang, SupportLang::C | SupportLang::Cpp) || !content.contains("define") {
        return Cow::Borrowed(content);
    }
    let mut aliases: HashMap<&str, &str> = HashMap::new();
    for c in DEFINE.captures_iter(content) {
        let (name, body) = (
            c.get(1).map_or("", |m| m.as_str()),
            c.get(2).map_or("", |m| m.as_str()),
        );
        if name != body {
            aliases.insert(name, body);
        }
    }
    if aliases.is_empty() {
        return Cow::Borrowed(content);
    }
    let resolve = |name: &str| -> Option<&str> {
        let mut at = *aliases.get(name)?;
        for _ in 0..DEPTH {
            match aliases.get(at) {
                Some(next) if *next != name => at = next,
                _ => break,
            }
        }
        Some(at)
    };
    let mut out = String::with_capacity(content.len());
    for line in content.split_inclusive('\n') {
        if line.trim_start().starts_with('#') {
            out.push_str(line);
        } else {
            replace_line(line, &resolve, &mut out);
        }
    }
    Cow::Owned(out)
}

/// Replaces the identifiers of one line outside strings, characters and
/// comments. A `/* … */` comment spanning lines is not followed.
fn replace_line<'a>(line: &str, resolve: &impl Fn(&str) -> Option<&'a str>, out: &mut String) {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'"' || b == b'\'' {
            let start = i;
            i += 1;
            while i < bytes.len() && bytes[i] != b {
                i += if bytes[i] == b'\\' { 2 } else { 1 };
            }
            i = (i + 1).min(bytes.len());
            out.push_str(&line[start..i]);
        } else if line[i..].starts_with("//") {
            out.push_str(&line[i..]);
            return;
        } else if b == b'_' || b.is_ascii_alphabetic() {
            let start = i;
            while i < bytes.len() && (bytes[i] == b'_' || bytes[i].is_ascii_alphanumeric()) {
                i += 1;
            }
            let word = &line[start..i];
            out.push_str(resolve(word).unwrap_or(word));
        } else {
            let start = i;
            i += 1;
            while i < bytes.len() && !line.is_char_boundary(i) {
                i += 1;
            }
            out.push_str(&line[start..i]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renaming_macros_are_applied_within_their_lines() {
        let src = "\
#ifdef _WIN32
#define SYSTEM _wsystem
#define COMMAND_INT \"cmd.exe\"
#else
#define SYSTEM system
#define COMMAND_INT \"sh\" /* POSIX */
#endif
#define COMMAND_ARG3 data
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define LONG_ONE (1 + 2)
void f(char *data) {
    SYSTEM(COMMAND_ARG3); // SYSTEM
    printf(\"SYSTEM %s\", COMMAND_INT);
    int m = MAX(1, LONG_ONE);
}
";
        let out = expand(SupportLang::C, src);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), src.lines().count());
        assert_eq!(lines[11], "    system(data); // SYSTEM");
        assert_eq!(lines[12], "    printf(\"SYSTEM %s\", \"sh\");");
        assert_eq!(lines[13], "    int m = MAX(1, LONG_ONE);");
        assert_eq!(lines[1], "#define SYSTEM _wsystem");
        assert!(matches!(expand(SupportLang::Java, src), Cow::Borrowed(_)));
    }
}

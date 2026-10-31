//! Base64 segments that decode to text, as gitleaks' decoder finds them.

use base64::Engine;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use regex::Regex;
use std::sync::LazyLock;

/// `(start, encoded, decoded)` for every base64 or base64url run of 16+
/// characters that decodes to printable text.
pub(super) fn base64_segments(content: &str) -> Vec<(usize, &str, String)> {
    static SEGMENT: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/_\-]{16,}={0,2}").expect("static regex"));
    let lenient =
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent);
    let engines = [
        GeneralPurpose::new(&base64::alphabet::STANDARD, lenient),
        GeneralPurpose::new(&base64::alphabet::URL_SAFE, lenient),
    ];
    SEGMENT
        .find_iter(content)
        .filter_map(|m| {
            let bytes = engines.iter().find_map(|e| e.decode(m.as_str()).ok())?;
            let text = String::from_utf8(bytes).ok()?;
            let printable = text
                .chars()
                .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'));
            (printable && text.len() >= 8).then(|| (m.start(), m.as_str(), text))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use base64::Engine;

    #[test]
    fn decodes_text_and_skips_binary_and_plain_words() {
        // Encoded at runtime so the repository holds no scannable secret.
        let secret = ["0192023a7bbd", "73250516f069df18b500"].concat();
        let jwt_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(format!("{{\"password\":\"{secret}\"}}"));
        let text = format!("token: x.{jwt_payload}.y");
        let found = super::base64_segments(&text);
        assert_eq!(found.len(), 1);
        assert!(found[0].2.contains(&secret));
        assert!(super::base64_segments("const veryLongIdentifierName = 1").is_empty());
    }
}

use super::*;

#[test]
fn detects_known_formats_and_respects_allowlists() {
    let s = Secrets::new().unwrap();
    assert!(
        s.detectors() >= 200,
        "only {} gitleaks rules compiled",
        s.detectors()
    );
    // Built at runtime so the repository never contains a scannable token.
    let gh = format!("ghp_{}", "x7Rk2mQ9vTz4LpW8sYb3NcD6fJh1Ga5Ue0Ki");
    let stripe = format!("sk_live_{}", "51HqLyjWDarjtT1zdp7dcXyz9Qa8RtUv");
    let src = format!(
        "const token = \"{gh}\";\nconst key = '{stripe}';\nconst ok = process.env.TOKEN;\n"
    );
    let found = s.check("src/a.ts", &src);
    let ids: Vec<&str> = found.iter().map(|v| v.message.as_str()).collect();
    assert!(ids.iter().any(|m| m.contains("github-pat")), "{ids:?}");
    assert!(
        ids.iter().any(|m| m.contains("stripe-access-token")),
        "{ids:?}"
    );
    assert!(
        found
            .iter()
            .all(|v| !v.snippet.as_deref().unwrap_or("").contains(&gh[8..]))
    );
    // Lockfiles are on gitleaks' global path allowlist.
    assert!(s.check("package-lock.json", &src).is_empty());
    assert!(
        s.check("src/b.ts", "const t = process.env.GITHUB_TOKEN;\n")
            .is_empty()
    );
}

#[test]
fn entropy_matches_gitleaks() {
    // Values gitleaks 8.30 reported for the same strings.
    assert!((entropy("0192023a7bbd73250516f069df18b500") - 3.545_958_5).abs() < 1e-5);
    // Non-ASCII: character counts over the byte length, like gitleaks.
    assert!(entropy("パスワード") < entropy("abcde"));
}

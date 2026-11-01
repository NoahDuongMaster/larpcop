//! Values read from the project's settings files.

use super::ast::AstRules;
use crate::files::SourceFile;
use std::collections::BTreeSet;

#[test]
fn values_from_settings_files() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let rules = root.join("rules");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::write(
        rules.join("weak.yml"),
        r#"id: weak
language: Java
rule:
  pattern: Cipher.getInstance($ALG)
message: weak
metadata:
  resolve:
    ALG: "(?i)^des"
"#,
    )
    .unwrap();
    let res = root.join("src/main/resources");
    std::fs::create_dir_all(&res).unwrap();
    std::fs::write(
        res.join("app.properties"),
        "# algorithms\ncryptoAlg1 = DES/ECB/PKCS5Padding\ncryptoAlg2=AES/GCM/NoPadding\n",
    )
    .unwrap();
    std::fs::write(
        res.join("application.yml"),
        "crypto:\n  legacy: DESede\n  current: AES/GCM/NoPadding\n",
    )
    .unwrap();
    // Test settings are not the program's.
    let test_res = root.join("src/test/resources");
    std::fs::create_dir_all(&test_res).unwrap();
    std::fs::write(test_res.join("app.properties"), "cryptoAlg2=DES\n").unwrap();
    let java = r#"class C {
  @Value("${crypto.legacy}") private String legacy;
  @Value("${crypto.current}") private String current;
  @Value("${crypto.missing:DES}") private String fallback;
  void f(java.util.Properties p) throws Exception {
    Cipher.getInstance(p.getProperty("cryptoAlg1", "AES/GCM/NoPadding"));
    Cipher.getInstance(p.getProperty("cryptoAlg2", "DES"));
    Cipher.getInstance(legacy);
    Cipher.getInstance(current);
    Cipher.getInstance(fallback);
    String alg = p.getProperty("unknown");
    Cipher.getInstance(alg);
  }
}
"#;
    let ast = AstRules::load(&[rules], &BTreeSet::new(), root).unwrap();
    let file = SourceFile {
        rel: "C.java".into(),
        content: java.into(),
    };
    let lines: Vec<usize> = ast.check(&file).iter().map(|v| v.line).collect();
    assert_eq!(lines, [6, 8, 10]);
}

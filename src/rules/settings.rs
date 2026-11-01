//! The project's settings files: `.properties` and `application*.yml`
//! (Spring), read once on first use, test directories left out. Rules that
//! resolve a value (values.rs) look keys up here.

use std::collections::HashMap;
use std::path::Path;

/// Settings files' keys → the values they are given, read on first use.
#[derive(Default)]
pub struct Settings {
    root: Option<std::path::PathBuf>,
    map: std::sync::OnceLock<HashMap<String, Vec<String>>>,
}

#[derive(Default)]
struct Map(HashMap<String, Vec<String>>);

/// Directories whose settings are not the program's.
const SKIPPED: [&str; 6] = ["test", "tests", "node_modules", "target", "build", "dist"];

impl Settings {
    pub fn new(root: &Path) -> Self {
        Settings {
            root: Some(root.to_path_buf()),
            map: std::sync::OnceLock::new(),
        }
    }

    pub(super) fn get(&self, key: &str) -> &[String] {
        let map = self
            .map
            .get_or_init(|| self.root.as_deref().map(Map::load).unwrap_or_default().0);
        map.get(key).map(Vec::as_slice).unwrap_or_default()
    }
}

impl Map {
    fn load(root: &Path) -> Self {
        let mut out = Map::default();
        // The repo's files, tracked ones included even when git-ignored.
        let rels = crate::files::list(root, &crate::files::Scope::All).unwrap_or_default();
        for rel in rels {
            if rel.split('/').any(|part| SKIPPED.contains(&part)) {
                continue;
            }
            let name = rel.rsplit('/').next().unwrap_or(&rel);
            let yaml = (name.starts_with("application") || name.starts_with("bootstrap"))
                && (name.ends_with(".yml") || name.ends_with(".yaml"));
            if !(name.ends_with(".properties") || yaml) {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(root.join(&rel)) else {
                continue;
            };
            if yaml {
                out.yaml(&text);
            } else {
                out.properties(&text);
            }
        }
        out
    }

    fn add(&mut self, key: &str, value: &str) {
        let values = self.0.entry(key.to_string()).or_default();
        if !values.iter().any(|v| v == value) {
            values.push(value.to_string());
        }
    }

    fn properties(&mut self, text: &str) {
        for line in text.lines().map(str::trim_start) {
            if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
                continue;
            }
            if let Some(i) = line
                .find(['=', ':'])
                .or_else(|| line.find(char::is_whitespace))
            {
                self.add(line[..i].trim(), line[i + 1..].trim());
            }
        }
    }

    fn yaml(&mut self, text: &str) {
        let docs: Vec<serde_json::Value> = serde_saphyr::from_multiple(text).unwrap_or_default();
        for doc in &docs {
            self.flatten("", doc);
        }
    }

    fn flatten(&mut self, prefix: &str, v: &serde_json::Value) {
        match v {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    let key = if prefix.is_empty() {
                        k.clone()
                    } else {
                        format!("{prefix}.{k}")
                    };
                    self.flatten(&key, v);
                }
            }
            serde_json::Value::String(s) => self.add(prefix, s),
            serde_json::Value::Number(n) => self.add(prefix, &n.to_string()),
            serde_json::Value::Bool(b) => self.add(prefix, &b.to_string()),
            _ => {}
        }
    }
}

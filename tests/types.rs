//! `sink_types`: the project's language server decides which sinks count.

mod common;

use common::Repo;

const DB: &str =
    "export class Pool { query(sql: string): Promise<unknown> { return Promise.resolve(sql); } }
export const pool = new Pool();
export class SearchIndex { query(text: string): string[] { return [text]; } }
";

const ROUTES: &str = "import { pool, SearchIndex } from \"./db.js\";
const index = new SearchIndex();

export async function users(req: { query: { name: string } }) {
  const sql = \"SELECT * FROM users WHERE name = '\" + req.query.name + \"'\";
  return pool.query(sql);
}

export function search(req: { query: { q: string } }) {
  const text = \"title:\" + req.query.q;
  return index.query(text);
}
";

fn repo(server: Option<&str>) -> Repo {
    let repo = Repo::new();
    let servers = server.map_or(String::new(), |s| {
        format!("language_servers:\n  typescript: [{s}]\n")
    });
    repo.write(
        ".larpcop.yaml",
        &format!(
            "{servers}taint:\n  - id: taint-sql\n    languages: [TypeScript]\n    message: Request data reaches SQL.\n    \
             sources: [\"req.query\"]\n    sinks: [\"$DB.query($SQL)\"]\n    sink_arg: SQL\n    sink_types: {{ DB: \"\\\\bPool\\\\b\" }}\n"
        ),
    );
    repo.write(
        "package.json",
        "{ \"name\": \"t\", \"private\": true, \"type\": \"module\" }\n",
    );
    repo.write(
        "tsconfig.json",
        "{ \"compilerOptions\": { \"strict\": true, \"module\": \"nodenext\", \"noEmit\": true }, \"include\": [\"src\"] }\n",
    );
    repo.write("src/db.ts", DB);
    repo.write("src/routes.ts", ROUTES);
    repo
}

fn lines(repo: &Repo) -> Vec<u64> {
    let out = repo.run(&["check", "--format", "json"]).stdout();
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    v["violations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["line"].as_u64().unwrap())
        .collect()
}

#[test]
fn without_a_language_server_every_syntactic_sink_counts() {
    assert_eq!(lines(&repo(Some("no-such-language-server"))), [6, 11]);
}

/// The server runs (a rustup proxy without the component does not).
fn installed(bin: &str) -> bool {
    let ok = std::process::Command::new(bin)
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        eprintln!("skipped: {bin} is not installed");
    }
    ok
}

#[test]
fn the_language_server_resolves_types_across_files() {
    if !installed("typescript-language-server") {
        return;
    }
    // `pool` is a Pool imported from db.ts; `index` is a SearchIndex.
    assert_eq!(lines(&repo(None)), [6]);
}

/// A Go or Rust project where `pool.Query(sql)` and `index.Query(sql)` take
/// the same tainted string; only `Pool` is a database.
fn typed_repo(lang: &str, source: &str, files: &[(&str, &str)]) -> Repo {
    let repo = Repo::new();
    repo.write(
        ".larpcop.yaml",
        &format!(
            "taint:\n  - id: taint-sql\n    languages: [{lang}]\n    message: Input reaches SQL.\n    \
             sources: [\"{source}\"]\n    sinks: [\"$DB.$Q($SQL)\"]\n    sink_arg: SQL\n    sink_types: {{ DB: \"\\\\bPool\\\\b\" }}\n"
        ),
    );
    for (path, text) in files {
        repo.write(path, text);
    }
    repo
}

#[test]
fn gopls_resolves_go_types() {
    if !installed("gopls") {
        return;
    }
    let repo = typed_repo(
        "Go",
        "$R.URL.Query()",
        &[
            ("go.mod", "module example.com/t\n\ngo 1.22\n"),
            (
                "db/db.go",
                "package db\n\ntype Pool struct{}\ntype Index struct{}\n\nfunc (Pool) Query(sql string)   {}\nfunc (Index) Query(text string) {}\n",
            ),
            (
                "main.go",
                "package main\n\nimport (\n\t\"net/http\"\n\n\t\"example.com/t/db\"\n)\n\nfunc handler(w http.ResponseWriter, r *http.Request) {\n\tpool := db.Pool{}\n\tindex := db.Index{}\n\tsql := \"select \" + r.URL.Query().Get(\"name\")\n\tpool.Query(sql)\n\tindex.Query(sql)\n}\n\nfunc main() { http.HandleFunc(\"/\", handler) }\n",
            ),
        ],
    );
    assert_eq!(lines(&repo), [13]);
}

#[test]
fn rust_analyzer_resolves_rust_types() {
    if !installed("rust-analyzer") {
        return;
    }
    let repo = typed_repo(
        "Rust",
        "std::env::args",
        &[
            (
                "Cargo.toml",
                "[package]\nname = \"t\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            ),
            (
                "src/db.rs",
                "pub struct Pool;\npub struct Index;\nimpl Pool {\n    pub fn query(&self, _sql: &str) {}\n}\nimpl Index {\n    pub fn query(&self, _text: &str) {}\n}\n",
            ),
            (
                "src/main.rs",
                "mod db;\nuse db::{Index, Pool};\n\nfn main() {\n    let arg = std::env::args().nth(1).unwrap_or_default();\n    let sql = String::from(\"select \") + &arg;\n    Pool.query(&sql);\n    Index.query(&sql);\n}\n",
            ),
        ],
    );
    assert_eq!(lines(&repo), [7]);
}

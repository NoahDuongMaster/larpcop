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

#[test]
fn the_language_server_resolves_types_across_files() {
    let on_path = std::env::var_os("PATH").is_some_and(|p| {
        std::env::split_paths(&p).any(|d| {
            [
                "typescript-language-server",
                "typescript-language-server.cmd",
            ]
            .iter()
            .any(|b| d.join(b).is_file())
        })
    });
    if !on_path {
        eprintln!("skipped: typescript-language-server is not installed");
        return;
    }
    // `pool` is a Pool imported from db.ts; `index` is a SearchIndex.
    assert_eq!(lines(&repo(None)), [6]);
}

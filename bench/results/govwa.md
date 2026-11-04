# GoVWA

[0c34/govwa](https://github.com/0c34/govwa) `4058f79`: Go, net/http and html/template.

Answer key: `bench/truth/govwa-truth.json`, 4 lines taken from the project's own vulnerability comments in `vulnerability/sqli` and `vulnerability/xss` (IDOR and client-side authentication are logic flaws, and the XXE module is an empty file). A line counts as found when a larpcop security finding lies within three lines of it in the same file. The Go rules were extended after the first run on this suite (XSS rules, SQL built before the query call, methods resolved by receiver), so the result is not a held-out number.

| Line | Vulnerability | larpcop |
|---|---|---|
| `vulnerability/sqli/function.go:39` | SQL injection (fmt.Sprintf of the uid form value, called from sqli.go) | `go-no-sql-sprintf` |
| `vulnerability/xss/xss.go:59` | Reflected XSS (template.HTML of the search term) | `go-no-unsafe-template-type`, `go-taint-xss` |
| `vulnerability/xss/xss.go:63` | Reflected XSS (template.HTML of the search term, second branch) | `go-no-unsafe-template-type`, `go-taint-xss` |
| `vulnerability/xss/xss.go:100` | XSS in inline JavaScript (template.HTML of a script built from the uid form value) | `go-no-unsafe-template-type`, `go-taint-xss` |

- larpcop: 4/4 lines; 18 security findings: go-no-unsafe-template-type 6, go-taint-xss 5, gha-unpinned-action 2, go-no-sql-sprintf 2, go-taint-sql 2, dependency-vulnerability 1

Missed: none.

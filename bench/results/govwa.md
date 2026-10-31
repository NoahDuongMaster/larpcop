| Line | Vulnerability | larpcop | Semgrep OSS |
|---|---|---|---|
| `vulnerability/sqli/function.go:39` | SQL injection (fmt.Sprintf of the uid form value, called from sqli.go) | `go-no-sql-sprintf` | `string-formatted-query` |
| `vulnerability/xss/xss.go:59` | Reflected XSS (template.HTML of the search term) | `go-no-unsafe-template-type`, `go-taint-xss` | `formatted-template-string`, `raw-html-format`, `unsafe-template-type` |
| `vulnerability/xss/xss.go:63` | Reflected XSS (template.HTML of the search term, second branch) | `go-no-unsafe-template-type`, `go-taint-xss` | `formatted-template-string`, `raw-html-format`, `unsafe-template-type` |
| `vulnerability/xss/xss.go:100` | XSS in inline JavaScript (template.HTML of a script built from the uid form value) | `go-no-unsafe-template-type`, `go-taint-xss` | `formatted-template-string`, `unsafe-template-type` |

- larpcop: 4/4 lines; 18 security findings: go-no-unsafe-template-type 6, go-taint-xss 5, gha-unpinned-action 2, go-no-sql-sprintf 2, go-taint-sql 2, dependency-vulnerability 1
- Semgrep OSS: 4/4 lines; 44 security findings: unsafe-template-type 6, plaintext-http-link 5, formatted-template-string 4, use-of-md5 3, raw-html-format 3, github-actions-mutable-action-tag 2, prototype-pollution-loop 2, missing-integrity 2, session-cookie-missing-httponly 2, session-cookie-missing-secure 2, cookie-missing-httponly 2, cookie-missing-secure 2, string-formatted-query 2, missing-user 1, no-new-privileges 1, writable-filesystem-service 1, detect-non-literal-regexp 1, django-no-csrf-token 1, gosql-sqli 1, no-direct-write-to-responsewriter 1

Secrets vs gitleaks: 0 identical findings; 0 only in gitleaks, 0 only in larpcop.

| Line | Vulnerability | larpcop | Semgrep OSS |
|---|---|---|---|
| `src/controllers/passphrase.js:44` | 1 SQL injection (INSERT built from req.body) | `no-sql-interpolation`, `taint-sql`, `validate-request-input` | `express-sequelize-injection` |
| `src/controllers/passphrase.js:59` | 1 SQL injection (SELECT by req.params.username) | `no-sql-interpolation`, `taint-sql`, `validate-request-input` | `direct-response-write`, `express-sequelize-injection` |
| `src/controllers/notes.js:164` | 2 NoSQL injection ($where) | `no-mongo-where`, `taint-nosql`, `validate-request-input` | `direct-response-write` |
| `src/controllers/notes.js:69` | 3 OS command injection (exec of req.params.command) | `no-shell-interpolation`, `taint-shell`, `validate-request-input` | `detect-child-process` |
| `src/utils/vulnerable-xml.js:81` | 4/5 XXE and XML bomb (custom entity expansion) | – | – |
| `src/services/xml-rpc/server.js:29` | 6 SSRF (needle.get of a URL from the request) | – | – |
| `src/controllers/passphrase.js:96` | 7 Insecure deserialization (node-serialize) | `no-unsafe-deserialization`, `validate-request-input` | `express-third-party-object-deserialization` |
| `src/controllers/notes.js:81` | 8 XPath injection | `taint-code`, `validate-request-input` | – |
| `src/controllers/users.js:656` | 9 LDAP injection (filter built from input) | `no-ldap-interpolation`, `validate-request-input` | – |
| `src/controllers/files.js:93` | 10 Path traversal (download path from req.body.filename) | `taint-path`, `validate-request-input` | `express-path-join-resolve-traversal`, `path-join-resolve-traversal` |
| `src/server.js:40` | 16 JWT verification accepts alg none | `no-jwt-none-algorithm` | – |
| `.env:4` | 17 Weak JWT secret | `no-env-file-secrets` | – |
| `src/controllers/users.js:138` | 20 Open redirect | `taint-redirect`, `validate-request-input` | `express-open-redirect` |
| `src/controllers/files.js:19` | 28 Prototype pollution (recursive merge) | `no-unsafe-recursive-merge` | – |
| `src/graphql/schema.js:123` | 34 GraphQL arbitrary file write (path from args) | `taint-path` | – |

- larpcop: 13/15 lines; 159 security findings: validate-request-input 52, dependency-vulnerability 39, taint-nosql 14, no-unescaped-template-output 12, no-jwt-none-algorithm 8, taint-path 7, gha-unpinned-action 3, no-sql-interpolation 3, taint-sql 3, no-env-file-secrets 2, no-unsafe-recursive-merge 2, no-eval 2, taint-code 2, no-mongo-where 2, no-unsafe-deserialization 2, secrets 1, no-shell-interpolation 1, taint-shell 1, taint-xss 1, taint-redirect 1, no-ldap-interpolation 1
- Semgrep OSS: 7/15 lines; 33 security findings: path-join-resolve-traversal 6, direct-response-write 4, github-actions-mutable-action-tag 3, no-new-privileges 2, writable-filesystem-service 2, express-path-join-resolve-traversal 2, express-sequelize-injection 2, express-check-csurf-middleware-usage 2, detected-jwt-token 1, missing-user 1, npm-missing-minimum-release-age 1, express-data-exfiltration 1, detect-child-process 1, express-third-party-object-deserialization 1, express-open-redirect 1, jwt-decode-without-verify 1, detect-non-literal-regexp 1, raw-html-format 1

Secrets vs gitleaks: 1 identical findings; 0 only in gitleaks, 0 only in larpcop.

| Line | Vulnerability | larpcop | Semgrep OSS |
|---|---|---|---|
| `app/routes/contributions.js:32` | A1-1 server-side JS injection (eval of req.body) | `no-eval`, `taint-code`, `validate-request-input` | `code-string-concat`, `eval-detected` |
| `app/routes/contributions.js:33` | A1-1 server-side JS injection (eval of req.body) | `no-eval`, `taint-code`, `validate-request-input` | `code-string-concat`, `eval-detected` |
| `app/routes/contributions.js:34` | A1-1 server-side JS injection (eval of req.body) | `no-eval`, `taint-code`, `validate-request-input` | `code-string-concat`, `eval-detected` |
| `app/data/allocations-dao.js:78` | A1-2 NoSQL injection ($where with threshold) | `no-mongo-where` | – |
| `app/routes/session.js:64` | A1-3 log injection (user name logged raw) | `taint-log` | – |
| `app/routes/profile.js:59` | ReDoS (/([0-9]+)+\#/) | `no-regex-redos` | – |
| `app/routes/allocations.js:18` | A4 insecure direct object reference (userId from URL) | `validate-request-input` | – |
| `app/data/user-dao.js:25` | A2-1 password stored in plain text | – | – |
| `app/data/user-dao.js:61` | A2 password compared in plain text | `no-plaintext-password-compare` | – |
| `app/routes/session.js:144` | A2-2 weak password policy | – | – |
| `server.js:137` | A3 XSS (template autoescape off) | `no-template-autoescape-off` | – |
| `app/routes/index.js:72` | A10 open redirect (req.query.url) | `taint-redirect`, `validate-request-input` | `express-open-redirect` |
| `app/routes/research.js:16` | SSRF (needle.get of req.query.url) | `taint-ssrf`, `validate-request-input` | – |
| `package-lock.json:6742` | A9 vulnerable dependency (marked 0.3.5) | `dependency-vulnerability` | – |

- larpcop: 12/14 lines; 241 security findings: dependency-vulnerability 204, validate-request-input 14, gha-unpinned-action 6, no-eval 3, taint-code 3, secrets 3, no-shell-interpolation 1, no-mongo-where 1, no-plaintext-password-compare 1, taint-redirect 1, no-regex-redos 1, taint-ssrf 1, taint-log 1, no-template-autoescape-off 1
- Semgrep OSS: 4/14 lines; 35 security findings: github-actions-mutable-action-tag 6, plaintext-http-link 5, eval-detected 3, code-string-concat 3, django-no-csrf-token 3, detected-bcrypt-hash 3, express-open-redirect 1, detected-private-key 1, no-new-privileges 1, writable-filesystem-service 1, express-check-csurf-middleware-usage 1, express-cookie-session-default-name 1, express-cookie-session-no-domain 1, express-cookie-session-no-expires 1, express-cookie-session-no-httponly 1, express-cookie-session-no-path 1, express-cookie-session-no-secure 1, using-http-server 1

Secrets vs gitleaks: 3 identical findings; 0 only in gitleaks, 0 only in larpcop.

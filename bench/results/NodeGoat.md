# NodeGoat

[OWASP/NodeGoat](https://github.com/OWASP/NodeGoat) `c5cb68a`: JavaScript, Express and MongoDB.

Answer key: `bench/truth/nodegoat-truth.json`, 14 lines taken from the project's tutorial. A line counts as found when a larpcop security finding lies within three lines of it in the same file. Rules for four gaps this suite exposed (ReDoS, log injection, template autoescape off, plaintext password comparison) were added after its first run, so the result is not a held-out number.

| Line | Vulnerability | larpcop |
|---|---|---|
| `app/routes/contributions.js:32` | A1-1 server-side JS injection (eval of req.body) | `no-eval`, `taint-code`, `validate-request-input` |
| `app/routes/contributions.js:33` | A1-1 server-side JS injection (eval of req.body) | `no-eval`, `taint-code`, `validate-request-input` |
| `app/routes/contributions.js:34` | A1-1 server-side JS injection (eval of req.body) | `no-eval`, `taint-code`, `validate-request-input` |
| `app/data/allocations-dao.js:78` | A1-2 NoSQL injection ($where with threshold) | `no-mongo-where` |
| `app/routes/session.js:64` | A1-3 log injection (user name logged raw) | `taint-log` |
| `app/routes/profile.js:59` | ReDoS (/([0-9]+)+\#/) | `no-regex-redos` |
| `app/routes/allocations.js:18` | A4 insecure direct object reference (userId from URL) | `validate-request-input` |
| `app/data/user-dao.js:25` | A2-1 password stored in plain text | – |
| `app/data/user-dao.js:61` | A2 password compared in plain text | `no-plaintext-password-compare` |
| `app/routes/session.js:144` | A2-2 weak password policy | – |
| `server.js:137` | A3 XSS (template autoescape off) | `no-template-autoescape-off` |
| `app/routes/index.js:72` | A10 open redirect (req.query.url) | `taint-redirect`, `validate-request-input` |
| `app/routes/research.js:16` | SSRF (needle.get of req.query.url) | `taint-ssrf`, `validate-request-input` |
| `package-lock.json:6742` | A9 vulnerable dependency (marked 0.3.5) | `dependency-vulnerability` |

- larpcop: 12/14 lines; 241 security findings: dependency-vulnerability 204, validate-request-input 14, gha-unpinned-action 6, no-eval 3, taint-code 3, secrets 3, no-shell-interpolation 1, no-mongo-where 1, no-plaintext-password-compare 1, taint-redirect 1, no-regex-redos 1, taint-ssrf 1, taint-log 1, no-template-autoescape-off 1

Missed: the password stored in plain text (`app/data/user-dao.js:25`, an assignment rather than a comparison) and the weak password policy (`app/routes/session.js:144`).

| Line | Vulnerability | larpcop | Semgrep OSS |
|---|---|---|---|
| `core/appHandler.js:10` | A1 SQL injection (query built from req.body.login) | `taint-sql`, `validate-request-input` | `express-sequelize-injection` |
| `core/appHandler.js:39` | A1 command injection (exec of req.body.address) | `no-shell-interpolation`, `taint-shell`, `validate-request-input` | – |
| `server.js:24` | A2 hard-coded session secret | `no-hardcoded-session-secret` | `express-cookie-session-default-name`, `express-cookie-session-no-domain`, `express-cookie-session-no-expires`, `express-cookie-session-no-httponly`, `express-cookie-session-no-path`, `express-cookie-session-no-secure`, `express-session-hardcoded-secret` |
| `core/appHandler.js:207` | A3 every user's record returned by the API | – | – |
| `core/appHandler.js:235` | A4 XXE (libxmljs noent:true) | `no-xml-external-entities` | `express-libxml-noent` |
| `routes/app.js:42` | A5 admin API without an authorization check | – | – |
| `core/appHandler.js:145` | A5 IDOR (user edited by req.body.id) | `validate-request-input` | – |
| `core/appHandler.js:197` | A6/A9 mathjs.eval of req.body.eqn | `taint-code`, `validate-request-input` | – |
| `views/app/products.ejs:20` | A7 reflected XSS (<%- searchTerm %>) | `no-unescaped-template-output` | `template-explicit-unescape` |
| `views/app/products.ejs:50` | A7 stored XSS (<%- product name %>) | `no-unescaped-template-output` | `template-explicit-unescape` |
| `views/app/adminusers.ejs:41` | A7 DOM XSS (innerHTML) | `no-inner-html-in-templates` | – |
| `core/appHandler.js:218` | A8 insecure deserialization (node-serialize) | `no-unsafe-deserialization` | `express-third-party-object-deserialization` |
| `package.json:25` | A9 vulnerable component (mathjs 3.10.1) | `dependency-vulnerability` | – |
| `core/appHandler.js:188` | Open redirect (req.query.url) | `taint-redirect`, `validate-request-input` | `express-open-redirect` |

- larpcop: 12/14 lines; 87 security findings: validate-request-input 65, no-unescaped-template-output 6, dependency-vulnerability 4, no-inner-html-in-templates 3, no-unsafe-deserialization 2, taint-sql 1, no-shell-interpolation 1, taint-shell 1, taint-redirect 1, taint-code 1, no-xml-external-entities 1, no-hardcoded-session-secret 1
- Semgrep OSS: 7/14 lines; 23 security findings: template-explicit-unescape 6, missing-user 1, sequelize-enforce-tls 1, express-sequelize-injection 1, express-open-redirect 1, express-third-party-object-deserialization 1, express-libxml-noent 1, no-new-privileges 1, writable-filesystem-service 1, path-join-resolve-traversal 1, express-check-csurf-middleware-usage 1, express-cookie-session-default-name 1, express-cookie-session-no-domain 1, express-cookie-session-no-expires 1, express-cookie-session-no-httponly 1, express-cookie-session-no-path 1, express-cookie-session-no-secure 1, express-session-hardcoded-secret 1

Secrets vs gitleaks: 0 identical findings; 0 only in gitleaks, 0 only in larpcop.

# DVNA

[appsecco/dvna](https://github.com/appsecco/dvna) `9ba473a`: JavaScript, Express, Sequelize and EJS.

Answer key: `bench/truth/dvna-truth.json`, 14 lines taken from the project's `docs/solution/*.md`. A line counts as found when a larpcop security finding lies within three lines of it in the same file. Rules for the gaps this suite exposed (hard-coded session secret, XXE, unsafe deserialization, `mathjs.eval`, unescaped output in EJS templates) were added after its first run, so the result is not a held-out number.

| Line | Vulnerability | larpcop |
|---|---|---|
| `core/appHandler.js:10` | A1 SQL injection (query built from req.body.login) | `no-sql-interpolation`, `taint-sql`, `validate-request-input` |
| `core/appHandler.js:39` | A1 command injection (exec of req.body.address) | `no-shell-interpolation`, `taint-shell`, `validate-request-input` |
| `server.js:24` | A2 hard-coded session secret | `no-hardcoded-session-secret` |
| `core/appHandler.js:207` | A3 every user's record returned by the API | – |
| `core/appHandler.js:235` | A4 XXE (libxmljs noent:true) | `no-xml-external-entities` |
| `routes/app.js:42` | A5 admin API without an authorization check | – |
| `core/appHandler.js:145` | A5 IDOR (user edited by req.body.id) | `validate-request-input` |
| `core/appHandler.js:197` | A6/A9 mathjs.eval of req.body.eqn | `taint-code`, `validate-request-input` |
| `views/app/products.ejs:20` | A7 reflected XSS (<%- searchTerm %>) | `no-unescaped-template-output` |
| `views/app/products.ejs:50` | A7 stored XSS (<%- product name %>) | `no-unescaped-template-output` |
| `views/app/adminusers.ejs:41` | A7 DOM XSS (innerHTML) | `no-inner-html-in-templates` |
| `core/appHandler.js:218` | A8 insecure deserialization (node-serialize) | `no-unsafe-deserialization` |
| `package.json:25` | A9 vulnerable component (mathjs 3.10.1) | `dependency-vulnerability` |
| `core/appHandler.js:188` | Open redirect (req.query.url) | `taint-redirect`, `validate-request-input` |

- larpcop: 12/14 lines; 88 security findings: validate-request-input 65, no-unescaped-template-output 6, dependency-vulnerability 4, no-inner-html-in-templates 3, no-unsafe-deserialization 2, no-sql-interpolation 1, taint-sql 1, no-shell-interpolation 1, taint-shell 1, taint-redirect 1, taint-code 1, no-xml-external-entities 1, no-hardcoded-session-secret 1

Missed: the API that returns every user's record (`core/appHandler.js:207`) and the admin route without an authorization check (`routes/app.js:42`). Both are access-control flaws.

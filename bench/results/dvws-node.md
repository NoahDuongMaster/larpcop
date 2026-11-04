# DVWS-Node

[snoopysecurity/dvws-node](https://github.com/snoopysecurity/dvws-node) `e83689c`: JavaScript, Express, MongoDB, MySQL, GraphQL and SOAP/XML-RPC.

Answer key: `bench/truth/dvws-truth.json`, 15 lines taken from the project's `CHALLENGES.md`: every challenge whose flaw sits on a single line of code (design flaws such as IDOR, CORS and missing rate limits are excluded). A line counts as found when a larpcop security finding lies within three lines of it in the same file. Rules for the gaps this suite exposed (JWT `alg: none`, LDAP filter concatenation, secrets in a committed `.env`, GraphQL resolver arguments as request data) were added after its first run, so the result is not a held-out number.

| Line | Vulnerability | larpcop |
|---|---|---|
| `src/controllers/passphrase.js:44` | 1 SQL injection (INSERT built from req.body) | `no-sql-interpolation`, `taint-sql`, `validate-request-input` |
| `src/controllers/passphrase.js:59` | 1 SQL injection (SELECT by req.params.username) | `no-sql-interpolation`, `taint-sql`, `validate-request-input` |
| `src/controllers/notes.js:164` | 2 NoSQL injection ($where) | `no-mongo-where`, `taint-nosql`, `validate-request-input` |
| `src/controllers/notes.js:69` | 3 OS command injection (exec of req.params.command) | `no-shell-interpolation`, `taint-shell`, `validate-request-input` |
| `src/utils/vulnerable-xml.js:81` | 4/5 XXE and XML bomb (custom entity expansion) | – |
| `src/services/xml-rpc/server.js:29` | 6 SSRF (needle.get of a URL from the request) | – |
| `src/controllers/passphrase.js:96` | 7 Insecure deserialization (node-serialize) | `no-unsafe-deserialization`, `validate-request-input` |
| `src/controllers/notes.js:81` | 8 XPath injection | `taint-code`, `validate-request-input` |
| `src/controllers/users.js:656` | 9 LDAP injection (filter built from input) | `no-ldap-interpolation`, `validate-request-input` |
| `src/controllers/files.js:93` | 10 Path traversal (download path from req.body.filename) | `taint-path`, `validate-request-input` |
| `src/server.js:40` | 16 JWT verification accepts alg none | `no-jwt-none-algorithm` |
| `.env:4` | 17 Weak JWT secret | `no-env-file-secrets` |
| `src/controllers/users.js:138` | 20 Open redirect | `taint-redirect`, `validate-request-input` |
| `src/controllers/files.js:19` | 28 Prototype pollution (recursive merge) | `no-unsafe-recursive-merge` |
| `src/graphql/schema.js:123` | 34 GraphQL arbitrary file write (path from args) | `taint-path` |

- larpcop: 13/15 lines; 159 security findings: validate-request-input 52, dependency-vulnerability 39, taint-nosql 14, no-unescaped-template-output 12, no-jwt-none-algorithm 8, taint-path 7, gha-unpinned-action 3, no-sql-interpolation 3, taint-sql 3, no-env-file-secrets 2, no-unsafe-recursive-merge 2, no-eval 2, taint-code 2, no-mongo-where 2, no-unsafe-deserialization 2, secrets 1, no-shell-interpolation 1, taint-shell 1, taint-xss 1, taint-redirect 1, no-ldap-interpolation 1

Missed: the XXE and XML bomb in a hand-written entity expander (`src/utils/vulnerable-xml.js:81`, which uses no XML parser) and the SSRF through a parameter of an XML-RPC method (`src/services/xml-rpc/server.js:29`, where the `xmlrpc` library is not a declared source).

# Writing rules and the recommended bundle

This page covers how to write rules so they cannot be dodged, how `fix:` and rule fixtures work, what the `recommended` bundle contains, and the code-quality metrics, CI reports, PR comment and language server.

[Back to the README](../README.md)

## Write rules by meaning

Agents will find loopholes. When Codex was run for real, it dodged the `console.$METHOD(...)` rule by writing `globalThis["console"]["log"](x)`, and that rule still reported clean. A rule must catch the *structure* under every way of writing it: identifier, property access, and computed-key access. See `no-console` in [rules/typescript.yml](../examples/standards/rules/typescript.yml) and the regression test `no_console_cannot_be_dodged`. The message sent to the agent also says plainly that rewriting the code to dodge a rule still counts as a violation.

### Rules on values

A rule that checks a *value* rather than the way it is written declares `metadata.resolve`. A match is kept only if the metavariable can carry a string that matches the regex at runtime. The value is traced through literals, local variables assigned once, file constants (`static final String ALG = "MD5"`, module-level `ALG = "md5"`), `props.getProperty("hashAlg1", "SHA512")` and Spring `@Value("${crypto.alg:MD5}")` fields. Values are read from the project's `.properties` and `application*.yml` files (test directories excluded). A value that cannot be determined is not reported.

```yaml
id: java-no-weak-hash
language: Java
rule: { pattern: MessageDigest.getInstance($ALG) }
metadata:
  resolve: { ALG: "(?i)^(md2|md4|md5|sha|sha-?1)$" }
```

## Fixes and rule tests

An ast-grep rule with `fix:` gets a `larpcop fix <file>` hint on its violations. A fix runs for at most 5 passes and skips fixes that overlap within the same pass.

`larpcop test` reads fixtures in the ast-grep format (`rule-tests/<id>-test.yml` with `valid`/`invalid`), plus `fixed: [{before, after}]` to check `fix:`. Taint rules and `text:` rules use the same format: each snippet is checked as a file in each of the rule's languages (a `text:` rule declares `file: views/page.ejs`). `--require-all` makes CI fail when any rule, of any kind, has no fixture.

## The recommended bundle

[`standards/recommended`](../standards/recommended) is the rule bundle that larpcop maintains, versioned by the tags of the repo:

```yaml
extends:
  - https://github.com/NoahDuongMaster/larpcop.git#v0.3.0//standards/recommended
```

(`URL#tag//directory` takes a subdirectory of the standards repo.) The bundle has 93 ast-grep rules, 99 taint rules, 6 `text:` rules, plus secrets and `dependency-vulnerability`. Security rules and the length and complexity metrics do not apply to test files (`test/`, `tests/`, `*.spec.*`, `test_*.py`, `tests.py`…). Quality rules (`no-explicit-any`, `no-console`, `no-empty-catch`…) still apply. In a trial run on the `expressjs/express` repo, the Express tests account for 96 of the 129 `validate-request-input` findings and 118 of the 120 `function-length` findings. Minified files (average line length above 300 bytes, such as `prism.js` or `jquery-3.2.1-min.js` committed into a repo) are scanned for secrets only, because a secret can sit inside a bundle. Go methods are known by their receiver type (`Profile.Load`), Rust methods by the type of the `impl`. Every rule comes with a fixture, and `larpcop test standards/recommended --require-all` runs in `cargo test`.

### Categories

- **Security bugs turned into syntax conventions** (no taint needed). The rules in this category cover:
  - SQL only through parameters (`no-sql-interpolation`, `py-no-sql-interpolation`, `go-no-sql-sprintf`). A string shaped like a SQL statement that is concatenated or formatted anywhere is caught, not only inside a `query` call.
  - Shell commands only through an argument array (`no-shell-interpolation`, `py-no-shell-true`). `java-no-shell-string` and `kt-no-shell-string` catch `Runtime.exec("sh -c …" + x)`. `exec("ls " + dir)` is not caught, because no shell runs: `Runtime.exec(String)` only splits on whitespace.
  - No `eval`, `new Function` or `exec`.
  - No assigning HTML from a variable to `innerHTML`.
  - No `dangerouslySetInnerHTML` or `bypassSecurityTrust*` (Angular).
  - No `serve-index`.
  - No MD5 or SHA-1, including `DigestUtils.md5Hex` of Commons Codec and Spring, and `Hashing.md5()` of Guava.
  - No MongoDB `$where`.
  - Request input must go through a schema (`validate-request-input`).
  - No turning off TLS certificate verification (`py-no-tls-verify-off`, `go-no-insecure-tls`).
  - `yaml.safe_load` (with auto-fix).
  - Regexes with nested quantifiers (ReDoS).
  - Turning off template autoescape.
  - Comparing passwords in plain text.
  - Hardcoded session or JWT secrets.
  - XML with external entities enabled (XXE).
  - Deserialization libraries that can run code (`node-serialize`, `pickle`).
  - Recursive merge functions that do not block `__proto__` (prototype pollution).
  - Writing a user into the server-side session without issuing a new session id (session fixation: `req.session.regenerate`, `new_session` of aiohttp).
- **Not turning checks off**: `@ts-ignore`, `@ts-expect-error`, `eslint-disable` and `biome-ignore` are violations; so are `any`, an empty catch, and `debugger` (with auto-fix).
- **Size and complexity**: functions of at most 80 lines, cyclomatic (McCabe) complexity of at most 15, files of at most 500 lines.
- **Framework misconfiguration**: Django (`DEBUG = True` in a settings file that is not dev or local, `ALLOWED_HOSTS = ["*"]`, `@csrf_exempt` except on webhook views), Flask (`debug=True`), Spring (CSRF `.disable()`, `@CrossOrigin` and `allowedOrigins("*")`, `management.endpoints.web.exposure.include=*`), Laravel (`$guarded = []`), Express and Node (`cors()` with no arguments, `Access-Control-Allow-Origin: *`).

Rules for JavaScript and TypeScript are generated for TypeScript, Tsx and JavaScript under the **same id** (`scripts/gen-recommended.py`), so `disable` or `locked` on one id applies to all three.

## Code quality

The features below replace Sonar and Codacy.

- **Metrics**: `larpcop metrics [--top N] [--json]` reports line count, function count, and the cyclomatic complexity of each function. It counts on the tree-sitter tree, for every language that ast-grep can read, and nested functions are counted separately. On this repository at the time of writing: 651 files, 4,122 functions, average 1.92. Enforce limits in config:

  ```yaml
  metrics:
    max_complexity: 15        # rule `complexity`
    max_function_lines: 80    # rule `function-length`
  ```

- **CI reports**: `--format sarif|gitlab|markdown`, or write several formats at once with `--output FORMAT=FILE`. The SARIF output was checked against the official SARIF 2.1.0 schema (0 errors) and has `partialFingerprints` that stay stable when code shifts lines. GitLab Code Quality has its own fingerprint for each issue.
- **PR comment**: the [`enforce.yml`](../.github/workflows/enforce.yml) workflow writes `larpcop-report.md` and keeps **one** comment on the PR, edited after every push (`comment: true`, the default). `sarif: true` uploads the results to GitHub code scanning.
- **LSP**: `larpcop lsp` gives diagnostics as you type (including unsaved buffers) and the code action "apply rule fixes". It was run in a real Neovim 0.12, where it showed `no-sql-interpolation` and `no-debugger` correctly and offered the code action. That run exposed a bug: a malformed request made the server exit. The server now returns an `InvalidParams` error and keeps running (there is a regression test).

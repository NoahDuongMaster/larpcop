# Security checks

This page describes the security layers in larpcop: syntax conventions, text rules for templates and config files, secret detection, and the known limits for logic flaws and CSRF.

[Back to the README](../README.md)

There are four layers, ordered by certainty. The first layer is 100% deterministic, and the later layers catch the rest.

1. Syntax conventions (the `recommended` set), described below.
2. Cross-function and cross-file taint, described in [taint](taint.md).
3. Secrets, described below.
4. Vulnerabilities and malware in dependencies, described in [dependencies](dependencies.md).

## Syntax conventions

The `recommended` set (see [`standards/recommended`](../standards/recommended)) does not trace the bug. It bans the way of writing that leads to the bug:

- SQL only through parameters.
- Shell commands only through argument arrays.
- Request data only after it has passed a schema. The rule `validate-request-input` requires `req.body`, `req.query`, `req.params` and `request.json()` to sit inside `X.parse(…)`/`safeParse`/`validate`….

That way, the bug cannot be written in the first place, and ast-grep catches these cases exactly (100%), with the same result on every run.

## Text rules

Templates and files without a grammar are covered by `text:` rules. A `text:` rule is a regex on files selected by glob (templates, HTML, config):

```yaml
text:
  - id: no-unescaped-template-output
    files: ["**/*.ejs", "**/*.hbs", "**/*.njk", "**/*.html", "**/*.vue"]
    regex: '<%-[^%]*%>|\{\{\{|\|\s*safe\b|\bv-html\s*='
    not: '^<%-\s*include\b'          # a match that also matches `not` is skipped
    message: Template output written without HTML escaping (XSS).
  - id: rb-csrf-off
    files: ["app/controllers/application_controller.rb"]
    regex: 'class\s+ApplicationController\s*<\s*ActionController::Base'
    unless:                          # the rule is off when one of the conditions matches
      - regex: '(?m)^\s*protect_from_forgery\b'              # on this same file
      - file: config/application.rb                           # or on another file in the repo
        regex: 'load_defaults\s*\(?\s*[''"]?(5\.[2-9]|[6-9])'
    message: CSRF protection is off.
```

The `recommended` set has 6 rules of this kind:

1. `no-unescaped-template-output`: output written without escaping. EJS `<%-`, Handlebars `{{{`, Jinja/Nunjucks `|safe` and `autoescape false`, Blade `{!!`, ERB `raw`/`html_safe`, Svelte `{@html}`, Vue `v-html`, Razor `Html.Raw`.
2. `pug-no-unescaped-output`: Pug `!=`/`!{}`.
3. `no-env-file-secrets`: a real secret in a committed `.env` file. Sample values such as `changeme` and `${VAR}` are skipped.
4. `spring-actuator-exposed`: Spring Boot exposing every actuator endpoint (`management.endpoints.web.exposure.include=*` in `application*` and `bootstrap*` files).
5. `mybatis-sql-interpolation`: MyBatis `${}` in a mapper XML (SQL injection). `${criterion.condition}` and `${orderByClause}` from MyBatis Generator are skipped.
6. `rb-csrf-off`: Rails with CSRF turned off. The ApplicationController does not call `protect_from_forgery` while the app does not load the Rails 5.2+ defaults.

`innerHTML` and `document.write` in the `<script>` of a template are not text rules: the page script is read as JavaScript, so the JavaScript rules and the DOM taint rules apply to it (see [taint](taint.md)).

## Secrets

`secrets: {}` turns on the 222 detectors of [gitleaks](https://github.com/gitleaks/gitleaks). Gitleaks is MIT licensed. larpcop embeds `gitleaks.toml` unchanged in the binary, and its license is in `assets/` ([`assets/gitleaks.LICENSE`](../assets/gitleaks.LICENSE)). Filtering by keyword, regex, entropy and allowlist follows the semantics of gitleaks exactly.

The output is redacted and keeps only the first 4 characters (`ghp_…[redacted]`).

`exclude` skips fixtures that contain fake keys. A rule that is locked cannot add `exclude`.

The hook also blocks agents from writing secrets into files.

## Limitations

### Logic and authorization flaws

IDOR, a missing admin permission check and returning too much data have no common syntax form. On the three benchmark sets (see [benchmarks](benchmarks.md)), this is the part that no SAST tool catches.

The `llm` rule (`larpcop review`) targets this kind of flaw, but it only gives warnings, because the model is not deterministic. `larpcop learn` gradually turns repeated review comments into deterministic rules. Both commands are described in [ai-review](ai-review.md).

### CSRF

There is no general CSRF rule for the missing-token case. A handler that changes state with `GET` differs from a correct handler only in that it does not check a token, and the absence of a call is satisfied by every file. XVWA has one such line. It is counted in the benchmark thanks to another finding one line away, and the report says so.

The `recommended` set does flag some explicit opt-outs, for example `rb-csrf-off` (the Rails `text:` rule in [Text rules](#text-rules)), `py-django-csrf-exempt` (`@csrf_exempt`, except on webhook views) and `java-spring-csrf-disabled` (Spring's CSRF `.disable()`). The last two are framework misconfiguration rules, listed in [rules](rules.md).

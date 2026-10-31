#!/usr/bin/env python3
"""Generates standards/recommended/rules/*.yml from one spec per rule.

JS-family rules are emitted once per language (TypeScript, Tsx, JavaScript)
under the same id, because an ast-grep rule targets exactly one grammar.
Run from the repo root: python3 scripts/gen-recommended.py
"""
import json
import pathlib
import sys

OUT = pathlib.Path("standards/recommended/rules")
JS = ["TypeScript", "Tsx", "JavaScript"]
TS = ["TypeScript", "Tsx"]
WORKFLOWS = [".github/workflows/*.yml", ".github/workflows/*.yaml"]
UNTRUSTED = ("\\$\\{\\{\\s*(github\\.event\\.(issue|pull_request|comment|review|review_comment|discussion|"
             "discussion_comment|pages|head_commit|commits|workflow_run|release)\\b[^}]*|github\\.head_ref)\\s*\\}\\}")

# Each: id, languages, severity, message, note, rule (dict), optional fix.
RULES = [
    # ---- JavaScript / TypeScript: security conventions ------------------------
    dict(id="no-sql-interpolation", langs=JS, severity="error",
         message="SQL built by interpolating or concatenating values.",
         note="Pass values as parameters: db.query('... WHERE id = $1', [id]), a query builder, or the ORM. "
              "Never splice values into SQL text, even after escaping.",
         rule={"kind": "call_expression", "all": [
             {"has": {"field": "function", "kind": "member_expression", "has": {
                 "field": "property",
                 "regex": "^(query|execute|raw|exec|unsafe|\\$queryRawUnsafe|\\$executeRawUnsafe)$"}}},
             {"has": {"field": "arguments", "has": {"nthChild": 1, "any": [
                 {"kind": "template_string", "has": {"kind": "template_substitution"}},
                 {"kind": "binary_expression", "regex": "^[\"'`]", "has": {"field": "operator", "regex": "^\\+$"}},
             ]}}},
         ]}),
    dict(id="no-shell-interpolation", langs=JS, severity="error",
         message="Shell command built from interpolated values (command injection).",
         note="Use execFile/spawn with an argument array: execFile('git', ['log', ref]). Never pass user data "
              "through a shell string.",
         rule={"kind": "call_expression", "all": [
             {"has": {"field": "function", "regex": "(^|\\.)(exec|execSync)$"}},
             {"has": {"field": "arguments", "has": {"nthChild": 1, "any": [
                 {"kind": "template_string", "has": {"kind": "template_substitution"}},
                 {"kind": "binary_expression", "has": {"field": "operator", "regex": "^\\+$"}},
             ]}}},
         ]}),
    dict(id="no-eval", langs=JS, severity="error",
         message="`eval` / `new Function` executes strings as code.",
         note="Parse data with JSON.parse or a schema; dispatch with a lookup table instead of generated code.",
         rule={"any": [{"pattern": "eval($$$ARGS)"}, {"pattern": "new Function($$$ARGS)"}]}),
    dict(id="no-inner-html", langs=JS, severity="error",
         message="Assigning HTML from a variable to innerHTML/outerHTML (XSS).",
         note="Set textContent, build elements with the DOM API, or sanitize with DOMPurify right at the assignment.",
         rule={"kind": "assignment_expression", "all": [
             {"has": {"field": "left", "kind": "member_expression",
                      "has": {"field": "property", "regex": "^(innerHTML|outerHTML)$"}}},
             {"not": {"has": {"field": "right", "kind": "string"}}},
             {"not": {"has": {"field": "right", "pattern": "DOMPurify.sanitize($$$A)"}}},
         ]}),
    dict(id="no-dangerously-set-inner-html", langs=["Tsx", "JavaScript"], severity="error",
         message="`dangerouslySetInnerHTML` renders raw HTML (XSS).",
         note="Render the content as React children, or sanitize it with DOMPurify where it is produced.",
         rule={"kind": "property_identifier", "regex": "^dangerouslySetInnerHTML$", "inside": {"kind": "jsx_attribute"}}),
    dict(id="validate-request-input", langs=JS, severity="error",
         message="Request input used before it went through a schema validator.",
         note="Validate at the boundary and use only the result: `const input = Body.parse(req.body)` "
              "(zod, valibot, yup, joi...). Handlers then never see unvalidated data.",
         rule={"any": [{"pattern": p} for p in [
                   "req.body", "req.query", "req.params",
                   "request.json()", "request.formData()", "request.nextUrl.searchParams"]],
               "not": {"inside": {"stopBy": "end", "kind": "call_expression", "has": {
                   "field": "function", "all": [
                       {"regex": "\\.(parse|safeParse|parseAsync|safeParseAsync|validate|validateSync|validateAsync|assert|decode|cast)$"},
                       {"not": {"regex": "^JSON\\."}}]}}}}),
    dict(id="no-bypass-security-trust", langs=TS, severity="error",
         message="Angular `bypassSecurityTrust*` on a non-constant value turns off XSS protection.",
         note="Bind the value normally and let Angular sanitize it, or sanitize it first with "
              "DomSanitizer.sanitize(SecurityContext.HTML, value).",
         rule={"kind": "call_expression", "all": [
             {"has": {"field": "function", "kind": "member_expression", "has": {
                 "field": "property", "regex": "^bypassSecurityTrust(Html|Script|Style|Url|ResourceUrl)$"}}},
             {"not": {"has": {"field": "arguments", "has": {"nthChild": 1, "kind": "string"}}}},
         ]}),
    dict(id="no-directory-listing", langs=JS, severity="error",
         message="`serve-index` publishes directory listings.",
         note="Serve known files with express.static or explicit routes; never list a directory.",
         rule={"any": [{"pattern": "serveIndex($$$ARGS)"}, {"pattern": "require('serve-index')"},
                       {"pattern": "import $X from 'serve-index'"}]}),
    dict(id="no-weak-hash", langs=JS, severity="error",
         message="MD5 / SHA-1 are broken hash functions.",
         note="Use SHA-256 for checksums and argon2/bcrypt/scrypt for passwords.",
         rule={"pattern": "$C.createHash($ALG)", "has": {"field": "arguments", "has": {
             "kind": "string", "regex": "^['\"](md5|sha1|md4|ripemd160)['\"]$"}}}),
    dict(id="no-mongo-where", langs=JS, severity="error",
         message="MongoDB `$where` runs JavaScript on the server (NoSQL injection).",
         note="Express the condition with query operators ($eq, $in, $expr…) and validated values.",
         rule={"kind": "pair", "has": {"field": "key", "regex": "^['\"]?\\$where['\"]?$"}}),
    # ---- JavaScript / TypeScript: no silencing the checks ---------------------
    dict(id="no-suppression-comment", langs=JS, severity="error",
         message="Suppression comment: it hides a check instead of fixing what it found.",
         note="Fix the underlying type or lint error. If the checker is wrong, fix its configuration in review.",
         rule={"kind": "comment", "regex": "@ts-ignore|@ts-nocheck|@ts-expect-error|eslint-disable|biome-ignore"}),
    dict(id="no-explicit-any", langs=TS, severity="error",
         message="`any` disables type checking.",
         note="Use a precise type, a generic, or `unknown` narrowed with a type guard or schema.",
         rule={"kind": "predefined_type", "regex": "^any$"}),
    dict(id="no-non-null-assertion", langs=TS, severity="warning",
         message="Non-null assertion `!` silences a possible null.",
         note="Narrow with a check (if/??/early return) so the null case is handled.",
         rule={"kind": "non_null_expression"}),
    # ---- JavaScript / TypeScript: hygiene -------------------------------------
    dict(id="no-debugger", langs=JS, severity="error",
         message="`debugger` statement left in code.", note="Remove it.",
         rule={"kind": "debugger_statement"}, fix=""),
    dict(id="no-empty-catch", langs=JS, severity="error",
         message="Empty catch block swallows the error.",
         note="Handle it, add context and rethrow, or log it through the project logger.",
         rule={"kind": "statement_block", "inside": {"kind": "catch_clause"}, "not": {"has": {"any": [
             {"kind": "expression_statement"}, {"kind": "return_statement"}, {"kind": "throw_statement"},
             {"kind": "lexical_declaration"}, {"kind": "if_statement"}, {"kind": "comment"}]}}}),
    dict(id="no-console", langs=JS, severity="warning",
         message="`console` call in committed code.",
         note="Use the project's logger so output is levelled and can be turned off.",
         rule={"pattern": "console.$METHOD($$$ARGS)"}),
    # ---- Python ----------------------------------------------------------------
    dict(id="py-no-sql-interpolation", langs=["Python"], severity="error",
         message="SQL built with an f-string, `%` or `.format()`.",
         note="Pass parameters: cursor.execute('... WHERE id = %s', (id,)) or use the ORM.",
         rule={"kind": "call", "all": [
             {"has": {"field": "function", "kind": "attribute",
                      "has": {"field": "attribute", "regex": "^(execute|executemany|raw)$"}}},
             {"has": {"field": "arguments", "has": {"nthChild": 1, "any": [
                 {"kind": "string", "has": {"kind": "interpolation"}},
                 {"kind": "binary_operator", "has": {"field": "operator", "regex": "^[%+]$"}},
                 {"kind": "call", "has": {"field": "function", "kind": "attribute",
                                          "has": {"field": "attribute", "regex": "^format$"}}},
             ]}}},
         ]}),
    dict(id="py-no-shell-true", langs=["Python"], severity="error",
         message="`shell=True` runs the command through a shell (command injection).",
         note="Pass an argument list without shell=True: subprocess.run(['git', 'log', ref], check=True).",
         rule={"kind": "keyword_argument", "all": [
             {"has": {"field": "name", "regex": "^shell$"}},
             {"has": {"field": "value", "regex": "^True$"}},
         ]}),
    dict(id="py-no-eval", langs=["Python"], severity="error",
         message="`eval` / `exec` executes strings as code.",
         note="Use ast.literal_eval for literals, json for data, or a dispatch table.",
         rule={"kind": "call", "has": {"field": "function", "kind": "identifier", "regex": "^(eval|exec)$"}}),
    dict(id="py-no-weak-hash", langs=["Python"], severity="error",
         message="MD5 / SHA-1 are broken hash functions.",
         note="Use hashlib.sha256 for checksums and argon2/bcrypt/scrypt for passwords "
              "(or pass usedforsecurity=False for a non-security checksum).",
         rule={"kind": "call", "all": [
             {"has": {"field": "function", "regex": "^hashlib\\.(md5|sha1|new)$"}},
             {"not": {"has": {"field": "arguments", "regex": "usedforsecurity\\s*=\\s*False"}}},
             {"any": [
                 {"has": {"field": "function", "regex": "^hashlib\\.(md5|sha1)$"}},
                 {"has": {"field": "arguments", "has": {"nthChild": 1, "regex": "^['\"](md5|sha1)['\"]$"}}},
             ]},
         ]}),
    dict(id="py-yaml-safe-load", langs=["Python"], severity="error",
         message="`yaml.load` without a safe loader can construct arbitrary objects.",
         note="Use yaml.safe_load.",
         rule={"pattern": "yaml.load($DATA)"}, fix="yaml.safe_load($DATA)"),
    dict(id="py-no-tls-verify-off", langs=["Python"], severity="error",
         message="TLS certificate verification turned off (`verify=False`).",
         note="Keep verification on; point `verify=` at the CA bundle for internal certificates.",
         rule={"kind": "keyword_argument", "all": [
             {"has": {"field": "name", "regex": "^verify$"}},
             {"has": {"field": "value", "regex": "^False$"}},
         ]}),
    dict(id="py-no-bare-except", langs=["Python"], severity="error",
         message="Bare `except:` swallows every error, including KeyboardInterrupt.",
         note="Catch the specific exceptions you expect, e.g. `except (ValueError, KeyError) as exc:`.",
         rule={"kind": "except_clause", "regex": "^except\\s*:"}),
    # ---- Go ----------------------------------------------------------------------
    dict(id="go-no-sql-sprintf", langs=["Go"], severity="error",
         message="SQL built with fmt.Sprintf or string concatenation.",
         note="Use placeholders: db.QueryContext(ctx, \"... WHERE id = $1\", id).",
         rule={"kind": "call_expression", "all": [
             {"has": {"field": "function", "kind": "selector_expression",
                      "has": {"field": "field", "regex": "^(Query|QueryContext|QueryRow|QueryRowContext|Exec|ExecContext)$"}}},
             {"has": {"field": "arguments", "has": {"any": [
                 {"kind": "call_expression", "has": {"field": "function", "regex": "^fmt\\.Sprintf$"}},
                 {"kind": "binary_expression", "has": {"field": "operator", "regex": "^\\+$"}},
             ]}}},
         ]}),
    dict(id="go-no-insecure-tls", langs=["Go"], severity="error",
         message="`InsecureSkipVerify: true` turns off TLS certificate checks.",
         note="Keep verification on; add the internal CA to RootCAs instead.",
         rule={"kind": "keyed_element", "regex": "^InsecureSkipVerify\\s*:\\s*true"}),
    # ---- Rust ----------------------------------------------------------------------
    dict(id="rs-no-unwrap", langs=["Rust"], severity="warning",
         message="`unwrap()` panics on error.",
         note="Propagate with `?` and context (anyhow::Context), or handle the None/Err case.",
         rule={"pattern": "$X.unwrap()", "not": {"inside": {"kind": "function_item", "follows": {
             "kind": "attribute_item", "regex": "test"}, "stopBy": "end"}}}),
    # ---- GitHub Actions ------------------------------------------------------
    dict(id="gha-script-injection", langs=["Yaml"], files=WORKFLOWS, severity="error",
         message="Untrusted event data expanded inside a script (`${{ github.event… }}` in `run:`).",
         note="GitHub substitutes the text before the shell runs, so a crafted issue title or branch name "
              "becomes code. Pass it through `env:` (TITLE: ${{ github.event.issue.title }}) and use \"$TITLE\".",
         rule={"kind": "block_mapping_pair", "all": [
             {"has": {"field": "key", "regex": "^(run|script)$"}},
             {"has": {"field": "value", "regex": UNTRUSTED}},
         ]}),
    dict(id="gha-curl-pipe-shell", langs=["Yaml"], files=WORKFLOWS, severity="error",
         message="A downloaded script is piped straight into a shell.",
         note="Download it, check its checksum or signature, then run it; or use a pinned action.",
         rule={"kind": "block_mapping_pair", "all": [
             {"has": {"field": "key", "regex": "^run$"}},
             {"has": {"field": "value", "regex": "(curl|wget)[^|\\n]*\\|\\s*(sudo\\s+)?(ba|z|da)?sh\\b"}},
         ]}),
    dict(id="gha-unpinned-action", langs=["Yaml"], files=WORKFLOWS, severity="warning",
         message="Action referenced by a movable tag or branch instead of a commit SHA.",
         note="A tag can be moved to malicious code (tj-actions/changed-files, 2025). Pin the full "
              "40-character commit SHA and keep the version in a comment: uses: org/action@<sha> # v4.",
         rule={"kind": "block_mapping_pair", "all": [
             {"has": {"field": "key", "regex": "^uses$"}},
             {"has": {"field": "value", "regex": "@"}},
             {"not": {"has": {"field": "value", "regex": "@[0-9a-f]{40}$|^\\./|^docker://"}}},
         ]}),
    dict(id="gha-pr-target-checkout", langs=["Yaml"], files=WORKFLOWS, severity="error",
         message="`pull_request_target` workflow checks out the pull request's code.",
         note="That trigger runs with the base repository's secrets and write token; building or running "
              "the fork's code there hands both to the fork. Use `pull_request`, or never execute the checkout.",
         rule={"kind": "block_mapping_pair", "all": [
             {"has": {"field": "key", "regex": "^ref$"}},
             {"has": {"field": "value", "regex": "github\\.event\\.pull_request\\.head\\.(sha|ref)|github\\.head_ref"}},
             {"inside": {"kind": "document", "stopBy": "end",
                         "has": {"kind": "string_scalar", "regex": "^pull_request_target$", "stopBy": "end"}}},
         ]}),
    # ---- Terraform -------------------------------------------------------------
    dict(id="tf-public-bucket-acl", langs=["Hcl"], severity="error",
         message="Storage bucket made public through its ACL.",
         note="Keep buckets private and serve public content through a CDN with origin access control.",
         rule={"kind": "attribute", "all": [
             {"has": {"kind": "identifier", "regex": "^(acl|predefined_acl)$"}},
             {"has": {"kind": "expression", "regex": "^\"(public-read|public-read-write|authenticated-read|publicRead|publicReadWrite|allUsers)\"$"}},
         ]}),
    dict(id="tf-open-ingress", langs=["Hcl"], severity="warning",
         message="Ingress open to the whole internet (0.0.0.0/0 or ::/0).",
         note="Restrict the source range to the networks that need it; expose public services through a load balancer.",
         rule={"kind": "attribute", "all": [
             {"has": {"kind": "identifier", "regex": "^(cidr_blocks|ipv6_cidr_blocks|cidr_ipv4|cidr_ipv6|source_ranges|source_address_prefix)$"}},
             {"has": {"kind": "expression", "regex": "\"(0\\.0\\.0\\.0/0|::/0|\\*|Internet)\""}},
             {"inside": {"kind": "block", "stopBy": "end", "any": [
                 {"has": {"kind": "identifier", "regex": "^ingress$"}},
                 {"has": {"kind": "string_lit", "regex": "aws_vpc_security_group_ingress_rule|google_compute_firewall|azurerm_network_security_rule"}},
             ]}},
         ]}),
    dict(id="tf-publicly-accessible-db", langs=["Hcl"], severity="error",
         message="Database instance reachable from the internet (`publicly_accessible = true`).",
         note="Keep databases in private subnets; reach them through a bastion, VPN or private link.",
         rule={"kind": "attribute", "all": [
             {"has": {"kind": "identifier", "regex": "^publicly_accessible$"}},
             {"has": {"kind": "expression", "regex": "^true$"}},
         ]}),
    dict(id="tf-iam-wildcard", langs=["Hcl"], severity="error",
         message="IAM policy grants every action (`\"*\"`).",
         note="List the actions the workload needs; wildcards turn any compromise into account takeover.",
         rule={"any": [
             {"kind": "attribute", "all": [
                 {"has": {"kind": "identifier", "regex": "^(actions|Action)$"}},
                 {"has": {"kind": "expression", "regex": "^\\[?\\s*\"\\*\"\\s*\\]?$"}}]},
             {"kind": "object_elem", "all": [
                 {"has": {"field": "key", "regex": "^\"?Action\"?$"}},
                 {"has": {"field": "val", "regex": "^\\[?\\s*\"\\*\"\\s*\\]?$"}}]},
         ]}),
]


def doc(spec, lang):
    d = {"id": spec["id"], "language": lang, "severity": spec["severity"],
         "message": spec["message"], "note": spec["note"], "rule": spec["rule"]}
    if "fix" in spec:
        d["fix"] = spec["fix"]
    if "files" in spec:
        d["files"] = spec["files"]
    # JSON is valid YAML: exact, and no YAML library needed to generate it.
    return json.dumps(d, indent=2, ensure_ascii=False)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for old in OUT.glob("*.yml"):
        old.unlink()
    for spec in RULES:
        body = "\n---\n".join(doc(spec, lang) for lang in spec["langs"])
        header = "# Generated by scripts/gen-recommended.py; edit the spec there.\n"
        (OUT / f"{spec['id']}.yml").write_text(header + body + "\n")
    sys.stdout.write(f"{len(RULES)} rules written to {OUT}\n")


main()

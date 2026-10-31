"""Python, Go, Rust, GitHub Actions and Terraform rule specs."""

from .common import NESTED_QUANTIFIER, SQL_TEXT, TESTS, UNTRUSTED, WORKFLOWS  # noqa: F401

RULES = [
    # ---- Python ----------------------------------------------------------------
    dict(id="py-no-sql-interpolation", langs=["Python"], severity="error",
         message="SQL built with an f-string, `%` or `.format()`.",
         note="Pass parameters: cursor.execute('... WHERE id = %s', (id,)) or use the ORM.",
         rule={"any": [
             {"kind": "call", "all": [
                 {"has": {"field": "function", "kind": "attribute",
                          "has": {"field": "attribute", "regex": "^(execute|executemany|raw)$"}}},
                 {"has": {"field": "arguments", "has": {"nthChild": 1, "any": [
                     {"kind": "string", "has": {"kind": "interpolation"}},
                     {"kind": "binary_operator", "has": {"field": "operator", "regex": "^[%+]$"}},
                     {"kind": "call", "has": {"field": "function", "kind": "attribute",
                                              "has": {"field": "attribute", "regex": "^format$"}}},
                 ]}}},
             ]},
             # SQL text built anywhere, then passed on in a variable.
             {"kind": "string", "regex": SQL_TEXT, "has": {"kind": "interpolation"},
              "not": {"inside": {"kind": "argument_list"}}},
             {"kind": "binary_operator", "regex": SQL_TEXT, "has": {"field": "operator", "regex": "^[%+]$"},
              "not": {"any": [{"inside": {"kind": "binary_operator"}}, {"inside": {"kind": "argument_list"}}]}},
             {"kind": "call", "regex": SQL_TEXT, "not": {"inside": {"kind": "argument_list"}},
              "has": {"field": "function", "kind": "attribute", "has": {"field": "attribute", "regex": "^format$"}}},
         ]}),
    dict(id="py-no-session-fixation", langs=["Python"], severity="error",
         message="Login or privilege change writes the user into a server-side session without a new session id (session fixation).",
         note="Start a fresh session first (aiohttp_session.new_session(request), session.cycle_key() in Django, session.regenerate() in Beaker).",
         rule={"kind": "assignment", "all": [
             {"has": {"field": "left", "kind": "subscript", "regex": "^session\\[['\"](user|user_id|userid|uid|account|account_id|auth|authenticated|logged_in|username|email|role|is_admin)['\"]\\]$"}},
             {"inside": {"stopBy": "end", "kind": "function_definition", "all": [
                 {"has": {"stopBy": "end", "regex": "^get_session\\("}},
                 {"not": {"has": {"stopBy": "end", "regex": "^(new_session|[\\w.]*cycle_key|[\\w.]*regenerate|[\\w.]*invalidate)\\("}}},
             ]}},
         ]}),
    dict(id="py-no-jwt-unverified", langs=["Python"], severity="error",
         message="JWT decoded without verifying it, or with the `none` algorithm: anyone can forge a token.",
         note="Decode with the key and the one algorithm the tokens use: jwt.decode(token, key, algorithms=['HS256']).",
         rule={"any": [
             {"kind": "keyword_argument", "all": [
                 {"has": {"field": "name", "regex": "^algorithms$"}},
                 {"has": {"field": "value", "regex": "(?i)['\"]none['\"]"}}]},
             {"kind": "pair", "all": [
                 {"has": {"field": "key", "regex": "^['\"]verify_signature['\"]$"}},
                 {"has": {"field": "value", "regex": "^False$"}}]},
             {"kind": "keyword_argument", "all": [
                 {"has": {"field": "name", "regex": "^verify$"}},
                 {"has": {"field": "value", "regex": "^False$"}},
                 {"inside": {"stopBy": "end", "kind": "call", "has": {"field": "function", "regex": "(^|\\.)jwt\\.decode$"}}}]},
         ]}),
    dict(id="py-no-ldap-interpolation", langs=["Python"], severity="error",
         message="LDAP filter built by interpolating values (LDAP injection).",
         note="Escape values with ldap.filter.escape_filter_chars / ldap3.utils.conv.escape_filter_chars, or build the filter with the library.",
         rule={"any": [
             {"kind": "string", "regex": '^[rRbBuUfF]*[\'\\"]\\(\\s*[&|!]?\\s*\\(?[\\w.-]+\\s*[~<>]?=', "has": {"kind": "interpolation"}, "not": {"regex": "(?i)escape"}},
             {"kind": "binary_operator", "regex": '^[rRbBuUfF]*[\'\\"]\\(\\s*[&|!]?\\s*\\(?[\\w.-]+\\s*[~<>]?=', "has": {"field": "operator", "regex": "^[%+]$"},
              "not": {"any": [{"inside": {"kind": "binary_operator"}}, {"regex": "(?i)escape"}]}},
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
             {"has": {"field": "function", "regex": "^(hashlib\\.)?(md5|sha1)$|^hashlib\\.new$"}},
             {"not": {"has": {"field": "arguments", "regex": "usedforsecurity\\s*=\\s*False"}}},
             {"any": [
                 {"has": {"field": "function", "regex": "^(hashlib\\.)?(md5|sha1)$"}},
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
         rule={"any": [
             {"kind": "call_expression", "all": [
                 {"has": {"field": "function", "kind": "selector_expression",
                          "has": {"field": "field", "regex": "^(Query|QueryContext|QueryRow|QueryRowContext|Exec|ExecContext)$"}}},
                 {"has": {"field": "arguments", "has": {"any": [
                     {"kind": "call_expression", "has": {"field": "function", "regex": "^fmt\\.Sprintf$"}},
                     {"kind": "binary_expression", "has": {"field": "operator", "regex": "^\\+$"}},
                 ]}}},
             ]},
             # SQL text formatted or concatenated anywhere, then passed on in a variable.
             {"kind": "call_expression", "not": {"inside": {"kind": "argument_list"}}, "all": [
                 {"has": {"field": "function", "regex": "^fmt\\.Sprintf$"}},
                 {"has": {"field": "arguments", "has": {"nthChild": 1, "regex": SQL_TEXT}}},
                 {"has": {"field": "arguments", "has": {"nthChild": 2}}},
             ]},
             {"kind": "binary_expression", "regex": SQL_TEXT, "has": {"field": "operator", "regex": "^\\+$"},
              "all": [{"has": {"stopBy": "end", "any": [{"kind": "identifier"}, {"kind": "call_expression"}]}}],
              "not": {"any": [{"inside": {"kind": "binary_expression"}}, {"inside": {"kind": "argument_list"}}]}},
         ]}),
    dict(id="go-no-unsafe-template-type", langs=["Go"], severity="error",
         message="html/template's escaping is turned off for a value that is not a constant (XSS).",
         note="Pass the value as data and let html/template escape it; keep template.HTML/JS/URL/CSS "
              "for constants, or for HTML a sanitizer (bluemonday) produced.",
         rule={"kind": "call_expression", "all": [
             {"has": {"field": "function", "regex": "^template\\.(HTML|JS|JSStr|URL|CSS|HTMLAttr|Srcset)$"}},
             {"has": {"field": "arguments", "has": {"nthChild": 1,
                      "not": {"kind": "interpreted_string_literal"},
                      "all": [{"not": {"kind": "raw_string_literal"}},
                              {"not": {"has": {"stopBy": "end", "regex": "(?i)sanitize"}}},
                              {"not": {"regex": "(?i)sanitize"}}]}}},
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

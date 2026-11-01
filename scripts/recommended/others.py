"""Go, Rust, GitHub Actions and Terraform rule specs."""

from .common import NESTED_QUANTIFIER, SQL_TEXT, TESTS, UNTRUSTED, WORKFLOWS  # noqa: F401

RULES = [
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

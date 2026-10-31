"""JavaScript / TypeScript rule specs."""

from .common import JS, NESTED_QUANTIFIER, TESTS, TS  # noqa: F401

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
    dict(id="no-regex-redos", langs=JS, severity="error",
         message="Regular expression with a nested quantifier: catastrophic backtracking (ReDoS).",
         note="Remove the inner or outer repetition (`(\\d+)+` → `\\d+`), anchor it, or validate the length first.",
         rule={"any": [
             {"kind": "regex", "has": {"field": "pattern", "regex": NESTED_QUANTIFIER}},
             {"pattern": "new RegExp($S, $$$F)", "has": {"field": "arguments", "has": {"kind": "string", "regex": NESTED_QUANTIFIER}}},
         ]}),
    dict(id="py-no-regex-redos", langs=["Python"], severity="error",
         message="Regular expression with a nested quantifier: catastrophic backtracking (ReDoS).",
         note="Remove the inner or outer repetition (`(\\d+)+` → `\\d+`), or use the `re2`/`regex` module with a timeout.",
         rule={"kind": "call", "all": [
             {"has": {"field": "function", "regex": "^re\\.(compile|match|search|fullmatch|sub|subn|findall|finditer|split)$"}},
             {"has": {"field": "arguments", "has": {"kind": "string", "regex": NESTED_QUANTIFIER}}},
         ]}),
    dict(id="no-template-autoescape-off", langs=JS, severity="error",
         message="Template autoescaping switched off: every interpolated value becomes HTML (XSS).",
         note="Keep autoescape on; mark the few trusted fragments safe one by one.",
         rule={"kind": "pair", "all": [
             {"has": {"field": "key", "regex": "^['\"]?autoescape['\"]?$"}},
             {"has": {"field": "value", "regex": "^false$"}},
         ]}),
    dict(id="py-no-template-autoescape-off", langs=["Python"], severity="error",
         message="Template autoescaping switched off: every interpolated value becomes HTML (XSS).",
         note="Use `autoescape=True` (or `select_autoescape()`); mark trusted fragments with Markup one by one.",
         rule={"kind": "keyword_argument", "all": [
             {"has": {"field": "name", "regex": "^autoescape$"}},
             {"has": {"field": "value", "regex": "^False$"}},
         ]}),
    dict(id="no-plaintext-password-compare", langs=JS, severity="error", ignores=TESTS,
         message="Stored password compared in plain text.",
         note="Store only a slow hash (bcrypt, argon2, scrypt) and check it with its verify function (bcrypt.compare).",
         rule={"kind": "binary_expression", "all": [
             {"has": {"field": "operator", "regex": "^(===|==|!==|!=)$"}},
             # Compared with a hash of the input: not plain text.
             {"not": {"has": {"kind": "call_expression", "regex": "(?i)hash|digest|crypt|hmac"}}},
             {"any": [
                 {"has": {"kind": "member_expression", "regex": "\\.(password|passwd|pwd)$",
                          "not": {"regex": "^(req|request|ctx\\.request)\\."}}},
                 # A password-checking helper that compares with `===`.
                 {"inside": {"stopBy": "end", "any": [
                     {"kind": k, "has": {"field": "name", "regex": '(?i)^((compare|check|verify|validate|match)_?pass(word|wd)?|pass(word|wd)?_?(matches|equals|valid|ok))$'}}
                     for k in ("function_declaration", "variable_declarator", "method_definition")]}},
             ]},
         ]}),
    dict(id="py-no-plaintext-password-compare", langs=["Python"], severity="error",
         message="Stored password compared in plain text.",
         note="Store only a slow hash and check it with check_password_hash / bcrypt.checkpw / argon2 verify.",
         rule={"kind": "comparison_operator", "has": {"kind": "attribute", "regex": "\\.(password|passwd|pwd)$",
                                                      "not": {"regex": "^request\\."}}}),
    dict(id="no-hardcoded-session-secret", langs=JS, severity="error", ignores=TESTS,
         message="Session / token signing secret hard-coded in the source.",
         note="Read it from the environment or a secret manager (process.env.SESSION_SECRET); anyone with the code can forge sessions.",
         rule={"any": [
             {"kind": "pair", "all": [
                 {"has": {"field": "key", "regex": "^['\"]?(secret|secretOrKey|secretOrPublicKey|jwtSecret|cookieSecret)['\"]?$"}},
                 {"has": {"field": "value", "kind": "string"}},
                 {"inside": {"stopBy": "end", "any": [
                     {"kind": "call_expression", "has": {"field": "function", "regex": "(^|\\.)(session|expressSession|cookieSession|Strategy|JwtStrategy|expressjwt|expressJwt|jwt|koaSession)$"}},
                     {"kind": "new_expression", "has": {"field": "constructor", "regex": "(^|\\.)(session|expressSession|cookieSession|Strategy|JwtStrategy|expressjwt|expressJwt|jwt|koaSession)$"}},
                 ]}},
             ]},
             {"kind": "call_expression", "all": [
                 {"has": {"field": "function", "regex": "^(jwt|jsonwebtoken|JWT|jose)\\.(sign|verify)$"}},
                 {"has": {"field": "arguments", "has": {"nthChild": 2, "kind": "string"}}},
             ]},
         ]}),
    dict(id="py-no-hardcoded-secret-key", langs=["Python"], severity="error",
         message="Framework secret key hard-coded in the source.",
         note="Read it from the environment (os.environ['SECRET_KEY']); anyone with the code can forge sessions and tokens.",
         rule={"kind": "assignment", "all": [
             {"has": {"field": "left", "regex": "^(SECRET_KEY|JWT_SECRET_KEY|([A-Za-z_][\\w.]*\\.)?secret_key)$"}},
             {"has": {"field": "right", "kind": "string"}},
         ]}),
    dict(id="no-xml-external-entities", langs=JS, severity="error",
         message="XML parsed with external entities enabled (XXE).",
         note="Leave `noent` off (the default): entities can read local files and reach internal hosts.",
         rule={"kind": "pair", "all": [
             {"has": {"field": "key", "regex": "^['\"]?noent['\"]?$"}},
             {"has": {"field": "value", "regex": "^true$"}},
         ]}),
    dict(id="py-no-xml-external-entities", langs=["Python"], severity="error",
         message="XML parser resolves external entities (XXE).",
         note="Use defusedxml, or lxml's XMLParser(resolve_entities=False, no_network=True).",
         rule={"kind": "keyword_argument", "all": [
             {"has": {"field": "name", "regex": "^resolve_entities$"}},
             {"has": {"field": "value", "regex": "^True$"}},
         ]}),
    dict(id="no-unsafe-deserialization", langs=JS, severity="error",
         message="Deserializer that can run code (node-serialize, funcster, serialize-to-js).",
         note="Parse data with JSON.parse and validate it with a schema; these libraries revive functions from input.",
         rule={"any": [
             {"pattern": "require('node-serialize')"}, {"pattern": "require(\"node-serialize\")"},
             {"pattern": "require('funcster')"}, {"pattern": "require('serialize-to-js')"},
             {"kind": "import_statement", "has": {"field": "source", "regex": "node-serialize|funcster|serialize-to-js"}},
             {"kind": "call_expression", "has": {"field": "function", "regex": "(^|\\.)(unserialize|deepDeserialize)$"}},
         ]}),
    dict(id="py-no-unsafe-deserialization", langs=["Python"], severity="error",
         message="Deserializer that runs code from its input (pickle, marshal, shelve, jsonpickle, dill).",
         note="Exchange data as JSON validated with a schema; unpickle only data this program wrote and signed.",
         rule={"kind": "call", "has": {"field": "function",
             "regex": "^(pickle|cPickle|_pickle|marshal|dill|jsonpickle)\\.(loads?|decode|Unpickler)$|^shelve\\.open$"}}),
    dict(id="no-unsafe-recursive-merge", langs=JS, severity="error",
         message="Recursive merge copies every key, `__proto__` included (prototype pollution).",
         note="Skip `__proto__`, `constructor` and `prototype` keys (or merge into Object.create(null)); a maintained merge (lodash ≥4.17.21) already does.",
         rule={"kind": "assignment_expression", "all": [
             {"has": {"field": "left", "kind": "subscript_expression", "has": {"field": "index", "pattern": "$K"}}},
             {"inside": {"stopBy": "end", "kind": "for_in_statement", "has": {"field": "left", "stopBy": "end", "pattern": "$K"}}},
             {"inside": {"stopBy": "end", "any": [
                 {"kind": "function_declaration", "all": [
                     {"has": {"field": "name", "pattern": "$F"}},
                     {"has": {"stopBy": "end", "kind": "call_expression", "has": {"field": "function", "pattern": "$F"}}}]},
                 {"kind": "variable_declarator", "all": [
                     {"has": {"field": "name", "pattern": "$F"}},
                     {"has": {"stopBy": "end", "kind": "call_expression", "has": {"field": "function", "pattern": "$F"}}}]},
             ]}},
             {"not": {"inside": {"stopBy": "end", "any": [{"kind": "function_declaration"}, {"kind": "variable_declarator"}],
                                 "has": {"stopBy": "end", "kind": "string", "regex": "__proto__|constructor|prototype"}}}},
         ]}),
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
]

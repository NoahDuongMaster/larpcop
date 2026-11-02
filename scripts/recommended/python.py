"""Python rule specs."""

from .common import SQL_TEXT, TESTS

RULES = [
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
                 {"has": {"field": "arguments", "has": {"nthChild": 1, "pattern": "$ALG"}}},
             ]},
         ]},
         resolve={"ALG": "(?i)^(md5|sha1)$"}),
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
    dict(id="py-no-xml-external-entities", langs=["Python"], severity="error",
         message="XML parser resolves external entities or loads DTDs (XXE).",
         note="Use defusedxml, or lxml's XMLParser(resolve_entities=False, no_network=True); "
              "keep xml.sax's feature_external_ges/feature_external_pes off.",
         rule={"any": [
             # lxml: XMLParser(resolve_entities=True / load_dtd=True / no_network=False).
             {"kind": "keyword_argument", "all": [
                 {"has": {"field": "name", "regex": "^(resolve_entities|load_dtd|dtd_validation)$"}},
                 {"has": {"field": "value", "regex": "^True$"}}]},
             {"kind": "keyword_argument", "all": [
                 {"has": {"field": "name", "regex": "^no_network$"}},
                 {"has": {"field": "value", "regex": "^False$"}}]},
             # xml.sax / pulldom: parser.setFeature(feature_external_ges, True).
             {"kind": "call", "all": [
                 {"has": {"field": "function", "regex": "\\.setFeature$"}},
                 {"has": {"field": "arguments", "regex": "feature_external_(ges|pes)[^,]*,\\s*(True|1)\\s*\\)"}}]},
         ]}),
    dict(id="py-no-insecure-random", langs=["Python"], severity="warning",
         message="random is predictable; tokens, ids and keys made with it can be guessed.",
         note="Use the secrets module (secrets.token_hex, secrets.choice) or random.SystemRandom() "
              "for anything a user must not guess.",
         rule={"kind": "call", "has": {"field": "function", "regex":
               "^(random|numpy\\.random|np\\.random)\\.(random|randint|randrange|choice|choices|sample|getrandbits|"
               "uniform|randbytes|shuffle|triangular|gauss|\\w+variate|rand|randn)$"}}),
    dict(id="py-no-insecure-cookie", langs=["Python"], severity="warning",
         message="Cookie set without secure=True or with httponly=False.",
         note="Pass secure=True and httponly=True (and samesite) to set_cookie.",
         rule={"kind": "call", "all": [
             {"has": {"field": "function", "regex": "\\.set_cookie$"}},
             {"any": [
                 {"not": {"has": {"field": "arguments", "regex": "\\bsecure\\s*=\\s*True\\b"}}},
                 {"has": {"field": "arguments", "regex": "\\bhttponly\\s*=\\s*False\\b"}},
             ]}]}),
    # A settings file named dev/local/test is not what runs in production.
    dict(id="py-django-debug-true", langs=["Python"], files=["**/settings.py", "**/settings/*.py", "**/*settings*.py"],
         ignores=TESTS + ["**/settings/*dev*.py", "**/settings/*local*.py", "**/settings/*development*.py",
                          "**/settings/test*.py", "**/settings/*test*.py"], severity="error",
         message="DEBUG = True in Django settings: a stack trace shows settings, SQL and source to whoever triggers an error.",
         note="Keep DEBUG False in the committed settings; run with DJANGO_DEBUG=1 or a local settings file instead.",
         rule={"kind": "assignment", "all": [
             {"has": {"field": "left", "regex": "^DEBUG$"}},
             {"has": {"field": "right", "regex": "^True$"}}]}),
    dict(id="py-django-allowed-hosts-wildcard", langs=["Python"], files=["**/settings.py", "**/settings/*.py", "**/*settings*.py"], severity="error",
         message="ALLOWED_HOSTS accepts any host: the Host header decides links, caches and password-reset URLs.",
         note="List the hostnames the site is served on and let the proxy pass the real Host.",
         rule={"kind": "assignment", "all": [
             {"has": {"field": "left", "regex": "^ALLOWED_HOSTS$"}},
             {"has": {"field": "right", "regex": "\\*"}}]}),
    dict(id="py-django-csrf-exempt", langs=["Python"], severity="error",
         message="`@csrf_exempt` switches Django's CSRF check off for a view.",
         note="Keep the check; for a token-authenticated API use DRF's authentication classes instead of exempting the view.",
         # A webhook receiver verifies the sender's signature instead (Stripe,
         # GitHub, Twilio…): no session, nothing for CSRF to protect.
         # Decorators are siblings of the function: the decorated definition
         # holds both, so it is what the rule matches.
         rule={"kind": "decorated_definition", "all": [
             {"has": {"stopBy": "end", "kind": "decorator", "regex": "^@csrf_exempt\\b"}},
             {"not": {"has": {"stopBy": "end", "kind": "function_definition",
                              "regex": "(?i)def\\s+\\w*(webhook|hook|stripe|github|twilio|slack|payment)"}}},
         ]}),
    dict(id="py-flask-debug-true", langs=["Python"], severity="error",
         message="Flask started with `debug=True`: the Werkzeug console runs code and the tracebacks show source.",
         note="Leave debug off in the code; run `flask --debug` (or FLASK_DEBUG=1) locally.",
         rule={"kind": "keyword_argument", "all": [
             {"has": {"field": "name", "regex": "^debug$"}},
             {"has": {"field": "value", "regex": "^True$"}}]}),
]

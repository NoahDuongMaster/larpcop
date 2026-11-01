"""PHP rule specs."""

from .common import SQL_TEXT

# Session keys that say who is logged in.
AUTH_KEYS = "user|user_id|userid|uid|username|login|logged_in|loggedin|auth|authenticated|account|account_id|role|is_admin|admin"

RULES = [
    dict(id="php-no-sql-interpolation", langs=["Php"], severity="error",
         message="SQL built by string interpolation or concatenation.",
         note="Use prepared statements with bound parameters (PDO prepare/execute, mysqli bind_param, query builder bindings).",
         rule={"any": [
             {"kind": "encapsed_string", "regex": SQL_TEXT, "has": {"stopBy": "end", "kind": "variable_name"}},
             {"kind": "binary_expression", "regex": SQL_TEXT, "has": {"field": "operator", "regex": "^\\.$"},
              "all": [{"has": {"stopBy": "end", "any": [{"kind": "variable_name"}, {"kind": "function_call_expression"},
                                                        {"kind": "member_call_expression"}]}}],
              "not": {"inside": {"kind": "binary_expression"}}},
         ]}),
    dict(id="php-no-eval", langs=["Php"], severity="error",
         message="eval / assert(string) / create_function run strings as PHP code.",
         note="Call the code directly; map allowed values to fixed functions.",
         rule={"any": [
             {"kind": "function_call_expression", "has": {"field": "function", "regex": "^(eval|create_function)$"}},
             {"kind": "expression_statement", "regex": "^eval\\s*\\("},
         ]}),
    dict(id="php-no-unserialize", langs=["Php"], severity="error",
         message="unserialize on data that is not a constant can instantiate any class (object injection).",
         note="Use json_decode; if unserialize is unavoidable pass ['allowed_classes' => false].",
         rule={"kind": "function_call_expression", "all": [
             {"has": {"field": "function", "regex": "^unserialize$"}},
             {"not": {"has": {"field": "arguments", "regex": "allowed_classes"}}},
         ]}),
    dict(id="php-no-weak-hash", langs=["Php"], severity="error",
         message="MD5 / SHA-1 are broken hash functions.",
         note="Use password_hash()/password_verify() for passwords and hash('sha256', …) for anything that must "
              "not be forged. A cache key or ETag is fine when the name it is stored in says so (etag, checksum, cache_key).",
         rule={"all": [
             {"any": [
                 {"kind": "function_call_expression", "has": {"field": "function", "regex": "^(md5|sha1)$"}},
                 {"kind": "function_call_expression", "all": [
                     {"has": {"field": "function", "regex": "^hash$"}},
                     {"has": {"field": "arguments", "has": {"nthChild": 1, "regex": "^[\'\"](md5|sha1)[\'\"]$"}}},
                 ]},
             ]},
             {"not": {"inside": {"stopBy": "end", "any": [
                 {"kind": "assignment_expression", "has": {"field": "left", "regex": "(?i)etag|checksum|fingerprint|cache_?key|cache_?id"}},
                 {"kind": "pair", "regex": "^[\'\"]?(?i:etag|checksum|fingerprint|cache_?key)"},
             ]}}},
         ]}),
    dict(id="php-no-insecure-random", langs=["Php"], severity="warning",
         message="rand / mt_rand / uniqid / lcg_value are predictable; tokens, ids and keys made with them can be guessed.",
         note="Use random_bytes() / random_int() (bin2hex(random_bytes(32)) for a token) for anything a user must not guess.",
         rule={"kind": "function_call_expression", "has": {"field": "function",
               "regex": "^(rand|mt_rand|uniqid|lcg_value|str_shuffle|array_rand|shuffle|mt_srand|srand)$"}}),
    dict(id="php-no-session-fixation", langs=["Php"], severity="error",
         message="Login writes the user into the session without a new session id (session fixation).",
         note="Call session_regenerate_id(true) once the credentials are checked, before storing who is logged in.",
         rule={"kind": "assignment_expression", "all": [
             {"has": {"field": "left", "kind": "subscript_expression",
                      "regex": "^\\$_SESSION\\s*\\[\\s*[\'\"](?i:" + AUTH_KEYS + ")[\'\"]\\s*\\]$"}},
             {"inside": {"stopBy": "end", "any": [
                 {"kind": "function_definition"}, {"kind": "method_declaration"}, {"kind": "program"}],
                 "all": [
                     {"has": {"stopBy": "end", "regex": "(?i)password_verify\\s*\\(|\\$_(POST|REQUEST|GET)\\s*\\[\\s*[\'\"]\\w*pass"}},
                     {"not": {"has": {"stopBy": "end", "regex": "^session_regenerate_id\\s*\\("}}},
                 ]}},
         ]}),
]

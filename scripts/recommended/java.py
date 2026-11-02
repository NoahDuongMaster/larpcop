"""Java rule specs."""

from .common import SQL_TEXT

# Settings that turn off DTDs or external entities (OWASP XXE cheat sheet).
# One setting that is enough on its own; external general entities off is
# enough only with parameter entities off too (XXE_PAIR).
XXE_SECURE = ("disallow-doctype-decl\"?\\s*,\\s*true"
              "|ACCESS_EXTERNAL_(DTD|SCHEMA|STYLESHEET)\\s*,\\s*\"\""
              "|SUPPORT_DTD\\s*,\\s*(false|Boolean\\.FALSE)|IS_SUPPORTING_EXTERNAL_ENTITIES\\s*,\\s*(false|Boolean\\.FALSE)"
              "|isSupportingExternalEntities\"\\s*,\\s*(false|Boolean\\.FALSE)|setExpandEntityReferences\\(\\s*false")
XXE_SCOPES = ["method_declaration", "constructor_declaration", "static_initializer", "lambda_expression"]
XXE_PAIR = ["external-general-entities\"?\\s*,\\s*false", "external-parameter-entities\"?\\s*,\\s*false"]


def inside_configured(where):
    """Inside a `where` holding a call that turns XXE off: one sufficient setting, or both entity kinds off."""
    one = {"kind": "method_invocation", "regex": XXE_SECURE, "stopBy": "end"}
    pair = [{"has": {"kind": "method_invocation", "regex": r, "stopBy": "end"}} for r in XXE_PAIR]
    return {"any": [{"inside": dict(where, has=one)}, {"inside": dict(where, all=pair)}]}



# Commons Codec `DigestUtils.md5Hex`, `getSha1Digest`; Spring `md5DigestAsHex`.
DIGEST_UTILS = "^(md2|md5|sha|sha1)(Hex|Digest|DigestAsHex)?$|^get(Md2|Md5|Sha|Sha1)Digest$|^appendMd5DigestAsHex$"
# A command string handed to a shell: `"sh -c …"`, `"/bin/bash -c …"`, `"cmd /c …"`,
# also as the format of `String.format`.
SHELL_STRING = (r'^(String\.format\(\s*)?"\s*((/usr)?/bin/)?(sh|bash|zsh|dash|ksh|ash)\s+-[a-z]*c\b'
                r'|^(String\.format\(\s*)?"\s*(?i:cmd(\.exe)?\s+/c|(powershell|pwsh)(\.exe)?\s+-(c|command))\b')


RULES = [
    dict(id="java-no-sql-concat", langs=["Java"], severity="error",
         message="SQL built by string concatenation.",
         note="Use a PreparedStatement with ? placeholders (JPA: named parameters) and bind the values.",
         rule={"kind": "binary_expression", "regex": SQL_TEXT, "has": {"field": "operator", "regex": "^\\+$"},
               "all": [{"has": {"stopBy": "end", "any": [{"kind": "identifier"}, {"kind": "method_invocation"}]}}],
               "not": {"inside": {"kind": "binary_expression"}}}),
    dict(id="java-no-weak-hash", langs=["Java"], severity="error",
         message="MD5 / SHA-1 are broken hash functions.",
         note="Use SHA-256 for checksums and a password hash (Argon2, bcrypt, PBKDF2) for passwords.",
         rule={"any": [
             {"kind": "method_invocation", "all": [
                 {"has": {"field": "name", "regex": "^getInstance$"}},
                 {"has": {"field": "object", "regex": "(^|\\.)MessageDigest$"}},
                 {"has": {"field": "arguments", "has": {"nthChild": 1, "pattern": "$ALG"}}},
             ]},
             # Apache Commons Codec, Spring; Guava.
             {"kind": "method_invocation", "all": [
                 {"has": {"field": "object", "regex": "(^|\\.)DigestUtils$"}},
                 {"has": {"field": "name", "regex": DIGEST_UTILS}},
             ]},
             {"kind": "method_invocation", "all": [
                 {"has": {"field": "object", "regex": "(^|\\.)Hashing$"}},
                 {"has": {"field": "name", "regex": "^(md5|sha1)$"}},
             ]},
         ]},
         # What the argument holds: a literal, a constant, a property file entry.
         resolve={"ALG": "(?i)^(md2|md4|md5|sha|sha-?1)$"}),
    dict(id="java-no-shell-string", langs=["Java"], severity="error",
         message="A command string that starts with a shell (`sh -c …`, `cmd /c …`) is built from values: "
                 "whatever they hold runs as shell code.",
         note="Run the program itself with an argument array (new ProcessBuilder(\"tool\", arg)); "
              "`Runtime.exec(String)` without a shell only splits on spaces.",
         rule={"kind": "method_invocation", "all": [
             {"has": {"field": "name", "regex": "^exec$"}},
             {"has": {"field": "arguments", "has": {
                 "nthChild": 1, "regex": SHELL_STRING,
                 "any": [{"kind": "binary_expression"}, {"kind": "method_invocation"}],
                 "has": {"stopBy": "end", "any": [{"kind": "identifier"}, {"kind": "method_invocation"}]},
             }}},
         ]}),
    dict(id="java-no-weak-cipher", langs=["Java"], severity="error",
         message="Broken cipher or mode (DES, 3DES, RC2/RC4, Blowfish, ECB; bare \"AES\" means AES/ECB).",
         note="Use AES/GCM/NoPadding (or ChaCha20-Poly1305) with a random IV per message.",
         rule={"kind": "method_invocation", "all": [
             {"has": {"field": "name", "regex": "^getInstance$"}},
             {"has": {"field": "object", "regex": "(^|\\.)Cipher$"}},
             {"has": {"field": "arguments", "has": {"nthChild": 1, "pattern": "$ALG"}}},
         ]},
         # ECB on a block cipher; RSA's "ECB" in a transformation means one block, not the mode.
         resolve={"ALG": "(?i)^(des|desede|tripledes|rc2|rc4|arcfour|blowfish)(/|$)|^aes$"
                         "|^(aes|aes_\\d+|camellia|aria|sm4|seed|twofish)/ecb/"}),
    dict(id="java-no-insecure-random", langs=["Java"], severity="warning",
         message="java.util.Random / Math.random are predictable; tokens, ids and keys made with them can be guessed.",
         note="Use java.security.SecureRandom for anything a user must not guess.",
         rule={"any": [
             {"kind": "object_creation_expression", "has": {"field": "type", "regex": "^(java\\.util\\.)?Random$"}},
             {"kind": "method_invocation", "all": [{"has": {"field": "object", "regex": "^(java\\.lang\\.)?Math$"}},
                                                   {"has": {"field": "name", "regex": "^random$"}}]},
         ]}),
    dict(id="java-no-insecure-cookie", langs=["Java"], severity="error",
         message="Cookie explicitly sent over plain HTTP or readable by scripts.",
         note="Call setSecure(true) and setHttpOnly(true) (Spring: ResponseCookie.from(...).secure(true).httpOnly(true)).",
         rule={"kind": "method_invocation", "all": [
             {"has": {"field": "name", "regex": "^(setSecure|setHttpOnly)$"}},
             {"has": {"field": "arguments", "regex": "^\\(\\s*false\\s*\\)$"}},
         ]}),
    dict(id="go-no-insecure-tls", langs=["Go"], severity="error",
         message="`InsecureSkipVerify: true` turns off TLS certificate checks.",
         note="Keep verification on; add the internal CA to RootCAs instead.",
         rule={"kind": "keyed_element", "regex": "^InsecureSkipVerify\\s*:\\s*true"}),
    dict(id="java-no-xxe", langs=["Java"], severity="error",
         message="XML parser created with DTDs and external entities on (XXE: file read, SSRF).",
         note="In the same method, setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true), or both "
              "external-general-entities and external-parameter-entities false "
              "(StAX: setProperty(XMLInputFactory.SUPPORT_DTD, false); TransformerFactory/SchemaFactory: "
              "setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, \"\")).",
         rule={"any": [
             {"kind": "method_invocation", "regex": "^(javax\\.xml\\.\\w+\\.)?(DocumentBuilderFactory|SAXParserFactory"
              "|XMLInputFactory|TransformerFactory|SAXTransformerFactory|SchemaFactory)\\s*\\.\\s*new(Instance|Factory)\\("},
             {"kind": "method_invocation", "regex": "^XMLReaderFactory\\s*\\.\\s*createXMLReader\\("},
             {"kind": "method_invocation", "regex": "\\.newSAXParser\\(\\)\\s*\\.\\s*getXMLReader\\(\\)$"},
             {"kind": "method_invocation", "regex": "^DocumentHelper\\s*\\.\\s*parseText\\("},
             {"kind": "object_creation_expression", "has": {"field": "type", "regex": "^(SAXBuilder|SAXReader|Digester)$"}},
             # JAXB has no XXE setting: unmarshal straight from a stream or file parses with its defaults.
             {"kind": "method_invocation", "all": [
                 {"has": {"field": "name", "regex": "^unmarshal$"}},
                 {"inside": {"any": [{"kind": k} for k in XXE_SCOPES], "stopBy": "end",
                             "has": {"kind": "method_invocation", "regex": "createUnmarshaller\\(", "stopBy": "end"}}},
                 {"not": {"inside": {"any": [{"kind": k} for k in XXE_SCOPES], "stopBy": "end",
                                     "has": {"regex": "^(SAXSource|StAXSource|DOMSource|XMLStreamReader|XMLEventReader)$",
                                             "stopBy": "end"}}}},
             ]},
         ], "not": {"any": [
             inside_configured({"any": [{"kind": k} for k in XXE_SCOPES], "stopBy": "end"}),
             # A factory kept in a field and configured elsewhere in the class.
             {"inside": dict({"kind": "field_declaration", "stopBy": "end"}, **inside_configured({"kind": "class_body"}))},
         ]}}),
    dict(id="java-no-jackson-default-typing", langs=["Java"], severity="error",
         message="Jackson polymorphic typing by class name: JSON from outside picks the class to build (deserialization RCE).",
         note="Drop enableDefaultTyping / Id.CLASS; deserialize into concrete types, or use activateDefaultTyping with a "
              "BasicPolymorphicTypeValidator that allows your own base types only.",
         rule={"any": [
             # Spring Security's SecurityJackson2Modules.enableDefaultTyping uses an allow-list.
             {"kind": "method_invocation", "has": {"field": "name", "regex": "^enableDefaultTyping(AsProperty)?$"},
              "not": {"has": {"field": "object", "regex": "SecurityJackson2Modules$"}}},
             {"kind": "method_invocation", "all": [
                 {"has": {"field": "name", "regex": "^activateDefaultTyping(AsProperty)?$"}},
                 {"has": {"field": "arguments", "regex": "LaissezFaireSubTypeValidator"}}]},
             # On a member typed Object/Serializable any class on the classpath fits.
             {"kind": "annotation", "all": [
                 {"has": {"field": "name", "regex": "^(com\\.fasterxml\\.jackson\\.annotation\\.)?JsonTypeInfo$"}},
                 {"has": {"field": "arguments", "regex": "Id\\.(MINIMAL_)?CLASS\\b"}},
                 {"inside": {"any": [{"kind": "field_declaration"}, {"kind": "formal_parameter"}, {"kind": "method_declaration"}],
                             "stopBy": "end", "has": {"field": "type", "regex": "^(java\\.lang\\.)?(Object|Serializable|Comparable|Cloneable)$"}}}]},
         ]}),
    dict(id="java-no-mybatis-sql-interpolation", langs=["Java"], severity="error",
         message="MyBatis ${} pastes the value into the SQL text (SQL injection).",
         note="Use #{} (a bound parameter); for an ORDER BY column or table name, map the request value to a fixed "
              "name in Java first.",
         rule={"kind": "annotation", "all": [
             {"has": {"field": "name", "regex": "^(Select|Update|Insert|Delete)$"}},
             {"has": {"field": "arguments", "stopBy": "end", "kind": "string_literal", "regex": "\\$\\{"}}]}),
    dict(id="java-spring-csrf-disabled", langs=["Java"], severity="error",
         message="Spring Security's CSRF protection switched off for the whole chain.",
         note="Keep CSRF on for anything a browser session drives; disable it only on a stateless token API, in that API's own chain.",
         rule={"kind": "method_invocation", "any": [
             {"regex": "\\.csrf\\(\\s*\\)\\s*\\.disable\\(\\s*\\)"},
             {"regex": "\\.csrf\\(\\s*\\w+\\s*->\\s*\\w+\\.disable\\(\\s*\\)\\s*\\)"}]}),
    dict(id="java-spring-permit-all", langs=["Java"], severity="error",
         message="`.anyRequest().permitAll()` leaves every URL public.",
         note="Deny by default and name what is public: `.requestMatchers(\"/login\", \"/health\").permitAll().anyRequest().authenticated()`.",
         rule={"kind": "method_invocation", "regex": "\\.anyRequest\\(\\s*\\)\\s*\\.permitAll\\(\\s*\\)"}),
    dict(id="java-spring-cors-wildcard", langs=["Java"], severity="warning",
         message="CORS open to every origin.",
         note="Name the origins the frontend runs on; `*` cannot be combined with credentials, and the usual workaround reflects any origin.",
         rule={"any": [
             {"kind": "annotation", "regex": "^@CrossOrigin\\s*\\([^)]*\"\\*\""},
             {"kind": "method_invocation", "regex": "allowedOrigin(s|Patterns)?\\(\\s*\"\\*\"\\s*\\)"}]}),
]

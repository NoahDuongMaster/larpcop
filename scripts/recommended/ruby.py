"""Ruby (Rails) rule specs."""

from .common import SQL_TEXT

# Names of values that are protocol checksums, not security digests.
NONSEC = "(?i)etag|checksum|md5|fingerprint|cache_key"

RULES = [
    dict(id="rb-no-sql-interpolation", langs=["Ruby"], severity="error",
         message="SQL built by string interpolation.",
         note="Use bind parameters: where(\"name = ?\", name), where(name: name), or sanitize_sql_array.",
         # Identifiers made safe for SQL (quote_column_name, sanitize_sql, to_i) are fine.
         rule={"kind": "string", "regex": SQL_TEXT, "has": {"kind": "interpolation", "not": {
             "regex": "quote_column_name|quote_table_name|\\.quote\\(|sanitize_sql|\\.to_i\\b|Integer\\("}}}),
    dict(id="rb-no-permit-all", langs=["Ruby"], severity="error",
         message="params.permit! allows every attribute (mass assignment: role, admin, owner…).",
         note="List the attributes a form may set: params.require(:user).permit(:name, :email).",
         rule={"kind": "call", "has": {"field": "method", "regex": "^permit!$"}}),
    dict(id="rb-no-csrf-skip", langs=["Ruby"], severity="error",
         message="CSRF protection turned off for a controller.",
         ignores=["**/api/**", "**/*_test.rb", "**/*_spec.rb", "**/test/**", "**/spec/**"],
         note="Keep verify_authenticity_token; for a JSON API authenticated by a token header, use protect_from_forgery with: :null_session in an API base controller.",
         rule={"any": [
             {"kind": "call", "all": [
                 {"has": {"field": "method", "regex": "^(skip_before_action|skip_before_filter)$"}},
                 {"has": {"field": "arguments", "regex": ":verify_authenticity_token"}}]},
             {"kind": "call", "has": {"field": "method", "regex": "^skip_forgery_protection$"}},
             {"kind": "identifier", "regex": "^skip_forgery_protection$"},
         ]}),
    dict(id="rb-no-weak-hash", langs=["Ruby"], severity="error",
         message="MD5 / SHA-1 are broken hash functions.",
         note="Use BCrypt / Argon2 (has_secure_password) for passwords and SHA-256 for anything that must not be forged. "
              "A protocol checksum (ETag, Content-MD5) is fine when the value it is stored in says so (etag, checksum, md5).",
         rule={"all": [
             {"any": [
                 {"kind": "scope_resolution", "regex": "^(OpenSSL::)?Digest::(MD5|SHA1)$",
                  "not": {"inside": {"kind": "scope_resolution"}}},
                 {"kind": "call", "regex": "^(OpenSSL::)?Digest(::Digest)?\\.new\\(\\s*['\"](?i:md5|sha1)['\"]"},
             ]},
             # Stored as a checksum: `etag = …`, `checksum: …`, `def info_checksum`.
             {"not": {"inside": {"stopBy": "end", "any": [
                 {"kind": "assignment", "has": {"field": "left", "regex": NONSEC}},
                 {"kind": "pair", "has": {"field": "key", "regex": NONSEC}},
                 {"kind": "method", "has": {"field": "name", "regex": NONSEC}},
             ]}}},
         ]}),
    dict(id="rb-no-ssl-verify-none", langs=["Ruby"], severity="error",
         message="TLS certificate verification turned off.",
         note="Keep OpenSSL::SSL::VERIFY_PEER; add the private CA to the store instead of disabling checks.",
         rule={"kind": "scope_resolution", "regex": "^OpenSSL::SSL::VERIFY_NONE$"}),
    dict(id="rb-no-html-safe-interpolation", langs=["Ruby"], severity="warning",
         message="Interpolated string marked html_safe: the interpolated values are not escaped (XSS).",
         note="Build the HTML with content_tag / tag helpers, or escape each value (ERB::Util.html_escape) before html_safe; safe_join joins escaped parts.",
         rule={"kind": "call", "all": [
             {"has": {"field": "method", "regex": "^html_safe$"}},
             {"has": {"field": "receiver", "kind": "string", "has": {"kind": "interpolation"}}},
         ]}),
    dict(id="rb-no-cookie-httponly-off", langs=["Ruby"], severity="error",
         message="Session or cookie readable by scripts (httponly: false) or sent over plain HTTP (secure: false).",
         note="Leave httponly and secure at their defaults (true in production), so an XSS cannot read the session and HTTP cannot leak it.",
         rule={"kind": "pair", "regex": "^:?(httponly|secure)(:|\\s*=>)\\s*false$"}),
    dict(id="rb-no-json-html-escape-off", langs=["Ruby"], severity="error",
         message="HTML entities left unescaped in JSON: JSON embedded in a page can close the <script> tag (XSS).",
         note="Keep escape_html_entities_in_json = true (the Rails default).",
         rule={"kind": "assignment", "regex": "escape_html_entities_in_json\\s*=\\s*false"}),
]

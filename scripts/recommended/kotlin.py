"""Kotlin rule specs: the Java ones whose construct reads the same in Kotlin,
written as patterns (Kotlin's grammar names few fields)."""

WEAK_HASH = "(?i)^(md2|md4|md5|sha|sha-?1)$"
# ECB on a block cipher; RSA's "ECB" in a transformation means one block.
WEAK_CIPHER = ("(?i)^(des|desede|tripledes|rc2|rc4|arcfour|blowfish)(/|$)|^aes$"
               "|^(aes|aes_\\d+|camellia|aria|sm4|seed|twofish)/ecb/")


def calls(receiver, method):
    """`R.m(arg)` and `R.m(arg, provider)`, with `$ALG` the first argument."""
    return {"any": [{"pattern": f"{receiver}.{method}($ALG)"},
                    {"pattern": f"{receiver}.{method}($ALG, $P)"}]}


from recommended.java import DIGEST_UTILS, SHELL_STRING  # noqa: E402


def named(regex):
    """A call whose callee (`a.b.name`) matches."""
    return {"kind": "call_expression", "has": {"kind": "navigation_expression", "regex": regex}}


RULES = [
    dict(id="kt-no-weak-hash", langs=["Kotlin"], severity="error",
         message="MD5 / SHA-1 are broken hash functions.",
         note="Use SHA-256 for checksums and a password hash (Argon2, bcrypt, PBKDF2) for passwords.",
         rule={"any": [calls("MessageDigest", "getInstance"), calls("java.security.MessageDigest", "getInstance"),
                       named("(^|\\.)DigestUtils\\.(" + DIGEST_UTILS.replace("^", "").replace("$", "") + ")$"),
                       named("(^|\\.)Hashing\\.(md5|sha1)$")]},
         resolve={"ALG": WEAK_HASH}),
    dict(id="kt-no-weak-cipher", langs=["Kotlin"], severity="error",
         message="Broken cipher or mode (DES, 3DES, RC2/RC4, Blowfish, ECB; bare \"AES\" means AES/ECB).",
         note="Use AES/GCM/NoPadding (or ChaCha20-Poly1305) with a random IV per message.",
         rule={"any": [calls("Cipher", "getInstance"), calls("javax.crypto.Cipher", "getInstance")]},
         resolve={"ALG": WEAK_CIPHER}),
    dict(id="kt-no-shell-string", langs=["Kotlin"], severity="error",
         message="A command string that starts with a shell (`sh -c …`, `cmd /c …`) is built from values: "
                 "whatever they hold runs as shell code.",
         note="Run the program itself with an argument list (ProcessBuilder(\"tool\", arg)); "
              "`Runtime.exec(String)` without a shell only splits on spaces.",
         rule={"kind": "call_expression", "all": [
             {"has": {"kind": "navigation_expression", "regex": "\\.exec$"}},
             {"has": {"kind": "call_suffix", "has": {"kind": "value_arguments", "has": {
                 "kind": "value_argument", "nthChild": 1, "has": {
                     "regex": SHELL_STRING,
                     "any": [
                         {"kind": "string_literal", "has": {"any": [
                             {"kind": "interpolated_identifier"}, {"kind": "interpolated_expression"}]}},
                         {"kind": "additive_expression", "has": {"stopBy": "end", "kind": "simple_identifier"}},
                         {"kind": "call_expression"},
                     ]}}}}},
         ]}),
]

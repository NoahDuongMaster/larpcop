#!/usr/bin/env python3
"""Scores SAST results against known vulnerable lines.

Juice Shop: every `// vuln-code-snippet vuln-line <challenge>` comment, written
by the Juice Shop maintainers for their coding challenges (outside test/ and
data/static/codefixes/). Other targets: a truth file (`--truth x.json`) fixed
before any tool ran on them. A tool finds a line when one of its findings spans
it, give or take WINDOW lines.

Usage: score.py REPO_DIR LARPCOP_JSON SEMGREP_JSON [GITLEAKS_JSON] [--truth TRUTH_JSON]
"""
import collections
import json
import pathlib
import re
import sys

WINDOW = 3
MARK = re.compile(r"vuln-code-snippet vuln-line ([\w ]+)")
SINK_AT = re.compile(r"Reaches the sink through .*? at ([^\s:]+):(\d+)\.")
SKIP = ("test/", "data/static/codefixes/", "lib/codingChallenges", "node_modules/")
# larpcop rules that are about security (the rest of `recommended` is code quality).
SECURITY = {
    "no-sql-interpolation", "py-no-sql-interpolation", "go-no-sql-sprintf", "taint-sql", "py-taint-sql",
    "taint-shell", "taint-redirect", "no-shell-interpolation", "py-no-shell-true", "no-eval", "py-no-eval",
    "no-inner-html", "no-dangerously-set-inner-html", "no-bypass-security-trust", "no-directory-listing",
    "no-weak-hash", "py-no-weak-hash", "no-mongo-where", "py-no-tls-verify-off", "go-no-insecure-tls",
    "py-yaml-safe-load", "secrets", "validate-request-input", "dependency-vulnerability",
    "gha-script-injection", "gha-curl-pipe-shell", "gha-unpinned-action", "gha-pr-target-checkout",
    "tf-public-bucket-acl", "tf-open-ingress", "tf-publicly-accessible-db", "tf-iam-wildcard",
    "no-regex-redos", "py-no-regex-redos", "no-template-autoescape-off", "py-no-template-autoescape-off",
    "no-plaintext-password-compare", "py-no-plaintext-password-compare", "taint-log", "py-taint-log",
    "no-hardcoded-session-secret", "py-no-hardcoded-secret-key", "no-xml-external-entities",
    "py-no-xml-external-entities", "no-unsafe-deserialization", "py-no-unsafe-deserialization", "taint-code",
    "no-unescaped-template-output", "pug-no-unescaped-output", "no-document-write",
    "taint-dom-xss", "taint-dom-redirect", "php-taint-ssti", "php-no-weak-hash", "php-no-session-fixation",
    "php-taint-predictable-token", "php-taint-csv", "py-taint-csv", "taint-csv", "java-taint-csv",
    "cs-taint-csv", "php-taint-stored-sql",
    "php-no-insecure-random",
    "taint-xss", "taint-path", "taint-ssrf", "taint-nosql", "taint-regex", "no-unsafe-recursive-merge",
    "py-taint-path", "py-taint-ssrf", "py-taint-ssti", "py-taint-code",
    "no-session-fixation", "py-no-session-fixation",
    "no-jwt-none-algorithm", "py-no-jwt-unverified", "no-ldap-interpolation", "py-no-ldap-interpolation",
    "no-env-file-secrets",
    "go-no-unsafe-template-type", "go-taint-sql", "go-taint-shell", "go-taint-path", "go-taint-ssrf",
    "go-taint-redirect", "go-taint-xss",
    "java-taint-sql", "java-taint-shell", "java-taint-path", "java-taint-xss", "java-taint-ldap", "java-taint-xpath",
    "java-taint-redirect", "java-taint-trust-boundary", "java-no-sql-concat", "java-no-weak-hash", "java-no-shell-string",
    "java-no-weak-cipher", "java-no-insecure-random", "java-no-insecure-cookie",
    "php-taint-sql", "php-taint-shell", "php-taint-code", "php-taint-path", "php-taint-xss", "php-taint-ssrf",
    "php-taint-redirect", "php-taint-deserialization", "php-no-sql-interpolation", "php-no-eval", "php-no-unserialize",
    "cs-taint-sql", "cs-taint-shell", "cs-taint-path", "cs-taint-xss", "cs-taint-ssrf", "cs-taint-redirect",
    "cs-taint-deserialization", "cs-taint-ldap", "cs-taint-xpath",
    "rb-taint-sql", "rb-taint-shell", "rb-taint-code", "rb-taint-path", "rb-taint-xss", "rb-taint-redirect",
    "rb-taint-ssrf", "rb-taint-deserialization", "rb-no-sql-interpolation", "rb-no-permit-all", "rb-no-csrf-skip",
    "rb-no-weak-hash", "rb-no-ssl-verify-none", "rb-no-html-safe-interpolation", "rb-no-cookie-httponly-off", "rb-csrf-off",
    "py-taint-xss", "py-taint-shell", "py-taint-redirect", "py-taint-deserialization", "java-taint-ssrf",
    "java-taint-code", "java-taint-deserialization", "php-taint-ldap", "php-taint-xpath",
    "php-taint-stored-xss",
    "rb-no-json-html-escape-off",
}


def out(line=""):
    sys.stdout.write(line + "\n")


def markers(root):
    found = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if path.suffix not in (".ts", ".js", ".html") or rel.startswith(SKIP) or not path.is_file():
            continue
        for i, line in enumerate(path.read_text(errors="ignore").splitlines(), 1):
            m = MARK.search(line)
            if m:
                found.append((rel, i, m.group(1).split()))
    return found


def sinks(v):
    """A finding at a call site also covers the sink its note names in another
    file: "Reaches the sink through `f` → … at app/models/x.rb:15"."""
    spans = [(v["file"], v["line"], v["line"], v["rule"], True)]
    if m := SINK_AT.search(v.get("note") or ""):
        spans.append((m.group(1), int(m.group(2)), int(m.group(2)), v["rule"], False))
    return spans


def load(ak, sg):
    a = json.load(open(ak))["violations"]
    s = json.load(open(sg))["results"]
    return {
        "larpcop": [span for v in a if v["rule"] in SECURITY for span in sinks(v)],
        "Semgrep OSS": [(r["path"], r["start"]["line"], r["end"]["line"], r["check_id"].split(".")[-1], True)
                        for r in s],
    }


def hit(spans, rel, line):
    return sorted({rule for f, s, e, rule, _ in spans if f == rel and s - WINDOW <= line <= e + WINDOW})


def secrets_parity(ak, gl):
    g = collections.Counter((x["File"].lstrip("./"), x["StartLine"], x["RuleID"]) for x in json.load(open(gl)))
    a = collections.Counter(
        (v["file"], v["line"], m.group(1))
        for v in json.load(open(ak))["violations"]
        if v["rule"] == "secrets" and (m := re.search(r"rule `([^`]+)`", v["message"])))
    out(f"\nSecrets vs gitleaks: {sum((g & a).values())} identical findings; "
        f"{sum((g - a).values())} only in gitleaks, {sum((a - g).values())} only in larpcop.")
    for k in sorted(g - a):
        out(f"- only gitleaks: `{k[0]}:{k[1]}` ({k[2]})")
    for k in sorted(a - g):
        out(f"- only larpcop: `{k[0]}:{k[1]}` ({k[2]})")


def truth(path):
    doc = json.load(open(path))
    return [(x["file"], x["line"], [x["label"]]) for x in doc["lines"]]


def main():
    args = sys.argv[1:]
    truth_file = args.pop(args.index("--truth") + 1) if "--truth" in args else None
    if truth_file:
        args.remove("--truth")
    root, ak, sg = pathlib.Path(args[0]), args[1], args[2]
    gl = args[3] if len(args) > 3 else None
    tools = load(ak, sg)
    rows = truth(truth_file) if truth_file else markers(root)
    found = collections.Counter()
    out("| Line | Vulnerability | " + " | ".join(tools) + " |\n|---|---|---|---|")
    for rel, line, challenges in rows:
        cells = []
        for name, spans in tools.items():
            rules = hit(spans, rel, line)
            found[name] += bool(rules)
            cells.append(", ".join(f"`{r}`" for r in rules) or "–")
        out(f"| `{rel}:{line}` | {', '.join(challenges)} | " + " | ".join(cells) + " |")
    out()
    for name, spans in tools.items():
        # Each finding once, not once per location it covers.
        per_rule = collections.Counter(s[3] for s in spans if s[4]).most_common()
        out(f"- {name}: {found[name]}/{len(rows)} lines; {sum(s[4] for s in spans)} security findings: "
            + ", ".join(f"{r} {n}" for r, n in per_rule))
    if gl:
        secrets_parity(ak, gl)


if __name__ == "__main__":
    main()

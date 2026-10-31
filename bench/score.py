#!/usr/bin/env python3
"""Scores SAST results against OWASP Juice Shop's own vulnerability markers.

Ground truth: every `// vuln-code-snippet vuln-line <challenge>` comment in the
Juice Shop source, written by the Juice Shop maintainers for their coding
challenges (outside test/ and data/static/codefixes/). A tool finds a marked
line when one of its findings spans it, give or take WINDOW lines.

Usage: score.py JUICE_SHOP_DIR AGENTKIT_JSON SEMGREP_JSON GITLEAKS_JSON
"""
import collections
import json
import pathlib
import re
import sys

WINDOW = 3
MARK = re.compile(r"vuln-code-snippet vuln-line ([\w ]+)")
SKIP = ("test/", "data/static/codefixes/", "lib/codingChallenges", "node_modules/")
# agentkit rules that are about security (the rest of `recommended` is code quality).
SECURITY = {
    "no-sql-interpolation", "py-no-sql-interpolation", "go-no-sql-sprintf", "taint-sql", "py-taint-sql",
    "taint-shell", "taint-redirect", "no-shell-interpolation", "py-no-shell-true", "no-eval", "py-no-eval",
    "no-inner-html", "no-dangerously-set-inner-html", "no-bypass-security-trust", "no-directory-listing",
    "no-weak-hash", "py-no-weak-hash", "no-mongo-where", "py-no-tls-verify-off", "go-no-insecure-tls",
    "py-yaml-safe-load", "secrets", "validate-request-input", "dependency-vulnerability",
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


def load(ak, sg):
    a = json.load(open(ak))["violations"]
    s = json.load(open(sg))["results"]
    return {
        "agentkit": [(v["file"], v["line"], v["line"], v["rule"]) for v in a if v["rule"] in SECURITY],
        "Semgrep OSS": [(r["path"], r["start"]["line"], r["end"]["line"], r["check_id"].split(".")[-1]) for r in s],
    }


def hit(spans, rel, line):
    return sorted({rule for f, s, e, rule in spans if f == rel and s - WINDOW <= line <= e + WINDOW})


def secrets_parity(ak, gl):
    g = collections.Counter((x["File"].lstrip("./"), x["StartLine"], x["RuleID"]) for x in json.load(open(gl)))
    a = collections.Counter(
        (v["file"], v["line"], m.group(1))
        for v in json.load(open(ak))["violations"]
        if v["rule"] == "secrets" and (m := re.search(r"rule `([^`]+)`", v["message"])))
    out(f"\nSecrets vs gitleaks: {sum((g & a).values())} identical findings; "
        f"{sum((g - a).values())} only in gitleaks, {sum((a - g).values())} only in agentkit.")
    for k in sorted(g - a):
        out(f"- only gitleaks: `{k[0]}:{k[1]}` ({k[2]})")
    for k in sorted(a - g):
        out(f"- only agentkit: `{k[0]}:{k[1]}` ({k[2]})")


def main():
    root, ak, sg, gl = pathlib.Path(sys.argv[1]), *sys.argv[2:5]
    tools = load(ak, sg)
    rows = markers(root)
    found = collections.Counter()
    out("| Marked line | Challenge | " + " | ".join(tools) + " |\n|---|---|---|---|")
    for rel, line, challenges in rows:
        cells = []
        for name, spans in tools.items():
            rules = hit(spans, rel, line)
            found[name] += bool(rules)
            cells.append(", ".join(f"`{r}`" for r in rules) or "–")
        out(f"| `{rel}:{line}` | {', '.join(challenges)} | " + " | ".join(cells) + " |")
    out()
    for name, spans in tools.items():
        per_rule = collections.Counter(s[3] for s in spans).most_common()
        out(f"- {name}: {found[name]}/{len(rows)} marked lines; {len(spans)} security findings: "
            + ", ".join(f"{r} {n}" for r, n in per_rule))
    secrets_parity(ak, gl)


main()

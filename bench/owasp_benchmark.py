#!/usr/bin/env python3
"""Scores tools on the OWASP Benchmark (Java or Python) the way its own scorecard does:
a test case counts as reported when a finding of the matching vulnerability
category falls in its file; score = true-positive rate - false-positive rate,
per category, then averaged over categories.

    owasp_benchmark.py BENCHMARK_DIR LARPCOP_JSON SEMGREP_JSON [SEMGREP_JSON_2 ...]
"""
import csv
import glob
import json
import re
import sys

CWE = {"22": "pathtraver", "78": "cmdi", "79": "xss", "89": "sqli", "90": "ldapi", "327": "crypto",
       "328": "hash", "330": "weakrand", "501": "trustbound", "614": "securecookie", "643": "xpathi",
       "94": "codeinj", "95": "codeinj", "502": "deserialization", "601": "redirect", "611": "xxe"}
LARPCOP = {
    "java-taint-sql": "sqli", "java-no-sql-concat": "sqli", "java-taint-shell": "cmdi",
    "java-no-shell-string": "cmdi",
    "java-taint-path": "pathtraver", "java-taint-xss": "xss", "java-taint-ldap": "ldapi",
    "java-taint-xpath": "xpathi", "java-taint-trust-boundary": "trustbound", "java-no-weak-hash": "hash",
    "java-no-weak-cipher": "crypto", "java-no-insecure-random": "weakrand", "java-no-insecure-cookie": "securecookie",
    "java-taint-redirect": "redirect", "java-taint-code": "codeinj", "java-taint-deserialization": "deserialization",
    "java-no-xxe": "xxe",
    "py-taint-sql": "sqli", "py-no-sql-interpolation": "sqli", "py-taint-shell": "cmdi", "py-no-shell-true": "cmdi",
    "py-taint-path": "pathtraver", "py-taint-xss": "xss", "py-no-template-autoescape-off": "xss",
    "py-taint-ldap": "ldapi", "py-no-ldap-interpolation": "ldapi", "py-taint-xpath": "xpathi",
    "py-taint-trust-boundary": "trustbound", "py-no-weak-hash": "hash", "py-no-insecure-random": "weakrand",
    "py-no-insecure-cookie": "securecookie", "py-taint-code": "codeinj", "py-no-eval": "codeinj",
    "py-taint-ssti": "codeinj", "py-taint-deserialization": "deserialization",
    "py-no-unsafe-deserialization": "deserialization", "py-yaml-safe-load": "deserialization",
    "py-taint-redirect": "redirect", "py-no-xml-external-entities": "xxe",
}
TEST = re.compile(r"(BenchmarkTest\d{5})\.(java|py)$")


def expected(root):
    out = {}
    with open(sorted(glob.glob(f"{root}/expectedresults-*.csv"))[-1]) as f:
        for row in csv.reader(f):
            if row and not row[0].startswith("#"):
                out[row[0]] = (row[1], row[2].strip() == "true")
    return out


def larpcop(path):
    found = set()
    for v in json.load(open(path))["violations"]:
        m, cat = TEST.search(v["file"]), LARPCOP.get(v["rule"])
        if m and cat:
            found.add((m.group(1), cat))
    return found


def semgrep(path):
    found = set()
    for r in json.load(open(path))["results"]:
        m = TEST.search(r["path"])
        cwes = r.get("extra", {}).get("metadata", {}).get("cwe", [])
        cwes = cwes if isinstance(cwes, list) else [cwes]
        for c in cwes:
            n = re.match(r"CWE-(\d+)", str(c))
            if m and n and n.group(1) in CWE:
                found.add((m.group(1), CWE[n.group(1)]))
    return found


def score(truth, found):
    cats = {}
    for test, (cat, real) in truth.items():
        c = cats.setdefault(cat, [0, 0, 0, 0])  # tp, fn, fp, tn
        hit = (test, cat) in found
        c[0 if real and hit else 1 if real else 2 if hit else 3] += 1
    rows, total = [], []
    for cat in sorted(cats):
        tp, fn, fp, tn = cats[cat]
        tpr, fpr = tp / max(tp + fn, 1), fp / max(fp + tn, 1)
        rows.append((cat, tpr, fpr, tpr - fpr))
        total.append(tpr - fpr)
    return rows, sum(total) / len(total)


def main():
    root, tools = sys.argv[1], [("larpcop", larpcop(sys.argv[2]))]
    for i, p in enumerate(sys.argv[3:]):
        tools.append((f"Semgrep ({p.rsplit('/', 1)[-1].removesuffix('.json')})", semgrep(p)))
    truth = expected(root)
    results = [(name, *score(truth, found)) for name, found in tools]
    out = sys.stdout.write
    out("| Category | " + " | ".join(f"{n} TPR / FPR / score" for n, *_ in results) + " |\n")
    out("|---|" + "---|" * len(results) + "\n")
    for i, (cat, *_) in enumerate(results[0][1]):
        cells = [f"{r[1][i][1]:.0%} / {r[1][i][2]:.0%} / **{r[1][i][3]:+.0%}**" for r in results]
        out(f"| {cat} | " + " | ".join(cells) + " |\n")
    out("| **average** | " + " | ".join(f"**{r[2]:+.1%}**" for r in results) + " |\n")


if __name__ == "__main__":
    main()

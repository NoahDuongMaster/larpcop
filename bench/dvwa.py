#!/usr/bin/env python3
"""Scores tools on DVWA's levels: in each module, source/low.php, medium.php
and high.php are vulnerable by design and impossible.php is the fixed
version. A file counts as reported when a finding of the module's category
falls in it; score = true-positive rate - false-positive rate per category.

    dvwa.py LARPCOP_JSON SEMGREP_JSON
"""
import json
import re
import sys

MODULES = {"sqli": "sql", "sqli_blind": "sql", "exec": "shell", "fi": "path", "upload": "path",
           "xss_r": "xss", "xss_s": "xss", "open_redirect": "redirect"}
LEVELS = {"low": True, "medium": True, "high": True, "impossible": False}
CWE = {"89": "sql", "78": "shell", "77": "shell", "22": "path", "98": "path", "73": "path", "434": "path",
       "79": "xss", "601": "redirect"}
LARPCOP = {"php-taint-sql": "sql", "php-no-sql-interpolation": "sql", "php-taint-shell": "shell",
           "php-taint-path": "path", "php-taint-xss": "xss", "php-taint-redirect": "redirect"}
FILE = re.compile(r"vulnerabilities/(\w+)/source/(\w+)\.php$")


def cases():
    return {(m, lvl): (cat, real) for m, cat in MODULES.items() for lvl, real in LEVELS.items()}


def found_larpcop(path):
    out = set()
    for v in json.load(open(path))["violations"]:
        m = FILE.search(v["file"])
        if m and LARPCOP.get(v["rule"]):
            out.add((m.group(1), m.group(2), LARPCOP[v["rule"]]))
    return out


def found_semgrep(path):
    out = set()
    for r in json.load(open(path))["results"]:
        m = FILE.search(r["path"])
        cwes = r.get("extra", {}).get("metadata", {}).get("cwe", [])
        for c in cwes if isinstance(cwes, list) else [cwes]:
            n = re.match(r"CWE-(\d+)", str(c))
            if m and n and n.group(1) in CWE:
                out.add((m.group(1), m.group(2), CWE[n.group(1)]))
    return out


def main():
    tools = [("larpcop", found_larpcop(sys.argv[1])), ("Semgrep OSS", found_semgrep(sys.argv[2]))]
    out = sys.stdout.write
    out("| Category | " + " | ".join(f"{n}: TPR / FPR / score" for n, _ in tools) + " |\n")
    out("|---|" + "---|" * len(tools) + "\n")
    averages = [[] for _ in tools]
    for cat in sorted(set(MODULES.values())):
        cells = []
        for i, (_, found) in enumerate(tools):
            tp = fn = fp = tn = 0
            for (mod, lvl), (c, real) in cases().items():
                if c != cat:
                    continue
                hit = (mod, lvl, cat) in found
                tp, fn, fp, tn = tp + (real and hit), fn + (real and not hit), fp + (hit and not real), tn + (not real and not hit)
            tpr, fpr = tp / max(tp + fn, 1), fp / max(fp + tn, 1)
            averages[i].append(tpr - fpr)
            cells.append(f"{tp}/{tp + fn} found, {fp}/{fp + tn} fixed flagged / **{tpr - fpr:+.0%}**")
        out(f"| {cat} | " + " | ".join(cells) + " |\n")
    out("| **average** | " + " | ".join(f"**{sum(a) / len(a):+.1%}**" for a in averages) + " |\n")


if __name__ == "__main__":
    main()

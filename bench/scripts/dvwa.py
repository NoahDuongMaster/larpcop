#!/usr/bin/env python3
"""Scores larpcop on DVWA's levels: in each module, source/low.php, medium.php
and high.php are vulnerable by design and impossible.php is the fixed
version. A file counts as reported when a finding of the module's category
falls in it; score = true-positive rate - false-positive rate per category.

    dvwa.py LARPCOP_JSON

LARPCOP_JSON is the output of `larpcop check --format json`.
"""
import json
import re
import sys

MODULES = {"sqli": "sql", "sqli_blind": "sql", "exec": "shell", "fi": "path", "upload": "path",
           "xss_r": "xss", "xss_s": "xss", "open_redirect": "redirect"}
LEVELS = {"low": True, "medium": True, "high": True, "impossible": False}
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


def main():
    found = found_larpcop(sys.argv[1])
    out = sys.stdout.write
    out("| Category | larpcop: TPR / FPR / score |\n")
    out("|---|---|\n")
    averages = []
    for cat in sorted(set(MODULES.values())):
        tp = fn = fp = tn = 0
        for (mod, lvl), (c, real) in cases().items():
            if c != cat:
                continue
            hit = (mod, lvl, cat) in found
            tp, fn, fp, tn = tp + (real and hit), fn + (real and not hit), fp + (hit and not real), tn + (not real and not hit)
        tpr, fpr = tp / max(tp + fn, 1), fp / max(fp + tn, 1)
        averages.append(tpr - fpr)
        out(f"| {cat} | {tp}/{tp + fn} found, {fp}/{fp + tn} fixed flagged / **{tpr - fpr:+.0%}** |\n")
    out(f"| **average** | **{sum(averages) / len(averages):+.1%}** |\n")


if __name__ == "__main__":
    main()

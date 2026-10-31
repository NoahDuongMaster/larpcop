#!/usr/bin/env python3
"""Scores scanners on Java endpoint truths (java-sec-code, VulnerableApp): an endpoint counts as reported when a
finding of its category lies in its line range (a call-site finding of an
interprocedural flow sits there too). Score per category = TPR - FPR.

usage: java_sec_code.py TRUTH REPO NAME=FINDINGS.json [NAME=FINDINGS.json …]
Findings: larpcop JSON (`violations`) or Semgrep JSON (`results`)."""
import json
import pathlib
import sys

# First match wins: deserialization before xxe (XMLDecoder), code before shell.
CATEGORIES = [
    ("deserializ", "deserialization"), ("xmldecoder", "deserialization"), ("xml-decoder", "deserialization"),
    ("xstream", "deserialization"), ("jackson", "deserialization"), ("fastjson", "deserialization"),
    ("objectinputstream", "deserialization"), ("snakeyaml", "deserialization"), ("yaml", "deserialization"),
    ("ssti", "ssti"), ("template", "ssti"), ("velocity", "ssti"),
    ("xxe", "xxe"), ("doctype", "xxe"), ("external-entit", "xxe"), ("xml-parser", "xxe"),
    ("ldap", "ldap"), ("sql", "sql"), ("ssrf", "ssrf"), ("tainted-url", "ssrf"), ("url-host", "ssrf"),
    ("redirect", "redirect"), ("xss", "xss"),
    ("spel", "code"), ("script-engine", "code"), ("scriptengine", "code"), ("groovy", "code"), ("ognl", "code"),
    ("el-injection", "code"), ("expression", "code"), ("eval", "code"), ("-code", "code"), ("reflection", "code"),
    ("command", "shell"), ("exec", "shell"), ("process", "shell"), ("shell", "shell"),
    ("path", "path"), ("traversal", "path"), ("file-inclusion", "path"),
]


def category(rule):
    rule = rule.lower()
    return next((c for k, c in CATEGORIES if k in rule), None)


def findings(path, repo):
    data = json.loads(pathlib.Path(path).read_text())
    out = []
    for v in data.get("violations", []):
        out.append((v["file"], v["line"], category(v["rule"])))
    for r in data.get("results", []):
        f = str((pathlib.Path(repo) / r["path"]).resolve().relative_to(pathlib.Path(repo).resolve()))
        out.append((f, r["start"]["line"], category(r["check_id"])))
    return out


def main(truth, repo, runs):
    rows = json.loads(pathlib.Path(truth).read_text())
    cats = sorted({r["category"] for r in rows})
    sys.stdout.write("| category (vuln/safe) | " + " | ".join(n for n, _ in runs) + " |" + "\n")
    sys.stdout.write("|---|" + "---|" * len(runs) + "\n")
    totals = {n: [0, 0, 0, 0] for n, _ in runs}
    scores = {n: [] for n, _ in runs}
    hits = {n: findings(p, repo) for n, p in runs}
    for c in cats:
        mine = [r for r in rows if r["category"] == c]
        pos = sum(r["vulnerable"] for r in mine)
        neg = len(mine) - pos
        cells = []
        for n, _ in runs:
            tp = fp = 0
            for r in mine:
                seen = any(f == r["file"] and r["start"] <= ln <= r["end"] and k == c for f, ln, k in hits[n])
                tp += seen and r["vulnerable"]
                fp += seen and not r["vulnerable"]
            t = totals[n]
            t[0] += tp; t[1] += pos - tp; t[2] += fp; t[3] += neg - fp
            tpr = tp / pos if pos else 0
            fpr = fp / neg if neg else 0
            scores[n].append(tpr - fpr)
            cells.append(f"{tp}/{pos} TP, {fp}/{neg} FP ({(tpr - fpr) * 100:+.0f}%)")
        sys.stdout.write(f"| {c} ({pos}/{neg}) | " + " | ".join(cells) + " |" + "\n")
    avg = [f"**{sum(s) / len(s) * 100:+.1f}%**" for s in scores.values()]
    sys.stdout.write("| **average** | " + " | ".join(avg) + " |" + "\n")
    tot = [f"{t[0]}/{t[0] + t[1]} TP, {t[2]}/{t[2] + t[3]} FP" for t in totals.values()]
    sys.stdout.write("| **total** | " + " | ".join(tot) + " |" + "\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], [tuple(a.split("=", 1)) for a in sys.argv[3:]])

#!/usr/bin/env python3
"""Scores larpcop's Kotlin rules on the Kotlin test files of the Semgrep rules
repository (semgrep/semgrep-rules, pinned), whose lines are labeled by their
authors: `// ruleid: <rule>` marks the next code line as a finding of that
rule, `// ok: <rule>` as clean. Only the categories larpcop has a Kotlin rule
for are scored; each labeled line is a case, found when a larpcop finding of
the mapped rule lands on it, flagged wrongly when one lands on an `ok` line.

The selection below was written and committed before any tool ran on these
files.

    semgrep_kotlin.py DIR LARPCOP_JSON     # DIR: where fetch() put the files
    semgrep_kotlin.py --fetch DIR
"""
import json
import pathlib
import re
import sys
import urllib.request

COMMIT = "16b9e6d45f10649f6a531ec4838ed9924372c3bc"
# Semgrep test file (under kotlin/lang/security/) -> (Semgrep rule id, larpcop rule ids).
# kt-no-shell-string was added after the first run (see bench/results/semgrep-kotlin.md).
CASES = {
    "use-of-md5.kt": ("use-of-md5", "kt-no-weak-hash"),
    "use-of-sha1.kt": ("use-of-sha1", "kt-no-weak-hash"),
    "ecb-cipher.kt": ("ecb-cipher", "kt-no-weak-cipher"),
    "command-injection-formatted-runtime-call.kt": ("command-injection-formatted-runtime-call",
                                                    "kt-taint-shell kt-no-shell-string"),
}
LABEL = re.compile(r"//\s*(ruleid|ok)\s*:\s*([\w.-]+)")


def fetch(out):
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    for name in CASES:
        url = f"https://raw.githubusercontent.com/semgrep/semgrep-rules/{COMMIT}/kotlin/lang/security/{name}"
        (out / name).write_bytes(urllib.request.urlopen(url).read())


def labels(path, semgrep_id):
    """(line, vulnerable) for each labeled line: the next non-comment line."""
    lines = path.read_text().splitlines()
    out = []
    for i, line in enumerate(lines):
        m = LABEL.search(line)
        if not m or m.group(2) != semgrep_id:
            continue
        j = i + 1
        while j < len(lines) and (not lines[j].strip() or lines[j].strip().startswith("//")):
            j += 1
        out.append((j + 1, m.group(1) == "ruleid"))
    return out


def main():
    if sys.argv[1] == "--fetch":
        fetch(sys.argv[2])
        return
    root, results = pathlib.Path(sys.argv[1]), sys.argv[2]
    found = {(pathlib.Path(v["file"]).name, v["line"], v["rule"]) for v in json.load(open(results))["violations"]}
    out = sys.stdout.write
    out("| File (rule) | found | flagged wrongly |\n|---|---|---|\n")
    tp = fn = fp = tn = 0
    for name, (semgrep_id, ours) in CASES.items():
        f_tp = f_fn = f_fp = f_tn = 0
        for line, bad in labels(root / name, semgrep_id):
            hit = any((name, line, rule) in found for rule in ours.split())
            f_tp += bad and hit
            f_fn += bad and not hit
            f_fp += (not bad) and hit
            f_tn += (not bad) and not hit
        out(f"| {name} (`{'`, `'.join(ours.split())}`) | {f_tp}/{f_tp + f_fn} | {f_fp}/{f_fp + f_tn} |\n")
        tp, fn, fp, tn = tp + f_tp, fn + f_fn, fp + f_fp, tn + f_tn
    tpr = tp / max(tp + fn, 1)
    fpr = fp / max(fp + tn, 1)
    out(f"| **total** | {tp}/{tp + fn} ({tpr:.0%}) | {fp}/{fp + tn} ({fpr:.0%}) |\n")
    out(f"\nscore (TPR - FPR): **{tpr - fpr:+.1%}**\n")


if __name__ == "__main__":
    main()

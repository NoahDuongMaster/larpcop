#!/usr/bin/env python3
"""Scores tools on the NIST SARD PHP Vulnerability Test Suite (#103, 2015-10-27,
sha256 3407473fc2cfa38eea9216b8a7f22559b656f20ba5f2eb3b6992010265780f8c):
42,212 single-file PHP cases, each labelled as a whole by its manifest.sarif
(`state`: bad or good). Kept: the cases whose data comes from the HTTP request,
8 of the suite's 16 inputs (`$_GET`, `$_POST`, `$_GET` in an array or through an
object, a `$_POST` string given to `unserialize`); `$_SESSION`, files and
command output are not request data. CWE 862 (authorization) is left out. A
case is found when a finding of its category lands in its file; in a good case
that is a wrong flag. Score = found rate - wrongly flagged rate per category.
larpcop is counted through its PHP taint rules (`php-taint-*`), not the policy
rules that forbid a construction whatever reaches it (`php-no-sql-interpolation`).
Selection, scorer and the rules counted were committed before any tool ran on
these files.
    sard_php.py --select SUITE_DIR OUT_DIR
    sard_php.py SUITE_DIR OUT_DIR LARPCOP_JSON [SEMGREP_JSON ...]
"""
import json
import pathlib
import re
import shutil
import sys

INPUTS = {"GET", "POST", "array-GET", "object-Array", "object-classicGet", "object-directGet",
          "object-indexArray", "unserialize"}
CWE = {"79": "xss", "89": "sql", "91": "xpath", "601": "redirect", "90": "ldap", "98": "include",
       "78": "shell", "95": "code"}
LARPCOP = {"php-taint-xss": "xss", "php-taint-sql": "sql", "php-taint-xpath": "xpath",
           "php-taint-redirect": "redirect", "php-taint-ldap": "ldap", "php-taint-path": "include",
           "php-taint-shell": "shell", "php-taint-code": "code"}
SEMGREP_CWE = {"79": "xss", "80": "xss", "89": "sql", "91": "xpath", "643": "xpath", "601": "redirect",
               "90": "ldap", "98": "include", "22": "include", "73": "include", "78": "shell", "77": "shell",
               "95": "code", "94": "code"}
NAME = re.compile(r"^CWE_(\d+)__(.+?)__")


def selected(suite):
    """(case id, category, state, source file) for every kept case."""
    for manifest in sorted(pathlib.Path(suite).glob("*/manifest.sarif")):
        props = json.loads(manifest.read_text())["runs"][0]["properties"]
        for src in sorted((manifest.parent / "src").glob("*.php")):
            m = NAME.match(src.name)
            if m and m.group(1) in CWE and m.group(2) in INPUTS:
                yield str(props["id"]), CWE[m.group(1)], props["state"], src


def select(suite, out):
    """Copies the kept cases as OUT/<category>/<id>-<name>: no label in the path."""
    n = 0
    for case, cat, _, src in selected(suite):
        dest = pathlib.Path(out) / cat / f"{case}-{src.name}"
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(src, dest)
        n += 1
    print(f"{n} cases")


def findings(path, tool):
    data = json.loads(pathlib.Path(path).read_text())
    if tool == "larpcop":
        for v in data["violations"]:
            if v["rule"] in LARPCOP:
                yield v["file"].rsplit("/", 1)[-1], LARPCOP[v["rule"]]
        return
    for r in data["results"]:
        cwes = r.get("extra", {}).get("metadata", {}).get("cwe", [])
        for c in cwes if isinstance(cwes, list) else [cwes]:
            n = re.match(r"CWE-(\d+)", str(c))
            if n and n.group(1) in SEMGREP_CWE:
                yield r["path"].rsplit("/", 1)[-1], SEMGREP_CWE[n.group(1)]


def main(suite, runs):
    cases = {f"{case}-{src.name}": (cat, state) for case, cat, state, src in selected(suite)}
    cats = sorted({c for c, _ in cases.values()})
    out = sys.stdout.write
    out("| Category (bad/good) | " + " | ".join(f"{n}: found / good flagged / score" for n, _ in runs) + " |\n")
    out("|---|" + "---|" * len(runs) + "\n")
    averages = {n: [] for n, _ in runs}
    hits = {n: {f for f, c in findings(p, n.split(" ")[0]) if f in cases and cases[f][0] == c} for n, p in runs}
    for cat in cats:
        bad = [f for f, (c, s) in cases.items() if c == cat and s == "bad"]
        good = [f for f, (c, s) in cases.items() if c == cat and s == "good"]
        cells = []
        for n, _ in runs:
            found = sum(f in hits[n] for f in bad) / len(bad) if bad else 0
            wrong = sum(f in hits[n] for f in good) / len(good) if good else 0
            averages[n].append(found - wrong)
            cells.append(f"{found:.0%} / {wrong:.0%} / **{found - wrong:+.0%}**")
        out(f"| {cat} ({len(bad)}/{len(good)}) | " + " | ".join(cells) + " |\n")
    out("| **average** | " + " | ".join(f"**{sum(a) / len(a):+.1%}**" for a in averages.values()) + " |\n")


if __name__ == "__main__":
    if sys.argv[1] == "--select":
        select(sys.argv[2], sys.argv[3])
    else:
        names = ["larpcop"] + [f"semgrep ({pathlib.Path(p).stem})" for p in sys.argv[4:]]
        main(sys.argv[1], list(zip(names, sys.argv[3:])))

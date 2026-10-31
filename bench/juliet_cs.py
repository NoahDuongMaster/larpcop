#!/usr/bin/env python3
"""Scores tools on the NIST Juliet C# 1.3 test cases whose data comes from an
HTTP request (QueryString, Params, Cookies). Juliet labels by construction:
code in a `Bad*` method (or a `*_bad.cs` file) is vulnerable, code in a
`Good*` method (or `*_good*.cs`) is not. Per test case, it is found when a
finding of its category lands in bad code and flagged wrongly when one lands
in good code; score = found rate - wrongly flagged rate per category.

    juliet_cs.py TESTCASES_DIR LARPCOP_JSON SEMGREP_JSON [SEMGREP_JSON ...]
"""
import json
import pathlib
import re
import sys

CATEGORIES = {"CWE89_": "sql", "CWE78_": "shell", "CWE23_": "path", "CWE36_": "path", "CWE601_": "redirect",
              "CWE80_": "xss", "CWE81_": "xss", "CWE83_": "xss", "CWE90_": "ldap", "CWE643_": "xpath"}
WEB = re.compile(r"_(QueryString_Web|Params_Get_Web|Get_Cookies_Web|Get_QueryString_Web|Params_Post_Web)_")
LARPCOP = {"cs-taint-sql": "sql", "cs-taint-shell": "shell", "cs-taint-path": "path", "cs-taint-redirect": "redirect",
           "cs-taint-xss": "xss", "cs-taint-ldap": "ldap", "cs-taint-xpath": "xpath"}
CWE = {"89": "sql", "78": "shell", "77": "shell", "22": "path", "23": "path", "36": "path", "73": "path",
       "601": "redirect", "79": "xss", "80": "xss", "90": "ldap", "643": "xpath"}
METHOD = re.compile(r"^\s*(?:(?:public|private|protected|internal|static|override|virtual|async)\s+)+"
                    r"[\w<>\[\],. ]+?\s+(\w+)\s*\(")
CASE = re.compile(r"^(CWE\d+_.+?_\d+)(?:[a-e]|_bad|_good\w*|_base)?\.cs$")


def category(name):
    return next((c for p, c in CATEGORIES.items() if name.startswith(p)), None)


def cases(root):
    """Test case id -> (category, {file: [(line, method)]})."""
    out = {}
    for f in pathlib.Path(root).rglob("*.cs"):
        m, cat = CASE.match(f.name), category(f.name)
        if not (m and cat and WEB.search(f.name)):
            continue
        methods = [(i + 1, mm.group(1)) for i, line in enumerate(f.read_text(errors="replace").splitlines())
                   if (mm := METHOD.match(line))]
        out.setdefault(m.group(1), (cat, {}))[1][f.name] = methods
    return out


def side(file, methods, line):
    if "_bad" in file:
        return "bad"
    if "_good" in file:
        return "good"
    name = next((n for start, n in reversed(methods) if start <= line), "")
    return "bad" if name.lower().startswith("bad") else "good" if name.lower().startswith("good") else None


def tally(all_cases, findings):
    """findings: (file name, line, category)."""
    by_file = {}
    for case, (cat, files) in all_cases.items():
        for f in files:
            by_file[f] = case
    hits = {}
    for f, line, cat in findings:
        case = by_file.get(f)
        if case and all_cases[case][0] == cat:
            s = side(f, all_cases[case][1][f], line)
            if s:
                hits.setdefault(case, set()).add(s)
    return hits


def larpcop(path):
    for v in json.load(open(path))["violations"]:
        if v["rule"] in LARPCOP:
            yield v["file"].rsplit("/", 1)[-1], v["line"], LARPCOP[v["rule"]]


def semgrep(path):
    for r in json.load(open(path))["results"]:
        cwes = r.get("extra", {}).get("metadata", {}).get("cwe", [])
        for c in cwes if isinstance(cwes, list) else [cwes]:
            n = re.match(r"CWE-(\d+)", str(c))
            if n and n.group(1) in CWE:
                yield r["path"].rsplit("/", 1)[-1], r["start"]["line"], CWE[n.group(1)]


def main():
    all_cases = cases(sys.argv[1])
    tools = [("larpcop", tally(all_cases, larpcop(sys.argv[2])))]
    tools += [(f"Semgrep ({p.rsplit('/', 1)[-1].removesuffix('.json')})", tally(all_cases, semgrep(p)))
              for p in sys.argv[3:]]
    cats = sorted({c for c, _ in all_cases.values()})
    out = sys.stdout.write
    out("| Category (cases) | " + " | ".join(f"{n}: found / good flagged / score" for n, _ in tools) + " |\n")
    out("|---|" + "---|" * len(tools) + "\n")
    averages = [[] for _ in tools]
    for cat in cats:
        ids = [c for c, (k, _) in all_cases.items() if k == cat]
        cells = []
        for i, (_, hits) in enumerate(tools):
            found = sum("bad" in hits.get(c, ()) for c in ids) / len(ids)
            wrong = sum("good" in hits.get(c, ()) for c in ids) / len(ids)
            averages[i].append(found - wrong)
            cells.append(f"{found:.0%} / {wrong:.0%} / **{found - wrong:+.0%}**")
        out(f"| {cat} ({len(ids)}) | " + " | ".join(cells) + " |\n")
    out("| **average** | " + " | ".join(f"**{sum(a) / len(a):+.1%}**" for a in averages) + " |\n")


if __name__ == "__main__":
    main()

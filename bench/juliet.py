#!/usr/bin/env python3
"""Scores tools on the NIST Juliet 1.3 test cases (C# or Java) whose data comes
from an HTTP request: C# `QueryString`, `Params`, `Cookies`; Java servlet
`getParameter`, `getCookies`, `getQueryString`. Juliet labels by
construction: code in a `bad*` method (or a `*_bad` file) is vulnerable, code
in a `good*` method (or `*_good*`) is not. Per test case, it is found when a
finding of its category lands in bad code and flagged wrongly when one lands
in good code; score = found rate - wrongly flagged rate per category.

    juliet.py TESTCASES_DIR LARPCOP_JSON SEMGREP_JSON [SEMGREP_JSON ...]
    juliet.py --stored TESTCASES_DIR LARPCOP_JSON SEMGREP_JSON [...]

`--c`: Juliet C 1.3, the `.c` cases of CWE78 (OS command injection) and CWE134
(format string), every source (console, environment, file, sockets); larpcop
counted through `c-taint-shell` and `c-taint-format`. Selection, scorer and
rule names, and the rules themselves, were committed before any tool ran on
these files. C functions say their side in their name (`CWE78_…_01_bad`,
`…_badSink`, `goodG2B`).

`--stored`: the XSS cases (CWE80, CWE81, CWE83) whose data comes from a
database row instead: stored XSS. Java `_Servlet_database_` (selection and the
rule counted, `java-taint-stored-xss`, fixed before any tool ran on them), then
C# `_Web_Database_` (`cs-taint-stored-xss`, likewise fixed before any run).
"""
import json
import pathlib
import re
import sys

CATEGORIES = {"CWE89_": "sql", "CWE78_": "shell", "CWE23_": "path", "CWE36_": "path", "CWE601_": "redirect",
              "CWE80_": "xss", "CWE81_": "xss", "CWE83_": "xss", "CWE90_": "ldap", "CWE643_": "xpath",
              "CWE134_": "format"}
WEB = re.compile(r"_(QueryString_Web|Params_Get_Web|Get_Cookies_Web|Get_QueryString_Web|Params_Post_Web"
                 r"|getParameter_Servlet|getCookies_Servlet|getQueryString_Servlet)_")
LARPCOP = {f"{lang}-taint-{c}": c for lang in ("cs", "java")
           for c in ("sql", "shell", "path", "redirect", "xss", "ldap", "xpath")}
LARPCOP["java-taint-stored-xss"] = "xss"
LARPCOP["cs-taint-stored-xss"] = "xss"
LARPCOP.update({"c-taint-shell": "shell", "c-taint-format": "format"})
C_SELECTED = re.compile(r"^CWE(78|134)_.*\.c$")
# C function definitions start at column 0: `void CWE78_…_01_bad()`,
# `static void goodG2B()`, `char * CWE78_…_61b_badSource(char * data)`.
C_FUNCTION = re.compile(r"^(?:static\s+)?[A-Za-z_][\w ]*?[\s*]+(\w+)\s*\(")
STORED = re.compile(r"^CWE(80|81|83)_.*_(Servlet_database|Web_Database)_")
CWE = {"89": "sql", "78": "shell", "77": "shell", "22": "path", "23": "path", "36": "path", "73": "path",
       "601": "redirect", "79": "xss", "80": "xss", "90": "ldap", "643": "xpath", "134": "format"}
METHOD = re.compile(r"^\s*(?:(?:public|private|protected|internal|static|override|virtual|async|final"
                    r"|synchronized)\s+)+[\w<>\[\],. ]+?\s+(\w+)\s*\(")
CASE = re.compile(r"^(CWE\d+_.+?_\d+)(?:[a-e]|_bad|_good\w*|_base)?\.(cs|java|c)$")


def category(name):
    return next((c for p, c in CATEGORIES.items() if name.startswith(p)), None)


def cases(root, selected=None):
    """Test case id -> (category, {file: [(line, method)]})."""
    out = {}
    for f in pathlib.Path(root).rglob("*"):
        m, cat = CASE.match(f.name), category(f.name)
        if not (m and cat and (selected or WEB).search(f.name)):
            continue
        pattern = C_FUNCTION if f.suffix == ".c" else METHOD
        methods = [(i + 1, mm.group(1)) for i, line in enumerate(f.read_text(errors="replace").splitlines())
                   if (mm := pattern.match(line))]
        out.setdefault(m.group(1), (cat, {}))[1][f.name] = methods
    return out


def side(file, methods, line):
    if "_bad" in file:
        return "bad"
    if "_good" in file:
        return "good"
    name = next((n for start, n in reversed(methods) if start <= line), "").lower()
    # Java/C# `badSink`, `goodG2B`; C `CWE78_…_01_bad`, `CWE78_…_54b_badSink`.
    if name.startswith("bad") or "_bad" in name:
        return "bad"
    return "good" if name.startswith("good") or "_good" in name else None


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
    args = sys.argv[1:]
    mode = args[0] if args[0] in ("--stored", "--c") else None
    args = args[1:] if mode else args
    all_cases = cases(args[0], {"--stored": STORED, "--c": C_SELECTED}.get(mode))
    tools = [("larpcop", tally(all_cases, larpcop(args[1])))]
    tools += [(f"Semgrep ({p.rsplit('/', 1)[-1].removesuffix('.json')})", tally(all_cases, semgrep(p)))
              for p in args[2:]]
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

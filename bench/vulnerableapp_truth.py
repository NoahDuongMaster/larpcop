#!/usr/bin/env python3
"""Writes bench/vulnerableapp-truth.json: every handler of SasanLabs/VulnerableApp
(9f45cd5) in a category a SAST tool can check, labelled by the project itself:
`@VulnerableAppRequestMapping(variant = Variant.SECURE)` is safe, the default
(UNSECURE) is vulnerable; the category is the package. Written before any tool
ran on it."""
import json
import pathlib
import re
import sys

CATEGORIES = {"sqlInjection": "sql", "commandInjection": "shell", "pathTraversal": "path", "ssrf": "ssrf",
              "rfi": "ssrf", "openRedirect": "redirect", "xss": "xss", "xxe": "xxe",
              "deserialization": "deserialization", "ldapInjection": "ldap"}
METHOD = re.compile(r"^\s+public\s+(?:static\s+)?[\w<>\[\], .?]+?\s+(\w+)\s*\(")


def handlers(path):
    lines = path.read_text(errors="replace").splitlines()
    out = []
    i = 0
    while i < len(lines):
        if "@VulnerableAppRequestMapping" not in lines[i]:
            i += 1
            continue
        at, secure = i + 1, False
        j = i
        while j < len(lines) and not METHOD.match(lines[j]):
            secure = secure or "Variant.SECURE" in lines[j]
            j += 1
        if j == len(lines):
            break
        depth, seen, end = 0, False, None
        for k in range(j, len(lines)):
            depth += lines[k].count("{") - lines[k].count("}")
            seen = seen or "{" in lines[k]
            if seen and depth <= 0:
                end = k + 1
                break
        method = METHOD.match(lines[j])
        out.append((at, end, method.group(1) if method else "", secure))
        i = j + 1
    return out


def main(root, out):
    base = pathlib.Path(root) / "src/main/java/org/sasanlabs/service/vulnerability"
    rows = []
    for f in sorted(base.rglob("*.java")):
        category = CATEGORIES.get(f.relative_to(base).parts[0])
        if not category:
            continue
        for at, end, name, secure in handlers(f):
            rows.append({"file": str(f.relative_to(root)), "start": at, "end": end, "method": name,
                         "route": name, "category": category, "vulnerable": not secure})
    pathlib.Path(out).write_text(json.dumps(rows, indent=1) + "\n")
    sys.stdout.write(f"{len(rows)} handlers; {sum(r['vulnerable'] for r in rows)} vulnerable\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])

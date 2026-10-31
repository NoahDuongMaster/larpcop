#!/usr/bin/env python3
"""Lists the endpoints of java-sec-code: (file, mapping line, method, path)."""
import pathlib
import re
import sys

MAP = re.compile(r'@(Get|Post|Request|Put)Mapping\((?:value\s*=\s*)?"([^"]*)"')
METHOD = re.compile(r"^\s+public\s+(?:static\s+)?[\w<>\[\], .]+?\s+(\w+)\s*\(")


def endpoints(path):
    lines = path.read_text(errors="replace").splitlines()
    out, pending = [], None
    for i, line in enumerate(lines, 1):
        if m := MAP.search(line):
            pending = (i, m.group(2))
        elif pending and (mm := METHOD.match(line)) and i - pending[0] < 8:
            start = i
            depth, end, seen = 0, None, False
            for j in range(i - 1, len(lines)):
                depth += lines[j].count("{") - lines[j].count("}")
                seen = seen or "{" in lines[j]
                if seen and depth <= 0:
                    end = j + 1
                    break
            out.append((pending[0], start, end, mm.group(1), pending[1]))
            pending = None
    return out


if __name__ == "__main__":
    for f in sys.argv[1:]:
        for at, start, end, name, route in endpoints(pathlib.Path(f)):
            sys.stdout.write(f"{pathlib.Path(f).name}:{at}-{end} {name} {route}" + "\n")

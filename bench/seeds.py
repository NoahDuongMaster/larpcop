"""Scores reports on vulnerable-node's SAST seeds with the project's own scorer.

vulnerable-node (cr0hn, 2026 rewrite) ships sast/seeds/*.js, one vulnerability
per file plus clean controls, and sast/tests/score.js, which counts a seed as
found when a report names its file. Each tool is scored twice: with every
security finding, and without the findings any request handler or Express file
gets regardless of the bug (larpcop's validate-request-input, Semgrep's CSRF
middleware check), which credit a file without naming its vulnerability.

    python3 bench/seeds.py <vulnerable-node> <larpcop.json> <semgrep.json>
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from score import SECURITY, out  # noqa: E402

GENERIC = {"validate-request-input", "express-check-csurf-middleware-usage"}


def score(repo, files):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump({"results": [{"file": x} for x in files]}, f)
    out = subprocess.run(["node", "sast/tests/score.js", f.name], cwd=repo,
                         capture_output=True, text=True, check=True).stdout
    return " · ".join(line.strip() for line in out.splitlines() if line.strip())


def main():
    repo, larpcop, semgrep = sys.argv[1:4]
    lc = [(v["file"], v["rule"]) for v in json.load(open(larpcop))["violations"]
          if v["rule"] in SECURITY]
    sg = [(r["path"], r["check_id"].rsplit(".", 1)[-1]) for r in json.load(open(semgrep))["results"]]
    out("| Tool | All security findings | Without per-file generic checks |")
    out("|---|---|---|")
    for name, found in (("larpcop", lc), ("Semgrep OSS", sg)):
        everything = score(repo, [f for f, _ in found])
        specific = score(repo, [f for f, r in found if r not in GENERIC])
        out(f"| {name} | {everything} | {specific} |")


if __name__ == "__main__":
    main()

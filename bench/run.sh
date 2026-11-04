#!/bin/sh
# Reproducible benchmark: larpcop (standards/recommended) on intentionally
# vulnerable applications and public test suites (OWASP Juice Shop, NodeGoat,
# DVNA, DVPWA, DVWS-Node, GoVWA, DSVW, the OWASP Benchmark, NIST Juliet and
# SARD, and others), scored against answer keys. Writes results/ next to this
# script. Needs: git, python3, node, curl, unzip and a larpcop release build.
#
#   bench/run.sh [path/to/larpcop]
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
LARPCOP=${1:-$REPO/target/release/larpcop}
WORK=${BENCH_WORK:-${TMPDIR:-/tmp}/larpcop-bench}
RUNS=3
OUT=$HERE/results
mkdir -p "$WORK" "$OUT"

clone() { # name url ref
  [ -d "$WORK/$1" ] && return
  git clone -q "$2" "$WORK/$1"
  git -C "$WORK/$1" checkout -q "$3"
}
clone juice-shop https://github.com/juice-shop/juice-shop.git v20.3.0
clone NodeGoat https://github.com/OWASP/NodeGoat.git c5cb68a
clone dvna https://github.com/appsecco/dvna.git 9ba473a
clone dvpwa https://github.com/anxolerd/dvpwa.git a1d8f89
clone dvws-node https://github.com/snoopysecurity/dvws-node.git e83689c
clone govwa https://github.com/0c34/govwa.git 4058f79
clone BenchmarkJava https://github.com/OWASP-Benchmark/BenchmarkJava.git f40c618
clone BenchmarkPython https://github.com/OWASP-Benchmark/BenchmarkPython.git f129148
clone DVWA https://github.com/digininja/DVWA.git a1978a2
clone railsgoat https://github.com/OWASP/railsgoat.git f5951f1
clone xvwa https://github.com/s4n7h0/xvwa.git fb30fa5
clone WackoPicko https://github.com/adamdoupe/WackoPicko.git cabc1b3
clone java-sec-code https://github.com/JoyChou93/java-sec-code.git 4711f4e
clone VulnerableApp https://github.com/SasanLabs/VulnerableApp.git 9f45cd5
# NIST Juliet C# 1.3: only the test cases whose data comes from an HTTP request.
if [ ! -d "$WORK/juliet-web" ]; then
  curl -sfL -o "$WORK/juliet-cs.zip" \
    https://samate.nist.gov/SARD/downloads/test-suites/2020-08-01-juliet-test-suite-for-csharp-v1-3.zip
  mkdir -p "$WORK/juliet-cs" && unzip -q -o "$WORK/juliet-cs.zip" -d "$WORK/juliet-cs"
  (cd "$WORK/juliet-cs/src/testcases" && find CWE89_* CWE78_* CWE23_* CWE36_* CWE601_* CWE80_* CWE81_* CWE83_* \
    CWE90_* CWE643_* -name '*.cs' | grep -E '_(QueryString_Web|Params_Get_Web|Get_Cookies_Web)_' |
    while read -r f; do mkdir -p "$WORK/juliet-web/$(dirname "$f")" && cp "$f" "$WORK/juliet-web/$f"; done)
  git -C "$WORK/juliet-web" init -q
fi
clone vulnerable-node https://github.com/cr0hn/vulnerable-node.git d68f2a3
clone dsvw https://github.com/stamparm/DSVW.git 9ca3c9a

# Median wall time of RUNS runs of "$@", in seconds (bench/scripts/time_it.py: the
# clock wraps the tool only, and a crash fails the benchmark). larpcop exits 1
# when it finds something.
time_it() {
  python3 "$HERE/scripts/time_it.py" "$RUNS" 0,1 -- "$@"
}

echo "larpcop $("$LARPCOP" --version | cut -d' ' -f2) | $(uname -sm) $(sysctl -n hw.ncpu 2>/dev/null || nproc) cpus" > "$OUT/timing.txt"

for target in juice-shop NodeGoat dvna dvpwa dvws-node govwa railsgoat xvwa WackoPicko dsvw; do
  cd "$WORK/$target"
  # Scoring uses the full recommended set, including dependency-vulnerability
  # (it queries OSV.dev, so this step needs network access).
  printf "extends: ['%s/standards/recommended']\n" "$REPO" > .larpcop.yaml
  "$LARPCOP" check --format json > "$OUT/$target-larpcop.json" || true
  # Timing leaves that rule out, so the clock does not include network round trips.
  printf "extends: ['%s/standards/recommended']\ndisable: [dependency-vulnerability]\n" "$REPO" > .larpcop.yaml
  echo "$target larpcop_seconds $(time_it "$LARPCOP" check --format json)" >> "$OUT/timing.txt"
done

python3 "$HERE/scripts/score.py" "$WORK/juice-shop" "$OUT/juice-shop-larpcop.json" > "$OUT/juice-shop.md"
python3 "$HERE/scripts/score.py" "$WORK/NodeGoat" "$OUT/NodeGoat-larpcop.json" --truth "$HERE/truth/nodegoat-truth.json" > "$OUT/NodeGoat.md"
python3 "$HERE/scripts/score.py" "$WORK/dvna" "$OUT/dvna-larpcop.json" --truth "$HERE/truth/dvna-truth.json" > "$OUT/dvna.md"
python3 "$HERE/scripts/score.py" "$WORK/dvpwa" "$OUT/dvpwa-larpcop.json" --truth "$HERE/truth/dvpwa-truth.json" > "$OUT/dvpwa.md"
python3 "$HERE/scripts/score.py" "$WORK/dvws-node" "$OUT/dvws-node-larpcop.json" --truth "$HERE/truth/dvws-truth.json" > "$OUT/dvws-node.md"
python3 "$HERE/scripts/score.py" "$WORK/govwa" "$OUT/govwa-larpcop.json" --truth "$HERE/truth/govwa-truth.json" > "$OUT/govwa.md"
python3 "$HERE/scripts/score.py" "$WORK/railsgoat" "$OUT/railsgoat-larpcop.json" --truth "$HERE/truth/railsgoat-truth.json" > "$OUT/railsgoat.md"
python3 "$HERE/scripts/score.py" "$WORK/xvwa" "$OUT/xvwa-larpcop.json" --truth "$HERE/truth/xvwa-truth.json" > "$OUT/xvwa.md"
python3 "$HERE/scripts/score.py" "$WORK/WackoPicko" "$OUT/WackoPicko-larpcop.json" --truth "$HERE/truth/wackopicko-truth.json" > "$OUT/WackoPicko.md"
python3 "$HERE/scripts/score.py" "$WORK/dsvw" "$OUT/dsvw-larpcop.json" --truth "$HERE/truth/dsvw-truth.json" > "$OUT/dsvw.md"

# OWASP Benchmark (Java): 2,740 test cases, scored like the project's scorecard.
cd "$WORK/BenchmarkJava"
printf "extends: ['%s/standards/recommended']\ndisable: [dependency-vulnerability]\n" "$REPO" > .larpcop.yaml
"$LARPCOP" check --format json > "$OUT/owasp-benchmark-larpcop.json" || true
echo "BenchmarkJava larpcop_seconds $(time_it "$LARPCOP" check --format json)" >> "$OUT/timing.txt"
python3 "$HERE/scripts/owasp_benchmark.py" "$WORK/BenchmarkJava" "$OUT/owasp-benchmark-larpcop.json" > "$OUT/owasp-benchmark.md"

# OWASP Benchmark (Python): 1,230 test cases, same scorer.
cd "$WORK/BenchmarkPython"
printf "extends: ['%s/standards/recommended']\ndisable: [dependency-vulnerability]\n" "$REPO" > .larpcop.yaml
"$LARPCOP" check --format json testcode > "$OUT/owasp-python-larpcop.json" || true
echo "BenchmarkPython larpcop_seconds $(time_it "$LARPCOP" check --format json testcode)" >> "$OUT/timing.txt"
rm .larpcop.yaml
python3 "$HERE/scripts/owasp_benchmark.py" "$WORK/BenchmarkPython" "$OUT/owasp-python-larpcop.json" > "$OUT/owasp-benchmark-python.md"

# DVWA (PHP): low/medium/high are vulnerable by design, impossible is the fix.
cd "$WORK/DVWA"
printf "extends: ['%s/standards/recommended']\ndisable: [dependency-vulnerability]\n" "$REPO" > .larpcop.yaml
"$LARPCOP" check --format json > "$OUT/dvwa-larpcop.json" || true
rm .larpcop.yaml
python3 "$HERE/scripts/dvwa.py" "$OUT/dvwa-larpcop.json" > "$OUT/dvwa.md"

# Juliet C#: Bad*/Good* methods are the answer key.
cd "$WORK/juliet-web"
printf "extends: ['%s/standards/recommended']\ndisable: [dependency-vulnerability]\n" "$REPO" > .larpcop.yaml
"$LARPCOP" check --format json > "$OUT/juliet-cs-larpcop.json" || true
rm .larpcop.yaml
python3 "$HERE/scripts/juliet.py" . "$OUT/juliet-cs-larpcop.json" > "$OUT/juliet-cs.md"

# Juliet Java 1.3: servlet test cases (getParameter, getCookies, getQueryString), same scorer.
if [ ! -d "$WORK/juliet-java-web" ]; then
  curl -sfL -o "$WORK/juliet-java.zip" \
    https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-java-v1-3.zip
  mkdir -p "$WORK/juliet-java" && unzip -q -o "$WORK/juliet-java.zip" -d "$WORK/juliet-java"
  (cd "$WORK/juliet-java/Java/src/testcases" && find . -name "*.java" \
    | grep -E "/CWE(89|78|23|36|601|80|81|83|90|643)_[^/]*$" | grep -E "_(getParameter|getCookies|getQueryString)_Servlet_" |
    while read -r f; do mkdir -p "$WORK/juliet-java-web/$(dirname "$f")" && cp "$f" "$WORK/juliet-java-web/$f"; done)
  mkdir -p "$WORK/juliet-java-web/testcasesupport"
  cp "$WORK/juliet-java/Java/src/testcasesupport/"*.java "$WORK/juliet-java-web/testcasesupport/"
  git -C "$WORK/juliet-java-web" init -q
fi
cd "$WORK/juliet-java-web"
printf "extends: ['%s/standards/recommended']\ndisable: [dependency-vulnerability]\n" "$REPO" > .larpcop.yaml
"$LARPCOP" check --format json > "$OUT/juliet-java-larpcop.json" || true
rm .larpcop.yaml
python3 "$HERE/scripts/juliet.py" . "$OUT/juliet-java-larpcop.json" > "$OUT/juliet-java.md"

# Juliet Java stored XSS: the CWE80/81/83 cases whose data comes from a database row.
if [ ! -d "$WORK/juliet-java-stored" ]; then
  (cd "$WORK/juliet-java/Java/src/testcases" && find . -name "*.java" \
    | grep -E "/CWE(80|81|83)_[^/]*_Servlet_database_[^/]*$" |
    while read -r f; do mkdir -p "$WORK/juliet-java-stored/$(dirname "$f")" && cp "$f" "$WORK/juliet-java-stored/$f"; done)
  mkdir -p "$WORK/juliet-java-stored/testcasesupport"
  cp "$WORK/juliet-java/Java/src/testcasesupport/"*.java "$WORK/juliet-java-stored/testcasesupport/"
  git -C "$WORK/juliet-java-stored" init -q
fi
cd "$WORK/juliet-java-stored"
printf "extends: ['%s/standards/recommended']\ndisable: [dependency-vulnerability]\n" "$REPO" > .larpcop.yaml
"$LARPCOP" check --format json > "$OUT/juliet-stored-larpcop.json" || true
rm .larpcop.yaml
python3 "$HERE/scripts/juliet.py" --stored . "$OUT/juliet-stored-larpcop.json" > "$OUT/juliet-java-stored.md"

# Juliet C# stored XSS: the CWE80/81/83 cases whose data comes from a database row.
if [ ! -d "$WORK/juliet-cs-stored" ]; then
  (cd "$WORK/juliet-cs/src/testcases" && find CWE80_* CWE81_* CWE83_* -name "*.cs" | grep -E "_Web_Database_" |
    while read -r f; do mkdir -p "$WORK/juliet-cs-stored/$(dirname "$f")" && cp "$f" "$WORK/juliet-cs-stored/$f"; done)
  git -C "$WORK/juliet-cs-stored" init -q
fi
cd "$WORK/juliet-cs-stored"
printf "extends: ['%s/standards/recommended']\ndisable: [dependency-vulnerability]\n" "$REPO" > .larpcop.yaml
"$LARPCOP" check --format json > "$OUT/juliet-cs-stored-larpcop.json" || true
rm .larpcop.yaml
python3 "$HERE/scripts/juliet.py" --stored . "$OUT/juliet-cs-stored-larpcop.json" > "$OUT/juliet-cs-stored.md"

# Juliet C 1.3: the .c cases of CWE78 (OS command injection) and CWE134 (format string).
if [ ! -d "$WORK/juliet-c-sel" ]; then
  curl -sfL -o "$WORK/juliet-c.zip" \
    https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip
  mkdir -p "$WORK/juliet-c" && unzip -q -o "$WORK/juliet-c.zip" -d "$WORK/juliet-c"
  (cd "$WORK/juliet-c/C/testcases" && find CWE78_* CWE134_* -name "*.c" |
    while read -r f; do mkdir -p "$WORK/juliet-c-sel/$(dirname "$f")" && cp "$f" "$WORK/juliet-c-sel/$f"; done)
  cp -r "$WORK/juliet-c/C/testcasesupport" "$WORK/juliet-c-sel/"
  git -C "$WORK/juliet-c-sel" init -q
fi
cd "$WORK/juliet-c-sel"
printf "extends: ['%s/standards/recommended']\ndisable: [dependency-vulnerability]\n" "$REPO" > .larpcop.yaml
"$LARPCOP" check --format json > "$OUT/juliet-c-larpcop.json" || true
rm .larpcop.yaml
python3 "$HERE/scripts/juliet.py" --c . "$OUT/juliet-c-larpcop.json" > "$OUT/juliet-c.md"

# NIST SARD PHP Vulnerability Test Suite (#103): the cases whose data comes from the request.
if [ ! -d "$WORK/sard-php-sel" ]; then
  curl -sfL -o "$WORK/sard-php.zip" \
    https://samate.nist.gov/SARD/downloads/test-suites/2015-10-27-php-vulnerability-test-suite.zip
  mkdir -p "$WORK/sard-php" && unzip -q -o "$WORK/sard-php.zip" -d "$WORK/sard-php"
  python3 "$HERE/scripts/sard_php.py" --select "$WORK/sard-php" "$WORK/sard-php-sel"
  git -C "$WORK/sard-php-sel" init -q
fi
cd "$WORK/sard-php-sel"
printf "extends: ['%s/standards/recommended']\ndisable: [dependency-vulnerability]\n" "$REPO" > .larpcop.yaml
"$LARPCOP" check --format json > "$OUT/sard-php-larpcop.json" || true
rm .larpcop.yaml
python3 "$HERE/scripts/sard_php.py" "$WORK/sard-php" . "$OUT/sard-php-larpcop.json" > "$OUT/sard-php.md"

# java-sec-code (Java/Spring): endpoints labelled by the project's routes and comments.
cd "$WORK/java-sec-code"
printf "extends: ['%s/standards/recommended']\ndisable: [dependency-vulnerability]\n" "$REPO" > .larpcop.yaml
"$LARPCOP" check --format json > "$OUT/java-sec-code-larpcop.json" || true
rm .larpcop.yaml
python3 "$HERE/scripts/java_sec_code.py" "$HERE/truth/java-sec-code-truth.json" "$OUT/java-sec-code-larpcop.json" > "$OUT/java-sec-code.md"

# VulnerableApp (Java/Spring): handlers labelled by the project's Variant.SECURE.
cd "$WORK/VulnerableApp"
printf "extends: ['%s/standards/recommended']\ndisable: [dependency-vulnerability]\n" "$REPO" > .larpcop.yaml
"$LARPCOP" check --format json > "$OUT/vulnerableapp-larpcop.json" || true
rm .larpcop.yaml
python3 "$HERE/scripts/java_sec_code.py" "$HERE/truth/vulnerableapp-truth.json" "$OUT/vulnerableapp-larpcop.json" > "$OUT/vulnerableapp.md"

# vulnerable-node: only sast/seeds/, scored by the project's own sast/tests/score.js.
cd "$WORK/vulnerable-node"
printf "extends: ['%s/standards/recommended']\ndisable: [dependency-vulnerability]\n" "$REPO" > .larpcop.yaml
"$LARPCOP" check --format json sast/seeds > "$OUT/seeds-larpcop.json" || true
python3 "$HERE/scripts/seeds.py" "$WORK/vulnerable-node" "$OUT/seeds-larpcop.json" > "$OUT/seeds.md"

cat "$OUT/timing.txt" "$OUT/juice-shop.md" "$OUT/NodeGoat.md" "$OUT/dvna.md" "$OUT/dvpwa.md" "$OUT/dvws-node.md" "$OUT/govwa.md" "$OUT/railsgoat.md" "$OUT/xvwa.md" "$OUT/WackoPicko.md" "$OUT/dsvw.md" "$OUT/owasp-benchmark.md" "$OUT/owasp-benchmark-python.md" "$OUT/dvwa.md" "$OUT/juliet-cs.md" "$OUT/juliet-java.md" "$OUT/juliet-java-stored.md" "$OUT/juliet-cs-stored.md" "$OUT/juliet-c.md" "$OUT/sard-php.md" "$OUT/java-sec-code.md" "$OUT/vulnerableapp.md" "$OUT/seeds.md"

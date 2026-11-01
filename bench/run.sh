#!/bin/sh
# Reproducible benchmark: larpcop (standards/recommended) vs Semgrep OSS
# (p/default) vs gitleaks, on OWASP Juice Shop, OWASP NodeGoat, DVNA, DVPWA
# (Python), DVWS-Node, GoVWA (Go) and vulnerable-node's SAST seeds. Writes results/ next to this script. Needs:
# git, python3, node, semgrep, gitleaks and a larpcop release build.
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
# Semgrep's registry pack, fetched once so timings exclude the download.
[ -f "$WORK/p-default.yml" ] || curl -sfL https://semgrep.dev/c/p/default -o "$WORK/p-default.yml"
[ -f "$WORK/p-java.yml" ] || curl -sfL https://semgrep.dev/c/p/java -o "$WORK/p-java.yml"
[ -f "$WORK/p-python.yml" ] || curl -sfL https://semgrep.dev/c/p/python -o "$WORK/p-python.yml"

# Median wall time of RUNS runs of "$@", in seconds.
time_it() {
  for _ in $(seq $RUNS); do
    start=$(python3 -c 'import time; print(time.time())')
    "$@" > /dev/null 2>&1 || true
    python3 -c "import time; print(round(time.time() - $start, 2))"
  done | sort -n | sed -n "$(( (RUNS + 1) / 2 ))p"
}

echo "larpcop $("$LARPCOP" --version | cut -d' ' -f2) | semgrep $(semgrep --version) | gitleaks $(gitleaks version) | $(uname -sm) $(sysctl -n hw.ncpu 2>/dev/null || nproc) cpus" > "$OUT/timing.txt"

for target in juice-shop NodeGoat dvna dvpwa dvws-node govwa railsgoat; do
  cd "$WORK/$target"
  printf "extends: ['%s/standards/recommended']\n" "$REPO" > .larpcop.yaml
  "$LARPCOP" check --format json > "$OUT/$target-larpcop.json" || true
  semgrep scan --config "$WORK/p-default.yml" --metrics off --json -o "$OUT/$target-semgrep.json" --quiet . || true
  gitleaks dir . --report-format json --report-path "$OUT/$target-gitleaks.json" --no-banner --log-level error || true
  {
    echo "$target larpcop_seconds $(time_it "$LARPCOP" check --format json)"
    echo "$target semgrep_seconds $(time_it semgrep scan --config "$WORK/p-default.yml" --metrics off --json -o /dev/null --quiet .)"
    echo "$target gitleaks_seconds $(time_it gitleaks dir . --report-format json --report-path /dev/null --no-banner --log-level error)"
  } >> "$OUT/timing.txt"
done

python3 "$HERE/score.py" "$WORK/juice-shop" "$OUT/juice-shop-larpcop.json" "$OUT/juice-shop-semgrep.json" \
  "$OUT/juice-shop-gitleaks.json" > "$OUT/juice-shop.md"
python3 "$HERE/score.py" "$WORK/NodeGoat" "$OUT/NodeGoat-larpcop.json" "$OUT/NodeGoat-semgrep.json" \
  "$OUT/NodeGoat-gitleaks.json" --truth "$HERE/nodegoat-truth.json" > "$OUT/NodeGoat.md"
python3 "$HERE/score.py" "$WORK/dvna" "$OUT/dvna-larpcop.json" "$OUT/dvna-semgrep.json" \
  "$OUT/dvna-gitleaks.json" --truth "$HERE/dvna-truth.json" > "$OUT/dvna.md"
python3 "$HERE/score.py" "$WORK/dvpwa" "$OUT/dvpwa-larpcop.json" "$OUT/dvpwa-semgrep.json" \
  "$OUT/dvpwa-gitleaks.json" --truth "$HERE/dvpwa-truth.json" > "$OUT/dvpwa.md"
python3 "$HERE/score.py" "$WORK/dvws-node" "$OUT/dvws-node-larpcop.json" "$OUT/dvws-node-semgrep.json" \
  "$OUT/dvws-node-gitleaks.json" --truth "$HERE/dvws-truth.json" > "$OUT/dvws-node.md"
python3 "$HERE/score.py" "$WORK/govwa" "$OUT/govwa-larpcop.json" "$OUT/govwa-semgrep.json" \
  "$OUT/govwa-gitleaks.json" --truth "$HERE/govwa-truth.json" > "$OUT/govwa.md"
python3 "$HERE/score.py" "$WORK/railsgoat" "$OUT/railsgoat-larpcop.json" "$OUT/railsgoat-semgrep.json" \
  "$OUT/railsgoat-gitleaks.json" --truth "$HERE/railsgoat-truth.json" > "$OUT/railsgoat.md"

# OWASP Benchmark (Java): 2,740 test cases, scored like the project's scorecard.
cd "$WORK/BenchmarkJava"
printf "extends: ['%s/standards/recommended']\ndisable: [dependency-vulnerability]\n" "$REPO" > .larpcop.yaml
"$LARPCOP" check --format json > "$OUT/owasp-benchmark-larpcop.json" || true
semgrep scan --config "$WORK/p-default.yml" --metrics off --json -o "$OUT/owasp-benchmark-semgrep-default.json" --quiet . || true
semgrep scan --config "$WORK/p-java.yml" --metrics off --json -o "$OUT/owasp-benchmark-semgrep-java.json" --quiet . || true
{
  echo "BenchmarkJava larpcop_seconds $(time_it "$LARPCOP" check --format json)"
  echo "BenchmarkJava semgrep_default_seconds $(time_it semgrep scan --config "$WORK/p-default.yml" --metrics off --json -o /dev/null --quiet .)"
} >> "$OUT/timing.txt"
python3 "$HERE/owasp_benchmark.py" "$WORK/BenchmarkJava" "$OUT/owasp-benchmark-larpcop.json" \
  "$OUT/owasp-benchmark-semgrep-default.json" "$OUT/owasp-benchmark-semgrep-java.json" > "$OUT/owasp-benchmark.md"

# OWASP Benchmark (Python): 1,230 test cases, same scorer.
cd "$WORK/BenchmarkPython"
printf "extends: ['%s/standards/recommended']\ndisable: [dependency-vulnerability]\n" "$REPO" > .larpcop.yaml
"$LARPCOP" check --format json testcode > "$OUT/owasp-python-larpcop.json" || true
semgrep scan --config "$WORK/p-default.yml" --metrics off --json -o "$OUT/owasp-python-semgrep-default.json" --quiet testcode || true
semgrep scan --config "$WORK/p-python.yml" --metrics off --json -o "$OUT/owasp-python-semgrep-python.json" --quiet testcode || true
{
  echo "BenchmarkPython larpcop_seconds $(time_it "$LARPCOP" check --format json testcode)"
  echo "BenchmarkPython semgrep_python_seconds $(time_it semgrep scan --config "$WORK/p-python.yml" --metrics off --json -o /dev/null --quiet testcode)"
} >> "$OUT/timing.txt"
rm .larpcop.yaml
python3 "$HERE/owasp_benchmark.py" "$WORK/BenchmarkPython" "$OUT/owasp-python-larpcop.json" \
  "$OUT/owasp-python-semgrep-default.json" "$OUT/owasp-python-semgrep-python.json" > "$OUT/owasp-benchmark-python.md"

# DVWA (PHP): low/medium/high are vulnerable by design, impossible is the fix.
cd "$WORK/DVWA"
printf "extends: ['%s/standards/recommended']\ndisable: [dependency-vulnerability]\n" "$REPO" > .larpcop.yaml
"$LARPCOP" check --format json > "$OUT/dvwa-larpcop.json" || true
rm .larpcop.yaml
semgrep scan --config "$WORK/p-default.yml" --metrics off --json -o "$OUT/dvwa-semgrep.json" --quiet . || true
python3 "$HERE/dvwa.py" "$OUT/dvwa-larpcop.json" "$OUT/dvwa-semgrep.json" > "$OUT/dvwa.md"

# Juliet C#: Bad*/Good* methods are the answer key.
cd "$WORK/juliet-web"
printf "extends: ['%s/standards/recommended']\ndisable: [dependency-vulnerability]\n" "$REPO" > .larpcop.yaml
"$LARPCOP" check --format json > "$OUT/juliet-cs-larpcop.json" || true
rm .larpcop.yaml
semgrep scan --config "$WORK/p-default.yml" --metrics off --json -o "$OUT/juliet-cs-semgrep-default.json" --quiet . || true
python3 "$HERE/juliet.py" . "$OUT/juliet-cs-larpcop.json" "$OUT/juliet-cs-semgrep-default.json" > "$OUT/juliet-cs.md"

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
semgrep scan --config "$WORK/p-default.yml" --metrics off --json -o "$OUT/juliet-java-semgrep-default.json" --quiet . || true
semgrep scan --config "$WORK/p-java.yml" --metrics off --json -o "$OUT/juliet-java-semgrep-java.json" --quiet . || true
python3 "$HERE/juliet.py" . "$OUT/juliet-java-larpcop.json" "$OUT/juliet-java-semgrep-default.json" \
  "$OUT/juliet-java-semgrep-java.json" > "$OUT/juliet-java.md"

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
semgrep scan --config "$WORK/p-default.yml" --metrics off --json -o "$OUT/juliet-stored-semgrep-default.json" --quiet . || true
semgrep scan --config "$WORK/p-java.yml" --metrics off --json -o "$OUT/juliet-stored-semgrep-java.json" --quiet . || true
python3 "$HERE/juliet.py" --stored . "$OUT/juliet-stored-larpcop.json" "$OUT/juliet-stored-semgrep-default.json" \
  "$OUT/juliet-stored-semgrep-java.json" > "$OUT/juliet-java-stored.md"

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
semgrep scan --config "$WORK/p-default.yml" --metrics off --json -o "$OUT/juliet-cs-stored-semgrep-default.json" --quiet . || true
python3 "$HERE/juliet.py" --stored . "$OUT/juliet-cs-stored-larpcop.json" "$OUT/juliet-cs-stored-semgrep-default.json" \
  > "$OUT/juliet-cs-stored.md"

# java-sec-code (Java/Spring): endpoints labelled by the project's routes and comments.
cd "$WORK/java-sec-code"
printf "extends: ['%s/standards/recommended']\ndisable: [dependency-vulnerability]\n" "$REPO" > .larpcop.yaml
"$LARPCOP" check --format json > "$OUT/java-sec-code-larpcop.json" || true
rm .larpcop.yaml
semgrep scan --config "$WORK/p-default.yml" --metrics off --json -o "$OUT/java-sec-code-semgrep.json" --quiet . || true
python3 "$HERE/java_sec_code.py" "$HERE/java-sec-code-truth.json" . larpcop="$OUT/java-sec-code-larpcop.json" \
  semgrep="$OUT/java-sec-code-semgrep.json" > "$OUT/java-sec-code.md"

# VulnerableApp (Java/Spring): handlers labelled by the project's Variant.SECURE.
cd "$WORK/VulnerableApp"
printf "extends: ['%s/standards/recommended']\ndisable: [dependency-vulnerability]\n" "$REPO" > .larpcop.yaml
"$LARPCOP" check --format json > "$OUT/vulnerableapp-larpcop.json" || true
rm .larpcop.yaml
semgrep scan --config "$WORK/p-default.yml" --metrics off --json -o "$OUT/vulnerableapp-semgrep.json" --quiet . || true
python3 "$HERE/java_sec_code.py" "$HERE/vulnerableapp-truth.json" . larpcop="$OUT/vulnerableapp-larpcop.json" \
  semgrep="$OUT/vulnerableapp-semgrep.json" > "$OUT/vulnerableapp.md"

# Kotlin: the labeled Kotlin test files of the Semgrep rules repository (pinned),
# larpcop only (they are Semgrep's own rule tests).
python3 "$HERE/semgrep_kotlin.py" --fetch "$WORK/semgrep-kotlin"
cd "$WORK/semgrep-kotlin"
[ -d .git ] || git init -q
printf "extends: ['%s/standards/recommended']\ndisable: [dependency-vulnerability]\n" "$REPO" > .larpcop.yaml
"$LARPCOP" check --format json > "$OUT/semgrep-kotlin-larpcop.json" || true
rm .larpcop.yaml
python3 "$HERE/semgrep_kotlin.py" . "$OUT/semgrep-kotlin-larpcop.json" > "$OUT/semgrep-kotlin.md"

# vulnerable-node: only sast/seeds/, scored by the project's own sast/tests/score.js.
cd "$WORK/vulnerable-node"
printf "extends: ['%s/standards/recommended']\n" "$REPO" > .larpcop.yaml
"$LARPCOP" check --format json sast/seeds > "$OUT/seeds-larpcop.json" || true
semgrep scan --config "$WORK/p-default.yml" --metrics off --json -o "$OUT/seeds-semgrep.json" --quiet sast/seeds || true
python3 "$HERE/seeds.py" "$WORK/vulnerable-node" "$OUT/seeds-larpcop.json" "$OUT/seeds-semgrep.json" > "$OUT/seeds.md"

cat "$OUT/timing.txt" "$OUT/juice-shop.md" "$OUT/NodeGoat.md" "$OUT/dvna.md" "$OUT/dvpwa.md" "$OUT/dvws-node.md" "$OUT/govwa.md" "$OUT/railsgoat.md" "$OUT/owasp-benchmark.md" "$OUT/owasp-benchmark-python.md" "$OUT/dvwa.md" "$OUT/juliet-cs.md" "$OUT/juliet-java.md" "$OUT/juliet-java-stored.md" "$OUT/juliet-cs-stored.md" "$OUT/semgrep-kotlin.md" "$OUT/java-sec-code.md" "$OUT/vulnerableapp.md" "$OUT/seeds.md"

#!/bin/sh
# Reproducible benchmark: larpcop (standards/recommended) vs Semgrep OSS
# (p/default) vs gitleaks, on OWASP Juice Shop, OWASP NodeGoat, DVNA, DVPWA
# (Python), DVWS-Node and vulnerable-node's SAST seeds. Writes results/ next to this script. Needs:
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
clone vulnerable-node https://github.com/cr0hn/vulnerable-node.git d68f2a3
# Semgrep's registry pack, fetched once so timings exclude the download.
[ -f "$WORK/p-default.yml" ] || curl -sfL https://semgrep.dev/c/p/default -o "$WORK/p-default.yml"

# Median wall time of RUNS runs of "$@", in seconds.
time_it() {
  for _ in $(seq $RUNS); do
    start=$(python3 -c 'import time; print(time.time())')
    "$@" > /dev/null 2>&1 || true
    python3 -c "import time; print(round(time.time() - $start, 2))"
  done | sort -n | sed -n "$(( (RUNS + 1) / 2 ))p"
}

echo "larpcop $("$LARPCOP" --version | cut -d' ' -f2) | semgrep $(semgrep --version) | gitleaks $(gitleaks version) | $(uname -sm) $(sysctl -n hw.ncpu 2>/dev/null || nproc) cpus" > "$OUT/timing.txt"

for target in juice-shop NodeGoat dvna dvpwa dvws-node; do
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

# vulnerable-node: only sast/seeds/, scored by the project's own sast/tests/score.js.
cd "$WORK/vulnerable-node"
printf "extends: ['%s/standards/recommended']\n" "$REPO" > .larpcop.yaml
"$LARPCOP" check --format json sast/seeds > "$OUT/seeds-larpcop.json" || true
semgrep scan --config "$WORK/p-default.yml" --metrics off --json -o "$OUT/seeds-semgrep.json" --quiet sast/seeds || true
python3 "$HERE/seeds.py" "$WORK/vulnerable-node" "$OUT/seeds-larpcop.json" "$OUT/seeds-semgrep.json" > "$OUT/seeds.md"

cat "$OUT/timing.txt" "$OUT/juice-shop.md" "$OUT/NodeGoat.md" "$OUT/dvna.md" "$OUT/dvpwa.md" "$OUT/dvws-node.md" "$OUT/seeds.md"

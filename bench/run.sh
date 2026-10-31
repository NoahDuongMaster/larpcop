#!/bin/sh
# Reproducible benchmark: agentkit (standards/recommended) vs Semgrep OSS
# (p/default) vs gitleaks, on OWASP Juice Shop. Writes results/ next to this
# script. Needs: git, python3, semgrep, gitleaks, and agentkit (release build).
#
#   bench/run.sh [path/to/agentkit]
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
AGENTKIT=${1:-$REPO/target/release/agentkit}
WORK=${BENCH_WORK:-${TMPDIR:-/tmp}/agentkit-bench}
JUICE_TAG=v20.3.0
RUNS=3
OUT=$HERE/results
mkdir -p "$WORK" "$OUT"

if [ ! -d "$WORK/juice-shop" ]; then
  git clone -q --depth 1 --branch "$JUICE_TAG" https://github.com/juice-shop/juice-shop.git "$WORK/juice-shop"
fi
cd "$WORK/juice-shop"
printf "extends: ['%s/standards/recommended']\n" "$REPO" > .agentkit.yaml
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

"$AGENTKIT" check --format json > "$OUT/agentkit.json" || true
semgrep scan --config "$WORK/p-default.yml" --metrics off --json -o "$OUT/semgrep.json" --quiet . || true
gitleaks dir . --report-format json --report-path "$OUT/gitleaks.json" --no-banner --log-level error || true

{
  echo "agentkit $("$AGENTKIT" --version | cut -d' ' -f2) | semgrep $(semgrep --version) | gitleaks $(gitleaks version) | juice-shop $JUICE_TAG | $(uname -sm) $(sysctl -n hw.ncpu 2>/dev/null || nproc) cpus"
  echo "agentkit_seconds $(time_it "$AGENTKIT" check --format json)"
  echo "semgrep_seconds $(time_it semgrep scan --config "$WORK/p-default.yml" --metrics off --json -o /dev/null --quiet .)"
  echo "gitleaks_seconds $(time_it gitleaks dir . --report-format json --report-path /dev/null --no-banner --log-level error)"
} > "$OUT/timing.txt"

python3 "$HERE/score.py" "$WORK/juice-shop" "$OUT/agentkit.json" "$OUT/semgrep.json" "$OUT/gitleaks.json" > "$OUT/score.md"
cat "$OUT/timing.txt" "$OUT/score.md"

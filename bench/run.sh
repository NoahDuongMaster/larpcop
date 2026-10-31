#!/bin/sh
# Reproducible benchmark: agentkit (standards/recommended) vs Semgrep OSS
# (p/default) vs gitleaks, on OWASP Juice Shop and OWASP NodeGoat. Writes
# results/ next to this script. Needs: git, python3, semgrep, gitleaks and an
# agentkit release build.
#
#   bench/run.sh [path/to/agentkit]
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
AGENTKIT=${1:-$REPO/target/release/agentkit}
WORK=${BENCH_WORK:-${TMPDIR:-/tmp}/agentkit-bench}
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

echo "agentkit $("$AGENTKIT" --version | cut -d' ' -f2) | semgrep $(semgrep --version) | gitleaks $(gitleaks version) | $(uname -sm) $(sysctl -n hw.ncpu 2>/dev/null || nproc) cpus" > "$OUT/timing.txt"

for target in juice-shop NodeGoat; do
  cd "$WORK/$target"
  printf "extends: ['%s/standards/recommended']\n" "$REPO" > .agentkit.yaml
  "$AGENTKIT" check --format json > "$OUT/$target-agentkit.json" || true
  semgrep scan --config "$WORK/p-default.yml" --metrics off --json -o "$OUT/$target-semgrep.json" --quiet . || true
  gitleaks dir . --report-format json --report-path "$OUT/$target-gitleaks.json" --no-banner --log-level error || true
  {
    echo "$target agentkit_seconds $(time_it "$AGENTKIT" check --format json)"
    echo "$target semgrep_seconds $(time_it semgrep scan --config "$WORK/p-default.yml" --metrics off --json -o /dev/null --quiet .)"
    echo "$target gitleaks_seconds $(time_it gitleaks dir . --report-format json --report-path /dev/null --no-banner --log-level error)"
  } >> "$OUT/timing.txt"
done

python3 "$HERE/score.py" "$WORK/juice-shop" "$OUT/juice-shop-agentkit.json" "$OUT/juice-shop-semgrep.json" \
  "$OUT/juice-shop-gitleaks.json" > "$OUT/juice-shop.md"
python3 "$HERE/score.py" "$WORK/NodeGoat" "$OUT/NodeGoat-agentkit.json" "$OUT/NodeGoat-semgrep.json" \
  "$OUT/NodeGoat-gitleaks.json" --truth "$HERE/nodegoat-truth.json" > "$OUT/NodeGoat.md"
cat "$OUT/timing.txt" "$OUT/juice-shop.md" "$OUT/NodeGoat.md"

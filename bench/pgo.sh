#!/bin/bash
# Builds a profile-guided binary: the release build, then a rebuild that knows
# which branches the work actually takes.
#
#   TRAIN="/path/to/repo-a /path/to/repo-b" bench/pgo.sh [output]
#
# Measured -2.4% on rails/activerecord (34.9 s -> 34.1 s, one thread, median of
# two runs), and no change on eight threads. Not the default build: it needs
# llvm-profdata and a training corpus, and the gain is small.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OUT="${1:-target/release/larpcop.pgo}"
DATA="$(mktemp -d)"
PROFDATA="$(command -v llvm-profdata || echo /opt/homebrew/opt/llvm/bin/llvm-profdata)"
TRAIN="${TRAIN:?set TRAIN to a space-separated list of directories to check}"

echo "== building with instrumentation"
RUSTFLAGS="-Cprofile-generate=$DATA" cargo build --release
BIN="$ROOT/target/release/larpcop"

echo "== training on $TRAIN"
for dir in $TRAIN; do
  ( cd "$dir" \
    && printf "extends: ['$ROOT/standards/recommended']\ndisable: [dependency-vulnerability]\n" > .larpcop.yaml \
    && LLVM_PROFILE_FILE="$DATA/%p.profraw" "$BIN" check >/dev/null 2>&1 || true
    rm -f "$dir/.larpcop.yaml" )
done

echo "== merging"
"$PROFDATA" merge -o "$DATA/merged.profdata" "$DATA"/*.profraw

echo "== rebuilding with the profile"
RUSTFLAGS="-Cprofile-use=$DATA/merged.profdata" cargo build --release
cp "$BIN" "$OUT"
echo "== $OUT"

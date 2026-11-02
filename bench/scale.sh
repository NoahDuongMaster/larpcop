#!/usr/bin/env bash
# Real repositories (nobody wrote them for a benchmark): time and findings.
# usage: bash bench/scale.sh [WORK_DIR]   (env LARPCOP, LARPCOP_RULES)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
LARPCOP=${LARPCOP:-$REPO/target/release/larpcop}
RULES=${LARPCOP_RULES:-$REPO/standards/recommended}
W=${1:-${TMPDIR:-/tmp}/larpcop-scale}
mkdir -p "$W"

clone() { # name url ref
  [ -d "$W/$1" ] && return 0
  git clone -q "https://github.com/$2.git" "$W/$1" && git -C "$W/$1" checkout -q "$3"
}

clone django django/django a05e16a
clone rails rails/rails d0f264a

for name in django rails; do
  cd "$W/$name" || continue
  printf "extends: ['%s']\ndisable: [dependency-vulnerability]\n" "$RULES" > .larpcop.yaml
  start=$(date +%s)
  "$LARPCOP" check --format json > "$W/$name.json" 2>/dev/null
  end=$(date +%s)
  rm .larpcop.yaml
  files=$(git ls-files | grep -cE '\.(py|rb)$')
  findings=$(python3 -c "import json;print(len(json.load(open('$W/$name.json'))['violations']))")
  printf '%-8s %5s files %4ss %5s findings\n' "$name" "$files" "$((end - start))" "$findings"
  python3 - "$W/$name.json" <<'PY'
import collections, json, sys
v = json.load(open(sys.argv[1]))["violations"]
for rule, n in collections.Counter(x["rule"] for x in v).most_common(8):
    print(f"    {n:5}  {rule}")
PY
done

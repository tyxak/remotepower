#!/usr/bin/env bash
# codeql-local.sh — reproduce GitHub "CodeQL default setup" code scanning locally,
# so you can catch what GitHub Code Scanning would flag BEFORE pushing.
#
# Mirrors the default setup: languages python + javascript, the default
# "<lang>-code-scanning" query suite (same one GitHub runs by default), SARIF out.
#
#   tools/codeql-local.sh             # full scan (python + javascript)
#   tools/codeql-local.sh python      # one language
#   LANGS="javascript" tools/codeql-local.sh
#
# First run downloads the CodeQL bundle (~600 MB) into .codeql-cache/ (gitignored)
# and caches it; later runs reuse it. Requires curl + tar + ~2 GB free disk.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
CACHE="$ROOT/.codeql-cache"
DBDIR="$CACHE/dbs"
OUT="$CACHE/results"
CODEQL="$CACHE/codeql/codeql"
LANGS="${LANGS:-${1:-python javascript}}"
BUNDLE_URL="https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz"

mkdir -p "$CACHE" "$DBDIR" "$OUT"

if [[ ! -x "$CODEQL" ]]; then
  echo "→ Downloading the CodeQL bundle (CLI + query packs) — first run only…"
  curl -fL --retry 3 -o "$CACHE/bundle.tar.gz" "$BUNDLE_URL"
  echo "→ Extracting…"
  tar -xzf "$CACHE/bundle.tar.gz" -C "$CACHE"
  rm -f "$CACHE/bundle.tar.gz"
fi
echo "→ CodeQL: $("$CODEQL" version --format=terse 2>/dev/null || echo '?')"

rc=0
for lang in $LANGS; do
  db="$DBDIR/$lang"
  sarif="$OUT/$lang.sarif"
  echo ""
  echo "═══ $lang ═══"
  rm -rf "$db"
  # python + javascript are interpreted → no build step (build-mode none).
  "$CODEQL" database create "$db" \
    --language="$lang" --build-mode=none --source-root="$ROOT" \
    --overwrite >/dev/null
  # The DEFAULT code-scanning suite — exactly what GitHub's default setup runs.
  "$CODEQL" database analyze "$db" \
    "$lang-code-scanning.qls" \
    --format=sarif-latest --output="$sarif" --threads=0 >/dev/null
  n=$(python3 - "$sarif" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))['runs'][0].get('results', [])
print(len(r))
for x in r[:80]:
    rule = x.get('ruleId', '?')
    loc = x['locations'][0]['physicalLocation']
    f = loc['artifactLocation']['uri']; ln = loc['region'].get('startLine', '?')
    print(f"  [{rule}] {f}:{ln} — {x['message']['text'][:90]}")
PY
)
  echo "$lang: $(echo "$n" | head -1) result(s) → $sarif"
  echo "$n" | tail -n +2
  [[ "$(echo "$n" | head -1)" != "0" ]] && rc=1
done

echo ""
if [[ $rc -eq 0 ]]; then echo "✓ CodeQL default suite: NO results across: $LANGS"
else echo "✗ CodeQL reported results — review the SARIF above (also under $OUT/)"; fi
exit $rc

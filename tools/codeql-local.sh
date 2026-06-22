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
  # --codescanning-config honors .github/codeql/codeql-config.yml (paths-ignore),
  # exactly as GitHub's default setup does, so local == GitHub.
  "$CODEQL" database create "$db" \
    --language="$lang" --build-mode=none --source-root="$ROOT" \
    --codescanning-config="$ROOT/.github/codeql/codeql-config.yml" \
    --overwrite >/dev/null
  # The DEFAULT code-scanning suite — exactly what GitHub's default setup runs.
  "$CODEQL" database analyze "$db" \
    "$lang-code-scanning.qls" \
    --format=sarif-latest --output="$sarif" --threads=0 >/dev/null
  n=$(python3 - "$sarif" "$ROOT/.github/codeql/codeql-config.yml" <<'PY'
import json, re, sys
r = json.load(open(sys.argv[1]))['runs'][0].get('results', [])
# Apply the config's query-filters excludes too (GitHub default setup does this
# at analyze time; the CLI applies the config only at database-create for
# paths-ignore). Each excluded RULE id is a reviewed by-design FP (see the
# config comments + docs/security-review-5.0.1.md).
excluded = set()
try:
    for ln in open(sys.argv[2]):
        m = re.match(r'\s*id:\s*(\S+)', ln)
        if m:
            excluded.add(m.group(1).strip())
except FileNotFoundError:
    pass
r = [x for x in r if x.get('ruleId') not in excluded]
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

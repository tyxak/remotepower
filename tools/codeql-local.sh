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
#   PARITY=1 tools/codeql-local.sh    # PROD-PARITY: simulate GitHub DEFAULT
#                                     # setup (IGNORES the config → scans tests/,
#                                     # fires the reviewed-FP rules). Run this
#                                     # BEFORE a prod tag while prod is still on
#                                     # default setup — it shows EXACTLY what the
#                                     # prod scan will flag. Once prod uses the
#                                     # advanced codeql.yml workflow, the default
#                                     # (config-honoring) run predicts prod and
#                                     # this mode is only a belt-and-braces check.
#
# First run downloads the CodeQL bundle (~600 MB) into .codeql-cache/ (gitignored)
# and caches it; later runs reuse it. Requires curl + tar + ~2 GB free disk.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
CACHE="$ROOT/.codeql-cache"
# PARITY=1 → separate db/results dirs + config DISABLED, so a parity run and a
# normal run don't clobber each other's caches.
PARITY="${PARITY:-0}"
if [[ "$PARITY" == "1" ]]; then
  DBDIR="$CACHE/dbs-prodparity"; OUT="$CACHE/results-prodparity"
else
  DBDIR="$CACHE/dbs"; OUT="$CACHE/results"
fi
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
  # Normal mode: --codescanning-config applies paths-ignore (tests/aur/…),
  # matching the ADVANCED-setup workflow (.github/workflows/codeql.yml).
  # PARITY=1: OMIT the config so tests/ ARE scanned — this reproduces GitHub's
  # DEFAULT setup, which ignores the config file (the v6.2.0 blind spot).
  _cfg_arg=(--codescanning-config="$ROOT/.github/codeql/codeql-config.yml")
  [[ "$PARITY" == "1" ]] && _cfg_arg=()
  "$CODEQL" database create "$db" \
    --language="$lang" --build-mode=none --source-root="$ROOT" \
    "${_cfg_arg[@]}" \
    --overwrite >/dev/null
  # The DEFAULT code-scanning suite — exactly what GitHub's default setup runs.
  "$CODEQL" database analyze "$db" \
    "$lang-code-scanning.qls" \
    --format=sarif-latest --output="$sarif" --threads=0 >/dev/null
  # Normal mode post-filters the reviewed-FP rule ids (advanced setup applies
  # the query-filters at analyze time). PARITY mode passes NO config path, so
  # nothing is filtered — the FP rules show, exactly as prod default setup does.
  _post_cfg="$ROOT/.github/codeql/codeql-config.yml"
  [[ "$PARITY" == "1" ]] && _post_cfg="/nonexistent-no-filter"
  n=$(python3 - "$sarif" "$_post_cfg" <<'PY'
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
_mode="config-honoring (== advanced-setup prod)"
[[ "$PARITY" == "1" ]] && _mode="PROD-PARITY (== default-setup prod: scans tests/, FP rules ON)"
if [[ $rc -eq 0 ]]; then echo "✓ CodeQL [$_mode]: NO results across: $LANGS"
else echo "✗ CodeQL [$_mode] reported results — review the SARIF above (also under $OUT/)"
     [[ "$PARITY" == "1" ]] && echo "  (parity mode: reviewed-FP rules fire here; triage + dismiss them on prod BEFORE the push, or switch prod to the advanced codeql.yml workflow so they never fire)"; fi
exit $rc

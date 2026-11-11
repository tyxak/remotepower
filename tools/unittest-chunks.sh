#!/usr/bin/env bash
# Runs the whole suite as six `unittest discover` processes, one after the other, and fails when any of them does.
#
#   tools/unittest-chunks.sh [unittest options]        run it from the root of the tree to test (the repository or an extracted tarball)
#   PYTHON=python3.14 tools/unittest-chunks.sh -v       the interpreter defaults to `python`
#
# One process that imports and keeps every test module held 12.3 GB at 7.5.0 and 14.9 GB at 8.0.0: 558 modules each load their own copy of api.py (about
# 10 MB apiece), and the rest is fixtures, the seeded demo and the JavaScript bundles. A hosted runner for a public repository has 16 GB. The 8.0.0 push
# ran past its 60-minute limit in three of its four jobs and in the fourth the test step was ended with exit code 143 after 42 minutes. The same suite
# takes 33 minutes on a machine with 64 GB, so what slowed the runner was memory and not the tests.
#
# The slices are contiguous parts of the alphabetical order (the order `unittest discover` uses), so inside a slice every module still runs after the same
# modules as before; only the process is new at each boundary. The biggest slice, test_v6*, is 319 of 1,239 modules. The patterns are checked against the
# real file names by tests/test_v800_ci_runs_the_suite_in_slices.py: every tests/test*.py must match exactly one pattern, and a new file that no pattern
# names fails the build, so a module cannot drop out of CI without anyone noticing.
#
# A slice is one or more patterns separated by `|`. Each slice writes its output to $RP_CHUNK_LOGS (default: $TMPDIR/rp-unittest-chunks, then
# /tmp/rp-unittest-chunks). The script prints one line per slice and, for a slice that failed, its FAIL/ERROR headings and the last 40 lines of its output.
set -u

PYTHON=${PYTHON:-python}
LOGS=${RP_CHUNK_LOGS:-${TMPDIR:-/tmp}/rp-unittest-chunks}

SLICES=(
  'test_[0-9a-u]*.py'
  'test_v[0-5]*.py'
  'test_v6*.py'
  'test_v7[0-3]*.py'
  'test_v7[4-9]*.py'
  'test_v[8-9]*.py|test_v[!0-9]*.py|test_[w-z]*.py'
)

mkdir -p "$LOGS" || exit 2
status=0
summary=()
n=0
for spec in "${SLICES[@]}"; do
  n=$((n + 1))
  log="$LOGS/slice-$n.log"
  IFS='|' read -r -a patterns <<< "$spec"
  echo "=== slice $n/${#SLICES[@]}: ${patterns[*]} ($(date +%T))"
  : > "$log"
  rc=0
  for p in "${patterns[@]}"; do
    "$PYTHON" -m unittest discover -s tests -p "$p" "$@" >> "$log" 2>&1
    this=$?
    # Exit 5 is unittest's answer to a pattern that matches no file. In a slice of several patterns that is allowed (test_v[!0-9]* names no file
    # today and is there for the day one exists); the coverage test holds that every slice, taken whole, matches files.
    if [ "$this" -ne 0 ] && ! { [ "$this" -eq 5 ] && [ "${#patterns[@]}" -gt 1 ]; }; then
      rc=$this
    fi
  done
  [ "$rc" -ne 0 ] && status=1
  ran=$(grep -a -E '^Ran [0-9]+ tests? in' "$log" | awk '{t += $2; s += $5} END {if (NR) printf "Ran %d tests in %.0fs", t, s}')
  # one verdict for the slice: the first FAILED line of any of its patterns, or OK with the skips of all of them added
  verdict=$(grep -a -E '^(OK|FAILED)' "$log" | awk '
    /^FAILED/ { if (!failed) failed = $0 }
    /^OK/ { ok = 1; if (match($0, /skipped=[0-9]+/)) skipped += substr($0, RSTART + 8, RLENGTH - 8) }
    END { if (failed) print failed; else if (ok) print "OK (skipped=" skipped + 0 ")" }')
  [ "$rc" -ne 0 ] && verdict="${verdict:-no verdict} (exit $rc)"
  line="slice $n/${#SLICES[@]}: ${ran:-no 'Ran' line} - ${verdict:-no verdict}"
  summary+=("$line")
  echo "$line"
  if [ "$rc" -ne 0 ]; then
    grep -a -E '^(FAIL|ERROR): ' "$log" | head -40
    tail -n 40 "$log"
  fi
done

echo "=== the slices"
printf '%s\n' "${summary[@]}"
if [ "$status" -eq 0 ]; then
  echo "=== every slice passed"
else
  echo "=== at least one slice failed (full output: $LOGS)"
fi
exit "$status"

#!/usr/bin/env bash
# Compare what the AUR is actually SERVING against what this repo has shipped.
#
# Why this exists: aur.archlinux.org was in maintenance during the v6.4.2
# promotion, so the AUR push was deferred — and then never happened. Six days
# later both packages were still live at 6.4.1-1 while production had been on
# v6.4.2 since 2026-08-06. Every Arch user installing from the AUR was a full
# release behind, and nothing anywhere said so: the repo's own PKGBUILDs were
# correct at 6.4.2, so every source-level check passed. The gap is only visible
# from outside, which is what this queries.
#
# tests/test_v643_aur_tracks_release.py covers the half that IS checkable from
# the tree (PKGBUILD == last dated CHANGELOG entry). This covers the other half.
# Read-only: it queries the public AUR RPC and prints. It changes nothing.
#
# Usage:  tools/aur-status.sh            # compare against the last shipped release
#         tools/aur-status.sh 6.4.3      # compare against a specific version
# Exit:   0 = in sync, 1 = behind (or unreachable), 2 = usage/parse error
set -uo pipefail

cd "$(dirname "$0")/.."

want="${1:-}"
if [[ -z "$want" ]]; then
  # Newest CHANGELOG entry carrying a real date — i.e. the last thing shipped.
  want="$(grep -E '^## v[0-9]+\.[0-9]+\.[0-9]+' CHANGELOG.md 2>/dev/null \
          | grep -vi 'unreleased' \
          | grep -viE 'no standalone release|folded into' \
          | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 | tr -d v)"
fi
if [[ ! "$want" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "!! Could not determine the released version (got '${want}')." >&2
  echo "   Pass one explicitly: tools/aur-status.sh 6.4.3" >&2
  exit 2
fi

echo "Last shipped release: ${want}"
echo

rc=0
for pkg in remotepower-agent remotepower-server; do
  local_ver="$(grep -E '^pkgver=' "packaging/aur/${pkg}/PKGBUILD" 2>/dev/null | cut -d= -f2)"
  live_json="$(curl -fsS --max-time 20 \
      "https://aur.archlinux.org/rpc/v5/info?arg[]=${pkg}" 2>/dev/null)" || live_json=""

  if [[ -z "$live_json" ]]; then
    printf '  %-20s repo=%-8s AUR=UNREACHABLE\n' "$pkg" "${local_ver:-?}"
    rc=1
    continue
  fi

  live_ver="$(printf '%s' "$live_json" | python3 -c '
import json, sys
try:
    r = json.load(sys.stdin).get("results") or []
    print(r[0].get("Version", "").split("-")[0] if r else "NOT-PUBLISHED")
except Exception:
    print("PARSE-ERROR")
')"

  # The v5 RPC is CACHED and lags a push by minutes — immediately after a
  # successful push it still reports the previous version. Taking that at face
  # value turns a completed release step into a false alarm, which is the same
  # kind of wrong answer this tool exists to prevent. If the RPC says we are
  # behind, confirm against the rendered package page (updated by the git hook)
  # before saying so.
  if [[ "$live_ver" != "$want" ]]; then
    page_ver="$(curl -fsS --max-time 20 "https://aur.archlinux.org/packages/${pkg}" 2>/dev/null \
                | grep -oE "Package Details: ${pkg} [0-9]+\.[0-9]+\.[0-9]+" \
                | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
    if [[ -n "$page_ver" ]]; then
      [[ "$page_ver" != "$live_ver" ]] && live_ver="${page_ver} (rpc cache stale)"
      live_ver_cmp="$page_ver"
    fi
  fi
  live_ver_cmp="${live_ver_cmp:-$live_ver}"

  status="ok"
  [[ "$local_ver" != "$want" ]] && status="repo PKGBUILD not bumped"
  [[ "$live_ver_cmp" != "$want" ]] && status="AUR NOT PUSHED"
  [[ "$status" != "ok" ]] && rc=1

  printf '  %-20s repo=%-8s AUR=%-22s %s\n' "$pkg" "${local_ver:-?}" "$live_ver" \
    "$([[ $status == ok ]] && echo '' || echo "<-- ${status}")"
  unset live_ver_cmp
done

echo
if [[ $rc -eq 0 ]]; then
  echo "In sync."
else
  cat <<EOF
OUT OF SYNC. To catch up, for each package that is behind:

  cd packaging/aur/<pkg> && ./update.sh ${want}   # needs the GitHub release published
  makepkg -f --nodeps                             # sanity-build (arch=any, no deps needed)
  # then copy PKGBUILD/.SRCINFO/.install into the AUR clone and push:
  #   ssh://aur@aur.archlinux.org/<pkg>.git  (branch master)

Do not defer this past the promotion. Deferring it once is why it was missed.
EOF
fi
exit $rc

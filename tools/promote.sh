#!/usr/bin/env bash
#
# RemotePower — prod-promotion orchestrator (v6.3.0).
# ---------------------------------------------------------------------------
# Codifies the release checklist that previously lived only as prose (and
# whose steps — CHANGELOG date flip, wiki sidebar, keep-5, CodeQL triage —
# were each missed at least once). One step at a time, checkpointed to
# .promote-state so a crashed/paused promotion resumes where it stopped.
#
#   tools/promote.sh --plan  v6.4.0        # print the steps, run nothing
#   tools/promote.sh v6.4.0 '"Codename"'   # interactive run (asks per step)
#   tools/promote.sh --reset               # forget checkpoint state
#
# DESIGN: three kinds of steps —
#   auto:    safe to execute directly (verifications, keep-5 listing, wiki gen)
#   manual:  printed as exact commands for the OPERATOR to run (gpg signing,
#            gh release create, AUR push, site rsync) — the script waits for
#            confirmation, then runs the step's verify. Interactive signing
#            stays with a human on purpose: no unattended-signing wrappers.
#   gate:    hard checks that refuse to continue on failure (pre-release
#            stamp, CHANGELOG header, tarball leak-check, lockstep).
# Nothing in this script pushes to prod by itself — every push/publish is a
# `manual` step the operator confirms.
# ---------------------------------------------------------------------------
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
STATE_FILE=".promote-state"
PROD_REPO="tyxak/remotepower"
PROD_REMOTE="remotepower"

PLAN=0
if [[ "${1:-}" == "--plan" ]]; then PLAN=1; shift; fi
if [[ "${1:-}" == "--reset" ]]; then rm -f "$STATE_FILE"; echo "state cleared"; exit 0; fi

VER="${1:-}"; CODENAME="${2:-}"
[[ -n "$VER" ]] || { echo "usage: tools/promote.sh [--plan] vX.Y.Z '\"Codename\"'"; exit 2; }
[[ "$VER" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "version must look like vX.Y.Z"; exit 2; }
NVER="${VER#v}"

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }
die()  { printf '   ✗ %s\n' "$*" >&2; exit 1; }

step_done() { grep -qxF "$1" "$STATE_FILE" 2>/dev/null; }
mark_done() { echo "$1" >> "$STATE_FILE"; }

confirm() {  # confirm "prompt" — returns only when the operator types yes
  local a; read -r -p "   → done? [yes/skip/abort] " a
  case "$a" in yes) return 0;; skip) return 1;; *) die "aborted by operator";; esac
}

run_step() {  # run_step <id> <title> <fn>
  local id="$1" title="$2" fn="$3"
  if step_done "$id"; then info "[$id] $title — already done (checkpoint)"; return 0; fi
  say "[$id] $title"
  if [[ "$PLAN" == 1 ]]; then return 0; fi
  if "$fn"; then mark_done "$id"; else die "step $id failed"; fi
}

# ── Step implementations ────────────────────────────────────────────────────

s_preflight() {  # gate
  git diff --quiet && git diff --cached --quiet || die "working tree not clean"
  local head; head="$(git rev-parse HEAD)"
  info "HEAD is $head"
  # cache-bust sanity: sw.js CACHE_NAME and index.html ?v= carry this version
  grep -q "remotepower-shell-v${NVER}" server/html/sw.js \
    || die "sw.js CACHE_NAME does not carry ${NVER}"
  grep -q "?v=${NVER}" server/html/index.html \
    || die "index.html ?v= does not carry ${NVER}"
  # prod remote must be SSH (OAuth token lacks workflow scope)
  git remote get-url "$PROD_REMOTE" | grep -q '^git@' \
    || die "$PROD_REMOTE remote is not SSH — workflow-file pushes will fail"
  return 0
}

s_pre_release() {  # gate — THE pre-tag gate; writes .pre-release-ok
  if [[ -f .pre-release-ok && "$(cat .pre-release-ok)" == "$(git rev-parse HEAD)" ]]; then
    info "stamp already matches HEAD"; return 0
  fi
  info "running: make pre-release   (check + dist + ci-parity + CodeQL — ~20 min)"
  make pre-release
  [[ -f .pre-release-ok && "$(cat .pre-release-ok)" == "$(git rev-parse HEAD)" ]] \
    || die ".pre-release-ok stamp missing/stale after make pre-release"
}

s_changelog_flip() {  # gate — header must carry a real date BEFORE the tag
  local head; head="$(head -c 2000 CHANGELOG.md)"
  echo "$head" | grep -q "## ${VER} — " || die "CHANGELOG has no ## ${VER} section"
  if echo "$head" | grep "## ${VER} — " | grep -q "unreleased"; then
    die "CHANGELOG ${VER} header still says 'unreleased (test)' — flip it to the release date (and fix any OLDER entry still marked unreleased), commit, then re-run"
  fi
  info "CHANGELOG header carries a date"
}

s_signed_tag() {  # manual — interactive gpg stays with the operator
  if git tag --verify "$VER" >/dev/null 2>&1 \
     && [[ "$(git rev-list -n1 "$VER")" == "$(git rev-parse HEAD)" ]]; then
    info "signed tag $VER already on HEAD"; return 0
  fi
  info "RUN (interactive — primes gpg-agent for the headless steps after):"
  info "    git tag -s ${VER} -m 'RemotePower ${VER} ${CODENAME}'"
  info "(tag exists on the wrong commit? use: git tag -s -f ${VER})"
  confirm || return 0
  git tag --verify "$VER" >/dev/null 2>&1 || die "tag $VER not found/verifiable"
}

s_push_prod() {  # manual — the actual promotion push. TAGS BEFORE ANY FETCH.
  info "RUN (pushes ${VER} + main to PROD; do this BEFORE any git fetch — a fetch can prune the local tag):"
  info "    git push ${PROD_REMOTE} ${VER} && git push ${PROD_REMOTE} HEAD:main"
  confirm || return 0
  git ls-remote --tags "$PROD_REMOTE" | grep -q "refs/tags/${VER}$" \
    || die "tag ${VER} not on ${PROD_REMOTE}"
}

s_release_artifacts() {  # manual — gpg pinentry gotcha: sign the BUILT tarball directly
  info "RUN:"
  info "    make dist          # tarball + sha256 (slow)"
  info "    gpg --local-user \$(git config user.signingkey) --armor \\"
  info "        -o dist/remotepower-${NVER}.tar.gz.asc --detach-sign dist/remotepower-${NVER}.tar.gz"
  info "(NOT bare 'make release': its dist run delays the pinentry past the 120s timeout)"
  confirm || return 0
  [[ -f "dist/remotepower-${NVER}.tar.gz" ]] || die "tarball missing"
  [[ -f "dist/remotepower-${NVER}.tar.gz.asc" ]] || die "signature missing"
  # leak-check: nothing internal ships (the tarball packs the working tree)
  local leaks
  leaks="$(tar -tzf "dist/remotepower-${NVER}.tar.gz" | grep -E \
    'CLAUDE\.md|opencode\.md|-internal\.md|\.claude/|\.git/|api\.env|\.enc$|\.ssh|^site/|^deploy/|^design/' || true)"
  [[ -z "$leaks" ]] || die "TARBALL LEAK: $leaks"
  info "tarball leak-check clean"
}

s_gh_release() {  # manual — canonical title format is load-bearing
  info "RUN (title format is canonical — em-dash, codename in double quotes):"
  info "    gh release create ${VER} dist/remotepower-${NVER}.tar.gz \\"
  info "        dist/remotepower-${NVER}.tar.gz.sha256 dist/remotepower-${NVER}.tar.gz.asc \\"
  info "        --repo ${PROD_REPO} --title '${VER} — ${CODENAME}' --notes-file docs/${NVER}-notes.md"
  info "(publishing the release is what triggers the ghcr multi-arch image workflow)"
  confirm || return 0
  gh release view "$VER" --repo "$PROD_REPO" >/dev/null || die "release not visible"
}

s_ghcr_verify() {  # auto — the workflow publishes; we only verify
  info "waiting is normal (arm64 emulation is slow — up to ~60 min job timeout)"
  info "verify when done:  docker manifest inspect ghcr.io/tyxak/remotepower:${NVER} >/dev/null"
  confirm || return 0
}

s_aur() {  # manual
  info "RUN for BOTH packaging/aur/remotepower-agent and .../remotepower-server:"
  info "    ./update.sh ${NVER}   (server: bump pkgver+sha256 by hand if no script)"
  info "    makepkg -f --nodeps && copy PKGBUILD/.SRCINFO into the AUR clone && git push"
  confirm || return 0
}

s_site() {  # manual — recipe lives in the internal runbook, deliberately out of repo
  info "site/: bump version badge + footer, rewrite 'New in ${VER}', refresh screenshots,"
  info "NEVER touch the logo files. Deploy per remotepower-internal-docs/ops-site-deploy-internal.md"
  info "verify:  curl -s https://remotepower.tvipper.com/ | grep -c ${NVER}"
  confirm || return 0
}

s_wiki() {  # manual (gen is auto, push is operator)
  info "RUN:"
  info "    git clone https://github.com/${PROD_REPO}.wiki.git /tmp/rp-wiki"
  info "    python3 tools/gen-wiki.py /tmp/rp-wiki ${NVER}"
  info "    # ACT ON the '_Sidebar.md not linked' warning list it prints!"
  info "    cd /tmp/rp-wiki && git add -A && git commit --no-gpg-sign -m 'docs: sync wiki to ${VER}'"
  info "    git push \"https://x-access-token:\$(gh auth token)@github.com/${PROD_REPO}.wiki.git\" master"
  confirm || return 0
}

s_codeql_triage() {  # manual
  info "release push re-runs CodeQL on prod. Check open alerts:"
  info "    gh api repos/${PROD_REPO}/code-scanning/alerts?state=open --jq length"
  info "dismiss only the documented FP classes (clear-text-storage on 0600 hashed stores etc.),"
  info "reasons need SPACES ('false positive'); log the triage in the security-review doc."
  confirm || return 0
}

s_keep5_and_lockstep() {  # manual verify — destructive bits stay with the operator
  info "keep-5 releases on ${PROD_REPO} (NEVER --cleanup-tag; tags stay):"
  info "    gh release list --repo ${PROD_REPO} --limit 100"
  info "lockstep: FF test remotes to the release commit:"
  info "    git push origin HEAD:main    (and FF tyxak/claude-code if still in use)"
  confirm || return 0
  local prod local_sha
  prod="$(git ls-remote "$PROD_REMOTE" main | cut -f1)"
  local_sha="$(git rev-parse HEAD)"
  [[ "$prod" == "$local_sha" ]] || info "note: prod main=$prod != local HEAD=$local_sha (fine if you tagged an earlier commit)"
}

# ── The checklist ───────────────────────────────────────────────────────────
run_step 01-preflight        "Preflight: clean tree, cache-bust, SSH prod remote"  s_preflight
run_step 02-pre-release      "make pre-release (THE gate; writes the push stamp)"  s_pre_release
run_step 03-changelog        "CHANGELOG header carries the release date"           s_changelog_flip
run_step 04-signed-tag       "Signed tag (operator, interactive gpg)"              s_signed_tag
run_step 05-push-prod        "Push tag + main to prod (tags BEFORE any fetch)"     s_push_prod
run_step 06-artifacts        "Release artifacts + signature + tarball leak-check"  s_release_artifacts
run_step 07-gh-release       "GitHub release (canonical title; triggers ghcr)"     s_gh_release
run_step 08-ghcr             "ghcr multi-arch image published"                     s_ghcr_verify
run_step 09-aur              "AUR agent + server packages"                         s_aur
run_step 10-site             "Marketing site refresh + deploy"                     s_site
run_step 11-wiki             "Wiki refresh (+ hand-curated sidebar!)"              s_wiki
run_step 12-codeql           "CodeQL alert triage on prod"                         s_codeql_triage
run_step 13-keep5-lockstep   "Releases keep-5 + test-remote lockstep"              s_keep5_and_lockstep

say "promotion checklist complete for ${VER} ${CODENAME}"
if [[ "$PLAN" == 1 ]]; then
  info "(plan mode — nothing was executed, checkpoint untouched)"
else
  rm -f "$STATE_FILE"
fi

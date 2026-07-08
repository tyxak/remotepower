#!/usr/bin/env bash
# RemotePower — one-command pre-6.1.0 -> 6.1.0 transport conversion.
#
# CGI (fcgiwrap) and the SCGI prefork worker (remotepower-api.service) are
# retired as of v6.1.0 — the server now runs ONLY on gunicorn + Flask
# (server/cgi-bin/wsgi.py, remotepower-wsgi.service). An install that predates
# v6.1.0 needs to move onto that transport; this script self-detects whether
# that's needed and does it, non-interactively, without changing anything else
# about your install (storage backend, scheduler mode and scanner stay exactly
# as they were — this is a transport-only fix, not an opt-in to the newer
# single-node "enterprise" topology).
#
# What it does, in order:
#   1. Detects whether this box is already on the gunicorn/Flask transport.
#      If so, skips straight to step 4 (idempotent — safe to re-run anytime).
#   2. If not: runs install-server.sh with --no-postgres --no-scheduler
#      --no-scanner (install-server.sh's own topology defaults changed in
#      v6.1.0; passing all three --no-* flags keeps this conversion strictly
#      about the transport). That installs gunicorn+Flask, deploys the current
#      code, refreshes the shared nginx snippet to proxy_pass, and starts
#      remotepower-wsgi. It does NOT touch your existing admin account,
#      storage backend, or main nginx site file.
#   3. Health-checks the new gunicorn tier directly (127.0.0.1:8090) before
#      touching anything old — if it's not answering, the old fcgiwrap/SCGI
#      path is left completely alone and the script exits non-zero. Nothing
#      is torn down on a failed conversion.
#   4. Only once the new tier is confirmed healthy: stops + disables the old
#      fcgiwrap service/socket and the old remotepower-api.service (if
#      present), and removes the retired api_cgi.py/api_worker.py files that
#      a plain `git pull` + deploy-server.sh leaves stranded on disk (deploy
#      never deletes files that disappeared from the source tree).
#   5. Detects a demo vhost (packaging/install-demo.sh) and, if it's still on
#      the old per-request CGI RP_DATA_DIR/RP_READ_ONLY override model instead
#      of its own dedicated remotepower-wsgi-demo process, re-runs
#      install-demo.sh against it — that script is itself idempotent
#      ("re-running re-seeds the demo data and re-renders the nginx config +
#      systemd unit"), so this upgrades the demo the same way.
#
# Usage:
#   sudo bash packaging/convert-to-wsgi.sh
#   sudo bash packaging/convert-to-wsgi.sh --dry-run
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
die()     { echo -e "${RED}[✗]${NC} $*"; exit 1; }

DRY_RUN=0
for a in "$@"; do
  case "$a" in
    --dry-run) DRY_RUN=1 ;;
    -h|--help)
      sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) die "Unknown option: $a (try --help)" ;;
  esac
done

run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "DRY-RUN: $*"
  else
    echo "  + $*"
    "$@"
  fi
}

[[ "$EUID" -ne 0 && "$DRY_RUN" -eq 0 ]] && die "Run as root: sudo bash $0"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "$ROOT/install-server.sh" ]] || die "install-server.sh not found next to this script ($ROOT) — run from a full repo checkout"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   RemotePower pre-6.1.0 -> gunicorn/Flask conversion  ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── Step 1: is the new transport already active? ────────────────────────────
wsgi_active() { systemctl is-active --quiet remotepower-wsgi 2>/dev/null; }

if wsgi_active; then
  success "remotepower-wsgi is already active — this box is on the v6.1.0 transport."
else
  info "remotepower-wsgi is not active — this box needs converting from CGI/SCGI."

  # ── Step 2: run install-server.sh, transport-only ──────────────────────────
  # --no-postgres/--no-scheduler/--no-scanner: install-server.sh's own
  # defaults changed to "enterprise" single-node in v6.1.0 — passing all three
  # keeps THIS script's job strictly to the mandatory transport change, not an
  # opt-in to Postgres/out-of-band-scheduler/co-located-scanner the operator
  # never asked for. It's still fully safe to re-run on an existing install:
  # the nginx site file and admin account are both left alone when they
  # already exist (the admin-account guard was added specifically so this
  # script could call install-server.sh non-interactively).
  info "Running install-server.sh --no-postgres --no-scheduler --no-scanner ..."
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "DRY-RUN: bash \"$ROOT/install-server.sh\" --no-postgres --no-scheduler --no-scanner"
  else
    bash "$ROOT/install-server.sh" --no-postgres --no-scheduler --no-scanner
  fi

  if [[ "$DRY_RUN" -eq 0 ]] && ! wsgi_active; then
    die "install-server.sh finished but remotepower-wsgi still isn't active — check: systemctl status remotepower-wsgi. Nothing old was touched."
  fi
fi

# ── Step 3: health-check the new tier directly, before touching anything old ─
health_ok=0
if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "DRY-RUN: would health-check http://127.0.0.1:8090/api/health"
  health_ok=1
else
  info "Health-checking the gunicorn tier (127.0.0.1:8090)..."
  for _ in $(seq 1 15); do
    if python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8090/api/health',timeout=3).status==200 else 1)" 2>/dev/null; then
      health_ok=1
      break
    fi
    sleep 2
  done
fi

if [[ "$health_ok" -ne 1 ]]; then
  warn "gunicorn did not answer a healthy /api/health after 30s."
  warn "Leaving any existing fcgiwrap/remotepower-api services untouched — nothing was torn down."
  die "conversion incomplete — check: systemctl status remotepower-wsgi ; journalctl -u remotepower-wsgi -n 50"
fi
success "gunicorn/Flask tier is healthy."

# ── Step 4: retire the old CGI/SCGI stack, now that the new one is proven ───
FOUND_OLD=0

if systemctl list-unit-files 2>/dev/null | grep -q '^fcgiwrap\.\(service\|socket\)'; then
  FOUND_OLD=1
  info "Found fcgiwrap — stopping + disabling (the package itself is left installed)..."
  run systemctl disable --now fcgiwrap.socket 2>/dev/null || true
  run systemctl disable --now fcgiwrap 2>/dev/null || true
fi

if [[ -f /etc/systemd/system/remotepower-api.service ]]; then
  FOUND_OLD=1
  info "Found the old SCGI worker unit (remotepower-api.service) — stopping + removing..."
  run systemctl disable --now remotepower-api 2>/dev/null || true
  run rm -f /etc/systemd/system/remotepower-api.service
fi

for stale in api_cgi.py api_worker.py; do
  if [[ -f "/var/www/remotepower/cgi-bin/$stale" ]]; then
    FOUND_OLD=1
    info "Removing stranded $stale (no longer deployed, but deploy-server.sh doesn't delete old files)..."
    run rm -f "/var/www/remotepower/cgi-bin/$stale"
  fi
done

if [[ "$FOUND_OLD" -eq 1 ]]; then
  run systemctl daemon-reload
  success "Old CGI/SCGI artifacts retired."
else
  info "No old CGI/SCGI artifacts found — nothing to clean up."
fi

# ── Step 5: is there a demo vhost, and does it match the main install? ──────
# Two things can be stale independently: the demo might still be on the old
# per-request CGI RP_DATA_DIR/RP_READ_ONLY override model (needs
# install-demo.sh to give it its own remotepower-wsgi-demo process at all),
# and/or it might be on the right process model but a different storage
# backend than the main install just ended up on. The demo's backend is made
# to MATCH the main install's, not forced to Postgres unconditionally — this
# script is a transport-only conversion (see the --no-postgres/--no-scheduler
# --no-scanner note above), so if the main install stayed on the file
# backend, the demo does too.
MAIN_IS_POSTGRES=0
if [[ -f /var/lib/remotepower/storage_backend.json ]] \
    && grep -q '"backend"[[:space:]]*:[[:space:]]*"postgres"' /var/lib/remotepower/storage_backend.json 2>/dev/null; then
  MAIN_IS_POSTGRES=1
fi

DEMO_CONF=""
for candidate in /etc/nginx/sites-available/remotepower-demo /etc/nginx/conf.d/remotepower-demo.conf; do
  [[ -f "$candidate" ]] && DEMO_CONF="$candidate" && break
done

DEMO_IS_POSTGRES=0
if [[ -f /var/lib/remotepower-demo/storage_backend.json ]] \
    && grep -q '"backend"[[:space:]]*:[[:space:]]*"postgres"' /var/lib/remotepower-demo/storage_backend.json 2>/dev/null; then
  DEMO_IS_POSTGRES=1
fi

if [[ -z "$DEMO_CONF" ]]; then
  info "No demo vhost detected — skipping."
elif systemctl is-active --quiet remotepower-wsgi-demo 2>/dev/null && [[ "$DEMO_IS_POSTGRES" -eq "$MAIN_IS_POSTGRES" ]]; then
  success "Demo vhost found, already on its own remotepower-wsgi-demo process, backend matches the main install — nothing to do."
else
  DEMO_HOST="$(sed -n 's/^\s*server_name\s\+\([^;]*\);.*/\1/p' "$DEMO_CONF" | head -1 | awk '{print $1}')"
  if [[ -z "$DEMO_HOST" ]]; then
    warn "Found a demo vhost ($DEMO_CONF) but couldn't parse its server_name — convert it manually: bash packaging/install-demo.sh <demo-hostname>"
  else
    demo_pg_flag=()
    [[ "$MAIN_IS_POSTGRES" -eq 1 ]] && demo_pg_flag=(--postgres)
    info "Found demo vhost for '$DEMO_HOST' needing an update — upgrading via install-demo.sh${demo_pg_flag:+ ${demo_pg_flag[*]}}..."
    if [[ "$DRY_RUN" -eq 1 ]]; then
      echo "DRY-RUN: bash \"$ROOT/packaging/install-demo.sh\" \"$DEMO_HOST\" ${demo_pg_flag[*]:-}"
    else
      [[ -f "$ROOT/packaging/install-demo.sh" ]] || die "packaging/install-demo.sh not found — can't upgrade the demo"
      bash "$ROOT/packaging/install-demo.sh" "$DEMO_HOST" "${demo_pg_flag[@]}"
    fi
    success "Demo vhost '$DEMO_HOST' upgraded (own remotepower-wsgi-demo process, backend matches the main install)."
  fi
fi

echo ""
success "Done."
[[ "$DRY_RUN" -eq 1 ]] && echo "  (dry run — nothing was actually changed)"
echo ""

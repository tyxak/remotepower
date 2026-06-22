#!/usr/bin/env bash
#
# RemotePower — server self-update script (turnkey).
# ---------------------------------------------------------------------------
# Point Settings → Install → "Guided self-update" at this script (absolute
# path) and the "Run update now" button executes it. The RemotePower API runs
# it DIRECTLY — never through a shell, with NO arguments — as the unprivileged
# user the API runs as (usually `www-data`). Pulling new code and restarting
# the service needs root, so this script re-executes itself under `sudo -n`;
# grant that with a SCOPED, passwordless sudoers drop-in so nothing else opens
# up.
#
# INSTALL (run as root, once):
#   install -m 755 -o root -g root \
#     packaging/remotepower-server-update.sh /usr/local/sbin/remotepower-server-update
#   # Let the API user run THIS ONE script as root, passwordless:
#   printf 'www-data ALL=(root) NOPASSWD: /usr/local/sbin/remotepower-server-update\n' \
#     > /etc/sudoers.d/remotepower-self-update
#   chmod 440 /etc/sudoers.d/remotepower-self-update
#   visudo -cf /etc/sudoers.d/remotepower-self-update   # validate
#   # Then set the path in Settings → Install:
#   #   /usr/local/sbin/remotepower-server-update
#   # (Replace www-data with your API service user if different.)
#
# WHAT IT DOES — auto-detects the install type and updates in place:
#   * git checkout   → fetch + hard-reset to the release ref, run deploy-server.sh
#   * pacman / AUR   → pacman -Sy the remotepower-server package
#   * apt / dpkg     → apt-get install the latest remotepower-server package
#   * container      → refuses (an image must be repulled by the orchestrator)
# then restarts the SCGI worker (classic-CGI installs need no restart — fcgiwrap
# re-execs the new code on the next request) and reloads nginx.
#
# TUNE via the environment (e.g. in the API unit's EnvironmentFile,
# /etc/remotepower/api.env). Defaults match a standard install:
#   RP_INSTALL_DIR   install root for a git checkout   (default /var/www/remotepower)
#   RP_API_SERVICE   systemd unit to restart           (default remotepower-api)
#   RP_UPDATE_REF    git ref to update to    (default: latest release TAG, not a
#                    branch tip — set e.g. RP_UPDATE_REF=v5.0.0, or a branch only
#                    if you deliberately want unreleased code)
#   RP_PKG_NAME      OS package name                   (default remotepower-server)
#   RP_API_USER      sudoers user (docs only)          (default www-data)
# ---------------------------------------------------------------------------
set -euo pipefail

INSTALL_DIR="${RP_INSTALL_DIR:-/var/www/remotepower}"
API_SERVICE="${RP_API_SERVICE:-remotepower-api}"
UPDATE_REF="${RP_UPDATE_REF:-}"   # empty → resolve the latest release tag below
PKG_NAME="${RP_PKG_NAME:-remotepower-server}"

log() { printf '[remotepower-update] %s\n' "$*"; }
die() { printf '[remotepower-update] ERROR: %s\n' "$*" >&2; exit 1; }

# ── Privilege escalation ────────────────────────────────────────────────────
# The API runs us as its unprivileged user. Re-exec as root via passwordless
# sudo (scoped to this script — see the header). `-n` never prompts: if the
# sudoers drop-in is missing it fails fast with a clear message instead of
# hanging the request.
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 || die "not root and sudo not available — install the sudoers drop-in (see this script's header)"
  log "escalating via sudo -n ..."
  exec sudo -n "$0" "$@"
fi

UPDATED=""

# ── Detect the install type and pull the new version ────────────────────────
if [ -f /.dockerenv ] || [ "${RP_IN_CONTAINER:-0}" = "1" ]; then
  die "containerized install — update by pulling a new image and recreating the container (e.g. 'docker compose pull && docker compose up -d'); a container can't update itself from the inside"

elif [ -d "$INSTALL_DIR/.git" ]; then
  command -v git >/dev/null 2>&1 || die "git not found"
  git -C "$INSTALL_DIR" fetch --tags --force --prune origin
  ref="$UPDATE_REF"
  if [ -z "$ref" ]; then
    # Default to the latest RELEASE tag, NOT a branch tip: resetting to a branch
    # like origin/main can land UNRELEASED code on a production server.
    ref="$(git -C "$INSTALL_DIR" describe --tags --abbrev=0 --match 'v[0-9]*' 2>/dev/null || true)"
    [ -n "$ref" ] || die "no release tag found — set RP_UPDATE_REF to a tag (e.g. v5.0.0) or a branch explicitly"
  fi
  prev="$(git -C "$INSTALL_DIR" rev-parse HEAD)"
  log "git checkout at $INSTALL_DIR → updating $prev → $ref"
  git -C "$INSTALL_DIR" reset --hard "$ref"
  if [ -x "$INSTALL_DIR/deploy-server.sh" ]; then
    log "running deploy-server.sh ..."
    if ! "$INSTALL_DIR/deploy-server.sh"; then   # installs files + restarts the worker
      log "deploy FAILED — rolling back to $prev"
      git -C "$INSTALL_DIR" reset --hard "$prev"
      "$INSTALL_DIR/deploy-server.sh" || log "rollback redeploy also failed — manual recovery needed"
      die "update failed; rolled back to $prev"
    fi
    UPDATED="git+deploy"
  else
    UPDATED="git"
  fi

elif command -v pacman >/dev/null 2>&1 && pacman -Qq "$PKG_NAME" >/dev/null 2>&1; then
  log "pacman/AUR package $PKG_NAME → syncing"
  pacman -Sy --noconfirm "$PKG_NAME"
  UPDATED="pacman"

elif command -v apt-get >/dev/null 2>&1 && dpkg -s "$PKG_NAME" >/dev/null 2>&1; then
  log "apt package $PKG_NAME → installing latest"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y --only-upgrade "$PKG_NAME"
  UPDATED="apt"

else
  die "could not detect a known install type — no .git at $INSTALL_DIR and no $PKG_NAME package. Set RP_INSTALL_DIR / RP_PKG_NAME, or update manually."
fi

# ── Restart the service ─────────────────────────────────────────────────────
# deploy-server.sh already restarts the worker for git installs; the package
# branches do not, so restart here. A restart is idempotent, so this is safe
# either way. Classic-CGI installs have no worker unit — fcgiwrap picks up the
# new code on the next request, so a missing unit is not an error.
if command -v systemctl >/dev/null 2>&1; then
  if systemctl list-unit-files 2>/dev/null | grep -q "^${API_SERVICE}\.service"; then
    log "restarting ${API_SERVICE} ..."
    systemctl restart "$API_SERVICE"
  else
    log "no ${API_SERVICE}.service unit (classic CGI) — nothing to restart"
  fi
  systemctl reload nginx 2>/dev/null || true
fi

log "update complete (${UPDATED})"

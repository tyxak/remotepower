#!/usr/bin/env bash
#
# RemotePower — server restart script (turnkey).
# ---------------------------------------------------------------------------
# Backs the "Restart server" button (Settings → Install). The RemotePower API
# runs this DIRECTLY — never through a shell, with NO arguments — as the
# unprivileged user the API runs as (usually `www-data`). Restarting the
# systemd service needs root, so this script re-execs itself under `sudo -n`;
# grant that with a SCOPED, passwordless sudoers drop-in so nothing else opens
# up. This is the SAME model the self-update script uses, and grants no
# privilege an admin doesn't already have (self-update also restarts the
# service). The scoped sudoers rule IS the enable gate: without it the button
# fails fast with a clear message rather than doing anything.
#
# INSTALL (run as root, once):
#   install -m 755 -o root -g root \
#     packaging/remotepower-server-restart.sh /usr/local/sbin/remotepower-server-restart
#   # Let the API user run THIS ONE script as root, passwordless:
#   printf 'www-data ALL=(root) NOPASSWD: /usr/local/sbin/remotepower-server-restart\n' \
#     > /etc/sudoers.d/remotepower-self-restart
#   chmod 440 /etc/sudoers.d/remotepower-self-restart
#   visudo -cf /etc/sudoers.d/remotepower-self-restart   # validate
#   # (Replace www-data with your API service user if different.)
#
# WHAT IT DOES — restarts the app-server unit (and, if present, the out-of-band
# scheduler), DETACHED so the restart survives this script's own death when the
# service it runs under is stopped. The API never sees the restart's exit code
# (its worker is gone by then) — it only confirms the restart was SCHEDULED.
#
# TUNE via the environment (e.g. /etc/remotepower/api.env). Defaults match a
# standard install:
#   RP_WSGI_SERVICE       app-server unit           (default remotepower-wsgi)
#   RP_SCHEDULER_SERVICE  scheduler unit, if any     (default remotepower-scheduler)
#   RP_RESTART_DELAY      seconds before the restart  (default 2 — lets the API's
#                         HTTP response flush before its worker is killed)
# ---------------------------------------------------------------------------
set -euo pipefail

WSGI_SERVICE="${RP_WSGI_SERVICE:-remotepower-wsgi}"
SCHED_SERVICE="${RP_SCHEDULER_SERVICE:-remotepower-scheduler}"
DELAY="${RP_RESTART_DELAY:-2}"

log() { printf '[remotepower-restart] %s\n' "$*"; }
die() { printf '[remotepower-restart] ERROR: %s\n' "$*" >&2; exit 1; }

# ── Privilege escalation ────────────────────────────────────────────────────
# Re-exec as root via passwordless sudo (scoped to this script — see the
# header). `-n` never prompts: a missing sudoers drop-in fails fast rather than
# hanging the request.
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 || die "not root and sudo not available — install the sudoers drop-in (see this script's header)"
  exec sudo -n "$0" "$@"
fi

command -v systemctl >/dev/null 2>&1 || die "systemctl not found — this restart path is for a systemd install (in a container, restart the container instead)"

# Confirm the unit exists before we claim success, so a misconfigured install
# gets a clear error instead of a silent no-op.
systemctl cat "$WSGI_SERVICE" >/dev/null 2>&1 || die "unit '$WSGI_SERVICE' not found — set RP_WSGI_SERVICE to your app-server unit"

# Detach the actual restart: `systemctl restart` on the unit we run UNDER kills
# this process mid-command, so hand the work to an independent session that
# outlives us. The delay lets the API flush its "restart scheduled" response
# first. Restart the scheduler too when it exists (best-effort).
restart_cmd="sleep ${DELAY}; systemctl restart '${WSGI_SERVICE}'"
if systemctl cat "$SCHED_SERVICE" >/dev/null 2>&1; then
  restart_cmd="${restart_cmd}; systemctl restart '${SCHED_SERVICE}' || true"
fi
setsid sh -c "$restart_cmd" </dev/null >/dev/null 2>&1 &

log "restart of ${WSGI_SERVICE} scheduled in ${DELAY}s"
exit 0

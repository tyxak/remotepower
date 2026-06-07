#!/bin/bash
# postgres-ha-standby.sh — bootstrap a PostgreSQL STANDBY that streams from the
# RemotePower primary (run postgres-ha-primary.sh on the primary first).
#
# *** DESTRUCTIVE on this host ***  It stops the local PostgreSQL and REPLACES
# its data directory with a base backup of the primary. Only run on a node you
# intend to be a replica — never on the primary, never on a server holding data
# you care about. Requires CONFIRM=yes.
#
# Usage:
#   sudo PRIMARY_HOST=10.0.0.4 REPL_USER=rp_repl REPL_PASS='…' \
#        REPL_SLOT=rp_standby_1 CONFIRM=yes bash packaging/postgres-ha-standby.sh
#
# Env:
#   PRIMARY_HOST   primary's host/IP                     (required)
#   REPL_USER      replication role (from the primary)   (default: rp_repl)
#   REPL_PASS      replication role password             (required)
#   REPL_SLOT      replication slot on the primary       (default: rp_standby_1)
#   PRIMARY_PORT   primary's port                        (default: 5432)
#   CONFIRM        must equal 'yes' to proceed (it wipes this node's PGDATA)

set -euo pipefail

PRIMARY_HOST="${PRIMARY_HOST:-}"
PRIMARY_PORT="${PRIMARY_PORT:-5432}"
REPL_USER="${REPL_USER:-rp_repl}"
REPL_PASS="${REPL_PASS:-}"
REPL_SLOT="${REPL_SLOT:-rp_standby_1}"
CONFIRM="${CONFIRM:-}"

if [ "$(id -u)" -ne 0 ]; then echo "run as root (sudo)" >&2; exit 1; fi
[ -n "$PRIMARY_HOST" ] || { echo "set PRIMARY_HOST=<primary-ip>" >&2; exit 2; }
[ -n "$REPL_PASS" ]    || { echo "set REPL_PASS=<replication password>" >&2; exit 2; }
command -v pg_basebackup >/dev/null || { echo "PostgreSQL client tools not installed" >&2; exit 1; }

log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }

# Resolve this node's PGDATA + cluster (Debian: /var/lib/postgresql/<ver>/<cluster>)
PGDATA="$(sudo -u postgres psql -tAc 'SHOW data_directory' 2>/dev/null || true)"
if [ -z "$PGDATA" ]; then
  PGDATA="$(ls -d /var/lib/postgresql/*/main 2>/dev/null | head -1 || true)"
fi
[ -n "$PGDATA" ] || { echo "could not determine PGDATA" >&2; exit 1; }

echo "This will STOP PostgreSQL on this host and ERASE:"
echo "    ${PGDATA}"
echo "  replacing it with a base backup streamed from ${PRIMARY_HOST}:${PRIMARY_PORT}."
if [ "$CONFIRM" != "yes" ]; then
  echo "Refusing: set CONFIRM=yes to proceed (destructive)." >&2
  exit 3
fi

log "Stopping PostgreSQL on this host."
systemctl stop postgresql

TS="$(date +%s 2>/dev/null || echo bak)"
if [ -d "$PGDATA" ] && [ -n "$(ls -A "$PGDATA" 2>/dev/null)" ]; then
  log "Moving old data dir aside → ${PGDATA}.old.${TS}"
  mv "$PGDATA" "${PGDATA}.old.${TS}"
fi
mkdir -p "$PGDATA"
chown postgres:postgres "$PGDATA"
chmod 700 "$PGDATA"

log "Streaming base backup from primary (this can take a while)…"
# -R writes standby.signal + primary_conninfo; -C -S registers/uses the slot.
PGPASSWORD="$REPL_PASS" sudo -u postgres pg_basebackup \
  -h "$PRIMARY_HOST" -p "$PRIMARY_PORT" -U "$REPL_USER" \
  -D "$PGDATA" -Fp -Xs -P -R -C -S "$REPL_SLOT"

log "Starting PostgreSQL (standby / hot_standby)."
systemctl start postgresql

sleep 2
if sudo -u postgres psql -tAc 'SELECT pg_is_in_recovery()' | grep -q t; then
  log "Standby is up and IN RECOVERY (streaming). ✓"
  sudo -u postgres psql -tAc \
    "SELECT status, sender_host FROM pg_stat_wal_receiver" 2>/dev/null || true
else
  echo "WARNING: node is not in recovery — check journalctl -u postgresql." >&2
fi

echo
log "Standby bootstrapped."
echo "   Point RemotePower's DSN at BOTH hosts so a failover is automatic:"
echo "     postgresql://rp:****@${PRIMARY_HOST},$(hostname -I | awk '{print $1}'):5432/remotepower"
echo "   (RemotePower adds target_session_attrs=read-write → always writes to"
echo "    whichever node is currently primary.)"

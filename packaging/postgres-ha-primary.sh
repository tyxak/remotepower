#!/bin/bash
# postgres-ha-primary.sh — configure an existing PostgreSQL as a streaming-
# replication PRIMARY for RemotePower HA. Run this on the primary AFTER
# postgres-setup.sh. Then run postgres-ha-standby.sh on each standby.
#
# It: sets wal_level/replication knobs, creates a replication role + physical
# replication slot, opens a scoped pg_hba entry for the standby, and reloads.
# Idempotent. A restart is needed only the first time wal_level changes.
#
# Usage:
#   sudo STANDBY_CIDR=10.0.0.5/32 REPL_PASS='…' bash packaging/postgres-ha-primary.sh
#
# Env:
#   STANDBY_CIDR   CIDR the standby connects from        (required, e.g. 10.0.0.5/32)
#   REPL_USER      replication role name                 (default: rp_repl)
#   REPL_PASS      replication role password             (default: generated, printed once)
#   REPL_SLOT      physical replication slot name        (default: rp_standby_1)
#
# After this + the standby is streaming, point RemotePower's DSN at BOTH hosts:
#   postgresql://rp:****@<primary>,<standby>:5432/remotepower
# RemotePower adds target_session_attrs=read-write, so it always writes to the
# current primary and follows a failover automatically.

set -euo pipefail

REPL_USER="${REPL_USER:-rp_repl}"
REPL_PASS="${REPL_PASS:-}"
REPL_SLOT="${REPL_SLOT:-rp_standby_1}"
STANDBY_CIDR="${STANDBY_CIDR:-}"

if [ "$(id -u)" -ne 0 ]; then echo "run as root (sudo)" >&2; exit 1; fi
if [ -z "$STANDBY_CIDR" ]; then echo "set STANDBY_CIDR=<standby-ip>/32" >&2; exit 2; fi
command -v psql >/dev/null || { echo "PostgreSQL not installed" >&2; exit 1; }

log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
psu() { sudo -u postgres psql -v ON_ERROR_STOP=1 -tAc "$1"; }

GENERATED=0
if [ -z "$REPL_PASS" ]; then
  REPL_PASS="$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)"
  GENERATED=1
fi

PGCONF="$(psu 'SHOW config_file')"
PGHBA="$(psu 'SHOW hba_file')"

# ── replication settings (idempotent appends; last value wins in postgresql.conf)
log "Setting replication parameters in ${PGCONF}"
need_restart=0
cur_wal="$(psu 'SHOW wal_level' || echo '')"
if [ "$cur_wal" != "replica" ] && [ "$cur_wal" != "logical" ]; then need_restart=1; fi
{
  echo ""
  echo "# RemotePower HA (postgres-ha-primary.sh)"
  echo "wal_level = replica"
  echo "max_wal_senders = 10"
  echo "max_replication_slots = 10"
  echo "wal_keep_size = 512MB"
  echo "hot_standby = on"
} >> "$PGCONF"

# ── replication role ────────────────────────────────────────────────────────────
if [ "$(psu "SELECT 1 FROM pg_roles WHERE rolname='${REPL_USER}'")" = "1" ]; then
  log "Replication role '${REPL_USER}' exists — updating password."
  sudo -u postgres psql -v ON_ERROR_STOP=1 -c \
    "ALTER ROLE \"${REPL_USER}\" WITH REPLICATION LOGIN PASSWORD '$(printf "%s" "$REPL_PASS" | sed "s/'/''/g")';" >/dev/null
else
  log "Creating replication role '${REPL_USER}'."
  sudo -u postgres psql -v ON_ERROR_STOP=1 -c \
    "CREATE ROLE \"${REPL_USER}\" WITH REPLICATION LOGIN PASSWORD '$(printf "%s" "$REPL_PASS" | sed "s/'/''/g")';" >/dev/null
fi

# ── replication slot (idempotent) ────────────────────────────────────────────────
if [ "$(psu "SELECT 1 FROM pg_replication_slots WHERE slot_name='${REPL_SLOT}'")" = "1" ]; then
  log "Replication slot '${REPL_SLOT}' already exists."
else
  log "Creating physical replication slot '${REPL_SLOT}'."
  psu "SELECT pg_create_physical_replication_slot('${REPL_SLOT}')" >/dev/null
fi

# ── pg_hba: allow the standby to connect for replication ──────────────────────────
if ! grep -q "RemotePower replication" "$PGHBA"; then
  log "Opening pg_hba for replication from ${STANDBY_CIDR}"
  cat >> "$PGHBA" <<EOF
# RemotePower replication
host    replication    ${REPL_USER}    ${STANDBY_CIDR}    scram-sha-256
EOF
fi

systemctl reload postgresql || true
if [ "$need_restart" -eq 1 ]; then
  log "wal_level changed → restarting PostgreSQL once."
  systemctl restart postgresql
fi

echo
log "Primary configured for streaming replication."
echo "   Replication role : ${REPL_USER}"
echo "   Replication slot : ${REPL_SLOT}"
if [ "$GENERATED" -eq 1 ]; then
  echo "   Replication pass : ${REPL_PASS}     <-- store it; you need it on the standby"
fi
echo
echo "   Now run on the STANDBY:"
echo "     sudo PRIMARY_HOST=<this-host> REPL_USER=${REPL_USER} REPL_PASS='****' \\"
echo "          REPL_SLOT=${REPL_SLOT} bash packaging/postgres-ha-standby.sh"

#!/bin/bash
# postgres-setup.sh — provision a PostgreSQL backend for RemotePower.
#
# Creates the role + database RemotePower's Postgres backend expects, on a
# fresh or existing PostgreSQL 14+ server (Debian/Ubuntu). Idempotent: safe to
# re-run (it won't drop anything). For high availability, run this on the
# PRIMARY, then see postgres-ha-primary.sh / postgres-ha-standby.sh.
#
# Usage:
#   sudo bash packaging/postgres-setup.sh                 # interactive-ish, sane defaults
#   sudo RP_DB_PASS='…' bash packaging/postgres-setup.sh  # supply the password
#   sudo bash packaging/postgres-setup.sh --write-marker /var/lib/remotepower
#
# Env / flags:
#   RP_DB_NAME   database name   (default: remotepower)
#   RP_DB_USER   role name       (default: rp)
#   RP_DB_PASS   role password   (default: a generated 32-char secret, printed once)
#   RP_DB_PORT   TCP port        (default: auto-detected via `SHOW port`, falls
#                                back to 5432 if detection fails — found live,
#                                a box running Postgres on a non-default port
#                                got a DSN hardcoded to 5432, which hung every
#                                connection attempt instead of failing fast)
#   --install            apt-install PostgreSQL if it isn't present
#   --write-marker DIR   write DIR/storage_backend.json so a local RemotePower
#                        install uses this DB (does NOT migrate data — use
#                        Settings → Advanced → Storage backend for that;
#                        tools/migrate_storage.py only covers json<->sqlite)
#   --listen             open postgresql.conf listen_addresses + pg_hba for LAN
#                        (needed when app nodes are on other hosts)
#
# It NEVER prints the password to logs other than the final summary, and never
# writes it into world-readable files (the marker is chmod 600).

set -euo pipefail

RP_DB_NAME="${RP_DB_NAME:-remotepower}"
RP_DB_USER="${RP_DB_USER:-rp}"
RP_DB_PASS="${RP_DB_PASS:-}"
RP_DB_PORT="${RP_DB_PORT:-}"
DO_INSTALL=0
WRITE_MARKER=""
DO_LISTEN=0

while [ $# -gt 0 ]; do
  case "$1" in
    --install) DO_INSTALL=1 ;;
    --write-marker) WRITE_MARKER="${2:?--write-marker needs a directory}"; shift ;;
    --listen) DO_LISTEN=1 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

if [ "$(id -u)" -ne 0 ]; then echo "run as root (sudo)" >&2; exit 1; fi

log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }

# ── install (opt-in) ──────────────────────────────────────────────────────────
if ! command -v psql >/dev/null 2>&1; then
  if [ "$DO_INSTALL" -eq 1 ]; then
    log "Installing PostgreSQL…"
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql postgresql-contrib
  else
    echo "PostgreSQL is not installed. Re-run with --install, or install it first." >&2
    exit 1
  fi
fi
systemctl enable --now postgresql >/dev/null 2>&1 || true

# ── port (auto-detect; the DSN we hand back must be right or every connection
# from the app just hangs on a non-listening/wrong-protocol port instead of
# failing fast — confirmed live) ───────────────────────────────────────────────
# Multiple local Postgres server processes (e.g. a leftover default instance
# on 5432 alongside the real one on a custom port) each get their own
# peer-auth socket, named after THEIR OWN port. A bare `sudo -u postgres
# psql` with no -p only ever reaches the socket for the CLIENT default port
# (5432) — on a multi-instance box that can be a totally different server
# than the one the operator actually means. Confirmed live: auto-detect
# picked one instance's port, but every subsequent role/database call below
# (before this fix) ran unpinned and landed on the *other*, 5432 one — so the
# DSN pointed at 5433 while the role only ever existed on 5432, and every app
# connection failed auth even right after a successful ALTER ROLE.
if [ -z "$RP_DB_PORT" ]; then
  RP_DB_PORT="$(sudo -u postgres psql -tAc 'SHOW port' 2>/dev/null | tr -d '[:space:]')"
  if [ -z "$RP_DB_PORT" ]; then
    RP_DB_PORT=5432
    log "Could not auto-detect the Postgres port — defaulting to 5432 (set RP_DB_PORT to override)."
  else
    log "Detected Postgres listening on port ${RP_DB_PORT}."
  fi
fi
if [ "$(ls /var/run/postgresql/.s.PGSQL.* 2>/dev/null | wc -l)" -gt 1 ]; then
  log "WARNING: multiple local Postgres sockets found — this box is running more"
  log "  than one Postgres server. Auto-detect picked port ${RP_DB_PORT}; if that's"
  log "  not the instance you mean, re-run with RP_DB_PORT=<port> set explicitly."
fi

# ── password ──────────────────────────────────────────────────────────────────
GENERATED=0
if [ -z "$RP_DB_PASS" ]; then
  RP_DB_PASS="$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)"
  GENERATED=1
fi

# Every peer-auth call from here on is pinned to -p "$RP_DB_PORT" — it MUST be
# the same instance the DSN we hand back will connect to over TCP, or role/db
# creation silently lands on a different local Postgres server (see above).
psql_su() { sudo -u postgres psql -p "$RP_DB_PORT" -v ON_ERROR_STOP=1 -tAc "$1"; }

# ── role (idempotent) ──────────────────────────────────────────────────────────
if [ "$(psql_su "SELECT 1 FROM pg_roles WHERE rolname='${RP_DB_USER}'")" = "1" ]; then
  log "Role '${RP_DB_USER}' exists — updating its password."
  # quote the password safely via a parameterised DO block
  sudo -u postgres psql -p "$RP_DB_PORT" -v ON_ERROR_STOP=1 -c \
    "ALTER ROLE \"${RP_DB_USER}\" WITH LOGIN PASSWORD '$(printf "%s" "$RP_DB_PASS" | sed "s/'/''/g")';" >/dev/null
else
  log "Creating role '${RP_DB_USER}'."
  sudo -u postgres psql -p "$RP_DB_PORT" -v ON_ERROR_STOP=1 -c \
    "CREATE ROLE \"${RP_DB_USER}\" WITH LOGIN PASSWORD '$(printf "%s" "$RP_DB_PASS" | sed "s/'/''/g")';" >/dev/null
fi

# ── database (idempotent) ───────────────────────────────────────────────────────
if [ "$(psql_su "SELECT 1 FROM pg_database WHERE datname='${RP_DB_NAME}'")" = "1" ]; then
  log "Database '${RP_DB_NAME}' already exists."
else
  log "Creating database '${RP_DB_NAME}' owned by '${RP_DB_USER}'."
  sudo -u postgres createdb -p "$RP_DB_PORT" -O "${RP_DB_USER}" "${RP_DB_NAME}"
fi
# RemotePower creates its own tables on first connect; just ensure connect/usage.
psql_su "GRANT ALL PRIVILEGES ON DATABASE \"${RP_DB_NAME}\" TO \"${RP_DB_USER}\"" >/dev/null

# ── optional: listen on the LAN for multi-node app servers ──────────────────────
if [ "$DO_LISTEN" -eq 1 ]; then
  PGCONF="$(sudo -u postgres psql -p "$RP_DB_PORT" -tAc 'SHOW config_file')"
  PGHBA="$(sudo -u postgres psql -p "$RP_DB_PORT" -tAc 'SHOW hba_file')"
  log "Opening listen_addresses (edit ${PGCONF} / ${PGHBA} to scope to your app subnet!)."
  if ! grep -qE "^listen_addresses *= *'\*'" "$PGCONF"; then
    echo "listen_addresses = '*'   # RemotePower: scope this down in production" >> "$PGCONF"
  fi
  if ! grep -q "RemotePower app nodes" "$PGHBA"; then
    cat >> "$PGHBA" <<EOF
# RemotePower app nodes — TIGHTEN this CIDR to your app subnet, use scram + TLS.
host    ${RP_DB_NAME}    ${RP_DB_USER}    10.0.0.0/8    scram-sha-256
EOF
  fi
  systemctl reload postgresql || systemctl restart postgresql
fi

# ── DSN + marker ────────────────────────────────────────────────────────────────
DSN="postgresql://${RP_DB_USER}:${RP_DB_PASS}@localhost:${RP_DB_PORT}/${RP_DB_NAME}"

if [ -n "$WRITE_MARKER" ]; then
  mkdir -p "$WRITE_MARKER"
  MARKER="${WRITE_MARKER%/}/storage_backend.json"
  log "Writing storage marker ${MARKER} (chmod 600)."
  cat > "$MARKER" <<EOF
{ "backend": "postgres", "dsn": "${DSN}" }
EOF
  chmod 600 "$MARKER"
  echo "   → this only points a local install at this DB — it does NOT migrate data."
  echo "     Migrate existing data with:  Settings → Advanced → Storage backend → Migrate"
  echo "     (tools/migrate_storage.py only covers json<->sqlite, not postgres)"
fi

echo
log "PostgreSQL backend ready."
echo "   Database : ${RP_DB_NAME}"
echo "   Role     : ${RP_DB_USER}"
if [ "$GENERATED" -eq 1 ]; then
  echo "   Password : ${RP_DB_PASS}     <-- generated, store it now (shown once)"
fi
echo
echo "   DSN (set RP_PG_DSN or the storage marker's \"dsn\"):"
echo "     ${DSN}"
echo
echo "   For HA, point the DSN at every node, e.g.:"
echo "     postgresql://${RP_DB_USER}:****@pg-primary,pg-standby:${RP_DB_PORT}/${RP_DB_NAME}"
echo "   then run postgres-ha-primary.sh (here) and postgres-ha-standby.sh (standby)."

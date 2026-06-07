#!/bin/bash
# satellite-setup.sh — install the RemotePower relay satellite as a systemd
# service. A satellite lets agents in a segmented network reach the central
# server through it:  agent ──(https)──▶ satellite ──https──▶ server.
#
# Mint a satellite token first: Settings → Integrations → Satellites → New.
#
# Usage:
#   sudo RP_UPSTREAM=https://remote.example.com RP_SATELLITE_TOKEN='…' \
#        bash packaging/satellite-setup.sh
#   # with TLS on the agent→satellite hop (recommended):
#   sudo RP_UPSTREAM=… RP_SATELLITE_TOKEN='…' \
#        RP_TLS_CERT=/etc/ssl/sat.crt RP_TLS_KEY=/etc/ssl/sat.key \
#        bash packaging/satellite-setup.sh
#   # quick internal TLS with a self-signed cert (agents must trust it via RP_CA_BUNDLE):
#   sudo RP_UPSTREAM=… RP_SATELLITE_TOKEN='…' --self-signed sat.lan \
#        bash packaging/satellite-setup.sh
#
# Env / flags:
#   RP_UPSTREAM          central server base URL (https)        [required]
#   RP_SATELLITE_TOKEN   token minted in the UI                 [required]
#   RP_LISTEN            listen addr (default 0.0.0.0:8800)
#   RP_TLS_CERT/RP_TLS_KEY  PEM cert+key → HTTPS on the agent hop
#   RP_UPSTREAM_INSECURE 1 to skip upstream TLS verify (self-signed server)
#   --self-signed CN     generate a self-signed cert for CN into /etc/remotepower/

set -euo pipefail

RP_UPSTREAM="${RP_UPSTREAM:-}"
RP_SATELLITE_TOKEN="${RP_SATELLITE_TOKEN:-}"
RP_LISTEN="${RP_LISTEN:-0.0.0.0:8800}"
RP_TLS_CERT="${RP_TLS_CERT:-}"
RP_TLS_KEY="${RP_TLS_KEY:-}"
RP_UPSTREAM_INSECURE="${RP_UPSTREAM_INSECURE:-}"
SELF_SIGNED_CN=""

while [ $# -gt 0 ]; do
  case "$1" in
    --self-signed) SELF_SIGNED_CN="${2:?--self-signed needs a CN/hostname}"; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)" >&2; exit 1; }
[ -n "$RP_UPSTREAM" ] || { echo "set RP_UPSTREAM=https://your-server" >&2; exit 2; }
[ -n "$RP_SATELLITE_TOKEN" ] || { echo "set RP_SATELLITE_TOKEN=<minted token>" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 required" >&2; exit 1; }
log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }

SRC="$(cd "$(dirname "$0")/.." && pwd)/client/remotepower-satellite.py"
[ -f "$SRC" ] || { echo "cannot find client/remotepower-satellite.py" >&2; exit 1; }

install -d -m 0755 /opt/remotepower
install -m 0755 "$SRC" /opt/remotepower/remotepower-satellite.py
install -d -m 0750 /etc/remotepower

# ── optional self-signed cert ───────────────────────────────────────────────────
if [ -n "$SELF_SIGNED_CN" ]; then
  RP_TLS_CERT=/etc/remotepower/satellite.crt
  RP_TLS_KEY=/etc/remotepower/satellite.key
  if [ ! -f "$RP_TLS_CERT" ]; then
    log "Generating self-signed cert for CN=${SELF_SIGNED_CN}"
    openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
      -keyout "$RP_TLS_KEY" -out "$RP_TLS_CERT" \
      -subj "/CN=${SELF_SIGNED_CN}" \
      -addext "subjectAltName=DNS:${SELF_SIGNED_CN}" >/dev/null 2>&1
    chmod 640 "$RP_TLS_KEY"
    echo "   → distribute ${RP_TLS_CERT} to agents as RP_CA_BUNDLE (they must trust it)."
  fi
fi

# ── systemd unit + env file ──────────────────────────────────────────────────────
ENVF=/etc/remotepower/satellite.env
log "Writing ${ENVF} (0640)."
{
  echo "RP_UPSTREAM=${RP_UPSTREAM}"
  echo "RP_SATELLITE_TOKEN=${RP_SATELLITE_TOKEN}"
  echo "RP_LISTEN=${RP_LISTEN}"
  [ -n "$RP_TLS_CERT" ] && echo "RP_TLS_CERT=${RP_TLS_CERT}"
  [ -n "$RP_TLS_KEY" ]  && echo "RP_TLS_KEY=${RP_TLS_KEY}"
  [ -n "$RP_UPSTREAM_INSECURE" ] && echo "RP_UPSTREAM_INSECURE=${RP_UPSTREAM_INSECURE}"
} > "$ENVF"
chmod 640 "$ENVF"

# dedicated unprivileged user
id remotepower-sat >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin remotepower-sat
chgrp remotepower-sat "$ENVF" "$RP_TLS_KEY" 2>/dev/null || true

log "Installing systemd unit remotepower-satellite.service"
cat > /etc/systemd/system/remotepower-satellite.service <<EOF
[Unit]
Description=RemotePower relay satellite
After=network-online.target
Wants=network-online.target

[Service]
User=remotepower-sat
EnvironmentFile=${ENVF}
ExecStart=/usr/bin/python3 /opt/remotepower/remotepower-satellite.py
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadOnlyPaths=/etc/remotepower

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now remotepower-satellite.service

sleep 1
SCHEME=http; [ -n "$RP_TLS_CERT" ] && SCHEME=https
echo
log "Satellite running."
echo "   Listening : ${SCHEME}://${RP_LISTEN}  →  ${RP_UPSTREAM}"
echo "   Status    : systemctl status remotepower-satellite"
echo "   Health    : curl -k ${SCHEME}://127.0.0.1:${RP_LISTEN##*:}/satellite/health"
echo
echo "   Point this segment's agents at:  ${SCHEME}://<this-host>:${RP_LISTEN##*:}"
if [ "$SCHEME" = "http" ]; then
  echo "   (plaintext — set RP_TLS_CERT/RP_TLS_KEY or --self-signed to encrypt the hop)"
else
  echo "   Agents must trust the satellite cert (RP_CA_BUNDLE=/path/to/ca.crt, or OS trust store)."
fi

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
#   --self-signed CN     generate a self-signed cert for CN into /etc/remotepower-satellite/

# -h / --help prints the comment block above and exits, before anything is checked or changed (so it needs no root).
for _a in "$@"; do case "$_a" in -h|--help) [ -r "$0" ] && awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0 ;; esac; done

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

# The relay runs as its own account, so its settings, key and certificate live in a directory that account can reach. They used to
# go into /etc/remotepower (root:root 0750, and the host agent resets it to 0700), where the service could not read its own key.
id remotepower-sat >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin remotepower-sat
CONF=/etc/remotepower-satellite
install -d -m 0750 -o root -g remotepower-sat "$CONF"

# ── optional self-signed cert ───────────────────────────────────────────────────
if [ -n "$SELF_SIGNED_CN" ]; then
  RP_TLS_CERT="$CONF/satellite.crt"
  RP_TLS_KEY="$CONF/satellite.key"
  if [ ! -f "$RP_TLS_CERT" ]; then
    log "Generating self-signed cert for CN=${SELF_SIGNED_CN}"
    openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
      -keyout "$RP_TLS_KEY" -out "$RP_TLS_CERT" \
      -subj "/CN=${SELF_SIGNED_CN}" \
      -addext "subjectAltName=DNS:${SELF_SIGNED_CN}" >/dev/null 2>&1
    chmod 640 "$RP_TLS_KEY"
    chgrp remotepower-sat "$RP_TLS_KEY"
    echo "   → distribute ${RP_TLS_CERT} to agents as RP_CA_BUNDLE (they must trust it)."
  fi
fi

# ── systemd unit + env file ──────────────────────────────────────────────────────
ENVF="$CONF/satellite.env"
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
chgrp remotepower-sat "$ENVF"

# No capabilities, except the one that lets an unprivileged account listen below port 1024 when you asked for one.
CAPS=""
[ "${RP_LISTEN##*:}" -lt 1024 ] 2>/dev/null && CAPS="CAP_NET_BIND_SERVICE"

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
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=${CAPS}
AmbientCapabilities=${CAPS}
ReadOnlyPaths=${CONF}

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

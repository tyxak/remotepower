#!/bin/bash
# scanner-setup.sh — install the RemotePower scanner satellite as a systemd
# service. A scanner satellite polls the central server for queued Security →
# Pentest scan jobs (nuclei/nikto/nmap/zap/wapiti) and runs them:
#   scanner ──(poll /api/scans/claim)──▶ server
#
# Two ways to run this:
#   1. Standalone, on a dedicated scanner box (recommended by
#      docs/security-scans.md — keeps the scanning tools off production
#      hosts): mint a token in the UI first (Settings → API Keys, then
#      POST /api/satellites with {"scanner":true}), then:
#        sudo RP_SERVER_URL=https://remote.example.com \
#             RP_SATELLITE_TOKEN='…' bash packaging/scanner-setup.sh
#   2. Co-located on the server node itself (the --mint-local path used by
#      install-server.sh's --with-scanner, i.e. the single-node "enterprise"
#      default): mints its own token by writing directly into the server's
#      satellites.json (mirrors how install-server.sh creates the initial
#      admin user directly in users.json), and points at the local server
#      over loopback. This trades the doc's recommended isolation (the
#      scanning tools run on the production box, and RP_SCAN_RUNNER=docker
#      needs the scanner user in the `docker` group, which is effectively
#      root-equivalent) for a one-command all-in-one install. Prefer option 1
#      for anything beyond a lab/small-fleet install.
#
# Env / flags:
#   RP_SERVER_URL        central server base URL                [required, unless --mint-local]
#   RP_SATELLITE_TOKEN   token minted in the UI                 [required, unless --mint-local]
#   RP_DATA_DIR           server data dir (--mint-local only, default /var/lib/remotepower)
#   RP_SCAN_RUNNER        'docker' (default) | 'podman' | 'nuclei' (local binary)
#   --mint-local          mint a scanner token directly into RP_DATA_DIR/satellites.json
#                         and default RP_SERVER_URL to http://127.0.0.1

set -euo pipefail

RP_SERVER_URL="${RP_SERVER_URL:-}"
RP_SATELLITE_TOKEN="${RP_SATELLITE_TOKEN:-}"
RP_DATA_DIR="${RP_DATA_DIR:-/var/lib/remotepower}"
RP_SCAN_RUNNER="${RP_SCAN_RUNNER:-docker}"
MINT_LOCAL=0

while [ $# -gt 0 ]; do
  case "$1" in
    --mint-local) MINT_LOCAL=1 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 required" >&2; exit 1; }
log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }

SRC="$(cd "$(dirname "$0")/.." && pwd)/client/remotepower-scanner.py"
[ -f "$SRC" ] || { echo "cannot find client/remotepower-scanner.py" >&2; exit 1; }

if [ "$MINT_LOCAL" = "1" ]; then
    RP_SERVER_URL="${RP_SERVER_URL:-http://127.0.0.1}"
    if [ -z "$RP_SATELLITE_TOKEN" ]; then
        log "Minting a local scanner token into ${RP_DATA_DIR}/satellites.json"
        RP_SATELLITE_TOKEN="$(RP_DATA_DIR="$RP_DATA_DIR" python3 - <<'PYEOF'
import json, os, time, secrets, hashlib
from pathlib import Path

data_dir = Path(os.environ['RP_DATA_DIR'])
data_dir.mkdir(parents=True, exist_ok=True)
sats_path = data_dir / 'satellites.json'
sats = json.loads(sats_path.read_text()) if sats_path.exists() else {}

token = secrets.token_urlsafe(32)
sid = secrets.token_hex(8)
sats[sid] = {
    'name': 'local-scanner',
    'token_hash': hashlib.sha256(token.encode('utf-8')).hexdigest(),
    'created': int(time.time()),
    'last_seen': None,
    'last_ip': '',
    'scanner': True,
}
sats_path.write_text(json.dumps(sats, indent=2))
print(token)
PYEOF
)"
    fi
fi

[ -n "$RP_SERVER_URL" ]      || { echo "set RP_SERVER_URL=https://your-server (or pass --mint-local)" >&2; exit 2; }
[ -n "$RP_SATELLITE_TOKEN" ] || { echo "set RP_SATELLITE_TOKEN=<minted token> (or pass --mint-local)" >&2; exit 2; }

install -d -m 0755 /opt/remotepower
install -m 0755 "$SRC" /opt/remotepower/remotepower-scanner.py
install -d -m 0750 /etc/remotepower

if ! command -v docker >/dev/null 2>&1 && ! command -v podman >/dev/null 2>&1; then
    if [ "$RP_SCAN_RUNNER" = "docker" ] || [ "$RP_SCAN_RUNNER" = "podman" ]; then
        if command -v nuclei >/dev/null 2>&1; then
            warn "no docker/podman found — falling back to RP_SCAN_RUNNER=nuclei (local binary)"
            RP_SCAN_RUNNER=nuclei
        else
            warn "no docker/podman/nuclei found — scanner will install but scan jobs will fail"
            warn "  until one is available (install Docker, or a scan-tool binary + RP_SCAN_RUNNER=<name>)"
        fi
    fi
fi
if [ "$MINT_LOCAL" = "1" ]; then
    warn "Scanner satellite is co-located with the server (single-node install)."
    warn "  docs/security-scans.md recommends a separate machine for this — the"
    warn "  scanning tools are heavy/security-sensitive, and RP_SCAN_RUNNER=docker"
    warn "  needs docker-group membership (effectively root-equivalent). Re-run"
    warn "  install-server.sh with --no-scanner and see docs/security-scans.md to"
    warn "  set one up on its own box instead."
fi

# ── systemd unit + env file ──────────────────────────────────────────────────────
ENVF=/etc/remotepower/scanner.env
log "Writing ${ENVF} (0640)."
{
  echo "RP_SERVER_URL=${RP_SERVER_URL}"
  echo "RP_SATELLITE_TOKEN=${RP_SATELLITE_TOKEN}"
  echo "RP_SCAN_RUNNER=${RP_SCAN_RUNNER}"
} > "$ENVF"
chmod 640 "$ENVF"

# dedicated unprivileged user (added to `docker` group only when that's the runner)
id remotepower-scan >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin remotepower-scan
chgrp remotepower-scan "$ENVF"
if [ "$RP_SCAN_RUNNER" = "docker" ] && getent group docker >/dev/null 2>&1; then
    usermod -aG docker remotepower-scan
fi

log "Installing systemd unit remotepower-scanner.service"
cat > /etc/systemd/system/remotepower-scanner.service <<EOF
[Unit]
Description=RemotePower scanner satellite
After=network-online.target docker.service
Wants=network-online.target

[Service]
User=remotepower-scan
EnvironmentFile=${ENVF}
ExecStart=/usr/bin/python3 /opt/remotepower/remotepower-scanner.py
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true
ReadOnlyPaths=/etc/remotepower

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now remotepower-scanner.service \
    && log "Scanner satellite running — check: systemctl status remotepower-scanner" \
    || warn "Could not start remotepower-scanner — check: systemctl status remotepower-scanner"

echo
log "Scanner satellite installed."
echo "   Upstream : ${RP_SERVER_URL}"
echo "   Runner   : ${RP_SCAN_RUNNER}"
echo "   Status   : systemctl status remotepower-scanner"
echo "   Use it   : Security → Pentest in the UI, pick a device + tool, Queue scan."

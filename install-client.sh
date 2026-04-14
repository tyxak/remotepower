#!/usr/bin/env bash
# RemotePower — Client installer
# Run as root on each machine you want to be able to shut down remotely
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
die()     { echo -e "${RED}[✗]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && die "Run as root: sudo bash install-client.sh"

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   RemotePower Client Installer               ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Install agent ────────────────────────────────────────────────────────────────
info "Installing agent..."
install -m 755 "$SCRIPT_DIR/client/remotepower-agent" /usr/local/bin/remotepower-agent
install -m 644 "$SCRIPT_DIR/client/remotepower-agent.service" /etc/systemd/system/remotepower-agent.service
mkdir -p /etc/remotepower
success "Agent installed"

# ── Enrollment ──────────────────────────────────────────────────────────────────
info "Starting enrollment wizard..."
echo ""
/usr/local/bin/remotepower-agent enroll
echo ""

# ── Enable service ───────────────────────────────────────────────────────────────
info "Enabling systemd service..."
systemctl daemon-reload
systemctl enable --now remotepower-agent
success "Service enabled and started"

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   Client installed!                          ║"
echo "╚══════════════════════════════════════════════╝"
echo ""
echo "  Status:   systemctl status remotepower-agent"
echo "  Logs:     journalctl -u remotepower-agent -f"
echo "  Re-enroll: remotepower-agent enroll"
echo ""

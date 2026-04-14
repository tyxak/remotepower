#!/usr/bin/env bash
# RemotePower — Server installer
# Run as root on the Nginx server
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
die()     { echo -e "${RED}[✗]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && die "Run as root: sudo bash install-server.sh"

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   RemotePower Server Installer               ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# ── Dependencies ────────────────────────────────────────────────────────────────
info "Installing dependencies..."
apt-get update -qq
apt-get install -y nginx fcgiwrap python3 python3-pip --no-install-recommends
success "Dependencies installed"

# ── Directories ─────────────────────────────────────────────────────────────────
info "Creating directories..."
install -d -m 755 /var/www/remotepower/cgi-bin
install -d -m 700 /var/lib/remotepower
chown www-data:www-data /var/lib/remotepower
success "Directories created"

# ── Copy files ──────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

info "Installing web files..."
cp "$SCRIPT_DIR/server/html/index.html" /var/www/remotepower/index.html
install -m 755 "$SCRIPT_DIR/server/cgi-bin/api.py" /var/www/remotepower/cgi-bin/api.py
success "Web files installed"

# ── Nginx config ────────────────────────────────────────────────────────────────
info "Configuring Nginx..."
cp "$SCRIPT_DIR/server/conf/remotepower.conf" /etc/nginx/sites-available/remotepower

# Ask for domain/IP
read -rp "  Enter server IP or domain (default: _): " SERVER_HOST
SERVER_HOST="${SERVER_HOST:-_}"
sed -i "s/server_name _;/server_name ${SERVER_HOST};/" /etc/nginx/sites-available/remotepower

ln -sf /etc/nginx/sites-available/remotepower /etc/nginx/sites-enabled/remotepower
# Disable default site if present
rm -f /etc/nginx/sites-enabled/default

nginx -t && systemctl reload nginx
success "Nginx configured"

# ── fcgiwrap ────────────────────────────────────────────────────────────────────
info "Starting fcgiwrap..."
systemctl enable --now fcgiwrap fcgiwrap.socket 2>/dev/null || true
# Make sure Nginx can reach the socket
if [[ -S /run/fcgiwrap.socket ]]; then
    chmod 660 /run/fcgiwrap.socket
    chown www-data:www-data /run/fcgiwrap.socket 2>/dev/null || \
      usermod -aG www-data fcgiwrap
fi
success "fcgiwrap running"

# ── Set admin password ───────────────────────────────────────────────────────────
echo ""
info "Setting admin password..."
read -rp "  Admin username [admin]: " ADMIN_USER
ADMIN_USER="${ADMIN_USER:-admin}"
read -srp "  Admin password: " ADMIN_PASS
echo ""

HASH=$(python3 -c "import hashlib; print(hashlib.sha256('${ADMIN_PASS}'.encode()).hexdigest())")
python3 - <<EOF
import json, time
from pathlib import Path
path = Path('/var/lib/remotepower/users.json')
users = json.loads(path.read_text()) if path.exists() else {}
users['${ADMIN_USER}'] = {'password_hash': '${HASH}', 'created': int(time.time())}
path.write_text(json.dumps(users, indent=2))
print("  User saved.")
EOF
chown www-data:www-data /var/lib/remotepower/users.json

success "Admin user '${ADMIN_USER}' created"

# ── Summary ─────────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   Installation complete!                     ║"
echo "╚══════════════════════════════════════════════╝"
echo ""
echo "  Dashboard: http://${SERVER_HOST}/"
echo "  Logs:      journalctl -u nginx -f"
echo "             tail -f /var/log/nginx/remotepower_*.log"
echo ""
echo "  Next: Install the client on each machine you want to control:"
echo "    sudo bash install-client.sh"
echo ""

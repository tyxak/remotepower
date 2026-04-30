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

# ── Detect distro ───────────────────────────────────────────────────────────────
if   command -v apt-get &>/dev/null; then PKG_MGR=apt
elif command -v dnf     &>/dev/null; then PKG_MGR=dnf
elif command -v pacman  &>/dev/null; then PKG_MGR=pacman
else die "Unsupported distro — install nginx, fcgiwrap, python3 manually then re-run."
fi
info "Detected package manager: ${PKG_MGR}"

# ── Dependencies ────────────────────────────────────────────────────────────────
info "Installing dependencies..."
case $PKG_MGR in
  apt)
    apt-get update -qq
    apt-get install -y nginx fcgiwrap python3 python3-pip --no-install-recommends
    ;;
  dnf)
    dnf install -y -q nginx fcgiwrap python3 python3-pip
    ;;
  pacman)
    pacman -Sy --noconfirm --noprogressbar nginx fcgiwrap python python-pip
    ;;
esac
success "Dependencies installed"

# ── bcrypt ──────────────────────────────────────────────────────────────────────
info "Installing bcrypt for password hashing..."
if python3 -c "import bcrypt" 2>/dev/null; then
    success "bcrypt already available"
else
    case $PKG_MGR in
      apt)    pip3 install bcrypt --break-system-packages 2>/dev/null \
                || pip3 install bcrypt || warn "bcrypt install failed — SHA-256 fallback will be used" ;;
      dnf)    pip3 install bcrypt || warn "bcrypt install failed — SHA-256 fallback will be used" ;;
      pacman) pip install bcrypt  || warn "bcrypt install failed — SHA-256 fallback will be used" ;;
    esac
    python3 -c "import bcrypt" 2>/dev/null \
      && success "bcrypt installed" \
      || warn "bcrypt unavailable — passwords will use SHA-256 (upgrade later with: pip3 install bcrypt)"
fi

# ── reportlab (for PDF patch reports) ────────────────────────────────────────
info "Installing reportlab for PDF patch reports..."
if python3 -c "import reportlab" 2>/dev/null; then
    success "reportlab already available"
else
    case $PKG_MGR in
      apt)    pip3 install reportlab --break-system-packages 2>/dev/null \
                || pip3 install reportlab || warn "reportlab install failed — PDF export will be unavailable" ;;
      dnf)    pip3 install reportlab || warn "reportlab install failed — PDF export will be unavailable" ;;
      pacman) pip install reportlab  || warn "reportlab install failed — PDF export will be unavailable" ;;
    esac
    python3 -c "import reportlab" 2>/dev/null \
      && success "reportlab installed" \
      || warn "reportlab unavailable — install later with: pip3 install reportlab"
fi

# ── cryptography (for v1.9.0 CMDB credential vault) ──────────────────────────
info "Installing cryptography for the CMDB credential vault..."
if python3 -c "import cryptography" 2>/dev/null; then
    success "cryptography already available"
else
    case $PKG_MGR in
      apt)    pip3 install cryptography --break-system-packages 2>/dev/null \
                || pip3 install cryptography \
                || apt-get install -y python3-cryptography \
                || warn "cryptography install failed — CMDB credential storage will be unavailable" ;;
      dnf)    pip3 install cryptography 2>/dev/null \
                || dnf install -y python3-cryptography \
                || warn "cryptography install failed — CMDB credential storage will be unavailable" ;;
      pacman) pip install cryptography 2>/dev/null \
                || pacman -S --noconfirm python-cryptography \
                || warn "cryptography install failed — CMDB credential storage will be unavailable" ;;
    esac
    python3 -c "import cryptography" 2>/dev/null \
      && success "cryptography installed" \
      || warn "cryptography unavailable — CMDB asset metadata will work but credentials cannot be stored"
fi

# ── dnspython (for v1.11.2 DANE/TLSA checks) ────────────────────────────────────
info "Installing dnspython for the DANE/TLSA checker..."
if python3 -c "import dns.resolver" 2>/dev/null; then
    success "dnspython already available"
else
    case $PKG_MGR in
      apt)    pip3 install dnspython --break-system-packages 2>/dev/null \
                || pip3 install dnspython \
                || apt-get install -y python3-dnspython \
                || warn "dnspython install failed — DANE checks will be unavailable" ;;
      dnf)    pip3 install dnspython 2>/dev/null \
                || dnf install -y python3-dns \
                || warn "dnspython install failed — DANE checks will be unavailable" ;;
      pacman) pip install dnspython 2>/dev/null \
                || pacman -S --noconfirm python-dnspython \
                || warn "dnspython install failed — DANE checks will be unavailable" ;;
    esac
    python3 -c "import dns.resolver" 2>/dev/null \
      && success "dnspython installed" \
      || warn "dnspython unavailable — TLS expiry monitor still works, only DANE checks need it"
fi

# ── Nginx user (differs by distro) ──────────────────────────────────────────────
case $PKG_MGR in
  apt)    NGINX_USER=www-data ;;
  dnf)    NGINX_USER=nginx    ;;
  pacman) NGINX_USER=http     ;;
esac

# ── Directories ─────────────────────────────────────────────────────────────────
info "Creating directories..."
install -d -m 755 /var/www/remotepower/cgi-bin
install -d -m 755 /var/www/remotepower/agent      # agent binary for self-update
install -d -m 700 /var/lib/remotepower
chown "${NGINX_USER}:${NGINX_USER}" /var/lib/remotepower
success "Directories created"

# ── Copy files ──────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

info "Installing web files..."
# Auto-discover all HTML pages — keeps this in sync when new ones are added.
for f in "$SCRIPT_DIR"/server/html/*.html; do
    name="$(basename "$f")"
    cp "$f" /var/www/remotepower/"$name"
done
# Auto-discover all cgi-bin Python modules (api.py plus siblings: cve_scanner,
# cmdb_vault, prometheus_export, openapi_spec, containers, tls_monitor, ...).
# api.py needs +x for CGI; others are imports so 644 is fine.
for f in "$SCRIPT_DIR"/server/cgi-bin/*.py; do
    name="$(basename "$f")"
    if [[ "$name" == "api.py" ]]; then
        install -m 755 "$f" /var/www/remotepower/cgi-bin/"$name"
    else
        install -m 644 "$f" /var/www/remotepower/cgi-bin/"$name"
    fi
done
# v1.11.0: extension-less helper scripts (cron runners, etc.)
for helper in remotepower-tls-check; do
    src="$SCRIPT_DIR/server/cgi-bin/$helper"
    if [[ -f "$src" ]]; then
        install -m 755 "$src" /var/www/remotepower/cgi-bin/"$helper"
    fi
done
install -m 755 "$SCRIPT_DIR/server/remotepower-passwd" /var/www/remotepower/cgi-bin/remotepower-passwd
success "Web files installed"

# ── Agent binary for self-update ────────────────────────────────────────────────
info "Publishing agent binary for self-update..."
install -m 755 "$SCRIPT_DIR/client/remotepower-agent" /var/www/remotepower/agent/remotepower-agent
# Write initial version into config.json
python3 - <<'PYEOF'
import json, re
from pathlib import Path

agent = Path('/var/www/remotepower/agent/remotepower-agent').read_text()
m = re.search(r"VERSION\s*=\s*['\"]([^'\"]+)['\"]", agent)
version = m.group(1) if m else 'unknown'

cfg_path = Path('/var/lib/remotepower/config.json')
cfg = json.loads(cfg_path.read_text()) if cfg_path.exists() else {}
cfg['agent_version'] = version
cfg_path.write_text(json.dumps(cfg, indent=2))
print(f"  Agent version set to: {version}")
PYEOF
success "Agent published"

# ── Nginx config ────────────────────────────────────────────────────────────────
info "Configuring Nginx..."
if [[ -f /etc/nginx/sites-available/remotepower ]]; then
    warn "Nginx config already exists — skipping (edit /etc/nginx/sites-available/remotepower manually)"
else
    cp "$SCRIPT_DIR/server/conf/remotepower.conf" /etc/nginx/sites-available/remotepower

    read -rp "  Enter server IP or domain (default: _): " SERVER_HOST
    SERVER_HOST="${SERVER_HOST:-_}"
    sed -i "s/server_name _;/server_name ${SERVER_HOST};/" /etc/nginx/sites-available/remotepower

    # Enable site
    case $PKG_MGR in
      apt|dnf)
        ln -sf /etc/nginx/sites-available/remotepower /etc/nginx/sites-enabled/remotepower
        rm -f /etc/nginx/sites-enabled/default
        ;;
      pacman)
        # Arch uses include in nginx.conf directly — symlink into conf.d
        mkdir -p /etc/nginx/conf.d
        ln -sf /etc/nginx/sites-available/remotepower /etc/nginx/conf.d/remotepower.conf
        ;;
    esac
fi

nginx -t && systemctl reload nginx
success "Nginx configured"

# ── fcgiwrap ────────────────────────────────────────────────────────────────────
info "Starting fcgiwrap..."
systemctl enable --now fcgiwrap fcgiwrap.socket 2>/dev/null || \
  systemctl enable --now fcgiwrap 2>/dev/null || \
  warn "Could not auto-start fcgiwrap — check: systemctl status fcgiwrap"

# Socket permissions so Nginx can reach it
FCGI_SOCK=/run/fcgiwrap.socket
if [[ -S $FCGI_SOCK ]]; then
    chmod 660 "$FCGI_SOCK"
    chown "${NGINX_USER}:${NGINX_USER}" "$FCGI_SOCK" 2>/dev/null || \
      usermod -aG "${NGINX_USER}" fcgiwrap
fi
success "fcgiwrap running"

# ── Admin user ──────────────────────────────────────────────────────────────────
echo ""
info "Creating admin user..."
read -rp "  Admin username [admin]: " ADMIN_USER
ADMIN_USER="${ADMIN_USER:-admin}"
read -srp "  Admin password: " ADMIN_PASS
echo ""

# Use bcrypt if available, fall back to SHA-256 — matches api.py logic exactly
python3 - <<PYEOF
import json, time, hashlib
from pathlib import Path

try:
    import bcrypt
    pw_hash = bcrypt.hashpw('${ADMIN_PASS}'.encode(), bcrypt.gensalt(12)).decode()
    hash_type = 'bcrypt'
except ImportError:
    pw_hash = hashlib.sha256('${ADMIN_PASS}'.encode()).hexdigest()
    hash_type = 'sha256'

path = Path('/var/lib/remotepower/users.json')
users = json.loads(path.read_text()) if path.exists() else {}
users['${ADMIN_USER}'] = {'password_hash': pw_hash, 'created': int(time.time())}
path.write_text(json.dumps(users, indent=2))
print(f"  User saved (hash: {hash_type}).")
PYEOF

chown "${NGINX_USER}:${NGINX_USER}" /var/lib/remotepower/users.json
success "Admin user '${ADMIN_USER}' created"

# ── Summary ─────────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   Installation complete!                     ║"
echo "╚══════════════════════════════════════════════╝"
echo ""
echo "  Dashboard: http://${SERVER_HOST:-localhost}/"
echo "  Logs:      journalctl -u nginx -f"
echo "             tail -f /var/log/nginx/remotepower_*.log"
echo ""
echo "  User mgmt: python3 /var/www/remotepower/cgi-bin/remotepower-passwd"
echo ""
echo "  Next: Install the client on each machine you want to control:"
echo "    sudo bash install-client.sh"
echo ""

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

# ── Optional opt-in scaling features (v6.x) — DEFAULT OFF ─────────────────────
# With none of these requested the install below is the standard, unchanged
# nginx + fcgiwrap (CGI) deployment. Each can also be set via an env var so the
# unified wizard (install.sh) and CI can pass them through.
APP_SERVER="${RP_APP_SERVER:-}"          # "wsgi" → persistent gunicorn app tier
WITH_SCHEDULER="${RP_WITH_SCHEDULER:-0}" # 1 → out-of-band maintenance scheduler
WITH_POSTGRES="${RP_WITH_POSTGRES:-0}"   # 1 → provision a PostgreSQL backend

_usage() {
  cat <<EOF
RemotePower server installer

Usage: sudo bash install-server.sh [options]

  --app-server=wsgi   Run the API under a persistent gunicorn WSGI tier
  --with-wsgi         (alias for --app-server=wsgi) — installs gunicorn +
                      remotepower-wsgi.service and points nginx /api/ at
                      http://127.0.0.1:8090 (default deployment stays CGI)
  --with-scheduler    Run the ~33 maintenance sweeps out-of-band — installs
                      remotepower-scheduler.service and sets
                      RP_EXTERNAL_SCHEDULER=1 in /etc/remotepower/api.env
  --with-postgres     Provision a PostgreSQL backend (packaging/postgres-setup.sh)
  -h, --help          Show this help

All three are OPT-IN and default OFF; the standard install is unchanged when
none are given. See docs/wsgi.md and docs/scaling.md.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --app-server=*)   APP_SERVER="${1#*=}" ;;
    --app-server)     APP_SERVER="${2:?--app-server needs a value (wsgi)}"; shift ;;
    --with-wsgi)      APP_SERVER="wsgi" ;;
    --with-scheduler) WITH_SCHEDULER=1 ;;
    --with-postgres)  WITH_POSTGRES=1 ;;
    -h|--help)        _usage; exit 0 ;;
    *) die "Unknown option: $1 (try --help)" ;;
  esac
  shift
done

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
                || pip3 install bcrypt || warn "bcrypt install failed — salted PBKDF2 fallback will be used" ;;
      dnf)    pip3 install bcrypt || warn "bcrypt install failed — salted PBKDF2 fallback will be used" ;;
      pacman) pip install bcrypt  || warn "bcrypt install failed — salted PBKDF2 fallback will be used" ;;
    esac
    python3 -c "import bcrypt" 2>/dev/null \
      && success "bcrypt installed" \
      || warn "bcrypt unavailable — passwords will use salted PBKDF2 (install bcrypt later with: pip3 install bcrypt)"
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

# ── webauthn / py_webauthn (v4.2.0 A1: passkeys; optional) ───────────────────
info "Installing webauthn for passkey / WebAuthn support..."
if python3 -c "import webauthn" 2>/dev/null; then
    success "webauthn already available"
else
    case $PKG_MGR in
      apt)    pip3 install webauthn --break-system-packages 2>/dev/null \
                || pip3 install webauthn || warn "webauthn install failed — passkeys will be unavailable" ;;
      dnf)    pip3 install webauthn || warn "webauthn install failed — passkeys will be unavailable" ;;
      pacman) pip install webauthn  || warn "webauthn install failed — passkeys will be unavailable" ;;
    esac
    python3 -c "import webauthn" 2>/dev/null \
      && success "webauthn installed" \
      || warn "webauthn unavailable — passkeys disabled; install later with: pip3 install webauthn"
fi

# ── pysaml2 + xmlsec1 (v4.2.0 B1: SAML SSO; optional) ────────────────────────
# SAML needs BOTH the pysaml2 library AND the xmlsec1 system binary (pysaml2
# shells out to it for signature verification). Either missing → SAML SSO simply
# reports unavailable; the rest of the app is unaffected.
info "Installing pysaml2 + xmlsec1 for SAML SSO support..."
if ! command -v xmlsec1 >/dev/null 2>&1; then
    case $PKG_MGR in
      apt)    apt-get install -y --no-install-recommends xmlsec1 \
                || warn "xmlsec1 install failed — SAML SSO will be unavailable" ;;
      dnf)    dnf install -y -q xmlsec1 xmlsec1-openssl \
                || warn "xmlsec1 install failed — SAML SSO will be unavailable" ;;
      pacman) pacman -S --noconfirm xmlsec \
                || warn "xmlsec install failed — SAML SSO will be unavailable" ;;
    esac
fi
if python3 -c "import saml2" 2>/dev/null; then
    success "pysaml2 already available"
else
    case $PKG_MGR in
      apt)    pip3 install pysaml2 --break-system-packages 2>/dev/null \
                || pip3 install pysaml2 || warn "pysaml2 install failed — SAML SSO will be unavailable" ;;
      dnf)    pip3 install pysaml2 || warn "pysaml2 install failed — SAML SSO will be unavailable" ;;
      pacman) pip install pysaml2  || warn "pysaml2 install failed — SAML SSO will be unavailable" ;;
    esac
fi
if python3 -c "import saml2" 2>/dev/null && command -v xmlsec1 >/dev/null 2>&1; then
    success "SAML SSO support installed (pysaml2 + xmlsec1)"
else
    warn "SAML SSO unavailable — needs both pysaml2 and the xmlsec1 binary"
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
# v2.4.15: Root-level non-HTML assets (favicon, manifest, service worker, robots.txt).
# The *.html glob above only catches .html files; these must be copied separately.
for f in "$SCRIPT_DIR"/server/html/favicon.* \
         "$SCRIPT_DIR"/server/html/robots.txt \
         "$SCRIPT_DIR"/server/html/manifest.json \
         "$SCRIPT_DIR"/server/html/sw.js; do
    [[ -f "$f" ]] || continue
    install -m 644 "$f" /var/www/remotepower/"$(basename "$f")"
done
# v3.4.0: product Markdown docs into the data dir for the RAG indexer
# (RAG_DOCS_DIR = /var/lib/remotepower/docs).
if compgen -G "$SCRIPT_DIR/docs/*.md" > /dev/null; then
    install -d -m 700 /var/lib/remotepower/docs
    install -m 644 "$SCRIPT_DIR"/docs/*.md /var/lib/remotepower/docs/
    chown -R "${NGINX_USER}:${NGINX_USER}" /var/lib/remotepower/docs
fi
# Also publish docs under the web root so the in-app "Documentation" links
# (href="docs/<name>.md") resolve instead of 404ing.
if compgen -G "$SCRIPT_DIR/docs/*.md" > /dev/null || compgen -G "$SCRIPT_DIR/docs/*.html" > /dev/null; then
    install -d -m 755 /var/www/remotepower/docs
    install -m 644 "$SCRIPT_DIR"/docs/*.md   /var/www/remotepower/docs/ 2>/dev/null || true
    install -m 644 "$SCRIPT_DIR"/docs/*.html /var/www/remotepower/docs/ 2>/dev/null || true
fi
# v2.0: static assets (logos, CSS, JS). rsync is preferred (atomic, handles
# subdirs); fall back to cp -r if rsync is absent on the target machine.
if [[ -d "$SCRIPT_DIR/server/html/static" ]]; then
    install -d -m 755 /var/www/remotepower/static
    if command -v rsync &>/dev/null; then
        rsync -a --delete "$SCRIPT_DIR/server/html/static/" /var/www/remotepower/static/
    else
        cp -rp "$SCRIPT_DIR/server/html/static/." /var/www/remotepower/static/
    fi
    chown -R root:root /var/www/remotepower/static
    find /var/www/remotepower/static -type f -exec chmod 644 {} \;
    find /var/www/remotepower/static -type d -exec chmod 755 {} \;
fi
# Auto-discover all cgi-bin Python modules (api.py plus siblings: cve_scanner,
# cmdb_vault, prometheus_export, openapi_spec, containers, tls_monitor, ...).
# The CGI entry points (api_cgi.py shim, and api.py for a direct install) need
# +x; the rest are imports so 644 is fine.
for f in "$SCRIPT_DIR"/server/cgi-bin/*.py; do
    name="$(basename "$f")"
    if [[ "$name" == "api.py" || "$name" == "api_cgi.py" ]]; then
        install -m 755 "$f" /var/www/remotepower/cgi-bin/"$name"
    else
        install -m 644 "$f" /var/www/remotepower/cgi-bin/"$name"
    fi
done
# Precompile the backend so the CGI user loads cached bytecode. The api_cgi.py
# entry point imports api, and a CGI *main script* never uses the .pyc cache --
# precompiling here means the ~50k-line module is not recompiled on every
# request. cgi-bin/ is root-owned, so the running CGI user can't write the
# .pyc itself; build it now.
python3 -m compileall -q /var/www/remotepower/cgi-bin/ || true
# v1.11.0: extension-less helper scripts (cron runners, etc.)
for helper in remotepower-tls-check; do
    src="$SCRIPT_DIR/server/cgi-bin/$helper"
    if [[ -f "$src" ]]; then
        install -m 755 "$src" /var/www/remotepower/cgi-bin/"$helper"
    fi
done
install -m 755 "$SCRIPT_DIR/server/remotepower-passwd" /var/www/remotepower/cgi-bin/remotepower-passwd
success "Web files installed"

# ── SCGI prefork API worker service (optional perf; not enabled by default) ──
# Copies the unit file so the operator can enable it later with:
#   systemctl enable --now remotepower-api
# then switch nginx to the scgi_pass block (see server/conf/remotepower.conf).
if [[ -f "$SCRIPT_DIR/server/conf/remotepower-api.service" ]]; then
    install -m 644 "$SCRIPT_DIR/server/conf/remotepower-api.service" \
        /etc/systemd/system/remotepower-api.service
    # The unit reads operator env/secrets from /etc/remotepower/api.env via
    # EnvironmentFile= (e.g. RP_BACKUP_PASSPHRASE). Create the dir so the operator
    # can drop that 0600 file in per the unit's header (the secret file itself is
    # never created here — only the directory).
    install -d -m 755 -o root -g root /etc/remotepower
    systemctl daemon-reload
    success "SCGI worker unit installed (not started — enable with: systemctl enable --now remotepower-api)"
fi

# ── WG Access privileged helper + scoped sudoers (v5.2.0) ───────────────────────
# The road-warrior WireGuard feature needs a root-owned helper to drive
# wireguard-go / wg / nft (the CGI runs unprivileged). It is invoked ONLY via a
# scoped sudoers rule granting NOPASSWD for this one script to the web user —
# exactly the deploy-remote-site.sh precedent. The helper uses in-kernel
# WireGuard when present and falls back to wireguard-go. The feature shows an
# "unavailable" notice in the UI until the WireGuard CLI is also present (not
# installed here — optional dependency; `pacman -S wireguard-tools` /
# `apt install wireguard wireguard-tools`).
if [[ -f "$SCRIPT_DIR/packaging/remotepower-wg-apply" ]]; then
    install -d -m 755 -o root -g root /usr/local/sbin
    install -m 755 -o root -g root "$SCRIPT_DIR/packaging/remotepower-wg-apply" \
        /usr/local/sbin/remotepower-wg-apply
    # Scoped, single-script NOPASSWD rule for the web user. 0440 root:root, and
    # validated with visudo -c before install so a bad drop-in can't lock sudo.
    _wg_sudoers="$(mktemp)"
    printf '%s ALL=(root) NOPASSWD: /usr/local/sbin/remotepower-wg-apply\n' "$NGINX_USER" > "$_wg_sudoers"
    if visudo -cf "$_wg_sudoers" >/dev/null 2>&1; then
        install -m 440 -o root -g root "$_wg_sudoers" /etc/sudoers.d/remotepower-wg
        success "WG Access helper + scoped sudoers installed (install wireguard-go to enable)"
    else
        info "WG Access sudoers validation failed — skipped (helper installed, feature stays unavailable)"
    fi
    rm -f "$_wg_sudoers"
fi

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
# v4.5.0: the location {} blocks live in a shared snippet that both the HTTP and
# HTTPS server blocks include (no drift; also serves /ca.crt). Install it first
# so `nginx -t` below can resolve the include.
mkdir -p /etc/nginx/snippets
cp "$SCRIPT_DIR/server/conf/remotepower-locations.conf" /etc/nginx/snippets/remotepower-locations.conf
if [[ -f /etc/nginx/sites-available/remotepower ]]; then
    warn "Nginx config already exists — skipping (edit /etc/nginx/sites-available/remotepower manually)"
    warn "  (refreshed /etc/nginx/snippets/remotepower-locations.conf to match this version)"
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

# Use bcrypt if available, else salted PBKDF2-HMAC-SHA256 — matches api.py's
# hash_password() exactly (never bare unsalted SHA-256). The password is passed
# via the environment, not interpolated into the script, so a password
# containing quotes can't break or inject into the Python source.
RP_ADMIN_USER="${ADMIN_USER}" RP_ADMIN_PASS="${ADMIN_PASS}" python3 - <<'PYEOF'
import json, time, os, hashlib, secrets
from pathlib import Path

plain = os.environ['RP_ADMIN_PASS']
try:
    import bcrypt
    pw_hash = bcrypt.hashpw(plain.encode(), bcrypt.gensalt(12)).decode()
    hash_type = 'bcrypt'
except ImportError:
    salt = secrets.token_bytes(16)
    iters = 600_000
    dk = hashlib.pbkdf2_hmac('sha256', plain.encode(), salt, iters)
    pw_hash = f'pbkdf2${iters}${salt.hex()}${dk.hex()}'
    hash_type = 'pbkdf2'

path = Path('/var/lib/remotepower/users.json')
users = json.loads(path.read_text()) if path.exists() else {}
users[os.environ['RP_ADMIN_USER']] = {'password_hash': pw_hash, 'created': int(time.time())}
path.write_text(json.dumps(users, indent=2))
print(f"  User saved (hash: {hash_type}).")
PYEOF

chown "${NGINX_USER}:${NGINX_USER}" /var/lib/remotepower/users.json
success "Admin user '${ADMIN_USER}' created"

# ── OPT-IN: PostgreSQL backend (v6.x; default backend is single-file) ─────────
# Runs the existing provisioner so the operator can pick PG at install time. It
# writes the storage marker; existing file-based data (incl. the admin user just
# created) still needs a one-time migration to land in the DB.
if [[ "$WITH_POSTGRES" == "1" ]]; then
    info "Provisioning PostgreSQL backend (packaging/postgres-setup.sh)..."
    if [[ -f "$SCRIPT_DIR/packaging/postgres-setup.sh" ]]; then
        if bash "$SCRIPT_DIR/packaging/postgres-setup.sh" --install --write-marker /var/lib/remotepower; then
            chown "${NGINX_USER}:${NGINX_USER}" /var/lib/remotepower/storage_backend.json 2>/dev/null || true
            success "PostgreSQL provisioned + storage marker written"
            warn "Migrate existing data into Postgres so the admin user is visible:"
            warn "  python3 tools/migrate_storage.py  (or Settings → Advanced → Storage backend)"
        else
            warn "postgres-setup.sh failed — install continues on the default backend"
        fi
    else
        warn "packaging/postgres-setup.sh not found — skipping Postgres provisioning"
    fi
fi

# ── OPT-IN: out-of-band maintenance scheduler (v6.x) ──────────────────────────
# Installs remotepower-scheduler.service and tells the API worker to stop running
# the cadence on the request path (RP_EXTERNAL_SCHEDULER=1 in api.env). NB the
# plain CGI/fcgiwrap path does NOT read api.env — pair --with-scheduler with the
# SCGI worker (remotepower-api) or --with-wsgi so the flag is actually honoured.
if [[ "$WITH_SCHEDULER" == "1" ]]; then
    info "Enabling the out-of-band maintenance scheduler..."
    install -m 644 "$SCRIPT_DIR/server/conf/remotepower-scheduler.service" \
        /etc/systemd/system/remotepower-scheduler.service
    install -d -m 755 -o root -g root /etc/remotepower
    touch /etc/remotepower/api.env && chmod 600 /etc/remotepower/api.env
    if ! grep -q '^RP_EXTERNAL_SCHEDULER=1' /etc/remotepower/api.env 2>/dev/null; then
        printf 'RP_EXTERNAL_SCHEDULER=1\n' >> /etc/remotepower/api.env
    fi
    systemctl daemon-reload
    systemctl enable --now remotepower-scheduler \
        && success "Out-of-band scheduler enabled (remotepower-scheduler)" \
        || warn "Could not start remotepower-scheduler — check: systemctl status remotepower-scheduler"
    # If a persistent worker is running, restart it so it picks up the flag.
    systemctl is-active --quiet remotepower-api  2>/dev/null && systemctl restart remotepower-api  || true
    systemctl is-active --quiet remotepower-wsgi 2>/dev/null && systemctl restart remotepower-wsgi || true
fi

# ── OPT-IN: persistent gunicorn WSGI app tier (v6.x) ──────────────────────────
# Installs gunicorn + remotepower-wsgi.service and repoints nginx /api/ from
# fcgiwrap to the gunicorn proxy. The rewrite of the DEPLOYED locations snippet
# is validated with `nginx -t` and reverted to fcgiwrap if it fails.
if [[ "$APP_SERVER" == "wsgi" ]]; then
    info "Setting up the persistent WSGI app tier (gunicorn)..."
    # gunicorn is NOT a RemotePower dependency. Prefer the distro package (lands
    # at /usr/bin/gunicorn, matching the unit's ExecStart) and fall back to pip.
    if ! command -v gunicorn >/dev/null 2>&1; then
        case $PKG_MGR in
          apt)    apt-get install -y --no-install-recommends gunicorn 2>/dev/null \
                    || pip3 install gunicorn --break-system-packages 2>/dev/null \
                    || pip3 install gunicorn || warn "gunicorn install failed — WSGI tier unavailable" ;;
          dnf)    dnf install -y -q python3-gunicorn 2>/dev/null \
                    || pip3 install gunicorn || warn "gunicorn install failed — WSGI tier unavailable" ;;
          pacman) pacman -S --noconfirm gunicorn 2>/dev/null \
                    || pip install gunicorn || warn "gunicorn install failed — WSGI tier unavailable" ;;
        esac
    fi
    if command -v gunicorn >/dev/null 2>&1; then
        # The unit hardcodes /usr/bin/gunicorn; symlink if pip put it elsewhere.
        [[ -x /usr/bin/gunicorn ]] || ln -sf "$(command -v gunicorn)" /usr/bin/gunicorn
        install -m 644 "$SCRIPT_DIR/server/conf/remotepower-wsgi.service" \
            /etc/systemd/system/remotepower-wsgi.service
        install -d -m 755 -o root -g root /etc/remotepower
        systemctl daemon-reload
        systemctl enable --now remotepower-wsgi \
            && success "remotepower-wsgi started (gunicorn on 127.0.0.1:8090)" \
            || warn "Could not start remotepower-wsgi — check: systemctl status remotepower-wsgi"
        _snip=/etc/nginx/snippets/remotepower-locations.conf
        if [[ -f "$_snip" ]]; then
            cp -a "$_snip" "${_snip}.cgi.bak"
            python3 - "$_snip" <<'PYEOF'
import re, sys
from pathlib import Path
p = Path(sys.argv[1]); text = p.read_text()
# Rewrite each ACTIVE (non-commented) location block that drives fcgiwrap into a
# gunicorn proxy_pass block. Commented example blocks start with '#' so the
# line-anchored matcher skips them; brace matching is depth-aware so the nested
# `limit_except { … }` doesn't confuse it.
loc_re = re.compile(r'(?m)^[ \t]*location\b[^{]*')
out, pos = [], 0
while True:
    m = loc_re.search(text, pos)
    if not m:
        out.append(text[pos:]); break
    out.append(text[pos:m.start()])
    sel = m.group(0)
    bopen = text.index('{', m.start())
    depth, j = 0, bopen
    while j < len(text):
        if text[j] == '{': depth += 1
        elif text[j] == '}':
            depth -= 1
            if depth == 0: break
        j += 1
    block = text[bopen:j + 1]
    if 'fcgiwrap.socket' in block:
        pim = re.search(r'PATH_INFO\s+(\S+);', block)
        suffix = pim.group(1) if (pim and pim.group(1) != '$uri') else ''
        le = re.search(r'limit_except[^{]*\{[^}]*\}', block)
        le_line = ('\n    ' + le.group(0)) if le else ''
        indent = re.match(r'[ \t]*', sel).group(0)
        out.append(
            sel.rstrip() + ' {\n'
            '    proxy_pass http://127.0.0.1:8090' + suffix + ';\n'
            '    proxy_set_header Host $host;\n'
            '    proxy_set_header X-Real-IP $remote_addr;\n'
            '    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n'
            '    proxy_set_header X-Forwarded-Proto $scheme;\n'
            '    proxy_read_timeout 130s;' + le_line + '\n' + indent + '}')
    else:
        out.append(sel + block)
    pos = j + 1
p.write_text(''.join(out))
PYEOF
            if nginx -t >/dev/null 2>&1; then
                systemctl reload nginx
                success "nginx /api/ now proxies to the WSGI tier (backup: ${_snip}.cgi.bak)"
            else
                warn "nginx -t failed after the WSGI switch — reverting to fcgiwrap"
                cp -a "${_snip}.cgi.bak" "$_snip"
                nginx -t >/dev/null 2>&1 && systemctl reload nginx || true
            fi
        fi
    fi
fi

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
echo "             (add / change / delete users and list accounts)"
echo ""
echo "  Perf (optional): systemctl enable --now remotepower-api"
echo "    then switch nginx /api/ to scgi_pass (see server/conf/remotepower.conf)"
echo ""
echo "  Next: Install the client on each machine you want to control:"
echo "    sudo bash install-client.sh"
echo ""
echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║  WARNING: TLS IS NOT CONFIGURED — DO THIS BEFORE GOING LIVE  ║${NC}"
echo -e "${RED}║                                                                ║${NC}"
echo -e "${RED}║  Session tokens and agent credentials travel in CLEARTEXT     ║${NC}"
echo -e "${RED}║  over HTTP. Set up HTTPS before enrolling any real agent or   ║${NC}"
echo -e "${RED}║  exposing this server to your network.                        ║${NC}"
echo -e "${RED}║                                                                ║${NC}"
echo -e "${RED}║  RECOMMENDED — real cert (Let's Encrypt):                     ║${NC}"
echo -e "${RED}║    sudo apt install certbot python3-certbot-nginx             ║${NC}"
echo -e "${RED}║    sudo certbot --nginx -d your.domain.com                    ║${NC}"
echo -e "${RED}║                                                                ║${NC}"
echo -e "${RED}║  Internal-only / no public DNS — self-signed CA:              ║${NC}"
echo -e "${RED}║    sudo make tls-selfsigned HOST=rp.internal NGINX=1          ║${NC}"
echo -e "${RED}║    (then enroll agents with the printed --ca-fingerprint)     ║${NC}"
echo -e "${RED}║                                                                ║${NC}"
echo -e "${RED}║  Then uncomment the HTTPS server block in                     ║${NC}"
echo -e "${RED}║    /etc/nginx/sites-available/remotepower  (+ HSTS/redirect)  ║${NC}"
echo -e "${RED}║                                                                ║${NC}"
echo -e "${RED}║  Full guide: docs/tls-selfsigned.md  /  docs/install.md       ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

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

# ── Enterprise single-node topology (v6.1+) — DEFAULT ON ──────────────────────
# The standard install is Postgres + the persistent gunicorn/Flask app tier
# (the only server — CGI/fcgiwrap is retired, see CHANGELOG v6.1.0) + the
# out-of-band maintenance scheduler + a co-located scanner satellite, all on
# this one node. Postgres/scheduler/scanner can be opted back OUT for a
# lightweight/dev install. Each can also be set via an env var so the unified
# wizard (install.sh) and CI can pass them through.
WITH_SCHEDULER="${RP_WITH_SCHEDULER:-1}" # 1 → out-of-band maintenance scheduler
WITH_POSTGRES="${RP_WITH_POSTGRES:-1}"   # 1 → provision a PostgreSQL backend
WITH_SCANNER="${RP_WITH_SCANNER:-1}"     # 1 → install a co-located scanner satellite

_usage() {
  cat <<EOF
RemotePower server installer

Usage: sudo bash install-server.sh [options]

  --with-scheduler      Run the ~33 maintenance sweeps out-of-band — installs
                        remotepower-scheduler.service and sets
                        RP_EXTERNAL_SCHEDULER=1 in /etc/remotepower/api.env
                        (default)
  --no-scheduler        Opt out — run maintenance sweeps on the request path
  --with-postgres        Provision a PostgreSQL backend (default)
  --no-postgres          Opt out — use the single-file/SQLite backend
  --with-scanner          Install a scanner satellite on this node, for
                        Security → Pentest scans (default)
  --no-scanner            Opt out — set one up later on a separate machine
                        per docs/security-scans.md
  -h, --help          Show this help

This is the "enterprise" single-node default: Postgres + gunicorn/Flask +
scheduler + scanner all on one box. Pass the --no-* flags for a lightweight
install. See docs/wsgi.md, docs/scaling.md, docs/security-scans.md.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-scheduler) WITH_SCHEDULER=1 ;;
    --no-scheduler)   WITH_SCHEDULER=0 ;;
    --with-postgres)  WITH_POSTGRES=1 ;;
    --no-postgres)    WITH_POSTGRES=0 ;;
    --with-scanner)   WITH_SCANNER=1 ;;
    --no-scanner)     WITH_SCANNER=0 ;;
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
else die "Unsupported distro — install nginx, gunicorn, python3 manually then re-run."
fi
info "Detected package manager: ${PKG_MGR}"

# ── Dependencies ────────────────────────────────────────────────────────────────
info "Installing dependencies..."
case $PKG_MGR in
  apt)
    apt-get update -qq
    apt-get install -y nginx python3 python3-pip iputils-ping --no-install-recommends
    ;;
  dnf)
    dnf install -y -q nginx python3 python3-pip iputils
    ;;
  pacman)
    pacman -Sy --noconfirm --noprogressbar nginx python python-pip iputils
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

# ── flask + gunicorn (v6.1.0+: the app server — required, not optional) ──────
# server/cgi-bin/wsgi.py is a real Flask app; gunicorn is the only way it's
# served (CGI/fcgiwrap is retired). Prefer the distro package (gunicorn lands
# at /usr/bin/gunicorn, matching remotepower-wsgi.service's ExecStart) and
# fall back to pip.
info "Installing flask + gunicorn (the app server)..."
if python3 -c "import flask" 2>/dev/null; then
    success "flask already available"
else
    case $PKG_MGR in
      apt)    apt-get install -y --no-install-recommends python3-flask 2>/dev/null \
                || pip3 install flask --break-system-packages 2>/dev/null \
                || pip3 install flask || die "flask install failed — the app server cannot run" ;;
      dnf)    dnf install -y -q python3-flask 2>/dev/null \
                || pip3 install flask || die "flask install failed — the app server cannot run" ;;
      pacman) pacman -S --noconfirm python-flask 2>/dev/null \
                || pip install flask || die "flask install failed — the app server cannot run" ;;
    esac
    python3 -c "import flask" 2>/dev/null || die "flask install failed — the app server cannot run"
    success "flask installed"
fi
if ! command -v gunicorn >/dev/null 2>&1; then
    case $PKG_MGR in
      apt)    apt-get install -y --no-install-recommends gunicorn 2>/dev/null \
                || pip3 install gunicorn --break-system-packages 2>/dev/null \
                || pip3 install gunicorn || die "gunicorn install failed — the app server cannot run" ;;
      dnf)    dnf install -y -q python3-gunicorn 2>/dev/null \
                || pip3 install gunicorn || die "gunicorn install failed — the app server cannot run" ;;
      pacman) pacman -S --noconfirm gunicorn 2>/dev/null \
                || pip install gunicorn || die "gunicorn install failed — the app server cannot run" ;;
    esac
fi
command -v gunicorn >/dev/null 2>&1 || die "gunicorn install failed — the app server cannot run"
# The unit hardcodes /usr/bin/gunicorn; symlink if pip put it elsewhere.
[[ -x /usr/bin/gunicorn ]] || ln -sf "$(command -v gunicorn)" /usr/bin/gunicorn
success "gunicorn installed"

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
# wsgi.py (the gunicorn entry point) and api.py need +x; the rest are imports
# so 644 is fine.
for f in "$SCRIPT_DIR"/server/cgi-bin/*.py; do
    name="$(basename "$f")"
    if [[ "$name" == "api.py" || "$name" == "wsgi.py" ]]; then
        install -m 755 "$f" /var/www/remotepower/cgi-bin/"$name"
    else
        install -m 644 "$f" /var/www/remotepower/cgi-bin/"$name"
    fi
done
# Precompile the backend so gunicorn loads cached bytecode on first request
# instead of recompiling the ~50k-line module. cgi-bin/ is root-owned, so the
# running www-data user can't write the .pyc itself; build it now.
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

# ── WG Access privileged helper + scoped sudoers (v5.2.0) ───────────────────────
# The road-warrior WireGuard feature needs a root-owned helper to drive
# wireguard-go / wg / nft (the app server runs unprivileged as www-data). It is invoked ONLY via a
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

# ── gunicorn/Flask app server (the only server) ───────────────────────────────
# nginx already proxies /api/ to 127.0.0.1:8090 (the shipped locations
# snippet) — start the app tier it's pointing at.
info "Starting the app server (gunicorn + wsgi.py)..."
install -m 644 "$SCRIPT_DIR/server/conf/remotepower-wsgi.service" \
    /etc/systemd/system/remotepower-wsgi.service
install -d -m 755 -o root -g root /etc/remotepower
systemctl daemon-reload
systemctl enable --now remotepower-wsgi \
    && success "remotepower-wsgi started (gunicorn on 127.0.0.1:8090)" \
    || warn "Could not start remotepower-wsgi — check: systemctl status remotepower-wsgi"

# ── Admin user ──────────────────────────────────────────────────────────────────
# Guarded on users.json NOT already existing — every other step in this script
# is safe to re-run (nginx config, gunicorn install, wsgi.service), but this one
# previously wasn't: re-running install-server.sh on an EXISTING install would
# silently overwrite the current admin account with whatever was typed at the
# prompt. Matches the same idempotent pattern docker/entrypoint.sh already uses.
if [[ -f /var/lib/remotepower/users.json ]]; then
    info "Admin user already exists (/var/lib/remotepower/users.json) — skipping"
else
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
fi

# ── Scanner satellite (default; --no-scanner to opt out) ─────────────────────
# Co-located Security → Pentest scan worker. Mints its own token directly into
# satellites.json (same file-write pattern as the admin user above) and points
# at this node over loopback. See packaging/scanner-setup.sh's own header for
# the isolation trade-off this makes vs. the doc-recommended separate machine.
# Runs BEFORE the Postgres block below so its token is included in the
# migration into Postgres, not left behind on the file backend.
if [[ "$WITH_SCANNER" == "1" ]]; then
    info "Installing the scanner satellite (packaging/scanner-setup.sh)..."
    if [[ -f "$SCRIPT_DIR/packaging/scanner-setup.sh" ]]; then
        if RP_DATA_DIR=/var/lib/remotepower bash "$SCRIPT_DIR/packaging/scanner-setup.sh" --mint-local; then
            chown "${NGINX_USER}:${NGINX_USER}" /var/lib/remotepower/satellites.json 2>/dev/null || true
            success "Scanner satellite installed (remotepower-scanner)"
        else
            warn "scanner-setup.sh failed — install continues without a scanner satellite"
        fi
    else
        warn "packaging/scanner-setup.sh not found — skipping scanner satellite"
    fi
fi

# ── psycopg (needed for the PostgreSQL backend) ───────────────────────────────
if [[ "$WITH_POSTGRES" == "1" ]]; then
    info "Installing psycopg for the PostgreSQL backend..."
    if python3 -c "import psycopg" 2>/dev/null; then
        success "psycopg already available"
    else
        case $PKG_MGR in
          apt)    apt-get install -y python3-psycopg 2>/dev/null \
                    || pip3 install 'psycopg[binary]' --break-system-packages 2>/dev/null \
                    || pip3 install 'psycopg[binary]' \
                    || warn "psycopg install failed — Postgres backend will be unavailable" ;;
          dnf)    dnf install -y -q python3-psycopg 2>/dev/null \
                    || pip3 install 'psycopg[binary]' \
                    || warn "psycopg install failed — Postgres backend will be unavailable" ;;
          pacman) pacman -S --noconfirm python-psycopg 2>/dev/null \
                    || pip install 'psycopg[binary]' \
                    || warn "psycopg install failed — Postgres backend will be unavailable" ;;
        esac
        python3 -c "import psycopg" 2>/dev/null \
          && success "psycopg installed" \
          || warn "psycopg unavailable — Postgres backend will not work until it is installed"
    fi
fi

# ── PostgreSQL backend (default; --no-postgres to opt out) ────────────────────
# Runs the existing provisioner (without --write-marker — we set the marker
# ourselves below, via a real migration, not a blind flip), then migrates the
# admin user + scanner token — both always written to the JSON files above,
# regardless of backend — into Postgres directly, so the default install
# actually works without a manual follow-up step. RP_DB_PASS is generated
# here (not left to postgres-setup.sh) so this script knows the DSN without
# having to scrape it back out of that script's human-readable output.
if [[ "$WITH_POSTGRES" == "1" ]]; then
    export RP_DB_NAME="${RP_DB_NAME:-remotepower}"
    export RP_DB_USER="${RP_DB_USER:-rp}"
    export RP_DB_PASS="${RP_DB_PASS:-$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')}"
    info "Provisioning PostgreSQL backend (packaging/postgres-setup.sh)..."
    if [[ -f "$SCRIPT_DIR/packaging/postgres-setup.sh" ]]; then
        if bash "$SCRIPT_DIR/packaging/postgres-setup.sh" --install; then
            success "PostgreSQL provisioned"
            PG_DSN="postgresql://${RP_DB_USER}:${RP_DB_PASS}@localhost:5432/${RP_DB_NAME}"
            info "Migrating the admin user + scanner token into Postgres..."
            # RP_STORAGE_BACKEND is left unset for this one call so the migration
            # reads its SOURCE data from the JSON files just written, not from
            # (empty) Postgres; _migrate_storage_pg writes storage_backend.json
            # itself once migration verifies clean.
            if RP_DATA_DIR=/var/lib/remotepower RP_PG_DSN="$PG_DSN" python3 - <<'PYEOF'
import os
import sys
sys.path.insert(0, '/var/www/remotepower/cgi-bin')
import api
result = api._migrate_storage_pg('postgres', os.environ['RP_PG_DSN'], log=print)
print('[migrate]', result)
sys.exit(0 if result.get('ok') else 1)
PYEOF
            then
                chown "${NGINX_USER}:${NGINX_USER}" /var/lib/remotepower/storage_backend.json 2>/dev/null || true
                success "Admin user + scanner token migrated — Postgres is the active backend"
            else
                warn "Postgres migration failed — admin user/scanner token stay on the file backend"
                warn "  Retry from Settings → Advanced → Storage backend once the server is up"
            fi
        else
            warn "postgres-setup.sh failed — install continues on the default backend"
        fi
    else
        warn "packaging/postgres-setup.sh not found — skipping Postgres provisioning"
    fi
fi

# ── Out-of-band maintenance scheduler (default; --no-scheduler to opt out) ───
# Installs remotepower-scheduler.service and tells gunicorn to stop running
# the cadence on the request path (RP_EXTERNAL_SCHEDULER=1 in api.env).
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
    # Restart gunicorn so it picks up the flag from api.env.
    systemctl is-active --quiet remotepower-wsgi 2>/dev/null && systemctl restart remotepower-wsgi || true
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
echo "  Topology:  app-server=gunicorn  postgres=${WITH_POSTGRES}  scheduler=${WITH_SCHEDULER}  scanner=${WITH_SCANNER}"
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

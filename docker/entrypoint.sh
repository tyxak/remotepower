#!/bin/bash
set -e

DATA_DIR="/var/lib/remotepower"
USERS_FILE="$DATA_DIR/users.json"

# Ensure data dir ownership
chown -R www-data:www-data "$DATA_DIR"
chmod 700 "$DATA_DIR"

# Write agent version into config.json
python3 - <<'PYEOF'
import json, re
from pathlib import Path

agent = Path('/var/www/remotepower/agent/remotepower-agent').read_text()
m = re.search(r"VERSION\s*=\s*['\"]([^'\"]+)['\"]", agent)
agent_v = m.group(1) if m else 'unknown'

api = Path('/var/www/remotepower/cgi-bin/api.py').read_text()
m = re.search(r"SERVER_VERSION\s*=\s*['\"]([^'\"]+)['\"]", api)
server_v = m.group(1) if m else agent_v

cfg_path = Path('/var/lib/remotepower/config.json')
cfg = json.loads(cfg_path.read_text()) if cfg_path.exists() else {}
cfg['agent_version'] = agent_v
cfg['server_version'] = server_v
cfg_path.write_text(json.dumps(cfg, indent=2))
PYEOF

# Create admin user if users.json doesn't exist
if [ ! -f "$USERS_FILE" ]; then
    RP_ADMIN_USER="${RP_ADMIN_USER:-admin}"
    # v2.2.6: if RP_ADMIN_PASS isn't set, generate a strong random
    # password instead of refusing to start. The password is printed
    # ONCE to the container log with a loud banner — grab it with
    # `docker logs <container>`. This is far better than the old
    # behaviour (either a hard-coded `changeme` default in
    # docker-compose.yml, or no admin user at all).
    GENERATED=""
    if [ -z "$RP_ADMIN_PASS" ]; then
        # 18 url-safe chars from the kernel CSPRNG via Python's secrets
        RP_ADMIN_PASS="$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')"
        GENERATED="yes"
    fi
    echo "[*] Creating admin user: $RP_ADMIN_USER"
    python3 -c "
import json, time, hashlib
from pathlib import Path
try:
    import bcrypt
    pw_hash = bcrypt.hashpw('${RP_ADMIN_PASS}'.encode(), bcrypt.gensalt(12)).decode()
except ImportError:
    pw_hash = hashlib.sha256('${RP_ADMIN_PASS}'.encode()).hexdigest()
path = Path('$USERS_FILE')
users = {
    '$RP_ADMIN_USER': {
        'password_hash': pw_hash,
        'role': 'admin',
        'created': int(time.time())
    }
}
path.write_text(json.dumps(users, indent=2))
"
    chown www-data:www-data "$USERS_FILE"
    echo "[+] Admin user created"
    if [ -n "$GENERATED" ]; then
        echo ""
        echo "  ╔══════════════════════════════════════════════════════════╗"
        echo "  ║  GENERATED ADMIN CREDENTIALS — SAVE THESE NOW             ║"
        echo "  ║  This password is shown ONCE and is not stored anywhere.  ║"
        echo "  ╠══════════════════════════════════════════════════════════╣"
        printf  "  ║  username : %-44s ║\n" "$RP_ADMIN_USER"
        printf  "  ║  password : %-44s ║\n" "$RP_ADMIN_PASS"
        echo "  ╠══════════════════════════════════════════════════════════╣"
        echo "  ║  Change it after first login: Settings, or run            ║"
        echo "  ║  python3 cgi-bin/remotepower-passwd inside the container.  ║"
        echo "  ╚══════════════════════════════════════════════════════════╝"
        echo ""
    fi
    # Don't leave the password sitting in the environment
    unset RP_ADMIN_PASS
fi

# ── Opt-in self-signed TLS (v4.5.0) ──────────────────────────────────────────
# RP_TLS_SELFSIGNED=1 makes the container terminate TLS itself: generate a CA +
# leaf into the persistent data volume (once) and serve HTTPS on :8443. Prefer a
# real cert / reverse proxy for production — see docs/tls-selfsigned.md.
if [ "${RP_TLS_SELFSIGNED:-}" = "1" ] || [ "${RP_TLS_SELFSIGNED:-}" = "true" ]; then
    TLS_HOST="${RP_TLS_HOST:-localhost}"
    TLS_DIR=/var/lib/remotepower/tls
    if [ ! -f "$TLS_DIR/server.crt" ]; then
        echo "[*] RP_TLS_SELFSIGNED set — generating self-signed CA + leaf for ${TLS_HOST}"
        /usr/local/bin/rp-gen-ca --host "$TLS_HOST" --dir "$TLS_DIR" >/tmp/genca.log 2>&1 || {
            echo "[!] cert generation failed:"; cat /tmp/genca.log; exit 1; }
    fi
    chown -R www-data:www-data "$TLS_DIR" 2>/dev/null || true
    ln -sf /etc/nginx/sites-available/remotepower-tls /etc/nginx/sites-enabled/remotepower
    FP="$(openssl x509 -in "$TLS_DIR/ca.crt" -noout -fingerprint -sha256 | sed 's/^.*=//')"
    echo ""
    echo "  ╔══════════════════════════════════════════════════════════╗"
    echo "  ║  SELF-SIGNED TLS ENABLED — HTTPS on container :8443       ║"
    echo "  ╠══════════════════════════════════════════════════════════╣"
    echo "  ║  Enroll agents with this CA fingerprint (pin it):         ║"
    echo "  ║  $FP"
    echo "  ║  install-client.sh --server https://${TLS_HOST} --ca-fingerprint <above>"
    echo "  ╚══════════════════════════════════════════════════════════╝"
    echo ""
fi

# Start fcgiwrap (socket for nginx)
echo "[*] Starting fcgiwrap..."
# Create socket dir
mkdir -p /run
spawn-fcgi -s /run/fcgiwrap.socket -u www-data -g www-data -- /usr/sbin/fcgiwrap
chmod 660 /run/fcgiwrap.socket
chown www-data:www-data /run/fcgiwrap.socket
echo "[+] fcgiwrap started"

# Start nginx in foreground
echo "[*] Starting nginx..."
exec nginx -g 'daemon off;'

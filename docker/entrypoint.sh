#!/bin/bash
set -euo pipefail

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
    if [ -z "${RP_ADMIN_PASS:-}" ]; then
        # 18 url-safe chars from the kernel CSPRNG via Python's secrets
        RP_ADMIN_PASS="$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')"
        GENERATED="yes"
    fi
    echo "[*] Creating admin user: $RP_ADMIN_USER"
    # Pass credentials via the environment, NOT shell-interpolated into the
    # Python source: a password containing a quote/backslash/newline would
    # otherwise break the literal (container fails to start) or inject Python.
    # The quoted heredoc delimiter ('PYEOF') disables all shell expansion.
    RP_ADMIN_USER="$RP_ADMIN_USER" RP_ADMIN_PASS="$RP_ADMIN_PASS" USERS_FILE="$USERS_FILE" \
        python3 - <<'PYEOF'
import json, time, hashlib, os
from pathlib import Path
user = os.environ['RP_ADMIN_USER']
pw   = os.environ['RP_ADMIN_PASS']
try:
    import bcrypt
    pw_hash = bcrypt.hashpw(pw.encode(), bcrypt.gensalt(12)).decode()
except ImportError:
    pw_hash = hashlib.sha256(pw.encode()).hexdigest()
path = Path(os.environ['USERS_FILE'])
users = {
    user: {
        'password_hash': pw_hash,
        'role': 'admin',
        'created': int(time.time())
    }
}
path.write_text(json.dumps(users, indent=2))
PYEOF
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
    FP="$(openssl x509 -in "$TLS_DIR/ca.crt" -noout -fingerprint -sha256 | sed 's/^.*=//')" || true
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

# ── Opt-in persistent WSGI app tier (v6.x) ──────────────────────────────────
# RP_APP_SERVER=wsgi runs the SAME api.py under gunicorn (persistent, threaded
# workers) instead of fork-per-request fcgiwrap, and repoints nginx /api/ at it.
# Default (unset) = the unchanged fcgiwrap path. Validated by nginx -t; reverts
# to fcgiwrap if the location rewrite doesn't parse. See docs/wsgi.md.
if [ "${RP_APP_SERVER:-}" = "wsgi" ]; then
    echo "[*] RP_APP_SERVER=wsgi — switching nginx /api/ to the gunicorn proxy"
    SNIP=/etc/nginx/snippets/remotepower-docker-locations.conf
    cp -a "$SNIP" "$SNIP.cgi.bak"
    python3 - "$SNIP" <<'PYEOF'
import re, sys
from pathlib import Path
p = Path(sys.argv[1]); text = p.read_text()
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
    if ! nginx -t >/dev/null 2>&1; then
        echo "[!] nginx -t failed after the WSGI switch — reverting to fcgiwrap"
        cp -a "$SNIP.cgi.bak" "$SNIP"
        RP_APP_SERVER=""
    fi
fi

if [ "${RP_APP_SERVER:-}" = "wsgi" ]; then
    echo "[*] Starting gunicorn WSGI tier on 127.0.0.1:8090..."
    cd /var/www/remotepower/cgi-bin
    RP_DATA_DIR=/var/lib/remotepower \
      gunicorn --workers 2 --threads 8 --timeout 120 --bind 127.0.0.1:8090 wsgi:application &
    cd /
    echo "[+] gunicorn started (pid $!)"
else
    # Default path — classic CGI via fcgiwrap (unchanged).
    echo "[*] Starting fcgiwrap..."
    # Create socket dir
    mkdir -p /run
    spawn-fcgi -s /run/fcgiwrap.socket -u www-data -g www-data -- /usr/sbin/fcgiwrap
    chmod 660 /run/fcgiwrap.socket
    chown www-data:www-data /run/fcgiwrap.socket
    echo "[+] fcgiwrap started"
fi

# ── Opt-in out-of-band maintenance scheduler (v6.x) ──────────────────────────
# RP_EXTERNAL_SCHEDULER=1 launches scheduler.py in the background; the WSGI/CGI
# request path stops running the cadence (gunicorn inherits the env var). Default
# (unset) = the cadence piggy-backs on requests exactly as before.
if [ "${RP_EXTERNAL_SCHEDULER:-}" = "1" ] || [ "${RP_EXTERNAL_SCHEDULER:-}" = "true" ]; then
    echo "[*] RP_EXTERNAL_SCHEDULER set — launching scheduler.py in the background"
    RP_DATA_DIR=/var/lib/remotepower python3 /var/www/remotepower/cgi-bin/scheduler.py &
    echo "[+] scheduler started (pid $!)"
fi

# First-greeting to the logs — the address to open.
_scheme=http
if [ "${RP_TLS_SELFSIGNED:-}" = "1" ] || [ "${RP_TLS_SELFSIGNED:-}" = "true" ]; then _scheme=https; fi
echo ""
echo "  ──────────────────────────────────────────────"
echo "   RemotePower is live  →  ${_scheme}://${RP_TLS_HOST:-localhost}"
echo "   Log in as 'admin' (one-time password printed above on first boot)."
echo "  ──────────────────────────────────────────────"
echo ""

# Start nginx in foreground
echo "[*] Starting nginx..."
exec nginx -g 'daemon off;'

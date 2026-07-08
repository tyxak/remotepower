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

# ── Does Postgres already have real bootstrap data? ──────────────────────────
# v6.1.0 originally gated admin-bootstrap on `users.json` and Postgres
# migration on a separate `$DATA_DIR/.pg_migrated` marker — both living on
# the app-data volume (`remotepower_data`), which has an INDEPENDENT lifecycle
# from the actual Postgres volume (`remotepower_pg`). Resetting just the data
# volume (e.g. to force-regenerate the admin account) made both files look
# like "first boot" to a Postgres store that still held real users/config/
# satellites — silently overwriting it with a fresh near-empty snapshot, and
# printing a "GENERATED ADMIN CREDENTIALS" banner for credentials that could
# never actually log in (the app was still reading Postgres, unaffected).
# Fix: ask Postgres itself whether it already has bootstrap data, and gate
# BOTH the admin-mint and the migration on that live answer instead of on a
# marker file that can drift out of sync with the store it's meant to guard.
PG_HAS_USERS=""
if [ "${RP_STORAGE_BACKEND:-}" = "postgres" ] && [ -n "${RP_PG_DSN:-}" ]; then
    if RP_PG_DSN="$RP_PG_DSN" python3 - <<'PYEOF'
import os, sys
from pathlib import Path
sys.path.insert(0, '/var/www/remotepower/cgi-bin')
import storage_pg
storage_pg.configure_dsn(os.environ['RP_PG_DSN'])
try:
    storage_pg._connect(None)
    users = storage_pg.load(Path('/var/lib/remotepower/users.json'))
except Exception as e:
    print(f'[!] could not query Postgres for existing users: {e}', file=sys.stderr)
    sys.exit(2)
sys.exit(0 if users else 1)
PYEOF
    then
        PG_HAS_USERS="yes"
    fi
    # exit code 2 (Postgres unreachable) falls through with PG_HAS_USERS
    # unset, same as "no" — the admin-bootstrap/migration blocks below will
    # attempt to proceed and their own error handling covers a down database.
fi

# Create admin user if users.json doesn't exist AND Postgres (when that's the
# backend) doesn't already have real users — otherwise this would mint local
# credentials that can never log in against an already-bootstrapped Postgres.
if [ ! -f "$USERS_FILE" ] && [ "$PG_HAS_USERS" != "yes" ]; then
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

# ── Co-located scanner satellite token (v6.1+; default on) ──────────────────
# RP_WITH_SCANNER=1 (default) mints a local scanner-satellite token directly
# into satellites.json (same file-write pattern as the admin user above) and
# drops the plaintext token into a 0600 file for the `scanner` compose service
# to read — satellites.json only ever stores the HASH (see
# handle_satellites_create in api.py), so the plaintext has to go somewhere
# once, same as the generated admin password above. Idempotent across
# restarts: skipped once the token file exists.
SCANNER_TOKEN_FILE="$DATA_DIR/.scanner-token"
if { [ "${RP_WITH_SCANNER:-1}" = "1" ] || [ "${RP_WITH_SCANNER:-1}" = "true" ]; } \
        && [ ! -f "$SCANNER_TOKEN_FILE" ]; then
    echo "[*] RP_WITH_SCANNER set — minting a local scanner satellite token"
    RP_DATA_DIR="$DATA_DIR" python3 - <<'PYEOF'
import json, os, time, secrets, hashlib
from pathlib import Path

data_dir = Path(os.environ['RP_DATA_DIR'])
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
(data_dir / '.scanner-token').write_text(token)
PYEOF
    chown www-data:www-data "$DATA_DIR/satellites.json" "$SCANNER_TOKEN_FILE"
    chmod 600 "$SCANNER_TOKEN_FILE"
    echo "[+] Scanner satellite token minted — Security → Pentest is ready once the scanner service is up"
fi

# ── Warn on the default Postgres password ────────────────────────────────────
# docker-compose.yml's RP_PG_PASSWORD default (remotepower-dev-changeme) is
# static and public (it's in the open-source repo) — unlike the admin password,
# it can't be auto-generated here (Postgres already initialized with it by the
# time this container boots; the value has to come from the docker-compose
# invocation itself). Postgres has no host port mapping, so this isn't
# internet-reachable, but warn loudly and repeatedly (every boot) so it
# doesn't go unnoticed, matching the TLS-not-configured warning below.
if [ -n "${RP_PG_DSN:-}" ] && printf '%s' "$RP_PG_DSN" | grep -q 'remotepower-dev-changeme'; then
    echo ""
    echo "  ╔══════════════════════════════════════════════════════════╗"
    echo "  ║  WARNING: DEFAULT POSTGRES PASSWORD IN USE                ║"
    echo "  ║  RP_PG_DSN still has the built-in default password —      ║"
    echo "  ║  it's public (in the open-source repo). Not internet-     ║"
    echo "  ║  reachable (no host port mapping), but set your own:      ║"
    echo "  ║    RP_PG_PASSWORD=<random> docker compose up -d           ║"
    echo "  ╚══════════════════════════════════════════════════════════╝"
    echo ""
fi

# ── Auto-migrate bootstrap data into Postgres (v6.1+ default topology) ──────
# The admin user + scanner token above are written to the JSON files first
# (bcrypt/etc run before any storage backend is chosen). When
# RP_STORAGE_BACKEND=postgres — this container's default per docker-compose.yml
# — that data is invisible to the app until migrated in, so a fresh
# `docker compose up -d` would print an admin password that can't log in.
# Run the same migration Settings → Advanced → Storage backend uses
# (_migrate_storage_pg in api.py) directly, once, before nginx starts serving.
# RP_STORAGE_BACKEND is unset for this one subprocess so `load()` inside the
# migration reads the JSON source data, not (empty) Postgres.
#
# Gated on PG_HAS_USERS (computed above by querying Postgres itself), NOT a
# DATA_DIR marker file — a marker on the app-data volume can't distinguish
# "never migrated" from "the data volume was reset but Postgres still has
# real data," which previously caused this block to blindly overwrite live
# Postgres rows with a freshly re-bootstrapped, near-empty JSON snapshot.
if [ "${RP_STORAGE_BACKEND:-}" = "postgres" ] && [ -n "${RP_PG_DSN:-}" ] \
        && [ "$PG_HAS_USERS" != "yes" ]; then
    echo "[*] RP_STORAGE_BACKEND=postgres — migrating bootstrap data into Postgres"
    if RP_DATA_DIR="$DATA_DIR" RP_PG_DSN="$RP_PG_DSN" \
            env -u RP_STORAGE_BACKEND python3 - <<'PYEOF'
import os
import sys
sys.path.insert(0, '/var/www/remotepower/cgi-bin')
import api
result = api._migrate_storage_pg('postgres', os.environ['RP_PG_DSN'], log=print)
print('[migrate]', result)
sys.exit(0 if result.get('ok') else 1)
PYEOF
    then
        echo "[+] Bootstrap data migrated into Postgres"
    else
        echo "[!] Postgres migration failed — admin user / scanner token may not be visible" >&2
        echo "[!] Retry via Settings -> Advanced -> Storage backend, or restart the container." >&2
    fi
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

# ── Persistent gunicorn/Flask app tier (v6.1.0+, the only server) ────────────
# server/cgi-bin/wsgi.py is a real Flask app; nginx's shipped location snippets
# (docker/nginx-docker-locations.conf, nginx-docker-tls.conf) already proxy_pass
# to it — no runtime rewrite needed. See docs/wsgi.md.
echo "[*] Starting gunicorn on 127.0.0.1:8090..."
cd /var/www/remotepower/cgi-bin
RP_DATA_DIR=/var/lib/remotepower \
  gunicorn --workers 2 --threads 8 --timeout 120 --bind 127.0.0.1:8090 wsgi:application &
cd /
echo "[+] gunicorn started (pid $!)"

# ── Out-of-band maintenance scheduler (default on, see RP_EXTERNAL_SCHEDULER above) ──
# RP_EXTERNAL_SCHEDULER=1 launches scheduler.py in the background; the app
# server's request path stops running the cadence (gunicorn inherits the env
# var). Unset = the cadence piggy-backs on requests instead.
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

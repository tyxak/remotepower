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

# Create admin user if users.json doesn't exist and env vars are set
if [ ! -f "$USERS_FILE" ]; then
    RP_ADMIN_USER="${RP_ADMIN_USER:-admin}"
    if [ -n "$RP_ADMIN_PASS" ]; then
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
    else
        echo "[!] No users.json found and RP_ADMIN_PASS not set."
        echo "    Set RP_ADMIN_PASS environment variable to create an admin user."
        echo "    Or mount an existing /var/lib/remotepower volume."
    fi
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

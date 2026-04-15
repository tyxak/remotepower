#!/usr/bin/env python3
"""
RemotePower API backend
Runs via fcgiwrap as a CGI script, or standalone with gunicorn/uvicorn behind Nginx.
Uses flat-file storage in /var/lib/remotepower/
"""

import os
import sys
import json
import time
import hashlib
import hmac
import secrets
import socket
import subprocess
import urllib.request
import urllib.error
from pathlib import Path

# ─── Config ────────────────────────────────────────────────────────────────────
DATA_DIR  = Path(os.environ.get('RP_DATA_DIR', '/var/lib/remotepower'))
USERS_FILE   = DATA_DIR / 'users.json'
DEVICES_FILE = DATA_DIR / 'devices.json'
PINS_FILE    = DATA_DIR / 'pins.json'
TOKENS_FILE  = DATA_DIR / 'tokens.json'
CMDS_FILE    = DATA_DIR / 'commands.json'
CONFIG_FILE  = DATA_DIR / 'config.json'

TOKEN_TTL    = 86400 * 7   # 7 days
PIN_TTL      = 600          # 10 minutes
ONLINE_TTL   = 180          # device considered offline after 3 minutes

SECRET_KEY = os.environ.get('RP_SECRET', 'change-me-in-production-please')

# ─── bcrypt (optional, graceful fallback to SHA-256) ───────────────────────────
try:
    import bcrypt as _bcrypt
    _BCRYPT = True
except ImportError:
    _BCRYPT = False

def hash_password(plain: str) -> str:
    if _BCRYPT:
        return _bcrypt.hashpw(plain.encode(), _bcrypt.gensalt(12)).decode()
    return hashlib.sha256(plain.encode()).hexdigest()

def verify_password(plain: str, stored: str) -> bool:
    """Verify against bcrypt hash or legacy sha256. Timing-safe."""
    if stored.startswith('$2'):
        if not _BCRYPT:
            return False
        try:
            return _bcrypt.checkpw(plain.encode(), stored.encode())
        except Exception:
            return False
    return hmac.compare_digest(
        hashlib.sha256(plain.encode()).hexdigest(),
        stored
    )

def maybe_rehash(username: str, plain: str, stored: str):
    """Silently upgrade a SHA-256 hash to bcrypt on successful login."""
    if _BCRYPT and not stored.startswith('$2'):
        users = load(USERS_FILE)
        users[username]['password_hash'] = hash_password(plain)
        save(USERS_FILE, users)

# ─── Storage helpers ────────────────────────────────────────────────────────────
DATA_DIR.mkdir(parents=True, exist_ok=True)

def load(path: Path) -> dict:
    try:
        return json.loads(path.read_text()) if path.exists() else {}
    except Exception:
        return {}

def save(path: Path, data):
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(data, indent=2))
    tmp.replace(path)

# ─── Default admin user ─────────────────────────────────────────────────────────
def ensure_default_user():
    users = load(USERS_FILE)
    if not users:
        pw_hash = hashlib.sha256(b'remotepower').hexdigest()
        users = {'admin': {'password_hash': pw_hash, 'created': int(time.time())}}
        save(USERS_FILE, users)

ensure_default_user()

# ─── Auth helpers ───────────────────────────────────────────────────────────────
def make_token() -> str:
    return secrets.token_urlsafe(32)

def verify_token(token: str):
    """Return username if valid, None otherwise."""
    if not token:
        return None
    tokens = load(TOKENS_FILE)
    now = int(time.time())
    entry = tokens.get(token)
    if not entry:
        return None
    if now - entry['created'] > TOKEN_TTL:
        del tokens[token]
        save(TOKENS_FILE, tokens)
        return None
    return entry.get('user')

def cleanup_tokens():
    tokens = load(TOKENS_FILE)
    now = int(time.time())
    pruned = {k: v for k, v in tokens.items() if now - v['created'] <= TOKEN_TTL}
    if len(pruned) != len(tokens):
        save(TOKENS_FILE, pruned)

# ─── Request parsing ────────────────────────────────────────────────────────────
def get_body() -> bytes:
    length = int(os.environ.get('CONTENT_LENGTH', 0) or 0)
    if length > 0:
        return sys.stdin.buffer.read(length)
    return b''

def get_json_body() -> dict:
    try:
        return json.loads(get_body())
    except Exception:
        return {}

def get_token_from_request() -> str:
    return os.environ.get('HTTP_X_TOKEN', '')

def path_info() -> str:
    return os.environ.get('PATH_INFO', '').rstrip('/')

def method() -> str:
    return os.environ.get('REQUEST_METHOD', 'GET').upper()

# ─── Response helpers ───────────────────────────────────────────────────────────
def respond(status: int, data):
    reason = {200:'OK', 201:'Created', 400:'Bad Request', 401:'Unauthorized',
              403:'Forbidden', 404:'Not Found', 405:'Method Not Allowed',
              500:'Internal Server Error'}
    print(f"Status: {status} {reason.get(status, '')}")
    print("Content-Type: application/json")
    print("Cache-Control: no-store")
    print()
    print(json.dumps(data))
    sys.exit(0)

def require_auth() -> str:
    """Return username or exit 401."""
    token = get_token_from_request()
    username = verify_token(token)
    if not username:
        respond(401, {'error': 'Unauthorized'})
    return username

# ─── Webhook helper ─────────────────────────────────────────────────────────────
def fire_webhook(event: str, payload: dict):
    cfg = load(CONFIG_FILE)
    url = cfg.get('webhook_url', '').strip()
    if not url:
        return
    body = json.dumps({'event': event, 'ts': int(time.time()), **payload}).encode()
    req = urllib.request.Request(
        url, data=body,
        headers={'Content-Type': 'application/json', 'User-Agent': 'RemotePower/2'},
        method='POST',
    )
    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass  # webhook failure must never break the API

# ─── Offline webhook: runs on every API request (cheap file check) ──────────────
def check_offline_webhooks():
    devices = load(DEVICES_FILE)
    now = int(time.time())
    cfg = load(CONFIG_FILE)
    notified = cfg.get('offline_notified', {})
    changed = False

    for dev_id, dev in devices.items():
        last = dev.get('last_seen', 0)
        is_offline = (now - last) > ONLINE_TTL
        already = notified.get(dev_id, False)

        if is_offline and not already:
            fire_webhook('device_offline', {
                'device_id': dev_id,
                'name': dev.get('name', dev_id),
                'hostname': dev.get('hostname', ''),
                'last_seen': last,
            })
            notified[dev_id] = True
            changed = True
        elif not is_offline and already:
            notified[dev_id] = False
            changed = True

    if changed:
        cfg['offline_notified'] = notified
        save(CONFIG_FILE, cfg)

# ─── Route handlers ─────────────────────────────────────────────────────────────

def handle_login():
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    username = body.get('username', '').strip()
    password = body.get('password', '')

    users = load(USERS_FILE)
    user = users.get(username)
    if not user:
        respond(200, {'ok': False})

    stored = user.get('password_hash', '')
    if not verify_password(password, stored):
        respond(200, {'ok': False})

    maybe_rehash(username, password, stored)

    cleanup_tokens()
    token = make_token()
    tokens = load(TOKENS_FILE)
    tokens[token] = {'user': username, 'created': int(time.time())}
    save(TOKENS_FILE, tokens)
    respond(200, {'ok': True, 'token': token})


def handle_devices_list():
    require_auth()
    devices = load(DEVICES_FILE)
    now = int(time.time())
    result = []
    for dev_id, dev in devices.items():
        last_ping = dev.get('last_seen', 0)
        is_online = (now - last_ping) < ONLINE_TTL
        result.append({
            'id': dev_id,
            'name': dev.get('name', dev_id),
            'hostname': dev.get('hostname', ''),
            'os': dev.get('os', ''),
            'ip': dev.get('ip', ''),
            'mac': dev.get('mac', ''),
            'version': dev.get('version', ''),
            'last_seen': last_ping,
            'enrolled': dev.get('enrolled', 0),
            'online': is_online,
            'sysinfo': dev.get('sysinfo', {}),
        })
    result.sort(key=lambda x: x['name'].lower())
    respond(200, result)


def handle_device_delete(dev_id: str):
    require_auth()
    if method() != 'DELETE':
        respond(405, {'error': 'Method not allowed'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    del devices[dev_id]
    save(DEVICES_FILE, devices)
    cmds = load(CMDS_FILE)
    cmds.pop(dev_id, None)
    save(CMDS_FILE, cmds)
    respond(200, {'ok': True})


def handle_enroll_pin():
    require_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    pin = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
    pins = load(PINS_FILE)
    now = int(time.time())
    pins = {k: v for k, v in pins.items() if now - v['created'] < PIN_TTL}
    pins[pin] = {'created': now}
    save(PINS_FILE, pins)
    respond(200, {'pin': pin, 'expires': now + PIN_TTL})


def handle_enroll_register():
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    pin = str(body.get('pin', '')).strip()
    if not pin:
        respond(400, {'error': 'PIN required'})

    pins = load(PINS_FILE)
    now = int(time.time())
    entry = pins.get(pin)
    if not entry or (now - entry['created']) > PIN_TTL:
        respond(403, {'error': 'Invalid or expired PIN'})

    del pins[pin]
    save(PINS_FILE, pins)

    dev_id = secrets.token_urlsafe(12)
    hostname = body.get('hostname', 'unknown')
    devices = load(DEVICES_FILE)
    devices[dev_id] = {
        'name':     body.get('name', hostname),
        'hostname': hostname,
        'os':       body.get('os', ''),
        'ip':       body.get('ip', ''),
        'mac':      body.get('mac', ''),
        'version':  body.get('version', '1.0'),
        'enrolled': now,
        'last_seen': now,
        'token':    secrets.token_urlsafe(32),
    }
    save(DEVICES_FILE, devices)
    respond(201, {'ok': True, 'device_id': dev_id, 'token': devices[dev_id]['token']})


def handle_heartbeat():
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    dev_id    = body.get('device_id', '')
    dev_token = body.get('token', '')

    devices = load(DEVICES_FILE)
    dev = devices.get(dev_id)
    if not dev or not hmac.compare_digest(dev.get('token', ''), dev_token):
        respond(403, {'error': 'Unauthorized device'})

    now = int(time.time())
    dev['last_seen'] = now
    dev['ip']      = body.get('ip',      dev.get('ip', ''))
    dev['os']      = body.get('os',      dev.get('os', ''))
    dev['version'] = body.get('version', dev.get('version', ''))

    # Store sysinfo + journal when agent sends them (every ~10th poll)
    if 'sysinfo' in body:
        dev['sysinfo'] = body['sysinfo']
    if 'journal' in body:
        dev['journal'] = body['journal']  # list of strings

    devices[dev_id] = dev
    save(DEVICES_FILE, devices)

    # Pending commands — preserve original single-string format the agent expects
    cmds = load(CMDS_FILE)
    pending = cmds.get(dev_id, [])
    if pending:
        cmd = pending.pop(0)
        cmds[dev_id] = pending
        save(CMDS_FILE, cmds)
        respond(200, {'command': cmd})
    else:
        respond(200, {'command': None})


def handle_shutdown():
    require_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    dev_id = body.get('device_id', '')
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    cmds = load(CMDS_FILE)
    if dev_id not in cmds:
        cmds[dev_id] = []
    cmds[dev_id].append('shutdown')
    save(CMDS_FILE, cmds)
    respond(200, {'ok': True})


def handle_reboot():
    require_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    dev_id = body.get('device_id', '')
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    cmds = load(CMDS_FILE)
    if dev_id not in cmds:
        cmds[dev_id] = []
    cmds[dev_id].append('reboot')
    save(CMDS_FILE, cmds)
    respond(200, {'ok': True})


def handle_wol():
    require_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    dev_id = body.get('device_id', '')
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})

    mac = devices[dev_id].get('mac', '').strip()
    if not mac:
        respond(400, {'error': 'No MAC address on record for this device'})

    import re
    if not re.match(r'^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$', mac):
        respond(400, {'error': 'Invalid MAC address format'})

    mac_bytes = bytes.fromhex(mac.replace(':', '').replace('-', ''))
    magic = b'\xff' * 6 + mac_bytes * 16

    cfg = load(CONFIG_FILE)
    bcast = cfg.get('wol_broadcast', '255.255.255.255')
    port  = int(cfg.get('wol_port', 9))

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(magic, (bcast, port))
    except Exception as e:
        respond(500, {'error': f'WoL send failed: {e}'})

    respond(200, {'ok': True, 'mac': mac, 'broadcast': bcast})


def handle_sysinfo(dev_id: str):
    require_auth()
    devices = load(DEVICES_FILE)
    dev = devices.get(dev_id)
    if not dev:
        respond(404, {'error': 'Device not found'})
    respond(200, {
        'sysinfo': dev.get('sysinfo', {}),
        'journal': dev.get('journal', []),
    })


def handle_monitor_run():
    require_auth()
    cfg = load(CONFIG_FILE)
    monitors = cfg.get('monitors', [])
    results = []
    for m in monitors:
        mtype  = m.get('type', 'ping')
        target = m.get('target', '')
        label  = m.get('label', target)
        ok     = False
        detail = ''

        if mtype == 'ping':
            try:
                r = subprocess.run(['ping', '-c', '1', '-W', '2', target],
                                   capture_output=True, timeout=5)
                ok = r.returncode == 0
                detail = 'up' if ok else 'no reply'
            except Exception as e:
                detail = str(e)
        elif mtype == 'tcp':
            host, _, port_s = target.partition(':')
            port = int(port_s) if port_s else 80
            try:
                with socket.create_connection((host, port), timeout=3):
                    ok = True
                    detail = 'open'
            except Exception as e:
                detail = str(e)
        elif mtype == 'http':
            try:
                req = urllib.request.Request(target, method='HEAD')
                with urllib.request.urlopen(req, timeout=5) as resp:
                    ok = resp.status < 400
                    detail = str(resp.status)
            except urllib.error.HTTPError as e:
                detail = str(e.code)
            except Exception as e:
                detail = str(e)

        results.append({'label': label, 'type': mtype, 'target': target,
                        'ok': ok, 'detail': detail, 'checked': int(time.time())})

    respond(200, {'monitors': results})


def handle_config_get():
    require_auth()
    cfg = load(CONFIG_FILE)
    safe = {k: v for k, v in cfg.items()
            if k not in ('webhook_url', 'offline_notified')}
    safe['webhook_configured'] = bool(cfg.get('webhook_url', '').strip())
    respond(200, safe)


def handle_config_save():
    require_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    cfg = load(CONFIG_FILE)
    for key in ('webhook_url', 'wol_broadcast', 'wol_port', 'monitors'):
        if key in body:
            cfg[key] = body[key]
    save(CONFIG_FILE, cfg)
    respond(200, {'ok': True})


# ── Multi-user management ───────────────────────────────────────────────────────

def handle_users_list():
    require_auth()
    users = load(USERS_FILE)
    out = [{'username': u, 'created': d.get('created', 0)} for u, d in users.items()]
    respond(200, out)


def handle_user_create():
    require_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    username = body.get('username', '').strip()
    password = body.get('password', '')
    import re
    if not username or not re.match(r'^[a-zA-Z0-9_\-]{2,32}$', username):
        respond(400, {'error': 'Invalid username (2-32 chars, alphanumeric/_/-)'})
    if not password:
        respond(400, {'error': 'Password required'})
    users = load(USERS_FILE)
    if username in users:
        respond(400, {'error': 'User already exists'})
    users[username] = {'password_hash': hash_password(password),
                       'created': int(time.time())}
    save(USERS_FILE, users)
    respond(201, {'ok': True, 'username': username})


def handle_user_delete(username: str):
    requester = require_auth()
    if method() != 'DELETE':
        respond(405, {'error': 'Method not allowed'})
    if username == requester:
        respond(400, {'error': 'Cannot delete yourself'})
    users = load(USERS_FILE)
    if username not in users:
        respond(404, {'error': 'User not found'})
    if len(users) <= 1:
        respond(400, {'error': 'Cannot delete last admin'})
    del users[username]
    save(USERS_FILE, users)
    respond(200, {'ok': True})


def handle_user_passwd():
    requester = require_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    username = body.get('username', requester)
    old_pw   = body.get('old_password', '')
    new_pw   = body.get('new_password', '')
    if not new_pw:
        respond(400, {'error': 'new_password required'})
    users = load(USERS_FILE)
    user = users.get(username)
    if not user:
        respond(404, {'error': 'User not found'})
    if username == requester:
        if not verify_password(old_pw, user['password_hash']):
            respond(401, {'error': 'Old password incorrect'})
    users[username]['password_hash'] = hash_password(new_pw)
    save(USERS_FILE, users)
    respond(200, {'ok': True})


# ── Agent self-update ───────────────────────────────────────────────────────────

def handle_agent_version():
    """Return current server-side agent version + SHA-256 so clients can self-update."""
    cfg = load(CONFIG_FILE)
    agent_path = Path('/var/www/remotepower/agent/remotepower-agent')
    if not agent_path.exists():
        respond(200, {'version': None, 'sha256': None})
    sha = hashlib.sha256(agent_path.read_bytes()).hexdigest()
    respond(200, {
        'version': cfg.get('agent_version', 'unknown'),
        'sha256': sha,
    })


def handle_agent_download():
    """Serve the latest agent binary for self-update. No auth — token checked by agent."""
    agent_path = Path('/var/www/remotepower/agent/remotepower-agent')
    if not agent_path.exists():
        respond(404, {'error': 'Agent binary not found on server'})
    data = agent_path.read_bytes()
    print("Status: 200 OK")
    print("Content-Type: application/octet-stream")
    print(f"Content-Disposition: attachment; filename=remotepower-agent")
    print(f"Content-Length: {len(data)}")
    print("Cache-Control: no-store")
    print()
    sys.stdout.buffer.write(data)
    sys.exit(0)


# ─── Router ─────────────────────────────────────────────────────────────────────
def main():
    # Offline webhook check on every request — cheap file stat, no subprocess
    try:
        check_offline_webhooks()
    except Exception:
        pass

    pi = path_info()
    m  = method()

    # ── original routes (unchanged) ────────────────────────────────────────────
    if pi == '/api/login':
        handle_login()
    elif pi == '/api/devices' and m == 'GET':
        handle_devices_list()
    elif pi.startswith('/api/devices/') and m == 'DELETE':
        handle_device_delete(pi[len('/api/devices/'):])
    elif pi == '/api/enroll/pin':
        handle_enroll_pin()
    elif pi == '/api/enroll/register':
        handle_enroll_register()
    elif pi == '/api/heartbeat':
        handle_heartbeat()
    elif pi == '/api/shutdown':
        handle_shutdown()
    # ── new routes ──────────────────────────────────────────────────────────────
    elif pi == '/api/reboot':
        handle_reboot()
    elif pi == '/api/wol':
        handle_wol()
    elif pi.startswith('/api/devices/') and pi.endswith('/sysinfo') and m == 'GET':
        handle_sysinfo(pi[len('/api/devices/'):-len('/sysinfo')])
    elif pi == '/api/monitor' and m == 'GET':
        handle_monitor_run()
    elif pi == '/api/config' and m == 'GET':
        handle_config_get()
    elif pi == '/api/config' and m == 'POST':
        handle_config_save()
    elif pi == '/api/users' and m == 'GET':
        handle_users_list()
    elif pi == '/api/users' and m == 'POST':
        handle_user_create()
    elif pi.startswith('/api/users/') and not pi.endswith('/passwd') and m == 'DELETE':
        handle_user_delete(pi[len('/api/users/'):])
    elif pi == '/api/users/passwd' and m == 'POST':
        handle_user_passwd()
    elif pi == '/api/agent/version' and m == 'GET':
        handle_agent_version()
    elif pi == '/api/agent/download' and m == 'GET':
        handle_agent_download()
    else:
        respond(404, {'error': 'Not found'})

if __name__ == '__main__':
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        print("Status: 500 Internal Server Error")
        print("Content-Type: application/json")
        print()
        print(json.dumps({'error': str(e)}))

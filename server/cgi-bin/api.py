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
import subprocess
from pathlib import Path

# ─── Config ────────────────────────────────────────────────────────────────────
DATA_DIR  = Path(os.environ.get('RP_DATA_DIR', '/var/lib/remotepower'))
USERS_FILE   = DATA_DIR / 'users.json'
DEVICES_FILE = DATA_DIR / 'devices.json'
PINS_FILE    = DATA_DIR / 'pins.json'
TOKENS_FILE  = DATA_DIR / 'tokens.json'
CMDS_FILE    = DATA_DIR / 'commands.json'

TOKEN_TTL    = 86400 * 7   # 7 days
PIN_TTL      = 600          # 10 minutes
ONLINE_TTL   = 180          # device considered offline after 3 minutes

SECRET_KEY = os.environ.get('RP_SECRET', 'change-me-in-production-please')

# ─── Storage helpers ────────────────────────────────────────────────────────────
DATA_DIR.mkdir(parents=True, exist_ok=True)

def load(path: Path) -> dict | list:
    try:
        return json.loads(path.read_text()) if path.exists() else {}
    except Exception:
        return {}

def save(path: Path, data):
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(data, indent=2))
    tmp.replace(path)

# ─── Default admin user (hashed) ───────────────────────────────────────────────
def ensure_default_user():
    users = load(USERS_FILE)
    if not users:
        # Default: admin / remotepower  — change with: remotepower-passwd
        pw_hash = hashlib.sha256(b'remotepower').hexdigest()
        users = {'admin': {'password_hash': pw_hash, 'created': int(time.time())}}
        save(USERS_FILE, users)

ensure_default_user()

# ─── Auth helpers ───────────────────────────────────────────────────────────────
def make_token() -> str:
    raw = secrets.token_urlsafe(32)
    return raw

def verify_token(token: str) -> bool:
    if not token:
        return False
    tokens = load(TOKENS_FILE)
    now = int(time.time())
    entry = tokens.get(token)
    if not entry:
        return False
    if now - entry['created'] > TOKEN_TTL:
        del tokens[token]
        save(TOKENS_FILE, tokens)
        return False
    return True

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
def respond(status: int, data: dict):
    reason = {200:'OK', 201:'Created', 400:'Bad Request', 401:'Unauthorized',
              403:'Forbidden', 404:'Not Found', 405:'Method Not Allowed', 500:'Internal Server Error'}
    print(f"Status: {status} {reason.get(status, '')}")
    print("Content-Type: application/json")
    print("Cache-Control: no-store")
    print()
    print(json.dumps(data))
    sys.exit(0)

def require_auth():
    token = get_token_from_request()
    if not verify_token(token):
        respond(401, {'error': 'Unauthorized'})

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

    expected = user.get('password_hash', '')
    actual = hashlib.sha256(password.encode()).hexdigest()

    if not hmac.compare_digest(expected, actual):
        respond(200, {'ok': False})

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
            'version': dev.get('version', ''),
            'last_seen': last_ping,
            'enrolled': dev.get('enrolled', 0),
            'online': is_online,
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
    respond(200, {'ok': True})


def handle_enroll_pin():
    require_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    pin = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
    pins = load(PINS_FILE)
    # Purge expired PINs
    now = int(time.time())
    pins = {k: v for k, v in pins.items() if now - v['created'] < PIN_TTL}
    pins[pin] = {'created': now}
    save(PINS_FILE, pins)
    respond(200, {'pin': pin, 'expires': now + PIN_TTL})


def handle_enroll_register():
    """Called by client agent to register itself using a PIN."""
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

    # Remove used PIN
    del pins[pin]
    save(PINS_FILE, pins)

    # Register device
    dev_id = secrets.token_urlsafe(12)
    hostname = body.get('hostname', 'unknown')
    devices = load(DEVICES_FILE)
    devices[dev_id] = {
        'name': body.get('name', hostname),
        'hostname': hostname,
        'os': body.get('os', ''),
        'ip': body.get('ip', ''),
        'version': body.get('version', '1.0'),
        'enrolled': now,
        'last_seen': now,
        'token': secrets.token_urlsafe(32),
    }
    save(DEVICES_FILE, devices)
    respond(201, {'ok': True, 'device_id': dev_id, 'token': devices[dev_id]['token']})


def handle_heartbeat():
    """Client polls this endpoint every 60s to signal it's alive and fetch commands."""
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    dev_id = body.get('device_id', '')
    dev_token = body.get('token', '')

    devices = load(DEVICES_FILE)
    dev = devices.get(dev_id)
    if not dev or dev.get('token') != dev_token:
        respond(403, {'error': 'Unauthorized device'})

    # Update last_seen and metadata
    now = int(time.time())
    dev['last_seen'] = now
    dev['ip'] = body.get('ip', dev.get('ip', ''))
    dev['os'] = body.get('os', dev.get('os', ''))
    dev['version'] = body.get('version', dev.get('version', ''))
    devices[dev_id] = dev
    save(DEVICES_FILE, devices)

    # Check for pending commands
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
    """Queue a shutdown command for a device."""
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


# ─── Router ─────────────────────────────────────────────────────────────────────
def main():
    pi = path_info()
    m = method()

    if pi == '/api/login':
        handle_login()
    elif pi == '/api/devices' and m == 'GET':
        handle_devices_list()
    elif pi.startswith('/api/devices/') and m == 'DELETE':
        dev_id = pi[len('/api/devices/'):]
        handle_device_delete(dev_id)
    elif pi == '/api/enroll/pin':
        handle_enroll_pin()
    elif pi == '/api/enroll/register':
        handle_enroll_register()
    elif pi == '/api/heartbeat':
        handle_heartbeat()
    elif pi == '/api/shutdown':
        handle_shutdown()
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

#!/usr/bin/env python3
"""
RemotePower API backend — v1.2.0
Runs via fcgiwrap as a CGI script behind Nginx.
Flat-file storage in /var/lib/remotepower/
"""

import os
import re
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

# ─── Version ───────────────────────────────────────────────────────────────────
SERVER_VERSION = '1.3.0'

# ─── Config ────────────────────────────────────────────────────────────────────
DATA_DIR     = Path(os.environ.get('RP_DATA_DIR', '/var/lib/remotepower'))
USERS_FILE   = DATA_DIR / 'users.json'
DEVICES_FILE = DATA_DIR / 'devices.json'
PINS_FILE    = DATA_DIR / 'pins.json'
TOKENS_FILE  = DATA_DIR / 'tokens.json'
CMDS_FILE    = DATA_DIR / 'commands.json'
CONFIG_FILE  = DATA_DIR / 'config.json'
HISTORY_FILE   = DATA_DIR / 'history.json'
SCHEDULE_FILE  = DATA_DIR / 'schedule.json'
UPTIME_FILE    = DATA_DIR / 'uptime.json'
MON_HIST_FILE  = DATA_DIR / 'monitor_history.json'
CMD_OUTPUT_FILE= DATA_DIR / 'cmd_output.json'

TOKEN_TTL  = 86400 * 7  # 7 days
PIN_TTL    = 600         # 10 minutes
ONLINE_TTL = 180         # seconds before device considered offline

MAX_HISTORY      = 200   # command history entries to keep
MAX_MON_HISTORY  = 50    # monitor results to keep per target
MAX_CMD_OUTPUT   = 100   # stored command outputs to keep
PATCH_ALERT_KEY  = 'patch_alert_threshold'  # config key

# ─── bcrypt (optional, graceful SHA-256 fallback) ──────────────────────────────
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
    if stored.startswith('$2'):
        if not _BCRYPT:
            return False
        try:
            return _bcrypt.checkpw(plain.encode(), stored.encode())
        except Exception:
            return False
    return hmac.compare_digest(
        hashlib.sha256(plain.encode()).hexdigest(), stored
    )

def maybe_rehash(username: str, plain: str, stored: str):
    """Silently upgrade SHA-256 → bcrypt on next login."""
    if _BCRYPT and not stored.startswith('$2'):
        users = load(USERS_FILE)
        users[username]['password_hash'] = hash_password(plain)
        save(USERS_FILE, users)

# ─── Storage ───────────────────────────────────────────────────────────────────
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

# ─── Default admin ─────────────────────────────────────────────────────────────
def ensure_default_user():
    users = load(USERS_FILE)
    if not users:
        save(USERS_FILE, {
            'admin': {
                'password_hash': hashlib.sha256(b'remotepower').hexdigest(),
                'created': int(time.time()),
            }
        })

ensure_default_user()

# ─── Auth ──────────────────────────────────────────────────────────────────────
def make_token() -> str:
    return secrets.token_urlsafe(32)

def verify_token(token: str):
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

# ─── Request helpers ───────────────────────────────────────────────────────────
def get_body() -> bytes:
    length = int(os.environ.get('CONTENT_LENGTH', 0) or 0)
    return sys.stdin.buffer.read(length) if length > 0 else b''

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

def remote_addr() -> str:
    return os.environ.get('REMOTE_ADDR', '')

# ─── Response helpers ──────────────────────────────────────────────────────────
def respond(status: int, data):
    reason = {
        200: 'OK', 201: 'Created', 400: 'Bad Request',
        401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found',
        405: 'Method Not Allowed', 500: 'Internal Server Error',
    }
    print(f"Status: {status} {reason.get(status, '')}")
    print("Content-Type: application/json")
    print("Cache-Control: no-store")
    print()
    print(json.dumps(data))
    sys.exit(0)

def require_auth() -> str:
    token = get_token_from_request()
    username = verify_token(token)
    if not username:
        respond(401, {'error': 'Unauthorized'})
    return username

# ─── Command history ───────────────────────────────────────────────────────────
def log_command(actor: str, device_id: str, device_name: str, command: str):
    history = load(HISTORY_FILE)
    entries = history.get('entries', [])
    entries.append({
        'ts':          int(time.time()),
        'actor':       actor,
        'device_id':   device_id,
        'device_name': device_name,
        'command':     command,
    })
    # Keep only the last MAX_HISTORY entries
    history['entries'] = entries[-MAX_HISTORY:]
    save(HISTORY_FILE, history)

# ─── Webhook ───────────────────────────────────────────────────────────────────
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
        pass

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
                'name':      dev.get('name', dev_id),
                'hostname':  dev.get('hostname', ''),
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

    # Patch alert — fire webhook if any device exceeds threshold
    threshold = cfg.get(PATCH_ALERT_KEY)
    if threshold is not None:
        try:
            threshold = int(threshold)
            devices = load(DEVICES_FILE)
            alerted = cfg.get('patch_alerted', {})
            patch_changed = False
            for dev_id, dev in devices.items():
                si  = dev.get('sysinfo', {})
                pkg = si.get('packages', {})
                count = pkg.get('upgradable')
                if count is None:
                    continue
                over = count >= threshold
                was  = alerted.get(dev_id, False)
                if over and not was:
                    fire_webhook('patch_alert', {
                        'device_id':  dev_id,
                        'name':       dev.get('name', dev_id),
                        'hostname':   dev.get('hostname', ''),
                        'upgradable': count,
                        'threshold':  threshold,
                    })
                    alerted[dev_id] = True
                    patch_changed = True
                elif not over and was:
                    alerted[dev_id] = False
                    patch_changed = True
            if patch_changed:
                cfg['patch_alerted'] = alerted
                save(CONFIG_FILE, cfg)
        except Exception:
            pass

# ─── Handlers ──────────────────────────────────────────────────────────────────

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
            'id':       dev_id,
            'name':     dev.get('name', dev_id),
            'hostname': dev.get('hostname', ''),
            'os':       dev.get('os', ''),
            'ip':       dev.get('ip', ''),
            'mac':      dev.get('mac', ''),
            'version':  dev.get('version', ''),
            'tags':     dev.get('tags', []),
            'last_seen': last_ping,
            'enrolled': dev.get('enrolled', 0),
            'online':   is_online,
            'sysinfo':  dev.get('sysinfo', {}),
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


def handle_device_tags(dev_id: str):
    """PATCH /api/devices/:id/tags — set tags list."""
    actor = require_auth()
    if method() != 'PATCH':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    tags = body.get('tags', [])
    if not isinstance(tags, list):
        respond(400, {'error': 'tags must be a list'})
    # sanitise: strings only, max 32 chars, max 10 tags
    tags = [str(t)[:32] for t in tags[:10]]
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    devices[dev_id]['tags'] = tags
    save(DEVICES_FILE, devices)
    respond(200, {'ok': True, 'tags': tags})


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
    dev_id   = secrets.token_urlsafe(12)
    hostname = body.get('hostname', 'unknown')
    devices  = load(DEVICES_FILE)
    devices[dev_id] = {
        'name':      body.get('name', hostname),
        'hostname':  hostname,
        'os':        body.get('os', ''),
        'ip':        body.get('ip', ''),
        'mac':       body.get('mac', ''),
        'version':   body.get('version', '1.0'),
        'tags':      [],
        'enrolled':  now,
        'last_seen': now,
        'token':     secrets.token_urlsafe(32),
    }
    save(DEVICES_FILE, devices)
    respond(201, {'ok': True, 'device_id': dev_id, 'token': devices[dev_id]['token']})


def handle_heartbeat():
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body     = get_json_body()
    dev_id   = body.get('device_id', '')
    dev_token = body.get('token', '')
    devices  = load(DEVICES_FILE)
    dev      = devices.get(dev_id)
    if not dev or not hmac.compare_digest(dev.get('token', ''), dev_token):
        respond(403, {'error': 'Unauthorized device'})
    now = int(time.time())
    dev['last_seen'] = now
    dev['ip']        = body.get('ip',      dev.get('ip', ''))
    dev['os']        = body.get('os',      dev.get('os', ''))
    dev['version']   = body.get('version', dev.get('version', ''))
    if 'sysinfo' in body:
        dev['sysinfo'] = body['sysinfo']
    if 'journal' in body:
        dev['journal'] = body['journal']
    devices[dev_id] = dev
    save(DEVICES_FILE, devices)

    # Track online/offline uptime history (lightweight — one entry per state change)
    _record_uptime(dev_id, dev.get('name', dev_id), True)

    # Store exec output if agent sent it
    if 'cmd_output' in body:
        outputs = load(CMD_OUTPUT_FILE)
        if dev_id not in outputs:
            outputs[dev_id] = []
        outputs[dev_id].append({
            'ts':     int(time.time()),
            'cmd':    body['cmd_output'].get('cmd', ''),
            'output': body['cmd_output'].get('output', ''),
            'rc':     body['cmd_output'].get('rc', -1),
        })
        outputs[dev_id] = outputs[dev_id][-MAX_CMD_OUTPUT:]
        save(CMD_OUTPUT_FILE, outputs)

    cmds = load(CMDS_FILE)
    pending = cmds.get(dev_id, [])
    if pending:
        cmd = pending.pop(0)
        cmds[dev_id] = pending
        save(CMDS_FILE, cmds)
        respond(200, {'command': cmd})
    else:
        respond(200, {'command': None})


def _queue_command(dev_id: str, command: str, actor: str):
    """Queue a command and write to history."""
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    cmds = load(CMDS_FILE)
    if dev_id not in cmds:
        cmds[dev_id] = []
    # Deduplicate — don't queue same command twice
    if command not in cmds[dev_id]:
        cmds[dev_id].append(command)
    save(CMDS_FILE, cmds)
    log_command(actor, dev_id, devices[dev_id].get('name', dev_id), command)
    respond(200, {'ok': True})


def handle_shutdown():
    actor = require_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    _queue_command(get_json_body().get('device_id', ''), 'shutdown', actor)


def handle_reboot():
    actor = require_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    _queue_command(get_json_body().get('device_id', ''), 'reboot', actor)


def handle_update_device():
    """Queue an agent self-update command — no SSH needed."""
    actor = require_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    _queue_command(get_json_body().get('device_id', ''), 'update', actor)


def handle_wol():
    require_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body    = get_json_body()
    dev_id  = body.get('device_id', '')
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    mac = devices[dev_id].get('mac', '').strip()
    if not mac:
        respond(400, {'error': 'No MAC address on record for this device'})
    if not re.match(r'^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$', mac):
        respond(400, {'error': 'Invalid MAC address format'})
    mac_bytes = bytes.fromhex(mac.replace(':', '').replace('-', ''))
    magic     = b'\xff' * 6 + mac_bytes * 16
    cfg   = load(CONFIG_FILE)
    port  = int(cfg.get('wol_port', 9))
    # Unicast to last known IP if available (works over routed/VPN networks)
    # Fall back to broadcast
    device_ip = devices[dev_id].get('ip', '').strip()
    target    = device_ip if device_ip else cfg.get('wol_broadcast', '255.255.255.255')
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(magic, (target, port))
    except Exception as e:
        respond(500, {'error': f'WoL send failed: {e}'})
    respond(200, {'ok': True, 'mac': mac, 'target': target})


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
    cfg      = load(CONFIG_FILE)
    monitors = cfg.get('monitors', [])
    results  = []
    for m in monitors:
        mtype  = m.get('type', 'ping')
        target = m.get('target', '')
        label  = m.get('label', target)
        ok     = False
        detail = ''
        if mtype == 'ping':
            try:
                r = subprocess.run(
                    ['ping', '-c', '1', '-W', '2', target],
                    capture_output=True, timeout=5
                )
                ok     = r.returncode == 0
                detail = 'up' if ok else 'no reply'
            except Exception as e:
                detail = str(e)
        elif mtype == 'tcp':
            host, _, port_s = target.partition(':')
            port = int(port_s) if port_s else 80
            try:
                with socket.create_connection((host, port), timeout=3):
                    ok     = True
                    detail = 'open'
            except Exception as e:
                detail = str(e)
        elif mtype == 'http':
            try:
                req = urllib.request.Request(target, method='HEAD')
                with urllib.request.urlopen(req, timeout=5) as resp:
                    ok     = resp.status < 400
                    detail = str(resp.status)
            except urllib.error.HTTPError as e:
                detail = str(e.code)
            except Exception as e:
                detail = str(e)
        results.append({
            'label': label, 'type': mtype, 'target': target,
            'ok': ok, 'detail': detail, 'checked': int(time.time()),
        })
    # Persist monitor history (last N results per target)
    try:
        mh = load(MON_HIST_FILE)
        for r in results:
            key = r['label']
            if key not in mh:
                mh[key] = []
            mh[key].append({
                'ts':     r['checked'],
                'ok':     r['ok'],
                'detail': r['detail'],
            })
            mh[key] = mh[key][-MAX_MON_HISTORY:]
        save(MON_HIST_FILE, mh)
    except Exception:
        pass

    respond(200, {'monitors': results})


def handle_config_get():
    require_auth()
    cfg  = load(CONFIG_FILE)
    safe = {k: v for k, v in cfg.items()
            if k not in ('webhook_url', 'offline_notified')}
    safe['webhook_configured'] = bool(cfg.get('webhook_url', '').strip())
    respond(200, safe)


def handle_config_save():
    require_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    cfg  = load(CONFIG_FILE)
    for key in ('webhook_url', 'wol_broadcast', 'wol_port', 'monitors', 'patch_alert_threshold'):
        if key in body:
            cfg[key] = body[key]
    save(CONFIG_FILE, cfg)
    respond(200, {'ok': True})


def handle_history():
    require_auth()
    history = load(HISTORY_FILE)
    entries = history.get('entries', [])
    # Return newest first
    respond(200, list(reversed(entries)))


def handle_users_list():
    require_auth()
    users = load(USERS_FILE)
    respond(200, [
        {'username': u, 'created': d.get('created', 0)}
        for u, d in users.items()
    ])


def handle_user_create():
    require_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body     = get_json_body()
    username = body.get('username', '').strip()
    password = body.get('password', '')
    if not username or not re.match(r'^[a-zA-Z0-9_\-]{2,32}$', username):
        respond(400, {'error': 'Invalid username (2-32 chars, alphanumeric/_/-)'})
    if not password:
        respond(400, {'error': 'Password required'})
    users = load(USERS_FILE)
    if username in users:
        respond(400, {'error': 'User already exists'})
    users[username] = {
        'password_hash': hash_password(password),
        'created':       int(time.time()),
    }
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
    body     = get_json_body()
    username = body.get('username', requester)
    old_pw   = body.get('old_password', '')
    new_pw   = body.get('new_password', '')
    if not new_pw:
        respond(400, {'error': 'new_password required'})
    users = load(USERS_FILE)
    user  = users.get(username)
    if not user:
        respond(404, {'error': 'User not found'})
    if username == requester:
        if not verify_password(old_pw, user['password_hash']):
            respond(401, {'error': 'Old password incorrect'})
    users[username]['password_hash'] = hash_password(new_pw)
    save(USERS_FILE, users)
    respond(200, {'ok': True})


def handle_agent_version():
    cfg        = load(CONFIG_FILE)
    agent_path = Path('/var/www/remotepower/agent/remotepower-agent')
    if not agent_path.exists():
        respond(200, {'version': None, 'sha256': None})
    sha = hashlib.sha256(agent_path.read_bytes()).hexdigest()
    respond(200, {
        'version': cfg.get('agent_version', 'unknown'),
        'sha256':  sha,
    })


def handle_agent_download():
    agent_path = Path('/var/www/remotepower/agent/remotepower-agent')
    if not agent_path.exists():
        respond(404, {'error': 'Agent binary not found'})
    data = agent_path.read_bytes()
    print("Status: 200 OK")
    print("Content-Type: application/octet-stream")
    print("Content-Disposition: attachment; filename=remotepower-agent")
    print(f"Content-Length: {len(data)}")
    print("Cache-Control: no-store")
    print()
    sys.stdout.buffer.write(data)
    sys.exit(0)


def handle_version_check():
    """Check installed server version against latest GitHub release."""
    cfg   = load(CONFIG_FILE)
    local = cfg.get('server_version', SERVER_VERSION)
    try:
        req = urllib.request.Request(
            'https://api.github.com/repos/tyxak/remotepower/releases/latest',
            headers={'User-Agent': 'RemotePower'}
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read())
        latest = data.get('tag_name', '').lstrip('v')
    except Exception:
        latest = None

    def vt(v):
        try:
            return tuple(int(x) for x in v.split('.'))
        except Exception:
            return (0,)

    update_available = (
        latest is not None and
        local  != 'unknown' and
        vt(latest) > vt(local)
    )
    respond(200, {
        'current':          local,
        'latest':           latest,
        'update_available': update_available,
        'release_url':      'https://github.com/tyxak/remotepower/releases/latest',
    })



# ── Uptime tracking ────────────────────────────────────────────────────────────
def _record_uptime(dev_id: str, name: str, is_online: bool):
    """Record state changes only — keeps the file small."""
    uptime = load(UPTIME_FILE)
    if dev_id not in uptime:
        uptime[dev_id] = {'name': name, 'events': []}
    events = uptime[dev_id].get('events', [])
    # Only append if state changed
    last_state = events[-1]['online'] if events else None
    if last_state != is_online:
        events.append({'ts': int(time.time()), 'online': is_online})
        # Keep last 500 events per device
        uptime[dev_id]['events'] = events[-500:]
        uptime[dev_id]['name'] = name
        save(UPTIME_FILE, uptime)


def handle_uptime(dev_id: str):
    """Return uptime event history for a device."""
    require_auth()
    uptime = load(UPTIME_FILE)
    dev = uptime.get(dev_id, {})
    respond(200, {
        'device_id': dev_id,
        'name':      dev.get('name', dev_id),
        'events':    dev.get('events', []),
    })


def handle_monitor_history(label: str):
    """Return last N check results for a monitor target."""
    require_auth()
    mh  = load(MON_HIST_FILE)
    respond(200, {
        'label':   label,
        'history': mh.get(label, []),
    })


# ── Scheduled commands ─────────────────────────────────────────────────────────
def handle_schedule_list():
    require_auth()
    schedule = load(SCHEDULE_FILE)
    respond(200, schedule.get('jobs', []))


def handle_schedule_add():
    actor = require_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body    = get_json_body()
    dev_id  = body.get('device_id', '').strip()
    command = body.get('command', '').strip()
    run_at  = body.get('run_at', 0)  # unix timestamp

    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    if command not in ('shutdown', 'reboot'):
        respond(400, {'error': 'command must be shutdown or reboot'})
    if not isinstance(run_at, (int, float)) or run_at <= int(time.time()):
        respond(400, {'error': 'run_at must be a future unix timestamp'})

    schedule = load(SCHEDULE_FILE)
    jobs = schedule.get('jobs', [])
    job = {
        'id':          secrets.token_hex(6),
        'device_id':   dev_id,
        'device_name': devices[dev_id].get('name', dev_id),
        'command':     command,
        'run_at':      int(run_at),
        'actor':       actor,
        'created':     int(time.time()),
    }
    jobs.append(job)
    schedule['jobs'] = jobs
    save(SCHEDULE_FILE, schedule)
    respond(201, {'ok': True, 'job': job})


def handle_schedule_delete(job_id: str):
    require_auth()
    if method() != 'DELETE':
        respond(405, {'error': 'Method not allowed'})
    schedule = load(SCHEDULE_FILE)
    jobs = [j for j in schedule.get('jobs', []) if j['id'] != job_id]
    if len(jobs) == len(schedule.get('jobs', [])):
        respond(404, {'error': 'Job not found'})
    schedule['jobs'] = jobs
    save(SCHEDULE_FILE, schedule)
    respond(200, {'ok': True})


def process_schedule():
    """Run due scheduled jobs. Called on every API request — cheap file check."""
    schedule = load(SCHEDULE_FILE)
    jobs     = schedule.get('jobs', [])
    now      = int(time.time())
    remaining = []
    for job in jobs:
        if job['run_at'] <= now:
            dev_id  = job['device_id']
            command = job['command']
            devices = load(DEVICES_FILE)
            if dev_id in devices:
                cmds = load(CMDS_FILE)
                if dev_id not in cmds:
                    cmds[dev_id] = []
                if command not in cmds[dev_id]:
                    cmds[dev_id].append(command)
                save(CMDS_FILE, cmds)
                log_command(
                    f"scheduler({job['actor']})",
                    dev_id, job['device_name'], command
                )
        else:
            remaining.append(job)
    if len(remaining) != len(jobs):
        schedule['jobs'] = remaining
        save(SCHEDULE_FILE, schedule)


# ── Custom commands ────────────────────────────────────────────────────────────
def handle_custom_cmd():
    """Queue an arbitrary shell command for a device."""
    actor = require_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body    = get_json_body()
    dev_id  = body.get('device_id', '').strip()
    cmd_str = body.get('cmd', '').strip()

    if not cmd_str:
        respond(400, {'error': 'cmd required'})
    if len(cmd_str) > 512:
        respond(400, {'error': 'cmd too long (max 512 chars)'})
    # Block obviously dangerous patterns
    blocked = ['rm -rf /', 'mkfs', '> /dev/sd', 'dd if=']
    for b in blocked:
        if b in cmd_str:
            respond(400, {'error': f'Blocked pattern: {b}'})

    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})

    cmds = load(CMDS_FILE)
    if dev_id not in cmds:
        cmds[dev_id] = []
    # Custom commands are prefixed with 'exec:' so the agent knows
    cmds[dev_id].append(f'exec:{cmd_str}')
    save(CMDS_FILE, cmds)
    log_command(actor, dev_id, devices[dev_id].get('name', dev_id), f'exec:{cmd_str[:40]}')
    respond(200, {'ok': True})


def handle_cmd_output(dev_id: str):
    """Return stored command output for a device."""
    require_auth()
    outputs = load(CMD_OUTPUT_FILE)
    respond(200, {'outputs': outputs.get(dev_id, [])})


# ─── Router ────────────────────────────────────────────────────────────────────
def main():
    try:
        check_offline_webhooks()
    except Exception:
        pass
    try:
        process_schedule()
    except Exception:
        pass

    pi = path_info()
    m  = method()

    # Auth
    if pi == '/api/login':
        handle_login()

    # Devices
    elif pi == '/api/devices' and m == 'GET':
        handle_devices_list()
    elif pi.startswith('/api/devices/') and m == 'DELETE' and not pi.endswith('/tags'):
        handle_device_delete(pi[len('/api/devices/'):])
    elif pi.startswith('/api/devices/') and pi.endswith('/tags') and m == 'PATCH':
        handle_device_tags(pi[len('/api/devices/'):-len('/tags')])
    elif pi.startswith('/api/devices/') and pi.endswith('/sysinfo') and m == 'GET':
        handle_sysinfo(pi[len('/api/devices/'):-len('/sysinfo')])

    # Enrollment
    elif pi == '/api/enroll/pin':
        handle_enroll_pin()
    elif pi == '/api/enroll/register':
        handle_enroll_register()

    # Heartbeat
    elif pi == '/api/heartbeat':
        handle_heartbeat()

    # Commands
    elif pi == '/api/shutdown':
        handle_shutdown()
    elif pi == '/api/reboot':
        handle_reboot()
    elif pi == '/api/update-device':
        handle_update_device()
    elif pi == '/api/wol':
        handle_wol()

    # Monitor
    elif pi == '/api/monitor' and m == 'GET':
        handle_monitor_run()

    # Config
    elif pi == '/api/config' and m == 'GET':
        handle_config_get()
    elif pi == '/api/config' and m == 'POST':
        handle_config_save()

    # History
    elif pi == '/api/history' and m == 'GET':
        handle_history()

    # Users
    elif pi == '/api/users' and m == 'GET':
        handle_users_list()
    elif pi == '/api/users' and m == 'POST':
        handle_user_create()
    elif pi.startswith('/api/users/') and not pi.endswith('/passwd') and m == 'DELETE':
        handle_user_delete(pi[len('/api/users/'):])
    elif pi == '/api/users/passwd' and m == 'POST':
        handle_user_passwd()

    # Agent self-update
    elif pi == '/api/agent/version' and m == 'GET':
        handle_agent_version()
    elif pi == '/api/agent/download' and m == 'GET':
        handle_agent_download()

    # Server version check
    elif pi == '/api/version' and m == 'GET':
        handle_version_check()

    # Schedule
    elif pi == '/api/schedule' and m == 'GET':
        handle_schedule_list()
    elif pi == '/api/schedule' and m == 'POST':
        handle_schedule_add()
    elif pi.startswith('/api/schedule/') and m == 'DELETE':
        handle_schedule_delete(pi[len('/api/schedule/'):])

    # Custom commands
    elif pi == '/api/exec' and m == 'POST':
        handle_custom_cmd()
    elif pi.startswith('/api/devices/') and pi.endswith('/output') and m == 'GET':
        handle_cmd_output(pi[len('/api/devices/'):-len('/output')])

    # Uptime history
    elif pi.startswith('/api/devices/') and pi.endswith('/uptime') and m == 'GET':
        handle_uptime(pi[len('/api/devices/'):-len('/uptime')])

    # Monitor history
    elif pi == '/api/monitor/history' and m == 'GET':
        from urllib.parse import parse_qs, urlparse
        qs    = parse_qs(os.environ.get('QUERY_STRING', ''))
        label = qs.get('label', [''])[0]
        handle_monitor_history(label)

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

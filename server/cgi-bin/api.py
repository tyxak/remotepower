#!/usr/bin/env python3
"""
RemotePower API backend - v1.6.3
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
import urllib.parse
from pathlib import Path

SERVER_VERSION = '1.6.3'

DATA_DIR         = Path(os.environ.get('RP_DATA_DIR', '/var/lib/remotepower'))
USERS_FILE       = DATA_DIR / 'users.json'
DEVICES_FILE     = DATA_DIR / 'devices.json'
PINS_FILE        = DATA_DIR / 'pins.json'
TOKENS_FILE      = DATA_DIR / 'tokens.json'
CMDS_FILE        = DATA_DIR / 'commands.json'
CONFIG_FILE      = DATA_DIR / 'config.json'
HISTORY_FILE     = DATA_DIR / 'history.json'
SCHEDULE_FILE    = DATA_DIR / 'schedule.json'
UPTIME_FILE      = DATA_DIR / 'uptime.json'
MON_HIST_FILE    = DATA_DIR / 'monitor_history.json'
CMD_OUTPUT_FILE  = DATA_DIR / 'cmd_output.json'
METRICS_FILE     = DATA_DIR / 'metrics.json'
CMD_LIBRARY_FILE = DATA_DIR / 'cmd_library.json'
LONGPOLL_FILE    = DATA_DIR / 'longpoll.json'
APIKEYS_FILE     = DATA_DIR / 'apikeys.json'
RATELIMIT_FILE   = DATA_DIR / 'ratelimit.json'
AUDIT_LOG_FILE   = DATA_DIR / 'audit_log.json'
SESSIONS_META_FILE = DATA_DIR / 'sessions_meta.json'
WEBHOOK_LOG_FILE = DATA_DIR / 'webhook_log.json'

TOKEN_TTL  = 86400 * 7
PIN_TTL    = 600
ONLINE_TTL = 180

MAX_HISTORY       = 200
MAX_MON_HISTORY   = 50
MAX_CMD_OUTPUT    = 100
MAX_CMD_OUT_BYTES = 8192    # per-entry output cap enforced at ingestion
MAX_METRICS       = 1440
MAX_SCHEDULE_JOBS = 200     # cap on total schedule entries
PATCH_ALERT_KEY   = 'patch_alert_threshold'
MAX_AUDIT_LOG     = 500
MAX_WEBHOOK_LOG   = 100

# ── Login brute-force protection ───────────────────────────────────────────────
LOGIN_FAIL_WINDOW  = 300   # 5-minute rolling window
LOGIN_FAIL_MAX     = 10    # lock after this many failures
LOGIN_LOCKOUT_TIME = 600   # 10-minute lockout

# ── Input size limits ──────────────────────────────────────────────────────────
MAX_BODY_BYTES    = 65536   # 64 KB hard cap on any request body
MAX_HOSTNAME_LEN  = 253
MAX_NAME_LEN      = 64
MAX_OS_LEN        = 128
MAX_VERSION_LEN   = 32
MAX_IP_LEN        = 45      # IPv6 max
MAX_MAC_LEN       = 17
MAX_TAG_LEN       = 32
MAX_TAG_COUNT     = 10
MAX_GROUP_LEN     = 64
MAX_NOTES_LEN     = 1024
MAX_JOURNAL_LINES = 200
MAX_JOURNAL_LINE  = 512     # bytes per journal line

# ── ID validation regex — alphanumeric + hyphen/underscore, 1-64 chars ─────────
_SAFE_ID_RE = re.compile(r'^[A-Za-z0-9_\-]{1,64}$')

def _validate_id(value: str) -> bool:
    """Return True only if value is a safe resource ID (no path traversal etc.)."""
    return bool(value and _SAFE_ID_RE.match(value))

# ── bcrypt ─────────────────────────────────────────────────────────────────────
try:
    import bcrypt as _bcrypt
    _BCRYPT = True
except ImportError:
    _BCRYPT = False

def hash_password(plain):
    if _BCRYPT:
        return _bcrypt.hashpw(plain.encode(), _bcrypt.gensalt(12)).decode()
    return hashlib.sha256(plain.encode()).hexdigest()

def verify_password(plain, stored):
    if stored.startswith('$2'):
        if not _BCRYPT:
            return False
        try:
            return _bcrypt.checkpw(plain.encode(), stored.encode())
        except Exception:
            return False
    return hmac.compare_digest(hashlib.sha256(plain.encode()).hexdigest(), stored)

def maybe_rehash(username, plain, stored):
    if _BCRYPT and not stored.startswith('$2'):
        users = load(USERS_FILE)
        users[username]['password_hash'] = hash_password(plain)
        save(USERS_FILE, users)

# ── TOTP (2FA) ─────────────────────────────────────────────────────────────────
import hmac as _hmac_mod
import struct as _struct
import base64 as _base64

def _hotp(key_bytes, counter):
    """Generate HOTP value (RFC 4226)."""
    msg = _struct.pack('>Q', counter)
    h = _hmac_mod.new(key_bytes, msg, 'sha1').digest()
    offset = h[-1] & 0x0F
    code = _struct.unpack('>I', h[offset:offset+4])[0] & 0x7FFFFFFF
    return str(code % 1000000).zfill(6)

def _totp(secret_b32, window=1):
    """Generate current TOTP and accept within window."""
    key = _base64.b32decode(secret_b32.upper().replace(' ', ''), casefold=True)
    now = int(time.time()) // 30
    return [_hotp(key, now + i) for i in range(-window, window + 1)]

def _generate_totp_secret():
    """Generate a random base32 TOTP secret."""
    raw = secrets.token_bytes(20)
    return _base64.b32encode(raw).decode().rstrip('=')

def _totp_provisioning_uri(secret, username, issuer='RemotePower'):
    """Generate otpauth:// URI for QR code scanning."""
    return f'otpauth://totp/{urllib.parse.quote(issuer)}:{urllib.parse.quote(username)}?secret={secret}&issuer={urllib.parse.quote(issuer)}&digits=6&period=30'

# ── Storage ────────────────────────────────────────────────────────────────────
DATA_DIR.mkdir(parents=True, exist_ok=True)

def load(path):
    try:
        return json.loads(path.read_text()) if path.exists() else {}
    except Exception:
        return {}

def save(path, data):
    """Atomic write with restrictive permissions (owner read/write only)."""
    tmp = path.with_name(path.name + '.tmp')
    try:
        # Write to temp with mode 600
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(json.dumps(data, indent=2))
        tmp.replace(path)
        # Ensure final file has correct permissions regardless of umask
        os.chmod(str(path), 0o600)
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass
        raise

def ensure_default_user():
    users = load(USERS_FILE)
    if not users:
        save(USERS_FILE, {'admin': {
            'password_hash': hashlib.sha256(b'remotepower').hexdigest(),
            'created': int(time.time()),
            'role': 'admin',
        }})

ensure_default_user()

# ── Auth ───────────────────────────────────────────────────────────────────────
def make_token():
    return secrets.token_urlsafe(32)

def verify_token(token):
    """Returns (username, role) or (None, None).
    Session tokens: O(1) dict lookup.
    API keys: constant-time scan but with early-exit only after full scan
    to avoid timing oracle revealing which key prefix is valid.
    """
    if not token:
        return None, None

    # Session tokens
    tokens = load(TOKENS_FILE)
    now = int(time.time())
    entry = tokens.get(token)
    if entry:
        if now - entry['created'] > TOKEN_TTL:
            del tokens[token]
            save(TOKENS_FILE, tokens)
        else:
            username = entry.get('user')
            users = load(USERS_FILE)
            u = users.get(username)
            if not u:
                return None, None
            role = u.get('role', 'admin')
            return username, role

    # API keys — full constant-time scan (no early exit)
    apikeys = load(APIKEYS_FILE)
    matched_user = None
    matched_role = None
    for kid, kdata in apikeys.items():
        stored_key = kdata.get('key', '')
        # Pad both to same length for compare_digest (keys are fixed-length urlsafe)
        if len(stored_key) == len(token):
            if hmac.compare_digest(stored_key, token):
                if kdata.get('active', True):
                    exp = kdata.get('expires_at')
                    if exp is not None and int(time.time()) > exp:
                        continue  # expired key
                    matched_user = kdata.get('user', 'api')
                    matched_role = kdata.get('role', 'admin')
    if matched_user:
        return matched_user, matched_role

    return None, None

def cleanup_tokens():
    tokens = load(TOKENS_FILE)
    now = int(time.time())
    pruned = {k: v for k, v in tokens.items() if now - v['created'] <= TOKEN_TTL}
    if len(pruned) != len(tokens):
        save(TOKENS_FILE, pruned)

# ── Brute-force protection ─────────────────────────────────────────────────────
def _get_client_ip():
    """Best-effort client IP from CGI env. Nginx should set REMOTE_ADDR."""
    return os.environ.get('REMOTE_ADDR', '0.0.0.0')

def _check_login_ratelimit(username: str) -> bool:
    """Return True if this login attempt is allowed, False if locked out."""
    rl = load(RATELIMIT_FILE)
    now = int(time.time())
    key = f'login:{username}'
    entry = rl.get(key, {'failures': [], 'locked_until': 0})

    # Purge old failures outside window
    entry['failures'] = [t for t in entry['failures'] if now - t < LOGIN_FAIL_WINDOW]

    if entry.get('locked_until', 0) > now:
        return False  # still locked

    return True

def _record_login_failure(username: str):
    rl = load(RATELIMIT_FILE)
    now = int(time.time())
    key = f'login:{username}'
    entry = rl.get(key, {'failures': [], 'locked_until': 0})
    entry['failures'] = [t for t in entry['failures'] if now - t < LOGIN_FAIL_WINDOW]
    entry['failures'].append(now)
    if len(entry['failures']) >= LOGIN_FAIL_MAX:
        entry['locked_until'] = now + LOGIN_LOCKOUT_TIME
        entry['failures'] = []  # reset counter after lockout
    rl[key] = entry
    save(RATELIMIT_FILE, rl)

def _clear_login_failures(username: str):
    rl = load(RATELIMIT_FILE)
    key = f'login:{username}'
    if key in rl:
        del rl[key]
        save(RATELIMIT_FILE, rl)

# ── Request helpers ────────────────────────────────────────────────────────────
def get_body():
    length = int(os.environ.get('CONTENT_LENGTH', 0) or 0)
    # Hard cap: reject oversized bodies
    if length > MAX_BODY_BYTES:
        respond(413, {'error': 'Request body too large'})
    return sys.stdin.buffer.read(length) if length > 0 else b''

def get_json_body():
    try:
        raw = get_body()
        if not raw:
            return {}
        return json.loads(raw)
    except Exception:
        return {}

def get_token_from_request():
    return os.environ.get('HTTP_X_TOKEN', '')

def path_info():
    return os.environ.get('PATH_INFO', '').rstrip('/')

def method():
    return os.environ.get('REQUEST_METHOD', 'GET').upper()

# ── Response helpers ───────────────────────────────────────────────────────────
def respond(status, data):
    reason = {
        200: 'OK', 201: 'Created', 400: 'Bad Request', 401: 'Unauthorized',
        403: 'Forbidden', 404: 'Not Found', 405: 'Method Not Allowed',
        413: 'Request Entity Too Large', 429: 'Too Many Requests',
        500: 'Internal Server Error',
    }
    print(f"Status: {status} {reason.get(status, '')}")
    print("Content-Type: application/json")
    print("Cache-Control: no-store")
    print("X-Content-Type-Options: nosniff")
    print()
    print(json.dumps(data))
    sys.exit(0)

def require_auth(require_admin=False):
    token = get_token_from_request()
    username, role = verify_token(token)
    if not username:
        respond(401, {'error': 'Unauthorized'})
    if require_admin and role == 'viewer':
        respond(403, {'error': 'Viewer accounts cannot perform this action'})
    return username

def require_admin_auth():
    return require_auth(require_admin=True)

# ── Input sanitization helpers ─────────────────────────────────────────────────
_IP_RE  = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'  # IPv4
    r'|(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$'                                # IPv6 simplified
)
_MAC_RE = re.compile(r'^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$')
_VER_RE = re.compile(r'^\d{1,4}\.\d{1,4}(?:\.\d{1,4})?(?:[.\-]\w{1,16})?$')

def _sanitize_str(value, max_len, allow_empty=True):
    """Truncate and strip a string field."""
    if value is None:
        return ''
    s = str(value).strip()
    if not allow_empty and not s:
        return ''
    return s[:max_len]

def _sanitize_hostname(h):
    """RFC-1123 hostname: letters, digits, hyphens, dots. Max 253 chars."""
    h = _sanitize_str(h, MAX_HOSTNAME_LEN)
    # Strip anything that isn't hostname-safe
    h = re.sub(r'[^a-zA-Z0-9.\-]', '', h)
    return h[:MAX_HOSTNAME_LEN] or 'unknown'

def _sanitize_ip(ip):
    if not ip:
        return ''
    ip = str(ip).strip()[:MAX_IP_LEN]
    if _IP_RE.match(ip):
        return ip
    return ''

def _sanitize_mac(mac):
    if not mac:
        return ''
    mac = str(mac).strip()[:MAX_MAC_LEN]
    if _MAC_RE.match(mac):
        return mac
    return ''

def _sanitize_version(v):
    if not v:
        return ''
    v = str(v).strip()[:MAX_VERSION_LEN]
    if _VER_RE.match(v):
        return v
    return ''

def _sanitize_monitor_target(mtype, target):
    """Validate monitor targets to prevent SSRF and flag injection."""
    target = str(target).strip()[:512]
    if mtype == 'ping':
        # Only allow valid hostname/IP — no flags (dashes at start)
        host = re.sub(r'[^a-zA-Z0-9.\-]', '', target)
        if not host or host.startswith('-'):
            return None
        return host
    elif mtype == 'tcp':
        # host:port — validate both parts
        host, _, port_s = target.partition(':')
        host = re.sub(r'[^a-zA-Z0-9.\-]', '', host)
        if not host or host.startswith('-'):
            return None
        try:
            port = int(port_s)
            if not (1 <= port <= 65535):
                return None
        except (ValueError, TypeError):
            return None
        return f"{host}:{port}"
    elif mtype == 'http':
        # Only allow http:// and https://, no file:// or internal schemes
        parsed = urllib.parse.urlparse(target)
        if parsed.scheme not in ('http', 'https'):
            return None
        # Block private/loopback ranges (basic SSRF guard)
        host = parsed.hostname or ''
        blocked_hosts = ('localhost', '127.', '0.0.0.0', '169.254.', '10.', '192.168.', '172.')
        # Allow explicit override via config for intentional internal monitoring
        for b in blocked_hosts:
            if host == b.rstrip('.') or host.startswith(b):
                cfg = load(CONFIG_FILE)
                if not cfg.get('allow_internal_monitors', False):
                    return None
        return target
    return None

# ── Command history ────────────────────────────────────────────────────────────
def log_command(actor, device_id, device_name, command):
    history = load(HISTORY_FILE)
    entries = history.get('entries', [])
    entries.append({
        'ts':          int(time.time()),
        'actor':       _sanitize_str(actor, 64),
        'device_id':   _sanitize_str(device_id, 64),
        'device_name': _sanitize_str(device_name, MAX_NAME_LEN),
        'command':     _sanitize_str(command, 600),
    })
    history['entries'] = entries[-MAX_HISTORY:]
    save(HISTORY_FILE, history)

# ── Audit log with IP tracking ─────────────────────────────────────────────────
def audit_log(actor, action, detail='', source_ip=None):
    """Log action with actor, IP, and detail for security auditing."""
    al = load(AUDIT_LOG_FILE)
    entries = al.get('entries', [])
    entries.append({
        'ts':        int(time.time()),
        'actor':     _sanitize_str(actor, 64),
        'action':    _sanitize_str(action, 128),
        'detail':    _sanitize_str(detail, 512),
        'source_ip': _sanitize_ip(source_ip or _get_client_ip()),
        'user_agent': _sanitize_str(os.environ.get('HTTP_USER_AGENT', ''), 256),
    })
    al['entries'] = entries[-MAX_AUDIT_LOG:]
    save(AUDIT_LOG_FILE, al)

# ── Webhook ────────────────────────────────────────────────────────────────────
def _log_webhook(event, url, status, detail=''):
    """Append an entry to the webhook log (last MAX_WEBHOOK_LOG entries)."""
    try:
        wl = load(WEBHOOK_LOG_FILE)
        entries = wl.get('entries', [])
        entries.append({
            'ts':     int(time.time()),
            'event':  str(event)[:64],
            'url':    str(url)[:256],
            'status': str(status)[:16],
            'detail': str(detail)[:512],
        })
        wl['entries'] = entries[-MAX_WEBHOOK_LOG:]
        save(WEBHOOK_LOG_FILE, wl)
    except Exception:
        pass


def fire_webhook(event, payload):
    cfg = load(CONFIG_FILE)
    url = cfg.get('webhook_url', '').strip()
    if not url:
        return
    # Validate URL scheme before firing
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        _log_webhook(event, url, 'error', 'invalid scheme (must be http or https)')
        return
    # Sanitize payload values before sending
    safe_payload = {k: (str(v)[:256] if isinstance(v, str) else v) for k, v in payload.items()}

    # Build human-readable title + message for push services
    titles = {
        'device_offline': 'Device Offline',
        'device_online':  'Device Online',
        'command_queued':  'Command Queued',
        'command_executed': 'Command Executed',
        'patch_alert':     'Patch Alert',
        'monitor_down':    'Monitor Down',
        'monitor_up':      'Monitor Recovered',
        'test':            'Webhook Test',
    }
    title = titles.get(event, f'RemotePower: {event}')
    message = _webhook_message(event, safe_payload)
    priority = _webhook_priority(event)

    # ── Auto-detect service and build appropriate payload ─────────────────
    host = parsed.hostname or ''

    if 'discord.com' in host or 'discordapp.com' in host:
        # Discord expects { content: "..." } or { embeds: [...] }
        colors = {
            'device_offline': 0xEF4444, 'device_online': 0x22C55E,
            'monitor_down': 0xEF4444, 'monitor_up': 0x22C55E,
            'patch_alert': 0xF59E0B, 'command_queued': 0x3B7EFF,
            'command_executed': 0x3B7EFF, 'test': 0x7C3AED,
        }
        body = json.dumps({
            'username': 'RemotePower',
            'embeds': [{
                'title': title,
                'description': message,
                'color': colors.get(event, 0x3B7EFF),
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'footer': {'text': f'RemotePower {SERVER_VERSION}'},
            }],
        }).encode()
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': f'RemotePower/{SERVER_VERSION}',
        }

    elif 'hooks.slack.com' in host:
        # Slack expects { text: "..." } or { blocks: [...] }
        body = json.dumps({
            'text': f'*{title}*\n{message}',
        }).encode()
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': f'RemotePower/{SERVER_VERSION}',
        }

    else:
        # Generic / Ntfy / Gotify — JSON body + push-friendly headers
        body = json.dumps({
            'event': str(event)[:64],
            'ts': int(time.time()),
            'title': title,
            'message': message,
            'priority': priority,
            **safe_payload,
        }).encode()
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': f'RemotePower/{SERVER_VERSION}',
            # Ntfy / Gotify / Pushover compatible headers
            'X-Title': title,
            'X-Priority': str(priority),
            'X-Tags': _webhook_tags(event),
        }

    req = urllib.request.Request(url, data=body, headers=headers, method='POST')
    try:
        ctx = None
        if parsed.scheme == 'https':
            ctx = _get_ssl_context()
        resp = urllib.request.urlopen(req, timeout=10, context=ctx)
        _log_webhook(event, url, resp.status, f'OK ({resp.status})')
    except urllib.error.HTTPError as e:
        _log_webhook(event, url, e.code, f'HTTP {e.code}: {str(e.reason)[:200]}')
    except urllib.error.URLError as e:
        _log_webhook(event, url, 'error', f'URLError: {str(e.reason)[:200]}')
    except Exception as e:
        _log_webhook(event, url, 'error', f'{type(e).__name__}: {str(e)[:200]}')


def _webhook_message(event, payload):
    """Build a human-readable message string for push notifications."""
    name = payload.get('name', payload.get('device_id', 'unknown'))
    if event == 'device_offline':
        return f'{name} went offline (last seen: {_ts_fmt(payload.get("last_seen", 0))})'
    elif event == 'device_online':
        return f'{name} is back online'
    elif event == 'command_queued':
        return f'{payload.get("actor", "system")} queued "{payload.get("command", "?")}" on {name}'
    elif event == 'command_executed':
        return f'{name} executed "{payload.get("command", "?")}"'
    elif event == 'patch_alert':
        return f'{name} has {payload.get("upgradable", "?")} pending updates (threshold: {payload.get("threshold", "?")})'
    elif event == 'monitor_down':
        return f'Monitor "{payload.get("label", "?")}" ({payload.get("type", "?")}: {payload.get("target", "?")}) is DOWN — {payload.get("detail", "")}'
    elif event == 'monitor_up':
        return f'Monitor "{payload.get("label", "?")}" ({payload.get("type", "?")}: {payload.get("target", "?")}) recovered'
    elif event == 'test':
        return f'This is a test notification from RemotePower ({payload.get("server_version", "?")}). If you see this, webhooks are working!'
    return f'{event}: {name}'


def _webhook_priority(event):
    """Return numeric priority (1-5) for push services. 3=default, 4=high, 5=urgent."""
    if event in ('device_offline', 'monitor_down', 'patch_alert'):
        return 4
    if event in ('device_online', 'monitor_up'):
        return 3
    return 3


def _webhook_tags(event):
    """Return emoji tags for Ntfy-style push services."""
    tags = {
        'device_offline': 'red_circle,computer',
        'device_online':  'green_circle,computer',
        'command_queued':  'arrow_forward',
        'command_executed': 'white_check_mark',
        'patch_alert':     'warning,package',
        'monitor_down':    'red_circle,satellite',
        'monitor_up':      'green_circle,satellite',
        'test':            'white_check_mark,bell',
    }
    return tags.get(event, 'bell')


def _ts_fmt(ts):
    """Format a unix timestamp to human-readable string."""
    if not ts:
        return 'never'
    try:
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(ts)))
    except Exception:
        return str(ts)


def check_offline_webhooks():
    cfg = load(CONFIG_FILE)
    # Skip if offline webhooks are disabled
    if not cfg.get('offline_webhook_enabled', True):
        return
    devices = load(DEVICES_FILE)
    now = int(time.time())
    notified = cfg.get('offline_notified', {})
    changed = False
    for dev_id, dev in devices.items():
        # Skip devices that have monitoring disabled
        if not dev.get('monitored', True):
            continue
        last = dev.get('last_seen', 0)
        is_offline = (now - last) > ONLINE_TTL
        already = notified.get(dev_id, False)
        if is_offline and not already:
            fire_webhook('device_offline', {
                'device_id': dev_id, 'name': dev.get('name', dev_id),
                'hostname': dev.get('hostname', ''), 'last_seen': last,
            })
            notified[dev_id] = True; changed = True
        elif not is_offline and already:
            fire_webhook('device_online', {'device_id': dev_id, 'name': dev.get('name', dev_id)})
            notified[dev_id] = False; changed = True
    if changed:
        cfg['offline_notified'] = notified
        save(CONFIG_FILE, cfg)

    threshold = cfg.get(PATCH_ALERT_KEY)
    if threshold is not None:
        try:
            threshold = int(threshold)
            alerted = cfg.get('patch_alerted', {})
            patch_changed = False
            for dev_id, dev in devices.items():
                count = dev.get('sysinfo', {}).get('packages', {}).get('upgradable')
                if not isinstance(count, int):
                    continue
                over = count >= threshold
                was = alerted.get(dev_id, False)
                if over and not was:
                    fire_webhook('patch_alert', {
                        'device_id': dev_id, 'name': dev.get('name', dev_id),
                        'hostname': dev.get('hostname', ''), 'upgradable': count,
                        'threshold': threshold,
                    })
                    alerted[dev_id] = True; patch_changed = True
                elif not over and was:
                    alerted[dev_id] = False; patch_changed = True
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
    username = _sanitize_str(body.get('username', ''), 32)
    password = body.get('password', '')

    # Enforce password type and length
    if not isinstance(password, str) or len(password) > 1024:
        respond(200, {'ok': False})

    # Rate limit check (keyed by username to prevent enumeration via timing)
    if not _check_login_ratelimit(username):
        respond(429, {'error': 'Too many failed attempts — try again later'})

    users = load(USERS_FILE)
    user = users.get(username)

    # Always do a dummy verify to prevent timing oracle on username existence
    dummy_hash = hashlib.sha256(b'dummy').hexdigest()
    stored = user.get('password_hash', dummy_hash) if user else dummy_hash
    valid = verify_password(password, stored) and bool(user)

    if not valid:
        _record_login_failure(username)
        audit_log(username, 'login_failed', 'invalid credentials')
        # Small constant delay to slow brute-force even further
        time.sleep(0.5)
        respond(200, {'ok': False})

    _clear_login_failures(username)
    maybe_rehash(username, password, stored)

    # Check TOTP if user has 2FA enabled
    totp_secret = user.get('totp_secret')
    if totp_secret:
        totp_code = str(body.get('totp_code', '')).strip()
        if not totp_code:
            # Password correct but need TOTP — return special status
            respond(200, {'ok': False, 'totp_required': True})
        valid_codes = _totp(totp_secret)
        if totp_code not in valid_codes:
            _record_login_failure(username)
            audit_log(username, 'login_failed', 'invalid TOTP code')
            time.sleep(0.5)
            respond(200, {'ok': False, 'totp_required': True, 'totp_invalid': True})

    cleanup_tokens()
    audit_log(username, 'login', 'successful login')
    token = make_token()
    tokens = load(TOKENS_FILE)
    tokens[token] = {'user': username, 'created': int(time.time())}
    save(TOKENS_FILE, tokens)
    respond(200, {'ok': True, 'token': token, 'role': user.get('role', 'admin'), 'username': username})


def handle_devices_list():
    require_auth()
    devices = load(DEVICES_FILE)
    now = int(time.time())
    result = []
    for dev_id, dev in devices.items():
        last_ping = dev.get('last_seen', 0)
        is_online = (now - last_ping) < ONLINE_TTL
        missed = max(0, (now - last_ping) // 60) if last_ping else None
        offline_reason = None
        if not is_online and last_ping:
            offline_reason = 'missed_polls' if (now - last_ping) < 300 else 'offline'
        result.append({
            'id': dev_id, 'name': dev.get('name', dev_id), 'hostname': dev.get('hostname', ''),
            'os': dev.get('os', ''), 'ip': dev.get('ip', ''), 'mac': dev.get('mac', ''),
            'version': dev.get('version', ''), 'tags': dev.get('tags', []),
            'group': dev.get('group', ''), 'notes': dev.get('notes', ''),
            'icon': dev.get('icon', ''), 'monitored': dev.get('monitored', True),
            'last_seen': last_ping, 'enrolled': dev.get('enrolled', 0),
            'online': is_online, 'offline_reason': offline_reason, 'missed_polls': missed,
            'poll_interval': dev.get('poll_interval', 60), 'sysinfo': dev.get('sysinfo', {}),
        })
    result.sort(key=lambda x: (x.get('group', ''), x['name'].lower()))
    respond(200, result)


def handle_device_delete(dev_id):
    require_admin_auth()
    if method() != 'DELETE':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    del devices[dev_id]
    save(DEVICES_FILE, devices)
    cmds = load(CMDS_FILE); cmds.pop(dev_id, None); save(CMDS_FILE, cmds)
    respond(200, {'ok': True})


def handle_device_tags(dev_id):
    require_admin_auth()
    if method() != 'PATCH':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    body = get_json_body()
    tags = body.get('tags', [])
    if not isinstance(tags, list):
        respond(400, {'error': 'tags must be a list'})
    tags = [re.sub(r'[^a-zA-Z0-9_\-/]', '', str(t))[:MAX_TAG_LEN] for t in tags[:MAX_TAG_COUNT]]
    tags = [t for t in tags if t]  # drop empty after sanitize
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    devices[dev_id]['tags'] = tags
    save(DEVICES_FILE, devices)
    respond(200, {'ok': True, 'tags': tags})


def handle_device_notes(dev_id):
    require_admin_auth()
    if method() != 'PATCH':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    notes = _sanitize_str(get_json_body().get('notes', ''), MAX_NOTES_LEN)
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    devices[dev_id]['notes'] = notes
    save(DEVICES_FILE, devices)
    respond(200, {'ok': True, 'notes': notes})


def handle_device_group(dev_id):
    require_admin_auth()
    if method() != 'PATCH':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    raw = _sanitize_str(get_json_body().get('group', ''), MAX_GROUP_LEN)
    # Allow alphanumeric, hyphen, underscore, forward-slash for namespaces
    group = re.sub(r'[^a-zA-Z0-9_\-/]', '', raw)[:MAX_GROUP_LEN]
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    devices[dev_id]['group'] = group
    save(DEVICES_FILE, devices)
    respond(200, {'ok': True, 'group': group})


def handle_device_poll_interval(dev_id):
    require_admin_auth()
    if method() != 'PATCH':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    try:
        interval = int(get_json_body().get('poll_interval', 60))
    except (TypeError, ValueError):
        respond(400, {'error': 'poll_interval must be an integer'})
    interval = max(10, min(3600, interval))
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    devices[dev_id]['poll_interval'] = interval
    cmds = load(CMDS_FILE)
    if dev_id not in cmds:
        cmds[dev_id] = []
    cmds[dev_id] = [c for c in cmds[dev_id] if not c.startswith('poll_interval:')]
    cmds[dev_id].append(f'poll_interval:{interval}')
    save(CMDS_FILE, cmds)
    save(DEVICES_FILE, devices)
    respond(200, {'ok': True, 'poll_interval': interval})


def handle_device_icon(dev_id):
    require_admin_auth()
    if method() != 'PATCH':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    icon = _sanitize_str(get_json_body().get('icon', ''), 32)
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    devices[dev_id]['icon'] = icon
    save(DEVICES_FILE, devices)
    respond(200, {'ok': True, 'icon': icon})


def handle_device_monitored(dev_id):
    require_admin_auth()
    if method() != 'PATCH':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    body = get_json_body()
    monitored = bool(body.get('monitored', True))
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    devices[dev_id]['monitored'] = monitored
    save(DEVICES_FILE, devices)
    # If disabling monitoring, clear any pending offline notification
    if not monitored:
        cfg = load(CONFIG_FILE)
        notified = cfg.get('offline_notified', {})
        if dev_id in notified:
            del notified[dev_id]
            cfg['offline_notified'] = notified
            save(CONFIG_FILE, cfg)
    respond(200, {'ok': True, 'monitored': monitored})


def handle_enroll_pin():
    require_admin_auth()
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
    if not re.match(r'^\d{6}$', pin):
        respond(400, {'error': 'Invalid PIN format'})
    pins = load(PINS_FILE)
    now = int(time.time())
    entry = pins.get(pin)
    if not entry or (now - entry['created']) > PIN_TTL:
        respond(403, {'error': 'Invalid or expired PIN'})
    del pins[pin]; save(PINS_FILE, pins)

    # Sanitize all enrollment fields
    hostname = _sanitize_hostname(body.get('hostname', 'unknown'))
    name     = _sanitize_str(body.get('name', hostname), MAX_NAME_LEN) or hostname
    os_str   = _sanitize_str(body.get('os', ''), MAX_OS_LEN)
    ip       = _sanitize_ip(body.get('ip', ''))
    mac      = _sanitize_mac(body.get('mac', ''))
    version  = _sanitize_version(body.get('version', ''))

    # Re-enrollment: existing device_id must be validated and token must match
    existing_id = str(body.get('device_id', '')).strip()
    devices = load(DEVICES_FILE)
    if existing_id and _validate_id(existing_id) and existing_id in devices:
        dev = devices[existing_id]
        # Require the existing device token to authorize re-enrollment
        provided_token = str(body.get('token', '')).strip()
        if not provided_token or not hmac.compare_digest(
                dev.get('token', ''), provided_token):
            respond(403, {'error': 'Existing device token required for re-enrollment'})
        dev.update({
            'hostname': hostname, 'name': name, 'os': os_str,
            'ip': ip, 'mac': mac, 'version': version, 'last_seen': now,
        })
        save(DEVICES_FILE, devices)
        respond(200, {'ok': True, 'device_id': existing_id, 'token': dev['token'], 'reregistered': True})

    dev_id = secrets.token_urlsafe(12)
    devices[dev_id] = {
        'name': name, 'hostname': hostname, 'os': os_str,
        'ip': ip, 'mac': mac, 'version': version,
        'tags': [], 'group': '', 'notes': '',
        'enrolled': now, 'last_seen': now, 'poll_interval': 60,
        'token': secrets.token_urlsafe(32),
    }
    save(DEVICES_FILE, devices)
    respond(201, {'ok': True, 'device_id': dev_id, 'token': devices[dev_id]['token']})


def handle_heartbeat():
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    dev_id    = str(body.get('device_id', '')).strip()
    dev_token = str(body.get('token', '')).strip()

    if not _validate_id(dev_id):
        respond(403, {'error': 'Unauthorized device'})

    devices = load(DEVICES_FILE)
    dev = devices.get(dev_id)
    if not dev or not hmac.compare_digest(dev.get('token', ''), dev_token):
        respond(403, {'error': 'Unauthorized device'})

    now = int(time.time())
    dev['last_seen'] = now

    # Sanitize all fields coming from the agent
    dev['ip']      = _sanitize_ip(body.get('ip', dev.get('ip', '')))
    dev['os']      = _sanitize_str(body.get('os', dev.get('os', '')), MAX_OS_LEN)
    dev['version'] = _sanitize_version(body.get('version', dev.get('version', ''))) or dev.get('version', '')

    if 'sysinfo' in body and isinstance(body['sysinfo'], dict):
        si = body['sysinfo']
        # Sanitize sysinfo sub-fields
        safe_si = {}
        if 'uptime' in si:
            safe_si['uptime'] = _sanitize_str(si['uptime'], 128)
        if 'platform' in si:
            safe_si['platform'] = _sanitize_str(si['platform'], 256)
        if 'packages' in si and isinstance(si['packages'], dict):
            pkg = si['packages']
            safe_pkg = {}
            safe_pkg['manager'] = _sanitize_str(pkg.get('manager', ''), 32)
            upg = pkg.get('upgradable')
            safe_pkg['upgradable'] = int(upg) if isinstance(upg, int) and 0 <= upg <= 100000 else None
            safe_si['packages'] = safe_pkg
        if 'network' in si and isinstance(si['network'], list):
            safe_net = []
            for iface in si['network'][:20]:  # max 20 interfaces
                if isinstance(iface, dict):
                    safe_net.append({
                        'iface': _sanitize_str(iface.get('iface', ''), 32),
                        'ip':    _sanitize_ip(iface.get('ip', '')),
                        'mac':   _sanitize_mac(iface.get('mac', '')),
                    })
            safe_si['network'] = safe_net
        # Metrics
        for metric_key in ('cpu_percent', 'mem_percent', 'disk_percent'):
            val = si.get(metric_key)
            if isinstance(val, (int, float)) and 0.0 <= val <= 100.0:
                safe_si[metric_key] = round(float(val), 2)
        dev['sysinfo'] = safe_si
        _record_metrics(dev_id, safe_si)

    if 'journal' in body and isinstance(body['journal'], list):
        # Cap journal: max lines and max bytes per line
        lines = body['journal'][:MAX_JOURNAL_LINES]
        dev['journal'] = [str(l)[:MAX_JOURNAL_LINE] for l in lines]

    devices[dev_id] = dev
    save(DEVICES_FILE, devices)
    _record_uptime(dev_id, dev.get('name', dev_id), True)

    # executed_command webhook — validate it's one of our known command types
    if 'executed_command' in body:
        cmd_val = str(body['executed_command'])[:600]
        allowed_prefixes = ('shutdown', 'reboot', 'update', 'exec:', 'poll_interval:')
        if any(cmd_val.startswith(p) for p in allowed_prefixes):
            fire_webhook('command_executed', {
                'device_id': dev_id,
                'name':      dev.get('name', dev_id),
                'command':   cmd_val,
            })

    if 'cmd_output' in body and isinstance(body['cmd_output'], dict):
        co = body['cmd_output']
        outputs = load(CMD_OUTPUT_FILE)
        if dev_id not in outputs:
            outputs[dev_id] = []
        # Enforce per-entry output size cap
        raw_output = str(co.get('output', ''))[:MAX_CMD_OUT_BYTES]
        outputs[dev_id].append({
            'ts':     now,
            'cmd':    _sanitize_str(co.get('cmd', ''), 512),
            'output': raw_output,
            'rc':     int(co['rc']) if isinstance(co.get('rc'), int) else -1,
        })
        outputs[dev_id] = outputs[dev_id][-MAX_CMD_OUTPUT:]
        save(CMD_OUTPUT_FILE, outputs)
        _resolve_longpoll(dev_id, body['cmd_output'])

    cmds = load(CMDS_FILE)
    pending = cmds.get(dev_id, [])
    if pending:
        cmd = pending.pop(0); cmds[dev_id] = pending; save(CMDS_FILE, cmds)
        respond(200, {'command': cmd, 'poll_interval': dev.get('poll_interval', 60)})
    else:
        respond(200, {'command': None, 'poll_interval': dev.get('poll_interval', 60)})


def _record_metrics(dev_id, sysinfo):
    cpu  = sysinfo.get('cpu_percent')
    mem  = sysinfo.get('mem_percent')
    disk = sysinfo.get('disk_percent')
    if cpu is None and mem is None and disk is None:
        return
    metrics = load(METRICS_FILE)
    if dev_id not in metrics:
        metrics[dev_id] = []
    metrics[dev_id].append({'ts': int(time.time()), 'cpu': cpu, 'mem': mem, 'disk': disk})
    metrics[dev_id] = metrics[dev_id][-MAX_METRICS:]
    save(METRICS_FILE, metrics)


def _resolve_targets(body):
    """Resolve device_ids, tag, group, or single device_id — with length limits."""
    if 'device_ids' in body and isinstance(body['device_ids'], list):
        raw = body['device_ids'][:100]  # cap at 100 targets
        return [str(d).strip() for d in raw if _validate_id(str(d).strip())]
    if 'tag' in body:
        tag = re.sub(r'[^a-zA-Z0-9_\-/]', '', str(body['tag']))[:MAX_TAG_LEN]
        if not tag:
            return []
        devices = load(DEVICES_FILE)
        return [did for did, dev in devices.items() if tag in dev.get('tags', [])]
    if 'group' in body:
        grp = re.sub(r'[^a-zA-Z0-9_\-/]', '', str(body['group']))[:MAX_GROUP_LEN]
        if not grp:
            return []
        devices = load(DEVICES_FILE)
        return [did for did, dev in devices.items() if dev.get('group', '') == grp]
    dev_id = str(body.get('device_id', '')).strip()
    return [dev_id] if _validate_id(dev_id) else []


def _queue_command(dev_id, command, actor):
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    cmds = load(CMDS_FILE)
    if dev_id not in cmds:
        cmds[dev_id] = []
    if command not in cmds[dev_id]:
        cmds[dev_id].append(command)
    save(CMDS_FILE, cmds)
    log_command(actor, dev_id, devices[dev_id].get('name', dev_id), command)
    fire_webhook('command_queued', {
        'device_id': dev_id, 'name': devices[dev_id].get('name', dev_id),
        'command': command, 'actor': actor,
    })
    respond(200, {'ok': True})


def _queue_command_batch(dev_ids, command, actor):
    devices = load(DEVICES_FILE); cmds = load(CMDS_FILE); results = {}
    for dev_id in dev_ids:
        if not _validate_id(dev_id):
            results[dev_id] = {'ok': False, 'error': 'Invalid device ID'}; continue
        if dev_id not in devices:
            results[dev_id] = {'ok': False, 'error': 'Device not found'}; continue
        if dev_id not in cmds:
            cmds[dev_id] = []
        if command not in cmds[dev_id]:
            cmds[dev_id].append(command)
        log_command(actor, dev_id, devices[dev_id].get('name', dev_id), command)
        fire_webhook('command_queued', {
            'device_id': dev_id, 'name': devices[dev_id].get('name', dev_id),
            'command': command, 'actor': actor,
        })
        results[dev_id] = {'ok': True}
    save(CMDS_FILE, cmds)
    return results


def _check_exec_allowlist(dev_id, cmd_str, devices):
    """Return (allowed: bool, reason: str). Checks per-device allowlist."""
    allowed = devices[dev_id].get('allowed_commands', [])
    if allowed:
        if cmd_str not in allowed:
            return False, 'Command not in allowed_commands list for this device'
    else:
        # Denylist fallback
        for b in ['rm -rf /', 'mkfs', '> /dev/sd', 'dd if=', ':(){:|:&};:']:
            if b in cmd_str:
                return False, f'Blocked pattern: {b}'
    return True, ''


def handle_shutdown():
    actor = require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body = get_json_body(); ids = _resolve_targets(body)
    if not ids: respond(400, {'error': 'No valid device targets'})
    if len(ids) == 1: _queue_command(ids[0], 'shutdown', actor)
    else: respond(200, {'ok': True, 'results': _queue_command_batch(ids, 'shutdown', actor)})


def handle_reboot():
    actor = require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body = get_json_body(); ids = _resolve_targets(body)
    if not ids: respond(400, {'error': 'No valid device targets'})
    if len(ids) == 1: _queue_command(ids[0], 'reboot', actor)
    else: respond(200, {'ok': True, 'results': _queue_command_batch(ids, 'reboot', actor)})


def handle_update_device():
    actor = require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body = get_json_body(); ids = _resolve_targets(body)
    if not ids: respond(400, {'error': 'No valid device targets'})
    if len(ids) == 1: _queue_command(ids[0], 'update', actor)
    else: respond(200, {'ok': True, 'results': _queue_command_batch(ids, 'update', actor)})


# Single self-detecting upgrade command. Runs on the device and picks
# apt-get / dnf / pacman at execution time, so it works even on freshly
# restarted agents that haven't sent a sysinfo poll yet (patch info is
# only collected every PATCH_EVERY polls = ~3h after agent restart, so
# relying on the server-side sysinfo cache was fragile).
#
# For apt: writes a one-line apt config to a tempfile and exports APT_CONFIG,
# so every apt-get call in the chain inherits APT::Sandbox::User=root and
# skips the seteuid(_apt) drop that fails under systemd hardening.
_UPGRADE_CMD = (
    'set -e; '
    'if command -v apt-get >/dev/null 2>&1; then '
    '  APT_CONFIG=$(mktemp); '
    '  trap "rm -f $APT_CONFIG" EXIT; '
    '  printf \'APT::Sandbox::User "root";\\n'
    'Dpkg::Options:: "--force-confdef";\\n'
    'Dpkg::Options:: "--force-confold";\\n\' > "$APT_CONFIG"; '
    '  export APT_CONFIG DEBIAN_FRONTEND=noninteractive; '
    '  apt-get update && apt-get -y upgrade && apt-get -y autoremove && apt-get clean; '
    'elif command -v dnf >/dev/null 2>&1; then '
    '  dnf -y upgrade; '
    'elif command -v pacman >/dev/null 2>&1; then '
    '  pacman -Syu --noconfirm; '
    'else '
    '  echo "No supported package manager (apt-get/dnf/pacman) found" >&2; '
    '  exit 2; '
    'fi'
)


def handle_upgrade_device():
    """
    Queue an OS package-manager upgrade (apt/dnf/pacman) per device.
    The command self-detects the package manager at runtime on each device,
    so it works even before the agent has sent its first sysinfo poll.
    Output arrives on the next heartbeat via the existing exec: channel.
    """
    actor = require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body = get_json_body(); ids = _resolve_targets(body)
    if not ids: respond(400, {'error': 'No valid device targets'})

    devices = load(DEVICES_FILE); cmds = load(CMDS_FILE); results = {}
    queued_str = f'exec:{_UPGRADE_CMD}'
    for dev_id in ids:
        if not _validate_id(dev_id):
            results[dev_id] = {'ok': False, 'error': 'Invalid device ID'}; continue
        dev = devices.get(dev_id)
        if not dev:
            results[dev_id] = {'ok': False, 'error': 'Device not found'}; continue
        if dev_id not in cmds:
            cmds[dev_id] = []
        if queued_str not in cmds[dev_id]:
            cmds[dev_id].append(queued_str)
        log_command(actor, dev_id, dev.get('name', dev_id), 'upgrade packages')
        fire_webhook('command_queued', {
            'device_id': dev_id, 'name': dev.get('name', dev_id),
            'command': 'upgrade packages', 'actor': actor,
        })
        results[dev_id] = {'ok': True}
    save(CMDS_FILE, cmds)
    if len(ids) == 1:
        r = results[ids[0]]
        if r.get('ok'): respond(200, {'ok': True})
        else:           respond(400, {'error': r.get('error', 'Failed')})
    respond(200, {'ok': True, 'results': results})


def handle_wol():
    require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    dev_id = str(body.get('device_id', '')).strip()
    if not _validate_id(dev_id): respond(404, {'error': 'Device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices: respond(404, {'error': 'Device not found'})
    mac = devices[dev_id].get('mac', '').strip()
    if not mac: respond(400, {'error': 'No MAC address on record for this device'})
    if not _MAC_RE.match(mac): respond(400, {'error': 'Invalid MAC address format'})
    mac_bytes = bytes.fromhex(mac.replace(':', '').replace('-', ''))
    magic = b'\xff' * 6 + mac_bytes * 16
    cfg = load(CONFIG_FILE)
    try:
        port = int(cfg.get('wol_port', 9))
        if not (1 <= port <= 65535):
            port = 9
    except (ValueError, TypeError):
        port = 9
    device_ip = _sanitize_ip(devices[dev_id].get('ip', ''))
    broadcast  = _sanitize_ip(cfg.get('wol_broadcast', '')) or '255.255.255.255'
    target = device_ip if device_ip else broadcast
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(magic, (target, port))
    except Exception as e:
        respond(500, {'error': 'WoL send failed'})
    respond(200, {'ok': True, 'mac': mac, 'target': target})


def handle_sysinfo(dev_id):
    require_auth()
    if not _validate_id(dev_id): respond(404, {'error': 'Device not found'})
    devices = load(DEVICES_FILE); dev = devices.get(dev_id)
    if not dev: respond(404, {'error': 'Device not found'})
    respond(200, {'sysinfo': dev.get('sysinfo', {}), 'journal': dev.get('journal', [])})


def handle_metrics(dev_id):
    require_auth()
    if not _validate_id(dev_id): respond(404, {'error': 'Device not found'})
    metrics = load(METRICS_FILE)
    respond(200, {'device_id': dev_id, 'metrics': metrics.get(dev_id, [])})


def handle_monitor_run():
    require_auth()
    cfg = load(CONFIG_FILE); monitors = cfg.get('monitors', []); results = []
    for m in monitors:
        mtype  = m.get('type', 'ping')
        raw_target = m.get('target', '')
        label  = _sanitize_str(m.get('label', raw_target), 128)

        # Validate target before use
        target = _sanitize_monitor_target(mtype, raw_target)
        if target is None:
            results.append({'label': label, 'type': mtype, 'target': raw_target,
                            'ok': False, 'detail': 'blocked: invalid target', 'checked': int(time.time())})
            continue

        ok = False; detail = ''
        if mtype == 'ping':
            try:
                r = subprocess.run(
                    ['ping', '-c', '1', '-W', '2', '--', target],  # '--' prevents flag injection
                    capture_output=True, timeout=5)
                ok = r.returncode == 0; detail = 'up' if ok else 'no reply'
            except Exception as e:
                detail = 'error'
        elif mtype == 'tcp':
            host, _, port_s = target.partition(':')
            port = int(port_s)
            try:
                with socket.create_connection((host, port), timeout=3):
                    ok = True; detail = 'open'
            except Exception:
                detail = 'closed'
        elif mtype == 'http':
            try:
                req = urllib.request.Request(target, method='HEAD')
                ctx = _get_ssl_context()
                with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                    ok = resp.status < 400; detail = str(resp.status)
            except urllib.error.HTTPError as e:
                detail = str(e.code)
            except Exception:
                detail = 'error'
        results.append({'label': label, 'type': mtype, 'target': target,
                        'ok': ok, 'detail': detail, 'checked': int(time.time())})
    try:
        mh = load(MON_HIST_FILE)
        cfg = load(CONFIG_FILE)
        mon_notified = cfg.get('monitor_notified', {})
        mon_webhook_on = cfg.get('monitor_webhook_enabled', True)
        mon_changed = False
        for r in results:
            key = r['label']
            if key not in mh: mh[key] = []
            mh[key].append({'ts': r['checked'], 'ok': r['ok'], 'detail': r['detail']})
            mh[key] = mh[key][-MAX_MON_HISTORY:]
            # Fire webhook on monitor state change
            if mon_webhook_on:
                was_down = mon_notified.get(key, False)
                if not r['ok'] and not was_down:
                    fire_webhook('monitor_down', {
                        'label': r['label'], 'type': r['type'],
                        'target': r['target'], 'detail': r['detail'],
                    })
                    mon_notified[key] = True; mon_changed = True
                elif r['ok'] and was_down:
                    fire_webhook('monitor_up', {
                        'label': r['label'], 'type': r['type'],
                        'target': r['target'], 'detail': r['detail'],
                    })
                    mon_notified[key] = False; mon_changed = True
        save(MON_HIST_FILE, mh)
        if mon_changed:
            cfg['monitor_notified'] = mon_notified
            save(CONFIG_FILE, cfg)
    except Exception:
        pass
    respond(200, {'monitors': results})


def _get_ssl_context():
    """Return a strict SSL context for outgoing HTTPS requests."""
    import ssl
    ctx = ssl.create_default_context()
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    return ctx


def handle_config_get():
    require_auth()
    cfg = load(CONFIG_FILE)
    safe = {k: v for k, v in cfg.items()
            if k not in ('offline_notified', 'patch_alerted', 'monitor_notified',
                         '_github_latest_version', '_github_latest_ts')}
    safe['webhook_configured'] = bool(cfg.get('webhook_url', '').strip())
    safe.setdefault('offline_webhook_enabled', True)
    safe.setdefault('monitor_webhook_enabled', True)
    safe.setdefault('monitor_interval', 300)
    respond(200, safe)


def handle_config_save():
    require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body = get_json_body(); cfg = load(CONFIG_FILE)

    if 'webhook_url' in body:
        url = str(body['webhook_url']).strip()
        if url:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme not in ('http', 'https'):
                respond(400, {'error': 'webhook_url must be http or https'})
        cfg['webhook_url'] = url

    if 'offline_webhook_enabled' in body:
        cfg['offline_webhook_enabled'] = bool(body['offline_webhook_enabled'])

    if 'monitor_webhook_enabled' in body:
        cfg['monitor_webhook_enabled'] = bool(body['monitor_webhook_enabled'])

    if 'wol_broadcast' in body:
        cfg['wol_broadcast'] = _sanitize_ip(body['wol_broadcast']) or '255.255.255.255'

    if 'wol_port' in body:
        try:
            port = int(body['wol_port'])
            if not (1 <= port <= 65535):
                respond(400, {'error': 'wol_port must be 1–65535'})
            cfg['wol_port'] = port
        except (ValueError, TypeError):
            respond(400, {'error': 'wol_port must be an integer'})

    if 'patch_alert_threshold' in body:
        val = body['patch_alert_threshold']
        if val is None or val == '' or val == 0:
            cfg.pop('patch_alert_threshold', None)
            cfg.pop('patch_alerted', None)
        else:
            try:
                t = int(val)
                if t < 1: respond(400, {'error': 'patch_alert_threshold must be >= 1'})
                cfg['patch_alert_threshold'] = t
            except (ValueError, TypeError):
                respond(400, {'error': 'patch_alert_threshold must be an integer'})

    if 'monitors' in body and isinstance(body['monitors'], list):
        validated = []
        for m in body['monitors'][:50]:  # max 50 monitors
            if not isinstance(m, dict):
                continue
            mtype = m.get('type', '')
            if mtype not in ('ping', 'tcp', 'http'):
                continue
            raw_target = str(m.get('target', ''))
            target = _sanitize_monitor_target(mtype, raw_target)
            if target is None:
                respond(400, {'error': f'Invalid monitor target: {raw_target[:80]}'})
            validated.append({
                'label':  _sanitize_str(m.get('label', target), 128),
                'type':   mtype,
                'target': target,
            })
        cfg['monitors'] = validated

    if 'allow_internal_monitors' in body:
        cfg['allow_internal_monitors'] = bool(body['allow_internal_monitors'])

    if 'monitor_interval' in body:
        try:
            mi = int(body['monitor_interval'])
            mi = max(60, min(3600, mi))
            cfg['monitor_interval'] = mi
        except (ValueError, TypeError):
            respond(400, {'error': 'monitor_interval must be an integer (60–3600)'})

    save(CONFIG_FILE, cfg)
    respond(200, {'ok': True})


def handle_history():
    require_auth()
    history = load(HISTORY_FILE)
    respond(200, list(reversed(history.get('entries', []))))


def handle_history_clear():
    actor = require_admin_auth()
    if method() != 'DELETE': respond(405, {'error': 'Method not allowed'})
    save(HISTORY_FILE, {'entries': []})
    audit_log(actor, 'clear_history', 'command history cleared')
    respond(200, {'ok': True})


def handle_users_list():
    require_auth()
    users = load(USERS_FILE)
    respond(200, [{'username': u, 'created': d.get('created', 0), 'role': d.get('role', 'admin')}
                  for u, d in users.items()])


def handle_user_create():
    require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    username = _sanitize_str(body.get('username', ''), 32)
    password = body.get('password', '')
    role     = body.get('role', 'admin')
    if role not in ('admin', 'viewer'): respond(400, {'error': 'role must be admin or viewer'})
    if not username or not re.match(r'^[a-zA-Z0-9_\-]{2,32}$', username):
        respond(400, {'error': 'Invalid username (2-32 chars, alphanumeric/_/-)'})
    if not isinstance(password, str) or not password or len(password) > 1024:
        respond(400, {'error': 'Password required (max 1024 chars)'})
    users = load(USERS_FILE)
    if username in users: respond(400, {'error': 'User already exists'})
    users[username] = {'password_hash': hash_password(password), 'created': int(time.time()), 'role': role}
    save(USERS_FILE, users)
    respond(201, {'ok': True, 'username': username, 'role': role})


def handle_user_delete(username):
    requester = require_admin_auth()
    if method() != 'DELETE': respond(405, {'error': 'Method not allowed'})
    if not re.match(r'^[a-zA-Z0-9_\-]{2,32}$', username):
        respond(404, {'error': 'User not found'})
    if username == requester: respond(400, {'error': 'Cannot delete yourself'})
    users = load(USERS_FILE)
    if username not in users: respond(404, {'error': 'User not found'})
    admins = [u for u, d in users.items() if d.get('role', 'admin') == 'admin']
    if len(admins) <= 1 and users[username].get('role', 'admin') == 'admin':
        respond(400, {'error': 'Cannot delete last admin'})
    del users[username]; save(USERS_FILE, users)
    respond(200, {'ok': True})


def handle_user_passwd():
    requester = require_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    username = _sanitize_str(body.get('username', requester), 32)
    old_pw   = body.get('old_password', '')
    new_pw   = body.get('new_password', '')

    if not isinstance(new_pw, str) or not new_pw or len(new_pw) > 1024:
        respond(400, {'error': 'new_password required (max 1024 chars)'})

    users = load(USERS_FILE)
    _, requester_role = verify_token(get_token_from_request())

    # Non-admins can only change their own password
    if username != requester and requester_role != 'admin':
        respond(403, {'error': 'Cannot change another user\'s password'})

    user = users.get(username)
    if not user: respond(404, {'error': 'User not found'})

    # Changing own password always requires old password
    if username == requester:
        if not verify_password(old_pw, user['password_hash']):
            respond(401, {'error': 'Old password incorrect'})

    users[username]['password_hash'] = hash_password(new_pw)
    save(USERS_FILE, users)

    # Invalidate all existing sessions for this user on password change
    tokens = load(TOKENS_FILE)
    tokens = {k: v for k, v in tokens.items() if v.get('user') != username}
    save(TOKENS_FILE, tokens)

    respond(200, {'ok': True})


def handle_totp_setup():
    """Generate a TOTP secret for the current user. Does NOT enable until confirmed."""
    username = require_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    secret = _generate_totp_secret()
    uri = _totp_provisioning_uri(secret, username)
    # Store pending secret — not active until confirmed
    users = load(USERS_FILE)
    if username not in users: respond(404, {'error': 'User not found'})
    users[username]['totp_pending'] = secret
    save(USERS_FILE, users)
    audit_log(username, 'totp_setup', 'generated new TOTP secret')
    respond(200, {'ok': True, 'secret': secret, 'uri': uri,
                  'note': 'Scan the QR code or enter the secret in your authenticator app, then confirm with /api/totp/confirm'})


def handle_totp_confirm():
    """Confirm TOTP setup by verifying a code from the authenticator app."""
    username = require_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    code = str(body.get('code', '')).strip()
    users = load(USERS_FILE)
    if username not in users: respond(404, {'error': 'User not found'})
    pending = users[username].get('totp_pending')
    if not pending: respond(400, {'error': 'No pending TOTP setup — call /api/totp/setup first'})
    valid_codes = _totp(pending)
    if code not in valid_codes:
        respond(400, {'error': 'Invalid code — check your authenticator app and try again'})
    # Activate TOTP
    users[username]['totp_secret'] = pending
    del users[username]['totp_pending']
    save(USERS_FILE, users)
    audit_log(username, 'totp_enabled', '2FA activated')
    respond(200, {'ok': True, 'message': '2FA is now enabled. You will need your authenticator code at each login.'})


def handle_totp_disable():
    """Disable 2FA for the current user (requires password confirmation)."""
    username = require_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    password = body.get('password', '')
    users = load(USERS_FILE)
    if username not in users: respond(404, {'error': 'User not found'})
    if not verify_password(password, users[username].get('password_hash', '')):
        respond(401, {'error': 'Password incorrect'})
    users[username].pop('totp_secret', None)
    users[username].pop('totp_pending', None)
    save(USERS_FILE, users)
    audit_log(username, 'totp_disabled', '2FA deactivated')
    respond(200, {'ok': True, 'message': '2FA has been disabled.'})


def handle_totp_status():
    """Check if 2FA is enabled for the current user."""
    username = require_auth()
    users = load(USERS_FILE)
    if username not in users: respond(404, {'error': 'User not found'})
    enabled = bool(users[username].get('totp_secret'))
    respond(200, {'enabled': enabled, 'username': username})


def handle_agent_version():
    agent_path = Path('/var/www/remotepower/agent/remotepower-agent')
    if not agent_path.exists():
        respond(200, {'version': None, 'sha256': None})
    cfg = load(CONFIG_FILE)
    sha = hashlib.sha256(agent_path.read_bytes()).hexdigest()
    respond(200, {'version': cfg.get('agent_version', 'unknown'), 'sha256': sha})


def handle_agent_download():
    agent_path = Path('/var/www/remotepower/agent/remotepower-agent')
    if not agent_path.exists(): respond(404, {'error': 'Agent binary not found'})
    data = agent_path.read_bytes()
    print("Status: 200 OK"); print("Content-Type: application/octet-stream")
    print("Content-Disposition: attachment; filename=remotepower-agent")
    print(f"Content-Length: {len(data)}"); print("Cache-Control: no-store"); print()
    sys.stdout.flush(); sys.stdout.buffer.write(data); sys.stdout.buffer.flush(); sys.exit(0)


def handle_version_check():
    require_auth()
    cfg   = load(CONFIG_FILE)
    local = cfg.get('server_version', SERVER_VERSION)
    now   = int(time.time())
    cached_latest = cfg.get('_github_latest_version')
    cached_ts     = cfg.get('_github_latest_ts', 0)
    if cached_latest and (now - cached_ts) < 3600:
        latest = cached_latest
    else:
        try:
            req = urllib.request.Request(
                'https://api.github.com/repos/tyxak/remotepower/releases/latest',
                headers={'User-Agent': 'RemotePower'})
            ctx = _get_ssl_context()
            with urllib.request.urlopen(req, timeout=5, context=ctx) as r:
                data = json.loads(r.read(65536))  # cap response size
            # Strictly validate: tag must match semver pattern
            raw_tag = data.get('tag_name', '').lstrip('v')
            if re.match(r'^\d{1,4}\.\d{1,4}\.\d{1,4}$', raw_tag):
                latest = raw_tag
            else:
                latest = cached_latest
            if latest:
                cfg['_github_latest_version'] = latest
                cfg['_github_latest_ts']      = now
                save(CONFIG_FILE, cfg)
        except Exception:
            latest = cached_latest

    def vt(v):
        try: return tuple(int(x) for x in v.split('.'))
        except Exception: return (0,)

    update_available = latest is not None and local != 'unknown' and vt(latest) > vt(local)
    respond(200, {
        'current': local, 'latest': latest,
        'update_available': update_available,
        'release_url': 'https://github.com/tyxak/remotepower/releases/latest',
    })


def _record_uptime(dev_id, name, is_online):
    uptime = load(UPTIME_FILE)
    if dev_id not in uptime:
        uptime[dev_id] = {'name': name, 'events': []}
    events = uptime[dev_id].get('events', [])
    last_state = events[-1]['online'] if events else None
    if last_state != is_online:
        events.append({'ts': int(time.time()), 'online': is_online})
        uptime[dev_id]['events'] = events[-500:]
        uptime[dev_id]['name'] = name
        save(UPTIME_FILE, uptime)


def handle_uptime(dev_id):
    require_auth()
    if not _validate_id(dev_id): respond(404, {'error': 'Device not found'})
    uptime = load(UPTIME_FILE); dev = uptime.get(dev_id, {})
    respond(200, {'device_id': dev_id, 'name': dev.get('name', dev_id), 'events': dev.get('events', [])})


def handle_monitor_history(label):
    require_auth()
    label = _sanitize_str(label, 128)
    mh = load(MON_HIST_FILE)
    respond(200, {'label': label, 'history': mh.get(label, [])})


def handle_schedule_list():
    require_auth()
    schedule = load(SCHEDULE_FILE)
    respond(200, schedule.get('jobs', []))


def _valid_cron(expr):
    """Validate a 5-field cron expression with range checks."""
    parts = expr.strip().split()
    if len(parts) != 5:
        return False
    ranges = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)]
    for part, (lo, hi) in zip(parts, ranges):
        if part == '*':
            continue
        if part.startswith('*/'):
            try:
                step = int(part[2:])
                if step < 1 or step > hi:
                    return False
            except ValueError:
                return False
        else:
            try:
                v = int(part)
                if not (lo <= v <= hi):
                    return False
            except ValueError:
                return False
    return True


def _cron_matches(cron, ts):
    import datetime
    parts = cron.split()
    if len(parts) != 5: return False
    minute, hour, dom, month, dow = parts
    dt = datetime.datetime.fromtimestamp(ts)
    def _match(field, val):
        if field == '*': return True
        if field.startswith('*/'):
            try: return val % int(field[2:]) == 0
            except: return False
        try: return int(field) == val
        except: return False
    return (_match(minute, dt.minute) and _match(hour, dt.hour) and
            _match(dom, dt.day) and _match(month, dt.month) and _match(dow, dt.weekday()))


def handle_schedule_add():
    actor = require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body    = get_json_body()
    dev_id  = str(body.get('device_id', '')).strip()
    command = str(body.get('command', '')).strip()
    run_at  = body.get('run_at', 0)
    cron    = _sanitize_str(body.get('cron', ''), 64)

    if not _validate_id(dev_id): respond(404, {'error': 'Device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices: respond(404, {'error': 'Device not found'})
    if command not in ('shutdown', 'reboot'): respond(400, {'error': 'command must be shutdown or reboot'})

    if cron:
        if not _valid_cron(cron): respond(400, {'error': 'Invalid cron expression'})
    elif not isinstance(run_at, (int, float)) or run_at <= int(time.time()):
        respond(400, {'error': 'run_at must be a future unix timestamp'})

    schedule = load(SCHEDULE_FILE)
    jobs = schedule.get('jobs', [])
    if len(jobs) >= MAX_SCHEDULE_JOBS:
        respond(400, {'error': f'Schedule limit reached (max {MAX_SCHEDULE_JOBS} jobs)'})

    job = {
        'id':          secrets.token_hex(6),
        'device_id':   dev_id,
        'device_name': devices[dev_id].get('name', dev_id),
        'command':     command,
        'run_at':      int(run_at) if not cron else None,
        'cron':        cron or None,
        'actor':       actor,
        'created':     int(time.time()),
        'recurring':   bool(cron),
    }
    jobs.append(job)
    schedule['jobs'] = jobs
    save(SCHEDULE_FILE, schedule)
    respond(201, {'ok': True, 'job': job})


def handle_schedule_delete(job_id):
    require_admin_auth()
    if method() != 'DELETE': respond(405, {'error': 'Method not allowed'})
    if not _validate_id(job_id): respond(404, {'error': 'Job not found'})
    schedule = load(SCHEDULE_FILE)
    jobs = [j for j in schedule.get('jobs', []) if j['id'] != job_id]
    if len(jobs) == len(schedule.get('jobs', [])): respond(404, {'error': 'Job not found'})
    schedule['jobs'] = jobs; save(SCHEDULE_FILE, schedule)
    respond(200, {'ok': True})


def process_schedule():
    schedule = load(SCHEDULE_FILE)
    jobs     = schedule.get('jobs', [])
    now      = int(time.time())
    remaining = []
    changed = False
    for job in jobs:
        due = False
        if job.get('recurring') and job.get('cron'):
            due = _cron_matches(job['cron'], now)
        elif job.get('run_at') and job['run_at'] <= now:
            due = True
        if due:
            dev_id  = job['device_id']
            command = job['command']
            if command not in ('shutdown', 'reboot'):  # extra safety
                if job.get('recurring'):
                    remaining.append(job)
                changed = True
                continue
            if _validate_id(dev_id):
                devices = load(DEVICES_FILE)
                if dev_id in devices:
                    cmds = load(CMDS_FILE)
                    if dev_id not in cmds: cmds[dev_id] = []
                    if command not in cmds[dev_id]: cmds[dev_id].append(command)
                    save(CMDS_FILE, cmds)
                    log_command(f"scheduler({job['actor']})", dev_id, job['device_name'], command)
            if job.get('recurring'):
                remaining.append(job)
            changed = True
        else:
            remaining.append(job)
    if changed:
        schedule['jobs'] = remaining
        save(SCHEDULE_FILE, schedule)


def handle_custom_cmd():
    actor = require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body    = get_json_body()
    cmd_str = str(body.get('cmd', '')).strip()
    if not cmd_str: respond(400, {'error': 'cmd required'})
    if len(cmd_str) > 512: respond(400, {'error': 'cmd too long (max 512 chars)'})

    # Support batch targets (device_ids, tag, group) just like shutdown/reboot
    ids = _resolve_targets(body)
    if not ids: respond(400, {'error': 'No valid device targets'})

    devices = load(DEVICES_FILE)
    cmds = load(CMDS_FILE)
    results = {}
    for dev_id in ids:
        if not _validate_id(dev_id):
            results[dev_id] = {'ok': False, 'error': 'Invalid device ID'}; continue
        if dev_id not in devices:
            results[dev_id] = {'ok': False, 'error': 'Device not found'}; continue
        ok, reason = _check_exec_allowlist(dev_id, cmd_str, devices)
        if not ok:
            results[dev_id] = {'ok': False, 'error': reason}; continue
        if dev_id not in cmds: cmds[dev_id] = []
        cmds[dev_id].append(f'exec:{cmd_str}')
        log_command(actor, dev_id, devices[dev_id].get('name', dev_id), f'exec:{cmd_str[:40]}')
        audit_log(actor, 'exec', f'{dev_id}: {cmd_str[:80]}')
        fire_webhook('command_queued', {
            'device_id': dev_id, 'name': devices[dev_id].get('name', dev_id),
            'command': f'exec:{cmd_str[:40]}', 'actor': actor,
        })
        results[dev_id] = {'ok': True}
    save(CMDS_FILE, cmds)
    if len(ids) == 1:
        r = results.get(ids[0], {})
        if r.get('ok'): respond(200, {'ok': True})
        else: respond(400, r)
    else:
        respond(200, {'ok': True, 'results': results})


def handle_cmd_output(dev_id):
    require_auth()
    if not _validate_id(dev_id): respond(404, {'error': 'Device not found'})
    outputs = load(CMD_OUTPUT_FILE)
    respond(200, {'outputs': outputs.get(dev_id, [])})


def handle_device_allowlist(dev_id):
    require_admin_auth()
    if not _validate_id(dev_id): respond(404, {'error': 'Device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices: respond(404, {'error': 'Device not found'})
    if method() == 'GET':
        respond(200, {'allowed_commands': devices[dev_id].get('allowed_commands', [])})
    if method() == 'POST':
        body = get_json_body(); cmds_input = body.get('allowed_commands', [])
        if not isinstance(cmds_input, list): respond(400, {'error': 'allowed_commands must be a list'})
        cmds_clean = [str(c)[:512] for c in cmds_input[:50] if str(c).strip()]
        devices[dev_id]['allowed_commands'] = cmds_clean
        save(DEVICES_FILE, devices)
        respond(200, {'ok': True, 'allowed_commands': cmds_clean})
    respond(405, {'error': 'Method not allowed'})


def handle_cmd_library_list():
    require_auth()
    lib = load(CMD_LIBRARY_FILE)
    respond(200, lib.get('snippets', []))


def handle_cmd_library_add():
    require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    name = _sanitize_str(body.get('name', ''), 64)
    cmd  = _sanitize_str(body.get('cmd', ''), 512)
    desc = _sanitize_str(body.get('description', ''), 256)
    if not name or not cmd: respond(400, {'error': 'name and cmd required'})
    lib = load(CMD_LIBRARY_FILE); snippets = lib.get('snippets', [])
    if len(snippets) >= 200: respond(400, {'error': 'Library limit reached (max 200 snippets)'})
    snippet = {'id': secrets.token_hex(6), 'name': name, 'cmd': cmd,
               'description': desc, 'created': int(time.time())}
    snippets.append(snippet); lib['snippets'] = snippets; save(CMD_LIBRARY_FILE, lib)
    respond(201, {'ok': True, 'snippet': snippet})


def handle_cmd_library_delete(snippet_id):
    require_admin_auth()
    if method() != 'DELETE': respond(405, {'error': 'Method not allowed'})
    if not _validate_id(snippet_id): respond(404, {'error': 'Snippet not found'})
    lib = load(CMD_LIBRARY_FILE)
    snippets = [s for s in lib.get('snippets', []) if s['id'] != snippet_id]
    if len(snippets) == len(lib.get('snippets', [])): respond(404, {'error': 'Snippet not found'})
    lib['snippets'] = snippets; save(CMD_LIBRARY_FILE, lib)
    respond(200, {'ok': True})


def handle_export():
    """Export backup ZIP — apikeys.json is included but key values are redacted."""
    require_admin_auth()
    import zipfile, io
    buf = io.BytesIO()
    exclude = {'tokens.json', 'longpoll.json', 'ratelimit.json'}
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for f in DATA_DIR.glob('*.json'):
            if f.name not in exclude:
                if f.name == 'apikeys.json':
                    # Redact key values in backup
                    raw = load(f)
                    redacted = {kid: {**v, 'key': '(redacted)'} for kid, v in raw.items()}
                    zf.writestr('apikeys.json', json.dumps(redacted, indent=2))
                else:
                    zf.write(f, f.name)
    data = buf.getvalue(); ts = time.strftime('%Y%m%d-%H%M%S')
    print("Status: 200 OK"); print("Content-Type: application/zip")
    print(f"Content-Disposition: attachment; filename=remotepower-backup-{ts}.zip")
    print(f"Content-Length: {len(data)}"); print("Cache-Control: no-store")
    print("X-Content-Type-Options: nosniff"); print()
    sys.stdout.flush(); sys.stdout.buffer.write(data); sys.stdout.buffer.flush(); sys.exit(0)


def handle_revoke_sessions():
    """Revoke all sessions for a specific user or all users."""
    requester = require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    target_user = _sanitize_str(body.get('username', ''), 32)
    tokens = load(TOKENS_FILE)
    if target_user:
        pruned = {k: v for k, v in tokens.items() if v.get('user') != target_user}
        count = len(tokens) - len(pruned)
    else:
        # Revoke all except requester's current session
        current_token = get_token_from_request()
        pruned = {k: v for k, v in tokens.items() if k == current_token}
        count = len(tokens) - len(pruned)
    save(TOKENS_FILE, pruned)
    audit_log(requester, 'revoke_sessions', f'target={target_user or "all"}, revoked={count}')
    respond(200, {'ok': True, 'revoked': count})


def handle_apikeys_list():
    require_admin_auth()
    apikeys = load(APIKEYS_FILE)
    respond(200, [{'id': kid, 'name': v.get('name', ''), 'user': v.get('user', ''),
                   'role': v.get('role', 'admin'), 'created': v.get('created', 0),
                   'active': v.get('active', True)}
                  for kid, v in apikeys.items()])


def handle_apikeys_create():
    require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    name = _sanitize_str(body.get('name', ''), 64)
    role = body.get('role', 'admin')
    user = _sanitize_str(body.get('user', 'api'), 32)
    if not name: respond(400, {'error': 'name required'})
    if role not in ('admin', 'viewer'): respond(400, {'error': 'role must be admin or viewer'})
    apikeys = load(APIKEYS_FILE)
    if len(apikeys) >= 50: respond(400, {'error': 'API key limit reached (max 50)'})
    key_value = secrets.token_urlsafe(40)
    kid       = secrets.token_hex(8)
    expires_at = body.get('expires_at')
    if expires_at is not None:
        try:
            expires_at = int(expires_at)
            if expires_at <= int(time.time()):
                respond(400, {'error': 'expires_at must be in the future'})
        except (ValueError, TypeError):
            respond(400, {'error': 'expires_at must be a unix timestamp'})
    apikeys[kid] = {'name': name, 'key': key_value, 'user': user, 'role': role,
                    'created': int(time.time()), 'active': True,
                    'expires_at': expires_at}
    save(APIKEYS_FILE, apikeys)
    respond(201, {'ok': True, 'id': kid, 'key': key_value,
                  'note': 'Store this key securely — it will not be shown again.'})


def handle_apikeys_delete(kid):
    require_admin_auth()
    if method() != 'DELETE': respond(405, {'error': 'Method not allowed'})
    if not _validate_id(kid): respond(404, {'error': 'API key not found'})
    apikeys = load(APIKEYS_FILE)
    if kid not in apikeys: respond(404, {'error': 'API key not found'})
    del apikeys[kid]; save(APIKEYS_FILE, apikeys)
    respond(200, {'ok': True})


def _resolve_longpoll(dev_id, cmd_output):
    lp = load(LONGPOLL_FILE)
    if dev_id in lp:
        lp[dev_id]['output'] = cmd_output
        lp[dev_id]['ready']  = True
        save(LONGPOLL_FILE, lp)


def handle_longpoll_exec():
    actor = require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body    = get_json_body()
    dev_id  = str(body.get('device_id', '')).strip()
    cmd_str = str(body.get('cmd', '')).strip()

    try:
        timeout = int(body.get('timeout', 90))
        timeout = max(10, min(timeout, 120))
    except (ValueError, TypeError):
        timeout = 90

    if not _validate_id(dev_id): respond(404, {'error': 'Device not found'})
    if not cmd_str: respond(400, {'error': 'cmd required'})
    if len(cmd_str) > 512: respond(400, {'error': 'cmd too long'})

    devices = load(DEVICES_FILE)
    if dev_id not in devices: respond(404, {'error': 'Device not found'})

    # Apply the same allowlist check as handle_custom_cmd
    ok, reason = _check_exec_allowlist(dev_id, cmd_str, devices)
    if not ok: respond(403, {'error': reason})

    lp = load(LONGPOLL_FILE)
    lp[dev_id] = {'cmd': cmd_str, 'ready': False, 'output': None, 'ts': int(time.time())}
    save(LONGPOLL_FILE, lp)

    cmds = load(CMDS_FILE)
    if dev_id not in cmds: cmds[dev_id] = []
    cmds[dev_id].append(f'exec:{cmd_str}')
    save(CMDS_FILE, cmds)
    log_command(actor, dev_id, devices[dev_id].get('name', dev_id), f'exec(wait):{cmd_str[:40]}')

    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(1)
        lp   = load(LONGPOLL_FILE)
        slot = lp.get(dev_id, {})
        if slot.get('ready'):
            output = slot.get('output', {})
            del lp[dev_id]; save(LONGPOLL_FILE, lp)
            respond(200, {'ok': True, 'output': output})

    lp = load(LONGPOLL_FILE); lp.pop(dev_id, None); save(LONGPOLL_FILE, lp)
    respond(200, {'ok': False, 'timeout': True,
                  'message': 'Output not received within timeout — poll /output endpoint'})


def handle_digest():
    require_auth()
    devices = load(DEVICES_FILE); now = int(time.time())
    online  = sum(1 for d in devices.values() if (now - d.get('last_seen', 0)) < ONLINE_TTL)
    patches = sum(
        (d.get('sysinfo', {}).get('packages', {}).get('upgradable') or 0)
        for d in devices.values()
        if isinstance(d.get('sysinfo', {}).get('packages', {}).get('upgradable'), int)
    )
    recent_cmds = load(HISTORY_FILE).get('entries', [])[-10:]
    respond(200, {
        'ts': now, 'total': len(devices), 'online': online,
        'offline': len(devices) - online, 'pending_patches': patches,
        'recent_commands': recent_cmds,
    })


# ── Patch report ─────────────────────────────────────────────────────────────
def handle_patch_report():
    """Return detailed patch information across all devices."""
    require_auth()
    devices = load(DEVICES_FILE)
    now = int(time.time())
    report = {
        'generated_at': now,
        'server_version': SERVER_VERSION,
        'devices': [],
        'summary': {
            'total_devices': len(devices),
            'devices_with_patches': 0,
            'devices_fully_patched': 0,
            'devices_no_data': 0,
            'total_pending_patches': 0,
        }
    }
    for dev_id, dev in devices.items():
        si = dev.get('sysinfo', {})
        pkg = si.get('packages', {})
        upgradable = pkg.get('upgradable')
        is_online = (now - dev.get('last_seen', 0)) < ONLINE_TTL

        entry = {
            'device_id': dev_id,
            'name': dev.get('name', dev_id),
            'hostname': dev.get('hostname', ''),
            'group': dev.get('group', ''),
            'tags': dev.get('tags', []),
            'os': dev.get('os', ''),
            'online': is_online,
            'last_seen': dev.get('last_seen', 0),
            'pkg_manager': pkg.get('manager', 'unknown'),
            'upgradable': upgradable,
            'patch_status': 'unknown',
        }

        if upgradable is None or not is_online:
            entry['patch_status'] = 'no_data'
            report['summary']['devices_no_data'] += 1
        elif upgradable == 0:
            entry['patch_status'] = 'fully_patched'
            report['summary']['devices_fully_patched'] += 1
        else:
            entry['patch_status'] = 'patches_available'
            report['summary']['devices_with_patches'] += 1
            report['summary']['total_pending_patches'] += upgradable

        # Recent exec history for patch commands
        outputs = load(CMD_OUTPUT_FILE).get(dev_id, [])
        patch_cmds = [o for o in outputs if any(kw in o.get('cmd', '')
                      for kw in ('apt', 'dnf', 'pacman', 'upgrade', 'update'))]
        entry['recent_patch_commands'] = patch_cmds[-5:]

        report['devices'].append(entry)

    # Patch percentage: only among ONLINE devices that have reported data
    online_with_data = report['summary']['devices_fully_patched'] + report['summary']['devices_with_patches']
    patched = report['summary']['devices_fully_patched']
    report['summary']['online_with_data'] = online_with_data
    report['summary']['patch_percentage'] = round((patched / online_with_data * 100) if online_with_data > 0 else 0, 1)

    report['devices'].sort(key=lambda x: (-(x.get('upgradable') or 0), x['name'].lower()))
    respond(200, report)


def handle_patch_report_device(dev_id):
    """Return detailed patch report for a single device."""
    require_auth()
    if not _validate_id(dev_id): respond(404, {'error': 'Device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices: respond(404, {'error': 'Device not found'})
    dev = devices[dev_id]
    now = int(time.time())
    si = dev.get('sysinfo', {})
    pkg = si.get('packages', {})
    upgradable = pkg.get('upgradable')
    is_online = (now - dev.get('last_seen', 0)) < ONLINE_TTL

    # All exec output related to patching
    outputs = load(CMD_OUTPUT_FILE).get(dev_id, [])
    patch_cmds = [o for o in outputs if any(kw in o.get('cmd', '')
                  for kw in ('apt', 'dnf', 'pacman', 'upgrade', 'update', 'yum'))]

    # Metrics history
    metrics = load(METRICS_FILE).get(dev_id, [])

    report = {
        'device_id': dev_id,
        'name': dev.get('name', dev_id),
        'hostname': dev.get('hostname', ''),
        'group': dev.get('group', ''),
        'tags': dev.get('tags', []),
        'os': dev.get('os', ''),
        'online': is_online,
        'last_seen': dev.get('last_seen', 0),
        'enrolled': dev.get('enrolled', 0),
        'version': dev.get('version', ''),
        'pkg_manager': pkg.get('manager', 'unknown'),
        'upgradable': upgradable,
        'patch_status': 'no_data' if upgradable is None else ('fully_patched' if upgradable == 0 else 'patches_available'),
        'uptime': si.get('uptime', ''),
        'platform': si.get('platform', ''),
        'patch_history': patch_cmds[-20:],
        'latest_metrics': metrics[-10:] if metrics else [],
    }
    respond(200, report)


def _filter_devices_for_export():
    """Filter devices by query params: group, device_id."""
    from urllib.parse import parse_qs
    qs = parse_qs(os.environ.get('QUERY_STRING', ''))
    group_filter = qs.get('group', [''])[0].strip()
    device_filter = qs.get('device_id', [''])[0].strip()
    devices = load(DEVICES_FILE)
    filtered = {}
    for dev_id, dev in devices.items():
        if group_filter and dev.get('group', '') != group_filter:
            continue
        if device_filter and dev_id != device_filter:
            continue
        filtered[dev_id] = dev
    return filtered


def handle_patch_report_csv():
    """Return patch report as CSV."""
    require_auth()
    devices = _filter_devices_for_export()
    now = int(time.time())
    import csv, io
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['Device', 'Hostname', 'Group', 'OS', 'Online', 'Pkg Manager',
                     'Pending Updates', 'Patch Status', 'Last Seen'])
    for dev_id, dev in sorted(devices.items(), key=lambda x: x[1].get('name', '').lower()):
        si = dev.get('sysinfo', {})
        pkg = si.get('packages', {})
        upgradable = pkg.get('upgradable')
        is_online = (now - dev.get('last_seen', 0)) < ONLINE_TTL
        status = 'no_data' if (upgradable is None or not is_online) else ('fully_patched' if upgradable == 0 else 'patches_available')
        last_seen_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(dev.get('last_seen', 0))) if dev.get('last_seen') else 'never'
        writer.writerow([
            dev.get('name', dev_id), dev.get('hostname', ''), dev.get('group', ''),
            dev.get('os', ''), 'yes' if is_online else 'no',
            pkg.get('manager', 'unknown'), upgradable if upgradable is not None else 'N/A',
            status, last_seen_str
        ])
    data = buf.getvalue().encode()
    ts = time.strftime('%Y%m%d-%H%M%S')
    print("Status: 200 OK")
    print("Content-Type: text/csv")
    print(f"Content-Disposition: attachment; filename=patch-report-{ts}.csv")
    print(f"Content-Length: {len(data)}")
    print("Cache-Control: no-store")
    print("X-Content-Type-Options: nosniff")
    print()
    sys.stdout.flush()
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()
    sys.exit(0)


def handle_patch_report_xml():
    """Return patch report as XML."""
    require_auth()
    devices = _filter_devices_for_export()
    now = int(time.time())
    from xml.etree.ElementTree import Element, SubElement, tostring
    root = Element('PatchReport')
    root.set('generated', time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(now)))
    root.set('serverVersion', SERVER_VERSION)
    summary = SubElement(root, 'Summary')
    total = len(devices)
    patched = 0; pending = 0; no_data = 0; with_patches = 0
    devs_el = SubElement(root, 'Devices')
    for dev_id, dev in sorted(devices.items(), key=lambda x: x[1].get('name', '').lower()):
        si = dev.get('sysinfo', {})
        pkg = si.get('packages', {})
        upgradable = pkg.get('upgradable')
        is_online = (now - dev.get('last_seen', 0)) < ONLINE_TTL
        d_el = SubElement(devs_el, 'Device')
        d_el.set('id', dev_id)
        SubElement(d_el, 'Name').text = dev.get('name', dev_id)
        SubElement(d_el, 'Hostname').text = dev.get('hostname', '')
        SubElement(d_el, 'Group').text = dev.get('group', '')
        SubElement(d_el, 'OS').text = dev.get('os', '')
        SubElement(d_el, 'Online').text = str(is_online).lower()
        SubElement(d_el, 'PkgManager').text = pkg.get('manager', 'unknown')
        SubElement(d_el, 'PendingUpdates').text = str(upgradable) if upgradable is not None else 'N/A'
        if upgradable is None or not is_online: status = 'no_data'; no_data += 1
        elif upgradable == 0: status = 'fully_patched'; patched += 1
        else: status = 'patches_available'; with_patches += 1; pending += upgradable
        SubElement(d_el, 'PatchStatus').text = status
    SubElement(summary, 'TotalDevices').text = str(total)
    SubElement(summary, 'FullyPatched').text = str(patched)
    SubElement(summary, 'WithPatches').text = str(with_patches)
    SubElement(summary, 'NoData').text = str(no_data)
    SubElement(summary, 'TotalPendingPatches').text = str(pending)
    online_with_data = patched + with_patches
    SubElement(summary, 'OnlineWithData').text = str(online_with_data)
    SubElement(summary, 'PatchPercentage').text = str(round((patched / online_with_data * 100) if online_with_data > 0 else 0, 1))
    xml_str = tostring(root, encoding='unicode')
    data = ('<?xml version="1.0" encoding="UTF-8"?>\n' + xml_str).encode('utf-8')
    ts = time.strftime('%Y%m%d-%H%M%S')
    print("Status: 200 OK")
    print("Content-Type: application/xml")
    print(f"Content-Disposition: attachment; filename=patch-report-{ts}.xml")
    print(f"Content-Length: {len(data)}")
    print("Cache-Control: no-store")
    print("X-Content-Type-Options: nosniff")
    print()
    sys.stdout.flush()
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()
    sys.exit(0)



def handle_audit_log():
    require_admin_auth()
    al = load(AUDIT_LOG_FILE)
    respond(200, list(reversed(al.get('entries', []))))


def handle_audit_log_clear():
    actor = require_admin_auth()
    if method() != 'DELETE': respond(405, {'error': 'Method not allowed'})
    save(AUDIT_LOG_FILE, {'entries': []})
    # Log the clear itself as the first new entry
    audit_log(actor, 'clear_audit_log', 'audit log cleared')
    respond(200, {'ok': True})


def handle_webhook_test():
    """Send a test webhook to verify the URL is working."""
    actor = require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    cfg = load(CONFIG_FILE)
    url = cfg.get('webhook_url', '').strip()
    if not url:
        respond(400, {'error': 'No webhook URL configured — set one in Settings first'})
    fire_webhook('test', {
        'server_version': SERVER_VERSION,
        'triggered_by': actor,
    })
    audit_log(actor, 'webhook_test', f'test webhook fired to {url[:80]}')
    # Return the most recent log entry so the UI can show success/failure
    wl = load(WEBHOOK_LOG_FILE)
    entries = wl.get('entries', [])
    last = entries[-1] if entries else None
    respond(200, {'ok': True, 'result': last})


def handle_webhook_log():
    """Return the webhook delivery log."""
    require_admin_auth()
    wl = load(WEBHOOK_LOG_FILE)
    respond(200, list(reversed(wl.get('entries', []))))


def handle_webhook_log_clear():
    """Clear the webhook delivery log."""
    actor = require_admin_auth()
    if method() != 'DELETE': respond(405, {'error': 'Method not allowed'})
    save(WEBHOOK_LOG_FILE, {'entries': []})
    audit_log(actor, 'clear_webhook_log', 'webhook log cleared')
    respond(200, {'ok': True})


def handle_monitor_alerts_clear():
    """Reset monitor alert state so alerts can re-fire."""
    actor = require_admin_auth()
    if method() != 'DELETE': respond(405, {'error': 'Method not allowed'})
    cfg = load(CONFIG_FILE)
    cfg['monitor_notified'] = {}
    cfg['offline_notified'] = {}
    save(CONFIG_FILE, cfg)
    audit_log(actor, 'clear_monitor_alerts', 'monitor alert state reset')
    respond(200, {'ok': True})


# ─── Router ────────────────────────────────────────────────────────────────────
def main():
    try: check_offline_webhooks()
    except Exception: pass
    try: process_schedule()
    except Exception: pass

    pi = path_info(); m = method()

    if pi == '/api/login': handle_login()
    elif pi == '/api/devices' and m == 'GET': handle_devices_list()
    elif pi.startswith('/api/devices/') and m == 'DELETE' and not any(
            pi.endswith(s) for s in ('/tags','/notes','/group','/sysinfo','/uptime',
                                     '/output','/metrics','/allowlist','/poll_interval',
                                     '/icon','/monitored')):
        handle_device_delete(pi[len('/api/devices/'):])
    elif pi.startswith('/api/devices/') and pi.endswith('/tags') and m == 'PATCH':
        handle_device_tags(pi[len('/api/devices/'):-len('/tags')])
    elif pi.startswith('/api/devices/') and pi.endswith('/notes') and m == 'PATCH':
        handle_device_notes(pi[len('/api/devices/'):-len('/notes')])
    elif pi.startswith('/api/devices/') and pi.endswith('/group') and m == 'PATCH':
        handle_device_group(pi[len('/api/devices/'):-len('/group')])
    elif pi.startswith('/api/devices/') and pi.endswith('/poll_interval') and m == 'PATCH':
        handle_device_poll_interval(pi[len('/api/devices/'):-len('/poll_interval')])
    elif pi.startswith('/api/devices/') and pi.endswith('/icon') and m == 'PATCH':
        handle_device_icon(pi[len('/api/devices/'):-len('/icon')])
    elif pi.startswith('/api/devices/') and pi.endswith('/monitored') and m == 'PATCH':
        handle_device_monitored(pi[len('/api/devices/'):-len('/monitored')])
    elif pi.startswith('/api/devices/') and pi.endswith('/sysinfo') and m == 'GET':
        handle_sysinfo(pi[len('/api/devices/'):-len('/sysinfo')])
    elif pi.startswith('/api/devices/') and pi.endswith('/metrics') and m == 'GET':
        handle_metrics(pi[len('/api/devices/'):-len('/metrics')])
    elif pi.startswith('/api/devices/') and pi.endswith('/allowlist'):
        handle_device_allowlist(pi[len('/api/devices/'):-len('/allowlist')])
    elif pi == '/api/enroll/pin': handle_enroll_pin()
    elif pi == '/api/enroll/register': handle_enroll_register()
    elif pi == '/api/heartbeat': handle_heartbeat()
    elif pi == '/api/shutdown': handle_shutdown()
    elif pi == '/api/reboot': handle_reboot()
    elif pi == '/api/update-device': handle_update_device()
    elif pi == '/api/upgrade-device': handle_upgrade_device()
    elif pi == '/api/wol': handle_wol()
    elif pi == '/api/monitor' and m == 'GET': handle_monitor_run()
    elif pi == '/api/config' and m == 'GET': handle_config_get()
    elif pi == '/api/config' and m == 'POST': handle_config_save()
    elif pi == '/api/history' and m == 'GET': handle_history()
    elif pi == '/api/history' and m == 'DELETE': handle_history_clear()
    elif pi == '/api/users' and m == 'GET': handle_users_list()
    elif pi == '/api/users' and m == 'POST': handle_user_create()
    elif pi.startswith('/api/users/') and not pi.endswith('/passwd') and m == 'DELETE':
        handle_user_delete(pi[len('/api/users/'):])
    elif pi == '/api/users/passwd' and m == 'POST': handle_user_passwd()
    elif pi == '/api/totp/setup' and m == 'POST': handle_totp_setup()
    elif pi == '/api/totp/confirm' and m == 'POST': handle_totp_confirm()
    elif pi == '/api/totp/disable' and m == 'POST': handle_totp_disable()
    elif pi == '/api/totp/status' and m == 'GET': handle_totp_status()
    elif pi == '/api/agent/version' and m == 'GET': handle_agent_version()
    elif pi == '/api/agent/download' and m == 'GET': handle_agent_download()
    elif pi == '/api/version' and m == 'GET': handle_version_check()
    elif pi == '/api/schedule' and m == 'GET': handle_schedule_list()
    elif pi == '/api/schedule' and m == 'POST': handle_schedule_add()
    elif pi.startswith('/api/schedule/') and m == 'DELETE':
        handle_schedule_delete(pi[len('/api/schedule/'):])
    elif pi == '/api/exec' and m == 'POST': handle_custom_cmd()
    elif pi == '/api/exec/wait' and m == 'POST': handle_longpoll_exec()
    elif pi.startswith('/api/devices/') and pi.endswith('/output') and m == 'GET':
        handle_cmd_output(pi[len('/api/devices/'):-len('/output')])
    elif pi.startswith('/api/devices/') and pi.endswith('/uptime') and m == 'GET':
        handle_uptime(pi[len('/api/devices/'):-len('/uptime')])
    elif pi == '/api/monitor/history' and m == 'GET':
        from urllib.parse import parse_qs
        label = parse_qs(os.environ.get('QUERY_STRING', '')).get('label', [''])[0]
        handle_monitor_history(label)
    elif pi == '/api/cmd-library' and m == 'GET': handle_cmd_library_list()
    elif pi == '/api/cmd-library' and m == 'POST': handle_cmd_library_add()
    elif pi.startswith('/api/cmd-library/') and m == 'DELETE':
        handle_cmd_library_delete(pi[len('/api/cmd-library/'):])
    elif pi == '/api/apikeys' and m == 'GET': handle_apikeys_list()
    elif pi == '/api/apikeys' and m == 'POST': handle_apikeys_create()
    elif pi.startswith('/api/apikeys/') and m == 'DELETE':
        handle_apikeys_delete(pi[len('/api/apikeys/'):])
    elif pi == '/api/export' and m == 'GET': handle_export()
    elif pi == '/api/digest' and m == 'GET': handle_digest()
    elif pi == '/api/patch-report' and m == 'GET': handle_patch_report()
    elif pi.startswith('/api/patch-report/device/') and m == 'GET':
        handle_patch_report_device(pi[len('/api/patch-report/device/'):])
    elif pi == '/api/patch-report/csv' and m == 'GET': handle_patch_report_csv()
    elif pi == '/api/patch-report/xml' and m == 'GET': handle_patch_report_xml()
    elif pi == '/api/audit-log' and m == 'GET': handle_audit_log()
    elif pi == '/api/audit-log' and m == 'DELETE': handle_audit_log_clear()
    elif pi == '/api/webhook/test' and m == 'POST': handle_webhook_test()
    elif pi == '/api/webhook/log' and m == 'GET': handle_webhook_log()
    elif pi == '/api/webhook/log' and m == 'DELETE': handle_webhook_log_clear()
    elif pi == '/api/monitor/alerts/clear' and m == 'DELETE': handle_monitor_alerts_clear()
    elif pi == '/api/sessions/revoke' and m == 'POST': handle_revoke_sessions()
    else: respond(404, {'error': 'Not found'})


if __name__ == '__main__':
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        # Do NOT leak exception details to the client
        print("Status: 500 Internal Server Error")
        print("Content-Type: application/json")
        print("Cache-Control: no-store")
        print()
        print(json.dumps({'error': 'Internal server error'}))

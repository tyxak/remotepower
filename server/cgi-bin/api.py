#!/usr/bin/env python3
"""
RemotePower API backend - v1.9.0
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

SERVER_VERSION = '1.10.0'

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
# v1.10.0: Update output captures from `update` commands (apt/dnf/pacman runs).
# Stored separately from generic exec output so the Patches page can filter
# without scanning thousands of unrelated entries.
UPDATE_LOGS_FILE = DATA_DIR / 'update_logs.json'
MAX_UPDATE_LOGS_PER_DEVICE = 10                # rolling buffer
MAX_UPDATE_LOG_BYTES       = 256 * 1024        # apt update -y can spew a lot
METRICS_FILE     = DATA_DIR / 'metrics.json'
CMD_LIBRARY_FILE = DATA_DIR / 'cmd_library.json'
LONGPOLL_FILE    = DATA_DIR / 'longpoll.json'
APIKEYS_FILE     = DATA_DIR / 'apikeys.json'
RATELIMIT_FILE   = DATA_DIR / 'ratelimit.json'
AUDIT_LOG_FILE   = DATA_DIR / 'audit_log.json'
SESSIONS_META_FILE = DATA_DIR / 'sessions_meta.json'
WEBHOOK_LOG_FILE = DATA_DIR / 'webhook_log.json'

# ── v1.7.0: CVE scanner + package inventory ────────────────────────────────────
PACKAGES_FILE       = DATA_DIR / 'packages.json'
CVE_FINDINGS_FILE   = DATA_DIR / 'cve_findings.json'
CVE_IGNORE_FILE     = DATA_DIR / 'cve_ignore.json'

MAX_PACKAGE_LIST    = 10000      # hard cap on packages per device payload
CVE_SCAN_MAX_AGE    = 86400      # auto-scan if findings older than this
CVE_ALERT_SEVERITY  = ('critical', 'high')  # which severities fire webhooks

# ── v1.8.0: service monitoring, log tail, maintenance windows ─────────────────
SERVICES_FILE       = DATA_DIR / 'services.json'          # current state per device
SERVICE_HIST_FILE   = DATA_DIR / 'service_history.json'   # transitions per (device,unit)
LOG_WATCH_FILE      = DATA_DIR / 'log_watch.json'         # captured log buffer per device
MAINT_FILE          = DATA_DIR / 'maintenance.json'       # active + scheduled windows
MAINT_SUPPRESS_LOG  = DATA_DIR / 'maint_suppressed.json'  # audit trail for suppressions

# v1.8.2: fleet-wide log alert rules (per-device rules still live on device.log_watch)
LOG_RULES_GLOBAL_FILE = DATA_DIR / 'log_rules_global.json'
MAX_GLOBAL_LOG_RULES  = 50

# v1.8.3: standalone shared calendar events
CALENDAR_FILE       = DATA_DIR / 'calendar.json'
MAX_CALENDAR_EVENTS = 1000

# v1.8.3: shared kanban-style task board (optional device linking)
TASKS_FILE          = DATA_DIR / 'tasks.json'
MAX_TASKS           = 500
TASK_STATES         = ('upcoming', 'ongoing', 'pending', 'closed')

# ── v1.9.0: CMDB (asset metadata + encrypted credentials) ─────────────────────
CMDB_FILE           = DATA_DIR / 'cmdb.json'
CMDB_VAULT_FILE     = DATA_DIR / 'cmdb_vault.json'

MAX_CMDB_DOC_LEN    = 64 * 1024     # 64 KB Markdown body per asset
MAX_CMDB_FUNC_LEN   = 64
MAX_CMDB_ASSET_ID   = 64
MAX_CMDB_URL_LEN    = 512
MAX_CMDB_LABEL      = 64
MAX_CMDB_USERNAME   = 128
MAX_CMDB_PASSWORD   = 1024
MAX_CMDB_CRED_NOTE  = 512
MAX_CMDB_CREDS      = 25            # per-asset cap

# server_function is a free-text field, but we restrict the charset so we can
# safely use it in the searchbox / autocomplete without escaping every char.
_CMDB_FUNC_RE       = re.compile(r'^[A-Za-z0-9 _\-/]{0,64}$')

# v1.10.0: SSH port for the per-credential SSH link feature. Default 22 = blank.
CMDB_DEFAULT_SSH_PORT = 22
CMDB_SSH_PORT_MIN     = 1
CMDB_SSH_PORT_MAX     = 65535

MAX_SERVICES_PER_DEVICE = 50       # sanity cap
MAX_SERVICE_HIST        = 100      # state transitions kept per (device,unit)
MAX_LOG_LINES_PER_UNIT  = 100      # per-poll capture window
LOG_BUFFER_TTL          = 6 * 3600 # rolling N-hour buffer
MAX_LOG_BUFFER_BYTES    = 2 * 1024 * 1024   # 2 MB per device cap

# Sibling modules — must live in the same cgi-bin directory
sys.path.insert(0, str(Path(__file__).parent))
import cve_scanner
import prometheus_export
# v1.8.6: SMTP + LDAP. ldap3 is optional — the module imports it lazily so
# servers that don't enable LDAP don't need the dependency installed.
import smtp_notifier
import ldap_auth
# v1.9.0: CMDB vault — symmetric crypto for asset credentials. The cryptography
# library is imported lazily inside the module so this import always succeeds.
import cmdb_vault
# v1.10.0: OpenAPI spec — handwritten dict served at /api/openapi.json,
# rendered by the Swagger UI page at /swagger.html.
import openapi_spec

# Default values — overridable via /api/config (v1.8.4)
DEFAULT_TOKEN_TTL_SHORT  = 86400        # 24h — when "remember me" is unchecked
DEFAULT_TOKEN_TTL_LONG   = 86400 * 30   # 30 days — when "remember me" is checked
TOKEN_TTL                = 86400 * 7    # legacy fallback if config has neither
PIN_TTL                  = 600
DEFAULT_ONLINE_TTL       = 180
MIN_ONLINE_TTL           = 90           # lower than this and devices flap between polls
DEFAULT_POLL_INTERVAL    = 60
DEFAULT_CVE_CACHE_DAYS   = 7
MAX_HISTORY       = 200
MAX_MON_HISTORY   = 50
MAX_CMD_OUTPUT    = 100
MAX_CMD_OUT_BYTES = 8192    # per-entry output cap enforced at ingestion
MAX_METRICS       = 1440
MAX_SCHEDULE_JOBS = 200     # cap on total schedule entries
PATCH_ALERT_KEY   = 'patch_alert_threshold'
MAX_AUDIT_LOG     = 500
MAX_WEBHOOK_LOG   = 100


# v1.8.4: All known webhook events, with metadata used by the UI to render
# the per-event toggle list. Order matters — drives the order in Settings.
WEBHOOK_EVENTS = (
    ('device_offline',   'Device went offline',                  True),
    ('device_online',    'Device came back online',              True),
    ('monitor_down',     'Monitor target went down',             True),
    ('monitor_up',       'Monitor target recovered',             True),
    ('patch_alert',      'Pending updates exceed threshold',     True),
    ('cve_found',        'New CVEs detected on a device',        True),
    ('service_down',     'Watched systemd unit went down',       True),
    ('service_up',       'Watched systemd unit recovered',       True),
    ('log_alert',        'Log pattern matched threshold',        True),
    ('command_queued',   'Command queued for a device',          False),
    ('command_executed', 'Command executed on a device',         False),
)
WEBHOOK_EVENT_NAMES = tuple(e[0] for e in WEBHOOK_EVENTS)

# CVE severity levels available for cve_found webhook filtering
CVE_SEVERITIES_ALL  = ('critical', 'high', 'medium', 'low', 'unknown')
CVE_SEVERITY_FILTER_DEFAULT = ('critical', 'high')


def _config():
    """Load config with merged defaults — call when you need a current value."""
    cfg = load(CONFIG_FILE)
    return cfg


def get_online_ttl():
    """Effective online TTL value, clamped to MIN_ONLINE_TTL."""
    try:
        v = int(_config().get('online_ttl', DEFAULT_ONLINE_TTL))
    except (TypeError, ValueError):
        v = DEFAULT_ONLINE_TTL
    return max(MIN_ONLINE_TTL, v)


def get_default_poll_interval():
    """Default poll interval used when enrolling new agents."""
    try:
        v = int(_config().get('default_poll_interval', DEFAULT_POLL_INTERVAL))
    except (TypeError, ValueError):
        v = DEFAULT_POLL_INTERVAL
    return max(10, min(3600, v))


def get_session_ttl(remember_me=False):
    """Session lifetime in seconds — short by default, long with 'remember me'."""
    cfg = _config()
    if remember_me:
        try:
            return int(cfg.get('session_ttl_long', DEFAULT_TOKEN_TTL_LONG))
        except (TypeError, ValueError):
            return DEFAULT_TOKEN_TTL_LONG
    try:
        return int(cfg.get('session_ttl_short', DEFAULT_TOKEN_TTL_SHORT))
    except (TypeError, ValueError):
        return DEFAULT_TOKEN_TTL_SHORT


def get_remember_me_default():
    """Whether the 'remember me' checkbox should be pre-ticked on the login page."""
    return bool(_config().get('remember_me_default', False))


def get_cve_cache_seconds():
    """How long to cache OSV vulnerability details before re-fetching."""
    try:
        days = int(_config().get('cve_cache_days', DEFAULT_CVE_CACHE_DAYS))
    except (TypeError, ValueError):
        days = DEFAULT_CVE_CACHE_DAYS
    return max(1, min(90, days)) * 86400


def is_webhook_event_enabled(event):
    """Check the per-event webhook toggle. Backward compatible with legacy keys."""
    cfg = _config()

    # New (v1.8.4): explicit per-event dict
    events = cfg.get('webhook_events') or {}
    if event in events:
        return bool(events[event])

    # Legacy: device_offline/device_online controlled by offline_webhook_enabled,
    # monitor_down/monitor_up by monitor_webhook_enabled, etc.
    if event in ('device_offline', 'device_online'):
        return cfg.get('offline_webhook_enabled', True)
    if event in ('monitor_down', 'monitor_up'):
        return cfg.get('monitor_webhook_enabled', True)
    if event == 'cve_found':
        return cfg.get('cve_webhook_enabled', True)
    if event in ('service_down', 'service_up'):
        return cfg.get('service_webhook_enabled', True)
    # Default ON for everything else not explicitly disabled
    return True


def get_cve_severity_filter():
    """Severity levels that fire cve_found webhooks."""
    cfg = _config()
    raw = cfg.get('cve_severity_filter')
    if isinstance(raw, list) and raw:
        clean = tuple(s for s in raw if s in CVE_SEVERITIES_ALL)
        if clean:
            return clean
    return CVE_SEVERITY_FILTER_DEFAULT


def get_server_name():
    """Display name for this server — webhook payloads, page title, etc."""
    name = _config().get('server_name', '').strip()
    return name or 'RemotePower'

# ── Login brute-force protection ───────────────────────────────────────────────
LOGIN_FAIL_WINDOW  = 300   # 5-minute rolling window
LOGIN_FAIL_MAX     = 10    # lock after this many failures
LOGIN_LOCKOUT_TIME = 600   # 10-minute lockout

# ── Input size limits ──────────────────────────────────────────────────────────
MAX_BODY_BYTES    = 50 * 1024 * 1024  # 50 MB — raised from 64 KB in v1.7.0 for package-list uploads
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
        # v1.8.4: tokens may have their own ttl (per-session — controlled by
        # remember-me at login). Fall back to legacy TOKEN_TTL.
        ttl = entry.get('ttl', TOKEN_TTL)
        if now - entry['created'] > ttl:
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
    pruned = {
        k: v for k, v in tokens.items()
        if now - v.get('created', 0) <= v.get('ttl', TOKEN_TTL)
    }
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


class HTTPError(Exception):
    """
    Short-circuit a handler with an HTTP status + JSON body.

    Replaces the older ``respond(...); sys.exit(0)`` pattern. Handlers that
    raise ``HTTPError`` are unwound by ``main()`` and rendered identically
    to a successful response — same status, same JSON envelope, same
    headers.

    The exception form is purely an internal control-flow tool. Callers
    that want to *return* an error response should still use
    ``respond(status, body)`` — ``respond`` raises ``HTTPError`` itself,
    which is then caught one level up.

    Why an exception instead of ``sys.exit``? Tests can catch ``HTTPError``
    and inspect ``status``/``body`` directly without monkey-patching
    ``sys.exit`` or capturing stdout. In production it's a wash — the
    process still terminates after rendering the response.
    """

    def __init__(self, status: int, body):
        super().__init__(f"HTTP {status}")
        self.status = status
        self.body = body


_HTTP_STATUS_REASONS = {
    200: 'OK', 201: 'Created', 400: 'Bad Request', 401: 'Unauthorized',
    403: 'Forbidden', 404: 'Not Found', 405: 'Method Not Allowed',
    409: 'Conflict', 413: 'Request Entity Too Large', 429: 'Too Many Requests',
    500: 'Internal Server Error',
}


def _render_response(status: int, data) -> None:
    """Render an HTTP response to stdout. Used by main() — handlers should
    use respond()/HTTPError instead so the response is uniformly handled."""
    print(f"Status: {status} {_HTTP_STATUS_REASONS.get(status, '')}")
    print("Content-Type: application/json")
    print("Cache-Control: no-store")
    print("X-Content-Type-Options: nosniff")
    print()
    print(json.dumps(data))


def respond(status, data):
    """
    Short-circuit the current handler with an HTTP response.

    Despite the name, this does **not** return — it raises ``HTTPError``
    which is unwound at the top of ``main()``. The signature is
    preserved for backward compatibility with the ~100 existing call
    sites; new code should prefer ``raise HTTPError(status, data)``
    directly.
    """
    raise HTTPError(status, data)


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


def is_email_event_enabled(event, cfg=None):
    """v1.8.6: per-event email toggle. Independent of webhook toggle.
    SMTP must also be enabled overall and have at least one recipient."""
    if cfg is None:
        cfg = _config()
    if not cfg.get('smtp_enabled'):
        return False
    if not (cfg.get('smtp_recipients') or '').strip():
        return False
    events = cfg.get('email_events') or {}
    if event in events:
        return bool(events[event])
    # Default: not enabled (opt-in per event). Webhook stays opt-out by default.
    return False


def _smtp_recipients_list(cfg):
    """Parse the comma/semicolon/whitespace-separated recipients string."""
    raw = (cfg.get('smtp_recipients') or '')
    parts = re.split(r'[,;\s]+', raw)
    return [p.strip() for p in parts if p and '@' in p]


def _send_event_email(event, payload, message, cfg, server_name):
    """Send the email channel for an event. Failures are logged, never raised."""
    recipients = _smtp_recipients_list(cfg)
    if not recipients:
        return
    try:
        subject, body = smtp_notifier.render_event_email(server_name, event, payload, message)
        smtp_notifier.send_email(cfg, recipients, subject, body)
        _log_email(event, recipients, 'ok', '')
    except smtp_notifier.SmtpError as e:
        _log_email(event, recipients, 'error', str(e))
    except Exception as e:
        _log_email(event, recipients, 'error', f'{type(e).__name__}: {e}')


def _log_email(event, recipients, status, detail):
    """Append to the webhook log file but tag as 'email' channel for visibility."""
    try:
        log = load(WEBHOOK_LOG_FILE)
        if not isinstance(log, list):
            log = []
        log.insert(0, {
            'ts':         int(time.time()),
            'event':      f'{event} (email)',
            'status':     status,
            'detail':     f'{len(recipients)} recipient(s): {detail}'[:300],
        })
        save(WEBHOOK_LOG_FILE, log[:MAX_WEBHOOK_LOG])
    except Exception:
        pass


def fire_webhook(event, payload):
    """
    v1.8.6: Despite the historical name, this is now the single dispatch point
    for both webhook and email notifications. It runs the shared gates
    (per-event toggle, CVE severity filter, maintenance suppression) once,
    then fans out to whichever channels are configured.
    """
    cfg = load(CONFIG_FILE)

    # v1.8.4: per-event toggle. If disabled, log it and bail.
    if not is_webhook_event_enabled(event):
        webhook_url = cfg.get('webhook_url', '').strip()
        if webhook_url:
            _log_webhook(event, webhook_url, 'disabled', f'event "{event}" disabled in settings')
        return

    # v1.8.4: cve_found severity filter
    if event == 'cve_found':
        allowed_sev = set(get_cve_severity_filter())
        any_in_allowlist = (
            ('critical' in allowed_sev and payload.get('critical', 0) > 0) or
            ('high' in allowed_sev and payload.get('high', 0) > 0)
        )
        if not any_in_allowlist:
            url = cfg.get('webhook_url', '').strip()
            if url:
                _log_webhook(event, url, 'filtered',
                             f'no findings match severity filter {sorted(allowed_sev)}')
            return

    # v1.8.0: maintenance-window suppression — applies to BOTH channels
    try:
        mw = in_maintenance(event, payload)
    except Exception:
        mw = None
    if mw:
        try:
            log_suppression(event, payload, mw)
        except Exception:
            pass
        url = cfg.get('webhook_url', '').strip()
        if url:
            _log_webhook(event, url, 'suppressed', f'maintenance: {mw.get("reason", "")}')
        return

    # Build the human-readable message once — used by both channels
    server_name = get_server_name()
    payload_with_branding = dict(payload)
    payload_with_branding['_server_name'] = server_name
    message = _webhook_message(event, payload_with_branding)

    # ── Channel 1: Webhook ──────────────────────────────────────────────────────
    _send_webhook_to_url(event, payload_with_branding, message, cfg)

    # ── Channel 2: Email ────────────────────────────────────────────────────────
    if is_email_event_enabled(event, cfg):
        _send_event_email(event, payload_with_branding, message, cfg, server_name)


def _send_webhook_to_url(event, safe_payload, message, cfg):
    """Send the HTTP webhook portion. Was the body of fire_webhook pre-1.8.6."""
    url = cfg.get('webhook_url', '').strip()
    if not url:
        return  # Webhooks disabled (just running for email)

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        _log_webhook(event, url, 'error', 'invalid scheme (must be http or https)')
        return

    # Sanitize values
    safe_payload = {k: (str(v)[:256] if isinstance(v, str) else v) for k, v in safe_payload.items()}

    # Build human-readable title + message for push services
    titles = {
        'device_offline': 'Device Offline',
        'device_online':  'Device Online',
        'command_queued':  'Command Queued',
        'command_executed': 'Command Executed',
        'patch_alert':     'Patch Alert',
        'monitor_down':    'Monitor Down',
        'monitor_up':      'Monitor Recovered',
        'cve_found':       'New CVEs Detected',
        'service_down':    'Service Down',
        'service_up':      'Service Recovered',
        'log_alert':       'Log Pattern Matched',
        'test':            'Webhook Test',
    }
    title = titles.get(event, f'RemotePower: {event}')
    # message was passed in (computed once for both webhook + email channels)
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
    elif event == 'cve_found':
        sev_summary = f'{payload.get("critical", 0)} critical, {payload.get("high", 0)} high'
        return f'{name}: {payload.get("count", "?")} new CVEs ({sev_summary})'
    elif event == 'monitor_down':
        return f'Monitor "{payload.get("label", "?")}" ({payload.get("type", "?")}: {payload.get("target", "?")}) is DOWN — {payload.get("detail", "")}'
    elif event == 'monitor_up':
        return f'Monitor "{payload.get("label", "?")}" ({payload.get("type", "?")}: {payload.get("target", "?")}) recovered'
    elif event == 'service_down':
        return f'{name}: {payload.get("unit", "?")} is {payload.get("active", "down")} (was {payload.get("previous", "active")})'
    elif event == 'service_up':
        return f'{name}: {payload.get("unit", "?")} is active again'
    elif event == 'log_alert':
        return f'{name}/{payload.get("unit", "?")}: pattern "{payload.get("pattern", "")}" matched {payload.get("count", "?")} times'
    elif event == 'test':
        return f'This is a test notification from RemotePower ({payload.get("server_version", "?")}). If you see this, webhooks are working!'
    return f'{event}: {name}'


def _webhook_priority(event):
    """Return numeric priority (1-5) for push services. 3=default, 4=high, 5=urgent."""
    if event == 'cve_found':
        return 5
    if event in ('device_offline', 'monitor_down', 'patch_alert', 'service_down', 'log_alert'):
        return 4
    if event in ('device_online', 'monitor_up', 'service_up'):
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
        'cve_found':       'rotating_light,shield',
        'monitor_down':    'red_circle,satellite',
        'monitor_up':      'green_circle,satellite',
        'service_down':    'red_circle,gear',
        'service_up':      'green_circle,gear',
        'log_alert':       'warning,scroll',
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
    # v1.8.4: prefer per-event toggle from webhook_events dict; legacy keys still respected
    if not is_webhook_event_enabled('device_offline'):
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
        is_offline = (now - last) > get_online_ttl()
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

def handle_public_info():
    """
    GET /api/public-info — no auth. Used by the login page to fetch the
    server's display name and remember-me default before the user logs in.
    Deliberately exposes only non-sensitive values.
    """
    respond(200, {
        'server_name':         get_server_name(),
        'server_version':      SERVER_VERSION,
        'remember_me_default': get_remember_me_default(),
    })


def handle_openapi_spec() -> None:
    """
    GET /api/openapi.json — return the OpenAPI 3.1 specification.

    Auth-gated like every other endpoint: the spec describes the surface
    that auth tokens grant access to, so it makes no sense to expose it
    publicly. The Swagger UI page (``/swagger.html``) fetches this
    endpoint with the user's existing session token.
    """
    require_auth()
    respond(200, openapi_spec.build_spec(SERVER_VERSION))


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

    # v1.8.6: LDAP fallback. Local-first means an emergency local admin
    # always works even when LDAP is down. Only attempt LDAP if local failed.
    ldap_user_info = None
    if not valid:
        cfg = load(CONFIG_FILE)
        if cfg.get('ldap_enabled'):
            try:
                ldap_user_info = ldap_auth.authenticate(cfg, username, password)
                valid = True
                # Auto-provision: if user doesn't exist in users.json yet,
                # create them with the role determined by group membership.
                if not user:
                    new_role = ldap_user_info.role
                    users[username] = {
                        'role':            new_role,
                        # Store a placeholder hash that nothing matches —
                        # subsequent local-auth attempts will fail and fall
                        # through to LDAP again.
                        'password_hash':   '!' + secrets.token_hex(32),
                        'created':         int(time.time()),
                        'ldap_dn':         ldap_user_info.dn,
                        'ldap_full_name':  ldap_user_info.full_name,
                        'ldap_email':      ldap_user_info.email,
                    }
                    save(USERS_FILE, users)
                    user = users[username]
                    audit_log(username, 'ldap_auto_provision',
                              f'created from LDAP, role={new_role}, dn={ldap_user_info.dn}')
                else:
                    # Existing user — if their role should change based on group
                    # membership, update it. (Admin may have manually demoted; we
                    # respect group-driven promotions on each login.)
                    if user.get('role') != ldap_user_info.role:
                        # Only auto-promote (viewer→admin) on group match — never auto-demote
                        if ldap_user_info.role == 'admin' and user.get('role') != 'admin':
                            user['role'] = 'admin'
                            users[username] = user
                            save(USERS_FILE, users)
                            audit_log(username, 'ldap_role_promoted', 'matched admin group')
                audit_log(username, 'login_ldap', f'authenticated via LDAP (dn={ldap_user_info.dn})')
            except ldap_auth.LdapAuthDenied:
                # LDAP reachable but rejected the user — treat as plain auth failure.
                pass
            except ldap_auth.LdapTransientError as e:
                # LDAP itself is broken. Surface it in the audit log so the admin
                # can investigate, but to the client this still looks like normal
                # invalid-credentials (we don't want to leak whether LDAP is up).
                audit_log(username, 'login_ldap_error', f'LDAP unavailable: {e}')

    if not valid:
        _record_login_failure(username)
        audit_log(username, 'login_failed', 'invalid credentials')
        # Small constant delay to slow brute-force even further
        time.sleep(0.5)
        respond(200, {'ok': False})

    _clear_login_failures(username)
    if ldap_user_info is None:
        # Only rehash on local auth — LDAP users have placeholder hashes
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
    # v1.8.4: remember-me selects between short and long session TTL
    remember_me = bool(body.get('remember_me', False))
    ttl = get_session_ttl(remember_me=remember_me)
    tokens = load(TOKENS_FILE)
    tokens[token] = {
        'user':    username,
        'created': int(time.time()),
        'ttl':     ttl,
    }
    save(TOKENS_FILE, tokens)
    respond(200, {
        'ok':       True,
        'token':    token,
        'role':     user.get('role', 'admin'),
        'username': username,
        'ttl':      ttl,        # client may use to set its own expiry hints
    })


def handle_devices_list():
    require_auth()
    devices = load(DEVICES_FILE)
    now = int(time.time())
    result = []
    for dev_id, dev in devices.items():
        last_ping = dev.get('last_seen', 0)
        is_online = (now - last_ping) < get_online_ttl()
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
        'enrolled': now, 'last_seen': now, 'poll_interval': get_default_poll_interval(),
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

    # v1.8.0: process service report
    if 'services' in body and isinstance(body['services'], list):
        try:
            process_service_report(dev_id, body['services'])
        except Exception:
            pass  # never let service processing break heartbeat

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

        # v1.10.0: if this output is from a package-upgrade run, also archive
        # it in the dedicated update_logs.json file. The Patches page can
        # then surface it without scanning every exec result the device has
        # ever produced. We detect the upgrade by matching the synthetic
        # shell script the server queues in handle_upgrade_device — anything
        # containing the 'apt-get -y upgrade' or 'dnf -y upgrade' or
        # 'pacman -Syu' fragments counts.
        cmd_text = str(co.get('cmd', ''))
        if any(needle in cmd_text for needle in
               ('apt-get -y upgrade', 'dnf -y upgrade', 'pacman -Syu')):
            pkg_mgr = ('apt' if 'apt-get' in cmd_text
                       else 'dnf' if 'dnf' in cmd_text
                       else 'pacman' if 'pacman' in cmd_text
                       else 'unknown')
            ulogs = load(UPDATE_LOGS_FILE)
            if dev_id not in ulogs:
                ulogs[dev_id] = []
            ulogs[dev_id].append({
                'started_at':  now - 1,            # we don't know exactly
                'finished_at': now,
                'exit_code':   int(co['rc']) if isinstance(co.get('rc'), int) else -1,
                'output':      raw_output[:MAX_UPDATE_LOG_BYTES],
                'package_manager': pkg_mgr,
                'triggered_by': '',                # actor info already in audit log
            })
            ulogs[dev_id] = ulogs[dev_id][-MAX_UPDATE_LOGS_PER_DEVICE:]
            save(UPDATE_LOGS_FILE, ulogs)

    # ── v1.10.0: dedicated update output channel ───────────────────────────
    # Agent posts {'update_log': {started_at, finished_at, exit_code,
    # output, triggered_by, package_manager}} after running an `update`
    # command. We keep these separate from cmd_output so the Patches page
    # can list "last update on this device" without scanning unrelated
    # exec results.
    if 'update_log' in body and isinstance(body['update_log'], dict):
        ul = body['update_log']
        logs = load(UPDATE_LOGS_FILE)
        if dev_id not in logs:
            logs[dev_id] = []
        logs[dev_id].append({
            'started_at':  int(ul.get('started_at') or now),
            'finished_at': int(ul.get('finished_at') or now),
            'exit_code':   int(ul['exit_code']) if isinstance(ul.get('exit_code'), int) else -1,
            'output':      str(ul.get('output', ''))[:MAX_UPDATE_LOG_BYTES],
            'package_manager': _sanitize_str(ul.get('package_manager', ''), 32),
            'triggered_by': _sanitize_str(ul.get('triggered_by', ''), 64),
        })
        logs[dev_id] = logs[dev_id][-MAX_UPDATE_LOGS_PER_DEVICE:]
        save(UPDATE_LOGS_FILE, logs)

    cmds = load(CMDS_FILE)
    pending = cmds.get(dev_id, [])
    common_resp = {
        'poll_interval':    dev.get('poll_interval', 60),
        'services_watched': dev.get('services_watched', []),
        'log_watch':        dev.get('log_watch', []),
    }
    if pending:
        cmd = pending.pop(0); cmds[dev_id] = pending; save(CMDS_FILE, cmds)
        respond(200, {'command': cmd, **common_resp})
    else:
        respond(200, {'command': None, **common_resp})


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
        # v1.8.4: per-event toggle (down/up are checked individually below)
        mon_changed = False
        for r in results:
            key = r['label']
            if key not in mh: mh[key] = []
            mh[key].append({'ts': r['checked'], 'ok': r['ok'], 'detail': r['detail']})
            mh[key] = mh[key][-MAX_MON_HISTORY:]
            # Fire webhook on monitor state change. fire_webhook() respects per-event toggles.
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
    safe.setdefault('cve_webhook_enabled', True)
    safe.setdefault('service_webhook_enabled', True)
    safe.setdefault('monitor_interval', 300)

    # v1.8.4 — derived/effective values that the UI uses
    safe.setdefault('server_name', '')
    safe.setdefault('default_poll_interval', DEFAULT_POLL_INTERVAL)
    safe.setdefault('online_ttl', DEFAULT_ONLINE_TTL)
    safe.setdefault('cve_cache_days', DEFAULT_CVE_CACHE_DAYS)
    safe.setdefault('remember_me_default', False)
    safe.setdefault('session_ttl_short', DEFAULT_TOKEN_TTL_SHORT)
    safe.setdefault('session_ttl_long', DEFAULT_TOKEN_TTL_LONG)
    safe.setdefault('cve_severity_filter', list(CVE_SEVERITY_FILTER_DEFAULT))

    # webhook_events: build from explicit dict, falling back to legacy flags
    explicit = cfg.get('webhook_events') or {}
    derived_events = {}
    for ev, _label, _default in WEBHOOK_EVENTS:
        if ev in explicit:
            derived_events[ev] = bool(explicit[ev])
        else:
            derived_events[ev] = is_webhook_event_enabled(ev)
    safe['webhook_events'] = derived_events

    # v1.8.6: SMTP + LDAP defaults — passwords are masked in output
    safe.setdefault('smtp_enabled', False)
    safe.setdefault('smtp_host', '')
    safe.setdefault('smtp_port', 587)
    safe.setdefault('smtp_tls',  'starttls')
    safe.setdefault('smtp_from', '')
    safe.setdefault('smtp_username', '')
    safe.setdefault('smtp_helo_name', '')
    safe.setdefault('smtp_recipients', '')
    safe.setdefault('email_events', {})
    # Mask password — show only whether one is set
    safe['smtp_password_set'] = bool(cfg.get('smtp_password'))
    safe.pop('smtp_password', None)

    safe.setdefault('ldap_enabled', False)
    safe.setdefault('ldap_url', '')
    safe.setdefault('ldap_bind_dn', '')
    safe.setdefault('ldap_user_base', '')
    safe.setdefault('ldap_user_filter', '(uid={u})')
    safe.setdefault('ldap_required_group', '')
    safe.setdefault('ldap_admin_group', '')
    safe.setdefault('ldap_tls_verify', True)
    safe.setdefault('ldap_timeout', 5)
    safe['ldap_bind_password_set'] = bool(cfg.get('ldap_bind_password'))
    safe.pop('ldap_bind_password', None)

    # Static UI metadata (so the front-end doesn't have to hardcode this)
    safe['_meta'] = {
        'webhook_event_descriptions': {ev: desc for ev, desc, _ in WEBHOOK_EVENTS},
        'cve_severities':             list(CVE_SEVERITIES_ALL),
        'min_online_ttl':             MIN_ONLINE_TTL,
        'smtp_tls_modes':             ['starttls', 'tls', 'plain'],
    }
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

    if 'cve_webhook_enabled' in body:
        cfg['cve_webhook_enabled'] = bool(body['cve_webhook_enabled'])

    if 'service_webhook_enabled' in body:
        cfg['service_webhook_enabled'] = bool(body['service_webhook_enabled'])

    # v1.8.4: per-event toggles (preferred over legacy flags above)
    if 'webhook_events' in body and isinstance(body['webhook_events'], dict):
        clean = {}
        for ev, _label, _default in WEBHOOK_EVENTS:
            if ev in body['webhook_events']:
                clean[ev] = bool(body['webhook_events'][ev])
        cfg['webhook_events'] = clean

    # v1.8.4: server identity
    if 'server_name' in body:
        cfg['server_name'] = _sanitize_str(body['server_name'], 80)

    # v1.8.4: default poll interval (used at enrollment)
    if 'default_poll_interval' in body:
        try:
            v = int(body['default_poll_interval'])
            if not (10 <= v <= 3600):
                respond(400, {'error': 'default_poll_interval must be 10–3600 seconds'})
            cfg['default_poll_interval'] = v
        except (ValueError, TypeError):
            respond(400, {'error': 'default_poll_interval must be an integer'})

    # v1.8.4: online TTL
    if 'online_ttl' in body:
        try:
            v = int(body['online_ttl'])
            if v < MIN_ONLINE_TTL:
                respond(400, {'error': f'online_ttl must be >= {MIN_ONLINE_TTL} seconds'})
            if v > 7200:
                respond(400, {'error': 'online_ttl must be <= 7200 seconds (2h)'})
            cfg['online_ttl'] = v
        except (ValueError, TypeError):
            respond(400, {'error': 'online_ttl must be an integer'})

    # v1.8.4: CVE details cache TTL (in days, internally stored as days)
    if 'cve_cache_days' in body:
        try:
            v = int(body['cve_cache_days'])
            if not (1 <= v <= 90):
                respond(400, {'error': 'cve_cache_days must be 1–90'})
            cfg['cve_cache_days'] = v
        except (ValueError, TypeError):
            respond(400, {'error': 'cve_cache_days must be an integer'})

    # v1.8.4: CVE severity filter (which severities fire cve_found webhook)
    if 'cve_severity_filter' in body:
        raw = body['cve_severity_filter']
        if not isinstance(raw, list):
            respond(400, {'error': 'cve_severity_filter must be a list'})
        clean = [s for s in raw if s in CVE_SEVERITIES_ALL]
        if not clean:
            respond(400, {'error': f'cve_severity_filter must contain at least one of {list(CVE_SEVERITIES_ALL)}'})
        cfg['cve_severity_filter'] = clean

    # v1.8.4: remember-me semantics
    if 'remember_me_default' in body:
        cfg['remember_me_default'] = bool(body['remember_me_default'])
    if 'session_ttl_short' in body:
        try:
            v = int(body['session_ttl_short'])
            if not (300 <= v <= 86400 * 7):
                respond(400, {'error': 'session_ttl_short must be 300–604800 seconds'})
            cfg['session_ttl_short'] = v
        except (ValueError, TypeError):
            respond(400, {'error': 'session_ttl_short must be an integer'})
    if 'session_ttl_long' in body:
        try:
            v = int(body['session_ttl_long'])
            if not (3600 <= v <= 86400 * 90):
                respond(400, {'error': 'session_ttl_long must be 3600–7776000 seconds'})
            cfg['session_ttl_long'] = v
        except (ValueError, TypeError):
            respond(400, {'error': 'session_ttl_long must be an integer'})

    # ── v1.8.6: SMTP settings ──────────────────────────────────────────────────
    if 'smtp_enabled' in body:
        cfg['smtp_enabled'] = bool(body['smtp_enabled'])
    if 'smtp_host' in body:
        cfg['smtp_host'] = _sanitize_str(body['smtp_host'], 255)
    if 'smtp_port' in body:
        try:
            v = int(body['smtp_port'])
            if not (1 <= v <= 65535):
                respond(400, {'error': 'smtp_port must be 1–65535'})
            cfg['smtp_port'] = v
        except (ValueError, TypeError):
            respond(400, {'error': 'smtp_port must be an integer'})
    if 'smtp_tls' in body:
        v = _sanitize_str(body['smtp_tls'], 16).lower()
        if v not in ('starttls', 'tls', 'plain'):
            respond(400, {'error': 'smtp_tls must be starttls, tls, or plain'})
        cfg['smtp_tls'] = v
    if 'smtp_from' in body:
        v = _sanitize_str(body['smtp_from'], 255)
        if v and '@' not in v:
            respond(400, {'error': 'smtp_from must be a valid email address'})
        cfg['smtp_from'] = v
    if 'smtp_username' in body:
        cfg['smtp_username'] = _sanitize_str(body['smtp_username'], 255)
    if 'smtp_password' in body:
        # Empty string clears it; leaving the key out preserves existing
        new_pw = body['smtp_password']
        if new_pw == '':
            cfg.pop('smtp_password', None)
        elif isinstance(new_pw, str):
            cfg['smtp_password'] = new_pw[:1024]
    if 'smtp_helo_name' in body:
        cfg['smtp_helo_name'] = _sanitize_str(body['smtp_helo_name'], 255)
    if 'smtp_recipients' in body:
        cfg['smtp_recipients'] = _sanitize_str(body['smtp_recipients'], 2000)

    # Per-event email toggles
    if 'email_events' in body and isinstance(body['email_events'], dict):
        clean = {}
        for ev_name in WEBHOOK_EVENT_NAMES:
            if ev_name in body['email_events']:
                clean[ev_name] = bool(body['email_events'][ev_name])
        cfg['email_events'] = clean

    # ── v1.8.6: LDAP settings ──────────────────────────────────────────────────
    if 'ldap_enabled' in body:
        cfg['ldap_enabled'] = bool(body['ldap_enabled'])
    if 'ldap_url' in body:
        v = _sanitize_str(body['ldap_url'], 255)
        if v and not (v.startswith('ldap://') or v.startswith('ldaps://')):
            respond(400, {'error': 'ldap_url must start with ldap:// or ldaps://'})
        cfg['ldap_url'] = v
    if 'ldap_bind_dn' in body:
        cfg['ldap_bind_dn'] = _sanitize_str(body['ldap_bind_dn'], 512)
    if 'ldap_bind_password' in body:
        new_pw = body['ldap_bind_password']
        if new_pw == '':
            cfg.pop('ldap_bind_password', None)
        elif isinstance(new_pw, str):
            cfg['ldap_bind_password'] = new_pw[:1024]
    if 'ldap_user_base' in body:
        cfg['ldap_user_base'] = _sanitize_str(body['ldap_user_base'], 512)
    if 'ldap_user_filter' in body:
        v = _sanitize_str(body['ldap_user_filter'], 256)
        if v and '{u}' not in v:
            respond(400, {'error': 'ldap_user_filter must contain {u} placeholder'})
        cfg['ldap_user_filter'] = v or '(uid={u})'
    if 'ldap_required_group' in body:
        cfg['ldap_required_group'] = _sanitize_str(body['ldap_required_group'], 512)
    if 'ldap_admin_group' in body:
        cfg['ldap_admin_group'] = _sanitize_str(body['ldap_admin_group'], 512)
    if 'ldap_tls_verify' in body:
        cfg['ldap_tls_verify'] = bool(body['ldap_tls_verify'])
    if 'ldap_timeout' in body:
        try:
            v = int(body['ldap_timeout'])
            if not (1 <= v <= 60):
                respond(400, {'error': 'ldap_timeout must be 1–60 seconds'})
            cfg['ldap_timeout'] = v
        except (ValueError, TypeError):
            respond(400, {'error': 'ldap_timeout must be an integer'})

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


def handle_device_update_logs(dev_id: str) -> None:
    """
    GET /api/devices/{id}/update-logs.

    Returns the rolling buffer of `update` command runs for this device.

    Each entry: ``{started_at, finished_at, exit_code, output,
    package_manager, triggered_by}``. Most recent runs are at the end of
    the list. Capped at :data:`MAX_UPDATE_LOGS_PER_DEVICE` entries per
    device with the oldest evicted on overflow.
    """
    require_auth()
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    logs = load(UPDATE_LOGS_FILE)
    respond(200, {
        'device_id': dev_id,
        'name':      devices[dev_id].get('name', dev_id),
        'logs':      logs.get(dev_id, []),
        'capacity':  MAX_UPDATE_LOGS_PER_DEVICE,
    })


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
    online  = sum(1 for d in devices.values() if (now - d.get('last_seen', 0)) < get_online_ttl())
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
        is_online = (now - dev.get('last_seen', 0)) < get_online_ttl()

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
    is_online = (now - dev.get('last_seen', 0)) < get_online_ttl()

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
        is_online = (now - dev.get('last_seen', 0)) < get_online_ttl()
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
        is_online = (now - dev.get('last_seen', 0)) < get_online_ttl()
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


# ─── v1.8.6: SMTP test endpoint ───────────────────────────────────────────────

def handle_smtp_test():
    """
    POST /api/smtp/test
    Sends a test email using current settings (or override config in body).
    Body may include 'recipient' to override the configured recipient list.
    """
    actor = require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})

    body = get_json_body() if os.environ.get('CONTENT_LENGTH', '0') != '0' else {}
    cfg = load(CONFIG_FILE)
    override_recipient = _sanitize_str(body.get('recipient', ''), 320)

    if override_recipient:
        if '@' not in override_recipient:
            respond(400, {'error': 'recipient must be a valid email address'})
        recipients = [override_recipient]
    else:
        recipients = _smtp_recipients_list(cfg)
    if not recipients:
        respond(400, {'error': 'No recipients configured. Set "smtp_recipients" or pass {"recipient": "..."}'})

    server_name = get_server_name()
    try:
        result = smtp_notifier.send_email(
            cfg, recipients,
            subject=f'[{server_name}] Test email from RemotePower',
            body=(
                f'This is a test email from {server_name}.\n\n'
                f'Triggered by: {actor}\n'
                f'Server version: {SERVER_VERSION}\n'
                f'Timestamp: {time.strftime("%Y-%m-%d %H:%M:%S %Z")}\n\n'
                'If you received this, your SMTP configuration works correctly.\n'
                'If you did NOT request this email, someone with admin access '
                'on the RemotePower server triggered it. Investigate.\n'
            ),
        )
        _log_email('test', recipients, 'ok', f'test sent to {len(recipients)} recipient(s)')
        audit_log(actor, 'smtp_test', f'test email sent to {len(recipients)} recipient(s)')
        respond(200, {'ok': True, 'recipients': recipients, 'result': result})
    except smtp_notifier.SmtpError as e:
        _log_email('test', recipients, 'error', str(e))
        audit_log(actor, 'smtp_test_failed', str(e))
        respond(200, {'ok': False, 'error': str(e), 'recipients': recipients})


# ─── v1.8.6: LDAP test endpoints ──────────────────────────────────────────────

def handle_ldap_test():
    """
    POST /api/ldap/test
    Verifies the service-account bind to LDAP. Doesn't try to authenticate
    a specific user. Useful for confirming URL/TLS/credentials before
    enabling LDAP login.
    """
    actor = require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})

    body = get_json_body() if os.environ.get('CONTENT_LENGTH', '0') != '0' else {}
    cfg = load(CONFIG_FILE)

    # Allow body to override config for "try before save" UX
    test_cfg = dict(cfg)
    for k in ('ldap_url', 'ldap_bind_dn', 'ldap_bind_password',
              'ldap_user_base', 'ldap_user_filter', 'ldap_tls_verify', 'ldap_timeout'):
        if k in body:
            test_cfg[k] = body[k]

    result = ldap_auth.test_connection(test_cfg)
    audit_log(actor, 'ldap_test',
              f'{"success" if result.get("ok") else "failed"}: {result.get("detail", "")[:200]}')
    respond(200, result)


def handle_ldap_test_user():
    """
    POST /api/ldap/test-user {"username":"alice","password":"..."}
    Runs the full authentication path for one user. Returns the resolved DN,
    role, and group-derived flags. Doesn't create a session.
    """
    actor = require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})

    body = get_json_body()
    username = _sanitize_str(body.get('username', ''), 64)
    password = body.get('password', '')
    if not username or not isinstance(password, str):
        respond(400, {'error': 'username and password are required'})

    cfg = load(CONFIG_FILE)
    if not cfg.get('ldap_enabled'):
        respond(400, {'error': 'LDAP is not enabled — turn it on first'})

    try:
        info = ldap_auth.authenticate(cfg, username, password)
        audit_log(actor, 'ldap_test_user',
                  f'tested {username} → role={info.role}, dn={info.dn}')
        respond(200, {
            'ok':         True,
            'dn':         info.dn,
            'role':       info.role,
            'full_name':  info.full_name,
            'email':      info.email,
            'username':   info.username,
        })
    except ldap_auth.LdapAuthDenied as e:
        respond(200, {'ok': False, 'error': f'auth denied: {e}'})
    except ldap_auth.LdapTransientError as e:
        respond(200, {'ok': False, 'error': f'LDAP error: {e}'})


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


# ─── v1.7.0: CVE scanner + package inventory ──────────────────────────────────

def _sanitize_package_entry(entry):
    """Sanitize one {name,version,arch} dict from agent payload."""
    if not isinstance(entry, dict):
        return None
    name = _sanitize_str(entry.get('name', ''), 128, allow_empty=False)
    version = _sanitize_str(entry.get('version', ''), 64, allow_empty=False)
    arch = _sanitize_str(entry.get('arch', ''), 16)
    if not name or not version:
        return None
    # Package names / versions are alphanum + common punctuation
    if not re.match(r'^[A-Za-z0-9][A-Za-z0-9._+\-:~]{0,127}$', name):
        return None
    if not re.match(r'^[A-Za-z0-9][A-Za-z0-9._+\-:~]{0,63}$', version):
        return None
    return {'name': name, 'version': version, 'arch': arch}


def handle_packages_submit():
    """POST /api/packages — agent submits its installed package list."""
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

    raw_pkgs = body.get('packages') or []
    if not isinstance(raw_pkgs, list):
        respond(400, {'error': 'packages must be a list'})
    if len(raw_pkgs) > MAX_PACKAGE_LIST:
        raw_pkgs = raw_pkgs[:MAX_PACKAGE_LIST]

    packages = []
    for entry in raw_pkgs:
        safe = _sanitize_package_entry(entry)
        if safe:
            packages.append(safe)

    pkg_manager = _sanitize_str(body.get('pkg_manager', ''), 16)
    hint = body.get('ecosystem_hint') or {}
    safe_hint = {
        'ID':         _sanitize_str(hint.get('ID', ''), 32),
        'VERSION_ID': _sanitize_str(hint.get('VERSION_ID', ''), 16),
        'ID_LIKE':    _sanitize_str(hint.get('ID_LIKE', ''), 64),
    }

    ecosystem = cve_scanner.detect_ecosystem(safe_hint, pkg_manager)

    store = load(PACKAGES_FILE)
    new_hash = cve_scanner.packages_hash(packages)
    existing = store.get(dev_id, {})
    store[dev_id] = {
        'hash':         new_hash,
        'collected_at': int(time.time()),
        'ecosystem':    ecosystem or '',
        'pkg_manager':  pkg_manager,
        'count':        len(packages),
        'packages':     packages,
    }
    save(PACKAGES_FILE, store)

    changed = existing.get('hash') != new_hash
    respond(200, {
        'ok':              True,
        'ecosystem':       ecosystem or 'unsupported',
        'packages_stored': len(packages),
        'changed':         changed,
        'scan_suggested':  changed and bool(ecosystem),
    })


def _detect_new_cve_and_fire_webhook(dev_id, devices, previous, current):
    """Fire webhook if new CVEs in the configured severity filter appeared since last scan."""
    if not is_webhook_event_enabled('cve_found'):
        return

    ignore_data = load(CVE_IGNORE_FILE)
    prev_ids = {f['vuln_id'] for f in previous}
    severity_filter = set(get_cve_severity_filter())

    new_alerted = []
    for f in current:
        if f['vuln_id'] in prev_ids:
            continue
        if f.get('severity') not in severity_filter:
            continue
        ig = ignore_data.get(f['vuln_id'])
        if ig and (ig.get('scope') == 'global' or ig.get('scope') == dev_id):
            continue
        new_alerted.append(f)

    if not new_alerted:
        return

    dev = devices.get(dev_id, {})
    fire_webhook('cve_found', {
        'device_id':  dev_id,
        'name':       dev.get('name', dev_id),
        'count':      len(new_alerted),
        'critical':   sum(1 for f in new_alerted if f['severity'] == 'critical'),
        'high':       sum(1 for f in new_alerted if f['severity'] == 'high'),
        'sample':     [{'id': f['vuln_id'], 'pkg': f['package'], 'sev': f['severity']}
                       for f in new_alerted[:5]],
    })


def handle_cve_scan():
    """POST /api/cve/scan — admin triggers scan for one or all devices."""
    actor = require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})

    body = get_json_body() if os.environ.get('CONTENT_LENGTH', '0') != '0' else {}
    target = body.get('device_id')
    if target is not None:
        target = str(target).strip()
        if not _validate_id(target):
            respond(400, {'error': 'Invalid device_id'})

    store = load(PACKAGES_FILE)
    findings_all = load(CVE_FINDINGS_FILE)
    devices = load(DEVICES_FILE)

    scanned = []
    skipped = []
    errors  = []

    targets = [target] if target else list(store.keys())

    for dev_id in targets:
        entry = store.get(dev_id)
        if not entry:
            skipped.append({'device_id': dev_id, 'reason': 'no package list submitted yet'})
            continue
        ecosystem = entry.get('ecosystem') or ''
        if not ecosystem:
            skipped.append({'device_id': dev_id, 'reason': 'unsupported ecosystem'})
            continue

        result = cve_scanner.scan_device(
            dev_id,
            entry.get('packages') or [],
            ecosystem,
            DATA_DIR,
            cache_ttl=get_cve_cache_seconds(),
        )

        if result.get('error') and not result.get('findings'):
            errors.append({'device_id': dev_id, 'error': result['error']})
            continue

        previous = findings_all.get(dev_id, {}).get('findings') or []
        findings_all[dev_id] = result
        _detect_new_cve_and_fire_webhook(dev_id, devices, previous, result.get('findings') or [])
        scanned.append({'device_id': dev_id, 'findings': len(result.get('findings') or [])})

    save(CVE_FINDINGS_FILE, findings_all)
    audit_log(actor, 'cve_scan',
              detail=f'scanned={len(scanned)} skipped={len(skipped)} errors={len(errors)}')
    respond(200, {'scanned': scanned, 'skipped': skipped, 'errors': errors})


def handle_cve_findings():
    """GET /api/cve/findings — aggregate CVE report across all devices."""
    require_auth()
    findings_all = load(CVE_FINDINGS_FILE)
    ignore_data  = load(CVE_IGNORE_FILE)
    pkg_store    = load(PACKAGES_FILE)
    devices      = load(DEVICES_FILE)
    now = int(time.time())

    report = {
        'generated_at': now,
        'devices':      [],
        'summary':      {'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
                         'unknown':  0, 'ignored':  0, 'devices_scanned': 0,
                         'devices_with_findings': 0,
                         'devices_unsupported': 0},
    }

    for dev_id, dev in devices.items():
        pkg_entry = pkg_store.get(dev_id) or {}
        ecosystem = pkg_entry.get('ecosystem', '')
        f_entry = findings_all.get(dev_id) or {}
        findings = f_entry.get('findings') or []
        summary = cve_scanner.summarize_findings(
            findings,
            {k for k, v in ignore_data.items()
             if v.get('scope') == 'global' or v.get('scope') == dev_id}
        )
        status = 'scanned'
        if not pkg_entry:
            status = 'no_packages'
        elif not ecosystem:
            status = 'unsupported'
            report['summary']['devices_unsupported'] += 1
        elif not f_entry:
            status = 'not_scanned'

        if f_entry:
            report['summary']['devices_scanned'] += 1
            if sum(summary[k] for k in ('critical', 'high', 'medium', 'low')) > 0:
                report['summary']['devices_with_findings'] += 1
            for k in ('critical', 'high', 'medium', 'low', 'unknown', 'ignored'):
                report['summary'][k] += summary[k]

        report['devices'].append({
            'device_id':   dev_id,
            'name':        dev.get('name', dev_id),
            'group':       dev.get('group', ''),
            'os':          dev.get('os', ''),
            'ecosystem':   ecosystem or 'unsupported',
            'status':      status,
            'scanned_at':  f_entry.get('scanned_at', 0),
            'package_count': pkg_entry.get('count', 0),
            'counts':      summary,
        })

    report['devices'].sort(
        key=lambda d: (-d['counts']['critical'], -d['counts']['high'], d['name'].lower())
    )
    respond(200, report)


def handle_cve_device(dev_id):
    """GET /api/devices/{id}/cve — detailed findings for one device."""
    require_auth()
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})

    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})

    findings_all = load(CVE_FINDINGS_FILE)
    ignore_data  = load(CVE_IGNORE_FILE)
    pkg_store    = load(PACKAGES_FILE)
    dev = devices[dev_id]

    f_entry   = findings_all.get(dev_id) or {}
    pkg_entry = pkg_store.get(dev_id) or {}
    findings  = f_entry.get('findings') or []
    findings  = cve_scanner.apply_ignore_list(findings, ignore_data, dev_id)

    respond(200, {
        'device_id':      dev_id,
        'name':           dev.get('name', dev_id),
        'group':          dev.get('group', ''),
        'os':             dev.get('os', ''),
        'ecosystem':      pkg_entry.get('ecosystem', '') or 'unsupported',
        'scanned_at':     f_entry.get('scanned_at', 0),
        'packages_count': pkg_entry.get('count', 0),
        'collected_at':   pkg_entry.get('collected_at', 0),
        'findings':       findings,
        'error':          f_entry.get('error', ''),
    })


def handle_cve_ignore_add():
    """POST /api/cve/ignore — mark a vuln as accepted risk."""
    actor = require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})

    body     = get_json_body()
    vuln_id  = _sanitize_str(body.get('vuln_id', ''), 64, allow_empty=False)
    reason   = _sanitize_str(body.get('reason', ''), 256)
    scope    = _sanitize_str(body.get('scope', 'global'), 64)
    if not vuln_id:
        respond(400, {'error': 'vuln_id required'})
    if scope != 'global' and not _validate_id(scope):
        respond(400, {'error': 'scope must be "global" or a valid device_id'})

    ignore_data = load(CVE_IGNORE_FILE)
    ignore_data[vuln_id] = {
        'scope':  scope,
        'reason': reason,
        'actor':  actor,
        'ts':     int(time.time()),
    }
    save(CVE_IGNORE_FILE, ignore_data)
    audit_log(actor, 'cve_ignore_add',
              detail=f'{vuln_id} scope={scope} reason={reason[:80]}')
    respond(200, {'ok': True, 'ignored': vuln_id})


def handle_cve_ignore_delete(vuln_id):
    """DELETE /api/cve/ignore/{vuln_id}"""
    actor = require_admin_auth()
    vuln_id = _sanitize_str(vuln_id, 64, allow_empty=False)
    if not vuln_id:
        respond(400, {'error': 'Invalid vuln_id'})
    ignore_data = load(CVE_IGNORE_FILE)
    if vuln_id in ignore_data:
        del ignore_data[vuln_id]
        save(CVE_IGNORE_FILE, ignore_data)
        audit_log(actor, 'cve_ignore_remove', detail=vuln_id)
    respond(200, {'ok': True})


def handle_cve_ignore_list():
    """GET /api/cve/ignore — list all active ignores."""
    require_auth()
    ignore_data = load(CVE_IGNORE_FILE)
    items = [{'vuln_id': k, **v} for k, v in ignore_data.items()]
    items.sort(key=lambda x: -x.get('ts', 0))
    respond(200, {'ignores': items})


# ─── v1.7.0: Prometheus metrics exporter ──────────────────────────────────────

def handle_prometheus_metrics():
    """
    GET /api/metrics — Prometheus text exposition.
    Auth: X-Token header OR Authorization: Bearer <key> (Prometheus-native).
    """
    token = get_token_from_request()
    if not token:
        auth = os.environ.get('HTTP_AUTHORIZATION', '')
        if auth.lower().startswith('bearer '):
            token = auth[7:].strip()
    username, _role = verify_token(token)
    if not username:
        print('Status: 401 Unauthorized')
        print('Content-Type: text/plain; charset=utf-8')
        print('WWW-Authenticate: Bearer realm="remotepower"')
        print('Cache-Control: no-store')
        print()
        print('Unauthorized')
        sys.exit(0)

    now = int(time.time())
    devices = load(DEVICES_FILE)
    cfg = load(CONFIG_FILE)
    mon_hist = load(MON_HIST_FILE)

    monitor_state = {}
    for label, entries in mon_hist.items():
        if entries:
            last = entries[-1]
            monitor_state[label] = {
                'up':   bool(last.get('up', True)),
                'last': last.get('ts', 0),
            }

    # v1.8.0: maintenance-window context — count currently active
    maint = load(MAINT_FILE)
    maint_active = 0
    for w in (maint.get('windows') or []):
        try:
            if _window_active(w, now):
                maint_active += 1
        except Exception:
            pass

    ctx = {
        'server_version':  SERVER_VERSION,
        'now':             now,
        'online_ttl':      get_online_ttl(),
        'devices':         devices,
        'monitors':        cfg.get('monitors') or [],
        'monitor_state':   monitor_state,
        'schedule':        load(SCHEDULE_FILE),
        'pending_cmds':    load(CMDS_FILE),
        'webhook_log':     load(WEBHOOK_LOG_FILE),
        'webhook_log_cap': MAX_WEBHOOK_LOG,
        'cve_findings':    load(CVE_FINDINGS_FILE),
        'cve_ignore':      load(CVE_IGNORE_FILE),
        'services':        load(SERVICES_FILE),
        'maintenance_active_count': maint_active,
    }
    body = prometheus_export.generate_metrics(ctx)

    print('Status: 200 OK')
    print('Content-Type: text/plain; version=0.0.4; charset=utf-8')
    print('Cache-Control: no-store')
    print()
    print(body)
    sys.exit(0)


# ─── v1.8.0: Maintenance windows ───────────────────────────────────────────────

def _cron_match(expr, ts):
    """
    Very small cron evaluator — 5 fields, no ranges like 1-5, no `@reboot`.
    Supports *, */N, a,b,c, single integers. Matches the minute containing `ts`.
    """
    parts = (expr or '').split()
    if len(parts) != 5:
        return False
    tm = time.localtime(ts)
    # cron weekday: 0=Sun..6=Sat; Python tm_wday: 0=Mon..6=Sun. Convert.
    cron_wday = (tm.tm_wday + 1) % 7
    values = (tm.tm_min, tm.tm_hour, tm.tm_mday, tm.tm_mon, cron_wday)
    for spec, v in zip(parts, values):
        if not _cron_field_match(spec, v):
            return False
    return True


def _cron_field_match(spec, value):
    spec = spec.strip()
    if spec == '*':
        return True
    if spec.startswith('*/'):
        try:
            step = int(spec[2:])
            return step > 0 and value % step == 0
        except ValueError:
            return False
    for part in spec.split(','):
        part = part.strip()
        if not part:
            continue
        try:
            if int(part) == value:
                return True
        except ValueError:
            continue
    return False


def _window_active(window, now):
    """Return True if this maintenance window is active right now."""
    # One-shot: ISO-8601 start + end
    start = window.get('start')
    end   = window.get('end')
    if start and end:
        try:
            # Accept both '2026-05-10T22:00:00Z' and '2026-05-10T22:00:00+00:00'
            s = _parse_iso(start)
            e = _parse_iso(end)
            if s <= now <= e:
                return True
        except ValueError:
            pass
    # Recurring cron window
    cron = window.get('cron')
    dur  = int(window.get('duration', 0) or 0)
    if cron and dur > 0:
        # Check the current minute and each minute in the past `dur` seconds
        # to see if this cron expression matched at a time that's still within
        # its duration. We scan backwards in 60s steps — cheap and good enough.
        for i in range(0, dur, 60):
            probe = now - i
            if _cron_match(cron, probe):
                return True
    return False


def _parse_iso(s):
    """Parse ISO-8601 timestamp → unix ts. Supports 'Z' suffix and +HH:MM."""
    if s.endswith('Z'):
        s = s[:-1] + '+00:00'
    # Python 3.7+ handles the rest
    import datetime as _dt
    return int(_dt.datetime.fromisoformat(s).timestamp())


# Events that maintenance windows can suppress
SUPPRESSIBLE_EVENTS = (
    'device_offline', 'device_online',
    'monitor_down',   'monitor_up',
    'service_down',   'service_up',
    'patch_alert',    'cve_found',
    'log_alert',
)


def in_maintenance(event, payload):
    """
    Return {'reason': ...} if this (event, device) is under an active
    maintenance window, else None. Matches on:
      - payload['device_id']          → device-specific windows
      - device.group                   → group-wide windows
      - window.scope == 'global'       → fleet-wide windows
    """
    if event not in SUPPRESSIBLE_EVENTS:
        return None

    maint = load(MAINT_FILE)
    windows = maint.get('windows') or []
    if not windows:
        return None

    now = int(time.time())
    dev_id = payload.get('device_id', '')
    dev_group = ''
    if dev_id:
        devices = load(DEVICES_FILE)
        dev_group = (devices.get(dev_id, {}).get('group') or '')

    for w in windows:
        scope = (w.get('scope') or 'device').lower()
        # Decide if this window applies to this target
        applies = False
        if scope == 'global':
            applies = True
        elif scope == 'group' and dev_group and w.get('target') == dev_group:
            applies = True
        elif scope == 'device' and dev_id and w.get('target') == dev_id:
            applies = True
        if not applies:
            continue
        if _window_active(w, now):
            # Respect an optional per-window event list (defaults to all)
            allowed = w.get('events')
            if allowed and event not in allowed:
                continue
            return {
                'window_id': w.get('id', ''),
                'reason':    w.get('reason', 'maintenance window active'),
                'scope':     scope,
                'target':    w.get('target', ''),
            }
    return None


def log_suppression(event, payload, info):
    """Append an entry to the maintenance-suppression audit trail."""
    try:
        log = load(MAINT_SUPPRESS_LOG)
        entries = log.get('entries') or []
        entries.append({
            'ts':         int(time.time()),
            'event':      event,
            'device_id':  payload.get('device_id', ''),
            'window_id':  info.get('window_id', ''),
            'reason':     info.get('reason', ''),
            'scope':      info.get('scope', ''),
        })
        entries = entries[-500:]  # keep last 500
        log['entries'] = entries
        save(MAINT_SUPPRESS_LOG, log)
    except Exception:
        pass


def handle_maintenance_list():
    """GET /api/maintenance — list all defined windows + currently active ones."""
    require_auth()
    maint = load(MAINT_FILE)
    windows = maint.get('windows') or []
    now = int(time.time())
    out = []
    for w in windows:
        out.append({**w, 'active': _window_active(w, now)})
    out.sort(key=lambda x: (not x['active'], x.get('reason', '')))
    respond(200, {'windows': out})


def handle_maintenance_add():
    """POST /api/maintenance — create a window."""
    actor = require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})

    body = get_json_body()
    reason = _sanitize_str(body.get('reason', ''), 128)
    scope  = _sanitize_str(body.get('scope', 'device'), 16).lower()
    target = _sanitize_str(body.get('target', ''), 128)
    start  = _sanitize_str(body.get('start', ''), 32)
    end    = _sanitize_str(body.get('end', ''), 32)
    cron   = _sanitize_str(body.get('cron', ''), 64)

    try:
        duration = int(body.get('duration', 0) or 0)
    except (TypeError, ValueError):
        duration = 0

    events = body.get('events') or []
    if not isinstance(events, list):
        events = []
    events = [e for e in events if e in SUPPRESSIBLE_EVENTS][:10]

    if scope not in ('device', 'group', 'global'):
        respond(400, {'error': 'scope must be device, group, or global'})
    if scope == 'device' and not _validate_id(target):
        respond(400, {'error': 'device-scoped window requires a valid target device_id'})
    if scope == 'group' and not target:
        respond(400, {'error': 'group-scoped window requires a target group name'})

    # Must be either (start+end) or (cron+duration) — not both, not neither
    has_oneshot = bool(start and end)
    has_cron    = bool(cron and duration > 0)
    if has_oneshot == has_cron:
        respond(400, {'error': 'specify exactly one of (start+end) or (cron+duration)'})

    if has_oneshot:
        try:
            s = _parse_iso(start); e = _parse_iso(end)
            if e <= s:
                respond(400, {'error': 'end must be after start'})
        except ValueError:
            respond(400, {'error': 'invalid ISO-8601 timestamp'})

    if has_cron:
        if _cron_match(cron, int(time.time())) is False and len(cron.split()) != 5:
            respond(400, {'error': 'cron must have 5 space-separated fields'})
        if duration < 60 or duration > 86400 * 7:
            respond(400, {'error': 'duration must be 60..604800 seconds'})

    window = {
        'id':       secrets.token_hex(8),
        'reason':   reason,
        'scope':    scope,
        'target':   target,
        'start':    start,
        'end':      end,
        'cron':     cron,
        'duration': duration,
        'events':   events,
        'created_by': actor,
        'created_at': int(time.time()),
    }

    maint = load(MAINT_FILE)
    windows = maint.get('windows') or []
    windows.append(window)
    maint['windows'] = windows
    save(MAINT_FILE, maint)
    audit_log(actor, 'maintenance_add',
              detail=f'id={window["id"]} scope={scope} target={target} reason={reason[:60]}')
    respond(200, {'ok': True, 'window': window})


def handle_maintenance_delete(window_id):
    """DELETE /api/maintenance/{id}"""
    actor = require_admin_auth()
    maint = load(MAINT_FILE)
    windows = maint.get('windows') or []
    remaining = [w for w in windows if w.get('id') != window_id]
    if len(remaining) == len(windows):
        respond(404, {'error': 'Window not found'})
    maint['windows'] = remaining
    save(MAINT_FILE, maint)
    audit_log(actor, 'maintenance_delete', detail=f'id={window_id}')
    respond(200, {'ok': True})


def handle_maintenance_suppressions():
    """GET /api/maintenance/suppressions — recent suppression audit trail."""
    require_auth()
    log = load(MAINT_SUPPRESS_LOG)
    respond(200, {'entries': (log.get('entries') or [])[-100:][::-1]})


# ─── v1.8.0: Service monitoring (agent-reported systemd units) ────────────────

def _sanitize_unit_name(name):
    """Allow systemd unit names: letters, digits, @.-_+ and must end in .service
    or have no dot. Just bound length and reject whitespace/path traversal."""
    if not isinstance(name, str):
        return None
    s = name.strip()[:128]
    if not s or not re.match(r'^[A-Za-z0-9][A-Za-z0-9._@+\-]{0,127}$', s):
        return None
    return s


def _sanitize_service_entry(entry):
    if not isinstance(entry, dict):
        return None
    unit   = _sanitize_unit_name(entry.get('unit', ''))
    if not unit:
        return None
    active = str(entry.get('active', 'unknown'))[:16]
    sub    = str(entry.get('sub', ''))[:32]
    since  = entry.get('since') or 0
    try:
        since = int(since)
    except (TypeError, ValueError):
        since = 0
    return {'unit': unit, 'active': active, 'sub': sub, 'since': since}


def _record_service_transition(dev_id, unit, old_active, new_active, ts):
    """Append a transition to service_history.json keyed by (device,unit)."""
    hist = load(SERVICE_HIST_FILE)
    key = f'{dev_id}:{unit}'
    entries = hist.get(key) or []
    entries.append({'ts': ts, 'from': old_active, 'to': new_active})
    entries = entries[-MAX_SERVICE_HIST:]
    hist[key] = entries
    save(SERVICE_HIST_FILE, hist)


def _fire_service_webhook(event, dev_id, unit, payload_extra=None):
    """Wrapper that fires service_up/service_down through fire_webhook."""
    devices = load(DEVICES_FILE)
    dev = devices.get(dev_id, {})
    payload = {
        'device_id': dev_id,
        'name':      dev.get('name', dev_id),
        'group':     dev.get('group', ''),
        'unit':      unit,
    }
    if payload_extra:
        payload.update(payload_extra)
    fire_webhook(event, payload)


def process_service_report(dev_id, services_payload):
    """
    Called from handle_heartbeat. Updates services.json, records transitions,
    fires webhooks on state changes.

    services_payload: [{unit, active, sub, since}, ...]
    """
    if not isinstance(services_payload, list):
        return

    now = int(time.time())
    clean = []
    for entry in services_payload[:MAX_SERVICES_PER_DEVICE]:
        e = _sanitize_service_entry(entry)
        if e:
            clean.append(e)
    if not clean:
        return

    store = load(SERVICES_FILE)
    prev_dev = store.get(dev_id) or {}
    prev_by_unit = {s['unit']: s for s in (prev_dev.get('services') or [])}

    for entry in clean:
        prev = prev_by_unit.get(entry['unit'])
        if not prev:
            continue  # first time we see this unit; no transition yet
        # Normalize: treat anything other than 'active' as "down" for alerting
        was_up = (prev.get('active') == 'active')
        is_up  = (entry['active'] == 'active')
        if was_up != is_up:
            _record_service_transition(
                dev_id, entry['unit'], prev.get('active'), entry['active'], now
            )
            # fire_webhook() respects per-event toggles (v1.8.4)
            event = 'service_up' if is_up else 'service_down'
            _fire_service_webhook(event, dev_id, entry['unit'], {
                'active':    entry['active'],
                'sub':       entry['sub'],
                'previous':  prev.get('active'),
            })

    store[dev_id] = {'updated_at': now, 'services': clean}
    save(SERVICES_FILE, store)


def handle_services_get():
    """GET /api/services — all current service states across the fleet."""
    require_auth()
    store = load(SERVICES_FILE)
    devices = load(DEVICES_FILE)
    out = []
    for dev_id, dev in devices.items():
        entry = store.get(dev_id) or {}
        services = entry.get('services') or []
        up = sum(1 for s in services if s.get('active') == 'active')
        down = len(services) - up
        out.append({
            'device_id':  dev_id,
            'name':       dev.get('name', dev_id),
            'group':      dev.get('group', ''),
            'updated_at': entry.get('updated_at', 0),
            'total':      len(services),
            'up':         up,
            'down':       down,
            'services':   services,
        })
    out.sort(key=lambda d: (-d['down'], d['name'].lower()))
    respond(200, {'devices': out})


def handle_services_device(dev_id):
    """GET /api/devices/{id}/services"""
    require_auth()
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})

    store = load(SERVICES_FILE)
    hist  = load(SERVICE_HIST_FILE)
    log_buf = load(LOG_WATCH_FILE).get(dev_id) or {}
    entry = store.get(dev_id) or {}
    services = entry.get('services') or []

    enriched = []
    for s in services:
        key = f'{dev_id}:{s["unit"]}'
        enriched.append({
            **s,
            'history':  (hist.get(key) or [])[-10:],
            'log_tail': (log_buf.get('units') or {}).get(s['unit'], [])[-50:],
        })
    respond(200, {
        'device_id':  dev_id,
        'name':       devices[dev_id].get('name', dev_id),
        'updated_at': entry.get('updated_at', 0),
        'services':   enriched,
    })


def handle_services_config(dev_id):
    """
    GET/POST /api/devices/{id}/services/config
    Manages services_watched list on the device record.
    """
    actor = require_admin_auth() if method() == 'POST' else None
    if not actor:
        require_auth()
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})

    if method() == 'GET':
        respond(200, {
            'services_watched': devices[dev_id].get('services_watched', []),
            'log_watch':        devices[dev_id].get('log_watch', []),
        })

    body = get_json_body()
    raw = body.get('services_watched') or []
    if not isinstance(raw, list):
        respond(400, {'error': 'services_watched must be a list'})
    watched = []
    for name in raw[:MAX_SERVICES_PER_DEVICE]:
        unit = _sanitize_unit_name(name)
        if unit:
            watched.append(unit)

    # Optional: log_watch rules — [{unit, pattern, threshold}]
    log_rules_raw = body.get('log_watch') or []
    log_rules = []
    if isinstance(log_rules_raw, list):
        for r in log_rules_raw[:10]:
            if not isinstance(r, dict):
                continue
            unit = _sanitize_unit_name(r.get('unit', ''))
            pat  = _sanitize_str(r.get('pattern', ''), 128, allow_empty=False)
            try:
                thr = int(r.get('threshold', 1) or 1)
            except (TypeError, ValueError):
                thr = 1
            if unit and pat and 1 <= thr <= 100:
                # Sanity-check the regex compiles
                try:
                    re.compile(pat)
                except re.error:
                    continue
                log_rules.append({'unit': unit, 'pattern': pat, 'threshold': thr})

    devices[dev_id]['services_watched'] = watched
    devices[dev_id]['log_watch']        = log_rules
    save(DEVICES_FILE, devices)
    audit_log(actor, 'services_config_update',
              detail=f'device={dev_id} watched={len(watched)} log_rules={len(log_rules)}')
    respond(200, {'ok': True, 'services_watched': watched, 'log_watch': log_rules})


# ─── v1.8.0: Log tail — called by agent with captured unit logs ───────────────

def handle_log_submit():
    """
    POST /api/logs — agent submits per-unit log lines (device-authenticated).
    Body: {device_id, token, units: {unit_name: [line, line, ...], ...}}

    v1.8.2:
      - Empty lines[] arrays are now preserved so quiet devices still register
        as "reporting" on the Logs page (previously they vanished entirely)
      - Evaluates both device.log_watch (per-device) AND global rules from
        log_rules_global.json (fleet-wide). Wildcard unit='*' matches any unit.
      - Dedupes alerts by (scope, unit, pattern) so a line that matches a
        per-device rule AND a global rule fires only once.
    """
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

    units_in = body.get('units') or {}
    if not isinstance(units_in, dict):
        respond(400, {'error': 'units must be an object'})

    now = int(time.time())
    log_store = load(LOG_WATCH_FILE)
    dev_buf = log_store.get(dev_id) or {'units': {}, 'updated_at': now}
    units_buf = dev_buf.get('units') or {}

    alerts_fired = []
    per_device_rules = dev.get('log_watch') or []
    global_rules = (load(LOG_RULES_GLOBAL_FILE).get('rules') or [])

    # Track which (unit, pattern) pairs have already fired this submission — a
    # line matching both a per-device and a global rule with the same pattern
    # should produce one alert, not two.
    fired_keys = set()

    for unit_raw, lines in units_in.items():
        unit = _sanitize_unit_name(unit_raw)
        if not isinstance(unit, str) or unit is None:
            continue
        if not isinstance(lines, list):
            continue

        clean_lines = []
        for line in lines[:MAX_LOG_LINES_PER_UNIT]:
            s = str(line)[:1024]
            clean_lines.append({'ts': now, 'line': s})

        existing = units_buf.get(unit) or []
        combined = existing + clean_lines
        # Trim by age
        cutoff = now - LOG_BUFFER_TTL
        combined = [e for e in combined if e.get('ts', 0) >= cutoff]
        # Trim by byte-size
        total_bytes = sum(len(e.get('line', '')) for e in combined)
        while total_bytes > MAX_LOG_BUFFER_BYTES and combined:
            removed = combined.pop(0)
            total_bytes -= len(removed.get('line', ''))
        # v1.8.2: always keep the unit key, even if empty — so the device
        # appears on the Logs page as "watched, quiet in this window"
        units_buf[unit] = combined

        # Evaluate per-device rules first, then global
        def _eval_rules(rules, scope):
            for rule in rules:
                rule_unit = rule.get('unit', '')
                # Wildcard '*' matches any unit; otherwise exact match
                if rule_unit != '*' and rule_unit != unit:
                    continue
                pattern = rule.get('pattern', '')
                key = (scope, unit, pattern)
                if key in fired_keys:
                    continue
                try:
                    rx = re.compile(pattern)
                except re.error:
                    continue
                matches = [e['line'] for e in clean_lines if rx.search(e['line'])]
                threshold = rule.get('threshold', 1)
                try:
                    threshold = int(threshold)
                except (TypeError, ValueError):
                    threshold = 1
                if len(matches) >= threshold:
                    fired_keys.add(key)
                    alerts_fired.append({
                        'unit': unit, 'pattern': pattern,
                        'count': len(matches), 'scope': scope,
                    })
                    fire_webhook('log_alert', {
                        'device_id': dev_id,
                        'name':      dev.get('name', dev_id),
                        'unit':      unit,
                        'pattern':   pattern,
                        'count':     len(matches),
                        'sample':    matches[:3],
                        'scope':     scope,  # v1.8.2: 'device' | 'global'
                    })

        _eval_rules(per_device_rules, 'device')
        _eval_rules(global_rules,     'global')

    dev_buf['units'] = units_buf
    dev_buf['updated_at'] = now
    log_store[dev_id] = dev_buf
    save(LOG_WATCH_FILE, log_store)

    respond(200, {'ok': True, 'alerts_fired': len(alerts_fired)})


def handle_log_search():
    """
    GET /api/logs/search?q=<pattern>&device=<id>&limit=<n>
    Searches the rolling buffer across devices. No indexing — just grep.
    """
    require_auth()
    qs = urllib.parse.parse_qs(os.environ.get('QUERY_STRING', ''))
    q       = (qs.get('q', [''])[0])[:128]
    device  = (qs.get('device', [''])[0])[:64]
    limit   = min(int(qs.get('limit', ['200'])[0] or 200), 1000)

    if not q:
        respond(400, {'error': 'q parameter is required'})

    try:
        rx = re.compile(q, re.IGNORECASE)
    except re.error as e:
        respond(400, {'error': f'invalid regex: {e}'})

    log_store = load(LOG_WATCH_FILE)
    devices = load(DEVICES_FILE)
    results = []

    target_devs = [device] if device else list(log_store.keys())
    for dev_id in target_devs:
        if dev_id not in devices:
            continue
        buf = log_store.get(dev_id) or {}
        units = buf.get('units') or {}
        dev_name = devices[dev_id].get('name', dev_id)
        for unit, lines in units.items():
            for entry in lines:
                if rx.search(entry.get('line', '')):
                    results.append({
                        'device_id': dev_id,
                        'name':      dev_name,
                        'unit':      unit,
                        'ts':        entry.get('ts', 0),
                        'line':      entry.get('line', ''),
                    })
                    if len(results) >= limit:
                        break
            if len(results) >= limit:
                break
        if len(results) >= limit:
            break

    results.sort(key=lambda r: -r['ts'])
    respond(200, {'query': q, 'count': len(results), 'results': results})


def handle_log_device(dev_id):
    """GET /api/devices/{id}/logs — full captured buffer for one device."""
    require_auth()
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    log_store = load(LOG_WATCH_FILE)
    buf = log_store.get(dev_id) or {'units': {}, 'updated_at': 0}
    respond(200, {
        'device_id':  dev_id,
        'name':       devices[dev_id].get('name', dev_id),
        'updated_at': buf.get('updated_at', 0),
        'units':      buf.get('units', {}),
    })


# ─── v1.8.1: Log alert rules aggregate + live tail ───────────────────────────

def handle_log_rules():
    """GET /api/logs/rules — cross-fleet view of all per-device log_watch rules."""
    require_auth()
    devices = load(DEVICES_FILE)
    out = []
    for dev_id, dev in devices.items():
        for rule in (dev.get('log_watch') or []):
            out.append({
                'device_id': dev_id,
                'device_name': dev.get('name', dev_id),
                'group':     dev.get('group', ''),
                'unit':      rule.get('unit', ''),
                'pattern':   rule.get('pattern', ''),
                'threshold': rule.get('threshold', 1),
            })
    out.sort(key=lambda r: (r['device_name'].lower(), r['unit']))
    respond(200, {'rules': out})


# ─── v1.8.2: Fleet-wide log alert rules ───────────────────────────────────────

def _validate_global_rule(body):
    """Return (clean_rule, error) — same shape whether valid or not."""
    unit    = _sanitize_str(body.get('unit', ''), 128, allow_empty=False)
    pattern = _sanitize_str(body.get('pattern', ''), 128, allow_empty=False)
    # Don't use `or 1` for threshold — we want to reject 0 explicitly rather
    # than coerce it to 1 silently, so the user gets a clear error.
    raw_threshold = body.get('threshold', 1)
    if raw_threshold is None or raw_threshold == '':
        raw_threshold = 1
    try:
        threshold = int(raw_threshold)
    except (TypeError, ValueError):
        return None, 'threshold must be an integer'

    if not unit:
        return None, 'unit is required (use "*" for any unit)'
    # Allow '*' OR a valid unit name
    if unit != '*' and not _sanitize_unit_name(unit):
        return None, 'invalid unit name'
    if not pattern:
        return None, 'pattern is required'
    if not (1 <= threshold <= 100):
        return None, 'threshold must be 1..100'
    try:
        re.compile(pattern)
    except re.error as e:
        return None, f'invalid regex: {e}'
    return {'unit': unit, 'pattern': pattern, 'threshold': threshold}, None


def handle_log_rules_global_list():
    """GET /api/logs/rules/global — list fleet-wide rules."""
    require_auth()
    rules = (load(LOG_RULES_GLOBAL_FILE).get('rules') or [])
    rules = sorted(rules, key=lambda r: (r.get('unit', ''), r.get('pattern', '')))
    respond(200, {'rules': rules})


def handle_log_rules_global_add():
    """POST /api/logs/rules/global — create a fleet-wide rule."""
    actor = require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})

    body = get_json_body()
    rule, err = _validate_global_rule(body)
    if err:
        respond(400, {'error': err})

    store = load(LOG_RULES_GLOBAL_FILE)
    rules = store.get('rules') or []
    # Dedup by (unit, pattern) — same rule can't exist twice
    for existing in rules:
        if existing.get('unit') == rule['unit'] and existing.get('pattern') == rule['pattern']:
            respond(409, {'error': 'rule with this unit+pattern already exists'})
    if len(rules) >= MAX_GLOBAL_LOG_RULES:
        respond(400, {'error': f'max {MAX_GLOBAL_LOG_RULES} global rules'})

    rule['id']         = secrets.token_hex(8)
    rule['created_by'] = actor
    rule['created_at'] = int(time.time())
    rules.append(rule)
    store['rules'] = rules
    save(LOG_RULES_GLOBAL_FILE, store)
    audit_log(actor, 'log_rule_global_add',
              detail=f'id={rule["id"]} unit={rule["unit"]} pattern={rule["pattern"][:60]}')
    respond(200, {'ok': True, 'rule': rule})


def handle_log_rules_global_delete(rule_id):
    """DELETE /api/logs/rules/global/{id}"""
    actor = require_admin_auth()
    rule_id = _sanitize_str(rule_id, 32, allow_empty=False)
    if not rule_id:
        respond(400, {'error': 'invalid id'})

    store = load(LOG_RULES_GLOBAL_FILE)
    rules = store.get('rules') or []
    remaining = [r for r in rules if r.get('id') != rule_id]
    if len(remaining) == len(rules):
        respond(404, {'error': 'rule not found'})
    store['rules'] = remaining
    save(LOG_RULES_GLOBAL_FILE, store)
    audit_log(actor, 'log_rule_global_delete', detail=f'id={rule_id}')
    respond(200, {'ok': True})


def handle_log_tail():
    """
    GET /api/logs/tail?since=<ts>&device=<id>&unit=<name>&limit=<n>
    Returns the newest lines across the fleet since a given unix ts.
    Use-case: live tail page, polls with monotonically-increasing `since`.
    """
    require_auth()
    qs = urllib.parse.parse_qs(os.environ.get('QUERY_STRING', ''))
    try:
        since = int(qs.get('since', ['0'])[0] or 0)
    except ValueError:
        since = 0
    device = (qs.get('device', [''])[0])[:64]
    unit   = (qs.get('unit',   [''])[0])[:128]
    try:
        limit = min(int(qs.get('limit', ['500'])[0] or 500), 2000)
    except ValueError:
        limit = 500

    log_store = load(LOG_WATCH_FILE)
    devices   = load(DEVICES_FILE)
    out = []
    newest_ts = since
    devices_reporting = 0
    total_lines = 0

    target_devs = [device] if device else list(log_store.keys())
    for dev_id in target_devs:
        if dev_id not in devices:
            continue
        buf = log_store.get(dev_id) or {}
        units = buf.get('units') or {}
        dev_name = devices[dev_id].get('name', dev_id)
        had_lines = False
        for u, lines in units.items():
            if unit and u != unit:
                continue
            for entry in lines:
                ts = entry.get('ts', 0)
                total_lines += 1
                if ts > since:
                    out.append({
                        'device_id': dev_id,
                        'name':      dev_name,
                        'unit':      u,
                        'ts':        ts,
                        'line':      entry.get('line', ''),
                    })
                    if ts > newest_ts:
                        newest_ts = ts
                    had_lines = True
        if had_lines or units:
            devices_reporting += 1

    out.sort(key=lambda r: r['ts'])
    if len(out) > limit:
        out = out[-limit:]  # keep the newest

    # For stats, compute totals across the whole buffer, not just new lines
    respond(200, {
        'lines':             out,
        'newest_ts':         newest_ts,
        'stats': {
            'total_lines':        total_lines,
            'devices_reporting':  devices_reporting,
        },
    })


# ─── v1.8.3: Shared calendar events ──────────────────────────────────────────

# Palette used by the UI — cap allowed colors to prevent CSS injection via
# arbitrary strings. The UI picker should present these same values.
ALLOWED_EVENT_COLORS = (
    'blue', 'green', 'amber', 'red', 'purple', 'teal', 'slate',
)


def _sanitize_event(body):
    """Sanitize a calendar event submission. Returns (clean, error)."""
    title = _sanitize_str(body.get('title', ''), 120, allow_empty=False)
    if not title:
        return None, 'title is required'
    description = _sanitize_str(body.get('description', ''), 2000)
    start = _sanitize_str(body.get('start', ''), 32, allow_empty=False)
    end   = _sanitize_str(body.get('end', ''), 32)
    if not start:
        return None, 'start is required (ISO-8601)'
    try:
        start_ts = _parse_iso(start)
    except ValueError:
        return None, 'invalid start timestamp'
    end_ts = None
    if end:
        try:
            end_ts = _parse_iso(end)
        except ValueError:
            return None, 'invalid end timestamp'
        if end_ts < start_ts:
            return None, 'end must be >= start'
    all_day = bool(body.get('all_day', False))
    color = _sanitize_str(body.get('color', 'blue'), 16)
    if color not in ALLOWED_EVENT_COLORS:
        color = 'blue'
    return {
        'title':       title,
        'description': description,
        'start':       start,
        'end':         end or start,
        'all_day':     all_day,
        'color':       color,
    }, None


def handle_calendar_list():
    """GET /api/calendar — list all events, optionally filtered by date range."""
    require_auth()
    qs = urllib.parse.parse_qs(os.environ.get('QUERY_STRING', ''))
    from_ts = 0
    to_ts   = 10 ** 10  # far future
    try:
        if qs.get('from'):
            from_ts = _parse_iso(qs['from'][0])
        if qs.get('to'):
            to_ts = _parse_iso(qs['to'][0])
    except ValueError:
        respond(400, {'error': 'invalid from/to timestamp'})

    store = load(CALENDAR_FILE)
    events = store.get('events') or []
    out = []
    for ev in events:
        try:
            ev_start = _parse_iso(ev.get('start', ''))
            ev_end   = _parse_iso(ev.get('end', '')) if ev.get('end') else ev_start
        except ValueError:
            continue
        # Overlap check
        if ev_end < from_ts or ev_start > to_ts:
            continue
        out.append(ev)
    out.sort(key=lambda e: e.get('start', ''))
    respond(200, {'events': out})


def handle_calendar_add():
    """POST /api/calendar — create a new event."""
    actor = require_auth()  # any authenticated user can create
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    clean, err = _sanitize_event(body)
    if err:
        respond(400, {'error': err})

    store = load(CALENDAR_FILE)
    events = store.get('events') or []
    if len(events) >= MAX_CALENDAR_EVENTS:
        respond(400, {'error': f'max {MAX_CALENDAR_EVENTS} events'})
    clean['id']         = secrets.token_hex(8)
    clean['created_by'] = actor
    clean['created_at'] = int(time.time())
    events.append(clean)
    store['events'] = events
    save(CALENDAR_FILE, store)
    audit_log(actor, 'calendar_add', detail=f'id={clean["id"]} title={clean["title"][:60]}')
    respond(200, {'ok': True, 'event': clean})


def handle_calendar_update(event_id):
    """PUT /api/calendar/{id} — edit an existing event."""
    actor = require_auth()
    event_id = _sanitize_str(event_id, 32, allow_empty=False)
    if not event_id:
        respond(400, {'error': 'invalid id'})

    store = load(CALENDAR_FILE)
    events = store.get('events') or []
    idx = next((i for i, e in enumerate(events) if e.get('id') == event_id), -1)
    if idx < 0:
        respond(404, {'error': 'event not found'})

    body = get_json_body()
    clean, err = _sanitize_event(body)
    if err:
        respond(400, {'error': err})
    # Preserve id + created_by/at, merge in the new fields
    clean['id']         = event_id
    clean['created_by'] = events[idx].get('created_by', '')
    clean['created_at'] = events[idx].get('created_at', 0)
    clean['updated_by'] = actor
    clean['updated_at'] = int(time.time())
    events[idx] = clean
    store['events'] = events
    save(CALENDAR_FILE, store)
    audit_log(actor, 'calendar_update', detail=f'id={event_id}')
    respond(200, {'ok': True, 'event': clean})


def handle_calendar_delete(event_id):
    """DELETE /api/calendar/{id}"""
    actor = require_auth()
    event_id = _sanitize_str(event_id, 32, allow_empty=False)
    if not event_id:
        respond(400, {'error': 'invalid id'})

    store = load(CALENDAR_FILE)
    events = store.get('events') or []
    remaining = [e for e in events if e.get('id') != event_id]
    if len(remaining) == len(events):
        respond(404, {'error': 'event not found'})
    store['events'] = remaining
    save(CALENDAR_FILE, store)
    audit_log(actor, 'calendar_delete', detail=f'id={event_id}')
    respond(200, {'ok': True})


# ─── v1.8.3: Shared tasks board ───────────────────────────────────────────────

def _sanitize_task(body, require_all=True):
    """Sanitize a task submission. Returns (clean, error).
    If require_all=False, allows partial updates (used by /state endpoint)."""
    title = _sanitize_str(body.get('title', ''), 200, allow_empty=not require_all)
    if require_all and not title:
        return None, 'title is required'
    description = _sanitize_str(body.get('description', ''), 4000)
    state = _sanitize_str(body.get('state', 'upcoming'), 16)
    if state and state not in TASK_STATES:
        return None, f'state must be one of {", ".join(TASK_STATES)}'
    # Device linking is optional. Empty string = no device; otherwise must be valid.
    device_id = _sanitize_str(body.get('device_id', ''), 64)
    if device_id:
        if not _validate_id(device_id):
            return None, 'invalid device_id'
        devices = load(DEVICES_FILE)
        if device_id not in devices:
            return None, 'device_id not found'
    out = {}
    if title:
        out['title'] = title
    if 'description' in body:
        out['description'] = description
    if state:
        out['state'] = state
    if 'device_id' in body:
        out['device_id'] = device_id  # '' means explicit unlink
    return out, None


def handle_tasks_list():
    """GET /api/tasks — all tasks with optional state / device filter."""
    require_auth()
    qs = urllib.parse.parse_qs(os.environ.get('QUERY_STRING', ''))
    state_filter  = (qs.get('state',  [''])[0])[:16]
    device_filter = (qs.get('device', [''])[0])[:64]

    store = load(TASKS_FILE)
    tasks = store.get('tasks') or []

    if state_filter and state_filter in TASK_STATES:
        tasks = [t for t in tasks if t.get('state') == state_filter]
    if device_filter:
        tasks = [t for t in tasks if t.get('device_id') == device_filter]

    # Enrich with device names for display (skip lookup if no tasks have devices)
    if any(t.get('device_id') for t in tasks):
        devices = load(DEVICES_FILE)
        for t in tasks:
            did = t.get('device_id')
            if did and did in devices:
                t['_device_name'] = devices[did].get('name', did)

    # Sort: newest first within each state, so kanban columns are fresh at top
    tasks.sort(key=lambda t: -t.get('updated_at', t.get('created_at', 0)))

    counts = {s: 0 for s in TASK_STATES}
    for t in tasks:
        s = t.get('state', 'upcoming')
        if s in counts:
            counts[s] += 1
    respond(200, {'tasks': tasks, 'counts': counts})


def handle_tasks_add():
    """POST /api/tasks — create."""
    actor = require_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    clean, err = _sanitize_task(body, require_all=True)
    if err:
        respond(400, {'error': err})

    store = load(TASKS_FILE)
    tasks = store.get('tasks') or []
    if len(tasks) >= MAX_TASKS:
        respond(400, {'error': f'max {MAX_TASKS} tasks — close some first'})

    now = int(time.time())
    task = {
        'id':          secrets.token_hex(8),
        'title':       clean['title'],
        'description': clean.get('description', ''),
        'state':       clean.get('state', 'upcoming'),
        'device_id':   clean.get('device_id', ''),
        'created_by':  actor,
        'created_at':  now,
        'updated_at':  now,
    }
    tasks.append(task)
    store['tasks'] = tasks
    save(TASKS_FILE, store)
    audit_log(actor, 'task_add', detail=f'id={task["id"]} title={task["title"][:60]}')
    respond(200, {'ok': True, 'task': task})


def handle_tasks_update(task_id):
    """PUT /api/tasks/{id} — edit title/description/state/device."""
    actor = require_auth()
    task_id = _sanitize_str(task_id, 32, allow_empty=False)
    if not task_id:
        respond(400, {'error': 'invalid id'})

    store = load(TASKS_FILE)
    tasks = store.get('tasks') or []
    idx = next((i for i, t in enumerate(tasks) if t.get('id') == task_id), -1)
    if idx < 0:
        respond(404, {'error': 'task not found'})

    body = get_json_body()
    clean, err = _sanitize_task(body, require_all=False)
    if err:
        respond(400, {'error': err})

    for k in ('title', 'description', 'state', 'device_id'):
        if k in clean:
            tasks[idx][k] = clean[k]
    tasks[idx]['updated_at'] = int(time.time())
    tasks[idx]['updated_by'] = actor
    store['tasks'] = tasks
    save(TASKS_FILE, store)
    audit_log(actor, 'task_update',
              detail=f'id={task_id} fields={",".join(sorted(clean.keys()))}')
    respond(200, {'ok': True, 'task': tasks[idx]})


def handle_tasks_delete(task_id):
    """DELETE /api/tasks/{id}"""
    actor = require_auth()
    task_id = _sanitize_str(task_id, 32, allow_empty=False)
    if not task_id:
        respond(400, {'error': 'invalid id'})

    store = load(TASKS_FILE)
    tasks = store.get('tasks') or []
    remaining = [t for t in tasks if t.get('id') != task_id]
    if len(remaining) == len(tasks):
        respond(404, {'error': 'task not found'})
    store['tasks'] = remaining
    save(TASKS_FILE, store)
    audit_log(actor, 'task_delete', detail=f'id={task_id}')
    respond(200, {'ok': True})


# ─── v1.9.0: CMDB ──────────────────────────────────────────────────────────────
# Asset metadata + encrypted credentials, scoped to enrolled devices only.
# Vault crypto details live in cmdb_vault.py — this section is plumbing.

def _cmdb_load() -> dict:
    """Load the CMDB store from disk.

    Returns:
        Mapping of ``device_id`` to record dict. Returns an empty dict if
        the store file is missing or corrupt — never raises.
    """
    store = load(CMDB_FILE)
    if not isinstance(store, dict):
        return {}
    return store


def _cmdb_record_default() -> dict:
    """Build an empty CMDB record skeleton.

    Every enrolled device implicitly has one of these — the storage layer
    only persists records the user has actually edited, but the API
    presents a uniform shape.

    Returns:
        Dict with all CMDB fields set to their type-appropriate empties
        (empty string, empty list, default port, zero timestamp).
    """
    return {
        'asset_id':        '',
        'server_function': '',
        'hypervisor_url':  '',
        'ssh_port':        CMDB_DEFAULT_SSH_PORT,
        'documentation':   '',
        'credentials':     [],
        'updated_by':      '',
        'updated_at':      0,
    }


def _cmdb_strip_creds(record: dict) -> dict:
    """Redact credential ciphertext from a CMDB record.

    Returns a shallow copy of ``record`` where each credential keeps only
    its plaintext-safe metadata (``id``, ``label``, ``username``, ``note``,
    timestamps). The ``nonce`` and ``ct`` fields — the AES-GCM ciphertext
    — are never returned by list endpoints; only ``/reveal`` decrypts and
    surfaces plaintext.

    Args:
        record: The full CMDB record as stored in ``cmdb.json``.

    Returns:
        A new dict safe to serialise to API clients.
    """
    out = dict(record)
    safe = []
    for c in record.get('credentials') or []:
        safe.append({
            'id':         c.get('id', ''),
            'label':      c.get('label', ''),
            'username':   c.get('username', ''),
            'note':       c.get('note', ''),
            'created_by': c.get('created_by', ''),
            'created_at': c.get('created_at', 0),
            'updated_by': c.get('updated_by', ''),
            'updated_at': c.get('updated_at', 0),
        })
    out['credentials'] = safe
    return out


def _cmdb_validate_url(url) -> 'str | None':
    """Validate a hypervisor URL.

    Empty is acceptable (resets the field). Anything else must be
    ``http://`` or ``https://``, ≤512 characters, and free of whitespace
    or control characters. The latter is a defence against header /
    response splitting if the URL is later interpolated unsafely.

    Args:
        url: Raw value from the request body. Strings, ints, ``None`` —
            anything stringifiable.

    Returns:
        The cleaned URL string on success, an empty string for falsy
        input, or ``None`` to indicate a validation failure (caller
        should respond with 400).
    """
    if not url:
        return ''
    url = str(url).strip()
    if len(url) > MAX_CMDB_URL_LEN:
        return None
    if not (url.startswith('http://') or url.startswith('https://')):
        return None
    # Reject control characters / whitespace inside the URL
    if any(c.isspace() or ord(c) < 0x20 for c in url):
        return None
    return url


def _cmdb_validate_function(fn) -> 'str | None':
    """Validate a ``server_function`` value.

    Free text but charset-restricted to ``[A-Za-z0-9 _\\-/]`` (max 64
    chars) so the value is safe to splice into autocomplete dropdowns
    without HTML escaping every code path.

    Args:
        fn: Raw value from the request body.

    Returns:
        Cleaned string on success, empty string for falsy input,
        ``None`` to signal validation failure.
    """
    if fn is None:
        return ''
    fn = str(fn).strip()
    if not fn:
        return ''
    if not _CMDB_FUNC_RE.match(fn):
        return None
    return fn


def _cmdb_get_vault_meta() -> dict:
    """Load vault metadata (KDF params + canary) from disk."""
    return load(CMDB_VAULT_FILE)


def _cmdb_get_request_key() -> bytes:
    """Extract the derived vault key from the request headers.

    Returns:
        The 32-byte key as raw bytes.

    Raises:
        cmdb_vault.VaultLockedError: Header is missing.
        cmdb_vault.VaultKeyError: Header is malformed (not hex, wrong length).
    """
    raw = os.environ.get('HTTP_X_RP_VAULT_KEY', '')
    return cmdb_vault.parse_key_header(raw)


def _cmdb_require_unlocked() -> 'tuple[bytes, dict]':
    """Common preamble for credential operations.

    Loads the vault metadata, extracts and verifies the request's vault
    key, and returns both for the caller to use. Short-circuits via
    :func:`respond` (which raises :class:`HTTPError`) on any failure.

    Returns:
        A ``(key, vault_meta)`` tuple. ``key`` is 32 bytes; ``vault_meta``
        is the dict from ``cmdb_vault.json``.
    """
    meta = _cmdb_get_vault_meta()
    if not cmdb_vault.is_configured(meta):
        respond(409, {'error': 'vault not configured', 'code': 'vault_not_configured'})
    try:
        key = _cmdb_get_request_key()
    except cmdb_vault.VaultLockedError:
        respond(401, {'error': 'vault locked', 'code': 'vault_locked'})
    except cmdb_vault.VaultKeyError as e:
        respond(400, {'error': str(e)})
    if not cmdb_vault.verify_key(key, meta):
        respond(403, {'error': 'invalid vault key', 'code': 'vault_key_invalid'})
    return key, meta


def handle_cmdb_list() -> None:
    """``GET /api/cmdb`` — list assets joined with their CMDB metadata.

    Returns one entry per enrolled device (devices with no CMDB record
    appear with empty fields). Supports two query-string filters:

    ``?q=<text>``
        Free-text search across name, hostname, OS, IP, MAC, group,
        asset_id, server_function, hypervisor_url, tags, and the
        documentation body. Case-insensitive substring match.

    ``?function=<value>``
        Exact match on ``server_function`` (case-insensitive).

    Results are sorted by ``server_function`` then by ``name``;
    unspecified-function assets sort last.

    Side effects:
        Calls :func:`respond` with status 200 and the asset list.
    """
    require_auth()
    devices = load(DEVICES_FILE)
    cmdb = _cmdb_load()
    qs = urllib.parse.parse_qs(os.environ.get('QUERY_STRING', ''))
    q = (qs.get('q', [''])[0] or '').strip().lower()
    func_filter = (qs.get('function', [''])[0] or '').strip().lower()

    out = []
    for dev_id, dev in devices.items():
        rec = cmdb.get(dev_id) or _cmdb_record_default()
        rec_safe = _cmdb_strip_creds(rec)
        entry = {
            'device_id':       dev_id,
            'name':            dev.get('name', dev_id),
            'hostname':        dev.get('hostname', ''),
            'os':              dev.get('os', ''),
            'ip':              dev.get('ip', ''),
            'mac':             dev.get('mac', ''),
            'group':           dev.get('group', ''),
            'tags':            dev.get('tags', []),
            'asset_id':        rec_safe.get('asset_id', ''),
            'server_function': rec_safe.get('server_function', ''),
            'hypervisor_url':  rec_safe.get('hypervisor_url', ''),
            'ssh_port':        rec_safe.get('ssh_port', CMDB_DEFAULT_SSH_PORT),
            'has_documentation': bool(rec_safe.get('documentation')),
            'credential_count': len(rec_safe.get('credentials') or []),
        }
        if func_filter and entry['server_function'].lower() != func_filter:
            continue
        if q:
            haystack = ' '.join([
                entry['name'], entry['hostname'], entry['os'], entry['ip'],
                entry['mac'], entry['group'], entry['asset_id'],
                entry['server_function'], entry['hypervisor_url'],
                ' '.join(entry['tags'] or []),
                rec_safe.get('documentation', ''),
            ]).lower()
            if q not in haystack:
                continue
        out.append(entry)
    out.sort(key=lambda x: (x.get('server_function') or '~', x['name'].lower()))
    respond(200, out)


def _trim_sysinfo(sysinfo) -> dict:
    """Return only the sysinfo fields the CMDB modal actually displays.

    The full sysinfo dict from a heartbeat can run 50+ KB (kernel,
    services, NICs, mountpoints, etc.). The CMDB asset modal only needs
    CPU/RAM/disk headlines and uptime. Trimming keeps page loads snappy
    when assets have rich sysinfo.

    Args:
        sysinfo: Anything — non-dict input is treated as empty.

    Returns:
        Dict with at most nine whitelisted fields. Missing fields are
        included with ``None`` values for shape stability on the client.
    """
    if not isinstance(sysinfo, dict):
        return {}
    return {
        'kernel':         sysinfo.get('kernel', ''),
        'cpu':            sysinfo.get('cpu', ''),
        'cores':          sysinfo.get('cores'),
        'mem_total_mb':   sysinfo.get('mem_total_mb'),
        'mem_free_mb':    sysinfo.get('mem_free_mb'),
        'disk_total_gb':  sysinfo.get('disk_total_gb'),
        'disk_free_gb':   sysinfo.get('disk_free_gb'),
        'uptime_seconds': sysinfo.get('uptime_seconds'),
        'boot_time':      sysinfo.get('boot_time'),
    }


def handle_cmdb_get(dev_id: str) -> None:
    """``GET /api/cmdb/{device_id}`` — full asset detail with credentials redacted.

    Args:
        dev_id: The enrolled device's ID.

    Side effects:
        Calls :func:`respond` with 200 + asset detail, or 404 if the
        device is unknown.
    """
    require_auth()
    if not _validate_id(dev_id):
        respond(404, {'error': 'device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'device not found'})
    cmdb = _cmdb_load()
    rec = cmdb.get(dev_id) or _cmdb_record_default()
    # Backfill ssh_port for records created before v1.10.0.
    if 'ssh_port' not in rec:
        rec['ssh_port'] = CMDB_DEFAULT_SSH_PORT
    dev = devices[dev_id]
    payload = _cmdb_strip_creds(rec)
    payload['device_id'] = dev_id
    payload['name']      = dev.get('name', dev_id)
    payload['hostname']  = dev.get('hostname', '')
    payload['os']        = dev.get('os', '')
    payload['ip']        = dev.get('ip', '')
    payload['mac']       = dev.get('mac', '')
    payload['version']   = dev.get('version', '')
    payload['group']     = dev.get('group', '')
    payload['tags']      = dev.get('tags', [])
    # v1.10.0: send a trimmed sysinfo subset rather than the full dict.
    # Saves ~50 KB on busy assets, cuts CMDB modal load time noticeably.
    payload['sysinfo']   = _trim_sysinfo(dev.get('sysinfo', {}))
    respond(200, payload)


def handle_cmdb_update(dev_id: str) -> None:
    """``PUT /api/cmdb/{device_id}`` — patch CMDB metadata for an asset.

    Accepts a JSON body with any subset of the writable fields.
    Unrecognised keys are silently ignored; recognised keys that fail
    validation cause a 400. At least one recognised key is required.

    Writable fields:
        ``asset_id``: Free text, ``[A-Za-z0-9_-]{0,64}``.
        ``server_function``: Free text, ``[A-Za-z0-9 _\\-/]{0,64}``.
        ``hypervisor_url``: ``http(s)://…``, max 512 chars.
        ``ssh_port``: 1-65535. Empty/0 resets to default 22.
        ``documentation``: Markdown, max 64 KB.

    Args:
        dev_id: The enrolled device's ID.
    """
    actor = require_auth()
    if method() != 'PUT':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'device not found'})

    body = get_json_body()
    cmdb = _cmdb_load()
    rec = cmdb.get(dev_id) or _cmdb_record_default()

    changed = []

    if 'asset_id' in body:
        asset_id = str(body.get('asset_id') or '').strip()
        if asset_id and not _SAFE_ID_RE.match(asset_id):
            respond(400, {'error': 'asset_id must match [A-Za-z0-9_-]{1,64}'})
        if len(asset_id) > MAX_CMDB_ASSET_ID:
            respond(400, {'error': f'asset_id too long (max {MAX_CMDB_ASSET_ID})'})
        rec['asset_id'] = asset_id
        changed.append('asset_id')

    if 'server_function' in body:
        fn = _cmdb_validate_function(body.get('server_function'))
        if fn is None:
            respond(400, {'error': 'server_function: alphanumerics/spaces/_-/, max 64 chars'})
        rec['server_function'] = fn
        changed.append('server_function')

    if 'hypervisor_url' in body:
        url = _cmdb_validate_url(body.get('hypervisor_url'))
        if url is None:
            respond(400, {'error': 'hypervisor_url must be http(s)://… and ≤512 chars'})
        rec['hypervisor_url'] = url
        changed.append('hypervisor_url')

    if 'ssh_port' in body:
        # Accept int, numeric string, or empty/None → reset to default.
        raw = body.get('ssh_port')
        if raw in (None, '', 0):
            port = CMDB_DEFAULT_SSH_PORT
        else:
            try:
                port = int(raw)
            except (TypeError, ValueError):
                respond(400, {'error': 'ssh_port must be an integer'})
            if port < CMDB_SSH_PORT_MIN or port > CMDB_SSH_PORT_MAX:
                respond(400, {'error': f'ssh_port must be between '
                                       f'{CMDB_SSH_PORT_MIN} and {CMDB_SSH_PORT_MAX}'})
        rec['ssh_port'] = port
        changed.append('ssh_port')

    if 'documentation' in body:
        doc = body.get('documentation') or ''
        if not isinstance(doc, str):
            respond(400, {'error': 'documentation must be a string'})
        if len(doc) > MAX_CMDB_DOC_LEN:
            respond(400, {'error': f'documentation too large (max {MAX_CMDB_DOC_LEN} bytes)'})
        rec['documentation'] = doc
        changed.append('documentation')

    if not changed:
        respond(400, {'error': 'no recognised fields to update'})

    rec['updated_by'] = actor
    rec['updated_at'] = int(time.time())
    cmdb[dev_id] = rec
    save(CMDB_FILE, cmdb)
    audit_log(actor, 'cmdb_update', detail=f'device={dev_id} fields={",".join(changed)}')
    respond(200, {'ok': True, 'record': _cmdb_strip_creds(rec)})


def handle_cmdb_server_functions() -> None:
    """``GET /api/cmdb/server-functions`` — distinct values for autocomplete.

    Returns the set of ``server_function`` values currently in use across
    all assets, sorted case-insensitively. The frontend feeds this into a
    ``<datalist>`` for the asset-edit modal.
    """
    require_auth()
    cmdb = _cmdb_load()
    seen = set()
    for rec in cmdb.values():
        fn = (rec or {}).get('server_function') or ''
        if fn:
            seen.add(fn)
    respond(200, sorted(seen, key=str.lower))


# ── Vault management endpoints ─────────────────────────────────────────────────

def handle_cmdb_vault_status() -> None:
    """``GET /api/cmdb/vault/status`` — has the vault been initialised?

    Returns a ``VaultStatus`` payload (see OpenAPI schema). Safe to call
    pre-login from the frontend bootstrap path — though it currently
    requires auth like every other endpoint.
    """
    require_auth()
    meta = _cmdb_get_vault_meta()
    respond(200, {
        'configured': cmdb_vault.is_configured(meta),
        'kdf':        meta.get('kdf') if meta else None,
        'iterations': meta.get('iterations') if meta else None,
        'created_at': meta.get('created_at') if meta else None,
        'created_by': meta.get('created_by') if meta else None,
    })


def handle_cmdb_vault_setup() -> None:
    """``POST /api/cmdb/vault/setup`` — initialise the credential vault.

    One-shot operation: subsequent calls return 409 even from the same
    admin. Use ``/cmdb/vault/change`` to rotate the passphrase later.

    The derived AES-GCM key is returned in the response so the browser
    doesn't need to re-unlock immediately after setup. The passphrase
    itself is never persisted.

    Audit:
        Logs ``cmdb_vault_setup`` with the chosen KDF.

    Raises:
        HTTPError 400: Passphrase fails strength validation.
        HTTPError 409: Vault already configured.
        HTTPError 500: ``cryptography`` package not installed.
    """
    actor = require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    meta = _cmdb_get_vault_meta()
    if cmdb_vault.is_configured(meta):
        respond(409, {'error': 'vault already configured'})
    body = get_json_body()
    passphrase = body.get('passphrase') or ''
    try:
        new_meta = cmdb_vault.setup_vault(passphrase)
    except cmdb_vault.VaultNotInstalledError as e:
        respond(500, {'error': str(e)})
    except cmdb_vault.VaultKeyError as e:
        respond(400, {'error': str(e)})
    new_meta['created_at'] = int(time.time())
    new_meta['created_by'] = actor
    save(CMDB_VAULT_FILE, new_meta)
    audit_log(actor, 'cmdb_vault_setup', detail=f'kdf={new_meta["kdf"]}')
    # Derive and return the key so the caller doesn't have to re-unlock
    key = cmdb_vault.derive_key_from_meta(passphrase, new_meta)
    respond(200, {'ok': True, 'key': key.hex()})


def handle_cmdb_vault_unlock() -> None:
    """``POST /api/cmdb/vault/unlock`` — derive the vault key from a passphrase.

    Any authenticated user can attempt to unlock; it's only the
    *credential operations* that require admin role. This split lets
    viewers see encrypted credential metadata (label, username) without
    being able to decrypt the password.

    Audit:
        Logs ``cmdb_vault_unlock`` on success, ``cmdb_vault_unlock_failed``
        on bad passphrase. Source IP recorded in both cases.
    """
    actor = require_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    meta = _cmdb_get_vault_meta()
    if not cmdb_vault.is_configured(meta):
        respond(409, {'error': 'vault not configured', 'code': 'vault_not_configured'})
    body = get_json_body()
    passphrase = body.get('passphrase') or ''
    try:
        key = cmdb_vault.derive_key_from_meta(passphrase, meta)
    except cmdb_vault.VaultNotInstalledError as e:
        respond(500, {'error': str(e)})
    except cmdb_vault.VaultKeyError as e:
        respond(400, {'error': str(e)})
    if not cmdb_vault.verify_key(key, meta):
        audit_log(actor, 'cmdb_vault_unlock_failed', detail='bad passphrase',
                  source_ip=_get_client_ip())
        respond(403, {'error': 'invalid passphrase'})
    audit_log(actor, 'cmdb_vault_unlock', source_ip=_get_client_ip())
    respond(200, {'ok': True, 'key': key.hex()})


def handle_cmdb_vault_change() -> None:
    """``POST /api/cmdb/vault/change`` — rotate passphrase, re-encrypt credentials.

    Walks every credential in the CMDB, decrypts under the old key, and
    re-encrypts under the new key. The new vault metadata is written
    first so a crash mid-rotation leaves the vault openable with the
    old passphrase. Credentials that fail to decrypt during rotation
    (corrupt entries) are dropped and logged as
    ``cmdb_vault_change_drop`` for the admin to investigate.

    Returns:
        ``{'ok': True, 'key': <hex>, 'rotated': <int>}`` where ``rotated``
        is the count of credentials successfully re-encrypted.
    """
    actor = require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    meta = _cmdb_get_vault_meta()
    if not cmdb_vault.is_configured(meta):
        respond(409, {'error': 'vault not configured'})
    body = get_json_body()
    old_pw = body.get('old_passphrase') or ''
    new_pw = body.get('new_passphrase') or ''

    try:
        old_key = cmdb_vault.derive_key_from_meta(old_pw, meta)
    except cmdb_vault.VaultNotInstalledError as e:
        respond(500, {'error': str(e)})
    except cmdb_vault.VaultKeyError as e:
        respond(400, {'error': str(e)})
    if not cmdb_vault.verify_key(old_key, meta):
        audit_log(actor, 'cmdb_vault_change_failed', detail='bad old passphrase',
                  source_ip=_get_client_ip())
        respond(403, {'error': 'invalid old passphrase'})

    try:
        new_meta = cmdb_vault.setup_vault(new_pw)
    except cmdb_vault.VaultKeyError as e:
        respond(400, {'error': str(e)})
    new_key = cmdb_vault.derive_key_from_meta(new_pw, new_meta)

    # Re-encrypt every credential in cmdb.json. We build the new file fully
    # before persisting it so a crash mid-rotation can't corrupt the vault.
    cmdb = _cmdb_load()
    rotated = 0
    for dev_id, rec in cmdb.items():
        new_creds = []
        for c in (rec.get('credentials') or []):
            try:
                pw_pt = cmdb_vault.decrypt(old_key,
                                           {'nonce': c.get('nonce', ''), 'ct': c.get('ct', '')})
            except cmdb_vault.VaultError:
                # Corrupt entry — drop it but log so the admin notices
                audit_log(actor, 'cmdb_vault_change_drop',
                          detail=f'device={dev_id} cred={c.get("id","?")} reason=decrypt_failed')
                continue
            blob = cmdb_vault.encrypt(new_key, pw_pt)
            new_c = dict(c)
            new_c['nonce'] = blob['nonce']
            new_c['ct']    = blob['ct']
            new_creds.append(new_c)
            rotated += 1
        rec['credentials'] = new_creds

    new_meta['created_at']   = meta.get('created_at') or int(time.time())
    new_meta['created_by']   = meta.get('created_by') or actor
    new_meta['rotated_at']   = int(time.time())
    new_meta['rotated_by']   = actor

    save(CMDB_VAULT_FILE, new_meta)
    save(CMDB_FILE, cmdb)
    audit_log(actor, 'cmdb_vault_change', detail=f'rotated_credentials={rotated}')
    respond(200, {'ok': True, 'key': new_key.hex(), 'rotated': rotated})


# ── Credentials CRUD (require admin + unlocked vault) ──────────────────────────

def handle_cmdb_credentials_list(dev_id: str) -> None:
    """``GET /api/cmdb/{device_id}/credentials`` — list credentials, metadata only.

    Returns each credential with ``id``, ``label``, ``username``, ``note``,
    and timestamps. The encrypted ciphertext is never included; callers
    that need plaintext use the dedicated ``/reveal`` endpoint.

    Args:
        dev_id: The enrolled device's ID.
    """
    require_auth()
    if not _validate_id(dev_id):
        respond(404, {'error': 'device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'device not found'})
    cmdb = _cmdb_load()
    rec = cmdb.get(dev_id) or _cmdb_record_default()
    safe = _cmdb_strip_creds(rec)
    respond(200, {'credentials': safe.get('credentials') or []})


def handle_cmdb_credentials_add(dev_id: str) -> None:
    """``POST /api/cmdb/{device_id}/credentials`` — encrypt and store a credential.

    Requires admin role and an unlocked vault (via the
    ``X-RP-Vault-Key`` request header). The plaintext password is
    AES-GCM-encrypted with a fresh nonce and stored alongside the
    plaintext metadata.

    Args:
        dev_id: The enrolled device's ID.

    Audit:
        Logs ``cmdb_credential_add`` with the credential ID + label.

    Raises:
        HTTPError 400: Missing/empty label or password, or password too long.
        HTTPError 401: Vault not unlocked (``code=vault_locked``).
        HTTPError 403: Bad vault key.
    """
    actor = require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'device not found'})

    key, _meta = _cmdb_require_unlocked()
    body = get_json_body()
    label    = _sanitize_str(body.get('label', ''),    MAX_CMDB_LABEL,    allow_empty=False)
    username = _sanitize_str(body.get('username', ''), MAX_CMDB_USERNAME, allow_empty=True) or ''
    password = body.get('password', '')
    note     = _sanitize_str(body.get('note', ''),     MAX_CMDB_CRED_NOTE, allow_empty=True) or ''

    if not label:
        respond(400, {'error': 'label required'})
    if not isinstance(password, str):
        respond(400, {'error': 'password must be a string'})
    if len(password) > MAX_CMDB_PASSWORD:
        respond(400, {'error': f'password too long (max {MAX_CMDB_PASSWORD})'})
    if not password:
        respond(400, {'error': 'password required'})

    cmdb = _cmdb_load()
    rec = cmdb.get(dev_id) or _cmdb_record_default()
    creds = rec.get('credentials') or []
    if len(creds) >= MAX_CMDB_CREDS:
        respond(400, {'error': f'max {MAX_CMDB_CREDS} credentials per asset'})

    try:
        blob = cmdb_vault.encrypt(key, password)
    except cmdb_vault.VaultError as e:
        respond(500, {'error': f'encrypt failed: {e}'})

    now = int(time.time())
    new_id = 'cred_' + secrets.token_hex(8)
    creds.append({
        'id':         new_id,
        'label':      label,
        'username':   username,
        'note':       note,
        'nonce':      blob['nonce'],
        'ct':         blob['ct'],
        'created_by': actor,
        'created_at': now,
        'updated_by': actor,
        'updated_at': now,
    })
    rec['credentials'] = creds
    rec['updated_by']  = actor
    rec['updated_at']  = now
    cmdb[dev_id] = rec
    save(CMDB_FILE, cmdb)
    audit_log(actor, 'cmdb_credential_add',
              detail=f'device={dev_id} cred={new_id} label={label[:40]}')
    respond(200, {'ok': True, 'id': new_id})


def handle_cmdb_credentials_update(dev_id: str, cred_id: str) -> None:
    """``PUT /api/cmdb/{device_id}/credentials/{cred_id}`` — update a credential.

    Sends only the fields you want to change. The vault key is required
    only if the password is being changed; metadata-only edits skip
    the unlock check. This lets viewers (in some configurations) update
    their own labels without touching ciphertext.

    Args:
        dev_id: The enrolled device's ID.
        cred_id: The credential's ``cred_<hex>`` identifier.
    """
    actor = require_admin_auth()
    if method() != 'PUT':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'device not found'})
    if not cred_id.startswith('cred_') or not _validate_id(cred_id[len('cred_'):]):
        respond(404, {'error': 'credential not found'})

    cmdb = _cmdb_load()
    rec = cmdb.get(dev_id)
    if not rec:
        respond(404, {'error': 'credential not found'})
    creds = rec.get('credentials') or []
    idx = next((i for i, c in enumerate(creds) if c.get('id') == cred_id), -1)
    if idx < 0:
        respond(404, {'error': 'credential not found'})

    body = get_json_body()
    cred = dict(creds[idx])
    changed = []

    if 'label' in body:
        label = _sanitize_str(body.get('label', ''), MAX_CMDB_LABEL, allow_empty=False)
        if not label:
            respond(400, {'error': 'label cannot be empty'})
        cred['label'] = label
        changed.append('label')
    if 'username' in body:
        cred['username'] = _sanitize_str(body.get('username', ''),
                                         MAX_CMDB_USERNAME, allow_empty=True) or ''
        changed.append('username')
    if 'note' in body:
        cred['note'] = _sanitize_str(body.get('note', ''),
                                     MAX_CMDB_CRED_NOTE, allow_empty=True) or ''
        changed.append('note')
    if 'password' in body:
        password = body.get('password', '')
        if not isinstance(password, str):
            respond(400, {'error': 'password must be a string'})
        if len(password) > MAX_CMDB_PASSWORD:
            respond(400, {'error': f'password too long (max {MAX_CMDB_PASSWORD})'})
        if not password:
            respond(400, {'error': 'password cannot be empty'})
        key, _meta = _cmdb_require_unlocked()
        try:
            blob = cmdb_vault.encrypt(key, password)
        except cmdb_vault.VaultError as e:
            respond(500, {'error': f'encrypt failed: {e}'})
        cred['nonce'] = blob['nonce']
        cred['ct']    = blob['ct']
        changed.append('password')

    if not changed:
        respond(400, {'error': 'no recognised fields to update'})

    cred['updated_by'] = actor
    cred['updated_at'] = int(time.time())
    creds[idx] = cred
    rec['credentials'] = creds
    rec['updated_by']  = actor
    rec['updated_at']  = int(time.time())
    cmdb[dev_id] = rec
    save(CMDB_FILE, cmdb)
    audit_log(actor, 'cmdb_credential_update',
              detail=f'device={dev_id} cred={cred_id} fields={",".join(changed)}')
    respond(200, {'ok': True})


def handle_cmdb_credentials_delete(dev_id: str, cred_id: str) -> None:
    """``DELETE /api/cmdb/{device_id}/credentials/{cred_id}`` — hard-delete.

    The encrypted blob is removed from ``cmdb.json`` on save. The audit
    log keeps the ``cmdb_credential_delete`` entry but the ciphertext
    itself is gone — there's no trash can.

    Args:
        dev_id: The enrolled device's ID.
        cred_id: The credential's ``cred_<hex>`` identifier.
    """
    actor = require_admin_auth()
    if method() != 'DELETE':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'device not found'})
    if not cred_id.startswith('cred_') or not _validate_id(cred_id[len('cred_'):]):
        respond(404, {'error': 'credential not found'})

    cmdb = _cmdb_load()
    rec = cmdb.get(dev_id)
    if not rec:
        respond(404, {'error': 'credential not found'})
    creds = rec.get('credentials') or []
    remaining = [c for c in creds if c.get('id') != cred_id]
    if len(remaining) == len(creds):
        respond(404, {'error': 'credential not found'})
    rec['credentials'] = remaining
    rec['updated_by']  = actor
    rec['updated_at']  = int(time.time())
    cmdb[dev_id] = rec
    save(CMDB_FILE, cmdb)
    audit_log(actor, 'cmdb_credential_delete',
              detail=f'device={dev_id} cred={cred_id}')
    respond(200, {'ok': True})


def handle_cmdb_credentials_reveal(dev_id: str, cred_id: str) -> None:
    """``POST /api/cmdb/{device_id}/credentials/{cred_id}/reveal`` — return plaintext.

    The audit-logged moment of truth. Decrypts the credential's
    ciphertext using the vault key from the request header and returns
    the plaintext. Every reveal is recorded with actor, source IP,
    asset, and credential label so post-incident review can answer
    "who looked at the IPMI password last Thursday".

    Args:
        dev_id: The enrolled device's ID.
        cred_id: The credential's ``cred_<hex>`` identifier.

    Audit:
        ``cmdb_credential_reveal`` on success,
        ``cmdb_credential_reveal_failed`` on decrypt failure.
    """
    actor = require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'device not found'})
    if not cred_id.startswith('cred_') or not _validate_id(cred_id[len('cred_'):]):
        respond(404, {'error': 'credential not found'})

    key, _meta = _cmdb_require_unlocked()

    cmdb = _cmdb_load()
    rec = cmdb.get(dev_id)
    if not rec:
        respond(404, {'error': 'credential not found'})
    cred = next((c for c in (rec.get('credentials') or []) if c.get('id') == cred_id), None)
    if not cred:
        respond(404, {'error': 'credential not found'})

    try:
        plaintext = cmdb_vault.decrypt(key,
                                       {'nonce': cred.get('nonce', ''), 'ct': cred.get('ct', '')})
    except cmdb_vault.VaultKeyError:
        audit_log(actor, 'cmdb_credential_reveal_failed',
                  detail=f'device={dev_id} cred={cred_id} reason=decrypt',
                  source_ip=_get_client_ip())
        respond(403, {'error': 'decryption failed — vault key may be stale'})
    except cmdb_vault.VaultError as e:
        respond(500, {'error': f'decrypt failed: {e}'})

    audit_log(actor, 'cmdb_credential_reveal',
              detail=f'device={dev_id} cred={cred_id} label={cred.get("label","")[:40]}',
              source_ip=_get_client_ip())
    respond(200, {
        'ok':       True,
        'id':       cred_id,
        'label':    cred.get('label', ''),
        'username': cred.get('username', ''),
        'password': plaintext,
        'note':     cred.get('note', ''),
    })


# ─── Router ────────────────────────────────────────────────────────────────────
def main():
    try: check_offline_webhooks()
    except Exception: pass
    try: process_schedule()
    except Exception: pass

    pi = path_info(); m = method()

    if pi == '/api/login': handle_login()
    elif pi == '/api/public-info' and m == 'GET': handle_public_info()
    elif pi == '/api/openapi.json' and m == 'GET': handle_openapi_spec()
    elif pi == '/api/devices' and m == 'GET': handle_devices_list()
    elif pi.startswith('/api/devices/') and m == 'DELETE' and not any(
            pi.endswith(s) for s in ('/tags','/notes','/group','/sysinfo','/uptime',
                                     '/output','/metrics','/allowlist','/poll_interval',
                                     '/icon','/monitored','/cve','/services',
                                     '/services/config','/logs','/update-logs')):
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
    elif pi.startswith('/api/devices/') and pi.endswith('/update-logs') and m == 'GET':
        handle_device_update_logs(pi[len('/api/devices/'):-len('/update-logs')])
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
    # ── v1.8.6: SMTP + LDAP test endpoints ─────────────────────────────────────
    elif pi == '/api/smtp/test' and m == 'POST': handle_smtp_test()
    elif pi == '/api/ldap/test' and m == 'POST': handle_ldap_test()
    elif pi == '/api/ldap/test-user' and m == 'POST': handle_ldap_test_user()
    elif pi == '/api/monitor/alerts/clear' and m == 'DELETE': handle_monitor_alerts_clear()
    elif pi == '/api/sessions/revoke' and m == 'POST': handle_revoke_sessions()

    # ── v1.7.0: Package inventory + CVE scanner ────────────────────────────────
    elif pi == '/api/packages' and m == 'POST': handle_packages_submit()
    elif pi == '/api/cve/scan' and m == 'POST': handle_cve_scan()
    elif pi == '/api/cve/findings' and m == 'GET': handle_cve_findings()
    elif pi == '/api/cve/ignore' and m == 'GET': handle_cve_ignore_list()
    elif pi == '/api/cve/ignore' and m == 'POST': handle_cve_ignore_add()
    elif pi.startswith('/api/cve/ignore/') and m == 'DELETE':
        handle_cve_ignore_delete(pi[len('/api/cve/ignore/'):])
    elif pi.startswith('/api/devices/') and pi.endswith('/cve') and m == 'GET':
        handle_cve_device(pi[len('/api/devices/'):-len('/cve')])

    # ── v1.7.0: Prometheus metrics endpoint ────────────────────────────────────
    elif pi == '/api/metrics' and m == 'GET': handle_prometheus_metrics()

    # ── v1.8.0: Service monitoring ─────────────────────────────────────────────
    elif pi == '/api/services' and m == 'GET': handle_services_get()
    elif pi.startswith('/api/devices/') and pi.endswith('/services') and m == 'GET':
        handle_services_device(pi[len('/api/devices/'):-len('/services')])
    elif pi.startswith('/api/devices/') and pi.endswith('/services/config'):
        handle_services_config(pi[len('/api/devices/'):-len('/services/config')])

    # ── v1.8.0: Log tail + pattern alerts ──────────────────────────────────────
    elif pi == '/api/logs' and m == 'POST': handle_log_submit()
    elif pi == '/api/logs/search' and m == 'GET': handle_log_search()
    # ── v1.8.1: live tail + rules aggregate ────────────────────────────────────
    elif pi == '/api/logs/tail' and m == 'GET': handle_log_tail()
    elif pi == '/api/logs/rules' and m == 'GET': handle_log_rules()
    # ── v1.8.2: fleet-wide log alert rules ─────────────────────────────────────
    elif pi == '/api/logs/rules/global' and m == 'GET': handle_log_rules_global_list()
    elif pi == '/api/logs/rules/global' and m == 'POST': handle_log_rules_global_add()
    elif pi.startswith('/api/logs/rules/global/') and m == 'DELETE':
        handle_log_rules_global_delete(pi[len('/api/logs/rules/global/'):])
    elif pi.startswith('/api/devices/') and pi.endswith('/logs') and m == 'GET':
        handle_log_device(pi[len('/api/devices/'):-len('/logs')])

    # ── v1.8.0: Maintenance windows ────────────────────────────────────────────
    elif pi == '/api/maintenance' and m == 'GET': handle_maintenance_list()
    elif pi == '/api/maintenance' and m == 'POST': handle_maintenance_add()
    elif pi == '/api/maintenance/suppressions' and m == 'GET':
        handle_maintenance_suppressions()
    elif pi.startswith('/api/maintenance/') and m == 'DELETE':
        handle_maintenance_delete(pi[len('/api/maintenance/'):])

    # ── v1.8.3: Shared calendar events ─────────────────────────────────────────
    elif pi == '/api/calendar' and m == 'GET':  handle_calendar_list()
    elif pi == '/api/calendar' and m == 'POST': handle_calendar_add()
    elif pi.startswith('/api/calendar/') and m == 'PUT':
        handle_calendar_update(pi[len('/api/calendar/'):])
    elif pi.startswith('/api/calendar/') and m == 'DELETE':
        handle_calendar_delete(pi[len('/api/calendar/'):])

    # ── v1.8.3: Shared tasks board ─────────────────────────────────────────────
    elif pi == '/api/tasks' and m == 'GET':  handle_tasks_list()
    elif pi == '/api/tasks' and m == 'POST': handle_tasks_add()
    elif pi.startswith('/api/tasks/') and m == 'PUT':
        handle_tasks_update(pi[len('/api/tasks/'):])
    elif pi.startswith('/api/tasks/') and m == 'DELETE':
        handle_tasks_delete(pi[len('/api/tasks/'):])

    # ── v1.9.0: CMDB ───────────────────────────────────────────────────────────
    # Vault management — order matters, more specific paths first
    elif pi == '/api/cmdb/vault/status'  and m == 'GET':  handle_cmdb_vault_status()
    elif pi == '/api/cmdb/vault/setup'   and m == 'POST': handle_cmdb_vault_setup()
    elif pi == '/api/cmdb/vault/unlock'  and m == 'POST': handle_cmdb_vault_unlock()
    elif pi == '/api/cmdb/vault/change'  and m == 'POST': handle_cmdb_vault_change()
    # Server-function autocomplete list
    elif pi == '/api/cmdb/server-functions' and m == 'GET': handle_cmdb_server_functions()
    # Per-device credential CRUD — match before the generic /api/cmdb/{id} route
    elif pi.startswith('/api/cmdb/') and pi.endswith('/credentials') and m == 'GET':
        handle_cmdb_credentials_list(pi[len('/api/cmdb/'):-len('/credentials')])
    elif pi.startswith('/api/cmdb/') and pi.endswith('/credentials') and m == 'POST':
        handle_cmdb_credentials_add(pi[len('/api/cmdb/'):-len('/credentials')])
    elif pi.startswith('/api/cmdb/') and '/credentials/' in pi and pi.endswith('/reveal') and m == 'POST':
        # /api/cmdb/{dev}/credentials/{cred}/reveal
        rest = pi[len('/api/cmdb/'):-len('/reveal')]
        dev_id, _, cred_id = rest.partition('/credentials/')
        handle_cmdb_credentials_reveal(dev_id, cred_id)
    elif pi.startswith('/api/cmdb/') and '/credentials/' in pi and m == 'PUT':
        rest = pi[len('/api/cmdb/'):]
        dev_id, _, cred_id = rest.partition('/credentials/')
        handle_cmdb_credentials_update(dev_id, cred_id)
    elif pi.startswith('/api/cmdb/') and '/credentials/' in pi and m == 'DELETE':
        rest = pi[len('/api/cmdb/'):]
        dev_id, _, cred_id = rest.partition('/credentials/')
        handle_cmdb_credentials_delete(dev_id, cred_id)
    # Asset list + per-asset metadata
    elif pi == '/api/cmdb' and m == 'GET':  handle_cmdb_list()
    elif pi.startswith('/api/cmdb/') and m == 'GET':
        handle_cmdb_get(pi[len('/api/cmdb/'):])
    elif pi.startswith('/api/cmdb/') and m == 'PUT':
        handle_cmdb_update(pi[len('/api/cmdb/'):])

    else: respond(404, {'error': 'Not found'})


if __name__ == '__main__':
    try:
        main()
    except HTTPError as e:
        # Normal short-circuit from a handler — render the planned response.
        _render_response(e.status, e.body)
    except SystemExit:
        # Some legacy code paths still use sys.exit() during initialisation.
        # Honour them rather than swallowing.
        raise
    except Exception:
        # Anything else is unexpected. Render a generic 500 — never leak
        # exception details to the client. Stack traces, if needed, are
        # available via fcgiwrap's stderr capture.
        _render_response(500, {'error': 'Internal server error'})

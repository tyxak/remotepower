"""Input sanitisation leaf helpers, extracted from api.py.

These are pure (stdlib only — no api globals, no I/O), so api.py imports them
back without an import cycle. Kept together with the small length limits and
regexes they need. Behaviour is byte-for-byte what lived inline in api.py;
`_sanitize_monitor_target` deliberately stays in api.py because it reads config
(load(CONFIG_FILE)) and so isn't a pure leaf.
"""
import re

# Input size limits used by the sanitisers below.
MAX_HOSTNAME_LEN = 253
MAX_VERSION_LEN  = 32
MAX_IP_LEN       = 45      # IPv6 max
MAX_MAC_LEN      = 17

_IP_RE  = re.compile(
    r'^(?:'
    r'(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'   # IPv4
    r'|(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}'                                # IPv6 simplified
    r')$'
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

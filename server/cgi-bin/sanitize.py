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


# v6.4.1: canary/honeytoken decoy paths. The agent creates a file at this path
# as root/SYSTEM, so the path is operator input that reaches a privileged
# filesystem write — it must be absolute (no cwd-relative surprise) and free of
# traversal. Cross-platform because the Windows and macOS agents plant canaries
# too; the previous POSIX-only check silently dropped every Windows entry at
# save time, which was backwards given ransomware is mostly a Windows problem.
_WIN_DRIVE_ABS_RE = re.compile(r'^[A-Za-z]:[\\/]')


def _canary_path_ok(p):
    """True if `p` is an absolute POSIX, drive-letter or UNC path with no
    traversal component. Rejects NUL and, on the Windows forms, the reserved
    characters that make a path ambiguous."""
    if not p or len(p) > 512 or '\x00' in p:
        return False
    posix = p.startswith('/')
    unc = p.startswith('\\\\')
    drive = bool(_WIN_DRIVE_ABS_RE.match(p))
    if not (posix or unc or drive):
        return False
    # Split on BOTH separators: 'C:\a\..\b' and 'C:/a/../b' are both traversal,
    # and a POSIX path containing a backslash is a literal filename, not a
    # separator — checking both ways is strictly safer than picking one.
    parts = re.split(r'[\\/]+', p)
    if any(seg == '..' for seg in parts):
        return False
    if (unc or drive) and any(ch in p[2:] for ch in '<>"|?*'):
        return False
    return True

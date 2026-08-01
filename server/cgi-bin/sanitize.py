"""Input sanitisation leaf helpers, extracted from api.py.

These are pure (stdlib only — no api globals, no I/O), so api.py imports them
back without an import cycle. Kept together with the small length limits and
regexes they need. Behaviour is byte-for-byte what lived inline in api.py;
`_sanitize_monitor_target` deliberately stays in api.py because it reads config
(load(CONFIG_FILE)) and so isn't a pure leaf.
"""
import ipaddress
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
    """A hostname safe to store and render. Max 253 chars.

    v6.4.2: UNDERSCORES ARE KEPT. RFC-1123 forbids them, but Windows/AD boxes,
    docker-compose service names and homelab hosts use them constantly, and this
    function does not reject what it dislikes — it silently REWRITES it. A host
    calling itself `db_primary` was enrolled as `dbprimary`, and every later join
    on the hostname then failed against the machine's real name. The one that
    matters is the EDR coverage cross-reference (`_edr_covered_map`), which
    compares our stored hostname against the name the EDR itself reports: the
    host came back `covered: false` while it was in fact protected. A false
    "unprotected" is what trains an operator to stop reading that list.

    The strip stays for genuinely unsafe characters — whitespace, quotes, path
    separators, control characters — because this value is stored, logged and
    rendered. Non-ASCII is still dropped: an IDN hostname belongs on the wire as
    punycode, and accepting raw UTF-8 here would make two spellings of the same
    host look like two hosts."""
    h = _sanitize_str(h, MAX_HOSTNAME_LEN)
    h = re.sub(r'[^a-zA-Z0-9._\-]', '', h)
    return h[:MAX_HOSTNAME_LEN] or 'unknown'


def _sanitize_ip(ip):
    """A validated IP address, or '' — never a partially-trusted string.

    v6.4.2: validated with `ipaddress` FIRST, falling back to the old regex.
    That regex's IPv6 branch matched only the fully-expanded eight-group form,
    so every address anyone actually writes — `2001:db8::1`, `::1`, an
    IPv4-mapped `::ffff:192.0.2.1` — was silently blanked. Nothing logged it;
    the address simply vanished. It reached the audit log's `source_ip`, device
    create/update, the interface and gateway inventory, and the WordPress login
    list, so on an IPv6 network those fields were quietly empty.

    The regex is kept as a FALLBACK rather than replaced, deliberately: it
    accepts a few things `ipaddress` rejects (leading-zero octets like
    `192.168.001.1`, which Python treats as ambiguous), and blanking a device
    IP that has worked for years would be a worse bug than the one being fixed.
    So this only ever accepts MORE than before.

    The value is returned as written, not normalised — callers store and
    compare it, and rewriting `2001:0db8::1` under them is not this function's
    decision to make."""
    if not ip:
        return ''
    s = str(ip).strip()[:MAX_IP_LEN]
    # A zone/scope id ("fe80::1%eth0") is interface-local metadata rather than
    # part of the address — drop the suffix, keep the address.
    addr = s.split('%', 1)[0]
    try:
        ipaddress.ip_address(addr)
        return addr
    except ValueError:
        pass
    return s if _IP_RE.match(s) else ''


# An IPv6 literal cannot be pattern-matched with the obvious regex. Both
# ai_provider.redact() and logsig.normalize() carried a copy of
# `(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}`, which can only ever match the
# fully-EXPANDED eight-group form: a `::` run cannot satisfy `[0-9a-fA-F]{1,4}:`,
# so `2001:db8::1`, `fe80::1`, `::1` and `::ffff:192.0.2.1` — i.e. every address
# anyone actually writes or logs — slipped straight through. In ai_provider that
# meant the "Send IP addresses = off" privacy toggle shipped every IPv6 address
# verbatim to the cloud provider while reading as ON; worse, a long address was
# matched in two halves ('<IPv6>::<IPv6>'), which looks redacted in a spot-check
# while both halves are still there. This is the same defect `_sanitize_ip`
# carried above, so it gets the same cure: match a permissive CANDIDATE run and
# let `ipaddress` decide what is an address.
#
# The lookarounds stop a run starting or ending mid-word, which is what keeps
# `std::vector` and `Foo::bar` from validating as the addresses `d::` and
# `::ba` and mangling readable text — they work because `std`/`Foo` contain
# non-hex letters. An identifier whose parts are ALL hex (`a::b`, `dead::beef`)
# is character-for-character a legal IPv6 address, so nothing can tell the two
# apart and it is redacted. That is the right way to be wrong for a privacy
# control: over-redacting costs a little readability, under-redacting ships the
# operator's addresses to a third party.
_IPV6_CANDIDATE_RE = re.compile(
    r'(?<![0-9A-Za-z_.:])[0-9A-Fa-f.:]*:[0-9A-Fa-f.:]*(?![0-9A-Za-z_])')


def _is_ipv6(value):
    """True if `value` is a literal IPv6 address in any legal form."""
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv6Address)
    except ValueError:
        return False


def _fold_ipv6(text, repl):
    """Replace every IPv6 literal in free text with `repl`.

    Characters that trail the address without being part of it — the full stop
    in "reached 2001:db8::1." or a ':443' port suffix — are preserved: the
    candidate run is shrunk from the right until `ipaddress` accepts a prefix.
    A run with fewer than two colons is skipped outright ('::', the shortest
    legal address, has two), which keeps a bare clock time out of the loop.
    """
    def _one(m):
        tok = m.group(0)
        if tok.count(':') < 2:
            return tok
        for end in range(min(len(tok), MAX_IP_LEN), 1, -1):
            if _is_ipv6(tok[:end]):
                return repl + tok[end:]
        return tok
    return _IPV6_CANDIDATE_RE.sub(_one, text)


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

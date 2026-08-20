"""Input sanitisation leaf helpers, extracted from api.py.

These are pure (stdlib only — no api globals, no I/O), so api.py imports them
back without an import cycle. Kept together with the small length limits and
regexes they need. Behaviour is byte-for-byte what lived inline in api.py;
`_sanitize_monitor_target` stays in api.py because it reads config
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

    The strip stays for unsafe characters — whitespace, quotes, path
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

    The regex is kept as a FALLBACK rather than replaced, : it
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
# unchanged to the cloud provider while reading as ON; worse, a long address was
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


# Places where a file IS code the system runs, or is configuration naming code
# to run. A decoy never needs to live in one.
#
# The canary channel writes a root-owned file with operator-supplied content to
# an operator-supplied path. Audit mode and require-signed-commands both exist
# to stop the server changing a host, and this channel honoured neither — so on
# a fleet where a stolen admin token cannot sign a command, it could still drop
# a file in /etc/cron.d. Both halves are fixed: the agents skip planting in
# audit mode, and these paths are refused at both ends.
#
# Kept in one tuple per rule so the three agents can mirror it exactly;
# tests/test_v702_canary_paths.py fails if any copy drifts.
CANARY_DENY_DIRS = (
    '/bin/', '/boot/', '/etc/apt/', '/etc/bash_completion.d/',
    '/etc/cron.d/', '/etc/cron.daily/', '/etc/cron.hourly/',
    '/etc/cron.monthly/', '/etc/cron.weekly/', '/etc/init.d/',
    '/etc/ld.so.conf.d/', '/etc/network/if-up.d/',
    '/etc/networkmanager/dispatcher.d/', '/etc/pam.d/', '/etc/polkit-1/',
    '/etc/profile.d/', '/etc/rc.d/', '/etc/sudoers.d/', '/etc/systemd/',
    '/etc/update-motd.d/', '/etc/yum.repos.d/', '/etc/zypp/repos.d/',
    '/lib/systemd/', '/sbin/', '/usr/bin/', '/usr/lib/systemd/',
    '/usr/local/bin/', '/usr/local/sbin/', '/usr/sbin/',
    '/usr/share/polkit-1/', '/var/spool/cron/',
    # Windows, matched after separators are normalised to '/'
    '/appdata/roaming/microsoft/windows/start menu/programs/startup/',
    '/start menu/programs/startup/', '/startup/',
    '/windows/system32/', '/windows/syswow64/', '/windows/tasks/',
)

# Whole files that name code to run, wherever they sit. `.ssh/id_rsa` stays a
# legal decoy — a fake private key is one of the better honeytokens — but
# `.ssh/authorized_keys` on a host that has none yet is a login.
CANARY_DENY_ENDINGS = (
    '/.ssh/authorized_keys', '/.ssh/authorized_keys2', '/.ssh/config',
    '/.ssh/rc', '/.bashrc', '/.bash_profile', '/.bash_login', '/.profile',
    '/.zshrc', '/.zshenv', '/.kshrc', '/.cshrc', '/.tcshrc',
    '/etc/rc.local', '/etc/crontab', '/etc/sudoers', '/etc/environment',
    '/etc/ld.so.preload', '/etc/hosts.allow', '/etc/hosts.deny',
)

CANARY_DENY_SUFFIXES = (
    '.bash', '.bat', '.cmd', '.com', '.cpl', '.desktop', '.dll', '.exe',
    '.hta', '.jar', '.js', '.jse', '.ksh', '.lnk', '.msi', '.mount', '.path',
    '.php', '.pl', '.ps1', '.psm1', '.py', '.pyw', '.rb', '.reg', '.rules',
    '.scr', '.service', '.sh', '.socket', '.timer', '.vbe', '.vbs', '.wsf',
    '.zsh',
)


def canary_path_safe(p):
    """(ok, reason) for a canary path that has already passed _canary_path_ok.

    Says what was refused rather than dropping it, so an operator is not told
    three files are armed when one was thrown away.
    """
    q = str(p).replace('\\', '/').lower()
    while '//' in q:
        q = q.replace('//', '/')
    for d in CANARY_DENY_DIRS:
        if d in q:
            return False, f'a decoy cannot live in {d.strip("/")}'
    for e in CANARY_DENY_ENDINGS:
        if q.endswith(e):
            return False, f'{e.rsplit("/", 1)[-1]} names code to run'
    for suf in CANARY_DENY_SUFFIXES:
        if q.endswith(suf):
            return False, f'{suf} is an executable file type'
    return True, ''


def as_list(v, limit=None):
    """A field that should be a list, as a list — capped if `limit` is given.

    `(body.get('x') or [])[:50]` is the idiom everywhere, and it raises
    KeyError when the value is a dict: slicing a dict looks a slice object up
    as a key. A JSON body can hold any type, so on a request field the idiom
    turns a malformed body into a 500 instead of a 400. Strings slice happily
    and would come through as a list of characters, which is its own quiet
    wrong answer, so anything that is not a list becomes empty.
    """
    if not isinstance(v, list):
        return []
    return v[:limit] if limit is not None else v


def gunzip_bounded(data, limit):
    """Decompress gzip bytes, refusing a stream that expands past `limit`.

    `gzip.decompress` has no output bound, so a few megabytes of repetitive
    bytes expand a thousandfold and take the process out of memory. Every place
    this product decompresses something it did not create — an agent's SCAP
    report, a DMARC aggregate that arrived by mail, a downloaded feed — is
    reading a size it does not control, and the SCAP one needs only a device
    token, the lowest-privilege credential in the product.

    Raises ValueError on a bomb or a corrupt stream, so a caller that already
    wraps its decompress in try/except keeps behaving the same way.
    """
    import zlib
    if limit <= 0:
        raise ValueError('limit must be positive')
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)   # 16 → gzip wrapper
    out = bytearray()
    src = bytes(data)
    while True:
        # max_length must never be 0 — zlib reads that as "no limit", which is
        # the bug this function exists to avoid.
        room = limit + 1 - len(out)
        if room <= 0:
            raise ValueError(f'gzip stream expands past {limit} bytes')
        try:
            chunk = d.decompress(src, room)
        except zlib.error as exc:
            raise ValueError(f'corrupt gzip stream: {exc}') from exc
        out += chunk
        if len(out) > limit:
            raise ValueError(f'gzip stream expands past {limit} bytes')
        src = d.unconsumed_tail
        if not src:
            break
    if not d.eof:
        # zlib returns b'' without complaining while it waits for more input, so
        # a stream that ENDS early — one to three bytes, a cut-off upload —
        # decompressed to nothing and looked like a valid empty document. The
        # SCAP path would have stored it and later served a blank report rather
        # than refusing it. Found by a property test, not by example.
        raise ValueError('truncated gzip stream')
    return bytes(out)


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

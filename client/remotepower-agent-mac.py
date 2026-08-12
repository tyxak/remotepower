#!/usr/bin/env python3
"""
RemotePower minimal macOS agent (v3.14.0, #50).

Speaks the same enroll / heartbeat / command-queue contract as the Linux and
Windows agents, so a Mac shows up in the fleet with metrics, runs queued
commands, and participates in the opt-in secrets scan — without a separate
server-side code path. Stdlib only; `psutil` is used when present for richer
metrics and gracefully skipped otherwise.

Still Linux-only, and honestly so (v6.4.1 audit — the heartbeat-response keys
this agent deliberately does NOT read): OpenSCAP (`force_scap_scan` /
`scap_profile`);
`host_scan` (lynis); `image_scan_*` (trivy); `mailbox_paths` (mail spools);
`host_config_desired` (users/sudoers/motd apply); `push_enabled` (push relay);
`mdns_enabled`; `force_iac_collect`; `guard_actions` (Integrity Guard check
types are Linux-only); `harvest_dns_creds` / `force_acme_rescan` (acme.sh).
Everything else the server sends is honoured here — when closing one of these,
also update this list and the Windows agent's.

Usage:
    remotepower-agent-mac --enroll --server https://rp.example --pin 123456
    remotepower-agent-mac --run        # heartbeat loop (run under launchd)
    remotepower-agent-mac --once       # one heartbeat, print the response
"""
import argparse
import hashlib
import json
import logging
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error

VERSION = '6.4.3'

# v6.4.3: the docstring's "deliberately does NOT read" list, machine-readable.
# See the Windows agent's copy for why it lives here rather than in the test.
# macOS DOES honour du_scan (since v6.4.1), which is exactly the kind of
# divergence this list has to record rather than leave to prose.
HEARTBEAT_KEYS_NOT_HONOURED = (
    'force_scap_scan', 'scap_profile',   # oscap
    'host_scan',                          # lynis
    'image_scan_enabled', 'force_image_scan',   # trivy
    'mailbox_paths',                      # Unix mail spools, not macOS layout
    'host_config_desired',                # users/sudoers/motd apply
    'push_enabled',
    'mdns_enabled',
    'force_iac_collect',
    'guard_actions',                      # Integrity Guard types are Linux-only
    'harvest_dns_creds', 'force_acme_rescan',   # acme.sh
)
DEFAULT_POLL = 60
HTTP_TIMEOUT = 20
EXEC_TIMEOUT = 300

# ── v6.4.1: bounded logging (this agent had NONE) ─────────────────────────────
#
# The macOS agent wrote to stderr and install-macos.sh pointed launchd's
# StandardOutPath/StandardErrorPath straight at /var/log/remotepower-agent.log.
# launchd does not rotate, and unlike the Linux and Windows agents this one had
# no RotatingFileHandler — so that file grew without limit, forever, on every
# Mac in the fleet. macOS ships `newsyslog` rather than logrotate, but relying on
# it is fragile here: newsyslog renames the file while launchd still holds an fd
# to the old inode, so output would silently keep going to the rotated-away
# file. Self-rotating in-process is what the other two agents do and what works.
#
# 5 MB x 5 backups (~25 MB), matching the Linux agent exactly.
# RP_AGENT_LOG redirects both files — for a container with a read-only /var/log,
# and so importing this module (tests do) can never create a real system log.
LOG_FILE = os.environ.get('RP_AGENT_LOG') or '/var/log/remotepower-agent.log'
LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_BACKUPS = 5
# launchd's own redirect goes to a SEPARATE file so it cannot fight the rotating
# handler for the same inode. It only ever receives output that escapes Python
# logging — an interpreter-level traceback at startup — so it is normally empty;
# `_trim_boot_log()` keeps it bounded anyway, because "normally empty" is how
# unbounded logs happen.
BOOT_LOG_FILE = (LOG_FILE[:-4] if LOG_FILE.endswith('.log') else LOG_FILE) + '-boot.log'
BOOT_LOG_MAX_BYTES = 1024 * 1024


from logging.handlers import RotatingFileHandler as _RFH


class _OwnerReadableRotatingHandler(_RFH):
    """RotatingFileHandler that keeps the log 0640 across rollovers.

    The stdlib handler creates every new file at the process umask — 0644 here —
    so a one-off chmod after construction is silently undone by the first
    rotation, and the log drifts back to world-readable without anyone noticing.
    Setting the mode in _open() covers the initial file AND each rollover.
    Worth doing because the log carries device ids, the server URL, and the
    output of commands the operator ran on the host.
    """

    def _open(self):
        stream = super()._open()
        try:
            os.chmod(self.baseFilename, 0o640)
        except OSError:
            pass
        return stream


def _make_logger():
    """Rotating file log when we can write /var/log (launchd runs us as root),
    plus stderr. Never fatal: a log handler must not stop the agent running."""
    lg = logging.getLogger('remotepower')
    if lg.handlers:
        return lg
    lg.setLevel(logging.INFO)
    fmt = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
    try:
        fh = _OwnerReadableRotatingHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES,
                                           backupCount=LOG_BACKUPS)
        fh.setFormatter(fmt)
        lg.addHandler(fh)
    except Exception:
        pass                      # not root, read-only /var/log, etc.
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(fmt)
    lg.addHandler(sh)
    return lg


def _trim_boot_log():
    """Truncate launchd's crash-output file if it has grown past the cap.

    TRUNCATE rather than rename: launchd holds an open O_APPEND fd to this file
    for the life of the process, so a rename would leave it writing to an inode
    nothing can see. ftruncate keeps that fd valid and writes resume at the new
    end. Best-effort — never fatal."""
    try:
        if os.path.getsize(BOOT_LOG_FILE) <= BOOT_LOG_MAX_BYTES:
            return False
        with open(BOOT_LOG_FILE, 'r+') as f:
            f.truncate(0)
        return True
    except OSError:
        return False


log = _make_logger()

# Prime the non-blocking CPU sampler once at import so the first heartbeat's
# cpu_percent(interval=None) measures against a real baseline instead of
# returning 0.0 — and we never pay a blocking 0.3s sample on the heartbeat hot
# path (parity with the Linux agent).
try:
    import psutil as _psutil_prime
    _psutil_prime.cpu_percent(interval=None)
except Exception:
    pass


def _make_ssl_context():
    """Strict TLS context: cert verification on, TLS 1.2 floor — parity with the
    Linux agent (v4.4.0). RP_CA_BUNDLE trusts an internal CA without weakening
    verification."""
    ctx = ssl.create_default_context()
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    _ca = os.environ.get('RP_CA_BUNDLE', '').strip()
    if not _ca and os.path.exists('/etc/remotepower/ca.crt'):
        _ca = '/etc/remotepower/ca.crt'   # v4.5.0: conventional self-signed CA path
    if _ca and os.path.exists(_ca):
        try:
            ctx.load_verify_locations(cafile=_ca)
        except Exception:
            pass
    return ctx


_SSL_CTX = _make_ssl_context()
MAX_OUTPUT = 32 * 1024

# v6.3.1: signed COMMAND channel — parity with the Linux agent. Pin the server
# signing key at /etc/remotepower/release.pub and touch
# /etc/remotepower/require-signed-commands: every dispatched command must then
# carry a valid detached signature binding it to THIS device + a fresh
# timestamp. Fail-closed (needs gpg — `brew install gnupg`).
_RELEASE_PUB_MAC = '/etc/remotepower/release.pub'
_REQUIRE_SIGNED_CMDS_MAC = '/etc/remotepower/require-signed-commands'
_CMD_SIG_MAX_AGE_S = 900


def _release_pubkey_mac():
    try:
        if os.path.exists(_RELEASE_PUB_MAC):
            with open(_RELEASE_PUB_MAC, 'r', encoding='utf-8') as f:
                return f.read().strip() or None
    except Exception:
        pass
    return None


def _require_signed_commands_mac():
    try:
        return os.path.exists(_REQUIRE_SIGNED_CMDS_MAC)
    except Exception:
        return False


def _verify_detached_sig_mac(data_bytes, sig_text, pubkey_armored):
    """Detached-signature verify via an ephemeral gpg keyring seeded only with
    the pinned key — the same shape as the Linux/Windows agents. (ok, detail);
    fails closed when gpg is unavailable."""
    gpg = shutil.which('gpg')
    if not gpg:
        return False, 'gpg not available'
    home = tempfile.mkdtemp(prefix='rp-cmdverify-')
    try:
        os.chmod(home, 0o700)
        env = dict(os.environ, GNUPGHOME=home)
        imp = subprocess.run([gpg, '--batch', '--import'],
                             input=(pubkey_armored or '').encode(),
                             env=env, capture_output=True, timeout=20)
        if imp.returncode != 0:
            return False, 'public key import failed'
        art = os.path.join(home, 'art')
        sig = os.path.join(home, 'art.asc')
        with open(art, 'wb') as f:
            f.write(data_bytes)
        with open(sig, 'w') as f:
            f.write(sig_text or '')
        r = subprocess.run([gpg, '--batch', '--status-fd', '1', '--verify', sig, art],
                           env=env, capture_output=True, timeout=20)
        out = r.stdout.decode('utf-8', 'replace')
        if not any(ln.startswith('[GNUPG:] VALIDSIG') for ln in out.splitlines()):
            return False, 'signature not valid'
        return True, 'valid'
    except Exception as e:
        return False, f'verify error: {e}'
    finally:
        shutil.rmtree(home, ignore_errors=True)


def _command_sig_ok_mac(cmd, sig_text, sig_ts, device_id, now=None):
    """(ok, detail). Canonical payload must byte-match the server's
    _sign_command_for_agent: 'rp-cmd\\nv1\\n{device_id}\\n{ts}\\n{cmd}'."""
    pubkey = _release_pubkey_mac()
    if not pubkey:
        return False, 'no release.pub pinned'
    if not sig_text:
        return False, 'command is unsigned'
    try:
        ts = int(sig_ts)
    except (TypeError, ValueError):
        return False, 'missing/invalid signature timestamp'
    now = int(now if now is not None else time.time())
    if abs(now - ts) > _CMD_SIG_MAX_AGE_S:
        return False, 'signature timestamp outside the freshness window'
    payload = f'rp-cmd\nv1\n{device_id}\n{ts}\n{cmd}'.encode()
    return _verify_detached_sig_mac(payload, str(sig_text), pubkey)

# No-redirect opener (parity with the Linux agent): a 3xx must never replay the
# token-bearing POST body to a redirect host or downgrade https→http in cleartext.
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None

_OPENER = urllib.request.build_opener(_NoRedirect,
                                      urllib.request.HTTPSHandler(context=_SSL_CTX))

# v6.4.3: bound every response the agent reads off the wire. A read with no
# size argument lets a compromised or impersonated server hand this
# root-privileged process an unbounded body and exhaust the host's memory. The
# caps had drifted three ways across the three agents, and the macOS agent had
# none at all. One pair of names, identical values, in all three.
MAX_JSON_RESP = 4 * 1024 * 1024      # any JSON reply (heartbeat, enroll, config)
MAX_DOWNLOAD  = 64 * 1024 * 1024     # a self-update binary


def _data_dir():
    # launchd daemons run as root; fall back to the user dir for a manual run.
    for d in ('/Library/Application Support/RemotePower',
              os.path.expanduser('~/Library/Application Support/RemotePower')):
        try:
            os.makedirs(d, exist_ok=True)
            # v5.0.0: tighten to owner-only — the dir holds credentials.json
            # (the enrolment bearer token). The file itself is 0600, but a 0700
            # dir keeps siblings from even enumerating it. Best-effort.
            try:
                os.chmod(d, 0o700)
            except OSError:
                pass
            return d
        except Exception:
            continue
    return os.path.expanduser('~')


def _creds_path():
    return os.path.join(_data_dir(), 'credentials.json')


def load_creds():
    try:
        with open(_creds_path()) as f:
            return json.load(f)
    except Exception:
        return {}


def save_creds(creds):
    p = _creds_path()
    try:
        # v4.6.0 (SECURITY): create a 0600 temp file, then atomically replace —
        # the old open+write+chmod left a brief window where the bearer token
        # was world-readable at the process umask before the chmod landed.
        d = os.path.dirname(p) or '.'
        os.makedirs(d, exist_ok=True)
        tmp = p + '.tmp'
        # O_NOFOLLOW | O_EXCL: never follow a planted symlink and never reuse a
        # pre-existing temp file — matches the Linux agent's symlink guard.
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_EXCL, 0o600)
        try:
            os.write(fd, json.dumps(creds).encode())
        finally:
            os.close(fd)
        os.replace(tmp, p)
    except Exception as e:
        log.warning('could not save credentials: %s', e)


def get_os_info():
    """e.g. 'macOS 14.5 (23F79)'. Falls back to platform.mac_ver()."""
    try:
        def _sw(k):
            return subprocess.run(['sw_vers', '-' + k], capture_output=True,
                                  text=True, timeout=5).stdout.strip()
        name = _sw('productName') or 'macOS'
        ver = _sw('productVersion')
        build = _sw('buildVersion')
        return f'{name} {ver}{f" ({build})" if build else ""}'.strip()
    except Exception:
        v = platform.mac_ver()[0]
        return f'macOS {v}'.strip()


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return ''


def get_mac():
    try:
        out = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            m = re.search(r'ether ([0-9a-f:]{17})', line)
            if m and m.group(1) != '00:00:00:00:00:00':
                return m.group(1)
    except Exception:
        pass
    return ''


def self_sha256():
    try:
        with open(os.path.abspath(__file__), 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return ''


def _sysctl(key):
    try:
        return subprocess.run(['sysctl', '-n', key], capture_output=True,
                              text=True, timeout=5).stdout.strip()
    except Exception:
        return ''


def _fmt_uptime(secs):
    secs = max(0, int(secs))
    d, secs = divmod(secs, 86400)
    h, secs = divmod(secs, 3600)
    m = secs // 60
    if d:
        return f'{d}d {h}h {m}m'
    if h:
        return f'{h}h {m}m'
    return f'{m}m'


def _port_scope(ip):
    """Classify a bind address into world / lan / local — matches the server's
    exposure buckets so listeners render like Linux/Windows ones. Pure.

    v6.4.2: was a string-prefix copy whose loopback test was the exact tuple
    ('127.0.0.1', '::1', 'localhost') with a `return 'world'` catch-all, so it
    reported as WORLD-EXPOSED:
      * 127.0.0.2, 127.0.1.1 and every other 127.0.0.0/8 alias;
      * `::ffff:127.0.0.1` and `::ffff:<RFC1918>` — the exact form a dual-stack
        AF_INET6 socket bound to an IPv4 address reports through psutil, which
        is what this agent uses to enumerate listeners;
      * `0:0:0:0:0:0:0:1`, the uncompressed IPv6 loopback.
    The server does not recompute the scope, so each of those raised a HIGH
    `port_exposed_world` alert for a service bound to localhost. Now the same
    `ipaddress` logic the Linux agent has always used, with the old prefix walk
    kept only as the ImportError fallback. 'world' stays the default for an
    address we cannot parse — an exposure we cannot classify is the riskier
    case and should fail loud."""
    a = (ip or '').strip().strip('[]')
    if not a or a in ('0.0.0.0', '::', '*'):
        return 'world'
    if a == 'localhost':
        return 'local'
    try:
        import ipaddress
        addr = ipaddress.ip_address(a)
        # A dual-stack socket reports an IPv4 bind as ::ffff:a.b.c.d; classify
        # the address it actually represents, not the mapping.
        mapped = getattr(addr, 'ipv4_mapped', None)
        if mapped is not None:
            addr = mapped
        # A wildcard bind is WORLD, however it is spelled. `0.0.0.0` and `::`
        # are caught above as literals, but a dual-stack socket reports the
        # wildcard as `::ffff:0.0.0.0` / `::ffff:0:0` — and 0.0.0.0/8 is
        # `is_private`, so those fell through to 'lan' and silenced the
        # world-exposed-port check for a service listening on every interface.
        # (Pre-existing on Linux since v3.11.0; fixed on all three agents.)
        if addr.is_unspecified:
            return 'world'
        if addr.is_loopback:
            return 'local'
        if addr.is_private or addr.is_link_local:
            return 'lan'
        return 'world'
    except (ValueError, ImportError):
        if a.startswith('127.') or a == '::1':
            return 'local'
        if a.startswith(('10.', '192.168.', '169.254.', 'fe80:', 'fc', 'fd')):
            return 'lan'
        if a.startswith('172.'):
            try:
                if 16 <= int(a.split('.')[1]) <= 31:
                    return 'lan'
            except (ValueError, IndexError):
                pass
        return 'world'

def collect_listening_ports():
    """LISTEN sockets via psutil. Returns the same shape the Linux/Windows agents
    send — [{proto, port, process, addr, scope}] — so the Exposure page and port
    audit work unchanged for macOS hosts. [] without psutil."""
    try:
        import psutil
    except ImportError:
        return []
    try:
        conns = psutil.net_connections(kind='inet')
    except Exception:
        return []
    ports, seen = [], set()
    for c in conns:
        laddr = getattr(c, 'laddr', None)
        if not laddr:
            continue
        is_tcp = (c.type == socket.SOCK_STREAM)
        # TCP listeners report LISTEN; UDP sockets have no state but no peer.
        if is_tcp and c.status != getattr(psutil, 'CONN_LISTEN', 'LISTEN'):
            continue
        if not is_tcp and getattr(c, 'raddr', None):
            continue
        proto = 'tcp' if is_tcp else 'udp'
        port = getattr(laddr, 'port', 0)
        key = (proto, port)
        if not port or key in seen:
            continue
        seen.add(key)
        proc = ''
        if c.pid:
            try:
                proc = psutil.Process(c.pid).name()
            except Exception:
                pass
        ip = getattr(laddr, 'ip', '') or ''
        ports.append({'proto': proto, 'port': port, 'process': proc,
                      'addr': ip, 'scope': _port_scope(ip)})
    ports.sort(key=lambda p: p['port'])
    return ports[:80]


def _audit_mode():
    """v4.10.0: observe-only (read-only) flag — an operator-owned file the server
    can't clear. When set, the agent refuses every command (parity with the Linux
    agent's /etc/remotepower/audit-mode)."""
    try:
        return (os.path.exists(os.path.join(_data_dir(), 'audit-mode'))
                or os.path.exists('/etc/remotepower/audit-mode'))
    except Exception:
        return False


def _posture_cmd(argv, timeout=5):
    """Run a short posture probe → combined stdout+stderr, or '' on any failure.
    (Several macOS security tools print their status to stderr.)"""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or '') + (r.stderr or '')
    except Exception:
        return ''


def _parse_mac_posture(fv, fw, gk, sip, au):
    """The five raw command outputs → a compact posture sub-dict. Pure/testable
    (no darwin needed), mirroring the Windows agent's _parse_win_posture shape."""
    out = {}
    low = (fv or '').lower()
    if 'filevault is on' in low:
        out['filevault'] = True
    elif 'filevault is off' in low:
        out['filevault'] = False
    low = (fw or '').lower()
    m = re.search(r'state\s*=\s*(\d)', low)
    if m:                                   # "(State = 1)" — 1/2 = on, 0 = off
        out['firewall'] = m.group(1) in ('1', '2')
    elif 'disabled' in low:
        out['firewall'] = False
    elif 'enabled' in low:
        out['firewall'] = True
    low = (gk or '').lower()
    if 'assessments enabled' in low:
        out['gatekeeper'] = True
    elif 'assessments disabled' in low:
        out['gatekeeper'] = False
    low = (sip or '').lower()               # "System Integrity Protection status: enabled."
    if 'status: enabled' in low or low.strip().endswith('enabled.'):
        out['sip'] = True
    elif 'status: disabled' in low or 'disabled' in low:
        out['sip'] = False
    au = (au or '').strip()
    if au in ('0', '1'):
        out['auto_security_update'] = au == '1'
    return out


def get_mac_posture():
    """macOS security-posture signals (FileVault / Application Firewall / Gatekeeper
    / SIP / automatic security updates) for the Checks catalog, or {}. Mirrors
    get_win_posture's contract: the server renders posture check rows ONLY when this
    sub-dict is present, so a Linux/Windows host never shows an empty FileVault row.
    Runs on the sysinfo cadence (not every heartbeat); each probe is bounded."""
    if sys.platform != 'darwin':
        return {}
    fv = _posture_cmd(['fdesetup', 'status'])
    fw = _posture_cmd(['/usr/libexec/ApplicationFirewall/socketfilterfw', '--getglobalstate'])
    gk = _posture_cmd(['spctl', '--status'])
    sip = _posture_cmd(['csrutil', 'status'])
    au = _posture_cmd(['defaults', 'read', '/Library/Preferences/com.apple.SoftwareUpdate',
                       'CriticalUpdateInstall'])
    try:
        return _parse_mac_posture(fv, fw, gk, sip, au)
    except Exception:
        return {}


def get_top_processes(limit=15):
    """Top processes by memory (RSS %). Returns (top_list, name_set) — the SAME
    {pid, name, cpu, mem} shape the Linux/Windows agents send (the server
    sanitizer keeps `cpu`/`mem`, and the server-side `process` custom-check reads
    sysinfo.proc_names). Needs psutil; ([], []) without it. cpu_percent(None) is
    non-blocking (primed at import)."""
    try:
        import psutil
    except Exception:
        return [], []
    procs = []
    names = set()
    for p in psutil.process_iter(['pid', 'name', 'memory_percent', 'cpu_percent']):
        try:
            pinfo = p.info
            nm = pinfo.get('name') or ''
            if nm:
                names.add(nm)
            procs.append({'pid': pinfo.get('pid'), 'name': nm,
                          'cpu': round(pinfo.get('cpu_percent') or 0, 1),
                          'mem': round(pinfo.get('memory_percent') or 0, 2)})
        except Exception:
            continue
    procs.sort(key=lambda x: x.get('mem') or 0, reverse=True)
    return procs[:limit], sorted(names)[:400]


def collect_sysinfo():
    """Core metrics. Uses psutil when available, else a best-effort subset so a
    host without psutil still reports OS / cpu model / hostname."""
    info = {
        'platform': get_os_info(),
        'kernel':   platform.release(),       # Darwin kernel version
        'hostname': socket.gethostname(),
        'audit_mode': _audit_mode(),          # v4.10.0: read-only agent flag
    }
    cpu = _sysctl('machdep.cpu.brand_string') or platform.processor()
    if cpu:
        info['cpu'] = cpu
    # v4.8.0: saturation-metric parity with the Linux agent (same field names so
    # the server checks/UI light up unchanged). macOS has both portable signals;
    # netfilter conntrack is Linux-only and has no macOS equivalent, so it's
    # intentionally omitted. Both are os-level — collected outside the psutil
    # block so they report even on a host without psutil.
    try:
        info['loadavg_1m'] = round(os.getloadavg()[0], 2)
    except (AttributeError, OSError):
        pass
    try:
        # open files vs system max — exhaustion → "too many open files" outages.
        _nf, _mf = _sysctl('kern.num_files'), _sysctl('kern.maxfiles')
        if _nf and _mf and int(_mf) > 0:
            info['fd_percent'] = round(int(_nf) / int(_mf) * 100, 1)
    except (ValueError, TypeError):
        pass
    try:
        import psutil
        info['cpu_percent'] = round(psutil.cpu_percent(interval=None), 1)  # non-blocking; primed at import
        info['cpu_count'] = psutil.cpu_count() or 0
        vm = psutil.virtual_memory()
        info['mem_percent'] = round(vm.percent, 1)
        info['mem_total_mb'] = int(vm.total / (1024 * 1024))
        sw = psutil.swap_memory()
        info['swap_percent'] = round(sw.percent, 1)
        boot = int(psutil.boot_time())
        info['last_boot'] = boot
        info['uptime'] = _fmt_uptime(int(time.time()) - boot)
        mounts, worst, total_gb = [], 0.0, 0.0
        for part in psutil.disk_partitions(all=False):
            try:
                u = psutil.disk_usage(part.mountpoint)
            except Exception:
                continue
            pct = round(u.percent, 1)
            worst = max(worst, pct)
            total_gb += u.total / (1024 ** 3)
            mounts.append({'path': part.mountpoint, 'fstype': part.fstype,
                           'used_gb': round(u.used / (1024 ** 3), 1),
                           'total_gb': round(u.total / (1024 ** 3), 1),
                           'percent': pct})
        if mounts:
            info['mounts'] = mounts[:50]
            info['disk_percent'] = worst
            info['disk_total_gb'] = round(total_gb, 1)
        nets = []
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                ipv4 = next((a.address for a in addrs if a.family == socket.AF_INET), '')
                mac = next((a.address for a in addrs
                            if getattr(a, 'family', None) == psutil.AF_LINK), '')
                if ipv4 and iface != 'lo0':
                    nets.append({'iface': iface, 'ip': ipv4, 'mac': mac})
        except Exception:
            pass
        if nets:
            info['network'] = nets[:20]
        try:
            nio = _collect_net_io(psutil)
            if nio:
                info['network_io'] = nio
        except Exception:
            pass
        try:
            lp = collect_listening_ports()
            if lp:
                info['listening_ports'] = lp
        except Exception:
            pass
        # v6.4.2: top processes + the process-name set. macOS was the only agent
        # not sending these (Linux/Windows both do), so every Mac's `process`
        # custom-check returned 'unknown' and the Top-Processes drawer/fleet view
        # rendered empty. psutil is already imported here, so it is fully
        # portable. Inside the psutil block AND after `info` is built (never a
        # collector before the dict is assigned — that UnboundLocalErrors under
        # the try and ships the field dead).
        try:
            _top, _names = get_top_processes()
            if _top:
                info['top_processes'] = _top
            if _names:
                info['proc_names'] = _names
        except Exception:
            pass
    except ImportError:
        info['psutil'] = False
        try:
            info['uptime'] = _mac_uptime()
        except Exception:
            pass
    except Exception:
        pass
    # W6-32: Homebrew outdated formulae → the Patches page (None-safe; skipped
    # without brew). Runs on the sysinfo cadence; brew outdated is cheap.
    try:
        _brew = brew_outdated()
        if _brew is not None:
            info['packages'] = _brew
    except Exception:
        pass
    # v6.3.0: macOS security posture (FileVault / firewall / Gatekeeper / SIP /
    # auto-update) → the Checks catalog, parity with the Windows agent's win_posture.
    try:
        _mp = get_mac_posture()
        if _mp:
            info['mac_posture'] = _mp
    except Exception:
        pass
    # v6.4.1 (parity): the last three Linux-only sysinfo fields. Each is
    # consumed by a feature that was therefore dead on Macs — the uptime
    # leaderboard (uptime_seconds), laptop offline-grace (chassis) and
    # battery-health alerting + hardware RAG (battery). Same field names and
    # record shapes as the Linux agent, so safe_si and every consumer light up
    # with no server change.
    try:
        info['uptime_seconds'] = get_uptime_seconds()
    except Exception:
        pass
    try:
        _ch = get_chassis()
        if _ch:
            info['chassis'] = _ch
    except Exception:
        pass
    try:
        _bat = get_battery()
        if _bat:
            info['battery'] = _bat
    except Exception:
        pass
    return info


def _mac_uptime():
    bt = _sysctl('kern.boottime')          # '{ sec = 1700000000, usec = 0 } ...'
    m = re.search(r'sec = (\d+)', bt)
    if m:
        return _fmt_uptime(int(time.time()) - int(m.group(1)))
    return ''


def _mac_boot_epoch():
    """Boot time as a unix epoch, or 0. Shared by uptime_seconds and last_boot."""
    m = re.search(r'sec = (\d+)', _sysctl('kern.boottime'))
    return int(m.group(1)) if m else 0


def get_uptime_seconds():
    """v6.4.1 (parity): sortable uptime in seconds — the field the fleet's
    uptime leaderboard filters on (`typeof d.sysinfo.uptime_seconds ===
    'number'`). The mac agent only ever sent the *formatted* `uptime` string,
    so every Mac was silently missing from that view."""
    boot = _mac_boot_epoch()
    return max(0, int(time.time()) - boot) if boot else 0


def get_chassis():
    """v6.4.1 (parity): chassis class, same vocabulary as the Linux agent's DMI
    read ('laptop'/'desktop'/'server'/…). The server's offline sweep gives
    laptop-class hosts a longer leash (`laptop_offline_grace_hours`) so a
    closed lid doesn't page like a dead server — which never applied to Macs,
    the most laptop-shaped hosts in most fleets, because this was Linux-only.

    `hw.model` is the identifier ('MacBookPro18,3', 'Macmini9,1', 'MacPro7,1'),
    so the class comes from the model family. A battery is the tiebreaker for
    anything unrecognised: no Apple desktop has one."""
    model = (_sysctl('hw.model') or '').strip()
    low = model.lower()
    if low.startswith('macbook'):
        return 'laptop'
    if low.startswith(('macmini', 'imac', 'macstudio', 'macpro')):
        return 'desktop' if low.startswith(('macmini', 'imac')) else 'server'
    # Unknown/virtual model: infer from the presence of a battery.
    return 'laptop' if get_battery() else ''


def get_battery():
    """v6.4.1 (parity): battery health, same record shape the Linux agent emits
    from /sys/class/power_supply so `safe_si`, the `battery_health_low` edge
    alert, the drawer card and the hardware RAG source all light up unchanged:
    [{name, percent, status, cycles, health_pct}]. Returns [] on desktops.

    Source is `ioreg -rc AppleSmartBattery` (no sudo, no extra dependency).
    macOS reports MaxCapacity/DesignCapacity, from which health_pct is derived
    exactly like the Linux energy_full/energy_full_design ratio."""
    try:
        r = subprocess.run(['ioreg', '-rc', 'AppleSmartBattery'],
                           capture_output=True, text=True, timeout=10)
    except Exception:
        return []
    out = r.stdout or ''
    if not out.strip():
        return []                      # no battery — a desktop Mac

    def _num(key):
        m = re.search(rf'"{key}"\s*=\s*(-?\d+)', out)
        return int(m.group(1)) if m else None

    ent: dict = {'name': 'InternalBattery'}
    pct = _num('CurrentCapacity')
    maxc, design = _num('MaxCapacity'), _num('DesignCapacity')
    # On Apple Silicon CurrentCapacity is already a percentage; on older Intel
    # models it is raw mAh and must be scaled against MaxCapacity.
    if pct is not None:
        if maxc and maxc > 100 and pct > 100:
            pct = round(pct * 100 / maxc)
        ent['percent'] = max(0, min(100, int(pct)))
    ext = re.search(r'"ExternalConnected"\s*=\s*(Yes|No)', out)
    charging = re.search(r'"IsCharging"\s*=\s*(Yes|No)', out)
    if charging and charging.group(1) == 'Yes':
        ent['status'] = 'Charging'
    elif ext:
        ent['status'] = 'Full' if ext.group(1) == 'Yes' else 'Discharging'
    cyc = _num('CycleCount')
    if cyc is not None:
        ent['cycles'] = cyc
    if maxc and design and design > 0:
        ent['health_pct'] = min(100, round(maxc * 100 / design))
    return [ent] if len(ent) > 1 else []


_prev_net_io = {}


def _collect_net_io(psutil):
    out = []
    try:
        counters = psutil.net_io_counters(pernic=True)
    except Exception:
        return out
    now = time.monotonic()
    for iface, c in counters.items():
        if iface == 'lo0' or iface.startswith(('utun', 'awdl', 'llw', 'bridge', 'gif', 'stf')):
            continue
        prev = _prev_net_io.get(iface)
        _prev_net_io[iface] = (c.bytes_sent, c.bytes_recv, now)
        if not prev:
            continue
        dt = now - prev[2]
        if dt <= 0:
            continue
        rx = max(0, c.bytes_recv - prev[1]) / dt
        tx = max(0, c.bytes_sent - prev[0]) / dt
        out.append({'iface': iface, 'rx_bps': round(rx), 'tx_bps': round(tx),
                    'rx_total': c.bytes_recv, 'tx_total': c.bytes_sent})
    out.sort(key=lambda x: x['rx_bps'] + x['tx_bps'], reverse=True)
    return out[:20]


# v3.14.0 #35: secrets-on-disk scanner (parity with the other agents). READ-ONLY
# + REDACTING — never sends a secret's value, only rule/location/masked-preview/
# sha256 fingerprint. Opt-in (server pushes secrets_scan_enabled); bounded hard.
# v6.2.0 (BUG): the mac agent gated the secrets scan on `poll_count % 360`, which
# is process-local and resets on every restart — macOS laptops sleep/restart
# constantly, so a mac restarting more often than ~6h never scanned at all, and
# the server's `force_secrets_scan` ("Scan now") flag was ignored entirely. Mirror
# the Linux agent: a PERSISTED wall-clock due-time plus a one-shot force flag.
SECRETS_SCAN_INTERVAL_S = 6 * 3600
_SECRETS_TS_FILE = 'secrets_scan_last'
_secrets_cfg = {'on': False, 'paths': None, 'force': False}
# v6.4.0: cross-platform heartbeat-flag parity. These were Linux-only and the
# mac agent silently dropped them, so an operator clicking "Scan packages" /
# "Update agent" / configuring backup monitors on a Mac got a success toast and
# nothing happened. Now honoured here too.
_force_sysinfo = False          # force_package_scan → refresh sysinfo (incl. brew) next beat
_backup_monitors = []           # server-pushed backup-freshness monitors
# v6.4.1: the last two Linux/Windows-only signals the mac agent dropped. Custom
# agent-side checks reported "unknown" forever on every Mac, and watched files
# produced no drift report at all — in both cases the server accepted the config
# and the UI showed the check/watch as configured, so the gap was invisible.
_watched_agent_checks = []      # pushed by the server each heartbeat
_watched_files = []             # config-drift watch list
# v6.4.1: watched services (launchd labels). Linux and Windows both honour
# services_watched; the mac agent dropped the key, so the Services page stayed
# empty for every Mac while the server accepted the config — the same
# success-toast-then-silence shape as the v6.4.0 flag-parity batch above.
_watched_services = []          # server-pushed launchd labels for the Services page

# ── v6.4.1: canary / honeytoken files (parity — this was Linux-only) ──────────
#
# Plant a decoy at each configured path (never over an existing file), then
# report access once. Unlike Windows, APFS/HFS+ do maintain last-access times,
# so a pure READ of a decoy is genuinely detectable here as well as a
# modification or deletion.
#
# NOTE: there is no `_remove_canaries()` here on purpose. The macOS agent has
# no uninstall command path at all, so a cleanup helper would be a function
# nothing ever calls. Removing a Mac agent is a manual operation today, and any
# decoys it planted have to be removed by hand along with it.
# ── v6.4.1: live mode / high-res metric burst (parity — was Linux-only) ───────
#
# The device drawer's Live tab asks the server to set `live_until`, and the
# agent then posts 1-second samples until it expires. Only the Linux agent read
# the flag, so opening the Live tab on a Mac showed an empty chart forever with
# no indication why — the server dutifully set the flag and nothing consumed it.
#
# Bounded by max_iters as well as the deadline so a stuck clock or a long
# `live_until` cannot park the heartbeat loop indefinitely.
LIVE_BURST_MAX_ITERS = 30


def _burst_live_samples(server, creds, live_until, max_iters=LIVE_BURST_MAX_ITERS):
    """Post 1 s high-res metric samples until `live_until`. Device-token auth;
    any failure stops the burst quietly — a live chart is a convenience, and it
    must never be able to break the heartbeat that carries everything else."""
    dev_id = creds.get('device_id')
    token = creds.get('token')
    if not dev_id or not token:
        return 0
    try:
        import psutil
    except ImportError:
        return 0          # no psutil on this Mac → no samples to send
    url = f"{str(server).rstrip('/')}/api/devices/{dev_id}/live-sample"
    sent = 0
    for _ in range(max_iters):
        if int(time.time()) >= int(live_until):
            break
        try:
            vm = psutil.virtual_memory()
            sw = psutil.swap_memory()
            worst = 0.0
            for part in psutil.disk_partitions(all=False):
                try:
                    worst = max(worst, psutil.disk_usage(part.mountpoint).percent)
                except Exception:
                    continue
            _post_json(url, {'token': token,
                             'cpu': round(psutil.cpu_percent(interval=None), 1),
                             'mem': round(vm.percent, 1),
                             'disk': round(worst, 1),
                             'swap': round(sw.percent, 1)}, timeout=5)
            sent += 1
        except Exception:
            break
        time.sleep(1)
    return sent


# ── v6.4.1: custom monitoring scripts (parity — this was Linux-only) ──────────
#
# The server assigns scripts by DEVICE ID with no OS awareness, so an operator
# could assign one to a Mac, get a success toast, and have the Custom Scripts
# results page stay empty forever. macOS ships /bin/bash, so this is the same
# implementation as the Linux agent rather than an approximation.
_custom_scripts = []
_pending_script_results = {}
CUSTOM_SCRIPT_EVERY = 5          # run on every 5th poll, like the Linux agent
MAX_SCRIPT_OUTPUT = 4096


def run_custom_scripts(scripts):
    """Run assigned scripts, return {id: {ok, output, rc, ran_at, duration_ms}}.

    Each body is written to a private 0700 temp file and run with a timeout;
    stdout+stderr are merged and capped. Exit 0 is ok, anything else (including
    timeout and exec failure) is not.

    Security: the bodies come from the server, which the agent already trusts
    via the device token on every heartbeat — the same boundary as the exec:
    command channel. Audit mode still refuses them: this runs server-supplied
    shell as root, which is exactly what observe-only mode exists to block.
    """
    import stat as _stat
    results = {}
    now = int(time.time())
    if _audit_mode():
        log.info('Audit mode (read-only): skipping custom scripts')
        return {}
    for s in scripts or []:
        sid = str(s.get('id', ''))
        body = str(s.get('body', ''))
        try:
            timeout = int(s.get('timeout', 30))
        except (TypeError, ValueError):
            timeout = 30
        if not sid or not body:
            continue
        t_start = time.monotonic()
        ok, output, rc, tmp_path = False, '', 1, None
        try:
            fd, tmp_path = tempfile.mkstemp(prefix='rp_cs_', suffix='.sh')
            try:
                os.write(fd, body.encode('utf-8', errors='replace'))
            finally:
                os.close(fd)
            os.chmod(tmp_path, _stat.S_IRWXU)      # 0700 — owner only
            proc = subprocess.run(['/bin/bash', tmp_path],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, timeout=timeout)
            rc = proc.returncode
            ok = (rc == 0)
            output = proc.stdout.decode('utf-8', errors='replace')[:MAX_SCRIPT_OUTPUT]
        except subprocess.TimeoutExpired:
            rc, ok, output = -1, False, f'TIMEOUT after {timeout}s'
        except Exception as e:
            rc, ok, output = -1, False, f'EXEC ERROR: {e}'
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
        results[sid] = {'ok': ok, 'output': output.strip(), 'rc': rc,
                        'ran_at': now,
                        'duration_ms': int((time.monotonic() - t_start) * 1000)}
    return results


_canary_planted = {}       # path -> {mtime, size, plant_ts, ours}
_canary_failed  = {}       # v6.4.2: path -> why the plant failed (arm report)
_canary_reported = set()   # paths already reported this run
_canary_cfg = []
_CANARY_DEFAULT = ('# AWS credentials — do not share\n'
                   '[default]\naws_access_key_id = AKIA' + 'IOSFODNN7EXAMPLE\n'
                   'aws_secret_access_key = wJalrXUtnFEMI/EXAMPLEKEY\n')


# ── v6.4.1: delta sysinfo (parity — this was Linux-only since v6.2.2) ─────────
#
# Heavy, slow-moving sysinfo fields are OMITTED when their content is unchanged
# since the last send the server CONFIRMED. The server merges its stored copy
# back in at ingest, so downstream consumers still see a complete sysinfo, and
# names anything it could not merge in the response's `delta_resend`.
#
# Only the three fields this agent actually produces are listed — the Linux set
# also has ssh_hostkeys/usb/autoupdate/ssh_config, which no macOS heartbeat
# carries. Listing a field the agent never sends would be harmless but is a lie
# about what this agent does.
#
# Nothing is omitted until the server advertises `delta_ok`, so a new agent
# against an old server keeps sending full payloads, and a server that STOPS
# advertising it (downgrade, restore-from-backup) gets full payloads again from
# the very next beat.
_DELTA_SYSINFO_FIELDS = ('packages', 'listening_ports', 'network')
_delta_ok = False        # server advertised the capability
_delta_hashes = {}       # field -> hash of the last value the server confirmed
_delta_pending = {}      # field -> hash sent full THIS beat, not yet confirmed


def _stable_hash(value):
    """Content hash for delta comparison. Agent-local only — the server never
    recomputes it, so the scheme is free to change."""
    blob = json.dumps(value, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def _apply_sysinfo_delta(payload):
    """Drop unchanged heavy fields from payload['sysinfo'] and record what was
    omitted. Records this beat's full-sent hashes as PENDING — they are only
    promoted to confirmed by _commit_sysinfo_delta once the server has
    acknowledged a non-busy store, so a dropped or 202'd beat can never leave
    the server holding data we then stop sending."""
    _delta_pending.clear()
    si = payload.get('sysinfo')
    if not _delta_ok or not isinstance(si, dict):
        return payload
    omitted = {}
    for f in _DELTA_SYSINFO_FIELDS:
        if f not in si:
            continue
        try:
            h = _stable_hash(si[f])
        except Exception:
            continue
        if _delta_hashes.get(f) == h:
            del si[f]
            omitted[f] = h
        else:
            _delta_pending[f] = h
    if omitted:
        payload['sysinfo_omitted'] = omitted
    return payload


def _commit_sysinfo_delta(resp):
    """Learn the capability from every response, commit pending hashes only on a
    non-busy store, and forget anything the server asks to be re-sent."""
    global _delta_ok
    if not isinstance(resp, dict):
        return
    if resp.get('busy') is not True:
        _delta_hashes.update(_delta_pending)
    _delta_pending.clear()
    _delta_ok = bool(resp.get('delta_ok'))
    for f in (resp.get('delta_resend') or []):
        _delta_hashes.pop(f, None)


def _canary_path_ok(p):
    """Absolute POSIX / drive-letter / UNC path, no traversal. Mirrors the
    server-side check so a path the server stored is one we will act on."""
    if not p or len(p) > 512 or '\x00' in p:
        return False
    if not (p.startswith('/') or p.startswith('\\\\')
            or re.match(r'^[A-Za-z]:[\\/]', p)):
        return False
    return not any(seg == '..' for seg in re.split(r'[\\/]+', p))


def _plant_canaries(canary_cfg):
    """Create any not-yet-planted decoy. Never overwrites an existing file —
    a pre-existing path is baselined and left alone."""
    for c in (canary_cfg or [])[:50]:
        p = c.get('path') if isinstance(c, dict) else c
        if not p:
            continue
        if not _canary_path_ok(str(p)):
            # v6.4.2: a rejected path used to vanish — the operator saw a
            # "armed" toast for a path the agent never even attempted.
            _canary_failed[str(p)[:256]] = 'path not permitted for a canary'
            continue
        p = str(p)
        if p in _canary_planted:
            continue
        try:
            if os.path.exists(p):
                st = os.stat(p)
                _canary_planted[p] = {'mtime': int(st.st_mtime), 'size': st.st_size,
                                      'plant_ts': int(time.time()), 'ours': False}
                _canary_failed.pop(p, None)
                continue
            content = (c.get('content') if isinstance(c, dict) else '') or _CANARY_DEFAULT
            d = os.path.dirname(p)
            if d and not os.path.isdir(d):
                os.makedirs(d, exist_ok=True)
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, content.encode())
            finally:
                os.close(fd)
            st = os.stat(p)
            _canary_planted[p] = {'mtime': int(st.st_mtime), 'size': st.st_size,
                                  'plant_ts': int(time.time()), 'ours': True}
            _canary_failed.pop(p, None)
        except OSError as e:
            log.debug('canary plant %s: %s', p, e)
            _canary_failed[p] = (e.strerror or str(e))[:120]


def _canary_status(canary_cfg):
    """[{path, state, detail}] for every CONFIGURED canary path — the arm report.

    v6.4.2: only trip reports (`canary_events`) ever rode the heartbeat, so the
    server had no way to answer "is this honeytoken actually in place?" for any
    host. States: armed (we created the decoy), watching (a REAL file was
    already there, so this is a change-watch on genuine data and NOT a
    honeytoken), failed (`detail` says why), pending (not processed yet).
    """
    out = []
    for c in (canary_cfg or [])[:50]:
        p = c.get('path') if isinstance(c, dict) else c
        if not p:
            continue
        p = str(p)
        base = _canary_planted.get(p)
        if base:
            out.append({'path': p[:256],
                        'state': 'armed' if base.get('ours') else 'watching',
                        'detail': '' if base.get('ours')
                                  else 'a real file was already at this path'})
        elif p in _canary_failed:
            out.append({'path': p[:256], 'state': 'failed',
                        'detail': str(_canary_failed[p])[:120]})
        else:
            out.append({'path': p[:256], 'state': 'pending', 'detail': ''})
    return out

def _check_canaries(canary_cfg):
    """[{path, reason, ts}] for decoys touched since plant, each reported once."""
    events = []
    wanted = {str(c.get('path') if isinstance(c, dict) else c)
              for c in (canary_cfg or [])}
    for p, base in list(_canary_planted.items()):
        if p not in wanted or p in _canary_reported:
            continue
        reason = None
        try:
            st = os.stat(p)
            if int(st.st_mtime) != base['mtime'] or st.st_size != base['size']:
                reason = 'modified'
            elif int(st.st_atime) > base['plant_ts'] + 2:
                reason = 'read'
        except FileNotFoundError:
            reason = 'deleted'
        except OSError:
            reason = None
        if reason:
            _canary_reported.add(p)
            events.append({'path': p, 'reason': reason, 'ts': int(time.time())})
    return events

MAX_DRIFT_FILES = 200
# launchd labels are reverse-DNS. Validated before it reaches argv so a label can
# never be anything but a single token (defence in depth — there is no shell).
_LAUNCHD_LABEL_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')


def compute_drift_report(paths):
    """sha256 each watched file → {path: {hash, size, mtime, exists}}. Identical
    contract to the Linux and Windows agents; pure file I/O, so it is genuinely
    OS-agnostic."""
    out = {}
    for p in (paths or [])[:MAX_DRIFT_FILES]:
        try:
            st = os.stat(p)
        except OSError:
            out[p] = {'hash': None, 'size': None, 'mtime': None, 'exists': False}
            continue
        try:
            h = hashlib.sha256()
            with open(p, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    h.update(chunk)
            out[p] = {'hash': 'sha256:' + h.hexdigest(),
                      'size': st.st_size, 'mtime': int(st.st_mtime), 'exists': True}
        except OSError:
            out[p] = {'hash': None, 'size': st.st_size,
                      'mtime': int(st.st_mtime), 'exists': False}
    return out


def _launchd_status(label):
    """`launchctl list <label>` → (status, output). Read-only, no shell."""
    if not _LAUNCHD_LABEL_RE.match(label or ''):
        return 'unknown', 'invalid label'
    try:
        r = subprocess.run(['launchctl', 'list', label],
                           capture_output=True, text=True, timeout=20)
    except Exception:
        return 'unknown', 'query failed'
    if r.returncode != 0:
        return 'critical', 'not loaded'
    out = r.stdout or ''
    m = re.search(r'"PID"\s*=\s*(\d+)', out)
    if m:
        return 'ok', f'running (pid {m.group(1)})'
    ex = re.search(r'"LastExitStatus"\s*=\s*(-?\d+)', out)
    if ex and ex.group(1) != '0':
        return 'critical', f'loaded, last exit {ex.group(1)}'
    # Loaded with no PID is normal for an on-demand job, so this is a warning
    # rather than critical — the operator asked "is it running", and it is not.
    return 'warning', 'loaded, not running'


def get_services(watched_units):
    """Report launchd job state for each watched label. Returns
    [{unit, active, sub, since}, ...] — the shape process_service_report
    ingests (the same `services` payload key as the Linux/Windows agents, so
    the Services page and failed-service alerting work for Macs).

    ONE argument-less `launchctl list` call covers every label (columns:
    PID, last exit status, label) — no per-label subprocess, and since no
    label is ever passed on a command line there is nothing to quote.
    `since` is 0: launchd doesn't expose a state-change timestamp here.
    """
    if not watched_units:
        return []
    units = [str(u) for u in watched_units[:50] if str(u).strip()]
    if not units:
        return []
    try:
        r = subprocess.run(['launchctl', 'list'],
                           capture_output=True, text=True, timeout=20)
        jobs = {}
        for line in (r.stdout or '').splitlines():
            parts = line.split('\t') if '\t' in line else line.split()
            if len(parts) < 3 or parts[2] in ('Label',):
                continue
            jobs[parts[2].strip()] = (parts[0].strip(), parts[1].strip())
    except Exception:
        return [{'unit': u, 'active': 'unknown', 'sub': '', 'since': 0}
                for u in units]
    out = []
    for u in units:
        pid, status = jobs.get(u, (None, None))
        if pid is None:
            # Not loaded in this launchd domain at all.
            active, sub = 'inactive', 'not loaded'
        elif pid != '-':
            active, sub = 'active', f'running pid {pid}'
        elif status not in ('0', '-', ''):
            active, sub = 'failed', f'last exit {status}'
        else:
            # Loaded, no PID, clean last exit: an on-demand job, not running.
            active, sub = 'inactive', 'loaded, not running'
        out.append({'unit': u, 'active': active, 'sub': sub, 'since': 0})
    return out


# Fixed predicate — error and fault level only. The operator's regex is applied
# in PYTHON below, never interpolated into the predicate, so there is nothing to
# inject through the pattern (same posture as the Windows agent's Event Log path).
_LOG_ERRORS_PREDICATE = 'eventType == "logEvent" AND messageType >= 16'
_LOG_ERRORS_MAX_BYTES = 4 * 1024 * 1024


def _eval_one_agent_check_mac(c):
    ctype = c.get('type')
    param = str(c.get('param', ''))
    if ctype in ('file_present', 'file_absent'):
        try:
            exists = os.path.exists(param)
        except Exception:
            return 'unknown', 'stat failed'
        if ctype == 'file_present':
            return ('ok', 'present') if exists else ('critical', 'missing')
        return ('critical', 'present (should be absent)') if exists else ('ok', 'absent')
    if ctype == 'job_fresh':
        try:
            max_age = int(c.get('max_age_hours', 24)) * 3600
        except (TypeError, ValueError):
            max_age = 24 * 3600
        try:
            age = time.time() - os.stat(param).st_mtime
        except FileNotFoundError:
            return 'critical', 'file missing'
        except Exception:
            return 'unknown', 'stat failed'
        hrs = age / 3600.0
        return ('ok', f'updated {hrs:.1f}h ago') if age <= max_age \
            else ('critical', f'stale: {hrs:.1f}h old (max {max_age // 3600}h)')
    if ctype == 'launchd_service':
        if not param.strip():
            return 'unknown', 'no service'
        return _launchd_status(param.strip())
    if ctype == 'log_errors':
        if not param:
            return 'unknown', 'no pattern'
        try:
            window = int(c.get('window_min', 15))
            warn = int(c.get('warn', 1))
            crit = int(c.get('crit', 10))
        except (TypeError, ValueError):
            window, warn, crit = 15, 1, 10
        window = max(1, min(1440, window))
        try:
            rx = re.compile(param)
        except re.error:
            return 'unknown', 'bad pattern'
        try:
            r = subprocess.run(['log', 'show', '--last', f'{window}m',
                                '--style', 'compact',
                                '--predicate', _LOG_ERRORS_PREDICATE],
                               capture_output=True, text=True, timeout=60)
        except Exception:
            return 'unknown', 'query failed'
        n = sum(1 for ln in (r.stdout or '')[:_LOG_ERRORS_MAX_BYTES].splitlines()
                if ln.strip() and rx.search(ln))
        status = 'critical' if n >= crit else 'warning' if n >= warn else 'ok'
        return status, f'{n} match(es) in {window}min'
    # systemd_unit, windows_service and the Linux-only integrity/egress guard
    # types have no macOS implementation — say so rather than reporting a
    # misleading ok/critical.
    return 'unknown', 'not applicable on macOS'


def eval_agent_checks(checks):
    """Evaluate every server-pushed agent-side check → {id: {status, output}}."""
    out = {}
    for c in checks or []:
        if not isinstance(c, dict) or not c.get('id'):
            continue
        try:
            status, output = _eval_one_agent_check_mac(c)
        except Exception:
            status, output = 'unknown', 'error'
        out[c['id']] = {'status': status, 'output': str(output)[:200]}
    return out


def collect_backup_status(backup_monitors):
    """v6.4.0: backup file/dir freshness (mtime + size) for each configured
    monitor. Portable mirror of the Linux agent's collector — the server-side
    staleness/anomaly logic is identical regardless of OS."""
    results = []
    for mon in (backup_monitors or []):
        p = mon.get('path', '')
        if not p:
            continue
        try:
            exists = os.path.exists(p)
            st = os.stat(p) if exists else None
            mtime = st.st_mtime if st else 0
            if st and os.path.isdir(p):
                size = 0
                try:
                    for i, name in enumerate(os.listdir(p)):
                        if i >= 5000:
                            break
                        try:
                            size += os.stat(os.path.join(p, name)).st_size
                        except OSError:
                            pass
                except OSError:
                    size = 0
            else:
                size = st.st_size if st else 0
        except Exception:
            exists, mtime, size = False, 0, 0
        results.append({'path': p, 'exists': exists, 'mtime': int(mtime),
                        'size': int(size)})
    return results


def _load_secrets_scan_ts():
    try:
        with open(os.path.join(_data_dir(), _SECRETS_TS_FILE), 'r', encoding='utf-8') as f:
            return float((f.read() or '').strip())
    except Exception:
        return 0.0


def _save_secrets_scan_ts(ts):
    try:
        p = os.path.join(_data_dir(), _SECRETS_TS_FILE)
        with open(p, 'w', encoding='utf-8') as f:
            f.write(str(int(ts)))
    except Exception:
        pass


# ── v6.4.1: log_watch file-path rules (were Linux-only) ──────────────────────
#
# A log-watch rule with a `path` tells the agent to tail that file and submit
# new lines to /api/logs under the synthetic unit 'file:<path>' — the same wire
# shape as the Linux agent, so the server's per-device + global pattern
# matching and rolling buffer apply unchanged. Until now this agent dropped the
# `log_watch` key entirely: a file-path rule on a Mac saved fine and never
# fired. Rules with a `unit` stay ignored here (no journald; unit health is the
# launchd_service / log_errors check types).
FILE_LOG_MAX_LINES = 200          # per poll, per file (matches Linux)
FILE_LOG_MAX_BYTES = 256 * 1024   # safety: don't read more than 256 KB per poll
FILE_LOG_SUBMIT_EVERY = 5         # every 5th poll, like the Linux agent
_FILE_LOG_STATE_FILE = 'file_log_state.json'
_log_watch_paths = []             # server-pushed log_watch rules with a `path`
_file_log_state = {}              # path → {inode, pos}; persisted across restarts

# Deny list, same rationale as the Linux agent's: NOT a hard security boundary
# (a server admin can already run commands), just a sanity barrier against the
# obvious silently-exfiltrate-credentials configurations. realpath() first so a
# symlink can't dodge it. macOS spellings: master.passwd + the dslocal user DB,
# and /etc resolves to /private/etc.
_FILE_LOG_DENY_EXACT = frozenset({
    '/etc/sudoers', '/etc/master.passwd',
    '/private/etc/sudoers', '/private/etc/master.passwd',
})
_FILE_LOG_DENY_PREFIX = (
    '/etc/sudoers.d/', '/private/etc/sudoers.d/',
    '/var/db/dslocal/', '/private/var/db/dslocal/',
    '/dev/',
)
_FILE_LOG_DENY_RE = re.compile(r'^/(?:Users/[^/]+|var/root|private/var/root)/\.ssh/')


def _file_log_path_allowed(path_str):
    try:
        real = os.path.realpath(path_str)
    except (OSError, ValueError):
        return False
    if real in _FILE_LOG_DENY_EXACT or _FILE_LOG_DENY_RE.match(real):
        return False
    return not any(real.startswith(p) for p in _FILE_LOG_DENY_PREFIX)


def collect_file_log(path_str, state):
    """Read new lines from a watched file → list of message strings.

    Mirrors the Linux agent's tail state machine: `state[path]` is
    {inode, pos}; rotation (inode changed) and truncation (pos > size) reset
    to 0; on first sight we bookmark the current end so a freshly-configured
    rule doesn't dump the file's history."""
    if not _file_log_path_allowed(path_str):
        log.warning('file_log: refusing to read denied path %r', path_str)
        return []
    lines = []
    try:
        if not os.path.isfile(path_str):
            return []
        st = os.stat(path_str)
        inode, size = st.st_ino, st.st_size
        prev = state.get(path_str) or {}
        prev_inode, prev_pos = prev.get('inode'), int(prev.get('pos', 0))
        if prev_inode is not None and prev_inode != inode:
            prev_pos = 0                       # rotated: new file, read from 0
        if prev_pos > size:
            prev_pos = 0                       # truncated
        if prev_inode is None:
            state[path_str] = {'inode': inode, 'pos': size}
            return []
        if prev_pos >= size:
            state[path_str] = {'inode': inode, 'pos': prev_pos}
            return []
        with open(path_str, 'r', errors='replace') as f:
            f.seek(prev_pos)
            new_text = f.read(FILE_LOG_MAX_BYTES)
            new_pos = f.tell()
        for line in new_text.splitlines()[-FILE_LOG_MAX_LINES:]:
            line = line.strip()
            if line:
                lines.append(line[:1024])
        state[path_str] = {'inode': inode, 'pos': new_pos}
    except PermissionError:
        log.debug('file_log: permission denied for %s', path_str)
    except Exception as e:
        log.debug('file_log: collection failed for %s: %s', path_str, e)
    return lines


def _file_log_state_path():
    return os.path.join(_data_dir(), _FILE_LOG_STATE_FILE)


def _load_file_log_state():
    try:
        with open(_file_log_state_path(), 'r', encoding='utf-8') as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _save_file_log_state(state):
    try:
        tmp = _file_log_state_path() + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(state, f)
        os.replace(tmp, _file_log_state_path())
    except Exception:
        pass


def _submit_file_logs(creds, poll_count):
    """Tail every watched path and POST new lines to /api/logs. State is saved
    only after a successful POST; on failure the in-memory state is reloaded
    from disk so the same region is re-read next time (the server dedupes
    replayed lines by content signature, so a retry can't double-alert)."""
    global _file_log_state
    if not _log_watch_paths:
        return
    if poll_count > 1 and poll_count % FILE_LOG_SUBMIT_EVERY != 0:
        return
    if not _file_log_state:
        _file_log_state = _load_file_log_state()
    units = {}
    for p in _log_watch_paths:
        entries = collect_file_log(p, _file_log_state)
        if entries:
            units[f'file:{p}'] = entries
    if not units:
        _save_file_log_state(_file_log_state)   # first-sight bookmarks still count
        return
    try:
        _post_json(creds.get('server_url', '') + '/api/logs',
                   {'device_id': creds.get('device_id', ''),
                    'token': creds.get('token', ''), 'units': units})
        _save_file_log_state(_file_log_state)
    except Exception as e:
        log.debug('file_log: submission failed: %s', e)
        _file_log_state = _load_file_log_state()


# v6.3.1: hail-mary log sweep — one-shot (server `force_log_sweep`), bounded
# snapshot of recently-modified /var/log text files. Mirrors the Linux agent's
# collect_log_sweep; macOS keeps plain-text logs in /var/log too (system.log,
# install.log, app logs). Binary ASL/tracev3 stores are skipped by the
# null-byte check. The server secret-redacts + re-caps at ingest.
LOG_SWEEP_MAX_FILES   = 40
LOG_SWEEP_TAIL_BYTES  = 12 * 1024
LOG_SWEEP_TOTAL_BYTES = 256 * 1024
LOG_SWEEP_RECENT_S    = 24 * 3600
LOG_SWEEP_MAX_LINE    = 512
_LOG_SWEEP_SKIP_EXT = ('.gz', '.xz', '.bz2', '.zst', '.zip', '.asl', '.tracev3', '.gpg')
_LOG_SWEEP_ERR_RX = re.compile(
    r'(?i)\b(error|err|crit|critical|alert|fatal|fail|failed|failure|panic|'
    r'oops|traceback|exception|denied|refused|timeout|unreachable|killed|corrupt)\b')
_log_sweep_cfg = {'force': False}


def collect_log_sweep():
    import glob as _glob
    now = time.time()
    scanned = skipped = 0
    candidates = []
    paths = _glob.glob('/var/log/*') + _glob.glob('/var/log/*/*')
    for p in paths[:2000]:
        try:
            base = os.path.basename(p)
            if base.lower().endswith(_LOG_SWEEP_SKIP_EXT) or re.search(r'\.\d+$', base):
                continue
            if not os.path.isfile(p) or os.path.islink(p):
                continue
            st = os.stat(p)
            if st.st_size == 0:
                continue
            scanned += 1
            if (now - st.st_mtime) > LOG_SWEEP_RECENT_S:
                continue
            with open(p, 'rb') as f:
                if st.st_size > LOG_SWEEP_TAIL_BYTES:
                    f.seek(st.st_size - LOG_SWEEP_TAIL_BYTES)
                data = f.read(LOG_SWEEP_TAIL_BYTES)
            if b'\x00' in data[:512]:
                skipped += 1
                continue
            lines = [l for l in data.decode('utf-8', errors='replace').splitlines()
                     if l.strip()]
            if st.st_size > LOG_SWEEP_TAIL_BYTES and lines:
                lines = lines[1:]
            if not lines:
                continue
            err_hits = sum(1 for l in lines if _LOG_SWEEP_ERR_RX.search(l))
            score = (err_hits / len(lines)) * 10 + max(0.0, 1 - (now - st.st_mtime) / LOG_SWEEP_RECENT_S) * 2
            candidates.append({'path': p, 'mtime': int(st.st_mtime),
                               'size': int(st.st_size), 'score': round(score, 2),
                               'lines': lines,
                               'truncated': st.st_size > LOG_SWEEP_TAIL_BYTES})
        except (PermissionError, OSError):
            skipped += 1
        except Exception:
            skipped += 1
    candidates.sort(key=lambda c: -c['score'])
    files, total = [], 0
    for c in candidates[:LOG_SWEEP_MAX_FILES]:
        kept = []
        for l in c['lines'][-200:]:
            l = l[:LOG_SWEEP_MAX_LINE]
            total += len(l) + 1
            if total > LOG_SWEEP_TOTAL_BYTES:
                break
            kept.append(l)
        c['lines'] = kept
        files.append(c)
        if total > LOG_SWEEP_TOTAL_BYTES:
            break
    return {'files': files, 'scanned': scanned, 'skipped': skipped}


_SECRET_RULES = [
    ('private_key',    re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----')),
    ('aws_access_key', re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
    ('github_token',   re.compile(r'\bghp_[A-Za-z0-9]{36}\b')),
    ('github_pat',     re.compile(r'\bgithub_pat_[A-Za-z0-9_]{60,}\b')),
    ('slack_token',    re.compile(r'\bxox[baprs]-[0-9A-Za-z-]{10,48}\b')),
    ('slack_webhook',  re.compile(r'https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}')),
    ('google_api_key', re.compile(r'\bAIza[0-9A-Za-z_\-]{35}\b')),
    ('stripe_secret',  re.compile(r'\bsk_live_[0-9A-Za-z]{24,}\b')),
    ('jwt',            re.compile(r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b')),
    ('generic_secret', re.compile(r'(?i)(?:password|passwd|secret|api[_-]?key|token)\s*[=:]\s*[\'"]?([^\s\'"]{8,})')),
]
_SECRETS_SKIP_DIRS = {'.git', 'node_modules', 'vendor', '__pycache__', 'site-packages',
                      '.cache', '.venv', 'venv', 'Library'}
_SECRETS_DEFAULT_PATHS = ['/etc', '/Users', '/opt', '/usr/local', '/srv']


def _redact_secret(s):
    s = s.strip()
    if len(s) <= 4:
        return '****'
    if len(s) <= 8:
        return s[:2] + '*' * (len(s) - 2)
    return s[:4] + '*' * 8 + f'({len(s)})'


def collect_secret_findings(paths=None, max_findings=200, max_file_bytes=1048576,
                            max_files=5000, time_budget=12.0):
    paths = paths or _SECRETS_DEFAULT_PATHS
    findings, seen = [], set()
    start = time.monotonic()
    visited = 0
    for base in paths:
        if not isinstance(base, str) or not os.path.exists(base):
            continue
        if len(findings) >= max_findings or visited >= max_files \
                or time.monotonic() - start > time_budget:
            break
        for dirpath, dirnames, filenames in os.walk(base):
            if len(findings) >= max_findings or visited >= max_files \
                    or time.monotonic() - start > time_budget:
                break
            dirnames[:] = [d for d in dirnames if d not in _SECRETS_SKIP_DIRS]
            for fn in filenames:
                if len(findings) >= max_findings or visited >= max_files:
                    break
                fpath = os.path.join(dirpath, fn)
                try:
                    if os.path.islink(fpath) or not os.path.isfile(fpath):
                        continue
                    sz = os.stat(fpath).st_size
                    if sz == 0 or sz > max_file_bytes:
                        continue
                    visited += 1
                    with open(fpath, 'rb') as f:
                        chunk = f.read(max_file_bytes)
                    if b'\x00' in chunk[:4096]:
                        continue
                    text = chunk.decode('utf-8', 'replace')
                except Exception:
                    continue
                for lineno, line in enumerate(text.splitlines(), 1):
                    if len(line) > 4000:
                        continue
                    for rule, rx in _SECRET_RULES:
                        m = rx.search(line)
                        if not m:
                            continue
                        val = m.group(m.lastindex) if m.lastindex else m.group(0)
                        fph = hashlib.sha256(val.encode('utf-8', 'replace')).hexdigest()[:16]
                        key = (rule, fph, fpath)
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append({'path': fpath[:300], 'line': lineno,
                                         'rule': rule, 'preview': _redact_secret(val)[:48],
                                         'fingerprint': fph})
                        if len(findings) >= max_findings:
                            break
                    if len(findings) >= max_findings:
                        break
    return findings


# ── v6.4.1: PII inventory scan (parity — this was Linux-only) ─────────────────
#
# Reports WHICH FILES contain regulated data, by kind and count. It never
# returns a matched value, not even redacted — the whole point is to find where
# PII lives without creating a second copy of it in the monitoring system. The
# server rebuilds each stored entry from four known-safe fields for the same
# reason, so a tampered agent cannot smuggle a value through.
#
# Ported unchanged from the Linux agent except the default paths, which are the
# macOS equivalents. /etc is deliberately excluded there and /private/etc here:
# it is full of maintainer emails in config files, and a report that opens with
# 400 hits from config is a report nobody reads twice. Look where an
# organisation's DATA lives, not where its config lives.
_PII_SKIP_DIRS = _SECRETS_SKIP_DIRS | {'.terraform', 'dist', 'build', 'Library'}
_PII_DEFAULT_PATHS = ['/Users', '/srv', '/opt', '/usr/local/var', '/Volumes']
_PII_CARD_RX = re.compile(r'\b(?:\d[ -]?){12,18}\d\b')
_PII_RULES = [
    ('email', re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')),
    ('ssn', re.compile(r'\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b')),
    ('iban', re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b')),
    ('phone', re.compile(r'(?<![\w.])\+\d{1,3}[ -]?\d{3}[ -]?\d{3,4}[ -]?\d{3,4}(?![\w.])')),
]
PII_SCAN_INTERVAL_S = 24 * 3600
_PII_TS_FILE = 'pii_scan_last'
_pii_cfg = {'on': False, 'paths': None, 'force': False}

# ── v6.4.1: disk-usage scan (du top-consumers — was Linux-only) ──────────────
#
# The fleet-wide du_scan toggle claimed every device but Macs silently never
# reported. Same design as the Linux agent: shell out to `du` (BSD flags here —
# `-d 1` for depth, `-k` for KiB since BSD du has no --block-size), one level
# deep, never crossing filesystems, hard time budgets. The drawer's "what to
# delete" view works for a filling-up MacBook exactly like a Linux NAS.
DU_SCAN_INTERVAL_S = 12 * 3600
_DU_TS_FILE = 'du_scan_last'
_DU_TOP_N = 15
_DU_DEFAULT_PATHS = ['/Users', '/Applications', '/Library',
                     '/private/var', '/opt', '/usr/local']
_du_cfg = {'on': False, 'paths': None, 'force': False}


def _load_du_scan_ts():
    try:
        with open(os.path.join(_data_dir(), _DU_TS_FILE), 'r', encoding='utf-8') as f:
            return float((f.read() or '').strip())
    except Exception:
        return 0.0


def _save_du_scan_ts(ts):
    try:
        with open(os.path.join(_data_dir(), _DU_TS_FILE), 'w', encoding='utf-8') as f:
            f.write(str(int(ts)))
    except Exception:
        pass


def _parse_du_kib(out, root):
    """Parse `du -x -k -d 1` output → children biggest-first, bytes.
    Pure — unit-testable. BSD du prints KiB; ×1024 restores the byte contract
    the server's _ingest_disk_usage expects. The root's own total (last line)
    is dropped — it's the sum, not a child."""
    rows = []
    for line in (out or '').splitlines():
        parts = line.split('\t', 1)
        if len(parts) != 2:
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
        try:
            size = int(parts[0].strip()) * 1024
        except ValueError:
            continue
        path = parts[1].strip()
        if not path or path.rstrip('/') == root.rstrip('/'):
            continue
        rows.append({'path': path, 'bytes': size})
    rows.sort(key=lambda r: r['bytes'], reverse=True)
    return rows[:_DU_TOP_N]


def collect_disk_usage(paths=None, time_budget=45.0):
    """Top space consumers per configured path. Bounded: one level deep,
    filesystem-local, per-path timeout + overall wall-clock budget.
    Feature-invisible when `du` is absent (returns {})."""
    if not shutil.which('du'):
        return {}
    out = {}
    started = time.time()
    for p in (paths or _DU_DEFAULT_PATHS):
        if time.time() - started > time_budget:
            break
        if not os.path.isdir(p):
            continue
        remaining = max(5.0, time_budget - (time.time() - started))
        try:
            r = subprocess.run(['du', '-x', '-k', '-d', '1', p],
                               capture_output=True, text=True,
                               timeout=min(30.0, remaining))
        except Exception:
            continue            # timeout / permission / vanished — skip this path
        # du exits non-zero on any unreadable subdir but still prints the rest;
        # a partial answer is normal and useful — parse stdout regardless.
        entries = _parse_du_kib(r.stdout, p)
        if entries:
            out[p] = entries
    return out


def _luhn_ok(digits: str) -> bool:
    """Luhn checksum. Without it EVERY 16-digit number — an order id, a
    timestamp, a serial — reads as a credit card, and the operator learns to
    ignore the whole report. The check is what makes the signal usable."""
    total, alt = 0, False
    for ch in reversed(digits):
        if not ch.isdigit():
            return False
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0 and len(digits) >= 13


def collect_pii_findings(paths=None, max_findings=300, max_file_bytes=2097152,
                         max_files=8000, time_budget=20.0):
    """Walk `paths` and report FILES containing PII, by kind and count.

    Never returns a matched value. Bounded on findings, files visited and
    wall-clock — checked at every loop level, like the secrets scan, so a
    pathological tree cannot wedge the heartbeat."""
    paths = paths or _PII_DEFAULT_PATHS
    findings = []
    start = time.monotonic()
    visited = 0

    def _spent():
        return (len(findings) >= max_findings or visited >= max_files
                or time.monotonic() - start > time_budget)

    for base in paths:
        if not isinstance(base, str) or not os.path.exists(base) or _spent():
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            if _spent():
                break
            dirnames[:] = [d for d in dirnames if d not in _PII_SKIP_DIRS]
            for fn in filenames:
                if _spent():
                    break
                fpath = os.path.join(dirpath, fn)
                try:
                    if os.path.islink(fpath) or not os.path.isfile(fpath):
                        continue
                    sz = os.stat(fpath).st_size
                    if sz == 0 or sz > max_file_bytes:
                        continue
                    visited += 1
                    with open(fpath, 'rb') as f:
                        chunk = f.read(max_file_bytes)
                    if b'\x00' in chunk[:4096]:
                        continue
                    text = chunk.decode('utf-8', 'replace')
                except Exception:
                    continue
                counts, lines = {}, {}
                for lineno, line in enumerate(text.splitlines(), 1):
                    if len(line) > 4000:
                        continue
                    for kind, rx in _PII_RULES:
                        n = len(rx.findall(line))
                        if n:
                            counts[kind] = counts.get(kind, 0) + n
                            lines.setdefault(kind, [])
                            if len(lines[kind]) < 5:
                                lines[kind].append(lineno)
                    for cand in _PII_CARD_RX.findall(line):
                        digits = re.sub(r'[ -]', '', cand)
                        if _luhn_ok(digits):
                            # 'credit_card', NOT 'card' — the server's
                            # _PII_KINDS whitelist drops an unknown kind
                            # silently, so a typo here loses every card finding
                            # with no error anywhere. (It did, until this line.)
                            counts['credit_card'] = counts.get('credit_card', 0) + 1
                            lines.setdefault('credit_card', [])
                            if len(lines['credit_card']) < 5:
                                lines['credit_card'].append(lineno)
                for kind, n in counts.items():
                    findings.append({
                        'path': fpath[:300], 'kind': kind, 'count': n,
                        'lines': lines.get(kind, []),
                        # NO 'preview', NO 'fingerprint'. On purpose.
                    })
                    if len(findings) >= max_findings:
                        break
    return findings


def _load_pii_scan_ts():
    try:
        with open(os.path.join(_data_dir(), _PII_TS_FILE), 'r', encoding='utf-8') as f:
            return float((f.read() or '').strip())
    except Exception:
        return 0.0


def _save_pii_scan_ts(ts):
    try:
        with open(os.path.join(_data_dir(), _PII_TS_FILE), 'w', encoding='utf-8') as f:
            f.write(str(ts))
    except OSError:
        pass


def command_argv(cmd):
    """Map a server command string to a macOS argv list, or None if handled
    elsewhere / unknown. Pure — unit-testable on any platform."""
    if cmd == 'reboot':
        return ['shutdown', '-r', '+1']        # needs root (launchd daemon)
    if cmd == 'shutdown':
        return ['shutdown', '-h', '+1']
    if isinstance(cmd, str) and cmd.startswith('exec:'):
        body = cmd[len('exec:'):]
        # v5.0.0 (#F3): strip the optional "to=<seconds>:" per-command timeout prefix.
        import re as _re
        m = _re.match(r'^to=\d{1,5}:(.*)$', body, _re.DOTALL)
        if m:
            body = m.group(1)
        return ['/bin/sh', '-c', body]
    # W6-32: patch execution via Homebrew. `upgrade` upgrades all outdated
    # formulae; `upgrade:<name>` upgrades one. Casks are NOT touched by default
    # (never --greedy). No-op-safe if brew isn't installed (rc reflects it).
    if cmd == 'upgrade' or (isinstance(cmd, str) and cmd.startswith('upgrade:')):
        pkg = cmd[len('upgrade:'):].strip() if cmd.startswith('upgrade:') else ''
        brew = _brew_path()
        if not brew:
            return None    # handled in handle_command → clear "brew not found"
        if pkg and re.match(r'^[A-Za-z0-9@._+-]{1,80}$', pkg):
            return [brew, 'upgrade', '--formula', pkg]
        return [brew, 'upgrade', '--formula']
    return None


def _brew_path():
    """Locate the Homebrew binary (Apple-silicon /opt/homebrew, Intel
    /usr/local). Returns the path or ''."""
    for p in ('/opt/homebrew/bin/brew', '/usr/local/bin/brew'):
        if os.path.exists(p):
            return p
    import shutil
    return shutil.which('brew') or ''


def brew_outdated():
    """W6-32: outdated Homebrew formulae as a packages entry (mirrors the Linux
    apt/dnf shape) so macOS hosts surface on the Patches page. None when brew
    isn't installed."""
    brew = _brew_path()
    if not brew:
        return None
    try:
        r = subprocess.run([brew, 'outdated', '--formula', '--json=v2'],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0 or not r.stdout.strip():
            return {'manager': 'brew', 'upgradable': 0, 'upgradable_names': []}
        data = json.loads(r.stdout)
        names = [f.get('name', '') for f in (data.get('formulae') or []) if f.get('name')]
        return {'manager': 'brew', 'upgradable': len(names),
                'upgradable_names': names[:100]}
    except Exception:
        return None


def _exec_timeout_override(cmd):
    """v5.0.0 (#F3): parse the optional exec:to=<seconds>: prefix → clamped int or None."""
    import re as _re
    if isinstance(cmd, str) and cmd.startswith('exec:'):
        m = _re.match(r'^to=(\d{1,5}):', cmd[len('exec:'):])
        if m:
            return max(1, min(int(m.group(1)), 3600))
    return None


def _http_get_json(url, timeout=HTTP_TIMEOUT):
    """GET a JSON body over HTTPS via the no-redirect opener (token-free)."""
    if not url.startswith('https://'):
        raise ValueError(f"Server URL must use HTTPS, got: {url[:32]}")
    req = urllib.request.Request(url, headers={'User-Agent': f'RemotePower-Mac/{VERSION}'})
    with _OPENER.open(req, timeout=timeout) as resp:
        return json.loads(resp.read(MAX_JSON_RESP).decode('utf-8'))


def _http_get_bytes(url, timeout=90):
    """GET raw bytes over HTTPS via the no-redirect opener (token-free)."""
    if not url.startswith('https://'):
        raise ValueError(f"Server URL must use HTTPS, got: {url[:32]}")
    req = urllib.request.Request(url, headers={'User-Agent': f'RemotePower-Mac/{VERSION}'})
    with _OPENER.open(req, timeout=timeout) as resp:
        return resp.read(MAX_DOWNLOAD)


# Set by a successful _self_update(); the run loop re-execs into the NEW file
# only AFTER the update's cmd_output has been reported to the server.
_RESTART_AFTER_REPORT = [False]


def _self_update():
    """v6.3.0: download + sha256-verify + atomically install a fresh mac agent.

    Mirrors the Windows agent's flow against /api/agent/mac/{version,download}.
    sha256 over HTTPS with a no-redirect opener is the trust anchor (same as
    the Linux agent's default; detached-signature pinning is not yet wired on
    macOS). rc 0 ONLY on a verified install or a genuine already-current no-op.
    The process re-execs into the new file after reporting, so launchd
    KeepAlive supervision (or a manual --run) continues seamlessly.
    """
    if _audit_mode():
        return {'cmd': 'update', 'output': 'audit (read-only) mode: self-update refused', 'rc': 126}
    creds = load_creds()
    server = (creds.get('server_url') or '').rstrip('/')
    if not server:
        return {'cmd': 'update', 'output': 'no server URL on record', 'rc': 1}
    try:
        info = _http_get_json(f'{server}/api/agent/mac/version', timeout=15)
    except Exception as e:
        return {'cmd': 'update', 'output': f'version check failed: {e}', 'rc': 1}
    remote_sha = (info.get('sha256') or '').strip().lower()
    remote_ver = info.get('version') or '?'
    if not remote_sha:
        return {'cmd': 'update', 'output': 'server publishes no macOS agent — nothing to update', 'rc': 0}
    local_sha = self_sha256().lower()
    import hmac as _hmac
    if local_sha and _hmac.compare_digest(local_sha, remote_sha):
        return {'cmd': 'update', 'output': f'already current (v{VERSION})', 'rc': 0}
    try:
        data = _http_get_bytes(f'{server}/api/agent/mac/download', timeout=90)
    except Exception as e:
        return {'cmd': 'update', 'output': f'download failed: {e}', 'rc': 1}
    actual_sha = hashlib.sha256(data).hexdigest().lower()
    if not _hmac.compare_digest(actual_sha, remote_sha):
        return {'cmd': 'update',
                'output': f'sha256 mismatch (got {actual_sha[:12]}…, expected {remote_sha[:12]}…) '
                          '— refusing to install', 'rc': 1}
    self_path = os.path.abspath(__file__)
    try:
        tmp = self_path + '.rp-new'
        with open(tmp, 'wb') as f:
            f.write(data)
        # v6.4.0: 0o700 (owner-only rwx), matching the Linux agent's self-update
        # (least privilege — the launchd daemon runs as root, so the replaced
        # binary never needs to be world-readable/executable).
        os.chmod(tmp, 0o700)
        os.replace(tmp, self_path)   # atomic on APFS
    except Exception as e:
        return {'cmd': 'update', 'output': f'install write failed: {e}', 'rc': 1}
    _RESTART_AFTER_REPORT[0] = True
    return {'cmd': 'update',
            'output': f'updated v{VERSION} → v{remote_ver} (sha {actual_sha[:12]}…); '
                      'restarting into the new agent after this report', 'rc': 0}


def handle_command(cmd):
    if not cmd:
        return None
    if _audit_mode():   # v4.10.0: read-only agent refuses every command
        return {'cmd': cmd, 'output': 'refused: agent is in audit (read-only) mode', 'rc': 126}
    if cmd.startswith('poll_interval:'):
        try:
            n = int(cmd.split(':', 1)[1])
            c = load_creds()
            c['poll_interval'] = max(10, min(3600, n))
            save_creds(c)
        except Exception:
            pass
        return None
    if cmd == 'update':
        # v6.3.0: real self-update (was an honest rc:1 "not implemented" stub;
        # the v6.2.0 bug before THAT reported rc:0 while installing nothing).
        return _self_update()
    # v6.4.0: conditional reboot for patch policies. On macOS the agent's
    # `upgrade` is Homebrew, and brew upgrades never require a restart — OS
    # updates go through softwareupdate, which manages its own. So "reboot if
    # required" honestly never reboots here; the explicit `reboot` command
    # remains for operators who want one regardless.
    if cmd == 'reboot-if-required':
        return {'cmd': cmd,
                'output': 'no reboot required (brew upgrades never need one) — skipped',
                'rc': 0}
    argv = command_argv(cmd)
    if argv is None:
        # W6-32: an upgrade command with no brew installed → a clear message.
        if cmd == 'upgrade' or cmd.startswith('upgrade:'):
            return {'cmd': cmd, 'output': 'Homebrew is not installed on this host', 'rc': 1}
        return {'cmd': cmd, 'output': f'unsupported command: {cmd}', 'rc': 1}
    try:
        is_exec = cmd.startswith('exec:')
        is_upgrade = cmd == 'upgrade' or cmd.startswith('upgrade:')   # W6-32: slow
        _to = _exec_timeout_override(cmd) if is_exec else (1800 if is_upgrade else None)
        r = subprocess.run(argv, capture_output=True, text=True,
                           timeout=_to or (EXEC_TIMEOUT if is_exec else 30))
        out = ((r.stdout or '') + (r.stderr or '')).strip()[:MAX_OUTPUT]
        return {'cmd': cmd, 'output': out or '(no output)', 'rc': r.returncode}
    except subprocess.TimeoutExpired:
        return {'cmd': cmd, 'output': 'command timed out', 'rc': 124}
    except Exception as e:
        return {'cmd': cmd, 'output': f'error: {e}', 'rc': 1}


def _post_json(url, payload, timeout=HTTP_TIMEOUT):
    # v4.4.0 (SECURITY): refuse non-HTTPS — otherwise the device token and all
    # command output travel in cleartext and a MITM can inject commands the
    # agent executes as root. Mirrors the Linux agent's guard.
    if not url.startswith('https://'):
        raise ValueError(f"Server URL must use HTTPS, got: {url[:32]}")
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, method='POST',
                                 headers={'Content-Type': 'application/json',
                                          'User-Agent': f'RemotePower-Mac/{VERSION}'})
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            return json.loads(resp.read(MAX_JSON_RESP).decode('utf-8'))
    except urllib.error.HTTPError as e:
        # Surface the server's JSON {"error": "..."} instead of a raw HTTPError
        # traceback — enrollment 400/403s are operator-actionable.
        detail = ''
        try:
            # v6.4.3: cap it. This is a NETWORK body on the enrol path — the one
            # request made before the server is trusted — and it was the only
            # uncapped read left in either agent. Same bound the success path
            # already uses.
            detail = (json.loads(e.read(MAX_JSON_RESP).decode('utf-8')) or {}).get('error', '')
        except Exception:
            pass
        raise RuntimeError(f'server returned HTTP {e.code}'
                           + (f': {detail}' if detail else '')) from None


def build_heartbeat(creds, poll_count, pending_output=None):
    """Assemble the heartbeat payload. Pure (no network) — unit-testable."""
    payload = {
        'device_id':    creds.get('device_id', ''),
        'token':        creds.get('token', ''),
        'ip':           get_local_ip(),
        'os':           get_os_info(),
        'version':      VERSION,
        'agent_sha256': self_sha256(),
    }
    global _force_sysinfo
    if poll_count <= 1 or poll_count % 12 == 0 or _force_sysinfo:
        payload['sysinfo'] = collect_sysinfo()
        _force_sysinfo = False   # v6.4.0: one-shot force_package_scan consumed
    # v6.4.1: agent-side custom checks. Evaluated every beat (they are the
    # health signal, so the sysinfo cadence would be too slow) and reported
    # under sysinfo, which is where the server's Checks engine reads them —
    # so a beat that carries results must carry a sysinfo dict to put them in.
    #
    # v6.4.2: that dict is a PARTIAL update, and it must say so. The server's
    # ingest replaces dev['sysinfo'] wholesale, so an unflagged one-key dict
    # wiped the stored record — uptime, platform, kernel, mounts,
    # listening_ports, network, every cpu/mem/disk percentage — on 11 of every
    # 12 beats for any Mac with a check assigned. The host's Checks page
    # collapsed from 14 rows to 2, so a filling disk or a world-exposed port
    # reported nothing wrong ~92% of the time. `sysinfo_partial` tells the
    # server to merge over the previous record instead of replacing it, which
    # keeps BOTH properties: results every beat, and a complete record.
    if _watched_agent_checks:
        try:
            results = eval_agent_checks(_watched_agent_checks)
            if results:
                _full = 'sysinfo' in payload
                payload.setdefault('sysinfo', {})['custom_check_results'] = results
                if not _full:
                    payload['sysinfo_partial'] = True
        except Exception:
            pass
    # v6.4.1: config-drift report on the sysinfo cadence (hashing is the
    # expensive part, and a watched file changing between beats still shows up).
    if _watched_files and (poll_count <= 1 or poll_count % 12 == 0):
        try:
            drift = compute_drift_report(_watched_files)
            if drift:
                payload['drift'] = drift
        except Exception:
            pass
    # v6.4.1: watched-service states, on the same slower cadence as sysinfo
    # (matches the Windows agent; a service dying between beats still shows up
    # on the next sampled beat, and the server's flap detection is delta-based).
    if _watched_services and (poll_count <= 1 or poll_count % 12 == 0):
        try:
            svcs = get_services(_watched_services)
            if svcs:
                payload['services'] = svcs
        except Exception:
            pass
    # v6.4.0: backup-freshness reporting when the server pushed monitors.
    if _backup_monitors:
        try:
            payload['backup_status'] = collect_backup_status(_backup_monitors)
        except Exception:
            pass
    # v6.4.1: du top-consumers, opt-in, ~12h or on demand (parity with Linux).
    if _du_cfg['on'] and (_du_cfg['force']
                          or time.time() - _load_du_scan_ts() >= DU_SCAN_INTERVAL_S):
        try:
            _du = collect_disk_usage(_du_cfg.get('paths'))
            if _du:
                payload['disk_usage'] = _du
            # Stamp on every real attempt (not only success), like the pii
            # scan — a host with nothing to report must not rescan every beat.
            _save_du_scan_ts(time.time())
        except Exception as _e:
            log.debug('du scan error: %s', _e)
        _du_cfg['force'] = False
    # v6.4.1: custom monitoring scripts, on their own cadence (every 5th poll,
    # like the Linux agent). Results are held until a beat carries them so a
    # failed POST doesn't lose a run.
    global _pending_script_results
    if _custom_scripts and poll_count > 1 and poll_count % CUSTOM_SCRIPT_EVERY == 0:
        try:
            _pending_script_results.update(run_custom_scripts(_custom_scripts))
        except Exception as _e:
            log.debug('custom script run error: %s', _e)
    if _pending_script_results:
        payload['custom_script_results'] = dict(_pending_script_results)
        _pending_script_results = {}
    # v6.4.1: canary-file access, edge-triggered. Reported on EVERY beat, not
    # the slower sysinfo cadence — a tripwire that waits ten minutes to fire is
    # not much of a tripwire.
    if _canary_cfg:
        try:
            _cev = _check_canaries(_canary_cfg)
            if _cev:
                payload['canary_events'] = _cev
        except Exception:
            pass
        # v6.4.2: the ARM report. Only trip reports rode the heartbeat, so the
        # server had no way to show whether a honeytoken was ever planted — an
        # operator could believe they had ransomware tripwire coverage that a
        # read-only filesystem or a permission error had silently prevented.
        # Written only onto a FULL sysinfo (never a partial one — a partial
        # dict is merged, but the state is cheap to recompute and belongs with
        # the rest of the posture).
        if isinstance(payload.get('sysinfo'), dict) and not payload.get('sysinfo_partial'):
            try:
                _cst = _canary_status(_canary_cfg)
                if _cst:
                    payload['sysinfo']['canary_status'] = _cst
            except Exception:
                pass
    _sec_due = (time.time() - _load_secrets_scan_ts()) >= SECRETS_SCAN_INTERVAL_S
    if _secrets_cfg.get('on') and (_sec_due or _secrets_cfg.get('force')):
        try:
            payload['secret_findings'] = collect_secret_findings(_secrets_cfg.get('paths'))
            _save_secrets_scan_ts(time.time())
        except Exception:
            pass
        _secrets_cfg['force'] = False
    # v6.4.1: PII inventory, on a persisted wall-clock due-time (never a
    # poll_count modulo — that resets on every restart, so a restart-churny host
    # would never scan; the v6.1.2 image-scan bug).
    _pii_due = (time.time() - _load_pii_scan_ts()) >= PII_SCAN_INTERVAL_S
    if _pii_cfg.get('on') and (_pii_due or _pii_cfg.get('force')):
        try:
            payload['pii_findings'] = collect_pii_findings(_pii_cfg.get('paths'))
            _save_pii_scan_ts(time.time())
        except Exception as _e:
            log.debug('pii scan error: %s', _e)
        _pii_cfg['force'] = False
    # v6.3.1: one-shot hail-mary log sweep (operator "Diagnose from logs").
    if _log_sweep_cfg.get('force'):
        try:
            payload['log_sweep'] = collect_log_sweep()
        except Exception:
            pass
        _log_sweep_cfg['force'] = False
    if pending_output:
        payload['cmd_output'] = pending_output
        payload['executed_command'] = pending_output.get('cmd', '')
    # v6.4.1: last — omit unchanged heavy sysinfo fields. Must run after every
    # sysinfo mutation above, or a field added later in this function would be
    # hashed before it was complete.
    return _apply_sysinfo_delta(payload)


def enroll(server, pin=None, token=None, name=None):
    server = server.rstrip('/')
    payload = {
        'hostname': socket.gethostname(),
        'name':     name or socket.gethostname(),
        'os':       get_os_info(),
        'ip':       get_local_ip(),
        'mac':      get_mac(),
        'version':  VERSION,
    }
    if pin:
        payload['pin'] = str(pin).strip()
    if token:
        payload['enrollment_token'] = token.strip()
    resp = _post_json(f'{server}/api/enroll/register', payload)
    if not resp.get('ok'):
        raise RuntimeError(resp.get('error', 'enrollment failed'))
    save_creds({'server_url': server, 'device_id': resp['device_id'],
                'token': resp['token'], 'poll_interval': DEFAULT_POLL})
    return resp


def heartbeat_once(creds, poll_count, pending_output=None):
    server = creds.get('server_url', '').rstrip('/')
    payload = build_heartbeat(creds, poll_count, pending_output)
    resp = _post_json(f'{server}/api/heartbeat', payload)
    new_pending = None
    if isinstance(resp, dict):
        if isinstance(resp.get('poll_interval'), int):
            if resp['poll_interval'] != creds.get('poll_interval'):
                creds['poll_interval'] = resp['poll_interval']
                save_creds(creds)
        cmd = resp.get('command')
        # v6.3.1: signed-command gate (opt-in, fail-closed); refusal is
        # reported as command output so the operator sees why nothing ran.
        if cmd and _require_signed_commands_mac():
            _ok, _detail = _command_sig_ok_mac(
                cmd, resp.get('command_sig'), resp.get('command_sig_ts'),
                creds.get('device_id', ''))
            if not _ok:
                new_pending = {'cmd': cmd, 'rc': 126,
                               'output': ('refused: require-signed-commands is '
                                          f'set and verification failed ({_detail})')}
                cmd = None
        if cmd:
            new_pending = handle_command(cmd)
        _secrets_cfg['on'] = bool(resp.get('secrets_scan_enabled'))
        _ssp = resp.get('secrets_scan_paths')
        _secrets_cfg['paths'] = _ssp if isinstance(_ssp, list) and _ssp else None
        if resp.get('force_secrets_scan'):
            _secrets_cfg['force'] = True   # one-shot "Scan now" from the server
        # v6.3.1: one-shot hail-mary log sweep, acted on next heartbeat.
        if resp.get('force_log_sweep'):
            _log_sweep_cfg['force'] = True
        # v6.4.0: cross-platform flag parity (were silently dropped).
        global _force_sysinfo, _backup_monitors, _watched_agent_checks, _watched_files
        if resp.get('force_package_scan'):
            _force_sysinfo = True   # refresh sysinfo (incl. brew outdated) next beat
        _bm = resp.get('backup_monitors')
        if isinstance(_bm, list):
            _backup_monitors = _bm
        # v6.4.1: agent-side checks + the config-drift watch list.
        _ac = resp.get('agent_checks')
        if isinstance(_ac, list):
            _watched_agent_checks = [c for c in _ac
                                     if isinstance(c, dict) and c.get('id')][:100]
        _wf = resp.get('watched_files')
        if isinstance(_wf, list):
            _watched_files = [str(f) for f in _wf if str(f).strip()][:MAX_DRIFT_FILES]
        # v6.4.1: watched services (launchd labels) — parity with Linux/Windows.
        global _watched_services
        _sw = resp.get('services_watched')
        if isinstance(_sw, list):
            _watched_services = [str(s) for s in _sw if str(s).strip()][:50]
        # v6.4.1: log_watch file-path rules — tail the named files. Unit rules
        # are ignored on purpose (no journald here).
        global _log_watch_paths
        _lw = resp.get('log_watch')
        if isinstance(_lw, list):
            _log_watch_paths = [str(r.get('path')) for r in _lw
                                if isinstance(r, dict) and r.get('path')][:20]
        # v6.4.1: PII inventory scan config (mirrors the secrets-scan trio).
        _pii_cfg['on'] = bool(resp.get('pii_scan_enabled'))
        _psp = resp.get('pii_scan_paths')
        _pii_cfg['paths'] = _psp if isinstance(_psp, list) and _psp else None
        if resp.get('force_pii_scan'):
            _pii_cfg['force'] = True   # one-shot "Scan now" from the server
        # v6.4.1: du-scan config trio (parity with Linux).
        _du_cfg['on'] = bool(resp.get('du_scan_enabled'))
        _dsp = resp.get('du_scan_paths')
        _du_cfg['paths'] = _dsp if isinstance(_dsp, list) and _dsp else None
        if resp.get('force_du_scan'):
            _du_cfg['force'] = True    # one-shot "Scan now" from the server
        # v6.4.1: custom monitoring scripts assigned to this device.
        global _custom_scripts
        _cs = resp.get('custom_scripts')
        if isinstance(_cs, list):
            # 20 is a runaway backstop, NOT a policy limit — the server already
            # caps at MAX_CUSTOM_SCRIPTS_PER_DEVICE (10), so this only bites if
            # something is badly wrong. Kept above the server's number so a
            # future raise there can't make us silently drop assigned scripts.
            _custom_scripts = [c for c in _cs
                               if isinstance(c, dict) and c.get('id')][:20]
        # v6.4.1: canary/honeytoken decoys — plant any new ones on receipt.
        if 'canary_files' in resp:
            global _canary_cfg
            _canary_cfg = resp.get('canary_files') or []
            try:
                _plant_canaries(_canary_cfg)
            except Exception as _e:
                log.debug('canary plant error: %s', _e)
            # Forget the reported flag for paths no longer configured, so a
            # re-added decoy can alert again instead of staying silent forever.
            _wanted = {str(c.get('path') if isinstance(c, dict) else c)
                       for c in _canary_cfg}
            for _gone in [p for p in list(_canary_reported) if p not in _wanted]:
                _canary_reported.discard(_gone)
        # v6.4.1: delta-sysinfo bookkeeping — commit only on a confirmed store.
        _commit_sysinfo_delta(resp)
        # v6.4.1: live mode — burst 1 s samples while the operator has the Live
        # tab open. Runs LAST so it cannot delay anything above it.
        _lu = resp.get('live_until')
        if _lu:
            try:
                _burst_live_samples(creds.get('server_url', ''), creds, int(_lu))
            except (TypeError, ValueError):
                pass
        if resp.get('force_agent_upgrade'):
            # Same self-update path as the `update` command; report the result
            # back on the next beat so the operator sees it took.
            try:
                new_pending = _self_update()
            except Exception as _e:
                new_pending = {'cmd': 'force_agent_upgrade',
                               'output': f'self-update failed: {_e}', 'rc': 1}
    # v6.4.1: log_watch file-path tails ride their own POST on the Linux
    # cadence (every 5th poll). Best-effort: a failure never breaks the beat.
    try:
        _submit_file_logs(creds, poll_count)
    except Exception as _e:
        log.debug('file_log submit error: %s', _e)
    return resp, new_pending


def run():
    poll_count = 0
    pending = None
    # v6.4.1: launchd's crash-output file is bounded too. Checked at startup and
    # hourly — a getsize() on a normally-empty file is free, and the alternative
    # is the unbounded growth this whole change exists to stop.
    if _trim_boot_log():
        log.info('truncated oversized %s', BOOT_LOG_FILE)
    while True:
        creds = load_creds()
        if not creds.get('device_id'):
            log.error('not enrolled — run with --enroll first')
            return 1
        poll_count += 1
        if poll_count % 60 == 0 and _trim_boot_log():
            log.info('truncated oversized %s', BOOT_LOG_FILE)
        sent = pending
        _resp = None
        try:
            _resp, pending = heartbeat_once(creds, poll_count, pending)
            # v6.3.0: a successful self-update swapped the file on disk; once
            # its result has been REPORTED (it was `sent` this iteration),
            # re-exec into the new file. Works under launchd KeepAlive and a
            # manual --run alike — execv replaces this process in place.
            if _RESTART_AFTER_REPORT[0] and sent and sent.get('cmd') == 'update':
                log.info('update installed — re-exec into the new agent')
                os.execv(sys.executable,
                         [sys.executable, os.path.abspath(__file__)] + sys.argv[1:])
        except Exception as e:
            log.warning('heartbeat error: %s', e)
        delay = max(10, int(load_creds().get('poll_interval', DEFAULT_POLL)))
        # v6.4.1: honour the 202-busy retry_after hint — lock contention is
        # momentary, so a short retry beats waiting out a full poll interval.
        # Floor of 5 s so a tiny hint can never turn the loop into a hammer.
        if isinstance(_resp, dict) and _resp.get('busy') is True:
            try:
                delay = max(5, min(delay, int(_resp.get('retry_after') or delay)))
            except (TypeError, ValueError):
                pass
        time.sleep(delay)


def main(argv=None):
    ap = argparse.ArgumentParser(description='RemotePower minimal macOS agent')
    ap.add_argument('--enroll', action='store_true')
    ap.add_argument('--server')
    ap.add_argument('--pin')
    ap.add_argument('--token')
    ap.add_argument('--name')
    ap.add_argument('--run', action='store_true')
    ap.add_argument('--once', action='store_true')
    ap.add_argument('--version', action='store_true')
    a = ap.parse_args(argv)
    if a.version:
        print(VERSION)
        return 0
    if a.enroll:
        if not a.server or not (a.pin or a.token):
            ap.error('--enroll needs --server and --pin (or --token)')
        if a.token and not a.pin and re.fullmatch(r'\d{6}', a.token.strip()):
            print('That looks like a 6-digit PIN, not an enrollment token — '
                  'use --pin instead of --token.', file=sys.stderr)
            return 2
        try:
            r = enroll(a.server, pin=a.pin, token=a.token, name=a.name)
        except Exception as e:
            print(f'Enrollment failed: {e}', file=sys.stderr)
            return 1
        print(f'enrolled: device_id={r["device_id"]}')
        return 0
    if a.once:
        resp, _ = heartbeat_once(load_creds(), 1)
        print(json.dumps(resp, indent=2))
        return 0
    if a.run:
        return run() or 0
    ap.print_help()
    return 0


if __name__ == '__main__':
    sys.exit(main())

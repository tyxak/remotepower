#!/usr/bin/env python3
"""RemotePower — minimal Windows agent (v3.14.0).

A small, standalone agent that speaks the same server contract as the Linux
agent (client/remotepower-agent.py) but implements only the essentials so a
Windows host can be managed:

  * enroll (PIN or enrollment token)
  * heartbeat loop with core sysinfo (CPU / memory / disk / uptime / network)
  * remote reboot / shutdown / exec / poll-interval / uninstall
  * posture parity: Windows Update pending (→ Patches), listening ports
    (→ Exposure + port audit), the Event Log tail (→ Logs/journal), and local
    users (→ account audit), all in the same shapes the Linux agent sends so the
    existing UI renders them

Still pending for full parity: watched-service status, SMART, drift apply,
signed self-update, and PyInstaller packaging — added in later phases, at which
point this converges onto the cross-platform agent. Keeping it separate for now
means it can't destabilise the production Linux agent.

Stdlib only (urllib/json/socket/subprocess/platform/hashlib). `psutil` is used
for richer metrics when present, but the agent runs without it.

Usage:
    remotepower-agent-win.py --enroll --server https://rp.example.com --pin 123456 [--name NAME]
    remotepower-agent-win.py --run            # service / scheduled-task entrypoint
    remotepower-agent-win.py --once           # one heartbeat (debugging)
"""
import argparse
import hashlib
import json
import os
import platform
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.request

VERSION = '4.10.0'
DEFAULT_POLL = 60

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
    Linux agent (v4.4.0). The default urlopen context already verifies certs, but
    it permits obsolete TLS 1.0/1.1; pin the floor here. RP_CA_BUNDLE lets the
    agent trust an internal CA without weakening verification."""
    ctx = ssl.create_default_context()
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    _ca = os.environ.get('RP_CA_BUNDLE', '').strip()
    if not _ca:
        # v4.5.0: conventional self-signed CA path (mirrors _data_dir(), inlined
        # because _SSL_CTX is built before _data_dir() is defined).
        _def = os.path.join(os.environ.get('ProgramData', r'C:\ProgramData'),
                            'RemotePower', 'ca.crt')
        if os.path.exists(_def):
            _ca = _def
    if _ca and os.path.exists(_ca):
        try:
            ctx.load_verify_locations(cafile=_ca)
        except Exception:
            pass
    return ctx


_SSL_CTX = _make_ssl_context()
HTTP_TIMEOUT = 20
EXEC_TIMEOUT = 300
MAX_OUTPUT = 32 * 1024


# ─── config / creds ──────────────────────────────────────────────────────────

def _data_dir():
    """Per-machine config dir. RP_DATA_DIR overrides (tests / non-Windows)."""
    env = os.environ.get('RP_DATA_DIR')
    if env:
        return env
    base = os.environ.get('ProgramData', r'C:\ProgramData')
    return os.path.join(base, 'RemotePower')


def _creds_path():
    return os.path.join(_data_dir(), 'agent.json')


def load_creds():
    try:
        with open(_creds_path(), 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def save_creds(creds):
    d = _data_dir()
    os.makedirs(d, exist_ok=True)

    # v4.6.0 (SECURITY): agent.json holds the device bearer token. Under
    # C:\ProgramData it inherits ACLs that let the local Users group read it,
    # so any non-admin user could read the token and impersonate this host.
    # Strip inheritance and grant only SYSTEM + Administrators. Best-effort
    # (icacls ships with Windows).
    def _harden_acl(path):
        try:
            subprocess.run(
                ['icacls', path, '/inheritance:r',
                 '/grant:r', 'SYSTEM:(OI)(CI)F', '/grant:r', 'Administrators:(OI)(CI)F'],
                capture_output=True, timeout=15,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        except Exception:
            pass

    # v4.8.0 (SECURITY): lock the data dir down BEFORE the first token write so
    # the creds file inherits the restricted ACL from creation — closes the
    # window where the freshly-written token briefly carried Users-readable ACLs.
    _harden_acl(d)
    tmp = _creds_path() + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(creds, f)
    os.replace(tmp, _creds_path())
    _harden_acl(_creds_path())


# ─── host facts ────────────────────────────────────────────────────────────--

def get_os_info():
    """e.g. 'Windows 11 (Build 22631)'. Falls back gracefully off-Windows."""
    try:
        rel, ver, _csd, _ptype = platform.win32_ver()
        build = (ver or '').split('.')[-1]
        name = f'Windows {rel}' if rel else platform.system()
        return f'{name} (Build {build})' if build else name
    except Exception:
        return platform.platform() or platform.system() or 'Windows'


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return ''


def get_mac():
    try:
        import uuid
        m = uuid.getnode()
        return ':'.join(f'{(m >> e) & 0xff:02x}' for e in range(40, -8, -8))
    except Exception:
        return ''


def self_sha256():
    """SHA-256 of this agent file (frozen exe path under PyInstaller)."""
    try:
        path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ''


def _parse_wu_titles(stdout):
    """Parse one-title-per-line output from the Windows Update searcher into a
    clean list. Pure — unit-testable off-Windows."""
    return [ln.strip() for ln in (stdout or '').splitlines() if ln.strip()][:200]


# PowerShell: pending (not-installed, not-hidden) Windows Updates, one title/line.
_WU_PS = (
    "$ErrorActionPreference='Stop';"
    "$u=(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()"
    ".Search('IsInstalled=0 and IsHidden=0').Updates;"
    "$u | ForEach-Object { $_.Title }"
)


def windows_update_pending():
    """Pending Windows Updates as a packages entry, or None. This is the
    security-patch posture on Windows; it surfaces on the Patches page. The COM
    search can be slow, so it only runs on the (infrequent) sysinfo cadence."""
    if not sys.platform.startswith('win'):
        return None
    try:
        r = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command', _WU_PS],
                           capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            return None
        titles = _parse_wu_titles(r.stdout)
        return {'manager': 'windows-update', 'upgradable': len(titles),
                'upgradable_names': titles[:50]}
    except Exception:
        return None


def _port_scope(ip):
    """Classify a bind address into world / lan / local — matches the server's
    exposure buckets so Windows listeners render like Linux ones. Pure."""
    if not ip or ip in ('127.0.0.1', '::1', 'localhost'):
        return 'local'
    if ip in ('0.0.0.0', '::'):
        return 'world'
    if ip.startswith(('10.', '192.168.', '169.254.', 'fe80:', 'fc', 'fd')):
        return 'lan'
    if ip.startswith('172.'):
        try:
            if 16 <= int(ip.split('.')[1]) <= 31:
                return 'lan'
        except (ValueError, IndexError):
            pass
    return 'world'


def collect_listening_ports():
    """LISTEN sockets via psutil (cross-platform). Returns the same shape the
    Linux agent sends — [{proto, port, process, addr, scope}] — so the Exposure
    page and port audit work unchanged for Windows hosts. [] without psutil."""
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


# PowerShell: recent System/Application events at Critical/Error/Warning level,
# one formatted line each — the Windows analogue of the Linux journal tail.
_EVENTLOG_PS = (
    "$ErrorActionPreference='SilentlyContinue';"
    "Get-WinEvent -FilterHashtable @{LogName='System','Application'; Level=1,2,3} "
    "-MaxEvents 100 | ForEach-Object { '{0} {1} {2}: {3}' -f "
    "$_.TimeCreated.ToString('MMM dd HH:mm:ss'), $_.LevelDisplayName, "
    "$_.ProviderName, ($_.Message -replace '\\s+',' ') }"
)


def _parse_eventlog(stdout):
    """One trimmed line per event, capped like the server's journal store
    (≤100 lines, ≤512 bytes each). Pure — unit-testable off-Windows."""
    out = []
    for ln in (stdout or '').splitlines():
        s = ln.strip()
        if s:
            out.append(s[:512])
        if len(out) >= 100:
            break
    return out


def get_event_log_journal():
    """Recent Windows Event Log entries as journal lines, or []. Off-Windows []."""
    if not sys.platform.startswith('win'):
        return []
    try:
        r = subprocess.run(['powershell', '-NoProfile', '-NonInteractive',
                            '-Command', _EVENTLOG_PS],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return []
        return _parse_eventlog(r.stdout)
    except Exception:
        return []


# PowerShell: local users + whether each is in the Administrators group + when
# its password was last set. One pipe-separated line per user.
_LOCAL_USERS_PS = (
    "$ErrorActionPreference='SilentlyContinue';"
    "$admins=@(); try { $admins=@(Get-LocalGroupMember -Group 'Administrators' | "
    "ForEach-Object { ($_.Name -split '\\\\')[-1] }) } catch {};"
    "Get-LocalUser | ForEach-Object { "
    "$pls=0; if ($_.PasswordLastSet) { $pls=[int][double]::Parse((Get-Date $_.PasswordLastSet -UFormat %s)) };"
    "'{0}|{1}|{2}|{3}' -f $_.Name, [int][bool]$_.Enabled, $pls, [int]($admins -contains $_.Name) }"
)


def _parse_local_accounts(stdout, now):
    """Map Get-LocalUser output to the server's account-audit shape
    ({user, uid, shell, home, login, locked, sudo, age_days, flags}). Windows has
    no numeric uid (SIDs) → uid=-1; Administrators membership → sudo/'admin' flag.
    Pure — unit-testable off-Windows."""
    out = []
    for ln in (stdout or '').splitlines():
        parts = ln.strip().split('|')
        if len(parts) != 4 or not parts[0]:
            continue
        name, en, pls, adm = parts
        enabled = en.strip() == '1'
        is_admin = adm.strip() == '1'
        try:
            pls_i = int(pls)
        except ValueError:
            pls_i = 0
        age = int((now - pls_i) / 86400) if pls_i > 0 else None
        flags = []
        if is_admin:
            flags.append('admin')
        if not enabled:
            flags.append('disabled')
        out.append({'user': name[:64], 'uid': -1, 'shell': '', 'home': '',
                    'login': enabled, 'locked': not enabled, 'sudo': is_admin,
                    'age_days': age, 'flags': flags})
        if len(out) >= 200:
            break
    return out


def get_local_accounts():
    """Local Windows users → the server's account-audit card, or []. Off-Win []."""
    if not sys.platform.startswith('win'):
        return []
    try:
        r = subprocess.run(['powershell', '-NoProfile', '-NonInteractive',
                            '-Command', _LOCAL_USERS_PS],
                           capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return []
        return _parse_local_accounts(r.stdout, int(time.time()))
    except Exception:
        return []


def _audit_mode():
    """v4.10.0: observe-only (read-only) flag — an operator-owned file the server
    can't clear. When set, the agent refuses every command (parity with the Linux
    agent's /etc/remotepower/audit-mode). Lives in ProgramData\\RemotePower."""
    try:
        return os.path.exists(os.path.join(_data_dir(), 'audit-mode'))
    except Exception:
        return False


def collect_sysinfo():
    """Core metrics. Uses psutil when available; otherwise a best-effort subset
    so a host without psutil still reports OS/uptime/hostname."""
    info = {
        'platform': platform.platform(),
        'kernel':   platform.version(),       # Windows build string
        'hostname': socket.gethostname(),
        'audit_mode': _audit_mode(),          # v4.10.0: read-only agent flag
    }
    pkgs = windows_update_pending()
    if pkgs is not None:
        info['packages'] = pkgs                # Windows Update pending → Patches page
    lports = collect_listening_ports()
    if lports:
        info['listening_ports'] = lports       # → Exposure page + port audit
    try:
        cpu = platform.processor()
        if cpu:
            info['cpu'] = cpu
    except Exception:
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
        # disks / mounts
        mounts = []
        worst = 0.0
        total_gb = 0.0
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
        # network interfaces
        nets = []
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                ipv4 = next((a.address for a in addrs if a.family == socket.AF_INET), '')
                mac = next((a.address for a in addrs if getattr(a, 'family', None) == psutil.AF_LINK), '')
                if ipv4:
                    nets.append({'iface': iface, 'ip': ipv4, 'mac': mac})
        except Exception:
            pass
        if nets:
            info['network'] = nets[:20]
        # v3.14.0 #37: per-interface bandwidth (bytes/sec), diffed across polls.
        try:
            nio = _collect_net_io(psutil)
            if nio:
                info['network_io'] = nio
        except Exception:
            pass
    except ImportError:
        info['psutil'] = False  # honest signal that metrics are limited
    except Exception:
        pass
    return info


# v3.14.0 #37: net_io_counters are cumulative; diff against the previous poll
# (this agent is long-running) for a bytes/sec rate. Matches the Linux agent.
_prev_net_io = {}   # iface -> (bytes_sent, bytes_recv, monotonic_ts)

def _collect_net_io(psutil):
    out = []
    try:
        counters = psutil.net_io_counters(pernic=True)
    except Exception:
        return out
    now = time.monotonic()
    for iface, c in counters.items():
        if iface.lower().startswith(('loopback', 'isatap', 'teredo')):
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


# ─── command handling (Windows) ───────────────────────────────────────────────

def command_argv(cmd):
    """Map a server command string to a Windows argv list, or None if the
    command is handled elsewhere / unknown. Pure — unit-testable off-Windows."""
    if cmd == 'reboot':
        return ['shutdown', '/r', '/t', '30', '/c', 'RemotePower: scheduled reboot']
    if cmd == 'shutdown':
        return ['shutdown', '/s', '/t', '30', '/c', 'RemotePower: scheduled shutdown']
    if isinstance(cmd, str) and cmd.startswith('exec:'):
        body = cmd[len('exec:'):]
        # Run via PowerShell for parity with operators' expectations.
        return ['powershell', '-NoProfile', '-NonInteractive', '-Command', body]
    return None


def handle_command(cmd):
    """Execute a queued command; return a cmd_output dict to report back (or
    None for fire-and-forget / control commands)."""
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
    if cmd == 'uninstall':
        _uninstall()
        return None
    if cmd == 'update':
        # Minimal agent: signed self-update is a later phase; just acknowledge.
        return {'cmd': cmd, 'output': 'self-update not supported by the minimal agent yet', 'rc': 0}
    argv = command_argv(cmd)
    if argv is None:
        return {'cmd': cmd, 'output': f'unsupported command: {cmd}', 'rc': 1}
    try:
        is_exec = cmd.startswith('exec:')
        r = subprocess.run(argv, capture_output=True, text=True,
                           timeout=EXEC_TIMEOUT if is_exec else 30)
        out = ((r.stdout or '') + (r.stderr or '')).strip()[:MAX_OUTPUT]
        return {'cmd': cmd, 'output': out or '(no output)', 'rc': r.returncode}
    except subprocess.TimeoutExpired:
        return {'cmd': cmd, 'output': 'command timed out', 'rc': 124}
    except Exception as e:
        return {'cmd': cmd, 'output': f'error: {e}', 'rc': 1}


def _uninstall():
    """Best-effort: remove the scheduled task and creds. Idempotent."""
    try:
        subprocess.run(['schtasks', '/delete', '/tn', 'RemotePowerAgent', '/f'],
                       capture_output=True, timeout=30)
    except Exception:
        pass
    try:
        os.remove(_creds_path())
    except Exception:
        pass


# ─── server I/O ────────────────────────────────────────────────────────────--

def _post_json(url, payload, timeout=HTTP_TIMEOUT):
    # v4.4.0 (SECURITY): refuse non-HTTPS — otherwise the device token and all
    # command output travel in cleartext and a MITM can inject commands the
    # agent executes as SYSTEM. Mirrors the Linux agent's guard.
    if not url.startswith('https://'):
        raise ValueError(f"Server URL must use HTTPS, got: {url[:32]}")
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, method='POST',
                                 headers={'Content-Type': 'application/json',
                                          'User-Agent': f'RemotePower-Win/{VERSION}'})
    with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
        return json.loads(resp.read().decode('utf-8'))


# v3.14.0 #35: secrets-on-disk scanner (parity with the Linux agent). READ-ONLY
# + REDACTING — never sends a secret's value, only rule/location/masked-preview/
# sha256 fingerprint. Opt-in (server pushes secrets_scan_enabled); bounded hard.
SECRETS_SCAN_EVERY = 360
_secrets_cfg = {'on': False, 'paths': None}   # updated from each heartbeat response
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
                      '.cache', '.venv', 'venv', 'AppData', 'Windows', '$Recycle.Bin'}
_SECRETS_DEFAULT_PATHS = [r'C:\Users', r'C:\ProgramData', r'C:\inetpub']


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


def get_gpu_status():
    """v4.8.0 (#A3): NVIDIA GPU telemetry via nvidia-smi. Emits the SAME CSV the
    Linux agent parses into the SAME `gpus` schema, so the fleet GPU page renders
    Windows GPU boxes (ML / CAD / render rigs) with no server change. Empty list
    when nvidia-smi isn't on PATH (no driver / non-NVIDIA). NVIDIA is the common
    Windows GPU-telemetry tool; AMD/Intel live metrics aren't covered here.
    Runs only on the slow cadence (see build_heartbeat) — the 10s timeout keeps a
    hung driver query off the heartbeat hot path."""
    def _num(x):
        try:
            return round(float(x), 1)
        except (ValueError, TypeError):
            return None
    gpus = []
    try:
        r = subprocess.run(
            ['nvidia-smi',
             '--query-gpu=name,utilization.gpu,memory.used,memory.total,'
             'temperature.gpu,power.draw,fan.speed',
             '--format=csv,noheader,nounits'],
            capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return gpus
    if r.returncode != 0:
        return gpus
    for ln in r.stdout.splitlines():
        c = [x.strip() for x in ln.split(',')]
        if len(c) < 6:
            continue
        gpus.append({'vendor': 'nvidia', 'name': c[0][:96],
                     'util_pct': _num(c[1]), 'mem_used_mb': _num(c[2]),
                     'mem_total_mb': _num(c[3]), 'temp_c': _num(c[4]),
                     'power_w': _num(c[5]),
                     'fan_pct': _num(c[6]) if len(c) > 6 else None})
    return gpus


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
    # sysinfo on a slower cadence (every ~12 polls), like the Linux agent.
    if poll_count <= 1 or poll_count % 12 == 0:
        payload['sysinfo'] = collect_sysinfo()
        journal = get_event_log_journal()      # Event Log tail → Logs page
        if journal:
            payload['journal'] = journal
        accounts = get_local_accounts()        # local users → account audit card
        if accounts:
            payload['accounts'] = accounts
        gpus = get_gpu_status()                 # NVIDIA GPU telemetry → fleet GPU page
        if gpus:
            payload['gpus'] = gpus
    # v3.14.0 #35: opt-in secrets scan on its own ~6h cadence (config from the
    # previous heartbeat response, stashed in _secrets_cfg by heartbeat_once).
    if _secrets_cfg.get('on') and (poll_count <= 1 or poll_count % SECRETS_SCAN_EVERY == 0):
        try:
            payload['secret_findings'] = collect_secret_findings(_secrets_cfg.get('paths'))
        except Exception:
            pass
    if pending_output:
        payload['cmd_output'] = pending_output
        payload['executed_command'] = pending_output.get('cmd', '')
    return payload


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
    save_creds({'server_url': server,
                'device_id': resp['device_id'],
                'token': resp['token'],
                'poll_interval': DEFAULT_POLL})
    return resp


def heartbeat_once(creds, poll_count, pending_output=None):
    """One heartbeat round-trip. Returns (response, new_pending_output)."""
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
        if cmd:
            new_pending = handle_command(cmd)
        # v3.14.0 #35: stash secrets-scan opt-in + paths for the next heartbeat.
        _secrets_cfg['on'] = bool(resp.get('secrets_scan_enabled'))
        _ssp = resp.get('secrets_scan_paths')
        _secrets_cfg['paths'] = _ssp if isinstance(_ssp, list) and _ssp else None
    return resp, new_pending


def run():
    poll_count = 0
    pending = None
    while True:
        creds = load_creds()
        if not creds.get('device_id'):
            sys.stderr.write('[remotepower] not enrolled — run with --enroll first\n')
            return 1
        poll_count += 1
        try:
            _resp, pending = heartbeat_once(creds, poll_count, pending)
        except Exception as e:
            sys.stderr.write(f'[remotepower] heartbeat error: {e}\n')
        time.sleep(max(10, int(load_creds().get('poll_interval', DEFAULT_POLL))))


def main(argv=None):
    ap = argparse.ArgumentParser(description='RemotePower minimal Windows agent')
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
        r = enroll(a.server, pin=a.pin, token=a.token, name=a.name)
        print(f'enrolled: device_id={r["device_id"]}')
        return 0
    if a.once:
        creds = load_creds()
        resp, _ = heartbeat_once(creds, 1)
        print(json.dumps(resp, indent=2))
        return 0
    if a.run:
        return run() or 0
    ap.print_help()
    return 0


if __name__ == '__main__':
    sys.exit(main())

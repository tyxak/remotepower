#!/usr/bin/env python3
"""
RemotePower minimal macOS agent (v3.14.0, #50).

Speaks the same enroll / heartbeat / command-queue contract as the Linux and
Windows agents, so a Mac shows up in the fleet with metrics, runs queued
commands, and participates in the opt-in secrets scan — without a separate
server-side code path. Stdlib only; `psutil` is used when present for richer
metrics and gracefully skipped otherwise.

Usage:
    remotepower-agent-mac --enroll --server https://rp.example --pin 123456
    remotepower-agent-mac --run        # heartbeat loop (run under launchd)
    remotepower-agent-mac --once       # one heartbeat, print the response
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

VERSION = '6.1.3'
DEFAULT_POLL = 60
HTTP_TIMEOUT = 20
EXEC_TIMEOUT = 300

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

# No-redirect opener (parity with the Linux agent): a 3xx must never replay the
# token-bearing POST body to a redirect host or downgrade https→http in cleartext.
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None

_OPENER = urllib.request.build_opener(_NoRedirect,
                                      urllib.request.HTTPSHandler(context=_SSL_CTX))


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
        sys.stderr.write(f'[remotepower] could not save credentials: {e}\n')


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
    exposure buckets so macOS listeners render like Linux/Windows ones. Pure."""
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
    return info


def _mac_uptime():
    bt = _sysctl('kern.boottime')          # '{ sec = 1700000000, usec = 0 } ...'
    m = re.search(r'sec = (\d+)', bt)
    if m:
        return _fmt_uptime(int(time.time()) - int(m.group(1)))
    return ''


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
SECRETS_SCAN_EVERY = 360
_secrets_cfg = {'on': False, 'paths': None}
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
        return {'cmd': cmd, 'output': 'self-update not supported by the minimal agent yet', 'rc': 0}
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
    with _OPENER.open(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode('utf-8'))


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
    if poll_count <= 1 or poll_count % 12 == 0:
        payload['sysinfo'] = collect_sysinfo()
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
        if cmd:
            new_pending = handle_command(cmd)
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
        r = enroll(a.server, pin=a.pin, token=a.token, name=a.name)
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

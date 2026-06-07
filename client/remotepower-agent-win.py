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
import socket
import subprocess
import sys
import time
import urllib.request

VERSION = '3.14.0'
DEFAULT_POLL = 60
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
    tmp = _creds_path() + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(creds, f)
    os.replace(tmp, _creds_path())


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


def collect_sysinfo():
    """Core metrics. Uses psutil when available; otherwise a best-effort subset
    so a host without psutil still reports OS/uptime/hostname."""
    info = {
        'platform': platform.platform(),
        'kernel':   platform.version(),       # Windows build string
        'hostname': socket.gethostname(),
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
        info['cpu_percent'] = round(psutil.cpu_percent(interval=0.3), 1)
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
    except ImportError:
        info['psutil'] = False  # honest signal that metrics are limited
    except Exception:
        pass
    return info


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
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, method='POST',
                                 headers={'Content-Type': 'application/json',
                                          'User-Agent': f'RemotePower-Win/{VERSION}'})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
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
    # sysinfo on a slower cadence (every ~12 polls), like the Linux agent.
    if poll_count <= 1 or poll_count % 12 == 0:
        payload['sysinfo'] = collect_sysinfo()
        journal = get_event_log_journal()      # Event Log tail → Logs page
        if journal:
            payload['journal'] = journal
        accounts = get_local_accounts()        # local users → account audit card
        if accounts:
            payload['accounts'] = accounts
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

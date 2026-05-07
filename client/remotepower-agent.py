#!/usr/bin/env python3
"""
remotepower-agent.py  -  Windows client daemon for RemotePower v1.8.6
Polls the RemotePower server at a configurable interval (default 60s).
On first run (or if not enrolled), prompts for server URL + PIN and registers.

Config dir  : %ProgramData%\\RemotePower\\
Credentials : %ProgramData%\\RemotePower\\credentials.json  (SYSTEM only)
Log file    : %ProgramData%\\RemotePower\\agent.log

Run as a Windows Service via NSSM, or interactively for testing.
"""

import os
import sys
import json
import time
import socket
import subprocess
import platform
import argparse
import logging
import hashlib
import shutil
import stat
import tempfile
import ctypes
import winreg
from pathlib import Path
from urllib import request, error

CONF_DIR     = Path(os.environ.get('PROGRAMDATA', 'C:\\ProgramData')) / 'RemotePower'
CREDS_FILE   = CONF_DIR / 'credentials.json'
LOG_FILE     = CONF_DIR / 'agent.log'
VERSION      = '1.12.1'
AGENT_SCRIPT = Path(sys.argv[0]).resolve()

POLL_INTERVAL      = 60
SYSINFO_EVERY      = 10
PATCH_EVERY        = 180
UPDATE_CHECK_EVERY = 60

# Metrics collection requires psutil (optional)
try:
    import psutil as _psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False

# ---- Logging setup --------------------------------------------------------
CONF_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(str(LOG_FILE), encoding='utf-8'),
    ]
)
log = logging.getLogger('remotepower')

import ssl as _ssl

# ---- SSL context -----------------------------------------------------------
def _make_ssl_context():
    ctx = _ssl.create_default_context()
    ctx.verify_mode = _ssl.CERT_REQUIRED
    ctx.check_hostname = True
    return ctx

_SSL_CTX = _make_ssl_context()

# ---- HTTP helpers ----------------------------------------------------------
def http_post(url, data, timeout=10):
    if not url.startswith('https://'):
        raise ValueError(f"Server URL must use HTTPS, got: {url[:32]}")
    body = json.dumps(data).encode()
    req = request.Request(url, data=body,
        headers={'Content-Type': 'application/json',
                 'User-Agent': f'RemotePower-Agent/{VERSION} (Windows)'})
    with request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
        return json.loads(resp.read(1024 * 1024))

def http_get(url, timeout=10):
    if not url.startswith('https://'):
        raise ValueError(f"Server URL must use HTTPS, got: {url[:32]}")
    req = request.Request(url, headers={'User-Agent': f'RemotePower-Agent/{VERSION} (Windows)'})
    with request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
        return json.loads(resp.read(1024 * 1024))

def http_get_binary(url, timeout=30):
    if not url.startswith('https://'):
        raise ValueError(f"Server URL must use HTTPS, got: {url[:32]}")
    req = request.Request(url, headers={'User-Agent': f'RemotePower-Agent/{VERSION} (Windows)'})
    with request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
        return resp.read(64 * 1024 * 1024)

# ---- Credentials ----------------------------------------------------------
def load_credentials():
    if not CREDS_FILE.exists():
        return None
    try:
        data = json.loads(CREDS_FILE.read_text(encoding='utf-8'))
        if data.get('device_id') and data.get('token') and data.get('server_url'):
            return data
    except Exception:
        pass
    return None

def save_credentials(creds):
    CONF_DIR.mkdir(parents=True, exist_ok=True)
    CREDS_FILE.write_text(json.dumps(creds, indent=2), encoding='utf-8')
    log.info(f"Credentials saved to {CREDS_FILE}")

# ---- System info (Windows) ------------------------------------------------
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]; s.close(); return ip
    except Exception:
        return '127.0.0.1'

def get_os_info():
    """Return a human-readable OS string like 'Windows 11 Pro 10.0.22631'."""
    try:
        ver = platform.version()
        edition = platform.win32_edition() if hasattr(platform, 'win32_edition') else ''
        # Detect Windows 11 vs 10 by build number
        build = int(ver.split('.')[-1]) if ver else 0
        name = 'Windows 11' if build >= 22000 else 'Windows 10'
        return f"{name} {edition} {ver}".strip()
    except Exception:
        return platform.platform()

def get_mac():
    """Return MAC of the primary adapter."""
    try:
        import uuid
        mac_int = uuid.getnode()
        mac_str = ':'.join(f'{(mac_int >> (8 * (5 - i))) & 0xFF:02x}' for i in range(6))
        return mac_str
    except Exception:
        return ''

def get_network_info():
    """Return list of network interfaces with IP and MAC."""
    interfaces = []
    if _PSUTIL:
        try:
            addrs = _psutil.net_if_addrs()
            for name, snics in addrs.items():
                if name.lower() == 'loopback pseudo-interface 1':
                    continue
                ip = ''
                mac = ''
                for snic in snics:
                    if snic.family == socket.AF_INET:
                        ip = snic.address
                    # psutil.AF_LINK = -1 on Windows, or use family 17
                    if snic.family == _psutil.AF_LINK:
                        mac = snic.address
                if ip and ip != '127.0.0.1':
                    interfaces.append({'iface': name[:32], 'ip': ip, 'mac': mac})
        except Exception:
            pass
    if not interfaces:
        interfaces.append({'iface': 'primary', 'ip': get_local_ip(), 'mac': get_mac()})
    return interfaces

def get_uptime():
    """Return uptime string."""
    if _PSUTIL:
        try:
            boot = _psutil.boot_time()
            elapsed = int(time.time() - boot)
            days, rem = divmod(elapsed, 86400)
            hours, rem = divmod(rem, 3600)
            mins = rem // 60
            parts = []
            if days: parts.append(f"{days} day{'s' if days != 1 else ''}")
            if hours: parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
            if mins: parts.append(f"{mins} minute{'s' if mins != 1 else ''}")
            return 'up ' + ', '.join(parts) if parts else 'up < 1 minute'
        except Exception:
            pass
    # Fallback: use systeminfo or net statistics
    try:
        out = subprocess.check_output(
            ['net', 'statistics', 'workstation'],
            text=True, timeout=10, stderr=subprocess.DEVNULL, encoding='utf-8', errors='replace')
        for line in out.splitlines():
            if 'Statistics since' in line or 'Statistik seit' in line:
                return 'up since ' + line.split('since')[-1].strip() if 'since' in line.lower() else line.strip()
    except Exception:
        pass
    return ''

def get_journal(lines=100):
    """Return recent Windows Event Log entries (System log)."""
    try:
        # Use wevtutil to get recent System events
        out = subprocess.check_output(
            ['wevtutil', 'qe', 'System', '/c:' + str(lines), '/f:text', '/rd:true'],
            text=True, timeout=15, stderr=subprocess.DEVNULL, encoding='utf-8', errors='replace')
        result = []
        for line in out.splitlines():
            line = line.strip()
            if line and not line.startswith('Event['):
                result.append(line[:512])
        return result[-lines:]
    except Exception:
        return []

def get_patch_info():
    """Check for pending Windows updates via COM (if available) or return unknown."""
    result = {'manager': 'windows_update', 'upgradable': None}
    try:
        # Try PowerShell approach - more reliable than COM
        ps_cmd = (
            "try {"
            "  $sess = New-Object -ComObject Microsoft.Update.Session;"
            "  $search = $sess.CreateUpdateSearcher();"
            "  $res = $search.Search('IsInstalled=0');"
            "  Write-Output $res.Updates.Count"
            "} catch { Write-Output '-1' }"
        )
        out = subprocess.check_output(
            ['powershell', '-NoProfile', '-NonInteractive', '-Command', ps_cmd],
            text=True, timeout=120, stderr=subprocess.DEVNULL, encoding='utf-8', errors='replace')
        count = int(out.strip())
        if count >= 0:
            result['upgradable'] = count
    except Exception:
        pass
    return result

def get_metrics():
    """Collect CPU/RAM/disk percentages via psutil (optional)."""
    if not _PSUTIL:
        return {}
    try:
        cpu  = _psutil.cpu_percent(interval=0.5)
        mem  = _psutil.virtual_memory().percent
        disk = _psutil.disk_usage('C:\\').percent
        return {'cpu_percent': cpu, 'mem_percent': mem, 'disk_percent': disk}
    except Exception:
        return {}

def get_agent_integrity(server_url):
    """Compare own SHA-256 against server's known-good hash."""
    try:
        info = http_get(f"{server_url}/api/agent/version", timeout=10)
        expected = info.get('sha256_windows') or info.get('sha256')
        if not expected:
            return True, 'no server hash available'
        actual = hashlib.sha256(AGENT_SCRIPT.read_bytes()).hexdigest()
        if hmac_compare(actual.lower(), expected.lower()):
            return True, 'ok'
        return False, f'MISMATCH: local={actual[:12]}... server={expected[:12]}...'
    except Exception as e:
        return True, f'check skipped: {e}'

def hmac_compare(a, b):
    import hmac as _hmac
    return _hmac.compare_digest(a, b)

# ---- Self-update -----------------------------------------------------------
def check_for_update(server_url):
    try:
        info = http_get(f"{server_url}/api/agent/version", timeout=10)
    except Exception as e:
        log.debug(f"Update check failed: {e}"); return False
    remote_version = info.get('version'); remote_sha256 = info.get('sha256')
    if not remote_version or not remote_sha256: return False
    if remote_version == VERSION: return False
    def vt(v):
        try: return tuple(int(x) for x in v.split('.'))
        except: return (0,)
    if vt(remote_version) <= vt(VERSION): return False
    log.info(f"Update available: {VERSION} -> {remote_version} (manual update recommended on Windows)")
    return False  # Windows agent doesn't self-update automatically - log it instead

# ---- Command execution -----------------------------------------------------
def execute_command(cmd):
    if cmd == 'shutdown':
        log.info("Executing: shutdown")
        try:
            _write_last_cmd('shutdown')
            subprocess.run(['shutdown', '/s', '/t', '30', '/c', 'RemotePower: shutdown requested'], check=True)
        except Exception as e:
            log.error(f"Shutdown failed: {e}")
    elif cmd == 'reboot':
        log.info("Executing: reboot")
        try:
            _write_last_cmd('reboot')
            subprocess.run(['shutdown', '/r', '/t', '30', '/c', 'RemotePower: reboot requested'], check=True)
        except Exception as e:
            log.error(f"Reboot failed: {e}")
    elif cmd == 'update':
        log.info("Agent self-update not supported on Windows - update manually")
    elif cmd.startswith('poll_interval:'):
        try:
            new_interval = int(cmd.split(':', 1)[1])
            new_interval = max(10, min(3600, new_interval))
            log.info(f"Poll interval changed to {new_interval}s")
            poll_interval_file = CONF_DIR / 'poll_interval.txt'
            poll_interval_file.write_text(str(new_interval), encoding='utf-8')
        except Exception as e:
            log.warning(f"Failed to set poll interval: {e}")
    elif cmd.startswith('exec:'):
        shell_cmd = cmd[5:]
        log.info(f"Executing custom command: {shell_cmd!r}")
        try:
            exec_timeout = 300
            # Use cmd.exe for Windows commands
            result = subprocess.run(
                shell_cmd, shell=True, capture_output=True, text=True,
                timeout=exec_timeout, encoding='utf-8', errors='replace')
            output = (result.stdout + result.stderr).strip()
            log.info(f"Command output (rc={result.returncode}): {output[:200]}")
            return {'cmd': shell_cmd, 'output': output[:4096], 'rc': result.returncode}
        except subprocess.TimeoutExpired:
            log.warning(f"Command timed out: {shell_cmd!r}")
            return {'cmd': shell_cmd, 'output': 'TIMEOUT', 'rc': -1}
        except Exception as e:
            log.error(f"Command failed: {e}")
            return {'cmd': shell_cmd, 'output': str(e), 'rc': -1}
    else:
        log.warning(f"Unknown command: {cmd!r}")
    return None

def _write_last_cmd(cmd):
    try:
        (CONF_DIR / 'last_cmd.txt').write_text(cmd, encoding='utf-8')
    except Exception:
        pass

# ---- Enrollment ------------------------------------------------------------
def enroll_interactive(re_enroll=False):
    print()
    print("+--------------------------------------------+")
    print("|     RemotePower Client Setup (Windows)      |")
    print("+--------------------------------------------+")
    print()
    server_url = input("RemotePower server URL (e.g. https://remote.example.com): ").strip().rstrip('/')
    if not server_url.startswith('https://'):
        print("!  Only HTTPS is supported. Prepending https://")
        server_url = 'https://' + server_url.lstrip('http://').lstrip('https://')
    pin = input("Enrollment PIN (shown in web dashboard): ").strip()
    device_name = input(f"Device display name [{socket.gethostname()}]: ").strip()
    if not device_name: device_name = socket.gethostname()
    print(); print("Enrolling device...")
    payload = {
        'pin': pin, 'hostname': socket.gethostname(), 'name': device_name,
        'os': get_os_info(), 'ip': get_local_ip(), 'mac': get_mac(), 'version': VERSION,
    }
    if re_enroll:
        creds = load_credentials()
        if creds and creds.get('device_id') and creds.get('token'):
            payload['device_id'] = creds['device_id']
            payload['token']     = creds['token']
            print(f"  Re-enrolling device ID: {creds['device_id']} (history + tags preserved)")
    try:
        resp = http_post(f"{server_url}/api/enroll/register", payload)
        if resp.get('ok'):
            creds = {'server_url': server_url, 'device_id': resp['device_id'],
                     'token': resp['token'], 'name': device_name}
            save_credentials(creds)
            if resp.get('reregistered'):
                print(f"  OK - Re-enrolled! Device ID unchanged: {resp['device_id']}")
            else:
                print(f"  OK - Enrolled! Device ID: {resp['device_id']}")
            print(f"  Credentials saved to {CREDS_FILE}")
            return creds
        else:
            print(f"  FAIL - Enrollment failed: {resp.get('error', 'Unknown error')}"); sys.exit(1)
    except Exception as e:
        print(f"  ERROR - Error contacting server: {e}"); sys.exit(1)

# ---- Heartbeat loop -------------------------------------------------------
def heartbeat(creds, interval=POLL_INTERVAL):
    server = creds['server_url']; dev_id = creds['device_id']; token = creds['token']
    log.info(f"RemotePower agent v{VERSION} (Windows) starting. Server: {server}, Device: {dev_id}")
    log.info(f"Poll: {interval}s | sysinfo every {SYSINFO_EVERY} polls | patches every {PATCH_EVERY} polls")

    poll_count = 0; cached_patch = None

    # Boot reason detection
    last_cmd_file = CONF_DIR / 'last_cmd.txt'
    boot_reason = None
    if last_cmd_file.exists():
        try:
            boot_reason = last_cmd_file.read_text(encoding='utf-8').strip()[:64]
            last_cmd_file.unlink()
        except Exception:
            pass

    interval_override_file = CONF_DIR / 'poll_interval.txt'

    while True:
        poll_count += 1

        # Check for dynamically updated interval
        if interval_override_file.exists():
            try:
                new_interval = int(interval_override_file.read_text(encoding='utf-8').strip())
                if new_interval != interval:
                    log.info(f"Poll interval updated: {interval}s -> {new_interval}s")
                    interval = new_interval
                interval_override_file.unlink()
            except Exception:
                pass

        payload = {'device_id': dev_id, 'token': token, 'ip': get_local_ip(),
                   'os': get_os_info(), 'version': VERSION}
        if poll_count == 1 and boot_reason:
            payload['boot_reason'] = boot_reason

        send_sysinfo = (poll_count == 1 or poll_count % SYSINFO_EVERY == 0)
        run_patch    = (poll_count % PATCH_EVERY == 0)

        if run_patch:
            log.debug(f"Poll {poll_count}: running patch check")
            cached_patch = get_patch_info(); send_sysinfo = True

        if send_sysinfo:
            sysinfo = {
                'uptime':   get_uptime(),
                'platform': platform.platform(),
                'packages': cached_patch,
                'network':  get_network_info(),
            }
            sysinfo.update(get_metrics())
            payload['sysinfo'] = sysinfo
            payload['journal'] = get_journal(100)
            log.debug(f"Poll {poll_count}: sending sysinfo + journal")

        try:
            resp = http_post(f"{server}/api/heartbeat", payload)
            cmd = resp.get('command')
            if cmd:
                log.info(f"Received command: {cmd}")
                result = execute_command(cmd)
                # v1.11.7: send a follow-up heartbeat carrying the
                # output. See remotepower-agent for the full reasoning.
                if result is not None:
                    follow_up = {
                        'device_id': dev_id, 'token': token,
                        'ip': get_local_ip(), 'os': get_os_info(),
                        'version': VERSION,
                        'cmd_output': result,
                        'executed_command': cmd,
                    }
                    try:
                        http_post(f"{server}/api/heartbeat", follow_up)
                    except Exception as e:
                        log.warning(f"Follow-up heartbeat failed: {e}")

        except error.HTTPError as e:
            if e.code == 403:
                log.error("Credentials rejected - re-enroll: python remotepower-agent.py enroll")
            else:
                log.warning(f"HTTP {e.code}")
        except Exception as e:
            log.warning(f"Heartbeat failed: {e}")

        if poll_count % UPDATE_CHECK_EVERY == 0:
            try:
                check_for_update(server)
            except Exception as e:
                log.debug(f"Update check error: {e}")

        time.sleep(interval)

# ---- Entry point -----------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description='RemotePower Windows agent')
    parser.add_argument('action', nargs='?', default='run',
        choices=['run', 'enroll', 're-enroll', 'status', 'integrity'],
        help='run | enroll | re-enroll | status | integrity')
    parser.add_argument('--interval', type=int, default=POLL_INTERVAL,
        help=f'Poll interval in seconds (default: {POLL_INTERVAL})')
    args = parser.parse_args()

    # Check for admin rights
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        is_admin = False

    if not is_admin:
        print("Warning: running without admin privileges. Shutdown/reboot may fail.")
        print("Run as Administrator or install as a Windows Service.")
        print()

    if args.action == 'enroll':
        enroll_interactive(re_enroll=False); return

    if args.action == 're-enroll':
        enroll_interactive(re_enroll=True); return

    if args.action == 'status':
        creds = load_credentials()
        if creds:
            print(f"Enrolled : Yes")
            print(f"Server   : {creds['server_url']}")
            print(f"Device   : {creds['name']} ({creds['device_id']})")
            print(f"Version  : {VERSION}")
            print(f"Platform : Windows")
            for n in get_network_info():
                print(f"Network  : {n['iface']}  {n['ip']}  {n['mac']}")
        else:
            print("Not enrolled. Run: python remotepower-agent.py enroll")
        return

    if args.action == 'integrity':
        creds = load_credentials()
        if not creds: print("Not enrolled."); sys.exit(1)
        ok, detail = get_agent_integrity(creds['server_url'])
        status = "OK" if ok else "MISMATCH"
        print(f"Agent integrity: {status} - {detail}")
        sys.exit(0 if ok else 1)

    creds = load_credentials()
    if not creds:
        print("Not enrolled. Starting enrollment wizard...")
        creds = enroll_interactive()

    heartbeat(creds, interval=args.interval)

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
v3.14.0 (#48): agentless SSH — run a command and collect a basic sysinfo
snapshot on a host that has NO RemotePower agent, over SSH. Lets Linux/BSD/macOS
boxes you can't (or won't) install an agent on still appear in the fleet with
metrics and accept the occasional command.

No paramiko is available, so this shells out to the system `ssh` with a private
key written to a 0600 temp file for the duration of the call. Security posture:
- BatchMode=yes (never prompts; fails fast if the key is rejected),
- StrictHostKeyChecking=accept-new (trust-on-first-use; a changed host key
  aborts),
- a hard command timeout.
api.py gates *who* may call this (admin + per-device opt-in + the command
allowlist + audit); this module is the transport.

The argv builder and the sysinfo parser are pure so the test suite drives them
without a real host (the runner is injectable).
"""
import json
import os
import shlex
import subprocess
import tempfile


# One remote snippet that prints a JSON sysinfo blob — portable across Linux and
# macOS/BSD (falls back gracefully when a tool is missing).
SYSINFO_SCRIPT = r'''
os=$(uname -sr 2>/dev/null)
host=$(hostname 2>/dev/null)
up=$(uptime 2>/dev/null | sed 's/.*up //' | sed 's/,.*load.*//')
mem=$( (free 2>/dev/null | awk '/Mem:/{printf "%.0f", $3/$2*100}') || echo "")
disk=$(df -P / 2>/dev/null | awk 'NR==2{gsub("%","",$5); print $5}')
load=$(uptime 2>/dev/null | sed 's/.*load average[s]*: //' | awk -F, '{print $1}' | tr -d ' ')
printf '{"os":"%s","hostname":"%s","uptime":"%s","mem_percent":"%s","disk_percent":"%s","loadavg_1m":"%s"}\n' \
  "$os" "$host" "$up" "$mem" "$disk" "$load"
'''.strip()


def build_ssh_argv(host, user, port, key_path, command, connect_timeout=10):
    """Build the ssh argv for a single non-interactive command. Pure."""
    return [
        'ssh',
        '-i', key_path,
        '-p', str(int(port or 22)),
        '-o', 'BatchMode=yes',
        '-o', 'StrictHostKeyChecking=accept-new',
        '-o', f'ConnectTimeout={int(connect_timeout)}',
        '-o', 'NumberOfPasswordPrompts=0',
        f'{user}@{host}',
        command,
    ]


def run(host, user, command, key_pem, port=22, timeout=30, runner=None):
    """Run one command over SSH. `key_pem` is the private key text. Returns
    {ok, rc, output}. `runner` is injected by tests (defaults to subprocess.run);
    it receives (argv, timeout) and returns an object with .returncode/.stdout/
    .stderr. The key is written to a 0600 temp file and removed afterwards."""
    if not (host and user and key_pem):
        return {'ok': False, 'rc': -1, 'output': 'missing host, user, or key'}
    fd, key_path = tempfile.mkstemp(prefix='rp-ssh-')
    try:
        os.write(fd, key_pem.encode('utf-8') if isinstance(key_pem, str) else key_pem)
        os.close(fd)
        os.chmod(key_path, 0o600)
        argv = build_ssh_argv(host, user, port, key_path, command)
        _run = runner or (lambda a, timeout=timeout: subprocess.run(
            a, capture_output=True, text=True, timeout=timeout))
        try:
            r = _run(argv, timeout=timeout)
        except subprocess.TimeoutExpired:
            return {'ok': False, 'rc': 124, 'output': 'ssh command timed out'}
        out = ((r.stdout or '') + (r.stderr or '')).strip()
        rc = r.returncode
        return {'ok': rc == 0, 'rc': rc, 'output': out[:32768]}
    except Exception as e:
        return {'ok': False, 'rc': -1, 'output': f'ssh error: {e}'}
    finally:
        try:
            os.unlink(key_path)
        except OSError:
            pass


def parse_sysinfo(output):
    """Parse the JSON blob from SYSINFO_SCRIPT into a sysinfo-shaped dict (the
    numeric fields coerced to numbers where present). Tolerant of junk lines
    before/after the JSON (motd banners etc.)."""
    info = {}
    raw = None
    for line in (output or '').splitlines():
        line = line.strip()
        if line.startswith('{') and line.endswith('}'):
            raw = line
    if not raw:
        return info
    try:
        d = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return info
    if d.get('os'):
        info['platform'] = str(d['os'])[:256]
    if d.get('hostname'):
        info['hostname'] = str(d['hostname'])[:128]
    if d.get('uptime'):
        info['uptime'] = str(d['uptime'])[:64]
    for k in ('mem_percent', 'disk_percent', 'loadavg_1m'):
        v = d.get(k)
        try:
            if v not in (None, ''):
                info[k] = round(float(v), 2)
        except (TypeError, ValueError):
            pass
    return info

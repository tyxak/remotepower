#!/usr/bin/env python3
"""RemotePower — Windows agent.

A standalone agent that speaks the same server contract as the Linux agent
(client/remotepower-agent.py). As of v6.2.0 it covers the core management surface
at parity with Linux:

  * enroll (PIN or enrollment token); heartbeat loop with core sysinfo
    (CPU / memory / disk / uptime / network)
  * commands: reboot / shutdown / exec (PowerShell) / explicit ps: + cmd: /
    upgrade + winget / svc: (service control) / kill: (process) /
    files: (file manager) / poll-interval / uninstall / signed self-update
  * posture: Windows Update + winget (→ Patches, with remediation), Defender AV,
    listening ports (→ Exposure), Event Log incl. the Security channel with a
    RecordId cursor + Event IDs (→ Logs/journal + log_watch rules), watched
    services (→ Services page), top processes + proc_names (→ process checks),
    local users + privileged-group tripwire, reboot-required detection

As of the v6.2.0 second wave it also reports SMART disk health, hardware inventory
(WMI), config drift (file hashing), containers (docker CLI), a Windows security-
posture set for the Checks catalog (BitLocker / firewall / Defender / WU service),
and evaluates agent-side custom checks incl. a `windows_service` type.

Still Linux-only, and honestly so: OpenSCAP (`oscap` is a Linux tool with Linux
SCAP content — the server-side CIS baseline is the cross-platform path). Kept as a
separate file from the Linux agent so it can't destabilise it; converging over time.

Stdlib only (urllib/json/socket/subprocess/platform/hashlib/winreg/logging).
`psutil` is used for richer metrics + the process list when present, but the
agent runs without it.

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
import urllib.error

VERSION = '6.2.2'
DEFAULT_POLL = 60


# ── SECURITY: resolve system binaries by ABSOLUTE PATH, never bare name ────────
#
# The agent runs as SYSTEM. Invoking `powershell`/`winget`/`shutdown`/… by bare
# name resolves them through %PATH%, and any directory on SYSTEM's PATH that a
# lower-privileged user can write to becomes a privilege-escalation vector: drop
# a `powershell.exe` there and the agent runs it as SYSTEM. So every fixed system
# tool is pinned to its real location under %SystemRoot% (or the known winget
# shim), and we refuse to fall back to a bare name — a missing tool is a clear
# "not found", never a PATH lookup.
_SYSTEM_ROOT = os.environ.get('SystemRoot', r'C:\Windows')
_SYS32 = os.path.join(_SYSTEM_ROOT, 'System32')
_POWERSHELL = os.path.join(
    _SYS32, 'WindowsPowerShell', 'v1.0', 'powershell.exe')


def _system_bin(name):
    """Absolute path to a System32 tool (shutdown/icacls/schtasks/where/…).

    Falls back to the bare name ONLY if the resolved path is absent, so a test
    box or an unusual layout still works — but on a normal Windows install the
    absolute path always wins, closing the writable-PATH hijack.
    """
    p = os.path.join(_SYS32, name if name.lower().endswith('.exe') else name + '.exe')
    return p if os.path.exists(p) else name


def _powershell_bin():
    """Absolute powershell.exe, or the bare name if the canonical path is gone."""
    return _POWERSHELL if os.path.exists(_POWERSHELL) else 'powershell'


def _winget_bin():
    """Resolve winget.exe absolutely. Unlike the System32 tools winget lives in a
    per-user/WindowsApps shim whose path isn't fixed, so ask the OS via the
    absolute `where.exe` (never bare `where`, same hijack reason) and cache it."""
    global _WINGET_PATH
    if _WINGET_PATH is not None:
        return _WINGET_PATH
    resolved = 'winget'
    try:
        r = subprocess.run([_system_bin('where'), 'winget'],
                           capture_output=True, text=True, timeout=10,
                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        for line in (r.stdout or '').splitlines():
            cand = line.strip()
            if cand and os.path.exists(cand):
                resolved = cand
                break
    except Exception:
        pass
    _WINGET_PATH = resolved
    return resolved


_WINGET_PATH = None

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

# No-redirect opener (parity with the Linux agent): a 3xx must never replay the
# token-bearing POST body to a redirect host or downgrade https→http in cleartext.
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None

_OPENER = urllib.request.build_opener(_NoRedirect,
                                      urllib.request.HTTPSHandler(context=_SSL_CTX))
EXEC_TIMEOUT = 300
MAX_OUTPUT = 32 * 1024


# ── v6.2.0: a real logger (the agent had NONE — collectors swallowed every
# exception silently, so a broken collector was indistinguishable from a host
# that simply has nothing to report). Rotating file in ProgramData\RemotePower
# plus stderr, so the scheduled task's failures are diagnosable after the fact.
import logging as _logging
from logging.handlers import RotatingFileHandler as _RotatingFileHandler

log = _logging.getLogger('remotepower-win')


def _init_logging():
    if log.handlers:
        return
    log.setLevel(_logging.INFO)
    fmt = _logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    try:
        d = _data_dir()
        os.makedirs(d, exist_ok=True)
        fh = _RotatingFileHandler(os.path.join(d, 'agent.log'),
                                  maxBytes=1_000_000, backupCount=3, encoding='utf-8')
        fh.setFormatter(fmt)
        log.addHandler(fh)
    except Exception:
        pass   # a file handler must never stop the agent from running
    sh = _logging.StreamHandler(sys.stderr)
    sh.setFormatter(fmt)
    log.addHandler(sh)


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
    #
    # v6.2.0 (BUG): two things made this lock the file out of even SYSTEM — the
    # account the agent's own service runs as — so `--run` read no creds and
    # logged "not enrolled" forever:
    #   1. `(OI)(CI)` are DIRECTORY-only inheritance flags. icacls REJECTS them on
    #      a file ("The parameter is incorrect"), so the file's /grant failed and,
    #      after /inheritance:r had already stripped inherited access, the file was
    #      readable by nobody. Files get plain `F`, only directories get (OI)(CI)F.
    #   2. Localized account NAMES ("SYSTEM"/"Administrators") don't resolve on a
    #      non-English Windows, failing the grant the same way. Use locale-proof
    #      SIDs: S-1-5-18 = LocalSystem, S-1-5-32-544 = BUILTIN\Administrators.
    def _harden_acl(path, is_dir):
        perm = '(OI)(CI)F' if is_dir else 'F'
        try:
            subprocess.run(
                [_system_bin('icacls'), path, '/inheritance:r',
                 '/grant:r', f'*S-1-5-18:{perm}',
                 '/grant:r', f'*S-1-5-32-544:{perm}'],
                capture_output=True, timeout=15,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        except Exception:
            pass

    # v4.8.0 (SECURITY): lock the data dir down BEFORE the first token write so
    # the creds file inherits the restricted ACL from creation — closes the
    # window where the freshly-written token briefly carried Users-readable ACLs.
    _harden_acl(d, is_dir=True)
    tmp = _creds_path() + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(creds, f)
    os.replace(tmp, _creds_path())
    _harden_acl(_creds_path(), is_dir=False)


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


# ── v6.2.0: signed self-update (parity with the Linux agent's fail-closed gate) ─
#
# The Windows agent is a .py script, so "swap the binary" = replace this file and
# re-launch the scheduled task. The trust model is IDENTICAL to Linux:
#   * trigger on sha256 drift (a re-build of the same version legitimately differs)
#   * verify the downloaded bytes against the server's advertised sha256
#   * if a release public key is pinned (release.pub in ProgramData\RemotePower),
#     REQUIRE a valid detached signature before installing — defends against a
#     compromised server that dictates both the binary and its advertised hash
#   * a `require-signed-updates` marker makes the signed path mandatory (refuse
#     to install anything unsigned), closing the default fail-open window
# Replaces the old stub that returned rc=0 ("not supported"), which made a
# fleet-wide agent-update rollout report SUCCESS on every Windows host while
# nothing happened.
def _release_pubkey_win():
    """Armored release public key pinned on this host, or None (→ no enforcement)."""
    try:
        p = os.path.join(_data_dir(), 'release.pub')
        if os.path.exists(p):
            with open(p, 'r', encoding='utf-8') as f:
                return f.read().strip() or None
    except Exception:
        pass
    return None


def _require_signed_updates_win():
    try:
        return os.path.exists(os.path.join(_data_dir(), 'require-signed-updates'))
    except Exception:
        return False


def _verify_detached_sig_win(data_bytes, sig_text, pubkey_armored, expected_fpr=''):
    """Verify a detached signature over data_bytes with an ephemeral gpg keyring
    seeded only with the pinned key. (ok, detail). Fails closed. Needs gpg on
    PATH (Gpg4win); absent gpg with a pinned key = refuse, never silently skip."""
    import shutil as _shutil
    import tempfile as _tempfile
    gpg = _shutil.which('gpg') or _shutil.which('gpg.exe')
    if not gpg:
        return False, 'gpg not available (install Gpg4win to enforce signed updates)'
    home = _tempfile.mkdtemp(prefix='rp-relverify-')
    try:
        env = dict(os.environ, GNUPGHOME=home)
        imp = subprocess.run([gpg, '--batch', '--import'],
                             input=(pubkey_armored or '').encode(),
                             env=env, capture_output=True, timeout=20,
                             creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        if imp.returncode != 0:
            return False, 'public key import failed'
        art = os.path.join(home, 'art')
        sig = os.path.join(home, 'art.asc')
        with open(art, 'wb') as f:
            f.write(data_bytes)
        with open(sig, 'w', encoding='utf-8') as f:
            f.write(sig_text or '')
        r = subprocess.run([gpg, '--batch', '--status-fd', '1', '--verify', sig, art],
                           env=env, capture_output=True, timeout=20,
                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        out = (r.stdout or b'').decode('utf-8', 'replace')
        valid = [ln for ln in out.splitlines() if ln.startswith('[GNUPG:] VALIDSIG')]
        if not valid:
            return False, 'signature not valid'
        if expected_fpr:
            want = expected_fpr.upper().replace(' ', '')
            if valid[0].split()[2].upper() != want:
                return False, 'signing key fingerprint mismatch'
        return True, 'verified'
    except Exception as e:
        return False, f'verify error: {e}'
    finally:
        _shutil.rmtree(home, ignore_errors=True)


def _http_get_json_win(url, timeout=15):
    if not url.startswith('https://'):
        raise ValueError('server URL must use HTTPS')
    req = urllib.request.Request(url, headers={'User-Agent': f'RemotePower-Win/{VERSION}'})
    with _OPENER.open(req, timeout=timeout) as resp:
        return json.loads(resp.read(4 * 1024 * 1024).decode('utf-8'))


def _http_get_bytes_win(url, timeout=60):
    if not url.startswith('https://'):
        raise ValueError('server URL must use HTTPS')
    req = urllib.request.Request(url, headers={'User-Agent': f'RemotePower-Win/{VERSION}'})
    with _OPENER.open(req, timeout=timeout) as resp:
        return resp.read(64 * 1024 * 1024)


def _self_update():
    """Download + verify + install a fresh Windows agent, then relaunch the task.

    Never runs under audit (read-only) mode — self-update is a write. Returns a
    cmd_output dict; rc is 0 ONLY on a real, verified install (or a legitimate
    "already current" no-op), never as a placeholder for "unimplemented".
    """
    if _audit_mode():
        return {'cmd': 'update', 'output': 'audit (read-only) mode: self-update refused', 'rc': 126}
    if getattr(sys, 'frozen', False):
        # A PyInstaller exe can't rewrite itself in place while running; that path
        # needs a separate updater. Report honestly rather than pretend success.
        return {'cmd': 'update',
                'output': 'self-update of a frozen .exe is not supported by this build', 'rc': 1}
    creds = load_creds()
    server = (creds.get('server_url') or '').rstrip('/')
    if not server:
        return {'cmd': 'update', 'output': 'no server URL on record', 'rc': 1}
    try:
        info = _http_get_json_win(f'{server}/api/agent/win/version', timeout=15)
    except Exception as e:
        return {'cmd': 'update', 'output': f'version check failed: {e}', 'rc': 1}
    remote_sha = (info.get('sha256') or '').strip().lower()
    remote_ver = info.get('version') or '?'
    if not remote_sha:
        return {'cmd': 'update', 'output': 'server publishes no Windows agent — nothing to update', 'rc': 0}

    self_path = os.path.abspath(__file__)
    local_sha = self_sha256().lower()
    import hmac as _hmac
    if local_sha and _hmac.compare_digest(local_sha, remote_sha):
        return {'cmd': 'update', 'output': f'already current (v{VERSION})', 'rc': 0}

    try:
        data = _http_get_bytes_win(f'{server}/api/agent/win/download', timeout=90)
    except Exception as e:
        return {'cmd': 'update', 'output': f'download failed: {e}', 'rc': 1}
    actual_sha = hashlib.sha256(data).hexdigest().lower()
    if not _hmac.compare_digest(actual_sha, remote_sha):
        return {'cmd': 'update',
                'output': f'sha256 mismatch (got {actual_sha[:12]}…, expected {remote_sha[:12]}…) '
                          '— refusing to install', 'rc': 1}

    # Signature gate — fail-closed when a key is pinned or signed updates required.
    pubkey = _release_pubkey_win()
    if not pubkey and _require_signed_updates_win():
        return {'cmd': 'update',
                'output': 'require-signed-updates is set but no release.pub is pinned — '
                          'refusing an unsigned update', 'rc': 1}
    if pubkey:
        try:
            sig_obj = _http_get_json_win(f'{server}/api/agent/win/signature', timeout=15)
            sig_text = (sig_obj or {}).get('signature', '')
        except Exception as e:
            return {'cmd': 'update', 'output': f'signature required but unavailable: {e}', 'rc': 1}
        ok, detail = _verify_detached_sig_win(data, sig_text, pubkey,
                                              (info.get('key_fingerprint') or ''))
        if not ok:
            return {'cmd': 'update', 'output': f'signature verification FAILED ({detail}) — refusing', 'rc': 1}

    # Atomic swap: write beside the target, os.replace (atomic on NTFS), harden ACL.
    try:
        tmp = self_path + '.rp-new'
        with open(tmp, 'wb') as f:
            f.write(data)
        os.replace(tmp, self_path)
    except Exception as e:
        return {'cmd': 'update', 'output': f'install write failed: {e}', 'rc': 1}

    # Re-launch the task so the NEW file runs. CRITICAL: the agent performing this
    # update IS the RemotePowerAgent task, so calling `schtasks /end` INLINE kills
    # THIS process before the `/run` on the next line executes → the task stops
    # with no trigger to restart it (its only trigger is AtStartup), and the host
    # goes offline until the next reboot. This was a real "went offline after an
    # agent update" bug. Instead, hand the restart to a DETACHED helper that
    # OUTLIVES our termination: it waits a few seconds (so this heartbeat can ship
    # the update result), ends the task — a no-op if we've already exited — then
    # runs it fresh with the swapped-in file. `ping` is the detached-safe sleep
    # (`timeout /t` needs a console stdin that a detached process lacks).
    _DETACHED = 0x00000008 | 0x00000200   # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    if _service_installed():
        # Under the Windows service, restart via the SCM: a detached helper stops
        # then starts the service (stop kills THIS process cleanly, start relaunches
        # the swapped-in file). Detached so it outlives our own termination.
        _sc = _system_bin('sc')
        _relaunch = (f'ping -n 6 127.0.0.1 >nul & '
                     f'"{_sc}" stop {SVC_NAME} & ping -n 2 127.0.0.1 >nul & '
                     f'"{_sc}" start {SVC_NAME}')
    else:
        # Scheduled-task path. CRITICAL: the agent performing this update IS the
        # RemotePowerAgent task, so calling `schtasks /end` INLINE kills THIS
        # process before `/run` executes → the task stops with no trigger to
        # restart it (only AtStartup), offline until reboot. Hand it to a DETACHED
        # helper that outlives our termination: wait, /end (a no-op if we already
        # exited), /run the swapped-in file. `ping` is the detached-safe sleep
        # (`timeout /t` needs a console stdin a detached process lacks).
        _sch = _system_bin('schtasks')
        _relaunch = (f'ping -n 6 127.0.0.1 >nul & '
                     f'"{_sch}" /end /tn RemotePowerAgent & '
                     f'ping -n 2 127.0.0.1 >nul & '
                     f'"{_sch}" /run /tn RemotePowerAgent')
    try:
        subprocess.Popen(['cmd', '/c', _relaunch],
                         creationflags=_DETACHED | getattr(subprocess, 'CREATE_NO_WINDOW', 0),
                         close_fds=True, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass   # the file is swapped; a crash-exit still restarts via SCM/RestartInterval
    return {'cmd': 'update', 'output': f'updated to v{remote_ver} ({remote_sha[:12]}…); relaunching', 'rc': 0}


# ── v6.2.0: Windows file manager (files:) ─────────────────────────────────────
#
# Parity with the Linux file manager so the existing browser UI works against a
# Windows host. Same command wire-format (`files:<op>:<b64path>[:<b64content>]`)
# and same JSON result shape; Windows path semantics throughout.
#
# Confinement: an operator-overridable allowlist of roots (default: the dirs where
# data actually lives, never the OS/System roots), plus a realpath re-check so a
# junction/symlink can't redirect a read/write outside the allowlist. Reads are
# always allowed; every MUTATION is refused under audit (read-only) mode.
FILE_MGR_MAX_READ = 256 * 1024
FILE_MGR_MAX_WRITE = 512 * 1024
_FILE_MGR_DEFAULT_ROOTS = [r'C:\Users', r'C:\ProgramData', r'C:\inetpub', r'C:\Temp']
# Never expose the OS itself through the file manager, even if a root is misconfigured.
_FILE_MGR_DENY = (r'c:\windows', r'c:\program files\windowsapps')


def _file_mgr_roots_win():
    try:
        p = os.path.join(_data_dir(), 'file-roots')
        if os.path.exists(p):
            with open(p, 'r', encoding='utf-8') as f:
                roots = [ln.strip() for ln in f if ln.strip() and ':' in ln]
            if roots:
                return roots
    except Exception:
        pass
    return list(_FILE_MGR_DEFAULT_ROOTS)


def _file_mgr_allowed_win(path):
    """True iff `path` (absolute, normalized) is under an allowlisted root and not
    under a denied prefix. Case-insensitive — Windows paths are."""
    rp = os.path.normpath(path).casefold()
    for d in _FILE_MGR_DENY:
        d = os.path.normpath(d).casefold()
        if rp == d or rp.startswith(d + os.sep):
            return False
    for r in _file_mgr_roots_win():
        r = os.path.normpath(r).casefold()
        if rp == r or rp.startswith(r + os.sep):
            return True
    return False


def _handle_file_op_win(cmd):
    """Execute a `files:` op → cmd_output dict with a JSON `output`. Never raises."""
    import base64 as _b64
    res, rc = {}, 0
    try:
        bits = cmd.split(':', 3)
        op = bits[1] if len(bits) > 1 else ''
        raw_path = (_b64.urlsafe_b64decode(bits[2]).decode('utf-8', 'replace')
                    if len(bits) > 2 else '')
        logical = os.path.normpath(raw_path)
        if not os.path.isabs(logical) or not _file_mgr_allowed_win(logical):
            return {'cmd': cmd, 'rc': 1,
                    'output': json.dumps({'error': 'path is outside the allowlisted roots'})}
        if op in ('write', 'mkdir', 'delete', 'upload') and _audit_mode():
            return {'cmd': cmd, 'rc': 126,
                    'output': json.dumps({'error': 'agent is in audit (read-only) mode'})}
        # Realpath re-check: resolve junctions/symlinks and confirm the resolved
        # target is STILL inside an allowed root (traversal / TOCTOU guard).
        real = os.path.realpath(logical)
        if not _file_mgr_allowed_win(real):
            return {'cmd': cmd, 'rc': 1,
                    'output': json.dumps({'error': 'resolved path escapes the allowlisted roots'})}

        if op == 'list':
            entries = []
            try:
                names = sorted(os.listdir(real))[:2000]
            except Exception as e:
                return {'cmd': cmd, 'rc': 1, 'output': json.dumps({'error': str(e)[:200]})}
            for nm in names:
                fp = os.path.join(real, nm)
                try:
                    st = os.lstat(fp)
                    import stat as _stat
                    kind = ('dir' if _stat.S_ISDIR(st.st_mode)
                            else ('link' if _stat.S_ISLNK(st.st_mode) else 'file'))
                    entries.append({'name': nm, 'type': kind, 'size': st.st_size,
                                    'mtime': int(st.st_mtime), 'mode': ''})
                except Exception:
                    continue
            res = {'path': logical, 'entries': entries}
        elif op == 'read':
            with open(real, 'rb') as f:
                data = f.read(FILE_MGR_MAX_READ + 1)
                size = os.fstat(f.fileno()).st_size
            truncated = len(data) > FILE_MGR_MAX_READ
            data = data[:FILE_MGR_MAX_READ]
            try:
                text, binary = data.decode('utf-8'), False
            except UnicodeDecodeError:
                text, binary = '', True
            res = {'path': logical, 'binary': binary, 'truncated': truncated,
                   'size': size, 'content': text}
            if binary:
                res['content_b64'] = _b64.b64encode(data).decode('ascii')
        elif op == 'write':
            content = (_b64.urlsafe_b64decode(bits[3]).decode('utf-8', 'replace')
                       if len(bits) > 3 else '')
            enc = content.encode('utf-8', 'replace')
            if len(enc) > FILE_MGR_MAX_WRITE:
                return {'cmd': cmd, 'rc': 1,
                        'output': json.dumps({'error': f'content exceeds {FILE_MGR_MAX_WRITE} bytes'})}
            tmp = real + '.rp-tmp'
            with open(tmp, 'wb') as f:
                f.write(enc)
            os.replace(tmp, real)
            res = {'path': logical, 'written': len(enc)}
        elif op == 'upload':
            raw = _b64.urlsafe_b64decode(bits[3]) if len(bits) > 3 else b''
            if len(raw) > 8 * 1024 * 1024:
                return {'cmd': cmd, 'rc': 1, 'output': json.dumps({'error': 'upload too large'})}
            if os.path.exists(real):
                rc, res = 1, {'error': 'file exists (overwrite not permitted)'}
            else:
                tmp = real + '.rp-tmp'
                with open(tmp, 'wb') as f:
                    f.write(raw)
                os.replace(tmp, real)
                res = {'path': logical, 'uploaded': len(raw)}
        elif op == 'mkdir':
            os.makedirs(real, exist_ok=True)
            res = {'path': logical, 'created': True}
        elif op == 'delete':
            if os.path.isdir(real):
                os.rmdir(real)          # empty dirs only
            else:
                os.remove(real)
            res = {'path': logical, 'deleted': True}
        else:
            rc, res = 1, {'error': f'unknown file op: {op}'}
    except Exception as e:
        rc, res = 1, {'error': str(e)[:300]}
    return {'cmd': cmd, 'rc': rc, 'output': json.dumps(res)}


# ── v6.2.0: Windows services (enumerate + control) ────────────────────────────
#
# Parity with the Linux agent's watched-service reporting and svc: command.
# The server pushes `watched_services` (a list of service names) in the heartbeat
# response, we report their state in the SAME {unit, active, sub, since} shape the
# server already ingests, and it maps Windows states onto its systemd vocabulary:
#   Running               → 'active'   (OK)
#   StartPending/StopPending → 'activating'  (OK-ish, in flight)
#   Stopped / Paused / …  → 'inactive' (warning — a watched service is down)
# Windows has no "failed" state, so we never fabricate the systemd 'failed' that
# the server escalates to CRITICAL — a stopped watched service is a warning, which
# is the honest severity.
_watched_services = []          # updated from each heartbeat response
_watched_files = []             # v6.2.0: drift — updated from each heartbeat response
_WIN_SVC_STATE = {
    'running': 'active', 'startpending': 'activating', 'stoppending': 'activating',
    'stopped': 'inactive', 'paused': 'inactive', 'pausepending': 'inactive',
    'continuepending': 'activating',
}
# Get-Service objects, one JSON line each: Name, Status, DisplayName.
_SVC_PS = (
    "$ErrorActionPreference='SilentlyContinue';"
    "$names={NAMES};"
    "foreach($n in $names){"
    "  $s=Get-Service -Name $n -ErrorAction SilentlyContinue;"
    "  if($s){"
    "    [pscustomobject]@{name=$n;canonical=$s.Name;status=$s.Status.ToString()}|ConvertTo-Json -Compress"
    "  } else {"
    "    [pscustomobject]@{name=$n;canonical='';status='NotFound'}|ConvertTo-Json -Compress"
    "  }"
    "}"
)


def _ps_single_quote(s):
    """Escape a string for a PowerShell single-quoted literal ('' escapes ')."""
    return "'" + str(s).replace("'", "''") + "'"


def get_services(watched_units):
    """Report the state of each watched Windows service. Returns
    [{unit, active, sub, since, canonical}, ...] — the shape the server ingests.

    The names came from the server's validated config; we still pass them as
    PowerShell single-quoted literals (never string-concatenated into a command),
    so there is nothing to inject even if a name were hostile.
    """
    if not watched_units:
        return []
    units = [str(u) for u in watched_units[:50] if str(u).strip()]
    if not units:
        return []
    names_ps = '@(' + ','.join(_ps_single_quote(u) for u in units) + ')'
    ps = _SVC_PS.replace('{NAMES}', names_ps)
    try:
        r = subprocess.run([_powershell_bin(), '-NoProfile', '-NonInteractive', '-Command', ps],
                           capture_output=True, text=True, timeout=30,
                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except Exception:
        return []
    out = []
    for line in (r.stdout or '').splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        name = str(obj.get('name') or '')
        if not name:
            continue
        status = str(obj.get('status') or '').lower()
        active = _WIN_SVC_STATE.get(status, 'unknown')
        entry = {'unit': name, 'active': active, 'sub': str(obj.get('status') or ''),
                 'since': 0}
        canonical = str(obj.get('canonical') or '')
        if canonical and canonical != name:
            entry['canonical'] = canonical
        out.append(entry)
    return out


def _run_service_action_win(cmd):
    """svc:<action>:<unit> — Start/Stop/Restart-Service via fixed argv-ish PS (no
    shell string-building; the unit is a single-quoted PS literal)."""
    try:
        _, action, unit = cmd.split(':', 2)
    except ValueError:
        return {'cmd': cmd, 'output': 'malformed service action', 'rc': 2}
    verb = {'restart': 'Restart-Service', 'start': 'Start-Service',
            'stop': 'Stop-Service'}.get(action)
    if not verb or not unit.strip():
        return {'cmd': cmd, 'output': 'refused: bad action/unit', 'rc': 2}
    ps = (f"$ErrorActionPreference='Stop';"
          f"{verb} -Name {_ps_single_quote(unit)} -Force;"
          f"'{action} ok'")
    try:
        r = subprocess.run([_powershell_bin(), '-NoProfile', '-NonInteractive', '-Command', ps],
                           capture_output=True, text=True, timeout=90,
                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        out = ((r.stdout or '') + (r.stderr or '')).strip() or f'{action} {unit} -> rc {r.returncode}'
        return {'cmd': cmd, 'output': out[:4000], 'rc': r.returncode}
    except Exception as e:
        return {'cmd': cmd, 'output': f'{type(e).__name__}: {e}', 'rc': 1}


# ── v6.2.0: Windows processes (list + kill) ───────────────────────────────────
def get_top_processes(limit=15):
    """Top processes by memory (RSS). Returns (top_list, name_set) where top_list
    is [{pid, name, cpu, mem_mb}] and name_set is the deduped names for the
    server-side `process` custom-check (which reads sysinfo.proc_names). Needs
    psutil; returns ([], []) without it."""
    try:
        import psutil
    except Exception:
        return [], []
    procs = []
    names = set()
    # v6.2.0: emit the SAME {pid,name,cpu,mem} shape (cpu% + memory PERCENT) the
    # Linux agent sends — the server sanitizer keeps `cpu`/`mem`, not `mem_mb`, so
    # a Windows-specific `mem_mb` key was silently dropped and the drawer rendered
    # every process at 0% memory. cpu_percent(None) is non-blocking (unprimed here,
    # so first sample reads ~0 — acceptable for a top-N snapshot).
    for p in psutil.process_iter(['pid', 'name', 'memory_percent', 'cpu_percent']):
        try:
            info = p.info
            nm = info.get('name') or ''
            if nm:
                names.add(nm)
            procs.append({'pid': info.get('pid'), 'name': nm,
                          'cpu': round(info.get('cpu_percent') or 0, 1),
                          'mem': round(info.get('memory_percent') or 0, 2)})
        except Exception:
            continue
    procs.sort(key=lambda x: x.get('mem') or 0, reverse=True)
    return procs[:limit], sorted(names)


def _run_process_kill_win(cmd):
    """kill:<SIG>:<pid> — terminate a PID. The server sends POSIX signal names
    (TERM/KILL/…) which have no meaning on Windows; we map ANY of them to a
    terminate (taskkill /PID), and refuse pid<=4 (System/Idle/csrss range)."""
    try:
        _, _sig, pid_s = cmd.split(':', 2)
        pid = int(pid_s)
    except ValueError:
        return {'cmd': cmd, 'output': 'malformed kill command', 'rc': 2}
    if pid <= 4:
        return {'cmd': cmd, 'output': 'refused: system pid', 'rc': 2}
    # /F force, /T with children. taskkill is a System32 tool → absolute path.
    try:
        r = subprocess.run([_system_bin('taskkill'), '/PID', str(pid), '/F', '/T'],
                           capture_output=True, text=True, timeout=30,
                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        out = ((r.stdout or '') + (r.stderr or '')).strip() or f'taskkill {pid} -> {r.returncode}'
        return {'cmd': cmd, 'output': out[:2000], 'rc': r.returncode}
    except Exception as e:
        return {'cmd': cmd, 'output': f'{type(e).__name__}: {e}', 'rc': 1}


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
        r = subprocess.run([_powershell_bin(), '-NoProfile', '-NonInteractive', '-Command', _WU_PS],
                           capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            return None
        titles = _parse_wu_titles(r.stdout)
        out = {'manager': 'windows-update', 'upgradable': len(titles),
               'upgradable_names': titles[:50]}
        # v6.2.0: third-party APPLICATION updates via winget, in the same
        # `third_party: {mgr: {count, names}}` shape the Linux agent uses for
        # flatpak/snap/pip/npm. Windows Update covers the OS; winget covers
        # Chrome, 7-Zip, VLC, Notepad++ … which is where the actual CVEs live.
        tp = get_winget_updates()
        if tp:
            out['third_party'] = {'winget': tp}
        return out
    except Exception:
        return None


# A winget package Id: reverse-DNS-ish, e.g. "Google.Chrome", "7zip.7zip".
_WINGET_ID_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$')


def _parse_winget(stdout):
    """Parse `winget upgrade` table output into (count, names). Pure.

    winget prints a fixed-width table with a header and a dashed rule; the Id
    column is what `winget upgrade --id <x>` takes. Deliberately tolerant: the
    table's exact columns shift between winget versions, so key off the header
    row's 'Id' offset rather than splitting on whitespace (app names contain
    spaces, which is precisely what breaks a naive split).
    """
    lines = [ln.rstrip() for ln in (stdout or '').splitlines() if ln.strip()]
    hdr_i = next((i for i, ln in enumerate(lines)
                  if 'Name' in ln and 'Id' in ln and 'Version' in ln), None)
    if hdr_i is None:
        return 0, []
    hdr = lines[hdr_i]
    id_start = hdr.index('Id')
    ver_start = hdr.index('Version')
    names = []
    for ln in lines[hdr_i + 1:]:
        if set(ln.strip()) <= {'-', '─'}:      # the dashed rule
            continue
        if len(ln) < id_start:
            continue
        pkg_id = ln[id_start:ver_start].strip()
        # Trailing summary lines ("3 upgrades available.") have no Id column.
        if not pkg_id or ' ' in pkg_id:
            continue
        names.append(pkg_id)
        if len(names) >= 100:
            break
    return len(names), names


def get_winget_updates():
    """Pending third-party app updates from winget, or {} when winget is absent.

    Feature-invisible without winget (Server SKUs and older Windows 10 builds
    don't ship it) — same contract as the Linux agent's flatpak/snap/pip/npm
    probes, which return nothing when the tool isn't installed.
    """
    if not sys.platform.startswith('win'):
        return {}
    try:
        r = subprocess.run(
            [_winget_bin(), 'upgrade', '--accept-source-agreements'],
            capture_output=True, text=True, timeout=120)
        # winget exits non-zero when there is nothing to upgrade; parse anyway.
        count, names = _parse_winget(r.stdout)
        return {'count': count, 'names': names} if count else {}
    except FileNotFoundError:
        return {}          # winget not installed — not an error
    except Exception:
        return {}


# PowerShell: Windows Defender posture. Pipe-delimited so parsing needs no JSON
# (Get-MpComputerStatus emits a huge object; we want five fields).
#   RealTimeProtectionEnabled | AntivirusSignatureAge(days) | QuickScanEndTime |
#   FullScanEndTime | (threat count from Get-MpThreatDetection)
_DEFENDER_PS = (
    "$ErrorActionPreference='Stop';"
    "$s=Get-MpComputerStatus;"
    "$t=@(Get-MpThreatDetection -ErrorAction SilentlyContinue).Count;"
    "$q=if($s.QuickScanEndTime){[int][double]::Parse((Get-Date $s.QuickScanEndTime -UFormat %s))}else{0};"
    "$f=if($s.FullScanEndTime){[int][double]::Parse((Get-Date $s.FullScanEndTime -UFormat %s))}else{0};"
    "Write-Output "
    "\"$($s.RealTimeProtectionEnabled)|$($s.AntivirusSignatureAge)|$q|$f|$t\""
)


def _parse_defender(out):
    """Parse the pipe-delimited Defender line into the server's `av` tool shape.
    Pure — unit-testable without Windows.

    Returns None when the line is unusable. `realtime_enabled` is a real bool
    because the server treats it as TRI-state: absent means "this tool has no
    real-time concept" (ClamAV/rkhunter), and must NOT read as "protection off".
    """
    line = (out or '').strip().splitlines()
    if not line:
        return None
    parts = line[-1].strip().split('|')
    if len(parts) < 5:
        return None
    rt, age, quick, full, threats = (p.strip() for p in parts[:5])

    def _int(v):
        try:
            return int(float(v))
        except (TypeError, ValueError):
            return 0

    # The agent must never invent a posture. If PowerShell gave us something
    # that isn't a bool, we report the tool WITHOUT realtime_enabled rather than
    # guessing — a wrong `False` here pages the operator for nothing, a wrong
    # `True` hides a genuinely unprotected host.
    tool = {'installed': True,
            'db_age_days': _int(age),
            'infected': _int(threats)}
    if rt.lower() in ('true', 'false'):
        tool['realtime_enabled'] = (rt.lower() == 'true')
    last_scan = max(_int(quick), _int(full))
    if last_scan > 0:
        tool['last_scan_ts'] = last_scan
    return tool


def get_defender_status():
    """Windows Defender posture → the server's existing `av` payload shape.

    Rides the SAME server pipeline as ClamAV/rkhunter (_ingest_av → av_status
    .json → attention items → av_infected/av_warning/av_clean), plus the
    Windows-only av_realtime_off signal. Returns {} when Defender isn't present
    (third-party AV installed, or a stripped image) — feature-invisible, like
    the Linux agent's AV collector on a host with no ClamAV.
    """
    if not sys.platform.startswith('win'):
        return {}
    try:
        r = subprocess.run(
            [_powershell_bin(), '-NoProfile', '-NonInteractive', '-Command', _DEFENDER_PS],
            capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return {}
        tool = _parse_defender(r.stdout)
        return {'defender': tool} if tool else {}
    except Exception:
        return {}


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


# v6.2.0: Event Log with a RecordId CURSOR + the Security channel + Event IDs.
#
# The old collector re-fetched the newest 100 System+Application events EVERY
# poll with no bookmark, so lines were duplicated across polls and any burst of
# >100 events between polls was silently lost. And the Security log — where
# logon failures (4625), account lockouts (4740), audit-policy changes live —
# was never read at all.
#
# Now: per-channel RecordId cursors persisted to disk. Each poll fetches only
# events NEWER than the cursor, advances the cursor to the newest fetched, and
# emits one line per event PREFIXED WITH THE EVENT ID so the server's regex
# log_watch rules can key on it (e.g. a rule matching "[4625]" alerts on failed
# logons). First run per channel baselines to the newest few, so a fresh agent
# doesn't dump the entire history into one heartbeat.
_EVENTLOG_CHANNELS = ('System', 'Application', 'Security')
_EVENTLOG_PER_POLL = 80          # cap per channel per poll (server stores ≤200 total)
_EVENTLOG_BASELINE = 20          # first-run: emit only the newest N, then cursor forward
_EVENTLOG_CURSOR_FILE = 'eventlog_cursor.json'
# JSON-per-line so we get RecordId + Id + level structurally, not by re-parsing text.
# Security events have no Level filter that's useful (most are Information), so we
# take that channel unfiltered; System/Application stay Critical/Error/Warning.
# NOTE: built with str.replace(), NOT str.format() — so the PowerShell hash/
# scriptblock braces are SINGLE (`@{ }` / `{ }`); only the {CHANNEL}/{LEVEL}/
# {MAX}/{SINCE} tokens are substituted. (A prior version doubled the braces as if
# for .format() and PowerShell rejected `@{{…}}` — caught by parsing it with the
# real pwsh, which is why the agent's PS is now parse-validated in tests.)
# We fetch the newest {MAX} events and filter by the cursor in PYTHON (not a
# Where-Object here) so a log CLEAR — which resets RecordId to 1 — is detectable:
# the newest RecordId then drops BELOW the cursor and the caller re-baselines,
# instead of the server-side filter silently returning nothing forever.
_EVENTLOG_PS_TMPL = (
    "$ErrorActionPreference='SilentlyContinue';"
    "$f=@{LogName='{CHANNEL}'{LEVEL}};"
    "Get-WinEvent -FilterHashtable $f -MaxEvents {MAX} | "
    "ForEach-Object { [pscustomobject]@{"
    "  rid=$_.RecordId; id=$_.Id; lvl=$_.LevelDisplayName; prov=$_.ProviderName;"
    "  t=$_.TimeCreated.ToString('MMM dd HH:mm:ss');"
    "  msg=($_.Message -replace '\\s+',' ')"
    "} | ConvertTo-Json -Compress }"
)


def _eventlog_cursor_path():
    return os.path.join(_data_dir(), _EVENTLOG_CURSOR_FILE)


def _load_eventlog_cursor():
    try:
        with open(_eventlog_cursor_path(), 'r', encoding='utf-8') as f:
            c = json.load(f)
            return c if isinstance(c, dict) else {}
    except Exception:
        return {}


def _save_eventlog_cursor(cur):
    try:
        d = _data_dir()
        os.makedirs(d, exist_ok=True)
        tmp = _eventlog_cursor_path() + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(cur, f)
        os.replace(tmp, _eventlog_cursor_path())
    except Exception:
        pass


def _parse_eventlog(stdout):
    """Parse the JSON-per-line output into (entries, max_rid), where entries is a
    list of (record_id, line). Filtering by the cursor happens in the caller (in
    Python, not PowerShell) so a log-CLEAR — which resets RecordId to 1 — can be
    detected and the cursor reset, instead of the cursor sitting above every new
    event forever.

    Each line: '<t> <LEVEL> <PROV>[<id>]: <msg>' — the '[<id>]' is what an alert
    rule keys on. Pure — unit-testable off-Windows with canned JSON lines.
    """
    entries, max_rid = [], 0
    for raw in (stdout or '').splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            o = json.loads(raw)
        except Exception:
            continue
        try:
            rid = int(o.get('rid') or 0)
        except (TypeError, ValueError):
            rid = 0
        max_rid = max(max_rid, rid)
        line = (f"{o.get('t','')} {o.get('lvl','')} "
                f"{o.get('prov','')}[{o.get('id','')}]: {o.get('msg','')}").strip()
        entries.append((rid, line[:512]))
    return entries, max_rid


def get_event_log_journal():
    """New Windows Event Log entries across System/Application/Security since the
    last cursor, as journal lines. Advances + persists the cursor. Off-Windows []."""
    if not sys.platform.startswith('win'):
        return []
    cursor = _load_eventlog_cursor()
    all_lines = []
    dirty = False
    for chan in _EVENTLOG_CHANNELS:
        since = cursor.get(chan)
        first_run = since is None
        since_val = 0 if first_run else int(since or 0)
        level = '' if chan == 'Security' else ";Level=1,2,3"
        maxn = _EVENTLOG_BASELINE if first_run else _EVENTLOG_PER_POLL
        ps = (_EVENTLOG_PS_TMPL
              .replace('{CHANNEL}', chan)
              .replace('{LEVEL}', level)
              .replace('{MAX}', str(maxn)))
        try:
            r = subprocess.run([_powershell_bin(), '-NoProfile', '-NonInteractive', '-Command', ps],
                               capture_output=True, text=True, timeout=60,
                               creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        except Exception:
            continue
        if r.returncode != 0:
            # The Security channel needs elevation; a non-SYSTEM agent just skips it
            # rather than erroring the whole collection.
            continue
        entries, max_rid = _parse_eventlog(r.stdout)
        # Log CLEARED since last poll: RecordId resets to 1, so the newest event
        # is now BELOW the cursor. Detect that (max_rid < cursor) and re-baseline
        # to the newest few, instead of filtering out every event forever.
        cleared = (not first_run) and max_rid and max_rid < since_val
        if first_run or cleared:
            # Baseline: emit the newest _EVENTLOG_BASELINE, set the cursor to the
            # newest RecordId seen.
            fresh = [ln for _rid, ln in entries[:_EVENTLOG_BASELINE]]
            all_lines.extend(fresh)
            cursor[chan] = max_rid
            dirty = True
        else:
            # Normal: emit only events newer than the cursor, advance to newest.
            all_lines.extend(ln for rid, ln in entries if rid > since_val)
            if max_rid > since_val:
                cursor[chan] = max_rid
                dirty = True
    if dirty:
        _save_eventlog_cursor(cursor)
    return all_lines[:200]


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
        r = subprocess.run([_powershell_bin(), '-NoProfile', '-NonInteractive',
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


def _reboot_required():
    """v6.2.0: Windows pending-reboot detection → sysinfo.reboot_required (bool).

    Parity with the Linux agent's /run/reboot-required. This is THE gap the
    Windows updater created: it installs updates with -IgnoreReboot and used to
    leave the host in a pending-reboot state that the operator never saw. The
    three canonical signals (a True on ANY of them means a reboot is pending):
      1. Component Based Servicing\\RebootPending          (servicing / .NET / role changes)
      2. WindowsUpdate\\Auto Update\\RebootRequired        (a Windows Update needs it)
      3. Session Manager\\PendingFileRenameOperations       (a file swap queued for boot)
    Pure registry reads via stdlib winreg — no PowerShell, no subprocess. On a
    non-Windows box (tests) winreg is absent, so this returns False, not an error.
    """
    try:
        import winreg
    except Exception:
        return False
    HKLM = winreg.HKEY_LOCAL_MACHINE

    def _key_exists(path):
        try:
            winreg.CloseKey(winreg.OpenKey(HKLM, path))
            return True
        except FileNotFoundError:
            return False
        except OSError:
            return False

    if _key_exists(r'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'):
        return True
    if _key_exists(r'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'):
        return True
    try:
        k = winreg.OpenKey(HKLM, r'SYSTEM\CurrentControlSet\Control\Session Manager')
        try:
            val, _typ = winreg.QueryValueEx(k, 'PendingFileRenameOperations')
            # A non-empty multi-string means at least one rename is queued for boot.
            if val and any(str(s).strip() for s in val):
                return True
        except FileNotFoundError:
            pass
        finally:
            winreg.CloseKey(k)
    except OSError:
        pass
    return False


def collect_sysinfo():
    """Core metrics. Uses psutil when available; otherwise a best-effort subset
    so a host without psutil still reports OS/uptime/hostname."""
    info = {
        'platform': platform.platform(),
        'kernel':   platform.version(),       # Windows build string
        'hostname': socket.gethostname(),
        'audit_mode': _audit_mode(),          # v4.10.0: read-only agent flag
        # v6.2.0: pending-reboot state — the server edge-triggers a reboot_required
        # alert + auto-resolves it, and feeds the risk score. Previously never sent
        # by Windows, so the -IgnoreReboot updater left a silent pending-reboot.
        'reboot_required': _reboot_required(),
    }
    # v6.2.0: Windows security posture → the Checks catalog (BitLocker, firewall,
    # Defender real-time + signature age, Windows Update service).
    try:
        wp = get_win_posture()
        if wp:
            info['win_posture'] = wp
    except Exception:
        pass
    # v6.2.0: agent-side custom checks — evaluate the server-pushed set on-host
    # and report the results (parity with the Linux agent).
    if _watched_agent_checks:
        try:
            info['custom_check_results'] = eval_agent_checks(_watched_agent_checks)
        except Exception:
            pass
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

def _win_update_install_ps(title=''):
    """W6-32: PowerShell to install pending Windows Updates. Prefers the
    PSWindowsUpdate module (Install-WindowsUpdate); falls back to the built-in
    Microsoft.Update COM API. `title` (optional) installs only updates whose
    title contains it. Never auto-reboots (IgnoreReboot). Pure builder."""
    safe = (title or '').replace("'", "''")[:200]
    if safe:
        psw = (f"Get-WindowsUpdate -Install -AcceptAll -IgnoreReboot "
               f"-Title '*{safe}*' -Verbose")
        com_filter = f"$_.Title -like '*{safe}*'"
    else:
        psw = "Get-WindowsUpdate -Install -AcceptAll -IgnoreReboot -Verbose"
        com_filter = "$true"
    return (
        "$ErrorActionPreference='Stop';"
        "if (Get-Command Get-WindowsUpdate -ErrorAction SilentlyContinue) {"
        f"  {psw}"
        "} else {"
        "  $s=(New-Object -ComObject Microsoft.Update.Session);"
        "  $sr=$s.CreateUpdateSearcher().Search('IsInstalled=0 and IsHidden=0').Updates;"
        f"  $c=New-Object -ComObject Microsoft.Update.UpdateColl;"
        f"  $sr | Where-Object {{ {com_filter} }} | ForEach-Object {{ $null=$c.Add($_) }};"
        "  if ($c.Count -eq 0) { Write-Output 'No matching updates.'; exit 0 }"
        "  $d=$s.CreateUpdateDownloader(); $d.Updates=$c; $null=$d.Download();"
        "  $i=$s.CreateUpdateInstaller(); $i.Updates=$c; $r=$i.Install();"
        "  Write-Output ('Installed '+$c.Count+' update(s); result='+$r.ResultCode);"
        "}"
    )


def command_argv(cmd):
    """Map a server command string to a Windows argv list, or None if the
    command is handled elsewhere / unknown. Pure — unit-testable off-Windows."""
    if cmd == 'reboot':
        return [_system_bin('shutdown'), '/r', '/t', '30', '/c', 'RemotePower: scheduled reboot']
    if cmd == 'shutdown':
        return [_system_bin('shutdown'), '/s', '/t', '30', '/c', 'RemotePower: scheduled shutdown']
    # W6-32: patch execution — `upgrade` (all) or `upgrade:<title>` (one update).
    if cmd == 'upgrade' or (isinstance(cmd, str) and cmd.startswith('upgrade:')):
        title = cmd[len('upgrade:'):].strip() if cmd.startswith('upgrade:') else ''
        return [_powershell_bin(), '-NoProfile', '-NonInteractive', '-Command',
                _win_update_install_ps(title)]
    # v6.2.0: third-party APP patching via winget. `winget:` upgrades everything,
    # `winget:<id>` one package. Kept as its own command rather than overloading
    # `upgrade:<title>` — that one filters Windows *Update* titles, and a package
    # id ("Google.Chrome") is not a title. No shell: argv is passed directly, and
    # the id is charset-validated below, so there is nothing to inject into.
    if isinstance(cmd, str) and cmd.startswith('winget:'):
        pkg = cmd[len('winget:'):].strip()
        base = [_winget_bin(), 'upgrade', '--accept-source-agreements',
                '--accept-package-agreements', '--disable-interactivity',
                '--silent']
        if not pkg:
            return base + ['--all']
        # A winget Id is [A-Za-z0-9.+_-] — refuse anything else rather than pass
        # an operator-supplied string through to a subprocess.
        if not _WINGET_ID_RE.match(pkg):
            return None
        return base + ['--id', pkg, '--exact']
    if isinstance(cmd, str) and cmd.startswith('exec:'):
        body = cmd[len('exec:'):]
        # v5.0.0 (#F3): strip the optional "to=<seconds>:" per-command timeout prefix.
        import re as _re
        m = _re.match(r'^to=\d{1,5}:(.*)$', body, _re.DOTALL)
        if m:
            body = m.group(1)
        # exec: runs via PowerShell on Windows (the native default). An operator
        # who needs a DIFFERENT interpreter — because `exec:` silently ran their
        # bash/cmd body as PowerShell — uses the explicit ps:/cmd: verbs below.
        return [_powershell_bin(), '-NoProfile', '-NonInteractive', '-Command', body]
    # v6.2.0: EXPLICIT interpreter selection. The old failure: a script written for
    # bash or cmd, queued as exec:, was reinterpreted as PowerShell with no error
    # (it just did the wrong thing). These verbs make the interpreter deterministic
    # instead of a function of which OS the command happened to land on.
    if isinstance(cmd, str) and cmd.startswith('ps:'):
        return [_powershell_bin(), '-NoProfile', '-NonInteractive', '-Command', cmd[len('ps:'):]]
    if isinstance(cmd, str) and cmd.startswith('cmd:'):
        # cmd.exe /c runs a batch/CMD one-liner; the remainder is one argument to
        # the interpreter (no agent-side shell), nothing to inject the operator
        # didn't author.
        return [_system_bin('cmd'), '/c', cmd[len('cmd:'):]]
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
    """Execute a queued command; return a cmd_output dict to report back (or
    None for fire-and-forget / control commands)."""
    if not cmd:
        return None
    # A non-string command from the server used to raise AttributeError on the
    # first `.startswith` below (swallowed nowhere → the heartbeat loop logged an
    # error and dropped the whole batch). Coerce defensively.
    if not isinstance(cmd, str):
        return {'cmd': str(cmd), 'output': 'malformed command (not a string)', 'rc': 1}
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
        return _self_update()
    # v6.2.0: service control + process kill + file ops report their own output.
    if cmd.startswith('svc:'):
        return _run_service_action_win(cmd)
    if cmd.startswith('kill:'):
        return _run_process_kill_win(cmd)
    if cmd.startswith('files:'):
        return _handle_file_op_win(cmd)
    argv = command_argv(cmd)
    if argv is None:
        return {'cmd': cmd, 'output': f'unsupported command: {cmd}', 'rc': 1}
    try:
        is_exec = cmd.startswith('exec:')
        # ps:/cmd: are operator scripts too — give them the exec timeout budget,
        # not the 30s control-command default.
        is_script = is_exec or cmd.startswith('ps:') or cmd.startswith('cmd:')
        # W6-32: Windows Update installs are slow — give them a wide timeout.
        is_upgrade = cmd == 'upgrade' or cmd.startswith('upgrade:')
        _to = _exec_timeout_override(cmd) if is_exec else (1800 if is_upgrade else None)
        r = subprocess.run(argv, capture_output=True, text=True,
                           timeout=_to or (EXEC_TIMEOUT if is_script else 30))
        out = ((r.stdout or '') + (r.stderr or '')).strip()[:MAX_OUTPUT]
        return {'cmd': cmd, 'output': out or '(no output)', 'rc': r.returncode}
    except subprocess.TimeoutExpired:
        return {'cmd': cmd, 'output': 'command timed out', 'rc': 124}
    except Exception as e:
        return {'cmd': cmd, 'output': f'error: {e}', 'rc': 1}


def _uninstall():
    """Best-effort: remove the service AND the scheduled task (a host may have
    either mechanism), then the creds. Idempotent."""
    _uninstall_service()   # sc stop + delete (no-op if not installed)
    try:
        subprocess.run([_system_bin('schtasks'), '/delete', '/tn', 'RemotePowerAgent', '/f'],
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
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        # Surface the server's JSON {"error": "..."} instead of letting a raw
        # HTTPError traceback bury it. Enrollment 400/403s ("Invalid enrollment
        # token format", "Invalid or expired PIN") are operator-actionable — the
        # person running the installer must be able to READ them.
        detail = ''
        try:
            detail = (json.loads(e.read().decode('utf-8')) or {}).get('error', '')
        except Exception:
            pass
        raise RuntimeError(f'server returned HTTP {e.code}'
                           + (f': {detail}' if detail else '')) from None


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


# ── v6.2.0: SMART disk health (parity with the Linux agent) ───────────────────
#
# Windows exposes disk health through the Storage subsystem, not smartctl:
# Get-PhysicalDisk gives the drive's own HealthStatus + identity, and
# Get-StorageReliabilityCounter gives the SMART-derived counters (wear,
# temperature, power-on hours, read/write error totals). Projected onto the SAME
# `smart[]` shape the server's _ingest_hardware already consumes, so failure
# prediction, wear tracking and the daily SMART trend all light up on Windows
# with zero server change.
_SMART_PS = (
    "$ErrorActionPreference='SilentlyContinue';"
    "Get-PhysicalDisk | ForEach-Object {"
    "  $d=$_; $rc=$d | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue;"
    "  [pscustomobject]@{"
    "    device=$d.DeviceId; model=$d.FriendlyName; serial=$d.SerialNumber;"
    "    health=$d.HealthStatus.ToString();"
    "    wear=($(if($rc){$rc.Wear}else{$null}));"
    "    temperature_c=($(if($rc){$rc.Temperature}else{$null}));"
    "    power_on_hours=($(if($rc){$rc.PowerOnHours}else{$null}));"
    "    read_errors=($(if($rc){$rc.ReadErrorsTotal}else{$null}))"
    "  } | ConvertTo-Json -Compress"
    "}"
)
# Windows HealthStatus → the server's PASSED|FAILED|UNKNOWN vocabulary. A
# 'Warning' (degraded) drive maps to FAILED so it ALERTS — a disk the OS already
# flags as degraded is exactly what disk-failure prediction exists to catch.
_SMART_HEALTH = {'healthy': 'PASSED', 'unhealthy': 'FAILED', 'warning': 'FAILED'}


def _num_or_none(v):
    try:
        if v is None:
            return None
        return int(float(v))
    except (TypeError, ValueError):
        return None


def get_smart_status():
    """Per-physical-disk SMART health, or []. Off-Windows []."""
    if not sys.platform.startswith('win'):
        return []
    try:
        r = subprocess.run([_powershell_bin(), '-NoProfile', '-NonInteractive', '-Command', _SMART_PS],
                           capture_output=True, text=True, timeout=45,
                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except Exception:
        return []
    if r.returncode != 0:
        return []
    return _parse_smart(r.stdout)


def _parse_smart(stdout):
    """JSON-per-line → the server's smart[] entry shape. Pure/unit-testable."""
    disks = []
    for raw in (stdout or '').splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            o = json.loads(raw)
        except Exception:
            continue
        entry: dict = {
            'device': str(o.get('device') or '')[:64],
            'model':  str(o.get('model') or '')[:64],
            'serial': str(o.get('serial') or '')[:64],
            'health': _SMART_HEALTH.get(str(o.get('health') or '').lower(), 'UNKNOWN'),
        }
        temp = _num_or_none(o.get('temperature_c'))
        if temp is not None:
            entry['temperature_c'] = temp
        poh = _num_or_none(o.get('power_on_hours'))
        if poh is not None:
            entry['power_on_hours'] = poh
        wear = _num_or_none(o.get('wear'))
        if wear is not None and 0 <= wear <= 100:
            entry['wear_pct'] = wear
        # Windows' ReadErrorsTotal is the closest analogue to the reallocated/
        # pending trend the server predicts on — surface it as crc_errors (a
        # counter the server already trends) rather than inventing a new field.
        rerr = _num_or_none(o.get('read_errors'))
        if rerr is not None:
            entry['crc_errors'] = rerr
        disks.append(entry)
    return disks


# ── v6.2.0: hardware inventory via WMI (parity) ───────────────────────────────
_HWINV_PS = (
    "$ErrorActionPreference='SilentlyContinue';"
    "$cs=Get-CimInstance Win32_ComputerSystem;"
    "$bios=Get-CimInstance Win32_BIOS;"
    "$mem=@(Get-CimInstance Win32_PhysicalMemory | ForEach-Object {"
    "  @{locator=$_.DeviceLocator;"
    "    size=(''+[math]::Round($_.Capacity/1GB)+' GB');"
    "    speed=(''+$_.Speed+' MHz');"
    "    serial=$_.SerialNumber; manufacturer=$_.Manufacturer}});"
    "[pscustomobject]@{"
    "  manufacturer=$cs.Manufacturer; product=$cs.Model;"
    "  serial=$bios.SerialNumber; memory=$mem"
    "} | ConvertTo-Json -Compress -Depth 4"
)


def get_hardware_inventory():
    """{system:{manufacturer,product,serial}, memory:[...]} via WMI, or {}.

    Temps/RAID are deliberately omitted — MSAcpi_ThermalZoneTemperature is absent
    on most desktops and Storage-Spaces RAID is niche; better to send nothing than
    a flaky half-signal. Off-Windows {}."""
    if not sys.platform.startswith('win'):
        return {}
    try:
        r = subprocess.run([_powershell_bin(), '-NoProfile', '-NonInteractive', '-Command', _HWINV_PS],
                           capture_output=True, text=True, timeout=30,
                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except Exception:
        return {}
    if r.returncode != 0:
        return {}
    return _parse_hwinv(r.stdout)


def _parse_hwinv(stdout):
    """The WMI JSON → the server's hardware shape. Pure/unit-testable."""
    try:
        o = json.loads((stdout or '').strip() or '{}')
    except Exception:
        return {}
    if not isinstance(o, dict):
        return {}
    hw = {}
    system = {k: str(o.get(sk) or '')[:128] for k, sk in
              (('manufacturer', 'manufacturer'), ('product', 'product'), ('serial', 'serial'))
              if o.get(sk)}
    if system:
        hw['system'] = system
    mem = o.get('memory')
    # ConvertTo-Json emits a single DIMM as an object, not a one-element array.
    if isinstance(mem, dict):
        mem = [mem]
    if isinstance(mem, list):
        dimms = []
        for d in mem[:64]:
            if not isinstance(d, dict):
                continue
            dimms.append({k: str(v)[:64] for k, v in d.items()
                          if k in ('locator', 'size', 'type', 'speed', 'serial', 'manufacturer') and v})
        if dimms:
            hw['memory'] = dimms
    return hw


# ── v6.2.0: agent-side custom checks (parity — the Windows agent had NONE) ────
#
# The server pushes `agent_checks` in the heartbeat response; the agent evaluates
# them read-only and reports {id: {status, output}} in sysinfo.custom_check_results.
# The Windows agent never did this, so every file/job/log/service custom check
# silently reported "unknown" on Windows. Portable types (file_present/absent,
# job_fresh) work as-is; `windows_service` is the Windows analogue of systemd_unit;
# `log_errors` matches against the Event Log in Python (never passing the operator
# regex into PowerShell).
_watched_agent_checks = []      # pushed by the server each heartbeat


def _eval_one_agent_check_win(c):
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
    if ctype == 'windows_service':
        # Read-only Get-Service; the name is a single-quoted PS literal (no shell,
        # nothing to inject). Running → ok, Start/StopPending → warning, else crit.
        if not param.strip():
            return 'unknown', 'no service'
        ps = (f"$ErrorActionPreference='SilentlyContinue';"
              f"$s=Get-Service -Name {_ps_single_quote(param)};"
              f"if($s){{$s.Status.ToString()}}else{{'NotFound'}}")
        try:
            r = subprocess.run([_powershell_bin(), '-NoProfile', '-NonInteractive', '-Command', ps],
                               capture_output=True, text=True, timeout=20,
                               creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            state = (r.stdout or '').strip().lower()
        except Exception:
            return 'unknown', 'query failed'
        if state == 'running':
            return 'ok', 'running'
        if state in ('startpending', 'continuepending'):
            return 'warning', state
        if state == 'notfound' or not state:
            return 'critical', 'not found'
        return 'critical', state
    if ctype == 'log_errors':
        # Match an operator regex against the recent Event Log. The regex is
        # applied in PYTHON (re) over JSON events, never interpolated into
        # PowerShell — so there is nothing to inject through the pattern.
        if not param:
            return 'unknown', 'no pattern'
        try:
            window = int(c.get('window_min', 15))
            warn = int(c.get('warn', 1))
            crit = int(c.get('crit', 10))
        except (TypeError, ValueError):
            window, warn, crit = 15, 1, 10
        ps = ("$ErrorActionPreference='SilentlyContinue';"
              f"Get-WinEvent -FilterHashtable @{{LogName='System','Application';"
              f" StartTime=(Get-Date).AddMinutes(-{window})}} -MaxEvents 5000 | "
              "ForEach-Object { ($_.Message -replace '\\s+',' ') }")
        try:
            r = subprocess.run([_powershell_bin(), '-NoProfile', '-NonInteractive', '-Command', ps],
                               capture_output=True, text=True, timeout=30,
                               creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        except Exception:
            return 'unknown', 'query failed'
        try:
            rx = re.compile(param)
        except re.error:
            return 'unknown', 'bad pattern'
        n = sum(1 for ln in (r.stdout or '').splitlines() if ln.strip() and rx.search(ln))
        status = 'critical' if n >= crit else 'warning' if n >= warn else 'ok'
        return status, f'{n} match(es) in {window}min'
    # systemd_unit and anything else is not applicable on Windows.
    return 'unknown', 'not applicable on Windows'


def eval_agent_checks(checks):
    """Evaluate every server-pushed agent-side check → {id: {status, output}}."""
    out = {}
    for c in checks or []:
        if not isinstance(c, dict) or not c.get('id'):
            continue
        try:
            status, output = _eval_one_agent_check_win(c)
        except Exception:
            status, output = 'unknown', 'error'
        out[c['id']] = {'status': status, 'output': str(output)[:200]}
    return out


# ── v6.2.0: Windows security posture → the Checks catalog ─────────────────────
#
# The RMM check-library staples that have no Linux equivalent, gathered into one
# sysinfo sub-dict so the server's Checks engine can render them as first-class
# check rows (BitLocker, Windows Firewall per profile, Defender real-time +
# signature age, the Windows Update service). One PowerShell call; the whole
# projection is parse- and shape-validated against the real pwsh in tests.
_WIN_POSTURE_PS = (
    "$ErrorActionPreference='SilentlyContinue';"
    "$fw=@(Get-NetFirewallProfile | ForEach-Object { @{name=$_.Name; enabled=[bool]$_.Enabled} });"
    "$bl=@(Get-BitLockerVolume | Where-Object { $_.VolumeType -eq 'OperatingSystem' } | "
    "  ForEach-Object { @{mount=$_.MountPoint; status=$_.ProtectionStatus.ToString()} });"
    "$def=Get-MpComputerStatus;"
    "$wu=Get-Service -Name wuauserv;"
    "[pscustomobject]@{"
    "  firewall=$fw; bitlocker=$bl;"
    "  defender_realtime=[bool]$def.RealTimeProtectionEnabled;"
    "  defender_sig_age_days=[int]$def.AntivirusSignatureAge;"
    "  wu_service=$wu.Status.ToString()"
    "} | ConvertTo-Json -Compress -Depth 4"
)


def get_win_posture():
    """Windows security-posture signals for the Checks catalog, or {}. Off-Win {}."""
    if not sys.platform.startswith('win'):
        return {}
    try:
        r = subprocess.run([_powershell_bin(), '-NoProfile', '-NonInteractive', '-Command', _WIN_POSTURE_PS],
                           capture_output=True, text=True, timeout=45,
                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except Exception:
        return {}
    if r.returncode != 0:
        return {}
    return _parse_win_posture(r.stdout)


def _parse_win_posture(stdout):
    """The posture JSON → a compact, sanitized sysinfo sub-dict. Pure/testable."""
    try:
        o = json.loads((stdout or '').strip() or '{}')
    except Exception:
        return {}
    if not isinstance(o, dict):
        return {}
    out = {}
    fw = o.get('firewall')
    if isinstance(fw, dict):        # single profile → object, not array
        fw = [fw]
    if isinstance(fw, list):
        out['firewall'] = [{'name': str(p.get('name') or '')[:32], 'enabled': bool(p.get('enabled'))}
                           for p in fw if isinstance(p, dict)][:8]
    bl = o.get('bitlocker')
    if isinstance(bl, dict):
        bl = [bl]
    if isinstance(bl, list):
        out['bitlocker'] = [{'mount': str(v.get('mount') or '')[:8], 'status': str(v.get('status') or '')[:24]}
                            for v in bl if isinstance(v, dict)][:8]
    if 'defender_realtime' in o:
        out['defender_realtime'] = bool(o.get('defender_realtime'))
    age = o.get('defender_sig_age_days')
    if isinstance(age, (int, float)) and 0 <= age < 100000:
        out['defender_sig_age_days'] = int(age)
    if o.get('wu_service'):
        out['wu_service'] = str(o.get('wu_service'))[:24]
    return out


# ── v6.2.0: config drift — watched-file hashing (parity, OS-agnostic) ─────────
MAX_DRIFT_FILES = 200


def compute_drift_report(paths):
    """sha256 each watched file → {path: {hash, size, mtime, exists}}. Identical
    contract to the Linux agent; pure file I/O, so it is genuinely OS-agnostic."""
    out = {}
    for p in (paths or [])[:MAX_DRIFT_FILES]:
        try:
            st = os.stat(p)
        except FileNotFoundError:
            out[p] = {'hash': None, 'size': None, 'mtime': None, 'exists': False}
            continue
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


# ── v6.2.0: containers via the docker CLI (parity) ────────────────────────────
def get_containers():
    """`docker ps` listing (Docker Desktop / Windows containers), or []. The
    server's containers.normalize_listing consumes the raw `{{json .}}` lines, so
    this just needs to produce them. Feature-invisible when docker isn't present."""
    docker = _winshell_which('docker')
    if not docker:
        return []
    try:
        r = subprocess.run([docker, 'ps', '--no-trunc', '--format', '{{json .}}'],
                           capture_output=True, text=True, timeout=15,
                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except Exception:
        return []
    if r.returncode != 0:
        return []
    out = []
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
        if len(out) >= 100:
            break
    return out


def _winshell_which(name):
    """Absolute path to a PATH tool (docker) via the absolute where.exe, or None.
    Same hijack-safe resolution as _winget_bin, but returns None when absent so a
    collector can cheaply no-op rather than invoking a bare name."""
    try:
        r = subprocess.run([_system_bin('where'), name],
                           capture_output=True, text=True, timeout=10,
                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        for line in (r.stdout or '').splitlines():
            cand = line.strip()
            if cand and os.path.exists(cand):
                return cand
    except Exception:
        pass
    return None


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
        # v6.2.0: top processes + proc_names (the latter unblocks the server-side
        # `process` custom-check type, which read sysinfo.proc_names — empty on
        # Windows until now, so every process check reported 'unknown').
        try:
            top, names = get_top_processes()
            if top:
                payload['sysinfo']['top_processes'] = top
            if names:
                payload['sysinfo']['proc_names'] = names
        except Exception:
            pass
        journal = get_event_log_journal()      # Event Log tail → Logs page
        if journal:
            payload['journal'] = journal
        accounts = get_local_accounts()        # local users → account audit card
        if accounts:
            payload['accounts'] = accounts
        # v6.2.0: SMART + hardware inventory (parity) — feed the existing
        # _ingest_hardware pipeline (failure prediction, wear trend, asset page).
        try:
            smart = get_smart_status()
            if smart:
                payload['smart'] = smart
        except Exception:
            pass
        try:
            hw = get_hardware_inventory()
            if hw:
                payload['hardware'] = hw
        except Exception:
            pass
        # v6.2.0: containers (Docker Desktop / Windows containers), if present.
        try:
            containers = get_containers()
            if containers:
                payload['containers'] = containers
        except Exception:
            pass
        gpus = get_gpu_status()                 # NVIDIA GPU telemetry → fleet GPU page
        if gpus:
            payload['gpus'] = gpus
        # v6.2.0: Defender AV posture. TOP-LEVEL 'av' (not sysinfo) — the server
        # ingests it via _ingest_av, which is not part of the safe_si sysinfo
        # whitelist. Rides the slow sysinfo cadence: the WMI/COM call is not free.
        av = get_defender_status()
        if av:
            payload['av'] = av
    # v3.14.0 #35: opt-in secrets scan on its own ~6h cadence (config from the
    # previous heartbeat response, stashed in _secrets_cfg by heartbeat_once).
    if _secrets_cfg.get('on') and (poll_count <= 1 or poll_count % SECRETS_SCAN_EVERY == 0):
        try:
            payload['secret_findings'] = collect_secret_findings(_secrets_cfg.get('paths'))
        except Exception:
            pass
    # v6.2.0: watched-service states, on the same slower cadence as sysinfo.
    if _watched_services and (poll_count <= 1 or poll_count % 12 == 0):
        try:
            svcs = get_services(_watched_services)
            if svcs:
                payload['services'] = svcs
        except Exception:
            pass
    # v6.2.0: config-drift report — hash the watched files on the sysinfo cadence.
    if _watched_files and (poll_count <= 1 or poll_count % 12 == 0):
        try:
            drift = compute_drift_report(_watched_files)
            if drift:
                payload['drift'] = drift
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
        # v6.2.0: watched services pushed by the server (parity with Linux).
        global _watched_services, _watched_files, _watched_agent_checks
        _sw = resp.get('services_watched')
        if isinstance(_sw, list):
            _watched_services = [str(s) for s in _sw if str(s).strip()][:50]
        # v6.2.0: watched files for drift (parity with the Linux agent).
        _wf = resp.get('watched_files')
        if isinstance(_wf, list):
            _watched_files = [str(f) for f in _wf if str(f).strip()][:MAX_DRIFT_FILES]
        # v6.2.0: agent-side custom checks pushed by the server.
        _ac = resp.get('agent_checks')
        if isinstance(_ac, list):
            _watched_agent_checks = [c for c in _ac if isinstance(c, dict) and c.get('id')][:100]
    return resp, new_pending


# ── v6.2.0: run as a real Windows service (services.msc) ──────────────────────
# Preferred over the scheduled task: the Service Control Manager restarts the
# agent on ANY exit (self-update, crash), it's visible/controllable in
# services.msc, and self-update becomes "just exit — SCM relaunches with the new
# file". Requires pywin32 (the installer pip-installs it); if it's unavailable
# the installer falls back to the scheduled task, so this is purely additive.
SVC_NAME = 'RemotePowerAgent'
SVC_DISPLAY = 'RemotePower Agent'
SVC_DESC = ('RemotePower fleet-monitoring agent: reports host telemetry and runs '
            'authorized commands. Auto-restarts and self-updates.')
_RUNNING_AS_SERVICE = False   # set True inside the SCM dispatch path


def _pywin32_available():
    try:
        import win32serviceutil  # noqa: F401
        import win32service       # noqa: F401
        import win32event         # noqa: F401
        import servicemanager     # noqa: F401
        return True
    except Exception:
        return False


def _service_installed():
    """True if the RemotePowerAgent Windows service is registered."""
    try:
        r = subprocess.run([_system_bin('sc'), 'query', SVC_NAME],
                           capture_output=True, timeout=15,
                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        return r.returncode == 0
    except Exception:
        return False


def _install_service():
    """Register + start the agent as a LocalSystem service with auto-start and
    SCM auto-restart on failure. Uses sc.exe (present on every Windows) for the
    registration; the service PROCESS speaks the SCM protocol via pywin32 in the
    --service-run path. Prints operator-facing progress (this is a CLI command)
    and returns rc."""
    _init_logging()
    if not _pywin32_available():
        msg = ('pywin32 is not installed - cannot run as a service '
               '(run: python -m pip install pywin32).')
        log.error(msg)
        print(msg, file=sys.stderr)
        return 1
    # Prefer the windowless interpreter so the service never flashes a console.
    exe = sys.executable or 'python.exe'
    pyw = os.path.join(os.path.dirname(exe), 'pythonw.exe')
    if os.path.exists(pyw):
        exe = pyw
    script = os.path.abspath(__file__)
    bin_path = f'"{exe}" "{script}" --service-run'
    sc = _system_bin('sc')

    def _sc(*args, timeout=30):
        return subprocess.run([sc, *args], capture_output=True, text=True,
                              timeout=timeout,
                              creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    try:
        # Clean slate: a stale/broken registration would make `create` fail.
        _sc('stop', SVC_NAME)
        _sc('delete', SVC_NAME)
        # sc.exe wants each option as `key=` followed by its value as a SEPARATE
        # token (`binPath= <value>`). Passing "binPath= <value>" as ONE argv token
        # makes Windows subprocess quoting mangle the nested quotes in the value
        # (the path + "--service-run"), so `create` silently failed. Keep the
        # `key=` and the value as distinct list elements.
        cr = _sc('create', SVC_NAME, 'binPath=', bin_path,
                 'start=', 'auto', 'obj=', 'LocalSystem', 'DisplayName=', SVC_DISPLAY)
        if cr.returncode != 0:
            msg = f'service registration failed: {(cr.stdout or cr.stderr or "").strip()}'
            log.error(msg)
            print(msg, file=sys.stderr)
            return 1
        _sc('description', SVC_NAME, SVC_DESC, timeout=15)
        # Auto-restart on any unexpected termination: wait 5s and restart; reset
        # the failure counter after a day of health.
        _sc('failure', SVC_NAME, 'reset=', '86400',
            'actions=', 'restart/5000/restart/5000/restart/5000', timeout=15)
        st = _sc('start', SVC_NAME)
    except Exception as e:
        log.error(f'service install failed: {e}')
        print(f'service install failed: {e}', file=sys.stderr)
        return 1
    if _service_running():
        print('RemotePower service installed and RUNNING (visible in services.msc '
              'as "RemotePower Agent").')
        log.info('service installed and started')
        return 0
    # Most common first-start failure is error 1053 — pywin32's service DLLs
    # (pywintypesXX.dll / pythonservceXX.exe) aren't registered. Self-heal: run
    # pywin32_postinstall once and retry, so the operator never has to. This is
    # what makes the service the reliable DEFAULT rather than a step people give
    # up on.
    if _register_pywin32_service_dlls():
        print('Registering pywin32 service support and retrying ...')
        try:
            st = _sc('start', SVC_NAME)
        except Exception:
            pass
        if _service_running():
            print('RemotePower service installed and RUNNING (visible in services.msc '
                  'as "RemotePower Agent").')
            log.info('service installed and started after pywin32 postinstall')
            return 0
    detail = (st.stdout or st.stderr or '').strip()
    msg = ('RemotePower service was registered but did not reach RUNNING. '
           f'sc start said: {detail or "(no output)"}. Check '
           r'C:\ProgramData\RemotePower\agent.log for a traceback.')
    log.error(msg)
    print(msg, file=sys.stderr)
    return 1


def _register_pywin32_service_dlls():
    """Run pywin32_postinstall.py -install, which copies pywin32's service DLLs
    (pywintypes/pythoncom/pythonservice) where the SCM can load them — the fix for
    the classic service error 1053. Best-effort; returns True if it ran."""
    exe = sys.executable or 'python.exe'
    cands = [
        os.path.join(os.path.dirname(exe), 'Scripts', 'pywin32_postinstall.py'),
        os.path.join(sys.prefix, 'Scripts', 'pywin32_postinstall.py'),
    ]
    script = next((p for p in cands if os.path.exists(p)), None)
    try:
        if script:
            subprocess.run([exe, script, '-install', '-quiet'],
                           capture_output=True, timeout=120,
                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        else:
            # Fallback: invoke it as a module (works on newer pywin32).
            subprocess.run([exe, '-m', 'pywin32_postinstall', '-install', '-quiet'],
                           capture_output=True, timeout=120,
                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        return True
    except Exception as e:
        log.warning(f'pywin32_postinstall failed: {e}')
        return False


def _service_running():
    """True if the service is registered AND in the RUNNING state."""
    try:
        r = subprocess.run([_system_bin('sc'), 'query', SVC_NAME],
                           capture_output=True, text=True, timeout=15,
                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        return r.returncode == 0 and 'RUNNING' in (r.stdout or '')
    except Exception:
        return False


def _uninstall_service():
    sc = _system_bin('sc')
    for args in (['stop', SVC_NAME], ['delete', SVC_NAME]):
        try:
            subprocess.run([sc, *args], capture_output=True, timeout=30,
                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        except Exception:
            pass
    print('RemotePower service stopped and removed (if it was present).')
    return 0


def _service_run():
    """SCM entry point (the service's binPath runs `--service-run`). Hosts the
    service class in THIS process via the standalone servicemanager dispatch, so
    no separate pythonservice.exe is needed."""
    global _RUNNING_AS_SERVICE
    _RUNNING_AS_SERVICE = True
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager

    class RemotePowerService(win32serviceutil.ServiceFramework):
        _svc_name_ = SVC_NAME
        _svc_display_name_ = SVC_DISPLAY
        _svc_description_ = SVC_DESC

        def __init__(self, args):
            super().__init__(args)
            self._stop_evt = win32event.CreateEvent(None, 0, 0, None)

        def SvcStop(self):
            # Tell the SCM we're stopping and give it a generous wait hint, so
            # services.msc / Stop-Service does NOT declare "could not stop in a
            # timely fashion" if a heartbeat happens to be in flight. The poll
            # sleep (where the agent spends ~all its time) is interruptible, so
            # stop is usually immediate; a mid-heartbeat stop waits at most one
            # HTTP timeout.
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING,
                                     waitHint=(HTTP_TIMEOUT + 5) * 1000)
            win32event.SetEvent(self._stop_evt)

        # A machine shutdown should stop the agent cleanly too.
        SvcShutdown = SvcStop

        def SvcDoRun(self):
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)

            def _should_stop():
                return win32event.WaitForSingleObject(self._stop_evt, 0) == win32event.WAIT_OBJECT_0

            def _wait(seconds):
                # Interruptible sleep: returns immediately when SvcStop signals.
                win32event.WaitForSingleObject(self._stop_evt, int(seconds * 1000))
            try:
                run(should_stop=_should_stop, wait=_wait)
            except Exception as e:   # never let the service crash without a trace
                try:
                    servicemanager.LogErrorMsg(f'RemotePower agent crashed: {e}')
                except Exception:
                    pass

    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(RemotePowerService)
    servicemanager.StartServiceCtrlDispatcher()
    return 0


def run(should_stop=None, wait=None):
    """The heartbeat loop. `should_stop()` (optional) is polled each iteration and
    `wait(seconds)` (optional) replaces time.sleep — the Windows service passes an
    event-backed wait so a service STOP interrupts the poll sleep promptly instead
    of hanging up to a full interval."""
    wait = wait or time.sleep
    _init_logging()
    log.info(f'RemotePower Windows agent v{VERSION} starting')
    poll_count = 0
    pending = None
    while True:
        if should_stop and should_stop():
            log.info('stop requested - exiting run loop')
            return 0
        creds = load_creds()
        if not creds.get('device_id'):
            log.error('not enrolled - run with --enroll first')
            return 1
        poll_count += 1
        try:
            _resp, pending = heartbeat_once(creds, poll_count, pending)
        except Exception as e:
            log.warning(f'heartbeat error: {e}')
        wait(max(10, int(load_creds().get('poll_interval', DEFAULT_POLL))))


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
    # v6.2.0: Windows-service lifecycle (services.msc).
    ap.add_argument('--service-run', action='store_true',
                    help=argparse.SUPPRESS)        # SCM entry point (internal)
    ap.add_argument('--install-service', action='store_true')
    ap.add_argument('--uninstall-service', action='store_true')
    a = ap.parse_args(argv)
    if a.version:
        print(VERSION)
        return 0
    if a.service_run:
        return _service_run() or 0
    if a.install_service:
        return _install_service()
    if a.uninstall_service:
        return _uninstall_service()
    if a.enroll:
        if not a.server or not (a.pin or a.token):
            ap.error('--enroll needs --server and --pin (or --token)')
        # A 6-digit value passed to --token is almost always a PIN — the server
        # would reject it as a bad token; catch it here with a readable hint.
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

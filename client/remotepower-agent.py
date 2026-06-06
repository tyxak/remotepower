#!/usr/bin/env python3
"""
remotepower-agent  -  Client-side daemon for RemotePower v1.8.6
Polls the RemotePower server at a configurable interval (default 60s).
On first run (or if not enrolled), prompts for server URL + PIN and registers.

Config file: /etc/remotepower/agent.conf
Credentials: /etc/remotepower/credentials   (mode 600, root only)
"""

import os
import re
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
import threading
from pathlib import Path
from urllib import request, error

CONF_DIR     = Path('/etc/remotepower')
CREDS_FILE   = CONF_DIR / 'credentials'
PKG_HASH_FILE = CONF_DIR / 'pkg_hash'
LOG_FILE     = '/var/log/remotepower-agent.log'
VERSION      = '3.14.0'
AGENT_BINARY = Path('/usr/local/bin/remotepower-agent')

# v3.4.2: sha256 of our own on-disk binary, computed once and cached. Reported
# on every heartbeat so the server can attest the running agent matches the
# canonical copy it serves (tamper / partial-update / corruption detection).
_AGENT_SELF_SHA = None
def _agent_self_sha256():
    global _AGENT_SELF_SHA
    if _AGENT_SELF_SHA is None:
        try:
            _AGENT_SELF_SHA = hashlib.sha256(AGENT_BINARY.read_bytes()).hexdigest()
        except Exception:
            _AGENT_SELF_SHA = ''
    return _AGENT_SELF_SHA


# v3.4.2: cryptographic release-signature verification (opt-in, fail-closed).
# Pin the release PUBLIC key here and the agent will refuse any self-update
# whose detached signature doesn't verify against it — defending against a
# compromised server that swaps both the binary and its advertised hash.
RELEASE_PUBKEY_FILE = CONF_DIR / 'release.pub'


def _release_pubkey():
    """Armored release public key pinned on this host, or None (→ no enforcement)."""
    try:
        if RELEASE_PUBKEY_FILE.exists():
            txt = RELEASE_PUBKEY_FILE.read_text().strip()
            return txt or None
    except Exception:
        pass
    return None


# v3.8.0: hard opt-in to fail-closed self-update. Touch
# /etc/remotepower/require-signed-updates and the agent refuses to self-update
# unless a release.pub is pinned AND the download carries a valid signature —
# closing the default fail-open window where a compromised server (which dictates
# both the binary and its advertised sha256) could push root RCE.
REQUIRE_SIGNED_FILE = CONF_DIR / 'require-signed-updates'


def _require_signed_updates():
    try:
        return REQUIRE_SIGNED_FILE.exists()
    except Exception:
        return False


def _verify_detached_sig(data_bytes, sig_text, pubkey_armored, expected_fpr=''):
    """Verify a detached signature over data_bytes using an ephemeral gpg keyring
    seeded only with the pinned public key. Returns (ok, detail). Fails closed.
    Mirrors the server's _gpg_verify_detached — no Python crypto dependency."""
    gpg = shutil.which('gpg')
    if not gpg:
        return False, 'gpg not available'
    home = tempfile.mkdtemp(prefix='rp-relverify-')
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
        shutil.rmtree(home, ignore_errors=True)

# v3.0.2: agent state directory. Used for files that should survive a
# /tmp wipe (boot-reason marker, poll interval override) and that must
# NOT be writable by non-root users. Previously these lived in /tmp/
# which is world-writable — a local attacker could symlink the path to
# /etc/passwd before the agent's write, or stuff fake content for the
# agent to read on the next heartbeat. /var/lib/remotepower exists on
# every install (server data dir, but the agent also creates it if
# missing as a defense against running before the server was set up).
STATE_DIR = Path('/var/lib/remotepower')

POLL_INTERVAL      = 60
SYSINFO_EVERY      = 10
PATCH_EVERY        = 180
UPDATE_CHECK_EVERY = 60
PACKAGE_LIST_EVERY = 360          # ≈ 6 hours at 60s poll
MAX_PACKAGES_SEND  = 10000        # matches server-side cap

# v2.2.0: configuration drift detection. Hash a small list of watched
# files every DRIFT_EVERY polls (~1 hour at 60s) and ship the hashes to
# the server. The server compares against its stored baseline. Cheap:
# typical watched list has 5-15 small files (sshd_config, sudoers etc.),
# total hashing time well under 100 ms.
DRIFT_EVERY        = 60
MAX_DRIFT_FILES    = 200          # matches server-side cap; defends
                                  # against an over-eager watched list
MAX_FILE_SIZE_HASH = 5 * 1024 * 1024   # don't try to hash files >5MB

# v2.4.3: mailbox-count monitor. Counting files in a directory is very
# cheap, but a directory with a huge backlog could be slow to scandir,
# so report every few polls rather than every poll.
MAILBOX_CHECK_EVERY = 5           # ~5 minutes at the default interval
MAX_MAILBOX_PATHS   = 20          # matches the server-side cap

# v1.8.0: service monitoring + log tail
SERVICE_CHECK_EVERY = 1           # every poll — cheap
# v2.5.0: custom monitoring scripts run every 5 polls (5 minutes at default 60s)
SCRIPT_CHECK_EVERY  = 5
HOST_CONFIG_COLLECT_EVERY = 15  # v2.6.0: collect+report host config state every 15 polls
LOG_SUBMIT_EVERY    = 5           # every 5 polls — batches a few minutes of logs
MAX_LOG_LINES_PER_UNIT = 100      # matches server-side cap
LOG_LOOKBACK_SECONDS   = 360      # capture the last 6 minutes on each submission

# v2.7.0: units auto-added to the watched list if they exist on this host.
# The server's services_watched config overrides; these are additive defaults
# that ensure useful logs flow without any manual configuration.
AUTO_WATCH_UNITS = [
    'remotepower-agent.service',
    'nginx.service',
    'apache2.service',
    'ssh.service',
    'sshd.service',
]

# v2.7.0: dmesg / apt history log collection
DMESG_LOG_LOOKBACK_HOURS = 24     # window on first run; incremental thereafter
DMESG_MAX_LINES          = 100    # kernel errors/warnings per submission
APT_HISTORY_MAX_LINES    = 200    # apt history lines per submission

# v2.8.0: web access log paths for brute-force detection (nginx/apache2).
WEB_ACCESS_LOGS = [
    ('/var/log/nginx/access.log',   'nginx.access'),
    ('/var/log/apache2/access.log', 'apache2.access'),
]
WEB_ACCESS_MAX_LINES = 500   # per submission

# v1.11.0: container/pod listing — sent every 5 polls (~5 minutes at default
# 60s interval). Cheap when no runtime is installed (immediate empty return);
# bounded to ~1s when Docker/Podman/k8s are present.
CONTAINER_CHECK_EVERY = 5
# v3.0.1: scan ~/.acme.sh once an hour by default. Cert state changes only
# when acme.sh's own cron runs (typically once daily) or after a manual
# action — no need to re-walk the directory every minute.
ACME_CHECK_EVERY = 60

# Metrics collection requires psutil (optional - gracefully skipped if absent)
try:
    import psutil as _psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False

def _agent_file_log_handler():
    """v3.12.0: size-capped rotating log so /var/log/remotepower-agent.log can't
    grow unbounded — 5 MB × 5 backups (~25 MB total), self-rotating so no
    logrotate/cron is required. NullHandler when not root (can't write /var/log)
    or if the rotating handler can't be created."""
    try:
        if os.geteuid() != 0:
            return logging.NullHandler()
    except AttributeError:           # non-POSIX (no geteuid) — skip file log
        return logging.NullHandler()
    try:
        from logging.handlers import RotatingFileHandler
        return RotatingFileHandler(
            LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5)
    except Exception:
        return logging.NullHandler()


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        _agent_file_log_handler(),
    ]
)
log = logging.getLogger('remotepower')

import ssl as _ssl

# ─── SSL context ────────────────────────────────────────────────────────────────
def _make_ssl_context():
    """Return a strict SSL context - certificate verification always on."""
    ctx = _ssl.create_default_context()
    ctx.verify_mode = _ssl.CERT_REQUIRED
    ctx.check_hostname = True
    return ctx

_SSL_CTX = _make_ssl_context()

def _strip_url_scheme(url: str) -> str:
    """Remove a leading http:// or https:// scheme from a URL.

    Replaces a long-standing bug: `url.lstrip('http://').lstrip('https://')`
    looked plausible but lstrip strips any CHARACTER in the argument from
    the start, not the literal prefix. For `'httpserver.com'`, the old
    code stripped 'h','t','t','p' (all in the char-set 'h','t','p',':','/')
    and produced `'server.com'` — wrong. For `'https://example.com'` it
    happened to work by accident.
    """
    for scheme in ('https://', 'http://'):
        if url.lower().startswith(scheme):
            return url[len(scheme):]
    return url


# ─── HTTP helpers ───────────────────────────────────────────────────────────────
def http_post(url, data, timeout=10):
    if not url.startswith('https://'):
        raise ValueError(f"Server URL must use HTTPS, got: {url[:32]}")
    body = json.dumps(data).encode()
    req = request.Request(url, data=body,
        headers={'Content-Type': 'application/json',
                 'User-Agent': f'RemotePower-Agent/{VERSION}'})
    with request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
        return json.loads(resp.read(1024 * 1024))  # cap at 1 MB

def http_get(url, timeout=10):
    if not url.startswith('https://'):
        raise ValueError(f"Server URL must use HTTPS, got: {url[:32]}")
    req = request.Request(url, headers={'User-Agent': f'RemotePower-Agent/{VERSION}'})
    with request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
        return json.loads(resp.read(1024 * 1024))

def http_get_binary(url, timeout=30):
    if not url.startswith('https://'):
        raise ValueError(f"Server URL must use HTTPS, got: {url[:32]}")
    req = request.Request(url, headers={'User-Agent': f'RemotePower-Agent/{VERSION}'})
    with request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
        return resp.read(64 * 1024 * 1024)  # cap at 64 MB

# ─── Credentials ───────────────────────────────────────────────────────────────
def load_credentials():
    if not CREDS_FILE.exists():
        return None
    try:
        data = json.loads(CREDS_FILE.read_text())
        if data.get('device_id') and data.get('token') and data.get('server_url'):
            return data
    except Exception:
        pass
    return None

def _safe_state_write(name: str, content: str) -> None:
    """Write a small marker file to STATE_DIR if possible, else /tmp/.

    The /tmp/ fallback uses O_NOFOLLOW + O_EXCL to defeat symlink attacks.
    If a file or symlink already exists at the /tmp/ path, we unlink it
    first (root can; this races against an attacker but losing the race
    leaves us writing to the attacker's location with O_NOFOLLOW failing
    safely — no security consequence).
    """
    primary = STATE_DIR / name
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(str(primary),
                     os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                     0o600)
        try:
            os.write(fd, content.encode())
        finally:
            os.close(fd)
        return
    except (PermissionError, OSError):
        pass
    # Fallback for non-root deploys (rare). Unlink any existing path
    # (symlink or file) so we start clean, then create with O_EXCL.
    fallback = Path('/tmp/remotepower-' + name)
    try:
        fallback.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        return
    try:
        fd = os.open(str(fallback),
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600)
        try:
            os.write(fd, content.encode())
        finally:
            os.close(fd)
    except OSError as e:
        log.warning(f'_safe_state_write({name}): both STATE_DIR and /tmp failed: {e}')


def _safe_state_read(name: str) -> str | None:
    """Read a marker file from STATE_DIR (preferred) or /tmp/, with
    O_NOFOLLOW so a pre-placed symlink can't redirect the read. Returns
    None if neither exists or both fail."""
    for cand in (STATE_DIR / name, Path('/tmp/remotepower-' + name)):
        try:
            fd = os.open(str(cand), os.O_RDONLY | os.O_NOFOLLOW)
            try:
                return os.read(fd, 4096).decode(errors='replace')
            finally:
                os.close(fd)
        except FileNotFoundError:
            continue
        except OSError:
            continue
    return None


def _safe_state_unlink(name: str) -> None:
    """Best-effort unlink of marker file in either location."""
    for cand in (STATE_DIR / name, Path('/tmp/remotepower-' + name)):
        try:
            cand.unlink()
        except (FileNotFoundError, OSError):
            pass


def save_credentials(creds):
    CONF_DIR.mkdir(parents=True, exist_ok=True)
    # v3.0.2: lock the directory to 0700 so a local non-root attacker
    # can't enumerate the credentials file or set up symlink attacks
    # inside the dir. mkdir's mode arg is only honoured at CREATE time,
    # so chmod unconditionally to handle the case where the dir already
    # exists with a looser mode from an older install.
    try:
        CONF_DIR.chmod(0o700)
    except OSError as e:
        log.warning(f'chmod {CONF_DIR} failed: {e}')
    # v3.0.2: atomic write. Previously was write_text → chmod, which
    # leaves the file at default umask (typically 0644) between the two
    # calls. A local non-root attacker could open the file for reading
    # in that window and exfiltrate the enrollment token. Now we open
    # with O_CREAT|O_EXCL|O_NOFOLLOW so the file is created with mode
    # 0600 atomically (and a pre-placed symlink with the same name
    # fails the open instead of redirecting it).
    try:
        CREDS_FILE.unlink()    # remove any prior file/symlink
    except FileNotFoundError:
        pass
    fd = os.open(str(CREDS_FILE),
                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600)
    try:
        os.write(fd, json.dumps(creds, indent=2).encode())
    finally:
        os.close(fd)
    log.info(f"Credentials saved to {CREDS_FILE}")

# ─── System info ───────────────────────────────────────────────────────────────
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]; s.close(); return ip
    except Exception:
        return '127.0.0.1'

def get_os_info():
    try:
        with open('/etc/os-release') as f:
            for line in f:
                if line.startswith('PRETTY_NAME='):
                    return line.split('=', 1)[1].strip().strip('"')
    except Exception:
        pass
    return platform.system() + ' ' + platform.release()

def get_mac():
    try:
        out = subprocess.check_output(['ip', 'route', 'get', '8.8.8.8'], text=True, timeout=3)
        parts = out.split()
        if 'dev' in parts:
            iface = parts[parts.index('dev') + 1]
            addr = Path(f'/sys/class/net/{iface}/address')
            if addr.exists(): return addr.read_text().strip()
    except Exception:
        pass
    return ''

def get_network_info():
    interfaces = []
    try:
        out = subprocess.check_output(['ip', '-j', 'addr'], text=True, timeout=5)
        for iface in json.loads(out):
            name = iface.get('ifname', '')
            if name == 'lo' or not iface.get('addr_info'): continue
            mac = iface.get('address', '')
            for addr in iface.get('addr_info', []):
                if addr.get('family') == 'inet':
                    interfaces.append({'iface': name, 'ip': addr.get('local', ''), 'mac': mac})
    except Exception:
        pass
    return interfaces

def get_uptime():
    try:
        return subprocess.check_output(['uptime', '-p'], text=True).strip()
    except Exception:
        return ''

def get_journal(lines=100):
    noisy = {'pipewire', 'pipewire-pulse', 'wireplumber', 'audit', 'dbus-daemon', 'systemd-networkd'}
    try:
        out = subprocess.check_output(
            ['journalctl', '-n', str(lines * 3), '--no-pager', '--output=short-iso', '--no-hostname'],
            text=True, stderr=subprocess.DEVNULL, timeout=10)
        filtered = [l for l in out.strip().splitlines() if not any(n in l for n in noisy)]
        return filtered[-lines:]
    except Exception:
        return []

_MAX_UPGRADABLE_NAMES = 300
def _parse_upgradable_names(manager, text):
    """v3.4.2: extract upgradable package names so the server can build a
    fleet-wide patch catalog ("package X pending on N hosts"). Best-effort,
    deduped + sorted + capped; an empty list just means we couldn't parse."""
    names = []
    for line in (text or '').splitlines():
        s = line.strip()
        if not s:
            continue
        if manager == 'apt':
            if line.startswith('Inst ') and len(line.split()) > 1:
                names.append(line.split()[1])
        elif manager == 'dnf':
            if line.startswith(' ') or s.startswith(('Last', 'Obsoleting')):
                continue
            tok = s.split()[0]
            names.append(tok.rsplit('.', 1)[0] if '.' in tok else tok)
        elif manager == 'pacman':
            names.append(s.split()[0])
    return sorted(set(names))[:_MAX_UPGRADABLE_NAMES]


def get_patch_info():
    result = {'manager': 'unknown', 'upgradable': None}
    # v3.4.2: non-OS package managers (flatpak/snap/pip/npm). Same periodic
    # cadence as the OS patch check; absent managers are simply omitted.
    try:
        tp = get_third_party_updates()
        if tp:
            result['third_party'] = tp
    except Exception:
        pass
    if Path('/usr/bin/apt-get').exists():
        result['manager'] = 'apt'
        try:
            out = subprocess.check_output(['apt-get', '--simulate', '--quiet', 'upgrade'],
                text=True, timeout=30, stderr=subprocess.DEVNULL)
            result['upgradable'] = sum(1 for l in out.splitlines() if l.startswith('Inst '))
            result['upgradable_names'] = _parse_upgradable_names('apt', out)
        except Exception: pass
    elif Path('/usr/bin/dnf').exists() or Path('/usr/bin/dnf5').exists():
        result['manager'] = 'dnf'
        try:
            out = subprocess.check_output(['dnf', 'check-update', '--quiet'],
                text=True, timeout=30, stderr=subprocess.DEVNULL)
            result['upgradable'] = sum(1 for l in out.splitlines() if l and not l.startswith(' ') and not l.startswith('Last'))
            result['upgradable_names'] = _parse_upgradable_names('dnf', out)
        except subprocess.CalledProcessError as e:
            if e.returncode == 100 and e.output:
                result['upgradable'] = sum(1 for l in e.output.splitlines() if l and not l.startswith(' ') and not l.startswith('Last'))
                result['upgradable_names'] = _parse_upgradable_names('dnf', e.output)
        except Exception: pass
    # v3.0.1: yum (RHEL 7, older CentOS) — same rpm-based ecosystem as dnf.
    # Report manager='dnf' so the OSV ecosystem detection (Rocky/Alma/Red Hat)
    # and CVE scanning paths Just Work — only the status check differs.
    elif Path('/usr/bin/yum').exists():
        result['manager'] = 'dnf'
        try:
            out = subprocess.check_output(['yum', 'check-update', '--quiet'],
                text=True, timeout=30, stderr=subprocess.DEVNULL)
            # yum check-update format: pkg-name.arch  version  repo  (one per line)
            # skip blank lines and the "Obsoleting Packages" section
            result['upgradable'] = sum(
                1 for l in out.splitlines()
                if l.strip() and not l.startswith(' ') and not l.startswith('Obsoleting'))
            result['upgradable_names'] = _parse_upgradable_names('dnf', out)
        except subprocess.CalledProcessError as e:
            if e.returncode == 100 and e.output:
                result['upgradable'] = sum(
                    1 for l in e.output.splitlines()
                    if l.strip() and not l.startswith(' ') and not l.startswith('Obsoleting'))
                result['upgradable_names'] = _parse_upgradable_names('dnf', e.output)
        except Exception: pass
    elif Path('/usr/bin/pacman').exists():
        result['manager'] = 'pacman'
        # v3.0.1: pacman 7+ runs downloads as the unprivileged "alpm" sandbox
        # user. On CachyOS and some Arch derivatives, that user isn't usable
        # and `pacman -Sy` fails with "switching to sandbox user failed",
        # which the previous version silently swallowed and reported as
        # "0 upgradable" — making the host look fully patched when it wasn't.
        # Fix: detect --disable-sandbox support and use it; on real failure
        # leave upgradable=None so the UI shows "unknown" instead of "0".
        pacman_flags = []
        # v3.0.1 (iteration 4): --disable-sandbox is an -S operation flag,
        # so it lives in `pacman -S --help` not the top-level `pacman --help`.
        # Previous probe checked the wrong help text, returned False on
        # pacman 7, and CachyOS continued to silent-fail. Try -S --help
        # first; fall back to version parse if that doesn't list it.
        try:
            help_out = subprocess.check_output(['pacman', '-S', '--help'],
                text=True, timeout=5, stderr=subprocess.STDOUT)
            if '--disable-sandbox' in help_out:
                pacman_flags = ['--disable-sandbox']
        except Exception:
            pass
        if not pacman_flags:
            try:
                ver_out = subprocess.check_output(['pacman', '--version'],
                    text=True, timeout=5, stderr=subprocess.STDOUT)
                # First line: "Pacman v7.0.0 - libalpm v15.0.0"
                m = re.search(r'v(\d+)\.', ver_out.splitlines()[0] if ver_out else '')
                if m and int(m.group(1)) >= 7:
                    pacman_flags = ['--disable-sandbox']
            except Exception:
                pass
        try:
            subprocess.check_call(
                ['pacman', '-Sy', '--noconfirm', '--noprogressbar'] + pacman_flags,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60,
            )
        except subprocess.CalledProcessError as e:
            result['upgradable'] = None
            log.warning(f'pacman sync failed (rc={e.returncode}); patch status unknown')
            return result
        except Exception as e:
            result['upgradable'] = None
            log.warning(f'pacman patch check failed: {e}')
            return result
        try:
            out = subprocess.check_output(['pacman', '-Qu'], text=True, timeout=10,
                                          stderr=subprocess.DEVNULL)
            result['upgradable'] = len(out.strip().splitlines()) if out.strip() else 0
            result['upgradable_names'] = _parse_upgradable_names('pacman', out)
        except subprocess.CalledProcessError:
            # rc=1 with empty stdout is the normal "no upgrades available" path
            result['upgradable'] = 0
        except Exception as e:
            result['upgradable'] = None
            log.warning(f'pacman patch check failed: {e}')
    return result


# ─── v3.4.2: third-party (non-OS) package updates ─────────────────────────────

def _tp_count(cmd, parse, timeout=30):
    """Run `cmd`; return (count, names[]) via `parse(stdout)`, or (None, []) if
    the tool is missing / errors. Best-effort — never raises."""
    if not shutil.which(cmd[0]):
        return None, []
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
        names = parse(out) or []
        return len(names), names[:100]
    except Exception:
        return None, []


def get_third_party_updates():
    """Available updates from non-OS package managers (flatpak/snap/pip/npm).
    Each entry is {count, names} or omitted when the manager isn't present.
    Counts feed the patch catalog; the OS package manager stays separate."""
    result = {}

    def _flatpak(out):
        return [l.split('\t')[0].strip() for l in out.splitlines()
                if l.strip() and not l.lower().startswith('looking')]
    c, n = _tp_count(['flatpak', 'remote-ls', '--updates', '--columns=application'], _flatpak)
    if c is not None:
        result['flatpak'] = {'count': c, 'names': n}

    def _snap(out):
        lines = [l for l in out.splitlines() if l.strip()]
        # skip the "Name Version Rev ..." header; first column is the snap name
        return [l.split()[0] for l in lines[1:] if l.split()]
    c, n = _tp_count(['snap', 'refresh', '--list'], _snap)
    if c is not None:
        result['snap'] = {'count': c, 'names': n}

    def _pip(out):
        try:
            return [p.get('name', '') for p in json.loads(out or '[]')]
        except Exception:
            return []
    c, n = _tp_count(['pip', 'list', '--outdated', '--format=json'], _pip, timeout=45)
    if c is None:
        c, n = _tp_count(['pip3', 'list', '--outdated', '--format=json'], _pip, timeout=45)
    if c is not None:
        result['pip'] = {'count': c, 'names': n}

    def _npm(out):
        try:
            return list(json.loads(out or '{}').keys())
        except Exception:
            return []
    c, n = _tp_count(['npm', 'outdated', '-g', '--json'], _npm, timeout=45)
    if c is not None:
        result['npm'] = {'count': c, 'names': n}

    return result


# ─── v3.4.2: OpenSCAP (oscap) compliance scan ─────────────────────────────────
_SSG_DIRS = ('/usr/share/xml/scap/ssg/content', '/usr/local/share/xml/scap/ssg/content')
_oscap_running = threading.Lock()


def _find_ssg_datastream():
    """Pick the SCAP Security Guide datastream that best matches this host, or
    None. Returns a path string.

    Distro families: we try the host's own ID first, then ID_LIKE (so Ubuntu,
    which ships no ssg-ubuntu content on Debian repos, falls back to the
    ssg-debian* datastreams via ID_LIKE=debian).

    Version: SSG ships one datastream per major release (ssg-debian10/11/12-...).
    The host's major version often won't have an exact file (Debian 13, or a
    point release), so we pick the HIGHEST available version that is <= the
    host's major version — never a wildly mismatched lower one. If the host's
    version is newer than anything shipped, we take the newest available for that
    family rather than the alphabetical first (which was the bug: Debian 13 and
    Ubuntu both ended up on ssg-debian10)."""
    import re as _re
    osr = get_os_release()
    oid = (osr.get('ID') or '').lower()
    like = [x for x in (osr.get('ID_LIKE') or '').lower().split() if x]
    families = [f for f in ([oid] + like) if f]
    # Host major version as an int, e.g. "24.04" -> 24, "13" -> 13.
    host_major = None
    m = _re.match(r'(\d+)', (osr.get('VERSION_ID') or ''))
    if m:
        host_major = int(m.group(1))

    candidates = []
    for d in _SSG_DIRS:
        p = Path(d)
        if p.is_dir():
            candidates += [str(f) for f in p.glob('ssg-*-ds.xml')]
    if not candidates:
        return None

    def ver_in(base):
        # ssg-debian12-ds.xml -> 12 ; ssg-ubuntu2204-ds.xml -> 2204
        mm = _re.search(r'ssg-[a-z]+?(\d+)', base)
        return int(mm.group(1)) if mm else None

    for fam in families:
        fam_ds = [c for c in candidates if fam in os.path.basename(c).lower()]
        if not fam_ds:
            continue
        # exact major match wins
        if host_major is not None:
            exact = [c for c in fam_ds if ver_in(os.path.basename(c)) == host_major]
            if exact:
                return sorted(exact)[-1]
            # else highest version <= host major
            le = [(ver_in(os.path.basename(c)), c) for c in fam_ds]
            le = [(v, c) for (v, c) in le if v is not None and v <= host_major]
            if le:
                return max(le)[1]
        # no version info, or host newer than everything: take the newest in fam
        byver = [(ver_in(os.path.basename(c)) or -1, c) for c in fam_ds]
        return max(byver)[1]

    # No family match at all — last resort, newest datastream available.
    byver = [(ver_in(os.path.basename(c)) or -1, c) for c in candidates]
    return max(byver)[1]


def _full_profile_id(profile, datastream):
    """Accept a short profile ('cis', 'stig', 'pci-dss') or a full
    xccdf_..._profile_<x> id. Short ids map onto the SSG naming convention."""
    if profile.startswith('xccdf_'):
        return profile
    return f'xccdf_org.ssgproject.content_profile_{profile}'


def _oscap_profiles(datastream):
    """Return the short profile ids actually present in a datastream (best
    effort), so the UI can offer only profiles that exist for this host's OS and
    a failed scan can list the alternatives. Parses `oscap info` output; returns
    [] on any trouble.

    oscap's output format varies by version:
      - older:  "Profile: xccdf_org.ssgproject.content_profile_cis"
      - newer:  "Title: ...\\n  Id: xccdf_org.ssgproject.content_profile_cis"
    So we don't anchor on a line prefix — we extract every
    `..._profile_<short>` id we see, which covers both."""
    import re as _re
    try:
        info = subprocess.run(['oscap', 'info', datastream],
                              capture_output=True, text=True, timeout=60)
        out = (info.stdout or '') + (info.stderr or '')
    except Exception:
        return []
    profs = []
    for m in _re.finditer(r'content_profile_([A-Za-z0-9._-]+)', out):
        short = m.group(1)
        if short and short not in profs:
            profs.append(short)
    return profs[:40]


def _oscap_zero_reason(profile, datastream):
    """Explain why a scan evaluated 0 applicable rules. The usual cause is a
    host-OS vs SCAP-content mismatch: oscap's CPE applicability check marks every
    rule notapplicable when the datastream targets a different OS than the host
    (e.g. an Ubuntu box with only ssg-debian content installed). Name the package
    to install so the operator can actually fix it, rather than just '0%'."""
    import re as _re
    base = os.path.basename(datastream or '')
    osr = get_os_release()
    oid = (osr.get('ID') or '').lower()
    pretty = osr.get('PRETTY_NAME') or osr.get('ID') or 'this host'
    # oscap's CPE applicability check is distro+version specific, so a real match
    # needs the host's own id AND its major version in the datastream name. We
    # distinguish three 0-rule causes so the advice is actually correct:
    #   1. wrong distro entirely  (e.g. ssg-debian on an Ubuntu host)
    #   2. right distro, WRONG version (e.g. ssg-ubuntu2204 on Ubuntu 24.04) —
    #      the installed SSG is just too old/new for this release
    #   3. distro+version match, but the chosen profile selected nothing
    hostmajor = ''
    mm = _re.match(r'(\d+)', (osr.get('VERSION_ID') or ''))
    if mm:
        hostmajor = mm.group(1)
    # Ubuntu datastreams encode the version without a dot (ubuntu2404); compare
    # against the version with dots stripped too.
    verflat = (osr.get('VERSION_ID') or '').replace('.', '')
    id_in_base = bool(oid and oid in base)
    ver_in_base = bool((hostmajor and hostmajor in base) or (verflat and verflat in base))

    if id_in_base and not ver_in_base:
        # Case 2: right distro family, wrong release. Installing the same package
        # again won't help — the operator needs SSG content built for THIS
        # release (often a newer ssg-* package, a backport, or upstream SSG).
        return (f"no applicable rules: the installed content {base} is for a "
                f"different {oid} release than {pretty} — oscap treats every rule "
                f"as not-applicable. Install SCAP Security Guide content built for "
                f"this release (a newer ssg-* package providing an "
                f"ssg-{oid}{verflat or hostmajor}-ds.xml datastream), or scan a "
                f"host whose release the content matches.")
    if not id_in_base and base:
        # Case 1: wrong distro entirely. Name the right package per family.
        families = [oid] + [x for x in (osr.get('ID_LIKE') or '').lower().split() if x]
        if oid == 'ubuntu' or 'ubuntu' in families:
            pkg = 'ssg-debderived (provides ssg-ubuntu* content)'
        elif oid == 'debian' or 'debian' in families:
            pkg = 'ssg-debian (matching this Debian release)'
        elif oid in ('rhel', 'centos', 'fedora', 'rocky', 'almalinux') or 'rhel' in families or 'fedora' in families:
            pkg = 'scap-security-guide'
        else:
            pkg = 'the SCAP Security Guide content for your OS'
        return (f"no applicable rules: the only SCAP content here is {base}, which "
                f"targets a different OS than {pretty}. Install {pkg} so a matching "
                f"datastream is scanned.")
    # Case 3: content matches the OS but this profile selected nothing.
    return (f"profile '{profile}' evaluated no applicable rules on {pretty} "
            f"({base}). Try a profile with real coverage for this OS — e.g. "
            f"cis_level1_server on Ubuntu, or the ANSSI BP-028 profiles on Debian.")


_USG_PROFILES = ('cis_level1_server', 'cis_level1_workstation',
                 'cis_level2_server', 'cis_level2_workstation',
                 'stig')   # Ubuntu Security Guide (Canonical) profile names


def _run_usg_scan(profile):
    """On Ubuntu, prefer Canonical's `usg` (Ubuntu Security Guide) over raw
    oscap. usg ships CIS/STIG content built for the EXACT Ubuntu release (incl.
    24.04, where the distro ssg-ubuntu datastream lags), wraps oscap, and writes
    a standard XCCDF results XML we can parse. Returns a parsed result dict (with
    'available': True), or a dict with available=False+reason, or None if usg
    can't be used (so the caller falls back to plain oscap).

    `usg audit <profile>` writes /var/lib/usg/usg-results-<ts>.xml. We capture
    stdout to find the exact path it reports, falling back to the newest results
    file in /var/lib/usg."""
    if not shutil.which('usg'):
        return None
    short = profile.rsplit('content_profile_', 1)[-1]
    if short not in _USG_PROFILES:
        # usg only knows CIS/STIG; let oscap handle anything else (e.g. ANSSI).
        return None
    try:
        proc = subprocess.run(['usg', 'audit', short],
                              capture_output=True, text=True, timeout=1800)
    except Exception as e:
        return {'available': False, 'reason': f'usg audit failed to run: {e}',
                'datastream': 'usg'}
    out = (proc.stdout or '') + (proc.stderr or '')
    # Find the results XML usg wrote. usg prints the path; match a
    # usg-results-*.xml anywhere on the line (don't hard-code /var/lib/usg —
    # the location is configurable), then fall back to the newest results file
    # in the usual directory.
    res = None
    m = re.search(r'(\S*usg-results-[^\s"\']+\.xml)', out)
    if m and os.path.exists(m.group(1)):
        res = m.group(1)
    if not res:
        try:
            cand = sorted(Path('/var/lib/usg').glob('usg-results-*.xml'),
                          key=lambda p: p.stat().st_mtime)
            res = str(cand[-1]) if cand else None
        except Exception:
            res = None
    if not res or not os.path.exists(res) or os.path.getsize(res) == 0:
        tail = (out.strip().splitlines() or ['no output'])[-1]
        return {'available': False, 'datastream': 'usg',
                'reason': f'usg audit produced no results XML — {tail[:160]}'}
    parsed = _parse_oscap_results(res)
    parsed['datastream'] = 'usg (Ubuntu Security Guide)'
    parsed['available_profiles'] = list(_USG_PROFILES)
    applicable = (parsed.get('pass') or 0) + (parsed.get('fail') or 0)
    if applicable == 0:
        return {'available': False, 'datastream': 'usg',
                'available_profiles': list(_USG_PROFILES),
                'reason': (f"usg profile '{short}' evaluated no applicable rules "
                           f"on this host")}
    parsed['available'] = True
    # usg writes a sibling HTML report (usg-report-<ts>.html) next to the
    # results XML — attach it for download. Try the printed path, then the
    # results filename with results→report, then newest in the dir.
    rep = None
    mh = re.search(r'(\S*usg-report-[^\s"\']+\.html)', out)
    if mh and os.path.exists(mh.group(1)):
        rep = mh.group(1)
    if not rep:
        cand = res.replace('usg-results-', 'usg-report-').replace('.xml', '.html')
        if os.path.exists(cand):
            rep = cand
    if not rep:
        try:
            hs = sorted(Path('/var/lib/usg').glob('usg-report-*.html'),
                        key=lambda p: p.stat().st_mtime)
            rep = str(hs[-1]) if hs else None
        except Exception:
            rep = None
    if rep:
        _attach_report_html(parsed, rep)
    return parsed


def run_oscap_scan(profile, creds):
    """Run an OpenSCAP-style compliance scan and POST a compact result to
    /api/scap/report. Heavy + slow, so callers run this in a thread.

    On Ubuntu, prefers Canonical's `usg` (correct content for the exact release)
    when it's installed and the profile is a CIS/STIG one; otherwise runs raw
    `oscap` against the best-matching SSG datastream. Degrades gracefully and
    never raises."""
    report = {'device_id': creds['device_id'], 'token': creds['token'],
              'ts': int(time.time()), 'profile': profile}
    try:
        # Ubuntu fast path: usg ships release-correct CIS/STIG content.
        usg = _run_usg_scan(profile)
        if usg is not None:
            report.update(usg)
        elif not shutil.which('oscap'):
            report.update(available=False, reason='oscap (openscap-scanner) not installed')
        else:
            ds = _find_ssg_datastream()
            if not ds:
                report.update(available=False,
                              reason='no SCAP content (install scap-security-guide)')
            else:
                # Always tell the server which profiles this datastream actually
                # offers, so the UI can present only the ones that exist for this
                # host's OS (Debian SSG has no cis/pci-dss/ospp — those are RHEL).
                valid = _oscap_profiles(ds)
                report['datastream'] = os.path.basename(ds)
                report['available_profiles'] = valid
                pid = _full_profile_id(profile, ds)
                if valid and profile not in valid and pid not in valid:
                    # Asked for a profile this datastream doesn't contain — don't
                    # run a doomed scan, just say so and list what IS available.
                    report.update(available=False,
                                  reason=(f"profile '{profile}' is not in "
                                          f"{os.path.basename(ds)} — available: "
                                          + ', '.join(valid)))
                    res_path = None
                    rep_path = None
                else:
                    res_path = tempfile.NamedTemporaryFile(
                        suffix='.xml', delete=False).name
                    rep_path = tempfile.NamedTemporaryFile(
                        suffix='.html', delete=False).name
                if res_path is not None:
                    try:
                        # --fetch-remote-resources: several SSG checks (platform
                        # applicability / OVAL, CVE feeds) reference remote
                        # content; without this oscap silently skips them, which
                        # can land at 0 applicable rules. The host needs outbound
                        # network for it — if offline, oscap still runs and just
                        # skips the remote checks (no hard failure).
                        #
                        # OSCAP_CPE_PATH: point oscap at the datastream's matching
                        # CPE dictionary (ssg-<os><ver>-cpe-dictionary.xml, sits
                        # next to the -ds.xml). Without it some builds fail with
                        # "Failed to add default CPE to newly created CPE Session
                        # [cpe_session.c:58]" and report 0 — setting it fixes that.
                        scan_env = dict(os.environ)
                        cpe = ds.replace('-ds.xml', '-cpe-dictionary.xml')
                        if cpe != ds and os.path.exists(cpe):
                            scan_env['OSCAP_CPE_PATH'] = cpe
                        proc = subprocess.run(['oscap', 'xccdf', 'eval',
                                               '--fetch-remote-resources',
                                               '--profile', pid,
                                               '--results', res_path,
                                               '--report', rep_path, ds],
                                              capture_output=True, text=True, timeout=900,
                                              env=scan_env)
                        # oscap exit codes: 0 = all rules pass, 2 = some rules failed
                        # (both are a SUCCESSFUL scan with a results file); 1 = error
                        # (bad profile, unreadable datastream, …) and NO usable
                        # results. Detect that and report oscap's real message plus
                        # the datastream's valid profiles, instead of letting the
                        # results parser choke on an empty file with the cryptic
                        # "no element found: line 1, column 0".
                        have_results = os.path.exists(res_path) and os.path.getsize(res_path) > 0
                        if proc.returncode not in (0, 2) or not have_results:
                            err = (proc.stderr or proc.stdout or '').strip().splitlines()
                            reason = err[-1] if err else f'oscap exited {proc.returncode} with no results'
                            if valid:
                                reason += ' — available profiles: ' + ', '.join(valid)
                            report.update(available=False, reason=reason)
                        else:
                            parsed = _parse_oscap_results(res_path)
                            # "Applicable" = rules that actually evaluated to
                            # pass or fail. oscap's base score is computed only
                            # over these; if every rule came back notapplicable /
                            # notchecked (common for the Debian SSG 'standard'
                            # profile, whose content is minimal), pass+fail is 0
                            # and the 0.0 "score" is meaningless — report it as
                            # not-applicable rather than a scary 0%. (total counts
                            # those skipped rules too, so we must check pass+fail,
                            # not total.)
                            applicable = (parsed.get('pass') or 0) + (parsed.get('fail') or 0)
                            if applicable == 0:
                                report.update(available=False,
                                              reason=_oscap_zero_reason(profile, ds))
                            else:
                                report.update(parsed)
                                report['available'] = True
                                _attach_report_html(report, rep_path)
                    finally:
                        for _p in (res_path, rep_path):
                            try:
                                if _p:
                                    os.unlink(_p)
                            except OSError:
                                pass
    except Exception as e:
        report.update(available=False, reason=f'scan error: {e}')
    try:
        http_post(f"{creds['server_url']}/api/scap/report", report, timeout=30)
        log.info(f"OpenSCAP scan reported (available={report.get('available')}, "
                 f"score={report.get('score')})")
    except Exception as e:
        log.warning(f'OpenSCAP report submission failed: {e}')


def _attach_report_html(report, html_path):
    """Attach a full oscap/usg HTML report to the result payload so the operator
    can download it from the dashboard. gzip + base64 keeps it compact and
    JSON-safe; the server stores it verbatim. Skips quietly if the file is
    missing, empty, or too large (cap well under the server's body limit)."""
    try:
        if not html_path or not os.path.exists(html_path):
            return
        raw = open(html_path, 'rb').read()
        if not raw or len(raw) > 25 * 1024 * 1024:   # 25 MB cap, pre-compression
            return
        import gzip as _gz, base64 as _b64
        report['report_html_gz'] = _b64.b64encode(_gz.compress(raw)).decode('ascii')
        report['report_bytes'] = len(raw)
    except Exception:
        pass   # report download is best-effort; never break the scan result


def _parse_oscap_results(path):
    """Parse an XCCDF results XML: overall score + rule-result tallies + up to
    200 failed rule ids/severities. Namespace-agnostic (matches on local tag)."""
    import xml.etree.ElementTree as ET
    counts = {'pass': 0, 'fail': 0, 'error': 0, 'notapplicable': 0,
              'notchecked': 0, 'notselected': 0, 'unknown': 0, 'informational': 0}
    failed = []
    score = None
    root = ET.parse(path).getroot()
    for el in root.iter():
        tag = el.tag.rsplit('}', 1)[-1]
        if tag == 'rule-result':
            res = ''
            for ch in el:
                if ch.tag.rsplit('}', 1)[-1] == 'result':
                    res = (ch.text or '').strip().lower()
                    break
            if res in counts:
                counts[res] += 1
            if res == 'fail' and len(failed) < 200:
                rid = (el.get('idref') or '').rsplit('content_rule_', 1)[-1]
                failed.append({'id': rid, 'severity': el.get('severity', 'unknown')})
        elif tag == 'score' and score is None:
            try:
                score = round(float((el.text or '').strip()), 1)
            except (ValueError, TypeError):
                pass
    total = sum(counts.values())
    return {'score': score, 'counts': counts, 'total': total,
            'pass': counts['pass'], 'fail': counts['fail'],
            'failed_rules': failed}


# ─── v1.7.0: Package inventory for CVE scanning ───────────────────────────────

def get_os_release():
    """Parse /etc/os-release into a dict. Returns {} if unavailable."""
    out = {}
    try:
        with open('/etc/os-release', 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                k, _, v = line.partition('=')
                v = v.strip()
                if len(v) >= 2 and v[0] in ('"', "'") and v[-1] == v[0]:
                    v = v[1:-1]
                out[k.strip()] = v
    except (OSError, UnicodeDecodeError):
        pass
    return out


def get_package_list():
    """
    Enumerate all installed packages via the system package manager.
    Returns (pkg_manager, [{name, version, arch}, ...]).
    """
    if Path('/usr/bin/dpkg-query').exists():
        try:
            out = subprocess.check_output(
                ['dpkg-query', '-W', '-f=${Package}\\t${Version}\\t${Architecture}\\n'],
                text=True, timeout=30, stderr=subprocess.DEVNULL,
            )
            pkgs = []
            for line in out.splitlines():
                parts = line.split('\t')
                if len(parts) >= 3 and parts[0] and parts[1]:
                    pkgs.append({
                        'name':    parts[0].strip(),
                        'version': parts[1].strip(),
                        'arch':    parts[2].strip(),
                    })
            return 'apt', pkgs
        except Exception:
            return 'apt', []

    if Path('/usr/bin/rpm').exists():
        try:
            out = subprocess.check_output(
                ['rpm', '-qa', '--qf', '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n'],
                text=True, timeout=30, stderr=subprocess.DEVNULL,
            )
            pkgs = []
            for line in out.splitlines():
                parts = line.split('\t')
                if len(parts) >= 3 and parts[0] and parts[1]:
                    pkgs.append({
                        'name':    parts[0].strip(),
                        'version': parts[1].strip(),
                        'arch':    parts[2].strip(),
                    })
            return 'dnf', pkgs
        except Exception:
            return 'dnf', []

    if Path('/usr/bin/pacman').exists():
        try:
            out = subprocess.check_output(
                ['pacman', '-Q'],
                text=True, timeout=15, stderr=subprocess.DEVNULL,
            )
            pkgs = []
            for line in out.splitlines():
                parts = line.split(None, 1)
                if len(parts) == 2:
                    pkgs.append({
                        'name':    parts[0].strip(),
                        'version': parts[1].strip(),
                        'arch':    '',
                    })
            return 'pacman', pkgs
        except Exception:
            return 'pacman', []

    if Path('/sbin/apk').exists() or Path('/usr/sbin/apk').exists():
        try:
            out = subprocess.check_output(
                ['apk', 'info', '-v'],
                text=True, timeout=15, stderr=subprocess.DEVNULL,
            )
            pkgs = []
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                m = re.match(r'^(.+?)-(\d[^-]*(-r\d+)?)$', line)
                if m:
                    pkgs.append({
                        'name':    m.group(1),
                        'version': m.group(2),
                        'arch':    '',
                    })
            return 'apk', pkgs
        except Exception:
            return 'apk', []

    return 'unknown', []


def _load_last_pkg_hash():
    try:
        return PKG_HASH_FILE.read_text().strip()
    except (OSError, UnicodeDecodeError):
        return ''


def _save_last_pkg_hash(h):
    try:
        PKG_HASH_FILE.write_text(h)
        os.chmod(PKG_HASH_FILE, 0o600)
    except OSError:
        pass


def _compute_pkg_hash(packages):
    """Matches server-side cve_scanner.packages_hash() — order-independent."""
    normalized = sorted(
        (p.get('name', ''), p.get('version', ''))
        for p in packages
    )
    return hashlib.sha256(
        json.dumps(normalized, separators=(',', ':')).encode()
    ).hexdigest()[:16]


def send_package_list(creds, force=False):
    """
    Collect installed packages and push to /api/packages.

    Normally the list is only submitted when it has *changed* since
    the last successful submission (a hash gate — saves bandwidth on
    the routine 6-hourly send, since installed packages rarely move
    on a stable host).

    v2.4.10: `force=True` bypasses that gate. The whole point of an
    operator-requested scan is "send the list now, regardless" — and
    on a stable host the list legitimately hasn't changed, so the
    hash gate was silently suppressing every forced scan. The forced
    heartbeat path passes force=True.

    Returns True if sent.
    """
    pkg_manager, pkgs = get_package_list()
    if not pkgs:
        log.debug(f'No packages enumerable (manager={pkg_manager})')
        return False

    if len(pkgs) > MAX_PACKAGES_SEND:
        log.warning(f'Truncating package list from {len(pkgs)} to {MAX_PACKAGES_SEND}')
        pkgs = pkgs[:MAX_PACKAGES_SEND]

    new_hash = _compute_pkg_hash(pkgs)
    if not force and new_hash == _load_last_pkg_hash():
        log.debug('Package list unchanged — skipping submission')
        return False

    os_release = get_os_release()
    payload = {
        'device_id':      creds['device_id'],
        'token':          creds['token'],
        'pkg_manager':    pkg_manager,
        'ecosystem_hint': {
            'ID':         os_release.get('ID', ''),
            'VERSION_ID': os_release.get('VERSION_ID', ''),
            'ID_LIKE':    os_release.get('ID_LIKE', ''),
        },
        'packages':       pkgs,
    }
    try:
        resp = http_post(f"{creds['server_url']}/api/packages", payload, timeout=30)
        log.info(f'Submitted {len(pkgs)} packages '
                 f'(ecosystem={resp.get("ecosystem", "?")}, '
                 f'changed={resp.get("changed", False)})')
        _save_last_pkg_hash(new_hash)
        return True
    except Exception as e:
        log.warning(f'Package list submission failed: {e}')
        return False


# ─── v1.8.0: Service monitoring (systemd) ─────────────────────────────────────

def _resolve_unit_alias(unit):
    """
    journalctl does NOT follow systemd unit aliases, but systemctl does.
    Return the canonical unit name (Id) for a possibly-aliased name.

    Critical on Debian/Ubuntu where 'sshd.service' is an alias for 'ssh.service'
    — a user typing the RHEL-style 'sshd.service' would otherwise get zero logs.
    Silently falls through to the original name on error.
    """
    try:
        proc = subprocess.run(
            ['systemctl', 'show', unit, '--property=Id', '--value'],
            capture_output=True, text=True, timeout=3,
        )
        resolved = (proc.stdout or '').strip()
        if resolved and resolved != unit:
            return resolved
    except Exception:
        pass
    return unit


# ── v1.11.0: container/k8s detection ─────────────────────────────────────────
# Probes for Docker, Podman, and Kubernetes (k3s/k0s/kubeadm). Each runtime
# is independent — if Docker is installed but Podman isn't, we just don't
# emit Podman entries. Failures in one runtime never break the others.
#
# Output is normalised to the schema the server expects:
#   {name, image, tag, status, namespace, runtime, ports, started_at,
#    uptime_seconds, restart_count}
#
# Caps:
#   - Per-runtime: 100 entries
#   - Total: 100 entries combined (server caps again at 100)

CONTAINERS_HARD_CAP = 100      # total across all runtimes
CONTAINER_CMD_TIMEOUT = 5      # seconds — never let a stuck runtime hang us


def _which(prog):
    """Return path to ``prog`` if it's executable on PATH, else None.

    v3.13.0: also searches the standard sbin dirs even when they're absent from
    a minimal service PATH — firewall tools (iptables/nft) live in /usr/sbin and
    /sbin, and a systemd unit's PATH often omits them, which made firewall
    detection report "unknown"."""
    seen = []
    for d in os.environ.get('PATH', '').split(':'):
        if d:
            seen.append(d)
    for d in ('/usr/sbin', '/sbin', '/usr/bin', '/bin', '/usr/local/sbin', '/usr/local/bin'):
        if d not in seen:
            seen.append(d)
    for d in seen:
        full = os.path.join(d, prog)
        if os.path.isfile(full) and os.access(full, os.X_OK):
            return full
    return None


def _cpu_model():
    """Best-effort CPU model string for the CMDB Hardware panel. Reads
    /proc/cpuinfo, matching exact field names so the numeric x86 `model : 33`
    line isn't mistaken for the human-readable `model name`."""
    try:
        fields = {}
        for line in _safe_read('/proc/cpuinfo').splitlines():
            if ':' not in line:
                continue
            k, v = line.split(':', 1)
            k, v = k.strip().lower(), v.strip()
            if k and v and k not in fields:
                fields[k] = v
        for key in ('model name', 'hardware', 'cpu model'):
            if fields.get(key):
                return fields[key][:128]
        # ARM boards put a full name in 'model' (e.g. "Raspberry Pi 4"); x86
        # puts a bare number there — only use it when it isn't numeric.
        m = fields.get('model', '')
        if m and not m.isdigit():
            return m[:128]
    except Exception:
        pass
    try:
        return (platform.processor() or platform.machine() or '')[:128]
    except Exception:
        return ''


def _docker_stats(cmd_path):
    """v2.2.6: one-shot `docker stats` for per-container CPU / memory.

    `--no-stream` takes a single sample and exits. Returns a dict keyed
    by container name → {cpu_percent, mem_percent, mem_usage}. Best
    effort — on failure returns {} and the caller just omits the
    stats fields. Separate call from `ps` because stats is slower and
    we want `ps` to succeed even if stats times out.
    """
    stats = {}
    try:
        r = subprocess.run(
            [cmd_path, 'stats', '--no-stream', '--format', '{{json .}}'],
            capture_output=True, text=True, timeout=CONTAINER_CMD_TIMEOUT)
    except Exception:
        return stats
    if r.returncode != 0:
        return stats
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        name = d.get('Name', '') or d.get('Container', '')
        if not name:
            continue
        # Values arrive as strings like "1.23%" / "45.6MiB / 1.9GiB"
        def _pct(s):
            try:
                return round(float(str(s).rstrip('%').strip()), 1)
            except (ValueError, AttributeError):
                return None
        stats[name] = {
            'cpu_percent': _pct(d.get('CPUPerc')),
            'mem_percent': _pct(d.get('MemPerc')),
            'mem_usage':   (d.get('MemUsage', '') or '').split('/')[0].strip(),
        }
    return stats


def _docker_inspect_meta(cmd_path, ids):
    """v3.10.0: one batched ``inspect`` for restart-count + start time.

    ``docker ps`` doesn't carry a restart count or a machine-readable start
    timestamp, so the docker/podman listing used to ship ``restart_count`` /
    ``started_at`` / ``uptime_seconds`` hardcoded to ``0`` — which left the
    server's ``container_restart`` alert permanently dead and the UI "age"
    column blank for every non-Kubernetes host. One ``inspect`` over the whole
    batch (newline-delimited ``Id RestartCount StartedAt``) fills them in
    cheaply. Best effort: returns ``{}`` on failure so the listing degrades to
    the old zeros rather than breaking.

    Returns ``{full_id: {restart_count, started_at, uptime_seconds}}``.
    """
    meta = {}
    ids = [i for i in (ids or []) if i]
    if not ids:
        return meta
    try:
        r = subprocess.run(
            [cmd_path, 'inspect', '--format',
             '{{.Id}} {{.RestartCount}} {{.State.StartedAt}}', *ids],
            capture_output=True, text=True, timeout=CONTAINER_CMD_TIMEOUT)
    except Exception:
        return meta
    if r.returncode != 0:
        return meta
    now = int(time.time())
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        cid = parts[0]
        try:
            restarts = int(parts[1])
        except (ValueError, IndexError):
            restarts = 0
        started_at = _parse_iso_to_epoch(parts[2]) if len(parts) >= 3 else 0
        uptime = max(0, now - started_at) if started_at else 0
        meta[cid] = {
            'restart_count':  restarts,
            'started_at':     started_at,
            'uptime_seconds': uptime,
        }
    return meta


def _parse_iso_to_epoch(s):
    """Parse a docker/k8s RFC3339 timestamp ('2024-01-15T10:30:00.123456789Z')
    into epoch seconds. Returns 0 on anything unparseable (incl. the zero-value
    '0001-01-01T00:00:00Z' docker emits for never-started containers)."""
    s = (s or '').strip()
    if not s or s.startswith('0001-01-01'):
        return 0
    try:
        import datetime as _dt
        # Normalise the Z suffix and drop sub-second precision entirely (we
        # return whole seconds, and Go emits 9 fractional digits which older
        # fromisoformat rejects). Keep any numeric tz offset so the instant is
        # unambiguous; a bare timestamp with no offset is treated as UTC.
        iso = re.sub(r'\.\d+', '', s.replace('Z', '+00:00'))
        dt = _dt.datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_dt.timezone.utc)
        return int(dt.timestamp())
    except (ValueError, TypeError, OverflowError):
        return 0


def _image_digests(cmd_path):
    """Map ``(repository, tag) -> RepoDigest`` (``sha256:…``) for locally
    present images, via ``<rt> images --digests``.

    The server uses this to compare what's pulled against the registry's
    current digest for that tag and flag stale images. Best-effort: any
    error, a runtime that doesn't expose digests, or locally-built images
    (``<none>`` digest) just yield no entry, and the server treats that
    image's update status as unknown.
    """
    out_map = {}
    try:
        out = subprocess.run(
            [cmd_path, 'images', '--digests', '--no-trunc', '--format', '{{json .}}'],
            capture_output=True, text=True, timeout=CONTAINER_CMD_TIMEOUT,
        )
    except Exception as e:
        log.debug(f'{cmd_path} images failed: {e}')
        return out_map
    if out.returncode != 0:
        return out_map
    text = out.stdout.strip()
    if not text:
        return out_map
    # Docker emits one JSON object per line; some Podman versions emit a
    # single JSON array. Tolerate both, same posture as the ps parser.
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except (json.JSONDecodeError, ValueError):
            pass
    if not rows:
        try:
            arr = json.loads(text)
            if isinstance(arr, list):
                rows = [r for r in arr if isinstance(r, dict)]
        except (json.JSONDecodeError, ValueError):
            return out_map
    for r in rows:
        repo = str(r.get('Repository') or r.get('repository') or '').strip()
        tag = str(r.get('Tag') or r.get('tag') or '').strip()
        digest = str(r.get('Digest') or r.get('digest') or '').strip()
        if not repo or not digest.startswith('sha256:'):
            continue
        out_map[(repo, tag)] = digest
    return out_map


_BARE_IMAGE_ID_RE = re.compile(r'^(sha256:)?[0-9a-f]{12,64}$')


def _resolve_config_image(cmd_path, container_id):
    """When `docker ps` reports a container's image as a bare ID (the tag was
    moved to a freshly-pulled image and this container still runs the old,
    now-untagged one), recover the image *name* the container was created with
    via `inspect .Config.Image` — e.g. `ghcr.io/seerr-team/seerr:latest`. That
    keeps the image identifiable in the UI and lets the registry comparison run.
    Best-effort; returns '' on any failure."""
    if not container_id:
        return ''
    try:
        out = subprocess.run(
            [cmd_path, 'inspect', '--format', '{{.Config.Image}}', container_id],
            capture_output=True, text=True, timeout=CONTAINER_CMD_TIMEOUT)
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        pass
    return ''


def _parse_labels(raw):
    """Docker's `{{json .}}` Labels field is a flat 'k=v,k=v' string. Return a
    dict; tolerant of missing '=' and empty input."""
    labels = {}
    for part in (raw or '').split(','):
        if '=' in part:
            k, _, v = part.partition('=')
            labels[k.strip()] = v.strip()
    return labels


def _docker_listing(cmd_path, runtime_name):
    """Run ``docker ps`` (or podman ps) and parse the line-oriented JSON output.

    ``--format '{{json .}}'`` produces one JSON object per line. This avoids
    the ``--format json`` Docker / Podman version quirks where the output is
    sometimes an array, sometimes lines, sometimes pretty-printed.

    v2.2.6: also folds in a `docker stats` sample for per-container CPU /
    memory, and parses a `health` substring out of the status string.
    """
    try:
        out = subprocess.run(
            [cmd_path, 'ps', '--no-trunc', '--format', '{{json .}}'],
            capture_output=True, text=True, timeout=CONTAINER_CMD_TIMEOUT,
        )
    except Exception as e:
        log.debug(f'{runtime_name} ps failed: {e}')
        return []
    if out.returncode != 0:
        log.debug(f'{runtime_name} ps rc={out.returncode}: {out.stderr.strip()[:200]}')
        return []

    # One stats sample for the whole batch (best effort).
    stats = _docker_stats(cmd_path)
    # v3.3.4: one image-digest sample for the whole batch (best effort).
    # Lets the server compare each container's pulled image against the
    # registry's current digest for that tag and flag stale images.
    digests = _image_digests(cmd_path)

    # Parse the line-oriented JSON first so we can collect container IDs and run
    # a single batched inspect (restart-count + start time) for the whole set,
    # rather than one inspect per container.
    parsed = []
    for line in out.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        parsed.append(d)
        if len(parsed) >= CONTAINERS_HARD_CAP:
            break
    inspect_meta = _docker_inspect_meta(
        cmd_path, [d.get('ID', '') for d in parsed])

    items = []
    now = int(time.time())
    for d in parsed:
        # Image splits as 'nginx:1.25-alpine' or 'nginx' (no tag = latest)
        image_full = d.get('Image', '')
        # If the container references an untagged image by bare ID (common right
        # after a `compose pull` that hasn't been followed by `up -d` to
        # recreate), recover the real image name so it isn't shown as "sha256".
        if _BARE_IMAGE_ID_RE.match(image_full.strip()):
            resolved = _resolve_config_image(cmd_path, d.get('ID', '') or d.get('Names', ''))
            if resolved and not _BARE_IMAGE_ID_RE.match(resolved):
                image_full = resolved
        if ':' in image_full and '/' not in image_full.rsplit(':', 1)[1]:
            image, tag = image_full.rsplit(':', 1)
        else:
            image, tag = image_full, ''
        # v3.9.0: compose working dir (from the project label) so the server can
        # offer a one-click pull+recreate update for compose-managed stacks.
        labels = _parse_labels(d.get('Labels', ''))
        compose_dir = labels.get('com.docker.compose.project.working_dir', '')
        raw_ports = d.get('Ports', '') or ''
        ports = [p.strip() for p in raw_ports.split(',') if p.strip()][:20]
        name = d.get('Names', '') or d.get('Name', '')
        status = d.get('Status', '') or d.get('State', '')
        # v2.2.6: docker writes container health into the status string
        # as "(healthy)" / "(unhealthy)" / "(health: starting)". Pull it
        # out into its own field so the UI can show a health badge.
        health = ''
        ms = re.search(r'\((healthy|unhealthy|health: starting)\)', status)
        if ms:
            health = ms.group(1).replace('health: ', '')
        st = stats.get(name, {})
        # v3.10.0: real restart-count + start time from the batched inspect.
        im = inspect_meta.get(d.get('ID', ''), {})
        items.append({
            'name':           name,
            'image':          image,
            'tag':            tag,
            # v3.3.4: `docker ps` reports an empty tag for an implicit
            # `latest` pull, but `docker images` lists it as `latest` — so
            # normalise here or the digest join misses every implicit-latest
            # image (i.e. most of them).
            'repo_digest':    digests.get((image, tag or 'latest'), ''),
            'status':         status,
            'health':         health,                       # v2.2.6
            'namespace':      '',
            'runtime':        runtime_name,
            'compose_dir':    compose_dir,                   # v3.9.0
            'ports':          ports,
            'started_at':     im.get('started_at', 0),       # v3.10.0
            'uptime_seconds': im.get('uptime_seconds', 0),   # v3.10.0
            'restart_count':  im.get('restart_count', 0),    # v3.10.0
            'cpu_percent':    st.get('cpu_percent'),         # v2.2.6
            'mem_percent':    st.get('mem_percent'),         # v2.2.6
            'mem_usage':      st.get('mem_usage', ''),       # v2.2.6
        })
    return items


def _kubectl_listing():
    """Run ``kubectl get pods --all-namespaces -o json`` if kubectl is around.

    The kubeconfig is found via the standard search path (``$KUBECONFIG``,
    ``~/.kube/config``, or in-cluster). For a single-node k3s/k0s install
    we expect ``/etc/rancher/k3s/k3s.yaml`` to be readable by the agent.
    """
    kubectl = _which('kubectl')
    if not kubectl:
        return []
    # Some k3s installs put kubeconfig in /etc/rancher/k3s/k3s.yaml. Set it
    # if KUBECONFIG isn't already set and that file exists.
    env = os.environ.copy()
    if 'KUBECONFIG' not in env:
        for candidate in ('/etc/rancher/k3s/k3s.yaml',
                          '/var/lib/k0s/pki/admin.conf',
                          os.path.expanduser('~/.kube/config')):
            if os.path.isfile(candidate):
                env['KUBECONFIG'] = candidate
                break
    try:
        out = subprocess.run(
            [kubectl, 'get', 'pods', '--all-namespaces', '-o', 'json'],
            capture_output=True, text=True, timeout=CONTAINER_CMD_TIMEOUT, env=env,
        )
    except Exception as e:
        log.debug(f'kubectl failed: {e}')
        return []
    if out.returncode != 0:
        log.debug(f'kubectl rc={out.returncode}: {out.stderr.strip()[:200]}')
        return []
    try:
        doc = json.loads(out.stdout)
    except (json.JSONDecodeError, ValueError):
        return []
    items_in = doc.get('items', []) if isinstance(doc, dict) else []
    items = []
    now = int(time.time())
    for pod in items_in:
        if not isinstance(pod, dict):
            continue
        meta = pod.get('metadata', {}) or {}
        spec = pod.get('spec', {}) or {}
        status = pod.get('status', {}) or {}
        name = meta.get('name', '')
        ns = meta.get('namespace', '')
        if not name:
            continue
        # First container's image is representative for naming purposes
        containers_spec = spec.get('containers') or []
        first_image = containers_spec[0].get('image', '') if containers_spec else ''
        if ':' in first_image and '/' not in first_image.rsplit(':', 1)[1]:
            image, tag = first_image.rsplit(':', 1)
        else:
            image, tag = first_image, ''
        # Aggregate restart count across all containers in the pod
        cstatuses = status.get('containerStatuses') or []
        restart_count = sum(int(cs.get('restartCount', 0)) for cs in cstatuses)
        # Started time: the first container's startedAt
        started_at = 0
        if cstatuses:
            state = cstatuses[0].get('state', {}) or {}
            running = state.get('running') or {}
            started_iso = running.get('startedAt')
            if started_iso:
                # 2024-04-29T13:45:32Z → unix
                try:
                    import datetime as _dt
                    dt = _dt.datetime.strptime(started_iso, '%Y-%m-%dT%H:%M:%SZ')
                    started_at = int(dt.replace(tzinfo=_dt.timezone.utc).timestamp())
                except (ValueError, TypeError):
                    started_at = 0
        # Ports — pull from spec.containers[].ports[].containerPort
        ports = []
        for c in containers_spec[:5]:
            for p in (c.get('ports') or [])[:5]:
                cp = p.get('containerPort')
                proto = p.get('protocol', 'TCP').lower()
                if cp:
                    ports.append(f'{cp}/{proto}')
        items.append({
            'name':           name,
            'image':          image,
            'tag':            tag,
            'status':         status.get('phase', ''),
            'namespace':      ns,
            'runtime':        'kubernetes',
            'ports':          ports[:20],
            'started_at':     started_at,
            'uptime_seconds': max(0, now - started_at) if started_at else 0,
            'restart_count':  restart_count,
        })
        if len(items) >= CONTAINERS_HARD_CAP:
            break
    return items


def get_containers():
    """Return up to CONTAINERS_HARD_CAP container/pod entries across runtimes.

    Cheap fast-path: returns ``[]`` immediately if no runtime is detected.
    Each runtime probe has a 5-second timeout so one stuck runtime can't
    block the heartbeat.
    """
    out = []
    for tool, name in (('docker', 'docker'), ('podman', 'podman')):
        path = _which(tool)
        if path:
            try:
                out.extend(_docker_listing(path, name))
            except Exception as e:
                log.debug(f'{name} listing error: {e}')
        if len(out) >= CONTAINERS_HARD_CAP:
            return out[:CONTAINERS_HARD_CAP]
    try:
        out.extend(_kubectl_listing())
    except Exception as e:
        log.debug(f'kubectl listing error: {e}')
    return out[:CONTAINERS_HARD_CAP]


# v2.1.0: scan well-known roots for docker-compose.yml files. Reported in
# the heartbeat (every CONTAINER_CHECK_EVERY polls, alongside container
# state) so the dashboard can offer up/down/restart/pull/logs actions
# against discovered projects without operators having to type the path.
#
# Scan budget is deliberately tight: only four top-level roots, max depth
# 4 (so projects nested like /opt/stack/postgres/docker-compose.yml are
# found, but a million-file home dir won't get walked exhaustively), and
# a hard cap on results. The `find` invocation has a timeout. If anything
# misbehaves the agent returns [] rather than blocking the heartbeat.
COMPOSE_SCAN_ROOTS = ('/opt', '/home', '/docker', '/srv')
COMPOSE_SCAN_MAX_DEPTH = 4
COMPOSE_SCAN_TIMEOUT_S = 5
COMPOSE_MAX_PROJECTS   = 50


def get_compose_projects():
    """Find docker-compose.yml / compose.yml under /opt /home /docker /srv.

    Returns a list of {path, dir, name, mtime} dicts (max COMPOSE_MAX_PROJECTS).
    Skipped entirely if docker isn't installed — there's no point reporting
    projects we can't act on.
    """
    if not _which('docker'):
        return []
    # Only scan roots that actually exist; on a fresh box /docker often
    # doesn't, and asking find for a missing path wastes a syscall.
    roots = [r for r in COMPOSE_SCAN_ROOTS if Path(r).is_dir()]
    if not roots:
        return []

    # Use `find` rather than os.walk: we get -maxdepth, -prune-style
    # protections, and the kernel-side directory traversal is faster
    # than Python iterating dir entries one by one. The -path excludes
    # are belt-and-braces against common noise: VCS metadata, runtime
    # caches, and node_modules trees that ship their own compose files
    # we don't care about.
    cmd = ['find', '-L'] + roots + [
        '-maxdepth', str(COMPOSE_SCAN_MAX_DEPTH),
        '(',
            '-path', '*/.git', '-o',
            '-path', '*/node_modules', '-o',
            '-path', '*/.cache', '-o',
            '-path', '*/__pycache__', '-o',
            '-path', '*/venv', '-o',
            '-path', '*/.venv',
        ')',
        '-prune', '-o',
        '(', '-name', 'docker-compose.yml', '-o',
             '-name', 'docker-compose.yaml', '-o',
             '-name', 'compose.yml', '-o',
             '-name', 'compose.yaml', ')',
        '-type', 'f',
        '-print',
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=COMPOSE_SCAN_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        log.debug('compose scan timed out')
        return []
    except FileNotFoundError:
        # No `find` (e.g. minimal container). Fall back to Python — single
        # depth scan, much narrower. Better than nothing.
        return _compose_scan_python(roots)
    except Exception as e:
        log.debug(f'compose scan failed: {e}')
        return []

    found = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith('/'):
            continue
        try:
            p = Path(line)
            if not p.is_file():
                continue
            d = p.parent
            found.append({
                'path':  str(p),
                'dir':   str(d),
                # Project name == the parent directory's basename. That's
                # what `docker compose` itself defaults to when COMPOSE_PROJECT_NAME
                # isn't set; matching that here keeps the UI labels honest.
                'name':  d.name,
                'mtime': int(p.stat().st_mtime),
            })
        except OSError:
            continue
        if len(found) >= COMPOSE_MAX_PROJECTS:
            break
    return found


def _compose_scan_python(roots):
    """Fallback compose scan using os.walk when `find` is unavailable.

    Same depth and exclusion logic as the find-based scan, but slower in
    practice on large /home trees — hence the fast path above.
    """
    found = []
    skip_names = {'.git', 'node_modules', '.cache', '__pycache__', 'venv', '.venv'}
    compose_names = {'docker-compose.yml', 'docker-compose.yaml',
                     'compose.yml', 'compose.yaml'}
    for root in roots:
        root_parts = Path(root).parts
        try:
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                depth = len(Path(dirpath).parts) - len(root_parts)
                if depth > COMPOSE_SCAN_MAX_DEPTH:
                    dirnames[:] = []
                    continue
                dirnames[:] = [d for d in dirnames if d not in skip_names]
                for f in filenames:
                    if f in compose_names:
                        p = Path(dirpath) / f
                        try:
                            found.append({
                                'path': str(p), 'dir': dirpath,
                                'name': Path(dirpath).name,
                                'mtime': int(p.stat().st_mtime),
                            })
                        except OSError:
                            continue
                        if len(found) >= COMPOSE_MAX_PROJECTS:
                            return found
        except Exception as e:
            log.debug(f'walk {root} failed: {e}')
    return found


def get_services(watched_units):
    """
    Query systemd for the given list of unit names.
    Returns [{unit, active, sub, since, canonical}, ...].

    `unit`:       the name as requested (what the user configured)
    `canonical`:  the canonical name after alias resolution (may equal `unit`)
    `active`: "active" | "inactive" | "failed" | "activating" | "unknown"
    `since`:  unix timestamp of last state change (0 if unknown)
    """
    if not watched_units:
        return []
    if not Path('/bin/systemctl').exists() and not Path('/usr/bin/systemctl').exists():
        return []

    out = []
    # Batch into one systemctl call per unit (simpler + each unit has its own
    # ActiveEnterTimestamp). Could use --all + --no-pager, but single-shot is
    # clearer and robust to unknown units.
    for unit in watched_units[:50]:  # matches server MAX_SERVICES_PER_DEVICE
        try:
            proc = subprocess.run(
                ['systemctl', 'show', unit,
                 '--property=Id,ActiveState,SubState,ActiveEnterTimestampMonotonic,ActiveEnterTimestamp',
                 '--no-pager'],
                capture_output=True, text=True, timeout=5,
            )
            props = {}
            for line in proc.stdout.splitlines():
                if '=' in line:
                    k, _, v = line.partition('=')
                    props[k.strip()] = v.strip()
            active = props.get('ActiveState', 'unknown')
            sub    = props.get('SubState', '')
            since  = _parse_systemd_timestamp(props.get('ActiveEnterTimestamp', ''))
            canonical = props.get('Id', unit) or unit
            entry = {'unit': unit, 'active': active, 'sub': sub, 'since': since}
            if canonical != unit:
                entry['canonical'] = canonical
            out.append(entry)
        except subprocess.TimeoutExpired:
            out.append({'unit': unit, 'active': 'unknown', 'sub': 'timeout', 'since': 0})
        except Exception as e:
            log.debug(f'systemctl show {unit} failed: {e}')
            out.append({'unit': unit, 'active': 'unknown', 'sub': '', 'since': 0})
    return out


def _parse_systemd_timestamp(s):
    """Parse systemd's 'Thu 2026-04-23 15:30:12 UTC' format into unix ts."""
    if not s:
        return 0
    # systemd emits timestamps like: "Thu 2026-04-23 15:30:12 UTC"
    # Strip weekday prefix and timezone suffix; parse the middle.
    parts = s.split()
    if len(parts) < 3:
        return 0
    # Expected: [Weekday, YYYY-MM-DD, HH:MM:SS, TZ]
    try:
        import datetime as _dt
        dt = _dt.datetime.strptime(f'{parts[1]} {parts[2]}', '%Y-%m-%d %H:%M:%S')
        # systemd uses local time unless TZ=UTC is seen
        if len(parts) >= 4 and parts[3] == 'UTC':
            dt = dt.replace(tzinfo=_dt.timezone.utc)
            return int(dt.timestamp())
        return int(dt.timestamp())
    except Exception:
        return 0


def get_unit_logs(unit, since_seconds=LOG_LOOKBACK_SECONDS, max_lines=MAX_LOG_LINES_PER_UNIT):
    """
    Return the last `max_lines` of journalctl output for a unit, going back
    at most `since_seconds`.

    v1.8.3: resolves systemd unit aliases before querying journalctl, which
    does not follow aliases. Critical on Debian/Ubuntu where e.g. sshd.service
    is an alias for ssh.service.
    """
    canonical = _resolve_unit_alias(unit)
    try:
        proc = subprocess.run(
            ['journalctl',
             '-u', canonical,
             '--since', f'{since_seconds} seconds ago',
             '--no-pager',
             '-n', str(max_lines),
             '-o', 'short-iso'],
            capture_output=True, text=True, timeout=10,
        )
        lines = proc.stdout.splitlines()
        # Strip boilerplate
        lines = [ln for ln in lines if ln and not ln.startswith('-- ')]
        if lines and canonical != unit:
            log.debug(f'Resolved unit alias {unit} → {canonical} ({len(lines)} lines)')
        return lines[-max_lines:]
    except subprocess.TimeoutExpired:
        return []
    except Exception as e:
        log.debug(f'journalctl for {unit} (canonical {canonical}) failed: {e}')
        return []


def submit_unit_logs(creds, units, extra_units=None):
    """
    Collect recent logs for each watched unit and submit to /api/logs.
    Server applies log_watch pattern matching and rolling-buffer storage.

    v1.8.2 fix: always include every watched unit (with empty list if quiet) and
    always POST, even if every unit is quiet.

    v1.8.3: submission activity logged at INFO level so ops can verify
    from `journalctl -u remotepower-agent` that logs are actually flowing.

    v2.7.0: extra_units — dict of {unit_name: [entry_dicts]} for virtual
    sources (kernel/dmesg, apt.history) that don't come from journalctl.
    """
    if not units and not extra_units:
        return False
    units_payload = {}
    for unit in (units or [])[:50]:
        lines = get_unit_logs(unit)
        units_payload[unit] = lines or []
    # Merge virtual log sources (dmesg, apt history)
    for vunit, ventries in (extra_units or {}).items():
        if ventries:                         # only include if there's something new
            units_payload[vunit] = ventries
    try:
        http_post(f"{creds['server_url']}/api/logs", {
            'device_id': creds['device_id'],
            'token':     creds['token'],
            'units':     units_payload,
        }, timeout=15)
        total = sum(len(v) for v in units_payload.values())
        quiet = sum(1 for v in units_payload.values() if not v)
        log.info(f'Logs submitted: {total} lines across {len(units_payload)} unit(s), '
                 f'{quiet} quiet')
        return True
    except Exception as e:
        log.warning(f'Log submission FAILED: {e}')
        return False


def collect_dmesg_logs(since_ts=None):
    """v2.7.0: collect kernel errors/warnings from dmesg.

    Submitted through /api/logs as virtual unit 'kernel'.
    Only emerg/alert/crit/err/warn levels — info/debug are too noisy.
    """
    entries = []
    try:
        since_arg = since_ts if since_ts else (time.time() - DMESG_LOG_LOOKBACK_HOURS * 3600)
        result = subprocess.run(
            ['dmesg', '--level=emerg,alert,crit,err,warn', '--time-format=iso'],
            capture_output=True, text=True, timeout=10,
        )
        now = time.time()
        for line in result.stdout.splitlines()[-DMESG_MAX_LINES * 3:]:
            line = line.strip()
            if not line:
                continue
            ts, msg = now, line
            try:
                parts = line.split(None, 1)
                if parts and len(parts[0]) > 10 and 'T' in parts[0]:
                    import datetime as _dt
                    dt = _dt.datetime.fromisoformat(parts[0].replace(',', '.'))
                    ts  = dt.timestamp()
                    msg = parts[1] if len(parts) > 1 else line
            except Exception:
                pass
            if ts >= since_arg:
                entries.append({
                    'ts':      int(ts * 1000),
                    'message': msg[:512],
                    'unit':    'kernel',
                    'level':   'warn',
                })
        entries = entries[-DMESG_MAX_LINES:]
    except Exception as e:
        log.debug(f'dmesg collection failed: {e}')
    return entries


def collect_apt_history(state_file):
    """v2.7.0: collect new entries from /var/log/apt/history.log.

    Tracks file position in state_file so only new lines are sent.
    Submitted as virtual unit 'apt.history'.
    """
    apt_log = Path('/var/log/apt/history.log')
    entries = []
    try:
        if not apt_log.exists():
            return []
        mtime    = apt_log.stat().st_mtime
        last_mtime = last_pos = 0
        if state_file.exists():
            try:
                st = json.loads(state_file.read_text())
                last_mtime = float(st.get('mtime', 0))
                last_pos   = int(st.get('pos', 0))
            except Exception:
                pass
        if mtime <= last_mtime:
            return []
        with apt_log.open('r', errors='replace') as f:
            f.seek(last_pos)
            new_text = f.read(APT_HISTORY_MAX_LINES * 300)
            new_pos  = f.tell()
        now = int(time.time() * 1000)
        for line in new_text.splitlines()[-APT_HISTORY_MAX_LINES:]:
            line = line.strip()
            if line:
                entries.append({
                    'ts': now, 'message': line[:512],
                    'unit': 'apt.history', 'level': 'info',
                })
        try:
            state_file.write_text(json.dumps({'mtime': mtime, 'pos': new_pos}))
        except Exception:
            pass
    except Exception as e:
        log.debug(f'apt history collection failed: {e}')
    return entries


# v3.0.1: arbitrary file-path log collector for log_watch rules with `path`.
# State persisted per-path as inode+position; on rotation (new inode) we reset
# to 0 and read from the start of the new file. On truncation (pos > size) we
# also reset. On first sight, we skip existing content (set pos to current size)
# so a freshly-configured rule doesn't dump the entire historic file.
FILE_LOG_MAX_LINES = 200          # per poll, per file
FILE_LOG_MAX_BYTES = 256 * 1024   # safety: don't read more than 256 KB per poll

# v3.0.2: defense-in-depth deny list for server-pushed log_watch file
# paths. By the threat model, an admin who pushes a malicious log_watch
# rule could already run `exec: cat /etc/shadow` and get the contents
# back the obvious way — so this is not a hard security boundary, just
# a sanity barrier that catches obviously-wrong configurations and
# (more usefully) raises the bar for a compromised-server-pivots-to-
# silently-exfiltrate-creds attack. realpath() resolution defeats
# symlink-bypass: a server-pushed rule with path=/tmp/innocent that's
# a symlink to /etc/shadow gets rejected.
_FILE_LOG_DENY_EXACT = frozenset({
    '/etc/shadow', '/etc/gshadow', '/etc/sudoers',
    '/etc/shadow-', '/etc/gshadow-',
})
_FILE_LOG_DENY_PREFIX = (
    '/etc/sudoers.d/',
    '/root/.ssh/',
    '/home/',           # too broad on its own — refined below to only block .ssh
    '/proc/',
    '/sys/',
    '/dev/',
)


def _file_log_path_allowed(path_str: str) -> bool:
    """Return True if the path is safe for log_watch to read.

    Resolves symlinks so a benign-looking path that resolves to /etc/shadow
    is still rejected. Blocks shadow/sudoers/SSH private keys + kernel/dev
    interfaces. Allows the common log locations (/var/log, /opt/*, /srv/*,
    /var/lib/*, ~/.local/share/, etc.).
    """
    try:
        # realpath dereferences symlinks. If the file doesn't exist yet,
        # realpath returns the unresolved-but-normalized path, which is
        # still useful for prefix matching.
        real = os.path.realpath(path_str)
    except (OSError, ValueError):
        return False
    if real in _FILE_LOG_DENY_EXACT:
        return False
    for pref in _FILE_LOG_DENY_PREFIX:
        if pref == '/home/':
            # Allow most of /home/, deny /home/*/.ssh/.
            import re as _re
            if _re.match(r'^/home/[^/]+/\.ssh/', real):
                return False
            continue
        if real.startswith(pref):
            return False
    return True


def collect_file_log(path_str, state):
    """Read new lines from an arbitrary file path.

    Args:
      path_str: absolute file path (e.g. '/var/log/myapp/access.log')
      state:    dict shared across calls — keyed by path. Caller persists it.

    Returns: list of {ts, message, unit, level} dicts, ready to be put under
    the synthetic unit name 'file:<path>'. Empty list on missing/unreadable
    file.
    """
    entries = []
    # v3.0.2: deny list for sensitive paths. See _file_log_path_allowed
    # for the rationale — this isn't a hard security boundary (server
    # admin has shell already) but it blocks the most obvious cred
    # exfiltration paths and resolves symlinks before checking.
    if not _file_log_path_allowed(path_str):
        log.warning(f'file_log: refusing to read denied path {path_str!r}')
        return []
    try:
        p = Path(path_str)
        if not p.exists() or not p.is_file():
            return []
        st = p.stat()
        inode = st.st_ino
        size  = st.st_size
        prev  = state.get(path_str) or {}
        prev_inode = prev.get('inode')
        prev_pos   = int(prev.get('pos', 0))
        # Rotation: inode changed → reset to start of the new file
        if prev_inode is not None and prev_inode != inode:
            log.debug(f'file_log: rotation detected for {path_str} (inode {prev_inode} -> {inode})')
            prev_pos = 0
        # Truncation: file shrank
        if prev_pos > size:
            log.debug(f'file_log: truncation detected for {path_str} (pos {prev_pos} > size {size})')
            prev_pos = 0
        # First sight: skip existing content, just bookmark current end
        if prev_inode is None:
            state[path_str] = {'inode': inode, 'pos': size}
            return []
        if prev_pos >= size:
            # Nothing new
            state[path_str] = {'inode': inode, 'pos': prev_pos}
            return []
        with p.open('r', errors='replace') as f:
            f.seek(prev_pos)
            new_text = f.read(FILE_LOG_MAX_BYTES)
            new_pos  = f.tell()
        now = int(time.time() * 1000)
        synthetic_unit = f'file:{path_str}'
        for line in new_text.splitlines()[-FILE_LOG_MAX_LINES:]:
            line = line.strip()
            if not line:
                continue
            entries.append({
                'ts': now, 'message': line[:1024],
                'unit': synthetic_unit, 'level': 'info',
            })
        state[path_str] = {'inode': inode, 'pos': new_pos}
    except PermissionError:
        log.debug(f'file_log: permission denied for {path_str} — agent needs read access')
    except Exception as e:
        log.debug(f'file_log: collection failed for {path_str}: {e}')
    return entries


# v3.0.1: ACME / Let's Encrypt scanner — reads acme.sh state from
# ~/.acme.sh/<domain>/<domain>.conf on the device. No mutation, just read.
# The actual issue/renew/revoke happens via exec: commands queued by the
# server (acme.sh writes back to the same dir; next scan picks up the new
# state).
ACME_HOME_CANDIDATES = (
    Path('/root/.acme.sh'),                # standard root install
    Path.home() / '.acme.sh',              # whoever the agent runs as
    Path('/etc/acme.sh'),                  # rare manual install
)

# acme.sh's DNS provider keys map to human-readable names. Subset — extend
# as we add UI support for more providers.
_ACME_DNS_LABELS = {
    'dns_cf':       'Cloudflare',
    'dns_aws':      'AWS Route 53',
    'dns_gandi_livedns': 'Gandi',
    'dns_dgon':     'DigitalOcean',
    'dns_he':       'Hurricane Electric',
    'dns_desec':    'deSEC',
    'dns_namecheap':'Namecheap',
    'dns_namesilo': 'NameSilo',
    'dns_ovh':      'OVH',
    'dns_rfc2136':  'RFC 2136 (dynamic DNS)',
    'dns_acmedns':  'acme-dns',
    'dns_hetzner':  'Hetzner',
    'dns_porkbun':  'Porkbun',
}

MAX_ACME_CERTS = 100
# v3.14.0: caps for the new heartbeat sections (match server-side sanitizers).
MAX_GPUS       = 16
MAX_CERT_FILES = 256
MAX_ACCOUNTS   = 1024
MAX_UPS        = 8

def _acme_decode_reload(s):
    """acme.sh stores Le_ReloadCmd base64-wrapped between sentinels."""
    if not isinstance(s, str) or not s:
        return ''
    marker_open  = '__ACME_BASE64__START_'
    marker_close = '__ACME_BASE64__END_'
    if marker_open not in s:
        return s
    try:
        a = s.index(marker_open) + len(marker_open)
        b = s.index(marker_close, a)
        import base64
        return base64.b64decode(s[a:b]).decode('utf-8', errors='replace').strip()
    except Exception:
        return s

def _acme_parse_conf(conf_path):
    """Parse an acme.sh per-domain .conf file. Returns dict or None."""
    try:
        lines = conf_path.read_text(errors='replace').splitlines()
    except Exception:
        return None
    out = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        k, _, v = line.partition('=')
        k = k.strip()
        v = v.strip()
        # Strip matching surrounding quotes (' or ")
        if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
            v = v[1:-1]
        out[k] = v
    return out

def collect_acme_state():
    """Walk acme.sh home and return per-cert metadata. Returns:
        {'available': bool, 'home': str|None, 'version': str|None, 'certs': [...]}

    A cert entry has: domain, alt_names, challenge, dns_provider, dns_provider_label,
    is_wildcard, key_length, created_ts, next_renew_ts, created_str, next_renew_str,
    reload_cmd, cert_path, key_path, fullchain_path."""
    state = {'available': False, 'home': None, 'version': None, 'certs': []}
    home = None
    for candidate in ACME_HOME_CANDIDATES:
        try:
            if candidate.is_dir() and (candidate / 'acme.sh').is_file():
                home = candidate
                break
        except (OSError, PermissionError):
            continue
    if home is None:
        return state
    state['available'] = True
    state['home'] = str(home)
    # Probe version. acme.sh --version prints "vX.Y.Z" to stdout.
    try:
        proc = subprocess.run([str(home / 'acme.sh'), '--version'],
                              capture_output=True, text=True, timeout=5,
                              cwd=str(home))
        ver_out = (proc.stdout or '').strip().splitlines()
        for vl in ver_out:
            vl = vl.strip()
            if vl.startswith('v') and vl[1:2].isdigit():
                state['version'] = vl
                break
    except Exception:
        pass
    # Walk per-domain subdirectories. acme.sh names them after the primary
    # domain. Subdir's .conf has the same name.
    count = 0
    for entry in sorted(home.iterdir()):
        if count >= MAX_ACME_CERTS:
            break
        try:
            if not entry.is_dir():
                continue
        except OSError:
            continue
        name = entry.name
        # Skip acme.sh internals — these aren't certs
        if name in ('ca', 'deploy', 'dnsapi', 'notify', 'zone', 'http.header'):
            continue
        conf_path = entry / f'{name}.conf'
        if not conf_path.is_file():
            continue
        conf = _acme_parse_conf(conf_path)
        if not conf or not conf.get('Le_Domain'):
            continue
        domain = conf.get('Le_Domain', name)
        alt_raw = conf.get('Le_Alt', '')
        alt_names = []
        if alt_raw and alt_raw != 'no':
            alt_names = [a.strip() for a in alt_raw.split(',') if a.strip() and a.strip() != 'no']
        challenge = conf.get('Le_Webroot', '')   # despite the name, may be 'dns_cf', 'apache', etc.
        is_dns = challenge.startswith('dns_')
        dns_provider = challenge if is_dns else ''
        dns_label = _ACME_DNS_LABELS.get(dns_provider, dns_provider) if is_dns else ''
        # Cert file paths under the domain dir
        cert_file = entry / f'{name}.cer'
        key_file  = entry / f'{name}.key'
        full_file = entry / 'fullchain.cer'
        def _int_or_none(s):
            try:
                return int(s) if s else None
            except (TypeError, ValueError):
                return None
        cert_entry = {
            'domain':              domain,
            'alt_names':           alt_names,
            'is_wildcard':         any(a.startswith('*.') for a in [domain, *alt_names]),
            'challenge':           challenge,
            'is_dns_challenge':    is_dns,
            'dns_provider':        dns_provider,
            'dns_provider_label':  dns_label,
            'key_length':          conf.get('Le_Keylength', ''),
            'created_ts':          _int_or_none(conf.get('Le_CertCreateTime')),
            'next_renew_ts':       _int_or_none(conf.get('Le_NextRenewTime')),
            'created_str':         conf.get('Le_CertCreateTimeStr', ''),
            'next_renew_str':      conf.get('Le_NextRenewTimeStr', ''),
            'reload_cmd':          _acme_decode_reload(conf.get('Le_ReloadCmd', ''))[:512],
            'cert_path':           str(cert_file) if cert_file.is_file() else '',
            'key_path':            str(key_file)  if key_file.is_file()  else '',
            'fullchain_path':      str(full_file) if full_file.is_file() else '',
        }
        state['certs'].append(cert_entry)
        count += 1
    return state



def collect_web_access_logs(state_dir):
    """v2.8.0: collect new lines from nginx/apache2 access logs.

    Incremental (mtime + byte-offset gated), same approach as collect_apt_history().
    Returns {virtual_unit_name: [line_strings]} for any log that has new content.
    """
    results = {}
    for log_path_str, unit_name in WEB_ACCESS_LOGS:
        log_path = Path(log_path_str)
        if not log_path.exists():
            continue
        state_file = state_dir / f'{unit_name.replace(".", "_")}_state.json'
        try:
            mtime    = log_path.stat().st_mtime
            last_mtime = last_pos = 0
            if state_file.exists():
                st = json.loads(state_file.read_text())
                last_mtime = float(st.get('mtime', 0))
                last_pos   = int(st.get('pos', 0))
            if mtime <= last_mtime:
                continue
            with log_path.open('r', errors='replace') as f:
                f.seek(last_pos)
                new_text = f.read(WEB_ACCESS_MAX_LINES * 300)
                new_pos  = f.tell()
            lines = new_text.splitlines()[-WEB_ACCESS_MAX_LINES:]
            if lines:
                results[unit_name] = [l.strip() for l in lines if l.strip()]
            try:
                state_file.write_text(json.dumps({'mtime': mtime, 'pos': new_pos}))
            except Exception:
                pass
        except Exception as e:
            log.debug(f'web access log {log_path_str} collect failed: {e}')
    return results


def collect_backup_status(backup_monitors):
    """v2.8.1: check mtime of configured backup file paths.

    backup_monitors: list of {path, label, max_age_hours} dicts from server config.
    Returns a list of {path, exists, mtime} for each configured path.
    """
    results = []
    for mon in (backup_monitors or []):
        p = mon.get('path', '')
        if not p:
            continue
        try:
            fp = Path(p)
            exists = fp.exists()
            mtime  = fp.stat().st_mtime if exists else 0
        except Exception:
            exists, mtime = False, 0
        results.append({'path': p, 'exists': exists, 'mtime': int(mtime)})
    return results


def detect_auto_watch_units():
    """v2.7.0: return AUTO_WATCH_UNITS that actually exist on this host."""
    present = []
    for unit in AUTO_WATCH_UNITS:
        try:
            r = subprocess.run(['systemctl', 'cat', unit],
                               capture_output=True, timeout=5)
            if r.returncode == 0:
                present.append(unit)
        except Exception:
            pass
    return present



def _sock_scope(addr):
    """v3.11.0: classify a listening socket's bind address into an exposure
    scope so the server can flag world-reachable services.
      'local' — loopback (127.0.0.0/8, ::1): never reachable off-host
      'lan'   — RFC1918 / link-local / ULA: reachable on the local network
      'world' — wildcard (0.0.0.0, ::) or any global address: reachable
                from anywhere the host is routable
    Unknown / unparseable addresses fall back to 'world' (fail loud, not
    silent — an exposure we can't classify is treated as the riskier case).
    """
    a = (addr or '').strip().strip('[]')
    if not a:
        return 'world'
    if a in ('0.0.0.0', '::', '*'):
        return 'world'
    try:
        import ipaddress
        ip = ipaddress.ip_address(a)
        if ip.is_loopback:
            return 'local'
        if ip.is_private or ip.is_link_local:
            return 'lan'
        return 'world'
    except (ValueError, ImportError):
        if a.startswith('127.') or a == '::1':
            return 'local'
        if (a.startswith('10.') or a.startswith('192.168.')
                or a.startswith('169.254.') or a.startswith('fe80')
                or a.startswith('fc') or a.startswith('fd')):
            return 'lan'
        for _o in range(16, 32):
            if a.startswith(f'172.{_o}.'):
                return 'lan'
        return 'world'


def collect_firewall_detail():
    """v3.12.0: per-backend host-firewall posture — nftables, iptables, ufw,
    ebtables. For each backend report whether the tool is present, whether it
    has an active ruleset, a rough rule count, and (where cheap) the default
    policy. Best-effort and root-dependent; each probe is isolated so one
    missing tool never sinks the rest. Feeds the device Audit -> Firewall view
    and the per-asset risk score."""
    def _run(argv, timeout=6):
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
            return r.returncode, (r.stdout or ''), (r.stderr or '')
        except Exception as e:
            return 127, '', str(e)
    # A probe that errors with no output couldn't read the ruleset (e.g. the
    # tool is a wrapper that needs a kernel module, or no permission). We must
    # NOT report that as "inactive" — that would wrongly flag a firewalled host
    # as unprotected and raise its risk. active=None means "unknown".
    def _unreadable(rc, txt):
        return rc != 0 and not txt.strip()
    backends = []

    # nftables — the modern in-kernel firewall (also the backend iptables-nft
    # uses). Count rules by their handle (`nft -a` stamps `# handle N` on each
    # *rule*; table/chain headers carry a handle too but always contain `{`, so
    # excluding `{` lines counts rules only). This is far more reliable than the
    # old verdict-keyword heuristic, which missed rules that don't end in a bare
    # accept/drop (e.g. `... counter` or a named-set jump).
    nft = _which('nft')
    if nft:
        rc, txt, _ = _run([nft, '-a', 'list', 'ruleset'])
        rules = sum(1 for l in txt.splitlines() if '# handle ' in l and '{' not in l)
        if rules == 0 and txt.strip():
            # Fallback for nft builds where -a doesn't emit handles.
            rules = sum(1 for l in txt.splitlines()
                        if any(v in l for v in (' accept', ' drop', ' reject', ' queue', ' jump ', ' goto ')))
        backends.append({'name': 'nftables', 'present': True, 'rules': rules,
                         'active': None if _unreadable(rc, txt) else rules > 0})

    # iptables — probe EVERY available variant and take the best reading. The
    # active ruleset can live in the nft *or* the legacy backend (Docker and
    # Proxmox/PMG commonly use legacy even when `iptables` resolves to the nft
    # shim), and `iptables-save` dumps all tables (filter/nat/mangle/raw) where
    # custom chains like Docker's or PVEFW-* live. We try -save AND the plain
    # `-S` list for both backends — crucially falling back to `-S` when `-save`
    # is present but errors (the v3.13.0 regression that reported "unknown"),
    # and take the MAX rule count across whatever was readable.
    ipt_present = False
    ipt_rules = 0
    ipt_policy = ''
    ipt_readable = False
    for binname, arg in (('iptables-save', None), ('iptables', '-S'),
                         ('iptables-legacy-save', None), ('iptables-legacy', '-S')):
        b = _which(binname)
        if not b:
            continue
        ipt_present = True
        rc, txt, _ = _run([b] if arg is None else [b, arg])
        if _unreadable(rc, txt) or not txt.strip():
            continue
        ipt_readable = True
        n, pol = 0, ''
        for l in txt.splitlines():
            ls = l.strip()
            if ls.startswith('-A '):
                n += 1
            elif ls.startswith(':INPUT ') and not pol:      # save form
                p = ls.split();  pol = p[1] if len(p) >= 2 else ''
            elif ls.startswith('-P INPUT ') and not pol:    # -S form
                p = ls.split();  pol = p[2] if len(p) >= 3 else ''
        if n > ipt_rules:
            ipt_rules = n
        if pol and (not ipt_policy or ipt_policy == 'ACCEPT'):
            ipt_policy = pol
    if ipt_present:
        b = {'name': 'iptables', 'present': True, 'rules': ipt_rules}
        if ipt_policy:
            b['policy'] = ipt_policy
        b['active'] = (ipt_rules > 0 or ipt_policy in ('DROP', 'REJECT')) if ipt_readable else None
        backends.append(b)

    # firewalld — a front-end that programs nftables/iptables underneath. The
    # nft probe above already sees its rules, but report it explicitly so the
    # operator knows what's managing the host.
    fwc = _which('firewall-cmd')
    if fwc:
        rc, st, _ = _run([fwc, '--state'])
        _rc2, allz, _ = _run([fwc, '--list-all'])
        rules = sum(len(ls.split(':', 1)[1].split())
                    for ls in (x.strip() for x in allz.splitlines())
                    if ls.startswith(('services:', 'ports:', 'rich rules:')) and ':' in ls)
        backends.append({'name': 'firewalld', 'present': True, 'rules': rules,
                         'active': None if _unreadable(rc, st) else ('running' in st.lower())})

    # ufw — a front-end (counted separately because operators manage it directly)
    ufw = _which('ufw')
    if ufw:
        rc, txt, _ = _run([ufw, 'status', 'verbose'])
        default, rules = '', 0
        for l in txt.splitlines():
            ls = l.strip()
            if ls.lower().startswith('default:'):
                default = ls.split(':', 1)[1].strip()
            elif any(tok in l for tok in ('ALLOW', 'DENY', 'REJECT', 'LIMIT')):
                rules += 1
        b = {'name': 'ufw', 'present': True, 'rules': rules}
        if default:
            b['default'] = default
        b['active'] = None if _unreadable(rc, txt) else ('status: active' in txt.lower())
        backends.append(b)

    # ebtables — layer-2 / bridge firewall
    ebt = _which('ebtables')
    if ebt:
        rc, txt, _ = _run([ebt, '-L'])
        rules = 0
        for l in txt.splitlines():
            ls = l.strip()
            if not ls or ls.startswith('Bridge table') or ls.startswith('Bridge chain'):
                continue
            rules += 1
        backends.append({'name': 'ebtables', 'present': True, 'rules': rules,
                         'active': None if _unreadable(rc, txt) else rules > 0})

    if not backends:
        return None
    # Overall active = any READABLE backend is active. If none were readable
    # (all unknown), overall is None so the risk score doesn't falsely penalise.
    readable = [b for b in backends if b.get('active') is not None]
    overall = any(b['active'] for b in readable) if readable else None
    return {'backends': backends, 'active': overall}


def get_host_health():
    """v2.2.6: extra host telemetry — cheap signals an operator wants
    at a glance but that weren't collected before. Everything here is
    best-effort: any probe that fails is simply omitted, never raises.

    Returns a dict merged into sysinfo:
      reboot_required : bool   — /run/reboot-required exists (Debian/Ubuntu)
      reboot_reason   : str    — package(s) that triggered it, if known
      failed_units    : [str]  — systemd units in 'failed' state
      logged_in       : [str]  — distinct usernames with an active session
      listening_ports : [dict] — {proto, port, process} for LISTEN sockets
      last_boot       : int    — epoch seconds of last boot
    """
    out = {}

    # ── reboot-required (Debian/Ubuntu convention) ───────────────────
    try:
        rr = Path('/run/reboot-required')
        if rr.exists() or Path('/var/run/reboot-required').exists():
            out['reboot_required'] = True
            pkgs = Path('/run/reboot-required.pkgs')
            if pkgs.exists():
                names = sorted(set(pkgs.read_text().split()))
                out['reboot_reason'] = ', '.join(names[:10])
        else:
            out['reboot_required'] = False
    except Exception:
        pass

    # ── systemd failed units ─────────────────────────────────────────
    try:
        if _which('systemctl'):
            r = subprocess.run(
                ['systemctl', '--failed', '--no-legend', '--plain',
                 '--no-pager'],
                capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                failed = []
                for line in r.stdout.splitlines():
                    line = line.strip()
                    if line:
                        # First column is the unit name
                        failed.append(line.split()[0])
                out['failed_units'] = failed[:30]
    except Exception:
        pass

    # ── logged-in users ──────────────────────────────────────────────
    try:
        if _which('who'):
            r = subprocess.run(['who'], capture_output=True, text=True,
                               timeout=5)
            if r.returncode == 0:
                users = sorted({ln.split()[0] for ln in r.stdout.splitlines()
                                if ln.strip()})
                out['logged_in'] = users[:50]
    except Exception:
        pass

    # ── listening ports ──────────────────────────────────────────────
    # Two complementary sources: `ss -tulnHp` (iproute2, ubiquitous on
    # mainstream Linux) and psutil.net_connections (portable, works on
    # any distro that has psutil). Each fills gaps in the other so the
    # process column stays populated across:
    #   • mainstream Linux as root: ss alone provides names
    #   • mainstream Linux as non-root with psutil: ss for ports,
    #     psutil for any missing names
    #   • minimal images (Alpine, distroless): no ss → psutil-only
    #   • host with neither: empty list (no regression vs prior behavior)
    ports = []
    seen = set()
    try:
        if _which('ss'):
            r = subprocess.run(['ss', '-tulnHp'], capture_output=True,
                               text=True, timeout=5)
            if r.returncode == 0:
                for ln in r.stdout.splitlines():
                    parts = ln.split()
                    if len(parts) < 5:
                        continue
                    proto = parts[0]
                    local = parts[4]      # e.g. 0.0.0.0:22  or  [::]:443
                    if ':' not in local:
                        continue
                    port = local.rsplit(':', 1)[1]
                    if not port.isdigit():
                        continue
                    port_n = int(port)
                    key = (proto, port_n)
                    if key in seen:
                        continue
                    seen.add(key)
                    addr = local.rsplit(':', 1)[0].strip('[]')
                    proc = ''
                    if 'users:' in ln:
                        m = re.search(r'\(\("([^"]+)"', ln)
                        if m:
                            proc = m.group(1)
                    ports.append({'proto': proto, 'port': port_n,
                                  'process': proc, 'addr': addr,
                                  'scope': _sock_scope(addr)})
    except Exception:
        pass

    # psutil supplements ss: adds entries ss missed (or runs solo when
    # ss isn't installed) and fills in process names ss left blank.
    # UDP listening sockets have status='NONE' in psutil (UDP is
    # connectionless), so accept both LISTEN and NONE for UDP.
    if _PSUTIL:
        try:
            for c in _psutil.net_connections('inet'):
                if not c.laddr:
                    continue
                is_tcp = (c.type == socket.SOCK_STREAM)
                is_udp = (c.type == socket.SOCK_DGRAM)
                if not (is_tcp or is_udp):
                    continue
                if is_tcp and c.status != 'LISTEN':
                    continue
                # UDP entries also include connected sockets (status='ESTABLISHED'
                # on a few kernels); restrict to true listeners.
                if is_udp and c.status not in ('NONE', 'LISTEN'):
                    continue
                proto = 'tcp' if is_tcp else 'udp'
                key = (proto, c.laddr.port)
                proc = ''
                if c.pid:
                    try:
                        proc = _psutil.Process(c.pid).name()
                    except (_psutil.NoSuchProcess, _psutil.AccessDenied):
                        pass
                existing = next((p for p in ports
                                 if (p['proto'], p['port']) == key), None)
                if existing:
                    if not existing['process'] and proc:
                        existing['process'] = proc
                elif key not in seen:
                    seen.add(key)
                    _ip = getattr(c.laddr, 'ip', '') or ''
                    ports.append({'proto': proto, 'port': c.laddr.port,
                                  'process': proc, 'addr': _ip,
                                  'scope': _sock_scope(_ip)})
        except Exception:
            pass

    if ports:
        ports.sort(key=lambda p: p['port'])
        out['listening_ports'] = ports[:80]

    # ── last boot time ───────────────────────────────────────────────
    try:
        with open('/proc/uptime') as fh:
            up = float(fh.read().split()[0])
        out['last_boot'] = int(time.time() - up)
    except Exception:
        pass

    # ── storage / RAID health (v3.11.0) ──────────────────────────────
    # ZFS / mdadm / btrfs redundant-storage state. Cheap, read-only, and
    # each backend is independently guarded so a host with only one (or
    # none) reports just what it has.
    pools = []
    try:
        if _which('zpool'):
            r = subprocess.run(['zpool', 'list', '-H', '-o',
                                'name,health,capacity'],
                               capture_output=True, text=True, timeout=8)
            if r.returncode == 0:
                for ln in r.stdout.splitlines():
                    f = ln.split('\t') if '\t' in ln else ln.split()
                    if len(f) < 2:
                        continue
                    pool = {'name': f[0], 'kind': 'zfs', 'state': f[1]}
                    if len(f) > 2:
                        try:
                            pool['capacity'] = int(f[2].rstrip('%'))
                        except ValueError:
                            pass
                    pools.append(pool)
            rs = subprocess.run(['zpool', 'status'], capture_output=True,
                                text=True, timeout=8)
            if rs.returncode == 0:
                cur = None
                for ln in rs.stdout.splitlines():
                    s = ln.strip()
                    if s.startswith('pool:'):
                        cur = s.split(':', 1)[1].strip()
                    elif s.startswith('scan:') and cur:
                        for p in pools:
                            if p['name'] == cur:
                                p['scrub'] = s.split(':', 1)[1].strip()[:140]
    except Exception:
        pass
    try:
        mdstat = Path('/proc/mdstat')
        if mdstat.exists():
            cur = None
            for ln in mdstat.read_text().splitlines():
                head = ln.split(':')[0].strip()
                if ln and not ln.startswith(' ') and head.startswith('md'):
                    cur = head
                    pools.append({'name': cur, 'kind': 'mdraid',
                                  'state': 'active' if 'active' in ln else 'unknown'})
                elif cur and '[' in ln and ']' in ln:
                    blockmap = ln[ln.rfind('['):]
                    if '_' in blockmap:   # a missing member → degraded
                        for p in pools:
                            if p['name'] == cur and p['kind'] == 'mdraid':
                                p['state'] = 'degraded'
    except Exception:
        pass
    try:
        if _which('btrfs'):
            r = subprocess.run(['btrfs', 'filesystem', 'show'],
                               capture_output=True, text=True, timeout=8)
            if r.returncode == 0:
                for ln in r.stdout.splitlines():
                    s = ln.strip()
                    if s.startswith('Label:'):
                        nm = (s.split('uuid:')[-1].strip()[:16]
                              if 'uuid:' in s else s[:24])
                        pools.append({'name': 'btrfs:' + nm, 'kind': 'btrfs',
                                      'state': 'online'})
    except Exception:
        pass
    if pools:
        out['storage_health'] = pools[:40]

    # ── recent logins / source IPs (v3.11.0 access watch) ────────────
    try:
        if _which('last'):
            r = subprocess.run(['last', '-i', '-w', '-F', '-n', '25'],
                               capture_output=True, text=True, timeout=8)
            if r.returncode == 0:
                logins, srcs = [], []
                for ln in r.stdout.splitlines():
                    s = ln.strip()
                    if not s or s.startswith('wtmp begins'):
                        continue
                    f = s.split()
                    if len(f) < 2 or f[0] in ('reboot', 'shutdown'):
                        continue
                    ip = ''
                    for tok in f[1:5]:
                        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', tok) or \
                           (tok.count(':') >= 2):
                            ip = tok
                            break
                    logins.append({'user': f[0], 'source': ip})
                    if ip and ip not in srcs and ip != '0.0.0.0':
                        srcs.append(ip)
                if logins:
                    out['auth'] = {'recent_logins': logins[:25],
                                   'sources': srcs[:25]}
    except Exception:
        pass

    # ── systemd timer (scheduled job) health (v3.11.0) ───────────────
    try:
        if _which('systemctl'):
            failed_set = set(out.get('failed_units', []))
            r = subprocess.run(['systemctl', 'list-timers', '--all',
                                '--no-legend', '--no-pager'],
                               capture_output=True, text=True, timeout=8)
            if r.returncode == 0:
                timers = []
                for ln in r.stdout.splitlines():
                    f = ln.split()
                    unit = activates = ''
                    for i, tok in enumerate(f):
                        if tok.endswith('.timer'):
                            unit = tok
                            activates = f[i + 1] if i + 1 < len(f) else ''
                            break
                    if not unit:
                        continue
                    timers.append({
                        'unit': unit, 'activates': activates,
                        'failed': bool(activates in failed_set
                                       or unit in failed_set)})
                if timers:
                    out['timers'] = timers[:60]
    except Exception:
        pass

    # ── host firewall fingerprint (v3.11.0 drift) ────────────────────
    # A stable hash of the active ruleset so the server can detect a
    # change vs the captured baseline. Volatile iptables packet/byte
    # counters are zeroed first so the fingerprint only moves on a real
    # rule change.
    try:
        import hashlib
        fw_backend = fw_text = ''
        if _which('nft'):
            r = subprocess.run(['nft', 'list', 'ruleset'],
                               capture_output=True, text=True, timeout=8)
            if r.returncode == 0 and r.stdout.strip():
                # Zero nftables per-rule `counter packets N bytes N`
                # statements so the fingerprint only moves on a real
                # rule change, not on traffic (mirrors the iptables path).
                fw_backend = 'nftables'
                fw_text = re.sub(r'counter packets \d+ bytes \d+',
                                 'counter packets 0 bytes 0', r.stdout)
        if not fw_text and _which('ufw'):
            r = subprocess.run(['ufw', 'status', 'verbose'],
                               capture_output=True, text=True, timeout=8)
            if r.returncode == 0 and r.stdout.strip():
                fw_backend, fw_text = 'ufw', r.stdout
        if not fw_text and _which('iptables-save'):
            r = subprocess.run(['iptables-save'],
                               capture_output=True, text=True, timeout=8)
            if r.returncode == 0 and r.stdout.strip():
                fw_backend = 'iptables'
                norm = re.sub(r'\[\d+:\d+\]', '[0:0]', r.stdout)
                fw_text = '\n'.join(l for l in norm.splitlines()
                                    if not l.startswith('#'))
        if fw_text:
            n = sum(1 for l in fw_text.splitlines()
                    if l.strip() and not l.strip().startswith('#'))
            out['firewall_fp'] = {
                'backend': fw_backend, 'rules': n,
                'fp': hashlib.sha256(
                    fw_text.encode('utf-8', 'replace')).hexdigest()[:16]}
    except Exception:
        pass

    # v3.12.0: richer per-backend firewall posture (Audit -> Firewall + risk)
    try:
        _fwd = collect_firewall_detail()
        if _fwd:
            out['firewall'] = _fwd
    except Exception:
        pass

    return out


# ─── v3.4.0: hardware / health probes ────────────────────────────────────────
# SMART, kernel/livepatch, and passive hardware inventory. All three are
# best-effort and follow get_host_health()'s contract: every probe is wrapped
# so a failure (missing tool, no permission, weird output) is silently omitted
# rather than raising. They run on the slower CONTAINER_CHECK_EVERY cadence —
# not every heartbeat — because smartctl/dmidecode/sensors aren't free.

# SMART attribute IDs worth surfacing: reallocated sectors, pending sectors,
# offline-uncorrectable, CRC errors, temperature, power-on hours. Pre-fail of
# any of the first three is the classic "disk is dying" signal.
_SMART_ATTRS = {
    5:   'reallocated_sectors',
    187: 'reported_uncorrect',
    197: 'pending_sectors',
    198: 'offline_uncorrectable',
    199: 'crc_errors',
    194: 'temperature_c',
    9:   'power_on_hours',
}


def _list_block_devices():
    """Return candidate disk device paths (/dev/sdX, /dev/nvmeXnY, /dev/vdX).

    Uses lsblk when present (authoritative, excludes partitions/loop/rom);
    falls back to scanning /sys/block. Best-effort, returns [] on failure.
    """
    devs = []
    try:
        if _which('lsblk'):
            r = subprocess.run(['lsblk', '-dnpo', 'NAME,TYPE'],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                for ln in r.stdout.splitlines():
                    parts = ln.split()
                    if len(parts) >= 2 and parts[1] == 'disk':
                        devs.append(parts[0])
                return devs
    except Exception:
        pass
    try:
        for name in sorted(os.listdir('/sys/block')):
            if name.startswith(('loop', 'ram', 'sr', 'fd', 'dm-', 'md')):
                continue
            devs.append('/dev/' + name)
    except Exception:
        pass
    return devs


def get_av_status():
    """v3.6.0: endpoint AV/malware posture from ClamAV and rkhunter.

    Best-effort, read-only — never triggers a scan here (an on-demand scan is a
    queued exec command). Reports which tools are installed, the ClamAV
    signature DB age, and a parse of the most recent rkhunter/clamav log for a
    warning/infection count. Returns {} when no AV tooling is present so the
    server keeps the key absent.

    Shape:
        {clamav: {installed, db_age_days|None, last_scan_ts|None, infected|None},
         rkhunter: {installed, last_run_ts|None, warnings|None}}
    """
    import os as _os, re as _re, time as _time
    out = {}
    # ── ClamAV ──────────────────────────────────────────────────────────────
    clam_installed = bool(_which('clamscan') or _which('clamdscan'))
    if clam_installed:
        c = {'installed': True, 'db_age_days': None, 'last_scan_ts': None, 'infected': None}
        # Signature DB freshness — newest of the daily/main/bytecode files.
        newest = 0
        for d in ('/var/lib/clamav',):
            try:
                for fn in _os.listdir(d):
                    if fn.endswith(('.cvd', '.cld')):
                        newest = max(newest, int(_os.path.getmtime(_os.path.join(d, fn))))
            except OSError:
                pass
        if newest:
            c['db_age_days'] = max(0, int((_time.time() - newest) / 86400))
        # Last scan result from a conventional clamav scan log, if present.
        log = _safe_read('/var/log/clamav/scan.log', 40_000) or ''
        m = _re.findall(r'Infected files:\s*(\d+)', log)
        if m:
            c['infected'] = int(m[-1])
        # v3.10.0: last-scan timestamp from the clamscan SCAN SUMMARY block
        # ("End Date: 2024:01:15 10:30:12"). Lets the UI show how fresh the
        # last on-demand scan was, not just the signature-DB age.
        dm = _re.findall(r'(?:End|Start) Date:\s*(\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2})', log)
        if dm:
            try:
                import datetime as _dt
                c['last_scan_ts'] = int(
                    _dt.datetime.strptime(dm[-1], '%Y:%m:%d %H:%M:%S').timestamp())
            except (ValueError, TypeError):
                pass
        out['clamav'] = c
    # ── rkhunter ─────────────────────────────────────────────────────────────
    if _which('rkhunter'):
        r = {'installed': True, 'last_run_ts': None, 'warnings': None}
        rk = _safe_read('/var/log/rkhunter.log', 200_000) or ''
        warn = _re.findall(r'\[\s*[Ww]arning\s*\]', rk)
        if rk:
            r['warnings'] = len(warn)
        try:
            r['last_run_ts'] = int(_os.path.getmtime('/var/log/rkhunter.log'))
        except OSError:
            pass
        out['rkhunter'] = r
    return out


def get_smart_status():
    """v3.4.0: SMART health per physical disk via `smartctl`.

    Returns a list of per-disk dicts:
        {device, health: PASSED|FAILED|UNKNOWN, model, serial,
         <attr>: <raw value>, ...}
    Empty list if smartctl isn't installed or no disks could be read.
    smartctl needs root for most devices; when run unprivileged it usually
    fails cleanly and that disk is simply omitted.
    """
    smartctl = _which('smartctl')
    if not smartctl:
        return []
    disks = []
    for dev in _list_block_devices()[:32]:
        try:
            r = subprocess.run([smartctl, '-H', '-A', '-i', dev],
                               capture_output=True, text=True, timeout=20)
        except Exception:
            continue
        out = r.stdout
        if not out:
            continue
        entry = {'device': dev, 'health': 'UNKNOWN'}
        # Overall health line varies by transport:
        #   ATA:  "SMART overall-health self-assessment test result: PASSED"
        #   NVMe: "SMART overall-health self-assessment test result: PASSED"
        #   some: "SMART Health Status: OK"
        m = re.search(r'self-assessment test result:\s*(\S+)', out)
        if m:
            entry['health'] = m.group(1).strip().upper()
        else:
            m = re.search(r'SMART Health Status:\s*(\S+)', out)
            if m:
                entry['health'] = 'PASSED' if m.group(1).upper() == 'OK' else m.group(1).upper()
        # Identity
        mi = re.search(r'(?:Device Model|Model Number):\s*(.+)', out)
        if mi:
            entry['model'] = mi.group(1).strip()
        si = re.search(r'Serial Number:\s*(.+)', out)
        if si:
            entry['serial'] = si.group(1).strip()
        # ATA attribute table: ID# ATTRIBUTE_NAME FLAG VALUE WORST THRESH ... RAW_VALUE
        for ln in out.splitlines():
            parts = ln.split()
            if len(parts) >= 10 and parts[0].isdigit():
                aid = int(parts[0])
                if aid in _SMART_ATTRS:
                    raw = parts[9].split()[0]
                    try:
                        entry[_SMART_ATTRS[aid]] = int(raw)
                    except ValueError:
                        entry[_SMART_ATTRS[aid]] = raw
                # v3.4.0+: SATA SSD wear. Vendors expose a life-remaining
                # NORMALIZED value (col 4, counts 100→0); invert to a used%.
                if 'wear_pct' not in entry and any(
                        t in parts[1].lower() for t in
                        ('wear_leveling', 'media_wearout', 'ssd_life_left',
                         'percent_lifetime', 'percent_life')):
                    try:
                        norm = int(parts[3])
                        entry['wear_pct'] = max(0, min(100, 100 - norm))
                    except (ValueError, IndexError):
                        pass
        # NVMe health lines (different format) — pull a couple of useful ones.
        nm = re.search(r'Temperature:\s*(\d+)\s*Celsius', out)
        if nm and 'temperature_c' not in entry:
            entry['temperature_c'] = int(nm.group(1))
        nh = re.search(r'Power On Hours:\s*([\d,]+)', out)
        if nh and 'power_on_hours' not in entry:
            entry['power_on_hours'] = int(nh.group(1).replace(',', ''))
        # v3.14.0: NVMe reports a direct "Percentage Used" (a used%) — wins.
        nw = re.search(r'Percentage Used:\s*(\d+)\s*%', out)
        if nw:
            entry['wear_pct'] = max(0, min(100, int(nw.group(1))))
        disks.append(entry)
    return disks


def get_kernel_status():
    """v3.4.0: running kernel vs newest installed kernel, plus livepatch.

    Returns:
        {running, latest_installed, reboot_for_kernel: bool,
         livepatch: {state, patched} | None}
    Best-effort; fields omitted when undeterminable.
    """
    out = {}
    try:
        out['running'] = platform.release()
    except Exception:
        return out

    # Newest installed kernel package. Debian/Ubuntu: dpkg linux-image-*;
    # RHEL/SUSE: rpm kernel; Arch: pacman linux. We compare the *version*
    # the package provides against the running release.
    latest = None
    try:
        if _which('dpkg-query'):
            r = subprocess.run(
                ['dpkg-query', '-W', '-f=${Package}\\n',
                 'linux-image-[0-9]*'],
                capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                vers = []
                for pkg in r.stdout.split():
                    mm = re.match(r'linux-image-(\d.+)', pkg)
                    if mm:
                        vers.append(mm.group(1))
                if vers:
                    latest = max(vers, key=_kernel_ver_key)
        elif _which('rpm'):
            r = subprocess.run(['rpm', '-q', '--qf', '%{VERSION}-%{RELEASE}.%{ARCH}\\n', 'kernel'],
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                vers = [v for v in r.stdout.split() if v]
                if vers:
                    latest = max(vers, key=_kernel_ver_key)
    except Exception:
        pass
    if latest:
        out['latest_installed'] = latest
        # Reboot needed when the running release isn't a prefix of the newest
        # installed one (handles the trailing arch/flavour suffix).
        run = out.get('running', '')
        out['reboot_for_kernel'] = bool(run) and (run not in latest) and (latest not in run)

    # Live patching: Canonical Livepatch or kpatch.
    try:
        if _which('canonical-livepatch'):
            r = subprocess.run(['canonical-livepatch', 'status'],
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                lp = {'provider': 'canonical-livepatch'}
                sm = re.search(r'(?:checkState|check state):\s*(\S+)', r.stdout)
                if sm:
                    lp['state'] = sm.group(1)
                lp['patched'] = 'applied' in r.stdout.lower() or 'kernel-applied' in r.stdout.lower()
                out['livepatch'] = lp
        elif _which('kpatch'):
            r = subprocess.run(['kpatch', 'list'], capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                loaded = [ln for ln in r.stdout.splitlines()
                          if ln.strip() and not ln.lower().startswith(('loaded', 'installed'))]
                out['livepatch'] = {'provider': 'kpatch', 'patched': bool(loaded)}
    except Exception:
        pass
    return out


def _kernel_ver_key(v):
    """Sort key for kernel version strings: split into numeric/text runs so
    '5.15.0-89' sorts below '5.15.0-101'. Best-effort, never raises."""
    parts = re.split(r'[.\-+~]', v)
    key = []
    for p in parts:
        if p.isdigit():
            key.append((1, int(p), ''))
        else:
            key.append((0, 0, p))
    return key


def get_gpu_status():
    """v3.14.0: GPU telemetry via nvidia-smi (and rocm-smi for AMD). Best-effort,
    read-only. Empty list when no GPU tooling is present."""
    gpus = []

    def _num(x):
        try:
            return round(float(x), 1)
        except (ValueError, TypeError):
            return None

    nv = _which('nvidia-smi')
    if nv:
        try:
            r = subprocess.run(
                [nv, '--query-gpu=name,utilization.gpu,memory.used,memory.total,'
                     'temperature.gpu,power.draw',
                 '--format=csv,noheader,nounits'],
                capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                for ln in r.stdout.splitlines():
                    c = [x.strip() for x in ln.split(',')]
                    if len(c) < 6:
                        continue
                    gpus.append({'vendor': 'nvidia', 'name': c[0][:96],
                                 'util_pct': _num(c[1]), 'mem_used_mb': _num(c[2]),
                                 'mem_total_mb': _num(c[3]), 'temp_c': _num(c[4]),
                                 'power_w': _num(c[5])})
        except Exception:
            pass
    amd = _which('rocm-smi')
    if amd and not gpus:
        try:
            r = subprocess.run([amd, '--showproductname', '--showtemp',
                                '--showuse', '--json'],
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0 and r.stdout.strip().startswith('{'):
                data = json.loads(r.stdout)
                for k, v in data.items():
                    if not isinstance(v, dict) or not k.lower().startswith('card'):
                        continue
                    name = v.get('Card series') or v.get('Card model') or k
                    temp = next((v[t] for t in v if 'Temperature' in t and 'edge' in t.lower()), None)
                    use = next((v[u] for u in v if 'GPU use' in u), None)
                    gpus.append({'vendor': 'amd', 'name': str(name)[:96],
                                 'util_pct': _num(use), 'temp_c': _num(temp)})
        except Exception:
            pass
    return gpus[:MAX_GPUS]


def _parse_openssl_date(s):
    """notAfter=Jun  6 12:00:00 2026 GMT → epoch seconds (0 on failure)."""
    import calendar
    s = re.sub(r'\s+', ' ', s.replace('GMT', '')).strip()
    try:
        return int(calendar.timegm(time.strptime(s, '%b %d %H:%M:%S %Y')))
    except ValueError:
        return 0


def get_cert_files():
    """v3.14.0: expiry inventory of x509 cert files in common locations, parsed
    with `openssl x509`. Best-effort; empty list when openssl is absent."""
    openssl = _which('openssl')
    if not openssl:
        return []
    import glob as _glob
    # v3.14.0 fix: scan only the host's OWN service certs — NOT the system CA
    # trust bundle (/etc/ssl/certs, /etc/pki/ca-trust, …), which holds hundreds
    # of CA certs and flooded the cert inventory/alerts.
    patterns = ['/etc/letsencrypt/live/*/fullchain.pem',
                '/etc/letsencrypt/live/*/cert.pem',
                '/etc/nginx/ssl/*.crt', '/etc/nginx/ssl/*.pem',
                '/etc/apache2/ssl/*.crt', '/etc/apache2/ssl/*.pem',
                '/etc/ssl/*.crt']
    seen = set()
    out = []
    for pat in patterns:
        for path in _glob.glob(pat):
            rp = os.path.realpath(path)
            if rp in seen:
                continue
            seen.add(rp)
            try:
                r = subprocess.run([openssl, 'x509', '-in', path, '-noout',
                                    '-enddate', '-subject', '-issuer'],
                                   capture_output=True, text=True, timeout=5)
            except Exception:
                continue
            if r.returncode != 0:
                continue
            nm = re.search(r'notAfter=(.+)', r.stdout)
            if not nm:
                continue
            subj = re.search(r'subject=(.+)', r.stdout)
            iss = re.search(r'issuer=(.+)', r.stdout)
            out.append({'path': path[:256],
                        'not_after': _parse_openssl_date(nm.group(1).strip()),
                        'subject': (subj.group(1).strip() if subj else '')[:256],
                        'issuer': (iss.group(1).strip() if iss else '')[:256]})
            if len(out) >= MAX_CERT_FILES:
                return out
    return out


_LOGIN_SHELLS = ('/bin/bash', '/bin/sh', '/bin/zsh', '/usr/bin/bash',
                 '/usr/bin/zsh', '/bin/ksh', '/usr/bin/fish', '/bin/dash')


def get_local_accounts():
    """v3.14.0: local account posture from /etc/passwd + /etc/shadow (root) +
    sudo group membership. Never includes password hashes; flags risky accounts
    (extra UID 0, empty/stale passwords)."""
    pw = _safe_read('/etc/passwd', 200_000)
    if not pw:
        return []
    shadow = {}
    sh = _safe_read('/etc/shadow', 500_000) if os.geteuid() == 0 else None
    if sh:
        today = int(time.time() // 86400)
        for ln in sh.splitlines():
            f = ln.split(':')
            if len(f) < 3:
                continue
            pwf = f[1]
            age = None
            try:
                if f[2]:
                    age = today - int(f[2])
            except ValueError:
                pass
            shadow[f[0]] = {'locked': pwf.startswith(('!', '*')),
                            'empty': pwf == '', 'age_days': age}
    sudoers = set()
    for ln in (_safe_read('/etc/group', 200_000) or '').splitlines():
        f = ln.split(':')
        if len(f) >= 4 and f[0] in ('sudo', 'wheel', 'admin'):
            sudoers.update(m for m in f[3].split(',') if m)
    accts = []
    for ln in pw.splitlines():
        f = ln.split(':')
        if len(f) < 7:
            continue
        try:
            uid = int(f[2])
        except ValueError:
            continue
        name, home, shell = f[0], f[5], f[6]
        s = shadow.get(name, {})
        can_login = shell in _LOGIN_SHELLS
        flags = []
        if uid == 0 and name != 'root':
            flags.append('uid0')
        if s.get('empty'):
            flags.append('empty_password')
        if can_login and s.get('locked') is False and isinstance(s.get('age_days'), int) and s['age_days'] > 365:
            flags.append('stale_password')
        if name in sudoers:
            flags.append('sudo')
        accts.append({'user': name[:64], 'uid': uid, 'shell': shell[:64],
                      'home': home[:128], 'login': can_login,
                      'locked': bool(s.get('locked')), 'sudo': name in sudoers,
                      'age_days': s.get('age_days'), 'flags': flags})
        if len(accts) >= MAX_ACCOUNTS:
            break
    return accts


def get_ups_status():
    """v3.14.0: UPS / power status via NUT (`upsc`) or apcupsd (`apcaccess`).
    Best-effort, read-only. Empty list when no UPS tooling is present."""
    def _f(s):
        try:
            return round(float(s), 1)
        except (TypeError, ValueError):
            return None

    out = []
    upsc = _which('upsc')
    if upsc:
        try:
            r = subprocess.run([upsc, '-l'], capture_output=True, text=True, timeout=8)
            names = [n.strip() for n in r.stdout.splitlines() if n.strip()][:8] if r.returncode == 0 else []
            for name in names:
                rr = subprocess.run([upsc, name], capture_output=True, text=True, timeout=8)
                if rr.returncode != 0:
                    continue
                kv = {}
                for ln in rr.stdout.splitlines():
                    if ':' in ln:
                        k, _, v = ln.partition(':')
                        kv[k.strip()] = v.strip()
                out.append({
                    'name': name[:64], 'driver': 'nut',
                    'status': kv.get('ups.status', '')[:32],
                    'battery_pct': _f(kv.get('battery.charge')),
                    'load_pct': _f(kv.get('ups.load')),
                    'runtime_s': _f(kv.get('battery.runtime')),
                    'input_v': _f(kv.get('input.voltage')),
                    'power_w': _f(kv.get('ups.realpower')) or _f(kv.get('ups.power')),
                })
        except Exception:
            pass
    if not out and _which('apcaccess'):
        try:
            r = subprocess.run([_which('apcaccess'), 'status'], capture_output=True, text=True, timeout=8)
            if r.returncode == 0:
                kv = {}
                for ln in r.stdout.splitlines():
                    if ':' in ln:
                        k, _, v = ln.partition(':')
                        kv[k.strip()] = v.strip()

                def _num(key):
                    m = re.search(r'[-\d.]+', kv.get(key, '') or '')
                    return float(m.group()) if m else None
                load, nom = _num('LOADPCT'), _num('NOMPOWER')
                tl = _num('TIMELEFT')
                out.append({
                    'name': (kv.get('UPSNAME') or 'apcups')[:64], 'driver': 'apcupsd',
                    'status': (kv.get('STATUS') or '')[:32],
                    'battery_pct': _num('BCHARGE'),
                    'load_pct': load,
                    'runtime_s': round(tl * 60, 1) if tl is not None else None,
                    'input_v': _num('LINEV'),
                    'power_w': round(nom * load / 100, 1) if (nom is not None and load is not None) else None,
                })
        except Exception:
            pass
    return out[:MAX_UPS]


def get_hardware_inventory():
    """v3.4.0: passive hardware inventory — DIMMs, system serial, temps,
    RAID arrays, disk models. Best-effort; each section omitted on failure.

    Returns:
        {system: {manufacturer, product, serial},
         memory: [{locator, size, type, speed, serial}],
         temps: [{label, current_c}],
         raid: [{name, level, state, devices}]}
    dmidecode requires root; when unavailable those sections are simply absent.
    """
    hw = {}

    # ── DMI: system identity + memory modules ────────────────────────
    dmidecode = _which('dmidecode')
    if dmidecode:
        try:
            r = subprocess.run([dmidecode, '-t', 'system'],
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                sysd = {}
                for key, field in (('Manufacturer', 'manufacturer'),
                                   ('Product Name', 'product'),
                                   ('Serial Number', 'serial')):
                    mm = re.search(rf'{key}:\s*(.+)', r.stdout)
                    if mm:
                        sysd[field] = mm.group(1).strip()
                if sysd:
                    hw['system'] = sysd
        except Exception:
            pass
        try:
            r = subprocess.run([dmidecode, '-t', 'memory'],
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                dimms = []
                # Split into "Memory Device" blocks.
                for block in re.split(r'\n(?=Memory Device|Handle )', r.stdout):
                    if 'Memory Device' not in block:
                        continue
                    size_m = re.search(r'\bSize:\s*(.+)', block)
                    if not size_m or 'No Module Installed' in size_m.group(1):
                        continue
                    dimm = {'size': size_m.group(1).strip()}
                    for key, field in (('Locator', 'locator'),
                                       ('Type', 'type'),
                                       ('Speed', 'speed'),
                                       ('Serial Number', 'serial'),
                                       ('Manufacturer', 'manufacturer')):
                        mm = re.search(rf'\n\s*{key}:\s*(.+)', block)
                        if mm:
                            val = mm.group(1).strip()
                            if val and val.lower() not in ('unknown', 'not specified'):
                                dimm[field] = val
                    dimms.append(dimm)
                if dimms:
                    hw['memory'] = dimms[:64]
        except Exception:
            pass

    # ── temperatures (lm-sensors) ────────────────────────────────────
    if _which('sensors'):
        try:
            r = subprocess.run(['sensors', '-A', '-j'],
                               capture_output=True, text=True, timeout=10)
            temps = []
            if r.returncode == 0 and r.stdout.strip():
                data = json.loads(r.stdout)
                for chip, feats in data.items():
                    if not isinstance(feats, dict):
                        continue
                    for label, vals in feats.items():
                        if not isinstance(vals, dict):
                            continue
                        for k, v in vals.items():
                            if k.endswith('_input') and 'temp' in k:
                                try:
                                    temps.append({'label': f'{chip}/{label}',
                                                  'current_c': round(float(v), 1)})
                                except (TypeError, ValueError):
                                    pass
            if temps:
                hw['temps'] = temps[:64]
        except Exception:
            pass

    # ── RAID arrays (mdadm software RAID; storcli hardware RAID) ──────
    raid = []
    try:
        mdstat = Path('/proc/mdstat')
        if mdstat.exists():
            txt = mdstat.read_text()
            for ln in txt.splitlines():
                m = re.match(r'(md\d+)\s*:\s*(\w+)\s+(\w+)\s+(.+)', ln)
                if m:
                    raid.append({'name': m.group(1), 'state': m.group(2),
                                 'level': m.group(3),
                                 'devices': m.group(4).strip()})
    except Exception:
        pass
    if raid:
        hw['raid'] = raid

    return hw


def get_helm_releases():
    """v3.4.0: list Helm releases via `helm list -A -o json`.

    Visibility only — we never deploy/upgrade/rollback (that's Helm's own
    CLI / CD pipeline). Returns [] when helm isn't installed or no kubeconfig
    is reachable; the agent already uses the same kubeconfig-discovery for
    Kubernetes pod listing. Best-effort, never raises.
    """
    helm = _which('helm')
    if not helm:
        return []
    try:
        r = subprocess.run([helm, 'list', '--all-namespaces', '-o', 'json'],
                           capture_output=True, text=True, timeout=30)
    except Exception:
        return []
    if r.returncode != 0 or not r.stdout.strip():
        return []
    try:
        data = json.loads(r.stdout)
    except Exception:
        return []
    out = []
    for rel in (data or [])[:500]:
        if not isinstance(rel, dict):
            continue
        out.append({
            'name':       str(rel.get('name', ''))[:128],
            'namespace':  str(rel.get('namespace', ''))[:128],
            'revision':   str(rel.get('revision', ''))[:16],
            'status':     str(rel.get('status', ''))[:32],
            'chart':      str(rel.get('chart', ''))[:128],
            'app_version': str(rel.get('app_version', ''))[:64],
            'updated':    str(rel.get('updated', ''))[:64],
        })
    return out


# ── v3.12.0: mount-point health ──────────────────────────────────────────────
_MOUNT_NET_FS = {'nfs', 'nfs4', 'cifs', 'smbfs', 'smb3', 'fuse.sshfs',
                 'glusterfs', 'ceph', 'fuse.glusterfs'}


def _mount_responsive(path, timeout=3):
    """True if `path` answers a statfs within `timeout`. False if it hangs
    (a dead NFS/SMB server) — the probe runs `stat -f` in a killable
    subprocess, so a hung mount can't block the heartbeat. None if we can't
    probe (no `stat` binary)."""
    try:
        r = subprocess.run(['stat', '-f', '--', path],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=timeout)
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except (FileNotFoundError, OSError):
        return None


def collect_mount_issues():
    """fstab vs live mounts. Returns a bounded list of issues:
       {'path', 'fstype', 'issue': 'missing'|'stalled', 'device'?}
       missing = an auto fstab entry that isn't mounted;
       stalled = a mounted network share that doesn't respond."""
    issues = []
    mounted = {}
    try:
        for line in _safe_read('/proc/mounts').splitlines():
            f = line.split()
            if len(f) >= 3:
                mounted[f[1]] = f[2]
    except Exception:
        return issues
    # fstab: auto entries that should be mounted but aren't.
    try:
        for line in _safe_read('/etc/fstab').splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            dev, mp, fstype, opts = parts[0], parts[1], parts[2], parts[3]
            if not mp.startswith('/') or fstype == 'swap' or mp == 'none':
                continue
            if 'noauto' in opts.split(','):
                continue
            if mp not in mounted:
                issues.append({'path': mp, 'fstype': fstype,
                               'issue': 'missing', 'device': dev[:120]})
    except Exception:
        pass
    # stalled: mounted network filesystems that don't respond.
    probed = 0
    for mp, fstype in list(mounted.items()):
        # Only probe genuine network filesystems. Generic fuse mounts
        # (fuse.portal, fuse.gvfsd, …) are local desktop plumbing — the network
        # fuse types (sshfs/glusterfs/ceph) are in the explicit set above.
        base = fstype.split('.')[0]
        if not (fstype in _MOUNT_NET_FS or base in ('nfs', 'cifs', 'smb')):
            continue
        probed += 1
        if probed > 20:
            break
        if _mount_responsive(mp) is False:
            issues.append({'path': mp, 'fstype': fstype, 'issue': 'stalled'})
    return issues[:50]


def get_metrics():
    """Collect CPU/RAM/disk/swap/loadavg metrics via psutil (optional).

    v1.11.10: extended to report per-mount disk usage, swap, and 1-minute
    load average / cpu count for metric alerting. Schema:

        {
          'cpu_percent':   <0..100>,        # current cpu utilisation
          'mem_percent':   <0..100>,        # virtual memory usage
          'disk_percent':  <0..100>,        # root mount usage (legacy)
          'swap_percent':  <0..100>,        # swap usage, 0 if no swap
          'loadavg_1m':    <float>,         # 1-minute load average
          'cpu_count':     <int>,           # logical CPU count
          'mounts': [                       # one entry per local mount
            {'path': '/', 'percent': 42.1, 'used_gb': 12.3, 'total_gb': 29.4},
            {'path': '/var', 'percent': 78.0, ...},
            ...
          ],
        }

    Backwards compatible: pre-v1.11.10 servers ignore the new fields.
    Pre-v1.11.10 agents on a v1.11.10+ server report only the legacy
    fields and the metric-alerting code falls back to those — root-mount
    disk alerting still works, per-mount alerting just doesn't fire for
    those agents until they self-update.
    """
    if not _PSUTIL:
        return {}
    try:
        cpu  = _psutil.cpu_percent(interval=0.5)
        mem  = _psutil.virtual_memory().percent
        # Root mount kept for backward compat; per-mount list is the new shape
        disk = _psutil.disk_usage('/').percent
    except Exception:
        return {}

    out = {'cpu_percent': cpu, 'mem_percent': mem, 'disk_percent': disk}

    try:
        swap = _psutil.swap_memory()
        out['swap_percent'] = swap.percent if swap.total > 0 else 0
    except Exception:
        out['swap_percent'] = 0

    try:
        loadavg = os.getloadavg()
        out['loadavg_1m'] = loadavg[0]
    except (AttributeError, OSError):
        # Windows or other systems without getloadavg
        out['loadavg_1m'] = 0.0

    try:
        out['cpu_count'] = _psutil.cpu_count(logical=True) or 1
    except Exception:
        out['cpu_count'] = 1

    # v3.13.0: total RAM (MB) for the CMDB Hardware panel.
    try:
        out['mem_total_mb'] = round(_psutil.virtual_memory().total / (1024 ** 2))
    except Exception:
        pass

    # Per-mount usage. Filter to "interesting" filesystems: skip
    # tmpfs, devtmpfs, squashfs (snap mounts), overlay (containers).
    # Include ext*, xfs, btrfs, zfs, AND network shares (NFS/SMB/CIFS) —
    # anything you'd actually want disk-fill / capacity monitoring for.
    #
    # v3.13.0: use disk_partitions(all=True). all=False omits EVERY network
    # filesystem (psutil only returns physical devices), which is why NFS/SMB
    # mounts never appeared. With all=True we get them too; the skip set still
    # drops the pseudo filesystems, and we dedupe by mountpoint (all=True can
    # list bind mounts twice). Network mounts get a `network: True` flag and
    # `server` (the export/share) so the UI can badge them, and their
    # statvfs is guarded by a killable responsiveness probe so a hung NFS/SMB
    # server can never block the heartbeat.
    skip_fstypes = {'tmpfs', 'devtmpfs', 'squashfs', 'overlay', 'overlayfs',
                    'fuse.gvfsd-fuse', 'autofs', 'proc', 'sysfs', 'cgroup',
                    'cgroup2', 'devpts', 'mqueue', 'debugfs', 'tracefs',
                    'pstore', 'bpf', 'configfs', 'fusectl', 'hugetlbfs',
                    'binfmt_misc', 'rpc_pipefs', 'ramfs', 'efivarfs',
                    'nsfs', 'tracefs', 'securityfs'}
    mounts = []
    seen_mp = set()
    seen_dev = set()        # for disk-total dedupe by block device
    local_total_gb = 0.0    # total LOCAL disk, counting each device once
    try:
        for part in _psutil.disk_partitions(all=True):
            fstype = part.fstype or ''
            base = fstype.split('.')[0]
            is_net = fstype in _MOUNT_NET_FS or base in ('nfs', 'cifs', 'smb')
            if not is_net and fstype in skip_fstypes:
                continue
            mp = part.mountpoint
            if mp in seen_mp:
                continue
            # Skip snap mounts even if fstype isn't squashfs (rare edge case).
            if mp.startswith('/snap/') or mp.startswith('/var/lib/snapd'):
                continue
            # Network mount: never call statvfs on a possibly-hung server
            # without a killable timeout probe first.
            if is_net and _mount_responsive(mp) is False:
                seen_mp.add(mp)
                mounts.append({'path': mp, 'fstype': fstype, 'network': True,
                               'server': (part.device or '')[:128], 'stalled': True})
                continue
            try:
                u = _psutil.disk_usage(mp)
            except (PermissionError, OSError):
                continue
            seen_mp.add(mp)
            entry = {
                'path':     mp,
                'percent':  round(u.percent, 1),
                'used_gb':  round(u.used / (1024**3), 2),
                'total_gb': round(u.total / (1024**3), 2),
                'fstype':   fstype,
            }
            if is_net:
                entry['network'] = True
                entry['server'] = (part.device or '')[:128]   # e.g. 1.2.3.4:/export
            else:
                # Count each local block device once toward the disk total —
                # btrfs subvolumes share one device (don't multi-count), while
                # separate LVM volumes are distinct devices (count each).
                dev = part.device or mp
                if dev not in seen_dev and u.total > 0:
                    seen_dev.add(dev)
                    local_total_gb += u.total / (1024 ** 3)
            mounts.append(entry)
    except Exception:
        pass
    # Sanity cap: if a host somehow has thousands of mounts (NFS automount
    # going wild), don't dump them all into every heartbeat. Sort so local
    # data filesystems and network shares come before transient bind mounts.
    mounts.sort(key=lambda m: (not m.get('network', False) and m['path'] != '/', m['path']))
    out['mounts'] = mounts[:60]
    # v3.13.0: total LOCAL disk (GB) for the CMDB Hardware panel — accumulated
    # above, deduped by block device (btrfs subvolumes collapse to one; LVM
    # volumes count individually; network shares excluded).
    if local_total_gb > 0:
        out['disk_total_gb'] = round(local_total_gb, 1)

    # v3.12.0: mount-point health — fstab entries that aren't mounted
    # ("missing"), and mounted network shares that don't respond ("stalled",
    # e.g. a hung NFS/SMB server). Best-effort + bounded; never blocks the
    # heartbeat (the stall probe runs stat in a killable subprocess).
    try:
        out['mount_issues'] = collect_mount_issues()
    except Exception:
        pass

    # Top processes by CPU and memory. cpu_percent() returns 0.0 on the
    # first call (needs two samples); values are meaningful from the second
    # heartbeat onward. Memory percent is always accurate.
    try:
        procs = []
        for p in _psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                info = p.info
                procs.append({
                    'pid':  info['pid'],
                    'name': (info['name'] or '')[:60],
                    'cpu':  round(info['cpu_percent'] or 0, 1),
                    'mem':  round(info['memory_percent'] or 0, 2),
                })
            except (_psutil.NoSuchProcess, _psutil.AccessDenied, _psutil.ZombieProcess):
                pass
        by_cpu = sorted(procs, key=lambda x: x['cpu'], reverse=True)[:10]
        by_mem = sorted(procs, key=lambda x: x['mem'], reverse=True)[:10]
        seen_pids = set()
        top = []
        for p in by_cpu + by_mem:
            if p['pid'] not in seen_pids:
                seen_pids.add(p['pid'])
                top.append(p)
        out['top_processes'] = top
    except Exception:
        pass

    return out

def get_agent_integrity(server_url):
    """Compare own SHA-256 against server's known-good hash. Returns (ok, detail)."""
    try:
        info = http_get(f"{server_url}/api/agent/version", timeout=10)
        expected = info.get('sha256')
        if not expected:
            return True, 'no server hash available'
        actual = hashlib.sha256(AGENT_BINARY.read_bytes()).hexdigest()
        if hmac_compare(actual.lower(), expected.lower()):
            return True, 'ok'
        return False, f'MISMATCH: local={actual[:12]}… server={expected[:12]}…'
    except Exception as e:
        return True, f'check skipped: {e}'

def hmac_compare(a, b):
    import hmac as _hmac
    return _hmac.compare_digest(a, b)

# ─── Self-update ───────────────────────────────────────────────────────────────
def check_for_update(server_url, force=False):
    """Poll server for a fresh agent build and upgrade if our local
    binary's sha256 differs from the server's canonical hash.

    v3.3.0: the trigger is now HASH-based instead of version-string-
    based. A re-build of the same version still has a different sha256
    and SHOULD update — which version-comparison silently skipped.
    Version is logged for human context but never used for the
    decision. The download path still verifies the downloaded bytes
    against the advertised sha256 before swapping the binary.

    force=True bypasses the sha-match early-return so an operator can
    push a re-download even when hashes match (useful when the local
    binary is suspected of tampering).
    """
    # Don't self-update while an OpenSCAP scan is running: applying an update
    # restarts the process, and the scan runs in a daemon thread that dies with
    # it — the scan never finishes or reports ("server requested scan, then
    # nothing"). Defer; the next poll retries the update once the scan is done.
    # This applies to force=True too: a forced re-deploy mid-scan kills the scan
    # exactly like a normal update would. The caller (heartbeat) re-tries a
    # deferred force upgrade locally so the one-shot server flag isn't lost.
    if _oscap_running.locked():
        log.info("Deferring agent self-update — an OpenSCAP scan is in progress")
        return False
    try:
        info = http_get(f"{server_url}/api/agent/version", timeout=10)
    except Exception as e:
        log.debug(f"Update check failed: {e}"); return False
    remote_sha256  = (info.get('sha256') or '').strip().lower()
    remote_version = info.get('version') or '?'
    if not remote_sha256:
        log.debug("server did not advertise an agent sha256 — skipping update")
        return False

    try:
        local_sha256 = hashlib.sha256(AGENT_BINARY.read_bytes()).hexdigest().lower()
    except Exception as e:
        log.warning(f"can't read own binary for hash check: {e}")
        local_sha256 = ''

    import hmac as _hmac
    matches = bool(local_sha256) and _hmac.compare_digest(local_sha256, remote_sha256)
    if matches and not force:
        return False

    if force:
        log.info(
            f"Force-upgrade: re-downloading agent (server v{remote_version}, "
            f"hash {remote_sha256[:12]}…, local hash {local_sha256[:12] or 'n/a'}…)"
        )
    else:
        log.info(
            f"Agent hash drift detected: local={local_sha256[:12] or 'n/a'}… "
            f"server={remote_sha256[:12]}… (v{VERSION} → v{remote_version}). "
            f"Downloading…"
        )

    try:
        data = http_get_binary(f"{server_url}/agent/remotepower-agent", timeout=30)
    except Exception as e:
        log.error(f"Download failed: {e}"); return False
    actual_sha = hashlib.sha256(data).hexdigest().lower()
    if not _hmac.compare_digest(actual_sha, remote_sha256):
        log.error(
            f"Downloaded binary sha256 mismatch — got {actual_sha[:12]}…, "
            f"expected {remote_sha256[:12]}…. Refusing to install."
        )
        return False

    # v3.4.2: cryptographic release-signature gate (opt-in, fail-closed). When a
    # release public key is pinned, the downloaded binary MUST carry a valid
    # detached signature from that key before we install it. No key pinned →
    # behaviour unchanged (sha256-only). With a key pinned, a missing or invalid
    # signature aborts the update.
    pubkey = _release_pubkey()
    if not pubkey and _require_signed_updates():
        log.error(
            "require-signed-updates is set but no release.pub is pinned — "
            "refusing to install an unsigned update.")
        _safe_state_write('update-rejected', 'signed updates required but no key pinned')
        return False
    if pubkey:
        try:
            sig = http_get_binary(f"{server_url}/api/agent/signature", timeout=15)
            import json as _json
            sig_text = _json.loads(sig.decode('utf-8')).get('signature', '')
        except Exception as e:
            log.error(f"Release signature required but unavailable ({e}). Refusing to install.")
            _safe_state_write('update-rejected', f'signature unavailable: {e}')
            return False
        ok, detail = _verify_detached_sig(data, sig_text, pubkey,
                                          (info.get('key_fingerprint') or ''))
        if not ok:
            log.error(f"Release signature verification FAILED ({detail}). Refusing to install.")
            _safe_state_write('update-rejected', f'signature invalid: {detail}')
            return False
        log.info("Release signature verified — installing.")
        _safe_state_unlink('update-rejected')

    try:
        fd, tmp_path = tempfile.mkstemp(dir=AGENT_BINARY.parent, prefix='.rp-update-')
        try: os.write(fd, data)
        finally: os.close(fd)
        os.chmod(tmp_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
        shutil.move(tmp_path, str(AGENT_BINARY))
        log.info(f"Agent updated to v{remote_version} ({remote_sha256[:12]}…). Restarting service…")
    except Exception as e:
        log.error(f"Failed to write update: {e}"); return False
    try: subprocess.Popen(['systemctl', 'restart', 'remotepower-agent'])
    except Exception as e: log.warning(f"systemctl restart failed: {e}")
    return True

# ─── Enrollment ────────────────────────────────────────────────────────────────
def enroll_with_token(server_url, token, device_name=None):
    """Non-interactive enrollment using a pre-shared one-time-use token.

    v1.11.10: companion to interactive PIN enrollment for use from
    Ansible / cloud-init / golden-image scripts. The token is created
    on the server side via POST /api/enrollment-tokens (admin-only,
    returns a 32+ char string), passed to this function, and consumed
    atomically — same token can't be used twice. Token may carry
    default group / tags that get applied at registration.

    Resolves the token from arguments in this order:

    1. The explicit ``token`` argument (used by the CLI).
    2. ``$REMOTEPOWER_ENROLL_TOKEN`` environment variable. Useful for
       systemd EnvironmentFile= or Ansible templated env vars.
    3. ``/etc/remotepower/enroll-token`` if it exists. The file should
       contain just the token (one line), and must be mode 600
       readable by root only — Ansible can drop it with the ``copy``
       module + ``mode: '0600'``.

    The 'token in CLI arg' path leaks into ``ps`` output for the
    duration of the enrollment call. Env var and file paths don't.
    Pick whichever fits your secret-distribution model.
    """
    # Resolution chain — args → env → file
    if not token:
        token = os.environ.get('REMOTEPOWER_ENROLL_TOKEN', '').strip()
    if not token:
        token_file = Path('/etc/remotepower/enroll-token')
        if token_file.exists():
            try:
                token = token_file.read_text().strip()
            except Exception as e:
                print(f"✗ Couldn't read {token_file}: {e}")
                sys.exit(1)
    if not token:
        print("✗ No enrollment token. Pass --token, set $REMOTEPOWER_ENROLL_TOKEN,")
        print("  or write the token to /etc/remotepower/enroll-token (mode 600).")
        sys.exit(1)

    if not server_url.startswith('https://'):
        print("⚠  Only HTTPS is supported. Prepending https://")
        server_url = 'https://' + _strip_url_scheme(server_url)

    if not device_name:
        device_name = socket.gethostname()

    # Existing creds → re-enroll path. Same logic as interactive.
    payload = {
        'enrollment_token': token,
        'hostname':         socket.gethostname(),
        'name':             device_name,
        'os':               get_os_info(),
        'ip':               get_local_ip(),
        'mac':              get_mac(),
        'version':          VERSION,
    }
    creds = load_credentials()
    if creds and creds.get('device_id') and creds.get('token'):
        payload['device_id'] = creds['device_id']
        payload['token']     = creds['token']
        print(f"Re-enrolling existing device ({creds['device_id']})")
    else:
        print(f"Enrolling {device_name} → {server_url}")

    try:
        resp = http_post(f"{server_url}/api/enroll/register", payload)
    except Exception as e:
        print(f"✗ Server contact failed: {e}")
        sys.exit(1)

    if not resp.get('ok'):
        print(f"✗ Enrollment rejected: {resp.get('error', 'Unknown error')}")
        sys.exit(1)

    new_creds = {
        'server_url': server_url,
        'device_id':  resp['device_id'],
        'token':      resp['token'],
        'name':       device_name,
    }
    save_credentials(new_creds)
    print(f"✓ Enrolled. Device ID: {resp['device_id']}")
    print(f"  Credentials saved to {CREDS_FILE}")
    # Best-effort: clear the on-disk token file so it can't be re-used
    # accidentally (the server already invalidated it on the wire, but
    # leaving it on disk is a footgun if a second copy of the agent
    # tried to enroll).
    try:
        token_file = Path('/etc/remotepower/enroll-token')
        if token_file.exists():
            token_file.unlink()
            print("  Cleared /etc/remotepower/enroll-token (one-time use)")
    except Exception:
        pass
    return new_creds


def enroll_interactive(re_enroll=False):
    print()
    print("╔══════════════════════════════════════════╗")
    print("║     RemotePower Client Setup             ║")
    print("╚══════════════════════════════════════════╝")
    print()
    server_url = input("RemotePower server URL (e.g. https://remote.example.com): ").strip().rstrip('/')
    if not server_url.startswith('https://'):
        print("⚠  Only HTTPS is supported. Prepending https://")
        server_url = 'https://' + _strip_url_scheme(server_url)
    pin = input("Enrollment PIN (shown in web dashboard): ").strip()
    device_name = input(f"Device display name [{socket.gethostname()}]: ").strip()
    if not device_name: device_name = socket.gethostname()
    print(); print("Enrolling device...")
    payload = {
        'pin': pin, 'hostname': socket.gethostname(), 'name': device_name,
        'os': get_os_info(), 'ip': get_local_ip(), 'mac': get_mac(), 'version': VERSION,
    }
    # Pass existing device_id AND token for seamless re-enrollment (server verifies token)
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
                print(f"✓ Re-enrolled! Device ID unchanged: {resp['device_id']}")
            else:
                print(f"✓ Enrolled! Device ID: {resp['device_id']}")
            print(f"  Credentials saved to {CREDS_FILE}")
            return creds
        else:
            print(f"✗ Enrollment failed: {resp.get('error', 'Unknown error')}"); sys.exit(1)
    except Exception as e:
        print(f"✗ Error contacting server: {e}"); sys.exit(1)

def _execute_uninstall():
    """v3.3.0: tear down this agent in place.

    Order matters: we want the OS-level cleanup (stop unit, remove
    files) to happen before the binary deletion, and we want the
    binary to outlive this Python process long enough to be unlinked
    by a detached shell. The shell trampoline writes itself to a
    tempfile, exec's, and then deletes the binary + sleeps + kills
    its parent so the running agent exits cleanly.
    """
    import tempfile as _tf
    # 1. Disable the systemd unit (so it doesn't auto-start at boot
    #    and so a future reinstall starts from a clean slate). Done
    #    here, in-process, so the disable runs as root.
    for action in ('stop', 'disable'):
        try:
            subprocess.run(['systemctl', action, 'remotepower-agent'],
                           timeout=15, check=False)
        except Exception as e:
            log.warning(f"systemctl {action} failed: {e}")
    # 2. Remove credentials + state + the systemd unit file.
    targets = [
        CREDS_FILE,
        PKG_HASH_FILE,
        STATE_DIR / 'last-cmd',
        STATE_DIR / 'poll-interval',
        STATE_DIR / 'boot-reason',
        Path('/etc/systemd/system/remotepower-agent.service'),
        Path('/var/log/remotepower-agent.log'),
    ]
    for p in targets:
        try:
            if p.exists() or p.is_symlink():
                p.unlink()
        except Exception as e:
            log.warning(f"failed to remove {p}: {e}")
    # 3. Try to remove the config dir if it's empty.
    try:
        if CONF_DIR.exists():
            for child in CONF_DIR.iterdir():
                # Other files in /etc/remotepower may belong to operator
                # — leave them. We only clear files we put there.
                break
            else:
                CONF_DIR.rmdir()
    except Exception:
        pass
    # 4. Detach a cleanup trampoline: remove the binary + run
    #    daemon-reload + kill this PID. Spawned with start_new_session
    #    so it survives our exit.
    try:
        script = f"""#!/bin/sh
sleep 2
rm -f {AGENT_BINARY!s}
systemctl daemon-reload 2>/dev/null || true
kill {os.getpid()} 2>/dev/null || true
"""
        fd, path = _tf.mkstemp(prefix='rp-uninstall-', suffix='.sh')
        try:
            os.write(fd, script.encode())
        finally:
            os.close(fd)
        os.chmod(path, 0o700)
        subprocess.Popen(['/bin/sh', path],
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL,
                         start_new_session=True)
        log.info("Uninstall trampoline spawned — agent will exit shortly.")
    except Exception as e:
        log.error(f"failed to spawn uninstall trampoline: {e}")
    # 5. Stop the main loop (clean exit so the user sees a final log
    #    line). The trampoline will SIGTERM us in 2s if we don't exit.
    sys.exit(0)


# ─── v3.4.0: on-demand actions (speedtest, network discovery) ────────────────
def run_speedtest():
    """v3.4.0: one-shot internet speed test via librespeed-cli.

    librespeed-cli is FOSS and emits JSON, so no EULA prompt and no parsing
    of human-readable output. If it isn't installed we return an explicit
    'unavailable' marker so the UI can tell "not installed" apart from "ran
    but failed". Returns a dict:
        {ok, download_mbps, upload_mbps, ping_ms, jitter_ms, server, ts}
      or {ok: False, error: ...}
    """
    cli = _which('librespeed-cli')
    if not cli:
        return {'ok': False, 'error': 'librespeed-cli not installed'}
    try:
        r = subprocess.run([cli, '--json'], capture_output=True, text=True,
                           timeout=120)
    except subprocess.TimeoutExpired:
        return {'ok': False, 'error': 'speedtest timed out'}
    except Exception as e:
        return {'ok': False, 'error': str(e)}
    if r.returncode != 0 or not r.stdout.strip():
        return {'ok': False, 'error': (r.stderr or 'speedtest failed').strip()[:200]}
    try:
        data = json.loads(r.stdout)
        # librespeed-cli reports a single object or a one-element array.
        if isinstance(data, list):
            data = data[0] if data else {}
    except Exception as e:
        return {'ok': False, 'error': f'could not parse output: {e}'}
    return {
        'ok':            True,
        'download_mbps': round(float(data.get('download', 0)), 2),
        'upload_mbps':   round(float(data.get('upload', 0)), 2),
        'ping_ms':       round(float(data.get('ping', 0)), 1),
        'jitter_ms':     round(float(data.get('jitter', 0)), 1),
        'server':        (data.get('server') or {}).get('name', ''),
        'ts':            int(time.time()),
    }


def run_netscan(subnet=None):
    """v3.4.0: discover other hosts on the agent's LAN (opt-in per device).

    Strategy, in order of preference:
      1. Read the kernel ARP/neighbour table (`ip neigh` then /proc/net/arp)
         — zero network noise, just what the host already knows about.
      2. If a subnet is given and `nmap` is present, a light `-sn` ping sweep
         to actively find quiet hosts.
    Returns {ok, hosts: [{ip, mac, hostname}], method, ts}. The agent never
    enrolls anything — it just reports candidates for the operator to import.
    """
    hosts = {}
    method = []

    # 1. Passive: neighbour / ARP table.
    try:
        if _which('ip'):
            r = subprocess.run(['ip', 'neigh'], capture_output=True,
                               text=True, timeout=10)
            if r.returncode == 0:
                method.append('neigh')
                for ln in r.stdout.splitlines():
                    parts = ln.split()
                    if len(parts) >= 5 and parts[0].count('.') == 3:
                        ip = parts[0]
                        mac = ''
                        if 'lladdr' in parts:
                            mac = parts[parts.index('lladdr') + 1]
                        if parts[-1] in ('FAILED', 'INCOMPLETE'):
                            continue
                        hosts.setdefault(ip, {'ip': ip, 'mac': mac, 'hostname': ''})
                        if mac:
                            hosts[ip]['mac'] = mac
    except Exception:
        pass
    if not hosts:
        try:
            arp = Path('/proc/net/arp')
            if arp.exists():
                method.append('arp')
                for ln in arp.read_text().splitlines()[1:]:
                    parts = ln.split()
                    if len(parts) >= 4 and parts[0].count('.') == 3:
                        ip, mac = parts[0], parts[3]
                        if mac != '00:00:00:00:00:00':
                            hosts.setdefault(ip, {'ip': ip, 'mac': mac, 'hostname': ''})
        except Exception:
            pass

    # 2. Active ping sweep (only if explicitly asked + nmap present).
    if subnet and _which('nmap') and re.match(r'^[0-9./]+$', subnet):
        try:
            r = subprocess.run(['nmap', '-sn', '-n', '--max-retries', '1', subnet],
                               capture_output=True, text=True, timeout=120)
            if r.returncode == 0:
                method.append('nmap')
                cur = None
                for ln in r.stdout.splitlines():
                    m = re.search(r'Nmap scan report for ([0-9.]+)', ln)
                    if m:
                        cur = m.group(1)
                        hosts.setdefault(cur, {'ip': cur, 'mac': '', 'hostname': ''})
                    elif cur and 'MAC Address:' in ln:
                        mm = re.search(r'MAC Address:\s*(\S+)', ln)
                        if mm:
                            hosts[cur]['mac'] = mm.group(1)
        except Exception:
            pass

    out = sorted(hosts.values(), key=lambda h: tuple(int(x) for x in h['ip'].split('.')))
    return {'ok': True, 'hosts': out[:512], 'method': '+'.join(method) or 'none',
            'ts': int(time.time())}


# ─── Command execution ──────────────────────────────────────────────────────────
def execute_command(cmd):
    if cmd == 'shutdown':
        log.info("Executing: shutdown")
        try: subprocess.run(['systemctl', 'poweroff'], check=True)
        except Exception as e: log.error(f"Shutdown failed: {e}")
    elif cmd == 'reboot':
        log.info("Executing: reboot")
        try:
            _safe_state_write('last-cmd', 'reboot')
            subprocess.run(['systemctl', 'reboot'], check=True)
        except Exception as e: log.error(f"Reboot failed: {e}")
    elif cmd == 'suspend':
        # v3.14.0: power scheduling — suspend to RAM (Wake-on-LAN can resume it).
        log.info("Executing: suspend")
        try: subprocess.run(['systemctl', 'suspend'], check=True)
        except Exception as e: log.error(f"Suspend failed: {e}")
    elif cmd == 'update':
        log.info("Executing: self-update (server-initiated)")
        creds = load_credentials()
        if creds: check_for_update(creds['server_url'])
    elif cmd == 'uninstall':
        # v3.3.0: operator-triggered agent removal. Stops the systemd
        # unit, deletes credentials + state, removes the binary, then
        # spawns a detached cleanup so this process can exit cleanly.
        # The device record on the server STAYS — operator can later
        # re-install + re-enroll (with the existing device_id+token if
        # any backup exists, otherwise as a new device via PIN).
        log.info("Executing: uninstall (server-initiated)")
        _execute_uninstall()
    elif cmd.startswith('poll_interval:'):
        # Server is requesting a poll interval change
        try:
            new_interval = int(cmd.split(':', 1)[1])
            new_interval = max(10, min(3600, new_interval))
            log.info(f"Poll interval changed to {new_interval}s")
            # Signal main loop by writing to a temp file
            _safe_state_write('poll-interval', str(new_interval))
        except Exception as e:
            log.warning(f"Failed to set poll interval: {e}")
    elif cmd.startswith('exec:'):
        shell_cmd = cmd[5:]
        # v3.0.1: Tag-routed commands. The server prefixes certain commands
        # with "#<scope>:<action_id>#" so the cmd_output ingestion can route
        # the full stdout to a per-scope log dir (ACME, mitigate). Strip the
        # tag before passing to the shell; keep it in the returned `cmd`
        # field so the server can still recognise it.
        import re as _tag_re
        acme_tag_m     = _tag_re.match(r'^#acme:[a-zA-Z0-9_-]+#(.*)$',     shell_cmd, _tag_re.DOTALL)
        mitigate_tag_m = _tag_re.match(r'^#mitigate:[a-zA-Z0-9_-]+#(.*)$', shell_cmd, _tag_re.DOTALL) if not acme_tag_m else None
        if acme_tag_m:
            actual_shell = acme_tag_m.group(1)
        elif mitigate_tag_m:
            actual_shell = mitigate_tag_m.group(1)
        else:
            actual_shell = shell_cmd
        log.info(f"Executing custom command: {actual_shell!r}")
        try:
            # v3.13.0: package upgrades can take far longer than 5 min on a host
            # with many pending updates. The old fixed 300s timeout killed the
            # command mid-upgrade — and for `upgrade_and_reboot` that meant the
            # trailing `systemctl reboot` never ran, so the host upgraded but
            # never rebooted. Give upgrade/reboot commands 30 min.
            _is_upgrade = any(n in actual_shell for n in (
                'apt-get -y upgrade', 'dnf -y upgrade', 'yum -y upgrade',
                'pacman -Syu', 'zypper', 'apk upgrade', 'remotepower_update.log'))
            exec_timeout = 1800 if _is_upgrade else 300
            result = subprocess.run(actual_shell, shell=True, capture_output=True, text=True, timeout=exec_timeout)
            output = (result.stdout + result.stderr).strip()
            log.info(f"Command output (rc={result.returncode}): {output[:200]}")
            # v1.10.0: bump output cap to 256 KB for package-upgrade runs.
            # v3.0.1: also bump for acme.sh runs and mitigation diagnostics
            # — their output is verbose (cert chains, journalctl dumps, du
            # output).
            is_pkg_upgrade = any(needle in actual_shell for needle in
                                 ('apt-get -y upgrade', 'dnf -y upgrade', 'pacman -Syu'))
            is_tagged      = bool(acme_tag_m or mitigate_tag_m)
            cap = 256 * 1024 if (is_pkg_upgrade or is_tagged) else 4096
            return {'cmd': cmd, 'output': output[:cap], 'rc': result.returncode}
        except subprocess.TimeoutExpired:
            log.warning(f"Command timed out: {actual_shell!r}")
            return {'cmd': cmd, 'output': 'TIMEOUT', 'rc': -1}
        except Exception as e:
            log.error(f"Command failed: {e}")
            return {'cmd': cmd, 'output': str(e), 'rc': -1}
    elif cmd.startswith('compose:'):
        # v2.1.0: compose:<action>:<dir> — server-side picks `dir` from the
        # list of projects we reported in the heartbeat. We re-validate
        # locally anyway: only directories containing a recognised compose
        # file can be acted on, and the action is one of a fixed set. No
        # shell interpolation of `dir` — it goes in argv directly to docker
        # compose, so a malicious or stale path can't inject command flags.
        return _run_compose(cmd)
    elif cmd.startswith('compose_deploy:'):
        # v3.3.4: compose_deploy:<action>:<stack_id> — deploy an
        # operator-uploaded stack. The agent fetches the YAML from the
        # server with its device token (so it never rides the command
        # queue), writes it under a managed dir, and runs docker compose
        # via argv. Gated server-side by the device's compose_enabled flag.
        return _run_compose_deploy(cmd)
    elif cmd.startswith('container:'):
        # v2.1.1: per-container start/stop/restart from the Containers
        # page. Same shape as compose: action verb + identifier, action
        # is allowlisted, identifier goes into argv (never shell). The
        # server only ever sends container IDs the agent itself
        # reported in its last heartbeat — but defence-in-depth: the
        # agent re-validates that the ID looks like a docker/podman ID
        # (alphanumeric, no slashes / dots / spaces) before invoking
        # anything. A crafted command can't reach `docker rm -f -v $(…)`
        # because we never let the shell see the string.
        return _run_container_action(cmd)
    elif cmd == 'speedtest':
        # v3.4.0: on-demand internet speed test. Result rides the same
        # command-result channel as exec; the server recognises it by the
        # 'speedtest' key rather than 'output'.
        log.info("Executing: speedtest")
        return {'cmd': cmd, 'speedtest': run_speedtest()}
    elif cmd == 'netscan' or cmd.startswith('netscan:'):
        # v3.4.0: discover unmanaged hosts on the agent's LAN. Optional
        # subnet after the colon enables an active nmap ping sweep; bare
        # `netscan` is passive (ARP/neighbour table only).
        subnet = cmd.split(':', 1)[1].strip() if ':' in cmd else None
        log.info(f"Executing: netscan (subnet={subnet or 'passive'})")
        return {'cmd': cmd, 'netscan': run_netscan(subnet)}
    else:
        log.warning(f"Unknown command: {cmd!r}")
    return None


# v2.1.0: docker-compose dispatcher. Called from execute_command on
# `compose:<action>:<dir>`. Actions are constrained to a known set; the
# directory is verified to exist and contain a compose file before any
# docker invocation. Output (capped) is returned via the existing exec
# channel so the dashboard sees results the same way it does for `exec:`.
COMPOSE_ALLOWED_ACTIONS = {'up', 'down', 'restart', 'pull', 'logs', 'update'}
COMPOSE_ACTION_TIMEOUT_S = 180  # pull + up can be slow on cold caches
COMPOSE_OUT_CAP          = 64 * 1024


def _run_compose(cmd):
    """Parse a compose:<action>:<dir> command and run docker compose against it.

    Returns the exec-channel result dict (or None on a malformed cmd).
    """
    # Strict split: exactly two ':' separators, action first then path.
    # We use rsplit so a path with ':' in it (unusual but legal on Linux)
    # doesn't truncate at the first colon.
    try:
        _, action, project_dir = cmd.split(':', 2)
    except ValueError:
        log.warning(f"Malformed compose command: {cmd!r}")
        return {'cmd': cmd, 'output': 'malformed compose command', 'rc': -1}

    action = action.strip().lower()
    if action not in COMPOSE_ALLOWED_ACTIONS:
        log.warning(f"Compose action not allowed: {action!r}")
        return {'cmd': cmd, 'output': f'action {action!r} not allowed', 'rc': -1}

    # Resolve the path and confirm it's real + contains a compose file.
    # No shell, no glob, no command substitution. Argv is the only path
    # that ever touches the docker binary.
    try:
        p = Path(project_dir).resolve(strict=False)
    except OSError:
        return {'cmd': cmd, 'output': f'cannot resolve {project_dir!r}', 'rc': -1}
    if not p.is_dir():
        return {'cmd': cmd, 'output': f'directory not found: {p}', 'rc': -1}
    compose_files = ('docker-compose.yml', 'docker-compose.yaml',
                     'compose.yml', 'compose.yaml')
    if not any((p / f).is_file() for f in compose_files):
        return {'cmd': cmd, 'output': f'no compose file under {p}', 'rc': -1}
    if not _which('docker'):
        return {'cmd': cmd, 'output': 'docker not installed on this host', 'rc': -1}

    # 'update' = pull the newest images then recreate (up -d) so the running
    # containers actually move onto them — the canonical "update my stack"
    # flow. It's a two-step sequence; the rest are single argv runs.
    if action == 'update':
        step_argvs = [['docker', 'compose', 'pull'],
                      ['docker', 'compose', 'up', '-d']]
    elif action == 'up':
        step_argvs = [['docker', 'compose', 'up', '-d']]
    elif action == 'down':
        step_argvs = [['docker', 'compose', 'down']]
    elif action == 'restart':
        step_argvs = [['docker', 'compose', 'restart']]
    elif action == 'pull':
        step_argvs = [['docker', 'compose', 'pull']]
    elif action == 'logs':
        step_argvs = [['docker', 'compose', 'logs', '--no-color', '--tail=50']]
    else:
        # Defensive — COMPOSE_ALLOWED_ACTIONS check above should make this
        # unreachable, but keep the branch so a future contributor adding
        # an entry to the set but forgetting the argv mapping gets a
        # sensible error.
        return {'cmd': cmd, 'output': f'no argv mapping for {action!r}', 'rc': -1}

    log.info(f"compose {action} in {p}")
    chunks = []
    rc = 0
    try:
        for argv in step_argvs:
            result = subprocess.run(argv, cwd=str(p), capture_output=True,
                                    text=True, timeout=COMPOSE_ACTION_TIMEOUT_S)
            label = ' '.join(argv[1:])  # e.g. "compose pull"
            chunks.append(f'$ docker {label}\n' + (result.stdout + result.stderr).strip())
            rc = result.returncode
            # Stop the sequence if a step fails (don't `up` onto a half-pull).
            if rc != 0:
                break
        output = '\n\n'.join(chunks).strip()[:COMPOSE_OUT_CAP]
        log.info(f"compose {action} rc={rc} output_len={len(output)}")
        return {'cmd': cmd, 'output': output, 'rc': rc}
    except subprocess.TimeoutExpired:
        return {'cmd': cmd, 'output': 'TIMEOUT', 'rc': -1}
    except Exception as e:
        return {'cmd': cmd, 'output': f'compose {action} failed: {e}', 'rc': -1}


# v3.3.4: operator-uploaded compose stacks. Written under a managed dir,
# one subdir per stack name; the project name is pinned with `-p` so up/down
# target the same stack regardless of the working directory.
COMPOSE_STACKS_DIR = STATE_DIR / 'stacks'
COMPOSE_DEPLOY_ACTIONS = {'up', 'down', 'redeploy'}
_STACK_NAME_RE = re.compile(r'^[a-z0-9][a-z0-9_-]{0,63}$')


def _run_compose_deploy(cmd):
    """Deploy an uploaded stack: compose_deploy:<action>:<stack_id>.

    Fetches {name, yaml} from the server with the device token, writes the
    compose file under COMPOSE_STACKS_DIR/<name>/, then runs docker compose
    via argv (no shell). Returns the exec-channel result dict so the server
    captures output + return code (and updates the stack status).
    """
    try:
        _, action, stack_id = cmd.split(':', 2)
    except ValueError:
        return {'cmd': cmd, 'output': 'malformed compose_deploy command', 'rc': -1}
    action = action.strip().lower()
    if action not in COMPOSE_DEPLOY_ACTIONS:
        return {'cmd': cmd, 'output': f'action {action!r} not allowed', 'rc': -1}
    if not _which('docker'):
        return {'cmd': cmd, 'output': 'docker not installed on this host', 'rc': -1}

    creds = load_credentials()
    if not creds:
        return {'cmd': cmd, 'output': 'agent not enrolled', 'rc': -1}
    try:
        resp = http_post(creds['server_url'].rstrip('/') + '/api/compose/fetch',
                         {'device_id': creds['device_id'], 'token': creds['token'],
                          'stack_id': stack_id})
    except Exception as e:
        return {'cmd': cmd, 'output': f'failed to fetch stack: {e}', 'rc': -1}
    if not resp or not resp.get('ok'):
        return {'cmd': cmd, 'output': f'stack fetch rejected: {(resp or {}).get("error", "?")}', 'rc': -1}
    name = str(resp.get('name', ''))
    yaml_text = resp.get('yaml', '')
    if not _STACK_NAME_RE.match(name):
        return {'cmd': cmd, 'output': f'invalid stack name {name!r}', 'rc': -1}
    if not isinstance(yaml_text, str) or not yaml_text.strip():
        return {'cmd': cmd, 'output': 'empty compose file', 'rc': -1}

    stack_dir = COMPOSE_STACKS_DIR / name
    try:
        stack_dir.mkdir(parents=True, exist_ok=True)
        (stack_dir / 'docker-compose.yml').write_text(yaml_text)
    except Exception as e:
        return {'cmd': cmd, 'output': f'failed to write compose file: {e}', 'rc': -1}

    base = ['docker', 'compose', '-p', name]
    steps = []
    if action == 'up':
        steps = [base + ['up', '-d']]
    elif action == 'down':
        steps = [base + ['down']]
    elif action == 'redeploy':
        steps = [base + ['pull'], base + ['up', '-d']]

    out_parts, rc = [], 0
    for argv in steps:
        log.info(f"compose_deploy {' '.join(argv[3:])} in {stack_dir}")
        try:
            r = subprocess.run(argv, cwd=str(stack_dir), capture_output=True,
                               text=True, timeout=COMPOSE_ACTION_TIMEOUT_S)
            out_parts.append((r.stdout + r.stderr).strip())
            rc = r.returncode
            if rc != 0:
                break          # don't run `up` if `pull` failed
        except subprocess.TimeoutExpired:
            return {'cmd': cmd, 'output': '\n'.join(out_parts + ['TIMEOUT']), 'rc': -1}
        except Exception as e:
            return {'cmd': cmd, 'output': '\n'.join(out_parts + [str(e)]), 'rc': -1}
    return {'cmd': cmd, 'output': '\n'.join(out_parts)[:COMPOSE_OUT_CAP], 'rc': rc}


# v2.1.1: per-container actions from the Containers page. Same allowlist
# pattern as compose — verb table, argv-only invocation, no shell.
CONTAINER_ALLOWED_ACTIONS = {'start', 'stop', 'restart', 'pause', 'unpause', 'logs'}
CONTAINER_ACTION_TIMEOUT_S = 60
CONTAINER_OUT_CAP          = 32 * 1024
# Docker / podman IDs are alphanumeric (lowercase hex usually); container
# names allow [a-zA-Z0-9_.-]. Reject anything else to keep argv safe.
_CONTAINER_ID_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$')


def _run_container_action(cmd):
    """Parse and execute container:<runtime>:<action>:<id> on this host.

    Runtime is docker | podman (we report both in the heartbeat). Action is
    one of CONTAINER_ALLOWED_ACTIONS. ID is validated against a tight
    regex so it can safely be passed to argv.
    """
    parts = cmd.split(':', 3)
    if len(parts) != 4:
        return {'cmd': cmd, 'output': 'malformed container command', 'rc': -1}
    _, runtime, action, container_id = parts
    runtime = runtime.strip().lower()
    action = action.strip().lower()
    container_id = container_id.strip()

    if runtime not in ('docker', 'podman'):
        return {'cmd': cmd, 'output': f'unsupported runtime {runtime!r}', 'rc': -1}
    if action not in CONTAINER_ALLOWED_ACTIONS:
        return {'cmd': cmd, 'output': f'action {action!r} not allowed', 'rc': -1}
    if not _CONTAINER_ID_RE.match(container_id):
        return {'cmd': cmd, 'output': 'invalid container id', 'rc': -1}
    if not _which(runtime):
        return {'cmd': cmd, 'output': f'{runtime} not installed', 'rc': -1}

    if action == 'logs':
        argv = [runtime, 'logs', '--tail=50', container_id]
    else:
        argv = [runtime, action, container_id]

    log.info(f"container {action} {runtime} {container_id}")
    try:
        result = subprocess.run(argv, capture_output=True, text=True,
                                timeout=CONTAINER_ACTION_TIMEOUT_S)
        output = (result.stdout + result.stderr).strip()[:CONTAINER_OUT_CAP]
        log.info(f"container {action} rc={result.returncode} output_len={len(output)}")
        return {'cmd': cmd, 'output': output, 'rc': result.returncode}
    except subprocess.TimeoutExpired:
        return {'cmd': cmd, 'output': 'TIMEOUT', 'rc': -1}
    except Exception as e:
        return {'cmd': cmd, 'output': f'{runtime} {action} failed: {e}', 'rc': -1}



def run_custom_scripts(scripts):
    """v2.5.0: run assigned custom monitoring scripts and return results.

    Each script is written to a private temp file (mode 0700), executed
    with a timeout, stdout+stderr merged and capped at 4 KB.
    Exit 0 -> ok=True; anything else (including timeout/exec error) -> ok=False.
    Results are keyed by script ID.

    Security: scripts come from the RemotePower server, which the agent
    already trusts via the device token on every heartbeat — same boundary
    as the existing exec: command channel.
    """
    import tempfile
    import stat as _stat
    results = {}
    now = int(time.time())

    for s in scripts:
        sid     = str(s.get('id', ''))
        name    = str(s.get('name', sid))
        body    = str(s.get('body', ''))
        timeout = int(s.get('timeout', 30))
        if not sid or not body:
            continue

        t_start = time.monotonic()
        ok = False; output = ''; rc = 1
        tmp_path = None
        try:
            fd, tmp_path = tempfile.mkstemp(prefix='rp_cs_', suffix='.sh')
            try:
                os.write(fd, body.encode('utf-8', errors='replace'))
            finally:
                os.close(fd)
            os.chmod(tmp_path, _stat.S_IRWXU)   # 0700 — owner only

            proc = subprocess.run(
                ['/bin/bash', tmp_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout,
            )
            rc     = proc.returncode
            ok     = (rc == 0)
            output = proc.stdout.decode('utf-8', errors='replace')[:4096]
        except subprocess.TimeoutExpired:
            rc = -1; ok = False; output = f'TIMEOUT after {timeout}s'
        except Exception as e:
            rc = -1; ok = False; output = f'EXEC ERROR: {e}'
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

        duration_ms = int((time.monotonic() - t_start) * 1000)
        results[sid] = {
            'ok':          ok,
            'output':      output.strip(),
            'rc':          rc,
            'ran_at':      now,
            'duration_ms': duration_ms,
        }
        log.debug(f'Custom script "{name}" ({sid}): rc={rc} ok={ok} dur={duration_ms}ms')

    return results


def collect_host_config():
    """v2.6.0: Collect current host configuration state for all managed sections.

    Returns a dict with the current live state of each section.
    Errors in individual sections are caught and reported as empty strings
    so one broken section never prevents the others from being reported.
    """
    import grp as _grp
    import pwd as _pwd

    def _read(path):
        try:
            return Path(path).read_text(errors='replace')
        except OSError:
            return ''

    def _run(cmd, **kw):
        try:
            r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               timeout=10, **kw)
            return r.stdout.decode('utf-8', errors='replace')
        except Exception:
            return ''

    current = {}

    # ── repos ────────────────────────────────────────────────────────────────
    if Path('/etc/apt/sources.list').exists():
        current['repos'] = _read('/etc/apt/sources.list')
    elif Path('/etc/yum.repos.d').is_dir():
        # Concatenate all .repo files
        parts = []
        for f in sorted(Path('/etc/yum.repos.d').glob('*.repo')):
            parts.append(f'# {f.name}\n' + _read(str(f)))
        current['repos'] = '\n'.join(parts)

    # ── netplan ──────────────────────────────────────────────────────────────
    netplan_dir = Path('/etc/netplan')
    if netplan_dir.is_dir():
        for f in sorted(netplan_dir.glob('*.yaml')):
            current['netplan'] = _read(str(f))
            break  # first file only; apply writes 01-remotepower.yaml

    # ── nmcli ────────────────────────────────────────────────────────────────
    nm_conn = Path('/etc/NetworkManager/system-connections/remotepower-managed.nmconnection')
    if nm_conn.exists():
        current['nmcli'] = _read(str(nm_conn))

    # ── resolv.conf ──────────────────────────────────────────────────────────
    current['resolv_conf'] = _read('/etc/resolv.conf')

    # ── /etc/hosts ───────────────────────────────────────────────────────────
    current['hosts'] = _read('/etc/hosts')

    # ── enabled services ─────────────────────────────────────────────────────
    svc_out = _run(['systemctl', 'list-unit-files', '--state=enabled',
                    '--no-legend', '--no-pager', '--type=service'])
    current['services'] = [
        line.split()[0] for line in svc_out.splitlines() if line.strip()
    ]

    # ── users (UID >= 1000, not nobody) ──────────────────────────────────────
    users = []
    try:
        for pw in _pwd.getpwall():
            if pw.pw_uid < 1000 or pw.pw_name == 'nobody':
                continue
            groups = [g.gr_name for g in _grp.getgrall() if pw.pw_name in g.gr_mem]
            ak_path = Path(pw.pw_dir) / '.ssh' / 'authorized_keys'
            ak = ''
            try:
                ak = ak_path.read_text(errors='replace') if ak_path.exists() else ''
            except OSError:
                pass
            users.append({
                'name':            pw.pw_name,
                'shell':           pw.pw_shell,
                'groups':          groups,
                'authorized_keys': ak,
            })
    except Exception as e:
        log.debug(f'collect_host_config users error: {e}')
    current['users'] = users

    # ── groups ───────────────────────────────────────────────────────────────
    try:
        current['groups'] = [
            {'name': g.gr_name, 'gid': g.gr_gid}
            for g in _grp.getgrall()
            if g.gr_gid >= 1000
        ]
    except Exception:
        current['groups'] = []

    # ── sudoers ──────────────────────────────────────────────────────────────
    sudoers_f = Path('/etc/sudoers.d/remotepower')
    current['sudoers'] = _read(str(sudoers_f)) if sudoers_f.exists() else ''

    # ── motd ─────────────────────────────────────────────────────────────────
    current['motd'] = _read('/etc/motd')

    # ── logrotate ────────────────────────────────────────────────────────────
    lr_path = Path('/etc/logrotate.d/remotepower')
    current['logrotate'] = _read(str(lr_path)) if lr_path.exists() else ''

    # ── cron (root crontab) ──────────────────────────────────────────────────
    current['cron'] = _run(['crontab', '-l', '-u', 'root'])

    return current


def apply_host_config(desired):
    """v2.6.0: Apply desired host configuration pushed by the server.

    Each section is applied independently. Failures are logged but do not
    prevent other sections from being applied. The agent runs as root so
    all file writes and systemctl calls are expected to succeed on a
    normal system.

    Security: the server is the trusted authority. The same trust boundary
    as the existing exec: command channel applies here.
    """
    import grp as _grp
    import pwd as _pwd

    results = {}

    def _write(path, content, mode=0o644):
        try:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
            os.chmod(path, mode)
            return True
        except OSError as e:
            log.warning(f'apply_host_config: write {path} failed: {e}')
            return False

    def _run(cmd, **kw):
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=30, **kw)
            return r.returncode == 0, r.stdout.decode(errors='replace') + r.stderr.decode(errors='replace')
        except Exception as e:
            return False, str(e)

    # ── repos ────────────────────────────────────────────────────────────────
    if 'repos' in desired:
        if Path('/etc/apt/sources.list').exists():
            ok = _write('/etc/apt/sources.list', desired['repos'])
        else:
            ok = _write('/etc/yum.repos.d/remotepower.repo', desired['repos'])
        results['repos'] = 'ok' if ok else 'write_error'
        log.info(f'apply_host_config repos: {results["repos"]}')

    # ── netplan ──────────────────────────────────────────────────────────────
    if 'netplan' in desired and desired['netplan'].strip():
        ok = _write('/etc/netplan/01-remotepower.yaml', desired['netplan'], 0o600)
        if ok:
            ok2, out = _run(['netplan', 'apply'])
            results['netplan'] = 'ok' if ok2 else f'apply_failed: {out[:200]}'
        else:
            results['netplan'] = 'write_error'
        log.info(f'apply_host_config netplan: {results["netplan"]}')

    # ── nmcli ────────────────────────────────────────────────────────────────
    if 'nmcli' in desired and desired['nmcli'].strip():
        conn_path = '/etc/NetworkManager/system-connections/remotepower-managed.nmconnection'
        ok = _write(conn_path, desired['nmcli'], 0o600)
        if ok:
            _run(['nmcli', 'connection', 'reload'])
        results['nmcli'] = 'ok' if ok else 'write_error'
        log.info(f'apply_host_config nmcli: {results["nmcli"]}')

    # ── resolv.conf ──────────────────────────────────────────────────────────
    if 'resolv_conf' in desired:
        # Handle systemd-resolved symlink — write to the real file
        rp = Path('/etc/resolv.conf')
        target = str(rp.resolve()) if rp.is_symlink() else '/etc/resolv.conf'
        ok = _write(target, desired['resolv_conf'])
        results['resolv_conf'] = 'ok' if ok else 'write_error'
        log.info(f'apply_host_config resolv_conf: {results["resolv_conf"]}')

    # ── /etc/hosts ───────────────────────────────────────────────────────────
    if 'hosts' in desired:
        ok = _write('/etc/hosts', desired['hosts'])
        results['hosts'] = 'ok' if ok else 'write_error'
        log.info(f'apply_host_config hosts: {results["hosts"]}')

    # ── services (enable desired, do not disable others) ─────────────────────
    if 'services' in desired:
        errs = []
        for svc in (desired['services'] or []):
            ok, out = _run(['systemctl', 'enable', '--now', svc])
            if not ok:
                errs.append(svc)
                log.warning(f'apply_host_config: enable {svc} failed: {out[:100]}')
        results['services'] = 'ok' if not errs else f'failed: {errs}'
        log.info(f'apply_host_config services: {results["services"]}')

    # ── users ────────────────────────────────────────────────────────────────
    if 'users' in desired:
        errs = []
        for u in (desired['users'] or []):
            name = u.get('name', '')
            if not name:
                continue
            try:
                try:
                    pw = _pwd.getpwnam(name)
                    # User exists — update shell and groups
                    _run(['usermod', '-s', u.get('shell', '/bin/bash')] +
                         (['-G', ','.join(u['groups'])] if u.get('groups') else []) +
                         [name])
                except KeyError:
                    # Create user
                    cmd = ['useradd', '-m', '-s', u.get('shell', '/bin/bash')]
                    if u.get('groups'):
                        cmd += ['-G', ','.join(u['groups'])]
                    cmd.append(name)
                    ok, out = _run(cmd)
                    if not ok:
                        errs.append(f'{name}: {out[:80]}')
                        continue
                    pw = _pwd.getpwnam(name)

                # Write authorized_keys
                if u.get('authorized_keys'):
                    ssh_dir = Path(pw.pw_dir) / '.ssh'
                    ssh_dir.mkdir(mode=0o700, exist_ok=True)
                    os.chown(str(ssh_dir), pw.pw_uid, pw.pw_gid)
                    ak_path = ssh_dir / 'authorized_keys'
                    ak_path.write_text(u['authorized_keys'])
                    os.chmod(str(ak_path), 0o600)
                    os.chown(str(ak_path), pw.pw_uid, pw.pw_gid)
            except Exception as e:
                errs.append(f'{name}: {e}')
                log.warning(f'apply_host_config user {name} error: {e}')
        results['users'] = 'ok' if not errs else f'partial: {errs}'
        log.info(f'apply_host_config users: {results["users"]}')

    # ── groups ───────────────────────────────────────────────────────────────
    if 'groups' in desired:
        errs = []
        for g in (desired['groups'] or []):
            name = g.get('name', '')
            if not name:
                continue
            try:
                _grp.getgrnam(name)  # already exists
            except KeyError:
                cmd = ['groupadd']
                if g.get('gid'):
                    cmd += ['-g', str(g['gid'])]
                cmd.append(name)
                ok, out = _run(cmd)
                if not ok:
                    errs.append(f'{name}: {out[:80]}')
        results['groups'] = 'ok' if not errs else f'partial: {errs}'
        log.info(f'apply_host_config groups: {results["groups"]}')

    # ── sudoers ──────────────────────────────────────────────────────────────
    if 'sudoers' in desired:
        content = desired['sudoers']
        if content.strip():
            tmp = '/etc/sudoers.d/.remotepower.tmp'
            ok = _write(tmp, content, 0o440)
            if ok:
                ok2, out = _run(['visudo', '-c', '-f', tmp])
                if ok2:
                    os.rename(tmp, '/etc/sudoers.d/remotepower')
                    results['sudoers'] = 'ok'
                else:
                    os.unlink(tmp)
                    results['sudoers'] = f'syntax_error: {out[:200]}'
                    log.warning(f'apply_host_config sudoers rejected: {out[:200]}')
            else:
                results['sudoers'] = 'write_error'
        else:
            # Empty content — remove the file if it exists
            try:
                Path('/etc/sudoers.d/remotepower').unlink(missing_ok=True)
                results['sudoers'] = 'removed'
            except OSError as e:
                results['sudoers'] = f'remove_error: {e}'
        log.info(f'apply_host_config sudoers: {results["sudoers"]}')

    # ── motd ─────────────────────────────────────────────────────────────────
    if 'motd' in desired:
        ok = _write('/etc/motd', desired['motd'])
        results['motd'] = 'ok' if ok else 'write_error'
        log.info(f'apply_host_config motd: {results["motd"]}')

    # ── logrotate ────────────────────────────────────────────────────────────
    if 'logrotate' in desired:
        content = desired['logrotate']
        if content.strip():
            ok = _write('/etc/logrotate.d/remotepower', content, 0o644)
            results['logrotate'] = 'ok' if ok else 'write_error'
        else:
            try:
                Path('/etc/logrotate.d/remotepower').unlink(missing_ok=True)
                results['logrotate'] = 'removed'
            except OSError as e:
                results['logrotate'] = f'remove_error: {e}'
        log.info(f'apply_host_config logrotate: {results["logrotate"]}')

    # ── cron (root crontab) ──────────────────────────────────────────────────
    if 'cron' in desired:
        content = desired['cron']
        if content.strip():
            import tempfile as _tf
            try:
                with _tf.NamedTemporaryFile(mode='w', suffix='.crontab', delete=False) as f:
                    f.write(content if content.endswith('\n') else content + '\n')
                    tmp_path = f.name
                ok, out = _run(['crontab', '-u', 'root', tmp_path])
                Path(tmp_path).unlink(missing_ok=True)
                results['cron'] = 'ok' if ok else f'crontab_error: {out[:200]}'
            except Exception as e:
                results['cron'] = f'error: {e}'
        else:
            ok, out = _run(['crontab', '-r', '-u', 'root'])
            results['cron'] = 'removed' if ok else f'remove_error: {out[:100]}'
        log.info(f'apply_host_config cron: {results["cron"]}')

    return results


def count_mailbox_paths(paths):
    """v2.4.3: count regular files directly inside each watched
    directory — the Maildir 'new' folder convention, where each
    unread message is one file.

    Equivalent to ``find <path> -maxdepth 1 -type f | wc -l`` but done
    with os.scandir() rather than a shell: no shell means no quoting
    or injection surface, and the path is operator-configured anyway.
    maxdepth 1 (non-recursive) matches the `find` example.

    Returns {path: {count: int, exists: bool, error: str|None}}. A
    missing or unreadable path is reported with exists/error rather
    than dropped, so the server can show "path gone" instead of
    silently losing the monitor.
    """
    out = {}
    for p in (paths or [])[:MAX_MAILBOX_PATHS]:
        entry = {'count': None, 'exists': False, 'error': None}
        try:
            if not os.path.isdir(p):
                entry['error'] = 'not_a_directory'
                out[p] = entry
                continue
            n = 0
            with os.scandir(p) as it:
                for de in it:
                    try:
                        # follow_symlinks=False: count the link itself,
                        # not its target — a Maildir file is a real file.
                        if de.is_file(follow_symlinks=False):
                            n += 1
                    except OSError:
                        continue
            entry['count'] = n
            entry['exists'] = True
        except PermissionError:
            entry['error'] = 'permission_denied'
        except OSError as e:
            entry['error'] = f'error: {e.__class__.__name__}'
        out[p] = entry
    return out


def compute_drift_report(paths):
    """v2.2.0: hash each watched file, return dict suitable for shipping
    in the heartbeat payload. Each entry has:
      hash:   "sha256:<hex>" or None if the file is missing
      size:   int or None
      mtime:  int (epoch seconds) or None
      exists: bool — distinguishes missing-and-was-here from
              never-existed; both look the same in current_hash but the
              server uses this to render "file removed" in the UI.

    Errors per-file are silently logged + the entry is still emitted
    with exists=False so the server can render "unreadable" — better
    than silently dropping a file that may have been moved or chmod-ed
    out from under the agent.
    """
    out = {}
    for p in (paths or [])[:MAX_DRIFT_FILES]:
        try:
            st = os.stat(p)
        except FileNotFoundError:
            out[p] = {'hash': None, 'size': None, 'mtime': None, 'exists': False}
            continue
        except (PermissionError, OSError) as e:
            log.debug(f"drift: stat({p}) failed: {e}")
            out[p] = {'hash': None, 'size': None, 'mtime': None, 'exists': False}
            continue
        if not stat.S_ISREG(st.st_mode):
            # Don't try to hash directories, sockets, etc.
            out[p] = {'hash': None, 'size': st.st_size, 'mtime': int(st.st_mtime),
                      'exists': True, 'note': 'not_regular_file'}
            continue
        if st.st_size > MAX_FILE_SIZE_HASH:
            # Avoid hashing huge files. Use size+mtime as a poor-man's
            # change indicator; full hash skipped.
            out[p] = {'hash': None, 'size': st.st_size, 'mtime': int(st.st_mtime),
                      'exists': True, 'note': 'too_large'}
            continue
        try:
            h = hashlib.sha256()
            with open(p, 'rb') as fh:
                while True:
                    chunk = fh.read(65536)
                    if not chunk:
                        break
                    h.update(chunk)
            out[p] = {
                'hash':   'sha256:' + h.hexdigest(),
                'size':   st.st_size,
                'mtime':  int(st.st_mtime),
                'exists': True,
            }
        except (PermissionError, OSError) as e:
            log.debug(f"drift: read({p}) failed: {e}")
            out[p] = {'hash': None, 'size': st.st_size, 'mtime': int(st.st_mtime),
                      'exists': True, 'note': 'read_failed'}
    return out


# ─── Heartbeat loop ─────────────────────────────────────────────────────────────
def heartbeat(creds, interval=POLL_INTERVAL):
    server = creds['server_url']; dev_id = creds['device_id']; token = creds['token']
    log.info(f"RemotePower agent v{VERSION} starting. Server: {server}, Device: {dev_id}")
    log.info(f"Poll: {interval}s | sysinfo every {SYSINFO_EVERY} polls | patches every {PATCH_EVERY} polls")

    poll_count = 0; cached_patch = None
    # v1.8.0: server pushes watched services + log rules in heartbeat response
    services_watched = []
    log_watch_rules  = []

    # v2.7.0: log source expansion state
    _auto_watch_detected = detect_auto_watch_units()
    if _auto_watch_detected:
        log.info(f'Auto-watch units detected: {_auto_watch_detected}')
    _dmesg_last_ts  = None   # None → 24h window on first run, then incremental
    _apt_state_file = Path('/var/lib/remotepower/apt-history-state.json')
    # v3.0.1: per-path tail state for file-based log_watch rules.
    # Persisted across restarts so we don't re-send the whole file every boot.
    _file_log_state_file = Path('/var/lib/remotepower/file-log-state.json')
    _file_log_state = {}
    if _file_log_state_file.exists():
        try:
            _file_log_state = json.loads(_file_log_state_file.read_text())
            if not isinstance(_file_log_state, dict):
                _file_log_state = {}
        except Exception:
            _file_log_state = {}
    # v2.8.1: backup monitors pushed from server config
    _backup_monitors = []
    # v2.2.0: server pushes watched files for drift detection. Empty list
    # before the first heartbeat completes — first heartbeat brings them
    # in, second heartbeat sends the first drift report.
    watched_files = []
    # v2.4.3: server pushes mailbox directory paths whose file count we
    # report (Maildir-style unread-message monitoring).
    mailbox_paths = []
    # v2.4.5: set true when the server requests an out-of-band package
    # scan; consumed (and cleared) on the next poll.
    force_pkg_scan = False
    # v3.0.2: one-shot ACME rescan request from server (operator clicked
    # "Force rescan" after renewing via CLI; skips the hourly cadence).
    force_acme_rescan = False
    # v3.0.0: IaC collection request from server
    pending_iac_request_id = None
    pending_iac_categories = None
    # v3.4.2: a force_agent_upgrade requested while an OpenSCAP scan is running
    # is held locally and retried on a later poll. The server clears its
    # one-shot flag after one delivery, so without this the deferred upgrade
    # would be lost entirely.
    pending_force_upgrade = False
    # v2.5.0: custom monitoring scripts pushed by the server. Empty list
    # until the first heartbeat response arrives carrying assignments.
    custom_scripts = []
    # v2.6.0: desired host config pushed by server; current state collected locally
    host_config_desired = None
    pending_script_results = {}

    # Detect if this is a fresh boot (first heartbeat after restart).
    # v3.0.2: read via O_NOFOLLOW helper from STATE_DIR (or /tmp fallback)
    # so a local non-root attacker can't pre-place a symlink and dictate
    # what the agent thinks the boot reason was, or get the agent to
    # read from an attacker-chosen file.
    boot_reason = None
    raw_reason = _safe_state_read('last-cmd')
    if raw_reason is not None:
        boot_reason = raw_reason.strip()[:64]
        _safe_state_unlink('last-cmd')
    # interval_override_file is still defined for later reads in the
    # heartbeat loop — we keep a Path reference for the O_NOFOLLOW open.
    interval_override_file = STATE_DIR / 'poll-interval'
    if not interval_override_file.parent.exists():
        # Fall back to legacy location only if STATE_DIR couldn't be created.
        interval_override_file = Path('/tmp/remotepower-poll-interval')

    # v1.11.7: stash file for cmd_output that couldn't be POSTed in its
    # follow-up heartbeat (network blip, server restart). The next
    # successful heartbeat picks it up and sends it through. /var/lib
    # is preferred (survives /tmp clearing on reboot, which would lose
    # the upgrade output across a reboot triggered by the upgrade
    # itself), with /tmp as a fallback for non-root deploys.
    # v3.0.2: prefer STATE_DIR over the loose /var/lib path so the file
    # sits in a directory we control rather than the parent of an
    # unrelated package install.
    pending_cmd_output_file = STATE_DIR / 'pending-cmd.json'
    if not pending_cmd_output_file.parent.exists() or not os.access(
            pending_cmd_output_file.parent, os.W_OK):
        pending_cmd_output_file = Path('/tmp/remotepower-pending-cmd.json')

    def _stash_pending_cmd_output(result, cmd):
        """Persist cmd_output to disk so the next heartbeat can retry it."""
        pending_cmd_output_file.write_text(json.dumps({
            'cmd_output': result,
            'executed_command': cmd,
            'stashed_at': int(time.time()),
        }))
        log.info(f"Stashed cmd_output for retry: {pending_cmd_output_file}")

    def _load_pending_cmd_output():
        """Pop any stashed cmd_output. Returns dict or None.

        We delete the file *before* the heartbeat goes out so a server
        that's still flapping doesn't cause us to retry forever and pile
        up duplicate entries. If the heartbeat then fails, the data is
        lost — but the alternative (replay until success) is worse for
        an upgrade log that might already be partially recorded.
        """
        if not pending_cmd_output_file.exists():
            return None
        try:
            data = json.loads(pending_cmd_output_file.read_text())
            pending_cmd_output_file.unlink()
            log.info("Loaded stashed cmd_output for retry")
            return data
        except Exception as e:
            log.warning(f"Failed to read stashed cmd_output: {e}")
            try: pending_cmd_output_file.unlink()
            except Exception: pass
            return None

    while True:
        poll_count += 1
        # Check for dynamically updated interval.
        # v3.0.2: read via O_NOFOLLOW helper. Belt-and-suspenders since
        # the primary path is now STATE_DIR/poll-interval (root-only),
        # but the /tmp/ fallback for non-root installs must also resist
        # symlink redirection.
        raw_iv = _safe_state_read('poll-interval')
        if raw_iv is not None:
            try:
                new_interval = int(raw_iv.strip())
                if new_interval != interval:
                    log.info(f"Poll interval updated: {interval}s → {new_interval}s")
                    interval = new_interval
                _safe_state_unlink('poll-interval')
            except (ValueError, OSError):
                pass

        payload = {'device_id': dev_id, 'token': token, 'ip': get_local_ip(),
                   'os': get_os_info(), 'version': VERSION,
                   # v3.4.2: report our own binary's hash so the server can
                   # attest the running agent matches its canonical copy.
                   'agent_sha256': _agent_self_sha256()}
        # v3.4.2: surface a refused (unsigned/invalid) self-update so the server
        # can flag it. Cleared on the next successful update.
        _rej = _safe_state_read('update-rejected')
        if _rej:
            payload['agent_update_rejected'] = _rej[:200]

        # v3.0.0: if the previous heartbeat asked us to collect IaC data,
        # run the requested collectors now and attach the result.
        if pending_iac_request_id and pending_iac_categories:
            log.info(f'Running IaC collection for req {pending_iac_request_id} '
                     f'({len(pending_iac_categories)} categories)')
            try:
                iac_result = run_iac_collection(pending_iac_categories)
                payload['iac_data'] = {
                    'request_id': pending_iac_request_id,
                    'categories': pending_iac_categories,
                    'data':       iac_result,
                }
            except Exception as e:
                log.warning(f'IaC collection failed: {e}')
                payload['iac_data'] = {
                    'request_id': pending_iac_request_id,
                    'categories': pending_iac_categories,
                    'error':      str(e),
                }
            # Clear — we only attempt once. If the server didn't get it,
            # the user can simply click Generate again.
            pending_iac_request_id = None
            pending_iac_categories = None

        # v2.8.1: backup file age reporting (every poll if monitors configured)
        if _backup_monitors:
            payload['backup_status'] = collect_backup_status(_backup_monitors)

        # v1.11.7: pick up any cmd_output that couldn't be sent in its
        # follow-up heartbeat last cycle. Piggybacks on this heartbeat.
        pending = _load_pending_cmd_output()
        if pending:
            payload['cmd_output'] = pending.get('cmd_output')
            payload['executed_command'] = pending.get('executed_command', '')
        if poll_count == 1 and boot_reason:
            payload['boot_reason'] = boot_reason

        send_sysinfo = (poll_count == 1 or poll_count % SYSINFO_EVERY == 0)
        run_patch    = (poll_count % PATCH_EVERY == 0)

        if run_patch:
            log.debug(f"Poll {poll_count}: running patch check")
            cached_patch = get_patch_info(); send_sysinfo = True

        # v1.7.0: submit package inventory for CVE scanning (hash-gated)
        # v2.4.5: also send immediately when the server set the
        # one-shot force_package_scan flag (operator clicked "scan
        # now"). force_pkg_scan is set from the previous heartbeat's
        # response, so this fires on the heartbeat after the click.
        if poll_count == 1 or poll_count % PACKAGE_LIST_EVERY == 0 or force_pkg_scan:
            try:
                # v2.4.10: a forced scan bypasses the unchanged-list
                # hash gate — otherwise a stable host's forced scan
                # is silently skipped because the list matches.
                send_package_list(creds, force=force_pkg_scan)
            except Exception as e:
                log.debug(f'Package submission error: {e}')
        # A forced scan also refreshes the patch / upgradable count.
        if force_pkg_scan:
            log.info('Forced package scan (operator requested)')
            cached_patch = get_patch_info()
            send_sysinfo = True
            force_pkg_scan = False

        # v1.8.0: report service states if any are configured to watch
        if services_watched and poll_count % SERVICE_CHECK_EVERY == 0:
            try:
                payload['services'] = get_services(services_watched)
            except Exception as e:
                log.debug(f'Service check error: {e}')

        # v2.2.0: compute drift report every DRIFT_EVERY polls. Cheap —
        # SHA-256 of a few small config files takes well under 100 ms
        # on any reasonable hardware. Skipped on poll 1 because we
        # haven't yet received the watched_files list from the server;
        # poll 2 (about 60s in) ships the first report.
        if watched_files and poll_count > 1 and (
            poll_count == 2 or poll_count % DRIFT_EVERY == 0
        ):
            try:
                payload['drift'] = compute_drift_report(watched_files)
                log.debug(f'Drift report: hashed {len(payload["drift"])} files')
            except Exception as e:
                log.debug(f'Drift report error: {e}')

        # v2.4.3: mailbox file counts. Same cadence rationale as drift —
        # the path list arrives with the first heartbeat, so reporting
        # starts at poll 2. Counting files in a directory is very cheap.
        if mailbox_paths and poll_count > 1 and (
            poll_count == 2 or poll_count % MAILBOX_CHECK_EVERY == 0
        ):
            try:
                payload['mailbox_counts'] = count_mailbox_paths(mailbox_paths)
                log.debug(f'Mailbox report: {len(payload["mailbox_counts"])} path(s)')
            except Exception as e:
                log.debug(f'Mailbox count error: {e}')

        # v3.0.1: ACME / acme.sh state scan. Walk ~/.acme.sh/ and report
        # the per-domain config (next renewal, alt names, challenge type,
        # reload command). Cheap when acme.sh isn't installed (just a
        # directory existence check), still cheap when it is (file reads).
        #
        # v3.0.2: respect one-shot `force_acme_rescan` flag from server
        # (operator clicked "Force rescan" after renewing via CLI).
        # Reuses force_pkg_scan-style pattern; flag is consumed here.
        if poll_count == 1 or poll_count % ACME_CHECK_EVERY == 0 or force_acme_rescan:
            try:
                acme_state = collect_acme_state()
                # Always send the state — even when acme.sh isn't installed,
                # so the server can display "not installed" rather than
                # stale data from a previous reading.
                payload['acme'] = acme_state
                if acme_state.get('available'):
                    log.debug(f'ACME scan: {len(acme_state["certs"])} cert(s) under {acme_state["home"]}')
            except Exception as e:
                log.debug(f'ACME scan error: {e}')
            force_acme_rescan = False

        # v2.5.0: run custom monitoring scripts every SCRIPT_CHECK_EVERY polls.
        # Scripts arrive via the heartbeat response and are stored in
        # custom_scripts. Results are keyed by script ID and held in
        # pending_script_results until the next heartbeat picks them up.
        # First poll is skipped (scripts list may not have arrived yet).
        if custom_scripts and poll_count > 1 and (
            poll_count % SCRIPT_CHECK_EVERY == 0
        ):
            try:
                new_results = run_custom_scripts(custom_scripts)
                pending_script_results.update(new_results)
                log.info(f'Custom scripts: ran {len(new_results)}, '
                         f'{sum(1 for r in new_results.values() if not r["ok"])} failed')
            except Exception as e:
                log.debug(f'Custom script runner error: {e}')

        # Include any pending custom script results in this heartbeat
        if pending_script_results:
            payload['custom_script_results'] = dict(pending_script_results)
            pending_script_results.clear()

        # v2.6.0: apply desired host config immediately when it changes.
        # Current state is NOT sent in the heartbeat — it is collected
        # on-demand when the admin clicks "⬇ Fetch current" in the UI,
        # which queues a host-config-collect command via the exec channel.
        if host_config_desired and poll_count == 2:
            try:
                apply_results = apply_host_config(host_config_desired)
                log.info(f'Host config applied: {apply_results}')
            except Exception as e:
                log.warning(f'Host config apply error: {e}')

        # v1.11.0: report containers/pods every CONTAINER_CHECK_EVERY polls.
        # Same cadence as services. Skipping the first heartbeat is fine —
        # it'd otherwise fire 0.1s after enrollment and confuse new users
        # waiting to see their containers; second heartbeat catches them.
        #
        # v1.11.4: previously this only sent ``containers`` when the list
        # was non-empty. That caused stale data: a host going from "1
        # docker container" to "0 docker containers" (stopped, daemon
        # restart, etc.) never overwrote the server's last report, so
        # the dashboard showed "1 running" forever. Fix: always send
        # the (possibly empty) list when a runtime is detected on the
        # host, so the server can clear out the previous state. Hosts
        # with no runtime installed at all still skip — no point
        # creating empty rows in containers.json for those.
        if poll_count > 1 and poll_count % CONTAINER_CHECK_EVERY == 0:
            try:
                if _which('docker') or _which('podman') or _which('kubectl'):
                    payload['containers'] = get_containers()
            except Exception as e:
                log.debug(f'Container listing error: {e}')
            # v2.1.0: compose projects ride alongside containers. Reported
            # at the same cadence — both come from the docker world and
            # we don't want to scan twice. Skipped if docker isn't installed
            # (get_compose_projects() returns [] in that case so the field
            # stays empty rather than triggering false UI affordances).
            try:
                projects = get_compose_projects()
                if projects:
                    payload['compose_projects'] = projects
            except Exception as e:
                log.debug(f'compose listing error: {e}')

        # v3.4.0: hardware / health inventory on the slow cadence — smartctl,
        # dmidecode, sensors and the kernel check aren't free, so they ride
        # alongside containers rather than every heartbeat. Each is wrapped:
        # a probe failure (missing tool, no root) leaves the key absent and
        # the server keeps the last known value.
        if poll_count > 1 and poll_count % CONTAINER_CHECK_EVERY == 0:
            try:
                smart = get_smart_status()
                if smart:
                    payload['smart'] = smart
            except Exception as e:
                log.debug(f'SMART probe error: {e}')
            try:
                payload['kernel'] = get_kernel_status()
            except Exception as e:
                log.debug(f'kernel probe error: {e}')
            try:
                hw = get_hardware_inventory()
                if hw:
                    payload['hardware'] = hw
            except Exception as e:
                log.debug(f'hardware inventory error: {e}')
            # v3.14.0: GPU telemetry (nvidia-smi / rocm-smi).
            try:
                gpus = get_gpu_status()
                if gpus:
                    payload['gpus'] = gpus
            except Exception as e:
                log.debug(f'gpu status error: {e}')
            # v3.14.0: local x509 cert-file expiry inventory.
            try:
                certs = get_cert_files()
                if certs:
                    payload['cert_files'] = certs
            except Exception as e:
                log.debug(f'cert files error: {e}')
            # v3.14.0: local account posture (passwd/shadow/sudo).
            try:
                accts = get_local_accounts()
                if accts:
                    payload['accounts'] = accts
            except Exception as e:
                log.debug(f'accounts probe error: {e}')
            # v3.14.0: UPS / power status (NUT / apcupsd).
            try:
                ups = get_ups_status()
                if ups:
                    payload['ups'] = ups
            except Exception as e:
                log.debug(f'ups probe error: {e}')
            # v3.6.0: endpoint AV/malware posture (ClamAV / rkhunter).
            try:
                av = get_av_status()
                if av:
                    payload['av'] = av
            except Exception as e:
                log.debug(f'av status error: {e}')
            # v3.4.0: Helm releases — only worth probing where a cluster CLI
            # exists; rides the same kubeconfig discovery as pod listing.
            try:
                if _which('helm') and (_which('kubectl') or os.environ.get('KUBECONFIG')):
                    helm_rel = get_helm_releases()
                    payload['helm'] = helm_rel
            except Exception as e:
                log.debug(f'helm listing error: {e}')

        if send_sysinfo:
            sysinfo = {
                'uptime':   get_uptime(),
                'platform': platform.platform(),
                'kernel':   platform.release(),     # v3.13.0: CMDB Hardware panel
                'cpu':      _cpu_model(),            # v3.13.0: CPU model string
                'packages': cached_patch,
                'network':  get_network_info(),
            }
            # Merge metrics if psutil available
            sysinfo.update(get_metrics())
            # v2.2.6: extra host telemetry (reboot-required, failed
            # systemd units, logged-in users, listening ports, last
            # boot). Best-effort — wrapped so a probe failure can't
            # break the heartbeat.
            try:
                sysinfo.update(get_host_health())
            except Exception as e:
                log.debug(f'host health probe error: {e}')
            payload['sysinfo'] = sysinfo
            payload['journal'] = get_journal(100)
            log.debug(f"Poll {poll_count}: sending sysinfo + journal")

        try:
            resp = http_post(f"{server}/api/heartbeat", payload)
            cmd = resp.get('command')
            # v2.1.0: server may return HTTP 202 with {'busy': True, ...}
            # when a save() couldn't acquire the per-file flock quickly
            # (i.e. another writer is holding it). This is *not* a failure:
            # the server intentionally drops this heartbeat's writes so the
            # request doesn't stall past our HTTP timeout. We log it at
            # debug and retry on the next normal cycle. http_post() doesn't
            # surface the status code, so we detect 202 by the response
            # shape (the {'busy': True} marker the server returns instead
            # of the usual {'command': ..., 'poll_interval': ...} payload).
            if resp.get('busy') is True:
                log.debug(f"Server busy (HTTP 202) — retry on next poll")
                # Skip command-processing and follow-up block; the next
                # heartbeat will re-send everything that mattered.
                cmd = None
            # v1.8.0: pick up server-pushed watch config
            # v1.8.3: log at info when it *changes* so ops can see config pushes
            if 'services_watched' in resp:
                new_sw = resp.get('services_watched') or []
                if new_sw != services_watched:
                    log.info(f'Config updated: services_watched = {new_sw}')
                services_watched = new_sw
            if 'log_watch' in resp:
                new_lw = resp.get('log_watch') or []
                if new_lw != log_watch_rules:
                    log.info(f'Config updated: log_watch rules = {len(new_lw)}')
                log_watch_rules = new_lw
            # v2.2.0: configuration drift detection — the server pushes the
            # list of files we should hash. Empty list means drift is
            # disabled for this device.
            if 'watched_files' in resp:
                new_wf = resp.get('watched_files') or []
                if new_wf != watched_files:
                    log.info(f'Config updated: watched_files = {len(new_wf)} file(s)')
                watched_files = new_wf
            # v2.4.3: mailbox-count monitor — the server pushes a list of
            # directory paths whose regular-file count we should report
            # (e.g. a Maildir 'new' folder → unread message count). Empty
            # list means the mailbox monitor is off for this device.
            if 'mailbox_paths' in resp:
                new_mp = resp.get('mailbox_paths') or []
                if new_mp != mailbox_paths:
                    log.info(f'Config updated: mailbox_paths = {len(new_mp)} path(s)')
                mailbox_paths = new_mp
            # v2.4.5: one-shot package-scan request from the server.
            # Acted on at the top of the next poll.
            if resp.get('force_package_scan'):
                force_pkg_scan = True
                log.info('Server requested a package scan')
            # v3.0.2: one-shot ACME rescan request
            if resp.get('force_acme_rescan'):
                force_acme_rescan = True
                log.info('Server requested an ACME rescan')
            # v3.4.2: one-shot OpenSCAP scan request. oscap is slow (minutes),
            # so run it in a daemon thread and POST results when done — the
            # heartbeat loop keeps running. The lock prevents overlap.
            if resp.get('force_scap_scan'):
                prof = resp.get('scap_profile') or 'cis'
                if _oscap_running.acquire(blocking=False):
                    log.info(f'Server requested OpenSCAP scan (profile={prof})')

                    def _run_scap(p=prof):
                        try:
                            run_oscap_scan(p, creds)
                        finally:
                            _oscap_running.release()
                    threading.Thread(target=_run_scap, daemon=True).start()
                else:
                    log.info('OpenSCAP scan already running; ignoring request')
            # v3.0.1: one-shot force-upgrade flag — re-download the agent
            # binary regardless of version match. Used for re-deploys or
            # corrupt-binary recovery; the server clears the flag after one
            # delivery so this fires exactly once.
            if resp.get('force_agent_upgrade') or pending_force_upgrade:
                if _oscap_running.locked():
                    # Hold the force upgrade until the in-progress OpenSCAP scan
                    # finishes — restarting now would kill the scan thread. The
                    # server already cleared its one-shot flag, so we remember
                    # locally and retry next poll.
                    pending_force_upgrade = True
                    log.info('Force upgrade requested during OpenSCAP scan — '
                             'deferring until the scan completes')
                else:
                    pending_force_upgrade = False
                    log.info('Server requested force agent upgrade — bypassing version check')
                    try:
                        # Variable in scope is `server` (set at top of heartbeat),
                        # not `server_url`. Previous code referenced an undefined
                        # name → NameError caught by the except clause → log line
                        # "Force upgrade failed: name 'server_url' is not defined"
                        # which is what tipped Jakob off in the journal.
                        if check_for_update(server, force=True):
                            # check_for_update with force=True returns True when it
                            # has overwritten the binary; restart so systemd picks
                            # up the new binary (the existing self-update path
                            # already restarts via the calling loop).
                            log.info('Force upgrade completed — agent will restart')
                            return  # Falls out of heartbeat loop; systemd respawns us
                    except Exception as e:
                        log.error(f'Force upgrade failed: {e}')
            # v3.0.0: one-shot IaC data collection request from the server.
            # Categories listed must be collected and returned in the NEXT heartbeat.
            iac_req = resp.get('force_iac_collect')
            if isinstance(iac_req, dict) and iac_req.get('request_id') and iac_req.get('categories'):
                pending_iac_request_id = str(iac_req['request_id'])
                pending_iac_categories = list(iac_req['categories'])
                log.info(f'Server requested IaC collection: req={pending_iac_request_id} '
                         f'categories={pending_iac_categories}')
            # v2.5.0: custom monitoring scripts pushed by the server.
            # Replace the local list on every heartbeat so assignments
            # and script body changes take effect at the next run window.
            if 'custom_scripts' in resp:
                new_cs = resp.get('custom_scripts') or []
                if isinstance(new_cs, list):
                    if len(new_cs) != len(custom_scripts) or \
                       [s['id'] for s in new_cs] != [s['id'] for s in custom_scripts]:
                        log.info(f'Config updated: custom_scripts = {len(new_cs)} script(s)')
                    custom_scripts = new_cs
            # v2.6.0: receive desired host config from server
            if 'backup_monitors' in resp:
                _backup_monitors = resp['backup_monitors'] or []

            if 'host_config_desired' in resp:
                new_hcd = resp.get('host_config_desired')
                if isinstance(new_hcd, dict):
                    if new_hcd != host_config_desired:
                        log.info('Host config desired updated from server — will apply')
                        # Apply immediately on next poll (poll_count == 2 check
                        # won't fire again; apply directly here instead)
                        try:
                            apply_results = apply_host_config(new_hcd)
                            log.info(f'Host config applied on update: {apply_results}')
                        except Exception as e:
                            log.warning(f'Host config apply error: {e}')
                    host_config_desired = new_hcd
            if cmd:
                log.info(f"Received command: {cmd}")
                result = execute_command(cmd)
                # v1.11.7: BUG FIX. Previously this code did
                # `payload['cmd_output'] = result` and relied on the
                # next heartbeat to ship it — but `payload` is reset
                # at the top of every loop iteration, so the result was
                # silently dropped on the floor. Symptom: "Update
                # history" stayed empty even though the upgrade ran
                # successfully (the journal showed `Command output
                # (rc=0): ...` but `update_logs.json` got nothing).
                #
                # Fix: send a dedicated follow-up heartbeat immediately
                # after the command finishes, carrying just the bits
                # the server needs (cmd_output + executed_command for
                # the webhook). We don't repeat the full sysinfo /
                # journal payload — that's already on the server from
                # the first heartbeat in this iteration.
                if result is not None:
                    follow_up = {
                        'device_id': dev_id,
                        'token':     token,
                        'ip':        get_local_ip(),
                        'os':        get_os_info(),
                        'version':   VERSION,
                        'cmd_output': result,
                        'executed_command': cmd,
                    }
                    try:
                        http_post(f"{server}/api/heartbeat", follow_up)
                        log.debug("Follow-up heartbeat with cmd_output sent")
                    except Exception as e:
                        log.warning(f"Follow-up heartbeat failed: {e} "
                                    f"(cmd_output will be retried on next poll)")
                        # Stash on disk so the next heartbeat picks it up.
                        # See pending_cmd_output handling below.
                        try:
                            _stash_pending_cmd_output(result, cmd)
                        except Exception:
                            pass

        except error.HTTPError as e:
            if e.code == 403:
                log.error("Credentials rejected - re-enroll: sudo remotepower-agent enroll")
            else:
                log.warning(f"HTTP {e.code}")
        except Exception as e:
            log.warning(f"Heartbeat failed: {e}")

        # v1.8.0: submit recent unit logs every N polls if any units are watched
        # (either as services_watched, or as log_watch targets)
        log_units = set(services_watched)
        # v2.7.0: auto-add common units that exist on this host
        for u in _auto_watch_detected:
            log_units.add(u)
        # v3.0.1: collect file-path entries separately. log_watch rules with a
        # `path` field tell us to tail that file and submit lines under unit
        # name 'file:<path>'. systemd units stay in log_units; file paths go
        # into extra_units directly so journalctl isn't queried for them.
        _file_paths = []
        for r in log_watch_rules:
            if r.get('path'):
                _file_paths.append(r['path'])
            elif r.get('unit') and not str(r.get('unit', '')).startswith('file:'):
                log_units.add(r['unit'])
        if log_units and poll_count % LOG_SUBMIT_EVERY == 0:
            try:
                # v2.7.0: extend with dmesg and apt history as virtual units
                extra = {}
                extra['kernel']      = collect_dmesg_logs(_dmesg_last_ts)
                extra['apt.history'] = collect_apt_history(_apt_state_file)
                if any(extra['kernel']):
                    _dmesg_last_ts = time.time()
                # v2.8.0: web access logs for brute-force detection
                _web_logs = collect_web_access_logs(_apt_state_file.parent)
                extra.update(_web_logs)
                # v3.0.1: file-path log_watch sources
                if _file_paths:
                    for _fp in _file_paths:
                        _file_entries = collect_file_log(_fp, _file_log_state)
                        if _file_entries:
                            extra[f'file:{_fp}'] = _file_entries
                    # Persist state so we don't re-read on agent restart
                    try:
                        _file_log_state_file.write_text(json.dumps(_file_log_state))
                    except Exception as e:
                        log.debug(f'file_log: failed to persist state: {e}')
                submit_unit_logs(creds, sorted(log_units), extra_units=extra)
            except Exception as e:
                log.debug(f'Log submission error: {e}')

        if poll_count % UPDATE_CHECK_EVERY == 0:
            try:
                if check_for_update(server): return
            except Exception as e:
                log.debug(f"Update check error: {e}")

        time.sleep(interval)

# ─── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description='RemotePower client agent')
    parser.add_argument('action', nargs='?', default='run',
        choices=['run', 'enroll', 're-enroll', 'enroll-token', 'status',
                 'update', 'integrity', 'send_current_configs'],
        help='run | enroll | re-enroll | enroll-token | status | update | integrity | send_current_configs')
    parser.add_argument('--interval', type=int, default=POLL_INTERVAL,
        help=f'Poll interval in seconds (default: {POLL_INTERVAL})')
    # v1.11.10: token-based enrollment for non-interactive use
    parser.add_argument('--server', help='Server URL for enroll-token (e.g. https://remote.example.com)')
    parser.add_argument('--token', help='Enrollment token (or use $REMOTEPOWER_ENROLL_TOKEN, or /etc/remotepower/enroll-token)')
    parser.add_argument('--name', help='Device display name (defaults to hostname)')
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Warning: running as non-root. Shutdown/reboot may fail.")
        print("Use sudo or the systemd unit (runs as root).")
        print()

    if args.action == 'enroll':
        enroll_interactive(re_enroll=False); return

    if args.action == 're-enroll':
        enroll_interactive(re_enroll=True); return

    if args.action == 'enroll-token':
        # Server URL: --server flag, or existing creds (re-enrollment), or
        # error out. We deliberately don't read it from env to keep the
        # surface small.
        server_url = args.server
        if not server_url:
            existing = load_credentials()
            if existing and existing.get('server_url'):
                server_url = existing['server_url']
            else:
                print("✗ No --server URL and no existing credentials.")
                print("  Pass --server https://your.server.example.com")
                sys.exit(1)
        enroll_with_token(server_url, args.token or '', args.name)
        return

    if args.action == 'status':
        creds = load_credentials()
        if creds:
            print(f"Enrolled : Yes")
            print(f"Server   : {creds['server_url']}")
            print(f"Device   : {creds['name']} ({creds['device_id']})")
            print(f"Version  : {VERSION}")
            for n in get_network_info():
                print(f"Network  : {n['iface']}  {n['ip']}  {n['mac']}")
        else:
            print("Not enrolled. Run: sudo remotepower-agent enroll")
        return

    if args.action == 'update':
        creds = load_credentials()
        if not creds: print("Not enrolled."); sys.exit(1)
        if not check_for_update(creds['server_url']): print(f"Already up to date (v{VERSION}).")
        return

    if args.action == 'integrity':
        creds = load_credentials()
        if not creds: print("Not enrolled."); sys.exit(1)
        ok, detail = get_agent_integrity(creds['server_url'])
        status = "✓ OK" if ok else "✗ MISMATCH"
        print(f"Agent integrity: {status} - {detail}")
        sys.exit(0 if ok else 1)

    if args.action == 'send_current_configs':
        """Collect current host configuration and send it to the server once."""
        creds = load_credentials()
        if not creds: print("Not enrolled."); sys.exit(1)
        print("Collecting current host configuration...")
        current = collect_host_config()
        sections = [s for s, v in current.items() if v]
        print(f"Collected {len(sections)} section(s): {', '.join(sections)}")
        payload = {
            'device_id':          creds['device_id'],
            'token':              creds['token'],
            'ip':                 get_local_ip(),
            'os':                 get_os_info(),
            'version':            VERSION,
            'host_config_current': current,
        }
        try:
            http_post(f"{creds['server_url']}/api/heartbeat", payload)
            print("✓ Current configuration sent to server.")
            print("  Open the Host Config modal and click '⬇ Fetch current' to view it.")
        except Exception as e:
            print(f"✗ Failed to send: {e}")
            sys.exit(1)
        return

    creds = load_credentials()
    if not creds:
        print("Not enrolled. Starting enrollment wizard...")
        creds = enroll_interactive()

    heartbeat(creds, interval=args.interval)
# ══ v3.0.0: IaC data collection ════════════════════════════════════════════════
# Each category returns a JSON-serialisable dict/list of raw state.
# Called on-demand when the server sets force_iac_collect:<categories> in the
# heartbeat response. The agent runs the requested collectors and returns the
# results in the NEXT heartbeat as iac_data.
# ═════════════════════════════════════════════════════════════════════════════

def _safe_run(cmd, timeout=10):
    """Run a shell command, return (rc, stdout); never raise."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or '')
    except Exception as e:
        return -1, f'<error: {e}>'

def _safe_read(path, max_bytes=200_000):
    try:
        with open(path, 'r', errors='replace') as f:
            return f.read(max_bytes)
    except Exception:
        return ''


def iac_collect_os_identity():
    """Category 1: OS & identity."""
    rc, hn = _safe_run(['hostname', '-f'])
    info = {
        'hostname': hn.strip() if rc == 0 else os.uname().nodename,
        'kernel':   ' '.join(os.uname()[2:4]),
        'arch':     os.uname().machine,
        'os_release': {},
    }
    # Parse /etc/os-release
    for line in _safe_read('/etc/os-release').splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            info['os_release'][k.strip()] = v.strip().strip('"')
    return info


def iac_collect_packages():
    """Category 2: full installed package list (manager + names + versions)."""
    if shutil.which('dpkg'):
        rc, out = _safe_run(['dpkg-query', '-W', '-f=${Package}\t${Version}\t${Status}\n'])
        pkgs = []
        for line in out.splitlines():
            parts = line.split('\t')
            if len(parts) >= 3 and 'installed' in parts[2]:
                pkgs.append({'name': parts[0], 'version': parts[1]})
        return {'manager': 'apt', 'packages': pkgs}
    if shutil.which('rpm'):
        rc, out = _safe_run(['rpm', '-qa', '--qf', '%{NAME}\t%{VERSION}-%{RELEASE}\n'])
        pkgs = [{'name': p.split('\t')[0], 'version': p.split('\t')[1]}
                for p in out.splitlines() if '\t' in p]
        return {'manager': 'dnf', 'packages': pkgs}
    if shutil.which('pacman'):
        rc, out = _safe_run(['pacman', '-Q'])
        pkgs = [{'name': p.split(' ')[0], 'version': p.split(' ', 1)[1]}
                for p in out.splitlines() if ' ' in p]
        return {'manager': 'pacman', 'packages': pkgs}
    return {'manager': 'unknown', 'packages': []}


def iac_collect_systemd():
    """Category 3: systemd units in enabled state."""
    rc, out = _safe_run(['systemctl', 'list-unit-files',
                          '--state=enabled', '--type=service', '--no-legend'])
    enabled = []
    for line in out.splitlines():
        parts = line.split()
        if parts and parts[0].endswith('.service'):
            enabled.append(parts[0])
    return {'enabled_services': enabled}


def iac_collect_users():
    """Category 4: local users with uid>=1000 (excluding nobody=65534)."""
    users = []
    for line in _safe_read('/etc/passwd').splitlines():
        parts = line.split(':')
        if len(parts) < 7: continue
        try:
            uid = int(parts[2])
        except ValueError:
            continue
        if uid >= 1000 and uid != 65534:
            users.append({
                'username': parts[0], 'uid': uid, 'gid': int(parts[3] or 0),
                'gecos': parts[4], 'home': parts[5], 'shell': parts[6],
            })
    return {'users': users}


def iac_collect_groups():
    """Category 5: local groups with gid>=1000."""
    groups = []
    for line in _safe_read('/etc/group').splitlines():
        parts = line.split(':')
        if len(parts) < 4: continue
        try:
            gid = int(parts[2])
        except ValueError:
            continue
        if gid >= 1000 and gid != 65534:
            members = [m for m in parts[3].split(',') if m]
            groups.append({'name': parts[0], 'gid': gid, 'members': members})
    return {'groups': groups}


def iac_collect_ssh_keys():
    """Category 6: SSH authorized_keys per user (including root)."""
    keys = {}
    homes = [('root', '/root')]
    for line in _safe_read('/etc/passwd').splitlines():
        parts = line.split(':')
        if len(parts) >= 6 and parts[5].startswith('/home/'):
            try:
                if int(parts[2]) >= 1000:
                    homes.append((parts[0], parts[5]))
            except ValueError:
                pass
    for username, home in homes:
        ak = Path(home) / '.ssh' / 'authorized_keys'
        if ak.exists():
            try:
                content = ak.read_text(errors='replace')
                user_keys = [ln.strip() for ln in content.splitlines()
                             if ln.strip() and not ln.strip().startswith('#')]
                if user_keys:
                    keys[username] = user_keys
            except Exception:
                pass
    return {'authorized_keys': keys}


def iac_collect_network():
    """Category 7: full network configuration (interfaces, addresses, routes)."""
    rc, addr = _safe_run(['ip', '-j', 'addr', 'show'])
    rc2, route = _safe_run(['ip', '-j', 'route', 'show'])
    try:
        addrs  = json.loads(addr) if addr else []
        routes = json.loads(route) if route else []
    except json.JSONDecodeError:
        addrs, routes = [], []
    # /etc/netplan or /etc/network/interfaces
    cfg_files = {}
    for path in ('/etc/network/interfaces',):
        if Path(path).exists():
            cfg_files[path] = _safe_read(path, 20_000)
    netplan_dir = Path('/etc/netplan')
    if netplan_dir.is_dir():
        for f in netplan_dir.glob('*.yaml'):
            cfg_files[str(f)] = _safe_read(str(f), 20_000)
    return {'addresses': addrs, 'routes': routes, 'config_files': cfg_files}


def iac_collect_fstab():
    """Category 8: /etc/fstab entries."""
    entries = []
    for line in _safe_read('/etc/fstab').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        if len(parts) >= 6:
            entries.append({
                'fs_spec': parts[0], 'fs_file': parts[1], 'fs_vfstype': parts[2],
                'fs_mntops': parts[3], 'fs_freq': parts[4], 'fs_passno': parts[5],
            })
    return {'fstab': entries}


def iac_collect_containers():
    """Category 9: Docker/Podman containers with full inspect."""
    out = {'docker': [], 'podman': []}
    for runtime, key in (('docker', 'docker'), ('podman', 'podman')):
        if not shutil.which(runtime):
            continue
        rc, ids_raw = _safe_run([runtime, 'ps', '-aq'])
        ids = ids_raw.split()
        if not ids:
            continue
        rc, inspect = _safe_run([runtime, 'inspect'] + ids, timeout=30)
        try:
            out[key] = json.loads(inspect) if inspect else []
        except json.JSONDecodeError:
            out[key] = [{'_error': 'inspect parse failed'}]
    return out


def iac_collect_repos():
    """Category 10: custom apt/dnf repos."""
    repos = {}
    # apt
    apt_dir = Path('/etc/apt/sources.list.d')
    apt_main = Path('/etc/apt/sources.list')
    if apt_main.exists():
        repos['/etc/apt/sources.list'] = _safe_read(str(apt_main), 50_000)
    if apt_dir.is_dir():
        for f in apt_dir.glob('*.list'):
            repos[str(f)] = _safe_read(str(f), 50_000)
        for f in apt_dir.glob('*.sources'):
            repos[str(f)] = _safe_read(str(f), 50_000)
    # dnf/yum
    yum_dir = Path('/etc/yum.repos.d')
    if yum_dir.is_dir():
        for f in yum_dir.glob('*.repo'):
            repos[str(f)] = _safe_read(str(f), 50_000)
    return {'repos': repos}


def iac_collect_firewall():
    """Category 11: firewall configuration (ufw, iptables, firewalld, nftables)."""
    out = {}
    if shutil.which('ufw'):
        rc, status = _safe_run(['ufw', 'status', 'verbose'])
        if rc == 0: out['ufw'] = status
    if shutil.which('firewall-cmd'):
        rc, info = _safe_run(['firewall-cmd', '--list-all-zones'])
        if rc == 0: out['firewalld'] = info
    if shutil.which('nft'):
        rc, info = _safe_run(['nft', 'list', 'ruleset'])
        if rc == 0: out['nftables'] = info
    if shutil.which('iptables-save'):
        rc, info = _safe_run(['iptables-save'])
        if rc == 0: out['iptables'] = info
    return {'firewall': out}


def iac_collect_cron():
    """Category 12: cron jobs across the system."""
    crons = {}
    # system crontab
    if Path('/etc/crontab').exists():
        crons['/etc/crontab'] = _safe_read('/etc/crontab', 50_000)
    # /etc/cron.d
    cron_d = Path('/etc/cron.d')
    if cron_d.is_dir():
        for f in cron_d.iterdir():
            if f.is_file():
                crons[str(f)] = _safe_read(str(f), 50_000)
    # user crontabs (root + uid≥1000)
    user_crons = {}
    rc, root_c = _safe_run(['crontab', '-u', 'root', '-l'])
    if rc == 0 and root_c.strip(): user_crons['root'] = root_c
    for line in _safe_read('/etc/passwd').splitlines():
        parts = line.split(':')
        if len(parts) >= 3:
            try:
                if int(parts[2]) >= 1000 and parts[2] != '65534':
                    rc, ct = _safe_run(['crontab', '-u', parts[0], '-l'])
                    if rc == 0 and ct.strip():
                        user_crons[parts[0]] = ct
            except ValueError: pass
    return {'system_cron_files': crons, 'user_crontabs': user_crons}


def iac_collect_tls():
    """Category 13: TLS certificate FILE PATHS only (no contents)."""
    paths = []
    for d in ('/etc/ssl/certs', '/etc/ssl/private', '/etc/letsencrypt/live',
              '/etc/pki/tls/certs', '/etc/nginx/ssl', '/etc/apache2/ssl'):
        p = Path(d)
        if p.is_dir():
            for f in p.rglob('*'):
                if f.is_file() and f.suffix in ('.crt', '.pem', '.cert', '.key'):
                    paths.append(str(f))
    return {'tls_cert_paths': sorted(set(paths))[:200]}


def iac_collect_env():
    """Category 14: /etc/environment + /etc/profile.d snippets."""
    out = {}
    if Path('/etc/environment').exists():
        out['/etc/environment'] = _safe_read('/etc/environment', 10_000)
    pd = Path('/etc/profile.d')
    if pd.is_dir():
        for f in pd.glob('*.sh'):
            content = _safe_read(str(f), 10_000)
            if content.strip():
                out[str(f)] = content
    return {'environment_files': out}


def iac_collect_snaps():
    """Category 15: installed snap packages (Ubuntu)."""
    if not shutil.which('snap'):
        return {'snaps': []}
    rc, out = _safe_run(['snap', 'list'])
    snaps = []
    for line in out.splitlines()[1:]:    # skip header
        parts = line.split()
        if len(parts) >= 3:
            snaps.append({'name': parts[0], 'version': parts[1], 'rev': parts[2]})
    return {'snaps': snaps}


def iac_collect_kmod():
    """Category 16: persistent kernel modules (modules-load.d, modprobe.d)."""
    out = {}
    for d in ('/etc/modules-load.d', '/etc/modprobe.d', '/usr/lib/modules-load.d'):
        p = Path(d)
        if p.is_dir():
            for f in p.glob('*.conf'):
                content = _safe_read(str(f), 20_000)
                if content.strip():
                    out[str(f)] = content
    if Path('/etc/modules').exists():
        out['/etc/modules'] = _safe_read('/etc/modules', 10_000)
    return {'kernel_module_config': out}


def iac_collect_sysctl():
    """Category 17: non-default sysctl parameters from /etc/sysctl.d/* and /etc/sysctl.conf."""
    out = {}
    if Path('/etc/sysctl.conf').exists():
        out['/etc/sysctl.conf'] = _safe_read('/etc/sysctl.conf', 50_000)
    for d in ('/etc/sysctl.d', '/usr/lib/sysctl.d', '/run/sysctl.d'):
        p = Path(d)
        if p.is_dir():
            for f in p.glob('*.conf'):
                content = _safe_read(str(f), 50_000)
                if content.strip():
                    out[str(f)] = content
    return {'sysctl_files': out}


# Category 18 is server-side only (RemotePower-specific metadata)

IAC_COLLECTORS = {
    'os_identity':  iac_collect_os_identity,
    'packages':     iac_collect_packages,
    'systemd':      iac_collect_systemd,
    'users':        iac_collect_users,
    'groups':       iac_collect_groups,
    'ssh_keys':     iac_collect_ssh_keys,
    'network':      iac_collect_network,
    'fstab':        iac_collect_fstab,
    'containers':   iac_collect_containers,
    'repos':        iac_collect_repos,
    'firewall':     iac_collect_firewall,
    'cron':         iac_collect_cron,
    'tls':          iac_collect_tls,
    'env':          iac_collect_env,
    'snaps':        iac_collect_snaps,
    'kmod':         iac_collect_kmod,
    'sysctl':       iac_collect_sysctl,
}


def run_iac_collection(category_keys):
    """Run the requested IaC collectors and return a dict of {key: data}.

    Each collector is wrapped to never raise — errors land in
    `_collection_error` so the LLM can be told a category is missing rather
    than the whole generation failing.
    """
    result = {}
    for key in category_keys:
        fn = IAC_COLLECTORS.get(key)
        if not fn:
            result[key] = {'_collection_error': f'unknown category: {key}'}
            continue
        try:
            result[key] = fn()
        except Exception as e:
            result[key] = {'_collection_error': str(e)}
    return result



if __name__ == '__main__':
    main()

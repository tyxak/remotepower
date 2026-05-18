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
from pathlib import Path
from urllib import request, error

CONF_DIR     = Path('/etc/remotepower')
CREDS_FILE   = CONF_DIR / 'credentials'
PKG_HASH_FILE = CONF_DIR / 'pkg_hash'
LOG_FILE     = '/var/log/remotepower-agent.log'
VERSION      = '2.4.13'
AGENT_BINARY = Path('/usr/local/bin/remotepower-agent')

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
LOG_SUBMIT_EVERY    = 5           # every 5 polls — batches a few minutes of logs
MAX_LOG_LINES_PER_UNIT = 100      # matches server-side cap
LOG_LOOKBACK_SECONDS   = 360      # capture the last 6 minutes on each submission

# v1.11.0: container/pod listing — sent every 5 polls (~5 minutes at default
# 60s interval). Cheap when no runtime is installed (immediate empty return);
# bounded to ~1s when Docker/Podman/k8s are present.
CONTAINER_CHECK_EVERY = 5

# Metrics collection requires psutil (optional - gracefully skipped if absent)
try:
    import psutil as _psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE) if os.geteuid() == 0 else logging.NullHandler(),
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

def save_credentials(creds):
    CONF_DIR.mkdir(parents=True, exist_ok=True)
    CREDS_FILE.write_text(json.dumps(creds, indent=2))
    CREDS_FILE.chmod(0o600)
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

def get_patch_info():
    result = {'manager': 'unknown', 'upgradable': None}
    if Path('/usr/bin/apt-get').exists():
        result['manager'] = 'apt'
        try:
            out = subprocess.check_output(['apt-get', '--simulate', '--quiet', 'upgrade'],
                text=True, timeout=30, stderr=subprocess.DEVNULL)
            result['upgradable'] = sum(1 for l in out.splitlines() if l.startswith('Inst '))
        except Exception: pass
    elif Path('/usr/bin/dnf').exists() or Path('/usr/bin/dnf5').exists():
        result['manager'] = 'dnf'
        try:
            out = subprocess.check_output(['dnf', 'check-update', '--quiet'],
                text=True, timeout=30, stderr=subprocess.DEVNULL)
            result['upgradable'] = sum(1 for l in out.splitlines() if l and not l.startswith(' ') and not l.startswith('Last'))
        except subprocess.CalledProcessError as e:
            if e.returncode == 100 and e.output:
                result['upgradable'] = sum(1 for l in e.output.splitlines() if l and not l.startswith(' ') and not l.startswith('Last'))
        except Exception: pass
    elif Path('/usr/bin/pacman').exists():
        result['manager'] = 'pacman'
        try:
            subprocess.check_call(['pacman', '-Sy', '--noconfirm', '--noprogressbar'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
            out = subprocess.check_output(['pacman', '-Qu'], text=True, timeout=10, stderr=subprocess.DEVNULL)
            result['upgradable'] = len(out.strip().splitlines())
        except subprocess.CalledProcessError: result['upgradable'] = 0
        except Exception: pass
    return result


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
    """Return path to ``prog`` if it's executable on PATH, else None."""
    for d in os.environ.get('PATH', '/usr/bin:/bin:/usr/local/bin').split(':'):
        full = os.path.join(d, prog)
        if os.path.isfile(full) and os.access(full, os.X_OK):
            return full
    return None


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

    items = []
    now = int(time.time())
    for line in out.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        # Image splits as 'nginx:1.25-alpine' or 'nginx' (no tag = latest)
        image_full = d.get('Image', '')
        if ':' in image_full and '/' not in image_full.rsplit(':', 1)[1]:
            image, tag = image_full.rsplit(':', 1)
        else:
            image, tag = image_full, ''
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
        items.append({
            'name':           name,
            'image':          image,
            'tag':            tag,
            'status':         status,
            'health':         health,                       # v2.2.6
            'namespace':      '',
            'runtime':        runtime_name,
            'ports':          ports,
            'started_at':     0,
            'uptime_seconds': 0,
            'restart_count':  0,
            'cpu_percent':    st.get('cpu_percent'),         # v2.2.6
            'mem_percent':    st.get('mem_percent'),         # v2.2.6
            'mem_usage':      st.get('mem_usage', ''),       # v2.2.6
        })
        if len(items) >= CONTAINERS_HARD_CAP:
            break
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


def submit_unit_logs(creds, units):
    """
    Collect recent logs for each watched unit and submit to /api/logs.
    Server applies log_watch pattern matching and rolling-buffer storage.

    v1.8.2 fix: always include every watched unit (with empty list if quiet) and
    always POST, even if every unit is quiet.

    v1.8.3: submission activity logged at INFO level so ops can verify
    from `journalctl -u remotepower-agent` that logs are actually flowing.
    """
    if not units:
        return False
    units_payload = {}
    for unit in units[:50]:
        lines = get_unit_logs(unit)
        # Always include — empty list means "watched but quiet in this window".
        units_payload[unit] = lines or []
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
    # `ss -tulnH` — TCP+UDP, listening only, numeric, no header. The
    # process column needs root for full detail; without it we still
    # get proto+port which is the useful part.
    try:
        if _which('ss'):
            r = subprocess.run(['ss', '-tulnH'], capture_output=True,
                               text=True, timeout=5)
            if r.returncode == 0:
                ports = []
                seen = set()
                for ln in r.stdout.splitlines():
                    parts = ln.split()
                    if len(parts) < 5:
                        continue
                    proto = parts[0]
                    local = parts[4]      # e.g. 0.0.0.0:22  or  [::]:443
                    # Port is whatever follows the last ':'
                    if ':' not in local:
                        continue
                    port = local.rsplit(':', 1)[1]
                    if not port.isdigit():
                        continue
                    key = (proto, port)
                    if key in seen:
                        continue
                    seen.add(key)
                    # Process name, if ss could see it (root)
                    proc = ''
                    if 'users:' in ln:
                        m = re.search(r'\(\("([^"]+)"', ln)
                        if m:
                            proc = m.group(1)
                    ports.append({'proto': proto, 'port': int(port),
                                  'process': proc})
                ports.sort(key=lambda p: p['port'])
                out['listening_ports'] = ports[:80]
    except Exception:
        pass

    # ── last boot time ───────────────────────────────────────────────
    try:
        with open('/proc/uptime') as fh:
            up = float(fh.read().split()[0])
        out['last_boot'] = int(time.time() - up)
    except Exception:
        pass

    return out


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

    # Per-mount usage. Filter to "interesting" filesystems: skip
    # tmpfs, devtmpfs, squashfs (snap mounts), overlay (containers).
    # Include ext*, xfs, btrfs, zfs, nfs — anything you'd actually want
    # disk-fill alerts for.
    skip_fstypes = {'tmpfs', 'devtmpfs', 'squashfs', 'overlay', 'overlayfs',
                    'fuse.gvfsd-fuse', 'autofs', 'proc', 'sysfs', 'cgroup',
                    'cgroup2', 'devpts', 'mqueue', 'debugfs', 'tracefs',
                    'pstore', 'bpf', 'configfs', 'fusectl', 'hugetlbfs',
                    'binfmt_misc', 'rpc_pipefs'}
    mounts = []
    try:
        for part in _psutil.disk_partitions(all=False):
            if part.fstype in skip_fstypes:
                continue
            # Skip snap mounts even if fstype isn't squashfs (rare edge case).
            if part.mountpoint.startswith('/snap/') or part.mountpoint.startswith('/var/lib/snapd'):
                continue
            try:
                u = _psutil.disk_usage(part.mountpoint)
            except (PermissionError, OSError):
                continue
            mounts.append({
                'path':     part.mountpoint,
                'percent':  round(u.percent, 1),
                'used_gb':  round(u.used / (1024**3), 2),
                'total_gb': round(u.total / (1024**3), 2),
                'fstype':   part.fstype,
            })
    except Exception:
        pass
    # Sanity cap: if a host somehow has thousands of mounts (NFS automount
    # going wild), don't dump them all into every heartbeat.
    out['mounts'] = mounts[:50]

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
    log.info(f"Update available: {VERSION} → {remote_version}. Downloading…")
    try:
        data = http_get_binary(f"{server_url}/agent/remotepower-agent", timeout=30)
    except Exception as e:
        log.error(f"Download failed: {e}"); return False
    import hmac as _hmac
    actual_sha = hashlib.sha256(data).hexdigest()
    if not _hmac.compare_digest(actual_sha.lower(), remote_sha256.lower()):
        log.error(f"SHA-256 mismatch: got {actual_sha}, expected {remote_sha256}"); return False
    try:
        fd, tmp_path = tempfile.mkstemp(dir=AGENT_BINARY.parent, prefix='.rp-update-')
        try: os.write(fd, data)
        finally: os.close(fd)
        os.chmod(tmp_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
        shutil.move(tmp_path, str(AGENT_BINARY))
        log.info(f"Agent updated to {remote_version}. Restarting service…")
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
        server_url = 'https://' + server_url.lstrip('http://').lstrip('https://')

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
        server_url = 'https://' + server_url.lstrip('http://').lstrip('https://')
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

# ─── Command execution ──────────────────────────────────────────────────────────
def execute_command(cmd):
    if cmd == 'shutdown':
        log.info("Executing: shutdown")
        try: subprocess.run(['systemctl', 'poweroff'], check=True)
        except Exception as e: log.error(f"Shutdown failed: {e}")
    elif cmd == 'reboot':
        log.info("Executing: reboot")
        try:
            Path('/tmp/remotepower-last-cmd').write_text('reboot')
            subprocess.run(['systemctl', 'reboot'], check=True)
        except Exception as e: log.error(f"Reboot failed: {e}")
    elif cmd == 'update':
        log.info("Executing: self-update (server-initiated)")
        creds = load_credentials()
        if creds: check_for_update(creds['server_url'])
    elif cmd.startswith('poll_interval:'):
        # Server is requesting a poll interval change
        try:
            new_interval = int(cmd.split(':', 1)[1])
            new_interval = max(10, min(3600, new_interval))
            log.info(f"Poll interval changed to {new_interval}s")
            # Signal main loop by writing to a temp file
            Path('/tmp/remotepower-poll-interval').write_text(str(new_interval))
        except Exception as e:
            log.warning(f"Failed to set poll interval: {e}")
    elif cmd.startswith('exec:'):
        shell_cmd = cmd[5:]
        log.info(f"Executing custom command: {shell_cmd!r}")
        try:
            # Parse optional timeout from exec:<timeout>:<cmd> format
            exec_timeout = 300  # default 5 min for longer tasks like apt upgrade
            result = subprocess.run(shell_cmd, shell=True, capture_output=True, text=True, timeout=exec_timeout)
            output = (result.stdout + result.stderr).strip()
            log.info(f"Command output (rc={result.returncode}): {output[:200]}")
            # v1.10.0: bump output cap to 256 KB for package-upgrade runs.
            # `apt -y upgrade` and `dnf -y upgrade` routinely produce 30-80 KB
            # of useful output; 4 KB used to truncate it mid-package and the
            # new update-logs feature would lose half the diagnostic info.
            # The server independently caps at MAX_UPDATE_LOG_BYTES.
            is_pkg_upgrade = any(needle in shell_cmd for needle in
                                 ('apt-get -y upgrade', 'dnf -y upgrade', 'pacman -Syu'))
            cap = 256 * 1024 if is_pkg_upgrade else 4096
            return {'cmd': shell_cmd, 'output': output[:cap], 'rc': result.returncode}
        except subprocess.TimeoutExpired:
            log.warning(f"Command timed out: {shell_cmd!r}")
            return {'cmd': shell_cmd, 'output': 'TIMEOUT', 'rc': -1}
        except Exception as e:
            log.error(f"Command failed: {e}")
            return {'cmd': shell_cmd, 'output': str(e), 'rc': -1}
    elif cmd.startswith('compose:'):
        # v2.1.0: compose:<action>:<dir> — server-side picks `dir` from the
        # list of projects we reported in the heartbeat. We re-validate
        # locally anyway: only directories containing a recognised compose
        # file can be acted on, and the action is one of a fixed set. No
        # shell interpolation of `dir` — it goes in argv directly to docker
        # compose, so a malicious or stale path can't inject command flags.
        return _run_compose(cmd)
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
    else:
        log.warning(f"Unknown command: {cmd!r}")
    return None


# v2.1.0: docker-compose dispatcher. Called from execute_command on
# `compose:<action>:<dir>`. Actions are constrained to a known set; the
# directory is verified to exist and contain a compose file before any
# docker invocation. Output (capped) is returned via the existing exec
# channel so the dashboard sees results the same way it does for `exec:`.
COMPOSE_ALLOWED_ACTIONS = {'up', 'down', 'restart', 'pull', 'logs'}
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

    if action == 'up':
        argv = ['docker', 'compose', 'up', '-d']
    elif action == 'down':
        argv = ['docker', 'compose', 'down']
    elif action == 'restart':
        argv = ['docker', 'compose', 'restart']
    elif action == 'pull':
        argv = ['docker', 'compose', 'pull']
    elif action == 'logs':
        argv = ['docker', 'compose', 'logs', '--no-color', '--tail=50']
    else:
        # Defensive — COMPOSE_ALLOWED_ACTIONS check above should make this
        # unreachable, but keep the branch so a future contributor adding
        # an entry to the set but forgetting the argv mapping gets a
        # sensible error.
        return {'cmd': cmd, 'output': f'no argv mapping for {action!r}', 'rc': -1}

    log.info(f"compose {action} in {p}")
    try:
        result = subprocess.run(argv, cwd=str(p), capture_output=True,
                                text=True, timeout=COMPOSE_ACTION_TIMEOUT_S)
        output = (result.stdout + result.stderr).strip()[:COMPOSE_OUT_CAP]
        log.info(f"compose {action} rc={result.returncode} "
                 f"output_len={len(output)}")
        return {'cmd': cmd, 'output': output, 'rc': result.returncode}
    except subprocess.TimeoutExpired:
        return {'cmd': cmd, 'output': 'TIMEOUT', 'rc': -1}
    except Exception as e:
        return {'cmd': cmd, 'output': f'compose {action} failed: {e}', 'rc': -1}


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

    # Detect if this is a fresh boot (first heartbeat after restart)
    boot_reason_file = Path('/tmp/remotepower-last-cmd')
    boot_reason = None
    if boot_reason_file.exists():
        try:
            boot_reason = boot_reason_file.read_text().strip()[:64]
            boot_reason_file.unlink()
        except Exception:
            pass
    interval_override_file = Path('/tmp/remotepower-poll-interval')

    # v1.11.7: stash file for cmd_output that couldn't be POSTed in its
    # follow-up heartbeat (network blip, server restart). The next
    # successful heartbeat picks it up and sends it through. /var/lib
    # is preferred (survives /tmp clearing on reboot, which would lose
    # the upgrade output across a reboot triggered by the upgrade
    # itself), with /tmp as a fallback for non-root deploys.
    pending_cmd_output_file = Path('/var/lib/remotepower-pending-cmd.json')
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
        # Check for dynamically updated interval
        if interval_override_file.exists():
            try:
                new_interval = int(interval_override_file.read_text().strip())
                if new_interval != interval:
                    log.info(f"Poll interval updated: {interval}s → {new_interval}s")
                    interval = new_interval
                interval_override_file.unlink()
            except Exception:
                pass

        payload = {'device_id': dev_id, 'token': token, 'ip': get_local_ip(),
                   'os': get_os_info(), 'version': VERSION}

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

        if send_sysinfo:
            sysinfo = {
                'uptime':   get_uptime(),
                'platform': platform.platform(),
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
        for r in log_watch_rules:
            if r.get('unit'):
                log_units.add(r['unit'])
        if log_units and poll_count % LOG_SUBMIT_EVERY == 0:
            try:
                submit_unit_logs(creds, sorted(log_units))
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
        choices=['run', 'enroll', 're-enroll', 'enroll-token', 'status', 'update', 'integrity'],
        help='run | enroll | re-enroll | enroll-token | status | update | integrity')
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

    creds = load_credentials()
    if not creds:
        print("Not enrolled. Starting enrollment wizard...")
        creds = enroll_interactive()

    heartbeat(creds, interval=args.interval)

if __name__ == '__main__':
    main()

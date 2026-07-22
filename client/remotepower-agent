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
import signal
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
import asyncio
from pathlib import Path
from urllib import request, error, parse as urlparse
import http.client as _http_client

CONF_DIR     = Path('/etc/remotepower')
CREDS_FILE   = CONF_DIR / 'credentials'
PKG_HASH_FILE = CONF_DIR / 'pkg_hash'
LOG_FILE     = '/var/log/remotepower-agent.log'
VERSION      = '6.3.1'
AGENT_BINARY = Path('/usr/local/bin/remotepower-agent')

# ── Containerized-agent support (v4.7.0) ─────────────────────────────────────
# When the agent runs INSIDE a container monitoring its Docker HOST, the host's
# filesystem is bind-mounted read-only under $HOST_ROOT (e.g. /host) and the host
# PID/network namespaces are shared (--pid=host --network=host). HOST_ROOT lets
# every host-fact collector read the HOST's files instead of the slim container's.
#
# IMPORTANT: this applies ONLY to host-FACT reads (os-release, /proc, /sys,
# /etc/passwd, package DBs, …). The agent's OWN files — CONF_DIR
# (/etc/remotepower, persisted via a volume), the state dir, its log and its
# binary — must NOT be remapped; they live in the container.
#
# Empty HOST_ROOT (the default) makes host_path() the identity function, so a
# native (non-container) install behaves exactly as before — zero behaviour change.
HOST_ROOT = os.environ.get('HOST_ROOT', '').rstrip('/')
# Container mode is implied by HOST_ROOT, or forced with RP_CONTAINER=1 (e.g. a
# container that genuinely only wants to report itself). Drives the package-DB
# rooting and the "don't run host scanners that would only see the container" gate.
IN_CONTAINER = bool(HOST_ROOT) or os.environ.get('RP_CONTAINER', '').lower() in ('1', 'true', 'yes')


def host_path(p):
    """Map an absolute HOST path to where it is actually readable.

    Native (HOST_ROOT unset): identity. Containerized with the host rootfs at
    HOST_ROOT: '/etc/os-release' -> '<HOST_ROOT>/etc/os-release'. Only absolute
    paths are rewritten; relative paths and already-prefixed paths pass through.
    Accepts and returns the same type-ish value (str in, str out; Path in, Path out).
    """
    if not HOST_ROOT:
        return p
    is_path = isinstance(p, Path)
    s = os.fspath(p)
    if not s.startswith('/') or s.startswith(HOST_ROOT + '/') or s == HOST_ROOT:
        return p
    mapped = HOST_ROOT + s
    return Path(mapped) if is_path else mapped


def unhost_path(p):
    """Inverse of host_path() for DISPLAY: strip the HOST_ROOT prefix so paths
    reported to the server read as the host sees them (/host/etc/x -> /etc/x).
    Identity when native."""
    if not HOST_ROOT:
        return p
    s = os.fspath(p)
    if s.startswith(HOST_ROOT + '/'):
        return s[len(HOST_ROOT):]
    return s


def host_glob(pattern):
    """glob a HOST path pattern and return DISPLAY paths (HOST_ROOT stripped).
    Read the results back through _safe_read()/host_path(), which re-apply the
    prefix. Native: a plain glob."""
    import glob as _g
    return [unhost_path(m) for m in _g.glob(host_path(pattern))]


# Point psutil at the host's procfs when containerized so process / memory /
# network stats reflect the HOST. The compose mounts host /proc at $HOST_ROOT/proc
# explicitly (a `-v /:/host` bind does NOT recurse into the /proc submount).
# Always set it explicitly (to '/proc' natively) so the path is deterministic and
# psutil is never left pointing at a stale root from an earlier import.
try:
    import psutil as _psutil_cfg
    _psutil_cfg.PROCFS_PATH = (HOST_ROOT + '/proc') if HOST_ROOT else '/proc'
except Exception:
    pass

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


# v4.11.0: audit / read-only mode. Touch /etc/remotepower/audit-mode and the
# agent becomes OBSERVE-ONLY: it keeps collecting and reporting, and read-only
# assessments (lynis / OpenSCAP / CVE — run on their own path) still run, but it
# REFUSES every server command (exec/scripts, reboot/shutdown/suspend, compose/
# container, netscan/speedtest, poll-interval, uninstall), host-config apply, and
# self-update. The flag is a LOCAL file the operator owns, so a compromised or
# hostile server can never clear it — the host cannot be modified through the
# agent, by design.
AUDIT_MODE_FILE = CONF_DIR / 'audit-mode'


def _audit_mode():
    try:
        return AUDIT_MODE_FILE.exists()
    except Exception:
        return False


# v6.3.1: signed COMMAND channel — the same trust model as signed self-update,
# applied to every server-dispatched command. Touch
# /etc/remotepower/require-signed-commands and the agent REFUSES any command
# that doesn't carry a valid detached signature (release.pub key) binding the
# command text to THIS device and a fresh timestamp. What that buys: tampering
# with the server's command queue at rest (DB compromise, storage tampering)
# or replaying a captured command to another host / at a later time no longer
# executes anything — an attacker needs the signing key, not just DB write
# access. (A full app-server compromise still signs — same honest boundary as
# server-side release signing.) Fail-closed by design: flag set + no pinned
# key / no gpg / bad sig / stale ts → the command is refused and reported.
REQUIRE_SIGNED_CMDS_FILE = CONF_DIR / 'require-signed-commands'
CMD_SIG_MAX_AGE_S = 900     # freshness window (covers modest clock skew)


def _require_signed_commands():
    try:
        return REQUIRE_SIGNED_CMDS_FILE.exists()
    except Exception:
        return False


def _command_sig_ok(cmd, sig_text, sig_ts, device_id, now=None):
    """Verify a dispatched command's detached signature. Returns (ok, detail).
    The canonical payload MUST byte-match the server's _sign_command_for_agent:
    'rp-cmd\\nv1\\n{device_id}\\n{ts}\\n{cmd}'."""
    pubkey = _release_pubkey()
    if not pubkey:
        return False, 'no release.pub pinned'
    if not sig_text:
        return False, 'command is unsigned'
    try:
        ts = int(sig_ts)
    except (TypeError, ValueError):
        return False, 'missing/invalid signature timestamp'
    now = int(now if now is not None else time.time())
    if abs(now - ts) > CMD_SIG_MAX_AGE_S:
        return False, 'signature timestamp outside the freshness window'
    payload = f'rp-cmd\nv1\n{device_id}\n{ts}\n{cmd}'.encode()
    return _verify_detached_sig(payload, str(sig_text), pubkey)


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

# W3-37: cheap per-poll change detector for near-real-time drift. Remembers each
# watched file's (mtime, size); a difference on any file returns True so the
# heartbeat re-hashes now instead of waiting the full DRIFT_EVERY cadence.
_drift_mtime_cache = {}


def _watched_files_changed(watched_files):
    changed = False
    seen = set()
    for f in (watched_files or [])[:MAX_DRIFT_FILES]:
        p = f.get('path') if isinstance(f, dict) else f
        if not p:
            continue
        seen.add(p)
        try:
            st = os.stat(host_path(p))
            sig = (int(st.st_mtime), st.st_size)
        except OSError:
            sig = None
        if _drift_mtime_cache.get(p) != sig:
            # First observation seeds the cache silently (no spurious "change").
            if p in _drift_mtime_cache:
                changed = True
            _drift_mtime_cache[p] = sig
    # forget files no longer watched
    for gone in [k for k in _drift_mtime_cache if k not in seen]:
        _drift_mtime_cache.pop(gone, None)
    return changed

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
# v6.1.2: `docker system df` walks the layer store (and `-v` every volume), so
# it gets its own slow cadence — ~1h at the 60s default poll. Disk footprint
# does not change by the minute, and this is not worth paying for on every beat.
DOCKER_DF_EVERY       = 60
# v3.0.1: scan ~/.acme.sh once an hour by default. Cert state changes only
# when acme.sh's own cron runs (typically once daily) or after a manual
# action — no need to re-walk the directory every minute.
ACME_CHECK_EVERY = 60

# Metrics collection requires psutil (optional - gracefully skipped if absent)
try:
    import psutil as _psutil
    _PSUTIL = True
    # Prime the non-blocking CPU sampler once at import so the first heartbeat's
    # cpu_percent(interval=None) measures against a real baseline instead of
    # returning 0.0 — and we never pay a blocking 0.5s sample on the hot path.
    try:
        _psutil.cpu_percent(interval=None)
    except Exception:
        pass
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
    """Return a strict SSL context - certificate verification always on.

    v3.14.0: RP_CA_BUNDLE (path to a CA cert/bundle) lets the agent trust an
    internal CA — e.g. a self-hosted server or a TLS satellite with a private
    cert — WITHOUT weakening verification (CERT_REQUIRED + hostname check stay
    on). Prefer adding the CA to the OS trust store; this is the no-root-needed
    alternative.

    v4.5.0: if RP_CA_BUNDLE is unset, fall back to the conventional path the
    installer drops the self-signed CA at (/etc/remotepower/ca.crt), so a bare
    `remotepower-agent run` trusts it even without the systemd EnvironmentFile.
    Public-CA / Let's Encrypt servers are unaffected (no file there)."""
    ctx = _ssl.create_default_context()
    ctx.verify_mode = _ssl.CERT_REQUIRED
    ctx.check_hostname = True
    # v4.1.0: refuse obsolete TLS 1.0/1.1 on the agent→server/satellite hop.
    ctx.minimum_version = _ssl.TLSVersion.TLSv1_2
    _ca = os.environ.get('RP_CA_BUNDLE', '').strip()
    if not _ca and os.path.exists('/etc/remotepower/ca.crt'):
        _ca = '/etc/remotepower/ca.crt'
    if _ca and os.path.exists(_ca):
        try:
            ctx.load_verify_locations(cafile=_ca)
        except Exception as _e:
            log.warning(f'RP_CA_BUNDLE load failed ({_ca}): {_e}')
    # v5.0.0 (#C1): present a client certificate for mutual TLS when the server
    # enforces require_agent_mtls. RP_CLIENT_CERT (and RP_CLIENT_KEY, or a combined
    # PEM) are operator-provisioned from the same CA. Absent → unchanged (the
    # server only demands a cert when mTLS is on).
    _cc = os.environ.get('RP_CLIENT_CERT', '').strip()
    _ck = os.environ.get('RP_CLIENT_KEY', '').strip()
    if _cc and os.path.exists(_cc):
        try:
            ctx.load_cert_chain(certfile=_cc, keyfile=(_ck or None))
        except Exception as _e:
            log.warning(f'RP_CLIENT_CERT load failed ({_cc}): {_e}')
    return ctx

_SSL_CTX = _make_ssl_context()

# No-redirect opener: the agent posts its device token + full host telemetry to the
# server. A 3xx from the server (open-redirect, misconfig, or a downgrade to http://)
# must NOT be followed — 307/308 would replay the credential-bearing POST body to the
# redirect host, and an https→http hop would leak the token in cleartext. We refuse
# every redirect (urlopen then raises HTTPError on any 3xx). Mirrors the server-side
# no-redirect hardening on its own outbound calls (Proxmox / AI provider).
class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None

_OPENER = request.build_opener(_NoRedirect, request.HTTPSHandler(context=_SSL_CTX))

# v6.1.1 (#1): OPTIONAL push-channel listener. Same "try/except ImportError,
# feature just doesn't activate" pattern this file already uses for psutil --
# NOT hand-rolled WebSocket framing in the core agent. This is a deliberate
# choice: the agent runs as root on every managed host, so a subtly-wrong
# hand-written binary-protocol parser here is a much worse place to carry
# that risk than depending on the same well-tested `websockets` library the
# server's companion push daemon (server/push/remotepower-push.py) already
# uses. Absent the library, or on ANY connection/protocol error, the agent
# behaves EXACTLY as it always has -- this channel only ever shortens the
# wait before the next already-scheduled poll, never replaces it.
try:
    import websockets
    _PUSH_AVAILABLE = True
except ImportError:
    _PUSH_AVAILABLE = False


def _ws_header_kwarg():
    """websockets >=14 takes `additional_headers`; <=13 takes `extra_headers`.

    CRITICAL: a try(additional_headers)/except TypeError(extra_headers) fallback
    does NOT work on the older library. On websockets 10.x `connect()` STORES
    unknown kwargs and only raises the TypeError when the connection is AWAITED
    (inside `async with`), not at the `connect()` call — so the call-time except
    never fires, the fallback is dead, and every push connect dies silently in
    the outer handler (reproduced live against websockets 10.4 on Debian). Pick
    the correct kwarg name up front from the signature instead."""
    try:
        import inspect
        if 'additional_headers' in inspect.signature(websockets.connect).parameters:
            return 'additional_headers'
    except (ValueError, TypeError, AttributeError):
        pass
    return 'extra_headers'


_WS_HEADER_KW = _ws_header_kwarg() if _PUSH_AVAILABLE else 'extra_headers'


def _push_listener_thread(server_url, dev_id, token, wake_event, stop_event):
    """Runs in a background daemon thread for the agent's whole lifetime
    once started. Maintains (and silently reconnects) a WebSocket to the
    push daemon; sets wake_event on every 'wake' nudge so the main poll
    loop can cut its sleep short. Never raises out of this function --
    every failure just means "no early wake this cycle," identical to the
    push channel never having been installed at all."""
    if not _PUSH_AVAILABLE:
        return
    host_and_path = _strip_url_scheme(server_url)
    # v6.1.2: derive the WS scheme from the server URL instead of hard-coding
    # wss://. Behind a RELAY SATELLITE the agent's server_url is the satellite,
    # and a satellite on a trusted segment LAN is explicitly allowed to listen
    # over plain HTTP — against which a wss:// connect can never succeed. (For
    # a normal https:// server this is still wss://, exactly as before.) The
    # `ssl` kwarg must be None for a ws:// URL or websockets rejects the call.
    _secure = not server_url.lower().startswith('http://')
    _scheme = 'wss' if _secure else 'ws'
    url = (f'{_scheme}://{host_and_path}/api/push/connect'
           f'?device_id={urlparse.quote(dev_id, safe="")}')

    async def _run():
        backoff = 5
        while not stop_event.is_set():
            try:
                connect_kwargs = dict(ping_interval=20, ping_timeout=20,
                                      ssl=(_SSL_CTX if _secure else None),
                                      open_timeout=10)
                # Use the header kwarg this websockets version actually accepts
                # (see _ws_header_kwarg — the old try/except-at-call-time was
                # broken on websockets 10.x, where the TypeError only fires when
                # the connection is awaited).
                connect_kwargs[_WS_HEADER_KW] = {'X-RP-Push-Token': token}
                async with websockets.connect(url, **connect_kwargs) as ws:
                    backoff = 5   # reset once a connection actually succeeds
                    async for raw in ws:
                        if stop_event.is_set():
                            break
                        try:
                            msg = json.loads(raw)
                        except (TypeError, ValueError):
                            continue
                        if isinstance(msg, dict) and msg.get('type') == 'wake':
                            wake_event.set()
            except Exception as e:
                log.debug(f'push listener: {type(e).__name__}: {e}')
            if stop_event.is_set():
                return
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 60)

    try:
        asyncio.run(_run())
    except Exception as e:
        log.debug(f'push listener thread exiting: {e}')


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
# v6.2.2: persistent HTTPS connections (keep-alive) for the POST hot path.
# The agent used to open a fresh TCP + TLS handshake for EVERY heartbeat —
# one full handshake per host per poll, fleet-wide. A per-thread
# http.client.HTTPSConnection (same _SSL_CTX: CA bundle + mTLS client cert)
# reuses the connection across beats. Deliberate properties:
#   * http.client NEVER follows redirects, so the _NoRedirect guarantee is
#     preserved by construction; any 3xx (and 4xx/5xx, mirroring urlopen)
#     raises error.HTTPError exactly like the legacy opener did.
#   * The hash-commit protocol above (delta sysinfo) and every caller see
#     identical semantics — only the transport changed.
#   * A stale kept-alive socket (server closed it between beats) gets ONE
#     retry on a fresh connection; a fresh-connection failure propagates.
#   * Proxied environments (urllib's ProxyHandler honours HTTPS_PROXY; a raw
#     HTTPSConnection would silently bypass the proxy) and RP_NO_KEEPALIVE=1
#     fall back to the legacy per-request opener.
#   * Per-THREAD connections (threading.local) — http.client connections are
#     not thread-safe, and the agent posts from more than one thread.
_KA_LOCAL = threading.local()


def _ka_proxied(url):
    """True when an environment proxy applies to this URL's host — those
    requests must keep going through _OPENER (its ProxyHandler)."""
    try:
        if not request.getproxies().get('https'):
            return False
        host = urlparse.urlsplit(url).hostname or ''
        return not request.proxy_bypass(host)
    except Exception:
        return True   # can't tell → take the safe legacy path


def _ka_drop():
    conn = getattr(_KA_LOCAL, 'conn', None)
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass
    _KA_LOCAL.conn = None
    _KA_LOCAL.host = None


def _ka_request(url, body, headers, timeout):
    """POST over the per-thread persistent connection. Returns the raw body
    bytes of a 2xx; raises error.HTTPError for any >=300 (no redirects,
    matching _NoRedirect + urlopen semantics)."""
    parts = urlparse.urlsplit(url)
    host = parts.netloc
    path = parts.path + (('?' + parts.query) if parts.query else '')
    for attempt in (0, 1):
        conn = getattr(_KA_LOCAL, 'conn', None)
        reused = conn is not None and getattr(_KA_LOCAL, 'host', None) == host
        if not reused:
            _ka_drop()
            conn = _http_client.HTTPSConnection(host, timeout=timeout,
                                                context=_SSL_CTX)
            _KA_LOCAL.conn = conn
            _KA_LOCAL.host = host
        else:
            conn.timeout = timeout
            if conn.sock is not None:
                conn.sock.settimeout(timeout)
        try:
            conn.request('POST', path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read(1024 * 1024)   # cap at 1 MB (as before)
        except (_http_client.HTTPException, OSError):
            _ka_drop()
            if reused and attempt == 0:
                continue   # stale keep-alive socket — one fresh-connection retry
            raise
        if not resp.isclosed():
            _ka_drop()   # body exceeded the cap — never reuse a dirty connection
        if resp.status >= 300:
            _ka_drop()
            import io as _io
            raise error.HTTPError(url, resp.status, resp.reason,
                                  resp.headers, _io.BytesIO(data))
        return data
    raise error.URLError('keep-alive retry exhausted')   # unreachable


def http_post(url, data, timeout=10):
    if not url.startswith('https://'):
        raise ValueError(f"Server URL must use HTTPS, got: {url[:32]}")
    body = json.dumps(data).encode()
    headers = {'Content-Type': 'application/json',
               'User-Agent': f'RemotePower-Agent/{VERSION}'}
    if os.environ.get('RP_NO_KEEPALIVE') == '1' or _ka_proxied(url):
        req = request.Request(url, data=body, headers=headers)
        with _OPENER.open(req, timeout=timeout) as resp:
            return json.loads(resp.read(1024 * 1024))  # cap at 1 MB
    return json.loads(_ka_request(url, body, headers, timeout))

def http_get(url, timeout=10):
    if not url.startswith('https://'):
        raise ValueError(f"Server URL must use HTTPS, got: {url[:32]}")
    req = request.Request(url, headers={'User-Agent': f'RemotePower-Agent/{VERSION}'})
    with _OPENER.open(req, timeout=timeout) as resp:
        return json.loads(resp.read(1024 * 1024))

def http_get_binary(url, timeout=30):
    if not url.startswith('https://'):
        raise ValueError(f"Server URL must use HTTPS, got: {url[:32]}")
    req = request.Request(url, headers={'User-Agent': f'RemotePower-Agent/{VERSION}'})
    with _OPENER.open(req, timeout=timeout) as resp:
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


def _safe_state_read_big(name: str, cap: int = 1_000_000) -> str | None:
    """Like _safe_state_read but for larger state (e.g. a dir_baseline map).
    O_NOFOLLOW so a pre-placed symlink can't redirect the read."""
    for cand in (STATE_DIR / name, Path('/tmp/remotepower-' + name)):
        try:
            fd = os.open(str(cand), os.O_RDONLY | os.O_NOFOLLOW)
            try:
                return os.read(fd, cap).decode(errors='replace')
            finally:
                os.close(fd)
        except FileNotFoundError:
            continue
        except OSError:
            continue
    return None


def _parse_hex_ip(h: str):
    """Convert a /proc/net/tcp{,6} hex address (little-endian words) to a
    printable IP. Returns None on anything unexpected."""
    import ipaddress
    if len(h) == 8:            # IPv4: one 4-byte little-endian word
        return '.'.join(str(b) for b in reversed(bytes.fromhex(h)))
    if len(h) == 32:           # IPv6: four 4-byte little-endian words
        raw = b''.join(bytes.fromhex(h[i:i + 8])[::-1] for i in range(0, 32, 8))
        return str(ipaddress.ip_address(raw))
    return None


# Integrity Guard rail: more new files than this in one diff is a deploy or a
# restore, not a dropped payload — report it, never auto-quarantine it.
_GUARD_MASS_CHANGE = 25


def _guard_quarantine(paths, check_id):
    """Integrity Guard: move flagged files into the on-host quarantine vault
    (STATE_DIR/guard-quarantine, 0700). Files are PRESERVED (0600, forensics +
    restore), a JSON-lines ledger records where each came from. Best-effort and
    bounded; returns the number moved. Only ever called for NEW files the
    operator scoped, never for changed/removed ones."""
    import shutil
    vault = STATE_DIR / 'guard-quarantine'
    try:
        vault.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError:
        return 0
    moved, ledger = 0, []
    for p in paths:
        try:
            if not Path(p).is_file():
                continue
            qid = f'{int(time.time())}-{os.urandom(4).hex()}'
            dst = vault / qid
            shutil.move(str(p), str(dst))
            try:
                os.chmod(str(dst), 0o600)
            except OSError:
                pass
            meta = {'id': qid, 'orig': p, 'check': str(check_id),
                    'ts': int(time.time())}
            # Sidecar: the vault is SELF-DESCRIBING so a file stays restorable
            # even if the append-only ledger rotates. Never rely on the log for
            # the id -> original-path mapping, or trimming it orphans the file.
            try:
                with open(str(vault / (qid + '.meta')), 'w') as mf:
                    json.dump(meta, mf)
                os.chmod(str(vault / (qid + '.meta')), 0o600)
            except OSError:
                pass
            ledger.append(meta)
            moved += 1
        except OSError:
            continue
    if ledger:
        prev = _safe_state_read_big('guard-quarantine.log') or ''
        lines = [ln for ln in prev.splitlines() if ln.strip()][-500:]
        lines.extend(json.dumps(e) for e in ledger)
        _safe_state_write('guard-quarantine.log', '\n'.join(lines))
    return moved


def _guard_vault_entry(qid):
    """Read one quarantined item's sidecar metadata, or None."""
    try:
        with open(str(STATE_DIR / 'guard-quarantine' / (str(qid) + '.meta'))) as mf:
            e = json.load(mf)
        return e if isinstance(e, dict) and e.get('orig') else None
    except (OSError, ValueError):
        return None


def _guard_ledger(limit=50):
    """What is actually IN the vault right now, newest first — this drives the
    server's Protect view and therefore what can be restored.

    Reads the per-file sidecars, NOT the append-only log: the log is trimmed, so
    using it here would make an older file invisible (and un-restorable) while it
    still sits on disk.
    """
    vault = STATE_DIR / 'guard-quarantine'
    out = []
    try:
        names = sorted(p.name for p in vault.iterdir() if p.name.endswith('.meta'))
    except OSError:
        return []
    for name in names:
        qid = name[:-5]
        if not (vault / qid).exists():       # payload gone -> nothing to restore
            continue
        e = _guard_vault_entry(qid)
        if not e:
            continue
        out.append({'id': str(e.get('id', qid))[:64], 'orig': str(e.get('orig', ''))[:512],
                    'check': str(e.get('check', ''))[:64], 'ts': int(e.get('ts', 0) or 0)})
    out.sort(key=lambda x: x['ts'], reverse=True)
    return out[:limit]


def _apply_guard_actions(actions):
    """Execute server-pushed restore/delete of quarantined files. Each action is
    {id, op:'restore'|'delete'}. Restore moves the vault file back to its origin
    only if that path is now free; delete removes it. Handled entries drop from
    the ledger. Read-only over anything but the vault + the origin path."""
    import shutil
    vault = STATE_DIR / 'guard-quarantine'
    handled = set()
    for a in actions:
        if not isinstance(a, dict):
            continue
        qid, op = str(a.get('id', '')), a.get('op')
        # The sidecar is the source of truth, so a trimmed log never costs us
        # the ability to put a file back.
        e = _guard_vault_entry(qid)
        if not e:
            log.warning(f'guard {op}: no vault metadata for {qid}')
            continue
        src, meta = vault / qid, vault / (qid + '.meta')
        try:
            if op == 'delete':
                for f in (src, meta):
                    try:
                        f.unlink()
                    except FileNotFoundError:
                        pass
                handled.add(qid)
            elif op == 'restore':
                orig = e.get('orig')
                if not orig or not src.is_file():
                    log.warning(f'guard restore {qid}: vault payload missing')
                elif Path(orig).exists():
                    # Never clobber whatever now occupies the path — the operator
                    # must clear it first. Say so instead of failing silently.
                    log.warning(f'guard restore {qid}: {orig} is occupied, refusing')
                else:
                    Path(orig).parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(src), str(orig))
                    try:
                        meta.unlink()
                    except FileNotFoundError:
                        pass
                    log.info(f'guard restore {qid}: put back at {orig}')
                    handled.add(qid)
        except OSError as ex:
            log.warning(f'guard action {op} {qid} failed: {ex}')
    # The .log stays APPEND-ONLY: it is the audit trail of what was ever taken,
    # not the restore index (the sidecars are). Removing the sidecar above is
    # what drops an item out of the vault view.
    return len(handled)


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

_os_info_cache = None
def get_os_info():
    # v4.4.0 (PERF): the OS string is constant for the process lifetime, so
    # read /etc/os-release once and memoize instead of re-opening it every
    # 60s heartbeat.
    global _os_info_cache
    if _os_info_cache is not None:
        return _os_info_cache
    info = platform.system() + ' ' + platform.release()
    try:
        with open(host_path('/etc/os-release')) as f:
            for line in f:
                if line.startswith('PRETTY_NAME='):
                    info = line.split('=', 1)[1].strip().strip('"')
                    break
    except Exception:
        pass
    _os_info_cache = info
    return info

def get_mac():
    try:
        out = subprocess.check_output(['ip', 'route', 'get', '8.8.8.8'], text=True, timeout=3)
        parts = out.split()
        if 'dev' in parts:
            iface = parts[parts.index('dev') + 1]
            addr = Path(host_path(f'/sys/class/net/{iface}/address'))
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

# v3.14.0 #37: per-interface bandwidth. net_io_counters are cumulative, so we
# diff against the previous heartbeat (this daemon is long-running) to get a
# bytes/sec rate. Per-process byte accounting isn't portably available without
# root-only tooling (nethogs/eBPF), so "top talkers" here is at interface
# granularity — the busiest interface first.
_prev_net_io = {}   # iface -> (bytes_sent, bytes_recv, monotonic_ts)

def collect_net_io():
    if not _PSUTIL:
        return []
    out = []
    try:
        counters = _psutil.net_io_counters(pernic=True)
    except Exception:
        return out
    now = time.monotonic()
    for iface, c in counters.items():
        if iface == 'lo' or iface.startswith(('veth', 'docker', 'br-', 'virbr',
                                              'tap', 'tun', 'cni', 'flannel')):
            continue
        prev = _prev_net_io.get(iface)
        _prev_net_io[iface] = (c.bytes_sent, c.bytes_recv, now)
        if not prev:
            continue            # first sample for this iface — need two to rate
        dt = now - prev[2]
        if dt <= 0:
            continue
        rx = max(0, c.bytes_recv - prev[1]) / dt
        tx = max(0, c.bytes_sent - prev[0]) / dt
        out.append({'iface': iface, 'rx_bps': round(rx), 'tx_bps': round(tx),
                    'rx_total': c.bytes_recv, 'tx_total': c.bytes_sent,
                    'rx_err': getattr(c, 'errin', 0), 'tx_err': getattr(c, 'errout', 0),
                    'rx_drop': getattr(c, 'dropin', 0), 'tx_drop': getattr(c, 'dropout', 0)})
    out.sort(key=lambda x: x['rx_bps'] + x['tx_bps'], reverse=True)
    return out[:20]

# W3-38: canary / honeytoken files. Plant a decoy at each configured path (never
# over an existing file), then watch for access: atime advancing past plant time
# (a read), or mtime/size change / deletion (tampering). Each event is reported
# once (edge-triggered via _canary_reported).
_CANARY_DEFAULT = ('# AWS credentials — do not share\n'
                   '[default]\naws_access_key_id = AKIA' + 'IOSFODNN7EXAMPLE\n'
                   'aws_secret_access_key = wJalrXUtnFEMI/EXAMPLEKEY\n')
_canary_planted = {}       # path -> {mtime, size, plant_ts}
_canary_reported = set()   # paths already reported this run


def _plant_canaries(canary_cfg):
    """Create any not-yet-planted canary files. Returns nothing; updates the
    in-memory baseline. Never overwrites an existing file."""
    for c in (canary_cfg or [])[:50]:
        p = c.get('path') if isinstance(c, dict) else c
        if not p or not str(p).startswith('/'):
            continue
        hp = host_path(p)
        if p in _canary_planted:
            continue
        try:
            if os.path.exists(hp):
                # pre-existing file — track its baseline but never clobber it
                st = os.stat(hp)
                _canary_planted[p] = {'mtime': int(st.st_mtime), 'size': st.st_size,
                                      'plant_ts': int(time.time()), 'ours': False}
                continue
            content = (c.get('content') if isinstance(c, dict) else '') or _CANARY_DEFAULT
            d = os.path.dirname(hp)
            if d and not os.path.isdir(d):
                os.makedirs(d, exist_ok=True)
            fd = os.open(hp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, content.encode())
            finally:
                os.close(fd)
            st = os.stat(hp)
            _canary_planted[p] = {'mtime': int(st.st_mtime), 'size': st.st_size,
                                  'plant_ts': int(time.time()), 'ours': True}
        except OSError as e:
            log.debug(f'canary plant {p}: {e}')


def _check_canaries(canary_cfg):
    """Return [{path, reason, ts}] for canaries that were accessed/tampered since
    plant, each reported only once."""
    events = []
    wanted = {(c.get('path') if isinstance(c, dict) else c) for c in (canary_cfg or [])}
    for p, base in list(_canary_planted.items()):
        if p not in wanted:
            continue
        if p in _canary_reported:
            continue
        hp = host_path(p)
        reason = None
        try:
            st = os.stat(hp)
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


def _remove_canaries():
    """Uninstall hook: remove only the decoys WE created (never a pre-existing
    file we merely baselined)."""
    for p, base in list(_canary_planted.items()):
        if base.get('ours'):
            try:
                os.unlink(host_path(p))
            except OSError:
                pass
    _canary_planted.clear()
    _canary_reported.clear()


CUSTOM_METRICS_DIR = '/etc/remotepower/metrics.d'   # W3-11 textfile collector dir
_CM_NAME_RE = re.compile(r'^[a-z][a-z0-9_]{0,63}$')


def collect_custom_metrics():
    """W3-11: read a Prometheus-textfile-collector-style dir — `name value`
    lines in *.prom files — into {name: float}. Bounded (32 metrics, numeric
    only, [a-z][a-z0-9_]* names). Best-effort; empty on any error."""
    out = {}
    try:
        d = host_path(CUSTOM_METRICS_DIR)
        names = sorted(os.listdir(d))[:50]
    except OSError:
        return {}
    for fn in names:
        if not fn.endswith('.prom'):
            continue
        try:
            body = _safe_read(os.path.join(d, fn), 64_000) or ''
        except Exception:
            continue
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            name = parts[0].lower()
            if not _CM_NAME_RE.match(name):
                continue
            try:
                out[name] = float(parts[1])
            except ValueError:
                continue
            if len(out) >= 32:
                return out
    return out


def _is_private_ip(ip):
    """RFC-1918 / link-local / CGNAT — the addresses worth suggesting a fleet
    dependency for (a world-bound peer is noise + a privacy leak)."""
    try:
        parts = [int(x) for x in ip.split('.')]
        if len(parts) != 4:
            return False
    except ValueError:
        return False
    a, b = parts[0], parts[1]
    return (a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)
            or (a == 169 and b == 254) or (a == 100 and 64 <= b <= 127))


def collect_peer_connections(limit=50):
    """W3-8: sample established outbound TCP peers (private IPs only) so the
    server can suggest fleet dependency edges. Best-effort + bounded; returns
    [{ip, port, count}] sorted by connection count."""
    peers = {}
    try:
        if _PSUTIL:
            for c in _psutil.net_connections(kind='tcp'):
                if c.status != 'ESTABLISHED' or not c.raddr:
                    continue
                ip = getattr(c.raddr, 'ip', '')
                port = getattr(c.raddr, 'port', 0)
                if _is_private_ip(ip):
                    peers[(ip, port)] = peers.get((ip, port), 0) + 1
        else:
            out = subprocess.check_output(
                ['ss', '-tn', 'state', 'established'],
                text=True, stderr=subprocess.DEVNULL, timeout=8)
            for line in out.splitlines()[1:]:
                cols = line.split()
                if len(cols) < 4:
                    continue
                peer = cols[-1]
                ip, _, port = peer.rpartition(':')
                ip = ip.strip('[]')
                if _is_private_ip(ip):
                    try:
                        p = int(port)
                    except ValueError:
                        continue
                    peers[(ip, p)] = peers.get((ip, p), 0) + 1
    except Exception:
        return []
    rows = [{'ip': ip, 'port': port, 'count': n} for (ip, port), n in peers.items()]
    rows.sort(key=lambda r: r['count'], reverse=True)
    return rows[:limit]


def collect_lldp_neighbors(limit=64):
    """W5-1: LLDP neighbors from `lldpctl -f keyvalue` (skips silently if lldpd
    isn't installed). Returns [{local_if, peer_name, peer_port, mgmt_ip}] so the
    server can suggest physical topology edges. Best-effort + bounded."""
    if not _which('lldpctl'):
        return []
    try:
        out = subprocess.check_output(['lldpctl', '-f', 'keyvalue'],
                                      text=True, stderr=subprocess.DEVNULL, timeout=8)
    except Exception:
        return []
    # keys look like: lldp.<localif>.chassis.name=<peer>, .port.ifname=<port>,
    # .chassis.mgmt-ip=<ip>. Group by the local interface segment.
    by_if = {}
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith('lldp.') or '=' not in line:
            continue
        key, _, val = line.partition('=')
        parts = key.split('.')
        if len(parts) < 3:
            continue
        local_if = parts[1]
        rest = '.'.join(parts[2:])
        rec = by_if.setdefault(local_if, {'local_if': local_if, 'peer_name': '',
                                          'peer_port': '', 'mgmt_ip': ''})
        if rest in ('chassis.name', 'chassis.descr') and not rec['peer_name']:
            rec['peer_name'] = val[:128]
        elif rest in ('port.ifname', 'port.descr') and not rec['peer_port']:
            rec['peer_port'] = val[:64]
        elif rest.startswith('chassis.mgmt-ip') and not rec['mgmt_ip']:
            rec['mgmt_ip'] = val[:64]
    rows = [r for r in by_if.values() if r['peer_name'] or r['mgmt_ip']]
    return rows[:limit]


# v3.14.0 #35: secrets-on-disk scanner. READ-ONLY + REDACTING by construction —
# it never transmits a secret's value, only the rule, the file:line location, a
# masked preview, and a sha256 fingerprint (so the server can dedupe/mute a
# finding without ever seeing the secret). Opt-in (the server pushes
# secrets_scan_enabled); bounded hard on files, file size, and wall-clock so it
# can never hog a host.
SECRETS_SCAN_EVERY = 360            # ~6h at the 60s default poll
IMAGE_SCAN_EVERY   = 1440           # ~24h at the 60s default poll (W6-34, legacy)

# v6.1.2: the image scan is due on a WALL-CLOCK interval, persisted across
# restarts. The old poll-count modulo (IMAGE_SCAN_EVERY, kept only so an old
# pinned reference still resolves) silently never fired on any host whose agent
# restarted more often than 24h.
IMAGE_SCAN_INTERVAL_S = 24 * 3600
IMAGE_SCAN_TS_FILE    = 'image_scan_last'

# v6.1.2: same restart-survival fix as the image scan (below) applied to the
# secrets-on-disk scan, which still used a poll_count % N cadence that reset on
# every agent restart — so a restart-churny host (agent self-update is common)
# with the feature enabled never actually scanned, and there was no manual
# trigger either. Persist the last-run epoch instead.
SECRETS_SCAN_INTERVAL_S = 6 * 3600
SECRETS_SCAN_TS_FILE    = 'secrets_scan_last'


def _load_secrets_scan_ts() -> float:
    raw = _safe_state_read(SECRETS_SCAN_TS_FILE)
    try:
        return float((raw or '').strip())
    except ValueError:
        return 0.0


def _save_secrets_scan_ts(ts: float) -> None:
    _safe_state_write(SECRETS_SCAN_TS_FILE, str(int(ts)))


# v6.2.0: host-wide disk-usage explorer ("disk 94% — of WHAT?").
# Slow + opt-in, on the same persisted-timestamp cadence as the scans above:
# walking a big filesystem is expensive, and a poll_count % N cadence would
# silently never fire on a restart-churny host.
DU_SCAN_INTERVAL_S = 12 * 3600
DU_SCAN_TS_FILE    = 'du_scan_last'
_DU_DEFAULT_PATHS  = ['/var', '/home', '/opt', '/srv', '/usr', '/tmp']
_DU_TOP_N          = 20      # per path — enough to explain a full disk


def _load_du_scan_ts() -> float:
    raw = _safe_state_read(DU_SCAN_TS_FILE)
    try:
        return float((raw or '').strip())
    except ValueError:
        return 0.0


def _save_du_scan_ts(ts: float) -> None:
    _safe_state_write(DU_SCAN_TS_FILE, str(int(ts)))


def _parse_du(out, root):
    """Parse `du -x --block-size=1 --max-depth=1` output into sorted entries.

    Pure — unit-testable without touching a filesystem. `du` prints the total
    for the root itself as the LAST line; we drop it (it's the sum, not a child)
    and return the children biggest-first.
    """
    rows = []
    for line in (out or '').splitlines():
        parts = line.split('\t', 1)
        if len(parts) != 2:
            continue
        try:
            size = int(parts[0].strip())
        except ValueError:
            continue
        path = parts[1].strip()
        if not path or path.rstrip('/') == root.rstrip('/'):
            continue            # the root's own total, not a child
        rows.append({'path': unhost_path(path), 'bytes': size})
    rows.sort(key=lambda r: r['bytes'], reverse=True)
    return rows[:_DU_TOP_N]


def collect_disk_usage(paths=None, time_budget=45.0):
    """Top space consumers per configured path — the missing half of disk-fill
    forecasting. RemotePower has always been able to say WHEN a mount fills up;
    this says WHAT to delete.

    Shells out to `du` deliberately rather than walking in Python: du is C-fast
    and already solves hardlink double-counting, sparse files and bind mounts —
    the traps a hand-rolled os.walk + st_blocks summer gets subtly wrong. The
    server's existing AI disk diagnostic already shells the same idioms.

    Bounded three ways, because this runs unattended on someone's NAS:
      * `-x`          — never cross a filesystem boundary (no walking into /proc,
                        a NFS mount, or a 40TB media array hung off /srv)
      * --max-depth=1 — one level; we want "/var/lib is 80G", not every file
      * per-path timeout + an overall wall-clock budget
    Feature-invisible when `du` is absent (returns {}), like trivy/lynis.
    """
    if not _which('du'):
        return {}
    out = {}
    started = time.time()
    for p in (paths or _DU_DEFAULT_PATHS):
        if time.time() - started > time_budget:
            break
        root = host_path(p)
        if not os.path.isdir(root):
            continue
        remaining = max(5.0, time_budget - (time.time() - started))
        try:
            r = subprocess.run(
                ['du', '-x', '--block-size=1', '--max-depth=1', root],
                capture_output=True, text=True,
                timeout=min(30.0, remaining))
        except Exception:
            continue            # timeout / permission / vanished — skip this path
        # du exits non-zero on *any* unreadable subdir but still prints the rest,
        # so a partial answer is normal and useful — parse stdout regardless.
        entries = _parse_du(r.stdout, root)
        if entries:
            out[unhost_path(root)] = entries
    return out


def _load_image_scan_ts() -> float:
    """Epoch of the last trivy image scan (0 if never / unreadable)."""
    raw = _safe_state_read(IMAGE_SCAN_TS_FILE)
    try:
        return float((raw or '').strip())
    except ValueError:
        return 0.0


def _save_image_scan_ts(ts: float) -> None:
    _safe_state_write(IMAGE_SCAN_TS_FILE, str(int(ts)))


def collect_image_cves(images, limit=20):
    """W6-34: scan container images with `trivy` (skips silently if absent).
    `images` is the set of image refs of RUNNING containers. Runs
    `trivy image` per unique image on a SLOW cadence, low priority, and ships a
    capped SUMMARY (severity counts + a few top findings) — never the full
    report. Bounded on image count + per-image wall clock. Best-effort."""
    if not _which('trivy') or not images:
        return []
    import json as _json
    out = []
    for image in sorted(set(images))[:limit]:
        if not image or len(image) > 256:
            continue
        try:
            # --quiet + explicit severities keep the JSON small; nice/ionice via
            # the argv is not portable, so rely on trivy's own light footprint.
            proc = subprocess.run(
                ['trivy', 'image', '--quiet', '--format', 'json',
                 '--severity', 'CRITICAL,HIGH,MEDIUM', '--scanners', 'vuln', image],
                capture_output=True, text=True, timeout=180)
            if proc.returncode != 0 or not proc.stdout.strip():
                continue
            data = _json.loads(proc.stdout)
        except Exception:
            continue
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0}
        top = []
        for res in (data.get('Results') or []):
            for v in (res.get('Vulnerabilities') or []):
                sev = str(v.get('Severity', '')).upper()
                if sev in counts:
                    counts[sev] += 1
                if len(top) < 25 and sev in ('CRITICAL', 'HIGH'):
                    top.append({
                        'id': str(v.get('VulnerabilityID', ''))[:40],
                        'pkg': str(v.get('PkgName', ''))[:80],
                        'severity': sev,
                        'installed': str(v.get('InstalledVersion', ''))[:40],
                        'fixed': str(v.get('FixedVersion', ''))[:40],
                    })
        out.append({'image': image[:256],
                    'critical': counts['CRITICAL'], 'high': counts['HIGH'],
                    'medium': counts['MEDIUM'], 'top': top})
    return out

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
    # Lower-confidence catch-all: secret-looking assignment in a config file.
    ('generic_secret', re.compile(r'(?i)(?:password|passwd|secret|api[_-]?key|token)\s*[=:]\s*[\'"]?([^\s\'"]{8,})')),
]
_SECRETS_SKIP_DIRS = {'.git', 'node_modules', 'vendor', '__pycache__', 'site-packages',
                      '.cache', '.venv', 'venv', 'snap', 'proc', 'sys', 'dev'}
_SECRETS_DEFAULT_PATHS = ['/etc', '/root', '/home', '/opt', '/srv', '/var/www']


def _redact_secret(s):
    """Mask a matched secret so only its shape survives: a short prefix + the
    length. NEVER returns the full value."""
    s = s.strip()
    if len(s) <= 4:
        return '****'
    if len(s) <= 8:
        return s[:2] + '*' * (len(s) - 2)
    return s[:4] + '*' * 8 + f'…({len(s)})'


def collect_secret_findings(paths=None, max_findings=200, max_file_bytes=1048576,
                            max_files=5000, time_budget=12.0):
    paths = paths or _SECRETS_DEFAULT_PATHS
    findings, seen = [], set()
    start = time.monotonic()
    visited = 0
    for base in paths:
        if not isinstance(base, str):
            continue
        hbase = host_path(base)   # read the real host rootfs when containerized
        if not os.path.exists(hbase):
            continue
        if len(findings) >= max_findings or visited >= max_files \
                or time.monotonic() - start > time_budget:
            break
        for dirpath, dirnames, filenames in os.walk(hbase):
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
                    if b'\x00' in chunk[:4096]:          # binary — skip
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
                        findings.append({'path': unhost_path(fpath)[:300], 'line': lineno,
                                         'rule': rule, 'preview': _redact_secret(val)[:48],
                                         'fingerprint': fph})
                        if len(findings) >= max_findings:
                            break
                    if len(findings) >= max_findings:
                        break
    return findings


# ── v6.2.0: PII / sensitive-data scan (GDPR/PCI "where is our regulated data?") ─
#
# Same bounded, opt-in, host_path()-aware walk as the secrets scan above. One
# rule dominates the design:
#
#   **THE SCANNER NEVER REPORTS THE MATCHED VALUE — not raw, not redacted, and
#   NOT HASHED.**
#
# A PII scanner that ships PII back to its own database is not a control, it is a
# second breach with a nicer UI. And hashing does NOT save you here: unlike an API
# key, the things this looks for are LOW-ENTROPY. There are only 10^9 possible
# US SSNs and a card number is pinned by its BIN + Luhn — a rainbow table over
# either is minutes of work, so a "fingerprint" would be a reversible copy of the
# PII wearing a disguise. So the finding carries only: WHICH FILE, WHAT KIND, HOW
# MANY, and WHICH LINES. That is everything an operator needs to go and look, and
# nothing an attacker who pops the RemotePower server can use.
PII_SCAN_INTERVAL_S = 24 * 3600      # slower than the secrets scan: it's a sweep,
PII_SCAN_TS_FILE    = 'pii_scan_last'   # not a tripwire. Persisted-epoch cadence.


def _load_pii_scan_ts() -> float:
    raw = _safe_state_read(PII_SCAN_TS_FILE)
    try:
        return float((raw or '').strip())
    except ValueError:
        return 0.0


def _save_pii_scan_ts(ts: float) -> None:
    _safe_state_write(PII_SCAN_TS_FILE, str(int(ts)))


def _luhn_ok(digits: str) -> bool:
    """Luhn checksum. Without this, EVERY 16-digit number — an order id, a
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


_PII_CARD_RX = re.compile(r'\b(?:\d[ -]?){12,18}\d\b')
_PII_RULES = [
    ('email', re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')),
    # US SSN. The excluded ranges are never issued, and they are exactly what a
    # test fixture reaches for ('123-45-6789', '000-…'), so skipping them cuts the
    # noise that would otherwise bury the real hits.
    ('ssn', re.compile(r'\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b')),
    ('iban', re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b')),
    ('phone', re.compile(r'(?<![\w.])\+\d{1,3}[ -]?\d{3}[ -]?\d{3,4}[ -]?\d{3,4}(?![\w.])')),
]
_PII_SKIP_DIRS = _SECRETS_SKIP_DIRS | {'.terraform', 'dist', 'build'}
# Deliberately NOT /etc: it is full of maintainer emails in config files, and a
# report that opens with 400 hits from /etc is a report nobody reads twice. This
# looks where an organisation's *data* lives, not where its config lives.
_PII_DEFAULT_PATHS = ['/home', '/srv', '/var/www', '/opt']


def collect_pii_findings(paths=None, max_findings=300, max_file_bytes=2097152,
                         max_files=8000, time_budget=20.0):
    """Walk `paths` and report FILES that contain PII, by kind and count.

    Never returns a matched value (see the note above). Bounded on findings,
    files visited and wall-clock — checked at every loop level, like the secrets
    scan, so a pathological tree cannot wedge the heartbeat.
    """
    paths = paths or _PII_DEFAULT_PATHS
    findings = []
    start = time.monotonic()
    visited = 0

    def _budget_spent():
        return (len(findings) >= max_findings or visited >= max_files
                or time.monotonic() - start > time_budget)

    for base in paths:
        if not isinstance(base, str):
            continue
        hbase = host_path(base)   # the real host rootfs when containerized
        if not os.path.exists(hbase) or _budget_spent():
            continue
        for dirpath, dirnames, filenames in os.walk(hbase):
            if _budget_spent():
                break
            dirnames[:] = [d for d in dirnames if d not in _PII_SKIP_DIRS]
            for fn in filenames:
                if _budget_spent():
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
                    if b'\x00' in chunk[:4096]:          # binary — skip
                        continue
                    text = chunk.decode('utf-8', 'replace')
                except Exception:
                    continue

                # Count per kind for THIS file. One row per (file, kind) — a row
                # per match would drown a customer CSV in 50,000 identical rows.
                counts: dict = {}
                lines: dict = {}
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
                    for m in _PII_CARD_RX.finditer(line):
                        digits = re.sub(r'[ -]', '', m.group(0))
                        if not _luhn_ok(digits):
                            continue          # not a card, just a long number
                        counts['credit_card'] = counts.get('credit_card', 0) + 1
                        lines.setdefault('credit_card', [])
                        if len(lines['credit_card']) < 5:
                            lines['credit_card'].append(lineno)

                for kind, n in counts.items():
                    findings.append({
                        'path':  unhost_path(fpath)[:300],
                        'kind':  kind,
                        'count': n,
                        'lines': lines.get(kind, []),
                        # NO 'preview', NO 'fingerprint'. On purpose. See above.
                    })
                    if len(findings) >= max_findings:
                        break
    return findings


def get_uptime():
    # v4.6.0: add a timeout — the bare check_output had none, so a hung `uptime`
    # (stuck utmp/NSS) could block the entire heartbeat loop indefinitely.
    try:
        return subprocess.check_output(['uptime', '-p'], text=True, timeout=5).strip()
    except Exception:
        return ''


def get_uptime_seconds():
    """v6.1.2: uptime as a NUMBER, not just the `uptime -p` prose.

    The only uptime the server ever stored was that human string ("up 3 weeks"),
    which can't be sorted or compared — so nothing could rank hosts by uptime.
    /proc/uptime is a cheap, dependency-free read. host_path() so a containerized
    agent reads the HOST's uptime, not the container's.
    """
    try:
        raw = _safe_read(host_path('/proc/uptime'), 64) or ''
        return int(float(raw.split()[0]))
    except (ValueError, IndexError, TypeError):
        return None

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

# W3-40: sudo / privileged-command audit trail. Tail sudo invocations from the
# journal (or /var/log/auth.log when journald is absent) and ship the NEW ones
# since the last report. Cursor is an epoch so we never re-send the same line.
_sudo_cursor = [0]
_SUDO_LINE_RE = re.compile(
    r'sudo(?:\[\d+\])?:\s*(?P<user>[\w.\-]+)\s*:.*?'
    r'(?:TTY=(?P<tty>[\w/\-]+))?.*?(?:PWD=(?P<pwd>\S+))?.*?'
    r'USER=(?P<target>[\w.\-]+)\s*;\s*COMMAND=(?P<cmd>.+)$')


def collect_sudo_events(limit=100):
    """Return newly-seen sudo invocations as
    [{ts, user, tty, pwd, target, command}], oldest-first, capped. Bounded +
    best-effort — any failure yields an empty list."""
    events = []
    try:
        if _which('journalctl'):
            out = subprocess.check_output(
                ['journalctl', '_COMM=sudo', '-n', '400', '--no-pager',
                 '--output=short-unix', '--no-hostname'],
                text=True, stderr=subprocess.DEVNULL, timeout=10)
            lines = out.strip().splitlines()
            parse_epoch = lambda ln: int(float(ln.split(None, 1)[0])) if ln[:1].isdigit() else 0
        else:
            raw = _safe_read(host_path('/var/log/auth.log'), 400_000) or ''
            lines = raw.splitlines()[-800:]
            parse_epoch = lambda ln: 0
    except Exception:
        return []
    last = _sudo_cursor[0]
    baseline = (last == 0)     # first run: mark seen, don't flood the server
    newest = last
    for ln in lines:
        if 'COMMAND=' not in ln:
            continue
        m = _SUDO_LINE_RE.search(ln)
        if not m:
            continue
        ts = parse_epoch(ln) or int(time.time())
        newest = max(newest, ts)
        if baseline or ts <= last:
            continue
        events.append({
            'ts': ts,
            'user': (m.group('user') or '')[:64],
            'tty': (m.group('tty') or '')[:32],
            'pwd': (m.group('pwd') or '')[:256],
            'target': (m.group('target') or '')[:64],
            'command': (m.group('cmd') or '').strip()[:512],
        })
    if newest > _sudo_cursor[0]:
        _sudo_cursor[0] = newest
    return [] if baseline else events[-limit:]


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


def _count_apt_security(simulate_out):
    """v5.0.0: count the SECURITY updates in `apt-get --simulate upgrade` output.

    Each `Inst <pkg> [old] (<new> <Archive> [<arch>])` line carries the candidate's
    source archive; Debian tags it `Debian-Security:...` and Ubuntu/derivatives use
    a `<codename>-security` suite. We count `Inst` lines whose annotation mentions
    a security archive — the vendor's own classification, no extra command."""
    n = 0
    for line in (simulate_out or '').splitlines():
        if not line.startswith('Inst '):
            continue
        low = line.lower()
        if 'security' in low:   # matches '-security' suites + 'Debian-Security'
            n += 1
    return n


def _count_dnf_security(cmd):
    """v5.0.0: count SECURITY updates via `<cmd> check-update --security`.

    dnf/yum report only the security-flagged upgradable packages here (rc 100 when
    some exist, 0 when none). Best-effort: any failure (no plugin, locked, network)
    returns None so the field reads "unknown" rather than a false 0."""
    def _count(text):
        return sum(1 for l in text.splitlines()
                   if l.strip() and not l.startswith(' ')
                   and not l.startswith(('Last', 'Obsoleting', 'Security:')))
    try:
        out = subprocess.check_output([cmd, 'check-update', '--security', '--quiet'],
                                      text=True, timeout=30, stderr=subprocess.DEVNULL)
        return _count(out)
    except subprocess.CalledProcessError as e:
        if e.returncode == 100 and e.output:
            return _count(e.output)
        return None
    except Exception:
        return None


def _count_pacman_security():
    """v5.0.0: Arch has no security pocket, but `arch-audit` (community tool) maps
    installed packages to known CVEs. If present, count its affected packages;
    otherwise None (unknown — not a false 0). One name per line, deduped."""
    if not _which('arch-audit'):
        return None
    try:
        out = subprocess.check_output(['arch-audit', '-q', '-u'],
                                      text=True, timeout=20, stderr=subprocess.DEVNULL)
        names = {l.split()[0] for l in out.splitlines() if l.strip()}
        return len(names)
    except Exception:
        return None


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
    if IN_CONTAINER:
        # Containerized: detect the HOST's package manager from its DB (not the
        # agent image's binaries) and try a rooted upgrade simulation. On any
        # failure upgradable stays None — an honest "unknown", never a false 0
        # that would read as "fully patched". dnf/pacman upgrade-rooting is
        # deliberately left unknown for v1 (documented).
        mgr, _ = _host_pkglist_from_db()
        if mgr:
            result['manager'] = mgr
        if mgr == 'apt' and shutil.which('apt-get'):
            try:
                out = subprocess.check_output(
                    ['apt-get', '-o', f'Dir={HOST_ROOT}',
                     '-o', f'Dir::State::status={HOST_ROOT}/var/lib/dpkg/status',
                     '--simulate', '--quiet', 'upgrade'],
                    text=True, timeout=45, stderr=subprocess.DEVNULL)
                result['upgradable'] = sum(1 for l in out.splitlines() if l.startswith('Inst '))
                result['upgradable_names'] = _parse_upgradable_names('apt', out)
                result['security_updates'] = _count_apt_security(out)
            except Exception:
                pass
        return result
    if Path('/usr/bin/apt-get').exists():
        result['manager'] = 'apt'
        try:
            out = subprocess.check_output(['apt-get', '--simulate', '--quiet', 'upgrade'],
                text=True, timeout=30, stderr=subprocess.DEVNULL)
            result['upgradable'] = sum(1 for l in out.splitlines() if l.startswith('Inst '))
            result['upgradable_names'] = _parse_upgradable_names('apt', out)
            # v5.0.0: how many of those are SECURITY updates. apt --simulate
            # annotates each `Inst` line with its source archive in parens, e.g.
            # `Inst libssl3 [..] (.. Debian-Security:12/stable ..)` or a
            # `<codename>-security` suite — so we count them straight from the
            # output the vendor itself flags (no extra subprocess).
            result['security_updates'] = _count_apt_security(out)
        except Exception:
            # check failed (locked dpkg, repo error): report "unknown" rather
            # than 0, so the host doesn't look fully patched when it isn't.
            result['upgradable'] = None
    elif Path('/usr/bin/dnf').exists() or Path('/usr/bin/dnf5').exists():
        result['manager'] = 'dnf'
        result['security_updates'] = _count_dnf_security('dnf')   # v5.0.0
        try:
            out = subprocess.check_output(['dnf', 'check-update', '--quiet'],
                text=True, timeout=30, stderr=subprocess.DEVNULL)
            result['upgradable'] = sum(1 for l in out.splitlines() if l and not l.startswith(' ') and not l.startswith('Last'))
            result['upgradable_names'] = _parse_upgradable_names('dnf', out)
        except subprocess.CalledProcessError as e:
            if e.returncode == 100 and e.output:
                result['upgradable'] = sum(1 for l in e.output.splitlines() if l and not l.startswith(' ') and not l.startswith('Last'))
                result['upgradable_names'] = _parse_upgradable_names('dnf', e.output)
        except Exception:
            result['upgradable'] = None  # check failed -> "unknown", not "0"
    # v3.0.1: yum (RHEL 7, older CentOS) — same rpm-based ecosystem as dnf.
    # Report manager='dnf' so the OSV ecosystem detection (Rocky/Alma/Red Hat)
    # and CVE scanning paths Just Work — only the status check differs.
    elif Path('/usr/bin/yum').exists():
        result['manager'] = 'dnf'
        result['security_updates'] = _count_dnf_security('yum')   # v5.0.0
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
        except Exception:
            result['upgradable'] = None  # check failed -> "unknown", not "0"
    elif Path('/usr/bin/pacman').exists():
        result['manager'] = 'pacman'
        result['security_updates'] = _count_pacman_security()   # v5.0.0 (arch-audit)
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

# ─── v4.2.0 (B5 P3): agent-side host scan (lynis) ─────────────────────────────
# Triggered by `host_scan` in the heartbeat response; runs lynis read-only in a
# daemon thread and drops a result into the outbox, which the heartbeat loop
# attaches to the next request body as `host_scan_result`.
_host_scan_running = threading.Lock()
_HOST_SCAN_OUTBOX = []


def _parse_lynis_report(path):
    """Parse a lynis report-file (warning[]= / suggestion[]= lines) into the
    RemotePower finding shape. Warnings → medium, suggestions → low.
    Returns (findings, hardening_index) — the 0–100 host-hardening score lynis
    writes into the same report (sweep: it used to be discarded at parse time)."""
    findings = []
    hardening = None
    try:
        with open(path, 'r', errors='replace') as f:
            lines = f.read().splitlines()
    except Exception:
        return findings, hardening
    for ln in lines:
        if ln.startswith('hardening_index='):
            try:
                hardening = max(0, min(100, int(ln.split('=', 1)[1].strip())))
            except ValueError:
                pass
            continue
        if ln.startswith('warning[]=') or ln.startswith('suggestion[]='):
            kind = 'warning' if ln.startswith('warning[]=') else 'suggestion'
            parts = ln.split('=', 1)[1].split('|')
            test_id = parts[0] if parts else ''
            desc = parts[1] if len(parts) > 1 and parts[1] else test_id
            findings.append({
                'rule_id': test_id[:200], 'title': desc[:300],
                'severity': 'medium' if kind == 'warning' else 'low',
                'evidence': kind, 'reference': '',
            })
    return findings[:1000], hardening


def run_host_scan(job):
    """Run an on-host posture audit (lynis) and return a heartbeat result dict:
    {id, status, findings, error}. Read-only; bounded by a wall-clock timeout."""
    sid = job.get('id')
    tool = job.get('tool', 'lynis')
    if IN_CONTAINER:
        # lynis introspects the RUNNING system; inside the agent container it
        # would score the container image, not the Docker host. Refuse honestly
        # rather than report a misleading hardening score for the host.
        return {'id': sid, 'status': 'skipped', 'findings': [],
                'error': 'host posture scan not available from the containerized agent'}
    if tool != 'lynis':
        return {'id': sid, 'status': 'failed', 'findings': [],
                'error': f'unsupported host tool {tool}'}
    if not _which('lynis'):
        return {'id': sid, 'status': 'failed', 'findings': [],
                'error': 'lynis not installed on this host'}
    # v4.4.0 (SECURITY): mkstemp gives an unpredictable, O_EXCL-created path
    # owned by root (0600). The old fixed /tmp/rp-lynis-report.dat let a local
    # unprivileged user pre-plant a symlink there so the root lynis run would
    # clobber an arbitrary file (e.g. /etc/cron.d/*) → local privilege
    # escalation. Unlink it after parsing.
    fd, report = tempfile.mkstemp(prefix='rp-lynis-', suffix='.dat')
    os.close(fd)
    try:
        try:
            subprocess.run(['lynis', 'audit', 'system', '--quiet', '--no-colors',
                            '--report-file', report],
                           capture_output=True, timeout=900)
        except subprocess.TimeoutExpired:
            return {'id': sid, 'status': 'failed', 'findings': [], 'error': 'lynis timed out'}
        except Exception as e:
            return {'id': sid, 'status': 'failed', 'findings': [], 'error': str(e)[:200]}
        findings, hardening = _parse_lynis_report(report)
    finally:
        try:
            os.unlink(report)
        except OSError:
            pass
    result = {'id': sid, 'status': 'done', 'findings': findings, 'error': ''}
    if hardening is not None:
        result['hardening_index'] = hardening
    return result


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
    if IN_CONTAINER:
        # OpenSCAP evaluates the running system's config; inside the agent
        # container it would grade the container image, not the Docker host —
        # report an honest "not available" instead of a misleading compliance score.
        report.update(available=False,
                      reason='compliance scan not available from the containerized agent '
                             '(it would evaluate the container, not the Docker host)')
        try:
            http_post(f"{creds['server_url']}/api/scap/report", report, timeout=30)
        except Exception as e:
            log.warning(f'OpenSCAP report submission failed: {e}')
        return
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


# Billion-laughs guard for the agent's one XML parse. stdlib ElementTree does
# NOT resolve EXTERNAL entities (no XXE), but it DOES expand internal ones, so a
# crafted XCCDF file could blow up memory. The results file is produced locally
# by `oscap` on trusted profiles, so the real risk is minimal — but the agent
# runs as root and a DTD here has no legitimate purpose, so we reject any
# DTD/entity declaration before parsing (mirrors server/cgi-bin/safe_xml.py,
# kept inline so the agent stays a single dependency-free file).
_XML_DTD_RE = re.compile(rb'<!\s*(?:doctype|entity)', re.IGNORECASE)


def _parse_oscap_results(path):
    """Parse an XCCDF results XML: overall score + rule-result tallies + up to
    200 failed rule ids/severities. Namespace-agnostic (matches on local tag)."""
    import xml.etree.ElementTree as ET  # nosec B405 - guarded below, no XXE in stdlib
    counts = {'pass': 0, 'fail': 0, 'error': 0, 'notapplicable': 0,
              'notchecked': 0, 'notselected': 0, 'unknown': 0, 'informational': 0}
    failed = []
    score = None
    with open(path, 'rb') as _xf:
        _raw = _xf.read()
    if _XML_DTD_RE.search(_raw):
        raise ValueError('XCCDF results declare a DTD/entity — refusing to parse')
    root = ET.fromstring(_raw)  # nosec B314 - DTD/entity rejected above
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
        with open(host_path('/etc/os-release'), 'r', encoding='utf-8') as f:
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


def _host_pkglist_from_db():
    """Container mode: enumerate the HOST's installed packages by reading its
    package DB directly under HOST_ROOT. dpkg/pacman DBs are plain text, so this
    works no matter what (if any) package tooling the slim agent image ships —
    avoiding the trap where a Debian-based image reports its own packages (or an
    empty list) instead of the host's. Returns (manager, [pkgs]) or (None, None)
    when the host's package manager can't be determined."""
    # Debian / Ubuntu — /var/lib/dpkg/status is RFC822-ish paragraphs.
    status = Path(host_path('/var/lib/dpkg/status'))
    if status.exists():
        pkgs, cur = [], {}
        try:
            for line in status.read_text(errors='replace').splitlines():
                if not line.strip():
                    if cur.get('Package') and 'installed' in cur.get('Status', ''):
                        pkgs.append({'name': cur['Package'], 'version': cur.get('Version', ''),
                                     'arch': cur.get('Architecture', '')})
                    cur = {}
                    continue
                if line[:1] in (' ', '\t'):
                    continue                      # folded continuation line
                k, _, v = line.partition(':')
                if k in ('Package', 'Version', 'Architecture', 'Status'):
                    cur[k] = v.strip()
            if cur.get('Package') and 'installed' in cur.get('Status', ''):
                pkgs.append({'name': cur['Package'], 'version': cur.get('Version', ''),
                             'arch': cur.get('Architecture', '')})
        except Exception:
            pass
        return 'apt', pkgs
    # Arch — /var/lib/pacman/local/<pkg>/desc, %FIELD% then value on next line.
    pac = Path(host_path('/var/lib/pacman/local'))
    if pac.is_dir():
        pkgs = []
        try:
            for d in sorted(pac.iterdir()):
                desc = d / 'desc'
                if not desc.is_file():
                    continue
                lines = desc.read_text(errors='replace').splitlines()
                f = {}
                for i, ln in enumerate(lines):
                    if ln.startswith('%') and ln.endswith('%') and i + 1 < len(lines):
                        f[ln.strip('%')] = lines[i + 1].strip()
                if f.get('NAME'):
                    pkgs.append({'name': f['NAME'], 'version': f.get('VERSION', ''),
                                 'arch': f.get('ARCH', '')})
        except Exception:
            pass
        return 'pacman', pkgs
    # RHEL / Fedora — the rpmdb is a binary store, so we still need the rpm tool,
    # run rooted at the host. If the image lacks rpm we return an HONEST empty
    # list tagged 'dnf' (never a false "0 packages / fully patched").
    if Path(host_path('/var/lib/rpm')).exists() or Path(host_path('/usr/lib/sysimage/rpm')).exists():
        if shutil.which('rpm'):
            try:
                out = subprocess.check_output(
                    ['rpm', '--root', HOST_ROOT, '-qa', '--qf',
                     '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n'],
                    text=True, timeout=30, stderr=subprocess.DEVNULL)
                pkgs = []
                for line in out.splitlines():
                    parts = line.split('\t')
                    if len(parts) >= 3 and parts[0] and parts[1]:
                        pkgs.append({'name': parts[0].strip(), 'version': parts[1].strip(),
                                     'arch': parts[2].strip()})
                return 'dnf', pkgs
            except Exception:
                return 'dnf', []
        return 'dnf', []
    return None, None


def get_package_list():
    """
    Enumerate all installed packages via the system package manager.
    Returns (pkg_manager, [{name, version, arch}, ...]).
    """
    if IN_CONTAINER:
        mgr, pkgs = _host_pkglist_from_db()
        if mgr is not None:
            return mgr, pkgs
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
            ['systemctl', 'show', '--property=Id', '--value', '--', unit],
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


def _which(prog, _cache={}):
    """Return path to ``prog`` if it's executable on PATH, else None.

    v4.6.0: memoized in a default-arg dict — tool paths are immutable for the
    agent's lifetime and this is called dozens of times per heartbeat
    (stat-walking PATH each call). (A plain dict rather than @lru_cache so the
    function source stays decorator-free for source-extraction tests.)

    v3.13.0: also searches the standard sbin dirs even when they're absent from
    a minimal service PATH — firewall tools (iptables/nft) live in /usr/sbin and
    /sbin, and a systemd unit's PATH often omits them, which made firewall
    detection report "unknown"."""
    if prog in _cache:
        return _cache[prog]
    seen = []
    for d in os.environ.get('PATH', '').split(':'):
        if d:
            seen.append(d)
    for d in ('/usr/sbin', '/sbin', '/usr/bin', '/bin', '/usr/local/sbin', '/usr/local/bin'):
        if d not in seen:
            seen.append(d)
    result = None
    for d in seen:
        full = os.path.join(d, prog)
        if os.path.isfile(full) and os.access(full, os.X_OK):
            result = full
            break
    _cache[prog] = result
    return result


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
            # v6.1.2: the memory / CPU LIMITS ride along in the SAME batched
            # inspect — no extra call. Usage without a limit is only half the
            # story: "this container is using 3 GB" means something completely
            # different depending on whether it's capped at 4 GB or unlimited
            # (in which case it can OOM the whole host, which is exactly how a
            # homelab box falls over).
            [cmd_path, 'inspect', '--format',
             '{{.Id}} {{.RestartCount}} {{.State.StartedAt}} '
             '{{.HostConfig.Memory}} {{.HostConfig.NanoCpus}}', *ids],
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
        # 0 means "no limit" in docker's model, for both fields.
        mem_limit = cpu_limit = 0
        try:
            if len(parts) >= 4:
                mem_limit = max(0, int(parts[3]))
            if len(parts) >= 5:
                cpu_limit = max(0, int(parts[4]))
        except (ValueError, TypeError):
            pass
        meta[cid] = {
            'restart_count':  restarts,
            'started_at':     started_at,
            'uptime_seconds': uptime,
            # 0 = unlimited (docker's own convention). NanoCpus/1e9 = cores.
            'mem_limit_bytes': mem_limit,
            'cpu_limit_cores': round(cpu_limit / 1e9, 2) if cpu_limit else 0,
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
            # v6.1.2: the configured LIMITS (0 = unlimited). Usage without a
            # limit is half a story — an unlimited container can OOM the host.
            'mem_limit_bytes': im.get('mem_limit_bytes', 0),
            'cpu_limit_cores': im.get('cpu_limit_cores', 0),
        })
    return items


def get_docker_disk_usage():
    """v6.1.2: `docker system df` — where the disk actually went.

    The 40 GB build-cache surprise is a rite of passage in every homelab: the
    box fills up, and nothing in the monitoring says WHY, because "disk 94%"
    doesn't distinguish "your data" from "layers of images you deleted the
    containers for months ago". This reports the four buckets Docker itself
    tracks, plus what is RECLAIMABLE — which is the number you actually act on.

    Also returns per-volume sizes (`docker system df -v`), so "which volume is
    eating 200 GB" is answerable without SSHing in. Best-effort and slow-ish
    (docker walks the layer store), so this rides a slow cadence, not every beat.
    """
    docker = _which('docker')
    if not docker:
        return {}
    out = {}
    try:
        r = subprocess.run(
            [docker, 'system', 'df', '--format', '{{json .}}'],
            capture_output=True, text=True, timeout=60)
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                # Type is "Images" / "Containers" / "Local Volumes" / "Build Cache"
                key = str(d.get('Type', '')).lower().replace(' ', '_')
                if not key:
                    continue
                out[key] = {
                    'size': str(d.get('Size', ''))[:24],
                    'reclaimable': str(d.get('Reclaimable', ''))[:32],
                    'total': str(d.get('TotalCount', d.get('Total', '')))[:12],
                    'active': str(d.get('Active', ''))[:12],
                }
    except Exception as e:
        log.debug(f'docker system df failed: {e}')
        return {}
    # Per-volume sizes. `-v` is the expensive part, so it's a separate call we
    # can drop without losing the summary above.
    try:
        r = subprocess.run(
            [docker, 'system', 'df', '-v', '--format',
             '{{range .Volumes}}{{.Name}}\t{{.Size}}\t{{.Links}}\n{{end}}'],
            capture_output=True, text=True, timeout=90)
        vols = []
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                f = line.split('\t')
                if len(f) >= 2 and f[0].strip():
                    v = {'name': f[0].strip()[:96], 'size': f[1].strip()[:24]}
                    if len(f) >= 3:
                        try:
                            v['links'] = int(f[2].strip())
                        except ValueError:
                            pass
                    vols.append(v)
        if vols:
            # Biggest first — that's the only order anyone reads this in.
            vols.sort(key=lambda v: _parse_docker_size(v['size']), reverse=True)
            out['volumes'] = vols[:40]
    except Exception as e:
        log.debug(f'docker system df -v failed: {e}')
    return out


_SIZE_UNITS = {'b': 1, 'kb': 1e3, 'mb': 1e6, 'gb': 1e9, 'tb': 1e12,
               'kib': 1024, 'mib': 1024**2, 'gib': 1024**3, 'tib': 1024**4}


def _parse_docker_size(s):
    """'1.234GB' -> bytes. Docker prints human sizes; we need to SORT them, and
    lexicographic order would put 9MB above 10GB. Returns 0 on anything odd."""
    m = re.match(r'\s*([\d.]+)\s*([A-Za-z]+)', str(s or ''))
    if not m:
        return 0
    try:
        return float(m.group(1)) * _SIZE_UNITS.get(m.group(2).lower(), 1)
    except (ValueError, TypeError):
        return 0


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
    roots = [host_path(r) for r in COMPOSE_SCAN_ROOTS if Path(host_path(r)).is_dir()]
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
                'path':  unhost_path(str(p)),
                'dir':   unhost_path(str(d)),
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
                                'path': unhost_path(str(p)), 'dir': unhost_path(dirpath),
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
    if not Path(host_path('/bin/systemctl')).exists() and not Path(host_path('/usr/bin/systemctl')).exists():
        return []

    out = []
    units = watched_units[:50]  # matches server MAX_SERVICES_PER_DEVICE
    # v4.10.0 (perf): batch ALL units into ONE `systemctl show` instead of one
    # subprocess per unit (up to 50 × timeout=5 → worst case ~250s of blocking on
    # the heartbeat thread, which would flip the device offline). systemctl emits
    # one property block per requested unit, IN ARGUMENT ORDER, separated by a
    # blank line — even for unknown units — so index alignment is safe.
    try:
        proc = subprocess.run(
            ['systemctl', 'show',
             # v6.1.2: NRestarts rides along in the SAME batched call — no extra
             # subprocess. A unit stuck in a crash/restart loop is 'active'
             # every time we happen to sample it, so failed_unit never fires and
             # the host looks perfectly healthy while a service flaps all day.
             # The restart COUNT is the only thing that reveals it.
             '--property=Id,ActiveState,SubState,ActiveEnterTimestampMonotonic,'
             'ActiveEnterTimestamp,NRestarts',
             '--no-pager', '--', *units],
            capture_output=True, text=True, timeout=15,
        )
        blocks = proc.stdout.split('\n\n')
        for i, unit in enumerate(units):
            props = {}
            if i < len(blocks):
                for line in blocks[i].splitlines():
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
            try:
                entry['restarts'] = int(props.get('NRestarts', ''))
            except ValueError:
                pass   # not a service unit (timer/socket/…), or an old systemd
            out.append(entry)
    except subprocess.TimeoutExpired:
        out = [{'unit': u, 'active': 'unknown', 'sub': 'timeout', 'since': 0} for u in units]
    except Exception as e:
        log.debug(f'systemctl show (batch) failed: {e}')
        out = [{'unit': u, 'active': 'unknown', 'sub': '', 'since': 0} for u in units]
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


# v3.14.0 #47: store-and-forward for log submission. get_unit_logs advances a
# cursor, so a failed POST loses those lines for good — a blind spot in log
# alerting whenever the server is briefly unreachable. We buffer the failed
# batch to a bounded on-disk outbox and fold it into the next successful
# submission (oldest first). Bounded hard on lines + file size so a long outage
# can't grow it without limit; failsafe — any outbox I/O error degrades to
# today's behaviour (drop + continue).
LOG_OUTBOX_FILE = STATE_DIR / 'log_outbox.json'
_LOG_OUTBOX_MAX_LINES = 5000

# W3-47: store-and-forward. When a heartbeat POST fails, spool the metrics
# sample locally; on reconnect, ship the spool as `backfill` so offline gaps
# fill into the sparklines. Bounded (oldest dropped) so it can't grow unbounded.
METRICS_SPOOL_FILE = STATE_DIR / 'metrics_spool.json'
_METRICS_SPOOL_MAX = 500          # samples (~oldest-dropped ring)
_BACKFILL_BATCH    = 200          # samples shipped per reconnect heartbeat


def _spool_metric_sample(sysinfo):
    """Append the current cpu/mem/disk/swap to the local spool (best-effort)."""
    if not isinstance(sysinfo, dict):
        return
    s = {'ts': int(time.time()),
         'cpu': sysinfo.get('cpu_percent'), 'mem': sysinfo.get('mem_percent'),
         'disk': sysinfo.get('disk_percent'), 'swap': sysinfo.get('swap_percent')}
    if s['cpu'] is None and s['mem'] is None and s['disk'] is None and s['swap'] is None:
        return
    try:
        spool = _read_metrics_spool()
        spool.append(s)
        _write_metrics_spool(spool[-_METRICS_SPOOL_MAX:])
    except Exception as e:
        log.debug(f'metrics spool write error: {e}')


def _read_metrics_spool():
    try:
        return json.loads((STATE_DIR / 'metrics_spool.json').read_text()) or []
    except Exception:
        return []


def _write_metrics_spool(spool):
    try:
        _safe_state_write('metrics_spool.json', json.dumps(spool))
    except Exception:
        pass


def _load_log_outbox():
    try:
        if LOG_OUTBOX_FILE.exists():
            d = json.loads(LOG_OUTBOX_FILE.read_text())
            if isinstance(d, dict):
                return {u: v for u, v in d.items() if isinstance(v, list)}
    except Exception:
        pass
    return {}


def _save_log_outbox(units_payload):
    """Persist the pending units→entries map, capped to the newest lines."""
    try:
        total = sum(len(v) for v in units_payload.values())
        if total > _LOG_OUTBOX_MAX_LINES:
            # Drop oldest entries per unit until under the cap (proportional).
            for u in list(units_payload.keys()):
                keep = max(0, len(units_payload[u]) - (total - _LOG_OUTBOX_MAX_LINES))
                units_payload[u] = units_payload[u][-keep:] if keep else []
                total = sum(len(v) for v in units_payload.values())
                if total <= _LOG_OUTBOX_MAX_LINES:
                    break
        _safe_state_write('log_outbox.json', json.dumps(units_payload))
    except Exception as e:
        log.debug(f'log outbox persist failed: {e}')


def _clear_log_outbox():
    try:
        if LOG_OUTBOX_FILE.exists():
            LOG_OUTBOX_FILE.unlink()
    except Exception:
        pass


def _merge_log_payloads(buffered, current):
    """Combine a buffered units→entries map (older) with the current one, oldest
    first, capped to _LOG_OUTBOX_MAX_LINES total."""
    merged = {}
    for src in (buffered, current):
        for unit, entries in (src or {}).items():
            if entries:
                merged.setdefault(unit, []).extend(entries)
    total = sum(len(v) for v in merged.values())
    if total > _LOG_OUTBOX_MAX_LINES:
        for u in list(merged.keys()):
            if total <= _LOG_OUTBOX_MAX_LINES:
                break
            drop = min(len(merged[u]), total - _LOG_OUTBOX_MAX_LINES)
            merged[u] = merged[u][drop:]     # drop oldest
            total -= drop
    return merged


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
    # v3.14.0 #47: fold in anything buffered from a previous failed submission so
    # those lines aren't lost (oldest first).
    outbox = _load_log_outbox()
    send_payload = _merge_log_payloads(outbox, units_payload) if outbox else units_payload
    try:
        http_post(f"{creds['server_url']}/api/logs", {
            'device_id': creds['device_id'],
            'token':     creds['token'],
            'units':     send_payload,
        }, timeout=15)
        if outbox:
            _clear_log_outbox()              # delivered the backlog too
        total = sum(len(v) for v in send_payload.values())
        quiet = sum(1 for v in send_payload.values() if not v)
        log.info(f'Logs submitted: {total} lines across {len(send_payload)} unit(s), '
                 f'{quiet} quiet')
        return True
    except Exception as e:
        log.warning(f'Log submission FAILED: {e}')
        # v3.14.0 #47: buffer this batch (merged with any prior backlog) for the
        # next successful submission instead of dropping it.
        _save_log_outbox(_merge_log_payloads(outbox, units_payload))
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
    apt_log = Path(host_path('/var/log/apt/history.log'))
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
        # Deny-list above checks the logical path (operator-facing semantics);
        # the actual read maps through host_path so a containerized agent reads
        # the host's log, not the empty container fs. v5.0.0.
        p = Path(host_path(path_str))
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


# v6.3.1: hail-mary log sweep — a one-shot, bounded snapshot of the host's
# recently-modified /var/log files, taken only when the server sends
# `force_log_sweep` (the operator clicked "Diagnose from logs"). The result is
# handed to the server for secret-redaction + AI root-cause analysis. Hard
# budgets everywhere: this must never balloon a heartbeat or walk forever.
LOG_SWEEP_MAX_FILES   = 40           # files reported per sweep
LOG_SWEEP_TAIL_BYTES  = 12 * 1024    # bytes read from the end of each file
LOG_SWEEP_TOTAL_BYTES = 256 * 1024   # whole-sweep text budget
LOG_SWEEP_RECENT_S    = 24 * 3600    # only files modified in the last day
LOG_SWEEP_MAX_LINE    = 512          # per-line clip
LOG_SWEEP_MAX_CANDIDATES = 2000      # glob-result cap (pathological /var/log)
_LOG_SWEEP_SKIP_EXT = ('.gz', '.xz', '.bz2', '.zst', '.zip', '.journal', '.gpg')
_LOG_SWEEP_SKIP_NAMES = frozenset({'wtmp', 'btmp', 'lastlog', 'faillog', 'tallylog'})
_LOG_SWEEP_ERR_RX = re.compile(
    r'(?i)\b(error|err|crit|critical|alert|fatal|fail|failed|failure|panic|'
    r'oops|segfault|traceback|exception|denied|refused|timeout|unreachable|'
    r'oom|killed|corrupt)\b')


def collect_log_sweep():
    """One-shot 'hail-mary' sweep of /var/log/* and /var/log/*/*.

    Keeps recently-modified plain-text files (compressed/binary/rotated-away
    files are skipped), tails each, scores by error density + recency, and
    returns the highest-scoring tails within a hard total budget. The server
    re-caps and secret-redacts at ingest — but we still keep the payload small
    here so a single heartbeat POST carries it comfortably.
    """
    import glob as _glob
    root = host_path('/var/log')
    now = time.time()
    scanned = skipped = 0
    candidates = []
    paths = (_glob.glob(os.path.join(root, '*'))
             + _glob.glob(os.path.join(root, '*', '*')))
    for p in paths[:LOG_SWEEP_MAX_CANDIDATES]:
        try:
            logical = unhost_path(p)
            base = os.path.basename(p)
            if base in _LOG_SWEEP_SKIP_NAMES or base.lower().endswith(_LOG_SWEEP_SKIP_EXT):
                continue
            # Rotated numeric suffixes (.1, .2.gz already caught above) are
            # yesterday's news — the sweep is about what's breaking NOW.
            if re.search(r'\.\d+$', base):
                continue
            st = os.stat(p)
            if not stat.S_ISREG(st.st_mode) or st.st_size == 0:
                continue
            scanned += 1
            if (now - st.st_mtime) > LOG_SWEEP_RECENT_S:
                continue
            # Same deny list as the log_watch file tail (shadow/sudoers/.ssh
            # never qualify under /var/log, but symlink tricks do).
            if not _file_log_path_allowed(logical):
                skipped += 1
                continue
            with open(p, 'rb') as f:
                if st.st_size > LOG_SWEEP_TAIL_BYTES:
                    f.seek(st.st_size - LOG_SWEEP_TAIL_BYTES)
                data = f.read(LOG_SWEEP_TAIL_BYTES)
            if b'\x00' in data[:512]:
                skipped += 1          # binary (utmp-style, sqlite, …)
                continue
            text = data.decode('utf-8', errors='replace')
            lines = [l for l in text.splitlines() if l.strip()]
            if st.st_size > LOG_SWEEP_TAIL_BYTES and lines:
                lines = lines[1:]     # drop the partial first line of a mid-file seek
            if not lines:
                continue
            err_hits = sum(1 for l in lines if _LOG_SWEEP_ERR_RX.search(l))
            age = now - st.st_mtime
            score = (err_hits / len(lines)) * 10 + max(0.0, 1 - age / LOG_SWEEP_RECENT_S) * 2
            candidates.append({
                'path':  logical,
                'mtime': int(st.st_mtime),
                'size':  int(st.st_size),
                'score': round(score, 2),
                'lines': lines,
                'truncated': st.st_size > LOG_SWEEP_TAIL_BYTES,
            })
        except (PermissionError, OSError):
            skipped += 1
        except Exception as e:
            log.debug(f'log sweep: {p}: {e}')
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


def collect_acme_dns_creds():
    """Read acme.sh's account.conf and return the saved DNS-provider API
    credentials as {ENV_NAME: value} (e.g. {'CF_Token': '...'}). acme.sh stores
    them as SAVED_<ENV_NAME>='...'. One-shot: only sent when the server asks
    (admin-triggered "Import from agent"); the secrets stay on-host otherwise.
    Returns {} when acme.sh / account.conf is absent."""
    home = None
    for candidate in ACME_HOME_CANDIDATES:
        try:
            hc = Path(host_path(candidate))   # v5.0.0: containerized agent reads host fs
            if hc.is_dir() and (hc / 'account.conf').is_file():
                home = hc
                break
        except (OSError, PermissionError):
            continue
    if home is None:
        return {}
    conf = _acme_parse_conf(home / 'account.conf') or {}
    creds = {}
    for k, v in conf.items():
        if k.startswith('SAVED_') and v:
            creds[k[len('SAVED_'):]] = v
    return creds


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
            hc = Path(host_path(candidate))   # v5.0.0: containerized agent reads host fs
            if hc.is_dir() and (hc / 'acme.sh').is_file():
                home = hc
                break
        except (OSError, PermissionError):
            continue
    if home is None:
        return state
    state['available'] = True
    state['home'] = unhost_path(str(home))
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
            'cert_path':           unhost_path(str(cert_file)) if cert_file.is_file() else '',
            'key_path':            unhost_path(str(key_file))  if key_file.is_file()  else '',
            'fullchain_path':      unhost_path(str(full_file)) if full_file.is_file() else '',
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
        log_path = Path(host_path(log_path_str))   # v5.0.0: containerized agent reads host fs
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
            fp = Path(host_path(p))   # v5.0.0: containerized agent reads host fs
            exists = fp.exists()
            st = fp.stat() if exists else None
            mtime  = st.st_mtime if st else 0
            # W3-42: size drives the anomaly check server-side. A directory
            # target sums its immediate file children (one level, bounded) so a
            # borg/restic repo dir still trends; a plain file uses its own size.
            if st and fp.is_dir():
                size = 0
                try:
                    for i, child in enumerate(fp.iterdir()):
                        if i >= 5000:
                            break
                        try:
                            size += child.stat().st_size
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


_BACKUP_VERIFY_STATE = 'backup_verify_state.json'


def _detect_backup_tool(path, hint=''):
    """v4.10.0: which backup tool owns this path. Explicit `hint` (restic/borg/
    tar) wins; otherwise sniff the path."""
    h = (hint or 'auto').lower()
    if h in ('restic', 'borg', 'tar'):
        return h
    pl = path.lower()
    if 'restic' in pl:
        return 'restic'
    if 'borg' in pl or pl.endswith('.borg'):
        return 'borg'
    if pl.endswith(('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz', '.txz')):
        return 'tar'
    return ''


def collect_backup_verify(backup_monitors):
    """v4.10.0: run each backup tool's OWN integrity check (restic/borg check,
    tar -t) for monitors with verify enabled — rate-gated (per `verify_max_age_hours`,
    default weekly) and time-bounded (<=30s each, <=60s/heartbeat). Returns
    [{path, tool, verify_status, verify_output, verify_at}]. tar needs nothing;
    restic/borg need their passphrase in the agent's environment (e.g.
    RESTIC_PASSWORD_FILE / BORG_PASSPHRASE set in the agent unit)."""
    out = []
    mons = [m for m in (backup_monitors or [])
            if isinstance(m, dict) and m.get('verify_enabled')]
    if not mons:
        return out
    try:
        # Read from the SAME place the verify-state is written
        # (_safe_state_write → STATE_DIR). The old read went through
        # _safe_read(CONF_DIR/…), which host_path()-maps to the *host's* /etc
        # in a container — so the rate-gate never saw its own writes and re-ran
        # `restic/borg check` on every heartbeat. Agent-owned state is not a
        # host fact; don't host_path() it.
        state = json.loads(_safe_state_read(_BACKUP_VERIFY_STATE) or '{}')
        if not isinstance(state, dict):
            state = {}
    except Exception:
        state = {}
    now = int(time.time())
    budget = 60
    for mon in mons:
        p = mon.get('path', '')
        if not p:
            continue
        tool = _detect_backup_tool(p, mon.get('tool', 'auto'))
        if not tool:
            continue
        interval = max(1, int(mon.get('verify_max_age_hours', 168) or 168)) * 3600
        if now - int(state.get(p, 0)) < interval:
            continue
        if budget <= 0:
            break
        hp = host_path(p)
        cmd = (['restic', '-r', hp, 'check'] if tool == 'restic'
               else ['borg', 'check', hp] if tool == 'borg'
               else ['tar', '-tf', hp])
        if not _which(cmd[0]):
            out.append({'path': p, 'tool': tool, 'verify_status': 'tool_missing',
                        'verify_output': f'{cmd[0]} not installed', 'verify_at': now})
            state[p] = now
            continue
        # Destination-reachability precheck for repo tools — cheap `cat config` /
        # `info` distinguishes "repo unreachable" from "integrity failed", and
        # skips the expensive full check when the repo can't be opened at all.
        if tool in ('restic', 'borg'):
            probe = (['restic', '-r', hp, 'cat', 'config'] if tool == 'restic'
                     else ['borg', 'info', hp])
            try:
                pr = subprocess.run(probe, capture_output=True, text=True, timeout=min(15, budget))
                if pr.returncode != 0:
                    out.append({'path': p, 'tool': tool, 'verify_status': 'unreachable',
                                'verify_output': ((pr.stdout or '') + (pr.stderr or '')).strip()[-200:],
                                'verify_at': now})
                    state[p] = now
                    continue
            except subprocess.TimeoutExpired:
                out.append({'path': p, 'tool': tool, 'verify_status': 'unreachable',
                            'verify_output': 'destination probe timed out', 'verify_at': now})
                state[p] = now
                continue
            except Exception:
                pass
        t0 = time.time()
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=min(30, budget))
            status = 'ok' if r.returncode == 0 else 'failed'
            output = ((r.stdout or '') + (r.stderr or '')).strip()[-200:]
        except subprocess.TimeoutExpired:
            status, output = 'timeout', 'integrity check exceeded the time limit'
        except Exception as e:
            status, output = 'error', str(e)[:200]
        budget -= int(time.time() - t0)
        state[p] = now
        out.append({'path': p, 'tool': tool, 'verify_status': status,
                    'verify_output': output, 'verify_at': now})
    try:
        _safe_state_write(_BACKUP_VERIFY_STATE, json.dumps(state))
    except Exception:
        pass
    return out


_RESTORE_DRILL_STATE = 'restore_drill_state.json'


def _verify_restored_tree(root):
    """W6-43: (bytes, sha256, file_count) for a restored sandbox — sha256 of the
    single largest restored regular file, so an empty restore is caught. Pure."""
    import hashlib
    biggest, biggest_size, count = None, -1, 0
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            fp = os.path.join(dirpath, f)
            try:
                sz = os.path.getsize(fp)
            except OSError:
                continue
            count += 1
            if sz > biggest_size:
                biggest, biggest_size = fp, sz
    if biggest is None or biggest_size <= 0:
        return 0, '', count
    h = hashlib.sha256()
    try:
        with open(biggest, 'rb') as fh:
            for chunk in iter(lambda: fh.read(65536), b''):
                h.update(chunk)
    except OSError:
        return biggest_size, '', count
    return biggest_size, h.hexdigest(), count


def run_restore_drills(backup_monitors, now=None):
    """W6-43: for monitors with `restore_drill_enabled`, restore ONE configured
    sample path from the LATEST archive into a fresh sandbox under the agent
    state dir, verify it's non-empty (+ sha256), then delete the sandbox. NEVER
    touches live paths. Rate-gated (restore_drill_max_age_hours, default weekly),
    time-bounded. Returns [{path, tool, drill_status, restored_bytes, sha256,
    files, drill_output, drill_at}]."""
    import shutil
    import tempfile
    now = int(now if now is not None else time.time())
    mons = [m for m in (backup_monitors or [])
            if isinstance(m, dict) and m.get('restore_drill_enabled')]
    if not mons:
        return []
    try:
        state = json.loads(_safe_state_read(_RESTORE_DRILL_STATE) or '{}')
        if not isinstance(state, dict):
            state = {}
    except Exception:
        state = {}
    out, budget = [], 90
    for mon in mons:
        p = mon.get('path', '')
        sample = str(mon.get('restore_sample_path', '') or '').strip()
        if not p or not sample:
            continue
        interval = max(1, int(mon.get('restore_drill_max_age_hours', 168) or 168)) * 3600
        if now - int(state.get(p, 0)) < interval or budget <= 0:
            continue
        tool = _detect_backup_tool(p, mon.get('tool', 'auto'))
        if not tool or not _which(tool):
            out.append({'path': p, 'tool': tool or 'unknown', 'drill_status': 'tool_missing',
                        'restored_bytes': 0, 'sha256': '', 'files': 0,
                        'drill_output': f'{tool or "backup tool"} not installed', 'drill_at': now})
            state[p] = now
            continue
        hp = host_path(p)
        sandbox = tempfile.mkdtemp(prefix='rp-restore-', dir=str(STATE_DIR))
        t0 = time.time()
        try:
            if tool == 'restic':
                cmd = ['restic', '-r', hp, 'restore', 'latest',
                       '--include', sample, '--target', sandbox]
            elif tool == 'borg':
                # resolve the latest archive name, then extract just the sample
                try:
                    lr = subprocess.run(['borg', 'list', '--last', '1', '--format', '{archive}',
                                         hp], capture_output=True, text=True, timeout=min(20, budget))
                    archive = (lr.stdout or '').strip().splitlines()[-1] if lr.returncode == 0 and lr.stdout.strip() else ''
                except Exception:
                    archive = ''
                if not archive:
                    raise RuntimeError('could not resolve latest borg archive')
                cmd = ['borg', 'extract', f'{hp}::{archive}', sample.lstrip('/')]
            else:   # tar — extract one member
                cmd = ['tar', '-xf', hp, '-C', sandbox, sample.lstrip('/')]
            kw = {'capture_output': True, 'text': True, 'timeout': min(60, budget)}
            if tool == 'borg':
                kw['cwd'] = sandbox
            r = subprocess.run(cmd, **kw)
            if r.returncode != 0:
                status = 'failed'
                output = ((r.stdout or '') + (r.stderr or '')).strip()[-200:] or 'restore command failed'
                nbytes = sha = files = 0
                sha = ''
            else:
                nbytes, sha, files = _verify_restored_tree(sandbox)
                if nbytes > 0:
                    status, output = 'ok', f'restored {files} file(s), {nbytes} bytes'
                else:
                    status, output = 'failed', 'restore produced no non-empty files'
        except subprocess.TimeoutExpired:
            status, output, nbytes, sha, files = 'timeout', 'restore exceeded time limit', 0, '', 0
        except Exception as e:
            status, output, nbytes, sha, files = 'error', str(e)[:200], 0, '', 0
        finally:
            shutil.rmtree(sandbox, ignore_errors=True)   # never leave a sandbox behind
        budget -= int(time.time() - t0)
        state[p] = now
        out.append({'path': p, 'tool': tool, 'drill_status': status,
                    'restored_bytes': int(nbytes), 'sha256': sha, 'files': int(files),
                    'drill_output': output, 'drill_at': now})
    try:
        _safe_state_write(_RESTORE_DRILL_STATE, json.dumps(state))
    except Exception:
        pass
    return out


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


MAX_FW_RULES = 200   # per-backend rule cap reported to the server


def _parse_nft_rules(txt, cap=MAX_FW_RULES):
    """Parse `nft -a list ruleset` into [{text, ref}] where ref =
    '<family> <table> <chain> handle <N>' so the server can build an exact
    `nft delete rule <ref>` without guessing context."""
    out, family, table, chain = [], '', '', ''
    for raw in txt.splitlines():
        sline = raw.strip()
        m = re.match(r'table (\S+) (\S+) \{', sline)
        if m:
            family, table, chain = m.group(1), m.group(2), ''
            continue
        m = re.match(r'chain (\S+) \{', sline)
        if m:
            chain = m.group(1)
            continue
        if not sline or sline == '}':
            continue
        if '# handle ' in sline and '{' not in sline:
            hm = re.search(r'# handle (\d+)', sline)
            if not hm or not (family and table and chain):
                continue
            text = sline.split(' # handle ')[0].strip()
            # Strip the volatile per-rule packet/byte counters — they're noise
            # that changes every second and make the ruleset unreadable.
            text = re.sub(r'\s*counter packets \d+ bytes \d+', '', text).strip()
            out.append({'text': text,
                        'ref': '%s %s %s handle %s' % (family, table, chain, hm.group(1)),
                        'table': '%s %s' % (family, table), 'chain': chain})
            if len(out) >= cap:
                break
    return out


def _parse_ipt_rules(txt, cap=MAX_FW_RULES):
    """iptables -A lines -> [{text, ref}]; ref is the spec after '-A ' so the
    server deletes with `iptables -D <ref>`."""
    out = []
    for line in txt.splitlines():
        ls = line.strip()
        if ls.startswith('-A '):
            spec = ls[3:].strip()
            out.append({'text': '-A ' + spec, 'ref': spec,
                        'chain': spec.split(' ', 1)[0]})
            if len(out) >= cap:
                break
    return out


def _parse_ufw_rules(txt, cap=MAX_FW_RULES):
    """ufw status numbered -> [{text, ref}]; ref is the rule number for
    `ufw --force delete <N>`."""
    out = []
    for line in txt.splitlines():
        m = re.match(r'\[\s*(\d+)\]\s+(.*)', line.strip())
        if m:
            out.append({'text': m.group(2).strip(), 'ref': m.group(1)})
            if len(out) >= cap:
                break
    return out


def _parse_firewalld_rules(txt, cap=MAX_FW_RULES):
    """firewall-cmd --list-all -> [{text, ref}] for ports and services (the
    editable units the server's firewalld action handles). ref = 'port:<p>' /
    'service:<s>'."""
    out = []
    for ls in (x.strip() for x in txt.splitlines()):
        if ls.startswith('ports:'):
            for p in ls.split(':', 1)[1].split():
                out.append({'text': 'port ' + p, 'ref': 'port:' + p})
        elif ls.startswith('services:'):
            for sv in ls.split(':', 1)[1].split():
                out.append({'text': 'service ' + sv, 'ref': 'service:' + sv})
        if len(out) >= cap:
            break
    return out


def collect_fail2ban():
    """v4.10.0: fail2ban posture — jails + currently-banned IPs. Best-effort and
    root/socket-dependent; returns {'available': False} when fail2ban-client is
    absent or its server socket is unreachable (e.g. a containerized agent)."""
    f2b = _which('fail2ban-client')
    if not f2b:
        return {'available': False}

    def _run(argv, timeout=6):
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
            return r.returncode, (r.stdout or '')
        except Exception:
            return 127, ''

    rc, out = _run([f2b, 'status'])
    if rc != 0 or 'Jail list:' not in out:
        return {'available': False}
    jail_names = []
    for line in out.splitlines():
        if 'Jail list:' in line:
            jail_names = [j.strip() for j in line.split(':', 1)[1].split(',') if j.strip()]
            break
    result = {'available': True, 'jails': []}
    for jail in jail_names[:50]:
        if not re.match(r'^[A-Za-z0-9_.\-]+$', jail):
            continue
        _jrc, jout = _run([f2b, 'status', jail])
        banned, total_banned, total_failed = [], 0, 0
        # fail2ban-client draws a tree, so lines look like "   `- Total banned: 5"
        # — match the label anywhere in the line, not at the start.
        for jl in jout.splitlines():
            if 'Banned IP list:' in jl:
                banned = [ip for ip in jl.split('Banned IP list:', 1)[1].split() if ip][:MAX_FW_RULES]
            elif 'Total banned:' in jl:
                try: total_banned = int(jl.split('Total banned:', 1)[1].strip())
                except ValueError: pass
            elif 'Total failed:' in jl:
                try: total_failed = int(jl.split('Total failed:', 1)[1].strip())
                except ValueError: pass
        result['jails'].append({
            'name': jail, 'banned': banned, 'banned_count': len(banned),
            'total_banned': total_banned, 'total_failed': total_failed,
        })
    return result


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
                         'active': None if _unreadable(rc, txt) else rules > 0,
                         'rule_list': _parse_nft_rules(txt)})

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
    ipt_best_txt = ''
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
            ipt_best_txt = txt
        if pol and (not ipt_policy or ipt_policy == 'ACCEPT'):
            ipt_policy = pol
    if ipt_present:
        b = {'name': 'iptables', 'present': True, 'rules': ipt_rules}
        if ipt_policy:
            b['policy'] = ipt_policy
        b['active'] = (ipt_rules > 0 or ipt_policy in ('DROP', 'REJECT')) if ipt_readable else None
        b['rule_list'] = _parse_ipt_rules(ipt_best_txt)
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
                         'active': None if _unreadable(rc, st) else ('running' in st.lower()),
                         'rule_list': _parse_firewalld_rules(allz)})

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
        _rcn, ntxt, _ = _run([ufw, 'status', 'numbered'])
        b['rule_list'] = _parse_ufw_rules(ntxt)
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
        rr = Path(host_path('/run/reboot-required'))
        if rr.exists() or Path(host_path('/var/run/reboot-required')).exists():
            out['reboot_required'] = True
            pkgs = Path(host_path('/run/reboot-required.pkgs'))
            if pkgs.exists():
                names = sorted(set(pkgs.read_text().split()))
                out['reboot_reason'] = ', '.join(names[:10])
        else:
            out['reboot_required'] = False
    except Exception:
        pass

    # ── kernel-module visibility (v6.2.2) ────────────────────────────
    # If this process can't see /lib/modules/<running kernel>, neither can
    # anything it runs — and a package upgrade that rebuilds the initramfs
    # from such a context produces an initrd with no kernel modules, which
    # is unbootable. Only reported where an initramfs generator exists at
    # all (WSL/containers without one are not flagged), mirroring the
    # server-side upgrade guard so the two can never disagree.
    try:
        has_gen = (_which('update-initramfs') or _which('dracut')
                   or _which('mkinitcpio'))
        if has_gen and 'microsoft' not in os.uname().release.lower():
            kv = os.uname().release
            out['modules_visible'] = bool(
                os.path.isdir(host_path('/lib/modules/' + kv))
                or os.path.isdir(host_path('/usr/lib/modules/' + kv)))
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
        with open(host_path('/proc/uptime')) as fh:
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
        mdstat = Path(host_path('/proc/mdstat'))
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
            # v5.0.0: map each btrfs filesystem to a mountpoint so the server can
            # offer one-click maintenance (scrub/balance/usage) against it. Build
            # device->mountpoint from the kernel mount table (prefer the shortest
            # mountpoint per device = the fs root, not a subvol bind).
            btrfs_mounts = {}
            try:
                for ml in Path(host_path('/proc/self/mounts')).read_text().splitlines():
                    parts = ml.split()
                    if len(parts) >= 3 and parts[2] == 'btrfs':
                        devp, mp = parts[0], parts[1].replace('\\040', ' ')
                        if devp not in btrfs_mounts or len(mp) < len(btrfs_mounts[devp]):
                            btrfs_mounts[devp] = mp
            except Exception:
                pass
            r = subprocess.run(['btrfs', 'filesystem', 'show'],
                               capture_output=True, text=True, timeout=8)
            if r.returncode == 0:
                cur = None
                for ln in r.stdout.splitlines():
                    s = ln.strip()
                    if s.startswith('Label:'):
                        nm = (s.split('uuid:')[-1].strip()[:16]
                              if 'uuid:' in s else s[:24])
                        cur = {'name': 'btrfs:' + nm, 'kind': 'btrfs', 'state': 'online'}
                        pools.append(cur)
                    elif s.startswith('devid') and cur is not None and 'path ' in s \
                            and 'mount' not in cur:
                        devp = s.split('path ', 1)[1].strip().split()[0]
                        if devp in btrfs_mounts:
                            cur['mount'] = btrfs_mounts[devp]
    except Exception:
        pass
    # ── v6.1.2: newest-snapshot age per pool ─────────────────────────
    # Scrub recency has been reported since v3.11.0; SNAPSHOT recency never
    # was — so a broken snapshot cron (the thing snapshots exist to survive)
    # stayed invisible until the day you needed one. Best-effort, read-only,
    # each backend guarded like the rest of this section.
    try:
        if _which('zfs') and any(p.get('kind') == 'zfs' for p in pools):
            for p in pools:
                if p.get('kind') != 'zfs':
                    continue
                r = subprocess.run(
                    ['zfs', 'list', '-t', 'snapshot', '-H', '-p',
                     '-o', 'creation', '-r', p['name']],
                    capture_output=True, text=True, timeout=10)
                if r.returncode == 0:
                    ts = [int(x) for x in r.stdout.split() if x.isdigit()]
                    if ts:
                        p['last_snapshot'] = max(ts)
                    else:
                        p['last_snapshot'] = 0   # pool has NO snapshots at all
    except Exception:
        pass
    try:
        if _which('btrfs'):
            for p in pools:
                if p.get('kind') != 'btrfs' or not p.get('mount'):
                    continue
                r = subprocess.run(
                    ['btrfs', 'subvolume', 'list', '-s', p['mount']],
                    capture_output=True, text=True, timeout=10)
                if r.returncode != 0:
                    continue
                newest = 0
                for ln in r.stdout.splitlines():
                    m = re.search(r'otime (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', ln)
                    if m:
                        try:
                            newest = max(newest, int(time.mktime(
                                time.strptime(m.group(1), '%Y-%m-%d %H:%M:%S'))))
                        except (ValueError, OverflowError):
                            pass
                p['last_snapshot'] = newest   # 0 = no snapshots found
    except Exception:
        pass

    if pools:
        out['storage_health'] = pools[:40]

    # ── recent logins / source IPs (v3.11.0 access watch) ────────────
    try:
        if _which('last'):
            # v4.4.0: LC_ALL=C so the `-F` full timestamps parse deterministically
            # (English weekday/month names) regardless of the host locale.
            r = subprocess.run(['last', '-i', '-w', '-F', '-n', '25'],
                               capture_output=True, text=True, timeout=8,
                               env=dict(os.environ, LC_ALL='C'))
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
                    ip_idx = -1
                    for idx in range(1, min(5, len(f))):
                        tok = f[idx]
                        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', tok) or \
                           (tok.count(':') >= 2):
                            ip = tok
                            ip_idx = idx
                            break
                    # v4.4.0: with -F the five tokens after the IP are the login
                    # time, e.g. "Wed Jun 9 14:23:01 2026". Parse to epoch so the
                    # drawer Access table can show *when*. Best-effort → 0 on any
                    # format/locale surprise.
                    ts = 0
                    if ip_idx >= 0 and len(f) >= ip_idx + 6:
                        try:
                            ts = int(time.mktime(time.strptime(
                                ' '.join(f[ip_idx + 1:ip_idx + 6]),
                                '%a %b %d %H:%M:%S %Y')))
                        except Exception:
                            ts = 0
                    logins.append({'user': f[0], 'source': ip, 'ts': ts})
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

    # v4.10.0: fail2ban posture (jails + banned IPs) for the Firewall page.
    try:
        _f2b = collect_fail2ban()
        if _f2b:
            out['fail2ban'] = _f2b
    except Exception:
        pass

    # v5.1.0: cron posture (root + user crontabs + /etc/cron.d) for the Cron page.
    try:
        _cron = collect_cron()
        if _cron:
            out['cron'] = _cron
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
        for name in sorted(os.listdir(host_path('/sys/block'))):
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
                hd = host_path(d)   # read the HOST's clamav dir when containerized
                for fn in _os.listdir(hd):
                    if fn.endswith(('.cvd', '.cld')):
                        newest = max(newest, int(_os.path.getmtime(_os.path.join(hd, fn))))
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
            r['last_run_ts'] = int(_os.path.getmtime(host_path('/var/log/rkhunter.log')))
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
        # v6.1.2: NVMe spare-block reserve. Wear% says how used the flash is;
        # available_spare says how much of the reserve pool is LEFT to remap
        # failures into. When that runs low the drive is close to going
        # read-only, which wear% alone doesn't tell you.
        ns = re.search(r'Available Spare:\s*(\d+)\s*%', out)
        if ns:
            entry['spare_pct'] = max(0, min(100, int(ns.group(1))))
        nst = re.search(r'Available Spare Threshold:\s*(\d+)\s*%', out)
        if nst:
            entry['spare_threshold_pct'] = max(0, min(100, int(nst.group(1))))

        # v6.1.2: the last SMART SELF-TEST. `-H -A -i` reports the drive's own
        # pass/fail opinion and its attributes, but NOT whether a self-test has
        # ever actually run — so a disk that has not been tested in two years
        # looked identical to one tested last night. A separate cheap call;
        # -l selftest is a log read, it does not start anything.
        try:
            rt = subprocess.run([smartctl, '-l', 'selftest', dev],
                                capture_output=True, text=True, timeout=20)
            tout = rt.stdout or ''
        except Exception:
            tout = ''
        if tout:
            # ATA log:  "# 1  Short offline  Completed without error  00%  1234  -"
            for ln in tout.splitlines():
                m = re.match(r'\s*#\s*\d+\s+(\S.*?)\s\s+(\S.*?)\s\s+(\d+)%\s+(\d+)', ln)
                if m:
                    entry['selftest_type'] = m.group(1).strip()[:40]
                    entry['selftest_result'] = m.group(2).strip()[:60]
                    try:
                        entry['selftest_hours'] = int(m.group(4))
                    except ValueError:
                        pass
                    break
            else:
                # NVMe log — no '#' and no Remaining%; the hours column is
                # followed by '-' placeholders, e.g.
                #   " 0   Short   Completed without error   7405   -   -   -   -"
                for ln in tout.splitlines():
                    m = re.match(
                        r'\s*\d+\s+(Short|Extended)\s+(\S.*?)\s\s+(\d+)\b', ln)
                    if m:
                        entry['selftest_type'] = m.group(1)
                        entry['selftest_result'] = m.group(2).strip()[:60]
                        try:
                            entry['selftest_hours'] = int(m.group(3))
                        except ValueError:
                            pass
                        break
            if 'selftest_result' not in entry and 'No self-tests have been logged' in tout:
                entry['selftest_result'] = 'never run'
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
        elif _which('pacman') and out.get('running'):
            # v6.1.2: Arch and derivatives. The comment above always SAID
            # "Arch: pacman linux" but no branch was ever written, so Arch
            # boxes never showed "reboot for kernel" — and Arch has no
            # /run/reboot-required either, so they had NO kernel-reboot signal
            # at all. The canonical Arch method:
            #   /usr/lib/modules/<uname -r>/pkgbase  = the package owning the
            #   RUNNING kernel (works for linux, linux-lts, -zen, -hardened,
            #   -cachyos, ...); `pacman -Q <pkgbase>` = its INSTALLED version.
            # If the whole modules dir for the running kernel is GONE, pacman
            # already removed it during an upgrade — a reboot is unambiguously
            # required (this is also why a just-upgraded Arch box can't load
            # e.g. USB-storage modules until it reboots).
            run = out['running']
            mod_dir = host_path(f'/usr/lib/modules/{run}')
            pkgbase = (_safe_read(f'{mod_dir}/pkgbase', 128) or '').strip()
            if pkgbase and re.fullmatch(r'[A-Za-z0-9._+-]{1,64}', pkgbase):
                r = subprocess.run(['pacman', '-Q', pkgbase],
                                   capture_output=True, text=True, timeout=10)
                parts = r.stdout.split() if r.returncode == 0 else []
                if len(parts) >= 2:
                    # pacman versions use '.' before the flavour tag where
                    # uname uses '-' ("6.9.7.arch1-1" vs "6.9.7-arch1-1") —
                    # normalise so the prefix-containment check below works.
                    latest = re.sub(r'\.([a-z])', r'-\1', parts[1])
            elif os.path.isdir(host_path('/usr/lib/modules')) and not os.path.isdir(mod_dir):
                out['reboot_for_kernel'] = True
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
                     'temperature.gpu,power.draw,fan.speed',
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
                                 'power_w': _num(c[5]),
                                 'fan_pct': _num(c[6]) if len(c) > 6 else None})
        except Exception:
            pass
    amd = _which('rocm-smi')
    amd_found = False
    if amd:
        try:
            r = subprocess.run([amd, '--showproductname', '--showtemp', '--showuse',
                                '--showmeminfo', 'vram', '--showpower', '--showfan',
                                '--json'],
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0 and r.stdout.strip().startswith('{'):
                data = json.loads(r.stdout)
                for k, v in data.items():
                    if not isinstance(v, dict) or not k.lower().startswith('card'):
                        continue
                    pick = lambda pred: next((v[x] for x in v if pred(x.lower())), None)
                    name = v.get('Card series') or v.get('Card model') or v.get('Card SKU') or k
                    used = pick(lambda s: 'vram' in s and 'used' in s)
                    total = pick(lambda s: 'vram' in s and ('total' in s or 'size' in s))
                    gpus.append({
                        'vendor': 'amd', 'name': str(name)[:96],
                        'util_pct': _num(pick(lambda s: 'gpu use' in s)),
                        'temp_c': _num(pick(lambda s: 'temperature' in s and 'edge' in s)),
                        'mem_used_mb': round(_num(used) / 1048576, 1) if _num(used) and _num(used) > 1e6 else _num(used),
                        'mem_total_mb': round(_num(total) / 1048576, 1) if _num(total) and _num(total) > 1e6 else _num(total),
                        'power_w': _num(pick(lambda s: 'average graphics package power' in s or ('power' in s and 'socket' in s))),
                        'fan_pct': _num(pick(lambda s: 'fan speed' in s and '%' in s)),
                    })
                    amd_found = True
        except Exception:
            pass
    # AMD fallback — no rocm-smi needed: read the kernel's amdgpu sysfs directly
    # (works in the containerized agent too, via host_path()). util + VRAM + temp.
    if not amd_found:
        try:
            import glob as _g
            for dev in sorted(_g.glob(host_path('/sys/class/drm/card[0-9]*/device'))):
                busy = _safe_read(unhost_path(dev) + '/gpu_busy_percent').strip()
                if not busy:
                    continue                      # not an amdgpu card
                used = _safe_read(unhost_path(dev) + '/mem_info_vram_used').strip()
                total = _safe_read(unhost_path(dev) + '/mem_info_vram_total').strip()
                temp = ''
                for hw in sorted(_g.glob(host_path(unhost_path(dev) + '/hwmon/hwmon*/temp1_input'))):
                    temp = _safe_read(unhost_path(hw)).strip()
                    if temp:
                        break
                gpus.append({
                    'vendor': 'amd', 'name': 'AMD GPU (' + dev.rsplit('/', 2)[-2] + ')',
                    'util_pct': _num(busy),
                    'mem_used_mb': round(_num(used) / 1048576, 1) if _num(used) else None,
                    'mem_total_mb': round(_num(total) / 1048576, 1) if _num(total) else None,
                    'temp_c': round(_num(temp) / 1000, 1) if _num(temp) else None,
                })
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
        for path in host_glob(pat):
            rp = os.path.realpath(host_path(path))
            if rp in seen:
                continue
            seen.add(rp)
            try:
                r = subprocess.run([openssl, 'x509', '-in', host_path(path), '-noout',
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


def get_clock_status():
    """v4.1.0: NTP / clock-sync state. Returns {synced: bool, offset_ms: float?}.

    `timedatectl` gives the synchronised flag; `chronyc tracking` (when present)
    gives the last measured offset. Best-effort, read-only; {} if nothing known.
    """
    out = {}
    if _which('timedatectl'):
        try:
            r = subprocess.run(['timedatectl', 'show', '-p', 'NTPSynchronized',
                                '--value'], capture_output=True, text=True, timeout=5)
            v = (r.stdout or '').strip().lower()
            if v in ('yes', 'true', '1'):
                out['synced'] = True
            elif v in ('no', 'false', '0'):
                out['synced'] = False
        except Exception:
            pass
    if _which('chronyc'):
        try:
            r = subprocess.run(['chronyc', '-n', 'tracking'],
                               capture_output=True, text=True, timeout=5)
            for line in (r.stdout or '').splitlines():
                if line.startswith('Last offset'):
                    m = re.search(r'([-+]?\d+\.?\d*(?:[eE][-+]?\d+)?)\s*seconds', line)
                    if m:
                        out['offset_ms'] = round(float(m.group(1)) * 1000, 3)
                    break
        except Exception:
            pass
        # Per-source (peer) detail — name, sync state, stratum, reachability.
        try:
            r = subprocess.run(['chronyc', '-n', 'sources'],
                               capture_output=True, text=True, timeout=5)
            peers = []
            started = False
            statemap = {'*': 'synced', '+': 'combined', '-': 'standby',
                        '?': 'unreachable', 'x': 'falseticker', '~': 'unstable'}
            for line in (r.stdout or '').splitlines():
                if line.startswith('==='):
                    started = True
                    continue
                if not started:
                    continue
                parts = line.split()
                if len(parts) >= 5 and 1 <= len(parts[0]) <= 2:
                    peers.append({'name': parts[1][:64],
                                  'state': statemap.get(parts[0][-1], parts[0]),
                                  'stratum': parts[2], 'reach': parts[4]})
                if len(peers) >= 12:
                    break
            if peers:
                out['peers'] = peers
        except Exception:
            pass
    return out


def get_mdns_services(limit=60):
    """v6.1.2: what is ADVERTISING itself on this LAN (mDNS / Bonjour).

    The netscan finds hosts (ARP/nmap) — it tells you an IP is alive, not what it
    IS. mDNS is how the other half of a homelab announces itself: Chromecasts,
    AirPlay speakers, printers, HomeKit bridges, Synology boxes, Proxmox nodes.
    Those are exactly the devices nobody enrols an agent on, so without this they
    are just anonymous IPs on the map.

    Uses avahi-browse where present; returns [] otherwise (so the feature is
    invisible rather than broken on a host without avahi). Strictly read-only:
    it browses, it never registers anything.
    """
    tool = _which('avahi-browse')
    if not tool:
        return []
    try:
        # -a all types, -t terminate after the cache is dumped, -r resolve to
        # host/port, -p parseable (semicolon-separated).
        r = subprocess.run([tool, '-atrp', '--no-db-lookup'],
                           capture_output=True, text=True, timeout=20)
    except Exception as e:
        log.debug(f'avahi-browse failed: {e}')
        return []
    if r.returncode != 0:
        return []
    seen = {}
    for line in (r.stdout or '').splitlines():
        # '=;eth0;IPv4;name;_http._tcp;local;host.local;192.168.1.5;80;"txt"'
        f = line.split(';')
        if len(f) < 9 or f[0] != '=' or f[2] != 'IPv4':
            continue
        name = f[3].replace('\\032', ' ').strip()[:96]
        stype = f[4].strip()[:48]
        host = f[6].strip()[:96]
        addr = f[7].strip()[:45]
        try:
            port = int(f[8])
        except (ValueError, IndexError):
            port = 0
        if not addr or not stype:
            continue
        key = (addr, stype, port)
        if key in seen:
            continue
        seen[key] = {'name': name, 'type': stype, 'host': host,
                     'address': addr, 'port': port}
        if len(seen) >= limit:
            break
    return list(seen.values())


def get_chassis():
    """v6.3.0: DMI chassis class ('laptop'/'desktop'/'server'/...) — one sysfs
    read. The server's offline sweep uses it to give roaming laptop-class
    hosts a longer leash (laptop_offline_grace_hours) so a lid-close doesn't
    page like a dead server. Empty string on VMs/containers/unknown codes."""
    code = (_safe_read('/sys/class/dmi/id/chassis_type', 8) or '').strip()
    names = {'3': 'desktop', '4': 'desktop', '6': 'desktop', '7': 'desktop',
             '8': 'portable', '9': 'laptop', '10': 'notebook',
             '13': 'all-in-one', '14': 'notebook', '17': 'server',
             '23': 'server', '25': 'server', '30': 'tablet',
             '31': 'convertible', '32': 'detachable', '34': 'server',
             '35': 'mini-pc'}
    return names.get(code, '')


def get_battery():
    """v6.3.0: laptop battery health from /sys/class/power_supply/BAT*.

    Laptop fleets care about wear long before failure: charge percent, cycle
    count and current-vs-design full capacity are free sysfs reads. Returns []
    on hosts without a battery (servers, VMs) so the feature is invisible
    there. External UPSes are a separate channel (NUT/apcupsd -> 'ups').
    """
    base = host_path('/sys/class/power_supply')
    if not os.path.isdir(base):
        return []
    out = []
    try:
        for name in sorted(os.listdir(base)):
            if not name.startswith('BAT'):
                continue
            d = os.path.join(base, name)

            def _r(f):
                v = _safe_read(os.path.join(d, f), 64)
                return v.strip() if v else None
            ent = {'name': name[:16]}
            cap = _r('capacity')
            if cap is not None:
                try:
                    ent['percent'] = max(0, min(100, int(cap)))
                except ValueError:
                    pass
            status = _r('status')
            if status:
                ent['status'] = status[:32]
            cycles = _r('cycle_count')
            if cycles:
                try:
                    ent['cycles'] = int(cycles)
                except ValueError:
                    pass
            # Wear: current full charge vs design capacity (energy_* on most
            # laptops, charge_* on some ACPI implementations).
            full = _r('energy_full') or _r('charge_full')
            design = _r('energy_full_design') or _r('charge_full_design')
            try:
                if full and design and int(design) > 0:
                    ent['health_pct'] = min(100, round(int(full) * 100 / int(design)))
            except (ValueError, TypeError):
                pass
            if len(ent) > 1:
                out.append(ent)
    except OSError:
        return []
    return out


def get_ecc_errors():
    """v6.1.2: ECC memory error counters from EDAC.

    Homelabbers (TrueNAS/ZFS especially) deliberately buy ECC RAM and then never
    look at the counters — which is a shame, because a rising correctable count
    is the earliest warning a DIMM gives you, long before anything crashes.
    /sys/devices/system/edac/mc/mc*/{ce_count,ue_count} is a free read.

    Returns {} when EDAC isn't present (no ECC, or the driver isn't loaded —
    very common), so the feature is simply invisible on those hosts.
    """
    base = host_path('/sys/devices/system/edac/mc')
    if not os.path.isdir(base):
        return {}
    ce = ue = 0
    controllers = 0
    try:
        for mc in sorted(os.listdir(base)):
            if not mc.startswith('mc'):
                continue
            mcdir = os.path.join(base, mc)
            c = _safe_read(os.path.join(mcdir, 'ce_count'), 32)
            u = _safe_read(os.path.join(mcdir, 'ue_count'), 32)
            if c is None and u is None:
                continue
            controllers += 1
            try:
                ce += int((c or '0').strip())
            except ValueError:
                pass
            try:
                ue += int((u or '0').strip())
            except ValueError:
                pass
    except OSError:
        return {}
    if not controllers:
        return {}
    # correctable = the DIMM caught and fixed it (a warning);
    # uncorrectable = it could not (data loss / a machine check).
    return {'ce': ce, 'ue': ue, 'controllers': controllers}


def get_zram():
    """v6.1.2: zram (compressed-RAM swap) presence and usage.

    Without this, swap pressure on a Pi or a Fedora box — where swap IS zram,
    living in RAM — reads as "this host is swapping to disk, its disk must be
    thrashing", which is simply wrong. Returns [] when no zram device exists.
    """
    base = host_path('/sys/block')
    out = []
    try:
        for name in sorted(os.listdir(base)):
            if not name.startswith('zram'):
                continue
            d = os.path.join(base, name)
            disksize = _safe_read(os.path.join(d, 'disksize'), 32)
            if not disksize:
                continue
            try:
                total = int(disksize.strip())
            except ValueError:
                continue
            if total <= 0:
                continue
            entry = {'name': name, 'total_bytes': total}
            # mm_stat: orig_data_size compr_data_size mem_used_total ...
            mm = (_safe_read(os.path.join(d, 'mm_stat'), 256) or '').split()
            if len(mm) >= 3:
                try:
                    entry['orig_bytes'] = int(mm[0])
                    entry['compr_bytes'] = int(mm[1])
                    entry['used_bytes'] = int(mm[2])
                except ValueError:
                    pass
            out.append(entry)
    except OSError:
        return []
    return out[:8]


# Where each distro records "patch yourself automatically". Value = the token
# that means ENABLED in that file (None = mere existence of an enabled unit).
_AUTOUPDATE_UNITS = ('unattended-upgrades.service', 'dnf-automatic.timer',
                     'dnf-automatic-install.timer', 'yum-cron.service',
                     'apt-daily-upgrade.timer')


def get_ssh_hostkeys():
    """v6.1.2: fingerprint this host's OWN SSH host keys.

    A host key that changes without a reinstall is the classic MITM tripwire —
    and the far more common benign case (the box was reimaged / the keys were
    regenerated) is exactly why people click through the scary ssh warning
    without reading it. Baselining the fingerprints server-side turns "ssh is
    warning me and I don't know why" into a dated, attributable event.

    Fingerprint format matches `ssh-keygen -lf`: SHA256:<base64, no padding> over
    the raw (base64-decoded) key blob — computed here rather than shelling out,
    so it works with no openssh-client installed and never touches a PRIVATE key.
    """
    import base64 as _b64
    out = {}
    # host_glob() globs the HOST rootfs and hands back DISPLAY paths; _safe_read()
    # re-applies the prefix. Going through both is what makes this work inside the
    # containerized agent instead of fingerprinting the slim image's own keys.
    for path in sorted(host_glob('/etc/ssh/ssh_host_*_key.pub')):
        raw = _safe_read(host_path(path), 8192)
        if not raw:
            continue
        parts = raw.split()
        if len(parts) < 2:
            continue
        keytype, blob = parts[0], parts[1]
        try:
            digest = hashlib.sha256(_b64.b64decode(blob, validate=True)).digest()
        except Exception:
            continue
        fp = _b64.b64encode(digest).decode('ascii').rstrip('=')
        out[keytype] = 'SHA256:' + fp
    return out


def get_usb_devices():
    """v6.2.0: enumerate connected USB devices from sysfs.

    A USB device appearing on a server is a physical-access signal: the rubber-
    ducky / mass-storage-exfil class, or (far more often, and still worth
    knowing) somebody plugged a disk into the rack and forgot about it.

    Read from /sys/bus/usb/devices rather than shelling `lsusb`: sysfs is
    bind-mounted read-only into the containerized agent (docker-compose.agent.yml
    mounts /sys:/host/sys), whereas usbutils is NOT in the agent image — so
    lsusb would silently return nothing there. Same reason get_hardware_inventory()
    reads /proc/mdstat directly.

    Keyed by VID:PID (stable across replug and reboot; the kernel's bus/port path
    is NOT — the same stick in a different port would read as a new device and
    cry wolf). Value is a human label. Hubs and root hubs are skipped: they are
    fixed silicon, not somebody plugging something in.
    """
    out = {}
    try:
        base = host_path('/sys/bus/usb/devices')
        if not os.path.isdir(base):
            return {}                      # no USB subsystem (VM, container, some ARM)
        for entry in sorted(os.listdir(base))[:256]:
            # Interfaces look like "1-1:1.0"; we want DEVICES ("1-1", "usb1").
            if ':' in entry:
                continue
            d = os.path.join(base, entry)
            vid = _safe_read(os.path.join(d, 'idVendor'), 16).strip()
            pid = _safe_read(os.path.join(d, 'idProduct'), 16).strip()
            if not vid or not pid:
                continue
            # bDeviceClass 09 == hub (incl. the root hubs). Not a plug-in event.
            if _safe_read(os.path.join(d, 'bDeviceClass'), 8).strip() == '09':
                continue
            vendor = _safe_read(os.path.join(d, 'manufacturer'), 128).strip()
            product = _safe_read(os.path.join(d, 'product'), 128).strip()
            label = ' '.join(x for x in (vendor, product) if x) or 'unknown device'
            out[f'{vid}:{pid}'] = label[:96]
            if len(out) >= 32:
                break
    except Exception:
        return {}
    return out


def get_autoupdate_posture():
    """v6.1.2: does this host patch ITSELF?

    A fleet where half the boxes silently auto-patch and half don't is a fleet
    you cannot reason about — "0 pending updates" means something different on
    each. This is a read-only config sniff, no new dependencies:

      Debian/Ubuntu: unattended-upgrades enabled AND
                     APT::Periodic::Unattended-Upgrade "1";
      Fedora/RHEL:   dnf-automatic timer active (or yum-cron on older)

    Returns {enabled: bool, mechanism: str} — mechanism is '' when nothing is
    configured, so the UI can say "manual" rather than "unknown".
    """
    out = {'enabled': False, 'mechanism': ''}
    # systemd is the common denominator for all of them.
    if _which('systemctl'):
        for unit in _AUTOUPDATE_UNITS:
            try:
                r = subprocess.run(['systemctl', 'is-enabled', unit],
                                   capture_output=True, text=True, timeout=5)
            except Exception:
                continue
            if r.returncode == 0 and r.stdout.strip() in ('enabled', 'static'):
                out['mechanism'] = unit.rsplit('.', 1)[0]
                out['enabled'] = True
                break
    # Debian's unit can be enabled while the periodic switch is 0, which means
    # it does NOT actually apply updates — checking the unit alone would report
    # "this host patches itself" when it doesn't.
    if out['mechanism'] == 'unattended-upgrades':
        periodic = ''
        for p in ('/etc/apt/apt.conf.d/20auto-upgrades',
                  '/etc/apt/apt.conf.d/50unattended-upgrades'):
            periodic += (_safe_read(host_path(p), 8192) or '')
        m = re.search(r'APT::Periodic::Unattended-Upgrade\s+"(\d+)"', periodic)
        if m and m.group(1) == '0':
            out['enabled'] = False
    return out


def get_network_gateway():
    """v4.1.0: default gateway IP + ping reachability. {ip, reachable} or {}.

    Parses /proc/net/route for the default route, then sends one short ping.
    `reachable` is None if ping couldn't run (server treats that as "unknown",
    not an outage). Best-effort, Linux-only."""
    gw = None
    try:
        with open(host_path('/proc/net/route')) as f:
            for line in f.read().splitlines()[1:]:
                fields = line.split()
                if len(fields) >= 3 and fields[1] == '00000000' and fields[2] != '00000000':
                    import socket as _s, struct as _st
                    gw = _s.inet_ntoa(_st.pack('<L', int(fields[2], 16)))
                    break
    except Exception:
        return {}
    if not gw:
        return {}
    out = {'ip': gw}
    try:
        # v6.1.2: capture the RTT, not just the exit code. The ping we already
        # run PRINTS the latency — it was simply thrown away, so the gateway
        # check could only ever say up/down. LAN congestion (a saturated uplink,
        # a dying switch port, wifi that's degraded but not dead) shows up as
        # rising latency long before it shows up as an unreachable gateway.
        r = subprocess.run(['ping', '-c', '1', '-W', '2', gw],
                           capture_output=True, text=True, timeout=5)
        out['reachable'] = (r.returncode == 0)
        m = re.search(r'time[=<]([\d.]+)\s*ms', r.stdout or '')
        if m:
            try:
                out['latency_ms'] = round(float(m.group(1)), 2)
            except ValueError:
                pass
    except Exception:
        out['reachable'] = None
    return out


def get_last_oom():
    """v4.1.0: (epoch, process_name) of the most recent kernel OOM kill, else
    (0, ''). Uses journald's own grep (-g) so it's a cheap, bounded query."""
    if not _which('journalctl'):
        return 0, ''
    try:
        r = subprocess.run(
            ['journalctl', '-k', '-g', 'Out of memory: Killed process|oom-kill',
             '-o', 'short-unix', '--no-pager', '-n', '5', '--since', '-7 days'],
            capture_output=True, text=True, timeout=8)
        last_ts, last_proc = 0, ''
        for line in (r.stdout or '').splitlines():
            parts = line.split(None, 1)
            try:
                ts = int(float(parts[0]))
            except (ValueError, IndexError):
                continue
            if ts >= last_ts:
                last_ts = ts
                m = re.search(r'Killed process \d+ \(([^)]+)\)', line)
                last_proc = m.group(1) if m else ''
        return last_ts, last_proc
    except Exception:
        return 0, ''


# v4.1.0: back-off so a broken MTA (e.g. postfix showq setuid failure) can't
# make us re-invoke postqueue every cycle — each call makes postfix log a fatal
# to the journal, which the agent then ships, flooding the activity feed.
_mailq_skip_until = 0
_MAILQ_FAIL_COOLDOWN = 3600     # 1h pause after a broken-MTA result


def get_mailq():
    """v4.1.0: mail queue depth for postfix/sendmail/exim, or None if no MTA.

    Read-only and bounded. Tries `mailq` (postfix/sendmail) first, then
    `exim -bpc`. Returns an int message count, or None when no mail tooling is
    present OR the MTA is broken (in which case we back off for an hour so we
    don't keep poking a misconfigured postfix and flooding its logs)."""
    global _mailq_skip_until
    if time.time() < _mailq_skip_until:
        return None
    # Signs the local mail system is broken rather than just empty — invoking it
    # again only spams the journal, so cool down instead.
    _broken = ('mail system is down', 'malformed', 'fatal:', 'operation not permitted',
               'connection refused')

    def _down(text):
        t = (text or '').lower()
        return any(s in t for s in _broken)
    try:
        if _which('exim') and not _which('mailq'):
            r = subprocess.run(['exim', '-bpc'], capture_output=True,
                               text=True, timeout=6)
            if r.returncode != 0 or _down(r.stderr) or _down(r.stdout):
                _mailq_skip_until = time.time() + _MAILQ_FAIL_COOLDOWN
                return None
            s = (r.stdout or '').strip()
            return int(s) if s.isdigit() else None
        if not _which('mailq') and not _which('postqueue'):
            return None
        cmd = ['postqueue', '-p'] if _which('postqueue') else ['mailq']
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
        # Broken MTA → back off (don't keep triggering postfix fatal logs).
        if r.returncode != 0 or _down(r.stderr) or _down(r.stdout):
            _mailq_skip_until = time.time() + _MAILQ_FAIL_COOLDOWN
            return None
        out = (r.stdout or '').strip()
        if not out or 'is empty' in out.lower() or 'no messages' in out.lower():
            return 0
        # postfix prints a trailing "-- N Kbytes in M Requests." summary line.
        m = re.search(r'--\s*[\d.]+\s*\w*bytes\s+in\s+(\d+)\s+Request', out, re.I)
        if m:
            return int(m.group(1))
        # sendmail: "Total requests: N"; else count message-id header lines.
        m = re.search(r'Total requests:\s*(\d+)', out, re.I)
        if m:
            return int(m.group(1))
        return sum(1 for ln in out.splitlines()
                   if re.match(r'^[0-9A-F]{8,}\*?\s', ln))
    except Exception:
        _mailq_skip_until = time.time() + _MAILQ_FAIL_COOLDOWN
        return None


def _eval_one_agent_check(c):
    """Evaluate a single server-pushed agent-side check. Returns (status, output).

    Read-only and bounded: file/job checks only stat paths (never read content
    or execute), the log check shells out to journalctl with the pattern as a
    single -g regex argument (list form, no shell) over a bounded window.
    """
    ctype = c.get('type')
    param = str(c.get('param', ''))
    if ctype in ('file_present', 'file_absent'):
        try:
            exists = os.path.exists(host_path(param))
        except Exception:
            return 'unknown', 'stat failed'
        if ctype == 'file_present':
            return ('ok', 'present') if exists else ('critical', 'missing')
        return ('critical', 'present (should be absent)') if exists else ('ok', 'absent')
    if ctype == 'job_fresh':
        max_age = int(c.get('max_age_hours', 24)) * 3600
        try:
            age = time.time() - os.stat(host_path(param)).st_mtime
        except FileNotFoundError:
            return 'critical', 'file missing'
        except Exception:
            return 'unknown', 'stat failed'
        hrs = age / 3600.0
        return ('ok', f'updated {hrs:.1f}h ago') if age <= max_age \
            else ('critical', f'stale: {hrs:.1f}h old (max {max_age // 3600}h)')
    if ctype == 'log_errors':
        if not _which('journalctl') or not param:
            return 'unknown', 'no journalctl' if not _which('journalctl') else 'no pattern'
        window = int(c.get('window_min', 15))
        warn = int(c.get('warn', 1))
        crit = int(c.get('crit', 10))
        cmd = ['journalctl', '--no-pager', '-q', '-g', param,
               '--since', f'-{window}min', '-n', '5000']
        unit = re.sub(r'[^a-zA-Z0-9_.@\-]', '', str(c.get('unit', '')))
        if unit:
            cmd += ['-u', unit]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            n = sum(1 for ln in (r.stdout or '').splitlines() if ln.strip())
        except Exception:
            return 'unknown', 'journalctl failed'
        status = 'critical' if n >= crit else 'warning' if n >= warn else 'ok'
        return status, f'{n} match(es) in {window}min'
    if ctype == 'systemd_unit':
        # v5.6.0: is a named systemd unit active? Read-only `systemctl is-active`
        # (list form, no shell), unit sanitised. Catches stopped/inactive units —
        # not just failed ones — so RemotePower's own services, satellites/relays
        # and any user service can be checked first-class.
        unit = re.sub(r'[^a-zA-Z0-9_.@\-]', '', param)
        if not unit:
            return 'unknown', 'no unit'
        if not _which('systemctl'):
            return 'unknown', 'no systemctl'
        try:
            r = subprocess.run(['systemctl', 'is-active', '--', unit],
                               capture_output=True, text=True, timeout=8)
            state = (r.stdout or '').strip() or (r.stderr or '').strip() or 'unknown'
        except Exception:
            return 'unknown', 'systemctl failed'
        if state == 'active':
            return 'ok', 'active'
        if state == 'activating':
            return 'warning', 'activating'
        return 'critical', state or 'inactive'
    if ctype == 'file_hash':
        # Integrity of a pinned file: baseline its SHA-256 on first run, then
        # alert if it ever changes. Read-only, streamed (no full-file buffer).
        try:
            hh = hashlib.sha256()
            with open(host_path(param), 'rb') as fh:
                for blk in iter(lambda: fh.read(65536), b''):
                    hh.update(blk)
            cur = hh.hexdigest()
        except FileNotFoundError:
            return 'critical', 'file missing'
        except OSError:
            return 'unknown', 'read failed'
        key = 'checkhash-' + re.sub(r'[^A-Za-z0-9_.\-]', '', str(c.get('id', '')))[:64]
        prev = (_safe_state_read(key) or '').strip()
        if not prev:
            _safe_state_write(key, cur)
            return 'ok', 'baseline set'
        if prev == cur:
            return 'ok', f'unchanged ({cur[:12]})'
        return 'critical', f'content changed (was {prev[:8]}…, now {cur[:8]}…)'
    if ctype == 'dir_baseline':
        # File-integrity tripwire over a subtree: baseline {path: size:mtime} on
        # first run, then alert on any new/changed/removed file. `param` is
        # "path" or "path::glob". Bounded to 5000 files; noise dirs skipped.
        import fnmatch
        raw, _sep, glob = param.partition('::')
        base = host_path(raw.strip())
        skip = {'cache', 'tmp', 'temp', 'log', 'logs', '.git', '.cache',
                'node_modules', 'vendor'}
        cur, n = {}, 0
        try:
            for root, dirs, files in os.walk(base):
                dirs[:] = [d for d in dirs if d not in skip]
                for fn in files:
                    if glob and not fnmatch.fnmatch(fn, glob):
                        continue
                    fp = os.path.join(root, fn)
                    try:
                        stt = os.stat(fp)
                    except OSError:
                        continue
                    cur[fp] = f'{stt.st_size}:{int(stt.st_mtime)}'
                    n += 1
                    if n >= 5000:
                        break
                if n >= 5000:
                    break
        except OSError:
            return 'unknown', 'scan failed'
        key = 'checkdir-' + re.sub(r'[^A-Za-z0-9_.\-]', '', str(c.get('id', '')))[:64]
        prevraw = _safe_state_read_big(key)
        if prevraw is None:
            _safe_state_write(key, json.dumps(cur))
            return 'ok', f'baseline set ({n} files)'
        try:
            prev = json.loads(prevraw)
        except ValueError:
            prev = {}
        added = [k for k in cur if k not in prev]
        removed = [k for k in prev if k not in cur]
        changed = [k for k in cur if k in prev and cur[k] != prev[k]]
        quarantined, mass_change = 0, False
        if c.get('protect') == 'quarantine' and added:
            if len(added) > _GUARD_MASS_CHANGE:
                # Rail: a burst of new files is a deploy/restore, not a dropped
                # shell. Refuse to quarantine (never nuke a legitimate rollout)
                # and report it loudly instead — a human decides.
                mass_change = True
            else:
                # Neutralise NEW files (never changed/removed ones). They move to
                # the vault, so the baseline stays clean and the check recovers to
                # OK next run — the threat is gone, not just logged.
                quarantined = _guard_quarantine(added, c.get('id', ''))
                added = []
        if not (added or removed or changed or quarantined):
            return 'ok', f'{n} files, unchanged'
        counts = []
        if quarantined:
            counts.append(f'{quarantined} quarantined')
        if added:
            counts.append(f'{len(added)} new'
                          + (' (mass change — NOT quarantined)' if mass_change else ''))
        if changed:
            counts.append(f'{len(changed)} changed')
        if removed:
            counts.append(f'{len(removed)} removed')
        sample = ', '.join(os.path.basename(x) for x in (added + changed + removed)[:3])
        out = '; '.join(counts) + (f' — {sample}' if sample else '')
        return 'critical', out[:200]
    if ctype == 'file_contains':
        # Content match across a subtree: `param` is path or path::glob, `pattern`
        # a regex. This is the signature half of Integrity Guard — dir_baseline
        # says a file APPEARED, this says a file LOOKS malicious, so it catches a
        # filename nobody has seen before. Read-only and bounded on every axis:
        # file count, bytes per file, and only files matching the glob.
        import fnmatch
        pat = str(c.get('pattern', ''))
        if not pat:
            return 'unknown', 'no pattern configured'
        try:
            rx = re.compile(pat)
        except re.error:
            return 'unknown', 'bad pattern'
        raw, _sep, glob = param.partition('::')
        base = host_path(raw.strip())
        skip = {'cache', 'tmp', 'temp', 'log', 'logs', '.git', '.cache',
                'node_modules', 'vendor'}
        hits, scanned = [], 0
        try:
            for root, dirs, files in os.walk(base):
                dirs[:] = [d for d in dirs if d not in skip]
                for fn in files:
                    if glob and not fnmatch.fnmatch(fn, glob):
                        continue
                    fp = os.path.join(root, fn)
                    try:
                        with open(fp, 'rb') as fh:
                            blob = fh.read(262144)      # 256 KB is plenty for a loader
                    except OSError:
                        continue
                    scanned += 1
                    if rx.search(blob.decode('utf-8', 'replace')):
                        hits.append(fp)
                    if scanned >= 2000 or len(hits) >= 50:
                        break
                if scanned >= 2000 or len(hits) >= 50:
                    break
        except OSError:
            return 'unknown', 'scan failed'
        if hits:
            sample = ', '.join(os.path.basename(x) for x in hits[:3])
            return 'critical', f'{len(hits)} file(s) match — {sample}'[:200]
        return 'ok', f'{scanned} file(s) scanned, no match'
    if ctype == 'auth_new_source':
        # Learns which source networks SUCCESSFULLY log in over SSH and alerts
        # the first time one shows up from somewhere new.
        #
        # This is the signal a stolen credential or key actually produces: the
        # login SUCCEEDS, so an auth-failure-rate check sees nothing at all. The
        # only anomaly is WHERE it came from.
        #
        # Private ranges are deliberately NOT excluded (unlike egress_baseline) —
        # a new internal source is just as interesting as an external one, e.g.
        # lateral movement. Use the param ignore-list for your office/VPN.
        import ipaddress
        if not _which('journalctl'):
            return 'unknown', 'no journalctl'
        ignore = []
        for tok in re.split(r'[\s,]+', param.strip()):
            if not tok:
                continue
            try:
                ignore.append(ipaddress.ip_network(tok, strict=False))
            except ValueError:
                continue
        window = int(c.get('window_min', 60) or 60)
        try:
            r = subprocess.run(
                ['journalctl', '--no-pager', '-q', '-t', 'sshd',
                 '--since', f'-{window}min', '-n', '5000'],
                capture_output=True, text=True, timeout=15)
        except Exception:
            return 'unknown', 'journalctl failed'
        rx = re.compile(r'Accepted \S+ for (\S+) from ([0-9A-Fa-f:.]+)')
        nets, who = set(), {}
        for ln in (r.stdout or '').splitlines():
            m = rx.search(ln)
            if not m:
                continue
            user, ip = m.group(1), m.group(2)
            try:
                ipo = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if any(ipo in nw for nw in ignore):
                continue
            pfx = 24 if ipo.version == 4 else 64
            net = str(ipaddress.ip_network(f'{ip}/{pfx}', strict=False))
            nets.add(net)
            who.setdefault(net, user)
        key = 'checkauthsrc-' + re.sub(r'[^A-Za-z0-9_.\-]', '', str(c.get('id', '')))[:64]
        prevraw = _safe_state_read_big(key)
        if prevraw is None:
            _safe_state_write(key, json.dumps(sorted(nets)))
            return 'ok', f'baseline set ({len(nets)} source network(s))'
        try:
            known = set(json.loads(prevraw))
        except ValueError:
            known = set()
        new = sorted(nets - known)
        if new:
            _safe_state_write(key, json.dumps(sorted(known | nets)[:2000]))
            detail = ', '.join(f'{who.get(n, "?")}@{n}' for n in new[:3])
            return 'critical', f'{len(new)} new SSH source network(s): {detail}'[:200]
        return 'ok', f'{len(nets)} known source network(s) in {window}min'
    if ctype == 'egress_baseline':
        # Learn where this host normally talks OUT to, then alert once per new
        # destination. Unlike egress_flagged this needs no prior threat intel —
        # a beacon to an unknown C2 is new by definition.
        #
        # Two things make it usable rather than noisy:
        #   * inbound is excluded — a connection whose LOCAL port is one we
        #     LISTEN on is a client talking to us, not us reaching out. Without
        #     this every web visitor would look like a new "destination".
        #   * destinations are grouped by /24 (v4) or /64 (v6), so a CDN
        #     rotating addresses inside one network doesn't flap.
        import ipaddress
        ignore = []
        for tok in re.split(r'[\s,]+', param.strip()):
            if not tok:
                continue
            try:
                ignore.append(ipaddress.ip_network(tok, strict=False))
            except ValueError:
                continue
        listen, conns = set(), []
        for pf in ('/proc/net/tcp', '/proc/net/tcp6'):
            try:
                with open(pf) as fh:
                    rows = fh.read().splitlines()[1:5001]
            except OSError:
                continue
            for ln in rows:
                fld = ln.split()
                if len(fld) < 4:
                    continue
                try:
                    lport = int(fld[1].split(':')[-1], 16)
                except (ValueError, IndexError):
                    continue
                if fld[3] == '0A':          # LISTEN
                    listen.add(lport)
                elif fld[3] == '01':        # ESTABLISHED
                    conns.append((lport, fld[2]))
        nets = set()
        for lport, rem in conns:
            if lport in listen:             # inbound client, not our egress
                continue
            try:
                ip = _parse_hex_ip(rem.split(':')[0])
            except (ValueError, IndexError):
                continue
            if not ip:
                continue
            try:
                ipo = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if (ipo.is_private or ipo.is_loopback or ipo.is_link_local
                    or ipo.is_multicast or ipo.is_reserved):
                continue                    # only EXTERNAL destinations matter
            if any(ipo in nw for nw in ignore):
                continue
            pfx = 24 if ipo.version == 4 else 64
            nets.add(str(ipaddress.ip_network(f'{ip}/{pfx}', strict=False)))
        key = 'checkegress-' + re.sub(r'[^A-Za-z0-9_.\-]', '', str(c.get('id', '')))[:64]
        prevraw = _safe_state_read_big(key)
        if prevraw is None:
            _safe_state_write(key, json.dumps(sorted(nets)))
            return 'ok', f'baseline set ({len(nets)} network(s))'
        try:
            known = set(json.loads(prevraw))
        except ValueError:
            known = set()
        new = sorted(nets - known)
        if new:
            # Remember them, so each destination alerts exactly ONCE instead of
            # re-firing every poll for the rest of its life.
            _safe_state_write(key, json.dumps(sorted(known | nets)[:2000]))
            return 'critical', (f'{len(new)} new outbound destination(s): '
                                + ', '.join(new[:3]))[:200]
        return 'ok', f'{len(nets)} known destination(s)'
    if ctype == 'egress_flagged':
        # Alert if any active outbound connection's remote endpoint falls in an
        # operator-supplied IP/CIDR flag-list. Read-only over /proc/net.
        import ipaddress
        nets = []
        for tok in re.split(r'[\s,]+', param.strip()):
            if not tok:
                continue
            try:
                nets.append(ipaddress.ip_network(tok, strict=False))
            except ValueError:
                continue
        if not nets:
            return 'ok', 'no flagged ranges configured'
        hits = set()
        for pf in ('/proc/net/tcp', '/proc/net/tcp6'):
            try:
                with open(pf) as fh:
                    rows = fh.read().splitlines()[1:5001]
            except OSError:
                continue
            for ln in rows:
                fld = ln.split()
                if len(fld) < 4 or fld[3] not in ('01', '02'):  # ESTABLISHED, SYN_SENT
                    continue
                try:
                    ip = _parse_hex_ip(fld[2].split(':')[0])
                except (ValueError, IndexError):
                    continue
                if not ip:
                    continue
                try:
                    ipo = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if any(ipo in nw for nw in nets):
                    hits.add(ip)
        if hits:
            return 'critical', 'outbound to flagged: ' + ', '.join(sorted(hits)[:5])
        return 'ok', 'no flagged endpoints'
    return 'unknown', 'unknown check type'


def eval_agent_checks(checks):
    """Evaluate every server-pushed agent-side check → {id: {status, output}}."""
    out = {}
    for c in checks or []:
        if not isinstance(c, dict) or not c.get('id'):
            continue
        try:
            status, output = _eval_one_agent_check(c)
        except Exception:
            status, output = 'unknown', 'error'
        out[c['id']] = {'status': status, 'output': str(output)[:200]}
    return out


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
                        # A temp feature exposes <name>_input (current) plus, on
                        # most chips, <name>_crit / <name>_max thresholds. Capture
                        # the hardware critical limit too so the UI can show how
                        # much headroom is left, not just the bare temperature.
                        cur = crit = high = None
                        for k, v in vals.items():
                            if 'temp' not in k:
                                continue
                            try:
                                fv = float(v)
                            except (TypeError, ValueError):
                                continue
                            if k.endswith('_input'):
                                cur = fv
                            elif k.endswith('_crit') and crit is None:
                                crit = fv
                            elif k.endswith('_max') and high is None:
                                high = fv
                        if cur is not None:
                            entry = {'label': f'{chip}/{label}', 'current_c': round(cur, 1)}
                            thr = crit if crit is not None else high
                            if thr is not None:
                                entry['crit_c'] = round(thr, 1)
                            temps.append(entry)
            if temps:
                hw['temps'] = temps[:64]
        except Exception:
            pass

    # ── RAID arrays (mdadm software RAID; storcli hardware RAID) ──────
    raid = []
    try:
        mdstat = Path(host_path('/proc/mdstat'))
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


def _burst_live_samples(server, creds, live_until, max_iters=30):
    """W3-19: post 1 s high-res metric samples until `live_until` (bounded by
    max_iters so the main heartbeat loop resumes promptly). Device-token auth;
    failures stop the burst quietly."""
    dev_id = creds.get('device_id')
    token = creds.get('token')
    if not dev_id or not token:
        return
    url = f'{server}/api/devices/{dev_id}/live-sample'
    for _ in range(max_iters):
        if int(time.time()) >= live_until:
            break
        try:
            m = get_metrics()
            http_post(url, {'token': token,
                            'cpu': m.get('cpu_percent'), 'mem': m.get('mem_percent'),
                            'disk': m.get('disk_percent'), 'swap': m.get('swap_percent')},
                      timeout=5)
        except Exception:
            break
        time.sleep(1)


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
        cpu  = _psutil.cpu_percent(interval=None)   # non-blocking: %CPU since the previous poll
        _vm  = _psutil.virtual_memory()   # v4.6.0: one call, reused for mem_total_mb below
        mem  = _vm.percent
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

    # v4.1.0: open file descriptors vs the system max (/proc/sys/fs/file-nr:
    # "allocated  unused  max"). Exhaustion → "too many open files" outages.
    try:
        with open(host_path('/proc/sys/fs/file-nr')) as _f:
            _alloc, _unused, _fmax = (int(x) for x in _f.read().split()[:3])
        if _fmax > 0:
            out['fd_percent'] = round(_alloc / _fmax * 100, 1)
    except Exception:
        pass
    # v4.1.0: netfilter conntrack table fullness. A full table silently drops
    # new connections — a classic hard-to-diagnose firewall/NAT outage.
    try:
        with open(host_path('/proc/sys/net/netfilter/nf_conntrack_count')) as _f:
            _ccount = int(_f.read().strip())
        with open(host_path('/proc/sys/net/netfilter/nf_conntrack_max')) as _f:
            _cmax = int(_f.read().strip())
        if _cmax > 0:
            out['conntrack_percent'] = round(_ccount / _cmax * 100, 1)
    except Exception:
        pass
    # v4.1.0: NTP / clock-sync state. {synced: bool, offset_ms: float?}. Time
    # drift silently breaks TLS, auth (Kerberos) and log correlation.
    try:
        clk = get_clock_status()
        if clk:
            out['clock'] = clk
    except Exception:
        pass
    # v4.1.0: default-gateway reachability.
    try:
        gw = get_network_gateway()
        if gw:
            out['gateway'] = gw
    except Exception:
        pass
    # v4.1.0: most recent kernel OOM kill (epoch + process), for edge-trigger.
    try:
        _ots, _oproc = get_last_oom()
        if _ots:
            out['last_oom_ts'] = _ots
            if _oproc:
                out['last_oom_proc'] = _oproc
    except Exception:
        pass
    # v4.1.0: mail queue depth (None on non-MTA hosts → server omits the check).
    try:
        _mq = get_mailq()
        if _mq is not None:
            out['mailq'] = _mq
    except Exception:
        pass

    # v3.13.0: total RAM (MB) for the CMDB Hardware panel.
    try:
        out['mem_total_mb'] = round(_vm.total / (1024 ** 2))   # v4.6.0: reuse the vm read above
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
                # v4.1.0: inode usage % — a filesystem can be far from full on
                # bytes yet refuse writes when out of inodes (many tiny files).
                try:
                    vfs = os.statvfs(mp)
                    if vfs.f_files > 0:
                        entry['inode_percent'] = round(
                            (vfs.f_files - vfs.f_ffree) / vfs.f_files * 100, 1)
                    # v4.1.0: read-only state per local mount. A writable fs the
                    # kernel remounted read-only (on I/O error) is a silent
                    # data-loss outage; emit always so the check shows ok too.
                    if hasattr(os, 'ST_RDONLY'):
                        entry['ro'] = bool(vfs.f_flag & os.ST_RDONLY)
                except (OSError, AttributeError):
                    pass
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
        # v4.1.0: capped, de-duped set of running process names so the server
        # can evaluate "process X must be running" custom checks without a
        # per-host agent config push. Sorted + bounded to stay small.
        out['proc_names'] = sorted({p['name'] for p in procs if p['name']})[:400]
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
    if IN_CONTAINER:
        # In a container the binary is baked into an immutable image; replacing
        # it in-place would be lost on the next restart and can break the running
        # container. Upgrades happen by pulling a newer image tag, so never
        # self-update here.
        log.debug("Containerized agent — skipping self-update (upgrade via image tag)")
        return False
    if _audit_mode():
        # v4.11.0: self-update rewrites the binary on disk — a write. Audit
        # (read-only) mode never self-updates.
        log.info("Audit mode (read-only): skipping self-update")
        return False
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

    # v5.0.1: refuse a silent DOWNGRADE. The update trigger is hash drift (a
    # re-build of the same version legitimately differs), but if the server now
    # advertises an OLDER version than we run — e.g. the agent was pointed at a
    # rolled-back or stale server — swapping to it loses fixes/features. Never
    # auto-downgrade; an operator who really wants a rollback uses a forced
    # re-deploy (force=True bypasses this, exactly like the sha-match short-circuit).
    def _vtuple(v):
        try:
            return tuple(int(x) for x in str(v).split('.')[:3])
        except (TypeError, ValueError):
            return ()
    _lv, _rv = _vtuple(VERSION), _vtuple(remote_version)
    if not force and _lv and _rv and _rv < _lv:
        log.warning(
            f"Server advertises agent v{remote_version}, OLDER than local v{VERSION} — "
            f"refusing to auto-downgrade (hash drift notwithstanding). "
            f"Point the agent at an up-to-date server, or force a re-deploy to override."
        )
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


def enroll_interactive(re_enroll=False, server_url=None, pin=None):
    # v4.5.0: server_url/pin may be supplied (by install-client.sh) to skip the
    # matching prompt — keeps the install fully non-interactive.
    print()
    print("╔══════════════════════════════════════════╗")
    print("║     RemotePower Client Setup             ║")
    print("╚══════════════════════════════════════════╝")
    print()
    if not server_url:
        server_url = input("RemotePower server URL (e.g. https://remote.example.com): ").strip()
    server_url = server_url.strip().rstrip('/')
    if not server_url.startswith('https://'):
        print("⚠  Only HTTPS is supported. Prepending https://")
        server_url = 'https://' + _strip_url_scheme(server_url)
    if not pin:
        pin = input("Enrollment PIN (shown in web dashboard): ").strip()
        # Only prompt for a display name in the interactive path; a scripted
        # enroll (pin supplied) defaults to the hostname without blocking.
        device_name = input(f"Device display name [{socket.gethostname()}]: ").strip()
    else:
        device_name = ''
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
    # W3-38: remove any decoy canary files we planted before tearing down.
    try:
        _remove_canaries()
    except Exception:
        pass
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
            arp = Path(host_path('/proc/net/arp'))   # host ARP table when containerized
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

    out = sorted(hosts.values(), key=lambda h: tuple(
        int(x) if x.isdigit() else 0
        for x in (h['ip'].split('.') + ['0', '0', '0', '0'])[:4]))
    return {'ok': True, 'hosts': out[:512], 'method': '+'.join(method) or 'none',
            'ts': int(time.time())}


# ─── Command execution ──────────────────────────────────────────────────────────
# ── v5.1.0: cron / timer posture + management ────────────────────────────────
def collect_cron():
    """Read root + user crontabs, /etc/crontab and /etc/cron.d for the Cron page.
    Best-effort; needs root to read other users' crontabs. systemd timers are
    collected separately (out['timers']). Returns {} on total failure."""
    out = {'crontabs': [], 'cron_d': []}
    try:
        users = ['root']
        try:
            for ln in Path(host_path('/etc/passwd')).read_text().splitlines():
                p = ln.split(':')
                if len(p) >= 3 and p[0] != 'root':
                    try:
                        uid = int(p[2])
                    except ValueError:
                        continue
                    if uid >= 1000:
                        users.append(p[0])
        except Exception:
            pass
        for u in users[:50]:
            try:
                r = subprocess.run(['crontab', '-u', u, '-l'],
                                   capture_output=True, text=True, timeout=6)
            except Exception:
                continue
            if r.returncode == 0:
                lines = [l for l in r.stdout.splitlines()
                         if l.strip() and not l.lstrip().startswith('#')]
                if lines:
                    out['crontabs'].append({'user': u, 'lines': lines[:100]})
        for src in ('/etc/crontab',):
            try:
                txt = Path(host_path(src)).read_text()
            except Exception:
                continue
            lines = [l for l in txt.splitlines() if l.strip() and not l.lstrip().startswith('#')]
            if lines:
                out['cron_d'].append({'file': src, 'lines': lines[:100]})
        try:
            crond = Path(host_path('/etc/cron.d'))
            if crond.is_dir():
                for fp in sorted(crond.iterdir())[:50]:
                    try:
                        lines = [l for l in fp.read_text().splitlines()
                                 if l.strip() and not l.lstrip().startswith('#')]
                    except Exception:
                        continue
                    if lines:
                        out['cron_d'].append({'file': '/etc/cron.d/' + fp.name,
                                              'lines': lines[:100]})
        except Exception:
            pass
    except Exception:
        return {}
    return out


def _handle_cron_op(cmd):
    """Execute a `cron:` mutation. The crontab CONTENT rides base64 (never a
    shell) because a cron line legitimately contains shell metacharacters — it is
    written to a temp file and installed with `crontab -u <user> <file>` (argv,
    no shell), so the content can't inject. Timer units / users are regex-pinned.
    Returns the standard cmd_output dict; never raises."""
    import json as _json
    import base64 as _b64
    import re as _re
    import tempfile as _tf
    res, rc = {}, 0
    try:
        bits = cmd.split(':', 3)          # cron:<op>:<arg_b64>[:<content_b64>]
        op = bits[1] if len(bits) > 1 else ''
        arg = (_b64.urlsafe_b64decode(bits[2]).decode('utf-8', 'replace')
               if len(bits) > 2 else '')
        if op in ('set', 'del'):
            if not _re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', arg):
                return {'cmd': cmd, 'rc': 1, 'output': _json.dumps({'error': 'invalid user'})}
            if op == 'set':
                content = (_b64.urlsafe_b64decode(bits[3]).decode('utf-8', 'replace')
                           if len(bits) > 3 else '')
                tmp = None
                try:
                    with _tf.NamedTemporaryFile('w', suffix='.crontab', delete=False) as fo:
                        fo.write(content if content.endswith('\n') else content + '\n')
                        tmp = fo.name
                    r = subprocess.run(['crontab', '-u', arg, tmp],
                                       capture_output=True, text=True, timeout=10)
                finally:
                    if tmp:
                        try:
                            os.unlink(tmp)
                        except OSError:
                            pass
                rc = 0 if r.returncode == 0 else 1
                res = {'user': arg, 'installed': rc == 0,
                       'error': (r.stderr or '')[:200] if rc else ''}
            else:
                r = subprocess.run(['crontab', '-u', arg, '-r'],
                                   capture_output=True, text=True, timeout=10)
                # crontab -r on an empty crontab returns non-zero ("no crontab"); treat as ok.
                rc = 0
                res = {'user': arg, 'removed': True}
        elif op in ('timer_enable', 'timer_disable', 'timer_start', 'timer_stop'):
            action = op.split('_', 1)[1]
            unit = arg
            if not _re.fullmatch(r'[A-Za-z0-9@._\-]{1,128}\.timer', unit):
                return {'cmd': cmd, 'rc': 1, 'output': _json.dumps({'error': 'invalid timer unit'})}
            r = subprocess.run(['systemctl', action, '--', unit],
                               capture_output=True, text=True, timeout=15)
            rc = 0 if r.returncode == 0 else 1
            res = {'unit': unit, 'action': action, 'ok': rc == 0,
                   'error': (r.stderr or '')[:200] if rc else ''}
        else:
            rc, res = 1, {'error': f'unknown cron op: {op}'}
    except Exception as e:
        rc, res = 1, {'error': str(e)[:300]}
    return {'cmd': cmd, 'rc': rc, 'output': _json.dumps(res)}


# ── v5.1.0: web file manager — server-driven file ops, allowlist-confined ────
# The server queues a base64-wrapped `files:<op>:<b64path>[:<b64content>]`
# command (NEVER a shell). We confine every path to an allowlisted root, resolve
# it symlink-following so a link can't escape, map it through host_path() for the
# containerized agent, and refuse mutations in audit mode (reads stay allowed —
# read-only, useful for incident response).
FILE_MGR_DEFAULT_ROOTS = ('/etc', '/var/log', '/var/lib', '/home', '/opt',
                          '/srv', '/tmp', '/usr/local')  # nosec B108 - allowlisted browse ROOT, not a temp-file path
FILE_MGR_DENY = ('/proc', '/sys', '/dev')
FILE_MGR_MAX_READ = 256 * 1024
FILE_MGR_ROOTS_FILE = CONF_DIR / 'file-roots'


def _file_mgr_roots():
    """Allowlisted roots. Operator may override via CONF_DIR/file-roots (one
    absolute path per line); otherwise the conservative built-in set."""
    try:
        if FILE_MGR_ROOTS_FILE.exists():
            roots = [ln.strip() for ln in FILE_MGR_ROOTS_FILE.read_text().splitlines()
                     if ln.strip().startswith('/')]
            if roots:
                return roots
    except Exception:
        pass
    return list(FILE_MGR_DEFAULT_ROOTS)


def _file_mgr_allowed(logical_path):
    """logical_path is a HOST-namespace absolute path (HOST_ROOT already stripped).
    True iff under an allowlisted root and not under a denied prefix."""
    rp = os.path.normpath(logical_path)
    if rp.startswith(FILE_MGR_DENY):
        return False
    for r in _file_mgr_roots():
        r = os.path.normpath(r)
        if rp == r or rp.startswith(r.rstrip('/') + '/'):
            return True
    return False


# v6.1.1: folder-as-tar streaming archive — a SEPARATE channel from _handle_file_op
# below. That one returns a single bounded result through the normal cmd_output
# path; an archive can be far bigger than any single heartbeat/exec response can
# carry, so this builds the tar.gz locally and streams it back to the server in
# bounded chunks over its own endpoint, authenticated the same way heartbeat is
# (device_id/token in the body). See docs/feature-buildout-scoping-internal.md #9.
_FILE_ARCHIVE_RAW_MAX = 300 * 1024 * 1024   # generous vs. the server's 200MB compressed cap
_FILE_ARCHIVE_CHUNK = 4 * 1024 * 1024       # matches the server's _FILE_ARCHIVE_CHUNK_MAX


def _archive_report_error(creds, dev_id, job_id, message):
    """Tell the server this job failed, even with zero chunk data sent, so the
    browser sees it via /archive-status instead of waiting out the server's
    10-minute stale-job timeout."""
    try:
        http_post(f"{creds['server_url']}/api/devices/{dev_id}/files/archive-chunk",
                  {'token': creds['token'], 'job_id': job_id, 'final': True,
                   'chunk': '', 'error': str(message)[:300]})
    except Exception as e:
        log.warning(f"Archive error report failed: {e}")


def _handle_file_archive(cmd):
    """files:archive:<job_id>:<b64path> — tar.gz an allowlisted directory and
    stream it back in bounded chunks. Never raises into the caller; every
    failure path reports itself to the server so a job never just sits
    'pending' waiting for the stale timeout. Symlinked files/dirs are skipped
    entirely (not resolved-and-rechecked like the single-file ops above) —
    the simplest correct answer for a whole-subtree walk that could otherwise
    touch thousands of entries."""
    import tarfile
    import tempfile
    import base64 as _b64
    import json as _json

    bits = cmd.split(':', 3)
    job_id = bits[2] if len(bits) > 2 else ''
    raw_path = (_b64.urlsafe_b64decode(bits[3]).decode('utf-8', 'replace')
                if len(bits) > 3 else '')
    logical = os.path.normpath(raw_path)
    creds = load_credentials()
    if not creds:
        return {'cmd': cmd, 'rc': 1,
                'output': _json.dumps({'error': 'agent has no credentials'})}
    dev_id = creds['device_id']

    if not logical.startswith('/') or not _file_mgr_allowed(logical):
        _archive_report_error(creds, dev_id, job_id, 'path is outside the allowlisted roots')
        return {'cmd': cmd, 'rc': 1,
                'output': _json.dumps({'error': 'path is outside the allowlisted roots'})}
    fs = Path(host_path(logical))
    real = os.path.realpath(fs)
    if not _file_mgr_allowed(unhost_path(real)) or not os.path.isdir(real):
        _archive_report_error(creds, dev_id, job_id,
                               'resolved path escapes the allowlisted roots or is not a directory')
        return {'cmd': cmd, 'rc': 1,
                'output': _json.dumps({'error': 'not an allowlisted directory'})}

    total = 0
    for root, dirs, files in os.walk(real, followlinks=False):
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
        for name in files:
            p = os.path.join(root, name)
            if os.path.islink(p):
                continue
            try:
                total += os.lstat(p).st_size
            except OSError:
                continue
        if total > _FILE_ARCHIVE_RAW_MAX:
            _archive_report_error(creds, dev_id, job_id,
                                   f'directory exceeds the {_FILE_ARCHIVE_RAW_MAX} byte archive cap')
            return {'cmd': cmd, 'rc': 1, 'output': _json.dumps({'error': 'too large to archive'})}

    tmp_fd, tmp_path = tempfile.mkstemp(suffix='.tar.gz', prefix='rp-archive-')
    os.close(tmp_fd)
    try:
        with tarfile.open(tmp_path, mode='w:gz') as tar:
            for root, dirs, files in os.walk(real, followlinks=False):
                dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
                for name in files:
                    p = os.path.join(root, name)
                    if os.path.islink(p):
                        continue
                    arcname = os.path.relpath(p, real)
                    try:
                        tar.add(p, arcname=arcname, recursive=False)
                    except OSError:
                        continue   # vanished/unreadable mid-walk — skip, don't abort the job

        url = f"{creds['server_url']}/api/devices/{dev_id}/files/archive-chunk"
        seq = 0
        size = os.path.getsize(tmp_path)
        sent = 0
        with open(tmp_path, 'rb') as f:
            while True:
                chunk = f.read(_FILE_ARCHIVE_CHUNK)
                final = f.tell() >= size
                resp = http_post(url, {'token': creds['token'], 'job_id': job_id,
                                        'seq': seq, 'final': final,
                                        'chunk': _b64.b64encode(chunk).decode('ascii') if chunk else ''})
                sent += len(chunk)
                seq += 1
                if not resp.get('continue', False) or final:
                    break   # server cancelled/rejected it, or this was the last chunk
        return {'cmd': cmd, 'rc': 0,
                'output': _json.dumps({'path': logical, 'job_id': job_id, 'bytes': sent})}
    except Exception as e:
        _archive_report_error(creds, dev_id, job_id, f'{type(e).__name__}: {e}')
        return {'cmd': cmd, 'rc': 1, 'output': _json.dumps({'error': str(e)[:300]})}
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


def _handle_file_op(cmd):
    """Execute a `files:` op → standard cmd_output dict with a JSON `output`.
    Never raises; the danger is path-traversal, blocked by a symlink-resolved
    allowlist re-check."""
    import json as _json
    import base64 as _b64
    res, rc = {}, 0
    try:
        bits = cmd.split(':', 3)            # files:<op>:<b64path>[:<b64content>]
        op = bits[1] if len(bits) > 1 else ''
        raw_path = (_b64.urlsafe_b64decode(bits[2]).decode('utf-8', 'replace')
                    if len(bits) > 2 else '')
        logical = os.path.normpath(raw_path)
        if not logical.startswith('/') or not _file_mgr_allowed(logical):
            return {'cmd': cmd, 'rc': 1,
                    'output': _json.dumps({'error': 'path is outside the allowlisted roots'})}
        if op in ('write', 'mkdir', 'delete') and _audit_mode():
            return {'cmd': cmd, 'rc': 126,
                    'output': _json.dumps({'error': 'agent is in audit (read-only) mode'})}
        fs = Path(host_path(logical))       # where it is actually readable
        # Symlink-resolved re-check: realpath the mapped path, un-map it back to
        # the host namespace, and confirm it is STILL inside an allowed root.
        real = os.path.realpath(fs)
        logical_real = unhost_path(real)
        if not _file_mgr_allowed(logical_real):
            return {'cmd': cmd, 'rc': 1,
                    'output': _json.dumps({'error': 'resolved path escapes the allowlisted roots'})}
        # v5.7.0 (SECURITY): read/list operate on the REALPATH-resolved target,
        # not the original `fs`. Re-opening `fs` re-followed the symlink, so a
        # local TOCTOU (swap an allowed symlink to /root/.ssh/id_rsa between the
        # check above and the read) bypassed the allowlist. `real` has no symlink
        # components at check time; the read additionally opens O_NOFOLLOW so the
        # leaf can't be swapped to a symlink after resolution (matches write).
        real_fs = Path(real)
        if op == 'list':
            entries = []
            for ent in sorted(real_fs.iterdir(), key=lambda e: e.name)[:2000]:
                try:
                    st = ent.lstat()
                    entries.append({
                        'name':  ent.name,
                        'type':  'dir' if ent.is_dir() else ('link' if ent.is_symlink() else 'file'),
                        'size':  st.st_size,
                        'mtime': int(st.st_mtime),
                        'mode':  oct(st.st_mode & 0o777)[2:],
                    })
                except Exception:
                    continue
            res = {'path': logical, 'entries': entries}
        elif op == 'read':
            # O_NOFOLLOW on the resolved leaf (see the TOCTOU note above); read +
            # stat come from the SAME fd so the reported size matches the bytes.
            _rfd = os.open(real, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(_rfd, 'rb') as _fh:
                data = _fh.read(FILE_MGR_MAX_READ + 1)
                _rsize = os.fstat(_fh.fileno()).st_size
            truncated = len(data) > FILE_MGR_MAX_READ
            data = data[:FILE_MGR_MAX_READ]
            try:
                text, binary = data.decode('utf-8'), False
            except UnicodeDecodeError:
                text, binary = '', True
            res = {'path': logical, 'binary': binary, 'truncated': truncated,
                   'size': _rsize, 'content': text}
            # W3-50: base64 the bytes for binary files so they can be downloaded
            # intact (text files keep the plain `content` for the editor).
            if binary:
                res['content_b64'] = _b64.b64encode(data).decode('ascii')
        elif op == 'write':
            content = (_b64.urlsafe_b64decode(bits[3]).decode('utf-8', 'replace')
                       if len(bits) > 3 else '')
            # v5.8.0 (SECURITY): mutate the REALPATH-verified target, not the raw
            # `fs` — matching the read/list hardening. Basing the tmp on `real`
            # means the parent dir is the already-resolved, already-allowlisted one,
            # closing the parent-symlink TOCTOU on world-writable roots (e.g. /tmp):
            # swapping a parent component after the realpath check can no longer
            # redirect the root-owned write outside the allowlist.
            tmp = real_fs.with_name(real_fs.name + '.rp-tmp')
            # O_NOFOLLOW: never follow a pre-placed symlink at the tmp path
            # (symlink-TOCTOU guard). O_TRUNC (not O_EXCL) so a stale .rp-tmp left
            # by an earlier crashed write is overwritten rather than wedging every
            # future write — matches the server's _write_json_atomic.
            _fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            try:
                os.write(_fd, content.encode('utf-8', 'replace'))
            finally:
                os.close(_fd)
            os.replace(str(tmp), real)      # atomic same-dir replace
            res = {'path': logical, 'written': len(content)}
        elif op == 'upload':
            # W3-50: binary-safe upload. bits[3]=base64 bytes, bits[4]='1' to
            # allow overwrite. Same realpath-verified target + tmp-then-rename
            # atomicity as write; O_EXCL on the final target when not overwriting.
            raw = _b64.urlsafe_b64decode(bits[3]) if len(bits) > 3 else b''
            allow_overwrite = len(bits) > 4 and bits[4] == '1'
            if not allow_overwrite and os.path.exists(real):
                rc, res = 1, {'error': 'file exists (overwrite not permitted)'}
            else:
                tmp = real_fs.with_name(real_fs.name + '.rp-tmp')
                _fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
                try:
                    os.write(_fd, raw)
                finally:
                    os.close(_fd)
                os.replace(str(tmp), real)
                res = {'path': logical, 'uploaded': len(raw)}
        elif op == 'mkdir':
            # v5.8.0 (SECURITY): create the realpath-verified target so the parent
            # is the allowlist-checked resolved dir, not a swappable symlink chain.
            real_fs.mkdir(parents=True, exist_ok=True)
            res = {'path': logical, 'created': True}
        elif op == 'delete':
            # v5.8.0 (SECURITY): delete via the realpath-verified target.
            if real_fs.is_dir():
                real_fs.rmdir()             # only empty dirs
            else:
                real_fs.unlink()
            res = {'path': logical, 'deleted': True}
        else:
            rc, res = 1, {'error': f'unknown file op: {op}'}
    except Exception as e:
        rc, res = 1, {'error': str(e)[:300]}
    return {'cmd': cmd, 'rc': rc, 'output': _json.dumps(res)}


def _run_service_action(cmd):
    """svc:<action>:<unit> — restart/start/stop a systemd unit via fixed argv (no
    shell). The unit was strictly validated server-side; double-check action here."""
    try:
        _, action, unit = cmd.split(':', 2)
    except ValueError:
        return {'cmd': cmd, 'output': 'malformed service action', 'rc': 2}
    if action not in ('restart', 'start', 'stop') or not unit:
        return {'cmd': cmd, 'output': f'refused: bad action/unit', 'rc': 2}
    log.info(f"Service action: systemctl {action} {unit}")
    try:
        r = subprocess.run(['systemctl', action, '--', unit],
                           capture_output=True, text=True, timeout=60)
        out = (r.stdout + r.stderr).strip() or f'systemctl {action} {unit} -> rc {r.returncode}'
        return {'cmd': cmd, 'output': out[:4000], 'rc': r.returncode}
    except Exception as e:
        return {'cmd': cmd, 'output': f'{type(e).__name__}: {e}', 'rc': 1}


def _run_process_kill(cmd):
    """kill:<SIG>:<pid> — send a signal to a PID via os.kill (no shell). PID 0/1
    are refused; SIG is from a fixed allowlist."""
    import signal as _signal
    try:
        _, sig, pid_s = cmd.split(':', 2)
        pid = int(pid_s)
    except ValueError:
        return {'cmd': cmd, 'output': 'malformed kill command', 'rc': 2}
    sigmap = {'TERM': _signal.SIGTERM, 'KILL': _signal.SIGKILL,
              'HUP': _signal.SIGHUP, 'INT': _signal.SIGINT}
    s = sigmap.get(sig.upper())
    if s is None or pid <= 1:
        return {'cmd': cmd, 'output': 'refused: bad signal or pid', 'rc': 2}
    log.info(f"Process kill: SIG{sig.upper()} -> pid {pid}")
    try:
        os.kill(pid, s)
        return {'cmd': cmd, 'output': f'sent SIG{sig.upper()} to pid {pid}', 'rc': 0}
    except ProcessLookupError:
        return {'cmd': cmd, 'output': f'pid {pid} not found (already gone)', 'rc': 0}
    except Exception as e:
        return {'cmd': cmd, 'output': f'{type(e).__name__}: {e}', 'rc': 1}


def execute_command(cmd):
    # v6.1.1: folder-as-tar archive is its own channel (see _handle_file_archive) —
    # check it BEFORE the general 'files:' prefix below, which would otherwise
    # route it into the single-result _handle_file_op op switch.
    if isinstance(cmd, str) and cmd.startswith('files:archive:'):
        return _handle_file_archive(cmd)
    # v5.1.0: file-manager ops carry their own audit-mode policy (reads allowed,
    # mutations refused) so dispatch them BEFORE the blanket audit-mode guard.
    if isinstance(cmd, str) and cmd.startswith('files:'):
        return _handle_file_op(cmd)
    # v4.11.0: audit (read-only) mode refuses EVERY server command. The result
    # rides the normal cmd_output channel so the operator sees the refusal in the
    # UI. Read-only assessments and the passive heartbeat are unaffected (they
    # don't come through here).
    if _audit_mode():
        log.warning(f"Audit mode (read-only): refusing command {str(cmd)[:60]!r}")
        return {'cmd': cmd, 'output': 'refused: agent is in audit (read-only) mode',
                'rc': 126}
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
    elif cmd.startswith('cron:'):
        # v5.1.0: cron / timer mutation (audit mode already refused above).
        return _handle_cron_op(cmd)
    elif cmd.startswith('svc:'):
        # Service restart/start/stop (audit mode already refused above).
        return _run_service_action(cmd)
    elif cmd.startswith('kill:'):
        # Send a signal to a PID (audit mode already refused above).
        return _run_process_kill(cmd)
    elif cmd.startswith('exec:'):
        shell_cmd = cmd[5:]
        import re as _tag_re
        # v5.0.0 (#F3): optional per-command timeout — the server may prefix the
        # shell with "to=<seconds>:". Parse it off first (before tag routing) and
        # clamp to 1..3600s; absent → the default heuristic below applies.
        exec_timeout_override = None
        _to_m = _tag_re.match(r'^to=(\d{1,5}):(.*)$', shell_cmd, _tag_re.DOTALL)
        if _to_m:
            exec_timeout_override = max(1, min(int(_to_m.group(1)), 3600))
            shell_cmd = _to_m.group(2)
        # v3.0.1: Tag-routed commands. The server prefixes certain commands
        # with "#<scope>:<action_id>#" so the cmd_output ingestion can route
        # the full stdout to a per-scope log dir (ACME, mitigate). Strip the
        # tag before passing to the shell; keep it in the returned `cmd`
        # field so the server can still recognise it.
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
                'apt-get -y upgrade', 'dnf -y upgrade', 'dnf upgrade', 'yum -y upgrade',
                'pacman -Syu', 'zypper', 'apk upgrade', 'remotepower_update.log'))
            # v5.0.0 (#F3): an explicit per-command timeout wins over the heuristic.
            exec_timeout = exec_timeout_override or (1800 if _is_upgrade else 300)
            # nosec B602 — this IS the agent's command channel: an authenticated
            # admin-pushed command run as the agent user (root by design). Guarded
            # by token auth + audit-mode refusal + the server's allowlist/4-eyes/
            # quarantine controls. shell=True is intentional (operators paste shell).
            # nosemgrep: subprocess-shell-true -- see the B602 note above: this
            # is the agent's authenticated, audited, allowlist/4-eyes-gated root
            # command channel; shell semantics are the feature, not a mistake.
            result = subprocess.run(actual_shell, shell=True, capture_output=True, text=True, timeout=exec_timeout)  # nosec B602
            output = (result.stdout + result.stderr).strip()
            log.info(f"Command output (rc={result.returncode}): {output[:200]}")
            # v1.10.0: bump output cap to 256 KB for package-upgrade runs.
            # v3.0.1: also bump for acme.sh runs and mitigation diagnostics
            # — their output is verbose (cert chains, journalctl dumps, du
            # output).
            is_pkg_upgrade = any(needle in actual_shell for needle in
                                 ('apt-get -y upgrade', 'dnf -y upgrade', 'dnf upgrade', 'pacman -Syu'))
            is_tagged      = bool(acme_tag_m or mitigate_tag_m)
            # v5.0.0: 4 KB was too small for routine diagnostics (zpool status -v,
            # btrfs subvolume list, systemctl status, …) — they were silently cut
            # mid-line. 32 KB covers those; upgrades/tagged keep the 256 KB cap.
            cap = 256 * 1024 if (is_pkg_upgrade or is_tagged) else 32 * 1024
            out = output[:cap]
            if len(output) > cap:
                out += '\n…(output truncated)'
            return {'cmd': cmd, 'output': out, 'rc': result.returncode}
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
CONTAINER_ALLOWED_ACTIONS = {'start', 'stop', 'restart', 'pause', 'unpause',
                             'logs', 'update'}
CONTAINER_ACTION_TIMEOUT_S = 60
CONTAINER_PULL_TIMEOUT_S   = 300   # image pull can be slow on a big image / link
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

    # v5.8.0 (B1.1): "update" = pull the image + recreate a STANDALONE container
    # with the same config. Compose-managed containers are refused (they have a
    # working update path via compose:update). Distinct control flow from the
    # single-verb docker actions below.
    if action == 'update':
        return _run_container_update(cmd, runtime, container_id)

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



def _container_inspect(runtime, container_id):
    """Return the parsed `<runtime> inspect` object for a container, or None."""
    try:
        r = subprocess.run([runtime, 'inspect', container_id],
                           capture_output=True, text=True,
                           timeout=CONTAINER_ACTION_TIMEOUT_S)
        if r.returncode != 0:
            return None
        data = json.loads(r.stdout or '[]')
        return data[0] if isinstance(data, list) and data else None
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return None


def _image_id(runtime, image_ref):
    """The local image ID (sha256:…) for a ref, or '' if not present."""
    try:
        r = subprocess.run([runtime, 'image', 'inspect', '--format', '{{.Id}}',
                            image_ref], capture_output=True, text=True,
                           timeout=CONTAINER_ACTION_TIMEOUT_S)
        return (r.stdout or '').strip() if r.returncode == 0 else ''
    except (subprocess.TimeoutExpired, OSError):
        return ''


def _container_run_argv(runtime, info):
    """Reconstruct a `<runtime> run -d` argv from an inspect object, covering the
    common fields (name, restart policy, env, ports, mounts, network, labels,
    privileged, entrypoint/cmd). Returns (argv, image) or (None, reason).

    Conservative by design: if inspect reveals config we can't faithfully
    reproduce, the caller aborts rather than recreate a subtly-different
    container (the plan's "refuse when unsure" rule)."""
    cfg = info.get('Config') or {}
    host = info.get('HostConfig') or {}
    image = cfg.get('Image') or ''
    if not image:
        return None, 'inspect has no Config.Image'
    name = (info.get('Name') or '').lstrip('/')
    argv = [runtime, 'run', '-d']
    if name:
        argv += ['--name', name]
    # restart policy
    rp = (host.get('RestartPolicy') or {}).get('Name') or ''
    if rp and rp != 'no':
        mrc = (host.get('RestartPolicy') or {}).get('MaximumRetryCount') or 0
        argv += ['--restart', f'{rp}:{mrc}' if rp == 'on-failure' and mrc else rp]
    # env
    for e in (cfg.get('Env') or []):
        argv += ['-e', e]
    # labels — skip compose/podman-internal ones (compose is refused upstream)
    for k, v in (cfg.get('Labels') or {}).items():
        if k.startswith(('com.docker.compose', 'io.podman', 'io.buildah',
                         'org.opencontainers.image')):
            continue
        argv += ['--label', f'{k}={v}']
    # network mode
    netmode = host.get('NetworkMode') or ''
    if netmode and netmode not in ('default', 'bridge'):
        argv += ['--network', netmode]
    if host.get('Privileged'):
        argv += ['--privileged']
    # port bindings: {"80/tcp": [{"HostIp":"","HostPort":"8080"}]}
    for cport, binds in (host.get('PortBindings') or {}).items():
        for b in (binds or []):
            hip = b.get('HostIp') or ''
            hport = b.get('HostPort') or ''
            spec = ':'.join(x for x in (hip, hport, cport) if x) if (hip or hport) else cport
            argv += ['-p', spec]
    # mounts: prefer HostConfig.Binds (source:dest:mode); fall back to Mounts
    binds = host.get('Binds')
    if binds:
        for b in binds:
            argv += ['-v', b]
    else:
        for m in (info.get('Mounts') or []):
            if m.get('Type') == 'bind' and m.get('Source') and m.get('Destination'):
                ro = '' if m.get('RW', True) else ':ro'
                argv += ['-v', f"{m['Source']}:{m['Destination']}{ro}"]
            elif m.get('Type') == 'volume' and m.get('Name') and m.get('Destination'):
                argv += ['-v', f"{m['Name']}:{m['Destination']}"]
    # entrypoint override (only if explicitly set on the container)
    ep = cfg.get('Entrypoint')
    if isinstance(ep, list) and ep:
        argv += ['--entrypoint', ep[0]]
        # extra entrypoint args are rare; fold into cmd below if present
    argv.append(image)
    # command
    cmd = cfg.get('Cmd')
    if isinstance(cmd, list) and cmd:
        argv += cmd
    return argv, image


def _run_container_update(cmd, runtime, container_id):
    """Pull the container's image and recreate it with the same config. No-op
    (no recreate) when the image is already current. Refuses compose-managed
    containers. Every step's outcome is reported in the command output so the
    operator can audit exactly what happened."""
    if not _which(runtime):
        return {'cmd': cmd, 'output': f'{runtime} not installed', 'rc': -1}
    info = _container_inspect(runtime, container_id)
    if info is None:
        return {'cmd': cmd, 'output': 'container not found / inspect failed', 'rc': -1}
    labels = (info.get('Config') or {}).get('Labels') or {}
    if labels.get('com.docker.compose.project'):
        return {'cmd': cmd, 'rc': -1, 'output':
                'container is compose-managed — update it with the compose '
                'stack action, not the standalone update'}
    image = (info.get('Config') or {}).get('Image') or ''
    if not image:
        return {'cmd': cmd, 'output': 'container has no image ref', 'rc': -1}

    before = _image_id(runtime, image)
    log.info(f"container update: pulling {image}")
    try:
        pull = subprocess.run([runtime, 'pull', image], capture_output=True,
                              text=True, timeout=CONTAINER_PULL_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return {'cmd': cmd, 'output': f'pull TIMEOUT for {image}', 'rc': -1}
    if pull.returncode != 0:
        out = (pull.stdout + pull.stderr).strip()[:CONTAINER_OUT_CAP]
        return {'cmd': cmd, 'output': f'pull failed: {out}', 'rc': pull.returncode}
    after = _image_id(runtime, image)
    if before and after and before == after:
        return {'cmd': cmd, 'rc': 0,
                'output': f'{image} already up to date — no recreate needed'}

    argv, image_or_reason = _container_run_argv(runtime, info)
    if argv is None:
        return {'cmd': cmd, 'rc': -1,
                'output': f'cannot safely recreate: {image_or_reason} '
                          f'(image pulled but container left running)'}

    name = (info.get('Name') or '').lstrip('/') or container_id
    # Recreate: stop + rm the old, then run the reconstructed argv. If run fails
    # we surface it loudly — the old container is already gone, so the operator
    # must act (this is why "already up to date" short-circuits above).
    steps = [f'pulled {image} (id {before[:19]}→{after[:19]})']
    try:
        subprocess.run([runtime, 'stop', container_id], capture_output=True,
                       text=True, timeout=CONTAINER_ACTION_TIMEOUT_S)
        subprocess.run([runtime, 'rm', container_id], capture_output=True,
                       text=True, timeout=CONTAINER_ACTION_TIMEOUT_S)
        steps.append(f'removed old container {name}')
        run = subprocess.run(argv, capture_output=True, text=True,
                             timeout=CONTAINER_ACTION_TIMEOUT_S)
        out = (run.stdout + run.stderr).strip()[:CONTAINER_OUT_CAP]
        if run.returncode == 0:
            steps.append(f'recreated {name} on the new image')
            log.info(f"container update ok: {name}")
            return {'cmd': cmd, 'rc': 0, 'output': '; '.join(steps) + f'\n{out}'}
        steps.append(f'RECREATE FAILED (rc={run.returncode}): {out}')
        log.error(f"container update recreate failed: {name}")
        return {'cmd': cmd, 'rc': run.returncode, 'output': '; '.join(steps)}
    except subprocess.TimeoutExpired:
        return {'cmd': cmd, 'rc': -1, 'output': '; '.join(steps) + '; TIMEOUT during recreate'}
    except Exception as e:
        return {'cmd': cmd, 'rc': -1, 'output': '; '.join(steps) + f'; error: {e}'}


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

    # v5.0.0: audit (read-only) mode must refuse this command channel too.
    # Custom scripts run arbitrary server-supplied bash as root — exactly the
    # kind of host mutation /etc/remotepower/audit-mode is meant to block. The
    # other three channels (execute_command, apply_host_config, check_for_update)
    # already early-return on _audit_mode(); this is the fourth.
    if _audit_mode():
        log.info('Audit mode (read-only): skipping custom scripts')
        return {}

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
        # host_path(): in a container this reads the bind-mounted host rootfs,
        # not the slim image. Idempotent — an already-mapped path passes through.
        try:
            return Path(host_path(path)).read_text(errors='replace')
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
    # Debian/Ubuntu: the monolithic /etc/apt/sources.list is often EMPTY or
    # absent on modern releases — the real repos live in
    # /etc/apt/sources.list.d/ as classic *.list fragments and, on Ubuntu
    # 24.04+/Debian 12+, deb822 *.sources files. Reading only sources.list
    # therefore reported nothing on those hosts ("Fetch current" came back
    # empty). Read the main file AND the drop-in directory so the reported
    # repos match what apt actually uses. RHEL/Fedora: concatenate *.repo.
    _apt_main = Path(host_path('/etc/apt/sources.list'))
    _apt_dir = Path(host_path('/etc/apt/sources.list.d'))
    if _apt_main.exists() or _apt_dir.is_dir():
        parts = []
        if _apt_main.exists():
            _m = _read('/etc/apt/sources.list').strip()
            if _m:
                parts.append('# /etc/apt/sources.list\n' + _m)
        if _apt_dir.is_dir():
            for f in (sorted(_apt_dir.glob('*.list'))
                      + sorted(_apt_dir.glob('*.sources'))):
                _c = _read(str(f)).strip()
                if _c:
                    parts.append(f'# {f.name}\n' + _c)
        current['repos'] = '\n\n'.join(parts)
    elif Path(host_path('/etc/yum.repos.d')).is_dir():
        # Concatenate all .repo files
        parts = []
        for f in sorted(Path(host_path('/etc/yum.repos.d')).glob('*.repo')):
            parts.append(f'# {f.name}\n' + _read(str(f)))
        current['repos'] = '\n'.join(parts)

    # ── netplan ──────────────────────────────────────────────────────────────
    netplan_dir = Path(host_path('/etc/netplan'))
    if netplan_dir.is_dir():
        for f in sorted(netplan_dir.glob('*.yaml')):
            current['netplan'] = _read(str(f))
            break  # first file only; apply writes 01-remotepower.yaml

    # ── nmcli ────────────────────────────────────────────────────────────────
    nm_conn = Path(host_path('/etc/NetworkManager/system-connections/remotepower-managed.nmconnection'))
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
    # In a container, _pwd/_grp resolve the CONTAINER's NSS, not the Docker
    # host — so the drift view would report the slim image's accounts. Parse the
    # host's /etc/passwd + /etc/group text (host_path'd via _safe_read) instead.
    # Natively, keep getpwall/getgrall so NSS/LDAP/SSSD users (which never appear
    # in a flat /etc/passwd) are still captured.
    users = []
    try:
        if IN_CONTAINER:
            memb = {}   # user -> [supplementary group names]
            for ln in (_safe_read('/etc/group', 200_000) or '').splitlines():
                gf = ln.split(':')
                if len(gf) >= 4:
                    for m in gf[3].split(','):
                        if m:
                            memb.setdefault(m, []).append(gf[0])
            for ln in (_safe_read('/etc/passwd', 200_000) or '').splitlines():
                pf = ln.split(':')
                if len(pf) < 7:
                    continue
                try:
                    uid = int(pf[2])
                except ValueError:
                    continue
                name, home, shell = pf[0], pf[5], pf[6]
                if uid < 1000 or name == 'nobody':
                    continue
                ak_path = Path(host_path(os.path.join(home, '.ssh', 'authorized_keys')))
                ak = ''
                try:
                    ak = ak_path.read_text(errors='replace') if ak_path.exists() else ''
                except OSError:
                    pass
                users.append({'name': name, 'shell': shell,
                              'groups': memb.get(name, []), 'authorized_keys': ak})
        else:
            for pw in _pwd.getpwall():
                if pw.pw_uid < 1000 or pw.pw_name == 'nobody':
                    continue
                groups = [g.gr_name for g in _grp.getgrall() if pw.pw_name in g.gr_mem]
                ak_path = Path(host_path(os.path.join(pw.pw_dir, '.ssh', 'authorized_keys')))
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
        if IN_CONTAINER:
            groups = []
            for ln in (_safe_read('/etc/group', 200_000) or '').splitlines():
                gf = ln.split(':')
                if len(gf) >= 3:
                    try:
                        gid = int(gf[2])
                    except ValueError:
                        continue
                    if gid >= 1000:
                        groups.append({'name': gf[0], 'gid': gid})
            current['groups'] = groups
        else:
            current['groups'] = [
                {'name': g.gr_name, 'gid': g.gr_gid}
                for g in _grp.getgrall()
                if g.gr_gid >= 1000
            ]
    except Exception:
        current['groups'] = []

    # ── sudoers ──────────────────────────────────────────────────────────────
    sudoers_f = Path(host_path('/etc/sudoers.d/remotepower'))
    current['sudoers'] = _read(str(sudoers_f)) if sudoers_f.exists() else ''

    # ── motd ─────────────────────────────────────────────────────────────────
    current['motd'] = _read('/etc/motd')

    # ── logrotate ────────────────────────────────────────────────────────────
    lr_path = Path(host_path('/etc/logrotate.d/remotepower'))
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

    # v4.11.0: audit (read-only) mode never writes host config.
    if _audit_mode():
        log.warning("Audit mode (read-only): refusing host-config apply")
        return {'_refused': 'agent is in audit (read-only) mode'}

    # Containerized agents monitor a Docker HOST read-only; applying host
    # config from inside a container would mutate the slim image (or, via a
    # bind-mounted rootfs, the host) with no operator expectation of it. Disable
    # apply in-container, matching self-update / lynis / oscap.
    if IN_CONTAINER:
        return {'_disabled': 'apply-host-config is disabled in containerized mode'}

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
            ok, out = _run(['systemctl', 'enable', '--now', '--', svc])
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
            # v5.6.0 pentest: validate the username (POSIX) so a name like "-Mx"
            # can't be read by useradd/usermod as an option; also pass it after a
            # `--` end-of-options guard. shell follows `-s` so it's never an option.
            if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', name):
                errs.append(f'{name}: invalid username')
                continue
            try:
                try:
                    pw = _pwd.getpwnam(name)
                    # User exists — update shell and groups
                    _run(['usermod', '-s', u.get('shell', '/bin/bash')] +
                         (['-G', ','.join(u['groups'])] if u.get('groups') else []) +
                         ['--', name])
                except KeyError:
                    # Create user
                    cmd = ['useradd', '-m', '-s', u.get('shell', '/bin/bash')]
                    if u.get('groups'):
                        cmd += ['-G', ','.join(u['groups'])]
                    cmd += ['--', name]
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
        hp = host_path(p)   # containerized agent: count the host's maildir
        try:
            if not os.path.isdir(hp):
                entry['error'] = 'not_a_directory'
                out[p] = entry
                continue
            n = 0
            with os.scandir(hp) as it:
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
        # Containerized agent: hash the Docker HOST's file, not the slim image's
        # copy. host_path() is identity natively. The report stays keyed by the
        # clean path `p` (mirrors _eval_one_agent_check).
        hp = host_path(p)
        try:
            st = os.stat(hp)
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
            with open(hp, 'rb') as fh:
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
# v6.2.2: delta sysinfo — the heavy, slow-moving sysinfo fields the agent may
# OMIT from a heartbeat when their content is unchanged since the last full
# send. The server merges its stored copy back in at ingest (so downstream
# consumers always see a complete sysinfo) and lists anything it can't merge in
# the response's delta_resend. Never omitted until the server has advertised
# `delta_ok` — a new agent against an old server keeps sending full payloads.
_DELTA_SYSINFO_FIELDS = ('packages', 'listening_ports', 'network',
                         'ssh_hostkeys', 'usb', 'autoupdate')


def _stable_hash(value):
    """Content hash for delta-sysinfo comparison (agent-local only — the server
    never recomputes it, so the exact scheme is free to change)."""
    blob = json.dumps(value, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def heartbeat(creds, interval=POLL_INTERVAL):
    server = creds['server_url']; dev_id = creds['device_id']; token = creds['token']
    log.info(f"RemotePower agent v{VERSION} starting. Server: {server}, Device: {dev_id}")
    log.info(f"Poll: {interval}s | sysinfo every {SYSINFO_EVERY} polls | patches every {PATCH_EVERY} polls")

    poll_count = 0; cached_patch = None
    # v1.8.0: server pushes watched services + log rules in heartbeat response
    services_watched = []
    log_watch_rules  = []
    # v6.2.2: delta sysinfo. delta_ok flips on when a heartbeat RESPONSE
    # advertises it; delta_hashes maps field → content hash of the last value
    # the server confirmed storing (updated only on a non-busy response, so a
    # failed POST or a 202 can never leave the server holding stale data we
    # then stop sending).
    delta_ok = False
    delta_hashes = {}

    # v6.1.1 (#1): push-channel wake nudge. wake_event is set by the
    # background listener thread (started lazily below, once, only if the
    # server advertises push_enabled) whenever a nudge arrives; the poll
    # loop's sleep at the bottom watches it to cut the wait short. Starting
    # the thread is a pure opt-in latency optimization -- if it's never
    # started (server doesn't advertise it, or websockets isn't installed),
    # every sleep just runs its full `interval` exactly as before.
    _push_wake_event = threading.Event()
    _push_stop_event = threading.Event()
    _push_thread_started = False

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
    _canary_cfg = []           # W3-38: canary/honeytoken file config from the server
    # v2.4.3: server pushes mailbox directory paths whose file count we
    # report (Maildir-style unread-message monitoring).
    mailbox_paths = []
    # v2.4.5: set true when the server requests an out-of-band package
    # scan; consumed (and cleared) on the next poll.
    force_pkg_scan = False
    # v3.0.2: one-shot ACME rescan request from server (operator clicked
    # "Force rescan" after renewing via CLI; skips the hourly cadence).
    force_acme_rescan = False
    # v4.9.0: one-shot DNS-credential harvest from acme.sh's account.conf
    # (admin clicked "Import from agent" on the DNS page).
    force_dns_harvest = False
    # v3.14.0 #35: secrets-on-disk scan. Opt-in — stays off until the server
    # pushes secrets_scan_enabled; paths come from the server too (defaults if
    # unset). force flag skips the 6h cadence for an on-demand rescan.
    secrets_scan_on = False
    secrets_scan_paths = None
    force_secrets_scan = False
    # W6-34: container-image CVE scan (trivy), opt-in + slow.
    image_scan_on = False
    force_image_scan = False
    last_image_scan_ts = _load_image_scan_ts()   # v6.1.2: survives agent restarts
    last_secrets_scan_ts = _load_secrets_scan_ts()   # v6.1.2: same restart fix
    # v6.2.0: host-wide disk-usage explorer — opt-in, slow (~12h), server-pushed
    # paths, same persisted-timestamp cadence (never poll_count % N).
    du_scan_on = False
    du_scan_paths = None
    force_du_scan = False
    last_du_scan_ts = _load_du_scan_ts()
    # v6.2.0: PII / sensitive-data scan — opt-in, slow (~24h), server-pushed paths,
    # same persisted-timestamp cadence (never poll_count % N).
    pii_scan_on = False
    pii_scan_paths = None
    force_pii_scan = False
    last_pii_scan_ts = _load_pii_scan_ts()
    # v6.3.1: hail-mary log sweep — one-shot only, no cadence: it fires purely
    # on the operator's "Diagnose from logs" click (force_log_sweep).
    force_log_sweep = False
    # v6.1.2: mDNS LAN browse — server-pushed opt-in, same shape as image_scan_on.
    mdns_on = False
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
    # v4.1.0: agent-side custom checks pushed by the server (file/log/job checks).
    # Evaluated on-host each cycle; results reported in sysinfo.custom_check_results.
    agent_checks = []

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
    # v4.6.0 (SECURITY): route this stash through the O_NOFOLLOW state-file
    # helpers like every other marker — the old write_text/read_text on a
    # predictable /tmp fallback let a local attacker pre-plant a symlink and
    # make the agent clobber an attacker-chosen file. _safe_state_write writes
    # the full payload safely; the read below uses an O_NOFOLLOW full read
    # (the shared _safe_state_read caps at 4 KB, too small for cmd output).

    def _stash_pending_cmd_output(result, cmd):
        """Persist cmd_output to disk (O_NOFOLLOW) so the next heartbeat can retry it."""
        _safe_state_write('pending-cmd.json', json.dumps({
            'cmd_output': result,
            'executed_command': cmd,
            'stashed_at': int(time.time()),
        }))
        log.info("Stashed cmd_output for retry")

    def _load_pending_cmd_output():
        """Pop any stashed cmd_output. Returns dict or None.

        We delete the file *before* the heartbeat goes out so a server
        that's still flapping doesn't cause us to retry forever and pile
        up duplicate entries. If the heartbeat then fails, the data is
        lost — but the alternative (replay until success) is worse for
        an upgrade log that might already be partially recorded.
        """
        raw = None
        for cand in (STATE_DIR / 'pending-cmd.json',
                     Path('/tmp/remotepower-pending-cmd.json')):
            try:
                fd = os.open(str(cand), os.O_RDONLY | os.O_NOFOLLOW)
            except (FileNotFoundError, OSError):
                continue
            try:
                chunks = []
                while True:
                    b = os.read(fd, 65536)
                    if not b:
                        break
                    chunks.append(b)
                raw = b''.join(chunks).decode(errors='replace')
            finally:
                os.close(fd)
            break
        # Delete before the heartbeat goes out (see docstring).
        _safe_state_unlink('pending-cmd.json')
        if raw is None:
            return None
        try:
            data = json.loads(raw)
            log.info("Loaded stashed cmd_output for retry")
            return data
        except Exception as e:
            log.warning(f"Failed to read stashed cmd_output: {e}")
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
        # v6.2.2: per-iteration — holds the delta-field hashes SENT FULL this
        # beat, committed to delta_hashes only on a non-busy response. Reset
        # here so a light (no-sysinfo) poll can never commit a prior beat's.
        _delta_sent_full = {}
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
            _bv = collect_backup_verify(_backup_monitors)   # v4.10.0: integrity checks
            if _bv:
                payload['backup_verify'] = _bv
            # W6-43: sandboxed restore drills (opt-in per monitor; rate-gated).
            try:
                _rd = run_restore_drills(_backup_monitors)
                if _rd:
                    payload['restore_drills'] = _rd
            except Exception as e:
                log.debug(f'restore drill error: {e}')

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
        # W3-37 (near-real-time FIM): a cheap per-poll mtime scan of the watched
        # list forces an immediate drift re-hash when a file changed, so drift
        # surfaces within ~one heartbeat (~60s) instead of the ~1h DRIFT_EVERY
        # cadence — no inotify/threading, works everywhere stat() does.
        _drift_due = watched_files and poll_count > 1 and (
            poll_count == 2 or poll_count % DRIFT_EVERY == 0)
        if watched_files and poll_count > 1 and not _drift_due:
            try:
                if _watched_files_changed(watched_files):
                    _drift_due = True
            except Exception:
                pass
        if _drift_due:
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

        # v4.9.0: one-shot DNS-credential harvest (admin-triggered import). Read
        # acme.sh's account.conf and send the SAVED_* provider creds ONCE, over
        # the authenticated heartbeat — never via the command-output channel.
        if force_dns_harvest:
            try:
                payload['dns_creds_harvest'] = collect_acme_dns_creds()
                log.info('Reporting acme.sh DNS credentials for server-side import')
            except Exception as e:
                log.debug(f'DNS cred harvest error: {e}')
            force_dns_harvest = False

        # v3.14.0 #35: secrets-on-disk scan — opt-in, bounded, redacting. Only
        # runs once the server has enabled it; every ~6h or on a force request.
        # v6.1.2: monotonic due-time (survives restarts), not poll_count % N.
        _sec_due = (time.time() - last_secrets_scan_ts) >= SECRETS_SCAN_INTERVAL_S
        if secrets_scan_on and (_sec_due or force_secrets_scan):
            try:
                payload['secret_findings'] = collect_secret_findings(secrets_scan_paths)
                log.debug(f'secrets scan: {len(payload["secret_findings"])} finding(s)')
                last_secrets_scan_ts = time.time()
                _save_secrets_scan_ts(last_secrets_scan_ts)
            except Exception as e:
                log.debug(f'secrets scan error: {e}')
            force_secrets_scan = False

        # v6.2.0: host-wide disk-usage explorer. Opt-in, ~12h, or on demand.
        _du_due = (time.time() - last_du_scan_ts) >= DU_SCAN_INTERVAL_S
        if du_scan_on and (_du_due or force_du_scan):
            try:
                _du = collect_disk_usage(du_scan_paths)
                if _du:
                    payload['disk_usage'] = _du
                log.debug(f'du scan: {len(_du)} path(s)')
                # Stamp on every real ATTEMPT (not only on success): a host whose
                # /srv takes 40s to walk must not retry it on every single poll.
                last_du_scan_ts = time.time()
                _save_du_scan_ts(last_du_scan_ts)
            except Exception as e:
                log.debug(f'du scan error: {e}')
            force_du_scan = False

        # v6.2.0: PII / sensitive-data scan. Opt-in, ~24h, or on demand.
        _pii_due = (time.time() - last_pii_scan_ts) >= PII_SCAN_INTERVAL_S
        if pii_scan_on and (_pii_due or force_pii_scan):
            try:
                payload['pii_findings'] = collect_pii_findings(pii_scan_paths)
                log.debug(f'pii scan: {len(payload["pii_findings"])} finding(s)')
                # Stamp on every real ATTEMPT (not only on success) — a host with a
                # huge /srv must not re-walk it on every poll.
                last_pii_scan_ts = time.time()
                _save_pii_scan_ts(last_pii_scan_ts)
            except Exception as e:
                log.debug(f'pii scan error: {e}')
            force_pii_scan = False

        # v6.3.1: hail-mary log sweep — one-shot, operator-requested only.
        if force_log_sweep:
            try:
                payload['log_sweep'] = collect_log_sweep()
                log.info(f"log sweep: {len(payload['log_sweep'].get('files') or [])} "
                         f"file tail(s) collected")
            except Exception as e:
                log.debug(f'log sweep error: {e}')
            force_log_sweep = False

        # W6-34: container-image CVE scan (trivy) — opt-in, slow (~24h) cadence.
        # Only images of RUNNING containers; feature-invisible without trivy.
        #
        # v6.1.2: the cadence is now a TIMESTAMP, not `poll_count % 1440`.
        # poll_count is process-local, so it reset to 0 on every agent restart
        # (self-update, reboot, unit restart) — any host restarting its agent
        # more often than 24h NEVER hit the modulo and so never scanned, which
        # is why hosts with trivy installed and the feature enabled still showed
        # an empty Image-CVE page. A monotonic due-time survives restarts.
        _img_due = (time.time() - last_image_scan_ts) >= IMAGE_SCAN_INTERVAL_S
        if image_scan_on and (_img_due or force_image_scan):
            try:
                _imgs = [c.get('image') for c in (payload.get('containers') or [])
                         if c.get('image')]
                if not _imgs and (_which('docker') or _which('podman')):
                    _imgs = [c.get('image') for c in (get_containers() or []) if c.get('image')]
                if _imgs:
                    log.info(f'image cve scan: {len(set(_imgs))} image(s) via trivy')
                    payload['image_cves'] = collect_image_cves(_imgs)
                    # Stamp only on a real attempt, so a host with no containers
                    # re-checks promptly once it gets some.
                    last_image_scan_ts = time.time()
                    _save_image_scan_ts(last_image_scan_ts)
                elif force_image_scan:
                    log.info('image cve scan requested but no running containers found')
            except Exception as e:
                log.debug(f'image cve scan error: {e}')
            force_image_scan = False

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

        # v2.6.0: desired host config is applied by the response handler below
        # the moment it changes (including its first arrival — host_config_desired
        # starts None). The old unconditional poll_count==2 re-apply here was pure
        # redundancy: it re-applied what the response handler had already applied on
        # poll 1, forcing a second netplan/nmcli/service reload on every boot.
        # Removed in the v6.2.0 bug hunt — the apply-on-change path is the single
        # source of truth. Current state is NOT sent in the heartbeat; it is
        # collected on-demand via the host-config-collect exec command.

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

        # v6.1.2: `docker system df` — the disk-footprint breakdown. This one
        # is EXPENSIVE (docker walks the whole layer store, and `-v` walks
        # every volume), so it rides its own much slower cadence rather than
        # the container listing's. Disk usage doesn't change by the minute.
        # v6.1.2: also on the FIRST heartbeat (poll_count==1), so a host that
        # restarts its agent more often than DOCKER_DF_EVERY still reports it —
        # the same restart-churn gap the hardware block below already guards.
        # v6.2.2 FIX: this block used to be nested INSIDE the container-listing
        # `if poll_count > 1 …` above, which made its own `poll_count == 1`
        # branch unreachable dead code — so a churny host NEVER reported
        # docker_df (the trivy/force_image_scan restart-churn class). Hoisted to
        # its own guard, mirroring the hardware block's correct pattern.
        if (poll_count == 1 or poll_count % DOCKER_DF_EVERY == 0) \
                and (_which('docker') or _which('podman')):
            try:
                df = get_docker_disk_usage()
                if df:
                    payload['docker_df'] = df
            except Exception as e:
                log.debug(f'docker df error: {e}')

        # v3.4.0: hardware / health inventory on the slow cadence — smartctl,
        # dmidecode, sensors and the kernel check aren't free, so they ride
        # alongside containers rather than every heartbeat. Each is wrapped:
        # a probe failure (missing tool, no root) leaves the key absent and
        # the server keeps the last known value.
        # v4.7.0: also send the hardware/GPU inventory on the FIRST heartbeat so a
        # freshly enrolled or just-restarted agent shows SMART/GPU/etc. within a
        # minute instead of waiting a full slow cycle (≈5 min).
        if poll_count == 1 or (poll_count > 1 and poll_count % CONTAINER_CHECK_EVERY == 0):
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
            # v6.1.2: mDNS service discovery — a LAN browse, so it rides the same
            # slow cadence as the docker-df walk rather than every sysinfo poll.
            # Only when the server asks for it (mdns_enabled), because browsing
            # the LAN from every host in the fleet would be redundant noise: one
            # agent per segment sees the same advertisements as all of them.
            if mdns_on and (poll_count == 1 or poll_count % DOCKER_DF_EVERY == 0):
                try:
                    svcs = get_mdns_services()
                    if svcs:
                        payload['mdns'] = svcs
                except Exception as e:
                    log.debug(f'mdns probe error: {e}')
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
                'uptime_seconds': get_uptime_seconds(),   # v6.1.2: sortable uptime
                'platform': platform.platform(),
                'kernel':   platform.release(),     # v3.13.0: CMDB Hardware panel
                'cpu':      _cpu_model(),            # v3.13.0: CPU model string
                'packages': cached_patch,
                'network':  get_network_info(),
                'network_io': collect_net_io(),   # v3.14.0 #37: per-iface bandwidth
                'audit_mode': _audit_mode(),      # v4.11.0: observe-only (read-only) agent
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
            # v4.1.0: evaluate server-pushed agent-side custom checks on-host.
            if agent_checks:
                try:
                    sysinfo['custom_check_results'] = eval_agent_checks(agent_checks)
                except Exception as e:
                    log.debug(f'agent checks error: {e}')
            # W3-11: operator-supplied custom metrics (textfile collector).
            try:
                _cm = collect_custom_metrics()
                if _cm:
                    sysinfo['custom_metrics'] = _cm
            except Exception as e:
                log.debug(f'custom metrics error: {e}')
            # v6.1.2: ECC counters / zram / auto-update posture / SSH host-key
            # fingerprints. The server's safe_si reads all four from the sysinfo
            # dict, so they MUST be written here — inside `if send_sysinfo:` and
            # AFTER sysinfo is built. (They previously sat in the container-cadence
            # block above, referencing `sysinfo` before it existed → an
            # UnboundLocalError swallowed by each try/except, so none of them were
            # ever sent and hostkey_changed could never fire.) Each is a cheap
            # read-only sniff and feature-invisible on a host without it (no EDAC →
            # {}, no zram → [], no auto-updater → enabled:false).
            try:
                ecc = get_ecc_errors()
                if ecc:
                    sysinfo['ecc'] = ecc
            except Exception as e:
                log.debug(f'ecc probe error: {e}')
            try:
                zr = get_zram()
                if zr:
                    sysinfo['zram'] = zr
            except Exception as e:
                log.debug(f'zram probe error: {e}')
            try:
                sysinfo['autoupdate'] = get_autoupdate_posture()
            except Exception as e:
                log.debug(f'autoupdate probe error: {e}')
            try:
                hk = get_ssh_hostkeys()
                if hk:
                    sysinfo['ssh_hostkeys'] = hk
            except Exception as e:
                log.debug(f'ssh hostkey probe error: {e}')
            try:
                # v6.2.0: USB inventory → the usb_device_added tripwire. MUST be
                # written here (inside `if send_sysinfo:`, AFTER `sysinfo = {...}`)
                # — the v6.1.2 batch-A bug put four collectors in the earlier
                # container-cadence block, where `sysinfo` is not yet bound, so
                # every one raised a swallowed UnboundLocalError and was silently
                # never sent. tests/test_v612_agent_sysinfo_scope.py guards this.
                usb = get_usb_devices()
                if usb:
                    sysinfo['usb'] = usb
            except Exception as e:
                log.debug(f'usb probe error: {e}')
            try:
                # v6.3.0: laptop battery health. Inside `if send_sysinfo:` and
                # AFTER `sysinfo = {...}` — the v6.1.2 scope gotcha applies.
                bat = get_battery()
                if bat:
                    sysinfo['battery'] = bat
            except Exception as e:
                log.debug(f'battery probe error: {e}')
            try:
                # Integrity Guard: report the quarantine ledger so the server can
                # show the vault + drive restore/delete. Inside `if send_sysinfo:`
                # and AFTER `sysinfo = {...}` (the v6.1.2 scope gotcha).
                gq = _guard_ledger()
                if gq:
                    sysinfo['guard_quarantine'] = gq
            except Exception as e:
                log.debug(f'guard ledger error: {e}')
            try:
                # v6.3.0: chassis class (same placement rule as battery).
                ch = get_chassis()
                if ch:
                    sysinfo['chassis'] = ch
            except Exception as e:
                log.debug(f'chassis probe error: {e}')
            payload['sysinfo'] = sysinfo
            payload['journal'] = get_journal(100)
            # v6.2.2: delta sysinfo — drop the heavy fields whose content is
            # unchanged since the last send the server CONFIRMED (non-busy
            # response). sysinfo_omitted names them so the server merges its
            # stored copy back in; delta_hashes is only committed after the
            # response below, so nothing is ever omitted on the strength of a
            # send the server may have dropped.
            if delta_ok:
                _omitted = {}
                for _f in _DELTA_SYSINFO_FIELDS:
                    if _f not in sysinfo:
                        continue
                    try:
                        _h = _stable_hash(sysinfo[_f])
                    except Exception:
                        continue
                    if delta_hashes.get(_f) == _h:
                        del sysinfo[_f]
                        _omitted[_f] = _h
                    else:
                        _delta_sent_full[_f] = _h
                if _omitted:
                    payload['sysinfo_omitted'] = _omitted
            # W3-8: sample outbound peer connections every ~15 polls so the
            # server can suggest dependency edges. Cheap, private-IPs only.
            if poll_count == 2 or poll_count % 15 == 0:
                try:
                    _peers = collect_peer_connections(50)
                    if _peers:
                        payload['peer_conns'] = _peers
                except Exception as e:
                    log.debug(f'peer conns error: {e}')
                # W5-1: LLDP neighbors (physical topology) on the same cadence.
                try:
                    _lldp = collect_lldp_neighbors(64)
                    if _lldp:
                        payload['lldp_neighbors'] = _lldp
                except Exception as e:
                    log.debug(f'lldp error: {e}')
            # W3-40: newly-seen sudo invocations (privileged-command audit trail).
            try:
                _sudo = collect_sudo_events(100)
                if _sudo:
                    payload['sudo_events'] = _sudo
            except Exception as e:
                log.debug(f'sudo events error: {e}')
            # W3-38: report any canary-file access (edge-triggered).
            try:
                _cev = _check_canaries(_canary_cfg)
                if _cev:
                    payload['canary_events'] = _cev
            except Exception as e:
                log.debug(f'canary check error: {e}')
            log.debug(f"Poll {poll_count}: sending sysinfo + journal")

        # v4.2.0 (B5 P3): report a finished host scan (lynis) to the server.
        # Peek, don't pop — the result is dequeued below only after the server
        # accepted the heartbeat. A network error or busy-202 (which drops the
        # heartbeat's writes) must not lose a finished scan permanently.
        if _HOST_SCAN_OUTBOX:
            payload['host_scan_result'] = _HOST_SCAN_OUTBOX[0]

        # W3-47: attach any spooled samples (from earlier offline cycles) so the
        # server backfills the metrics gap. Cleared only after a successful POST.
        _spool_snapshot = _read_metrics_spool()
        if _spool_snapshot and send_sysinfo:
            payload['backfill'] = _spool_snapshot[:_BACKFILL_BATCH]

        try:
            resp = http_post(f"{server}/api/heartbeat", payload)
            cmd = resp.get('command')
            # Delivered — drop the samples we just shipped from the spool.
            if _spool_snapshot and resp.get('busy') is not True and payload.get('backfill'):
                try:
                    _write_metrics_spool(_read_metrics_spool()[len(payload['backfill']):])
                except Exception:
                    pass
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
            elif 'host_scan_result' in payload and _HOST_SCAN_OUTBOX:
                # Server stored this heartbeat's writes — the scan result is
                # safely delivered, drop it from the retry queue.
                _HOST_SCAN_OUTBOX.pop(0)
            # v6.2.2: delta sysinfo bookkeeping. Commit this beat's full-sent
            # hashes only when the server actually stored the beat (non-busy);
            # (re)learn the capability from every response — a downgraded or
            # restored-from-backup server that stops advertising delta_ok gets
            # full payloads again from the very next beat; and drop the hash
            # for anything it explicitly asks to be re-sent.
            if resp.get('busy') is not True:
                delta_hashes.update(_delta_sent_full)
            delta_ok = bool(resp.get('delta_ok'))
            for _f in (resp.get('delta_resend') or []):
                delta_hashes.pop(_f, None)
            # v6.2.3: honour the server-sent poll_interval directly, like the
            # Windows/Mac agents. The device drawer / profile apply set the
            # device FIELD without queuing a `poll_interval:` command, so
            # field-only changes never reached this agent (the command path
            # still works and takes effect via the STATE_DIR override read at
            # the top of the loop). Clamped like the command path.
            _srv_iv = resp.get('poll_interval')
            if isinstance(_srv_iv, int) and not isinstance(_srv_iv, bool):
                _srv_iv = max(10, min(3600, _srv_iv))
                if _srv_iv != interval:
                    log.info(f"Poll interval updated by server: {interval}s → {_srv_iv}s")
                    interval = _srv_iv
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
            # W3-38: canary/honeytoken files — plant any new ones on receipt.
            if 'canary_files' in resp:
                _canary_cfg = resp.get('canary_files') or []
                try:
                    _plant_canaries(_canary_cfg)
                except Exception as e:
                    log.debug(f'canary plant error: {e}')
                # forget the reported flag for canaries no longer configured so a
                # re-added path can alert again
                _wanted = {(c.get('path') if isinstance(c, dict) else c) for c in _canary_cfg}
                for _gone in [p for p in list(_canary_reported) if p not in _wanted]:
                    _canary_reported.discard(_gone)
            # v6.1.1 (#1): server opts a device INTO the push channel via the
            # heartbeat response, same as every other server-pushed setting
            # here. Started at most once per agent process lifetime -- if
            # push_enabled later flips back off server-side there's
            # currently no clean way to stop a running listener thread
            # short of an agent restart, which is an acceptable limitation
            # for a pure latency optimization (worst case: the thread keeps
            # trying to connect and getting nothing useful to do).
            if resp.get('push_enabled') and _PUSH_AVAILABLE and not _push_thread_started:
                _push_thread_started = True
                threading.Thread(
                    target=_push_listener_thread,
                    args=(server, dev_id, token, _push_wake_event, _push_stop_event),
                    daemon=True, name='push-listener').start()
                log.info('push channel: listener thread started')
            # W3-19: live high-res view — when armed, burst 1 s metric samples
            # for a bounded window so the operator's Live tab updates in near
            # real time. Bounded (≤30 iterations) so command processing resumes
            # promptly; each sample is a tiny device-token POST.
            _live_until = resp.get('live_until')
            if _live_until and _PSUTIL:
                try:
                    _burst_live_samples(server, creds, int(_live_until))
                except Exception as e:
                    log.debug(f'live burst error: {e}')
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
            # v4.9.0: one-shot DNS-credential harvest request (admin clicked
            # "Import from agent"). Read acme.sh's account.conf next poll.
            if resp.get('harvest_dns_creds'):
                force_dns_harvest = True
                log.info('Server requested a DNS-credential harvest from acme.sh')
            # v3.14.0 #35: secrets scan opt-in + paths pushed by the server.
            secrets_scan_on = bool(resp.get('secrets_scan_enabled'))
            _ssp = resp.get('secrets_scan_paths')
            secrets_scan_paths = _ssp if isinstance(_ssp, list) and _ssp else None
            if resp.get('force_secrets_scan'):
                force_secrets_scan = True
                log.info('Server requested a secrets scan')
            # Integrity Guard: server-driven restore/delete of quarantined files.
            _ga = resp.get('guard_actions')
            if isinstance(_ga, list) and _ga:
                try:
                    _n = _apply_guard_actions(_ga)
                    if _n:
                        log.info(f'Applied {_n} guard action(s)')
                except Exception as _e:
                    log.warning(f'guard actions failed: {_e}')
            # v6.3.1: one-shot hail-mary /var/log sweep ("Diagnose from logs").
            if resp.get('force_log_sweep'):
                force_log_sweep = True
                log.info('Server requested a hail-mary log sweep')
            # v6.2.0: disk-usage explorer opt-in + paths + one-shot force.
            du_scan_on = bool(resp.get('du_scan_enabled'))
            _dsp = resp.get('du_scan_paths')
            du_scan_paths = _dsp if isinstance(_dsp, list) and _dsp else None
            if resp.get('force_du_scan'):
                force_du_scan = True
                log.info('Server requested a disk-usage scan')
            # v6.2.0: PII / sensitive-data scan opt-in + paths + one-shot force.
            pii_scan_on = bool(resp.get('pii_scan_enabled'))
            _psp = resp.get('pii_scan_paths')
            pii_scan_paths = _psp if isinstance(_psp, list) and _psp else None
            if resp.get('force_pii_scan'):
                force_pii_scan = True
                log.info('Server requested a PII scan')
            # W6-34: container-image CVE scan (trivy), opt-in + force.
            image_scan_on = bool(resp.get('image_scan_enabled'))
            mdns_on = bool(resp.get('mdns_enabled'))   # v6.1.2
            if resp.get('force_image_scan'):
                force_image_scan = True
                log.info('Server requested an image CVE scan')
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
            # v4.2.0 (B5 P3): one-shot host scan (lynis). Same model as oscap —
            # daemon thread, lock prevents overlap; result goes back via the
            # heartbeat outbox, not a direct POST.
            _hs = resp.get('host_scan')
            if isinstance(_hs, dict) and _hs.get('id'):
                if _host_scan_running.acquire(blocking=False):
                    log.info(f"Server requested host scan: {_hs.get('tool')} (id={_hs.get('id')})")

                    def _run_hs(job=_hs):
                        try:
                            _HOST_SCAN_OUTBOX.append(run_host_scan(job))
                        finally:
                            _host_scan_running.release()
                    threading.Thread(target=_run_hs, daemon=True).start()
                else:
                    log.info('Host scan already running; ignoring request')
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
            # v4.1.0: receive agent-side custom check definitions from server.
            if 'agent_checks' in resp:
                new_ac = resp.get('agent_checks') or []
                if isinstance(new_ac, list):
                    if [c.get('id') for c in new_ac] != [c.get('id') for c in agent_checks]:
                        log.info(f'Config updated: agent_checks = {len(new_ac)} check(s)')
                    agent_checks = new_ac
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
                # v6.3.1: signed-command gate (opt-in, fail-closed). The refusal
                # is REPORTED as command output so the operator sees exactly why
                # nothing ran, instead of a silent drop.
                _sig_ok, _sig_detail = (True, '')
                if _require_signed_commands():
                    _sig_ok, _sig_detail = _command_sig_ok(
                        cmd, resp.get('command_sig'),
                        resp.get('command_sig_ts'), dev_id)
                if not _sig_ok:
                    log.error(f'REFUSED command (require-signed-commands, '
                              f'{_sig_detail}): {str(cmd)[:120]!r}')
                    result = {'cmd': cmd, 'rc': 126,
                              'output': ('refused: require-signed-commands is set '
                                         f'and verification failed ({_sig_detail})')}
                else:
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
            # W3-47: server unreachable — spool this cycle's metrics so the gap
            # backfills into the sparklines once we reconnect.
            if send_sysinfo:
                try:
                    _spool_metric_sample(payload.get('sysinfo') or {})
                except Exception:
                    pass

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

        # v6.1.1 (#1): wake early on a push nudge instead of always sleeping
        # the full interval. wake_event.wait() with a timeout is exactly
        # time.sleep(interval) when the event never fires (the channel isn't
        # installed/enabled, or simply didn't have anything to say this
        # cycle) -- no behavior change for the unmodified case.
        if _push_wake_event.wait(timeout=interval):
            _push_wake_event.clear()
            log.debug('woken early by a push nudge')

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
    parser.add_argument('--server', help='Server URL for enroll / enroll-token (e.g. https://remote.example.com)')
    parser.add_argument('--token', help='Enrollment token (or use $REMOTEPOWER_ENROLL_TOKEN, or /etc/remotepower/enroll-token)')
    parser.add_argument('--pin', help='Enrollment PIN for a non-interactive `enroll` (skips the prompt)')
    parser.add_argument('--name', help='Device display name (defaults to hostname)')
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Warning: running as non-root. Shutdown/reboot may fail.")
        print("Use sudo or the systemd unit (runs as root).")
        print()

    if args.action == 'enroll':
        enroll_interactive(re_enroll=False, server_url=args.server, pin=args.pin); return

    if args.action == 're-enroll':
        enroll_interactive(re_enroll=True, server_url=args.server, pin=args.pin); return

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

    # v4.10.0: graceful-stop notice. On SIGTERM (systemctl stop) or SIGINT, tell
    # the server we're stopping so it fires a distinct "agent stopped (host was
    # up)" signal instead of a silent offline, then exit. Sending from the handler
    # lands the notice within systemd's stop timeout even while sleeping between
    # polls. An ungraceful kill -9 still shows as offline (documented).
    def _on_term(_signum, _frame):
        try:
            http_post(f"{creds['server_url']}/api/heartbeat",
                      {'device_id': creds['device_id'], 'token': creds['token'],
                       'agent_stopping': True}, timeout=5)
            log.info("Sent graceful-stop notice to server")
        except Exception as e:
            log.debug(f"stop notice failed: {e}")
        sys.exit(0)
    try:
        signal.signal(signal.SIGTERM, _on_term)
        signal.signal(signal.SIGINT, _on_term)
    except Exception:
        pass   # not in the main thread / platform without these signals

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
    # host_path() is the identity when running natively; in a container it
    # redirects host-fact reads (/proc, /etc, …) to the bind-mounted host rootfs.
    try:
        with open(host_path(path), 'r', errors='replace') as f:
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
        ak = Path(host_path(home)) / '.ssh' / 'authorized_keys'
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
        if Path(host_path(path)).exists():
            cfg_files[path] = _safe_read(path, 20_000)
    netplan_dir = Path(host_path('/etc/netplan'))
    if netplan_dir.is_dir():
        for f in netplan_dir.glob('*.yaml'):
            cfg_files[unhost_path(str(f))] = _safe_read(str(f), 20_000)
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
    apt_dir = Path(host_path('/etc/apt/sources.list.d'))
    apt_main = Path(host_path('/etc/apt/sources.list'))
    if apt_main.exists():
        repos['/etc/apt/sources.list'] = _safe_read('/etc/apt/sources.list', 50_000)
    if apt_dir.is_dir():
        for f in apt_dir.glob('*.list'):
            repos[unhost_path(str(f))] = _safe_read(str(f), 50_000)
        for f in apt_dir.glob('*.sources'):
            repos[unhost_path(str(f))] = _safe_read(str(f), 50_000)
    # dnf/yum
    yum_dir = Path(host_path('/etc/yum.repos.d'))
    if yum_dir.is_dir():
        for f in yum_dir.glob('*.repo'):
            repos[unhost_path(str(f))] = _safe_read(str(f), 50_000)
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
    if Path(host_path('/etc/crontab')).exists():
        crons['/etc/crontab'] = _safe_read('/etc/crontab', 50_000)
    # /etc/cron.d
    cron_d = Path(host_path('/etc/cron.d'))
    if cron_d.is_dir():
        for f in cron_d.iterdir():
            if f.is_file():
                crons[unhost_path(str(f))] = _safe_read(str(f), 50_000)
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
        p = Path(host_path(d))
        if p.is_dir():
            for f in p.rglob('*'):
                if f.is_file() and f.suffix in ('.crt', '.pem', '.cert', '.key'):
                    paths.append(unhost_path(str(f)))
    return {'tls_cert_paths': sorted(set(paths))[:200]}


def iac_collect_env():
    """Category 14: /etc/environment + /etc/profile.d snippets."""
    out = {}
    if Path(host_path('/etc/environment')).exists():
        out['/etc/environment'] = _safe_read('/etc/environment', 10_000)
    pd = Path(host_path('/etc/profile.d'))
    if pd.is_dir():
        for f in pd.glob('*.sh'):
            content = _safe_read(str(f), 10_000)
            if content.strip():
                out[unhost_path(str(f))] = content
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
        p = Path(host_path(d))
        if p.is_dir():
            for f in p.glob('*.conf'):
                content = _safe_read(str(f), 20_000)
                if content.strip():
                    out[unhost_path(str(f))] = content
    if Path(host_path('/etc/modules')).exists():
        out['/etc/modules'] = _safe_read('/etc/modules', 10_000)
    return {'kernel_module_config': out}


def iac_collect_sysctl():
    """Category 17: non-default sysctl parameters from /etc/sysctl.d/* and /etc/sysctl.conf."""
    out = {}
    if Path(host_path('/etc/sysctl.conf')).exists():
        out['/etc/sysctl.conf'] = _safe_read('/etc/sysctl.conf', 50_000)
    for d in ('/etc/sysctl.d', '/usr/lib/sysctl.d', '/run/sysctl.d'):
        p = Path(host_path(d))
        if p.is_dir():
            for f in p.glob('*.conf'):
                content = _safe_read(str(f), 50_000)
                if content.strip():
                    out[unhost_path(str(f))] = content
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

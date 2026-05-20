#!/usr/bin/env python3
"""
RemotePower API backend - v1.9.0
Runs via fcgiwrap as a CGI script behind Nginx.
Flat-file storage in /var/lib/remotepower/
"""

import os
import re
import sys
import json
import time
import hashlib
import hmac
import secrets
import socket
import subprocess
import shutil
import fcntl
import traceback
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path

SERVER_VERSION = '2.6.0'

DATA_DIR         = Path(os.environ.get('RP_DATA_DIR', '/var/lib/remotepower'))
USERS_FILE       = DATA_DIR / 'users.json'
DEVICES_FILE     = DATA_DIR / 'devices.json'
PINS_FILE        = DATA_DIR / 'pins.json'
# v1.11.10: pre-shared one-time-use tokens for non-interactive enrollment.
# Created via POST /api/enrollment-tokens (admin-only). Same shape as
# pins.json but tokens are 32-char URL-safe random strings instead of
# 6-digit PINs, and they carry optional default group/tags/expiry.
ENROLL_TOKENS_FILE = DATA_DIR / 'enrollment_tokens.json'
TOKENS_FILE      = DATA_DIR / 'tokens.json'
CMDS_FILE        = DATA_DIR / 'commands.json'
CONFIG_FILE      = DATA_DIR / 'config.json'
HISTORY_FILE     = DATA_DIR / 'history.json'
SCHEDULE_FILE    = DATA_DIR / 'schedule.json'
UPTIME_FILE      = DATA_DIR / 'uptime.json'
MON_HIST_FILE    = DATA_DIR / 'monitor_history.json'
CMD_OUTPUT_FILE  = DATA_DIR / 'cmd_output.json'
# v1.10.0: Update output captures from `update` commands (apt/dnf/pacman runs).
# Stored separately from generic exec output so the Patches page can filter
# without scanning thousands of unrelated entries.
UPDATE_LOGS_FILE = DATA_DIR / 'update_logs.json'
MAX_UPDATE_LOGS_PER_DEVICE = 10                # rolling buffer
MAX_UPDATE_LOG_BYTES       = 256 * 1024        # apt update -y can spew a lot
METRICS_FILE     = DATA_DIR / 'metrics.json'
CMD_LIBRARY_FILE = DATA_DIR / 'cmd_library.json'
LONGPOLL_FILE    = DATA_DIR / 'longpoll.json'
APIKEYS_FILE     = DATA_DIR / 'apikeys.json'
RATELIMIT_FILE   = DATA_DIR / 'ratelimit.json'
AUDIT_LOG_FILE   = DATA_DIR / 'audit_log.json'
SESSIONS_META_FILE = DATA_DIR / 'sessions_meta.json'
WEBHOOK_LOG_FILE = DATA_DIR / 'webhook_log.json'
# v2.2.4: dedicated fleet event log. The webhook log was always
# delivery-attempt-only — if a `device_offline` fired but no webhook
# URL was configured AND email wasn't enabled for the event, nothing
# got logged anywhere. The Home dashboard activity panel relied on
# webhook_log, so events fired with no destinations were invisible.
# This new file records every fired event regardless of destination
# config; the Home dashboard reads from it. Webhook log stays
# delivery-attempts-only for Settings → Webhook log (unchanged).
FLEET_EVENTS_FILE = DATA_DIR / 'fleet_events.json'

# ── v2.1.0: multi-line script library (separate from one-liner cmd_library) ───
# cmd_library is for single-line snippets the operator picks from the exec
# modal. Scripts are full multi-line bash that gets queued as an exec: body
# at execution time. Stored separately because:
#   * Different size budget (multi-line, larger payloads).
#   * Different validation surface (dry-run via `bash -n` + dangerous-command
#     detection on save and before queueing).
#   * Different UI affordance (own page; multi-select batch runner).
SCRIPTS_FILE         = DATA_DIR / 'scripts.json'
BATCH_JOBS_FILE      = DATA_DIR / 'batch_jobs.json'
MAX_SCRIPTS          = 500            # fleet-wide cap
MAX_SCRIPT_NAME      = 80
MAX_SCRIPT_DESC      = 512
MAX_SCRIPT_BODY      = 64 * 1024      # 64 KB matches MAX_CMDB_DOC_LEN budget
MAX_BATCH_TARGETS    = 100            # mirrors _resolve_targets cap
BATCH_JOB_TTL_SEC    = 3600           # 1h — purges old jobs on next access

# v2.1.0: docker-compose discovery + action endpoint. Projects come from
# the agent's heartbeat (which scans /opt /home /docker /srv); the server
# only stores the listing per-device and queues compose:<action>:<dir>
# commands against the agent's exec channel.
MAX_COMPOSE_PROJECTS_PER_DEVICE = 50
MAX_COMPOSE_PATH_LEN            = 1024
COMPOSE_ALLOWED_ACTIONS         = ('up', 'down', 'restart', 'pull', 'logs')

# ── v1.7.0: CVE scanner + package inventory ────────────────────────────────────
PACKAGES_FILE       = DATA_DIR / 'packages.json'
CVE_FINDINGS_FILE   = DATA_DIR / 'cve_findings.json'
CVE_IGNORE_FILE     = DATA_DIR / 'cve_ignore.json'

MAX_PACKAGE_LIST    = 10000      # hard cap on packages per device payload
CVE_SCAN_MAX_AGE    = 86400      # auto-scan if findings older than this
CVE_ALERT_SEVERITY  = ('critical', 'high')  # which severities fire webhooks

# ── v1.8.0: service monitoring, log tail, maintenance windows ─────────────────
SERVICES_FILE       = DATA_DIR / 'services.json'          # current state per device
SERVICE_HIST_FILE   = DATA_DIR / 'service_history.json'   # transitions per (device,unit)
LOG_WATCH_FILE      = DATA_DIR / 'log_watch.json'         # captured log buffer per device
MAINT_FILE          = DATA_DIR / 'maintenance.json'       # active + scheduled windows
MAINT_SUPPRESS_LOG  = DATA_DIR / 'maint_suppressed.json'  # audit trail for suppressions

# v1.8.2: fleet-wide log alert rules (per-device rules still live on device.log_watch)
LOG_RULES_GLOBAL_FILE = DATA_DIR / 'log_rules_global.json'
MAX_GLOBAL_LOG_RULES  = 50

# v1.8.3: standalone shared calendar events
CALENDAR_FILE       = DATA_DIR / 'calendar.json'
MAX_CALENDAR_EVENTS = 1000

# v1.8.3: shared kanban-style task board (optional device linking)
TASKS_FILE          = DATA_DIR / 'tasks.json'
MAX_TASKS           = 500
TASK_STATES         = ('upcoming', 'ongoing', 'pending', 'closed')

# ── v1.9.0: CMDB (asset metadata + encrypted credentials) ─────────────────────
CMDB_FILE           = DATA_DIR / 'cmdb.json'
CMDB_VAULT_FILE     = DATA_DIR / 'cmdb_vault.json'

MAX_CMDB_DOC_LEN    = 64 * 1024     # 64 KB Markdown body per asset
MAX_CMDB_FUNC_LEN   = 64
MAX_CMDB_ASSET_ID   = 64
MAX_CMDB_URL_LEN    = 512
MAX_CMDB_LABEL      = 64
MAX_CMDB_USERNAME   = 128
MAX_CMDB_PASSWORD   = 1024
MAX_CMDB_CRED_NOTE  = 512
MAX_CMDB_CREDS      = 25            # per-asset cap
# v2.0: multi-doc attachments per asset
MAX_CMDB_DOCS       = 50            # sanity cap; 50 docs/asset is more than anyone needs
MAX_CMDB_DOC_TITLE  = 120           # single line title length

# server_function is a free-text field, but we restrict the charset so we can
# safely use it in the searchbox / autocomplete without escaping every char.
# server_function is a free-text field, but we restrict the charset so we can
# safely use it in the searchbox / autocomplete without escaping every char.
_CMDB_FUNC_RE       = re.compile(r'^[A-Za-z0-9 _\-/]{0,64}$')

# v1.10.0: SSH port for the per-credential SSH link feature. Default 22 = blank.
CMDB_DEFAULT_SSH_PORT = 22
CMDB_SSH_PORT_MIN     = 1
CMDB_SSH_PORT_MAX     = 65535

# ── v1.11.0: container/k8s awareness, TLS monitor, network map, agentless ────
CONTAINERS_FILE = DATA_DIR / 'containers.json'
TLS_TARGETS_FILE = DATA_DIR / 'tls_targets.json'
TLS_RESULTS_FILE = DATA_DIR / 'tls_results.json'
# Agentless devices live in the regular devices.json with a special marker
# (`agentless: True`). Network map is rendered from the existing devices
# data plus a new `connected_to: <device_id>` field on each record. No
# separate storage files for either.

MAX_TLS_TARGETS = 200
MAX_TLS_HOST_LEN = 255
TLS_DEFAULT_WARN_DAYS = 14
TLS_DEFAULT_CRIT_DAYS = 3

# ── v1.11.1: network-map tunnels + draggable positions ───────────────────────
# Tunnels are a second kind of edge between two devices — distinct from the
# physical `connected_to` parent-child relationship. Stored as a flat list
# rather than per-device because they're peer relationships (no clear "owner").
# Positions live on the device record itself (pos_x, pos_y) — they're a
# rendering hint, not a separate concern.
TUNNELS_FILE = DATA_DIR / 'tunnels.json'
MAX_TUNNELS = 200

# ── v1.11.2: shared link dashboard ───────────────────────────────────────────
# A simple bookmark dashboard, shared across all admins. Card grid grouped by
# category. Each link has a `scope` ("internal" / "external") that's purely
# a display hint — we don't probe internal links from the server, and we don't
# enforce anything based on the field. It's just a label so the user can see
# at a glance "this link works on the LAN only."
LINKS_FILE = DATA_DIR / 'links.json'
MAX_LINKS = 500
MAX_LINK_TITLE_LEN       = 128
MAX_LINK_URL_LEN         = 1024
MAX_LINK_DESCRIPTION_LEN = 512
MAX_LINK_CATEGORY_LEN    = 64
LINK_SCOPES = ('internal', 'external')
LINK_DEFAULT_CATEGORY    = 'Uncategorised'

MAX_SERVICES_PER_DEVICE = 50       # sanity cap
MAX_SERVICE_HIST        = 100      # state transitions kept per (device,unit)
MAX_LOG_LINES_PER_UNIT  = 100      # per-poll capture window
LOG_BUFFER_TTL          = 6 * 3600 # rolling N-hour buffer
MAX_LOG_BUFFER_BYTES    = 2 * 1024 * 1024   # 2 MB per device cap

# v1.11.5: per-user UI preferences (density, persistent filter strings,
# column sort state). Stored in users.json under the 'ui_prefs' key, keyed
# by table name. Total size capped to keep users.json manageable.
MAX_UI_PREFS_BYTES         = 16 * 1024     # 16 KB total per user — generous
MAX_UI_PREFS_FILTER_LEN    = 256           # per-filter string cap
MAX_UI_PREFS_SORT_KEYS     = 5             # multi-column sort depth limit
MAX_UI_PREFS_TABLES        = 50            # distinct tables we'll remember prefs for
UI_DENSITY_VALUES          = ('minimal', 'compact', 'comfortable', 'spacious')
UI_DENSITY_DEFAULT         = 'comfortable'

# ─── v1.11.10: enrollment tokens & metric alerting ───────────────────────────

# Default lifetime of an enrollment token. 24h is a sensible balance —
# long enough that an Ansible run started overnight still has time, short
# enough that a leaked token has bounded risk. Override via the create
# endpoint's `expires_in` parameter (capped at 7 days).
DEFAULT_ENROLL_TOKEN_TTL = 24 * 3600
MAX_ENROLL_TOKEN_TTL     = 7 * 24 * 3600

# Default metric alert thresholds. These match the values discussed in
# v1.11.10 planning and are documented in the Settings page. Per-device
# overrides go in devices[id]['metric_thresholds']; per-mount disk
# overrides in devices[id]['metric_thresholds']['disk_per_mount'][path].
#
# Hysteresis: a metric must drop ``METRIC_RECOVERY_BUFFER`` percentage
# points below the warn threshold before we fire metric_recovered. Without
# this, a metric oscillating around 80% would generate webhook spam.
DEFAULT_METRIC_THRESHOLDS = {
    'disk_warn_percent':   80,
    'disk_crit_percent':   90,
    'mem_warn_percent':    85,
    'mem_crit_percent':    95,
    'swap_warn_percent':   20,
    'swap_crit_percent':   50,
    # CPU thresholds are loadavg/cpu_count multiples. 1.5 = 1-minute load
    # of 1.5× cores sustained = warning. The values match what most
    # sysadmins consider 'busy' (warn) and 'overloaded' (critical).
    'cpu_warn_load_ratio': 1.5,
    'cpu_crit_load_ratio': 3.0,
}
METRIC_RECOVERY_BUFFER = 5      # percentage points (or load-ratio*100 equivalent)
METRIC_KINDS           = ('disk', 'memory', 'swap', 'cpu')
METRIC_SEVERITIES      = ('warning', 'critical')

# ─── v1.11.11: web terminal (browser → SSH via companion daemon) ─────────────
#
# Tickets are short-lived single-use credentials issued by the CGI's
# /api/webterm/auth endpoint after re-validating the user's admin
# password. The remotepower-webterm daemon (separate systemd unit
# listening on 127.0.0.1:8765) reads the ticket store, validates the
# ticket the browser presents on WS connect, and proxies bytes between
# the browser and an SSH session to the target device.
#
# The CGI never speaks SSH directly. The daemon never speaks to the
# database. The ticket file is the only thing they share.
WEBTERM_TICKETS_FILE = DATA_DIR / 'webterm_tickets.json'
WEBTERM_TICKET_TTL   = 60          # seconds — long enough to click Connect
WEBTERM_SESSION_DIR  = DATA_DIR / 'webterm-sessions'
WEBTERM_MAX_SESSION_LOG_BYTES = 10 * 1024 * 1024   # 10 MiB cap per recording

# Sibling modules — must live in the same cgi-bin directory
sys.path.insert(0, str(Path(__file__).parent))
import cve_scanner
import prometheus_export
# v1.8.6: SMTP + LDAP. ldap3 is optional — the module imports it lazily so
# servers that don't enable LDAP don't need the dependency installed.
import smtp_notifier
import ldap_auth
# v1.9.0: CMDB vault — symmetric crypto for asset credentials. The cryptography
# library is imported lazily inside the module so this import always succeeds.
import cmdb_vault
# v1.10.0: OpenAPI spec — handwritten dict served at /api/openapi.json,
# rendered by the Swagger UI page at /swagger.html.
import openapi_spec
# v1.11.0: container/pod awareness. Agent posts a normalised list in
# heartbeats; this module validates and summarises.
import containers as containers_mod
# v2.3.0: Proxmox VE integration — server-side API client for QEMU VMs
# and LXC containers on a single Proxmox node.
import proxmox_client
# v1.11.0: TLS/DNS expiry monitor. Server-side cron-driven probes; results
# stored alongside the watchlist for UI rendering and webhook alerting.
import tls_monitor

# v2.1.3: AI assistant — OpenAI-compatible + Anthropic adapters.
import ai_provider
# v2.1.7: Level-1 RAG context (project + fleet awareness)
import ai_context

# Default values — overridable via /api/config (v1.8.4)
DEFAULT_TOKEN_TTL_SHORT  = 86400        # 24h — when "remember me" is unchecked
DEFAULT_TOKEN_TTL_LONG   = 86400 * 30   # 30 days — when "remember me" is checked
TOKEN_TTL                = 86400 * 7    # legacy fallback if config has neither
PIN_TTL                  = 600
# v2.1.1: bumped from 180→300 (3min→5min) so a device has to miss 5
# heartbeats (at the default 60s poll) before it's marked offline. Field
# reports of "device went offline" turning out to be brief network blips
# or load spikes the agent recovered from on its own; 5 missed polls is
# the new bar. Operators who want the old behaviour can lower it via the
# Settings → Webhooks page or POST /api/config {"online_ttl": 180}.
DEFAULT_ONLINE_TTL       = 300
MIN_ONLINE_TTL           = 150          # don't allow flapping under <2.5 poll intervals
DEFAULT_POLL_INTERVAL    = 60
DEFAULT_CVE_CACHE_DAYS   = 7
MAX_HISTORY       = 200
MAX_MON_HISTORY   = 50
MAX_CMD_OUTPUT    = 100
MAX_CMD_OUT_BYTES = 8192    # per-entry output cap enforced at ingestion
MAX_METRICS       = 1440
MAX_SCHEDULE_JOBS = 200     # cap on total schedule entries
PATCH_ALERT_KEY   = 'patch_alert_threshold'
MAX_AUDIT_LOG     = 500
MAX_WEBHOOK_LOG   = 100
# v2.2.4: cap on the fleet event log (separate from webhook log).
# 200 fits well into a few KB on disk and gives the Home dashboard
# enough history to show meaningful activity even on quiet fleets
# where events arrive sparsely.
MAX_FLEET_EVENTS = 200


# v1.8.4: All known webhook events, with metadata used by the UI to render
# the per-event toggle list. Order matters — drives the order in Settings.
#
# v1.11.4: container alerts. Modeled on the service_up/service_down pair —
# transitions are detected by comparing the new heartbeat's container list
# against the previous one. ``containers_stale`` is fired by the periodic
# offline-check sweep when no fresh report has arrived within the configured
# TTL.
WEBHOOK_EVENTS = (
    ('device_offline',     'Device went offline',                  True),
    ('device_online',      'Device came back online',              True),
    ('monitor_down',       'Monitor target went down',             True),
    ('monitor_up',         'Monitor target recovered',             True),
    ('patch_alert',        'Pending updates exceed threshold',     True),
    ('cve_found',          'New CVEs detected on a device',        True),
    ('service_down',       'Watched systemd unit went down',       True),
    ('service_up',         'Watched systemd unit recovered',       True),
    ('log_alert',          'Log pattern matched threshold',        True),
    ('container_stopped',  'Container/pod disappeared or stopped', True),
    ('container_restarting', 'Container restart count climbing',   True),
    ('containers_stale',   'No container report for >TTL',         True),
    # v1.11.10: metric thresholds (disk, memory, swap, cpu loadavg)
    ('metric_warning',     'Resource crossed warning threshold',   True),
    ('metric_critical',    'Resource crossed critical threshold',  True),
    ('metric_recovered',   'Resource dropped back below threshold', True),
    ('command_queued',     'Command queued for a device',          False),
    ('command_executed',   'Command executed on a device',         False),
    # v2.2.0: configuration drift detection
    ('drift_detected',     'Watched config file diverged from baseline', True),
    # v2.4.7: mailbox count crossed its alert threshold
    ('mailbox_threshold',  'Mailbox count crossed its alert threshold', True),
    # v2.5.0: custom monitoring script results
    ('custom_script_fail',    'Custom monitoring script returned non-zero', True),
    ('custom_script_recover', 'Custom monitoring script recovered to OK',   True),
    # v2.6.0: host configuration drift
    ('config_drift',          'Host configuration drift detected',          True),
)
WEBHOOK_EVENT_NAMES = tuple(e[0] for e in WEBHOOK_EVENTS)

# CVE severity levels available for cve_found webhook filtering
CVE_SEVERITIES_ALL  = ('critical', 'high', 'medium', 'low', 'unknown')
CVE_SEVERITY_FILTER_DEFAULT = ('critical', 'high')


def _config():
    """Load config with merged defaults — call when you need a current value."""
    cfg = load(CONFIG_FILE)
    return cfg


def get_online_ttl():
    """Effective online TTL value, clamped to MIN_ONLINE_TTL."""
    try:
        v = int(_config().get('online_ttl', DEFAULT_ONLINE_TTL))
    except (TypeError, ValueError):
        v = DEFAULT_ONLINE_TTL
    return max(MIN_ONLINE_TTL, v)


def get_default_poll_interval():
    """Default poll interval used when enrolling new agents."""
    try:
        v = int(_config().get('default_poll_interval', DEFAULT_POLL_INTERVAL))
    except (TypeError, ValueError):
        v = DEFAULT_POLL_INTERVAL
    return max(10, min(3600, v))


def get_session_ttl(remember_me=False):
    """Session lifetime in seconds — short by default, long with 'remember me'."""
    cfg = _config()
    if remember_me:
        try:
            return int(cfg.get('session_ttl_long', DEFAULT_TOKEN_TTL_LONG))
        except (TypeError, ValueError):
            return DEFAULT_TOKEN_TTL_LONG
    try:
        return int(cfg.get('session_ttl_short', DEFAULT_TOKEN_TTL_SHORT))
    except (TypeError, ValueError):
        return DEFAULT_TOKEN_TTL_SHORT


def get_remember_me_default():
    """Whether the 'remember me' checkbox should be pre-ticked on the login page."""
    return bool(_config().get('remember_me_default', False))


def get_cve_cache_seconds():
    """How long to cache OSV vulnerability details before re-fetching."""
    try:
        days = int(_config().get('cve_cache_days', DEFAULT_CVE_CACHE_DAYS))
    except (TypeError, ValueError):
        days = DEFAULT_CVE_CACHE_DAYS
    return max(1, min(90, days)) * 86400


def is_webhook_event_enabled(event):
    """Check the per-event webhook toggle. Backward compatible with legacy keys."""
    cfg = _config()

    # New (v1.8.4): explicit per-event dict
    events = cfg.get('webhook_events') or {}
    if event in events:
        return bool(events[event])

    # Legacy: device_offline/device_online controlled by offline_webhook_enabled,
    # monitor_down/monitor_up by monitor_webhook_enabled, etc.
    if event in ('device_offline', 'device_online'):
        return cfg.get('offline_webhook_enabled', True)
    if event in ('monitor_down', 'monitor_up'):
        return cfg.get('monitor_webhook_enabled', True)
    if event == 'cve_found':
        return cfg.get('cve_webhook_enabled', True)
    if event in ('service_down', 'service_up'):
        return cfg.get('service_webhook_enabled', True)
    # Default ON for everything else not explicitly disabled
    return True


def get_cve_severity_filter():
    """Severity levels that fire cve_found webhooks."""
    cfg = _config()
    raw = cfg.get('cve_severity_filter')
    if isinstance(raw, list) and raw:
        clean = tuple(s for s in raw if s in CVE_SEVERITIES_ALL)
        if clean:
            return clean
    return CVE_SEVERITY_FILTER_DEFAULT


def get_server_name():
    """Display name for this server — webhook payloads, page title, etc."""
    name = _config().get('server_name', '').strip()
    return name or 'RemotePower'

# ── Login brute-force protection ───────────────────────────────────────────────
LOGIN_FAIL_WINDOW  = 300   # 5-minute rolling window
LOGIN_FAIL_MAX     = 10    # lock after this many failures
LOGIN_LOCKOUT_TIME = 600   # 10-minute lockout

# ── Input size limits ──────────────────────────────────────────────────────────
MAX_BODY_BYTES    = 50 * 1024 * 1024  # 50 MB — raised from 64 KB in v1.7.0 for package-list uploads
MAX_HOSTNAME_LEN  = 253
MAX_NAME_LEN      = 64
MAX_OS_LEN        = 128
MAX_VERSION_LEN   = 32
MAX_IP_LEN        = 45      # IPv6 max
MAX_MAC_LEN       = 17
MAX_TAG_LEN       = 32
MAX_TAG_COUNT     = 10
MAX_GROUP_LEN     = 64
MAX_NOTES_LEN     = 1024
MAX_JOURNAL_LINES = 200
MAX_JOURNAL_LINE  = 512     # bytes per journal line

# ── ID validation regex — alphanumeric + hyphen/underscore, 1-64 chars ─────────
_SAFE_ID_RE = re.compile(r'^[A-Za-z0-9_\-]{1,64}$')

def _validate_id(value: str) -> bool:
    """Return True only if value is a safe resource ID (no path traversal etc.)."""
    return bool(value and _SAFE_ID_RE.match(value))

# ── Password hashing ───────────────────────────────────────────────────────────
#
# Primary: bcrypt (cost 12). Present in the Docker image and the
# documented bare-metal install.
#
# Fallback when bcrypt is unavailable: v2.3.2 replaced the previous
# fallback — a bare, UNSALTED hashlib.sha256 — with salted PBKDF2-HMAC-
# SHA256. Unsalted SHA-256 is fast and rainbow-table-able; PBKDF2 with a
# per-hash random salt and a high iteration count is dramatically
# stronger, and it's pure stdlib (no new dependency).
#
# Three on-disk hash formats are recognised by verify_password:
#   $2...                       — bcrypt
#   pbkdf2$<iters>$<salt>$<hash> — v2.3.2 PBKDF2 fallback
#   <64 hex chars>              — LEGACY unsalted sha256 (pre-2.3.2)
# Legacy hashes still verify, and maybe_rehash() upgrades them to the
# best available scheme on the user's next successful login.
try:
    import bcrypt as _bcrypt
    _BCRYPT = True
except ImportError:
    _BCRYPT = False

_PBKDF2_ITERATIONS = 600_000   # OWASP-recommended floor for PBKDF2-SHA256

def _pbkdf2_hash(plain: str, salt: bytes = None,
                 iterations: int = _PBKDF2_ITERATIONS) -> str:
    """Return a self-describing PBKDF2 hash string:
    pbkdf2$<iterations>$<hex-salt>$<hex-digest>"""
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac('sha256', plain.encode(), salt, iterations)
    return f'pbkdf2${iterations}${salt.hex()}${dk.hex()}'

def hash_password(plain):
    if _BCRYPT:
        return _bcrypt.hashpw(plain.encode(), _bcrypt.gensalt(12)).decode()
    # No bcrypt — salted PBKDF2 rather than the old bare sha256.
    return _pbkdf2_hash(plain)

def verify_password(plain, stored):
    if stored.startswith('$2'):
        if not _BCRYPT:
            return False
        try:
            return _bcrypt.checkpw(plain.encode(), stored.encode())
        except Exception:
            return False
    if stored.startswith('pbkdf2$'):
        try:
            _, iters, salt_hex, digest_hex = stored.split('$', 3)
            candidate = hashlib.pbkdf2_hmac(
                'sha256', plain.encode(), bytes.fromhex(salt_hex), int(iters))
            return hmac.compare_digest(candidate.hex(), digest_hex)
        except Exception:
            return False
    # Legacy unsalted sha256 (pre-2.3.2). Still verified for
    # backward compatibility; maybe_rehash upgrades on next login.
    return hmac.compare_digest(hashlib.sha256(plain.encode()).hexdigest(), stored)

def maybe_rehash(username, plain, stored):
    """Upgrade a stored hash to the strongest available scheme after a
    successful login. v2.3.2: also upgrades the legacy unsalted-sha256
    hashes to PBKDF2 when bcrypt isn't available (previously a
    bcrypt-less server left legacy hashes in place forever)."""
    needs_upgrade = False
    if _BCRYPT and not stored.startswith('$2'):
        needs_upgrade = True            # → bcrypt
    elif not _BCRYPT and not stored.startswith(('pbkdf2$', '$2')):
        needs_upgrade = True            # legacy sha256 → PBKDF2
    if needs_upgrade:
        users = load(USERS_FILE)
        if username in users:
            users[username]['password_hash'] = hash_password(plain)
            save(USERS_FILE, users)

# ── TOTP (2FA) ─────────────────────────────────────────────────────────────────
import hmac as _hmac_mod
import struct as _struct
import base64 as _base64

def _hotp(key_bytes, counter):
    """Generate HOTP value (RFC 4226)."""
    msg = _struct.pack('>Q', counter)
    h = _hmac_mod.new(key_bytes, msg, 'sha1').digest()
    offset = h[-1] & 0x0F
    code = _struct.unpack('>I', h[offset:offset+4])[0] & 0x7FFFFFFF
    return str(code % 1000000).zfill(6)

def _totp(secret_b32, window=1):
    """Generate current TOTP and accept within window."""
    key = _base64.b32decode(secret_b32.upper().replace(' ', ''), casefold=True)
    now = int(time.time()) // 30
    return [_hotp(key, now + i) for i in range(-window, window + 1)]

def _generate_totp_secret():
    """Generate a random base32 TOTP secret."""
    raw = secrets.token_bytes(20)
    return _base64.b32encode(raw).decode().rstrip('=')

def _totp_provisioning_uri(secret, username, issuer='RemotePower'):
    """Generate otpauth:// URI for QR code scanning."""
    return f'otpauth://totp/{urllib.parse.quote(issuer)}:{urllib.parse.quote(username)}?secret={secret}&issuer={urllib.parse.quote(issuer)}&digits=6&period=30'

# ── Storage ────────────────────────────────────────────────────────────────────
DATA_DIR.mkdir(parents=True, exist_ok=True)


# v1.12.1: hardened against the concurrent-write corruption that made
# devices.json a problem in the wild. The bug pattern was:
#
#   Process A: opens devices.json.tmp with O_TRUNC, starts writing
#   Process B: opens devices.json.tmp with O_TRUNC (truncates A's bytes),
#              writes its own content
#   Both processes' writes interleave on the same fd offset, producing
#   a file that contains a complete first JSON document followed by
#   trailing garbage — exactly what we saw.
#
# Three layers of defence now:
#   1. Per-process unique tmp filename (`.tmp.<pid>.<nonce>`) — two writers
#      never share a tmp file, so even without locking they can't trample
#      each other.
#   2. Exclusive flock on a sidecar lock file — serialises writers cleanly,
#      so we don't even create the second tmp until the first has renamed.
#      This solves last-update races as a bonus.
#   3. Rolling .bak preserved before each rename — if a write somehow still
#      manages to corrupt the file (filesystem failure, full disk mid-write,
#      or a process killed between rename and chmod), load() automatically
#      falls back to the .bak.
#
# Plus an integrity check before write: we serialise + round-trip-parse
# the data before touching disk, so a logic bug producing malformed JSON
# fails fast instead of writing garbage.


def _backup_path(path):
    """Return the rolling-backup path for a data file."""
    return path.with_name(path.name + '.bak')


def _lock_path(path):
    """Return the lock-coordination sidecar path for a data file."""
    return path.with_name(path.name + '.lock')


def load(path):
    """Robust load: try the canonical file, fall back to the rolling .bak.

    On corruption, logs a warning to stderr (which goes to nginx error log
    via fcgiwrap) and returns the .bak content if it parses. As a last
    resort, returns {} — same as a missing file — so the rest of the code
    keeps working in degraded mode rather than crashing the whole CGI.

    The fallback path is the difference between "one bad write makes
    devices invisible until manual recovery" (v1.12.0) and "one bad write
    is silently absorbed using the previous heartbeat's state" (v1.12.1).
    """
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        bak = _backup_path(path)
        if bak.exists():
            try:
                data = json.loads(bak.read_text())
                # Log to stderr so this shows up in nginx error log.
                # Don't try to "auto-heal" by writing the .bak back over
                # the corrupted file here — that's load()'s caller's job
                # if they decide to. Read paths shouldn't have side
                # effects on disk.
                sys.stderr.write(
                    f"[remotepower] WARN: {path} corrupted ({exc}); "
                    f"served from {bak.name}\n")
                return data
            except json.JSONDecodeError:
                pass
        sys.stderr.write(
            f"[remotepower] ERROR: {path} corrupted and no usable "
            f".bak ({exc}); returning empty dict\n")
        return {}
    except Exception as exc:
        sys.stderr.write(f"[remotepower] WARN: {path} read failed: {exc}\n")
        return {}


# v2.1.0: split critical section. The v1.12.1 design held the lock across
# the *entire* save — backup + write + fsync + rename. fsync alone can take
# 50–200 ms on a busy ext4 / spinning disk, and the chained saves inside
# handle_heartbeat (devices + cmd_output + containers + config + commands)
# meant one slow writer could stall every agent's heartbeat behind it. The
# CGI then bumped past the agent's HTTP timeout, the agent recorded the
# poll as failed, the server flipped the device to offline — until the
# next heartbeat made it online again. That was the "flock offline
# fluctuation" reported in the field.
#
# The fix here moves the expensive work — serialise, write tmp, fsync —
# *outside* the lock. The lock is now held only for the rename + the
# rolling-backup copy of the previous canonical, both O(1) operations.
# Per-process unique tmp filenames (.tmp.<pid>.<nonce>) already prevented
# the corruption that originally motivated the lock, so writing the tmp
# without the lock is safe; the lock only enforces "one rename at a time"
# so concurrent renames don't tear the .bak rotation.
#
# Two new knobs:
#   * non_blocking=True   — try LOCK_NB; on EAGAIN/EWOULDBLOCK after a
#     short retry budget, raise LockBusy so the caller (heartbeat) can
#     return HTTP 202 instead of stalling the agent. See handle_heartbeat.
#   * Lock wait time is logged whenever the wait exceeds LOCK_WAIT_LOG_MS,
#     so flock contention is visible in nginx's error log without enabling
#     debug mode. If a future "fluctuation" report turns out *not* to be
#     flock, these timings will say so quickly.

LOCK_WAIT_LOG_MS = 50           # log lock waits longer than this
LOCK_NB_RETRIES  = 20           # 20 × 5 ms = 100 ms total before LockBusy
LOCK_NB_SLEEP_S  = 0.005


class LockBusy(Exception):
    """Raised by save(..., non_blocking=True) when the per-file flock is
    held by another writer and the retry budget is exhausted. The caller
    is expected to translate this into HTTP 202 (Accepted) so the agent
    treats the heartbeat as delivered, retries on the next cycle, and
    doesn't get flipped to offline."""
    def __init__(self, path, waited_ms):
        self.path = path
        self.waited_ms = waited_ms
        super().__init__(f"lock busy for {path} after {waited_ms} ms")


def _acquire_lock(path, non_blocking):
    """Open the sidecar lock file and acquire LOCK_EX (blocking) or LOCK_EX
    | LOCK_NB with retries (non-blocking mode). Returns (lock_fd, waited_ms).

    On success in non_blocking mode, waited_ms is the time spent waiting.
    On failure in non_blocking mode, raises LockBusy.
    """
    lock_p = _lock_path(path)
    # Tolerate the sidecar not existing yet or its parent dir not
    # existing yet — first save on a fresh data dir hits both cases.
    try:
        lock_p.touch(mode=0o600, exist_ok=True)
    except FileNotFoundError:
        lock_p.parent.mkdir(parents=True, exist_ok=True)
        lock_p.touch(mode=0o600, exist_ok=True)
    lock_fd = os.open(str(lock_p), os.O_RDWR)

    t0 = time.monotonic()
    if non_blocking:
        # Bounded retry loop — each attempt is non-blocking, sleep between.
        # Total wall time is roughly LOCK_NB_RETRIES * LOCK_NB_SLEEP_S.
        for _ in range(LOCK_NB_RETRIES):
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                waited_ms = int((time.monotonic() - t0) * 1000)
                # v2.1.5: routine lock-wait events are hot paths under
                # load. Logging every one swamps stderr (which under
                # nginx+fcgiwrap becomes the error log). Default silent;
                # set RP_LOG_LOCK_WAITS=1 in the CGI environment to
                # re-enable for diagnostics.
                if waited_ms >= LOCK_WAIT_LOG_MS and os.environ.get('RP_LOG_LOCK_WAITS') == '1':
                    sys.stderr.write(
                        f"[remotepower] lock_wait path={path.name} "
                        f"waited_ms={waited_ms} mode=nb pid={os.getpid()}\n")
                return lock_fd, waited_ms
            except BlockingIOError:
                time.sleep(LOCK_NB_SLEEP_S)
        # Budget exhausted — caller decides what to do
        waited_ms = int((time.monotonic() - t0) * 1000)
        try:
            os.close(lock_fd)
        except OSError:
            pass
        raise LockBusy(path, waited_ms)
    else:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        waited_ms = int((time.monotonic() - t0) * 1000)
        if waited_ms >= LOCK_WAIT_LOG_MS and os.environ.get('RP_LOG_LOCK_WAITS') == '1':
            sys.stderr.write(
                f"[remotepower] lock_wait path={path.name} "
                f"waited_ms={waited_ms} mode=block pid={os.getpid()}\n")
        return lock_fd, waited_ms


def save(path, data, non_blocking=False):
    """Concurrent-safe atomic save. See module-level comment for the
    threat model and the v2.1.0 redesign rationale.

    Sequence:
      1. Round-trip serialise to catch logic bugs before any disk I/O.
      2. Write to a per-process unique .tmp.<pid>.<nonce> file with fsync.
         No lock held during this step — the unique filename prevents
         collisions, and the eventual rename is what publishes the data.
      3. Acquire the lock (blocking or LOCK_NB depending on the flag).
      4. Copy the current canonical to .bak (rolling backup).
      5. Atomic rename of the tmp into the canonical name.
      6. Release the lock.

    Raises LockBusy if non_blocking=True and the lock is contended for
    longer than LOCK_NB_RETRIES * LOCK_NB_SLEEP_S.
    """
    # Step 1: serialise + validate before any disk write. Same as before —
    # allow_nan=False rejects NaN / Infinity / -Infinity. Standard JSON
    # doesn't allow them; Python's default does. Letting them through
    # would mean every non-Python consumer (jq, browsers) fails to parse
    # our files.
    try:
        serialised = json.dumps(data, indent=2, allow_nan=False)
        json.loads(serialised)   # round-trip parse
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Refusing to save unparseable data to {path}: {exc}")

    # Step 2: write the tmp *outside* the lock. Per-process unique filename
    # (pid + nonce) ensures no two writers ever share a tmp, so the historical
    # interleaving bug stays fixed even without locking here.
    tmp = path.with_name(
        f'{path.name}.tmp.{os.getpid()}.{secrets.token_hex(4)}')
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(serialised)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                # tmpfs and a few other filesystems don't support fsync.
                # Not worth failing the write over.
                pass
    except Exception:
        try:
            Path(tmp).unlink(missing_ok=True)
        except OSError:
            pass
        raise

    # Step 3–6: lock just long enough to rotate .bak + rename. Both are
    # metadata ops on modern filesystems; the critical section is now
    # microseconds rather than the tens-of-milliseconds the old fsync
    # path could take.
    lock_fd = None
    try:
        try:
            lock_fd, _ = _acquire_lock(path, non_blocking)
        except LockBusy:
            # Tmp file is orphaned — clean it up before re-raising so we
            # don't leave .tmp.<pid>.<nonce> sitting in the data dir forever.
            try:
                Path(tmp).unlink(missing_ok=True)
            except OSError:
                pass
            raise

        # Rolling backup. Copy (not rename) so a reader concurrently
        # opening the canonical doesn't get a hole. copy2 preserves
        # mode/owner/timestamps — close enough for backup.
        if path.exists():
            try:
                shutil.copy2(str(path), str(_backup_path(path)))
            except OSError:
                # Backup failure shouldn't block the primary write —
                # losing one rolling backup is recoverable; failing the
                # save is not.
                pass

        # Atomic publish
        try:
            os.replace(str(tmp), str(path))
            try:
                os.chmod(str(path), 0o600)
            except OSError:
                pass
        except Exception:
            try:
                Path(tmp).unlink(missing_ok=True)
            except OSError:
                pass
            raise

    finally:
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
            except OSError:
                pass


# ─── v2.1.2: atomic read-modify-write ───────────────────────────────────────
#
# Field report from a real deployment showed last_seen values getting
# *reverted* between heartbeats — `pmg01` heartbeats at T with last_seen=T,
# 60s later the OFFLINE check reads last_seen=T-120 from devices.json.
# Cause: classic lost-update race introduced by the v2.1.0 save() redesign.
# v2.0 held the flock from before the tmp write through after the rename;
# the v2.1.0 fsync-outside-lock optimisation moved tmp+fsync OUTSIDE the
# lock, leaving only the rename protected.
#
# But the caller's pattern is read-modify-write:
#     devices = load(DEVICES_FILE)        # reads OUTSIDE any lock
#     devices[id]['last_seen'] = now      # in-memory mutation
#     save(DEVICES_FILE, devices)         # only the rename is locked
#
# Two heartbeats interleaving:
#   A: load → devices = {pmg01: T-180, web01: T-180}
#   B: load → devices = {pmg01: T-180, web01: T-180}
#   A: devices[pmg01].last_seen = T; write tmp.A with that snapshot
#   B: devices[web01].last_seen  = T; write tmp.B with that snapshot
#   A: lock → rename tmp.A → devices.json has pmg01=T, web01=T-180
#   B: lock → rename tmp.B → devices.json has pmg01=T-180, web01=T  ← A's update lost
#
# The lock was protecting the rename. It wasn't protecting the read-modify-
# write that the *caller* was doing. Holding the lock for longer in v2.0
# happened to narrow the window but didn't eliminate it; v2.1.0's faster
# saves widened it dramatically.
#
# Fix: callers that do read-modify-write must hold the lock across all
# three steps. The context manager below does that. The yielded data is
# loaded WHILE the lock is held; on clean exit, it's saved WHILE the lock
# is still held. SystemExit (raised by respond()) is treated as "abort,
# don't save" — the lock is still released.

class _LockedUpdate:
    """Context manager: acquire flock → load → yield data → save → release.

    Usage:
        with _locked_update(DEVICES_FILE) as devices:
            devices[id]['last_seen'] = now
            # auto-saved on exit if no exception

    If the with-block raises (including SystemExit from respond()), the
    save is skipped. The lock is always released. The on-disk file
    cannot be torn or partially overwritten because save_held uses the
    same tmp-and-rename pattern as save(); the difference is just that
    the lock is already held.

    `non_blocking` triggers LockBusy if the lock is contended past the
    retry budget. Default is blocking — the alternative for the devices
    update is the agent's heartbeat silently losing last_seen, which is
    exactly the bug we're fixing.
    """

    def __init__(self, path, non_blocking=False):
        self.path = path
        self.non_blocking = non_blocking
        self._lock_fd = None
        self._data = None

    def __enter__(self):
        self._lock_fd, _wait = _acquire_lock(self.path, self.non_blocking)
        try:
            self._data = load(self.path)
        except Exception:
            # Release the lock if load itself fails; otherwise __exit__
            # would also try to release a lock that's already released.
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
                os.close(self._lock_fd)
            except OSError:
                pass
            self._lock_fd = None
            raise
        return self._data

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            # Only save on clean exit. SystemExit (from respond()) and
            # any other exception aborts the write — the partial dict
            # is not safe to publish if the handler bailed out mid-way.
            if exc_type is None and self._data is not None:
                _save_held(self.path, self._data)
        finally:
            if self._lock_fd is not None:
                try:
                    fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
                    os.close(self._lock_fd)
                except OSError:
                    pass
                self._lock_fd = None
        return False  # don't swallow exceptions


def _locked_update(path, non_blocking=False):
    return _LockedUpdate(path, non_blocking)


def _save_held(path, data):
    """save() variant that assumes the caller already holds the flock.

    Same serialise → tmp → fsync → backup → rename sequence; only the
    flock acquisition and release are skipped. Used by _LockedUpdate
    and anywhere else inside an already-locked section.
    """
    try:
        serialised = json.dumps(data, indent=2, allow_nan=False)
        json.loads(serialised)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Refusing to save unparseable data to {path}: {exc}")

    tmp = path.with_name(
        f'{path.name}.tmp.{os.getpid()}.{secrets.token_hex(4)}')
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(serialised)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
    except Exception:
        try:
            Path(tmp).unlink(missing_ok=True)
        except OSError:
            pass
        raise

    if path.exists():
        try:
            shutil.copy2(str(path), str(_backup_path(path)))
        except OSError:
            pass

    try:
        os.replace(str(tmp), str(path))
        try:
            os.chmod(str(path), 0o600)
        except OSError:
            pass
    except Exception:
        try:
            Path(tmp).unlink(missing_ok=True)
        except OSError:
            pass
        raise


def ensure_default_user():
    users = load(USERS_FILE)
    if not users:
        # v2.3.2: seed via hash_password() (bcrypt or salted PBKDF2)
        # instead of a bare unsalted sha256. The password is still the
        # documented default 'remotepower' — the operator MUST change
        # it on first login; `must_change_password` drives a warning
        # banner in the UI until they do.
        save(USERS_FILE, {'admin': {
            'password_hash': hash_password('remotepower'),
            'created': int(time.time()),
            'role': 'admin',
            'must_change_password': True,
        }})

ensure_default_user()

# ── Auth ───────────────────────────────────────────────────────────────────────
def make_token():
    return secrets.token_urlsafe(32)

def verify_token(token):
    """Returns (username, role) or (None, None).
    Session tokens: O(1) dict lookup.
    API keys: constant-time scan but with early-exit only after full scan
    to avoid timing oracle revealing which key prefix is valid.
    """
    if not token:
        return None, None

    # Session tokens
    tokens = load(TOKENS_FILE)
    now = int(time.time())
    entry = tokens.get(token)
    if entry:
        # v1.8.4: tokens may have their own ttl (per-session — controlled by
        # remember-me at login). Fall back to legacy TOKEN_TTL.
        ttl = entry.get('ttl', TOKEN_TTL)
        if now - entry['created'] > ttl:
            del tokens[token]
            save(TOKENS_FILE, tokens)
        else:
            username = entry.get('user')
            users = load(USERS_FILE)
            u = users.get(username)
            if not u:
                return None, None
            role = u.get('role', 'admin')
            return username, role

    # API keys — full constant-time scan (no early exit)
    apikeys = load(APIKEYS_FILE)
    matched_user = None
    matched_role = None
    for kid, kdata in apikeys.items():
        stored_key = kdata.get('key', '')
        # Pad both to same length for compare_digest (keys are fixed-length urlsafe)
        if len(stored_key) == len(token):
            if hmac.compare_digest(stored_key, token):
                if kdata.get('active', True):
                    exp = kdata.get('expires_at')
                    if exp is not None and int(time.time()) > exp:
                        continue  # expired key
                    matched_user = kdata.get('user', 'api')
                    matched_role = kdata.get('role', 'admin')
    if matched_user:
        return matched_user, matched_role

    return None, None

def cleanup_tokens():
    tokens = load(TOKENS_FILE)
    now = int(time.time())
    pruned = {
        k: v for k, v in tokens.items()
        if now - v.get('created', 0) <= v.get('ttl', TOKEN_TTL)
    }
    if len(pruned) != len(tokens):
        save(TOKENS_FILE, pruned)

# ── Brute-force protection ─────────────────────────────────────────────────────
def _get_client_ip():
    """Best-effort client IP from CGI env. Nginx should set REMOTE_ADDR."""
    return os.environ.get('REMOTE_ADDR', '0.0.0.0')

def _check_login_ratelimit(username: str) -> bool:
    """Return True if this login attempt is allowed, False if locked out."""
    rl = load(RATELIMIT_FILE)
    now = int(time.time())
    key = f'login:{username}'
    entry = rl.get(key, {'failures': [], 'locked_until': 0})

    # Purge old failures outside window
    entry['failures'] = [t for t in entry['failures'] if now - t < LOGIN_FAIL_WINDOW]

    if entry.get('locked_until', 0) > now:
        return False  # still locked

    return True

def _record_login_failure(username: str):
    rl = load(RATELIMIT_FILE)
    now = int(time.time())
    key = f'login:{username}'
    entry = rl.get(key, {'failures': [], 'locked_until': 0})
    entry['failures'] = [t for t in entry['failures'] if now - t < LOGIN_FAIL_WINDOW]
    entry['failures'].append(now)
    if len(entry['failures']) >= LOGIN_FAIL_MAX:
        entry['locked_until'] = now + LOGIN_LOCKOUT_TIME
        entry['failures'] = []  # reset counter after lockout
    rl[key] = entry
    save(RATELIMIT_FILE, rl)

def _clear_login_failures(username: str):
    rl = load(RATELIMIT_FILE)
    key = f'login:{username}'
    if key in rl:
        del rl[key]
        save(RATELIMIT_FILE, rl)

# ── Request helpers ────────────────────────────────────────────────────────────
def get_body():
    length = int(os.environ.get('CONTENT_LENGTH', 0) or 0)
    # Hard cap: reject oversized bodies
    if length > MAX_BODY_BYTES:
        respond(413, {'error': 'Request body too large'})
    return sys.stdin.buffer.read(length) if length > 0 else b''

def get_json_body():
    try:
        raw = get_body()
        if not raw:
            return {}
        return json.loads(raw)
    except Exception:
        return {}

def get_token_from_request():
    return os.environ.get('HTTP_X_TOKEN', '')

def path_info():
    return os.environ.get('PATH_INFO', '').rstrip('/')

def method():
    return os.environ.get('REQUEST_METHOD', 'GET').upper()

# ── Response helpers ───────────────────────────────────────────────────────────


class HTTPError(Exception):
    """
    Short-circuit a handler with an HTTP status + JSON body.

    Replaces the older ``respond(...); sys.exit(0)`` pattern. Handlers that
    raise ``HTTPError`` are unwound by ``main()`` and rendered identically
    to a successful response — same status, same JSON envelope, same
    headers.

    The exception form is purely an internal control-flow tool. Callers
    that want to *return* an error response should still use
    ``respond(status, body)`` — ``respond`` raises ``HTTPError`` itself,
    which is then caught one level up.

    Why an exception instead of ``sys.exit``? Tests can catch ``HTTPError``
    and inspect ``status``/``body`` directly without monkey-patching
    ``sys.exit`` or capturing stdout. In production it's a wash — the
    process still terminates after rendering the response.
    """

    def __init__(self, status: int, body):
        super().__init__(f"HTTP {status}")
        self.status = status
        self.body = body


_HTTP_STATUS_REASONS = {
    200: 'OK', 201: 'Created', 400: 'Bad Request', 401: 'Unauthorized',
    403: 'Forbidden', 404: 'Not Found', 405: 'Method Not Allowed',
    409: 'Conflict', 413: 'Request Entity Too Large', 429: 'Too Many Requests',
    500: 'Internal Server Error',
}


def _render_response(status: int, data) -> None:
    """Render an HTTP response to stdout. Used by main() — handlers should
    use respond()/HTTPError instead so the response is uniformly handled."""
    print(f"Status: {status} {_HTTP_STATUS_REASONS.get(status, '')}")
    print("Content-Type: application/json")
    print("Cache-Control: no-store")
    print("X-Content-Type-Options: nosniff")
    print()
    print(json.dumps(data))


def respond(status, data):
    """
    Short-circuit the current handler with an HTTP response.

    Despite the name, this does **not** return — it raises ``HTTPError``
    which is unwound at the top of ``main()``. The signature is
    preserved for backward compatibility with the ~100 existing call
    sites; new code should prefer ``raise HTTPError(status, data)``
    directly.
    """
    raise HTTPError(status, data)


def require_auth(require_admin=False):
    token = get_token_from_request()
    username, role = verify_token(token)
    if not username:
        respond(401, {'error': 'Unauthorized'})
    if require_admin and role == 'viewer':
        respond(403, {'error': 'Viewer accounts cannot perform this action'})
    return username

def require_admin_auth():
    return require_auth(require_admin=True)

# ── Input sanitization helpers ─────────────────────────────────────────────────
_IP_RE  = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'  # IPv4
    r'|(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$'                                # IPv6 simplified
)
_MAC_RE = re.compile(r'^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$')
_VER_RE = re.compile(r'^\d{1,4}\.\d{1,4}(?:\.\d{1,4})?(?:[.\-]\w{1,16})?$')

def _sanitize_str(value, max_len, allow_empty=True):
    """Truncate and strip a string field."""
    if value is None:
        return ''
    s = str(value).strip()
    if not allow_empty and not s:
        return ''
    return s[:max_len]

def _sanitize_hostname(h):
    """RFC-1123 hostname: letters, digits, hyphens, dots. Max 253 chars."""
    h = _sanitize_str(h, MAX_HOSTNAME_LEN)
    # Strip anything that isn't hostname-safe
    h = re.sub(r'[^a-zA-Z0-9.\-]', '', h)
    return h[:MAX_HOSTNAME_LEN] or 'unknown'

def _sanitize_ip(ip):
    if not ip:
        return ''
    ip = str(ip).strip()[:MAX_IP_LEN]
    if _IP_RE.match(ip):
        return ip
    return ''

def _sanitize_mac(mac):
    if not mac:
        return ''
    mac = str(mac).strip()[:MAX_MAC_LEN]
    if _MAC_RE.match(mac):
        return mac
    return ''

def _sanitize_version(v):
    if not v:
        return ''
    v = str(v).strip()[:MAX_VERSION_LEN]
    if _VER_RE.match(v):
        return v
    return ''

def _sanitize_monitor_target(mtype, target):
    """Validate monitor targets to prevent SSRF and flag injection."""
    target = str(target).strip()[:512]
    if mtype == 'ping':
        # Only allow valid hostname/IP — no flags (dashes at start)
        host = re.sub(r'[^a-zA-Z0-9.\-]', '', target)
        if not host or host.startswith('-'):
            return None
        return host
    elif mtype == 'tcp':
        # host:port — validate both parts
        host, _, port_s = target.partition(':')
        host = re.sub(r'[^a-zA-Z0-9.\-]', '', host)
        if not host or host.startswith('-'):
            return None
        try:
            port = int(port_s)
            if not (1 <= port <= 65535):
                return None
        except (ValueError, TypeError):
            return None
        return f"{host}:{port}"
    elif mtype == 'http':
        # Only allow http:// and https://, no file:// or internal schemes
        parsed = urllib.parse.urlparse(target)
        if parsed.scheme not in ('http', 'https'):
            return None
        # Block private/loopback ranges (basic SSRF guard)
        host = parsed.hostname or ''
        blocked_hosts = ('localhost', '127.', '0.0.0.0', '169.254.', '10.', '192.168.', '172.')
        # Allow explicit override via config for intentional internal monitoring
        for b in blocked_hosts:
            if host == b.rstrip('.') or host.startswith(b):
                cfg = load(CONFIG_FILE)
                if not cfg.get('allow_internal_monitors', False):
                    return None
        return target
    return None

# ── Command history ────────────────────────────────────────────────────────────
def log_command(actor, device_id, device_name, command):
    history = load(HISTORY_FILE)
    entries = history.get('entries', [])
    entries.append({
        'ts':          int(time.time()),
        'actor':       _sanitize_str(actor, 64),
        'device_id':   _sanitize_str(device_id, 64),
        'device_name': _sanitize_str(device_name, MAX_NAME_LEN),
        'command':     _sanitize_str(command, 600),
    })
    history['entries'] = entries[-MAX_HISTORY:]
    save(HISTORY_FILE, history)

# ── Audit log with IP tracking ─────────────────────────────────────────────────
def audit_log(actor, action, detail='', source_ip=None):
    """Log action with actor, IP, and detail for security auditing."""
    al = load(AUDIT_LOG_FILE)
    entries = al.get('entries', [])
    entries.append({
        'ts':        int(time.time()),
        'actor':     _sanitize_str(actor, 64),
        'action':    _sanitize_str(action, 128),
        'detail':    _sanitize_str(detail, 512),
        'source_ip': _sanitize_ip(source_ip or _get_client_ip()),
        'user_agent': _sanitize_str(os.environ.get('HTTP_USER_AGENT', ''), 256),
    })
    al['entries'] = entries[-MAX_AUDIT_LOG:]
    save(AUDIT_LOG_FILE, al)

# ── Webhook ────────────────────────────────────────────────────────────────────
def _log_webhook(event, url, status, detail=''):
    """Append an entry to the webhook log (last MAX_WEBHOOK_LOG entries)."""
    try:
        wl = load(WEBHOOK_LOG_FILE)
        entries = wl.get('entries', [])
        entries.append({
            'ts':     int(time.time()),
            'event':  str(event)[:64],
            'url':    str(url)[:256],
            'status': str(status)[:16],
            'detail': str(detail)[:512],
        })
        wl['entries'] = entries[-MAX_WEBHOOK_LOG:]
        save(WEBHOOK_LOG_FILE, wl)
    except Exception:
        pass


def is_email_event_enabled(event, cfg=None):
    """v1.8.6: per-event email toggle. Independent of webhook toggle.
    SMTP must also be enabled overall and have at least one recipient."""
    if cfg is None:
        cfg = _config()
    if not cfg.get('smtp_enabled'):
        return False
    if not (cfg.get('smtp_recipients') or '').strip():
        return False
    events = cfg.get('email_events') or {}
    if event in events:
        return bool(events[event])
    # Default: not enabled (opt-in per event). Webhook stays opt-out by default.
    return False


def _smtp_recipients_list(cfg):
    """Parse the comma/semicolon/whitespace-separated recipients string."""
    raw = (cfg.get('smtp_recipients') or '')
    parts = re.split(r'[,;\s]+', raw)
    return [p.strip() for p in parts if p and '@' in p]


def _send_event_email(event, payload, message, cfg, server_name):
    """Send the email channel for an event. Failures are logged, never raised."""
    recipients = _smtp_recipients_list(cfg)
    if not recipients:
        return
    try:
        subject, body = smtp_notifier.render_event_email(server_name, event, payload, message)
        smtp_notifier.send_email(cfg, recipients, subject, body)
        _log_email(event, recipients, 'ok', '')
    except smtp_notifier.SmtpError as e:
        _log_email(event, recipients, 'error', str(e))
    except Exception as e:
        _log_email(event, recipients, 'error', f'{type(e).__name__}: {e}')


def _log_email(event, recipients, status, detail):
    """Append to the webhook log file but tag as 'email' channel for visibility."""
    try:
        log = load(WEBHOOK_LOG_FILE)
        if not isinstance(log, list):
            log = []
        log.insert(0, {
            'ts':         int(time.time()),
            'event':      f'{event} (email)',
            'status':     status,
            'detail':     f'{len(recipients)} recipient(s): {detail}'[:300],
        })
        save(WEBHOOK_LOG_FILE, log[:MAX_WEBHOOK_LOG])
    except Exception:
        pass


def _record_fleet_event(event, payload):
    """v2.2.4: append to the dedicated fleet event log. Records every
    fired event regardless of whether anything got delivered downstream.

    Filters the payload down to a compact summary (device id+name plus
    a few discriminator fields) — the full payload can be huge for
    cve_found, log_alert, etc., and the Home dashboard only needs
    enough to render a single feed item.

    Bounded write: the log is capped at MAX_FLEET_EVENTS entries with
    oldest evicted. 'test' events (operator SMTP / webhook tests) are
    NOT recorded — they're not fleet events.
    """
    if event == 'test':
        return    # operator-triggered tests don't belong here
    summary = {}
    if isinstance(payload, dict):
        for key in ('device_id', 'device_name', 'name', 'host',
                    'path', 'unit', 'metric', 'cve_id',
                    'severity', 'critical', 'high',
                    'upgradable', 'pattern', 'level',
                    # v2.3.0: Proxmox action discriminators
                    'guest_type', 'vmid', 'action'):
            if key in payload and payload[key] is not None:
                v = payload[key]
                # Cap string lengths so a poisoned payload can't bloat
                # the log file
                if isinstance(v, str):
                    v = v[:256]
                summary[key] = v
    entry = {
        'ts':      int(time.time()),
        'event':   str(event)[:64],
        'payload': summary,
    }
    try:
        with _LockedUpdate(FLEET_EVENTS_FILE) as store:
            events = store.setdefault('events', [])
            events.append(entry)
            if len(events) > MAX_FLEET_EVENTS:
                # Keep the newest tail
                del events[:-MAX_FLEET_EVENTS]
    except Exception:
        # Caller wraps us too, but be defensive
        pass


def fire_webhook(event, payload):
    """
    v1.8.6: Despite the historical name, this is now the single dispatch point
    for both webhook and email notifications. It runs the shared gates
    (per-event toggle, CVE severity filter, maintenance suppression) once,
    then fans out to whichever channels are configured.

    v2.2.4: now also records the event itself in fleet_events.json,
    BEFORE the gates. The fleet event log captures what HAPPENED on
    the fleet, regardless of whether anything was delivered downstream.
    The Home dashboard activity panel reads from fleet_events.json so
    fleet events show up there even if no webhook or email is
    configured. The original gates (per-event toggle, maintenance
    window, etc.) still apply to deliveries — they don't filter out
    "what happened" from the log.
    """
    # v2.2.4: always record the event itself, regardless of any
    # downstream gating. Wrapped — a bug here must never break the
    # event firing path.
    try:
        _record_fleet_event(event, payload)
    except Exception:
        pass

    cfg = load(CONFIG_FILE)

    # v1.8.4: per-event toggle. If disabled, log it and bail.
    if not is_webhook_event_enabled(event):
        webhook_url = cfg.get('webhook_url', '').strip()
        if webhook_url:
            _log_webhook(event, webhook_url, 'disabled', f'event "{event}" disabled in settings')
        return

    # v1.8.4: cve_found severity filter
    if event == 'cve_found':
        allowed_sev = set(get_cve_severity_filter())
        any_in_allowlist = (
            ('critical' in allowed_sev and payload.get('critical', 0) > 0) or
            ('high' in allowed_sev and payload.get('high', 0) > 0)
        )
        if not any_in_allowlist:
            url = cfg.get('webhook_url', '').strip()
            if url:
                _log_webhook(event, url, 'filtered',
                             f'no findings match severity filter {sorted(allowed_sev)}')
            return

    # v1.8.0: maintenance-window suppression — applies to BOTH channels
    try:
        mw = in_maintenance(event, payload)
    except Exception:
        mw = None
    if mw:
        try:
            log_suppression(event, payload, mw)
        except Exception:
            pass
        url = cfg.get('webhook_url', '').strip()
        if url:
            _log_webhook(event, url, 'suppressed', f'maintenance: {mw.get("reason", "")}')
        return

    # Build the human-readable message once — used by both channels
    server_name = get_server_name()
    payload_with_branding = dict(payload)
    payload_with_branding['_server_name'] = server_name
    message = _webhook_message(event, payload_with_branding)

    # ── Channel 1: Webhook ──────────────────────────────────────────────────────
    _send_webhook_to_url(event, payload_with_branding, message, cfg)

    # ── Channel 2: Email ────────────────────────────────────────────────────────
    if is_email_event_enabled(event, cfg):
        _send_event_email(event, payload_with_branding, message, cfg, server_name)


def _send_webhook_to_url(event, safe_payload, message, cfg):
    """Send the HTTP webhook portion. Was the body of fire_webhook pre-1.8.6."""
    url = cfg.get('webhook_url', '').strip()
    if not url:
        return  # Webhooks disabled (just running for email)

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        _log_webhook(event, url, 'error', 'invalid scheme (must be http or https)')
        return

    # Sanitize values
    safe_payload = {k: (str(v)[:256] if isinstance(v, str) else v) for k, v in safe_payload.items()}

    # Build human-readable title + message for push services
    titles = {
        'device_offline': 'Device Offline',
        'device_online':  'Device Online',
        'command_queued':  'Command Queued',
        'command_executed': 'Command Executed',
        'patch_alert':     'Patch Alert',
        'monitor_down':    'Monitor Down',
        'monitor_up':      'Monitor Recovered',
        'cve_found':       'New CVEs Detected',
        'service_down':    'Service Down',
        'service_up':      'Service Recovered',
        'log_alert':       'Log Pattern Matched',
        # v1.11.4
        'container_stopped':    'Container Stopped',
        'container_restarting': 'Container Restarting',
        'containers_stale':     'Container Data Stale',
        # v1.11.10
        'metric_warning':       'Resource Warning',
        'metric_critical':      'Resource Critical',
        'metric_recovered':     'Resource Recovered',
        # v2.5.0
        'custom_script_fail':    'Custom Script Failed',
        'custom_script_recover': 'Custom Script Recovered',
        # v2.6.0
        'config_drift':          'Host Config Drift Detected',
        'test':            'Webhook Test',
    }
    title = titles.get(event, f'RemotePower: {event}')
    # message was passed in (computed once for both webhook + email channels)
    priority = _webhook_priority(event)

    # ── Auto-detect service and build appropriate payload ─────────────────
    host = parsed.hostname or ''

    if 'discord.com' in host or 'discordapp.com' in host:
        # Discord expects { content: "..." } or { embeds: [...] }
        colors = {
            'device_offline': 0xEF4444, 'device_online': 0x22C55E,
            'monitor_down': 0xEF4444, 'monitor_up': 0x22C55E,
            'patch_alert': 0xF59E0B, 'command_queued': 0x3B7EFF,
            'command_executed': 0x3B7EFF, 'test': 0x7C3AED,
            # v1.11.4
            'container_stopped': 0xEF4444,
            'container_restarting': 0xF59E0B,
            'containers_stale': 0xF59E0B,
        }
        body = json.dumps({
            'username': 'RemotePower',
            'embeds': [{
                'title': title,
                'description': message,
                'color': colors.get(event, 0x3B7EFF),
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'footer': {'text': f'RemotePower {SERVER_VERSION}'},
            }],
        }).encode()
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': f'RemotePower/{SERVER_VERSION}',
        }

    elif 'hooks.slack.com' in host:
        # Slack expects { text: "..." } or { blocks: [...] }
        body = json.dumps({
            'text': f'*{title}*\n{message}',
        }).encode()
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': f'RemotePower/{SERVER_VERSION}',
        }

    else:
        # Generic / Ntfy / Gotify — JSON body + push-friendly headers
        body = json.dumps({
            'event': str(event)[:64],
            'ts': int(time.time()),
            'title': title,
            'message': message,
            'priority': priority,
            **safe_payload,
        }).encode()
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': f'RemotePower/{SERVER_VERSION}',
            # Ntfy / Gotify / Pushover compatible headers
            'X-Title': title,
            'X-Priority': str(priority),
            'X-Tags': _webhook_tags(event),
        }

    req = urllib.request.Request(url, data=body, headers=headers, method='POST')
    try:
        ctx = None
        if parsed.scheme == 'https':
            ctx = _get_ssl_context()
        resp = urllib.request.urlopen(req, timeout=10, context=ctx)
        _log_webhook(event, url, resp.status, f'OK ({resp.status})')
    except urllib.error.HTTPError as e:
        _log_webhook(event, url, e.code, f'HTTP {e.code}: {str(e.reason)[:200]}')
    except urllib.error.URLError as e:
        _log_webhook(event, url, 'error', f'URLError: {str(e.reason)[:200]}')
    except Exception as e:
        _log_webhook(event, url, 'error', f'{type(e).__name__}: {str(e)[:200]}')


def _webhook_message(event, payload):
    """Build a human-readable message string for push notifications."""
    name = payload.get('name', payload.get('device_id', 'unknown'))
    if event == 'device_offline':
        return f'{name} went offline (last seen: {_ts_fmt(payload.get("last_seen", 0))})'
    elif event == 'device_online':
        return f'{name} is back online'
    elif event == 'command_queued':
        return f'{payload.get("actor", "system")} queued "{payload.get("command", "?")}" on {name}'
    elif event == 'command_executed':
        return f'{name} executed "{payload.get("command", "?")}"'
    elif event == 'patch_alert':
        return f'{name} has {payload.get("upgradable", "?")} pending updates (threshold: {payload.get("threshold", "?")})'
    elif event == 'cve_found':
        sev_summary = f'{payload.get("critical", 0)} critical, {payload.get("high", 0)} high'
        return f'{name}: {payload.get("count", "?")} new CVEs ({sev_summary})'
    elif event == 'monitor_down':
        return f'Monitor "{payload.get("label", "?")}" ({payload.get("type", "?")}: {payload.get("target", "?")}) is DOWN — {payload.get("detail", "")}'
    elif event == 'monitor_up':
        return f'Monitor "{payload.get("label", "?")}" ({payload.get("type", "?")}: {payload.get("target", "?")}) recovered'
    elif event == 'service_down':
        return f'{name}: {payload.get("unit", "?")} is {payload.get("active", "down")} (was {payload.get("previous", "active")})'
    elif event == 'service_up':
        return f'{name}: {payload.get("unit", "?")} is active again'
    elif event == 'log_alert':
        # v2.1.1: include the first matched line in the message. Field
        # report: "pattern matched 1 times" is useless on its own — the
        # operator wants to see WHICH line tripped the rule so they can
        # decide if it's a real alert or noise. We truncate aggressively
        # (200 chars) because Discord/Slack message limits + multi-line
        # journald entries can blow up the embed.
        sample = payload.get('sample') or []
        head = f'{name}/{payload.get("unit", "?")}: pattern "{payload.get("pattern", "")}" matched {payload.get("count", "?")} time(s)'
        if isinstance(sample, list) and sample:
            first = str(sample[0]).strip().replace('\n', ' ')
            if len(first) > 200:
                first = first[:200] + '…'
            head += f'\n→ {first}'
            extra = len(sample) - 1
            if extra > 0:
                head += f'\n(+ {extra} more matching line{"s" if extra > 1 else ""})'
        return head
    # ── v1.11.4: container events ──────────────────────────────────────────
    elif event == 'container_stopped':
        return (f'{name}: container "{payload.get("container", "?")}" '
                f'({payload.get("runtime", "?")}) stopped '
                f'(was {payload.get("previous_status", "?")}, now {payload.get("status", "gone")})')
    elif event == 'container_restarting':
        return (f'{name}: container "{payload.get("container", "?")}" '
                f'restarted {payload.get("delta", "?")} time(s) since last report '
                f'(total restart_count={payload.get("restart_count", "?")})')
    elif event == 'containers_stale':
        return (f'{name}: no container report for {payload.get("age_minutes", "?")} '
                f'minutes (TTL: {payload.get("ttl_minutes", "?")} min). '
                f'Last seen {_ts_fmt(payload.get("reported_at", 0))}.')
    # ── v1.11.10: metric thresholds ────────────────────────────────────────
    elif event in ('metric_warning', 'metric_critical'):
        kind = payload.get('kind', '?')
        target = payload.get('target', '')
        sev = 'CRITICAL' if event == 'metric_critical' else 'WARNING'
        # Disk has a target (mount path); other kinds don't.
        if kind == 'disk' and target:
            return (f'{name}: {sev} — disk {target} at '
                    f'{payload.get("value", "?")}% '
                    f'(threshold: {payload.get("threshold", "?")}%)')
        if kind == 'cpu':
            return (f'{name}: {sev} — load avg '
                    f'{payload.get("value", "?")} on {payload.get("cpu_count", "?")} '
                    f'CPUs (threshold ratio: {payload.get("threshold", "?")})')
        return (f'{name}: {sev} — {kind} at '
                f'{payload.get("value", "?")}% (threshold: {payload.get("threshold", "?")}%)')
    elif event == 'metric_recovered':
        kind = payload.get('kind', '?')
        target = payload.get('target', '')
        if kind == 'disk' and target:
            return (f'{name}: disk {target} recovered to '
                    f'{payload.get("value", "?")}%')
        if kind == 'cpu':
            return (f'{name}: cpu load recovered to {payload.get("value", "?")}')
        return f'{name}: {kind} recovered to {payload.get("value", "?")}%'
    elif event == 'test':
        return f'This is a test notification from RemotePower ({payload.get("server_version", "?")}). If you see this, webhooks are working!'
    # ── v2.5.0: custom monitoring scripts ─────────────────────────────────
    elif event == 'custom_script_fail':
        out = str(payload.get('output', '')).strip()
        snippet = (f' — {out[:120]}' if out else '')
        return f'{name}: script "{payload.get("script_name", "?")}" FAILED (exit {payload.get("rc", "?")}){snippet}'
    elif event == 'custom_script_recover':
        return f'{name}: script "{payload.get("script_name", "?")}" recovered (OK)'
    elif event == 'config_drift':
        sections = payload.get('sections', [])
        sec_str = ', '.join(sections[:5]) if sections else 'unknown'
        return f'{name}: host config drift in {sec_str}'
    return f'{event}: {name}'


def _webhook_priority(event):
    """Return numeric priority (1-5) for push services. 3=default, 4=high, 5=urgent."""
    if event == 'cve_found' or event == 'metric_critical':
        return 5
    if event in ('device_offline', 'monitor_down', 'patch_alert', 'service_down',
                 'log_alert', 'container_stopped', 'containers_stale',
                 'metric_warning', 'custom_script_fail', 'config_drift'):
        return 4
    if event in ('device_online', 'monitor_up', 'service_up', 'metric_recovered',
                 'custom_script_recover'):
        return 3
    return 3


def _webhook_tags(event):
    """Return emoji tags for Ntfy-style push services."""
    tags = {
        'device_offline': 'red_circle,computer',
        'device_online':  'green_circle,computer',
        'command_queued':  'arrow_forward',
        'command_executed': 'white_check_mark',
        'patch_alert':     'warning,package',
        'cve_found':       'rotating_light,shield',
        'monitor_down':    'red_circle,satellite',
        'monitor_up':      'green_circle,satellite',
        'service_down':    'red_circle,gear',
        'service_up':      'green_circle,gear',
        'log_alert':       'warning,scroll',
        # v1.11.4
        'container_stopped':    'red_circle,whale',
        'container_restarting': 'warning,whale',
        'containers_stale':     'warning,hourglass',
        # v1.11.10
        'metric_warning':       'warning,bar_chart',
        'metric_critical':      'rotating_light,bar_chart',
        'metric_recovered':     'green_circle,bar_chart',
        # v2.5.0: custom monitoring scripts
        'custom_script_fail':    'red_circle,test_tube',
        'custom_script_recover': 'green_circle,test_tube',
        # v2.6.0: host configuration drift
        'config_drift':          'warning,wrench',
        'test':            'white_check_mark,bell',
    }
    return tags.get(event, 'bell')


def _ts_fmt(ts):
    """Format a unix timestamp to human-readable string."""
    if not ts:
        return 'never'
    try:
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(ts)))
    except Exception:
        return str(ts)


def check_offline_webhooks():
    """Per-request sweep: walk every monitored device, flip the on/off
    sticky bit, fire device_offline / device_online webhooks on edge.

    v2.1.1: every state change now logs to stderr regardless of webhook
    config. Previous versions only logged if a webhook fired, and only
    inside the fire_webhook() path — so an operator who hadn't configured
    webhooks had no way to tell from server logs why a device showed as
    offline. The dashboard would just flip the badge silently and the
    only artifact was 'last_seen' getting old in devices.json.
    """
    cfg = load(CONFIG_FILE)
    devices = load(DEVICES_FILE)
    now = int(time.time())
    ttl = get_online_ttl()
    notified = cfg.get('offline_notified', {})
    webhook_enabled = is_webhook_event_enabled('device_offline')
    changed = False
    for dev_id, dev in devices.items():
        if dev.get('agentless'):
            continue
        if not dev.get('monitored', True):
            continue
        last = dev.get('last_seen', 0)
        if not last:
            continue  # never heartbeated, don't claim it went offline
        delta = now - last
        is_offline = delta > ttl
        already = notified.get(dev_id, False)
        if is_offline and not already:
            # ALWAYS log the transition, regardless of webhook config. This
            # is the single most useful diagnostic for the "why is X
            # offline?" question — it tells the operator exactly when the
            # server flipped state and what last_seen was at the time.
            sys.stderr.write(
                f"[remotepower] OFFLINE dev={dev_id} name={dev.get('name','?')!r} "
                f"last_seen={last} delta={delta}s ttl={ttl}s "
                f"poll_interval={dev.get('poll_interval', 60)}s\n")
            if webhook_enabled:
                fire_webhook('device_offline', {
                    'device_id': dev_id, 'name': dev.get('name', dev_id),
                    'hostname': dev.get('hostname', ''), 'last_seen': last,
                    'delta_seconds': delta, 'ttl_seconds': ttl,
                })
            # v2.4.10: record the OFFLINE transition in uptime.json.
            # Previously _record_uptime was only ever called with
            # online=True (from the heartbeat), so uptime.json only
            # ever held a single online event per device and the
            # 7-day status stripe had no real history to draw on.
            try:
                _record_uptime(dev_id, dev.get('name', dev_id), False)
            except Exception:
                pass
            notified[dev_id] = True
            changed = True
        elif not is_offline and already:
            sys.stderr.write(
                f"[remotepower] ONLINE dev={dev_id} name={dev.get('name','?')!r} "
                f"last_seen={last} delta={delta}s\n")
            if webhook_enabled:
                fire_webhook('device_online', {'device_id': dev_id,
                                               'name': dev.get('name', dev_id)})
            try:
                _record_uptime(dev_id, dev.get('name', dev_id), True)
            except Exception:
                pass
            notified[dev_id] = False
            changed = True
    if changed:
        cfg['offline_notified'] = notified
        save(CONFIG_FILE, cfg)

    threshold = cfg.get(PATCH_ALERT_KEY)
    if threshold is not None:
        try:
            threshold = int(threshold)
            alerted = cfg.get('patch_alerted', {})
            patch_changed = False
            for dev_id, dev in devices.items():
                count = dev.get('sysinfo', {}).get('packages', {}).get('upgradable')
                if not isinstance(count, int):
                    continue
                over = count >= threshold
                was = alerted.get(dev_id, False)
                if over and not was:
                    fire_webhook('patch_alert', {
                        'device_id': dev_id, 'name': dev.get('name', dev_id),
                        'hostname': dev.get('hostname', ''), 'upgradable': count,
                        'threshold': threshold,
                    })
                    alerted[dev_id] = True; patch_changed = True
                elif not over and was:
                    alerted[dev_id] = False; patch_changed = True
            if patch_changed:
                cfg['patch_alerted'] = alerted
                save(CONFIG_FILE, cfg)
        except Exception:
            pass

# ─── Handlers ──────────────────────────────────────────────────────────────────

def handle_public_info():
    """
    GET /api/public-info — no auth. Used by the login page to fetch the
    server's display name and remember-me default before the user logs in.
    Deliberately exposes only non-sensitive values.
    """
    respond(200, {
        'server_name':         get_server_name(),
        'server_version':      SERVER_VERSION,
        'remember_me_default': get_remember_me_default(),
        # v2.0: surface demo / read-only state so the dashboard can render
        # a clear banner. The flag itself isn't sensitive — anyone who
        # tries a write will get the same 403 regardless. Knowing up-front
        # lets the UI pre-emptively hide pointless buttons.
        'read_only':           _is_demo_read_only(),
    })


def handle_openapi_spec() -> None:
    """
    GET /api/openapi.json — return the OpenAPI 3.1 specification.

    Auth-gated like every other endpoint: the spec describes the surface
    that auth tokens grant access to, so it makes no sense to expose it
    publicly. The Swagger UI page (``/swagger.html``) fetches this
    endpoint with the user's existing session token.
    """
    require_auth()
    respond(200, openapi_spec.build_spec(SERVER_VERSION))


def handle_login():
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    username = _sanitize_str(body.get('username', ''), 32)
    password = body.get('password', '')

    # Enforce password type and length
    if not isinstance(password, str) or len(password) > 1024:
        respond(200, {'ok': False})

    # Rate limit check (keyed by username to prevent enumeration via timing)
    if not _check_login_ratelimit(username):
        respond(429, {'error': 'Too many failed attempts — try again later'})

    users = load(USERS_FILE)
    user = users.get(username)

    # Always do a dummy verify to prevent timing oracle on username existence
    dummy_hash = hashlib.sha256(b'dummy').hexdigest()
    stored = user.get('password_hash', dummy_hash) if user else dummy_hash
    valid = verify_password(password, stored) and bool(user)

    # v1.8.6: LDAP fallback. Local-first means an emergency local admin
    # always works even when LDAP is down. Only attempt LDAP if local failed.
    ldap_user_info = None
    if not valid:
        cfg = load(CONFIG_FILE)
        if cfg.get('ldap_enabled'):
            try:
                ldap_user_info = ldap_auth.authenticate(cfg, username, password)
                valid = True
                # Auto-provision: if user doesn't exist in users.json yet,
                # create them with the role determined by group membership.
                if not user:
                    new_role = ldap_user_info.role
                    users[username] = {
                        'role':            new_role,
                        # Store a placeholder hash that nothing matches —
                        # subsequent local-auth attempts will fail and fall
                        # through to LDAP again.
                        'password_hash':   '!' + secrets.token_hex(32),
                        'created':         int(time.time()),
                        'ldap_dn':         ldap_user_info.dn,
                        'ldap_full_name':  ldap_user_info.full_name,
                        'ldap_email':      ldap_user_info.email,
                    }
                    save(USERS_FILE, users)
                    user = users[username]
                    audit_log(username, 'ldap_auto_provision',
                              f'created from LDAP, role={new_role}, dn={ldap_user_info.dn}')
                else:
                    # Existing user — if their role should change based on group
                    # membership, update it. (Admin may have manually demoted; we
                    # respect group-driven promotions on each login.)
                    if user.get('role') != ldap_user_info.role:
                        # Only auto-promote (viewer→admin) on group match — never auto-demote
                        if ldap_user_info.role == 'admin' and user.get('role') != 'admin':
                            user['role'] = 'admin'
                            users[username] = user
                            save(USERS_FILE, users)
                            audit_log(username, 'ldap_role_promoted', 'matched admin group')
                audit_log(username, 'login_ldap', f'authenticated via LDAP (dn={ldap_user_info.dn})')
            except ldap_auth.LdapAuthDenied:
                # LDAP reachable but rejected the user — treat as plain auth failure.
                pass
            except ldap_auth.LdapTransientError as e:
                # LDAP itself is broken. Surface it in the audit log so the admin
                # can investigate, but to the client this still looks like normal
                # invalid-credentials (we don't want to leak whether LDAP is up).
                audit_log(username, 'login_ldap_error', f'LDAP unavailable: {e}')

    if not valid:
        _record_login_failure(username)
        audit_log(username, 'login_failed', 'invalid credentials')
        # Small constant delay to slow brute-force even further
        time.sleep(0.5)
        respond(200, {'ok': False})

    _clear_login_failures(username)
    if ldap_user_info is None:
        # Only rehash on local auth — LDAP users have placeholder hashes
        maybe_rehash(username, password, stored)

    # Check TOTP if user has 2FA enabled
    totp_secret = user.get('totp_secret')
    if totp_secret:
        totp_code = str(body.get('totp_code', '')).strip()
        if not totp_code:
            # Password correct but need TOTP — return special status
            respond(200, {'ok': False, 'totp_required': True})
        valid_codes = _totp(totp_secret)
        if totp_code not in valid_codes:
            _record_login_failure(username)
            audit_log(username, 'login_failed', 'invalid TOTP code')
            time.sleep(0.5)
            respond(200, {'ok': False, 'totp_required': True, 'totp_invalid': True})

    cleanup_tokens()
    audit_log(username, 'login', 'successful login')
    token = make_token()
    # v1.8.4: remember-me selects between short and long session TTL
    remember_me = bool(body.get('remember_me', False))
    ttl = get_session_ttl(remember_me=remember_me)
    tokens = load(TOKENS_FILE)
    tokens[token] = {
        'user':    username,
        'created': int(time.time()),
        'ttl':     ttl,
    }
    save(TOKENS_FILE, tokens)
    respond(200, {
        'ok':       True,
        'token':    token,
        'role':     user.get('role', 'admin'),
        'username': username,
        'ttl':      ttl,        # client may use to set its own expiry hints
        # v2.3.2: tells the UI to show a "change the default password"
        # warning banner. Set on the seeded default admin, cleared
        # when the password is changed.
        'must_change_password': bool(user.get('must_change_password')),
    })


def handle_devices_list():
    require_auth()
    devices = load(DEVICES_FILE)
    now = int(time.time())
    result = []
    for dev_id, dev in devices.items():
        last_ping = dev.get('last_seen', 0)
        # v1.11.0: agentless devices don't have a heartbeat. They're "online"
        # if the user marked them so manually; offline_reason is None either way.
        agentless = bool(dev.get('agentless', False))
        if agentless:
            is_online = bool(dev.get('manual_status', True))
            missed = None
            offline_reason = None
        else:
            is_online = (now - last_ping) < get_online_ttl()
            missed = max(0, (now - last_ping) // 60) if last_ping else None
            offline_reason = None
            if not is_online and last_ping:
                offline_reason = 'missed_polls' if (now - last_ping) < 300 else 'offline'
        result.append({
            'id': dev_id, 'name': dev.get('name', dev_id), 'hostname': dev.get('hostname', ''),
            'os': dev.get('os', ''), 'ip': dev.get('ip', ''), 'mac': dev.get('mac', ''),
            'version': dev.get('version', ''), 'tags': dev.get('tags', []),
            'group': dev.get('group', ''), 'notes': dev.get('notes', ''),
            'icon': dev.get('icon', ''), 'monitored': dev.get('monitored', True),
            'last_seen': last_ping, 'enrolled': dev.get('enrolled', 0),
            'online': is_online, 'offline_reason': offline_reason, 'missed_polls': missed,
            'poll_interval': dev.get('poll_interval', 60), 'sysinfo': dev.get('sysinfo', {}),
            # v1.11.0: agentless flag + network-map link
            'agentless':    agentless,
            'connected_to': dev.get('connected_to', ''),
            'device_type':  dev.get('device_type', ''),
            # v2.1.0: surface compose project count + reported_at so the
            # dropdown on the device card knows whether to render. Full
            # project list comes from GET /api/devices/<id>/compose.
            'compose_projects_count': len(dev.get('compose_projects', []) or []),
            'compose_projects_ts':    dev.get('compose_projects_ts', 0),
        })
    result.sort(key=lambda x: (x.get('group', ''), x['name'].lower()))
    respond(200, result)


def handle_device_delete(dev_id):
    require_admin_auth()
    if method() != 'DELETE':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    del devices[dev_id]
    save(DEVICES_FILE, devices)
    cmds = load(CMDS_FILE); cmds.pop(dev_id, None); save(CMDS_FILE, cmds)

    # v2.6.0: comprehensive orphan cleanup — remove the device's data from
    # every per-device store so deleted devices don't ghost in the UI.
    _SIMPLE_STORES = [
        CONTAINERS_FILE, PACKAGES_FILE, SERVICES_FILE, LOG_WATCH_FILE,
        CMD_OUTPUT_FILE, UPDATE_LOGS_FILE, METRICS_FILE, UPTIME_FILE,
        DRIFT_STATE_FILE,
    ]
    try:
        for store_path in _SIMPLE_STORES:
            try:
                data = load(store_path)
                if isinstance(data, dict) and dev_id in data:
                    data.pop(dev_id)
                    save(store_path, data)
            except Exception:
                pass

        # fleet_events: filter out events for this device
        try:
            fe = load(FLEET_EVENTS_FILE)
            if isinstance(fe, dict):
                fe['events'] = [
                    e for e in (fe.get('events') or [])
                    if e.get('device_id') != dev_id
                ]
                save(FLEET_EVENTS_FILE, fe)
        except Exception:
            pass

        # config: stale-notified flags keyed by dev_id
        try:
            cfg = load(CONFIG_FILE)
            changed = False
            for key in ('containers_stale_notified', 'metric_notified'):
                if isinstance(cfg.get(key), dict) and dev_id in cfg[key]:
                    cfg[key].pop(dev_id)
                    changed = True
            if changed:
                save(CONFIG_FILE, cfg)
        except Exception:
            pass

        # host_config_current per-device file
        try:
            hcc = HOST_CONFIG_CURRENT_DIR / f'{dev_id}.json'
            if hcc.exists():
                hcc.unlink()
        except Exception:
            pass

        # service_history: keys are dev_id:service_name
        try:
            sh = load(DATA_DIR / 'service_history.json')
            if isinstance(sh, dict):
                keys = [k for k in sh if k.startswith(f'{dev_id}:')]
                if keys:
                    for k in keys:
                        sh.pop(k)
                    save(DATA_DIR / 'service_history.json', sh)
        except Exception:
            pass

    except Exception:
        pass  # device delete must succeed even if cleanup hits an edge case
    respond(200, {'ok': True})


def handle_device_tags(dev_id):
    require_admin_auth()
    if method() != 'PATCH':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    body = get_json_body()
    tags = body.get('tags', [])
    if not isinstance(tags, list):
        respond(400, {'error': 'tags must be a list'})
    tags = [re.sub(r'[^a-zA-Z0-9_\-/]', '', str(t))[:MAX_TAG_LEN] for t in tags[:MAX_TAG_COUNT]]
    tags = [t for t in tags if t]  # drop empty after sanitize
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    devices[dev_id]['tags'] = tags
    save(DEVICES_FILE, devices)
    respond(200, {'ok': True, 'tags': tags})


def handle_device_notes(dev_id):
    require_admin_auth()
    if method() != 'PATCH':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    notes = _sanitize_str(get_json_body().get('notes', ''), MAX_NOTES_LEN)
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    devices[dev_id]['notes'] = notes
    save(DEVICES_FILE, devices)
    respond(200, {'ok': True, 'notes': notes})


# v1.11.10: per-device metric threshold overrides
def handle_device_metric_thresholds(dev_id):
    """``GET|PATCH|DELETE /api/devices/{id}/metric-thresholds``.

    GET — returns the device's current overrides merged with defaults so
    the UI can show effective values without resolving them itself.

    PATCH — accepts any subset of these keys; missing keys keep their
    previous value (or fall through to default if never set):
        disk_warn_percent, disk_crit_percent  — global (non-mount-specific)
        mem_warn_percent, mem_crit_percent
        swap_warn_percent, swap_crit_percent
        cpu_warn_load_ratio, cpu_crit_load_ratio
        disk_per_mount  — dict keyed by mount path → {warn, crit}

    DELETE — clears all overrides for this device, reverting to defaults.

    All thresholds validated to plausible ranges (1–100 for percentages,
    0.1–100 for load ratios). Out-of-range values are rejected with 400
    rather than silently clamped — better to fail loudly than alert at
    a threshold the user didn't intend.
    """
    require_admin_auth()
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    dev = devices[dev_id]

    if method() == 'GET':
        overrides = dev.get('metric_thresholds') or {}
        # Compute "effective" values by merging defaults
        effective = dict(DEFAULT_METRIC_THRESHOLDS)
        for k in ('disk_warn_percent', 'disk_crit_percent',
                  'mem_warn_percent',  'mem_crit_percent',
                  'swap_warn_percent', 'swap_crit_percent',
                  'cpu_warn_load_ratio', 'cpu_crit_load_ratio'):
            if k in overrides:
                effective[k] = overrides[k]
        respond(200, {
            'overrides': overrides,
            'effective': effective,
            'defaults':  DEFAULT_METRIC_THRESHOLDS,
            'recovery_buffer_percent': METRIC_RECOVERY_BUFFER,
        })

    if method() == 'DELETE':
        if 'metric_thresholds' in dev:
            del dev['metric_thresholds']
            save(DEVICES_FILE, devices)
        respond(200, {'ok': True})

    if method() != 'PATCH':
        respond(405, {'error': 'Method not allowed'})

    body = get_json_body() or {}
    overrides = dev.get('metric_thresholds') or {}

    # Percentage thresholds (1-99 — 0 and 100 don't make sense as alerts)
    pct_keys = ('disk_warn_percent', 'disk_crit_percent',
                'mem_warn_percent',  'mem_crit_percent',
                'swap_warn_percent', 'swap_crit_percent')
    for k in pct_keys:
        if k in body:
            v = body[k]
            if not isinstance(v, (int, float)) or not (1 <= v <= 99):
                respond(400, {'error': f'{k} must be a number between 1 and 99'})
            overrides[k] = float(v)

    # Load ratios (0.1 to 100 — 0.1 is "alert when even partially loaded")
    for k in ('cpu_warn_load_ratio', 'cpu_crit_load_ratio'):
        if k in body:
            v = body[k]
            if not isinstance(v, (int, float)) or not (0.1 <= v <= 100):
                respond(400, {'error': f'{k} must be a number between 0.1 and 100'})
            overrides[k] = float(v)

    # Per-mount overrides
    if 'disk_per_mount' in body:
        pm = body['disk_per_mount']
        if not isinstance(pm, dict):
            respond(400, {'error': 'disk_per_mount must be a dict'})
        clean_pm = {}
        for path, entry in list(pm.items())[:50]:  # cap mounts
            if not isinstance(path, str) or not path.startswith('/'):
                continue
            if not isinstance(entry, dict):
                continue
            w = entry.get('warn'); c = entry.get('crit')
            if not (isinstance(w, (int, float)) and 1 <= w <= 99):
                respond(400, {'error': f'disk_per_mount[{path}].warn must be 1-99'})
            if not (isinstance(c, (int, float)) and 1 <= c <= 99):
                respond(400, {'error': f'disk_per_mount[{path}].crit must be 1-99'})
            if w >= c:
                respond(400, {'error': f'disk_per_mount[{path}].warn must be < crit'})
            clean_pm[path[:256]] = {'warn': float(w), 'crit': float(c)}
        overrides['disk_per_mount'] = clean_pm

    # Sanity: warn must be < crit for every kind
    for warn_k, crit_k in (('disk_warn_percent', 'disk_crit_percent'),
                           ('mem_warn_percent',  'mem_crit_percent'),
                           ('swap_warn_percent', 'swap_crit_percent'),
                           ('cpu_warn_load_ratio','cpu_crit_load_ratio')):
        w = overrides.get(warn_k, DEFAULT_METRIC_THRESHOLDS[warn_k])
        c = overrides.get(crit_k, DEFAULT_METRIC_THRESHOLDS[crit_k])
        if w >= c:
            respond(400, {'error': f'{warn_k} must be < {crit_k}'})

    dev['metric_thresholds'] = overrides
    # Reset metric state so next heartbeat re-fires alerts under new thresholds
    # (otherwise a metric currently in 'warning' state with old threshold 80
    # would silently stay 'warning' even if you raised threshold to 90).
    dev.pop('metric_state', None)
    save(DEVICES_FILE, devices)
    respond(200, {'ok': True, 'overrides': overrides})


def handle_device_group(dev_id):
    require_admin_auth()
    if method() != 'PATCH':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    raw = _sanitize_str(get_json_body().get('group', ''), MAX_GROUP_LEN)
    # Allow alphanumeric, hyphen, underscore, forward-slash for namespaces
    group = re.sub(r'[^a-zA-Z0-9_\-/]', '', raw)[:MAX_GROUP_LEN]
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    devices[dev_id]['group'] = group
    save(DEVICES_FILE, devices)
    respond(200, {'ok': True, 'group': group})


def handle_device_poll_interval(dev_id):
    require_admin_auth()
    if method() != 'PATCH':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    try:
        interval = int(get_json_body().get('poll_interval', 60))
    except (TypeError, ValueError):
        respond(400, {'error': 'poll_interval must be an integer'})
    interval = max(10, min(3600, interval))
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    devices[dev_id]['poll_interval'] = interval
    cmds = load(CMDS_FILE)
    if dev_id not in cmds:
        cmds[dev_id] = []
    cmds[dev_id] = [c for c in cmds[dev_id] if not c.startswith('poll_interval:')]
    cmds[dev_id].append(f'poll_interval:{interval}')
    save(CMDS_FILE, cmds)
    save(DEVICES_FILE, devices)
    respond(200, {'ok': True, 'poll_interval': interval})


def handle_device_icon(dev_id):
    require_admin_auth()
    if method() != 'PATCH':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    icon = _sanitize_str(get_json_body().get('icon', ''), 32)
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    devices[dev_id]['icon'] = icon
    save(DEVICES_FILE, devices)
    respond(200, {'ok': True, 'icon': icon})


def handle_device_monitored(dev_id):
    require_admin_auth()
    if method() != 'PATCH':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    body = get_json_body()
    monitored = bool(body.get('monitored', True))
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    devices[dev_id]['monitored'] = monitored
    save(DEVICES_FILE, devices)
    # If disabling monitoring, clear any pending offline notification
    if not monitored:
        cfg = load(CONFIG_FILE)
        notified = cfg.get('offline_notified', {})
        if dev_id in notified:
            del notified[dev_id]
            cfg['offline_notified'] = notified
            save(CONFIG_FILE, cfg)
    respond(200, {'ok': True, 'monitored': monitored})


def handle_enroll_pin():
    require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    pin = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
    pins = load(PINS_FILE)
    now = int(time.time())
    pins = {k: v for k, v in pins.items() if now - v['created'] < PIN_TTL}
    pins[pin] = {'created': now}
    save(PINS_FILE, pins)
    respond(200, {'pin': pin, 'expires': now + PIN_TTL})


# ─── v1.11.10: API enrollment via one-time pre-shared tokens ────────────────
#
# Three endpoints:
#   POST   /api/enrollment-tokens          (admin) → create a token
#   GET    /api/enrollment-tokens          (admin) → list non-expired tokens
#   DELETE /api/enrollment-tokens/{token}  (admin) → revoke a token
#
# Tokens are consumed atomically by handle_enroll_register() — the registration
# call deletes the token before creating the device, so a leaked token can't
# enroll twice. If a request races (two agents holding the same token enroll
# at the same instant), exactly one wins; the other gets HTTP 403. That's
# the expected behaviour for "one-time use".
#
# Token storage shape (in enrollment_tokens.json):
#   {
#     "<token>": {
#       "created":       <unix_ts>,
#       "expires":       <unix_ts>,
#       "actor":         "<username who created it>",
#       "default_group": "servers",       # optional — applied at enrollment
#       "default_tags":  ["prod","linux"], # optional
#       "label":         "ansible-batch-2026-05-06"  # optional, free-form
#     },
#     ...
#   }


def _purge_expired_enroll_tokens(tokens, now):
    """Drop tokens whose ``expires`` has passed. Mutates and returns ``tokens``."""
    expired = [t for t, meta in tokens.items() if meta.get('expires', 0) < now]
    for t in expired:
        tokens.pop(t, None)
    return tokens


def handle_enroll_token_create():
    """``POST /api/enrollment-tokens`` — generate a one-time-use enrollment token.

    Body (all optional):
        expires_in    — seconds until expiry. Default 24h, capped at 7 days.
        default_group — group string applied to the device on enrollment.
        default_tags  — list of tag strings applied on enrollment.
        label         — free-form description shown in the listing endpoint.

    Response:
        ``{token, expires, created, label}`` — the token is shown ONCE here;
        we never return it again from the GET endpoint (only the truncated
        prefix), so the caller must capture it now.
    """
    actor = require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body() or {}

    # Validate expires_in
    try:
        ttl = int(body.get('expires_in', DEFAULT_ENROLL_TOKEN_TTL))
    except (TypeError, ValueError):
        respond(400, {'error': 'expires_in must be an integer (seconds)'})
    if ttl < 60:
        respond(400, {'error': 'expires_in must be >= 60 seconds'})
    if ttl > MAX_ENROLL_TOKEN_TTL:
        respond(400, {'error': f'expires_in cannot exceed {MAX_ENROLL_TOKEN_TTL} seconds (7 days)'})

    # Validate default_group / default_tags
    default_group = _sanitize_str(body.get('default_group', ''), MAX_GROUP_LEN) if body.get('default_group') else ''
    default_tags = body.get('default_tags', []) or []
    if not isinstance(default_tags, list):
        respond(400, {'error': 'default_tags must be a list of strings'})
    clean_tags = []
    for t in default_tags[:MAX_TAG_COUNT]:
        s = _sanitize_str(str(t), MAX_TAG_LEN)
        if s:
            clean_tags.append(s)

    label = _sanitize_str(body.get('label', ''), 128)

    # Generate the token. 32 url-safe bytes → 43 chars after base64. That's
    # enough entropy that brute-forcing at the rate-limit isn't a concern.
    token = secrets.token_urlsafe(32)
    now = int(time.time())

    tokens = load(ENROLL_TOKENS_FILE)
    _purge_expired_enroll_tokens(tokens, now)
    tokens[token] = {
        'created':       now,
        'expires':       now + ttl,
        'actor':         actor,
        'default_group': default_group,
        'default_tags':  clean_tags,
        'label':         label,
    }
    save(ENROLL_TOKENS_FILE, tokens)
    audit_log(actor, 'enrollment_token_created',
              f'label="{label}" expires_in={ttl}s group="{default_group}" tags={clean_tags}')
    respond(201, {
        'token':   token,
        'expires': now + ttl,
        'created': now,
        'label':   label,
    })


def handle_enroll_token_list():
    """``GET /api/enrollment-tokens`` — list non-expired tokens (no values).

    The actual token strings are never returned here — only a truncated
    prefix for identification. If you need to see the token again you
    have to revoke it and create a new one. This protects against the
    "list endpoint leaks active tokens to anyone with admin access" footgun.
    """
    require_admin_auth()
    tokens = load(ENROLL_TOKENS_FILE)
    now = int(time.time())
    _purge_expired_enroll_tokens(tokens, now)
    save(ENROLL_TOKENS_FILE, tokens)
    out = []
    for token, meta in tokens.items():
        out.append({
            'prefix':        token[:8] + '…',  # first 8 chars for ID purposes only
            'created':       meta.get('created', 0),
            'expires':       meta.get('expires', 0),
            'actor':         meta.get('actor', ''),
            'default_group': meta.get('default_group', ''),
            'default_tags':  meta.get('default_tags', []) or [],
            'label':         meta.get('label', ''),
            'remaining_seconds': max(0, meta.get('expires', 0) - now),
        })
    out.sort(key=lambda t: t['created'], reverse=True)
    respond(200, out)


def handle_enroll_token_revoke(token_prefix: str):
    """``DELETE /api/enrollment-tokens/{prefix}`` — revoke by 8-char prefix.

    Why the prefix and not the full token? Because the list endpoint only
    returns prefixes, and the dashboard wires its Revoke button against
    those prefixes. Revoking by full token would mean either showing the
    token in the listing (bad) or making the user paste it from somewhere.
    Prefixes are 8 chars from a 256-token-urlsafe alphabet — collisions
    are essentially impossible at any plausible scale, and we explicitly
    refuse if multiple tokens share a prefix (asks the user to pass more
    chars).
    """
    actor = require_admin_auth()
    if method() != 'DELETE':
        respond(405, {'error': 'Method not allowed'})
    prefix = _sanitize_str(token_prefix, 64).rstrip('…')
    if len(prefix) < 4:
        respond(400, {'error': 'Token prefix must be at least 4 characters'})
    tokens = load(ENROLL_TOKENS_FILE)
    matches = [t for t in tokens if t.startswith(prefix)]
    if len(matches) == 0:
        respond(404, {'error': 'No matching enrollment token'})
    if len(matches) > 1:
        respond(400, {'error': f'{len(matches)} tokens share that prefix — use a longer prefix'})
    full = matches[0]
    label = tokens[full].get('label', '')
    del tokens[full]
    save(ENROLL_TOKENS_FILE, tokens)
    audit_log(actor, 'enrollment_token_revoked', f'prefix={prefix} label="{label}"')
    respond(200, {'ok': True})


# ─── v1.11.11: web terminal auth + audit endpoints ──────────────────────────
#
# The CGI's job in the web-terminal flow is narrow:
#   1. Re-validate the user's admin password BEFORE we let them open a shell.
#   2. Issue a short-lived single-use ticket the daemon will recognise.
#   3. Accept session-completion audit POSTs from the daemon.
#
# Everything else — the actual SSH connection, byte pumping, recording —
# is the daemon's job. The CGI never holds an SSH connection open.


def _purge_expired_webterm_tickets(tickets, now):
    """Drop tickets past their TTL. Mutates ``tickets`` and returns it."""
    expired = [t for t, meta in tickets.items()
               if meta.get('expires', 0) < now or meta.get('used')]
    for t in expired:
        tickets.pop(t, None)
    return tickets


def handle_webterm_auth():
    """``POST /api/webterm/auth`` — re-prompt admin password, issue ticket.

    Body:
        device_id      — which device to open a terminal to
        admin_password — must match the *current user's* password

    The user is already authenticated via the session token (X-Token
    header), so this isn't asking them to log in again — it's a re-auth
    challenge specifically for the terminal action. Same pattern banks
    use for "you're logged in but we want a password before this
    privileged action."

    Why not TOTP? You explicitly didn't ask for it. The spec was
    "admin password every time" and that's what this is. If you ever
    want TOTP on top, it's a small addition.

    Response:
        ``{ticket, expires, daemon_url}`` — daemon_url is the WebSocket
        endpoint the browser should connect to. We compute it from the
        request's Host header so it works the same in dev (single host)
        and production (real domain).
    """
    actor = require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body() or {}
    dev_id = str(body.get('device_id', '')).strip()
    admin_password = str(body.get('admin_password', ''))

    if not dev_id or not _validate_id(dev_id):
        respond(400, {'error': 'device_id required'})
    if not admin_password:
        respond(400, {'error': 'admin_password required'})

    # Look up the device (just to confirm it exists; we don't pass any
    # device data to the daemon — the user supplies SSH host/user/pw).
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})

    # Re-verify the admin's password
    users = load(USERS_FILE)
    user = users.get(actor)
    if not user:
        respond(403, {'error': 'User no longer exists'})
    if not verify_password(admin_password, user.get('password_hash', '')):
        # Audit-log the failure so a brute-force attempt against this
        # endpoint shows up. Real defence is the rate limiter on the
        # CGI; this is just visibility.
        audit_log(actor, 'webterm_auth_failed', f'device={dev_id}')
        respond(403, {'error': 'Admin password did not match'})

    # Issue ticket
    ticket = secrets.token_urlsafe(32)
    now = int(time.time())
    tickets = load(WEBTERM_TICKETS_FILE)
    _purge_expired_webterm_tickets(tickets, now)
    tickets[ticket] = {
        'actor':     actor,
        'device_id': dev_id,
        'created':   now,
        'expires':   now + WEBTERM_TICKET_TTL,
        'used':      False,
        'source_ip': _get_client_ip(),
    }
    save(WEBTERM_TICKETS_FILE, tickets)
    audit_log(actor, 'webterm_ticket_issued',
              f'device={dev_id} expires_in={WEBTERM_TICKET_TTL}s')

    # Build daemon URL. nginx proxies /api/webterm/connect to the daemon,
    # so the browser uses the same host as the dashboard (real TLS,
    # real cookies). In dev / non-nginx setups the user can override
    # via config.
    cfg = load(CONFIG_FILE)
    daemon_url_override = cfg.get('webterm_daemon_url', '')
    if daemon_url_override:
        daemon_url = daemon_url_override
    else:
        # Same host as the request. The browser sets the protocol to wss
        # automatically when the page is HTTPS.
        daemon_url = '/api/webterm/connect'

    respond(200, {
        'ticket':     ticket,
        'expires':    now + WEBTERM_TICKET_TTL,
        'daemon_url': daemon_url,
        'device':     {
            'id':       dev_id,
            'name':     devices[dev_id].get('name', dev_id),
            'ip':       devices[dev_id].get('ip', ''),
            'hostname': devices[dev_id].get('hostname', ''),
        },
    })


def handle_webterm_session_audit():
    """``POST /api/webterm/audit`` — daemon reports session completion.

    Called by the daemon when an SSH session ends, with metadata about
    the session (duration, byte counts, exit reason). The CGI logs it
    to the audit log so it shows up alongside the rest of the audit
    trail. Authenticated via a shared secret stored in config —
    daemon and CGI both read the same config.json so this works
    automatically once the deploy script generates the secret.
    """
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body() or {}

    # Daemon authenticates with a shared secret rather than session
    # tokens — the daemon doesn't have a session token, it's a system
    # service. The secret is generated once by the deploy script and
    # written to config.json (only readable by the rp-www user) and to
    # /etc/remotepower/webterm-secret (only readable by the daemon's
    # user). If they match, it's the legit daemon talking.
    cfg = load(CONFIG_FILE)
    expected = cfg.get('webterm_daemon_secret', '')
    provided = os.environ.get('HTTP_X_WEBTERM_SECRET', '')
    if not expected or not provided or not hmac.compare_digest(expected, provided):
        respond(403, {'error': 'Daemon secret mismatch'})

    actor       = _sanitize_str(body.get('actor', 'unknown'), 64)
    dev_id      = _sanitize_str(body.get('device_id', ''), 64)
    ssh_user    = _sanitize_str(body.get('ssh_user', ''), 64)
    ssh_host    = _sanitize_str(body.get('ssh_host', ''), 256)
    duration_s  = int(body.get('duration_s', 0)) if isinstance(body.get('duration_s'), (int, float)) else 0
    bytes_in    = int(body.get('bytes_in', 0))   if isinstance(body.get('bytes_in'), int) else 0
    bytes_out   = int(body.get('bytes_out', 0))  if isinstance(body.get('bytes_out'), int) else 0
    reason      = _sanitize_str(body.get('reason', ''), 128)
    session_id  = _sanitize_str(body.get('session_id', ''), 64)
    detail = (f'device={dev_id} ssh_user={ssh_user}@{ssh_host} '
              f'duration={duration_s}s bytes_in={bytes_in} bytes_out={bytes_out} '
              f'reason={reason} session_id={session_id}')
    audit_log(actor, 'webterm_session', detail[:600])
    respond(200, {'ok': True})


def handle_enroll_register():
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body()

    # v1.11.10: enrollment can use either a 6-digit PIN (interactive) OR
    # a long pre-shared one-time-use token (non-interactive — Ansible,
    # cloud-init, etc.). Either path validates and consumes its credential
    # before creating the device. Both are atomic: the credential is
    # deleted before the device is created so a leaked credential can't
    # enroll twice.
    pin = str(body.get('pin', '')).strip()
    enroll_token = str(body.get('enrollment_token', '')).strip()
    default_group = ''
    default_tags = []

    if enroll_token:
        # Token path. The token must exist, not be expired, and gets
        # deleted as part of consumption. Default group/tags from the
        # token apply unless the agent explicitly provides its own.
        if len(enroll_token) < 16 or len(enroll_token) > 256:
            respond(400, {'error': 'Invalid enrollment token format'})
        tokens = load(ENROLL_TOKENS_FILE)
        now = int(time.time())
        _purge_expired_enroll_tokens(tokens, now)
        meta = tokens.get(enroll_token)
        if not meta:
            respond(403, {'error': 'Invalid or expired enrollment token'})
        # Consume the token *before* creating the device. If save fails
        # for some reason the device creation below still happens (we
        # accept that edge case rather than building two-phase commit
        # over a JSON file). In practice save() is atomic.
        del tokens[enroll_token]
        save(ENROLL_TOKENS_FILE, tokens)
        default_group = meta.get('default_group', '') or ''
        default_tags = meta.get('default_tags', []) or []
    elif pin:
        # PIN path (existing flow).
        if not re.match(r'^\d{6}$', pin):
            respond(400, {'error': 'Invalid PIN format'})
        pins = load(PINS_FILE)
        now = int(time.time())
        entry = pins.get(pin)
        if not entry or (now - entry['created']) > PIN_TTL:
            respond(403, {'error': 'Invalid or expired PIN'})
        del pins[pin]; save(PINS_FILE, pins)
    else:
        respond(400, {'error': 'Either pin or enrollment_token is required'})

    now = int(time.time())

    # Sanitize all enrollment fields
    hostname = _sanitize_hostname(body.get('hostname', 'unknown'))
    name     = _sanitize_str(body.get('name', hostname), MAX_NAME_LEN) or hostname
    os_str   = _sanitize_str(body.get('os', ''), MAX_OS_LEN)
    ip       = _sanitize_ip(body.get('ip', ''))
    mac      = _sanitize_mac(body.get('mac', ''))
    version  = _sanitize_version(body.get('version', ''))

    # Re-enrollment: existing device_id must be validated and token must match
    existing_id = str(body.get('device_id', '')).strip()
    devices = load(DEVICES_FILE)
    if existing_id and _validate_id(existing_id) and existing_id in devices:
        dev = devices[existing_id]
        # Require the existing device token to authorize re-enrollment
        provided_token = str(body.get('token', '')).strip()
        if not provided_token or not hmac.compare_digest(
                dev.get('token', ''), provided_token):
            respond(403, {'error': 'Existing device token required for re-enrollment'})
        dev.update({
            'hostname': hostname, 'name': name, 'os': os_str,
            'ip': ip, 'mac': mac, 'version': version, 'last_seen': now,
        })
        save(DEVICES_FILE, devices)
        respond(200, {'ok': True, 'device_id': existing_id, 'token': dev['token'], 'reregistered': True})

    dev_id = secrets.token_urlsafe(12)
    devices[dev_id] = {
        'name': name, 'hostname': hostname, 'os': os_str,
        'ip': ip, 'mac': mac, 'version': version,
        'tags': list(default_tags), 'group': default_group, 'notes': '',
        'enrolled': now, 'last_seen': now, 'poll_interval': get_default_poll_interval(),
        'token': secrets.token_urlsafe(32),
    }
    save(DEVICES_FILE, devices)
    respond(201, {'ok': True, 'device_id': dev_id, 'token': devices[dev_id]['token']})


def handle_heartbeat():
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    dev_id    = str(body.get('device_id', '')).strip()
    dev_token = str(body.get('token', '')).strip()

    if not _validate_id(dev_id):
        respond(403, {'error': 'Unauthorized device'})

    # v2.1.0: every non-DEVICES save() inside this handler uses
    # non_blocking=True. If any of them hits LockBusy, we bail with HTTP 202
    # (Accepted) — the agent treats 202 as "delivered, retry next cycle",
    # so a contended save no longer stalls the request long enough for
    # the agent's HTTP timeout to fire and the device to flip to offline.
    # The DEVICES_FILE update is the *one* save that must complete
    # synchronously; it's done via _locked_update below (v2.1.2 fix for
    # the lost-update race that the v2.1.0 non-blocking version
    # introduced).
    def _save_nb(path, data):
        try:
            save(path, data, non_blocking=True)
        except LockBusy as lb:
            # v2.1.5: heartbeat 202s on a busy lock are routine under load.
            # Silent by default; set RP_LOG_HEARTBEATS=1 to diagnose lock
            # contention. The 202 response itself is unaffected — the
            # client retries as before.
            if os.environ.get('RP_LOG_HEARTBEATS') == '1':
                sys.stderr.write(
                    f"[remotepower] heartbeat 202 dev={dev_id} path={path.name} "
                    f"waited_ms={lb.waited_ms}\n")
            respond(202, {'busy': True, 'retry_after': 1})

    # v2.1.2: atomic read-modify-write for devices.json. The whole block —
    # load through final mutation — runs under the flock so two concurrent
    # heartbeats can't lose each other's updates. See the comment on
    # _LockedUpdate in this file for the bug rationale. The lock blocks
    # for as long as it takes; the work inside is bounded (a few hundred
    # μs of regex / sanitisation), so even under fleet-wide poll bursts
    # the wait is short. We cache the few values we need *outside* the
    # lock (device name, poll interval, allowlist, etc.) before exit.
    saved_dev = {}
    with _locked_update(DEVICES_FILE) as devices:
        dev = devices.get(dev_id)
        if not dev or not hmac.compare_digest(dev.get('token', ''), dev_token):
            # respond() raises SystemExit; __exit__ skips the save, releases
            # the lock. No partial write on disk.
            respond(403, {'error': 'Unauthorized device'})

        now = int(time.time())
        dev['last_seen'] = now

        # Sanitize all fields coming from the agent
        dev['ip']      = _sanitize_ip(body.get('ip', dev.get('ip', '')))
        dev['os']      = _sanitize_str(body.get('os', dev.get('os', '')), MAX_OS_LEN)
        dev['version'] = _sanitize_version(body.get('version', dev.get('version', ''))) or dev.get('version', '')

        if 'sysinfo' in body and isinstance(body['sysinfo'], dict):
            si = body['sysinfo']
            # Sanitize sysinfo sub-fields
            safe_si = {}
            if 'uptime' in si:
                safe_si['uptime'] = _sanitize_str(si['uptime'], 128)
            if 'platform' in si:
                safe_si['platform'] = _sanitize_str(si['platform'], 256)
            if 'packages' in si and isinstance(si['packages'], dict):
                pkg = si['packages']
                safe_pkg = {}
                safe_pkg['manager'] = _sanitize_str(pkg.get('manager', ''), 32)
                upg = pkg.get('upgradable')
                safe_pkg['upgradable'] = int(upg) if isinstance(upg, int) and 0 <= upg <= 100000 else None
                safe_si['packages'] = safe_pkg
            if 'network' in si and isinstance(si['network'], list):
                safe_net = []
                for iface in si['network'][:20]:  # max 20 interfaces
                    if isinstance(iface, dict):
                        safe_net.append({
                            'iface': _sanitize_str(iface.get('iface', ''), 32),
                            'ip':    _sanitize_ip(iface.get('ip', '')),
                            'mac':   _sanitize_mac(iface.get('mac', '')),
                        })
                safe_si['network'] = safe_net
            # Metrics — legacy three (root-mount disk, cpu, memory) plus
            # v1.11.10 additions: per-mount disk list, swap, loadavg, cpu_count.
            for metric_key in ('cpu_percent', 'mem_percent', 'disk_percent', 'swap_percent'):
                val = si.get(metric_key)
                if isinstance(val, (int, float)) and 0.0 <= val <= 100.0:
                    safe_si[metric_key] = round(float(val), 2)
            # loadavg can be > 100 on a heavily loaded box — different validation
            for fkey in ('loadavg_1m',):
                v = si.get(fkey)
                if isinstance(v, (int, float)) and 0.0 <= v <= 1000.0:
                    safe_si[fkey] = round(float(v), 2)
            # cpu_count
            cc = si.get('cpu_count')
            if isinstance(cc, int) and 1 <= cc <= 1024:
                safe_si['cpu_count'] = cc
            # mounts: bounded list, each with sanitised path, percent, sizes
            if isinstance(si.get('mounts'), list):
                safe_mounts = []
                for m in si['mounts'][:50]:
                    if not isinstance(m, dict):
                        continue
                    p = _sanitize_str(m.get('path', ''), 256)
                    if not p or not p.startswith('/'):
                        continue
                    pct = m.get('percent')
                    if not (isinstance(pct, (int, float)) and 0.0 <= pct <= 100.0):
                        continue
                    safe_mounts.append({
                        'path':     p,
                        'percent':  round(float(pct), 1),
                        'used_gb':  round(float(m.get('used_gb', 0)), 2)
                                      if isinstance(m.get('used_gb'), (int, float)) else 0,
                        'total_gb': round(float(m.get('total_gb', 0)), 2)
                                      if isinstance(m.get('total_gb'), (int, float)) else 0,
                        'fstype':   _sanitize_str(m.get('fstype', ''), 32),
                    })
                safe_si['mounts'] = safe_mounts
            # v2.4.14: reboot-required flag (Debian/Ubuntu /run/reboot-required)
            if 'reboot_required' in si:
                safe_si['reboot_required'] = bool(si['reboot_required'])
                if si.get('reboot_reason'):
                    safe_si['reboot_reason'] = _sanitize_str(si['reboot_reason'], 256)
            dev['sysinfo'] = safe_si
            # _record_metrics writes to METRICS_FILE (different lock — no
            # deadlock with the DEVICES_FILE lock we currently hold)
            _record_metrics(dev_id, safe_si)
            # v1.11.10: check thresholds and fire metric_warning / metric_critical /
            # metric_recovered webhooks. Wrapped in try so a logic bug here never
            # breaks the heartbeat path. process_metric_thresholds touches
            # CONFIG_FILE only, not DEVICES_FILE.
            try:
                process_metric_thresholds(dev_id, dev, safe_si)
            except Exception:
                pass

        if 'journal' in body and isinstance(body['journal'], list):
            # Cap journal: max lines and max bytes per line
            lines = body['journal'][:MAX_JOURNAL_LINES]
            dev['journal'] = [str(l)[:MAX_JOURNAL_LINE] for l in lines]

        # v2.2.0: drift hashes from the agent. Optional — only newer agents
        # send these. Hash-only payload; we never receive file content here.
        # Format: {file_path: {hash, size, mtime, exists}}.  The server
        # function _ingest_drift_report handles comparison against the stored
        # baseline, history rotation, and firing the drift_detected webhook.
        # Wrapped in try so a logic bug here never breaks the heartbeat path.
        if 'drift' in body and isinstance(body['drift'], dict):
            try:
                _ingest_drift_report(dev_id, body['drift'])
            except Exception:
                pass

        # v2.1.0 compose_projects update. Moved INSIDE the locked block
        # in v2.1.2 so it's part of the same atomic devices.json update —
        # losing the compose listing isn't catastrophic but the previous
        # design did a separate save() afterwards which was vulnerable to
        # the same lost-update race as last_seen.
        if 'compose_projects' in body:
            raw_projects = body.get('compose_projects') or []
            if isinstance(raw_projects, list):
                safe_projects = []
                for p in raw_projects[:MAX_COMPOSE_PROJECTS_PER_DEVICE]:
                    if not isinstance(p, dict):
                        continue
                    path_s = _sanitize_str(p.get('path', ''), MAX_COMPOSE_PATH_LEN)
                    pdir = _sanitize_str(p.get('dir', ''), MAX_COMPOSE_PATH_LEN)
                    pname = _sanitize_str(p.get('name', ''), 128)
                    if not path_s.startswith('/') or not pdir.startswith('/'):
                        continue
                    if not path_s.startswith(pdir.rstrip('/') + '/'):
                        continue
                    mtime = p.get('mtime')
                    safe_projects.append({
                        'path':  path_s,
                        'dir':   pdir,
                        'name':  pname or pdir.rsplit('/', 1)[-1],
                        'mtime': int(mtime) if isinstance(mtime, int) and mtime >= 0 else 0,
                    })
                dev['compose_projects'] = safe_projects
                dev['compose_projects_ts'] = now

        devices[dev_id] = dev
        # Cache a snapshot of the fields we'll need below, so we don't
        # have to re-acquire the lock just to read them.
        saved_dev['name']          = dev.get('name', dev_id)
        saved_dev['last_seen']     = dev['last_seen']
        saved_dev['poll_interval'] = dev.get('poll_interval', 60)
        saved_dev['cmd_allowlist'] = dev.get('cmd_allowlist', [])
        saved_dev['agentless']     = dev.get('agentless', False)
        saved_dev['services_watched'] = dev.get('services_watched', [])
        saved_dev['log_watch']     = dev.get('log_watch', [])
        # v2.4.3: cache the mailbox monitor paths so the heartbeat
        # response can push them to the agent. Without this line the
        # agent always received an empty list and never counted —
        # mailbox_paths was read off saved_dev, which never had it.
        saved_dev['mailbox_paths'] = dev.get('mailbox_paths', [])
        # v2.4.5: one-shot "scan packages now" flag. If an operator
        # clicked the button, tell the agent to send its package list
        # on the next heartbeat — then clear the flag immediately so
        # it fires exactly once (the agent is told once; if it misses,
        # the operator clicks again).
        if dev.get('force_package_scan'):
            saved_dev['force_package_scan'] = True
            dev.pop('force_package_scan', None)
        # devices is auto-saved here by _LockedUpdate.__exit__, atomically
        # under the same flock we acquired at __enter__.

    # ── OUT OF THE LOCK ────────────────────────────────────────────────
    # Everything below this point operates on OTHER files (cmd_output,
    # containers, etc.) — each has its own flock. Holding DEVICES_FILE's
    # lock for any longer would serialise all heartbeat handling for no
    # benefit.
    # v2.1.5: at 6 devices polling every 60s that's ~8,600 log lines/day
    # of routine "heartbeat received" noise drowning out real errors in
    # the nginx error log. Default silent; set RP_LOG_HEARTBEATS=1 in
    # the CGI environment to re-enable for diagnostics. Offline/online
    # transitions (above) are state changes and stay unconditional.
    if os.environ.get('RP_LOG_HEARTBEATS') == '1':
        sys.stderr.write(
            f"[remotepower] heartbeat dev={dev_id} name={saved_dev['name']!r} "
            f"last_seen={saved_dev['last_seen']} pid={os.getpid()}\n")
    _record_uptime(dev_id, saved_dev['name'], True)

    # v1.8.0: process service report
    if 'services' in body and isinstance(body['services'], list):
        try:
            process_service_report(dev_id, body['services'])
        except Exception:
            pass  # never let service processing break heartbeat

    # executed_command webhook — validate it's one of our known command types
    if 'executed_command' in body:
        cmd_val = str(body['executed_command'])[:600]
        allowed_prefixes = ('shutdown', 'reboot', 'update', 'exec:', 'poll_interval:')
        if any(cmd_val.startswith(p) for p in allowed_prefixes):
            fire_webhook('command_executed', {
                'device_id': dev_id,
                'name':      dev.get('name', dev_id),
                'command':   cmd_val,
            })

    if 'cmd_output' in body and isinstance(body['cmd_output'], dict):
        co = body['cmd_output']
        outputs = load(CMD_OUTPUT_FILE)
        if dev_id not in outputs:
            outputs[dev_id] = []
        # Enforce per-entry output size cap
        raw_output = str(co.get('output', ''))[:MAX_CMD_OUT_BYTES]
        outputs[dev_id].append({
            'ts':     now,
            'cmd':    _sanitize_str(co.get('cmd', ''), 512),
            'output': raw_output,
            'rc':     int(co['rc']) if isinstance(co.get('rc'), int) else -1,
        })
        outputs[dev_id] = outputs[dev_id][-MAX_CMD_OUTPUT:]
        _save_nb(CMD_OUTPUT_FILE, outputs)
        _resolve_longpoll(dev_id, body['cmd_output'])

        # v1.10.0: if this output is from a package-upgrade run, also archive
        # it in the dedicated update_logs.json file. The Patches page can
        # then surface it without scanning every exec result the device has
        # ever produced. We detect the upgrade by matching the synthetic
        # shell script the server queues in handle_upgrade_device — anything
        # containing the 'apt-get -y upgrade' or 'dnf -y upgrade' or
        # 'pacman -Syu' fragments counts.
        cmd_text = str(co.get('cmd', ''))
        # v2.2.1: drift content mirroring. If the just-arrived output is
        # an `exec:cat /some/watched/path` and that path is currently
        # being watched for drift on this device, we ALSO copy it into
        # drift_contents.json so the diff viewer can fetch it directly.
        # Cheap match — single regex, then a couple of dict lookups.
        try:
            _maybe_mirror_drift_content(dev_id, cmd_text, raw_output,
                                        int(co['rc']) if isinstance(co.get('rc'), int) else -1,
                                        now)
        except Exception:
            pass    # never let mirroring break heartbeat
        if any(needle in cmd_text for needle in
               ('apt-get -y upgrade', 'dnf -y upgrade', 'pacman -Syu')):
            pkg_mgr = ('apt' if 'apt-get' in cmd_text
                       else 'dnf' if 'dnf' in cmd_text
                       else 'pacman' if 'pacman' in cmd_text
                       else 'unknown')
            ulogs = load(UPDATE_LOGS_FILE)
            if dev_id not in ulogs:
                ulogs[dev_id] = []
            ulogs[dev_id].append({
                'started_at':  now - 1,            # we don't know exactly
                'finished_at': now,
                'exit_code':   int(co['rc']) if isinstance(co.get('rc'), int) else -1,
                'output':      raw_output[:MAX_UPDATE_LOG_BYTES],
                'package_manager': pkg_mgr,
                'triggered_by': '',                # actor info already in audit log
            })
            ulogs[dev_id] = ulogs[dev_id][-MAX_UPDATE_LOGS_PER_DEVICE:]
            _save_nb(UPDATE_LOGS_FILE, ulogs)

    # ── v1.10.0: dedicated update output channel ───────────────────────────
    # Agent posts {'update_log': {started_at, finished_at, exit_code,
    # output, triggered_by, package_manager}} after running an `update`
    # command. We keep these separate from cmd_output so the Patches page
    # can list "last update on this device" without scanning unrelated
    # exec results.
    if 'update_log' in body and isinstance(body['update_log'], dict):
        ul = body['update_log']
        logs = load(UPDATE_LOGS_FILE)
        if dev_id not in logs:
            logs[dev_id] = []
        logs[dev_id].append({
            'started_at':  int(ul.get('started_at') or now),
            'finished_at': int(ul.get('finished_at') or now),
            'exit_code':   int(ul['exit_code']) if isinstance(ul.get('exit_code'), int) else -1,
            'output':      str(ul.get('output', ''))[:MAX_UPDATE_LOG_BYTES],
            'package_manager': _sanitize_str(ul.get('package_manager', ''), 32),
            'triggered_by': _sanitize_str(ul.get('triggered_by', ''), 64),
        })
        logs[dev_id] = logs[dev_id][-MAX_UPDATE_LOGS_PER_DEVICE:]
        _save_nb(UPDATE_LOGS_FILE, logs)

    # ── v1.11.0: container/k8s listing ─────────────────────────────────────
    # Agent posts {'containers': [<list of normalised entries>]} when it has
    # detected a runtime. We overwrite the per-device list (last-write-wins)
    # rather than append — container state changes too often for history
    # to be useful, and the next heartbeat refreshes it.
    #
    # v1.11.4: agent now sends an empty list when a runtime is installed but
    # no containers are running, so this branch fires every report — not just
    # non-empty ones. Before storing, we diff against the previous report
    # and fire container_stopped / container_restarting webhooks.
    if 'containers' in body:
        normalised = containers_mod.normalize_listing(body.get('containers'))
        try:
            process_container_report(dev_id, normalised, now)
        except Exception:
            pass  # never let container processing break heartbeat
        store = load(CONTAINERS_FILE)
        store[dev_id] = {'ts': now, 'items': normalised}
        _save_nb(CONTAINERS_FILE, store)
        # v1.11.4: this device just gave us fresh container data, so clear
        # any "containers_stale" notified flag — the next time it goes stale
        # we want a new webhook to fire (matches device_offline pattern).
        cfg_now = load(CONFIG_FILE)
        stale_notified = cfg_now.get('containers_stale_notified') or {}
        if isinstance(stale_notified, dict) and stale_notified.get(dev_id):
            stale_notified[dev_id] = False
            cfg_now['containers_stale_notified'] = stale_notified
            _save_nb(CONFIG_FILE, cfg_now)

    # v2.1.0 compose_projects update was previously here as a separate
    # save. v2.1.2 moved it inside the _locked_update block above so it
    # participates in the same atomic devices.json transaction as
    # last_seen — the prior structure was vulnerable to the same
    # lost-update race.

    cmds = load(CMDS_FILE)
    pending = cmds.get(dev_id, [])

    # v2.2.0: ingest drift report if the agent sent one. Runs OUTSIDE the
    # devices.json lock — _ingest_drift_report takes its own lock on
    # drift_state.json. Failure is non-fatal; the heartbeat itself
    # already succeeded.
    if 'drift' in body and isinstance(body['drift'], dict):
        try:
            _ingest_drift_report(dev_id, body['drift'])
        except Exception as e:
            sys.stderr.write(f"[remotepower] drift ingest failed dev={dev_id}: {e}\n")

    # v2.2.0: surface the watched-files list to the agent so it knows what
    # to hash next round. Added to common_resp below.
    watched_files = get_watched_files_for(dev_id, devices=load(DEVICES_FILE))

    # v2.4.3: mailbox-count monitor. Ingest the counts the agent
    # reported, and tell the agent which paths to count next round.
    if 'mailbox_counts' in body and isinstance(body['mailbox_counts'], dict):
        try:
            _ingest_mailbox_counts(dev_id, body['mailbox_counts'])
        except Exception as e:
            sys.stderr.write(f"[remotepower] mailbox ingest failed dev={dev_id}: {e}\n")
    mailbox_paths = (saved_dev.get('mailbox_paths') or [])[:MAX_MAILBOX_PATHS]

    # v2.5.0: custom monitoring scripts — ingest results from agent,
    # then build the list of scripts assigned to this device for the
    # heartbeat response.
    if 'custom_script_results' in body and isinstance(body['custom_script_results'], dict):
        try:
            _ingest_custom_script_results(dev_id, saved_dev['name'],
                                          body['custom_script_results'])
        except Exception as e:
            sys.stderr.write(f"[remotepower] custom script ingest failed dev={dev_id}: {e}\n")

    # v2.6.0: host config current state — sent on-demand via
    # `remotepower-agent send_current_configs` or a UI-triggered command.
    if 'host_config_current' in body and isinstance(body['host_config_current'], dict):
        try:
            _ingest_host_config_current(dev_id, saved_dev['name'],
                                        body['host_config_current'])
        except HTTPError:
            raise
        except Exception as e:
            sys.stderr.write(f"[remotepower] host config ingest failed dev={dev_id}: {e}\n")

    custom_scripts_for_device = _get_custom_scripts_for_device(dev_id)

    # v2.6.0: push desired host config to agent if one is set
    host_config_desired = saved_dev.get('host_config', {}).get('desired') or None

    # v2.1.2: use the snapshot we captured under the lock instead of the
    # leaked `dev` reference from the with-block. After exit, devices has
    # been written back to disk and `dev` is just an in-memory copy that
    # nobody else can observe; for the fields that vary at runtime (e.g.
    # poll_interval can be changed by an admin between heartbeats), we'd
    # want the value as-of the heartbeat which is exactly what saved_dev
    # holds.
    common_resp = {
        'poll_interval':    saved_dev['poll_interval'],
        'services_watched': saved_dev.get('services_watched', []),
        'log_watch':        saved_dev.get('log_watch', []),
        'watched_files':    watched_files,
        'mailbox_paths':    mailbox_paths,
        # v2.5.0: push assigned scripts so the agent runs them every 5 min
        'custom_scripts':   custom_scripts_for_device,
    }
    # v2.6.0: include desired host config so agent can apply + audit it
    if host_config_desired:
        common_resp['host_config_desired'] = host_config_desired

    # v2.4.5: one-shot package-scan request. Only present (and true)
    # on the single heartbeat after the operator clicked "scan now".
    if saved_dev.get('force_package_scan'):
        common_resp['force_package_scan'] = True
    if pending:
        cmd = pending.pop(0); cmds[dev_id] = pending; _save_nb(CMDS_FILE, cmds)
        respond(200, {'command': cmd, **common_resp})
    else:
        respond(200, {'command': None, **common_resp})


def _record_metrics(dev_id, sysinfo):
    cpu  = sysinfo.get('cpu_percent')
    mem  = sysinfo.get('mem_percent')
    disk = sysinfo.get('disk_percent')
    if cpu is None and mem is None and disk is None:
        return
    metrics = load(METRICS_FILE)
    if dev_id not in metrics:
        metrics[dev_id] = []
    metrics[dev_id].append({'ts': int(time.time()), 'cpu': cpu, 'mem': mem, 'disk': disk})
    metrics[dev_id] = metrics[dev_id][-MAX_METRICS:]
    save(METRICS_FILE, metrics)


def _resolve_targets(body):
    """Resolve device_ids, tag, group, or single device_id — with length limits."""
    if 'device_ids' in body and isinstance(body['device_ids'], list):
        raw = body['device_ids'][:100]  # cap at 100 targets
        return [str(d).strip() for d in raw if _validate_id(str(d).strip())]
    if 'tag' in body:
        tag = re.sub(r'[^a-zA-Z0-9_\-/]', '', str(body['tag']))[:MAX_TAG_LEN]
        if not tag:
            return []
        devices = load(DEVICES_FILE)
        return [did for did, dev in devices.items() if tag in dev.get('tags', [])]
    if 'group' in body:
        grp = re.sub(r'[^a-zA-Z0-9_\-/]', '', str(body['group']))[:MAX_GROUP_LEN]
        if not grp:
            return []
        devices = load(DEVICES_FILE)
        return [did for did, dev in devices.items() if dev.get('group', '') == grp]
    dev_id = str(body.get('device_id', '')).strip()
    return [dev_id] if _validate_id(dev_id) else []


def _queue_command(dev_id, command, actor):
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    cmds = load(CMDS_FILE)
    if dev_id not in cmds:
        cmds[dev_id] = []
    if command not in cmds[dev_id]:
        cmds[dev_id].append(command)
    save(CMDS_FILE, cmds)
    log_command(actor, dev_id, devices[dev_id].get('name', dev_id), command)
    fire_webhook('command_queued', {
        'device_id': dev_id, 'name': devices[dev_id].get('name', dev_id),
        'command': command, 'actor': actor,
    })
    respond(200, {'ok': True})


def _queue_command_batch(dev_ids, command, actor):
    devices = load(DEVICES_FILE); cmds = load(CMDS_FILE); results = {}
    for dev_id in dev_ids:
        if not _validate_id(dev_id):
            results[dev_id] = {'ok': False, 'error': 'Invalid device ID'}; continue
        if dev_id not in devices:
            results[dev_id] = {'ok': False, 'error': 'Device not found'}; continue
        if dev_id not in cmds:
            cmds[dev_id] = []
        if command not in cmds[dev_id]:
            cmds[dev_id].append(command)
        log_command(actor, dev_id, devices[dev_id].get('name', dev_id), command)
        fire_webhook('command_queued', {
            'device_id': dev_id, 'name': devices[dev_id].get('name', dev_id),
            'command': command, 'actor': actor,
        })
        results[dev_id] = {'ok': True}
    save(CMDS_FILE, cmds)
    return results


def _check_exec_allowlist(dev_id, cmd_str, devices):
    """Return (allowed: bool, reason: str). Checks per-device allowlist."""
    allowed = devices[dev_id].get('allowed_commands', [])
    if allowed:
        if cmd_str not in allowed:
            return False, 'Command not in allowed_commands list for this device'
    else:
        # Denylist fallback
        for b in ['rm -rf /', 'mkfs', '> /dev/sd', 'dd if=', ':(){:|:&};:']:
            if b in cmd_str:
                return False, f'Blocked pattern: {b}'
    return True, ''


def handle_shutdown():
    actor = require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body = get_json_body(); ids = _resolve_targets(body)
    if not ids: respond(400, {'error': 'No valid device targets'})
    if len(ids) == 1: _queue_command(ids[0], 'shutdown', actor)
    else: respond(200, {'ok': True, 'results': _queue_command_batch(ids, 'shutdown', actor)})


def handle_reboot():
    actor = require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body = get_json_body(); ids = _resolve_targets(body)
    if not ids: respond(400, {'error': 'No valid device targets'})
    if len(ids) == 1: _queue_command(ids[0], 'reboot', actor)
    else: respond(200, {'ok': True, 'results': _queue_command_batch(ids, 'reboot', actor)})


def handle_update_device():
    actor = require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body = get_json_body(); ids = _resolve_targets(body)
    if not ids: respond(400, {'error': 'No valid device targets'})
    if len(ids) == 1: _queue_command(ids[0], 'update', actor)
    else: respond(200, {'ok': True, 'results': _queue_command_batch(ids, 'update', actor)})


# Single self-detecting upgrade command. Runs on the device and picks
# apt-get / dnf / pacman at execution time, so it works even on freshly
# restarted agents that haven't sent a sysinfo poll yet (patch info is
# only collected every PATCH_EVERY polls = ~3h after agent restart, so
# relying on the server-side sysinfo cache was fragile).
#
# For apt: writes a one-line apt config to a tempfile and exports APT_CONFIG,
# so every apt-get call in the chain inherits APT::Sandbox::User=root and
# skips the seteuid(_apt) drop that fails under systemd hardening.
_UPGRADE_CMD = (
    'set -e; '
    'if command -v apt-get >/dev/null 2>&1; then '
    '  APT_CONFIG=$(mktemp); '
    '  trap "rm -f $APT_CONFIG" EXIT; '
    '  printf \'APT::Sandbox::User "root";\\n'
    'Dpkg::Options:: "--force-confdef";\\n'
    'Dpkg::Options:: "--force-confold";\\n\' > "$APT_CONFIG"; '
    '  export APT_CONFIG DEBIAN_FRONTEND=noninteractive; '
    '  apt-get update && apt-get -y upgrade && apt-get -y autoremove && apt-get clean; '
    'elif command -v dnf >/dev/null 2>&1; then '
    '  dnf -y upgrade; '
    'elif command -v pacman >/dev/null 2>&1; then '
    '  pacman -Syu --noconfirm; '
    'else '
    '  echo "No supported package manager (apt-get/dnf/pacman) found" >&2; '
    '  exit 2; '
    'fi'
)


def handle_upgrade_device():
    """
    Queue an OS package-manager upgrade (apt/dnf/pacman) per device.
    The command self-detects the package manager at runtime on each device,
    so it works even before the agent has sent its first sysinfo poll.
    Output arrives on the next heartbeat via the existing exec: channel.
    """
    actor = require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body = get_json_body(); ids = _resolve_targets(body)
    if not ids: respond(400, {'error': 'No valid device targets'})

    devices = load(DEVICES_FILE); cmds = load(CMDS_FILE); results = {}
    queued_str = f'exec:{_UPGRADE_CMD}'
    for dev_id in ids:
        if not _validate_id(dev_id):
            results[dev_id] = {'ok': False, 'error': 'Invalid device ID'}; continue
        dev = devices.get(dev_id)
        if not dev:
            results[dev_id] = {'ok': False, 'error': 'Device not found'}; continue
        if dev_id not in cmds:
            cmds[dev_id] = []
        if queued_str not in cmds[dev_id]:
            cmds[dev_id].append(queued_str)
        log_command(actor, dev_id, dev.get('name', dev_id), 'upgrade packages')
        fire_webhook('command_queued', {
            'device_id': dev_id, 'name': dev.get('name', dev_id),
            'command': 'upgrade packages', 'actor': actor,
        })
        results[dev_id] = {'ok': True}
    save(CMDS_FILE, cmds)
    if len(ids) == 1:
        r = results[ids[0]]
        if r.get('ok'): respond(200, {'ok': True})
        else:           respond(400, {'error': r.get('error', 'Failed')})
    respond(200, {'ok': True, 'results': results})


def handle_wol():
    require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    dev_id = str(body.get('device_id', '')).strip()
    if not _validate_id(dev_id): respond(404, {'error': 'Device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices: respond(404, {'error': 'Device not found'})
    mac = devices[dev_id].get('mac', '').strip()
    if not mac: respond(400, {'error': 'No MAC address on record for this device'})
    if not _MAC_RE.match(mac): respond(400, {'error': 'Invalid MAC address format'})
    mac_bytes = bytes.fromhex(mac.replace(':', '').replace('-', ''))
    magic = b'\xff' * 6 + mac_bytes * 16
    cfg = load(CONFIG_FILE)
    try:
        port = int(cfg.get('wol_port', 9))
        if not (1 <= port <= 65535):
            port = 9
    except (ValueError, TypeError):
        port = 9
    device_ip = _sanitize_ip(devices[dev_id].get('ip', ''))
    broadcast  = _sanitize_ip(cfg.get('wol_broadcast', '')) or '255.255.255.255'
    target = device_ip if device_ip else broadcast
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(magic, (target, port))
    except Exception as e:
        respond(500, {'error': 'WoL send failed'})
    respond(200, {'ok': True, 'mac': mac, 'target': target})


def handle_sysinfo(dev_id):
    require_auth()
    if not _validate_id(dev_id): respond(404, {'error': 'Device not found'})
    devices = load(DEVICES_FILE); dev = devices.get(dev_id)
    if not dev: respond(404, {'error': 'Device not found'})
    respond(200, {'sysinfo': dev.get('sysinfo', {}), 'journal': dev.get('journal', [])})


def handle_metrics(dev_id):
    require_auth()
    if not _validate_id(dev_id): respond(404, {'error': 'Device not found'})
    metrics = load(METRICS_FILE)
    respond(200, {'device_id': dev_id, 'metrics': metrics.get(dev_id, [])})


def _execute_monitor_checks(monitors):
    """Run every configured monitor and return the result list.

    Pure check logic — no auth, no HTTP response, no persistence beyond
    what callers do with the results. Shared by:

    - :func:`handle_monitor_run` (synchronous: a user opened the
      Monitor page and we run them right now to give an instantaneous
      view).
    - :func:`run_monitors_if_due` (background: called from
      :func:`main` on every CGI request, runs at most once every
      ``monitor_interval`` seconds).

    v1.11.8: extracted from handle_monitor_run because monitors used to
    only run when somebody loaded the Monitor page. Long gaps between
    page loads meant long gaps between checks — and webhooks for down
    services never fired during those gaps. Now there's a periodic
    runner that calls this on every CGI hit, gated on the configured
    interval.
    """
    results = []
    for m in monitors:
        mtype = m.get('type', 'ping')
        raw_target = m.get('target', '')
        label = _sanitize_str(m.get('label', raw_target), 128)

        target = _sanitize_monitor_target(mtype, raw_target)
        if target is None:
            results.append({
                'label': label, 'type': mtype, 'target': raw_target,
                'ok': False, 'detail': 'blocked: invalid target',
                'checked': int(time.time()),
            })
            continue

        ok = False; detail = ''
        if mtype == 'ping':
            try:
                r = subprocess.run(
                    ['ping', '-c', '1', '-W', '2', '--', target],
                    capture_output=True, timeout=5)
                ok = r.returncode == 0; detail = 'up' if ok else 'no reply'
            except Exception:
                detail = 'error'
        elif mtype == 'tcp':
            host, _, port_s = target.partition(':')
            try:
                port = int(port_s)
                with socket.create_connection((host, port), timeout=3):
                    ok = True; detail = 'open'
            except Exception:
                detail = 'closed'
        elif mtype == 'http':
            try:
                req = urllib.request.Request(target, method='HEAD')
                ctx = _get_ssl_context()
                with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                    ok = resp.status < 400; detail = str(resp.status)
            except urllib.error.HTTPError as e:
                detail = str(e.code)
            except Exception:
                detail = 'error'
        results.append({
            'label': label, 'type': mtype, 'target': target,
            'ok': ok, 'detail': detail, 'checked': int(time.time()),
        })
    return results


def _persist_monitor_results(results):
    """Append results to history, fire webhooks on transitions, save flags.

    Shared sink for monitor results — same logic regardless of whether
    they came from a user-triggered run or the periodic auto-runner.
    """
    try:
        mh = load(MON_HIST_FILE)
        cfg = load(CONFIG_FILE)
        mon_notified = cfg.get('monitor_notified', {})
        mon_changed = False
        for r in results:
            key = r['label']
            if key not in mh: mh[key] = []
            mh[key].append({'ts': r['checked'], 'ok': r['ok'], 'detail': r['detail']})
            mh[key] = mh[key][-MAX_MON_HISTORY:]
            was_down = mon_notified.get(key, False)
            if not r['ok'] and not was_down:
                fire_webhook('monitor_down', {
                    'label': r['label'], 'type': r['type'],
                    'target': r['target'], 'detail': r['detail'],
                })
                mon_notified[key] = True; mon_changed = True
            elif r['ok'] and was_down:
                fire_webhook('monitor_up', {
                    'label': r['label'], 'type': r['type'],
                    'target': r['target'], 'detail': r['detail'],
                })
                mon_notified[key] = False; mon_changed = True
        save(MON_HIST_FILE, mh)
        if mon_changed:
            cfg['monitor_notified'] = mon_notified
            save(CONFIG_FILE, cfg)
    except Exception:
        pass


def run_monitors_if_due():
    """Run all configured monitors if it's been longer than monitor_interval
    since the last run.

    Called from :func:`main` on every CGI request. Cheap when not due
    (one CONFIG_FILE read + a timestamp compare). When due, runs the
    same logic as the user-triggered run — same webhook firing, same
    history append. Idempotent in the sense that running twice within
    the same interval is a no-op.

    The "last run" timestamp is stored in CONFIG_FILE under
    ``last_monitor_run`` so it survives CGI process restarts (no shared
    in-memory state in CGI). Race condition: two concurrent CGI
    requests can both see "due" and run monitors twice. Acceptable —
    the duplicate writes to history just mean two consecutive entries
    a few seconds apart, and the webhook notification flag prevents
    duplicate alerts.

    Skipped if no monitors are configured (saves the config write).
    """
    cfg = load(CONFIG_FILE)
    monitors = cfg.get('monitors', [])
    if not monitors:
        return
    interval = max(60, int(cfg.get('monitor_interval', 300)))
    last_run = int(cfg.get('last_monitor_run', 0))
    now = int(time.time())
    if (now - last_run) < interval:
        return

    # Mark as in-progress *before* running so a long-running monitor
    # check doesn't trigger a parallel run from another CGI request.
    cfg['last_monitor_run'] = now
    save(CONFIG_FILE, cfg)

    results = _execute_monitor_checks(monitors)
    _persist_monitor_results(results)


def handle_monitor_run():
    """``GET /api/monitor`` — run monitors NOW and return current state.

    User-triggered: somebody opened the Monitor page and wants the
    freshest possible data, not the cached output of the last
    background sweep. We run all monitors synchronously (which can
    take seconds for ping/http with timeouts) and return the results.

    Side effect: also updates ``last_monitor_run`` so the periodic
    runner doesn't immediately re-run. This means refreshing the
    Monitor page resets the background-run schedule, which is fine —
    the user just got fresh data.
    """
    require_auth()
    cfg = load(CONFIG_FILE)
    monitors = cfg.get('monitors', [])
    results = _execute_monitor_checks(monitors)
    _persist_monitor_results(results)
    # Update the timestamp so the background runner doesn't immediately
    # re-check what we just returned.
    cfg2 = load(CONFIG_FILE)
    cfg2['last_monitor_run'] = int(time.time())
    save(CONFIG_FILE, cfg2)
    respond(200, {'monitors': results})


def _get_ssl_context():
    """Return a strict SSL context for outgoing HTTPS requests."""
    import ssl
    ctx = ssl.create_default_context()
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    return ctx


def handle_config_get():
    require_auth()
    cfg = load(CONFIG_FILE)
    safe = {k: v for k, v in cfg.items()
            if k not in ('offline_notified', 'patch_alerted', 'monitor_notified',
                         'containers_stale_notified',
                         '_github_latest_version', '_github_latest_ts')}
    safe['webhook_configured'] = bool(cfg.get('webhook_url', '').strip())
    safe.setdefault('offline_webhook_enabled', True)
    safe.setdefault('monitor_webhook_enabled', True)
    safe.setdefault('cve_webhook_enabled', True)
    safe.setdefault('service_webhook_enabled', True)
    safe.setdefault('monitor_interval', 300)

    # v1.8.4 — derived/effective values that the UI uses
    safe.setdefault('server_name', '')
    safe.setdefault('default_poll_interval', DEFAULT_POLL_INTERVAL)
    safe.setdefault('online_ttl', DEFAULT_ONLINE_TTL)
    safe.setdefault('cve_cache_days', DEFAULT_CVE_CACHE_DAYS)
    safe.setdefault('remember_me_default', False)
    safe.setdefault('session_ttl_short', DEFAULT_TOKEN_TTL_SHORT)
    safe.setdefault('session_ttl_long', DEFAULT_TOKEN_TTL_LONG)
    safe.setdefault('cve_severity_filter', list(CVE_SEVERITY_FILTER_DEFAULT))
    # v1.11.4 — container staleness threshold (seconds). Floor of 300s
    # is enforced at read time by get_container_stale_ttl().
    safe.setdefault('container_stale_ttl', containers_mod.DEFAULT_STALE_TTL)

    # webhook_events: build from explicit dict, falling back to legacy flags
    explicit = cfg.get('webhook_events') or {}
    derived_events = {}
    for ev, _label, _default in WEBHOOK_EVENTS:
        if ev in explicit:
            derived_events[ev] = bool(explicit[ev])
        else:
            derived_events[ev] = is_webhook_event_enabled(ev)
    safe['webhook_events'] = derived_events

    # v1.8.6: SMTP + LDAP defaults — passwords are masked in output
    safe.setdefault('smtp_enabled', False)
    safe.setdefault('smtp_host', '')
    safe.setdefault('smtp_port', 587)
    safe.setdefault('smtp_tls',  'starttls')
    safe.setdefault('smtp_from', '')
    safe.setdefault('smtp_username', '')
    safe.setdefault('smtp_helo_name', '')
    safe.setdefault('smtp_recipients', '')
    safe.setdefault('email_events', {})
    # Mask password — show only whether one is set
    safe['smtp_password_set'] = bool(cfg.get('smtp_password'))
    safe.pop('smtp_password', None)

    safe.setdefault('ldap_enabled', False)
    safe.setdefault('ldap_url', '')
    safe.setdefault('ldap_bind_dn', '')
    safe.setdefault('ldap_user_base', '')
    safe.setdefault('ldap_user_filter', '(uid={u})')
    safe.setdefault('ldap_required_group', '')
    safe.setdefault('ldap_admin_group', '')
    safe.setdefault('ldap_tls_verify', True)
    safe.setdefault('ldap_timeout', 5)

    # v2.3.0: Proxmox connection. Token secret is masked exactly like
    # the SMTP / LDAP passwords — the UI only learns whether one is
    # set, never the value.
    # v2.3.1: the secret may come from the RP_PROXMOX_TOKEN_SECRET
    # environment variable instead of config.json — config_from()
    # resolves that, and we surface where it came from so the
    # settings page can show the right hint.
    safe.setdefault('proxmox_enabled', False)
    safe.setdefault('proxmox_host', '')
    safe.setdefault('proxmox_node', '')
    safe.setdefault('proxmox_token_id', '')
    safe.setdefault('proxmox_verify_tls', True)
    _px = proxmox_client.config_from(cfg)
    safe['proxmox_token_secret_set'] = bool(_px['token_secret'])
    safe['proxmox_token_secret_from_env'] = _px['token_secret_from_env']
    safe.pop('proxmox_token_secret', None)
    safe['ldap_bind_password_set'] = bool(cfg.get('ldap_bind_password'))
    safe.pop('ldap_bind_password', None)

    # Static UI metadata (so the front-end doesn't have to hardcode this)
    safe['_meta'] = {
        'webhook_event_descriptions': {ev: desc for ev, desc, _ in WEBHOOK_EVENTS},
        'cve_severities':             list(CVE_SEVERITIES_ALL),
        'min_online_ttl':             MIN_ONLINE_TTL,
        'smtp_tls_modes':             ['starttls', 'tls', 'plain'],
    }
    respond(200, safe)


def handle_config_save():
    require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body = get_json_body(); cfg = load(CONFIG_FILE)

    if 'webhook_url' in body:
        url = str(body['webhook_url']).strip()
        if url:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme not in ('http', 'https'):
                respond(400, {'error': 'webhook_url must be http or https'})
        cfg['webhook_url'] = url

    if 'offline_webhook_enabled' in body:
        cfg['offline_webhook_enabled'] = bool(body['offline_webhook_enabled'])

    if 'monitor_webhook_enabled' in body:
        cfg['monitor_webhook_enabled'] = bool(body['monitor_webhook_enabled'])

    if 'cve_webhook_enabled' in body:
        cfg['cve_webhook_enabled'] = bool(body['cve_webhook_enabled'])

    if 'service_webhook_enabled' in body:
        cfg['service_webhook_enabled'] = bool(body['service_webhook_enabled'])

    # v1.8.4: per-event toggles (preferred over legacy flags above)
    if 'webhook_events' in body and isinstance(body['webhook_events'], dict):
        clean = {}
        for ev, _label, _default in WEBHOOK_EVENTS:
            if ev in body['webhook_events']:
                clean[ev] = bool(body['webhook_events'][ev])
        cfg['webhook_events'] = clean

    # v1.8.4: server identity
    if 'server_name' in body:
        cfg['server_name'] = _sanitize_str(body['server_name'], 80)

    # v1.8.4: default poll interval (used at enrollment)
    if 'default_poll_interval' in body:
        try:
            v = int(body['default_poll_interval'])
            if not (10 <= v <= 3600):
                respond(400, {'error': 'default_poll_interval must be 10–3600 seconds'})
            cfg['default_poll_interval'] = v
        except (ValueError, TypeError):
            respond(400, {'error': 'default_poll_interval must be an integer'})

    # v1.8.4: online TTL
    if 'online_ttl' in body:
        try:
            v = int(body['online_ttl'])
            if v < MIN_ONLINE_TTL:
                respond(400, {'error': f'online_ttl must be >= {MIN_ONLINE_TTL} seconds'})
            if v > 7200:
                respond(400, {'error': 'online_ttl must be <= 7200 seconds (2h)'})
            cfg['online_ttl'] = v
        except (ValueError, TypeError):
            respond(400, {'error': 'online_ttl must be an integer'})

    # v1.8.4: CVE details cache TTL (in days, internally stored as days)
    if 'cve_cache_days' in body:
        try:
            v = int(body['cve_cache_days'])
            if not (1 <= v <= 90):
                respond(400, {'error': 'cve_cache_days must be 1–90'})
            cfg['cve_cache_days'] = v
        except (ValueError, TypeError):
            respond(400, {'error': 'cve_cache_days must be an integer'})

    # v1.11.4: container staleness TTL (seconds). Floor at 300s so we don't
    # alert on normal poll-interval jitter; cap at 24h so a misclick can't
    # silently break alerting.
    if 'container_stale_ttl' in body:
        try:
            v = int(body['container_stale_ttl'])
            if not (300 <= v <= 86400):
                respond(400, {'error': 'container_stale_ttl must be 300–86400 seconds'})
            cfg['container_stale_ttl'] = v
        except (ValueError, TypeError):
            respond(400, {'error': 'container_stale_ttl must be an integer'})

    # v1.8.4: CVE severity filter (which severities fire cve_found webhook)
    if 'cve_severity_filter' in body:
        raw = body['cve_severity_filter']
        if not isinstance(raw, list):
            respond(400, {'error': 'cve_severity_filter must be a list'})
        clean = [s for s in raw if s in CVE_SEVERITIES_ALL]
        if not clean:
            respond(400, {'error': f'cve_severity_filter must contain at least one of {list(CVE_SEVERITIES_ALL)}'})
        cfg['cve_severity_filter'] = clean

    # v1.8.4: remember-me semantics
    if 'remember_me_default' in body:
        cfg['remember_me_default'] = bool(body['remember_me_default'])
    if 'session_ttl_short' in body:
        try:
            v = int(body['session_ttl_short'])
            if not (300 <= v <= 86400 * 7):
                respond(400, {'error': 'session_ttl_short must be 300–604800 seconds'})
            cfg['session_ttl_short'] = v
        except (ValueError, TypeError):
            respond(400, {'error': 'session_ttl_short must be an integer'})
    if 'session_ttl_long' in body:
        try:
            v = int(body['session_ttl_long'])
            if not (3600 <= v <= 86400 * 90):
                respond(400, {'error': 'session_ttl_long must be 3600–7776000 seconds'})
            cfg['session_ttl_long'] = v
        except (ValueError, TypeError):
            respond(400, {'error': 'session_ttl_long must be an integer'})

    # ── v1.8.6: SMTP settings ──────────────────────────────────────────────────
    if 'smtp_enabled' in body:
        cfg['smtp_enabled'] = bool(body['smtp_enabled'])
    if 'smtp_host' in body:
        cfg['smtp_host'] = _sanitize_str(body['smtp_host'], 255)
    if 'smtp_port' in body:
        try:
            v = int(body['smtp_port'])
            if not (1 <= v <= 65535):
                respond(400, {'error': 'smtp_port must be 1–65535'})
            cfg['smtp_port'] = v
        except (ValueError, TypeError):
            respond(400, {'error': 'smtp_port must be an integer'})
    if 'smtp_tls' in body:
        v = _sanitize_str(body['smtp_tls'], 16).lower()
        if v not in ('starttls', 'tls', 'plain'):
            respond(400, {'error': 'smtp_tls must be starttls, tls, or plain'})
        cfg['smtp_tls'] = v
    if 'smtp_from' in body:
        v = _sanitize_str(body['smtp_from'], 255)
        if v and '@' not in v:
            respond(400, {'error': 'smtp_from must be a valid email address'})
        cfg['smtp_from'] = v
    if 'smtp_username' in body:
        cfg['smtp_username'] = _sanitize_str(body['smtp_username'], 255)
    if 'smtp_password' in body:
        # Empty string clears it; leaving the key out preserves existing
        new_pw = body['smtp_password']
        if new_pw == '':
            cfg.pop('smtp_password', None)
        elif isinstance(new_pw, str):
            cfg['smtp_password'] = new_pw[:1024]
    if 'smtp_helo_name' in body:
        cfg['smtp_helo_name'] = _sanitize_str(body['smtp_helo_name'], 255)
    if 'smtp_recipients' in body:
        cfg['smtp_recipients'] = _sanitize_str(body['smtp_recipients'], 2000)

    # Per-event email toggles
    if 'email_events' in body and isinstance(body['email_events'], dict):
        clean = {}
        for ev_name in WEBHOOK_EVENT_NAMES:
            if ev_name in body['email_events']:
                clean[ev_name] = bool(body['email_events'][ev_name])
        cfg['email_events'] = clean

    # ── v2.3.0: Proxmox connection settings ────────────────────────────────────
    if 'proxmox_enabled' in body:
        cfg['proxmox_enabled'] = bool(body['proxmox_enabled'])
    if 'proxmox_host' in body:
        # Bare host, host:port, or a full URL — the client normalises it.
        cfg['proxmox_host'] = _sanitize_str(body['proxmox_host'], 255)
    if 'proxmox_node' in body:
        cfg['proxmox_node'] = _sanitize_str(body['proxmox_node'], 64)
    if 'proxmox_token_id' in body:
        # e.g. root@pam!remotepower
        cfg['proxmox_token_id'] = _sanitize_str(body['proxmox_token_id'], 255)
    if 'proxmox_verify_tls' in body:
        cfg['proxmox_verify_tls'] = bool(body['proxmox_verify_tls'])
    if 'proxmox_token_secret' in body:
        # Same convention as smtp_password: '' clears, omitted preserves.
        new_secret = body['proxmox_token_secret']
        if new_secret == '':
            cfg.pop('proxmox_token_secret', None)
        elif isinstance(new_secret, str):
            cfg['proxmox_token_secret'] = new_secret[:1024]

    # ── v1.8.6: LDAP settings ──────────────────────────────────────────────────
    if 'ldap_enabled' in body:
        cfg['ldap_enabled'] = bool(body['ldap_enabled'])
    if 'ldap_url' in body:
        v = _sanitize_str(body['ldap_url'], 255)
        if v and not (v.startswith('ldap://') or v.startswith('ldaps://')):
            respond(400, {'error': 'ldap_url must start with ldap:// or ldaps://'})
        cfg['ldap_url'] = v
    if 'ldap_bind_dn' in body:
        cfg['ldap_bind_dn'] = _sanitize_str(body['ldap_bind_dn'], 512)
    if 'ldap_bind_password' in body:
        new_pw = body['ldap_bind_password']
        if new_pw == '':
            cfg.pop('ldap_bind_password', None)
        elif isinstance(new_pw, str):
            cfg['ldap_bind_password'] = new_pw[:1024]
    if 'ldap_user_base' in body:
        cfg['ldap_user_base'] = _sanitize_str(body['ldap_user_base'], 512)
    if 'ldap_user_filter' in body:
        v = _sanitize_str(body['ldap_user_filter'], 256)
        if v and '{u}' not in v:
            respond(400, {'error': 'ldap_user_filter must contain {u} placeholder'})
        cfg['ldap_user_filter'] = v or '(uid={u})'
    if 'ldap_required_group' in body:
        cfg['ldap_required_group'] = _sanitize_str(body['ldap_required_group'], 512)
    if 'ldap_admin_group' in body:
        cfg['ldap_admin_group'] = _sanitize_str(body['ldap_admin_group'], 512)
    if 'ldap_tls_verify' in body:
        cfg['ldap_tls_verify'] = bool(body['ldap_tls_verify'])
    if 'ldap_timeout' in body:
        try:
            v = int(body['ldap_timeout'])
            if not (1 <= v <= 60):
                respond(400, {'error': 'ldap_timeout must be 1–60 seconds'})
            cfg['ldap_timeout'] = v
        except (ValueError, TypeError):
            respond(400, {'error': 'ldap_timeout must be an integer'})

    if 'wol_broadcast' in body:
        cfg['wol_broadcast'] = _sanitize_ip(body['wol_broadcast']) or '255.255.255.255'

    if 'wol_port' in body:
        try:
            port = int(body['wol_port'])
            if not (1 <= port <= 65535):
                respond(400, {'error': 'wol_port must be 1–65535'})
            cfg['wol_port'] = port
        except (ValueError, TypeError):
            respond(400, {'error': 'wol_port must be an integer'})

    if 'patch_alert_threshold' in body:
        val = body['patch_alert_threshold']
        if val is None or val == '' or val == 0:
            cfg.pop('patch_alert_threshold', None)
            cfg.pop('patch_alerted', None)
        else:
            try:
                t = int(val)
                if t < 1: respond(400, {'error': 'patch_alert_threshold must be >= 1'})
                cfg['patch_alert_threshold'] = t
            except (ValueError, TypeError):
                respond(400, {'error': 'patch_alert_threshold must be an integer'})

    if 'monitors' in body and isinstance(body['monitors'], list):
        validated = []
        for m in body['monitors'][:50]:  # max 50 monitors
            if not isinstance(m, dict):
                continue
            mtype = m.get('type', '')
            if mtype not in ('ping', 'tcp', 'http'):
                continue
            raw_target = str(m.get('target', ''))
            target = _sanitize_monitor_target(mtype, raw_target)
            if target is None:
                respond(400, {'error': f'Invalid monitor target: {raw_target[:80]}'})
            validated.append({
                'label':  _sanitize_str(m.get('label', target), 128),
                'type':   mtype,
                'target': target,
            })
        cfg['monitors'] = validated

    if 'allow_internal_monitors' in body:
        cfg['allow_internal_monitors'] = bool(body['allow_internal_monitors'])

    if 'monitor_interval' in body:
        try:
            mi = int(body['monitor_interval'])
            mi = max(60, min(3600, mi))
            cfg['monitor_interval'] = mi
        except (ValueError, TypeError):
            respond(400, {'error': 'monitor_interval must be an integer (60–3600)'})

    save(CONFIG_FILE, cfg)
    respond(200, {'ok': True})


def handle_history():
    require_auth()
    history = load(HISTORY_FILE)
    respond(200, list(reversed(history.get('entries', []))))


def handle_history_clear():
    actor = require_admin_auth()
    if method() != 'DELETE': respond(405, {'error': 'Method not allowed'})
    save(HISTORY_FILE, {'entries': []})
    audit_log(actor, 'clear_history', 'command history cleared')
    respond(200, {'ok': True})


def handle_users_list():
    require_auth()
    users = load(USERS_FILE)
    respond(200, [{'username': u, 'created': d.get('created', 0), 'role': d.get('role', 'admin')}
                  for u, d in users.items()])


def handle_user_create():
    require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    username = _sanitize_str(body.get('username', ''), 32)
    password = body.get('password', '')
    role     = body.get('role', 'admin')
    if role not in ('admin', 'viewer'): respond(400, {'error': 'role must be admin or viewer'})
    if not username or not re.match(r'^[a-zA-Z0-9_\-]{2,32}$', username):
        respond(400, {'error': 'Invalid username (2-32 chars, alphanumeric/_/-)'})
    if not isinstance(password, str) or not password or len(password) > 1024:
        respond(400, {'error': 'Password required (max 1024 chars)'})
    users = load(USERS_FILE)
    if username in users: respond(400, {'error': 'User already exists'})
    users[username] = {'password_hash': hash_password(password), 'created': int(time.time()), 'role': role}
    save(USERS_FILE, users)
    respond(201, {'ok': True, 'username': username, 'role': role})


def handle_user_delete(username):
    requester = require_admin_auth()
    if method() != 'DELETE': respond(405, {'error': 'Method not allowed'})
    if not re.match(r'^[a-zA-Z0-9_\-]{2,32}$', username):
        respond(404, {'error': 'User not found'})
    if username == requester: respond(400, {'error': 'Cannot delete yourself'})
    users = load(USERS_FILE)
    if username not in users: respond(404, {'error': 'User not found'})
    admins = [u for u, d in users.items() if d.get('role', 'admin') == 'admin']
    if len(admins) <= 1 and users[username].get('role', 'admin') == 'admin':
        respond(400, {'error': 'Cannot delete last admin'})
    del users[username]; save(USERS_FILE, users)
    respond(200, {'ok': True})


def handle_user_passwd():
    requester = require_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    username = _sanitize_str(body.get('username', requester), 32)
    old_pw   = body.get('old_password', '')
    new_pw   = body.get('new_password', '')

    if not isinstance(new_pw, str) or not new_pw or len(new_pw) > 1024:
        respond(400, {'error': 'new_password required (max 1024 chars)'})

    users = load(USERS_FILE)
    _, requester_role = verify_token(get_token_from_request())

    # Non-admins can only change their own password
    if username != requester and requester_role != 'admin':
        respond(403, {'error': 'Cannot change another user\'s password'})

    user = users.get(username)
    if not user: respond(404, {'error': 'User not found'})

    # Changing own password always requires old password
    if username == requester:
        if not verify_password(old_pw, user['password_hash']):
            respond(401, {'error': 'Old password incorrect'})

    users[username]['password_hash'] = hash_password(new_pw)
    # v2.3.2: once the password is changed, clear the default-password
    # warning flag so the UI banner stops showing.
    users[username].pop('must_change_password', None)
    save(USERS_FILE, users)

    # Invalidate all existing sessions for this user on password change
    tokens = load(TOKENS_FILE)
    tokens = {k: v for k, v in tokens.items() if v.get('user') != username}
    save(TOKENS_FILE, tokens)

    respond(200, {'ok': True})


# ─── v1.11.5: per-user UI preferences ────────────────────────────────────────
#
# Stored under users[username]['ui_prefs'] as a dict keyed by table name. Each
# table entry can carry:
#
#   density   — 'compact' / 'comfortable' / 'spacious'
#   filter    — string, the live filter input value
#   sort      — list of {col: str, dir: 'asc'|'desc'}, in priority order
#
# Schema enforced by :func:`_sanitise_ui_prefs` — the client can send anything,
# but we strip everything we don't recognise so a future field rename or
# malicious payload can't blow up users.json. Stored together with the user
# record (rather than a separate file) so password changes / user deletes
# automatically clean up the prefs too.


def _sanitise_ui_prefs(raw):
    """Validate and trim a UI prefs payload before persisting.

    Args:
        raw: Whatever the client sent. Expected to be a dict keyed by
            table name. Anything else returns an empty dict.

    Returns:
        A clean dict safe to drop into ``users[username]['ui_prefs']``.
        Drops unknown keys silently — old clients sending now-removed
        fields don't break, new clients sending unknown fields don't
        bloat the store.
    """
    if not isinstance(raw, dict):
        return {}
    out = {}

    # v2.4.2: a per-user default SSH username — a single top-level
    # string, not a per-table pref. Reused by the Devices-page quick
    # SSH link so the operator doesn't retype their login each time.
    # Validated as an SSH-safe username (letters, digits, dot, dash,
    # underscore; max 32) — this value is interpolated into an ssh://
    # URL, so the character set is deliberately strict.
    ssh_user = raw.get('default_ssh_username')
    if isinstance(ssh_user, str) and ssh_user:
        if re.fullmatch(r'[A-Za-z0-9._-]{1,32}', ssh_user):
            out['default_ssh_username'] = ssh_user

    # Cap how many distinct table prefs we'll persist for one user. Stops
    # a misbehaving client from filling users.json with junk keys.
    for table_name, prefs in list(raw.items())[:MAX_UI_PREFS_TABLES]:
        if table_name == 'default_ssh_username':
            continue   # handled above — not a table
        # Table names are short alphanumeric identifiers (e.g. 'devices',
        # 'cves_overview'). Strip anything not in that vocabulary.
        clean_name = re.sub(r'[^a-zA-Z0-9_]', '', str(table_name))[:64]
        if not clean_name or not isinstance(prefs, dict):
            continue
        clean = {}

        density = prefs.get('density')
        if density in UI_DENSITY_VALUES:
            clean['density'] = density

        filt = prefs.get('filter')
        if isinstance(filt, str) and filt:
            clean['filter'] = filt[:MAX_UI_PREFS_FILTER_LEN]

        sort = prefs.get('sort')
        if isinstance(sort, list):
            clean_sort = []
            for entry in sort[:MAX_UI_PREFS_SORT_KEYS]:
                if not isinstance(entry, dict):
                    continue
                col = entry.get('col')
                dirn = entry.get('dir')
                if not isinstance(col, str) or not col:
                    continue
                # Column identifiers are short alphanumeric strings — same
                # rule as table names above.
                clean_col = re.sub(r'[^a-zA-Z0-9_]', '', col)[:64]
                if not clean_col:
                    continue
                if dirn not in ('asc', 'desc'):
                    dirn = 'asc'
                clean_sort.append({'col': clean_col, 'dir': dirn})
            if clean_sort:
                clean['sort'] = clean_sort

        if clean:
            out[clean_name] = clean

    # Final size enforcement — JSON-encode and check. Cheap insurance
    # against pathological payloads that pass field-level checks but
    # bloat the file.
    encoded = json.dumps(out)
    if len(encoded) > MAX_UI_PREFS_BYTES:
        # Bail out cleanly rather than silently truncating — easier to debug.
        return {}
    return out


def handle_ui_prefs_get():
    """``GET /api/ui-prefs`` — return current user's stored UI prefs.

    Returns ``{}`` if the user has none yet (fresh sign-up). Never errors
    on missing data — UI prefs are best-effort cosmetics, the page must
    work without them.
    """
    username = require_auth()
    users = load(USERS_FILE)
    user = users.get(username) or {}
    prefs = user.get('ui_prefs') or {}
    if not isinstance(prefs, dict):
        prefs = {}
    respond(200, prefs)


def handle_ui_prefs_set():
    """``POST /api/ui-prefs`` — overwrite current user's UI prefs.

    Whole-document replacement, not patch. The client is the source of
    truth (it has the latest filter strings, sort orders, etc.); the
    server just stores. This avoids the merge-conflict trap of partial
    updates when the same user has two tabs open.
    """
    username = require_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    if not isinstance(body, dict):
        respond(400, {'error': 'body must be a JSON object'})

    clean = _sanitise_ui_prefs(body)
    users = load(USERS_FILE)
    if username not in users:
        # Should be impossible — auth just succeeded — but defend anyway.
        respond(404, {'error': 'User not found'})
    users[username]['ui_prefs'] = clean
    save(USERS_FILE, users)
    respond(200, {'ok': True, 'prefs': clean})


def handle_ui_prefs_clear():
    """``DELETE /api/ui-prefs`` — wipe current user's UI prefs.

    Useful for "reset to defaults" buttons in the UI without forcing the
    client to know what 'defaults' means.
    """
    username = require_auth()
    if method() != 'DELETE':
        respond(405, {'error': 'Method not allowed'})
    users = load(USERS_FILE)
    if username in users and 'ui_prefs' in users[username]:
        users[username].pop('ui_prefs', None)
        save(USERS_FILE, users)
    respond(200, {'ok': True})


def handle_totp_setup():
    """Generate a TOTP secret for the current user. Does NOT enable until confirmed."""
    username = require_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    secret = _generate_totp_secret()
    uri = _totp_provisioning_uri(secret, username)
    # Store pending secret — not active until confirmed
    users = load(USERS_FILE)
    if username not in users: respond(404, {'error': 'User not found'})
    users[username]['totp_pending'] = secret
    save(USERS_FILE, users)
    audit_log(username, 'totp_setup', 'generated new TOTP secret')
    respond(200, {'ok': True, 'secret': secret, 'uri': uri,
                  'note': 'Scan the QR code or enter the secret in your authenticator app, then confirm with /api/totp/confirm'})


def handle_totp_confirm():
    """Confirm TOTP setup by verifying a code from the authenticator app."""
    username = require_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    code = str(body.get('code', '')).strip()
    users = load(USERS_FILE)
    if username not in users: respond(404, {'error': 'User not found'})
    pending = users[username].get('totp_pending')
    if not pending: respond(400, {'error': 'No pending TOTP setup — call /api/totp/setup first'})
    valid_codes = _totp(pending)
    if code not in valid_codes:
        respond(400, {'error': 'Invalid code — check your authenticator app and try again'})
    # Activate TOTP
    users[username]['totp_secret'] = pending
    del users[username]['totp_pending']
    save(USERS_FILE, users)
    audit_log(username, 'totp_enabled', '2FA activated')
    respond(200, {'ok': True, 'message': '2FA is now enabled. You will need your authenticator code at each login.'})


def handle_totp_disable():
    """Disable 2FA for the current user (requires password confirmation)."""
    username = require_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    password = body.get('password', '')
    users = load(USERS_FILE)
    if username not in users: respond(404, {'error': 'User not found'})
    if not verify_password(password, users[username].get('password_hash', '')):
        respond(401, {'error': 'Password incorrect'})
    users[username].pop('totp_secret', None)
    users[username].pop('totp_pending', None)
    save(USERS_FILE, users)
    audit_log(username, 'totp_disabled', '2FA deactivated')
    respond(200, {'ok': True, 'message': '2FA has been disabled.'})


def handle_totp_status():
    """Check if 2FA is enabled for the current user."""
    username = require_auth()
    users = load(USERS_FILE)
    if username not in users: respond(404, {'error': 'User not found'})
    enabled = bool(users[username].get('totp_secret'))
    respond(200, {'enabled': enabled, 'username': username})


def handle_agent_version():
    agent_path = Path('/var/www/remotepower/agent/remotepower-agent')
    if not agent_path.exists():
        respond(200, {'version': None, 'sha256': None})
    cfg = load(CONFIG_FILE)
    sha = hashlib.sha256(agent_path.read_bytes()).hexdigest()
    respond(200, {'version': cfg.get('agent_version', 'unknown'), 'sha256': sha})


def handle_agent_download():
    agent_path = Path('/var/www/remotepower/agent/remotepower-agent')
    if not agent_path.exists(): respond(404, {'error': 'Agent binary not found'})
    data = agent_path.read_bytes()
    print("Status: 200 OK"); print("Content-Type: application/octet-stream")
    print("Content-Disposition: attachment; filename=remotepower-agent")
    print(f"Content-Length: {len(data)}"); print("Cache-Control: no-store"); print()
    sys.stdout.flush(); sys.stdout.buffer.write(data); sys.stdout.buffer.flush(); sys.exit(0)


def handle_version_check():
    require_auth()
    cfg   = load(CONFIG_FILE)
    # v2.1.3: read the *actually running* version from SERVER_VERSION, not
    # from CONFIG_FILE. The previous code (`cfg.get('server_version',
    # SERVER_VERSION)`) returned a stale value whenever an old upgrade
    # had stamped the version into config.json and the next upgrade
    # forgot to refresh it. That's why the About page showed "Latest
    # release 2.0.0 ✓ up to date" on a 2.1.2 box: `local` was the
    # cached 2.0.0 from a year ago, and the comparison against GitHub's
    # 2.0.0 release tag came out equal.
    local = SERVER_VERSION
    now   = int(time.time())
    cached_latest = cfg.get('_github_latest_version')
    cached_ts     = cfg.get('_github_latest_ts', 0)
    if cached_latest and (now - cached_ts) < 3600:
        latest = cached_latest
    else:
        try:
            req = urllib.request.Request(
                'https://api.github.com/repos/tyxak/remotepower/releases/latest',
                headers={'User-Agent': 'RemotePower'})
            ctx = _get_ssl_context()
            with urllib.request.urlopen(req, timeout=5, context=ctx) as r:
                data = json.loads(r.read(65536))  # cap response size
            # Strictly validate: tag must match semver pattern
            raw_tag = data.get('tag_name', '').lstrip('v')
            if re.match(r'^\d{1,4}\.\d{1,4}\.\d{1,4}$', raw_tag):
                latest = raw_tag
            else:
                latest = cached_latest
            if latest:
                cfg['_github_latest_version'] = latest
                cfg['_github_latest_ts']      = now
                save(CONFIG_FILE, cfg)
        except Exception:
            latest = cached_latest

    def vt(v):
        try: return tuple(int(x) for x in v.split('.'))
        except Exception: return (0,)

    # v2.1.3: the "Latest release" on About is conceptually "the latest
    # version you should consider running". If GitHub's tagged latest is
    # *older* than what we're actually running (true on dev builds, true
    # during the gap between cutting a release and publishing it), the
    # latest you should run is the version you have. So clamp:
    #   latest = max(github_tag, local)
    # The `update_available` flag stays accurate (false when running
    # ahead), and the UI no longer confusingly displays an older
    # version as "Latest release".
    if latest is None or vt(latest) < vt(local):
        latest = local

    update_available = vt(latest) > vt(local)
    respond(200, {
        'current': local, 'latest': latest,
        'update_available': update_available,
        'release_url': 'https://github.com/tyxak/remotepower/releases/latest',
    })


def _record_uptime(dev_id, name, is_online):
    uptime = load(UPTIME_FILE)
    if dev_id not in uptime:
        uptime[dev_id] = {'name': name, 'events': []}
    events = uptime[dev_id].get('events', [])
    last_state = events[-1]['online'] if events else None
    if last_state != is_online:
        events.append({'ts': int(time.time()), 'online': is_online})
        uptime[dev_id]['events'] = events[-500:]
        uptime[dev_id]['name'] = name
        save(UPTIME_FILE, uptime)


def handle_uptime(dev_id):
    require_auth()
    if not _validate_id(dev_id): respond(404, {'error': 'Device not found'})
    uptime = load(UPTIME_FILE); dev = uptime.get(dev_id, {})
    respond(200, {'device_id': dev_id, 'name': dev.get('name', dev_id), 'events': dev.get('events', [])})


def _day_status_from_events(events, day_start, day_end):
    """Derive a single day's status from a device's uptime events.

    `events` is the sorted [{ts, online}] transition list. A day is:
      - 'down'    if the device entered the day offline, or went
                  offline at any point during it;
      - 'up'      if the device had data covering the day and was
                  never offline in it;
      - 'unknown' if there is no event at or before the day's end —
                  RemotePower genuinely has no record for that day.
    """
    state_at_start = None     # state as of day_start
    state_seen = None         # any state with ts < day_end
    saw_down = False
    for e in events:
        ts = e.get('ts', 0)
        online = bool(e.get('online'))
        if ts < day_start:
            state_at_start = online
            state_seen = online
        elif ts < day_end:
            state_seen = online
            if not online:
                saw_down = True
        else:
            break
    if state_seen is None:
        return 'unknown'
    if state_at_start is False or saw_down:
        return 'down'
    return 'up'


def handle_fleet_uptime7d():
    """GET /api/fleet/uptime7d — a real 7-day daily up/down status per
    device, derived from uptime.json.

    Days with no recorded data come back 'unknown' — RemotePower does
    not invent history it never recorded. The array is oldest-first;
    the last element is today.

    Only monitored devices are included: a device explicitly set to
    `monitored: false` (decommissioned, dev box, being rebuilt) is
    silenced everywhere else — the attention digest, the alert
    pipeline — and must not appear in the fleet roster stripe either.
    """
    require_auth()
    uptime = load(UPTIME_FILE) or {}
    devices = load(DEVICES_FILE) or {}
    now = int(time.time())
    DAY = 86400
    # Midnight (local) of today, then the 7 day-windows ending with it.
    today_start = now - (now % DAY)
    windows = [(today_start - (6 - i) * DAY,
                today_start - (6 - i) * DAY + DAY) for i in range(7)]
    out = {}
    for dev_id, rec in uptime.items():
        dev = devices.get(dev_id)
        # Skip unmonitored devices, and any uptime record with no
        # matching device entry (stale leftover).
        if dev is None or not dev.get('monitored', True):
            continue
        events = sorted((rec or {}).get('events') or [],
                        key=lambda e: e.get('ts', 0))
        out[dev_id] = [_day_status_from_events(events, s, e)
                       for (s, e) in windows]
    respond(200, {'uptime': out})


def handle_monitor_history(label):
    require_auth()
    label = _sanitize_str(label, 128)
    mh = load(MON_HIST_FILE)
    respond(200, {'label': label, 'history': mh.get(label, [])})


def handle_schedule_list():
    require_auth()
    schedule = load(SCHEDULE_FILE)
    respond(200, schedule.get('jobs', []))


def _valid_cron(expr):
    """Validate a 5-field cron expression with range checks."""
    parts = expr.strip().split()
    if len(parts) != 5:
        return False
    ranges = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)]
    for part, (lo, hi) in zip(parts, ranges):
        if part == '*':
            continue
        if part.startswith('*/'):
            try:
                step = int(part[2:])
                if step < 1 or step > hi:
                    return False
            except ValueError:
                return False
        else:
            try:
                v = int(part)
                if not (lo <= v <= hi):
                    return False
            except ValueError:
                return False
    return True


def _cron_matches(cron, ts):
    import datetime
    parts = cron.split()
    if len(parts) != 5: return False
    minute, hour, dom, month, dow = parts
    dt = datetime.datetime.fromtimestamp(ts)
    def _match(field, val):
        if field == '*': return True
        if field.startswith('*/'):
            try: return val % int(field[2:]) == 0
            except: return False
        try: return int(field) == val
        except: return False
    return (_match(minute, dt.minute) and _match(hour, dt.hour) and
            _match(dom, dt.day) and _match(month, dt.month) and _match(dow, dt.weekday()))


def handle_schedule_add():
    actor = require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body    = get_json_body()
    dev_id  = str(body.get('device_id', '')).strip()
    command = str(body.get('command', '')).strip()
    run_at  = body.get('run_at', 0)
    cron    = _sanitize_str(body.get('cron', ''), 64)

    if not _validate_id(dev_id): respond(404, {'error': 'Device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices: respond(404, {'error': 'Device not found'})
    if command not in ('shutdown', 'reboot'): respond(400, {'error': 'command must be shutdown or reboot'})

    if cron:
        if not _valid_cron(cron): respond(400, {'error': 'Invalid cron expression'})
    elif not isinstance(run_at, (int, float)) or run_at <= int(time.time()):
        respond(400, {'error': 'run_at must be a future unix timestamp'})

    schedule = load(SCHEDULE_FILE)
    jobs = schedule.get('jobs', [])
    if len(jobs) >= MAX_SCHEDULE_JOBS:
        respond(400, {'error': f'Schedule limit reached (max {MAX_SCHEDULE_JOBS} jobs)'})

    job = {
        'id':          secrets.token_hex(6),
        'device_id':   dev_id,
        'device_name': devices[dev_id].get('name', dev_id),
        'command':     command,
        'run_at':      int(run_at) if not cron else None,
        'cron':        cron or None,
        'actor':       actor,
        'created':     int(time.time()),
        'recurring':   bool(cron),
    }
    jobs.append(job)
    schedule['jobs'] = jobs
    save(SCHEDULE_FILE, schedule)
    respond(201, {'ok': True, 'job': job})


def handle_schedule_delete(job_id):
    require_admin_auth()
    if method() != 'DELETE': respond(405, {'error': 'Method not allowed'})
    if not _validate_id(job_id): respond(404, {'error': 'Job not found'})
    schedule = load(SCHEDULE_FILE)
    jobs = [j for j in schedule.get('jobs', []) if j['id'] != job_id]
    if len(jobs) == len(schedule.get('jobs', [])): respond(404, {'error': 'Job not found'})
    schedule['jobs'] = jobs; save(SCHEDULE_FILE, schedule)
    respond(200, {'ok': True})


def process_schedule():
    schedule = load(SCHEDULE_FILE)
    jobs     = schedule.get('jobs', [])
    now      = int(time.time())
    remaining = []
    changed = False
    for job in jobs:
        due = False
        if job.get('recurring') and job.get('cron'):
            due = _cron_matches(job['cron'], now)
        elif job.get('run_at') and job['run_at'] <= now:
            due = True
        if due:
            dev_id  = job['device_id']
            command = job['command']
            if command not in ('shutdown', 'reboot'):  # extra safety
                if job.get('recurring'):
                    remaining.append(job)
                changed = True
                continue
            if _validate_id(dev_id):
                devices = load(DEVICES_FILE)
                if dev_id in devices:
                    cmds = load(CMDS_FILE)
                    if dev_id not in cmds: cmds[dev_id] = []
                    if command not in cmds[dev_id]: cmds[dev_id].append(command)
                    save(CMDS_FILE, cmds)
                    log_command(f"scheduler({job['actor']})", dev_id, job['device_name'], command)
            if job.get('recurring'):
                remaining.append(job)
            changed = True
        else:
            remaining.append(job)
    if changed:
        schedule['jobs'] = remaining
        save(SCHEDULE_FILE, schedule)


def handle_custom_cmd():
    actor = require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body    = get_json_body()
    cmd_str = str(body.get('cmd', '')).strip()
    if not cmd_str: respond(400, {'error': 'cmd required'})
    if len(cmd_str) > 512: respond(400, {'error': 'cmd too long (max 512 chars)'})

    # Support batch targets (device_ids, tag, group) just like shutdown/reboot
    ids = _resolve_targets(body)
    if not ids: respond(400, {'error': 'No valid device targets'})

    devices = load(DEVICES_FILE)
    cmds = load(CMDS_FILE)
    results = {}
    for dev_id in ids:
        if not _validate_id(dev_id):
            results[dev_id] = {'ok': False, 'error': 'Invalid device ID'}; continue
        if dev_id not in devices:
            results[dev_id] = {'ok': False, 'error': 'Device not found'}; continue
        ok, reason = _check_exec_allowlist(dev_id, cmd_str, devices)
        if not ok:
            results[dev_id] = {'ok': False, 'error': reason}; continue
        if dev_id not in cmds: cmds[dev_id] = []
        cmds[dev_id].append(f'exec:{cmd_str}')
        log_command(actor, dev_id, devices[dev_id].get('name', dev_id), f'exec:{cmd_str[:40]}')
        audit_log(actor, 'exec', f'{dev_id}: {cmd_str[:80]}')
        fire_webhook('command_queued', {
            'device_id': dev_id, 'name': devices[dev_id].get('name', dev_id),
            'command': f'exec:{cmd_str[:40]}', 'actor': actor,
        })
        results[dev_id] = {'ok': True}
    save(CMDS_FILE, cmds)
    if len(ids) == 1:
        r = results.get(ids[0], {})
        if r.get('ok'): respond(200, {'ok': True})
        else: respond(400, r)
    else:
        respond(200, {'ok': True, 'results': results})


def handle_cmd_output(dev_id):
    require_auth()
    if not _validate_id(dev_id): respond(404, {'error': 'Device not found'})
    outputs = load(CMD_OUTPUT_FILE)
    respond(200, {'outputs': outputs.get(dev_id, [])})


def handle_device_update_logs(dev_id: str) -> None:
    """
    GET /api/devices/{id}/update-logs.

    Returns the rolling buffer of `update` command runs for this device.

    Each entry: ``{started_at, finished_at, exit_code, output,
    package_manager, triggered_by}``. Most recent runs are at the end of
    the list. Capped at :data:`MAX_UPDATE_LOGS_PER_DEVICE` entries per
    device with the oldest evicted on overflow.
    """
    require_auth()
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    logs = load(UPDATE_LOGS_FILE)
    respond(200, {
        'device_id': dev_id,
        'name':      devices[dev_id].get('name', dev_id),
        'logs':      logs.get(dev_id, []),
        'capacity':  MAX_UPDATE_LOGS_PER_DEVICE,
    })


def handle_device_containers(dev_id: str) -> None:
    """``GET /api/devices/{id}/containers`` — return last reported containers.

    The list is overwritten on every heartbeat (state, not history) and
    capped at :data:`containers_mod.MAX_CONTAINERS_PER_DEVICE` items.

    Args:
        dev_id: The enrolled device's ID.
    """
    require_auth()
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    store = load(CONTAINERS_FILE)
    entry = store.get(dev_id) or {}
    items = entry.get('items', [])
    reported_at = entry.get('ts', 0)
    # v1.11.4: surface staleness so the UI can flag old data without each
    # caller having to recompute the threshold.
    ttl = get_container_stale_ttl()
    now = int(time.time())
    respond(200, {
        'device_id': dev_id,
        'name':      devices[dev_id].get('name', dev_id),
        'reported_at': reported_at,
        'is_stale':  containers_mod.is_stale(reported_at, now, ttl),
        'stale_ttl': ttl,
        'items':     items,
        'summary':   containers_mod.summarise(items),
    })


def handle_proxmox_status() -> None:
    """``GET /api/proxmox/status`` — is Proxmox configured / enabled?

    Cheap, no network call. The frontend uses this to decide whether
    to show the Virtualization nav entry and the LXC section.
    """
    require_auth()
    cfg = load(CONFIG_FILE)
    pc = proxmox_client.config_from(cfg)
    respond(200, {
        'enabled':    pc['enabled'],
        'configured': proxmox_client.is_configured(pc),
        'host':       pc['host'],
        'node':       pc['node'],
        'verify_tls': pc['verify_tls'],
    })


def handle_proxmox_test() -> None:
    """``POST /api/proxmox/test`` — probe the connection (Settings page).

    Uses the saved config. If the request body carries a fresh
    token_secret (operator typed a new one but hasn't saved yet) it's
    used for the probe so "Test" works before "Save".
    """
    require_admin_auth()
    cfg = load(CONFIG_FILE)
    pc = proxmox_client.config_from(cfg)
    body = get_json_body() or {}
    # Allow testing un-saved values straight from the form.
    for k in ('proxmox_host', 'proxmox_node', 'proxmox_token_id'):
        if body.get(k):
            pc[k.replace('proxmox_', '')] = str(body[k]).strip()
    if body.get('proxmox_token_secret'):
        pc['token_secret'] = str(body['proxmox_token_secret'])
    if 'proxmox_verify_tls' in body:
        pc['verify_tls'] = bool(body['proxmox_verify_tls'])
    result = proxmox_client.test_connection(pc)
    respond(200, result)


def handle_proxmox_list(guest_type: str) -> None:
    """``GET /api/proxmox/qemu`` or ``/api/proxmox/lxc`` — list guests."""
    require_auth()
    cfg = load(CONFIG_FILE)
    pc = proxmox_client.config_from(cfg)
    if not pc['enabled']:
        respond(200, {'enabled': False, 'guests': []})
    if not proxmox_client.is_configured(pc):
        respond(200, {'enabled': True, 'configured': False, 'guests': []})
    try:
        guests = proxmox_client.list_guests(pc, guest_type)
    except proxmox_client.ProxmoxError as e:
        respond(502, {'error': str(e)})
        return
    respond(200, {'enabled': True, 'configured': True,
                  'node': pc['node'], 'guests': guests})


def handle_proxmox_action(guest_type: str, rest: str) -> None:
    """``POST /api/proxmox/{qemu,lxc}/<vmid>/<action>`` — guest action.

    Actions are gated by proxmox_client.ALLOWED_VM_ACTIONS. The UI
    only ever sends start / shutdown / status; `stop` (hard) is in
    the allow-list for a future force-stop but isn't exposed yet.
    """
    require_admin_auth()
    parts = [p for p in rest.split('/') if p]
    if len(parts) != 2:
        respond(400, {'error': 'Expected /<vmid>/<action>'})
        return
    vmid_str, action = parts
    try:
        vmid = int(vmid_str)
    except ValueError:
        respond(400, {'error': 'vmid must be numeric'})
        return
    cfg = load(CONFIG_FILE)
    pc = proxmox_client.config_from(cfg)
    if not (pc['enabled'] and proxmox_client.is_configured(pc)):
        respond(400, {'error': 'Proxmox is not configured.'})
        return
    try:
        result = proxmox_client.guest_action(pc, guest_type, vmid, action)
    except proxmox_client.ProxmoxError as e:
        # Action-not-allowed and bad input map to 400; the message is
        # safe (never contains the token).
        code = 400 if 'not allowed' in str(e).lower() else 502
        respond(code, {'error': str(e)})
        return
    # Record a fleet event so the action shows in the activity log.
    try:
        _record_fleet_event('proxmox_action', {
            'guest_type': guest_type, 'vmid': vmid, 'action': action,
        })
    except Exception:
        pass
    respond(200, result)


def handle_proxmox_snapshots_list() -> None:
    """``GET /api/proxmox/snapshots?type=qemu&vmid=100`` — list a
    guest's snapshots."""
    require_auth()
    qs = urllib.parse.parse_qs(os.environ.get('QUERY_STRING', '') or '')
    guest_type = (qs.get('type') or [''])[0]
    vmid_str = (qs.get('vmid') or [''])[0]
    if guest_type not in ('qemu', 'lxc') or not vmid_str.isdigit():
        respond(400, {'error': 'type (qemu|lxc) and numeric vmid required'})
        return
    cfg = load(CONFIG_FILE)
    pc = proxmox_client.config_from(cfg)
    if not (pc['enabled'] and proxmox_client.is_configured(pc)):
        respond(400, {'error': 'Proxmox is not configured.'})
        return
    try:
        snaps = proxmox_client.list_snapshots(pc, guest_type, int(vmid_str))
    except proxmox_client.ProxmoxError as e:
        respond(502, {'error': str(e)})
        return
    respond(200, {'snapshots': snaps})


def handle_proxmox_snapshot_action() -> None:
    """``POST /api/proxmox/snapshot`` — create / rollback / delete a
    snapshot.

    Body: {"type": "qemu"|"lxc", "vmid": N, "action": "...",
           "name": "...", "description": "..."}

    `rollback` and `delete` are destructive; the UI gates them behind
    confirmation dialogs (rollback requires typing the guest name).
    The action set is validated here regardless.
    """
    require_admin_auth()
    body = get_json_body() or {}
    guest_type = body.get('type')
    action = body.get('action')
    name = (body.get('name') or '').strip()
    if guest_type not in ('qemu', 'lxc'):
        respond(400, {'error': 'type must be qemu or lxc'})
        return
    try:
        vmid = int(body.get('vmid'))
    except (ValueError, TypeError):
        respond(400, {'error': 'numeric vmid required'})
        return
    if action not in ('create', 'rollback', 'delete'):
        respond(400, {'error': 'action must be create, rollback or delete'})
        return
    cfg = load(CONFIG_FILE)
    pc = proxmox_client.config_from(cfg)
    if not (pc['enabled'] and proxmox_client.is_configured(pc)):
        respond(400, {'error': 'Proxmox is not configured.'})
        return
    try:
        if action == 'create':
            result = proxmox_client.create_snapshot(
                pc, guest_type, vmid, name, body.get('description', '') or '')
        elif action == 'rollback':
            result = proxmox_client.rollback_snapshot(pc, guest_type, vmid, name)
        else:
            result = proxmox_client.delete_snapshot(pc, guest_type, vmid, name)
    except proxmox_client.ProxmoxError as e:
        code = 400 if 'invalid' in str(e).lower() else 502
        respond(code, {'error': str(e)})
        return
    try:
        _record_fleet_event('proxmox_action', {
            'guest_type': guest_type, 'vmid': vmid,
            'action': f'snapshot_{action}',
        })
    except Exception:
        pass
    respond(200, result)


def handle_containers_overview() -> None:
    """``GET /api/containers`` — fleet-wide container overview.

    Returns one entry per device that has reported containers, with
    summary counts. The Containers page uses this for the "all
    containers across the fleet" landing view.

    v1.11.4: each entry now carries an ``is_stale`` flag, set when the
    device's last container report is older than the configured TTL
    (``container_stale_ttl``, default 900s). The UI uses this to badge
    stale rows.
    """
    require_auth()
    devices = load(DEVICES_FILE)
    store = load(CONTAINERS_FILE)
    ttl = get_container_stale_ttl()
    now = int(time.time())
    out = []
    for dev_id, entry in store.items():
        if dev_id not in devices:
            continue
        items = entry.get('items', []) if isinstance(entry, dict) else []
        ts = entry.get('ts', 0) if isinstance(entry, dict) else 0
        out.append({
            'device_id':   dev_id,
            'name':        devices[dev_id].get('name', dev_id),
            'os':          devices[dev_id].get('os', ''),
            'reported_at': ts,
            'is_stale':    containers_mod.is_stale(ts, now, ttl),
            'summary':     containers_mod.summarise(items),
        })
    out.sort(key=lambda r: r['name'].lower())
    respond(200, out)


def handle_device_containers_clear(dev_id: str) -> None:
    """``DELETE /api/devices/{id}/containers`` — clear stored container data.

    v1.11.4: useful in two scenarios:

    1. **Decommissioning a host** but you want to keep the device record
       around (e.g. agentless conversion). The container entry would
       otherwise sit forever in ``containers.json`` and keep showing up
       with whatever its last-known list was.
    2. **You ran ``docker rm`` on a container and don't want to wait the
       ~5 minutes for the next heartbeat.** Clearing forces the
       Containers page to show "no data" until the next report rebuilds
       the list with current state.

    This is *not* a way to suppress webhooks — the
    ``container_stopped`` / ``container_restarting`` webhooks have
    already fired by the time you'd hit this. It's purely a cosmetic /
    cleanup operation against the stored snapshot. If a live agent is
    still polling, the next heartbeat will repopulate the list within
    one ``CONTAINER_CHECK_EVERY`` window.

    Also clears the ``containers_stale_notified`` flag so the next
    staleness can fire a fresh webhook (without this you'd have to
    wait for a fresh report → stale again before re-firing).

    Args:
        dev_id: Enrolled device ID.
    """
    actor = require_admin_auth()
    if method() != 'DELETE':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})

    store = load(CONTAINERS_FILE)
    had_entry = dev_id in store
    store.pop(dev_id, None)
    save(CONTAINERS_FILE, store)

    # Also clear any lingering stale-notified flag so the next time this
    # device goes stale we generate a fresh webhook rather than thinking
    # we already notified.
    cfg = load(CONFIG_FILE)
    notified = cfg.get('containers_stale_notified') or {}
    if isinstance(notified, dict) and dev_id in notified:
        notified.pop(dev_id, None)
        cfg['containers_stale_notified'] = notified
        save(CONFIG_FILE, cfg)

    audit_log(actor, 'containers_clear',
              f'cleared container data for {dev_id} (had_entry={had_entry})')
    respond(200, {'ok': True, 'cleared': had_entry})


# ─── v2.1.0: docker-compose dropdown ────────────────────────────────────────
#
# GET    /api/devices/<id>/compose          — list reported compose projects
# POST   /api/devices/<id>/compose/action   — queue compose:<action>:<dir>
#
# Projects are reported by the agent in its heartbeat (see
# get_compose_projects in client/remotepower-agent). We never read directly
# from a path the operator typed — the action endpoint verifies the
# requested `dir` is one of the paths the agent itself reported, so a
# stale or malicious admin POST can't ask the agent to run compose against
# arbitrary directories.

def handle_device_compose_list(dev_id):
    """List the compose projects this device reported in its heartbeat."""
    require_auth()
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    devices = load(DEVICES_FILE)
    dev = devices.get(dev_id)
    if not dev:
        respond(404, {'error': 'Device not found'})
    projects = dev.get('compose_projects', []) or []
    respond(200, {
        'device_id': dev_id,
        'projects':  projects,
        'reported_at': dev.get('compose_projects_ts', 0),
        # If docker is installed but no projects were found, the agent
        # still reports an empty list — letting the UI distinguish "we
        # checked, none found" from "we never checked, no data".
        'docker_seen': bool(dev.get('compose_projects_ts')),
    })


def handle_device_compose_action(dev_id):
    """Queue a compose:<action>:<dir> command after validating both halves.

    The `dir` is required to be one of the paths the agent itself reported.
    This is the critical security boundary: even an admin token can't ask
    a device to run docker compose against /etc/passwd or some other
    arbitrary directory. The action is restricted to the small fixed set
    COMPOSE_ALLOWED_ACTIONS (also enforced agent-side as belt-and-braces).
    """
    actor = require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    body = get_json_body()
    action = str(body.get('action', '')).strip().lower()
    project_dir = str(body.get('dir', '')).strip()

    if action not in COMPOSE_ALLOWED_ACTIONS:
        respond(400, {'error': f'action must be one of {list(COMPOSE_ALLOWED_ACTIONS)}'})
    if not project_dir or len(project_dir) > MAX_COMPOSE_PATH_LEN:
        respond(400, {'error': 'dir required'})

    devices = load(DEVICES_FILE)
    dev = devices.get(dev_id)
    if not dev:
        respond(404, {'error': 'Device not found'})
    if dev.get('agentless'):
        respond(400, {'error': 'cannot run compose on agentless device'})

    # Path must match a project the agent reported. This is *the* security
    # check — if it weren't here, a stolen admin token could ask any
    # device for `compose:up:/etc` (which the agent would reject anyway,
    # but defence-in-depth: belt-and-braces).
    reported = dev.get('compose_projects', []) or []
    reported_dirs = {p.get('dir') for p in reported if isinstance(p, dict)}
    if project_dir not in reported_dirs:
        respond(400, {
            'error': 'dir not in this device\'s reported compose projects '
                     '(refresh the listing if you just added the project)'
        })

    # Queue the command. The agent re-validates everything when it dequeues.
    cmd_payload = f'compose:{action}:{project_dir}'
    cmds = load(CMDS_FILE)
    cmds.setdefault(dev_id, [])
    if cmd_payload not in cmds[dev_id]:
        cmds[dev_id].append(cmd_payload)
    save(CMDS_FILE, cmds)

    log_command(actor, dev_id, dev.get('name', dev_id), cmd_payload)
    audit_log(actor, 'compose_action',
              detail=f'device={dev_id} action={action} dir={project_dir!r}')
    fire_webhook('command_queued', {
        'device_id': dev_id, 'name': dev.get('name', dev_id),
        'command':   cmd_payload, 'actor': actor,
    })
    respond(200, {'ok': True, 'queued': cmd_payload})


# v2.1.1: per-container action endpoint. Matches compose semantics:
# action is allowlisted, container ID is validated against the agent's
# reported listing so the server can't ask the agent to act on an
# arbitrary container. Agent re-validates everything when it dequeues.
CONTAINER_ACTION_ALLOWED = ('start', 'stop', 'restart', 'pause', 'unpause', 'logs')


def handle_device_container_action(dev_id):
    actor = require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    body = get_json_body()
    action = str(body.get('action', '')).strip().lower()
    container_id = str(body.get('container_id', '')).strip()
    runtime = str(body.get('runtime', '')).strip().lower() or 'docker'

    if action not in CONTAINER_ACTION_ALLOWED:
        respond(400, {'error': f'action must be one of {list(CONTAINER_ACTION_ALLOWED)}'})
    if runtime not in ('docker', 'podman'):
        respond(400, {'error': 'runtime must be docker or podman'})
    # Tight ID validation here too — defence in depth even though agent
    # re-validates. Blocks anyone shoving a path-traversal or argv
    # injection through the dashboard before the command ever reaches
    # the wire.
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$', container_id):
        respond(400, {'error': 'invalid container_id'})

    devices = load(DEVICES_FILE)
    dev = devices.get(dev_id)
    if not dev:
        respond(404, {'error': 'Device not found'})
    if dev.get('agentless'):
        respond(400, {'error': 'cannot run container actions on agentless device'})

    # Verify the container ID matches one this device reported in its
    # last heartbeat. Same security boundary as compose: even an admin
    # token can't ask any device to act on arbitrary container IDs.
    store = load(CONTAINERS_FILE)
    reported = (store.get(dev_id) or {}).get('items', []) or []
    reported_ids = set()
    for c in reported:
        if isinstance(c, dict):
            cid = c.get('id') or c.get('container_id') or c.get('name')
            if cid:
                reported_ids.add(str(cid))
            # Container IDs are reported as 12-char short IDs OR full
            # 64-char IDs depending on runtime. Accept either by also
            # adding any longer ID's 12-char prefix.
            full = c.get('id_full') or c.get('full_id')
            if full and isinstance(full, str):
                reported_ids.add(full)
                reported_ids.add(full[:12])
    if container_id not in reported_ids:
        respond(400, {'error':
                      'container_id not in this device\'s reported container '
                      'list (refresh the listing if you just started it)'})

    cmd_payload = f'container:{runtime}:{action}:{container_id}'
    cmds = load(CMDS_FILE)
    cmds.setdefault(dev_id, [])
    if cmd_payload not in cmds[dev_id]:
        cmds[dev_id].append(cmd_payload)
    save(CMDS_FILE, cmds)

    log_command(actor, dev_id, dev.get('name', dev_id), cmd_payload)
    audit_log(actor, 'container_action',
              detail=f'device={dev_id} runtime={runtime} action={action} '
                     f'container={container_id!r}')
    fire_webhook('command_queued', {
        'device_id': dev_id, 'name': dev.get('name', dev_id),
        'command':   cmd_payload, 'actor': actor,
    })
    respond(200, {'ok': True, 'queued': cmd_payload})


# ─── v1.11.0: TLS / DNS expiry monitor ──────────────────────────────────────


def _tls_targets() -> dict:
    """Load the TLS watchlist."""
    s = load(TLS_TARGETS_FILE)
    return s if isinstance(s, dict) else {}


def _tls_results() -> dict:
    """Load the last-probe results store."""
    s = load(TLS_RESULTS_FILE)
    return s if isinstance(s, dict) else {}


def handle_tls_list() -> None:
    """``GET /api/tls/targets`` — list watchlist + last results.

    Joins the watchlist with the last probe result for each entry so
    the UI can render in one round-trip.
    """
    require_auth()
    targets = _tls_targets()
    results = _tls_results()
    out = []
    for tid, t in targets.items():
        if not isinstance(t, dict):
            continue
        r = results.get(tid) or {}
        warn = int(t.get('warn_days', TLS_DEFAULT_WARN_DAYS))
        crit = int(t.get('crit_days', TLS_DEFAULT_CRIT_DAYS))
        out.append({
            'id':              tid,
            'host':            t.get('host', ''),
            'port':            int(t.get('port', 443)),
            'label':           t.get('label', ''),
            'warn_days':       warn,
            'crit_days':       crit,
            # v1.11.2: connect override + DANE config + DANE result fields
            'connect_address': t.get('connect_address', ''),
            'dane_check':      bool(t.get('dane_check', False)),
            # v1.11.3: STARTTLS protocol selection
            'starttls':        t.get('starttls', 'none'),
            'last_check':      r.get('checked_at', 0),
            'expires_at':      r.get('expires_at', 0),
            'days_left':       tls_monitor.days_until_expiry(r) if r else 0,
            'status':          tls_monitor.status_for(r, warn, crit) if r else 'unknown',
            'addresses':       r.get('addresses', []),
            'issuer':          r.get('issuer', ''),
            'subject':         r.get('subject', ''),
            'san':             r.get('san', []),
            'hostname_match':  r.get('hostname_match'),
            'dns_error':       r.get('dns_error', ''),
            'tls_error':       r.get('tls_error', ''),
            'verify_error':    r.get('verify_error', ''),
            'dane_status':     r.get('dane_status', 'not_checked'),
            'dane_records':    r.get('dane_records', []),
            'dane_error':      r.get('dane_error', ''),
        })
    out.sort(key=lambda x: (x['status'] != 'critical',
                            x['status'] != 'warning',
                            (x['host'] or '').lower()))
    respond(200, out)


def handle_tls_add() -> None:
    """``POST /api/tls/targets`` — add a watchlist entry. Admin only.

    Body: ``{host, port?, label?, warn_days?, crit_days?}``.
    """
    actor = require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    parsed = tls_monitor.parse_target(body)
    if parsed is None:
        respond(400, {'error': 'invalid target — host required, port 1-65535'})
    targets = _tls_targets()
    if len(targets) >= MAX_TLS_TARGETS:
        respond(400, {'error': f'max {MAX_TLS_TARGETS} TLS targets'})
    new_id = 'tls_' + secrets.token_hex(6)
    targets[new_id] = parsed
    save(TLS_TARGETS_FILE, targets)
    audit_log(actor, 'tls_target_add',
              detail=f'host={parsed["host"]}:{parsed["port"]}')
    respond(200, {'ok': True, 'id': new_id})


def handle_tls_delete(target_id: str) -> None:
    """``DELETE /api/tls/targets/{id}`` — remove from watchlist."""
    actor = require_admin_auth()
    if not target_id.startswith('tls_'):
        respond(404, {'error': 'target not found'})
    targets = _tls_targets()
    if target_id not in targets:
        respond(404, {'error': 'target not found'})
    host = targets[target_id].get('host', '?')
    del targets[target_id]
    save(TLS_TARGETS_FILE, targets)
    # Also clean the result if present
    results = _tls_results()
    results.pop(target_id, None)
    save(TLS_RESULTS_FILE, results)
    audit_log(actor, 'tls_target_delete', detail=f'host={host}')
    respond(200, {'ok': True})


def handle_tls_scan() -> None:
    """``POST /api/tls/scan`` — probe all targets now (synchronous).

    This is intentionally synchronous so the UI can render the fresh
    results immediately. The cron runner uses the same code path. Each
    probe has a hard 5+5s timeout, so even with 200 targets the worst
    case is ~30 minutes; in practice it's seconds.

    Admin only because probing makes outbound network requests from
    the server, and someone with viewer access shouldn't be able to
    trigger 200 outbound connections.
    """
    actor = require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    targets = _tls_targets()
    results = tls_monitor.probe_all(targets)
    save(TLS_RESULTS_FILE, results)
    audit_log(actor, 'tls_scan', detail=f'targets={len(targets)}')
    respond(200, {'ok': True, 'scanned': len(results)})


# ─── v1.11.0: agentless devices + network map ────────────────────────────────


# Allowed device types — used for the icon mapping on the network map and
# for sanity checks at the API layer. Free-text would be tempting but limits
# the icon switch in the UI; if you need a new type add it here and to the
# UI's icon picker.
AGENTLESS_DEVICE_TYPES = (
    'switch', 'router', 'firewall', 'access_point', 'ap',
    'printer', 'camera', 'ipmi', 'ups', 'pdu', 'nas',
    'iot', 'smart_plug', 'phone', 'other',
)


def handle_agentless_create() -> None:
    """``POST /api/devices/agentless`` — create a manual (no-agent) device.

    Body: ``{name, hostname?, ip?, mac?, os?, device_type?, group?, tags?,
    notes?, connected_to?, manual_status?}``.

    The created record gets ``agentless: True`` so it bypasses the heartbeat-
    based online/offline logic and shows whatever ``manual_status`` (default
    True) says it shows. Otherwise it's a regular device — same audit log,
    same CMDB metadata, same vault credentials.
    """
    actor = require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body()

    name = _sanitize_str(body.get('name', ''), 64, allow_empty=False)
    if not name:
        respond(400, {'error': 'name required'})

    hostname     = _sanitize_str(body.get('hostname', ''), 128, allow_empty=True) or ''
    ip           = _sanitize_str(body.get('ip', ''), 64, allow_empty=True) or ''
    mac          = _sanitize_str(body.get('mac', ''), 32, allow_empty=True) or ''
    os_str       = _sanitize_str(body.get('os', ''), 64, allow_empty=True) or ''
    group        = _sanitize_str(body.get('group', ''), 64, allow_empty=True) or ''
    notes        = _sanitize_str(body.get('notes', ''), 1024, allow_empty=True) or ''
    connected_to = _sanitize_str(body.get('connected_to', ''), 64, allow_empty=True) or ''

    dtype = str(body.get('device_type', '')).strip().lower()
    if dtype and dtype not in AGENTLESS_DEVICE_TYPES:
        respond(400, {'error': f'device_type must be one of {",".join(AGENTLESS_DEVICE_TYPES)}'})

    tags = body.get('tags') or []
    if not isinstance(tags, list):
        respond(400, {'error': 'tags must be a list'})
    tags = [_sanitize_str(t, 32, allow_empty=False) for t in tags[:20]]
    tags = [t for t in tags if t]

    devices = load(DEVICES_FILE)
    if connected_to and connected_to not in devices:
        respond(400, {'error': f'connected_to: device {connected_to} not found'})

    new_id = 'al_' + secrets.token_hex(6)
    devices[new_id] = {
        'name':          name,
        'hostname':      hostname,
        'ip':            ip,
        'mac':           mac,
        'os':            os_str,
        'group':         group,
        'tags':          tags,
        'notes':         notes,
        'device_type':   dtype,
        'connected_to':  connected_to,
        'manual_status': bool(body.get('manual_status', True)),
        'agentless':     True,
        # No token — agentless devices can't post heartbeats
        'token':         '',
        'last_seen':     0,
        'enrolled':      int(time.time()),
        'monitored':     True,
        'sysinfo':       {},
    }
    save(DEVICES_FILE, devices)
    audit_log(actor, 'agentless_create',
              detail=f'id={new_id} name={name} type={dtype}')
    respond(200, {'ok': True, 'id': new_id})


def handle_device_connected_to(dev_id: str) -> None:
    """``PUT /api/devices/{id}/connected-to`` — set the upstream link.

    The ``connected_to`` field is the device-id this one connects to
    upstream — typically a switch or AP. Used by the network map to
    render edges.

    Body: ``{connected_to: <device_id> | ''}``. Empty string clears it.
    """
    actor = require_admin_auth()
    if method() != 'PUT':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    body = get_json_body()
    target = _sanitize_str(body.get('connected_to', ''), 64, allow_empty=True) or ''
    if target == dev_id:
        respond(400, {'error': 'a device cannot connect to itself'})
    if target and target not in devices:
        respond(400, {'error': f'device {target} not found'})
    devices[dev_id]['connected_to'] = target
    save(DEVICES_FILE, devices)
    audit_log(actor, 'device_connected_to', detail=f'{dev_id} → {target or "(cleared)"}')
    respond(200, {'ok': True})


def handle_network_map() -> None:
    """``GET /api/network-map`` — nodes, edges, tunnels, positions.

    Returns a graph-friendly shape that the UI renders directly:

    ::

        {
          "nodes": [
            {"id": ..., "name": ..., "type": ..., "online": ...,
             "agentless": ..., "pos_x": <int|null>, "pos_y": <int|null>},
            ...
          ],
          "edges": [
            {"from": "<device_id>", "to": "<device_id>"},
            ...
          ],
          "tunnels": [
            {"id": "tun_<hex>", "endpoints": ["<device_id>", "<device_id>"]},
            ...
          ]
        }

    Edges follow ``connected_to``: physical / wired link, parent-child.
    Tunnels are peer relationships — order of endpoints isn't meaningful.
    Edges and tunnels referencing non-existent devices are silently dropped
    (a device may have been deleted since the link/tunnel was set).
    """
    require_auth()
    devices = load(DEVICES_FILE)
    now = int(time.time())
    nodes = []
    for dev_id, dev in devices.items():
        agentless = bool(dev.get('agentless', False))
        if agentless:
            online = bool(dev.get('manual_status', True))
        else:
            online = (now - dev.get('last_seen', 0)) < get_online_ttl()
        # Position fields — None means "no manual position set, fall back
        # to the auto layout in the renderer".
        px = dev.get('pos_x')
        py = dev.get('pos_y')
        nodes.append({
            'id':        dev_id,
            'name':      dev.get('name', dev_id),
            'hostname':  dev.get('hostname', ''),
            'ip':        dev.get('ip', ''),
            'os':        dev.get('os', ''),
            'type':      dev.get('device_type', '') or ('host' if not agentless else 'other'),
            'group':     dev.get('group', ''),
            'agentless': agentless,
            'online':    online,
            'pos_x':     int(px) if isinstance(px, (int, float)) else None,
            'pos_y':     int(py) if isinstance(py, (int, float)) else None,
        })
    edges = []
    for dev_id, dev in devices.items():
        target = dev.get('connected_to', '')
        if target and target in devices:
            edges.append({'from': dev_id, 'to': target})
    nodes.sort(key=lambda n: (n['type'], n['name'].lower()))

    # v1.11.1: tunnels (peer relationships, second-class edges)
    tunnels_raw = load(TUNNELS_FILE)
    tunnels: list[dict] = []
    if isinstance(tunnels_raw, dict):
        for tid, t in tunnels_raw.items():
            if not isinstance(t, dict):
                continue
            ends = t.get('endpoints') or []
            if not (isinstance(ends, list) and len(ends) == 2):
                continue
            if ends[0] not in devices or ends[1] not in devices:
                continue
            tunnels.append({'id': tid, 'endpoints': [ends[0], ends[1]]})

    respond(200, {'nodes': nodes, 'edges': edges, 'tunnels': tunnels})


# ── v1.11.1: persisted node positions ─────────────────────────────────────────


def handle_network_positions() -> None:
    """``PUT /api/network-map/positions`` — batch-save node positions.

    Body: ``{"positions": [{"id": "<device_id>", "x": <int>, "y": <int>}, ...]}``.

    Positions are stored on each device's record (``pos_x``, ``pos_y``)
    rather than in a separate file because they're inherently tied to
    the device and disappear when the device is deleted. Sending ``null``
    for either coordinate clears that field, returning the node to the
    auto-layout.

    Admin-only because positions are shared across all users — letting
    viewers move things around would be confusing for everyone else.
    """
    actor = require_admin_auth()
    if method() != 'PUT':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    positions = body.get('positions')
    if not isinstance(positions, list):
        respond(400, {'error': 'positions must be a list'})
    if len(positions) > 1000:
        respond(400, {'error': 'too many positions in one batch'})
    devices = load(DEVICES_FILE)
    changed = 0
    for p in positions:
        if not isinstance(p, dict):
            continue
        dev_id = p.get('id')
        if not dev_id or dev_id not in devices:
            continue
        x, y = p.get('x'), p.get('y')
        # Allow null to clear, otherwise must be numeric and in a sane range.
        # The render-side SVG defaults to a few hundred pixels each side so
        # millions are wasted; cap defensively.
        if x is None and y is None:
            devices[dev_id].pop('pos_x', None)
            devices[dev_id].pop('pos_y', None)
        else:
            try:
                xi = int(x); yi = int(y)
            except (TypeError, ValueError):
                continue
            if not (-10000 <= xi <= 10000 and -10000 <= yi <= 10000):
                continue
            devices[dev_id]['pos_x'] = xi
            devices[dev_id]['pos_y'] = yi
        changed += 1
    save(DEVICES_FILE, devices)
    audit_log(actor, 'network_positions_save', detail=f'count={changed}')
    respond(200, {'ok': True, 'updated': changed})


# ── v1.11.1: VPN-style tunnels (peer links between devices) ──────────────────


def _tunnels_load() -> dict:
    """Load the tunnels store, normalised to a dict (empty on bad data)."""
    s = load(TUNNELS_FILE)
    return s if isinstance(s, dict) else {}


def handle_tunnels_list() -> None:
    """``GET /api/network-map/tunnels`` — list all tunnels.

    Tunnels referencing devices that no longer exist are filtered out
    so the UI never has to deal with dangling endpoints.
    """
    require_auth()
    devices = load(DEVICES_FILE)
    raw = _tunnels_load()
    out = []
    for tid, t in raw.items():
        if not isinstance(t, dict):
            continue
        ends = t.get('endpoints') or []
        if not (isinstance(ends, list) and len(ends) == 2):
            continue
        if ends[0] not in devices or ends[1] not in devices:
            continue
        out.append({'id': tid, 'endpoints': [ends[0], ends[1]]})
    out.sort(key=lambda x: (x['endpoints'][0], x['endpoints'][1]))
    respond(200, out)


def handle_tunnel_add() -> None:
    """``POST /api/network-map/tunnels`` — create a tunnel between two devices.

    Body: ``{"endpoints": ["<device_id_a>", "<device_id_b>"]}``.

    Tunnels are peer relationships, so the order of endpoints isn't
    meaningful — we normalise to ``[min, max]`` so duplicate-detection
    is symmetric. A tunnel from A to B and a tunnel from B to A are the
    same tunnel and the second create attempt returns 409.
    """
    actor = require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    ends = body.get('endpoints') or []
    if not (isinstance(ends, list) and len(ends) == 2):
        respond(400, {'error': 'endpoints must be a list of exactly 2 device IDs'})
    a, b = ends
    if not isinstance(a, str) or not isinstance(b, str) or not a or not b:
        respond(400, {'error': 'endpoints must be two non-empty strings'})
    if a == b:
        respond(400, {'error': 'a tunnel cannot have the same device on both ends'})
    devices = load(DEVICES_FILE)
    for ep in (a, b):
        if ep not in devices:
            respond(400, {'error': f'device {ep} not found'})
    # Normalise to canonical order so duplicate-detection works regardless
    # of which end the user clicked first.
    canonical = sorted([a, b])
    raw = _tunnels_load()
    if len(raw) >= MAX_TUNNELS:
        respond(400, {'error': f'max {MAX_TUNNELS} tunnels'})
    for t in raw.values():
        existing = sorted(t.get('endpoints') or [])
        if existing == canonical:
            respond(409, {'error': 'tunnel already exists between these devices'})
    new_id = 'tun_' + secrets.token_hex(6)
    raw[new_id] = {'endpoints': canonical, 'created_at': int(time.time()), 'created_by': actor}
    save(TUNNELS_FILE, raw)
    audit_log(actor, 'tunnel_add', detail=f'{canonical[0]} ↔ {canonical[1]}')
    respond(200, {'ok': True, 'id': new_id, 'endpoints': canonical})


def handle_tunnel_delete(tunnel_id: str) -> None:
    """``DELETE /api/network-map/tunnels/{id}`` — remove a tunnel."""
    actor = require_admin_auth()
    if not tunnel_id.startswith('tun_'):
        respond(404, {'error': 'tunnel not found'})
    raw = _tunnels_load()
    if tunnel_id not in raw:
        respond(404, {'error': 'tunnel not found'})
    ends = raw[tunnel_id].get('endpoints') or ['?', '?']
    del raw[tunnel_id]
    save(TUNNELS_FILE, raw)
    audit_log(actor, 'tunnel_delete', detail=f'{ends[0]} ↔ {ends[1]}')
    respond(200, {'ok': True})


# ─── v1.11.2: shared link dashboard ───────────────────────────────────────────
#
# Simple bookmark dashboard. Global, not per-user — the "shared admin"
# convention used everywhere else in the project. Stored as a flat dict
# keyed by ``lnk_<hex>`` for stable IDs across renames.


def _links_load() -> dict:
    """Return the {link_id -> link} mapping, always a dict."""
    s = load(LINKS_FILE)
    return s if isinstance(s, dict) else {}


def _validate_link_url(raw) -> 'str | None':
    """Validate a candidate URL.

    Args:
        raw: User-supplied URL string. Anything else returns ``None``.

    Returns:
        Cleaned URL on success, ``None`` if invalid.

    Rules:
        - http:// or https:// only (no javascript:, file://, ftp:// etc.)
        - max 1024 chars
        - no whitespace or control characters anywhere in the URL
        - no quote characters that would break attribute interpolation
    """
    if not isinstance(raw, str):
        return None
    url = raw.strip()
    if not url or len(url) > MAX_LINK_URL_LEN:
        return None
    if not (url.startswith('http://') or url.startswith('https://')):
        return None
    if any(c.isspace() or ord(c) < 0x20 for c in url):
        return None
    # Don't allow quote chars; they get HTML-escaped in the renderer but
    # belt-and-braces — a clean URL never contains them.
    if any(c in url for c in ('"', "'", '<', '>')):
        return None
    return url


def _normalize_link(payload: dict) -> 'tuple[dict | None, str]':
    """Validate a request body into a clean link record.

    Returns a tuple of ``(record, error)`` — exactly one will be truthy.
    Used by both the create and update handlers so they don't have to
    duplicate field validation.
    """
    if not isinstance(payload, dict):
        return None, 'body must be a JSON object'
    title = _sanitize_str(payload.get('title', ''), MAX_LINK_TITLE_LEN, allow_empty=False)
    if not title:
        return None, 'title required'
    url = _validate_link_url(payload.get('url'))
    if url is None:
        return None, 'url must be http(s)://… (max 1024 chars, no whitespace/quotes)'
    description = _sanitize_str(payload.get('description', ''),
                                MAX_LINK_DESCRIPTION_LEN, allow_empty=True) or ''
    category = _sanitize_str(payload.get('category', ''),
                             MAX_LINK_CATEGORY_LEN, allow_empty=True) or LINK_DEFAULT_CATEGORY
    scope = str(payload.get('scope', 'external')).strip().lower()
    if scope not in LINK_SCOPES:
        return None, f'scope must be one of {",".join(LINK_SCOPES)}'
    return {
        'title':       title,
        'url':         url,
        'description': description,
        'category':    category,
        'scope':       scope,
    }, ''


def handle_links_list() -> None:
    """``GET /api/links`` — list all links plus the distinct category set.

    Returns one entry per link, sorted by category then title (case-insensitive).
    The frontend uses the category list to populate a datalist for the
    "+ Add link" modal — same autocomplete pattern as ``server_function``.
    """
    require_auth()
    store = _links_load()
    links = []
    cats = set()
    for lid, l in store.items():
        if not isinstance(l, dict):
            continue
        cats.add(l.get('category') or LINK_DEFAULT_CATEGORY)
        links.append({
            'id':          lid,
            'title':       l.get('title', ''),
            'url':         l.get('url', ''),
            'description': l.get('description', ''),
            'category':    l.get('category') or LINK_DEFAULT_CATEGORY,
            'scope':       l.get('scope', 'external'),
            'created_by':  l.get('created_by', ''),
            'created_at':  l.get('created_at', 0),
        })
    links.sort(key=lambda x: (x['category'].lower(), x['title'].lower()))
    respond(200, {'links': links, 'categories': sorted(cats, key=str.lower)})


def handle_link_add() -> None:
    """``POST /api/links`` — admin only.

    Body: ``{title, url, description?, category?, scope}``. Returns the
    new link's ID for the frontend to use in subsequent edits.
    """
    actor = require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    record, err = _normalize_link(body)
    if err:
        respond(400, {'error': err})
    store = _links_load()
    if len(store) >= MAX_LINKS:
        respond(400, {'error': f'max {MAX_LINKS} links'})
    new_id = 'lnk_' + secrets.token_hex(6)
    record['created_by'] = actor
    record['created_at'] = int(time.time())
    store[new_id] = record
    save(LINKS_FILE, store)
    audit_log(actor, 'link_add',
              detail=f'id={new_id} title={record["title"][:40]} scope={record["scope"]}')
    respond(200, {'ok': True, 'id': new_id})


def handle_link_update(link_id: str) -> None:
    """``PUT /api/links/{id}`` — replace a link's contents.

    All fields are required (it's a PUT, not a PATCH). The link's
    ``created_by`` and ``created_at`` are preserved across the update.
    """
    actor = require_admin_auth()
    if method() != 'PUT':
        respond(405, {'error': 'Method not allowed'})
    if not link_id.startswith('lnk_'):
        respond(404, {'error': 'link not found'})
    store = _links_load()
    if link_id not in store:
        respond(404, {'error': 'link not found'})
    body = get_json_body()
    record, err = _normalize_link(body)
    if err:
        respond(400, {'error': err})
    # Preserve original creation metadata
    record['created_by'] = store[link_id].get('created_by', '')
    record['created_at'] = store[link_id].get('created_at', 0)
    record['updated_by'] = actor
    record['updated_at'] = int(time.time())
    store[link_id] = record
    save(LINKS_FILE, store)
    audit_log(actor, 'link_update',
              detail=f'id={link_id} title={record["title"][:40]}')
    respond(200, {'ok': True})


def handle_link_delete(link_id: str) -> None:
    """``DELETE /api/links/{id}`` — remove a link."""
    actor = require_admin_auth()
    if not link_id.startswith('lnk_'):
        respond(404, {'error': 'link not found'})
    store = _links_load()
    if link_id not in store:
        respond(404, {'error': 'link not found'})
    title = store[link_id].get('title', '?')
    del store[link_id]
    save(LINKS_FILE, store)
    audit_log(actor, 'link_delete', detail=f'id={link_id} title={title[:40]}')
    respond(200, {'ok': True})


def handle_device_allowlist(dev_id):
    require_admin_auth()
    if not _validate_id(dev_id): respond(404, {'error': 'Device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices: respond(404, {'error': 'Device not found'})
    if method() == 'GET':
        respond(200, {'allowed_commands': devices[dev_id].get('allowed_commands', [])})
    if method() == 'POST':
        body = get_json_body(); cmds_input = body.get('allowed_commands', [])
        if not isinstance(cmds_input, list): respond(400, {'error': 'allowed_commands must be a list'})
        cmds_clean = [str(c)[:512] for c in cmds_input[:50] if str(c).strip()]
        devices[dev_id]['allowed_commands'] = cmds_clean
        save(DEVICES_FILE, devices)
        respond(200, {'ok': True, 'allowed_commands': cmds_clean})
    respond(405, {'error': 'Method not allowed'})


def handle_cmd_library_list():
    require_auth()
    lib = load(CMD_LIBRARY_FILE)
    respond(200, lib.get('snippets', []))


def handle_cmd_library_add():
    require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    name = _sanitize_str(body.get('name', ''), 64)
    cmd  = _sanitize_str(body.get('cmd', ''), 512)
    desc = _sanitize_str(body.get('description', ''), 256)
    if not name or not cmd: respond(400, {'error': 'name and cmd required'})
    lib = load(CMD_LIBRARY_FILE); snippets = lib.get('snippets', [])
    if len(snippets) >= 200: respond(400, {'error': 'Library limit reached (max 200 snippets)'})
    snippet = {'id': secrets.token_hex(6), 'name': name, 'cmd': cmd,
               'description': desc, 'created': int(time.time())}
    snippets.append(snippet); lib['snippets'] = snippets; save(CMD_LIBRARY_FILE, lib)
    respond(201, {'ok': True, 'snippet': snippet})


def handle_cmd_library_delete(snippet_id):
    require_admin_auth()
    if method() != 'DELETE': respond(405, {'error': 'Method not allowed'})
    if not _validate_id(snippet_id): respond(404, {'error': 'Snippet not found'})
    lib = load(CMD_LIBRARY_FILE)
    snippets = [s for s in lib.get('snippets', []) if s['id'] != snippet_id]
    if len(snippets) == len(lib.get('snippets', [])): respond(404, {'error': 'Snippet not found'})
    lib['snippets'] = snippets; save(CMD_LIBRARY_FILE, lib)
    respond(200, {'ok': True})


# ── v2.1.0: Multi-line script library ─────────────────────────────────────────
#
# Saved bash scripts (CRUD + dry-run) live in scripts.json. The execution
# path reuses the existing `exec:` command channel — when an operator runs a
# script, the server builds an `exec:<body>` and queues it via the normal
# command pipeline. So the agent doesn't need any new capability: scripts
# are just multi-line exec payloads with a name attached.
#
# Security posture:
#   * Admin-only (same as exec).
#   * `bash -n` syntax check on save and as part of dry-run (catches
#     unterminated quotes, missing fi/done before they hit production).
#   * Dangerous-command heuristic flags rm -rf /, fork bombs, dd to block
#     devices, etc. The heuristic is advisory — admins can save a script
#     containing dangerous commands (they're admins, they get to make
#     that decision) but the dry-run surfaces the matches and the dispatch
#     endpoint forces an explicit ack via {"confirm_dangerous": true}.
#   * Body size capped at MAX_SCRIPT_BODY (64 KB), well under MAX_CMD_OUT_BYTES.
#   * Per-device allowlist is *not* applied to scripts. Allowlist matches
#     exact one-liners; arbitrary scripts wouldn't ever match. If an
#     operator wants to lock down a device, they shouldn't let scripts
#     reach it — that's a future "per-device script-policy" feature.

# Patterns that strongly suggest the script would do something dangerous.
# All matched case-insensitively. False positives are acceptable here —
# this is a confirmation prompt, not a block. A name like "wipe-disk.sh"
# triggers nothing on its own; the body has to contain the regex.
_DANGEROUS_PATTERNS = [
    (r'\brm\s+(-[rRf]+\s+)+/(\s|$)',     'rm -rf /'),
    (r'\brm\s+(-[rRf]+\s+)+/\*',         'rm -rf /*'),
    # Long-flag form: `rm -rf --no-preserve-root /` is the standard
    # incantation to defeat GNU rm's built-in safety check, so it's
    # specifically worth flagging.
    (r'\brm\s+[^\n]*--no-preserve-root[^\n]*\s+/(\s|$)',
                                          'rm --no-preserve-root /'),
    (r':\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:', 'fork bomb (:(){ :|:& };:)'),
    (r'\bdd\s+[^\n]*of=/dev/(sd|nvme|xvd|vd|hd)[a-z]', 'dd writing to a block device'),
    (r'\bmkfs(\.\w+)?\s+/dev/',          'mkfs against a raw device'),
    (r'\bchmod\s+(-R\s+)?[0-9]+\s+/(\s|$)', 'chmod against /'),
    (r'\bchown\s+-R\s+\S+\s+/(\s|$)',    'chown -R against /'),
    (r'>\s*/dev/sd[a-z]',                'redirecting output to a block device'),
    (r'\bshred\s+[^\n]*/dev/',           'shred against a block device'),
    (r'\bcurl\s+[^\n|]*\|\s*(sudo\s+)?(bash|sh)\b', 'curl … | bash (remote code execution)'),
    (r'\bwget\s+[^\n|]*\|\s*(sudo\s+)?(bash|sh)\b', 'wget … | bash (remote code execution)'),
    (r'\b/etc/shadow\b',                 'reads/writes /etc/shadow'),
]


def _script_lint(body):
    """Return {'ok': bool, 'syntax_error': str|None, 'dangerous': [...]}.

    Syntax check: `bash -n` on the script body via stdin (never written
    to a file, so no race conditions or leftover artifacts). 5-second
    timeout — bash -n is normally instant; a stuck shell shouldn't hang
    the request.

    Dangerous-command check: regex sweep against _DANGEROUS_PATTERNS.
    """
    result = {'ok': True, 'syntax_error': None, 'dangerous': []}
    # Syntax
    try:
        proc = subprocess.run(
            ['bash', '-n'],
            input=body,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.returncode != 0:
            result['ok'] = False
            result['syntax_error'] = (proc.stderr or proc.stdout or 'bash -n failed').strip()[:2000]
    except FileNotFoundError:
        # No bash on the server — skip the syntax check rather than
        # failing closed (the script will run on the *agent*, which has
        # its own bash). Surface this in the result so the UI can show
        # "syntax check skipped" rather than a confusing "passed".
        result['syntax_error'] = '__skipped__'
    except subprocess.TimeoutExpired:
        result['ok'] = False
        result['syntax_error'] = 'bash -n timed out after 5s'

    # Dangerous-command heuristics
    for pat, label in _DANGEROUS_PATTERNS:
        if re.search(pat, body, re.IGNORECASE | re.MULTILINE):
            result['dangerous'].append(label)
    return result


def _sanitize_script_body(s):
    """Reject the obvious wrong shapes and truncate to budget."""
    if not isinstance(s, str):
        return ''
    # Reject ASCII control characters except tab + newline. Lets unicode
    # through (people put comments in Greek / Cyrillic / etc.) but blocks
    # anything that would confuse terminals or break JSON encoding.
    s = ''.join(c for c in s if c in '\t\n' or ord(c) >= 0x20)
    return s[:MAX_SCRIPT_BODY]


def handle_scripts_list():
    require_auth()
    data = load(SCRIPTS_FILE)
    scripts = data.get('scripts', [])
    # Return body lengths but not bodies in the list endpoint — keeps the
    # response small for fleets with lots of long scripts. Body is fetched
    # via GET /api/scripts/<id>.
    out = []
    for s in scripts:
        out.append({
            'id':          s.get('id'),
            'name':        s.get('name'),
            'description': s.get('description', ''),
            'created':     s.get('created'),
            'updated':     s.get('updated', s.get('created')),
            'created_by':  s.get('created_by', ''),
            'body_len':    len(s.get('body', '')),
            'dangerous':   bool(s.get('last_lint', {}).get('dangerous')),
        })
    respond(200, out)


def handle_scripts_get(script_id):
    require_auth()
    if not _validate_id(script_id):
        respond(404, {'error': 'Script not found'})
    data = load(SCRIPTS_FILE)
    for s in data.get('scripts', []):
        if s.get('id') == script_id:
            respond(200, s)
    respond(404, {'error': 'Script not found'})


def handle_scripts_add():
    actor = require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    name = _sanitize_str(body.get('name', ''), MAX_SCRIPT_NAME, allow_empty=False)
    desc = _sanitize_str(body.get('description', ''), MAX_SCRIPT_DESC)
    script_body = _sanitize_script_body(body.get('body', ''))
    if not name:
        respond(400, {'error': 'name required'})
    if not script_body.strip():
        respond(400, {'error': 'body required'})

    data = load(SCRIPTS_FILE)
    scripts = data.get('scripts', [])
    if len(scripts) >= MAX_SCRIPTS:
        respond(400, {'error': f'Script library limit reached (max {MAX_SCRIPTS} scripts)'})

    lint = _script_lint(script_body)
    new = {
        'id':          secrets.token_hex(6),
        'name':        name,
        'description': desc,
        'body':        script_body,
        'created':     int(time.time()),
        'updated':     int(time.time()),
        'created_by':  actor,
        'last_lint':   lint,
    }
    scripts.append(new)
    data['scripts'] = scripts
    save(SCRIPTS_FILE, data)
    audit_log(actor, 'script_create', detail=f'name={name!r} id={new["id"]} '
              f'body_len={len(script_body)} dangerous={lint["dangerous"]}')
    respond(201, {'ok': True, 'script': new, 'lint': lint})


def handle_scripts_update(script_id):
    actor = require_admin_auth()
    if method() != 'PUT':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(script_id):
        respond(404, {'error': 'Script not found'})
    body = get_json_body()
    data = load(SCRIPTS_FILE)
    scripts = data.get('scripts', [])
    for s in scripts:
        if s.get('id') == script_id:
            if 'name' in body:
                s['name'] = _sanitize_str(body['name'], MAX_SCRIPT_NAME, allow_empty=False) or s['name']
            if 'description' in body:
                s['description'] = _sanitize_str(body['description'], MAX_SCRIPT_DESC)
            if 'body' in body:
                new_body = _sanitize_script_body(body['body'])
                if new_body.strip():
                    s['body'] = new_body
                    s['last_lint'] = _script_lint(new_body)
            s['updated'] = int(time.time())
            data['scripts'] = scripts
            save(SCRIPTS_FILE, data)
            audit_log(actor, 'script_update',
                      detail=f'id={script_id} name={s["name"]!r}')
            respond(200, {'ok': True, 'script': s})
    respond(404, {'error': 'Script not found'})


def handle_scripts_delete(script_id):
    actor = require_admin_auth()
    if method() != 'DELETE':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(script_id):
        respond(404, {'error': 'Script not found'})
    data = load(SCRIPTS_FILE)
    scripts = data.get('scripts', [])
    before = len(scripts)
    deleted_name = None
    for s in scripts:
        if s.get('id') == script_id:
            deleted_name = s.get('name')
            break
    scripts = [s for s in scripts if s.get('id') != script_id]
    if len(scripts) == before:
        respond(404, {'error': 'Script not found'})
    data['scripts'] = scripts
    save(SCRIPTS_FILE, data)
    audit_log(actor, 'script_delete',
              detail=f'id={script_id} name={deleted_name!r}')
    respond(200, {'ok': True})


def handle_scripts_dry_run(script_id):
    """Run bash -n and dangerous-command detection. No execution. Idempotent.

    Operators hit this from the UI before queueing a script across the
    fleet. The result is also stored on the script record (last_lint) so
    the list endpoint can surface a "⚠ dangerous" badge without re-running
    the lint on every page load.
    """
    require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(script_id):
        respond(404, {'error': 'Script not found'})
    data = load(SCRIPTS_FILE)
    for s in data.get('scripts', []):
        if s.get('id') == script_id:
            lint = _script_lint(s.get('body', ''))
            s['last_lint'] = lint
            save(SCRIPTS_FILE, data)
            respond(200, {'ok': True, 'lint': lint})
    respond(404, {'error': 'Script not found'})


# ── v2.1.0: Batch script execution ────────────────────────────────────────────
#
# POST /api/exec/batch
#   { "script_id": "...", "device_ids": [...] | "tag": "..." | "group": "...",
#     "confirm_dangerous": false }
#
# Queues the script as an exec: command on each resolved target. Returns a
# batch job ID; the UI polls GET /api/exec/batch/<id> for per-device status.
# Job records live in batch_jobs.json with a 1-hour TTL — pruned on every
# access so we don't accumulate forever.

def _purge_expired_batch_jobs(data):
    """Drop batch jobs older than BATCH_JOB_TTL_SEC. Mutates `data` in place."""
    now = int(time.time())
    jobs = data.get('jobs', {})
    fresh = {jid: j for jid, j in jobs.items()
             if (now - int(j.get('created', 0))) < BATCH_JOB_TTL_SEC}
    if len(fresh) != len(jobs):
        data['jobs'] = fresh
    return data


def handle_exec_batch():
    actor = require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    script_id = str(body.get('script_id', '')).strip()
    if not _validate_id(script_id):
        respond(400, {'error': 'valid script_id required'})

    # Resolve script
    sdata = load(SCRIPTS_FILE)
    script = None
    for s in sdata.get('scripts', []):
        if s.get('id') == script_id:
            script = s
            break
    if not script:
        respond(404, {'error': 'Script not found'})

    # Re-lint at dispatch time. If the script body has dangerous markers
    # we require an explicit confirmation flag from the caller. This is
    # not a substitute for review — it's a "did you mean to do this on
    # 47 machines?" prompt.
    lint = _script_lint(script.get('body', ''))
    if lint['dangerous'] and not body.get('confirm_dangerous'):
        respond(400, {
            'error': 'Script contains dangerous commands; pass '
                     '{"confirm_dangerous": true} to acknowledge',
            'dangerous': lint['dangerous'],
        })
    if lint.get('syntax_error') and lint['syntax_error'] != '__skipped__':
        respond(400, {'error': 'Script has syntax errors; fix or re-run dry run',
                      'syntax_error': lint['syntax_error']})

    # Resolve targets (reuses the existing helper — same rules as every
    # other batch command path). _resolve_targets internally caps at 100,
    # but it does so by silent truncation. We want explicit failure so an
    # operator asking for 200 devices doesn't quietly hit only 100; check
    # the input length up front and 400 if it exceeds the cap.
    if isinstance(body.get('device_ids'), list) and \
       len(body['device_ids']) > MAX_BATCH_TARGETS:
        respond(400, {'error': f'too many targets (max {MAX_BATCH_TARGETS})'})
    targets = _resolve_targets(body)
    if not targets:
        respond(400, {'error': 'no valid targets'})
    if len(targets) > MAX_BATCH_TARGETS:
        respond(400, {'error': f'too many targets (max {MAX_BATCH_TARGETS})'})

    devices = load(DEVICES_FILE)
    cmds = load(CMDS_FILE)
    now = int(time.time())
    exec_payload = 'exec:' + script.get('body', '')

    per_device = {}
    for dev_id in targets:
        if dev_id not in devices:
            per_device[dev_id] = {'queued': False, 'reason': 'not_found'}
            continue
        if devices[dev_id].get('agentless'):
            per_device[dev_id] = {'queued': False, 'reason': 'agentless'}
            continue
        cmds.setdefault(dev_id, [])
        if exec_payload not in cmds[dev_id]:
            cmds[dev_id].append(exec_payload)
        per_device[dev_id] = {
            'queued': True,
            'name':   devices[dev_id].get('name', dev_id),
            'queued_at': now,
        }
    save(CMDS_FILE, cmds)

    # Persist the job record. Pruned on every access.
    jobs_data = load(BATCH_JOBS_FILE)
    _purge_expired_batch_jobs(jobs_data)
    jobs = jobs_data.get('jobs', {})
    job_id = secrets.token_hex(8)
    jobs[job_id] = {
        'id':          job_id,
        'script_id':   script_id,
        'script_name': script.get('name', ''),
        'actor':       actor,
        'created':     now,
        'targets':     list(per_device.keys()),
        'per_device':  per_device,
        'dangerous':   lint['dangerous'],
    }
    jobs_data['jobs'] = jobs
    save(BATCH_JOBS_FILE, jobs_data)

    queued_count = sum(1 for p in per_device.values() if p['queued'])
    audit_log(actor, 'script_batch_exec',
              detail=f'job={job_id} script={script.get("name")!r} '
                     f'targets={len(targets)} queued={queued_count} '
                     f'dangerous={lint["dangerous"]}')
    log_command(actor, 'batch', f'script:{script.get("name", "")}',
                f'batch_exec:{job_id}')
    respond(202, {'ok': True, 'job_id': job_id, 'queued': queued_count,
                  'total': len(targets), 'per_device': per_device})


def handle_exec_batch_status(job_id):
    require_auth()
    if not _validate_id(job_id):
        respond(404, {'error': 'Batch job not found'})
    jobs_data = load(BATCH_JOBS_FILE)
    _purge_expired_batch_jobs(jobs_data)
    save(BATCH_JOBS_FILE, jobs_data)
    job = jobs_data.get('jobs', {}).get(job_id)
    if not job:
        respond(404, {'error': 'Batch job not found or expired'})

    # Enrich per-device entries with the most recent exec output for the
    # script body. We match against the queued payload (exec:<body>) so a
    # device that ran the same body via another path doesn't get falsely
    # attributed.
    sdata = load(SCRIPTS_FILE)
    script = None
    for s in sdata.get('scripts', []):
        if s.get('id') == job['script_id']:
            script = s
            break
    outputs = load(CMD_OUTPUT_FILE)
    enriched = {}
    body_match = ('exec:' + script['body']) if script else None
    job_created = int(job.get('created', 0))
    for dev_id, entry in job['per_device'].items():
        out = dict(entry)
        if entry.get('queued') and body_match:
            # Find the newest cmd_output for this device that matches the
            # script body AND was recorded after the job was created.
            for rec in reversed(outputs.get(dev_id, [])):
                if rec.get('cmd', '').strip() == body_match.strip() and int(rec.get('ts', 0)) >= job_created:
                    out['status']     = 'done'
                    out['rc']         = rec.get('rc', -1)
                    out['output']     = rec.get('output', '')[:8192]
                    out['finished_at'] = rec.get('ts')
                    break
            else:
                out['status'] = 'pending'
        enriched[dev_id] = out

    respond(200, {
        'job_id':     job_id,
        'script_id':  job['script_id'],
        'script_name': job['script_name'],
        'created':    job_created,
        'actor':      job['actor'],
        'per_device': enriched,
        'dangerous':  job.get('dangerous', []),
    })


# ── v2.1.3: AI assistant ────────────────────────────────────────────────────
#
# Config lives in cfg['ai']. API keys are stored in the same CONFIG_FILE
# the rest of the server reads — the file is created mode 0600 and owned
# by the CGI user, so cleartext-on-disk is acceptable given the threat
# model. (Operators who want stronger storage can plug in cmdb_vault.)
#
# Usage tracking lives in AI_USAGE_FILE — a simple per-user-per-day
# counter that resets when the date changes. Rate-limiting only;
# we don't store the prompts/responses there (that goes in the audit
# log if you really want it).
#
# Three endpoints:
#   GET  /api/ai/config       — return current config with api_key masked
#   POST /api/ai/config       — update config (admin)
#   POST /api/ai/chat         — actually call the model
#   POST /api/ai/test         — admin: round-trip a tiny "say hi" against
#                                the configured provider to verify creds

AI_USAGE_FILE = DATA_DIR / 'ai_usage.json'

_AI_DEFAULTS = {
    'enabled':  False,
    'provider': 'anthropic',
    'model':    '',
    'base_url': '',
    'api_key':  '',
    'insecure_ssl': False,
    # v2.1.7: project + fleet context (Level-1 RAG). Always-on by
    # default — these blocks are 1-3 KB of cheap context that makes
    # the model know what RemotePower is and what your fleet looks
    # like. Turn off if you have a specific reason to keep prompts
    # minimal (e.g. running a tiny local model with a 2k context
    # window).
    #
    # Fleet context contains hostnames + group names by design — a
    # redacted fleet context is useless. If you're on a cloud provider
    # and don't want hostnames egressing, turn `include_fleet_context`
    # off; project context is non-sensitive and stays on.
    'context': {
        'include_project_context': True,
        'include_fleet_context':   True,
    },
    'privacy': {
        'send_hostnames':  False,
        'send_ips':        False,
        'send_journal':    False,
        'send_cmd_output': True,
    },
    'limits': {
        'max_tokens_per_response':  4000,
        'max_requests_per_user_day': 100,
    },
}


def _ai_cfg():
    """Read current AI config with defaults merged in."""
    cfg = load(CONFIG_FILE).get('ai') or {}
    out = dict(_AI_DEFAULTS)
    out.update({k: v for k, v in cfg.items() if k in _AI_DEFAULTS})
    # Nested dicts need explicit merge, not overwrite
    out['privacy'] = dict(_AI_DEFAULTS['privacy'])
    out['privacy'].update((cfg.get('privacy') or {}))
    out['limits']  = dict(_AI_DEFAULTS['limits'])
    out['limits'].update((cfg.get('limits') or {}))
    out['context'] = dict(_AI_DEFAULTS['context'])
    out['context'].update((cfg.get('context') or {}))
    return out


def _ai_cfg_for_display(cfg):
    """Mask the API key for GET responses. Same Settings UX pattern as the
    rest of the codebase: dots if present, empty if not."""
    out = dict(cfg)
    if out.get('api_key'):
        out['api_key'] = '••••••••' + cfg['api_key'][-4:]
    return out


def handle_ai_config_get():
    require_admin_auth()
    cfg = _ai_cfg()
    out = _ai_cfg_for_display(cfg)
    # Surface the provider list + per-provider defaults so the UI doesn't
    # have to hardcode them.
    out['_providers'] = list(ai_provider.VALID_PROVIDERS)
    out['_defaults']  = {
        p: {'base_url': ai_provider.DEFAULT_BASE_URLS[p],
            'model':    ai_provider.DEFAULT_MODELS[p]}
        for p in ai_provider.VALID_PROVIDERS
    }
    respond(200, out)


def handle_ai_config_set():
    actor = require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body()

    with _locked_update(CONFIG_FILE) as cfg:
        cur = dict(_AI_DEFAULTS)
        cur.update(cfg.get('ai') or {})
        # Allow-listed merge — never let the caller inject random keys
        for k in ('enabled', 'provider', 'model', 'base_url', 'insecure_ssl'):
            if k in body:
                cur[k] = body[k]
        # API key: only update if non-empty; empty/missing keeps existing.
        # Special value '__clear__' wipes the stored key.
        if body.get('api_key') == '__clear__':
            cur['api_key'] = ''
        elif body.get('api_key'):
            cur['api_key'] = str(body['api_key'])[:512]
        # Nested merges
        if isinstance(body.get('privacy'), dict):
            cur['privacy'] = dict(cur.get('privacy') or {})
            for k in ('send_hostnames', 'send_ips', 'send_journal', 'send_cmd_output'):
                if k in body['privacy']:
                    cur['privacy'][k] = bool(body['privacy'][k])
        if isinstance(body.get('limits'), dict):
            cur['limits'] = dict(cur.get('limits') or {})
            mt = body['limits'].get('max_tokens_per_response')
            if isinstance(mt, int) and 1 <= mt <= 16000:
                cur['limits']['max_tokens_per_response'] = mt
            rl = body['limits'].get('max_requests_per_user_day')
            if isinstance(rl, int) and 0 <= rl <= 100000:
                cur['limits']['max_requests_per_user_day'] = rl
        # v2.1.7: project + fleet context toggles
        if isinstance(body.get('context'), dict):
            cur['context'] = dict(cur.get('context') or {})
            for k in ('include_project_context', 'include_fleet_context'):
                if k in body['context']:
                    cur['context'][k] = bool(body['context'][k])
        # Validate before saving
        ok, err = ai_provider.validate_config(cur)
        if not ok:
            respond(400, {'error': err})
        cfg['ai'] = cur

    audit_log(actor, 'ai_config_update',
              detail=f"provider={cur.get('provider')} "
                     f"enabled={cur.get('enabled')} "
                     f"model={cur.get('model')!r}")
    respond(200, _ai_cfg_for_display(_ai_cfg()))


def _ai_rate_limit_check(actor, cfg):
    """Returns (allowed, used, cap). Bumps the counter on allow."""
    cap = int(cfg.get('limits', {}).get('max_requests_per_user_day', 100))
    if cap <= 0:
        return True, 0, 0   # 0 means unlimited
    today = time.strftime('%Y-%m-%d')
    with _locked_update(AI_USAGE_FILE) as usage:
        key = f'{today}:{actor}'
        # Garbage-collect old days so the file doesn't grow forever
        for k in list(usage.keys()):
            if not k.startswith(today + ':'):
                del usage[k]
        used = int(usage.get(key, 0))
        if used >= cap:
            return False, used, cap
        usage[key] = used + 1
    return True, used + 1, cap


def handle_ai_chat():
    """Main chat endpoint. Body:
        {
          "messages":   [{"role": "user|assistant|system", "content": "..."}, ...],
          "system":     "optional system prompt key OR raw string",
          "context":    "optional free-form label for audit log",
          "max_tokens": optional int, defaults to configured cap,
          "model":      optional model name to override the configured one
        }
    `system` can be a key from ai_provider.SYSTEM_PROMPTS (e.g.
    'explain_output') or a literal prompt string. Keys are looked up
    first so the client can stay simple.

    `model` lets the AI page's per-conversation model picker request a
    different model than the configured default without poking Settings.
    `max_tokens` lets the inline buttons request shorter responses
    (Explain doesn't need 4000 tokens) — caps to the configured limit.
    """
    actor = require_auth()       # any authenticated user can use AI
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    cfg = _ai_cfg()
    if not cfg.get('enabled'):
        respond(400, {'error': 'AI is disabled. Configure in Settings → AI.'})

    messages = body.get('messages')
    ok, err = ai_provider.validate_messages(messages)
    if not ok:
        respond(400, {'error': err})

    raw_system = body.get('system') or ''
    if isinstance(raw_system, str):
        # If it's a key, look it up — otherwise treat as a literal
        system_prompt = ai_provider.SYSTEM_PROMPTS.get(raw_system, raw_system)
        # Bound the literal: don't let the client send a 50-KB system prompt
        if len(system_prompt) > 16 * 1024:
            respond(400, {'error': 'system prompt too long'})
    else:
        respond(400, {'error': 'system must be a string'})

    # v2.1.7: Level-1 RAG — prepend project + fleet context per cfg toggles.
    # The fleet snapshot is read fresh on every call so it always reflects
    # current state (online/offline status, recent additions, etc.). This
    # is cheap — devices.json is small and we already load() it constantly.
    ctx_opts = cfg.get('context') or {}
    include_project = bool(ctx_opts.get('include_project_context', True))
    include_fleet   = bool(ctx_opts.get('include_fleet_context', True))
    fleet_devices = None
    if include_fleet:
        try:
            raw = load(DEVICES_FILE)
            fleet_devices = list(raw.values()) if isinstance(raw, dict) else (raw or [])
        except Exception:
            # If devices.json can't be read, just skip fleet context —
            # the AI call should still work, just with less awareness.
            fleet_devices = None
    if include_project or fleet_devices:
        system_prompt = ai_context.build_combined_system_prompt(
            system_prompt,
            devices=fleet_devices,
            include_project=include_project,
            include_fleet=include_fleet and fleet_devices is not None,
            now=int(time.time()),
            ttl=get_online_ttl(),
        )

    context = ai_provider.redact(str(body.get('context', '') or '')[:128],
                                 cfg.get('privacy') or {})

    # Per-request overrides — cap to the configured server-side limits
    # so a client can't ask for more than the operator allowed.
    req_max_tokens = body.get('max_tokens')
    if isinstance(req_max_tokens, int) and req_max_tokens > 0:
        cfg_cap = int(cfg.get('limits', {}).get('max_tokens_per_response', 4000))
        req_max_tokens = min(req_max_tokens, cfg_cap)
    else:
        req_max_tokens = None
    req_model = body.get('model')
    if not (isinstance(req_model, str) and 1 <= len(req_model) <= 200):
        req_model = None

    # Rate limit
    allowed, used, cap = _ai_rate_limit_check(actor, cfg)
    if not allowed:
        respond(429, {'error': f'Daily AI request cap reached ({used}/{cap}). '
                               'Cap is configurable in Settings → AI.'})

    t0 = time.monotonic()
    result = ai_provider.chat(cfg, messages, system=system_prompt,
                              max_tokens=req_max_tokens, model=req_model)
    elapsed_ms = int((time.monotonic() - t0) * 1000)

    audit_log(actor, 'ai_chat',
              detail=f"provider={cfg.get('provider')} "
                     f"model={result.get('model', '?')} "
                     f"context={context!r} "
                     f"tokens_in={result.get('tokens_in', 0)} "
                     f"tokens_out={result.get('tokens_out', 0)} "
                     f"elapsed_ms={elapsed_ms} "
                     f"ok={result.get('ok', False)} "
                     f"used_today={used}/{cap if cap else 'unlimited'}")
    if not result.get('ok'):
        respond(502, {'error': result.get('error', 'AI provider error')})
    respond(200, {
        'ok':         True,
        'text':       result['text'],
        'model':      result.get('model'),
        'tokens_in':  result.get('tokens_in', 0),
        'tokens_out': result.get('tokens_out', 0),
        'elapsed_ms': elapsed_ms,
        'used_today': used,
        'daily_cap':  cap,
    })


# v2.1.4 follow-up: model listing + provider stats for the AI page.
# Read-only by everyone with auth; doesn't expose the API key.

def handle_ai_models():
    require_auth()
    if method() != 'GET':
        respond(405, {'error': 'Method not allowed'})
    cfg = _ai_cfg()
    if not cfg.get('enabled'):
        respond(400, {'error': 'AI is disabled'})
    result = ai_provider.list_models(cfg)
    if not result.get('ok'):
        respond(502, {'error': result.get('error', 'list_models failed')})
    respond(200, result)


def handle_ai_stats():
    require_auth()
    if method() != 'GET':
        respond(405, {'error': 'Method not allowed'})
    cfg = _ai_cfg()
    if not cfg.get('enabled'):
        respond(400, {'error': 'AI is disabled'})
    respond(200, ai_provider.provider_stats(cfg))


def handle_ai_test():
    """Smoke-test the configured provider. Sends a one-token request and
    returns success/error so the Settings page can show a green checkmark."""
    actor = require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    cfg = _ai_cfg()
    if not cfg.get('enabled'):
        respond(400, {'error': 'AI is disabled'})
    result = ai_provider.chat(
        cfg,
        messages=[{'role': 'user', 'content': 'Reply with exactly: OK'}],
        system="Respond with exactly the two-letter word OK and nothing else.",
        max_tokens=8,
    )
    audit_log(actor, 'ai_test',
              detail=f"provider={cfg.get('provider')} ok={result.get('ok')}")
    if not result.get('ok'):
        respond(502, {'ok': False, 'error': result.get('error')})
    respond(200, {
        'ok':         True,
        'text':       result['text'],
        'model':      result.get('model'),
        'tokens_in':  result.get('tokens_in', 0),
        'tokens_out': result.get('tokens_out', 0),
    })


# ── v2.1.7: Device runbooks ───────────────────────────────────────────────
#
# An AI-generated operations document per device. Storage is a single
# JSON file keyed by device ID; small payload (~3-10 KB per runbook),
# small fleet, no need for separate per-device files.
#
# Generation builds a structured snapshot from what we already have —
# sysinfo, watched services, containers, recent commands, journal, CVE
# findings, patch status — and hands it to the model with the
# 'generate_runbook' system prompt. No new agent-side discovery: we
# work with what the heartbeat already brings in. A future Phase 2
# can fire batch-exec discovery scripts before generation if we need
# fuller data.
#
# The endpoint is sync — the request stays open for the model
# round-trip (15-90 s typical). Same nginx fastcgi_read_timeout
# requirement as /api/ai/chat applies.

RUNBOOKS_FILE = DATA_DIR / 'runbooks.json'


def _build_runbook_snapshot(dev_id, devices):
    """Assemble the structured snapshot we send to the model.

    Returns a dict that gets JSON-stringified into the user message.
    Compact-ish — bounded to avoid blowing the context budget when
    a device has years of accumulated journal entries.

    `devices` may be either a dict (id → device record, the canonical
    shape) or a list of records. Handle both.
    """
    if isinstance(devices, dict):
        dev = devices.get(dev_id)
    else:
        dev = next((d for d in (devices or [])
                    if isinstance(d, dict) and d.get('id') == dev_id), None)
    if not dev:
        return None

    # v2.1.9: bound the snapshot total to ~8 KB / 2K tokens. The
    # v2.1.7-2.1.8 version was 20-25 KB at the high end — fine for a
    # 32K-context cloud model, fatal for an Ollama 14B-coder default
    # whose context cap of 2048-4096 tokens silently truncated mid-data
    # and left the model with garbage to invent around. The hard caps
    # below are the result of trial; if you're sending to a real
    # frontier model that wants more data, it can have it via direct
    # AI chat (which uses larger budgets), not the runbook generator.

    # Sysinfo: keep but trim to essentials. Full sysinfo can have
    # ~3-5 KB of nested data; we only need the operator-relevant bits.
    si_full = dev.get('sysinfo') or {}
    si = {}
    for k in ('uptime', 'platform', 'kernel', 'hostname', 'load',
              'cpu_percent', 'memory', 'disks', 'os_pretty'):
        if k in si_full:
            si[k] = si_full[k]
    # disks can be a list with many entries — keep top 5 by usage
    if isinstance(si.get('disks'), list):
        si['disks'] = sorted(
            si['disks'],
            key=lambda d: d.get('percent', 0) if isinstance(d, dict) else 0,
            reverse=True,
        )[:5]

    # Journal: 20 most recent lines (was 40)
    journal = (dev.get('journal') or [])[-20:]
    services = dev.get('services_watched_state') or dev.get('services') or []
    # Containers: 10 max, just the fields a runbook actually uses
    containers = (dev.get('containers') or [])[:10]
    last_seen = dev.get('last_seen')

    # Recent command output — last 5 (was 15), output capped to 200 chars
    try:
        out = load(CMD_OUTPUT_FILE).get(dev_id) or {}
        recent_cmds = (out.get('outputs') or [])[-5:]
    except Exception:
        recent_cmds = []
    recent_cmds = [{
        'ts':     c.get('ts'),
        'cmd':    (c.get('cmd') or '')[:120],
        'rc':     c.get('rc'),
        'output': (c.get('output') or '')[:200],
    } for c in recent_cmds]

    # CVE findings: top 10 (was 20), summary capped to 100 chars (was 200)
    try:
        cve = load(CVE_FINDINGS_FILE).get(dev_id) or {}
        cve_findings = (cve.get('findings') or [])[:10]
    except Exception:
        cve_findings = []
    cve_findings = [{
        'id':       f.get('vuln_id'),
        'severity': f.get('severity'),
        'pkg':      f.get('package'),
        'fixed':    f.get('fixed_version'),
        'summary':  (f.get('summary') or '')[:100],
    } for f in cve_findings if not f.get('ignored')]

    # Patch status — inline in the device dict.
    patches = {
        'patch_status': dev.get('patch_status'),
        'upgradable':   dev.get('upgradable'),
        'last_check':   dev.get('last_patch_check'),
    }

    return {
        'name':           dev.get('name'),
        'os':             dev.get('os'),
        'pkg_manager':    dev.get('pkg_manager'),
        'agent_version':  dev.get('version'),
        'last_seen':      last_seen,
        'group':          dev.get('group'),
        'tags':           dev.get('tags') or [],
        # Notes capped at 500 (was 1000) — runbooks aren't biographies
        'notes':          (dev.get('notes') or '')[:500],
        'ip':             dev.get('ip'),
        'mac':            dev.get('mac'),
        'sysinfo':        si,
        'services':       services,
        'containers':     [{
            'name':    c.get('name'),
            'image':   c.get('image'),
            'state':   c.get('state'),
        } for c in containers],
        'recent_commands': recent_cmds,
        'recent_journal':  journal,
        'cve_findings':   cve_findings,
        'patch_status':   patches,
    }


def handle_runbook_get(dev_id):
    """Return the stored runbook for a device (if any)."""
    require_auth()
    if method() != 'GET':
        respond(405, {'error': 'Method not allowed'})
    runbooks = load(RUNBOOKS_FILE)
    entry = runbooks.get(dev_id)
    if not entry:
        respond(200, {'exists': False})
    respond(200, {'exists': True, **entry})


def handle_runbook_generate(dev_id):
    """Generate a fresh runbook for the device. Sync — model round-trip
    happens during the request, can take 15-90 s. Saves on success."""
    actor = require_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})

    cfg = _ai_cfg()
    if not cfg.get('enabled'):
        respond(400, {'error': 'AI is disabled — enable in Settings → AI assistant'})

    # Rate limit (same per-user-per-day cap as /api/ai/chat)
    allowed, used, cap = _ai_rate_limit_check(actor, cfg)
    if not allowed:
        respond(429, {'error': f'Daily AI request cap reached ({used}/{cap}).'})

    # Build the snapshot
    devices = load(DEVICES_FILE)
    snapshot = _build_runbook_snapshot(dev_id, devices)
    if not snapshot:
        respond(404, {'error': 'Device not found'})

    # Prepend project + fleet context if the operator has it enabled.
    # Runbook quality benefits a lot from fleet awareness ("this is
    # one of N webservers" rather than "this is a Linux box").
    base_system = ai_provider.SYSTEM_PROMPTS['generate_runbook']
    ctx_opts = cfg.get('context') or {}
    fleet = list(devices.values()) if isinstance(devices, dict) else (devices or [])
    system_prompt = ai_context.build_combined_system_prompt(
        base_system,
        devices=fleet,
        include_project=bool(ctx_opts.get('include_project_context', True)),
        include_fleet=bool(ctx_opts.get('include_fleet_context', True)),
        now=int(time.time()),
        ttl=get_online_ttl(),
    )

    # v2.1.9: dump snapshot as compact JSON (no indent — wastes tokens)
    # and cap at 12 KB. The snapshot is already trimmed to ~8 KB by
    # _build_runbook_snapshot; the cap here is belt-and-braces in case
    # an unusual device has extra-large sysinfo fields we didn't trim.
    user_msg = (
        f"Generate a runbook for device '{snapshot['name']}'. "
        f"Use only the fields present in the snapshot below — do not "
        f"infer or invent.\n\n"
        f"```json\n{json.dumps(snapshot, default=str)[:12000]}\n```"
    )

    t0 = time.monotonic()
    result = ai_provider.chat(
        cfg,
        messages=[{'role': 'user', 'content': user_msg}],
        system=system_prompt,
        max_tokens=4000,
    )
    elapsed_ms = int((time.monotonic() - t0) * 1000)

    audit_log(actor, 'runbook_generate',
              detail=f"device={dev_id} ok={result.get('ok')} "
                     f"tokens_in={result.get('tokens_in', 0)} "
                     f"tokens_out={result.get('tokens_out', 0)} "
                     f"elapsed_ms={elapsed_ms}")
    if not result.get('ok'):
        respond(502, {'error': result.get('error', 'AI provider error')})

    # Save under the device ID
    entry = {
        'content':       result['text'],
        'generated_at':  int(time.time()),
        'generated_by':  actor,
        'model':         result.get('model'),
        'tokens_in':     result.get('tokens_in', 0),
        'tokens_out':    result.get('tokens_out', 0),
        'elapsed_ms':    elapsed_ms,
    }
    with _locked_update(RUNBOOKS_FILE) as runbooks:
        runbooks[dev_id] = entry
    respond(200, {'ok': True, 'exists': True, **entry})


def handle_runbook_delete(dev_id):
    """Remove the stored runbook for a device. Idempotent."""
    actor = require_auth()
    if method() != 'DELETE':
        respond(405, {'error': 'Method not allowed'})
    existed = False
    with _locked_update(RUNBOOKS_FILE) as runbooks:
        if dev_id in runbooks:
            del runbooks[dev_id]
            existed = True
    audit_log(actor, 'runbook_delete', detail=f"device={dev_id} existed={existed}")
    respond(200, {'ok': True, 'deleted': existed})


# ── v2.2.0: Configuration drift detection ─────────────────────────────────
#
# Per-device file integrity monitoring. The agent computes SHA-256 hashes
# of a watched-files list every DRIFT_EVERY heartbeats and ships them in
# the heartbeat payload. The server compares against the stored baseline
# and emits a `drift_detected` webhook event when hashes diverge.
#
# DESIGN DECISION: agent ships HASHES ONLY, never file contents. Storing
# /etc/sshd_config or /etc/sudoers contents in RemotePower's JSON files
# would be a real secrets-leak surface. To see what changed, the operator
# clicks "Show current" which queues a `cat <path>` command through the
# existing exec mechanism — the diff is then reconstructed from the two
# command outputs.
#
# STORAGE: drift_state.json
# {
#   "<device_id>": {
#     "files": {
#       "<path>": {
#         "current_hash":     "sha256...",
#         "current_size":     12345,
#         "current_mtime":    1700000000,
#         "baseline_hash":    "sha256...",
#         "baseline_size":    12345,
#         "baseline_set_at":  1700000000,
#         "baseline_set_by":  "admin",
#         "first_seen":       1700000000,
#         "last_check":       1700000000,
#         "drift_count":      0,          # incremented each time baseline != current
#         "exists":           true,        # false if agent reported the file missing
#         "history": [
#           {"ts": ..., "hash": "sha256...", "size": ...},
#           ...                            # bounded to last 20 entries
#         ]
#       }
#     }
#   }
# }

DRIFT_STATE_FILE = DATA_DIR / 'drift_state.json'

# v2.2.1: drift content fetch — operator-triggered retrieval of the
# actual file contents on a drifted host, for the diff viewer. By
# default, drift detection ships hashes only. When the operator
# explicitly clicks "Show diff" on a drifted file, the server queues
# `cat <path>` as a regular exec command. When its output comes back
# via the normal output-ingest path, we ALSO mirror it into
# drift_contents.json so the diff viewer can pull it without scanning
# the whole command-output log.
#
# Storage: {device_id: {path: [{ts, content, rc}, ...]}} — last 2
# captures per path kept; older ones evicted so the diff is always
# baseline-capture vs current-capture without unbounded growth.
DRIFT_CONTENTS_FILE = DATA_DIR / 'drift_contents.json'
MAX_DRIFT_CONTENT_CAPTURES = 2          # rolling buffer per path
MAX_DRIFT_CONTENT_BYTES    = 256 * 1024 # cap per capture to bound disk
                                        # /etc/sshd_config is ~3KB,
                                        # /etc/sudoers ~1KB, even
                                        # bloated /etc/hosts <16KB —
                                        # 256KB is generous.

# DRIFT_CONTENT_DENYLIST — paths whose content is NEVER retrievable,
# regardless of operator role. /etc/shadow contains password hashes;
# even a "viewer" operator with drift-fetch permission must not be
# able to pull it. Drift hashes still work for these — the hash tells
# you something changed without revealing what.
DRIFT_CONTENT_DENYLIST = frozenset({
    '/etc/shadow', '/etc/gshadow',
    '/etc/shadow-', '/etc/gshadow-',    # the rotated copies
})

# Default watched files. Operators can override per-device via the UI.
# Conservative list — config files that should rarely change without
# the operator's knowledge, and where a change is operationally
# significant. We deliberately don't watch /etc/passwd or /etc/shadow
# directly because those legitimately change often (every user login
# can update lastlog metadata adjacent to it on some distros). The
# operator can add them via the watched-files override if they want.
DEFAULT_WATCHED_FILES = [
    # ── SSH ──────────────────────────────────────────────────────
    '/etc/ssh/sshd_config',
    # ── Identity / auth ──────────────────────────────────────────
    '/etc/sudoers',
    '/etc/passwd',           # v2.2.6: account list — additions/removals
    '/etc/group',            # v2.2.6: group membership changes
    '/etc/login.defs',       # v2.2.6: password-policy / UID range config
    '/etc/pam.d/sshd',
    '/etc/pam.d/common-auth',# v2.2.6: PAM auth stack
    # ── System / boot ────────────────────────────────────────────
    '/etc/fstab',
    '/etc/crontab',
    '/etc/hosts',
    '/etc/resolv.conf',
    '/etc/nsswitch.conf',
    # ── Package sources ──────────────────────────────────────────
    '/etc/apt/sources.list', # v2.2.6: a changed apt source is a
                             # supply-chain red flag
]

# v2.2.6: how many consecutive heartbeats a watched file must report
# `exists: false` before it's marked dormant. One missed sighting can
# be a transient (file mid-rotation, agent race) — three in a row
# means it's genuinely gone. A dormant file stops counting as drift
# and drops out of the "files with drift" total, but is NOT deleted —
# it's kept with a `dormant` flag so the operator can still see it was
# being watched, and it auto-revives if the file reappears.
DRIFT_MISSING_DORMANT_AFTER = 3

# Maximum history entries kept per file
DRIFT_HISTORY_CAP = 20


# ── v2.4.3: mailbox-count monitor ──────────────────────────────────────────
#
# A lightweight mailbox monitor. The agent counts the regular files in
# one or more directories (the Maildir 'new' folder convention — one
# file per unread message) and reports the numbers in its heartbeat.
# No IMAP, no SMTP, no email content — just counts. A device can be
# "promoted" so its mailbox counts show as a dashboard widget.
MAX_MAILBOX_PATHS    = 20      # paths counted per device
MAX_MAILBOX_PATH_LEN = 512

# ── v2.5.0: custom monitoring scripts ────────────────────────────────────────
#
# Admin-defined bash scripts that run on enrolled devices every 5 minutes.
# Exit code 0 = OK, anything else = FAIL (binary — no MRPE severity levels).
# Scripts are defined server-side, assigned to devices, pushed via heartbeat
# response, executed by the agent with a timeout, and results reported back.
CUSTOM_SCRIPTS_FILE     = DATA_DIR / 'custom_scripts.json'
MAX_CUSTOM_SCRIPTS      = 50       # fleet-wide script definitions
MAX_CUSTOM_SCRIPTS_PER_DEVICE = 10 # scripts assigned to one device
MAX_CUSTOM_SCRIPT_NAME  = 80
MAX_CUSTOM_SCRIPT_DESC  = 256
MAX_CUSTOM_SCRIPT_BODY  = 32 * 1024   # 32 KB per script body
MAX_SCRIPT_OUTPUT       = 4096        # bytes captured from stdout+stderr
CUSTOM_SCRIPT_TIMEOUT   = 30          # seconds; hard cap, not configurable

# ── v2.6.0: Host configuration management ─────────────────────────────────
# Sections the server can push to agents and agents report current state of.
HOST_CONFIG_TEXT_SECTIONS = [
    'repos', 'netplan', 'nmcli', 'resolv_conf', 'hosts', 'sudoers', 'motd',
]
HOST_CONFIG_STRUCT_SECTIONS = ['services', 'users', 'groups']
HOST_CONFIG_ALL_SECTIONS    = HOST_CONFIG_TEXT_SECTIONS + HOST_CONFIG_STRUCT_SECTIONS
MAX_HOST_CONFIG_SECTION_SIZE = 65536   # 64 KB per text section
HOST_CONFIG_AUDIT_EVERY      = 15      # drift audit cadence in polls (~15 min)
# Current state is stored in separate per-device files, NOT in devices.json,
# to keep devices.json small and fast to read on every API call.
HOST_CONFIG_CURRENT_DIR = DATA_DIR / 'host_config_current'


def _ingest_mailbox_counts(dev_id, counts):
    """Store the mailbox file counts reported by an agent heartbeat.

    `counts` maps directory path → {count, exists, error}. We store
    the latest snapshot plus a timestamp on the device record under
    `mailbox_state`. Latest-wins; no history kept (a count is a
    point-in-time number, not an event stream).

    v2.4.7: if the device has a mailbox alert threshold set, each
    path's count is compared against it. The check is EDGE-triggered
    — the `mailbox_threshold` webhook fires once when a count crosses
    from below the threshold to at-or-above it, not on every
    heartbeat while it stays high. A per-path `alerted` flag remembers
    the state; it clears when the count drops back below, re-arming
    the alert. This is the same anti-fatigue pattern the metric and
    service alerts use.
    """
    if not isinstance(counts, dict):
        return
    clean = {}
    for path, info in list(counts.items())[:MAX_MAILBOX_PATHS]:
        if not isinstance(path, str) or not isinstance(info, dict):
            continue
        c = info.get('count')
        clean[path[:MAX_MAILBOX_PATH_LEN]] = {
            'count':  int(c) if isinstance(c, int) and c >= 0 else None,
            'exists': bool(info.get('exists')),
            'error':  str(info.get('error'))[:100] if info.get('error') else None,
        }
    # Crossings to fire are collected inside the lock, then the
    # webhooks are fired AFTER the lock is released — fire_webhook does
    # its own file I/O and must never run while we hold DEVICES_FILE.
    to_fire = []
    with _LockedUpdate(DEVICES_FILE) as devices:
        dev = devices.get(dev_id)
        if dev is None:
            return
        prev_state = dev.get('mailbox_state') or {}
        prev_alerted = prev_state.get('alerted') or {}
        threshold = dev.get('mailbox_threshold')
        alerted = {}
        if isinstance(threshold, int) and threshold > 0:
            for path, info in clean.items():
                cnt = info.get('count')
                was = bool(prev_alerted.get(path))
                if not isinstance(cnt, int):
                    # No usable count (error/missing) — carry the old
                    # state, don't fire and don't re-arm.
                    alerted[path] = was
                    continue
                now_over = cnt >= threshold
                alerted[path] = now_over
                if now_over and not was:
                    to_fire.append({
                        'name':      dev.get('name', dev_id),
                        'device_id': dev_id,
                        'path':      path,
                        'count':     cnt,
                        'threshold': threshold,
                    })
        dev['mailbox_state'] = {
            'counts':      clean,
            'reported_at': int(time.time()),
            'alerted':     alerted,
        }
    for payload in to_fire:
        try:
            fire_webhook('mailbox_threshold', payload)
        except Exception:
            pass


def handle_mailwatch_set(dev_id):
    """POST /api/devices/<id>/mailwatch — configure the mailbox monitor.

    Body: {"paths": ["/var/mail/.../new", ...], "dashboard": true|false}

    `paths` is the list of directories the agent should count files in
    (replaces any existing list — whole-list semantics, like the drift
    watch list). `dashboard` promotes this device so its mailbox counts
    appear as a widget on the Home dashboard.
    """
    require_admin_auth()
    if not _validate_id(dev_id):
        respond(400, {'error': 'invalid device id'})
        return
    body = get_json_body() or {}
    raw_paths = body.get('paths')
    if not isinstance(raw_paths, list):
        respond(400, {'error': 'paths must be a list'})
        return
    # Normalise: absolute paths only, trimmed, capped, de-duplicated.
    clean_paths = []
    for p in raw_paths[:MAX_MAILBOX_PATHS]:
        if not isinstance(p, str):
            continue
        p = p.strip()
        if not p or not p.startswith('/') or len(p) > MAX_MAILBOX_PATH_LEN:
            continue
        if p not in clean_paths:
            clean_paths.append(p)
    with _LockedUpdate(DEVICES_FILE) as devices:
        dev = devices.get(dev_id)
        if dev is None:
            respond(404, {'error': 'device not found'})
            return
        dev['mailbox_paths'] = clean_paths
        if 'dashboard' in body:
            dev['mailbox_dashboard'] = bool(body['dashboard'])
        # v2.4.7: optional alert threshold. A positive integer arms
        # the mailbox_threshold webhook; 0, null or absent disarms it.
        if 'threshold' in body:
            t = body.get('threshold')
            if isinstance(t, int) and t > 0:
                dev['mailbox_threshold'] = t
            else:
                dev.pop('mailbox_threshold', None)
        # Clearing all paths also clears any stored counts so a stale
        # number doesn't linger on the dashboard.
        if not clean_paths:
            dev.pop('mailbox_state', None)
    respond(200, {'ok': True, 'paths': clean_paths,
                  'dashboard': bool(body.get('dashboard'))})


def handle_mailwatch_overview():
    """GET /api/mailwatch — mailbox monitor state across the fleet.

    Returns one entry per device that has the mailbox monitor
    configured, with its latest counts. The Home dashboard widget
    uses the `dashboard`-promoted subset; the full list backs a
    management view.
    """
    require_auth()
    devices = load(DEVICES_FILE)
    rows = []
    for dev_id, dev in (devices or {}).items():
        paths = dev.get('mailbox_paths') or []
        if not paths:
            continue
        state = dev.get('mailbox_state') or {}
        rows.append({
            'device_id':   dev_id,
            'device_name': dev.get('name', dev_id),
            'paths':       paths,
            'dashboard':   bool(dev.get('mailbox_dashboard')),
            'threshold':   dev.get('mailbox_threshold') or 0,
            'counts':      state.get('counts') or {},
            'reported_at': state.get('reported_at', 0),
        })
    rows.sort(key=lambda r: r['device_name'].lower())
    respond(200, {'devices': rows})


# ── v2.5.0: custom monitoring scripts ─────────────────────────────────────────
#
# Admin-defined bash scripts pushed to enrolled devices and executed every
# 5 minutes by the agent. Exit 0 = OK, anything else = FAIL.
# Storage: custom_scripts.json holds definitions; results land on the device
# record in devices.json so queries don't need a separate join.

def _cs_id():
    """Generate a collision-resistant custom script ID."""
    return 'cs_' + secrets.token_hex(8)


def _load_custom_scripts():
    """Return {id: script_dict}. Missing file → empty dict."""
    return load(CUSTOM_SCRIPTS_FILE) or {}


def _get_custom_scripts_for_device(dev_id):
    """Return list of {id, name, body, timeout} for scripts assigned to dev_id.

    Called from the heartbeat handler; failure must never break heartbeat,
    so the caller wraps it in try/except.
    """
    scripts = _load_custom_scripts()
    result = []
    for s in scripts.values():
        if dev_id in (s.get('assigned_devices') or []):
            result.append({
                'id':      s['id'],
                'name':    s['name'],
                'body':    s['body'],
                'timeout': s.get('timeout', CUSTOM_SCRIPT_TIMEOUT),
            })
    # Enforce per-device cap — return the first N by creation order
    result.sort(key=lambda x: x['id'])
    return result[:MAX_CUSTOM_SCRIPTS_PER_DEVICE]


def _ingest_custom_script_results(dev_id, dev_name, results):
    """Store custom script results from a heartbeat and fire edge-triggered alerts.

    `results` is the raw dict from the agent:
        {script_id: {ok: bool, output: str, ran_at: int, duration_ms: int, rc: int}}

    We store results on the device record (devices.json) so the fleet results
    view can read everything in one pass. Alert state (prev_ok) is also stored
    there so we survive server restarts without re-firing alerts.
    """
    scripts = _load_custom_scripts()

    with _locked_update(DEVICES_FILE) as devices:
        dev = devices.get(dev_id)
        if not dev:
            return  # device vanished between heartbeat auth and here

        stored = dev.setdefault('custom_script_results', {})
        now = int(time.time())

        for script_id, raw in list(results.items())[:MAX_CUSTOM_SCRIPTS_PER_DEVICE]:
            # Validate the script ID actually belongs to this device
            s = scripts.get(script_id)
            if not s or dev_id not in (s.get('assigned_devices') or []):
                continue  # reject results for unassigned scripts

            ok    = bool(raw.get('ok', False))
            out   = str(raw.get('output', ''))[:MAX_SCRIPT_OUTPUT]
            rc    = int(raw['rc']) if isinstance(raw.get('rc'), int) else (0 if ok else 1)
            ran_at = int(raw['ran_at']) if isinstance(raw.get('ran_at'), int) else now
            dur   = int(raw['duration_ms']) if isinstance(raw.get('duration_ms'), int) else 0

            prev  = stored.get(script_id, {})
            prev_ok = prev.get('ok')   # None on first run

            changed_at = prev.get('changed_at', ran_at)
            if prev_ok is not None and ok != prev_ok:
                changed_at = now

            stored[script_id] = {
                'ok':          ok,
                'output':      out,
                'rc':          rc,
                'ran_at':      ran_at,
                'duration_ms': dur,
                'prev_ok':     prev_ok,
                'changed_at':  changed_at,
            }

            # Fire edge-triggered alerts — only on state transitions, not
            # every failing heartbeat.
            if prev_ok is None:
                # First result — no alert on initial acquisition
                pass
            elif not ok and prev_ok:
                # Transition OK → FAIL
                fire_webhook('custom_script_fail', {
                    'device_id':   dev_id,
                    'name':        dev_name,
                    'script_id':   script_id,
                    'script_name': s['name'],
                    'output':      out,
                    'rc':          rc,
                })
            elif ok and not prev_ok:
                # Transition FAIL → OK
                fire_webhook('custom_script_recover', {
                    'device_id':   dev_id,
                    'name':        dev_name,
                    'script_id':   script_id,
                    'script_name': s['name'],
                })

        devices[dev_id] = dev
        # devices auto-saved by _locked_update.__exit__


def handle_custom_scripts_list():
    """GET /api/custom-scripts — list all script definitions (admin + viewer)."""
    require_auth()
    scripts = _load_custom_scripts()
    # Strip body from list view to keep payload small; body is in the detail endpoint
    out = []
    for s in sorted(scripts.values(), key=lambda x: x.get('created_at', 0)):
        out.append({
            'id':               s['id'],
            'name':             s['name'],
            'description':      s.get('description', ''),
            'assigned_devices': s.get('assigned_devices', []),
            'timeout':          s.get('timeout', CUSTOM_SCRIPT_TIMEOUT),
            'created_at':       s.get('created_at', 0),
            'updated_at':       s.get('updated_at', 0),
            'created_by':       s.get('created_by', ''),
        })
    respond(200, {'scripts': out})


def handle_custom_script_get(script_id):
    """GET /api/custom-scripts/:id — full script detail including body."""
    require_auth()
    scripts = _load_custom_scripts()
    s = scripts.get(script_id)
    if not s:
        respond(404, {'error': 'Script not found'})
    respond(200, s)


def handle_custom_script_create():
    """POST /api/custom-scripts — create a new script definition (admin)."""
    actor = require_admin_auth()
    body = get_json_body()
    scripts = _load_custom_scripts()

    if len(scripts) >= MAX_CUSTOM_SCRIPTS:
        respond(400, {'error': f'Fleet limit of {MAX_CUSTOM_SCRIPTS} scripts reached'})

    name = _sanitize_str(str(body.get('name', '')).strip(), MAX_CUSTOM_SCRIPT_NAME)
    if not name:
        respond(400, {'error': 'name is required'})

    script_body = str(body.get('body', '')).strip()
    if not script_body:
        respond(400, {'error': 'body is required'})
    if len(script_body.encode()) > MAX_CUSTOM_SCRIPT_BODY:
        respond(400, {'error': f'Script body exceeds {MAX_CUSTOM_SCRIPT_BODY // 1024} KB limit'})
    # Reject NUL bytes — they break shell execution
    if '\x00' in script_body:
        respond(400, {'error': 'Script body must not contain NUL bytes'})

    desc = _sanitize_str(str(body.get('description', '')), MAX_CUSTOM_SCRIPT_DESC)

    # Validate assigned_devices: must be strings that look like known device IDs
    raw_devs = body.get('assigned_devices', [])
    if not isinstance(raw_devs, list):
        respond(400, {'error': 'assigned_devices must be a list'})
    devices = load(DEVICES_FILE)
    assigned = []
    for d in raw_devs[:MAX_CUSTOM_SCRIPTS_PER_DEVICE * 10]:
        d = str(d).strip()
        if _validate_id(d) and d in devices:
            assigned.append(d)

    now = int(time.time())
    sid = _cs_id()
    scripts[sid] = {
        'id':               sid,
        'name':             name,
        'description':      desc,
        'body':             script_body,
        'assigned_devices': assigned,
        'timeout':          CUSTOM_SCRIPT_TIMEOUT,
        'created_at':       now,
        'updated_at':       now,
        'created_by':       actor,
    }
    save(CUSTOM_SCRIPTS_FILE, scripts)
    audit_log(actor, 'custom_script_create', f'script_id={sid} name={name}')
    _record_fleet_event('custom_script_create', {
        'name': name, 'script_id': sid, 'device_count': len(assigned)})
    respond(201, scripts[sid])


def handle_custom_script_update(script_id):
    """PUT /api/custom-scripts/:id — update name, body, description, or assignments."""
    actor = require_admin_auth()
    body = get_json_body()
    scripts = _load_custom_scripts()
    s = scripts.get(script_id)
    if not s:
        respond(404, {'error': 'Script not found'})

    if 'name' in body:
        s['name'] = _sanitize_str(str(body['name']).strip(), MAX_CUSTOM_SCRIPT_NAME) or s['name']
    if 'description' in body:
        s['description'] = _sanitize_str(str(body['description']), MAX_CUSTOM_SCRIPT_DESC)
    if 'body' in body:
        new_body = str(body['body']).strip()
        if '\x00' in new_body:
            respond(400, {'error': 'Script body must not contain NUL bytes'})
        if len(new_body.encode()) > MAX_CUSTOM_SCRIPT_BODY:
            respond(400, {'error': f'Script body exceeds {MAX_CUSTOM_SCRIPT_BODY // 1024} KB limit'})
        s['body'] = new_body
    if 'assigned_devices' in body:
        raw_devs = body['assigned_devices']
        if not isinstance(raw_devs, list):
            respond(400, {'error': 'assigned_devices must be a list'})
        devices = load(DEVICES_FILE)
        assigned = []
        for d in raw_devs[:MAX_CUSTOM_SCRIPTS_PER_DEVICE * 10]:
            d = str(d).strip()
            if _validate_id(d) and d in devices:
                assigned.append(d)
        s['assigned_devices'] = assigned

    s['updated_at'] = int(time.time())
    scripts[script_id] = s
    save(CUSTOM_SCRIPTS_FILE, scripts)
    audit_log(actor, 'custom_script_update', f'script_id={script_id} name={s["name"]}')
    respond(200, s)


def handle_custom_script_delete(script_id):
    """DELETE /api/custom-scripts/:id — remove script and clear stored results."""
    actor = require_admin_auth()
    scripts = _load_custom_scripts()
    if script_id not in scripts:
        respond(404, {'error': 'Script not found'})

    name = scripts[script_id].get('name', script_id)
    del scripts[script_id]
    save(CUSTOM_SCRIPTS_FILE, scripts)

    # Remove stored results from every device that had them
    with _locked_update(DEVICES_FILE) as devices:
        for dev in devices.values():
            dev.get('custom_script_results', {}).pop(script_id, None)

    audit_log(actor, 'custom_script_delete', f'script_id={script_id} name={name}')
    _record_fleet_event('custom_script_delete', {'name': name, 'script_id': script_id})
    respond(200, {'ok': True})


def handle_custom_scripts_results():
    """GET /api/custom-scripts/results — fleet-wide current results per device."""
    require_auth()
    scripts   = _load_custom_scripts()
    devices   = load(DEVICES_FILE)
    now       = int(time.time())

    # Build index: script_id → script meta (name, assigned_devices)
    script_meta = {sid: {
        'id':               sid,
        'name':             s['name'],
        'description':      s.get('description', ''),
        'assigned_devices': s.get('assigned_devices', []),
    } for sid, s in scripts.items()}

    rows = []
    for dev_id, dev in devices.items():
        if dev.get('agentless'):
            continue
        results = dev.get('custom_script_results', {})
        if not results:
            continue
        online = (now - dev.get('last_seen', 0)) < get_online_ttl()
        for script_id, r in results.items():
            meta = script_meta.get(script_id, {'name': script_id, 'description': ''})
            rows.append({
                'device_id':   dev_id,
                'device_name': dev.get('name', dev_id),
                'group':       dev.get('group', ''),
                'online':      online,
                'script_id':   script_id,
                'script_name': meta['name'],
                'description': meta['description'],
                'ok':          r.get('ok', False),
                'output':      r.get('output', ''),
                'rc':          r.get('rc', 0),
                'ran_at':      r.get('ran_at', 0),
                'duration_ms': r.get('duration_ms', 0),
                'changed_at':  r.get('changed_at', 0),
            })

    rows.sort(key=lambda r: (r['ok'], r['device_name'].lower(), r['script_name'].lower()))
    respond(200, {'results': rows, 'scripts': list(script_meta.values())})



#
# Both the dashboard digest and the machine-readable status endpoint
# read from one place: _compute_attention(). It merges signals that
# already exist — offline devices, pending-patch pileups, CVE
# findings, drift, mailbox threshold breaches — into a single list of
# items, each with a severity so the caller can rank them.

# Severity rank — higher = more urgent. Used to sort the digest.
_ATTN_RANK = {'critical': 3, 'warning': 2, 'info': 1}


def _compute_attention():
    """Build the fleet-wide list of things needing attention.

    Returns a list of dicts: {severity, kind, device, summary}. Pure
    aggregation over data RemotePower already stores — no new probing.

    Unmonitored devices (operator set `monitored: false` — decommissioned
    hosts, dev boxes) are skipped entirely: the same gate the webhook
    pipeline and the old dashboard digest applied.
    """
    items = []
    devices = load(DEVICES_FILE) or {}
    now = int(time.time())
    try:
        ttl = get_online_ttl()
    except Exception:
        ttl = 180

    # The set of devices the digest considers at all.
    def _watched(dev):
        return not dev.get('agentless') and dev.get('monitored', True)

    monitored = {dev_id: dev for dev_id, dev in devices.items()
                 if _watched(dev)}

    # Offline devices (has heartbeated before).
    for dev_id, dev in monitored.items():
        last = dev.get('last_seen', 0)
        if last and (now - last) > ttl:
            mins = (now - last) // 60
            items.append({
                'severity': 'critical', 'kind': 'offline',
                'device': dev.get('name', dev_id),
                'summary': f'Offline for {mins} min — last seen '
                           f'{time.strftime("%H:%M", time.localtime(last))}',
            })

    # Pending-patch pileups.
    for dev_id, dev in monitored.items():
        up = dev.get('upgradable')
        if isinstance(up, int) and up > 0:
            sev = 'warning' if up >= 20 else 'info'
            items.append({
                'severity': sev, 'kind': 'patches',
                'device': dev.get('name', dev_id),
                'summary': f'{up} pending package update'
                           f'{"s" if up != 1 else ""}',
            })

    # CVE findings — excluding any vuln on the ignore list. An
    # operator who has accepted a CVE as a risk (globally or for that
    # device) does not want it back on the Needs Attention list.
    cve_all = load(CVE_FINDINGS_FILE) or {}
    cve_ignore = load(CVE_IGNORE_FILE) or {}
    for dev_id, rec in cve_all.items():
        if dev_id not in monitored:
            continue
        findings = (rec or {}).get('findings') or []
        if not findings:
            continue
        # apply_ignore_list marks each finding with an `ignored` flag
        # (scope 'global' or this device); drop the ignored ones.
        findings = [f for f in cve_scanner.apply_ignore_list(
                        findings, cve_ignore, dev_id)
                    if not f.get('ignored')]
        if not findings:
            continue
        crit = sum(1 for f in findings if f.get('severity') == 'critical')
        high = sum(1 for f in findings if f.get('severity') == 'high')
        name = monitored[dev_id].get('name', dev_id)
        if crit:
            items.append({'severity': 'critical', 'kind': 'cve',
                           'device': name,
                           'summary': f'{crit} critical CVE'
                                      f'{"s" if crit != 1 else ""}'})
        elif high:
            items.append({'severity': 'warning', 'kind': 'cve',
                           'device': name,
                           'summary': f'{high} high-severity CVE'
                                      f'{"s" if high != 1 else ""}'})

    # Configuration drift.
    for dev_id, dev in monitored.items():
        drift = dev.get('drift_state') or {}
        drifted = [f for f, st in drift.items()
                   if isinstance(st, dict) and st.get('status') == 'drifted'
                   and not st.get('ignored')]
        if drifted:
            items.append({
                'severity': 'warning', 'kind': 'drift',
                'device': dev.get('name', dev_id),
                'summary': f'{len(drifted)} config file'
                           f'{"s" if len(drifted) != 1 else ""} drifted '
                           f'from baseline',
            })

    # Mailbox threshold breaches (re-uses the alerted flags set by
    # _ingest_mailbox_counts — no recomputation).
    for dev_id, dev in monitored.items():
        state = dev.get('mailbox_state') or {}
        alerted = state.get('alerted') or {}
        counts = state.get('counts') or {}
        for path, is_over in alerted.items():
            if is_over:
                cnt = (counts.get(path) or {}).get('count')
                items.append({
                    'severity': 'warning', 'kind': 'mailbox',
                    'device': dev.get('name', dev_id),
                    'summary': f'Mailbox {path} at {cnt} '
                               f'(over threshold)',
                })

    items.sort(key=lambda i: _ATTN_RANK.get(i['severity'], 0), reverse=True)
    return items


def handle_attention():
    """GET /api/attention — the unified Needs Attention digest."""
    require_auth()
    items = _compute_attention()
    counts = {'critical': 0, 'warning': 0, 'info': 0}
    for i in items:
        counts[i['severity']] = counts.get(i['severity'], 0) + 1
    respond(200, {'items': items, 'counts': counts,
                  'total': len(items)})


def handle_status():
    """GET /api/status?token=<status_token> — machine-readable fleet
    summary for external dashboards (Uptime Kuma, Homepage, Grafana).

    Auth is a dedicated status token, NOT a session — so a monitoring
    tool can poll it — but it is not public: without the token, 403.
    The token is generated in Settings.
    """
    cfg = load(CONFIG_FILE)
    token = cfg.get('status_token')
    qs = urllib.parse.parse_qs(os.environ.get('QUERY_STRING', '') or '')
    given = (qs.get('token') or [''])[0]
    if not token:
        respond(403, {'error': 'status endpoint not enabled — generate a '
                               'status token in Settings'})
        return
    if not given or not hmac.compare_digest(given, token):
        respond(403, {'error': 'invalid or missing status token'})
        return

    devices = load(DEVICES_FILE) or {}
    now = int(time.time())
    try:
        ttl = get_online_ttl()
    except Exception:
        ttl = 180
    online = offline = 0
    for dev_id, dev in devices.items():
        if dev.get('agentless') or not dev.get('monitored', True):
            continue
        last = dev.get('last_seen', 0)
        if not last:
            continue
        if (now - last) > ttl:
            offline += 1
        else:
            online += 1

    items = _compute_attention()
    counts = {'critical': 0, 'warning': 0, 'info': 0}
    for i in items:
        counts[i['severity']] = counts.get(i['severity'], 0) + 1

    # A single rolled-up health word, so a dashboard can show one dot.
    if counts['critical']:
        health = 'critical'
    elif counts['warning']:
        health = 'warning'
    else:
        health = 'ok'

    respond(200, {
        'health':           health,
        'devices_online':   online,
        'devices_offline':  offline,
        'devices_total':    online + offline,
        'attention': {
            'critical': counts['critical'],
            'warning':  counts['warning'],
            'info':     counts['info'],
            'total':    len(items),
        },
        'version':   SERVER_VERSION,
        'generated': now,
    })


def handle_status_token():
    """POST /api/status-token — generate (or rotate) the status token.
    Body {"enabled": false} clears it, disabling the status endpoint."""
    require_admin_auth()
    body = get_json_body() or {}
    with _LockedUpdate(CONFIG_FILE) as cfg:
        if body.get('enabled') is False:
            cfg.pop('status_token', None)
            token = None
        else:
            token = secrets.token_urlsafe(24)
            cfg['status_token'] = token
    respond(200, {'ok': True, 'status_token': token})


def handle_force_package_scan(dev_id):
    """POST /api/devices/<id>/scan-packages — request an immediate
    package scan.

    The agent normally submits its full package inventory (for CVE
    scanning) and the patch/upgradable count only every few hundred
    heartbeats. This sets a one-shot flag; the device's next
    heartbeat response carries `force_package_scan`, the agent then
    sends a fresh package list and patch count on the heartbeat after
    that. The flag is cleared the moment it's handed to the agent —
    it fires exactly once.
    """
    require_admin_auth()
    if not _validate_id(dev_id):
        respond(400, {'error': 'invalid device id'})
        return
    with _LockedUpdate(DEVICES_FILE) as devices:
        dev = devices.get(dev_id)
        if dev is None:
            respond(404, {'error': 'device not found'})
            return
        dev['force_package_scan'] = True
    respond(200, {'ok': True,
                  'message': 'Package scan queued — the device sends a '
                             'fresh inventory within the next minute or two.'})


def get_watched_files_for(dev_id, devices=None):
    """Return the list of files this device should watch.

    Defaults from config / DEFAULT_WATCHED_FILES, with optional per-device
    overrides in devices[dev_id].watched_files.
    """
    cfg = _config()
    drift_cfg = cfg.get('drift') or {}
    if not drift_cfg.get('enabled', True):
        return []
    defaults = drift_cfg.get('default_watched_files') or DEFAULT_WATCHED_FILES
    if devices is None:
        devices = load(DEVICES_FILE)
    dev = devices.get(dev_id) if isinstance(devices, dict) else None
    if dev and isinstance(dev.get('watched_files'), list):
        # Per-device override completely replaces defaults
        return list(dev['watched_files'])
    return list(defaults)


def _ingest_drift_report(dev_id, drift_payload, actor='agent'):
    """Process a drift report submitted by the agent. Called from
    handle_heartbeat when payload['drift'] is present.

    drift_payload is a dict mapping file path → {hash, size, mtime,
    exists}. We compare each against the stored baseline; on the first
    sighting of a file we accept the current value as the baseline
    (operator can re-baseline at any time). On a change, we increment
    drift_count, push to history, and fire a webhook.
    """
    if not isinstance(drift_payload, dict):
        return

    fired_events = []
    now = int(time.time())
    with _LockedUpdate(DRIFT_STATE_FILE) as state:
        dev_state = state.setdefault(dev_id, {})
        files = dev_state.setdefault('files', {})
        for path, info in drift_payload.items():
            if not isinstance(info, dict):
                continue
            cur_hash  = info.get('hash')
            cur_size  = info.get('size')
            cur_mtime = info.get('mtime')
            exists    = bool(info.get('exists', True))

            existing = files.get(path)
            if existing is None:
                # First sighting — accept as baseline.
                files[path] = {
                    'current_hash':    cur_hash,
                    'current_size':    cur_size,
                    'current_mtime':   cur_mtime,
                    'baseline_hash':   cur_hash,
                    'baseline_size':   cur_size,
                    'baseline_set_at': now,
                    'baseline_set_by': actor,
                    'first_seen':      now,
                    'last_check':      now,
                    'drift_count':     0,
                    'exists':          exists,
                    'history':         [],
                }
                continue

            existing['current_hash']  = cur_hash
            existing['current_size']  = cur_size
            existing['current_mtime'] = cur_mtime
            existing['last_check']    = now
            existing['exists']        = exists

            # v2.2.6: dormant handling for files that aren't on the host.
            # A watched file reporting exists:false used to count as
            # drift forever (missing hash != baseline hash), nagging the
            # operator about a file that simply isn't there. Now: after
            # DRIFT_MISSING_DORMANT_AFTER consecutive missing sightings
            # the file is marked dormant — it stops counting as drift.
            # If the file comes back, dormant clears and normal drift
            # comparison resumes. The file is never deleted, so the
            # operator can still see it in the per-device detail.
            if not exists:
                miss = existing.get('missing_streak', 0) + 1
                existing['missing_streak'] = miss
                if miss >= DRIFT_MISSING_DORMANT_AFTER and not existing.get('dormant'):
                    existing['dormant']      = True
                    existing['dormant_since'] = now
                    # Fire one event so the operator knows — once, not
                    # every poll. After this the file is quiet.
                    fired_events.append({
                        'path':           path,
                        'baseline_hash':  existing.get('baseline_hash'),
                        'current_hash':   None,
                        'exists':         False,
                        'reason':         'file_absent',
                    })
                # While missing (dormant or not yet) skip drift compare —
                # a missing file's None hash must not trip the change path.
                continue
            else:
                # File present (again). Clear any missing state.
                if existing.get('missing_streak') or existing.get('dormant'):
                    existing['missing_streak'] = 0
                    if existing.get('dormant'):
                        existing['dormant'] = False
                        existing['revived_at'] = now

            # Is this a change from the prior known state?
            prior_hash = existing.get('prior_hash') or existing.get('baseline_hash')
            if cur_hash != prior_hash:
                # Push to history
                hist = existing.setdefault('history', [])
                hist.append({
                    'ts':   now,
                    'hash': cur_hash,
                    'size': cur_size,
                    'exists': exists,
                })
                if len(hist) > DRIFT_HISTORY_CAP:
                    del hist[:-DRIFT_HISTORY_CAP]
                # Update prior_hash so we don't re-fire on the next poll
                # if the file stays at the new hash.
                existing['prior_hash'] = cur_hash

                # If different from baseline, increment drift_count + queue webhook
                if cur_hash != existing.get('baseline_hash'):
                    existing['drift_count'] = existing.get('drift_count', 0) + 1
                    fired_events.append({
                        'path':           path,
                        'baseline_hash':  existing.get('baseline_hash'),
                        'current_hash':   cur_hash,
                        'exists':         exists,
                    })

    # Fire webhooks outside the lock
    if fired_events:
        devices = load(DEVICES_FILE)
        dev = devices.get(dev_id, {})
        for ev in fired_events:
            try:
                fire_webhook('drift_detected', {
                    'device_id':   dev_id,
                    'device_name': dev.get('name', dev_id),
                    'path':        ev['path'],
                    'exists':      ev['exists'],
                    'baseline_hash': ev['baseline_hash'],
                    'current_hash':  ev['current_hash'],
                })
            except Exception as e:
                sys.stderr.write(f"[remotepower] drift webhook failed: {e}\n")


def handle_drift_overview():
    """GET /api/drift — fleet-wide overview. Returns one row per device with
    summary counts (total files watched, files with drift, files missing)."""
    require_auth()
    state = load(DRIFT_STATE_FILE)
    devices = load(DEVICES_FILE)
    rows = []
    for dev_id, dev_state in state.items():
        files = (dev_state or {}).get('files') or {}
        n_total   = len(files)
        # v2.2.6: a dormant file (one that's been absent from the host
        # for several heartbeats) no longer counts as drift — its
        # missing hash != baseline hash is expected, not a change to
        # alarm on. Counted separately as `dormant` so the operator
        # can still see it.
        # v2.3.4: an explicitly IGNORED file (operator marked it — e.g.
        # a /etc/pam.d/common-auth that's legitimately absent on this
        # host) is non-critical. It drops out of the drift/missing
        # counts (so it doesn't drive a red status) but is still
        # counted as `ignored` and remains visible in the per-device
        # detail. This is the explicit-decision counterpart to the
        # automatic time-based `dormant` state.
        n_drifted = sum(1 for f in files.values()
                        if not f.get('dormant') and not f.get('ignored')
                        and f.get('exists', True)
                        and f.get('current_hash') != f.get('baseline_hash'))
        n_missing = sum(1 for f in files.values()
                        if not f.get('exists', True) and not f.get('ignored'))
        n_dormant = sum(1 for f in files.values() if f.get('dormant'))
        n_ignored = sum(1 for f in files.values() if f.get('ignored'))
        dev = devices.get(dev_id) or {}
        rows.append({
            'device_id':   dev_id,
            'device_name': dev.get('name', dev_id),
            'group':       dev.get('group', ''),
            'total':       n_total,
            'drifted':     n_drifted,
            'missing':     n_missing,
            'dormant':     n_dormant,
            'ignored':     n_ignored,
            'last_check':  max((f.get('last_check') or 0 for f in files.values()),
                               default=0),
        })
    rows.sort(key=lambda r: (-r['drifted'], r['device_name'].lower()))
    respond(200, {'devices': rows})


def handle_drift_ignore(dev_id):
    """POST /api/devices/<id>/drift/ignore — toggle the ignore flag on
    one watched file.

    Body: {"path": "/etc/...", "ignored": true|false, "reason": "..."}

    An ignored file is non-critical: it no longer counts toward the
    device's drift / missing totals and doesn't drive a red status,
    but it stays visible in the drift detail (marked "ignored"). This
    is the fix for drift false positives — e.g. a watched file that is
    legitimately absent on a particular host.
    """
    require_admin_auth()
    if not _validate_id(dev_id):
        respond(400, {'error': 'invalid device id'})
        return
    body = get_json_body() or {}
    path = (body.get('path') or '').strip()
    if not path:
        respond(400, {'error': 'path is required'})
        return
    ignored = bool(body.get('ignored', True))
    reason = (body.get('reason') or '')[:500]
    with _LockedUpdate(DRIFT_STATE_FILE) as state:
        dev_state = state.get(dev_id)
        if not dev_state or path not in (dev_state.get('files') or {}):
            respond(404, {'error': 'no drift record for that file'})
            return
        fentry = dev_state['files'][path]
        if ignored:
            fentry['ignored'] = True
            fentry['ignore_reason'] = reason
            fentry['ignored_at'] = int(time.time())
        else:
            fentry.pop('ignored', None)
            fentry.pop('ignore_reason', None)
            fentry.pop('ignored_at', None)
    respond(200, {'ok': True, 'path': path, 'ignored': ignored})


def handle_device_drift_get(dev_id):
    """GET /api/devices/<id>/drift — full drift state for one device."""
    require_auth()
    state = load(DRIFT_STATE_FILE)
    entry = state.get(dev_id) or {'files': {}}
    devices = load(DEVICES_FILE)
    watched = get_watched_files_for(dev_id, devices)
    respond(200, {
        'device_id':     dev_id,
        'watched_files': watched,
        'files':         entry.get('files') or {},
    })


def handle_device_drift_baseline(dev_id):
    """POST /api/devices/<id>/drift/baseline — accept current as new baseline.
    Body: {"paths": ["/etc/..."]} or {"all": true}."""
    actor = require_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body() or {}
    target_paths = body.get('paths')
    target_all = bool(body.get('all'))

    updated = []
    now = int(time.time())
    with _LockedUpdate(DRIFT_STATE_FILE) as state:
        dev_state = state.get(dev_id) or {}
        files = dev_state.get('files') or {}
        for path, entry in files.items():
            if not target_all and target_paths is not None and path not in target_paths:
                continue
            if entry.get('current_hash') == entry.get('baseline_hash'):
                continue   # nothing to update
            entry['baseline_hash']   = entry.get('current_hash')
            entry['baseline_size']   = entry.get('current_size')
            entry['baseline_set_at'] = now
            entry['baseline_set_by'] = actor
            entry['drift_count']     = 0
            entry['prior_hash']      = entry.get('current_hash')
            updated.append(path)
    audit_log(actor, 'drift_baseline',
              detail=f"device={dev_id} paths={updated}")
    respond(200, {'ok': True, 'updated': updated})


def handle_device_drift_reset(dev_id):
    """DELETE /api/devices/<id>/drift — wipe drift state for a device.
    Used when re-baselining or removing a device from drift monitoring."""
    actor = require_auth()
    if method() != 'DELETE':
        respond(405, {'error': 'Method not allowed'})
    existed = False
    with _LockedUpdate(DRIFT_STATE_FILE) as state:
        if dev_id in state:
            del state[dev_id]
            existed = True
    audit_log(actor, 'drift_reset', detail=f"device={dev_id} existed={existed}")
    respond(200, {'ok': True, 'deleted': existed})


# ── v2.2.1: drift content fetch (for the diff visualisation) ──────────────
#
# Three pieces:
#   1. _maybe_mirror_drift_content() — hook called from the heartbeat
#      output-ingest path. Detects `exec:cat <watched_path>` outputs and
#      mirrors the content into drift_contents.json (capped to last 2
#      captures per path).
#   2. handle_drift_fetch_content() — POST endpoint that queues a
#      `exec:cat <path>` command for each requested path. The agent
#      picks it up on next heartbeat, runs it, output mirrors via (1).
#   3. handle_drift_get_content() — GET endpoint that returns stored
#      captures for a given path. UI uses this to fetch baseline +
#      current and feed them to the JS diff renderer.
#
# DRIFT_CONTENT_DENYLIST is checked on BOTH endpoints — fetch refuses to
# queue, get refuses to return. Defense in depth.

# Used by _maybe_mirror_drift_content: parses `exec:cat <path>` and
# `exec:cat '/path with spaces'` forms. The agent emits the same
# command string we queued, so we can match by prefix.
_CAT_CMD_RE = __import__('re').compile(
    r"^exec:\s*cat\s+(?:'([^']+)'|\"([^\"]+)\"|(\S+))\s*$"
)


def _maybe_mirror_drift_content(dev_id, cmd_text, output, rc, ts):
    """Mirror a `cat <watched>` output into drift_contents.json. No-op
    if the command isn't a cat, the path isn't watched, or the path is
    on the denylist. Bounded write — drops anything >MAX_DRIFT_CONTENT_BYTES.
    """
    m = _CAT_CMD_RE.match(cmd_text or '')
    if not m:
        return
    path = m.group(1) or m.group(2) or m.group(3)
    if not path or not path.startswith('/'):
        return
    if path in DRIFT_CONTENT_DENYLIST:
        # Belt-and-braces — should never reach here because the fetch
        # endpoint refuses to queue these. If a malicious agent forged
        # an output for a denylisted path we still drop it.
        return
    # Is this path even being watched for drift on this device?
    watched = get_watched_files_for(dev_id)
    if path not in watched:
        return

    safe_output = (output or '')[:MAX_DRIFT_CONTENT_BYTES]
    with _LockedUpdate(DRIFT_CONTENTS_FILE) as store:
        dev = store.setdefault(dev_id, {})
        captures = dev.setdefault(path, [])
        captures.append({
            'ts':      ts,
            'rc':      rc,
            'content': safe_output,
        })
        # Keep only the last N — older captures don't help the
        # baseline-vs-current diff and they grow the file.
        if len(captures) > MAX_DRIFT_CONTENT_CAPTURES:
            del captures[:-MAX_DRIFT_CONTENT_CAPTURES]


def handle_drift_fetch_content(dev_id):
    """POST /api/devices/<id>/drift/fetch_content
       body: {"paths": ["/etc/...", ...]}

    Queue a `cat` command for each requested path. The agent picks it
    up on its next heartbeat (typically within a poll interval, usually
    60s). When the output comes back, _maybe_mirror_drift_content
    mirrors it into drift_contents.json for the diff viewer.

    Denylist enforcement: requests for /etc/shadow or other denylisted
    paths are dropped silently from the queue list (returned in
    `denied`). Other paths in the same request still get queued.
    """
    actor = require_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    body = get_json_body() or {}
    paths = body.get('paths') or []
    if not isinstance(paths, list):
        respond(400, {'error': 'paths must be a list'})

    watched = set(get_watched_files_for(dev_id, devices))
    queued, denied, not_watched = [], [], []
    cmds = load(CMDS_FILE)
    if dev_id not in cmds:
        cmds[dev_id] = []

    for p in paths:
        if not isinstance(p, str) or not p.startswith('/'):
            continue
        if p in DRIFT_CONTENT_DENYLIST:
            denied.append(p)
            continue
        if p not in watched:
            # Only allow content fetch for files we're actively
            # watching — otherwise this endpoint is just an
            # arbitrary file-read primitive.
            not_watched.append(p)
            continue
        # Single-quote the path for the shell to handle awkward
        # characters; this matches the agent's exec dispatcher.
        cmd = f"exec:cat '{p}'"
        if cmd not in cmds[dev_id]:
            cmds[dev_id].append(cmd)
            queued.append(p)
        log_command(actor, dev_id, devices[dev_id].get('name', dev_id), cmd)

    save(CMDS_FILE, cmds)
    audit_log(actor, 'drift_fetch_content',
              detail=f"device={dev_id} queued={queued} denied={denied}")
    respond(200, {
        'ok': True,
        'queued':      queued,
        'denied':      denied,
        'not_watched': not_watched,
        'note': 'Captures arrive after the next agent heartbeat. '
                'Poll /drift/content?path=... to retrieve.',
    })


def handle_drift_get_content(dev_id):
    """GET /api/devices/<id>/drift/content?path=...

    Returns stored captures for a single path. Up to
    MAX_DRIFT_CONTENT_CAPTURES (currently 2) chronologically — when the
    operator has fetched the path twice, the UI gets baseline+current
    and can render a diff.

    Response: {captures: [{ts, rc, content, sha256}], path, denied}
    """
    require_auth()
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    qs = urllib.parse.parse_qs(os.environ.get('QUERY_STRING', '') or '')
    path = (qs.get('path') or [''])[0]
    if not path or not path.startswith('/'):
        respond(400, {'error': 'path query parameter required'})
    if path in DRIFT_CONTENT_DENYLIST:
        respond(403, {
            'error':  'Path is on the drift-content denylist '
                      '(/etc/shadow and similar). Hash tracking continues; '
                      'content retrieval is refused regardless of role.',
            'denied': True, 'path': path,
        })
    store = load(DRIFT_CONTENTS_FILE)
    captures = (store.get(dev_id) or {}).get(path) or []
    # Add sha256 of each capture so the UI can confirm which capture
    # matches which baseline/current hash from the drift state.
    enriched = []
    for c in captures:
        sha = hashlib.sha256((c.get('content') or '').encode('utf-8',
                                                              'replace')).hexdigest()
        enriched.append({
            'ts':      c.get('ts'),
            'rc':      c.get('rc'),
            'content': c.get('content', ''),
            'sha256':  f"sha256:{sha}",
        })
    respond(200, {'path': path, 'captures': enriched})


def handle_export():
    """Export backup ZIP.

    Secrets are redacted: apikeys.json key values, and (v2.3.1) the
    password / token fields in config.json — the Proxmox API token
    secret, the SMTP password, and the LDAP bind password. Before
    v2.3.1 config.json went into the ZIP verbatim, so a backup file
    carried live credentials; that's the leak this closes.
    """
    require_admin_auth()
    import zipfile, io
    buf = io.BytesIO()
    exclude = {'tokens.json', 'longpoll.json', 'ratelimit.json'}
    # config.json keys whose values are secrets and must be redacted
    # out of the backup. Keeping the key (with a marker value) rather
    # than dropping it means a restored backup is structurally intact
    # and the operator can see at a glance that a secret needs
    # re-entering.
    config_secret_keys = ('proxmox_token_secret', 'smtp_password',
                          'ldap_bind_password')
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for f in DATA_DIR.glob('*.json'):
            if f.name in exclude:
                continue
            if f.name == 'apikeys.json':
                # Redact key values in backup
                raw = load(f)
                redacted = {kid: {**v, 'key': '(redacted)'}
                            for kid, v in raw.items()}
                zf.writestr('apikeys.json', json.dumps(redacted, indent=2))
            elif f.name == 'config.json':
                # Redact secret fields — see config_secret_keys above.
                raw = load(f)
                if isinstance(raw, dict):
                    for k in config_secret_keys:
                        if raw.get(k):
                            raw[k] = '(redacted)'
                zf.writestr('config.json', json.dumps(raw, indent=2))
            else:
                zf.write(f, f.name)
    data = buf.getvalue(); ts = time.strftime('%Y%m%d-%H%M%S')
    print("Status: 200 OK"); print("Content-Type: application/zip")
    print(f"Content-Disposition: attachment; filename=remotepower-backup-{ts}.zip")
    print(f"Content-Length: {len(data)}"); print("Cache-Control: no-store")
    print("X-Content-Type-Options: nosniff"); print()
    sys.stdout.flush(); sys.stdout.buffer.write(data); sys.stdout.buffer.flush(); sys.exit(0)


def handle_revoke_sessions():
    """Revoke all sessions for a specific user or all users."""
    requester = require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    target_user = _sanitize_str(body.get('username', ''), 32)
    tokens = load(TOKENS_FILE)
    if target_user:
        pruned = {k: v for k, v in tokens.items() if v.get('user') != target_user}
        count = len(tokens) - len(pruned)
    else:
        # Revoke all except requester's current session
        current_token = get_token_from_request()
        pruned = {k: v for k, v in tokens.items() if k == current_token}
        count = len(tokens) - len(pruned)
    save(TOKENS_FILE, pruned)
    audit_log(requester, 'revoke_sessions', f'target={target_user or "all"}, revoked={count}')
    respond(200, {'ok': True, 'revoked': count})


def handle_apikeys_list():
    require_admin_auth()
    apikeys = load(APIKEYS_FILE)
    respond(200, [{'id': kid, 'name': v.get('name', ''), 'user': v.get('user', ''),
                   'role': v.get('role', 'admin'), 'created': v.get('created', 0),
                   'active': v.get('active', True)}
                  for kid, v in apikeys.items()])


def handle_apikeys_create():
    require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    name = _sanitize_str(body.get('name', ''), 64)
    role = body.get('role', 'admin')
    user = _sanitize_str(body.get('user', 'api'), 32)
    if not name: respond(400, {'error': 'name required'})
    if role not in ('admin', 'viewer'): respond(400, {'error': 'role must be admin or viewer'})
    apikeys = load(APIKEYS_FILE)
    if len(apikeys) >= 50: respond(400, {'error': 'API key limit reached (max 50)'})
    key_value = secrets.token_urlsafe(40)
    kid       = secrets.token_hex(8)
    expires_at = body.get('expires_at')
    if expires_at is not None:
        try:
            expires_at = int(expires_at)
            if expires_at <= int(time.time()):
                respond(400, {'error': 'expires_at must be in the future'})
        except (ValueError, TypeError):
            respond(400, {'error': 'expires_at must be a unix timestamp'})
    apikeys[kid] = {'name': name, 'key': key_value, 'user': user, 'role': role,
                    'created': int(time.time()), 'active': True,
                    'expires_at': expires_at}
    save(APIKEYS_FILE, apikeys)
    respond(201, {'ok': True, 'id': kid, 'key': key_value,
                  'note': 'Store this key securely — it will not be shown again.'})


def handle_apikeys_delete(kid):
    require_admin_auth()
    if method() != 'DELETE': respond(405, {'error': 'Method not allowed'})
    if not _validate_id(kid): respond(404, {'error': 'API key not found'})
    apikeys = load(APIKEYS_FILE)
    if kid not in apikeys: respond(404, {'error': 'API key not found'})
    del apikeys[kid]; save(APIKEYS_FILE, apikeys)
    respond(200, {'ok': True})


def _resolve_longpoll(dev_id, cmd_output):
    lp = load(LONGPOLL_FILE)
    if dev_id in lp:
        lp[dev_id]['output'] = cmd_output
        lp[dev_id]['ready']  = True
        save(LONGPOLL_FILE, lp)


def handle_longpoll_exec():
    actor = require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    body    = get_json_body()
    dev_id  = str(body.get('device_id', '')).strip()
    cmd_str = str(body.get('cmd', '')).strip()

    try:
        timeout = int(body.get('timeout', 90))
        timeout = max(10, min(timeout, 120))
    except (ValueError, TypeError):
        timeout = 90

    if not _validate_id(dev_id): respond(404, {'error': 'Device not found'})
    if not cmd_str: respond(400, {'error': 'cmd required'})
    if len(cmd_str) > 512: respond(400, {'error': 'cmd too long'})

    devices = load(DEVICES_FILE)
    if dev_id not in devices: respond(404, {'error': 'Device not found'})

    # Apply the same allowlist check as handle_custom_cmd
    ok, reason = _check_exec_allowlist(dev_id, cmd_str, devices)
    if not ok: respond(403, {'error': reason})

    lp = load(LONGPOLL_FILE)
    lp[dev_id] = {'cmd': cmd_str, 'ready': False, 'output': None, 'ts': int(time.time())}
    save(LONGPOLL_FILE, lp)

    cmds = load(CMDS_FILE)
    if dev_id not in cmds: cmds[dev_id] = []
    cmds[dev_id].append(f'exec:{cmd_str}')
    save(CMDS_FILE, cmds)
    log_command(actor, dev_id, devices[dev_id].get('name', dev_id), f'exec(wait):{cmd_str[:40]}')

    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(1)
        lp   = load(LONGPOLL_FILE)
        slot = lp.get(dev_id, {})
        if slot.get('ready'):
            output = slot.get('output', {})
            del lp[dev_id]; save(LONGPOLL_FILE, lp)
            respond(200, {'ok': True, 'output': output})

    lp = load(LONGPOLL_FILE); lp.pop(dev_id, None); save(LONGPOLL_FILE, lp)
    respond(200, {'ok': False, 'timeout': True,
                  'message': 'Output not received within timeout — poll /output endpoint'})


def handle_digest():
    require_auth()
    devices = load(DEVICES_FILE); now = int(time.time())
    online  = sum(1 for d in devices.values() if (now - d.get('last_seen', 0)) < get_online_ttl())
    patches = sum(
        (d.get('sysinfo', {}).get('packages', {}).get('upgradable') or 0)
        for d in devices.values()
        if isinstance(d.get('sysinfo', {}).get('packages', {}).get('upgradable'), int)
    )
    recent_cmds = load(HISTORY_FILE).get('entries', [])[-10:]
    respond(200, {
        'ts': now, 'total': len(devices), 'online': online,
        'offline': len(devices) - online, 'pending_patches': patches,
        'recent_commands': recent_cmds,
    })


# ── Patch report ─────────────────────────────────────────────────────────────
def handle_patch_report():
    """Return detailed patch information across all devices."""
    require_auth()
    devices = load(DEVICES_FILE)
    now = int(time.time())
    report = {
        'generated_at': now,
        'server_version': SERVER_VERSION,
        'devices': [],
        'summary': {
            'total_devices': len(devices),
            'devices_with_patches': 0,
            'devices_fully_patched': 0,
            'devices_no_data': 0,
            'total_pending_patches': 0,
        }
    }
    for dev_id, dev in devices.items():
        si = dev.get('sysinfo', {})
        pkg = si.get('packages', {})
        upgradable = pkg.get('upgradable')
        is_online = (now - dev.get('last_seen', 0)) < get_online_ttl()

        entry = {
            'device_id': dev_id,
            'name': dev.get('name', dev_id),
            'hostname': dev.get('hostname', ''),
            'group': dev.get('group', ''),
            'tags': dev.get('tags', []),
            'os': dev.get('os', ''),
            'online': is_online,
            'last_seen': dev.get('last_seen', 0),
            'pkg_manager': pkg.get('manager', 'unknown'),
            'upgradable': upgradable,
            'patch_status': 'unknown',
            # reboot_required: True when /run/reboot-required exists on the host
            # (Debian/Ubuntu); False or absent on other distros / older agents.
            'reboot_required': bool(si.get('reboot_required', False)),
        }

        if upgradable is None or not is_online:
            entry['patch_status'] = 'no_data'
            report['summary']['devices_no_data'] += 1
        elif upgradable == 0:
            entry['patch_status'] = 'fully_patched'
            report['summary']['devices_fully_patched'] += 1
        else:
            entry['patch_status'] = 'patches_available'
            report['summary']['devices_with_patches'] += 1
            report['summary']['total_pending_patches'] += upgradable

        # Recent exec history for patch commands
        outputs = load(CMD_OUTPUT_FILE).get(dev_id, [])
        patch_cmds = [o for o in outputs if any(kw in o.get('cmd', '')
                      for kw in ('apt', 'dnf', 'pacman', 'upgrade', 'update'))]
        entry['recent_patch_commands'] = patch_cmds[-5:]

        report['devices'].append(entry)

    # Patch percentage: only among ONLINE devices that have reported data
    online_with_data = report['summary']['devices_fully_patched'] + report['summary']['devices_with_patches']
    patched = report['summary']['devices_fully_patched']
    report['summary']['online_with_data'] = online_with_data
    report['summary']['patch_percentage'] = round((patched / online_with_data * 100) if online_with_data > 0 else 0, 1)

    report['devices'].sort(key=lambda x: (-(x.get('upgradable') or 0), x['name'].lower()))
    respond(200, report)


def handle_patch_report_device(dev_id):
    """Return detailed patch report for a single device."""
    require_auth()
    if not _validate_id(dev_id): respond(404, {'error': 'Device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices: respond(404, {'error': 'Device not found'})
    dev = devices[dev_id]
    now = int(time.time())
    si = dev.get('sysinfo', {})
    pkg = si.get('packages', {})
    upgradable = pkg.get('upgradable')
    is_online = (now - dev.get('last_seen', 0)) < get_online_ttl()

    # All exec output related to patching
    outputs = load(CMD_OUTPUT_FILE).get(dev_id, [])
    patch_cmds = [o for o in outputs if any(kw in o.get('cmd', '')
                  for kw in ('apt', 'dnf', 'pacman', 'upgrade', 'update', 'yum'))]

    # Metrics history
    metrics = load(METRICS_FILE).get(dev_id, [])

    report = {
        'device_id': dev_id,
        'name': dev.get('name', dev_id),
        'hostname': dev.get('hostname', ''),
        'group': dev.get('group', ''),
        'tags': dev.get('tags', []),
        'os': dev.get('os', ''),
        'online': is_online,
        'last_seen': dev.get('last_seen', 0),
        'enrolled': dev.get('enrolled', 0),
        'version': dev.get('version', ''),
        'pkg_manager': pkg.get('manager', 'unknown'),
        'upgradable': upgradable,
        'patch_status': 'no_data' if upgradable is None else ('fully_patched' if upgradable == 0 else 'patches_available'),
        'uptime': si.get('uptime', ''),
        'platform': si.get('platform', ''),
        'patch_history': patch_cmds[-20:],
        'latest_metrics': metrics[-10:] if metrics else [],
    }
    respond(200, report)


def _filter_devices_for_export():
    """Filter devices by query params: group, device_id."""
    from urllib.parse import parse_qs
    qs = parse_qs(os.environ.get('QUERY_STRING', ''))
    group_filter = qs.get('group', [''])[0].strip()
    device_filter = qs.get('device_id', [''])[0].strip()
    devices = load(DEVICES_FILE)
    filtered = {}
    for dev_id, dev in devices.items():
        if group_filter and dev.get('group', '') != group_filter:
            continue
        if device_filter and dev_id != device_filter:
            continue
        filtered[dev_id] = dev
    return filtered


def handle_patch_report_csv():
    """Return patch report as CSV."""
    require_auth()
    devices = _filter_devices_for_export()
    now = int(time.time())
    import csv, io
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['Device', 'Hostname', 'Group', 'OS', 'Online', 'Pkg Manager',
                     'Pending Updates', 'Patch Status', 'Last Seen'])
    for dev_id, dev in sorted(devices.items(), key=lambda x: x[1].get('name', '').lower()):
        si = dev.get('sysinfo', {})
        pkg = si.get('packages', {})
        upgradable = pkg.get('upgradable')
        is_online = (now - dev.get('last_seen', 0)) < get_online_ttl()
        status = 'no_data' if (upgradable is None or not is_online) else ('fully_patched' if upgradable == 0 else 'patches_available')
        last_seen_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(dev.get('last_seen', 0))) if dev.get('last_seen') else 'never'
        writer.writerow([
            dev.get('name', dev_id), dev.get('hostname', ''), dev.get('group', ''),
            dev.get('os', ''), 'yes' if is_online else 'no',
            pkg.get('manager', 'unknown'), upgradable if upgradable is not None else 'N/A',
            status, last_seen_str
        ])
    data = buf.getvalue().encode()
    ts = time.strftime('%Y%m%d-%H%M%S')
    print("Status: 200 OK")
    print("Content-Type: text/csv")
    print(f"Content-Disposition: attachment; filename=patch-report-{ts}.csv")
    print(f"Content-Length: {len(data)}")
    print("Cache-Control: no-store")
    print("X-Content-Type-Options: nosniff")
    print()
    sys.stdout.flush()
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()
    sys.exit(0)


def handle_patch_report_xml():
    """Return patch report as XML."""
    require_auth()
    devices = _filter_devices_for_export()
    now = int(time.time())
    from xml.etree.ElementTree import Element, SubElement, tostring
    root = Element('PatchReport')
    root.set('generated', time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(now)))
    root.set('serverVersion', SERVER_VERSION)
    summary = SubElement(root, 'Summary')
    total = len(devices)
    patched = 0; pending = 0; no_data = 0; with_patches = 0
    devs_el = SubElement(root, 'Devices')
    for dev_id, dev in sorted(devices.items(), key=lambda x: x[1].get('name', '').lower()):
        si = dev.get('sysinfo', {})
        pkg = si.get('packages', {})
        upgradable = pkg.get('upgradable')
        is_online = (now - dev.get('last_seen', 0)) < get_online_ttl()
        d_el = SubElement(devs_el, 'Device')
        d_el.set('id', dev_id)
        SubElement(d_el, 'Name').text = dev.get('name', dev_id)
        SubElement(d_el, 'Hostname').text = dev.get('hostname', '')
        SubElement(d_el, 'Group').text = dev.get('group', '')
        SubElement(d_el, 'OS').text = dev.get('os', '')
        SubElement(d_el, 'Online').text = str(is_online).lower()
        SubElement(d_el, 'PkgManager').text = pkg.get('manager', 'unknown')
        SubElement(d_el, 'PendingUpdates').text = str(upgradable) if upgradable is not None else 'N/A'
        if upgradable is None or not is_online: status = 'no_data'; no_data += 1
        elif upgradable == 0: status = 'fully_patched'; patched += 1
        else: status = 'patches_available'; with_patches += 1; pending += upgradable
        SubElement(d_el, 'PatchStatus').text = status
    SubElement(summary, 'TotalDevices').text = str(total)
    SubElement(summary, 'FullyPatched').text = str(patched)
    SubElement(summary, 'WithPatches').text = str(with_patches)
    SubElement(summary, 'NoData').text = str(no_data)
    SubElement(summary, 'TotalPendingPatches').text = str(pending)
    online_with_data = patched + with_patches
    SubElement(summary, 'OnlineWithData').text = str(online_with_data)
    SubElement(summary, 'PatchPercentage').text = str(round((patched / online_with_data * 100) if online_with_data > 0 else 0, 1))
    xml_str = tostring(root, encoding='unicode')
    data = ('<?xml version="1.0" encoding="UTF-8"?>\n' + xml_str).encode('utf-8')
    ts = time.strftime('%Y%m%d-%H%M%S')
    print("Status: 200 OK")
    print("Content-Type: application/xml")
    print(f"Content-Disposition: attachment; filename=patch-report-{ts}.xml")
    print(f"Content-Length: {len(data)}")
    print("Cache-Control: no-store")
    print("X-Content-Type-Options: nosniff")
    print()
    sys.stdout.flush()
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()
    sys.exit(0)



def handle_audit_log():
    require_admin_auth()
    al = load(AUDIT_LOG_FILE)
    respond(200, list(reversed(al.get('entries', []))))


def handle_audit_log_clear():
    actor = require_admin_auth()
    if method() != 'DELETE': respond(405, {'error': 'Method not allowed'})
    save(AUDIT_LOG_FILE, {'entries': []})
    # Log the clear itself as the first new entry
    audit_log(actor, 'clear_audit_log', 'audit log cleared')
    respond(200, {'ok': True})


def handle_webhook_test():
    """Send a test webhook to verify the URL is working."""
    actor = require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})
    cfg = load(CONFIG_FILE)
    url = cfg.get('webhook_url', '').strip()
    if not url:
        respond(400, {'error': 'No webhook URL configured — set one in Settings first'})
    fire_webhook('test', {
        'server_version': SERVER_VERSION,
        'triggered_by': actor,
    })
    audit_log(actor, 'webhook_test', f'test webhook fired to {url[:80]}')
    # Return the most recent log entry so the UI can show success/failure
    wl = load(WEBHOOK_LOG_FILE)
    entries = wl.get('entries', [])
    last = entries[-1] if entries else None
    respond(200, {'ok': True, 'result': last})


def handle_fleet_events():
    """v2.2.4: GET /api/fleet/events — return the fleet event log.

    Records of every fleet event that fired, regardless of whether any
    webhook / email destination was configured. Powers the Home
    dashboard activity panel. Newest first.

    Optional ?limit=N (default 50, max 200).

    Auth: require_auth (any logged-in user) — unlike the webhook log
    which is admin-only (delivery URLs and detailed errors could leak
    information). Fleet events are operationally useful for viewers
    too: knowing a device went offline is the kind of thing a viewer
    operator should see.
    """
    require_auth()
    store = load(FLEET_EVENTS_FILE)
    events = (store or {}).get('events') or []
    qs = urllib.parse.parse_qs(os.environ.get('QUERY_STRING', '') or '')
    try:
        limit = int((qs.get('limit') or ['50'])[0])
    except ValueError:
        limit = 50
    limit = max(1, min(MAX_FLEET_EVENTS, limit))

    # v2.3.4: exclude events belonging to unmonitored devices. A device
    # the operator has explicitly set monitored=false should not appear
    # in the activity feed, timelines, or any aggregation. Filtered at
    # READ time (not record time) so it reflects the CURRENT monitored
    # state — re-monitoring a device brings its history back, and we
    # never silently drop events that might matter later.
    devices = load(DEVICES_FILE) or {}
    unmonitored = {dev_id for dev_id, d in devices.items()
                   if isinstance(d, dict) and d.get('monitored') is False}
    if unmonitored:
        events = [e for e in events
                  if (e.get('payload') or {}).get('device_id') not in unmonitored]

    # Newest first
    respond(200, list(reversed(events))[:limit])


def handle_webhook_log():
    """Return the webhook delivery log."""
    require_admin_auth()
    wl = load(WEBHOOK_LOG_FILE)
    # v2.2.2: tolerate both the canonical {entries: [...]} shape AND
    # a bare list (older deployments, or hand-edited files). Reading
    # both is cheap; deciding to upgrade the format on read isn't —
    # operators may have other tooling assuming the bare-list shape,
    # so we just normalise for the response and leave disk alone.
    if isinstance(wl, list):
        entries = wl
    elif isinstance(wl, dict):
        entries = wl.get('entries', []) or []
    else:
        entries = []
    respond(200, list(reversed(entries)))


def handle_webhook_log_clear():
    """Clear the webhook delivery log."""
    actor = require_admin_auth()
    if method() != 'DELETE': respond(405, {'error': 'Method not allowed'})
    save(WEBHOOK_LOG_FILE, {'entries': []})
    audit_log(actor, 'clear_webhook_log', 'webhook log cleared')
    respond(200, {'ok': True})


# ─── v1.8.6: SMTP test endpoint ───────────────────────────────────────────────

def handle_smtp_test():
    """
    POST /api/smtp/test
    Sends a test email using current settings (or override config in body).
    Body may include 'recipient' to override the configured recipient list.
    """
    actor = require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})

    body = get_json_body() if os.environ.get('CONTENT_LENGTH', '0') != '0' else {}
    cfg = load(CONFIG_FILE)
    override_recipient = _sanitize_str(body.get('recipient', ''), 320)

    if override_recipient:
        if '@' not in override_recipient:
            respond(400, {'error': 'recipient must be a valid email address'})
        recipients = [override_recipient]
    else:
        recipients = _smtp_recipients_list(cfg)
    if not recipients:
        respond(400, {'error': 'No recipients configured. Set "smtp_recipients" or pass {"recipient": "..."}'})

    server_name = get_server_name()
    try:
        result = smtp_notifier.send_email(
            cfg, recipients,
            subject=f'[{server_name}] Test email from RemotePower',
            body=(
                f'This is a test email from {server_name}.\n\n'
                f'Triggered by: {actor}\n'
                f'Server version: {SERVER_VERSION}\n'
                f'Timestamp: {time.strftime("%Y-%m-%d %H:%M:%S %Z")}\n\n'
                'If you received this, your SMTP configuration works correctly.\n'
                'If you did NOT request this email, someone with admin access '
                'on the RemotePower server triggered it. Investigate.\n'
            ),
        )
        _log_email('test', recipients, 'ok', f'test sent to {len(recipients)} recipient(s)')
        audit_log(actor, 'smtp_test', f'test email sent to {len(recipients)} recipient(s)')
        respond(200, {'ok': True, 'recipients': recipients, 'result': result})
    except smtp_notifier.SmtpError as e:
        _log_email('test', recipients, 'error', str(e))
        audit_log(actor, 'smtp_test_failed', str(e))
        respond(200, {'ok': False, 'error': str(e), 'recipients': recipients})


# ─── v1.8.6: LDAP test endpoints ──────────────────────────────────────────────

def handle_ldap_test():
    """
    POST /api/ldap/test
    Verifies the service-account bind to LDAP. Doesn't try to authenticate
    a specific user. Useful for confirming URL/TLS/credentials before
    enabling LDAP login.
    """
    actor = require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})

    body = get_json_body() if os.environ.get('CONTENT_LENGTH', '0') != '0' else {}
    cfg = load(CONFIG_FILE)

    # Allow body to override config for "try before save" UX
    test_cfg = dict(cfg)
    for k in ('ldap_url', 'ldap_bind_dn', 'ldap_bind_password',
              'ldap_user_base', 'ldap_user_filter', 'ldap_tls_verify', 'ldap_timeout'):
        if k in body:
            test_cfg[k] = body[k]

    result = ldap_auth.test_connection(test_cfg)
    audit_log(actor, 'ldap_test',
              f'{"success" if result.get("ok") else "failed"}: {result.get("detail", "")[:200]}')
    respond(200, result)


def handle_ldap_test_user():
    """
    POST /api/ldap/test-user {"username":"alice","password":"..."}
    Runs the full authentication path for one user. Returns the resolved DN,
    role, and group-derived flags. Doesn't create a session.
    """
    actor = require_admin_auth()
    if method() != 'POST': respond(405, {'error': 'Method not allowed'})

    body = get_json_body()
    username = _sanitize_str(body.get('username', ''), 64)
    password = body.get('password', '')
    if not username or not isinstance(password, str):
        respond(400, {'error': 'username and password are required'})

    cfg = load(CONFIG_FILE)
    if not cfg.get('ldap_enabled'):
        respond(400, {'error': 'LDAP is not enabled — turn it on first'})

    try:
        info = ldap_auth.authenticate(cfg, username, password)
        audit_log(actor, 'ldap_test_user',
                  f'tested {username} → role={info.role}, dn={info.dn}')
        respond(200, {
            'ok':         True,
            'dn':         info.dn,
            'role':       info.role,
            'full_name':  info.full_name,
            'email':      info.email,
            'username':   info.username,
        })
    except ldap_auth.LdapAuthDenied as e:
        respond(200, {'ok': False, 'error': f'auth denied: {e}'})
    except ldap_auth.LdapTransientError as e:
        respond(200, {'ok': False, 'error': f'LDAP error: {e}'})


def handle_monitor_alerts_clear():
    """Reset monitor alert state so alerts can re-fire."""
    actor = require_admin_auth()
    if method() != 'DELETE': respond(405, {'error': 'Method not allowed'})
    cfg = load(CONFIG_FILE)
    cfg['monitor_notified'] = {}
    cfg['offline_notified'] = {}
    save(CONFIG_FILE, cfg)
    audit_log(actor, 'clear_monitor_alerts', 'monitor alert state reset')
    respond(200, {'ok': True})


# ─── v1.7.0: CVE scanner + package inventory ──────────────────────────────────

def _sanitize_package_entry(entry):
    """Sanitize one {name,version,arch} dict from agent payload."""
    if not isinstance(entry, dict):
        return None
    name = _sanitize_str(entry.get('name', ''), 128, allow_empty=False)
    version = _sanitize_str(entry.get('version', ''), 64, allow_empty=False)
    arch = _sanitize_str(entry.get('arch', ''), 16)
    if not name or not version:
        return None
    # Package names / versions are alphanum + common punctuation
    if not re.match(r'^[A-Za-z0-9][A-Za-z0-9._+\-:~]{0,127}$', name):
        return None
    if not re.match(r'^[A-Za-z0-9][A-Za-z0-9._+\-:~]{0,63}$', version):
        return None
    return {'name': name, 'version': version, 'arch': arch}


def handle_packages_submit():
    """POST /api/packages — agent submits its installed package list."""
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})

    body = get_json_body()
    dev_id    = str(body.get('device_id', '')).strip()
    dev_token = str(body.get('token', '')).strip()
    if not _validate_id(dev_id):
        respond(403, {'error': 'Unauthorized device'})

    devices = load(DEVICES_FILE)
    dev = devices.get(dev_id)
    if not dev or not hmac.compare_digest(dev.get('token', ''), dev_token):
        respond(403, {'error': 'Unauthorized device'})

    raw_pkgs = body.get('packages') or []
    if not isinstance(raw_pkgs, list):
        respond(400, {'error': 'packages must be a list'})
    if len(raw_pkgs) > MAX_PACKAGE_LIST:
        raw_pkgs = raw_pkgs[:MAX_PACKAGE_LIST]

    packages = []
    for entry in raw_pkgs:
        safe = _sanitize_package_entry(entry)
        if safe:
            packages.append(safe)

    pkg_manager = _sanitize_str(body.get('pkg_manager', ''), 16)
    hint = body.get('ecosystem_hint') or {}
    safe_hint = {
        'ID':         _sanitize_str(hint.get('ID', ''), 32),
        'VERSION_ID': _sanitize_str(hint.get('VERSION_ID', ''), 16),
        'ID_LIKE':    _sanitize_str(hint.get('ID_LIKE', ''), 64),
    }

    ecosystem = cve_scanner.detect_ecosystem(safe_hint, pkg_manager)

    store = load(PACKAGES_FILE)
    new_hash = cve_scanner.packages_hash(packages)
    existing = store.get(dev_id, {})
    store[dev_id] = {
        'hash':         new_hash,
        'collected_at': int(time.time()),
        'ecosystem':    ecosystem or '',
        'pkg_manager':  pkg_manager,
        'count':        len(packages),
        'packages':     packages,
    }
    save(PACKAGES_FILE, store)

    changed = existing.get('hash') != new_hash
    respond(200, {
        'ok':              True,
        'ecosystem':       ecosystem or 'unsupported',
        'packages_stored': len(packages),
        'changed':         changed,
        'scan_suggested':  changed and bool(ecosystem),
    })


def _detect_new_cve_and_fire_webhook(dev_id, devices, previous, current):
    """Fire webhook if new CVEs in the configured severity filter appeared since last scan."""
    if not is_webhook_event_enabled('cve_found'):
        return

    ignore_data = load(CVE_IGNORE_FILE)
    prev_ids = {f['vuln_id'] for f in previous}
    severity_filter = set(get_cve_severity_filter())

    new_alerted = []
    for f in current:
        if f['vuln_id'] in prev_ids:
            continue
        if f.get('severity') not in severity_filter:
            continue
        ig = ignore_data.get(f['vuln_id'])
        if ig and (ig.get('scope') == 'global' or ig.get('scope') == dev_id):
            continue
        new_alerted.append(f)

    if not new_alerted:
        return

    dev = devices.get(dev_id, {})
    fire_webhook('cve_found', {
        'device_id':  dev_id,
        'name':       dev.get('name', dev_id),
        'count':      len(new_alerted),
        'critical':   sum(1 for f in new_alerted if f['severity'] == 'critical'),
        'high':       sum(1 for f in new_alerted if f['severity'] == 'high'),
        'sample':     [{'id': f['vuln_id'], 'pkg': f['package'], 'sev': f['severity']}
                       for f in new_alerted[:5]],
    })


def handle_cve_scan():
    """POST /api/cve/scan — admin triggers scan for one or all devices."""
    actor = require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})

    body = get_json_body() if os.environ.get('CONTENT_LENGTH', '0') != '0' else {}
    target = body.get('device_id')
    if target is not None:
        target = str(target).strip()
        if not _validate_id(target):
            respond(400, {'error': 'Invalid device_id'})

    store = load(PACKAGES_FILE)
    findings_all = load(CVE_FINDINGS_FILE)
    devices = load(DEVICES_FILE)

    scanned = []
    skipped = []
    errors  = []

    targets = [target] if target else list(store.keys())

    for dev_id in targets:
        entry = store.get(dev_id)
        if not entry:
            skipped.append({'device_id': dev_id, 'reason': 'no package list submitted yet'})
            continue
        ecosystem = entry.get('ecosystem') or ''
        if not ecosystem:
            skipped.append({'device_id': dev_id, 'reason': 'unsupported ecosystem'})
            continue

        result = cve_scanner.scan_device(
            dev_id,
            entry.get('packages') or [],
            ecosystem,
            DATA_DIR,
            cache_ttl=get_cve_cache_seconds(),
        )

        if result.get('error') and not result.get('findings'):
            errors.append({'device_id': dev_id, 'error': result['error']})
            continue

        previous = findings_all.get(dev_id, {}).get('findings') or []
        findings_all[dev_id] = result
        _detect_new_cve_and_fire_webhook(dev_id, devices, previous, result.get('findings') or [])
        scanned.append({'device_id': dev_id, 'findings': len(result.get('findings') or [])})

    save(CVE_FINDINGS_FILE, findings_all)
    audit_log(actor, 'cve_scan',
              detail=f'scanned={len(scanned)} skipped={len(skipped)} errors={len(errors)}')
    respond(200, {'scanned': scanned, 'skipped': skipped, 'errors': errors})


def handle_cve_findings():
    """GET /api/cve/findings — aggregate CVE report across all devices."""
    require_auth()
    findings_all = load(CVE_FINDINGS_FILE)
    ignore_data  = load(CVE_IGNORE_FILE)
    pkg_store    = load(PACKAGES_FILE)
    devices      = load(DEVICES_FILE)
    now = int(time.time())

    report = {
        'generated_at': now,
        'devices':      [],
        'summary':      {'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
                         'unknown':  0, 'ignored':  0, 'devices_scanned': 0,
                         'devices_with_findings': 0,
                         'devices_unsupported': 0},
    }

    for dev_id, dev in devices.items():
        pkg_entry = pkg_store.get(dev_id) or {}
        ecosystem = pkg_entry.get('ecosystem', '')
        f_entry = findings_all.get(dev_id) or {}
        findings = f_entry.get('findings') or []
        summary = cve_scanner.summarize_findings(
            findings,
            {k for k, v in ignore_data.items()
             if v.get('scope') == 'global' or v.get('scope') == dev_id}
        )
        status = 'scanned'
        if not pkg_entry:
            status = 'no_packages'
        elif not ecosystem:
            status = 'unsupported'
            report['summary']['devices_unsupported'] += 1
        elif not f_entry:
            status = 'not_scanned'

        if f_entry:
            report['summary']['devices_scanned'] += 1
            if sum(summary[k] for k in ('critical', 'high', 'medium', 'low')) > 0:
                report['summary']['devices_with_findings'] += 1
            for k in ('critical', 'high', 'medium', 'low', 'unknown', 'ignored'):
                report['summary'][k] += summary[k]

        report['devices'].append({
            'device_id':   dev_id,
            'name':        dev.get('name', dev_id),
            'group':       dev.get('group', ''),
            'os':          dev.get('os', ''),
            'ecosystem':   ecosystem or 'unsupported',
            'status':      status,
            'scanned_at':  f_entry.get('scanned_at', 0),
            'package_count': pkg_entry.get('count', 0),
            'counts':      summary,
        })

    report['devices'].sort(
        key=lambda d: (-d['counts']['critical'], -d['counts']['high'], d['name'].lower())
    )
    respond(200, report)


def handle_cve_device(dev_id):
    """GET /api/devices/{id}/cve — detailed findings for one device."""
    require_auth()
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})

    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})

    findings_all = load(CVE_FINDINGS_FILE)
    ignore_data  = load(CVE_IGNORE_FILE)
    pkg_store    = load(PACKAGES_FILE)
    dev = devices[dev_id]

    f_entry   = findings_all.get(dev_id) or {}
    pkg_entry = pkg_store.get(dev_id) or {}
    findings  = f_entry.get('findings') or []
    findings  = cve_scanner.apply_ignore_list(findings, ignore_data, dev_id)

    respond(200, {
        'device_id':      dev_id,
        'name':           dev.get('name', dev_id),
        'group':          dev.get('group', ''),
        'os':             dev.get('os', ''),
        'ecosystem':      pkg_entry.get('ecosystem', '') or 'unsupported',
        'scanned_at':     f_entry.get('scanned_at', 0),
        'packages_count': pkg_entry.get('count', 0),
        'collected_at':   pkg_entry.get('collected_at', 0),
        'findings':       findings,
        'error':          f_entry.get('error', ''),
    })


def handle_cve_ignore_add():
    """POST /api/cve/ignore — mark a vuln as accepted risk."""
    actor = require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})

    body     = get_json_body()
    vuln_id  = _sanitize_str(body.get('vuln_id', ''), 64, allow_empty=False)
    reason   = _sanitize_str(body.get('reason', ''), 256)
    scope    = _sanitize_str(body.get('scope', 'global'), 64)
    if not vuln_id:
        respond(400, {'error': 'vuln_id required'})
    if scope != 'global' and not _validate_id(scope):
        respond(400, {'error': 'scope must be "global" or a valid device_id'})

    ignore_data = load(CVE_IGNORE_FILE)
    ignore_data[vuln_id] = {
        'scope':  scope,
        'reason': reason,
        'actor':  actor,
        'ts':     int(time.time()),
    }
    save(CVE_IGNORE_FILE, ignore_data)
    audit_log(actor, 'cve_ignore_add',
              detail=f'{vuln_id} scope={scope} reason={reason[:80]}')
    respond(200, {'ok': True, 'ignored': vuln_id})


def handle_cve_ignore_delete(vuln_id):
    """DELETE /api/cve/ignore/{vuln_id}"""
    actor = require_admin_auth()
    vuln_id = _sanitize_str(vuln_id, 64, allow_empty=False)
    if not vuln_id:
        respond(400, {'error': 'Invalid vuln_id'})
    ignore_data = load(CVE_IGNORE_FILE)
    if vuln_id in ignore_data:
        del ignore_data[vuln_id]
        save(CVE_IGNORE_FILE, ignore_data)
        audit_log(actor, 'cve_ignore_remove', detail=vuln_id)
    respond(200, {'ok': True})


def handle_cve_ignore_list():
    """GET /api/cve/ignore — list all active ignores."""
    require_auth()
    ignore_data = load(CVE_IGNORE_FILE)
    items = [{'vuln_id': k, **v} for k, v in ignore_data.items()]
    items.sort(key=lambda x: -x.get('ts', 0))
    respond(200, {'ignores': items})


# ─── v1.7.0: Prometheus metrics exporter ──────────────────────────────────────

def handle_prometheus_metrics():
    """
    GET /api/metrics — Prometheus text exposition.
    Auth: X-Token header OR Authorization: Bearer <key> (Prometheus-native).
    """
    token = get_token_from_request()
    if not token:
        auth = os.environ.get('HTTP_AUTHORIZATION', '')
        if auth.lower().startswith('bearer '):
            token = auth[7:].strip()
    username, _role = verify_token(token)
    if not username:
        print('Status: 401 Unauthorized')
        print('Content-Type: text/plain; charset=utf-8')
        print('WWW-Authenticate: Bearer realm="remotepower"')
        print('Cache-Control: no-store')
        print()
        print('Unauthorized')
        sys.exit(0)

    now = int(time.time())
    devices = load(DEVICES_FILE)
    cfg = load(CONFIG_FILE)
    mon_hist = load(MON_HIST_FILE)

    monitor_state = {}
    for label, entries in mon_hist.items():
        if entries:
            last = entries[-1]
            monitor_state[label] = {
                'up':   bool(last.get('up', True)),
                'last': last.get('ts', 0),
            }

    # v1.8.0: maintenance-window context — count currently active
    maint = load(MAINT_FILE)
    maint_active = 0
    for w in (maint.get('windows') or []):
        try:
            if _window_active(w, now):
                maint_active += 1
        except Exception:
            pass

    ctx = {
        'server_version':  SERVER_VERSION,
        'now':             now,
        'online_ttl':      get_online_ttl(),
        'devices':         devices,
        'monitors':        cfg.get('monitors') or [],
        'monitor_state':   monitor_state,
        'schedule':        load(SCHEDULE_FILE),
        'pending_cmds':    load(CMDS_FILE),
        'webhook_log':     load(WEBHOOK_LOG_FILE),
        'webhook_log_cap': MAX_WEBHOOK_LOG,
        'cve_findings':    load(CVE_FINDINGS_FILE),
        'cve_ignore':      load(CVE_IGNORE_FILE),
        'services':        load(SERVICES_FILE),
        'maintenance_active_count': maint_active,
    }
    body = prometheus_export.generate_metrics(ctx)

    print('Status: 200 OK')
    print('Content-Type: text/plain; version=0.0.4; charset=utf-8')
    print('Cache-Control: no-store')
    print()
    print(body)
    sys.exit(0)


# ─── v1.8.0: Maintenance windows ───────────────────────────────────────────────

def _cron_match(expr, ts):
    """
    Very small cron evaluator — 5 fields, no ranges like 1-5, no `@reboot`.
    Supports *, */N, a,b,c, single integers. Matches the minute containing `ts`.
    """
    parts = (expr or '').split()
    if len(parts) != 5:
        return False
    tm = time.localtime(ts)
    # cron weekday: 0=Sun..6=Sat; Python tm_wday: 0=Mon..6=Sun. Convert.
    cron_wday = (tm.tm_wday + 1) % 7
    values = (tm.tm_min, tm.tm_hour, tm.tm_mday, tm.tm_mon, cron_wday)
    for spec, v in zip(parts, values):
        if not _cron_field_match(spec, v):
            return False
    return True


def _cron_field_match(spec, value):
    spec = spec.strip()
    if spec == '*':
        return True
    if spec.startswith('*/'):
        try:
            step = int(spec[2:])
            return step > 0 and value % step == 0
        except ValueError:
            return False
    for part in spec.split(','):
        part = part.strip()
        if not part:
            continue
        try:
            if int(part) == value:
                return True
        except ValueError:
            continue
    return False


def _window_active(window, now):
    """Return True if this maintenance window is active right now."""
    # One-shot: ISO-8601 start + end
    start = window.get('start')
    end   = window.get('end')
    if start and end:
        try:
            # Accept both '2026-05-10T22:00:00Z' and '2026-05-10T22:00:00+00:00'
            s = _parse_iso(start)
            e = _parse_iso(end)
            if s <= now <= e:
                return True
        except ValueError:
            pass
    # Recurring cron window
    cron = window.get('cron')
    dur  = int(window.get('duration', 0) or 0)
    if cron and dur > 0:
        # Check the current minute and each minute in the past `dur` seconds
        # to see if this cron expression matched at a time that's still within
        # its duration. We scan backwards in 60s steps — cheap and good enough.
        for i in range(0, dur, 60):
            probe = now - i
            if _cron_match(cron, probe):
                return True
    return False


def _parse_iso(s):
    """Parse ISO-8601 timestamp → unix ts. Supports 'Z' suffix and +HH:MM."""
    if s.endswith('Z'):
        s = s[:-1] + '+00:00'
    # Python 3.7+ handles the rest
    import datetime as _dt
    return int(_dt.datetime.fromisoformat(s).timestamp())


# Events that maintenance windows can suppress
SUPPRESSIBLE_EVENTS = (
    'device_offline', 'device_online',
    'monitor_down',   'monitor_up',
    'service_down',   'service_up',
    'patch_alert',    'cve_found',
    'log_alert',
)


def in_maintenance(event, payload):
    """
    Return {'reason': ...} if this (event, device) is under an active
    maintenance window, else None. Matches on:
      - payload['device_id']          → device-specific windows
      - device.group                   → group-wide windows
      - window.scope == 'global'       → fleet-wide windows
    """
    if event not in SUPPRESSIBLE_EVENTS:
        return None

    maint = load(MAINT_FILE)
    windows = maint.get('windows') or []
    if not windows:
        return None

    now = int(time.time())
    dev_id = payload.get('device_id', '')
    dev_group = ''
    if dev_id:
        devices = load(DEVICES_FILE)
        dev_group = (devices.get(dev_id, {}).get('group') or '')

    for w in windows:
        scope = (w.get('scope') or 'device').lower()
        # Decide if this window applies to this target
        applies = False
        if scope == 'global':
            applies = True
        elif scope == 'group' and dev_group and w.get('target') == dev_group:
            applies = True
        elif scope == 'device' and dev_id and w.get('target') == dev_id:
            applies = True
        if not applies:
            continue
        if _window_active(w, now):
            # Respect an optional per-window event list (defaults to all)
            allowed = w.get('events')
            if allowed and event not in allowed:
                continue
            return {
                'window_id': w.get('id', ''),
                'reason':    w.get('reason', 'maintenance window active'),
                'scope':     scope,
                'target':    w.get('target', ''),
            }
    return None


def log_suppression(event, payload, info):
    """Append an entry to the maintenance-suppression audit trail."""
    try:
        log = load(MAINT_SUPPRESS_LOG)
        entries = log.get('entries') or []
        entries.append({
            'ts':         int(time.time()),
            'event':      event,
            'device_id':  payload.get('device_id', ''),
            'window_id':  info.get('window_id', ''),
            'reason':     info.get('reason', ''),
            'scope':      info.get('scope', ''),
        })
        entries = entries[-500:]  # keep last 500
        log['entries'] = entries
        save(MAINT_SUPPRESS_LOG, log)
    except Exception:
        pass


def handle_maintenance_list():
    """GET /api/maintenance — list all defined windows + currently active ones."""
    require_auth()
    maint = load(MAINT_FILE)
    windows = maint.get('windows') or []
    now = int(time.time())
    out = []
    for w in windows:
        out.append({**w, 'active': _window_active(w, now)})
    out.sort(key=lambda x: (not x['active'], x.get('reason', '')))
    respond(200, {'windows': out})


def handle_maintenance_add():
    """POST /api/maintenance — create a window."""
    actor = require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})

    body = get_json_body()
    reason = _sanitize_str(body.get('reason', ''), 128)
    scope  = _sanitize_str(body.get('scope', 'device'), 16).lower()
    target = _sanitize_str(body.get('target', ''), 128)
    start  = _sanitize_str(body.get('start', ''), 32)
    end    = _sanitize_str(body.get('end', ''), 32)
    cron   = _sanitize_str(body.get('cron', ''), 64)

    try:
        duration = int(body.get('duration', 0) or 0)
    except (TypeError, ValueError):
        duration = 0

    events = body.get('events') or []
    if not isinstance(events, list):
        events = []
    events = [e for e in events if e in SUPPRESSIBLE_EVENTS][:10]

    if scope not in ('device', 'group', 'global'):
        respond(400, {'error': 'scope must be device, group, or global'})
    if scope == 'device' and not _validate_id(target):
        respond(400, {'error': 'device-scoped window requires a valid target device_id'})
    if scope == 'group' and not target:
        respond(400, {'error': 'group-scoped window requires a target group name'})

    # Must be either (start+end) or (cron+duration) — not both, not neither
    has_oneshot = bool(start and end)
    has_cron    = bool(cron and duration > 0)
    if has_oneshot == has_cron:
        respond(400, {'error': 'specify exactly one of (start+end) or (cron+duration)'})

    if has_oneshot:
        try:
            s = _parse_iso(start); e = _parse_iso(end)
            if e <= s:
                respond(400, {'error': 'end must be after start'})
        except ValueError:
            respond(400, {'error': 'invalid ISO-8601 timestamp'})

    if has_cron:
        if _cron_match(cron, int(time.time())) is False and len(cron.split()) != 5:
            respond(400, {'error': 'cron must have 5 space-separated fields'})
        if duration < 60 or duration > 86400 * 7:
            respond(400, {'error': 'duration must be 60..604800 seconds'})

    window = {
        'id':       secrets.token_hex(8),
        'reason':   reason,
        'scope':    scope,
        'target':   target,
        'start':    start,
        'end':      end,
        'cron':     cron,
        'duration': duration,
        'events':   events,
        'created_by': actor,
        'created_at': int(time.time()),
    }

    maint = load(MAINT_FILE)
    windows = maint.get('windows') or []
    windows.append(window)
    maint['windows'] = windows
    save(MAINT_FILE, maint)
    audit_log(actor, 'maintenance_add',
              detail=f'id={window["id"]} scope={scope} target={target} reason={reason[:60]}')
    respond(200, {'ok': True, 'window': window})


def handle_maintenance_delete(window_id):
    """DELETE /api/maintenance/{id}"""
    actor = require_admin_auth()
    maint = load(MAINT_FILE)
    windows = maint.get('windows') or []
    remaining = [w for w in windows if w.get('id') != window_id]
    if len(remaining) == len(windows):
        respond(404, {'error': 'Window not found'})
    maint['windows'] = remaining
    save(MAINT_FILE, maint)
    audit_log(actor, 'maintenance_delete', detail=f'id={window_id}')
    respond(200, {'ok': True})


def handle_maintenance_suppressions():
    """GET /api/maintenance/suppressions — recent suppression audit trail."""
    require_auth()
    log = load(MAINT_SUPPRESS_LOG)
    respond(200, {'entries': (log.get('entries') or [])[-100:][::-1]})


# ─── v1.8.0: Service monitoring (agent-reported systemd units) ────────────────

def _sanitize_unit_name(name):
    """Allow systemd unit names: letters, digits, @.-_+ and must end in .service
    or have no dot. Just bound length and reject whitespace/path traversal."""
    if not isinstance(name, str):
        return None
    s = name.strip()[:128]
    if not s or not re.match(r'^[A-Za-z0-9][A-Za-z0-9._@+\-]{0,127}$', s):
        return None
    return s


def _sanitize_service_entry(entry):
    if not isinstance(entry, dict):
        return None
    unit   = _sanitize_unit_name(entry.get('unit', ''))
    if not unit:
        return None
    active = str(entry.get('active', 'unknown'))[:16]
    sub    = str(entry.get('sub', ''))[:32]
    since  = entry.get('since') or 0
    try:
        since = int(since)
    except (TypeError, ValueError):
        since = 0
    return {'unit': unit, 'active': active, 'sub': sub, 'since': since}


def _record_service_transition(dev_id, unit, old_active, new_active, ts):
    """Append a transition to service_history.json keyed by (device,unit)."""
    hist = load(SERVICE_HIST_FILE)
    key = f'{dev_id}:{unit}'
    entries = hist.get(key) or []
    entries.append({'ts': ts, 'from': old_active, 'to': new_active})
    entries = entries[-MAX_SERVICE_HIST:]
    hist[key] = entries
    save(SERVICE_HIST_FILE, hist)


def _fire_service_webhook(event, dev_id, unit, payload_extra=None):
    """Wrapper that fires service_up/service_down through fire_webhook."""
    devices = load(DEVICES_FILE)
    dev = devices.get(dev_id, {})
    payload = {
        'device_id': dev_id,
        'name':      dev.get('name', dev_id),
        'group':     dev.get('group', ''),
        'unit':      unit,
    }
    if payload_extra:
        payload.update(payload_extra)
    fire_webhook(event, payload)


def process_service_report(dev_id, services_payload):
    """
    Called from handle_heartbeat. Updates services.json, records transitions,
    fires webhooks on state changes.

    services_payload: [{unit, active, sub, since}, ...]
    """
    if not isinstance(services_payload, list):
        return

    now = int(time.time())
    clean = []
    for entry in services_payload[:MAX_SERVICES_PER_DEVICE]:
        e = _sanitize_service_entry(entry)
        if e:
            clean.append(e)
    if not clean:
        return

    store = load(SERVICES_FILE)
    prev_dev = store.get(dev_id) or {}
    prev_by_unit = {s['unit']: s for s in (prev_dev.get('services') or [])}

    for entry in clean:
        prev = prev_by_unit.get(entry['unit'])
        if not prev:
            continue  # first time we see this unit; no transition yet
        # Normalize: treat anything other than 'active' as "down" for alerting
        was_up = (prev.get('active') == 'active')
        is_up  = (entry['active'] == 'active')
        if was_up != is_up:
            _record_service_transition(
                dev_id, entry['unit'], prev.get('active'), entry['active'], now
            )
            # fire_webhook() respects per-event toggles (v1.8.4)
            event = 'service_up' if is_up else 'service_down'
            _fire_service_webhook(event, dev_id, entry['unit'], {
                'active':    entry['active'],
                'sub':       entry['sub'],
                'previous':  prev.get('active'),
            })

    store[dev_id] = {'updated_at': now, 'services': clean}
    save(SERVICES_FILE, store)


# ─── v1.11.4: container alerting ────────────────────────────────────────────
#
# Same shape as the service report processor: diff this heartbeat against the
# previous one and fire webhooks on transitions. The transitions we care about:
#
#   1. A previously-seen container is now missing or has a non-running status
#      → fire ``container_stopped``. Restart-during-the-poll-window is
#      indistinguishable from a real stop here (we'd need ``docker events``
#      for that), but the webhook lets the operator decide if it's noise.
#
#   2. ``restart_count`` climbed since the last report → fire
#      ``container_restarting``. Only meaningful for Kubernetes pods (Docker
#      ``ps`` doesn't expose it; agent reports 0). Threshold: ``delta >= 1``.
#
# We don't fire ``container_started`` for new entries, mirroring the
# service-up convention of "transitions back to a known state are quieter
# than transitions away from it." Add later if anyone asks.

# Threshold for the restart-count delta to fire the restarting webhook.
# A bare 1 is enough — if a pod restarted, that's something to know.
CONTAINER_RESTART_DELTA_THRESHOLD = 1


# ─── v1.11.10: metric threshold processing ──────────────────────────────────
#
# Fires metric_warning / metric_critical when a resource crosses its
# configured threshold, and metric_recovered when it drops below the
# warn threshold minus the recovery buffer (hysteresis to prevent
# webhook spam from values oscillating around the line).
#
# Per-metric notification state is stored under
# ``dev['metric_state']`` as a dict keyed by ``f"{kind}:{target}"``:
#
#     "disk:/var":   "critical"   — current alert level
#     "memory:":     "warning"
#     "cpu:":        "ok"          — explicit "no alert" state
#
# Transitions:
#   ok       → warning   : fire metric_warning
#   ok       → critical  : fire metric_critical (skip the warning fire)
#   warning  → critical  : fire metric_critical
#   critical → warning   : fire metric_warning  (downgrade)
#   any      → ok        : fire metric_recovered (when value drops below
#                          warn - recovery_buffer; one-shot)
#
# Thresholds resolution order (most-to-least specific):
#   1. devices[id]['metric_thresholds']['disk_per_mount'][path] for disk
#      with a specific mount path
#   2. devices[id]['metric_thresholds'][key] for that kind
#   3. config[key] (global override) — not implemented in v1.11.10 to
#      keep the surface small; per-device covers 95% of real cases.
#   4. DEFAULT_METRIC_THRESHOLDS[key] (the constants at the top of api.py)


def _resolve_metric_thresholds(dev, kind, target=''):
    """Return ``(warn, crit)`` for a given (kind, target) on this device.

    Args:
        dev: the device dict from devices.json.
        kind: one of 'disk', 'memory', 'swap', 'cpu'.
        target: for kind='disk' a mount path; otherwise empty.

    Returns:
        Tuple ``(warn, crit)``. Units are percent for disk/memory/swap,
        load-ratio for cpu.
    """
    overrides = (dev.get('metric_thresholds') or {}) if isinstance(dev, dict) else {}

    if kind == 'disk':
        # Per-mount overrides first
        per_mount = overrides.get('disk_per_mount') or {}
        if isinstance(per_mount, dict) and target in per_mount:
            entry = per_mount[target]
            if isinstance(entry, dict):
                w = entry.get('warn')
                c = entry.get('crit')
                if isinstance(w, (int, float)) and isinstance(c, (int, float)):
                    return float(w), float(c)
        # Per-device disk override
        w = overrides.get('disk_warn_percent', DEFAULT_METRIC_THRESHOLDS['disk_warn_percent'])
        c = overrides.get('disk_crit_percent', DEFAULT_METRIC_THRESHOLDS['disk_crit_percent'])
        return float(w), float(c)

    if kind == 'memory':
        return (float(overrides.get('mem_warn_percent', DEFAULT_METRIC_THRESHOLDS['mem_warn_percent'])),
                float(overrides.get('mem_crit_percent', DEFAULT_METRIC_THRESHOLDS['mem_crit_percent'])))
    if kind == 'swap':
        return (float(overrides.get('swap_warn_percent', DEFAULT_METRIC_THRESHOLDS['swap_warn_percent'])),
                float(overrides.get('swap_crit_percent', DEFAULT_METRIC_THRESHOLDS['swap_crit_percent'])))
    if kind == 'cpu':
        return (float(overrides.get('cpu_warn_load_ratio', DEFAULT_METRIC_THRESHOLDS['cpu_warn_load_ratio'])),
                float(overrides.get('cpu_crit_load_ratio', DEFAULT_METRIC_THRESHOLDS['cpu_crit_load_ratio'])))
    return (None, None)


def _classify_metric(value, warn, crit):
    """Return 'critical' / 'warning' / 'ok' for a numeric value vs thresholds."""
    if value >= crit:
        return 'critical'
    if value >= warn:
        return 'warning'
    return 'ok'


def _below_recovery(value, warn):
    """True if value has dropped far enough below warn to fire 'recovered'."""
    return value < (warn - METRIC_RECOVERY_BUFFER)


def _fire_metric_webhook(event, dev_id, dev, kind, target, value, threshold,
                         extra=None):
    """Wrapper to fire metric_* webhooks with consistent payload shape."""
    payload = {
        'device_id': dev_id,
        'name':      dev.get('name', dev_id),
        'group':     dev.get('group', ''),
        'kind':      kind,
        'target':    target,
        'value':     value,
        'threshold': threshold,
    }
    if extra:
        payload.update(extra)
    fire_webhook(event, payload)


def process_metric_thresholds(dev_id, dev, safe_si):
    """Check each resource against its threshold and fire webhooks on transitions.

    Called from handle_heartbeat after sysinfo storage. Updates
    ``dev['metric_state']`` in place — caller is expected to save the
    devices file (it already does). Updates run before container processing
    so the state from this heartbeat is visible to the rest of the request.

    No-op cleanly when:
        - psutil isn't installed on the agent (no metrics in payload)
        - the device is in a maintenance window (alerts suppressed globally)
        - global metric webhooks are disabled in config
    """
    if not isinstance(safe_si, dict):
        return

    # Note: we deliberately don't check the per-event 'enabled' flag here —
    # fire_webhook() already does that. Suppressing earlier would skip the
    # state-tracking too, which means a transition during the disabled
    # window would be missed when re-enabled. Better to track always and
    # let fire_webhook decide whether to actually deliver.

    state = dev.get('metric_state') or {}
    if not isinstance(state, dict):
        state = {}

    def _check(kind, target, value):
        """Check one metric and fire webhooks on transition."""
        if value is None:
            return
        warn, crit = _resolve_metric_thresholds(dev, kind, target)
        if warn is None:
            return
        new_level = _classify_metric(value, warn, crit)
        key = f'{kind}:{target}'
        prev_level = state.get(key, 'ok')

        if new_level == prev_level:
            # No transition. Special-case: if currently in 'warning' state
            # and value has DROPPED below warn-buffer, fire metric_recovered.
            # This happens if the metric oscillates: it briefly went above
            # warn, came back. Standard hysteresis.
            if prev_level != 'ok' and _below_recovery(value, warn):
                _fire_metric_webhook('metric_recovered', dev_id, dev, kind, target,
                                     value, warn)
                state[key] = 'ok'
            return

        # Transition. Fire the appropriate event.
        if new_level == 'critical':
            _fire_metric_webhook('metric_critical', dev_id, dev, kind, target,
                                 value, crit)
        elif new_level == 'warning':
            _fire_metric_webhook('metric_warning', dev_id, dev, kind, target,
                                 value, warn)
        else:  # new_level == 'ok'
            # Only fire recovered if we're below the buffer; otherwise stay
            # in 'warning' until value drops further. This is the classic
            # hysteresis: don't bounce between ok/warning.
            if _below_recovery(value, warn):
                _fire_metric_webhook('metric_recovered', dev_id, dev, kind, target,
                                     value, warn)
            else:
                # Don't transition to 'ok' yet — the value is below warn but
                # within the recovery buffer. Stay in the previous level so
                # we don't fire 'recovered' prematurely.
                return
        state[key] = new_level

    # Memory
    _check('memory', '', safe_si.get('mem_percent'))
    # Swap
    _check('swap', '', safe_si.get('swap_percent'))
    # CPU as load ratio (loadavg / cpu_count)
    load = safe_si.get('loadavg_1m')
    cpu_count = safe_si.get('cpu_count', 1) or 1
    if isinstance(load, (int, float)) and load >= 0:
        # CPU "value" we compare to threshold is the load ratio itself.
        ratio = load / max(cpu_count, 1)
        # Threshold extras for the webhook payload
        warn, crit = _resolve_metric_thresholds(dev, 'cpu', '')
        new_level = _classify_metric(ratio, warn, crit)
        key = 'cpu:'
        prev_level = state.get(key, 'ok')
        if new_level != prev_level:
            if new_level == 'critical':
                _fire_metric_webhook('metric_critical', dev_id, dev, 'cpu', '',
                                     round(load, 2), crit, {'cpu_count': cpu_count})
            elif new_level == 'warning':
                _fire_metric_webhook('metric_warning', dev_id, dev, 'cpu', '',
                                     round(load, 2), warn, {'cpu_count': cpu_count})
            else:
                if _below_recovery(ratio, warn):
                    _fire_metric_webhook('metric_recovered', dev_id, dev, 'cpu', '',
                                         round(load, 2), warn, {'cpu_count': cpu_count})
                else:
                    return
            state[key] = new_level
        elif prev_level != 'ok' and _below_recovery(ratio, warn):
            _fire_metric_webhook('metric_recovered', dev_id, dev, 'cpu', '',
                                 round(load, 2), warn, {'cpu_count': cpu_count})
            state[key] = 'ok'

    # Disks: per-mount if reported, fall back to legacy disk_percent for /
    mounts = safe_si.get('mounts') or []
    if mounts:
        # Track which keys are seen this report; orphan disk states (mount
        # was unmounted between reports) get silently cleaned up.
        seen_disk_keys = set()
        for m in mounts:
            path = m.get('path')
            pct = m.get('percent')
            if not path or pct is None:
                continue
            seen_disk_keys.add(f'disk:{path}')
            _check('disk', path, pct)
        # Clean orphans
        for key in list(state.keys()):
            if key.startswith('disk:') and key not in seen_disk_keys:
                state.pop(key, None)
    elif safe_si.get('disk_percent') is not None:
        # Pre-v1.11.10 agent: only legacy root-disk metric. Treat as '/'.
        _check('disk', '/', safe_si['disk_percent'])

    dev['metric_state'] = state


def _container_is_running(status_str):
    """Return True if the agent-reported status string suggests "running".

    Mirrors :func:`containers_mod.summarise`'s permissive matching — different
    runtimes phrase status differently ("Up 2 hours", "running", "Ready").
    """
    s = (status_str or '').lower()
    return any(t in s for t in ('running', 'up ', 'up\t', 'ready'))


def _fire_container_webhook(event, dev_id, container_name, payload_extra=None):
    """Wrapper that fires container_stopped / container_restarting via fire_webhook."""
    devices = load(DEVICES_FILE)
    dev = devices.get(dev_id, {})
    payload = {
        'device_id': dev_id,
        'name':      dev.get('name', dev_id),
        'group':     dev.get('group', ''),
        'container': container_name,
    }
    if payload_extra:
        payload.update(payload_extra)
    fire_webhook(event, payload)


def process_container_report(dev_id, normalised, now):
    """Diff a heartbeat's container list against the previous one and fire webhooks.

    Called from :func:`handle_heartbeat` *before* the new list overwrites the
    stored one. Side-effects: zero or more webhook fires. Storage is the
    caller's responsibility — we read CONTAINERS_FILE for the previous state
    but never write it.

    Args:
        dev_id: The reporting device ID.
        normalised: The new list of normalised container dicts (already
            passed through :func:`containers_mod.normalize_listing`).
        now: Current Unix timestamp.
    """
    if not isinstance(normalised, list):
        return

    store = load(CONTAINERS_FILE)
    prev_entry = store.get(dev_id) or {}
    prev_items = prev_entry.get('items') or []
    if not isinstance(prev_items, list):
        prev_items = []

    # First report ever for this device — nothing to diff against.
    # Skip transition detection but DO let storage proceed (caller's job).
    if not prev_items:
        return

    # Index by (runtime, name) to make k8s pods in different namespaces
    # collide-free, and to keep docker/podman containers separate even
    # when they happen to share a name.
    def _key(c):
        return (c.get('runtime', 'unknown'), c.get('namespace', ''), c.get('name', ''))

    new_by_key = {_key(c): c for c in normalised if c.get('name')}
    prev_by_key = {_key(c): c for c in prev_items if c.get('name')}

    # 1) Containers that disappeared or transitioned out of "running"
    for key, prev in prev_by_key.items():
        prev_was_running = _container_is_running(prev.get('status'))
        if not prev_was_running:
            continue  # already-stopped containers don't generate noise
        cur = new_by_key.get(key)
        if cur is None:
            # vanished entirely — docker rm / kubectl delete pod / crashed and
            # was cleaned up by the runtime. Either way: alertable.
            _fire_container_webhook('container_stopped', dev_id, prev.get('name', '?'), {
                'runtime':         prev.get('runtime', 'unknown'),
                'namespace':       prev.get('namespace', ''),
                'image':           prev.get('image', ''),
                'previous_status': prev.get('status', ''),
                'status':          'gone',
            })
        elif not _container_is_running(cur.get('status')):
            # still listed, but no longer running (e.g. "Exited (1) 3s ago")
            _fire_container_webhook('container_stopped', dev_id, prev.get('name', '?'), {
                'runtime':         prev.get('runtime', 'unknown'),
                'namespace':       prev.get('namespace', ''),
                'image':           prev.get('image', ''),
                'previous_status': prev.get('status', ''),
                'status':          cur.get('status', ''),
            })

    # 2) Containers whose restart_count climbed since the last report.
    # Mostly meaningful for Kubernetes (Docker doesn't expose this without
    # `docker inspect`, which the agent skips for performance).
    for key, cur in new_by_key.items():
        prev = prev_by_key.get(key)
        if not prev:
            continue
        try:
            cur_n = int(cur.get('restart_count', 0))
            prev_n = int(prev.get('restart_count', 0))
        except (TypeError, ValueError):
            continue
        delta = cur_n - prev_n
        if delta >= CONTAINER_RESTART_DELTA_THRESHOLD:
            _fire_container_webhook('container_restarting', dev_id, cur.get('name', '?'), {
                'runtime':       cur.get('runtime', 'unknown'),
                'namespace':     cur.get('namespace', ''),
                'image':         cur.get('image', ''),
                'restart_count': cur_n,
                'delta':         delta,
            })


def get_container_stale_ttl():
    """Effective container-staleness TTL in seconds, clamped to a sane minimum.

    The default of 900s (15 min) gives comfortable headroom over the agent's
    5-minute container-report cadence. Operators can tune via the
    ``container_stale_ttl`` config key. Anything under 300s would alert on
    every brief network hiccup, so we floor at that.
    """
    try:
        v = int(_config().get('container_stale_ttl', containers_mod.DEFAULT_STALE_TTL))
    except (TypeError, ValueError):
        v = containers_mod.DEFAULT_STALE_TTL
    return max(300, v)


def check_container_webhooks():
    """Fire ``containers_stale`` for devices whose last container report is old.

    Called from :func:`main` on every CGI request, alongside
    :func:`check_offline_webhooks`. A device fires the webhook at most once
    per stale period — the ``containers_stale_notified`` flag is cleared in
    the heartbeat handler whenever fresh container data arrives.

    Devices that have never reported containers (no entry in
    ``containers.json``) are skipped — they probably just have no runtime
    installed. This is checked, not assumed: an entry with ``ts > 0``
    proves the device once had a runtime, so its silence now is a
    regression worth alerting on.
    """
    if not is_webhook_event_enabled('containers_stale'):
        return
    store = load(CONTAINERS_FILE)
    if not isinstance(store, dict) or not store:
        return
    devices = load(DEVICES_FILE)
    cfg = load(CONFIG_FILE)
    notified = cfg.get('containers_stale_notified') or {}
    if not isinstance(notified, dict):
        notified = {}
    ttl = get_container_stale_ttl()
    now = int(time.time())
    changed = False

    for dev_id, entry in store.items():
        if dev_id not in devices:
            continue
        dev = devices[dev_id]
        # Don't bother for devices the operator deliberately stopped monitoring.
        if not dev.get('monitored', True):
            continue
        # And don't fire while the device itself is offline — there's already
        # a device_offline webhook for that, no point double-paging.
        last_seen = dev.get('last_seen', 0)
        if (now - last_seen) > get_online_ttl():
            continue

        ts = entry.get('ts', 0) if isinstance(entry, dict) else 0
        stale = containers_mod.is_stale(ts, now, ttl)
        already = bool(notified.get(dev_id, False))

        if stale and not already:
            age = max(0, now - int(ts)) if ts else 0
            fire_webhook('containers_stale', {
                'device_id':    dev_id,
                'name':         dev.get('name', dev_id),
                'hostname':     dev.get('hostname', ''),
                'reported_at':  int(ts),
                'age_seconds':  age,
                'age_minutes':  age // 60,
                'ttl_minutes':  ttl // 60,
            })
            notified[dev_id] = True
            changed = True
        elif not stale and already:
            # Already cleared on heartbeat ingest, but keep this branch for
            # safety in case the heartbeat path missed it (e.g. config rewrite
            # race). No webhook on the recovery — same convention as patch_alert.
            notified[dev_id] = False
            changed = True

    if changed:
        cfg['containers_stale_notified'] = notified
        save(CONFIG_FILE, cfg)


def handle_services_get():
    """GET /api/services — all current service states across the fleet."""
    require_auth()
    store = load(SERVICES_FILE)
    devices = load(DEVICES_FILE)
    out = []
    for dev_id, dev in devices.items():
        entry = store.get(dev_id) or {}
        services = entry.get('services') or []
        up = sum(1 for s in services if s.get('active') == 'active')
        down = len(services) - up
        out.append({
            'device_id':  dev_id,
            'name':       dev.get('name', dev_id),
            'group':      dev.get('group', ''),
            'updated_at': entry.get('updated_at', 0),
            'total':      len(services),
            'up':         up,
            'down':       down,
            'services':   services,
        })
    out.sort(key=lambda d: (-d['down'], d['name'].lower()))
    respond(200, {'devices': out})


def handle_services_device(dev_id):
    """GET /api/devices/{id}/services"""
    require_auth()
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})

    store = load(SERVICES_FILE)
    hist  = load(SERVICE_HIST_FILE)
    log_buf = load(LOG_WATCH_FILE).get(dev_id) or {}
    entry = store.get(dev_id) or {}
    services = entry.get('services') or []

    enriched = []
    for s in services:
        key = f'{dev_id}:{s["unit"]}'
        enriched.append({
            **s,
            'history':  (hist.get(key) or [])[-10:],
            'log_tail': (log_buf.get('units') or {}).get(s['unit'], [])[-50:],
        })
    respond(200, {
        'device_id':  dev_id,
        'name':       devices[dev_id].get('name', dev_id),
        'updated_at': entry.get('updated_at', 0),
        'services':   enriched,
    })


def handle_services_config(dev_id):
    """
    GET/POST /api/devices/{id}/services/config
    Manages services_watched list on the device record.
    """
    actor = require_admin_auth() if method() == 'POST' else None
    if not actor:
        require_auth()
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})

    if method() == 'GET':
        respond(200, {
            'services_watched': devices[dev_id].get('services_watched', []),
            'log_watch':        devices[dev_id].get('log_watch', []),
        })

    body = get_json_body()
    raw = body.get('services_watched') or []
    if not isinstance(raw, list):
        respond(400, {'error': 'services_watched must be a list'})
    watched = []
    for name in raw[:MAX_SERVICES_PER_DEVICE]:
        unit = _sanitize_unit_name(name)
        if unit:
            watched.append(unit)

    # Optional: log_watch rules — [{unit, pattern, threshold}]
    log_rules_raw = body.get('log_watch') or []
    log_rules = []
    if isinstance(log_rules_raw, list):
        for r in log_rules_raw[:10]:
            if not isinstance(r, dict):
                continue
            unit = _sanitize_unit_name(r.get('unit', ''))
            pat  = _sanitize_str(r.get('pattern', ''), 128, allow_empty=False)
            try:
                thr = int(r.get('threshold', 1) or 1)
            except (TypeError, ValueError):
                thr = 1
            if unit and pat and 1 <= thr <= 100:
                # Sanity-check the regex compiles
                try:
                    re.compile(pat)
                except re.error:
                    continue
                log_rules.append({'unit': unit, 'pattern': pat, 'threshold': thr})

    devices[dev_id]['services_watched'] = watched
    devices[dev_id]['log_watch']        = log_rules
    save(DEVICES_FILE, devices)
    audit_log(actor, 'services_config_update',
              detail=f'device={dev_id} watched={len(watched)} log_rules={len(log_rules)}')
    respond(200, {'ok': True, 'services_watched': watched, 'log_watch': log_rules})


# ─── v1.8.0: Log tail — called by agent with captured unit logs ───────────────

def handle_log_submit():
    """
    POST /api/logs — agent submits per-unit log lines (device-authenticated).
    Body: {device_id, token, units: {unit_name: [line, line, ...], ...}}

    v1.8.2:
      - Empty lines[] arrays are now preserved so quiet devices still register
        as "reporting" on the Logs page (previously they vanished entirely)
      - Evaluates both device.log_watch (per-device) AND global rules from
        log_rules_global.json (fleet-wide). Wildcard unit='*' matches any unit.
      - Dedupes alerts by (scope, unit, pattern) so a line that matches a
        per-device rule AND a global rule fires only once.
    """
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})

    body = get_json_body()
    dev_id    = str(body.get('device_id', '')).strip()
    dev_token = str(body.get('token', '')).strip()
    if not _validate_id(dev_id):
        respond(403, {'error': 'Unauthorized device'})

    devices = load(DEVICES_FILE)
    dev = devices.get(dev_id)
    if not dev or not hmac.compare_digest(dev.get('token', ''), dev_token):
        respond(403, {'error': 'Unauthorized device'})

    units_in = body.get('units') or {}
    if not isinstance(units_in, dict):
        respond(400, {'error': 'units must be an object'})

    now = int(time.time())
    log_store = load(LOG_WATCH_FILE)
    dev_buf = log_store.get(dev_id) or {'units': {}, 'updated_at': now}
    units_buf = dev_buf.get('units') or {}

    alerts_fired = []
    per_device_rules = dev.get('log_watch') or []
    global_rules = (load(LOG_RULES_GLOBAL_FILE).get('rules') or [])

    # Track which (unit, pattern) pairs have already fired this submission — a
    # line matching both a per-device and a global rule with the same pattern
    # should produce one alert, not two.
    fired_keys = set()

    for unit_raw, lines in units_in.items():
        unit = _sanitize_unit_name(unit_raw)
        if not isinstance(unit, str) or unit is None:
            continue
        if not isinstance(lines, list):
            continue

        clean_lines = []
        for line in lines[:MAX_LOG_LINES_PER_UNIT]:
            s = str(line)[:1024]
            clean_lines.append({'ts': now, 'line': s})

        existing = units_buf.get(unit) or []
        combined = existing + clean_lines
        # Trim by age
        cutoff = now - LOG_BUFFER_TTL
        combined = [e for e in combined if e.get('ts', 0) >= cutoff]
        # Trim by byte-size
        total_bytes = sum(len(e.get('line', '')) for e in combined)
        while total_bytes > MAX_LOG_BUFFER_BYTES and combined:
            removed = combined.pop(0)
            total_bytes -= len(removed.get('line', ''))
        # v1.8.2: always keep the unit key, even if empty — so the device
        # appears on the Logs page as "watched, quiet in this window"
        units_buf[unit] = combined

        # Evaluate per-device rules first, then global
        def _eval_rules(rules, scope):
            for rule in rules:
                rule_unit = rule.get('unit', '')
                # Wildcard '*' matches any unit; otherwise exact match
                if rule_unit != '*' and rule_unit != unit:
                    continue
                pattern = rule.get('pattern', '')
                key = (scope, unit, pattern)
                if key in fired_keys:
                    continue
                try:
                    rx = re.compile(pattern)
                except re.error:
                    continue
                matches = [e['line'] for e in clean_lines if rx.search(e['line'])]
                threshold = rule.get('threshold', 1)
                try:
                    threshold = int(threshold)
                except (TypeError, ValueError):
                    threshold = 1
                if len(matches) >= threshold:
                    fired_keys.add(key)
                    alerts_fired.append({
                        'unit': unit, 'pattern': pattern,
                        'count': len(matches), 'scope': scope,
                    })
                    fire_webhook('log_alert', {
                        'device_id': dev_id,
                        'name':      dev.get('name', dev_id),
                        'unit':      unit,
                        'pattern':   pattern,
                        'count':     len(matches),
                        'sample':    matches[:3],
                        'scope':     scope,  # v1.8.2: 'device' | 'global'
                    })

        _eval_rules(per_device_rules, 'device')
        _eval_rules(global_rules,     'global')

    dev_buf['units'] = units_buf
    dev_buf['updated_at'] = now
    log_store[dev_id] = dev_buf
    save(LOG_WATCH_FILE, log_store)

    respond(200, {'ok': True, 'alerts_fired': len(alerts_fired)})


def handle_log_search():
    """
    GET /api/logs/search?q=<pattern>&device=<id>&limit=<n>
    Searches the rolling buffer across devices. No indexing — just grep.
    """
    require_auth()
    qs = urllib.parse.parse_qs(os.environ.get('QUERY_STRING', ''))
    q       = (qs.get('q', [''])[0])[:128]
    device  = (qs.get('device', [''])[0])[:64]
    limit   = min(int(qs.get('limit', ['200'])[0] or 200), 1000)

    if not q:
        respond(400, {'error': 'q parameter is required'})

    try:
        rx = re.compile(q, re.IGNORECASE)
    except re.error as e:
        respond(400, {'error': f'invalid regex: {e}'})

    log_store = load(LOG_WATCH_FILE)
    devices = load(DEVICES_FILE)
    results = []

    target_devs = [device] if device else list(log_store.keys())
    for dev_id in target_devs:
        if dev_id not in devices:
            continue
        buf = log_store.get(dev_id) or {}
        units = buf.get('units') or {}
        dev_name = devices[dev_id].get('name', dev_id)
        for unit, lines in units.items():
            for entry in lines:
                if rx.search(entry.get('line', '')):
                    results.append({
                        'device_id': dev_id,
                        'name':      dev_name,
                        'unit':      unit,
                        'ts':        entry.get('ts', 0),
                        'line':      entry.get('line', ''),
                    })
                    if len(results) >= limit:
                        break
            if len(results) >= limit:
                break
        if len(results) >= limit:
            break

    results.sort(key=lambda r: -r['ts'])
    respond(200, {'query': q, 'count': len(results), 'results': results})


def handle_log_device(dev_id):
    """GET /api/devices/{id}/logs — full captured buffer for one device."""
    require_auth()
    if not _validate_id(dev_id):
        respond(404, {'error': 'Device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'Device not found'})
    log_store = load(LOG_WATCH_FILE)
    buf = log_store.get(dev_id) or {'units': {}, 'updated_at': 0}
    respond(200, {
        'device_id':  dev_id,
        'name':       devices[dev_id].get('name', dev_id),
        'updated_at': buf.get('updated_at', 0),
        'units':      buf.get('units', {}),
    })


# ─── v1.8.1: Log alert rules aggregate + live tail ───────────────────────────

def handle_log_rules():
    """GET /api/logs/rules — cross-fleet view of all per-device log_watch rules."""
    require_auth()
    devices = load(DEVICES_FILE)
    out = []
    for dev_id, dev in devices.items():
        for rule in (dev.get('log_watch') or []):
            out.append({
                'device_id': dev_id,
                'device_name': dev.get('name', dev_id),
                'group':     dev.get('group', ''),
                'unit':      rule.get('unit', ''),
                'pattern':   rule.get('pattern', ''),
                'threshold': rule.get('threshold', 1),
            })
    out.sort(key=lambda r: (r['device_name'].lower(), r['unit']))
    respond(200, {'rules': out})


# ─── v1.8.2: Fleet-wide log alert rules ───────────────────────────────────────

def _validate_global_rule(body):
    """Return (clean_rule, error) — same shape whether valid or not."""
    unit    = _sanitize_str(body.get('unit', ''), 128, allow_empty=False)
    pattern = _sanitize_str(body.get('pattern', ''), 128, allow_empty=False)
    # Don't use `or 1` for threshold — we want to reject 0 explicitly rather
    # than coerce it to 1 silently, so the user gets a clear error.
    raw_threshold = body.get('threshold', 1)
    if raw_threshold is None or raw_threshold == '':
        raw_threshold = 1
    try:
        threshold = int(raw_threshold)
    except (TypeError, ValueError):
        return None, 'threshold must be an integer'

    if not unit:
        return None, 'unit is required (use "*" for any unit)'
    # Allow '*' OR a valid unit name
    if unit != '*' and not _sanitize_unit_name(unit):
        return None, 'invalid unit name'
    if not pattern:
        return None, 'pattern is required'
    if not (1 <= threshold <= 100):
        return None, 'threshold must be 1..100'
    try:
        re.compile(pattern)
    except re.error as e:
        return None, f'invalid regex: {e}'
    return {'unit': unit, 'pattern': pattern, 'threshold': threshold}, None


def handle_log_rules_global_list():
    """GET /api/logs/rules/global — list fleet-wide rules."""
    require_auth()
    rules = (load(LOG_RULES_GLOBAL_FILE).get('rules') or [])
    rules = sorted(rules, key=lambda r: (r.get('unit', ''), r.get('pattern', '')))
    respond(200, {'rules': rules})


def handle_log_rules_global_add():
    """POST /api/logs/rules/global — create a fleet-wide rule."""
    actor = require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})

    body = get_json_body()
    rule, err = _validate_global_rule(body)
    if err:
        respond(400, {'error': err})

    store = load(LOG_RULES_GLOBAL_FILE)
    rules = store.get('rules') or []
    # Dedup by (unit, pattern) — same rule can't exist twice
    for existing in rules:
        if existing.get('unit') == rule['unit'] and existing.get('pattern') == rule['pattern']:
            respond(409, {'error': 'rule with this unit+pattern already exists'})
    if len(rules) >= MAX_GLOBAL_LOG_RULES:
        respond(400, {'error': f'max {MAX_GLOBAL_LOG_RULES} global rules'})

    rule['id']         = secrets.token_hex(8)
    rule['created_by'] = actor
    rule['created_at'] = int(time.time())
    rules.append(rule)
    store['rules'] = rules
    save(LOG_RULES_GLOBAL_FILE, store)
    audit_log(actor, 'log_rule_global_add',
              detail=f'id={rule["id"]} unit={rule["unit"]} pattern={rule["pattern"][:60]}')
    respond(200, {'ok': True, 'rule': rule})


def handle_log_rules_global_delete(rule_id):
    """DELETE /api/logs/rules/global/{id}"""
    actor = require_admin_auth()
    rule_id = _sanitize_str(rule_id, 32, allow_empty=False)
    if not rule_id:
        respond(400, {'error': 'invalid id'})

    store = load(LOG_RULES_GLOBAL_FILE)
    rules = store.get('rules') or []
    remaining = [r for r in rules if r.get('id') != rule_id]
    if len(remaining) == len(rules):
        respond(404, {'error': 'rule not found'})
    store['rules'] = remaining
    save(LOG_RULES_GLOBAL_FILE, store)
    audit_log(actor, 'log_rule_global_delete', detail=f'id={rule_id}')
    respond(200, {'ok': True})


def handle_log_tail():
    """
    GET /api/logs/tail?since=<ts>&device=<id>&unit=<name>&limit=<n>
    Returns the newest lines across the fleet since a given unix ts.
    Use-case: live tail page, polls with monotonically-increasing `since`.
    """
    require_auth()
    qs = urllib.parse.parse_qs(os.environ.get('QUERY_STRING', ''))
    try:
        since = int(qs.get('since', ['0'])[0] or 0)
    except ValueError:
        since = 0
    device = (qs.get('device', [''])[0])[:64]
    unit   = (qs.get('unit',   [''])[0])[:128]
    try:
        limit = min(int(qs.get('limit', ['500'])[0] or 500), 2000)
    except ValueError:
        limit = 500

    log_store = load(LOG_WATCH_FILE)
    devices   = load(DEVICES_FILE)
    out = []
    newest_ts = since
    devices_reporting = 0
    total_lines = 0

    target_devs = [device] if device else list(log_store.keys())
    for dev_id in target_devs:
        if dev_id not in devices:
            continue
        buf = log_store.get(dev_id) or {}
        units = buf.get('units') or {}
        dev_name = devices[dev_id].get('name', dev_id)
        had_lines = False
        for u, lines in units.items():
            if unit and u != unit:
                continue
            for entry in lines:
                ts = entry.get('ts', 0)
                total_lines += 1
                if ts > since:
                    out.append({
                        'device_id': dev_id,
                        'name':      dev_name,
                        'unit':      u,
                        'ts':        ts,
                        'line':      entry.get('line', ''),
                    })
                    if ts > newest_ts:
                        newest_ts = ts
                    had_lines = True
        if had_lines or units:
            devices_reporting += 1

    out.sort(key=lambda r: r['ts'])
    if len(out) > limit:
        out = out[-limit:]  # keep the newest

    # For stats, compute totals across the whole buffer, not just new lines
    respond(200, {
        'lines':             out,
        'newest_ts':         newest_ts,
        'stats': {
            'total_lines':        total_lines,
            'devices_reporting':  devices_reporting,
        },
    })


# ─── v1.8.3: Shared calendar events ──────────────────────────────────────────

# Palette used by the UI — cap allowed colors to prevent CSS injection via
# arbitrary strings. The UI picker should present these same values.
ALLOWED_EVENT_COLORS = (
    'blue', 'green', 'amber', 'red', 'purple', 'teal', 'slate',
)


def _sanitize_event(body):
    """Sanitize a calendar event submission. Returns (clean, error)."""
    title = _sanitize_str(body.get('title', ''), 120, allow_empty=False)
    if not title:
        return None, 'title is required'
    description = _sanitize_str(body.get('description', ''), 2000)
    start = _sanitize_str(body.get('start', ''), 32, allow_empty=False)
    end   = _sanitize_str(body.get('end', ''), 32)
    if not start:
        return None, 'start is required (ISO-8601)'
    try:
        start_ts = _parse_iso(start)
    except ValueError:
        return None, 'invalid start timestamp'
    end_ts = None
    if end:
        try:
            end_ts = _parse_iso(end)
        except ValueError:
            return None, 'invalid end timestamp'
        if end_ts < start_ts:
            return None, 'end must be >= start'
    all_day = bool(body.get('all_day', False))
    color = _sanitize_str(body.get('color', 'blue'), 16)
    if color not in ALLOWED_EVENT_COLORS:
        color = 'blue'
    return {
        'title':       title,
        'description': description,
        'start':       start,
        'end':         end or start,
        'all_day':     all_day,
        'color':       color,
    }, None


def handle_calendar_list():
    """GET /api/calendar — list all events, optionally filtered by date range."""
    require_auth()
    qs = urllib.parse.parse_qs(os.environ.get('QUERY_STRING', ''))
    from_ts = 0
    to_ts   = 10 ** 10  # far future
    try:
        if qs.get('from'):
            from_ts = _parse_iso(qs['from'][0])
        if qs.get('to'):
            to_ts = _parse_iso(qs['to'][0])
    except ValueError:
        respond(400, {'error': 'invalid from/to timestamp'})

    store = load(CALENDAR_FILE)
    events = store.get('events') or []
    out = []
    for ev in events:
        try:
            ev_start = _parse_iso(ev.get('start', ''))
            ev_end   = _parse_iso(ev.get('end', '')) if ev.get('end') else ev_start
        except ValueError:
            continue
        # Overlap check
        if ev_end < from_ts or ev_start > to_ts:
            continue
        out.append(ev)
    out.sort(key=lambda e: e.get('start', ''))
    respond(200, {'events': out})


def handle_calendar_add():
    """POST /api/calendar — create a new event."""
    actor = require_auth()  # any authenticated user can create
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    clean, err = _sanitize_event(body)
    if err:
        respond(400, {'error': err})

    store = load(CALENDAR_FILE)
    events = store.get('events') or []
    if len(events) >= MAX_CALENDAR_EVENTS:
        respond(400, {'error': f'max {MAX_CALENDAR_EVENTS} events'})
    clean['id']         = secrets.token_hex(8)
    clean['created_by'] = actor
    clean['created_at'] = int(time.time())
    events.append(clean)
    store['events'] = events
    save(CALENDAR_FILE, store)
    audit_log(actor, 'calendar_add', detail=f'id={clean["id"]} title={clean["title"][:60]}')
    respond(200, {'ok': True, 'event': clean})


def handle_calendar_update(event_id):
    """PUT /api/calendar/{id} — edit an existing event."""
    actor = require_auth()
    event_id = _sanitize_str(event_id, 32, allow_empty=False)
    if not event_id:
        respond(400, {'error': 'invalid id'})

    store = load(CALENDAR_FILE)
    events = store.get('events') or []
    idx = next((i for i, e in enumerate(events) if e.get('id') == event_id), -1)
    if idx < 0:
        respond(404, {'error': 'event not found'})

    body = get_json_body()
    clean, err = _sanitize_event(body)
    if err:
        respond(400, {'error': err})
    # Preserve id + created_by/at, merge in the new fields
    clean['id']         = event_id
    clean['created_by'] = events[idx].get('created_by', '')
    clean['created_at'] = events[idx].get('created_at', 0)
    clean['updated_by'] = actor
    clean['updated_at'] = int(time.time())
    events[idx] = clean
    store['events'] = events
    save(CALENDAR_FILE, store)
    audit_log(actor, 'calendar_update', detail=f'id={event_id}')
    respond(200, {'ok': True, 'event': clean})


def handle_calendar_delete(event_id):
    """DELETE /api/calendar/{id}"""
    actor = require_auth()
    event_id = _sanitize_str(event_id, 32, allow_empty=False)
    if not event_id:
        respond(400, {'error': 'invalid id'})

    store = load(CALENDAR_FILE)
    events = store.get('events') or []
    remaining = [e for e in events if e.get('id') != event_id]
    if len(remaining) == len(events):
        respond(404, {'error': 'event not found'})
    store['events'] = remaining
    save(CALENDAR_FILE, store)
    audit_log(actor, 'calendar_delete', detail=f'id={event_id}')
    respond(200, {'ok': True})


# ─── v1.8.3: Shared tasks board ───────────────────────────────────────────────

def _sanitize_task(body, require_all=True):
    """Sanitize a task submission. Returns (clean, error).
    If require_all=False, allows partial updates (used by /state endpoint)."""
    title = _sanitize_str(body.get('title', ''), 200, allow_empty=not require_all)
    if require_all and not title:
        return None, 'title is required'
    description = _sanitize_str(body.get('description', ''), 4000)
    state = _sanitize_str(body.get('state', 'upcoming'), 16)
    if state and state not in TASK_STATES:
        return None, f'state must be one of {", ".join(TASK_STATES)}'
    # Device linking is optional. Empty string = no device; otherwise must be valid.
    device_id = _sanitize_str(body.get('device_id', ''), 64)
    if device_id:
        if not _validate_id(device_id):
            return None, 'invalid device_id'
        devices = load(DEVICES_FILE)
        if device_id not in devices:
            return None, 'device_id not found'
    out = {}
    if title:
        out['title'] = title
    if 'description' in body:
        out['description'] = description
    if state:
        out['state'] = state
    if 'device_id' in body:
        out['device_id'] = device_id  # '' means explicit unlink
    return out, None


def handle_tasks_list():
    """GET /api/tasks — all tasks with optional state / device filter."""
    require_auth()
    qs = urllib.parse.parse_qs(os.environ.get('QUERY_STRING', ''))
    state_filter  = (qs.get('state',  [''])[0])[:16]
    device_filter = (qs.get('device', [''])[0])[:64]

    store = load(TASKS_FILE)
    tasks = store.get('tasks') or []

    if state_filter and state_filter in TASK_STATES:
        tasks = [t for t in tasks if t.get('state') == state_filter]
    if device_filter:
        tasks = [t for t in tasks if t.get('device_id') == device_filter]

    # Enrich with device names for display (skip lookup if no tasks have devices)
    if any(t.get('device_id') for t in tasks):
        devices = load(DEVICES_FILE)
        for t in tasks:
            did = t.get('device_id')
            if did and did in devices:
                t['_device_name'] = devices[did].get('name', did)

    # Sort: newest first within each state, so kanban columns are fresh at top
    tasks.sort(key=lambda t: -t.get('updated_at', t.get('created_at', 0)))

    counts = {s: 0 for s in TASK_STATES}
    for t in tasks:
        s = t.get('state', 'upcoming')
        if s in counts:
            counts[s] += 1
    respond(200, {'tasks': tasks, 'counts': counts})


def handle_tasks_add():
    """POST /api/tasks — create."""
    actor = require_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    body = get_json_body()
    clean, err = _sanitize_task(body, require_all=True)
    if err:
        respond(400, {'error': err})

    store = load(TASKS_FILE)
    tasks = store.get('tasks') or []
    if len(tasks) >= MAX_TASKS:
        respond(400, {'error': f'max {MAX_TASKS} tasks — close some first'})

    now = int(time.time())
    task = {
        'id':          secrets.token_hex(8),
        'title':       clean['title'],
        'description': clean.get('description', ''),
        'state':       clean.get('state', 'upcoming'),
        'device_id':   clean.get('device_id', ''),
        'created_by':  actor,
        'created_at':  now,
        'updated_at':  now,
    }
    tasks.append(task)
    store['tasks'] = tasks
    save(TASKS_FILE, store)
    audit_log(actor, 'task_add', detail=f'id={task["id"]} title={task["title"][:60]}')
    respond(200, {'ok': True, 'task': task})


def handle_tasks_update(task_id):
    """PUT /api/tasks/{id} — edit title/description/state/device."""
    actor = require_auth()
    task_id = _sanitize_str(task_id, 32, allow_empty=False)
    if not task_id:
        respond(400, {'error': 'invalid id'})

    store = load(TASKS_FILE)
    tasks = store.get('tasks') or []
    idx = next((i for i, t in enumerate(tasks) if t.get('id') == task_id), -1)
    if idx < 0:
        respond(404, {'error': 'task not found'})

    body = get_json_body()
    clean, err = _sanitize_task(body, require_all=False)
    if err:
        respond(400, {'error': err})

    for k in ('title', 'description', 'state', 'device_id'):
        if k in clean:
            tasks[idx][k] = clean[k]
    tasks[idx]['updated_at'] = int(time.time())
    tasks[idx]['updated_by'] = actor
    store['tasks'] = tasks
    save(TASKS_FILE, store)
    audit_log(actor, 'task_update',
              detail=f'id={task_id} fields={",".join(sorted(clean.keys()))}')
    respond(200, {'ok': True, 'task': tasks[idx]})


def handle_tasks_delete(task_id):
    """DELETE /api/tasks/{id}"""
    actor = require_auth()
    task_id = _sanitize_str(task_id, 32, allow_empty=False)
    if not task_id:
        respond(400, {'error': 'invalid id'})

    store = load(TASKS_FILE)
    tasks = store.get('tasks') or []
    remaining = [t for t in tasks if t.get('id') != task_id]
    if len(remaining) == len(tasks):
        respond(404, {'error': 'task not found'})
    store['tasks'] = remaining
    save(TASKS_FILE, store)
    audit_log(actor, 'task_delete', detail=f'id={task_id}')
    respond(200, {'ok': True})


# ─── v1.9.0: CMDB ──────────────────────────────────────────────────────────────
# Asset metadata + encrypted credentials, scoped to enrolled devices only.
# Vault crypto details live in cmdb_vault.py — this section is plumbing.

def _cmdb_load() -> dict:
    """Load the CMDB store from disk.

    Returns:
        Mapping of ``device_id`` to record dict. Returns an empty dict if
        the store file is missing or corrupt — never raises.

    Migration: v2.0 introduced the multi-doc ``docs`` field. Records that
    were last written under v1.x have ``documentation`` (a single Markdown
    string) but no ``docs`` list. We synthesise a single-doc list from
    the legacy field so downstream code only has to handle the new shape.
    The legacy field is left in place — old API consumers (scripts, the
    ``documentation`` field in the existing ``handle_cmdb_update``) keep
    working unchanged. On first save through the new endpoints the legacy
    field is cleared.
    """
    store = load(CMDB_FILE)
    if not isinstance(store, dict):
        return {}
    # Lightweight in-memory migration. Cheap to do on every load (just
    # walks N records, conditional). Pushing it into save() would mean
    # records weren't migrated until they were modified.
    for rec in store.values():
        if not isinstance(rec, dict):
            continue
        if 'docs' not in rec or not isinstance(rec.get('docs'), list):
            legacy = rec.get('documentation') or ''
            if isinstance(legacy, str) and legacy.strip():
                rec['docs'] = [{
                    'id':         'legacy',
                    'title':      'Documentation',
                    'body':       legacy,
                    'created_by': rec.get('updated_by', ''),
                    'created_at': rec.get('updated_at', 0),
                    'updated_by': rec.get('updated_by', ''),
                    'updated_at': rec.get('updated_at', 0),
                }]
            else:
                rec['docs'] = []
    return store


def _cmdb_record_default() -> dict:
    """Build an empty CMDB record skeleton.

    Every enrolled device implicitly has one of these — the storage layer
    only persists records the user has actually edited, but the API
    presents a uniform shape.

    Returns:
        Dict with all CMDB fields set to their type-appropriate empties
        (empty string, empty list, default port, zero timestamp).
    """
    return {
        'asset_id':        '',
        'server_function': '',
        'hypervisor_url':  '',
        'ssh_port':        CMDB_DEFAULT_SSH_PORT,
        'documentation':   '',     # v1.x: single Markdown blob (kept for back-compat)
        'docs':            [],     # v2.0: multiple titled Markdown docs
        'credentials':     [],
        'updated_by':      '',
        'updated_at':      0,
    }


def _cmdb_strip_creds(record: dict) -> dict:
    """Redact credential ciphertext from a CMDB record.

    Returns a shallow copy of ``record`` where each credential keeps only
    its plaintext-safe metadata (``id``, ``label``, ``username``, ``note``,
    timestamps). The ``nonce`` and ``ct`` fields — the AES-GCM ciphertext
    — are never returned by list endpoints; only ``/reveal`` decrypts and
    surfaces plaintext.

    Args:
        record: The full CMDB record as stored in ``cmdb.json``.

    Returns:
        A new dict safe to serialise to API clients.
    """
    out = dict(record)
    safe = []
    for c in record.get('credentials') or []:
        safe.append({
            'id':         c.get('id', ''),
            'label':      c.get('label', ''),
            'username':   c.get('username', ''),
            'note':       c.get('note', ''),
            'created_by': c.get('created_by', ''),
            'created_at': c.get('created_at', 0),
            'updated_by': c.get('updated_by', ''),
            'updated_at': c.get('updated_at', 0),
        })
    out['credentials'] = safe
    return out


def _cmdb_validate_url(url) -> 'str | None':
    """Validate a hypervisor URL.

    Empty is acceptable (resets the field). Anything else must be
    ``http://`` or ``https://``, ≤512 characters, and free of whitespace
    or control characters. The latter is a defence against header /
    response splitting if the URL is later interpolated unsafely.

    Args:
        url: Raw value from the request body. Strings, ints, ``None`` —
            anything stringifiable.

    Returns:
        The cleaned URL string on success, an empty string for falsy
        input, or ``None`` to indicate a validation failure (caller
        should respond with 400).
    """
    if not url:
        return ''
    url = str(url).strip()
    if len(url) > MAX_CMDB_URL_LEN:
        return None
    if not (url.startswith('http://') or url.startswith('https://')):
        return None
    # Reject control characters / whitespace inside the URL
    if any(c.isspace() or ord(c) < 0x20 for c in url):
        return None
    return url


def _cmdb_validate_function(fn) -> 'str | None':
    """Validate a ``server_function`` value.

    Free text but charset-restricted to ``[A-Za-z0-9 _\\-/]`` (max 64
    chars) so the value is safe to splice into autocomplete dropdowns
    without HTML escaping every code path.

    Args:
        fn: Raw value from the request body.

    Returns:
        Cleaned string on success, empty string for falsy input,
        ``None`` to signal validation failure.
    """
    if fn is None:
        return ''
    fn = str(fn).strip()
    if not fn:
        return ''
    if not _CMDB_FUNC_RE.match(fn):
        return None
    return fn


def _cmdb_get_vault_meta() -> dict:
    """Load vault metadata (KDF params + canary) from disk."""
    return load(CMDB_VAULT_FILE)


def _cmdb_get_request_key() -> bytes:
    """Extract the derived vault key from the request headers.

    Returns:
        The 32-byte key as raw bytes.

    Raises:
        cmdb_vault.VaultLockedError: Header is missing.
        cmdb_vault.VaultKeyError: Header is malformed (not hex, wrong length).
    """
    raw = os.environ.get('HTTP_X_RP_VAULT_KEY', '')
    return cmdb_vault.parse_key_header(raw)


def _cmdb_require_unlocked() -> 'tuple[bytes, dict]':
    """Common preamble for credential operations.

    Loads the vault metadata, extracts and verifies the request's vault
    key, and returns both for the caller to use. Short-circuits via
    :func:`respond` (which raises :class:`HTTPError`) on any failure.

    Returns:
        A ``(key, vault_meta)`` tuple. ``key`` is 32 bytes; ``vault_meta``
        is the dict from ``cmdb_vault.json``.
    """
    meta = _cmdb_get_vault_meta()
    if not cmdb_vault.is_configured(meta):
        respond(409, {'error': 'vault not configured', 'code': 'vault_not_configured'})
    try:
        key = _cmdb_get_request_key()
    except cmdb_vault.VaultLockedError:
        respond(401, {'error': 'vault locked', 'code': 'vault_locked'})
    except cmdb_vault.VaultKeyError as e:
        respond(400, {'error': str(e)})
    if not cmdb_vault.verify_key(key, meta):
        respond(403, {'error': 'invalid vault key', 'code': 'vault_key_invalid'})
    return key, meta


def handle_cmdb_list() -> None:
    """``GET /api/cmdb`` — list assets joined with their CMDB metadata.

    Returns one entry per enrolled device (devices with no CMDB record
    appear with empty fields). Supports two query-string filters:

    ``?q=<text>``
        Free-text search across name, hostname, OS, IP, MAC, group,
        asset_id, server_function, hypervisor_url, tags, and the
        documentation body. Case-insensitive substring match.

    ``?function=<value>``
        Exact match on ``server_function`` (case-insensitive).

    Results are sorted by ``server_function`` then by ``name``;
    unspecified-function assets sort last.

    Side effects:
        Calls :func:`respond` with status 200 and the asset list.
    """
    require_auth()
    devices = load(DEVICES_FILE)
    cmdb = _cmdb_load()
    qs = urllib.parse.parse_qs(os.environ.get('QUERY_STRING', ''))
    q = (qs.get('q', [''])[0] or '').strip().lower()
    func_filter = (qs.get('function', [''])[0] or '').strip().lower()

    out = []
    for dev_id, dev in devices.items():
        rec = cmdb.get(dev_id) or _cmdb_record_default()
        rec_safe = _cmdb_strip_creds(rec)
        entry = {
            'device_id':       dev_id,
            'name':            dev.get('name', dev_id),
            'hostname':        dev.get('hostname', ''),
            'os':              dev.get('os', ''),
            'ip':              dev.get('ip', ''),
            'mac':             dev.get('mac', ''),
            'group':           dev.get('group', ''),
            'tags':            dev.get('tags', []),
            'asset_id':        rec_safe.get('asset_id', ''),
            'server_function': rec_safe.get('server_function', ''),
            'hypervisor_url':  rec_safe.get('hypervisor_url', ''),
            'ssh_port':        rec_safe.get('ssh_port', CMDB_DEFAULT_SSH_PORT),
            'has_documentation': bool(rec_safe.get('documentation')),
            'credential_count': len(rec_safe.get('credentials') or []),
        }
        if func_filter and entry['server_function'].lower() != func_filter:
            continue
        if q:
            haystack = ' '.join([
                entry['name'], entry['hostname'], entry['os'], entry['ip'],
                entry['mac'], entry['group'], entry['asset_id'],
                entry['server_function'], entry['hypervisor_url'],
                ' '.join(entry['tags'] or []),
                rec_safe.get('documentation', ''),
            ]).lower()
            if q not in haystack:
                continue
        out.append(entry)
    out.sort(key=lambda x: (x.get('server_function') or '~', x['name'].lower()))
    respond(200, out)


def _trim_sysinfo(sysinfo) -> dict:
    """Return only the sysinfo fields the CMDB modal actually displays.

    The full sysinfo dict from a heartbeat can run 50+ KB (kernel,
    services, NICs, mountpoints, etc.). The CMDB asset modal only needs
    CPU/RAM/disk headlines and uptime. Trimming keeps page loads snappy
    when assets have rich sysinfo.

    Args:
        sysinfo: Anything — non-dict input is treated as empty.

    Returns:
        Dict with at most nine whitelisted fields. Missing fields are
        included with ``None`` values for shape stability on the client.
    """
    if not isinstance(sysinfo, dict):
        return {}
    return {
        'kernel':         sysinfo.get('kernel', ''),
        'cpu':            sysinfo.get('cpu', ''),
        'cores':          sysinfo.get('cores'),
        'mem_total_mb':   sysinfo.get('mem_total_mb'),
        'mem_free_mb':    sysinfo.get('mem_free_mb'),
        'disk_total_gb':  sysinfo.get('disk_total_gb'),
        'disk_free_gb':   sysinfo.get('disk_free_gb'),
        'uptime_seconds': sysinfo.get('uptime_seconds'),
        'boot_time':      sysinfo.get('boot_time'),
    }


def handle_cmdb_get(dev_id: str) -> None:
    """``GET /api/cmdb/{device_id}`` — full asset detail with credentials redacted.

    Args:
        dev_id: The enrolled device's ID.

    Side effects:
        Calls :func:`respond` with 200 + asset detail, or 404 if the
        device is unknown.
    """
    require_auth()
    if not _validate_id(dev_id):
        respond(404, {'error': 'device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'device not found'})
    cmdb = _cmdb_load()
    rec = cmdb.get(dev_id) or _cmdb_record_default()
    # Backfill ssh_port for records created before v1.10.0.
    if 'ssh_port' not in rec:
        rec['ssh_port'] = CMDB_DEFAULT_SSH_PORT
    dev = devices[dev_id]
    payload = _cmdb_strip_creds(rec)
    payload['device_id'] = dev_id
    payload['name']      = dev.get('name', dev_id)
    payload['hostname']  = dev.get('hostname', '')
    payload['os']        = dev.get('os', '')
    payload['ip']        = dev.get('ip', '')
    payload['mac']       = dev.get('mac', '')
    payload['version']   = dev.get('version', '')
    payload['group']     = dev.get('group', '')
    payload['tags']      = dev.get('tags', [])
    # v1.10.0: send a trimmed sysinfo subset rather than the full dict.
    # Saves ~50 KB on busy assets, cuts CMDB modal load time noticeably.
    payload['sysinfo']   = _trim_sysinfo(dev.get('sysinfo', {}))
    respond(200, payload)


def handle_cmdb_update(dev_id: str) -> None:
    """``PUT /api/cmdb/{device_id}`` — patch CMDB metadata for an asset.

    Accepts a JSON body with any subset of the writable fields.
    Unrecognised keys are silently ignored; recognised keys that fail
    validation cause a 400. At least one recognised key is required.

    Writable fields:
        ``asset_id``: Free text, ``[A-Za-z0-9_-]{0,64}``.
        ``server_function``: Free text, ``[A-Za-z0-9 _\\-/]{0,64}``.
        ``hypervisor_url``: ``http(s)://…``, max 512 chars.
        ``ssh_port``: 1-65535. Empty/0 resets to default 22.
        ``documentation``: Markdown, max 64 KB.

    Args:
        dev_id: The enrolled device's ID.
    """
    actor = require_auth()
    if method() != 'PUT':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'device not found'})

    body = get_json_body()
    cmdb = _cmdb_load()
    rec = cmdb.get(dev_id) or _cmdb_record_default()

    changed = []

    if 'asset_id' in body:
        asset_id = str(body.get('asset_id') or '').strip()
        if asset_id and not _SAFE_ID_RE.match(asset_id):
            respond(400, {'error': 'asset_id must match [A-Za-z0-9_-]{1,64}'})
        if len(asset_id) > MAX_CMDB_ASSET_ID:
            respond(400, {'error': f'asset_id too long (max {MAX_CMDB_ASSET_ID})'})
        rec['asset_id'] = asset_id
        changed.append('asset_id')

    if 'server_function' in body:
        fn = _cmdb_validate_function(body.get('server_function'))
        if fn is None:
            respond(400, {'error': 'server_function: alphanumerics/spaces/_-/, max 64 chars'})
        rec['server_function'] = fn
        changed.append('server_function')

    if 'hypervisor_url' in body:
        url = _cmdb_validate_url(body.get('hypervisor_url'))
        if url is None:
            respond(400, {'error': 'hypervisor_url must be http(s)://… and ≤512 chars'})
        rec['hypervisor_url'] = url
        changed.append('hypervisor_url')

    if 'ssh_port' in body:
        # Accept int, numeric string, or empty/None → reset to default.
        raw = body.get('ssh_port')
        if raw in (None, '', 0):
            port = CMDB_DEFAULT_SSH_PORT
        else:
            try:
                port = int(raw)
            except (TypeError, ValueError):
                respond(400, {'error': 'ssh_port must be an integer'})
            if port < CMDB_SSH_PORT_MIN or port > CMDB_SSH_PORT_MAX:
                respond(400, {'error': f'ssh_port must be between '
                                       f'{CMDB_SSH_PORT_MIN} and {CMDB_SSH_PORT_MAX}'})
        rec['ssh_port'] = port
        changed.append('ssh_port')

    if 'documentation' in body:
        doc = body.get('documentation') or ''
        if not isinstance(doc, str):
            respond(400, {'error': 'documentation must be a string'})
        if len(doc) > MAX_CMDB_DOC_LEN:
            respond(400, {'error': f'documentation too large (max {MAX_CMDB_DOC_LEN} bytes)'})
        rec['documentation'] = doc
        changed.append('documentation')

    if not changed:
        respond(400, {'error': 'no recognised fields to update'})

    rec['updated_by'] = actor
    rec['updated_at'] = int(time.time())
    cmdb[dev_id] = rec
    save(CMDB_FILE, cmdb)
    audit_log(actor, 'cmdb_update', detail=f'device={dev_id} fields={",".join(changed)}')
    respond(200, {'ok': True, 'record': _cmdb_strip_creds(rec)})


def _cmdb_validate_doc_title(raw) -> 'str | None':
    """Validate a CMDB doc title.

    Returns the cleaned title if valid, or None and emits a 400 response.
    Titles are required (a doc with no title is unsearchable in the UI).
    They have a sane upper bound — anything longer is probably a mistake.
    """
    if not isinstance(raw, str):
        respond(400, {'error': 'doc title must be a string'})
        return None
    title = raw.strip()
    if not title:
        respond(400, {'error': 'doc title is required'})
        return None
    if len(title) > MAX_CMDB_DOC_TITLE:
        respond(400, {'error': f'doc title too long (max {MAX_CMDB_DOC_TITLE})'})
        return None
    # Disallow control characters that could mangle UI rendering or
    # produce confusable headings. Allow common Unicode (people might
    # title things in their own language).
    if any(ord(c) < 0x20 and c not in '\t' for c in title):
        respond(400, {'error': 'doc title may not contain control characters'})
        return None
    return title


def _cmdb_validate_doc_body(raw) -> 'str | None':
    """Validate a CMDB doc body. Returns cleaned body or None with 400."""
    if not isinstance(raw, str):
        respond(400, {'error': 'doc body must be a string'})
        return None
    if len(raw) > MAX_CMDB_DOC_LEN:
        respond(400, {'error': f'doc body too large (max {MAX_CMDB_DOC_LEN} bytes)'})
        return None
    return raw


def handle_cmdb_doc_add(dev_id: str) -> None:
    """``POST /api/cmdb/{device_id}/docs`` — attach a new doc to an asset.

    Body: ``{"title": "...", "body": "..."}``. Body may be empty;
    title may not. Returns the created doc with its server-assigned id.

    The new doc is appended (not prepended) so existing UI ordering
    is preserved.
    """
    actor = require_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'device not found'})

    body = get_json_body()
    title = _cmdb_validate_doc_title(body.get('title'))
    if title is None:
        return
    doc_body = _cmdb_validate_doc_body(body.get('body', ''))
    if doc_body is None:
        return

    cmdb = _cmdb_load()
    rec = cmdb.get(dev_id) or _cmdb_record_default()
    docs = rec.get('docs') or []
    if len(docs) >= MAX_CMDB_DOCS:
        respond(400, {'error': f'too many docs (max {MAX_CMDB_DOCS} per asset)'})

    now = int(time.time())
    new_doc = {
        'id':         secrets.token_hex(6),   # 12 hex chars, ~48 bits — plenty per asset
        'title':      title,
        'body':       doc_body,
        'created_by': actor,
        'created_at': now,
        'updated_by': actor,
        'updated_at': now,
    }
    docs.append(new_doc)
    rec['docs'] = docs
    rec['updated_by'] = actor
    rec['updated_at'] = now
    cmdb[dev_id] = rec
    save(CMDB_FILE, cmdb)
    audit_log(actor, 'cmdb_doc_add', f'device={dev_id} doc={new_doc["id"]} title="{title}"')
    respond(200, new_doc)


def handle_cmdb_doc_update(dev_id: str, doc_id: str) -> None:
    """``PUT /api/cmdb/{device_id}/docs/{doc_id}`` — edit a doc.

    Body: any subset of ``{"title", "body"}``. Updates ``updated_by``
    and ``updated_at`` on the doc and on the parent record. Returns
    the updated doc.

    Migrated 'legacy' docs use a fixed id of ``legacy``; once edited,
    they get a real random id assigned to make subsequent operations
    less ambiguous and to clear the legacy flag.
    """
    actor = require_auth()
    if method() != 'PUT':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'device not found'})

    body = get_json_body()
    cmdb = _cmdb_load()
    rec = cmdb.get(dev_id)
    if rec is None:
        respond(404, {'error': 'no CMDB record'})
    docs = rec.get('docs') or []

    idx = next((i for i, d in enumerate(docs) if d.get('id') == doc_id), -1)
    if idx < 0:
        respond(404, {'error': 'doc not found'})
    doc = docs[idx]

    changed = []
    if 'title' in body:
        title = _cmdb_validate_doc_title(body.get('title'))
        if title is None:
            return
        doc['title'] = title
        changed.append('title')
    if 'body' in body:
        new_body = _cmdb_validate_doc_body(body.get('body'))
        if new_body is None:
            return
        doc['body'] = new_body
        changed.append('body')

    if not changed:
        respond(400, {'error': 'no recognised fields'})

    now = int(time.time())
    doc['updated_by'] = actor
    doc['updated_at'] = now
    # Promote legacy doc to a real id once edited
    if doc_id == 'legacy':
        doc['id'] = secrets.token_hex(6)
        # Clear the legacy field — it's been superseded by the docs list
        rec['documentation'] = ''
    docs[idx] = doc
    rec['docs'] = docs
    rec['updated_by'] = actor
    rec['updated_at'] = now
    cmdb[dev_id] = rec
    save(CMDB_FILE, cmdb)
    audit_log(actor, 'cmdb_doc_update',
              f'device={dev_id} doc={doc["id"]} changed={",".join(changed)}')
    respond(200, doc)


def handle_cmdb_doc_delete(dev_id: str, doc_id: str) -> None:
    """``DELETE /api/cmdb/{device_id}/docs/{doc_id}`` — remove a doc.

    Hard delete. Audit log retains the title so you can tell after the
    fact what got removed.
    """
    actor = require_auth()
    if method() != 'DELETE':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'device not found'})

    cmdb = _cmdb_load()
    rec = cmdb.get(dev_id)
    if rec is None:
        respond(404, {'error': 'no CMDB record'})
    docs = rec.get('docs') or []

    idx = next((i for i, d in enumerate(docs) if d.get('id') == doc_id), -1)
    if idx < 0:
        respond(404, {'error': 'doc not found'})

    removed = docs.pop(idx)
    # If we just deleted the last doc that's a legacy migration, clear
    # the back-compat field too. Otherwise it'd reappear on next load.
    if doc_id == 'legacy' and not docs:
        rec['documentation'] = ''

    rec['docs'] = docs
    rec['updated_by'] = actor
    rec['updated_at'] = int(time.time())
    cmdb[dev_id] = rec
    save(CMDB_FILE, cmdb)
    audit_log(actor, 'cmdb_doc_delete',
              f'device={dev_id} doc={doc_id} title="{removed.get("title", "")}"')
    respond(200, {'ok': True})


def handle_cmdb_server_functions() -> None:
    """``GET /api/cmdb/server-functions`` — distinct values for autocomplete.

    Returns the set of ``server_function`` values currently in use across
    all assets, sorted case-insensitively. The frontend feeds this into a
    ``<datalist>`` for the asset-edit modal.
    """
    require_auth()
    cmdb = _cmdb_load()
    seen = set()
    for rec in cmdb.values():
        fn = (rec or {}).get('server_function') or ''
        if fn:
            seen.add(fn)
    respond(200, sorted(seen, key=str.lower))


# ── Vault management endpoints ─────────────────────────────────────────────────

def handle_cmdb_vault_status() -> None:
    """``GET /api/cmdb/vault/status`` — has the vault been initialised?

    Returns a ``VaultStatus`` payload (see OpenAPI schema). Safe to call
    pre-login from the frontend bootstrap path — though it currently
    requires auth like every other endpoint.
    """
    require_auth()
    meta = _cmdb_get_vault_meta()
    respond(200, {
        'configured': cmdb_vault.is_configured(meta),
        'kdf':        meta.get('kdf') if meta else None,
        'iterations': meta.get('iterations') if meta else None,
        'created_at': meta.get('created_at') if meta else None,
        'created_by': meta.get('created_by') if meta else None,
    })


def handle_cmdb_vault_setup() -> None:
    """``POST /api/cmdb/vault/setup`` — initialise the credential vault.

    One-shot operation: subsequent calls return 409 even from the same
    admin. Use ``/cmdb/vault/change`` to rotate the passphrase later.

    The derived AES-GCM key is returned in the response so the browser
    doesn't need to re-unlock immediately after setup. The passphrase
    itself is never persisted.

    Audit:
        Logs ``cmdb_vault_setup`` with the chosen KDF.

    Raises:
        HTTPError 400: Passphrase fails strength validation.
        HTTPError 409: Vault already configured.
        HTTPError 500: ``cryptography`` package not installed.
    """
    actor = require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    meta = _cmdb_get_vault_meta()
    if cmdb_vault.is_configured(meta):
        respond(409, {'error': 'vault already configured'})
    body = get_json_body()
    passphrase = body.get('passphrase') or ''
    try:
        new_meta = cmdb_vault.setup_vault(passphrase)
    except cmdb_vault.VaultNotInstalledError as e:
        respond(500, {'error': str(e)})
    except cmdb_vault.VaultKeyError as e:
        respond(400, {'error': str(e)})
    new_meta['created_at'] = int(time.time())
    new_meta['created_by'] = actor
    save(CMDB_VAULT_FILE, new_meta)
    audit_log(actor, 'cmdb_vault_setup', detail=f'kdf={new_meta["kdf"]}')
    # Derive and return the key so the caller doesn't have to re-unlock
    key = cmdb_vault.derive_key_from_meta(passphrase, new_meta)
    respond(200, {'ok': True, 'key': key.hex()})


def handle_cmdb_vault_unlock() -> None:
    """``POST /api/cmdb/vault/unlock`` — derive the vault key from a passphrase.

    Any authenticated user can attempt to unlock; it's only the
    *credential operations* that require admin role. This split lets
    viewers see encrypted credential metadata (label, username) without
    being able to decrypt the password.

    Audit:
        Logs ``cmdb_vault_unlock`` on success, ``cmdb_vault_unlock_failed``
        on bad passphrase. Source IP recorded in both cases.
    """
    actor = require_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    meta = _cmdb_get_vault_meta()
    if not cmdb_vault.is_configured(meta):
        respond(409, {'error': 'vault not configured', 'code': 'vault_not_configured'})
    body = get_json_body()
    passphrase = body.get('passphrase') or ''
    try:
        key = cmdb_vault.derive_key_from_meta(passphrase, meta)
    except cmdb_vault.VaultNotInstalledError as e:
        respond(500, {'error': str(e)})
    except cmdb_vault.VaultKeyError as e:
        respond(400, {'error': str(e)})
    if not cmdb_vault.verify_key(key, meta):
        audit_log(actor, 'cmdb_vault_unlock_failed', detail='bad passphrase',
                  source_ip=_get_client_ip())
        respond(403, {'error': 'invalid passphrase'})
    audit_log(actor, 'cmdb_vault_unlock', source_ip=_get_client_ip())
    respond(200, {'ok': True, 'key': key.hex()})


def handle_cmdb_vault_change() -> None:
    """``POST /api/cmdb/vault/change`` — rotate passphrase, re-encrypt credentials.

    Walks every credential in the CMDB, decrypts under the old key, and
    re-encrypts under the new key. The new vault metadata is written
    first so a crash mid-rotation leaves the vault openable with the
    old passphrase. Credentials that fail to decrypt during rotation
    (corrupt entries) are dropped and logged as
    ``cmdb_vault_change_drop`` for the admin to investigate.

    Returns:
        ``{'ok': True, 'key': <hex>, 'rotated': <int>}`` where ``rotated``
        is the count of credentials successfully re-encrypted.
    """
    actor = require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    meta = _cmdb_get_vault_meta()
    if not cmdb_vault.is_configured(meta):
        respond(409, {'error': 'vault not configured'})
    body = get_json_body()
    old_pw = body.get('old_passphrase') or ''
    new_pw = body.get('new_passphrase') or ''

    try:
        old_key = cmdb_vault.derive_key_from_meta(old_pw, meta)
    except cmdb_vault.VaultNotInstalledError as e:
        respond(500, {'error': str(e)})
    except cmdb_vault.VaultKeyError as e:
        respond(400, {'error': str(e)})
    if not cmdb_vault.verify_key(old_key, meta):
        audit_log(actor, 'cmdb_vault_change_failed', detail='bad old passphrase',
                  source_ip=_get_client_ip())
        respond(403, {'error': 'invalid old passphrase'})

    try:
        new_meta = cmdb_vault.setup_vault(new_pw)
    except cmdb_vault.VaultKeyError as e:
        respond(400, {'error': str(e)})
    new_key = cmdb_vault.derive_key_from_meta(new_pw, new_meta)

    # Re-encrypt every credential in cmdb.json. We build the new file fully
    # before persisting it so a crash mid-rotation can't corrupt the vault.
    cmdb = _cmdb_load()
    rotated = 0
    for dev_id, rec in cmdb.items():
        new_creds = []
        for c in (rec.get('credentials') or []):
            try:
                pw_pt = cmdb_vault.decrypt(old_key,
                                           {'nonce': c.get('nonce', ''), 'ct': c.get('ct', '')})
            except cmdb_vault.VaultError:
                # Corrupt entry — drop it but log so the admin notices
                audit_log(actor, 'cmdb_vault_change_drop',
                          detail=f'device={dev_id} cred={c.get("id","?")} reason=decrypt_failed')
                continue
            blob = cmdb_vault.encrypt(new_key, pw_pt)
            new_c = dict(c)
            new_c['nonce'] = blob['nonce']
            new_c['ct']    = blob['ct']
            new_creds.append(new_c)
            rotated += 1
        rec['credentials'] = new_creds

    new_meta['created_at']   = meta.get('created_at') or int(time.time())
    new_meta['created_by']   = meta.get('created_by') or actor
    new_meta['rotated_at']   = int(time.time())
    new_meta['rotated_by']   = actor

    save(CMDB_VAULT_FILE, new_meta)
    save(CMDB_FILE, cmdb)
    audit_log(actor, 'cmdb_vault_change', detail=f'rotated_credentials={rotated}')
    respond(200, {'ok': True, 'key': new_key.hex(), 'rotated': rotated})


# ── Credentials CRUD (require admin + unlocked vault) ──────────────────────────

def handle_cmdb_credentials_list(dev_id: str) -> None:
    """``GET /api/cmdb/{device_id}/credentials`` — list credentials, metadata only.

    Returns each credential with ``id``, ``label``, ``username``, ``note``,
    and timestamps. The encrypted ciphertext is never included; callers
    that need plaintext use the dedicated ``/reveal`` endpoint.

    Args:
        dev_id: The enrolled device's ID.
    """
    require_auth()
    if not _validate_id(dev_id):
        respond(404, {'error': 'device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'device not found'})
    cmdb = _cmdb_load()
    rec = cmdb.get(dev_id) or _cmdb_record_default()
    safe = _cmdb_strip_creds(rec)
    respond(200, {'credentials': safe.get('credentials') or []})


def handle_cmdb_credentials_add(dev_id: str) -> None:
    """``POST /api/cmdb/{device_id}/credentials`` — encrypt and store a credential.

    Requires admin role and an unlocked vault (via the
    ``X-RP-Vault-Key`` request header). The plaintext password is
    AES-GCM-encrypted with a fresh nonce and stored alongside the
    plaintext metadata.

    Args:
        dev_id: The enrolled device's ID.

    Audit:
        Logs ``cmdb_credential_add`` with the credential ID + label.

    Raises:
        HTTPError 400: Missing/empty label or password, or password too long.
        HTTPError 401: Vault not unlocked (``code=vault_locked``).
        HTTPError 403: Bad vault key.
    """
    actor = require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'device not found'})
    devices = load(DEVICES_FILE)
    if dev_id not in devices:
        respond(404, {'error': 'device not found'})

    key, _meta = _cmdb_require_unlocked()
    body = get_json_body()
    label    = _sanitize_str(body.get('label', ''),    MAX_CMDB_LABEL,    allow_empty=False)
    username = _sanitize_str(body.get('username', ''), MAX_CMDB_USERNAME, allow_empty=True) or ''
    password = body.get('password', '')
    note     = _sanitize_str(body.get('note', ''),     MAX_CMDB_CRED_NOTE, allow_empty=True) or ''

    if not label:
        respond(400, {'error': 'label required'})
    if not isinstance(password, str):
        respond(400, {'error': 'password must be a string'})
    if len(password) > MAX_CMDB_PASSWORD:
        respond(400, {'error': f'password too long (max {MAX_CMDB_PASSWORD})'})
    if not password:
        respond(400, {'error': 'password required'})

    cmdb = _cmdb_load()
    rec = cmdb.get(dev_id) or _cmdb_record_default()
    creds = rec.get('credentials') or []
    if len(creds) >= MAX_CMDB_CREDS:
        respond(400, {'error': f'max {MAX_CMDB_CREDS} credentials per asset'})

    try:
        blob = cmdb_vault.encrypt(key, password)
    except cmdb_vault.VaultError as e:
        respond(500, {'error': f'encrypt failed: {e}'})

    now = int(time.time())
    new_id = 'cred_' + secrets.token_hex(8)
    creds.append({
        'id':         new_id,
        'label':      label,
        'username':   username,
        'note':       note,
        'nonce':      blob['nonce'],
        'ct':         blob['ct'],
        'created_by': actor,
        'created_at': now,
        'updated_by': actor,
        'updated_at': now,
    })
    rec['credentials'] = creds
    rec['updated_by']  = actor
    rec['updated_at']  = now
    cmdb[dev_id] = rec
    save(CMDB_FILE, cmdb)
    audit_log(actor, 'cmdb_credential_add',
              detail=f'device={dev_id} cred={new_id} label={label[:40]}')
    respond(200, {'ok': True, 'id': new_id})


def handle_cmdb_credentials_update(dev_id: str, cred_id: str) -> None:
    """``PUT /api/cmdb/{device_id}/credentials/{cred_id}`` — update a credential.

    Sends only the fields you want to change. The vault key is required
    only if the password is being changed; metadata-only edits skip
    the unlock check. This lets viewers (in some configurations) update
    their own labels without touching ciphertext.

    Args:
        dev_id: The enrolled device's ID.
        cred_id: The credential's ``cred_<hex>`` identifier.
    """
    actor = require_admin_auth()
    if method() != 'PUT':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'device not found'})
    if not cred_id.startswith('cred_') or not _validate_id(cred_id[len('cred_'):]):
        respond(404, {'error': 'credential not found'})

    cmdb = _cmdb_load()
    rec = cmdb.get(dev_id)
    if not rec:
        respond(404, {'error': 'credential not found'})
    creds = rec.get('credentials') or []
    idx = next((i for i, c in enumerate(creds) if c.get('id') == cred_id), -1)
    if idx < 0:
        respond(404, {'error': 'credential not found'})

    body = get_json_body()
    cred = dict(creds[idx])
    changed = []

    if 'label' in body:
        label = _sanitize_str(body.get('label', ''), MAX_CMDB_LABEL, allow_empty=False)
        if not label:
            respond(400, {'error': 'label cannot be empty'})
        cred['label'] = label
        changed.append('label')
    if 'username' in body:
        cred['username'] = _sanitize_str(body.get('username', ''),
                                         MAX_CMDB_USERNAME, allow_empty=True) or ''
        changed.append('username')
    if 'note' in body:
        cred['note'] = _sanitize_str(body.get('note', ''),
                                     MAX_CMDB_CRED_NOTE, allow_empty=True) or ''
        changed.append('note')
    if 'password' in body:
        password = body.get('password', '')
        if not isinstance(password, str):
            respond(400, {'error': 'password must be a string'})
        if len(password) > MAX_CMDB_PASSWORD:
            respond(400, {'error': f'password too long (max {MAX_CMDB_PASSWORD})'})
        if not password:
            respond(400, {'error': 'password cannot be empty'})
        key, _meta = _cmdb_require_unlocked()
        try:
            blob = cmdb_vault.encrypt(key, password)
        except cmdb_vault.VaultError as e:
            respond(500, {'error': f'encrypt failed: {e}'})
        cred['nonce'] = blob['nonce']
        cred['ct']    = blob['ct']
        changed.append('password')

    if not changed:
        respond(400, {'error': 'no recognised fields to update'})

    cred['updated_by'] = actor
    cred['updated_at'] = int(time.time())
    creds[idx] = cred
    rec['credentials'] = creds
    rec['updated_by']  = actor
    rec['updated_at']  = int(time.time())
    cmdb[dev_id] = rec
    save(CMDB_FILE, cmdb)
    audit_log(actor, 'cmdb_credential_update',
              detail=f'device={dev_id} cred={cred_id} fields={",".join(changed)}')
    respond(200, {'ok': True})


def handle_cmdb_credentials_delete(dev_id: str, cred_id: str) -> None:
    """``DELETE /api/cmdb/{device_id}/credentials/{cred_id}`` — hard-delete.

    The encrypted blob is removed from ``cmdb.json`` on save. The audit
    log keeps the ``cmdb_credential_delete`` entry but the ciphertext
    itself is gone — there's no trash can.

    Args:
        dev_id: The enrolled device's ID.
        cred_id: The credential's ``cred_<hex>`` identifier.
    """
    actor = require_admin_auth()
    if method() != 'DELETE':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'device not found'})
    if not cred_id.startswith('cred_') or not _validate_id(cred_id[len('cred_'):]):
        respond(404, {'error': 'credential not found'})

    cmdb = _cmdb_load()
    rec = cmdb.get(dev_id)
    if not rec:
        respond(404, {'error': 'credential not found'})
    creds = rec.get('credentials') or []
    remaining = [c for c in creds if c.get('id') != cred_id]
    if len(remaining) == len(creds):
        respond(404, {'error': 'credential not found'})
    rec['credentials'] = remaining
    rec['updated_by']  = actor
    rec['updated_at']  = int(time.time())
    cmdb[dev_id] = rec
    save(CMDB_FILE, cmdb)
    audit_log(actor, 'cmdb_credential_delete',
              detail=f'device={dev_id} cred={cred_id}')
    respond(200, {'ok': True})


def handle_cmdb_credentials_reveal(dev_id: str, cred_id: str) -> None:
    """``POST /api/cmdb/{device_id}/credentials/{cred_id}/reveal`` — return plaintext.

    The audit-logged moment of truth. Decrypts the credential's
    ciphertext using the vault key from the request header and returns
    the plaintext. Every reveal is recorded with actor, source IP,
    asset, and credential label so post-incident review can answer
    "who looked at the IPMI password last Thursday".

    Args:
        dev_id: The enrolled device's ID.
        cred_id: The credential's ``cred_<hex>`` identifier.

    Audit:
        ``cmdb_credential_reveal`` on success,
        ``cmdb_credential_reveal_failed`` on decrypt failure.
    """
    actor = require_admin_auth()
    if method() != 'POST':
        respond(405, {'error': 'Method not allowed'})
    if not _validate_id(dev_id):
        respond(404, {'error': 'device not found'})
    if not cred_id.startswith('cred_') or not _validate_id(cred_id[len('cred_'):]):
        respond(404, {'error': 'credential not found'})

    key, _meta = _cmdb_require_unlocked()

    cmdb = _cmdb_load()
    rec = cmdb.get(dev_id)
    if not rec:
        respond(404, {'error': 'credential not found'})
    cred = next((c for c in (rec.get('credentials') or []) if c.get('id') == cred_id), None)
    if not cred:
        respond(404, {'error': 'credential not found'})

    try:
        plaintext = cmdb_vault.decrypt(key,
                                       {'nonce': cred.get('nonce', ''), 'ct': cred.get('ct', '')})
    except cmdb_vault.VaultKeyError:
        audit_log(actor, 'cmdb_credential_reveal_failed',
                  detail=f'device={dev_id} cred={cred_id} reason=decrypt',
                  source_ip=_get_client_ip())
        respond(403, {'error': 'decryption failed — vault key may be stale'})
    except cmdb_vault.VaultError as e:
        respond(500, {'error': f'decrypt failed: {e}'})

    audit_log(actor, 'cmdb_credential_reveal',
              detail=f'device={dev_id} cred={cred_id} label={cred.get("label","")[:40]}',
              source_ip=_get_client_ip())
    respond(200, {
        'ok':       True,
        'id':       cred_id,
        'label':    cred.get('label', ''),
        'username': cred.get('username', ''),
        'password': plaintext,
        'note':     cred.get('note', ''),
    })


# ─── Router ────────────────────────────────────────────────────────────────────
def _is_demo_read_only() -> bool:
    """True if the server is running in demo / read-only mode.

    Controlled by the ``RP_READ_ONLY`` env var (set in the systemd unit,
    fcgiwrap config, or shell environment). Unset / empty / "0" / "false"
    means normal operation. Anything else means read-only.

    The env var lives outside the dashboard's reach — there's no API to
    toggle it. That's deliberate: a public sandbox shouldn't expose
    "stop being a sandbox" as a button somebody could find.
    """
    val = os.environ.get('RP_READ_ONLY', '').strip().lower()
    return val not in ('', '0', 'false', 'no', 'off')


# Endpoints that stay open even in read-only mode. Login is needed so
# visitors can browse with a session; logout is fine; the few small
# endpoints that issue/refresh credentials are safe because they don't
# touch user-controllable state. Heartbeat is NOT in this list — a
# demo server has no real agents, so heartbeat hits are noise we'd
# rather reject loudly.
_READ_ONLY_ALLOWED = frozenset({
    '/api/login',
    '/api/logout',
    '/api/totp/verify',
    '/api/public-info',
    '/api/openapi.json',
})


def _enforce_read_only():
    """Block non-GET requests in read-only mode, except whitelisted endpoints.

    Called from main() right before route dispatch. The whitelist is the
    minimal set needed to let an anonymous visitor log in to the demo
    user, browse, and log out. Everything else returns 403 with a
    friendly, demo-aware error body so the frontend can surface a
    helpful toast instead of a generic failure.
    """
    if not _is_demo_read_only():
        return
    if method() == 'GET':
        return
    pi = path_info()
    if pi in _READ_ONLY_ALLOWED:
        return
    respond(403, {
        'error': 'Demo mode — this is a read-only sandbox.',
        'detail': ('This instance is configured as a public demo. '
                   'Browsing works fully; nothing can be modified, deleted, '
                   'or executed. For the real thing, see '
                   'https://github.com/tyxak/remotepower'),
        'demo': True,
    })


def main():
    # v2.1.1: these per-request maintenance sweeps used to be wrapped in
    # bare `except Exception: pass` blocks. That silently swallowed every
    # error — including the ones an operator most needs to see: "why
    # didn't the offline webhook fire?" / "why isn't the schedule
    # running?". Now each one logs the exception traceback to stderr so
    # it lands in nginx's error log, but still doesn't propagate (the
    # CGI response itself must complete regardless of a maintenance
    # task failing).
    def _safe(fn, label):
        try:
            fn()
        except Exception as exc:
            sys.stderr.write(
                f"[remotepower] {label} failed: {exc.__class__.__name__}: {exc}\n")
            traceback.print_exc(file=sys.stderr)
    _safe(check_offline_webhooks, 'check_offline_webhooks')
    # v1.11.4: container-data-stale sweep, mirroring the offline check.
    # Cheap (one CONTAINERS_FILE read + per-device timestamp compare).
    _safe(check_container_webhooks, 'check_container_webhooks')
    # v1.11.8: monitor checks used to only run when somebody opened
    # the Monitor page in the dashboard. Now they run on every CGI hit
    # but gated to the configured interval (default 300s). For low-
    # traffic servers this means monitors run whenever an agent
    # heartbeats — typically every 60s, so the gate kicks in and the
    # actual checks happen every interval.
    _safe(run_monitors_if_due, 'run_monitors_if_due')
    _safe(process_schedule,    'process_schedule')

    # v2.0: gate mutations in read-only / demo mode. Cheap: one env var
    # read + a constant set membership check. Done before route dispatch
    # so every mutation handler is uniformly protected without needing
    # an assert_writable() call at the top of each one.
    _enforce_read_only()

    pi = path_info(); m = method()

    if pi == '/api/login': handle_login()
    elif pi == '/api/public-info' and m == 'GET': handle_public_info()
    elif pi == '/api/openapi.json' and m == 'GET': handle_openapi_spec()
    elif pi == '/api/devices' and m == 'GET': handle_devices_list()
    # v1.11.0: agentless device creation. Must precede the prefix-DELETE
    # check so a POST to /api/devices/agentless doesn't get misrouted.
    elif pi == '/api/devices/agentless' and m == 'POST': handle_agentless_create()
    elif pi.startswith('/api/devices/') and m == 'DELETE' and not any(
            pi.endswith(s) for s in ('/tags','/notes','/group','/sysinfo','/uptime',
                                     '/output','/metrics','/allowlist','/poll_interval',
                                     '/icon','/monitored','/cve','/services',
                                     '/services/config','/logs','/update-logs',
                                     '/containers','/connected-to',
                                     # v1.11.10
                                     '/metric-thresholds')):
        handle_device_delete(pi[len('/api/devices/'):])
    elif pi.startswith('/api/devices/') and pi.endswith('/tags') and m == 'PATCH':
        handle_device_tags(pi[len('/api/devices/'):-len('/tags')])
    elif pi.startswith('/api/devices/') and pi.endswith('/notes') and m == 'PATCH':
        handle_device_notes(pi[len('/api/devices/'):-len('/notes')])
    # v1.11.10: per-device metric threshold overrides (GET/PATCH/DELETE)
    elif pi.startswith('/api/devices/') and pi.endswith('/metric-thresholds') \
            and m in ('GET', 'PATCH', 'DELETE'):
        handle_device_metric_thresholds(pi[len('/api/devices/'):-len('/metric-thresholds')])
    elif pi.startswith('/api/devices/') and pi.endswith('/group') and m == 'PATCH':
        handle_device_group(pi[len('/api/devices/'):-len('/group')])
    elif pi.startswith('/api/devices/') and pi.endswith('/poll_interval') and m == 'PATCH':
        handle_device_poll_interval(pi[len('/api/devices/'):-len('/poll_interval')])
    elif pi.startswith('/api/devices/') and pi.endswith('/icon') and m == 'PATCH':
        handle_device_icon(pi[len('/api/devices/'):-len('/icon')])
    elif pi.startswith('/api/devices/') and pi.endswith('/monitored') and m == 'PATCH':
        handle_device_monitored(pi[len('/api/devices/'):-len('/monitored')])
    elif pi.startswith('/api/devices/') and pi.endswith('/sysinfo') and m == 'GET':
        handle_sysinfo(pi[len('/api/devices/'):-len('/sysinfo')])
    elif pi.startswith('/api/devices/') and pi.endswith('/metrics') and m == 'GET':
        handle_metrics(pi[len('/api/devices/'):-len('/metrics')])
    elif pi.startswith('/api/devices/') and pi.endswith('/allowlist'):
        handle_device_allowlist(pi[len('/api/devices/'):-len('/allowlist')])
    elif pi == '/api/enroll/pin': handle_enroll_pin()
    elif pi == '/api/enroll/register': handle_enroll_register()
    # v1.11.10: pre-shared one-time-use enrollment tokens for non-interactive
    # enrollment. Same final destination as /enroll/register, but via a
    # different credential path.
    elif pi == '/api/enrollment-tokens' and m == 'POST': handle_enroll_token_create()
    elif pi == '/api/enrollment-tokens' and m == 'GET':  handle_enroll_token_list()
    elif pi.startswith('/api/enrollment-tokens/') and m == 'DELETE':
        handle_enroll_token_revoke(pi[len('/api/enrollment-tokens/'):])
    # v1.11.11: web terminal — only the auth + audit endpoints live in CGI.
    # The actual websocket /api/webterm/connect is proxied by nginx to the
    # remotepower-webterm daemon (see packaging/nginx-webterm.conf).
    elif pi == '/api/webterm/auth'  and m == 'POST': handle_webterm_auth()
    elif pi == '/api/webterm/audit' and m == 'POST': handle_webterm_session_audit()
    elif pi == '/api/heartbeat': handle_heartbeat()
    elif pi == '/api/shutdown': handle_shutdown()
    elif pi == '/api/reboot': handle_reboot()
    elif pi == '/api/update-device': handle_update_device()
    elif pi == '/api/upgrade-device': handle_upgrade_device()
    elif pi == '/api/wol': handle_wol()
    elif pi == '/api/monitor' and m == 'GET': handle_monitor_run()
    elif pi == '/api/config' and m == 'GET': handle_config_get()
    elif pi == '/api/config' and m == 'POST': handle_config_save()
    elif pi == '/api/history' and m == 'GET': handle_history()
    elif pi == '/api/history' and m == 'DELETE': handle_history_clear()
    elif pi == '/api/users' and m == 'GET': handle_users_list()
    elif pi == '/api/users' and m == 'POST': handle_user_create()
    elif pi.startswith('/api/users/') and not pi.endswith('/passwd') and m == 'DELETE':
        handle_user_delete(pi[len('/api/users/'):])
    elif pi == '/api/users/passwd' and m == 'POST': handle_user_passwd()
    # v1.11.5: per-user UI preferences (density / filter / sort persistence)
    elif pi == '/api/ui-prefs' and m == 'GET':    handle_ui_prefs_get()
    elif pi == '/api/ui-prefs' and m == 'POST':   handle_ui_prefs_set()
    elif pi == '/api/ui-prefs' and m == 'DELETE': handle_ui_prefs_clear()
    elif pi == '/api/totp/setup' and m == 'POST': handle_totp_setup()
    elif pi == '/api/totp/confirm' and m == 'POST': handle_totp_confirm()
    elif pi == '/api/totp/disable' and m == 'POST': handle_totp_disable()
    elif pi == '/api/totp/status' and m == 'GET': handle_totp_status()
    elif pi == '/api/agent/version' and m == 'GET': handle_agent_version()
    elif pi == '/api/agent/download' and m == 'GET': handle_agent_download()
    elif pi == '/api/version' and m == 'GET': handle_version_check()
    elif pi == '/api/schedule' and m == 'GET': handle_schedule_list()
    elif pi == '/api/schedule' and m == 'POST': handle_schedule_add()
    elif pi.startswith('/api/schedule/') and m == 'DELETE':
        handle_schedule_delete(pi[len('/api/schedule/'):])
    elif pi == '/api/exec' and m == 'POST': handle_custom_cmd()
    elif pi == '/api/exec/wait' and m == 'POST': handle_longpoll_exec()
    elif pi.startswith('/api/devices/') and pi.endswith('/output') and m == 'GET':
        handle_cmd_output(pi[len('/api/devices/'):-len('/output')])
    elif pi.startswith('/api/devices/') and pi.endswith('/update-logs') and m == 'GET':
        handle_device_update_logs(pi[len('/api/devices/'):-len('/update-logs')])
    elif pi.startswith('/api/devices/') and pi.endswith('/uptime') and m == 'GET':
        handle_uptime(pi[len('/api/devices/'):-len('/uptime')])
    elif pi == '/api/fleet/uptime7d' and m == 'GET':
        handle_fleet_uptime7d()
    elif pi == '/api/monitor/history' and m == 'GET':
        from urllib.parse import parse_qs
        label = parse_qs(os.environ.get('QUERY_STRING', '')).get('label', [''])[0]
        handle_monitor_history(label)
    elif pi == '/api/cmd-library' and m == 'GET': handle_cmd_library_list()
    elif pi == '/api/cmd-library' and m == 'POST': handle_cmd_library_add()
    elif pi.startswith('/api/cmd-library/') and m == 'DELETE':
        handle_cmd_library_delete(pi[len('/api/cmd-library/'):])
    # ── v2.1.0: multi-line script library + batch exec ─────────────────────
    elif pi == '/api/scripts' and m == 'GET': handle_scripts_list()
    elif pi == '/api/scripts' and m == 'POST': handle_scripts_add()
    elif pi.startswith('/api/scripts/') and pi.endswith('/dry-run') and m == 'POST':
        handle_scripts_dry_run(pi[len('/api/scripts/'):-len('/dry-run')])
    elif pi.startswith('/api/scripts/') and m == 'GET':
        handle_scripts_get(pi[len('/api/scripts/'):])
    elif pi.startswith('/api/scripts/') and m == 'PUT':
        handle_scripts_update(pi[len('/api/scripts/'):])
    elif pi.startswith('/api/scripts/') and m == 'DELETE':
        handle_scripts_delete(pi[len('/api/scripts/'):])
    elif pi == '/api/exec/batch' and m == 'POST': handle_exec_batch()
    elif pi.startswith('/api/exec/batch/') and m == 'GET':
        handle_exec_batch_status(pi[len('/api/exec/batch/'):])
    # v2.1.3: AI assistant
    elif pi == '/api/ai/config' and m == 'GET':  handle_ai_config_get()
    elif pi == '/api/ai/config' and m == 'POST': handle_ai_config_set()
    elif pi == '/api/ai/chat'   and m == 'POST': handle_ai_chat()
    elif pi == '/api/ai/test'   and m == 'POST': handle_ai_test()
    elif pi == '/api/ai/models' and m == 'GET':  handle_ai_models()
    elif pi == '/api/ai/stats'  and m == 'GET':  handle_ai_stats()
    # v2.1.7: per-device AI-generated runbooks
    elif pi.startswith('/api/devices/') and pi.endswith('/runbook') and m == 'GET':
        handle_runbook_get(pi[len('/api/devices/'):-len('/runbook')])
    elif pi.startswith('/api/devices/') and pi.endswith('/runbook/generate') and m == 'POST':
        handle_runbook_generate(pi[len('/api/devices/'):-len('/runbook/generate')])
    elif pi.startswith('/api/devices/') and pi.endswith('/runbook') and m == 'DELETE':
        handle_runbook_delete(pi[len('/api/devices/'):-len('/runbook')])
    # v2.2.0: configuration drift detection
    elif pi == '/api/drift' and m == 'GET':
        handle_drift_overview()
    elif pi.startswith('/api/devices/') and pi.endswith('/drift') and m == 'GET':
        handle_device_drift_get(pi[len('/api/devices/'):-len('/drift')])
    elif pi.startswith('/api/devices/') and pi.endswith('/drift/baseline') and m == 'POST':
        handle_device_drift_baseline(pi[len('/api/devices/'):-len('/drift/baseline')])
    # v2.2.1: drift content fetch (diff visualisation)
    elif pi.startswith('/api/devices/') and pi.endswith('/drift/fetch_content') and m == 'POST':
        handle_drift_fetch_content(pi[len('/api/devices/'):-len('/drift/fetch_content')])
    elif pi.startswith('/api/devices/') and pi.endswith('/drift/content') and m == 'GET':
        handle_drift_get_content(pi[len('/api/devices/'):-len('/drift/content')])
    elif pi.startswith('/api/devices/') and pi.endswith('/drift') and m == 'DELETE':
        handle_device_drift_reset(pi[len('/api/devices/'):-len('/drift')])
    # v2.3.4: per-file drift ignore toggle
    elif pi.startswith('/api/devices/') and pi.endswith('/drift/ignore') and m == 'POST':
        handle_drift_ignore(pi[len('/api/devices/'):-len('/drift/ignore')])
    # v2.4.3: mailbox-count monitor config (paths + dashboard promotion)
    elif pi.startswith('/api/devices/') and pi.endswith('/mailwatch') and m == 'POST':
        handle_mailwatch_set(pi[len('/api/devices/'):-len('/mailwatch')])
    elif pi == '/api/mailwatch' and m == 'GET':
        handle_mailwatch_overview()
    # v2.4.6: update-available check is handled by /api/version above
    # v2.4.7: needs-attention digest + machine-readable status endpoint
    elif pi == '/api/attention' and m == 'GET':
        handle_attention()
    elif pi == '/api/status' and m == 'GET':
        handle_status()
    elif pi == '/api/status-token' and m == 'POST':
        handle_status_token()
    # v2.4.5: force a package scan on the device's next heartbeat
    elif pi.startswith('/api/devices/') and pi.endswith('/scan-packages') and m == 'POST':
        handle_force_package_scan(pi[len('/api/devices/'):-len('/scan-packages')])
    elif pi == '/api/apikeys' and m == 'GET': handle_apikeys_list()
    elif pi == '/api/apikeys' and m == 'POST': handle_apikeys_create()
    elif pi.startswith('/api/apikeys/') and m == 'DELETE':
        handle_apikeys_delete(pi[len('/api/apikeys/'):])
    elif pi == '/api/export' and m == 'GET': handle_export()
    elif pi == '/api/digest' and m == 'GET': handle_digest()
    elif pi == '/api/patch-report' and m == 'GET': handle_patch_report()
    elif pi.startswith('/api/patch-report/device/') and m == 'GET':
        handle_patch_report_device(pi[len('/api/patch-report/device/'):])
    elif pi == '/api/patch-report/csv' and m == 'GET': handle_patch_report_csv()
    elif pi == '/api/patch-report/xml' and m == 'GET': handle_patch_report_xml()
    elif pi == '/api/audit-log' and m == 'GET': handle_audit_log()
    elif pi == '/api/audit-log' and m == 'DELETE': handle_audit_log_clear()
    elif pi == '/api/webhook/test' and m == 'POST': handle_webhook_test()
    elif pi == '/api/webhook/log' and m == 'GET': handle_webhook_log()
    elif pi == '/api/webhook/log' and m == 'DELETE': handle_webhook_log_clear()
    # v2.2.4: fleet event log (every fired event, regardless of destinations)
    elif pi == '/api/fleet/events' and m == 'GET': handle_fleet_events()
    # ── v1.8.6: SMTP + LDAP test endpoints ─────────────────────────────────────
    elif pi == '/api/smtp/test' and m == 'POST': handle_smtp_test()
    elif pi == '/api/ldap/test' and m == 'POST': handle_ldap_test()
    elif pi == '/api/ldap/test-user' and m == 'POST': handle_ldap_test_user()
    elif pi == '/api/monitor/alerts/clear' and m == 'DELETE': handle_monitor_alerts_clear()
    elif pi == '/api/sessions/revoke' and m == 'POST': handle_revoke_sessions()

    # ── v1.7.0: Package inventory + CVE scanner ────────────────────────────────
    elif pi == '/api/packages' and m == 'POST': handle_packages_submit()
    elif pi == '/api/cve/scan' and m == 'POST': handle_cve_scan()
    elif pi == '/api/cve/findings' and m == 'GET': handle_cve_findings()
    elif pi == '/api/cve/ignore' and m == 'GET': handle_cve_ignore_list()
    elif pi == '/api/cve/ignore' and m == 'POST': handle_cve_ignore_add()
    elif pi.startswith('/api/cve/ignore/') and m == 'DELETE':
        handle_cve_ignore_delete(pi[len('/api/cve/ignore/'):])
    elif pi.startswith('/api/devices/') and pi.endswith('/cve') and m == 'GET':
        handle_cve_device(pi[len('/api/devices/'):-len('/cve')])

    # ── v1.7.0: Prometheus metrics endpoint ────────────────────────────────────
    elif pi == '/api/metrics' and m == 'GET': handle_prometheus_metrics()

    # ── v1.8.0: Service monitoring ─────────────────────────────────────────────
    elif pi == '/api/services' and m == 'GET': handle_services_get()
    elif pi.startswith('/api/devices/') and pi.endswith('/services') and m == 'GET':
        handle_services_device(pi[len('/api/devices/'):-len('/services')])
    elif pi.startswith('/api/devices/') and pi.endswith('/services/config'):
        handle_services_config(pi[len('/api/devices/'):-len('/services/config')])

    # ── v1.8.0: Log tail + pattern alerts ──────────────────────────────────────
    elif pi == '/api/logs' and m == 'POST': handle_log_submit()
    elif pi == '/api/logs/search' and m == 'GET': handle_log_search()
    # ── v1.8.1: live tail + rules aggregate ────────────────────────────────────
    elif pi == '/api/logs/tail' and m == 'GET': handle_log_tail()
    elif pi == '/api/logs/rules' and m == 'GET': handle_log_rules()
    # ── v1.8.2: fleet-wide log alert rules ─────────────────────────────────────
    elif pi == '/api/logs/rules/global' and m == 'GET': handle_log_rules_global_list()
    elif pi == '/api/logs/rules/global' and m == 'POST': handle_log_rules_global_add()
    elif pi.startswith('/api/logs/rules/global/') and m == 'DELETE':
        handle_log_rules_global_delete(pi[len('/api/logs/rules/global/'):])
    elif pi.startswith('/api/devices/') and pi.endswith('/logs') and m == 'GET':
        handle_log_device(pi[len('/api/devices/'):-len('/logs')])

    # ── v1.8.0: Maintenance windows ────────────────────────────────────────────
    elif pi == '/api/maintenance' and m == 'GET': handle_maintenance_list()
    elif pi == '/api/maintenance' and m == 'POST': handle_maintenance_add()
    elif pi == '/api/maintenance/suppressions' and m == 'GET':
        handle_maintenance_suppressions()
    elif pi.startswith('/api/maintenance/') and m == 'DELETE':
        handle_maintenance_delete(pi[len('/api/maintenance/'):])

    # ── v1.8.3: Shared calendar events ─────────────────────────────────────────
    elif pi == '/api/calendar' and m == 'GET':  handle_calendar_list()
    elif pi == '/api/calendar' and m == 'POST': handle_calendar_add()
    elif pi.startswith('/api/calendar/') and m == 'PUT':
        handle_calendar_update(pi[len('/api/calendar/'):])
    elif pi.startswith('/api/calendar/') and m == 'DELETE':
        handle_calendar_delete(pi[len('/api/calendar/'):])

    # ── v1.8.3: Shared tasks board ─────────────────────────────────────────────
    elif pi == '/api/tasks' and m == 'GET':  handle_tasks_list()
    elif pi == '/api/tasks' and m == 'POST': handle_tasks_add()
    elif pi.startswith('/api/tasks/') and m == 'PUT':
        handle_tasks_update(pi[len('/api/tasks/'):])
    elif pi.startswith('/api/tasks/') and m == 'DELETE':
        handle_tasks_delete(pi[len('/api/tasks/'):])

    # ── v1.9.0: CMDB ───────────────────────────────────────────────────────────
    # Vault management — order matters, more specific paths first
    elif pi == '/api/cmdb/vault/status'  and m == 'GET':  handle_cmdb_vault_status()
    elif pi == '/api/cmdb/vault/setup'   and m == 'POST': handle_cmdb_vault_setup()
    elif pi == '/api/cmdb/vault/unlock'  and m == 'POST': handle_cmdb_vault_unlock()
    elif pi == '/api/cmdb/vault/change'  and m == 'POST': handle_cmdb_vault_change()
    # Server-function autocomplete list
    elif pi == '/api/cmdb/server-functions' and m == 'GET': handle_cmdb_server_functions()
    # Per-device credential CRUD — match before the generic /api/cmdb/{id} route
    elif pi.startswith('/api/cmdb/') and pi.endswith('/credentials') and m == 'GET':
        handle_cmdb_credentials_list(pi[len('/api/cmdb/'):-len('/credentials')])
    elif pi.startswith('/api/cmdb/') and pi.endswith('/credentials') and m == 'POST':
        handle_cmdb_credentials_add(pi[len('/api/cmdb/'):-len('/credentials')])
    elif pi.startswith('/api/cmdb/') and '/credentials/' in pi and pi.endswith('/reveal') and m == 'POST':
        # /api/cmdb/{dev}/credentials/{cred}/reveal
        rest = pi[len('/api/cmdb/'):-len('/reveal')]
        dev_id, _, cred_id = rest.partition('/credentials/')
        handle_cmdb_credentials_reveal(dev_id, cred_id)
    elif pi.startswith('/api/cmdb/') and '/credentials/' in pi and m == 'PUT':
        rest = pi[len('/api/cmdb/'):]
        dev_id, _, cred_id = rest.partition('/credentials/')
        handle_cmdb_credentials_update(dev_id, cred_id)
    elif pi.startswith('/api/cmdb/') and '/credentials/' in pi and m == 'DELETE':
        rest = pi[len('/api/cmdb/'):]
        dev_id, _, cred_id = rest.partition('/credentials/')
        handle_cmdb_credentials_delete(dev_id, cred_id)
    # v2.0: multi-doc per asset. Match before generic /api/cmdb/{id} route.
    elif pi.startswith('/api/cmdb/') and pi.endswith('/docs') and m == 'POST':
        handle_cmdb_doc_add(pi[len('/api/cmdb/'):-len('/docs')])
    elif pi.startswith('/api/cmdb/') and '/docs/' in pi and m == 'PUT':
        rest = pi[len('/api/cmdb/'):]
        dev_id, _, doc_id = rest.partition('/docs/')
        handle_cmdb_doc_update(dev_id, doc_id)
    elif pi.startswith('/api/cmdb/') and '/docs/' in pi and m == 'DELETE':
        rest = pi[len('/api/cmdb/'):]
        dev_id, _, doc_id = rest.partition('/docs/')
        handle_cmdb_doc_delete(dev_id, doc_id)
    # Asset list + per-asset metadata
    elif pi == '/api/cmdb' and m == 'GET':  handle_cmdb_list()
    elif pi.startswith('/api/cmdb/') and m == 'GET':
        handle_cmdb_get(pi[len('/api/cmdb/'):])
    elif pi.startswith('/api/cmdb/') and m == 'PUT':
        handle_cmdb_update(pi[len('/api/cmdb/'):])

    # ── v1.11.0: containers ────────────────────────────────────────────────
    elif pi == '/api/containers' and m == 'GET': handle_containers_overview()
    elif pi.startswith('/api/devices/') and pi.endswith('/containers') and m == 'GET':
        handle_device_containers(pi[len('/api/devices/'):-len('/containers')])
    # v1.11.4: manual clear of a device's container snapshot. Useful for
    # decommissioning, or for forcing a redraw without waiting for the next
    # heartbeat after deliberate `docker rm`.
    elif pi.startswith('/api/devices/') and pi.endswith('/containers') and m == 'DELETE':
        handle_device_containers_clear(pi[len('/api/devices/'):-len('/containers')])

    # ── v2.3.0: Proxmox virtualization ─────────────────────────────────────
    elif pi == '/api/proxmox/status' and m == 'GET':
        handle_proxmox_status()
    elif pi == '/api/proxmox/test' and m == 'POST':
        handle_proxmox_test()
    elif pi == '/api/proxmox/qemu' and m == 'GET':
        handle_proxmox_list('qemu')
    elif pi == '/api/proxmox/lxc' and m == 'GET':
        handle_proxmox_list('lxc')
    elif pi.startswith('/api/proxmox/qemu/') and m == 'POST':
        handle_proxmox_action('qemu', pi[len('/api/proxmox/qemu/'):])
    elif pi.startswith('/api/proxmox/lxc/') and m == 'POST':
        handle_proxmox_action('lxc', pi[len('/api/proxmox/lxc/'):])
    # v2.4.0: Proxmox snapshots — list / create / rollback / delete.
    elif pi == '/api/proxmox/snapshots' and m == 'GET':
        handle_proxmox_snapshots_list()
    elif pi == '/api/proxmox/snapshot' and m == 'POST':
        handle_proxmox_snapshot_action()

    # ── v2.1.0: docker-compose dropdown ────────────────────────────────────
    elif pi.startswith('/api/devices/') and pi.endswith('/compose') and m == 'GET':
        handle_device_compose_list(pi[len('/api/devices/'):-len('/compose')])
    elif pi.startswith('/api/devices/') and pi.endswith('/compose/action') and m == 'POST':
        handle_device_compose_action(pi[len('/api/devices/'):-len('/compose/action')])
    # v2.1.1: per-container start/stop/restart from the Containers page
    elif pi.startswith('/api/devices/') and pi.endswith('/containers/action') and m == 'POST':
        handle_device_container_action(pi[len('/api/devices/'):-len('/containers/action')])

    # ── v1.11.0: TLS / DNS expiry monitor ──────────────────────────────────
    elif pi == '/api/tls/targets' and m == 'GET':  handle_tls_list()
    elif pi == '/api/tls/targets' and m == 'POST': handle_tls_add()
    elif pi.startswith('/api/tls/targets/') and m == 'DELETE':
        handle_tls_delete(pi[len('/api/tls/targets/'):])
    elif pi == '/api/tls/scan' and m == 'POST': handle_tls_scan()

    # ── v1.11.0: network map + agentless device link ──────────────────────
    elif pi == '/api/network-map' and m == 'GET': handle_network_map()
    elif pi.startswith('/api/devices/') and pi.endswith('/connected-to') and m == 'PUT':
        handle_device_connected_to(pi[len('/api/devices/'):-len('/connected-to')])

    # ── v1.11.1: positions + tunnels ───────────────────────────────────────
    elif pi == '/api/network-map/positions' and m == 'PUT': handle_network_positions()
    elif pi == '/api/network-map/tunnels'   and m == 'GET':  handle_tunnels_list()
    elif pi == '/api/network-map/tunnels'   and m == 'POST': handle_tunnel_add()
    elif pi.startswith('/api/network-map/tunnels/') and m == 'DELETE':
        handle_tunnel_delete(pi[len('/api/network-map/tunnels/'):])

    # ── v1.11.2: shared link dashboard ────────────────────────────────────
    elif pi == '/api/links' and m == 'GET':  handle_links_list()
    elif pi == '/api/links' and m == 'POST': handle_link_add()
    elif pi.startswith('/api/links/') and m == 'PUT':
        handle_link_update(pi[len('/api/links/'):])
    elif pi.startswith('/api/links/') and m == 'DELETE':
        handle_link_delete(pi[len('/api/links/'):])

    # ── v2.5.0: custom monitoring scripts ──────────────────────────────────
    elif pi == '/api/custom-scripts' and m == 'GET':
        handle_custom_scripts_list()
    elif pi == '/api/custom-scripts' and m == 'POST':
        handle_custom_script_create()
    elif pi == '/api/custom-scripts/results' and m == 'GET':
        handle_custom_scripts_results()
    elif pi.startswith('/api/custom-scripts/') and m == 'GET':
        handle_custom_script_get(pi[len('/api/custom-scripts/'):])
    elif pi.startswith('/api/custom-scripts/') and m == 'PUT':
        handle_custom_script_update(pi[len('/api/custom-scripts/'):])
    elif pi.startswith('/api/custom-scripts/') and m == 'DELETE':
        handle_custom_script_delete(pi[len('/api/custom-scripts/'):])

    # ── v2.6.0: host configuration management ──────────────────────────────
    elif pi.startswith('/api/devices/') and pi.endswith('/host-config') and m == 'GET':
        handle_device_host_config_get(pi[len('/api/devices/'):-len('/host-config')])
    elif pi.startswith('/api/devices/') and pi.endswith('/host-config') and m == 'PUT':
        handle_device_host_config_put(pi[len('/api/devices/'):-len('/host-config')])
    elif pi.startswith('/api/devices/') and pi.endswith('/host-config/current') and m == 'GET':
        handle_device_host_config_current(pi[len('/api/devices/'):-len('/host-config/current')])

    else: respond(404, {'error': 'Not found'})



# ─── v2.6.0: Host Configuration Management ───────────────────────────────────


def _validate_host_config_section(section, val):
    """Validate and sanitize a single host config section value.
    Returns the sanitized value or raises HTTPError on bad input."""
    if section in HOST_CONFIG_TEXT_SECTIONS:
        if not isinstance(val, str):
            respond(400, {'error': f'{section} must be a string'})
        if len(val.encode('utf-8', errors='replace')) > MAX_HOST_CONFIG_SECTION_SIZE:
            respond(400, {'error': f'{section} exceeds 64 KB limit'})
        if '\x00' in val:
            respond(400, {'error': f'{section} contains NUL bytes'})
        return val
    elif section == 'services':
        if not isinstance(val, list):
            respond(400, {'error': 'services must be a list of strings'})
        return [_sanitize_str(str(s), 128) for s in val[:200] if str(s).strip()]
    elif section == 'users':
        if not isinstance(val, list):
            respond(400, {'error': 'users must be a list'})
        out = []
        for u in val[:100]:
            if not isinstance(u, dict):
                continue
            name = _sanitize_str(u.get('name', ''), 64).strip()
            if not name:
                continue
            out.append({
                'name':            name,
                'shell':           _sanitize_str(u.get('shell', '/bin/bash'), 128),
                'groups':          [_sanitize_str(g, 64) for g in
                                    (u.get('groups') or [])[:30]],
                'authorized_keys': _sanitize_str(u.get('authorized_keys', ''), 16384),
            })
        return out
    elif section == 'groups':
        if not isinstance(val, list):
            respond(400, {'error': 'groups must be a list'})
        out = []
        for g in val[:100]:
            if not isinstance(g, dict):
                continue
            name = _sanitize_str(g.get('name', ''), 64).strip()
            if not name:
                continue
            gid = g.get('gid')
            out.append({
                'name': name,
                'gid':  int(gid) if isinstance(gid, int) and 0 < gid < 65536 else None,
            })
        return out
    respond(400, {'error': f'Unknown section: {section}'})


def _audit_host_config_drift(desired, current):
    """Compare desired vs current host config. Return list of sections with drift."""
    drifting = []
    for section in HOST_CONFIG_ALL_SECTIONS:
        if section not in desired:
            continue
        if section not in current:
            drifting.append(section)
            continue
        d = desired[section]
        c = current[section]
        if section in HOST_CONFIG_TEXT_SECTIONS:
            # Normalize line endings and trailing whitespace
            if d.strip().replace('\r\n', '\n') != c.strip().replace('\r\n', '\n'):
                drifting.append(section)
        elif section == 'services':
            # All desired services must be present in current enabled list
            d_set = set(d) if isinstance(d, list) else set()
            c_set = set(c) if isinstance(c, list) else set()
            if not d_set.issubset(c_set):
                drifting.append(section)
        elif section == 'users':
            c_map = {u['name']: u for u in (c or []) if isinstance(u, dict)}
            for u in (d or []):
                name = u.get('name')
                if name not in c_map:
                    drifting.append(section)
                    break
                cu = c_map[name]
                if u.get('shell') and u['shell'] != cu.get('shell'):
                    drifting.append(section)
                    break
                d_keys = u.get('authorized_keys', '').strip()
                c_keys = cu.get('authorized_keys', '').strip()
                if d_keys and d_keys != c_keys:
                    drifting.append(section)
                    break
                d_grps = set(u.get('groups') or [])
                c_grps = set(cu.get('groups') or [])
                if not d_grps.issubset(c_grps):
                    drifting.append(section)
                    break
        elif section == 'groups':
            c_names = {g['name'] for g in (c or []) if isinstance(g, dict)}
            for g in (d or []):
                if g.get('name') not in c_names:
                    drifting.append(section)
                    break
    return drifting


def _ingest_host_config_current(dev_id, dev_name, current):
    """Store current host config state reported by agent; run drift audit.

    Current state is written to DATA_DIR/host_config_current/<dev_id>.json
    rather than inside devices.json — it can be several hundred KB of file
    contents (repos, netplan, authorized_keys…) and would bloat devices.json,
    slowing every API call that reads it.
    """
    if not isinstance(current, dict):
        return
    now = int(time.time())

    # Persist current state to its own small file
    HOST_CONFIG_CURRENT_DIR.mkdir(exist_ok=True)
    current_path = HOST_CONFIG_CURRENT_DIR / f'{dev_id}.json'
    payload      = {'current': current, 'collected_at': now}
    save(current_path, payload)

    # Read desired config from devices.json and run drift audit
    with _locked_update(DEVICES_FILE) as devices:
        if dev_id not in devices:
            return
        hc      = devices[dev_id].setdefault('host_config', {})
        desired = hc.get('desired', {})
        if not desired:
            return
        drifting  = _audit_host_config_drift(desired, current)
        was_clean = not hc.get('drift', {}).get('sections')
        hc['drift'] = {
            'sections':   drifting,
            'checked_at': now,
            'clean':      not drifting,
        }
        # Store only the drift summary — NOT the full current state
        hc['current_collected_at'] = now

    # Edge-triggered: fire webhook only on first drift detection
    if drifting and was_clean:
        fire_webhook('config_drift', {
            'device_id': dev_id,
            'name':      dev_name,
            'sections':  drifting,
        })


def handle_device_host_config_get(dev_id):
    """GET /api/devices/:id/host-config — desired config + current state + drift."""
    require_auth()
    with _locked_update(DEVICES_FILE) as devices:
        if dev_id not in devices:
            respond(404, {'error': 'Device not found'})
        hc = devices[dev_id].get('host_config', {})
    # Current state lives in a separate per-device file — keeps devices.json small
    current_path = HOST_CONFIG_CURRENT_DIR / f'{dev_id}.json'
    current_data = {}
    collected_at = hc.get('current_collected_at')
    if current_path.exists():
        try:
            raw = load(current_path) or {}
            current_data = raw.get('current', {})
            collected_at = raw.get('collected_at', collected_at)
        except Exception:
            pass
    respond(200, {
        'desired':              hc.get('desired', {}),
        'current':              current_data,
        'current_collected_at': collected_at,
        'drift':                hc.get('drift', {}),
        'desired_at':           hc.get('desired_at'),
    })


def handle_device_host_config_put(dev_id):
    """PUT /api/devices/:id/host-config — save desired host configuration."""
    actor = require_admin_auth()
    body = get_json_body()
    if not isinstance(body, dict):
        respond(400, {'error': 'Expected JSON object'})

    desired = {}
    for section in HOST_CONFIG_ALL_SECTIONS:
        if section in body:
            desired[section] = _validate_host_config_section(section, body[section])

    with _locked_update(DEVICES_FILE) as devices:
        if dev_id not in devices:
            respond(404, {'error': 'Device not found'})
        hc = devices[dev_id].setdefault('host_config', {})
        hc['desired']    = desired
        hc['desired_at'] = int(time.time())
        # Clear drift so it re-evaluates on next agent report
        hc.pop('drift', None)

    audit_log(actor, 'host_config_update',
              f'dev_id={dev_id} sections={list(desired.keys())}')
    respond(200, {'ok': True})


def handle_device_host_config_current(dev_id):
    """GET /api/devices/:id/host-config/current — current state only (for fetch button)."""
    require_auth()
    with _locked_update(DEVICES_FILE) as devices:
        if dev_id not in devices:
            respond(404, {'error': 'Device not found'})
        hc = devices[dev_id].get('host_config', {})
    current_path = HOST_CONFIG_CURRENT_DIR / f'{dev_id}.json'
    current_data = {}
    collected_at = hc.get('current_collected_at')
    if current_path.exists():
        try:
            raw = load(current_path) or {}
            current_data = raw.get('current', {})
            collected_at = raw.get('collected_at', collected_at)
        except Exception:
            pass
    respond(200, {
        'current':              current_data,
        'current_collected_at': collected_at,
    })

if __name__ == '__main__':
    try:
        main()
    except HTTPError as e:
        # Normal short-circuit from a handler — render the planned response.
        _render_response(e.status, e.body)
    except SystemExit:
        # Some legacy code paths still use sys.exit() during initialisation.
        # Honour them rather than swallowing.
        raise
    except Exception:
        # Anything else is unexpected. Render a generic 500 — never leak
        # exception details to the client. Stack traces, if needed, are
        # available via fcgiwrap's stderr capture.
        _render_response(500, {'error': 'Internal server error'})




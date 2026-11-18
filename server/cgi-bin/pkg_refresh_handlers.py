"""RemotePower — Package list refresh: "Check for updates now", and the setting that refreshes before each scheduled scan

`Scan packages` re-reads what a host's package manager already knows. A refresh asks the repositories: the Linux agent runs the
distribution's own fixed command (apt-get update, dnf makecache, zypper refresh, apk update, or checkupdates on Arch) and keeps
how it went as {at, status, source, error_class}, which rides the system information (api.py takes it in through
pkg_refresh.clean) and which the host's Packages section shows.

A bound-module carve-out following the tls_ct_handlers / dmarc_handlers /
rack_ipam_handlers pattern:

  - api.py execs a PRIVATE instance and binds its own ``globals()`` here, so
    every api service is reached as ``A.<name>`` — a DYNAMIC attribute lookup,
    which keeps the test suite's monkeypatching of api.respond / api.save / …
    working, and resolves identically under the CGI (__main__) and
    imported-module (wsgi.py/scheduler.py) models.
  - api.py then from-imports every public + private name back into its own
    globals, so the route tables, main()'s _safe() cadence and scheduler.py's
    CADENCE tuple keep resolving the names unchanged.
  - Calls BETWEEN these functions ALSO go through ``A.`` so a test that patches
    one of them is seen by its caller.

Constants stay in api.py and are read here through A. Pure logic goes in a
sibling module (imported directly, like dmarc_monitor / tls_monitor).
"""

import time

import pkg_refresh


class _ApiNamespace:
    __slots__ = ('_g',)

    def __init__(self, g):
        self._g = g

    def __getattr__(self, name):
        try:
            return self._g[name]
        except KeyError:
            raise AttributeError(f'api namespace has no {name!r}') from None


A = None


def bind(api_globals):
    """Called once by api.py right after importing this module, with
    api's ``globals()``."""
    global A
    A = _ApiNamespace(api_globals)


# ── handlers ─────────────────────────────────────────────────────────────────
def handle_device_pkg_refresh(dev_id):
    """POST /api/devices/<id>/refresh-package-lists — ask a Linux host to refresh its package lists now.

    The request becomes the command `pkg_refresh` on the host's queue, so it passes what every queued command passes: the server
    in maintenance mode, a quarantined host, an agent in audit mode, the per-host queue limit, a maintenance window that holds
    commands, and four-eyes approval when the operator has put the `scan` kind behind it (the reply is then 202 with
    `approval_required`). Anyone who may patch the host may ask (the `patch` permission, scoped to the host).

    The route is under /api/devices/<id>/, so a host outside the caller's tenant or role scope is refused before this runs.
    A body is optional: `reason` and `ticket_ref` ride onto a parked change for the approver, as they do for an upgrade."""
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'Host not found'})
    actor = A.require_perm('patch', [dev_id])
    dev = A.device_get(dev_id)
    if not isinstance(dev, dict):
        A.respond(404, {'error': 'Host not found'})
    if dev.get('agentless'):
        A.respond(400, {'error': 'an agentless host has no agent to refresh package lists'})
    if A._device_os_family(dev) != 'linux':
        A.respond(409, {'error': 'the package list refresh is available for Linux hosts only'})
    reason, ticket_ref = A._approval_context(A.get_json_obj())
    A.audit_log(actor, 'pkg_refresh', f'host={dev_id}')
    A._queue_command(dev_id, pkg_refresh.VERB, actor, reason=reason, ticket_ref=ticket_ref)   # responds 200, 202 or a refusal


# The maintenance windows that hold commands, as read from the store, kept for a short while by this process. refresh_before_scan_for runs on
# the heartbeat of every Linux host while the setting is on, and reading the store (parse and shape repair of every window, gate or not)
# cost about 0.1 ms at 20 windows and 6 ms at 1,000 on every beat. All the hosts one process serves share one read. The answer for a host is
# still worked out from the windows and the clock on every beat, so a window that opens or closes is seen at once; a window that is saved
# is seen by this process after at most GATE_CACHE_S seconds, which is soon enough for a refresh that only reads from the repositories and
# runs once in three hours.
GATE_CACHE_S = 20
_gate = (None, 0.0, ())            # (the store's path, when it was read, the windows in it that hold commands)


def forget_the_gate():
    """Read the windows again on the next question (for a caller that has just saved a window, and for tests)."""
    global _gate
    _gate = (None, 0.0, ())


def _windows_that_hold_commands():
    global _gate
    key, at, windows = _gate
    now = time.monotonic()
    if key != str(A.MAINT_FILE) or now - at >= GATE_CACHE_S:
        stored = (A._load_ro(A.MAINT_FILE) or {}).get('windows') or []     # read only: nothing below writes to a window
        windows = tuple(w for w in stored if isinstance(w, dict) and w.get('gate_exec'))
        _gate = (str(A.MAINT_FILE), now, windows)
    return windows


def refresh_before_scan_for(dev_id, dev):
    """Whether this host is told, in its heartbeat answer, to refresh its package lists before each scheduled scan.

    True only when the setting `pkg_refresh_before_scan` is on (off by default, which keeps what a scan has always done), the host is a
    Linux one, and it may take an action right now: the server is not in maintenance mode, the host is not quarantined and its agent is
    not in audit mode (the same predicate every queued command passes), and no maintenance window that holds commands is closed for it.
    A host that is held simply scans without the refresh; it is told again on a later heartbeat when the hold is over."""
    if A._config_ro().get('pkg_refresh_before_scan') is not True:
        return False
    if not isinstance(dev, dict) or A._device_os_family(dev) != 'linux':
        return False
    if A._command_block_reason(dev, pkg_refresh.VERB):
        return False
    return not A._exec_gated(dev_id, dev, windows=_windows_that_hold_commands())

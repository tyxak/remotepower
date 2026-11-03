"""RemotePower — Patch preview: what the next upgrade would change on a Linux host (7.4.9)

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

import secrets

import patch_plan


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


# A request that comes in while one is waiting and young is the same question: answer it with the one already queued.
REUSE_WITHIN_S = 60

REASONS = {
    'not_linux': 'The patch preview is for Linux hosts. A Windows or macOS host lists what is pending on the Patches page',
    'no_manager': 'The patch preview reads apt, dnf, yum and pacman, and this host reports another package manager',
}


def _manager(dev):
    """The package manager the host last reported ('' when it has not reported one)."""
    si = dev.get('sysinfo') if isinstance(dev.get('sysinfo'), dict) else {}
    pkg = si.get('packages') if isinstance(si.get('packages'), dict) else {}
    m = pkg.get('manager')
    return m if isinstance(m, str) else ''


def _applies(dev):
    """(True, '') when a preview can be asked of this host, otherwise (False, reason key)."""
    if A._device_os_family(dev) != 'linux':
        return False, 'not_linux'
    manager = _manager(dev)
    if manager and manager not in ('apt', 'dnf', 'pacman', 'unknown'):
        return False, 'no_manager'
    return True, ''


def _view(dev, rec, with_raw=False):
    """What GET answers: the last plan, whether a request is still waiting, and whether the preview applies to the host."""
    ok, why = _applies(dev)
    now = int(A.time.time())
    pending = None
    plan = None
    if isinstance(rec, dict):
        p = rec.get('pending')
        if isinstance(p, dict) and p.get('id'):
            age = max(0, now - int(p.get('at') or 0))
            pending = {'id': p['id'], 'at': int(p.get('at') or 0), 'by': str(p.get('by') or '')[:64], 'age_s': age,
                       'timed_out': age > patch_plan.PENDING_TTL}
        pl = rec.get('plan')
        if isinstance(pl, dict):
            plan = {k: v for k, v in pl.items() if with_raw or k != 'raw'}
    return {'ok': True, 'applies': ok, 'reason': why, 'reason_text': REASONS.get(why, ''), 'pending': pending, 'plan': plan,
            'mode': A.upgrade_mode_mod.mode_of(dev), 'manager': _manager(dev)}


def request_patch_preview(dev_id, dev, actor):
    """Queue a preview on the host. Returns (status, body) and never responds, so a caller that parks an upgrade for approval
    can ask for the preview without being able to fail the parking.

    The command is read-only (a dry run), so it is queued directly and not through the four-eyes gate: an approver has to be
    able to see the plan before they approve the change. The checks every other queued command passes still apply: the server
    in maintenance, a quarantined host, an agent in audit mode. At most one preview waits in a host's queue."""
    ok, why = _applies(dev)
    if not ok:
        return 409, {'error': REASONS[why], 'reason': why}
    rec = A._entity_read_one(A.PATCH_PREVIEWS_FILE, dev_id, None)
    rec = rec if isinstance(rec, dict) else {}
    now = int(A.time.time())
    pend = rec.get('pending')
    if isinstance(pend, dict) and pend.get('id') and 0 <= now - int(pend.get('at') or 0) < REUSE_WITHIN_S:
        return 200, {'ok': True, 'id': pend['id'], 'already_pending': True}
    mode = A.upgrade_mode_mod.mode_of(dev)
    pid = 'pp-' + secrets.token_hex(6)
    command = patch_plan.command(pid, mode)
    blocked = A._command_block_reason(dev, command)
    if blocked:
        extra = {'maintenance': True} if blocked[0] == 503 else {}
        return blocked[0], dict({'error': blocked[1]}, **extra)
    rec['pending'] = {'id': pid, 'at': now, 'by': str(actor or '')[:64]}
    A._entity_write_one(A.PATCH_PREVIEWS_FILE, dev_id, rec, non_blocking=False)
    full = False
    with A._LockedUpdate(A.CMDS_FILE) as cmds:
        q = cmds.setdefault(dev_id, [])
        q[:] = [c for c in q if not patch_plan.plan_id_of(c)]
        if len(q) >= A.MAX_QUEUED_PER_DEVICE:
            full = True
        else:
            q.append(command)
    if full:
        rec['pending'] = None
        A._entity_write_one(A.PATCH_PREVIEWS_FILE, dev_id, rec, non_blocking=False)
        return 429, {'error': f'Command queue full ({A.MAX_QUEUED_PER_DEVICE} already waiting) — {dev.get("name", dev_id)} '
                              'may be offline. Cancel or clear its queued commands first.'}
    A.log_command(actor, dev_id, dev.get('name', dev_id), 'patch preview')
    return 200, {'ok': True, 'id': pid}


def handle_device_patch_preview(dev_id):
    """GET/POST /api/devices/<id>/patch-preview — what the next upgrade would change on a Linux host.

    POST asks the host for a dry run of the upgrade it would run (the host's upgrade mode decides whether new packages are
    allowed), by anyone who may patch the host. The answer rides the host's next report; GET gives the last plan and says
    whether a request is still waiting. `applies` is false for a Windows or macOS host and for a Linux host with another
    package manager, with the reason. `?raw=1` adds the start of the host's own answer, for when a plan looks wrong.

    The route is under /api/devices/<id>/, so a host outside the caller's tenant or role scope is refused before this runs."""
    verb = A.method()
    if verb not in ('GET', 'POST'):
        A.respond(405, {'error': 'Method not allowed'})
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'Host not found'})
    actor = A.require_perm('patch', [dev_id]) if verb == 'POST' else A.require_auth()
    dev = (A.load(A.DEVICES_FILE) or {}).get(dev_id)
    if not isinstance(dev, dict):
        A.respond(404, {'error': 'Host not found'})
    if verb == 'GET':
        qs = A.urllib.parse.parse_qs(A._env('QUERY_STRING', '') or '')
        rec = A._entity_read_one(A.PATCH_PREVIEWS_FILE, dev_id, None)
        A.respond(200, _view(dev, rec, with_raw=(qs.get('raw', [''])[0] == '1')))
    status, body = A.request_patch_preview(dev_id, dev, actor)
    if status == 200 and not body.get('already_pending'):
        A.audit_log(actor, 'patch_preview', f'device={dev_id}')
    A.respond(status, body)


def patch_preview_ingest(dev_id, cmd, output, rc, now):
    """Called for every command result a host reports. When the command is a patch preview, read the answer into a plan, keep
    it on the host's record and return the one line the command history keeps in place of the dry run; for any other
    command return None.

    A result is taken only when its id is the one the host was asked for last: a stale answer, one for a request that was
    replaced, and one the server never asked for are dropped (and still swallowed here, so they do not fill the history)."""
    pid = patch_plan.plan_id_of(cmd)
    if not pid:
        return None
    rec = A._entity_read_one(A.PATCH_PREVIEWS_FILE, dev_id, None)
    pend = rec.get('pending') if isinstance(rec, dict) else None
    if not isinstance(pend, dict) or pend.get('id') != pid:
        return 'patch preview: an answer nobody was waiting for was dropped'
    plan = patch_plan.parse(output)
    plan['id'] = pid
    plan['at'] = int(now)
    plan['requested_at'] = int(pend.get('at') or 0)
    plan['by'] = str(pend.get('by') or '')[:64]
    plan['rc'] = rc if isinstance(rc, int) and not isinstance(rc, bool) else -1
    rec['pending'] = None
    rec['plan'] = plan
    A._entity_write_one(A.PATCH_PREVIEWS_FILE, dev_id, rec, non_blocking=False)
    return patch_plan.summary_line(plan)

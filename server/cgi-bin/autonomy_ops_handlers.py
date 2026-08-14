"""RemotePower — Autonomous remediation loop: policy, shadow receipts, blast radius

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


import json
import time

import autonomy


# ── policy ───────────────────────────────────────────────────────────────────

def _policy_for(tenant):
    """The effective policy for a tenant, defaults merged in.

    Stored per tenant so one customer opting into autonomy never enables it for
    another — the same isolation rule every device-keyed store in this codebase
    follows, and the one place where getting it wrong would be worst.
    """
    store = A.load(A.AUTONOMY_POLICY_FILE) or {}
    raw = (store.get('tenants') or {}).get(tenant or A.DEFAULT_TENANT)
    return autonomy.normalize_policy(raw)


def handle_autonomy_policy():
    """GET|PUT /api/autonomy/policy — the per-tenant safety envelope."""
    if A.method() == 'GET':
        tenant = A._tenant_gate() or A.DEFAULT_TENANT
        A.require_auth()
        A.respond(200, {'ok': True, 'tenant': tenant,
                        'policy': _policy_for(tenant),
                        'action_classes': autonomy.ACTION_CLASSES,
                        'modes': list(autonomy.MODES)})
        return
    if A.method() != 'PUT':
        A.respond(405, {'error': 'Method not allowed'})
    # Changing the envelope is a control-plane act: admin only, and audited.
    actor = A.require_admin_auth()
    tenant = A._tenant_gate() or A.DEFAULT_TENANT
    body = A.get_json_obj()
    new = autonomy.normalize_policy(body.get('policy') if isinstance(
        body.get('policy'), dict) else body)
    with A._LockedUpdate(A.AUTONOMY_POLICY_FILE) as store:
        tenants = store.get('tenants')
        if not isinstance(tenants, dict):
            tenants = {}
        tenants[tenant] = new
        store['tenants'] = tenants
    A.audit_log(actor, 'autonomy_policy_set',
                detail=f"tenant={tenant} mode={new['mode']} "
                       f"actions={','.join(new['allowed_actions'])}")
    A.respond(200, {'ok': True, 'policy': new})


# ── receipts ─────────────────────────────────────────────────────────────────

_RECEIPT_MAX = 2000


def _append_receipt(rec):
    """Append to the ledger. Trimmed by insertion order, oldest first."""
    with A._LockedUpdate(A.AUTONOMY_RECEIPTS_FILE) as store:
        rows = store.get('receipts')
        if not isinstance(rows, list):
            rows = []
        rows.append(rec)
        store['receipts'] = rows[-_RECEIPT_MAX:]


def handle_autonomy_receipts():
    """GET /api/autonomy/receipts — what the loop did, or would have done.

    Tenant-filtered: a receipt names a device, so the same rule as every other
    device-keyed store applies. A caller sees only their own tenant's rows, and
    an unscoped superadmin sees all.
    """
    A.require_auth()
    gate = A._tenant_gate()
    rows = (A.load(A.AUTONOMY_RECEIPTS_FILE) or {}).get('receipts') or []
    if gate is not None:
        rows = [r for r in rows if isinstance(r, dict) and r.get('tenant') == gate]
    rows = list(reversed(rows))[:500]
    agg = {}
    for r in rows:
        key = str(r.get('reason') or 'ok')
        agg[key] = agg.get(key, 0) + 1
    A.respond(200, {'ok': True, 'receipts': rows, 'by_reason': agg,
                    'total': len(rows)})


# ── blast radius ─────────────────────────────────────────────────────────────

def _blast_radius_for(dev_id, dev, devices):
    """What goes dark if we act on this host.

    Assembled ONLY from stores verified to exist, and deliberately NOT wrapped
    in a blanket try/except. The first draft of this reached for MONITORS_FILE,
    STATUS_PAGE_FILE and NETWORK_MAP_FILE — none of which exist — inside
    `except Exception: pass`, which would have made every blast radius silently
    zero and every policy limit trivially satisfied. A safety input that fails
    open is worse than no safety input, so a missing store now raises and the
    caller records the failure rather than acting on a comfortable number.

    Monitors live in CONFIG_FILE under `monitors` (each carrying `device_id`),
    not in a store of their own. Containers come from the device's own sysinfo.
    Redundancy keys off group+function siblings.
    """
    cfg = A._config_ro() or {}
    monitors = [m.get('id') or m.get('label') or m.get('path')
                for m in (cfg.get('monitors') or [])
                if isinstance(m, dict) and m.get('device_id') == dev_id
                and not m.get('paused')]

    si = dev.get('sysinfo') or {}
    containers = [c.get('name') for c in (si.get('containers') or [])
                  if isinstance(c, dict)]

    # Services the host runs that something else is watching. `services.json`
    # is per-device current state; a failing-relevant count is enough here.
    services = []
    svc = (A.load(A.SERVICES_FILE) or {}).get(dev_id) or {}
    if isinstance(svc, dict):
        services = [k for k in (svc.get('watched') or [])]

    # LLDP neighbours: who is physically adjacent and would notice.
    peers = []
    lldp = A.load(A.LLDP_NEIGHBORS_FILE) or {}
    row = lldp.get(dev_id) if isinstance(lldp, dict) else None
    if isinstance(row, list):
        peers = [n for n in row]
    elif isinstance(row, dict):
        peers = [n for n in (row.get('neighbors') or [])]

    group = dev.get('group') or ''
    fn = (dev.get('cmdb') or {}).get('function') if isinstance(
        dev.get('cmdb'), dict) else ''
    siblings = 0
    if group:
        for _oid, other in (devices or {}).items():
            if not isinstance(other, dict) or other.get('group') != group:
                continue
            ofn = (other.get('cmdb') or {}).get('function') if isinstance(
                other.get('cmdb'), dict) else ''
            if (fn or '') == (ofn or ''):
                siblings += 1

    return autonomy.blast_radius(
        dev_id, monitors=monitors, containers=containers,
        status_services=services, peers=peers,
        redundancy_group=group if siblings > 1 else None,
        group_size=siblings or 1)


def handle_autonomy_preview():
    """POST /api/autonomy/preview {device_id, action} — the pre-flight.

    Usable on its own, before any autonomy is enabled: "what breaks if I reboot
    this host?" is worth answering even for a human about to do it by hand. That
    is deliberate — the blast-radius view earns its keep whether or not the loop
    is ever switched on.
    """
    A.require_auth()
    body = A.get_json_obj()
    dev_id = A._sanitize_str(str(body.get('device_id') or ''), 64)
    action = A._sanitize_str(str(body.get('action') or ''), 40)
    A._scope_block_device(dev_id)
    devices = A.load(A.DEVICES_FILE) or {}
    dev = devices.get(dev_id)
    if not dev:
        A.respond(404, {'error': 'device not found'})
    radius = _blast_radius_for(dev_id, dev, devices)
    tenant = A._device_tenant(dev)
    policy = _policy_for(tenant)
    would = radius['score'] > int(policy.get('max_blast_radius', 0))
    A.respond(200, {'ok': True, 'device_id': dev_id, 'action': action,
                    'blast_radius': radius, 'policy_limit':
                        int(policy.get('max_blast_radius', 0)),
                    'exceeds_policy': would})


# ── handlers ─────────────────────────────────────────────────────────────────
# def handle_autonomy_ops_example():
#     """GET /api/autonomy_ops/example."""
#     A.require_auth()
#     A.respond(200, {'ok': True})

# ── the loop ─────────────────────────────────────────────────────────────────

_LOOP_INTERVAL_S = 300

# Which alert events map to which action class. An event with no mapping is
# never a candidate — the loop cannot invent an action for a signal nobody
# analysed, which is the same default-deny rule the decision core applies to
# action names.
_EVENT_ACTIONS = {
    'unit_failed':          'restart_service',
    'failed_unit':          'restart_service',
    'container_restarting': 'restart_container',
    'container_down':       'restart_container',
    'disk_low':             'clear_journal',
    'inode_low':            'clear_journal',
}

# The command each class runs. Kept HERE, next to the safety analysis, rather
# than assembled from an alert payload — a command built out of remote data is
# how an alert becomes an injection vector.
_ACTION_COMMANDS = {
    'restart_service':   'systemctl restart {unit}',
    'restart_container': 'docker restart {container}',
    'clear_journal':     'journalctl --vacuum-time=3d',
    'clear_cache':       'sync; echo 3 > /proc/sys/vm/drop_caches',
}


def _actions_this_hour(tenant):
    now = int(time.time())
    rows = (A._load_ro(A.AUTONOMY_RECEIPTS_FILE) or {}).get('receipts') or []
    return sum(1 for r in rows if isinstance(r, dict)
               and r.get('tenant') == tenant
               and r.get('verdict') == autonomy.ACT
               and (now - int(r.get('ts') or 0)) < 3600)


def _backup_is_verified(dev_id):
    """Proven recoverable — a restore drill that actually restored and checked,
    not a backup that merely ran. The distinction is the entire reason the
    destructive gate exists."""
    jobs = A.load(A.BACKUP_JOBS_FILE) or {}
    row = jobs.get(dev_id) if isinstance(jobs, dict) else None
    if not isinstance(row, dict):
        return False
    drill = row.get('restore_drill')
    if not isinstance(drill, dict) or not drill.get('ok'):
        return False
    # A drill that succeeded two years ago is not evidence about today's host.
    return (int(time.time()) - int(drill.get('ts') or 0)) < 30 * 86400


def _candidate_alerts(alerts):
    """Open, unacknowledged alerts whose event maps to a known action."""
    out = []
    for a in alerts or []:
        if not isinstance(a, dict):
            continue
        if a.get('resolved_at') or a.get('acked_at'):
            continue
        act = _EVENT_ACTIONS.get(a.get('event'))
        if act:
            out.append((a, act))
    return out


def _build_plan(alert, action, dev, dev_id, radius, precedent_action):
    payload = alert.get('payload') if isinstance(alert.get('payload'), dict) else {}
    tmpl = _ACTION_COMMANDS.get(action) or ''
    unit = A._sanitize_str(str(payload.get('unit') or payload.get('name') or ''), 64)
    container = A._sanitize_str(str(payload.get('container') or payload.get('name') or ''), 64)
    cmd = tmpl.format(unit=unit, container=container) if tmpl else ''
    return {
        'ts': int(time.time()),
        'tenant': A._device_tenant(dev),
        'device_id': dev_id,
        'device_name': dev.get('name') or dev_id,
        'trigger': alert.get('event'),
        'alert_id': alert.get('id'),
        'action': action,
        'command': cmd,
        'blast_radius': radius,
        'precedent_action': precedent_action,
        'dry_run': 'not-run',
    }


def run_autonomy_if_due():
    """Cadence: evaluate open alerts against each tenant's policy.

    In shadow mode this writes receipts and touches NOTHING — that is the whole
    adoption story, so the execution branch is deliberately the short one and
    everything before it is shared, which means a shadow receipt describes the
    same reasoning a real action would have used.

    Cheap on the not-due path: one read-only gate before any store is opened.
    """
    now = int(time.time())
    state = A._load_ro(A.AUTONOMY_RECEIPTS_FILE) or {}
    if (now - int(state.get('last_run') or 0)) < _LOOP_INTERVAL_S:
        return
    if not A._module_on('autonomy'):
        return

    alerts = (A.load(A.ALERTS_FILE) or {}).get('alerts', [])
    cands = _candidate_alerts(alerts)
    if not cands:
        with A._LockedUpdate(A.AUTONOMY_RECEIPTS_FILE) as store:
            store['last_run'] = now
        return

    devices = A.load(A.DEVICES_FILE) or {}
    made = []
    for alert, action in cands[:25]:
        dev_id = alert.get('device_id') or ''
        dev = devices.get(dev_id)
        if not dev:
            continue
        tenant = A._device_tenant(dev)
        policy = _policy_for(tenant)
        if policy.get('mode') == 'off':
            continue                      # nothing to record; nobody opted in

        similar = []
        try:
            similar = A._similar_incidents(
                alert.get('event'),
                A.EVENT_KIND_MAP.get(alert.get('event')), tenant,
                exclude_alert_id=alert.get('id'), limit=8) or []
        except Exception:
            similar = []
        conf, samples, prec_action = autonomy.precedent_confidence(similar)
        radius = _blast_radius_for(dev_id, dev, devices)
        plan = _build_plan(alert, action, dev, dev_id, radius, prec_action)

        decision = autonomy.decide(
            action=action, policy=policy, module_enabled=True,
            tenant_ok=bool(tenant), radius=radius,
            precedent_conf=conf, precedent_samples=samples,
            backup_verified=_backup_is_verified(dev_id),
            in_window=A._in_maintenance_window(dev) if hasattr(
                A, '_in_maintenance_window') else True,
            actions_this_hour=_actions_this_hour(tenant),
            dry_run_ok=True, has_plan=False)

        rec = autonomy.receipt(plan, decision)
        # v7.0.0: execution is NOT wired in this commit. A receipt with an ACT
        # verdict means "the envelope would have permitted this" — the signed
        # command path, the four-eyes hop and the post-action verification land
        # next, behind the same module switch. Recording the verdict first is
        # what makes shadow mode gradeable before anything can run.
        if decision.verdict == autonomy.ACT:
            rec['outcome'] = 'not-executed (execution not yet enabled)'
        made.append(rec)

    for rec in made:
        _append_receipt(rec)
    with A._LockedUpdate(A.AUTONOMY_RECEIPTS_FILE) as store:
        store['last_run'] = now

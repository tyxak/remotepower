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
import re
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

# Which alert events map to which action classes. An event with no mapping is
# never a candidate — the loop cannot invent an action for a signal nobody
# analysed, which is the same default-deny rule the decision core applies to
# action names.
#
# The value is an ORDERED LADDER, not a single action, and that is what makes
# the allow-list mean something. A host low on disk has half a dozen plausible
# remedies of escalating nerve; the operator ticks the ones they are willing to
# have happen unattended and the loop takes the first of those. A single-action
# map would have forced that judgement into the source, where the operator
# cannot see or change it.
#
# EVERY KEY IS AN EVENT_REGISTRY NAME. The first version of this table invented
# four of its six — `unit_failed`, `container_down`, `disk_low`, `inode_low` do
# not exist, so the loop could only ever have fired on the two real ones and
# would have looked, from a green test suite, as though it covered six.
# `tests/test_v700_action_catalog.py` checks each key against the registry now.
_EVENT_ACTIONS = {
    # services and timers
    'failed_unit':          ('restart_service',),
    'unit_flapping':        ('restart_service',),
    'service_down':         ('restart_service', 'start_service'),
    'vpn_handshake_stale':  ('restart_service',),
    'win_update_stopped':   ('start_service',),
    'timer_failed':         ('restart_timer',),
    # containers
    'container_restarting': ('restart_container',),
    'container_stopped':    ('start_container',),
    # disk pressure — the ladder, gentlest first
    'server_disk_low':      ('clear_journal', 'rotate_logs', 'clear_package_cache',
                             'clear_tmp', 'prune_container_images',
                             'trim_filesystem'),
    'disk_predict_fail':    ('clear_journal', 'rotate_logs', 'clear_package_cache',
                             'trim_filesystem'),
    'resource_saturation_predicted': ('clear_cache',),
    # host services that fix themselves with a nudge
    'clock_skew':           ('resync_clock',),
    'resolver_unhealthy':   ('restart_resolver',),
    'mailq_high':           ('flush_mail_queue',),
    'mailflow_delayed':     ('flush_mail_queue',),
    'av_warning':           ('update_av_definitions',),
    'win_defender_stale':   ('update_av_definitions',),
    'scrub_overdue':        ('start_scrub',),
    # destructive territory — reachable, but off in the default policy
    'process_alert':        ('kill_process',),
    'oom_detected':         ('kill_process',),
    'readonly_fs':          ('remount_rw',),
    'wan_down':             ('restart_networking',),
    'gateway_unreachable':  ('restart_networking',),
    'mac_firewall_off':     ('enable_firewall',),
    'win_firewall_off':     ('enable_firewall',),
    'reboot_required':      ('reboot',),
    'kernel_outdated':      ('reboot',),
    'patch_alert':          ('patch',),
    'cve_found':            ('patch',),
    'patch_sla_violation':  ('patch',),
    'password_stale':       ('rotate_credential',),
    'secret_exposed':       ('rotate_credential',),
}

# The command each class runs, in the SERVER'S COMMAND GRAMMAR — `svc:`,
# `container:`, `ps:`, `exec:` — not a raw shell line. Three reasons that
# matters and the first version (`systemctl restart {unit}`) got wrong:
#
#  * the typed verbs run through fixed argv on the agent, so a unit name can
#    never become shell;
#  * `_verb_unsupported_on()` already knows which verbs each platform's agent
#    implements, so routing through them is what makes the platform column in
#    ACTION_CLASSES enforceable rather than aspirational;
#  * `_command_block_reason()` — maintenance mode, quarantine, audit mode, the
#    approval gate — keys off the same grammar, so autonomy inherits every
#    guard an operator-issued command already passes.
#
# Kept HERE, next to the safety analysis, and never assembled from alert text: a
# command built out of remote data is how an alert becomes an injection vector.
# A value may be a single template or a per-OS-family dict.
_ACTION_COMMANDS = {
    'restart_service':     'svc:restart:{unit}',
    'start_service':       'svc:start:{unit}',
    'restart_timer':       'svc:restart:{unit}',
    'restart_container':   'container:{runtime}:restart:{container}',
    'start_container':     'container:{runtime}:start:{container}',

    'clear_journal':       'exec:journalctl --vacuum-time=3d',
    'rotate_logs':         'exec:logrotate -f /etc/logrotate.conf',
    'clear_tmp':           'exec:systemd-tmpfiles --clean',
    'clear_package_cache': ('exec:apt-get clean 2>/dev/null || dnf clean all '
                            '2>/dev/null || pacman -Sc --noconfirm 2>/dev/null '
                            '|| zypper clean 2>/dev/null'),
    'prune_container_images': ('exec:docker image prune -af 2>/dev/null '
                               '|| podman image prune -af'),
    'trim_filesystem':     'exec:fstrim -av',
    'clear_cache':         'exec:sync; echo 3 > /proc/sys/vm/drop_caches',

    'resync_clock':        ('exec:chronyc makestep 2>/dev/null '
                            '|| timedatectl set-ntp true'),
    'restart_resolver':    'svc:restart:systemd-resolved',
    'flush_mail_queue':    'exec:postqueue -f',
    'update_av_definitions': {'linux':   'exec:freshclam',
                              'windows': 'ps:Update-MpSignature'},
    'start_scrub':         'exec:zpool scrub -- {pool}',

    'kill_process':        'exec:pkill -TERM -x -- {process}',
    'remount_rw':          'exec:mount -o remount,rw -- {mount}',
    # Detached on purpose: restarting networking from a command the network
    # delivered kills the delivery. Same shape as the agent-restart rule.
    'restart_networking':  ('exec:systemd-run --on-active=5 systemctl restart '
                            'NetworkManager systemd-networkd'),
    'enable_firewall':     {
        'linux':   ('exec:ufw --force enable 2>/dev/null '
                    '|| systemctl start firewalld'),
        'windows': ('ps:Set-NetFirewallProfile -Profile Domain,Public,Private '
                    '-Enabled True'),
        'darwin':  ('exec:/usr/libexec/ApplicationFirewall/socketfilterfw '
                    '--setglobalstate on'),
    },
    'reboot':              'reboot',
    # Linux patches via the server's own vetted upgrade script (the one with
    # the initramfs safety analysis in it); Windows and macOS take the bare
    # `upgrade` verb. Resolved in _command_for so it tracks _UPGRADE_CMD.
    'patch':               {'linux': '@upgrade', 'windows': 'upgrade',
                            'darwin': 'upgrade'},
    # No entry for rotate_credential: rotation is a server-side operation on
    # the vault, not a command sent to a host, and this build does not wire it.
    # The absence is deliberate and refuses with `no_command_template` rather
    # than emitting an empty command that would read as "nothing to do".
}

# Where each template parameter comes from in the alert payload, in preference
# order. `_record_alert` stores only a whitelisted subset of a payload, so an
# alias that is not on that whitelist can never arrive — the catalog test pins
# that at least one alias per parameter is a key the alert can actually carry.
_ACTION_PARAMS = {
    'unit':      ('unit', 'name', 'label'),
    'container': ('container', 'name', 'label'),
    'process':   ('process', 'name'),
    'mount':     ('path', 'name'),
    'pool':      ('disk', 'name', 'label'),
}


# Every character a legitimate unit / container / process / mount / pool name
# can contain, and nothing that means anything to a shell or to the
# colon-delimited command wire format.
#
# The first character may not be `-`. Every template already writes `--` before
# its parameter, so `-rf` would be treated as an operand rather than an option —
# but that makes safety depend on each template remembering the separator, and a
# name beginning with a hyphen is not a real unit, container, process, mount or
# pool anyway. Refusing it here means a template that forgets `--` is still not
# an option-injection path. (test_v700_action_catalog also asserts the separator
# is present in every parameterised template, so both halves are held.)
_SAFE_PARAM = re.compile(r'[A-Za-z0-9._@/+][A-Za-z0-9._@/+-]{0,63}')


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
    """Open, unacknowledged alerts whose event maps to a ladder of actions."""
    out = []
    for a in alerts or []:
        if not isinstance(a, dict):
            continue
        if a.get('resolved_at') or a.get('acked_at'):
            continue
        ladder = _EVENT_ACTIONS.get(a.get('event'))
        if ladder:
            out.append((a, tuple(ladder)))
    return out


def _pick_action(ladder, policy):
    """The first rung of the ladder this tenant has actually permitted.

    When none are permitted we still return the FIRST rung rather than nothing,
    so the receipt names a concrete action and refuses with `action_not_allowed`
    against it. Dropping the candidate silently would leave the operator with a
    fleet full of alerts and an empty receipts page, which reads as "autonomy
    found nothing to do" when the truth is "you have not allowed anything".
    """
    allowed = policy.get('allowed_actions') or []
    return next((a for a in ladder if a in allowed), ladder[0])


def _command_for(action, family):
    """The command template for this action on this OS family, or ''."""
    tmpl = _ACTION_COMMANDS.get(action)
    if isinstance(tmpl, dict):
        tmpl = tmpl.get(family) or ''
    tmpl = tmpl or ''
    if tmpl == '@upgrade':
        # The vetted upgrade script — the same one auto-patch runs, carrying the
        # initramfs safety analysis. Resolved here rather than copied so a fix
        # to that script reaches autonomy too.
        return 'exec:' + A._UPGRADE_CMD
    return tmpl


def _container_runtime(dev_id, name):
    """docker | podman for this container, from what the agent REPORTED.

    Never a guess: a host may run either, and `container:docker:…` sent to a
    podman host is a verb the agent recognises and an action that does nothing.
    """
    items = ((A.load(A.CONTAINERS_FILE) or {}).get(dev_id) or {}).get('items') or []
    for c in items:
        if isinstance(c, dict) and c.get('name') == name \
                and c.get('runtime') in ('docker', 'podman'):
            return c['runtime']
    return ''


def _resolve_params(tmpl, payload, dev_id):
    """Fill a template's parameters from the alert payload.

    Returns (command, problem). `problem` is a REASONS code, so the caller hands
    it straight to decide() and the refusal is machine-readable like every
    other one. Every value is passed through `_sanitize_str` before it reaches
    a template — the typed verbs run fixed argv on the agent, but a unit name
    with a colon in it would still split the wire format.
    """
    if not tmpl:
        return '', 'no_command_template'
    fields = set(re.findall(r'\{(\w+)\}', tmpl))
    vals = {}
    for f in sorted(fields):
        if f == 'runtime':
            continue                     # resolved below, once we know the name
        raw = ''
        for alias in _ACTION_PARAMS.get(f, (f,)):
            v = payload.get(alias)
            if v:
                raw = str(v)
                break
        clean = A._sanitize_str(raw, 64).strip()
        # STRICT ALLOWLIST, not a denylist, and not `_sanitize_str` alone —
        # that helper only trims and truncates, it removes no shell
        # metacharacter. Several templates are `exec:` verbs, which the agent
        # runs through a SHELL, so a parameter is the one place remote data
        # reaches a command line. A `;` in an alert's process name would be a
        # second command. `:` is excluded separately because the typed verbs
        # (`svc:`, `container:`) are colon-delimited and the agent re-splits
        # them, so a name containing one arrives as a DIFFERENT action.
        #
        # The set is what real values need and nothing more: unit names
        # (`wg-quick@wg0.service`), container names, process names, mount paths
        # and pool names. Anything else refuses rather than being cleaned up —
        # a silently rewritten target is worse than no action.
        if not clean or not _SAFE_PARAM.fullmatch(clean):
            return '', 'missing_parameter'
        vals[f] = clean
    if 'runtime' in fields:
        rt = _container_runtime(dev_id, vals.get('container', ''))
        if not rt:
            return '', 'missing_parameter'
        vals['runtime'] = rt
    return tmpl.format(**vals), None


def _build_plan(alert, action, dev, dev_id, radius, precedent_action):
    payload = alert.get('payload') if isinstance(alert.get('payload'), dict) else {}
    family = A._device_os_family(dev)
    cmd, problem = _resolve_params(_command_for(action, family), payload, dev_id)
    return {
        'ts': int(time.time()),
        'tenant': A._device_tenant(dev),
        'device_id': dev_id,
        'device_name': dev.get('name') or dev_id,
        'os_family': family,
        'trigger': alert.get('event'),
        'alert_id': alert.get('id'),
        'action': action,
        'command': cmd,
        'problem': problem,
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
    for alert, ladder in cands[:25]:
        dev_id = alert.get('device_id') or ''
        dev = devices.get(dev_id)
        if not dev:
            continue
        tenant = A._device_tenant(dev)
        policy = _policy_for(tenant)
        if policy.get('mode') == 'off':
            continue                      # nothing to record; nobody opted in
        action = _pick_action(ladder, policy)

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
            dry_run_ok=True, has_plan=False,
            os_family=plan.get('os_family'), plan_problem=plan.get('problem'))

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

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
import secrets
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


def handle_autonomy_receipts_clear():
    """DELETE /api/autonomy/receipts[?id=<receipt id>] — drop receipts.

    Without `id`, every receipt the caller may SEE goes; with one, just that row.

    Tenant-scoped the same way the GET is: a tenant admin resolves to a
    `_tenant_gate()` of their own tenant and can only remove their own rows,
    while an unscoped superadmin (or a single-tenant install) removes all. That
    is not decoration — a bulk clear was the one alert mutation that shipped
    WITHOUT its siblings' tenant filter, so this one gets it at birth.

    Admin-only and audited. The receipts page is the evidence an operator grades
    the loop on, so who emptied it and how much they emptied is worth keeping;
    the audit entry carries both, plus how many rows still owed a verification
    sample, since deleting those drops the second half of their measurement.

    `last_run` is preserved. It is the sweep's cadence marker, not a receipt, and
    resetting it would make the next request re-evaluate every open alert.
    """
    actor = A.require_admin_auth()
    if A.method() != 'DELETE':
        A.respond(405, {'error': 'Method not allowed'})
    qs = A.urllib.parse.parse_qs(A._env('QUERY_STRING', '') or '')
    want_id = A._sanitize_str((qs.get('id', [''])[0] or ''), 64)
    gate = A._tenant_gate()
    removed = 0
    pending = 0
    with A._LockedUpdate(A.AUTONOMY_RECEIPTS_FILE) as store:
        rows = store.get('receipts')
        if not isinstance(rows, list):
            rows = []
        kept = []
        for r in rows:
            mine = isinstance(r, dict) and (gate is None or r.get('tenant') == gate)
            hit = mine and (not want_id or r.get('id') == want_id)
            if not hit:
                kept.append(r)
                continue
            removed += 1
            if r.get('verified') is None and r.get('verify_due'):
                pending += 1
        store['receipts'] = kept
    if want_id and not removed:
        # 404 rather than a cheerful 200: an id that matched nothing is either
        # gone or another tenant's, and both answers are "not yours to delete".
        A.respond(404, {'error': 'receipt not found'})
    A.audit_log(actor, 'autonomy_receipts_clear',
                detail=f"tenant={gate or 'all'} "
                       f"id={want_id or '*'} removed={removed} "
                       f"awaiting_verification={pending}")
    A.respond(200, {'ok': True, 'removed': removed,
                    'awaiting_verification': pending})


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
    # NOT vpn_handshake_stale: `_vpn_evt_payload` carries client_id / tunnel_id
    # and no device_id at all, so the sweep — which resolves a device before it
    # does anything else — could never see it. The tunnel is server-side; there
    # is no host command to send.
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
    # Gentlest rung first: a stale cache is the common cause and flushing it
    # costs nothing, where restarting the resolver drops every in-flight lookup.
    'resolver_unhealthy':   ('flush_dns_cache', 'restart_resolver'),
    'mount_issue':          ('remount_all',),
    'mailq_high':           ('flush_mail_queue',),
    'mailflow_delayed':     ('flush_mail_queue',),
    'av_warning':           ('update_av_definitions',),
    'win_defender_stale':   ('update_av_definitions',),
    # Posture that drifted off. Each is a single, reversible switch.
    'autoupdate_disabled':  ('enable_autoupdates',),
    'av_realtime_off':      ('enable_av_realtime',),
    'mac_gatekeeper_off':   ('enable_gatekeeper',),
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
    # The UPS says minutes of battery are left. A clean shutdown is the only
    # thing that helps, and it is the one action here that gets LESS useful the
    # longer a human takes to approve it — which is the argument for having the
    # loop able to do it at all.
    'ups_critical':         ('shutdown_host',),
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
    'flush_dns_cache':     {'linux':   'exec:resolvectl flush-caches',
                            'windows': 'ps:Clear-DnsClientCache'},
    'restart_resolver':    'svc:restart:systemd-resolved',
    # What fstab already says, re-applied. A stalled network share is the usual
    # cause and the agent's exec timeout bounds the wait.
    'remount_all':         'exec:mount -a',
    'flush_mail_queue':    'exec:postqueue -f',
    'update_av_definitions': {'linux':   'exec:freshclam',
                              'windows': 'ps:Update-MpSignature'},
    'start_scrub':         'exec:zpool scrub -- {pool}',

    'enable_autoupdates':  ('exec:systemctl enable --now unattended-upgrades.service '
                            '2>/dev/null || systemctl enable --now '
                            'dnf-automatic-install.timer'),
    'enable_av_realtime':  'ps:Set-MpPreference -DisableRealtimeMonitoring $false',
    'enable_gatekeeper':   'exec:spctl --master-enable',

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
    # Every agent implements it: systemctl poweroff on Linux, `shutdown /s /t 30`
    # on Windows, `shutdown -h +1` on macOS. All three are graceful.
    'shutdown_host':       'shutdown',
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
#
# ⛔ `name` IS NOT AN ALIAS FOR ANYTHING, and neither is `label`.
#
# Every alert payload in this codebase uses `name` for the DEVICE name — the
# `_fire`, `_fire_service_webhook` and `_fire_container_webhook` wrappers all
# stamp `'name': dev.get('name')` and the resource travels under its own key.
# So `('unit', 'name')` did not mean "the unit, or failing that another name for
# the unit". It meant: when the alert does not say which unit, restart a unit
# named after the host.
#
# Two mappings shipped doing exactly that, because the fallback hid it:
#   * `scrub_overdue` fires {'pool': …} while the alias list asked for `disk`,
#     which that payload has never carried — so `start_scrub` fell through to
#     `name` and built `exec:zpool scrub -- web01`.
#   * `readonly_fs` fires {'paths': [ … ]} — plural, and a list — so `remount_rw`
#     fell through and built `mount -o remount,rw -- web01`.
# Both were reachable, both would have been recorded as an action taken, and
# both passed the catalog gate, which only asks whether SOME alias is on the
# payload whitelist and never whether the MAPPED EVENT carries it.
#
# Without the fallback the worst case is `missing_parameter` — an honest refusal
# on the receipt — rather than a confident command aimed at the wrong thing.
_ACTION_PARAMS = {
    'unit':      ('unit',),
    'container': ('container',),
    'process':   ('process',),
    'mount':     ('path', 'paths'),
    'pool':      ('pool', 'disk'),
}

# Constants for events whose payload names no resource because there is only
# ever one of it. Curated here beside the safety analysis and never read from
# the alert, so this cannot become a path from remote data into a command.
#
# `win_update_stopped` says the Windows Update service is not running and does
# not name it, for the same reason nobody writes it down: it is always
# `wuauserv`. Before this, that mapping resolved `{unit}` to the device name.
_EVENT_PARAM_DEFAULTS = {
    'win_update_stopped': {'unit': 'wuauserv'},
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


def _actions_this_hour(tenant, taken_this_sweep=None):
    """Actions this tenant has taken in the last hour, INCLUDING this sweep.

    The `taken_this_sweep` term is not an optimisation, it is the whole guard.
    Receipts are appended after the candidate loop finishes, so a version that
    only counted the STORE gave every candidate in a sweep the same pre-sweep
    number: with a ceiling of 3 and 25 candidate alerts, all 25 dispatched.

    And that is exactly the scenario the ceiling exists for. The setting is
    described as stopping a flapping host becoming a storm — a flapping host
    produces its alerts all at once, which means they land in ONE sweep. The
    limit held only in the case nobody needed it to.
    """
    now = int(time.time())
    rows = (A._load_ro(A.AUTONOMY_RECEIPTS_FILE) or {}).get('receipts') or []
    stored = sum(1 for r in rows if isinstance(r, dict)
                 and r.get('tenant') == tenant
                 and r.get('verdict') == autonomy.ACT
                 and (now - int(r.get('ts') or 0)) < 3600)
    return stored + int((taken_this_sweep or {}).get(tenant, 0))


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
            if isinstance(v, (list, tuple)):
                # A one-element list is unambiguous (`readonly_fs` reports
                # {'paths': ['/srv']}). Two or more is not: there is no honest
                # way to pick, and acting on the first would leave the rest
                # broken while the receipt claimed a fix.
                v = v[0] if len(v) == 1 else None
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
    # Curated constants first, the alert's own values second — so a payload that
    # does name the resource always wins over the default.
    payload = {**_EVENT_PARAM_DEFAULTS.get(alert.get('event'), {}), **payload}
    family = A._device_os_family(dev)
    cmd, problem = _resolve_params(_command_for(action, family), payload, dev_id)
    return {
        # A unique id. `ts` is a whole second and a sweep builds every
        # candidate's plan in the same pass, so several receipts routinely
        # share one -- and verification keyed on ts alone then wrote ONE
        # host's verdict and check counts onto every receipt in that second,
        # across devices and across tenants. A receipt whose entire job is
        # answering "why did it do that?" was reporting another host's answer.
        'id': 'rcpt_' + secrets.token_hex(6),
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


# How long the agent gets to pick the command up and run it before the second
# checks sample is taken. Dispatch is ASYNCHRONOUS — the command waits in the
# queue until the host's next heartbeat — so "verify after acting" cannot mean
# "verify on the next line". Generous on purpose: a slow poll interval must not
# be reported as a failed remediation.
_VERIFY_DELAY_S = 900


def _check_summary_for(dev_id, dev):
    """The host's own checks verdict, from the engine the Checks page uses.

    Autonomy does NOT get its own opinion of whether a host is healthy. Reusing
    `_host_checks` means the operator's own thresholds, mutes and disabled rows
    decide, so the loop can never claim success against a definition of healthy
    nobody else shares.
    """
    cfg = A._config_ro() or {}
    disabled = (cfg.get('host_checks_disabled') or {}).get(dev_id) or []
    hw = {}
    if A.backend_exists(A.HARDWARE_FILE):
        hw = (A.load(A.HARDWARE_FILE) or {}).get(dev_id) or {}
    checks = A._host_checks(
        dev_id, dev, hw, disabled, int(time.time()), A.get_online_ttl(),
        custom_defs=cfg.get('custom_checks') or [],
        scripts=A._load_custom_scripts(),
        exposure_mutes=cfg.get('exposure_mutes') or [],
        **A._checks_threshold_kwargs(cfg))
    sm = A._host_check_summary(checks) or {}
    # NORMALISE to the key the pure comparison reads. `_host_check_summary`
    # returns {'counts': {ok, warning, critical, unknown}, 'worst', 'total'} —
    # it has no `failing`, so `verification_failed` would have compared 0 with 0
    # on every host, forever, and reported every action as verified. Caught by
    # printing a real summary instead of assuming its shape; it is the same
    # dead-signal shape as a consumer reading a key no producer writes.
    counts = sm.get('counts') or {}
    sm['failing'] = int(counts.get('critical', 0) or 0) + int(counts.get('warning', 0) or 0)
    return sm


def _dispatch(dev_id, dev, cmd):
    """Queue the command. Returns (outcome, ok).

    `_queue_command_batch`, never `_queue_command`: the latter calls respond()
    on its gate checks, which raises HTTPError and is only safe inside a real
    request. This runs from the cadence sweep with none in flight, and the
    difference between the two is a 500 on somebody's heartbeat.

    The batch helper carries every guard an operator's own command passes —
    maintenance mode, quarantine, audit mode, the four-eyes gate — so a refusal
    here is the same refusal a person would have got, reported as it happened
    rather than as success.
    """
    try:
        res = (A._queue_command_batch([dev_id], cmd, 'autonomy') or {}).get(dev_id) or {}
    except Exception as exc:                       # a guard that raises, not returns
        return f'refused: {type(exc).__name__}', False
    if res.get('approval_required'):
        return f"awaiting approval ({res.get('confirmation_id')})", False
    if not res.get('ok'):
        return f"refused: {res.get('error') or 'unknown'}", False
    return 'queued', True


def _escalate(dev_id, cmd):
    """Park the action as a real four-eyes confirmation.

    An ESCALATE verdict that only wrote the word "escalate" into a receipt would
    be a queue nobody can see and nobody can approve. This puts it in the
    confirmations ledger an admin already works from, so approving it dispatches
    through the ordinary path.
    """
    try:
        cid = A._park_for_approval(dev_id, cmd, 'autonomy', A._command_kind(cmd),
                                   reason='Proposed by autonomous remediation')
        return f'parked for approval ({cid})', cid
    except Exception as exc:
        return f'could not park for approval: {type(exc).__name__}', None


def _verify_due_receipts(now):
    """Second checks sample for actions whose verify window has passed.

    Compares against the snapshot taken before the action, using the pure
    `verification_failed` rule: any increase in FAILING checks is a regression.
    A regression raises `remediation_failed` — the event that already exists for
    exactly this ("an auto-remediation ran but its alert did not clear").

    It does NOT roll anything back, and the receipt no longer pretends
    otherwise: you cannot un-restart a service or un-reboot a host. Telling the
    operator plainly that a fix made things worse is the honest capability.
    """
    def _key(r):
        """Stable identity for a receipt. Falls back to (ts, device_id) for
        rows written before receipts carried an id -- still far better than ts
        alone, which collides across every device in the same second."""
        return r.get('id') or (r.get('ts'), r.get('device_id'))

    store = A._load_ro(A.AUTONOMY_RECEIPTS_FILE) or {}
    rows = store.get('receipts') or []
    due = [r for r in rows if isinstance(r, dict) and r.get('verified') is None
           and r.get('verify_due') and int(r['verify_due']) <= now]
    if not due:
        return
    devices = A.load(A.DEVICES_FILE) or {}
    still_open = {a.get('id') for a in (A.load(A.ALERTS_FILE) or {}).get('alerts', [])
                  if isinstance(a, dict) and not a.get('resolved_at')}
    verdicts, alerts, worked = {}, [], []
    for r in due:
        dev = devices.get(r.get('device_id'))
        if not dev:
            verdicts[_key(r)] = (False, 'device is gone')
            continue
        after = _check_summary_for(r['device_id'], dev)
        worse = autonomy.verification_failed(r.get('before_checks') or {}, after)
        verdicts[_key(r)] = (not worse, after)
        if worse:
            alerts.append((r, after))
        elif r.get('alert_id') and r['alert_id'] not in still_open:
            # It acted, the host's own checks did not get worse, and the alert
            # it was triggered by has closed. That is the same standard the
            # operator-fix and automation-rule sources are held to, and it is
            # stricter than `verified` on purpose: checks-did-not-worsen alone
            # would let an action that changed nothing count as a fix.
            #
            # Self-reinforcement is bounded by the same things as the other two
            # sources: one outcome per ALERT, and the loop can only have acted
            # here because it already had precedent or the operator waived it,
            # and — for anything destructive — because a person approved it.
            worked.append((r, dev))
    if verdicts:
        with A._LockedUpdate(A.AUTONOMY_RECEIPTS_FILE) as st:
            for row in (st.get('receipts') or []):
                v = verdicts.get(_key(row)) if isinstance(row, dict) else None
                if v is None:
                    continue
                ok, after = v
                row['verified'] = bool(ok)
                row['after_checks'] = after if isinstance(after, dict) else None
                if not ok:
                    row['outcome'] = (row.get('outcome') or '') + ' — verification failed'
    # After the lock, for the same reason the webhooks are: capture_fix_outcome
    # takes its own _LockedUpdate and a nested one is an OperationalError on the
    # SQL backends.
    for r, dev in worked:
        A.capture_fix_outcome(
            alert_id=r.get('alert_id'), event=r.get('trigger') or '',
            device_id=r.get('device_id') or '',
            device_name=r.get('device_name') or '',
            tenant=r.get('tenant') or '', actor='autonomous remediation',
            fix_command=r.get('command') or r.get('action') or '',
            source='autonomy', now=now)
    # Fire AFTER the lock: fire_webhook is self-locking and the deferral rules
    # apply, but keeping it outside is the habit this codebase asks for.
    for r, after in alerts:
        A.fire_webhook('remediation_failed', {
            'device_id': r.get('device_id'), 'device_name': r.get('device_name'),
            'name': r.get('action'), 'rule_name': r.get('action'),
            'detail': (f"autonomous {r.get('action')} on {r.get('device_name')} ran, "
                       f"and failing checks went from "
                       f"{(r.get('before_checks') or {}).get('failing', 0)} to "
                       f"{after.get('failing', 0)}"),
        })


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

    # Close out anything whose verify window has elapsed BEFORE looking for new
    # work, so a host that a previous action made worse is on record before this
    # sweep considers acting on it again.
    try:
        _verify_due_receipts(now)
    except Exception as exc:
        A.sys.stderr.write(f'[remotepower] autonomy verify failed: {exc}\n')

    alerts = (A.load(A.ALERTS_FILE) or {}).get('alerts', [])
    cands = _candidate_alerts(alerts)
    if not cands:
        with A._LockedUpdate(A.AUTONOMY_RECEIPTS_FILE) as store:
            store['last_run'] = now
        return

    devices = A.load(A.DEVICES_FILE) or {}
    made = []
    # Actions dispatched so far IN THIS SWEEP, per tenant. Receipts are written
    # after the loop, so without this the rate limit reads a stale count for
    # every candidate after the first.
    _taken = {}
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
            # A change-GATED maintenance window is this product's "only touch
            # this host inside the window" model, and `_exec_gated` is the
            # predicate the heartbeat dispatch already uses for it (True ==
            # hold). Refusing here rather than letting the command sit in the
            # queue is the right call for an autonomous action: a held command
            # fires whenever the window next opens — hours later, on a decision
            # made against evidence that has moved on since.
            #
            # It is also inert on a fleet that has declared no change window,
            # which matters because the shipped default is require_window=True
            # and most installs have none: the setting holds where an operator
            # asked for it and deadlocks nobody who did not.
            #
            # This replaces a call to `A._in_maintenance_window` behind a
            # `hasattr` guard. No function of that name exists anywhere in the
            # codebase, so the guard was always False, `in_window` was always
            # True, and "Only inside a maintenance window" — ticked, in the UI,
            # on the maintainer's own instance — had never once been evaluated.
            in_window=not A._exec_gated(dev_id, dev),
            actions_this_hour=_actions_this_hour(tenant, _taken),
            dry_run_ok=True,
            # A drafted plan: a concrete command out of the curated catalog. It
            # only counts as evidence where the operator has waived precedent,
            # so this is False on a default policy and the loop keeps asking the
            # fleet's own history first.
            has_plan=(bool(plan.get('command'))
                      and not policy.get('require_precedent', True)),
            os_family=plan.get('os_family'), plan_problem=plan.get('problem'))

        rec = autonomy.receipt(plan, decision)
        # v7.0.0: ACT dispatches, ESCALATE parks for approval. Both go through
        # the operator's own command path, so every guard a person's command
        # passes applies here unchanged.
        #
        # SHADOW NEVER REACHES THIS: `decide()` short-circuits on the mode
        # before any ACT branch, so a shadow tenant produces a SHADOW verdict
        # and falls through both arms below. That is checked exhaustively over
        # every input combination in tests/test_v700_autonomy_core.py, and it is
        # the property the whole adoption story rests on.
        if decision.verdict == autonomy.ACT:
            before = _check_summary_for(dev_id, dev)
            outcome, ok = _dispatch(dev_id, dev, plan.get('command') or '')
            rec['outcome'] = outcome
            if ok:
                _taken[tenant] = _taken.get(tenant, 0) + 1
                # Dispatch is asynchronous — the agent collects the command on
                # its next heartbeat — so the second checks sample is owed
                # later, not now.
                rec['before_checks'] = before
                rec['verify_due'] = now + _VERIFY_DELAY_S
        elif decision.verdict == autonomy.ESCALATE:
            rec['outcome'], cid = _escalate(dev_id, plan.get('command') or '')
            if cid:
                rec['confirmation_id'] = cid
        made.append(rec)

    for rec in made:
        _append_receipt(rec)
    with A._LockedUpdate(A.AUTONOMY_RECEIPTS_FILE) as store:
        store['last_run'] = now

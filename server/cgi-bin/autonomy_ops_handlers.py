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
                        'action_groups': [list(g) for g in autonomy.ACTION_GROUPS],
                        'modes': list(autonomy.MODES)})
        return
    if A.method() != 'PUT':
        A.respond(405, {'error': 'Method not allowed'})
    # Changing the envelope is a control-plane act: admin only, and audited.
    actor = A.require_admin_auth()
    tenant = A._tenant_gate() or A.DEFAULT_TENANT
    body = A.get_json_obj()
    # Merged over what this tenant already has, not over the shipped defaults:
    # an absent key on an update means "leave it alone". Merging over the
    # defaults meant a partial PUT re-granted the whole default allow-list to a
    # tenant that had narrowed it, and said "saved".
    new = autonomy.normalize_policy(
        body.get('policy') if isinstance(body.get('policy'), dict) else body,
        base=_policy_for(tenant))
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


def _visible_receipts(rows):
    """The receipts this caller may see. Both halves of the filter.

    A receipt names a device, so the rule is the one every device-keyed store
    follows — and it has TWO parts. The tenant gate is the one that shipped;
    the ROLE scope was missing, so a custom role confined to two hosts could
    read the decision history of the whole fleet, hostnames and commands
    included. `handle_alerts_clear` gets both from `_filter_alerts_for_caller`;
    there is no such helper for this store, so it is spelled out here and used
    by the read and the delete alike.

    The device scope is applied ONLY when the caller actually has one. Filtering
    an unscoped caller against the live device set would hide the receipts of
    decommissioned hosts, and a receipt is self-contained precisely because the
    fleet changes — the audit outlives the device.
    """
    gate = A._tenant_gate()
    if gate is not None:
        rows = [r for r in rows if isinstance(r, dict) and r.get('tenant') == gate]
    scope = A._caller_scope()
    if scope is not None:
        visible = set(A._scope_filter_devices(A.load(A.DEVICES_FILE) or {}, scope))
        rows = [r for r in rows if isinstance(r, dict)
                and (not r.get('device_id') or r.get('device_id') in visible)]
    return rows


def handle_autonomy_receipts():
    """GET /api/autonomy/receipts — what the loop did, or would have done."""
    A.require_auth()
    rows = _visible_receipts(
        (A.load(A.AUTONOMY_RECEIPTS_FILE) or {}).get('receipts') or [])
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
        # Exactly what a GET would return — you cannot delete what you cannot
        # read, and the two must not be able to drift apart.
        deletable = {id(r) for r in _visible_receipts(rows)}
        kept = []
        for r in rows:
            mine = id(r) in deletable
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

    Assembled ONLY from stores verified to exist, and NOT wrapped
    in a blanket try/except. The first draft of this reached for MONITORS_FILE,
    STATUS_PAGE_FILE and NETWORK_MAP_FILE — none of which exist — inside
    `except Exception: pass`, which would have made every blast radius silently
    zero and every policy limit trivially satisfied. A safety input that fails
    open is worse than no safety input, so a missing store now raises and the
    caller records the failure rather than acting on a comfortable number.

    Monitors live in CONFIG_FILE under `monitors` (each carrying `device_id`),
    not in a store of their own. Containers live in CONTAINERS_FILE and watched
    units in SERVICES_FILE — neither is on the device record, and reading them
    off it made both components zero on every host, which is the fail-open this
    docstring rules out. Redundancy keys off group+function siblings.
    """
    cfg = A._config_ro() or {}
    monitors = [m.get('id') or m.get('label') or m.get('path')
                for m in (cfg.get('monitors') or [])
                if isinstance(m, dict) and m.get('device_id') == dev_id
                and not m.get('paused')]

    # `containers` is not in the safe_si whitelist — the ingest writes
    # CONTAINERS_FILE as {ts, items:[…]}. Same lookup as _build_runbook_snapshot.
    ctr = (A.load(A.CONTAINERS_FILE) or {}).get(dev_id) or {}
    containers = [c.get('name') for c in (ctr.get('items') or [])
                  if isinstance(c, dict) and c.get('name')]

    # Services the host runs that something else is watching. `services.json`
    # is per-device current state — {updated_at, services:[…], flapping:[…]}.
    # The key `watched` is written nowhere.
    services = []
    svc = (A.load(A.SERVICES_FILE) or {}).get(dev_id) or {}
    if isinstance(svc, dict):
        services = [s.get('unit') for s in (svc.get('services') or [])
                    if isinstance(s, dict) and s.get('unit')]

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
    is intentional — the blast-radius view earns its keep whether or not the loop
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
#
# AND EVERY KEY IS AN EVENT THAT NAMES A DEVICE. The sweep resolves a device
# before it does anything else, so a FLEET-SINGLETON event — one whose payload
# carries no `device_id` — is a mapping the loop can never act on, and it fails
# silently: the candidate is dropped before a receipt is written, so the table
# looks wider than the loop is. Three rows were exactly that until v7.0.2:
# `wan_down` (whose own source comment says "fleet singleton, no device_id"),
# `mailflow_delayed` (a server-side mail round-trip) and `resolver_unhealthy`
# (a server-side DNS check over operator-configured targets, not hosts).
# `tests/test_v702_autonomy.py` holds the rule now.
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
    # disk pressure — the ladder, gentlest first.
    # NOT `server_disk_low`: that is the CONTROLLER's own disk watchdog
    # ({'target': 'server', 'name': 'RemotePower server'}), so it names no host
    # and the sweep drops it. It was mapped to the whole six-rung ladder, which
    # made disk pressure look covered by six remedies when the event an operator
    # would expect to fire is about this server's data directory.
    # The full ladder lives here now. `disk_predict_fail` is the per-HOST
    # "this filesystem is going to fill" signal, which is what the six rungs
    # were written for; they were on `server_disk_low`, which is this server's
    # own data directory.
    'disk_predict_fail':    ('clear_journal', 'rotate_logs', 'clear_package_cache',
                             'clear_tmp', 'prune_container_images',
                             'trim_filesystem'),
    'resource_saturation_predicted': ('clear_cache',),
    # host services that fix themselves with a nudge
    'clock_skew':           ('resync_clock',),
    'mailq_high':           ('flush_mail_queue',),
    'av_warning':           ('update_av_definitions',),
    'win_defender_stale':   ('update_av_definitions',),
    # Posture that drifted off. Each is a single, reversible switch.
    #
    # NOT `autoupdate_disabled`: walking the states the agent's collector can
    # produce, there is essentially none where the alert fires AND
    # `systemctl enable --now` fixes it. On Debian the alert means the periodic
    # switch in /etc/apt/apt.conf.d/20auto-upgrades is "0" while the unit is
    # already enabled, so the command exits 0 having changed nothing; on
    # RHEL/Fedora it usually means dnf-automatic is not installed, and enabling
    # a unit does not install a package; on a non-systemd host the collector
    # reports disabled unconditionally and both halves of the command are
    # systemctl.
    'av_realtime_off':      ('enable_av_realtime',),
    'mac_gatekeeper_off':   ('enable_gatekeeper',),
    'scrub_overdue':        ('start_scrub',),
    # destructive territory — reachable, but off in the default policy
    'process_alert':        ('kill_process',),
    # NOT `oom_detected`: the payload's `process` is `last_oom_proc`, the name of
    # the process the kernel ALREADY killed and systemd has since restarted. So
    # the action would TERM the fresh one — into the middle of crash recovery on
    # a database — and nothing resolves oom_detected, so it would repeat every
    # hour to the rate ceiling. Verification could not catch it either: the
    # before-sample is taken with the service already failing, so a host that
    # cannot get worse scores as a successful remediation.
    'readonly_fs':          ('remount_rw',),
    'gateway_unreachable':  ('restart_networking',),
    'mac_firewall_off':     ('enable_firewall',),
    'win_firewall_off':     ('enable_firewall',),
    'reboot_required':      ('reboot',),
    # NOT `ups_critical`. The product already shuts hosts down on a failing UPS,
    # through `_ups_shutdown_dependents`, and that path is opt-in on TWO axes on
    # purpose: a global `ups_auto_shutdown_enabled` flag AND each dependent
    # device's own `ups_dependency` mapping. It also shuts down the DEPENDENTS
    # and excludes the reporting host, because a device cannot depend on its own
    # UPS.
    #
    # An autonomy action here honoured neither axis and targeted exactly the
    # wrong host: `ups_critical` names the machine whose agent reports the UPS —
    # the NUT master. Powering that off first ends the UPS telemetry, so
    # `ups_on_line` never fires, the alert never clears, and the orderly
    # shutdown of everything else on that UPS is gone. A checkbox on this page
    # would have routed around an intentional opt-in and made the outage worse.
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
    'flush_mail_queue':    'exec:postqueue -f',
    'update_av_definitions': {'linux':   'exec:freshclam',
                              'windows': 'ps:Update-MpSignature'},
    'start_scrub':         'exec:zpool scrub -- {pool}',
    # Timestamped, because a fixed snapshot name fails on the second run with
    # "dataset already exists" — which would read as an action that ran.
    'create_zfs_snapshot': 'exec:zfs snapshot -- {pool}@rp-$(date +%Y%m%d-%H%M%S)',

    'enable_av_realtime':  'ps:Set-MpPreference -DisableRealtimeMonitoring $false',
    'enable_gatekeeper':   'exec:spctl --master-enable',

    'kill_process':        'exec:pkill -TERM -x -- {process}',
    'remount_rw':          'exec:mount -o remount,rw -- {mount}',
    # Detached on purpose: restarting networking from a command the network
    # delivered kills the delivery. Same shape as the agent-restart rule.
    'restart_networking':  ('exec:systemd-run --on-active=5 systemctl restart '
                            'NetworkManager systemd-networkd'),
    'enable_firewall':     {
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
    # The absence is intentional and refuses with `no_command_template` rather
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
    # ESCALATE counts too. It is not an action on a host, but it is an item in
    # the queue a human has to work through, and the setting is described as
    # stopping a flapping host becoming a storm — a storm of approval requests
    # is the same storm. Counting only ACT left the whole escalation path
    # outside every ceiling.
    stored = sum(1 for r in rows if isinstance(r, dict)
                 and r.get('tenant') == tenant
                 and r.get('verdict') in (autonomy.ACT, autonomy.ESCALATE)
                 and (now - int(r.get('ts') or 0)) < 3600)
    return stored + int((taken_this_sweep or {}).get(tenant, 0))


_DRILL_MAX_AGE_S = 30 * 86400


def _proxmox_guest_for(dev):
    """The Proxmox guest name this device IS, or ''.

    There is no formal link between a fleet device and a Proxmox guest — the
    Virtualization page lists guests by name and the fleet lists hosts by name,
    and nothing joins them. So this matches on the first DNS label, lowercased:
    `pmg01.tvipper.com` is the guest called `pmg01`.

    A heuristic standing in for a safety precondition is exactly the shape this
    codebase keeps finding bugs in, so it is narrow: an operator can
    pin the link explicitly with `proxmox_guest` on the device record, and the
    name match below refuses anything ambiguous. Whatever it resolves to is
    written onto the receipt, because "your backups are fine" is not a claim to
    make without saying which machine's.
    """
    if not isinstance(dev, dict):
        return ''
    pinned = str(dev.get('proxmox_guest') or '').strip()
    if pinned:
        return pinned.lower()
    name = str(dev.get('name') or dev.get('hostname') or '').strip()
    return name.split('.')[0].lower()


def _proxmox_backup_evidence(dev, now):
    """(ok, why) — a recent vzdump backup or snapshot for this device's guest.

    Both stores are refreshed by the Proxmox pages and keyed by guest, not by
    device, so the join is by name (see above). Recency uses the operator's OWN
    thresholds — `proxmox_backup_warn_days` and `proxmox_snapshot_warn_days`,
    the same numbers that decide whether a guest is flagged as under-protected
    on the attention list. A backup this product is already telling you is stale
    must not be the thing that lets it patch.

    A vzdump archive is a backup. A snapshot is a rollback point rather than a
    backup — it lives on the same storage as the guest — but for the question
    this gate actually asks, "if this upgrade breaks the host, can I get it
    back", it is a real answer, and the operator asked for it to count.
    """
    guest = _proxmox_guest_for(dev)
    if not guest:
        return False, ''
    cfg = A._config_ro() or {}

    if A.backend_exists(A.PROXMOX_BACKUP_CACHE):
        rows = (A.load(A.PROXMOX_BACKUP_CACHE) or {}).get('guests') or []
        hits = [g for g in rows if isinstance(g, dict)
                and str(g.get('name') or '').strip().lower() == guest]
        if len(hits) == 1 and hits[0].get('last_backup'):
            age = (now - int(hits[0]['last_backup'])) // 86400
            try:
                warn = int(cfg.get('proxmox_backup_warn_days', 7))
            except (TypeError, ValueError):
                warn = 7
            if age <= warn:
                return True, (f"Proxmox backup of guest {hits[0].get('name')} "
                              f"(vmid {hits[0].get('vmid')}), {age}d old")
        elif len(hits) > 1:
            return False, ''      # ambiguous name — resolve nothing

    if A.backend_exists(A.PROXMOX_SNAPSHOT_CACHE):
        cache = A.load(A.PROXMOX_SNAPSHOT_CACHE) or {}
        try:
            warn = int(cfg.get('proxmox_snapshot_warn_days', 7))
        except (TypeError, ValueError):
            warn = 7
        hits = [e for e in cache.values() if isinstance(e, dict)
                and str(e.get('vm_name') or '').strip().lower() == guest]
        if len(hits) != 1:
            return False, ''
        snaps = [s for s in (hits[0].get('snapshots') or [])
                 if isinstance(s, dict) and s.get('snaptime')]
        if snaps:
            newest = max(snaps, key=lambda s: int(s.get('snaptime') or 0))
            age = (now - int(newest['snaptime'])) // 86400
            if age <= warn:
                return True, (f"Proxmox snapshot \"{newest.get('name')}\" of guest "
                              f"{hits[0].get('vm_name')} (vmid {hits[0].get('vmid')}), "
                              f"{age}d old")
    return False, ''


def _backup_evidence(dev_id, dev):
    """(ok, why) — what, if anything, says this host is recoverable."""
    now = int(time.time())
    state = A.load(A.DATA_DIR / 'backup_state.json') or {}
    if isinstance(state, dict):
        prefix = f'{dev_id}:'
        for key, row in state.items():
            if not isinstance(row, dict) or not str(key).startswith(prefix):
                continue
            if row.get('drill_status') != 'ok':
                continue
            age = now - int(row.get('drill_at') or 0)
            if age < _DRILL_MAX_AGE_S:
                return True, (f'restore drill of {str(key)[len(prefix):] or "?"}, '
                              f'{age // 86400}d ago')
    return _proxmox_backup_evidence(dev, now)


# Some events describe several different conditions and say WHICH in the
# payload. `metric_critical` is the per-host resource alert — the one that
# actually fires when a fleet host fills its disk — and the remedy for a full
# filesystem has nothing to do with the remedy for CPU saturation. A single
# ladder per event cannot express that, so these events map through one payload
# field.
#
# A value with no entry is NOT a candidate. There is no honest ladder for `cpu`
# at 98%: nothing in the catalog frees CPU, and mapping it to something would be
# the invented-remedy shape this file keeps removing.
#
# Kept as its own table rather than overloading _EVENT_ACTIONS with two value
# shapes: a dict where a tuple is expected fails by iterating its KEYS, which is
# a silent wrong answer rather than an error.
_EVENT_ACTIONS_BY = {
    # `metric` is one of cpu / conntrack / disk / fd / inode / memory / swap.
    'metric_critical': ('metric', {
        'disk':   ('clear_journal', 'rotate_logs', 'clear_package_cache',
                   'clear_tmp', 'prune_container_images', 'trim_filesystem'),
        # Inodes are freed by deleting FILES, so the two rungs that free bytes
        # without freeing files are not on this ladder.
        'inode':  ('clear_journal', 'rotate_logs', 'clear_tmp',
                   'clear_package_cache'),
        'memory': ('clear_cache',),
        'swap':   ('clear_cache',),
    }),
    'metric_warning': ('metric', {
        'disk':   ('clear_journal', 'rotate_logs', 'clear_package_cache',
                   'clear_tmp'),
        'inode':  ('clear_journal', 'rotate_logs', 'clear_tmp'),
    }),
    # The pool kind: zfs | btrfs. btrfs has no entry on purpose — its snapshot
    # takes a source subvolume and a destination path, neither of which the
    # alert carries.
    'snapshot_stale': ('kind', {'zfs': ('create_zfs_snapshot',)}),
}


def _ladder_for(alert):
    """The action ladder this alert maps to, or ()."""
    event = alert.get('event')
    disc = _EVENT_ACTIONS_BY.get(event)
    if disc:
        field, table = disc
        payload = alert.get('payload') if isinstance(alert.get('payload'), dict) else {}
        return tuple(table.get(str(payload.get(field) or '')) or ())
    return tuple(_EVENT_ACTIONS.get(event) or ())


def _candidate_alerts(alerts):
    """Open, unacknowledged alerts whose event maps to a ladder of actions.

    `acknowledged_at` is the field an alert row actually carries — `_record_alert`
    writes it and eight read sites in api.py use it. The first version of this
    filter said `acked_at`, which appears nowhere else in the codebase, so
    acknowledging an alert had never once stopped the loop from acting on it.
    An operator saying "I have got this" is the clearest possible signal not to,
    and it was being read from a key that is never set.
    """
    out = []
    for a in alerts or []:
        if not isinstance(a, dict):
            continue
        if a.get('resolved_at') or a.get('acknowledged_at') or a.get('acked_at'):
            continue
        ladder = _ladder_for(a)
        if ladder:
            out.append((a, ladder))
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
        'backup_evidence': '',
    }


# How long the agent gets to pick the command up and run it before the second
# checks sample is taken. Dispatch is ASYNCHRONOUS — the command waits in the
# queue until the host's next heartbeat — so "verify after acting" cannot mean
# "verify on the next line". Generous on purpose: a slow poll interval must not
# be reported as a failed remediation.
_VERIFY_DELAY_S = 900


def _change_window_open(dev_id, dev):
    """False when a change-gated maintenance window covers this host and is shut.

    `_exec_gated` answers the same question for the heartbeat's dispatch, and
    every failure path in it means ALLOW: a bare `except Exception: return False`,
    and `load()` returning {} on a corrupt store lands in the same place. That is
    the right default for the dispatch path, which holds rather than drops.

    It is the wrong default here. This file's own blast-radius helper states the
    house rule — a safety input that fails open is worse than no safety input —
    so an error reading the window store means HOLD, and the receipt says
    outside_window rather than acting through a gate it could not read.
    """
    try:
        return not A._exec_gated(dev_id, dev)
    except Exception as exc:
        A.sys.stderr.write(
            f'[remotepower] autonomy window check failed dev={dev_id}: {exc}\n')
        return False


def _verify_delay_for(dev):
    """How long this host gets before the second checks sample.

    At least the shipped 15 minutes, and at least two of its own poll intervals —
    a device can be set to poll hourly, and verifying a command the agent has not
    collected yet measures nothing."""
    try:
        poll = int((dev or {}).get('poll_interval') or 0)
    except (TypeError, ValueError):
        poll = 0
    return max(_VERIFY_DELAY_S, 2 * poll)


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
        drift_rec=A._drift_state_ro().get(dev_id) or {},
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


# An autonomous decision has a shelf life. `CMDS_FILE` entries are plain strings
# with no timestamp, drained only when a heartbeat pops one — so a command queued
# at 03:58 into a change window closing at 04:00 is HELD at the next heartbeat
# and dispatches at 02:00 the following night, onto a host that has been healthy
# for 22 hours. A host that is simply offline holds it until it comes back.
#
# A human's queued command is theirs to leave sitting there. One nobody watched
# being decided is not, so this side store stamps only the loop's own commands
# and the dispatch chokepoint drops the ones that have gone stale. A side store
# rather than a richer queue entry because ~20 call sites read those entries as
# plain strings — `x in cmds[dev]`, `tag not in c` — and a dict among them fails
# quietly (a dedup that stops matching) rather than loudly.
_CMD_TTL_S = 3600


def _stamp_command_ttl(dev_id, cmd, now):
    """Record when the loop queued this command, for the dispatch-time check."""
    try:
        with A._LockedUpdate(A.AUTONOMY_CMD_TTL_FILE) as store:
            row = store.get(dev_id)
            if not isinstance(row, dict):
                row = {}
            # Prune this device's stale entries while we are here: bounded by the
            # number of distinct commands the loop has queued for one host.
            row = {c: t for c, t in row.items()
                   if isinstance(t, int) and (now - t) < 2 * _CMD_TTL_S}
            row[str(cmd)[:512]] = now
            store[dev_id] = row
    except Exception as exc:
        A.sys.stderr.write(
            f'[remotepower] autonomy ttl stamp failed dev={dev_id}: {exc}\n')


def command_is_stale(dev_id, cmd, now):
    """True when this is an autonomy-queued command older than its shelf life.

    Called from the heartbeat's dispatch chokepoint, so it stays cheap: no store
    read at all on an install that has never queued one.
    """
    try:
        if not A.backend_exists(A.AUTONOMY_CMD_TTL_FILE):
            return False
        row = (A._load_ro(A.AUTONOMY_CMD_TTL_FILE) or {}).get(dev_id)
        if not isinstance(row, dict):
            return False
        ts = row.get(str(cmd)[:512])
        return isinstance(ts, int) and (now - ts) >= _CMD_TTL_S
    except Exception:
        return False        # never let this break a heartbeat's dispatch


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
    _stamp_command_ttl(dev_id, cmd, int(time.time()))
    return 'queued', True


def _pending_confirmation(dev_id, cmd):
    """An id already parked for this exact (device, command), or ''.

    The loop has no per-alert memory: it re-evaluates every open candidate every
    sweep, and an alert that needs approval is still open by definition. Without
    this, one open `gateway_unreachable` on one host produced a new confirmation
    row every five minutes — twelve an hour, indefinitely — and from the second
    hour, twelve `mcp_confirmation_expired` alerts an hour as the first batch
    aged out. Into the same ledger an operator approves real changes from, and
    the same inbox they use to notice real problems.

    It had never happened, because until the backup gate was fixed no
    destructive action could reach ESCALATE at all. Making that verdict
    reachable is what made this reachable.
    """
    try:
        # `load()` memoises per request and this sweep writes to the same store
        # as it goes, so a cached snapshot taken before the first escalation
        # would not see it — and every later candidate on that host would park a
        # duplicate. Same shape as the file-manager long-poll: a loop that reads
        # a key something else in the same pass is writing has to bust the cache.
        A._invalidate_load_cache(A.CONFIRMATIONS_FILE)
        rows = (A.load(A.CONFIRMATIONS_FILE) or {}).get('confirmations') or []
    except Exception:
        return ''
    for c in rows:
        if not isinstance(c, dict) or c.get('status') != 'pending':
            continue
        if c.get('device_id') != dev_id:
            continue
        params = c.get('params') if isinstance(c.get('params'), dict) else {}
        if params.get('command') == cmd or c.get('command') == cmd:
            return str(c.get('id') or '')
    return ''


def _escalate(dev_id, cmd):
    """Park the action as a real four-eyes confirmation.

    An ESCALATE verdict that only wrote the word "escalate" into a receipt would
    be a queue nobody can see and nobody can approve. This puts it in the
    confirmations ledger an admin already works from, so approving it dispatches
    through the ordinary path.
    """
    already = _pending_confirmation(dev_id, cmd)
    if already:
        return f'already awaiting approval ({already})', already
    try:
        cid = A._park_for_approval(dev_id, cmd, 'autonomy', A._command_kind(cmd),
                                   reason='Proposed by autonomous remediation')
        return f'parked for approval ({cid})', cid
    except Exception as exc:
        return f'could not park for approval: {type(exc).__name__}', None


def _command_result(outputs, dev_id, command, after_ts):
    """The agent's own answer for this command, or None if it never reported one.

    Four of the actions in the catalog are `exec:`/`ps:` one-liners whose only
    failure signal is the exit code. The agent returns it — `cmd_output` carries
    {ts, cmd, output, rc} and api.py stores the last N per device — and nothing
    in this subsystem read it. So a command that exited 127 because the tool is
    not installed and a command that worked produced byte-identical receipts:
    `outcome: queued`, `verified: true`.

    Matched on the exact command string and only rows newer than the dispatch,
    because a host runs the same command more than once over its life and the
    previous run's success is not evidence about this one.
    """
    rows = (outputs or {}).get(dev_id) or []
    want = A._sanitize_str(str(command or ''), 512)
    if not want:
        return None
    for r in reversed(rows):
        if not isinstance(r, dict):
            continue
        if int(r.get('ts') or 0) < after_ts:
            break                       # append-ordered: older still from here
        if r.get('cmd') == want:
            return {'rc': int(r.get('rc')) if isinstance(r.get('rc'), int) else -1,
                    'output': str(r.get('output') or '')[:400],
                    'ts': int(r.get('ts') or 0)}
    return None


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
    # One read for the whole sweep. Only reached when something is actually due,
    # which is at most once every few minutes.
    outputs = A.load(A.CMD_OUTPUT_FILE) or {}
    still_open, resolved = set(), set()
    for a in (A.load(A.ALERTS_FILE) or {}).get('alerts', []):
        if not isinstance(a, dict):
            continue
        (resolved if a.get('resolved_at') else still_open).add(a.get('id'))
    verdicts, alerts, worked, results = {}, [], [], {}
    for r in due:
        dev = devices.get(r.get('device_id'))
        if not dev:
            verdicts[_key(r)] = (False, 'device is gone', False)
            continue
        after = _check_summary_for(r['device_id'], dev)
        worse = autonomy.verification_failed(r.get('before_checks') or {}, after)
        res = _command_result(outputs, r['device_id'], r.get('command'),
                              int(r.get('ts') or 0))
        results[_key(r)] = res
        # A non-zero exit is the action telling us it did not do the thing. It
        # outranks the checks comparison, which cannot see the difference
        # between "fixed it" and "the binary is not installed on this distro".
        ran_ok = bool(res) and res['rc'] == 0
        failed = worse or (res is not None and res['rc'] != 0)
        verdicts[_key(r)] = (not failed, after, worse)
        if failed:
            alerts.append((r, after, res))
        elif r.get('alert_id') in resolved and ran_ok:
            # It acted, the host's own checks did not get worse, and the alert
            # it was triggered by is PRESENT AND RESOLVED. That is the same
            # standard the operator-fix and automation-rule sources are held to,
            # and it is stricter than `verified` on purpose: checks-did-not-worsen
            # alone would let an action that changed nothing count as a fix.
            #
            # `in resolved` rather than `not in still_open`: an id is equally
            # absent when the ROW IS GONE — retention, an admin clearing the
            # inbox, the 5000-row cap, or `load()` returning {} on a corrupt
            # store. Absence would turn every in-flight receipt into precedent
            # at confidence 1.0 in a single pass, for commands nothing was
            # observed to fix. The sibling sweeps fail safe here by accident
            # (a missing row yields no event and capture_fix_outcome refuses
            # one); this path passes the receipt's own `trigger`, which is
            # always populated, so it has no such net.
            #
            # And `ran_ok`: the agent has to have REPORTED this exact command
            # with rc 0. No report at all means it never collected it — the host
            # was offline, or its poll interval outran the window — and an alert
            # that cleared on its own in the meantime is not evidence about a
            # command that never ran.
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
                ok, after, worse = v
                row['verified'] = bool(ok)
                row['after_checks'] = after if isinstance(after, dict) else None
                # What the agent said, on the receipt — the difference between
                # "it ran and worked" and "nothing ever ran" was invisible.
                #
                # Both notes when both are true: an operator reading "no result
                # from the agent" on a row whose checks also got worse needs the
                # second half more than the first.
                res = results.get(_key(row))
                row['rc'] = res['rc'] if res else None
                row['command_output'] = res['output'] if res else None
                notes = []
                if res is None:
                    notes.append('no result from the agent')
                elif res['rc'] != 0:
                    notes.append(f"the command exited {res['rc']}")
                if worse:
                    notes.append('verification failed')
                if notes:
                    row['outcome'] = ' — '.join([row.get('outcome') or ''] + notes)
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
            action=r.get('action') or '', source='autonomy', now=now)
    # Fire AFTER the lock: fire_webhook is self-locking and the deferral rules
    # apply, but keeping it outside is the habit this codebase asks for.
    for r, after, res in alerts:
        if res is not None and res['rc'] != 0:
            detail = (f"autonomous {r.get('action')} on {r.get('device_name')} "
                      f"exited {res['rc']}: {res['output'][:160]}")
        else:
            detail = (f"autonomous {r.get('action')} on {r.get('device_name')} ran, "
                      f"and failing checks went from "
                      f"{(r.get('before_checks') or {}).get('failing', 0)} to "
                      f"{after.get('failing', 0)}")
        A.fire_webhook('remediation_failed', {
            'device_id': r.get('device_id'), 'device_name': r.get('device_name'),
            'name': r.get('action'), 'rule_name': r.get('action'),
            'detail': detail,
        })


def run_autonomy_if_due():
    """Cadence: evaluate open alerts against each tenant's policy.

    In shadow mode this writes receipts and touches NOTHING — that is the whole
    adoption story, so the execution branch is the short one and
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
            # kind=None on purpose. `_similar_incidents` matches same-event OR
            # same-KIND, which is right for the triage tool showing a human
            # related history — but here it would let a prior fix for one event
            # justify acting on another that merely shares a kind. `service`
            # alone pools service_down, unit_flapping and failed_unit, whose
            # ladders differ. The module's own contract is "this exact thing was
            # fixed this exact way before"; kind-matching is not that.
            similar = A._similar_incidents(
                alert.get('event'), None, tenant,
                exclude_alert_id=alert.get('id'), limit=8) or []
        except Exception:
            similar = []
        conf, samples, prec_action = autonomy.precedent_confidence(similar, action)
        radius = _blast_radius_for(dev_id, dev, devices)
        plan = _build_plan(alert, action, dev, dev_id, radius, prec_action)
        # WHICH backup, on the receipt. The Proxmox evidence is matched to a
        # guest by NAME, and "this host is recoverable" is not a claim to make
        # without saying which machine's backup said so.
        backup_ok, plan['backup_evidence'] = _backup_evidence(dev_id, dev)

        decision = autonomy.decide(
            action=action, policy=policy, module_enabled=True,
            tenant_ok=bool(tenant), radius=radius,
            precedent_conf=conf, precedent_samples=samples,
            backup_verified=backup_ok,
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
            in_window=_change_window_open(dev_id, dev),
            actions_this_hour=_actions_this_hour(tenant, _taken),
            dry_run_ok=True,
            # Whether a concrete command came out of the curated catalog. Whether
            # that COUNTS as evidence is decide()'s call, from the policy — the
            # envelope is one function, and a knob evaluated out here would not
            # be part of it.
            has_plan=bool(plan.get('command')),
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
                #
                # And "later" has to mean later than THIS host's poll interval.
                # A fixed 15 minutes against a device polling hourly guarantees
                # the sample is taken before the agent could have collected the
                # command: checks unchanged, and if the alert happened to close
                # on its own, a precedent row would name a command that never
                # ran, stamped verified.
                rec['before_checks'] = before
                rec['verify_due'] = now + _verify_delay_for(dev)
        elif decision.verdict == autonomy.ESCALATE:
            rec['outcome'], cid = _escalate(dev_id, plan.get('command') or '')
            if cid:
                rec['confirmation_id'] = cid
                _taken[tenant] = _taken.get(tenant, 0) + 1
        made.append(rec)

    for rec in made:
        _append_receipt(rec)
    with A._LockedUpdate(A.AUTONOMY_RECEIPTS_FILE) as store:
        store['last_run'] = now

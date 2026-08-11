"""RemotePower — Proxmox VE guest lifecycle handlers (LXC + QEMU).

A bound-module carve-out of api.py's request-coupled Proxmox handlers,
following the tls_ct_handlers / rack_ipam_handlers / cmdb_handlers pattern:

  - api.py execs a PRIVATE instance and binds its own ``globals()`` here, so
    every api service is reached as ``A.<name>`` — a DYNAMIC attribute lookup,
    which keeps the test suite's monkeypatching of api.respond / api.load /
    api.audit_log working, and resolves identically under the imported-module
    (wsgi.py / scheduler.py) and standalone-exec models.
  - api.py then from-imports every public + private name back into its own
    globals, so the route tables keep resolving the names unchanged and the
    behavioural tests that call api.handle_proxmox_list see them.
  - Calls BETWEEN these functions ALSO go through ``A.`` (handle_proxmox_list
    reaches _refresh_snapshot_cache as A._refresh_snapshot_cache).

The pure protocol layer already lived in its own sibling — ``proxmox_client``,
imported by api.py and reached here as ``A.proxmox_client``. This module is
only the request-coupled half: auth, validation, audit, confirmations and the
snapshot cache.

Constants (CONFIG_FILE, PROXMOX_SNAPSHOT_CACHE) stay in api.py and are read
through A.

Carved at v6.4.3 because the inline-handler ratchet was sitting at its ceiling
with zero slack, so the next core-spine handler would have failed the build.
Proxmox was the cleanest remaining candidate: 13 functions referencing only 20
distinct api globals, none of them the notify/event core the ratchet exists to
protect.
"""
import hmac
import time
import urllib.parse


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


def handle_proxmox_status() -> None:
    """``GET /api/proxmox/status`` — is Proxmox configured / enabled?

    Cheap, no network call. The frontend uses this to decide whether
    to show the Virtualization nav entry and the LXC section.
    """
    A.require_auth()
    cfg = A.load(A.CONFIG_FILE)
    pc = A.proxmox_client.config_from(cfg)
    A.respond(200, {
        'enabled':    pc['enabled'],
        'configured': A.proxmox_client.is_configured(pc),
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
    A.require_admin_auth()
    cfg = A.load(A.CONFIG_FILE)
    pc = A.proxmox_client.config_from(cfg)
    body = A._read_valid(A.request_models.ProxmoxTestRequest)
    # Allow testing un-saved values straight from the form.
    for k in ('proxmox_host', 'proxmox_node', 'proxmox_token_id'):
        if body.get(k):
            pc[k.replace('proxmox_', '')] = str(body[k]).strip()
    if body.get('proxmox_token_secret'):
        pc['token_secret'] = str(body['proxmox_token_secret'])
    if 'proxmox_verify_tls' in body:
        pc['verify_tls'] = bool(body['proxmox_verify_tls'])
    # v4.8.0 (SSRF): the Test path accepts a fresh host straight from the form.
    # Preflight it exactly like the save path so it can't be turned into an
    # internal port-scan oracle (loopback / link-local / cloud-metadata).
    _host = str(pc.get('host') or '').strip()
    if _host and A._url_targets_local_or_meta(
            urllib.parse.urlparse('https://' + _host), allow_loopback=False):
        A.respond(400, {'error': 'Refusing to probe a loopback, link-local or metadata address.'})
    result = A.proxmox_client.test_connection(pc)
    A.respond(200, result)

def handle_proxmox_lifecycle() -> None:
    """POST /api/proxmox/lifecycle {guest_type, vmid, action, params?, dry?} —
    perform a VM/CT lifecycle action (start/stop/reboot/snapshot/clone/migrate).

    DESTRUCTIVE — gated three ways: admin-only, a per-deployment opt-in flag
    (proxmox_lifecycle_enabled, default off), and full audit of every call.
    `dry: true` returns the action that WOULD run without touching Proxmox, so
    operators can preview from the UI. When 4-eyes approval is on, the action is
    parked for a second admin instead of executing."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    cfg = A.load(A.CONFIG_FILE) or {}
    if not cfg.get('proxmox_enabled'):
        A.respond(400, {'error': 'Proxmox integration is not enabled.'})
    if not cfg.get('proxmox_lifecycle_enabled'):
        A.respond(403, {'error': 'Proxmox VM lifecycle actions are disabled. '
                               'Enable them in Settings → Proxmox first.'})
    body = A._read_valid(A.request_models.ProxmoxLifecycleRequest)
    guest_type = str(body.get('guest_type', '')).strip()
    action = str(body.get('action', '')).strip()
    vmid = body.get('vmid')
    params = body.get('params') if isinstance(body.get('params'), dict) else {}
    if guest_type not in ('qemu', 'lxc') or action not in A.proxmox_client.LIFECYCLE_ACTIONS:
        A.respond(400, {'error': 'invalid guest_type or action'})
    try:
        int(vmid)   # reject a non-numeric vmid BEFORE parking a 4-eyes confirmation
    except (TypeError, ValueError):
        A.respond(400, {'error': 'numeric vmid required'})
    label = f'{action} {guest_type}/{vmid}'
    if body.get('dry'):
        A.respond(200, {'ok': True, 'dry': True, 'planned': label})
    # 4-eyes: park destructive lifecycle actions for a second admin when enabled.
    if cfg.get('change_approval_enabled'):
        cid = A._create_confirmation('proxmox_lifecycle', str(vmid),
                                   {'guest_type': guest_type, 'action': action,
                                    'params': params, 'label': label}, actor, None, None)
        A.audit_log(actor, 'proxmox_lifecycle_parked', label)
        A.respond(202, {'ok': True, 'approval_required': True, 'confirmation_id': cid})
    pc = A.proxmox_client.config_from(cfg)
    try:
        _pc = {**pc, 'node': A.proxmox_client.find_guest_node(pc, vmid, guest_type)}
        upid = A.proxmox_client.lifecycle(_pc, guest_type, vmid, action, params)
    except A.proxmox_client.ProxmoxError as e:
        A.audit_log(actor, 'proxmox_lifecycle_failed', f'{label}: {e}')
        A.respond(502, {'error': str(e)})
    A.audit_log(actor, 'proxmox_lifecycle', label)
    A.respond(200, {'ok': True, 'task': upid, 'action': label})

def _refresh_snapshot_cache(pc: dict, guests: list, guest_type: str) -> None:
    """v2.7.0: Fetch snapshot lists for all guests and persist to
    PROXMOX_SNAPSHOT_CACHE so _compute_attention() can flag stale snapshots
    without making live Proxmox API calls on every attention request.

    This is called opportunistically when the Virtualization page loads —
    no separate cron needed.
    """
    now = int(time.time())
    cache = A.load(A.PROXMOX_SNAPSHOT_CACHE) if A.backend_exists(A.PROXMOX_SNAPSHOT_CACHE) else {}
    if not isinstance(cache, dict):
        cache = {}

    cfg     = A.load(A.CONFIG_FILE)
    warn_days = int(cfg.get('proxmox_snapshot_warn_days', 7))

    snapshot_recovers = []   # v6.3.0: VMs whose snapshot_old alert should clear
    for guest in guests:
        vmid = guest.get('vmid')
        if not vmid:
            continue
        key = f'{guest_type}_{vmid}'
        try:
            _pc = {**pc, 'node': guest.get('node') or pc['node']}
            snaps = A.proxmox_client.list_snapshots(_pc, guest_type, int(vmid))
        except Exception:
            snaps = []

        entry = cache.get(key, {})
        entry.update({
            'vmid':      vmid,
            'vm_name':   guest.get('name', str(vmid)),
            'guest_type': guest_type,
            'snapshots': snaps,
            'updated_at': now,
        })

        # Edge-trigger: fire snapshot_old webhook once per VM per crossing
        already_notified = entry.get('notified_at', 0)
        old_snaps = [s for s in snaps
                     if s.get('snaptime', 0)
                     and (now - s['snaptime']) > warn_days * 86400]
        if old_snaps and (now - already_notified) > 86400:
            # Fire webhook for the oldest snapshot
            oldest = min(old_snaps, key=lambda s: s.get('snaptime', 0))
            days_old = max(1, (now - oldest['snaptime']) // 86400)
            try:
                A.fire_webhook('snapshot_old', {
                    'vmid':      vmid,
                    'vm_name':   guest.get('name', str(vmid)),
                    'snap_name': oldest['name'],
                    'days_old':  days_old,
                    'warn_days': warn_days,
                })
                entry['notified_at'] = now
            except Exception:
                pass
        elif not old_snaps:
            was_notified = entry.pop('notified_at', None)   # reset so next crossing fires
            # v6.3.0: a guest that had an open snapshot_old alert now has no
            # stale snapshots → fire the recover event to auto-resolve it
            # (per-VM, matched by vmid). Only when it was actually notified.
            if was_notified:
                snapshot_recovers.append({
                    'vmid':    vmid,
                    'vm_name': guest.get('name', str(vmid)),
                })

        cache[key] = entry

    A.save(A.PROXMOX_SNAPSHOT_CACHE, cache)
    # Fire recover events AFTER the cache save (fire_webhook is self-locking).
    for _sp in snapshot_recovers:
        try:
            A.fire_webhook('snapshot_recovered', _sp)
        except Exception:
            pass

def handle_proxmox_list(guest_type: str) -> None:
    """``GET /api/proxmox/qemu`` or ``/api/proxmox/lxc`` — list guests."""
    A.require_auth()
    cfg = A.load(A.CONFIG_FILE)
    pc = A.proxmox_client.config_from(cfg)
    if not pc['enabled']:
        A.respond(200, {'enabled': False, 'guests': []})
    if not A.proxmox_client.is_configured(pc):
        A.respond(200, {'enabled': True, 'configured': False, 'guests': []})
    try:
        guests = A.proxmox_client.list_guests(pc, guest_type)
    except A.proxmox_client.ProxmoxError as e:
        A.respond(502, {'error': str(e)})
        return

    # v2.7.0: opportunistically refresh the snapshot age cache so
    # _compute_attention() has fresh data without a separate cron.
    try:
        A._refresh_snapshot_cache(pc, guests, guest_type)
    except Exception:
        pass
    # v3.6.0: refresh per-guest backup recency (only on the lxc pass to avoid
    # doing the double-guest-type fetch twice per page load).
    if guest_type == 'lxc':
        try:
            A._refresh_proxmox_backup_cache(pc)
        except Exception:
            pass

    # list_nodes is best-effort: the guests are already fetched, so a failure
    # here (e.g. a non-ProxmoxError escaping the client) must not 500 the page.
    try:
        _nodes = A.proxmox_client.list_nodes(pc)
    except Exception:
        _nodes = []
    A.respond(200, {'enabled': True, 'configured': True,
                  'node': pc['node'], 'guests': guests,
                  'nodes': _nodes,
                  'lifecycle': bool(A._config_ro().get('proxmox_lifecycle_enabled'))})

def handle_proxmox_action(guest_type: str, rest: str) -> None:
    """``POST /api/proxmox/{qemu,lxc}/<vmid>/<action>`` — guest action.

    Actions are gated by proxmox_client.ALLOWED_VM_ACTIONS. The UI
    only ever sends start / shutdown / status; `stop` (hard) is in
    the allow-list for a future force-stop but isn't exposed yet.
    """
    A.require_admin_auth()
    parts = [p for p in rest.split('/') if p]
    if len(parts) != 2:
        A.respond(400, {'error': 'Expected /<vmid>/<action>'})
        return
    vmid_str, action = parts
    try:
        vmid = int(vmid_str)
    except ValueError:
        A.respond(400, {'error': 'vmid must be numeric'})
        return
    cfg = A.load(A.CONFIG_FILE)
    pc = A.proxmox_client.config_from(cfg)
    if not (pc['enabled'] and A.proxmox_client.is_configured(pc)):
        A.respond(400, {'error': 'Proxmox is not configured.'})
        return
    try:
        _pc = {**pc, 'node': A.proxmox_client.find_guest_node(pc, vmid, guest_type)}
        result = A.proxmox_client.guest_action(_pc, guest_type, vmid, action)
    except A.proxmox_client.ProxmoxError as e:
        # Action-not-allowed and bad input map to 400; the message is
        # safe (never contains the token).
        code = 400 if 'not allowed' in str(e).lower() else 502
        A.respond(code, {'error': str(e)})
        return
    # Record a fleet event so the action shows in the activity log.
    try:
        A._record_fleet_event('proxmox_action', {
            'guest_type': guest_type, 'vmid': vmid, 'action': action,
        })
    except Exception:
        pass
    A.respond(200, result)

def handle_proxmox_lxc_create_options() -> None:
    """GET /api/proxmox/lxc/create-options — data the create wizard needs:
    next free vmid, root-disk-capable storages, OS templates, bridges."""
    A.require_admin_auth()
    cfg = A.load(A.CONFIG_FILE)
    pc = A.proxmox_client.config_from(cfg)
    if not (pc['enabled'] and A.proxmox_client.is_configured(pc)):
        A.respond(400, {'error': 'Proxmox is not configured.'})
        return
    try:
        storages = A.proxmox_client.list_storages(pc)
        out = {
            'node':      pc['node'],
            'next_vmid': A.proxmox_client.next_vmid(pc),
            'storages':  [s for s in storages if s['rootdir']],
            'templates': A.proxmox_client.list_templates(pc),
            'bridges':   A.proxmox_client.list_bridges(pc),
        }
    except A.proxmox_client.ProxmoxError as e:
        A.respond(502, {'error': str(e)})
        return
    A.respond(200, out)

def handle_proxmox_lxc_create() -> None:
    """POST /api/proxmox/lxc/create — create an LXC container.

    Admin-only, side-effecting (creates a real container on the Proxmox node).
    All fields are validated in proxmox_client.create_lxc. The root password,
    if supplied, is passed straight to Proxmox and never logged or stored."""
    actor = A.require_admin_auth()
    body = A._read_valid(A.request_models.ProxmoxLxcCreateRequest)
    cfg = A.load(A.CONFIG_FILE)
    pc = A.proxmox_client.config_from(cfg)
    if not (pc['enabled'] and A.proxmox_client.is_configured(pc)):
        A.respond(400, {'error': 'Proxmox is not configured.'})
        return
    try:
        result = A.proxmox_client.create_lxc(pc, body)
    except A.proxmox_client.ProxmoxError as e:
        msg = str(e)
        code = 502 if ('Proxmox API' in msg or 'reach Proxmox' in msg) else 400
        A.respond(code, {'error': msg})
        return
    # Audit WITHOUT the password / ssh key.
    A.audit_log(actor, 'proxmox_lxc_create',
              f"vmid={result.get('vmid')} hostname={body.get('hostname', '')!r} "
              f"template={body.get('ostemplate', '')!r} node={pc['node']}")
    try:
        A._record_fleet_event('proxmox_action', {
            'guest_type': 'lxc', 'vmid': result.get('vmid'), 'action': 'create',
        })
    except Exception:
        pass
    A.respond(200, result)

def handle_proxmox_qemu_create_options() -> None:
    """GET /api/proxmox/qemu/create-options — data the VM-create wizard needs:
    next free vmid, disk-capable storages, ISO images, bridges."""
    A.require_admin_auth()
    cfg = A.load(A.CONFIG_FILE)
    pc = A.proxmox_client.config_from(cfg)
    if not (pc['enabled'] and A.proxmox_client.is_configured(pc)):
        A.respond(400, {'error': 'Proxmox is not configured.'})
        return
    try:
        out = {
            'node':      pc['node'],
            'next_vmid': A.proxmox_client.next_vmid(pc),
            'storages':  [s for s in A.proxmox_client.list_storages(pc) if s['rootdir']],
            'isos':      A.proxmox_client.list_isos(pc),
            'bridges':   A.proxmox_client.list_bridges(pc),
        }
    except A.proxmox_client.ProxmoxError as e:
        A.respond(502, {'error': str(e)})
        return
    A.respond(200, out)

def handle_proxmox_qemu_create() -> None:
    """POST /api/proxmox/qemu/create — create a QEMU VM. Admin-only, audited."""
    actor = A.require_admin_auth()
    body = A._read_valid(A.request_models.ProxmoxQemuCreateRequest)
    cfg = A.load(A.CONFIG_FILE)
    pc = A.proxmox_client.config_from(cfg)
    if not (pc['enabled'] and A.proxmox_client.is_configured(pc)):
        A.respond(400, {'error': 'Proxmox is not configured.'})
        return
    try:
        result = A.proxmox_client.create_qemu(pc, body)
    except A.proxmox_client.ProxmoxError as e:
        msg = str(e)
        code = 502 if ('Proxmox API' in msg or 'reach Proxmox' in msg) else 400
        A.respond(code, {'error': msg})
        return
    A.audit_log(actor, 'proxmox_qemu_create',
              f"vmid={result.get('vmid')} name={body.get('name', '')!r} node={pc['node']}")
    try:
        A._record_fleet_event('proxmox_action', {
            'guest_type': 'qemu', 'vmid': result.get('vmid'), 'action': 'create',
        })
    except Exception:
        pass
    A.respond(200, result)

def handle_proxmox_lxc_delete(rest) -> None:
    """DELETE /api/proxmox/lxc/<vmid> — delete a container. Admin-only,
    destructive (auto-stops a running container, no purge), audited. The
    type-to-confirm guard lives in the UI; the server just gates on admin."""
    actor = A.require_admin_auth()
    parts = [p for p in rest.split('/') if p]
    if len(parts) != 1:
        A.respond(400, {'error': 'Expected /<vmid>'})
        return
    try:
        vmid = int(parts[0])
    except ValueError:
        A.respond(400, {'error': 'vmid must be numeric'})
        return
    cfg = A.load(A.CONFIG_FILE)
    pc = A.proxmox_client.config_from(cfg)
    if not (pc['enabled'] and A.proxmox_client.is_configured(pc)):
        A.respond(400, {'error': 'Proxmox is not configured.'})
        return
    try:
        result = A.proxmox_client.delete_lxc(pc, vmid, auto_stop=True)
    except A.proxmox_client.ProxmoxError as e:
        msg = str(e)
        code = 502 if ('Proxmox API' in msg or 'reach Proxmox' in msg) else 400
        A.respond(code, {'error': msg})
        return
    A.audit_log(actor, 'proxmox_lxc_delete',
              f"vmid={vmid} node={pc['node']} auto_stopped={result.get('stopped')}")
    try:
        A._record_fleet_event('proxmox_action', {
            'guest_type': 'lxc', 'vmid': vmid, 'action': 'delete',
        })
    except Exception:
        pass
    A.respond(200, result)

def handle_proxmox_snapshots_list() -> None:
    """``GET /api/proxmox/snapshots?type=qemu&vmid=100`` — list a
    guest's snapshots."""
    A.require_auth()
    qs = urllib.parse.parse_qs(A._env('QUERY_STRING', '') or '')
    guest_type = (qs.get('type') or [''])[0]
    vmid_str = (qs.get('vmid') or [''])[0]
    if guest_type not in ('qemu', 'lxc') or not vmid_str.isdigit():
        A.respond(400, {'error': 'type (qemu|lxc) and numeric vmid required'})
        return
    cfg = A.load(A.CONFIG_FILE)
    pc = A.proxmox_client.config_from(cfg)
    if not (pc['enabled'] and A.proxmox_client.is_configured(pc)):
        A.respond(400, {'error': 'Proxmox is not configured.'})
        return
    try:
        _vmid = int(vmid_str)
        _pc = {**pc, 'node': A.proxmox_client.find_guest_node(pc, _vmid, guest_type)}
        snaps = A.proxmox_client.list_snapshots(_pc, guest_type, _vmid)
    except A.proxmox_client.ProxmoxError as e:
        A.respond(502, {'error': str(e)})
        return
    A.respond(200, {'snapshots': snaps})

def handle_proxmox_snapshot_action() -> None:
    """``POST /api/proxmox/snapshot`` — create / rollback / delete a
    snapshot.

    Body: {"type": "qemu"|"lxc", "vmid": N, "action": "...",
           "name": "...", "description": "...", "confirm": "..." (rollback only)}

    `rollback` and `delete` are destructive. The UI additionally gates
    rollback behind a type-the-guest-name confirmation dialog; `confirm`
    is that typed value, and the server itself checks it against the
    guest's real name (via proxmox_client.guest_name) before rolling back
    — previously this check was UI-only, so a direct API call could roll
    back with no confirmation at all (docs/master-improvement-scoping-
    internal.md #77). The action set is validated here regardless.
    """
    A.require_admin_auth()
    body = A._read_valid(A.request_models.ProxmoxSnapshotActionRequest)
    guest_type = body.get('type')
    action = body.get('action')
    name = (body.get('name') or '').strip()
    if guest_type not in ('qemu', 'lxc'):
        A.respond(400, {'error': 'type must be qemu or lxc'})
        return
    try:
        vmid = int(body.get('vmid'))
    except (ValueError, TypeError):
        A.respond(400, {'error': 'numeric vmid required'})
        return
    if action not in ('create', 'rollback', 'delete'):
        A.respond(400, {'error': 'action must be create, rollback or delete'})
        return
    cfg = A.load(A.CONFIG_FILE)
    pc = A.proxmox_client.config_from(cfg)
    if not (pc['enabled'] and A.proxmox_client.is_configured(pc)):
        A.respond(400, {'error': 'Proxmox is not configured.'})
        return
    try:
        _pc = {**pc, 'node': A.proxmox_client.find_guest_node(pc, vmid, guest_type)}
        if action == 'rollback':
            confirm = str(body.get('confirm') or '').strip()
            real_name = A.proxmox_client.guest_name(_pc, guest_type, vmid)
            if not confirm or not hmac.compare_digest(confirm, real_name):
                A.respond(400, {'error': 'confirm must exactly match the guest name'})
                return
        if action == 'create':
            result = A.proxmox_client.create_snapshot(
                _pc, guest_type, vmid, name, body.get('description', '') or '')
        elif action == 'rollback':
            result = A.proxmox_client.rollback_snapshot(_pc, guest_type, vmid, name)
        else:
            result = A.proxmox_client.delete_snapshot(_pc, guest_type, vmid, name)
    except A.proxmox_client.ProxmoxError as e:
        code = 400 if 'invalid' in str(e).lower() else 502
        A.respond(code, {'error': str(e)})
        return
    try:
        A._record_fleet_event('proxmox_action', {
            'guest_type': guest_type, 'vmid': vmid,
            'action': f'snapshot_{action}',
        })
    except Exception:
        pass
    A.respond(200, result)

"""RemotePower — Docker Compose stacks + the curated App Catalog (one-click
deploy of popular self-hosted apps as compose stacks).

Compose: per-device stack CRUD (name/device/YAML), queued up/down/redeploy
through the audited command channel, and the device-token-authenticated
YAML-fetch the agent uses. App Catalog: a curated + admin-custom template list;
"deploy" instantiates a template as a compose stack and rides the exact same
audited, permission-gated, scope-checked compose path.

A bound-module carve-out following the dmarc/acme_handlers pattern: api.py execs
a PRIVATE instance, binds its own ``globals()`` here (every api service reached
as ``A.<name>`` — a dynamic lookup that keeps the suite's monkeypatching +
inspect.getsource assertions working), then re-imports the names — INCLUDING the
block-local constants (APP_CATALOG / _APP_CATALOG_BY_ID / _STACK_NAME_RE /
COMPOSE_YAML_MAX / _COMPOSE_ACTIONS), which tests read as api.<NAME> — back into
its own globals. The FILE constants (COMPOSE_STACKS_FILE / APP_CATALOG_CUSTOM_FILE
/ DEVICES_FILE) stay in api.py, read via A. The heartbeat caller of
_compose_status_from resolves it via the re-import.

SECURITY NOTE: the device-command handlers here (handle_app_catalog_deploy,
handle_compose_stack_action, and the create/delete/get siblings) take a device
id from the body and are NOT under /api/devices/, so `main()`'s device-scope
chokepoint does NOT cover them — each keeps its explicit `A._scope_block_device`
(and require_perm / require_admin_auth) gate. Those gates are load-bearing; do
not remove them. The scope-gate guardrail (test_body_device_scope_guard) scans
this module too (it auto-globs *_handlers.py, stripping the A. prefix).
"""
import os
import re
import time

_STACK_NAME_RE = re.compile(r'^[a-z0-9][a-z0-9_-]{0,63}$')
COMPOSE_YAML_MAX = 128 * 1024
_COMPOSE_ACTIONS = ('up', 'down', 'redeploy')

# v5.1.0: app catalog — one-click deploy of curated compose templates.
# A curated set of popular, self-contained homelab apps. "Deploy" instantiates
# the template as a compose STACK (reusing compose_stacks.json) and triggers the
# existing, audited compose_deploy path — so the agent fetches + runs the YAML
# exactly as for a hand-authored stack. No new agent code, no new privilege.
APP_CATALOG = (
    {'id': 'uptime-kuma', 'name': 'Uptime Kuma', 'category': 'Monitoring',
     'description': 'Self-hosted uptime monitor with a clean status dashboard.',
     'port': 3001,
     'yaml': ('services:\n  uptime-kuma:\n    image: louislam/uptime-kuma:1\n'
              '    container_name: uptime-kuma\n    restart: unless-stopped\n'
              '    ports:\n      - "3001:3001"\n    volumes:\n'
              '      - uptime-kuma:/app/data\nvolumes:\n  uptime-kuma:\n')},
    {'id': 'it-tools', 'name': 'IT-Tools', 'category': 'Utilities',
     'description': 'A handy collection of developer / sysadmin tools in one page.',
     'port': 8080,
     'yaml': ('services:\n  it-tools:\n    image: corentinth/it-tools:latest\n'
              '    container_name: it-tools\n    restart: unless-stopped\n'
              '    ports:\n      - "8080:80"\n')},
    {'id': 'dozzle', 'name': 'Dozzle', 'category': 'Monitoring',
     'description': 'Real-time Docker container log viewer in the browser.',
     'port': 8888,
     'yaml': ('services:\n  dozzle:\n    image: amir20/dozzle:latest\n'
              '    container_name: dozzle\n    restart: unless-stopped\n'
              '    ports:\n      - "8888:8080"\n    volumes:\n'
              '      - /var/run/docker.sock:/var/run/docker.sock:ro\n')},
    {'id': 'linkding', 'name': 'Linkding', 'category': 'Productivity',
     'description': 'Minimal self-hosted bookmark manager.',
     'port': 9090,
     'yaml': ('services:\n  linkding:\n    image: sissbruecker/linkding:latest\n'
              '    container_name: linkding\n    restart: unless-stopped\n'
              '    ports:\n      - "9090:9090"\n    volumes:\n'
              '      - linkding:/etc/linkding/data\nvolumes:\n  linkding:\n')},
    {'id': 'whoami', 'name': 'whoami', 'category': 'Utilities',
     'description': 'Tiny test service that echoes request info — handy to verify a deploy.',
     'port': 8088,
     'yaml': ('services:\n  whoami:\n    image: traefik/whoami:latest\n'
              '    container_name: whoami\n    restart: unless-stopped\n'
              '    ports:\n      - "8088:80"\n')},
)
_APP_CATALOG_BY_ID = {a['id']: a for a in APP_CATALOG}


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


def _compose_status_from(action, rc):
    if rc != 0:
        return 'error'
    return 'down' if action == 'down' else 'up'   # up / redeploy → up


def _custom_apps():
    """Admin-added catalog entries — stored as a dict {id: app}; returned as a list."""
    raw = A.load(A.APP_CATALOG_CUSTOM_FILE) or {}
    return [a for a in raw.values() if isinstance(a, dict) and a.get('id')]


def _app_catalog_all():
    """Curated apps + admin-added custom apps (custom ones flagged `custom:True`)."""
    apps = [dict(a) for a in APP_CATALOG]
    apps.extend({**a, 'custom': True} for a in A._custom_apps())
    return apps


def _app_by_id(app_id):
    tpl = _APP_CATALOG_BY_ID.get(app_id)
    if tpl:
        return dict(tpl)
    return next((dict(a) for a in A._custom_apps() if a.get('id') == app_id), None)


def handle_app_catalog():
    """GET /api/app-catalog — the curated + custom template list (incl. YAML for preview)."""
    A.require_auth()
    A.respond(200, {'apps': A._app_catalog_all()})


def handle_app_catalog_custom_add():
    """POST /api/app-catalog/custom — add a custom app to the catalog (admin only).
    Body {name, yaml, category?, description?, port?}. The compose YAML is stored as
    a template; deploying it still rides the audited, permission-gated compose path
    (so this only manages the shared catalog, it never runs anything). Idempotent on
    a slugified id derived from the name (re-adding updates the entry)."""
    actor = A.require_admin_auth()
    body = A._read_valid(A.request_models.AppCatalogCustomAddRequest)
    name = A._sanitize_str(body.get('name', ''), 64, allow_empty=False)
    yaml = body.get('yaml', '')
    if not isinstance(yaml, str) or 'services:' not in yaml:
        A.respond(400, {'error': 'compose YAML is required and must contain a "services:" block'})
    if len(yaml) > COMPOSE_YAML_MAX:
        A.respond(400, {'error': f'compose YAML is too large ({COMPOSE_YAML_MAX // 1024} KB max)'})
    category = A._sanitize_str(body.get('category', '') or 'Custom', 32, allow_empty=True) or 'Custom'
    description = A._sanitize_str(body.get('description', ''), 240, allow_empty=True) or ''
    try:
        port = int(body.get('port') or 0) or None
    except (TypeError, ValueError):
        port = None
    if port is not None and not (1 <= port <= 65535):
        A.respond(400, {'error': 'port must be 1–65535'})
    # slugify the name into a stable id; the id is reused as the compose stack
    # name, so it must satisfy _STACK_NAME_RE. Never collide with a curated id.
    slug = re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')[:48] or 'app'
    if slug in _APP_CATALOG_BY_ID:
        slug = 'custom-' + slug
    if not _STACK_NAME_RE.match(slug):
        A.respond(400, {'error': 'could not derive a valid id from that name'})
    entry = {'id': slug, 'name': name, 'category': category,
             'description': description, 'port': port, 'yaml': yaml}
    with A._LockedUpdate(A.APP_CATALOG_CUSTOM_FILE) as apps:
        apps[slug] = entry
    A.audit_log(actor, 'app_catalog_custom_add', f'{slug} ({name})')
    A.respond(200, {'ok': True, 'id': slug})


def handle_app_catalog_custom_delete():
    """POST /api/app-catalog/custom/delete {id} — remove a custom app (admin only).
    Curated apps cannot be removed."""
    actor = A.require_admin_auth()
    body = A._read_valid(A.request_models.AppCatalogCustomDeleteRequest)
    app_id = A._sanitize_str(A.get_json_obj().get('id', ''), 64, allow_empty=False)
    if app_id in _APP_CATALOG_BY_ID:
        A.respond(400, {'error': 'built-in catalog apps cannot be removed'})
    with A._LockedUpdate(A.APP_CATALOG_CUSTOM_FILE) as apps:
        if app_id not in apps:
            A.respond(404, {'error': 'unknown custom app'})
        del apps[app_id]
    A.audit_log(actor, 'app_catalog_custom_delete', app_id)
    A.respond(200, {'ok': True})


def handle_app_catalog_deploy():
    """POST /api/app-catalog/deploy {device_id, app_id} — instantiate a catalog
    template as a compose stack and queue its deploy. Idempotent: redeploys an
    existing same-named stack on that device. Gated on `containers`, scope- and
    compose_enabled-checked, audited; the deploy itself rides the proven
    compose_deploy command path."""
    actor = A.require_perm('containers')
    body = A._read_valid(A.request_models.AppCatalogDeployRequest)
    app_id = A._sanitize_str(body.get('app_id', ''), 64)
    device_id = A._sanitize_str(body.get('device_id', ''), 64, allow_empty=False)
    tpl = A._app_by_id(app_id)
    if not tpl:
        A.respond(404, {'error': 'unknown app'})
    devices = A.load(A.DEVICES_FILE)
    if device_id not in devices:
        A.respond(404, {'error': 'device not found'})
    A._scope_block_device(device_id)
    if not devices[device_id].get('compose_enabled', False):
        A.respond(403, {'error': 'compose deploys are disabled on this device — enable them first'})
    name, yaml = tpl['id'], tpl['yaml']
    with A._LockedUpdate(A.COMPOSE_STACKS_FILE) as stacks:
        existing = next((sid for sid, st in stacks.items()
                         if st.get('device_id') == device_id and st.get('name') == name), None)
        if existing:
            stack_id, action = existing, 'redeploy'
            stacks[stack_id].update({'yaml': yaml, 'status': 'deploying',
                                     'last_action': action, 'last_action_ts': int(time.time())})
        else:
            stack_id, action = 's-' + os.urandom(6).hex(), 'up'
            stacks[stack_id] = {
                'name': name, 'device_id': device_id, 'yaml': yaml, 'app_id': app_id,
                'status': 'deploying', 'created_by': actor, 'created_ts': int(time.time()),
                'last_action': action, 'last_action_ts': int(time.time()),
                'last_rc': None, 'last_output': '',
            }
    A.audit_log(actor, 'app_catalog_deploy', f'{app_id} dev={device_id} ({action})')
    A._queue_command_batch([device_id], f'compose_deploy:{action}:{stack_id}', actor)
    A.respond(200, {'ok': True, 'id': stack_id, 'action': action})


def handle_compose_stacks_list():
    """GET /api/compose/stacks — list stacks (metadata only, no YAML)."""
    A.require_auth()
    stacks = A.load(A.COMPOSE_STACKS_FILE) or {}
    devs = A.load(A.DEVICES_FILE) or {}
    # v6.2.2: confine to the caller's visible devices (role scope AND tenant).
    # This handler had no filter at all, so any authenticated user — including a
    # tenant admin or a scoped role — saw every tenant's stacks. Mirror the
    # sibling handle_compose_stack_action, which scope-blocks its device.
    _visible = A._scope_filter_devices(devs)
    items = []
    for sid, s in stacks.items():
        if s.get('device_id') not in _visible:
            continue
        dev = devs.get(s.get('device_id')) or {}
        items.append({
            'id':              sid,
            'name':            s.get('name', ''),
            'device_id':       s.get('device_id', ''),
            'device_name':     dev.get('name') or s.get('device_id', ''),
            'compose_enabled': bool(dev.get('compose_enabled', False)),
            'status':          s.get('status', 'created'),
            'last_action':     s.get('last_action', ''),
            'last_action_ts':  int(s.get('last_action_ts', 0)),
            'last_rc':         s.get('last_rc'),
            'created_by':      s.get('created_by', ''),
            'created_ts':      int(s.get('created_ts', 0)),
        })
    items.sort(key=lambda x: (x['device_name'], x['name']))
    A.respond(200, {'stacks': items})


def handle_compose_stack_get(stack_id):
    """GET /api/compose/stacks/<id> — full stack incl. YAML + last output."""
    A.require_admin_auth()
    s = (A.load(A.COMPOSE_STACKS_FILE) or {}).get(stack_id)
    if not s:
        A.respond(404, {'error': 'stack not found'})
    # v6.2.2: require_admin_auth early-returns for a tenant admin — block a
    # cross-tenant read of the full compose YAML (which can carry secrets).
    A._scope_block_device(s.get('device_id') or '')
    out = dict(s)
    out['id'] = stack_id
    A.respond(200, out)


def handle_compose_stack_create():
    """POST /api/compose/stacks — create a stack {name, device_id, yaml}."""
    actor = A.require_admin_auth()
    body = A._read_valid(A.request_models.ComposeStackCreateRequest)
    name = A._sanitize_str(body.get('name', ''), 64).lower()
    device_id = A._sanitize_str(body.get('device_id', ''), 64, allow_empty=False)
    yaml = body.get('yaml', '')
    if not _STACK_NAME_RE.match(name or ''):
        A.respond(400, {'error': 'name must be lowercase [a-z0-9_-], up to 64 chars'})
    if not isinstance(yaml, str) or not yaml.strip():
        A.respond(400, {'error': 'compose yaml required'})
    if len(yaml) > COMPOSE_YAML_MAX:
        A.respond(400, {'error': f'compose file too large (>{COMPOSE_YAML_MAX} bytes)'})
    if 'services:' not in yaml:
        A.respond(400, {'error': 'does not look like a compose file (no "services:" key)'})
    # v6.2.2: block a tenant admin from creating a stack on another tenant's
    # host (require_admin_auth early-returns for admin, so this is the only gate).
    A._scope_block_device(device_id)
    devices = A.load(A.DEVICES_FILE)
    if device_id not in devices:
        A.respond(404, {'error': 'device not found'})
    stacks = A.load(A.COMPOSE_STACKS_FILE) or {}
    for s in stacks.values():
        if s.get('device_id') == device_id and s.get('name') == name:
            A.respond(409, {'error': f'a stack named "{name}" already exists on this device'})
    stack_id = 's-' + os.urandom(6).hex()
    stacks[stack_id] = {
        'name': name, 'device_id': device_id, 'yaml': yaml,
        'status': 'created', 'created_by': actor, 'created_ts': int(time.time()),
        'last_action': '', 'last_action_ts': 0, 'last_rc': None, 'last_output': '',
    }
    A.save(A.COMPOSE_STACKS_FILE, stacks)
    A.audit_log(actor, 'compose_stack_create', f'{name} dev={device_id}')
    A.respond(200, {'ok': True, 'id': stack_id})


def handle_compose_stack_delete(stack_id):
    """DELETE /api/compose/stacks/<id> — drop the stored definition (admin).

    Does NOT tear down running containers — run "down" first if you want
    that. We only forget the stack."""
    actor = A.require_admin_auth()
    stacks = A.load(A.COMPOSE_STACKS_FILE) or {}
    if stack_id in stacks:
        # v6.2.2: block a tenant admin from deleting another tenant's stack.
        A._scope_block_device(stacks[stack_id].get('device_id') or '')
        name = stacks[stack_id].get('name', '')
        del stacks[stack_id]
        A.save(A.COMPOSE_STACKS_FILE, stacks)
        A.audit_log(actor, 'compose_stack_delete', f'{name} ({stack_id})')
    A.respond(200, {'ok': True})


def handle_compose_stack_action(stack_id):
    """POST /api/compose/stacks/<id>/action {action} — queue up/down/redeploy."""
    actor = A.require_perm('containers')   # v3.12.0 RBAC: was admin-only
    body = A._read_valid(A.request_models.ComposeStackActionRequest)
    action = A._sanitize_str(body.get('action', ''), 16).lower()
    if action not in _COMPOSE_ACTIONS:
        A.respond(400, {'error': f'action must be one of {_COMPOSE_ACTIONS}'})
    stacks = A.load(A.COMPOSE_STACKS_FILE) or {}
    s = stacks.get(stack_id)
    if not s:
        A.respond(404, {'error': 'stack not found'})
    device_id = s.get('device_id')
    A._scope_block_device(device_id)       # a scoped role can't act on a foreign device's stack
    dev = A.device_get(device_id)
    if not dev:
        A.respond(404, {'error': 'target device not found'})
    if not dev.get('compose_enabled', False):
        A.respond(403, {'error': 'compose deploys are disabled on this device — enable them first'})
    s['status'] = 'deploying'
    s['last_action'] = action
    s['last_action_ts'] = int(time.time())
    A.save(A.COMPOSE_STACKS_FILE, stacks)
    # _queue_command_batch queues without responding (unlike _queue_command);
    # the agent fetches the YAML itself via /api/compose/fetch.
    A._queue_command_batch([device_id], f'compose_deploy:{action}:{stack_id}', actor)
    A.audit_log(actor, 'compose_stack_action', f'{action} {s.get("name")} dev={device_id}')
    A.respond(200, {'ok': True, 'queued': action})


def handle_compose_fetch():
    """POST /api/compose/fetch {device_id, token, stack_id} — agent fetches a
    stack's YAML with its device token. Kept off the command queue so the
    compose file never lands in the command log."""
    body = A._read_valid(A.request_models.ComposeFetchRequest)
    device_id = str(body.get('device_id', '')).strip()
    token = str(body.get('token', '')).strip()
    stack_id = str(body.get('stack_id', '')).strip()
    dev = A.device_get(device_id)
    if not dev or not A._device_token_ok(dev, token):
        A.respond(403, {'error': 'Unauthorized device'})
    s = (A.load(A.COMPOSE_STACKS_FILE) or {}).get(stack_id)
    if not s or s.get('device_id') != device_id:
        A.respond(404, {'error': 'stack not found for this device'})
    A.respond(200, {'ok': True, 'name': s.get('name', ''), 'yaml': s.get('yaml', '')})

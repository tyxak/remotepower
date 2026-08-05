"""RemotePower — fleet-wide bulk device edit, group taxonomy ops, per-package patch approval, log-buffer retention + export (v6.4.2)

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

WHAT LIVES HERE
  1. Bulk device ATTRIBUTE edit (``POST /api/devices/bulk-attrs``) — the
     missing third sibling of bulk-delete / bulk-tags: set group / site /
     tags / monitored / … across many devices in ONE atomic call.
  2. Fleet-wide GROUP taxonomy (``GET /api/taxonomy`` +
     ``POST /api/taxonomy/groups/{rename,merge,delete}``). Before this the only
     primitive was ``PATCH /api/devices/<id>/group`` — one device per request,
     so a client-side rename loop could half-apply and leave a group split in
     two. These are ONE ``_LockedUpdate(DEVICES_FILE)`` read-modify-write.
  3. Per-package PATCH APPROVAL (``/api/patch-approvals``) — an operator
     approve/decline list over the fleet-wide patch catalog, CONSUMED by
     ``_autopatch_queue`` (declined packages are pinned on the host before the
     upgrade runs, approved ones un-pinned) so it is not decorative.
  4. The ingested log-line ring's retention, made operator-tunable
     (``log_buffer_retention_hours`` / ``log_buffer_max_bytes_per_unit``, both
     read here and consumed by api.py's four ingest/read sites), plus
     ``GET /api/logs/export`` — there was no export of log lines at all.

SECURITY NOTE THAT APPLIES TO EVERY HANDLER IN THIS FILE. All of these take
their device set from the request BODY or query string, so ``main()``'s
pre-dispatch ``_enforce_device_scope()`` (which only covers
``/api/devices/<id>/…``) does NOT cover them. A tenant admin resolves to
``_caller_scope() is None``, so a gate shaped ``if scope is not None: …`` waves
them straight through. Every handler here therefore resolves its device set
from ``A._scope_filter_devices(A.load(A.DEVICES_FILE) or {})`` (role scope AND
tenant, even for a scope=None admin) or ``A._scope_block_device(id)``, and
never from the raw store. The group handlers are the subtle case: they are
keyed on a NAME, not a device id, so the AST guardrail in
tests/test_body_device_scope_guard.py would not have flagged them.
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


# ── shared helpers ───────────────────────────────────────────────────────────


def _visible_devices():
    """The device dict this caller may see — role scope AND tenant, including
    for a scope=None tenant admin. THE read for every handler in this module;
    never reach for a raw ``load(DEVICES_FILE)``."""
    return A._scope_filter_devices(A.load(A.DEVICES_FILE) or {})


def _require_instance_wide_policy_writer():
    """Gate for a setting that is INSTANCE-wide, not tenant-scoped.

    The patch-approval store is keyed by package name with no tenant dimension,
    and `_autopatch_pin_prefix()` folds it into the command queued for EVERY
    tenant's Linux hosts. A tenant admin has `role == 'admin'`, so
    `require_write_role` admits them and `_caller_scope()` is None — meaning
    without this, one tenant's admin declining `openssl` would pin it across the
    whole instance, and approving it would un-pin it for everyone else.

    Same shape, and the same fix, as `handle_config_save`'s `sso_group_roles`
    branch (api.py). A no-op on the common single-tenant install, where every
    admin resolves to the default tenant — this only bites multi-tenant ones.

    Reads are deliberately NOT gated: seeing the policy that governs your own
    hosts is legitimate. Only the writes are."""
    if A._tenancy_enforced() and not A._caller_is_superadmin():
        A.respond(403, {'error': 'Patch approvals are an instance-wide policy '
                                 "affecting every tenant's auto-patch — only a "
                                 'platform superadmin can change them'})


def _clean_tags(raw):
    out = [A.re.sub(r'[^a-zA-Z0-9_\-/]', '', str(t))[:A.MAX_TAG_LEN]
           for t in (raw or [])[:A.MAX_TAG_COUNT]]
    return [t for t in out if t]


def _clean_group(raw):
    """The SAME sanitiser handle_device_group / handle_device_save_bulk apply:
    alphanumeric + - _ / , capped at MAX_GROUP_LEN. Returns '' for anything
    that sanitises away, which the callers treat as "no group"."""
    txt = A._sanitize_str(str(raw or ''), A.MAX_GROUP_LEN)
    return A.re.sub(r'[^a-zA-Z0-9_\-/]', '', txt)[:A.MAX_GROUP_LEN]


# ── 1. bulk device writes (moved here from api.py — see the ratchet note) ────
# handle_devices_bulk_delete / handle_devices_bulk_tags were inline in api.py
# since v5.0.0; they moved into this module with their new sibling
# handle_devices_bulk_attrs so the three bulk-write endpoints live together and
# the api.py inline-handler ratchet drops 627 → 625.


def handle_devices_bulk_delete():
    """v5.0.0 (#F1): ``POST /api/devices/bulk-delete`` {device_ids:[...]} — delete
    many devices in one action (e.g. everything matching a tag, selected in the
    UI). Admin only; audit-logged with the count."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A._read_valid(A.request_models.DevicesBulkDeleteRequest)
    ids = body.get('device_ids') or []
    if not isinstance(ids, list) or not ids:
        A.respond(400, {'error': 'device_ids must be a non-empty list'})
    ids = [str(i) for i in ids if A._validate_id(str(i))][:1000]
    # SEC: body-supplied id list, not under /api/devices/ — a tenant admin must
    # not delete another tenant's devices. Keep only ids the caller can see
    # (no-op for an unscoped single-tenant admin).
    _vis = A._scope_filter_devices(A.load(A.DEVICES_FILE) or {})
    ids = [i for i in ids if i in _vis]
    deleted = 0
    for dev_id in ids:
        try:
            if A._purge_device(dev_id):
                deleted += 1
        # nosec B110: by design and unchanged since v5.0.0 — one device failing
        # to purge must not abort the rest of the batch; the count in the
        # response and the audit row report exactly how many actually went.
        except Exception:  # nosec B110
            pass
    A.audit_log(actor, 'devices_bulk_delete', detail=f'deleted={deleted}/{len(ids)}')
    A.respond(200, {'ok': True, 'deleted': deleted, 'requested': len(ids)})


def handle_devices_bulk_tags():
    """v5.0.0 (#F2): ``POST /api/devices/bulk-tags`` — add and/or remove tags on
    many devices at once. Body: {device_ids:[...], add:[...], remove:[...]}.
    Add/remove are set-merged onto each device's existing tags (idempotent)."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A._read_valid(A.request_models.DevicesBulkTagsRequest)
    ids = body.get('device_ids') or []
    if not isinstance(ids, list) or not ids:
        A.respond(400, {'error': 'device_ids must be a non-empty list'})
    add = A._clean_tags(body.get('add'))
    remove = set(A._clean_tags(body.get('remove')))
    if not add and not remove:
        A.respond(400, {'error': 'pass at least one tag in add or remove'})
    ids = {str(i) for i in ids if A._validate_id(str(i))}
    _vis = A._scope_filter_devices(A.load(A.DEVICES_FILE) or {})   # SEC: tenant/scope filter
    ids = {i for i in ids if i in _vis}
    updated = 0
    with A._LockedUpdate(A.DEVICES_FILE) as devices:
        for dev_id in ids:
            dev = devices.get(dev_id)
            if not dev:
                continue
            cur = [t for t in (dev.get('tags') or []) if t not in remove]
            for t in add:
                if t not in cur:
                    cur.append(t)
            dev['tags'] = cur[:A.MAX_TAG_COUNT]
            updated += 1
    A.audit_log(actor, 'devices_bulk_tags',
                detail=f'updated={updated} add={",".join(add)[:80]} remove={",".join(remove)[:80]}')
    A.respond(200, {'ok': True, 'updated': updated})


# The attribute fields a bulk edit may set, in the order they are applied.
# Deliberately a SUBSET of handle_device_save_bulk's bundle: the per-device
# bundle also carries per-host wiring (log_watch rules, watched files, SSH
# creds, cmd allowlists, tenant moves) that makes no sense to stamp identically
# across a whole selection.
_BULK_ATTR_FIELDS = ('group', 'site', 'tags', 'tags_add', 'tags_remove',
                     'monitored', 'decommissioned', 'icon', 'poll_interval',
                     'notes', 'update_channel', 'offline_alert_delay_min',
                     'reachability')


def handle_devices_bulk_attrs():
    """v6.4.2: ``POST /api/devices/bulk-attrs`` — set device ATTRIBUTES across
    many devices in one atomic call.

    Body: ``{device_ids:[...], <field>: <value>, ...}`` where <field> is any of
    _BULK_ATTR_FIELDS. Contract matches handle_device_save_bulk's, per field:
    **a key that is absent is not touched; an empty list/string is an explicit
    clear.** Sanitisers are the same ones the per-device handlers use, so a bulk
    edit can never write a value a single-device edit would have rejected.

    Why this exists: bulk-delete and bulk-tags shipped in v5.0.0, but setting a
    group / site / monitored flag across a selection still meant one PATCH per
    device from the client — N requests that can half-apply, with no audit row
    tying them together. This is one read-modify-write under one lock.

    SEC: body-supplied device ids. See the module docstring."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A._read_valid(A.request_models.DevicesBulkAttrsRequest)
    ids = body.get('device_ids') or []
    if not isinstance(ids, list) or not ids:
        A.respond(400, {'error': 'device_ids must be a non-empty list'})
    # Cap matches bulk-delete's 1000, NOT _resolve_targets' 100 — a 500-host
    # selection silently truncated to 100 while reporting success is exactly
    # the class of bug this endpoint exists to remove.
    ids = [str(i) for i in ids if A._validate_id(str(i))][:1000]
    _vis = A._scope_filter_devices(A.load(A.DEVICES_FILE) or {})   # SEC: tenant/scope filter
    ids = [i for i in ids if i in _vis]

    touched = [f for f in _BULK_ATTR_FIELDS if f in body]
    if not touched:
        A.respond(400, {'error': 'no editable field in body; one of: '
                                 + ', '.join(_BULK_ATTR_FIELDS)})

    # Build the update set ONCE (it is identical for every device), so a
    # validation 400 happens before we take the write lock rather than halfway
    # through the fleet.
    updates = {}
    tags_add = tags_remove = None
    if 'group' in body:
        updates['group'] = A._clean_group(body.get('group'))
    if 'site' in body:
        site_id = str(body.get('site') or '').strip()[:64]
        if site_id and site_id not in (A.load(A.SITES_FILE) or {}):
            A.respond(400, {'error': 'unknown site'})
        updates['site'] = site_id
    if 'tags' in body:
        raw_tags = body.get('tags') or []
        if not isinstance(raw_tags, list):
            A.respond(400, {'error': 'tags must be a list'})
        updates['tags'] = A._clean_tags(raw_tags)
    if 'tags_add' in body or 'tags_remove' in body:
        tags_add = A._clean_tags(body.get('tags_add'))
        tags_remove = set(A._clean_tags(body.get('tags_remove')))
    if 'monitored' in body:
        updates['monitored'] = bool(body.get('monitored'))
    if 'decommissioned' in body:
        dc = bool(body.get('decommissioned'))
        updates['decommissioned'] = dc
        # Same rule as handle_device_save_bulk: a decommissioned host is never
        # monitored, and un-decommissioning restores monitoring. Set AFTER any
        # explicit `monitored` above so decommission wins.
        updates['monitored'] = False if dc else True
    if 'icon' in body:
        updates['icon'] = A._sanitize_str(body.get('icon') or '', A.MAX_NAME_LEN)
    if 'notes' in body:
        updates['notes'] = A._sanitize_str(str(body.get('notes') or ''), A.MAX_NOTES_LEN)
    if 'update_channel' in body:
        ch = A._sanitize_str(body.get('update_channel') or '', 16).lower()
        updates['update_channel'] = ch if ch in ('stable', 'beta') else 'stable'
    if 'reachability' in body:
        rm = A._sanitize_str(body.get('reachability') or '', 16).lower()
        updates['reachability'] = rm if rm in ('icmp', 'manual', 'ssh') else 'icmp'
    if 'poll_interval' in body:
        try:
            pi_val = int(body.get('poll_interval'))
        except (TypeError, ValueError):
            A.respond(400, {'error': 'poll_interval must be an integer'})
        if pi_val < 30 or pi_val > 3600:
            A.respond(400, {'error': 'poll_interval must be 30..3600 seconds'})
        updates['poll_interval'] = pi_val
    if 'offline_alert_delay_min' in body:
        try:
            _ad = int(body.get('offline_alert_delay_min') or 0)
        except (TypeError, ValueError):
            _ad = 0
        updates['offline_alert_delay_min'] = max(0, min(1440, _ad))

    updated = 0
    with A._LockedUpdate(A.DEVICES_FILE) as devices:
        for dev_id in ids:
            dev = devices.get(dev_id)
            if not isinstance(dev, dict):
                continue
            dev.update(updates)
            if tags_add is not None or tags_remove is not None:
                cur = [t for t in (dev.get('tags') or [])
                       if t not in (tags_remove or set())]
                for t in (tags_add or []):
                    if t not in cur:
                        cur.append(t)
                dev['tags'] = cur[:A.MAX_TAG_COUNT]
            updated += 1
    A.audit_log(actor, 'devices_bulk_attrs',
                detail=f'updated={updated}/{len(ids)} fields={",".join(touched)[:120]}')
    A.respond(200, {'ok': True, 'updated': updated, 'requested': len(ids),
                    'fields': touched})


# ── 2. taxonomy: fleet-wide tag/group inventory + group rename/merge/delete ──
# Stores that can NAME a group and are NOT rewritten by a rename/merge/delete.
# Reported back as `orphan_references` so the operator is told the truth
# instead of discovering it when an alert stops routing. Deliberately a
# report, not a rewrite: a group is the primary selector for role scopes,
# auto-patch targets, rollout rings and smart groups, and silently rewriting
# an RBAC scope from a device-taxonomy screen is a worse failure than a
# stale reference the operator was told about.
_GROUP_REF_STORES = (
    ('roles',              'ROLES_FILE'),
    ('autopatch_policies', 'AUTOPATCH_FILE'),
    ('rollouts',           'ROLLOUTS_FILE'),
    ('smart_groups',       'SMART_GROUPS_FILE'),
    ('config',             'CONFIG_FILE'),
)


def _count_group_refs(node, names, depth=0):
    """Recursively count references to any group in `names` inside a loaded
    store. Matches the two shapes group selectors take across the codebase:
    a typed selector (``{'type':'group'|'groups', 'value'/'values': …}`` — role
    scopes, auto-patch targets, rollout ring selectors) and a plain
    ``group``/``groups`` key (notification-channel filters, saved views)."""
    if depth > 12:
        return 0
    n = 0
    if isinstance(node, dict):
        if str(node.get('type') or '') in ('group', 'groups'):
            if str(node.get('value') or '') in names:
                n += 1
            vals = node.get('values')
            if isinstance(vals, list):
                n += sum(1 for v in vals if str(v) in names)
        for key in ('group', 'groups'):
            v = node.get(key)
            if isinstance(v, str) and v in names:
                n += 1
            elif isinstance(v, list):
                n += sum(1 for x in v if str(x) in names)
        for v in node.values():
            if isinstance(v, (dict, list)):
                n += _count_group_refs(v, names, depth + 1)
    elif isinstance(node, list):
        for v in node[:2000]:
            if isinstance(v, (dict, list)):
                n += _count_group_refs(v, names, depth + 1)
    return n


def _group_reference_report(names):
    """[{'store': label, 'references': n}, …] for the stores that still name any
    of `names` after the device records have been rewritten. Read-only."""
    out = []
    wanted = {str(x) for x in names if str(x)}
    if not wanted:
        return out
    for label, attr in _GROUP_REF_STORES:
        try:
            data = A.load(getattr(A, attr))
        # nosec B112: this is an advisory REPORT bolted onto a device write that
        # has already succeeded. A corrupt or unreadable side store must cost
        # the operator one line of the warning, never the whole rename.
        except Exception:  # nosec B112
            continue
        n = A._count_group_refs(data, wanted)
        if n:
            out.append({'store': label, 'references': n})
    return out


def handle_taxonomy_list():
    """``GET /api/taxonomy`` — the fleet's tag / group / site inventory with
    device counts, scope- and tenant-filtered.

    The Taxonomy page derived these client-side from ``GET /devices``; that
    works for the UI but leaves API clients (and anything that wants counts
    without pulling the whole fleet payload) with nothing. Read-only."""
    A.require_auth()
    if A.method() != 'GET':
        A.respond(405, {'error': 'Method not allowed'})
    devices = A._visible_devices()
    tags, groups, sites = {}, {}, {}
    ungrouped = untagged = 0
    for dev in devices.values():
        if not isinstance(dev, dict):
            continue
        g = dev.get('group') or ''
        if g:
            groups[g] = groups.get(g, 0) + 1
        else:
            ungrouped += 1
        s = dev.get('site') or ''
        if s:
            sites[s] = sites.get(s, 0) + 1
        dts = [t for t in (dev.get('tags') or []) if t]
        if dts:
            for t in dts:
                tags[t] = tags.get(t, 0) + 1
        else:
            untagged += 1

    def _rows(d):
        return [{'name': k, 'device_count': v}
                for k, v in sorted(d.items(), key=lambda kv: (-kv[1], kv[0].lower()))]

    A.respond(200, {
        'tags':      _rows(tags),
        'groups':    _rows(groups),
        'sites':     _rows(sites),
        'ungrouped': ungrouped,
        'untagged':  untagged,
        'devices':   len(devices),
    })


def _taxonomy_group_apply(op):
    """Shared core for group rename / merge / delete.

    ONE ``_LockedUpdate(DEVICES_FILE)`` read-modify-write over the whole
    affected set — the point of the endpoint. A client-side loop of
    ``PATCH /api/devices/<id>/group`` can fail halfway and leave a group split
    across two names with no way to tell which half moved; here the context
    manager either commits every device or (on any exception) commits none.

    SEC: the affected set is resolved from the SCOPE-FILTERED device dict, so a
    tenant admin renaming "prod" only touches their own tenant's "prod" —
    another tenant's identically-named group is invisible and untouched. The
    handler is keyed on a NAME, not a device id, so tests/test_body_device_
    scope_guard.py's AST scan would not have caught a missing gate here."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A._read_valid(A.request_models.TaxonomyGroupOpRequest)

    raw_from = body.get('from')
    if op == 'delete' and raw_from in (None, '', []):
        raw_from = body.get('group')
    if isinstance(raw_from, str):
        raw_from = [raw_from]
    if not isinstance(raw_from, list):
        raw_from = []
    sources = []
    for x in raw_from[:50]:
        g = A._clean_group(x)
        if g and g not in sources:
            sources.append(g)
    dest = '' if op == 'delete' else A._clean_group(body.get('to'))

    if not sources:
        A.respond(400, {'error': 'from must name at least one group'})
    if op != 'delete' and not dest:
        A.respond(400, {'error': 'to must be a non-empty group name'})
    if op == 'rename' and len(sources) != 1:
        A.respond(400, {'error': 'rename takes exactly one source group '
                                 '(use merge for many)'})
    if op != 'delete' and dest in sources and len(sources) == 1:
        A.respond(400, {'error': 'from and to are the same group'})

    src_set = set(sources)
    devices_ro = A._visible_devices()      # SEC: role scope AND tenant
    ids = [did for did, dev in devices_ro.items()
           if isinstance(dev, dict) and (dev.get('group') or '') in src_set]
    if not ids:
        # 404 rather than 200/updated=0: for a caller who cannot see the group
        # this is indistinguishable from "no such group", which is exactly the
        # non-disclosure we want (never confirm another tenant's group exists).
        A.respond(404, {'error': 'no devices in that group'})

    # Read-only scan of the OTHER stores that can name the old group. Done
    # BEFORE the lock: those loads are plain reads, but keeping every non-device
    # store access outside the DEVICES lock is the house rule (a self-locking
    # helper nested inside _LockedUpdate is an OperationalError on SQLite/PG).
    orphans = A._group_reference_report(sources)

    updated = 0
    with A._LockedUpdate(A.DEVICES_FILE) as devices:
        for dev_id in ids:
            dev = devices.get(dev_id)
            if not isinstance(dev, dict):
                continue
            if (dev.get('group') or '') not in src_set:
                continue          # changed under us between the read and the lock
            dev['group'] = dest
            updated += 1
    A.audit_log(actor, f'taxonomy_group_{op}',
                detail=f'from={",".join(sources)[:100]} to={dest or "(none)"} '
                       f'devices={updated}')
    A.respond(200, {'ok': True, 'op': op, 'from': sources, 'to': dest,
                    'updated': updated, 'orphan_references': orphans})


def handle_taxonomy_group_rename():
    """``POST /api/taxonomy/groups/rename`` {from, to} — move every device in
    one group to a new group name, atomically. Admin."""
    A._taxonomy_group_apply('rename')


def handle_taxonomy_group_merge():
    """``POST /api/taxonomy/groups/merge`` {from:[...], to} — fold several
    groups into one, atomically. Admin."""
    A._taxonomy_group_apply('merge')


def handle_taxonomy_group_delete():
    """``POST /api/taxonomy/groups/delete`` {group} — clear the group on every
    device that carries it (the devices survive; only the label goes). Admin."""
    A._taxonomy_group_apply('delete')


# ── 3. per-package patch approval ────────────────────────────────────────────
# The fleet-wide patch catalog (GET /api/patch-catalog) already aggregates
# pending updates BY PACKAGE, and hold/unhold already pins a package on the
# host. What was missing is the operator's DECISION recorded between them: an
# approve/decline list that auto-patch actually honours. Package-scoped and
# fleet-wide by design — the catalog aggregates by package, and "we do not want
# this update anywhere" is the decision operators actually make.

_APPROVAL_STATES = ('approved', 'declined')


def _patch_approvals():
    """The raw {package: {state, actor, ts, note}} map. Never raises."""
    data = A.load(A.PATCH_APPROVALS_FILE)
    if not isinstance(data, dict):
        return {}
    pkgs = data.get('packages')
    return pkgs if isinstance(pkgs, dict) else {}


def _patch_approval_sets():
    """(approved, declined) package-name sets, re-validated against
    _INSTALL_PKG_RE on the way out — the store is operator data and these names
    are interpolated into a shell command by _build_hold_cmd, so a hand-edited
    or migrated store must not be able to smuggle a metacharacter through."""
    approved, declined = set(), set()
    for name, ent in A._patch_approvals().items():
        if not isinstance(ent, dict) or not A._INSTALL_PKG_RE.match(str(name)):
            continue
        state = str(ent.get('state') or '')
        if state == 'approved':
            approved.add(str(name))
        elif state == 'declined':
            declined.add(str(name))
    return approved, declined


def _autopatch_pin_prefix():
    """Shell prefix prepended to the auto-patch upgrade command so the operator's
    approval decisions are ENFORCED on the host rather than merely recorded.

    Declined packages are pinned (apt-mark hold / versionlock / zypper addlock)
    and approved ones un-pinned immediately before the upgrade, so the state
    CONVERGES: approving a package that was previously declined releases its pin
    on the next policy run, with no separate operator action.

    Best-effort by construction — a subshell so _build_hold_cmd's ``set -e`` is
    scoped, output discarded, ``|| true`` so a host whose package manager has no
    hold equivalent (pacman/apk exit 2) still gets its upgrade. Returns '' when
    no approvals exist, so an install that never uses the feature queues the
    exact same command string it always did."""
    approved, declined = A._patch_approval_sets()
    parts = []
    if declined:
        parts.append('( ' + A._build_hold_cmd(sorted(declined)[:30], hold=True)
                     + ' ) >/dev/null 2>&1 || true; ')
    if approved:
        parts.append('( ' + A._build_hold_cmd(sorted(approved)[:30], hold=False)
                     + ' ) >/dev/null 2>&1 || true; ')
    return ''.join(parts)


def handle_patch_approvals_list():
    """``GET /api/patch-approvals`` — the approve/decline decisions recorded
    against fleet packages. Fleet-wide operator policy, not device data, so it
    carries no per-device scope; read for any authenticated caller."""
    A.require_auth()
    if A.method() != 'GET':
        A.respond(405, {'error': 'Method not allowed'})
    approvals = A._patch_approvals()
    rows = []
    for name in sorted(approvals):
        ent = approvals[name]
        if not isinstance(ent, dict):
            continue
        rows.append({'package': name,
                     'state':   str(ent.get('state') or ''),
                     'actor':   str(ent.get('actor') or ''),
                     'ts':      int(ent.get('ts') or 0),
                     'note':    str(ent.get('note') or '')})
    A.respond(200, {
        'approvals': rows,
        'approved':  sum(1 for r in rows if r['state'] == 'approved'),
        'declined':  sum(1 for r in rows if r['state'] == 'declined'),
        'enforced_by': 'autopatch',   # see _autopatch_pin_prefix
    })


def _approval_packages_from_body(body):
    """Package names from either ``packages: [...]`` or a whitespace/comma
    separated ``packages: "a b"`` — the same tolerant shape _handle_pkg_action
    accepts, validated with the same regex."""
    raw = body.get('packages')
    if raw in (None, ''):
        raw = body.get('package')
    if isinstance(raw, list):
        names = [str(x).strip() for x in raw]
    else:
        names = [n for n in A.re.split(r'[\s,]+', str(raw or '').strip()) if n]
    names = [n for n in names if n][:100]
    if not names:
        A.respond(400, {'error': 'no package names given'})
    bad = [n for n in names if not A._INSTALL_PKG_RE.match(n)]
    if bad:
        A.respond(400, {'error': 'invalid package name(s): ' + ', '.join(bad[:5])
                                 + ' — allowed: letters, digits, . _ + : @ / -'})
    return names


def handle_patch_approval_set():
    """``POST /api/patch-approvals`` {packages, state, note} — record an
    approve/decline decision for one or more packages fleet-wide.

    Gated on require_write_role: this MUTATES state and feeds a command that
    runs on every auto-patched host, so a bare require_auth() (which admits
    viewer/mcp/auditor/finance) would be the read-only-role write-gate bug."""
    actor = A.require_write_role('manage patch approvals')
    _require_instance_wide_policy_writer()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A._read_valid(A.request_models.PatchApprovalSetRequest)
    names = A._approval_packages_from_body(body)
    state = str(body.get('state') or '').strip().lower()
    if state not in _APPROVAL_STATES:
        A.respond(400, {'error': 'state must be one of '
                                 + ', '.join(_APPROVAL_STATES)})
    note = A._sanitize_str(str(body.get('note') or ''), 200)
    now = int(A.time.time())
    with A._LockedUpdate(A.PATCH_APPROVALS_FILE) as data:
        pkgs = data.setdefault('packages', {})
        if not isinstance(pkgs, dict):
            pkgs = data['packages'] = {}
        for n in names:
            pkgs[n] = {'state': state, 'actor': actor, 'ts': now, 'note': note}
        # Cap the store — it is operator-curated, but an integration looping
        # over a big catalog should not grow it without bound.
        if len(pkgs) > 2000:
            for stale in sorted(pkgs, key=lambda k: int((pkgs[k] or {}).get('ts') or 0))[:len(pkgs) - 2000]:
                pkgs.pop(stale, None)
    A.audit_log(actor, 'patch_approval_set',
                detail=f'state={state} packages={",".join(names)[:120]}')
    A.respond(200, {'ok': True, 'state': state, 'packages': names})


def handle_patch_approval_clear():
    """``POST /api/patch-approvals/delete`` {packages} — drop the recorded
    decision(s), returning those packages to "no decision"."""
    actor = A.require_write_role('manage patch approvals')
    _require_instance_wide_policy_writer()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A._read_valid(A.request_models.PatchApprovalClearRequest)
    names = A._approval_packages_from_body(body)
    removed = 0
    with A._LockedUpdate(A.PATCH_APPROVALS_FILE) as data:
        pkgs = data.get('packages')
        if isinstance(pkgs, dict):
            for n in names:
                if pkgs.pop(n, None) is not None:
                    removed += 1
    A.audit_log(actor, 'patch_approval_clear',
                detail=f'removed={removed} packages={",".join(names)[:120]}')
    A.respond(200, {'ok': True, 'removed': removed, 'packages': names})


# ── 4. ingested-log-line ring: retention tunables + export ───────────────────
# LOG_BUFFER_TTL / MAX_LOG_BUFFER_BYTES were module constants in api.py with no
# config read: seven OTHER retention keys were operator-tunable, but the ring
# holding the actual ingested log lines was not. Both readers below keep the
# api.py constant as the default so an install that never touches Settings
# behaves exactly as before.


def _log_buffer_ttl():
    """Effective ingested-log-line ring TTL in SECONDS.

    ``log_buffer_retention_hours`` (Settings → Advanced → Data retention);
    unset/0 falls back to the LOG_BUFFER_TTL constant (6h). Clamped 1h..7d so a
    typo cannot either evict everything instantly or grow the store forever.
    Reads through _config_ro (no deepcopy) and MUST be hoisted out of any
    per-device / per-unit loop by the caller."""
    try:
        hours = int(A._config_ro().get('log_buffer_retention_hours') or 0)
    except (TypeError, ValueError):
        hours = 0
    if hours <= 0:
        return A.LOG_BUFFER_TTL
    return max(3600, min(168 * 3600, hours * 3600))


def _log_buffer_unit_cap():
    """Per-UNIT byte cap for the ingested log ring; 0 (the default) = no cap.

    Deliberately opt-in, and deliberately per-unit. The old per-DEVICE byte cap
    was removed in v3.0.1 because it let one bloated unit (apt.history) starve
    every other unit on the host — reinstating that as a default would re-ship
    the bug. MAX_LOG_BUFFER_BYTES survives as the value the Settings hint
    recommends when an operator does want a ceiling; the cap keeps the NEWEST
    lines, so enabling it never hides recent evidence."""
    try:
        v = int(A._config_ro().get('log_buffer_max_bytes_per_unit') or 0)
    except (TypeError, ValueError):
        v = 0
    return max(0, min(64 * 1024 * 1024, v))


def _trim_unit_buffer(entries, cap):
    """Drop OLDEST entries until the unit's buffer fits `cap` bytes. cap<=0 is a
    no-op (today's behaviour). Always keeps at least one line so a single
    oversized line cannot empty the unit and hide that anything arrived."""
    if cap <= 0 or not entries:
        return entries
    total = 0
    keep_from = 0
    for i in range(len(entries) - 1, -1, -1):
        total += len(str((entries[i] or {}).get('line') or '')) + 32
        if total > cap and i < len(entries) - 1:
            keep_from = i + 1
            break
    return entries[keep_from:]


_LOG_EXPORT_MAX_LINES = 50000


def handle_logs_export():
    """``GET /api/logs/export?device=&unit=&q=&since=&limit=&format=csv|ndjson``
    — download the ingested log buffer.

    The three existing log endpoints (search / per-device / tail) all render
    JSON into the UI; there was no way to get the lines OUT for an incident
    write-up or an offline grep. Read-only.

    SEC: ``device=`` goes through _scope_block_device (403s a real out-of-scope
    or cross-tenant id); a fleet-wide export iterates the scope-filtered device
    set only. CSV cells go through _csv_safe, so a log line beginning ``=``,
    ``+``, ``-`` or ``@`` (trivially attacker-controlled — it is remote log
    content) cannot execute as a spreadsheet formula."""
    A.require_auth()
    if A.method() != 'GET':
        A.respond(405, {'error': 'Method not allowed'})
    qs = A.urllib.parse.parse_qs(A._env('QUERY_STRING', ''))
    device = (qs.get('device', [''])[0])[:64]
    unit_f = (qs.get('unit', [''])[0])[:128]
    q = (qs.get('q', [''])[0])[:128]
    fmt = (qs.get('format', ['csv'])[0]).lower()
    if fmt not in ('csv', 'ndjson'):
        fmt = 'csv'
    try:
        since = int(qs.get('since', ['0'])[0] or 0)
    except (TypeError, ValueError):
        since = 0
    try:
        limit = int(qs.get('limit', [str(_LOG_EXPORT_MAX_LINES)])[0]
                    or _LOG_EXPORT_MAX_LINES)
    except (TypeError, ValueError):
        limit = _LOG_EXPORT_MAX_LINES
    limit = max(1, min(_LOG_EXPORT_MAX_LINES, limit))

    rx = None
    if q:
        try:
            rx = A.re.compile(q, A.re.IGNORECASE)
        except A.re.error as e:
            A.respond(400, {'error': f'invalid regex: {e}'})

    devices = A._visible_devices()          # SEC: role scope AND tenant
    if device:
        A._scope_block_device(device)       # SEC: 403 a real out-of-scope id
        if device not in devices:
            A.respond(404, {'error': 'Device not found'})
        targets = [device]
    else:
        targets = sorted(devices)

    store = A.load(A.LOG_WATCH_FILE) or {}
    rows = []
    for dev_id in targets:
        buf = store.get(dev_id) or {}
        units = buf.get('units') or {}
        if not isinstance(units, dict):
            continue
        name = (devices.get(dev_id) or {}).get('name', dev_id)
        for unit, lines in units.items():
            if unit_f and unit != unit_f:
                continue
            for entry in (lines or []):
                if not isinstance(entry, dict):
                    continue
                ts = int(entry.get('ts') or 0)
                if since and ts < since:
                    continue
                line = str(entry.get('line') or '')
                if rx is not None and not rx.search(line):
                    continue
                rows.append((ts, name, dev_id, unit, line))
                if len(rows) >= limit:
                    break
            if len(rows) >= limit:
                break
        if len(rows) >= limit:
            break
    rows.sort(key=lambda r: -r[0])

    ts_label = A.time.strftime('%Y%m%d-%H%M%S')
    if fmt == 'ndjson':
        import json as _json
        payload = '\n'.join(_json.dumps({
            'ts': r[0], 'time': A.time.strftime('%Y-%m-%dT%H:%M:%S',
                                                A.time.localtime(r[0])) if r[0] else '',
            'device': r[1], 'device_id': r[2], 'unit': r[3], 'line': r[4],
        }, sort_keys=True) for r in rows)
        data = (payload + ('\n' if payload else '')).encode()
        print('Status: 200 OK')
        print('Content-Type: application/x-ndjson')
        print(f'Content-Disposition: attachment; filename=logs-{ts_label}.ndjson')
        print(f'Content-Length: {len(data)}')
        print('Cache-Control: no-store')
        print('X-Content-Type-Options: nosniff')
        print()
        A.sys.stdout.flush()
        A.sys.stdout.buffer.write(data)
        A.sys.stdout.buffer.flush()
        A.sys.exit(0)
    # CSV — _csv_emit already does the formula-injection escaping, the safe
    # filename and the exit.
    A._csv_emit(f'logs-{ts_label}.csv',
                ['Timestamp', 'Device', 'Device ID', 'Unit', 'Line'],
                [[A.time.strftime('%Y-%m-%d %H:%M:%S', A.time.localtime(r[0]))
                  if r[0] else '', r[1], r[2], r[3], r[4]] for r in rows])

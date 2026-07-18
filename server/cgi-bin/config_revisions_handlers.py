"""RemotePower — Config revision history + one-click rollback

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

The feature (v6.3.0, UX program item 4): every successful ``POST /api/config``
that actually changed something stores the PRE-save config as a restorable
revision (cap 10, newest last, in CONFIG_REVS_FILE — same 0600/backing-store
protection as config.json itself). ``GET /api/config/revisions`` lists
metadata ONLY (never the config bodies — they hold secrets);
``POST /api/config/revisions/restore`` swaps the live config for a picked
revision, saving the just-replaced state as a new revision first, so a
restore is itself always restorable (inherent undo).
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


_MAX_REVISIONS = 10


# ── handlers ─────────────────────────────────────────────────────────────────

def record_config_revision(prev_cfg, new_cfg, user):
    """Append the PRE-save config as a restorable revision (no-op when nothing
    changed). Called from handle_config_save's audit tail and from restore."""
    prev_cfg = prev_cfg or {}
    new_cfg = new_cfg or {}
    changed = sorted(k for k in (set(prev_cfg) | set(new_cfg))
                     if prev_cfg.get(k) != new_cfg.get(k))
    if not changed:
        return
    with A._LockedUpdate(A.CONFIG_REVS_FILE) as revs:
        lst = revs.setdefault('revisions', [])
        lst.append({
            'id': 'rev-' + A.secrets.token_hex(4),   # non-numeric by construction
            'ts': int(A.time.time()),
            'user': str(user or ''),
            'changed_keys': changed[:50],
            'config': prev_cfg,
        })
        del lst[:-_MAX_REVISIONS]


def handle_config_revisions_list():
    """GET /api/config/revisions — metadata only, newest first. The stored
    config bodies are NEVER returned (they hold unscrubbed secrets)."""
    A.require_admin_auth()
    revs = (A.load(A.CONFIG_REVS_FILE) or {}).get('revisions') or []
    out = [{
        'id': str(r.get('id') or ''),
        'ts': int(r.get('ts') or 0),
        'user': str(r.get('user') or ''),
        'changed_keys': [str(k) for k in (r.get('changed_keys') or [])[:50]],
    } for r in reversed(revs)]
    A.respond(200, {'revisions': out})


def handle_config_revision_restore():
    """POST /api/config/revisions/restore {id} — swap the live config for the
    picked revision. The just-replaced config becomes a revision itself first,
    so a restore is always undoable by restoring THAT."""
    actor = A.require_admin_auth()
    body = A.get_json_obj()
    rid = str(body.get('id') or '')
    revs = (A.load(A.CONFIG_REVS_FILE) or {}).get('revisions') or []
    rev = next((r for r in revs if r.get('id') == rid), None)
    if not rev or not isinstance(rev.get('config'), dict):
        A.respond(404, {'error': 'Revision not found'})
    current = A.load(A.CONFIG_FILE) or {}
    A.record_config_revision(current, rev['config'], f'{actor} (pre-restore)')
    A.save(A.CONFIG_FILE, rev['config'])
    A.audit_log(actor, 'config_restored',
                f'revision={rid} ts={int(rev.get("ts") or 0)}')
    A.respond(200, {'ok': True, 'restored': rid})

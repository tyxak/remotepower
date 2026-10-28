"""RemotePower — A host's own CPU and memory lines for its containers

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


def handle_device_container_thresholds(dev_id):
    """GET/PUT /api/devices/<id>/container-thresholds — the CPU and memory lines for the containers
    on one host (v7.4.3, issue #50).

    The shape is the fleet's (see the block above _clean_container_thresholds in api.py): cpu_pct,
    mem_pct, mem_mb, sustain and a list of overrides, each a `match` and the lines it changes. Only the
    keys that are set are kept, and a key that is not there is inherited from the fleet. PUT replaces
    the host's whole line with {"thresholds": {...}}; an empty object removes it. GET answers with the
    host's line and the fleet's, so a form can show what is being inherited.

    Reading is for anyone who can see the host. Changing a line decides what pages somebody, so it is
    an administrator or a role with an action permission, like naming a disk. The route is under
    /api/devices/<id>/, so a host outside the caller's tenant or role scope is refused before this runs.
    """
    verb = A.method()
    if verb == 'GET':
        A.require_auth()
    elif verb == 'PUT':
        actor = A.require_write_role('change container thresholds')
    else:
        A.respond(405, {'error': 'Method not allowed'})
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'Host not found'})
    fleet = A._config_ro().get('container_thresholds')
    fleet = fleet if isinstance(fleet, dict) else {}
    if verb == 'GET':
        dev = A.device_get(dev_id)
        if not dev:
            A.respond(404, {'error': 'Host not found'})
        mine = dev.get('container_thresholds')
        A.respond(200, {'thresholds': mine if isinstance(mine, dict) else {}, 'fleet': fleet})
    body = A._read_valid(A.request_models.ContainerThresholdsRequest)
    raw = body.get('thresholds')
    if not isinstance(raw, dict):
        A.respond(400, {'error': 'thresholds must be an object'})
    clean = A._clean_container_thresholds(raw)
    with A._LockedUpdate(A.DEVICES_FILE) as devices:
        if dev_id not in devices:
            A.respond(404, {'error': 'Host not found'})
        if clean:
            devices[dev_id]['container_thresholds'] = clean
        else:
            devices[dev_id].pop('container_thresholds', None)
    # The host and the number of lines, not the words: an override names a container.
    A.audit_log(actor, 'container_thresholds_set',
                detail=f'host={dev_id} lines={len(clean) - (1 if "overrides" in clean else 0)} '
                       f'overrides={len(clean.get("overrides") or [])}')
    A.respond(200, {'ok': True, 'thresholds': clean})

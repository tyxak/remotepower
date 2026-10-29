"""RemotePower — A host's exposure switch: treat its listeners as internal (v7.4.5, issue #55)

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


def handle_device_exposure_internal(dev_id):
    """GET/PUT /api/devices/<id>/exposure-internal — whether a host counts as internal when its listeners
    are graded (v7.4.5, issue #55).

    GET answers with the switch and what it does for the host right now: `assumed` when it holds, and
    `blocked` with the reason when it does not ('public_address', with the addresses that block it, or
    'no_address_data' when the agent does not report its addresses). PUT {"internal": true|false} sets the
    switch and grades the host's stored listeners at once; the port audit sees the change at the host's
    next report.

    Turning it on lowers how the host's listeners are graded, which is what a host mute does, so setting
    it is for an administrator and is audited. Reading is for anyone who can see the host. The route is
    under /api/devices/<id>/, so a host outside the caller's tenant or role scope is refused before this
    runs.
    """
    verb = A.method()
    if verb == 'GET':
        A.require_auth()
    elif verb == 'PUT':
        actor = A.require_admin_auth()
    else:
        A.respond(405, {'error': 'Method not allowed'})
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'Host not found'})
    mod = A.exposure_scope_mod
    if verb == 'GET':
        dev = A.device_get(dev_id)
        if not dev:
            A.respond(404, {'error': 'Host not found'})
        A.respond(200, mod.host_state(dev.get('exposure_internal'),
                                      (dev.get('sysinfo') or {}).get('host_addresses')))
    body = A._read_valid(A.request_models.ExposureInternalRequest)
    # A request that does not say what it wants must not change a host's grade. The model above is loose (it
    # never rejects what an older client sent), so the body is read again here: only the JSON values true and
    # false are an answer. An empty body, a broken one, null, "true" and 1 are refused.
    asked = A.get_json_obj()
    said = asked.get('internal') if isinstance(asked, dict) else None
    if said is not True and said is not False:
        A.respond(400, {'error': 'The internal setting must be true or false'})
    internal = body.get('internal') is True
    with A._LockedUpdate(A.DEVICES_FILE) as devices:
        dev = devices.get(dev_id)
        if not isinstance(dev, dict):
            A.respond(404, {'error': 'Host not found'})
        was = dev.get('exposure_internal') is True
        if internal:
            dev['exposure_internal'] = True
        else:
            dev.pop('exposure_internal', None)
        si = dev.get('sysinfo') if isinstance(dev.get('sysinfo'), dict) else {}
        regraded = mod.apply(internal, si)
        state = mod.host_state(internal, si.get('host_addresses'))
    if was != internal:
        A.audit_log(actor, 'exposure_internal_set',
                    detail=f'host={dev_id} internal={"on" if internal else "off"} '
                           f'holds={"yes" if state["assumed"] else "no"}')
    A.respond(200, dict(state, ok=True, regraded=regraded))

"""RemotePower — A host's apt upgrade mode: Standard or Extended (Discussion #30)

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


def _state(dev):
    """What the host's upgrade mode is and whether it does anything for the host, for GET and for the answer of a PUT."""
    mod = A.upgrade_mode_mod
    pkg = (dev.get('sysinfo') or {}).get('packages') if isinstance(dev.get('sysinfo'), dict) else None
    manager = pkg.get('manager') if isinstance(pkg, dict) else ''
    why = mod.not_applicable(A._device_os_family(dev), manager)
    return {'mode': mod.mode_of(dev), 'modes': list(mod.MODES), 'applies': why is None, 'reason': why or '',
            'manager': manager if isinstance(manager, str) else ''}


def handle_device_upgrade_mode(dev_id):
    """GET/PUT /api/devices/<id>/upgrade-mode — how the upgrade runs on this host: `standard` (`apt-get upgrade`) or
    `extended` (`apt-get upgrade --with-new-pkgs`, which also installs the new packages an update needs, such as a
    new kernel image). Discussion #30.

    GET answers with the mode and whether it does anything for the host: `applies` is false for a Windows or macOS
    host and for a Linux host that reports another package manager, with `reason` saying which. PUT {"mode":
    "standard"|"extended"} sets it. Only those two words are an answer: an empty body, a broken one, null, a number,
    a different case and any other word are refused, and a request that does not say what it wants never changes the
    mode. A host the mode does nothing for is refused with the reason, so a setting is never kept that nothing reads.

    It changes what the patch button, auto-patch, scheduled upgrades, rollouts and the autonomy loop install on the
    host as root, so setting it is for an administrator and only a change is audited. Reading is for anyone who can see
    the host. The route is under /api/devices/<id>/, so a host outside the caller's tenant or role scope is refused
    before this runs.
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
    if verb == 'GET':
        dev = A.device_get(dev_id)
        if not isinstance(dev, dict):
            A.respond(404, {'error': 'Host not found'})
        A.respond(200, dict(_state(dev), ok=True))
    mod = A.upgrade_mode_mod
    A._read_valid(A.request_models.UpgradeModeRequest)
    # The model above is loose (it never rejects what an older client sent), so the body is read again here: only the
    # exact words are an answer.
    asked = A.get_json_obj()
    mode = asked.get('mode') if isinstance(asked, dict) else None
    if not isinstance(mode, str) or mode not in mod.MODES:
        A.respond(400, {'error': 'The upgrade mode must be "standard" or "extended"'})
    with A._LockedUpdate(A.DEVICES_FILE) as devices:
        dev = devices.get(dev_id)
        if not isinstance(dev, dict):
            A.respond(404, {'error': 'Host not found'})
        state = _state(dev)
        if not state['applies']:
            A.respond(400, {'error': mod.REASONS[state['reason']], 'reason': state['reason']})
        was = mod.mode_of(dev)
        if mode == 'extended':
            dev['upgrade_mode'] = 'extended'
        else:
            dev.pop('upgrade_mode', None)
        state = _state(dev)
    if was != mode:
        A.audit_log(actor, 'upgrade_mode_set', detail=f'host={dev_id} mode={mode}')
    A.respond(200, dict(state, ok=True, changed=was != mode))

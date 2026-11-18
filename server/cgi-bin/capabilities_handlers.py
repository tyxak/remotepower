"""RemotePower — What an agent can see on its host: the panel behind the host drawer's "What this agent can see"

A Linux agent sends one structure with its system information: whether it runs as root, in a container, which of the tools it uses are
on the host, which logs the threat sensor can open, and its own version and Python. api.py keeps it, cleaned by
agent_capabilities.clean, in the host's sysinfo. This answers the panel: each tool as present, missing, not needed on this host or not
available in a container, with the feature that needs a missing one and an install hint for the host's package manager.

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

import agent_capabilities


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


# ── handlers ─────────────────────────────────────────────────────────────────
def handle_device_capabilities(dev_id):
    """GET /api/devices/<id>/capabilities — what this host's agent can see, for the host drawer.

    `reported` is false until the agent has sent it (an older agent never does, and a Windows or macOS agent has no such report).
    Every tool the agent reported is a row with a status (present, missing, not_needed, unavailable), the feature that needs it, whether
    that feature is optional and, for a missing one, an install hint for the host's package manager. Nothing in the answer is text the
    host wrote: the record is cleaned on the way in and the rows come from the server's own table.

    Reading is open to any signed-in role. The route is under /api/devices/<id>/, so a host outside the caller's tenant or role scope is
    refused before this runs."""
    if A.method() != 'GET':
        A.respond(405, {'error': 'Method not allowed'})
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'Host not found'})
    A.require_auth()
    dev = A.device_get(dev_id)
    if not isinstance(dev, dict):
        A.respond(404, {'error': 'Host not found'})
    si = dev.get('sysinfo') if isinstance(dev.get('sysinfo'), dict) else {}
    A.respond(200, dict(agent_capabilities.panel(si.get('capabilities'), agent_capabilities.manager_of(si)), ok=True))

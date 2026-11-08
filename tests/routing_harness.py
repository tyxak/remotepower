"""Shared helper: resolve a (method, path) through api._dispatch and return the
name of the handler it routes to — without executing the handler.

Used by the route-registration tests (test_v250 / test_v306 / test_v340 / …)
so they assert *behaviour* (this path reaches that handler) instead of grepping
the dispatcher source for a literal `elif` line. Source-text route assertions
broke spuriously when the dispatch chain was refactored into the _EXACT_ROUTES
table even though every route still resolved correctly; this resolves that
whole class of false failure.
"""
import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))

import api  # noqa: E402


class _Hit(Exception):
    def __init__(self, name, args):
        self.name = name
        self.handler_args = args


def resolve_route(method, path):
    """Return (handler_name, handler_args) for the route, or ('__http__N', [])
    when the dispatcher responds directly (e.g. 404), or ('__nocall__', [])."""
    saved = {}
    for name in dir(api):
        if name.startswith('handle_') and callable(getattr(api, name)):
            saved[name] = getattr(api, name)

            def mk(n):
                def rec(*a, **k):
                    raise _Hit(n, list(a))
                return rec
            setattr(api, name, mk(name))
    saved_table = api._EXACT_ROUTES
    api._EXACT_ROUTES = None     # rebuild capturing the recorders
    # v5.6.x: the pattern chain is a lazily-built table too — reset it the
    # same way or a cached build holds stale handler objects across the swap.
    saved_patterns = api._PATTERN_ROUTES
    api._PATTERN_ROUTES = None
    # the request the dispatcher reads is put back afterwards: a PATH_INFO and a REQUEST_METHOD left in the environment were read by the next module that ran
    # in the same process (test_v640_client_errors answered a list for a GET after test_v500_features)
    env_before = {n: os.environ.get(n) for n in ('REQUEST_METHOD', 'PATH_INFO')}
    os.environ['REQUEST_METHOD'] = method
    os.environ['PATH_INFO'] = path
    try:
        api._dispatch(path, method)
        return ('__nocall__', [])
    except _Hit as h:
        return (h.name, h.handler_args)
    except api.HTTPError as e:
        return (f'__http__{e.status}', [])
    finally:
        for n, v in env_before.items():
            if v is None:
                os.environ.pop(n, None)
            else:
                os.environ[n] = v
        for name, fn in saved.items():
            setattr(api, name, fn)
        api._EXACT_ROUTES = saved_table
        api._PATTERN_ROUTES = saved_patterns


def routes_to(method, path):
    """Just the handler name."""
    return resolve_route(method, path)[0]

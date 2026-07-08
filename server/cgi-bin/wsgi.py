"""RemotePower — native Flask entry point, served by gunicorn.

Flask owns routing, the WSGI application object, and the gunicorn
integration. ``api.py``'s business logic — the ~500-route dispatcher, every
handler, and the pre-dispatch security pipeline in ``api.main()`` (CSRF,
read-only/demo-mode, IP allowlist, forced password change, MFA enrollment,
device-scope enforcement, satellite auth, the ~30 maintenance-cadence
sweeps) — is UNCHANGED: every request still runs through ``api.main()``
exactly as it always has. Only the transport shell changed: a hand-rolled
WSGI ``application(environ, start_response)`` callable became a Flask view,
and the CGI shim (``api_cgi.py``) + SCGI prefork worker (``api_worker.py``)
are retired in favour of this being the only server path.

The response bridge is deliberately UNCHANGED from the pre-Flask version of
this module: ``api.main()`` still writes to a captured, thread-local stdout
proxy — ``respond()``/``HTTPError`` handlers AND the handful of handlers that
write straight to ``sys.stdout.buffer`` then ``sys.exit()`` (file/backup/
export downloads) both work identically, because the capture is transport-
agnostic. ``_parse_cgi_response()`` turns the captured bytes into
``(status, headers, body)``, which this module wraps in a ``flask.Response``
instead of hand-calling ``start_response``. No handler code needed to change
for this cutover.

THREADING: request context + output buffer + storage connections are all
thread-local (``api._RCTX``), so this serves requests **concurrently on
threads**, no process-wide lock. Run with sync workers + threads — NOT
gevent/eventlet (see CLAUDE.md's long-poll / `_LOAD_CACHE` notes, which were
validated against this worker model):

    gunicorn --workers 4 --threads 8 wsgi:application

``application`` is a genuine ``flask.Flask`` instance (not a bare function)
so gunicorn's existing ``wsgi:application`` target keeps working unchanged.
"""
import io
import sys

from flask import Flask, Response, request

import api  # imported ONCE per worker and reused — the whole point of the persistent tier

# v5.6.x: mark the request tier so /api/self/status can report what's serving.
api._SERVER_TIER = 'wsgi'

# CGI meta-variables (RFC 3875) copied straight from the WSGI environ.
_CGI_META = (
    'REQUEST_METHOD', 'PATH_INFO', 'QUERY_STRING', 'CONTENT_TYPE', 'CONTENT_LENGTH',
    'SERVER_NAME', 'SERVER_PORT', 'SERVER_PROTOCOL', 'REMOTE_ADDR', 'REMOTE_HOST',
    'REMOTE_USER', 'AUTH_TYPE', 'SCRIPT_NAME', 'REQUEST_URI', 'HTTPS', 'GATEWAY_INTERFACE',
)


def _cgi_env_from_wsgi(environ):
    """Project the WSGI environ onto the CGI meta-variables + HTTP_* headers."""
    env = {}
    for k in _CGI_META:
        v = environ.get(k)
        if v is not None:
            env[k] = str(v)
    for k, v in environ.items():
        if k.startswith('HTTP_') and v is not None:
            env[k] = str(v)
    env.setdefault('REQUEST_METHOD', 'GET')
    env.setdefault('PATH_INFO', environ.get('PATH_INFO', '') or '')
    return env


def _parse_cgi_response(raw):
    """Split CGI output (header block + blank line + body) → (status, headers, body)."""
    sep = b'\r\n\r\n' if b'\r\n\r\n' in raw else b'\n\n'
    head, found, body = raw.partition(sep)
    if not found:                      # no separator → the whole thing is the body
        head, body = b'', raw
    status = '200 OK'
    headers = []
    for line in head.replace(b'\r\n', b'\n').split(b'\n'):
        if not line.strip():
            continue
        name, _, val = line.partition(b':')
        name = name.decode('latin-1').strip()
        val = val.decode('latin-1').strip()
        if not name:
            continue
        if name.lower() == 'status':
            status = val or '200 OK'
        else:
            headers.append((name, val))
    if not any(h[0].lower() == 'content-type' for h in headers):
        headers.append(('Content-Type', 'text/html; charset=utf-8'))
    return status, headers, body


# ── Thread-dispatching stdout proxy ──────────────────────────────────────────
# Installed ONCE (process-global) but routes writes to the CURRENT THREAD's
# per-request buffer (api._RCTX.out / .out_text) when one is set, else to the real
# stdout. That removes the per-request sys.stdout SWAP (and the lock it required):
# concurrent request threads each capture into their own buffer.
class _OutProxyBuffer:
    def __init__(self, real_buffer):
        self._real = real_buffer

    def _target(self):
        o = getattr(api._RCTX, 'out', None)
        return o if o is not None else self._real

    def write(self, b):
        return self._target().write(b)

    def flush(self):
        try:
            self._target().flush()
        except Exception:
            pass


class _OutProxy:
    def __init__(self, real):
        self._real = real
        self.buffer = _OutProxyBuffer(getattr(real, 'buffer', real))

    def _target(self):
        o = getattr(api._RCTX, 'out_text', None)
        return o if o is not None else self._real

    def write(self, s):
        return self._target().write(s)

    def flush(self):
        try:
            self._target().flush()
        except Exception:
            pass

    def __getattr__(self, name):      # encoding / isatty / fileno / … → real stdout
        return getattr(self._real, name)


def _ensure_stdout_proxy():
    """Install (or re-install) the capture proxy. Checked at the top of every
    request, not just once at import: if ANYTHING later reassigns
    sys.stdout wholesale (a test harness's stdout capture, a logging/APM
    library that wraps stdout, a REPL) the plain object-identity swap
    silently discards our proxy — every following request's respond()/
    HTTPError output then writes straight to whatever now owns sys.stdout
    instead of the per-request buffer, so `out.getvalue()` comes back EMPTY
    (an empty 200 body) while the real response leaks into that other
    stream. Re-checking here is a cheap isinstance() call per request and
    makes the capture self-healing instead of a one-shot import-time
    assumption that production doesn't happen to violate."""
    if not isinstance(sys.stdout, _OutProxy):
        sys.stdout = _OutProxy(sys.stdout)


# Install once at import (the common case — nothing else touches sys.stdout
# in a plain gunicorn worker), then re-verified per request below.
_ensure_stdout_proxy()


# static_folder=None: Flask registers a `/static/<path:filename>` route by
# default, served by Flask's own handler — a code path that bypasses
# api.main() entirely (no CSRF/auth/read-only/IP-allowlist enforcement). It's
# inert today (no server/cgi-bin/static/ dir, and nginx never proxies /static/
# here anyway — that's served directly from disk), but both of those are
# operational assumptions, not guarantees at the code level. Disabling it
# keeps the catch-all route below the ONLY route, as intended.
application = Flask(__name__, static_folder=None)


def _run_request(environ):
    """Run api.main() against a WSGI environ, exactly as the pre-Flask bridge
    did, and return (status, headers, body) — the CGI-response triple."""
    _ensure_stdout_proxy()
    try:
        n = int(environ.get('CONTENT_LENGTH') or 0)
    except (TypeError, ValueError):
        n = 0
    body_in = environ['wsgi.input'].read(n) if n > 0 else b''

    out = io.BytesIO()
    out_text = io.TextIOWrapper(out, encoding='utf-8', write_through=True, newline='')
    # Populate api's thread-local request context (read by _env / _read_request_body
    # and the stdout proxy). No process-global swap → safe under concurrent threads.
    api._RCTX.environ = _cgi_env_from_wsgi(environ)
    api._RCTX.stdin = body_in
    api._RCTX.out = out
    api._RCTX.out_text = out_text
    try:
        # api.py's __main__ contract, replicated.
        try:
            api.main()
        except api.HTTPError as e:
            # Pass e.headers so extra response headers survive — above all the
            # portal Set-Cookie (handle_portal_session). The CGI __main__ block
            # renders with headers; this non-CGI path must match, or the portal
            # session cookie is silently dropped → every next request is 401.
            api._render_response(e.status, e.body, getattr(e, 'headers', None))
        except SystemExit:
            pass                       # a streaming handler wrote its body then exited
        except Exception:
            import traceback as _tb     # WSGI catches it → log the traceback ourselves
            _tb.print_exc(file=sys.stderr)
            try:
                api._render_response(500, {'error': 'Internal server error'})
            except Exception:
                pass
        try:
            out_text.flush()
        except Exception:
            pass
    finally:
        try:
            api._end_request()
        except Exception:
            pass
        try:
            out_text.detach()          # disconnect from `out` so GC won't close it
        except Exception:
            pass
        for _a in ('environ', 'stdin', 'out', 'out_text'):
            try:
                setattr(api._RCTX, _a, None)
            except Exception:
                pass

    return _parse_cgi_response(out.getvalue())


_ALL_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']


@application.route('/', defaults={'_path': ''}, methods=_ALL_METHODS,
                    provide_automatic_options=False)
@application.route('/<path:_path>', methods=_ALL_METHODS,
                    provide_automatic_options=False)
def _view(_path):
    # `_path` is unused — api.main()/path_info() re-derive the path from
    # api._RCTX.environ (PATH_INFO), same as the pre-Flask bridge and the CGI
    # shim. Flask's routing here exists to make `application` a real Flask
    # app (gunicorn target, error handling, testability), not to re-route.
    status, headers, out_body = _run_request(request.environ)
    status_code = int(status.split(' ', 1)[0])
    return Response(out_body, status=status_code, headers=headers)


@application.errorhandler(405)
def _method_not_allowed(_e):
    # The route above only lists 7 methods (Werkzeug requires an explicit
    # list), so any other verb (WebDAV, a custom LB probe, …) would otherwise
    # get a framework-generated, non-JSON 405 before ever reaching
    # api.main() — unlike every prior transport (CGI, the old hand-rolled
    # WSGI bridge), which passed every REQUEST_METHOD through unconditionally
    # and let api.py's own routing/error format decide. Re-run the same
    # request through _run_request so behavior is unchanged for any method.
    status, headers, out_body = _run_request(request.environ)
    status_code = int(status.split(' ', 1)[0])
    return Response(out_body, status=status_code, headers=headers)

"""RemotePower — Phase-5 "keystone": an OPT-IN WSGI entry point.

The default + permanent fallback entry point is still the CGI shim ``api_cgi.py``
(fork-per-request). This module lets the SAME unchanged ``api.py`` be served by a
**persistent** WSGI worker (gunicorn, uvicorn's WSGI bridge, …) so the process is
reused across requests instead of re-forked + re-interpreted each time.

How it works — a CGI-under-WSGI bridge, NOT a handler rewrite:
  * ``api.py`` keeps its CGI contract — read the request from ``os.environ`` +
    ``sys.stdin`` (now via ``_env()`` / ``_read_request_body()``, which read a
    thread-local request context when one is active), write the response to
    ``sys.stdout``, ``respond()`` raises ``HTTPError`` which the ``__main__`` block
    renders.
  * ``application()`` populates api's **thread-local** request context (``_RCTX``)
    — environ + body — runs api's exact ``main()`` + ``__main__`` contract, and reads
    the response from a per-request buffer that a thread-dispatching ``sys.stdout``
    proxy routes ``print``/``buffer.write`` into. Per-request state (``_LOAD_CACHE``,
    correlation/trace ids, auth-key scope, DB connections) is all thread-local.

THREADING: because the request context + output buffer + storage connections are
thread-local, this NO LONGER needs a process-wide lock — it serves requests
**concurrently on threads**. Run with either model:

    gunicorn --workers 4 --threads 8 wsgi:application     # threaded (in-process concurrency)
    gunicorn --workers 8 --threads 1 wsgi:application     # process-per-worker

The CGI path (api_cgi.py) is untouched and remains the supported default + fallback.
SQLite stays single-node; multi-node needs Postgres (see the keystone design doc).
"""
import io
import sys

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


# Install the proxy once, when this module is imported by the WSGI server. The CGI
# entry point (api_cgi.py) never imports this module, so its stdout is untouched.
if not isinstance(sys.stdout, _OutProxy):
    sys.stdout = _OutProxy(sys.stdout)


def application(environ, start_response):
    """WSGI entry point (``wsgi:application``). Thread-safe — no lock."""
    try:
        n = int(environ.get('CONTENT_LENGTH') or 0)
    except (TypeError, ValueError):
        n = 0
    body = environ['wsgi.input'].read(n) if n > 0 else b''

    out = io.BytesIO()
    out_text = io.TextIOWrapper(out, encoding='utf-8', write_through=True, newline='')
    # Populate api's thread-local request context (read by _env / _read_request_body
    # and the stdout proxy). No process-global swap → safe under concurrent threads.
    api._RCTX.environ = _cgi_env_from_wsgi(environ)
    api._RCTX.stdin = body
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

    status, headers, out_body = _parse_cgi_response(out.getvalue())
    start_response(status, headers)
    return [out_body]

"""RemotePower — Phase-5 "keystone" Stage B: an OPT-IN WSGI entry point.

The default + permanent fallback entry point is still the CGI shim ``api_cgi.py``
(fork-per-request). This module lets the SAME unchanged ``api.py`` be served by a
**persistent** WSGI worker (gunicorn sync workers, uvicorn's WSGI bridge, …) so the
process is reused across requests instead of re-forked + re-interpreted each time.

How it works — a CGI-under-WSGI bridge, NOT a rewrite:
  * ``api.py`` is written for the CGI contract (read the request from ``os.environ``
    + ``sys.stdin``, write the response to ``sys.stdout``, ``respond()`` raises
    ``HTTPError`` which the ``__main__`` block renders). We keep ALL of that.
  * ``application()`` adapts the WSGI ``environ`` → the CGI ``os.environ`` + a stdin
    buffer, runs api's exact ``main()`` + ``__main__`` contract with ``sys.stdout``
    redirected to a buffer, then parses that captured CGI response back into a WSGI
    ``(status, headers, body)``.
  * Per-request isolation rides on Stage A: ``api.main()`` calls ``_begin_request()``
    at its top (clears the ``load()`` cache + correlation id); we call
    ``_end_request()`` in teardown and restore the request slice of ``os.environ`` +
    ``sys.stdin``/``sys.stdout`` so nothing leaks into the next request.

THREADING — IMPORTANT: ``os.environ`` and ``sys.stdin``/``sys.stdout`` are
process-global, so this shim **serialises requests with a lock**. Run it with
*synchronous, single-thread* workers and scale with PROCESSES:

    gunicorn --workers 4 --threads 1 wsgi:application        # from server/cgi-bin/

That trades in-process concurrency for a zero-rewrite, provably-correct Stage B; the
streaming-response abstraction that removes the lock is a later stage. SQLite stays
single-node; multi-node needs Postgres (see the keystone design doc).
"""
import io
import os
import sys
import threading

import api  # imported ONCE per worker and reused — the whole point of the persistent tier

# Serialises the process-global os.environ / sys.stdio swap. One request at a time
# per worker process; concurrency comes from running multiple worker PROCESSES.
_LOCK = threading.Lock()

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


def _run_capture(cgi_env, body_bytes):
    """Run api's CGI request contract once with env + stdio redirected; return raw bytes.

    Replicates api.py's ``__main__`` block exactly (HTTPError → render, SystemExit
    from a streaming handler → already written, any other exception → 500), then
    restores every process-global it touched."""
    out = io.BytesIO()
    # Snapshot ONLY the request-variable slice of os.environ (CGI meta + HTTP_* +
    # whatever this request sets) — never the deploy env (RP_DATA_DIR, RP_CONFIG_KEY…).
    touched = set(_CGI_META) | {h for h in os.environ if h.startswith('HTTP_')} | set(cgi_env)
    saved_env = {k: os.environ.get(k) for k in touched}
    saved_stdin, saved_stdout = sys.stdin, sys.stdout
    cap = io.TextIOWrapper(out, encoding='utf-8', write_through=True, newline='')
    try:
        for k in touched:              # drop stale request vars from the previous request
            os.environ.pop(k, None)
        os.environ.update(cgi_env)
        sys.stdin = io.TextIOWrapper(io.BytesIO(body_bytes), encoding='utf-8')
        sys.stdout = cap
        try:
            api.main()
        except api.HTTPError as e:
            api._render_response(e.status, e.body)
        except SystemExit:
            pass                       # a streaming handler wrote its body then exited
        except Exception:
            api._render_response(500, {'error': 'Internal server error'})
        finally:
            try:
                api._end_request()
            except Exception:
                pass
    finally:
        try:
            cap.flush()
        except Exception:
            pass
        try:
            cap.detach()               # disconnect from `out` so GC of cap won't close it
        except Exception:
            pass
        sys.stdin, sys.stdout = saved_stdin, saved_stdout
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return out.getvalue()


def application(environ, start_response):
    """WSGI entry point. gunicorn etc. import this as ``wsgi:application``."""
    try:
        n = int(environ.get('CONTENT_LENGTH') or 0)
    except (TypeError, ValueError):
        n = 0
    body = environ['wsgi.input'].read(n) if n > 0 else b''
    cgi_env = _cgi_env_from_wsgi(environ)
    with _LOCK:
        raw = _run_capture(cgi_env, body)
    status, headers, out_body = _parse_cgi_response(raw)
    start_response(status, headers)
    return [out_body]

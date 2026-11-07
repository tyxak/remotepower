"""RemotePower — the hosted, read-only MCP endpoint: POST /api/mcp (8.0.0).

The protocol and the tools are the pure mcp_http.py. This module is the part that touches the server: it authenticates the caller, and answers
each read a tool asks for by running the REAL request, as the caller, in this process — the same gates, the same handler, the same permission,
host-scope and tenant checks that serve the dashboard — so the endpoint has no authority of its own and no second copy of any rule.

Off until the `mcp` optional module is switched on (Settings → Advanced → Optional modules): main()'s module gate answers 404 for /api/mcp
before this runs, as it does for every switched-off module.

A bound-module carve-out following the tls_ct_handlers / dmarc_handlers / rack_ipam_handlers pattern: api.py execs a PRIVATE instance and
binds its own ``globals()`` here, so every api service is reached as ``A.<name>``, a dynamic attribute lookup that keeps the test suite's
monkeypatching working.
"""
import io
import json
import sys
import traceback

import mcp_http as mcp_http_mod


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

# one client address may ask this often in a minute (an AI host asks a handful of questions; each is a few reads). The token's own rate limit
# applies as well, to every read a tool makes.
MCP_PER_MINUTE = 300
MAX_PATH_CHARS = 400


def bind(api_globals):
    """Called once by api.py right after importing this module, with api's ``globals()``."""
    global A
    A = _ApiNamespace(api_globals)


def _mcp_gates(pi, m):
    """The chain main() runs before it hands a request to a handler, in the same order. A read a tool makes passes through it too.
    tests/test_v800_mcp_http.py compares this list with the _enforce_* calls in main(), so a gate that is added there and not here fails
    the build."""
    A._enforce_read_only()
    A._enforce_same_origin()
    A._enforce_ip_allowlist()
    A._enforce_password_change()
    A._enforce_mfa_enrollment()
    A._enforce_device_scope()
    A._enforce_module_gate(pi)
    A._enforce_platform_routes(pi, m)
    A._enforce_operator_org_routes(pi)


def _parse_cgi(raw):
    """(status, body bytes) of a CGI-shaped response: header lines, a blank line, the body."""
    head, _, body = raw.partition(b'\n\n')
    status = 500
    for line in head.split(b'\n'):
        if line.lower().startswith(b'status:'):
            try:
                status = int(line.split(b':', 1)[1].strip().split(b' ', 1)[0])
            except ValueError:
                status = 500
    return status, body


def _mcp_get(path):
    """One GET against this server, as the caller. Returns the parsed JSON of a success; raises mcp_http.FetchError for any other answer.

    The request is the caller's own: the token and the client address stay as they arrived, so a token's host scope, its allowed addresses,
    its rate limit and a tenant's limits all apply to it. The method is always GET and the path must be under /api/; what changes in the
    environment is only what a read must not carry (a body, an Origin, a conditional header, gzip)."""
    if not isinstance(path, str) or not path.startswith('/api/') or len(path) > MAX_PATH_CHARS or any(ord(c) < 33 or ord(c) == 127 for c in path):
        raise mcp_http_mod.FetchError(400, 'a read must be a path under /api/')
    pi, _, query = path.partition('?')
    if '..' in pi.split('/') or '//' in pi:
        raise mcp_http_mod.FetchError(400, 'a read must be a plain path')
    ctx = A._RCTX
    saved = {a: getattr(ctx, a, None) for a in ('environ', 'stdin', 'out', 'out_text')}
    env = dict(saved['environ'] or {})
    env.update(REQUEST_METHOD='GET', PATH_INFO=pi, QUERY_STRING=query, REQUEST_URI=path, CONTENT_LENGTH='0', HTTP_X_MCP_CLIENT='mcp-http')
    for k in ('CONTENT_TYPE', 'HTTP_ORIGIN', 'HTTP_REFERER', 'HTTP_IF_NONE_MATCH', 'HTTP_IF_MODIFIED_SINCE', 'HTTP_ACCEPT_ENCODING'):
        env.pop(k, None)
    out = io.BytesIO()
    out_text = io.TextIOWrapper(out, encoding='utf-8', write_through=True, newline='')
    ctx.environ, ctx.stdin, ctx.out, ctx.out_text = env, b'', out, out_text
    try:
        try:
            _mcp_gates(pi, 'GET')
            A._dispatch(pi, 'GET')
        except A.HTTPError as e:
            A._render_response(e.status, e.body, getattr(e, 'headers', None))
        except SystemExit:
            pass                                    # a handler that wrote its own response and left
        except A.LockBusy:
            raise mcp_http_mod.FetchError(503, 'Storage busy, retry shortly')
        except Exception:
            traceback.print_exc(file=sys.stderr)
            raise mcp_http_mod.FetchError(500, 'Internal server error')
        out_text.flush()
        status, body = _parse_cgi(out.getvalue())
    finally:
        try:
            out_text.detach()
        except Exception:
            pass
        for a, v in saved.items():
            setattr(ctx, a, v)
    try:
        data = json.loads(body.decode('utf-8', 'replace')) if body.strip() else None
    except ValueError:
        data = None
    if 200 <= status < 300:
        return data
    message = data.get('error') if isinstance(data, dict) else None
    raise mcp_http_mod.FetchError(status, str(message or 'request refused')[:300])


def handle_mcp():
    """POST /api/mcp — one MCP message in, one JSON answer out. Read-only tools, with the permissions of the calling token."""
    if A.method() != 'POST':
        # the transport allows a server to offer a stream on GET or end a session on DELETE; this one does neither
        raise A.HTTPError(405, {'error': 'The MCP endpoint takes POST'}, headers=[('Allow', 'POST')])
    try:
        user = A.require_auth()
    except A.HTTPError as e:
        if e.status == 401:
            raise A.HTTPError(401, e.body, headers=[('WWW-Authenticate', 'Bearer realm="RemotePower"')])
        raise
    if not A._ip_ratelimit('mcp', A._get_client_ip(), MCP_PER_MINUTE, window=60):
        A.respond(429, {'error': 'Too many requests, slow down'})
    version = A._env('HTTP_MCP_PROTOCOL_VERSION', '').strip()
    if version and version not in mcp_http_mod.PROTOCOL_VERSIONS:
        A.respond(400, {'error': 'Unsupported MCP-Protocol-Version: %s' % version[:30]})
    raw = A.get_body()                              # a body over MAX_BODY_BYTES is refused here with a 413
    try:
        message = A._json_loads(raw if isinstance(raw, str) else raw.decode('utf-8'))
    except Exception:
        A.respond(400, {'jsonrpc': '2.0', 'id': None, 'error': {'code': mcp_http_mod.PARSE_ERROR, 'message': 'Parse error'}})
    if isinstance(message, dict) and message.get('method') == 'tools/call':
        params = message.get('params') if isinstance(message.get('params'), dict) else {}
        shown = json.dumps(params.get('arguments') or {}, ensure_ascii=False, separators=(',', ':'), default=str)[:200]
        A.audit_log(user, 'mcp_http_call', '%s %s' % (str(params.get('name'))[:60], shown))
    status, answer = mcp_http_mod.handle(message, _mcp_get, A.SERVER_VERSION)
    A.respond(status, answer if answer is not None else {})

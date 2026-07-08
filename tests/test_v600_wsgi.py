"""Phase-5 "keystone" Stage B — WSGI shim parity + per-request isolation.

Drives the opt-in `wsgi:application` against the REAL api.main() and asserts it
produces correct CGI-equivalent responses while leaking no per-request state
between requests (the cross-request-leak risk the whole migration hinges on).

`_run_detached` is neutralised so the per-request maintenance cadence can't spawn
network children in the test; everything else is the real request path.
"""
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-wsgi-test-"))

import wsgi  # noqa: E402  (imports api)
api = wsgi.api


def _environ(method, path, body=b'', query='', headers=None):
    env = {
        'REQUEST_METHOD': method,
        'PATH_INFO': path,
        'QUERY_STRING': query,
        'SERVER_NAME': 'localhost',
        'SERVER_PORT': '80',
        'SERVER_PROTOCOL': 'HTTP/1.1',
        'REMOTE_ADDR': '127.0.0.1',
        'wsgi.input': io.BytesIO(body),
        'wsgi.errors': io.BytesIO(),
        # PEP 3333 keys Werkzeug's URL routing requires (the pre-Flask bridge
        # was a bare function and didn't need these; the Flask app does).
        'wsgi.version': (1, 0),
        'wsgi.url_scheme': 'http',
        'wsgi.multithread': True,
        'wsgi.multiprocess': False,
        'wsgi.run_once': False,
    }
    if body:
        env['CONTENT_LENGTH'] = str(len(body))
        env['CONTENT_TYPE'] = 'application/json'
    for k, v in (headers or {}).items():
        env['HTTP_' + k.upper().replace('-', '_')] = v
    return env


def _call(method, path, **kw):
    cap = {}

    def start_response(status, headers):
        cap['status'] = status
        cap['headers'] = headers

    cap['body'] = b''.join(wsgi.application(_environ(method, path, **kw), start_response))
    cap['hdr'] = {h[0].lower(): h[1] for h in cap['headers']}
    return cap


class TestWsgiShim(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Don't let the per-request cadence fork network children in the test.
        cls._orig_detached = api._run_detached
        api._run_detached = lambda *a, **k: None

    @classmethod
    def tearDownClass(cls):
        api._run_detached = cls._orig_detached

    def test_health_200_json(self):
        r = _call('GET', '/api/health')
        self.assertTrue(r['status'].startswith('200'), r['status'])
        self.assertIn('content-type', r['hdr'])
        self.assertIn(b'ok', r['body'].lower())

    def test_protected_route_clean_response(self):
        # The shim must convey a protected route's response as a well-formed HTTP
        # reply (valid 3-digit status + a content-type), never a 5xx crash. The
        # actual auth verdict (401 vs 200 under demo/shared state) is covered by
        # the rest of the suite — asserting it here would be order-fragile.
        r = _call('GET', '/api/devices')
        self.assertRegex(r['status'], r'^[1-4]\d\d ', r['status'])   # not a 5xx
        self.assertIn('content-type', r['hdr'])

    def test_unknown_route_404(self):
        r = _call('GET', '/api/_definitely_not_a_route_')
        self.assertTrue(r['status'].startswith('404'), r['status'])

    def test_api_v1_alias_through_shim(self):
        # the /api/v1 alias (E2) must resolve the same as the unversioned path
        r = _call('GET', '/api/v1/health')
        self.assertTrue(r['status'].startswith('200'), r['status'])

    def test_no_load_cache_leak_between_requests(self):
        _call('GET', '/api/health')
        self.assertEqual(api._LOAD_CACHE, {}, 'load cache must be cleared after a request')
        _call('GET', '/api/health')
        self.assertEqual(api._LOAD_CACHE, {})

    def test_correlation_id_differs_per_request(self):
        r1 = _call('GET', '/api/health')
        r2 = _call('GET', '/api/health')
        a, b = r1['hdr'].get('x-request-id'), r2['hdr'].get('x-request-id')
        self.assertTrue(a and b, 'X-Request-Id should be emitted on rendered responses')
        self.assertNotEqual(a, b, 'correlation id must reset per request (no leak)')

    def test_request_env_does_not_leak(self):
        before = dict(os.environ)
        _call('GET', '/api/health', query='x=1', headers={'X-Test': 'hi'})
        after = dict(os.environ)
        leaked = {k for k in after if k not in before
                  and (k in wsgi._CGI_META or k.startswith('HTTP_'))}
        self.assertEqual(leaked, set(), f'request vars leaked into os.environ: {leaked}')
        self.assertEqual(after.get('RP_DATA_DIR'), before.get('RP_DATA_DIR'))

    def test_post_body_is_read(self):
        # Posting a JSON body must produce a clean response (a 4xx), never a 5xx
        # from a stdin/Content-Length mishap in the shim.
        r = _call('POST', '/api/devices', body=b'{"hello":"world"}')
        self.assertRegex(r['status'], r'^4\d\d ', r['status'])

    def test_httperror_headers_survive(self):
        # Regression: the non-CGI servers (this wsgi shim + the SCGI worker)
        # caught the handler HTTPError and rendered WITHOUT e.headers, so any
        # extra response header — above all the portal session Set-Cookie
        # (handle_portal_session) — was silently dropped. Sign-in "worked" (body
        # rendered) but the cookie never reached the browser, so every next
        # /api/portal/* request was 401 ("Not signed in" on submit). The WSGI
        # path must now emit HTTPError.headers, exactly like api.py's __main__.
        def _boom():
            raise api.HTTPError(200, {'ok': True},
                                headers=[('Set-Cookie',
                                          'rp_portal=abc; Path=/api/portal; HttpOnly; Secure; SameSite=Strict')])
        orig = api.main
        api.main = _boom
        try:
            r = _call('GET', '/api/anything')
        finally:
            api.main = orig
        self.assertTrue(r['status'].startswith('200'), r['status'])
        setc = [v for (k, v) in r['headers'] if k.lower() == 'set-cookie']
        self.assertTrue(setc, 'HTTPError.headers (Set-Cookie) dropped by the WSGI path')
        self.assertIn('rp_portal=abc', setc[0])
        self.assertIn('HttpOnly', setc[0])

    def test_wsgi_systemd_unit_present_and_wired(self):
        unit = _ROOT / "server" / "conf" / "remotepower-wsgi.service"
        self.assertTrue(unit.exists(), "remotepower-wsgi.service missing")
        txt = unit.read_text()
        self.assertIn("wsgi:application", txt)        # runs the shim
        self.assertIn("--threads", txt)               # threaded workers (state is thread-local)
        self.assertIn("[Install]", txt)

    def test_concurrent_requests_no_cross_thread_leak(self):
        # The shim serves requests on threads (no lock). Fire many concurrent
        # requests across distinct paths and assert: each response matches its own
        # path (no output-buffer bleed) and every correlation id is unique (no
        # _RCTX / request-id leak between threads). Validates thread-safety on the
        # SQLite backend (make test has no Postgres; the PG path is the same code).
        import threading
        cases = [('/api/health', b'"status"'), ('/api/public-info', b'server_name'),
                 ('/api/_nope_', None)]
        out, lock = [], threading.Lock()

        def worker(i):
            path, marker = cases[i % len(cases)]
            r = _call('GET', path)
            with lock:
                out.append((path, marker, r['status'], r['hdr'].get('x-request-id'), r['body']))

        ts = [threading.Thread(target=worker, args=(i,)) for i in range(24)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()

        self.assertEqual(len(out), 24)
        rids = [t[3] for t in out if t[3]]
        self.assertEqual(len(rids), len(set(rids)), "correlation ids must be unique across threads")
        for path, marker, status, rid, body in out:
            if path == '/api/_nope_':
                self.assertRegex(status, r'^404')
            else:
                self.assertRegex(status, r'^200', f'{path} -> {status}')
                self.assertIn(marker, body, f'{path} body missing {marker!r} (cross-thread bleed?)')

    def test_parse_cgi_response_helper(self):
        raw = b'Status: 201 Created\r\nContent-Type: application/json\r\n\r\n{"ok":true}'
        status, headers, body = wsgi._parse_cgi_response(raw)
        self.assertEqual(status, '201 Created')
        self.assertEqual(body, b'{"ok":true}')
        self.assertIn(('Content-Type', 'application/json'), headers)

    def test_capture_survives_external_stdout_reassignment(self):
        # v6.1.0 pentest sweep: the capture proxy was installed ONCE at
        # import time (`if not isinstance(sys.stdout, _OutProxy): sys.stdout
        # = _OutProxy(...)`). Anything that later reassigns sys.stdout
        # wholesale (a test harness's capture fixture, a logging/APM library
        # that wraps stdout) silently discards the proxy: every following
        # request's respond()/HTTPError output then writes straight to
        # whatever now owns sys.stdout instead of the per-request buffer,
        # so the WSGI response comes back with an EMPTY body while the real
        # content leaks into that other stream. _run_request() must
        # re-verify (and reinstall if needed) the proxy on every call.
        real_stdout = sys.stdout
        try:
            class _ExternalCapture:
                def __init__(self):
                    self.chunks = []
                def write(self, s):
                    self.chunks.append(s)
                    return len(s)
                def flush(self):
                    pass

            external = _ExternalCapture()
            sys.stdout = external  # simulate an external library swapping stdout
            self.assertFalse(isinstance(sys.stdout, wsgi._OutProxy))

            r = _call('GET', '/api/health')
            self.assertTrue(r['status'].startswith('200'), r['status'])
            self.assertIn(b'ok', r['body'].lower(), 'response body must not be empty')
            self.assertEqual(''.join(external.chunks), '',
                              'response content must not leak into the reassigned stdout')
        finally:
            sys.stdout = real_stdout


if __name__ == '__main__':
    unittest.main()

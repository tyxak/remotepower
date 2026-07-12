"""v6.1.0: gunicorn/Flask (server/cgi-bin/wsgi.py) is the ONLY server — the CGI
shim (api_cgi.py) and the SCGI prefork worker (api_worker.py) are retired.

These are static contract checks, replacing the old test_cgi_shim.py (which
tested the now-deleted CGI shim): the app entry point exists and is a real
Flask app, api.py stays directly importable/executable (still imported by the
WSGI bridge, cve_scan_runner.py, and the test suite), and every installer
marks wsgi.py executable and precompiles cgi-bin/."""

import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"

# Flask is a hard runtime dependency since v6.1.0, but the tests that actually
# import/exec wsgi.py must degrade to a skip (not ERROR) in a minimal env that
# lacks it — e.g. a `make dist` staged-tree run on a box without the runtime
# deps installed. CI installs flask so these still run there.
try:
    import flask  # noqa: F401

    _HAS_FLASK = True
except ImportError:
    _HAS_FLASK = False


def _maybe(p):
    p = _ROOT / p
    return p.read_text() if p.exists() else None


class TestWsgiEntrypoint(unittest.TestCase):
    def test_cgi_shim_and_scgi_worker_deleted(self):
        self.assertFalse((_CGI / "api_cgi.py").exists())
        self.assertFalse((_CGI / "api_worker.py").exists())

    def test_wsgi_is_a_real_flask_app(self):
        src = (_CGI / "wsgi.py").read_text()
        self.assertIn("from flask import", src)
        self.assertIn("application = Flask(", src)

    @unittest.skipUnless(_HAS_FLASK, "flask not installed")
    def test_no_flask_default_static_route(self):
        # Flask registers /static/<path:filename> by default, served by
        # Flask's own handler — a code path that bypasses api.main() entirely
        # (no CSRF/auth/read-only/IP-allowlist enforcement). The catch-all
        # route must be the ONLY route.
        import importlib.util
        import os
        import sys
        import tempfile

        os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-wsgi-static-test-"))
        sys.path.insert(0, str(_CGI))
        spec = importlib.util.spec_from_file_location("wsgi_static_test", _CGI / "wsgi.py")
        wsgi = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(wsgi)
        rules = {str(r) for r in wsgi.application.url_map.iter_rules()}
        self.assertNotIn("/static/<path:filename>", rules)

    @unittest.skipUnless(_HAS_FLASK, "flask not installed")
    def test_nonstandard_method_reaches_api_main(self):
        # v6.1.0 pentest sweep: the catch-all route only lists 7 explicit
        # methods (Werkzeug requires an explicit list), so any other verb
        # used to get a framework-generated 405 before api.main() ever ran —
        # unlike every prior transport, which passed any REQUEST_METHOD
        # through unconditionally. The errorhandler(405) fallback must
        # restore that: a PROPFIND to a real API route should reach api.py's
        # own routing/auth (a 401, not a Werkzeug 405 HTML page).
        import importlib.util
        import os
        import sys
        import tempfile

        os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-wsgi-405-test-"))
        sys.path.insert(0, str(_CGI))
        spec = importlib.util.spec_from_file_location("wsgi_405_test", _CGI / "wsgi.py")
        wsgi = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(wsgi)
        client = wsgi.application.test_client()
        resp = client.open("/api/devices", method="PROPFIND")
        self.assertNotEqual(resp.status_code, 405)
        self.assertEqual(resp.content_type, "application/json")

    @unittest.skipUnless(_HAS_FLASK, "flask not installed")
    def test_span_recorded_for_real_request(self):
        # v6.1.1 (#48): confirm the wsgi.py _run_request hook actually wires
        # up end-to-end through a real Flask test-client request — not just
        # api._otlp_record_span in isolation (test_v3140.TestOtlpTraceExport
        # covers that unit). A request is made whether or not it reaches an
        # authenticated handler (this one 401s), so the span must still be
        # recorded regardless of status code.
        import importlib.util
        import os
        import sys
        import tempfile

        os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-wsgi-span-test-"))
        sys.path.insert(0, str(_CGI))
        spec = importlib.util.spec_from_file_location("wsgi_span_test", _CGI / "wsgi.py")
        wsgi = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(wsgi)

        posts = []
        wsgi.api._siem_post = lambda url, data, headers, cfg: posts.append((url, data, headers))
        wsgi.api.save(
            wsgi.api.CONFIG_FILE,
            {
                "otlp_enabled": True,
                "otlp_traces_enabled": True,
                "otlp_endpoint": "http://collector:4318",
                "otlp_traces_interval": 15,
            },
        )
        client = wsgi.application.test_client()
        resp = client.get("/api/devices")
        self.assertEqual(resp.status_code, 401)  # unauthenticated — span still recorded
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0][0], "http://collector:4318/v1/traces")
        import json as _json

        span = _json.loads(posts[0][1])["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
        self.assertEqual(span["name"], "GET /api/devices")
        self.assertEqual(span["attributes"][2]["value"]["intValue"], "401")

    def test_api_py_still_directly_executable(self):
        # api.py must keep its __main__ entry block and stay importable — the
        # WSGI app imports it once per worker, and tools like cve_scan_runner.py
        # spawn it as a standalone process.
        api = _CGI / "api.py"
        self.assertIn("if __name__ == '__main__':", api.read_text())

    def test_installers_chmod_and_precompile_wsgi(self):
        for rel in ("install-server.sh", "install.sh", "deploy-server.sh", "Dockerfile"):
            txt = _maybe(rel)
            if txt is None:
                continue
            self.assertIn("wsgi.py", txt, f"{rel}: entry point not installed +x")
            self.assertIn("compileall", txt, f"{rel}: missing precompile step")

    def test_aur_package_installs_wsgi_and_compiles(self):
        inst = _maybe("packaging/aur/remotepower-server/remotepower-server.install")
        pkgb = _maybe("packaging/aur/remotepower-server/PKGBUILD")
        if inst is not None:
            self.assertIn("compileall", inst)
        if pkgb is not None:
            self.assertIn("wsgi.py", pkgb)


if __name__ == "__main__":
    unittest.main()

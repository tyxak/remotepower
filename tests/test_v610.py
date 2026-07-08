"""Strict version-surface + feature pins for v6.1.0 "Runt1meMatters" — the
enterprise-productization release: Postgres + the out-of-band scheduler + a
co-located scanner satellite are the single-node default, and the server
runs entirely on gunicorn + Flask (CGI/fcgiwrap and the SCGI worker retired).

Loosen TestVersionBumps to dynamic (V = api.SERVER_VERSION) on the NEXT bump.
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v610-test-"))
_spec = importlib.util.spec_from_file_location("api_v610_ver", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _html():
    return (_ROOT / "server/html/index.html").read_text()


class TestVersionBumps(unittest.TestCase):
    V = "6.1.0"

    def test_server_version(self):
        self.assertEqual(api.SERVER_VERSION, self.V)

    def test_agent_versions(self):
        self.assertIn(
            f"VERSION      = '{self.V}'", (_ROOT / "client/remotepower-agent.py").read_text()
        )
        for rel in ("client/remotepower-agent-win.py", "client/remotepower-agent-mac.py"):
            self.assertIn(f"VERSION = '{self.V}'", (_ROOT / rel).read_text(), rel)

    def test_agent_extensionless_in_sync(self):
        self.assertEqual(
            (_ROOT / "client/remotepower-agent.py").read_bytes(),
            (_ROOT / "client/remotepower-agent").read_bytes(),
        )

    def test_sw_and_cachebust(self):
        self.assertIn(f"remotepower-shell-v{self.V}", (_ROOT / "server/html/sw.js").read_text())
        self.assertIn(f"?v={self.V}", _html())

    def test_no_stale_cachebust(self):
        self.assertNotIn("?v=6.0.1", _html())

    def test_readme_and_changelog(self):
        self.assertIn(f"version-{self.V}-blue", (_ROOT / "README.md").read_text())
        self.assertIn(f"v{self.V}", (_ROOT / "CHANGELOG.md").read_text()[:2000])

    def test_version_doc_exists(self):
        self.assertTrue((_ROOT / f"docs/v{self.V}.md").exists())

    def test_doc_set_keeps_five_versions(self):
        vdocs = sorted(p.name for p in (_ROOT / "docs").glob("v[0-9]*.md"))
        self.assertEqual(len(vdocs), 5, f"expected exactly 5 version docs, got {vdocs}")

    def test_whats_new_card_present(self):
        self.assertIn(f"What's new — v{self.V}", _html())

    def test_changelog_header_is_runt1mematters(self):
        head = (_ROOT / "CHANGELOG.md").read_text()[:400]
        self.assertIn('## v6.1.0 — "Runt1meMatters"', head)


class TestRunt1meMattersFeatures(unittest.TestCase):
    def test_install_server_defaults_enterprise_topology(self):
        src = (_ROOT / "install-server.sh").read_text()
        self.assertIn('WITH_POSTGRES="${RP_WITH_POSTGRES:-1}"', src)
        self.assertIn('WITH_SCHEDULER="${RP_WITH_SCHEDULER:-1}"', src)
        self.assertIn('WITH_SCANNER="${RP_WITH_SCANNER:-1}"', src)

    def test_docker_compose_defaults_enterprise_topology(self):
        compose = (_ROOT / "docker-compose.yml").read_text()
        self.assertIn('RP_STORAGE_BACKEND: "postgres"', compose)
        self.assertIn("\n  scanner:\n", compose)

    def test_cgi_and_scgi_deleted(self):
        self.assertFalse((_CGI / "api_cgi.py").exists())
        self.assertFalse((_CGI / "api_worker.py").exists())

    def test_wsgi_is_flask_app(self):
        src = (_CGI / "wsgi.py").read_text()
        self.assertIn("application = Flask(", src)

    def test_agent_install_reads_request_scoped_environ(self):
        # The fixed bug: handle_agent_install() must use the thread-local
        # per-request environ (_RCTX), not bare os.environ, for host/token.
        src = (_CGI / "api.py").read_text()
        i = src.index("def handle_agent_install")
        body = src[i : i + 800]
        self.assertIn("getattr(_RCTX, 'environ', None) or os.environ", body)


class TestClientIpBehindLocalProxy(unittest.TestCase):
    """v6.1.0 pentest sweep: the CGI->proxy_pass cutover made REMOTE_ADDR
    always be nginx's own loopback peer. _get_client_ip() must now trust
    X-Forwarded-For/X-Real-IP whenever the immediate peer IS loopback, with
    no operator config required (a real remote client can't forge
    REMOTE_ADDR==loopback)."""

    def setUp(self):
        api.save(api.CONFIG_FILE, {})  # trust_proxy off

    def tearDown(self):
        for k in ('REMOTE_ADDR', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP'):
            os.environ.pop(k, None)

    def test_loopback_peer_trusts_x_forwarded_for(self):
        os.environ['REMOTE_ADDR'] = '127.0.0.1'
        os.environ['HTTP_X_FORWARDED_FOR'] = '203.0.113.7'
        self.assertEqual(api._get_client_ip(), '203.0.113.7')

    def test_loopback_peer_trusts_x_real_ip_when_no_xff(self):
        os.environ['REMOTE_ADDR'] = '127.0.0.1'
        os.environ['HTTP_X_REAL_IP'] = '203.0.113.9'
        self.assertEqual(api._get_client_ip(), '203.0.113.9')

    def test_ipv6_loopback_peer_also_trusted(self):
        os.environ['REMOTE_ADDR'] = '::1'
        os.environ['HTTP_X_FORWARDED_FOR'] = '203.0.113.11'
        self.assertEqual(api._get_client_ip(), '203.0.113.11')

    def test_non_loopback_peer_without_trust_proxy_still_uses_remote_addr(self):
        # Not a local-proxy hop and trust_proxy is off — unchanged behaviour,
        # a directly-connecting client's header can't override REMOTE_ADDR.
        os.environ['REMOTE_ADDR'] = '198.51.100.5'
        os.environ['HTTP_X_FORWARDED_FOR'] = '203.0.113.13'
        self.assertEqual(api._get_client_ip(), '198.51.100.5')

    def test_loopback_peer_no_headers_falls_back_to_remote_addr(self):
        os.environ['REMOTE_ADDR'] = '127.0.0.1'
        self.assertEqual(api._get_client_ip(), '127.0.0.1')


class TestWsgiAcceptsAnyMethod(unittest.TestCase):
    """v6.1.0 pentest sweep: the Flask catch-all route only lists 7 explicit
    methods, so Werkzeug auto-405'd anything else before api.main() ever ran
    — unlike every prior transport. An errorhandler(405) must re-run the
    same request through _run_request so any verb still reaches api.py."""

    def test_405_errorhandler_falls_through_to_run_request(self):
        src = (_CGI / "wsgi.py").read_text()
        self.assertIn("@application.errorhandler(405)", src)
        i = src.index("@application.errorhandler(405)")
        body = src[i : i + 700]
        self.assertIn("_run_request(request.environ)", body)


class TestPostgresMigrationGatedOnLiveData(unittest.TestCase):
    """v6.1.0 pentest sweep: .pg_migrated (and users.json alone) lived on the
    independently-resettable app-data volume, so resetting it looked like
    "first boot" to a Postgres store that already held real data --
    silently overwriting it, or printing admin credentials that could never
    log in. Both gates must instead key off a live query against Postgres
    itself (PG_HAS_USERS)."""

    SRC = (_ROOT / "docker" / "entrypoint.sh").read_text()

    def test_queries_postgres_directly_for_existing_users(self):
        self.assertIn("PG_HAS_USERS", self.SRC)
        self.assertIn("storage_pg.load(Path('/var/lib/remotepower/users.json'))", self.SRC)

    def test_admin_bootstrap_gated_on_pg_has_users(self):
        i = self.SRC.index('if [ ! -f "$USERS_FILE" ]')
        self.assertIn('PG_HAS_USERS', self.SRC[i : i + 120])

    def test_migration_gated_on_pg_has_users_not_marker_file(self):
        i = self.SRC.index("RP_STORAGE_BACKEND=postgres — migrating bootstrap data")
        cond = self.SRC[i - 400 : i]
        self.assertIn('"$PG_HAS_USERS" != "yes"', cond)
        self.assertNotIn(".pg_migrated", cond)


class TestSelfSignedCertCoversScannerHostname(unittest.TestCase):
    """Real-world sweep: the co-located `scanner` service (docker-compose.yml)
    connects to https://remotepower:8443 -- the fixed Docker Compose service
    name -- but the self-signed cert was issued with only RP_TLS_HOST (the
    operator's external hostname) as a SAN, so the scanner's cert-pinned TLS
    verification always failed with a hostname mismatch. rp-gen-ca must be
    called with "remotepower" as an additional --host SAN."""

    SRC = (Path(__file__).parent.parent / "docker" / "entrypoint.sh").read_text()

    def test_gen_ca_includes_remotepower_san(self):
        i = self.SRC.index("rp-gen-ca --host")
        line = self.SRC[i : i + 200]
        self.assertIn('--host "$TLS_HOST"', line)
        self.assertIn("--host remotepower", line)


if __name__ == "__main__":
    unittest.main()

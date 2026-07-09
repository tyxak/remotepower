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


class TestInstallServerAdminUserIdempotent(unittest.TestCase):
    """Re-running install-server.sh on an EXISTING install previously
    overwrote the current admin account unconditionally (no users.json-exists
    guard, unlike every other step in the script). That made it unsafe to
    call install-server.sh a second time -- including from the new
    convert-to-wsgi.sh conversion script, which needs to."""

    SRC = (Path(__file__).parent.parent / "install-server.sh").read_text()

    def test_admin_creation_guarded_on_users_file(self):
        i = self.SRC.index("Creating admin user")
        block = self.SRC[i - 200 : i]
        self.assertIn("if [[ -f /var/lib/remotepower/users.json ]]", block)

    def test_skip_message_present(self):
        self.assertIn("Admin user already exists", self.SRC)


class TestConvertToWsgiScript(unittest.TestCase):
    """packaging/convert-to-wsgi.sh -- self-detecting pre-6.1.0 -> gunicorn/
    Flask conversion. Source-text assertions matching the pattern used across
    this suite for installer/packaging surfaces (no root/systemd in CI)."""

    _ROOT = Path(__file__).parent.parent
    SCRIPT_PATH = _ROOT / "packaging" / "convert-to-wsgi.sh"
    SRC = SCRIPT_PATH.read_text() if SCRIPT_PATH.exists() else ""

    def test_script_exists_and_executable(self):
        self.assertTrue(self.SCRIPT_PATH.exists())
        self.assertTrue(os.access(self.SCRIPT_PATH, os.X_OK), "convert-to-wsgi.sh must be +x")

    def test_bash_syntax_valid(self):
        import subprocess

        r = subprocess.run(["bash", "-n", str(self.SCRIPT_PATH)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_detects_existing_wsgi_before_reinstalling(self):
        self.assertIn("systemctl is-active --quiet remotepower-wsgi", self.SRC)

    def test_wsgi_active_check_also_verifies_flask_importable(self):
        # Real-world bug: a pre-v6.1.0 "experimental" opt-in WSGI bridge used
        # the SAME systemd unit name (remotepower-wsgi) without needing
        # Flask. Checking only "is the service active" reports a box as
        # already-converted while Flask is still missing -- confirmed live,
        # gunicorn's workers crash-looped on ModuleNotFoundError the moment
        # this session's Flask-based wsgi.py got deployed onto one. The
        # active-check must also confirm Flask is importable.
        i = self.SRC.index("wsgi_active()")
        body = self.SRC[i : i + 300]
        self.assertIn("import flask", body)

    def test_calls_install_server_transport_only(self):
        self.assertIn("install-server.sh", self.SRC)
        self.assertIn("--no-postgres --no-scheduler --no-scanner", self.SRC)

    def test_health_checks_before_touching_old_services(self):
        # The health-check block must appear BEFORE the fcgiwrap
        # stop/disable block, so a failed conversion never tears down a
        # still-working old transport.
        i_health = self.SRC.index("Health-checking the gunicorn tier")
        i_fcgiwrap = self.SRC.index("fcgiwrap.socket")
        self.assertLess(i_health, i_fcgiwrap)

    def test_stops_old_fcgiwrap_and_scgi_worker(self):
        self.assertIn("systemctl disable --now fcgiwrap", self.SRC)
        self.assertIn("remotepower-api.service", self.SRC)

    def test_removes_stranded_cgi_entry_points(self):
        self.assertIn("api_cgi.py", self.SRC)
        self.assertIn("api_worker.py", self.SRC)

    def test_detects_and_upgrades_demo_vhost(self):
        self.assertIn("remotepower-demo", self.SRC)
        self.assertIn("remotepower-wsgi-demo", self.SRC)
        self.assertIn("install-demo.sh", self.SRC)

    def test_has_dry_run_flag(self):
        self.assertIn("--dry-run", self.SRC)

    def test_never_touches_storage_backend_flags(self):
        # This is a transport-only conversion -- must never pass
        # --with-postgres or otherwise opt someone into the newer topology.
        self.assertNotIn("--with-postgres", self.SRC)
        self.assertNotIn("--with-scheduler", self.SRC)
        self.assertNotIn("--with-scanner", self.SRC)

    def test_demo_backend_matches_main_install(self):
        # The demo's storage backend should MATCH whatever the main install
        # ended up on (transport-only conversion), not be forced to Postgres
        # unconditionally.
        self.assertIn("MAIN_IS_POSTGRES", self.SRC)
        self.assertIn("DEMO_IS_POSTGRES", self.SRC)
        self.assertIn("--postgres", self.SRC)


class TestInstallDemoPostgresOption(unittest.TestCase):
    """packaging/install-demo.sh --postgres: provisions a SEPARATE demo
    database and migrates the seeded JSON data into it, matching the pattern
    install-server.sh already uses for the main install."""

    SRC = (Path(__file__).parent.parent / "packaging" / "install-demo.sh").read_text()

    def test_bash_syntax_valid(self):
        import subprocess

        r = subprocess.run(
            ["bash", "-n", str(Path(__file__).parent.parent / "packaging" / "install-demo.sh")],
            capture_output=True,
            text=True,
        )
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_postgres_flag_present(self):
        self.assertIn("--postgres)", self.SRC)
        self.assertIn("WITH_POSTGRES", self.SRC)

    def test_uses_separate_demo_database(self):
        self.assertIn("remotepower_demo", self.SRC)
        self.assertIn("rp_demo", self.SRC)
        # Must never reuse the main install's own database/role names.
        self.assertNotIn('RP_DB_NAME:-remotepower}"', self.SRC)

    def test_migrates_via_api_migrate_storage_pg(self):
        self.assertIn("api._migrate_storage_pg", self.SRC)
        self.assertIn("postgres-setup.sh", self.SRC)

    def test_seed_runs_before_migration(self):
        i_seed = self.SRC.index("Seeding fake homelab data")
        i_migrate = self.SRC.index("api._migrate_storage_pg")
        self.assertLess(i_seed, i_migrate)

    def test_default_stays_json_backend(self):
        # --postgres is opt-in; without it the demo must stay on flat-JSON.
        self.assertIn("flat-JSON", self.SRC)

    def test_uninstall_warns_about_postgres_cleanup(self):
        i = self.SRC.index("--uninstall")
        block = self.SRC[i : i + 1500]
        self.assertIn("storage_backend.json", block)
        self.assertIn("dropdb", block)


class TestInstallShUpdateCommand(unittest.TestCase):
    """install.sh's `update` subcommand: previously a stub, now dispatches to
    deploy-server.sh (already-current installs) or packaging/convert-to-wsgi.sh
    (pre-6.1.0 CGI/SCGI installs), matching the same self-detection story."""

    SRC = (Path(__file__).parent.parent / "install.sh").read_text()

    def test_bash_syntax_valid(self):
        import subprocess

        r = subprocess.run(
            ["bash", "-n", str(Path(__file__).parent.parent / "install.sh")],
            capture_output=True,
            text=True,
        )
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_update_no_longer_a_stub(self):
        i = self.SRC.index('case "$CMD" in')
        dispatch = self.SRC[i : i + 400]
        self.assertIn("update) cmd_update", dispatch)
        # The old stub case handled tls/passwd/update together; update must
        # no longer be one of the commands routed to that stub message.
        stub_case = self.SRC[self.SRC.index("tls|passwd)") : self.SRC.index("is part of the unified tool")]
        self.assertNotIn("update", stub_case)

    def test_detects_docker_and_refuses(self):
        i = self.SRC.index("cmd_update()")
        body = self.SRC[i : i + 1500]
        self.assertIn("/.dockerenv", body)
        self.assertIn("docker compose", body)

    def test_detects_no_existing_install(self):
        i = self.SRC.index("cmd_update()")
        body = self.SRC[i : i + 1500]
        self.assertIn("/var/www/remotepower", body)

    def test_dispatches_to_deploy_or_convert(self):
        i = self.SRC.index("cmd_update()")
        body = self.SRC[i : i + 2000]
        self.assertIn("deploy-server.sh", body)

    def test_cheap_deploy_path_also_verifies_flask_importable(self):
        # Same real-world bug as convert-to-wsgi.sh's wsgi_active(): a
        # service named remotepower-wsgi being active doesn't guarantee
        # Flask is installed (a pre-v6.1.0 experimental WSGI bridge used the
        # same unit name without needing it). The cheap deploy-only path
        # must not be taken unless Flask is confirmed importable too.
        i = self.SRC.index("cmd_update()")
        body = self.SRC[i : i + 2500]
        i_check = body.index("systemctl is-active --quiet remotepower-wsgi")
        cond = body[i_check : i_check + 150]
        self.assertIn("import flask", cond)
        self.assertIn("convert-to-wsgi.sh", body)

    def test_doctor_reports_transport_state(self):
        self.assertIn("transport_state()", self.SRC)
        i = self.SRC.index("transport_state()")
        body = self.SRC[i : i + 400]
        self.assertIn("remotepower-wsgi", body)

    def test_doctor_checks_disk_space(self):
        self.assertIn("disk_free_mb", self.SRC)

    def test_doctor_names_port_conflict_owner(self):
        self.assertIn("port_owner()", self.SRC)

    def test_doctor_detects_container(self):
        i = self.SRC.index("preflight()")
        body = self.SRC[i : i + 800]
        self.assertIn("/.dockerenv", body)


class TestDeployServerInstallsMissingFlask(unittest.TestCase):
    """deploy-server.sh only ever redeploys code, by design (see its own
    header: "Does NOT touch Nginx config") -- it never installed packages.
    That's exactly what let a real upgrade crash: a pre-v6.1.0 experimental
    WSGI bridge had the remotepower-wsgi.service unit already installed
    without Flask; deploying this session's Flask-based wsgi.py onto it and
    restarting crash-looped every worker. Flask/gunicorn are hard
    dependencies now, not optional -- deploy-server.sh must check and
    install them before it restarts a unit that needs them."""

    SRC = (Path(__file__).parent.parent / "deploy-server.sh").read_text()

    def test_bash_syntax_valid(self):
        import subprocess

        r = subprocess.run(
            ["bash", "-n", str(Path(__file__).parent.parent / "deploy-server.sh")],
            capture_output=True,
            text=True,
        )
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_checks_flask_before_restarting_wsgi(self):
        i_check = self.SRC.index("import flask")
        i_restart = self.SRC.index("for _svc in remotepower-wsgi")
        self.assertLess(i_check, i_restart,
                         "Flask check must run before the restart loop, not after")

    def test_installs_via_package_manager_not_bare_pip(self):
        # The bug that caused this fix in the first place (blinker installed
        # by apt, pip refusing to override it) means the distro package must
        # be tried first, matching install-server.sh's own pattern.
        self.assertIn("python3-flask", self.SRC)
        self.assertIn("--break-system-packages", self.SRC)

    def test_only_triggers_when_wsgi_service_is_installed(self):
        # Must not try to install Flask on a box that's still on plain CGI
        # with no remotepower-wsgi unit at all -- that's convert-to-wsgi.sh's
        # job, not deploy-server.sh's.
        i = self.SRC.index("import flask")
        block = self.SRC[max(0, i - 500) : i]
        self.assertIn("systemctl list-unit-files", block)


if __name__ == "__main__":
    unittest.main()

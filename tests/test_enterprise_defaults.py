#!/usr/bin/env python3
"""
Guardrail tests for the single-node "enterprise" default topology
(Postgres + WSGI/gunicorn + out-of-band scheduler + a co-located scanner
satellite, default-on in both install-server.sh and docker-compose.yml).

Source-text assertions only — no bash/docker execution — matching the
pattern used across this suite for installer/packaging surfaces.
"""

import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_INSTALL = (_ROOT / "install-server.sh").read_text()
_COMPOSE = (_ROOT / "docker-compose.yml").read_text()
_ENTRYPOINT = (_ROOT / "docker" / "entrypoint.sh").read_text()
_DOCKERFILE = (_ROOT / "Dockerfile").read_text()


class TestInstallServerDefaults(unittest.TestCase):
    def test_gunicorn_and_flask_installed_unconditionally(self):
        # No app-server choice anymore — gunicorn/Flask is the only server.
        self.assertIn("import flask", _INSTALL)
        self.assertIn("command -v gunicorn", _INSTALL)
        self.assertNotIn("APP_SERVER", _INSTALL)

    def test_cgi_fcgiwrap_fully_retired(self):
        # "fcgiwrap"/"api_cgi.py" as PACKAGE/FILE references must be gone;
        # the one narrative "CGI/fcgiwrap is retired" comment is fine.
        self.assertNotIn("install fcgiwrap", _INSTALL)
        self.assertNotIn("enable --now fcgiwrap", _INSTALL)
        self.assertNotIn("api_cgi.py", _INSTALL)

    def test_scheduler_postgres_scanner_default_on(self):
        self.assertIn('WITH_SCHEDULER="${RP_WITH_SCHEDULER:-1}"', _INSTALL)
        self.assertIn('WITH_POSTGRES="${RP_WITH_POSTGRES:-1}"', _INSTALL)
        self.assertIn('WITH_SCANNER="${RP_WITH_SCANNER:-1}"', _INSTALL)

    def test_opt_out_flags_present(self):
        for flag in ("--no-scheduler", "--no-postgres", "--no-scanner"):
            self.assertIn(flag, _INSTALL, flag)

    def test_psycopg_installed_when_postgres_requested(self):
        self.assertIn("import psycopg", _INSTALL)
        self.assertIn("psycopg[binary]", _INSTALL)

    def test_scanner_setup_wired_in(self):
        self.assertIn("packaging/scanner-setup.sh", _INSTALL)
        self.assertIn("--mint-local", _INSTALL)

    def test_postgres_migration_runs_bootstrap_data_in(self):
        # The admin user + scanner token are always JSON-file writes; when
        # Postgres is selected they must be migrated in, not left stranded.
        self.assertIn("_migrate_storage_pg", _INSTALL)
        self.assertIn("'postgres'", _INSTALL)

    def test_scanner_setup_runs_before_postgres_migration(self):
        # Otherwise the scanner token is minted into the JSON file AFTER the
        # migration already ran and is never carried into Postgres.
        scanner_pos = _INSTALL.index("packaging/scanner-setup.sh")
        migrate_pos = _INSTALL.index("_migrate_storage_pg")
        self.assertLess(scanner_pos, migrate_pos)


class TestScannerSetupScript(unittest.TestCase):
    SRC = (_ROOT / "packaging" / "scanner-setup.sh").read_text()

    def test_mint_local_writes_satellites_json(self):
        self.assertIn("--mint-local", self.SRC)
        self.assertIn("satellites.json", self.SRC)
        self.assertIn("'scanner': True", self.SRC)

    def test_no_docker_socket_dependency_required(self):
        # docker.sock must never be mounted/required by default — see the
        # CLAUDE.md rule this script's own header cites.
        self.assertNotIn("docker.sock", self.SRC)

    def test_warns_about_colocation_tradeoff(self):
        self.assertIn("co-located", self.SRC.lower())


class TestDockerComposeDefaults(unittest.TestCase):
    def test_postgres_service_active_not_commented(self):
        self.assertIn("\n  postgres:\n", _COMPOSE)
        self.assertNotIn("#   postgres:", _COMPOSE)

    def test_scanner_service_present(self):
        self.assertIn("\n  scanner:\n", _COMPOSE)
        self.assertIn("Dockerfile.scanner", _COMPOSE)

    def test_enterprise_env_vars_active_not_commented(self):
        for line in (
            'RP_EXTERNAL_SCHEDULER: "1"',
            'RP_STORAGE_BACKEND: "postgres"',
            'RP_WITH_SCANNER: "1"',
        ):
            self.assertIn(line, _COMPOSE, line)
            self.assertNotIn("# " + line, _COMPOSE, line)

    def test_remotepower_depends_on_postgres_healthy(self):
        self.assertIn("condition: service_healthy", _COMPOSE)

    def test_postgres_not_exposed_to_host(self):
        # No `ports:` mapping under the postgres service — only reachable
        # from other containers on the compose network.
        pg_block = _COMPOSE.split("\n  postgres:\n", 1)[1].split("\n  scanner:", 1)[0]
        self.assertNotIn("\n    ports:", pg_block)


class TestDockerEntrypointBootstrap(unittest.TestCase):
    def test_scanner_token_minted_idempotently(self):
        self.assertIn(".scanner-token", _ENTRYPOINT)
        self.assertIn("RP_WITH_SCANNER", _ENTRYPOINT)

    def test_postgres_auto_migration_present(self):
        self.assertIn("_migrate_storage_pg", _ENTRYPOINT)
        self.assertIn(".pg_migrated", _ENTRYPOINT)

    def test_migration_clears_storage_backend_env_for_source_read(self):
        # Otherwise `load()` inside the migration reads from (empty) Postgres
        # instead of the just-written JSON source data.
        self.assertIn("env -u RP_STORAGE_BACKEND", _ENTRYPOINT)

    def test_gunicorn_starts_unconditionally(self):
        self.assertNotIn("fcgiwrap", _ENTRYPOINT)
        self.assertNotIn("RP_APP_SERVER", _ENTRYPOINT)
        self.assertIn("gunicorn", _ENTRYPOINT)

    def test_warns_on_default_postgres_password(self):
        self.assertIn("remotepower-dev-changeme", _ENTRYPOINT)
        self.assertIn("DEFAULT POSTGRES PASSWORD", _ENTRYPOINT)


class TestDockerfileDeps(unittest.TestCase):
    def test_psycopg_binary_installed(self):
        self.assertIn("psycopg[binary]", _DOCKERFILE)

    def test_flask_installed_fcgiwrap_removed(self):
        self.assertIn("flask", _DOCKERFILE)
        # fcgiwrap/spawn-fcgi must not be an installed PACKAGE (a "retired"
        # comment mentioning the word doesn't count) — check the actual
        # apt-get install block, not the whole file.
        start = _DOCKERFILE.index("apt-get install")
        end = _DOCKERFILE.index("pip install", start)
        install_block = _DOCKERFILE[start:end]
        self.assertNotIn("fcgiwrap", install_block)
        self.assertNotIn("spawn-fcgi", install_block)


class TestCgiScgiFullyRetired(unittest.TestCase):
    """server/cgi-bin/api_cgi.py and api_worker.py are deleted; nginx configs
    and packaging no longer reference fcgiwrap/SCGI anywhere."""

    def test_api_cgi_and_api_worker_deleted(self):
        self.assertFalse((_ROOT / "server" / "cgi-bin" / "api_cgi.py").exists())
        self.assertFalse((_ROOT / "server" / "cgi-bin" / "api_worker.py").exists())

    def test_nginx_configs_are_proxy_pass_only(self):
        for rel in ("server/conf/remotepower-locations.conf", "docker/nginx-docker-locations.conf"):
            text = (_ROOT / rel).read_text()
            self.assertNotIn("fcgiwrap", text, rel)
            self.assertNotIn("api_cgi.py", text, rel)
            self.assertIn("proxy_pass http://127.0.0.1:8090", text, rel)


if __name__ == "__main__":
    unittest.main()

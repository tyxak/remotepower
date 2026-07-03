"""Strict version-surface pins for v5.8.0 (unreleased, test) — the TLS-schedule
fix + GitHub issue monitor release: TLS/DANE expiry probing now runs on the
server's own maintenance cadence (was cron-only and backend-blind), and a new
`github` connector raises edge-triggered `github_new_issue` alerts for newly
opened issues on watched repositories.

Loosen TestVersionBumps to dynamic (V = api.SERVER_VERSION) on the NEXT bump,
the same way test_v550 / test_v560 / test_v570 were loosened.
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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v580-test-"))
_spec = importlib.util.spec_from_file_location("api_v580_ver", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import integrations as I  # noqa: E402


def _html():
    return (_ROOT / "server/html/index.html").read_text()


class TestVersionBumps(unittest.TestCase):
    V = "5.8.0"

    def test_server_version(self):
        self.assertEqual(api.SERVER_VERSION, self.V)

    def test_agent_versions(self):
        self.assertIn(f"VERSION      = '{self.V}'",
                      (_ROOT / "client/remotepower-agent.py").read_text())
        for rel in ("client/remotepower-agent-win.py", "client/remotepower-agent-mac.py"):
            self.assertIn(f"VERSION = '{self.V}'", (_ROOT / rel).read_text(), rel)

    def test_agent_extensionless_in_sync(self):
        self.assertEqual((_ROOT / "client/remotepower-agent.py").read_bytes(),
                         (_ROOT / "client/remotepower-agent").read_bytes())

    def test_sw_and_cachebust(self):
        self.assertIn(f"remotepower-shell-v{self.V}",
                      (_ROOT / "server/html/sw.js").read_text())
        self.assertIn(f"?v={self.V}", _html())

    def test_no_stale_cachebust(self):
        # every ?v= must be the current version — no lingering 5.7.0 busts
        self.assertNotIn("?v=5.7.0", _html())

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


class TestDistExcludesLocalTooling(unittest.TestCase):
    """The release tarball is built from the WORKING TREE (tar, not git
    archive), so untracked/gitignored local files ship unless the
    hand-maintained exclude list names them. `.claude/` (session tooling)
    leaked into the published v5.2.0–v5.7.0 tarballs this way — benign
    content, but it must never recur."""

    def test_dist_excludes(self):
        mk = (_ROOT / "Makefile").read_text()
        self.assertIn("--exclude='./.claude'", mk)
        self.assertIn("--exclude='./design'", mk)


class TestTlsScheduleWiring(unittest.TestCase):
    """The v5.8.0 fix: the server owns the TLS re-probe cadence (was cron-only)."""

    def test_sweep_exists_and_registered(self):
        self.assertTrue(callable(getattr(api, "run_tls_scan_if_due", None)))
        src = (_CGI / "api.py").read_text()
        self.assertIn("_safe(run_tls_scan_if_due, 'run_tls_scan_if_due')", src)
        self.assertIn("'run_tls_scan_if_due',", (_CGI / "scheduler.py").read_text())

    def test_cadence_constants(self):
        self.assertEqual(api.TLS_SCAN_INTERVAL, 6 * 3600)
        self.assertGreater(api.TLS_MAX_PER_RUN, 0)
        self.assertGreater(api.TLS_RUN_BUDGET, 0)


class TestGithubIssueMonitorWiring(unittest.TestCase):
    """The v5.8.0 feature: github connector + github_new_issue alert event."""

    def test_connector_registered(self):
        self.assertIn("github", I.CONNECTORS)
        self.assertTrue(I._STATS.get("github"))

    def test_event_registered_everywhere(self):
        self.assertIn("github_new_issue", api.WEBHOOK_EVENT_NAMES)
        self.assertEqual(api.EVENT_REGISTRY["github_new_issue"]["kind"], "github_issue")
        self.assertIn("github_issue", {k[0] for k in api.CHANNEL_KINDS})

    def test_default_routing_inbox_on_paging_off(self):
        slot = api._kind_default("github_issue")
        self.assertTrue(slot["alerts"])
        self.assertFalse(slot["webhook"])
        self.assertFalse(slot["needs_attention"])

    def test_frontend_feed_wired(self):
        js = (_ROOT / "server/html/static/js/app.js").read_text()
        self.assertIn("'github_new_issue',", js)          # FLEET_EVENTS
        self.assertIn("case 'github_new_issue':", js)     # _homeActivityAttrs + detail


if __name__ == "__main__":
    unittest.main()

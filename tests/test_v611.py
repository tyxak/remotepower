"""Strict version-surface + feature pins for v6.1.1 "HardenMatters" — a broad
correctness-and-coverage pass: cross-tenant security fixes, step-up re-auth,
litigation hold, a STRIDE threat model, a full accessibility pass, real
per-package patch-pin enforcement, invoice PDFs + payment-webhook
reconciliation, a fleet query engine, distributed tracing, and a long tail
of smaller features and fixes found across the whole product.

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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v611-test-"))
_spec = importlib.util.spec_from_file_location("api_v611_ver", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _html():
    return (_ROOT / "server/html/index.html").read_text()


class TestVersionBumps(unittest.TestCase):
    V = "6.1.1"

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
        self.assertNotIn("?v=6.1.0", _html())

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

    def test_changelog_header_is_hardenmatters(self):
        head = (_ROOT / "CHANGELOG.md").read_text()[:400]
        self.assertIn('## v6.1.1 — "HardenMatters"', head)


class TestApiKeyTenantIsolationFix(unittest.TestCase):
    """A real cross-tenant bypass: an API key with no tenant of its own
    resolved as a full superadmin key once tenancy enforcement was on. Keys
    must now get their own tenant_id, and the list handler must be scoped."""

    SRC = (_CGI / "api.py").read_text()

    def test_apikey_gets_own_tenant_id_at_creation(self):
        i = self.SRC.index("def handle_apikeys_create")
        j = self.SRC.index("\ndef ", i + 10)
        self.assertIn("'tenant_id':", self.SRC[i:j])

    def test_caller_effective_tenant_exists(self):
        self.assertIn("def _caller_effective_tenant", self.SRC)

    def test_apikeys_list_is_tenant_scoped(self):
        i = self.SRC.index("def handle_apikeys_list")
        body = self.SRC[i : i + 1500]
        self.assertIn("tenant", body.lower())


class TestSsoGroupRolesSuperadminGate(unittest.TestCase):
    """The instance-wide sso_group_roles map was gated only on
    require_admin_auth() -- any tenant admin could overwrite it for every
    other tenant. Must be gated on _caller_is_superadmin()."""

    SRC = (_CGI / "api.py").read_text()

    def test_sso_group_roles_save_checks_superadmin(self):
        i = self.SRC.index("'sso_group_roles' in body")
        block = self.SRC[i : i + 900]
        self.assertIn("_caller_is_superadmin", block)


class TestStepUpAuthExists(unittest.TestCase):
    SRC = (_CGI / "api.py").read_text()

    def test_step_up_endpoint_exists(self):
        self.assertIn("def handle_step_up", self.SRC)

    def test_require_step_up_helper_exists(self):
        self.assertIn("def require_step_up", self.SRC)


class TestLitigationHoldExists(unittest.TestCase):
    SRC = (_CGI / "api.py").read_text()

    def test_handler_exists(self):
        self.assertIn("def handle_litigation_hold", self.SRC)

    def test_purge_checks_hold(self):
        i = self.SRC.index("def _purge_old_data")
        body = self.SRC[i : i + 800]
        self.assertIn("litigation", body.lower())


class TestPatchSnapshotEnforceExists(unittest.TestCase):
    SRC = (_CGI / "api.py").read_text()

    def test_handler_exists(self):
        self.assertIn("def handle_patch_snapshot_enforce", self.SRC)

    def test_pacman_refused(self):
        self.assertIn("def _pinned_install_cmd_for", self.SRC)
        i = self.SRC.index("def _pinned_install_cmd_for")
        body = self.SRC[i : i + 2500]
        self.assertIn("pacman", body.lower())

    def test_route_registered(self):
        self.assertIn("/enforce", self.SRC)
        self.assertIn("handle_patch_snapshot_enforce", self.SRC)


class TestBillingPaymentWebhookExists(unittest.TestCase):
    SRC = (_CGI / "api.py").read_text()

    def test_handler_exists(self):
        self.assertIn("def handle_billing_payment_webhook", self.SRC)

    def test_partially_paid_status(self):
        self.assertIn("partially_paid", self.SRC)


class TestDataExplorerQueryEngineExists(unittest.TestCase):
    def test_query_engine_module_exists(self):
        self.assertTrue((_CGI / "query_engine.py").exists())

    def test_batch_endpoint_exists(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("def handle_query_batch", src)


class TestOtlpTracingExists(unittest.TestCase):
    SRC = (_CGI / "api.py").read_text()

    def test_span_recording_helper_exists(self):
        self.assertIn("_otlp_record_span", self.SRC)

    def test_traces_export_helper_exists(self):
        self.assertIn("_export_otlp_traces", self.SRC)


class TestA11yGateFullyEnforced(unittest.TestCase):
    def test_no_axe_options_exemptions(self):
        src = (_ROOT / "tests" / "test_a11y_axe.py").read_text()
        self.assertIn("_AXE_OPTIONS = {}", src)


class TestThreatModelDocExists(unittest.TestCase):
    def test_doc_exists(self):
        self.assertTrue((_ROOT / "docs" / "threat-model.md").exists())


if __name__ == "__main__":
    unittest.main()

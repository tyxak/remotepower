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
    # v6.1.2: loosened from the "6.1.1" literal to the live version, exactly as
    # this file's docstring instructs on the next bump. The STRICT pins for the
    # current release live in tests/test_v612.py; what stays valuable here is
    # that every version surface remains in lockstep with SERVER_VERSION.
    V = api.SERVER_VERSION

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
        self.assertNotIn("?v=6.1.1", _html())

    def test_readme_and_changelog(self):
        self.assertIn(f"version-{self.V}-blue", (_ROOT / "README.md").read_text())
        self.assertIn(f"v{self.V}", (_ROOT / "CHANGELOG.md").read_text()[:2000])

    def test_version_doc_exists(self):
        self.assertTrue((_ROOT / f"docs/v{self.V}.md").exists())

    def test_doc_set_keeps_three_versions(self):
        vdocs = sorted(p.name for p in (_ROOT / "docs").glob("v[0-9]*.md"))
        self.assertEqual(len(vdocs), 3, f"expected exactly 3 version docs, got {vdocs}")

    def test_whats_new_card_present(self):
        self.assertIn(f"What's new — v{self.V}", _html())

    def test_hardenmatters_stays_in_the_changelog(self):
        # v6.1.2: this used to pin HardenMatters as the TOP entry. It's history
        # now — what still matters is that its entry survives (and keeps its
        # release date, i.e. never regressed to "unreleased").
        text = (_ROOT / "CHANGELOG.md").read_text()
        self.assertIn('## v6.1.1 — "HardenMatters" — 2026-07-12', text)


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


class TestAlertsTenantIsolationFix(unittest.TestCase):
    """v6.1.1 finalize: the alerts subsystem was the device-keyed sibling of
    confirmations but was MISSED by the v6.1.1 tenant sweep — a tenant admin
    could read and resolve another tenant's alerts (cross-tenant IDOR). The
    list/summary must tenant-filter and every mutation must tenant-gate."""

    SRC = (_CGI / "api.py").read_text()

    def test_shared_tenant_filter_helpers_exist(self):
        self.assertIn("def _alert_tenant_visible", self.SRC)
        self.assertIn("def _filter_alerts_for_caller", self.SRC)

    def test_alerts_list_and_summary_are_filtered(self):
        for fn in ("def handle_alerts_list", "def handle_alerts_summary"):
            i = self.SRC.index(fn)
            body = self.SRC[i : self.SRC.index("\ndef ", i + 10)]
            self.assertIn("_filter_alerts_for_caller", body, fn)

    def test_alert_mutations_are_tenant_gated(self):
        for fn in ("def handle_alert_ack", "def handle_alert_unack",
                   "def handle_alert_resolve", "def handle_alerts_bulk_resolve",
                   "def handle_alerts_bulk_ack"):
            i = self.SRC.index(fn)
            body = self.SRC[i : self.SRC.index("\ndef ", i + 10)]
            self.assertIn("_alert_tenant_visible", body, fn)

    def test_alert_mutes_gate_and_diagnostics_bundle_url_pop(self):
        i = self.SRC.index("def handle_alert_mutes")
        body = self.SRC[i : self.SRC.index("\ndef ", i + 10)]
        self.assertIn("_tenant", body)
        # diagnostics bundle must strip integration URLs (basic-auth userinfo)
        i2 = self.SRC.index("def handle_diagnostics_bundle")
        b2 = self.SRC[i2 : self.SRC.index("\ndef ", i2 + 10)]
        self.assertIn("integrations", b2)
        self.assertIn("_ig.pop('url'", b2)


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


class TestFleetAggregateTenantIsolationFix(unittest.TestCase):
    """v6.1.1 finalize (2026-07-12): the alerts IDOR fix was NOT generalized —
    six fleet-aggregate handlers filtered by _caller_scope() only (which is None
    for a tenant admin) and never consulted the tenant gate, so a tenant admin
    could read (and, for scans-clear, destructively mutate) other tenants'
    device data when tenancy_enforced is on. Each must route its device set
    through _scope_filter_devices() (which folds in _tenant_filter_devices) or
    consult _tenant_gate()."""

    SRC = (_CGI / "api.py").read_text()

    def _body(self, fn):
        i = self.SRC.index(fn)
        return self.SRC[i : self.SRC.index("\ndef ", i + 10)]

    def test_scap_overview_tenant_filtered(self):
        self.assertIn("_scope_filter_devices", self._body("def handle_scap_overview"))

    def test_sudo_search_tenant_filtered(self):
        self.assertIn("_scope_filter_devices", self._body("def handle_sudo_search"))

    def test_fleet_events_tenant_filtered(self):
        b = self._body("def handle_fleet_events")
        self.assertIn("_tenant_gate", b)
        # the conditional-GET ETag must vary by tenant too (else two tenant
        # admins with scope=None share a 304)
        self.assertIn("_tgate", b)

    def test_scans_list_and_clear_tenant_filtered(self):
        for fn in ("def handle_scans_list", "def handle_scans_clear"):
            b = self._body(fn)
            self.assertIn("_scope_filter_devices", b, fn)
            self.assertIn("_tenant_gate", b, fn)

    def test_risk_overview_tenant_filtered(self):
        b = self._body("def handle_risk_overview")
        self.assertIn("_scope_filter_devices", b)
        self.assertIn("_tgate", b)  # ETag varies by tenant

    def test_fleet_health_tenant_filtered(self):
        self.assertIn("_scope_filter_devices", self._body("def handle_fleet_health"))

    def test_no_regressed_bare_device_load_in_scans(self):
        # scans-list/clear must not fall back to the un-filtered device set.
        for fn in ("def handle_scans_list", "def handle_scans_clear"):
            self.assertNotIn(
                "load(DEVICES_FILE) if scope is not None else None",
                self._body(fn), fn)


if __name__ == "__main__":
    unittest.main()

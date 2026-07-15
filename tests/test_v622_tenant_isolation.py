"""v6.2.2 pre-prod security audit — tenant-isolation gap fills.

The logic-security sweep found four handler families still on the old
`if scope is not None` shape (which is None for a tenant admin) after prior
sweeps fixed their structural siblings — a cross-tenant read / active-scan
trigger / mutation when tenancy is enforced. Each fix routes its device
decision through _scope_filter_devices() or _scope_block_device() (which
403s a cross-tenant/out-of-scope target BEFORE role scope), mirroring the
already-correct sibling in the same subsystem.

Same gate-presence assertion style as
tests/test_v611.py::TestFleetAggregateTenantIsolationFix — it catches a
regression that drops the gate.
"""

import sys
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

import unittest

SRC = (_CGI / "api.py").read_text()


def _body(fn):
    i = SRC.index(fn)
    return SRC[i: SRC.index("\ndef ", i + 10)]


class TestScanSubsystemTenantGated(unittest.TestCase):
    """H1: scan detail/create/delete + the schedule scope helper + schedule
    create must not let a tenant admin (scope=None) read/launch/delete against
    another tenant's host."""

    def test_scan_detail_gates_on_tenant(self):
        b = _body("def handle_scan_detail")
        self.assertIn("_tenant_gate", b)
        self.assertIn("_scope_filter_devices", b)

    def test_scans_create_blocks_cross_tenant_target(self):
        self.assertIn("_scope_block_device", _body("def handle_scans_create"))

    def test_scan_delete_blocks_cross_tenant(self):
        self.assertIn("_scope_block_device", _body("def handle_scan_delete"))

    def test_sched_scope_helper_consults_tenant(self):
        b = _body("def _scan_sched_in_scope")
        self.assertIn("_tenant_gate", b)
        self.assertIn("_tenant_visible", b)

    def test_scan_schedule_create_blocks_cross_tenant_device(self):
        self.assertIn("_scope_block_device", _body("def handle_scan_schedules_create"))


class TestBatchJobTrackerTenantGated(unittest.TestCase):
    """M1: the batch/exec job tracker list + status used
    `load(DEVICES_FILE) if scope is not None else None`, so a tenant admin saw
    every tenant's jobs. Both must restrict on tenant too."""

    def test_batch_jobs_list_confines_by_tenant(self):
        b = _body("def handle_batch_jobs_list")
        self.assertIn("_tenant_gate", b)
        self.assertIn("_scope_filter_devices", b)
        self.assertIn("visible_ids", b)

    def test_exec_batch_status_confines_by_tenant(self):
        b = _body("def handle_exec_batch_status")
        self.assertIn("_tenant_gate", b)
        self.assertIn("_scope_filter_devices", b)


class TestComposeStackTenantGated(unittest.TestCase):
    """M2: compose stack list/get/create/delete lacked the _scope_block_device
    the sibling handle_compose_stack_action already had."""

    def test_list_filters_visible_devices(self):
        self.assertIn("_scope_filter_devices", _body("def handle_compose_stacks_list"))

    def test_get_blocks_cross_tenant(self):
        self.assertIn("_scope_block_device", _body("def handle_compose_stack_get"))

    def test_create_blocks_cross_tenant(self):
        self.assertIn("_scope_block_device", _body("def handle_compose_stack_create"))

    def test_delete_blocks_cross_tenant(self):
        self.assertIn("_scope_block_device", _body("def handle_compose_stack_delete"))


class TestSecretScrubGaps(unittest.TestCase):
    """M3 + L1: two credential-bearing config fields were not withheld."""

    def test_diagnostics_bundle_scrubs_warranty_client_id(self):
        # The Lenovo API ClientID ends 'client_id', so the name-based scrub
        # misses it — the bundle must pop it explicitly like /api/config does.
        self.assertIn("warranty_lenovo_client_id",
                      _body("def handle_diagnostics_bundle"))

    def test_config_get_withholds_endpoint_urls_from_non_admins(self):
        b = _body("def handle_config_get")
        # the three URLs are redacted in a non-admin loop that builds `<k>_set`
        for k in ("siem_url", "audit_forward_url", "otlp_endpoint"):
            self.assertIn(k, b, k)
        self.assertIn("_set'", b)     # the *_set indicator construction
        self.assertIn("not _cfg_is_admin", b)


if __name__ == "__main__":
    unittest.main()

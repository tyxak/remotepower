"""Phase 6 (v6.1.0) — opt-in DB-level RLS tenant isolation.

The DB-enforced row-level-security layer beneath the app-layer device tenancy. Active
ONLY when tenancy_enforced + tenancy_rls + the Postgres backend (default OFF). These
tests cover the inert-when-off contract + the wiring; the actual cross-tenant isolation
is validated against real Postgres (devices table: tenant A cannot read/write tenant
B's rows; empty GUC is fail-closed; FORCE makes it apply to the table owner).
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-rls-test-"))

import api  # noqa: E402
import storage_pg  # noqa: E402


class TestRlsInertWhenOff(unittest.TestCase):
    def test_inactive_by_default(self):
        # sqlite/json backend + no flags → RLS not active
        self.assertFalse(api._tenancy_rls_active())

    def test_rls_narrow_is_noop_when_inactive(self):
        # must not raise / must not try to touch Postgres when off
        api._rls_narrow('someone', 'viewer')
        api._rls_narrow('admin', 'admin')

    def test_set_request_tenant_noop_when_flag_off(self):
        self.assertFalse(storage_pg.RLS_ACTIVE)   # default
        storage_pg.set_request_tenant('acme')      # no-op, no connection, no raise


class TestRlsWiring(unittest.TestCase):
    def test_storage_pg_surface(self):
        for n in ('_enable_rls', 'set_request_tenant', 'RLS_ACTIVE', '_RLS_TABLES'):
            self.assertTrue(hasattr(storage_pg, n), n)
        sp = (_CGI / "storage_pg.py").read_text()
        # the owner-bypass guard + the GUC-keyed policy (the security core)
        self.assertIn("FORCE ROW LEVEL SECURITY", sp)
        self.assertIn("current_setting('app.rp_tenant', true) = '*'", sp)
        self.assertIn("tenant_id = current_setting('app.rp_tenant', true)", sp)
        # tenant_id kept in sync with the doc's tenant by a trigger
        self.assertIn("rp_tenant_sync_", sp)

    def test_multi_table_coverage(self):
        # v5.6.x: RLS extended beyond the device roster to every device-keyed
        # row table. The '__shared__' class keeps non-device rows (monitor
        # history, server-level alerts) visible to every tenant — matching
        # the app layer, so hardening never hides legitimately shared rows.
        self.assertEqual(set(storage_pg._RLS_TABLES),
                         {'devices', 'entity', 'listrow', 'metric_samples'})
        sp = (_CGI / "storage_pg.py").read_text()
        # tenant derivation: owning device, '__shared__' when none
        self.assertIn("rp_tenant_of_device", sp)
        self.assertIn("'__shared__'", sp)
        # the row-table policies admit shared rows; devices policy must NOT
        # (a device row is never shared)
        self.assertIn("OR tenant_id = '__shared__'", sp)
        dev_policy = sp[sp.index("CREATE POLICY rp_tenant_iso ON devices"):]
        dev_policy = dev_policy[:dev_policy.index('"""')]
        self.assertNotIn("__shared__", dev_policy)
        # tenant moves cascade to the device's rows
        self.assertIn("rp_tenant_cascade", sp)
        self.assertIn("AFTER UPDATE OF tenant_id ON devices", sp)
        # the heavy backfill is one-time (schema_meta marker), not per-process
        self.assertIn("rls_backfill_v2", sp)

    def test_api_wiring(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("def _tenancy_rls_active", src)
        self.assertIn("storage_pg.set_request_tenant('*')", src)        # _begin_request reset
        self.assertIn("_rls_narrow(username, role)", src)               # session auth
        self.assertIn("_rls_narrow(matched_user, matched_role)", src)   # apikey auth
        self.assertIn("cfg['tenancy_rls'] = bool(body['tenancy_rls'])", src)  # config save
        self.assertIn("safe.setdefault('tenancy_rls', False)", src)     # config GET

    def test_ui_toggle(self):
        html = (_ROOT / "server/html/index.html").read_text()
        self.assertIn('id="cfg-tenancy-rls"', html)
        app = (_ROOT / "server/html/static/js/app.js").read_text()
        self.assertIn("payload.tenancy_rls = _tSaveRls.checked", app)


if __name__ == '__main__':
    unittest.main()

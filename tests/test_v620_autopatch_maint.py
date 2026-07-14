"""v6.2.0 — regression tests for the reported autopatch / maintenance-window /
schedule-id live bugs.

Bugs fixed:
  1. POST /api/autopatch 400 for a single-device policy — the client offers a
     'device' target type the server allowlist rejected.
  2. DELETE /api/schedule/<id> 404 for a token_hex id that JS coerced to Infinity
     via the data-arg dispatcher — delete buttons moved to data-action-btn/data-id.
  3. Auto-patch created maintenance windows with no id/reason/scope ("(no reason)",
     "undefined", undeletable) — _autopatch_sync now writes a COMPLETE window and
     handle_maintenance_list backfills legacy windows missing an id.
"""
import os
import re
import json
import tempfile
import importlib.util
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

REPO_ROOT = Path(__file__).resolve().parent.parent
_CGI_BIN = REPO_ROOT / "server" / "cgi-bin"
_spec = importlib.util.spec_from_file_location("api_v620", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ('AUTOPATCH_FILE', 'MAINT_FILE', 'CALENDAR_FILE', 'DEVICES_FILE'):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        self._orig = {n: getattr(api, n) for n in
                      ('require_auth', 'require_admin_auth', 'audit_log',
                       'respond', 'method', 'get_json_obj')}
        api.require_auth = lambda require_admin=False: 'jakob'
        api.require_admin_auth = lambda: 'jakob'
        api.audit_log = lambda *a, **k: None
        api.method = lambda: 'POST'
        self.cap = {}

        def _resp(s, b=None):
            self.cap['s'] = s
            self.cap['b'] = b
            raise api.HTTPError(s, b)
        api.respond = _resp
        # a real device so type='device' resolves
        (self.d / 'devices.json').write_text(json.dumps({'dev-abc': {'name': 'win01', 'os': 'Windows 11'}}))

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for attr, v in self._files.items():
            setattr(api, attr, v)

    def _post(self, fn, body, meth='POST'):
        api.method = lambda: meth
        api.get_json_obj = lambda: body
        try:
            fn()
        except api.HTTPError:
            pass
        return self.cap.get('s'), self.cap.get('b')


class TestAutopatchDeviceTarget(_Base):
    def test_single_device_policy_is_accepted(self):
        s, b = self._post(api.handle_autopatch_create, {
            'name': 'Win nightly', 'cron': '0 3 * * *',
            'target': {'type': 'device', 'value': 'dev-abc'},
            'reboot': False, 'rings': [],
        })
        self.assertEqual(s, 200, f'device-target autopatch should succeed, got {s}: {b}')
        self.assertTrue(b.get('ok'))

    def test_sync_writes_a_complete_window(self):
        self._post(api.handle_autopatch_create, {
            'name': 'Fleet nightly', 'cron': '0 3 * * *',
            'target': {'type': 'all', 'value': ''}, 'rings': [],
        })
        wins = (json.loads((self.d / 'maintenance.json').read_text()).get('windows') or [])
        self.assertEqual(len(wins), 1)
        w = wins[0]
        # The whole point of the fix: id/reason/scope are all present + sane.
        self.assertTrue(str(w.get('id', '')).startswith('ap_'), 'window id must be the non-numeric ap_ id')
        self.assertIn('Fleet nightly', w.get('reason', ''))
        self.assertIn(w.get('scope'), ('global', 'device', 'group'))
        self.assertNotIn('name', {k: v for k, v in w.items() if k == 'name' and not w.get('reason')})


class TestMaintenanceLegacyBackfill(_Base):
    def test_list_backfills_missing_id_and_scope(self):
        # A legacy window as produced by the OLD _autopatch_sync (no id/scope/reason).
        (self.d / 'maintenance.json').write_text(json.dumps({'windows': [
            {'name': 'Auto-patch: legacy', 'cron': '0 3 * * *', 'duration': 3600,
             'autopatch_id': 'pid123', 'auto': True},
        ]}))
        api.method = lambda: 'GET'
        try:
            api.handle_maintenance_list()
        except api.HTTPError:
            pass
        out = self.cap['b']['windows']
        self.assertEqual(len(out), 1)
        w = out[0]
        self.assertTrue(w.get('id'), 'legacy window must get an id backfilled')
        self.assertFalse(str(w['id']).replace('.', '').isdigit(),
                         'backfilled id must be non-numeric (Infinity-coercion class)')
        self.assertTrue(w.get('scope'), 'legacy window must get a scope')
        # And it persisted, so the id is stable across reloads.
        persisted = json.loads((self.d / 'maintenance.json').read_text())['windows'][0]
        self.assertEqual(persisted['id'], w['id'])


class TestClientIdCoercionFix(unittest.TestCase):
    def test_delete_buttons_use_action_btn_not_data_arg(self):
        js = (REPO_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        # The two id-bearing delete buttons must NOT use the coercing data-arg path.
        self.assertNotIn('data-action="deleteJob"', js)
        self.assertNotIn('data-action="deleteMaintenance"', js)
        self.assertIn('data-action-btn="_deleteJobBtn"', js)
        self.assertIn('data-action-btn="_deleteMaintenanceBtn"', js)

    def test_quick_rdp_exists_for_windows(self):
        js = (REPO_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        self.assertIn('function rdpLinkIcon', js)
        self.assertIn('function quickRdp', js)
        self.assertIn('rdpLinkIcon(d)', js)  # wired into the device row


class TestWindowsPostureDrawerBinding(unittest.TestCase):
    """Windows posture (si.win_posture) is collected + persisted; the drawer
    sysinfo pills must surface it (BitLocker / Defender / Firewall / WU)."""

    def test_win_posture_pills_are_bound(self):
        js = (REPO_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        # Locate the sysinfo pills array and assert each posture field is read.
        self.assertIn('si.win_posture.bitlocker', js)
        self.assertIn('defender_realtime', js)
        self.assertIn('si.win_posture.firewall', js)
        self.assertIn('win_posture.wu_service', js)

    def test_sysinfo_endpoint_returns_full_sysinfo(self):
        # win_posture rides inside dev['sysinfo']; the handler must return it whole.
        src = (_CGI_BIN / 'api.py').read_text()
        m = re.search(r"def handle_sysinfo\(dev_id\):(.*?)\n\ndef ", src, re.S)
        self.assertIsNotNone(m)
        self.assertIn("dev.get('sysinfo'", m.group(1))


if __name__ == '__main__':
    unittest.main()

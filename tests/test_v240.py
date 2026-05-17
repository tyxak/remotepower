#!/usr/bin/env python3
"""
Tests for v2.4.0 — Proxmox snapshots + CVE Debian-urgency fix.

  - proxmox_client snapshot methods: name validation, the 'current'
    pseudo-snapshot is filtered/reserved, action gating.
  - CVE: the Debian Security Tracker fallback no longer reports
    `high`/`critical` — Debian `urgency` is a patching-priority
    signal, not CVSS severity, so it's capped at `medium`.
  - api.py snapshot endpoints validate input.
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT    = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_sp = importlib.util.spec_from_file_location("proxmox_v240", _CGI_BIN / "proxmox_client.py")
px = importlib.util.module_from_spec(_sp)
_sp.loader.exec_module(px)

_sc = importlib.util.spec_from_file_location("cve_v240", _CGI_BIN / "cve_scanner.py")
cve = importlib.util.module_from_spec(_sc)
_sc.loader.exec_module(cve)


# ─── CVE: Debian urgency is not severity ─────────────────────────────────


class TestDebianUrgencyFix(unittest.TestCase):

    def test_debian_fallback_caps_at_medium(self):
        # The reported bug: DEBIAN-CVE-2018-1000021 — Debian urgency
        # 'high', OSV CVSS 5.0 Medium — was shown HIGH. The Debian
        # fallback must never return high/critical.
        import unittest.mock as m
        # Simulate the tracker returning each urgency level
        for urgency, expected in (('high', 'medium'), ('medium', 'medium'),
                                  ('low', 'low'), ('unimportant', 'low'),
                                  ('negligible', 'low')):
            with m.patch.object(cve.urllib.request, 'urlopen') as mock:
                fake = m.MagicMock()
                fake.read.return_value = (
                    '{"urgency": "%s"}' % urgency).encode()
                mock.return_value.__enter__.return_value = fake
                got = cve._debian_severity_fallback('CVE-2018-1000021')
                self.assertEqual(got, expected,
                                 f'urgency {urgency!r} → {got!r}, want {expected!r}')

    def test_debian_fallback_strips_postponed_marker(self):
        # Debian urgency can be 'low**' (postponed) — the ** suffix
        # must be stripped before matching.
        import unittest.mock as m
        with m.patch.object(cve.urllib.request, 'urlopen') as mock:
            fake = m.MagicMock()
            fake.read.return_value = b'{"urgency": "high**"}'
            mock.return_value.__enter__.return_value = fake
            self.assertEqual(cve._debian_severity_fallback('CVE-x'), 'medium')

    def test_debian_fallback_never_high(self):
        # Belt-and-braces: no urgency value can produce high/critical.
        import unittest.mock as m
        for urgency in ('high', 'critical', 'HIGH', 'high**'):
            with m.patch.object(cve.urllib.request, 'urlopen') as mock:
                fake = m.MagicMock()
                fake.read.return_value = ('{"urgency":"%s"}' % urgency).encode()
                mock.return_value.__enter__.return_value = fake
                got = cve._debian_severity_fallback('CVE-x')
                self.assertNotIn(got, ('high', 'critical'))


# ─── Proxmox snapshot client ─────────────────────────────────────────────


class TestSnapshotClient(unittest.TestCase):

    def _pc(self):
        return {'host': 'pve', 'node': 'pve', 'token_id': 't',
                'token_secret': 's', 'verify_tls': True}

    def test_snapshot_name_validation(self):
        self.assertTrue(px._valid_snapshot_name('before_upgrade'))
        self.assertTrue(px._valid_snapshot_name('Snap1'))
        self.assertFalse(px._valid_snapshot_name('123bad'))      # leading digit
        self.assertFalse(px._valid_snapshot_name('has-dash'))    # dash
        self.assertFalse(px._valid_snapshot_name('has space'))
        self.assertFalse(px._valid_snapshot_name(''))
        self.assertFalse(px._valid_snapshot_name('x' * 41))      # too long

    def test_current_is_reserved(self):
        self.assertIn('current', px._SNAPSHOT_RESERVED)

    def test_create_rejects_bad_name(self):
        with self.assertRaises(px.ProxmoxError):
            px.create_snapshot(self._pc(), 'qemu', 100, '123bad')

    def test_rollback_rejects_current(self):
        # 'current' is the live state — never a rollback/delete target.
        with self.assertRaises(px.ProxmoxError):
            px.rollback_snapshot(self._pc(), 'qemu', 100, 'current')

    def test_delete_rejects_current(self):
        with self.assertRaises(px.ProxmoxError):
            px.delete_snapshot(self._pc(), 'qemu', 100, 'current')

    def test_snapshot_rejects_unknown_guest_type(self):
        with self.assertRaises(px.ProxmoxError):
            px.list_snapshots(self._pc(), 'wibble', 100)
        with self.assertRaises(px.ProxmoxError):
            px.create_snapshot(self._pc(), 'wibble', 100, 'snap')

    def test_snapshot_rejects_bad_vmid(self):
        with self.assertRaises(px.ProxmoxError):
            px.create_snapshot(self._pc(), 'qemu', 'notanumber', 'snap')


# ─── Proxmox snapshot API endpoints ──────────────────────────────────────


class TestSnapshotEndpoints(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault('REQUEST_METHOD', 'GET')
        os.environ.setdefault('PATH_INFO', '/')
        os.environ.setdefault('CONTENT_LENGTH', '0')
        _s = importlib.util.spec_from_file_location("api_v240", _CGI_BIN / "api.py")
        cls.api = importlib.util.module_from_spec(_s)
        _s.loader.exec_module(cls.api)

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        self.api.CONFIG_FILE = self._tmp / 'config.json'
        self.api.save(self.api.CONFIG_FILE, {})

    def _capture(self, fn):
        cap = {}
        def fake_respond(status, body):
            cap['status'] = status
            cap['body'] = body
            raise SystemExit(0)
        self.api.respond = fake_respond
        self.api.require_auth = lambda **kw: 'admin'
        self.api.require_admin_auth = lambda **kw: 'admin'
        try:
            fn()
        except SystemExit:
            pass
        return cap

    def test_snapshot_action_rejects_bad_action(self):
        self.api.get_json_body = lambda: {'type': 'qemu', 'vmid': 100,
                                          'action': 'destroy', 'name': 'x'}
        cap = self._capture(self.api.handle_proxmox_snapshot_action)
        self.assertEqual(cap['status'], 400)

    def test_snapshot_action_rejects_bad_type(self):
        self.api.get_json_body = lambda: {'type': 'wibble', 'vmid': 100,
                                          'action': 'create', 'name': 'x'}
        cap = self._capture(self.api.handle_proxmox_snapshot_action)
        self.assertEqual(cap['status'], 400)

    def test_snapshot_action_rejects_non_numeric_vmid(self):
        self.api.get_json_body = lambda: {'type': 'qemu', 'vmid': 'abc',
                                          'action': 'create', 'name': 'x'}
        cap = self._capture(self.api.handle_proxmox_snapshot_action)
        self.assertEqual(cap['status'], 400)

    def test_snapshot_list_rejects_bad_query(self):
        os.environ['QUERY_STRING'] = 'type=qemu&vmid=notanumber'
        cap = self._capture(self.api.handle_proxmox_snapshots_list)
        self.assertEqual(cap['status'], 400)
        os.environ['QUERY_STRING'] = ''

    def test_snapshot_action_unconfigured_proxmox(self):
        # Valid request shape, but Proxmox isn't configured → 400
        self.api.get_json_body = lambda: {'type': 'qemu', 'vmid': 100,
                                          'action': 'create', 'name': 'snap'}
        cap = self._capture(self.api.handle_proxmox_snapshot_action)
        self.assertEqual(cap['status'], 400)
        self.assertIn('not configured', cap['body']['error'].lower())


class TestSnapshotAssets(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.js = (_ROOT / 'server/html/static/js/app.js').read_text()

    def test_snapshot_js_present(self):
        for fn in ('openSnapshots', 'loadSnapshots', 'snapshotCreate',
                   'snapshotRollback', 'snapshotDelete'):
            self.assertIn(f'function {fn}', self.js, f'{fn} missing')

    def test_rollback_requires_typed_confirmation(self):
        # Rollback is destructive — must require typing the guest name.
        idx = self.js.find('function snapshotRollback')
        chunk = self.js[idx:idx + 900]
        self.assertIn('prompt(', chunk)
        self.assertIn('_snapCtx.name', chunk)


if __name__ == '__main__':
    unittest.main(verbosity=2)

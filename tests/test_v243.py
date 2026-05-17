#!/usr/bin/env python3
"""
Tests for v2.4.3 — mailbox-count monitor.

  - Agent: count_mailbox_paths counts regular files at depth 1,
    handles missing / non-directory / permission cases.
  - Server: _ingest_mailbox_counts stores a clean snapshot;
    handle_mailwatch_set validates and stores paths + the dashboard
    flag; handle_mailwatch_overview returns configured devices.
  - Frontend assets present.
"""

import importlib.machinery
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT    = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

# The agent file has no .py extension — load it via SourceFileLoader.
_agent_loader = importlib.machinery.SourceFileLoader(
    'rp_agent_v243', str(_ROOT / 'client' / 'remotepower-agent'))
_agent_spec = importlib.util.spec_from_loader('rp_agent_v243', _agent_loader)
agent = importlib.util.module_from_spec(_agent_spec)
_agent_loader.exec_module(agent)


# ─── Agent: count_mailbox_paths ──────────────────────────────────────────


class TestMailboxCount(unittest.TestCase):

    def test_counts_regular_files(self):
        d = Path(tempfile.mkdtemp())
        # 3 regular files + a subdirectory (must NOT be counted)
        for i in range(3):
            (d / f'msg{i}').write_text('x')
        (d / 'subdir').mkdir()
        out = agent.count_mailbox_paths([str(d)])
        self.assertEqual(out[str(d)]['count'], 3)
        self.assertTrue(out[str(d)]['exists'])
        self.assertIsNone(out[str(d)]['error'])

    def test_empty_directory_is_zero(self):
        d = Path(tempfile.mkdtemp())
        out = agent.count_mailbox_paths([str(d)])
        self.assertEqual(out[str(d)]['count'], 0)
        self.assertTrue(out[str(d)]['exists'])

    def test_missing_path(self):
        out = agent.count_mailbox_paths(['/no/such/path/xyzzy'])
        e = out['/no/such/path/xyzzy']
        self.assertFalse(e['exists'])
        self.assertEqual(e['error'], 'not_a_directory')
        self.assertIsNone(e['count'])

    def test_file_instead_of_directory(self):
        f = Path(tempfile.mkdtemp()) / 'afile'
        f.write_text('x')
        out = agent.count_mailbox_paths([str(f)])
        self.assertEqual(out[str(f)]['error'], 'not_a_directory')

    def test_multiple_paths(self):
        d1 = Path(tempfile.mkdtemp())
        d2 = Path(tempfile.mkdtemp())
        (d1 / 'a').write_text('x')
        (d2 / 'a').write_text('x'); (d2 / 'b').write_text('x')
        out = agent.count_mailbox_paths([str(d1), str(d2)])
        self.assertEqual(out[str(d1)]['count'], 1)
        self.assertEqual(out[str(d2)]['count'], 2)

    def test_path_cap(self):
        # More than MAX_MAILBOX_PATHS → only the cap is processed.
        d = Path(tempfile.mkdtemp())
        many = [str(d)] * (agent.MAX_MAILBOX_PATHS + 10)
        out = agent.count_mailbox_paths(many)
        # All entries collapse to the one path key — but the function
        # must not error and must respect the slice.
        self.assertIn(str(d), out)


# ─── Server: ingest + config endpoints ──────────────────────────────────


class TestMailwatchServer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault('REQUEST_METHOD', 'GET')
        os.environ.setdefault('PATH_INFO', '/')
        os.environ.setdefault('CONTENT_LENGTH', '0')
        _s = importlib.util.spec_from_file_location("api_v243", _CGI_BIN / "api.py")
        cls.api = importlib.util.module_from_spec(_s)
        _s.loader.exec_module(cls.api)

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        self.api.DEVICES_FILE = self._tmp / 'devices.json'

    def _capture(self, fn, *a):
        cap = {}
        def fake_respond(status, body):
            cap['status'] = status
            cap['body'] = body
            raise SystemExit(0)
        self.api.respond = fake_respond
        self.api.require_auth = lambda **kw: 'admin'
        self.api.require_admin_auth = lambda **kw: 'admin'
        try:
            fn(*a)
        except SystemExit:
            pass
        return cap

    def test_ingest_stores_counts(self):
        self.api.save(self.api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'mail01'}})
        self.api._ingest_mailbox_counts('d1', {
            '/var/mail/new': {'count': 7, 'exists': True, 'error': None},
        })
        dev = self.api.load(self.api.DEVICES_FILE)['d1']
        self.assertEqual(dev['mailbox_state']['counts']['/var/mail/new']['count'], 7)
        self.assertGreater(dev['mailbox_state']['reported_at'], 0)

    def test_ingest_rejects_negative_count(self):
        self.api.save(self.api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'm'}})
        self.api._ingest_mailbox_counts('d1', {
            '/p': {'count': -5, 'exists': True},
        })
        dev = self.api.load(self.api.DEVICES_FILE)['d1']
        # A nonsense negative count is stored as None, not -5.
        self.assertIsNone(dev['mailbox_state']['counts']['/p']['count'])

    def test_mailwatch_set_stores_paths(self):
        self.api.save(self.api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'm'}})
        self.api.get_json_body = lambda: {
            'paths': ['/var/mail/a/new', '/var/mail/b/new', '  ',
                      'relative/path', '/var/mail/a/new'],   # dup + junk
            'dashboard': True,
        }
        cap = self._capture(self.api.handle_mailwatch_set, 'd1')
        self.assertEqual(cap['status'], 200)
        dev = self.api.load(self.api.DEVICES_FILE)['d1']
        # Blank and relative paths dropped; duplicate collapsed.
        self.assertEqual(dev['mailbox_paths'],
                         ['/var/mail/a/new', '/var/mail/b/new'])
        self.assertTrue(dev['mailbox_dashboard'])

    def test_mailwatch_set_empty_clears_state(self):
        self.api.save(self.api.DEVICES_FILE, {'d1': {
            'id': 'd1', 'name': 'm', 'mailbox_paths': ['/old'],
            'mailbox_state': {'counts': {'/old': {}}, 'reported_at': 1},
        }})
        self.api.get_json_body = lambda: {'paths': []}
        self._capture(self.api.handle_mailwatch_set, 'd1')
        dev = self.api.load(self.api.DEVICES_FILE)['d1']
        self.assertEqual(dev['mailbox_paths'], [])
        self.assertNotIn('mailbox_state', dev)

    def test_mailwatch_set_rejects_non_list(self):
        self.api.save(self.api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'm'}})
        self.api.get_json_body = lambda: {'paths': 'notalist'}
        cap = self._capture(self.api.handle_mailwatch_set, 'd1')
        self.assertEqual(cap['status'], 400)

    def test_mailwatch_overview(self):
        self.api.save(self.api.DEVICES_FILE, {
            'd1': {'id': 'd1', 'name': 'mail01',
                   'mailbox_paths': ['/var/mail/new'],
                   'mailbox_dashboard': True,
                   'mailbox_state': {'counts': {'/var/mail/new':
                       {'count': 4, 'exists': True, 'error': None}},
                       'reported_at': 100}},
            'd2': {'id': 'd2', 'name': 'web01'},   # no mailbox config
        })
        cap = self._capture(self.api.handle_mailwatch_overview)
        rows = cap['body']['devices']
        self.assertEqual(len(rows), 1)            # only the configured one
        self.assertEqual(rows[0]['device_id'], 'd1')
        self.assertTrue(rows[0]['dashboard'])
        self.assertEqual(rows[0]['counts']['/var/mail/new']['count'], 4)


class TestMailwatchAssets(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.js   = (_ROOT / 'server/html/static/js/app.js').read_text()
        cls.html = (_ROOT / 'server/html/index.html').read_text()

    def test_dashboard_tile_present(self):
        # v2.4.4: the mailbox monitor is a Home-dashboard tile (added
        # inside _renderHomeTiles), not a separate widget.
        self.assertIn("label: 'Unread mail'", self.js)

    def test_config_section_present(self):
        # v2.4.4: configuration moved to the Settings → Mailbox pane.
        self.assertIn('function saveMailwatch', self.js)
        self.assertIn('function loadMailwatchSettings', self.js)
        self.assertIn('settings-pane-mailbox', self.html)


if __name__ == '__main__':
    unittest.main(verbosity=2)

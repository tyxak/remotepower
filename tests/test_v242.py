#!/usr/bin/env python3
"""
Tests for v2.4.2 — default SSH username + quick SSH link + docs.

  - The ui_prefs sanitiser accepts a top-level `default_ssh_username`
    string, validates it as SSH-safe, and rejects bad values without
    discarding the rest of the prefs document.
  - Frontend: the SSH settings field, the quick-SSH icon, and the
    ssh:// + clipboard-fallback logic are present.
  - The new documentation cards exist.
"""

import sys as _cj_sys
from pathlib import Path as _cj_Path
_cj_sys.path.insert(0, str(_cj_Path(__file__).resolve().parent))
from clientjs import client_js
import importlib.util
import os
import sys
import unittest
from pathlib import Path

_ROOT    = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

os.environ.setdefault('REQUEST_METHOD', 'GET')
os.environ.setdefault('PATH_INFO', '/')
os.environ.setdefault('CONTENT_LENGTH', '0')
_spec = importlib.util.spec_from_file_location("api_v242", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestSshUsernamePref(unittest.TestCase):

    def test_valid_username_kept(self):
        for name in ('root', 'deploy', 'jmo', 'svc-account', 'user_1', 'a.b'):
            out = api._sanitise_ui_prefs({'default_ssh_username': name})
            self.assertEqual(out.get('default_ssh_username'), name,
                             f'{name!r} should be accepted')

    def test_invalid_username_dropped(self):
        # Bad characters / too long → the key is dropped, not stored.
        for bad in ('has space', 'semi;colon', 'a' * 33, 'quote"d',
                    'slash/y', '', 'back`tick'):
            out = api._sanitise_ui_prefs({'default_ssh_username': bad})
            self.assertNotIn('default_ssh_username', out,
                             f'{bad!r} should have been rejected')

    def test_bad_username_does_not_drop_other_prefs(self):
        # A bad SSH username must not nuke the rest of the prefs doc.
        out = api._sanitise_ui_prefs({
            'default_ssh_username': 'bad name',
            'devices': {'density': 'compact'},
        })
        self.assertNotIn('default_ssh_username', out)
        self.assertEqual(out['devices']['density'], 'compact')

    def test_username_not_treated_as_table(self):
        # The key must not leak into the table-prefs loop and become a
        # bogus empty table entry.
        out = api._sanitise_ui_prefs({'default_ssh_username': 'root'})
        self.assertEqual(list(out.keys()), ['default_ssh_username'])

    def test_roundtrip_via_handlers(self):
        # POST then GET — the username survives a real save/load cycle.
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        api.USERS_FILE = tmp / 'users.json'
        api.save(api.USERS_FILE, {'alice': {'role': 'admin'}})
        api.require_auth = lambda **kw: 'alice'
        api.method = lambda: 'POST'
        cap = {}
        def fake_respond(status, body):
            cap['status'] = status
            cap['body'] = body
            raise SystemExit(0)
        api.respond = fake_respond
        api.get_json_body = lambda: {'default_ssh_username': 'deploy',
                                     'devices': {'density': 'compact'}}
        try:
            api.handle_ui_prefs_set()
        except SystemExit:
            pass
        # Confirm it persisted
        users = api.load(api.USERS_FILE)
        self.assertEqual(users['alice']['ui_prefs'].get('default_ssh_username'),
                         'deploy')
        # And that GET returns it
        cap.clear()
        try:
            api.handle_ui_prefs_get()
        except SystemExit:
            pass
        self.assertEqual(cap['body'].get('default_ssh_username'), 'deploy')


class TestSshFrontend(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.js   = client_js()
        cls.html = (_ROOT / 'server/html/index.html').read_text()

    def test_settings_field_present(self):
        self.assertIn('cfg-ssh-username', self.html)
        self.assertIn('SSH preferences', self.html)

    def test_ssh_js_functions(self):
        for fn in ('getDefaultSshUsername', 'saveSshUsername',
                   'sshLinkIcon', 'quickSsh'):
            self.assertIn(f'function {fn}', self.js, f'{fn} missing')

    def test_quickssh_has_clipboard_fallback(self):
        # quickSsh must attempt ssh:// AND offer a copy fallback —
        # a browser can't open a terminal on its own.
        idx = self.js.find('function quickSsh')
        chunk = self.js[idx:idx + 1200]
        self.assertIn('ssh://', chunk)
        self.assertIn('clipboard', chunk)

    def test_ssh_icon_uses_ip_then_hostname(self):
        # sshLinkIcon falls back to hostname when there's no IP.
        idx = self.js.find('function sshLinkIcon')
        chunk = self.js[idx:idx + 400]
        self.assertIn('d.ip', chunk)
        self.assertIn('d.hostname', chunk)


class TestDocumentation(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.html = (_ROOT / 'server/html/index.html').read_text()

    def test_new_doc_cards_present(self):
        # The four documentation topics requested.
        for kw in ('Proxmox virtualization', 'Proxmox LXC containers',
                   'Snapshots &amp; rollback', 'Quick SSH from the Devices page'):
            self.assertIn(kw, self.html, f'doc card missing: {kw}')

    def test_doc_cards_well_formed(self):
        self.assertEqual(self.html.count('<details'),
                         self.html.count('</details>'))


if __name__ == '__main__':
    unittest.main(verbosity=2)

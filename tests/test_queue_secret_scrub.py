#!/usr/bin/env python3
"""GET /api/command-queue must never echo ACME DNS-provider secrets.

A queued acme.sh issue/renew command carries the provider credentials as an
`export X='…'` prefix (built by _acme_credential_env_prefix). The agent needs
the queue verbatim, but the admin queue-viewer endpoint is display-only —
both the humanized summary (first line of the exec body) and the `raw` echo
must go through _scrub_acme_credentials. This was a written-but-never-wired
scrubber until the 2026-07 housekeeping sweep; this test keeps it wired.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_CGI_BIN = Path(__file__).parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI_BIN))

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
os.environ.setdefault('REQUEST_METHOD', 'GET')
os.environ.setdefault('PATH_INFO', '/')
os.environ.setdefault('CONTENT_LENGTH', '0')

_spec = importlib.util.spec_from_file_location('api_qscrub', _CGI_BIN / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

SECRET = 'sk-live-supersecret-token-123'


class TestQueueSecretScrub(unittest.TestCase):
    def setUp(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'host1', 'last_seen': 0}})
        api.save(api.CMDS_FILE, {'d1': [
            f"exec:#acme:a-1#export CF_Token='{SECRET}' "
            f"~/.acme.sh/acme.sh --issue --dns dns_cf -d example.com",
            'reboot',
        ]})
        for f in (api.DEVICES_FILE, api.CMDS_FILE):
            api._invalidate_load_cache(f)
        self.cap = {}
        self._respond = api.respond
        self._auth = api.require_admin_auth

        def fake_respond(status, body):
            self.cap['s'] = status
            self.cap['b'] = body
            raise SystemExit(0)
        api.respond = fake_respond
        api.require_admin_auth = lambda *a, **k: 'admin'

    def tearDown(self):
        api.respond = self._respond
        api.require_admin_auth = self._auth

    def test_scrubber_redacts_known_provider_fields(self):
        cmd = f"export CF_Token='{SECRET}' acme.sh --issue"
        out = api._scrub_acme_credentials(cmd)
        self.assertNotIn(SECRET, out)
        self.assertIn('***REDACTED***', out)

    def test_queue_viewer_never_echoes_the_secret(self):
        with self.assertRaises(SystemExit):
            api.handle_command_queue()
        self.assertEqual(self.cap['s'], 200)
        payload = json.dumps(self.cap['b'])
        self.assertNotIn(SECRET, payload,
                         'queued acme credentials leaked through /api/command-queue')
        self.assertIn('***REDACTED***', payload)
        # non-acme commands pass through untouched
        self.assertIn('reboot', payload)


if __name__ == '__main__':
    unittest.main()

"""E6 — notification sandbox / test mode.

When `notifications_test_mode` is on (a staging/test instance), webhook + email
deliveries are LOGGED but not actually sent, so event routing can be validated
without spamming real recipients. Opt-in, default off. A per-destination `dry_run`
does the same for a single webhook destination. The explicit "send test email"
SMTP connectivity check bypasses it (force=True).
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-testmode-test-"))

import api            # noqa: E402
import smtp_notifier  # noqa: E402


class TestEmailSandbox(unittest.TestCase):
    def test_dry_run_when_test_mode(self):
        r = smtp_notifier.send_email({'notifications_test_mode': True, 'smtp_host': 'x'},
                                     ['a@b.c'], 'subj', 'body')
        self.assertTrue(r.get('dry_run'))
        self.assertEqual(r.get('recipients'), 1)

    def test_force_bypasses_dry_run(self):
        # force=True must NOT short-circuit to a dry-run — it proceeds to send and
        # (no SMTP server configured) fails, proving the bypass took effect.
        with self.assertRaises(Exception) as cm:
            smtp_notifier.send_email({'notifications_test_mode': True, 'smtp_host': '',
                                      'smtp_from': 'x@y.z'}, ['a@b.c'], 's', 'b', force=True)
        self.assertNotIsInstance(cm.exception, AssertionError)


class TestWebhookSandbox(unittest.TestCase):
    def setUp(self):
        self._cfg = api.CONFIG_FILE
        self._log = api._log_webhook
        self._d = tempfile.mkdtemp()
        api.CONFIG_FILE = api.Path(self._d) / 'config.json'
        self._logged = []
        api._log_webhook = lambda ev, url, status, detail='': self._logged.append((status, detail))

    def tearDown(self):
        api.CONFIG_FILE = self._cfg
        api._log_webhook = self._log

    def _dispatch(self):
        api._dispatch_one_webhook(
            'device_offline',
            {'url': 'https://hooks.example.com/x', 'format': 'generic'},
            {}, 'a message', 'A Title', 5)

    def test_global_test_mode_logs_dry_run_not_send(self):
        api.save(api.CONFIG_FILE, {'notifications_test_mode': True, 'webhook_block_local': False})
        self._dispatch()
        self.assertTrue(any(s == 'dry-run' for s, _ in self._logged),
                        f'expected a dry-run log, got {self._logged}')

    def test_per_destination_dry_run(self):
        api.save(api.CONFIG_FILE, {'webhook_block_local': False})
        api._dispatch_one_webhook(
            'device_offline',
            {'url': 'https://hooks.example.com/x', 'format': 'generic', 'dry_run': True},
            {}, 'm', 'T', 5)
        self.assertTrue(any(s == 'dry-run' for s, _ in self._logged))


class TestSourceWiring(unittest.TestCase):
    def test_wiring(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("if dest.get('dry_run') or cfg.get('notifications_test_mode'):", src)
        self.assertIn("force=True,   # v5.4.1 (E6)", src)          # SMTP-test bypass
        self.assertIn("cfg['notifications_test_mode'] = bool(body['notifications_test_mode'])", src)
        sn = (_CGI / "smtp_notifier.py").read_text()
        self.assertIn("if not force and cfg.get('notifications_test_mode'):", sn)


if __name__ == '__main__':
    unittest.main()

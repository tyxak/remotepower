"""v3.4.0: SMART failure classification + global webhook rate limit.

Imports api.py against a throwaway data dir (the established pattern — see
test_routeros / test_opnsense).
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'server' / 'cgi-bin'))

import api  # noqa: E402


class TestSmartDiskFailed(unittest.TestCase):
    """UNKNOWN must NOT count as a failure; FAILED / bad-sectors must."""

    def test_not_failed(self):
        for d in ({'health': 'UNKNOWN'}, {'health': 'PASSED'},
                  {'health': 'OK'}, {'health': ''},
                  {'health': 'PASSED', 'reallocated_sectors': 0}):
            self.assertFalse(api._smart_disk_failed(d), d)

    def test_failed(self):
        for d in ({'health': 'FAILED'}, {'health': 'FAILURE'},
                  {'health': 'PASSED', 'reallocated_sectors': 3},
                  {'health': 'UNKNOWN', 'pending_sectors': 1},
                  {'health': 'OK', 'offline_uncorrectable': 2}):
            self.assertTrue(api._smart_disk_failed(d), d)

    def test_non_dict(self):
        self.assertFalse(api._smart_disk_failed(None))
        self.assertFalse(api._smart_disk_failed('x'))


class TestWebhookRateLimit(unittest.TestCase):
    def setUp(self):
        try:
            api.WEBHOOK_RATELIMIT_FILE.unlink()
        except Exception:
            pass

    def test_caps_at_max(self):
        n = api.WEBHOOK_RATE_MAX
        results = [api._webhook_rate_limit_ok() for _ in range(n + 5)]
        # exactly MAX sends are allowed in the window; the rest are dropped
        self.assertEqual(sum(1 for r in results if r), n)
        self.assertTrue(all(results[:n]))
        self.assertFalse(results[n])      # the (MAX+1)th is blocked

    def test_window_prunes(self):
        # entries older than the window don't count toward the cap
        old = api.time.time() - api.WEBHOOK_RATE_WINDOW - 5
        api.save(api.WEBHOOK_RATELIMIT_FILE, {'sends': [old] * api.WEBHOOK_RATE_MAX})
        self.assertTrue(api._webhook_rate_limit_ok())


class TestNewPortDefault(unittest.TestCase):
    """A new listening port is informational by default: recent-activity on,
    but no alert / webhook / Needs-Attention nag unless the operator opts in."""

    def setUp(self):
        # ensure no saved channel_routing influences the default
        try:
            cfg = api.load(api.CONFIG_FILE) or {}
            cfg.pop('channel_routing', None)
            api.save(api.CONFIG_FILE, cfg)
        except Exception:
            pass

    def test_new_port_no_alert_no_webhook_no_na(self):
        self.assertFalse(api._channel_allowed('new_port_detected', 'alerts'))
        self.assertFalse(api._channel_allowed('new_port_detected', 'webhook'))
        self.assertFalse(api._channel_allowed('new_port_detected', 'needs_attention'))

    def test_new_port_still_logged_in_activity(self):
        self.assertTrue(api._channel_allowed('new_port_detected', 'recent_activity'))

    def test_other_events_still_alert(self):
        self.assertTrue(api._channel_allowed('smart_failure', 'alerts'))
        self.assertTrue(api._channel_allowed('cve_found', 'alerts'))


if __name__ == '__main__':
    unittest.main()

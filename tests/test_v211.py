#!/usr/bin/env python3
"""
Tests for v2.1.1 bug fixes:

  - DEVICES_FILE save in heartbeat must be blocking so last_seen always
    persists. The 2.1.0 regression used _save_nb which silently dropped
    last_seen updates under flock contention, causing devices to drift
    past TTL → marked offline → "offline bug still persistent".
  - DEFAULT_ONLINE_TTL bumped to 300s (5 missed polls at 60s)
  - check_offline_webhooks logs OFFLINE/ONLINE transitions to stderr
    regardless of webhook config
  - log_alert message includes the first matched line (not just count)
  - per-container action endpoint validates against the agent's
    reported container list (security boundary)
"""
import importlib.util
import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_CGI_BIN = Path(__file__).parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_TMPDIR = tempfile.mkdtemp()
os.environ["RP_DATA_DIR"] = _TMPDIR
os.environ["REQUEST_METHOD"] = "GET"
os.environ["PATH_INFO"] = "/"
os.environ["CONTENT_LENGTH"] = "0"

_spec = importlib.util.spec_from_file_location("api_v211", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Captured(SystemExit):
    def __init__(self, status, body):
        super().__init__(0)
        self.status = status
        self.body = body


def _capture_respond():
    def fake_respond(status, data):
        raise _Captured(status, data)
    api.respond = fake_respond


class _StdinShim:
    def __init__(self, data: bytes):
        self.buffer = io.BytesIO(data)


def _set_request(method='GET', body=None, query=''):
    os.environ['REQUEST_METHOD'] = method
    os.environ['QUERY_STRING'] = query
    if body is not None:
        body_bytes = json.dumps(body).encode('utf-8')
        os.environ['CONTENT_LENGTH'] = str(len(body_bytes))
        api.sys.stdin = _StdinShim(body_bytes)
    else:
        os.environ['CONTENT_LENGTH'] = '0'
        api.sys.stdin = _StdinShim(b'')


def _stub_auth(username='admin'):
    api.require_auth = lambda **kw: username
    api.require_admin_auth = lambda: username


class _Base(unittest.TestCase):
    def setUp(self):
        self._data_dir = Path(tempfile.mkdtemp())
        api.DATA_DIR        = self._data_dir
        api.DEVICES_FILE    = self._data_dir / 'devices.json'
        api.CMDS_FILE       = self._data_dir / 'commands.json'
        api.CMD_OUTPUT_FILE = self._data_dir / 'cmd_output.json'
        api.CONTAINERS_FILE = self._data_dir / 'containers.json'
        api.CONFIG_FILE     = self._data_dir / 'config.json'
        api.UPTIME_FILE     = self._data_dir / 'uptime.json'
        api.AUDIT_LOG_FILE  = self._data_dir / 'audit_log.json'

        _capture_respond()
        _stub_auth('admin')
        api.fire_webhook = lambda *_, **__: None

        # Capture stderr writes so we can assert logging happened
        self._stderr_buf = io.StringIO()
        self._orig_stderr_write = api.sys.stderr.write
        api.sys.stderr.write = self._stderr_buf.write

        api.save(api.DEVICES_FILE, {
            'dev1': {'name': 'host1', 'token': 't1',
                     'last_seen': int(time.time()), 'monitored': True,
                     'poll_interval': 60},
        })

    def tearDown(self):
        api.sys.stderr.write = self._orig_stderr_write


# ─── Offline TTL + logging ────────────────────────────────────────────────


class TestOfflineDetection(_Base):

    def test_default_online_ttl_is_five_minutes(self):
        """The bump from 180→300 is the new 'allow 5 missed polls' floor."""
        self.assertEqual(api.DEFAULT_ONLINE_TTL, 300)
        self.assertGreaterEqual(api.MIN_ONLINE_TTL, 150)

    def test_get_online_ttl_returns_default(self):
        api.save(api.CONFIG_FILE, {})
        self.assertEqual(api.get_online_ttl(), 300)

    def test_get_online_ttl_clamped_to_min(self):
        api.save(api.CONFIG_FILE, {'online_ttl': 30})  # below MIN
        self.assertEqual(api.get_online_ttl(), api.MIN_ONLINE_TTL)

    def test_offline_logs_to_stderr_even_without_webhook(self):
        """The core fix: when nothing is in nginx logs, the operator has
        no diagnostic. Now every state transition logs unconditionally.

        OFFLINE is debounced (see _offline_thresholds): the first sweep
        only arms a candidate, so drive a second sweep with the candidate
        aged past the debounce window to get the actual transition."""
        # Make the device look offline: last_seen 10 minutes ago
        devs = api.load(api.DEVICES_FILE)
        devs['dev1']['last_seen'] = int(time.time()) - 600
        api.save(api.DEVICES_FILE, devs)
        # Disable webhooks — used to mean silent flip
        api.save(api.CONFIG_FILE, {'webhook_events': {'device_offline': False}})

        # First sweep arms the debounce candidate but must NOT fire yet.
        api.check_offline_webhooks()
        self.assertNotIn('OFFLINE', self._stderr_buf.getvalue())
        # Age the candidate past the debounce window.
        cfg = api.load(api.CONFIG_FILE)
        cfg['offline_pending']['dev1'] = int(time.time()) - 9999
        api.save(api.CONFIG_FILE, cfg)

        api.check_offline_webhooks()
        logs = self._stderr_buf.getvalue()
        self.assertIn('OFFLINE', logs)
        self.assertIn('dev1', logs)
        self.assertIn('last_seen=', logs)
        self.assertIn('delta=', logs)
        self.assertIn('ttl=', logs)

    def test_online_transition_also_logged(self):
        # Plant the offline-notified marker so the next pass sees a
        # back-online transition
        devs = api.load(api.DEVICES_FILE)
        devs['dev1']['last_seen'] = int(time.time())  # currently online
        api.save(api.DEVICES_FILE, devs)
        api.save(api.CONFIG_FILE, {'offline_notified': {'dev1': True},
                                   'webhook_events': {'device_offline': False}})
        api.check_offline_webhooks()
        logs = self._stderr_buf.getvalue()
        self.assertIn('ONLINE', logs)
        self.assertIn('dev1', logs)

    def test_skips_devices_with_no_last_seen(self):
        """A device that was enrolled but never heartbeated shouldn't
        register as 'offline' — there's nothing to be offline from."""
        api.save(api.DEVICES_FILE, {
            'never': {'name': 'never', 'token': 'x', 'last_seen': 0,
                      'monitored': True},
        })
        api.check_offline_webhooks()
        logs = self._stderr_buf.getvalue()
        self.assertNotIn('OFFLINE', logs)

    def test_skips_agentless_devices(self):
        api.save(api.DEVICES_FILE, {
            'switch1': {'name': 'switch1', 'agentless': True,
                        'last_seen': 0, 'monitored': True},
        })
        api.check_offline_webhooks()
        logs = self._stderr_buf.getvalue()
        self.assertNotIn('OFFLINE', logs)

    def test_skips_unmonitored_devices(self):
        devs = api.load(api.DEVICES_FILE)
        devs['dev1']['monitored'] = False
        devs['dev1']['last_seen'] = int(time.time()) - 600
        api.save(api.DEVICES_FILE, devs)
        api.check_offline_webhooks()
        logs = self._stderr_buf.getvalue()
        self.assertNotIn('OFFLINE', logs)


# ─── per-device threshold + debounce flap hardening ────────────────────────


class TestOfflineFlapHardening(_Base):
    """Per-device threshold + debounce that kill the OFFLINE→ONLINE-in-
    the-same-second flap (see api._offline_thresholds / offline_pending)."""

    def test_threshold_scales_with_poll_interval(self):
        # A slow poller's cutoff is driven by its own interval, not the
        # global TTL, so it isn't perpetually flagged offline.
        offline_after, debounce = api._offline_thresholds(
            {'poll_interval': 600}, ttl=300)
        self.assertEqual(
            offline_after, 600 * api.OFFLINE_MISSED_POLLS + api.OFFLINE_GRACE_S)
        self.assertEqual(debounce, 600)

    def test_threshold_floored_by_global_ttl(self):
        # A fast poller never gets a cutoff below the operator's TTL.
        offline_after, debounce = api._offline_thresholds(
            {'poll_interval': 30}, ttl=300)
        self.assertEqual(offline_after, 300 + api.OFFLINE_GRACE_S)
        self.assertEqual(debounce, max(api.OFFLINE_GRACE_S, 30))

    def test_single_sweep_arms_candidate_without_firing(self):
        devs = api.load(api.DEVICES_FILE)
        devs['dev1']['last_seen'] = int(time.time()) - 9999
        api.save(api.DEVICES_FILE, devs)
        api.check_offline_webhooks()
        self.assertNotIn('OFFLINE', self._stderr_buf.getvalue())
        cfg = api.load(api.CONFIG_FILE)
        self.assertIn('dev1', cfg.get('offline_pending', {}))
        self.assertFalse(cfg.get('offline_notified', {}).get('dev1'))

    def test_heartbeat_within_debounce_clears_candidate_no_flap(self):
        # Arm a candidate, then let the device 'beat' (fresh last_seen)
        # before the debounce window: OFFLINE must never fire and the
        # candidate must be dropped. This is the flap the fix targets.
        devs = api.load(api.DEVICES_FILE)
        devs['dev1']['last_seen'] = int(time.time()) - 9999
        api.save(api.DEVICES_FILE, devs)
        api.check_offline_webhooks()                  # arms candidate
        devs = api.load(api.DEVICES_FILE)
        devs['dev1']['last_seen'] = int(time.time())  # device beat
        api.save(api.DEVICES_FILE, devs)
        api.check_offline_webhooks()                  # clears, must not fire
        self.assertNotIn('OFFLINE', self._stderr_buf.getvalue())
        cfg = api.load(api.CONFIG_FILE)
        self.assertNotIn('dev1', cfg.get('offline_pending', {}))

    def test_candidate_past_debounce_fires_offline(self):
        devs = api.load(api.DEVICES_FILE)
        devs['dev1']['last_seen'] = int(time.time()) - 9999
        api.save(api.DEVICES_FILE, devs)
        api.check_offline_webhooks()                  # arms candidate
        cfg = api.load(api.CONFIG_FILE)
        cfg['offline_pending']['dev1'] = int(time.time()) - 9999   # age it
        api.save(api.CONFIG_FILE, cfg)
        api.check_offline_webhooks()                  # confirms → fires
        self.assertIn('OFFLINE', self._stderr_buf.getvalue())
        cfg = api.load(api.CONFIG_FILE)
        self.assertTrue(cfg['offline_notified'].get('dev1'))
        self.assertNotIn('dev1', cfg.get('offline_pending', {}))

    def test_skip_dev_id_cancels_pending_candidate(self):
        # The actively-heartbeating device is exempt: its armed candidate
        # is cancelled so its own slightly-stale pre-commit last_seen can't
        # confirm a spurious OFFLINE.
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg['offline_pending'] = {'dev1': int(time.time()) - 9999}
        api.save(api.CONFIG_FILE, cfg)
        devs = api.load(api.DEVICES_FILE)
        devs['dev1']['last_seen'] = int(time.time()) - 9999
        api.save(api.DEVICES_FILE, devs)
        api.check_offline_webhooks(skip_dev_id='dev1')
        self.assertNotIn('OFFLINE', self._stderr_buf.getvalue())
        cfg = api.load(api.CONFIG_FILE)
        self.assertNotIn('dev1', cfg.get('offline_pending', {}))


# ─── log_alert message includes sample ─────────────────────────────────────


class TestLogAlertMessage(_Base):

    def test_message_includes_first_matched_line(self):
        msg = api._webhook_message('log_alert', {
            'name': 'pmg01.tvipper.com',
            'unit': 'postfix.service',
            'pattern': 'warning|error|critical|FATAL',
            'count': 1,
            'sample': ['Nov 13 12:00:01 pmg01 postfix/smtpd[1234]: warning: '
                       'unknown[10.0.0.5]: SASL LOGIN authentication failed'],
        })
        # The old format only had pattern + count
        self.assertIn('pattern "warning|error|critical|FATAL"', msg)
        self.assertIn('matched 1 time', msg)
        # New: actual log line content
        self.assertIn('SASL LOGIN authentication failed', msg)
        self.assertIn('postfix/smtpd', msg)

    def test_message_truncates_long_lines(self):
        long_line = 'X' * 5000
        msg = api._webhook_message('log_alert', {
            'name': 'host', 'unit': 'u.service',
            'pattern': '.*', 'count': 1, 'sample': [long_line],
        })
        # Should be truncated
        self.assertLess(len(msg), 500)
        self.assertIn('…', msg)

    def test_message_indicates_additional_matches(self):
        msg = api._webhook_message('log_alert', {
            'name': 'host', 'unit': 'u.service',
            'pattern': 'err', 'count': 5,
            'sample': ['err line 1', 'err line 2', 'err line 3'],
        })
        self.assertIn('err line 1', msg)
        # Should mention the additional lines
        self.assertIn('+ 2 more', msg)

    def test_message_handles_empty_sample(self):
        msg = api._webhook_message('log_alert', {
            'name': 'host', 'unit': 'u.service',
            'pattern': 'err', 'count': 1, 'sample': [],
        })
        # No "→" prefix because nothing to show
        self.assertNotIn('→', msg)
        self.assertIn('matched 1', msg)

    def test_message_handles_missing_sample_key(self):
        msg = api._webhook_message('log_alert', {
            'name': 'host', 'unit': 'u.service',
            'pattern': 'err', 'count': 1,
            # no 'sample' key at all
        })
        # Falls back gracefully — no crash, no "→"
        self.assertNotIn('→', msg)


# ─── Per-container action endpoint ─────────────────────────────────────────


class TestContainerAction(_Base):

    def setUp(self):
        super().setUp()
        # Plant a device with a reported container
        api.save(api.CONTAINERS_FILE, {
            'dev1': {
                'ts': int(time.time()),
                'items': [
                    {'id': 'abc123def456', 'name': 'wizarr',
                     'runtime': 'docker', 'status': 'Up 9 days'},
                ],
            },
        })

    def _action(self, dev_id, body):
        _set_request('POST', body)
        try:
            api.handle_device_container_action(dev_id)
        except _Captured as c:
            return c
        self.fail("respond not called")

    def test_start_queues_container_command(self):
        r = self._action('dev1', {'runtime': 'docker', 'action': 'start',
                                  'container_id': 'abc123def456'})
        self.assertEqual(r.status, 200)
        cmds = api.load(api.CMDS_FILE)
        self.assertIn('container:docker:start:abc123def456', cmds.get('dev1', []))

    def test_stop_restart_logs_all_accepted(self):
        for action in ('stop', 'restart', 'pause', 'unpause', 'logs'):
            r = self._action('dev1', {'runtime': 'docker', 'action': action,
                                      'container_id': 'abc123def456'})
            self.assertEqual(r.status, 200, f'action {action}')

    def test_rejects_unknown_action(self):
        r = self._action('dev1', {'runtime': 'docker', 'action': 'rm',
                                  'container_id': 'abc123def456'})
        self.assertEqual(r.status, 400)
        self.assertIn('action must be one of', r.body['error'])

    def test_rejects_unknown_runtime(self):
        r = self._action('dev1', {'runtime': 'lxc', 'action': 'start',
                                  'container_id': 'abc123def456'})
        self.assertEqual(r.status, 400)

    def test_rejects_unreported_container(self):
        """Security boundary: ID must be in the device's reported list."""
        r = self._action('dev1', {'runtime': 'docker', 'action': 'start',
                                  'container_id': 'nonexistent'})
        self.assertEqual(r.status, 400)
        self.assertIn('reported container', r.body['error'])
        cmds = api.load(api.CMDS_FILE)
        self.assertEqual(cmds.get('dev1', []), [])

    def test_rejects_shell_injection_attempt(self):
        """Argv-only invocation in the agent + tight ID regex server-side."""
        for bad in ('abc; rm -rf /', '$(curl evil)', '../etc/passwd',
                    'abc def', 'abc/123', ''):
            r = self._action('dev1', {'runtime': 'docker', 'action': 'start',
                                      'container_id': bad})
            self.assertEqual(r.status, 400, f'should reject: {bad!r}')

    def test_rejects_agentless(self):
        api.save(api.DEVICES_FILE, {
            'switch1': {'name': 'switch1', 'agentless': True,
                        'last_seen': int(time.time())},
        })
        r = self._action('switch1', {'runtime': 'docker', 'action': 'start',
                                     'container_id': 'abc123def456'})
        self.assertEqual(r.status, 400)


if __name__ == '__main__':
    unittest.main(verbosity=2)

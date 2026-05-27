#!/usr/bin/env python3
"""
Tests for v2.2.4 — fleet event log + unmonitored attention filter.

Covers two bugs from live testing of 2.2.3:

1. Recent fleet events panel was empty. Root cause: the webhook log
   only stored delivery attempts. A device_offline fired with no
   webhook URL configured and no email-for-event enabled simply did
   not get logged anywhere. v2.2.4 adds a dedicated fleet_events.json
   that records every fired event regardless of destinations.

2. Unmonitored devices showed up in "Needs attention". v2.2.4 filters
   them out (the same gate the alerting pipeline already applies).
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

_ROOT    = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_TMPDIR = tempfile.mkdtemp()
os.environ["RP_DATA_DIR"]    = _TMPDIR
os.environ["REQUEST_METHOD"] = "GET"
os.environ["PATH_INFO"]      = "/"
os.environ["CONTENT_LENGTH"] = "0"

_spec = importlib.util.spec_from_file_location("api_v224", _CGI_BIN / "api.py")
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


def _stub_auth():
    api.require_auth = lambda **kw: 'viewer'
    api.require_admin_auth = lambda: 'admin'


def _set_method(m='GET', qs=''):
    os.environ['REQUEST_METHOD'] = m
    os.environ['QUERY_STRING'] = qs


class _Base(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        api.DATA_DIR           = self._tmp
        api.CONFIG_FILE        = self._tmp / 'config.json'
        api.DEVICES_FILE       = self._tmp / 'devices.json'
        api.WEBHOOK_LOG_FILE   = self._tmp / 'webhook_log.json'
        api.FLEET_EVENTS_FILE  = self._tmp / 'fleet_events.json'
        api.AUDIT_LOG_FILE     = self._tmp / 'audit_log.json'
        _capture_respond()
        _stub_auth()


# ─── _record_fleet_event ─────────────────────────────────────────────────


class TestRecordFleetEvent(_Base):

    def test_records_event(self):
        api._record_fleet_event('device_offline', {
            'device_id': 'd1', 'device_name': 'web01',
        })
        store = api.load(api.FLEET_EVENTS_FILE)
        events = store.get('events', [])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['event'], 'device_offline')
        self.assertEqual(events[0]['payload']['device_name'], 'web01')
        self.assertIn('ts', events[0])

    def test_test_event_NOT_recorded(self):
        # Operator-triggered SMTP / webhook tests are not fleet events
        api._record_fleet_event('test', {'channel': 'email'})
        store = api.load(api.FLEET_EVENTS_FILE)
        self.assertEqual(store.get('events', []), [])

    def test_payload_summarised_not_verbatim(self):
        # Big payload — only the discriminator keys should survive,
        # bounding the on-disk file size.
        big = 'A' * 10000
        api._record_fleet_event('cve_found', {
            'device_name': 'web01',
            'cve_id':      'CVE-2024-12345',
            'description': big,    # not in the summary keys
            'references':  ['url'] * 100,
            'critical':    3,
            'high':        12,
        })
        events = api.load(api.FLEET_EVENTS_FILE)['events']
        p = events[0]['payload']
        self.assertEqual(p['cve_id'], 'CVE-2024-12345')
        self.assertEqual(p['critical'], 3)
        self.assertEqual(p['high'], 12)
        # Big fields filtered out — not in the SUMMARY_KEYS list
        self.assertNotIn('description', p)
        self.assertNotIn('references', p)

    def test_string_payload_capped_at_256(self):
        api._record_fleet_event('drift_detected', {
            'device_name': 'web01',
            'path':        '/' + 'X' * 500,
        })
        events = api.load(api.FLEET_EVENTS_FILE)['events']
        self.assertLessEqual(len(events[0]['payload']['path']), 256)

    def test_log_capped_at_max_fleet_events(self):
        for i in range(api.MAX_FLEET_EVENTS + 50):
            api._record_fleet_event('device_offline', {
                'device_id': f'd{i}', 'device_name': f'host{i}',
            })
        events = api.load(api.FLEET_EVENTS_FILE)['events']
        self.assertEqual(len(events), api.MAX_FLEET_EVENTS)
        # The newest survive; check the tail
        self.assertEqual(events[-1]['payload']['device_name'],
                         f'host{api.MAX_FLEET_EVENTS + 49}')

    def test_recorded_even_with_no_destinations(self):
        """The core bug. fire_webhook called with no webhook URL and
        email disabled — used to vanish into the void; now is recorded."""
        api.save(api.CONFIG_FILE, {
            'webhook_url':  '',           # not configured
            'smtp_enabled': False,        # not configured
            'webhook_events': {},
            'email_events':   {},
        })
        # Stub the maintenance + gate checks so we get to the record step
        api.is_webhook_event_enabled = lambda ev: True
        api.in_maintenance = lambda ev, p: None
        api.fire_webhook('device_offline', {
            'device_id': 'd1', 'device_name': 'web01',
        })
        events = api.load(api.FLEET_EVENTS_FILE).get('events', [])
        self.assertEqual(len(events), 1,
                         "v2.2.4 must record fleet events even when no "
                         "destination is configured")
        self.assertEqual(events[0]['event'], 'device_offline')


# ─── handle_fleet_events endpoint ────────────────────────────────────────


class TestHandleFleetEvents(_Base):

    def test_returns_newest_first(self):
        for i in range(5):
            api._record_fleet_event('device_offline', {
                'device_id': f'd{i}', 'device_name': f'host{i}',
            })
            time.sleep(0.001)
        _set_method('GET', '')
        try: api.handle_fleet_events()
        except _Captured as c: r = c
        self.assertEqual(r.status, 200)
        self.assertEqual(len(r.body), 5)
        # Newest first — last recorded is at index 0
        self.assertEqual(r.body[0]['payload']['device_name'], 'host4')
        self.assertEqual(r.body[-1]['payload']['device_name'], 'host0')

    def test_limit_honoured(self):
        for i in range(20):
            api._record_fleet_event('device_offline', {'device_id': f'd{i}'})
        _set_method('GET', 'limit=5')
        try: api.handle_fleet_events()
        except _Captured as c: r = c
        self.assertEqual(r.status, 200)
        self.assertEqual(len(r.body), 5)

    def test_limit_capped_at_max(self):
        # Even a wild limit can't exceed MAX_FLEET_EVENTS
        for i in range(api.MAX_FLEET_EVENTS):
            api._record_fleet_event('device_offline', {'device_id': f'd{i}'})
        _set_method('GET', 'limit=99999')
        try: api.handle_fleet_events()
        except _Captured as c: r = c
        self.assertEqual(len(r.body), api.MAX_FLEET_EVENTS)

    def test_no_events_returns_empty(self):
        _set_method('GET', '')
        try: api.handle_fleet_events()
        except _Captured as c: r = c
        self.assertEqual(r.status, 200)
        self.assertEqual(r.body, [])

    def test_invalid_limit_falls_back_to_default(self):
        for i in range(5):
            api._record_fleet_event('device_offline', {'device_id': f'd{i}'})
        _set_method('GET', 'limit=not-an-int')
        try: api.handle_fleet_events()
        except _Captured as c: r = c
        self.assertEqual(r.status, 200)
        # Default is 50; we have 5 entries so just get them all
        self.assertEqual(len(r.body), 5)

    def test_viewer_role_can_read(self):
        # Unlike /webhook/log (admin-only), /fleet/events is open to
        # any logged-in user. Verify the handler uses require_auth, not
        # require_admin_auth — by stubbing only the admin function to
        # raise, we'd see a SystemExit if the handler used it.
        api.require_admin_auth = lambda: (_ for _ in ()).throw(
            AssertionError("must not call require_admin_auth"))
        _set_method('GET', '')
        try: api.handle_fleet_events()
        except _Captured as c: pass
        # If we got here without AssertionError, the test passes


# ─── Frontend changes ───────────────────────────────────────────────────


class TestFrontendChanges(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.js = (_ROOT / 'server/html/static/js/app.js').read_text()

    def test_loadhome_uses_fleet_events(self):
        # v2.2.4 introduced /fleet/events for the activity panel.
        # v3.3.0 consolidates loadHome into a single /api/home round-trip
        # — that endpoint bundles fleet_events (the activity feed source)
        # inside its response. Either the legacy direct call or the
        # consolidated endpoint is acceptable.
        load_home_start = self.js.find('async function loadHome')
        self.assertGreater(load_home_start, 0)
        chunk = self.js[load_home_start:load_home_start + 2000]
        uses_direct  = "'/fleet/events?limit=50'" in chunk
        uses_bundled = "'/home'" in chunk and 'fleet_events' in chunk
        self.assertTrue(uses_direct or uses_bundled,
            'loadHome must source fleet events either directly via '
            "'/fleet/events?limit=50' or bundled inside '/api/home'")
        # Confirm /webhook/log is NOT in loadHome anymore
        self.assertNotIn("'/webhook/log'", chunk,
                         "loadHome must no longer call /webhook/log")

    def test_home_attention_uses_server_digest(self):
        # v2.4.7: the Needs Attention digest moved server-side to the
        # /api/attention endpoint (one source of truth, and it now
        # includes CVE + mailbox signals). The client renderer just
        # fetches and displays it.
        func_start = self.js.find('function _renderHomeAttention')
        self.assertGreater(func_start, 0)
        chunk = self.js[func_start:func_start + 2000]
        self.assertIn("api('GET', '/attention')", chunk,
                      "Attention panel must consume the /attention endpoint")

    def test_attention_filters_unmonitored_server_side(self):
        # The monitored-device gate moved into _compute_attention() on
        # the server. Same intent as the old client-side test: an
        # unmonitored device must not surface in the digest.
        api = (_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        cstart = api.find('def _compute_attention')
        self.assertGreater(cstart, 0)
        cchunk = api[cstart:cstart + 3500]
        self.assertIn("monitored", cchunk,
                      "_compute_attention must gate on the monitored flag")
        self.assertIn("get('monitored', True)", cchunk)

    def test_render_activity_handles_fleet_event_shape(self):
        # 2.2.4 entries are {ts, event, payload}. Renderer reads from
        # `p.path / p.unit / p.metric` etc — not a top-level `detail`.
        func_start = self.js.find('function _renderHomeActivity')
        chunk = self.js[func_start:func_start + 4000]
        # Filter & slice ordering (regression: filter before slice)
        filter_pos = chunk.find('.filter(')
        slice_pos  = chunk.find('.slice(', filter_pos)
        self.assertGreater(slice_pos, filter_pos)


if __name__ == '__main__':
    unittest.main(verbosity=2)

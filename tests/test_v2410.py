#!/usr/bin/env python3
"""
Tests for v2.4.10 — two bug fixes.

  1. Forced package scan was silently skipped on a stable host: the
     unchanged-list hash gate in send_package_list() also applied to
     forced sends. force=True now bypasses it.
  2. The 7-day status stripe was hardcoded ('unknown' x6 + today).
     Underlying cause: _record_uptime was only ever called with
     online=True, so uptime.json had no offline history. Offline
     transitions are now recorded; a real 7-day endpoint derives the
     stripe from uptime.json events.
"""

import sys as _cj_sys
from pathlib import Path as _cj_Path
_cj_sys.path.insert(0, str(_cj_Path(__file__).resolve().parent))
from clientjs import client_js
import importlib.machinery
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT    = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))


class TestForcedPackageBypass(unittest.TestCase):
    """The agent's send_package_list must bypass the hash gate when
    force=True."""

    @classmethod
    def setUpClass(cls):
        cls.src = (_ROOT / 'client' / 'remotepower-agent').read_text()

    def test_send_package_list_takes_force(self):
        self.assertIn('def send_package_list(creds, force=False)', self.src)

    def test_hash_gate_skipped_when_forced(self):
        # The unchanged-list short-circuit must be guarded by `not force`.
        self.assertIn('if not force and new_hash == _load_last_pkg_hash()',
                      self.src)

    def test_forced_call_passes_force(self):
        # The heartbeat's forced path must call with force=force_pkg_scan.
        self.assertIn('send_package_list(creds, force=force_pkg_scan)',
                      self.src)


class TestUptimeRecording(unittest.TestCase):
    """_record_uptime must now be called for offline transitions too."""

    @classmethod
    def setUpClass(cls):
        cls.src = (_CGI_BIN / 'api.py').read_text()

    def test_offline_transition_recorded(self):
        # Both an offline (False) and a recovery (True) _record_uptime call
        # must exist in the offline-detection sweep. The sweep may extract
        # name into a local before calling, so accept either form.
        offline_forms = (
            '_record_uptime(dev_id, dev.get(\'name\', dev_id), False)',
            '_record_uptime(dev_id, name, False)',
        )
        online_forms = (
            '_record_uptime(dev_id, dev.get(\'name\', dev_id), True)',
            '_record_uptime(dev_id, name, True)',
        )
        self.assertTrue(any(f in self.src for f in offline_forms),
                        'No _record_uptime(..., False) call found in offline sweep')
        self.assertTrue(any(f in self.src for f in online_forms),
                        'No _record_uptime(..., True) call found in offline sweep')


class TestFleetUptime7d(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault('REQUEST_METHOD', 'GET')
        os.environ.setdefault('PATH_INFO', '/')
        os.environ.setdefault('CONTENT_LENGTH', '0')
        _s = importlib.util.spec_from_file_location("api_v2410", _CGI_BIN / "api.py")
        cls.api = importlib.util.module_from_spec(_s)
        _s.loader.exec_module(cls.api)

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        self.api.UPTIME_FILE = self._tmp / 'uptime.json'
        self.api.DEVICES_FILE = self._tmp / 'devices.json'

    def test_day_status_helper(self):
        api = self.api
        DAY = 86400
        now = int(time.time())
        day_start = now - (now % DAY)
        day_end = day_start + DAY
        # No events at all → unknown.
        self.assertEqual(
            api._day_status_from_events([], day_start, day_end), 'unknown')
        # An online event before the day, nothing since → up all day.
        self.assertEqual(
            api._day_status_from_events(
                [{'ts': day_start - 999999, 'online': True}],
                day_start, day_end), 'up')
        # Offline coming into the day → down.
        self.assertEqual(
            api._day_status_from_events(
                [{'ts': day_start - 999999, 'online': False}],
                day_start, day_end), 'down')
        # Went offline during the day → down.
        self.assertEqual(
            api._day_status_from_events(
                [{'ts': day_start - 999999, 'online': True},
                 {'ts': day_start + 3600, 'online': False}],
                day_start, day_end), 'down')

    def test_endpoint_returns_seven_cells(self):
        api = self.api
        api.require_auth = lambda **kw: 'admin'
        now = int(time.time())
        # A device online since well before the 7-day window.
        api.save(api.UPTIME_FILE, {'d1': {
            'name': 'web01',
            'events': [{'ts': now - 30 * 86400, 'online': True}],
        }})
        api.save(api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'web01'}})
        cap = {}
        def fake_respond(s, b):
            cap['body'] = b
            raise SystemExit(0)
        api.respond = fake_respond
        try:
            api.handle_fleet_uptime7d()
        except SystemExit:
            pass
        arr = cap['body']['uptime']['d1']
        self.assertEqual(len(arr), 7)
        # Online for 30 days → every cell 'up'.
        self.assertEqual(set(arr), {'up'})

    def test_endpoint_unknown_when_no_history(self):
        api = self.api
        api.require_auth = lambda **kw: 'admin'
        # Device with an event only from today — earlier days unknown.
        now = int(time.time())
        api.save(api.UPTIME_FILE, {'d1': {
            'name': 'new01',
            'events': [{'ts': now, 'online': True}],
        }})
        api.save(api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'new01'}})
        cap = {}
        def fake_respond(s, b):
            cap['body'] = b
            raise SystemExit(0)
        api.respond = fake_respond
        try:
            api.handle_fleet_uptime7d()
        except SystemExit:
            pass
        arr = cap['body']['uptime']['d1']
        # The earliest day must be 'unknown' — no record back then.
        self.assertEqual(arr[0], 'unknown')

    def test_endpoint_excludes_unmonitored(self):
        # A device with monitored:false must not appear in the roster
        # stripe — same gate the attention digest applies.
        api = self.api
        api.require_auth = lambda **kw: 'admin'
        now = int(time.time())
        api.save(api.UPTIME_FILE, {
            'd1': {'name': 'web01',
                   'events': [{'ts': now - 30 * 86400, 'online': True}]},
            'd2': {'name': 'decom',
                   'events': [{'ts': now - 30 * 86400, 'online': True}]},
        })
        api.save(api.DEVICES_FILE, {
            'd1': {'id': 'd1', 'name': 'web01'},
            'd2': {'id': 'd2', 'name': 'decom', 'monitored': False},
        })
        cap = {}
        def fake_respond(s, b):
            cap['body'] = b
            raise SystemExit(0)
        api.respond = fake_respond
        try:
            api.handle_fleet_uptime7d()
        except SystemExit:
            pass
        uptime = cap['body']['uptime']
        self.assertIn('d1', uptime)
        self.assertNotIn('d2', uptime, 'unmonitored device leaked into the roster')


class TestFrontend(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.js = client_js()

    def test_stripe_uses_real_endpoint(self):
        idx = self.js.find('function _renderHomeFleet')
        chunk = self.js[idx:idx + 1800]
        self.assertIn("/fleet/uptime7d", chunk)
        # The old hardcoded 6x'unknown' mock must be gone as the
        # primary path (only kept as a labelled fallback).
        self.assertIn('fallback', chunk.lower())


if __name__ == '__main__':
    unittest.main(verbosity=2)

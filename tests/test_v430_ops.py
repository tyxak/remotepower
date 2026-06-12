#!/usr/bin/env python3
"""v4.3.0 operational-robustness pins: rollback schema guard, SQLite
integrity check, and the heartbeat rate floor.

Each of these is a failure-mode guard, so the tests exercise the failure:
a DB written by a newer server, and an agent polling faster than the floor.
"""
import importlib.util
import io
import os
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())

import storage  # noqa: E402


class TestSchemaRollbackGuard(unittest.TestCase):
    """A database stamped by a NEWER schema must warn loudly and must NOT be
    silently downgraded (the recorded version is the only rollback evidence)."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        storage.close_connection()

    def tearDown(self):
        storage.close_connection()

    def test_newer_db_warns_and_keeps_version(self):
        conn = storage._connect(self.d)
        conn.execute("UPDATE schema_meta SET value='99' WHERE key='schema_version'")
        storage.close_connection()
        err = io.StringIO()
        with redirect_stderr(err):
            conn = storage._connect(self.d)
        self.assertIn('NEWER than this server', err.getvalue())
        row = conn.execute(
            "SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()
        self.assertEqual(row['value'], '99',
                         'rollback evidence (newer version stamp) must survive')

    def test_current_db_connects_silently(self):
        storage._connect(self.d)
        storage.close_connection()
        err = io.StringIO()
        with redirect_stderr(err):
            storage._connect(self.d)
        self.assertNotIn('NEWER', err.getvalue())


class TestIntegrityCheck(unittest.TestCase):
    def test_fresh_store_reports_ok(self):
        d = tempfile.mkdtemp()
        storage.close_connection()
        try:
            self.assertEqual(storage.integrity_check(d), 'ok')
        finally:
            storage.close_connection()


class TestHeartbeatRateFloor(unittest.TestCase):
    """heartbeat_min_interval_s: off by default; when set, an authenticated
    heartbeat arriving faster than the floor gets 429 and writes nothing."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        old = os.environ.get('RP_DATA_DIR')
        os.environ['RP_DATA_DIR'] = cls.tmp
        try:
            spec = importlib.util.spec_from_file_location('api_v430ops', _CGI / 'api.py')
            cls.api = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.api)
        finally:
            if old is not None:
                os.environ['RP_DATA_DIR'] = old
        cls.api.method = lambda: 'POST'

    def setUp(self):
        api = self.api
        api._LOAD_CACHE.clear()
        self.cap = {}

        def fake_respond(status, body=None):
            self.cap['status'] = status
            self.cap['body'] = body
            raise SystemExit(0)
        api.respond = fake_respond

    _seq = 0

    def _beat(self, last_seen, floor):
        # Fresh device id per call: the save() layer has a last_seen
        # anti-regression guard ("last_seen regression prevented") that
        # refuses to rewind an existing device's last_seen on disk — exactly
        # right in production, but it would silently override this fixture.
        TestHeartbeatRateFloor._seq += 1
        dev_id = f'dev{TestHeartbeatRateFloor._seq}'
        api = self.api
        api._LOAD_CACHE.clear()
        api.save(api.CONFIG_FILE, {'heartbeat_min_interval_s': floor} if floor else {})
        api.save(api.DEVICES_FILE, {dev_id: {
            'id': dev_id, 'name': 'host1', 'token': 'tok',
            'poll_interval': 60, 'last_seen': last_seen,
        }})
        api.get_json_body = lambda: {'device_id': dev_id, 'token': 'tok',
                                     'version': '9.9.9'}
        try:
            api.handle_heartbeat()
        except SystemExit:
            pass
        return self.cap.get('status'), dev_id

    def test_floor_off_by_default_allows_rapid_heartbeats(self):
        status, _ = self._beat(last_seen=int(time.time()), floor=0)
        self.assertNotEqual(status, 429)

    def test_too_fast_heartbeat_gets_429(self):
        before = int(time.time())
        status, dev_id = self._beat(last_seen=before, floor=30)
        self.assertEqual(status, 429)
        self.assertIn('retry_after', self.cap['body'])
        # and nothing was written: last_seen unchanged from the fixture value
        self.api._LOAD_CACHE.clear()
        dev = (self.api.load(self.api.DEVICES_FILE) or {}).get(dev_id) or {}
        self.assertEqual(dev.get('last_seen', 0), before)

    def test_heartbeat_after_floor_passes(self):
        status, _ = self._beat(last_seen=int(time.time()) - 120, floor=30)
        self.assertNotEqual(status, 429)


class TestBumpScriptDryRun(unittest.TestCase):
    """tools/bump_version.py must keep finding every version surface — a
    pattern that stops matching means a checklist step silently went manual
    again. Dry-run only: writes nothing."""

    def test_dry_run_touches_every_surface(self):
        import subprocess
        r = subprocess.run(
            [sys.executable, str(_ROOT / 'tools' / 'bump_version.py'),
             '9.9.9', '--dry-run'],
            capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for surface in ('api.py', 'remotepower-agent.py',
                        'remotepower-agent-win.py', 'remotepower-agent-mac.py',
                        'sw.js', 'index.html', 'README.md', 'CHANGELOG.md'):
            self.assertIn(surface, r.stdout, f'{surface} missing from bump plan')


if __name__ == '__main__':
    unittest.main()

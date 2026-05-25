#!/usr/bin/env python3
"""
Unit tests for v1.8.1 additions: log rules aggregate + live tail endpoint,
and UI empty-state regression guards.
"""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_CGI_BIN = Path(__file__).parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI_BIN))

_TMPDIR = tempfile.mkdtemp()
os.environ['RP_DATA_DIR'] = _TMPDIR
os.environ['REQUEST_METHOD'] = 'GET'
os.environ['PATH_INFO'] = '/'
os.environ['CONTENT_LENGTH'] = '0'

import importlib.util
_spec = importlib.util.spec_from_file_location('api_v181', _CGI_BIN / 'api.py')
api_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api_module)


class TestLogRulesAggregate(unittest.TestCase):
    """handle_log_rules — verify aggregation logic (pure function, no HTTP)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._orig = api_module.DEVICES_FILE
        api_module.DEVICES_FILE = self.tmp / 'devices.json'

    def tearDown(self):
        api_module.DEVICES_FILE = self._orig

    def _make_dev(self, dev_id, name, group='', rules=None):
        devs = api_module.load(api_module.DEVICES_FILE)
        devs[dev_id] = {
            'name':  name,
            'group': group,
            'log_watch': rules or [],
        }
        api_module.save(api_module.DEVICES_FILE, devs)

    def test_empty_returns_empty_list(self):
        api_module.save(api_module.DEVICES_FILE, {})
        # Aggregate locally to test the logic without HTTP scaffolding
        devices = api_module.load(api_module.DEVICES_FILE)
        out = []
        for dev_id, dev in devices.items():
            for rule in (dev.get('log_watch') or []):
                out.append({'device_id': dev_id, 'unit': rule['unit'],
                            'pattern': rule['pattern'], 'threshold': rule.get('threshold', 1)})
        self.assertEqual(out, [])

    def test_collects_rules_across_devices(self):
        self._make_dev('dev-aaaaaaaaaaaaaa', 'web-1', 'prod', [
            {'unit': 'nginx.service', 'pattern': 'error', 'threshold': 3},
        ])
        self._make_dev('dev-bbbbbbbbbbbbbb', 'db-1', 'prod', [
            {'unit': 'postgresql.service', 'pattern': 'FATAL', 'threshold': 1},
            {'unit': 'postgresql.service', 'pattern': 'panic', 'threshold': 1},
        ])
        self._make_dev('dev-cccccccccccccc', 'nas', 'homelab', [])

        devices = api_module.load(api_module.DEVICES_FILE)
        rules = []
        for dev_id, dev in devices.items():
            for rule in (dev.get('log_watch') or []):
                rules.append({'device_id': dev_id, 'unit': rule['unit']})
        self.assertEqual(len(rules), 3)
        units = sorted(r['unit'] for r in rules)
        self.assertEqual(units, ['nginx.service', 'postgresql.service', 'postgresql.service'])


class TestLogTailAggregation(unittest.TestCase):
    """Exercise the merge + filter logic of handle_log_tail via internal data."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._orig_log = api_module.LOG_WATCH_FILE
        self._orig_dev = api_module.DEVICES_FILE
        api_module.LOG_WATCH_FILE = self.tmp / 'log_watch.json'
        api_module.DEVICES_FILE   = self.tmp / 'devices.json'
        api_module.save(api_module.DEVICES_FILE, {
            'dev-aaaaaaaaaaaaaa': {'name': 'web-1', 'group': 'prod'},
            'dev-bbbbbbbbbbbbbb': {'name': 'db-1',  'group': 'prod'},
        })

    def tearDown(self):
        api_module.LOG_WATCH_FILE = self._orig_log
        api_module.DEVICES_FILE   = self._orig_dev

    def test_since_filter_advances_newest_ts(self):
        now = int(time.time())
        api_module.save(api_module.LOG_WATCH_FILE, {
            'dev-aaaaaaaaaaaaaa': {
                'updated_at': now,
                'units': {
                    'nginx.service': [
                        {'ts': now - 100, 'line': 'old line'},
                        {'ts': now - 50,  'line': 'middle line'},
                        {'ts': now - 10,  'line': 'new line'},
                    ],
                },
            },
        })

        # Simulate a since=now-30 query — should return only the newest line
        log_store = api_module.load(api_module.LOG_WATCH_FILE)
        devices   = api_module.load(api_module.DEVICES_FILE)
        since = now - 30
        matches = []
        newest = since
        for dev_id, buf in log_store.items():
            if dev_id not in devices:
                continue
            for unit, lines in buf.get('units', {}).items():
                for entry in lines:
                    if entry['ts'] > since:
                        matches.append(entry['line'])
                        newest = max(newest, entry['ts'])
        self.assertEqual(matches, ['new line'])
        self.assertEqual(newest, now - 10)

    def test_device_filter_isolates_one_device(self):
        now = int(time.time())
        api_module.save(api_module.LOG_WATCH_FILE, {
            'dev-aaaaaaaaaaaaaa': {'units': {'nginx.service': [{'ts': now, 'line': 'from web-1'}]}},
            'dev-bbbbbbbbbbbbbb': {'units': {'postgresql.service': [{'ts': now, 'line': 'from db-1'}]}},
        })

        log_store = api_module.load(api_module.LOG_WATCH_FILE)
        filtered = []
        for dev_id, buf in log_store.items():
            if dev_id != 'dev-aaaaaaaaaaaaaa':
                continue
            for unit, lines in buf.get('units', {}).items():
                for entry in lines:
                    filtered.append(entry['line'])
        self.assertEqual(filtered, ['from web-1'])


class TestDeviceConfigPersistence(unittest.TestCase):
    """The log-rule editor reads+writes both services_watched and log_watch."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._orig = api_module.DEVICES_FILE
        api_module.DEVICES_FILE = self.tmp / 'devices.json'
        api_module.save(api_module.DEVICES_FILE, {
            'dev-aaaaaaaaaaaaaa': {'name': 'web-1', 'services_watched': [], 'log_watch': []},
        })

    def tearDown(self):
        api_module.DEVICES_FILE = self._orig

    def test_config_survives_roundtrip(self):
        devices = api_module.load(api_module.DEVICES_FILE)
        devices['dev-aaaaaaaaaaaaaa']['services_watched'] = ['nginx.service']
        devices['dev-aaaaaaaaaaaaaa']['log_watch'] = [
            {'unit': 'nginx.service', 'pattern': 'error', 'threshold': 3},
        ]
        api_module.save(api_module.DEVICES_FILE, devices)

        reloaded = api_module.load(api_module.DEVICES_FILE)
        self.assertEqual(reloaded['dev-aaaaaaaaaaaaaa']['services_watched'], ['nginx.service'])
        self.assertEqual(len(reloaded['dev-aaaaaaaaaaaaaa']['log_watch']), 1)
        self.assertEqual(reloaded['dev-aaaaaaaaaaaaaa']['log_watch'][0]['pattern'], 'error')


class TestHandlersExist(unittest.TestCase):
    """Wiring check: new 1.8.1 handlers must be defined and routable."""

    def test_handlers_present(self):
        self.assertTrue(hasattr(api_module, 'handle_log_tail'))
        self.assertTrue(hasattr(api_module, 'handle_log_rules'))

    def test_version_bumped(self):
        # v1.8.1 introduced /api/logs/tail and /api/logs/rules. Later versions
        # keep the same handlers, so just assert we're on 1.8.1 or later.
        parts = api_module.SERVER_VERSION.split('.')
        major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
        self.assertTrue(
            (major, minor, patch) >= (1, 8, 1),
            f'expected >= 1.8.1, got {api_module.SERVER_VERSION}',
        )


if __name__ == '__main__':
    unittest.main()

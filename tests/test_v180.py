#!/usr/bin/env python3
"""
Unit tests for v1.8.0 features: service monitoring, maintenance windows,
and log ingestion helpers.
"""

import os
import sys
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

# Make the cgi-bin dir importable
_CGI_BIN = Path(__file__).parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI_BIN))

# Set up a data dir before importing api.py (it initializes constants from env)
_TMPDIR = tempfile.mkdtemp()
os.environ['RP_DATA_DIR'] = _TMPDIR
os.environ['REQUEST_METHOD'] = 'GET'
os.environ['PATH_INFO'] = '/'
os.environ['CONTENT_LENGTH'] = '0'

import importlib.util
_spec = importlib.util.spec_from_file_location('api_v180', _CGI_BIN / 'api.py')
api_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api_module)


class TestCronEvaluator(unittest.TestCase):
    """Tests for the lightweight cron evaluator used by maintenance windows."""

    def test_wildcards(self):
        self.assertTrue(api_module._cron_field_match('*', 5))
        self.assertTrue(api_module._cron_field_match('*', 0))
        self.assertTrue(api_module._cron_field_match('*', 59))

    def test_exact_match(self):
        self.assertTrue(api_module._cron_field_match('5', 5))
        self.assertFalse(api_module._cron_field_match('5', 6))
        self.assertFalse(api_module._cron_field_match('5', 4))

    def test_step_notation(self):
        self.assertTrue(api_module._cron_field_match('*/5', 0))
        self.assertTrue(api_module._cron_field_match('*/5', 5))
        self.assertTrue(api_module._cron_field_match('*/5', 15))
        self.assertFalse(api_module._cron_field_match('*/5', 7))
        self.assertFalse(api_module._cron_field_match('*/5', 11))

    def test_list_notation(self):
        self.assertTrue(api_module._cron_field_match('1,5,10', 5))
        self.assertTrue(api_module._cron_field_match('1,5,10', 1))
        self.assertTrue(api_module._cron_field_match('1,5,10', 10))
        self.assertFalse(api_module._cron_field_match('1,5,10', 6))

    def test_invalid_expression(self):
        # Wrong number of fields → never matches
        self.assertFalse(api_module._cron_match('* * *', int(time.time())))
        self.assertFalse(api_module._cron_match('', int(time.time())))

    def test_step_zero_no_match(self):
        # */0 would be division by zero — guard against it
        self.assertFalse(api_module._cron_field_match('*/0', 5))

    def test_always_matches_star_fields(self):
        # All-wildcard expression matches every minute
        self.assertTrue(api_module._cron_match('* * * * *', int(time.time())))


class TestMaintenanceWindows(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._orig_files = {}
        for attr in ('MAINT_FILE', 'MAINT_SUPPRESS_LOG', 'DEVICES_FILE'):
            self._orig_files[attr] = getattr(api_module, attr)
            setattr(api_module, attr, self.tmp / f'{attr.lower()}.json')
        # A single device for targeting
        api_module.save(api_module.DEVICES_FILE, {
            'dev-aaaaaaaaaaaaaa': {'name': 'web-1', 'group': 'prod'},
        })

    def tearDown(self):
        for attr, orig in self._orig_files.items():
            setattr(api_module, attr, orig)

    def test_inactive_returns_none(self):
        api_module.save(api_module.MAINT_FILE, {'windows': []})
        self.assertIsNone(api_module.in_maintenance('device_offline',
                                                    {'device_id': 'dev-aaaaaaaaaaaaaa'}))

    def test_oneshot_active_window_suppresses(self):
        now = int(time.time())
        start_iso = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now - 60))
        end_iso   = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now + 60))
        api_module.save(api_module.MAINT_FILE, {'windows': [{
            'id':     'w1',
            'reason': 'patching',
            'scope':  'device',
            'target': 'dev-aaaaaaaaaaaaaa',
            'start':  start_iso,
            'end':    end_iso,
        }]})
        result = api_module.in_maintenance('device_offline',
                                            {'device_id': 'dev-aaaaaaaaaaaaaa'})
        self.assertIsNotNone(result)
        self.assertEqual(result['reason'], 'patching')
        self.assertEqual(result['window_id'], 'w1')

    def test_oneshot_past_window_does_not_suppress(self):
        past = int(time.time()) - 3600
        api_module.save(api_module.MAINT_FILE, {'windows': [{
            'id':    'w2', 'reason': 'old', 'scope': 'device',
            'target': 'dev-aaaaaaaaaaaaaa',
            'start': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(past - 60)),
            'end':   time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(past)),
        }]})
        self.assertIsNone(api_module.in_maintenance('device_offline',
                                                     {'device_id': 'dev-aaaaaaaaaaaaaa'}))

    def test_global_window_applies_to_any_device(self):
        now = int(time.time())
        api_module.save(api_module.MAINT_FILE, {'windows': [{
            'id':    'wg', 'reason': 'fleet-wide', 'scope': 'global',
            'target': '',
            'start': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now - 60)),
            'end':   time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now + 60)),
        }]})
        self.assertIsNotNone(api_module.in_maintenance('monitor_down',
                                                        {'device_id': 'dev-aaaaaaaaaaaaaa'}))
        self.assertIsNotNone(api_module.in_maintenance('cve_found',
                                                        {'device_id': 'some-other-device'}))

    def test_group_window_matches_by_group(self):
        now = int(time.time())
        api_module.save(api_module.MAINT_FILE, {'windows': [{
            'id':    'wgr', 'reason': 'prod patching', 'scope': 'group',
            'target': 'prod',
            'start': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now - 60)),
            'end':   time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now + 60)),
        }]})
        # Should match the device in group 'prod'
        self.assertIsNotNone(api_module.in_maintenance('service_down',
                                                        {'device_id': 'dev-aaaaaaaaaaaaaa'}))

    def test_event_filter_respects_allowlist(self):
        now = int(time.time())
        api_module.save(api_module.MAINT_FILE, {'windows': [{
            'id':    'wf', 'reason': 'only patches', 'scope': 'global',
            'target': '',
            'start': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now - 60)),
            'end':   time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now + 60)),
            'events': ['patch_alert'],
        }]})
        # patch_alert is in the list — suppressed
        self.assertIsNotNone(api_module.in_maintenance('patch_alert',
                                                        {'device_id': 'dev-aaaaaaaaaaaaaa'}))
        # device_offline is NOT in the list — still fires
        self.assertIsNone(api_module.in_maintenance('device_offline',
                                                     {'device_id': 'dev-aaaaaaaaaaaaaa'}))

    def test_non_suppressible_event_ignored(self):
        # 'test' (webhook test) is not in SUPPRESSIBLE_EVENTS — should always pass through
        now = int(time.time())
        api_module.save(api_module.MAINT_FILE, {'windows': [{
            'id':    'wnx', 'reason': 'x', 'scope': 'global', 'target': '',
            'start': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now - 60)),
            'end':   time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now + 60)),
        }]})
        self.assertIsNone(api_module.in_maintenance('test',
                                                     {'device_id': 'dev-aaaaaaaaaaaaaa'}))


class TestParseIso(unittest.TestCase):

    def test_z_suffix(self):
        ts = api_module._parse_iso('2026-01-15T12:00:00Z')
        import datetime
        expected = datetime.datetime(2026, 1, 15, 12, 0, 0,
                                      tzinfo=datetime.timezone.utc).timestamp()
        self.assertEqual(ts, int(expected))

    def test_offset_suffix(self):
        ts = api_module._parse_iso('2026-01-15T12:00:00+00:00')
        import datetime
        expected = datetime.datetime(2026, 1, 15, 12, 0, 0,
                                      tzinfo=datetime.timezone.utc).timestamp()
        self.assertEqual(ts, int(expected))

    def test_invalid_raises(self):
        with self.assertRaises(ValueError):
            api_module._parse_iso('not-a-date')


class TestServiceProcessing(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._orig_files = {}
        for attr in ('SERVICES_FILE', 'SERVICE_HIST_FILE', 'DEVICES_FILE',
                     'CONFIG_FILE', 'WEBHOOK_LOG_FILE'):
            self._orig_files[attr] = getattr(api_module, attr)
            setattr(api_module, attr, self.tmp / f'{attr.lower()}.json')
        api_module.save(api_module.DEVICES_FILE, {
            'dev-aaaaaaaaaaaaaa': {'name': 'web-1', 'group': ''},
        })
        api_module.save(api_module.CONFIG_FILE, {'service_webhook_enabled': False})

    def tearDown(self):
        for attr, orig in self._orig_files.items():
            setattr(api_module, attr, orig)

    def test_sanitize_valid_unit(self):
        self.assertEqual(api_module._sanitize_unit_name('nginx.service'), 'nginx.service')
        self.assertEqual(api_module._sanitize_unit_name('getty@tty1.service'), 'getty@tty1.service')
        self.assertEqual(api_module._sanitize_unit_name('docker'), 'docker')

    def test_sanitize_rejects_bad_names(self):
        self.assertIsNone(api_module._sanitize_unit_name('nginx /etc/passwd'))
        self.assertIsNone(api_module._sanitize_unit_name(''))
        self.assertIsNone(api_module._sanitize_unit_name('../path/traversal'))
        self.assertIsNone(api_module._sanitize_unit_name('unit with space'))

    def test_process_stores_clean_services(self):
        api_module.process_service_report('dev-aaaaaaaaaaaaaa', [
            {'unit': 'nginx.service',  'active': 'active',   'sub': 'running', 'since': 1714000000},
            {'unit': 'redis.service',  'active': 'inactive', 'sub': 'dead',    'since': 0},
        ])
        store = api_module.load(api_module.SERVICES_FILE)
        self.assertIn('dev-aaaaaaaaaaaaaa', store)
        services = store['dev-aaaaaaaaaaaaaa']['services']
        self.assertEqual(len(services), 2)
        units = {s['unit'] for s in services}
        self.assertEqual(units, {'nginx.service', 'redis.service'})

    def test_transitions_recorded_across_polls(self):
        # First report — no history yet, just baseline
        api_module.process_service_report('dev-aaaaaaaaaaaaaa', [
            {'unit': 'nginx.service', 'active': 'active', 'sub': 'running'},
        ])
        # Second report — nginx now failed. This should record a transition.
        api_module.process_service_report('dev-aaaaaaaaaaaaaa', [
            {'unit': 'nginx.service', 'active': 'failed', 'sub': 'dead'},
        ])
        hist = api_module.load(api_module.SERVICE_HIST_FILE)
        key = 'dev-aaaaaaaaaaaaaa:nginx.service'
        self.assertIn(key, hist)
        self.assertEqual(len(hist[key]), 1)
        self.assertEqual(hist[key][0]['from'], 'active')
        self.assertEqual(hist[key][0]['to'], 'failed')

    def test_same_state_no_transition(self):
        api_module.process_service_report('dev-aaaaaaaaaaaaaa', [
            {'unit': 'nginx.service', 'active': 'active', 'sub': 'running'},
        ])
        api_module.process_service_report('dev-aaaaaaaaaaaaaa', [
            {'unit': 'nginx.service', 'active': 'active', 'sub': 'running'},
        ])
        hist = api_module.load(api_module.SERVICE_HIST_FILE)
        self.assertNotIn('dev-aaaaaaaaaaaaaa:nginx.service', hist)

    def test_cap_on_services_per_device(self):
        huge = [{'unit': f'svc-{i}.service', 'active': 'active'}
                for i in range(api_module.MAX_SERVICES_PER_DEVICE + 20)]
        api_module.process_service_report('dev-aaaaaaaaaaaaaa', huge)
        store = api_module.load(api_module.SERVICES_FILE)
        self.assertLessEqual(
            len(store['dev-aaaaaaaaaaaaaa']['services']),
            api_module.MAX_SERVICES_PER_DEVICE,
        )


class TestSuppressibleEvents(unittest.TestCase):

    def test_covers_all_known_alert_events(self):
        expected = {
            'device_offline', 'device_online',
            'monitor_down', 'monitor_up',
            'service_down', 'service_up',
            'patch_alert', 'cve_found',
            'log_alert',
        }
        self.assertEqual(set(api_module.SUPPRESSIBLE_EVENTS), expected)


if __name__ == '__main__':
    unittest.main()

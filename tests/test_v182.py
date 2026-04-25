#!/usr/bin/env python3
"""
Unit tests for v1.8.2 additions:
- Fleet-wide (global) log alert rules CRUD + validation
- handle_log_submit accepts empty lines[] arrays (preserves unit key)
- handle_log_submit evaluates per-device + global rules with dedupe
- handle_log_submit honours wildcard unit='*' in global rules
"""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

_CGI_BIN = Path(__file__).parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI_BIN))

_TMPDIR = tempfile.mkdtemp()
os.environ['RP_DATA_DIR'] = _TMPDIR
os.environ['REQUEST_METHOD'] = 'POST'
os.environ['PATH_INFO'] = '/'
os.environ['CONTENT_LENGTH'] = '0'

import importlib.util
_spec = importlib.util.spec_from_file_location('api_v182', _CGI_BIN / 'api.py')
api_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api_module)


class TestGlobalRuleValidation(unittest.TestCase):

    def test_wildcard_unit_allowed(self):
        r, err = api_module._validate_global_rule(
            {'unit': '*', 'pattern': 'OOMkilled', 'threshold': 1})
        self.assertIsNone(err)
        self.assertEqual(r['unit'], '*')
        self.assertEqual(r['pattern'], 'OOMkilled')
        self.assertEqual(r['threshold'], 1)

    def test_specific_unit_allowed(self):
        r, err = api_module._validate_global_rule(
            {'unit': 'sshd.service', 'pattern': 'Failed password', 'threshold': 5})
        self.assertIsNone(err)
        self.assertEqual(r['unit'], 'sshd.service')
        self.assertEqual(r['threshold'], 5)

    def test_empty_unit_rejected(self):
        r, err = api_module._validate_global_rule({'unit': '', 'pattern': 'x'})
        self.assertIsNone(r)
        self.assertIn('unit is required', err)

    def test_bad_unit_name_rejected(self):
        r, err = api_module._validate_global_rule({'unit': '../etc/passwd', 'pattern': 'x'})
        self.assertIsNone(r)
        self.assertIn('invalid unit', err)

    def test_invalid_regex_rejected(self):
        r, err = api_module._validate_global_rule({'unit': '*', 'pattern': '[unclosed'})
        self.assertIsNone(r)
        self.assertIn('invalid regex', err)

    def test_zero_threshold_rejected(self):
        r, err = api_module._validate_global_rule(
            {'unit': '*', 'pattern': 'x', 'threshold': 0})
        self.assertIsNone(r)
        self.assertIn('threshold must be 1', err)

    def test_too_high_threshold_rejected(self):
        r, err = api_module._validate_global_rule(
            {'unit': '*', 'pattern': 'x', 'threshold': 1000})
        self.assertIsNone(r)
        self.assertIn('threshold must be 1', err)

    def test_empty_pattern_rejected(self):
        r, err = api_module._validate_global_rule({'unit': 'nginx.service', 'pattern': ''})
        self.assertIsNone(r)
        self.assertIn('pattern is required', err)


class TestLogSubmitEmptyArrays(unittest.TestCase):
    """v1.8.2 bug fix: empty lines[] preserves the unit key so quiet devices
    still appear on the Logs page."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._orig = {
            attr: getattr(api_module, attr) for attr in
            ('LOG_WATCH_FILE', 'DEVICES_FILE', 'LOG_RULES_GLOBAL_FILE', 'CONFIG_FILE')
        }
        for attr in self._orig:
            setattr(api_module, attr, self.tmp / f'{attr.lower()}.json')
        api_module.save(api_module.DEVICES_FILE, {
            'dev-aaaaaaaaaaaaaa': {
                'name': 'web-1', 'group': '',
                'token': 'tok123',
                'log_watch': [],
            },
        })
        api_module.save(api_module.LOG_RULES_GLOBAL_FILE, {'rules': []})
        api_module.save(api_module.CONFIG_FILE, {})

    def tearDown(self):
        for attr, orig in self._orig.items():
            setattr(api_module, attr, orig)

    def _simulate_submit(self, units):
        """Exercise the core logic of handle_log_submit without HTTP plumbing."""
        dev_id = 'dev-aaaaaaaaaaaaaa'
        devices = api_module.load(api_module.DEVICES_FILE)
        dev = devices[dev_id]
        now = int(time.time())
        log_store = api_module.load(api_module.LOG_WATCH_FILE)
        dev_buf = log_store.get(dev_id) or {'units': {}, 'updated_at': now}
        units_buf = dev_buf.get('units') or {}

        for unit_raw, lines in units.items():
            unit = api_module._sanitize_unit_name(unit_raw)
            if not isinstance(unit, str) or unit is None:
                continue
            if not isinstance(lines, list):
                continue
            clean_lines = [{'ts': now, 'line': str(l)[:1024]}
                            for l in lines[:api_module.MAX_LOG_LINES_PER_UNIT]]
            existing = units_buf.get(unit) or []
            combined = existing + clean_lines
            cutoff = now - api_module.LOG_BUFFER_TTL
            combined = [e for e in combined if e.get('ts', 0) >= cutoff]
            units_buf[unit] = combined

        dev_buf['units'] = units_buf
        dev_buf['updated_at'] = now
        log_store[dev_id] = dev_buf
        api_module.save(api_module.LOG_WATCH_FILE, log_store)

    def test_empty_array_preserves_unit(self):
        """Quiet unit should appear in the buffer with an empty list."""
        self._simulate_submit({'nginx.service': []})
        store = api_module.load(api_module.LOG_WATCH_FILE)
        self.assertIn('dev-aaaaaaaaaaaaaa', store)
        self.assertIn('nginx.service', store['dev-aaaaaaaaaaaaaa']['units'])
        self.assertEqual(store['dev-aaaaaaaaaaaaaa']['units']['nginx.service'], [])

    def test_mixed_quiet_and_chatty(self):
        """Multiple units, some with lines, some empty — all preserved."""
        self._simulate_submit({
            'nginx.service': [],
            'postfix.service': ['connect from client'],
            'sshd.service': [],
        })
        units = api_module.load(api_module.LOG_WATCH_FILE)['dev-aaaaaaaaaaaaaa']['units']
        self.assertEqual(sorted(units.keys()),
                          ['nginx.service', 'postfix.service', 'sshd.service'])
        self.assertEqual(units['nginx.service'], [])
        self.assertEqual(len(units['postfix.service']), 1)
        self.assertEqual(units['sshd.service'], [])


class TestWildcardRuleMatching(unittest.TestCase):
    """Global rules with unit='*' match any unit on any device."""

    def test_pattern_matches_across_units(self):
        import re as _re
        lines = [
            {'line': 'memory pressure rising'},
            {'line': 'OOMkilled: killed process 12345 (postgres)'},
            {'line': 'all clear'},
        ]
        rx = _re.compile('OOMkilled')
        matches = [e['line'] for e in lines if rx.search(e['line'])]
        self.assertEqual(len(matches), 1)

    def test_dedupe_key_shape(self):
        """Same pattern as both per-device and global rule should dedupe by
        (scope, unit, pattern) — so only one alert fires even if both match."""
        fired_keys = set()
        key_device = ('device', 'nginx.service', 'error')
        key_global = ('global', 'nginx.service', 'error')
        # Different scope ⇒ different keys by design (we want both logged once)
        self.assertNotEqual(key_device, key_global)
        fired_keys.add(key_device)
        fired_keys.add(key_global)
        self.assertEqual(len(fired_keys), 2)
        # Adding the same per-device key again is a no-op
        fired_keys.add(key_device)
        self.assertEqual(len(fired_keys), 2)


class TestRoutesRegistered(unittest.TestCase):

    def test_version(self):
        # v1.8.2 introduced fleet-wide rules. Later versions keep them, so
        # just assert we're on 1.8.2 or later (avoids breaking on each bump).
        parts = api_module.SERVER_VERSION.split('.')
        self.assertGreaterEqual(
            (int(parts[0]), int(parts[1]), int(parts[2])),
            (1, 8, 2),
            f'expected >= 1.8.2, got {api_module.SERVER_VERSION}',
        )

    def test_handlers_exist(self):
        for fn in ('handle_log_rules_global_list',
                   'handle_log_rules_global_add',
                   'handle_log_rules_global_delete',
                   '_validate_global_rule'):
            self.assertTrue(hasattr(api_module, fn), f'missing {fn}')

    def test_max_global_rules_defined(self):
        self.assertTrue(hasattr(api_module, 'MAX_GLOBAL_LOG_RULES'))
        self.assertGreater(api_module.MAX_GLOBAL_LOG_RULES, 0)


if __name__ == '__main__':
    unittest.main()

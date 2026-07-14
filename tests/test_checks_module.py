#!/usr/bin/env python3
"""checks.py — the carved-out per-host Checks engine.

Pins the carve's contract: checks.py stays PURE (no storage / request /
network), api.py re-binds the names its handlers and the older tests
reference, and the engine still builds rows for the basic device shapes.
"""
import importlib.util
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

import checks  # noqa: E402

_spec = importlib.util.spec_from_file_location('api_checks', _CGI_BIN / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

CHECKS_SRC = (_CGI_BIN / 'checks.py').read_text()


class TestPurity(unittest.TestCase):
    def test_no_storage_or_request_coupling(self):
        for forbidden in ('import os', 'load(', 'save(', 'respond(',
                          'require_auth', 'urllib', 'import socket',
                          '_LockedUpdate', 'DATA_DIR', 'fire_webhook'):
            self.assertNotIn(forbidden, CHECKS_SRC,
                             f'checks.py must stay pure — found {forbidden!r}')

    def test_api_reexports(self):
        for name in ('SERVER_CHECK_TYPES', 'AGENT_CHECK_TYPES', '_host_checks',
                     '_custom_checks_for', '_eval_custom_check',
                     '_custom_check_applies', '_exposure_muted'):
            self.assertIs(getattr(api, name), getattr(checks, name),
                          f'api.{name} must be the checks.py implementation')

    def test_custom_check_types_split(self):
        # server evaluates process/port; agent evaluates file/job/log/unit
        self.assertEqual(checks.SERVER_CHECK_TYPES,
                         ('process', 'port_open', 'port_closed'))
        self.assertEqual(checks.AGENT_CHECK_TYPES,
                         ('file_present', 'file_absent', 'log_errors',
                          'job_fresh', 'systemd_unit',
                          'windows_service'))   # v6.2.0: Windows parity


class TestEngine(unittest.TestCase):
    def test_agentless_reachability_row(self):
        rows = checks._host_checks(
            'd1', {'name': 'sw1', 'agentless': True, 'reachable': True},
            now=1000, ttl=180)
        self.assertTrue(rows)
        self.assertTrue(any(r.get('status') == 'ok' for r in rows))

    def test_offline_agent_row_is_critical(self):
        # last_seen far beyond the TTL → the reachability row goes critical.
        rows = checks._host_checks(
            'd2', {'name': 'host2', 'last_seen': 1}, now=10_000, ttl=180)
        reach = next(r for r in rows if r['key'] == 'reachability')
        self.assertEqual(reach['status'], 'critical')

    def test_eval_custom_check_process(self):
        cdef = {'type': 'process', 'param': 'nginx'}
        ok, _out = checks._eval_custom_check(
            cdef, {'sysinfo': {'proc_names': ['nginx', 'sshd']}})
        bad, _out = checks._eval_custom_check(
            cdef, {'sysinfo': {'proc_names': ['sshd']}})
        self.assertEqual((ok, bad), ('ok', 'critical'))


if __name__ == '__main__':
    unittest.main()

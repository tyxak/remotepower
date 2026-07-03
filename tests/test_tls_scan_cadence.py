"""TLS watchlist scheduled scanning — run_tls_scan_if_due().

Historically the TLS expiry cadence lived ONLY in the optional
``remotepower-tls-check`` cron (which the installer merely suggests, and which
read the watchlist as a raw file — invisible under the SQLite/Postgres
backends), so scheduled scans silently never ran on most installs. These tests
pin the in-server sweep: per-target 6h cadence, bounded per run, edge-triggered
``tls_expiry`` webhooks honouring per-target warn/crit days, and the sweep's
registration in main()'s _safe list (scheduler parity is covered by
test_v600_scheduler).
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
_CGI = Path(__file__).parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location('api_tls_cadence', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

DAY = 86400


def _result(days_left, dane_status='not_checked', checked_at=None):
    """A minimal probe result the sweep/crossing logic consumes."""
    return {
        'expires_at': int(time.time()) + days_left * DAY,
        'checked_at': int(time.time()) if checked_at is None else checked_at,
        'dns_error': '', 'tls_error': '',
        'dane_status': dane_status,
    }


class _Env(unittest.TestCase):
    """Fresh stores + captured webhooks + fake prober per test."""

    def setUp(self):
        api.save(api.TLS_TARGETS_FILE, {})
        api.save(api.TLS_RESULTS_FILE, {})
        self.fired = []
        self.probed = []
        self._orig_fire = api.fire_webhook
        self._orig_probe = api.tls_monitor.probe_all
        api.fire_webhook = lambda ev, payload: self.fired.append((ev, payload))
        self.canned = {}

        def _fake_probe_all(targets):
            self.probed.extend(targets.keys())
            return {tid: dict(self.canned.get(tid) or _result(90))
                    for tid in targets}
        api.tls_monitor.probe_all = _fake_probe_all

    def tearDown(self):
        api.fire_webhook = self._orig_fire
        api.tls_monitor.probe_all = self._orig_probe


class TestSweep(_Env):
    def test_probes_and_persists_when_due(self):
        api.save(api.TLS_TARGETS_FILE, {'tls_a': {'host': 'a.example', 'port': 443}})
        self.canned['tls_a'] = _result(90)
        api.run_tls_scan_if_due()
        self.assertEqual(self.probed, ['tls_a'])
        results = api.load(api.TLS_RESULTS_FILE)
        self.assertIn('tls_a', results)
        self.assertGreater(results['tls_a']['checked_at'], 0)
        self.assertEqual(self.fired, [])   # 90d out: no threshold crossed

    def test_not_due_again_within_interval(self):
        api.save(api.TLS_TARGETS_FILE, {'tls_a': {'host': 'a.example'}})
        api.run_tls_scan_if_due()
        self.probed.clear()
        api._invalidate_load_cache(api.TLS_RESULTS_FILE)
        api.run_tls_scan_if_due()
        self.assertEqual(self.probed, [], 'fresh result must not re-probe')

    def test_stale_result_is_due(self):
        api.save(api.TLS_TARGETS_FILE, {'tls_a': {'host': 'a.example'}})
        stale = _result(90, checked_at=int(time.time()) - api.TLS_SCAN_INTERVAL - 60)
        api.save(api.TLS_RESULTS_FILE, {'tls_a': stale})
        api.run_tls_scan_if_due()
        self.assertEqual(self.probed, ['tls_a'])

    def test_bounded_per_run(self):
        targets = {f'tls_{i}': {'host': f'h{i}.example'}
                   for i in range(api.TLS_MAX_PER_RUN + 5)}
        api.save(api.TLS_TARGETS_FILE, targets)
        api.run_tls_scan_if_due()
        self.assertEqual(len(self.probed), api.TLS_MAX_PER_RUN)

    def test_no_targets_is_cheap_noop(self):
        api.run_tls_scan_if_due()
        self.assertEqual(self.probed, [])
        self.assertEqual(self.fired, [])

    def test_deleted_target_result_pruned(self):
        api.save(api.TLS_TARGETS_FILE, {'tls_a': {'host': 'a.example'}})
        api.save(api.TLS_RESULTS_FILE, {'tls_gone': _result(90, checked_at=1)})
        api.run_tls_scan_if_due()
        results = api.load(api.TLS_RESULTS_FILE)
        self.assertNotIn('tls_gone', results)
        self.assertIn('tls_a', results)

    def test_crossing_warn_fires_once(self):
        api.save(api.TLS_TARGETS_FILE, {'tls_a': {'host': 'a.example', 'port': 8443}})
        # First probe: 10 days left (default warn 14) with NO previous result →
        # treated as a crossing (prev_days=9999).
        self.canned['tls_a'] = _result(10)
        api.run_tls_scan_if_due()
        self.assertEqual(len(self.fired), 1)
        ev, payload = self.fired[0]
        self.assertEqual(ev, 'tls_expiry')
        self.assertEqual(payload['severity'], 'warning')
        self.assertEqual(payload['host'], 'a.example')
        self.assertEqual(payload['port'], 8443)
        # Next due probe still inside the warn band → no re-fire.
        self.fired.clear()
        api._invalidate_load_cache(api.TLS_RESULTS_FILE)
        results = api.load(api.TLS_RESULTS_FILE)
        results['tls_a']['checked_at'] -= api.TLS_SCAN_INTERVAL + 60
        api.save(api.TLS_RESULTS_FILE, results)
        self.canned['tls_a'] = _result(9)
        api.run_tls_scan_if_due()
        self.assertEqual(self.fired, [])

    def test_crossing_crit_honours_per_target_days(self):
        api.save(api.TLS_TARGETS_FILE,
                 {'tls_a': {'host': 'a.example', 'warn_days': 30, 'crit_days': 20}})
        api.save(api.TLS_RESULTS_FILE,
                 {'tls_a': _result(25, checked_at=1)})   # stale → due; inside warn
        self.canned['tls_a'] = _result(15)               # crosses the 20d crit line
        api.run_tls_scan_if_due()
        self.assertEqual([p['severity'] for _, p in self.fired], ['critical'])

    def test_dane_flip_fires_warning(self):
        api.save(api.TLS_TARGETS_FILE, {'tls_a': {'host': 'a.example'}})
        api.save(api.TLS_RESULTS_FILE,
                 {'tls_a': _result(90, dane_status='ok', checked_at=1)})
        self.canned['tls_a'] = _result(90, dane_status='mismatch')
        api.run_tls_scan_if_due()
        self.assertEqual([p['severity'] for _, p in self.fired], ['warning'])


class TestWiring(unittest.TestCase):
    def test_sweep_registered_in_main_safe_list(self):
        src = (_CGI / 'api.py').read_text()
        self.assertIn("_safe(run_tls_scan_if_due, 'run_tls_scan_if_due')", src)

    def test_scheduler_cadence_includes_tls(self):
        src = (_CGI / 'scheduler.py').read_text()
        self.assertIn("'run_tls_scan_if_due',", src)

    def test_cron_runner_is_backend_aware(self):
        # The standalone runner must go through api.load/save (the watchlist is
        # a DB row under SQLite/Postgres — a raw file read sees nothing there).
        src = (_CGI / 'remotepower-tls-check').read_text()
        self.assertIn('import api as _api', src)
        self.assertIn('_api.load(', src)
        self.assertIn('_api.save(', src)


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
"""v4.3.0 "ImprovementMatters" — feature wiring tests (posture links, audit
archive download, cadence-job staleness)."""
import gzip
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
import sys
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v430f", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_APP_JS = (_ROOT / 'server/html/static/js/app.js').read_text()
_HTML = (_ROOT / 'server/html/index.html').read_text()


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for a in ('CONFIG_FILE', 'USERS_FILE', 'AUDIT_LOG_FILE',
                  'SCAN_SCHEDULES_FILE', 'DATA_DIR'):
            self._files[a] = getattr(api, a)
        for a in ('CONFIG_FILE', 'USERS_FILE', 'AUDIT_LOG_FILE',
                  'SCAN_SCHEDULES_FILE'):
            setattr(api, a, self.d / Path(getattr(api, a)).name)
        api.DATA_DIR = self.d
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ('respond', 'method', 'require_admin_auth', 'require_auth',
                       'audit_log')}

        def _resp(s, b=None):
            self.cap['s'] = s; self.cap['b'] = b
            raise api.HTTPError(s, b)
        api.respond = _resp
        api.require_admin_auth = lambda: 'alice'
        api.require_auth = lambda require_admin=False: 'alice'
        api.audit_log = lambda *a, **k: None
        api.method = lambda: 'GET'

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for a, v in self._files.items():
            setattr(api, a, v)

    def call(self, fn, *a):
        self.cap.clear()
        try:
            fn(*a)
        except api.HTTPError:
            pass
        return self.cap.get('b')


class TestPostureFixLinks(_Base):
    def test_rows_carry_fix_tab(self):
        api.save(api.CONFIG_FILE, {})
        api.save(api.USERS_FILE, {})
        api.save(api.AUDIT_LOG_FILE, {'entries': []})
        r = self.call(api.handle_security_posture)
        by = {c['key']: c for c in r['checks']}
        # The guardrail rows fixed in Settings → Security must name the tab.
        for key in ('mfa_enforced', 'apikey_expiry', 'session_cap',
                    'webhook_block_local', 'audit_forward', 'secrets_scan'):
            self.assertEqual(by[key]['fix_tab'], 'security', key)
        # admin_mfa is fixed in My Account, not a settings tab → no fix_tab.
        self.assertIsNone(by['admin_mfa']['fix_tab'])

    def test_frontend_renders_fix_link(self):
        self.assertIn('gotoSettingsTab', _APP_JS)
        self.assertIn('c.fix_tab', _APP_JS)


class TestAuditArchiveDownload(_Base):
    def test_404_when_no_archive(self):
        self.call(api.handle_audit_log_archive)
        self.assertEqual(self.cap['s'], 404)

    def test_route_registered(self):
        self.assertIn(('GET', '/api/audit-log/archive'), api._build_exact_routes())

    def test_streams_when_archive_exists(self):
        # Write a real gzip archive and capture the streamed bytes.
        arch = self.d / 'audit_log_archive.jsonl.gz'
        with gzip.open(str(arch), 'wt') as f:
            f.write('{"ts": 1, "action": "old"}\n')
        import io
        buf = io.BytesIO()

        class _Stdout:
            def __init__(self, b): self.buffer = b
            def write(self, *_a): pass
            def flush(self): pass
        orig = api.sys.stdout
        api.sys.stdout = _Stdout(buf)
        try:
            try:
                api.handle_audit_log_archive()
            except api.HTTPError:
                pass
        finally:
            api.sys.stdout = orig
        self.assertTrue(buf.getvalue())          # streamed something
        self.assertEqual(gzip.decompress(buf.getvalue()).decode(),
                         '{"ts": 1, "action": "old"}\n')

    def test_frontend_button_and_fn(self):
        self.assertIn('downloadAuditArchive', _APP_JS)
        self.assertIn('data-action="downloadAuditArchive"', _HTML)


class TestCadenceJobStaleness(_Base):
    def test_fresh_job_not_stale(self):
        now = int(api.time.time())
        api.save(api.CONFIG_FILE, {'last_kev_epss_refresh': now - 100,
                                   'monitors': [{'type': 'ping'}],
                                   'last_monitor_run': now - 30})
        jobs = api._cadence_job_status(now)
        self.assertFalse(jobs['kev_epss_refresh']['stale'])
        self.assertFalse(jobs['monitors']['stale'])

    def test_wedged_job_flagged_stale(self):
        now = int(api.time.time())
        api.save(api.CONFIG_FILE, {'last_kev_epss_refresh': now - 5 * 86400})
        jobs = api._cadence_job_status(now)
        self.assertTrue(jobs['kev_epss_refresh']['stale'])   # >3× daily interval

    def test_never_run_not_stale(self):
        now = int(api.time.time())
        api.save(api.CONFIG_FILE, {})
        jobs = api._cadence_job_status(now)
        self.assertTrue(jobs['kev_epss_refresh']['never_ran'])
        self.assertFalse(jobs['kev_epss_refresh']['stale'])

    def test_scheduled_scans_reports_worst(self):
        now = int(api.time.time())
        api.save(api.CONFIG_FILE, {})
        api.save(api.SCAN_SCHEDULES_FILE, {
            's1': {'enabled': True, 'last_run': now - 9 * 86400},
            's2': {'enabled': True, 'last_run': now - 100},
        })
        jobs = api._cadence_job_status(now)
        self.assertIn('scheduled_scans', jobs)
        self.assertTrue(jobs['scheduled_scans']['stale'])    # worst is 9d old
        self.assertEqual(jobs['scheduled_scans']['count'], 2)

    def test_frontend_renders_card(self):
        self.assertIn('_cadenceJobsCard', _APP_JS)


if __name__ == '__main__':
    unittest.main()

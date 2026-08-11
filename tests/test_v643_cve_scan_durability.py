#!/usr/bin/env python3
"""A killed CVE scan must not discard everything it had already found.

`_cve_scan_worker` checkpointed PROGRESS every 3 devices and persisted FINDINGS
exactly once, after the loop. So a worker killed at device 16 of 40 left
cve_findings.json holding NOTHING — 100 % of completed work discarded, however
far it got, while the progress bar had been faithfully reporting how much was
about to be thrown away.

A fleet CVE scan is minutes of network I/O against the OSV API. Losing all of
it to a deploy, an OOM or a restart is the expensive kind of crash, and the
cheap fix is to checkpoint findings on the same cadence as the bar.

SECOND DEFECT, same worker: the status marker was left `running: True` and
nothing ever cleared it — no reaper, and the only routes are POST /api/cve/scan
and GET /api/cve/scan-status, so there was no cancel. The staleness window was
1800 s inline, which locked the operator out of retrying for HALF AN HOUR after
a crash. It is 300 s now (a live worker checkpoints every 3 devices, so five
minutes of silence means it is gone) and the 409 says when it will clear.

The backlog item that led here claimed there is "no durable job queue with
retry/backoff/DLQ". That is REFUTED — one shipped in v6.1.1 with lease reclaim
and dead-lettering, tested in test_v3140. What was true is the half nobody
wrote down: the heavy scans are not ON it, and each has its own durability
defect. This fixes the worst one where it is, rather than migrating it.
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v643cve-'))

_spec = importlib.util.spec_from_file_location('api_v643_cve', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('api', api)
_spec.loader.exec_module(api)


class TestFindingsAreCheckpointed(unittest.TestCase):
    def test_the_worker_saves_findings_inside_the_loop(self):
        """Source-level, and narrow on purpose: the defect is WHERE the save
        sits, which no black-box assertion can see without actually killing a
        worker mid-scan."""
        import ast
        import inspect
        node = ast.parse(inspect.getsource(api._cve_scan_worker)).body[0]
        loop = next((n for n in ast.walk(node) if isinstance(n, ast.For)), None)
        self.assertIsNotNone(loop, 'the per-device loop is gone')
        saves = [n for n in ast.walk(loop)
                 if isinstance(n, ast.Call)
                 and getattr(n.func, 'id', '') == 'save'
                 and any(getattr(a, 'id', '') == 'CVE_FINDINGS_FILE' for a in n.args)]
        self.assertTrue(saves,
                        'findings are only persisted AFTER the loop, so a '
                        'worker killed part-way through discards everything it '
                        'has found')

    def test_the_progress_checkpoint_is_still_there(self):
        """Positive control — a change that removed both saves would satisfy
        nothing useful."""
        import inspect
        src = inspect.getsource(api._cve_scan_worker)
        self.assertIn('CVE_SCAN_STATUS_FILE', src)

    def test_a_contended_checkpoint_does_not_kill_the_scan(self):
        """The checkpoint is best-effort: the scan runner writes the status
        file continuously, and a LockBusy on a hot key must not abort minutes
        of network work. CLAUDE.md documents this exact class."""
        import inspect
        src = inspect.getsource(api._cve_scan_worker)
        self.assertIn('except LockBusy', src)


class TestAStuckScanClearsItself(unittest.TestCase):
    def setUp(self):
        self.cap = {}
        self._orig = {k: getattr(api, k) for k in
                      ('require_admin_auth', 'method', 'get_json_obj', 'respond',
                       'audit_log', '_run_detached')}
        api.require_admin_auth = lambda *a, **k: 'admin'
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {}
        api.audit_log = lambda *a, **k: None
        api._run_detached = lambda *a, **k: None

        def _r(status, data=None, *a, **k):
            self.cap['s'], self.cap['d'] = status, data
            raise api.HTTPError(status, data)
        api.respond = _r

    def tearDown(self):
        for k, v in self._orig.items():
            setattr(api, k, v)

    def _scan(self, updated_ago):
        api.save(api.CVE_SCAN_STATUS_FILE,
                 {'running': True, 'updated': int(time.time()) - updated_ago})
        api._invalidate_load_cache(api.CVE_SCAN_STATUS_FILE)
        try:
            api.handle_cve_scan()
        except (SystemExit, api.HTTPError):
            pass
        return self.cap

    def test_a_live_scan_is_still_refused(self):
        """Positive control: a scan that checkpointed seconds ago is genuinely
        running and a second one must not start."""
        self.assertEqual(self._scan(10).get('s'), 409)

    def test_a_crashed_scan_no_longer_blocks_for_half_an_hour(self):
        """The worker checkpoints every 3 devices; silence for 5 minutes means
        it is gone. It used to be believed for 1800 s with no way to clear it."""
        r = self._scan(400)
        self.assertNotEqual(r.get('s'), 409,
                            'a dead scan still blocks the retry')

    def test_the_refusal_says_when_it_clears(self):
        """"A scan is already running" with no way to cancel and no expiry is
        a dead end for the operator."""
        r = self._scan(10)
        self.assertIn('retry_after_seconds', r.get('d') or {})
        self.assertGreater((r['d'] or {}).get('retry_after_seconds', 0), 0)

    def test_the_window_is_a_named_constant(self):
        """It was 1800 inline. A number that decides how long a person is
        locked out should be findable."""
        self.assertTrue(hasattr(api, '_CVE_SCAN_STALE_S'))
        self.assertLessEqual(api._CVE_SCAN_STALE_S, 600)


if __name__ == '__main__':
    unittest.main()

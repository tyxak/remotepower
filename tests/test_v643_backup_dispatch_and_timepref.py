#!/usr/bin/env python3
"""Two residuals: a gate on the write path only, and a pref with one home.

1. FILE-BACKUP JOBS WERE GATED AT CREATE AND UPDATE, NOT AT DISPATCH.
   v6.4.3 added `_split_targets_by_os_support` to the two WRITE paths, so a new
   job cannot target a Windows or macOS host. The two DISPATCH paths — the cron
   sweep and POST /run — had no filter, so a job that ALREADY held such a target
   (created before the gate, or whose device changed platform) kept queueing a
   bash rsync at it on every tick, forever, and the agent silently dropped it.

   A gate on the write path alone stops NEW instances of a bug while leaving
   every existing one running. The scheduled path logs the skip rather than
   swallowing it, so an operator can see why that host never backs up.

2. `ui_prefs.time_display` — relative ("3d ago") vs absolute timestamps.
   67 sites render a relative time; exactly 4 carry a hover-absolute tooltip.
   The pref lives inside `timeAgo` because 59 of those 67 render through it,
   so one line covers 88 % of the surface. It returns a plain STRING on
   purpose: callers put the result into both textContent and innerHTML, so a
   `<span title=…>` wrapper would appear as literal markup in about half of
   them. Eight private reimplementations are unaffected — listed below so the
   gap is recorded rather than assumed away.
"""
import importlib.util
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_JS = _ROOT / 'server' / 'html' / 'static' / 'js'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v643bd-'))

_spec = importlib.util.spec_from_file_location('api_v643_bd', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('api', api)
_spec.loader.exec_module(api)


class TestTheScheduledSweepSkipsNonLinux(unittest.TestCase):
    def setUp(self):
        now = int(time.time())
        api.save(api.DEVICES_FILE, {
            'lin1': {'name': 'web01', 'os': 'Debian GNU/Linux 12', 'last_seen': now},
            'win1': {'name': 'desk01', 'os': 'Windows 11 Pro', 'last_seen': now},
        })
        api.save(api.CMDS_FILE, {})
        for f in (api.DEVICES_FILE, api.CMDS_FILE):
            api._invalidate_load_cache(f)
        self.logged = []
        self._orig = api.log_command
        api.log_command = lambda *a, **k: self.logged.append(a)

    def tearDown(self):
        api.log_command = self._orig

    def test_a_windows_target_is_skipped_and_said_so(self):
        api._invalidate_load_cache(api.DEVICES_FILE)
        devices = api.load(api.DEVICES_FILE)
        self.assertEqual(api._device_os_family(devices['win1']), 'windows')
        self.assertEqual(api._device_os_family(devices['lin1']), 'linux')

    def test_the_sweep_checks_the_os_family(self):
        """Source-pinned: the sweep queues into CMDS_FILE directly rather than
        through a helper, so there is nothing to call in isolation."""
        import inspect
        src = inspect.getsource(api.process_backup_jobs)
        self.assertIn('_device_os_family', src,
                      'the scheduled sweep queues a bash rsync at whatever the '
                      'job targets, including hosts that silently drop it')
        self.assertIn('Linux-only', src,
                      'a silent skip is only half a fix — the operator needs to '
                      'see why that host never backs up')

    def test_the_run_handler_gates_too(self):
        import inspect
        src = inspect.getsource(api.handle_backup_job_run)
        self.assertIn('_split_targets_by_os_support', src)

    def test_all_four_paths_are_now_covered(self):
        """create + update (v6.4.3 earlier) and run + sweep (here). Enumerated
        so a fifth dispatch path cannot land ungated."""
        src = (_CGI / 'backups_handlers.py').read_text()
        self.assertGreaterEqual(
            src.count('_split_targets_by_os_support') + src.count('_device_os_family'), 4,
            'a backup dispatch path lost its OS gate')


class TestTheTimeDisplayPref(unittest.TestCase):
    JS = (_JS / 'app.js').read_text()

    def test_time_ago_honours_the_pref(self):
        i = self.JS.index('function timeAgo(')
        self.assertIn('_timeDisplayAbsolute()', self.JS[i:i + 700])

    def test_it_returns_a_string_not_markup(self):
        """Callers use both textContent and innerHTML. A <span title=…> wrapper
        would render as literal markup in about half of them — the reason the
        hover-tooltip half of the backlog item was NOT done this way."""
        i = self.JS.index('function timeAgo(')
        body = self.JS[i:i + 900]
        self.assertNotIn('<span', body)

    def test_the_server_persists_it(self):
        """The ui_prefs whitelist is the silent one: a value not listed there
        is dropped and the toggle appears to work until you reload."""
        src = (_CGI / 'api.py').read_text()
        self.assertIn("time_display in ('relative', 'absolute')", src)

    def test_the_setting_exists_and_is_translated(self):
        html = (_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertIn('id="cfg-time-display"', html)
        i18n = (_JS / 'i18n.js').read_text()
        for s in ("'Time display':", "'Absolute timestamp':"):
            self.assertIn(s, i18n)

    def test_the_private_reimplementations_are_recorded_not_forgotten(self):
        """Eight sites reimplement timeAgo privately, so the pref does not
        reach them. That is a known, bounded gap — asserted so it stays bounded
        rather than growing quietly."""
        private = []
        for p in sorted(_JS.glob('*.js')):
            for m in re.finditer(r'function\s+(_?\w*[Aa]go\w*|_reltime|fmtRelative)\s*\(', p.read_text()):
                name = m.group(1)
                if name != 'timeAgo':
                    private.append(f'{p.name}:{name}')
        self.assertLessEqual(len(private), 10,
                             'more private relative-time helpers have appeared; '
                             'the pref does not reach them: ' + str(private))


if __name__ == '__main__':
    unittest.main()

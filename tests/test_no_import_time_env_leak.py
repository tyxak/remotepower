#!/usr/bin/env python3
"""No test module may change the process environment at IMPORT time.

`unittest discover` — what `make test` and `make test-sqlite` actually run —
imports EVERY test module before executing a single test. So a module that
mutates `os.environ` at import time has already broken every other module's
`setUpClass` before any of them get to look, and a `tearDownModule` restore
(however correct) fires far too late to help.

This is not hypothetical and it was not cheap. `test_hypothesis_props.py` had a
module-level `_API = _fresh_api()`, and `_fresh_api()` POPS
`RP_STORAGE_BACKEND`. The file carried a careful `tearDownModule` restore and a
comment warning about exactly this leak class — and leaked at import anyway,
where the restore could not reach.

What it cost, all of it invisible:

  * `make test-sqlite` re-ran the ENTIRE a11y browser walk. That suite skips
    itself under RP_STORAGE_BACKEND=sqlite because it audits the rendered
    frontend, which no storage backend can change — but the guard read None.
  * `test_v430_e2e` re-ran for the same reason.
  * ~7 minutes added to every gate run, spent proving something already proven.
  * A 90-second Playwright selector timeout under the contention that created,
    reported as a gate FAILURE twice and written off as environmental twice,
    because the documented advice for that symptom is "e2e flake under load".

The last point is the reason this test exists rather than a comment: the leak
manufactured evidence for its own dismissal.

pytest is NOT affected the same way (it imports lazily per module), which is
why this only ever showed up in the real gate and never while iterating.
"""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent
# Environment keys that steer behaviour across module boundaries. A leak in any
# of these silently reconfigures every module imported after it.
_WATCHED = ('RP_STORAGE_BACKEND', 'RP_DATA_DIR', 'RP_PG_DSN', 'RP_PG_TEST_DSN',
            'RP_EXTERNAL_SCHEDULER', 'RP_CGI_BIN', 'RP_READ_ONLY')


# The measurement runs in a FRESH interpreter, for two reasons found on 2026-11-08.
#
#   * Under `unittest discover` every test module is imported before the first test runs, so an in-process
#     `import_module` here returns the cached module and executes nothing: the first version of this test measured
#     NOTHING in the gate (only a targeted run, where the modules are not imported yet, measured anything).
#   * That targeted run imported every module for the first time in the middle of the process. Modules that exec
#     api.py at import created further `api` instances and the handler modules were rebound to the newest one, so
#     the next test module (test_v702_autonomy) failed for no reason of its own.
#
# A child process sees the import exactly as discover does, and leaves this one alone. Its temp files go to a
# directory of its own, removed afterwards: a thousand modules each make a scratch directory at import.
_SCRIPT = r'''
import importlib, json, os, pathlib, sys
directory, skip, watched = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
sys.path.insert(0, directory)
for k in watched:
    os.environ[k] = "__sentinel_%s__" % k
offenders, imported, failed = [], 0, []
for path in sorted(pathlib.Path(directory).glob("test_*.py")):
    if path.name == skip:
        continue
    pre = {k: os.environ.get(k) for k in watched}
    try:
        importlib.import_module(path.stem)
    except BaseException:
        failed.append(path.name)      # an import that fails is another test's problem
        continue
    imported += 1
    for k in watched:
        if os.environ.get(k) != pre[k]:
            offenders.append("%s: %s %r -> %r" % (path.name, k, pre[k], os.environ.get(k)))
            if pre[k] is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = pre[k]
print(json.dumps({"imported": imported, "failed": failed, "offenders": offenders}))
'''


def _measure(directory, skip='', timeout=900):
    """Import every test_*.py of `directory` in a child interpreter, in discover's order, with a sentinel planted for each watched key.
    Returns {"imported": n, "failed": [names], "offenders": [lines]}."""
    # RP_DATA_DIR is exempt from the VALUE check: several modules set it at import time on purpose, which CLAUDE.md requires so a stray
    # import never writes into a live /var/lib/remotepower. What must not change is the rest.
    watched = [k for k in _WATCHED if k != 'RP_DATA_DIR']
    with tempfile.TemporaryDirectory(prefix='rp-envleak-') as scratch:
        env = {k: v for k, v in os.environ.items() if k not in watched}
        env['TMPDIR'] = scratch
        done = subprocess.run([sys.executable, '-c', _SCRIPT, str(directory), skip, json.dumps(watched)],
                              capture_output=True, text=True, timeout=timeout, env=env, cwd=str(directory))
    lines = [ln for ln in done.stdout.splitlines() if ln.startswith('{')]
    assert lines, f'the measuring child printed no result (exit {done.returncode}):\n{done.stderr[-2000:]}'
    return json.loads(lines[-1])


class TestNoImportTimeEnvLeak(unittest.TestCase):
    """Imports every test module in a child interpreter, in discover's order, and reports any that change a watched key. Behavioural:
    a static scan cannot see a module-level call to a helper that mutates the environment three frames down, which is precisely how
    the real one hid."""

    def test_importing_every_test_module_leaves_the_env_alone(self):
        if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
            raise unittest.SkipTest('what a module does to the environment at import does not depend on the storage backend: measured once, in the JSON gate')
        result = _measure(_ROOT, skip=pathlib.Path(__file__).name)
        total = len(list(_ROOT.glob('test_*.py'))) - 1
        # A control that fails when this measures nothing: the child must have imported nearly all of them.
        self.assertGreater(result['imported'], 500, f"the child imported {result['imported']} of {total} modules: this measured too little to mean anything")
        self.assertLessEqual(len(result['failed']), max(5, total // 20), f"{len(result['failed'])} of {total} modules did not import in the child: {result['failed'][:8]}")
        self.assertEqual(result['offenders'], [], '\n'.join([
            'these modules change the environment at IMPORT time:', *result['offenders'],
            '',
            'unittest discover imports every module before running anything, so '
            'this has already reconfigured every other module by the time their '
            'setUpClass runs — and tearDownModule cannot help, because it fires '
            'after the damage. Move the mutation into setUp/setUpClass, or '
            'restore it immediately after the import-time call.']))

    def test_the_measurement_finds_a_module_that_leaks(self):
        """Guard the guard: a directory of three small modules, two of which change the environment at import. The child must name exactly those two,
        or a green result above would mean "nothing leaked" when it can mean "nothing was measured"."""
        with tempfile.TemporaryDirectory(prefix='rp-envleak-demo-') as d:
            d = pathlib.Path(d)
            (d / 'test_a_clean.py').write_text('import os\nX = os.environ.get("HOME")\n')
            (d / 'test_b_pops.py').write_text('import os\nos.environ.pop("RP_STORAGE_BACKEND", None)\n')
            (d / 'test_c_overwrites.py').write_text('import os\nos.environ["RP_CGI_BIN"] = "/elsewhere"\n')
            (d / 'test_d_raises.py').write_text('raise RuntimeError("a module that cannot import")\n')
            result = _measure(d)
        self.assertEqual(result['imported'], 3)
        self.assertEqual(result['failed'], ['test_d_raises.py'])
        self.assertEqual(sorted(o.split(':')[0] for o in result['offenders']), ['test_b_pops.py', 'test_c_overwrites.py'], result['offenders'])


if __name__ == '__main__':
    unittest.main()

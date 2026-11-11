#!/usr/bin/env python3
"""8.0.0: CI runs the suite as six processes, and no test module can fall out of them.

The 8.0.0 push to production was not red because a test failed. One `unittest discover` process imports every test module and keeps them: it held 12.3 GB at 7.5.0 and 14.9 GB at
8.0.0 (558 modules each load their own copy of api.py, about 10 MB apiece), and a hosted runner for a public repository has 16 GB. Three of the four jobs of the push ran past their
60 minutes, and in the fourth the test step was ended with exit code 143 after 42 minutes. The same suite takes 33 minutes on a machine with 64 GB, which is why every local gate
was green. `tools/unittest-chunks.sh` runs it as six `unittest discover` processes, one after the other, each over a contiguous part of the alphabetical order.

What has to hold, and the way each part is measured:
  * every `tests/test*.py` is matched by exactly one pattern of the script, and every slice matches files, or a module could stop running in CI with nothing failing;
  * the slices are contiguous parts of the sorted order, so inside a slice a module runs after the same modules as before, and none is a large share of the whole;
  * the script itself, run on a small tree: a slice that fails fails the run and the slices after it still run; a slice that matches nothing fails instead of passing;
  * ci.yml (both jobs) and the Makefile (ci-parity and the staged-tree suite) call the script, and both jobs keep a longer limit and a step that prints the end of the log after a cancel.
"""
import fnmatch
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / 'tools' / 'unittest-chunks.sh'
CI_YML = ROOT / '.github' / 'workflows' / 'ci.yml'
MAKEFILE = ROOT / 'Makefile'
TESTS = ROOT / 'tests'

LARGEST_SHARE = 0.35        # of all test modules; the biggest slice is about 26% today


def _require_sources(test):
    """ci.yml and the Makefile are not in the release tarball, so the staged-tree suite has nothing to read here."""
    if not (SCRIPT.exists() and CI_YML.exists() and MAKEFILE.exists()):
        test.skipTest('the script, ci.yml or the Makefile is not in this tree (the dist tree leaves them out)')


def slices_of(script_text):
    """The SLICES array of the script, as a list of slices, each a list of patterns."""
    m = re.search(r'^SLICES=\(\n(.*?)^\)', script_text, re.M | re.S)
    if m is None:
        raise AssertionError('no SLICES=( ... ) array in the script')
    out = []
    for line in m.group(1).splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        q = re.fullmatch(r"'([^']+)'", line)
        if q is None:
            raise AssertionError('a SLICES entry that is not one quoted string: %r' % line)
        out.append(q.group(1).split('|'))
    return out


def problems(names, slices):
    """What is wrong with `slices` for the sorted file names `names`: files no pattern names, files named twice, a slice that matches no file, and an order that is not the sorted one."""
    found = []
    where = {}
    order = []
    for i, patterns in enumerate(slices, 1):
        in_slice = [n for n in names if any(fnmatch.fnmatchcase(n, p) for p in patterns)]
        if not in_slice:
            found.append('slice %d (%s) matches no file' % (i, '|'.join(patterns)))
        for n in in_slice:
            where.setdefault(n, []).append(i)
        order += in_slice
    found += ['%s is named by no slice' % n for n in names if n not in where]
    found += ['%s is named by slices %s' % (n, v) for n, v in where.items() if len(v) > 1]
    if order != sorted(order):
        found.append('the slices do not follow the sorted order of the file names')
    return found


def _must(match, what):
    """The match of a search that has to succeed, or a failure that says what was looked for."""
    if match is None:
        raise AssertionError('not found: ' + what)
    return match


def population():
    return sorted(p.name for p in TESTS.glob('test*.py'))


class TestEveryTestFileIsInOneSlice(unittest.TestCase):

    def test_the_population_is_the_whole_suite(self):
        """The glob below reads the real directory; a population this small would mean the scan sees nothing."""
        _require_sources(self)
        self.assertGreater(len(population()), 1000)

    def test_no_file_is_missed_or_named_twice_and_no_slice_is_empty(self):
        _require_sources(self)
        slices = slices_of(SCRIPT.read_text())
        self.assertGreaterEqual(len(slices), 4)
        self.assertEqual(problems(population(), slices), [])

    def test_no_slice_holds_a_large_share_of_the_modules(self):
        """Memory grows with the modules a process imports; the point of the slices is that none of them has the whole suite."""
        _require_sources(self)
        names = population()
        for i, patterns in enumerate(slices_of(SCRIPT.read_text()), 1):
            n = sum(1 for f in names if any(fnmatch.fnmatchcase(f, p) for p in patterns))
            self.assertLessEqual(n, LARGEST_SHARE * len(names),
                                 'slice %d holds %d of %d modules: add a slice (and a pattern) before it grows further' % (i, n, len(names)))

    def test_the_check_sees_each_thing_it_is_for(self):
        """Control: names that no pattern covers, an overlap, an empty slice and a wrong order are each found; the real slices and a plain list are clean."""
        names = ['test_a.py', 'test_b.py', 'test_v1.py', 'test_v6.py', 'test_z.py']
        good = [['test_[a-b]*.py'], ['test_v[0-5]*.py'], ['test_v6*.py'], ['test_z*.py']]
        self.assertEqual(problems(names, good), [])
        self.assertTrue(any('named by no slice' in p for p in problems(names + ['testx.py'], good)))
        self.assertTrue(any('named by no slice' in p for p in problems(names + ['test_vault.py'], good)))
        self.assertTrue(any('named by slices' in p for p in problems(names, good + [['test_a*.py']])))
        self.assertTrue(any('matches no file' in p for p in problems(names, good + [['test_q*.py']])))
        self.assertTrue(any('sorted order' in p for p in problems(names, [good[3]] + good[:3])))
        # the real script's slices, seen through the same check, with the last slice dropped, miss the end of the suite
        real = slices_of(SCRIPT.read_text()) if SCRIPT.exists() else None
        if real is not None and TESTS.exists():
            self.assertTrue(problems(population(), real[:-1]))


class TestTheScriptRunOnASmallTree(unittest.TestCase):
    """The script itself, over six small test modules, one for each slice."""

    FILES = ['test_a_ok.py', 'test_v1_ok.py', 'test_v6_ok.py', 'test_v70_ok.py', 'test_v74_ok.py', 'test_v8_ok.py']

    def setUp(self):
        _require_sources(self)
        if not shutil.which('bash'):
            self.skipTest('no bash')
        self.tree = Path(tempfile.mkdtemp(prefix='rp-slices-'))
        self.addCleanup(shutil.rmtree, self.tree, ignore_errors=True)
        (self.tree / 'tests').mkdir()
        for name in self.FILES:
            self._write(name, 'self.assertTrue(True)')

    def _write(self, name, body):
        cls = 'T' + re.sub(r'\W', '', name)
        (self.tree / 'tests' / name).write_text(textwrap.dedent('''\
            import unittest


            class %s(unittest.TestCase):
                def test_it(self):
                    %s


            if __name__ == '__main__':
                unittest.main()
            ''') % (cls, body))

    def _run(self):
        env = dict(os.environ, PYTHON=sys.executable, RP_CHUNK_LOGS=str(self.tree / 'logs'), PYTHONDONTWRITEBYTECODE='1')
        return subprocess.run(['bash', str(SCRIPT)], cwd=str(self.tree), env=env, capture_output=True, text=True, timeout=300)

    def test_a_tree_that_passes_exits_zero_and_every_slice_ran(self):
        r = self._run()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        summary = r.stdout.split('=== the slices')[1]
        self.assertEqual(len(re.findall(r'^slice \d/6: Ran 1 tests? in \d+s - OK \(skipped=0\)$', summary, re.M)), 6, r.stdout)
        self.assertIn('every slice passed', r.stdout)

    def test_a_failing_slice_fails_the_run_and_the_slices_after_it_still_run(self):
        self._write('test_v6_ok.py', "self.fail('planted failure')")
        r = self._run()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertRegex(r.stdout, r'(?m)^FAIL: test_it \(test_v6_ok\.', 'the heading of the failing test is printed')
        self.assertRegex(r.stdout, r'(?m)^slice 3/6: .*FAILED', 'the summary names the slice that failed')
        for later in (4, 5, 6):
            self.assertRegex(r.stdout, r'(?m)^slice %d/6: Ran 1 tests? in .*OK' % later, 'slice %d ran after the failure' % later)
        self.assertIn('at least one slice failed', r.stdout)

    def test_a_slice_that_matches_no_file_is_a_failure_and_not_a_pass(self):
        if sys.version_info < (3, 12):
            self.skipTest('unittest answers "no tests ran" with exit 5 from 3.12 on')
        (self.tree / 'tests' / 'test_v1_ok.py').unlink()
        r = self._run()
        self.assertNotEqual(r.returncode, 0, 'a slice of a pattern that names no file went through as a pass:\n' + r.stdout)
        self.assertRegex(r.stdout, r'(?m)^slice 2/6: .*exit 5', r.stdout)


    def test_a_slice_of_several_patterns_gets_one_verdict_for_all_of_them(self):
        """Slice 6 names three patterns. A skip in the first and one in the last are added up, and a failure in the first is not hidden behind the OK of the last."""
        self._write('test_v8_ok.py', "self.skipTest('first pattern')")
        self._write('test_zz_ok.py', "self.skipTest('last pattern')")
        r = self._run()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertRegex(r.stdout, r'(?m)^slice 6/6: Ran 2 tests in \d+s - OK \(skipped=2\)$')
        self._write('test_v8_ok.py', "self.fail('first pattern')")
        r = self._run()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertRegex(r.stdout, r'(?m)^slice 6/6: Ran 2 tests in \d+s - FAILED \(failures=1\)')


class TestCiAndTheMakefileCallTheScript(unittest.TestCase):

    def setUp(self):
        _require_sources(self)
        self.ci = CI_YML.read_text()
        self.mk = MAKEFILE.read_text()

    @staticmethod
    def _jobs(ci):
        """{job name: text of the job} for the top-level jobs of ci.yml."""
        body = ci[ci.index('\njobs:\n') + len('\njobs:\n'):]
        parts = re.split(r'^  ([a-z][a-z0-9_-]*):\n', body, flags=re.M)
        return {parts[i]: parts[i + 1] for i in range(1, len(parts) - 1, 2)}

    def test_the_test_job_runs_the_suite_through_the_script_and_keeps_the_exit_status(self):
        job = self._jobs(self.ci)['test']
        code = [ln for ln in job.splitlines() if 'unittest-chunks.sh' in ln and not ln.lstrip().startswith('#')]
        self.assertEqual(len(code), 1, code)
        self.assertRegex(code[0], r'unittest-chunks\.sh -v 2>&1 \| tail')
        self.assertRegex(job, r'(?m)^\s*set -o pipefail\s*$', 'the pipe into tail needs pipefail, or the job cannot fail')
        self.assertNotRegex('\n'.join(ln for ln in job.splitlines() if not ln.lstrip().startswith('#')), r'python -m unittest discover',
                            'the test job runs the whole suite in one process again')

    def test_the_makefile_runs_ci_parity_and_the_staged_tree_suite_through_the_script(self):
        parity = self.mk[self.mk.index('\nci-parity:'):][:1600]
        self.assertIn('tools/unittest-chunks.sh >', parity)
        dist = self.mk[self.mk.index('Running tests against staged tree'):][:1400]
        self.assertIn('unittest-chunks.sh', dist)
        self.assertNotIn('-m unittest discover', dist)

    def test_both_jobs_keep_a_longer_limit_and_print_the_end_of_the_log_after_a_cancel(self):
        jobs = self._jobs(self.ci)
        for name in ('test', 'dist'):
            job = jobs[name]
            limit = _must(re.search(r'^\s*timeout-minutes:\s*(\d+)', job, re.M), name + ': timeout-minutes')
            self.assertGreaterEqual(int(limit.group(1)), 90, '%s: the limit is the headroom for a slow runner' % name)
            step = _must(re.search(r'- name: End of the test log\n(.*?)(?=\n      - |\n  [a-z]|\Z)', job, re.S), name + ': the "End of the test log" step')
            self.assertRegex(step.group(1), r'if:\s*always\(\)')
            self.assertIn('rp-unittest-chunks', step.group(1), 'it must read the directory the script writes to')

    def test_the_directory_the_step_reads_is_the_one_the_script_writes(self):
        script = SCRIPT.read_text()
        self.assertIn('${TMPDIR:-/tmp}/rp-unittest-chunks', script)
        self.assertIn('slice-$n.log', script)
        self.assertIn('slice-*.log', self.ci)


if __name__ == '__main__':
    unittest.main()

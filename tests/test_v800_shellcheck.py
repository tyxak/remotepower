#!/usr/bin/env python3
"""8.0.0: the shell scripts the repository ships have no shellcheck finding of error level.

`rp doctor` tested for a SQLite file with `[ -f "$dir"/*.db ]`, which answers no when there are two files (shellcheck SC2144, error level), and nothing had looked at the
scripts since the 7.x reviews. The population is every tracked file with a sh or bash shebang or a .sh name. The test skips when shellcheck is not installed, and it checks only
error level so that a newer shellcheck, which adds warnings, cannot turn a release red.
"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SHELLCHECK = shutil.which('shellcheck')


def shell_files():
    out = subprocess.run(['git', 'ls-files'], cwd=ROOT, capture_output=True, text=True)
    if out.returncode != 0:
        return None
    files = []
    for name in out.stdout.split('\n'):
        p = ROOT / name
        if not name or not p.is_file() or p.stat().st_size > 400_000:
            continue
        head = p.open('rb').read(80)
        if name.endswith('.sh') or head.startswith((b'#!/bin/sh', b'#!/bin/bash', b'#!/usr/bin/env bash', b'#!/usr/bin/env sh')):
            files.append(name)
    return files


@unittest.skipUnless(SHELLCHECK, 'shellcheck is not installed')
class TestShellcheck(unittest.TestCase):

    def run_on(self, files, cwd=ROOT):
        return subprocess.run([SHELLCHECK, '-S', 'error', '-f', 'gcc'] + files, cwd=cwd, capture_output=True, text=True)

    def test_it_sees_a_planted_error_and_a_clean_script(self):
        with tempfile.TemporaryDirectory() as d:
            bad, good = Path(d) / 'bad.sh', Path(d) / 'good.sh'
            bad.write_text('#!/bin/bash\nif [ -f /tmp/*.db ]; then echo yes; fi\n')
            good.write_text('#!/bin/bash\nif compgen -G "/tmp/*.db" >/dev/null; then echo yes; fi\n')
            self.assertIn('SC2144', self.run_on([str(bad)]).stdout, 'control: the check can fail')
            self.assertEqual(self.run_on([str(good)]).stdout, '', 'control: a clean script passes')

    def test_the_population_is_not_empty(self):
        files = shell_files()
        if files is None:
            self.skipTest('not a git checkout')
        self.assertGreaterEqual(len(files), 20, files)
        for known in ('install-server.sh', 'server/rp', 'docker/entrypoint.sh'):
            self.assertIn(known, files)

    def test_no_script_has_a_finding_of_error_level(self):
        files = shell_files()
        if files is None:
            self.skipTest('not a git checkout')
        res = self.run_on(files)
        self.assertEqual(res.stdout.strip(), '', '%d scripts read; findings:\n%s' % (len(files), res.stdout))


if __name__ == '__main__':
    unittest.main()

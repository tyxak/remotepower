#!/usr/bin/env python3
"""8.0.0: the asset stamp moves with a client asset, and the pre-commit hook says so when it does not.

`tools/bump-stamp.py` moves CACHE_NAME in sw.js and every ?v= of the pages by one, and `--check` (what `tools/git-hooks/pre-commit` runs) fails when a file under server/html is
staged without a changed CACHE_NAME. The demo showed why: two deploys under one stamp left the first deploy's script in the CDN for a day. The tests run the tool in a scratch
repository, so the real tree is never touched.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / 'tools' / 'bump-stamp.py'
HOOK = ROOT / 'tools' / 'git-hooks' / 'pre-commit'


def setUpModule():
    __import__("sys").path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import env_guard

    env_guard.save(__name__)


def tearDownModule():
    import env_guard

    env_guard.restore(__name__)


def git(cwd, *args):
    return subprocess.run(['git', '-C', str(cwd), '-c', 'user.name=t', '-c', 'user.email=t@example.org', '-c', 'commit.gpgsign=false', *args], capture_output=True, text=True)


class _Repo(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='rp-stamp-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / 'tools').mkdir()
        shutil.copy(TOOL, self.tmp / 'tools' / 'bump-stamp.py')
        html = self.tmp / 'server' / 'html'
        (html / 'static' / 'js').mkdir(parents=True)
        (html / 'static' / 'vendor').mkdir()
        (html / 'sw.js').write_text("const CACHE_NAME = 'remotepower-shell-v8.0.0-4';\n")
        (html / 'index.html').write_text('<script src="static/js/app.js?v=8.0.0-4"></script>\n<link href="static/css/s.css?v=8.0.0-4">\n')
        (html / 'status.html').write_text('<script src="static/js/status.js?v=8.0.0-4"></script>\n')
        (html / 'static' / 'js' / 'app.js').write_text('// one\n')
        (html / 'static' / 'vendor' / 'lib.js').write_text('// lib\n')
        git(self.tmp, 'init', '-q')
        git(self.tmp, 'add', '-A')
        git(self.tmp, 'commit', '-q', '-m', 'base')

    def run_tool(self, *args):
        return subprocess.run([sys.executable, str(self.tmp / 'tools' / 'bump-stamp.py'), *args], capture_output=True, text=True, cwd=str(self.tmp))

    def stage(self, rel, text):
        (self.tmp / rel).write_text(text)
        git(self.tmp, 'add', rel)


class TestTheTool(_Repo):

    def test_a_client_asset_without_the_stamp_is_refused_and_the_message_names_it(self):
        self.stage('server/html/static/js/app.js', '// two\n')
        r = self.run_tool('--check')
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn('server/html/static/js/app.js', r.stderr)
        self.assertIn('bump-stamp.py', r.stderr)

    def test_bumping_moves_every_place_by_one_and_then_the_check_passes(self):
        self.stage('server/html/static/js/app.js', '// two\n')
        r = self.run_tool()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('8.0.0-4 -> 8.0.0-5 in 3 files', r.stdout)
        html = self.tmp / 'server' / 'html'
        self.assertIn("remotepower-shell-v8.0.0-5'", (html / 'sw.js').read_text())
        self.assertEqual((html / 'index.html').read_text().count('?v=8.0.0-5'), 2)
        self.assertNotIn('8.0.0-4', (html / 'status.html').read_text())
        git(self.tmp, 'add', '-A')
        self.assertEqual(self.run_tool('--check').returncode, 0)

    def test_a_ten_after_nine_is_a_ten_and_a_prefix_is_not_touched(self):
        html = self.tmp / 'server' / 'html'
        (html / 'sw.js').write_text("const CACHE_NAME = 'remotepower-shell-v8.0.0-9';\n")
        (html / 'index.html').write_text('<script src="a.js?v=8.0.0-9"></script>\n<script src="b.js?v=8.0.0-90"></script>\n')
        self.run_tool()
        self.assertIn("v8.0.0-10'", (html / 'sw.js').read_text())
        text = (html / 'index.html').read_text()
        self.assertIn('a.js?v=8.0.0-10', text)
        self.assertIn('b.js?v=8.0.0-90', text, 'a longer number that starts with the same digits is not this stamp')

    def test_nothing_under_server_html_means_nothing_to_check(self):
        (self.tmp / 'README.md').write_text('x\n')
        git(self.tmp, 'add', 'README.md')
        self.assertEqual(self.run_tool('--check').returncode, 0)

    def test_a_vendored_file_does_not_need_a_stamp(self):
        self.stage('server/html/static/vendor/lib.js', '// lib 2\n')
        self.assertEqual(self.run_tool('--check').returncode, 0)

    def test_the_stamp_alone_passes(self):
        self.run_tool()
        git(self.tmp, 'add', '-A')
        self.assertEqual(self.run_tool('--check').returncode, 0)

    def test_a_page_changed_without_the_stamp_is_refused_too(self):
        self.stage('server/html/status.html', '<script src="static/js/status.js?v=8.0.0-4"></script>\n<p>new</p>\n')
        self.assertEqual(self.run_tool('--check').returncode, 1)


class TestTheHook(unittest.TestCase):

    def test_the_hook_runs_the_check_and_is_executable_and_clean_shell(self):
        src = HOOK.read_text()
        self.assertTrue(src.startswith('#!/bin/sh\n'))
        self.assertIn('bump-stamp.py" --check', src)
        self.assertTrue(os.access(HOOK, os.X_OK))
        self.assertEqual(subprocess.run(['sh', '-n', str(HOOK)], capture_output=True).returncode, 0)

    def test_the_real_tree_is_in_lockstep_with_its_own_tool(self):
        # the tool and test_ui_wiring.TestCacheBustLockstep read the same stamp: one version in sw.js and in every page
        sw = (ROOT / 'server' / 'html' / 'sw.js').read_text()
        self.assertRegex(sw, r"CACHE_NAME\s*=\s*'remotepower-shell-v\d+\.\d+\.\d+-\d+'")


if __name__ == '__main__':
    unittest.main()

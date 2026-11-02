#!/usr/bin/env python3
"""7.4.9 agent security pass: a restore drill must not run a command named in a setting.

A backup monitor can ask the agent to prove a restore: extract one sample path from the latest archive into a scratch directory.
The repository string had been checked since 7.0.3 ("refuse anything that argparse would read as an option"); the sample path
beside it had not, and it went into the command line of `tar -xf <archive> -C <dir> <member>`, which runs as root. GNU tar reads
an option wherever it stands, so a sample path of `--to-command=<anything>` ran <anything> for the first member (reproduced with
GNU tar 1.35 before the fix: the command ran, as the agent's user, and wrote its marker file). tar has other options that name a
program (`--use-compress-program`, `-I`, `--info-script`, `--checkpoint-action`); they did not run anything in this harness, but
they are refused the same way. Saving the setting needs no more than permission to edit backup monitors, and the drill rides the
heartbeat response, which `require-signed-commands` does not sign.

Now the sample is validated like the repository (a relative path: no leading dash, no `..`, no control characters), and `--`
ends the options in the tar and borg command lines either way. The files the drill restores are also read without following
links, since the archive came from a backup system and may hold a link to anything on the host.
"""
import importlib.machinery
import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
AGENT = Path(os.environ.get('RP_TEST_AGENT') or ROOT / 'client' / 'remotepower-agent.py')


def load_agent():
    loader = importlib.machinery.SourceFileLoader('agent_restore_drill', str(AGENT))
    spec = importlib.util.spec_from_loader('agent_restore_drill', loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


agent = load_agent()
HAVE_TAR = bool(shutil.which('tar'))


class _Drill(unittest.TestCase):

    def setUp(self):
        self._td = tempfile.TemporaryDirectory(prefix='rp-drill-')
        self.addCleanup(self._td.cleanup)
        self.tmp = Path(self._td.name)
        self.state = self.tmp / 'state'
        self.state.mkdir()
        self.marker = self.tmp / 'MARKER'
        patcher = mock.patch.object(agent, 'STATE_DIR', self.state)
        patcher.start()
        self.addCleanup(patcher.stop)
        am = mock.patch.object(agent, '_audit_mode', lambda: False)
        am.start()
        self.addCleanup(am.stop)

    def archive(self):
        src = self.tmp / 'src'
        (src / 'data').mkdir(parents=True, exist_ok=True)
        (src / 'data' / 'file.txt').write_text('hello world\n')
        tar = self.tmp / 'backup.tar'
        subprocess.run(['tar', '-cf', str(tar), '-C', str(src), 'data'], check=True)
        return tar

    def drill(self, tar, sample, tool='tar'):
        mon = {'path': str(tar), 'tool': tool, 'restore_drill_enabled': True, 'restore_sample_path': sample}
        return agent.run_restore_drills([mon], now=1_800_000_000)


@unittest.skipUnless(HAVE_TAR, 'tar is not installed')
class TestTarOptionsInTheSamplePath(_Drill):

    def test_the_ordinary_drill_still_restores_its_sample(self):
        res = self.drill(self.archive(), 'data/file.txt')
        self.assertEqual(len(res), 1, res)
        self.assertEqual(res[0]['drill_status'], 'ok', res)
        self.assertEqual(res[0]['files'], 1)

    def test_a_leading_slash_is_still_accepted(self):
        res = self.drill(self.archive(), '/data/file.txt')
        self.assertEqual(res[0]['drill_status'], 'ok', res)

    def test_no_option_spelled_as_a_path_runs_anything(self):
        marker = str(self.marker)
        for sample in (f'--to-command=touch {marker}',
                       f'--use-compress-program=touch {marker}',
                       f'-Itouch {marker}',
                       f'--info-script=touch {marker}',
                       f'--checkpoint-action=exec=touch {marker}',
                       f'--rsh-command=touch {marker}'):
            with self.subTest(sample=sample):
                if self.marker.exists():
                    self.marker.unlink()
                res = self.drill(self.archive(), sample)
                self.assertFalse(self.marker.exists(), f'tar ran the command in {sample!r}')
                self.assertEqual(len(res), 1)
                self.assertEqual(res[0]['drill_status'], 'invalid_path', res)
                # Every attempt starts a fresh drill: the rate gate remembers the last one.
                for f in self.state.glob('restore_drill_state.json'):
                    f.unlink()

    def test_a_path_that_climbs_out_of_the_archive_is_refused(self):
        for sample in ('../etc/passwd', 'data/../../etc/passwd', '/../x'):
            with self.subTest(sample=sample):
                res = self.drill(self.archive(), sample)
                self.assertEqual(res[0]['drill_status'], 'invalid_path', res)
                for f in self.state.glob('restore_drill_state.json'):
                    f.unlink()

    def test_control_characters_are_refused(self):
        for sample in ('data/file.txt\n--to-command=x', 'data/\x00file', 'a\tb'):
            with self.subTest(sample=repr(sample)):
                res = self.drill(self.archive(), sample)
                self.assertEqual(res[0]['drill_status'], 'invalid_path', res)
                for f in self.state.glob('restore_drill_state.json'):
                    f.unlink()

    def test_the_command_line_ends_options_before_the_member(self):
        # Belt and braces: even a path the validator let through cannot be read as an option.
        calls = []
        real_run = subprocess.run
        tar = self.archive()

        def spy(cmd, *a, **k):
            calls.append(list(cmd))
            return real_run(cmd, *a, **k)
        with mock.patch.object(agent.subprocess, 'run', spy):
            self.drill(tar, 'data/file.txt')
        tar_calls = [c for c in calls if c and c[0] == 'tar']
        self.assertEqual(len(tar_calls), 1, calls)
        argv = tar_calls[0]
        self.assertIn('--', argv)
        self.assertEqual(argv[argv.index('--') + 1:], ['data/file.txt'])


class TestBorgAndRestic(_Drill):
    """borg and restic are not installed on the test host; their command lines are checked through a stand-in."""

    def _run(self, tool, sample):
        calls = []

        def fake_run(cmd, *a, **k):
            calls.append(list(cmd))
            r = mock.Mock()
            r.returncode = 0
            r.stdout = 'archive-2026-11-01\n' if cmd[:2] == ['borg', 'list'] else ''
            r.stderr = ''
            return r
        with mock.patch.object(agent, '_which', lambda prog: '/usr/bin/' + prog), \
                mock.patch.object(agent.subprocess, 'run', fake_run), \
                mock.patch.object(agent, '_verify_restored_tree', lambda root: (0, '', 0)):
            res = agent.run_restore_drills(
                [{'path': '/srv/borg-repo' if tool == 'borg' else '/srv/restic-repo', 'tool': tool,
                  'restore_drill_enabled': True, 'restore_sample_path': sample}], now=1_800_000_000)
        return res, calls

    def test_borg_gets_the_member_after_a_double_dash(self):
        res, calls = self._run('borg', 'etc/hostname')
        extract = [c for c in calls if c[:2] == ['borg', 'extract']]
        self.assertEqual(len(extract), 1, calls)
        self.assertEqual(extract[0][-2:], ['--', 'etc/hostname'])

    def test_restic_takes_the_pattern_as_the_value_of_include(self):
        res, calls = self._run('restic', '/etc/hostname')
        restore = [c for c in calls if c[:4] == ['restic', '-r', '/srv/restic-repo', 'restore']]
        self.assertEqual(len(restore), 1, calls)
        self.assertEqual(restore[0][restore[0].index('--include') + 1], '/etc/hostname')

    def test_an_option_spelled_as_a_path_never_reaches_either_tool(self):
        for tool in ('borg', 'restic'):
            for sample in ('--help', '-o', '--exclude=*', '--rsh=touch x'):
                with self.subTest(tool=tool, sample=sample):
                    res, calls = self._run(tool, sample)
                    self.assertEqual(res[0]['drill_status'], 'invalid_path', res)
                    self.assertEqual([c for c in calls if c[1:2] in (['extract'], ['-r']) or 'restore' in c], [], calls)
                    for f in self.state.glob('restore_drill_state.json'):
                        f.unlink()


class TestTheRestoredTreeIsReadWithoutFollowingLinks(unittest.TestCase):

    def test_a_link_to_a_big_file_elsewhere_is_not_the_biggest_restored_file(self):
        with tempfile.TemporaryDirectory(prefix='rp-tree-') as td:
            td = Path(td)
            sandbox = td / 'sandbox'
            sandbox.mkdir()
            outside = td / 'outside.bin'
            outside.write_bytes(b'S' * 100_000)
            (sandbox / 'small.txt').write_text('ok\n')
            os.symlink(outside, sandbox / 'link-to-big')
            size, sha, count = agent._verify_restored_tree(str(sandbox))
            self.assertEqual(count, 1, 'a link was counted as a restored file')
            self.assertEqual(size, 3)
            import hashlib
            self.assertNotEqual(sha, hashlib.sha256(b'S' * 100_000).hexdigest(), 'the file behind the link was hashed')

    def test_a_fifo_in_the_restored_tree_is_not_opened(self):
        with tempfile.TemporaryDirectory(prefix='rp-tree-') as td:
            sandbox = Path(td)
            os.mkfifo(sandbox / 'pipe')
            (sandbox / 'real.txt').write_text('payload\n')
            size, sha, count = agent._verify_restored_tree(str(sandbox))
            self.assertEqual((size, count), (8, 1))
            self.assertTrue(sha)

    def test_an_empty_restore_is_still_reported_as_empty(self):
        with tempfile.TemporaryDirectory(prefix='rp-tree-') as td:
            self.assertEqual(agent._verify_restored_tree(td), (0, '', 0))


if __name__ == '__main__':
    unittest.main()

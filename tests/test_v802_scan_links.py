"""The secrets scan and the PII scan of the Windows and macOS agents do not go into a folder that is a link (8.0.2).

Both scans are off until an operator turns them on, and the point of them is to read the folders people keep their files in: C:\\Users by default on a Windows host. They walk as SYSTEM
(Windows) or root (macOS) with os.walk. A person can make a folder of their own a directory junction without a privilege, and os.walk decides what is a link with os.path.islink,
which is false for a junction: the walk went into it, read whatever files the junction named as the machine account (a share on another machine included, which sends that
account's credentials there) and reported where it found a secret or a regulated value. The macOS agent never follows a symbolic link in os.walk, and runs the same two functions.

The walk now looks at each folder before it goes into it (lstat, which does not follow it) and leaves out a symbolic link and, on Windows, any reparse point. The helper is twinned
with the macOS agent like the two scans (tests/test_agent_twin_drift.py).

A symbolic link is the Linux twin of a junction here, and a junction is held with an answer of lstat that carries the Windows file attribute. Nothing runs on Windows (see the hand-over).
"""
import importlib.util
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-scanlinks-'))

ROOT = Path(__file__).resolve().parent.parent


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


AGENTS = (('Windows', load('rp_scanlinks_win', 'client/remotepower-agent-win.py')), ('macOS', load('rp_scanlinks_mac', 'client/remotepower-agent-mac.py')))
REAL_LSTAT = os.lstat
TEXT = 'key AKIAIOSFODNN7EXAMPLE mail alice@example.test\n'


class JunctionStat:
    """What lstat answers for a junction on Windows: a directory with the reparse point attribute and no mark of a symbolic link."""
    st_mode = stat.S_IFDIR | 0o755
    st_file_attributes = 0x400 | 0x10
    st_size = 0


class Tree(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='rp-scanlinks-fs-'))
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))
        self.scan = self.root / 'scan'
        (self.scan / 'real').mkdir(parents=True)
        (self.scan / 'real' / 'keys.txt').write_text(TEXT)
        (self.scan / 'top.txt').write_text(TEXT)
        self.outside = self.root / 'outside'
        (self.outside / 'deeper').mkdir(parents=True)
        (self.outside / 'secret.txt').write_text(TEXT)
        (self.outside / 'deeper' / 'more.txt').write_text(TEXT)

    def found(self, agent, kind='secrets'):
        fn = agent.collect_secret_findings if kind == 'secrets' else agent.collect_pii_findings
        return sorted({os.path.relpath(f['path'], self.root) for f in fn([str(self.scan)])})

    def each(self, kind):
        for name, agent in AGENTS:
            with self.subTest(agent=name, scan=kind):
                yield agent


class TestAnHonestTreeIsScanned(Tree):
    def test_the_files_of_the_tree_are_found_by_both_scans_on_both_agents(self):
        for kind in ('secrets', 'pii'):
            for agent in self.each(kind):
                self.assertEqual(self.found(agent, kind), ['scan/real/keys.txt', 'scan/top.txt'])


class TestAFolderThatIsALinkIsNotEntered(Tree):
    def test_a_symbolic_link_to_a_folder_outside_is_not_entered(self):
        os.symlink(self.outside, self.scan / 'link', target_is_directory=True)
        for kind in ('secrets', 'pii'):
            for agent in self.each(kind):
                got = self.found(agent, kind)
                self.assertEqual(got, ['scan/real/keys.txt', 'scan/top.txt'], 'nothing of the folder outside is reported')

    def test_a_junction_is_not_entered_either(self):
        # a junction is a directory with the reparse point attribute and no mark of a symbolic link: the answer of lstat that carries it
        (self.scan / 'junc').mkdir()
        (self.scan / 'junc' / 'in-junction.txt').write_text(TEXT)
        target = str(self.scan / 'junc')

        def lstat(path, *a, **k):
            return JunctionStat() if str(path) == target else REAL_LSTAT(path, *a, **k)

        for kind in ('secrets', 'pii'):
            for agent in self.each(kind):
                with mock.patch.object(os, 'lstat', lstat):
                    got = self.found(agent, kind)
                self.assertEqual(got, ['scan/real/keys.txt', 'scan/top.txt'])
                self.assertEqual(self.found(agent, kind), ['scan/junc/in-junction.txt', 'scan/real/keys.txt', 'scan/top.txt'], 'the control: without the attribute it is a folder')

    def test_a_folder_that_cannot_be_looked_at_is_left_alone(self):
        (self.scan / 'denied').mkdir()
        (self.scan / 'denied' / 'x.txt').write_text(TEXT)
        target = str(self.scan / 'denied')

        def lstat(path, *a, **k):
            if str(path) == target:
                raise PermissionError(13, 'Access is denied')
            return REAL_LSTAT(path, *a, **k)

        for kind in ('secrets', 'pii'):
            for agent in self.each(kind):
                with mock.patch.object(os, 'lstat', lstat):
                    self.assertEqual(self.found(agent, kind), ['scan/real/keys.txt', 'scan/top.txt'])

    def test_a_link_deeper_in_the_tree_is_left_out_and_the_folders_beside_it_are_read(self):
        (self.scan / 'real' / 'sub').mkdir()
        (self.scan / 'real' / 'sub' / 'inner.txt').write_text(TEXT)
        os.symlink(self.outside, self.scan / 'real' / 'sub' / 'link', target_is_directory=True)
        for kind in ('secrets', 'pii'):
            for agent in self.each(kind):
                self.assertEqual(self.found(agent, kind), ['scan/real/keys.txt', 'scan/real/sub/inner.txt', 'scan/top.txt'])


class TestWhatIsALinkFolder(Tree):
    def test_the_helper_asks_lstat(self):
        os.symlink(self.outside, self.root / 'ln', target_is_directory=True)
        for name, agent in AGENTS:
            with self.subTest(agent=name):
                self.assertFalse(agent._is_link_dir(str(self.scan / 'real')))
                self.assertTrue(agent._is_link_dir(str(self.root / 'ln')), 'a symbolic link')
                self.assertTrue(agent._is_link_dir(str(self.root / 'nowhere')), 'a folder that cannot be looked at is left alone')
                with mock.patch.object(os, 'lstat', lambda p, *a, **k: JunctionStat()):
                    self.assertTrue(agent._is_link_dir('anything'), 'a reparse point')

    def test_the_helper_and_the_two_scans_are_the_same_text_in_both_agents(self):
        import inspect
        (_, win), (_, mac) = AGENTS
        for fn in ('_is_link_dir', 'collect_secret_findings', 'collect_pii_findings'):
            self.assertEqual(inspect.getsource(getattr(win, fn)), inspect.getsource(getattr(mac, fn)), fn)


if __name__ == '__main__':
    unittest.main()

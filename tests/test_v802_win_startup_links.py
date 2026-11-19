"""The Windows agent does not follow a link on the way to a startup folder (8.0.2).

The persistence inventory lists the startup folder of each profile as SYSTEM, and every folder of a profile below its root (`AppData`, `Roaming`, `Microsoft`, `Windows`,
`Start Menu`, `Programs`, `Startup`) belongs to the person the profile is of. They can make any of them a directory junction without a privilege, and a symbolic link where
Developer Mode is on, and the listing followed it: the agent sent the names and sizes of a folder the person chose as that person's startup entries, and it opened whatever the
link named as the machine account (a share on another machine included, which sends that account's credentials there). The macOS agent opens every step of the way to an
Info.plist with O_NOFOLLOW; the Windows reader had no such rule.

The reader now looks at each step with lstat, which does not follow it, before it opens the folder. A step that is a link is reported as an entry of its own (`User bob (link)`,
`Startup`, `not followed`) and the folder is not opened. A file in a real folder that is itself a link is reported with ` (link)` after its name and is not measured. A folder with
more entries than the agent looks at is read as far as the limit and the place is cut, where the whole folder used to be in memory before the cap was applied.

A symbolic link is the Linux twin of a junction here: the same code runs on both, and a junction (a reparse point that is not a symbolic link) is held with a result of lstat that
carries the Windows file attribute. Nothing runs on Windows, and the part that cannot be shown is the opening of a path on a real host (see the hand-over).
"""
import os
import shutil
import stat
import sys
import tempfile
import time
import unittest
import importlib.util
from pathlib import Path
from unittest import mock

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-startup-links-'))

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / 'server' / 'cgi-bin'))

import persistence as P  # noqa: E402

_spec = importlib.util.spec_from_file_location('rp_win_startup_links_agent', ROOT / 'client' / 'remotepower-agent-win.py')
win = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(win)

TAIL = ('AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
COMMON = ('Microsoft', 'Windows', 'Start Menu', 'Programs', 'StartUp')
REAL_LSTAT = os.lstat
REAL_SCANDIR = os.scandir


class JunctionStat:
    """What lstat answers for a junction on Windows: a directory with the reparse point attribute and no mark of a symbolic link."""
    st_mode = stat.S_IFDIR | 0o755
    st_file_attributes = 0x400 | 0x10
    st_size = 0


class Tree(unittest.TestCase):
    """A drive in a temporary directory: ProgramData, Users with two honest profiles, and a folder outside every profile that nobody may make the agent read."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='rp-startup-links-fs-'))
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))
        self.users = self.root / 'Users'
        self.programdata = self.root / 'ProgramData'
        self.outside = self.root / 'outside'
        (self.outside / 'Windows' / 'Start Menu' / 'Programs' / 'Startup').mkdir(parents=True)
        for name, size in (('ntds.dit', 4096), ('payroll-2026.xlsx', 123)):
            (self.outside / name).write_bytes(b'x' * size)
        (self.outside / 'Windows' / 'Start Menu' / 'Programs' / 'Startup' / 'from-a-parent-link.exe').write_bytes(b'x' * 7)
        common = self.programdata.joinpath(*COMMON)
        common.mkdir(parents=True)
        (common / 'all-users.lnk').write_bytes(b'u' * 5)
        self.startup('alice').mkdir(parents=True)
        (self.startup('alice') / 'alice-startup.lnk').write_bytes(b'a' * 10)
        (self.users / 'bob').mkdir(parents=True)
        self.env = {'programdata': str(self.programdata), 'systemdrive': str(self.root)}

    def startup(self, user):
        return self.users.joinpath(user, *TAIL)

    def read(self, **kw):
        return win._persist_startup_items(self.env, time.time() + 30)

    def of(self, place, res=None):
        res = res or self.read()
        return sorted((e[1], e[2]) for e in res['items'] if e[0] == place)

    def places(self, res=None):
        return sorted({e[0] for e in (res or self.read())['items']})


class TestAnHonestProfileIsReadAsItself(Tree):
    def test_the_folders_of_honest_profiles_and_of_all_users_are_listed_with_their_sizes(self):
        res = self.read()
        self.assertEqual((res['ok'], res['cut']), (True, False))
        self.assertEqual(self.of('User alice', res), [('alice-startup.lnk', '10 bytes')])
        self.assertEqual(self.of('All users', res), [('all-users.lnk', '5 bytes')])
        self.assertEqual(self.places(res), ['All users', 'User alice'], 'bob has no startup folder yet: it holds nothing')

    def test_a_folder_inside_a_startup_folder_is_listed_by_its_name_with_a_backslash(self):
        (self.startup('alice') / 'sub').mkdir()
        self.assertIn(('sub\\', ''), self.of('User alice'))


class TestALinkOnTheWayIsNotFollowed(Tree):
    def make_link(self, step):
        """bob's path with the step `step` of TAIL made a link to a folder of the outside that holds what the rest of the path would."""
        parts = list(TAIL)
        cur = self.users / 'bob'
        for part in parts[:parts.index(step)]:
            cur = cur / part
        cur.mkdir(parents=True, exist_ok=True)
        os.symlink(self.outside, cur / step, target_is_directory=True)

    def test_the_startup_folder_that_is_a_link_is_one_entry_and_nothing_of_where_it_points_is_listed(self):
        self.make_link('Startup')
        res = self.read()
        self.assertEqual(self.of('User bob (link)', res), [('Startup', 'not followed')])
        self.assertEqual(self.of('User bob', res), [], 'nothing is listed as bob\'s startup entries')
        names = [e[1] for e in res['items']]
        for leaked in ('ntds.dit', 'payroll-2026.xlsx', 'Windows\\', 'from-a-parent-link.exe'):
            self.assertNotIn(leaked, names)
        self.assertEqual((res['ok'], res['cut']), (True, False), 'a place that was read as far as the agent chose to is not a place that was not read')
        self.assertEqual(self.of('User alice', res), [('alice-startup.lnk', '10 bytes')], 'the other profiles are read either way')

    def test_each_step_of_the_way_is_looked_at_and_the_entry_names_the_step(self):
        for step in TAIL:
            with self.subTest(step=step):
                shutil.rmtree(self.users / 'bob')
                self.make_link(step)
                res = self.read()
                self.assertEqual(self.of('User bob (link)', res), [(step, 'not followed')])
                self.assertEqual(self.of('User bob', res), [])

    def test_the_folder_of_all_users_is_held_to_the_same_rule(self):
        shutil.rmtree(self.programdata / 'Microsoft' / 'Windows' / 'Start Menu' / 'Programs' / 'StartUp')
        os.symlink(self.outside, self.programdata.joinpath(*COMMON), target_is_directory=True)
        res = self.read()
        self.assertEqual(self.of('All users (link)', res), [('StartUp', 'not followed')])
        self.assertEqual(self.of('All users', res), [])

    def test_a_link_to_nothing_is_still_a_link_and_not_a_folder_that_holds_nothing(self):
        (self.users / 'bob' / 'AppData' / 'Roaming' / 'Microsoft' / 'Windows' / 'Start Menu' / 'Programs').mkdir(parents=True)
        os.symlink(self.root / 'nowhere', self.startup('bob'), target_is_directory=True)
        self.assertEqual(self.of('User bob (link)'), [('Startup', 'not followed')])

    def test_a_junction_is_a_link_too(self):
        # a junction is a directory with the reparse point attribute and no mark of a symbolic link: the answer of lstat that carries it
        self.startup('bob').mkdir(parents=True)
        (self.startup('bob') / 'real.lnk').write_bytes(b'r')
        target = str(self.startup('bob'))
        opened = []

        def lstat(path, *a, **k):
            return JunctionStat() if str(path) == target else REAL_LSTAT(path, *a, **k)

        def scandir(path):
            opened.append(str(path))
            return REAL_SCANDIR(path)

        with mock.patch.object(os, 'lstat', lstat), mock.patch.object(os, 'scandir', scandir):
            res = self.read()
        self.assertEqual(self.of('User bob (link)', res), [('Startup', 'not followed')])
        self.assertNotIn(target, opened, 'the folder that is a junction was never opened')
        self.assertEqual(self.of('User bob', res), [])

    def test_a_folder_that_cannot_be_looked_at_is_not_read_and_the_others_are(self):
        self.startup('bob').mkdir(parents=True)
        target = str(self.startup('bob'))

        def lstat(path, *a, **k):
            if str(path) == target:
                raise PermissionError(13, 'Access is denied')
            return REAL_LSTAT(path, *a, **k)

        with mock.patch.object(os, 'lstat', lstat):
            res = self.read()
        self.assertFalse(res['ok'], 'access denied is not an empty folder')
        self.assertEqual(self.of('User alice', res), [('alice-startup.lnk', '10 bytes')])


class TestAnEntryThatIsALinkIsNotFollowedEither(Tree):
    def test_a_link_in_a_real_folder_is_marked_and_what_it_points_at_is_not_measured(self):
        os.symlink(self.outside / 'ntds.dit', self.startup('alice') / 'big.lnk')
        os.symlink(self.root / 'nowhere', self.startup('alice') / 'dangling.lnk')
        os.symlink(self.outside, self.startup('alice') / 'folder', target_is_directory=True)
        got = dict(self.of('User alice'))
        self.assertEqual(got['big.lnk (link)'], 'not followed', 'a link to a file is not measured: the size of ntds.dit is not sent')
        self.assertEqual(got['dangling.lnk (link)'], 'not followed')
        self.assertEqual(got['folder (link)'], 'not followed')
        self.assertEqual(got['alice-startup.lnk'], '10 bytes')

    def test_the_size_of_an_entry_is_read_without_following_it(self):
        os.symlink(self.outside / 'ntds.dit', self.startup('alice') / 'big.lnk')
        entries = {e.name: e for e in REAL_SCANDIR(str(self.startup('alice')))}
        self.assertEqual(win._persist_entry_size(entries['alice-startup.lnk']), 10)
        self.assertIsNone(win._persist_entry_size(entries['big.lnk']))

    def test_what_is_a_link_is_decided_by_the_answer_of_lstat(self):
        regular = REAL_LSTAT(self.startup('alice') / 'alice-startup.lnk')
        folder = REAL_LSTAT(self.startup('alice'))
        os.symlink(self.outside, self.root / 'ln', target_is_directory=True)
        self.assertFalse(win._persist_is_link(regular))
        self.assertFalse(win._persist_is_link(folder))
        self.assertTrue(win._persist_is_link(REAL_LSTAT(self.root / 'ln')), 'a symbolic link')
        self.assertTrue(win._persist_is_link(JunctionStat()), 'a junction: no mark of a symbolic link, the reparse point attribute')

        class Placeholder:
            st_mode = stat.S_IFREG | 0o644
            st_file_attributes = 0x400 | 0x20
        self.assertTrue(win._persist_is_link(Placeholder()), 'any reparse point')

        class Plain:
            st_mode = stat.S_IFREG | 0o644
            st_file_attributes = 0x20
        self.assertFalse(win._persist_is_link(Plain()), 'an archive file is not one')


class TestAStepThatBecomesALinkWhileTheFolderIsRead(Tree):
    def test_a_listing_made_while_the_path_was_swapped_for_a_link_is_not_taken(self):
        folder = str(self.startup('alice'))
        parked = str(self.root / 'parked')

        def scandir(path):
            it = REAL_SCANDIR(path)                    # the directory is open now: what it holds is what the listing reads
            if str(path) == folder:
                os.rename(folder, parked)              # and the person swaps the folder for a link to somewhere else
                os.symlink(self.outside, folder, target_is_directory=True)
            return it

        with mock.patch.object(os, 'scandir', scandir):
            res = self.read()
        self.assertEqual(self.of('User alice (link)', res), [('Startup', 'not followed')])
        self.assertEqual(self.of('User alice', res), [], 'what the listing held is not kept as the folder of the profile')


class TestAFolderThatHoldsMillionsIsReadAsFarAsTheLimit(Tree):
    def test_no_more_entries_than_the_limit_are_looked_at_and_the_place_is_cut(self):
        for i in range(60):
            (self.startup('alice') / ('f%03d.lnk' % i)).write_bytes(b'x')
        sizes = []
        real = win._persist_entry_size

        def spy(e):
            sizes.append(e.name)
            return real(e)

        with mock.patch.object(win, '_PERSIST_STARTUP_READ_MAX', 20), mock.patch.object(win, '_persist_entry_size', spy):
            res = self.read()
        self.assertTrue(res['cut'])
        self.assertTrue(res['ok'])
        self.assertLessEqual(len(sizes), 20 + 2, 'the files after the limit were not measured')
        self.assertLessEqual(len(self.of('User alice', res)), win._PERSIST_STARTUP_PER_FOLDER)
        self.assertEqual(win._PERSIST_STARTUP_READ_MAX, 5000)

    def test_a_folder_with_fewer_entries_than_the_limit_is_not_cut(self):
        for i in range(10):
            (self.startup('alice') / ('g%03d.lnk' % i)).write_bytes(b'x')
        with mock.patch.object(win, '_PERSIST_STARTUP_READ_MAX', 20):
            res = self.read()
        self.assertEqual((res['ok'], res['cut']), (True, False))


class TestWhatTheServerDoesWithALinkEntry(Tree):
    """The entry is an ordinary entry of the startup place: a new one after the first inventory is one alert, as any other new entry is."""

    def feed(self, rec, snap_startup, t):
        snap = {'v': P.VERSION}
        for cat in P.CATEGORIES:
            snap[cat] = snap_startup if cat == 'startup' else {'ok': True, 'cut': False, 'items': []}
        rec, added, _removed = P.apply_snapshot(rec, P.clean_snapshot(snap), t)
        due, _gone = P.due_alert(rec, t)
        return rec, [e[1] for _c, e in added], [e['name'] for e in due]

    def test_the_first_inventory_is_a_baseline_and_a_link_made_later_is_a_new_entry_that_alerts(self):
        self.startup('bob').mkdir(parents=True)
        (self.startup('bob') / 'payload.lnk').write_bytes(b'p')
        t = 1794961425
        rec, added, alerts = self.feed({}, self.read(), t)
        self.assertEqual(alerts, [], 'the first inventory of a host is its baseline')
        shutil.rmtree(self.users / 'bob')
        (self.users / 'bob' / 'AppData' / 'Roaming' / 'Microsoft' / 'Windows' / 'Start Menu' / 'Programs').mkdir(parents=True)
        os.symlink(self.outside, self.startup('bob'), target_is_directory=True)
        rec, added, alerts = self.feed(rec, self.read(), t + 900)
        self.assertIn('Startup', added)
        self.assertIn('Startup', alerts, 'a startup folder that became a link is reported')
        stored = [e for e in rec['inv']['startup']['items'] if e[0] == 'User bob (link)']
        self.assertEqual(stored, [['User bob (link)', 'Startup', 'not followed']])


if __name__ == '__main__':
    unittest.main()

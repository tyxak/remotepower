"""The macOS agent's walk of the application folders has one budget, keeps nothing until the end, and says when it stopped (8.0.2).

The walk runs inline in the heartbeat as root: at the first poll, every 360 polls and when the server asks for it. It read every `Info.plist` of /Applications, /System/Applications and
the Applications folder of every account, and kept the parsed dictionary of each bundle until the whole walk was over. The limits were per file (1 MiB) and per folder listing (5,000):
none on the sum, none on the time. A standard user makes a folder of 5,000 bundles whose property lists are one hard link to one 1 MiB file of `<array/>` elements, and each costs the
walk 124 ms and 9 MB: 44 GB and ten minutes, with no heartbeat sent and no command taken.

Now each property list becomes its small row the moment it is read, one budget covers every folder together (time, bytes of property lists, bundles, directory entries), a folder that is
too long to be read to its end is read as far as a limit, and a walk that stopped at a limit says the list is cut. The same module holds the rest of what the list says about itself:
the rows of an account's own folder are marked, a report that must drop rows drops those first, and a report that is cut is another report than the same rows that say they are whole.

The macOS agent cannot run here. The walk uses os.scandir(fd), O_DIRECTORY, O_NOFOLLOW and dir_fd, which Linux has, so the real functions run on a scratch tree; the memory and time of
Python on a Mac are not measured (see the hand-over).
"""
import contextlib
import hashlib
import importlib.util
import itertools
import json
import os
import plistlib
import shutil
import sys
import tempfile
import time
import tracemalloc
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-macscan-'))

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

_mspec = importlib.util.spec_from_file_location('rp_mac_scan_budget_agent', ROOT / 'client' / 'remotepower-agent-mac.py')
mac = importlib.util.module_from_spec(_mspec)
_mspec.loader.exec_module(mac)
_wspec = importlib.util.spec_from_file_location('rp_win_scan_budget_agent', ROOT / 'client' / 'remotepower-agent-win.py')
win = importlib.util.module_from_spec(_wspec)
_wspec.loader.exec_module(win)


def write_plist(path, plist):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps(plist))


def bundle(folder, folder_name, display, version='1.0', ident=None):
    write_plist(Path(folder) / (folder_name + '.app') / 'Contents' / 'Info.plist',
                {'CFBundleDisplayName': display, 'CFBundleShortVersionString': version, 'CFBundleIdentifier': ident or 'com.example.' + folder_name.replace(' ', '')})


HEAD = ('<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0"><dict><key>CFBundleName</key><string>Decoy</string><key>CFBundleShortVersionString</key><string>1.0</string><key>X</key>')


def big_plist(size):
    """A property list of about `size` bytes that is mostly `<array/>` elements: the shape that takes the parser a long time and a lot of memory."""
    return HEAD + '<array>' + '<array/>' * ((size - len(HEAD) - 40) // len('<array/>')) + '</array></dict></plist>'


class Tree(unittest.TestCase):
    """A drive in a temporary directory with the system's Applications folder and one account's, and the agent pointed at them."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='rp-macscan-fs-'))
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))
        self.system = self.root / 'Applications'
        self.user = self.root / 'Users' / 'bob' / 'Applications'
        self.user2 = self.root / 'Users' / 'carol' / 'Applications'
        for d in (self.system, self.user, self.user2):
            d.mkdir(parents=True)
        self.folders = [str(self.system), str(self.user), str(self.user2)]
        p = mock.patch.object(mac, '_application_folders', lambda: self.folders)
        p.start()
        self.addCleanup(p.stop)
        mac._inventory_state['cut'] = False
        self.addCleanup(lambda: mac._inventory_state.update(cut=False))

    def scan(self):
        mac._inventory_state['cut'] = False
        rows, skipped = mac.collect_installed_applications()
        return rows, skipped, mac._inventory_state['cut']

    def names(self, rows):
        return sorted(r['name'] for r in rows)


class TestAnHonestMacIsReadWholeAndIsNotCut(Tree):
    def test_a_walk_that_stopped_at_nothing_does_not_say_it_is_cut(self):
        for i in range(30):
            bundle(self.system, 'App%02d' % i, 'App %02d' % i)
        bundle(self.user, 'Mine', 'Mine')
        rows, skipped, cut = self.scan()
        self.assertEqual(len(rows), 31)
        self.assertEqual((skipped, cut), (0, False))
        self.assertEqual(mac.APP_SCAN_SECONDS, 25)
        self.assertEqual(mac.APP_SCAN_BUNDLES, 5000)


class TestTheWalkSpendsOneBudget(Tree):
    def test_the_bytes_of_property_lists_it_reads_have_a_limit_for_all_the_folders_together(self):
        master = self.root / 'one-plist'
        master.write_text(big_plist(400 * 1024))
        for i in range(20):
            d = self.user / ('Decoy%02d.app' % i) / 'Contents'
            d.mkdir(parents=True)
            os.link(master, d / 'Info.plist')               # a hard link costs a directory entry, not 400 KiB
        parsed = []
        real = mac.plistlib.loads

        def spy(data, *a, **k):
            parsed.append(len(data))
            return real(data, *a, **k)

        with mock.patch.object(mac, 'APP_SCAN_PLIST_BYTES', 1024 * 1024), mock.patch.object(mac.plistlib, 'loads', spy):
            rows, _skipped, cut = self.scan()
        self.assertTrue(cut, 'the walk stopped at the limit and says so')
        self.assertLessEqual(len(parsed), 4, '1 MiB of budget is three property lists of 400 KiB and the one that crosses it')
        self.assertGreaterEqual(len(parsed), 2, 'the instrument sees property lists read')
        self.assertEqual(len(rows), 1, 'twenty bundles of one name and one version are one row')
        self.assertEqual(mac.APP_SCAN_PLIST_BYTES, 12 * 1024 * 1024)

    def test_the_bundles_it_looks_at_have_a_limit_and_the_system_folders_come_first(self):
        for i in range(5):
            bundle(self.system, 'Sys%02d' % i, 'System App %02d' % i)
        for i in range(20):
            bundle(self.user, 'User%02d' % i, 'User App %02d' % i)
        with mock.patch.object(mac, 'APP_SCAN_BUNDLES', 8):
            rows, _skipped, cut = self.scan()
        self.assertTrue(cut)
        self.assertEqual(len(rows), 8)
        self.assertEqual([r['name'] for r in rows if not r.get('in_user_folder')], ['System App %02d' % i for i in range(5)], 'every row of the system was read before the limit')

    def test_the_time_it_takes_has_a_limit(self):
        for i in range(40):
            bundle(self.user, 'Slow%02d' % i, 'Slow %02d' % i)
        clock = itertools.count()
        with mock.patch.object(mac, 'APP_SCAN_SECONDS', 5), mock.patch.object(mac.time, 'monotonic', lambda: next(clock)):
            rows, _skipped, cut = self.scan()
        self.assertTrue(cut)
        self.assertTrue(0 < len(rows) < 40, 'the walk read some bundles and then ran out of time: %d' % len(rows))

    def test_the_directory_entries_it_looks_at_have_a_limit(self):
        for i in range(30):
            (self.user / ('note%02d.txt' % i)).write_text('x')
        bundle(self.system, 'Real', 'Real')
        with mock.patch.object(mac, 'APP_SCAN_ENTRIES', 10):
            rows, _skipped, cut = self.scan()
        self.assertEqual(self.names(rows), ['Real'])
        self.assertTrue(cut, 'a folder of thirty entries took the limit of ten')

    def test_a_folder_too_long_to_be_read_to_its_end_is_read_as_far_as_the_limit_and_cut(self):
        for i in range(30):
            bundle(self.user, 'Many%02d' % i, 'Many %02d' % i)
        with mock.patch.object(mac, 'APP_LISTING_READ', 10):
            rows, _skipped, cut = self.scan()
        self.assertTrue(cut)
        self.assertLessEqual(len(rows), 10)
        self.assertEqual(mac.APP_LISTING_READ, 50000)

    def test_a_folder_with_more_entries_than_the_cap_of_one_folder_is_cut_and_not_silently_short(self):
        for i in range(6):
            bundle(self.system, 'Cap%d' % i, 'Cap %d' % i)
        with mock.patch.object(mac, 'MAX_APP_ENTRIES', 3):
            rows, _skipped, cut = self.scan()
        self.assertEqual(self.names(rows), ['Cap 0', 'Cap 1', 'Cap 2'], 'the first by name, the same ones each time')
        self.assertTrue(cut, 'the three that were not read are not a list that says it is whole')

    def test_the_reviewers_shape_is_stopped_and_what_was_read_is_kept(self):
        # 150 bundles that are hard links to one property list of 1 MiB: the walk reads the budget's worth and stops
        master = self.root / 'one-plist'
        master.write_text(big_plist(mac.MAX_PLIST_BYTES - 16))
        for i in range(150):
            d = self.user / ('Bundle%04d.app' % i) / 'Contents'
            d.mkdir(parents=True)
            os.link(master, d / 'Info.plist')
        bundle(self.system, 'Safari', 'Safari', '17.2')
        t = time.perf_counter()
        rows, _skipped, cut = self.scan()
        spent = time.perf_counter() - t
        self.assertTrue(cut)
        self.assertEqual(sorted(r['name'] for r in rows if not r.get('in_user_folder')), ['Safari'], 'what the system holds is in the list')
        self.assertLess(spent, 12.0, 'twelve megabytes of property lists, not 150')


class TestNothingIsKeptUntilTheEnd(Tree):
    def test_the_memory_of_the_walk_is_about_one_property_list_and_not_all_of_them(self):
        master = self.root / 'one-plist'
        master.write_text(big_plist(300 * 1024))
        for i in range(24):
            d = self.user / ('Held%02d.app' % i) / 'Contents'
            d.mkdir(parents=True)
            os.link(master, d / 'Info.plist')
            (self.user / ('Held%02d.app' % i) / 'Contents' / 'marker').write_text(str(i))
        # a plist of 300 KiB of empty arrays takes about 3 MB once parsed: 24 of them held to the end are 70 MB, and one is 3
        tracemalloc.start()
        try:
            with mock.patch.object(mac, 'APP_SCAN_PLIST_BYTES', 64 * 1024 * 1024):
                rows, _skipped, cut = self.scan()
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertFalse(cut, 'nothing stopped the walk: every property list was read')
        self.assertEqual(len(rows), 1)
        self.assertLess(peak, 25 * 1024 * 1024, 'peak %.1f MB for 24 property lists read one after the other' % (peak / 1048576.0))
        self.assertGreater(peak, 1024 * 1024, 'the instrument sees the parse of a property list')


class TestWhichFoldersAreAnAccountsOwn(Tree):
    def test_the_system_folders_are_not_and_an_account_folder_is(self):
        with mock.patch.object(mac, '_USERS_DIR', '/Users'), mock.patch.object(os, 'geteuid', lambda: 0):
            self.assertFalse(mac._is_account_folder('/Applications'))
            self.assertFalse(mac._is_account_folder('/System/Applications'))
            self.assertTrue(mac._is_account_folder('/Users/alice/Applications'))
            self.assertFalse(mac._is_account_folder('/Users/Shared'))
            self.assertFalse(mac._is_account_folder('/var/root/Applications'), 'the account the agent runs as is root: nobody else writes it')

    def test_the_applications_folder_of_a_person_the_agent_runs_as_is_theirs(self):
        with mock.patch.object(mac, '_USERS_DIR', '/Users'), mock.patch.object(os, 'geteuid', lambda: 501), mock.patch.dict(os.environ, {'HOME': '/Users/dave'}):
            self.assertTrue(mac._is_account_folder(os.path.expanduser('~/Applications')))
            self.assertFalse(mac._is_account_folder('/Applications'))

    def test_every_folder_the_agent_walks_is_classified_and_the_ones_under_users_are_the_accounts(self):
        users = self.root / 'UsersDir'
        for name in ('alice', 'bob'):
            (users / name).mkdir(parents=True)
        real = mac.__dict__['_application_folders']
        with mock.patch.object(mac, '_application_folders', _REAL_FOLDERS), mock.patch.object(mac, '_USERS_DIR', str(users)), \
                mock.patch.object(os, 'geteuid', lambda: 0):
            listed = mac._application_folders()
            marks = {f: mac._is_account_folder(f) for f in listed}
        del real
        self.assertEqual([f for f, m in marks.items() if m], [str(users / n / 'Applications') for n in ('alice', 'bob')])
        self.assertEqual([f for f, m in marks.items() if not m][:2], ['/Applications', '/System/Applications'])
        self.assertGreaterEqual(len(listed), 5, 'the derivation reached the folders of the accounts')

    def test_a_row_only_an_account_holds_is_marked_and_a_row_the_system_holds_too_is_not(self):
        bundle(self.system, 'Safari', 'Safari', '17.2', 'com.apple.Safari')
        bundle(self.user, 'Safari', 'Safari', '17.2', 'com.apple.Safari')          # the same app, in bob's folder
        bundle(self.user, 'Mine', 'Mine', '1.0')
        bundle(self.user2, 'Mine', 'Mine', '1.0')                                   # and in carol's
        rows, _s, _c = self.scan()
        by = {r['name']: r for r in rows}
        self.assertEqual(by['Safari'], {'name': 'Safari', 'version': '17.2', 'manager': 'macos', 'id': 'com.apple.Safari'})
        self.assertIs(by['Mine'].get('in_user_folder'), True)
        self.assertEqual(len(rows), 2)

    def test_the_system_copy_wins_whatever_order_the_folders_are_read_in(self):
        bundle(self.system, 'Safari', 'Safari', '17.2', 'com.apple.Safari')
        bundle(self.user, 'Safari', 'Safari', '17.2', 'com.apple.Safari')
        self.folders[:] = [str(self.user), str(self.system)]                        # the account's folder first
        rows, _s, _c = self.scan()
        self.assertEqual(len(rows), 1)
        self.assertNotIn('in_user_folder', rows[0])


_REAL_FOLDERS = mac._application_folders


def row(name, version='1.0', user=False, manager='macos'):
    r = {'name': name, 'version': version, 'manager': manager}
    if user:
        r['in_user_folder'] = True
    return r


class TestAReportThatMustDropRowsDropsAnAccountsFirst(unittest.TestCase):
    AGENTS = (('macOS', mac), ('Windows', win))

    def setUp(self):
        for _name, agent in self.AGENTS:
            agent._inventory_state['cut'] = False
            self.addCleanup(lambda a=agent: a._inventory_state.update(cut=False))

    def test_decoys_in_an_accounts_folder_do_not_push_the_systems_rows_out(self):
        system = [row('Real %03d' % i) for i in range(40)]
        decoys = [row('0 decoy %04d' % i, user=True) for i in range(5000)]
        rows = sorted(decoys + system, key=lambda r: r['name'].lower())            # the decoys sort first: the old cut by name kept 5,000 of them and dropped the system's
        for name, agent in self.AGENTS:
            with self.subTest(agent=name):
                kept = agent._fit_inventory(rows)
                self.assertEqual(len(kept), 5000)
                self.assertEqual([r['name'] for r in kept if not r.get('in_user_folder')], [r['name'] for r in system], 'every row of the system is in the report')
                self.assertTrue(agent._inventory_state['cut'])
                self.assertEqual([r['name'] for r in kept], sorted((r['name'] for r in kept), key=str.lower), 'the report is still sorted by name')

    def test_the_cut_by_bytes_keeps_the_systems_rows_first_too(self):
        big = 'x' * 380                 # 4,100 rows of about 480 bytes are two megabytes: over the 1.5 MB a report may weigh
        system = [dict(row('S%03d' % i), id=big) for i in range(100)]
        decoys = [dict(row('A%04d' % i, user=True), id=big) for i in range(4000)]
        rows = sorted(decoys + system, key=lambda r: r['name'].lower())
        for name, agent in self.AGENTS:
            with self.subTest(agent=name):
                kept = agent._fit_inventory(rows)
                self.assertLess(len(kept), len(rows))
                self.assertEqual(sum(1 for r in kept if not r.get('in_user_folder')), 100)
                self.assertTrue(agent._inventory_state['cut'])

    def test_a_list_that_fits_is_returned_as_it_is_and_is_not_cut(self):
        rows = [row('A'), row('B', user=True), row('C')]
        for name, agent in self.AGENTS:
            with self.subTest(agent=name):
                self.assertEqual(agent._fit_inventory(rows), rows)
                self.assertFalse(agent._inventory_state['cut'])

    def test_the_two_agents_hold_a_report_to_the_same_limits(self):
        self.assertEqual((mac.MAX_INVENTORY_SEND, mac.MAX_INVENTORY_BYTES), (win.MAX_INVENTORY_SEND, win.MAX_INVENTORY_BYTES))


def old_hash(packages):
    """The fingerprint as it was before 8.0.2."""
    rows = sorted((str(p.get('manager', '')), str(p.get('name', '')), str(p.get('version', '')), str(p.get('arch', '')),
                   str(p.get('publisher', '')), str(p.get('installed', '')), str(p.get('id', ''))) for p in packages)
    return hashlib.sha256(json.dumps(rows, separators=(',', ':')).encode()).hexdigest()[:16]


class TestTheFingerprintOfAListSaysWhatTheListSays(unittest.TestCase):
    ROWS = [{'name': 'A', 'version': '1', 'manager': 'macos', 'id': 'x.a'}, {'name': 'B', 'version': '2', 'manager': 'windows', 'arch': 'x64', 'publisher': 'P', 'installed': '2023-01-02'}]

    def test_a_list_without_a_mark_has_the_fingerprint_it_had_so_that_no_host_sends_its_list_again_for_the_upgrade(self):
        for agent in (mac, win):
            self.assertEqual(agent._compute_pkg_hash(self.ROWS), old_hash(self.ROWS))
            self.assertEqual(agent._compute_pkg_hash(self.ROWS, False), old_hash(self.ROWS))

    def test_the_same_rows_that_say_they_are_cut_are_another_list(self):
        for agent in (mac, win):
            self.assertNotEqual(agent._compute_pkg_hash(self.ROWS, True), agent._compute_pkg_hash(self.ROWS, False))

    def test_a_row_that_moves_into_an_accounts_folder_is_another_list(self):
        moved = [dict(self.ROWS[0], in_user_folder=True), self.ROWS[1]]
        for agent in (mac, win):
            self.assertNotEqual(agent._compute_pkg_hash(moved), agent._compute_pkg_hash(self.ROWS))
            self.assertEqual(agent._compute_pkg_hash(list(reversed(moved))), agent._compute_pkg_hash(moved), 'in any order')


class _Sent:
    def __init__(self, agent, rows, skipped=0, manager='macos'):
        self.agent, self.rows, self.skipped, self.manager = agent, rows, skipped, manager
        self.posts = []

    def __enter__(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='rp-macscan-send-'))
        a = self.agent
        self.patches = [mock.patch.object(a, 'collect_software_inventory', lambda: (self.manager, list(self.rows), self.skipped)),
                        mock.patch.object(a, '_post_json', lambda url, payload, timeout=0: self.posts.append(payload) or {'changed': True}),
                        mock.patch.object(a, '_data_dir', lambda: str(self.tmp))]
        for p in self.patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestTheReportSaysWhenItIsCut(unittest.TestCase):
    CREDS = {'device_id': 'd1', 'token': 't', 'server_url': 'https://srv.invalid'}

    def test_a_report_that_was_whole_has_no_cut_in_it_and_one_that_was_cut_has(self):
        for agent in (mac, win):
            with _Sent(agent, [row('A'), row('B')]) as sent:
                self.assertTrue(agent.send_package_list(self.CREDS))
                self.assertNotIn('cut', sent.posts[0])
            with _Sent(agent, [row('N%04d' % i) for i in range(5001)]) as sent:
                self.assertTrue(agent.send_package_list(self.CREDS))
                self.assertIs(sent.posts[0]['cut'], True)
                self.assertEqual(len(sent.posts[0]['packages']), 5000)

    def test_a_walk_that_ran_out_of_its_budget_is_a_cut_report(self):
        with _Sent(mac, [row('A')]) as sent:
            mac._inventory_state['cut'] = False

            def collect():
                mac._inventory_state['cut'] = True          # what the walk does when it stops at a limit
                return 'macos', [row('A')], 0
            with mock.patch.object(mac, 'collect_software_inventory', collect):
                self.assertTrue(mac.send_package_list(self.CREDS))
            self.assertIs(sent.posts[0]['cut'], True)

    def test_the_flag_of_one_report_is_not_the_flag_of_the_next(self):
        with _Sent(mac, [row('N%04d' % i) for i in range(5001)]) as sent:
            self.assertTrue(mac.send_package_list(self.CREDS))
            self.assertIs(sent.posts[0]['cut'], True)
            sent.rows = [row('A'), row('B')]
            self.assertTrue(mac.send_package_list(self.CREDS))
            self.assertNotIn('cut', sent.posts[1], 'the second report is whole')

    def test_the_same_rows_say_a_different_thing_when_they_become_whole(self):
        # a list that was cut and is whole later with the same rows must be sent again: the hash gate keeps no list that says something else
        rows = [row('A'), row('B')]
        with _Sent(mac, rows) as sent:
            def cut_collect():
                mac._inventory_state['cut'] = True
                return 'macos', list(rows), 0
            with mock.patch.object(mac, 'collect_software_inventory', cut_collect):
                self.assertTrue(mac.send_package_list(self.CREDS))
            self.assertTrue(mac.send_package_list(self.CREDS), 'the same rows, whole now: not skipped by the hash gate')
            self.assertFalse(mac.send_package_list(self.CREDS), 'and the third look is the unchanged one')
            self.assertIs(sent.posts[0]['cut'], True)
            self.assertNotIn('cut', sent.posts[1])


class TestTheOtherPlacesThatLeaveRowsOutSayItToo(unittest.TestCase):
    def test_a_homebrew_list_cut_at_its_limit_says_so(self):
        text = {'--formula': ''.join('pkg%d 1.0\n' % i for i in range(6)), '--cask': 'firefox 125.0.1\n'}

        def fake(argv, timeout, cap, **kw):
            return text[argv[2]]
        mac._inventory_state['cut'] = False
        with mock.patch.object(mac, '_brew_path', lambda: '/x/brew'), mock.patch.object(mac, '_brew_run_kwargs', lambda b: {}), mock.patch.object(mac, '_run_capped', fake):
            rows = mac.collect_brew_packages()
            self.assertEqual(len(rows), 7)
            self.assertFalse(mac._inventory_state['cut'])
            with mock.patch.object(mac, 'MAX_INVENTORY_SEND', 3):
                rows = mac.collect_brew_packages()
        self.assertTrue(mac._inventory_state['cut'])
        self.assertEqual(len(rows), 4, 'three formulae and the cask')
        mac._inventory_state['cut'] = False

    def test_a_formula_with_more_versions_than_are_kept_says_so(self):
        text = {'--formula': 'tool ' + ' '.join('1.%d' % i for i in range(25)) + '\n', '--cask': ''}
        mac._inventory_state['cut'] = False
        with mock.patch.object(mac, '_brew_path', lambda: '/x/brew'), mock.patch.object(mac, '_brew_run_kwargs', lambda b: {}), \
                mock.patch.object(mac, '_run_capped', lambda argv, timeout, cap, **kw: text[argv[2]]):
            rows = mac.collect_brew_packages()
        self.assertEqual(len(rows), 20)
        self.assertTrue(mac._inventory_state['cut'])
        mac._inventory_state['cut'] = False

    def test_a_registry_key_with_more_subkeys_than_the_limit_says_so(self):
        class Reg:
            HKEY_LOCAL_MACHINE = 1
            KEY_READ = 2

            def __init__(self, count):
                self.count = count

            def OpenKey(self, parent, path, reserved=0, access=0):
                return (path,)

            def EnumKey(self, key, index):
                if len(key) == 1 and index < self.count:
                    return 'k%d' % index
                raise OSError(259, 'No more data is available')

            def QueryValueEx(self, key, name):
                if name == 'DisplayName':
                    return 'Program ' + key[0], 1
                raise FileNotFoundError(2, 'x')

            def CloseKey(self, key):
                pass

        win._inventory_state['cut'] = False
        rows, _s = win._read_uninstall_key(Reg(5), 'U', 0, 'x64')
        self.assertEqual(len(rows), 5)
        self.assertFalse(win._inventory_state['cut'], 'the key said it had no more subkeys')
        with mock.patch.object(win, '_MAX_UNINSTALL_SUBKEYS', 3):
            rows, _s = win._read_uninstall_key(Reg(5), 'U', 0, 'x64')
        self.assertEqual(len(rows), 3)
        self.assertTrue(win._inventory_state['cut'], 'two subkeys were not read')
        win._inventory_state['cut'] = False


if __name__ == '__main__':
    unittest.main()

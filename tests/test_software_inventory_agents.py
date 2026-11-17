"""The Windows and macOS agents report the software installed on their host.

Neither agent could run here, so what they read is replaced by the real thing's shape and the agents' own functions run on it:

  * Windows: a stand-in for the standard library's `winreg` that behaves as the real module does (OpenKey and EnumKey and
    QueryValueEx and CloseKey; EnumKey raises OSError when the subkeys end, QueryValueEx raises FileNotFoundError for a value
    that is not there, a key is a handle that is closed). The registry entries are written from what Windows keeps under the
    Uninstall keys; none was read from a host, there is none here.
  * macOS: application bundles written to a temporary directory tree with `plistlib` (binary and XML property lists, one
    with a plist that does not parse, symlinks that leave the folder), and a `brew` script on a PATH of its own.

Each module of the pair is held to the contract the server reads: what an agent sends goes through the real handler.
"""
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(Path(__file__).resolve().parent))
_TMP = []


def _tmp(prefix):
    d = tempfile.mkdtemp(prefix=prefix)
    _TMP.append(d)
    return d


os.environ.setdefault('RP_DATA_DIR', _tmp('rp-softinv-agents-'))
os.environ.setdefault('RP_AGENT_LOG', os.path.join(_tmp('rp-softinv-agents-log-'), 'agent.log'))


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


win = _load('rp_softinv_win_agent', ROOT / 'client' / 'remotepower-agent-win.py')
api = _load('api_softinv_agents', _CGI / 'api.py')


def tearDownModule():
    for d in _TMP:
        shutil.rmtree(d, ignore_errors=True)


# ── Windows ────────────────────────────────────────────────────────────────────────────────────────────────────────────
PLAIN = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
WOW = r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
SZ, DWORD, BINARY = 1, 4, 3


def sz(text):
    return (text, SZ)


# What the two Uninstall keys of a Windows 11 host hold, as the registry hands the values over: text is (str, 1), a flag is
# (int, 4). A key with no DisplayName, one that is a system component, one that is an update of another program, a value
# that is not text, and an install date that is not one are in it on purpose, because each is in a real registry.
UNINSTALL_64 = {
    '{8A69D345-D564-463C-AFF1-A69D9E530F96}': {
        'DisplayName': sz('Google Chrome'), 'DisplayVersion': sz('120.0.6099.109'), 'Publisher': sz('Google LLC'),
        'InstallDate': sz('20231215'), 'UninstallString': sz('"C:\\Program Files\\Google\\Chrome\\setup.exe"')},
    '7-Zip': {'DisplayName': sz('7-Zip 23.01 (x64)'), 'DisplayVersion': sz('23.01'), 'Publisher': sz('Igor Pavlov'),
              'InstallDate': sz('20231102'), 'EstimatedSize': (5120, DWORD)},
    '{36F68A90-239C-34DF-B58C-64B30153CE35}': {
        'DisplayName': sz('Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33130'),
        'DisplayVersion': sz('14.38.33130.0'), 'Publisher': sz('Microsoft Corporation'), 'InstallDate': sz('20231030')},
    'Microsoft Edge': {'DisplayName': sz('Microsoft Edge'), 'DisplayVersion': sz('120.0.2210.91'),
                       'Publisher': sz('Microsoft Corporation'), 'InstallDate': sz('20231220')},
    'KB5034441': {'DisplayName': sz('Security Update for Microsoft Windows (KB5034441)'), 'DisplayVersion': sz('1.0'),
                  'ParentKeyName': sz('OperatingSystem'), 'ParentDisplayName': sz('Windows 11')},
    'IntelChipset': {'DisplayName': sz('Intel(R) Chipset Device Software'), 'DisplayVersion': sz('10.1.19444.8378'),
                     'SystemComponent': (1, DWORD)},
    'HiddenText': {'DisplayName': sz('Hidden By A Text Flag'), 'SystemComponent': sz('1')},
    'NotAComponent': {'DisplayName': sz('Shown Though Flag Is Zero'), 'DisplayVersion': sz('2.0'),
                      'SystemComponent': (0, DWORD)},
    'NoName': {'Publisher': sz('Nobody'), 'DisplayVersion': sz('1.0')},
    'BlankName': {'DisplayName': sz('    '), 'DisplayVersion': sz('1.0')},
    'BinaryName': {'DisplayName': (b'\x00\x01bytes', BINARY)},
    'DwordVersion': {'DisplayName': sz('Version Is A Number'), 'DisplayVersion': (16777216, DWORD)},
    'NoVersion': {'DisplayName': sz('Quiet App'), 'Publisher': sz('Acme')},
    'BadDate': {'DisplayName': sz('Date With Dashes'), 'DisplayVersion': sz('1'), 'InstallDate': sz('2023-12-15')},
    'ZeroDate': {'DisplayName': sz('Date Of Zeros'), 'DisplayVersion': sz('1'), 'InstallDate': sz('00000000')},
    'Long': {'DisplayName': sz('L' * 500), 'DisplayVersion': sz('9' * 500), 'Publisher': sz('P' * 500)},
    # the same program as the first key of this hive, under another key name: one row
    'GoogleChromeAgain': {'DisplayName': sz('Google Chrome'), 'DisplayVersion': sz('120.0.6099.109'),
                          'Publisher': sz('Google LLC')},
}
UNINSTALL_32 = {
    'Mozilla Firefox 121.0 (x86 en-US)': {'DisplayName': sz('Mozilla Firefox (x86 en-US)'),
                                          'DisplayVersion': sz('121.0'), 'Publisher': sz('Mozilla')},
    '{E1A1BF41-0DFD-4C3F-A8F4-AB8A2B2A1B5C}': {
        'DisplayName': sz('Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.38.33130'),
        'DisplayVersion': sz('14.38.33130.0'), 'Publisher': sz('Microsoft Corporation'), 'InstallDate': sz('20231030')},
    # the same program as in the plain key, from a 32-bit installer: another architecture, so another row
    'GoogleChrome32': {'DisplayName': sz('Google Chrome'), 'DisplayVersion': sz('120.0.6099.109')},
}
READ_ONLY_BITS = 0x2 | 0x4 | 0x20 | 0x10000 | 0x40000 | 0x80000       # set value, create subkey, create link, delete, write dac, write owner


class FakeWinreg:
    """`winreg` as far as the agent uses it, behaving as the real module does.

    The tree is {key path: {subkey name: {value name: (value, type)}}}. A key that is not in the tree is FileNotFoundError, EnumKey
    raises OSError when the subkeys end, and a handle that was opened and not closed is a leak the tests look for. Any other name of the
    real module (LoadKey, SaveKey, CreateKey, SetValueEx, DeleteKey ...) is recorded when the agent reaches for it, and is not there."""
    HKEY_LOCAL_MACHINE = 0x80000002
    KEY_READ = 0x20019
    KEY_WOW64_64KEY = 0x0100
    KEY_WOW64_32KEY = 0x0200

    def __init__(self, tree, endless=None):
        self.tree = tree
        self.calls = []
        self.opened = []
        self.reached_for = []
        self.access = []
        self.endless = endless              # {path: n}: EnumKey of that key answers n subkeys, then OSError

    def __getattr__(self, name):
        if not name.startswith('__'):         # the import machinery asks every module for __spec__ and the like
            self.reached_for.append(name)
        raise AttributeError(name)

    class _Handle:
        def __init__(self, node, path):
            self.node, self.path, self.closed = node, path, False

    def OpenKey(self, key, sub_key, reserved=0, access=0x20019):          # noqa: N802 (the real name)
        self.calls.append('OpenKey')
        self.access.append(access)
        if key == self.HKEY_LOCAL_MACHINE:
            if sub_key not in self.tree:
                raise FileNotFoundError(2, 'The system cannot find the file specified')
            handle = self._Handle(self.tree[sub_key], sub_key)
        else:
            if key.closed:
                raise OSError('handle is closed')
            node = key.node.get(sub_key) if isinstance(key.node, dict) else None
            if node is None or sub_key not in key.node:
                raise FileNotFoundError(2, 'The system cannot find the file specified')
            if isinstance(node, Exception):
                raise node
            handle = self._Handle(node, key.path + '\\' + sub_key)
        self.opened.append(handle)
        return handle

    def EnumKey(self, key, index):                                         # noqa: N802
        self.calls.append('EnumKey')
        if key.closed:
            raise OSError('handle is closed')
        limit = (self.endless or {}).get(key.path)
        if limit is not None:
            if index >= limit:
                raise OSError(259, 'No more data is available')
            return f'endless-{index}'
        names = list(key.node)
        if index >= len(names):
            raise OSError(259, 'No more data is available')
        return names[index]

    def QueryValueEx(self, key, name):                                     # noqa: N802
        self.calls.append('QueryValueEx')
        if key.closed:
            raise OSError('handle is closed')
        if name not in key.node:
            raise FileNotFoundError(2, 'The system cannot find the file specified')
        return key.node[name]

    def CloseKey(self, key):                                               # noqa: N802
        self.calls.append('CloseKey')
        key.closed = True

    def leaks(self):
        return [h.path for h in self.opened if not h.closed]


def registry(tree64=None, tree32=None, **kw):
    tree = {}
    if tree64 is not None:
        tree[PLAIN] = tree64
    if tree32 is not None:
        tree[WOW] = tree32
    return FakeWinreg(tree, **kw)


def read_registry(fake):
    with mock.patch.dict(sys.modules, {'winreg': fake}):
        return win.collect_installed_programs()


class TestWindowsReadsTheUninstallKeys(unittest.TestCase):
    def setUp(self):
        self.fake = registry(UNINSTALL_64, UNINSTALL_32)
        self.rows, self.skipped = read_registry(self.fake)
        self.by = {(r['name'], r['arch']): r for r in self.rows}

    def test_a_program_has_a_name_a_version_a_publisher_a_date_and_the_architecture_of_its_key(self):
        chrome = self.by[('Google Chrome', 'x64')]
        self.assertEqual(chrome, {'name': 'Google Chrome', 'version': '120.0.6099.109', 'arch': 'x64',
                                  'manager': 'windows', 'publisher': 'Google LLC', 'installed': '2023-12-15'})
        self.assertEqual(self.by[('7-Zip 23.01 (x64)', 'x64')]['installed'], '2023-11-02')
        # the WOW6432Node key holds the 32-bit programs
        self.assertEqual(self.by[('Mozilla Firefox (x86 en-US)', 'x86')]['publisher'], 'Mozilla')
        self.assertEqual(self.by[('Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.38.33130', 'x86')]['version'],
                         '14.38.33130.0')

    def test_the_architecture_of_the_plain_key_is_that_of_the_machine(self):
        for machine, arch in (('AMD64', 'x64'), ('x86_64', 'x64'), ('ARM64', 'arm64'), ('x86', 'x86'), ('i686', 'x86'),
                              ('', ''), ('riscv64', '')):
            with mock.patch.object(win.platform, 'machine', lambda m=machine: m):
                rows, _ = read_registry(registry({'k': {'DisplayName': sz('Tool')}}))
            self.assertEqual(rows[0]['arch'], arch, machine)

    def test_what_is_not_a_program_is_left_out_and_counted(self):
        names = {r['name'] for r in self.rows}
        for gone in ('Security Update for Microsoft Windows (KB5034441)', 'Intel(R) Chipset Device Software',
                     'Hidden By A Text Flag', '    ', ''):
            self.assertNotIn(gone, names)
        self.assertIn('Shown Though Flag Is Zero', names)               # SystemComponent 0 is a program
        # no DisplayName, a blank one, a value that is not text, an update, and two system components
        self.assertEqual(self.skipped, 6)

    def test_a_value_that_is_not_text_is_no_text(self):
        row = self.by[('Version Is A Number', 'x64')]
        self.assertEqual(row['version'], '')
        self.assertNotIn('publisher', row)
        self.assertEqual(self.by[('Quiet App', 'x64')], {'name': 'Quiet App', 'version': '', 'arch': 'x64',
                                                          'manager': 'windows', 'publisher': 'Acme'})

    def test_an_install_date_is_yyyymmdd_or_nothing(self):
        self.assertNotIn('installed', self.by[('Date With Dashes', 'x64')])
        self.assertNotIn('installed', self.by[('Date Of Zeros', 'x64')])
        for given, want in (('20240229', '2024-02-29'), ('20230229', ''), ('19891231', ''), ('21010101', ''), ('2023121', ''),
                            ('٢٠٢٣١٢١٥', ''), ('', ''), (None, '')):
            self.assertEqual(win._install_date(given), want, given)

    def test_a_field_is_at_most_200_characters(self):
        row = self.by[('L' * 200, 'x64')]
        self.assertEqual((len(row['version']), len(row['publisher'])), (200, 200))

    def test_the_same_program_under_two_keys_is_one_row_and_a_different_architecture_is_another(self):
        chrome = [r['arch'] for r in self.rows if r['name'] == 'Google Chrome']
        self.assertEqual(sorted(chrome), ['x64', 'x86'])             # two keys of the plain hive name it: one row; the 32-bit key: another
        rows, _ = read_registry(registry({'a': {'DisplayName': sz('Tool'), 'DisplayVersion': sz('1')},
                                          'b': {'DisplayName': sz('TOOL'), 'DisplayVersion': sz('1')}},
                                         {'c': {'DisplayName': sz('Tool'), 'DisplayVersion': sz('1')}}))
        self.assertEqual(sorted(r['arch'] for r in rows), ['x64', 'x86'])

    def test_the_rows_are_sorted_by_name_whatever_the_order_of_the_keys(self):
        names = [r['name'].lower() for r in self.rows]
        self.assertEqual(names, sorted(names))
        reversed_tree = dict(reversed(list(UNINSTALL_64.items())))
        rows, skipped = read_registry(registry(reversed_tree, dict(reversed(list(UNINSTALL_32.items())))))
        self.assertEqual((rows, skipped), (self.rows, self.skipped))

    def test_the_registry_is_only_read_and_every_key_is_closed(self):
        self.assertEqual(self.fake.reached_for, [])                       # no LoadKey, SaveKey, CreateKey, SetValueEx ...
        self.assertEqual(set(self.fake.calls), {'OpenKey', 'EnumKey', 'QueryValueEx', 'CloseKey'})
        self.assertTrue(self.fake.access)
        for access in self.fake.access:
            self.assertEqual(access & self.fake.KEY_READ, self.fake.KEY_READ, hex(access))
            self.assertEqual(access & READ_ONLY_BITS, 0, hex(access))
            self.assertTrue(access & self.fake.KEY_WOW64_64KEY, hex(access))   # the 64-bit view, whatever the Python's own kind is
        self.assertEqual(self.fake.leaks(), [])

    def test_a_key_that_is_missing_leaves_the_other(self):
        rows, skipped = read_registry(registry(UNINSTALL_64))
        self.assertEqual([r for r in rows if r['arch'] == 'x86'], [])
        self.assertTrue(rows)
        rows, skipped = read_registry(registry(None, UNINSTALL_32))
        self.assertEqual({r['arch'] for r in rows}, {'x86'})
        self.assertEqual(read_registry(registry()), ([], 0))

    def test_a_subkey_that_cannot_be_opened_is_passed_over(self):
        tree = {'good': {'DisplayName': sz('Good One'), 'DisplayVersion': sz('1')},
                'locked': PermissionError(5, 'Access is denied'),
                'good two': {'DisplayName': sz('Good Two'), 'DisplayVersion': sz('2')}}
        fake = registry(tree)
        rows, skipped = read_registry(fake)
        self.assertEqual([r['name'] for r in rows], ['Good One', 'Good Two'])
        self.assertEqual(fake.leaks(), [])

    def test_a_key_that_fails_in_another_way_leaves_the_other_key_alone(self):
        class Flaky(FakeWinreg):
            def QueryValueEx(self, key, name):                              # noqa: N802
                if key.path.startswith(PLAIN):
                    raise RuntimeError('a driver of the registry fell over')
                return super().QueryValueEx(key, name)
        fake = Flaky({PLAIN: UNINSTALL_64, WOW: UNINSTALL_32})
        rows, skipped = read_registry(fake)
        self.assertEqual({r['arch'] for r in rows}, {'x86'})              # the 32-bit programs are still read
        self.assertEqual(fake.leaks(), [])

    def test_a_key_that_never_ends_does_not_keep_the_agent(self):
        fake = registry({'unused': {}}, endless={PLAIN: 25000})
        rows, skipped = read_registry(fake)
        self.assertEqual(fake.calls.count('EnumKey'), win._MAX_UNINSTALL_SUBKEYS)
        self.assertEqual(win._MAX_UNINSTALL_SUBKEYS, 20000)
        self.assertEqual(rows, [])

    def test_off_windows_there_is_nothing_to_read(self):
        with mock.patch.dict(sys.modules, {'winreg': None}):                # `import winreg` raises ImportError
            self.assertEqual(win.collect_installed_programs(), ([], 0))
            self.assertEqual(win.collect_software_inventory(), ('windows', [], 0))

    def test_the_host_reports_under_its_own_manager(self):
        with mock.patch.dict(sys.modules, {'winreg': self.fake}):
            manager, rows, skipped = win.collect_software_inventory()
        self.assertEqual(manager, 'windows')
        self.assertEqual({r['manager'] for r in rows}, {'windows'})
        self.assertEqual(skipped, self.skipped)


class _Sender(unittest.TestCase):
    """The agent's own send, with the network replaced and a data directory of its own."""

    agent = win

    def setUp(self):
        self.data = _tmp('rp-softinv-data-')
        self.sent = []
        self.answer = {'ok': True, 'changed': True, 'ecosystem': 'unsupported', 'packages_stored': 1}
        for target, name, value in self.patches():
            p = mock.patch.object(target, name, value)
            p.start()
            self.addCleanup(p.stop)
        env = mock.patch.dict(os.environ, {'RP_DATA_DIR': self.data})
        env.start()
        self.addCleanup(env.stop)
        self.agent._inventory_cfg['force'] = False
        self.creds = {'device_id': 'sinvagent1', 'token': 'tok-sinvagent1', 'server_url': 'https://rp.example.com'}

    def patches(self):
        def post(url, payload, timeout=20):
            self.sent.append((url, payload))
            if isinstance(self.answer, Exception):
                raise self.answer
            return self.answer
        return [(self.agent, '_post_json', post)]

    def hashes(self):
        return self.agent._load_last_pkg_hash()


class TestWindowsSendsWhatChanged(_Sender):
    def patches(self):
        self.fake = registry(UNINSTALL_64, UNINSTALL_32)
        self._reg = mock.patch.dict(sys.modules, {'winreg': self.fake})
        self._reg.start()
        self.addCleanup(self._reg.stop)
        return super().patches()

    def test_the_list_goes_to_the_packages_route_with_the_manager_the_rows_and_the_count_left_out(self):
        self.assertTrue(win.send_package_list(self.creds))
        (url, payload), = self.sent
        self.assertEqual(url, 'https://rp.example.com/api/packages')
        self.assertEqual(payload['pkg_manager'], 'windows')
        self.assertEqual((payload['device_id'], payload['token']), ('sinvagent1', 'tok-sinvagent1'))
        self.assertEqual(payload['skipped'], 6)
        self.assertEqual(len(payload['packages']), 13)
        self.assertEqual(payload['packages'][0]['name'], '7-Zip 23.01 (x64)')
        self.assertTrue(self.hashes())

    def test_a_list_that_has_not_changed_is_not_sent_again(self):
        self.assertTrue(win.send_package_list(self.creds))
        self.assertFalse(win.send_package_list(self.creds))
        self.assertFalse(win.send_package_list(self.creds))
        self.assertEqual(len(self.sent), 1)

    def test_the_force_command_sends_it_whatever_the_hash_says(self):
        self.assertTrue(win.send_package_list(self.creds))
        self.assertTrue(win.send_package_list(self.creds, force=True))
        self.assertEqual(len(self.sent), 2)

    def test_a_change_to_any_field_of_any_row_is_sent(self):
        win.send_package_list(self.creds)
        for change in ({'Publisher': sz('Google Inc.')}, {'DisplayVersion': sz('121.0.6167.85')},
                       {'InstallDate': sz('20240102')}):
            tree = {k: dict(v) for k, v in UNINSTALL_64.items()}
            tree['{8A69D345-D564-463C-AFF1-A69D9E530F96}'] = dict(tree['{8A69D345-D564-463C-AFF1-A69D9E530F96}'], **change)
            self.fake.tree[PLAIN] = tree
            self.assertTrue(win.send_package_list(self.creds), change)
            win.send_package_list(self.creds)
        self.assertEqual(len(self.sent), 4)

    def test_what_changes_in_the_count_of_what_was_left_out_alone_is_not_a_change(self):
        win.send_package_list(self.creds)
        tree = dict(UNINSTALL_64)
        tree['AnotherUpdate'] = {'DisplayName': sz('Update For X'), 'ParentKeyName': sz('X')}
        self.fake.tree[PLAIN] = tree
        self.assertFalse(win.send_package_list(self.creds))

    def test_a_failed_send_is_not_remembered_and_raises_nothing(self):
        self.answer = RuntimeError('server returned HTTP 502')
        self.assertFalse(win.send_package_list(self.creds))
        self.assertEqual(self.hashes(), '')
        self.answer = {'ok': True}
        self.assertTrue(win.send_package_list(self.creds))                # the next look sends it, the hash gate never saw the list
        self.answer = OSError('timed out')
        self.assertFalse(win.send_package_list(self.creds, force=True))

    def test_a_host_with_nothing_to_report_sends_nothing(self):
        self.fake.tree.clear()
        self.assertFalse(win.send_package_list(self.creds, force=True))
        self.assertEqual(self.sent, [])

    def test_the_report_fits_what_the_web_server_takes(self):
        """nginx refuses a request over 2 MB. 5,000 rows of 200-character fields are 3.5 MB: the rows that do not fit are left off."""
        huge = {f'k{i}': {'DisplayName': sz(f'{i:05d} ' + 'N' * 195), 'DisplayVersion': sz('9' * 200),
                          'Publisher': sz('P' * 200), 'InstallDate': sz('20240102')} for i in range(5200)}
        self.fake.tree[PLAIN] = huge
        self.assertTrue(win.send_package_list(self.creds))
        (_, payload), = self.sent
        self.assertLess(len(json.dumps(payload)), 2 * 1024 * 1024)
        self.assertGreater(len(payload['packages']), 1000)
        self.assertLessEqual(len(payload['packages']), win.MAX_INVENTORY_SEND)
        self.assertEqual(win.MAX_INVENTORY_SEND, 5000)
        names = [p['name'] for p in payload['packages']]
        self.assertEqual(names, sorted(names, key=str.lower))              # the same rows are left off each time

    def test_no_more_than_5000_rows(self):
        many = {f'k{i}': {'DisplayName': sz(f'App {i:05d}'), 'DisplayVersion': sz('1')} for i in range(5600)}
        self.fake.tree[PLAIN] = many
        self.assertTrue(win.send_package_list(self.creds))
        self.assertEqual(len(self.sent[0][1]['packages']), 5000)


class TestWindowsCadence(TestWindowsSendsWhatChanged):
    def test_it_looks_at_the_first_poll_every_360_polls_and_when_asked(self):
        looked = []
        with mock.patch.object(win, 'send_package_list', lambda creds, force=False: looked.append(force)):
            for poll in (1, 2, 3, 359, 361, 719):
                win._submit_software_inventory(self.creds, poll)
            self.assertEqual(looked, [False])
            win._submit_software_inventory(self.creds, 360)
            win._submit_software_inventory(self.creds, 720)
            self.assertEqual(looked, [False, False, False])
            win._inventory_cfg['force'] = True
            win._submit_software_inventory(self.creds, 5)
            self.assertEqual(looked, [False, False, False, True])
            self.assertFalse(win._inventory_cfg['force'])                 # one-shot
            win._submit_software_inventory(self.creds, 6)
            self.assertEqual(len(looked), 4)
        self.assertEqual(win.PACKAGE_LIST_EVERY, 360)

    def test_a_look_that_finds_the_list_unchanged_sends_nothing(self):
        win._submit_software_inventory(self.creds, 1)
        win._submit_software_inventory(self.creds, 360)
        win._submit_software_inventory(self.creds, 720)
        self.assertEqual(len(self.sent), 1)

    def test_a_look_that_fails_does_not_reach_the_heartbeat(self):
        with mock.patch.object(win, 'send_package_list', lambda creds, force=False: 1 / 0):
            win._submit_software_inventory(self.creds, 1)                 # raises nothing

    def heartbeat(self, answer, poll_count):
        """heartbeat_once as the loop calls it: the POST to /api/heartbeat answers `answer`, the POST of the list answers as the server does."""
        posts = []

        def post(url, payload, timeout=20):
            posts.append(url.rsplit('/api/', 1)[-1])
            return dict(answer) if url.endswith('/api/heartbeat') else {'ok': True, 'changed': True}
        with mock.patch.object(win, '_post_json', post), mock.patch.object(win, 'build_heartbeat', lambda *a, **k: {}):
            win.heartbeat_once(self.creds, poll_count)
        return posts

    def test_the_server_asking_for_a_scan_makes_the_next_beat_send_the_list(self):
        win.send_package_list(self.creds)                                  # the hash gate has seen this list
        self.sent.clear()
        self.assertEqual(self.heartbeat({}, 5), ['heartbeat'])             # not due, not asked: no list
        self.assertEqual(self.heartbeat({'force_package_scan': True}, 6), ['heartbeat', 'packages'])
        self.assertEqual(self.heartbeat({}, 7), ['heartbeat'])             # one-shot
        self.assertEqual(self.heartbeat({}, 1), ['heartbeat'])             # the first poll looks, and the list is unchanged

    def test_the_first_poll_sends_a_list_the_server_has_not_seen(self):
        self.assertEqual(self.heartbeat({}, 1), ['heartbeat', 'packages'])

    def test_the_other_things_the_flag_does_are_still_done(self):
        win._force_sysinfo = False
        self.heartbeat({'force_package_scan': True}, 5)
        self.assertTrue(win._force_sysinfo)                                # the sysinfo refresh it always meant
        win._force_sysinfo = False


# ── the contract: what the agent sends is what the server reads ───────────────────────────────────────────────────────────
class _Server(unittest.TestCase):
    HOST = 'sinvagent1'

    def setUp(self):
        class Captured(Exception):
            def __init__(self, status, body):
                super().__init__(status)
                self.status, self.body = status, body
        self.Captured = Captured
        for name, value in (('respond', lambda status, data=None, headers=None: (_ for _ in ()).throw(Captured(status, data))),
                            ('method', lambda: 'POST'), ('_eval_software_policy', lambda *a, **k: None)):
            p = mock.patch.object(api, name, value)
            p.start()
            self.addCleanup(p.stop)
        api.save(api.DEVICES_FILE, {self.HOST: {'id': self.HOST, 'name': 'box', 'token': 'tok-sinvagent1',
                                                'monitored': True}})
        api.save(api.PACKAGES_FILE, {})
        self.addCleanup(lambda: [api.save(f, {}) for f in (api.DEVICES_FILE, api.PACKAGES_FILE)])
        api._LOAD_CACHE.clear()

    def take(self, payload):
        with mock.patch.object(api, 'get_json_obj', lambda: payload):
            api._LOAD_CACHE.clear()
            try:
                api.handle_packages_submit()
            except self.Captured as c:
                self.assertEqual(c.status, 200, c.body)
        api._LOAD_CACHE.clear()
        return (api.load(api.PACKAGES_FILE) or {}).get(self.HOST) or {}


class TestTheServerTakesWhatTheWindowsAgentSends(_Server, _Sender):
    def setUp(self):
        _Sender.setUp(self)
        _Server.setUp(self)

    def patches(self):
        self.fake = registry(UNINSTALL_64, UNINSTALL_32)
        self._reg = mock.patch.dict(sys.modules, {'winreg': self.fake})
        self._reg.start()
        self.addCleanup(self._reg.stop)
        return _Sender.patches(self)

    def test_every_row_the_agent_found_is_kept_with_everything_it_said(self):
        win.send_package_list(self.creds)
        (_, payload), = self.sent
        entry = self.take(payload)
        self.assertEqual(entry['pkg_manager'], 'windows')
        self.assertEqual(entry['count'], 13)
        self.assertEqual(entry['skipped'], 6)
        self.assertEqual(entry['ecosystem'], '')
        sent = {(p['name'], p['arch']): p for p in payload['packages']}
        kept = {(p['name'], p['arch']): p for p in entry['packages']}
        self.assertEqual(kept, {k: dict(v) for k, v in sent.items()})        # nothing the agent said was dropped or changed
        self.assertIn(('Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33130', 'x64'), kept)

    def test_a_list_that_arrives_twice_is_not_a_change_the_second_time(self):
        win.send_package_list(self.creds)
        payload = self.sent[0][1]
        self.assertTrue(self.take(payload))
        api._LOAD_CACHE.clear()
        before = api.load(api.PACKAGES_FILE)[self.HOST]['hash']
        self.take(payload)
        api._LOAD_CACHE.clear()
        self.assertEqual(api.load(api.PACKAGES_FILE)[self.HOST]['hash'], before)


if __name__ == '__main__':
    unittest.main()

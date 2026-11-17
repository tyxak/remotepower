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
import contextlib
import importlib.util
import json
import os
import plistlib
import shutil
import signal
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
mac = _load('rp_softinv_mac_agent', ROOT / 'client' / 'remotepower-agent-mac.py')
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


# ── macOS ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
class TookTooLong(BaseException):
    """Not an Exception, so that the `except Exception` of the code under test does not take it for one of its own failures."""


@contextlib.contextmanager
def deadline(seconds):
    """Fail the test, instead of hanging it, when what is inside does not finish: a read that waits on a planted FIFO would hang it."""
    def late(signum, frame):
        raise TookTooLong(f'did not finish in {seconds} s')
    old = signal.signal(signal.SIGALRM, late)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


def bundle(folder, name, plist, fmt=plistlib.FMT_XML, raw=None, contents=True):
    """An application bundle under `folder`: <name>/Contents/Info.plist, written by plistlib (or `raw` bytes)."""
    app = Path(folder) / name
    if contents:
        (app / 'Contents').mkdir(parents=True)
        if raw is not None:
            (app / 'Contents' / 'Info.plist').write_bytes(raw)
        elif plist is not None:
            (app / 'Contents' / 'Info.plist').write_bytes(plistlib.dumps(plist, fmt=fmt))
    else:
        app.mkdir(parents=True)
    return app


SAFARI = {'CFBundleName': 'Safari', 'CFBundleDisplayName': 'Safari', 'CFBundleShortVersionString': '17.2',
          'CFBundleVersion': '19617.1.17.11.12', 'CFBundleIdentifier': 'com.apple.Safari', 'LSMinimumSystemVersion': '14.0'}
CHROME = {'CFBundleName': 'Chrome', 'CFBundleDisplayName': 'Google Chrome', 'CFBundleShortVersionString': '120.0.6099.129',
          'CFBundleVersion': '6099.129', 'CFBundleIdentifier': 'com.google.Chrome'}


class MacTree(unittest.TestCase):
    """A tree of application folders in a temporary directory, with what the real ones hold and what a hostile account could leave."""

    def setUp(self):
        self.root = Path(_tmp('rp-softinv-mac-'))
        self.apps = self.root / 'Applications'
        self.system = self.root / 'System' / 'Applications'
        self.user = self.root / 'Users' / 'alice' / 'Applications'
        for d in (self.apps, self.system, self.user):
            d.mkdir(parents=True)
        self.outside = self.root / 'outside'
        self.outside.mkdir()
        # the application folders the agent reads: the three of a Mac, each in the tree
        p = mock.patch.object(mac, '_application_folders', lambda: [str(self.apps), str(self.system), str(self.user)])
        p.start()
        self.addCleanup(p.stop)

    def build(self):
        bundle(self.apps, 'Safari.app', SAFARI, plistlib.FMT_BINARY)                        # a binary property list
        bundle(self.apps, 'Google Chrome.app', CHROME, plistlib.FMT_XML)                    # an XML one
        bundle(self.system, 'Calendar.app', {'CFBundleName': 'Calendar', 'CFBundleShortVersionString': '14.0',
                                              'CFBundleIdentifier': 'com.apple.iCal'})
        bundle(self.user, 'Tool.app', {'CFBundleName': 'Tool', 'CFBundleVersion': '3', 'CFBundleIdentifier': 'org.example.tool'})
        bundle(self.apps, 'Name Only.app', {'CFBundleVersion': '4'})
        bundle(self.apps, 'Display Wins.app', {'CFBundleDisplayName': 'Fancy Name', 'CFBundleName': 'plain',
                                                'CFBundleShortVersionString': '1.0'})
        bundle(self.apps, 'Odd Types.app', {'CFBundleDisplayName': 5, 'CFBundleName': ['x'], 'CFBundleShortVersionString': b'\x00\x01',
                                            'CFBundleVersion': '1.0', 'CFBundleIdentifier': ['no']})
        bundle(self.apps, 'Blank Names.app', {'CFBundleDisplayName': '   ', 'CFBundleName': '', 'CFBundleVersion': '2'})
        (self.apps / 'Utilities').mkdir()
        bundle(self.apps / 'Utilities', 'Terminal.app', {'CFBundleName': 'Terminal', 'CFBundleShortVersionString': '2.14',
                                                         'CFBundleIdentifier': 'com.apple.Terminal'})
        (self.apps / 'Utilities' / 'Deeper').mkdir()
        bundle(self.apps / 'Utilities' / 'Deeper', 'TooDeep.app', {'CFBundleName': 'Too Deep'})
        bundle(self.user, 'Safari.app', SAFARI)                                              # the same app, in a second folder
        (self.apps / '.hidden').mkdir()
        bundle(self.apps / '.hidden', 'InHidden.app', {'CFBundleName': 'In Hidden'})
        (self.apps / '.DS_Store').write_bytes(b'x')
        (self.apps / 'readme.txt').write_text('hi')

    def hostile(self):
        """Everything that is left out of the list, and counted: 9 bundles."""
        bundle(self.apps, 'Broken.app', None, raw=b'<?xml version="1.0"?><plist><dict><key>CFBundleName</key><string>Broken')
        bundle(self.apps, 'Garbage.app', None, raw=b'bplist00 not a property list at all')
        bundle(self.apps, 'List.app', ['not', 'a', 'dict'])
        bundle(self.apps, 'Huge.app', None, raw=plistlib.dumps({'CFBundleName': 'Huge', 'CFBundleVersion': '1'}) + b' ' * (1024 * 1024 + 4096))
        bundle(self.apps, 'NoPlist.app', None)
        bundle(self.apps, 'NoContents.app', None, contents=False)
        (self.apps / 'File.app').write_text('a file that is named like a bundle')
        bundle(self.apps, '.app', {'CFBundleVersion': '1'})                                  # a folder whose name is nothing: no name at all
        outside_app = bundle(self.outside, 'Outside Secret.app', {'CFBundleName': 'Outside Secret', 'CFBundleVersion': '9'})
        os.symlink(outside_app, self.apps / 'Link.app')                                      # a bundle that is a symlink
        return outside_app

    def names(self, rows):
        return sorted(r['name'] for r in rows)


class TestMacReadsTheApplications(MacTree):
    def test_every_bundle_is_a_row_with_the_name_the_version_and_the_identifier(self):
        self.build()
        rows, skipped = mac.collect_installed_applications()
        by = {r['name']: r for r in rows}
        self.assertEqual(by['Safari'], {'name': 'Safari', 'version': '17.2', 'manager': 'macos', 'id': 'com.apple.Safari'})
        self.assertEqual(by['Google Chrome'], {'name': 'Google Chrome', 'version': '120.0.6099.129', 'manager': 'macos',
                                               'id': 'com.google.Chrome'})
        self.assertEqual(by['Calendar']['id'], 'com.apple.iCal')
        self.assertEqual(by['Tool']['version'], '3')                                         # no short version: CFBundleVersion
        self.assertEqual(skipped, 0)

    def test_the_name_is_the_display_name_then_the_bundle_name_then_the_folder(self):
        self.build()
        rows, _ = mac.collect_installed_applications()
        names = self.names(rows)
        self.assertIn('Fancy Name', names)                                                   # CFBundleDisplayName beats CFBundleName
        self.assertNotIn('plain', names)
        self.assertIn('Name Only', names)                                                    # neither: the folder, without .app
        self.assertIn('Odd Types', names)                                                    # a value that is not text is not used
        self.assertIn('Blank Names', names)                                                  # nor is a blank one
        by = {r['name']: r for r in rows}
        self.assertEqual(by['Name Only']['version'], '4')
        self.assertEqual((by['Odd Types']['version'], 'id' in by['Odd Types']), ('1.0', False))

    def test_the_version_is_the_short_version_then_the_bundle_version(self):
        self.build()
        by = {r['name']: r for r in mac.collect_installed_applications()[0]}
        self.assertEqual(by['Safari']['version'], '17.2')                                    # not 19617.1.17.11.12
        self.assertEqual(by['Blank Names']['version'], '2')

    def test_one_level_of_folders_is_read_and_no_more(self):
        self.build()
        names = self.names(mac.collect_installed_applications()[0])
        self.assertIn('Terminal', names)
        self.assertNotIn('Too Deep', names)
        self.assertNotIn('In Hidden', names)                                                 # a hidden folder is not an application folder

    def test_an_app_two_folders_hold_is_one_row_and_the_rows_are_sorted(self):
        self.build()
        rows, _ = mac.collect_installed_applications()
        self.assertEqual(self.names(rows).count('Safari'), 1)
        keys = [r['name'].lower() for r in rows]
        self.assertEqual(keys, sorted(keys))
        # the same app spelled in another case in a later folder is the same row, and the first folder's spelling is the one kept
        bundle(self.system, 'safari.app', {'CFBundleName': 'safari', 'CFBundleShortVersionString': '17.2',
                                           'CFBundleIdentifier': 'com.apple.Safari'})
        rows, _ = mac.collect_installed_applications()
        self.assertEqual([n for n in self.names(rows) if n.lower() == 'safari'], ['Safari'])

    def test_a_bundle_that_cannot_be_read_is_left_out_and_counted_and_nothing_is_raised(self):
        self.build()
        self.hostile()
        rows, skipped = mac.collect_installed_applications()
        names = self.names(rows)
        for gone in ('Broken', 'Garbage', 'List', 'Huge', 'NoPlist', 'NoContents', 'File', 'Link', 'Outside Secret'):
            self.assertNotIn(gone, names)
        self.assertEqual(skipped, 9)                                                         # five that do not read, the file, the empty one, the link, the nameless one
        self.assertIn('Safari', names)                                                       # and the rest is still there

    def test_a_symlink_is_never_followed_out_of_a_folder(self):
        self.build()
        outside = self.hostile()
        # a Contents folder that is a link to a folder with a plist in it
        evil = self.apps / 'Evil.app'
        evil.mkdir()
        os.symlink(outside / 'Contents', evil / 'Contents')
        # an Info.plist that is a link to a plist outside
        linked = self.apps / 'PlistLink.app'
        (linked / 'Contents').mkdir(parents=True)
        os.symlink(outside / 'Contents' / 'Info.plist', linked / 'Contents' / 'Info.plist')
        # a folder that is a link to a folder of applications
        os.symlink(self.outside, self.apps / 'Linked Folder')
        # the whole application folder of an account is a link
        for d in (self.user,):
            for child in d.iterdir():
                shutil.rmtree(child)
            d.rmdir()
        os.symlink(self.outside, self.user)
        rows, skipped = mac.collect_installed_applications()
        names = self.names(rows)
        self.assertNotIn('Outside Secret', names)
        for gone in ('Evil', 'PlistLink'):
            self.assertNotIn(gone, names)
        self.assertEqual(skipped, 11)                                                        # the nine, Evil and PlistLink

    def test_a_planted_fifo_is_not_waited_for(self):
        """A name an account can write may be a FIFO, and opening one for reading waits for a writer that never comes."""
        self.build()
        app = bundle(self.apps, 'Pipe.app', None)
        os.mkfifo(app / 'Contents' / 'Info.plist')                 # as the plist
        os.mkfifo(self.apps / 'Pipe Bundle.app')                   # as the bundle
        os.mkfifo(self.apps / 'pipe-folder')                       # as a folder that might hold bundles
        with deadline(10):
            rows, skipped = mac.collect_installed_applications()
        self.assertNotIn('Pipe', self.names(rows))
        self.assertEqual(skipped, 2)

    def test_a_folder_that_is_missing_or_not_a_folder_is_nothing(self):
        (self.root / 'plain-file').write_text('x')
        with mock.patch.object(mac, '_application_folders', lambda: [str(self.root / 'nowhere'), str(self.root / 'plain-file')]):
            self.assertEqual(mac.collect_installed_applications(), ([], 0))

    def test_every_descriptor_is_closed(self):
        self.build()
        self.hostile()
        before = set(os.listdir('/proc/self/fd')) if os.path.isdir('/proc/self/fd') else None
        for _ in range(3):
            mac.collect_installed_applications()
        if before is not None:
            self.assertEqual(set(os.listdir('/proc/self/fd')) - before, set())

    def test_the_text_of_a_row_is_capped(self):
        bundle(self.apps, 'Long.app', {'CFBundleDisplayName': 'N' * 500, 'CFBundleShortVersionString': '9' * 500,
                                       'CFBundleIdentifier': 'i' * 500})
        row, = mac.collect_installed_applications()[0]
        self.assertEqual([len(row[k]) for k in ('name', 'version', 'id')], [200, 200, 200])

    def test_the_folders_are_the_system_ones_the_agents_own_and_each_account(self):
        users = self.root / 'UsersDir'
        for name in ('alice', 'bob', 'Shared', 'Guest', '.localized', '.hidden'):
            (users / name).mkdir(parents=True)
        (users / 'afile').write_text('x')
        home = self.root / 'home-of-the-agent'
        with mock.patch.object(mac, '_USERS_DIR', str(users)), mock.patch.dict(os.environ, {'HOME': str(home)}), \
                mock.patch.object(mac, '_application_folders', _REAL_APPLICATION_FOLDERS):
            folders = mac._application_folders()
        self.assertEqual(folders[:3], ['/Applications', '/System/Applications', str(home / 'Applications')])
        self.assertEqual([f for f in folders[3:]], [str(users / n / 'Applications') for n in ('afile', 'alice', 'bob')])


_REAL_APPLICATION_FOLDERS = mac._application_folders


FAKE_BREW = '''#!{python}
import os, sys, time
mode = os.environ.get('FAKE_BREW_MODE', 'ok')
marker = os.environ.get('FAKE_BREW_MARKER')
if marker:
    open(marker, 'a').write(' '.join(sys.argv[1:]) + '\\n')
args = sys.argv[1:]
if mode == 'fail':
    sys.stdout.write('wget 1.21.4\\n')
    sys.exit(1)
if mode == 'hang':
    sys.stdout.write('wget 1.21.4\\n')
    sys.stdout.flush()
    time.sleep(60)
if mode == 'flood':
    sys.stdout.write(('x' * 99 + '\\n') * 100000)
    sys.exit(0)
if mode == 'empty':
    sys.exit(0)
if mode == 'endless':
    while True:
        sys.stdout.write('x' * 99 + '\\n')
if args == ['list', '--formula', '--versions']:
    sys.stdout.write('wget 1.21.4\\npython@3.12 3.12.1\\nnode 21.7.1 22.0.0\\n\\n   \\n' + 'z' * 300 + ' 1.0\\nzlib\\n')
elif args == ['list', '--cask', '--versions']:
    sys.stdout.write('firefox 125.0.1\\niterm2 3.4.23\\n')
else:
    sys.exit(3)
'''


class MacBrew(MacTree):
    def setUp(self):
        super().setUp()
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.marker = self.root / 'brew-was-run'
        brew = self.bin / 'brew'
        brew.write_text(FAKE_BREW.format(python=sys.executable))
        brew.chmod(0o755)
        env = mock.patch.dict(os.environ, {'PATH': str(self.bin), 'FAKE_BREW_MODE': 'ok', 'FAKE_BREW_MARKER': str(self.marker)})
        env.start()
        self.addCleanup(env.stop)
        # the places a real Homebrew is: not on this machine, and the test must not depend on whether it is
        real_exists = os.path.exists
        p = mock.patch.object(mac.os.path, 'exists', lambda path: False if str(path) in ('/opt/homebrew/bin/brew', '/usr/local/bin/brew')
                              else real_exists(path))
        p.start()
        self.addCleanup(p.stop)

    def set_mode(self, mode):
        os.environ['FAKE_BREW_MODE'] = mode


class TestMacReadsHomebrew(MacBrew):
    def test_a_row_for_each_version_of_each_formula_and_cask(self):
        rows = mac.collect_brew_packages()
        got = sorted((r['name'], r['version']) for r in rows)
        self.assertEqual(got, [('firefox', '125.0.1'), ('iterm2', '3.4.23'), ('node', '21.7.1'), ('node', '22.0.0'),
                               ('python@3.12', '3.12.1'), ('wget', '1.21.4'), ('zlib', '')])
        self.assertEqual({r['manager'] for r in rows}, {'brew'})
        self.assertEqual(self.marker.read_text().split('\n')[:2], ['list --formula --versions', 'list --cask --versions'])

    def test_a_blank_line_and_a_name_that_is_too_long_are_passed_over(self):
        names = {r['name'] for r in mac.collect_brew_packages()}
        self.assertNotIn('z' * 300, names)
        self.assertFalse([n for n in names if not n.strip()])

    def test_no_brew_is_no_rows_and_nothing_is_run(self):
        os.environ['PATH'] = str(self.root / 'empty-bin')
        self.assertEqual(mac.collect_brew_packages(), [])
        self.assertFalse(self.marker.exists())

    def test_a_brew_that_prints_nothing_is_a_brew_with_nothing_installed(self):
        self.set_mode('empty')
        self.assertEqual(mac.collect_brew_packages(), [])

    def test_a_list_that_failed_timed_out_or_was_cut_is_not_a_list(self):
        """None, not []: a Homebrew whose list could not be read has packages installed, and an empty answer would take them
        from the server's copy as if they had been removed."""
        self.set_mode('fail')
        self.assertIsNone(mac.collect_brew_packages())
        self.set_mode('hang')
        with mock.patch.object(mac, 'BREW_TIMEOUT', 1), deadline(30):
            self.assertIsNone(mac.collect_brew_packages())
        self.set_mode('flood')
        with deadline(30):
            self.assertIsNone(mac.collect_brew_packages())
        self.assertEqual(mac.MAX_BREW_BYTES, 512 * 1024)
        self.assertEqual(mac.BREW_TIMEOUT, 60)

    def test_what_a_command_prints_is_read_up_to_the_limit_and_the_command_is_killed(self):
        self.set_mode('flood')
        with mock.patch.object(mac, 'MAX_BREW_BYTES', 1000), deadline(30):
            self.assertIsNone(mac._run_capped([str(self.bin / 'brew'), 'list'], 30, 1000))
        self.set_mode('ok')
        self.assertEqual(mac._run_capped([str(self.bin / 'brew'), 'list', '--cask', '--versions'], 30, 1000),
                         'firefox 125.0.1\niterm2 3.4.23\n')
        self.assertIsNone(mac._run_capped([str(self.bin / 'brew'), 'list', '--cask', '--versions'], 30, 10))   # 10 bytes is not enough
        self.assertIsNone(mac._run_capped([str(self.root / 'no-such-command')], 30, 1000))

    def test_a_command_that_hangs_does_not_outlive_the_agents_wait(self):
        self.set_mode('hang')
        with deadline(30):
            self.assertIsNone(mac._run_capped([str(self.bin / 'brew'), 'list'], 1, 1000))

    def test_a_command_that_never_stops_printing_is_read_to_the_limit_and_no_further(self):
        self.set_mode('endless')
        with deadline(30):
            self.assertIsNone(mac._run_capped([str(self.bin / 'brew'), 'list'], 30, 4096))

    def test_a_command_that_printed_too_much_and_has_already_exited_is_still_cut(self):
        """The cut is not left to the kill: a command that wrote more than the limit and exited at once has no one to kill."""
        class Done:
            pid = 99999999
            returncode = 0

            class stdout:                                                    # noqa: N801
                data = b'x' * 2000

                @classmethod
                def read(cls, n):
                    return cls.data[:n]

                @staticmethod
                def close():
                    pass

            def poll(self):
                return 0

            def wait(self, timeout=None):
                return 0
        with mock.patch.object(mac.subprocess, 'Popen', lambda *a, **k: Done()):
            self.assertIsNone(mac._run_capped(['x'], 30, 1000))
            self.assertEqual(mac._run_capped(['x'], 30, 2000), 'x' * 2000)       # exactly the limit is not too much

    def test_brew_runs_as_its_owner_and_never_as_root_when_the_owner_is_not_known(self):
        with mock.patch.object(mac, '_brew_run_kwargs', lambda brew: None):
            self.assertEqual(mac.collect_brew_packages(), [])
        self.assertFalse(self.marker.exists())                                              # it was not run
        seen = {}
        real = mac._run_capped

        def spy(argv, timeout, cap, **kw):
            seen.update(kw)
            return real(argv, timeout, cap)
        with mock.patch.object(mac, '_brew_run_kwargs', lambda brew: {'env': dict(os.environ, FROM_OWNER='1')}), \
                mock.patch.object(mac, '_run_capped', spy):
            mac.collect_brew_packages()
        self.assertEqual(seen['env']['FROM_OWNER'], '1')


class TestMacSoftwareInventory(MacBrew):
    def test_the_host_reports_its_applications_and_its_homebrew_packages_under_one_manager(self):
        self.build()
        manager, rows, skipped = mac.collect_software_inventory()
        self.assertEqual(manager, 'macos')
        self.assertEqual({r['manager'] for r in rows}, {'macos', 'brew'})
        names = [r['name'].lower() for r in rows]
        self.assertEqual(names, sorted(names))
        self.assertIn(('wget', 'brew'), {(r['name'], r['manager']) for r in rows})
        self.assertIn(('Safari', 'macos'), {(r['name'], r['manager']) for r in rows})

    def test_a_homebrew_that_cannot_be_read_sends_no_list_at_all(self):
        self.build()
        self.set_mode('fail')
        self.assertEqual(mac.collect_software_inventory(), ('macos', [], 0))
        sent = []
        with mock.patch.object(mac, '_post_json', lambda *a, **k: sent.append(a) or {}), \
                mock.patch.dict(os.environ, {'RP_DATA_DIR': _tmp('rp-softinv-data-')}):
            self.assertFalse(mac.send_package_list({'device_id': 'd', 'token': 't', 'server_url': 'https://x'}, force=True))
        self.assertEqual(sent, [])

    def test_a_mac_without_homebrew_still_reports_its_applications(self):
        self.build()
        os.environ['PATH'] = str(self.root / 'empty-bin')
        manager, rows, skipped = mac.collect_software_inventory()
        self.assertEqual({r['manager'] for r in rows}, {'macos'})
        self.assertTrue(rows)

    def test_a_host_with_nothing_to_report_reports_nothing(self):
        os.environ['PATH'] = str(self.root / 'empty-bin')
        self.assertEqual(mac.collect_software_inventory(), ('macos', [], 0))


class TestMacSendsWhatChanged(MacBrew, _Sender):
    agent = mac

    def setUp(self):
        MacBrew.setUp(self)
        _Sender.setUp(self)
        self.build()
        self.hostile()

    def patches(self):
        def post(url, payload, timeout=20):
            self.sent.append((url, payload))
            if isinstance(self.answer, Exception):
                raise self.answer
            return self.answer
        return [(mac, '_post_json', post)]

    def test_the_list_goes_to_the_packages_route_under_the_manager_macos(self):
        self.assertTrue(mac.send_package_list(self.creds))
        (url, payload), = self.sent
        self.assertEqual(url, 'https://rp.example.com/api/packages')
        self.assertEqual(payload['pkg_manager'], 'macos')
        self.assertEqual(payload['skipped'], 9)
        self.assertEqual({r['manager'] for r in payload['packages']}, {'macos', 'brew'})
        self.assertEqual((payload['device_id'], payload['token']), ('sinvagent1', 'tok-sinvagent1'))

    def test_an_unchanged_list_is_not_sent_again_and_a_force_sends_it(self):
        self.assertTrue(mac.send_package_list(self.creds))
        self.assertFalse(mac.send_package_list(self.creds))
        self.assertTrue(mac.send_package_list(self.creds, force=True))
        self.assertEqual(len(self.sent), 2)

    def test_an_app_that_arrives_is_a_change(self):
        mac.send_package_list(self.creds)
        bundle(self.apps, 'New.app', {'CFBundleName': 'New', 'CFBundleShortVersionString': '1.0'})
        self.assertTrue(mac.send_package_list(self.creds))
        self.assertFalse(mac.send_package_list(self.creds))
        self.set_mode('empty')                                                                # every Homebrew package removed: a change
        self.assertTrue(mac.send_package_list(self.creds))

    def test_a_failed_send_is_not_remembered(self):
        self.answer = RuntimeError('server returned HTTP 502')
        self.assertFalse(mac.send_package_list(self.creds))
        self.assertEqual(mac._load_last_pkg_hash(), '')
        self.answer = {'ok': True}
        self.assertTrue(mac.send_package_list(self.creds))

    def test_the_report_fits_what_the_web_server_takes(self):
        for i in range(3400):                                # 3,400 rows of 200-character fields are 2.2 MB
            bundle(self.apps, f'App {i:05d}.app', {'CFBundleDisplayName': f'{i:05d} ' + 'N' * 190,
                                                   'CFBundleShortVersionString': '9' * 200, 'CFBundleIdentifier': 'i' * 200})
        self.assertTrue(mac.send_package_list(self.creds))
        (_, payload), = self.sent
        self.assertLess(len(json.dumps(payload)), 2 * 1024 * 1024)
        self.assertGreater(len(payload['packages']), 1000)
        self.assertLess(len(payload['packages']), 3400)

    def test_the_cadence_and_the_flag_are_the_windows_agents(self):
        looked = []
        with mock.patch.object(mac, 'send_package_list', lambda creds, force=False: looked.append(force)):
            for poll in (1, 2, 359, 361):
                mac._submit_software_inventory(self.creds, poll)
            mac._submit_software_inventory(self.creds, 360)
            self.assertEqual(looked, [False, False])
            mac._inventory_cfg['force'] = True
            mac._submit_software_inventory(self.creds, 7)
            mac._submit_software_inventory(self.creds, 8)
            self.assertEqual(looked, [False, False, True])
        self.assertEqual(mac.PACKAGE_LIST_EVERY, 360)

    def heartbeat(self, answer, poll_count):
        posts = []

        def post(url, payload, timeout=20):
            posts.append(url.rsplit('/api/', 1)[-1])
            return dict(answer) if url.endswith('/api/heartbeat') else {'ok': True, 'changed': True}
        with mock.patch.object(mac, '_post_json', post), mock.patch.object(mac, 'build_heartbeat', lambda *a, **k: {}):
            mac.heartbeat_once(self.creds, poll_count)
        return posts

    def test_the_server_asking_for_a_scan_makes_the_beat_send_the_list(self):
        mac.send_package_list(self.creds)
        self.assertEqual(self.heartbeat({}, 5), ['heartbeat'])
        self.assertEqual(self.heartbeat({'force_package_scan': True}, 6), ['heartbeat', 'packages'])
        self.assertEqual(self.heartbeat({}, 7), ['heartbeat'])
        self.assertEqual(self.heartbeat({}, 1), ['heartbeat'])                                # unchanged: not sent at the first poll either

    def test_the_other_things_the_flag_does_are_still_done(self):
        mac._force_sysinfo = False
        self.heartbeat({'force_package_scan': True}, 5)
        self.assertTrue(mac._force_sysinfo)
        mac._force_sysinfo = False


class TestTheServerTakesWhatTheMacAgentSends(MacBrew, _Server, _Sender):
    agent = mac

    def setUp(self):
        MacBrew.setUp(self)
        _Sender.setUp(self)
        _Server.setUp(self)
        self.build()
        self.hostile()

    def patches(self):
        def post(url, payload, timeout=20):
            self.sent.append((url, payload))
            return self.answer
        return [(mac, '_post_json', post)]

    def test_every_row_is_kept_with_its_manager_and_its_identifier(self):
        mac.send_package_list(self.creds)
        (_, payload), = self.sent
        entry = self.take(payload)
        self.assertEqual(entry['pkg_manager'], 'macos')
        self.assertEqual(entry['skipped'], 9)
        self.assertEqual(entry['ecosystem'], '')
        sent = {(p['name'], p['manager'], p['version']): p for p in payload['packages']}
        kept = {(p['name'], p['manager'], p['version']): p for p in entry['packages']}
        self.assertEqual(set(kept), set(sent))
        safari = kept[('Safari', 'macos', '17.2')]
        self.assertEqual(safari['id'], 'com.apple.Safari')
        self.assertEqual(kept[('wget', 'brew', '1.21.4')]['manager'], 'brew')
        self.assertEqual(entry['count'], len(sent))


if __name__ == '__main__':
    unittest.main()

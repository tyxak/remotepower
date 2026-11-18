#!/usr/bin/env python3
"""What starts by itself on a Windows host: the inventory the agent takes, the log of what was added and removed, and the one alert for a new entry.

A person who has got into a Windows host leaves something that starts again by itself, and nothing here looked at those places. The Windows agent now lists five of
them (the Run and RunOnce keys of HKLM in both registry views, the Winlogon Shell and Userinit values, services that run from a temporary or user folder, scheduled
tasks that are not Microsoft's, startup folders) at most every 15 minutes, and the server keeps the last list, writes what is new and what is gone into a log and raises
one alert for what is new after the host's first inventory.

What is held here, and how:

  * the reading of a snapshot (server/cgi-bin/persistence.py): what a host may send, the caps, a hostile name, a password in a command line;
  * what counts as a change: the first inventory is a baseline, a place that could not be read or that was cut is not compared, a changed command is a new entry beside a
    removed one, a removed entry does not alert, one alert an hour and nothing lost that arrived inside it;
  * the agent, driven with a fake `winreg` that records every call and fails on a write, canned `schtasks /query /xml` output in the form Windows prints it (UTF-16, one
    document after another, a wrapper), and real folders in a temporary directory; the agent's cleaning and the server's are given the same text and must agree;
  * the chain from the real agent function through the real heartbeat, the store, the page's endpoint and the alert in the inbox, as a tenant administrator and as a
    read-only user, with the host deleted at the end;
  * the registrations a new store and a new event need (storage, store shape, host purge, the event, its routing kind) and the six languages of what a person reads.

Nothing runs on Windows: the registry, schtasks and the folders are made here in the form the real ones have, and what could not be shown is in the hand-over.
"""
import importlib.util
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-persist-'))

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import persistence as P  # noqa: E402
from i18n_engine import LANGS, dict_rows  # noqa: E402

_spec = importlib.util.spec_from_file_location('api_win_persistence', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_wspec = importlib.util.spec_from_file_location('rp_win_persistence_agent', _ROOT / 'client' / 'remotepower-agent-win.py')
win = importlib.util.module_from_spec(_wspec)
_wspec.loader.exec_module(win)

NOW = 1794961425
OS_END = OSError(259, 'No more data is available')


# ── a registry, a schtasks and a set of folders in the form Windows has them ─
class FakeRegistry:
    """The part of winreg the inventory may use, with the values, the end-of-list error and the access errors the real module has.

    A key is a path in one of the two views (64 and 32 bit: the 32-bit view of a path is its own list). Anything the agent asks for that a read does not need is recorded in
    `touched` and raises, and every OpenKey is recorded with its access mask, so a test can say that nothing but read access was asked for.
    """
    HKEY_LOCAL_MACHINE = 0x80000002
    KEY_READ = 0x20019
    KEY_WOW64_64KEY = 0x100
    KEY_WOW64_32KEY = 0x200
    REG_NONE, REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD = 0, 1, 2, 3, 4, 7, 11

    def __init__(self):
        self.keys = {64: {}, 32: {}}           # view -> {path lower: {'values': [(name, data, type)], 'subkeys': [names]}}
        self.deny = set()                       # (view, path lower): OpenKey raises PermissionError
        self.enum_fail = {}                     # (view, path lower): (index, exception) raised by EnumValue/EnumKey at that index
        self.opened = []
        self.touched = []

    def add(self, path, values=(), subkeys=(), view=64):
        self.keys[view][path.lower()] = {'values': list(values), 'subkeys': list(subkeys)}

    def OpenKey(self, parent, path, reserved=0, access=KEY_READ):
        self.opened.append((path, access))
        view = 32 if access & self.KEY_WOW64_32KEY else 64
        full = path if parent == self.HKEY_LOCAL_MACHINE else parent[2] + '\\' + path
        if (view, full.lower()) in self.deny:
            raise PermissionError(5, 'Access is denied')
        if full.lower() not in self.keys[view]:
            raise FileNotFoundError(2, 'The system cannot find the file specified')
        return ('hkey', view, full)

    def _node(self, key):
        return self.keys[key[1]][key[2].lower()]

    def EnumValue(self, key, i):
        fail = self.enum_fail.get((key[1], key[2].lower()))
        if fail and i >= fail[0]:
            raise fail[1]
        vals = self._node(key)['values']
        if i >= len(vals):
            raise OSError(259, 'No more data is available')
        return vals[i]

    def EnumKey(self, key, i):
        fail = self.enum_fail.get((key[1], key[2].lower()))
        if fail and i >= fail[0]:
            raise fail[1]
        subs = self._node(key)['subkeys']
        if i >= len(subs):
            raise OSError(259, 'No more data is available')
        return subs[i]

    def QueryValueEx(self, key, name):
        for n, data, typ in self._node(key)['values']:
            if n.lower() == name.lower():
                return data, typ
        raise FileNotFoundError(2, 'The system cannot find the file specified')

    def CloseKey(self, key):
        pass

    def __getattr__(self, name):
        if not name.startswith('__'):          # the import machinery looks up __spec__ on a module it finds in sys.modules
            self.touched.append(name)
        raise AttributeError('the inventory used winreg.%s' % name)


S, X, D, B = FakeRegistry.REG_SZ, FakeRegistry.REG_EXPAND_SZ, FakeRegistry.REG_DWORD, FakeRegistry.REG_BINARY
RUN = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
RUNONCE = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
WINLOGON = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'
SERVICES = 'SYSTEM\\CurrentControlSet\\Services'


def hardened_registry():
    """A Windows 11 host as it comes, with the Run values its software leaves, and two services that run from a user folder."""
    r = FakeRegistry()
    r.add(RUN, [('SecurityHealth', '%windir%\\system32\\SecurityHealthSystray.exe', X),
                ('RtkAudUService', '"C:\\Windows\\System32\\DriverStore\\FileRepository\\realtek\\RtkAudUService64.exe" -background', S),
                ('Chunk', b'\x01\x02\x03', B), ('Flags', 7, D)])
    r.add(RUNONCE, [])
    r.add(RUN, [('OneDriveSetup', '"C:\\Windows\\SysWOW64\\OneDriveSetup.exe" /thfirstsetup', S)], view=32)
    r.add(WINLOGON, [('Shell', 'explorer.exe', S), ('Userinit', 'C:\\Windows\\system32\\userinit.exe,', S), ('Background', '0 0 0', S)])
    r.add(SERVICES, subkeys=['Spooler', 'WinDefend', 'Updater', 'DriverX', 'UsesVar', 'NoImage', 'BinaryImage', 'Locked'])
    r.add(SERVICES + '\\Spooler', [('ImagePath', '%SystemRoot%\\System32\\spoolsv.exe', X), ('Type', 16, D)])
    r.add(SERVICES + '\\WinDefend', [('ImagePath', '"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2309.6-0\\MsMpEng.exe"', S)])
    r.add(SERVICES + '\\Updater', [('ImagePath', 'C:\\Users\\bob\\AppData\\Local\\Temp\\upd.exe -k run', S)])
    r.add(SERVICES + '\\DriverX', [('ImagePath', '\\??\\C:\\Windows\\Temp\\x.sys', S), ('Type', 1, D)])
    r.add(SERVICES + '\\UsesVar', [('ImagePath', '%TEMP%\\u.exe', X)])
    r.add(SERVICES + '\\NoImage', [('Description', 'no program', S)])
    r.add(SERVICES + '\\BinaryImage', [('ImagePath', b'C:\\Users\\x.exe', B)])
    r.add(SERVICES + '\\Locked', [('ImagePath', 'C:\\Users\\locked.exe', S)])
    r.deny.add((64, (SERVICES + '\\Locked').lower()))
    return r


NS = 'http://schemas.microsoft.com/windows/2004/02/mit/task'


def task_xml(uri, command=None, arguments=None, com=None, enabled=True, declaration=True, extra=''):
    """One task as `schtasks /query /xml` prints it: the declaration, the namespace, the URI in RegistrationInfo, the actions."""
    if com:
        actions = '<ComHandler><ClassId>%s</ClassId></ComHandler>' % com
    else:
        actions = '<Exec><Command>%s</Command>%s</Exec>' % (command, '<Arguments>%s</Arguments>' % arguments if arguments is not None else '')
    return ('%s<Task version="1.2" xmlns="%s">\n  <RegistrationInfo>\n    <Date>2026-11-18T00:23:45.0000000</Date>\n    <Author>CORP\\bob</Author>\n'
            '    <URI>%s</URI>\n  </RegistrationInfo>\n  <Triggers>\n    <LogonTrigger>\n      <Enabled>true</Enabled>\n    </LogonTrigger>\n  </Triggers>\n'
            '  <Principals>\n    <Principal id="Author">\n      <UserId>S-1-5-18</UserId>\n      <RunLevel>HighestAvailable</RunLevel>\n    </Principal>\n  </Principals>\n'
            '  <Settings>\n    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n    <Enabled>%s</Enabled>\n  </Settings>\n%s'
            '  <Actions Context="Author">\n    %s\n  </Actions>\n</Task>' % (
                '<?xml version="1.0" encoding="UTF-16"?>\n' if declaration else '', NS, uri, 'true' if enabled else 'false', extra, actions))


def schtasks_output(wrapper=False):
    """What a host with Microsoft's tasks, three that are not, one that is disabled and one that hides in Microsoft's folder prints."""
    tasks = [
        task_xml('\\Microsoft\\Windows\\Defrag\\ScheduledDefrag', '%windir%\\system32\\defrag.exe', '-c -h -o -$'),
        task_xml('\\Microsoft\\Windows\\WindowsUpdate\\Scheduled Start', '%systemroot%\\system32\\sc.exe', 'start wuauserv'),
        task_xml('\\Microsoft\\Windows\\Maintenance\\WinSAT', None, None, com='{1A2B3C4D-0000-0000-0000-000000000001}'),
        task_xml('\\GoogleUpdateTaskMachineCore{8A69D345-D564-463C-AFF1-A69D9E530F96}', '"C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe"', '/c'),
        task_xml('\\OneDrive Standalone Update Task-S-1-5-21-3623811015-3361044348-30300820-1013', '%localappdata%\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe'),
        task_xml('\\Updater', 'C:\\Users\\bob\\AppData\\Local\\Temp\\upd.exe', '-k run'),
        task_xml('\\Vendor\\Agent\\ComTask', None, None, com='{DEADBEEF-0000-0000-0000-000000000002}'),
        task_xml('\\Vendor\\Disabled', 'C:\\Vendor\\old.exe', None, enabled=False),
        task_xml('\\Microsoft\\Windows\\Maintenance\\SystemCare', 'C:\\Users\\Public\\care.exe', '--quiet'),
    ]
    body = '\n'.join(tasks)
    return ('<?xml version="1.0" encoding="UTF-16"?>\n<Tasks>\n' + body.replace('<?xml version="1.0" encoding="UTF-16"?>\n', '') + '\n</Tasks>') if wrapper else body


class Folders:
    """The folders a Windows host has for startup entries, made in a temporary directory with the names the real ones have."""

    def __init__(self):
        self.root = Path(tempfile.mkdtemp(prefix='rp-persist-fs-'))
        self.programdata = self.root / 'ProgramData'
        self.users = self.root / 'Users'
        common = self.programdata / 'Microsoft' / 'Windows' / 'Start Menu' / 'Programs' / 'StartUp'
        common.mkdir(parents=True)
        (common / 'desktop.ini').write_text('[.ShellClassInfo]')
        (common / 'OneNote.lnk').write_bytes(b'L' * 1893)
        for name in ('bob', 'alice', 'Public', 'Default', 'All Users', 'Default User'):
            (self.users / name).mkdir(parents=True)
        self.startup('bob').mkdir(parents=True)
        (self.startup('bob') / 'evil.lnk').write_bytes(b'x' * 700)
        self.startup('Default').mkdir(parents=True)

    def startup(self, user):
        return self.users / user / 'AppData' / 'Roaming' / 'Microsoft' / 'Windows' / 'Start Menu' / 'Programs' / 'Startup'

    def env(self):
        return {'programdata': str(self.programdata), 'systemdrive': str(self.root), 'systemroot': 'C:\\Windows', 'windir': 'C:\\Windows',
                'temp': 'C:\\Windows\\TEMP', 'localappdata': 'C:\\Windows\\system32\\config\\systemprofile\\AppData\\Local'}

    def remove(self):
        shutil.rmtree(self.root, ignore_errors=True)


def collect(reg=None, tasks=None, folders=None, budget=60):
    """The agent's snapshot of a host built from the pieces above."""
    own = folders is None
    folders = folders or Folders()
    try:
        return win.collect_persistence(wr=reg or hardened_registry(), run=lambda args, timeout: schtasks_output() if tasks is None else tasks, env=folders.env(), budget=budget)
    finally:
        if own:
            folders.remove()


def snap_of(**places):
    """A snapshot as a host would send it, for the server side alone: each place `[[place, name, command], ...]` and read whole unless said otherwise."""
    out = {'v': P.VERSION}
    for cat in P.CATEGORIES:
        v = places.get(cat, [])
        out[cat] = v if isinstance(v, dict) else {'ok': True, 'cut': False, 'items': v}
    return out


def entries(rec, cat):
    return [tuple(e) for e in rec['inv'][cat]['items']]


# ── the reading of a snapshot ────────────────────────────────────────────────
class TestReadingASnapshot(unittest.TestCase):
    def test_a_snapshot_is_cleaned_sorted_and_free_of_duplicates(self):
        raw = snap_of(run=[['Run', 'b', 'two'], ['Run', 'a', 'one'], ['Run', 'a', 'one'], ['RunOnce', 'c', 'three']])
        got = P.clean_snapshot(raw)
        self.assertEqual(got['run'], {'ok': True, 'cut': False, 'items': [['Run', 'a', 'one'], ['Run', 'b', 'two'], ['RunOnce', 'c', 'three']]})
        self.assertEqual(got['v'], 1)

    def test_anything_that_is_not_a_snapshot_of_this_version_is_nothing(self):
        for bad in (None, [], 'x', 5, {}, {'v': 2}, {'v': True}, {'v': '1'}, {'v': 1.5}, {'v': None}):
            self.assertIsNone(P.clean_snapshot(bad), repr(bad))
        self.assertIsNotNone(P.clean_snapshot({'v': 1}), 'a snapshot that names no place is one, every place of it not read')

    def test_a_place_that_is_missing_or_wrongly_shaped_is_not_read_and_ok_is_only_ever_true(self):
        got = P.clean_snapshot({'v': 1, 'run': 'x', 'winlogon': [], 'services': {'ok': 'yes', 'items': [['a', 'b', 'c']]}, 'tasks': {'ok': 1, 'items': []},
                                'startup': {'ok': True, 'items': 'nope'}})
        for cat in ('run', 'winlogon'):
            self.assertEqual(got[cat], {'ok': False, 'cut': False, 'items': []})
        self.assertFalse(got['services']['ok'])
        self.assertFalse(got['tasks']['ok'])
        self.assertEqual(got['startup'], {'ok': True, 'cut': False, 'items': []})

    def test_the_caps_and_a_list_over_one_are_marked_cut(self):
        for cat, cap in P.CAPS.items():
            if cat == 'winlogon':
                continue
            items = [['p', 'n%03d' % i, 'c'] for i in range(cap + 40)]
            got = P.clean_snapshot(snap_of(**{cat: items}))[cat]
            self.assertEqual((len(got['items']), got['cut']), (cap, True), cat)
            whole = P.clean_snapshot(snap_of(**{cat: items[:cap]}))[cat]
            self.assertEqual((len(whole['items']), whole['cut']), (cap, False), cat)
        flood = [['p', 'n%d' % i, ''] for i in range(100000)]
        started = time.time()
        got = P.clean_snapshot(snap_of(run=flood))['run']
        self.assertEqual((len(got['items']), got['cut']), (100, True))
        self.assertLess(time.time() - started, 2.0, 'a flood is read as far as it could matter and no further')
        self.assertTrue(P.clean_snapshot(snap_of(run={'ok': True, 'cut': True, 'items': []}))['run']['cut'], 'a host that says it cut a list is believed')

    def test_a_field_is_cut_and_a_hostile_one_loses_its_control_characters(self):
        got = P.clean_snapshot(snap_of(run=[['x' * 500, 'n' * 500, 'c' * 900]]))['run']['items'][0]
        self.assertEqual([len(f) for f in got], [120, 120, 240])
        evil = 'a' + chr(0) + 'b' + chr(27) + '[31m' + chr(10) + 'c' + chr(13) + chr(9) + 'd' + chr(0x85) + 'e' + chr(0x2028) + 'f' + chr(0x202e) + 'g' + chr(0x9b) + 'h' + chr(0x7f)
        got = P.clean_snapshot(snap_of(run=[['Run', evil, evil]]))['run']['items'][0]
        for field in got[1:]:
            self.assertEqual([c for c in field if ord(c) < 32 or 0x7f <= ord(c) <= 0x9f or c in chr(0x2028) + chr(0x202e)], [], repr(field))
            self.assertEqual(field, 'a b [31m c d e f g h')

    def test_a_row_that_is_not_an_entry_is_left_out(self):
        rows = [None, 5, 'run', [], ['only'], ['a', 'b', 'c', 'd'], ['a', None, 'c'], ['a', '', 'c'], ['a', '   ', 'c'], ['a', ['b'], 'c'], ['a', 'b', {'c': 1}],
                {'loc': 'Run', 'name': 'ok', 'data': 'd'}, ['Run', 'two texts'], ('Run', 'tuple', 'x')]
        got = P.clean_snapshot(snap_of(run=rows))['run']['items']
        self.assertEqual(got, [['Run', 'ok', 'd'], ['Run', 'tuple', 'x'], ['Run', 'two texts', '']])

    def test_winlogon_holds_the_shell_and_the_userinit_value_and_nothing_else(self):
        got = P.clean_snapshot(snap_of(winlogon=[['Winlogon', 'Shell', 'explorer.exe'], ['Winlogon', 'Userinit', 'u,'], ['Winlogon', 'Background', '0 0 0'],
                                                 ['Winlogon', 'shell', 'x']]))['winlogon']['items']
        self.assertEqual([e[1] for e in got], ['Shell', 'Userinit'])

    def test_a_password_in_a_command_line_is_replaced_and_the_name_stays(self):
        cases = {
            'tool.exe --password hunter2 --silent': 'tool.exe --password [REDACTED] --silent',
            'tool.exe /token:abc123 /q': 'tool.exe /token:[REDACTED] /q',
            'tool.exe -ApiKey=abc123': 'tool.exe -ApiKey=[REDACTED]',
            'tool.exe --client-secret "a b c" --x': 'tool.exe --client-secret [REDACTED] --x',
            'tool.exe password=hunter2': 'tool.exe password=[REDACTED]',
            'tool.exe --db "https://admin:s3cret@db.example/x"': 'tool.exe --db "https://admin:[REDACTED]@db.example/x"',
            'tool.exe --pwd=abc': 'tool.exe --pwd=[REDACTED]',
        }
        for text, want in cases.items():
            with self.subTest(text):
                self.assertEqual(P.redact_command(text), want)
                self.assertEqual(win._persist_command(text), want, 'the agent replaces it before it is sent')
        for fine in ('"C:\\Program Files\\Foo\\foo.exe" --silent --autostart', 'C:\\Tools\\password-manager\\pm.exe --start', 'C:\\Windows\\system32\\userinit.exe,',
                     'OneDrive.exe /background', 'tool.exe --author bob'):
            with self.subTest(fine):
                self.assertEqual(P.redact_command(fine), fine)
                self.assertEqual(win._persist_command(fine), fine)

    def test_the_agent_and_the_server_clean_a_text_the_same_way(self):
        """The two copies are given the same 6,000 generated texts (words, secrets, controls, separators, long runs) and must agree."""
        rnd = random.Random(8)
        words = ['--password', '/token:', '-ApiKey=', 'secret=', 'x', 'C:\\Users\\bob', ' ', '  ', '"q q"', "'s'", '://u:p@h/', 'abc', chr(0), chr(27), chr(0x85), chr(0x202e),
                 chr(0x2028), '\t', 'Auth', 'pwd:', '\\', '%TEMP%', 'é', '字']
        for _ in range(6000):
            text = ''.join(rnd.choice(words) for _ in range(rnd.randint(0, 25)))
            with self.subTest(text=text):
                self.assertEqual(win._persist_command(text), P.redact_command(P.clean_text(text, P.FIELD_MAX[2])))
                self.assertEqual(win._persist_text(text, 120), P.clean_text(text, 120))


# ── what counts as a change ──────────────────────────────────────────────────
class TestWhatIsAChange(unittest.TestCase):
    A = ['Run', 'OneDrive', '"C:\\Program Files\\OneDrive.exe" /background']
    B = ['Run', 'Updater', 'C:\\Users\\bob\\AppData\\Local\\Temp\\upd.exe']

    def apply(self, prev, snap, now=NOW):
        return P.apply_snapshot(prev, P.clean_snapshot(snap), now)

    def test_the_first_inventory_is_a_baseline_and_nothing_in_it_is_a_change(self):
        rec, added, removed = self.apply({}, snap_of(run=[self.A, self.B], tasks=[['\\', 'x', 'y']]))
        self.assertEqual((added, removed, rec['log']), ([], [], []))
        self.assertEqual((rec['baseline'], rec['ts'], rec['alert_ts']), (NOW, NOW, 0))
        self.assertEqual(entries(rec, 'run'), [tuple(self.A), tuple(self.B)])
        self.assertEqual(P.due_alert(rec, NOW), ([], []), 'a baseline never alerts')

    def test_what_is_new_is_logged_and_what_is_gone_is_logged_without_an_alert_flag_to_send(self):
        rec, *_ = self.apply({}, snap_of(run=[self.A]))
        rec, added, removed = self.apply(rec, snap_of(run=[self.B]), NOW + 900)
        self.assertEqual(([e for _c, e in added], [e for _c, e in removed]), ([self.B], [self.A]))
        log = rec['log']
        self.assertEqual([(e['op'], e['name'], e['alerted']) for e in log], [('added', 'Updater', False), ('removed', 'OneDrive', True)])
        self.assertEqual(rec['baseline'], NOW, 'the baseline stays the time of the first inventory')
        due, gone = P.due_alert(rec, NOW + 900)
        self.assertEqual([e['name'] for e in due], ['Updater'], 'only the added one is due an alert')

    def test_a_snapshot_that_holds_what_the_last_held_changes_nothing(self):
        rec, *_ = self.apply({}, snap_of(run=[self.A, self.B], startup=[['All users', 'x.lnk', '10 bytes']]))
        again, added, removed = self.apply(rec, snap_of(run=[self.A, self.B], startup=[['All users', 'x.lnk', '10 bytes']]), NOW + 900)
        self.assertEqual((added, removed, again['log']), ([], [], []))
        self.assertEqual(again['inv']['run']['ts'], NOW + 900)

    def test_a_command_that_was_changed_is_a_new_entry_beside_a_removed_one(self):
        shell = ['Winlogon', 'Shell', 'explorer.exe']
        rec, *_ = self.apply({}, snap_of(winlogon=[shell]))
        rec, added, removed = self.apply(rec, snap_of(winlogon=[['Winlogon', 'Shell', 'explorer.exe, C:\\Users\\Public\\x.exe']]), NOW + 900)
        self.assertEqual([e[2] for _c, e in added], ['explorer.exe, C:\\Users\\Public\\x.exe'])
        self.assertEqual([e[2] for _c, e in removed], ['explorer.exe'])
        self.assertEqual(len(P.due_alert(rec, NOW + 900)[0]), 1, 'a Shell that was pointed somewhere else alerts')

    def test_a_place_that_could_not_be_read_keeps_what_it_held_and_is_never_read_as_empty(self):
        rec, *_ = self.apply({}, snap_of(run=[self.A, self.B], tasks=[['\\', 't', 'c']]))
        rec, added, removed = self.apply(rec, snap_of(run={'ok': False, 'cut': False, 'items': []}, tasks=[['\\', 't', 'c']]), NOW + 900)
        self.assertEqual((added, removed, rec['log']), ([], [], []))
        self.assertEqual(entries(rec, 'run'), [tuple(self.A), tuple(self.B)])
        self.assertFalse(rec['inv']['run']['ok'])
        self.assertEqual(rec['inv']['run']['ts'], NOW, 'it says when it was last read')
        rec, added, removed = self.apply(rec, snap_of(run=[self.A, self.B], tasks=[['\\', 't', 'c']]), NOW + 1800)
        self.assertEqual((added, removed), ([], []), 'read again and unchanged: nothing happened while it could not be read')

    def test_a_place_never_read_whole_is_baselined_when_it_is_first_read_and_does_not_alert_then(self):
        rec, *_ = self.apply({}, snap_of(run=[self.A], tasks={'ok': False, 'cut': False, 'items': []}))
        rec, added, removed = self.apply(rec, snap_of(run=[self.A], tasks=[['\\', 'new', 'c'], ['\\', 'old', 'c']]), NOW + 900)
        self.assertEqual((added, removed, rec['log']), ([], [], []), 'the tasks were never read before: their first read is their baseline')
        rec, added, _ = self.apply(rec, snap_of(run=[self.A], tasks=[['\\', 'new', 'c'], ['\\', 'old', 'c'], ['\\', 'newer', 'c']]), NOW + 1800)
        self.assertEqual([e[1] for _c, e in added], ['newer'])

    def test_a_list_that_was_cut_is_not_compared_and_its_next_whole_read_is_a_new_baseline(self):
        many = [['p', 'n%03d' % i, ''] for i in range(130)]
        rec, *_ = self.apply({}, snap_of(run=many[:100]))
        rec, added, removed = self.apply(rec, snap_of(run=many), NOW + 900)             # 130 > the cap of 100: cut
        self.assertTrue(rec['inv']['run']['complete'] is False)
        self.assertEqual((added, removed), ([], []), 'the entries that fall at the edge of a cut list are not news')
        rec, added, removed = self.apply(rec, snap_of(run=many[:90]), NOW + 1800)       # whole again, 40 fewer than the cut list: nothing is "removed"
        self.assertEqual((added, removed, rec['log']), ([], [], []))
        self.assertTrue(rec['inv']['run']['complete'])

    def test_a_cut_list_is_not_compared_even_when_its_edge_moved_so_a_rotation_is_not_news(self):
        """130 entries cut at 100 keep the first 100 by name. Entries that sort before the old ones push others over the edge: one added and one gone for each of them, and all of it is only the edge."""
        old = [['p', 'n%03d' % i, ''] for i in range(100)]
        rec, *_ = self.apply({}, snap_of(run=old))
        shifted = [['p', 'a%03d' % i, ''] for i in range(30)] + old
        rec, added, removed = self.apply(rec, snap_of(run=shifted), NOW + 900)
        self.assertEqual((added, removed, rec['log']), ([], [], []))
        self.assertFalse(rec['inv']['run']['complete'])
        self.assertEqual(len(entries(rec, 'run')), 100)

    def test_a_new_layout_of_the_snapshot_starts_every_baseline_again(self):
        rec, *_ = self.apply({}, snap_of(run=[self.A]))
        rec['v'] = 0
        rec, added, removed = self.apply(rec, snap_of(run=[self.A, self.B]), NOW + 900)
        self.assertEqual((added, removed, rec['log']), ([], [], []))
        self.assertEqual(rec['v'], P.VERSION)

    def test_the_log_is_capped_and_one_snapshot_writes_at_most_fifty_of_each_kind(self):
        rec, *_ = self.apply({}, snap_of(run=[]))
        rec, added, removed = self.apply(rec, snap_of(run=[['Run', 'n%03d' % i, ''] for i in range(100)]), NOW + 900)
        self.assertEqual(len(added), 100)
        self.assertEqual(len(rec['log']), P.PER_SNAPSHOT_MAX)
        self.assertEqual(P.alert_payload([e for e in rec['log']])['count'], 50)
        for n in range(6):
            rec, *_ = self.apply(rec, snap_of(run=[['Run', 'g%d-%03d' % (n, i), ''] for i in range(60)]), NOW + 1800 + n * 900)
        self.assertEqual(len(rec['log']), P.LOG_MAX)

    def test_a_stored_record_of_the_wrong_kind_is_replaced_not_read(self):
        for bad in (None, [], 'x', {'inv': 'x', 'log': 'y', 'baseline': 'z', 'alert_ts': [], 'v': 1}, {'inv': {'run': 'x'}, 'log': [None, 3, {'op': 'added'}]}):
            rec, added, removed = self.apply(bad, snap_of(run=[self.A]))
            self.assertEqual((added, removed), ([], []), repr(bad))
            self.assertEqual(entries(rec, 'run'), [tuple(self.A)])
            self.assertTrue(all(isinstance(e, dict) for e in rec['log']))


class TestWhenAnAlertIsDue(unittest.TestCase):
    def rec_with(self, names, alert_ts=0, present=True):
        rec, *_ = P.apply_snapshot({}, P.clean_snapshot(snap_of(run=[])), NOW)
        rec, *_ = P.apply_snapshot(rec, P.clean_snapshot(snap_of(run=[['Run', n, 'c'] for n in names])), NOW + 60)
        rec['alert_ts'] = alert_ts
        return rec

    def test_the_hour_is_an_hour_and_the_logs_are_the_size_the_guide_says(self):
        self.assertEqual((P.ALERT_EVERY_S, P.LOG_MAX, P.PER_SNAPSHOT_MAX, P.SAMPLE_LINES), (3600, 200, 50, 3))
        self.assertEqual(P.CAPS, {'run': 100, 'winlogon': 4, 'services': 100, 'tasks': 200, 'startup': 100})
        self.assertEqual(win._PERSIST_CAPS, P.CAPS, 'the agent cuts where the server cuts')
        self.assertEqual((win._PERSIST_EVERY_S, win._PERSIST_FIELD_MAX), (900, P.FIELD_MAX))
        self.assertEqual(win._PERSIST_VERSION, P.VERSION)

    def test_a_new_entry_is_due_an_alert_and_marking_it_starts_the_hour(self):
        rec = self.rec_with(['a', 'b'])
        due, gone = P.due_alert(rec, NOW + 60)
        self.assertEqual(([e['name'] for e in due], gone), (['a', 'b'], []))
        P.mark_alerted(rec, due, gone, NOW + 60)
        self.assertEqual(rec['alert_ts'], NOW + 60)
        self.assertTrue(all(e['alerted'] for e in rec['log']))
        self.assertEqual(P.due_alert(rec, NOW + 120), ([], []), 'nothing unsent, nothing due')

    def test_inside_the_hour_nothing_is_due_and_what_arrived_goes_out_with_the_next_alert(self):
        rec = self.rec_with(['late'], alert_ts=NOW)
        self.assertEqual(P.due_alert(rec, NOW + P.ALERT_EVERY_S - 1), ([], []))
        due, gone = P.due_alert(rec, NOW + P.ALERT_EVERY_S)
        self.assertEqual([e['name'] for e in due], ['late'], 'the entry that came inside the hour is not lost')

    def test_an_unsent_entry_that_has_left_the_host_is_marked_and_never_alerts(self):
        rec = self.rec_with(['a', 'b'], alert_ts=NOW)
        rec['inv']['run']['items'] = [['Run', 'b', 'c']]            # 'a' is gone again
        due, gone = P.due_alert(rec, NOW + 10)                       # inside the hour
        self.assertEqual(([e['name'] for e in due], [e['name'] for e in gone]), ([], ['a']))
        P.mark_alerted(rec, due, gone, NOW + 10)
        self.assertEqual(rec['alert_ts'], NOW, 'nothing was sent, so the hour did not start again')
        due, gone = P.due_alert(rec, NOW + P.ALERT_EVERY_S)
        self.assertEqual([e['name'] for e in due], ['b'])

    def test_once_the_hour_is_over_the_entries_that_left_are_not_due_and_the_ones_that_stayed_are(self):
        rec = self.rec_with(['a', 'b'])
        rec['inv']['run']['items'] = [['Run', 'b', 'c']]
        due, gone = P.due_alert(rec, NOW + P.ALERT_EVERY_S + 100)
        self.assertEqual(([e['name'] for e in due], [e['name'] for e in gone]), (['b'], ['a']))

    def test_a_removed_entry_is_never_due_and_the_payload_says_how_many_and_what(self):
        rec = self.rec_with(['a'])
        rec['log'].append({'ts': NOW, 'op': 'removed', 'cat': 'run', 'loc': 'Run', 'name': 'old', 'data': '', 'alerted': True})
        due, _gone = P.due_alert(rec, NOW + 60)
        self.assertEqual([e['name'] for e in due], ['a'])
        mixed = [{'cat': 'run', 'name': 'a', 'data': 'c'}, {'cat': 'run', 'name': 'b', 'data': ''}, {'cat': 'tasks', 'name': 'T', 'data': 'x' * 400}, {'cat': 'services', 'name': 'S', 'data': 'y'}]
        payload = P.alert_payload(mixed)
        self.assertEqual(payload['count'], 4)
        self.assertEqual(payload['detail'], '4 new startup entries (2 Run keys, 1 service, 1 scheduled task)')
        self.assertEqual(len(payload['sample']), P.SAMPLE_LINES)
        self.assertEqual(payload['sample'][0], 'Run key: a = c')
        self.assertEqual(payload['sample'][1], 'Run key: b')
        self.assertLessEqual(len(payload['sample'][2]), P.SAMPLE_CHARS)
        self.assertEqual(P.alert_payload([mixed[0]])['detail'], '1 new startup entry (1 Run key)')

    def test_the_changes_are_newest_first_and_within_one_inventory_what_came_in_comes_before_what_went_out(self):
        rec, *_ = P.apply_snapshot({}, P.clean_snapshot(snap_of(run=[['Run', 'old1', ''], ['Run', 'old2', '']])), NOW)
        rec, *_ = P.apply_snapshot(rec, P.clean_snapshot(snap_of(run=[['Run', 'old2', ''], ['Run', 'new1', '']])), NOW + 900)        # new1 in, old1 out
        rec, *_ = P.apply_snapshot(rec, P.clean_snapshot(snap_of(run=[['Run', 'new1', ''], ['Run', 'new2', '']])), NOW + 1800)      # new2 in, old2 out
        got = [(c['ts'] - NOW, c['op'], c['name']) for c in P.view(rec)['changes']]
        self.assertEqual(got, [(1800, 'added', 'new2'), (1800, 'removed', 'old2'), (900, 'added', 'new1'), (900, 'removed', 'old1')])

    def test_the_page_is_given_the_inventory_by_place_and_the_changes_newest_first(self):
        rec = self.rec_with(['a', 'b'])
        v = P.view(rec)
        self.assertEqual(list(v['inventory']), list(P.CATEGORIES))
        self.assertEqual([c['name'] for c in v['changes']], ['b', 'a'])
        self.assertEqual(v['inventory']['run']['items'][0], {'loc': 'Run', 'name': 'a', 'data': 'c'})
        self.assertEqual((v['baseline'], v['ts'], v['alert_every_s']), (NOW, NOW + 60, P.ALERT_EVERY_S))
        for bad in (None, [], 'x', {}, {'inv': 'x'}):
            self.assertIsNone(P.view(bad), repr(bad))
        garbage = {'inv': {'run': {'items': [None, ['a'], ['p', 'n', 'd']], 'ts': 'x'}}, 'log': [None, {'ts': 'x', 'op': 'weird', 'cat': 'nope', 'name': None}], 'ts': True}
        v = P.view(garbage)
        self.assertEqual(v['inventory']['run']['items'], [{'loc': 'p', 'name': 'n', 'data': 'd'}])
        self.assertEqual(v['changes'], [{'ts': 0, 'op': 'added', 'cat': 'run', 'loc': '', 'name': '', 'data': '', 'alerted': False}])
        self.assertEqual(v['ts'], 0)


# ── the agent ────────────────────────────────────────────────────────────────
class TestTheAgentReadsFivePlaces(unittest.TestCase):
    def setUp(self):
        self.reg = hardened_registry()
        self.folders = Folders()
        self.addCleanup(self.folders.remove)

    def snap(self, **kw):
        return win.collect_persistence(wr=kw.get('reg', self.reg), run=lambda args, timeout: kw.get('tasks', schtasks_output()), env=self.folders.env())

    def test_the_run_keys_are_read_in_both_views_and_a_value_is_text_whatever_its_type(self):
        run = self.snap()['run']
        self.assertEqual((run['ok'], run['cut']), (True, False))
        got = {(p, n): d for p, n, d in run['items']}
        self.assertEqual(got[('Run', 'SecurityHealth')], '%windir%\\system32\\SecurityHealthSystray.exe')
        self.assertIn('RtkAudUService64.exe" -background', got[('Run', 'RtkAudUService')])
        self.assertEqual(got[('Run (32-bit)', 'OneDriveSetup')], '"C:\\Windows\\SysWOW64\\OneDriveSetup.exe" /thfirstsetup')
        self.assertEqual(got[('Run', 'Chunk')], 'binary, 3 bytes', 'a binary value is never sent as its bytes')
        self.assertEqual(got[('Run', 'Flags')], '7')
        self.assertEqual(len(run['items']), 5, 'RunOnce is empty and the 32-bit RunOnce does not exist: both hold nothing')

    def test_only_read_access_is_asked_for_and_nothing_is_written(self):
        self.snap()
        self.assertEqual(self.reg.touched, [])
        self.assertTrue(self.reg.opened)
        allowed = FakeRegistry.KEY_READ | FakeRegistry.KEY_WOW64_64KEY | FakeRegistry.KEY_WOW64_32KEY
        for path, access in self.reg.opened:
            self.assertEqual(access & ~allowed, 0, (path, hex(access)))
            self.assertEqual(access & FakeRegistry.KEY_READ, FakeRegistry.KEY_READ, 'every key is opened with read access: %s' % path)
        views = {(p, bool(a & FakeRegistry.KEY_WOW64_32KEY)) for p, a in self.reg.opened if p in (RUN, RUNONCE)}
        self.assertEqual(views, {(RUN, False), (RUN, True), (RUNONCE, False), (RUNONCE, True)})

    def test_winlogon_reads_the_shell_and_userinit_and_nothing_else(self):
        w = self.snap()['winlogon']
        self.assertEqual(w, {'ok': True, 'cut': False, 'items': [['Winlogon', 'Shell', 'explorer.exe'], ['Winlogon', 'Userinit', 'C:\\Windows\\system32\\userinit.exe,']]})
        self.reg.keys[64][WINLOGON.lower()]['values'] = [('Userinit', 'C:\\Windows\\system32\\userinit.exe,', S)]      # no Shell: it is not an entry
        self.assertEqual([e[1] for e in self.snap()['winlogon']['items']], ['Userinit'])

    def test_services_are_the_ones_that_run_from_a_temporary_or_user_folder_by_path_alone(self):
        s = self.snap()['services']
        self.assertEqual((s['ok'], s['cut']), (True, False))
        self.assertEqual({e[1]: e[2] for e in s['items']}, {
            'DriverX': '\\??\\C:\\Windows\\Temp\\x.sys', 'UsesVar': '%TEMP%\\u.exe', 'Updater': 'C:\\Users\\bob\\AppData\\Local\\Temp\\upd.exe -k run'})
        self.assertTrue(all(e[0] == 'Service' for e in s['items']))

    def test_the_path_rule_in_a_table(self):
        env = self.folders.env()
        yes = ['C:\\Users\\bob\\x.exe', '"C:\\Users\\Public\\p.exe" -x', 'C:\\Windows\\Temp\\a.exe', 'c:\\windows\\temp\\a.exe', 'C:\\Windows\\TEMP\\a.exe /c',
               'C:\\Users\\bob\\AppData\\Roaming\\x\\y.exe', '%TEMP%\\u.exe', '%tmp%\\u.exe', '%USERPROFILE%\\u.exe', '%AppData%\\x', '%LOCALAPPDATA%\\x', '%PUBLIC%\\x',
               '%SystemRoot%\\Temp\\x.exe', 'D:\\Documents and Settings\\bob\\x.exe', 'C:\\$Recycle.Bin\\S-1-5\\x.exe', '\\??\\C:\\Windows\\Temp\\x.sys',
               'C:/Users/bob/x.exe', 'cmd /c C:\\Users\\bob\\x.bat']
        no = ['C:\\Windows\\System32\\svchost.exe -k netsvcs', '%SystemRoot%\\System32\\spoolsv.exe', '"C:\\Program Files\\Foo\\foo.exe"', 'C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe /c',
              '"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe"', 'C:\\Windows\\system32\\userinit.exe,', 'explorer.exe', '', None,
              'C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\OfficeClickToRun.exe /service']
        for t in yes:
            self.assertTrue(win._persist_user_path(t, env), t)
        for t in no:
            self.assertFalse(win._persist_user_path(t, env), repr(t))

    def test_scheduled_tasks_that_are_not_microsofts_with_their_folder_name_and_action(self):
        t = self.snap()['tasks']
        self.assertEqual((t['ok'], t['cut']), (True, False))
        got = {(f, n): d for f, n, d in t['items']}
        self.assertEqual(got[('\\', 'GoogleUpdateTaskMachineCore{8A69D345-D564-463C-AFF1-A69D9E530F96}')], '"C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe" /c')
        self.assertEqual(got[('\\', 'Updater')], 'C:\\Users\\bob\\AppData\\Local\\Temp\\upd.exe -k run')
        self.assertEqual(got[('\\Vendor\\Agent', 'ComTask')], 'COM handler {DEADBEEF-0000-0000-0000-000000000002}')
        self.assertEqual(got[('\\Microsoft\\Windows\\Maintenance', 'SystemCare')], 'C:\\Users\\Public\\care.exe --quiet')
        names = {n for _f, n in got}
        self.assertNotIn('ScheduledDefrag', names, "Microsoft's own task is not listed")
        self.assertNotIn('Scheduled Start', names)
        self.assertNotIn('WinSAT', names)
        self.assertNotIn('Disabled', names, 'a disabled task starts nothing')
        self.assertEqual(len(got), 5)

    def test_the_same_tasks_are_read_from_a_wrapped_document_and_from_utf16_bytes(self):
        plain = {(f, n, d) for f, n, d in self.snap()['tasks']['items']}
        self.assertEqual({(f, n, d) for f, n, d in self.snap(tasks=schtasks_output(wrapper=True))['tasks']['items']}, plain)
        raw = schtasks_output().encode('utf-16')                      # what a pipe may carry: UTF-16 with a byte order mark
        with mock.patch.object(win.subprocess, 'run', return_value=mock.Mock(returncode=0, stdout=raw)):
            text = win._persist_run_command(['schtasks'], 5)
        self.assertEqual({(f, n, d) for f, n, d in self.snap(tasks=text)['tasks']['items']}, plain)
        raw8 = schtasks_output().replace('UTF-16', 'UTF-8').encode('utf-8')
        with mock.patch.object(win.subprocess, 'run', return_value=mock.Mock(returncode=0, stdout=raw8)):
            self.assertEqual({(f, n, d) for f, n, d in self.snap(tasks=win._persist_run_command(['schtasks'], 5))['tasks']['items']}, plain)

    def test_a_task_written_to_be_unreadable_is_still_listed(self):
        evil = (task_xml('\\Odd', 'C:\\Users\\bob\\x.exe', None).replace('<Command>', '<Comm' + 'and note="a"><!-- c --><![CDATA[').replace('</Command>', ']]></Command>')
                .replace('<URI>\\Odd</URI>', '<URI>\\Odd</URI><Bad & stuff>'))
        got = win._persist_parse_tasks(evil, self.folders.env())
        self.assertEqual([(f, n) for f, n, _d in got[0]], [('\\', 'Odd')], 'a task that does not parse is read field by field and not dropped')
        ctl = win._persist_parse_tasks(task_xml('\\Ctl' + chr(0) + 'x' + chr(27), 'C:\\Users\\a.exe', None), self.folders.env())[0]
        self.assertEqual(ctl[0][1], 'Ctl x', 'control characters in a name become a space')
        bomb = ('<?xml version="1.0"?><!DOCTYPE t [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>' +
                task_xml('\\Bomb', 'C:\\Users\\bob\\&b;.exe', None, declaration=False))
        started = time.time()
        got = win._persist_parse_tasks(bomb, self.folders.env())[0]
        self.assertLess(time.time() - started, 2.0)
        self.assertEqual([n for _f, n, _d in got], ['Bomb'])
        self.assertNotIn('aaaaaaaaaaaaaaaaaaaa', repr(got), 'a declared entity is not expanded')

    def test_startup_folders_list_the_files_of_all_users_and_each_profile_with_their_size(self):
        s = self.snap()['startup']
        self.assertEqual((s['ok'], s['cut']), (True, False))
        self.assertEqual(sorted(s['items']), sorted([['All users', 'OneNote.lnk', '1893 bytes'], ['User bob', 'evil.lnk', '700 bytes']]))
        self.assertFalse([e for e in s['items'] if e[1].lower() == 'desktop.ini'])
        (self.folders.startup('alice')).mkdir(parents=True)
        (self.folders.startup('alice') / 'x.lnk').write_bytes(b'x')
        (self.folders.startup('bob') / 'sub').mkdir()
        got = {(p, n): d for p, n, d in self.snap()['startup']['items']}
        self.assertEqual(got[('User alice', 'x.lnk')], '1 bytes')
        self.assertEqual(got[('User bob', 'sub\\')], '', 'a folder is listed by its name with a backslash and has no size')
        (self.folders.startup('bob') / 'evil.lnk').write_bytes(b'x' * 701)
        self.assertEqual({(p, n): d for p, n, d in self.snap()['startup']['items']}[('User bob', 'evil.lnk')], '701 bytes', 'a replaced file shows as another entry')
        self.assertNotIn('User Public', {p for p, _n, _d in self.snap()['startup']['items']})

    def test_a_missing_key_holds_nothing_but_a_key_that_cannot_be_read_is_not_read(self):
        reg = hardened_registry()
        del reg.keys[32][RUN.lower()]
        self.assertTrue(self.snap(reg=reg)['run']['ok'], 'a key that is not there holds nothing')
        reg.deny.add((64, RUN.lower()))
        run = self.snap(reg=reg)['run']
        self.assertFalse(run['ok'], 'access denied is not an empty list')
        reg = hardened_registry()
        reg.enum_fail[(64, RUN.lower())] = (1, OSError(5, 'Access is denied'))
        self.assertFalse(self.snap(reg=reg)['run']['ok'], 'a read that failed half way is not read whole')
        reg = hardened_registry()
        reg.deny.add((64, SERVICES.lower()))
        self.assertEqual(self.snap(reg=reg)['services'], {'ok': False, 'cut': False, 'items': []})
        reg = hardened_registry()
        reg.enum_fail[(64, SERVICES.lower())] = (2, OSError(5, 'Access is denied'))
        self.assertFalse(self.snap(reg=reg)['services']['ok'], 'a list of services that stopped half way is not read whole')
        reg = hardened_registry()
        reg.deny.add((64, WINLOGON.lower()))
        self.assertFalse(self.snap(reg=reg)['winlogon']['ok'])

    def test_schtasks_that_fails_or_says_nothing_readable_is_not_read_and_a_host_with_no_task_is_not_the_answer(self):
        for answer in (None, '', 'ERROR: Access is denied.', '<Tasks></Tasks>', 'not xml'):
            t = self.snap(tasks=answer)['tasks']
            self.assertEqual(t, {'ok': False, 'cut': False, 'items': []}, repr(answer))
        t = win._persist_task_items(lambda args, timeout: None, time.time() + 30, self.folders.env())
        self.assertFalse(t['ok'])
        with mock.patch.object(win.subprocess, 'run', side_effect=OSError('no such file')):
            self.assertIsNone(win._persist_run_command(['schtasks'], 5))
        with mock.patch.object(win.subprocess, 'run', side_effect=subprocess.TimeoutExpired('schtasks', 5)):
            self.assertIsNone(win._persist_run_command(['schtasks'], 5))
        with mock.patch.object(win.subprocess, 'run', return_value=mock.Mock(returncode=1, stdout=b'<Task/>')):
            self.assertIsNone(win._persist_run_command(['schtasks'], 5))

    def test_a_probe_that_raises_is_a_place_that_was_not_read_and_the_others_are_read(self):
        with mock.patch.object(win, '_persist_winlogon_items', side_effect=RuntimeError('boom')):
            snap = self.snap()
        self.assertEqual(snap['winlogon'], {'ok': False, 'cut': False, 'items': []})
        self.assertTrue(snap['run']['ok'] and snap['startup']['ok'])
        no_registry = win.collect_persistence(wr=None, run=lambda a, t: schtasks_output(), env=self.folders.env())
        with mock.patch.dict(sys.modules, {'winreg': None}):
            no_registry = win.collect_persistence(run=lambda a, t: schtasks_output(), env=self.folders.env())
        self.assertFalse(any(no_registry[c]['ok'] for c in ('run', 'winlogon', 'services')), 'without a registry the registry places are not read')
        self.assertTrue(no_registry['tasks']['ok'] and no_registry['startup']['ok'])

    def test_the_time_budget_leaves_the_places_that_got_no_turn_not_read(self):
        snap = win.collect_persistence(wr=self.reg, run=lambda a, t: schtasks_output(), env=self.folders.env(), budget=-1)
        self.assertFalse(any(snap[c]['ok'] for c in ('run', 'services', 'tasks', 'startup')), snap)
        self.assertEqual(snap['v'], win._PERSIST_VERSION)

    def test_the_lists_are_cut_at_their_caps_and_marked(self):
        reg = hardened_registry()
        reg.add(RUN, [('v%03d' % i, 'C:\\Program Files\\a%d.exe' % i, S) for i in range(130)])
        subs = ['s%03d' % i for i in range(150)]
        reg.add(SERVICES, subkeys=subs)
        for s in subs:
            reg.add(SERVICES + '\\' + s, [('ImagePath', 'C:\\Users\\bob\\%s.exe' % s, S)])
        tasks = '\n'.join(task_xml('\\V\\t%03d' % i, 'C:\\V\\t%d.exe' % i) for i in range(260))
        snap = self.snap(reg=reg, tasks=tasks)
        for cat, cap in (('run', 100), ('services', 100), ('tasks', 200)):
            self.assertTrue(snap[cat]['cut'], cat)
            self.assertEqual(len(snap[cat]['items']), cap + 1, cat + ': one more than the cap, so the server can tell a cut list from a full one')
            cleaned = P.clean_snapshot(snap)[cat]
            self.assertEqual((len(cleaned['items']), cleaned['cut']), (cap, True), cat)
        for i in range(60):
            (self.folders.startup('bob') / ('f%02d.lnk' % i)).write_bytes(b'x')
        self.assertFalse(self.snap()['startup']['ok'], 'a folder with more files than it may hold is not read whole')

    def test_what_the_agent_sends_is_what_the_server_reads_without_changing_it(self):
        snap = self.snap()
        got = P.clean_snapshot(snap)
        for cat in P.CATEGORIES:
            self.assertTrue(got[cat]['ok'], cat)
            self.assertEqual(sorted(got[cat]['items']), sorted(snap[cat]['items']), cat + ': the agent already sent what the server keeps')
        self.assertEqual(json.loads(json.dumps(snap)), snap)
        self.assertLess(len(json.dumps(snap)), 20000, 'a host like this one sends a few kilobytes')

    def test_a_secret_in_a_command_line_is_replaced_before_it_leaves_the_host(self):
        reg = hardened_registry()
        reg.add(RUN, [('Backup', 'C:\\Tools\\backup.exe --password hunter2 --target \\\\nas\\x', S), ('Sync', 'sync.exe "https://bob:p4ss@cloud.example/x"', S)])
        run = self.snap(reg=reg)['run']['items']
        text = json.dumps(run)
        for secret in ('hunter2', 'p4ss'):
            self.assertNotIn(secret, text)
        self.assertIn('[REDACTED]', text)


class TestHowOften(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='rp-persist-ts-')
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))
        self.calls = []
        patches = [mock.patch.object(win, '_data_dir', lambda: self.dir),
                   mock.patch.object(win, 'collect_persistence', lambda *a, **k: self.calls.append(1) or {'v': 1})]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_the_first_check_in_takes_a_snapshot_and_the_next_ones_within_15_minutes_do_not(self):
        self.assertEqual(win.collect_persistence_if_due(), {'v': 1})
        self.assertEqual(win.collect_persistence_if_due(), None)
        self.assertEqual(win.collect_persistence_if_due(), None)
        self.assertEqual(len(self.calls), 1)

    def test_it_is_due_again_after_15_minutes_and_the_time_is_kept_on_disk_for_a_restart(self):
        win.collect_persistence_if_due()
        path = Path(self.dir, win._PERSIST_TS_FILE)
        self.assertTrue(path.exists())
        path.write_text(str(time.time() - 899))
        self.assertIsNone(win.collect_persistence_if_due())
        path.write_text(str(time.time() - 901))
        self.assertEqual(win.collect_persistence_if_due(), {'v': 1})
        self.assertEqual(len(self.calls), 2)

    def test_a_missing_or_corrupt_time_file_is_due_and_the_time_is_written_after_the_snapshot(self):
        Path(self.dir, win._PERSIST_TS_FILE).write_text('not a number')
        self.assertEqual(win.collect_persistence_if_due(), {'v': 1})
        self.assertGreater(float(Path(self.dir, win._PERSIST_TS_FILE).read_text()), time.time() - 5)
        with mock.patch.object(win, 'collect_persistence', side_effect=RuntimeError('boom')):
            Path(self.dir, win._PERSIST_TS_FILE).write_text('0')
            with self.assertRaises(RuntimeError):
                win.collect_persistence_if_due()
            self.assertEqual(Path(self.dir, win._PERSIST_TS_FILE).read_text(), '0', 'a snapshot that failed is made again at the next check-in')

    def test_the_heartbeat_carries_the_snapshot_under_sysinfo_when_due_and_never_fails_for_it(self):
        creds = {'device_id': 'w', 'token': 't', 'server_url': 'https://x'}
        with mock.patch.object(win, 'collect_sysinfo', side_effect=lambda: {'hostname': 'W'}), mock.patch.object(win, 'get_event_log_journal', return_value=[]), \
                mock.patch.object(win, 'get_local_accounts', return_value=[]), mock.patch.object(win, 'get_smart_status', return_value=None), \
                mock.patch.object(win, 'get_hardware_inventory', return_value=None), mock.patch.object(win, 'get_containers', return_value=[]), \
                mock.patch.object(win, 'get_gpu_status', return_value=[]), mock.patch.object(win, 'get_defender_status', return_value=None), \
                mock.patch.object(win, 'get_top_processes', return_value=([], [])):
            payload = win.build_heartbeat(creds, 1)
            self.assertEqual(payload['sysinfo']['persistence'], {'v': 1})
            payload = win.build_heartbeat(creds, 12)                  # a later sysinfo check-in inside the 15 minutes
            self.assertNotIn('persistence', payload['sysinfo'])
            Path(self.dir, win._PERSIST_TS_FILE).write_text('0')
            with mock.patch.object(win, 'collect_persistence_if_due', side_effect=RuntimeError('boom')):
                payload = win.build_heartbeat(creds, 24)
            self.assertIn('sysinfo', payload)
            self.assertNotIn('persistence', payload['sysinfo'])


# ── the server ───────────────────────────────────────────────────────────────
class _Server(unittest.TestCase):
    STORES = ('CONFIG_FILE', 'USERS_FILE', 'TENANTS_FILE', 'DEVICES_FILE', 'ALERTS_FILE', 'FLEET_EVENTS_FILE', 'PERSISTENCE_FILE', 'AUDIT_LOG_FILE', 'ALERT_MUTES_FILE')
    FNS = ('respond', 'method', 'get_json_obj', 'get_json_body', 'audit_log', 'get_token_from_request', 'verify_token', 'path_info')

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix='rp-persist-srv-'))
        self.addCleanup(lambda: shutil.rmtree(self.d, ignore_errors=True))
        self._saved = {n: getattr(api, n) for n in self.STORES if hasattr(api, n)}
        for n, v in self._saved.items():
            setattr(api, n, self.d / v.name)
        self._data_dir = api.DATA_DIR              # the host purge reads the stores it names from DATA_DIR itself
        api.DATA_DIR = self.d
        self._fns = {n: getattr(api, n) for n in self.FNS}
        self.cap, self.body, self.m, self.who = {}, {}, 'POST', 'platform'

        def _respond(status, data=None):
            self.cap['status'], self.cap['data'] = status, data
            raise api.HTTPError(status, data)
        api.respond = _respond
        api.method = lambda: self.m
        api.get_json_obj = lambda: dict(self.body)
        api.get_json_body = lambda: dict(self.body)
        api.audit_log = lambda *a, **k: None
        api.get_token_from_request = lambda: 'tok'
        api.verify_token = lambda _t=None: ((self.who, (api._load_ro(api.USERS_FILE) or {}).get(self.who, {}).get('role')) if self.who else (None, None))
        now = int(time.time())
        mk = lambda name, os_, tenant='default', **kw: dict({'name': name, 'hostname': name, 'os': os_, 'token': 'tok-' + name, 'last_seen': now, 'enrolled': now, 'tags': [],
                                                           'group': '', 'sysinfo': {}, 'agentless': False, 'tenant': tenant}, **kw)
        api.save(api.TENANTS_FILE, {'default': {'name': 'Default', 'status': 'active', 'builtin': True}, 'tenantB': {'name': 'B', 'status': 'active'}})
        api.save(api.USERS_FILE, {'platform': {'role': 'admin', 'tenant_id': 'default'}, 'badmin': {'role': 'admin', 'tenant_id': 'tenantB'},
                                  'viewer1': {'role': 'viewer', 'tenant_id': 'default'}, 'viewerB': {'role': 'viewer', 'tenant_id': 'tenantB'}})
        api.save(api.DEVICES_FILE, {'win1': mk('win1', 'Windows 11 Pro'), 'win2': mk('win2', 'Windows Server 2022'), 'lin1': mk('lin1', 'Debian GNU/Linux 12'),
                                    'winB': mk('winB', 'Windows 11 Pro', tenant='tenantB'), 'winOff': mk('winOff', 'Windows 10 Pro', monitored=False)})
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()
        self.fired = []
        self._fire = api.fire_webhook
        api.fire_webhook = lambda event, payload: self.fired.append((event, dict(payload)))
        self.addCleanup(lambda: setattr(api, 'fire_webhook', self._fire))

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(api, n, v)
        api.DATA_DIR = self._data_dir
        for n, v in self._fns.items():
            setattr(api, n, v)
        api._LOAD_CACHE.clear()

    def call(self, fn, *args, body=None, m='GET', who='platform'):
        self.who, self.body, self.m = who, dict(body or {}), m
        self.cap.clear()
        api._LOAD_CACHE.clear()
        try:
            fn(*args)
        except (api.HTTPError, SystemExit):
            pass
        api._LOAD_CACHE.clear()
        data = self.cap.get('data')
        return self.cap.get('status'), ({} if data is None else data)

    def beat(self, dev_id, snap=None, extra=None):
        si = {} if snap is None else {'persistence': snap}
        si.update(extra or {})
        return self.call(api.handle_heartbeat, m='POST', body={'device_id': dev_id, 'token': 'tok-' + dev_id, 'sysinfo': si})

    def stored(self, dev_id):
        return api._entity_read_one(api.PERSISTENCE_FILE, dev_id, None)

    def alerts(self, dev_id=None):
        rows = (api.load(api.ALERTS_FILE) or {}).get('alerts', [])
        return [a for a in rows if a.get('event') == 'persistence_added' and (dev_id is None or a['payload'].get('device_id') == dev_id)]


A = ['Run', 'OneDrive', '"C:\\Program Files\\OneDrive.exe" /background']
B = ['Run', 'Updater', 'C:\\Users\\bob\\AppData\\Local\\Temp\\upd.exe']
C = ['\\', 'Backdoor', 'C:\\Users\\Public\\b.exe']


class TestFromTheHeartbeatToTheAlert(_Server):
    def test_the_first_inventory_is_stored_and_never_alerts_and_the_next_one_with_a_new_entry_alerts_once(self):
        st, resp = self.beat('win1', snap_of(run=[A, B], tasks=[C]))
        self.assertEqual(st, 200, resp)
        self.assertEqual(self.fired, [])
        rec = self.stored('win1')
        self.assertEqual((entries(rec, 'run'), rec['log']), ([tuple(A), tuple(B)], []))
        self.assertNotIn('persistence', api.load(api.DEVICES_FILE)['win1']['sysinfo'], 'the inventory is not kept in the devices store')
        self.beat('win1', snap_of(run=[A, B], tasks=[C, ['\\', 'Second', 'x']]))
        self.assertEqual(len(self.fired), 1)
        event, payload = self.fired[0]
        self.assertEqual(event, 'persistence_added')
        self.assertEqual((payload['device_id'], payload['name'], payload['count']), ('win1', 'win1', 1))
        self.assertEqual(payload['detail'], '1 new startup entry (1 scheduled task)')
        self.assertEqual(payload['sample'], ['Scheduled task: Second = x'])
        self.assertTrue(all(e['alerted'] for e in self.stored('win1')['log']))

    def test_the_alert_reaches_the_inbox_through_the_real_event_machinery(self):
        api.fire_webhook = self._fire
        self.beat('win1', snap_of(run=[A]))
        self.beat('win1', snap_of(run=[A, B, C]))
        (alert,) = self.alerts('win1')
        self.assertEqual((alert['severity'], alert['payload']['count']), ('medium', 2))
        self.assertEqual(alert['title'], 'New startup entries on win1')
        self.assertEqual(alert['payload']['sample'], ['Run key: Backdoor = C:\\Users\\Public\\b.exe', 'Run key: Updater = C:\\Users\\bob\\AppData\\Local\\Temp\\upd.exe'])
        feed = [e for e in (api.load(api.FLEET_EVENTS_FILE) or {}).get('events', []) if e['event'] == 'persistence_added']
        self.assertEqual(len(feed), 1)
        self.assertEqual(feed[0]['payload']['count'], 2, 'the activity feed keeps the count')
        self.assertEqual(feed[0]['payload']['detail'], '2 new startup entries (2 Run keys)')
        self.assertTrue(feed[0]['payload']['sample'])

    def test_one_alert_an_hour_and_what_came_inside_it_goes_out_with_the_next(self):
        self.beat('win1', snap_of(run=[A]))
        self.beat('win1', snap_of(run=[A, B]))
        self.assertEqual(len(self.fired), 1)
        self.beat('win1', snap_of(run=[A, B, C]))                          # a moment later: inside the hour
        self.assertEqual(len(self.fired), 1, 'rate limited')
        self.assertEqual([e['alerted'] for e in self.stored('win1')['log']], [True, False])
        rec = self.stored('win1')
        rec['alert_ts'] -= 3601
        api._entity_write_one(api.PERSISTENCE_FILE, 'win1', rec)
        self.beat('win1', snap_of(run=[A, B, C]))                         # nothing new, the hour is over
        self.assertEqual(len(self.fired), 2)
        self.assertEqual(self.fired[1][1]['count'], 1)
        self.assertEqual(self.fired[1][1]['sample'], ['Run key: Backdoor = C:\\Users\\Public\\b.exe'], 'only the entry that was waiting, not the one already sent')

    def test_a_removed_entry_is_logged_and_does_not_alert(self):
        self.beat('win1', snap_of(run=[A, B]))
        self.beat('win1', snap_of(run=[A]))
        self.assertEqual(self.fired, [])
        self.assertEqual([(e['op'], e['name']) for e in self.stored('win1')['log']], [('removed', 'Updater')])

    def test_a_place_that_could_not_be_read_is_not_a_removal_and_is_marked(self):
        self.beat('win1', snap_of(run=[A, B], tasks=[C]))
        self.beat('win1', snap_of(run=[A, B], tasks={'ok': False, 'cut': False, 'items': []}))
        rec = self.stored('win1')
        self.assertEqual((rec['log'], entries(rec, 'tasks'), rec['inv']['tasks']['ok']), ([], [tuple(C)], False))

    def test_a_snapshot_that_is_not_one_changes_nothing_and_does_not_fail_the_heartbeat(self):
        self.beat('win1', snap_of(run=[A]))
        before = self.stored('win1')
        for bad in ('x', 5, [], {'v': 2}, {'v': 1, 'run': 'x'}):
            st, resp = self.beat('win1', bad)
            self.assertEqual(st, 200, repr(bad))
        after = self.stored('win1')
        self.assertEqual(entries(after, 'run'), entries(before, 'run'))
        self.assertEqual(self.fired, [])

    def test_the_word_of_a_host_that_is_not_a_windows_one_is_not_read(self):
        st, resp = self.beat('lin1', snap_of(run=[A]))
        self.assertEqual(st, 200, resp)
        self.assertIsNone(self.stored('lin1'))

    def test_a_host_that_is_not_monitored_keeps_an_inventory_and_raises_nothing_in_the_inbox(self):
        api.fire_webhook = self._fire
        self.beat('winOff', snap_of(run=[A]))
        self.beat('winOff', snap_of(run=[A, B]))
        self.assertIsNotNone(self.stored('winOff'))
        self.assertEqual(self.alerts('winOff'), [], 'monitored=false means collect and do not bother')

    def test_a_mute_for_the_host_and_the_event_silences_the_inbox_but_not_the_log_or_the_feed(self):
        api.fire_webhook = self._fire
        api.save(api.CONFIG_FILE, {})
        self.assertTrue(hasattr(api, '_alert_mute_set'))
        with mock.patch.object(api, '_alert_mute_set', lambda: {('win1', 'persistence_added')}):
            self.beat('win1', snap_of(run=[A]))
            self.beat('win1', snap_of(run=[A, B]))
        self.assertEqual(self.alerts('win1'), [])
        self.assertEqual([e['name'] for e in self.stored('win1')['log']], ['Updater'])
        feed = [e for e in (api.load(api.FLEET_EVENTS_FILE) or {}).get('events', []) if e['event'] == 'persistence_added']
        self.assertEqual(len(feed), 1, 'a mute silences the paging channels, the history stays')

    def test_the_write_is_checked_before_the_alert_goes_out_so_a_skipped_write_alerts_once_later(self):
        self.beat('win1', snap_of(run=[A]))
        real = api._entity_write_one
        with mock.patch.object(api, '_entity_write_one', lambda *a, **k: None):            # the write is skipped under lock contention
            self.beat('win1', snap_of(run=[A, B]))
        self.assertEqual(self.fired, [], 'an alert for a row that was not kept would be sent twice')
        self.assertEqual(self.stored('win1')['log'], [])
        api._entity_write_one = real
        self.beat('win1', snap_of(run=[A, B]))
        self.assertEqual(len(self.fired), 1, 'the same new entry shows again at the next snapshot')

    def test_the_real_agent_snapshot_goes_through_the_real_heartbeat(self):
        folders = Folders()
        self.addCleanup(folders.remove)
        reg = hardened_registry()
        first = win.collect_persistence(wr=reg, run=lambda a, t: schtasks_output(), env=folders.env())
        st, resp = self.beat('win2', first)
        self.assertEqual(st, 200, resp)
        self.assertEqual(self.fired, [])
        rec = self.stored('win2')
        self.assertEqual(sum(len(rec['inv'][c]['items']) for c in P.CATEGORIES), 5 + 2 + 3 + 5 + 2)
        self.assertTrue(all(rec['inv'][c]['ok'] and rec['inv'][c]['complete'] for c in P.CATEGORIES))
        reg.add(RUN, reg.keys[64][RUN.lower()]['values'] + [('Persist', 'C:\\Users\\bob\\AppData\\Roaming\\p.exe --password hunter2', S)])
        (folders.startup('alice')).mkdir(parents=True)
        (folders.startup('alice') / 'x.lnk').write_bytes(b'x')
        second = win.collect_persistence(wr=reg, run=lambda a, t: schtasks_output() + task_xml('\\Fresh', 'C:\\Users\\bob\\f.exe', None), env=folders.env())
        self.beat('win2', second)
        (_event, payload), = self.fired
        self.assertEqual(payload['count'], 3)
        self.assertEqual(payload['detail'], '3 new startup entries (1 Run key, 1 scheduled task, 1 startup folder file)')
        self.assertNotIn('hunter2', json.dumps(self.stored('win2')))
        self.assertNotIn('hunter2', json.dumps(self.fired))
        self.assertIn('[REDACTED]', json.dumps(self.stored('win2')['log']))


class TestThePageOfAHost(_Server):
    def get(self, dev_id, who='platform'):
        return self.call(api.handle_device_persistence, dev_id, who=who)

    def test_a_host_with_an_inventory_is_given_it_and_a_host_without_is_given_null(self):
        st, d = self.get('win1')
        self.assertEqual((st, d['persistence'], d['windows']), (200, None, True))
        self.beat('win1', snap_of(run=[A], startup=[['All users', 'x.lnk', '3 bytes']]))
        self.beat('win1', snap_of(run=[A, B], startup=[['All users', 'x.lnk', '3 bytes']]))
        st, d = self.get('win1')
        self.assertEqual(st, 200)
        p = d['persistence']
        self.assertEqual([(c['op'], c['name']) for c in p['changes']], [('added', 'Updater')])
        self.assertEqual([e['name'] for e in p['inventory']['run']['items']], ['OneDrive', 'Updater'])
        self.assertEqual(sorted(p), ['alert_every_s', 'baseline', 'changes', 'inventory', 'ts'])
        st, d = self.get('lin1')
        self.assertEqual((st, d['persistence'], d['windows']), (200, None, False))

    def test_an_unknown_host_a_bad_id_and_a_wrong_method_are_refused(self):
        self.assertEqual(self.get('nope')[0], 404)
        self.assertEqual(self.get('../x')[0], 404)
        self.assertEqual(self.call(api.handle_device_persistence, 'win1', m='POST')[0], 405)

    def test_a_tenant_administrator_cannot_read_another_tenants_host_and_a_viewer_can_read_its_own(self):
        self.beat('winB', snap_of(run=[A]))
        api.save(api.CONFIG_FILE, {'tenancy_enforced': True})
        api._LOAD_CACHE.clear()
        api.path_info = lambda: '/api/devices/winB/persistence'
        self.who = 'badmin'
        self.assertIsNone(api._enforce_device_scope(), 'the administrator of the host\'s own tenant passes the gate')
        self.assertEqual(self.get('winB', who='badmin')[0], 200)
        api.path_info = lambda: '/api/devices/win1/persistence'
        self.cap.clear()
        with self.assertRaises(api.HTTPError):
            api._enforce_device_scope()
        self.assertEqual((self.cap['status'], self.cap['data']['error']), (403, 'Host belongs to another tenant'), 'a tenant administrator of tenant B is refused host win1 before the handler runs')
        self.who = 'viewer1'
        api.path_info = lambda: '/api/devices/win1/persistence'
        self.assertIsNone(api._enforce_device_scope())
        self.assertEqual(self.get('win1', who='viewer1')[0], 200, 'reading is for every signed-in role')
        self.who = 'viewerB'
        self.cap.clear()
        with self.assertRaises(api.HTTPError):
            api._enforce_device_scope()
        self.assertEqual(self.cap['status'], 403)

    def test_nobody_signed_out_reads_it_and_there_is_nothing_to_write(self):
        st, d = self.call(api.handle_device_persistence, 'win1', who=None)
        self.assertIn(st, (401, 403))
        self.assertNotIn(('POST',), [r[1] for r in api._PATTERN_ROUTE_DEFS if r[4] == 'handle_device_persistence'])
        routes = [r for r in api._PATTERN_ROUTE_DEFS if r[4] == 'handle_device_persistence']
        self.assertEqual([(r[1], r[2], r[3]) for r in routes], [(('GET',), '/api/devices/', '/persistence')])

    def test_what_a_host_sent_is_written_back_cleaned_and_in_no_other_shape(self):
        evil = 'x' + chr(0) + chr(27) + '<img src=x onerror=alert(1)>' + chr(0x202e)
        self.beat('win1', snap_of(run=[A]))
        self.beat('win1', snap_of(run=[A, ['Run', evil, evil + ' --token abc123']]))
        st, d = self.get('win1')
        text = json.dumps(d)
        self.assertNotIn('abc123', text)
        c = d['persistence']['changes'][0]
        self.assertEqual(c['name'], 'x <img src=x onerror=alert(1)>', 'markup is left as text for the page to escape; control characters are gone')
        self.assertEqual([ch for ch in c['name'] + c['data'] if ord(ch) < 32 or ch == chr(0x202e)], [])


class TestHostDeletion(_Server):
    def test_deleting_the_host_deletes_its_inventory_and_its_log_and_no_other_hosts(self):
        self.beat('win1', snap_of(run=[A]))
        self.beat('win2', snap_of(run=[B]))
        self.assertTrue(api._purge_device('win1'))
        api._LOAD_CACHE.clear()
        self.assertIsNone(self.stored('win1'))
        self.assertIsNotNone(self.stored('win2'))
        self.assertIn('persistence.json', api.host_purge.STORES)


# ── the registrations ────────────────────────────────────────────────────────
class TestTheRegistrations(unittest.TestCase):
    def test_the_store_is_an_entity_store_with_a_shape_and_a_purge_rule(self):
        import host_purge
        import storage
        import store_shapes
        self.assertEqual(storage._classify(api.PERSISTENCE_FILE), 'entity')
        self.assertIn('persistence.json', storage.ENTITY_FILES)
        self.assertIn('persistence.json', store_shapes.SHAPES)
        self.assertIn('persistence.json', host_purge.RULES)
        self.assertEqual(api.PERSISTENCE_FILE.name, 'persistence.json')

    def test_a_row_of_the_wrong_shape_is_repaired_where_it_is_read(self):
        import store_shapes
        good = {'v': 1, 'ts': 5, 'baseline': 4, 'alert_ts': 0, 'inv': {'run': {'ok': True, 'complete': True, 'ts': 5, 'items': [['a', 'b', 'c']]}},
                'log': [{'ts': 5, 'op': 'added', 'cat': 'run', 'loc': 'a', 'name': 'b', 'data': 'c', 'alerted': False}]}
        self.assertEqual(store_shapes.normalize('persistence.json', {'h': good}), {'h': good})
        bad = {'h': dict(good, ts='7', inv={'run': 'x', 'tasks': {'items': 'nope', 'ts': 3}}, log=[None, 5, {'op': 'added'}, dict(good['log'][0], name=7)]), 'x': 'text', 'y': None}
        fixed = store_shapes.normalize('persistence.json', bad)
        self.assertEqual(sorted(fixed), ['h'])
        self.assertEqual(fixed['h']['ts'], 7)
        self.assertNotIn('run', fixed['h']['inv'])
        self.assertEqual([e['name'] for e in fixed['h']['log']], ['7'])

    def test_the_event_the_kind_and_what_the_default_does_for_it(self):
        spec = api.EVENT_REGISTRY['persistence_added']
        self.assertEqual((spec['kind'], spec['severity'], spec['lifecycle']), ('persistence', 'medium', 'point'))
        self.assertIn(('persistence', 'New startup entries on Windows hosts', 'security'), api.CHANNEL_KIND_DEFS)
        self.assertEqual(api.EVENT_KIND_MAP['persistence_added'], 'persistence')
        self.assertIn('persistence_added', api.WEBHOOK_EVENT_NAMES)
        default = api._kind_default('persistence')
        self.assertEqual((default['needs_attention'], default['webhook'], default['alerts'], default['recent_activity']), (False, False, True, True))

    def test_the_title_and_the_webhook_sentence_read_well(self):
        self.assertEqual(api._alert_title('persistence_added', {'name': 'WIN01', 'count': 1}), 'New startup entry on WIN01')
        self.assertEqual(api._alert_title('persistence_added', {'name': 'WIN01', 'count': 3}), 'New startup entries on WIN01')
        msg = api.notify_mod._webhook_message('persistence_added', {'name': 'WIN01', 'detail': '1 new startup entry (1 Run key)', 'sample': ['Run key: x = y']})
        self.assertEqual(msg, 'WIN01: 1 new startup entry (1 Run key) — Run key: x = y')
        self.assertEqual(api.notify_mod._webhook_message('persistence_added', {'name': 'W'}), 'W: new startup entry')

    def test_the_activity_feed_knows_the_event(self):
        js = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text(encoding='utf-8')
        self.assertIn("'ssh_key_added', 'persistence_added', 'brute_force_detected'", js)
        self.assertIn("case 'persistence_added':", js)
        self.assertIn("'persistence_added': 'warn'", js)

    def test_the_module_is_fetched_when_a_drawer_opens_and_is_in_the_lazy_list(self):
        js = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text(encoding='utf-8')
        lazy = re.search(r'const _LAZY_NON_PAGE_MODULES = \[([^\]]*)\]', js).group(1)
        self.assertIn("'app-persistence.js'", lazy)
        self.assertIn("_loadJsModule('app-persistence.js').then(() => { if (typeof loadDrawerPersistence === 'function') loadDrawerPersistence(id); })", js)
        html = (_ROOT / 'server' / 'html' / 'index.html').read_text(encoding='utf-8')
        for needle in ('id="drawer-persistence-section"', 'id="drawer-persistence-when"', 'id="drawer-persistence-changes"', 'id="drawer-persistence-list"'):
            self.assertIn(needle, html)
        self.assertIsNone(re.search(r'<script[^>]*app-persistence\.js', html), 'a lazy module is not also a script tag')


# ── what a person reads ──────────────────────────────────────────────────────
class TestSixLanguages(unittest.TestCase):
    STRINGS = ['Persistence', 'Changes', 'On the host now', 'Run key', 'Winlogon value', 'Scheduled task', 'Startup folder', 'First inventory', 'Last inventory',
               'Nothing has changed since the first inventory.', 'This place could not be read at the last inventory. It is shown as it was.',
               'This list was cut at its limit, so changes in it are not tracked.',
               'What starts by itself on this Windows host: Run keys, the Winlogon shell, services that run from a temporary or user folder, scheduled tasks that are not '
               "Microsoft's, and startup folders. Once a first inventory is on record, a new entry raises an alert.",
               'A new startup entry appeared on a Windows host', 'New startup entries on Windows hosts', 'Added', 'Removed', 'Service']

    @classmethod
    def setUpClass(cls):
        cls.rows = dict_rows()

    def test_every_string_the_section_shows_has_all_six_languages(self):
        missing = {s: sorted(set(LANGS) - self.rows.get(s, set())) for s in self.STRINGS if not set(LANGS) <= self.rows.get(s, set())}
        self.assertEqual(missing, {})

    def test_the_labels_of_the_script_and_the_markup_are_the_sentences_the_dictionary_is_keyed_on(self):
        js = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-persistence.js').read_text(encoding='utf-8')
        html = (_ROOT / 'server' / 'html' / 'index.html').read_text(encoding='utf-8')
        for label in ('Run key', 'Winlogon value', 'Service', 'Scheduled task', 'Startup folder', 'Added', 'Removed', 'First inventory', 'Last inventory',
                      'Nothing has changed since the first inventory.', 'This place could not be read at the last inventory. It is shown as it was.',
                      'This list was cut at its limit, so changes in it are not tracked.'):
            self.assertIn(label, js, label)
        for label in ('Persistence', 'Changes', 'On the host now', self.STRINGS[12]):
            self.assertIn('>%s' % label, html, label)

    def test_the_server_labels_are_in_the_registries_the_label_gate_reads(self):
        self.assertEqual(api.EVENT_REGISTRY['persistence_added']['label'], 'A new startup entry appeared on a Windows host')
        self.assertIn('New startup entries on Windows hosts', [k[1] for k in api.CHANNEL_KIND_DEFS])

    def test_a_host_is_a_host_and_no_word_the_house_style_drops_is_in_what_was_added(self):
        banned = ('genu' + 'ine', 'verba' + 'tim', 'delib' + 'erate')      # written in two parts so that this file does not hold the words it checks for
        agent = (_ROOT / 'client' / 'remotepower-agent-win.py').read_text(encoding='utf-8')
        region = agent[agent.index('# ── persistence inventory'):agent.index('def _eval_one_agent_check_win')]
        docs = (_ROOT / 'docs' / 'windows-client.md').read_text(encoding='utf-8')
        docs_region = docs[docs.index('### Persistence inventory'):docs.index('### Interpreter selection')]
        texts = [region, docs_region, (_CGI / 'persistence.py').read_text(encoding='utf-8'), (_CGI / 'persistence_handlers.py').read_text(encoding='utf-8'),
                 (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-persistence.js').read_text(encoding='utf-8')] + self.STRINGS
        for text in texts:
            for w in banned:
                self.assertNotIn(w, text.lower())
        for text in (docs_region, ' '.join(self.STRINGS)):
            self.assertNotRegex(text.lower(), r'\bdevices?\b', 'a managed machine is a host')


if __name__ == '__main__':
    unittest.main()

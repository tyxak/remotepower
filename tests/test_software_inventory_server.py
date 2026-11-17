"""The installed software of Windows and macOS hosts, on the server.

The Linux agent has always sent the packages of its distribution to POST /api/packages, and every software view reads
them: the search, the software center, the policy, the metering, the SBOM and the CVE page. The Windows and macOS agents
sent nothing, so those hosts were blank in all of them. What they send now is a list of applications: names with spaces
and capitals ("Google Chrome", "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33130"), versions a vendor
wrote, a publisher, an install date and, for a Mac application, its bundle identifier.

This module drives the real handlers and the real readers over lists in the shapes the agents write (the samples are
written from what the Uninstall keys and an Info.plist hold; none was read from a host, there is none here) and holds:

  * what the server keeps of such a list, with every field capped, and that a Linux list is read as it always was;
  * that nothing about such a list reaches the vulnerability scan, the package snapshots or the install and remove
    commands, which are written for the packages of a distribution;
  * that every view reads the lists by their own rules (names by case, versions as numbers when they are numbers,
    a title is no process name), for each caller: a tenant administrator, a read-only user, a role scoped to a tag.
"""
import importlib.util
import itertools
import json
import os
import random
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


os.environ.setdefault('RP_DATA_DIR', _tmp('rp-softinv-'))
_spec = importlib.util.spec_from_file_location('api_softinv_server', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import cve_scanner  # noqa: E402
import sbom  # noqa: E402
import software_inventory as si  # noqa: E402
import store_shapes  # noqa: E402


def tearDownModule():
    for d in _TMP:
        shutil.rmtree(d, ignore_errors=True)


# ── what the agents write ──────────────────────────────────────────────────────────────────────────────────────────────
WINDOWS = [
    {'name': 'Google Chrome', 'version': '120.0.6099.109', 'publisher': 'Google LLC', 'installed': '2023-12-15',
     'arch': 'x64', 'manager': 'windows'},
    {'name': '7-Zip 23.01 (x64)', 'version': '23.01', 'publisher': 'Igor Pavlov', 'installed': '2023-11-02',
     'arch': 'x64', 'manager': 'windows'},
    {'name': 'Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33130', 'version': '14.38.33130.0',
     'publisher': 'Microsoft Corporation', 'installed': '2023-10-30', 'arch': 'x64', 'manager': 'windows'},
    {'name': 'Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.38.33130', 'version': '14.38.33130.0',
     'publisher': 'Microsoft Corporation', 'installed': '2023-10-30', 'arch': 'x86', 'manager': 'windows'},
    {'name': 'Microsoft Edge', 'version': '120.0.2210.91', 'publisher': 'Microsoft Corporation',
     'installed': '2023-12-20', 'arch': 'x86', 'manager': 'windows'},
    {'name': 'TeamViewer', 'version': '15.49.2', 'publisher': 'TeamViewer Germany GmbH', 'arch': 'x64',
     'manager': 'windows'},
    {'name': 'Git', 'version': '2.43.0.windows.1', 'publisher': 'The Git Development Community', 'arch': 'x64',
     'manager': 'windows'},
    {'name': 'Windows Driver Package - Intel (e1dexpress) Net', 'version': '12.19.2.45', 'manager': 'windows'},
]
MAC = [
    {'name': 'Safari', 'version': '17.2', 'id': 'com.apple.Safari', 'manager': 'macos'},
    {'name': 'Google Chrome', 'version': '120.0.6099.129', 'id': 'com.google.Chrome', 'manager': 'macos'},
    {'name': 'wget', 'version': '1.21.4', 'manager': 'brew'},
    {'name': 'git', 'version': '2.43.0', 'manager': 'brew'},
]
LINUX = [
    {'name': 'openssl', 'version': '3.0.2-0ubuntu1.12', 'arch': 'amd64'},
    {'name': 'git', 'version': '1:2.34.1-1ubuntu1.10', 'arch': 'amd64'},
    {'name': 'nginx', 'version': '1.18.0-6ubuntu14.4', 'arch': 'amd64'},
]
WIN_A, WIN_B, MAC_A, LNX_B = 'sinvwinalpha', 'sinvwinbravo', 'sinvmacalpha', 'sinvlnxbravo'


class _Captured(Exception):
    def __init__(self, status, body):
        super().__init__(status)
        self.status, self.body = status, body


def _device(name, tenant, os_name, tags=(), **extra):
    return dict({'id': name, 'name': name, 'tenant': tenant, 'os': os_name, 'token': 'tok-' + name, 'monitored': True,
                 'group': (list(tags) or [''])[0], 'tags': list(tags), 'last_seen': 2_000_000_000}, **extra)


class _Fleet(unittest.TestCase):
    """Four hosts of two tenants whose lists arrived through the real ingest."""

    def setUp(self):
        self._patches = []
        self.addCleanup(self._stop)
        self.events = []
        self.patch(api, 'respond', self._respond)
        self.patch(api, 'audit_log', lambda *a, **k: None)
        self.patch(api, 'fire_webhook', lambda event, payload=None, *a, **k: self.events.append((event, payload)))
        self.patch(api, 'get_token_from_request', lambda: 'x')
        api.save(api.CONFIG_FILE, {})
        api.save(api.TENANTS_FILE, {'tenantA': {'name': 'Tenant A', 'status': 'active'},
                                    'tenantB': {'name': 'Tenant B', 'status': 'active'}})
        api.save(api.USERS_FILE, {'alice': {'tenant_id': 'tenantA', 'role': 'admin'},
                                  'carol': {'tenant_id': 'tenantA', 'role': 'viewer'},
                                  'root': {'tenant_id': 'default', 'role': 'admin'}})
        api.save(api.ROLES_FILE, {'roles': [{'name': 'scopedwin', 'permissions': [],
                                             'scope': {'type': 'tags', 'values': ['windows']}}]})
        api.save(api.DEVICES_FILE, {
            WIN_A: _device(WIN_A, 'tenantA', 'Windows 11 (Build 22631)', ['windows', 'prod'],
                           sysinfo={'top_processes': [{'name': 'explorer.exe'}]}),
            MAC_A: _device(MAC_A, 'tenantA', 'macOS 14.5 (23F79)', ['mac', 'prod'],
                           sysinfo={'top_processes': [{'name': 'launchd'}]}),
            LNX_B: _device(LNX_B, 'tenantB', 'Ubuntu 22.04', ['linux', 'prod'],
                           sysinfo={'top_processes': [{'name': 'sshd'}]}),
            WIN_B: _device(WIN_B, 'tenantB', 'Windows 10 Pro (Build 19045)', ['bravo'],
                           sysinfo={'top_processes': [{'name': 'explorer.exe'}]}),
        })
        for store in (api.PACKAGES_FILE, api.SOFTWARE_POLICY_FILE, api.SOFTWARE_VIOLATIONS_FILE,
                      api.PATCH_SNAPSHOTS_FILE, api.CVE_FINDINGS_FILE):
            api.save(store, {})
        api._LOAD_CACHE.clear()
        self.send(WIN_A, 'windows', WINDOWS, skipped=41)
        self.send(MAC_A, 'macos', MAC)
        self.send(LNX_B, 'apt', LINUX, hint={'ID': 'ubuntu', 'VERSION_ID': '22.04', 'ID_LIKE': 'debian'})
        self.send(WIN_B, 'windows', [WINDOWS[1], dict(WINDOWS[6], name='GIT', version='2.42.0.windows.2')])

    def patch(self, target, name, value):
        p = mock.patch.object(target, name, value)
        p.start()
        self._patches.append(p)

    def _stop(self):
        for p in reversed(self._patches):
            p.stop()
        for store in (api.DEVICES_FILE, api.PACKAGES_FILE, api.SOFTWARE_POLICY_FILE, api.SOFTWARE_VIOLATIONS_FILE,
                      api.PATCH_SNAPSHOTS_FILE, api.CVE_FINDINGS_FILE, api.CONFIG_FILE, api.TENANTS_FILE,
                      api.USERS_FILE, api.ROLES_FILE):
            api.save(store, {})
        api._LOAD_CACHE.clear()

    @staticmethod
    def _respond(status, data=None, headers=None):
        raise _Captured(status, data)

    # ── the agent's side of the contract ────────────────────────────────────────────────────────────────────────────
    def post(self, body, user_agent_token=None):
        """POST /api/packages as an agent: (status, answer)."""
        with mock.patch.object(api, 'method', lambda: 'POST'), mock.patch.object(api, 'get_json_obj', lambda: body):
            api._LOAD_CACHE.clear()
            try:
                api.handle_packages_submit()
            except _Captured as c:
                api._LOAD_CACHE.clear()
                return c.status, c.body
        self.fail('the handler did not answer')

    def send(self, dev_id, manager, packages, hint=None, skipped=None, **extra):
        body = dict({'device_id': dev_id, 'token': 'tok-' + dev_id, 'pkg_manager': manager, 'packages': packages},
                    **extra)
        if hint is not None:
            body['ecosystem_hint'] = hint
        if skipped is not None:
            body['skipped'] = skipped
        status, answer = self.post(body)
        self.assertEqual(status, 200, answer)
        return answer

    def stored(self, dev_id):
        api._LOAD_CACHE.clear()
        return (api.load(api.PACKAGES_FILE) or {}).get(dev_id) or {}

    # ── the reader's side: only verify_token is stubbed, never a gate ───────────────────────────────────────────────
    def get(self, handler, query='', *args, user=('root', 'admin'), tenancy=False, config=None, verb='GET', body=None):
        cfg = dict(config or {})
        if tenancy:
            cfg['tenancy_enforced'] = True
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()
        env = lambda key, default=None, _q=query: _q if key == 'QUERY_STRING' else default  # noqa: E731
        with mock.patch.object(api, '_env', env), mock.patch.object(api, 'method', lambda: verb), \
                mock.patch.object(api, 'get_json_obj', lambda: dict(body or {})), \
                mock.patch.object(api, 'verify_token', lambda tok=None: user):
            try:
                handler(*args)
            except _Captured as c:
                return c.status, c.body
        self.fail('the handler did not answer')

    def as_tenant_admin(self, handler, query='', *args, **kw):
        return self.get(handler, query, *args, user=('alice', 'admin'), tenancy=True, **kw)

    def as_read_only(self, handler, query='', *args, **kw):
        return self.get(handler, query, *args, user=('carol', 'viewer'), tenancy=True, **kw)

    def as_scoped(self, handler, query='', *args, **kw):
        return self.get(handler, query, *args, user=('bob', 'scopedwin'), **kw)


# ── the rows ───────────────────────────────────────────────────────────────────────────────────────────────────────────
class TestTheRowsOfAList(unittest.TestCase):
    def test_a_title_keeps_its_spaces_and_capitals_and_a_version_may_be_empty(self):
        row = si.clean_entry({'name': 'Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33130',
                              'version': '', 'publisher': 'Microsoft Corporation', 'installed': '20231030',
                              'arch': 'x64', 'id': 'bundle.id'}, 'windows')
        self.assertEqual(row, {'name': 'Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33130',
                               'version': '', 'arch': 'x64', 'manager': 'windows',
                               'publisher': 'Microsoft Corporation', 'installed': '2023-10-30', 'id': 'bundle.id'})

    def test_what_is_not_a_row_is_left_out(self):
        for bad in (None, 'Chrome', 5, [], ['Chrome'], {}, {'name': ''}, {'name': '   '}, {'name': 7},
                    {'name': None}, {'name': ['a']}, {'version': '1.0'}):
            self.assertIsNone(si.clean_entry(bad, 'windows'), bad)
        self.assertIsNone(si.clean_entry({'name': 'x'}, 'apt'))          # not a host of an application list
        self.assertIsNone(si.clean_entry({'name': 'x'}, ''))

    def test_a_field_is_text_a_page_can_print_and_at_most_200_characters(self):
        self.assertEqual(si.clean_text('a\x00b\x07c\x1bd\x7fe'), 'abcde')
        self.assertEqual(si.clean_text('Chrome ‮exe.pdf‬'), 'Chrome exe.pdf')      # a bidirectional override
        self.assertEqual(si.clean_text('a​b‍c'), 'abc')                           # zero-width format characters
        self.assertEqual(si.clean_text('lone \ud800 surrogate'), 'lone surrogate')           # one that cannot be written
        self.assertEqual(si.clean_text('a \t b\r\n c d e'), 'a b c d e')
        self.assertEqual(len(si.clean_text('x' * 5000)), 200)
        self.assertEqual(si.clean_text('x' * 199 + ' ' + 'y' * 50), 'x' * 199)               # no trailing space left by the cut
        for none in (None, 5, ['a'], {'a': 1}, b'bytes', True):
            self.assertEqual(si.clean_text(none), '', none)

    def test_a_field_of_a_row_is_capped_at_200_characters(self):
        row = si.clean_entry({'name': 'n' * 300, 'version': 'v' * 300, 'publisher': 'p' * 300, 'id': 'i' * 300},
                             'macos')
        self.assertEqual([len(row[k]) for k in ('name', 'version', 'publisher', 'id')], [200, 200, 200, 200])

    def test_a_date_is_a_date(self):
        for given, want in (('20231030', '2023-10-30'), ('2023-10-30', '2023-10-30'), (' 20240229 ', '2024-02-29'),
                            ('20230229', ''), ('20231330', ''), ('00000000', ''), ('18991231', ''),
                            ('21010101', ''), ('2023103', ''), ('Oct 30 2023', ''), ('', ''), (None, ''),
                            (20231030, ''), ('2023-10-30T10:00', '')):
            self.assertEqual(si.clean_date(given), want, given)

    def test_an_architecture_is_a_word(self):
        for given, want in (('x64', 'x64'), ('arm64', 'arm64'), (' x86 ', 'x86'), ('', ''), ('x64 <b>', ''),
                            ('a' * 17, ''), (None, ''), (64, '')):
            self.assertEqual(si.clean_arch(given), want, given)

    def test_a_row_names_its_own_manager_only_when_its_host_may_hold_one_like_it(self):
        pick = lambda manager, host: si.clean_entry({'name': 'x', 'manager': manager}, host)['manager']  # noqa: E731
        self.assertEqual(pick('brew', 'macos'), 'brew')
        self.assertEqual(pick('macos', 'macos'), 'macos')
        self.assertEqual(pick('BREW', 'macos'), 'brew')
        self.assertEqual(pick('brew', 'windows'), 'windows')      # a Windows host has no Homebrew
        self.assertEqual(pick('windows', 'macos'), 'macos')
        self.assertEqual(pick('apt', 'windows'), 'windows')
        self.assertEqual(pick(['brew'], 'macos'), 'macos')
        self.assertEqual(pick(None, 'windows'), 'windows')

    def test_a_list_drops_repeats_not_versions_and_reads_at_most_5000(self):
        row = {'name': 'Python 3.12.1 (64-bit)', 'version': '3.12.1', 'arch': 'x64'}
        rows = si.clean_list([row, dict(row), dict(row, name='PYTHON 3.12.1 (64-BIT)'),
                              dict(row, version='3.12.2'), dict(row, arch='x86')], 'windows')
        self.assertEqual([(r['name'], r['version'], r['arch']) for r in rows],
                         [('Python 3.12.1 (64-bit)', '3.12.1', 'x64'), ('Python 3.12.1 (64-bit)', '3.12.2', 'x64'),
                          ('Python 3.12.1 (64-bit)', '3.12.1', 'x86')])
        many = [{'name': f'App {i}', 'version': '1'} for i in range(si.MAX_PACKAGES + 700)]
        self.assertEqual(len(si.clean_list(many, 'macos')), si.MAX_PACKAGES)
        self.assertEqual(si.MAX_PACKAGES, 5000)
        for none in (None, {}, 'x', 5, {'name': 'a'}):
            self.assertEqual(si.clean_list(none, 'windows'), [])

    def test_which_lists_and_rows_are_applications(self):
        self.assertTrue(si.is_inventory_host('windows') and si.is_inventory_host(' MacOS '))
        for no in ('apt', 'dnf', 'brew', '', None, 5, ['windows']):
            self.assertFalse(si.is_inventory_host(no), no)
        self.assertEqual(si.row_manager({'name': 'x', 'manager': 'brew'}, 'macos'), 'brew')
        self.assertEqual(si.row_manager({'name': 'x'}, 'windows'), 'windows')
        self.assertEqual(si.row_manager({'name': 'x'}, 'apt'), '')
        self.assertEqual(si.row_manager({'name': 'x', 'manager': 'apt'}, 'apt'), '')
        self.assertEqual(si.row_manager('x', 'windows'), 'windows')

    def test_a_count_of_what_the_agent_left_out(self):
        for given, want in ((41, 41), (0, 0), (-1, 0), (10 ** 9, 0), (True, 0), ('41', 0), (4.5, 0), (None, 0)):
            self.assertEqual(si.clean_skipped(given), want, given)


class TestVersions(unittest.TestCase):
    def order(self, a, b):
        return si.compare_versions(a, b)

    def test_dotted_numbers_are_numbers(self):
        self.assertEqual(self.order('10.0.9', '10.0.19045'), -1)             # text order would say 1
        self.assertEqual(self.order('10.0.19045.3693', '10.0.19044.9999'), 1)
        self.assertEqual(self.order('14.38.33130', '14.38.33130.0'), 0)
        self.assertEqual(self.order('1.2', '1.2.0'), 0)
        self.assertEqual(self.order('3.12.1', '3.9.18'), 1)
        self.assertEqual(self.order('v2.1', '2.1'), 0)
        self.assertEqual(self.order('120.0.6099.109', '120.0.6099.1090'), -1)

    def test_the_words_after_a_number_are_text_and_a_version_never_raises(self):
        self.assertEqual(self.order('2023.1 (64-bit)', '2023.1'), 1)               # the words after the number come last
        self.assertEqual(self.order('Beta 3', 'beta 3'), 0)
        self.assertEqual(self.order('2023.4 (build 9)', '2023.4 (build 10)'), 1)     # text after the number, as the brief says
        self.assertEqual(self.order('', ''), 0)
        self.assertEqual(self.order('', '1.0'), -1)
        self.assertEqual(self.order('1.0', 'one'), 1)                       # no number in front: below every version that has one
        self.assertEqual(self.order('', 'one'), -1)                         # and an empty version is below the rest
        self.assertEqual(self.order('', '0'), -1)                           # even below the version 0
        self.assertEqual(self.order('one', '0'), -1)
        self.assertEqual(self.order('\u0663.\u0664', '0.1'), -1)           # digits of another script are text: read as numbers it is 3.4, above 0.1
        for odd in (None, 7, 4.5, ['1'], {'v': 1}, b'1.0', '9' * 5000, '1.' + '9' * 4400, '٣.٤', 'v', '.', '..', '1..2'):
            self.assertIn(self.order(odd, '1.0'), (-1, 0, 1), repr(odd)[:40])
            self.assertIn(self.order('1.0', odd), (-1, 0, 1), repr(odd)[:40])

    def test_the_number_in_front_decides_before_the_words(self):
        """Git for Windows writes 2.43.0.windows.1. As text it is above 2.100 and below 2.9; as the number it starts with it is
        the other way round, which is what a minimum or a search for 2.100 means."""
        self.assertEqual(self.order('2.43.0.windows.1', '2.100'), -1)
        self.assertEqual(self.order('2.43.0.windows.1', '2.9'), 1)
        self.assertEqual(self.order('2.43.0.windows.1', '10.0'), -1)
        self.assertEqual(self.order('2.43.0.windows.1', '2.43'), 1)
        self.assertEqual(self.order('2.43.0.windows.1', '2.43.0.windows.2'), -1)
        self.assertEqual(self.order('15.0.1 (64-bit)', '9.0'), 1)
        self.assertEqual(self.order('v2.1 beta', '2.1 BETA'), 0)
        self.assertEqual(self.order('2.0 beta', '2.0.0 beta'), 0)                    # trailing zeros of the number are not a difference

    SAMPLE = ['', '0', '0.0', '1', '1.0', '1.0.1', '1.10', '1.9', '2', '2.5 beta', '2.9', '2.10', '2.43.0.windows.1', '10',
              'Beta', 'beta 3', 'N/A', 'one', '2023.1', '2023.1 (64-bit)', '2023.4 (build 9)', '2023.4 (build 10)', 'v3',
              'v3 rc1', '\u0663.\u0664', '14.38.33130.0', '14.38.33130']

    def test_the_order_is_an_order(self):
        """Antisymmetric, and transitive over every triple. The first version of this test checked the first only, and the
        order it was written for had a cycle: 2.10 above 2.9 above "2.5 beta" above 2.10."""
        sample = self.SAMPLE
        for a in sample:
            self.assertEqual(self.order(a, a), 0)
            for b in sample:
                self.assertEqual(self.order(a, b), -self.order(b, a), (a, b))
        for a in sample:
            for b in sample:
                for c in sample:
                    if self.order(a, b) <= 0 and self.order(b, c) <= 0:
                        self.assertLessEqual(self.order(a, c), 0, (a, b, c))
                    if self.order(a, b) == 0:
                        self.assertEqual(self.order(a, c), self.order(b, c), (a, b, c))

    def test_the_three_versions_that_made_a_cycle_have_one_order(self):
        a, b, c = '2.10', '2.9', '2.5 beta'
        self.assertEqual((self.order(a, b), self.order(b, c), self.order(a, c)), (1, 1, 1))

    def test_a_list_sorts_the_same_whatever_order_it_comes_in(self):
        keys = lambda rows: [si.version_key(v) for v in rows]  # noqa: E731
        want = keys(sorted(self.SAMPLE, key=si.version_key))
        rng = random.Random(7)
        for _ in range(200):
            rows = list(self.SAMPLE)
            rng.shuffle(rows)
            self.assertEqual(keys(sorted(rows, key=si.version_key)), want)
        trio = ['2.10', '2.9', '2.5 beta', '2.5', '10.1 (x)']
        self.assertEqual(len({tuple(keys(sorted(p, key=si.version_key))) for p in itertools.permutations(trio)}), 1)
        # the highest of a list, the way the policy and the SBOM keep it: a running maximum over compare_versions
        for perm in itertools.permutations(trio):
            highest = perm[0]
            for v in perm[1:]:
                if self.order(v, highest) > 0:
                    highest = v
            self.assertEqual(highest, '10.1 (x)', perm)


# ── what the server keeps ─────────────────────────────────────────────────────────────────────────────────────────────
class TestWhatTheServerKeeps(_Fleet):
    def test_a_windows_list_is_kept_as_it_was_sent(self):
        entry = self.stored(WIN_A)
        self.assertEqual(entry['pkg_manager'], 'windows')
        self.assertEqual(entry['count'], len(WINDOWS))
        self.assertEqual(entry['skipped'], 41)
        self.assertEqual(entry['ecosystem'], '')
        self.assertEqual((entry['os_id'], entry['version_id']), ('', ''))
        self.assertEqual(entry['packages'][0], {'name': 'Google Chrome', 'version': '120.0.6099.109', 'arch': 'x64',
                                                 'manager': 'windows', 'publisher': 'Google LLC',
                                                 'installed': '2023-12-15'})
        names = [p['name'] for p in entry['packages']]
        self.assertIn('Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33130', names)
        self.assertIn('Windows Driver Package - Intel (e1dexpress) Net', names)
        self.assertEqual(entry['packages'][-1]['version'], '12.19.2.45')

    def test_a_mac_holds_applications_and_homebrew_rows_with_their_own_managers(self):
        entry = self.stored(MAC_A)
        self.assertEqual(entry['pkg_manager'], 'macos')
        self.assertEqual({p['name']: p['manager'] for p in entry['packages']},
                         {'Safari': 'macos', 'Google Chrome': 'macos', 'wget': 'brew', 'git': 'brew'})
        self.assertEqual(next(p for p in entry['packages'] if p['name'] == 'Safari')['id'], 'com.apple.Safari')

    def test_the_answer_says_nothing_is_to_scan_and_the_page_is_not_told_to_ask(self):
        answer = self.send(WIN_A, 'windows', WINDOWS, hint={'ID': 'ubuntu', 'VERSION_ID': '22.04', 'ID_LIKE': 'debian'})
        self.assertEqual(answer['ecosystem'], 'unsupported')
        self.assertFalse(answer['scan_suggested'])
        self.assertFalse(answer['changed'])
        self.assertEqual(answer['packages_stored'], len(WINDOWS))
        changed = self.send(WIN_A, 'windows', WINDOWS + [{'name': 'Notepad++ (64-bit x64)', 'version': '8.6'}])
        self.assertTrue(changed['changed'])
        self.assertFalse(changed['scan_suggested'])

    def test_a_hint_from_another_os_names_no_ecosystem_and_no_end_of_life_release(self):
        """The os-release is the hint of a Linux host. Kept for a Windows host it would name an end-of-life release
        for it: the end-of-life check reads os_id and version_id before it reads the host's own OS string."""
        self.send(WIN_A, 'windows', WINDOWS, hint={'ID': 'ubuntu', 'VERSION_ID': '16.04', 'ID_LIKE': 'debian',
                                                    'UBUNTU_CODENAME': 'xenial'})
        entry = self.stored(WIN_A)
        self.assertEqual((entry['ecosystem'], entry['os_id'], entry['version_id']), ('', '', ''))
        self.assertNotIn('ubuntu_codename', entry)
        dev = api.load(api.DEVICES_FILE)[WIN_A]
        self.assertIsNone(api._device_os_eol(dev, entry))
        # the control: the same hint on a list of a Linux host does name the release, which is past its end of life
        linux = dict(entry, os_id='ubuntu', version_id='16.04')
        self.assertEqual(api._device_os_eol(dev, linux)['status'], 'eol')

    def test_a_manager_is_read_by_its_word_whatever_the_case(self):
        self.send(WIN_A, ' Windows ', WINDOWS[:2])
        self.assertEqual(self.stored(WIN_A)['pkg_manager'], 'windows')
        self.assertEqual(self.stored(WIN_A)['count'], 2)

    def test_a_linux_list_is_read_as_it_always_was(self):
        """The control. A name with a space is not a package of a distribution, and a Linux list keeps nothing it did not."""
        odd = [{'name': 'Google Chrome', 'version': '120.0', 'arch': 'amd64', 'publisher': 'Google LLC',
                'manager': 'windows', 'installed': '2023-12-15'},
               {'name': 'bash', 'version': '5.1-6ubuntu1', 'arch': 'amd64', 'publisher': 'x', 'manager': 'windows'}]
        self.send(LNX_B, 'apt', odd, hint={'ID': 'ubuntu', 'VERSION_ID': '22.04', 'ID_LIKE': 'debian'})
        entry = self.stored(LNX_B)
        self.assertEqual(entry['packages'], [{'name': 'bash', 'version': '5.1-6ubuntu1', 'arch': 'amd64'}])
        self.assertEqual((entry['ecosystem'], entry['pkg_manager'], entry['os_id']), ('Ubuntu', 'apt', 'ubuntu'))
        self.assertNotIn('skipped', entry)

    def test_the_manager_of_a_list_decides_how_it_is_read_not_the_rows(self):
        """A Linux agent cannot give a list the rules of an application list by naming a row's manager."""
        self.send(LNX_B, 'apt', [{'name': 'Fake App', 'version': '1', 'manager': 'windows'},
                                 {'name': 'fine', 'version': '1.0', 'manager': 'brew'}])
        self.assertEqual([p['name'] for p in self.stored(LNX_B)['packages']], ['fine'])
        self.assertNotIn('manager', self.stored(LNX_B)['packages'][0])

    def test_no_more_than_5000_rows_and_200_characters_a_field(self):
        many = [{'name': f'Application number {i}', 'version': '1.0.%d' % i, 'publisher': 'P' * 400} for i in range(5600)]
        self.send(WIN_A, 'windows', many)
        entry = self.stored(WIN_A)
        self.assertEqual(entry['count'], 5000)
        self.assertEqual(len(entry['packages']), 5000)
        self.assertEqual(len(entry['packages'][0]['publisher']), 200)

    def test_what_is_not_a_list_is_refused_and_what_is_not_a_row_is_left_out(self):
        status, answer = self.post({'device_id': WIN_A, 'token': 'tok-' + WIN_A, 'pkg_manager': 'windows',
                                    'packages': 'Google Chrome'})
        self.assertEqual(status, 400, answer)
        self.send(WIN_A, 'windows', ['Chrome', None, 5, ['x'], {'name': 'Kept', 'version': '1'},
                                     {'name': 'x' * 10, 'version': {'a': 1}, 'publisher': ['p'], 'installed': 5,
                                      'arch': {}, 'id': 7}], skipped='41')
        entry = self.stored(WIN_A)
        self.assertEqual([p['name'] for p in entry['packages']], ['Kept', 'xxxxxxxxxx'])
        self.assertEqual(entry['packages'][1], {'name': 'xxxxxxxxxx', 'version': '', 'arch': '', 'manager': 'windows'})
        self.assertEqual(entry['skipped'], 0)

    def test_only_the_host_itself_can_send_its_list(self):
        body = {'pkg_manager': 'windows', 'packages': [{'name': 'Planted', 'version': '1'}]}
        before = self.stored(WIN_A)
        for ident in ({'device_id': WIN_A, 'token': 'wrong'}, {'device_id': WIN_A, 'token': 'tok-' + MAC_A},
                      {'device_id': 'sinvnosuchhost', 'token': 'tok-' + WIN_A}, {'device_id': WIN_A, 'token': ''},
                      {'device_id': '../etc', 'token': 'x'}):
            status, answer = self.post(dict(body, **ident))
            self.assertEqual(status, 403, ident)
        self.assertEqual(self.stored(WIN_A), before)

    def test_the_list_is_written_under_the_lock_of_the_store(self):
        """Every host sends its list into the one store. A bare load and save lost one of two lists that arrived together,
        and a host whose list does not change is not asked again, so it stayed without one."""
        entered = []
        real = api._LockedUpdate

        def recording(path, non_blocking=False):
            entered.append(Path(str(path)).name)
            return real(path, non_blocking)
        with mock.patch.object(api, '_LockedUpdate', recording):
            self.send(WIN_A, 'windows', WINDOWS[:3])
        self.assertIn(Path(str(api.PACKAGES_FILE)).name, entered)
        self.assertEqual(self.stored(WIN_A)['count'], 3)
        self.assertEqual(self.stored(MAC_A)['count'], len(MAC))          # the other host's list is still there

    def test_the_registry_of_shapes_knows_the_new_fields(self):
        data = {WIN_A: {'collected_at': 5, 'count': 1, 'pkg_manager': 'windows', 'skipped': '12',
                        'packages': [{'name': 'a', 'version': '1', 'publisher': 5, 'installed': 20231030, 'id': 7,
                                      'manager': ['x']}, 'not a row', 5]}}
        fixed = store_shapes.normalize('packages.json', json.loads(json.dumps(data)))
        row = fixed[WIN_A]['packages'][0]
        self.assertEqual((row['publisher'], row['installed'], row['id']), ('5', '20231030', '7'))
        self.assertNotIn('manager', row)                    # not text: removed, so the reader's default applies
        self.assertEqual(len(fixed[WIN_A]['packages']), 1)
        self.assertEqual(fixed[WIN_A]['skipped'], 12)


# ── nothing about such a list reaches the scan ────────────────────────────────────────────────────────────────────────
class TestNoMatcher(_Fleet):
    def asked_nothing(self):
        asked = []

        def boom(*a, **k):
            asked.append(a)
            raise AssertionError('OSV was asked about an application list')
        return asked, mock.patch.object(cve_scanner, '_osv_querybatch', boom), \
            mock.patch.object(cve_scanner, '_osv_vuln_details', boom)

    def worker(self, target=None):
        cache = Path(_tmp('rp-softinv-cache-'))
        asked, q, d = self.asked_nothing()
        with q, d, mock.patch.object(api, 'DATA_DIR', cache):
            api._cve_scan_worker('tester', target)
        api._LOAD_CACHE.clear()
        return asked, api.load(api.CVE_SCAN_STATUS_FILE) or {}

    def test_a_stored_ecosystem_never_makes_such_a_list_a_question(self):
        """A store edited by hand, or restored from a backup, may say Debian:12 for a Windows list."""
        store = api.load(api.PACKAGES_FILE)
        store[WIN_A]['ecosystem'] = 'Debian:12'
        store[MAC_A]['ecosystem'] = 'Ubuntu'
        api.save(api.PACKAGES_FILE, store)
        api._LOAD_CACHE.clear()
        for dev_id in (WIN_A, MAC_A):
            self.assertEqual(cve_scanner.entry_ecosystem(self.stored(dev_id)), '', dev_id)
        asked, q, d = self.asked_nothing()
        lists = {k: v for k, v in api.load(api.PACKAGES_FILE).items() if k in (WIN_A, MAC_A, WIN_B)}
        self.assertEqual(len(lists), 3)
        with q, d:
            plan = cve_scanner.prefetch_osv(lists, Path(_tmp('rp-softinv-pf-')))
        self.assertEqual(plan, {})
        self.assertEqual(asked, [])

    def test_the_scan_skips_such_hosts_and_asks_nothing(self):
        store = api.load(api.PACKAGES_FILE)
        store[WIN_A]['ecosystem'] = 'Debian:12'
        api.save(api.PACKAGES_FILE, store)
        api._LOAD_CACHE.clear()
        asked, status = self.worker(WIN_A)
        self.assertEqual(asked, [])
        self.assertEqual((status.get('scanned'), status.get('skipped'), status.get('errors')), (0, 1, 0), status)
        self.assertNotIn(WIN_A, api.load(api.CVE_FINDINGS_FILE) or {})

    def test_the_scan_of_the_whole_fleet_asks_about_the_linux_host_alone(self):
        asked = []

        def querybatch(queries):
            asked.extend(queries)
            return [{'vulns': []} for _ in queries]
        cache = Path(_tmp('rp-softinv-cache-'))
        with mock.patch.object(cve_scanner, '_osv_querybatch', querybatch), \
                mock.patch.object(cve_scanner, '_osv_vuln_details', lambda vid: None), \
                mock.patch.object(api, 'DATA_DIR', cache):
            api._cve_scan_worker('tester', None)
        api._LOAD_CACHE.clear()
        status = api.load(api.CVE_SCAN_STATUS_FILE) or {}
        self.assertEqual((status.get('scanned'), status.get('skipped'), status.get('errors')), (1, 3, 0), status)
        self.assertEqual({q['package']['ecosystem'] for q in asked}, {'Ubuntu'})
        self.assertTrue(asked)
        names = {q['package']['name'] for q in asked}
        self.assertTrue(names <= {'openssl', 'git', 'nginx'}, names)

    def test_the_page_is_told_the_list_is_not_checked(self):
        self.assertEqual(cve_scanner.entry_coverage(self.stored(WIN_A)), 'no_matcher')
        self.assertEqual(cve_scanner.entry_coverage(self.stored(MAC_A)), 'no_matcher')
        arch = {'ecosystem': '', 'pkg_manager': 'pacman', 'packages': [{'name': 'bash', 'version': '5.2'}]}
        self.assertEqual(cve_scanner.entry_coverage(arch), 'no_matcher')
        for none in ({}, {'ecosystem': '', 'pkg_manager': 'pacman', 'packages': []}, None, 'x', []):
            self.assertEqual(cve_scanner.entry_coverage(none), '', none)
        # a host with an ecosystem keeps the words it always had
        self.assertEqual(cve_scanner.entry_coverage({'ecosystem': 'Ubuntu', 'packages': [{'name': 'a', 'version': '1'}]}),
                         cve_scanner.coverage('Ubuntu', False, ''))

    def test_the_fleet_page_says_not_checked_where_it_said_unsupported(self):
        status, report = self.get(api.handle_cve_findings)
        self.assertEqual(status, 200, report)
        rows = {r['device_id']: r for r in report['devices']}
        self.assertEqual(rows[WIN_A]['status'], 'no_matcher')
        self.assertEqual(rows[MAC_A]['status'], 'no_matcher')
        self.assertEqual(rows[WIN_A]['ecosystem'], 'unsupported')
        self.assertEqual(rows[WIN_A]['package_count'], len(WINDOWS))
        self.assertEqual(rows[LNX_B]['status'], 'not_scanned')
        self.assertEqual(report['summary']['devices_scanned'], 0)
        # an Arch host keeps the word it had
        store = api.load(api.PACKAGES_FILE)
        store[LNX_B] = {'ecosystem': '', 'pkg_manager': 'pacman', 'count': 1, 'packages': [{'name': 'bash', 'version': '5'}]}
        api.save(api.PACKAGES_FILE, store)
        status, report = self.get(api.handle_cve_findings)
        self.assertEqual({r['device_id']: r['status'] for r in report['devices']}[LNX_B], 'unsupported')

    def test_the_host_page_says_nothing_was_checked(self):
        api.save(api.CVE_IGNORE_FILE, {})
        with mock.patch.object(api, 'device_get', lambda dev_id: api.load(api.DEVICES_FILE).get(dev_id)):
            status, view = self.get(api.handle_cve_device, '', WIN_A)
        self.assertEqual(status, 200, view)
        self.assertEqual(view['coverage'], 'no_matcher')
        self.assertEqual(view['findings'], [])
        self.assertEqual(view['packages_count'], len(WINDOWS))
        self.assertEqual(view['ecosystem'], 'unsupported')


# ── what is not for an application ────────────────────────────────────────────────────────────────────────────────────
class TestWhatIsForTheLinuxPackagesOfADistribution(_Fleet):
    def test_a_snapshot_pins_no_application(self):
        pins = api._ps_build_entries()
        self.assertEqual(pins, {'openssl': '3.0.2-0ubuntu1.12', 'git': '1:2.34.1-1ubuntu1.10', 'nginx': '1.18.0-6ubuntu14.4'})
        scoped = api.load(api.PACKAGES_FILE)
        self.assertEqual(sorted(k for k, v in scoped.items() if v['pkg_manager'] == 'windows'), [WIN_A, WIN_B])

    def snapshot(self):
        api.save(api.PATCH_SNAPSHOTS_FILE, {'snap1': {'name': 'golden', 'created': 1, 'entries': {
            'git': '1:2.34.1-1ubuntu1.10', 'Google Chrome': '1.0', 'openssl': '3.0.2-0ubuntu1.12'},
            'entry_count': 3, 'promoted_tag': 'prod'}})
        api._LOAD_CACHE.clear()

    def test_the_drift_report_leaves_the_applications_out(self):
        self.snapshot()
        status, report = self.get(api.handle_patch_snapshot_drift, '', 'snap1')
        self.assertEqual(status, 200, report)
        # a Windows host holds "Google Chrome", a Mac holds a Homebrew "git": neither is a package of the pin
        self.assertEqual(report['devices_drifted'], 0, report)
        self.assertEqual(report['devices_checked'], 1, report)

    def test_enforcing_a_snapshot_queues_nothing_for_an_application_host(self):
        self.snapshot()
        queued = {}
        # the mac host's Homebrew git is 2.43.0, the pin is 1:2.34.1: drift, if the host were read as a distribution's
        with mock.patch.object(api, '_queue_command_map', lambda cmds, actor: queued.update(cmds) or
                               {d: {'ok': True} for d in cmds}):
            status, answer = self.get(api.handle_patch_snapshot_enforce, '', 'snap1', verb='POST')
        self.assertEqual(status, 200, answer)
        self.assertEqual(queued, {})
        for dev_id in (WIN_A, MAC_A):
            self.assertFalse(answer['results'][dev_id]['queued'], dev_id)
            self.assertIn('Windows or macOS', answer['results'][dev_id]['reason'])

    def test_the_install_and_remove_commands_are_for_linux_hosts_only(self):
        queued = {}

        def batch(ids, command, actor, **kw):
            queued.update({i: command for i in ids})
            return {i: {'ok': True} for i in ids}
        for handler in (api.handle_install_packages, api.handle_uninstall_packages):
            queued.clear()
            with mock.patch.object(api, '_queue_command_batch', batch):
                status, answer = self.get(handler, verb='POST',
                                          body={'device_ids': [WIN_A, MAC_A, LNX_B], 'packages': 'teamviewer'})
            self.assertEqual(status, 202, answer)
            self.assertEqual(sorted(queued), [LNX_B])
            for dev_id in (WIN_A, MAC_A):
                self.assertEqual(answer['per_device'][dev_id]['reason'], 'unsupported')
                self.assertFalse(answer['per_device'][dev_id]['queued'])
            self.assertEqual(answer['queued'], 1)


# ── the views ─────────────────────────────────────────────────────────────────────────────────────────────────────────
class TestTheSearch(_Fleet):
    def search(self, query, who='admin'):
        status, answer = getattr(self, {'admin': 'get', 'tenant': 'as_tenant_admin', 'read': 'as_read_only',
                                        'scoped': 'as_scoped'}[who])(api.handle_inventory_search, query)
        self.assertEqual(status, 200, answer)
        return answer

    def rows(self, query, who='admin'):
        return sorted((r['device_name'], r['package'], r['version']) for r in self.search(query, who)['results'])

    def test_a_name_is_found_whatever_its_case(self):
        want = [(MAC_A, 'Google Chrome', '120.0.6099.129'), (WIN_A, 'Google Chrome', '120.0.6099.109')]
        for q in ('chrome', 'CHROME', 'Google Chr', 'google chrome'):
            self.assertEqual(self.rows('q=' + q.replace(' ', '%20')), sorted(want), q)
        self.assertEqual(self.rows('q=safari&exact=1'), [(MAC_A, 'Safari', '17.2')])
        self.assertEqual(self.rows('q=SAFARI&exact=1'), [(MAC_A, 'Safari', '17.2')])
        self.assertEqual(self.rows('q=chrome&exact=1'), [])

    def test_a_dotted_version_is_compared_as_a_number(self):
        def redist(op, version):
            return 'q=visual%20c%2B%2B&op=' + op + '&version=' + version
        self.assertEqual(len(self.rows(redist('lt', '14.40'))), 2)
        self.assertEqual(len(self.rows(redist('lt', '14.9'))), 0)             # text order would call 14.38 below 14.9
        self.assertEqual(len(self.rows(redist('ge', '14.38.33130'))), 2)
        self.assertEqual(len(self.rows(redist('eq', '14.38.33130'))), 2)
        self.assertEqual(len(self.rows(redist('gt', '14.38.33130'))), 0)
        self.assertEqual(self.rows('q=chrome&op=lt&version=120.0.6099.120'), [(WIN_A, 'Google Chrome', '120.0.6099.109')])

    def test_a_version_in_words_is_read_by_its_number_then_as_text_and_never_fails(self):
        win = api.load(api.PACKAGES_FILE)
        win[WIN_A]['packages'].append({'name': 'Odd Tool', 'version': '2023.1 (64-bit)', 'manager': 'windows'})
        win[WIN_A]['packages'].append({'name': 'Odd Tool', 'version': '', 'manager': 'windows'})
        win[WIN_A]['packages'].append({'name': 'Odd Tool', 'version': 'Beta 3', 'manager': 'windows'})
        api.save(api.PACKAGES_FILE, win)
        # a package manager's order reads "Beta 3" and "Alpha 9" as the same version (no digits up front): here they are text,
        # and text has an order, and it is below every version that starts with a number
        self.assertEqual(self.rows('q=odd%20tool&op=gt&version=Alpha%209'),
                         [(WIN_A, 'Odd Tool', '2023.1 (64-bit)'), (WIN_A, 'Odd Tool', 'Beta 3')])
        self.assertEqual(self.rows('q=odd%20tool&op=lt&version=Alpha%209'), [(WIN_A, 'Odd Tool', '')])
        # tuple order would read "2023.1 (64-bit)" as equal to "2023.1": the words after the number keep them apart
        self.assertEqual(self.rows('q=odd%20tool&op=eq&version=2023.1'), [])
        self.assertEqual(self.rows('q=odd%20tool&op=eq&version=2023.1%20(64-bit)'), [(WIN_A, 'Odd Tool', '2023.1 (64-bit)')])
        self.assertEqual([r[2] for r in self.rows('q=odd%20tool&op=ge&version=1.0')],
                         ['2023.1 (64-bit)'])                       # "" and "Beta 3" have no number: they are below 1.0

    def test_a_version_that_starts_with_a_number_is_searched_by_that_number(self):
        win = api.load(api.PACKAGES_FILE)
        win[WIN_A]['packages'].append({'name': 'Odd Tool', 'version': '2.43.0.windows.1', 'manager': 'windows'})
        api.save(api.PACKAGES_FILE, win)
        self.assertEqual(self.rows('q=odd%20tool&op=lt&version=2.100'), [(WIN_A, 'Odd Tool', '2.43.0.windows.1')])
        self.assertEqual(self.rows('q=odd%20tool&op=lt&version=2.9'), [])
        self.assertEqual(self.rows('q=odd%20tool&op=ge&version=2.9'), [(WIN_A, 'Odd Tool', '2.43.0.windows.1')])

    def test_a_linux_search_is_as_it_was(self):
        self.assertEqual(self.rows('q=openssl&op=lt&version=3.0.3'), [(LNX_B, 'openssl', '3.0.2-0ubuntu1.12')])
        self.assertEqual(self.rows('q=openssl&op=ge&version=3.0.3'), [])

    def test_each_caller_sees_its_own_hosts_only(self):
        both = 'q=google%20chrome'
        self.assertEqual({r[0] for r in self.rows(both)}, {WIN_A, MAC_A})
        for who in ('tenant', 'read'):
            self.assertEqual({r[0] for r in self.rows(both, who)}, {WIN_A, MAC_A}, who)
        self.assertEqual({r[0] for r in self.rows('q=teamviewer', 'tenant')}, {WIN_A})
        self.assertEqual({r[0] for r in self.rows('q=7-zip', 'read')}, {WIN_A})                # WIN_B lists it too
        self.assertEqual({r[0] for r in self.rows('q=7-zip')}, {WIN_A, WIN_B})
        # a role scoped to the tag "windows": the Windows host of its tag and nothing else
        self.assertEqual({r[0] for r in self.rows('q=chrome', 'scoped')}, {WIN_A})
        self.assertEqual(self.rows('q=safari', 'scoped'), [])
        self.assertEqual(self.rows('q=openssl', 'scoped'), [])

    def test_the_other_tenants_names_are_not_in_the_answer(self):
        for who in ('tenant', 'read'):
            text = json.dumps(self.search('q=', who)) + json.dumps(self.search('q=e', who))
            self.assertNotIn(WIN_B, text, who)
            self.assertNotIn(LNX_B, text, who)


class TestTheSoftwareCenter(_Fleet):
    def catalog(self, who='get', query=''):
        status, answer = getattr(self, who)(api.handle_inventory_catalog, query)
        self.assertEqual(status, 200, answer)
        return {r['package']: r for r in answer['packages']}, answer

    def test_a_title_is_one_row_however_hosts_spell_it(self):
        rows, answer = self.catalog()
        git_rows = [k for k in rows if k.lower() == 'git']
        self.assertEqual(len(git_rows), 1, sorted(rows))
        row = rows[git_rows[0]]
        # the Linux host's git (exact name), the Windows host's Git and the other's GIT, a Mac's Homebrew git
        self.assertEqual(row['hosts'], 4)
        self.assertEqual(row['package'], 'git')           # a distribution's own spelling wins the name
        self.assertEqual(row['version_count'], 4)

    def test_the_commonest_spelling_names_a_row_no_distribution_has(self):
        store = api.load(api.PACKAGES_FILE)
        for p in store[WIN_A]['packages']:
            if p['name'] == 'Google Chrome':
                p['name'] = 'GOOGLE chrome'
        store[WIN_B]['packages'].append({'name': 'Google Chrome', 'version': '119.0', 'manager': 'windows'})
        api.save(api.PACKAGES_FILE, store)
        rows, _ = self.catalog(query='q=google')
        self.assertEqual(sorted(rows), ['Google Chrome'])                  # two hosts write it so, one writes it GOOGLE chrome
        self.assertEqual(rows['Google Chrome']['hosts'], 3)
        self.assertEqual(rows['Google Chrome']['version_count'], 3)

    def test_a_title_is_found_by_part_of_it_in_any_case(self):
        rows, _ = self.catalog(query='q=VISUAL%20C')
        self.assertEqual(sorted(rows), ['Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33130',
                                        'Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.38.33130'])

    def test_a_version_that_is_empty_has_a_dash(self):
        store = api.load(api.PACKAGES_FILE)
        store[WIN_A]['packages'].append({'name': 'Quiet App', 'version': '', 'manager': 'windows'})
        api.save(api.PACKAGES_FILE, store)
        rows, _ = self.catalog(query='q=quiet')
        self.assertEqual([v['version'] for v in rows['Quiet App']['versions']], ['—'])

    def test_each_caller_counts_its_own_hosts(self):
        for who in ('as_tenant_admin', 'as_read_only'):
            rows, answer = self.catalog(who, 'q=7-zip')
            self.assertEqual({k: v['hosts'] for k, v in rows.items()}, {'7-Zip 23.01 (x64)': 1}, who)
            self.assertNotIn(WIN_B, json.dumps(answer))
        rows, _ = self.catalog('as_scoped', 'q=chrome')
        self.assertEqual(rows['Google Chrome']['hosts'], 1)
        self.assertNotIn(MAC_A, json.dumps(rows))


class TestTheMetering(_Fleet):
    METERS = [{'name': 'google chrome', 'limit': 1}, {'name': 'nginx', 'limit': 5}, {'name': 'TeamViewer', 'limit': 0}]

    def meter(self, who='get', meters=None):
        status, answer = getattr(self, who)(api.handle_inventory_metering,
                                            config={'software_meters': meters or self.METERS})
        self.assertEqual(status, 200, answer)
        return {m['name']: m for m in answer['meters']}

    def test_applications_are_counted_by_a_name_in_any_case(self):
        meters = self.meter()
        self.assertEqual(meters['google chrome']['installed'], 2)           # a Windows host and a Mac
        self.assertTrue(meters['google chrome']['over'])
        self.assertEqual(sorted(meters['google chrome']['devices']), sorted([WIN_A, MAC_A]))
        self.assertEqual(sorted(meters['TeamViewer']['devices']), [WIN_A])
        self.assertEqual(sorted(meters['nginx']['devices']), [LNX_B])

    def test_a_title_is_not_a_process_so_an_application_is_never_reclaimable(self):
        """Google Chrome is installed under that title and runs as chrome.exe. Compared with the process list, every
        Windows and macOS host would be one that does not use what it has installed."""
        meters = self.meter()
        self.assertEqual(meters['google chrome']['reclaimable'], 0, meters['google chrome'])
        self.assertEqual(meters['TeamViewer']['reclaimable'], 0)
        # the control: the Linux host has a process list, and nginx is not in it
        self.assertEqual(meters['nginx']['reclaimable'], 1)
        self.assertEqual(meters['nginx']['reclaim_hosts'], [LNX_B])

    def test_a_homebrew_package_can_be_a_process(self):
        meters = self.meter(meters=[{'name': 'wget', 'limit': 0}])
        self.assertEqual(meters['wget']['reclaimable'], 1)        # wget is not among the processes of the Mac
        self.assertEqual(meters['wget']['reclaim_hosts'], [MAC_A])

    def test_each_caller_counts_its_own_hosts(self):
        for who in ('as_tenant_admin', 'as_read_only'):
            meters = self.meter(who)
            self.assertEqual(sorted(meters['google chrome']['devices']), sorted([WIN_A, MAC_A]), who)
            self.assertEqual(meters['nginx']['installed'], 0, who)          # the Linux host is the other tenant's


class TestThePolicy(_Fleet):
    RULES = [
        {'id': 'r1', 'type': 'banned', 'package': 'teamviewer'},
        {'id': 'r2', 'type': 'required', 'package': 'fail2ban'},
        {'id': 'r3', 'type': 'required', 'package': 'microsoft defender antivirus', 'tags': ['windows']},
        {'id': 'r4', 'type': 'min_version', 'package': 'GOOGLE CHROME', 'version': '121.0'},
        {'id': 'r5', 'type': 'min_version', 'package': 'Microsoft Edge', 'version': '120.0.2210.9'},
        {'id': 'r6', 'type': 'min_version', 'package': 'Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33130',
         'version': '14.9'},
        {'id': 'r7', 'type': 'banned', 'package': 'wget'},
        {'id': 'r8', 'type': 'min_version', 'package': 'openssl', 'version': '3.1'},
    ]

    def evaluate(self, rules=None):
        api.save(api.SOFTWARE_POLICY_FILE, {'rules': rules if rules is not None else self.RULES})
        api.save(api.SOFTWARE_VIOLATIONS_FILE, {})
        api._LOAD_CACHE.clear()
        self.events.clear()
        api._reeval_software_policy_all()
        api._LOAD_CACHE.clear()
        store = api.load(api.SOFTWARE_VIOLATIONS_FILE) or {}
        return {d: {v['rule_id']: v for v in rec['violations']} for d, rec in store.items()}

    def test_a_windows_host_is_judged_by_its_titles(self):
        found = self.evaluate()
        win = found[WIN_A]
        self.assertEqual(sorted(win), ['r1', 'r3', 'r4'])
        self.assertEqual(win['r1']['found'], '15.49.2')                    # rule `teamviewer`, installed as `TeamViewer`
        self.assertEqual(win['r3']['found'], 'missing')
        self.assertEqual(win['r4']['found'], '120.0.6099.109')
        self.assertEqual(win['r4']['expected'], '>= 121.0')
        # Edge is above 120.0.2210.9 as a number (2210.91 is 91 above 9), and 14.38 is not below 14.9 in text but is as a number
        self.assertNotIn('r5', win)
        self.assertNotIn('r6', win)

    def test_a_version_below_a_minimum_as_a_number_not_as_text(self):
        rules = [{'id': 'v', 'type': 'min_version', 'package': 'Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33130',
                  'version': '14.40'}]
        self.assertIn('v', self.evaluate(rules)[WIN_A])
        rules[0]['version'] = '14.9'
        self.assertNotIn(WIN_A, self.evaluate(rules))                      # 14.38 is above 14.9, though "14.3" sorts below "14.9"

    def test_an_application_a_host_holds_twice_is_judged_by_its_highest_version(self):
        """A host can hold two versions of one title: a runtime kept beside its successor, a Homebrew formula and a cask of one name."""
        store = api.load(api.PACKAGES_FILE)
        store[WIN_A]['packages'] += [{'name': 'Runtime Tool', 'version': '1.0', 'manager': 'windows'},
                                     {'name': 'RUNTIME TOOL', 'version': '3.0', 'manager': 'windows'},
                                     {'name': 'Runtime Tool', 'version': '2.0', 'manager': 'windows'}]
        api.save(api.PACKAGES_FILE, store)
        rules = [{'id': 'm', 'type': 'min_version', 'package': 'runtime tool', 'version': '2.5'}]
        self.assertNotIn(WIN_A, self.evaluate(rules))                    # 3.0 is above 2.5, though 1.0 and 2.0 are not
        rules[0]['version'] = '3.5'
        self.assertEqual(self.evaluate(rules)[WIN_A]['m']['found'], '3.0')       # and the highest is the one that is shown

    def test_a_version_in_words_is_compared_as_text(self):
        store = api.load(api.PACKAGES_FILE)
        store[WIN_A]['packages'].append({'name': 'Build Tool', 'version': '2023.4 (build 9)', 'manager': 'windows'})
        api.save(api.PACKAGES_FILE, store)
        rules = [{'id': 'b', 'type': 'min_version', 'package': 'Build Tool', 'version': '2023.4 (build 10)'}]
        # as numbers (2023, 4, 9) is below (2023, 4, 10); as the text it is, "9" is above "10"
        self.assertNotIn(WIN_A, self.evaluate(rules))

    def test_a_version_that_starts_with_a_number_is_judged_by_that_number(self):
        """The Git of the sample is 2.43.0.windows.1. Read as text it is below a minimum of 2.9 and above one of 2.100."""
        def verdict(minimum):
            return 'g' in self.evaluate([{'id': 'g', 'type': 'min_version', 'package': 'Git', 'version': minimum}]).get(WIN_A, {})
        self.assertFalse(verdict('2.9'))
        self.assertFalse(verdict('2.43'))
        self.assertTrue(verdict('2.100'))
        self.assertTrue(verdict('10.0'))

    def test_the_verdict_does_not_depend_on_the_order_of_the_rows(self):
        """One program listed three times: 2.10, 2.9 and "2.5 beta". With an order that had a cycle, the highest the policy kept
        was the last the running maximum ended on, so the same list gave two verdicts depending on how the agent sorted it."""
        rows = [{'name': 'Foo', 'version': v, 'manager': 'windows'} for v in ('2.10', '2.9', '2.5 beta')]
        api.save(api.SOFTWARE_POLICY_FILE, {'rules': [{'id': 'm', 'type': 'min_version', 'package': 'Foo', 'version': '2.20'},
                                                      {'id': 'ok', 'type': 'min_version', 'package': 'Foo', 'version': '2.8'}]})
        for perm in itertools.permutations(rows):
            self.send(WIN_A, 'windows', list(perm))
            api._LOAD_CACHE.clear()
            found = {v['rule_id']: v for v in api.load(api.SOFTWARE_VIOLATIONS_FILE)[WIN_A]['violations']}
            self.assertEqual(sorted(found), ['m'], [r['version'] for r in perm])        # below 2.20, not below 2.8
            self.assertEqual(found['m']['found'], '2.10', [r['version'] for r in perm])  # the highest of the three, always

    def test_a_required_rule_with_no_tags_is_for_linux_hosts(self):
        found = self.evaluate()
        self.assertNotIn('r2', found[WIN_A])
        self.assertNotIn('r2', found[MAC_A])
        self.assertNotIn('r2', found.get(WIN_B, {}))
        self.assertIn('r2', found[LNX_B])                                 # the control: it is judged where it was written for
        self.assertEqual(found[LNX_B]['r2']['found'], 'missing')

    def test_a_required_rule_with_a_tag_is_judged_on_a_host_of_the_tag(self):
        found = self.evaluate()
        self.assertIn('r3', found[WIN_A])
        self.assertNotIn(WIN_B, found)             # carries no tag "windows": the rule is not for it

    def test_a_homebrew_package_is_found_by_its_name_on_a_mac(self):
        found = self.evaluate()
        self.assertEqual(found[MAC_A]['r7']['found'], '1.21.4')
        self.assertNotIn('r8', found[MAC_A])

    def test_a_linux_host_is_judged_as_it_was(self):
        found = self.evaluate()
        self.assertEqual(sorted(found[LNX_B]), ['r2', 'r8'])
        self.assertEqual(found[LNX_B]['r8']['found'], '3.0.2-0ubuntu1.12')
        # names of a distribution are still matched exactly
        self.assertNotIn('r1', found[LNX_B])
        self.assertEqual(self.evaluate([{'id': 'x', 'type': 'banned', 'package': 'OpenSSL'}]).get(LNX_B), None)
        self.assertIn('x', self.evaluate([{'id': 'x', 'type': 'banned', 'package': 'openssl'}])[LNX_B])

    def test_a_violation_of_an_application_host_says_so_for_the_page(self):
        self.evaluate()
        status, answer = self.get(api.handle_software_policy_violations)
        self.assertEqual(status, 200, answer)
        by = {(v['device_id'], v['rule_id']): v for v in answer['violations']}
        self.assertEqual(by[(WIN_A, 'r1')]['manager'], 'windows')
        self.assertEqual(by[(MAC_A, 'r7')]['manager'], 'macos')
        self.assertNotIn('manager', by[(LNX_B, 'r2')])
        for who in ('as_tenant_admin', 'as_read_only'):
            status, answer = getattr(self, who)(api.handle_software_policy_violations)
            hosts = {v['device_id'] for v in answer['violations']}
            self.assertEqual(hosts, {WIN_A, MAC_A}, who)
        status, answer = self.as_scoped(api.handle_software_policy_violations)
        self.assertEqual({v['device_id'] for v in answer['violations']}, {WIN_A})

    def test_a_new_list_is_judged_the_moment_it_arrives_and_an_alert_goes_with_it(self):
        api.save(api.SOFTWARE_POLICY_FILE, {'rules': self.RULES[:1]})
        api.save(api.SOFTWARE_VIOLATIONS_FILE, {})
        self.events.clear()
        self.send(WIN_A, 'windows', WINDOWS)
        self.assertEqual([(e, p['package'], p['name']) for e, p in self.events if e == 'software_policy_violation'],
                         [('software_policy_violation', 'teamviewer', WIN_A)])
        self.events.clear()
        self.send(WIN_A, 'windows', [r for r in WINDOWS if r['name'] != 'TeamViewer'])
        self.assertEqual([e for e, _ in self.events], ['policy_compliant'])

    def test_a_required_rule_with_no_tags_is_not_judged_when_a_windows_or_mac_list_arrives(self):
        """The rule as it is applied at the ingest, which is where the first list of every Windows host meets it. Read as the
        packages of a distribution, that list would break `required: fail2ban` on every Windows host the day its agent starts to
        send one, and nothing would say why. The other tests of the rule go through the re-check of the stored lists."""
        api.save(api.SOFTWARE_POLICY_FILE, {'rules': [self.RULES[1]]})            # required fail2ban, no tags
        api.save(api.SOFTWARE_VIOLATIONS_FILE, {})
        self.events.clear()
        self.send(WIN_A, 'windows', WINDOWS)
        self.send(MAC_A, 'macos', MAC)
        self.assertEqual(self.events, [])
        api._LOAD_CACHE.clear()
        self.assertEqual(api.load(api.SOFTWARE_VIOLATIONS_FILE) or {}, {})
        # the control: the same rule is judged where it was written for, when a Linux list arrives
        self.send(LNX_B, 'apt', LINUX, hint={'ID': 'ubuntu', 'VERSION_ID': '22.04', 'ID_LIKE': 'debian'})
        self.assertEqual([(e, p['package'], p['name']) for e, p in self.events],
                         [('software_policy_violation', 'fail2ban', LNX_B)])


class TestTheSbom(_Fleet):
    def dev(self, dev_id):
        return dict(api.load(api.DEVICES_FILE)[dev_id], id=dev_id)

    def test_an_application_is_a_generic_component_with_its_publisher(self):
        doc = sbom.build_cyclonedx(self.dev(WIN_A), self.stored(WIN_A), [])
        by = {c['name']: c for c in doc['components']}
        chrome = by['Google Chrome']
        self.assertEqual(chrome['purl'], 'pkg:generic/Google%20Chrome@120.0.6099.109')
        self.assertEqual(chrome['type'], 'application')
        self.assertEqual(chrome['version'], '120.0.6099.109')       # the purl is built from the version apart: it stays right without it
        self.assertEqual(by['7-Zip 23.01 (x64)']['version'], '23.01')
        props = {p['name']: p['value'] for p in chrome['properties']}
        self.assertEqual(props['remotepower:publisher'], 'Google LLC')
        self.assertEqual((props['remotepower:arch'], props['remotepower:installed'], props['remotepower:manager']),
                         ('x64', '2023-12-15', 'windows'))
        self.assertEqual(by['Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33130']['purl'],
                         'pkg:generic/Microsoft%20Visual%20C%2B%2B%202015-2022%20Redistributable%20%28x64%29%20-%2014.38.33130@14.38.33130.0')
        self.assertEqual(len(doc['components']), len(WINDOWS))
        self.assertNotIn('vulnerabilities', doc)
        self.assertEqual(doc['metadata']['component']['properties'][1]['value'], '')

    def test_a_mac_has_applications_and_homebrew_packages_under_one_namespace(self):
        doc = sbom.build_cyclonedx(self.dev(MAC_A), self.stored(MAC_A), [])
        by = {c['name']: c for c in doc['components']}
        self.assertEqual(by['wget']['purl'], 'pkg:generic/wget@1.21.4')
        self.assertEqual(by['Safari']['purl'], 'pkg:generic/Safari@17.2')
        self.assertEqual({p['name']: p['value'] for p in by['Safari']['properties']}['remotepower:id'], 'com.apple.Safari')
        self.assertEqual({p['name']: p['value'] for p in by['wget']['properties']}['remotepower:manager'], 'brew')
        self.assertEqual((by['Safari']['version'], by['wget']['version']), ('17.2', '1.21.4'))
        spdx = {p['name']: p for p in sbom.build_spdx(self.dev(MAC_A), self.stored(MAC_A), [])['packages']}
        self.assertEqual((spdx['Safari']['versionInfo'], spdx['wget']['versionInfo']), ('17.2', '1.21.4'))

    def test_a_program_with_no_version_is_still_there(self):
        store = self.stored(WIN_A)
        store['packages'].append({'name': 'No Version App', 'version': '', 'manager': 'windows', 'publisher': 'Acme'})
        doc = sbom.build_cyclonedx(self.dev(WIN_A), store, [])
        comp = next(c for c in doc['components'] if c['name'] == 'No Version App')
        self.assertEqual(comp['purl'], 'pkg:generic/No%20Version%20App')
        self.assertNotIn('version', comp)
        spdx = sbom.build_spdx(self.dev(WIN_A), store, [])
        pkg = next(p for p in spdx['packages'] if p['name'] == 'No Version App')
        self.assertNotIn('versionInfo', pkg)
        self.assertEqual(pkg['supplier'], 'Organization: Acme')

    def test_spdx_names_the_publisher_as_the_supplier(self):
        spdx = sbom.build_spdx(self.dev(WIN_A), self.stored(WIN_A), [])
        by = {p['name']: p for p in spdx['packages']}
        self.assertEqual(by['Google Chrome']['supplier'], 'Organization: Google LLC')
        self.assertEqual(by['Google Chrome']['externalRefs'][0]['referenceLocator'], 'pkg:generic/Google%20Chrome@120.0.6099.109')
        self.assertEqual(by['Google Chrome']['versionInfo'], '120.0.6099.109')
        self.assertEqual(by['7-Zip 23.01 (x64)']['versionInfo'], '23.01')
        self.assertNotIn('supplier', by['Windows Driver Package - Intel (e1dexpress) Net'])

    def test_every_version_of_the_stored_list_is_in_both_documents_and_a_missing_one_is_left_out(self):
        """Derived from the list the host sent, not from the rows a test remembers: the version of each row is in the
        component and in the package, and a row that has none has no `version` and no `versionInfo` at all."""
        for dev_id in (WIN_A, MAC_A):
            store = self.stored(dev_id)
            store['packages'] = store['packages'] + [{'name': 'No Version App', 'version': '', 'manager': store['pkg_manager']}]
            want = sorted((p['name'], p['version'] or None) for p in store['packages'])
            self.assertGreater(len([1 for _, v in want if v]), 3)
            self.assertEqual(len([1 for _, v in want if not v]), 1)
            doc = sbom.build_cyclonedx(self.dev(dev_id), store, [])
            self.assertEqual(sorted((c['name'], c.get('version')) for c in doc['components']), want, dev_id)
            spdx = sbom.build_spdx(self.dev(dev_id), store, [])
            self.assertEqual(sorted((q['name'], q.get('versionInfo')) for q in spdx['packages']
                                    if q['SPDXID'].startswith('SPDXRef-Package-')), want, dev_id)

    def test_a_document_says_how_many_entries_were_left_out_of_the_list(self):
        """The list of a Windows host is not all that is installed: updates and system components are left out, and a document that
        does not say so is read as if it were whole."""
        doc = sbom.build_cyclonedx(self.dev(WIN_A), self.stored(WIN_A), [])
        props = {p['name']: p['value'] for p in doc['metadata']['component']['properties']}
        self.assertEqual(props['remotepower:left_out'], '41')
        self.assertIn('41 entries', sbom.build_spdx(self.dev(WIN_A), self.stored(WIN_A), [])['creationInfo']['comment'])
        # nothing left out, nothing said; and a Linux list says nothing, whatever a hand-edited store holds
        for dev_id in (MAC_A, LNX_B):
            entry = self.stored(dev_id)
            if dev_id == LNX_B:
                entry['skipped'] = 12
            props = {p['name'] for p in sbom.build_cyclonedx(self.dev(dev_id), entry, [])['metadata']['component']['properties']}
            self.assertNotIn('remotepower:left_out', props, dev_id)
            self.assertNotIn('comment', sbom.build_spdx(self.dev(dev_id), entry, [])['creationInfo'], dev_id)
        for odd in (True, '41', -3, 4.5, None):
            entry = dict(self.stored(WIN_A), skipped=odd)
            props = {p['name'] for p in sbom.build_cyclonedx(self.dev(WIN_A), entry, [])['metadata']['component']['properties']}
            self.assertNotIn('remotepower:left_out', props, odd)

    def test_a_linux_component_is_as_it_was(self):
        doc = sbom.build_cyclonedx(self.dev(LNX_B), self.stored(LNX_B), [])
        openssl = next(c for c in doc['components'] if c['name'] == 'openssl')
        self.assertEqual(openssl['type'], 'library')
        self.assertEqual(openssl['purl'], 'pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.12?arch=amd64')
        self.assertEqual(openssl['properties'], [{'name': 'remotepower:arch', 'value': 'amd64'}])
        self.assertNotIn('supplier', sbom.build_spdx(self.dev(LNX_B), self.stored(LNX_B), [])['packages'][1])

    def test_the_download_of_a_host_and_of_the_fleet(self):
        for fmt in ('cyclonedx', 'spdx'):
            doc = api._build_sbom_doc(WIN_A, self.dev(WIN_A), fmt)
            self.assertTrue(json.dumps(doc))
        for dev_id in (WIN_A, MAC_A):
            self.assertTrue(api._build_sbom_doc(dev_id, self.dev(dev_id), 'cyclonedx')['components'])


class TestTheSbomChanges(_Fleet):
    """Baseline and Changes since baseline read the list of a host by name. A program of a Windows host that writes no version
    is installed all the same, and one that is added or removed after the baseline has to show in the changes."""

    def setUp(self):
        super().setUp()
        api.save(api.SBOM_BASELINE_FILE, {})
        self.addCleanup(lambda: api.save(api.SBOM_BASELINE_FILE, {}))

    def baseline(self, dev_id):
        status, answer = self.get(api.handle_sbom_baseline, '', dev_id, verb='POST')
        self.assertEqual(status, 200, answer)
        return answer

    def changes(self, dev_id):
        status, answer = self.get(api.handle_sbom_diff, '', dev_id)
        self.assertEqual(status, 200, answer)
        return answer

    def test_a_program_that_writes_no_version_is_in_the_baseline_and_in_the_changes(self):
        self.send(WIN_A, 'windows', WINDOWS + [{'name': 'Quiet App', 'version': '', 'publisher': 'Acme'}])
        self.assertEqual(self.baseline(WIN_A)['count'], len(WINDOWS) + 1)
        # it goes, and another that writes no version comes
        self.send(WIN_A, 'windows', WINDOWS + [{'name': 'Other Quiet App', 'version': ''}])
        report = self.changes(WIN_A)
        self.assertEqual(report['added'], [{'name': 'Other Quiet App', 'version': ''}])
        self.assertEqual(report['removed'], [{'name': 'Quiet App', 'version': ''}])
        self.assertEqual(report['counts'], {'added': 1, 'removed': 1, 'changed': 0})

    def test_a_list_of_programs_that_write_no_version_has_a_baseline(self):
        self.send(WIN_B, 'windows', [{'name': 'Only Quiet App', 'version': ''}])
        self.assertEqual(self.baseline(WIN_B)['count'], 1)

    def test_a_name_that_two_rows_share_is_compared_by_its_highest_version(self):
        """Homebrew keeps the old version beside the new one. The agent sorts its rows as text, so the last of node 10.0, 11.0
        and 9.0 is 9.0: read by the last row, the arrival of 11.0 would show as no change."""
        rows = [r for r in MAC if r['name'] != 'wget']

        def node(*versions):
            return rows + [{'name': 'node', 'version': v, 'manager': 'brew'} for v in versions]
        self.send(MAC_A, 'macos', node('10.0', '9.0'))
        self.baseline(MAC_A)
        self.send(MAC_A, 'macos', node('10.0', '11.0', '9.0'))
        report = self.changes(MAC_A)
        self.assertEqual(report['changed'], [{'name': 'node', 'from': '10.0', 'to': '11.0'}])
        self.assertEqual(report['counts'], {'added': 0, 'removed': 0, 'changed': 1})

    def test_the_highest_row_of_a_name_does_not_depend_on_the_order_of_the_rows(self):
        for perm in itertools.permutations(('2.10', '2.9', '2.5 beta')):
            self.send(WIN_A, 'windows', [{'name': 'Foo', 'version': v} for v in perm])
            api._LOAD_CACHE.clear()
            self.assertEqual(api._sbom_pkg_index(WIN_A)[0]['Foo'], '2.10', perm)

    def test_a_linux_host_is_read_as_it_was(self):
        """The control: a package with no version is not one of a Linux list (the ingest drops it, and a store edited by hand
        or written by an old release may hold it), and it stays out of the index."""
        store = api.load(api.PACKAGES_FILE)
        store[LNX_B]['packages'].append({'name': 'no-version', 'version': '', 'arch': 'amd64'})
        api.save(api.PACKAGES_FILE, store)
        self.assertEqual(self.baseline(LNX_B)['count'], len(LINUX))
        api._LOAD_CACHE.clear()
        self.assertNotIn('no-version', api.load(api.SBOM_BASELINE_FILE)[LNX_B]['packages'])


class TestTheExplorer(_Fleet):
    def test_a_row_says_which_manager_and_publisher_it_has(self):
        with mock.patch.object(api, 'verify_token', lambda tok=None: ('root', 'admin')):
            rows = api._qe_packages_rows()
        chrome = [r for r in rows if r['package'] == 'Google Chrome' and r['device_id'] == WIN_A]
        self.assertEqual(chrome, [{'device_id': WIN_A, 'device_name': WIN_A, 'package': 'Google Chrome',
                                   'version': '120.0.6099.109', 'ecosystem': '', 'manager': 'windows',
                                   'publisher': 'Google LLC', 'installed': '2023-12-15'}])
        wget = next(r for r in rows if r['package'] == 'wget')
        self.assertEqual((wget['manager'], wget['publisher']), ('brew', ''))
        openssl = next(r for r in rows if r['package'] == 'openssl')
        self.assertEqual((openssl['ecosystem'], openssl['manager']), ('Ubuntu', ''))
        self.assertEqual(sorted(api._QE_PACKAGE_FIELDS), sorted(
            ['device_id', 'device_name', 'package', 'version', 'ecosystem', 'manager', 'publisher', 'installed']))


if __name__ == '__main__':
    unittest.main()

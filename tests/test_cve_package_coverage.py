"""Each package a host listed is checked, or has one reason it was not (8.0.2).

A CVE scan said what it found, and "none found" read as "clean" for packages that were never asked about: a Debian host whose
agent does not send source packages (the advisories are filed under the source, so `libc6` answers nothing), an Ubuntu
derivative whose release is not known, the applications of a Windows host, an Arch host. The scan now keeps, on the host's
record, how many of the packages it listed were checked and, for the others, one reason each (`cve_fixes.REASONS`), with the
first 200 of them by name. Every text that says "no CVEs" says what it found in the packages that could be checked.

The scans here are real scans (`cve_scanner.scan_device`, and the real worker over a fleet) against the recordings of
api.osv.dev in tests/data, and the readers are the real handlers, tools and builders, called as a tenant administrator and as a
read-only user where they are scoped. What the page does with the block is in tests/test_cve_package_coverage_page.py.
"""
import importlib.util
import json
import os
import re
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


os.environ.setdefault('RP_DATA_DIR', _tmp('rp-cov-'))
_spec = importlib.util.spec_from_file_location('api_cve_package_coverage', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
cve_scanner = api.cve_scanner
cve_fixes = api.cve_fixes

import mcp_http  # noqa: E402
import sbom  # noqa: E402
import store_shapes  # noqa: E402
from osv_recording import BEHIND, DEB, UBU, Database  # noqa: E402

_mcp_spec = importlib.util.spec_from_file_location('rp_mcp_coverage', ROOT / 'mcp' / 'remotepower-mcp.py')
sidecar = importlib.util.module_from_spec(_mcp_spec)
_mcp_spec.loader.exec_module(sidecar)


def tearDownModule():
    for d in _TMP:
        shutil.rmtree(d, ignore_errors=True)


# what a Debian 12 host asked about by source, and the three packages of it that an older agent lists by name
DEBIAN_12 = {'ID': 'debian', 'VERSION_ID': '12', 'ID_LIKE': ''}
BY_NAME = [{'name': p['name'], 'version': p['version'], 'arch': p['arch']} for p in BEHIND
           if p['name'] in ('libc6', 'openssh-server')] + [
    {'name': 'sudo', 'version': '1.9.13p3-1+deb12u1', 'arch': 'amd64'}]
WINDOWS = [{'name': f'Program {i}', 'version': '1.0', 'publisher': 'Acme', 'arch': 'x64', 'manager': 'windows'}
           for i in range(8)]
ARCH = [{'name': 'bash', 'version': '5.2.021-1', 'arch': 'x86_64'}]


def scan(recording, packages, ecosystem, **kw):
    """A real scan against a recording of the data source. The tracker is not asked."""
    db = Database(recording)
    with mock.patch.object(cve_scanner, '_osv_querybatch', db.querybatch), \
            mock.patch.object(cve_scanner, '_osv_vuln_details', db.details), \
            mock.patch.object(cve_scanner, '_debian_severity_fallback', lambda cve: None):
        result = cve_scanner.scan_device('h', packages, ecosystem, Path(_tmp('rp-cov-scan-')), **kw)
    assert 'error' not in result, result.get('error')
    return result


def no_findings(queries):
    """A data source that knows no advisory for anything."""
    return [{'vulns': []} for _ in queries]


def scan_with(querybatch, packages, ecosystem, **kw):
    with mock.patch.object(cve_scanner, '_osv_querybatch', querybatch), \
            mock.patch.object(cve_scanner, '_osv_vuln_details', lambda vid: None):
        return cve_scanner.scan_device('h', packages, ecosystem, Path(_tmp('rp-cov-scan-')), **kw)


def without_rows(block):
    return {k: v for k, v in block.items() if k != 'packages'}


def adds_up(test, block):
    """The numbers of a block say one thing: the packages listed are the checked and the not checked, the reasons are the
    not checked, and the rows and the rows left out are the not checked too."""
    test.assertEqual(block['checked'] + block['not_checked'], block['listed'], block)
    test.assertEqual(sum(block['reasons'].values()), block['not_checked'], block)
    test.assertEqual(len(block['packages']) + block['more'], block['not_checked'], block)
    test.assertLessEqual(len(block['packages']), cve_fixes.MAX_NOT_CHECKED_LISTED)
    test.assertTrue(set(block['reasons']) <= set(cve_fixes.REASONS), block)
    test.assertTrue(all(r['reason'] in block['reasons'] for r in block['packages']), block)


class TestTheReasonsAreAFixedSet(unittest.TestCase):
    def test_the_set(self):
        self.assertEqual(cve_fixes.REASONS, ('no_source', 'no_matcher', 'no_release', 'ceiling', 'unanswered'))
        self.assertEqual(sorted(cve_fixes.REASON_WORDS), sorted(cve_fixes.REASONS))
        self.assertEqual(cve_fixes.MAX_NOT_CHECKED_LISTED, 200)


class TestAScanSaysWhatItChecked(unittest.TestCase):
    def test_every_package_of_a_host_asked_by_source_is_checked(self):
        result = scan(DEB, BEHIND, 'Debian:12', has_meta=True)
        self.assertEqual(without_rows(result['covered']),
                         {'listed': 6, 'checked': 6, 'not_checked': 0, 'reasons': {}, 'more': 0})
        self.assertEqual(result['covered']['packages'], [])
        adds_up(self, result['covered'])

    def test_a_list_without_source_names_is_checked_only_where_the_name_is_the_source(self):
        """`libc6` and `openssh-server` are asked for by their own names, which the data does not know: it answers
        nothing, which is what a clean package answers too. `sudo` is its own source, and its answer names advisories."""
        result = scan(DEB, BY_NAME, 'Debian:12', has_meta=False)
        block = result['covered']
        self.assertEqual((block['listed'], block['checked'], block['not_checked']), (3, 1, 2))
        self.assertEqual(block['reasons'], {'no_source': 2})
        self.assertEqual([(r['name'], r['reason']) for r in block['packages']],
                         [('libc6', 'no_source'), ('openssh-server', 'no_source')])
        self.assertEqual(block['packages'][0]['version'], '2.36-9+deb12u3')
        adds_up(self, block)
        self.assertEqual(cve_scanner.coverage('Debian:12', False), 'needs_agent')

    def test_the_same_list_from_an_agent_that_names_sources_is_all_checked(self):
        """The control: the reason is the list, not the packages."""
        named = [p for p in BEHIND if p['name'] in ('libc6', 'openssh-server', 'sudo')]
        self.assertEqual(scan(DEB, named, 'Debian:12', has_meta=True)['covered']['not_checked'], 0)

    def test_a_derivative_whose_release_is_not_known_is_asked_by_name(self):
        packages = [{'name': 'libc6', 'version': '2.35-0ubuntu3.6', 'source': 'glibc'},
                    {'name': 'openssh-server', 'version': '1:8.9p1-3ubuntu0.6', 'source': 'openssh'},
                    {'name': 'sudo', 'version': '1.9.9-1ubuntu2.4'}]
        self.assertEqual(cve_scanner.coverage('Ubuntu', True, ''), 'no_release')
        block = scan(UBU, packages, 'Ubuntu', has_meta=True)['covered']
        self.assertEqual((block['listed'], block['checked']), (3, 1))
        self.assertEqual(block['reasons'], {'no_release': 2})
        adds_up(self, block)
        # and with the release it is asked by source, and all of it is checked
        known = scan(UBU, packages, 'Ubuntu', has_meta=True, release='Ubuntu:22.04:LTS')['covered']
        self.assertEqual((known['checked'], known['not_checked']), (3, 0))

    def test_with_neither_the_source_names_come_first(self):
        """The word of the host says needs_agent before no_release: updating the agent is what helps."""
        packages = [{'name': 'libc6', 'version': '2.35-0ubuntu3.6'}]
        self.assertEqual(cve_scanner.coverage('Ubuntu', False, ''), 'needs_agent')
        self.assertEqual(scan(UBU, packages, 'Ubuntu', has_meta=False)['covered']['reasons'], {'no_source': 1})

    def test_the_keys_an_rpm_host_has_imported_are_not_packages_and_do_not_stop_it_reading_clean(self):
        """rpm -qa lists every GPG key in the database of the host as a package named gpg-pubkey. Counted as packages that were
        not checked they made every RPM host read "none found in the packages that could be checked", however well it was
        patched."""
        packages = [{'name': 'bash', 'version': '5.1.8-9.el9', 'arch': 'x86_64'},
                    {'name': 'gpg-pubkey', 'version': 'b86b3716-61e69f29', 'arch': ''},
                    {'name': 'gpg-pubkey', 'version': '8483c65d-5ccc5b19', 'arch': ''}]
        asked = []

        def querybatch(queries):
            asked.extend(q['package']['name'] for q in queries)
            return no_findings(queries)
        for ecosystem in ('AlmaLinux:9', 'Rocky Linux:9', 'Red Hat'):
            asked.clear()
            block = scan_with(querybatch, packages, ecosystem, has_meta=True)['covered']
            self.assertEqual((block['listed'], block['checked'], block['reasons'], block['packages']), (1, 1, {}, []), ecosystem)
            self.assertEqual(sorted(set(asked)), ['bash'], ecosystem)       # nothing was asked about a key
            adds_up(self, block)
            # the readers say the plain thing for a host that has no finding
            self.assertEqual((cve_fixes.coverage_words(block), cve_fixes.none_found_words(block)), ('', ''), ecosystem)
        # a host that is not matched against anything leaves them out of its number too, by either way of asking
        entry = {'ecosystem': '', 'pkg_manager': 'zypper', 'count': 3, 'packages': packages}
        for with_packages in (True, False):
            view = cve_scanner.entry_package_coverage(entry, {}, with_packages=with_packages)
            self.assertEqual((view['listed'], view['not_checked'], view['reasons']), (1, 1, {'no_matcher': 1}), with_packages)

    def test_an_rpm_host_asked_by_name_whole_is_checked_and_a_rocky_list_without_sources_is_not(self):
        packages = [{'name': 'bash', 'version': '5.1.8-9.el9', 'arch': 'x86_64'}]
        self.assertEqual(scan_with(no_findings, packages, 'AlmaLinux:9', has_meta=False)['covered']['not_checked'], 0)
        self.assertEqual(scan_with(no_findings, packages, 'Red Hat', has_meta=False)['covered']['not_checked'], 0)
        rocky = scan_with(no_findings, packages, 'Rocky Linux:9', has_meta=False)['covered']
        self.assertEqual(rocky['reasons'], {'no_source': 1})
        self.assertEqual(cve_scanner.coverage('Rocky Linux:9', False), 'needs_agent')
        self.assertEqual(scan_with(no_findings, packages, 'Rocky Linux:9', has_meta=True)['covered']['not_checked'], 0)

    def test_alpine_is_checked_by_origin_and_not_without_it(self):
        packages = [{'name': 'libcrypto3', 'version': '3.1.0-r0', 'source': 'openssl'}]
        self.assertEqual(scan_with(no_findings, packages, 'Alpine:v3.18', has_meta=True)['covered']['not_checked'], 0)
        self.assertEqual(scan_with(no_findings, packages, 'Alpine:v3.18', has_meta=False)['covered']['reasons'],
                         {'no_source': 1})

    def test_a_package_past_the_ceiling_is_not_read(self):
        packages = [{'name': f'p{i}', 'version': '1.0'} for i in range(5)]
        with mock.patch.object(cve_scanner, 'MAX_PACKAGES', 3):
            block = scan_with(no_findings, packages, 'Debian:12', has_meta=True)['covered']
        self.assertEqual((block['listed'], block['checked'], block['reasons']), (5, 3, {'ceiling': 2}))
        self.assertEqual([r['name'] for r in block['packages']], ['p3', 'p4'])
        adds_up(self, block)

    def test_the_real_ceiling_is_ten_thousand_and_the_set_is_the_one_the_scan_has(self):
        self.assertEqual(cve_scanner.MAX_PACKAGES, cve_fixes.MAX_PACKAGES_READ)
        packages = [{'name': f'p{i}', 'version': '1.0'} for i in range(cve_scanner.MAX_PACKAGES + 1)]
        units = cve_scanner.plan(packages, 'AlmaLinux:9', True)
        self.assertEqual(len(units), cve_scanner.MAX_PACKAGES)
        block = cve_scanner.package_coverage(packages, units, [{}] * len(units), '')
        self.assertEqual((block['listed'], block['checked'], block['reasons']), (10001, 10000, {'ceiling': 1}))
        self.assertEqual(block['packages'], [{'name': 'p10000', 'version': '1.0', 'reason': 'ceiling'}])

    def test_an_answer_cut_at_the_last_page_is_not_a_whole_answer(self):
        def endless(queries):
            return [{'vulns': [{'id': 'X-1', 'modified': '2026-11-10T08:00:00.123456Z'}], 'next_page_token': 't'}
                    for _ in queries]
        packages = [{'name': 'libc6', 'version': '2.36-9', 'source': 'glibc'},
                    {'name': 'openssh-server', 'version': '1:9.2p1-2', 'source': 'openssh'}]
        with mock.patch.object(cve_scanner, '_osv_querybatch', endless), \
                mock.patch.object(cve_scanner, '_osv_vuln_details', lambda vid: None):
            result = cve_scanner.scan_device('h', packages, 'Debian:12', Path(_tmp('rp-cov-scan-')), has_meta=True)
        self.assertEqual(sorted(result['cut']), ['glibc', 'openssh'])
        self.assertEqual(result['covered']['reasons'], {'unanswered': 2})
        self.assertEqual(result['covered']['checked'], 0)

    def test_the_names_are_capped_and_the_counts_are_not(self):
        packages = [{'name': f'p{i:04d}', 'version': '1.0'} for i in range(450)]
        block = scan_with(no_findings, packages, 'Debian:12', has_meta=False)['covered']
        self.assertEqual((block['listed'], block['not_checked']), (450, 450))
        self.assertEqual(len(block['packages']), 200)
        self.assertEqual(block['more'], 250)
        self.assertEqual(block['packages'][0]['name'], 'p0000')          # the first, in the order the host listed them
        self.assertEqual(block['packages'][-1]['name'], 'p0199')
        adds_up(self, block)

    def test_what_is_not_a_package_is_not_counted_and_does_not_end_the_scan(self):
        junk = [None, 7, 'x', [], {}, {'name': 'a'}, {'version': '1'}, {'name': '', 'version': '1'},
                {'name': 'ok', 'version': '1-1'}]
        block = scan_with(no_findings, junk, 'Debian:12', has_meta=True)['covered']
        self.assertEqual(block['listed'], 1)

    def test_the_plan_asks_what_it_asked_and_names_the_rows(self):
        units = cve_scanner.plan(BEHIND, 'Debian:12', True, True)
        self.assertEqual([(u['name'], u['version'], u['package'], u['binaries']) for u in units],
                         [('glibc', '2.36-9+deb12u3', 'glibc', ['libc6', 'libc-bin']),
                          ('openssh', '1:9.2p1-2+deb12u2', 'openssh', ['openssh-server', 'openssh-client']),
                          ('sudo', '1.9.13p3-1+deb12u1', 'sudo', ['sudo']),
                          ('zlib', '1:1.2.13.dfsg-1', 'zlib', ['zlib1g'])])
        self.assertEqual([u['rows'] for u in units], [[0, 1], [2, 3], [4], [5]])
        # the same package twice (two architectures) is one question and two packages
        twice = [{'name': 'libc6', 'version': '2.36-9', 'arch': 'amd64'}, {'name': 'libc6', 'version': '2.36-9', 'arch': 'i386'}]
        (unit,) = cve_scanner.plan(twice, 'Debian:12')
        self.assertEqual(unit['rows'], [0, 1])
        self.assertEqual(scan_with(no_findings, twice, 'Debian:12')['covered']['listed'], 2)

    def test_the_rocky_source_unit_holds_the_rows_of_its_packages(self):
        packages = [{'name': 'openssl', 'version': '3.0.7-16.el9', 'epoch': '1', 'source': 'openssl'},
                    {'name': 'openssl-libs', 'version': '3.0.7-16.el9', 'epoch': '1', 'source': 'openssl'}]
        units = cve_scanner.plan(packages, 'Rocky Linux:9', True)
        by_name = {u['name']: u['rows'] for u in units}
        self.assertEqual(by_name, {'openssl': [0, 1], 'openssl-libs': [1]})

    def test_a_host_nothing_is_matched_against_counts_every_package_as_not_checked(self):
        block = cve_scanner.package_coverage(WINDOWS, [], [], 'no_matcher')
        self.assertEqual((block['listed'], block['checked'], block['reasons']), (8, 0, {'no_matcher': 8}))
        adds_up(self, block)
        # a program that writes no version is still on the list of its host
        self.assertEqual(cve_scanner.package_coverage([{'name': 'Tool', 'version': ''}], [], [], 'no_matcher')['listed'], 1)

    def test_an_ecosystem_the_data_does_not_hold_is_not_matched(self):
        entry = {'ecosystem': 'Arch Linux', 'pkg_manager': 'apt', 'packages': [{'name': 'a', 'version': '1'}]}
        self.assertEqual(cve_scanner.entry_coverage(entry), 'no_matcher')
        self.assertEqual(cve_scanner.entry_coverage(dict(entry, ecosystem='Debian:12', sources=True)), '')


class TestTheViewOfABlock(unittest.TestCase):
    BLOCK = {'listed': 1901, 'checked': 1834, 'not_checked': 67, 'reasons': {'no_source': 52, 'no_release': 15},
             'packages': [{'name': 'libfoo', 'version': '1.0', 'reason': 'no_source'}], 'more': 66}

    def test_a_good_block_is_read_as_it_is(self):
        view = cve_fixes.covered_view(self.BLOCK)
        self.assertEqual(view['reasons'], {'no_source': 52, 'no_release': 15})
        self.assertEqual((view['listed'], view['checked'], view['not_checked'], view['more']), (1901, 1834, 67, 66))
        self.assertEqual(view['packages'], self.BLOCK['packages'])
        self.assertNotIn('packages', cve_fixes.covered_view(self.BLOCK, with_packages=False))

    def test_the_words(self):
        self.assertEqual(cve_fixes.coverage_words(self.BLOCK),
                         'Checked 1,834 of 1,901 packages; 67 not checked: 52 have no source name, '
                         '15 cannot be checked because the release is not known.')
        self.assertEqual(cve_fixes.none_found_words(self.BLOCK), 'none found in the 1,834 packages that could be checked')
        nothing = {'listed': 9, 'reasons': {'no_matcher': 9}}
        self.assertEqual(cve_fixes.none_found_words(nothing), 'none found, but none of the 9 packages could be checked')
        self.assertEqual(cve_fixes.none_found_words({'listed': 2, 'reasons': {'ceiling': 1}}),
                         'none found in the 1 package that could be checked')
        # all of it checked: the plain "none found" is true, and nothing is said
        self.assertEqual(cve_fixes.none_found_words({'listed': 5, 'checked': 5, 'reasons': {}}), '')
        self.assertEqual(cve_fixes.coverage_words({'listed': 5, 'checked': 5, 'reasons': {}}), '')

    def test_a_block_of_another_shape_is_no_block_or_a_repaired_one(self):
        for odd in (None, 7, 'many', [], {}, {'listed': 0}, {'listed': 'x', 'reasons': []}, {'reasons': {'bogus': 3}}):
            self.assertIsNone(cve_fixes.covered_view(odd), odd)
            self.assertEqual(cve_fixes.coverage_words(odd), '')
            self.assertEqual(cve_fixes.none_found_words(odd), '')
        # the numbers are made to add up from the reasons, and a reason nobody defined is left out
        view = cve_fixes.covered_view({'listed': 3, 'checked': 99, 'not_checked': -4,
                                       'reasons': {'no_source': 5, 'bogus': 7, 'ceiling': True, 'unanswered': -1}})
        self.assertEqual(view, {'listed': 5, 'checked': 0, 'not_checked': 5, 'reasons': {'no_source': 5},
                                'packages': [], 'more': 5})
        # rows of another kind are left out, the rest are cut and capped
        rows = [None, 7, {'name': None, 'reason': 'no_source'}, {'name': 'a', 'reason': 'bogus'}, {'name': '', 'reason': 'no_source'},
                {'name': 'x' * 500, 'version': 7, 'reason': 'no_source'}] + [{'name': f'p{i}', 'reason': 'no_source'} for i in range(300)]
        view = cve_fixes.covered_view({'listed': 400, 'reasons': {'no_source': 400}, 'packages': rows})
        self.assertEqual(len(view['packages']), 200)
        self.assertEqual(view['packages'][0], {'name': 'x' * 128, 'version': '', 'reason': 'no_source'})
        self.assertEqual(view['more'], 200)

    def test_the_fleet_adds_the_hosts_up(self):
        total = {'listed': 0, 'checked': 0, 'not_checked': 0, 'reasons': {}}
        cve_fixes.covered_add(total, cve_fixes.covered_view(self.BLOCK))
        cve_fixes.covered_add(total, cve_fixes.covered_view({'listed': 8, 'reasons': {'no_matcher': 8}}))
        for odd in (None, 7, 'x', {}, {'reasons': 'x'}):
            cve_fixes.covered_add(total, odd)
        self.assertEqual(total, {'listed': 1909, 'checked': 1834, 'not_checked': 75,
                                 'reasons': {'no_source': 52, 'no_release': 15, 'no_matcher': 8}})


class TestTheStoreHoldsTheBlock(unittest.TestCase):
    def test_the_shape_is_registered_and_a_good_block_is_not_changed(self):
        block = {'listed': 3, 'checked': 1, 'not_checked': 2, 'more': 0, 'reasons': {'no_source': 2},
                 'packages': [{'name': 'libc6', 'version': '1', 'reason': 'no_source'}]}
        store = {'h': {'findings': [], 'covered': json.loads(json.dumps(block))}}
        got = store_shapes.normalize('cve_findings.json', json.loads(json.dumps(store)))
        self.assertEqual(got, store)

    def test_a_block_of_another_kind_is_repaired_and_a_row_without_a_name_is_left_out(self):
        store = {'h': {'findings': [], 'covered': {'listed': '7', 'reasons': {'no_source': '2', 'ceiling': 'x'},
                                                   'packages': [{'reason': 'no_source'}, {'name': 'a', 'reason': 'no_source'}, 5]}},
                 'g': {'findings': [], 'covered': 'many'}}
        got = store_shapes.normalize('cve_findings.json', store)
        self.assertEqual(got['h']['covered']['listed'], 7)
        self.assertEqual([r['name'] for r in got['h']['covered']['packages']], ['a'])
        self.assertEqual(got['g']['covered'], {})                   # a wrong container is an empty one
        self.assertIsNone(cve_fixes.covered_view(got['g']['covered']))
        # and what survives is a block the readers can use
        self.assertEqual(cve_fixes.covered_view(got['h']['covered'], False)['reasons'], {'no_source': 2})


class _Fleet(unittest.TestCase):
    """Four hosts of two tenants, their lists through the real ingest and their scan through the real worker.

    tenant A: a Debian 12 host with an agent that names sources, one with an older agent. tenant B: a Windows host and an
    Arch host. Only verify_token is stubbed when a reader is called, never a gate."""

    DEB_NEW, DEB_OLD, WIN, ARCH = 'covdebnew', 'covdebold', 'covwin', 'covarch'

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
                                  'bruno': {'tenant_id': 'tenantB', 'role': 'admin'},
                                  'carol': {'tenant_id': 'tenantA', 'role': 'viewer'},
                                  'root': {'tenant_id': 'default', 'role': 'admin'}})
        api.save(api.DEVICES_FILE, {
            self.DEB_NEW: self.device(self.DEB_NEW, 'tenantA', 'Debian 12'),
            self.DEB_OLD: self.device(self.DEB_OLD, 'tenantA', 'Debian 12'),
            self.WIN: self.device(self.WIN, 'tenantB', 'Windows 11'),
            self.ARCH: self.device(self.ARCH, 'tenantB', 'Arch Linux'),
        })
        for store in (api.PACKAGES_FILE, api.CVE_FINDINGS_FILE, api.CVE_IGNORE_FILE, api.CVE_CAMPAIGNS_FILE,
                      api.KEV_EPSS_FILE):
            api.save(store, {})
        api._LOAD_CACHE.clear()
        self.send(self.DEB_NEW, 'apt', BEHIND, hint=DEBIAN_12, sources=True)
        self.send(self.DEB_OLD, 'apt', BY_NAME, hint=DEBIAN_12)
        self.send(self.WIN, 'windows', WINDOWS)
        self.send(self.ARCH, 'pacman', ARCH, hint={'ID': 'arch', 'VERSION_ID': '', 'ID_LIKE': ''})
        self.scan_the_fleet()

    @staticmethod
    def device(name, tenant, os_name):
        return {'id': name, 'name': name, 'tenant': tenant, 'os': os_name, 'token': 'tok-' + name, 'monitored': True,
                'group': '', 'tags': [], 'last_seen': 2_000_000_000}

    def patch(self, target, name, value):
        p = mock.patch.object(target, name, value)
        p.start()
        self._patches.append(p)

    def _stop(self):
        for p in reversed(self._patches):
            p.stop()
        for store in (api.DEVICES_FILE, api.PACKAGES_FILE, api.CVE_FINDINGS_FILE, api.CVE_IGNORE_FILE,
                      api.CVE_CAMPAIGNS_FILE, api.KEV_EPSS_FILE, api.CONFIG_FILE, api.TENANTS_FILE, api.USERS_FILE):
            api.save(store, {})
        api._LOAD_CACHE.clear()

    @staticmethod
    def _respond(status, data=None, headers=None):
        raise _Captured(status, data)

    def send(self, dev_id, manager, packages, hint=None, **extra):
        body = dict({'device_id': dev_id, 'token': 'tok-' + dev_id, 'pkg_manager': manager, 'packages': packages}, **extra)
        if hint is not None:
            body['ecosystem_hint'] = hint
        with mock.patch.object(api, 'method', lambda: 'POST'), mock.patch.object(api, 'get_json_obj', lambda: body):
            api._LOAD_CACHE.clear()
            try:
                api.handle_packages_submit()
            except _Captured as c:
                self.assertEqual(c.status, 200, c.body)
                return c.body
        self.fail('the handler did not answer')

    def scan_the_fleet(self):
        db = Database(DEB)
        with mock.patch.object(cve_scanner, '_osv_querybatch', db.querybatch), \
                mock.patch.object(cve_scanner, '_osv_vuln_details', db.details), \
                mock.patch.object(cve_scanner, '_debian_severity_fallback', lambda cve: None), \
                mock.patch.object(api, 'DATA_DIR', Path(_tmp('rp-cov-cache-'))):
            api._cve_scan_worker('tester', None)
        api._LOAD_CACHE.clear()

    def record(self, dev_id):
        api._LOAD_CACHE.clear()
        return (api.load(api.CVE_FINDINGS_FILE) or {}).get(dev_id) or {}

    def get(self, handler, *args, user=('root', 'admin'), tenancy=False, query=''):
        api.save(api.CONFIG_FILE, {'tenancy_enforced': True} if tenancy else {})
        api._LOAD_CACHE.clear()
        env = lambda key, default=None, _q=query: _q if key == 'QUERY_STRING' else default  # noqa: E731
        with mock.patch.object(api, '_env', env), mock.patch.object(api, 'method', lambda: 'GET'), \
                mock.patch.object(api, 'verify_token', lambda tok=None: user), \
                mock.patch.object(api, '_kev_epss', lambda: (set(), {})), \
                mock.patch.object(api, 'device_get', lambda dev_id: api.load(api.DEVICES_FILE).get(dev_id)):
            try:
                handler(*args)
            except _Captured as c:
                return c.status, c.body
        self.fail('the handler did not answer')

    def as_tenant_admin(self, handler, *args, user=('alice', 'admin')):
        return self.get(handler, *args, user=user, tenancy=True)

    def gated(self, caller, dev_id):
        """GET /api/devices/<id>/cve as main() serves it: the device gate runs before the handler."""
        def run(*_):
            api._enforce_device_scope()
            api.handle_cve_device(dev_id)
        with mock.patch.object(api, 'path_info', lambda: f'/api/devices/{dev_id}/cve'):
            return caller(run)

    def as_read_only(self, handler, *args):
        return self.get(handler, *args, user=('carol', 'viewer'), tenancy=True)


class _Captured(Exception):
    def __init__(self, status, body):
        super().__init__(status)
        self.status, self.body = status, body


class TestTheWorkerStoresIt(_Fleet):
    def test_a_host_scanned_by_source_has_all_of_it_checked_and_the_record_says_so(self):
        block = self.record(self.DEB_NEW)['covered']
        self.assertEqual(without_rows(block), {'listed': 6, 'checked': 6, 'not_checked': 0, 'reasons': {}, 'more': 0})

    def test_a_host_of_an_older_agent_says_what_it_did_not_check(self):
        block = self.record(self.DEB_OLD)['covered']
        self.assertEqual((block['listed'], block['checked'], block['reasons']), (3, 1, {'no_source': 2}))
        adds_up(self, block)

    def test_a_host_nothing_is_matched_against_has_no_record_and_the_page_derives_the_account(self):
        self.assertEqual(self.record(self.WIN), {})
        self.assertEqual(self.record(self.ARCH), {})
        entry = api.load(api.PACKAGES_FILE)[self.WIN]
        view = cve_scanner.entry_package_coverage(entry, {})
        self.assertEqual((view['listed'], view['checked'], view['not_checked'], view['reasons']), (8, 0, 8, {'no_matcher': 8}))
        self.assertEqual(len(view['packages']), 8)
        quick = cve_scanner.entry_package_coverage(entry, {}, with_packages=False)
        self.assertEqual((quick['listed'], quick['not_checked']), (8, 8))
        self.assertNotIn('packages', quick)
        # a scannable host that was never scanned says nothing
        self.assertIsNone(cve_scanner.entry_package_coverage(api.load(api.PACKAGES_FILE)[self.DEB_NEW], {}))

    def test_a_scan_from_before_the_block_says_nothing_of_its_packages(self):
        store = api.load(api.CVE_FINDINGS_FILE)
        store[self.DEB_NEW].pop('covered')
        api.save(api.CVE_FINDINGS_FILE, store)
        status, view = self.get(api.handle_cve_device, self.DEB_NEW)
        self.assertEqual(status, 200, view)
        self.assertIsNone(view['covered'])


class TestThePagesAreHandedIt(_Fleet):
    def test_the_host_view_carries_the_block_and_the_word(self):
        status, view = self.get(api.handle_cve_device, self.DEB_OLD)
        self.assertEqual(status, 200, view)
        self.assertEqual(view['coverage'], 'needs_agent')
        self.assertEqual((view['covered']['checked'], view['covered']['not_checked']), (1, 2))
        self.assertEqual([r['name'] for r in view['covered']['packages']], ['libc6', 'openssh-server'])
        status, view = self.get(api.handle_cve_device, self.WIN)
        self.assertEqual((view['coverage'], view['covered']['reasons']), ('no_matcher', {'no_matcher': 8}))

    def test_the_fleet_page_adds_the_hosts_and_names_the_ones_with_most_not_checked(self):
        status, report = self.get(api.handle_cve_findings)
        self.assertEqual(status, 200, report)
        total = report['summary']['covered']
        self.assertEqual(total, {'listed': 18, 'checked': 7, 'not_checked': 11, 'reasons': {'no_source': 2, 'no_matcher': 9},
                                 'hosts_unstated': 0})
        self.assertEqual([(r['name'], r['not_checked']) for r in report['summary']['most_not_checked']],
                         [(self.WIN, 8), (self.DEB_OLD, 2), (self.ARCH, 1)])
        rows = {r['device_id']: r for r in report['devices']}
        self.assertEqual((rows[self.DEB_NEW]['covered']['checked'], rows[self.DEB_NEW]['covered']['not_checked']), (6, 0))
        self.assertEqual(rows[self.WIN]['covered']['reasons'], {'no_matcher': 8})
        self.assertNotIn('packages', rows[self.WIN]['covered'])          # the fleet page carries numbers, not the rows

    def test_a_tenant_administrator_is_told_of_their_own_hosts_only(self):
        status, report = self.as_tenant_admin(api.handle_cve_findings)
        self.assertEqual(status, 200, report)
        self.assertEqual(report['summary']['covered'], {'listed': 9, 'checked': 7, 'not_checked': 2, 'reasons': {'no_source': 2},
                                                         'hosts_unstated': 0})
        self.assertEqual([r['name'] for r in report['summary']['most_not_checked']], [self.DEB_OLD])
        self.assertEqual(sorted(r['device_id'] for r in report['devices']), sorted([self.DEB_NEW, self.DEB_OLD]))
        # the other tenant's, as theirs
        status, report = self.as_tenant_admin(api.handle_cve_findings, user=('bruno', 'admin'))
        self.assertEqual(report['summary']['covered'], {'listed': 9, 'checked': 0, 'not_checked': 9, 'reasons': {'no_matcher': 9},
                                                         'hosts_unstated': 0})
        self.assertEqual([r['name'] for r in report['summary']['most_not_checked']], [self.WIN, self.ARCH])

    def test_a_read_only_user_reads_the_same_numbers_and_the_other_tenants_host_is_not_theirs(self):
        status, report = self.as_read_only(api.handle_cve_findings)
        self.assertEqual(status, 200, report)
        self.assertEqual(report['summary']['covered']['not_checked'], 2)
        status, view = self.as_read_only(api.handle_cve_device, self.DEB_OLD)
        self.assertEqual((status, view['covered']['not_checked']), (200, 2))
        # a host of another tenant is refused before the handler runs, as main() does, and says nothing of its packages
        for caller in (self.as_tenant_admin, self.as_read_only):
            status, view = self.gated(caller, self.WIN)
            self.assertEqual(status, 403, view)
            self.assertNotIn('covered', view)
            self.assertNotIn('packages_count', view)
        status, view = self.gated(self.as_tenant_admin, self.DEB_OLD)
        self.assertEqual((status, view['covered']['not_checked']), (200, 2))

    def test_the_dashboard_is_told_how_many_each_host_did_not_check(self):
        with mock.patch.object(api, 'verify_token', lambda tok=None: ('root', 'admin')):
            status, home = self.get(api.handle_home)
        self.assertEqual(status, 200)
        rows = {r['device_id']: r for r in home['cves']['devices']}
        self.assertEqual((rows[self.DEB_NEW]['not_checked'], rows[self.DEB_OLD]['not_checked']), (0, 2))
        # two hosts show findings, so the tile says those and the packages store is not read for the hosts with no record:
        # what the payload carries when nothing shows a finding is held in test_cve_coverage_readers
        self.assertEqual(rows[self.WIN]['not_checked'], 0)


class TestEveryTextThatSaysNoCvesSaysWhatItLookedAt(_Fleet):
    def dev(self, dev_id):
        return api.load(api.DEVICES_FILE)[dev_id]

    def without_findings(self, dev_id):
        """The record of a host that lists nothing and counts nothing: only what it checked is left."""
        store = api.load(api.CVE_FINDINGS_FILE)
        store[dev_id]['findings'] = []
        store[dev_id].pop('rollup', None)
        api.save(api.CVE_FINDINGS_FILE, store)
        api._LOAD_CACHE.clear()

    def test_the_assistants_triage_tool(self):
        self.without_findings(self.DEB_OLD)
        text = api._triage_tools(self.DEB_OLD, self.dev(self.DEB_OLD))['cves']({})
        self.assertIn('none found in the 1 package that could be checked', text)
        self.assertIn('Checked 1 of 3 packages; 2 not checked: 2 have no source name.', text)
        self.assertNotIn('(no open CVE findings for this host)', text)
        # the host that was checked whole keeps the plain sentence
        self.without_findings(self.DEB_NEW)
        self.assertEqual(api._triage_tools(self.DEB_NEW, self.dev(self.DEB_NEW))['cves']({}),
                         '(no open CVE findings for this host)')

    def test_the_triage_tool_says_it_also_when_there_are_findings(self):
        text = api._triage_tools(self.DEB_OLD, self.dev(self.DEB_OLD))['cves']({})
        self.assertIn('open finding', text)
        self.assertIn('Checked 1 of 3 packages; 2 not checked: 2 have no source name.', text)
        self.assertNotIn('none found', text)

    def ticket(self, host):
        api._LOAD_CACHE.clear()
        text = api._alert_ticket_detail({'event': 'cve_found', 'device_id': host, 'title': 'New CVEs',
                                         'payload': {'device_id': host}})
        self.assertIsInstance(text, str)
        return text

    def test_the_text_of_a_ticket(self):
        self.without_findings(self.DEB_OLD)
        text = self.ticket(self.DEB_OLD)
        self.assertIn('Open CVEs on this host: 0 total', text)
        self.assertIn('None found in the 1 package that could be checked.', text)
        self.assertIn('Checked 1 of 3 packages; 2 not checked: 2 have no source name.', text)
        # a host checked whole says neither
        whole = self.ticket(self.DEB_NEW)
        self.assertNotIn('could be checked', whole)
        self.assertNotIn('not checked', whole)

    def test_the_runbook_snapshot_and_what_the_model_is_told_to_do_with_it(self):
        snap = api._build_runbook_snapshot(self.DEB_OLD, api.load(api.DEVICES_FILE))
        self.assertEqual((snap['cve_coverage']['checked'], snap['cve_coverage']['not_checked']), (1, 2))
        self.assertEqual(snap['cve_coverage']['reasons'], {'no_source': 2})
        self.assertNotIn('packages', snap['cve_coverage'])
        # a host nothing is matched against has no record and says what its package list gives (more in test_cve_coverage_readers)
        self.assertEqual(api._build_runbook_snapshot(self.WIN, api.load(api.DEVICES_FILE))['cve_coverage'],
                         {'listed': 8, 'checked': 0, 'not_checked': 8, 'reasons': {'no_matcher': 8}})
        import ai_provider
        prompt = next(v for v in ai_provider.SYSTEM_PROMPTS.values() if isinstance(v, str) and 'cve_findings' in v
                      and 'No risks flagged in this snapshot.' in v)
        for said in ('cve_coverage', 'not_checked', 'none were found in the packages that could be checked',
                     'cve_counted is zero'):
            self.assertIn(said, prompt)

    def fetch(self, path, method='GET', body=None):
        if path == '/api/devices':
            return {'devices': [dict(d) for d in api.load(api.DEVICES_FILE).values()]}
        match = re.fullmatch(r'/api/devices/([^/]+)/cve', path)
        if not match:
            raise AssertionError('a path this test does not know: ' + path)
        status, answer = self.get(api.handle_cve_device, match.group(1))
        self.assertEqual(status, 200, answer)
        return answer

    def test_the_mcp_tools_carry_the_account_and_say_it_in_a_sentence(self):
        hosted = mcp_http.tool_get_cves({'name': self.DEB_OLD}, self.fetch)
        with mock.patch.object(sidecar, '_api', lambda method, path, body=None, mcp_prompt=None: self.fetch(path)):
            local = sidecar.tool_get_cves({'name': self.DEB_OLD})
            whole = sidecar.tool_get_cves({'name': self.DEB_NEW})
            windows = sidecar.tool_get_cves({'name': self.WIN})
        for out in (hosted, local):
            self.assertEqual((out['coverage']['checked'], out['coverage']['not_checked']), (1, 2))
            self.assertEqual(out['coverage']['reasons'], {'no_source': 2})
            self.assertIn('2 of the 3 packages were not checked', out['note'])
        # a host with nothing listed and part of it not checked
        self.assertEqual(whole['coverage']['not_checked'], 0)
        self.assertNotIn('note', whole)
        self.assertIn('none of the 8 packages could be checked', windows['note'])
        self.assertEqual(windows['findings'], [])

    def test_the_note_of_the_tools_is_the_same_in_both(self):
        for covered, has in (({'listed': 9, 'checked': 0, 'not_checked': 9}, False),
                             ({'listed': 9, 'checked': 4, 'not_checked': 5}, False),
                             ({'listed': 9, 'checked': 4, 'not_checked': 5}, True),
                             ({'listed': 9, 'checked': 9, 'not_checked': 0}, False),
                             ({'listed': 'x', 'checked': 0, 'not_checked': 1}, False), ({}, False)):
            self.assertEqual(mcp_http._coverage_note(covered, has), sidecar._coverage_note(covered, has), covered)
        self.assertEqual(mcp_http._coverage_note({'listed': 9, 'checked': 4, 'not_checked': 5}, False),
                         'None found in the 4 packages that could be checked; 5 were not checked (coverage.reasons).')

    def test_the_sbom_of_a_host_says_how_many_of_its_components_nothing_was_matched_against(self):
        def doc(dev_id, fmt):
            return api._build_sbom_doc(dev_id, api.load(api.DEVICES_FILE)[dev_id], fmt)
        props = {p['name']: p['value'] for p in doc(self.DEB_OLD, 'cyclonedx')['metadata']['component']['properties']}
        self.assertEqual((props['remotepower:cve_packages_checked'], props['remotepower:cve_packages_not_checked']), ('1', '2'))
        self.assertEqual(props['remotepower:cve_not_checked:no_source'], '2')
        win = {p['name']: p['value'] for p in doc(self.WIN, 'cyclonedx')['metadata']['component']['properties']}
        self.assertEqual((win['remotepower:cve_packages_checked'], win['remotepower:cve_packages_not_checked']), ('0', '8'))
        self.assertEqual(win['remotepower:cve_not_checked:no_matcher'], '8')
        whole = {p['name']: p['value'] for p in doc(self.DEB_NEW, 'cyclonedx')['metadata']['component']['properties']}
        self.assertEqual((whole['remotepower:cve_packages_checked'], whole['remotepower:cve_packages_not_checked']), ('6', '0'))
        self.assertFalse([k for k in whole if k.startswith('remotepower:cve_not_checked:')])
        self.assertIn('CVE matching. Checked 1 of 3 packages; 2 not checked: 2 have no source name.',
                      doc(self.DEB_OLD, 'spdx')['creationInfo']['comment'])
        self.assertNotIn('comment', doc(self.DEB_NEW, 'spdx')['creationInfo'])

    def test_the_sbom_of_a_host_without_the_block_has_none_of_these_properties(self):
        entry = {'packages': BEHIND, 'pkg_manager': 'apt', 'os_id': 'debian'}
        doc = sbom.build_cyclonedx({'id': 'h', 'name': 'h'}, entry, [])
        self.assertFalse([p for p in doc['metadata']['component']['properties'] if 'cve_' in p['name']])
        self.assertNotIn('comment', sbom.build_spdx({'id': 'h', 'name': 'h'}, entry, [])['creationInfo'])

    def test_the_comment_of_the_sbom_keeps_what_the_agent_left_out_too(self):
        entry = {'packages': [{'name': 'App', 'version': '1', 'manager': 'windows'}], 'pkg_manager': 'windows',
                 'skipped': 41}
        covered = cve_fixes.covered_view({'listed': 1, 'reasons': {'no_matcher': 1}})
        comment = sbom.build_spdx({'id': 'h', 'name': 'h'}, entry, [], covered=covered)['creationInfo']['comment']
        self.assertIn('41 entries were left out', comment)
        self.assertIn('CVE matching. Checked 0 of 1 package; 1 not checked: 1 have no matcher', comment)


if __name__ == '__main__':
    unittest.main()

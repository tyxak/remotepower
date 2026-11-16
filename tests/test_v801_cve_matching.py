"""What the CVE scan asks the advisory database, and what it does with the answer (8.0.1).

Measured on 2026-11-15 against https://api.osv.dev and replayed here from tests/data/osv_recorded_2026-11-15.tsv
(the queries, the advisory ids each returned, and the fixed versions of those advisories):

  * an AlmaLinux 9 host with openssl-libs 3.0.7-16.el9 showed no openssl finding at all. The agent reports the
    version without its epoch, the database answers with every advisory of the package, and the "already
    patched" check then read the epoch of each fix ("1:3.0.7-28.el9_4") as the first number of a version, so 3
    beat 1 and all of them were dropped;
  * the same host on a fully patched package with a high epoch (bind, 32:) kept every advisory for ever;
  * "AlmaLinux" without a release answered with the advisories of release 10 as well: 20 for a release 9
    package where 13 are its own;
  * Alpine files an advisory under the origin ("openssl"), and "libcrypto3" was asked for and answered nothing;
  * the older Rocky advisories name only the source package;
  * one failed request while the fleet's packages were looked up together emptied the findings of every host.

A query that was not recorded fails the test that makes it, so nothing here passes on an empty answer.
"""
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v801-cve-'))
_spec = importlib.util.spec_from_file_location('api_v801_cve', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
cve_scanner = api.cve_scanner

import srcpin  # noqa: E402

RECORDED = ROOT / 'tests' / 'data' / 'osv_recorded_2026-11-15.tsv'
HOST = 'v801cvehost'
_JS = ROOT / 'server' / 'html' / 'static' / 'js'
_APP = (_JS / 'app.js').read_text()
_PAGE = (_JS / 'app-cve.js').read_text()
HAVE_NODE = shutil.which('node') is not None


def _recorded():
    queries, entries = {}, {}
    for line in RECORDED.read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        kind, *rest = line.split('\t')
        if kind == 'Q':
            ecosystem, name, version, ids = rest
            queries[(ecosystem, name, version)] = [] if ids == '-' else ids.split(',')
        elif kind == 'A':
            vid, ecosystem, name, introduced, fixed = rest
            entries.setdefault(vid, []).append((ecosystem, name, introduced, fixed))
    return queries, entries


QUERIES, ENTRIES = _recorded()


class NotRecorded(AssertionError):
    pass


class Database:
    """Stands where the two network calls of the scanner are, and answers from the recording."""

    def __init__(self):
        self.asked = []          # every (ecosystem, name, version) sent, in order
        self.batches = 0

    def querybatch(self, body):
        self.batches += 1
        out = []
        for q in body:
            key = (q['package']['ecosystem'], q['package']['name'], q['version'])
            self.asked.append(key)
            if key not in QUERIES:
                raise NotRecorded(f'this query was never recorded: {key}')
            out.append({'vulns': [{'id': i, 'modified': '2026-11-15T00:00:00Z'} for i in QUERIES[key]]})
        return out

    def details(self, vid):
        if vid not in ENTRIES:
            raise NotRecorded(f'no recorded entry for {vid}')
        affected = []
        for ecosystem, name, introduced, fixed in ENTRIES[vid]:
            events = [] if introduced == '-' else [{'introduced': introduced}]
            if fixed != '-':
                events.append({'fixed': fixed})
            affected.append({'package': {'ecosystem': ecosystem, 'name': name},
                             'ranges': [{'type': 'ECOSYSTEM', 'events': events}]})
        return {'id': vid, 'summary': 'recorded', 'affected': affected,
                'database_specific': {'severity': 'Important'}}


class _Scan(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix='rp-v801-cve-scan-'))
        self.db = Database()
        self._patches = [mock.patch.object(cve_scanner, '_osv_querybatch', self.db.querybatch),
                         mock.patch.object(cve_scanner, '_osv_vuln_details', self.db.details)]
        for p in self._patches:
            p.start()
            self.addCleanup(p.stop)

    def scan(self, packages, ecosystem, has_meta=False, prefetch=None):
        result = cve_scanner.scan_device(HOST, packages, ecosystem, self.dir, osv_prefetch=prefetch,
                                         has_meta=has_meta)
        self.assertNotIn('error', result, result.get('error'))
        return result

    def ids(self, result):
        return sorted(f['vuln_id'] for f in result['findings'])


def recorded(ecosystem, name, version):
    return sorted(QUERIES[(ecosystem, name, version)])


class TestTheRecordingIsWhatTheTestsSayItIs(unittest.TestCase):
    def test_it_holds_the_measured_numbers(self):
        self.assertEqual(len(QUERIES), 15)
        self.assertEqual(len(recorded('AlmaLinux:9', 'openssl-libs', '3.0.7-16.el9')), 17)
        self.assertEqual(len(recorded('AlmaLinux:9', 'openssl-libs', '1:3.0.7-16.el9')), 13)
        self.assertEqual(len(recorded('AlmaLinux:9', 'openssl-libs', '3.5.9-1.el9_9')), 17)
        self.assertEqual(recorded('AlmaLinux:9', 'openssl-libs', '1:3.5.9-1.el9_9'), [])
        self.assertEqual(len(recorded('Alpine:v3.18', 'openssl', '3.1.0-r0')), 19)
        self.assertEqual(recorded('Alpine:v3.18', 'libcrypto3', '3.1.0-r0'), [])
        self.assertEqual(len(recorded('Rocky Linux:9', 'openssl', '1:3.0.7-16.el9')), 11)
        self.assertEqual(len(recorded('Rocky Linux:9', 'openssl-libs', '1:3.0.7-16.el9')), 1)

    def test_every_advisory_a_query_returned_has_its_entries(self):
        missing = sorted({i for ids in QUERIES.values() for i in ids} - set(ENTRIES))
        self.assertEqual(missing, [])
        self.assertGreater(len(ENTRIES), 60)

    def test_a_query_that_was_not_recorded_fails(self):
        with self.assertRaises(NotRecorded):
            Database().querybatch([{'package': {'name': 'nothing', 'ecosystem': 'AlmaLinux:9'}, 'version': '1-1'}])


class TestAnRpmHostWhoseAgentSendsNoEpoch(_Scan):
    """The list every agent before 8.0.1 sends: the version and release, no epoch."""

    def test_a_host_that_needs_the_update_is_told(self):
        got = self.ids(self.scan([{'name': 'openssl-libs', 'version': '3.0.7-16.el9'}], 'AlmaLinux:9'))
        # the answer to the exact question (with the epoch) is what a host on this package has
        self.assertEqual(got, recorded('AlmaLinux:9', 'openssl-libs', '1:3.0.7-16.el9'))
        self.assertIn('ALSA-2024:6783', got)
        self.assertEqual(len(got), 13)

    def test_the_four_it_is_past_are_left_out_and_counted(self):
        result = self.scan([{'name': 'openssl-libs', 'version': '3.0.7-16.el9'}], 'AlmaLinux:9')
        self.assertEqual(result['suppressed_patched'], 4)

    def test_a_patched_host_shows_nothing(self):
        result = self.scan([{'name': 'openssl-libs', 'version': '3.5.9-1.el9_9'}], 'AlmaLinux:9')
        self.assertEqual(self.ids(result), recorded('AlmaLinux:9', 'openssl-libs', '1:3.5.9-1.el9_9'))
        self.assertEqual(result['findings'], [])
        self.assertEqual(result['suppressed_patched'], 17)

    def test_an_epoch_above_the_version_no_longer_keeps_every_advisory(self):
        behind = self.ids(self.scan([{'name': 'bind-libs', 'version': '9.16.23-11.el9'}], 'AlmaLinux:9'))
        self.assertEqual(behind, recorded('AlmaLinux:9', 'bind-libs', '32:9.16.23-11.el9'))
        self.assertEqual(len(behind), 14)
        patched = self.scan([{'name': 'bind-libs', 'version': '9.99.99-99.el9'}], 'AlmaLinux:9')
        self.assertEqual(patched['findings'], [])

    def test_the_old_check_gave_the_opposite_answers(self):
        """The control. Put the comparison that was replaced back, and the host that needs the update shows
        nothing while the patched bind shows everything."""
        old = lambda installed, fixed, **_kw: cve_scanner._tuple_ge(installed, fixed)   # noqa: E731
        with mock.patch.object(cve_scanner.pkg_versions, 'rpm_ge', old):
            needs = self.scan([{'name': 'openssl-libs', 'version': '3.0.7-16.el9'}], 'AlmaLinux:9')
            patched = self.scan([{'name': 'bind-libs', 'version': '9.99.99-99.el9'}], 'AlmaLinux:9')
        self.assertEqual(needs['findings'], [])
        self.assertEqual(len(patched['findings']), 17)


class TestAnRpmHostWhoseAgentSendsEpochAndSource(_Scan):
    LIST = [{'name': 'openssl-libs', 'version': '3.0.7-16.el9', 'epoch': '1', 'source': 'openssl'},
            {'name': 'openssl', 'version': '3.0.7-16.el9', 'epoch': '1'}]

    def test_the_question_carries_the_epoch(self):
        self.scan(self.LIST, 'AlmaLinux:9', has_meta=True)
        self.assertEqual(self.db.asked, [('AlmaLinux:9', 'openssl-libs', '1:3.0.7-16.el9'),
                                         ('AlmaLinux:9', 'openssl', '1:3.0.7-16.el9')])

    def test_one_advisory_against_one_source_is_one_finding(self):
        result = self.scan(self.LIST, 'AlmaLinux:9', has_meta=True)
        self.assertEqual(self.ids(result), recorded('AlmaLinux:9', 'openssl-libs', '1:3.0.7-16.el9'))
        self.assertEqual(len(result['findings']), 13)                      # it was 26: one per package
        for f in result['findings']:
            self.assertEqual(f['package'], 'openssl')
            self.assertEqual(f['version'], '1:3.0.7-16.el9')
            self.assertEqual(f['binaries'], ['openssl', 'openssl-libs'])
            self.assertTrue(f['fixed_version'].startswith('1:'), f)

    def test_a_patched_host_is_not_asked_to_sort_anything_out(self):
        result = self.scan([{'name': 'openssl-libs', 'version': '3.5.9-1.el9_9', 'epoch': '1', 'source': 'openssl'}],
                           'AlmaLinux:9', has_meta=True)
        self.assertEqual(result['findings'], [])
        self.assertEqual(result['suppressed_patched'], 0)      # the database itself answered "none"

    def test_alma_is_not_asked_for_the_source_name(self):
        self.scan([self.LIST[0]], 'AlmaLinux:9', has_meta=True)
        self.assertEqual(self.db.asked, [('AlmaLinux:9', 'openssl-libs', '1:3.0.7-16.el9')])


class TestRockyIsAskedByBothNames(_Scan):
    LIST = [{'name': 'openssl-libs', 'version': '3.0.7-16.el9', 'epoch': '1', 'source': 'openssl'}]

    def test_the_source_name_finds_what_the_package_name_does_not(self):
        by_package = set(recorded('Rocky Linux:9', 'openssl-libs', '1:3.0.7-16.el9'))
        by_source = set(recorded('Rocky Linux:9', 'openssl', '1:3.0.7-16.el9'))
        self.assertGreaterEqual(len(by_source - by_package), 10)           # the reason for the second question
        result = self.scan(self.LIST, 'Rocky Linux:9', has_meta=True)
        self.assertEqual(set(self.ids(result)), by_package | by_source)
        self.assertEqual(len(result['findings']), len(by_package | by_source))    # an advisory under both: once
        self.assertEqual(sorted(self.db.asked), [('Rocky Linux:9', 'openssl', '1:3.0.7-16.el9'),
                                                 ('Rocky Linux:9', 'openssl-libs', '1:3.0.7-16.el9')])
        for f in result['findings']:
            self.assertEqual((f['package'], f['binaries']), ('openssl', ['openssl-libs']))

    def test_the_source_epoch_comes_from_a_package_with_the_source_version(self):
        units = cve_scanner.plan([
            {'name': 'perl-Errno', 'version': '1.30-481.el9', 'source': 'perl', 'source_version': '5.32.1-481.el9'},
            {'name': 'perl-libs', 'version': '5.32.1-481.el9', 'epoch': '4', 'source': 'perl'},
        ], 'Rocky Linux:9', True)
        asked = {(u['name'], u['version']) for u in units}
        self.assertEqual(asked, {('perl-Errno', '1.30-481.el9'), ('perl-libs', '4:5.32.1-481.el9'),
                                 ('perl', '4:5.32.1-481.el9')})
        source = next(u for u in units if u['name'] == 'perl')
        self.assertEqual(sorted(source['binaries']), ['perl-Errno', 'perl-libs'])

    def test_a_finding_carries_the_fix_of_the_package_that_was_asked_about(self):
        """One advisory fixes a source's packages at their own versions. The finding is filed under the source
        and still names the fix of the package the host has."""
        key = ('Rocky Linux:9', 'perl-Errno', '1.30-481.el9')
        entries = [('Rocky Linux:9', 'perl', '-', '4:5.32.1-481.el9_4'),
                   ('Rocky Linux:9', 'perl-Errno', '-', '0:1.30-481.el9_4')]
        with mock.patch.dict(QUERIES, {key: ['X-PERL-1']}), mock.patch.dict(ENTRIES, {'X-PERL-1': entries}):
            result = self.scan([{'name': 'perl-Errno', 'version': '1.30-481.el9', 'source': 'perl',
                                 'source_version': '5.32.1-481.el9'}], 'Rocky Linux:9', has_meta=True)
        (finding,) = result['findings']
        self.assertEqual((finding['package'], finding['version'], finding['fixed_version'], finding['binaries']),
                         ('perl', '1.30-481.el9', '0:1.30-481.el9_4', ['perl-Errno']))

    def test_a_source_whose_epoch_cannot_be_known_is_not_asked_for(self):
        # no installed package has the source's own version, so nothing says what its epoch is
        units = cve_scanner.plan([{'name': 'perl-Errno', 'version': '1.30-481.el9', 'source': 'perl',
                                   'source_version': '5.32.1-481.el9'}], 'Rocky Linux:9', True)
        self.assertEqual([(u['name'], u['version']) for u in units], [('perl-Errno', '1.30-481.el9')])
        # and two packages that disagree about it do not settle it either
        units = cve_scanner.plan([{'name': 'a', 'version': '1-1', 'epoch': '1', 'source': 's'},
                                  {'name': 'b', 'version': '1-1', 'epoch': '2', 'source': 's'}], 'Rocky Linux:9', True)
        self.assertEqual(sorted(u['name'] for u in units), ['a', 'b'])


class TestAlpineIsAskedByOrigin(_Scan):
    LIST = [{'name': 'libcrypto3', 'version': '3.1.0-r0', 'source': 'openssl'},
            {'name': 'libssl3', 'version': '3.1.0-r0', 'source': 'openssl'}]

    def test_the_libraries_are_checked_as_their_origin(self):
        result = self.scan(self.LIST, 'Alpine:v3.18', has_meta=True)
        self.assertEqual(self.db.asked, [('Alpine:v3.18', 'openssl', '3.1.0-r0')])
        self.assertEqual(self.ids(result), recorded('Alpine:v3.18', 'openssl', '3.1.0-r0'))
        self.assertEqual(len(result['findings']), 19)
        for f in result['findings']:
            self.assertEqual((f['package'], f['binaries']), ('openssl', ['libcrypto3', 'libssl3']))
            self.assertEqual(f['fix_status'], 'fixed', f)

    def test_without_the_origin_the_library_is_asked_for_and_nothing_answers(self):
        result = self.scan([{'name': 'libcrypto3', 'version': '3.1.0-r0'}], 'Alpine:v3.18')
        self.assertEqual(self.db.asked, [('Alpine:v3.18', 'libcrypto3', '3.1.0-r0')])
        self.assertEqual(result['findings'], [])
        self.assertEqual(cve_scanner.coverage('Alpine:v3.18', False), 'needs_agent')

    def test_a_fix_one_revision_ahead_is_not_installed(self):
        """ALPINE-CVE-2023-5363 is fixed in 3.1.4-r0 on 3.18. The fake answer says a host on 3.1.4_rc1-r0 is
        affected, and the finding has to survive the "already patched" check."""
        key = ('Alpine:v3.18', 'openssl', '3.1.4_rc1-r0')
        with mock.patch.dict(QUERIES, {key: ['ALPINE-CVE-2023-5363']}):
            result = self.scan([{'name': 'openssl', 'version': '3.1.4_rc1-r0'}], 'Alpine:v3.18')
        self.assertEqual(self.ids(result), ['ALPINE-CVE-2023-5363'])
        self.assertEqual(result['findings'][0]['fixed_version'], '3.1.4-r0')


class TestTheReleaseOfRockyAndAlma(_Scan):
    def test_the_bare_name_answers_for_two_releases(self):
        bare = set(recorded('AlmaLinux', 'openssl-libs', '1:3.0.7-16.el9'))
        nine = set(recorded('AlmaLinux:9', 'openssl-libs', '1:3.0.7-16.el9'))
        ten = set(recorded('AlmaLinux:10', 'openssl-libs', '1:3.0.7-16.el9'))
        self.assertEqual((len(bare), len(nine), len(ten)), (20, 13, 7))
        self.assertEqual(bare, nine | ten)
        self.assertEqual(nine & ten, set())

    def test_a_new_list_is_filed_under_its_release(self):
        detect = cve_scanner.detect_ecosystem
        self.assertEqual(detect({'ID': 'almalinux', 'VERSION_ID': '9.4'}, 'dnf'), 'AlmaLinux:9')
        self.assertEqual(detect({'ID': 'rocky', 'VERSION_ID': '10.0'}, 'dnf'), 'Rocky Linux:10')
        self.assertEqual(detect({'ID': 'rocky', 'VERSION_ID': '8'}, 'dnf'), 'Rocky Linux:8')
        self.assertEqual(detect({'ID': 'rhel', 'VERSION_ID': '9.4'}, 'dnf'), 'Red Hat')
        # no usable number: the bare name, which finds too much and never too little
        for odd in ('', 'rolling', '9x', '0', '1234', '９'):
            self.assertEqual(detect({'ID': 'almalinux', 'VERSION_ID': odd}, 'dnf'), 'AlmaLinux', odd)

    def test_a_list_stored_before_the_release_was_kept_is_scanned_under_it(self):
        name = cve_scanner.entry_ecosystem
        self.assertEqual(name({'ecosystem': 'AlmaLinux', 'version_id': '9.4'}), 'AlmaLinux:9')
        self.assertEqual(name({'ecosystem': 'Rocky Linux', 'version_id': '8.10'}), 'Rocky Linux:8')
        self.assertEqual(name({'ecosystem': 'Rocky Linux'}), 'Rocky Linux')
        self.assertEqual(name({'ecosystem': 'AlmaLinux:9', 'version_id': '10.0'}), 'AlmaLinux:9')
        self.assertEqual(name({'ecosystem': 'Debian:12', 'version_id': '12'}), 'Debian:12')
        self.assertEqual(name({'ecosystem': 'Ubuntu', 'version_id': '24.04'}), 'Ubuntu')
        for odd in (None, [], 'AlmaLinux', {'ecosystem': None}, {'ecosystem': 7}, {}):
            self.assertEqual(name(odd), '')

    def test_the_fleet_lookup_asks_under_the_release_too(self):
        store = {'a': {'ecosystem': 'AlmaLinux', 'version_id': '9.4',
                       'packages': [{'name': 'openssl-libs', 'version': '3.0.7-16.el9'}]}}
        found = cve_scanner.prefetch_osv(store, self.dir)
        self.assertEqual(list(found), [('AlmaLinux:9', 'openssl-libs', '3.0.7-16.el9')])


class TestDebianAndUbuntuAreAskedBySourceWhenTheReleaseIsKnown(unittest.TestCase):
    """The plan only. What a scan then finds is in tests/test_v801_deb_source_matching.py."""

    PACKAGES = [{'name': 'libc6', 'version': '2.36-9+deb12u7', 'source': 'glibc'},
                {'name': 'libc-bin', 'version': '2.36-9+deb12u7', 'source': 'glibc'},
                {'name': 'libgcc-s1', 'version': '12.2.0-14+b1', 'source': 'gcc-12', 'source_version': '12.2.0-14'},
                {'name': 'openssl', 'version': '3.0.15-1'}]

    def test_one_question_per_source_package_and_its_version(self):
        for ecosystem in ('Debian:12', 'Ubuntu'):
            units = cve_scanner.plan(self.PACKAGES, ecosystem, True, True)
            self.assertEqual([(u['name'], u['version'], u['package'], u['binaries']) for u in units],
                             [('glibc', '2.36-9+deb12u7', 'glibc', ['libc6', 'libc-bin']),
                              ('gcc-12', '12.2.0-14', 'gcc-12', ['libgcc-s1']),      # the source's own version
                              ('openssl', '3.0.15-1', 'openssl', ['openssl'])], ecosystem)

    def test_without_the_release_or_without_sources_it_is_one_question_per_installed_name(self):
        by_name = [('libc6', '2.36-9+deb12u7', 'libc6', []), ('libc-bin', '2.36-9+deb12u7', 'libc-bin', []),
                   ('libgcc-s1', '12.2.0-14+b1', 'libgcc-s1', []), ('openssl', '3.0.15-1', 'openssl', [])]
        for ecosystem in ('Debian:12', 'Ubuntu'):
            for has_meta, by_source in ((True, False), (False, True), (False, False)):
                units = cve_scanner.plan(self.PACKAGES, ecosystem, has_meta, by_source)
                self.assertEqual([(u['name'], u['version'], u['package'], u['binaries']) for u in units], by_name,
                                 (ecosystem, has_meta, by_source))

    def test_when_a_host_is_asked_by_source(self):
        by_source = cve_scanner.by_source
        self.assertTrue(by_source('Debian:12', ''))
        self.assertTrue(by_source('Debian:12', 'Debian:12'))
        self.assertTrue(by_source('Ubuntu', 'Ubuntu:22.04:LTS'))
        self.assertTrue(by_source('Ubuntu', 'Ubuntu:24.10'))
        self.assertFalse(by_source('Ubuntu', ''))                       # a derivative with a version of its own
        self.assertFalse(by_source('Ubuntu', 'Ubuntu:Pro:FIPS:20.04:LTS'))
        for other in ('Alpine:v3.19', 'Rocky Linux:9', 'AlmaLinux:9', 'Red Hat', '', None, 7):
            self.assertFalse(by_source(other, 'Debian:12'), other)

    def test_the_page_is_told_what_a_scan_leaves_out(self):
        coverage = cve_scanner.coverage
        self.assertEqual(coverage('Debian:12', True), '')
        self.assertEqual(coverage('Debian:12', False), 'needs_agent')
        self.assertEqual(coverage('Ubuntu', True, 'Ubuntu:22.04:LTS'), '')
        self.assertEqual(coverage('Ubuntu', False, 'Ubuntu:22.04:LTS'), 'needs_agent')
        self.assertEqual(coverage('Ubuntu', True), 'no_release')
        self.assertEqual(coverage('Ubuntu', False), 'no_release')       # a newer agent would not change it
        self.assertEqual(coverage('Alpine:v3.19', True), '')
        self.assertEqual(coverage('Rocky Linux:9', True), '')
        self.assertEqual(coverage('Rocky Linux:9', False), 'needs_agent')
        self.assertEqual(coverage('AlmaLinux:9', False), '')      # asked by package name, whole
        self.assertEqual(coverage('Red Hat', False), '')
        self.assertEqual(coverage('', False), '')


class TestThePlan(unittest.TestCase):
    def test_a_package_listed_twice_is_one_question(self):
        units = cve_scanner.plan([{'name': 'libc6', 'version': '2.36-9', 'arch': 'amd64'},
                                  {'name': 'libc6', 'version': '2.36-9', 'arch': 'i386'}], 'Debian:12')
        self.assertEqual(len(units), 1)

    def test_a_list_without_sources_is_asked_name_by_name_whatever_the_format(self):
        pkgs = [{'name': 'openssl-libs', 'version': '3.0.7-16.el9', 'epoch': '1', 'source': 'openssl'}]
        for ecosystem in ('Rocky Linux:9', 'AlmaLinux:9', 'Alpine:v3.18'):
            units = cve_scanner.plan(pkgs, ecosystem, False)
            self.assertEqual([(u['name'], u['version'], u['package'], u['binaries']) for u in units],
                             [('openssl-libs', '3.0.7-16.el9', 'openssl-libs', [])], ecosystem)
        self.assertFalse(cve_scanner.plan(pkgs, 'AlmaLinux:9', False)[0]['epoch_known'])
        self.assertTrue(cve_scanner.plan(pkgs, 'AlmaLinux:9', True)[0]['epoch_known'])

    def test_what_is_not_a_package_is_skipped(self):
        junk = [None, 7, 'x', [], {}, {'name': 'a'}, {'version': '1'}, {'name': '', 'version': '1'},
                {'name': 'ok', 'version': '1-1', 'epoch': 'x', 'source': None, 'source_version': 5}]
        for ecosystem in ('Rocky Linux:9', 'Alpine:v3.18', 'Debian:12'):
            for meta in (False, True):
                units = cve_scanner.plan(junk, ecosystem, meta)
                self.assertEqual([u['name'] for u in units], ['ok'], (ecosystem, meta))
        self.assertEqual(cve_scanner.plan(None, 'Rocky Linux:9', True), [])
        self.assertEqual(cve_scanner.plan('nope', 'Alpine:v3.18', True), [])

    def test_the_list_of_installed_names_on_a_finding_is_bounded(self):
        many = [{'name': f'lib{i:03d}', 'version': '1-r0', 'source': 'big'} for i in range(45)]
        key = ('Alpine:v3.18', 'big', '1-r0')
        db = Database()
        with mock.patch.dict(QUERIES, {key: ['ALPINE-CVE-2023-5363']}), \
                mock.patch.object(cve_scanner, '_osv_querybatch', db.querybatch), \
                mock.patch.object(cve_scanner, '_osv_vuln_details', db.details):
            result = cve_scanner.scan_device(HOST, many, 'Alpine:v3.18', Path(tempfile.mkdtemp()), has_meta=True)
        (finding,) = result['findings']
        self.assertEqual(len(finding['binaries']), cve_scanner.MAX_BINARIES_SHOWN)
        self.assertEqual(finding['binaries_more'], 45 - cve_scanner.MAX_BINARIES_SHOWN)
        self.assertNotIn('_binaries', finding)


class TestALongAnswerIsReadToTheEnd(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix='rp-v801-cve-page-'))
        self.calls = []

    def pages(self, total, endless=False):
        def querybatch(body):
            self.calls.append([dict(q) for q in body])
            out = []
            for q in body:
                page = int(q.get('page_token') or 0)
                answer = {'vulns': [{'id': f'X-{q["package"]["name"]}-{page}'}]}
                if endless or page + 1 < total:
                    answer['next_page_token'] = str(page + 1)
                out.append(answer)
            return out
        return querybatch

    def test_every_page_is_asked_for_with_its_token(self):
        queries = [{'package': {'name': 'kernel', 'ecosystem': 'Rocky Linux:9'}, 'version': '1-1'},
                   {'package': {'name': 'small', 'ecosystem': 'Rocky Linux:9'}, 'version': '1-1'}]
        short = self.pages(1)

        def querybatch(body):                      # "kernel" has three pages, "small" has one
            out = []
            for q in body:
                if q['package']['name'] == 'kernel':
                    out.extend(self.pages(3)([q]))
                else:
                    out.extend(short([q]))
            return out
        with mock.patch.object(cve_scanner, '_osv_querybatch', querybatch):
            answers = cve_scanner._osv_query_all(queries)
        self.assertEqual([v['id'] for v in answers[0]['vulns']], ['X-kernel-0', 'X-kernel-1', 'X-kernel-2'])
        self.assertEqual([v['id'] for v in answers[1]['vulns']], ['X-small-0'])
        self.assertNotIn('truncated', answers[0])
        self.assertNotIn('page_token', queries[0])           # the caller's queries are not written into

    def test_the_first_page_alone_was_the_old_answer(self):
        """The control: without following the token the scan holds one advisory of three."""
        with mock.patch.object(cve_scanner, '_osv_querybatch', self.pages(3)), \
                mock.patch.object(cve_scanner, 'OSV_MAX_PAGES', 1):
            answers = cve_scanner._osv_query_all([{'package': {'name': 'k', 'ecosystem': 'e'}, 'version': '1'}])
        self.assertEqual(len(answers[0]['vulns']), 1)
        self.assertTrue(answers[0]['truncated'])

    def test_an_answer_that_never_ends_is_cut_and_the_scan_says_so(self):
        with mock.patch.object(cve_scanner, '_osv_querybatch', self.pages(0, endless=True)), \
                mock.patch.object(cve_scanner, '_osv_vuln_details', lambda vid: None):
            result = cve_scanner.scan_device(HOST, [{'name': 'kernel', 'version': '5.14.0-1.el9'}],
                                             'Rocky Linux:9', self.dir)
        self.assertEqual(len(self.calls), cve_scanner.OSV_MAX_PAGES)
        self.assertEqual(result['cut'], ['kernel'])
        self.assertEqual(len(result['findings']), cve_scanner.OSV_MAX_PAGES)

    def test_a_whole_answer_is_not_called_cut(self):
        with mock.patch.object(cve_scanner, '_osv_querybatch', self.pages(2)), \
                mock.patch.object(cve_scanner, '_osv_vuln_details', lambda vid: None):
            result = cve_scanner.scan_device(HOST, [{'name': 'kernel', 'version': '5.14.0-1.el9'}],
                                             'Rocky Linux:9', self.dir)
        self.assertEqual(result['cut'], [])
        self.assertEqual(len(result['findings']), 2)

    ONE = [{'package': {'name': 'k', 'ecosystem': 'e'}, 'version': '1'}]

    def test_an_answer_of_another_shape_is_a_failure_not_an_empty_answer(self):
        """Read as "no advisories", a short or malformed answer would empty the host's findings."""
        for odd in (None, 'x', {}, [], [{}, {}], [None], [7], ['x'], [{'vulns': 'x'}], [{'vulns': {'id': 'A-1'}}],
                    [{'vulns': [None]}], [{'vulns': [{'id': 'A-1'}, 3]}]):
            with mock.patch.object(cve_scanner, '_osv_querybatch', lambda body, odd=odd: odd):
                with self.assertRaises(ValueError, msg=repr(odd)):
                    cve_scanner._osv_query_all(self.ONE)

    def test_the_shapes_the_database_does_send(self):
        for fine, ids in (([{}], []), ([{'vulns': []}], []), ([{'vulns': [{'id': 'A-1', 'modified': 'x'}], 'more': 1}],
                                                                  ['A-1'])):
            with mock.patch.object(cve_scanner, '_osv_querybatch', lambda body, fine=fine: fine):
                answers = cve_scanner._osv_query_all(self.ONE)
            self.assertEqual([v['id'] for v in answers[0]['vulns']], ids)

    def test_a_scan_that_got_such_an_answer_reports_it_and_holds_no_findings(self):
        with mock.patch.object(cve_scanner, '_osv_querybatch', lambda body: []):
            result = cve_scanner.scan_device(HOST, [{'name': 'kernel', 'version': '5.14.0-1.el9'}], 'Rocky Linux:9',
                                             self.dir)
        self.assertIn('OSV query failed', result['error'])
        self.assertTrue(result['partial'])
        self.assertEqual(result['findings'], [])        # with an error: the worker keeps the host's last findings


class TestOneFailedRequestDoesNotEmptyTheFleet(unittest.TestCase):
    STORE = {'a': {'ecosystem': 'AlmaLinux:9', 'packages': [{'name': 'openssl-libs', 'version': '3.0.7-16.el9'}]},
             'b': {'ecosystem': 'Alpine:v3.18', 'packages': [{'name': 'libcrypto3', 'version': '3.1.0-r0'}]}}

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix='rp-v801-cve-pf-'))

    def test_the_lookup_says_it_failed_instead_of_returning_half(self):
        db, calls = Database(), []

        def second_fails(body):
            calls.append(1)
            if len(calls) == 2:
                raise OSError('connection reset')
            return db.querybatch(body)
        with mock.patch.object(cve_scanner, '_osv_querybatch', second_fails):
            self.assertIsNone(cve_scanner.prefetch_osv(self.STORE, self.dir))
        self.assertEqual(len(calls), 2)

    def test_the_lookup_plans_a_list_the_way_the_scan_does(self):
        """`sources` is the mark only when it is true. Anything else in its place is no mark, for both."""
        pkgs = [{'name': 'openssl-libs', 'version': '3.0.7-16.el9', 'epoch': '1', 'source': 'openssl'}]
        for mark in (1, 'yes', [1], {'a': 1}):
            db = Database()
            with mock.patch.object(cve_scanner, '_osv_querybatch', db.querybatch):
                found = cve_scanner.prefetch_osv({'a': {'ecosystem': 'AlmaLinux:9', 'sources': mark, 'packages': pkgs}},
                                                 self.dir)
            self.assertEqual(list(found), [('AlmaLinux:9', 'openssl-libs', '3.0.7-16.el9')], mark)

    def test_a_whole_lookup_is_a_map_and_an_open_breaker_is_an_empty_one(self):
        db = Database()
        with mock.patch.object(cve_scanner, '_osv_querybatch', db.querybatch):
            found = cve_scanner.prefetch_osv(self.STORE, self.dir)
        self.assertEqual(sorted(found), [('AlmaLinux:9', 'openssl-libs', '3.0.7-16.el9'),
                                         ('Alpine:v3.18', 'libcrypto3', '3.1.0-r0')])
        for _ in range(cve_scanner.OSV_FAIL_THRESHOLD):
            cve_scanner.osv_breaker_record(self.dir, ok=False)
        self.assertEqual(cve_scanner.prefetch_osv(self.STORE, self.dir), {})


class TestTheWorker(unittest.TestCase):
    """The scan as the product runs it: the real worker, the real stores, the network replaced."""

    def setUp(self):
        self.events = []
        self._saved = (api.fire_webhook, api.audit_log)
        api.fire_webhook = lambda event, payload: self.events.append((event, dict(payload)))
        api.audit_log = lambda *a, **k: None
        self.cache = Path(tempfile.mkdtemp(prefix='rp-v801-cve-worker-'))
        self._data_dir = mock.patch.object(api, 'DATA_DIR', self.cache)
        self._data_dir.start()
        api.save(api.CONFIG_FILE, {})
        api.save(api.DEVICES_FILE, {
            'v801cvea': {'id': 'v801cvea', 'name': 'alma-a', 'token': 't', 'monitored': True},
            'v801cveb': {'id': 'v801cveb', 'name': 'alma-b', 'token': 't', 'monitored': True}})
        api.save(api.PACKAGES_FILE, {
            'v801cvea': {'ecosystem': 'AlmaLinux', 'version_id': '9.4', 'pkg_manager': 'dnf',
                         'packages': [{'name': 'openssl-libs', 'version': '3.0.7-16.el9'}]},
            'v801cveb': {'ecosystem': 'AlmaLinux:9', 'version_id': '9.4', 'pkg_manager': 'dnf', 'sources': True,
                         'packages': [{'name': 'openssl-libs', 'version': '3.0.7-16.el9', 'epoch': '1',
                                       'source': 'openssl'}]}})
        self.before = [{'vuln_id': 'ALSA-2024:6783', 'package': 'openssl-libs', 'version': '3.0.7-16.el9',
                        'severity': 'high', 'fixed_version': '1:3.0.7-28.el9_4', 'fix_status': 'unknown'}]
        api.save(api.CVE_FINDINGS_FILE, {'v801cvea': {'scanned_at': 1, 'ecosystem': 'AlmaLinux',
                                                      'findings': list(self.before)}})
        api.save(api.CVE_IGNORE_FILE, {})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        api.fire_webhook, api.audit_log = self._saved
        self._data_dir.stop()
        for f, empty in ((api.DEVICES_FILE, {}), (api.PACKAGES_FILE, {}), (api.CVE_FINDINGS_FILE, {})):
            api.save(f, empty)
        api._LOAD_CACHE.clear()

    def findings(self):
        api._LOAD_CACHE.clear()
        return api.load(api.CVE_FINDINGS_FILE) or {}

    def test_both_hosts_get_their_findings_under_the_release(self):
        db = Database()
        with mock.patch.object(cve_scanner, '_osv_querybatch', db.querybatch), \
                mock.patch.object(cve_scanner, '_osv_vuln_details', db.details):
            api._cve_scan_worker('tester', None)
        stored = self.findings()
        want = recorded('AlmaLinux:9', 'openssl-libs', '1:3.0.7-16.el9')
        for host in ('v801cvea', 'v801cveb'):
            self.assertEqual(sorted(f['vuln_id'] for f in stored[host]['findings']), want, host)
            self.assertEqual(stored[host]['ecosystem'], 'AlmaLinux:9')
        self.assertEqual({f['package'] for f in stored['v801cvea']['findings']}, {'openssl-libs'})
        self.assertEqual({f['package'] for f in stored['v801cveb']['findings']}, {'openssl'})
        self.assertEqual({k[0] for k in db.asked}, {'AlmaLinux:9'})          # never the bare name
        self.assertEqual([e for e, _p in self.events if e == 'cve_cleared'], [])

    def test_a_failed_lookup_leaves_the_last_findings_and_clears_nothing(self):
        def down(body):
            raise OSError('connection reset')
        with mock.patch.object(cve_scanner, '_osv_querybatch', down), \
                mock.patch.object(cve_scanner, '_osv_vuln_details', lambda vid: None):
            api._cve_scan_worker('tester', None)
        stored = self.findings()
        self.assertEqual(stored['v801cvea']['findings'], self.before)
        self.assertNotIn('v801cveb', stored)
        self.assertEqual([e for e, _p in self.events if e == 'cve_cleared'], [])

    HALF = {('AlmaLinux:9', 'openssl-libs', '3.0.7-16.el9'):
            {'vulns': [{'id': i} for i in QUERIES[('AlmaLinux:9', 'openssl-libs', '3.0.7-16.el9')]]}}

    def test_what_the_lookup_did_not_hold_is_asked_for(self):
        """A map that holds one host's question and not the other's: the other is asked now. It used to be
        read as "no advisories", and that host lost its findings."""
        db = Database()
        with mock.patch.object(cve_scanner, 'prefetch_osv', lambda store, cache_dir: dict(self.HALF)), \
                mock.patch.object(cve_scanner, '_osv_querybatch', db.querybatch), \
                mock.patch.object(cve_scanner, '_osv_vuln_details', db.details):
            api._cve_scan_worker('tester', None)
        stored = self.findings()
        want = recorded('AlmaLinux:9', 'openssl-libs', '1:3.0.7-16.el9')
        self.assertEqual(sorted(f['vuln_id'] for f in stored['v801cvea']['findings']), want)
        self.assertEqual(sorted(f['vuln_id'] for f in stored['v801cveb']['findings']), want)
        self.assertEqual(db.asked, [('AlmaLinux:9', 'openssl-libs', '1:3.0.7-16.el9')])     # only what was missing

    def test_what_it_did_not_hold_and_cannot_be_asked_for_clears_nothing(self):
        def down(body):
            raise OSError('connection reset')
        db = Database()
        api.save(api.CVE_FINDINGS_FILE, {'v801cveb': {'scanned_at': 1, 'ecosystem': 'AlmaLinux:9',
                                                      'findings': list(self.before)}})
        api._LOAD_CACHE.clear()
        with mock.patch.object(cve_scanner, 'prefetch_osv', lambda store, cache_dir: dict(self.HALF)), \
                mock.patch.object(cve_scanner, '_osv_querybatch', down), \
                mock.patch.object(cve_scanner, '_osv_vuln_details', db.details):
            api._cve_scan_worker('tester', None)
        stored = self.findings()
        self.assertEqual(len(stored['v801cvea']['findings']), 13)             # the host the map held
        self.assertEqual(stored['v801cveb']['findings'], self.before)         # the other keeps what it had
        self.assertEqual([e for e, _p in self.events if e == 'cve_cleared'], [])

    def test_the_worker_hands_the_scan_the_release_and_the_mark(self):
        block = srcpin.py_function((_CGI / 'api.py').read_text(), '_cve_scan_worker')
        self.assertIn('cve_scanner.entry_ecosystem(entry)', block)
        self.assertIn("has_meta=entry.get('sources') is True", block)
        self.assertNotIn("entry['ecosystem'], DATA_DIR", block)


class _Captured(Exception):
    def __init__(self, status, body):
        super().__init__(status)
        self.status, self.body = status, body


class TestWhatTheServerKeepsOfAList(unittest.TestCase):
    def setUp(self):
        self._saved = (api.respond, api.method, api.get_json_obj, api.require_auth, api._eval_software_policy)

        def respond(status, data):
            raise _Captured(status, data)
        api.respond = respond
        api.method = lambda: 'POST'
        api._eval_software_policy = lambda *a, **k: None
        api.save(api.DEVICES_FILE, {HOST: {'id': HOST, 'name': 'box', 'token': 'tok', 'monitored': True}})
        api.save(api.PACKAGES_FILE, {})
        api.save(api.CVE_FINDINGS_FILE, {})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        (api.respond, api.method, api.get_json_obj, api.require_auth, api._eval_software_policy) = self._saved
        for f in (api.DEVICES_FILE, api.PACKAGES_FILE, api.CVE_FINDINGS_FILE):
            api.save(f, {})
        api._LOAD_CACHE.clear()

    def submit(self, body):
        api.get_json_obj = lambda: dict({'device_id': HOST, 'token': 'tok'}, **body)
        api._LOAD_CACHE.clear()
        try:
            api.handle_packages_submit()
        except _Captured as c:
            self.assertEqual(c.status, 200, c.body)
            api._LOAD_CACHE.clear()
            return c.body, (api.load(api.PACKAGES_FILE) or {}).get(HOST) or {}
        self.fail('the handler did not answer')

    def test_one_package_with_everything(self):
        keep = api._sanitize_package_entry
        self.assertEqual(keep({'name': 'openssl-libs', 'version': '3.0.7-16.el9', 'arch': 'x86_64', 'epoch': '1',
                               'source': 'openssl', 'source_version': '3.0.7-17.el9'}),
                         {'name': 'openssl-libs', 'version': '3.0.7-16.el9', 'arch': 'x86_64', 'epoch': '1',
                          'source': 'openssl', 'source_version': '3.0.7-17.el9'})

    def test_a_field_that_adds_nothing_or_is_not_one_is_left_out(self):
        keep = api._sanitize_package_entry
        plain = {'name': 'bash', 'version': '5.2-1', 'arch': ''}
        for extra in ({'source': 'bash'}, {'source_version': '5.2-1'}, {'epoch': '0'}, {'epoch': 0}, {'epoch': ''},
                      {'epoch': '-1'}, {'epoch': '1e3'}, {'epoch': '1234567'}, {'epoch': True}, {'epoch': 1.5},
                      {'epoch': '١'}, {'source': 'a b'}, {'source': '<b>'}, {'source': ['x']}, {'source': ''},
                      {'source_version': '1 2'}, {'source_version': {'a': 1}}, {'source': 'x' * 200}):
            self.assertEqual(keep(dict({'name': 'bash', 'version': '5.2-1'}, **extra)), plain, extra)
        self.assertEqual(keep({'name': 'bash', 'version': '5.2-1', 'epoch': 7})['epoch'], '7')
        self.assertEqual(keep({'name': 'bash', 'version': '5.2-1', 'epoch': '007'})['epoch'], '7')

    def test_a_version_with_a_caret_is_a_version(self):
        # RPM writes a snapshot after a release as 1.0^20240101git; the package was dropped from the list
        self.assertEqual(api._sanitize_package_entry({'name': 'tool', 'version': '1.0^20240101git-1.el9'})['version'],
                         '1.0^20240101git-1.el9')

    def test_the_mark_is_kept_for_the_three_formats_that_have_sources(self):
        pkgs = [{'name': 'openssl-libs', 'version': '3.0.7-16.el9', 'epoch': '1', 'source': 'openssl'}]
        hint = {'ID': 'almalinux', 'VERSION_ID': '9.4', 'ID_LIKE': 'rhel'}
        answer, stored = self.submit({'pkg_manager': 'dnf', 'ecosystem_hint': hint, 'packages': pkgs, 'sources': True})
        self.assertEqual(answer['ecosystem'], 'AlmaLinux:9')
        self.assertIs(stored.get('sources'), True)
        self.assertEqual(stored['packages'], [{'name': 'openssl-libs', 'version': '3.0.7-16.el9', 'arch': '',
                                               'epoch': '1', 'source': 'openssl'}])
        for body in ({'pkg_manager': 'dnf', 'packages': pkgs},                       # not said
                     {'pkg_manager': 'dnf', 'packages': pkgs, 'sources': 'yes'},     # not the mark
                     {'pkg_manager': 'dnf', 'packages': pkgs, 'sources': 1},
                     {'pkg_manager': 'pacman', 'packages': pkgs, 'sources': True}):  # a format without sources
            _answer, stored = self.submit(dict(body, ecosystem_hint=hint))
            self.assertNotIn('sources', stored, body)

    def test_the_hash_tells_a_list_with_sources_from_the_same_list_without(self):
        h = cve_scanner.packages_hash
        plain = [{'name': 'b', 'version': '2'}, {'name': 'a', 'version': '1'}]
        self.assertEqual(h(plain), h(list(reversed(plain))))
        # the value every list without the new fields has always had
        import hashlib
        import json
        old = hashlib.sha256(json.dumps(sorted((p['name'], p['version']) for p in plain),
                                        separators=(',', ':')).encode()).hexdigest()[:16]
        self.assertEqual(h(plain), old)
        with_source = [dict(plain[0], source='src'), plain[1]]
        with_epoch = [dict(plain[0], epoch='1'), plain[1]]
        with_sv = [dict(plain[0], source_version='9'), plain[1]]
        self.assertEqual(len({h(plain), h(with_source), h(with_epoch), h(with_sv)}), 4)

    def test_the_host_view_names_the_release_what_is_left_out_and_what_was_cut(self):
        api.save(api.PACKAGES_FILE, {HOST: {'ecosystem': 'Rocky Linux', 'version_id': '9.3', 'count': 1,
                                            'packages': [{'name': 'bash', 'version': '5.1.8-9.el9'}]}})
        # a number in a stored list of names is read as its text and what is not text at all is left out
        api.save(api.CVE_FINDINGS_FILE, {HOST: {'scanned_at': 5, 'findings': [], 'cut': ['kernel', 7, None, ['x']]}})
        api._LOAD_CACHE.clear()
        api.require_auth = lambda *a, **k: 'admin'
        with mock.patch.object(api, '_kev_epss', lambda: (set(), {})):
            try:
                api.handle_cve_device(HOST)
            except _Captured as c:
                body = c.body
        self.assertEqual(body['ecosystem'], 'Rocky Linux:9')
        self.assertEqual(body['coverage'], 'needs_agent')
        self.assertEqual(body['cut'], ['kernel', '7'])


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestTheHostView(unittest.TestCase):
    """The page's own functions, under node."""

    def run_js(self, call):
        esc = re.search(r'^function escHtml\(.*$', _APP, re.M).group(0)
        esca = re.search(r'^function escAttr\(.*$', _APP, re.M).group(0)
        words = re.search(r'^const _CVE_COVERAGE = \{.*?^\};', _PAGE, re.M | re.S).group(0)
        script = '\n'.join([esc, esca, words, srcpin.js_function(_PAGE, '_cveCoverageHtml'),
                            srcpin.js_function(_PAGE, '_cveBinariesHtml'),
                            'console.log(JSON.stringify({html: %s}));' % call])
        r = subprocess.run(['node', '-e', script], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)['html']

    def coverage(self, data):
        return self.run_js('_cveCoverageHtml(%s)' % json.dumps(data))

    def binaries(self, finding):
        return self.run_js('_cveBinariesHtml(%s)' % json.dumps(finding))

    def test_each_word_the_server_sends_has_its_sentence(self):
        for word, part in (('no_release', 'The Ubuntu release this host is based on is not known'),
                           ('needs_agent', 'does not report source packages')):
            html = self.coverage({'coverage': word})
            self.assertIn(part, html)
            self.assertIn(f'data-cve-coverage="{word}"', html)
        # the two words are the ones the scanner can say
        said = {cve_scanner.coverage(e, m, r) for e in ('Debian:12', 'Ubuntu', 'Alpine:v3.18', 'Rocky Linux:9',
                                                        'AlmaLinux:9', 'Red Hat')
                for m in (False, True) for r in ('', 'Ubuntu:22.04:LTS', 'Debian:12')} - {''}
        self.assertEqual(said, {'no_release', 'needs_agent'})

    def test_a_word_it_does_not_know_prints_nothing(self):
        for word in ('', 'other', 'own_name', 'constructor', '__proto__', 'toString', 7, None, ['no_release'],
                     {'a': 1}):
            self.assertEqual(self.coverage({'coverage': word}), '', word)
        self.assertEqual(self.coverage({}), '')

    def test_the_cut_packages_are_named_and_escaped(self):
        html = self.coverage({'cut': ['kernel', '<img src=x onerror=1>']})
        self.assertIn('was longer than a scan reads', html)
        self.assertIn('kernel, &lt;img src=x onerror=1&gt;', html)
        self.assertNotIn('<img', html)
        for none in ([], None, 'kernel', {'0': 'kernel'}, 5):
            self.assertEqual(self.coverage({'cut': none}), '', none)

    def test_the_installed_packages_of_a_finding(self):
        html = self.binaries({'binaries': ['libcrypto3', 'libssl3']})
        self.assertIn('<span>installed as</span>', html)
        self.assertIn('libcrypto3, libssl3', html)
        self.assertIn('libssl3 +15<', self.binaries({'binaries': ['libcrypto3', 'libssl3'], 'binaries_more': 15}))
        self.assertNotIn('+', self.binaries({'binaries': ['a'], 'binaries_more': '<b>'}))
        self.assertIn('&lt;b&gt;', self.binaries({'binaries': ['<b>']}))
        for none in ({}, {'binaries': []}, {'binaries': 'libssl3'}, {'binaries': None}, {'binaries': {'length': 2}}):
            self.assertEqual(self.binaries(none), '', none)

    def test_the_host_view_prints_both(self):
        view = srcpin.js_function(_PAGE, 'openDeviceCVE')
        self.assertIn('_cveCoverageHtml(data)', view)
        self.assertIn('_cveBinariesHtml(f)', view)

    def test_the_four_texts_are_in_six_languages(self):
        from test_v710_i18n_glue import dict_rows
        rows = dict_rows()
        words = re.findall(r"^  [a-z_]+: '([^']+)',$", re.search(r'^const _CVE_COVERAGE = \{.*?^\};', _PAGE,
                                                                 re.M | re.S).group(0), re.M)
        self.assertEqual(len(words), 2)
        for text in words + ['The advisory list of these packages was longer than a scan reads, so it is cut:',
                             'installed as']:
            self.assertIn(text, _PAGE)
            self.assertTrue(rows.get(text) and all(rows[text].get(lang) for lang in ('zh', 'hi', 'es', 'ar', 'de', 'fr')),
                            text)


if __name__ == '__main__':
    unittest.main()

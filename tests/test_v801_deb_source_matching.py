"""Debian and Ubuntu hosts are matched by source package, and a scan stores what can be acted on (8.0.1).

OSV files a Debian or Ubuntu advisory under the source package: "glibc" answers, "libc6" answers nothing. Asked
by installed name, a host was never told about its libraries, its SSH server or its kernel. Asked by source
package, it is told about every known CVE of its release, fixed or not: more than a thousand for the kernel alone.

So the scan asks by source, and stores one by one only what an update for the host's release clears, what is
critical or high, and what is known to be exploited (`cve_fixes.kept`), at most 300 for a host and 50 for a
package. Everything else is counted per package in `rollup`, with its severity and its fix status.

Replayed here from two recordings of api.osv.dev made on 2026-11-15
(tests/data/osv_recorded_debian_2026-11-15.tsv and osv_recorded_ubuntu_2026-11-15.tsv): the queries, the ids each
returned, and what each advisory record says about the packages asked. A query that was not recorded fails the
test that makes it.

What the recordings also showed, and is held here:
  * a record has no `aliases`; its CVE id is in `upstream`. The known-exploited list and EPSS go by CVE id and
    matched nothing on any distribution's findings;
  * a Debian or Ubuntu notice (DSA, USN) comes back beside the records of its CVEs. For 78 of the 81 notices read
    that day a per-CVE record carries the same fix, so the notice was those findings a second time; three carry a
    fix no CVE record has, so a notice is left out only when another finding reaches its fix;
  * Debian marks a package "unimportant" per release, and a CVSS score calls 8 of the 20 such records here critical
    or high (13 of 38 in the full recording);
  * Ubuntu keeps the fixes of Ubuntu Pro in entries of their own, and a release past its standard support only there;
  * the stamp of a query answer and of the record are the same instant written with 6 and with 9 digits.
"""
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v801-deb-'))
_spec = importlib.util.spec_from_file_location('api_v801_deb', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
cve_scanner = api.cve_scanner
cve_fixes = api.cve_fixes

import pkg_versions  # noqa: E402
import srcpin  # noqa: E402
from osv_recording import (BEHIND, BEHIND_ASKED, DEB, PATCHED, UBU, Database, per_cve)  # noqa: E402

_JS = ROOT / 'server' / 'html' / 'static' / 'js'
_APP = (_JS / 'app.js').read_text()
_PAGE = (_JS / 'app-cve.js').read_text()
HAVE_NODE = shutil.which('node') is not None
HOST = 'v801debhost'


class _Scan(unittest.TestCase):
    RECORDING = DEB

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix='rp-v801-deb-scan-'))
        self.db = Database(self.RECORDING)
        for patcher in (mock.patch.object(cve_scanner, '_osv_querybatch', self.db.querybatch),
                        mock.patch.object(cve_scanner, '_osv_vuln_details', self.db.details),
                        mock.patch.object(cve_scanner, '_debian_severity_fallback',
                                          side_effect=AssertionError('the tracker was asked'))):
            patcher.start()
            self.addCleanup(patcher.stop)

    def scan(self, packages, ecosystem, has_meta=True, **kw):
        result = cve_scanner.scan_device(HOST, packages, ecosystem, self.dir, has_meta=has_meta, **kw)
        self.assertNotIn('error', result, result.get('error'))
        return result

    def by_id(self, result):
        return {f['vuln_id']: f for f in result['findings']}

    def assertRollupAddsUp(self, result):
        counted = result.get('rollup')
        if not counted:
            return 0
        total = counted['total']
        self.assertEqual(sum(counted['severity'].values()), total, counted)
        self.assertEqual(sum(counted['fix'].values()), total, counted)
        self.assertEqual(sum(p['count'] for p in counted['packages']) + counted['more']['count'], total, counted)
        self.assertLessEqual(len(counted['packages']), cve_fixes.ROLLUP_PACKAGES)
        return total


class TestTheRecordings(unittest.TestCase):
    def test_the_helper_and_the_scanner_agree_on_what_a_per_cve_id_is(self):
        import osv_recording
        self.assertEqual(osv_recording.PER_CVE_IDS, cve_scanner._PER_CVE_IDS)

    def test_a_query_that_was_not_recorded_fails_the_test_that_makes_it(self):
        import osv_recording
        with self.assertRaises(osv_recording.NotRecorded):
            Database(DEB).querybatch([{'package': {'ecosystem': 'Debian:12', 'name': 'nginx'}, 'version': '1.22.1-9'}])
        with self.assertRaises(osv_recording.NotRecorded):
            Database(DEB).details('DEBIAN-CVE-1999-0001')

    def test_they_hold_what_the_tests_say(self):
        self.assertEqual((len(DEB.queries), len(UBU.queries)), (10, 10))
        self.assertEqual([len(DEB.queries[k]) for k in BEHIND_ASKED], [46, 44, 7, 4])
        self.assertEqual(len(per_cve(DEB, BEHIND_ASKED)), 95)
        for name in ('libc6', 'openssh-server', 'zlib1g'):
            (key,) = [k for k in DEB.queries if k[1] == name]
            self.assertEqual(DEB.queries[key], [], name)              # asked by installed name: nothing
        self.assertEqual(UBU.queries[('Ubuntu', 'libc6', '2.35-0ubuntu3.6')], [])
        self.assertEqual(len(UBU.queries[('Ubuntu', 'glibc', '2.35-0ubuntu3.6')]), 39)

    def test_every_id_a_query_returned_has_its_record(self):
        for rec in (DEB, UBU):
            missing = sorted({i for ids in rec.queries.values() for i in ids} - set(rec.entries))
            self.assertEqual(missing, [])


class TestTheDebianOrderAgainstTheRecording(unittest.TestCase):
    """An advisory came back exactly when the version asked was below its fix. So the recording says how OSV
    orders Debian versions, and `pkg_versions.deb_compare` has to say the same."""

    def check(self, recording, release, keys):
        checked, wrong = 0, []
        for key in keys:
            _eco, package, version = key
            got = set(recording.queries[key])
            for vid, entries in recording.entries.items():
                for ecosystem, name, _introduced, fixed, _urgency in entries:
                    if ecosystem != release or name != package:
                        continue
                    checked += 1
                    below = fixed == '-' or pkg_versions.deb_compare(version, fixed) < 0
                    if below != (vid in got):
                        wrong.append((package, version, vid, fixed))
        return checked, wrong

    def test_debian_twelve(self):
        checked, wrong = self.check(DEB, 'Debian:12', list(DEB.queries))
        self.assertEqual(wrong, [])
        self.assertGreater(checked, 150)

    def test_ubuntu_jammy(self):
        keys = [k for k in UBU.queries if k[1] in ('glibc', 'openssh', 'sudo')]
        checked, wrong = self.check(UBU, 'Ubuntu:22.04:LTS', keys)
        self.assertEqual(wrong, [])
        self.assertGreater(checked, 150)

    def test_the_check_can_fail(self):
        """The control: an order that reads a version as text gets recorded answers wrong."""
        as_text = lambda a, b: (a > b) - (a < b)      # noqa: E731
        with mock.patch.object(pkg_versions, 'deb_compare', as_text):
            _checked, wrong = self.check(DEB, 'Debian:12', list(DEB.queries))
        self.assertGreater(len(wrong), 5)

    def test_the_scan_uses_it_and_starts_no_process(self):
        with mock.patch('subprocess.run', side_effect=AssertionError('a process was started')):
            self.assertTrue(cve_scanner._already_patched('2.36-9+deb12u14', '2.36-9+deb12u4', 'Debian:12'))
            self.assertFalse(cve_scanner._already_patched('2.36-9+deb12u3', '2.36-9+deb12u4', 'Debian:12'))
            self.assertFalse(cve_scanner._already_patched('1:8.9p1-3ubuntu0.6', '1:8.9p1-3ubuntu0.7', 'Ubuntu'))
            self.assertFalse(cve_scanner._already_patched('not a version', '1.0-1', 'Debian:12'))


class TestADebianHostAskedBySource(_Scan):
    def setUp(self):
        super().setUp()
        self.result = self.scan(BEHIND, 'Debian:12')
        self.found = self.by_id(self.result)

    def test_four_source_packages_are_asked_for_and_no_installed_name(self):
        self.assertEqual(self.db.asked, BEHIND_ASKED)

    def test_the_ssh_server_is_told_about_its_fix(self):
        """CVE-2024-6387: asked as "openssh-server" the host never heard of it."""
        finding = self.found['DEBIAN-CVE-2024-6387']
        self.assertEqual((finding['package'], finding['version'], finding['fix_status'], finding['fixed_version']),
                         ('openssh', '1:9.2p1-2+deb12u2', 'fixed', '1:9.2p1-2+deb12u3'))
        self.assertEqual(finding['binaries'], ['openssh-client', 'openssh-server'])

    def test_a_library_is_filed_under_its_source_with_the_packages_built_from_it(self):
        glibc = [f for f in self.result['findings'] if f['package'] == 'glibc']
        self.assertGreater(len(glibc), 10)
        for f in glibc:
            self.assertEqual(f['binaries'], ['libc-bin', 'libc6'])
        (zlib,) = {f['version'] for f in self.result['findings'] if f['package'] == 'zlib'} or {'1:1.2.13.dfsg-1'}
        self.assertEqual(zlib, '1:1.2.13.dfsg-1')            # the source's version, not the rebuilt package's

    def test_every_cve_is_stored_or_counted_and_none_twice(self):
        stored = len(self.result['findings'])
        counted = self.assertRollupAddsUp(self.result)
        self.assertEqual(stored + counted, len(per_cve(DEB, BEHIND_ASKED)))
        self.assertEqual(len(self.found), stored)                                 # one finding per id
        self.assertGreater(stored, 30)
        self.assertGreater(counted, 20)

    def test_a_notice_is_not_a_second_finding(self):
        notices = sorted({i for k in BEHIND_ASKED for i in DEB.queries[k] if i.startswith('DSA-')})
        self.assertEqual(len(notices), 6)
        self.assertEqual(self.result['duplicates'], 6)
        self.assertEqual([i for i in self.found if i.startswith(cve_scanner._NOTICE_IDS)], [])
        # each was read, to see that the records of its CVEs already reach its fix
        self.assertEqual(sorted(i for i in self.db.read if i.startswith('DSA-')), notices)

    def test_what_is_stored_is_what_the_rule_keeps(self):
        self.assertIs(self.result['ruled'], True)
        for f in self.result['findings']:
            self.assertTrue(cve_fixes.kept(f), f)
        fixable = [i for k in BEHIND_ASKED for i in DEB.queries[k] if i.startswith('DEBIAN-CVE-')
                   and any(e[0] == 'Debian:12' and e[1] == k[1] and e[3] != '-' for e in DEB.entries[i])]
        self.assertEqual(sorted(i for i, f in self.found.items() if f['fix_status'] == 'fixed'), sorted(fixable))
        self.assertGreater(len(fixable), 25)

    def test_what_is_counted_is_medium_or_lower_with_no_fix_for_this_release(self):
        counted = self.result['rollup']
        self.assertEqual(set(counted['severity']) - {'medium', 'low', 'unknown'}, set())
        self.assertEqual(set(counted['fix']) - {'newer_release', 'none', 'unchecked'}, set())
        self.assertEqual({p['name'] for p in counted['packages']}, {'glibc', 'openssh', 'sudo', 'zlib'})

    def test_the_cve_name_is_among_the_other_names(self):
        for vid, f in self.found.items():
            self.assertIn(vid.replace('DEBIAN-', ''), f['aliases'], vid)

    def test_a_package_debian_calls_unimportant_is_low_whatever_a_score_says(self):
        minor = [(vid, e[1]) for vid, entries in DEB.entries.items() for e in entries
                 if e[0] == 'Debian:12' and e[4] == 'unimportant'
                 and vid in {i for k in BEHIND_ASKED for i in DEB.queries[k]}]
        self.assertGreater(len(minor), 10)
        scored_high = [vid for vid, _pkg in minor
                       if cve_scanner._severity_from_vuln(DEB.record(vid), 'Debian:13')[0] in ('critical', 'high')]
        self.assertGreater(len(scored_high), 2, 'the recording holds none a score calls high: the test would hold nothing')
        for vid, _pkg in minor:
            self.assertNotIn(vid, self.found, vid)                 # low, no fix: counted, not stored
        self.assertGreaterEqual(self.result['rollup']['severity'].get('low', 0), len(minor))

    def test_the_tracker_is_not_asked(self):
        # _debian_severity_fallback raises in this class's setUp if it is called at all
        self.assertGreater(len(self.db.read), 80)

    def test_a_cve_on_the_known_exploited_list_is_stored_whatever_its_fix(self):
        counted_only = sorted(set(per_cve(DEB, BEHIND_ASKED)) - set(self.found))
        victim = next(i for i in counted_only
                      if not any(e[0] == 'Debian:12' and e[4] == 'unimportant' for e in DEB.entries[i]))
        kev = {victim.replace('DEBIAN-', '')}
        again = self.by_id(self.scan(BEHIND, 'Debian:12', kev=kev))
        self.assertIn(victim, again)
        self.assertFalse(cve_fixes.is_fixable(again[victim]))
        self.assertEqual(len(again), len(self.found) + 1)

    def test_and_without_the_cve_name_it_would_not_be(self):
        """The control for the test above: the list goes by CVE id, and the record keeps it in `upstream`."""
        counted_only = sorted(set(per_cve(DEB, BEHIND_ASKED)) - set(self.found))
        victim = next(i for i in counted_only
                      if not any(e[0] == 'Debian:12' and e[4] == 'unimportant' for e in DEB.entries[i]))
        with mock.patch.object(cve_scanner, '_cve_names', lambda vuln: list(vuln.get('aliases') or [])):
            shutil.rmtree(self.dir)
            self.dir.mkdir()
            again = self.by_id(self.scan(BEHIND, 'Debian:12', kev={victim.replace('DEBIAN-', '')}))
        self.assertNotIn(victim, again)


class TestANoticeThatSaysMoreThanTheCveRecords(_Scan):
    """A notice is left out when the per-CVE records of the same package already reach its fix. Three of the 81
    notices read on 2026-11-15 had no per-CVE record with their fix (an update without a CVE of its own)."""

    SUDO = ('Debian:12', 'sudo', '1.9.13p3-1+deb12u1')

    @staticmethod
    def notice(vid, *fixes):
        return {'id': vid, 'summary': 'sudo update', 'modified': '2026-11-10T08:00:00.123456789Z',
                'affected': [{'package': {'ecosystem': release, 'name': 'sudo'},
                              'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': fixed}]}]}
                             for release, fixed in fixes]}

    def scan_with(self, vid, *fixes, **kw):
        self.db = Database(DEB, extra={self.SUDO: [vid]}, records={vid: self.notice(vid, *fixes)})
        for name, fake in (('_osv_querybatch', self.db.querybatch), ('_osv_vuln_details', self.db.details)):
            patcher = mock.patch.object(cve_scanner, name, fake)
            patcher.start()
            self.addCleanup(patcher.stop)
        return self.scan(BEHIND, 'Debian:12', **kw)

    def test_the_recording_holds_what_the_case_is_built_on(self):
        fixes = sorted({e[3] for i in DEB.queries[self.SUDO] if i.startswith('DEBIAN-CVE-')
                        for e in DEB.entries[i] if e[0] == 'Debian:12' and e[1] == 'sudo' and e[3] != '-'})
        self.assertEqual(fixes, ['1.9.13p3-1+deb12u2', '1.9.13p3-1+deb12u4'])

    def test_a_fix_nothing_else_reaches_stays_a_finding(self):
        result = self.scan_with('DSA-9999-1', ('Debian:12', '1.9.13p3-1+deb12u9'))
        (kept,) = [f for f in result['findings'] if f['vuln_id'] == 'DSA-9999-1']
        self.assertEqual((kept['package'], kept['fix_status'], kept['fixed_version']),
                         ('sudo', 'fixed', '1.9.13p3-1+deb12u9'))
        self.assertEqual(result['duplicates'], 6)                 # the six recorded notices, as before

    def test_a_fix_that_a_later_fix_is_past_is_left_out(self):
        """No record carries this version, and the host is told to install a newer one anyway."""
        result = self.scan_with('DSA-9998-1', ('Debian:12', '1.9.13p3-1+deb12u3'))
        self.assertEqual([f for f in result['findings'] if f['vuln_id'].startswith('DSA-')], [])
        self.assertEqual(result['duplicates'], 7)

    def test_only_the_hosts_own_release_is_compared(self):
        """The notice also fixes Debian 11, where the per-CVE records of this answer carry nothing."""
        result = self.scan_with('DSA-9997-1', ('Debian:11', '1.9.5p2-3+deb11u9'), ('Debian:12', '1.9.13p3-1+deb12u4'))
        self.assertEqual(result['duplicates'], 7)

    def test_a_notice_that_names_no_fix_for_the_hosts_release_is_kept(self):
        result = self.scan_with('DSA-9996-1', ('Debian:13', '1.9.16p2-3+deb13u1'))
        self.assertIn('DSA-9996-1', {f['vuln_id'] for f in result['findings']})      # what cannot be compared is kept
        self.assertEqual(result['duplicates'], 6)

    def test_the_comparison_piece_by_piece(self):
        repeats = cve_scanner._notice_repeats
        det = {'eco_fix': {'Ubuntu:22.04:LTS': {'p': ['2.0-1ubuntu1.3']}, 'Ubuntu:Pro:22.04:LTS': {'p': ['2.0-1ubuntu1.3+esm1']},
                           'Ubuntu:24.04:LTS': {'p': ['2.4-1ubuntu0.2']}}}
        reach = {'Ubuntu:22.04:LTS': ['2.0-1ubuntu1.5'], 'Ubuntu:Pro:22.04:LTS': ['2.0-1ubuntu1.3+esm1']}
        self.assertTrue(repeats(det, 'p', reach, 'Ubuntu:22.04:LTS'))
        self.assertFalse(repeats(det, 'p', reach, ''))                            # 24.04 is not reached
        self.assertTrue(repeats(det, 'p', dict(reach, **{'Ubuntu:24.04:LTS': ['2.4-1ubuntu0.2']}), ''))
        self.assertFalse(repeats(det, 'p', {'Ubuntu:22.04:LTS': ['2.0-1ubuntu1.5']}, 'Ubuntu:22.04:LTS'))    # its Pro fix
        self.assertFalse(repeats(det, 'p', {'Ubuntu:22.04:LTS': ['2.0-1ubuntu1.2'],
                                            'Ubuntu:Pro:22.04:LTS': ['2.0-1ubuntu1.3+esm1']}, 'Ubuntu:22.04:LTS'))
        self.assertFalse(repeats(det, 'other', reach, 'Ubuntu:22.04:LTS'))        # names no fix for the package
        self.assertFalse(repeats(det, 'p', reach, 'Ubuntu:20.04:LTS'))            # nor for the release
        self.assertFalse(repeats({'eco_fix': {'Debian:12': {'p': ['not a version']}}}, 'p',
                                 {'Debian:12': ['also not one']}, 'Debian:12'))
        for unread in (None, {}, {'eco_fix': None}, {'eco_fix': 'x'}, 'x', 7):
            self.assertFalse(repeats(unread, 'p', reach, 'Ubuntu:22.04:LTS'), unread)
        for odd in ({'eco_fix': {'Debian:12': 'p'}}, {'eco_fix': {'Debian:12': {'p': 'v'}}},
                    {'eco_fix': {'Debian:12': {'p': [None, 7, '']}}}):
            self.assertFalse(repeats(odd, 'p', {'Debian:12': ['9']}, 'Debian:12'), odd)

    def test_a_package_without_cve_records_keeps_its_notices(self):
        hits = [({'name': 'p'}, 'DSA-1-1'), ({'name': 'p'}, 'USN-2-1')]
        self.assertEqual(cve_scanner._without_repeated_notices(hits, {}, 'Debian:12'), (hits, 0))
        self.assertEqual(cve_scanner._without_repeated_notices([], {}, ''), ([], 0))


class TestTheSameHostFromAnOlderAgent(_Scan):
    """No source packages in the list: asked by installed name, as before, and the host view says what that misses."""

    def test_only_the_package_named_like_its_source_answers(self):
        plain = [{k: v for k, v in p.items() if k in ('name', 'version', 'arch')} for p in BEHIND]
        plain = [p for p in plain if p['name'] in ('libc6', 'openssh-server', 'sudo')]
        result = self.scan(plain, 'Debian:12', has_meta=False)
        self.assertEqual(self.db.asked, [('Debian:12', 'libc6', '2.36-9+deb12u3'),
                                         ('Debian:12', 'openssh-server', '1:9.2p1-2+deb12u2'),
                                         ('Debian:12', 'sudo', '1.9.13p3-1+deb12u1')])
        self.assertEqual({f['package'] for f in result['findings']}, {'sudo'})
        self.assertEqual(cve_scanner.coverage('Debian:12', False, 'Debian:12'), 'needs_agent')
        self.assertEqual(cve_scanner.coverage('Debian:12', True, 'Debian:12'), '')
        self.assertIs(result['ruled'], True)                 # the rule holds for the release, whoever asked


class TestAPatchedDebianHost(_Scan):
    def test_nothing_an_update_clears_is_left_and_the_rest_is_counted(self):
        result = self.scan(PATCHED, 'Debian:12')
        self.assertEqual([f for f in result['findings'] if cve_fixes.is_fixable(f)], [])
        for f in result['findings']:
            self.assertIn(f['severity'], ('critical', 'high'), f)
            self.assertIn(f['fix_status'], ('newer_release', 'none'), f)
        counted = self.assertRollupAddsUp(result)
        self.assertEqual(len(result['findings']) + counted, 26 + 31 + 4 + 4)
        self.assertGreater(counted, len(result['findings']))
        self.assertNotIn('duplicates', result)


class TestAnUbuntuHost(_Scan):
    RECORDING = UBU
    JAMMY = [{'name': 'libc6', 'version': '2.35-0ubuntu3.6', 'arch': 'amd64', 'source': 'glibc'},
             {'name': 'openssh-server', 'version': '1:8.9p1-3ubuntu0.6', 'arch': 'amd64', 'source': 'openssh'},
             {'name': 'sudo', 'version': '1.9.9-1ubuntu2.4', 'arch': 'amd64'}]
    ASKED = [('Ubuntu', 'glibc', '2.35-0ubuntu3.6'), ('Ubuntu', 'openssh', '1:8.9p1-3ubuntu0.6'),
             ('Ubuntu', 'sudo', '1.9.9-1ubuntu2.4')]

    def test_the_release_comes_from_the_version_the_host_reported(self):
        name = cve_scanner.entry_release
        self.assertEqual(name({'ecosystem': 'Ubuntu', 'os_id': 'ubuntu', 'version_id': '22.04'}), 'Ubuntu:22.04:LTS')
        self.assertEqual(name({'ecosystem': 'Ubuntu', 'os_id': 'ubuntu', 'version_id': '24.10'}), 'Ubuntu:24.10')
        self.assertEqual(name({'ecosystem': 'Ubuntu', 'os_id': 'pop', 'version_id': '22.04'}), 'Ubuntu:22.04:LTS')
        self.assertEqual(name({'ecosystem': 'Ubuntu', 'os_id': 'Ubuntu', 'version_id': ' 20.04 '}), 'Ubuntu:20.04:LTS')
        for derivative in ({'os_id': 'linuxmint', 'version_id': '21.3'}, {'os_id': 'zorin', 'version_id': '17'},
                           {'os_id': 'ubuntu', 'version_id': ''}, {'os_id': 'ubuntu', 'version_id': 'rolling'},
                           {'os_id': 'ubuntu', 'version_id': '22.4'}, {'os_id': 'ubuntu', 'version_id': '9.10'},
                           {'os_id': 'linuxmint', 'version_id': '22.04'}, {'version_id': '22.04'}):
            self.assertEqual(name(dict(derivative, ecosystem='Ubuntu')), '', derivative)
        self.assertEqual(name({'ecosystem': 'Debian:12'}), 'Debian:12')
        self.assertEqual(name({'ecosystem': 'Alpine:v3.19'}), 'Alpine:v3.19')
        self.assertEqual(name({'ecosystem': 'AlmaLinux', 'version_id': '9.4'}), '')
        self.assertEqual(name(None), '')

    def test_a_jammy_host_is_asked_by_source_and_reads_its_own_release(self):
        result = self.scan(self.JAMMY, 'Ubuntu', release='Ubuntu:22.04:LTS')
        self.assertEqual(self.db.asked, self.ASKED)
        found = self.by_id(result)
        glibc_fix = found['UBUNTU-CVE-2024-2961']
        # the fix of 22.04. The record's last entry is 24.04's 2.39-0ubuntu8.1, which is what the folded
        # version said for every host.
        self.assertEqual((glibc_fix['fix_status'], glibc_fix['fixed_version']), ('fixed', '2.35-0ubuntu3.7'))
        self.assertEqual(glibc_fix['binaries'], ['libc6'])
        self.assertIn('CVE-2024-2961', glibc_fix['aliases'])
        self.assertEqual(glibc_fix['severity'], 'medium')                     # Ubuntu's own priority
        self.assertTrue(glibc_fix['summary'].startswith('A description'))     # the record has no summary
        self.assertIs(result['ruled'], True)

    def test_a_notice_is_not_a_second_finding(self):
        result = self.scan(self.JAMMY, 'Ubuntu', release='Ubuntu:22.04:LTS')
        self.assertEqual(result['duplicates'], 9 + 8 + 3)
        self.assertEqual([f['vuln_id'] for f in result['findings'] if not f['vuln_id'].startswith('UBUNTU-CVE-')], [])
        counted = self.assertRollupAddsUp(result)
        self.assertEqual(len(result['findings']) + counted, len(per_cve(UBU, self.ASKED)))

    def test_a_patched_jammy_host(self):
        patched = [{'name': 'libc6', 'version': '2.35-0ubuntu3.18', 'arch': 'amd64', 'source': 'glibc'},
                   {'name': 'openssh-server', 'version': '1:8.9p1-3ubuntu0.18', 'arch': 'amd64', 'source': 'openssh'},
                   {'name': 'sudo', 'version': '1.9.9-1ubuntu2.7', 'arch': 'amd64'}]
        result = self.scan(patched, 'Ubuntu', release='Ubuntu:22.04:LTS')
        self.assertEqual([f for f in result['findings'] if cve_fixes.is_fixable(f)], [])
        self.assertEqual(len(result['findings']) + self.assertRollupAddsUp(result), 3 + 2)

    def test_a_derivative_with_a_version_of_its_own_is_asked_by_name_and_keeps_everything(self):
        result = self.scan(self.JAMMY, 'Ubuntu', release='')
        self.assertEqual(self.db.asked, [('Ubuntu', 'libc6', '2.35-0ubuntu3.6'),
                                         ('Ubuntu', 'openssh-server', '1:8.9p1-3ubuntu0.6'),
                                         ('Ubuntu', 'sudo', '1.9.9-1ubuntu2.4')])
        self.assertNotIn('ruled', result)
        self.assertNotIn('rollup', result)
        self.assertEqual({f['package'] for f in result['findings']}, {'sudo'})
        self.assertEqual(cve_scanner.coverage('Ubuntu', True, ''), 'no_release')
        self.assertEqual(cve_scanner.coverage('Ubuntu', True, 'Ubuntu:22.04:LTS'), '')
        self.assertEqual(cve_scanner.coverage('Ubuntu', False, 'Ubuntu:22.04:LTS'), 'needs_agent')


class TestUbuntuPro(_Scan):
    RECORDING = UBU
    FOCAL = [{'name': 'libssl1.1', 'version': '1.1.1f-1ubuntu2.23', 'arch': 'amd64', 'source': 'openssl'}]
    BIONIC = [{'name': 'libssl1.1', 'version': '1.1.1-1ubuntu2.1~18.04.23', 'arch': 'amd64', 'source': 'openssl'}]

    def test_a_release_past_standard_support_says_which_fixes_need_pro(self):
        result = self.scan(self.FOCAL, 'Ubuntu', release='Ubuntu:20.04:LTS')
        everything = result['findings']
        by_status = {}
        for f in everything:
            by_status.setdefault(f['fix_status'], []).append(f)
        counted = result.get('rollup', {})
        cves = UBU.ids('Ubuntu', 'openssl', '1.1.1f-1ubuntu2.23', 'UBUNTU-CVE-')
        self.assertEqual(len(everything) + counted.get('total', 0), len(cves))
        # the two a standard update still clears
        self.assertEqual(sorted({f['fixed_version'] for f in by_status['fixed']}), ['1.1.1f-1ubuntu2.24'])
        self.assertEqual(sorted(f['vuln_id'] for f in by_status['fixed']), ['UBUNTU-CVE-2024-13176', 'UBUNTU-CVE-2024-9143'])
        # the rest that has a fix has it in Ubuntu Pro: stored when high, counted otherwise, never "fixable"
        pro = len(by_status.get('pro', [])) + counted.get('fix', {}).get('pro', 0)
        self.assertEqual(pro, len([i for i in cves if any(
            e[0] == 'Ubuntu:Pro:20.04:LTS' and e[3] != '-' for e in UBU.entries[i])]))
        self.assertGreater(pro, 20)
        for f in by_status.get('pro', []):
            self.assertEqual(f['fixed_version'], '')
            self.assertEqual(list(f['fixed_elsewhere']), ['Ubuntu:Pro:20.04:LTS'])
            self.assertIn('esm', f['fixed_elsewhere']['Ubuntu:Pro:20.04:LTS'])
            self.assertFalse(cve_fixes.is_fixable(f))

    def test_a_fips_build_is_never_the_hosts_fix(self):
        result = self.scan(self.FOCAL, 'Ubuntu', release='Ubuntu:20.04:LTS')
        text = json.dumps(result).lower()
        self.assertNotIn('fips', text)
        self.assertTrue(any('FIPS' in e[0] for entries in UBU.entries.values() for e in entries),
                        'the recording holds no FIPS entry: the test would hold nothing')

    def test_a_host_that_has_pro_can_install_those_fixes(self):
        with_pro = self.FOCAL + [{'name': 'bash', 'version': '5.0-6ubuntu1.2+esm1', 'arch': 'amd64'}]
        self.db.extra[('Ubuntu', 'bash', '5.0-6ubuntu1.2+esm1')] = []
        result = self.scan(with_pro, 'Ubuntu', release='Ubuntu:20.04:LTS')
        statuses = {f['fix_status'] for f in result['findings']}
        self.assertNotIn('pro', statuses)
        self.assertNotIn('pro', result.get('rollup', {}).get('fix', {}))
        fixed = [f for f in result['findings'] if f['fix_status'] == 'fixed']
        self.assertGreater(len(fixed), 20)
        self.assertTrue(any('esm' in f['fixed_version'] for f in fixed))

    def test_what_makes_a_host_one_with_pro(self):
        def statuses(extra_version):
            key = ('Ubuntu', 'tool', extra_version)
            self.db.extra[key] = []
            shutil.rmtree(self.dir)
            self.dir.mkdir()
            result = self.scan(self.FOCAL + [{'name': 'tool', 'version': extra_version, 'arch': 'amd64'}], 'Ubuntu',
                               release='Ubuntu:20.04:LTS')
            return {f['fix_status'] for f in result['findings']} | set(result.get('rollup', {}).get('fix', {}))
        self.assertNotIn('pro', statuses('1.0-1ubuntu0.1~esm1'))
        self.assertNotIn('pro', statuses('1.0-1ubuntu0.20.04.1+esm2'))
        for not_a_marker in ('1.0-1resmoke2', '2.0+esmeralda', '1.0~esm', 'esm1'):
            self.assertIn('pro', statuses(not_a_marker), not_a_marker)

    def test_bionic_has_only_pro_entries(self):
        result = self.scan(self.BIONIC, 'Ubuntu', release='Ubuntu:18.04:LTS')
        cves = UBU.ids('Ubuntu', 'openssl', '1.1.1-1ubuntu2.1~18.04.23', 'UBUNTU-CVE-')
        self.assertEqual(len(result['findings']) + self.assertRollupAddsUp(result), len(cves))
        self.assertEqual([f for f in result['findings'] if f['fix_status'] == 'fixed'], [])
        pro = len([f for f in result['findings'] if f['fix_status'] == 'pro']) + result['rollup']['fix'].get('pro', 0)
        self.assertGreater(pro, 25)

    def test_the_statuses_as_a_table(self):
        fixes = {'Ubuntu:20.04:LTS': {'a': ['1-1ubuntu1'], 'b': []},
                 'Ubuntu:Pro:20.04:LTS': {'b': ['1-1ubuntu1+esm1'], 'c': ['2+esm1'], 'd': []},
                 'Ubuntu:22.04:LTS': {'d': ['3'], 'e': ['4']},
                 'Ubuntu:Pro:FIPS-updates:20.04:LTS': {'f': ['9.fips']}}
        status = lambda p, **kw: cve_fixes.classify(fixes, 'Ubuntu:20.04:LTS', p, **kw)['status']    # noqa: E731
        self.assertEqual([status(p) for p in 'abcdef'], ['fixed', 'pro', 'pro', 'newer_release', 'unknown', 'unknown'])
        self.assertEqual([status(p, pro=True) for p in 'abc'], ['fixed', 'fixed', 'fixed'])
        self.assertEqual(cve_fixes.classify(fixes, 'Ubuntu:20.04:LTS', 'c', pro=True)['fixed'], ['2+esm1'])
        # at or past a Pro fix counts as patched for any host; an interim release has no Pro entries
        self.assertEqual(cve_fixes.patched_by(fixes, 'Ubuntu:20.04:LTS', 'b'), ['1-1ubuntu1+esm1'])
        self.assertEqual(cve_fixes.pro_name('Ubuntu:24.10'), '')
        self.assertEqual(cve_fixes.pro_name('Ubuntu:22.04:LTS'), 'Ubuntu:Pro:22.04:LTS')
        for name in ('Ubuntu:Pro:FIPS-updates:20.04:LTS', 'Ubuntu:Pro:FIPS:20.04:LTS', 'Ubuntu', 'Ubuntu:jammy',
                     'Ubuntu:Pro:22.04', 'Ubuntu:22.04:LTS:x'):
            self.assertIsNone(cve_fixes.release_of(name), name)
        self.assertEqual(cve_fixes.release_of('Ubuntu:Pro:22.04:LTS'), ('Ubuntu Pro', (22, 4)))


def finding(n, severity='medium', status='none', package='pkg', fixed='', **more):
    return dict({'vuln_id': f'CVE-2024-{n}', 'severity': severity, 'fix_status': status, 'package': package,
                 'version': '1.0-1', 'fixed_version': fixed, 'aliases': []}, **more)


class TestTheRule(unittest.TestCase):
    def test_what_is_kept(self):
        kept = cve_fixes.kept
        self.assertTrue(kept(finding(1, status='fixed', fixed='2')))
        self.assertTrue(kept(finding(1, severity='low', status='fixed', fixed='2')))
        self.assertTrue(kept(finding(1, severity='critical')))
        self.assertTrue(kept(finding(1, severity='high', status='newer_release')))
        self.assertTrue(kept(finding(1), {'CVE-2024-1'}))
        self.assertTrue(kept(finding(1, aliases=['CVE-2020-9']), {'CVE-2020-9'}))
        self.assertTrue(kept(finding(1, kev=True)))
        self.assertTrue(kept(finding(1, status='unknown', fixed='2')))              # a folded version counts as a fix
        for f in (finding(1), finding(1, severity='low', status='newer_release'), finding(1, severity='unknown'),
                  finding(1, status='pro'), finding(1, status='unknown'), finding(1, severity='medium', status='pro')):
            self.assertFalse(kept(f), f)
        for junk in (None, 7, 'x', [], {}):
            self.assertFalse(kept(junk), junk)

    def test_the_most_pressing_take_the_room(self):
        many = ([finding(1000 + i, 'high', 'none', 'linux') for i in range(80)]
                + [finding(2000 + i, 'medium', 'fixed', 'linux', fixed='9') for i in range(10)]
                + [finding(3000 + i, 'critical', 'none', 'linux') for i in range(5)]
                + [dict(finding(1, 'low', 'none', 'linux'), vuln_id='CVE-2019-1')])
        stored, counted = cve_fixes.split(many, {'CVE-2019-1'})
        self.assertEqual(len(stored), cve_fixes.KEEP_PER_PACKAGE)
        ids = {f['vuln_id'] for f in stored}
        # known to be exploited: first. It is low, has no fix and is the oldest id of all, so nothing else keeps it.
        self.assertIn('CVE-2019-1', ids)
        self.assertTrue(all(f'CVE-2024-{3000 + i}' in ids for i in range(5)))      # then critical
        self.assertTrue(all(f'CVE-2024-{2000 + i}' in ids for i in range(10)))     # then what an update clears
        high = sorted(f['vuln_id'] for f in stored if f['vuln_id'].startswith('CVE-2024-10'))
        self.assertEqual(len(high), 50 - 16)
        self.assertEqual(high[0], f'CVE-2024-{1080 - 34}')                         # and of the rest, the newest
        self.assertEqual(counted['total'], 96 - 50)
        self.assertEqual(counted['severity'], {'high': 46})
        self.assertEqual(counted['fix'], {'none': 46})

    def test_a_host_has_a_ceiling_too(self):
        many = [finding(i, 'high', 'none', f'p{i % 40:02d}') for i in range(1, 801)]
        stored, counted = cve_fixes.split(many)
        self.assertEqual(len(stored), cve_fixes.KEEP_PER_HOST)
        self.assertEqual(counted['total'], 500)
        self.assertEqual(len(counted['packages']), cve_fixes.ROLLUP_PACKAGES)
        self.assertEqual(counted['more']['packages'], 40 - cve_fixes.ROLLUP_PACKAGES)
        self.assertEqual(sum(p['count'] for p in counted['packages']) + counted['more']['count'], 500)
        counts = [p['count'] for p in counted['packages']]
        self.assertEqual(counts, sorted(counts, reverse=True))

    def test_the_packages_of_the_count_are_the_ones_that_hold_the_most(self):
        counted = cve_fixes.rollup([finding(i, package=p, version=v) for i, (p, v) in enumerate(
            [('b', '1')] * 3 + [('zlib', '9')] * 7 + [('a', '1')] * 3 + [('linux', '6.1')] * 40 + [('one', '2')])])
        self.assertEqual([(p['name'], p['version'], p['count']) for p in counted['packages']],
                         [('linux', '6.1', 40), ('zlib', '9', 7), ('a', '1', 3), ('b', '1', 3), ('one', '2', 1)])
        self.assertEqual(counted['more'], {'packages': 0, 'count': 0})
        many = cve_fixes.rollup([finding(i, package=f'p{i % 30:02d}') for i in range(90)]
                                + [finding(1000 + i, package='big') for i in range(9)])
        self.assertEqual(many['packages'][0], {'name': 'big', 'version': '1.0-1', 'count': 9})
        self.assertEqual((len(many['packages']), many['more']), (20, {'packages': 11, 'count': 33}))

    def test_nothing_is_dropped_and_the_order_is_kept(self):
        mixed = [finding(i, s, st, fixed='2' if st == 'fixed' else '')
                 for i, (s, st) in enumerate([('low', 'none'), ('high', 'none'), ('medium', 'fixed'),
                                              ('unknown', 'unknown'), ('critical', 'pro'), ('medium', 'pro')])]
        stored, counted = cve_fixes.split(mixed)
        self.assertEqual([f['vuln_id'] for f in stored], ['CVE-2024-1', 'CVE-2024-2', 'CVE-2024-4'])
        self.assertEqual(counted['total'], 3)
        self.assertEqual(counted['severity'], {'medium': 1, 'low': 1, 'unknown': 1})
        self.assertEqual(counted['fix'], {'none': 1, 'pro': 1, 'unchecked': 1})
        self.assertEqual(cve_fixes.split([], None), ([], {}))
        self.assertEqual(cve_fixes.split([finding(1, 'high')], None), ([finding(1, 'high')], {}))
        self.assertEqual(cve_fixes.split('nope'), ([], {}))
        self.assertEqual(cve_fixes.split([None, 3, finding(1, 'high')])[0], [finding(1, 'high')])

    def test_the_total_of_a_stored_result(self):
        total = cve_fixes.rollup_total
        self.assertEqual(total({'rollup': {'total': 7}}), 7)
        for odd in (None, {}, {'rollup': None}, {'rollup': []}, {'rollup': {'total': '7'}}, {'rollup': {'total': -1}},
                    {'rollup': {'total': True}}, {'rollup': {'total': 1.5}}, {'rollup': {}}):
            self.assertEqual(total(odd), 0, odd)

    def test_the_tiles_are_five(self):
        self.assertEqual(cve_fixes.FIX_KEYS, ('fixable', 'newer_release', 'none', 'pro', 'unchecked'))
        self.assertEqual(sorted(cve_fixes.summarize([], set())), sorted(cve_fixes.FIX_KEYS))
        self.assertEqual([cve_fixes.fix_key(f) for f in (finding(1, status='fixed', fixed='1'), finding(1, status='pro'),
                                                         finding(1, status='unknown'), {}, None)],
                         ['fixable', 'pro', 'unchecked', 'unchecked', 'unchecked'])
        self.assertFalse(cve_fixes.is_fixable(finding(1, status='pro', fixed='9')))


class TestReadingTheAdvisoryRecords(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix='rp-v801-deb-details-'))
        self.cache = self.dir / 'cve_details_cache.json'

    def test_the_same_instant_written_two_ways_is_not_a_change(self):
        same = cve_scanner._instant
        self.assertEqual(same('2026-11-10T08:00:00.123456Z'), same('2026-11-10T08:00:00.123456789Z'))
        self.assertEqual(same('2026-11-10T08:00:00Z'), same('2026-11-10T08:00:00.000000000Z'))
        self.assertNotEqual(same('2026-11-10T08:00:00.123456Z'), same('2026-11-10T08:00:00.123457Z'))
        for odd in ('', None, 'yesterday', 7, '2026-11-10'):
            self.assertEqual(same(odd), '', odd)

    def test_when_a_record_is_read_again(self):
        needs = cve_scanner._needs_fetch
        now = int(time.time())
        held = {'v': cve_scanner.DETAILS_FORMAT, 'severity_source': 'cvss_v3', 'eco_fix': {},
                'modified': '2026-11-10T08:00:00.123456789Z', 'cached_at': now - 90 * 86400}
        self.assertFalse(needs(held, '2026-11-10T08:00:00.123456Z', 7 * 86400, now))     # unchanged, however old
        self.assertTrue(needs(held, '2026-11-12T09:30:00.000001Z', 7 * 86400, now))      # changed
        self.assertTrue(needs(held, '', 7 * 86400, now))                                 # no stamp: the age decides
        self.assertFalse(needs(dict(held, cached_at=now), None, 7 * 86400, now))
        self.assertTrue(needs(dict(held, modified=''), '2026-11-10T08:00:00.123456Z', 7 * 86400, now))
        for old_format in (dict(held, v=1), {k: v for k, v in held.items() if k != 'v'},
                           {k: v for k, v in held.items() if k != 'eco_fix'},
                           {k: v for k, v in held.items() if k != 'severity_source'}):
            self.assertTrue(needs(dict(old_format, cached_at=now), '2026-11-10T08:00:00.123456Z', 7 * 86400, now))
        for nothing in (None, 'x', [], 7):
            self.assertTrue(needs(nothing, '', 0, now))
        self.assertTrue(needs(dict(held, cached_at='soon'), '', 7 * 86400, now))

    def test_the_names_of_an_advisory(self):
        names = cve_scanner._cve_names
        self.assertEqual(names({'upstream': ['CVE-2024-6387']}), ['CVE-2024-6387'])
        self.assertEqual(names({'aliases': ['GHSA-x'], 'upstream': ['CVE-1', 'DEBIAN-CVE-1', 'cve-2', 'CVE-1']}),
                         ['GHSA-x', 'CVE-1', 'cve-2'])
        self.assertEqual(names({'upstream': [f'CVE-2024-{i}' for i in range(90)]}),
                         [f'CVE-2024-{i}' for i in range(cve_scanner.MAX_ALIASES)])
        for odd in ({}, {'aliases': 'CVE-1'}, {'upstream': {'a': 1}}, {'aliases': [None, 7, '', 'x' * 99]}):
            self.assertEqual(names(odd), [], odd)

    def test_what_the_cache_keeps_of_a_record(self):
        entry = cve_scanner._detail_entry(DEB.record('DEBIAN-CVE-2024-6387'), 'Debian:12')
        self.assertEqual(entry['v'], cve_scanner.DETAILS_FORMAT)
        self.assertEqual(entry['aliases'], ['CVE-2024-6387'])
        self.assertEqual(entry['summary'], 'A description, as these records have no summary.')
        self.assertNotIn('details', entry)                    # read by nothing, and half the file
        self.assertEqual(entry['eco_fix']['Debian:12'], {'openssh': ['1:9.2p1-2+deb12u3']})
        self.assertEqual((entry['severity'], entry['severity_source']), ('high', 'cvss_v3'))
        long = cve_scanner._detail_entry({'id': 'X', 'details': 'word ' * 400}, 'Debian:12')
        self.assertEqual(len(long['summary']), cve_scanner.SUMMARY_LEN)
        self.assertEqual(cve_scanner._detail_entry({'id': 'X', 'summary': 'kept', 'details': 'not this'}, 'x')['summary'],
                         'kept')

    def test_a_package_debian_calls_unimportant_per_release(self):
        vid = next(v for v, entries in DEB.entries.items() if any(e[4] == 'unimportant' for e in entries))
        minors = cve_fixes.minor(DEB.record(vid))
        (package,) = {e[1] for e in DEB.entries[vid] if e[4] == 'unimportant'}
        self.assertTrue(cve_fixes.is_minor(minors, 'Debian:12', package))
        self.assertFalse(cve_fixes.is_minor(minors, 'Debian:12', 'something-else'))
        self.assertFalse(cve_fixes.is_minor(minors, 'Debian:99', package))
        for odd in (None, [], 'x', {'Debian:12': 'glibc'}):
            self.assertFalse(cve_fixes.is_minor(odd, 'Debian:12', 'glibc'), odd)
        self.assertEqual(cve_fixes.minor({'affected': [{'package': {'ecosystem': 'Rocky Linux:9', 'name': 'x'},
                                                        'ecosystem_specific': {'urgency': 'unimportant'}}]}), {})
        self.assertEqual(cve_fixes.minor(None), {})

    def test_several_are_read_at_once_and_never_more(self):
        active, most, lock = [0], [0], threading.Lock()

        def details(vid):
            with lock:
                active[0] += 1
                most[0] = max(most[0], active[0])
            time.sleep(0.01)
            with lock:
                active[0] -= 1
            return {'id': vid, 'summary': 's'}
        held = {}
        with mock.patch.object(cve_scanner, '_osv_vuln_details', details):
            unread = cve_scanner._fetch_details({f'X-{i}' for i in range(40)}, 'Debian:12', held, self.cache)
        self.assertEqual((unread, len(held)), (0, 40))
        self.assertEqual(most[0], cve_scanner.DETAIL_FETCHES_AT_ONCE)
        self.assertEqual(len(json.loads(self.cache.read_text())), 40)

    def test_a_dead_endpoint_ends_the_reading(self):
        calls = []

        def details(vid):
            calls.append(vid)
            return None
        held = {}
        with mock.patch.object(cve_scanner, '_osv_vuln_details', details):
            unread = cve_scanner._fetch_details({f'X-{i:04d}' for i in range(3000)}, 'Debian:12', held, self.cache)
        self.assertEqual(unread, 3000)
        self.assertEqual(held, {})
        self.assertLessEqual(len(calls), cve_scanner.DETAIL_FAILURES_IN_A_ROW + cve_scanner.DETAIL_FETCHES_AT_ONCE)
        self.assertFalse(self.cache.exists())                         # nothing was read: nothing to write

    def test_a_failure_here_and_there_does_not(self):
        def details(vid):
            return None if int(vid[2:]) % 7 == 0 else {'id': vid, 'summary': 's'}
        held = {}
        with mock.patch.object(cve_scanner, '_osv_vuln_details', details):
            unread = cve_scanner._fetch_details({f'X-{i}' for i in range(700)}, 'Debian:12', held, self.cache)
        self.assertEqual((unread, len(held)), (100, 600))

    def test_a_record_of_a_shape_that_cannot_be_read_is_one_unread_record(self):
        def details(vid):
            if vid == 'X-3':
                return {'id': vid, 'references': 7, 'affected': 'everything', 'severity': 'high'}
            return {'id': vid, 'summary': 's'}
        with self.assertRaises(TypeError):
            cve_scanner._detail_entry(details('X-3'), 'Debian:12')          # the shape does break the reader
        held = {}
        with mock.patch.object(cve_scanner, '_osv_vuln_details', details):
            unread = cve_scanner._fetch_details({f'X-{i}' for i in range(10)}, 'Debian:12', held, self.cache)
        self.assertEqual(unread, 1)
        self.assertEqual(sorted(held), sorted(f'X-{i}' for i in range(10) if i != 3))

    def test_the_cache_is_written_as_the_work_goes_and_the_caller_is_told_it_is_alive(self):
        saves, ticks = [], []
        real_save = cve_scanner._save_json

        def save(path, data):
            saves.append(len(data))
            real_save(path, data)
        with mock.patch.object(cve_scanner, '_osv_vuln_details', lambda vid: {'id': vid, 'summary': 's'}), \
                mock.patch.object(cve_scanner, '_save_json', save):
            cve_scanner._fetch_details({f'X-{i}' for i in range(700)}, 'Debian:12', {}, self.cache,
                                       tick=lambda: ticks.append(1))
        self.assertGreaterEqual(len(saves), 3)                        # every 250, and at the end
        self.assertEqual(saves[-1], 700)
        self.assertEqual(saves, sorted(saves))
        self.assertGreater(len(ticks), 80)                            # between rounds of eight

    def test_a_tick_that_fails_does_not_end_the_scan(self):
        def boom():
            raise RuntimeError('the marker could not be written')
        with mock.patch.object(cve_scanner, '_osv_vuln_details', lambda vid: {'id': vid, 'summary': 's'}):
            self.assertEqual(cve_scanner._fetch_details({'X-1'}, 'Debian:12', {}, self.cache, tick=boom), 0)

    def test_two_scanners_do_not_write_through_one_temporary_file(self):
        seen = []
        real_write = Path.write_text

        def write(path, text, *a, **k):
            seen.append(path.name)
            return real_write(path, text, *a, **k)
        with mock.patch.object(Path, 'write_text', write):
            cve_scanner._save_json(self.cache, {'a': 1})
        self.assertEqual(seen, [f'cve_details_cache.json.{os.getpid()}.tmp'])
        self.assertEqual(json.loads(self.cache.read_text()), {'a': 1})
        self.assertEqual([p.name for p in self.dir.iterdir()], ['cve_details_cache.json'])

    def test_a_scan_with_records_it_could_not_read_says_so(self):
        db = Database(DEB)

        def details(vid):
            return None if vid.endswith(('1', '3')) else db.details(vid)
        with mock.patch.object(cve_scanner, '_osv_querybatch', db.querybatch), \
                mock.patch.object(cve_scanner, '_osv_vuln_details', details), \
                mock.patch.object(cve_scanner, '_debian_severity_fallback', lambda cve: None):
            result = cve_scanner.scan_device(HOST, BEHIND, 'Debian:12', self.dir, has_meta=True)
        self.assertTrue(result['partial'])
        self.assertGreater(result['unread'], 5)
        self.assertIn(f"{result['unread']} of the advisory records could not be read", result['error'])
        # every DSA id ends in "-1", so none of the six notices was read: a notice that cannot be compared is
        # kept, among the unchecked, until a scan reads it
        self.assertEqual(len(result['findings']) + result['rollup']['total'], len(per_cve(DEB, BEHIND_ASKED)) + 6)
        self.assertNotIn('duplicates', result)
        self.assertGreaterEqual(result['rollup']['fix'].get('unchecked', 0), result['unread'])

    def test_a_second_scan_reads_nothing_again(self):
        db = Database(DEB)
        with mock.patch.object(cve_scanner, '_osv_querybatch', db.querybatch), \
                mock.patch.object(cve_scanner, '_osv_vuln_details', db.details):
            first = cve_scanner.scan_device(HOST, BEHIND, 'Debian:12', self.dir, has_meta=True, cache_ttl=0)
            read = len(db.read)
            second = cve_scanner.scan_device(HOST, BEHIND, 'Debian:12', self.dir, has_meta=True, cache_ttl=0)
        self.assertGreater(read, 80)
        self.assertEqual(len(db.read), read)          # a record that did not change is not read again, at any age
        self.assertEqual([f['vuln_id'] for f in first['findings']], [f['vuln_id'] for f in second['findings']])


class TestTheSeverityOfACachedRecord(_Scan):
    """An unchanged record is not read again, so what the cache keeps has to stay true: under another band
    setting, and for a host of another release than the one that read the record first."""

    def setUp(self):
        super().setUp()
        self.addCleanup(cve_scanner.set_cvss_bands)        # back to the defaults

    def test_the_cache_keeps_the_score_and_not_only_the_word(self):
        entry = cve_scanner._detail_entry(DEB.record('DEBIAN-CVE-2024-6387'), 'Debian:12')
        self.assertEqual((entry['severity'], entry['severity_source'], entry['score']), ('high', 'cvss_v3', 8.1))
        # Ubuntu's own priority decides before a score does, and then no score is kept
        ubuntu = cve_scanner._detail_entry(UBU.record('UBUNTU-CVE-2024-2961'), 'Ubuntu')
        self.assertEqual((ubuntu['severity'], ubuntu['severity_source']), ('medium', 'ubuntu_priority'))
        self.assertNotIn('score', ubuntu)
        self.assertNotIn('score', cve_scanner._detail_entry({'id': 'X'}, 'Debian:12'))

    def test_a_changed_band_shows_on_the_next_scan_and_no_record_is_read_again(self):
        before = self.scan(BEHIND, 'Debian:12')
        self.assertEqual(self.by_id(before)['DEBIAN-CVE-2024-6387']['severity'], 'high')      # scored 8.1
        read = len(self.db.read)
        cve_scanner.set_cvss_bands(critical=8.0, high=7.0, medium=4.0)
        raised = self.by_id(self.scan(BEHIND, 'Debian:12'))
        self.assertEqual(raised['DEBIAN-CVE-2024-6387']['severity'], 'critical')
        cve_scanner.set_cvss_bands(critical=9.0, high=8.5, medium=4.0)
        lowered = self.scan(BEHIND, 'Debian:12')
        self.assertEqual(self.by_id(lowered)['DEBIAN-CVE-2024-6387']['severity'], 'medium')
        self.assertEqual(len(self.db.read), read)                   # three scans, the records read once
        # and the rule follows the bands: what is no longer high and has no fix moves into the count
        self.assertGreater(lowered['rollup']['total'], before['rollup']['total'])
        self.assertLess(len(lowered['findings']), len(before['findings']))
        self.assertEqual(len(lowered['findings']) + lowered['rollup']['total'],
                         len(before['findings']) + before['rollup']['total'])

    def test_only_a_score_is_banded_again(self):
        now = cve_scanner._severity_now
        cve_scanner.set_cvss_bands(critical=5.0, high=3.0, medium=1.0)
        self.assertEqual(now({'severity': 'medium', 'severity_source': 'cvss_v3', 'score': 6.1}), ('critical', 'cvss_v3'))
        self.assertEqual(now({'severity': 'medium', 'severity_source': 'cvss_v4_approx', 'score': 3.3}),
                         ('high', 'cvss_v4_approx'))
        self.assertEqual(now({'severity': 'medium', 'severity_source': 'ubuntu_priority', 'score': 9.9}),
                         ('medium', 'ubuntu_priority'))
        self.assertEqual(now({'severity': 'low', 'severity_source': 'debian_urgency', 'score': 9.9}),
                         ('low', 'debian_urgency'))
        for odd in (None, '9.9', True, False, [9.9], {'a': 1}):
            # under these bands True (1) would be medium and False (0) low; the word that was kept stays
            self.assertEqual(now({'severity': 'high', 'severity_source': 'cvss_v3', 'score': odd}),
                             ('high', 'cvss_v3'), odd)
        self.assertEqual(now({}), ('unknown', 'unknown'))
        self.assertEqual(now({'severity': 'high', 'severity_source': 7, 'score': 1.0}), ('high', 7))

    @staticmethod
    def record(vid, *urgencies):
        return {'id': vid, 'affected': [
            {'package': {'ecosystem': release, 'name': 'pkg'}, 'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}]}],
             **({'ecosystem_specific': {'urgency': urgency}} if urgency else {})}
            for release, urgency in urgencies]}

    def test_a_record_without_a_score_reads_the_same_for_every_release(self):
        """The severity is kept in a cache that hosts of several releases share."""
        mixed = self.record('DEBIAN-CVE-2020-1', ('Debian:12', 'unimportant'), ('Debian:13', 'not yet assigned'))
        for asked_from in ('Debian:12', 'Debian:13', 'Debian:11'):
            self.assertEqual(cve_scanner._severity_from_vuln(mixed, asked_from), ('unknown', 'unknown'), asked_from)
        # the release that calls it unimportant still gets it as low, when the finding is made
        minors = cve_fixes.minor(mixed)
        self.assertTrue(cve_fixes.is_minor(minors, 'Debian:12', 'pkg'))
        self.assertFalse(cve_fixes.is_minor(minors, 'Debian:13', 'pkg'))

    def test_what_the_urgency_of_a_record_means(self):
        rate = cve_scanner._severity_from_vuln
        cases = (((('Debian:12', 'unimportant'), ('Debian:13', 'Unimportant ')), ('low', 'debian_urgency')),
                 ((('Debian:12', 'not yet assigned'),), ('unknown', 'unknown')),
                 ((('Debian:12', 'end-of-life'),), ('unknown', 'unknown')),
                 ((('Debian:12', 'low'), ('Debian:13', 'not yet assigned')), ('low', 'debian_urgency')),
                 ((('Debian:12', 'low**'), ('Debian:13', 'medium')), ('medium', 'debian_urgency')),
                 ((('Debian:12', 'high'),), ('medium', 'debian_urgency')))      # never above medium without a score
        for urgencies, want in cases:
            self.assertEqual(rate(self.record('DEBIAN-CVE-2020-1', *urgencies), 'Debian:12'), want, urgencies)
        # (the tracker raises in this class's setUp if it is asked: none of the above asked it)

    def test_the_tracker_is_asked_only_for_a_record_that_carries_no_urgency(self):
        asked = []

        def tracker(cve):
            asked.append(cve)
            return 'medium'
        bare = self.record('DEBIAN-CVE-2020-2', ('Debian:12', ''))
        with mock.patch.object(cve_scanner, '_debian_severity_fallback', tracker):
            self.assertEqual(cve_scanner._severity_from_vuln(bare, 'Debian:12'), ('medium', 'debian_urgency'))
            self.assertEqual(cve_scanner._severity_from_vuln(dict(bare, id='DSA-5000-1'), 'Debian:12'),
                             ('unknown', 'unknown'))                  # the tracker knows CVE ids
            self.assertEqual(cve_scanner._severity_from_vuln(bare, 'Ubuntu'), ('unknown', 'unknown'))
            with_urgency = self.record('DEBIAN-CVE-2020-3', ('Debian:13', 'not yet assigned'))
            self.assertEqual(cve_scanner._severity_from_vuln(with_urgency, 'Debian:12'), ('unknown', 'unknown'))
        self.assertEqual(asked, ['DEBIAN-CVE-2020-2'])

    def test_a_severity_list_of_another_shape_is_no_score(self):
        for odd in ('high', {'type': 'CVSS_V3'}, [None, 7, 'x', {'type': 'CVSS_V3', 'score': 8}, {'score': None}], 7):
            self.assertIsNone(cve_scanner._cvss_first({'severity': odd}), odd)
            self.assertEqual(cve_scanner._severity_from_vuln({'id': 'X', 'severity': odd}, 'Ubuntu'), ('unknown', 'unknown'))
        self.assertEqual(cve_scanner._cvss_first({'severity': [{'type': 'CVSS_V2', 'score': '7.5'}]}), (7.5, 'cvss_v2'))
        self.assertIsNone(cve_scanner._cvss_first(None))


class _Captured(Exception):
    def __init__(self, status, body):
        super().__init__(status)
        self.status, self.body = status, body


class TestTheAlertComparison(unittest.TestCase):
    """A host scanned before the rule holds findings the rule now counts. Read as they are, they look like
    findings that went away."""

    def setUp(self):
        self.fired = []
        self._saved = (api.fire_webhook, api.get_cve_severity_filter, api.is_webhook_event_enabled,
                       api.get_cve_alert_fixable_only)
        api.fire_webhook = lambda event, payload: self.fired.append((event, dict(payload)))
        api.get_cve_severity_filter = lambda: ('critical', 'high', 'medium')
        api.is_webhook_event_enabled = lambda event: True
        api.get_cve_alert_fixable_only = lambda: False
        api.save(api.CVE_IGNORE_FILE, {})
        api._LOAD_CACHE.clear()
        self.devices = {HOST: {'name': 'box'}}

    def tearDown(self):
        (api.fire_webhook, api.get_cve_severity_filter, api.is_webhook_event_enabled,
         api.get_cve_alert_fixable_only) = self._saved

    def events(self):
        return [e for e, _p in self.fired]

    def test_a_finding_that_moved_into_the_count_is_not_a_finding_that_was_cleared(self):
        before = [finding(1, 'medium', 'none')]
        api._detect_new_cve_and_fire_webhook(HOST, self.devices, before, [], ruled=True)
        self.assertEqual(self.events(), [])

    def test_read_as_it_is_it_was(self):
        """The control: without the rule on the previous result the host announces its vulnerabilities cleared."""
        before = [finding(1, 'medium', 'none')]
        api._detect_new_cve_and_fire_webhook(HOST, self.devices, before, [], ruled=False)
        self.assertEqual(self.events(), ['cve_cleared'])

    def test_a_finding_that_really_went_away_still_clears(self):
        before = [finding(1, 'high', 'fixed', fixed='2')]
        api._detect_new_cve_and_fire_webhook(HOST, self.devices, before, [], ruled=True)
        self.assertEqual(self.events(), ['cve_cleared'])

    def test_a_counted_finding_that_gets_a_fix_alerts_as_new(self):
        before = [finding(1, 'medium', 'none')]
        after = [finding(1, 'medium', 'fixed', fixed='2')]
        api._detect_new_cve_and_fire_webhook(HOST, self.devices, before, after, ruled=True)
        self.assertEqual(self.events(), ['cve_found'])
        self.assertEqual(self.fired[0][1]['count'], 1)

    def test_a_finding_that_was_stored_before_and_still_is_does_not_alert_again(self):
        same = [finding(1, 'high', 'none')]
        api._detect_new_cve_and_fire_webhook(HOST, self.devices, same, list(same), ruled=True)
        self.assertEqual(self.events(), [])

    def test_a_known_exploited_finding_counts_as_stored_before(self):
        same = [finding(1, 'medium', 'none')]
        api._detect_new_cve_and_fire_webhook(HOST, self.devices, same, list(same), ruled=True, kev={'CVE-2024-1'})
        self.assertEqual(self.events(), [])


class TestTheWorker(unittest.TestCase):
    """The product's own scan: the real worker and stores, the network replaced by the recording."""

    def setUp(self):
        self.events = []
        self._saved = (api.fire_webhook, api.audit_log)
        api.fire_webhook = lambda event, payload: self.events.append((event, dict(payload)))
        api.audit_log = lambda *a, **k: None
        self.cache = Path(tempfile.mkdtemp(prefix='rp-v801-deb-worker-'))
        patcher = mock.patch.object(api, 'DATA_DIR', self.cache)
        patcher.start()
        self.addCleanup(patcher.stop)
        api.save(api.CONFIG_FILE, {})
        api.save(api.DEVICES_FILE, {HOST: {'id': HOST, 'name': 'bookworm', 'token': 't', 'monitored': True}})
        api.save(api.PACKAGES_FILE, {HOST: {'ecosystem': 'Debian:12', 'os_id': 'debian', 'version_id': '12',
                                            'pkg_manager': 'apt', 'sources': True, 'count': len(BEHIND),
                                            'packages': BEHIND}})
        api.save(api.CVE_FINDINGS_FILE, {})
        api.save(api.CVE_IGNORE_FILE, {})
        api._LOAD_CACHE.clear()
        self.db = Database(DEB)

    def tearDown(self):
        api.fire_webhook, api.audit_log = self._saved
        for f in (api.DEVICES_FILE, api.PACKAGES_FILE, api.CVE_FINDINGS_FILE, api.KEV_EPSS_FILE):
            api.save(f, {})
        api._LOAD_CACHE.clear()

    def run_scan(self):
        with mock.patch.object(cve_scanner, '_osv_querybatch', self.db.querybatch), \
                mock.patch.object(cve_scanner, '_osv_vuln_details', self.db.details), \
                mock.patch.object(cve_scanner, '_debian_severity_fallback', lambda cve: None):
            api._cve_scan_worker('tester', HOST)
        api._LOAD_CACHE.clear()
        return (api.load(api.CVE_FINDINGS_FILE) or {}).get(HOST) or {}

    def test_the_host_is_asked_by_source_and_its_result_carries_the_count(self):
        stored = self.run_scan()
        self.assertEqual(self.db.asked, BEHIND_ASKED)
        self.assertIs(stored['ruled'], True)
        self.assertEqual(len(stored['findings']) + stored['rollup']['total'], len(per_cve(DEB, BEHIND_ASKED)))
        self.assertIn('DEBIAN-CVE-2024-6387', {f['vuln_id'] for f in stored['findings']})

    def test_the_known_exploited_list_reaches_the_rule_and_the_page(self):
        first = self.run_scan()
        counted_only = sorted(set(per_cve(DEB, BEHIND_ASKED)) - {f['vuln_id'] for f in first['findings']})
        victim = next(i for i in counted_only
                      if not any(e[0] == 'Debian:12' and e[4] == 'unimportant' for e in DEB.entries[i]))
        cve = victim.replace('DEBIAN-', '')
        api.save(api.KEV_EPSS_FILE, {'kev': [cve], 'epss': {cve: 0.93}})
        api._LOAD_CACHE.clear()
        again = self.run_scan()
        self.assertIn(victim, {f['vuln_id'] for f in again['findings']})
        # and the host view marks it: the list is matched through the CVE name the record keeps in `upstream`
        saved = (api.respond, api.require_auth)

        def respond(status, data):
            raise _Captured(status, data)
        api.respond, api.require_auth = respond, lambda *a, **k: 'admin'
        try:
            api.handle_cve_device(HOST)
        except _Captured as c:
            body = c.body
        finally:
            api.respond, api.require_auth = saved
        (shown,) = [f for f in body['findings'] if f['vuln_id'] == victim]
        self.assertIs(shown['kev'], True)
        self.assertEqual(shown['epss'], 0.93)
        self.assertEqual(body['rollup']['total'], again['rollup']['total'])
        self.assertEqual(body['coverage'], '')

    def test_the_worker_hands_the_scan_what_it_needs(self):
        block = srcpin.py_function((_CGI / 'api.py').read_text(), '_cve_scan_worker')
        for needle in ('release=cve_scanner.entry_release(entry)', 'kev=_kev_ids', 'tick=_still_alive',
                       "ruled=result.get('ruled') is True, kev=_kev_ids"):
            self.assertIn(needle, block)

    def test_the_marker_is_kept_alive_from_inside_a_host(self):
        writes = []
        real_save = api.save

        def save(path, data, *a, **k):
            if Path(str(path)).name == api.CVE_SCAN_STATUS_FILE.name:
                writes.append(dict(data))
            return real_save(path, data, *a, **k)
        clock = [1_800_000_000.0]

        def tick_clock():
            clock[0] += 20           # every look at the clock is twenty seconds later
            return clock[0]
        with mock.patch.object(api, 'save', save), mock.patch.object(api.time, 'time', tick_clock):
            self.run_scan()
        alive = [w for w in writes if w.get('running') and w.get('done') == 0]
        self.assertGreater(len(alive), 1, 'the marker was not written while the host was being scanned')


class TestWhatThePagesAreHanded(unittest.TestCase):
    def setUp(self):
        self._saved = (api.respond, api.require_auth)

        def respond(status, data):
            raise _Captured(status, data)
        api.respond, api.require_auth = respond, lambda *a, **k: 'admin'
        api.save(api.DEVICES_FILE, {HOST: {'id': HOST, 'name': 'box', 'token': 't', 'monitored': True}})
        api.save(api.PACKAGES_FILE, {HOST: {'ecosystem': 'Ubuntu', 'os_id': 'ubuntu', 'version_id': '22.04',
                                            'count': 2, 'sources': True, 'packages': []}})
        api.save(api.CVE_IGNORE_FILE, {})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        api.respond, api.require_auth = self._saved
        for f in (api.DEVICES_FILE, api.PACKAGES_FILE, api.CVE_FINDINGS_FILE):
            api.save(f, {})
        api._LOAD_CACHE.clear()

    def call(self, handler, *args):
        api._LOAD_CACHE.clear()
        with mock.patch.object(api, '_kev_epss', lambda: (set(), {})), mock.patch.object(api, 'method', lambda: 'GET'):
            try:
                handler(*args)
            except _Captured as c:
                self.assertEqual(c.status, 200, c.body)
                return c.body
        self.fail('the handler did not answer')

    def store(self, record):
        api.save(api.CVE_FINDINGS_FILE, {HOST: record})

    GOOD = {'total': 12, 'severity': {'medium': 9, 'low': 3}, 'fix': {'none': 10, 'pro': 2},
            'packages': [{'name': 'linux', 'version': '5.15.0-1', 'count': 10}, {'name': 'vim', 'version': '2:8', 'count': 1}],
            'more': {'packages': 1, 'count': 1}}

    def test_the_host_view_gets_the_count(self):
        self.store({'scanned_at': 5, 'findings': [], 'rollup': self.GOOD})
        body = self.call(api.handle_cve_device, HOST)
        self.assertEqual(body['rollup'], self.GOOD)
        self.assertEqual(body['coverage'], '')
        self.assertEqual(body['ecosystem'], 'Ubuntu')

    def test_a_count_of_another_shape_does_not_break_the_page(self):
        for odd in (None, 'x', [], 7, {}, {'total': 'many'}, {'total': 0}, {'total': -4}):
            self.store({'scanned_at': 5, 'findings': [], 'rollup': odd})
            self.assertIsNone(self.call(api.handle_cve_device, HOST)['rollup'], odd)
        self.store({'scanned_at': 5, 'findings': [], 'rollup': {
            'total': 5, 'severity': 'x', 'fix': {'none': '4', 'pro': 1, 'made_up': 3},
            'packages': [None, 'x', {'name': 7}, {'name': 'ok', 'count': 'three', 'version': None}] + [
                {'name': f'p{i}', 'count': 1} for i in range(60)],
            'more': []}})
        got = self.call(api.handle_cve_device, HOST)['rollup']
        self.assertEqual((got['total'], got['severity'], got['fix'], got['more']),
                         (5, {}, {'none': 4, 'pro': 1}, {'packages': 0, 'count': 0}))   # "4" is repaired, a made-up key dropped
        self.assertEqual(len(got['packages']), cve_fixes.ROLLUP_PACKAGES)
        # the store repairs a number to a name; what is left of a row is text and a number
        self.assertEqual(got['packages'][:2], [{'name': '7', 'version': '', 'count': 0},
                                               {'name': 'ok', 'version': '', 'count': 0}])
        for row in got['packages']:
            self.assertEqual((type(row['name']), type(row['version']), type(row['count'])), (str, str, int), row)

    def test_the_report_carries_a_number_per_host_and_one_for_the_fleet(self):
        self.store({'scanned_at': 5, 'findings': [finding(1, 'high', 'pro')], 'rollup': self.GOOD})
        report = self.call(api.handle_cve_findings)
        self.assertEqual(report['summary']['rollup'], 12)
        (row,) = [d for d in report['devices'] if d['device_id'] == HOST]
        self.assertEqual(row['rollup'], 12)
        self.assertEqual(sorted(report['summary']['fix']), sorted(cve_fixes.FIX_KEYS))
        self.assertEqual(report['summary']['fix']['pro'], 1)
        self.assertEqual(row['fix']['pro'], 1)
        # the count is beside the tiles, never inside them: a tile filters the hosts and the findings by it
        self.assertEqual(sum(row['fix'].values()), 1)

    def test_a_host_without_a_count_reads_as_zero(self):
        self.store({'scanned_at': 5, 'findings': []})
        self.assertIsNone(self.call(api.handle_cve_device, HOST)['rollup'])
        self.assertEqual(self.call(api.handle_cve_findings)['summary']['rollup'], 0)

    def test_the_words_for_what_a_scan_leaves_out(self):
        for os_id, version, sources, want in (('ubuntu', '22.04', True, ''), ('ubuntu', '22.04', False, 'needs_agent'),
                                              ('linuxmint', '21.3', True, 'no_release'),
                                              ('linuxmint', '21.3', False, 'no_release')):
            entry = {'ecosystem': 'Ubuntu', 'os_id': os_id, 'version_id': version, 'packages': []}
            if sources:
                entry['sources'] = True
            api.save(api.PACKAGES_FILE, {HOST: entry})
            self.store({'scanned_at': 5, 'findings': []})
            self.assertEqual(self.call(api.handle_cve_device, HOST)['coverage'], want, (os_id, sources))

    def test_the_stored_shape_is_registered(self):
        import store_shapes
        damaged = {HOST: {'findings': [], 'rollup': {'total': '12', 'severity': {'medium': 'x', 'low': 3},
                                                     'packages': [{'name': 'ok', 'count': 2}, {'count': 1}, 'x'],
                                                     'more': 'none'}}}
        fixed = store_shapes.normalize('cve_findings.json', json.loads(json.dumps(damaged)))
        counted = fixed[HOST]['rollup']
        self.assertEqual(counted['total'], 12)
        self.assertEqual(counted['severity'], {'low': 3})
        self.assertEqual(counted['packages'], [{'name': 'ok', 'count': 2}])
        self.assertNotIsInstance(counted.get('more'), str)


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestThePage(unittest.TestCase):
    def run_js(self, call, *functions):
        esc = re.search(r'^function escHtml\(.*$', _APP, re.M).group(0)
        esca = re.search(r'^function escAttr\(.*$', _APP, re.M).group(0)
        script = '\n'.join([esc, esca] + [srcpin.js_function(_PAGE, f) for f in functions]
                           + ['console.log(JSON.stringify({out: %s}));' % call])
        r = subprocess.run(['node', '-e', script], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)['out']

    def rollup(self, value):
        return self.run_js('_cveRollupHtml(%s)' % json.dumps(value), '_cveRollupHtml')

    GOOD = {'total': 1497, 'severity': {'high': 12, 'critical': 1, 'medium': 900}, 'fix': {'fixable': 40, 'none': 1400},
            'packages': [{'name': 'linux', 'version': '6.1.140-1', 'count': 1021}, {'name': 'shadow', 'version': '1:4.13', 'count': 3}],
            'more': {'packages': 7, 'count': 30}}

    def test_the_count_of_a_host(self):
        html = self.rollup(self.GOOD)
        self.assertIn('<strong>1497</strong>', html)
        self.assertIn('Known vulnerabilities counted per package and not listed one by one:', html)
        self.assertIn('<span>Of these, critical or high:</span> <span>13</span>', html)
        self.assertIn('<span>Of these, cleared by an update:</span> <span>40</span>', html)
        self.assertIn('<span>Packages not shown:</span> <span>7</span>', html)
        self.assertIn('<td class="mono-12">linux</td><td class="mono-12">6.1.140-1</td><td class="ta-center">1021</td>', html)

    def test_a_package_name_is_not_a_word_to_translate(self):
        # "shadow" and "at" are source packages, and words the dictionary holds
        self.assertIn('<tbody data-no-i18n="">', self.rollup(self.GOOD))
        self.assertIn('<strong data-no-i18n="">${escHtml(f.package)}</strong>', _PAGE)
        self.assertIn('data-no-i18n="">${escHtml(f.binaries.join', _PAGE)

    def test_lines_that_have_nothing_to_say_are_left_out(self):
        html = self.rollup({'total': 3, 'severity': {'low': 3}, 'fix': {'none': 3},
                            'packages': [{'name': 'a', 'version': '1', 'count': 3}], 'more': {'packages': 0, 'count': 0}})
        for absent in ('critical or high', 'cleared by an update', 'Packages not shown'):
            self.assertNotIn(absent, html)

    def test_no_count_prints_nothing(self):
        for none in (None, {}, {'total': 0}, {'total': -3}, {'total': 'x'}, [], 'x', 7, {'packages': [{'name': 'a'}]}):
            self.assertEqual(self.rollup(none), '', none)

    def test_hostile_values_come_out_as_text_or_as_nothing(self):
        html = self.rollup({'total': 2, 'severity': {'high': '<b>'}, 'fix': {'fixable': {'a': 1}},
                            'packages': [{'name': '<img src=x onerror=1>', 'version': '"><script>', 'count': '<i>'},
                                         None, 'row', 5, {'name': None}],
                            'more': {'packages': '<u>', 'count': 1}})
        for raw in ('<img', '<script', '<b>', '<i>', '<u>'):
            self.assertNotIn(raw, html)
        self.assertIn('&lt;img src=x onerror=1&gt;', html)
        self.assertEqual(self.rollup({'total': 2, 'packages': 'linux'}).count('<tr>'), 0)

    def test_the_fifth_tile(self):
        keys = self.run_js('[%s].map(_cveFixKey)' % ', '.join(json.dumps(f) for f in (
            {'fix_status': 'pro'}, {'fix_status': 'pro', 'fixed_version': '9'}, {'fix_status': 'fixed'},
            {'fix_status': 'unknown', 'fixed_version': '2'}, {})), '_cveFixKey')
        self.assertEqual(keys, ['pro', 'pro', 'fixable', 'fixable', 'unchecked'])
        names = re.search(r'^const _CVE_FIX_NAME = \{(.*)\};$', _PAGE, re.M).group(1)
        self.assertEqual(re.findall(r'(\w+): ', names), list(cve_fixes.FIX_KEYS))
        html = (ROOT / 'server' / 'html' / 'index.html').read_text()
        for key in cve_fixes.FIX_KEYS:
            self.assertIn(f'id="cve-fix-{key}"', html)

    def test_a_fix_in_ubuntu_pro_says_so(self):
        html = self.run_js('_cveFixHtml(%s)' % json.dumps(
            {'fix_status': 'pro', 'fixed_elsewhere': {'Ubuntu:Pro:20.04:LTS': '1.1.1f-1ubuntu2.24+esm1'}}), '_cveFixHtml')
        self.assertIn('Fixed with Ubuntu Pro', html)
        self.assertIn('Ubuntu:Pro:20.04:LTS 1.1.1f-1ubuntu2.24+esm1', html)
        self.assertNotIn('newer release', html)
        newer = self.run_js('_cveFixHtml(%s)' % json.dumps(
            {'fix_status': 'newer_release', 'fixed_elsewhere': {'Debian:13': '<b>'}}), '_cveFixHtml')
        self.assertIn('Fixed in a newer release', newer)
        self.assertIn('&lt;b&gt;', newer)

    def test_the_host_view_and_the_fleet_table_show_the_count(self):
        view = srcpin.js_function(_PAGE, 'openDeviceCVE')
        self.assertIn('const roll = _cveRollupHtml(data.rollup);', view)
        self.assertIn("if (!data.findings.length) { if (!roll) html += '<div class=\"empty-state\">No vulnerabilities found.</div>'; }",
                      view)
        loader = srcpin.js_function(_PAGE, 'loadCVEReport')
        self.assertIn("document.getElementById('cve-rollup-note')", loader)
        html = (ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertIn('id="cve-rollup-note" hidden', html)
        self.assertIn('data-col="counted"', html)
        table = srcpin.js_function(_APP, '_registerCveTable')
        self.assertIn("'low', 'counted', 'last_scan'", table)
        self.assertIn('colspan: 11', table)
        self.assertIn("cell(Number(d.rollup) || 0, 'var(--muted)')", table)
        self.assertEqual(html.count('colspan="10" class="empty-state">Click Refresh to load findings.'), 0)

    def test_the_new_texts_are_in_six_languages(self):
        from test_v710_i18n_glue import dict_rows
        rows = dict_rows()
        texts = ['Needs Ubuntu Pro', 'Fixed with Ubuntu Pro',
                 'Known vulnerabilities counted per package and not listed one by one:',
                 'Known vulnerabilities counted per package and not listed one by one',
                 'Packages not shown:', 'Of these, critical or high:', 'Of these, cleared by an update:', 'Counted', 'Count',
                 'Package', 'Installed']
        texts += re.findall(r"^  [a-z_]+: '([^']+)',$", re.search(r'^const _CVE_COVERAGE = \{.*?^\};', _PAGE,
                                                                    re.M | re.S).group(0), re.M)
        self.assertEqual(len(texts), 13)
        for text in texts:
            self.assertTrue(rows.get(text) and all(rows[text].get(lang) for lang in ('zh', 'hi', 'es', 'ar', 'de', 'fr')),
                            text)


class TestTheDemoSeed(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('seed_v801_deb', ROOT / 'packaging' / 'seed-demo-data.py')
        if spec is None or spec.loader is None:
            raise unittest.SkipTest('demo seeder not in this tree')
        cls.seed = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.seed)
        cls.findings = cls.seed.build_cve_findings()

    def test_it_stores_only_what_a_scan_would(self):
        stored = [f for record in self.findings.values() for f in record['findings']]
        self.assertGreater(len(stored), 15)
        for f in stored:
            self.assertTrue(cve_fixes.kept(f), f)
            self.assertNotIn('references', f)                 # a scan writes `refs`, which is what the page reads
            self.assertTrue(f['refs'])

    def test_every_host_has_a_count_that_adds_up_and_some_have_nothing_else(self):
        for dev_id, record in self.findings.items():
            counted = record['rollup']
            self.assertEqual(sum(counted['severity'].values()), counted['total'], dev_id)
            self.assertEqual(sum(counted['fix'].values()), counted['total'], dev_id)
            self.assertEqual(sum(p['count'] for p in counted['packages']) + counted['more']['count'], counted['total'])
            self.assertIs(record['ruled'], True)
        self.assertTrue([d for d, r in self.findings.items() if not r['findings']], 'no host with a count alone')
        self.assertTrue(next(iter(self.findings.values()))['findings'])

    def test_the_package_lists_are_what_an_agent_sends(self):
        packages = self.seed.build_packages()
        self.assertGreater(len(packages), 5)
        for entry in packages.values():
            self.assertEqual((entry['ecosystem'], entry['sources']), ('Ubuntu', True))
            self.assertEqual(cve_scanner.entry_release(entry), 'Ubuntu:22.04:LTS')
            self.assertEqual(cve_scanner.coverage(entry['ecosystem'], True, cve_scanner.entry_release(entry)), '')
            self.assertIn({'name': 'libc6', 'source': 'glibc'},
                          [{k: p[k] for k in ('name', 'source')} for p in entry['packages'] if 'source' in p])


if __name__ == '__main__':
    unittest.main()

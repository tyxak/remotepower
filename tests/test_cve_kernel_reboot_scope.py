"""Only a finding of the running kernel may read "reboot to apply" (8.0.2).

A finding is `reboot` when the kernel it is about runs and a kernel installed beside it already holds the fix. The test that
decides it, "an installed kernel is at or past the fix", compares versions: and the version of a kernel (6.1.192-1) is past
the fixed version of almost any other package in the order dpkg gives (1.9.13p3-1+deb12u4 of sudo). What keeps a sudo finding
from reading "reboot to apply" is the running-kernel check in front of it, and no fixture had a package that is not a
kernel: removing the check left every guard of the branch green. This host has a newer kernel installed beside the one it
runs and sudo findings that nothing installed fixes.
"""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'server' / 'cgi-bin'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
_TMP = []


def _tmp(prefix):
    d = tempfile.mkdtemp(prefix=prefix)
    _TMP.append(d)
    return d


import cve_fixes  # noqa: E402
import cve_scanner  # noqa: E402
from osv_recording import DEB, Database  # noqa: E402


def tearDownModule():
    for d in _TMP:
        shutil.rmtree(d, ignore_errors=True)


# ── only the running kernel's findings may read "reboot" ──────────────────────────────────────────────────────────────
class TestOnlyTheRunningKernelsFindingsReadReboot(unittest.TestCase):
    """The advisories of sudo are the recording's: real ones, for the version this host has."""
    OLD_RELEASE, NEW_RELEASE = '6.1.0-40-amd64', '6.1.0-48-amd64'
    PACKAGES = [{'name': f'linux-image-{OLD_RELEASE}', 'version': '6.1.158-1', 'arch': 'amd64', 'source': 'linux'},
                {'name': f'linux-image-{NEW_RELEASE}', 'version': '6.1.192-1', 'arch': 'amd64', 'source': 'linux'},
                {'name': 'sudo', 'version': '1.9.13p3-1+deb12u1', 'arch': 'amd64'}]
    KERNEL = {'release': OLD_RELEASE, 'images': [
        {'name': f'linux-image-{OLD_RELEASE}', 'version': '6.1.158-1', 'release': OLD_RELEASE},
        {'name': f'linux-image-{NEW_RELEASE}', 'version': '6.1.192-1', 'release': NEW_RELEASE}]}
    K = 'DEBIAN-CVE-2099-1001'
    RECORD = {'id': K, 'details': 'a flaw in the kernel', 'upstream': ['CVE-2099-1001'],
              'modified': '2026-11-10T08:00:00.123456789Z', 'database_specific': {'severity': 'high'},
              'affected': [{'package': {'ecosystem': 'Debian:12', 'name': 'linux'},
                            'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': '6.1.170-1'}]}],
                            'ecosystem_specific': {'urgency': 'high'}}]}

    def scan(self, kernel):
        db = Database(DEB, extra={('Debian:12', 'linux', '6.1.158-1'): [self.K], ('Debian:12', 'linux', '6.1.192-1'): []},
                      records={self.K: self.RECORD})
        with mock.patch.object(cve_scanner, '_osv_querybatch', db.querybatch), \
                mock.patch.object(cve_scanner, '_osv_vuln_details', db.details), \
                mock.patch.object(cve_scanner, '_debian_severity_fallback', lambda cve: None):
            result = cve_scanner.scan_device('h', self.PACKAGES, 'Debian:12', Path(_tmp('rp-rpmk-deb-')), has_meta=True,
                                             kernel=kernel)
        self.assertNotIn('error', result)
        return result

    def test_a_finding_of_another_package_is_never_a_reboot(self):
        result = self.scan(self.KERNEL)
        by_package = {}
        for finding in result['findings']:
            by_package.setdefault(finding['package'], []).append(finding)
        # the population is not empty on either side: the kernel's finding is a reboot, and sudo has findings the
        # recording holds that nothing installed fixes
        self.assertEqual([(f['vuln_id'], f['fix_status']) for f in by_package['linux']], [(self.K, 'reboot')])
        self.assertGreaterEqual(len(by_package['sudo']), 3)
        for finding in by_package['sudo']:
            self.assertNotEqual(finding['fix_status'], cve_fixes.REBOOT, finding['vuln_id'])
            self.assertNotIn('reboot_to', finding, finding['vuln_id'])
        self.assertTrue(any(f['fix_status'] == 'fixed' for f in by_package['sudo']))

    def test_the_same_host_without_the_report_has_no_reboot_at_all(self):
        result = self.scan(None)
        self.assertFalse([f for f in result['findings'] if f['fix_status'] == cve_fixes.REBOOT])


if __name__ == '__main__':
    unittest.main()

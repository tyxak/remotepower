"""An RPM kernel is several packages, and what a scan says of it does not depend on the order of the list (8.0.2).

The first version of the running-kernel rule worked on the one package the agent names for each kernel, the owner of
/boot/vmlinuz-<release>. On a Debian host that package's unit is the source package and its version, which holds every
package built from it. On an RPM host the plan asks about each package by its own name, and the owner is kernel-core: kernel,
kernel-modules and kernel-modules-core of the kernels that do not run were still asked about and counted, and the status of
a finding depended on which of them the list named first (rpm prints its database in hash order). The review of that
version found it with 12 of 24 orders of four rows reading `reboot` and the other 12 reading "an update to install".

  * a kernel's units are those of every package built from the same source package at the same version as its image, so the
    kernels that do not run are left out with all of them and the running kernel's are all the running kernel's;
  * the finding of one advisory against one package is the same in every order of the list: a unit of the running kernel
    that an installed kernel clears decides, whichever unit the list named first;

The rows come from the agent's own parser of `rpm -qa`, not from a shape written for the test.
"""
import itertools
import random
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


import cve_scanner  # noqa: E402
from osv_recording import DEB, Database  # noqa: E402
from test_docker_agent import load_agent  # noqa: E402

AGENT = load_agent()


def tearDownModule():
    for d in _TMP:
        shutil.rmtree(d, ignore_errors=True)


# ── an RPM host as the agent lists it ─────────────────────────────────────────────────────────────────────────────────
OLD, NEW = '5.14.0-362.8.1.el9_3', '5.14.0-427.13.1.el9_4'
ROLD, RNEW = OLD + '.x86_64', NEW + '.x86_64'
NAMES = ('kernel', 'kernel-core', 'kernel-modules', 'kernel-modules-core')


def rows(*items):
    """The packages of `rpm -qa --queryformat`, through the agent's own parser. An item is (name, version) of a package built
    from the kernel's source package, or (name, version, source rpm, epoch) for any other."""
    lines = []
    for name, version, *more in items:
        srpm, epoch = (more + [None, None])[:2] if more else (None, None)
        lines.append(f'{name}\t{version}\tx86_64\t{epoch or "(none)"}\t{srpm or "kernel-" + version + ".src.rpm"}')
    packages, has_sources = AGENT._parse_rpm_query('\n'.join(lines))
    assert has_sources
    return packages


BASH = ('bash', '5.1.8-9.el9', 'bash-5.1.8-9.el9.src.rpm')
EVERY_PACKAGE = rows(*[(n, v) for n in NAMES for v in (OLD, NEW)], BASH)
KERNEL_IMAGES = [{'name': 'kernel-core', 'version': OLD, 'release': ROLD},
                 {'name': 'kernel-core', 'version': NEW, 'release': RNEW}]


def report(running):
    return {'release': running, 'images': list(KERNEL_IMAGES)}


VID = 'ALSA-2099:1'


def advisory(vid, names, fixed, ecosystem):
    """A record as the data source serves an AlmaLinux or Rocky Linux advisory: one entry for each binary package, with the
    fixed version as RPM writes it (epoch, version and release)."""
    return {'id': vid, 'details': 'a flaw in the kernel', 'modified': '2026-11-10T08:00:00.123456789Z',
            'severity': [{'type': 'CVSS_V3', 'score': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}],
            'affected': [{'package': {'ecosystem': ecosystem, 'name': n},
                          'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': fixed}]}]}
                         for n in names]}


def database(ecosystem, vulnerable, names=NAMES, more=None):
    """The packages named in `vulnerable` answer with the advisory at the old version and none at the new one; the rest
    answer with nothing. `more` adds answers ({(name, version): [ids]}) for a package the fixtures above do not hold."""
    answers = {(ecosystem, n, v): [] for n in NAMES for v in (OLD, NEW)}
    answers[(ecosystem, 'bash', '5.1.8-9.el9')] = []
    for n in vulnerable:
        answers[(ecosystem, n, OLD)] = [VID]
    for (name, version), ids in (more or {}).items():
        answers[(ecosystem, name, version)] = ids
    return Database(DEB, extra=answers, records={VID: advisory(VID, names, '0:' + NEW, ecosystem)})


def scan(packages, kernel, db, ecosystem='AlmaLinux:9'):
    with mock.patch.object(cve_scanner, '_osv_querybatch', db.querybatch), \
            mock.patch.object(cve_scanner, '_osv_vuln_details', db.details), \
            mock.patch.object(cve_scanner, '_debian_severity_fallback', lambda cve: None):
        result = cve_scanner.scan_device('h', packages, ecosystem, Path(_tmp('rp-rpmk-scan-')), has_meta=True, kernel=kernel)
    assert 'error' not in result, result.get('error')
    return result


def asked_names(db, package_filter=None):
    return sorted((k[1], k[2]) for k in db.asked if package_filter is None or k[1] in package_filter)


def the_finding(result):
    (finding,) = result['findings']
    return finding


ECOSYSTEMS = ('AlmaLinux:9', 'Rocky Linux:9')
REBOOT = ('reboot', 'kernel-core ' + NEW, '0:' + NEW)


class TestTheKernelsThatDoNotRunAreLeftOutWithAllTheirPackages(unittest.TestCase):
    def test_a_host_that_runs_the_older_kernel_asks_about_the_older_packages_only(self):
        for ecosystem in ECOSYSTEMS:
            db = database(ecosystem, NAMES)
            result = scan(EVERY_PACKAGE, report(ROLD), db, ecosystem)
            self.assertEqual(sorted({v for _, v in asked_names(db)}), sorted([OLD, '5.1.8-9.el9']), ecosystem)
            self.assertEqual([n for n, v in asked_names(db) if v == OLD and n.startswith('kernel')], list(NAMES), ecosystem)
            self.assertEqual(result['kernel']['state'], 'matched', ecosystem)
            self.assertEqual(result['kernel']['package'], 'kernel-core')
            self.assertEqual(result['kernel']['left_out'], 4, ecosystem)            # the four packages of the newer kernel
            self.assertEqual(result['kernel']['newer'], 'kernel-core ' + NEW)

    def test_the_account_of_what_was_checked_leaves_them_out_too(self):
        for ecosystem in ECOSYSTEMS:
            result = scan(EVERY_PACKAGE, report(ROLD), database(ecosystem, NAMES), ecosystem)
            covered = result['covered']
            self.assertEqual((covered['listed'], covered['checked'], covered['not_checked']), (5, 5, 0), ecosystem)

    def test_a_host_that_runs_the_newer_kernel_asks_about_the_newer_packages_only(self):
        for ecosystem in ECOSYSTEMS:
            db = database(ecosystem, NAMES)
            result = scan(EVERY_PACKAGE, report(RNEW), db, ecosystem)
            self.assertEqual(sorted({v for _, v in asked_names(db)}), sorted([NEW, '5.1.8-9.el9']), ecosystem)
            self.assertEqual(result['kernel']['left_out'], 4, ecosystem)
            self.assertEqual(result['findings'], [], ecosystem)                     # the fix is what runs
            self.assertNotIn('newer', result['kernel'])

    def test_the_fleet_prefetch_asks_what_a_scan_asks(self):
        entry = {'ecosystem': 'AlmaLinux:9', 'sources': True, 'pkg_manager': 'dnf', 'os_id': 'almalinux', 'version_id': '9.4',
                 'packages': EVERY_PACKAGE, 'kernel': report(ROLD)}
        db = database('AlmaLinux:9', NAMES)
        with mock.patch.object(cve_scanner, '_osv_querybatch', db.querybatch):
            held = cve_scanner.prefetch_osv({'h': entry}, Path(_tmp('rp-rpmk-pf-')))
        self.assertEqual(sorted(k[1:] for k in held if k[1].startswith('kernel')), [(n, OLD) for n in NAMES])

    def test_a_package_built_from_the_same_source_at_the_same_version_as_another_image_is_not_another_kernel(self):
        """kernel-debug-core owns the file of the debug kernel, which is built with kernel-core from one source package: when
        the host runs the plain kernel the debug one is not a newer kernel and its packages are not left out."""
        packages = rows(*[(n, OLD) for n in NAMES], ('kernel-debug-core', OLD), ('kernel-core', NEW), BASH)
        images = [KERNEL_IMAGES[0], {'name': 'kernel-debug-core', 'version': OLD, 'release': ROLD + '+debug'}, KERNEL_IMAGES[1]]
        db = database('AlmaLinux:9', NAMES, more={('kernel-debug-core', OLD): []})
        result = scan(packages, {'release': ROLD, 'images': images}, db)
        self.assertIn(('kernel-debug-core', OLD), asked_names(db))
        self.assertEqual(result['kernel']['left_out'], 1)                           # kernel-core of the newer kernel
        self.assertEqual(result['kernel']['newer'], 'kernel-core ' + NEW)


class TestTheFindingDoesNotDependOnTheOrderOfTheList(unittest.TestCase):
    FOUR = [('kernel-core', OLD), ('kernel-core', NEW), ('kernel-modules', OLD), ('kernel-modules', NEW)]

    def finding_of(self, items, ecosystem, vulnerable=('kernel', 'kernel-core', 'kernel-modules'), names=NAMES):
        db = database(ecosystem, vulnerable, names)
        # the questions of the packages that are not listed are never asked, so they are not in the recording either
        result = scan(rows(*items), report(ROLD), db, ecosystem)
        finding = the_finding(result)
        return finding['fix_status'], finding.get('reboot_to'), finding['fixed_version']

    def test_every_order_of_four_rows_says_reboot(self):
        """The review's case: kernel-core and kernel-modules, each in two versions, the advisory names both."""
        for ecosystem in ECOSYSTEMS:
            seen = {}
            for order in itertools.permutations(self.FOUR):
                got = self.finding_of(list(order), ecosystem, names=('kernel-core', 'kernel-modules'))
                seen.setdefault(got, []).append(order)
            self.assertEqual(list(seen), [REBOOT], f'{ecosystem}: {[(k, len(v)) for k, v in seen.items()]}')
            self.assertEqual(sum(len(v) for v in seen.values()), 24)

    def test_shuffles_of_every_package_say_the_same(self):
        rng = random.Random(802)
        items = [(n, v) for n in NAMES for v in (OLD, NEW)]
        for ecosystem in ECOSYSTEMS:
            for _ in range(30):
                rng.shuffle(items)
                self.assertEqual(self.finding_of(list(items), ecosystem), REBOOT, (ecosystem, items))

    def test_an_advisory_that_names_only_the_meta_package_is_a_reboot_too(self):
        """The record lists `kernel` alone. The kernel block already said a newer kernel is there, and the finding said an
        update installs it."""
        for ecosystem in ECOSYSTEMS:
            got = self.finding_of([(n, v) for n in NAMES for v in (OLD, NEW)], ecosystem, vulnerable=('kernel',),
                                  names=('kernel',))
            self.assertEqual(got, ('reboot', 'kernel-core ' + NEW, '0:' + NEW), ecosystem)

    def test_a_unit_that_is_nobodys_kernel_cannot_decide_the_status_by_coming_first(self):
        """kernel-devel of a third version is built from the same source and is no kernel's package, so it is asked about and
        hits the advisory for itself. Named first or last it must not take the finding's status from the running kernel."""
        stray = ('kernel-devel', '5.14.0-300.1.1.el9_2')
        packages = [(n, v) for n in NAMES for v in (OLD, NEW)]
        for ecosystem in ECOSYSTEMS:
            for position in (0, len(packages)):
                items = list(packages)
                items.insert(position, stray)
                db = database(ecosystem, NAMES, names=NAMES + ('kernel-devel',), more={stray: [VID], ('kernel', stray[1]): []})
                result = scan(rows(*items), report(ROLD), db, ecosystem)
                finding = the_finding(result)
                self.assertEqual((finding['fix_status'], finding.get('reboot_to')), ('reboot', 'kernel-core ' + NEW),
                                 (ecosystem, position))
                self.assertIn('kernel-devel', finding['binaries'])

    def test_without_a_kernel_the_packages_built_from_one_source_are_still_one_finding_in_any_order(self):
        """openssl and openssl-libs are built from one source package: one finding that names both, whichever is listed first."""
        ssl = 'openssl-3.0.7-28.el9_4.src.rpm'
        packages = rows(('openssl', '3.0.7-28.el9_4', ssl, '1'), ('openssl-libs', '3.0.7-28.el9_4', ssl, '1'))
        for order in (packages, packages[::-1]):
            db = Database(DEB, extra={('AlmaLinux:9', 'openssl', '1:3.0.7-28.el9_4'): [VID],
                                      ('AlmaLinux:9', 'openssl-libs', '1:3.0.7-28.el9_4'): [VID]},
                          records={VID: advisory(VID, ('openssl', 'openssl-libs'), '1:3.0.7-29.el9_4', 'AlmaLinux:9')})
            result = scan(order, None, db)
            finding = the_finding(result)
            self.assertEqual((finding['package'], finding['binaries']), ('openssl', ['openssl', 'openssl-libs']))
            self.assertNotIn('kernel', result)
            self.assertNotEqual(finding['fix_status'], 'reboot')


if __name__ == '__main__':
    unittest.main()

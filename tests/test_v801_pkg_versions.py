"""The version order of RPM and Alpine packages (8.0.1).

The CVE scanner asks whether an installed package is already at or past the version that fixed a finding. For RPM
and Alpine it used a comparison that split a version on punctuation and took the leading digits of each piece:

  * the epoch of "1:3.0.7-28.el9_4" became the first number, so an installed 3.0.7-16.el9 was "newer" than the
    fix and a host that needed the update showed nothing for the package;
  * "-r5" and the letter of "1.1.1w" were read as nothing, so a fix that only raised one of them counted as
    installed.

`pkg_versions` orders both formats by their published rules. The first class holds it to an outside answer: 116
versions were sent to the advisory database on 2026-11-15, each against an advisory with a known fix, and the
file records whether the advisory came back. The rest states the rules one at a time.
"""
import functools
import itertools
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'server' / 'cgi-bin'))
import cve_scanner  # noqa: E402
import pkg_versions as pv  # noqa: E402

RECORDED = ROOT / 'tests' / 'data' / 'osv_version_order_2026-11-15.tsv'

# Where this module and the advisory database order a version differently, and why that is left alone. None of
# these shapes is what a host reports or an advisory names as a fix; they are here so the list cannot grow
# unnoticed, and a row that starts to agree has to be taken out.
DIFFERS = {
    ('apk', '3.1.4', '3.1.4-r0'): 'no revision: the database reads it as -r0, apk as older than -r0',
    ('apk', '3.00.0-r0', '3.1.4-r0'): 'the lower bound 3.0.0: the database reads 3.00.0 as newer, apk as older',
    ('apk', '3.0-r0', '3.1.4-r0'): 'the lower bound 3.0.0: the database reads 3.0 as 3.0.0, apk as older',
    ('apk', '3.0.00-r0', '3.1.4-r0'): 'the lower bound 3.0.0: the database reads 3.0.00 as 3.0.0, apk as older',
}


def _rows():
    rows = []
    for line in RECORDED.read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        fmt, version, introduced, fixed, affected = line.split('\t')
        rows.append((fmt, version, introduced, fixed, affected == '1'))
    return rows


def _affected(fmt, version, introduced, fixed):
    """Would this module file `version` inside [introduced, fixed)?"""
    if fmt == 'rpm':
        return pv.rpm_compare(version, fixed) < 0
    return pv.apk_compare(version, introduced) >= 0 and pv.apk_compare(version, fixed) < 0


class TestAgainstTheAdvisoryDatabase(unittest.TestCase):
    def test_the_recording_is_there(self):
        rows = _rows()
        self.assertEqual(len(rows), 116)
        self.assertEqual(sum(1 for r in rows if r[0] == 'rpm'), 50)
        self.assertEqual(sum(1 for r in rows if r[0] == 'apk'), 66)
        # both answers occur, or "it agrees" could mean "it always says no"
        for fmt in ('rpm', 'apk'):
            answers = {r[4] for r in rows if r[0] == fmt}
            self.assertEqual(answers, {True, False}, fmt)

    def test_every_recorded_answer_is_reproduced(self):
        wrong = []
        for fmt, version, introduced, fixed, affected in _rows():
            if (fmt, version, fixed) in DIFFERS:
                continue
            if _affected(fmt, version, introduced, fixed) != affected:
                wrong.append((fmt, version, fixed, affected))
        self.assertEqual(wrong, [])

    def test_the_listed_differences_are_real_and_complete(self):
        rows = {(fmt, version, fixed): (introduced, affected) for fmt, version, introduced, fixed, affected in _rows()}
        for key, why in DIFFERS.items():
            self.assertIn(key, rows, why)
            introduced, affected = rows[key]
            self.assertNotEqual(_affected(key[0], key[1], introduced, key[2]), affected,
                                f'{key} agrees now: take it out of DIFFERS')

    def test_the_old_comparison_fails_the_same_recording(self):
        """The control: the comparison this replaces, asked the question the scanner asked of it (is the
        version at or past the fix?), gets recorded answers wrong. A test that the old code passed would hold
        nothing."""
        wrong = [(fmt, version) for fmt, version, _i, fixed, affected in _rows()
                 if (not cve_scanner._tuple_ge(version, fixed)) != affected and (fmt, version, fixed) not in DIFFERS
                 and (fmt == 'rpm' or pv.apk_compare(version, _i) >= 0)]
        self.assertGreater(len(wrong), 20, wrong)


class TestRpmOrder(unittest.TestCase):
    def older(self, a, b):
        self.assertEqual(pv.rpm_compare(a, b), -1, (a, b))
        self.assertEqual(pv.rpm_compare(b, a), 1, (b, a))

    def same(self, a, b):
        self.assertEqual(pv.rpm_compare(a, b), 0, (a, b))
        self.assertEqual(pv.rpm_compare(b, a), 0, (b, a))

    def test_the_epoch_decides_before_anything_else(self):
        self.older('9:9.9-9', '10:0.1-1')
        self.older('3.0.7-28.el9_4', '1:1.0-1')         # no epoch is epoch 0
        self.same('0:1.0-1', '1.0-1')
        self.same('01:1.0-1', '1:1.0-1')

    def test_the_case_that_hid_findings(self):
        # installed without its epoch, the fix with it: older by RPM's reading, and the same package once the
        # caller says the list was collected without epochs
        self.assertFalse(pv.rpm_ge('3.0.7-16.el9', '1:3.0.7-28.el9_4'))
        self.assertFalse(pv.rpm_ge('3.0.7-16.el9', '1:3.0.7-28.el9_4', assume_same_epoch=True))
        self.assertTrue(pv.rpm_ge('3.5.9-1.el9_9', '1:3.0.7-28.el9_4', assume_same_epoch=True))
        self.assertFalse(pv.rpm_ge('3.5.9-1.el9_9', '1:3.0.7-28.el9_4'))
        # and the other way round: an epoch above the version's first number
        self.assertTrue(pv.rpm_ge('9.16.23-34.el9', '32:9.16.23-11.el9', assume_same_epoch=True))
        self.assertFalse(pv.rpm_ge('9.16.23-5.el9', '32:9.16.23-11.el9', assume_same_epoch=True))

    def test_assuming_the_epoch_changes_nothing_when_both_sides_have_one(self):
        self.assertFalse(pv.rpm_ge('1:9.9-9', '2:1.0-1', assume_same_epoch=True))
        self.assertTrue(pv.rpm_ge('2:1.0-1', '1:9.9-9', assume_same_epoch=True))

    def test_numbers_are_numbers(self):
        self.older('1.9-1', '1.10-1')
        self.same('1.010-1', '1.10-1')
        self.older('1.0-9.el9', '1.0-10.el9')
        self.older('1.0-1.el9_4', '1.0-1.el9_10')
        self.older('99999999999999999999-1', '100000000000000000000-1')    # longer than any machine integer

    def test_a_number_is_newer_than_letters_and_more_is_newer_than_less(self):
        self.older('1.a-1', '1.0-1')
        self.older('1.0-1', '1.0.1-1')
        self.older('1.0-1', '1.0a-1')
        self.older('1.0-1.el9', '1.0-1.el9_4')
        self.older('1.0-1.el9', '1.0-1.fc9')

    def test_punctuation_only_separates(self):
        self.same('1.0.7-28.el9_4', '1_0_7-28.el9.4')
        self.same('1.0-1.', '1.0-1')
        self.same('1.0+-1', '1.0-1')

    def test_a_tilde_sorts_before_everything(self):
        self.older('1.0~rc1-1', '1.0-1')
        self.older('1.0~rc1-1', '1.0~rc2-1')
        self.older('1.0~~-1', '1.0~-1')
        self.older('1.0-1~1', '1.0-1')

    def test_a_caret_sorts_after_the_end_and_before_anything_else(self):
        self.older('1.0-1', '1.0^git1-1')
        self.older('1.0^git1-1', '1.0.1-1')
        self.older('1.0^git1-1', '1.0^git2-1')
        self.older('1.0^1~2-1', '1.0^1-1')

    def test_a_missing_release_is_older_than_any_release(self):
        self.older('1.0', '1.0-1')
        self.same('1.0', '1.0')

    def test_what_cannot_be_read_raises(self):
        for bad in ('', '   ', None, 7, 'a:1.0-1', ':1.0-1', '1.0-', '-1', 'x' * 300, '1234567890:1.0-1'):
            with self.assertRaises(ValueError, msg=repr(bad)):
                pv.rpm_compare(bad, '1.0-1')

    def test_the_order_is_one_order(self):
        pool = ['1.0-1', '1.0-1.el9', '1.0-1.el9_4', '1:0.1-1', '1.0~rc1-1', '1.0^1-1', '1.0a-1', '1.a-1',
                '1.0.1-1', '0.9-99', '1.0', '2:0-0', '1.10-1', '1.9-1', '1.0-1~1', '1.0-10', '1.0-9']
        for a, b in itertools.product(pool, repeat=2):
            self.assertEqual(pv.rpm_compare(a, b), -pv.rpm_compare(b, a), (a, b))
        ordered = sorted(pool, key=functools.cmp_to_key(pv.rpm_compare))
        for i, a in enumerate(ordered):
            for b in ordered[i:]:
                self.assertLessEqual(pv.rpm_compare(a, b), 0, (a, b))


class TestAlpineOrder(unittest.TestCase):
    def older(self, a, b):
        self.assertEqual(pv.apk_compare(a, b), -1, (a, b))
        self.assertEqual(pv.apk_compare(b, a), 1, (b, a))

    def test_the_revision_counts(self):
        self.older('3.1.4-r5', '3.1.4-r6')
        self.older('3.1.4-r9', '3.1.4-r10')
        self.assertFalse(pv.apk_ge('3.1.4-r5', '3.1.4-r6'))
        self.assertTrue(pv.apk_ge('3.1.4-r6', '3.1.4-r6'))

    def test_the_letter_counts(self):
        self.older('1.1.1w-r0', '1.1.1x-r0')
        self.older('1.1.1-r9', '1.1.1a-r0')
        self.older('1.1.1z-r0', '1.1.2-r0')
        self.assertFalse(pv.apk_ge('1.1.1w-r0', '1.1.1x-r0'))

    def test_the_suffixes_in_their_order(self):
        chain = ['1.0_alpha-r0', '1.0_alpha1-r0', '1.0_beta-r0', '1.0_pre-r0', '1.0_rc1-r0', '1.0_rc2-r0', '1.0-r0',
                 '1.0_cvs-r0', '1.0_svn-r0', '1.0_git-r0', '1.0_git20240101-r0', '1.0_hg-r0', '1.0_p-r0', '1.0_p1-r0',
                 '1.0_p2-r0', '1.0a-r0', '1.0.0-r0', '1.1-r0']
        for a, b in zip(chain, chain[1:]):
            self.older(a, b)

    def test_numbers_are_numbers_and_a_leading_zero_is_a_fraction(self):
        self.older('1.9-r0', '1.10-r0')
        self.older('2.03.23-r0', '2.03.24-r0')
        self.older('1.05-r0', '1.1-r0')
        self.older('1.05-r0', '1.050-r0')
        self.older('2023.09-r0', '2023.10-r0')
        self.older('99999999999999999999-r0', '100000000000000000000-r0')

    def test_what_cannot_be_read_raises(self):
        for bad in ('', None, 3, 'abc', '1.0-r', '1.0_foo-r0', '1.0A-r0', '1.0ab-r0', '1..0-r0', '1.0-1', 'x' * 300,
                    '1:1.0-r0', '1.0 -r0'):
            with self.assertRaises(ValueError, msg=repr(bad)):
                pv.apk_compare(bad, '1.0-r0')

    def test_the_order_is_one_order(self):
        pool = ['1.0-r0', '1.0-r1', '1.0', '1.0_rc1-r0', '1.0_p1-r0', '1.0a-r0', '1.0.1-r0', '1.01-r0', '1.1-r0',
                '0.9z-r9', '1.0_alpha_p1-r0', '1.0_p1_rc1-r0', '1.0~ab12-r0', '1.10-r0']
        for a, b in itertools.product(pool, repeat=2):
            self.assertEqual(pv.apk_compare(a, b), -pv.apk_compare(b, a), (a, b))
        ordered = sorted(pool, key=functools.cmp_to_key(pv.apk_compare))
        for i, a in enumerate(ordered):
            for b in ordered[i:]:
                self.assertLessEqual(pv.apk_compare(a, b), 0, (a, b))


class TestTheScannerUsesThem(unittest.TestCase):
    """`_already_patched` is the one place that asks, and a version it cannot read keeps the finding."""

    def test_rpm(self):
        patched = cve_scanner._already_patched
        self.assertFalse(patched('3.0.7-16.el9', '1:3.0.7-28.el9_4', 'AlmaLinux:9', epoch_known=False))
        self.assertTrue(patched('3.5.9-1.el9_9', '1:3.0.7-28.el9_4', 'AlmaLinux:9', epoch_known=False))
        self.assertFalse(patched('1:3.0.7-16.el9', '1:3.0.7-28.el9_4', 'Rocky Linux:9'))
        self.assertTrue(patched('1:3.0.7-28.el9_4', '1:3.0.7-28.el9_4', 'Red Hat'))
        self.assertTrue(patched('9.16.23-34.el9', '32:9.16.23-11.el9', 'AlmaLinux', epoch_known=False))
        # the epoch is taken as given unless the caller says the list has none
        self.assertFalse(patched('3.5.9-1.el9_9', '1:3.0.7-28.el9_4', 'AlmaLinux:9'))

    def test_alpine(self):
        patched = cve_scanner._already_patched
        self.assertFalse(patched('3.1.4-r5', '3.1.4-r6', 'Alpine:v3.18'))
        self.assertFalse(patched('1.1.1w-r0', '1.1.1x-r0', 'Alpine:v3.16'))
        self.assertTrue(patched('3.1.4-r6', '3.1.4-r6', 'Alpine:v3.18'))
        self.assertTrue(patched('3.1.5-r0', '3.1.4-r6, 3.2.0-r0', 'Alpine:v3.18'))    # any one of the fixes

    def test_an_unreadable_version_keeps_the_finding(self):
        patched = cve_scanner._already_patched
        self.assertFalse(patched('not a version', '1:3.0.7-28.el9_4', 'AlmaLinux:9'))
        self.assertFalse(patched('3.1.4-r6', 'what', 'Alpine:v3.18'))
        self.assertFalse(patched('', '1.0-1', 'Rocky Linux:9'))

    def test_the_family_of_a_scan_name(self):
        self.assertEqual([cve_scanner.family(e) for e in (
            'Debian:12', 'Ubuntu', 'Ubuntu:22.04:LTS', 'Rocky Linux', 'Rocky Linux:9', 'AlmaLinux:10', 'Red Hat',
            'Alpine:v3.19', 'npm', '', None, 7)],
            ['deb', 'deb', 'deb', 'rpm', 'rpm', 'rpm', 'rpm', 'apk', '', '', '', ''])


if __name__ == '__main__':
    unittest.main()

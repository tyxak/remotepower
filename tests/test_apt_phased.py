#!/usr/bin/env python3
"""Discussion #30, the open question of the 7.4.8 reply: an update Ubuntu has not phased in to a host is not pending.

7.4.8 counts every package under "The following packages have been kept back:" except the ones held with `apt-mark
hold`. It had never run against a real apt. Run against two (Ubuntu 22.04's apt 2.4.13 and 24.04's 2.8.3, the output in
tests/data/apt_real), it did two things right and one wrong:

  right: the package that needs a new package is kept back and counted, with its security flag from the security
         pocket; the held package stays out;
  right on 24.04: apt 2.8 gives an update it defers for phasing a heading of its own, so it was never counted;
  wrong on 22.04: apt 2.4 lists the deferred update under "kept back", so it was counted as pending. It arrives on its
         own when Ubuntu reaches the host, and neither upgrade mode installs it before then.

The agent now asks apt the same question with phasing ignored. A name that stops being kept back was only deferred.
The fixtures are what apt printed, not text written to match the code.
"""
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from test_apt_kept_back import agent, patch_info  # noqa: E402

DATA = HERE / "data" / "apt_real"
RELEASES = ("ubuntu-22.04", "ubuntu-24.04")


def fixture(release, name):
    return (DATA / release / f"{name}.txt").read_text()


class _RealApt:
    """apt as the lab answered it: the plain simulation, the one that ignores phasing, the one with new packages
    allowed, and apt-mark. `state` is `deferred` or `included`."""

    def __init__(self, release, state, fail=(), override=None):
        self.release, self.state, self.fail, self.override = release, state, set(fail), override or {}
        self.calls = []

    def read(self, name):
        return self.override.get(name) if name in self.override else fixture(self.release, name)

    def __call__(self, cmd, **kw):
        self.calls.append(list(cmd))
        if cmd[0] == "apt-mark":
            return self.read("showhold")
        if "--with-new-pkgs" in cmd:
            return self.read(f"{self.state}_with_new_pkgs")
        if any("Always-Include-Phased-Updates=true" in a for a in cmd):
            if "ignoring" in self.fail:
                raise subprocess.CalledProcessError(100, cmd)
            return self.read(f"{self.state}_ignoring_phasing")
        return self.read(f"{self.state}_plain")


class TestWhatTheRealOutputLooksLike(unittest.TestCase):
    """The facts the rest rests on, read out of the fixtures."""

    def test_the_fixtures_are_there_and_are_apt_of_the_versions_named(self):
        self.assertIn("2.4", fixture("ubuntu-22.04", "apt_version"))
        self.assertIn("2.8", fixture("ubuntu-24.04", "apt_version"))
        for release in RELEASES:
            for name in ("deferred_plain", "deferred_ignoring_phasing", "deferred_with_new_pkgs", "included_plain", "showhold"):
                self.assertGreater(len(fixture(release, name)), 0, (release, name))

    def test_apt_2_4_lists_the_phased_update_under_kept_back(self):
        self.assertEqual(agent._apt_kept_back(fixture("ubuntu-22.04", "deferred_plain")),
                         ["lab-held", "lab-kernel-meta", "lab-phased"])

    def test_apt_2_8_gives_it_a_heading_of_its_own(self):
        out = fixture("ubuntu-24.04", "deferred_plain")
        self.assertIn("The following upgrades have been deferred due to phasing:\n  lab-phased", out)
        self.assertEqual(agent._apt_kept_back(out), ["lab-held", "lab-kernel-meta"])

    def test_with_phasing_ignored_both_take_it_and_it_leaves_the_kept_back_block(self):
        for release in RELEASES:
            self.assertEqual(agent._apt_kept_back(fixture(release, "deferred_ignoring_phasing")),
                             ["lab-held", "lab-kernel-meta"], release)


class TestTheCountOnARealApt(unittest.TestCase):

    def test_a_deferred_update_is_not_pending_on_either_release(self):
        for release in RELEASES:
            with self.subTest(release=release):
                got = patch_info(_RealApt(release, "deferred"))
                self.assertEqual((got["upgradable"], got["upgradable_names"]), (2, ["lab-kernel-meta", "lab-plain"]))

    def test_the_package_that_needs_a_new_package_still_counts_and_is_a_security_update(self):
        for release in RELEASES:
            with self.subTest(release=release):
                self.assertEqual(patch_info(_RealApt(release, "deferred"))["security_updates"], 1)

    def test_the_held_package_stays_out(self):
        for release in RELEASES:
            with self.subTest(release=release):
                self.assertNotIn("lab-held", patch_info(_RealApt(release, "deferred"))["upgradable_names"])

    def test_the_same_update_not_deferred_is_pending(self):
        """The control: once the host is in the phase the update is an ordinary one and counts."""
        for release in RELEASES:
            with self.subTest(release=release):
                got = patch_info(_RealApt(release, "included"))
                self.assertEqual((got["upgradable"], got["upgradable_names"]),
                                 (3, ["lab-kernel-meta", "lab-phased", "lab-plain"]))

    def test_apt_is_asked_the_phasing_question_once_and_only_when_something_is_kept_back(self):
        apt = _RealApt("ubuntu-22.04", "deferred")
        patch_info(apt)
        asked = [c for c in apt.calls if any("Always-Include-Phased-Updates=true" in a for a in c)]
        self.assertEqual(len(asked), 1, apt.calls)
        self.assertIn("--simulate", asked[0])
        clean = _RealApt("ubuntu-22.04", "deferred", override={"deferred_plain": "Inst curl [1] (2 Debian:12/stable [amd64])\n"})
        patch_info(clean)
        self.assertEqual(len(clean.calls), 1, clean.calls)

    def test_nothing_is_installed(self):
        apt = _RealApt("ubuntu-22.04", "deferred")
        patch_info(apt)
        for cmd in apt.calls:
            if cmd[0] == "apt-get":
                self.assertIn("--simulate", cmd, cmd)


class TestWhenTheQuestionCannotBeAnswered(unittest.TestCase):
    """An update that is hidden is the worse mistake, so the answer is to count what apt keeps back, as 7.4.8 did."""

    def test_a_failed_question_counts_the_phased_package_again(self):
        got = patch_info(_RealApt("ubuntu-22.04", "deferred", fail=("ignoring",)))
        self.assertEqual(got["upgradable_names"], ["lab-kernel-meta", "lab-phased", "lab-plain"])

    def test_an_answer_that_is_not_apt_is_not_believed(self):
        for junk in ("", "E: Could not open lock file\n", "nothing is kept back here\n"):
            with self.subTest(junk=junk):
                apt = _RealApt("ubuntu-22.04", "deferred", override={"deferred_ignoring_phasing": junk})
                self.assertEqual(patch_info(apt)["upgradable_names"], ["lab-kernel-meta", "lab-phased", "lab-plain"])


class TestWhenEverythingKeptBackIsDeferred(unittest.TestCase):
    """Derived from the real 22.04 output by leaving the other names out: the shape apt prints, an empty block omitted."""

    def setUp(self):
        plain = fixture("ubuntu-22.04", "deferred_plain").replace("  lab-held lab-kernel-meta lab-phased", "  lab-phased")
        ignoring = fixture("ubuntu-22.04", "deferred_ignoring_phasing")
        ignoring = ignoring.replace("The following packages have been kept back:\n  lab-held lab-kernel-meta\n", "")
        self.assertNotIn("kept back", ignoring)          # the derivation did what it says
        self.apt = _RealApt("ubuntu-22.04", "deferred", override={"deferred_plain": plain, "deferred_ignoring_phasing": ignoring,
                                                                  "showhold": ""})

    def test_the_host_reads_fully_patched_apart_from_the_plain_update(self):
        got = patch_info(self.apt)
        self.assertEqual((got["upgradable"], got["upgradable_names"], got["security_updates"]), (1, ["lab-plain"], 0))

    def test_apt_is_not_asked_for_the_security_flag_of_nothing(self):
        patch_info(self.apt)
        self.assertFalse([c for c in self.apt.calls if "--with-new-pkgs" in c], self.apt.calls)


class TestTheAgentCopiesAreTheSame(unittest.TestCase):

    def test_extensionless_matches_py(self):
        root = HERE.parent / "client"
        self.assertEqual((root / "remotepower-agent").read_bytes(), (root / "remotepower-agent.py").read_bytes())


if __name__ == "__main__":
    unittest.main()

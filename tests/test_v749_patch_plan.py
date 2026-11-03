#!/usr/bin/env python3
"""7.4.9: a patch preview shows what the next upgrade would change before anybody approves or runs it.

The patch button and the four-eyes gate showed a count ("14 pending") and nothing about what the run does. POST
/api/devices/<id>/patch-preview queues one fixed, read-only script on a Linux host; it asks the package manager for a dry run
and prints marked sections; `patch_plan.parse` reads them into versions, new packages, removals, what is kept back or deferred,
a kernel flag and a reboot estimate.

What is real and what is not:
  * apt is real. tests/data/patch_plan/*.txt are the script's own output from real apt 2.4.13 (Ubuntu 22.04), 2.8.3 (Ubuntu
    24.04) and 3.0.3 (Debian 13) run without root against two small local repositories, in four states each (Standard and
    Extended, with an update deferred for phasing and without). The script itself is run here under sh against fake
    package-manager commands that print the earlier real apt captures in tests/data/apt_real, and the two agree.
  * dnf and pacman are NOT real here: no dnf host was available. Their samples are written from the documented output of dnf 4,
    dnf 5 and pacman, so they prove the reader against those formats and nothing about a live dnf. The reader marks a plan whose
    rows do not match the counts the package manager printed (`partial`) instead of passing a short list off as the whole.
"""
import json
import os
import random
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v749-pp-"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_tenant_instance_gate import _Base, api  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))
import patch_plan as P  # noqa: E402

FIX = ROOT / "tests" / "data" / "patch_plan"
APT_REAL = ROOT / "tests" / "data" / "apt_real"
RELEASES = ("ubuntu-22.04", "ubuntu-24.04", "debian-13")
PID = "pp-0123456789ab"


def real(rel, state):
    return P.parse((FIX / f"{rel}-{state}.txt").read_text())


def names(rows):
    return [r["name"] if isinstance(r, dict) else r for r in rows]


# ── apt, as real apt printed it ───────────────────────────────────────────────────────────────────────────────────────
class TestRealApt(unittest.TestCase):

    def test_there_is_something_to_look_at(self):
        files = sorted(FIX.glob("*.txt"))
        self.assertEqual(len(files), 12, "three apt versions x four states")
        for f in files:
            self.assertGreater(len(f.read_text()), 300, f.name)

    def test_standard_without_phasing(self):
        for rel in RELEASES:
            p = real(rel, "standard")
            self.assertEqual(p["status"], "done", rel)
            self.assertEqual(p["manager"], "apt")
            self.assertEqual(p["mode"], "standard")
            self.assertEqual(sorted(names(p["upgrades"])), ["lab-phased", "lab-plain"], rel)
            self.assertEqual(p["installs"], [], rel)
            # lab-held is held on purpose; lab-kernel-meta is kept back because its new version needs a package that is
            # not installed yet. The two are told apart, since only the second is solved by Extended.
            kept = {k["name"]: k["held"] for k in p["kept_back"]}
            self.assertEqual(kept, {"lab-held": True, "lab-kernel-meta": False}, rel)
            self.assertEqual(p["deferred"], [], rel)
            self.assertEqual(p["counts"]["upgrade"], 2)
            self.assertFalse(p["truncated"], rel)

    def test_versions_and_the_source_are_read(self):
        for rel in RELEASES:
            plain = {u["name"]: u for u in real(rel, "standard")["upgrades"]}["lab-plain"]
            self.assertEqual((plain["from"], plain["to"]), ("1.0", "1.1"), rel)
            self.assertFalse(plain["security"])
            self.assertEqual(plain["source"], "Lab:noble-updates")

    def test_a_phased_update_is_deferred_on_every_apt_version(self):
        # apt 2.4 (Ubuntu 22.04) lists the deferred package under "kept back"; apt 2.8 and 3.0 give it a heading of its own.
        # The script asks again with phasing ignored, so all three end in the same place.
        for rel in RELEASES:
            p = real(rel, "standard-deferred")
            self.assertEqual(names(p["upgrades"]), ["lab-plain"], rel)
            self.assertEqual(p["deferred"], ["lab-phased"], rel)
            self.assertEqual(sorted(names(p["kept_back"])), ["lab-held", "lab-kernel-meta"], rel)

    def test_the_22_04_quirk_needs_the_second_question(self):
        raw = (FIX / "ubuntu-22.04-standard-deferred.txt").read_text()
        self.assertIn("lab-phased", raw.split("##unphased")[0], "apt 2.4 kept it back in the first answer")
        without = P.parse(raw.split("##unphased")[0] + "##end\n")
        self.assertIn("lab-phased", names(without["kept_back"]), "negative control: without the second answer it is kept back")
        self.assertEqual(without["deferred"], [])

    def test_extended_installs_what_standard_keeps_back(self):
        for rel in RELEASES:
            p = real(rel, "extended")
            self.assertEqual(p["mode"], "extended")
            self.assertEqual(sorted(names(p["upgrades"])), ["lab-kernel-meta", "lab-phased", "lab-plain"], rel)
            self.assertEqual(names(p["installs"]), ["lab-kernel-image-2"], rel)
            self.assertEqual(names(p["kept_back"]), ["lab-held"], rel)
            self.assertTrue(p["kept_back"][0]["held"])
            self.assertEqual(p["autoremove"], ["lab-kernel-image-1"], "the old image becomes unneeded after the upgrade")
            self.assertEqual(p["removals"], [], "upgrade never removes")
            self.assertEqual(p["counts"]["security"], 2, "the kernel meta package and its new image come from the security pocket")
            sec = {u["name"]: u["security"] for u in p["upgrades"] + p["installs"]}
            self.assertTrue(sec["lab-kernel-meta"] and sec["lab-kernel-image-2"] and not sec["lab-plain"])

    def test_extended_with_phasing(self):
        for rel in RELEASES:
            p = real(rel, "extended-deferred")
            self.assertEqual(sorted(names(p["upgrades"])), ["lab-kernel-meta", "lab-plain"], rel)
            self.assertEqual(p["deferred"], ["lab-phased"], rel)

    def test_the_age_of_the_package_lists_comes_from_the_host_clock(self):
        p = real("ubuntu-24.04", "standard")
        self.assertGreaterEqual(p["lists_age_s"], 0)
        self.assertLess(p["lists_age_s"], 600)
        self.assertEqual(p["lists_age_s"], p["host_time"] - p["lists_at"])

    def test_it_reads_the_older_captures_of_the_plain_command_too(self):
        # tests/data/apt_real holds the bare apt-get answers the agent's package scan was tested on.
        for rel in RELEASES:
            for state, up in (("included_plain", 2), ("included_with_new_pkgs", 3)):
                raw = (APT_REAL / rel / f"{state}.txt").read_text()
                p = P.parse(f"##now 1\n##manager apt\n##mode standard\n##held\nlab-held\n##rc 0\n##plan\n{raw}\n##end\n")
                self.assertEqual(p["status"], "done", (rel, state))
                self.assertEqual(p["counts"]["upgrade"], up, (rel, state))


# ── apt, edge cases ───────────────────────────────────────────────────────────────────────────────────────────────────
def apt(body, held="", rc=0, tail="##end\n"):
    return f"##now 1000\n##manager apt\n##mode standard\n##lists 900\n##held\n{held}\n##rc {rc}\n##plan\n{body}\n{tail}"


class TestAptEdges(unittest.TestCase):

    def test_nothing_to_upgrade_is_an_answer(self):
        p = P.parse(apt("0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded."))
        self.assertEqual((p["status"], p["counts"]["upgrade"], p["upgrades"]), ("done", 0, []))
        self.assertFalse(p["reboot_likely"])

    def test_an_error_is_not_an_empty_plan(self):
        p = P.parse(apt("E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 812", rc=100))
        self.assertEqual(p["status"], "failed")
        self.assertIn("Could not get lock", p["error"])
        self.assertEqual(p["upgrades"], [])

    def test_removals_and_the_removed_block(self):
        body = ("The following packages will be REMOVED:\n  libold1 libold2\n"
                "1 upgraded, 0 newly installed, 2 to remove and 0 not upgraded.\n"
                "Remv libold1 [1.2-3]\n"
                "Inst foo [1.0-1] (1.0-2 Debian:12/stable [amd64])")
        p = P.parse(apt(body))
        self.assertEqual(sorted(names(p["removals"])), ["libold1", "libold2"], "one entry each, not one per line and block")
        self.assertEqual(p["removals"][0].get("from"), "1.2-3")
        self.assertEqual(p["counts"]["remove"], 2)

    def test_several_sources_and_a_security_suite(self):
        line = "Inst openssl [3.0.2-0ubuntu1.10] (3.0.2-0ubuntu1.12 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])"
        p = P.parse(apt("1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n" + line))
        self.assertTrue(p["upgrades"][0]["security"])
        self.assertEqual(p["upgrades"][0]["from"], "3.0.2-0ubuntu1.10")
        self.assertEqual(p["upgrades"][0]["to"], "3.0.2-0ubuntu1.12")

    def test_a_kernel_and_a_reboot_are_estimated_from_the_names(self):
        body = ("2 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.\n"
                "Inst linux-image-6.8.0-50-generic (6.8.0-50.51 Ubuntu:24.04/noble-security [amd64])\n"
                "Inst libc6 [2.39-0ubuntu8.2] (2.39-0ubuntu8.3 Ubuntu:24.04/noble-updates [amd64])\n"
                "Inst curl [8.5.0-2] (8.5.0-3 Ubuntu:24.04/noble-updates [amd64])")
        p = P.parse(apt(body))
        self.assertTrue(p["kernel"])
        self.assertTrue(p["reboot_likely"])
        self.assertEqual(p["reboot_reasons"], ["linux-image-6.8.0-50-generic", "libc6"])
        quiet = P.parse(apt("1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\nInst curl [1] (2 Ubuntu:24.04/noble-updates [amd64])"))
        self.assertFalse(quiet["kernel"] or quiet["reboot_likely"])

    def test_which_names_count_as_a_kernel(self):
        kernel = ("linux-image-6.8.0-50-generic", "linux-image-amd64", "linux-generic", "linux-generic-hwe-22.04", "linux-signed-azure",
                  "linux-modules-6.8.0-50-generic", "proxmox-kernel-6.8.12-4-pve", "pve-kernel-5.15.0-1-pve", "kernel", "kernel-core",
                  "kernel-modules-core", "linux", "linux-lts", "linux-zen", "linux-hardened", "linux-cachyos", "linux-cachyos-bore")
        not_kernel = ("linux-firmware", "linux-headers-6.8.0-50", "linux-libc-dev", "linux-base", "kernel-headers", "kernel-devel",
                      "kernel-tools", "linux-headers", "linux-lts-headers", "linux-cachyos-headers", "linux-cachyos-bore-headers",
                      "curl", "libc6", "systemd")
        for n in kernel:
            self.assertTrue(P._KERNEL_RE.match(n), n)
        for n in not_kernel:
            self.assertFalse(P._KERNEL_RE.match(n), n)

    def test_a_cut_answer_says_so_and_drops_the_half_line(self):
        full = "1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\nInst alpha [1] (2 o [amd64])\nInst beta [1] (2 o [amd6"
        p = P.parse(apt(full, tail="") + P.TRUNC_MARK)
        self.assertTrue(p["truncated"])
        self.assertEqual(names(p["upgrades"]), ["alpha"], "the half line is not a package")

    def test_an_answer_without_its_end_is_marked_cut(self):
        self.assertTrue(P.parse(apt("0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.", tail=""))["truncated"])

    def test_the_summary_can_say_there_is_more_than_was_listed(self):
        body = "5 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\nInst alpha [1] (2 o [amd64])"
        self.assertTrue(P.parse(apt(body))["truncated"])

    def test_each_list_is_capped(self):
        lines = "\n".join(f"Inst pkg{i} [1] (2 o [amd64])" for i in range(P.MAX_ITEMS + 80))
        p = P.parse(apt(f"{P.MAX_ITEMS + 80} upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n{lines}"))
        self.assertEqual(len(p["upgrades"]), P.MAX_ITEMS)
        self.assertTrue(p["truncated"])

    def test_names_and_versions_from_a_host_are_checked(self):
        bad = ["Inst <img src=x onerror=alert(1)> [1] (2 o [amd64])",
               "Inst " + "a" * 5000 + " [1] (2 o [amd64])",
               "Inst -rf [1] (2 o [amd64])",
               "Inst ok [1] (; rm -rf / o [amd64])",
               "Inst ok2 [<b>] (2 o [amd64])",
               "Inst  [1] (2 o [amd64])",
               "Inst nover",
               "Remv <x>"]
        good = "Inst fine [1.0-1] (1.0-2 Debian:12/stable [amd64])"
        p = P.parse(apt("\n".join(bad + [good])))
        self.assertEqual(names(p["upgrades"]), ["fine"])
        self.assertEqual(p["removals"], [])
        self.assertGreaterEqual(p["skipped"], 6, "what was dropped is counted")
        self.assertNotIn("<", json.dumps({k: v for k, v in p.items() if k != "raw"}), "the raw answer is the host's own text and is escaped where it is shown")

    def test_a_trailing_newline_does_not_make_a_name(self):
        # `$` matches before a final newline, so a pattern ending in it accepts "name\n"; the readers use fullmatch
        for bad in ("foo\n", "1.0\n", "foo\n\n"):
            self.assertEqual(P._name(bad), "")
            self.assertEqual(P._ver(bad), "")
        self.assertEqual(P._name("foo"), "foo")

    def test_it_never_raises_on_what_is_not_text(self):
        for junk in (None, 5, 1.5, b"##manager apt", [], {}, True, "", "\x00" * 100, "##", "##manager", "##manager apt\n##plan"):
            p = P.parse(junk)
            self.assertIn(p["status"], ("failed", "done"), repr(junk))
            self.assertIsInstance(p["error"], str)

    def test_no_package_manager_is_said_plainly(self):
        p = P.parse("##now 1\n##manager none\n##end\n")
        self.assertEqual(p["status"], "failed")
        self.assertIn("no package manager", p["error"])
        self.assertEqual(P.parse("##manager zypper\n##plan\n##end\n")["status"], "failed")

    def test_a_long_line_does_not_make_it_slow(self):
        t0 = time.time()
        for line in ("Inst " + "a " * 40000, "Inst x [" + "[" * 50000, "The following " + "x" * 90000, "Remv " + "b" * 90000):
            P.parse(apt(line))
        self.assertLess(time.time() - t0, 2.0)

    def test_random_text_is_bounded_and_does_not_raise(self):
        rnd = random.Random(7)
        frags = ["Inst ", "Remv ", "[", "]", "(", ")", " ", "\n", "##plan\n", "##manager apt\n", "##held\n", "The following ",
                 "packages", "  ", "lab-x", "1.0", "upgraded, ", "0 ", "newly installed, ", "E: ", "x" * 300, "\x00", "é", "##end\n"]
        for _ in range(400):
            txt = "".join(rnd.choice(frags) for _ in range(rnd.randint(1, 60)))
            p = P.parse(txt)
            for k in ("upgrades", "installs", "removals", "kept_back", "deferred", "autoremove"):
                self.assertLessEqual(len(p[k]), P.MAX_ITEMS)
            json.dumps(p)


# ── dnf and pacman: samples written from the documented formats, NOT captured from a live host ───────────────────────
DNF4 = """Last metadata expiration check: 0:12:01 ago on Mon 03 Nov 2026 09:00:00 AM UTC.
Dependencies resolved.
================================================================================
 Package                 Architecture Version                    Repository Size
================================================================================
Installing:
 kernel-core             x86_64       5.14.0-503.14.1.el9_5      baseos      17 M
Upgrading:
 openssl                 x86_64       1:3.2.2-6.el9_5.1          baseos     1.4 M
 selinux-policy-targeted-and-a-very-long-package-name-that-wraps
                         noarch       38.1.45-3.el9_5            baseos     6.9 M
Installing dependencies:
 kernel-modules-core     x86_64       5.14.0-503.14.1.el9_5      baseos      38 M
Removing:
 kernel-core             x86_64       5.14.0-284.el9             @System     64 M

Transaction Summary
================================================================================
Install  2 Packages
Upgrade  2 Packages
Remove   1 Package

Total download size: 62 M
Is this ok [y/N]: Operation aborted.
"""

DNF5 = """Updating and loading repositories:
Repositories loaded.
Package                Arch   Version                 Repository      Size
Installing:
 kernel-core           x86_64 6.11.4-300.fc41         updates     18.2 MiB
Upgrading:
 curl                  x86_64 8.9.1-2.fc41            updates    410.0 KiB
   replacing curl      x86_64 8.9.1-1.fc41            @System    399.1 KiB
 openssl-libs          x86_64 1:3.2.2-8.fc41          updates      2.3 MiB
   replacing openssl-libs x86_64 1:3.2.2-7.fc41       @System      2.3 MiB
Removing:
 kernel-core           x86_64 6.10.9-200.fc40         @System     70.1 MiB

Transaction Summary:
 Installing:         1 package
 Upgrading:          2 packages
 Removing:           1 package

Total size of inbound packages is 21 MiB. Need to download 21 MiB.
After this operation, 5 MiB extra will be used (install 91 MiB, remove 86 MiB).
Operation aborted by the user.
"""


def dnf(plan, security="", rc=1):
    return f"##now 1000\n##manager dnf\n##rc {rc}\n##plan\n{plan}\n##security\n{security}\n##end\n"


class TestDnf(unittest.TestCase):

    def test_dnf4_table(self):
        p = P.parse(dnf(DNF4, "openssl.x86_64   1:3.2.2-6.el9_5.1   baseos\n"))
        self.assertEqual(p["status"], "done")
        self.assertEqual(sorted(names(p["upgrades"])),
                         ["openssl", "selinux-policy-targeted-and-a-very-long-package-name-that-wraps"], "a wrapped name is one row")
        self.assertEqual(sorted(names(p["installs"])), ["kernel-core", "kernel-modules-core"], "dependencies are installs")
        self.assertEqual(names(p["removals"]), ["kernel-core"])
        self.assertEqual(p["removals"][0]["from"], "5.14.0-284.el9")
        self.assertFalse(p["partial"])
        self.assertEqual(p["download_bytes"], 62 * 1024 * 1024)
        self.assertTrue(p["kernel"] and p["reboot_likely"])
        by = {u["name"]: u for u in p["upgrades"]}
        self.assertTrue(by["openssl"]["security"], "named by check-update --security")
        self.assertEqual(by["openssl"]["to"], "1:3.2.2-6.el9_5.1")
        self.assertEqual(by["openssl"]["source"], "baseos")
        self.assertEqual((p["counts"]["upgrade"], p["counts"]["install"], p["counts"]["remove"]), (2, 2, 1))

    def test_dnf5_table_gives_the_old_version_from_the_replacing_line(self):
        p = P.parse(dnf(DNF5))
        self.assertEqual(p["status"], "done")
        by = {u["name"]: u for u in p["upgrades"]}
        self.assertEqual((by["curl"]["from"], by["curl"]["to"]), ("8.9.1-1.fc41", "8.9.1-2.fc41"))
        self.assertEqual(by["openssl-libs"]["from"], "1:3.2.2-7.fc41")
        self.assertEqual(names(p["installs"]), ["kernel-core"])
        self.assertEqual(names(p["removals"]), ["kernel-core"])
        self.assertFalse(p["partial"])
        self.assertEqual(p["download_bytes"], 21 * 1024 * 1024)

    def test_rows_that_do_not_match_the_counts_are_marked_partial(self):
        short = DNF4.replace(" openssl                 x86_64       1:3.2.2-6.el9_5.1          baseos     1.4 M\n", "")
        p = P.parse(dnf(short))
        self.assertTrue(p["partial"], "the table says Upgrade 2 Packages and one row was read")
        self.assertEqual(p["counts"]["upgrade"], 2, "the count the package manager printed is kept")
        self.assertEqual(len(p["upgrades"]), 1)

    def test_a_table_that_cannot_be_read_still_gives_the_counts(self):
        unreadable = "Transaction Summary\n====\nUpgrade  12 Packages\n"
        p = P.parse(dnf(unreadable))
        self.assertEqual(p["status"], "done")
        self.assertTrue(p["partial"])
        self.assertEqual((p["counts"]["upgrade"], p["upgrades"]), (12, []))

    def test_nothing_to_do(self):
        p = P.parse(dnf("Last metadata expiration check: 0:01:00 ago.\nDependencies resolved.\nNothing to do.\nComplete!"))
        self.assertEqual((p["status"], p["upgrades"], p["partial"]), ("done", [], False))

    def test_an_error_is_failed_with_its_text(self):
        p = P.parse(dnf("Error: Failed to download metadata for repo 'appstream': Cannot prepare internal mirrorlist"))
        self.assertEqual(p["status"], "failed")
        self.assertIn("Failed to download metadata", p["error"])

    def test_unknown_output_is_failed_not_empty(self):
        self.assertEqual(P.parse(dnf("something else entirely"))["status"], "failed")

    def test_old_yum_names_its_sections_differently(self):
        yum = ("Dependencies Resolved\n====\nUpdating:\n bash        x86_64    4.2.46-35.el7_9   updates   1.0 M\n"
               "Installing for dependencies:\n libfoo   x86_64    1.0-1.el7   base   10 k\n\n"
               "Transaction Summary\n====\nInstall             ( 1 Dependent package)\nUpgrade  1 Package\n")
        p = P.parse(dnf(yum))
        self.assertEqual(names(p["upgrades"]), ["bash"])
        self.assertEqual(names(p["installs"]), ["libfoo"])


class TestPacman(unittest.TestCase):

    QU = "linux 6.11.5.arch1-1 -> 6.11.6.arch1-1\nopenssl 3.3.2-1 -> 3.4.0-1\nignored-pkg 1-1 -> 2-1 [ignored]\n"
    TARGETS = "linux 6.11.6.arch1-1\nopenssl 3.4.0-1\nlibnew 1.0-1\n"

    def pac(self, qu, targets, rc_marker=True):
        return f"##now 1000\n##manager pacman\n##lists 900\n##plan\n{qu}##targets\n{targets}##end\n"

    def test_versions_and_new_dependencies(self):
        p = P.parse(self.pac(self.QU, self.TARGETS))
        self.assertEqual(p["status"], "done")
        by = {u["name"]: u for u in p["upgrades"]}
        self.assertEqual((by["linux"]["from"], by["linux"]["to"]), ("6.11.5.arch1-1", "6.11.6.arch1-1"))
        self.assertEqual(names(p["installs"]), ["libnew"], "only a target that is not an upgrade is new")
        self.assertEqual(names(p["kept_back"]), ["ignored-pkg"])
        self.assertEqual(p["removals"], [], "pacman prints no removals in a dry run, so none are claimed")
        self.assertTrue(p["kernel"] and p["reboot_likely"])

    def test_up_to_date_is_an_answer(self):
        p = P.parse(self.pac("", ""))
        self.assertEqual((p["status"], p["upgrades"], p["installs"]), ("done", [], []))

    def test_a_missing_section_is_not_an_answer(self):
        self.assertEqual(P.parse("##now 1\n##manager pacman\n##end\n")["status"], "failed")


# ── the script ────────────────────────────────────────────────────────────────────────────────────────────────────────
class TestCommand(unittest.TestCase):

    def test_only_a_well_formed_id_and_a_known_mode_are_accepted(self):
        for bad in ("", "pp-", "pp-0123456789a", "pp-0123456789abc", "pp-0123456789AB", "pp-012345678;ab", "x" * 40, None, 5, "pp-01234567 9ab"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                P.command(bad)
        for mode in ("", "EXTENDED", "extended; rm -rf /", None, "dist-upgrade"):
            with self.assertRaises(ValueError, msg=repr(mode)):
                P.command(PID, mode)

    def test_the_mode_changes_only_the_apt_flag(self):
        std, ext = P.command(PID, "standard"), P.command(PID, "extended")
        self.assertTrue(std.startswith("exec:#patchplan:" + PID + "#\n"))
        self.assertNotIn("--with-new-pkgs", std)
        self.assertEqual(ext.count("--with-new-pkgs"), 2, "the plan and the question about phasing")
        self.assertEqual(ext.replace("--with-new-pkgs ", "").replace("##mode extended", "##mode standard"), std)

    def test_no_placeholder_is_left_and_nothing_can_be_injected(self):
        for mode in P.MODES:
            self.assertNotIn("@", P.command(PID, mode).replace("@ ", ""))

    def test_the_script_only_asks(self):
        script = P.command(PID, "extended")
        for word in ("apt-get update", " -y ", "install ", "autoremove", "dist-upgrade", "apt-get upgrade", "dnf upgrade -y",
                     "pacman -Sy", "pacman -S ", "reboot", "curl", "wget", "> /", "rm -rf", "eval", "sudo"):
            self.assertNotIn(word, script, word)
        self.assertIn("--simulate", script)
        self.assertIn("--assumeno", script)

    def test_the_id_round_trips_through_the_echo_the_agent_sends_back(self):
        cmd = P.command(PID, "standard")
        self.assertEqual(P.plan_id_of(cmd), PID)
        self.assertEqual(P.plan_id_of("exec:to=120:" + cmd[5:]), PID)
        self.assertEqual(P.plan_id_of(cmd[5:]), PID)
        for other in ("exec:ls", "", None, 5, "exec:#acme:x#y", "exec:#patchplan:pp-zzzzzzzzzzzz#", "x" + cmd):
            self.assertEqual(P.plan_id_of(other), "", repr(other))

    @unittest.skipUnless(shutil.which("shellcheck"), "shellcheck is not installed")
    def test_shellcheck_accepts_it_as_posix_sh(self):
        for mode in P.MODES:
            p = subprocess.run(["shellcheck", "-s", "sh", "-"], input=P.command(PID, mode)[5:], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stdout)


class _Shims:
    """A directory of fake package managers that print recorded output, and a log of how each was called."""

    def __init__(self, tmp):
        self.bin = Path(tmp) / "bin"
        self.bin.mkdir()
        self.log = Path(tmp) / "calls.log"
        self.tmp = Path(tmp) / "tmp"
        self.tmp.mkdir()

    def add(self, name, body):
        f = self.bin / name
        f.write_text("#!/bin/sh\n" + f'echo "{name} $*" >> "{self.log}"\n' + body)
        f.chmod(f.stat().st_mode | stat.S_IEXEC)

    def run(self, script, extra_path=True):
        env = {"PATH": f"{self.bin}:/usr/bin:/bin" if extra_path else str(self.bin), "TMPDIR": str(self.tmp), "HOME": str(self.tmp)}
        p = subprocess.run(["sh", "-c", script], capture_output=True, text=True, env=env, timeout=60)
        return p

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []


class TestScriptRun(unittest.TestCase):
    """The script is run for real under sh. The package managers are fake and print what real apt printed."""

    def setUp(self):
        self.t = tempfile.mkdtemp(prefix="rp-pp-sh-")
        self.s = _Shims(self.t)

    def tearDown(self):
        shutil.rmtree(self.t, ignore_errors=True)

    def apt_shims(self, rel, state):
        plain, newpk, nophase = (APT_REAL / rel / f"{state}_plain.txt", APT_REAL / rel / f"{state}_with_new_pkgs.txt",
                                 APT_REAL / rel / f"{state}_ignoring_phasing.txt")
        self.s.add("apt-get", f'case "$*" in\n*Always-Include-Phased*) cat "{nophase}";;\n*with-new-pkgs*) cat "{newpk}";;\n*) cat "{plain}";;\nesac\nexit 0\n')
        self.s.add("apt-mark", 'echo lab-held\n')

    def test_it_agrees_with_real_apt_on_every_version(self):
        # state "deferred" is the one where apt 2.4 mixes the deferred package into "kept back".
        for rel in RELEASES:
            for state, kind in (("deferred", "standard-deferred"), ("included", "standard")):
                self.s = _Shims(tempfile.mkdtemp(prefix="rp-pp-sh-", dir=self.t))
                self.apt_shims(rel, state)
                out = self.s.run(P.command(PID, "standard")[5:]).stdout
                mine, theirs = P.parse(out), real(rel, kind)
                self.assertEqual(mine["status"], "done", (rel, state, out))
                for k in ("upgrades", "installs", "kept_back", "deferred", "autoremove"):
                    self.assertEqual(mine[k], theirs[k], (rel, state, k))

    def test_extended_uses_the_new_packages_flag_on_both_questions(self):
        self.apt_shims("ubuntu-24.04", "included")
        out = self.s.run(P.command(PID, "extended")[5:]).stdout
        calls = [c for c in self.s.calls() if c.startswith("apt-get")]
        self.assertEqual(len(calls), 2, calls)
        for c in calls:
            self.assertIn("--with-new-pkgs", c)
            self.assertIn("--simulate", c)
        self.assertEqual(names(P.parse(out)["installs"]), ["lab-kernel-image-2"])

    def test_the_second_question_is_asked_only_when_something_is_kept_back(self):
        self.s.add("apt-get", 'echo "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded."\n')
        self.s.add("apt-mark", "true\n")
        out = self.s.run(P.command(PID, "standard")[5:]).stdout
        self.assertEqual(len([c for c in self.s.calls() if c.startswith("apt-get")]), 1)
        self.assertEqual(P.parse(out)["counts"]["upgrade"], 0)

    def test_it_never_changes_anything(self):
        self.apt_shims("ubuntu-24.04", "included")
        self.s.run(P.command(PID, "extended")[5:])
        for c in self.s.calls():
            if c.startswith("apt-get"):
                self.assertIn("--simulate", c)
                for bad in (" update", " install", " remove", " autoremove", " dist-upgrade", " -y"):
                    self.assertNotIn(bad, c)
            else:
                self.assertEqual(c, "apt-mark showhold")

    def test_it_leaves_no_temporary_file_behind(self):
        self.apt_shims("ubuntu-24.04", "included")
        self.s.run(P.command(PID, "standard")[5:])
        self.assertEqual(list(self.s.tmp.iterdir()), [])

    def test_a_huge_answer_stays_inside_what_the_agent_will_return(self):
        lines = "\n".join(f"Inst package-number-{i} [1.0.{i}-1] (1.0.{i}-2 Ubuntu:24.04/noble-updates [amd64])" for i in range(5000))
        self.s.add("apt-get", f'cat <<\'EOF\'\n5000 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n{lines}\nEOF\n')
        self.s.add("apt-mark", "true\n")
        out = self.s.run(P.command(PID, "standard")[5:]).stdout
        self.assertLess(len(out.splitlines()), 320)
        p = P.parse(out)
        self.assertEqual(p["status"], "done")
        self.assertTrue(p["truncated"], "the summary says 5000, the list holds fewer")
        self.assertEqual(p["counts"]["upgrade"], len(p["upgrades"]))

    def test_dnf_is_asked_with_assumeno_and_never_yes(self):
        self.s.add("dnf", f'case "$*" in\n*check-update*) printf "openssl.x86_64   1:3.2.2-6.el9_5.1   baseos\\n"; exit 100;;\n*) cat <<\'EOF\'\n{DNF4}EOF\nexit 1;;\nesac\n')
        out = self.s.run(P.command(PID, "standard")[5:]).stdout
        p = P.parse(out)
        self.assertEqual(p["manager"], "dnf")
        self.assertEqual(p["status"], "done", out)
        self.assertEqual(len(p["upgrades"]), 2)
        self.assertTrue([u for u in p["upgrades"] if u["name"] == "openssl"][0]["security"])
        calls = self.s.calls()
        self.assertTrue(any("upgrade --assumeno" in c for c in calls), calls)
        self.assertFalse(any(" -y" in c or " install" in c for c in calls), calls)

    def test_yum_is_used_when_there_is_no_dnf(self):
        self.s.add("yum", f"cat <<'EOF'\n{DNF4}EOF\nexit 1\n")
        out = self.s.run(P.command(PID, "standard")[5:]).stdout
        self.assertEqual(P.parse(out)["manager"], "dnf")
        self.assertTrue(any(c.startswith("yum upgrade --assumeno") for c in self.s.calls()), self.s.calls())

    def test_pacman_is_only_asked_what_it_has(self):
        self.s.add("pacman", f'case "$1" in\n-Qu) printf "{TestPacman.QU}";;\n-Sup) printf "{TestPacman.TARGETS}";;\n*) exit 1;;\nesac\n')
        out = self.s.run(P.command(PID, "standard")[5:]).stdout
        p = P.parse(out)
        self.assertEqual(p["manager"], "pacman")
        self.assertEqual(names(p["installs"]), ["libnew"])
        for c in self.s.calls():
            self.assertRegex(c, r"^pacman (-Qu|-Sup --print-format)")

    def test_a_host_with_no_package_manager_says_so(self):
        # only the tools the script needs before it knows the manager
        for tool in ("mktemp", "date", "rm", "sh"):
            found = shutil.which(tool)
            if found:
                (self.s.bin / tool).symlink_to(found)
        out = self.s.run(P.command(PID, "standard")[5:], extra_path=False).stdout
        self.assertIn("##manager none", out)
        self.assertTrue(out.rstrip().endswith("##end"))
        self.assertEqual(P.parse(out)["status"], "failed")


# ── the handlers ──────────────────────────────────────────────────────────────────────────────────────────────────────
class _PP(_Base):
    STORES = _Base.STORES + ("CMDS_FILE", "PATCH_PREVIEWS_FILE", "CMD_OUTPUT_FILE", "ROLES_FILE", "CONFIRMATIONS_FILE")

    def setUp(self):
        super().setUp()
        os.environ["QUERY_STRING"] = ""
        self._more = {n: getattr(api, n) for n in ("log_command", "_maintenance_active")}
        self.logged = []
        api.log_command = lambda *a, **k: self.logged.append(a)
        api._maintenance_active = lambda: (False, "")
        self.audits = []
        api.audit_log = lambda *a, **k: self.audits.append(a)
        devs = api.load(api.DEVICES_FILE)
        for did, extra in {
            "lin1": {"os": "Ubuntu 24.04", "sysinfo": {"packages": {"manager": "apt"}}},
            "lin2": {"os": "Ubuntu 22.04", "upgrade_mode": "extended", "sysinfo": {"packages": {"manager": "apt"}}},
            "arch1": {"os": "Arch Linux", "sysinfo": {"packages": {"manager": "pacman"}}},
            "new1": {"os": "Debian 13", "sysinfo": {}},
            "sus1": {"os": "openSUSE Leap", "sysinfo": {"packages": {"manager": "zypper"}}},
            "win1": {"os": "Windows 11 (Build 22631)", "sysinfo": {}},
            "mac1": {"os": "macOS 14.5 (23F79)", "sysinfo": {}},
        }.items():
            devs[did] = dict({"name": did, "tenant": "tenantB", "token_hash": "x"}, **extra)
        api.save(api.DEVICES_FILE, devs)
        api.save(api.CMDS_FILE, {})
        api.save(api.PATCH_PREVIEWS_FILE, {})
        api.save(api.CMD_OUTPUT_FILE, {})
        api.save(api.USERS_FILE, dict(api.load(api.USERS_FILE), bviewer={"role": "viewer", "tenant_id": "tenantB"},
                                      bpatcher={"role": "patcher", "tenant_id": "tenantB"},
                                      bnopatch={"role": "nopatch", "tenant_id": "tenantB"}))
        api.save(api.ROLES_FILE, {"roles": [{"name": "patcher", "permissions": ["patch"], "scope": {"type": "all"}},
                                            {"name": "nopatch", "permissions": ["command"], "scope": {"type": "all"}}]})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._more.items():
            setattr(api, n, v)
        super().tearDown()

    def post(self, dev_id, who="badmin"):
        return self.call(api.handle_device_patch_preview, dev_id, m="POST", who=who)

    def get(self, dev_id, who="badmin", query=""):
        os.environ["QUERY_STRING"] = query
        r = self.call(api.handle_device_patch_preview, dev_id, m="GET", who=who)
        os.environ["QUERY_STRING"] = ""
        return r

    def queue(self, dev_id):
        api._LOAD_CACHE.clear()
        return (api.load(api.CMDS_FILE) or {}).get(dev_id, [])

    def record(self, dev_id):
        api._LOAD_CACHE.clear()
        return (api.load(api.PATCH_PREVIEWS_FILE) or {}).get(dev_id)

    def answer(self, dev_id, text, rc=0, cmd=None, now=5000):
        rec = self.record(dev_id)
        cmd = cmd or self.queue(dev_id)[-1]
        return api.patch_preview_ingest(dev_id, cmd, text, rc, now), rec


class TestAsking(_PP):

    def test_it_queues_one_read_only_command_and_remembers_it(self):
        st, d = self.post("lin1")
        self.assertEqual(st, 200, d)
        q = self.queue("lin1")
        self.assertEqual(len(q), 1)
        self.assertEqual(P.plan_id_of(q[0]), d["id"])
        self.assertIn("--simulate", q[0])
        self.assertNotIn("with-new-pkgs", q[0], "a Standard host is asked the Standard question")
        rec = self.record("lin1")
        self.assertEqual((rec["pending"]["id"], rec["pending"]["by"]), (d["id"], "badmin"))
        self.assertEqual(self.logged[-1][3], "patch preview")
        self.assertEqual(self.audits[-1][1], "patch_preview")

    def test_an_extended_host_is_asked_the_extended_question(self):
        self.post("lin2")
        self.assertIn("--with-new-pkgs", self.queue("lin2")[0])

    def test_asking_twice_in_a_row_is_one_request(self):
        st1, d1 = self.post("lin1")
        st2, d2 = self.post("lin1")
        self.assertEqual((st2, d2["id"], d2.get("already_pending")), (200, d1["id"], True))
        self.assertEqual(len(self.queue("lin1")), 1)
        self.assertEqual(len([a for a in self.audits if a[1] == "patch_preview"]), 1, "the second was not a new request")

    def test_an_old_request_is_replaced_and_only_one_waits_in_the_queue(self):
        st, d1 = self.post("lin1")
        rec = self.record("lin1")
        rec["pending"]["at"] -= 600
        api.save(api.PATCH_PREVIEWS_FILE, {"lin1": rec})
        api.save(api.CMDS_FILE, {"lin1": ["exec:ls"] + self.queue("lin1")})
        st, d2 = self.post("lin1")
        self.assertEqual(st, 200)
        self.assertNotEqual(d2["id"], d1["id"])
        q = self.queue("lin1")
        self.assertEqual([c for c in q if P.plan_id_of(c)], [c for c in q if P.plan_id_of(c) == d2["id"]])
        self.assertEqual(len(q), 2)
        self.assertIn("exec:ls", q, "another queued command is left alone")

    def test_the_host_must_be_linux_with_a_package_manager_the_preview_reads(self):
        for dev, reason in (("win1", "not_linux"), ("mac1", "not_linux"), ("sus1", "no_manager")):
            st, d = self.post(dev)
            self.assertEqual((st, d["reason"]), (409, reason), dev)
            self.assertEqual(self.queue(dev), [], dev)
            self.assertIsNone(self.record(dev), dev)
        for dev in ("arch1", "new1"):
            self.assertEqual(self.post(dev)[0], 200, dev)

    def test_a_host_that_cannot_take_a_command_is_refused_like_any_other(self):
        devs = api.load(api.DEVICES_FILE)
        devs["lin1"]["quarantined"] = True
        devs["lin2"]["sysinfo"]["audit_mode"] = True
        api.save(api.DEVICES_FILE, devs)
        self.assertEqual(self.post("lin1")[0], 409)
        self.assertEqual(self.post("lin2")[0], 409)
        api._maintenance_active = lambda: (True, "upgrade")
        st, d = self.post("arch1")
        self.assertEqual((st, d.get("maintenance")), (503, True))
        for dev in ("lin1", "lin2", "arch1"):
            self.assertEqual(self.queue(dev), [], dev)
            self.assertIsNone(self.record(dev), dev)

    def test_a_full_queue_is_refused_and_leaves_no_request_behind(self):
        api.save(api.CMDS_FILE, {"lin1": ["exec:x"] * api.MAX_QUEUED_PER_DEVICE})
        st, d = self.post("lin1")
        self.assertEqual(st, 429, d)
        self.assertIsNone((self.record("lin1") or {}).get("pending"))
        self.assertEqual(len(self.queue("lin1")), api.MAX_QUEUED_PER_DEVICE)

    def test_who_may_ask(self):
        self.assertEqual(self.post("lin1", who="bpatcher")[0], 200, "a role with the patch permission")
        self.assertEqual(self.post("arch1", who="bviewer")[0], 403)
        self.assertEqual(self.post("new1", who="bnopatch")[0], 403, "a different permission is not this one")
        self.assertEqual(self.queue("arch1"), [])
        self.assertEqual(self.post("lin1", who=None)[0], 401)

    def test_the_other_verbs_and_bad_ids(self):
        self.assertEqual(self.call(api.handle_device_patch_preview, "lin1", m="DELETE")[0], 405)
        self.assertEqual(self.call(api.handle_device_patch_preview, "lin1", m="PUT")[0], 405)
        for bad in ("../x", "a b", "", "x" * 200, "lin1/../../x"):
            self.assertEqual(self.post(bad)[0], 404, bad)
        self.assertEqual(self.post("nope")[0], 404)
        self.assertEqual(self.get("nope")[0], 404)

    def test_the_route_is_under_the_host_path_so_the_tenant_and_scope_gate_runs_first(self):
        src = (ROOT / "server" / "cgi-bin" / "api.py").read_text()
        self.assertIn("'/api/devices/', '/patch-preview', 'handle_device_patch_preview'", src)
        api.path_info = lambda: "/api/devices/devC/patch-preview"
        st, d = self.call(api._enforce_device_scope, m="POST", who="badmin")
        self.assertEqual(st, 403, "tenant B's administrator is turned away from tenant C's host before the handler runs")


class TestReading(_PP):

    def test_nothing_yet(self):
        st, d = self.get("lin1")
        self.assertEqual((st, d["applies"], d["plan"], d["pending"], d["mode"]), (200, True, None, None, "standard"))

    def test_a_host_it_does_not_apply_to_says_why(self):
        st, d = self.get("win1")
        self.assertEqual((st, d["applies"], d["reason"]), (200, False, "not_linux"))
        self.assertIn("Windows or macOS", d["reason_text"])

    def test_a_waiting_request_is_reported_and_times_out(self):
        self.post("lin1")
        d = self.get("lin1")[1]
        self.assertEqual((d["pending"]["by"], d["pending"]["timed_out"]), ("badmin", False))
        rec = self.record("lin1")
        rec["pending"]["at"] -= P.PENDING_TTL + 5
        api.save(api.PATCH_PREVIEWS_FILE, {"lin1": rec})
        self.assertTrue(self.get("lin1")[1]["pending"]["timed_out"])

    def test_anyone_who_can_see_the_host_can_read_the_plan_and_the_raw_answer_is_opt_in(self):
        self.post("lin1")
        self.answer("lin1", (FIX / "ubuntu-24.04-standard.txt").read_text())
        d = self.get("lin1", who="bviewer")[1]
        self.assertEqual(d["plan"]["status"], "done")
        self.assertNotIn("raw", d["plan"])
        self.assertIn("lab-plain", self.get("lin1", who="bviewer", query="raw=1")[1]["plan"]["raw"])
        self.assertEqual(self.get("lin1", who=None)[0], 401)


class TestTheAnswer(_PP):
    GOOD = (FIX / "ubuntu-24.04-extended.txt").read_text()

    def test_it_is_read_stored_and_the_request_cleared(self):
        self.post("lin2")
        line, _ = self.answer("lin2", self.GOOD, rc=0, now=7777)
        self.assertEqual(line, "patch preview: 3 to upgrade, 1 new, 0 removed, 1 kept back")
        rec = self.record("lin2")
        self.assertIsNone(rec["pending"])
        plan = rec["plan"]
        self.assertEqual((plan["status"], plan["at"], plan["by"], plan["rc"]), ("done", 7777, "badmin", 0))
        self.assertEqual(plan["id"], self.queue("lin2")[0] and P.plan_id_of(self.queue("lin2")[0]))
        self.assertEqual(sorted(names(plan["upgrades"])), ["lab-kernel-meta", "lab-phased", "lab-plain"])

    def test_the_last_plan_is_kept_while_a_new_one_is_asked_for(self):
        self.post("lin1")
        self.answer("lin1", self.GOOD)
        rec = self.record("lin1")
        rec["pending"] = None
        api.save(api.PATCH_PREVIEWS_FILE, {"lin1": rec})
        self.post("lin1")
        d = self.get("lin1")[1]
        self.assertIsNotNone(d["pending"])
        self.assertEqual(d["plan"]["status"], "done", "the earlier plan is still shown while the new one is awaited")

    def test_an_answer_nobody_asked_for_is_dropped(self):
        self.post("lin1")
        before = self.record("lin1")
        for cmd in ("exec:#patchplan:pp-aaaaaaaaaaaa#\nx", P.command("pp-bbbbbbbbbbbb")):
            line = api.patch_preview_ingest("lin1", cmd, self.GOOD, 0, 9)
            self.assertIn("dropped", line)
        self.assertEqual(self.record("lin1"), before, "neither a stale id nor a made-up one changes the record")
        self.assertIn("dropped", api.patch_preview_ingest("lin2", P.command(PID), self.GOOD, 0, 9), "no request at all")
        self.assertIsNone(self.record("lin2"))

    def test_another_command_is_not_touched(self):
        self.assertIsNone(api.patch_preview_ingest("lin1", "exec:uptime", "up 3 days", 0, 9))
        self.assertIsNone(api.patch_preview_ingest("lin1", "exec:#acme:abc#x", "ok", 0, 9))

    def test_garbage_from_the_host_is_a_failed_plan_not_a_fault(self):
        self.post("lin1")
        for junk in (None, 12, {"a": 1}, ["x"], "\x00\x01", "E: nothing", "<script>alert(1)</script>" * 100):
            rec = self.record("lin1") or {}
            rec["pending"] = {"id": P.plan_id_of(self.queue("lin1")[0]), "at": 1, "by": "badmin"}
            api.save(api.PATCH_PREVIEWS_FILE, {"lin1": rec})
            line = api.patch_preview_ingest("lin1", self.queue("lin1")[0], junk, "not-an-int", 9)
            self.assertTrue(line.startswith("patch preview: "), junk)
            plan = self.record("lin1")["plan"]
            self.assertEqual(plan["status"], "failed", junk)
            self.assertEqual(plan["rc"], -1)
            self.assertNotIn("<script", plan["error"], junk)

    def test_the_stored_plan_is_small(self):
        self.post("lin1")
        lines = "\n".join(f"Inst package-{i} [1.0.{i}] (2.0.{i} Ubuntu:24.04/noble-security [amd64])" for i in range(2000))
        big = f"##now 1\n##manager apt\n##mode standard\n##held\n##rc 0\n##plan\n2000 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n{lines}\n##end\n"
        self.answer("lin1", big)
        self.assertLess(len(json.dumps(self.record("lin1"))), 200_000)

    def test_a_deleted_host_takes_its_plan_with_it(self):
        self.post("lin1")
        self.answer("lin1", self.GOOD)
        self.assertIsNotNone(self.record("lin1"))
        api._purge_device("lin1")
        self.assertIsNone(self.record("lin1"))


class TestThroughTheHeartbeat(unittest.TestCase):
    """The hook in handle_heartbeat, driven with the agent's own request body."""

    DEV = "d1"

    def setUp(self):
        self._saved = {k: getattr(api, k) for k in ("respond",)}
        self._env = dict(os.environ)
        self._files = {n: getattr(api, n) for n in ("PATCH_PREVIEWS_FILE",)}
        for f, empty in ((api.ALERTS_FILE, {"alerts": []}), (api.CONTAINERS_FILE, {}), (api.CONFIG_FILE, {}),
                         (api.MAINT_FILE, {"windows": []}), (api.MAINT_SUPPRESS_LOG, {"entries": []}),
                         (api.CMD_OUTPUT_FILE, {}), (api.PATCH_PREVIEWS_FILE, {}), (api.CMDS_FILE, {})):
            api.save(f, empty)
        now = int(time.time())
        api.save(api.DEVICES_FILE, {self.DEV: {"id": self.DEV, "name": "box", "hostname": "box", "token": "tok", "last_seen": now,
                                                "enrolled": now, "tags": [], "group": "", "sysinfo": {}, "monitored": True,
                                                "os": "Ubuntu 24.04"}})
        api._LOAD_CACHE.clear()

        class _Captured(SystemExit):
            def __init__(self, status, body):
                super().__init__(0)
                self.status, self.body = status, body
        self.Captured = _Captured

        def fake(status, data):
            raise _Captured(status, data)
        setattr(api, "respond", fake)

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(api, k, v)
        os.environ.clear()
        os.environ.update(self._env)
        api._LOAD_CACHE.clear()

    def beat(self, cmd, output, rc=0):
        import io
        raw = json.dumps({"device_id": self.DEV, "token": "tok", "cmd_output": {"cmd": cmd, "output": output, "rc": rc}}).encode()
        os.environ.update({"REQUEST_METHOD": "POST", "PATH_INFO": "/api/heartbeat", "QUERY_STRING": "", "CONTENT_LENGTH": str(len(raw))})
        for k in ("HTTP_X_TOKEN", "HTTP_X_RP_VAULT_KEY"):
            os.environ.pop(k, None)

        class _Stdin:
            def __init__(self, data):
                self.buffer = io.BytesIO(data)
        api.sys.stdin = _Stdin(raw)
        api._LOAD_CACHE.clear()
        try:
            api.handle_heartbeat()
        except self.Captured:
            pass
        api._LOAD_CACHE.clear()
        return (api.load(api.CMD_OUTPUT_FILE) or {}).get(self.DEV, [])

    def test_the_history_keeps_one_line_and_the_plan_lands_on_the_host(self):
        dev = api.load(api.DEVICES_FILE)[self.DEV]
        status, body = api.request_patch_preview(self.DEV, dev, "alice")
        self.assertEqual(status, 200, body)
        cmd = api.load(api.CMDS_FILE)[self.DEV][0]
        out = (FIX / "ubuntu-24.04-standard.txt").read_text()
        rows = self.beat(cmd, out)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["cmd"], "patch preview")
        self.assertEqual(rows[0]["output"], "patch preview: 2 to upgrade, 0 new, 0 removed, 2 kept back")
        self.assertNotIn("Inst lab-plain", rows[0]["output"], "the dry run's text is not kept in the shared history")
        plan = api.load(api.PATCH_PREVIEWS_FILE)[self.DEV]["plan"]
        self.assertEqual((plan["status"], plan["by"]), ("done", "alice"))
        self.assertIsNone(api.load(api.PATCH_PREVIEWS_FILE)[self.DEV]["pending"])

    def test_another_result_is_stored_as_before(self):
        rows = self.beat("exec:uptime", "up 3 days")
        self.assertEqual((rows[0]["cmd"], rows[0]["output"]), ("exec:uptime", "up 3 days"))

    def test_an_answer_for_a_request_that_is_gone_is_swallowed(self):
        rows = self.beat(P.command(PID), "whatever the host sends")
        self.assertEqual(rows[0]["cmd"], "patch preview")
        self.assertIn("dropped", rows[0]["output"])
        self.assertEqual(api.load(api.PATCH_PREVIEWS_FILE).get(self.DEV), None)


class TestWhenAnUpgradeIsParked(_PP):
    """With four-eyes on, the approver should find the plan waiting."""

    def setUp(self):
        super().setUp()
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg["change_approval_enabled"] = True
        api.save(api.CONFIG_FILE, cfg)
        api.save(api.CONFIRMATIONS_FILE, {"confirmations": []})
        api._LOAD_CACHE.clear()

    def upgrade(self, *ids, who="badmin"):
        return self.call(api.handle_upgrade_device, body={"device_ids": list(ids)}, who=who)

    def test_a_parked_upgrade_comes_with_a_preview_and_no_upgrade_is_queued(self):
        st, d = self.upgrade("lin1")
        self.assertEqual(st, 202, d)
        self.assertTrue(d["approval_required"])
        q = self.queue("lin1")
        self.assertEqual([P.plan_id_of(c) != "" for c in q], [True], q)
        self.assertNotIn("apt-get $ALT -y upgrade", q[0], "the run itself waits for the approval")
        self.assertIsNotNone((self.record("lin1") or {}).get("pending"))

    def test_a_host_that_cannot_have_one_still_parks(self):
        st, d = self.upgrade("win1")
        self.assertEqual((st, d["approval_required"]), (202, True))
        self.assertEqual(self.queue("win1"), [])
        self.assertIsNone(self.record("win1"))
        devs = api.load(api.DEVICES_FILE)
        devs["lin1"]["quarantined"] = True
        api.save(api.DEVICES_FILE, devs)
        st, d = self.upgrade("lin1")
        self.assertEqual((st, d["approval_required"]), (202, True), "parking does not depend on the preview")
        self.assertEqual(self.queue("lin1"), [])

    def test_without_four_eyes_nothing_extra_is_asked(self):
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg["change_approval_enabled"] = False
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()
        st, d = self.upgrade("lin1")
        self.assertEqual(st, 200, d)
        self.assertEqual(len([c for c in self.queue("lin1") if P.plan_id_of(c)]), 0)


# ── where it is registered ────────────────────────────────────────────────────────────────────────────────────────────
class TestRegistration(unittest.TestCase):

    def test_the_store_is_an_entity_store_with_a_shape(self):
        import storage
        import store_shapes
        self.assertIn("patch_previews.json", storage.ENTITY_FILES)
        self.assertIn("patch_previews.json", store_shapes.SHAPES)
        fixed = store_shapes.normalize("patch_previews.json", {"h1": {"pending": "x", "plan": {"status": "done"}}, "h2": 5})
        self.assertNotIn("h2", fixed)
        self.assertIsNone(fixed["h1"].get("pending"), "a request of the wrong kind is dropped, the plan is kept")
        self.assertEqual(fixed["h1"]["plan"]["status"], "done")

    def test_the_pure_module_is_in_the_lint_and_type_baselines(self):
        mk = (ROOT / "Makefile").read_text()
        self.assertEqual(mk.count("server/cgi-bin/patch_plan.py"), 2)

    def test_the_hook_and_the_parking_call_are_in_the_source(self):
        src = (ROOT / "server" / "cgi-bin" / "api.py").read_text()
        self.assertIn("patch_preview_ingest(dev_id, cmd_raw", src)
        self.assertIn("request_patch_preview(dev_id, dev, actor)", src)
        self.assertIn("PATCH_PREVIEWS_FILE,         # 7.4.9: and its upgrade plan", src)


if __name__ == "__main__":
    unittest.main()

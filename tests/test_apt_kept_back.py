#!/usr/bin/env python3
"""Discussion #30: a package apt keeps back is pending, not "Fully Patched".

The report (Debian 13, then Ubuntu 24.04): `apt-get upgrade` exits 0 and leaves a security kernel update, or the split
linux-firmware, "kept back" because installing it needs a package that is not installed yet. The agent counted the
`Inst` lines of `apt-get --simulate upgrade`, a kept-back package has none, and the host read "Fully Patched, Pending: 0"
while the CVE page listed 63 fixable findings.

Kept-back packages count as pending now, with three limits:

  * a package held with `apt-mark hold` stays out, because somebody chose that, and when the holds cannot be read
    nothing is added, since a held package would otherwise count for ever;
  * the distro's own security flag is on the `Inst` line of what would be installed, so the agent asks apt what the
    upgrade would do with new packages allowed (a simulation, nothing is installed) and counts the lines of the
    kept-back names;
  * the upgrade command itself is unchanged. It still does not install them; the count is what changes.

The "kept back" block and the summary lines in the fixtures are the ones quoted in the discussion. The `Inst` lines
follow apt's documented format, as the tests of the security counter do.
"""
import importlib.machinery
import importlib.util
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
_loader = importlib.machinery.SourceFileLoader("agent_kept_back", str(ROOT / "client" / "remotepower-agent.py"))
_spec = importlib.util.spec_from_loader("agent_kept_back", _loader)
agent = importlib.util.module_from_spec(_spec)
_loader.exec_module(agent)

DEBIAN = (
    "Reading package lists...\nBuilding dependency tree...\nReading state information...\nCalculating upgrade...\n"
    "The following packages have been kept back:\n  linux-image-amd64\n"
    "0 upgraded, 0 newly installed, 0 to remove and 1 not upgraded.\n")
WITH_NEW = (
    "The following NEW packages will be installed:\n  linux-image-6.12.107+deb13-amd64\n"
    "The following packages will be upgraded:\n  linux-image-amd64\n"
    "1 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.\n"
    "Inst linux-image-6.12.107+deb13-amd64 (6.12.107-1 Debian-Security:13/stable-security [amd64])\n"
    "Inst linux-image-amd64 [6.12.101-1] (6.12.107-1 Debian-Security:13/stable-security [amd64])\n"
    "Conf linux-image-6.12.107+deb13-amd64 (6.12.107-1 Debian-Security:13/stable-security [amd64])\n"
    "Conf linux-image-amd64 (6.12.107-1 Debian-Security:13/stable-security [amd64])\n")
CURL = "Inst curl [7.88.1-10] (7.88.1-10+deb12u8 Debian-Security:12/stable-security [amd64])\n"


class TestTheBlock(unittest.TestCase):

    def test_the_block_of_the_discussion(self):
        self.assertEqual(agent._apt_kept_back(DEBIAN), ["linux-image-amd64"])

    def test_names_wrapped_over_several_lines_are_all_read(self):
        out = ("The following packages have been kept back:\n  a b c\n  d e\n"
               "0 upgraded, 0 newly installed, 0 to remove and 5 not upgraded.\n")
        self.assertEqual(agent._apt_kept_back(out), ["a", "b", "c", "d", "e"])

    def test_only_that_block_is_read(self):
        out = ("The following packages will be upgraded:\n  curl\n"
               "The following packages have been kept back:\n  linux-firmware\n"
               "The following NEW packages will be installed:\n  linux-firmware-amd\n")
        self.assertEqual(agent._apt_kept_back(out), ["linux-firmware"])

    def test_nothing_kept_back_is_nothing(self):
        for out in ("", None, "Inst curl [1] (2 Debian:12/stable [amd64])\n",
                    "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"):
            self.assertEqual(agent._apt_kept_back(out), [], out)


class _Apt:
    """apt as a host answers it: the plain simulation, the one with new packages allowed, and apt-mark."""

    def __init__(self, plain, with_new=WITH_NEW, holds="", fail=()):
        self.plain, self.with_new, self.holds, self.fail, self.calls = plain, with_new, holds, set(fail), []

    def __call__(self, cmd, **kw):
        self.calls.append((list(cmd), kw))
        if cmd[0] == "apt-mark":
            if "mark" in self.fail:
                raise subprocess.CalledProcessError(1, cmd)
            return self.holds
        if "--with-new-pkgs" in cmd:
            if "new" in self.fail:
                raise subprocess.CalledProcessError(100, cmd)
            return self.with_new
        return self.plain


def patch_info(apt, *, container=False):
    def exists(self):
        return str(self) == "/usr/bin/apt-get"

    patches = [patch.object(agent, "get_third_party_updates", return_value={}),
               patch.object(Path, "exists", exists), patch("subprocess.check_output", apt)]
    if container:
        patches += [patch.object(agent, "IN_CONTAINER", True), patch.object(agent, "HOST_ROOT", "/host"),
                    patch.object(agent, "_host_pkglist_from_db", return_value=("apt", [])),
                    patch("shutil.which", return_value="/usr/bin/apt-get")]
    for p in patches:
        p.start()
    try:
        return agent.get_patch_info()
    finally:
        for p in reversed(patches):
            p.stop()


class TestTheCount(unittest.TestCase):

    def test_the_host_of_the_discussion_is_not_fully_patched(self):
        got = patch_info(_Apt(DEBIAN))
        self.assertEqual((got["manager"], got["upgradable"], got["upgradable_names"]), ("apt", 1, ["linux-image-amd64"]))

    def test_it_is_a_security_update_when_apt_says_the_new_package_is(self):
        self.assertEqual(patch_info(_Apt(DEBIAN))["security_updates"], 1)

    def test_it_comes_on_top_of_the_packages_apt_does_upgrade(self):
        got = patch_info(_Apt(DEBIAN.replace("The following packages have been kept back", CURL + "The following packages have been kept back", 1)))
        self.assertEqual(got["upgradable"], 2)
        self.assertEqual(got["upgradable_names"], ["curl", "linux-image-amd64"])
        self.assertEqual(got["security_updates"], 2, "curl from the first simulation, the kernel from the second")

    def test_a_held_package_stays_out(self):
        got = patch_info(_Apt(DEBIAN, holds="linux-image-amd64\nsomething-else\n"))
        self.assertEqual((got["upgradable"], got["upgradable_names"], got["security_updates"]), (0, [], 0))

    def test_when_the_holds_cannot_be_read_nothing_is_added(self):
        got = patch_info(_Apt(DEBIAN, fail=("mark",)))
        self.assertEqual((got["upgradable"], got["security_updates"]), (0, 0))

    def test_when_the_second_simulation_fails_the_package_still_counts_but_not_as_security(self):
        got = patch_info(_Apt(DEBIAN, fail=("new",)))
        self.assertEqual((got["upgradable"], got["security_updates"]), (1, 0))

    def test_a_package_the_second_simulation_does_not_mention_adds_nothing_to_security(self):
        got = patch_info(_Apt(DEBIAN, with_new="1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"))
        self.assertEqual((got["upgradable"], got["security_updates"]), (1, 0))

    def test_with_nothing_kept_back_apt_is_asked_once_and_the_count_is_what_it_was(self):
        apt = _Apt("Inst curl [1] (2 Debian:12/stable [amd64])\nInst nginx [1] (2 Debian-Security:12/stable-security [amd64])\n")
        got = patch_info(apt)
        self.assertEqual((got["upgradable"], got["upgradable_names"], got["security_updates"]), (2, ["curl", "nginx"], 1))
        self.assertEqual(len(apt.calls), 1, apt.calls)

    def test_the_messages_are_read_in_the_c_locale(self):
        """The heading is English only there; a host in another language would print it translated."""
        apt = _Apt(DEBIAN)
        patch_info(apt)
        for cmd, kw in apt.calls:
            self.assertEqual((kw.get("env") or {}).get("LC_ALL"), "C", cmd)

    def test_nothing_is_installed(self):
        apt = _Apt(DEBIAN)
        patch_info(apt)
        for cmd, _ in apt.calls:
            if cmd[0] == "apt-get":
                self.assertIn("--simulate", cmd, cmd)

    def test_the_agent_in_a_container_asks_about_the_hosts_packages(self):
        apt = _Apt(DEBIAN)
        got = patch_info(apt, container=True)
        self.assertEqual((got["upgradable"], got["security_updates"]), (1, 1))
        self.assertEqual(len(apt.calls), 4, apt.calls)     # the plain simulation, the holds, the one that ignores phasing, new packages
        for cmd, _ in apt.calls:
            self.assertIn("Dir=/host", cmd, cmd)
            self.assertIn("Dir::State::status=/host/var/lib/dpkg/status", cmd, cmd)


if __name__ == "__main__":
    unittest.main()

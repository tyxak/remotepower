"""v6.4.3: the AUR packages must track the last SHIPPED release.

They did not, and nothing noticed. aur.archlinux.org was in maintenance during
the v6.4.2 promotion, so the AUR push was deferred — and then never happened.
Checked on 2026-08-12, both packages were live at **6.4.1-1** while production
had been on v6.4.2 since 2026-08-06: every Arch user installing from the AUR was
a full release behind, with nothing anywhere reporting it.

That is the same shape as the receiver that says Running while dropping every
packet — a step that silently did not happen, reported by nobody. A deferred
step needs a gate, or the deferral becomes the state.

The gate compares the PKGBUILDs against the newest DATED entry in CHANGELOG.md,
not against SERVER_VERSION. That distinction is the whole design:

  * SERVER_VERSION is the version under development (6.4.3 while unreleased), and
    the AUR cannot carry it — `update.sh` derives its sha256 from the PUBLISHED
    release tarball, which does not exist yet. A gate on SERVER_VERSION would be
    red for the entire development cycle and would simply be switched off.
  * The newest *dated* CHANGELOG entry is the last thing actually shipped, which
    is exactly what the AUR should be serving. It goes red at the moment the
    release header flips from "unreleased (test)" to a date — the one moment the
    bump is both possible and required.

The live AUR itself is out of reach here (tests must not need network); that half
is `tools/aur-status.sh`, wired into the release checklist.
"""

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CHANGELOG = _ROOT / "CHANGELOG.md"
_PKGBUILDS = {
    "remotepower-agent": _ROOT / "packaging" / "aur" / "remotepower-agent" / "PKGBUILD",
    "remotepower-server": _ROOT / "packaging" / "aur" / "remotepower-server" / "PKGBUILD",
}

# "## v6.4.2 — "Ver1tyMatters" — 2026-08-06"  ->  released
# "## v6.4.3 — "Gu4rdMatters" — unreleased (test)"  ->  not yet
_HEADER = re.compile(r"^## v(\d+\.\d+\.\d+)\b(.*)$", re.M)


def _last_released_version():
    """The newest CHANGELOG entry that carries a real date."""
    if not _CHANGELOG.exists():
        return None
    for m in _HEADER.finditer(_CHANGELOG.read_text(encoding="utf-8")):
        rest = m.group(2)
        if "unreleased" in rest.lower():
            continue
        if "no standalone release" in rest.lower() or "folded into" in rest.lower():
            continue
        if re.search(r"\d{4}-\d{2}-\d{2}", rest):
            return m.group(1)
    return None


def _pkgver(path):
    m = re.search(r"^pkgver=(\S+)", path.read_text(encoding="utf-8"), re.M)
    return m.group(1) if m else None


class TestTheGateCanSeeWhatItIsMeasuring(unittest.TestCase):
    """Positive controls. Both parsers read live files through formats that
    have changed before; if either silently returns None the version assertions
    below would pass over nothing."""

    def setUp(self):
        if not _CHANGELOG.exists():
            self.skipTest("CHANGELOG.md excluded from this tree")

    def test_a_released_version_is_found(self):
        v = _last_released_version()
        self.assertIsNotNone(
            v,
            "no dated CHANGELOG entry parsed — the header format changed and "
            "this gate is now blind",
        )
        self.assertRegex(v, r"^\d+\.\d+\.\d+$")

    def test_the_in_development_version_is_not_mistaken_for_released(self):
        """The whole design rests on 'unreleased (test)' being excluded."""
        text = _CHANGELOG.read_text(encoding="utf-8")
        first = _HEADER.search(text)
        self.assertIsNotNone(first)
        if "unreleased" in first.group(2).lower():
            self.assertNotEqual(
                first.group(1),
                _last_released_version(),
                "an unreleased version is being reported as shipped",
            )

    def test_every_pkgbuild_declares_a_version(self):
        for name, path in _PKGBUILDS.items():
            if not path.exists():
                self.skipTest("packaging/ excluded from this tree")
            self.assertIsNotNone(_pkgver(path), f"{name}: no pkgver= line found")


class TestTheAurPackagesTrackTheLastRelease(unittest.TestCase):
    def setUp(self):
        if not _CHANGELOG.exists() or not all(p.exists() for p in _PKGBUILDS.values()):
            self.skipTest("excluded from this tree")
        self.released = _last_released_version()

    def test_each_package_is_on_the_last_released_version(self):
        for name, path in _PKGBUILDS.items():
            with self.subTest(package=name):
                self.assertEqual(
                    self.released,
                    _pkgver(path),
                    f"{name} is at {_pkgver(path)} but the last SHIPPED release "
                    f"is {self.released}. Run packaging/aur/{name}/update.sh "
                    f"{self.released} and push to the AUR — a deferred AUR push "
                    "is how both packages ended up a full release behind after "
                    "the v6.4.2 outage.",
                )

    def test_both_packages_agree_with_each_other(self):
        vers = {n: _pkgver(p) for n, p in _PKGBUILDS.items()}
        self.assertEqual(
            1,
            len(set(vers.values())),
            f"the two AUR packages are on different versions: {vers}",
        )


class TestTheReleaseChecklistCarriesTheLiveCheck(unittest.TestCase):
    """The source tree can only prove the PKGBUILD is right. Whether the AUR
    actually SERVES it needs a network query, which is what let the v6.4.2 push
    vanish — the tree looked correct the whole time."""

    def test_the_status_tool_exists_and_is_executable(self):
        t = _ROOT / "tools" / "aur-status.sh"
        if not t.exists():
            self.fail(
                "tools/aur-status.sh is missing — nothing compares the LIVE AUR "
                "against this repo, which is exactly how 6.4.2 was never pushed"
            )
        self.assertTrue(t.stat().st_mode & 0o111, "tools/aur-status.sh is not executable")

    def test_the_promotion_checklist_mentions_it(self):
        notes = _ROOT / "CLAUDE.md"
        if not notes.exists():
            self.skipTest("CLAUDE.md excluded from this tree")
        self.assertIn(
            "aur-status.sh",
            notes.read_text(encoding="utf-8"),
            "the live-AUR check is not in the promotion checklist, so it will "
            "be skipped exactly when it matters",
        )


if __name__ == "__main__":
    unittest.main()

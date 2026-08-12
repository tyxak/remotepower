"""v6.4.3: the sidebar has a declared order, and a new page cannot land at random.

Reported from use: *"things are put in randomly when new features are added"*.
Measured, that was exactly right — of 12 sidebar groups, ONE (`security`) was in
alphabetical order and one had a single item. Every other group was in the order
features happened to ship in, which is to say no order at all. Someone
alphabetised `security` at some point and nothing held the line, so the drift
resumed everywhere else.

**Why not sub-menus.** The obvious-looking fix is a third level of nesting, and
it is the wrong one. The rail is 248px and is already a one-group-open-at-a-time
accordion; a third level adds a click to reach every leaf, is awkward on touch,
and — decisively — does not address the problem. Random placement is a DECISION
problem, not a DEPTH problem. More nesting just creates more places to put
something arbitrarily. What stops the drift is a rule a machine can check.

**The rule.** Alphabetical within each group, with exactly three declared
escapes, because a few positions really do carry meaning:

  * ``_PIN_FIRST`` — an entry point that must lead its group (Needs Attention is
    where triage starts; alphabetising it into the middle would be a regression
    dressed up as consistency).
  * ``_PIN_LAST``  — trailing conventions (About).
  * ``_SEQUENCE``  — a whole group whose order encodes a workflow, listed
    explicitly with the sequence written out.

The escapes are the point as much as the rule is: an exception here is a visible
decision with a reason next to it, which is the opposite of what was happening.
Anything not listed must be alphabetical, so a new page has exactly one correct
position and the build says so when it is not there.
"""

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_HTML = _ROOT / "server" / "html" / "index.html"

# An entry point that must lead its group.
_PIN_FIRST = {
    # Triage starts here — this is the page an operator opens when something is
    # wrong, and burying it under "Checks"/"Forecast" for alphabetical purity
    # would make the sidebar tidier and the product worse.
    "monitoring": ["Needs Attention"],
}

# Trailing conventions.
_PIN_LAST = {
    # "About" last is near-universal convention; Documentation reads naturally
    # beside it.
    "admin": ["Documentation", "About"],
}

# Whole groups whose order encodes a sequence rather than a name.
_SEQUENCE = {
    # The patch lifecycle, in the order an operator moves through it: see what
    # is outstanding, decide what applies automatically, stage the rest.
    "patching": ["Patches", "Auto-patch", "Rollouts"],
}


def _groups():
    """{group: [visible label, ...]} in document order."""
    html = _HTML.read_text(encoding="utf-8")
    out = {}
    for gm in re.finditer(
        r'<div class="sidebar-group" data-group="([a-z0-9-]+)">(.*?)\n    </div>',
        html,
        re.S,
    ):
        labels = []
        for _page, inner in re.findall(
            r'<button class="nav-btn"[^>]*data-page="([a-z0-9-]+)"[^>]*>(.*?)</button>',
            gm.group(2),
            re.S,
        ):
            text = " ".join(re.sub(r"<[^>]+>", "", inner).split())
            # Strip a trailing count badge ("Confirmations 0").
            text = re.sub(r"\s+\d+$", "", text).strip()
            if text:
                labels.append(text)
        out[gm.group(1)] = labels
    return out


def _expected(group, labels):
    """The one correct order for this group, given the declared escapes."""
    if group in _SEQUENCE:
        return list(_SEQUENCE[group])
    first = [x for x in _PIN_FIRST.get(group, []) if x in labels]
    last = [x for x in _PIN_LAST.get(group, []) if x in labels]
    middle = sorted(
        (x for x in labels if x not in first and x not in last),
        key=lambda s: s.lower(),
    )
    return first + middle + last


# ── Settings → the same rule, the same reason ──────────────────────────────
# Settings is a second surface with the same drift: all four of its tab groups
# were in ship order. Same escapes apply; none is currently needed, which is
# itself worth noting — nothing in Settings has a position that carries meaning.
_SETTINGS_PIN_FIRST: dict[str, list[str]] = {}
_SETTINGS_PIN_LAST: dict[str, list[str]] = {}


def _settings_groups():
    """{group label: [tab label, ...]} in document order."""
    html = _HTML.read_text(encoding="utf-8")
    i = html.index('<div class="settings-tabs"')
    seg = html[i : html.index("\n        </div>", i)]
    out = {}
    for gm in re.finditer(
        r'<div class="settings-tab-group"[^>]*>(.*?)\n          </div>', seg, re.S
    ):
        body = gm.group(1)
        lbl = re.search(r'settings-tab-group-label"[^>]*>([^<]*)<', body)
        tabs = re.findall(r'data-tab="[a-z0-9-]+"[^>]*?tabindex="[^"]*">([^<]*)</button>', body)
        out[(lbl.group(1) if lbl else "?").strip()] = [t.strip() for t in tabs]
    return out


def _settings_expected(group, labels):
    first = [x for x in _SETTINGS_PIN_FIRST.get(group, []) if x in labels]
    last = [x for x in _SETTINGS_PIN_LAST.get(group, []) if x in labels]
    middle = sorted(
        (x for x in labels if x not in first and x not in last), key=lambda s: s.lower()
    )
    return first + middle + last


class TestSettingsTabsAreOrderedToo(unittest.TestCase):
    def setUp(self):
        if not _HTML.exists():
            self.skipTest("index.html excluded from this tree")
        self.groups = _settings_groups()

    def test_the_extraction_finds_the_groups(self):
        """Positive control."""
        self.assertGreaterEqual(len(self.groups), 4, f"parsed {self.groups!r}")
        for name, tabs in self.groups.items():
            self.assertTrue(tabs, f"settings group {name!r} parsed with no tabs")

    def test_each_settings_group_is_alphabetical(self):
        for group, labels in self.groups.items():
            with self.subTest(group=group):
                self.assertEqual(
                    _settings_expected(group, labels),
                    labels,
                    f"Settings group {group!r} is not alphabetical. Same rule as "
                    "the sidebar: a new pane has exactly one correct position.",
                )


class TestTheExtractionWorks(unittest.TestCase):
    """Positive controls. This reads live markup with a regex; if the markup
    shifts, every ordering assertion below would pass over an empty list."""

    def setUp(self):
        if not _HTML.exists():
            self.skipTest("index.html excluded from this tree")

    def test_groups_are_found(self):
        g = _groups()
        self.assertGreaterEqual(len(g), 10, f"only parsed {len(g)} sidebar groups")

    def test_groups_have_items(self):
        for name, labels in _groups().items():
            self.assertTrue(labels, f"group {name!r} parsed with no nav items")

    def test_a_known_label_is_present(self):
        self.assertIn("Needs Attention", _groups().get("monitoring", []))


class TestEveryGroupIsInItsDeclaredOrder(unittest.TestCase):
    def setUp(self):
        if not _HTML.exists():
            self.skipTest("index.html excluded from this tree")
        self.groups = _groups()

    def test_each_group_matches(self):
        for group, labels in self.groups.items():
            with self.subTest(group=group):
                self.assertEqual(
                    _expected(group, labels),
                    labels,
                    f"sidebar group {group!r} is not in its declared order. "
                    "Alphabetical within the group unless the item is listed in "
                    "_PIN_FIRST / _PIN_LAST / _SEQUENCE in this file — and if a "
                    "new page genuinely needs a fixed position, add it there "
                    "WITH the reason rather than placing it by hand.",
                )

    def test_no_duplicate_labels_within_a_group(self):
        for group, labels in self.groups.items():
            with self.subTest(group=group):
                self.assertEqual(len(labels), len(set(labels)), f"{group}: {labels}")


class TestTheEscapeHatchesAreHonest(unittest.TestCase):
    """An escape list that names things which no longer exist is how a rule
    quietly stops applying."""

    def setUp(self):
        if not _HTML.exists():
            self.skipTest("index.html excluded from this tree")
        self.groups = _groups()

    def test_every_declared_group_exists(self):
        for src, name in (
            (_PIN_FIRST, "_PIN_FIRST"),
            (_PIN_LAST, "_PIN_LAST"),
            (_SEQUENCE, "_SEQUENCE"),
        ):
            for group in src:
                self.assertIn(group, self.groups, f"{name} names unknown group {group!r}")

    def test_every_declared_label_exists(self):
        for src, name in (
            (_PIN_FIRST, "_PIN_FIRST"),
            (_PIN_LAST, "_PIN_LAST"),
            (_SEQUENCE, "_SEQUENCE"),
        ):
            for group, labels in src.items():
                for label in labels:
                    self.assertIn(
                        label,
                        self.groups.get(group, []),
                        f"{name}[{group!r}] pins {label!r}, which is no longer "
                        "in that group — the exception is stale",
                    )

    def test_a_sequence_group_is_declared_completely(self):
        """A partial sequence would silently drop whatever it omits."""
        for group, seq in _SEQUENCE.items():
            self.assertEqual(
                sorted(seq),
                sorted(self.groups.get(group, [])),
                f"_SEQUENCE[{group!r}] does not list every item in the group",
            )


if __name__ == "__main__":
    unittest.main()

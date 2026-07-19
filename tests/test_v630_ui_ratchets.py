"""v6.3.0 (wave 13): UI ratchets for the two rules CLAUDE.md says keep
shipping broken and getting patched in follow-ups:

1. Every table with an id'd <thead> must wire sorting (wireSortOnly or a
   tableCtl register sortHeaders) — sort regressions shipped repeatedly
   (Custom Scripts results, Log Alert global rules, Processes).
2. No NEW uncapped <table> in static index.html — every variable-row table
   belongs in a scrollable-table-wrap / table-card / scroll-cap container
   (the box-overflow rule). Existing violations are baselined; the count
   may only go DOWN.
"""

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_HTML = _ROOT / "server/html/index.html"
_JSDIR = _ROOT / "server/html/static/js"

# Dynamic-column tables where per-column sort prefs genuinely don't apply.
ALLOW_UNSORTED = {
    "qe-results-thead",   # query explorer: result columns vary per query
}

# Static tables that predate the ratchet (fixed-size settings/about tables).
# Lower this number when one gets capped; NEVER raise it.
UNCAPPED_STATIC_BASELINE = 4

_CAP_MARKERS = re.compile(
    r"scrollable-table-wrap|table-card|audit-scroll|scroll-cap|devices-minimal-wrap")


def _all_src():
    return _HTML.read_text() + "".join(
        p.read_text() for p in sorted(_JSDIR.glob("*.js")))


class TestSortWiringRatchet(unittest.TestCase):
    def test_every_thead_is_sort_wired(self):
        src = _all_src()
        theads = set(re.findall(r'<thead[^>]*\bid="([a-zA-Z0-9_-]+)"', src))
        wired = set(re.findall(r"wireSortOnly\(\s*'([a-zA-Z0-9_-]+)'", src))
        wired |= set(re.findall(r"sortHeaders:\s*'([a-zA-Z0-9_-]+)'", src))
        unwired = sorted(theads - wired - ALLOW_UNSORTED)
        self.assertEqual(unwired, [],
                         f"tables with an id'd thead but no sort wiring: {unwired} — "
                         "wire tableCtl.wireSortOnly/sortHeaders or add to ALLOW_UNSORTED "
                         "with a reason")

    def test_allowlist_entries_still_exist(self):
        src = _all_src()
        for tid in ALLOW_UNSORTED:
            self.assertIn(tid, src, f"stale ALLOW_UNSORTED entry: {tid}")


class TestBoxOverflowRatchet(unittest.TestCase):
    def test_no_new_uncapped_static_tables(self):
        html = _HTML.read_text()
        viol = []
        for m in re.finditer(r"<table[^>]*>", html):
            back = html[max(0, m.start() - 600):m.start()]
            if not _CAP_MARKERS.search(back):
                viol.append(m.group(0)[:60])
        self.assertLessEqual(
            len(viol), UNCAPPED_STATIC_BASELINE,
            f"NEW uncapped <table> in index.html (cap it in a scrollable-table-wrap "
            f"or table-card): {viol}")


if __name__ == "__main__":
    unittest.main()

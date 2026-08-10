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
# 4 -> 3 (v6.4.3): one of the four was never uncapped. #event-toggle-table sits
# directly inside <div class="sticky-head-scroll">, which IS a real cap
# (max-height: 460px; overflow: auto) — it just was not in the marker list, so
# the ratchet counted a compliant table against the budget. A false positive in
# a shrink-only baseline is worse than noise: it consumes headroom, so a
# genuinely uncapped table can be added later without tripping anything.
UNCAPPED_STATIC_BASELINE = 3

_CAP_MARKERS = re.compile(
    r"scrollable-table-wrap|table-card|audit-scroll|scroll-cap|devices-minimal-wrap"
    r"|sticky-head-scroll")

# v6.4.3: the ratchet above reads ONLY index.html, so the 146 tables built in
# JS template literals had no structural guard at all — and that is where the
# variable-row tables actually live (a static table in this app is usually a
# fixed settings/about grid). Same rule, applied to the place it matters more.
# 30 is the measured current state, not a target: 25 of them are fixed
# key/value tables in app-self.js and report.js, which is why this is a ceiling
# rather than an assertEqual(0).
UNCAPPED_JS_BASELINE = 30


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
        # Shrink-only in the other direction too: a baseline left above the
        # real count silently stops nudging.
        self.assertGreaterEqual(
            UNCAPPED_STATIC_BASELINE, len(viol))
        self.assertLessEqual(
            UNCAPPED_STATIC_BASELINE - len(viol), 1,
            f"baseline ({UNCAPPED_STATIC_BASELINE}) is above the real count "
            f"({len(viol)}) — a table was capped; lower it to {len(viol)}")

    def test_no_new_uncapped_js_built_tables(self):
        """The rule is 'every box with a variable row count caps and scrolls',
        and JS template literals are where the variable-row tables are. The
        invoice line-items table was the lone bare one of six in
        app-billing.js — its own file's majority set the target."""
        viol = []
        for path in sorted(_JSDIR.glob("*.js")):
            src = path.read_text()
            for m in re.finditer(r"<table\b", src):
                if not _CAP_MARKERS.search(src[max(0, m.start() - 400):m.start()]):
                    viol.append(f"{path.name}:{src.count(chr(10), 0, m.start()) + 1}")
        self.assertLessEqual(
            len(viol), UNCAPPED_JS_BASELINE,
            f"NEW uncapped <table> built in JS — wrap it in "
            f"<div class=\"scrollable-table-wrap audit-scroll\">: {viol}")
        self.assertLessEqual(
            UNCAPPED_JS_BASELINE - len(viol), 2,
            f"baseline ({UNCAPPED_JS_BASELINE}) is above the real count "
            f"({len(viol)}) — lower it to {len(viol)}")


if __name__ == "__main__":
    unittest.main()

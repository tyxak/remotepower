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
    # v7.0.0: `md-table-wrap` is the markdown renderer's table container. It
    # scrolls HORIZONTALLY and deliberately does not cap height, which is the
    # same judgement the rendered box-overflow sweep already records for
    # `docs-container`: "the Documentation page IS a document — it scrolls at
    # page level, like every other long-form page". A reference table inside a
    # scrolling modal that ALSO capped its own height would put the reader in a
    # box inside a box, and features.md is 29 tables long.
    r"|md-table-wrap"
    r"|sticky-head-scroll")

# v6.4.3: the ratchet above reads ONLY index.html, so the 146 tables built in
# JS template literals had no structural guard at all — and that is where the
# variable-row tables actually live (a static table in this app is usually a
# fixed settings/about grid). Same rule, applied to the place it matters more.
# 29 is the measured current state, not a target: 24 of them are fixed
# key/value tables in app-self.js and report.js, which is why this is a ceiling
# rather than an assertEqual(0).
# 30 -> 29 (v7.0.2): one of the thirty was a `<table>` written in a COMMENT
# (app-self.js:973, the note recording that a bare table was capped). See
# _js_srcs() — the ratchet used to read raw source.
UNCAPPED_JS_BASELINE = 29


def _blank_js_comments(src):
    """Replace JS comment bodies with spaces, preserving every offset.

    A stack, not a flag: a template literal's ${...} is CODE, which can hold
    another string, which can hold a backtick. A single-state scanner desyncs
    on the first `${name}` inside a quoted attribute and then reads live code
    as string for thousands of lines.
    """
    out = list(src)
    n = len(src)
    stack = ['code']
    i = 0
    while i < n:
        c = src[i]
        top = stack[-1]
        if top in ("'", '"'):
            if c == '\\':
                i += 2
                continue
            if c == top or c == '\n':
                stack.pop()
            i += 1
            continue
        if top == '`':
            if c == '\\':
                i += 2
                continue
            if c == '`':
                stack.pop()
                i += 1
                continue
            if c == '$' and i + 1 < n and src[i + 1] == '{':
                stack.append('expr')
                i += 2
                continue
            i += 1
            continue
        # code / expr
        if c == '}' and top == 'expr':
            stack.pop()
            i += 1
            continue
        if c in '\'"`':
            stack.append(c)
            i += 1
            continue
        if c == '/' and i + 1 < n and src[i + 1] == '/':
            j = src.find('\n', i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = ' '
            i = j
            continue
        if c == '/' and i + 1 < n and src[i + 1] == '*':
            j = src.find('*/', i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != '\n':
                    out[k] = ' '
            i = j
            continue
        i += 1
    return ''.join(out)


def _blank_html_comments(src):
    """<!-- … --> blanked, offsets preserved."""
    return re.sub(r"<!--.*?-->",
                  lambda m: re.sub(r"[^\n]", " ", m.group(0)), src, flags=re.S)


def _html_src():
    return _blank_html_comments(_HTML.read_text())


def _js_srcs():
    """Every client module with its comment bodies blanked.

    The ratchet read RAW source, so `<table>` written inside a comment counted
    as a table: `// The wrap lives on the .table-card around the <table>.`
    (app.js:709) and `// v6.4.1: was a bare <table> with no cap`
    (app-self.js:973). Both happened to land on the capped side of the
    proximity check, so the only visible effect was an inflated population —
    but a future comment mentioning a table with no marker nearby would eat one
    of the baseline's slots, and a shrink-only baseline spent on a comment is
    headroom a real uncapped table can then hide in.

    Blanking rather than deleting keeps every offset, so the reported line
    numbers still point at the source.
    """
    return {p.name: _blank_js_comments(p.read_text())
            for p in sorted(_JSDIR.glob("*.js"))}


def _all_src():
    return _html_src() + "".join(_js_srcs().values())


class TestTheCommentBlankerWorks(unittest.TestCase):
    """The blanker is the instrument. A broken one shrinks the population and
    every ceiling below passes for the wrong reason, so it gets its own
    controls in both directions."""

    def test_it_blanks_a_table_written_in_a_comment(self):
        src = "const a = 1;\n// note: was a bare <table> with no cap\n"
        self.assertNotIn('<table', _blank_js_comments(src))

    def test_it_blanks_a_block_comment_and_keeps_offsets(self):
        src = "x;/* <table> */y;\n"
        out = _blank_js_comments(src)
        self.assertEqual(len(out), len(src))
        self.assertNotIn('<table', out)
        self.assertTrue(out.startswith('x;') and out.rstrip().endswith('y;'))

    def test_it_does_not_eat_a_table_inside_a_template_literal(self):
        """Negative control, and the exact case the first scanner failed: a
        `${…}` inside a quoted attribute made it read live code as string for
        thousands of lines, so a real table stopped being counted."""
        src = ('const h = `<div data-x="${name}|${col}">`;\n'
               'const t = `<table class="x"><tbody></tbody></table>`;\n')
        self.assertIn('<table', _blank_js_comments(src))

    def test_it_does_not_eat_a_url_in_a_string(self):
        src = "const u = 'https://example.test/a'; const t = `<table>`;\n"
        self.assertIn('<table', _blank_js_comments(src))

    def test_it_actually_removes_something_from_the_real_tree(self):
        """A blanker that returned its input unchanged would pass every case
        above that asserts presence."""
        raw = sum(src.count('<table')
                  for src in (p.read_text() for p in sorted(_JSDIR.glob('*.js'))))
        blanked = sum(src.count('<table') for src in _js_srcs().values())
        self.assertLess(blanked, raw,
                        'the blanker removed nothing — the two known comment '
                        'tables (app.js:709, app-self.js:973) should go')


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
        html = _html_src()
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
        seen = 0
        for name, src in _js_srcs().items():
            for m in re.finditer(r"<table\b", src):
                seen += 1
                if not _CAP_MARKERS.search(src[max(0, m.start() - 400):m.start()]):
                    viol.append(f"{name}:{src.count(chr(10), 0, m.start()) + 1}")
        # Non-emptiness control: the comment blanker is a hand-written scanner,
        # and one that desynced (a `${…}` inside a quoted attribute is exactly
        # how the first version did) would blank live code and shrink this to
        # nothing while the ceiling below still passed.
        self.assertGreater(seen, 100,
                           "only %d JS-built tables found — the extractor is "
                           "broken, not the markup" % seen)
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

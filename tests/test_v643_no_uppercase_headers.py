#!/usr/bin/env python3
"""No header-role class may be an uppercase eyebrow.

styles.css already says this, at the v6.4.1 note that removed
`.drawer-section-title`: *"it was the last live survivor of the retired
industrial skin … Do not reintroduce uppercase eyebrow headers."*

It was not the last one. Two more were live when this was written —
`.kb-cat-head` (the KB category header, `app-kb.js`) and
`.cmdb-iface-tree-title` (the CMDB "Preview" panel, `app-cmdb.js`) — plus
`.status-h2`, which had no users at all. The note removed one RULE; nothing
stopped the SHAPE, so "do not reintroduce" was advice with no enforcement behind
it, which is the same thing as no rule.

WHY THIS IS A RATCHET AND NOT A BAN. `text-transform: uppercase` is legal and
correct on badges, pills, `th` cells and stat labels — 53 of the 56 uppercase
rules in the stylesheet are exactly that, and the v6 design wants them. Only
HEADER-role selectors are in scope, identified by name (`-head`, `-title`,
`-h2`, `-heading`). That is a heuristic, so it is a shrink-only ceiling rather
than a hard zero: it cannot be raised without someone deciding to, and it can
only go down.
"""
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CSS_DIR = _ROOT / 'server' / 'html' / 'static' / 'css'
_VENDORED = {'swagger.css'}

# Shrink-only. Currently ZERO — every header-role uppercase rule has been
# folded onto the .section-title values (13px/620, no transform, no tracking).
# Raising this needs a reason in the commit message, not just a passing build.
UPPERCASE_HEADER_CEILING = 0

_HEADER_NAME = re.compile(r'\.[a-z0-9-]*(?:head|title|h2|heading)[a-z0-9-]*\b', re.I)


def _uppercase_header_rules():
    """(file, selector) for every rule whose selector looks like a header and
    whose body sets text-transform: uppercase."""
    out = []
    for f in sorted(_CSS_DIR.glob('*.css')):
        if f.name in _VENDORED:
            continue
        css = re.sub(r'/\*.*?\*/', '', f.read_text(), flags=re.S)
        for m in re.finditer(r'([^{}]+)\{([^{}]*)\}', css):
            sel, body = m.group(1).strip(), m.group(2)
            if 'text-transform' not in body:
                continue
            if not re.search(r'text-transform:\s*uppercase', body):
                continue
            if _HEADER_NAME.search(sel):
                out.append((f.name, ' '.join(sel.split())[:70]))
    return out


class TestTheScanWorks(unittest.TestCase):
    """Positive controls — the assertion below is 'nothing found', which is what
    a broken parse produces too."""

    def test_it_finds_uppercase_rules_at_all(self):
        """There ARE uppercase rules in this stylesheet — on badges and th, all
        legitimate. If the scan sees none, its selector matching is broken and
        the header check below proves nothing."""
        css = (_CSS_DIR / 'styles.css').read_text()
        self.assertGreater(len(re.findall(r'text-transform:\s*uppercase', css)), 20,
                           'no uppercase rules found at all — parse is broken')

    def test_it_would_flag_a_header_shaped_rule(self):
        self.assertRegex('.foo-title', _HEADER_NAME)
        self.assertRegex('.kb-cat-head', _HEADER_NAME)
        self.assertRegex('.status-h2', _HEADER_NAME)

    def test_it_does_not_flag_a_badge(self):
        """The rule must not fire on the 53 legitimate uses."""
        self.assertNotRegex('.badge-crit', _HEADER_NAME)
        self.assertNotRegex('.pill', _HEADER_NAME)
        self.assertNotRegex('.stat-label', _HEADER_NAME)


class TestNoUppercaseEyebrowHeaders(unittest.TestCase):

    def test_count_is_at_or_under_the_ceiling(self):
        found = _uppercase_header_rules()
        self.assertLessEqual(
            len(found), UPPERCASE_HEADER_CEILING,
            'header-role selectors styled as uppercase eyebrows — the retired '
            'industrial idiom styles.css explicitly says not to reintroduce. '
            'Fold onto .section-title (13px/620, no transform, no tracking):\n'
            + '\n'.join(f'  {f}: {s}' for f, s in found))

    def test_the_ceiling_has_not_been_left_above_the_real_count(self):
        """Shrink-only: if the real count drops, the ceiling must follow, or it
        silently buys room for the next one."""
        found = _uppercase_header_rules()
        self.assertEqual(
            UPPERCASE_HEADER_CEILING, len(found),
            f'ceiling is {UPPERCASE_HEADER_CEILING} but the real count is '
            f'{len(found)} — lower it to match')

    def test_the_retirement_note_is_still_there(self):
        """The prose that states the rule. If someone deletes it, the next
        reader has no idea why these selectors look the way they do.

        Whitespace-normalised because the comment WRAPS ("Do not\n   reintroduce"),
        and asserted with a short message rather than the default — the naive
        version dumped the entire 400KB stylesheet into the failure output.
        """
        css = (_CSS_DIR / 'styles.css').read_text()
        flat = ' '.join(css.split())
        self.assertTrue(
            'Do not reintroduce uppercase eyebrow headers' in flat,
            'the v6.4.1 retirement note is gone from styles.css — it is the '
            'only place the rule is written down')


if __name__ == '__main__':
    unittest.main()

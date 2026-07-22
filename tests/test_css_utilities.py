"""A presentational class that does not exist in the stylesheet is a SILENT bug.

Python fails loudly on an undefined name. CSS does not: an element with
`class="card"` where no `.card` rule exists renders as an unstyled box, and
nothing anywhere reports it. That shipped twice in one release cycle — the
Security Advisory cards used `.card` (the house class is `.dash-card`) and came
out transparent, and a "no findings" panel used `.ta-left` when only
`.ta-center` / `.ta-right` were ever defined.

This guards the classes where absence is *guaranteed* to be a bug: pure
utilities and card containers, which exist only to apply styling. It
deliberately does NOT check every class — hundreds are JS hook selectors
(`bc-chk`, `alerts-row-cb`, `docker-prune-cb`) that are queried by script and
never styled, so requiring a rule for those would be wrong.
"""

import re
import unittest
from pathlib import Path

_HTML = Path(__file__).resolve().parent.parent / 'server' / 'html'
_STYLES = _HTML / 'static' / 'css' / 'styles.css'

# Prefixes whose whole purpose is visual. If one of these has no rule, the
# author meant something to happen and nothing did.
_UTILITY_PREFIXES = (
    'ta-', 'mt-', 'mb-', 'ml-', 'mr-', 'fs-', 'd-', 'flex-', 'mono-', 'fw-',
    'c-', 'w-', 'h-', 'gap-', 'p-', 'px-', 'py-', 'scroll-cap',
)
# Container idioms: a panel must use a real one or it renders with no surface,
# no border and no padding — the exact "transparent background" bug.
_CONTAINERS = ('card', 'dash-card')


def _defined_classes():
    # styles.css only: report.css / status.css / portal.css style standalone
    # pages that do NOT load styles.css (report.js legitimately uses its own
    # `.card`), so mixing them would hide a real miss in the main app.
    return set(re.findall(r'\.([A-Za-z][A-Za-z0-9_-]*)',
                          _STYLES.read_text(encoding='utf-8')))


def _sources():
    yield _HTML / 'index.html'
    yield from sorted((_HTML / 'static' / 'js').glob('app*.js'))


# `${…}` inside a class attribute is a runtime value. Blanking it to a sentinel
# (rather than dropping the whole attribute) keeps the STATIC tokens around it
# checkable, which is most of what the JS renderers emit —
# `class="dash-card adv-sev-${x}"` still proves `dash-card` is used. Any token
# that touched the expression carries the sentinel and is discarded, so a
# fragment like `adv-sev-` is never reported as a missing class.
_SENTINEL = '\x00'


def _used_classes():
    """{class: {file, …}} for every class token in the app surface.

    Covers interpolated attributes too. An earlier version matched only
    `class="([^"$]*)"`, which skipped every templated attribute — so the very
    bug this file was written for (`class="card adv-card ..."`) sailed past it.
    """
    out = {}
    for f in _sources():
        txt = f.read_text(encoding='utf-8')
        for attr in re.findall(r'class="([^"<>]*)"', txt):
            cleaned = re.sub(r'\$\{[^}]*\}', _SENTINEL, attr)
            for cls in cleaned.split():
                if cls and _SENTINEL not in cls:
                    out.setdefault(cls, set()).add(f.name)
    return out


class TestPresentationalClassesExist(unittest.TestCase):
    def setUp(self):
        self.defined = _defined_classes()
        self.used = _used_classes()

    def test_the_extractor_actually_finds_things(self):
        """A guardrail that silently matches nothing passes forever."""
        self.assertGreater(len(self.defined), 500)
        self.assertGreater(len(self.used), 500)
        self.assertIn('dash-card', self.defined)
        self.assertIn('dash-card', self.used)

    def test_every_utility_class_has_a_rule(self):
        missing = sorted(
            f'{c}  (used in {", ".join(sorted(self.used[c]))})'
            for c in self.used
            if any(c.startswith(p) for p in _UTILITY_PREFIXES) and c not in self.defined)
        self.assertEqual(missing, [], 'utility classes with NO rule in styles.css '
                                      '— they render as nothing:\n  '
                                      + '\n  '.join(missing))

    def test_every_card_container_has_a_rule(self):
        missing = sorted(
            f'{c}  (used in {", ".join(sorted(self.used[c]))})'
            for c in _CONTAINERS if c in self.used and c not in self.defined)
        self.assertEqual(missing, [],
                         'card container with no rule — the panel renders with no '
                         'surface, border or padding (transparent background):\n  '
                         + '\n  '.join(missing))

    def test_card_has_no_base_rule_so_it_must_not_be_used(self):
        """`.card` has a real base rule only in report.css, for the standalone
        report page, which does not load styles.css. styles.css mentions it once
        (`body.density-compact .card` — a padding override), so the TOKEN is
        present while the surface/border/padding baseline is not. Using it in
        the app therefore renders a transparent, border-less box: the exact bug
        this file exists to prevent."""
        css = _STYLES.read_text(encoding='utf-8')
        base = re.search(r'(^|[},/*\s])\.card\s*(,\s*\.[\w-]+\s*)*\{', css, re.M)
        self.assertIsNone(
            base, 'styles.css now has a base .card rule — if that is deliberate, '
                  'delete this test; otherwise it is a typo for .dash-card')
        where = sorted(self.used.get('card', ()))
        self.assertEqual(where, [], f'.card used in {where} — the app card '
                                    'container is .dash-card')

    def test_the_specific_regressions_stay_fixed(self):
        for c in ('ta-left', 'ta-center', 'ta-right', 'c-success', 'c-warning',
                  'flex-wrap', 'mt-0', 'mb-0', 'p-6'):
            self.assertIn(c, self.defined, f'.{c} lost its rule')


if __name__ == '__main__':
    unittest.main()

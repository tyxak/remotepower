#!/usr/bin/env python3
"""One role, one size.

`test_v430_typography.py` holds every font size on the design's scale. That is
the right rule and it is not the whole rule: 12px, 12.5px and 13px are all on
the scale, so two elements playing the same part can sit at different sizes and
the gate stays green. The design assigns a size per ROLE — 13px for a section
heading, 12px for a hint, 11px for a table header — and what drifts is the
assignment, not the scale.

Two selectors named `hint` rendered at 11px against the ten that render at 12px:
the device hovercard's and the timeline's zoom affordance. Both are short
strings in tight chrome, which is how they got there, and neither is different
enough from a hint to be a different size.

Only roles whose CSS class NAMES them are checked, and only where the name is
unambiguous. A rule keyed on a guess about what a selector means would argue
with every honest change, and a gate that argues gets switched off.
"""
import re
import unittest
from pathlib import Path

_CSS_DIR = (Path(__file__).resolve().parent.parent / 'server' / 'html'
            / 'static' / 'css')
_VENDORED = {'swagger.css'}

# role token -> (the one size it renders at, why)
ROLE_SIZES = {
    'hint': (12.0, 'secondary explanatory text under a control or heading'),
    'section-title': (13.0, 'the card and section heading, per the v6 scale'),
    'page-title': (19.0, 'the page heading, per the v6 scale'),
}

# Selectors that carry a role token and are legitimately a different size, keyed
# by a substring of the selector, each with its reason. An undeclared exception
# is indistinguishable from a selector nobody has looked at.
#
# Two of the three are separate SURFACES with their own audience and their own
# scale — the customer portal and the public status page are standalone pages,
# not part of the dashboard's chrome. The third is a room display and says so in
# the stylesheet next to it.
EXCEPTIONS = {
    'portal.css:.hint': 'the customer portal is a standalone page for a '
                        'non-operator audience, set one step larger throughout',
    'status.css:.status-section-title': 'the public status page is a '
                                        'standalone surface with its own scale',
    'body.alertwall': 'the alert wall is a room display — the stylesheet says '
                      'so beside it, and the rule is scoped to that body class',
}


def _rules():
    """[(file, selector, font-size)] over every shipped stylesheet.

    Comments are stripped first: without that, the text of a comment explaining
    a rule is read as part of the selector that follows it.
    """
    out = []
    for f in sorted(_CSS_DIR.glob('*.css')):
        if f.name in _VENDORED:
            continue
        css = re.sub(r'/\*.*?\*/', ' ', f.read_text(encoding='utf-8'), flags=re.S)
        for m in re.finditer(r'([^{}\n][^{}]*?)\{([^{}]*)\}', css):
            sel = ' '.join(m.group(1).split())
            if sel.startswith('@'):
                continue
            fs = re.search(r'font-size:\s*([0-9.]+)px', m.group(2))
            if fs:
                out.append((f.name, sel, float(fs.group(1))))
    return out


def _selector_parts(sel):
    """The individual class/element selectors in a comma-free selector."""
    return re.findall(r'\.[A-Za-z0-9_-]+', sel)


class TestOneRoleOneSize(unittest.TestCase):

    def test_every_role_named_selector_uses_its_role_size(self):
        offenders = []
        for fname, sel, size in _rules():
            if any(k.split(':')[-1] in sel and (':' not in k or k.split(':')[0] == fname)
                   for k in EXCEPTIONS):
                continue
            parts = _selector_parts(sel)
            for role, (want, _why) in ROLE_SIZES.items():
                # The role token must be the LAST class in the selector — the
                # element being sized — and an exact class, so `.hint-mb` and
                # `.dev-hovercard-hint` count while `.hint-wrapper .value`
                # does not.
                if not parts:
                    continue
                last = parts[-1].lstrip('.')
                if last == role or last.startswith(role + '-') or last.endswith('-' + role):
                    if size != want:
                        offenders.append(f'{fname}: {sel} is {size}px, '
                                         f'{role} renders at {want}px')
        self.assertEqual(
            offenders, [],
            'same role, different size — the scale allows both, the design '
            'assigns one. Change the size, or add the selector to EXCEPTIONS '
            f'with the reason it plays a different part: {offenders}')

    def test_every_exception_still_names_a_live_selector(self):
        rules = _rules()
        stale = []
        for key in EXCEPTIONS:
            fname, _, needle = key.rpartition(':')
            hit = any(needle in sel and (not fname or fname == f)
                      for f, sel, _s in rules)
            if not hit:
                stale.append(key)
        self.assertEqual(stale, [],
                         f'exception for a selector that is gone: {stale}')


class TestTheScanIsHonest(unittest.TestCase):

    def test_it_reads_every_stylesheet(self):
        files = {f for f, _s, _z in _rules()}
        self.assertGreaterEqual(len(files), 4, sorted(files))
        self.assertIn('styles.css', files)

    def test_it_finds_the_roles_it_checks(self):
        """The check above is "this list is empty", which is also what a scan
        that matches no selector produces."""
        seen = set()
        for _f, sel, _size in _rules():
            parts = _selector_parts(sel)
            if not parts:
                continue
            last = parts[-1].lstrip('.')
            for role in ROLE_SIZES:
                if last == role or last.startswith(role + '-') or last.endswith('-' + role):
                    seen.add(role)
        self.assertEqual(sorted(seen), sorted(ROLE_SIZES),
                         f'roles the scan never matched: '
                         f'{sorted(set(ROLE_SIZES) - seen)}')

    def test_it_would_report_an_off_size_selector(self):
        """Control for the matcher itself."""
        parts = _selector_parts('#dev-hovercard .dev-hovercard-hint')
        self.assertTrue(parts[-1].lstrip('.').endswith('-hint'))


if __name__ == '__main__':
    unittest.main()

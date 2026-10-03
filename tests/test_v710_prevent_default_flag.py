"""`data-prevent-default` must work with no value, because that is how most sites write it.

The click dispatcher read the flag as `if (el.dataset.preventDefault) e.preventDefault()`.
A valueless attribute has the dataset value "", which is falsy, so a link written
`<a href="#" data-action="x" data-prevent-default>` never had its default action cancelled:
the page jumped to the top and the URL gained a `#` on every click. Nine sites wrote
`data-prevent-default="1"` and worked; thirty-one wrote it bare and did not. The rule was
half-applied, and every one of the 31 looked right in review.

The dispatcher now tests for the attribute (`!== undefined`), so both spellings behave the
same. This pins that, and counts the population so the rule cannot quietly stop mattering.
"""
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_WEB = _ROOT / 'server' / 'html'
_SOURCES = [_WEB / 'index.html'] + sorted((_WEB / 'static' / 'js').glob('app*.js'))


def _uses():
    """[(path, valueless?)] for every data-prevent-default in the shipped UI sources."""
    out = []
    for p in _SOURCES:
        text = p.read_text(encoding='utf-8')
        for m in re.finditer(r'data-prevent-default(=("[^"]*"|\'[^\']*\'))?', text):
            out.append((p.name, m.group(1) is None))
    return out


class TestPreventDefaultFlag(unittest.TestCase):

    def test_both_spellings_are_in_use(self):
        """Control: if only one spelling existed the dispatcher change would not matter."""
        uses = _uses()
        bare = sum(1 for _, v in uses if v)
        valued = len(uses) - bare
        self.assertGreaterEqual(bare, 20, 'only %d valueless uses found' % bare)
        self.assertGreaterEqual(valued, 5, 'only %d valued uses found' % valued)

    def test_no_use_writes_a_falsy_value(self):
        """`data-prevent-default="0"` or `="false"` would read as present and cancel anyway."""
        bad = []
        for p in _SOURCES:
            for m in re.finditer(r'data-prevent-default=("([^"]*)"|\'([^\']*)\')', p.read_text(encoding='utf-8')):
                v = m.group(2) if m.group(2) is not None else m.group(3)
                if v.strip().lower() in ('', '0', 'false', 'no', 'off'):
                    bad.append((p.name, m.group(0)))
        self.assertEqual([], bad)

    def test_the_dispatcher_tests_for_presence_at_both_sites(self):
        src = (_WEB / 'static' / 'js' / 'app.js').read_text(encoding='utf-8')
        sites = re.findall(r'if \((\w+)\.dataset\.preventDefault([^)]*)\) e\.preventDefault\(\);', src)
        self.assertEqual(2, len(sites), 'expected the data-action-btn and data-action dispatch sites, found %r' % sites)
        for name, rest in sites:
            self.assertEqual(' !== undefined', rest, '%s.dataset.preventDefault is tested for truthiness; a bare attribute is ""' % name)


if __name__ == '__main__':
    unittest.main()

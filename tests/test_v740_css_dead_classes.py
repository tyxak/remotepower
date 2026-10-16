"""A class the stylesheet defines must be written somewhere.

test_css_class_parity holds one direction: a class used in markup must exist.
Nothing held the other, and at v7.4.0 32 classes in styles.css were written by
no page, script or server template, among them `.fw-600-14` (which set 13px),
`.fs-body` (commented "THE body anchor — reach for this one" and used nowhere)
and `.rp-well`. They were removed with this gate.

A class counts as written when its name appears as a token in a page, a client
script or the server/agent/tools code, or when it belongs to a family the code
builds by interpolation: a prefix of it is followed by `${` or concatenated
(`up-${kind}` writes `up-maintenance`), or a suffix of it follows `}` (`heat-l${n}`
style, the other way round). That is lenient on purpose: a short prefix such as
`c-` matches a lot, so the gate may miss a dead class, but it never blocks a live
one. A class that appears only inside `:not(...)` is not a styling hook and is
not counted as defined.
"""
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CSS = _ROOT / 'server' / 'html' / 'static' / 'css' / 'styles.css'


def defined_classes(css):
    """Class names used in selectors, outside comments, declaration blocks and :not()."""
    css = re.sub(r'/\*.*?\*/', '', css, flags=re.S)
    selectors = []
    depth, buf = 0, []
    for ch in css:
        if ch == '{':
            if depth == 0 or (depth == 1 and buf and '@' not in ''.join(buf)):
                selectors.append(''.join(buf))
            depth += 1
            buf = []
        elif ch == '}':
            depth -= 1
            buf = []
        elif depth == 0 or depth == 1:
            buf.append(ch)
    out = set()
    for sel in selectors:
        if sel.strip().startswith('@'):
            continue
        sel = re.sub(r':not\([^()]*\)', '', sel)
        sel = re.sub(r'\[[^\]]*\]', '', sel)          # attribute values are not classes
        out.update(m for m in re.findall(r'\.(-?[A-Za-z_][\w-]*)', sel) if not m[0].isdigit())
    return out


def written(paths):
    hay = '\n'.join(p.read_text(errors='replace') for p in paths)
    tokens = set(re.findall(r'[A-Za-z_][\w-]*', hay))
    prefixes = {p for p in re.findall(r'([A-Za-z][\w-]+)\$\{', hay)} | \
               {p for p in re.findall(r"""['"`]([A-Za-z][\w-]+)['"`]\s*\+""", hay)}
    suffixes = {s for s in re.findall(r'\}(-[\w-]{2,})', hay)} | \
               {s for s in re.findall(r"""\+\s*['"`](-[\w-]{2,})['"`]""", hay)}
    return tokens, {p for p in prefixes if len(p) >= 2}, suffixes


def never_written(classes, tokens, prefixes, suffixes):
    dead = []
    for c in classes:
        if c in tokens:
            continue
        if any(c.startswith(p) for p in prefixes) or any(c.endswith(s) for s in suffixes):
            continue
        dead.append(c)
    return sorted(dead)


def _sources():
    html = _ROOT / 'server' / 'html'
    paths = list((html / 'static' / 'js').glob('*.js')) + list(html.rglob('*.html'))
    paths += [p for p in (html / 'static' / 'css').glob('*.css') if p.name != 'styles.css']
    for d in ('server/cgi-bin', 'client', 'tools'):
        paths += list((_ROOT / d).glob('*.py'))
    return paths


class TestEveryDefinedClassIsWritten(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.classes = defined_classes(_CSS.read_text())
        cls.tokens, cls.prefixes, cls.suffixes = written(_sources())

    def test_the_population(self):
        """Control: the parser finds the stylesheet's classes and the sources."""
        self.assertGreater(len(self.classes), 1500)
        self.assertIn('section-title', self.classes)
        self.assertNotIn('nav-icon', self.classes, 'a class only inside :not() is not a styling hook')

    def test_an_interpolated_family_counts_as_written(self):
        """`up-${escAttr(it.kind)}` writes up-maintenance; `heat-l${lvl}` writes heat-l1."""
        self.assertEqual(never_written(['up-maintenance', 'heat-l1'], self.tokens, self.prefixes, self.suffixes), [])

    def test_a_class_nothing_writes_is_found(self):
        self.assertEqual(never_written(['zz-never-written-anywhere'], self.tokens, self.prefixes, self.suffixes),
                         ['zz-never-written-anywhere'])

    def test_no_class_in_the_stylesheet_is_dead(self):
        dead = never_written(self.classes, self.tokens, self.prefixes, self.suffixes)
        self.assertEqual(dead, [], 'classes no page, script or template writes; delete their rules')


if __name__ == '__main__':
    unittest.main()

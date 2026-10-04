"""The in-app documentation viewer renders links and heading anchors.

`renderMarkdown` shipped for the AI chat and the knowledge base, which show model and operator
text, so it deliberately renders no links. The documentation viewer reuses it for the product's
own docs, and until now a link in a doc was a line of raw `[text](url)`, a heading had no id, and
a pointer written `docs/x.md#anchor` did not match the interceptor's `.md$` test, so it unloaded
the whole SPA and handed the browser a raw markdown file.

With `{docs: true}` the renderer gives every heading a `doc-<slug>` id and renders three kinds of
link: `#anchor`, a same-folder `name.md[#anchor]`, and http(s). Every other target is shown as its
text. The AI and KB callers pass no options and are unchanged.

This runs the real functions in V8 over every document in docs/. The slug rule is GitHub's and is
held in Python by test_v710_docs_internal_links; the two must agree on every heading, or an anchor
the Python gate calls valid lands nowhere in the viewer.
"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_v710_docs_internal_links import _slug   # noqa: E402

try:
    from py_mini_racer import MiniRacer
    _HAVE_V8 = True
except Exception:                          # pragma: no cover - env dependent
    _HAVE_V8 = False

_ROOT = Path(__file__).resolve().parent.parent
_APP = _ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js'
_DOCS = sorted((_ROOT / 'docs').glob('*.md'))

# V8 has no URL class; _safeHttpHref only needs the scheme.
_SHIM = """
function URL(u) { var m = /^([A-Za-z][A-Za-z0-9+.-]*:)/.exec(String(u)); this.protocol = m ? m[1].toLowerCase() : 'https:'; }
var window = { location: { origin: 'https://rp.example' } };
"""


def _oneline(src, name):
    m = re.search(r'^function %s\(.*$' % re.escape(name), src, re.M)
    assert m, '%s not found as a one-line function in app.js' % name
    return m.group(0)


def _toplevel(src, name):
    """A top-level function, from its `function name(` line to the first line that is just `}`.

    srcpin's brace scanner treats a backtick as a template literal, and renderMarkdown has the
    regex /```(\\w+)?.../ in it, so it cannot be balanced by srcpin. This file's style (everything
    inside a function is indented) makes the closing `}` at column 0 unambiguous."""
    m = re.search(r'^function %s\(.*?\n\}\n' % re.escape(name), src, re.M | re.S)
    assert m, '%s not found as a top-level function in app.js' % name
    return m.group(0)


def _context():
    src = _APP.read_text(encoding='utf-8')
    parts = [_oneline(src, 'escHtml'), _oneline(src, 'escAttr')]
    parts += [_toplevel(src, n) for n in ('_safeHttpHref', '_mdWord', '_mdSlug', '_mdHeadingIds', 'renderMarkdown')]
    ctx = MiniRacer()
    ctx.eval(_SHIM + '\n'.join(parts))
    return ctx


def _ordered_anchors(text):
    """test_v710_docs_internal_links.anchors(), but in document order."""
    seen, out, fence = {}, [], False
    for ln in text.splitlines():
        if ln.lstrip().startswith('```'):
            fence = not fence
            continue
        if fence:
            continue
        m = re.match(r'^#{1,6}\s+(.*?)\s*#*\s*$', ln)
        if not m:
            continue
        s = _slug(m.group(1))
        n = seen.get(s, 0)
        seen[s] = n + 1
        out.append('doc-' + (s if n == 0 else '%s-%d' % (s, n)))
    return out


@unittest.skipUnless(_HAVE_V8, 'py_mini_racer (V8) is not installed')
class TestDocViewerMarkdown(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ctx = _context()

    def render(self, text, docs=True):
        return self.ctx.call('renderMarkdown', text, {'docs': True} if docs else None)

    def test_the_corpus_is_not_empty(self):
        """Control: with no documents the loops below would pass without checking anything."""
        self.assertGreater(len(_DOCS), 100)
        self.assertGreater(sum(len(_ordered_anchors(p.read_text(encoding='utf-8'))) for p in _DOCS), 1200)

    def test_every_heading_gets_the_id_github_would_give_it(self):
        bad = []
        for p in _DOCS:
            text = p.read_text(encoding='utf-8')
            want, got = _ordered_anchors(text), self.ctx.call('_mdHeadingIds', text)
            if want != got:
                diff = next((i for i, (a, b) in enumerate(zip(want, got)) if a != b), min(len(want), len(got)))
                bad.append('%s: heading %d python=%r js=%r' % (p.name, diff, want[diff:diff + 1], got[diff:diff + 1]))
        self.assertEqual([], bad)

    def test_every_in_page_link_lands_on_a_heading_in_the_rendered_page(self):
        total, bad = 0, []
        for p in _DOCS:
            html = self.render(p.read_text(encoding='utf-8'))
            ids = set(re.findall(r'\bid="(doc-[^"]*)"', html))
            for target in re.findall(r'data-doc-anchor="([^"]*)"', html):
                total += 1
                if target not in ids:
                    bad.append('%s -> %s' % (p.name, target))
        self.assertGreater(total, 15, 'only %d in-page links rendered across docs/' % total)
        self.assertEqual([], bad[:10])

    def test_link_forms(self):
        self.assertIn('href="docs/api.md#rate-limits"', self.render('[api](api.md#rate-limits)'))
        self.assertIn('href="docs/api.md"', self.render('[api](api.md)'))
        self.assertIn('data-doc-anchor="doc-why-this"', self.render('[w](#why-this)'))
        ext = self.render('[x](https://example.org/a?b=1&c=2)')
        self.assertIn('target="_blank" rel="noopener noreferrer"', ext)
        self.assertIn('href="https://example.org/a?b=1&amp;c=2"', ext)

    def test_a_target_that_is_not_one_of_the_three_forms_is_only_text(self):
        for target in ('javascript:alert(1)', '../README.md', 'mailto:a@b.c', 'data:text/html,x', 'sub/dir.md', 'ftp://h/f'):
            html = self.render('see [the thing](%s) now' % target)
            self.assertNotIn('<a ', html, target)
            self.assertNotIn('href=', html, target)
            self.assertIn('the thing', html, target)

    def test_markup_in_a_link_label_is_escaped(self):
        html = self.render('[<img src=x onerror=alert(1)>](api.md)')
        self.assertNotIn('<img', html)
        self.assertIn('&lt;img', html)

    def test_repeated_headings_are_numbered(self):
        html = self.render('## Setup\n\ntext\n\n## Setup\n')
        self.assertIn('id="doc-setup"', html)
        self.assertIn('id="doc-setup-1"', html)

    def test_headings_below_h3_are_anchors_too(self):
        self.assertIn('id="doc-deep-one"', self.render('#### Deep one\n'))

    def test_the_model_and_kb_callers_are_unchanged(self):
        """No options: no links, no ids, headings exactly as before."""
        html = self.render('# Title\n\n[x](https://example.org)', docs=False)
        self.assertNotIn('<a ', html)
        self.assertNotIn(' id=', html)
        self.assertIn('[x](https://example.org)', html)


@unittest.skipUnless(_HAVE_V8, 'py_mini_racer (V8) is not installed')
class TestDocViewerWiring(unittest.TestCase):

    def test_a_pointer_with_a_fragment_is_intercepted(self):
        """`docs/x.md#anchor` used to miss the `.md$` test and unload the SPA."""
        src = _APP.read_text(encoding='utf-8')
        m = re.search(r"if \(!(/\\\.md[^/]*/i)\.test\(href\)\) return;", src)
        self.assertIsNotNone(m, 'the interceptor no longer tests href against a .md pattern')
        pattern = re.compile(m.group(1)[1:-2].replace('\\/', '/'), re.I)
        self.assertTrue(pattern.search('docs/api.md'))
        self.assertTrue(pattern.search('docs/api.md#rate-limits'))
        self.assertFalse(pattern.search('docs/logo.png'))
        self.assertFalse(pattern.search('docs/api.md#two#hashes'))

    def test_the_viewer_renders_in_docs_mode(self):
        src = _APP.read_text(encoding='utf-8')
        self.assertIn('renderMarkdown(text, { docs: true })', src)


if __name__ == '__main__':
    unittest.main()

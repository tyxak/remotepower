"""The engine's text-node cap has to reach every static UI string.

`translateTextNode` (i18n.js) skips a text node longer than its cap before it
looks at DICT, so a string above the cap stays English whatever the dictionary
holds, and nothing reports it. The About blurb (942 characters) and three
Settings hints (407-542) sat in that state until the cap went from 400 to 1000
in v7.1.0.

This walks index.html the way the engine walks the live DOM and requires every
static text node outside the in-app Documentation page to fit under the cap. The
Documentation page is English by design (long prose, translated only for the
short cards), so it is the one exclusion, and a control proves the exclusion is
what hides its long paragraphs rather than a walker that cannot see them.
"""
import sys
import unittest
from html.parser import HTMLParser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from i18n_engine import text_node_cap   # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
INDEX = _ROOT / 'server' / 'html' / 'index.html'

# The engine's SKIP_TAGS and _skipText classes, so a node it would never touch is
# not counted against the cap.
_SKIP_TAGS = {'script', 'style', 'pre', 'code', 'textarea', 'kbd', 'samp', 'svg', 'head', 'title'}
_SKIP_CLASSES = {'page-subtitle', 'logo-text'}      # subtitles go through HTMLDICT, no cap
_VOID = {'br', 'img', 'input', 'hr', 'meta', 'link', 'source', 'col', 'area', 'base', 'wbr', 'embed', 'track', 'param'}
_DOCS_ID = 'docs-container'      # the in-app Documentation page


class _Walk(HTMLParser):
    def __init__(self, cap, docs_excluded):
        super().__init__(convert_charrefs=True)
        self.cap, self.docs_excluded = cap, docs_excluded
        self.stack = []          # (tag, skip?, docs?)
        self.long = []           # (length, line, text)
        self.seen = 0

    def handle_starttag(self, tag, attrs):
        if tag in _VOID:
            return
        a = dict(attrs)
        classes = set((a.get('class') or '').split())
        skip = tag in _SKIP_TAGS or bool(classes & _SKIP_CLASSES) or 'data-no-i18n' in a
        self.stack.append((tag, skip, a.get('id') == _DOCS_ID))

    def handle_endtag(self, tag):
        while self.stack and self.stack[-1][0] != tag:
            self.stack.pop()
        if self.stack:
            self.stack.pop()

    def handle_data(self, data):
        text = data.strip()
        if len(text) < 2 or any(s for _t, s, _d in self.stack):
            return
        if self.docs_excluded and any(d for _t, _s, d in self.stack):
            return
        self.seen += 1
        if len(text) > self.cap:
            self.long.append((len(text), self.getpos()[0], text[:60]))


def long_text_nodes(html, cap, docs_excluded=True):
    """(nodes over the cap, nodes examined) for a page, mirroring the engine's walk."""
    w = _Walk(cap, docs_excluded)
    w.feed(html)
    return w.long, w.seen


class TestStaticMarkupFitsTheEngineCap(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = INDEX.read_text(encoding='utf-8')
        cls.cap = text_node_cap()

    def test_no_ui_text_node_in_index_html_is_past_the_cap(self):
        over, seen = long_text_nodes(self.html, self.cap)
        self.assertGreater(seen, 3000, 'the walk examined almost nothing - the parser lost the page')
        self.assertEqual(over, [], '\n'.join([
            'these static text nodes are longer than the engine cap (%d), so no DICT entry '
            'for them would ever be applied:' % self.cap,
            *('  line %d (%d chars): %s...' % (ln, n, txt) for n, ln, txt in over),
            '',
            'Split the sentence at an inline element, shorten it, or raise the cap in '
            'translateTextNode (i18n.js); the markup gate follows that number.']))

    def test_the_walk_can_see_long_nodes(self):
        """Control. With the cap at its old value of 400 the About blurb and the Settings
        hints are over it, and with the Documentation page included its long cards are
        too, so a walker that returned nothing for everything would fail here."""
        over_400, _ = long_text_nodes(self.html, 400)
        self.assertGreaterEqual(len(over_400), 3, 'the About blurb and Settings hints are over 400')
        with_docs, _ = long_text_nodes(self.html, 400, docs_excluded=False)
        self.assertGreater(len(with_docs), len(over_400) + 5,
                           'the Documentation page carries long paragraphs the exclusion hides')

    def test_the_cap_helper_reads_the_engine_source(self):
        self.assertEqual(text_node_cap('if (trimmed.length < 2 || trimmed.length > 777) return;'), 777)
        self.assertGreaterEqual(self.cap, 942, 'the About blurb has to fit')


if __name__ == '__main__':
    unittest.main()

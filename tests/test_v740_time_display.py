"""One rule for a time in the interface: relative in place, the exact time on hover.

Before v7.4.0, 67 places showed a relative time ("3h ago") and four carried the
exact time on hover, so a time you had to line up with a log line, a change
window or a colleague's screenshot was usually just "3h ago". timeAgo() returns
a plain string, because its callers put it in textContent and in sentences as
well as in markup, so the hover could not be added there.

timeAgoHtml() is the markup form: a <time> element with the relative time in
place, the exact one in its title and a machine-readable datetime; with the
"absolute" display setting, the other way round. This file holds the call sites
to it: no timeAgo() inside markup outside an attribute. It also holds the
private copies of timeAgo to delegating to it, since three had their own
English "just now" and ignored the display setting.
"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import srcpin  # noqa: E402

try:
    from py_mini_racer import MiniRacer
    _HAVE_V8 = True
except Exception:                          # pragma: no cover - env dependent
    _HAVE_V8 = False

_ROOT = Path(__file__).resolve().parent.parent
_JS = _ROOT / 'server' / 'html' / 'static' / 'js'
_TAG = re.compile(r'</?(td|th|span|div|b|li|small|p|a)\b')


def _in_attribute(line, pos):
    lt = line.rfind('<', 0, pos)
    seg = line[lt:pos] if lt >= 0 else line[:pos]
    m = list(re.finditer(r'=\s*"', seg))
    return bool(m) and seg[m[-1].end():].count('"') % 2 == 0


def markup_sites(text, name='<src>'):
    """timeAgo( calls on a line that carries markup, outside an attribute value."""
    out = []
    for n, line in enumerate(text.split('\n'), 1):
        if 'timeAgo(' not in line or not _TAG.search(line) or 'function timeAgo' in line:
            continue
        for m in re.finditer(r'(?<![\w.])timeAgo\(', line):
            if not _in_attribute(line, m.start()):
                out.append('%s:%d' % (name, n))
    return out


class TestTheMarkupSitesUseTheOneRule(unittest.TestCase):

    def test_the_scan_sees_a_site_and_spares_an_attribute(self):
        self.assertEqual(markup_sites('x = `<td>${timeAgo(t)}</td>`;'), ['<src>:1'])
        self.assertEqual(markup_sites('x = `<td title="${timeAgo(t)}">a</td>`;'), [])
        self.assertEqual(markup_sites('el.textContent = `Last sync ${timeAgo(t)}`;'), [])

    def test_no_markup_site_uses_the_plain_string(self):
        files = sorted(_JS.glob('app*.js'))
        self.assertGreater(len(files), 40, 'control: the scripts were found')
        bad = []
        for p in files:
            bad += markup_sites(p.read_text(), p.name)
        self.assertEqual(bad, [], 'a time in markup goes through timeAgoHtml() '
                                  '(relative in place, exact on hover)')
        uses = sum(p.read_text().count('timeAgoHtml(') for p in files)
        self.assertGreater(uses, 30, 'control: the call sites were moved, not deleted')

    def test_private_copies_delegate(self):
        """A private relative-time helper must call timeAgo, so the language and
        the display setting reach it. status.js is the public status page: its
        own bundle, without app.js."""
        found = {}
        for p in sorted(_JS.glob('*.js')):
            src = p.read_text()
            for m in re.finditer(r'function\s+(_?\w*[Aa]go\w*|_reltime|fmtRelative)\s*\(', src):
                name = m.group(1)
                if name in ('timeAgo', 'timeAgoHtml', '_relAgo', '_fmtAgo') or p.name == 'status.js':
                    continue
                found['%s:%s' % (p.name, name)] = srcpin.js_function(src, name) or ''
        self.assertGreaterEqual(len(found), 3, 'control: the private helpers were found')
        bad = [k for k, body in found.items() if 'timeAgo(' not in body]
        self.assertEqual(bad, [], 'these compute a relative time of their own')


@unittest.skipUnless(_HAVE_V8, 'py_mini_racer not installed')
class TestTimeAgoHtml(unittest.TestCase):
    """The real functions from app.js, run in V8."""

    @classmethod
    def setUpClass(cls):
        src = (_JS / 'app.js').read_text()
        esc = re.search(r'^function escHtml\(.*$', src, re.M).group(0)
        parts = [esc] + [srcpin.js_function(src, n) for n in (
            '_localeTag', '_fmtAgo', '_fmtAbsTs', '_timeDisplayAbsolute', 'timeAgo', '_relAgo', 'timeAgoHtml')]
        cls.ctx = MiniRacer()
        cls.ctx.eval('var window = {}; var _uiPrefs = {};\n' + '\n'.join(parts))

    def html(self, expr, absolute=False):
        self.ctx.eval("_uiPrefs = { time_display: %s };" % ("'absolute'" if absolute else "'relative'"))
        return self.ctx.eval(expr)

    def test_relative_in_place_exact_on_hover(self):
        out = self.html('timeAgoHtml(Math.floor(Date.now() / 1000) - 120)')
        m = re.fullmatch(r'<time datetime="(\d{4}-\d\d-\d\dT[\d:.]+Z)" title="([^"]+)">([^<]+)</time>', out)
        self.assertIsNotNone(m, out)
        self.assertEqual(m.group(3), '2m ago')
        self.assertRegex(m.group(2), r'\d', 'the title is the exact time')

    def test_the_absolute_setting_swaps_them(self):
        out = self.html('timeAgoHtml(Math.floor(Date.now() / 1000) - 7200)', absolute=True)
        m = re.fullmatch(r'<time datetime="[^"]+" title="([^"]+)">([^<]+)</time>', out)
        self.assertIsNotNone(m, out)
        self.assertEqual(m.group(1), '2h ago')
        self.assertNotIn('ago', m.group(2))

    def test_no_time_is_the_label_without_an_element(self):
        self.assertEqual(self.html("timeAgoHtml(0, {empty: 'never'})"), 'never')
        self.assertEqual(self.html("timeAgoHtml(null, {empty: '<b>x</b>'})"), '&lt;b&gt;x&lt;/b&gt;')
        self.assertEqual(self.html("timeAgoHtml('junk')"), 'never')

    def test_timeago_is_still_a_plain_string(self):
        self.assertEqual(self.html('timeAgo(Math.floor(Date.now() / 1000) - 120)'), '2m ago')


if __name__ == '__main__':
    unittest.main()

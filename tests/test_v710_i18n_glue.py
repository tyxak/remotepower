"""A translated text node must not print attached to the tag it sat beside in English.

A sentence built around inline markup is several text nodes, and DICT is keyed per
node. The engine puts each node's ORIGINAL edge whitespace back around its
translation, so a node that was glued to the tag before it in English ("</code>, then
connect with") stays glued in every language. When a translation starts with a WORD
instead of the punctuation the English began with, that word prints against the tag:

    ~/.ssh/config + "hinzu und verbinden Sie sich dann mit"  ->  "~/.ssh/confighinzu und ..."

A rendered sweep found 11 such nodes (28 language values) across German, French,
Spanish, Hindi and Arabic. Every one read as correct in the dictionary, because the
dictionary holds only the piece, never the seam. The fix is always the same: start
the translation with the punctuation the English started with, and move the word that
used to be there into the node before the tag. The same applies at the other end: a
node that ends on punctuation glued to the NEXT tag ("rsyslog (<code>") must not end
on a word.

Chinese is left out on purpose: CJK text sets inline code without spaces.

The population is derived from index.html, the way the engine walks it, and a control
checks that the scan found glued nodes at all, so the gate cannot go green by looking
at nothing.
"""
import re
import unittest
from html.parser import HTMLParser
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_HTML = _ROOT / 'server' / 'html' / 'index.html'
_I18N = _ROOT / 'server' / 'html' / 'static' / 'js' / 'i18n.js'
_LANGS = ('de', 'fr', 'es', 'hi', 'ar')
# The engine skips these subtrees; text inside them is never translated.
_SKIP = {'script', 'style', 'code', 'pre', 'kbd', 'samp', 'textarea', 'svg'}
_INLINE = {'code', 'strong', 'em', 'b', 'i', 'a', 'span', 'kbd', 'samp', 'small', 'mark', 'u', 'sup', 'sub',
           'abbr', 'cite'}
_WORD = re.compile(r'\w', re.U)
_VOID = {'br', 'hr', 'img', 'input', 'meta', 'link', 'source', 'wbr', 'col', 'area', 'base', 'embed', 'param',
         'track'}


class _Walker(HTMLParser):
    """Collects text nodes with the tag event directly before and after each."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.events = []        # ('start'|'end'|'text', value)
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in _VOID:
            self.events.append(('void', tag))
            return
        if tag in _SKIP:
            self._skip += 1
        self.events.append(('start', tag))

    def handle_endtag(self, tag):
        self.events.append(('end', tag))
        if tag in _SKIP and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.events.append(('text', data))


def glued_nodes(html):
    """[(key, glued_start, glued_end)] for every text node glued to inline markup on a punctuation edge."""
    w = _Walker()
    w.feed(html)
    ev = w.events
    out = []
    for i, (kind, val) in enumerate(ev):
        if kind != 'text':
            continue
        core = val.strip()
        if len(core) < 2:
            continue
        lead = val[:len(val) - len(val.lstrip())]
        trail = val[len(val.rstrip()):]
        prev = ev[i - 1] if i else ('', '')
        nxt = ev[i + 1] if i + 1 < len(ev) else ('', '')
        start = (not lead) and prev[0] == 'end' and prev[1] in _INLINE and not _WORD.match(core[0])
        end = (not trail) and nxt[0] == 'start' and nxt[1] in _INLINE and not _WORD.search(core[-1])
        if start or end:
            out.append((core, bool(start), bool(end)))
    return out


def _unescape(s):
    def one(m):
        t = m.group(1)
        if t[0] in 'ux':
            return chr(int(t[1:], 16))
        return {'n': '\n', 't': '\t', 'r': '\r'}.get(t, t)
    return re.sub(r'\\(u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)', one, s)


def dict_rows():
    """{english key: {lang: value}} for DICT, both the single-quoted block and the machine-written one."""
    src = _I18N.read_text(encoding='utf-8')
    m = re.search(r'var DICT = \{(.*?)\n  \};', src, re.S)
    assert m, 'DICT block not found in i18n.js'
    rows = {}
    entry = re.compile(r"""^\s{4}(?:'((?:[^'\\]|\\.)+)'|"((?:[^"\\]|\\.)+)"):\s*\{(.*)\},?\s*$""", re.M)
    val = re.compile(r"""(?:"(de|fr|es|zh|hi|ar)"|\b(de|fr|es|zh|hi|ar))\s*:\s*(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')""")
    for em in entry.finditer(m.group(1)):
        key = _unescape(em.group(1) if em.group(1) is not None else em.group(2))
        langs = {}
        for vm in val.finditer(em.group(3)):
            langs[vm.group(1) or vm.group(2)] = _unescape(vm.group(3) if vm.group(3) is not None else vm.group(4))
        rows[key] = langs
    return rows


def violations(nodes, rows):
    """[(key, lang, where, value)] — values that start or end on a word where the English was glued on punctuation."""
    bad = []
    for key, start, end in nodes:
        row = rows.get(key)
        if not row:
            continue
        for lang in _LANGS:
            v = (row.get(lang) or '').strip()
            if not v:
                continue
            if start and _WORD.match(v[0]):
                bad.append((key, lang, 'start', v))
            if end and _WORD.search(v[-1]):
                bad.append((key, lang, 'end', v))
    return bad


class TestTranslationsStayGluedLikeTheEnglish(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.nodes = glued_nodes(_HTML.read_text(encoding='utf-8'))
        cls.rows = dict_rows()

    def test_the_scan_finds_glued_nodes_and_dictionary_rows(self):
        """Control: with an empty population the check below would pass without inspecting anything."""
        translated = [n for n in self.nodes if n[0] in self.rows]
        self.assertGreaterEqual(len(self.nodes), 150, 'only %d glued nodes found in index.html' % len(self.nodes))
        self.assertGreaterEqual(len(translated), 100, 'only %d glued nodes have a DICT row' % len(translated))
        self.assertGreater(len(self.rows), 5000, 'DICT parsed to %d rows' % len(self.rows))

    def test_no_translation_starts_or_ends_on_a_word_where_the_english_was_glued_on_punctuation(self):
        bad = violations(self.nodes, self.rows)
        self.assertEqual([], bad[:12],
                         '%d glued values; start the value with the punctuation the English starts with and move '
                         'the word into the node before the tag' % len(bad))

    def test_the_checker_flags_a_word_start_and_a_word_end(self):
        """The checker itself: hand it a bad value on a real glued node and it must report it."""
        start = next(n for n in self.nodes if n[1] and n[0] in self.rows)
        end = next(n for n in self.nodes if n[2] and n[0] in self.rows)
        rows = {start[0]: {'de': 'und dann'}, end[0]: {'fr': 'puis voir'}}
        found = violations([start, end], rows)
        self.assertIn((start[0], 'de', 'start', 'und dann'), found)
        self.assertIn((end[0], 'fr', 'end', 'puis voir'), found)


if __name__ == '__main__':
    unittest.main()

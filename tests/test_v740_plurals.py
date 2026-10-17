#!/usr/bin/env python3
"""7.4.0: "3 hosts", never "3 host(s)".

`host(s)` is a sentence that gives up: it is wrong for 1 as well as for 3, it reads badly aloud, and a
screen reader spells the brackets. 404 places in the pages and code wrote it. `plural(n, one, other)` (app.js and
server/cgi-bin/textfmt.py) returns the count with the right noun, `agree(n, one, other)` picks the
verb that goes with it ("1 account has", "3 accounts have").

The scan reads the static text of every string a person can see: the pages, the strings of the client
scripts, and the string constants of the server modules (docstrings and comments are developers').
Left alone, and listed in ALLOWED with the reason: the text sent to an AI model as an instruction.
"""
import ast
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import host_terms as H  # noqa: E402
from srcpin import js_function  # noqa: E402

try:
    from py_mini_racer import MiniRacer
    _HAVE_V8 = True
except Exception:                                # pragma: no cover - env dependent
    _HAVE_V8 = False

ROOT = Path(__file__).resolve().parent.parent
CGI = ROOT / 'server' / 'cgi-bin'
HTML = ROOT / 'server' / 'html'
JS = HTML / 'static' / 'js'
sys.path.insert(0, str(CGI))
import textfmt  # noqa: E402

# A word with "(s)" or "(es)" glued to it. Single letters before the bracket are code (`f(s)`), and so are
# a few names that take a string called s.
BRACKET = re.compile(r"\b([A-Za-z][A-Za-z\-]{2,})\((s|es)\)")
CODE_NAMES = {'endswith', 'startswith', 'has', 'signature', 'escHtml', 'escAttr', 'cmdbEscHtml', 'cmdbInlineMd',
              'encodeURIComponent', 'appendChild', 'sevCls', 'btoa', 'floor', 'String', 'JSON', 'http'}

# file -> why the "(s)" stays
ALLOWED = {
    'app-ai.js': 'the message sent to the model for an advisor card is an instruction to it, not text for a reader',
    'ai_provider.py': 'system prompts: instructions to a model',
    'rag_index.py': 'text indexed for the model',
}

SKIP_PY = {'storage.py', 'storage_pg.py'}


def bracketed(text):
    return [m.group(0) for m in BRACKET.finditer(text) if m.group(1) not in CODE_NAMES]


def py_strings(source):
    tree = ast.parse(source)
    docs = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.body \
                and isinstance(n.body[0], ast.Expr) and isinstance(getattr(n.body[0], 'value', None), ast.Constant):
            docs.add(id(n.body[0].value))
    return [(n.lineno, n.value) for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docs]


def findings():
    found, seen = [], 0
    for p in sorted(HTML.glob('*.html')):
        for ln, _kind, text in H.html_prose(p.read_text(encoding='utf-8')):
            seen += 1
            found += [f'{p.name}:{ln}: {b}' for b in bracketed(text)]
    for p in sorted(JS.glob('app*.js')):
        if p.name in ALLOWED:
            continue
        for ln, text in H.js_literals(p.read_text(encoding='utf-8')):
            seen += 1
            found += [f'{p.name}:{ln}: {b}' for b in bracketed(text)]
    for p in sorted(CGI.glob('*.py')):
        if p.name in SKIP_PY or p.name in ALLOWED:
            continue
        for ln, text in py_strings(p.read_text(encoding='utf-8')):
            seen += 1
            found += [f'{p.name}:{ln}: {b}' for b in bracketed(text)]
    return found, seen


class TestNoBracketedPlural(unittest.TestCase):
    def test_none_left_in_what_a_person_reads(self):
        found, _seen = findings()
        self.assertEqual(found, [], 'write "3 hosts", not "host(s)": plural(n, one, other) gives the count and the noun, '
                                    'agree(n, one, other) the verb:\n  ' + '\n  '.join(found[:25]))

    def test_the_scan_reads_the_product(self):
        _found, seen = findings()
        self.assertGreater(seen, 60000, 'the scan found almost no strings')

    def test_the_allowed_files_are_real(self):
        for name in ALLOWED:
            self.assertTrue((JS / name).exists() or (CGI / name).exists(), name)

    def test_the_scanner_can_say_no(self):
        self.assertEqual(bracketed('Remove 3 host(s)? Delete the file(s) and match(es)'), ['host(s)', 'file(s)', 'match(es)'])
        self.assertEqual(bracketed('escHtml(s) and has(s) and f(s)'), [])
        self.assertEqual(bracketed('Cooldown (s)'), [])          # seconds, with a space: not a plural


class TestPluralInPython(unittest.TestCase):
    def test_counts(self):
        self.assertEqual(textfmt.plural(1, 'host'), '1 host')
        self.assertEqual(textfmt.plural(0, 'host'), '0 hosts')
        self.assertEqual(textfmt.plural(3, 'host'), '3 hosts')
        self.assertEqual(textfmt.plural(3, 'entry', 'entries'), '3 entries')
        self.assertEqual(textfmt.plural(1, 'entry', 'entries'), '1 entry')

    def test_odd_counts(self):
        self.assertEqual(textfmt.plural(None, 'host'), '0 hosts')
        self.assertEqual(textfmt.plural('1', 'host'), '1 host')
        self.assertEqual(textfmt.plural('?', 'host'), '? hosts')
        self.assertEqual(textfmt.plural(2.5, 'day'), '2.5 days')

    def test_agree(self):
        self.assertEqual(textfmt.agree(1, 'has', 'have'), 'has')
        self.assertEqual(textfmt.agree(2, 'has', 'have'), 'have')
        self.assertEqual(textfmt.agree(0, 'has', 'have'), 'have')
        self.assertEqual(textfmt.agree(None, 'is', 'are'), 'are')


@unittest.skipUnless(_HAVE_V8, 'py_mini_racer (V8) not installed')
class TestPluralInTheBrowser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ctx = MiniRacer()
        cls.ctx.eval(js_function((JS / 'app.js').read_text(encoding='utf-8'), 'plural'))

    def call(self, expr):
        return self.ctx.eval(expr)

    def test_counts(self):
        self.assertEqual(self.call("plural(1, 'host')"), '1 host')
        self.assertEqual(self.call("plural(0, 'host')"), '0 hosts')
        self.assertEqual(self.call("plural(3, 'host', 'hosts')"), '3 hosts')
        self.assertEqual(self.call("plural(3, 'entry', 'entries')"), '3 entries')
        self.assertEqual(self.call("plural(1, 'entry', 'entries')"), '1 entry')

    def test_odd_counts(self):
        self.assertEqual(self.call("plural('1', 'host')"), '1 host')
        self.assertEqual(self.call("plural('?', 'host')"), '? hosts')
        self.assertEqual(self.call("plural(undefined, 'host')"), 'undefined hosts')

    def test_both_languages_agree_on_a_table(self):
        for n in (0, 1, 2, 5, 11, 100):
            self.assertEqual(self.call(f"plural({n}, 'rule', 'rules')"), textfmt.plural(n, 'rule', 'rules'))


if __name__ == '__main__':
    unittest.main()

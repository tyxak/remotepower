"""The Threat intel status column is built from phrases the language engine can translate.

The column used to be one string joined in JavaScript: "reported to AbuseIPDB · not blocked:
auto-block is off". The engine translates a whole text node by exact match, so a sentence
assembled at runtime was never in the dictionary and stayed English in every language. Each fixed
phrase is now a span of its own. This pins that, and derives the population of server-sent reasons
from ip_intel.py and ip_intel_handlers.py so a reason added later without a dictionary entry fails
here instead of reading English to a German operator.
"""
import ast
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from srcpin import js_function            # noqa: E402
from test_v710_i18n_glue import dict_rows   # noqa: E402

try:
    from py_mini_racer import MiniRacer
    _HAVE_V8 = True
except Exception:                          # pragma: no cover - env dependent
    _HAVE_V8 = False

_ROOT = Path(__file__).resolve().parent.parent
_JS = _ROOT / 'server' / 'html' / 'static' / 'js'
_CGI = _ROOT / 'server' / 'cgi-bin'
_LANGS = ('de', 'fr', 'es', 'zh', 'hi', 'ar')


def server_reasons():
    """Every fixed English reason the server can attach to an attacker row."""
    reasons = set()
    mod = ast.parse((_CGI / 'ip_intel.py').read_text(encoding='utf-8'))
    for fn in mod.body:
        if isinstance(fn, ast.FunctionDef) and fn.name in ('block_decision', 'never_block_reason'):
            for node in ast.walk(fn):
                if isinstance(node, ast.Return) and node.value is not None:
                    vals = node.value.elts if isinstance(node.value, ast.Tuple) else [node.value]
                    for v in vals:
                        if isinstance(v, ast.Constant) and isinstance(v.value, str) and v.value:
                            reasons.add(v.value)
    handlers = ast.parse((_CGI / 'ip_intel_handlers.py').read_text(encoding='utf-8'))
    for node in ast.walk(handlers):
        # `ok, why = False, 'reason'`
        if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Tuple) and len(node.value.elts) == 2
                and isinstance(node.value.elts[1], ast.Constant) and isinstance(node.value.elts[1].value, str)
                and any(isinstance(t, ast.Tuple) and any(isinstance(e, ast.Name) and e.id == 'why' for e in t.elts)
                        for t in node.targets)):
            reasons.add(node.value.elts[1].value)
    return reasons


def _context():
    src = (_JS / 'app-ipintel.js').read_text(encoding='utf-8')
    app = (_JS / 'app.js').read_text(encoding='utf-8')
    esc = re.search(r'^function escHtml\(.*$', app, re.M).group(0)
    parts = [esc, 'var _ipiData = {blocks: []};']
    parts += [js_function(src, n) for n in ('_ipiStatus', '_ipiPhrase', '_ipiReason', '_ipiStatusHtml')]
    ctx = MiniRacer()
    ctx.eval('\n'.join(parts))
    return ctx


@unittest.skipUnless(_HAVE_V8, 'py_mini_racer (V8) is not installed')
class TestIpIntelStatus(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ctx = _context()
        cls.rows = dict_rows()

    def html(self, attacker):
        return self.ctx.call('_ipiStatusHtml', attacker)

    def test_the_reason_population_is_derived_and_not_trivial(self):
        reasons = server_reasons()
        self.assertGreaterEqual(len(reasons), 9, sorted(reasons))
        self.assertIn('auto-block is off', reasons)
        self.assertIn('hourly block limit reached for this host', reasons)

    def test_every_fixed_reason_is_a_dictionary_key_in_all_six_languages(self):
        missing = []
        for r in sorted(server_reasons() - {''}):
            if re.match(r'^score ', r) or r.startswith('not reported'):
                continue          # built from a template below
            row = self.rows.get(r)
            if not row or not all(row.get(l) for l in _LANGS):
                missing.append(r)
        self.assertEqual([], missing)

    def test_the_label_phrases_are_dictionary_keys_in_all_six_languages(self):
        for key in ('reported to', 'blocked on', 'not blocked:', 'not reported:', 'score below threshold'):
            row = self.rows.get(key)
            self.assertTrue(row and all(row.get(l) for l in _LANGS), key)

    def test_each_phrase_is_its_own_text_node(self):
        h = self.html({'ip': '1.2.3.4', 'reported': {'abuseipdb': 1}, 'devices': [{'not_blocked': 'auto-block is off'}]})
        self.assertIn('<span>reported to</span> AbuseIPDB', h)
        self.assertIn('<span>not blocked:</span> <span>auto-block is off</span>', h)
        self.assertIn(' · ', h)

    def test_a_score_reason_becomes_a_phrase_and_two_numbers(self):
        h = self.html({'ip': '1.2.3.4', 'devices': [{'not_blocked': 'score 40 is below 90'}]})
        self.assertIn('<span>score below threshold</span> (40 &lt; 90)', h)

    def test_an_unknown_provider_error_is_escaped_and_kept(self):
        h = self.html({'ip': '1.2.3.4', 'errors': {'abuseipdb': '<b>HTTP 429</b>'}})
        self.assertNotIn('<b>', h)
        self.assertIn('&lt;b&gt;HTTP 429&lt;/b&gt;', h)

    def test_a_reporting_refusal_keeps_its_reason_as_a_phrase(self):
        h = self.html({'ip': '1.2.3.4', 'errors': {'abuseipdb': 'not reported: not a public address'}})
        self.assertIn('<span>not reported:</span> <span>not a public address</span>', h)

    def test_the_sort_key_is_still_the_plain_string(self):
        s = self.ctx.call('_ipiStatus', {'ip': '1.2.3.4', 'devices': [{'not_blocked': 'auto-block is off'}]})
        self.assertEqual('not blocked: auto-block is off', s)


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
"""The mark on a notification destination's card in Settings: what it says and how it is drawn.

`_destFailingHtml(d)` (app.js) draws the mark from the two fields the settings route adds to a failing destination, `fail_streak` and `fail_class`. The real function
runs under node: nothing for a destination without a streak, the badge with its count and the kind of its last error for one with a streak, the kind as one of the
ten words of the closed list (`other` for anything the server could not have sent), and nothing the server sent is written as markup: the count is a whole number
made here and the kind is looked up in the page's own table, never copied. The six languages are held for each word and for the tooltip.

The card is measured in a browser: tests/test_failing_destination_mark_e2e.py.
"""
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_JS = _ROOT / 'server' / 'html' / 'static' / 'js'
_APP = (_JS / 'app.js').read_text(encoding='utf-8')
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import srcpin  # noqa: E402
from i18n_engine import LANGS, dict_rows  # noqa: E402

_NODE = shutil.which('node')

CLASSES = {'timeout': 'Timed out', 'unreachable': 'Unreachable', 'dns': 'Name lookup failed', 'tls': 'TLS or certificate error', 'auth': 'Credentials rejected',
           'http_4xx': 'Rejected (HTTP 4xx)', 'http_5xx': 'Receiver error (HTTP 5xx)', 'blocked': 'Blocked address', 'config': 'Settings incomplete', 'other': 'Delivery error'}
TITLE = 'Deliveries to this destination have failed several times in a row. The mark clears when one gets through, or when you save a new address, format or credentials for it.'
WORDS = ['Failing', 'Failed in a row', 'Last error', TITLE] + sorted(CLASSES.values())


class TestTheWordsAreTranslated(unittest.TestCase):

    def test_every_word_of_the_mark_has_all_six_languages(self):
        rows = dict_rows()
        missing = {w: sorted(set(LANGS) - rows.get(w, set())) for w in WORDS if set(LANGS) - rows.get(w, set())}
        self.assertEqual(missing, {}, 'words of the destination mark that are not in the dictionary in every language')

    def test_the_page_table_is_the_server_list_and_the_words_above(self):
        block = srcpin.balanced_block(_APP, 'const _DEST_FAIL_CLASSES = ', '{', '}')
        self.assertEqual(dict(re.findall(r"(\w+):\s*'([^']+)'", block)), CLASSES)

    def test_every_class_the_server_can_send_has_a_word(self):
        src = (_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text(encoding='utf-8')
        body = srcpin.py_function(src, '_notify_error_class')
        sent = set(re.findall(r"return '(\w+)'", body))
        self.assertEqual(sent, set(CLASSES), 'the classes the server returns and the words the page has are one list')

    def test_the_card_draws_the_mark_between_the_name_row_and_the_format_row(self):
        # the scanner of srcpin cannot read this function (its templates hold quotes and braces of their own), so the order is read from the function's start
        start = _APP.index('function renderWebhookDests()')
        name, mark, fmt = (_APP.index(t, start) for t in ('data-field="name"', '${_destFailingHtml(d)}', 'data-field="format"'))
        self.assertLess(name, mark)
        self.assertLess(mark, fmt)


_STUB = r'''
function escHtml(s) { return String(s); }
'''


def _run(destinations):
    body = '\n'.join((srcpin.balanced_block(_APP, 'const _DEST_FAIL_CLASSES = ', '{', '}') + ';', srcpin.js_function(_APP, '_destFailingHtml')))
    script = _STUB + body + '\nconsole.log(JSON.stringify(%s.map(_destFailingHtml)));\n' % json.dumps(destinations)
    d = pathlib.Path(tempfile.mkdtemp(prefix='rp-dest-mark-'))
    try:
        f = d / 'mark.js'
        f.write_text(script)
        r = subprocess.run([_NODE, str(f)], capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise AssertionError('node failed: ' + r.stderr[-600:])
        return json.loads(r.stdout)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def text(html):
    """What a person reads in the markup: the text of its elements, spaces collapsed."""
    return re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', html)).strip()


@unittest.skipUnless(_NODE, 'node not installed')
class TestTheMarkIsDrawnFromTheTwoFields(unittest.TestCase):

    def test_a_destination_with_no_streak_has_no_mark(self):
        for d in ({}, {'name': 'x'}, {'fail_streak': 0}, {'fail_streak': None}, {'fail_streak': -3}, {'fail_streak': 'three'}, {'fail_streak': 'NaN'}, {'fail_streak': {}}, None):
            self.assertEqual(_run([d])[0], '', repr(d))

    def test_a_streak_shows_the_badge_the_count_and_the_kind(self):
        got = _run([{'fail_streak': 3, 'fail_class': 'timeout'}, {'fail_streak': 12, 'fail_class': 'http_5xx'}])
        self.assertEqual(text(got[0]), 'Failing Failed in a row 3 Last error Timed out')
        self.assertEqual(text(got[1]), 'Failing Failed in a row 12 Last error Receiver error (HTTP 5xx)')
        self.assertIn('class="mon-status down"', got[0])
        self.assertIn('title="%s"' % TITLE, got[0])

    def test_every_class_of_the_list_has_its_word(self):
        for cls, word in CLASSES.items():
            self.assertTrue(text(_run([{'fail_streak': 3, 'fail_class': cls}])[0]).endswith('Last error ' + word), cls)

    def test_a_class_the_server_could_not_have_sent_is_a_delivery_error_and_is_never_copied(self):
        for cls in ('nope', '', None, '<img src=x onerror=alert(1)>', '__proto__', 'constructor', 'toString', 'hasOwnProperty', 3, ['timeout'], {'a': 1}):
            html = _run([{'fail_streak': 3, 'fail_class': cls}])[0]
            self.assertTrue(text(html).endswith('Last error Delivery error'), repr(cls))
            self.assertNotIn('<img', html)
            self.assertNotIn('onerror', html)

    def test_the_count_is_a_whole_number_made_here(self):
        self.assertTrue(text(_run([{'fail_streak': 3.9, 'fail_class': 'dns'}])[0]).startswith('Failing Failed in a row 3 '))
        self.assertTrue(text(_run([{'fail_streak': '7', 'fail_class': 'dns'}])[0]).startswith('Failing Failed in a row 7 '))
        for hostile in ('<script>alert(1)</script>', 'Infinity', '1e999', '0x10 <b>'):
            self.assertNotIn('<script', _run([{'fail_streak': hostile, 'fail_class': 'dns'}])[0], hostile)
            self.assertNotIn('<b>', _run([{'fail_streak': hostile, 'fail_class': 'dns'}])[0], hostile)


if __name__ == '__main__':
    unittest.main()

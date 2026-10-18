#!/usr/bin/env python3
"""7.4.0: one way to say that an action did not go through.

238 call sites ended `toast(r?.error || 'Failed', 'error')`. When the server gave no reason, the person
read the word "Failed" and nothing else. When it did, api() had already toasted it ("POST /x failed —
why", added in 7.0.2 so that no refusal is silent), so the same sentence came twice.

`failText(r)` and `failToast(r)` (app.js) replace them. Four cases are told apart: the server gave a
reason (the reason), it answered and gave none ("The server refused this and gave no reason.", or "The
server failed and gave no reason." for a 5xx), it did not answer (api() gave null: "The server did not
answer."). `failToast` stays quiet when api() has just announced this very failure, or has just signed
the person out; it speaks for the refusals api() does not announce: a 200 with {ok: false}, and a call
made with {quiet: true}.

api()'s own toast is the reason ALONE as the message, with the request under it ("POST /x · 404") in a
node of its own. The old "POST /x failed — why" was one text node holding a method, a path and the
reason, which no dictionary can match, so no server message could ever be shown in the person's language.

The helpers run in V8 here, with a clock the test moves, because "quiet for five seconds, for this body
only" is a rule about time and identity that no source grep can check.
"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from srcpin import js_function  # noqa: E402

try:
    from py_mini_racer import MiniRacer
    _HAVE_V8 = True
except Exception:                                # pragma: no cover - env dependent
    _HAVE_V8 = False

ROOT = Path(__file__).resolve().parent.parent
JS = ROOT / 'server' / 'html' / 'static' / 'js'
APP = (JS / 'app.js').read_text(encoding='utf-8')

# A fallback that is only the one word. 'Save failed' names the action; this does not.
BARE = re.compile(r"""\|\|\s*(['"])(?:Failed|Error|Failed\.|Error\.)\1""")


def bare_fallbacks(source):
    """(line, text) for each bare fallback outside a comment."""
    out = []
    for no, line in enumerate(source.split('\n'), 1):
        if line.lstrip().startswith('//'):
            continue
        code = re.sub(r'\s//\s.*$', '', line)
        if BARE.search(code):
            out.append((no, line.strip()[:120]))
    return out


class TestNoBareFailedFallback(unittest.TestCase):
    def test_none_left_in_the_client(self):
        found = []
        for p in sorted(JS.glob('*.js')):
            if p.name == 'i18n.js':
                continue
            found += [f'{p.name}:{no}: {text}' for no, text in bare_fallbacks(p.read_text(encoding='utf-8'))]
        self.assertEqual(found, [], 'a bare "Failed" fallback is back; use failToast(r) or failText(r):\n  '
                         + '\n  '.join(found[:20]))

    def test_the_scan_reads_the_client_and_the_rewrite_is_there(self):
        files = [p for p in JS.glob('*.js') if p.name != 'i18n.js']
        self.assertGreater(len(files), 40)
        calls = sum(p.read_text(encoding='utf-8').count('failToast(') for p in files)
        self.assertGreater(calls, 180, 'the failed-action call sites are not using failToast any more')

    def test_the_scanner_can_say_no(self):
        sample = ("toast(r?.error || 'Failed', 'error');\n"
                  "x.textContent = (d && d.error) || \"Failed\";\n"
                  "// toast(r?.error || 'Failed', 'error') in a comment\n"
                  "toast(r?.error || 'Save failed', 'error');\n")
        self.assertEqual([no for no, _t in bare_fallbacks(sample)], [1, 2])


@unittest.skipUnless(_HAVE_V8, 'py_mini_racer (V8) not installed')
class TestTheHelperTellsTheThreeCasesApart(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pieces = [
            re.search(r"let _apiFailureShown = [^\n]*\n", APP).group(0),
            re.search(r"let _apiSignedOutAt = [^\n]*\n", APP).group(0),
            js_function(APP, 'failText'),
            js_function(APP, 'failToast'),
        ]
        cls.source = '\n'.join(pieces)

    def ctx(self, now=1_000_000):
        c = MiniRacer()
        c.eval("var __toasts = []; var __now = %d; "
               "var Date = {now: function () { return __now; }}; "
               "function toast(msg, type, opts) { __toasts.push([msg, type, opts || null]); }" % now)
        c.eval(self.source)
        return c

    def toasts(self, c):
        import json
        return json.loads(c.eval('JSON.stringify(__toasts)'))

    def test_a_reason_is_shown_as_it_is(self):
        c = self.ctx()
        c.eval("failToast({error: 'Host not found'})")
        self.assertEqual(self.toasts(c), [['Host not found', 'error', None]])

    def test_a_message_stands_in_for_an_error(self):
        c = self.ctx()
        c.eval("failToast({ok: false, message: 'Queue is full'})")
        self.assertEqual(self.toasts(c)[0][0], 'Queue is full')

    def test_an_answer_with_no_reason(self):
        c = self.ctx()
        c.eval("failToast({ok: false})")
        self.assertEqual(self.toasts(c)[0][0], 'The server refused this and gave no reason.')

    def test_no_answer_at_all(self):
        c = self.ctx()
        c.eval("failToast(null)")
        self.assertEqual(self.toasts(c)[0][0], 'The server did not answer.')

    def test_a_server_error_without_a_reason_says_the_server_failed(self):
        c = self.ctx()
        self.assertEqual(c.eval("failText({}, 502)"), 'The server failed and gave no reason.')
        self.assertEqual(c.eval("failText({}, 500)"), 'The server failed and gave no reason.')
        self.assertEqual(c.eval("failText({}, 404)"), 'The server refused this and gave no reason.')
        self.assertEqual(c.eval("failText({})"), 'The server refused this and gave no reason.')
        self.assertEqual(c.eval("failText({error: 'Nope'}, 502)"), 'Nope')

    def test_options_reach_the_toast(self):
        c = self.ctx()
        c.eval("failToast({error: 'x'}, {transient: true})")
        self.assertEqual(self.toasts(c)[0][2], {'transient': True})

    def test_quiet_when_api_has_just_said_it(self):
        c = self.ctx()
        c.eval("var body = {error: 'Host not found'}; _apiFailureShown = {body: body, at: __now}; failToast(body)")
        self.assertEqual(self.toasts(c), [])

    def test_quiet_only_for_that_body(self):
        c = self.ctx()
        c.eval("_apiFailureShown = {body: {error: 'a'}, at: __now}; failToast({error: 'b'})")
        self.assertEqual(len(self.toasts(c)), 1)

    def test_a_null_answer_api_announced_is_quiet(self):
        c = self.ctx()
        c.eval("_apiFailureShown = {body: null, at: __now}; failToast(null)")
        self.assertEqual(self.toasts(c), [])

    def test_the_announcement_expires(self):
        c = self.ctx()
        c.eval("var body = {error: 'x'}; _apiFailureShown = {body: body, at: __now}; __now += 5001; failToast(body)")
        self.assertEqual(len(self.toasts(c)), 1)

    def test_signed_out_is_the_message(self):
        c = self.ctx()
        c.eval("_apiSignedOutAt = __now; failToast(null)")
        self.assertEqual(self.toasts(c), [])

    def test_signed_out_a_while_ago_does_not_hide_a_later_failure(self):
        c = self.ctx()
        c.eval("_apiSignedOutAt = __now; __now += 6000; failToast(null)")
        self.assertEqual(len(self.toasts(c)), 1)

    def test_a_reason_still_shows_after_a_sign_out(self):
        """The sign-out rule is for a null answer only; a body with a reason is its own news."""
        c = self.ctx()
        c.eval("_apiSignedOutAt = __now; failToast({error: 'Nope'})")
        self.assertEqual(self.toasts(c)[0][0], 'Nope')


class TestApiRecordsWhatItSaid(unittest.TestCase):
    """The helper is only quiet if api() writes down what it announced."""

    def test_each_place_api_speaks_records_it(self):
        body = js_function(APP, 'api')
        self.assertIn('_apiSignedOutAt = Date.now(); doLogout()', body)
        self.assertEqual(body.count('_apiFailureShown = {body:'), 3,
                         'demo mode, a forced password change and an HTTP error each announce themselves')
        # the HTTP-error record sits inside the same block that toasts it
        block = body[body.index("const _why = "):]
        self.assertIn('_apiFailureShown = {body: _body, at: Date.now()}', block)

    def test_every_sentence_is_translated(self):
        i18n = (JS / 'i18n.js').read_text(encoding='utf-8')
        for key in ('The server did not answer.', 'The server refused this and gave no reason.',
                    'The server failed and gave no reason.'):
            m = re.search(r'^\s*"' + re.escape(key) + r'":\s*\{([^}]*)\}', i18n, re.M)
            self.assertTrue(m, f'{key!r} has no dictionary entry')
            langs = set(re.findall(r'"(\w+)"\s*:', m.group(1)))
            self.assertEqual(langs, {'zh', 'hi', 'es', 'ar', 'de', 'fr'}, key)



def _async_function(source, name):
    """js_function() tries `function name(` first, so it drops the `async` keyword; put it back."""
    body = js_function(source, name)
    at = source.index(body)
    return ('async ' + body) if source[max(0, at - 6):at] == 'async ' else body


@unittest.skipUnless(_HAVE_V8, 'py_mini_racer (V8) not installed')
class TestApiToastsTheReasonAndTheRequest(unittest.TestCase):
    """The real api(), against a fetch that answers what the test says."""

    @classmethod
    def setUpClass(cls):
        cls.source = '\n'.join([
            re.search(r"let _apiFailureShown = [^\n]*\n", APP).group(0),
            re.search(r"let _apiSignedOutAt = [^\n]*\n", APP).group(0),
            js_function(APP, 'failText'),
            js_function(APP, '_toastDetailHtml'),
            _async_function(APP, 'api'),
        ])

    def run_api(self, status, body, *, quiet=False):
        import json
        c = MiniRacer()
        c.eval("""
            var __toasts = [], __logouts = 0, __warn = [];
            function toast(msg, type, opts) { __toasts.push([msg, type, opts || null]); }
            function escHtml(s) { return String(s); }
            function getToken() { return 'tok'; }
            function _rpLoad() {} function _setApiDown() {} function _bcast() {}
            function doLogout() { __logouts += 1; }
            var window = {}; var console = {warn: function () { __warn.push([].slice.call(arguments).join(' ')); }};
            var __reply = null;
            function fetch() { return Promise.resolve(__reply); }
        """)
        c.eval(self.source)
        c.eval("__reply = {status: %d, ok: %s, headers: {get: function () { return null; }}, "
               "clone: function () { return this; }, json: function () { return %s; }};"
               % (status, 'true' if status < 400 else 'false',
                  ('Promise.resolve(%s)' % json.dumps(body)) if body is not None else 'Promise.reject(new Error("not json"))'))
        c.eval("api('POST', '/devices/web01/command', {}%s);" % (', {quiet: true}' if quiet else ''))
        return json.loads(c.eval('JSON.stringify({toasts: __toasts, logouts: __logouts, warn: __warn})'))

    def test_the_reason_is_the_whole_message_and_the_request_sits_under_it(self):
        got = self.run_api(404, {'error': 'Host not found'})
        self.assertEqual(got['toasts'], [['Host not found', 'error', {'detail': 'POST /devices/web01/command · 404'}]])

    def test_the_old_composite_is_gone(self):
        got = self.run_api(403, {'error': 'Forbidden'})
        for msg, _type, _opts in got['toasts']:
            self.assertNotIn('failed', msg)
            self.assertNotIn('/devices', msg)

    def test_no_json_body_on_a_gateway_error(self):
        got = self.run_api(502, None)
        self.assertEqual(got['toasts'][0][0], 'The server failed and gave no reason.')
        self.assertEqual(got['toasts'][0][2], {'detail': 'POST /devices/web01/command · 502'})

    def test_a_refusal_without_a_reason(self):
        got = self.run_api(400, {})
        self.assertEqual(got['toasts'][0][0], 'The server refused this and gave no reason.')

    def test_quiet_calls_and_signed_out_calls_say_nothing(self):
        self.assertEqual(self.run_api(404, {'error': 'x'}, quiet=True)['toasts'], [])
        got = self.run_api(401, {'error': 'Unauthorized'})
        self.assertEqual(got['toasts'], [])
        self.assertEqual(got['logouts'], 1)

    def test_the_request_line_is_a_node_the_translator_skips(self):
        c = MiniRacer()
        c.eval("function escHtml(s) { return String(s).replace(/</g, '&lt;'); }")
        c.eval(js_function(APP, '_toastDetailHtml'))
        html = c.eval("_toastDetailHtml('POST /x · 404')")
        self.assertIn('data-no-i18n', html)
        self.assertIn('dir="ltr"', html)
        self.assertIn('class="toast-detail"', html)
        self.assertEqual(c.eval("_toastDetailHtml('')"), '')
        self.assertEqual(c.eval("_toastDetailHtml(undefined)"), '')
        self.assertIn('&lt;b>', c.eval("_toastDetailHtml('<b>')"))


if __name__ == '__main__':
    unittest.main()

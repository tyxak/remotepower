#!/usr/bin/env python3
"""A failed request must not render as "nothing to see here".

`api()` RESOLVES on 4xx and 5xx — only a 401 and a network failure return null.
So `try { await api(...) } catch` around a load is dead code for a refusal or a
server error, and 72 renderers then do `(data && data.rows) || []`, which turns
an error body into an empty list and paints the empty state.

What an operator saw, all three reproduced against a real failing server:

  Checks         0 Critical / 0 Warning / 0 Unknown / 0 OK, "No checks match."
  Alerts         "No alerts in this view." on a fleet with open alerts
  Confirmations  "Nothing is waiting for approval." — the approval gate for
                 privileged writes, so the approver walks away

Two layers, because 72 call sites is a bigger change than the bug:

1. `api()` now says something on any non-2xx (a toast naming the call and the
   reason). A page may still paint an empty table, but it can no longer do it in
   silence. Opt out with a 4th argument of `{quiet: true}` where a non-2xx is an
   expected answer.
2. The three pages where "all clear" is most dangerous check the body and render
   a real error state with a retry.
"""
import pathlib
import re
import sys
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_JS = _ROOT / 'server' / 'html' / 'static' / 'js'
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import srcpin  # noqa: E402


class TestApiSurfacesFailure(unittest.TestCase):

    def setUp(self):
        self.body = srcpin.js_function((_JS / 'app.js').read_text(), 'api')

    def test_it_reports_a_non_2xx(self):
        self.assertRegex(self.body, r'!r\.ok\b',
                         'api() no longer notices a failed response at all')
        seg = self.body[self.body.index('!r.ok'):]
        self.assertIn('toast(', seg[:600],
                      'the failure is noticed and still not said out loud')

    def test_a_401_stays_silent(self):
        """401 already logs the operator out; a toast on top of that is noise
        at exactly the moment the page is being replaced."""
        self.assertRegex(self.body, r'!r\.ok[^\n]*401')

    def test_callers_can_opt_out(self):
        """A probe or a poll for something not yet created answers non-2xx as a
        matter of course; those must not toast on every tick."""
        self.assertRegex(self.body, r'extra && extra\.quiet')

    def test_the_body_is_still_returned(self):
        """Callers that inspect `r.error` must keep working — the change adds a
        message, it does not change what api() hands back."""
        tail = self.body[self.body.index('!r.ok'):]
        self.assertRegex(tail, r'return _body;')


class TestTheThreePagesRenderAnError(unittest.TestCase):
    """Where an empty state reads as 'all clear', the difference between 'no
    rows' and 'we could not ask' has to be visible on the page itself."""

    CASES = (
        ('app-checks.js', 'loadChecks'),
        ('app-alerts.js', 'loadAlerts'),
        ('app.js', 'loadConfirmations'),
    )

    @staticmethod
    def _code(fname, fn):
        """The function with // comments dropped.

        Every one of these blocks is introduced by a comment explaining the bug
        and prints `${data.error}` in its message, so asserting over the raw
        text matches the explanation whether or not the check is there — which
        is exactly what a fail-demo of the alerts case revealed.
        """
        body = srcpin.js_function((_JS / fname).read_text(), fn)
        return '\n'.join(l for l in body.splitlines()
                          if not l.lstrip().startswith('//'))

    def test_each_checks_the_body_before_rendering(self):
        for fname, fn in self.CASES:
            code = self._code(fname, fn)
            self.assertRegex(
                code, r'if\s*\(\s*!data\s*\|\|\s*data\.error\s*\)',
                f'{fname}:{fn} still treats an error body as empty')

    def test_each_returns_rather_than_falling_through(self):
        for fname, fn in self.CASES:
            code = self._code(fname, fn)
            m = re.search(r'if\s*\(\s*!data\s*\|\|\s*data\.error\s*\).{0,400}', code, re.S)
            self.assertTrue(m, f'{fname}:{fn} has no error branch')
            self.assertIn('return', m.group(0),
                          f'{fname}:{fn} detects the error and renders anyway')

    def test_each_offers_a_retry(self):
        for fname, fn in self.CASES:
            body = srcpin.js_function((_JS / fname).read_text(), fn)
            self.assertIn('_errorState(', body,
                          f'{fname}:{fn} has no error state to show')

    def test_the_error_text_carries_the_reason(self):
        """"Something went wrong" sends the operator to the logs; the server
        already said what happened."""
        for fname, fn in self.CASES:
            code = self._code(fname, fn)
            m = re.search(r'if\s*\(\s*!data\s*\|\|\s*data\.error\s*\).{0,400}', code, re.S)
            self.assertTrue(m, f'{fname}:{fn} has no error branch')
            self.assertRegex(m.group(0), r'\$\{data\.error\}',
                             f'{fname}:{fn} discards the reason')


class TestTheClassIsUnderstood(unittest.TestCase):
    """The premise, pinned. If api() ever starts THROWING on 4xx/5xx, the
    reasoning above stops applying and the catch blocks come back to life."""

    def test_api_does_not_throw_on_a_server_error(self):
        body = srcpin.js_function((_JS / 'app.js').read_text(), 'api')
        tail = body[body.index('r.status === 403'):]
        self.assertNotRegex(tail, r'\bthrow\b',
                            'api() now throws on an error status — revisit '
                            'every catch block this file reasons about')

    def test_only_401_returns_null_early(self):
        body = srcpin.js_function((_JS / 'app.js').read_text(), 'api')
        self.assertRegex(body, r'r\.status === 401.*doLogout\(\); return null;')


if __name__ == '__main__':
    unittest.main()

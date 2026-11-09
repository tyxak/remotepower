#!/usr/bin/env python3
"""8.0.0: the public OIDC callback writes what it was given to the log as one line.

`GET /api/auth/oidc/callback` needs no sign-in, and when the query holds `error` it wrote `error` and `error_description` to the error log as they came. A line break in either
value started a line of its own, so anyone who could reach the server could add a `[remotepower] ...` entry to the log an operator reads. It was found by a scanner that reported
the route as an SQL injection (it is not: the value never reaches a query, and the answer is the same redirect for every value; the scanner read the server's own rate limit, a 429,
as a difference between its true and false probes), and reading the handler found the log line. The values go through the two log helpers the heartbeat already uses (`_log_field` for the error code, cut to 80 characters, the codes of RFC 6749 are short, and
`_log_text` for the description, cut to 240), which replace every control character and line separator.
"""

import contextlib
import io
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-oidclog-'))
_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_TESTS.parent / 'server' / 'cgi-bin'))

from test_ip_intel import _fresh_api  # noqa: E402


def setUpModule():
    __import__("sys").path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import env_guard

    env_guard.save(__name__)


def tearDownModule():
    import env_guard

    env_guard.restore(__name__)


class TestTheCallbackLog(unittest.TestCase):
    _n = 0

    @classmethod
    def setUpClass(cls):
        cls.api = _fresh_api()

    def call(self, query):
        """(what went to stderr, what went to stdout) of one request to the callback, from an address of its own so the per-address limit never answers."""
        type(self)._n += 1
        api = self.api
        api._begin_request()
        os.environ.update(REQUEST_METHOD='GET', PATH_INFO='/api/auth/oidc/callback', QUERY_STRING=query, REMOTE_ADDR='203.0.113.%d' % (10 + type(self)._n))
        err, out = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            try:
                api.handle_oidc_callback()
            except SystemExit:
                pass
        return err.getvalue(), out.getvalue()

    def test_a_plain_error_is_one_line(self):
        err, out = self.call('error=access_denied&error_description=User+said+no&state=s')
        self.assertEqual(err, '[remotepower] OIDC IdP returned error=access_denied desc=User said no\n', 'a normal error reads as it always did')
        self.assertIn('Location: /?oidc_error=access_denied', out)

    def test_a_line_break_in_either_value_does_not_start_a_line(self):
        err, out = self.call('error=x%0aFAKE&error_description=a%0d%0a%5Bremotepower%5D+forged+entry%0a%5Bremotepower%5D+another')
        self.assertEqual(err.count('\n'), 1, 'one request, one line: %r' % err)
        self.assertTrue(err.startswith('[remotepower] OIDC IdP returned error='), err)
        self.assertNotIn('\n[remotepower] forged', err)
        self.assertIn('a??[remotepower]?forged', err.replace(' ', '?'), 'control: each break became a character of its own, it was not dropped')
        self.assertEqual(out.count('Location:'), 1, out)
        self.assertNotIn('\r', out.split('Location:', 1)[1].split('\n', 1)[0], 'the redirect carries no raw break either')

    def test_the_other_line_separators_are_replaced_too(self):
        err, _ = self.call('error=x&error_description=a%E2%80%A8b%C2%85c%0Bd%0Ce%00f')
        for ch in ('\u2028', '\u0085', '\x0b', '\x0c', '\x00'):
            self.assertNotIn(ch, err, repr(ch))
        self.assertEqual(len(err.splitlines()), 1, 'str.splitlines() is the reader that breaks at all of them: %r' % err)

    def test_the_values_are_cut(self):
        err, out = self.call('error=%s&error_description=%s' % ('e' * 5000, 'd' * 5000))
        m = re.fullmatch(r'\[remotepower\] OIDC IdP returned error=(e+) desc=(d+)\n', err)
        self.assertTrue(m, err[:120])
        self.assertEqual((len(m.group(1)), len(m.group(2))), (80, 240), 'the error code is cut to 80 characters and the description to 240')
        self.assertLess(len(out), 400, 'the redirect is short too')

    def test_the_helper_replaces_every_control_character_and_cuts(self):
        f = self.api._log_text
        self.assertEqual(f('a\nb\rc\td\x00e\x7ff\x9fg\u2028h\u2029i', 100), 'a?b?c?d?e?f?g?h?i')
        self.assertEqual(f('kept: spaces, ünï©ode and punctuation!', 100), 'kept: spaces, ünï©ode and punctuation!')
        self.assertEqual(f('x' * 500, 240), 'x' * 240)
        self.assertEqual(f(None, 10), 'None', 'what is not text is made text')


if __name__ == '__main__':
    unittest.main()

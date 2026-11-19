#!/usr/bin/env python3
"""8.0.2 review (F9): a path segment that is a capability link does not leave the host in a sample, and is not shown or published.

The sensor remembers the refused requests of every address for fifteen minutes and sends the last three as samples when a ban engine or the WAF flags the address. A reset or
invite token that is a path segment (`/reset-password/Zm9v...`) went into the page and, with examples on, into a public report. A segment of 24 or more letters, digits,
hyphens and underscores with both a letter and a digit is replaced by `~token~`, by the agent before the sample is sent and by the server when it rebuilds the sample; the two
copies are held equal here.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-sample-token-'))
sys.path.insert(0, str(ROOT / 'server' / 'cgi-bin'))
import threat_evidence as te  # noqa: E402


def _agent():
    spec = importlib.util.spec_from_file_location('agent_sample_token', ROOT / 'client' / 'remotepower-agent.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


AGENT = _agent()
TOKEN = 'Zm9vYmFyU2VjcmV0VG9rZW4xMjM0NTY3ODkw'

MASKED = {
    '/reset-password/' + TOKEN: '/reset-password/~token~',
    '/invite/' + TOKEN + '/accept': '/invite/~token~/accept',
    '/s/ab12cd34ef56ab12cd34ef56ab12cd34': '/s/~token~',                      # a 32-character hex session id
    '/x/' + 'a1' * 20 + '?next=/': '/x/~token~',
}
KEPT = {
    '/wp-login.php': '/wp-login.php',
    '/u/a-very-long-name-with-many-words-but-no-digits.php': '/u/a-very-long-name-with-many-words-but-no-digits.php',
    '/' + 'a' * 40: '/' + 'a' * 40,                                         # letters only
    '/' + '1' * 40: '/' + '1' * 40,                                          # digits only
    '/short1/abc123': '/short1/abc123',
    '/jquery-3.6.0.min.js': '/jquery-3.6.0.min.js',
}


class TestTheTwoCopies(unittest.TestCase):

    def test_a_capability_link_is_masked_by_the_server_and_by_the_agent(self):
        for raw, want in MASKED.items():
            with self.subTest(raw=raw[:50]):
                self.assertEqual(te.clean_path(raw), want)
                self.assertEqual(AGENT._ts_clean_path(raw), want)
                self.assertNotIn(TOKEN, te.clean_path(raw))

    def test_control_an_ordinary_path_is_as_it_was(self):
        for raw, want in KEPT.items():
            with self.subTest(raw=raw[:50]):
                self.assertEqual(te.clean_path(raw), want)
                self.assertEqual(AGENT._ts_clean_path(raw), want)

    def test_cleaning_what_was_returned_returns_it_unchanged(self):
        for raw in list(MASKED) + list(KEPT):
            once = te.clean_path(raw)
            self.assertEqual(te.clean_path(once), once)
            self.assertEqual(AGENT._ts_clean_path(once), AGENT._ts_clean_path(raw))

    def test_a_sample_the_server_rebuilds_carries_no_token(self):
        smp = te.normalize_sample({'f': 'web', 'm': 'GET', 'p': '/reset-password/' + TOKEN, 'c': 410, 't': 1790000000}, now=1790000100)
        self.assertEqual(smp['p'], '/reset-password/~token~')
        self.assertNotIn(TOKEN, te.sample_text(smp))


if __name__ == '__main__':
    unittest.main()

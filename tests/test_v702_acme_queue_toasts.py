#!/usr/bin/env python3
"""Two of three ACME actions reported plain success when their log was lost.

Every ACME mutation — issue, force-renew, revoke — goes through one server
funnel, `_acme_queue_command`. It reserves a log file so the run shows up as
`pending` immediately, and when that reservation fails the action still goes
ahead (better a renewal with no log than no renewal) and the response carries
`log_error`.

Only `acmeForceRenew` read it. `acmeRevoke` toasted a plain success, and the
issue path toasted "output appears in the Logs tab once the agent runs it" —
which is the sentence that is untrue in exactly this case, and the field report
that started this was worded the same way: "the cert was renewed, but no logs
or confirmation."

A half-applied rule: the one correct call site makes the file read as though the
handling is there. So the check here is not "is it handled" but the ratio —
every client call site hitting an endpoint that can return `log_error` must go
through the shared helper.
"""
import pathlib
import re
import subprocess
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_JS = _ROOT / 'server' / 'html' / 'static' / 'js' / 'app-dns.js'
_SRV = _ROOT / 'server' / 'cgi-bin' / 'acme_handlers.py'


def _node():
    try:
        subprocess.run(['node', '--version'], capture_output=True, check=True)
        return True
    except Exception:
        return False


class TestTheServerStillReportsIt(unittest.TestCase):
    """Premise. If the funnel stops returning log_error the client checks below
    are asserting about a field that no longer exists."""

    def test_the_funnel_returns_log_error(self):
        src = _SRV.read_text()
        self.assertIn("out['log_error'] = log_error", src)

    def test_three_actions_go_through_the_funnel(self):
        """The population. Adding a fourth mutation without routing its toast
        through the helper puts this back where it started."""
        src = _SRV.read_text()
        actions = set(re.findall(r"_acme_queue_command\(dev_id, '(\w+)'", src))
        self.assertEqual({'issue', 'renew', 'revoke'}, actions,
                         'the set of funnelled ACME actions changed — check '
                         'the new one surfaces log_error client-side')


class TestEveryCallSiteSurfacesIt(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.js = _JS.read_text()

    def _sites(self):
        """Client POSTs to an endpoint the funnel serves, and whether the
        following block routes through the shared helper."""
        out = []
        for m in re.finditer(r"api\('POST',\s*`/acme/[^`]*`[^)]*\)", self.js):
            path = m.group(0)
            if not re.search(r'/(renew|revoke|issue)`', path):
                continue          # cancel/ignore bypass the funnel by design
            fn = re.findall(r'async function (\w+)', self.js[:m.start()])[-1]
            out.append((fn, '_acmeQueuedToast' in self.js[m.end():m.end() + 800]))
        return out

    def test_the_enumeration_found_all_three(self):
        """Positive control. A regex that matched nothing would make the ratio
        below trivially perfect — which is the shape of the bug this file is
        about."""
        sites = self._sites()
        self.assertEqual(3, len(sites), f'expected 3 funnelled call sites, '
                                        f'found {sites}')

    def test_every_one_of_them_uses_the_shared_helper(self):
        missing = [fn for fn, ok in self._sites() if not ok]
        self.assertEqual([], missing,
                         f'these report success without checking log_error: '
                         f'{missing}')

    def test_there_is_one_helper_not_three_inline_copies(self):
        self.assertEqual(1, self.js.count('function _acmeQueuedToast'))
        # No call site should still build the warning text itself.
        self.assertEqual(1, self.js.count('could not be reserved'),
                         'an inline copy of the warning is back')


@unittest.skipUnless(_node(), 'node not available')
class TestTheHelperSaysTheRightThing(unittest.TestCase):
    """Source checks prove the wiring. Only running it proves the operator is
    told the truth in both branches."""

    def _run(self, resp, ok_msg, what):
        js = _JS.read_text()
        i = js.index('function _acmeQueuedToast')
        helper = js[i:js.index('\n}\n', i) + 3]
        import json
        prog = ("let out=[];function toast(m,k,o){out.push({m:m,k:k});}\n"
                + helper
                + f"\n_acmeQueuedToast({json.dumps(resp)}, {json.dumps(ok_msg)},"
                  f" {json.dumps(what)});\nconsole.log(JSON.stringify(out[0]));")
        r = subprocess.run(['node', '-e', prog], capture_output=True, text=True)
        self.assertEqual(0, r.returncode, r.stderr)
        return json.loads(r.stdout)

    def test_a_clean_queue_is_a_success_toast(self):
        got = self._run({'ok': True}, 'Renew queued — output in detail view',
                        'The renewal will still run.')
        self.assertEqual('success', got['k'])
        self.assertNotIn('could not be reserved', got['m'])

    def test_a_lost_log_is_a_warning_that_says_what_did_happen(self):
        got = self._run({'ok': True, 'log_error': 'OSError: read-only fs'},
                        'Renew queued — output in detail view',
                        'The renewal will still run.')
        self.assertEqual('warning', got['k'])
        self.assertIn('OSError: read-only fs', got['m'])
        self.assertIn('will still run', got['m'],
                      'the operator must be told the action DID happen, or '
                      'they will run it again')
        self.assertIn('Logs tab will stay empty', got['m'])

    def test_the_issue_message_stops_promising_logs(self):
        """The issue toast's success text promises the Logs tab. In the
        log_error branch that promise has to go, not just be appended to."""
        got = self._run(
            {'ok': True, 'log_error': 'OSError: disk full'},
            'Issue queued for a.example.com — output appears in the Logs tab '
            'once the agent runs it',
            'The issuance will still run.')
        self.assertNotIn('output appears in the Logs tab', got['m'])
        self.assertIn('a.example.com', got['m'], 'the domain is still named')


if __name__ == '__main__':
    unittest.main()

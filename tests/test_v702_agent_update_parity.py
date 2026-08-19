#!/usr/bin/env python3
"""macOS was the one agent of three that would install an unsigned update.

`release.pub` pinned on a host means "only install builds signed by this key".
The Linux and Windows agents both fetch the detached signature and refuse
without a valid one; the macOS agent verified only the sha256 the SERVER
advertised. That checks the download arrived intact and says nothing about who
built it — so a server that could serve a modified agent binary could also serve
a matching sha256, and macOS would install it as root under launchd. An operator
who pinned the key had two of three agents enforcing it and no way to tell.

macOS also had no downgrade guard, so an agent pointed at a rolled-back server
would walk itself backwards on hash drift.

Both server endpoints already existed (`/api/agent/mac/signature` is in the
auth-exempt list next to the Windows one, added in v6.4.2) — only the agent
never called them.
"""
import re
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).parent))
import srcpin  # noqa: E402

_UPDATE_FNS = (
    ('client/remotepower-agent.py', 'check_for_update'),
    ('client/remotepower-agent-mac.py', '_self_update'),
    ('client/remotepower-agent-win.py', '_self_update'),
)


def _body(rel, fn):
    return srcpin.py_function((_ROOT / rel).read_text(), fn)


def _code(rel, fn):
    """The same body with comment lines dropped. Every one of these guards is
    introduced by a comment that names it, so asserting over the raw text finds
    the explanation whether or not the code is there — which is how a fail-demo
    of the Windows downgrade guard came back green."""
    return '\n'.join(ln for ln in _body(rel, fn).splitlines()
                     if not ln.lstrip().startswith('#'))


class TestEveryAgentGatesItsSelfUpdate(unittest.TestCase):

    def test_the_update_functions_are_all_still_here(self):
        """Positive control for the three tests below: if a rename silently
        broke the extraction, every assertion after it would be about an empty
        string."""
        for rel, fn in _UPDATE_FNS:
            self.assertGreater(len(_body(rel, fn)), 500, f'{rel}:{fn}')

    def test_each_one_reads_the_pinned_key(self):
        for rel, fn in _UPDATE_FNS:
            self.assertRegex(_code(rel, fn), r'_release_pubkey\w*\(\)',
                             f'{rel} installs without consulting release.pub')

    def test_each_one_verifies_a_detached_signature(self):
        for rel, fn in _UPDATE_FNS:
            self.assertRegex(_code(rel, fn), r'_verify_detached_sig\w*\(',
                             f'{rel} never verifies the signature it fetched')

    def test_each_one_fails_closed_when_updates_must_be_signed(self):
        for rel, fn in _UPDATE_FNS:
            self.assertRegex(_code(rel, fn), r'_require_signed_updates\w*\(\)',
                             f'{rel} ignores require-signed-updates')

    def test_each_one_fetches_the_signature_for_its_own_platform(self):
        for rel, fn, want in (
                ('client/remotepower-agent.py', 'check_for_update', '/agent/signature'),
                ('client/remotepower-agent-mac.py', '_self_update', '/api/agent/mac/signature'),
                ('client/remotepower-agent-win.py', '_self_update', '/api/agent/win/signature')):
            self.assertIn(want, _code(rel, fn), rel)

    def test_none_of_them_auto_downgrades(self):
        for rel, fn in _UPDATE_FNS:
            code = _code(rel, fn)
            self.assertIn('_vtuple', code,
                          f'{rel} does not compare versions at all')
            self.assertRegex(code, r'_rv\s*<\s*_lv',
                             f'{rel} compares versions and does not act on it')


class TestTheMacMarkerAndEndpointExist(unittest.TestCase):

    def test_the_marker_path_matches_the_other_agents(self):
        """A different filename would make the operator's marker inert on
        macOS — the same failure wearing a typo."""
        for rel in ('client/remotepower-agent.py', 'client/remotepower-agent-mac.py'):
            self.assertIn('/etc/remotepower/require-signed-updates',
                          (_ROOT / rel).read_text(), rel)

    def test_the_signature_route_is_auth_exempt(self):
        """The agent fetches it token-free during self-update. When the Windows
        leg was missing from this list the agent downloaded the binary, 403'd on
        the signature and hit its fail-closed branch — self-update died
        fleet-wide while the heartbeat kept everything looking healthy."""
        src = (_ROOT / 'server/cgi-bin/api.py').read_text()
        for p in ("'/api/agent/signature'", "'/api/agent/win/signature'",
                  "'/api/agent/mac/signature'"):
            self.assertIn(p, src, p)

    def test_the_stale_docstring_is_gone(self):
        """It said signature pinning was "not yet wired on macOS" — which was
        true, and is the kind of line that outlives the fact."""
        body = _body('client/remotepower-agent-mac.py', '_self_update')
        self.assertNotIn('not yet wired', body)


class TestTheMacUpdateStillWorks(unittest.TestCase):
    """A gate that refuses everything would pass every assertion above."""

    def test_no_key_pinned_leaves_the_flow_alone(self):
        body = _body('client/remotepower-agent-mac.py', '_self_update')
        m = re.search(r'pubkey = _release_pubkey_mac\(\)(.{0,900})', body, re.S)
        self.assertTrue(m, 'the gate moved')
        seg = m.group(1)
        self.assertIn('if pubkey:', seg,
                      'verification must be conditional on a key being pinned — '
                      'unpinned hosts keep the sha256-only behaviour')
        self.assertIn('_require_signed_updates_mac()', seg)


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
"""Full tunnel must not claim IPv6 it does not route.

The Settings hint said clients route all traffic "(0.0.0.0/0, ::/0)" through
the hub. `client_allowed_ips` returns `"0.0.0.0/0"` and nothing else, and there
is no IPv6 anywhere in WG Access — no v6 pool, no ip6 masquerade, no inet6
rules (`grep -ci 'ipv6|::/0|ip6|inet6'` over wg_access.py and vpn_handlers.py
is 0). So on a dual-stack client IPv6 traffic BYPASSES the tunnel entirely,
which is the opposite of what "full tunnel" implies to anyone reading it.

The tell that this was aspiration rather than a regression: the client-side
config builder's fallback was `'0.0.0.0/0, ::/0'` — dead code, because the
server always supplies the value — and the hint appears to have been written
against that fallback rather than against what the server sends.

WHY THE FIX IS THE TEXT AND NOT THE CODE. Sending `::/0` would route IPv6 into
a tunnel the hub cannot forward, blackholing it rather than protecting it. Real
IPv6 support is a feature; claiming it is a lie. So the claim goes, the
limitation is stated in the UI and the docs, and the behaviour is unchanged and
pinned below.
"""
import importlib.util
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location('wg_access_v643', _CGI / 'wg_access.py')
W = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(W)


class TestBehaviourIsUnchanged(unittest.TestCase):
    """Pinned deliberately: this change touches text only. If someone later
    decides to route ::/0 they should have to edit this test and think about
    blackholing."""

    def test_full_tunnel_is_ipv4_only(self):
        self.assertEqual(
            W.client_allowed_ips({'pool': '10.97.3.0/24', 'allow_internet': True}, []),
            '0.0.0.0/0')

    def test_split_tunnel_unchanged(self):
        self.assertEqual(
            W.client_allowed_ips({'pool': '10.97.3.0/24', 'allow_internet': False}, []),
            '10.97.3.1/32')


class TestNothingClaimsIPv6AnyMore(unittest.TestCase):
    def test_the_settings_hint_does_not_promise_it(self):
        html = (_ROOT / 'server' / 'html' / 'index.html').read_text()
        i = html.index('vpn-tunnel-allow-internet')
        hint = html[i:i + 700]
        self.assertNotIn('::/0', hint,
                         'the full-tunnel hint promises IPv6 the hub cannot '
                         'route — on a dual-stack client it silently bypasses '
                         'the tunnel')

    def test_the_hint_states_the_limitation(self):
        """Removing the false claim is not enough. Someone turning on "full
        tunnel" for privacy reasons needs to be told IPv6 is not covered."""
        html = (_ROOT / 'server' / 'html' / 'index.html').read_text()
        i = html.index('vpn-tunnel-allow-internet')
        self.assertIn('IPv6 is not routed', html[i:i + 700])

    def test_the_client_config_fallback_matches_the_server(self):
        js = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'wg-access.js').read_text()
        i = js.index("lines.push('AllowedIPs = '")
        self.assertNotIn('::/0', js[i:i + 200],
                         'the fallback implies IPv6 is routed; it is dead code '
                         'and it is what the false hint was written against')

    def test_the_docs_state_it_too(self):
        doc = (_ROOT / 'docs' / 'wg-access.md').read_text()
        self.assertIn('IPv6 is not routed', doc)


class TestThePremiseIsStillTrue(unittest.TestCase):
    """If WG Access ever gains real IPv6, this fails and the text above should
    be revisited rather than left understating the product."""

    def test_wg_access_has_no_ipv6_support(self):
        import re
        src = (_CGI / 'wg_access.py').read_text() + (_CGI / 'vpn_handlers.py').read_text()
        # strip comments/docstrings — v6.4.3 added prose ABOUT ipv6 to both
        code = re.sub(r'#[^\n]*', '', src)
        code = re.sub(r'"""..*?"""', '', code, flags=re.S)
        for token in ('::/0', 'inet6', 'ip6tables', 'AF_INET6'):
            self.assertNotIn(token, code,
                             f'{token} appears in the code — WG Access may now '
                             'support IPv6, in which case the "not routed" '
                             'wording is understating it')


if __name__ == '__main__':
    unittest.main()

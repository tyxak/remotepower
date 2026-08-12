#!/usr/bin/env python3
"""A blocked WireGuard port and an unused tunnel are indistinguishable.

The single most common WG-Access failure is the router not forwarding the UDP
listen port. What the operator sees is: config correct, server up, client
imported, and nothing ever connects. What the page said was "0 connected now".

Why this is an INFERENCE and not a probe. WireGuard does not reply to
unauthenticated packets — that silence is a deliberate design property, not a
bug. So an external UDP probe receives nothing whether the port is open and
working or dropped by a firewall, and a check built on it would report the same
result in both cases: a gate that measures nothing, which is precisely the
class this release exists to close. The evidence that actually distinguishes
the two is whether a handshake has ever happened, which the product already
collects.

The restart trap is the load-bearing detail. `last_handshake` is OVERWRITTEN
from the live `wg show dump` on every poll, so it returns to 0 whenever the
interface restarts. An inference built on `last_handshake == 0` would therefore
accuse a perfectly healthy tunnel of being firewalled after every reboot — a
warning that is wrong that often is one operators learn to ignore, taking the
true ones with it. `ever_handshaked` only ever goes 0 -> 1.
"""
import importlib.util
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v643vpn-'))

_spec = importlib.util.spec_from_file_location('api_v643_vpn', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('api', api)
_spec.loader.exec_module(api)
import vpn_handlers as V  # noqa: E402

_VPN_SRC = (_CGI / 'vpn_handlers.py').read_text()
_JS = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-vpn.js').read_text()
_HTML = (_ROOT / 'server' / 'html' / 'index.html').read_text()

NOW = int(time.time())
OLD = NOW - 90000          # comfortably past the grace window
TUN = {'enabled': True, 'listen_port': 51820}


def verdict(clients, tunnel=None):
    return V._vpn_inbound_verdict(tunnel or TUN, clients, NOW)


class TestItAccusesOnlyOnEvidence(unittest.TestCase):
    def test_an_old_tunnel_that_never_handshaked_is_flagged(self):
        """The finding this exists to make."""
        v = verdict([{'created_at': OLD}])
        self.assertEqual(v['state'], 'never')
        self.assertEqual(v['port'], 51820)

    def test_a_tunnel_that_has_ever_handshaked_is_not(self):
        """One handshake proves inbound UDP reached this host. A current
        outage is then something else, and blaming the firewall is wrong."""
        self.assertEqual(verdict([{'created_at': OLD, 'ever_handshaked': 1}])['state'],
                         'proven')

    def test_a_restart_does_not_resurrect_the_accusation(self):
        """THE regression this guards. wg was restarted, so last_handshake is
        back to 0 — but the tunnel has demonstrably worked."""
        v = verdict([{'created_at': OLD, 'ever_handshaked': 1, 'last_handshake': 0}])
        self.assertEqual(v['state'], 'proven')

    def test_a_currently_connected_client_counts_without_the_flag(self):
        """An install that predates the flag still has live handshakes."""
        self.assertEqual(verdict([{'created_at': OLD, 'last_handshake': NOW - 10}])['state'],
                         'proven')


class TestItStaysQuietWhenItCannotKnow(unittest.TestCase):
    def test_a_disabled_tunnel_says_nothing(self):
        self.assertEqual(verdict([{'created_at': OLD}],
                                 {'enabled': False, 'listen_port': 51820})['state'],
                         'unknown')

    def test_a_tunnel_with_no_clients_says_nothing(self):
        self.assertEqual(verdict([])['state'], 'unknown')

    def test_a_freshly_created_client_says_nothing(self):
        """"I made the config a minute ago and have not imported it yet" is the
        overwhelmingly common state in the first minutes and is not a fault."""
        self.assertEqual(verdict([{'created_at': NOW - 60}])['state'], 'unknown')

    def test_the_grace_window_is_generous(self):
        self.assertGreaterEqual(V._VPN_INBOUND_GRACE_S, 15 * 60)

    def test_one_new_client_does_not_reset_a_long_broken_tunnel(self):
        """Oldest client decides. Otherwise adding a peer each week hides a
        tunnel that has never once worked."""
        self.assertEqual(verdict([{'created_at': NOW - 10}, {'created_at': OLD}])['state'],
                         'never')


class TestTheFlagIsMonotonic(unittest.TestCase):
    def test_the_poll_sets_it_only_on_a_real_handshake(self):
        self.assertIn("if d['last_handshake']:", _VPN_SRC)
        self.assertIn("c['ever_handshaked'] = 1", _VPN_SRC)

    def test_nothing_ever_clears_it(self):
        """A single `= 0` anywhere reintroduces the restart bug."""
        self.assertNotRegex(_VPN_SRC, r"ever_handshaked'\]\s*=\s*0")
        self.assertNotRegex(_VPN_SRC, r"pop\('ever_handshaked'")
        for src in (_VPN_SRC, (_CGI / 'wg_access.py').read_text()):
            self.assertNotIn("del c['ever_handshaked']", src)

    def test_it_is_set_where_last_handshake_is_set(self):
        """If the two ever drift apart, the flag stops tracking reality."""
        i = _VPN_SRC.find("c['last_handshake'] = d['last_handshake']")
        self.assertGreater(i, 0)
        self.assertIn('ever_handshaked', _VPN_SRC[i:i + 900])


class TestItReachesTheOperator(unittest.TestCase):
    def test_the_verdict_is_in_the_stats_response(self):
        self.assertIn("'inbound': inbound", _VPN_SRC)
        self.assertIn('_vpn_inbound_verdict(t, clients, now)', _VPN_SRC)

    def test_the_client_paints_it(self):
        self.assertIn('function _vpnPaintInbound(', _JS)
        self.assertIn('_vpnPaintInbound(st)', _JS)
        self.assertIn('id="vpn-sel-inbound"', _HTML)

    def test_only_the_never_verdict_is_painted(self):
        """A permanently-visible "we cannot tell" box is noise, and noise is
        how a real warning gets ignored later."""
        body = re.search(r'function _vpnPaintInbound\(st\) \{.*?\n\}', _JS, re.S).group(0)
        self.assertIn("inb.state !== 'never'", body)
        self.assertIn('el.hidden = true', body)

    def test_it_names_the_port_and_the_thing_to_check(self):
        body = re.search(r'function _vpnPaintInbound\(st\) \{.*?\n\}', _JS, re.S).group(0)
        self.assertIn('inb.port', body)
        # Match on the RENDERED text, not the source: the message is assembled
        # from adjacent template literals, so "the port " and "forward on your
        # router" sit in different string literals and the phrase spanning them
        # never appears in the file. Asserting on source text here would have
        # failed against a message that reads exactly right.
        rendered = re.sub(r"`\s*\n\s*\+ `", '', body)
        self.assertIn('port forward', rendered)
        self.assertIn('firewall', rendered)

    def test_it_says_a_port_scan_cannot_settle_it(self):
        """Without this the operator's next move is nmap, which returns
        open|filtered forever and teaches them nothing."""
        body = re.search(r'function _vpnPaintInbound\(st\) \{.*?\n\}', _JS, re.S).group(0)
        self.assertIn('unauthenticated', body)

    def test_it_builds_the_dom_rather_than_interpolating_html(self):
        """CSP, and the message embeds a server-supplied port."""
        body = re.search(r'function _vpnPaintInbound\(st\) \{.*?\n\}', _JS, re.S).group(0)
        self.assertNotIn('innerHTML', body)
        self.assertIn('createElement', body)

    def test_it_points_at_the_documentation(self):
        body = re.search(r'function _vpnPaintInbound\(st\) \{.*?\n\}', _JS, re.S).group(0)
        self.assertIn('docs/wg-access.md', body)
        self.assertTrue((_ROOT / 'docs' / 'wg-access.md').is_file())


if __name__ == '__main__':
    unittest.main()

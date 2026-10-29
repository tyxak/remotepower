#!/usr/bin/env python3
"""v7.4.5, issue #55: a host can be marked internal.

"The world-exposed check grades any service listening on 0.0.0.0 or [::] as 'world'. On a host whose
interfaces are all on private networks behind a NAT firewall with no port forwards, those listeners are
only reachable from the LAN, so the host carries a permanent warning that isn't a real exposure. Docker
makes it constant, since published ports default to 0.0.0.0. [...] any interface with a public IPv4 or
global IPv6 address (2000::/3) keeps the host's listeners graded 'world', since NAT doesn't protect IPv6.
The grade should read 'assumed internal' rather than plain 'lan', and new-listener detection should stay
active on internal hosts so a newly opened port is still flagged."

This file holds the pure rules: which addresses count as private, what a report's address list can be
taken to say, and what the switch does to the rows. The ingest, the route and the pages have their own
files. Every rule here is one that fails closed: what cannot be checked is not assumed.
"""
import copy
import sys
import unittest
from pathlib import Path

_CGI = Path(__file__).resolve().parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

import exposure_scope as ex  # noqa: E402


class TestWhichAddressesArePrivate(unittest.TestCase):

    PRIVATE = (
        "10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255", "192.168.1.10",
        "169.254.10.10", "127.0.0.1", "100.64.0.1", "100.127.255.254",    # the last two: Tailscale's range
        "fd00::1", "fc00::5", "fdff:ffff::1", "fe80::1", "fe80::1%eth0", "::1",
        "::ffff:10.0.0.1", "::ffff:192.168.1.1",                          # an IPv4 address in IPv6 dress
        " 10.0.0.1 ",
    )
    NOT_PRIVATE = (
        "8.8.8.8", "203.0.113.5", "192.0.2.1", "198.51.100.7", "1.1.1.1",
        "172.15.255.255", "172.32.0.1", "100.63.255.255", "100.128.0.1",  # one step outside each private block
        "11.0.0.1", "192.169.0.1", "169.255.0.1",
        "0.0.0.0", "255.255.255.255",
        "2001:db8::1", "2606:4700::1111", "2a00::1", "3fff::1",
        "2002:c000:204::1",        # 6to4: reachable from the internet, though the standard library calls it private
        "2001::1",                 # Teredo: the same
        "::", "::ffff:8.8.8.8", "ff02::1", "fec0::1",
    )
    NOT_ADDRESSES = ("", " ", "nope", "10.0.0", "10.0.0.1/24", "999.1.1.1", "fe80::g", None, 5, 10.0, [], {}, True, b"10.0.0.1")

    def test_private_ranges(self):
        for a in self.PRIVATE:
            self.assertTrue(ex.is_private(a), a)

    def test_everything_else_is_not_private(self):
        for a in self.NOT_PRIVATE:
            self.assertFalse(ex.is_private(a), a)

    def test_what_is_not_an_address_is_not_private(self):
        for a in self.NOT_ADDRESSES:
            self.assertFalse(ex.is_private(a), repr(a))

    def test_the_standard_librarys_own_private_would_have_let_a_tunnel_through(self):
        """The reason is_private is not used: it calls these private, and they are not."""
        import ipaddress
        for a in ("2002:c000:204::1", "2001::1"):
            self.assertTrue(ipaddress.ip_address(a).is_private, a + " (precondition)")
            self.assertFalse(ex.is_private(a), a)


class TestWhatAReportCanSay(unittest.TestCase):

    def test_a_list_of_addresses_is_kept_as_text_without_repeats(self):
        self.assertEqual(ex.clean_addresses(["10.0.0.5", "fd00::1", "10.0.0.5", "FD00:0::1"]),
                         ["10.0.0.5", "fd00::1"])
        self.assertEqual(ex.clean_addresses(["::ffff:10.0.0.5"]), ["10.0.0.5"])

    def test_an_empty_list_stays_empty(self):
        self.assertEqual(ex.clean_addresses([]), [])

    def test_what_cannot_be_the_whole_truth_is_unknown(self):
        for raw in (None, "10.0.0.1", {"a": 1}, 5, True):
            self.assertIsNone(ex.clean_addresses(raw), repr(raw))
        self.assertIsNone(ex.clean_addresses(["10.0.0.1", "not an address"]), "one bad entry spoils the list")
        self.assertIsNone(ex.clean_addresses(["10.0.0.1", None]))
        self.assertIsNone(ex.clean_addresses(["10.0.0.1", ["10.0.0.2"]]))

    def test_a_list_longer_than_the_limit_is_unknown_and_one_at_the_limit_is_not(self):
        at = [f"10.0.{i // 250}.{i % 250 + 1}" for i in range(ex.MAX_ADDRESSES)]
        self.assertEqual(len(ex.clean_addresses(at)), ex.MAX_ADDRESSES)
        self.assertIsNone(ex.clean_addresses(at + ["10.9.9.9"]),
                          "a list cut short could hide the one public address")

    def test_assess(self):
        self.assertEqual(ex.assess(["10.0.0.5", "fd00::1"]), ("private", []))
        self.assertEqual(ex.assess(["10.0.0.5", "203.0.113.5", "2606:4700::1111"]),
                         ("public", ["203.0.113.5", "2606:4700::1111"]))
        for nothing in (None, [], "10.0.0.5", {}, 5):
            self.assertEqual(ex.assess(nothing), ("unknown", []), repr(nothing))

    def test_an_empty_list_is_not_private(self):
        """A probe that found no address has not seen the host. Vacuous truth is the wrong answer here."""
        self.assertEqual(ex.assess([])[0], "unknown")


class TestWhatTheSwitchDoes(unittest.TestCase):

    def test_off_is_off_whatever_the_addresses_say(self):
        for addrs in (["10.0.0.5"], ["203.0.113.5"], None, []):
            st = ex.host_state(False, addrs)
            self.assertEqual((st["internal"], st["assumed"], st["blocked"]), (False, False, ""), addrs)
            st = ex.host_state(None, addrs)
            self.assertEqual((st["internal"], st["assumed"]), (False, False))

    def test_on_with_private_addresses_holds(self):
        st = ex.host_state(True, ["192.168.1.5", "172.17.0.1", "fd12::5"])
        self.assertEqual(st, {"internal": True, "assumed": True, "blocked": "", "public": []})

    def test_on_with_a_public_address_does_not_hold_and_says_which(self):
        st = ex.host_state(True, ["192.168.1.5", "203.0.113.9"])
        self.assertEqual(st, {"internal": True, "assumed": False, "blocked": "public_address",
                              "public": ["203.0.113.9"]})

    def test_a_global_ipv6_address_blocks_too(self):
        """The reporter's own condition: a NAT does not protect IPv6."""
        st = ex.host_state(True, ["192.168.1.5", "2a01:4f8::5"])
        self.assertEqual((st["assumed"], st["blocked"], st["public"]), (False, "public_address", ["2a01:4f8::5"]))

    def test_on_without_address_data_does_not_hold(self):
        for addrs in (None, []):
            st = ex.host_state(True, addrs)
            self.assertEqual((st["assumed"], st["blocked"]), (False, "no_address_data"), addrs)
        self.assertIn("no_address_data", ex.REASONS)
        self.assertIn("public_address", ex.REASONS)

    def test_only_a_real_true_turns_it_on(self):
        """A stored value written by hand, an import or a form is not a decision."""
        for odd in ("true", "yes", 1, [1], {"a": 1}, "False"):
            self.assertFalse(ex.host_state(odd, ["10.0.0.5"])["internal"], repr(odd))

    def test_the_list_of_public_addresses_is_capped(self):
        addrs = ["10.0.0.5"] + [f"203.0.113.{i}" for i in range(1, 30)]
        self.assertEqual(len(ex.host_state(True, addrs)["public"]), 8)


def _ports():
    return [
        {"proto": "tcp", "port": 443, "process": "nginx", "addr": "0.0.0.0", "scope": "world"},
        {"proto": "tcp", "port": 53, "process": "resolved", "addr": "127.0.0.53", "scope": "local"},
        {"proto": "udp", "port": 53, "process": "AdGuardHome", "addr": "10.0.0.2", "scope": "lan"},
        {"proto": "tcp", "port": 8080, "process": "docker-proxy", "addr": "::", "scope": "world"},
    ]


class TestRegradingTheRows(unittest.TestCase):

    def test_a_wildcard_listener_becomes_lan_and_is_marked(self):
        rows = _ports()
        self.assertEqual(ex.regrade(rows, True), 2)
        self.assertEqual([(r["port"], r["scope"], r.get("assumed")) for r in rows],
                         [(443, "lan", True), (53, "local", None), (53, "lan", None), (8080, "lan", True)])

    def test_the_agents_own_lan_and_local_rows_are_never_marked(self):
        rows = _ports()
        ex.regrade(rows, True)
        self.assertNotIn("assumed", rows[1])
        self.assertNotIn("assumed", rows[2], "a row the agent itself graded lan is not an assumption")

    def test_it_is_idempotent(self):
        rows = _ports()
        ex.regrade(rows, True)
        again = copy.deepcopy(rows)
        self.assertEqual(ex.regrade(again, True), 0)
        self.assertEqual(again, rows)

    def test_turning_it_off_restores_exactly_what_the_agent_sent(self):
        original = _ports()
        rows = copy.deepcopy(original)
        ex.regrade(rows, True)
        self.assertNotEqual(rows, original)
        self.assertEqual(ex.regrade(rows, False), 2)
        self.assertEqual(rows, original)

    def test_off_on_rows_that_were_never_marked_changes_nothing(self):
        rows = _ports()
        self.assertEqual(ex.regrade(rows, False), 0)
        self.assertEqual(rows, _ports())

    def test_what_is_not_a_list_of_rows_is_left_alone(self):
        for junk in (None, {}, "x", 5):
            self.assertEqual(ex.regrade(junk, True), 0)
        rows = [None, "x", 5, _ports()[0]]
        self.assertEqual(ex.regrade(rows, True), 1)

    def test_apply_reads_the_switch_and_the_records_own_addresses(self):
        si = {"listening_ports": _ports(), "host_addresses": ["192.168.1.5"]}
        self.assertEqual(ex.apply(True, si), 2)
        self.assertEqual([r["scope"] for r in si["listening_ports"]], ["lan", "local", "lan", "lan"])
        si["host_addresses"] = ["192.168.1.5", "203.0.113.9"]
        self.assertEqual(ex.apply(True, si), 2, "a public address appeared: both rows go back")
        self.assertEqual([r["scope"] for r in si["listening_ports"]], ["world", "local", "lan", "world"])
        self.assertTrue(all("assumed" not in r for r in si["listening_ports"]))

    def test_apply_with_no_address_data_assumes_nothing(self):
        for si in ({"listening_ports": _ports()}, {"listening_ports": _ports(), "host_addresses": []}):
            self.assertEqual(ex.apply(True, si), 0)
            self.assertEqual(si["listening_ports"], _ports())

    def test_apply_with_the_switch_off_assumes_nothing(self):
        si = {"listening_ports": _ports(), "host_addresses": ["192.168.1.5"]}
        self.assertEqual(ex.apply(False, si), 0)
        self.assertEqual(si["listening_ports"], _ports())

    def test_apply_survives_a_record_without_ports_or_without_a_dict(self):
        self.assertEqual(ex.apply(True, {"host_addresses": ["10.0.0.5"]}), 0)
        for junk in (None, [], "x", 5):
            self.assertEqual(ex.apply(True, junk), 0)


if __name__ == "__main__":
    unittest.main()

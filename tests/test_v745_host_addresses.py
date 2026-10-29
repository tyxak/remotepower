#!/usr/bin/env python3
"""v7.4.5, issue #55: the Linux agent reports the addresses the host holds.

A host an operator marked internal keeps that grade only while every address it holds is private, and
the server could not check that: the agent reported IPv4 addresses only, as `network`. This is the
producer side. The fixtures below are what `ip -j addr` prints, and the last test hands the agent's own
answer to the server's reader, so the two halves are shown to agree rather than each to its own idea of
the other.
"""
import ast
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import exposure_scope as ex  # noqa: E402


def _lo():
    return {"ifname": "lo", "addr_info": [
        {"family": "inet", "local": "127.0.0.1", "prefixlen": 8, "scope": "host", "label": "lo"},
        {"family": "inet6", "local": "::1", "prefixlen": 128, "scope": "host"}]}


def _eth0(*extra):
    return {"ifname": "eth0", "addr_info": [
        {"family": "inet", "local": "192.168.1.20", "prefixlen": 24, "scope": "global", "label": "eth0"},
        {"family": "inet6", "local": "fe80::a00:27ff:fe4e:66a1", "prefixlen": 64, "scope": "link"},
        *extra]}


def _docker0():
    return {"ifname": "docker0", "addr_info": [
        {"family": "inet", "local": "172.17.0.1", "prefixlen": 16, "scope": "global", "label": "docker0"}]}


def _veth():
    return {"ifname": "veth3a2b1c", "addr_info": []}


class TestTheAgentReportsItsAddresses(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from test_v643_smart_standby import _agent
        cls.ag = _agent()

    def probe(self, rows=None, raw=None, boom=None):
        """What get_host_addresses() answers when `ip -j addr` prints these rows (or this raw text)."""
        ag = self.ag
        saved = ag.subprocess.check_output

        def fake(argv, *a, **k):
            self.assertEqual(list(argv), ["ip", "-j", "addr"])
            if boom is not None:
                raise boom
            return raw if raw is not None else json.dumps(rows)

        ag.subprocess.check_output = fake
        try:
            return ag.get_host_addresses()
        finally:
            ag.subprocess.check_output = saved

    def test_a_host_with_private_addresses_lists_them_and_nothing_else(self):
        got = self.probe([_lo(), _eth0(), _docker0(), _veth()])
        self.assertEqual(got, ["192.168.1.20", "172.17.0.1"],
                         "the loopback, the link-local address and the empty interface are left out")

    def test_a_global_ipv6_address_is_in_the_list(self):
        got = self.probe([_lo(), _eth0({"family": "inet6", "local": "2a01:4f8::5", "prefixlen": 64, "scope": "global"})])
        self.assertEqual(got, ["192.168.1.20", "2a01:4f8::5"])

    def test_a_public_ipv4_address_is_in_the_list(self):
        got = self.probe([{"ifname": "eth0", "addr_info": [
            {"family": "inet", "local": "203.0.113.9", "prefixlen": 24, "scope": "global"}]}])
        self.assertEqual(got, ["203.0.113.9"])

    def test_a_public_address_on_the_loopback_is_kept(self):
        """A virtual address on lo is reachable, so it counts. 127.0.0.1 and ::1 are host scope and do not."""
        lo = _lo()
        lo["addr_info"].append({"family": "inet", "local": "203.0.113.77", "prefixlen": 32, "scope": "global"})
        got = self.probe([lo, _eth0()])
        self.assertEqual(got, ["203.0.113.77", "192.168.1.20"])

    def test_it_is_none_when_the_probe_fails_and_never_an_empty_list(self):
        for boom in (FileNotFoundError("ip"), OSError("denied"), TimeoutError("slow")):
            self.assertIsNone(self.probe(boom=boom), repr(boom))
        import subprocess
        self.assertIsNone(self.probe(boom=subprocess.CalledProcessError(1, ["ip"])))
        for raw in ("", "not json", "{}", "null", '"x"'):
            self.assertIsNone(self.probe(raw=raw), repr(raw))

    def test_it_is_none_when_there_is_nothing_to_report(self):
        self.assertIsNone(self.probe([_lo()]))
        self.assertIsNone(self.probe([]))
        self.assertIsNone(self.probe([_lo(), {"ifname": "eth0", "addr_info": [
            {"family": "inet6", "local": "fe80::1", "prefixlen": 64, "scope": "link"}]}]))

    def test_it_tolerates_rows_of_the_wrong_shape(self):
        got = self.probe([None, "x", 5, {"ifname": "a", "addr_info": None}, {"ifname": "b", "addr_info": ["x", None]},
                          _eth0()])
        self.assertEqual(got, ["192.168.1.20"])

    def test_more_than_the_server_accepts_is_none(self):
        def many(n):
            return [{"ifname": "br0", "addr_info": [
                {"family": "inet", "local": f"10.1.{i // 250}.{i % 250 + 1}", "prefixlen": 32, "scope": "global"}
                for i in range(n)]}]
        self.assertEqual(len(self.probe(many(ex.MAX_ADDRESSES))), ex.MAX_ADDRESSES)
        self.assertIsNone(self.probe(many(ex.MAX_ADDRESSES + 1)))

    def test_the_server_reads_what_the_agent_sends(self):
        """The producer's own answer, through the consumer's own reader."""
        mixed = self.probe([_lo(), _eth0({"family": "inet6", "local": "2a01:4f8::5", "prefixlen": 64, "scope": "global"}),
                            _docker0()])
        self.assertEqual(ex.clean_addresses(mixed), mixed)
        self.assertEqual(ex.assess(ex.clean_addresses(mixed)), ("public", ["2a01:4f8::5"]))
        quiet = self.probe([_lo(), _eth0(), _docker0(), _veth()])
        self.assertEqual(ex.assess(ex.clean_addresses(quiet)), ("private", []))


class TestTheKeyIsSentFromTheRightPlace(unittest.TestCase):
    """The poll loop is not unit-drivable, so this reads it: the key is stored from inside the
    `if send_sysinfo:` block, after `sysinfo` exists. The ECC and host-key collectors once shipped dead
    from outside it (tests/test_v612_agent_sysinfo_scope.py holds the general rule)."""

    def test_host_addresses_is_stored_inside_if_send_sysinfo(self):
        tree = ast.parse((ROOT / "client" / "remotepower-agent.py").read_text())
        hb = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "heartbeat")
        stores = 0
        for node in ast.walk(hb):
            if isinstance(node, ast.If) and isinstance(node.test, ast.Name) and node.test.id == "send_sysinfo":
                for sub in ast.walk(node):
                    if (isinstance(sub, ast.Assign) and isinstance(sub.targets[0], ast.Subscript)
                            and isinstance(sub.targets[0].value, ast.Name) and sub.targets[0].value.id == "sysinfo"
                            and isinstance(sub.targets[0].slice, ast.Constant)
                            and sub.targets[0].slice.value == "host_addresses"):
                        stores += 1
        self.assertEqual(stores, 1)

    def test_it_is_not_among_the_fields_an_agent_may_leave_out_as_unchanged(self):
        """It is small and decides a grade, so every full report carries it."""
        src = (ROOT / "client" / "remotepower-agent.py").read_text()
        i = src.index("_DELTA_SYSINFO_FIELDS = (")
        self.assertNotIn("host_addresses", src[i:src.index(")", i)])

    def test_the_extensionless_agent_carries_it_too(self):
        self.assertEqual((ROOT / "client" / "remotepower-agent.py").read_bytes(),
                         (ROOT / "client" / "remotepower-agent").read_bytes())
        self.assertIn("def get_host_addresses", (ROOT / "client" / "remotepower-agent").read_text())


if __name__ == "__main__":
    unittest.main()

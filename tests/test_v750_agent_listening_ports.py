#!/usr/bin/env python3
"""7.5.0 agent review: any user on a host can no longer make the agent go quiet by listening on many ports.

get_host_health() builds the list of listening ports. For every socket psutil reported it searched the list from the start (so n
sockets cost n squared steps) and built a process object to name the owner. Any user may hold tens of thousands of listening sockets
(the hard limit on open files is 500,000 under systemd), so the one thread that also sends the heartbeat could be kept busy for as
long as the user liked: measured with 12,000 listeners 3.3 seconds, with 40,000 listeners 33 seconds, every tenth poll. The list
that is sent has 80 entries. One table lookup per socket now, and only the 80 are named.

RP_TEST_AGENT points the test at another copy (a `git show HEAD:` of the old file shows it fail).
"""
import collections
import importlib.machinery
import importlib.util
import os
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-data-"))

ROOT = Path(__file__).resolve().parent.parent
AGENT = Path(os.environ.get("RP_TEST_AGENT") or ROOT / "client" / "remotepower-agent.py")


def load_agent(name="agent_v750_ports"):
    loader = importlib.machinery.SourceFileLoader(name, str(AGENT))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


agent = load_agent()

Addr = collections.namedtuple("Addr", "ip port")
Conn = collections.namedtuple("Conn", "laddr raddr type status pid")


class TestListeningPortsDoNotCostSquaredTime(unittest.TestCase):
    N = 20000

    def run_section(self, conns):
        named = []

        class FakeProcess:
            def __init__(self, pid):
                named.append(pid)

            def name(self):
                return "proc%d" % named[-1]
        patches = [
            mock.patch.object(agent, "_PSUTIL", True),
            mock.patch.object(agent, "_which", lambda prog, _c=None: None),            # no ss, no zpool, no tools at all
            mock.patch.object(agent._psutil, "net_connections", lambda kind="inet": conns),
            mock.patch.object(agent._psutil, "Process", FakeProcess),
            mock.patch.object(agent.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a[0], 1, stdout="", stderr="")),
        ]
        for p in patches:
            p.start()
        try:
            t0 = time.monotonic()
            out = agent.get_host_health()
            return out, named, time.monotonic() - t0
        finally:
            for p in reversed(patches):
                p.stop()

    def many(self, n):
        # one process holds them all, as a user's script would; the ports run from 1100 up
        return [Conn(Addr("127.0.0.1", 1100 + i), None, socket.SOCK_STREAM, "LISTEN", 4242) for i in range(n)]

    def test_twenty_thousand_listeners_take_a_fraction_of_a_second_and_name_only_what_is_sent(self):
        out, named, took = self.run_section(self.many(self.N))
        ports = out["listening_ports"]
        self.assertEqual(len(ports), 80)
        self.assertEqual([p["port"] for p in ports], list(range(1100, 1180)), "the 80 sent are the 80 lowest ports, as before")
        self.assertLessEqual(len(named), 80, f"{len(named)} process objects were built for {self.N} sockets")
        self.assertLess(took, 3.0, f"{self.N} listeners took {took:.1f} s")

    def test_control_the_list_that_is_sent_is_what_it_was(self):
        conns = [Conn(Addr("0.0.0.0", 22), None, socket.SOCK_STREAM, "LISTEN", 10),
                 Conn(Addr("::", 22), None, socket.SOCK_STREAM, "LISTEN", 11),          # the same port on IPv6: one entry
                 Conn(Addr("127.0.0.1", 5432), None, socket.SOCK_STREAM, "LISTEN", 12),
                 Conn(Addr("0.0.0.0", 53), None, socket.SOCK_DGRAM, "NONE", 13),
                 Conn(Addr("10.0.0.2", 80), Addr("10.0.0.9", 5555), socket.SOCK_STREAM, "ESTABLISHED", 14)]   # not a listener
        out, _named, _took = self.run_section(conns)
        rows = {(p["proto"], p["port"]): p for p in out["listening_ports"]}
        self.assertEqual(sorted(rows), [("tcp", 22), ("tcp", 5432), ("udp", 53)])
        self.assertEqual(rows[("tcp", 22)]["process"], "proc10")           # named from the first socket that had an owner
        self.assertEqual(rows[("tcp", 5432)]["process"], "proc12")
        self.assertEqual(rows[("udp", 53)]["process"], "proc13")
        self.assertEqual([p["port"] for p in out["listening_ports"]], [22, 53, 5432])

    def test_a_port_whose_first_socket_had_no_owner_is_named_from_a_later_one(self):
        conns = [Conn(Addr("0.0.0.0", 8080), None, socket.SOCK_STREAM, "LISTEN", None),
                 Conn(Addr("::", 8080), None, socket.SOCK_STREAM, "LISTEN", 77)]
        out, _named, _took = self.run_section(conns)
        self.assertEqual(out["listening_ports"][0]["process"], "proc77")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""8.0.0: the SSH monitor on the identification lines real systems send, through the three engines that run it.

tests/test_v800_real_sshd.py starts the OpenSSH server of the machine it runs on, and what that server sends differs by machine: a bare line on Arch, and on the Ubuntu runner of
the 8.0.0 push "Ubuntu-2ubuntu3.8" after the version, which that test could not know in advance. This one serves the lines of real systems from a socket, so every machine runs
all of them and none needs an sshd. Each line must come back whole (one printable line, cut at 80 characters) from the server's own module, from the copy in the Linux agent and
from the copy in the satellite, and the three must say the same.
"""
import importlib.machinery
import importlib.util
import re
import ssl
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_v800_protocol_probes as pp  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
P = pp.P
BANNER_CAP = 80                  # protocol_probes shows one printable line, cut at this many characters

# Lines as these systems send them. The Ubuntu ones are what the runner answered: its own sshd's line, and the same with the comment a test server adds after it.
LINES = [
    "SSH-2.0-OpenSSH_10.6",                                                  # upstream OpenSSH, no distribution comment
    "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",                              # Ubuntu 24.04
    "SSH-2.0-OpenSSH_10.2p1 Ubuntu-2ubuntu3.8",                              # Ubuntu 26.04, the runner's sshd on its own
    "SSH-2.0-OpenSSH_10.2p1 Ubuntu-2ubuntu3.8 Ubuntu-3ubuntu13.5",           # the same with a second comment after it (the line the runner's test server sent)
    "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",                                # Debian 12: the package version has a plus sign
    "SSH-2.0-OpenSSH_9.7 FreeBSD-20240701",
    "SSH-2.0-dropbear_2022.83",
    "SSH-1.99-OpenSSH_3.9p1",                                                # an old server that speaks both protocol versions
    "SSH-2.0-OpenSSH_10.2p1 " + "Ubuntu-2ubuntu3.8 " * 8 + "end",            # longer than the cap: cut, and cut the same way by all three
]


def _load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)             # type: ignore[arg-type]
    loader.exec_module(mod)                                  # type: ignore[union-attr]
    return mod


def _same(detail):
    return re.sub(r"\d+ms", "Nms", detail)


class TestTheThreeEnginesOnTheLinesOfRealSystems(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.agent = _load("rp_agent_ssh_lines", ROOT / "client" / "remotepower-agent.py")
        cls.satellite = _load("rp_sat_ssh_lines", ROOT / "client" / "remotepower-satellite.py")

    def engines(self, port):
        ctx = ssl.create_default_context()

        def keep(_ip):
            return True             # the loopback is the point of this test
        return {
            "server": P.run("ssh", "127.0.0.1", port, {}, peer_ok=keep, ssl_ctx=ctx, timeout=5),
            "agent": self.agent._pp_run("ssh", "127.0.0.1", port, {}, peer_ok=keep, ssl_ctx=ctx, timeout=5),
            "satellite": self.satellite._pp_run("ssh", "127.0.0.1", port, {}, peer_ok=keep, ssl_ctx=ctx, timeout=5),
        }

    def serve(self, data):
        s = pp._Tcp(pp.banner(data))
        self.addCleanup(s.stop)
        return s.port

    def test_every_line_comes_back_whole_from_all_three_engines_and_they_say_the_same(self):
        for line in LINES:
            with self.subTest(line=line):
                got = self.engines(self.serve(line.encode() + b"\r\n"))
                want = " ".join(line.split())[:BANNER_CAP]
                for name, (ok, detail) in got.items():
                    self.assertTrue(ok, (name, detail))
                    self.assertRegex(detail, r" · \d+ms$", name)
                    self.assertEqual(detail.rsplit(" · ", 1)[0], want, name)
                self.assertEqual(len({(ok, _same(detail)) for ok, detail in got.values()}), 1, got)

    def test_the_check_sees_a_line_that_is_cut_short(self):
        """Control: the comparison is against the whole line, so an engine that dropped everything after the first space would fail it."""
        got = self.engines(self.serve(b"SSH-2.0-OpenSSH_10.2p1 Ubuntu-2ubuntu3.8 Ubuntu-3ubuntu13.5\r\n"))
        for name, (ok, detail) in got.items():
            self.assertNotEqual(detail.rsplit(" · ", 1)[0], "SSH-2.0-OpenSSH_10.2p1", name)
            self.assertIn("Ubuntu-3ubuntu13.5", detail, name)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""8.0.0: the SSH monitor against a real OpenSSH server, with the three engines that run it.

The other tests of the handshake monitors use servers written for the test (tests/test_v800_protocol_probes.py), which agree with the author's reading of the protocol.
This one starts the OpenSSH server that is installed on the machine (`sshd`, as the user running the tests, on a loopback port, with a host key made for the test and no way
to sign in) and probes it the way the monitor does, with the server's own module, the copy in the Linux agent and the copy in the satellite: the identification line is
read, the answer is the same in all three, and a port with nothing behind it is refused in the same words.

Skips when there is no `sshd` or `ssh-keygen` here, or when `sshd` cannot be started without root (the reason is in the skip). Nothing is downloaded and nothing is
listened on outside the loopback. The SMTP, IMAP and NTP monitors have no such test: no mail server and no NTP server is installed here.
"""
import importlib.machinery
import importlib.util
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_v800_protocol_probes as pp  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
P = pp.P
_STATE = {}

# Debian and Ubuntu servers send their package version after the protocol version ("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"), so most servers a monitor meets have a
# comment on the line, and the test server sends one on every machine. What the whole line is depends on the machine: a bare sshd sends none of its own, the Ubuntu
# runner's sshd sends "Ubuntu-2ubuntu3.8" first and this one comes after it. So the test never spells the line out: it reads the line from the socket itself and holds
# the engines to that (the first version of this test assumed a bare sshd and failed on the runner of the 8.0.0 push, the second assumed one comment and failed there too).
ADDENDUM = "Ubuntu-3ubuntu13.5"
BANNER_CAP = 80                  # protocol_probes shows one printable line, cut at this many characters


def _load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)             # type: ignore[arg-type]
    loader.exec_module(mod)                                  # type: ignore[union-attr]
    return mod


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _find(name):
    return shutil.which(name) or next((p for p in ("/usr/sbin/" + name, "/usr/bin/" + name, "/usr/local/sbin/" + name) if os.access(p, os.X_OK)), None)


def setUpModule():
    sshd, keygen = _find("sshd"), _find("ssh-keygen")
    if not sshd or not keygen:
        raise unittest.SkipTest("no OpenSSH server (sshd, ssh-keygen) is installed here")
    work = Path(tempfile.mkdtemp(prefix="rp-real-sshd-"))
    key = work / "host_key"
    made = subprocess.run([keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(key)], capture_output=True, timeout=60)
    if made.returncode != 0:
        raise unittest.SkipTest("ssh-keygen failed: " + made.stderr.decode(errors="replace")[-200:])
    port = _free_port()
    (work / "sshd_config").write_text("\n".join([
        "Port %d" % port, "ListenAddress 127.0.0.1", "HostKey %s" % key, "PidFile %s" % (work / "sshd.pid"), "UsePAM no", "PasswordAuthentication no",
        "KbdInteractiveAuthentication no", "PubkeyAuthentication no", "StrictModes no", "LogLevel ERROR", "VersionAddendum " + ADDENDUM, ""]))
    log = open(work / "sshd.log", "w")
    proc = subprocess.Popen([sshd, "-D", "-e", "-f", str(work / "sshd_config")], stdout=log, stderr=log, stdin=subprocess.DEVNULL)
    deadline = time.time() + 15
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            break
        except OSError:
            time.sleep(0.2)
    else:
        proc.kill()
    if proc.poll() is not None:
        log.close()
        raise unittest.SkipTest("sshd could not be started without root: " + (work / "sshd.log").read_text()[-300:].strip())
    _STATE.update(proc=proc, port=port, log=log, work=work, agent=_load("rp_agent_real_sshd", ROOT / "client" / "remotepower-agent.py"),
                  satellite=_load("rp_sat_real_sshd", ROOT / "client" / "remotepower-satellite.py"))


def tearDownModule():
    proc = _STATE.get("proc")
    if proc is not None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    if _STATE.get("log"):
        _STATE["log"].close()
    if _STATE.get("work"):
        shutil.rmtree(str(_STATE["work"]), ignore_errors=True)


def _same(detail):
    return re.sub(r"\d+ms", "Nms", detail)


class TestTheSshMonitorAgainstARealOpenSshServer(unittest.TestCase):

    def engines(self, port):
        ctx = ssl.create_default_context()

        def keep(_ip):
            return True             # the loopback is the point of this test
        return {
            "server": P.run("ssh", "127.0.0.1", port, {}, peer_ok=keep, ssl_ctx=ctx, timeout=5),
            "agent": _STATE["agent"]._pp_run("ssh", "127.0.0.1", port, {}, peer_ok=keep, ssl_ctx=ctx, timeout=5),
            "satellite": _STATE["satellite"]._pp_run("ssh", "127.0.0.1", port, {}, peer_ok=keep, ssl_ctx=ctx, timeout=5),
        }

    @staticmethod
    def raw_banner(port):
        """The identification line the server sends, read without any of the engines."""
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            data = b""
            while b"\n" not in data and len(data) < 255:
                chunk = s.recv(255)
                if not chunk:
                    break
                data += chunk
        finally:
            s.close()
        return data.split(b"\n", 1)[0].decode("ascii", "replace")

    def test_all_three_engines_read_the_identification_line_of_a_real_server_and_say_the_same(self):
        line = self.raw_banner(_STATE["port"])
        self.assertRegex(line, r"^SSH-2\.0-OpenSSH_[0-9.p]+", "the server is a real OpenSSH: " + line)
        want = " ".join(line.split())[:BANNER_CAP]
        got = self.engines(_STATE["port"])
        for name, (ok, detail) in got.items():
            self.assertTrue(ok, (name, detail))
            self.assertRegex(detail, r" · \d+ms$", name)
            self.assertEqual(detail.rsplit(" · ", 1)[0], want, "%s shows the line the server sent, and the line is %r" % (name, line))
        self.assertEqual(len({(ok, _same(detail)) for ok, detail in got.values()}), 1, got)

    def test_the_whole_monitor_path_of_the_agent_and_of_the_satellite_gives_an_ok_row_with_the_banner(self):
        spec = {"label": "jump", "type": "ssh", "target": "127.0.0.1:%d" % _STATE["port"], "host": "127.0.0.1", "port": _STATE["port"]}
        for name in ("agent", "satellite"):
            row = _STATE[name]._probe_run_one(dict(spec))
            self.assertEqual((row["ok"], row["type"], row["label"]), (True, "ssh", "jump"), (name, row))
            self.assertTrue(row["detail"].startswith("SSH-2.0-OpenSSH_"), (name, row))

    def test_a_port_with_nothing_behind_it_is_refused_in_the_same_words_by_all_three(self):
        got = self.engines(_free_port())
        for name, (ok, detail) in got.items():
            self.assertEqual((ok, detail), (False, "the connection was refused"), name)

    def test_the_server_is_a_real_openssh_and_not_a_banner_written_for_the_test(self):
        s = socket.create_connection(("127.0.0.1", _STATE["port"]), timeout=5)
        try:
            s.sendall(b"SSH-2.0-RemotePowerTest\r\n")
            data = b""
            deadline = time.time() + 5
            s.settimeout(1)
            while time.time() < deadline and len(data) < 200:
                try:
                    chunk = s.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
        finally:
            s.close()
        self.assertTrue(data.startswith(b"SSH-2.0-OpenSSH_"), data[:40])
        self.assertIn(b"curve25519", data, "after the banner it sends its key exchange proposal, which a test server does not")


if __name__ == "__main__":
    unittest.main()

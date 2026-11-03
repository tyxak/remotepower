#!/usr/bin/env python3
"""7.4.9: a monitor can be probed from a host's own agent.

The server probes from where it is, and a satellite from its own network. A monitor can now name a host (`via_host`): the Linux agent
of that host runs the probe from there, which is the only way to watch a service on the host's own loopback or on a network only that
host reaches. The server validates the monitor (the host, the type, the address), sends the specs in the heartbeat response, takes
the results from a later heartbeat and keeps them where a satellite's go, with the same history and the same down and up alerts.

The agent's probes run for real here, against servers started on the loopback: a listening and a closed TCP port, and an HTTP server
that answers 200, 404, 500 and a redirect, answers HEAD with 405, never answers, and presents a self-signed certificate. `ping` is not
run (it needs a permission a test machine may not have); its argument list is checked instead.
"""
import http.server
import importlib.machinery
import importlib.util
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v749-hp-"))
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))
_ldr = importlib.machinery.SourceFileLoader("api_hp", str(ROOT / "server" / "cgi-bin" / "api.py"))
_spec = importlib.util.spec_from_loader("api_hp", _ldr)
api: Any = importlib.util.module_from_spec(_spec)         # type: ignore[arg-type]
_ldr.exec_module(api)                                     # type: ignore[union-attr]

_REAL_GETADDRINFO = socket.getaddrinfo


def load_agent():
    loader = importlib.machinery.SourceFileLoader("agent_hp_under_test", str(ROOT / "client" / "remotepower-agent.py"))
    spec = importlib.util.spec_from_loader("agent_hp_under_test", loader)
    agent = importlib.util.module_from_spec(spec)           # type: ignore[arg-type]
    loader.exec_module(agent)                                # type: ignore[union-attr]
    return agent


# ── the agent, against real servers ───────────────────────────────────────────────────────────────────────────────────
class _Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    other_port = 0


class _Handler(http.server.BaseHTTPRequestHandler):
    hits: list = []
    server: Any

    def log_message(self, format, *args):
        pass

    def _answer(self, head):
        _Handler.hits.append((self.command, self.path, self.headers.get("User-Agent", "")))
        if self.path == "/ok":
            self._send(200, b"hello world, all fine", head)
        elif self.path == "/missing":
            self._send(404, b"nope", head)
        elif self.path == "/boom":
            self._send(500, b"oops", head)
        elif self.path == "/moved":
            self.send_response(301)
            self.send_header("Location", f"http://127.0.0.1:{self.server.other_port}/landed")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/no-head":
            if head:
                self._send(405, b"", True)
            else:
                self._send(200, b"get works", False)
        elif self.path == "/hang":
            time.sleep(8)
        else:
            self._send(200, b"root", head)

    def _send(self, code, body, head):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def do_GET(self):
        self._answer(False)

    def do_HEAD(self):
        self._answer(True)


def _serve(handler=_Handler, tls=None):
    srv = _Server(("127.0.0.1", 0), handler)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*tls)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _selfsigned(tmp):
    if not shutil.which("openssl"):
        return None
    crt, key = str(Path(tmp) / "c.pem"), str(Path(tmp) / "k.pem")
    r = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt, "-days", "2",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], capture_output=True)
    return (crt, key) if r.returncode == 0 else None


class TestTheAgentProbes(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.agent = load_agent()
        cls.srv = _serve()
        cls.other = _serve()
        cls.srv.other_port = cls.other.server_address[1]
        cls.port = cls.srv.server_address[1]
        cls.tmp = tempfile.mkdtemp(prefix="rp-hp-tls-")
        cls.cert = _selfsigned(cls.tmp)
        cls.tls = _serve(tls=cls.cert) if cls.cert else None
        cls.tls_port = cls.tls.server_address[1] if cls.tls else 0

    @classmethod
    def tearDownClass(cls):
        for s in (cls.srv, cls.other, cls.tls):
            if s:
                s.shutdown()
                s.server_close()

    def setUp(self):
        _Handler.hits.clear()

    def run_spec(self, **kw):
        raw = dict({"label": "t", "type": "http", "target": f"http://127.0.0.1:{self.port}/ok"}, **kw)
        spec = self.agent._probe_spec(raw)
        self.assertIsNotNone(spec, raw)
        return self.agent._probe_run_one(spec)

    # the specs
    def test_good_specs(self):
        for raw in ({"label": "db", "type": "tcp", "target": "10.0.0.5:5432"}, {"label": "w", "type": "http", "target": "https://example.org/health"},
                    {"label": "p", "type": "ping", "target": "example.org"}, {"label": "l", "type": "tcp", "target": "127.0.0.1:22"},
                    {"label": "v6", "type": "tcp", "target": "[::1]:80"}, {"label": "h", "type": "http", "target": "http://[::1]:8080/x"}):
            self.assertIsNotNone(self.agent._probe_spec(raw), raw)

    def test_specs_that_are_not_run(self):
        bad = [{"label": "", "type": "tcp", "target": "a:1"}, {"label": "x", "type": "dns", "target": "a"}, {"label": "x", "type": "icmp", "target": "a"},
               {"label": "x", "type": "db", "target": "a:5432"}, {"label": "x", "type": "tcp", "target": "a"}, {"label": "x", "type": "tcp", "target": "a:0"},
               {"label": "x", "type": "tcp", "target": "a:70000"}, {"label": "x", "type": "tcp", "target": "a:b"}, {"label": "x", "type": "tcp", "target": "-x:80"},
               {"label": "x", "type": "tcp", "target": "a b:80"}, {"label": "x", "type": "ping", "target": "-c5"}, {"label": "x", "type": "ping", "target": "a;b"},
               {"label": "x", "type": "ping", "target": "$(id)"}, {"label": "x", "type": "http", "target": "file:///etc/passwd"},
               {"label": "x", "type": "http", "target": "ftp://h/x"}, {"label": "x", "type": "http", "target": "gopher://h/"}, {"label": "x", "type": "http", "target": "http://"},
               {"label": "x", "type": "http", "target": "//h/x"}, {"label": "x", "type": "http", "target": "javascript:alert(1)"},
               {"label": "x", "type": "http", "target": "http://-evil/"}, {"label": "x", "type": "http", "target": "http://a b/"},
               None, "x", 5, [], {"label": "x"}, {"type": "tcp", "target": "a:1"}, {"label": "x", "type": ["tcp"], "target": "a:1"}]
        for raw in bad:
            self.assertIsNone(self.agent._probe_spec(raw), repr(raw))

    def test_a_label_and_a_target_are_cleaned(self):
        spec = self.agent._probe_spec({"label": "a\x00b\nc" + "z" * 300, "type": "tcp", "target": "h\x07ost:80"})
        self.assertIsNotNone(spec)
        self.assertNotRegex(spec["label"], r"[\x00-\x1f]")
        self.assertLessEqual(len(spec["label"]), 128)
        self.assertEqual((spec["host"], spec["port"]), ("host", 80))

    def test_options_of_an_http_spec(self):
        s = self.agent._probe_spec({"label": "x", "type": "http", "target": "http://h/", "expect_status": 401, "expect_contains": "ok", "method": "get",
                                    "verify_tls": False})
        self.assertEqual((s["expect_status"], s["expect_contains"], s["method"], s["verify_tls"]), (401, "ok", "get", False))
        for junk in (True, "200", 99, 600, None, 1.5, [200]):
            self.assertNotIn("expect_status", self.agent._probe_spec({"label": "x", "type": "http", "target": "http://h/", "expect_status": junk}), repr(junk))
        for v in ("false", 0, None, "no"):
            self.assertNotIn("verify_tls", self.agent._probe_spec({"label": "x", "type": "http", "target": "http://h/", "verify_tls": v}), repr(v))
        for v in ("post", "delete", "GET", None):
            self.assertNotIn("method", self.agent._probe_spec({"label": "x", "type": "http", "target": "http://h/", "method": v}), repr(v))

    # tcp
    def test_tcp_open_and_closed(self):
        r = self.agent._probe_run_one(self.agent._probe_spec({"label": "o", "type": "tcp", "target": f"127.0.0.1:{self.port}"}))
        self.assertEqual((r["ok"], r["detail"]), (True, "open"))
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        closed = s.getsockname()[1]
        s.close()
        r = self.agent._probe_run_one(self.agent._probe_spec({"label": "c", "type": "tcp", "target": f"127.0.0.1:{closed}"}))
        self.assertEqual((r["ok"], r["detail"]), (False, "closed"))
        self.assertGreaterEqual(r["latency_ms"], 0)

    # http
    def test_http_status_rules(self):
        self.assertTrue(self.run_spec()["ok"])
        self.assertEqual(self.run_spec()["detail"], "200")
        for path, ok in (("/missing", False), ("/boom", False)):
            r = self.run_spec(target=f"http://127.0.0.1:{self.port}{path}")
            self.assertEqual(r["ok"], ok, path)
        r = self.run_spec(target=f"http://127.0.0.1:{self.port}/missing", expect_status=404)
        self.assertTrue(r["ok"], "an expected status decides alone")
        r = self.run_spec(target=f"http://127.0.0.1:{self.port}/ok", expect_status=404)
        self.assertEqual((r["ok"], r["detail"]), (False, "200 (expected 404)"))

    def test_a_redirect_is_not_followed(self):
        r = self.run_spec(target=f"http://127.0.0.1:{self.port}/moved")
        self.assertEqual(r["detail"], "301")
        self.assertTrue(r["ok"], "under 400 is up, as for a server-run monitor")
        self.assertFalse([h for h in _Handler.hits if h[1] == "/landed"], "the redirect target was never asked")

    def test_the_body_check_needs_the_body(self):
        r = self.run_spec(expect_contains="all fine")
        self.assertTrue(r["ok"])
        self.assertEqual({h[0] for h in _Handler.hits}, {"GET"}, "a body check asks with GET")
        r = self.run_spec(expect_contains="not there")
        self.assertEqual((r["ok"], r["detail"]), (False, '200 · "not there" not found'))

    def test_auto_tries_get_when_head_is_refused(self):
        r = self.run_spec(target=f"http://127.0.0.1:{self.port}/no-head")
        self.assertTrue(r["ok"])
        self.assertEqual([h[0] for h in _Handler.hits if h[1] == "/no-head"], ["HEAD", "GET"])
        _Handler.hits.clear()
        r = self.run_spec(target=f"http://127.0.0.1:{self.port}/no-head", method="head")
        self.assertFalse(r["ok"], "HEAD only: a 405 is the answer")
        r = self.run_spec(target=f"http://127.0.0.1:{self.port}/no-head", method="get")
        self.assertTrue(r["ok"])

    def test_it_says_who_is_asking(self):
        self.run_spec()
        self.assertTrue(any(h[2].startswith("RemotePower-agent/") for h in _Handler.hits), _Handler.hits)

    def test_an_answer_that_never_comes_is_a_failure_in_time(self):
        t0 = time.time()
        r = self.run_spec(target=f"http://127.0.0.1:{self.port}/hang")
        self.assertFalse(r["ok"])
        self.assertLess(time.time() - t0, 7.5, "the probe stops waiting at its own timeout")

    def test_only_http_and_https_are_ever_opened(self):
        victim = Path(self.tmp) / "secret.txt"
        victim.write_text("do not read me")
        # the spec is refused; and even handed to the probe by a caller that skipped the check, the opener has no file: handler
        self.assertIsNone(self.agent._probe_spec({"label": "x", "type": "http", "target": victim.as_uri()}))
        r = self.agent._probe_run_one({"label": "x", "type": "http", "target": victim.as_uri()})
        self.assertFalse(r["ok"])
        self.assertNotIn("do not read me", json.dumps(r))
        self.assertNotIn("file:", [h[1] for h in _Handler.hits])

    @unittest.skipUnless(shutil.which("openssl"), "openssl is not installed")
    def test_certificates_are_checked_unless_the_monitor_says_not_to(self):
        port = self.tls_port
        r = self.agent._probe_run_one(self.agent._probe_spec({"label": "t", "type": "http", "target": f"https://127.0.0.1:{port}/ok"}))
        self.assertFalse(r["ok"], "a self-signed certificate is not trusted")
        self.assertIn("error", r["detail"])
        r = self.agent._probe_run_one(self.agent._probe_spec({"label": "t", "type": "http", "target": f"https://127.0.0.1:{port}/ok", "verify_tls": False}))
        self.assertTrue(r["ok"], r)

    # ping
    def test_ping_is_asked_with_no_room_for_a_flag(self):
        calls = []
        with mock.patch.object(self.agent.shutil, "which", lambda p: "/bin/ping"), \
                mock.patch.object(self.agent.subprocess, "run", lambda cmd, **k: calls.append(cmd) or mock.Mock(returncode=0, stdout="", stderr="")):
            r = self.agent._probe_run_one(self.agent._probe_spec({"label": "p", "type": "ping", "target": "example.org"}))
        self.assertEqual(calls, [["ping", "-c", "1", "-W", "2", "--", "example.org"]])
        self.assertEqual((r["ok"], r["detail"]), (True, "reachable"))

    def test_ping_failure_and_a_host_without_ping(self):
        with mock.patch.object(self.agent.shutil, "which", lambda p: "/bin/ping"), \
                mock.patch.object(self.agent.subprocess, "run", lambda cmd, **k: mock.Mock(returncode=1, stdout="", stderr="")):
            r = self.agent._probe_run_one(self.agent._probe_spec({"label": "p", "type": "ping", "target": "example.org"}))
        self.assertEqual((r["ok"], r["detail"]), (False, "unreachable"))
        with mock.patch.object(self.agent.shutil, "which", lambda p: None):
            r = self.agent._probe_run_one(self.agent._probe_spec({"label": "p", "type": "ping", "target": "example.org"}))
        self.assertEqual((r["ok"], "not installed" in r["detail"]), (False, True))

    def test_a_probe_that_raises_is_a_failed_result(self):
        r = self.agent._probe_run_one({"label": "x", "type": "http", "target": "http://127.0.0.1:1/", "expect_contains": "x"})
        self.assertEqual((r["ok"], r["type"]), (False, "http"))
        json.dumps(r)

    def test_results_are_bounded(self):
        r = self.agent._probe_run_one({"label": "L" * 300, "type": "tcp", "target": "h" * 400 + ":80", "host": "127.0.0.1", "port": 1})
        self.assertLessEqual(len(r["target"]), 256)
        self.assertLessEqual(len(r["detail"]), 200)


class TestTheAgentRefusesWhatItMayNotReach(unittest.TestCase):
    """The server refuses a link-local or cloud metadata address when it saves a monitor. A name can change its answer after that, so the
    agent checks the address it is about to connect to, and connects to the address it checked."""

    @classmethod
    def setUpClass(cls):
        cls.agent = load_agent()
        cls.srv = _serve()
        cls.port = cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        _Handler.hits.clear()
        self.answers = {}
        self.lookups = []
        agent = self.agent
        real = socket.getaddrinfo

        def fake(host, port, *a, **k):
            self.lookups.append(host)
            if host in self.answers:
                seq = self.answers[host]
                ip = seq.pop(0) if len(seq) > 1 else seq[0]
                fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
                return [(fam, socket.SOCK_STREAM, 6, "", (ip, port) if fam == socket.AF_INET else (ip, port, 0, 0))]
            return real(host, port, *a, **k)
        self._patch = mock.patch.object(agent.socket, "getaddrinfo", fake)
        self._patch.start()
        self.addCleanup(self._patch.stop)
        self.connects = []
        real_cc = agent.socket.create_connection

        def cc(address, *a, **k):
            self.connects.append(address)
            return real_cc(address, *a, **k)
        self._cc = mock.patch.object(agent.socket, "create_connection", cc)
        self._cc.start()
        self.addCleanup(self._cc.stop)

    def run_spec(self, **kw):
        spec = self.agent._probe_spec(dict({"label": "t", "type": "tcp", "target": "svc.test:80"}, **kw))
        self.assertIsNotNone(spec, kw)
        return self.agent._probe_run_one(spec)

    def test_a_name_that_resolves_to_the_metadata_address_is_not_connected_to(self):
        for ip in ("169.254.169.254", "169.254.0.1", "fe80::1", "fd00:ec2::254", "100.100.100.200", "192.0.0.192", "0.0.0.0", "224.0.0.1",
                   "::ffff:169.254.169.254", "2002:a9fe:a9fe::1", "64:ff9b::a9fe:a9fe"):
            self.answers = {"svc.test": [ip]}
            self.connects.clear()
            r = self.run_spec(target=f"svc.test:{self.port}")
            self.assertEqual((r["ok"], r["detail"]), (False, "that address is not allowed (link-local or cloud metadata)"), ip)
            self.assertEqual(self.connects, [], f"{ip}: nothing was connected to")

    def test_the_same_for_http(self):
        for ip in ("169.254.169.254", "fd00:ec2::254", "::ffff:169.254.169.254"):
            self.answers = {"svc.test": [ip]}
            r = self.run_spec(type="http", target=f"http://svc.test:{self.port}/ok")
            self.assertFalse(r["ok"], ip)
            self.assertIn("not allowed", r["detail"], ip)
            self.assertEqual(self.connects, [], ip)
            self.assertEqual(_Handler.hits, [], "and no request was made")

    def test_the_same_for_https(self):
        # the TLS connection is a different class from the plain one and has to use the same vetted connect
        for ip in ("169.254.169.254", "fd00:ec2::254"):
            self.answers = {"svc.test": [ip]}
            self.connects.clear()
            r = self.run_spec(type="http", target=f"https://svc.test:{self.port}/ok", verify_tls=False)
            self.assertEqual((r["ok"], r["detail"]), (False, "that address is not allowed (link-local or cloud metadata)"), ip)
            self.assertEqual(self.connects, [], ip)

    def test_one_bad_address_among_good_ones_refuses_the_name(self):
        real = socket.getaddrinfo

        def two(host, port, *a, **k):
            if host == "svc.test":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)), (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port))]
            return real(host, port, *a, **k)
        with mock.patch.object(self.agent.socket, "getaddrinfo", two):
            r = self.run_spec(target=f"svc.test:{self.port}")
        self.assertIn("not allowed", r["detail"])
        self.assertEqual(self.connects, [])

    def test_the_hosts_own_loopback_and_its_private_networks_are_the_point(self):
        for ip in ("127.0.0.1", "10.1.2.3", "192.168.1.5", "172.16.0.9", "::1"):
            self.assertFalse(self.agent._probe_addr_blocked(ip), ip)
        self.answers = {"svc.test": ["127.0.0.1"]}
        r = self.run_spec(target=f"svc.test:{self.port}")
        self.assertEqual((r["ok"], r["detail"]), (True, "open"))
        r = self.run_spec(type="http", target=f"http://svc.test:{self.port}/ok")
        self.assertEqual((r["ok"], r["detail"]), (True, "200"))

    def test_it_connects_to_the_address_it_checked(self):
        # the first answer is the loopback, any later one is the metadata address; one lookup is made and the connection goes to the first
        self.answers = {"svc.test": ["127.0.0.1", "169.254.169.254"]}
        r = self.run_spec(type="http", target=f"http://svc.test:{self.port}/ok")
        self.assertTrue(r["ok"], r)
        self.assertEqual([h for h in self.lookups if h == "svc.test"], ["svc.test"], "the name is resolved once")
        self.assertEqual(self.connects, [("127.0.0.1", self.port)], "and the connection is made to the address that was checked")

    def test_the_certificate_is_still_checked_against_the_name(self):
        if not shutil.which("openssl"):
            self.skipTest("openssl is not installed")
        tmp = tempfile.mkdtemp(prefix="rp-hp-tls2-")
        cert = _selfsigned(tmp)
        tls = _serve(tls=cert)
        self.addCleanup(tls.server_close)
        self.addCleanup(tls.shutdown)
        port = tls.server_address[1]
        self.answers = {"svc.test": ["127.0.0.1"]}
        # verification on: the certificate is for localhost and 127.0.0.1, and the monitor asked for svc.test
        r = self.run_spec(type="http", target=f"https://svc.test:{port}/ok")
        self.assertFalse(r["ok"], "the name in the certificate decides, not the address that was connected to")
        r = self.run_spec(type="http", target=f"https://svc.test:{port}/ok", verify_tls=False)
        self.assertTrue(r["ok"], r)

    def test_a_ping_to_a_blocked_literal_is_not_sent(self):
        calls = []
        with mock.patch.object(self.agent.shutil, "which", lambda p: "/bin/ping"), \
                mock.patch.object(self.agent.subprocess, "run", lambda cmd, **k: calls.append(cmd) or mock.Mock(returncode=0)):
            for target in ("169.254.169.254", "0.0.0.0", "100.100.100.200", "192.0.0.192", "224.0.0.1"):
                r = self.agent._probe_run_one(self.agent._probe_spec({"label": "p", "type": "ping", "target": target}))
                self.assertEqual((r["ok"], "not allowed" in r["detail"]), (False, True), target)
            self.assertIsNone(self.agent._probe_spec({"label": "p", "type": "ping", "target": "fd00:ec2::254"}), "an IPv6 address is not pinged")
            r = self.agent._probe_run_one(self.agent._probe_spec({"label": "p", "type": "ping", "target": "127.0.0.1"}))
            self.assertTrue(r["ok"])
        self.assertEqual(len(calls), 1, "only the loopback was pinged")

    def test_the_agents_ladder_is_the_servers(self):
        import ssrf_ip
        addresses = ["127.0.0.1", "127.255.255.254", "::1", "10.0.0.1", "172.16.5.4", "192.168.0.1", "8.8.8.8", "1.1.1.1", "2606:4700::1111",
                     "169.254.169.254", "169.254.0.0", "169.254.255.255", "fe80::1", "fe80::abcd", "0.0.0.0", "::", "224.0.0.1", "239.255.255.250",
                     "ff02::1", "240.0.0.1", "255.255.255.255", "100.64.0.1", "100.100.100.200", "192.0.0.192", "192.0.0.193", "fd00:ec2::254",
                     "fd00:ec2::255", "fc00::1", "::ffff:169.254.169.254", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:8.8.8.8",
                     "2002:a9fe:a9fe::1", "2002:7f00:1::1", "2002:0a00:0001::1", "64:ff9b::a9fe:a9fe", "64:ff9b::7f00:1", "64:ff9b::808:808", "not an ip", ""]
        for ip in addresses:
            try:
                want = ssrf_ip.blocked(ip, allow_loopback=True)
            except ValueError:
                want = True       # the agent does not connect to what it cannot read
            self.assertEqual(self.agent._probe_addr_blocked(ip), want, ip)
        self.assertGreater(len(addresses), 30, "the comparison looked at something")


class TestTheAgentRuns(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.agent = load_agent()
        cls.srv = _serve()
        cls.port = cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        a = self.agent
        a._PROBE.update(specs=[], interval=300, next=0.0, running=False)
        a._PROBE_OUTBOX.clear()

    def wait(self, n, t=10):
        end = time.time() + t
        while time.time() < end and len(self.agent._PROBE_OUTBOX) < n:
            time.sleep(0.05)

    def test_update_keeps_only_runnable_specs_and_clamps_the_interval(self):
        a = self.agent
        a._probe_update([{"label": "ok", "type": "tcp", "target": "h:1"}, {"label": "bad", "type": "dns", "target": "h"}, "x", None], 5)
        self.assertEqual([s["label"] for s in a._PROBE["specs"]], ["ok"])
        self.assertEqual(a._PROBE["interval"], 60)
        a._probe_update([{"label": "ok", "type": "tcp", "target": "h:1"}], 10 ** 9)
        self.assertEqual(a._PROBE["interval"], 3600)
        a._probe_update([{"label": "ok", "type": "tcp", "target": "h:1"}], "x")
        self.assertEqual(a._PROBE["interval"], 300)

    def test_at_most_so_many_specs(self):
        specs = [{"label": f"m{i}", "type": "tcp", "target": f"h{i}:1"} for i in range(60)]
        self.agent._probe_update(specs, 300)
        self.assertEqual(len(self.agent._PROBE["specs"]), self.agent._PROBE_MAX_SPECS)

    def test_not_a_list_leaves_the_monitors_as_they_are(self):
        self.agent._probe_update([{"label": "ok", "type": "tcp", "target": "h:1"}], 300)
        for junk in (None, "x", 5, {"a": 1}):
            self.agent._probe_update(junk, 60)
        self.assertEqual(len(self.agent._PROBE["specs"]), 1)

    def test_an_empty_list_stops_it_and_forgets_what_was_waiting(self):
        a = self.agent
        a._probe_update([{"label": "ok", "type": "tcp", "target": "h:1"}], 300)
        a._PROBE_OUTBOX.append({"label": "old"})
        a._probe_update([], 300)
        self.assertEqual((a._PROBE["specs"], list(a._PROBE_OUTBOX)), ([], []))
        a._probe_tick()
        self.assertFalse(a._PROBE["running"], "nothing to run")

    def test_a_run_reports_every_monitor_and_waits_for_its_interval(self):
        a = self.agent
        a._probe_update([{"label": "up", "type": "tcp", "target": f"127.0.0.1:{self.port}"},
                         {"label": "web", "type": "http", "target": f"http://127.0.0.1:{self.port}/ok", "expect_contains": "hello"}], 300)
        a._probe_tick()
        self.wait(2)
        got = {r["label"]: r["ok"] for r in a._PROBE_OUTBOX}
        self.assertEqual(got, {"up": True, "web": True})
        n = len(a._PROBE_OUTBOX)
        a._probe_tick()
        time.sleep(0.4)
        self.assertEqual(len(a._PROBE_OUTBOX), n, "not due again for an interval")
        self.assertFalse(a._PROBE["running"])

    def test_a_run_never_overlaps_the_last(self):
        a = self.agent
        a._probe_update([{"label": "up", "type": "tcp", "target": f"127.0.0.1:{self.port}"}], 60)
        a._PROBE["running"] = True
        with mock.patch.object(a.threading, "Thread") as thread:
            a._probe_tick()
        thread.assert_not_called()
        self.assertEqual(a._PROBE_OUTBOX, [], "one is still running")

    def test_a_host_in_audit_mode_runs_nothing_the_server_assigns(self):
        """Observe-only means the server's instructions are not acted on: ping and a connection to an address the server names would
        let a hostile server look around the network of an audited host."""
        a = self.agent
        spec = {"label": "up", "type": "tcp", "target": f"127.0.0.1:{self.port}"}
        a._probe_update([spec], 60)
        a._PROBE_OUTBOX.append({"label": "old"})
        with mock.patch.object(a, "_audit_mode", return_value=True):
            a._probe_update([spec], 60)
            self.assertEqual((a._PROBE["specs"], list(a._PROBE_OUTBOX)), ([], []), "nothing is kept and nothing waits to be sent")
            a._PROBE["specs"] = [dict(spec)]                    # assigned before the flag was set
            a._probe_tick()
        self.assertFalse(a._PROBE["running"])
        self.assertEqual(list(a._PROBE_OUTBOX), [])
        a._probe_update([spec], 60)
        self.assertEqual(len(a._PROBE["specs"]), 1, "and out of audit mode it works as before")

    def test_the_outbox_is_bounded(self):
        a = self.agent
        a._probe_update([{"label": "up", "type": "tcp", "target": f"127.0.0.1:{self.port}"}], 60)
        a._PROBE_OUTBOX.extend({"label": f"old{i}"} for i in range(a._PROBE_OUTBOX_MAX + 50))
        a._probe_tick()
        end = time.time() + 5
        while time.time() < end and a._PROBE["running"]:
            time.sleep(0.05)
        self.assertLessEqual(len(a._PROBE_OUTBOX), a._PROBE_OUTBOX_MAX)

    def test_what_was_sent_is_forgotten_and_nothing_else(self):
        a = self.agent
        a._PROBE_OUTBOX.extend({"label": f"r{i}"} for i in range(5))
        batch = a._probe_take(3)
        self.assertEqual([r["label"] for r in batch], ["r0", "r1", "r2"])
        self.assertEqual(len(a._PROBE_OUTBOX), 5, "taking is a peek")
        # a run that finishes meanwhile trims the front of the list; the matching is by identity, not by position
        del a._PROBE_OUTBOX[:1]
        a._PROBE_OUTBOX.append({"label": "r5"})
        a._probe_delivered(batch)
        self.assertEqual([r["label"] for r in a._PROBE_OUTBOX], ["r3", "r4", "r5"])

    def test_the_heartbeat_loop_carries_them(self):
        src = (ROOT / "client" / "remotepower-agent.py").read_text()
        self.assertIn("payload['monitor_results'] = _probe_batch", src)
        self.assertIn("_probe_update(resp.get('host_monitors'), resp.get('host_monitor_interval'))", src)
        i = src.index("_probe_delivered(_probe_batch)")
        self.assertIn("resp.get('busy') is not True", src[i - 120:i], "dropped only after the server accepted the heartbeat")
        self.assertEqual(src.count("_probe_delivered(_probe_batch)"), 1)


# ── the server: saving a monitor that runs from a host ────────────────────────────────────────────────────────────────
def _fake_dns(mapping):
    def f(host, *a, **k):
        if host in mapping:
            return [(socket.AF_INET, 1, 6, "", (mapping[host], 0))]
        return _REAL_GETADDRINFO(host, *a, **k)
    return f


class _Save(unittest.TestCase):

    def setUp(self):
        self.cap = {}
        self._real = {n: getattr(api, n) for n in ("respond", "verify_token", "audit_log", "_env", "method", "get_json_obj", "fire_webhook")}

        def _resp(status, body=None):
            self.cap["s"], self.cap["b"] = status, body
            raise api.HTTPError(status, body)
        api.respond = _resp
        api.audit_log = lambda *a, **k: None
        self.hooks = []
        api.fire_webhook = lambda ev, payload=None, *a, **k: self.hooks.append((ev, payload))
        api._env = lambda k, d="": d
        api.method = lambda: "POST"
        api.verify_token = lambda *a, **k: ("admin", "admin")
        api.save(api.CONFIG_FILE, {})
        now = int(time.time())
        api.save(api.DEVICES_FILE, {
            "lin1": {"name": "web1", "os": "Ubuntu 24.04", "token_hash": "x", "last_seen": now},
            "lin2": {"name": "web2", "os": "Debian 12", "token_hash": "x", "last_seen": now},
            "win1": {"name": "win", "os": "Windows 11", "token_hash": "x", "last_seen": now},
            "mac1": {"name": "mac", "os": "macOS 15", "token_hash": "x", "last_seen": now},
            "agentless1": {"name": "router", "os": "Linux", "agentless": True, "last_seen": now},
        })
        api.save(api.SATELLITES_FILE, {"sat-1": {"name": "edge"}})
        api.save(api.SATELLITE_MON_FILE, {})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._real.items():
            setattr(api, n, v)
        socket.getaddrinfo = _REAL_GETADDRINFO
        api._LOAD_CACHE.clear()

    def save(self, monitors):
        api.get_json_obj = lambda: {"monitors": monitors}
        self.cap.clear()
        try:
            api.handle_config_save()
        except api.HTTPError:
            pass
        return self.cap.get("s"), self.cap.get("b") or {}

    def stored(self):
        api._invalidate_load_cache(api.CONFIG_FILE)
        return (api.load(api.CONFIG_FILE) or {}).get("monitors") or []

    def mon(self, **kw):
        return dict({"label": "m", "type": "tcp", "target": "10.0.0.5:5432", "target_kind": "host", "via_host": "lin1"}, **kw)


class TestSaving(_Save):

    def test_the_three_types_save_with_the_host(self):
        for m in (self.mon(), self.mon(label="w", type="http", target="http://10.0.0.5:8080/health", expect_status=200),
                  self.mon(label="p", type="ping", target="10.0.0.5")):
            st, body = self.save([m])
            self.assertEqual(st, 200, (m, body))
            self.assertEqual(self.stored()[0]["via_host"], "lin1")

    def test_the_hosts_own_loopback_is_allowed(self):
        socket.getaddrinfo = _fake_dns({"localhost-svc.example": "127.0.0.1"})
        for m in (self.mon(target="127.0.0.1:5432"), self.mon(label="h", type="http", target="http://127.0.0.1:8080/health"),
                  self.mon(label="h2", type="http", target="http://localhost-svc.example/x"), self.mon(label="l", type="ping", target="127.0.0.1")):
            self.assertEqual(self.save([m])[0], 200, m)
        # a server-run monitor of the same loopback target is still refused unless the setting allows it
        self.assertEqual(self.save([self.mon(via_host="", target="127.0.0.1:5432")])[0], 400)

    def test_cloud_metadata_and_link_local_are_never_allowed(self):
        socket.getaddrinfo = _fake_dns({"meta.example": "169.254.169.254"})
        for m in (self.mon(target="169.254.169.254:80"), self.mon(label="a", type="http", target="http://169.254.169.254/latest/meta-data/"),
                  self.mon(label="b", type="http", target="http://meta.example/"), self.mon(label="c", type="ping", target="169.254.169.254")):
            st, body = self.save([m])
            self.assertEqual(st, 400, m)
            self.assertIn("link-local", body["error"], m)

    def test_a_host_in_audit_mode_is_not_a_place_to_probe_from(self):
        devs = api.load(api.DEVICES_FILE)
        devs["lin1"]["sysinfo"] = {"audit_mode": True}
        api.save(api.DEVICES_FILE, devs)
        api._LOAD_CACHE.clear()
        st, body = self.save([self.mon()])
        self.assertEqual(st, 400)
        self.assertIn("audit mode", body["error"])
        self.assertEqual(self.save([self.mon(via_host="lin2")])[0], 200, "another host is fine")

    def test_which_hosts_may_probe(self):
        # an id is cut to 64 characters before it is looked up, so a 200-character one is simply a host that is not enrolled
        for dev, why in (("win1", "only the Linux agent"), ("mac1", "only the Linux agent"), ("agentless1", "no agent"),
                         ("nope", "not enrolled"), ("../x", "valid host id"), ("a/b", "valid host id"), ("a" * 200, "not enrolled")):
            st, body = self.save([self.mon(via_host=dev)])
            self.assertEqual(st, 400, dev)
            self.assertIn(why, body["error"], dev)
        self.assertEqual(self.stored(), [])

    def test_which_types_may_run_from_a_host(self):
        for t, target in (("dns", "example.org"), ("icmp", "example.org"), ("db", "10.0.0.5:5432"), ("path", "example.org")):
            st, body = self.save([self.mon(type=t, target=target)])
            self.assertEqual(st, 400, t)
            self.assertIn("tcp, http and ping", body["error"], t)

    def test_one_address_not_a_group(self):
        for kind in ("tag", "group"):
            st, body = self.save([self.mon(type="ping", target="web", target_kind=kind)])
            self.assertEqual(st, 400, kind)
            self.assertIn("one address", body["error"])

    def test_a_satellite_or_a_host_not_both(self):
        st, body = self.save([self.mon(via_satellite="sat-1")])
        self.assertEqual(st, 400)
        self.assertIn("not both", body["error"])

    def test_bad_targets(self):
        for m in (self.mon(target="no-port"), self.mon(target="h:0"), self.mon(target="h:70000"), self.mon(target="-x:80"),
                  self.mon(type="ping", target="-c5"), self.mon(type="ping", target="a;b"), self.mon(type="http", target="ftp://h/"),
                  self.mon(type="http", target="file:///etc/passwd"), self.mon(type="http", target="http://")):
            self.assertEqual(self.save([m])[0], 400, m)

    def test_a_server_monitor_is_unchanged(self):
        self.assertEqual(self.save([{"label": "pub", "type": "tcp", "target": "example.org:443", "target_kind": "host"}])[0], 200)
        self.assertNotIn("via_host", self.stored()[0])

    def test_a_host_that_has_gone_does_not_veto_an_unrelated_edit(self):
        stale = self.mon(label="old", via_host="lin2")
        self.assertEqual(self.save([stale])[0], 200)
        devs = api.load(api.DEVICES_FILE)
        devs.pop("lin2")
        api.save(api.DEVICES_FILE, devs)
        api._LOAD_CACHE.clear()
        new = {"label": "pub", "type": "tcp", "target": "example.org:443", "target_kind": "host"}
        st, body = self.save([self.stored()[0], new])
        self.assertEqual(st, 200, body)
        self.assertEqual({m["label"] for m in self.stored()}, {"old", "pub"}, "the old one is kept, with a warning")
        self.assertTrue(body.get("monitor_warnings"))


class TestTheRuleItself(_Save):
    """host_probe_validate is the rule; the save handler's own address check runs first and hides a hole in it, so it is asked directly."""

    def ask(self, mtype, **m):
        return api.host_probe_validate("lin1", mtype, dict({"target_kind": "host"}, **m))

    def test_a_good_monitor_of_each_type(self):
        for mtype, target in (("tcp", "10.0.0.5:5432"), ("http", "https://10.0.0.5/health"), ("ping", "10.0.0.5"), ("tcp", "127.0.0.1:22"),
                              ("http", "http://127.0.0.1:8080/"), ("ping", "127.0.0.1")):
            self.assertEqual(self.ask(mtype, target=target), "", (mtype, target))

    def test_metadata_and_link_local_for_each_type(self):
        socket.getaddrinfo = _fake_dns({"meta.example": "169.254.169.254", "alibaba.example": "100.100.100.200"})
        for mtype, target in (("tcp", "169.254.169.254:80"), ("tcp", "meta.example:80"), ("http", "http://169.254.169.254/latest/"),
                              ("http", "http://meta.example/"), ("http", "http://alibaba.example/"), ("ping", "169.254.169.254"),
                              ("ping", "meta.example"), ("tcp", "100.100.100.200:80"), ("http", "http://[fe80::1]/")):
            why = self.ask(mtype, target=target)
            self.assertIn("not allowed", why, (mtype, target))

    def test_a_host_with_nothing_wrong_with_it_is_asked_about_the_address_last(self):
        # the order of the reasons: who may probe, what it may ask, then where
        self.assertIn("only the Linux agent", api.host_probe_validate("win1", "http", {"target": "http://169.254.169.254/", "expect_json": {"path": "a"}}))
        self.assertIn("only available when the server", self.ask("http", target="http://169.254.169.254/", expect_json={"path": "a"}))

    def test_what_the_agent_does_not_evaluate_is_refused(self):
        refused = (dict(body_match={"mode": "regex", "value": "ok.*"}), dict(body_match={"mode": "not_contains", "value": "error"}),
                   dict(expect_json={"path": "status.ok", "value": "true"}), dict(expect_json={"path": "a"}), dict(max_latency_ms=500),
                   dict(max_latency_ms=0.5), dict(max_latency_ms=600000))
        for extra in refused:
            why = self.ask("http", target="http://10.0.0.5/", **extra)
            self.assertIn("only available when the server", why, extra)

    def test_what_the_agent_does_evaluate_is_accepted(self):
        accepted = (dict(body_match={"mode": "contains", "value": "ok"}), dict(body_match={"mode": "", "value": "ok"}), dict(body_match={"value": "ok"}),
                    dict(body_match={"mode": "regex", "value": ""}), dict(body_match=None), dict(expect_status=401), dict(method="get"),
                    dict(verify_tls=False), dict(expect_json={"path": " "}), dict(expect_json=None), dict(max_latency_ms=0), dict(max_latency_ms=-5),
                    dict(max_latency_ms=None), dict(max_latency_ms="500"), dict(failures_before_alert=3))
        for extra in accepted:
            self.assertEqual(self.ask("http", target="http://10.0.0.5/", **extra), "", extra)

    def test_only_an_http_check_has_these_assertions(self):
        # the server stores none of them for other types, so a stray key on a tcp monitor is not a reason to refuse it
        self.assertEqual(self.ask("tcp", target="10.0.0.5:22", max_latency_ms=500, expect_json={"path": "a"}, body_match={"mode": "regex", "value": "x"}), "")

    def test_the_save_says_which_one_to_take_out(self):
        for extra, word in ((dict(body_match={"mode": "regex", "value": "ok.*"}), "regex"), (dict(body_match={"mode": "not_contains", "value": "x"}), "NOT contain"),
                            (dict(expect_json={"path": "a"}), "JSON"), (dict(max_latency_ms=500), "latency")):
            st, body = self.save([self.mon(type="http", target="http://10.0.0.5/", **extra)])
            self.assertEqual(st, 400, extra)
            self.assertIn(word, body["error"], extra)
        self.assertEqual(self.stored(), [])

    def test_the_same_check_saves_when_the_server_runs_it(self):
        st, body = self.save([self.mon(type="http", target="http://10.0.0.5/", via_host="", body_match={"mode": "regex", "value": "ok.*"}, max_latency_ms=500)])
        self.assertEqual(st, 200, body)
        self.assertEqual(self.stored()[0]["body_match"], {"mode": "regex", "value": "ok.*"})


class TestOneGuardForLatency(_Save):

    def test_what_is_kept(self):
        clean = api.clean_latency
        for lat, want in ((12.34, 12.3), (0, 0.0), (7, 7.0), (9999999, 9999999.0), (0.04, 0.0)):
            self.assertEqual(clean(lat), want, lat)
        for bad in (True, False, "5", None, float("nan"), float("inf"), float("-inf"), -1, -0.1, 10 ** 7, 10 ** 400, -(10 ** 400), [1], {"a": 1}):
            self.assertIsNone(clean(bad), repr(bad)[:30])

    def test_a_satellite_result_with_a_huge_latency_does_not_fail_the_post(self):
        api.save(api.CONFIG_FILE, {"monitors": [{"label": "far", "type": "ping", "target": "10.0.0.1", "target_kind": "host", "via_satellite": "sat-1"}]})
        api._LOAD_CACHE.clear()
        api.method = lambda: "POST"
        real = api.require_satellite
        api.require_satellite = lambda: "sat-1"
        self.addCleanup(setattr, api, "require_satellite", real)
        for lat, kept in ((10 ** 400, None), (True, None), (3.14159, 3.1)):
            api.get_json_obj = lambda lat=lat: {"results": [{"label": "far", "type": "ping", "target": "10.0.0.1", "ok": True, "detail": "x", "latency_ms": lat}]}
            self.cap.clear()
            try:
                api.handle_satellite_monitor_results()
            except api.HTTPError:
                pass
            self.assertEqual(self.cap.get("s"), 200, (lat, self.cap))
            api._LOAD_CACHE.clear()
            row = api.load(api.SATELLITE_MON_FILE)["far"]
            self.assertEqual(row.get("latency_ms"), kept, str(lat)[:10])


# ── the server: what a host runs, and what it reports ────────────────────────────────────────────────────────────────
class TestSendingAndTaking(_Save):

    def setUp(self):
        super().setUp()
        cfg = {"monitors": [
            self.mon(label="db", via_host="lin1"), self.mon(label="web", type="http", target="http://10.0.0.5/x", via_host="lin1", expect_status=200,
                                                            body_match={"mode": "contains", "value": "ok"}, method="get", verify_tls=False),
            self.mon(label="paused", via_host="lin1", paused=True), self.mon(label="other-host", via_host="lin2"),
            {"label": "pub", "type": "tcp", "target": "example.org:443", "target_kind": "host"},
            {"label": "sat", "type": "tcp", "target": "10.0.0.9:22", "target_kind": "host", "via_satellite": "sat-1"},
            self.mon(label="regex", type="http", target="http://10.0.0.5/r", via_host="lin1", body_match={"mode": "not_contains", "value": "bad"})]}
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()

    def test_a_linux_host_gets_its_own_monitors_and_only_those(self):
        specs = api.host_monitors_for("lin1", api.load(api.DEVICES_FILE)["lin1"])
        self.assertEqual([s["label"] for s in specs], ["db", "web", "regex"])
        web = specs[1]
        self.assertEqual((web["type"], web["expect_status"], web["expect_contains"], web["method"], web["verify_tls"]),
                         ("http", 200, "ok", "get", False))
        self.assertIsNone(specs[2]["expect_contains"], "only a `contains` body check is sent; the others are not what the agent runs")

    def test_a_host_with_none_gets_an_empty_list_and_others_get_nothing(self):
        devs = api.load(api.DEVICES_FILE)
        cfg = api.load(api.CONFIG_FILE)
        cfg["monitors"] = []
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()
        self.assertEqual(api.host_monitors_for("lin1", devs["lin1"]), [], "so a removed monitor stops")
        for d in ("win1", "mac1", "agentless1"):
            self.assertIsNone(api.host_monitors_for(d, devs[d]), d)
        self.assertIsNone(api.host_monitors_for("x", None))
        self.assertIsNone(api.host_monitors_for("x", "junk"))

    def test_at_most_so_many_are_sent(self):
        cfg = api.load(api.CONFIG_FILE)
        cfg["monitors"] = [self.mon(label=f"m{i}") for i in range(60)]
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()
        self.assertEqual(len(api.host_monitors_for("lin1", api.load(api.DEVICES_FILE)["lin1"])), 20)

    def test_the_server_does_not_probe_a_monitor_a_host_runs(self):
        seen = []
        real = api._run_one_monitor_check
        api._run_one_monitor_check = lambda mtype, target, label, m: seen.append(label) or {"label": label, "type": mtype, "target": target, "ok": True, "detail": "x", "checked": 1}
        try:
            api._execute_monitor_checks(api._config_ro().get("monitors"))
        finally:
            api._run_one_monitor_check = real
        self.assertEqual(seen, ["pub"], "not the host's, not the satellite's, not the paused ones")

    def results(self, dev="lin1", **extra):
        return api.host_probe_ingest(dev, [dict({"label": "db", "type": "tcp", "target": "10.0.0.5:5432", "ok": True, "detail": "open", "latency_ms": 12.34}, **extra)])

    def test_a_result_is_kept_like_a_satellites(self):
        self.assertEqual(self.results(), 1)
        api._LOAD_CACHE.clear()
        row = api.load(api.SATELLITE_MON_FILE)["db"]
        self.assertEqual((row["ok"], row["detail"], row["latency_ms"], row["type"]), (True, "open", 12.3, "tcp"))
        self.assertGreater(row["checked"], 0)
        hist = (api.load(api.MONITOR_HISTORY_FILE) or {}).get("db") if hasattr(api, "MONITOR_HISTORY_FILE") else True
        self.assertTrue(hist)

    def test_a_host_can_only_report_on_its_own_monitors(self):
        for label in ("pub", "sat", "other-host", "nope", "paused-not-owned-by-lin2"):
            self.assertEqual(api.host_probe_ingest("lin2", [{"label": label, "type": "tcp", "target": "x:1", "ok": False, "detail": "closed"}]) if label != "other-host" else 0, 0, label)
        self.assertEqual(api.host_probe_ingest("lin1", [{"label": "pub", "type": "tcp", "target": "x:1", "ok": False}, {"label": "sat", "ok": False},
                                                         {"label": "other-host", "ok": False}]), 0, "none of the server's, the satellite's or another host's")
        api._LOAD_CACHE.clear()
        self.assertEqual(api.load(api.SATELLITE_MON_FILE), {})
        self.assertEqual(api.host_probe_ingest("win1", [{"label": "db", "ok": True}]), 0, "a host with no monitors takes nothing")

    def test_a_down_and_an_up_are_alerted_like_any_monitor(self):
        self.results(ok=True)
        self.results(ok=False, detail="closed")
        self.results(ok=False, detail="closed")
        self.results(ok=True)
        events = [e for e, p in self.hooks if e in ("monitor_down", "monitor_up")]
        self.assertEqual(events, ["monitor_down", "monitor_up"])

    def test_values_are_checked(self):
        for ok_in, ok_out in ((True, True), (False, False), ("false", False), ("true", False), (1, False), (None, False), ([], False)):
            self.results(ok=ok_in)
            api._LOAD_CACHE.clear()
            self.assertIs(api.load(api.SATELLITE_MON_FILE)["db"]["ok"], ok_out, repr(ok_in))
        for lat in (True, "5", None, float("nan"), float("inf"), -1, 10 ** 400, [1]):
            self.results(latency_ms=lat)
            api._LOAD_CACHE.clear()
            self.assertNotIn("latency_ms", api.load(api.SATELLITE_MON_FILE)["db"], repr(lat))
        self.results(detail="x" * 900, target="t" * 900)
        api._LOAD_CACHE.clear()
        row = api.load(api.SATELLITE_MON_FILE)["db"]
        self.assertLessEqual((len(row["detail"]), len(row["target"])), (256, 256))

    def test_junk_is_not_a_result(self):
        for junk in (None, "x", 5, {"a": 1}, [None, 5, "x", {"label": 5}, {"no": "label"}], []):
            self.assertEqual(api.host_probe_ingest("lin1", junk), 0, repr(junk))

    def test_a_flood_is_capped(self):
        flood = [{"label": "db", "type": "tcp", "target": "x:1", "ok": True} for _ in range(5000)]
        self.assertEqual(api.host_probe_ingest("lin1", flood), api.host_probe_handlers_mod.MAX_RESULTS)

    def test_the_monitor_list_shows_where_each_ran(self):
        self.results()
        rows = api._satellite_monitor_display(api._config_ro().get("monitors"))
        by = {r["label"]: r for r in rows}
        self.assertEqual(by["db"]["origin"], "host:lin1")
        self.assertEqual(by["web"]["origin"], "host:lin1")
        self.assertEqual(by["web"]["detail"], "awaiting first probe from the host")
        self.assertEqual(by["sat"]["origin"], "satellite:sat-1")
        self.assertEqual(by["sat"]["detail"], "awaiting first satellite probe")
        self.assertNotIn("paused", by, "a paused monitor has its own display row")
        self.assertEqual((by["db"]["origin_name"], by["web"]["origin_name"]), ("web1", "web1"), "the host's name comes with the id")
        self.assertNotIn("origin_name", by["sat"], "and only for a host")

    def test_a_pending_row_of_a_host_in_audit_mode_says_so(self):
        devs = api.load(api.DEVICES_FILE)
        devs["lin1"]["sysinfo"] = {"audit_mode": True}
        api.save(api.DEVICES_FILE, devs)
        api._LOAD_CACHE.clear()
        by = {r["label"]: r for r in api._satellite_monitor_display(api._config_ro().get("monitors"))}
        self.assertEqual(by["web"]["detail"], "the host is in audit mode and does not run probes")
        self.assertEqual(by["sat"]["detail"], "awaiting first satellite probe", "only a host can be in audit mode")

    def test_a_host_that_is_gone_has_no_name(self):
        cfg = api.load(api.CONFIG_FILE)
        cfg["monitors"].append(self.mon(label="orphan", via_host="gone-host"))
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()
        by = {r["label"]: r for r in api._satellite_monitor_display(api._config_ro().get("monitors"))}
        self.assertEqual((by["orphan"]["origin"], by["orphan"]["origin_name"]), ("host:gone-host", ""))

    def test_a_long_host_name_is_cut(self):
        devs = api.load(api.DEVICES_FILE)
        devs["lin1"]["name"] = "web1" + "z" * 400
        api.save(api.DEVICES_FILE, devs)
        api._LOAD_CACHE.clear()
        by = {r["label"]: r for r in api._satellite_monitor_display(api._config_ro().get("monitors"))}
        self.assertEqual(len(by["db"]["origin_name"]), 128)
        devs["lin1"]["name"] = {"not": "text"}
        api.save(api.DEVICES_FILE, devs)
        api._LOAD_CACHE.clear()
        api._satellite_monitor_display(api._config_ro().get("monitors"))      # a name of the wrong kind does not raise


class TestAResultThatIsNoLongerCurrent(_Save):
    """A monitor probed by a host or a satellite keeps its last result. When the prober stops reporting, that result must not go on
    reading as the state of the check: a green arrow from three days ago is a reading nobody took today."""

    NOW = 1_800_000_000

    def setUp(self):
        super().setUp()
        api.save(api.CONFIG_FILE, {"monitors": [
            self.mon(label="db", via_host="lin1"),
            {"label": "sat", "type": "tcp", "target": "10.0.0.9:22", "target_kind": "host", "via_satellite": "sat-1"},
            self.mon(label="paused", via_host="lin1", paused=True)]})
        api._LOAD_CACHE.clear()

    def put(self, label, age, by="host:lin1", **kw):
        row = dict({"label": label, "type": "tcp", "target": "10.0.0.5:5432", "ok": True, "detail": "open", "checked": self.NOW - age}, **kw)
        if by is not None:
            row["by"] = by
        store = api.load(api.SATELLITE_MON_FILE) or {}
        store[label] = row
        api.save(api.SATELLITE_MON_FILE, store)
        api._LOAD_CACHE.clear()

    def rows(self):
        with mock.patch.object(api.time, "time", return_value=self.NOW):
            return {r["label"]: r for r in api._satellite_monitor_display(api._config_ro().get("monitors"))}

    def test_a_recent_result_is_a_reading(self):
        self.put("db", 100)
        row = self.rows()["db"]
        self.assertNotIn("state", row)
        self.assertEqual((row["ok"], row["detail"]), (True, "open"))

    def test_the_limit_is_two_rounds_of_the_interval_and_the_hosts_report(self):
        # the interval is 300 s and the host reports every 60 s: 2 x (300 + 60) = 720
        self.put("db", 720)
        self.assertNotIn("state", self.rows()["db"], "exactly at the limit is still current")
        self.put("db", 721)
        self.assertEqual(self.rows()["db"]["state"], "stale")

    def test_a_stale_result_keeps_what_it_was_and_says_so(self):
        self.put("db", 5000)
        up = self.rows()["db"]
        self.assertEqual((up["state"], up["ok"]), ("stale", True))
        self.assertEqual(up["detail"], "no recent result from the host (the last one was up: open)")
        self.assertEqual(up["checked"], self.NOW - 5000, "the age column still says how old it is")
        self.put("db", 5000, ok=False, detail="connection refused")
        down = self.rows()["db"]
        self.assertEqual((down["state"], down["ok"]), ("stale", False))
        self.assertEqual(down["detail"], "no recent result from the host (the last one was down: connection refused)")
        self.put("db", 5000, detail="")
        self.assertEqual(self.rows()["db"]["detail"], "no recent result from the host (the last one was up)")

    def test_a_host_that_reports_slowly_is_given_the_time_it_needs(self):
        self.put("db", 1000)
        self.assertEqual(self.rows()["db"]["state"], "stale", "60 s between reports: the limit is 720")
        devs = api.load(api.DEVICES_FILE)
        devs["lin1"]["poll_interval"] = 600
        api.save(api.DEVICES_FILE, devs)
        api._LOAD_CACHE.clear()
        self.assertNotIn("state", self.rows()["db"], "600 s between reports: the limit is 1800")
        self.put("db", 1801)
        self.assertEqual(self.rows()["db"]["state"], "stale")

    def test_a_poll_interval_that_is_not_a_number_is_the_default(self):
        for junk in ("soon", None, [], {}, 10 ** 400, True):
            devs = api.load(api.DEVICES_FILE)
            devs["lin1"]["poll_interval"] = junk
            api.save(api.DEVICES_FILE, devs)
            api._LOAD_CACHE.clear()
            self.put("db", 100)
            self.assertNotIn("state", self.rows()["db"], repr(junk)[:20])

    def test_the_limit_follows_the_monitor_interval(self):
        for interval, limit in ((60, 240), (600, 1320), (3600, 7320)):
            cfg = api.load(api.CONFIG_FILE)
            cfg["monitor_interval"] = interval
            api.save(api.CONFIG_FILE, cfg)
            api._LOAD_CACHE.clear()
            self.put("db", limit)
            self.assertNotIn("state", self.rows()["db"], (interval, limit))
            self.put("db", limit + 1)
            self.assertEqual(self.rows()["db"]["state"], "stale", (interval, limit))

    def interval_is(self, value):
        cfg = api.load(api.CONFIG_FILE)
        cfg["monitor_interval"] = value
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()

    def test_an_interval_that_is_not_a_number_is_five_minutes(self):
        for junk in ("x", None, [], {}, 0, ""):
            self.interval_is(junk)
            self.put("db", 700)
            self.assertNotIn("state", self.rows()["db"], f"{junk!r}: five minutes, a limit of 720")
            self.put("db", 721)
            self.assertEqual(self.rows()["db"]["state"], "stale", repr(junk))

    def test_a_setting_the_loader_let_through_is_five_minutes_too(self):
        # the loader repairs a setting of the wrong kind before it gets here, so the guard is reached by handing it one directly
        monitors = api._config_ro().get("monitors")
        for junk in ("x", "", [], {}, float("nan"), float("inf")):
            self.put("db", 700)
            with mock.patch.object(api, "_config_ro", return_value={"monitor_interval": junk}):
                with mock.patch.object(api.time, "time", return_value=self.NOW):
                    row = {r["label"]: r for r in api._satellite_monitor_display(monitors)}["db"]
            self.assertNotIn("state", row, repr(junk))
            self.put("db", 721)
            with mock.patch.object(api, "_config_ro", return_value={"monitor_interval": junk}):
                with mock.patch.object(api.time, "time", return_value=self.NOW):
                    row = {r["label"]: r for r in api._satellite_monitor_display(monitors)}["db"]
            self.assertEqual(row["state"], "stale", repr(junk))

    def test_an_interval_below_the_minimum_is_the_minimum(self):
        for small in (-5, 1, 59):
            self.interval_is(small)
            self.put("db", 240)
            self.assertNotIn("state", self.rows()["db"], f"{small}: a minute, a limit of 240")
            self.put("db", 241)
            self.assertEqual(self.rows()["db"]["state"], "stale", small)

    def test_an_interval_too_large_to_be_one_does_not_raise(self):
        self.interval_is(10 ** 400)
        self.put("db", 5000)
        self.assertEqual(self.rows()["db"]["checked"], self.NOW - 5000, "the row is there, whatever the loader made of the setting")

    def test_a_satellite_reports_at_its_interval(self):
        self.put("sat", 1200, by="satellite:sat-1", target="10.0.0.9:22")
        self.assertNotIn("state", self.rows()["sat"], "2 x (300 + 300)")
        self.put("sat", 1201, by="satellite:sat-1", target="10.0.0.9:22")
        row = self.rows()["sat"]
        self.assertEqual(row["state"], "stale")
        self.assertEqual(row["detail"], "no recent result from the satellite (the last one was up: open)")

    def test_a_stamp_that_is_not_a_time_is_old_and_one_in_the_future_is_not(self):
        for junk in ("soon", None, [], {}, 10 ** 400, "12"):
            self.put("db", 0, checked=junk)
            self.assertEqual(self.rows()["db"]["state"], "stale", repr(junk)[:20])
        self.put("db", -10 ** 6)
        self.assertNotIn("state", self.rows()["db"], "a result stamped ahead of this clock is not old")

    def test_numbers_a_file_could_hold_but_the_store_will_not_write(self):
        # a hand-edited file can carry NaN and Infinity, which the writer refuses, so these go to the helpers directly
        for junk in (float("nan"), float("inf"), float("-inf")):
            self.assertTrue(api._probe_result_stale(junk, 300, 60, self.NOW), repr(junk))
        self.assertEqual(api._host_poll_seconds({"poll_interval": float("nan")}), 60)
        self.assertEqual(api._host_poll_seconds({"poll_interval": float("inf")}), 60)
        self.assertEqual(api._host_poll_seconds(None), 60)
        self.assertEqual(api._host_poll_seconds("not a host"), 60)
        self.assertEqual(api._host_poll_seconds({"poll_interval": 0}), 1, "never zero")
        self.assertEqual(api._host_poll_seconds({"poll_interval": 90}), 90)

    def test_a_monitor_that_has_not_reported_yet_is_waiting_not_up(self):
        row = self.rows()["db"]
        self.assertEqual((row["state"], row["detail"], row["checked"]), ("pending", "awaiting first probe from the host", 0))
        self.assertEqual(self.rows()["sat"]["state"], "pending")

    def test_the_result_of_another_prober_is_no_result(self):
        # the monitor was assigned to another host, to a satellite, or to the server, and the old prober's result is still stored
        for other in ("host:lin2", "satellite:sat-1", "host:gone", "server"):
            self.put("db", 100, by=other)
            row = self.rows()["db"]
            self.assertEqual((row["state"], row["origin"], row["checked"]), ("pending", "host:lin1", 0), other)
        self.put("sat", 100, by="host:lin1", target="10.0.0.9:22")
        self.assertEqual(self.rows()["sat"]["state"], "pending", "and the other way round")

    def test_a_result_stored_before_the_producer_was_recorded_is_still_shown(self):
        self.put("db", 100, by=None)
        self.assertNotIn("state", self.rows()["db"])
        self.put("db", 5000, by=None)
        self.assertEqual(self.rows()["db"]["state"], "stale", "and it ages like any other")

    def test_the_producer_is_not_in_the_row(self):
        self.put("db", 100)
        self.put("sat", 100, by="satellite:sat-1")
        for label, row in self.rows().items():
            self.assertNotIn("by", row, label)

    def test_the_result_is_stamped_with_who_probed_it(self):
        self.assertEqual(api.host_probe_ingest("lin1", [{"label": "db", "type": "tcp", "target": "x:1", "ok": True}]), 1)
        api._LOAD_CACHE.clear()
        self.assertEqual(api.load(api.SATELLITE_MON_FILE)["db"]["by"], "host:lin1")
        real = api.require_satellite
        api.require_satellite = lambda: "sat-1"
        self.addCleanup(setattr, api, "require_satellite", real)
        api.method = lambda: "POST"
        api.get_json_obj = lambda: {"results": [{"label": "sat", "type": "tcp", "target": "10.0.0.9:22", "ok": True, "detail": "open"}]}
        try:
            api.handle_satellite_monitor_results()
        except api.HTTPError:
            pass
        api._LOAD_CACHE.clear()
        self.assertEqual(api.load(api.SATELLITE_MON_FILE)["sat"]["by"], "satellite:sat-1")

    def test_a_result_that_arrives_makes_a_stale_row_current_again(self):
        self.put("db", 5000)
        self.assertEqual(self.rows()["db"]["state"], "stale")
        self.assertEqual(api.host_probe_ingest("lin1", [{"label": "db", "type": "tcp", "target": "x:1", "ok": True, "detail": "open"}]), 1)
        api._LOAD_CACHE.clear()
        row = {r["label"]: r for r in api._satellite_monitor_display(api._config_ro().get("monitors"))}["db"]
        self.assertNotIn("state", row)
        self.assertEqual(row["detail"], "open")

    def test_the_monitor_page_gets_the_states(self):
        self.put("db", 5000)
        api.method = lambda: "GET"
        self.cap.clear()
        with mock.patch.object(api.time, "time", return_value=self.NOW):
            try:
                api.handle_monitor_run()
            except api.HTTPError:
                pass
        self.assertEqual(self.cap.get("s"), 200, self.cap)
        by = {r["label"]: r for r in self.cap["b"]["monitors"]}
        self.assertEqual(by["db"]["state"], "stale")
        self.assertEqual(by["sat"]["state"], "pending")
        self.assertNotIn("state", by["paused"], "a paused monitor is its own row")
        self.assertTrue(by["paused"]["paused"])
        self.assertNotIn("by", json.dumps(self.cap["b"]), "who probed is not given to a reader")

    def test_the_row_of_a_quiet_host_does_not_name_it_to_a_reader_who_cannot_see_it(self):
        self.put("db", 5000)
        rows = [dict(r) for r in self.rows().values()]
        before = {r["label"]: r for r in rows}["db"]
        self.assertEqual((before["origin"], before["origin_name"]), ("host:lin1", "web1"), "an administrator is told")
        with mock.patch.object(api, "_scope_filter_devices", return_value={}):
            masked = {r["label"]: r for r in api._mask_host_origins(rows)}["db"]
        self.assertEqual(masked["origin"], "host")
        self.assertNotIn("origin_name", masked)
        self.assertEqual(masked["state"], "stale")
        self.assertNotIn("web1", json.dumps(masked))
        self.assertNotIn("lin1", json.dumps(masked))


class TestThroughTheHeartbeat(_Save):
    """The response carries the monitors and the body carries the results, with the agent's own request."""

    DEV = "lin1"

    def setUp(self):
        super().setUp()
        api._env = self._real["_env"]            # the heartbeat reads its body from the request environment
        api.method = self._real["method"]
        api.save(api.CONFIG_FILE, {"monitor_interval": 120, "monitors": [self.mon(label="db"), self.mon(label="other", via_host="lin2")]})
        now = int(time.time())

        def host(dev_id, name, os_name, token):
            return {"id": dev_id, "name": name, "hostname": name, "os": os_name, "token": token, "last_seen": now, "enrolled": now,
                    "tags": [], "group": "", "sysinfo": {}, "monitored": True}
        api.save(api.DEVICES_FILE, {"lin1": host("lin1", "web1", "Ubuntu 24.04", "tok"), "lin2": host("lin2", "web2", "Debian 12", "tok2"),
                                    "win1": host("win1", "win", "Windows 11", "wtok")})
        for f, empty in ((api.ALERTS_FILE, {"alerts": []}), (api.CONTAINERS_FILE, {}), (api.MAINT_FILE, {"windows": []}),
                         (api.MAINT_SUPPRESS_LOG, {"entries": []}), (api.CMD_OUTPUT_FILE, {})):
            api.save(f, empty)
        api._LOAD_CACHE.clear()
        self._envsave = dict(os.environ)

        class _Captured(SystemExit):
            def __init__(s, status, body):
                super().__init__(0)
                s.status, s.body = status, body
        self.Captured = _Captured

        def fake(status, data):
            raise _Captured(status, data)
        api.respond = fake

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._envsave)
        super().tearDown()

    def beat(self, dev="lin1", token="tok", **body):
        import io
        raw = json.dumps(dict({"device_id": dev, "token": token}, **body)).encode()
        os.environ.update({"REQUEST_METHOD": "POST", "PATH_INFO": "/api/heartbeat", "QUERY_STRING": "", "CONTENT_LENGTH": str(len(raw))})
        for k in ("HTTP_X_TOKEN", "HTTP_X_RP_VAULT_KEY"):
            os.environ.pop(k, None)

        class _Stdin:
            def __init__(s, data):
                s.buffer = io.BytesIO(data)
        api.sys.stdin = _Stdin(raw)
        api._LOAD_CACHE.clear()
        try:
            api.handle_heartbeat()
        except self.Captured as c:
            return c.body
        return None

    def test_the_response_carries_the_monitors_and_the_interval(self):
        resp = self.beat()
        self.assertEqual([m["label"] for m in resp["host_monitors"]], ["db"])
        self.assertEqual(resp["host_monitor_interval"], 120)

    def test_the_key_is_there_even_when_empty_and_absent_for_other_agents(self):
        api.save(api.CONFIG_FILE, {"monitors": []})
        api._LOAD_CACHE.clear()
        self.assertEqual(self.beat()["host_monitors"], [])
        self.assertNotIn("host_monitors", self.beat(dev="win1", token="wtok"), "the Windows agent never sees the key")

    def test_the_results_in_the_body_are_taken(self):
        self.beat(monitor_results=[{"label": "db", "type": "tcp", "target": "10.0.0.5:5432", "ok": False, "detail": "closed", "latency_ms": 3.0},
                                   {"label": "other", "type": "tcp", "target": "x:1", "ok": True}])
        api._LOAD_CACHE.clear()
        store = api.load(api.SATELLITE_MON_FILE)
        self.assertEqual(set(store), {"db"}, "and not the one that belongs to another host")
        self.assertFalse(store["db"]["ok"])

    def test_a_hostile_body_does_not_fail_the_beat(self):
        for junk in ("x", 5, {"a": 1}, [None, 5], [{"label": ["x"]}]):
            self.assertIsNotNone(self.beat(monitor_results=junk), repr(junk))


class TestWhoSeesTheHost(_Save):
    """A row probed from a host names it in `origin`. A role scoped to other hosts gets the row without that id."""

    def setUp(self):
        super().setUp()
        devs = api.load(api.DEVICES_FILE)
        devs["lin1"]["tags"] = ["zone-a"]
        devs["lin2"]["tags"] = ["zone-b"]
        api.save(api.DEVICES_FILE, devs)
        api.save(api.ROLES_FILE, {"roles": [{"name": "zone-a-ops", "permissions": [], "scope": {"type": "tags", "values": ["zone-a"]}}]})
        api.save(api.CONFIG_FILE, {"monitors": [self.mon(label="a-db", via_host="lin1"), self.mon(label="b-db", via_host="lin2"),
                                                self.mon(label="b-paused", via_host="lin2", paused=True)]})
        api._LOAD_CACHE.clear()
        patch = mock.patch.object(api, "_ip_ratelimit", lambda *a, **k: True)
        patch.start()
        self.addCleanup(patch.stop)

    def origins(self, user, role):
        api.verify_token = lambda *a, **k: (user, role)
        api._LOAD_CACHE.clear()
        self.cap.clear()
        try:
            api.handle_monitor_run()
        except api.HTTPError:
            pass
        self.assertEqual(self.cap.get("s"), 200, self.cap)
        return {r["label"]: r.get("origin") for r in self.cap["b"]["monitors"]}

    def test_an_administrator_sees_every_host(self):
        self.assertEqual(self.origins("admin", "admin"), {"a-db": "host:lin1", "b-db": "host:lin2", "b-paused": "host:lin2"})
        names = {r["label"]: r.get("origin_name") for r in self.cap["b"]["monitors"]}
        self.assertEqual(names, {"a-db": "web1", "b-db": "web2", "b-paused": "web2"}, "the paused row names its host as well")

    def test_a_scoped_role_does_not_get_the_id_of_a_host_outside_its_scope(self):
        got = self.origins("ops", "zone-a-ops")
        self.assertEqual(got, {"a-db": "host:lin1", "b-db": "host", "b-paused": "host"})
        self.assertNotIn("lin2", json.dumps(self.cap["b"]), "the id is nowhere in the answer")
        self.assertNotIn("web2", json.dumps(self.cap["b"]), "and neither is the name")
        self.assertIn("web1", json.dumps(self.cap["b"]), "while the host in the role's scope keeps its name")

    def test_a_row_that_is_not_from_a_host_is_left_alone(self):
        rows = [{"label": "x", "origin": "server"}, {"label": "y", "origin": "satellite:sat-1"}, {"label": "z"}, "junk", None]
        api.verify_token = lambda *a, **k: ("ops", "zone-a-ops")
        self.assertEqual(api._mask_host_origins(rows), rows)
        self.assertEqual(rows[0]["origin"], "server")


class TestExport(_Save):

    def test_an_export_does_not_carry_the_host(self):
        # via_host is an id local to one install, like via_satellite: on another install it would name no host
        api.save(api.CONFIG_FILE, {"monitors": [self.mon(label="db"), {"label": "pub", "type": "tcp", "target": "example.org:443", "target_kind": "host"}]})
        api._LOAD_CACHE.clear()
        try:
            api.handle_export_monitors()
        except api.HTTPError:
            pass
        out = self.cap["b"]["monitors"]
        self.assertEqual([m["label"] for m in out], ["db", "pub"])
        self.assertNotIn("via_host", json.dumps(out))


class TestRegistration(unittest.TestCase):

    def test_the_module_is_wired(self):
        src = (ROOT / "server" / "cgi-bin" / "api.py").read_text()
        self.assertIn("host_probe_validate(vh, mtype, m)", src)
        self.assertIn("host_probe_ingest(dev_id, body['monitor_results'])", src)
        self.assertIn("common_resp['host_monitors'] = _hm", src)
        self.assertIn("if m.get('via_host'):\n            continue", src)



if __name__ == "__main__":
    unittest.main()

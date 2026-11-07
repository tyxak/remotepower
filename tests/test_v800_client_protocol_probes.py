#!/usr/bin/env python3
"""8.0.0: the smtp, imap, ssh and ntp monitors run from a host's agent and from a satellite, with the server's own handshake.

A monitor has to give the same answer wherever it is probed from, so the clients do not have a second implementation: the block between the
two marker lines of client/remotepower-agent.py and client/remotepower-satellite.py is the text of server/cgi-bin/protocol_probes.py, written by
tools/sync-protocol-probes.py with its names prefixed. This holds:

* the blocks are what the tool writes, and the tool's check can say no;
* the blocks stay in their own names: nothing the client defines is shadowed, and no bare `socket` or `time` of the block escapes the prefix;
* the three engines (the server's, the agent's, the satellite's) give the same `(ok, detail)` for the same service, over real sockets: a greeting
  that is refused, STARTTLS and implicit TLS with and without a certificate check, a banner that is not SSH, a server that is out of sync;
* the address rule of a client: loopback may be probed, metadata and link-local never, and nothing is connected to before the check;
* a client reads a spec the way the other does, takes only what it checks, and says which types it runs: the agent in its heartbeat, the
  satellite in a header on every call it makes.
"""
import ast
import importlib.machinery
import importlib.util
import re
import socket
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_v800_protocol_probes as pp  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
AGENT = ROOT / "client" / "remotepower-agent.py"
SATELLITE = ROOT / "client" / "remotepower-satellite.py"
P = pp.P


def setUpModule():
    pp.setUpModule()


def tearDownModule():
    pp.tearDownModule()


def _load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)             # type: ignore[arg-type]
    loader.exec_module(mod)                                  # type: ignore[union-attr]
    return mod


def _tool():
    loader = importlib.machinery.SourceFileLoader("sync_protocol_probes", str(ROOT / "tools" / "sync-protocol-probes.py"))
    spec = importlib.util.spec_from_loader("sync_protocol_probes", loader)
    mod = importlib.util.module_from_spec(spec)             # type: ignore[arg-type]
    loader.exec_module(mod)                                  # type: ignore[union-attr]
    return mod


def _same(detail):
    """A detail with what changes from one run to the next taken out: durations, the clock offset and the delay."""
    detail = re.sub(r"\d+ms", "Nms", detail)
    detail = re.sub(r"offset [+-]?\d+(\.\d+)? ms", "offset X ms", detail)
    return re.sub(r"delay \d+ ms", "delay X ms", detail)


class TestTheBlocksAreTheServersCode(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tool = _tool()
        cls.block = cls.tool.render()

    def test_each_client_holds_the_block_the_tool_writes(self):
        self.assertEqual(self.tool.main(["--check"]), 0, "run tools/sync-protocol-probes.py")
        for path in (AGENT, SATELLITE):
            text = path.read_text()
            self.assertEqual(text.count(self.tool.BEGIN), 1, path.name)
            start = text.index(self.tool.BEGIN)
            self.assertEqual(text[start:text.index(self.tool.END, start) + len(self.tool.END) + 1], self.block, path.name)

    def test_the_check_says_no_to_a_block_that_was_edited_or_is_missing(self):
        for path, anchor in self.tool.TARGETS.items():
            text = path.read_text()
            self.assertEqual(self.tool.splice(text, self.block, anchor), text, "control: the real file is current")
            edited = text.replace("_pp_TLS_MODES = ", "_pp_TLS_MODES = ('x',) + ", 1)
            self.assertNotEqual(self.tool.splice(edited, self.block, anchor), edited, "an edit inside the block is written over: " + path.name)
            gone = text[:text.index(self.tool.BEGIN)] + text[text.index(self.tool.END, text.index(self.tool.BEGIN)) + len(self.tool.END) + 1:]
            self.assertIn(self.tool.BEGIN, self.tool.splice(gone, self.block, anchor), "a missing block is put back in front of its anchor: " + path.name)

    def test_the_block_is_the_servers_text_with_only_the_names_changed(self):
        server = (ROOT / "server" / "cgi-bin" / "protocol_probes.py").read_text()
        body = server[server.index("DEFAULT_PORTS = "):]
        back = self.block[self.block.index("_pp_DEFAULT_PORTS = "):self.block.index(self.tool.END)].rstrip("\n") + "\n"
        for name in sorted(self.tool._defined_names(server)):
            back = re.sub(r"(?<![\w.])%s\b" % re.escape(self.tool._new(name)), name, back)
        for mod in self.tool.MODULES:
            back = re.sub(r"(?<![\w.])_pp_%s\b" % mod, mod, back)
        self.assertEqual(back.rstrip("\n"), body.rstrip("\n"), "renaming back gives the server's text: nothing else was changed")

    def test_the_block_compiles_and_uses_no_name_outside_its_own_prefix(self):
        code = compile(self.block, "block", "exec")
        self.assertTrue(code)
        tree = ast.parse(self.block)
        defined = {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
        defined |= {t.id for n in tree.body if isinstance(n, ast.Assign) for t in n.targets if isinstance(t, ast.Name)}
        defined |= {a.asname for n in tree.body if isinstance(n, ast.Import) for a in n.names}
        self.assertGreater(len(defined), 20, "the population is not empty")
        defined = {d for d in defined if d}
        self.assertTrue(all(d.startswith("_pp_") for d in defined), sorted(d for d in defined if not d.startswith("_pp_")))
        bare = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id in self.tool.MODULES}
        self.assertEqual(bare, set(), "a bare socket, ssl, struct or time would be the client's own, not the block's")

    def test_a_client_defines_no_name_of_the_block_twice(self):
        for path in (AGENT, SATELLITE):
            names = [n.name for n in ast.parse(path.read_text()).body if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name.startswith("_pp_")]
            self.assertEqual(len(names), len(set(names)), path.name)
            self.assertIn("_pp_run", names)


class TestTheThreeEnginesAgree(unittest.TestCase):
    """The same service, probed by the server's module, the agent and the satellite: the same verdict and the same words."""

    @classmethod
    def setUpClass(cls):
        cls.agent = _load("agent_pp_under_test", AGENT)
        cls.sat = _load("sat_pp_under_test", SATELLITE)

    def serve(self, handler):
        s = pp._Tcp(handler)
        self.addCleanup(s.stop)
        return s

    def three(self, mtype, port, **m):
        """[(ok, detail)] of the server's module, the agent and the satellite for one monitor on 127.0.0.1:port."""
        ctx = pp.UNVERIFIED if m.get("verify_tls") is False else None
        server = P.run(mtype, "127.0.0.1", port, m, peer_ok=lambda ip: True, ssl_ctx=ctx, timeout=3)
        raw = dict({"label": "x", "type": mtype, "target": "127.0.0.1:%d" % port}, **m)
        out = [server]
        for client in (self.agent, self.sat):
            spec = client._probe_spec(raw)
            self.assertIsNotNone(spec, raw)
            r = client._probe_run_one(spec)
            out.append((r["ok"], r["detail"]))
        return out

    def agree(self, mtype, port, expect_ok, words, **m):
        got = self.three(mtype, port, **m)
        norm = [(ok, _same(d)) for ok, d in got]
        self.assertEqual(norm[0], norm[1], "the agent says what the server says: %r" % (got,))
        self.assertEqual(norm[0], norm[2], "the satellite says what the server says: %r" % (got,))
        self.assertEqual(got[0][0], expect_ok, got)
        self.assertIn(words, got[0][1], got)

    def test_smtp(self):
        self.agree("smtp", self.serve(pp.smtp()).port, True, "mail.test ESMTP ready")
        self.agree("smtp", self.serve(pp.smtp(greeting=b"554 no service\r\n")).port, False, "554")
        self.agree("smtp", self.serve(pp.smtp(greeting=b"SSH-2.0-x\r\n")).port, False, "not SMTP")
        self.agree("smtp", self.serve(pp.smtp(ehlo=(b"502 no\r\n",))).port, False, "EHLO refused")

    def test_smtp_with_tls_with_and_without_a_certificate_check(self):
        self.agree("smtp", self.serve(pp.smtp()).port, True, "STARTTLS", tls="starttls", verify_tls=False)
        self.agree("smtp", self.serve(pp.smtp(implicit=True)).port, True, "TLS", tls="tls", verify_tls=False)
        self.agree("smtp", self.serve(pp.smtp()).port, False, "certificate was not accepted", tls="starttls")
        self.agree("smtp", self.serve(pp.smtp(ehlo=(b"250 8BITMIME\r\n",))).port, False, "STARTTLS", tls="starttls", verify_tls=False)

    def test_imap(self):
        self.agree("imap", self.serve(pp.imap()).port, True, "IMAP")
        self.agree("imap", self.serve(pp.imap(greeting=b"* BYE going away\r\n")).port, False, "refused: going away")
        self.agree("imap", self.serve(pp.imap()).port, True, "STARTTLS", tls="starttls", verify_tls=False)
        self.agree("imap", self.serve(pp.imap(implicit=True)).port, True, "TLS", tls="tls", verify_tls=False)

    def test_ssh(self):
        self.agree("ssh", self.serve(pp.banner(b"SSH-2.0-OpenSSH_9.6\r\n")).port, True, "SSH-2.0-OpenSSH_9.6")
        self.agree("ssh", self.serve(pp.banner(b"220 hello\r\n" * 9)).port, False, "no SSH banner")
        self.agree("ssh", self.serve(pp.banner(b"SSH-1.5-old\r\n")).port, False, "not SSH 2")

    def agree_ntp(self, expect_ok, words, fake, **m):
        """The fake NTP server answers one request, so each engine asks a server of its own that is made the same way."""
        got = []
        for engine in ("server", "agent", "satellite"):
            ntp = pp._Ntp(**fake)
            self.addCleanup(ntp.stop)
            if engine == "server":
                got.append(P.run("ntp", "127.0.0.1", ntp.port, m, peer_ok=lambda ip: True, timeout=3))
            else:
                client = self.agent if engine == "agent" else self.sat
                r = client._probe_run_one(client._probe_spec(dict({"label": "x", "type": "ntp", "target": "127.0.0.1:%d" % ntp.port}, **m)))
                got.append((r["ok"], r["detail"]))
        norm = [(ok, _same(d)) for ok, d in got]
        self.assertEqual(norm[0], norm[1], "the agent says what the server says: %r" % (got,))
        self.assertEqual(norm[0], norm[2], "the satellite says what the server says: %r" % (got,))
        self.assertEqual(got[0][0], expect_ok, got)
        self.assertIn(words, got[0][1], got)

    def test_ntp(self):
        self.agree_ntp(True, "stratum 2", dict(skew=0.0, stratum=2))
        self.agree_ntp(False, "limit 1000 ms", dict(skew=5.0, stratum=2), max_offset_ms=1000)
        self.agree_ntp(True, "stratum 2", dict(skew=5.0, stratum=2), max_offset_ms=60000)
        self.agree_ntp(False, "kiss-of-death RATE", dict(kod=b"RATE", stratum=0))
        self.agree_ntp(False, "not synchronised", dict(stratum=16))

    def test_a_closed_port_and_a_name_that_does_not_resolve_are_said_in_words(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        self.agree("smtp", port, False, "the connection was refused")
        raw = {"label": "x", "type": "smtp", "target": "no-such-host.invalid:25"}
        for client in (self.agent, self.sat):
            r = client._probe_run_one(client._probe_spec(raw))
            self.assertEqual((r["ok"], r["detail"]), (False, "the host name does not resolve"))

    def test_the_result_has_the_keys_a_result_always_has(self):
        s = self.serve(pp.banner(b"SSH-2.0-x\r\n"))
        for client in (self.agent, self.sat):
            r = client._probe_run_one(client._probe_spec({"label": "ssh box", "type": "ssh", "target": "127.0.0.1:%d" % s.port}))
            self.assertEqual(set(r), {"label", "type", "target", "ok", "detail", "latency_ms"})
            self.assertEqual((r["label"], r["type"], r["ok"]), ("ssh box", "ssh", True))


class TestTheAddressRuleOfAClient(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.agent = _load("agent_pp_addr", AGENT)
        cls.sat = _load("sat_pp_addr", SATELLITE)

    def test_metadata_and_link_local_are_refused_before_anything_is_connected_to_and_loopback_is_not(self):
        for client in (self.agent, self.sat):
            made = []
            real = socket.create_connection
            socket.create_connection = lambda addr, timeout=None, **k: made.append(addr) or (_ for _ in ()).throw(OSError("never reached"))
            try:
                for host in ("169.254.169.254", "169.254.1.1", "100.100.100.200", "192.0.0.192", "0.0.0.0", "224.0.0.1"):
                    spec = client._probe_spec({"label": "x", "type": "smtp", "target": host + ":25"})
                    r = client._probe_run_one(spec)
                    self.assertEqual((r["ok"], r["detail"]), (False, "that address is not allowed (link-local or cloud metadata)"), host)
                self.assertEqual(made, [], "no connection was made to any of them")
                r = client._probe_run_one(client._probe_spec({"label": "x", "type": "smtp", "target": "127.0.0.1:25"}))
                self.assertEqual((r["ok"], r["detail"]), (False, "the connection failed"), "the stub refuses, so it is a failure in words, not a block")
                self.assertEqual(made, [("127.0.0.1", 25)], "loopback is the point of probing from a host: it is connected to")
            finally:
                socket.create_connection = real


class TestAClientReadsASpecAndSaysWhatItRuns(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.agent = _load("agent_pp_spec", AGENT)
        cls.sat = _load("sat_pp_spec", SATELLITE)

    def both(self, raw):
        a, s = self.agent._probe_spec(raw), self.sat._probe_spec(raw)
        self.assertEqual(a, s, "the agent and the satellite read a spec the same way: %r" % (raw,))
        return a

    def test_a_handshake_spec_is_host_and_port_with_the_protocols_own_port_by_default(self):
        spec = self.both({"label": "mail", "type": "smtp", "target": "mail.lan:587", "tls": "starttls", "verify_tls": False})
        self.assertEqual(spec, {"label": "mail", "type": "smtp", "target": "mail.lan:587", "host": "mail.lan", "port": 587, "tls": "starttls", "verify_tls": False})
        for mtype, port in (("smtp", 25), ("imap", 143), ("ssh", 22), ("ntp", 123)):
            spec = self.both({"label": "x", "type": mtype, "target": "h.lan"})
            self.assertEqual((spec["host"], spec["port"]), ("h.lan", port), mtype)
        spec = self.both({"label": "clock", "type": "ntp", "target": "pool.ntp.org", "max_offset_ms": 250})
        self.assertEqual(spec["max_offset_ms"], 250)

    def test_what_is_not_a_choice_or_a_sane_number_is_left_out_and_what_is_not_a_spec_is_none(self):
        spec = self.both({"label": "x", "type": "smtp", "target": "h:25", "tls": "rot13", "max_offset_ms": True, "verify_tls": True})
        self.assertNotIn("tls", spec)
        self.assertNotIn("max_offset_ms", spec)
        self.assertNotIn("verify_tls", spec)
        for off in (0, -5, 3_600_001, "250", None, [250]):
            self.assertNotIn("max_offset_ms", self.both({"label": "x", "type": "ntp", "target": "h", "max_offset_ms": off}), off)
        for raw in ({"label": "x", "type": "smtp", "target": ""}, {"label": "", "type": "smtp", "target": "h:25"}, {"label": "x", "type": "ftp", "target": "h:21"},
                    {"label": "x", "type": "smtp", "target": "h:0"}, {"label": "x", "type": "smtp", "target": "h:70000"}, {"label": "x", "type": "smtp", "target": "h:abc"},
                    {"label": "x", "type": "smtp", "target": "bad host:25"}, {"label": "x", "type": "smtp", "target": "-oX:25"}, {"label": "x", "type": "smtp", "target": ":25"},
                    "smtp", None, ["x"]):
            self.assertIsNone(self.both(raw), repr(raw))

    def test_the_older_three_types_are_read_as_before(self):
        self.assertEqual(self.both({"label": "t", "type": "tcp", "target": "h:80"})["port"], 80)
        self.assertEqual(self.both({"label": "p", "type": "ping", "target": "h"})["type"], "ping")
        self.assertEqual(self.both({"label": "w", "type": "http", "target": "http://h/", "expect_status": 204})["expect_status"], 204)

    def test_each_client_says_the_types_it_runs(self):
        want = ["tcp", "http", "ping"] + list(P.TYPES)
        self.assertEqual(self.agent._probe_types(), want)
        self.assertEqual(self.sat._probe_types(), want)

    def test_the_satellite_says_it_in_a_header_on_every_call_to_the_server(self):
        seen = []

        class _Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n=-1):
                return b"{}"

        class _Opener:
            def open(self, req, timeout=None):
                seen.append((req.get_method(), req.full_url, req.get_header("X-rp-probes"), req.get_header("X-rp-satellite")))
                return _Resp()
        names = ("_OPENER", "UPSTREAM", "TOKEN")
        saved = {n: getattr(self.sat, n) for n in names}
        for n, v in zip(names, (_Opener(), "https://rp.test", "tok")):
            setattr(self.sat, n, v)
        try:
            self.sat._upstream_json("GET", "/api/satellite/monitor-work")
            self.sat._upstream_json("POST", "/api/satellite/monitor-results", {"results": []})
        finally:
            for n, v in saved.items():
                setattr(self.sat, n, v)
        self.assertEqual([s[2] for s in seen], ["tcp,http,ping,smtp,imap,ssh,ntp"] * 2)
        self.assertEqual([s[3] for s in seen], ["tok", "tok"])

    def test_the_agent_puts_its_types_in_the_sysinfo_it_sends(self):
        tree = ast.parse(AGENT.read_text())
        keyed = [n for n in ast.walk(tree) if isinstance(n, ast.Dict) and any(isinstance(k, ast.Constant) and k.value == "audit_mode" for k in n.keys)]
        self.assertEqual(len(keyed), 1, "the sysinfo dict is the one that carries audit_mode")
        pairs = {k.value: v for k, v in zip(keyed[0].keys, keyed[0].values) if isinstance(k, ast.Constant)}
        self.assertIn("probe_types", pairs)
        self.assertEqual(ast.unparse(pairs["probe_types"]), "_probe_types()")


class TestTheAgentFilesAreTheSame(unittest.TestCase):

    def test_the_extensionless_agent_is_the_py_file(self):
        self.assertEqual((ROOT / "client" / "remotepower-agent").read_bytes(), AGENT.read_bytes())


if __name__ == "__main__":
    unittest.main()

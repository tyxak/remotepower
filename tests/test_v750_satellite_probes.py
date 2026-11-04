#!/usr/bin/env python3
"""v7.5.0 (docs cross-check, finding W2-F3): a monitor assigned to a satellite is probed by the satellite.

A monitor can name a relay satellite (`via_satellite`) so that it is probed from the satellite's side of the network, which is the
only way to watch a service in a segment the server cannot reach. The server kept the assignment, listed the monitors on
GET /api/satellite/monitor-work and took results on POST /api/satellite/monitor-results. The satellite never called either, so no such
monitor was ever probed and its row showed nothing. The list itself read `body_value` and `body_mode`, keys no monitor has.

What this holds:

* The server hands out the same spec an agent gets for a monitor assigned to its host (a check for a text in the page included), and
  leaves out a paused monitor, another satellite's monitor and a type the engine does not run.
* The save refuses to assign what the engine cannot run: a dns check, a regex or a JSON check, a tag or a group, a cloud metadata
  address. It allows a tcp, http or ping check of a private or loopback address. A stored monitor that is left untouched is kept.
* The satellite's engine and the agent's give the same answer to the same specs, the same addresses and the same servers (a real
  listening and closed port, an HTTP server that answers 200, 404, 500, a redirect and a 405 to HEAD): copied code that drifts apart
  fails here.
* A whole round against a fake server: the satellite asks with its own token, runs the monitors side by side and reports a result for
  each, with the right verdicts. A hostile answer does not stop it. The metadata address is refused without a connection.
* `ping` that could not run (exit status 2) is not reported as an unreachable host.
* `main()` starts the poller, and not when RP_SATELLITE_PROBES=0.
"""

import http.server
import importlib.machinery
import importlib.util
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-sat-"))
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))

_ldr = importlib.machinery.SourceFileLoader("api_v750_sat", str(ROOT / "server" / "cgi-bin" / "api.py"))
_spec = importlib.util.spec_from_loader("api_v750_sat", _ldr)
api: Any = importlib.util.module_from_spec(_spec)         # type: ignore[arg-type]
_ldr.exec_module(api)                                     # type: ignore[union-attr]


def _load(name, path, env=None):
    with mock.patch.dict(os.environ, env or {}):
        loader = importlib.machinery.SourceFileLoader(name, str(path))
        spec = importlib.util.spec_from_loader(name, loader)
        mod = importlib.util.module_from_spec(spec)       # type: ignore[arg-type]
        loader.exec_module(mod)                           # type: ignore[union-attr]
    return mod


# ── servers on the loopback ─────────────────────────────────────────────────────────────────────────────────────────────────
class _Quiet(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass


class _Site(_Quiet):
    other_port = 0

    def _answer(self, head):
        if self.path == "/ok":
            self._send(200, b"hello world, all fine", head)
        elif self.path == "/missing":
            self._send(404, b"nope", head)
        elif self.path == "/boom":
            self._send(500, b"oops", head)
        elif self.path == "/moved":
            self.send_response(301)
            self.send_header("Location", f"http://127.0.0.1:{self.server.other_port}/landed")  # type: ignore[attr-defined]
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/no-head":
            self._send(405, b"", True) if head else self._send(200, b"get works", False)
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


class _Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    other_port = 0


def _serve(handler):
    srv = _Server(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ── the server side ─────────────────────────────────────────────────────────────────────────────────────────────────────────
class _ServerBase(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="rp-v750-sat-d-"))
        self._saved = {n: getattr(api, n) for n in ("CONFIG_FILE", "SATELLITES_FILE", "DEVICES_FILE")}
        for n, v in self._saved.items():
            setattr(api, n, self.d / v.name)   # the basename is the storage key on the SQL backends
        self.addCleanup(self._restore)
        api.save(api.SATELLITES_FILE, {"sat1": {"name": "dmz"}, "sat2": {"name": "lab"}})
        api.save(api.DEVICES_FILE, {})
        self.sat = "sat1"
        for name, value in (("verify_token", lambda token=None, *a, **k: ("alice", "admin")),
                            ("get_token_from_request", lambda: "t"),
                            ("require_satellite", lambda: self.sat),
                            ("audit_log", lambda *a, **k: None)):
            p = mock.patch.object(api, name, value)
            p.start()
            self.addCleanup(p.stop)

    def _restore(self):
        for n, v in self._saved.items():
            setattr(api, n, v)
        api._LOAD_CACHE.clear()

    def config(self, **cfg):
        api.save(api.CONFIG_FILE, dict(cfg))
        api._LOAD_CACHE.clear()

    def call(self, fn, method="GET", body=None):
        with mock.patch.object(api, "method", lambda: method), \
                mock.patch.object(api, "get_json_obj", lambda: json.loads(json.dumps(body or {}))), \
                mock.patch.object(api, "get_json_body", lambda: json.loads(json.dumps(body or {}))), \
                mock.patch.object(api, "_read_valid", lambda model, *a, **k: json.loads(json.dumps(body or {}))):
            try:
                fn()
            except api.HTTPError as e:
                return e.status, e.body
        self.fail("answered nothing")


class TestTheWorkTheServerHandsOut(_ServerBase):

    def test_the_spec_is_the_one_an_agent_gets_and_carries_the_checks(self):
        self.config(monitors=[
            {"label": "site", "type": "http", "target": "https://intranet.lab/health", "target_kind": "host", "via_satellite": "sat1",
             "expect_status": 204, "body_match": {"mode": "contains", "value": "ready"}, "method": "get", "verify_tls": False},
            {"label": "db", "type": "tcp", "target": "10.0.5.9:5432", "target_kind": "host", "via_satellite": "sat1"},
            {"label": "gw", "type": "ping", "target": "10.0.5.1", "target_kind": "host", "via_satellite": "sat1"},
        ], monitor_interval=120)
        status, body = self.call(api.handle_satellite_monitor_work)
        self.assertEqual(status, 200)
        self.assertEqual(body["interval"], 120)
        by = {m["label"]: m for m in body["monitors"]}
        self.assertEqual(set(by), {"site", "db", "gw"})
        site = by["site"]
        self.assertEqual((site["expect_status"], site["expect_contains"], site["method"], site["verify_tls"]), (204, "ready", "get", False))
        self.assertEqual(by["db"]["target"], "10.0.5.9:5432")
        self.assertEqual(body["monitors"], [api.monitor_spec(m) for m in api.load(api.CONFIG_FILE)["monitors"]])

    def test_a_paused_monitor_another_satellites_monitor_and_a_type_it_cannot_run_are_left_out(self):
        self.config(monitors=[
            {"label": "paused", "type": "ping", "target": "10.0.5.1", "via_satellite": "sat1", "paused": True},
            {"label": "theirs", "type": "ping", "target": "10.0.5.2", "via_satellite": "sat2"},
            {"label": "server's own", "type": "ping", "target": "10.0.5.3"},
            {"label": "old dns check", "type": "dns", "target": "example.org", "via_satellite": "sat1"},
            {"label": "mine", "type": "ping", "target": "10.0.5.4", "via_satellite": "sat1"},
        ])
        status, body = self.call(api.handle_satellite_monitor_work)
        self.assertEqual([m["label"] for m in body["monitors"]], ["mine"])


class TestWhatMayBeAssigned(_ServerBase):

    def save(self, *monitors):
        return self.call(api.handle_config_save, "POST", {"monitors": list(monitors)})

    def mon(self, **kw):
        return dict({"label": "m", "type": "tcp", "target": "10.0.5.9:5432", "via_satellite": "sat1"}, **kw)

    def test_tcp_http_and_ping_of_a_private_or_loopback_address_are_accepted(self):
        for m in (self.mon(), self.mon(type="http", target="http://10.0.5.9/health"), self.mon(type="ping", target="10.0.5.1"),
                  self.mon(type="tcp", target="127.0.0.1:8080")):
            with self.subTest(m=m):
                self.config()
                status, body = self.save(m)
                self.assertEqual(status, 200, body)
                self.assertEqual(api.load(api.CONFIG_FILE)["monitors"][0]["via_satellite"], "sat1")

    def test_what_the_engine_cannot_run_is_refused_with_a_reason(self):
        refused = (
            (self.mon(type="dns", target="example.org"), "tcp, http and ping"),
            (self.mon(type="http", target="http://10.0.5.9/", body_match={"mode": "regex", "value": "a+"}), "regex"),
            (self.mon(type="http", target="http://10.0.5.9/", expect_json={"path": "status"}), "JSON"),
            (self.mon(type="http", target="http://10.0.5.9/", max_latency_ms=500), "latency"),
            (self.mon(type="ping", target="web", target_kind="tag"), "one address"),
            (self.mon(type="tcp", target="169.254.169.254:80"), "cloud-metadata"),      # the target sanitiser refuses it first
            (self.mon(type="http", target="http://169.254.169.254/latest/meta-data/"), "cloud-metadata"),
        )
        for m, why in refused:
            with self.subTest(m=m):
                self.config()
                status, body = self.save(m)
                self.assertEqual(status, 400, body)
                self.assertIn(why, body["error"])

    def test_a_stored_monitor_that_is_left_untouched_is_kept(self):
        """A monitor stored before the check existed (a dns check on a satellite) survives a save that does not touch it."""
        old = {"label": "old dns", "type": "dns", "target": "example.org", "target_kind": "host", "paused": False, "via_satellite": "sat1"}
        self.config(monitors=[old])
        status, body = self.save(dict(old))
        self.assertEqual(status, 200, body)
        self.assertEqual([m["label"] for m in api.load(api.CONFIG_FILE)["monitors"]], ["old dns"])


# ── the satellite's engine against the agent's ─────────────────────────────────────────────────────────────────────────────
class TestTheEnginesAgree(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.agent = _load("agent_v750_sat", ROOT / "client" / "remotepower-agent.py")
        cls.sat = _load("sat_v750_engine", ROOT / "client" / "remotepower-satellite.py",
                        {"RP_UPSTREAM": "http://127.0.0.1:9", "RP_SATELLITE_TOKEN": "tok"})
        cls.site, cls.other = _serve(_Site), _serve(_Quiet)
        cls.site.other_port = cls.other.server_address[1]
        cls.port = cls.site.server_address[1]
        cls.closed = _closed_port()
        lst = socket.socket()
        lst.bind(("127.0.0.1", 0))
        lst.listen(8)
        cls.listener = lst
        cls.open_port = lst.getsockname()[1]

    @classmethod
    def tearDownClass(cls):
        cls.listener.close()
        for s in (cls.site, cls.other):
            s.shutdown()
            s.server_close()

    RAW = [
        None, "x", [], {}, {"label": "", "type": "ping", "target": "10.0.0.1"}, {"label": "a", "type": "dns", "target": "x.org"},
        {"label": "a", "type": "ping", "target": "-c 1"}, {"label": "a", "type": "ping", "target": "has space"},
        {"label": "a", "type": "ping", "target": "10.0.0.1"}, {"label": "a", "type": "ping", "target": "[::1]"},
        {"label": "a", "type": "tcp", "target": "10.0.0.1"}, {"label": "a", "type": "tcp", "target": "10.0.0.1:0"},
        {"label": "a", "type": "tcp", "target": "10.0.0.1:65536"}, {"label": "a", "type": "tcp", "target": "10.0.0.1:x"},
        {"label": "a", "type": "tcp", "target": "db.lab:5432"}, {"label": "a", "type": "tcp", "target": "[::1]:80"},
        {"label": "a", "type": "http", "target": "ftp://10.0.0.1/"}, {"label": "a", "type": "http", "target": "http:///x"},
        {"label": "a", "type": "http", "target": "http://10.0.0.1/", "expect_status": 204},
        {"label": "a", "type": "http", "target": "http://10.0.0.1/", "expect_status": True},
        {"label": "a", "type": "http", "target": "http://10.0.0.1/", "expect_status": 99},
        {"label": "a", "type": "http", "target": "http://10.0.0.1/", "expect_status": 600},
        {"label": "a", "type": "http", "target": "http://10.0.0.1/", "expect_contains": "x" * 500, "method": "post"},
        {"label": "a", "type": "http", "target": "https://10.0.0.1/", "verify_tls": False, "method": "head"},
        {"label": "a", "type": "http", "target": "https://10.0.0.1/", "verify_tls": 0},
        {"label": "la\x00bel\n", "type": "http", "target": "http://10.0.0.1/\x07x"}, {"label": "L" * 400, "type": "ping", "target": "h" * 600},
    ]
    ADDRS = ["127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1", "169.254.169.254", "169.254.1.1", "fd00:ec2::254", "100.100.100.200",
             "192.0.0.192", "::1", "::ffff:169.254.169.254", "::ffff:10.0.0.1", "64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::1", "0.0.0.0",
             "224.0.0.1", "240.0.0.1", "255.255.255.255", "not-an-ip", "", "8.8.8.8", "fe80::1", "2001:db8::1"]

    def test_the_specs_a_server_may_send_are_read_the_same(self):
        for raw in self.RAW:
            with self.subTest(raw=str(raw)[:80]):
                self.assertEqual(self.sat._probe_spec(raw), self.agent._probe_spec(raw))
        self.assertTrue(any(self.sat._probe_spec(r) for r in self.RAW), "control: some of the specs are valid")
        self.assertTrue(any(self.sat._probe_spec(r) is None for r in self.RAW), "control: some are refused")

    def test_the_addresses_a_probe_never_reaches_are_the_same_list(self):
        blocked = 0
        for addr in self.ADDRS:
            with self.subTest(addr=addr):
                got = self.sat._probe_addr_blocked(addr)
                self.assertEqual(got, self.agent._probe_addr_blocked(addr))
                blocked += bool(got)
        self.assertTrue(0 < blocked < len(self.ADDRS), "control: some are blocked and some are not")
        self.assertTrue(self.sat._probe_addr_blocked("169.254.169.254") and not self.sat._probe_addr_blocked("127.0.0.1"))

    def specs(self):
        base = f"http://127.0.0.1:{self.port}"
        return [
            {"label": "open", "type": "tcp", "target": f"127.0.0.1:{self.open_port}"},
            {"label": "closed", "type": "tcp", "target": f"127.0.0.1:{self.closed}"},
            {"label": "ok", "type": "http", "target": base + "/ok"},
            {"label": "ok text", "type": "http", "target": base + "/ok", "expect_contains": "all fine"},
            {"label": "missing text", "type": "http", "target": base + "/ok", "expect_contains": "not on the page"},
            {"label": "404", "type": "http", "target": base + "/missing"},
            {"label": "404 wanted", "type": "http", "target": base + "/missing", "expect_status": 404},
            {"label": "500", "type": "http", "target": base + "/boom"},
            {"label": "redirect", "type": "http", "target": base + "/moved"},
            {"label": "405 to HEAD", "type": "http", "target": base + "/no-head"},
            {"label": "metadata", "type": "http", "target": "http://169.254.169.254/latest/meta-data/"},
            {"label": "metadata tcp", "type": "tcp", "target": "169.254.169.254:80"},
        ]

    def test_the_same_servers_get_the_same_verdicts(self):
        verdicts = {}
        for raw in self.specs():
            a_spec, s_spec = self.agent._probe_spec(raw), self.sat._probe_spec(raw)
            self.assertEqual(a_spec, s_spec, raw["label"])
            a, s = self.agent._probe_run_one(a_spec), self.sat._probe_run_one(s_spec)
            with self.subTest(label=raw["label"]):
                self.assertEqual((a["ok"], a["detail"]), (s["ok"], s["detail"]))
            verdicts[raw["label"]] = (s["ok"], s["detail"])
        want = {"open": True, "closed": False, "ok": True, "ok text": True, "missing text": False, "404": False, "404 wanted": True,
                "500": False, "redirect": True, "405 to HEAD": True, "metadata": False, "metadata tcp": False}
        self.assertEqual({k: v[0] for k, v in verdicts.items()}, want)
        self.assertIn("not allowed", verdicts["metadata"][1])
        self.assertIn("not allowed", verdicts["metadata tcp"][1])

    def test_a_result_is_what_the_servers_endpoint_reads(self):
        res = self.sat._probe_run_one(self.sat._probe_spec({"label": "open", "type": "tcp", "target": f"127.0.0.1:{self.open_port}"}))
        self.assertEqual(set(res), {"label", "type", "target", "ok", "detail", "latency_ms"})
        self.assertIs(res["ok"], True)
        self.assertIsNotNone(api.clean_latency(res["latency_ms"]))

    def test_ping_that_could_not_run_is_not_an_unreachable_host(self):
        spec = self.sat._probe_spec({"label": "gw", "type": "ping", "target": "10.0.5.1"})
        for code, ok, word in ((0, True, "reachable"), (1, False, "unreachable"), (2, False, "could not run")):
            with self.subTest(code=code), mock.patch.object(self.sat.shutil, "which", lambda n: "/bin/ping"), \
                    mock.patch.object(self.sat.subprocess, "run", lambda *a, **k: mock.Mock(returncode=code, stdout="", stderr="")):
                res = self.sat._probe_run_one(spec)
                self.assertEqual((res["ok"], word in res["detail"]), (ok, True), res)
                if code == 2:
                    self.assertNotIn("unreachable", res["detail"])

    def test_a_ping_to_the_metadata_address_is_refused_without_running_ping(self):
        spec = self.sat._probe_spec({"label": "md", "type": "ping", "target": "169.254.169.254"})
        with mock.patch.object(self.sat.subprocess, "run", side_effect=AssertionError("ping was started")):
            res = self.sat._probe_run_one(spec)
        self.assertFalse(res["ok"])
        self.assertIn("not allowed", res["detail"])


# ── a whole round against a fake server ────────────────────────────────────────────────────────────────────────────────────
class _Upstream(_Quiet):
    def _json(self, code, obj):
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        srv: Any = self.server
        srv.seen.append(("GET", self.path, self.headers.get("X-RP-Satellite")))
        if self.path == "/api/satellite/monitor-work":
            self._json(200, srv.work)
        else:
            self._json(404, {"error": "no"})

    def do_POST(self):
        srv: Any = self.server
        n = int(self.headers.get("Content-Length") or 0)
        srv.seen.append(("POST", self.path, self.headers.get("X-RP-Satellite")))
        srv.posted.append(json.loads(self.rfile.read(n) or b"{}"))
        self._json(200, {"ok": True})


class TestARound(unittest.TestCase):

    def setUp(self):
        self.up: Any = _Server(("127.0.0.1", 0), _Upstream)
        self.up.seen, self.up.posted, self.up.work = [], [], {"monitors": [], "interval": 300}
        threading.Thread(target=self.up.serve_forever, daemon=True).start()
        self.addCleanup(lambda: (self.up.shutdown(), self.up.server_close()))
        self.site = _serve(_Site)
        self.addCleanup(lambda: (self.site.shutdown(), self.site.server_close()))
        self.sat = _load("sat_v750_round", ROOT / "client" / "remotepower-satellite.py",
                         {"RP_UPSTREAM": f"http://127.0.0.1:{self.up.server_address[1]}", "RP_SATELLITE_TOKEN": "sat-token-1"})

    def test_it_asks_with_its_token_runs_everything_and_reports_each_result(self):
        base = f"http://127.0.0.1:{self.site.server_address[1]}"
        self.up.work = {"satellite_id": "sat1", "interval": 90, "monitors": [
            {"label": "up", "type": "http", "target": base + "/ok", "expect_status": 200},
            {"label": "down", "type": "http", "target": base + "/boom"},
            {"label": "closed", "type": "tcp", "target": f"127.0.0.1:{_closed_port()}"},
            {"label": "metadata", "type": "http", "target": "http://169.254.169.254/"},
            {"label": "garbage", "type": "dns", "target": "x.org"},          # not a type it runs: not run, not reported
        ]}
        wait = self.sat._monitor_cycle()
        self.assertEqual(wait, 90)
        self.assertEqual([(m, p) for m, p, _ in self.up.seen], [("GET", "/api/satellite/monitor-work"), ("POST", "/api/satellite/monitor-results")])
        self.assertEqual({t for _, _, t in self.up.seen}, {"sat-token-1"}, "both calls carry the satellite's own token")
        results = {r["label"]: r for r in self.up.posted[0]["results"]}
        self.assertEqual({k: v["ok"] for k, v in results.items()}, {"up": True, "down": False, "closed": False, "metadata": False})
        self.assertIn("not allowed", results["metadata"]["detail"])

    def test_with_nothing_assigned_it_reports_nothing(self):
        self.up.work = {"monitors": [], "interval": 600}
        self.assertEqual(self.sat._monitor_cycle(), 600)
        self.assertEqual(self.up.posted, [])

    def test_a_hostile_answer_does_not_stop_it(self):
        for work, expect in (({"monitors": "nope", "interval": "soon"}, 300), ({"monitors": [None, 3, "x"], "interval": 5}, 60),
                             ({"monitors": [], "interval": 10 ** 9}, 3600), ({"monitors": [], "interval": None}, 300)):
            with self.subTest(work=work):
                self.up.work = work
                self.assertEqual(self.sat._monitor_cycle(), expect)

    def test_a_server_that_cannot_be_reached_raises_so_the_loop_can_back_off(self):
        self.up.shutdown()
        self.up.server_close()
        with self.assertRaises(Exception):
            self.sat._monitor_cycle()


class TestTheLoopIsStarted(unittest.TestCase):

    def run_main(self, env):
        sat = _load("sat_v750_main", ROOT / "client" / "remotepower-satellite.py",
                    dict({"RP_UPSTREAM": "http://127.0.0.1:9", "RP_SATELLITE_TOKEN": "tok", "RP_LISTEN": "127.0.0.1:0"}, **env))
        started = []

        class _Thread:
            def __init__(self, target=None, name=None, daemon=None, **k):
                self.target, self.daemon = target, daemon

            def start(self):
                started.append((self.target.__name__, self.daemon))

        fake_srv = mock.Mock()
        with mock.patch.object(sat, "ThreadingHTTPServer", lambda *a, **k: fake_srv), \
                mock.patch.object(sat.threading, "Thread", _Thread), mock.patch.object(sat.sys.stderr, "write"):
            self.assertEqual(sat.main(), 0)
        fake_srv.serve_forever.assert_called_once()
        return started

    def test_main_starts_the_poller_as_a_daemon(self):
        self.assertEqual(self.run_main({}), [("_monitor_loop", True)])

    def test_the_switch_turns_it_off(self):
        self.assertEqual(self.run_main({"RP_SATELLITE_PROBES": "0"}), [])


if __name__ == "__main__":
    unittest.main()

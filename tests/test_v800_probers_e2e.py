#!/usr/bin/env python3
"""8.0.0: a real satellite process against a real server, running the SMTP, SSH and NTP monitors it is assigned.

tests/test_v800_client_protocol_probes.py drives the clients' functions, and tests/test_v800_protocol_monitors.py the server's. This file runs the
whole path across two processes: a satellite (client/remotepower-satellite.py, started as a program) says what it runs in a header, the server
keeps it, takes a handshake monitor for the satellite or refuses it in words, hands the satellite the monitors it can run, and the results the
satellite probed come back and are shown as its own. The services it probes are fakes on the loopback (tests/test_v800_protocol_probes.py), so
nothing here is a real mail server or a real NTP pool.

A satellite from before this release is run too, from the commit before the change: it says nothing, so it is assigned the three types it has
always run and is refused the new ones. That half skips when the history is not there.

Self-skips without playwright, Chromium and gunicorn (the shared guard of the e2e files: the stack needs gunicorn), and runs under the default
storage backend only.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import urlparse
import http.client

sys.path.insert(0, str(Path(__file__).resolve().parent))
import browser_required  # noqa: E402
from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SATELLITE = ROOT / "client" / "remotepower-satellite.py"
_GATE = browser_available() or browser_required.required()
_STATE = {}
OLD_COMMIT = "0c03251a"          # the satellite as it was before it said what it runs


def setUpModule():
    if not _GATE:
        raise unittest.SkipTest(SKIP_REASON)
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("measured once, under the default backend")
    seeder = ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-probers-")
    proc = subprocess.run([sys.executable, str(seeder), "--data-dir", data_dir, "--apply"], capture_output=True, cwd=str(ROOT), timeout=900)
    if proc.returncode != 0:
        raise unittest.SkipTest("demo seeder failed: " + proc.stderr.decode(errors="replace")[-300:])
    try:
        from e2e_harness import start_stack
        base, shutdown = start_stack(data_dir=data_dir)
    except Exception as exc:
        raise unittest.SkipTest("app stack not available: %s" % exc)
    import test_v800_protocol_probes as pp
    pp.setUpModule()
    _STATE.update(base=base, shutdown=shutdown, data_dir=data_dir, pp=pp)


def tearDownModule():
    try:
        if _STATE.get("pp"):
            _STATE["pp"].tearDownModule()
    finally:
        if _STATE.get("shutdown"):
            _STATE["shutdown"]()


def http_call(method, path, body=None, token=None, headers=None):
    u = urlparse(_STATE["base"])
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=60)
    h = dict(headers or {})
    data = json.dumps(body).encode() if body is not None else None
    if data is not None:
        h.setdefault("Content-Type", "application/json")
    if token:
        h.setdefault("Authorization", "Bearer " + token)
    conn.request(method, path, body=data, headers=h)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    try:
        parsed = json.loads(raw) if raw.strip() else None
    except ValueError:
        parsed = raw
    return resp.status, parsed


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestARealSatelliteAgainstARealServer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        status, body = http_call("POST", "/api/login", {"username": "alice", "password": "demo"})
        assert status == 200 and isinstance(body, dict), body
        cls.token = body["token"]
        status, body = http_call("POST", "/api/config", {"allow_internal_monitors": True, "monitor_interval": 60}, token=cls.token)
        assert status == 200, body
        cls.procs, cls.servers = [], []

    @classmethod
    def tearDownClass(cls):
        for p in cls.procs:
            if p.poll() is None:
                p.terminate()
        for p in cls.procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
        for s in cls.servers:
            s.stop()

    # ── helpers ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def register(self, name):
        status, body = http_call("POST", "/api/satellites", {"name": name}, token=self.token)
        self.assertEqual(status, 201, body)
        assert isinstance(body, dict)
        return body["id"], body["token"]

    def start(self, token, script=SATELLITE):
        """The satellite as a program. Its first round of monitors is five seconds after it starts."""
        proc = subprocess.Popen([sys.executable, str(script)], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                env=dict(os.environ, RP_UPSTREAM=_STATE["base"], RP_SATELLITE_TOKEN=token, RP_LISTEN="127.0.0.1:%d" % free_port(), RP_SATELLITE_PROBES="1"))
        self.procs.append(proc)
        return proc

    def stop(self, proc):
        proc.terminate()
        proc.wait(timeout=10)

    def read(self, name):
        path = Path(_STATE["data_dir"]) / name
        return json.loads(path.read_text()) if path.exists() else {}

    def wait_for(self, what, test, seconds=60):
        deadline = time.time() + seconds
        while time.time() < deadline:
            got = test()
            if got:
                return got
            time.sleep(0.5)
        self.fail("timed out waiting for " + what)

    def serve(self, handler):
        s = _STATE["pp"]._Tcp(handler)
        self.servers.append(s)
        return s

    def save_monitors(self, monitors):
        return http_call("POST", "/api/config", {"monitors": monitors}, token=self.token)

    def result(self, label, sid):
        r = self.read("satellite_monitors.json").get(label) or {}
        return r if r.get("by") == "satellite:" + sid else None

    # ── the tests ───────────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_a_satellite_says_what_it_runs_is_assigned_the_handshakes_and_its_results_come_back(self):
        pp = _STATE["pp"]
        sid, token = self.register("e2e satellite")
        first = self.start(token)
        self.wait_for("the satellite to connect", lambda: self.read("satellites.json").get(sid, {}).get("last_seen"))
        self.assertEqual(self.read("satellites.json")[sid].get("probe_types"), ["tcp", "http", "ping", "smtp", "imap", "ssh", "ntp"],
                         "what a real process said in its header was kept")
        self.stop(first)
        smtp = self.serve(pp.smtp())
        ssh = self.serve(pp.banner(b"SSH-2.0-OpenSSH_9.6\r\n"))
        ntp = pp._Ntp(skew=0.0, stratum=2, wait=120)      # the satellite asks five seconds after it starts, and the fake answers once
        self.addCleanup(ntp.stop)
        status, body = self.save_monitors([
            {"label": "mail relay", "type": "smtp", "target": "127.0.0.1:%d" % smtp.port, "via_satellite": sid},
            {"label": "jump box", "type": "ssh", "target": "127.0.0.1:%d" % ssh.port, "via_satellite": sid},
            {"label": "clock", "type": "ntp", "target": "127.0.0.1:%d" % ntp.port, "max_offset_ms": 5000, "via_satellite": sid}])
        self.assertEqual(status, 200, "the server takes them for a satellite that said it runs them: %r" % (body,))
        self.start(token)                    # a new process asks at once, where the first would wait out the monitor interval
        for label in ("mail relay", "jump box", "clock"):
            self.wait_for("the result of " + label, lambda label=label: self.result(label, sid))
        mail, jump, clock = (self.result(label, sid) for label in ("mail relay", "jump box", "clock"))
        self.assertEqual((mail["ok"], mail["type"], mail["by"]), (True, "smtp", "satellite:" + sid), mail)
        self.assertIn("mail.test ESMTP ready", mail["detail"])
        self.assertEqual((jump["ok"], jump["type"]), (True, "ssh"), jump)
        self.assertIn("SSH-2.0-OpenSSH_9.6", jump["detail"])
        self.assertEqual((clock["ok"], clock["type"]), (True, "ntp"), clock)
        self.assertIn("stratum 2", clock["detail"])

    def test_a_satellite_that_has_not_connected_has_said_nothing_and_is_refused_the_new_types_in_words(self):
        sid, _token = self.register("silent satellite")
        status, body = self.save_monitors([{"label": "mail relay", "type": "smtp", "target": "mail.example.org:25", "via_satellite": sid}])
        self.assertEqual(status, 400, body)
        self.assertIn("does not say it runs smtp monitors", json.dumps(body))
        status, body = self.save_monitors([{"label": "web", "type": "tcp", "target": "127.0.0.1:%d" % free_port(), "via_satellite": sid}])
        self.assertEqual(status, 200, "the three it has always run need no word: %r" % (body,))

    def test_a_satellite_from_before_says_nothing_still_works_with_the_new_server_and_is_refused_the_new_types(self):
        try:
            old = subprocess.run(["git", "show", "%s:client/remotepower-satellite.py" % OLD_COMMIT], cwd=str(ROOT), capture_output=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            old = None
        if old is None or old.returncode != 0 or b"def _probe_run_one" not in old.stdout:
            self.skipTest("the history of %s is not here" % OLD_COMMIT)
        script = Path(tempfile.mkdtemp(prefix="rp-old-satellite-")) / "remotepower-satellite-old.py"
        script.write_bytes(old.stdout)
        sid, token = self.register("old satellite")
        first = self.start(token, script)
        self.wait_for("the old satellite to connect", lambda: self.read("satellites.json").get(sid, {}).get("last_seen"))
        self.assertNotIn("probe_types", self.read("satellites.json")[sid], "it sends no header, so nothing is recorded")
        self.stop(first)
        status, body = self.save_monitors([{"label": "old mail", "type": "smtp", "target": "mail.example.org:25", "via_satellite": sid}])
        self.assertEqual(status, 400, body)
        self.assertIn("does not say it runs smtp monitors", json.dumps(body))
        web = self.serve(_STATE["pp"].banner(b"hello\r\n"))
        status, body = self.save_monitors([{"label": "old tcp", "type": "tcp", "target": "127.0.0.1:%d" % web.port, "via_satellite": sid}])
        self.assertEqual(status, 200, body)
        self.start(token, script)
        got = self.wait_for("the old satellite's result", lambda: self.result("old tcp", sid))
        self.assertEqual((got["ok"], got["type"]), (True, "tcp"), "the new server's spec, with the new keys in it, is read by the old satellite")


if __name__ == "__main__":
    unittest.main()

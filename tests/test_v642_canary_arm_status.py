"""v6.4.2 — canary files report whether they were actually PLANTED.

Canary/honeytoken paths are configured as a fleet-wide textarea. Each agent
planted a decoy at each path, skipping any path that already had a file (it
baselined the REAL file instead) and swallowing every OSError into `log.debug`.
Nothing about plant outcome ever rode the heartbeat — only `canary_events` (trip
reports) — so the server had no canary status store, no per-device armed list,
no fleet count. The sole operator feedback was a toast fired at SAVE time,
before any agent had even received the config.

So an operator who armed `/root/.aws/credentials` across the fleet saw
"3 canary file(s) armed" and, on every host with a read-only /root or a real
credentials file already in place, had either no honeytoken at all or a
change-watch on genuine data — with no screen anywhere that would tell them.
That is worse than a missing feature: it is a security control the operator now
stops worrying about.

The agent half is driven against a real filesystem (a real decoy, a real
pre-existing file, a real permission error) rather than mocked, because the
whole bug was an assumption about what the filesystem does.
"""

import ast
import importlib.util
import json
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-canary642-"))

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
_CLIENT = ROOT / "client"
sys.path.insert(0, str(_CGI))

_SPEC = importlib.util.spec_from_file_location("api", str(_CGI / "api.py"))
api = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("api", api)
_SPEC.loader.exec_module(api)

import checks   # noqa: E402

_AGENTS = ("remotepower-agent.py", "remotepower-agent-win.py",
           "remotepower-agent-mac.py")


def _load_canary_ns(agent_file):
    """Execute JUST the canary functions out of an agent, with a stub namespace.

    The agents import psutil/pywin32/etc at module scope, so importing one here
    is not an option — but a source-TEXT assertion would prove only that a line
    exists. Lifting the real function bodies out by AST keeps the behaviour
    under test while skipping the imports.
    """
    src = (_CLIENT / agent_file).read_text()
    tree = ast.parse(src)
    ns = {
        "os": os, "time": time,
        "host_path": lambda p: p,
        "log": type("L", (), {"debug": staticmethod(lambda *a, **k: None)})(),
        "_canary_planted": {}, "_canary_failed": {}, "_canary_reported": set(),
        "_canary_path_ok": lambda p: str(p).startswith(("/", "C:\\", "c:\\")),
    }
    wanted = {"_plant_canaries", "_canary_status", "_check_canaries"}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in wanted:
            exec(compile(ast.Module([node], []), "<agent>", "exec"), ns)
        elif (isinstance(node, ast.Assign)
              and getattr(node.targets[0], "id", "") == "_CANARY_DEFAULT"):
            exec(compile(ast.Module([node], []), "<agent>", "exec"), ns)
    return ns


class TestAgentReportsPlantOutcome(unittest.TestCase):
    """Driven against a real filesystem, on the Linux agent."""

    def setUp(self):
        self.ns = _load_canary_ns("remotepower-agent.py")
        self.work = tempfile.mkdtemp(prefix="rp-canary-fs-")
        self.decoy = os.path.join(self.work, "decoy.txt")
        self.real = os.path.join(self.work, "real.txt")
        with open(self.real, "w") as f:
            f.write("genuine data")
        self.ro_dir = os.path.join(self.work, "ro")
        os.makedirs(self.ro_dir)
        os.chmod(self.ro_dir, stat.S_IRUSR | stat.S_IXUSR)
        self.blocked = os.path.join(self.ro_dir, "nope.txt")

    def tearDown(self):
        os.chmod(self.ro_dir, 0o700)

    def _run(self, paths):
        cfg = [{"path": p} for p in paths]
        self.ns["_plant_canaries"](cfg)
        return {r["path"]: r for r in self.ns["_canary_status"](cfg)}

    def test_a_planted_decoy_reports_armed(self):
        st = self._run([self.decoy])
        self.assertEqual(st[self.decoy]["state"], "armed")
        self.assertTrue(os.path.exists(self.decoy), "no decoy was written")

    def test_a_blocked_plant_reports_failed_with_the_reason(self):
        """This used to be `log.debug` and nothing else. On a host with a
        read-only /root the honeytoken never existed and the operator's only
        feedback said it did."""
        if os.geteuid() == 0:
            self.skipTest("root ignores the directory mode")
        st = self._run([self.blocked])
        self.assertEqual(st[self.blocked]["state"], "failed")
        self.assertTrue(st[self.blocked]["detail"],
                        "'failed' with no reason is barely better than silence")

    def test_a_preexisting_real_file_reports_watching_not_armed(self):
        """The subtler half. The agent baselines a real file and leaves it
        alone — correct behaviour, never clobber user data — but that makes the
        path a change-watch on genuine data, NOT a honeytoken. It reported as
        success."""
        st = self._run([self.real])
        self.assertEqual(st[self.real]["state"], "watching")
        self.assertNotEqual(st[self.real]["state"], "armed")
        with open(self.real) as f:
            self.assertEqual(f.read(), "genuine data",
                             "the agent clobbered a real file")

    def test_a_relative_path_reports_failed_not_silence(self):
        st = self._run(["relative/path"])
        self.assertEqual(st["relative/path"]["state"], "failed")

    def test_every_configured_path_appears_exactly_once(self):
        """A path missing from the report is indistinguishable from a healthy
        one on the UI side, which is the failure mode being fixed."""
        paths = [self.decoy, self.real, "relative/path"]
        st = self._run(paths)
        self.assertEqual(sorted(st), sorted(paths))

    def test_a_recovered_path_stops_reporting_failed(self):
        """The failure dict must not be write-only, or a fixed permission
        problem shows as broken forever."""
        if os.geteuid() == 0:
            self.skipTest("root ignores the directory mode")
        st = self._run([self.blocked])
        self.assertEqual(st[self.blocked]["state"], "failed")
        os.chmod(self.ro_dir, 0o700)
        st = self._run([self.blocked])
        self.assertEqual(st[self.blocked]["state"], "armed")


class TestAllThreeAgentsAgree(unittest.TestCase):
    """Cross-agent parity: a signal one agent sends and the others don't is the
    recurring class here (`poll_interval` was win/mac-only, `force_secrets_scan`
    was linux/mac-only)."""

    def test_every_agent_has_the_status_reporter(self):
        for a in _AGENTS:
            with self.subTest(agent=a):
                self.assertIn("def _canary_status(", (_CLIENT / a).read_text(),
                              f"{a} cannot report arm status")

    def test_every_agent_records_failures(self):
        for a in _AGENTS:
            with self.subTest(agent=a):
                self.assertIn("_canary_failed", (_CLIENT / a).read_text())

    def test_every_agent_sends_it_under_sysinfo(self):
        for a in _AGENTS:
            with self.subTest(agent=a):
                src = (_CLIENT / a).read_text()
                self.assertIn("canary_status", src)
                self.assertRegex(
                    src, r"sysinfo\W{0,3}\[.canary_status.\]",
                    f"{a} computes the status and never puts it on the wire")

    def test_the_same_four_states(self):
        for a in _AGENTS:
            with self.subTest(agent=a):
                ns = _load_canary_ns(a)
                src = (_CLIENT / a).read_text()
                for s in ("armed", "watching", "failed", "pending"):
                    self.assertIn(f"'{s}'", src, f"{a} lost the {s} state")

    def test_extensionless_agent_matches(self):
        ext = _CLIENT / "remotepower-agent"
        if not ext.exists():
            self.skipTest("extensionless copy excluded from this tree")
        self.assertEqual(ext.read_bytes(),
                         (_CLIENT / "remotepower-agent.py").read_bytes(),
                         "run: cp client/remotepower-agent.py "
                         "client/remotepower-agent")


class TestServerPersistsIt(unittest.TestCase):
    """`safe_si` is a WHITELIST — a field the agent sends but it drops silently
    never reaches the check or the UI. That is the class this whole finding is."""

    def setUp(self):
        self.now = int(time.time())
        api.save(api.DEVICES_FILE,
                 {"h1": {"name": "web-01", "token": "tok", "last_seen": self.now}})
        self._saved = {n: getattr(api, n) for n in
                       ("get_json_body", "method", "_env",
                        "get_token_from_request")}
        api.method = lambda: "POST"
        api._env = lambda k, d="": d
        api.get_token_from_request = lambda: "tok"

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(api, n, v)

    def _beat(self, canary_status):
        api.get_json_body = lambda: {
            "device_id": "h1", "token": "tok",
            "sysinfo": {"canary_status": canary_status, "platform": "linux"}}
        try:
            api.handle_heartbeat()
        except (SystemExit, api.HTTPError):
            pass
        dev = (api.load(api.DEVICES_FILE) or {}).get("h1") or {}
        return (dev.get("sysinfo") or {}).get("canary_status")

    def test_it_survives_the_sanitizer(self):
        got = self._beat([{"path": "/root/decoy", "state": "armed", "detail": ""}])
        self.assertTrue(got, "safe_si dropped canary_status — the signal is "
                             "collected and never stored")
        self.assertEqual(got[0]["state"], "armed")

    def test_an_unknown_state_is_clamped(self):
        """`state` reaches the UI. The agent is authenticated but it is still
        the far side of the wire."""
        got = self._beat([{"path": "/x", "state": "<script>alert(1)</script>",
                           "detail": "d"}])
        self.assertEqual(got[0]["state"], "pending",
                         "an arbitrary string reached the client as a state")

    def test_the_detail_is_sanitised_and_bounded(self):
        got = self._beat([{"path": "/x" * 400, "state": "failed",
                           "detail": "y" * 400}])
        self.assertLessEqual(len(got[0]["path"]), 256)
        self.assertLessEqual(len(got[0]["detail"]), 120)


class TestChecksRow(unittest.TestCase):
    def _row(self, status_list):
        rows = checks._host_checks(
            "h1", {"name": "web-01", "last_seen": int(time.time()),
                   "sysinfo": {"canary_status": status_list} if status_list
                              is not None else {}},
            now=int(time.time()))
        return next((r for r in rows if r["key"] == "canary_files"), None)

    F = {"path": "/ro/x", "state": "failed", "detail": "Permission denied"}
    W = {"path": "/home/x/.aws/credentials", "state": "watching",
         "detail": "a real file was already at this path"}
    A = {"path": "/root/decoy", "state": "armed", "detail": ""}
    P = {"path": "/p", "state": "pending", "detail": ""}

    def test_a_failed_plant_is_critical_and_says_why(self):
        r = self._row([self.F, self.W, self.A])
        self.assertEqual(r["status"], "critical")
        self.assertIn("Permission denied", r["output"])

    def test_watching_a_real_file_is_a_warning(self):
        r = self._row([self.W, self.A])
        self.assertEqual(r["status"], "warning")
        self.assertIn("NOT a honeytoken", r["output"],
                      "the row has to say what is actually wrong, or it reads "
                      "as noise and gets disabled")

    def test_all_armed_is_ok(self):
        self.assertEqual(self._row([self.A])["status"], "ok")

    def test_nothing_planted_yet_is_unknown_not_ok(self):
        """Zero armed decoys is not working coverage. Reporting `ok` here would
        be the same lie the whole finding is about."""
        self.assertEqual(self._row([self.P])["status"], "unknown")

    def test_no_row_where_canaries_are_not_configured(self):
        self.assertIsNone(self._row(None))
        self.assertIsNone(self._row([]))


class TestClientHalf(unittest.TestCase):
    def setUp(self):
        self.js = (ROOT / "server" / "html" / "static" / "js"
                   / "app.js").read_text()

    def test_the_drawer_shows_arm_status(self):
        self.assertIn("si.canary_status", self.js,
                      "the field is persisted and rendered nowhere")

    def test_failures_sort_first(self):
        """A failed plant buried under a wall of healthy 'armed' lines is the
        same invisibility in a new place."""
        self.assertIn("_CANARY_RANK", self.js)
        i = self.js.index("_CANARY_RANK = {")
        block = self.js[i:i + 120]
        self.assertLess(block.index("failed"), block.index("armed"))

    def test_the_save_toast_no_longer_claims_armed(self):
        """It said 'N canary file(s) armed' at SAVE time, before any agent had
        received the config — the single most misleading string in the feature."""
        import re as _re
        body = self.js[self.js.index("async function saveCanaryFiles"):]
        body = body[:body.index("\n}\n")]
        # The comment above the fix quotes the old string on purpose — assert
        # against the CODE, or this passes/fails on prose.
        code = _re.sub(r"^\s*//.*$", "", body, flags=_re.M)
        self.assertNotIn("canary file(s) armed", code)
        self.assertIn("saved", code)


if __name__ == "__main__":
    unittest.main()

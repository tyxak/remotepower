#!/usr/bin/env python3
"""8.0.0: an unhealthy container's alert can carry the container's own last log lines. Off until an administrator turns it on.

The failing health check says why the CHECK failed, and the alert has carried that since 7.4.9. The container's own log often says why the
PROGRAM did. A log is also where passwords and tokens end up, and the lines would land in the alert ledger, the e-mail and the webhook, so
the setting is 0 by default and every layer enforces it on its own:

* the agent runs `docker logs` only when the heartbeat answer told it a number (1 to 10), only for an unhealthy container and within the
  per-report budget the health check already has, and cuts what it reads;
* the server's normaliser keeps a list of short single lines and nothing else;
* the alert takes the lines only when the SERVER's setting is above 0 (an agent that sends them anyway is ignored), masks credentials, caps the
  length and the total, and keeps the newest;
* the heartbeat answer carries the number to Linux agents, 0 included (so turning it off reaches an agent that was told a number), and to no
  other agent;
* the setting is a whole number from 0 to 10 and nothing else is stored.
"""
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v741_drift_globs import load_agent  # noqa: E402
from test_v742_container_recovery import DEV, _Base, _Captured, _Stdin, api, ctr  # noqa: E402
from test_v749_container_health import _Run  # noqa: E402
import test_v700_documented_config_keys as cfgkeys  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
AGENT = ROOT / "client" / "remotepower-agent.py"
containers_mod = api.containers_mod


class _RunLogs(_Run):
    """The docker double, with the output of `docker logs <id>`."""

    def __init__(self, ps_lines=(), inspect_by_id=None, logs=None):
        super().__init__(list(ps_lines), inspect_by_id or {})
        self.logs, self.log_calls = logs or {}, []

    def __call__(self, argv, **kw):
        if "logs" in argv:
            self.calls.append(list(argv))
            self.log_calls.append((list(argv), kw))
            return mock.Mock(returncode=0, stdout=self.logs.get(argv[-1], ""), stderr="")
        return super().__call__(argv, **kw)


def unhealthy_ps(n):
    return [{"ID": "id%d" % i, "Names": "web%d" % i, "Image": "acme/app:1", "Status": "Up 3 hours (unhealthy)"} for i in range(n)]


class TestTheAgent(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.agent = load_agent("rp_agent_loglines", AGENT)

    def tearDown(self):
        self.agent._set_container_log_lines(0)

    def tail(self, text, n=5, rc=0):
        run = _RunLogs(logs={"c1": text})
        run_ret = mock.Mock(returncode=rc, stdout=text, stderr="")
        with mock.patch.object(self.agent.subprocess, "run", return_value=run_ret) as m:
            out = self.agent._docker_log_tail("/usr/bin/docker", "c1", n)
        return out, m, run

    def test_the_setting_is_a_whole_number_from_one_to_ten_and_anything_else_is_none(self):
        for v, want in ((0, 0), (1, 1), (5, 5), (10, 10), (11, 0), (-1, 0), (True, 0), (False, 0), ("5", 0), (5.0, 0), (None, 0), ([], 0), ({}, 0),
                        (10 ** 30, 0)):
            with self.subTest(v=repr(v)):
                self.agent._set_container_log_lines(v)
                self.assertEqual(self.agent._CONTAINER_LOG_LINES, want)

    def test_the_last_lines_newest_last_with_the_error_stream_merged(self):
        out, m, _ = self.tail("one\ntwo\nthree\nfour\n", n=3)
        self.assertEqual(out, ["two", "three", "four"])
        argv = m.call_args[0][0]
        self.assertEqual(argv[:2], ["/usr/bin/docker", "logs"])
        self.assertIn("--tail", argv)
        self.assertEqual(argv[argv.index("--tail") + 1], "3")
        self.assertIs(m.call_args[1]["stderr"], subprocess.STDOUT, "a container writes errors to stderr: both are the log")
        self.assertTrue(m.call_args[1]["timeout"] > 0, "a stuck runtime must not hang the agent")

    def test_colour_codes_control_characters_and_blank_lines_are_gone(self):
        out, _, _ = self.tail("\x1b[31mERROR\x1b[0m boom\n\n   \nwith\ttab\x00nul\r\n")
        self.assertEqual(out, ["ERROR boom", "with tab nul"])
        for s in out:
            self.assertNotRegex(s, r"[\x00-\x1f\x7f]")

    def test_a_long_line_is_cut(self):
        out, _, _ = self.tail("x" * 5000 + "\n")
        self.assertEqual(len(out[0]), self.agent._LOG_LINE_CAP)

    def test_the_newest_lines_win_the_total(self):
        text = "\n".join("%02d" % i + "y" * 198 for i in range(10)) + "\n"      # ten lines of 200 characters
        out, _, _ = self.tail(text, n=10)
        self.assertEqual(sum(len(s) for s in out), self.agent._LOG_TOTAL_CAP)
        self.assertTrue(out[-1].startswith("09"))
        self.agent._LOG_TOTAL_CAP, saved = 450, self.agent._LOG_TOTAL_CAP
        try:
            out, _, _ = self.tail(text, n=10)
        finally:
            self.agent._LOG_TOTAL_CAP = saved
        self.assertEqual([s[:2] for s in out], ["08", "09"], "when they do not all fit it is the old ones that go")

    def test_nothing_is_run_without_a_container_or_a_number(self):
        for cid, n in (("", 5), (None, 5), ("c1", 0), ("c1", -3), ("c1", True), ("c1", None), ("c1", "5")):
            with self.subTest(cid=cid, n=n):
                with mock.patch.object(self.agent.subprocess, "run") as m:
                    self.assertEqual(self.agent._docker_log_tail("/usr/bin/docker", cid, n), [])
                m.assert_not_called()

    def test_it_never_asks_for_more_than_ten(self):
        _, m, _ = self.tail("a\n", n=500)
        self.assertEqual(m.call_args[0][0][m.call_args[0][0].index("--tail") + 1], "10")

    def test_a_runtime_that_fails_or_cannot_be_run_is_no_lines(self):
        self.assertEqual(self.tail("some text", rc=1)[0], [])
        for exc in (OSError("no docker"), subprocess.TimeoutExpired("docker", 5), RuntimeError("x")):
            with mock.patch.object(self.agent.subprocess, "run", side_effect=exc):
                self.assertEqual(self.agent._docker_log_tail("/usr/bin/docker", "c1", 3), [])

    def listing(self, ps, logs):
        inspect = {r["ID"]: {"field": ".State.Health", "value": {"Status": "unhealthy", "FailingStreak": 3,
                                                                    "Log": [{"ExitCode": 1, "Output": "boom"}]}} for r in ps}
        run = _RunLogs(ps, inspect, logs)
        with mock.patch.object(self.agent.subprocess, "run", run), \
                mock.patch.object(self.agent, "_docker_stats", return_value={}), \
                mock.patch.object(self.agent, "_image_digests", return_value={}):
            items = self.agent._docker_listing("/usr/bin/docker", "docker")
        return {i["name"]: i for i in items}, run

    def test_with_the_setting_off_docker_logs_is_never_run_and_no_key_is_sent(self):
        ps = unhealthy_ps(3)
        by, run = self.listing(ps, {"id0": "a\nb\n"})
        self.assertEqual(run.log_calls, [])
        for item in by.values():
            self.assertNotIn("health_log", item)

    def test_with_a_number_only_unhealthy_containers_are_read_and_only_so_many(self):
        self.agent._set_container_log_lines(2)
        ps = unhealthy_ps(self.agent._HEALTH_DETAIL_MAX + 3)
        ps.append({"ID": "ok", "Names": "db", "Image": "acme/db:1", "Status": "Up 3 hours (healthy)"})
        ps.append({"ID": "none", "Names": "cache", "Image": "acme/cache:1", "Status": "Up 3 hours"})
        logs = {p["ID"]: "first %s\nsecond %s\nthird %s\n" % (p["ID"], p["ID"], p["ID"]) for p in ps}
        by, run = self.listing(ps, logs)
        asked = [c[0][-1] for c in run.log_calls]
        self.assertEqual(len(asked), self.agent._HEALTH_DETAIL_MAX)
        self.assertNotIn("ok", asked)
        self.assertNotIn("none", asked)
        self.assertEqual(by["web0"]["health_log"], ["second id0", "third id0"])
        self.assertNotIn("health_log", by["db"])
        self.assertNotIn("health_log", by["cache"])
        self.assertNotIn("health_log", by["web%d" % (self.agent._HEALTH_DETAIL_MAX + 2)], "past the budget: not asked, so no key")

    def test_a_container_with_an_empty_log_sends_no_key(self):
        self.agent._set_container_log_lines(3)
        by, _ = self.listing(unhealthy_ps(1), {"id0": "\n\n"})
        self.assertNotIn("health_log", by["web0"])


class TestTheNormaliser(unittest.TestCase):

    def norm(self, value):
        return containers_mod.normalize_container(ctr("web", health_log=value))["health_log"]

    def test_a_list_of_short_clean_lines_is_kept(self):
        self.assertEqual(self.norm(["a", " b ", "c\td"]), ["a", "b", "c d"])

    def test_only_the_last_ten_lines_and_each_cut_to_200(self):
        out = self.norm(["%d" % i for i in range(30)])
        self.assertEqual(out, ["%d" % i for i in range(20, 30)])
        self.assertEqual(len(self.norm(["x" * 900])[0]), containers_mod.MAX_HEALTH_LOG_LINE_LEN)

    def test_control_characters_become_spaces(self):
        out = self.norm(["a\x00b\x1b[31m\r\nc"])
        self.assertEqual(len(out), 1)
        self.assertNotRegex(out[0], r"[\x00-\x1f\x7f]")

    def test_anything_that_is_not_a_list_of_strings_is_no_lines(self):
        for bad in (None, "a line", 5, {"a": "b"}, True, float("nan"), [None, 5, {"a": 1}, [], True]):
            with self.subTest(bad=repr(bad)[:30]):
                self.assertEqual(self.norm(bad), [])

    def test_a_container_without_the_key_has_an_empty_list(self):
        self.assertEqual(containers_mod.normalize_container(ctr("web"))["health_log"], [])


class _Alert(_Base):
    """The real heartbeat, the real diff and the real alert ledger (see test_v749_container_health)."""

    def set_lines(self, n):
        cfg = api.load(api.CONFIG_FILE) or {}
        if n is None:
            cfg.pop("container_alert_log_lines", None)
        else:
            cfg["container_alert_log_lines"] = n
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()

    def unhealthy(self, lines, name="web"):
        return ctr(name, status="Up 3 hours (unhealthy)", health="unhealthy", health_output="curl: (7) refused", health_streak=3,
                   health_log=lines)

    def sent(self):
        return [p for e, p in self.events if e == "container_unhealthy"]

    def open_row(self):
        return [a for a in self.alerts("container_unhealthy") if not a.get("resolved_at")][0]


class TestTheAlert(_Alert):

    def test_with_the_setting_off_an_agents_lines_are_dropped(self):
        for off in (None, 0):
            with self.subTest(off=off):
                api.save(api.ALERTS_FILE, {"alerts": []})
                api.save(api.CONTAINERS_FILE, {})
                self.events.clear()
                self.set_lines(off)
                self.beat([self.unhealthy(["secret-ish line", "another"])])
                self.assertEqual(len(self.sent()), 1)
                self.assertNotIn("log", self.sent()[0])
                self.assertNotIn("log", self.open_row()["payload"])
                self.assertNotIn("Last", api._webhook_message("container_unhealthy", self.sent()[0]))

    def test_with_a_number_the_newest_lines_ride_with_the_alert(self):
        self.set_lines(2)
        self.beat([self.unhealthy(["one", "two", "three"])])
        self.assertEqual(self.sent()[0]["log"], ["two", "three"])
        self.assertNotIn("log", self.open_row()["payload"], "the Alerts list keeps what it always kept: the lines go out with the notification only")
        msg = api._webhook_message("container_unhealthy", self.sent()[0])
        self.assertIn("curl: (7) refused", msg)
        self.assertIn("Last 2 log lines:\ntwo\nthree", msg)

    def test_one_line_is_singular(self):
        self.set_lines(5)
        self.beat([self.unhealthy(["only"])])
        self.assertIn("Last 1 log line:\nonly", api._webhook_message("container_unhealthy", self.sent()[0]))

    def test_no_lines_from_the_agent_is_no_block_even_with_a_number(self):
        self.set_lines(5)
        self.beat([self.unhealthy([])])
        self.assertNotIn("log", self.sent()[0])
        self.assertNotIn("Last", api._webhook_message("container_unhealthy", self.sent()[0]))

    def test_passwords_and_tokens_are_masked(self):
        self.set_lines(6)
        self.beat([self.unhealthy([
            "connecting with password=hunter2 to db",
            "request failed token: abcDEF123456 retrying",
            "GET https://user:s3cretpass@registry.example/v2/ 401",
            "api_key=AKIA1234567890ABCDEF used",
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
            "plain harmless line",
        ])])
        shown = "\n".join(self.sent()[0]["log"])
        for leaked in ("hunter2", "abcDEF123456", "s3cretpass", "AKIA1234567890ABCDEF", "eyJhbGciOiJIUzI1NiJ9"):
            self.assertNotIn(leaked, shown)
        self.assertIn("[REDACTED]", shown)
        self.assertIn("plain harmless line", shown, "an ordinary line is left alone")
        self.assertNotIn("hunter2", json.dumps(self.open_row()))
        self.assertNotIn("REDACTED", json.dumps(self.open_row()), "and none of it is stored in the Alerts list")

    def test_the_total_is_capped_and_the_newest_lines_are_what_stays(self):
        self.set_lines(10)
        self.beat([self.unhealthy(["%02d" % i + "z" * 198 for i in range(10)])])
        out = self.sent()[0]["log"]
        self.assertLessEqual(sum(len(s) for s in out), api._ALERT_LOG_TOTAL_CAP)
        self.assertEqual(out[-1][:2], "09")
        self.assertLess(len(out), 10)

    def test_the_recovery_carries_no_lines(self):
        self.set_lines(3)
        self.beat([self.unhealthy(["a", "b"])])
        self.beat([ctr("web", status="Up 3 hours (healthy)", health="healthy")])
        healthy = [p for e, p in self.events if e == "container_healthy"]
        self.assertEqual(len(healthy), 1)
        self.assertNotIn("log", healthy[0])

    def test_the_fleet_event_log_does_not_keep_the_lines(self):
        self.set_lines(3)
        self.beat([self.unhealthy(["something private", "more"])])
        api._LOAD_CACHE.clear()
        stored = json.dumps(api.load(api.FLEET_EVENTS_FILE) if hasattr(api, "FLEET_EVENTS_FILE") else {})
        self.assertNotIn("something private", stored)


class TestTheSettingReachesLinuxAgentsOnly(_Alert):

    def answer(self, dev_patch=None):
        devs = api.load(api.DEVICES_FILE)
        devs[DEV].update(dev_patch or {})
        api.save(api.DEVICES_FILE, devs)
        raw = json.dumps({"device_id": DEV, "token": "tok", "containers": []}).encode()
        import os
        os.environ.update({"REQUEST_METHOD": "POST", "PATH_INFO": "/api/heartbeat", "QUERY_STRING": "", "CONTENT_LENGTH": str(len(raw))})
        for k in ("HTTP_X_TOKEN", "HTTP_X_RP_VAULT_KEY"):
            os.environ.pop(k, None)
        api.sys.stdin = _Stdin(raw)
        api._LOAD_CACHE.clear()
        try:
            api.handle_heartbeat()
        except _Captured as c:
            self.assertEqual(c.status, 200, c.body)
            return c.body
        self.fail("no answer")

    def test_a_linux_agent_is_told_the_number_zero_included(self):
        for n, want in ((None, 0), (0, 0), (4, 4), (10, 10)):
            with self.subTest(n=n):
                self.set_lines(n)
                self.assertEqual(self.answer({"os": "Ubuntu 24.04"}).get("container_log_lines"), want)

    def test_a_stored_value_that_is_not_a_number_from_one_to_ten_is_told_as_zero(self):
        for bad in (True, -1, 11, "5", 2.5, None, [], {}):
            with self.subTest(bad=repr(bad)):
                api.save(api.CONFIG_FILE, {"container_alert_log_lines": bad})
                api._LOAD_CACHE.clear()
                self.assertEqual(self.answer({"os": "Debian 12"}).get("container_log_lines"), 0)

    def test_no_other_agent_is_sent_it(self):
        self.set_lines(5)
        for dev in ({"os": "Windows 11 (Build 22631)"}, {"os": "macOS 14.5 (23F79)"}):
            with self.subTest(dev=dev):
                self.assertNotIn("container_log_lines", self.answer(dev))


class TestTheSetting(cfgkeys._Base):

    def test_a_whole_number_from_zero_to_ten_is_kept(self):
        for n in range(0, 11):
            st, cfg = self.save({"container_alert_log_lines": n})
            self.assertEqual((st, cfg.get("container_alert_log_lines")), (200, n))

    def test_nothing_else_is_stored(self):
        self.save({"container_alert_log_lines": 4})
        for bad in (True, False, -1, 11, 100, "3", 2.5, None, [], {}, 10 ** 30, float("nan")):
            with self.subTest(bad=repr(bad)):
                st, cfg = self.save({"container_alert_log_lines": bad})
                self.assertEqual(st, 400)
                self.assertEqual(cfg.get("container_alert_log_lines"), 4, "a refused save leaves what was there")

    def test_a_save_that_does_not_name_it_leaves_it_alone(self):
        self.save({"container_alert_log_lines": 7})
        st, cfg = self.save({"container_alert_excludes": ["pause"]})
        self.assertEqual((st, cfg.get("container_alert_log_lines")), (200, 7))

    def test_it_is_read_back(self):
        self.save({"container_alert_log_lines": 3})
        self.assertEqual(self.read().get("container_alert_log_lines"), 3)


class TestThePage(unittest.TestCase):

    HTML = (ROOT / "server" / "html" / "index.html").read_text()
    JS = (ROOT / "server" / "html" / "static" / "js" / "app-tuning.js").read_text()

    def test_the_card_is_in_the_containers_tab_and_starts_disabled_and_off(self):
        import re
        card = re.search(r'<div class="dash-card mt-16" data-pg-tab="containers" id="container-log-lines-card">(.*?)\n        </div>', self.HTML, re.S)
        self.assertTrue(card, "the card is missing from the Containers tab of Tuning")
        body = card.group(1)
        self.assertRegex(body, r'<input type="number" id="container-log-lines"[^>]*min="0"[^>]*max="10"[^>]*value="0"[^>]*disabled>')
        self.assertRegex(body, r'id="container-log-lines-save" data-action="saveContainerLogLines" disabled')

    def test_the_page_reads_and_writes_the_key_and_loads_with_the_page(self):
        self.assertIn("container_alert_log_lines: n", self.JS)
        self.assertIn("cfg.container_alert_log_lines", self.JS)
        import srcpin
        self.assertEqual(srcpin.js_function(self.JS, "loadTuning").count("loadContainerLogLines();"), 2, "both branches of the page loader read it")

    def test_the_agent_twin_is_identical(self):
        self.assertEqual((ROOT / "client" / "remotepower-agent").read_bytes(), AGENT.read_bytes())

    def test_the_guide_documents_the_key_and_the_heartbeat_key(self):
        doc = (ROOT / "docs" / "containers.md").read_text()
        for word in ("container_alert_log_lines", "container_log_lines", "Last 3 log lines", "off by default"):
            self.assertIn(word, doc)


if __name__ == "__main__":
    unittest.main()

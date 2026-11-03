#!/usr/bin/env python3
"""7.4.9: a container whose own health check keeps failing raises an alert, with what the check said.

The agent already read docker's "(unhealthy)" out of the status text and the container list showed a badge,
but nothing fired: a container that is up and not serving fails neither the stopped nor the restarting test.
The check's own output ("curl: (7) Failed to connect to localhost port 8080") is the first thing anyone asks
for, so the alert carries it.

Three layers, each driven for real: the agent's reading of `docker inspect`, the server's normaliser, and the
heartbeat through the real diff and the real alert ledger. A hand-built alert row would skip the one thing
under test: which container name the recovery matches.
"""
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v741_drift_globs import load_agent  # noqa: E402
from test_v742_container_recovery import DEV, _Base, api, ctr  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
AGENT = ROOT / "client" / "remotepower-agent.py"
containers_mod = api.containers_mod


class _Run:
    """A subprocess.run double answering by the docker sub-command."""

    def __init__(self, ps_lines, inspect_by_id, batched=""):
        self.ps_lines, self.inspect_by_id, self.batched, self.calls = ps_lines, inspect_by_id, batched, []

    def __call__(self, argv, **_kw):
        self.calls.append(list(argv))
        out = mock.Mock(returncode=0, stdout="", stderr="")
        if "ps" in argv:
            out.stdout = "\n".join(json.dumps(x) for x in self.ps_lines)
        elif "inspect" in argv and any("State.Health" in a or "State.Healthcheck" in a for a in argv):
            fmt = next(a for a in argv if "State.Health" in a)
            cid = argv[-1]
            rec = self.inspect_by_id.get(cid)
            field = ".State.Healthcheck" if ".State.Healthcheck" in fmt else ".State.Health"
            if rec is None or rec.get("field") != field:
                out.returncode = 1
                out.stderr = "template: map has no entry for key"
            else:
                out.stdout = json.dumps(rec["value"])
        elif "inspect" in argv:
            out.stdout = self.batched
        else:
            out.returncode = 1
        return out


def health(streak, *entries):
    return {"Status": "unhealthy", "FailingStreak": streak,
            "Log": [{"ExitCode": c, "Output": o} for c, o in entries]}


class TestTheAgentReading(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.agent = load_agent("rp_agent_health", AGENT)

    def detail(self, rec, field=".State.Health"):
        run = _Run([], {"c1": {"field": field, "value": rec}})
        with mock.patch.object(self.agent.subprocess, "run", run):
            return self.agent._docker_health_detail("/usr/bin/docker", "c1")

    def test_the_newest_failing_entry_is_the_answer(self):
        out, streak = self.detail(health(
            4, (1, "old failure"), (0, "OK"), (1, "curl: (7) Failed to connect to localhost port 8080"), (0, "fine")))
        self.assertEqual(out, "curl: (7) Failed to connect to localhost port 8080")
        self.assertEqual(streak, 4)

    def test_control_characters_and_runs_of_blanks_are_one_line(self):
        out, _ = self.detail(health(1, (1, "line one\n\x1b[31mline\ttwo\x00\r\n   three")))
        self.assertEqual(out, "line one [31mline two three".replace("[31m", "[31m"))
        self.assertNotRegex(out, r"[\x00-\x1f\x7f]")

    def test_a_long_output_is_cut(self):
        out, _ = self.detail(health(1, (1, "x" * 5000)))
        self.assertEqual(len(out), self.agent._HEALTH_OUTPUT_CAP)

    def test_older_podman_calls_the_record_healthcheck(self):
        out, streak = self.detail(health(2, (125, "no such file")), field=".State.Healthcheck")
        self.assertEqual((out, streak), ("no such file", 2))

    def test_nothing_to_read_is_empty_not_an_error(self):
        run = _Run([], {})
        with mock.patch.object(self.agent.subprocess, "run", run):
            self.assertEqual(self.agent._docker_health_detail("/usr/bin/docker", "c1"), ("", 0))
            self.assertEqual(self.agent._docker_health_detail("/usr/bin/docker", ""), ("", 0))

    def test_hostile_values_do_not_raise(self):
        for rec in (health(True, (1, "x")), health(-5, (1, "x")), health("9", (1, "x")),
                    {"FailingStreak": 1, "Log": "not a list"}, {"Log": [None, 3, {"ExitCode": "1"}]},
                    {"Log": [{"ExitCode": True, "Output": "bool is not an exit code"}]}):
            out, streak = self.detail(rec)
            self.assertIsInstance(out, str)
            self.assertIn(streak, (0, 1))
        self.assertEqual(self.detail(health(True, (1, "x")))[1], 0)
        self.assertEqual(self.detail(health(-5, (1, "x")))[1], 0)

    def test_only_an_unhealthy_container_is_asked_and_only_so_many(self):
        ps = [{"ID": f"id{i}", "Names": f"web{i}", "Image": "acme/app:1", "Status": "Up 3 hours (unhealthy)"}
              for i in range(self.agent._HEALTH_DETAIL_MAX + 3)]
        ps.append({"ID": "ok", "Names": "db", "Image": "acme/db:1", "Status": "Up 3 hours (healthy)"})
        ps.append({"ID": "none", "Names": "cache", "Image": "acme/cache:1", "Status": "Up 3 hours"})
        inspect = {r["ID"]: {"field": ".State.Health", "value": health(3, (1, "boom " + r["ID"]))} for r in ps}
        run = _Run(ps, inspect)
        with mock.patch.object(self.agent.subprocess, "run", run), \
                mock.patch.object(self.agent, "_docker_stats", return_value={}), \
                mock.patch.object(self.agent, "_image_digests", return_value={}):
            items = self.agent._docker_listing("/usr/bin/docker", "docker")
        asked = [c[-1] for c in run.calls if any("State.Health}}" in a for a in c)]
        self.assertEqual(len(asked), self.agent._HEALTH_DETAIL_MAX)
        self.assertNotIn("ok", asked)
        self.assertNotIn("none", asked)
        by = {i["name"]: i for i in items}
        self.assertEqual(by["web0"]["health_output"], "boom id0")
        self.assertEqual(by["web0"]["health_streak"], 3)
        self.assertEqual(by["db"]["health_output"], "")
        self.assertEqual(by["db"]["health"], "healthy")
        self.assertEqual(by[f"web{self.agent._HEALTH_DETAIL_MAX + 2}"]["health_output"], "")


class TestTheNormaliser(unittest.TestCase):

    def test_the_output_is_one_clean_capped_line(self):
        n = containers_mod.normalize_container(ctr("web", health="unhealthy", health_output="a\n\x00b\t\tc" + "z" * 999))
        self.assertTrue(n["health_output"].startswith("a b c"))
        self.assertLessEqual(len(n["health_output"]), containers_mod.MAX_HEALTH_OUTPUT_LEN)
        self.assertNotRegex(n["health_output"], r"[\x00-\x1f\x7f]")

    def test_hostile_types_become_empty_and_zero(self):
        for bad in (None, 5, [1], {"a": 1}, float("inf"), True):
            n = containers_mod.normalize_container(ctr("web", health_output=bad, health_streak=bad))
            self.assertIsInstance(n["health_output"], str)
            self.assertIsInstance(n["health_streak"], int)
        for bad in (-3, 10 ** 400, float("nan"), "x", None):
            n = containers_mod.normalize_container(ctr("web", health_streak=bad))
            self.assertTrue(0 <= n["health_streak"] <= 100000, bad)

    def test_a_container_without_the_fields_still_normalises(self):
        n = containers_mod.normalize_container(ctr("web"))
        self.assertEqual((n["health_output"], n["health_streak"]), ("", 0))

    def test_the_summary_counts_unhealthy_containers_that_run(self):
        items = [ctr("a", health="unhealthy"), ctr("b", health="healthy"), ctr("c", health="unhealthy"),
                 ctr("d", status="Exited (1) 3 minutes ago", health="unhealthy")]
        s = containers_mod.summarise([containers_mod.normalize_container(i) for i in items])
        self.assertEqual(s["unhealthy"], 2)


class TestTheAlert(_Base):

    def unhealthy(self, name="web", output="curl: (7) Failed to connect", streak=3, **kw):
        return ctr(name, status="Up 3 hours (unhealthy)", health="unhealthy", health_output=output,
                   health_streak=streak, **kw)

    def open_unhealthy(self):
        return [a for a in self.alerts("container_unhealthy") if not a.get("resolved_at")]

    def test_it_fires_once_with_what_the_check_said(self):
        self.beat([self.unhealthy()])
        self.beat([self.unhealthy()])
        self.beat([self.unhealthy(streak=9)])
        self.assertEqual(self.fired("container_unhealthy"), ["web"])
        rows = self.open_unhealthy()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["payload"]["output"], "curl: (7) Failed to connect")
        self.assertEqual(rows[0]["payload"]["container"], "web")
        self.assertEqual(rows[0].get("severity"), "high")
        sent = [p for e, p in self.events if e == "container_unhealthy"][0]
        self.assertEqual(sent["health_streak"], 3)

    def test_the_message_names_the_container_the_run_and_the_output(self):
        msg = api._webhook_message("container_unhealthy", {
            "name": "serverbox", "container": "web", "runtime": "docker", "health_streak": 3,
            "output": "curl: (7) Failed to connect"})
        self.assertIn('container "web"', msg)
        self.assertIn("3 failed checks in a row", msg)
        self.assertIn("curl: (7) Failed to connect", msg)
        one = api._webhook_message("container_unhealthy", {"name": "h", "container": "w", "health_streak": 1})
        self.assertIn("1 failed check in a row", one)

    def test_a_passing_check_closes_it_once(self):
        self.beat([self.unhealthy()])
        self.beat([ctr("web", status="Up 3 hours (healthy)", health="healthy")])
        self.beat([ctr("web", status="Up 3 hours (healthy)", health="healthy")])
        self.assertEqual(self.fired("container_healthy"), ["web"])
        self.assertEqual(self.open_unhealthy(), [])

    def test_a_restart_that_is_still_starting_keeps_it_open(self):
        self.beat([self.unhealthy()])
        self.beat([ctr("web", status="Up 10 seconds (health: starting)", health="starting")])
        self.assertEqual(self.fired("container_healthy"), [])
        self.assertEqual(len(self.open_unhealthy()), 1)
        self.beat([ctr("web", status="Up 1 minute (healthy)", health="healthy")])
        self.assertEqual(self.fired("container_healthy"), ["web"])
        self.assertEqual(self.open_unhealthy(), [])

    def test_a_container_that_stops_or_leaves_closes_it(self):
        for gone in ([], [ctr("web", status="Exited (1) 5 seconds ago")]):
            with self.subTest(gone=gone):
                api.save(api.ALERTS_FILE, {"alerts": []})
                api.save(api.CONTAINERS_FILE, {})
                self.events.clear()
                self.beat([self.unhealthy()])
                self.assertEqual(len(self.open_unhealthy()), 1)
                self.beat(gone)
                self.assertEqual(self.open_unhealthy(), [])
                self.assertEqual(self.fired("container_healthy"), ["web"])

    def test_each_container_closes_on_its_own(self):
        self.beat([self.unhealthy("web"), self.unhealthy("db", output="pg_isready: no response")])
        self.assertEqual(sorted(a["payload"]["container"] for a in self.open_unhealthy()), ["db", "web"])
        self.beat([ctr("web", status="Up (healthy)", health="healthy"), self.unhealthy("db", output="still bad")])
        self.assertEqual([a["payload"]["container"] for a in self.open_unhealthy()], ["db"])

    def test_it_fires_on_the_first_report_ever(self):
        # State based, not a diff of two reports: a host that reports for the first time while a container is
        # already unhealthy is told.
        api.save(api.CONTAINERS_FILE, {})
        self.beat([self.unhealthy()])
        self.assertEqual(self.fired("container_unhealthy"), ["web"])

    def test_an_excluded_container_is_left_alone(self):
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg["container_alert_excludes"] = ["web"]
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()
        self.beat([self.unhealthy()])
        self.assertEqual(self.fired("container_unhealthy"), [])
        # control: a container the list does not name is still told
        self.beat([self.unhealthy("db")])
        self.assertEqual(self.fired("container_unhealthy"), ["db"])

    def test_the_host_shows_in_needs_attention(self):
        self.beat([self.unhealthy("web"), self.unhealthy("db")])
        api._LOAD_CACHE.clear()
        rows = [i for i in api._compute_attention() if i.get("kind") == "container"]
        self.assertTrue(any("2 containers unhealthy" in i["summary"] for i in rows), rows)

    def test_the_registry_wires_the_pair(self):
        reg = api.EVENT_REGISTRY
        self.assertEqual(reg["container_unhealthy"]["severity"], "high")
        self.assertEqual(reg["container_healthy"]["resolves"], ("container_unhealthy",))
        self.assertNotIn("severity", reg["container_healthy"])
        self.assertEqual(api._ALERT_RECOVER["container_healthy"], "container_unhealthy")
        for ev in ("container_unhealthy", "container_healthy"):
            self.assertIn(ev, api.SUPPRESSIBLE_EVENTS)
            self.assertIn(ev, {e[0] for e in api.WEBHOOK_EVENTS})

    def test_the_state_survives_in_the_hosts_container_record(self):
        self.beat([self.unhealthy()])
        api._LOAD_CACHE.clear()
        rec = api._entity_read_one(api.CONTAINERS_FILE, DEV, {})
        self.assertEqual(rec.get("unhealthy_alerted"), ["web"])
        self.beat([ctr("web", status="Up (healthy)", health="healthy")])
        api._LOAD_CACHE.clear()
        rec = api._entity_read_one(api.CONTAINERS_FILE, DEV, {})
        self.assertNotIn("unhealthy_alerted", rec)


if __name__ == "__main__":
    unittest.main()

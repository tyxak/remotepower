#!/usr/bin/env python3
"""One host cannot flood the operator's channels and the shared history with software-policy events.

`_eval_software_policy` judges the list a host sends against the rules of the software policy (up to 500) and told one event for each
rule that became violated and one for each that was cleared. A host whose list flipped between "all 100 banned packages installed"
and "none" caused 100 events a push, each 3.3 seconds of work, 6,000 events in 60 pushes: a notification to the operator's channels
each, a row in the shared activity feed (a ring of 1,000, so another organisation's two events were gone after ten pushes) and in the
alert inbox (3,000 rows for the host, in a ledger of 5,000 that then drops the resolved history of every host).

What this holds, with the real ingest, the real policy evaluation and the real alert and activity stores (a process of its own):

* a host with a few rules is told as before: one event for each rule that became violated and one for each that was cleared, in the
  order of the policy;
* a push that changes more than five rules tells five of each kind one by one (in the order of the rule ids, so that the violated and
  the cleared ones are the same five) and one event that stands for the rest, which is one open alert for the host and which closes
  with the host's alerts when it is whole again;
* a host may cause 40 events an hour: past that, one event says the rest are held back, and nothing more is told until the hour has
  passed. A host that flips 60 times causes 41 events, not 6,000, and another organisation's history is still there;
* the rule as a function, with the activity feed it reads.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v802-pf-"))
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
_TMP = []


def tearDownModule():
    import shutil
    for d in _TMP:
        shutil.rmtree(d, ignore_errors=True)


_DRIVER = r"""
import json, sys, time
sys.path.insert(0, sys.argv[1])
sys.dont_write_bytecode = True
import wsgi
api = wsgi.api
now = int(time.time())


def put(attr, obj):
    api.save(getattr(api, attr), obj)
    api._invalidate_load_cache(getattr(api, attr))


def key(token, user, role, tenant):
    return {"name": token, "key_hash": api._apikey_hash(token), "user": user, "role": role, "active": True, "created": 1,
            "tenant_id": tenant}


put("CONFIG_FILE", {})
put("USERS_FILE", {"op": {"role": "admin", "tenant_id": "default", "created": 1}})
put("APIKEYS_FILE", {"k1": key("T-OP", "op", "admin", "default")})
put("DEVICES_FILE", {h: {"name": h.upper(), "hostname": h, "os": "Debian 12", "monitored": True, "last_seen": now, "token": "T-" + h,
                         "group": "g", "ip": "10.0.0.1"} for h in ("alpha-1", "alpha-2", "bravo-1")})


def call(method, path, body=None, token=None):
    c = wsgi.application.test_client()
    kw = {"headers": {"X-Token": token} if token else {}}
    if body is not None:
        kw["data"] = json.dumps(body)
        kw["content_type"] = "application/json"
    r = getattr(c, method.lower())(path, **kw)
    try:
        return r.status_code, json.loads(r.data.decode("utf-8", "replace"))
    except ValueError:
        return r.status_code, None


def push(host, names):
    pk = [{"name": n, "version": "1.0", "arch": "amd64"} for n in names] or [{"name": "coreutils", "version": "9.1", "arch": "amd64"}]
    st, _ = call("POST", "/api/packages", {"device_id": host, "token": "T-" + host, "pkg_manager": "apt", "packages": pk,
                                          "ecosystem_hint": {"ID": "debian", "VERSION_ID": "12", "ID_LIKE": "", "UBUNTU_CODENAME": "",
                                                             "DEBIAN_CODENAME": "", "VERSION_CODENAME": ""}})
    assert st == 200, st


events = []
real_fire = api.fire_webhook


def fire(event, payload, *a, **k):
    events.append([event, dict(payload)])
    return real_fire(event, payload, *a, **k)


api.fire_webhook = fire
BANNED = ["banned-pkg-%d" % i for i in range(100)]
st, r = call("POST", "/api/software-policy", {"rules": [{"type": "banned", "package": n, "note": "x"} for n in BANNED]}, "T-OP")
out = {"policy_saved": st}
# another organisation's history, made before: an alert raised and cleared, and its place in the activity feed
real_fire("cve_found", {"device_id": "bravo-1", "name": "BRAVO-1", "count": 3, "critical": 1, "high": 2, "sample": []})
real_fire("cve_cleared", {"device_id": "bravo-1", "name": "BRAVO-1"})


def feed_of(host):
    api._invalidate_load_cache(api.FLEET_EVENTS_FILE)
    return len([e for e in (api.load(api.FLEET_EVENTS_FILE) or {}).get("events", []) if (e.get("payload") or {}).get("device_id") == host])


def alerts_of(host, only_open=False):
    api._invalidate_load_cache(api.ALERTS_FILE)
    rows = [a for a in (api.load(api.ALERTS_FILE) or {}).get("alerts", []) if a.get("device_id") == host]
    return [a for a in rows if not a.get("resolved_at")] if only_open else rows


out["bravo_feed_before"] = feed_of("bravo-1")
out["bravo_alerts_before"] = len(alerts_of("bravo-1"))
del events[:]

# 1. a host with a few rules: three of them
push("alpha-2", BANNED[:3])
out["few_violated"] = [[e, p.get("rule")] for e, p in events]
del events[:]
push("alpha-2", [])
out["few_cleared"] = [[e, p.get("rule")] for e, p in events]
del events[:]
out["few_open_alerts_after"] = len(alerts_of("alpha-2", True))

# 2. a host that breaks all 100 rules, then none (two pushes) and the alerts it leaves
push("alpha-1", BANNED)
first = [[e, p.get("rule"), p.get("detail", "")[:60]] for e, p in events]
out["first_push"] = first
out["first_push_open_alerts"] = sorted(a["payload"].get("rule") for a in alerts_of("alpha-1", True))
del events[:]
push("alpha-1", [])
out["second_push"] = [[e, p.get("rule")] for e, p in events]
out["second_push_open_alerts"] = len(alerts_of("alpha-1", True))
out["second_push_closer_has_no_rule"] = [("rule" in p) for e, p in events if e == "policy_compliant"][-1:]
del events[:]

# 3. the flood: 58 more pushes of the same flip
per_push = []
for i in range(58):
    before = len(events)
    push("alpha-1", BANNED if i % 2 == 0 else [])
    per_push.append(len(events) - before)
out["flood_total_events"] = len(events)
out["flood_max_per_push"] = max(per_push)
out["held_notices"] = [e for e, p in events if p.get("rule") == "(held back)"]
# once the budget is met nothing more is told: the tail of the list is zeros
tail = per_push[-30:]
out["tail_of_pushes"] = tail
out["bravo_feed_after"] = feed_of("bravo-1")
out["bravo_alerts_after"] = len(alerts_of("bravo-1"))
out["alpha_alert_rows"] = len(alerts_of("alpha-1"))
out["recent_events_of_alpha"] = (api._policy_events_recent("alpha-1", int(time.time())) if hasattr(api, "_policy_events_recent") else None)


try:
    # 4. the rule as a function
    def log(entries):
        put("FLEET_EVENTS_FILE", {"events": entries})


    def told(prev, now_rules, recent=0):
        t = int(time.time())
        log([{"ts": t - 5, "event": "policy_compliant", "payload": {"device_id": "h1"}} for _ in range(recent)])
        viol = [{"rule_id": r, "type": "banned", "package": r.split(":")[-1], "detail": "banned package %s is installed" % r.split(":")[-1]}
                for r in now_rules]
        return [[e, p.get("rule")] for e, p in api._policy_events_to_tell("h1", "H1", set(prev), viol, t)]


    R = ["banned:p%02d" % i for i in range(30)]
    out["fn_few_new"] = told([], R[:3])
    out["fn_few_gone"] = told(R[:3], [])
    out["fn_five_new"] = told([], R[:5])
    out["fn_six_new"] = told([], R[:6])
    out["fn_many_gone_whole"] = told(R[:12], [])
    out["fn_many_gone_partial"] = told(R[:12], R[12:14])
    out["fn_new_order_is_by_id"] = told([], list(reversed(R[:9])))
    out["fn_budget_38"] = told([], R[:4], recent=38)
    out["fn_budget_40"] = told([], R[:4], recent=40)
    out["fn_budget_55"] = told([], R[:4], recent=55)
    out["fn_budget_room_for_all"] = told([], R[:4], recent=10)
    viol = [{"rule_id": r, "type": "banned", "package": "x", "detail": "d"} for r in R[:20]]
    log([])
    summary = [p for e, p in api._policy_events_to_tell("h1", "H1", set(), viol, int(time.time())) if p.get("rule") == "(more rules)"][0]
    out["fn_summary_detail"] = summary["detail"]
    out["fn_old_events_do_not_count"] = told([], R[:4], recent=0)
    t = int(time.time())
    log([{"ts": t - 7200, "event": "policy_compliant", "payload": {"device_id": "h1"}} for _ in range(60)])
    out["fn_an_hour_old_is_not_recent"] = api._policy_events_recent("h1", t)
    log(["junk", None, {"ts": "x"}] + [{"ts": t - 5, "event": "policy_compliant", "payload": {"device_id": "h2"}} for _ in range(60)]
    + ["junk", {"ts": None, "event": "policy_compliant", "payload": {"device_id": "h1"}}])
    out["fn_other_hosts_do_not_count"] = api._policy_events_recent("h1", t)
    log(["junk"] + [{"ts": t - 5, "event": "software_policy_violation", "payload": {"device_id": "h1"}} for _ in range(3)] + [{"ts": "x"}]
        + [{"ts": t - 5, "event": "policy_compliant", "payload": {"device_id": "h1"}}] + ["junk", None])
    out["fn_junk_between_events_does_not_end_the_count"] = api._policy_events_recent("h1", t)
except Exception as e:      # the code before 8.0.2 has no such functions: say that, and let the pushes answer
    out["missing_rule_as_a_function"] = repr(e)
print(json.dumps(out))
"""


_OUT = {}


def _driver_output():
    if _OUT:
        return _OUT
    try:
        import flask  # noqa: F401
    except ImportError:
        raise unittest.SkipTest("flask is not installed")
    d = Path(tempfile.mkdtemp(prefix="rp-v802-pf-run-"))
    _TMP.append(d)
    (d / "driver.py").write_text(_DRIVER, encoding="utf-8")
    data = d / "data"
    data.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith(("REQUEST_", "HTTP_", "PATH_INFO", "QUERY_", "CONTENT_"))}
    env["RP_DATA_DIR"] = str(data)
    proc = subprocess.run([sys.executable, str(d / "driver.py"), str(_CGI)], capture_output=True, text=True, env=env, timeout=900)
    if proc.returncode != 0:
        raise AssertionError("the driver failed:\n" + proc.stderr[-2500:])
    _OUT.update(json.loads(proc.stdout.strip().splitlines()[-1]))
    return _OUT


class TestOnTheRealStack(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.o = _driver_output()

    def test_setup_worked(self):
        self.assertEqual(self.o["policy_saved"], 200)
        self.assertEqual((self.o["bravo_feed_before"], self.o["bravo_alerts_before"]), (2, 1))

    def test_a_host_with_a_few_rules_is_told_as_before(self):
        o = self.o
        self.assertEqual(o["few_violated"], [["software_policy_violation", "banned:banned-pkg-%d" % i] for i in range(3)])
        self.assertEqual(o["few_cleared"], [["policy_compliant", "banned:banned-pkg-%d" % i] for i in range(3)])
        self.assertEqual(o["few_open_alerts_after"], 0)

    def test_a_push_that_changes_a_hundred_rules_tells_five_and_one_for_the_rest(self):
        o = self.o
        first = o["first_push"]
        self.assertEqual(len(first), 6, first)
        self.assertEqual([r for e, r, d in first[:5]], ["banned:banned-pkg-0", "banned:banned-pkg-1", "banned:banned-pkg-10",
                                                         "banned:banned-pkg-11", "banned:banned-pkg-12"], "the order of the rule ids")
        self.assertEqual(first[5][:2], ["software_policy_violation", "(more rules)"])
        self.assertTrue(first[5][2].startswith("95 more rules are violated: "), first[5][2])
        self.assertEqual(len(o["first_push_open_alerts"]), 6)

    def test_the_cleared_ones_are_the_same_five_and_the_rest_closes_with_the_host(self):
        o = self.o
        self.assertEqual(len(o["second_push"]), 6)
        self.assertEqual([r for e, r in o["second_push"][:5]], ["banned:banned-pkg-0", "banned:banned-pkg-1", "banned:banned-pkg-10",
                                                                "banned:banned-pkg-11", "banned:banned-pkg-12"])
        self.assertEqual(o["second_push_closer_has_no_rule"], [False])
        self.assertEqual(o["second_push_open_alerts"], 0, "the alert that stood for the other 95 rules is closed too")

    def test_sixty_flips_cause_about_forty_events_and_not_six_thousand(self):
        o = self.o
        total = 12 + o["flood_total_events"]
        self.assertLessEqual(total, 41, "the budget of the hour is 40, and the one event that says it was met")
        self.assertGreaterEqual(total, 30, "control: events were told until the budget was met")
        self.assertLessEqual(o["flood_max_per_push"], 12)

    def test_the_budget_being_met_is_one_event_and_then_nothing(self):
        o = self.o
        self.assertEqual(o["held_notices"], ["software_policy_violation"])
        self.assertEqual(o["tail_of_pushes"], [0] * 30)
        self.assertGreaterEqual(o["recent_events_of_alpha"], 41)

    def test_another_organisations_history_is_still_there(self):
        o = self.o
        self.assertEqual((o["bravo_feed_after"], o["bravo_alerts_after"]), (2, 1))
        self.assertLess(o["alpha_alert_rows"], 40)


class TestTheRuleAsAFunction(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.o = _driver_output()

    def test_five_or_fewer_are_told_one_by_one_in_the_order_of_the_policy(self):
        o = self.o
        self.assertEqual(o["fn_few_new"], [["software_policy_violation", r] for r in ("banned:p00", "banned:p01", "banned:p02")])
        self.assertEqual(o["fn_few_gone"], [["policy_compliant", r] for r in ("banned:p00", "banned:p01", "banned:p02")])
        self.assertEqual(o["fn_five_new"], [["software_policy_violation", "banned:p%02d" % i] for i in range(5)])

    def test_the_sixth_makes_the_summary(self):
        self.assertEqual(self.o["fn_six_new"], [["software_policy_violation", "banned:p%02d" % i] for i in range(5)]
                         + [["software_policy_violation", "(more rules)"]])

    def test_the_listed_ones_are_chosen_by_the_rule_id_whatever_the_order_of_the_policy(self):
        self.assertEqual([r for e, r in self.o["fn_new_order_is_by_id"]][:5], ["banned:p%02d" % i for i in range(5)])

    def test_a_host_that_is_whole_again_closes_every_policy_alert_with_one_event(self):
        got = self.o["fn_many_gone_whole"]
        self.assertEqual(got[:5], [["policy_compliant", "banned:p%02d" % i] for i in range(5)])
        self.assertEqual(got[5], ["policy_compliant", None], "no rule: it closes all of them")
        self.assertEqual(len(got), 6)

    def test_a_partial_recovery_does_not_close_what_is_still_violated(self):
        got = self.o["fn_many_gone_partial"]
        self.assertEqual([r for e, r in got if e == "policy_compliant"], ["banned:p%02d" % i for i in range(5)])
        self.assertNotIn(["policy_compliant", None], got)

    def test_the_summary_names_the_first_rules_and_says_there_are_others(self):
        d = self.o["fn_summary_detail"]
        self.assertTrue(d.startswith("15 more rules are violated: banned:p05, banned:p06"), d)
        self.assertTrue(d.endswith(" and others"), d)

    def test_the_budget_of_the_hour(self):
        o = self.o
        self.assertEqual(o["fn_budget_room_for_all"], [["software_policy_violation", "banned:p%02d" % i] for i in range(4)])
        self.assertEqual(o["fn_budget_38"], [["software_policy_violation", "banned:p00"], ["software_policy_violation", "banned:p01"],
                                              ["software_policy_violation", "(held back)"]])
        self.assertEqual(o["fn_budget_40"], [], "the budget was met before: the notice has been told")
        self.assertEqual(o["fn_budget_55"], [])

    def test_only_this_hosts_events_of_the_last_hour_count(self):
        o = self.o
        self.assertEqual(o["fn_an_hour_old_is_not_recent"], 0)
        self.assertEqual(o["fn_other_hosts_do_not_count"], 0, "and a row that is not an event is not one")
        self.assertEqual(o["fn_junk_between_events_does_not_end_the_count"], 4, "control: the count sees this host's events past a junk row")
        self.assertEqual(o["fn_old_events_do_not_count"], [["software_policy_violation", "banned:p%02d" % i] for i in range(4)])


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""8.0.0: automatic container image updates (opt-in).

The pure part (server/cgi-bin/image_autoupdate.py) holds the rules: what the policy may say, which updates it allows now and why it holds the others back,
and whether an update worked. The server part (image_autoupdate_handlers.py) is driven here against the real handlers and stores: it queues what the
Update button of the Image updates tab queues, through the helper a sweep may use, so maintenance mode, quarantine and change approval apply to it.

What must hold, each with a test that fails when it does not:
  * off is the default and does nothing; shadow records what it would have done and queues nothing; on queues, and only for an image on the list.
  * a project holds several images and one command updates all of them, so a project with a stale image that is not on the list is left alone.
  * an update is tried once per release: a receipt for the same images at the same digests stops the next sweep.
  * a refusal (maintenance mode, a quarantined host) records nothing and is tried again; a change that needs a second admin is parked once and followed.
  * what was queued is checked against what the host reports, and a failure is an alert, once.
  * the policy is the platform operator's, and switching it on asks for a fresh sign-in.
"""
import json
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v742_container_recovery import api  # noqa: E402  (one shared import of api.py, with RP_DATA_DIR pinned before it)
from test_v800_smtp_guide import _call  # noqa: E402

import image_autoupdate as IA  # noqa: E402


def _anonymous(handler, body, verb="POST"):
    """The handler with no token at all: the real sign-in check runs and answers, and the answer is captured."""
    names = ("get_token_from_request", "method", "get_json_body", "get_json_obj", "respond")
    saved = {n: getattr(api, n) for n in names}
    box = {}
    api.get_token_from_request = lambda: None
    api.method = lambda: verb
    api.get_json_body = lambda: json.loads(json.dumps(body))
    api.get_json_obj = api.get_json_body

    def _resp(status, data=None):
        box["status"], box["body"] = status, data
        raise api.HTTPError(status, data)
    api.respond = _resp
    try:
        try:
            handler()
        except api.HTTPError:
            pass
    finally:
        for n, v in saved.items():
            setattr(api, n, v)
    api._LOAD_CACHE.clear()
    return box

NOW = 1_800_000_000
REG = "sha256:" + "b" * 64
OLD = "sha256:" + "a" * 64
OLD2 = "sha256:" + "c" * 64


def row(ref="ghcr.io/acme/web:1", hosts=None, **kw):
    r = {"ref": ref, "image": ref.rsplit(":", 1)[0], "tag": ref.rsplit(":", 1)[1], "update_available": True, "ignored": False, "local": False, "registry_digest": REG,
         "hosts": hosts if hosts is not None else [host("d1", "web01", "/srv/web")]}
    r.update(kw)
    return r


def host(dev_id="d1", name="web01", cdir="/srv/web", stale=True, container="web", local=OLD):
    return {"device_id": dev_id, "device_name": name, "container": container, "local_digest": local, "compose_dir": cdir, "stale": stale}


POLICY_ON = {"mode": "on", "include": ["ghcr.io/acme/*"], "exclude": [], "period": "", "max_hosts_per_run": 2, "verify_after_min": 10}


class TestThePolicy(unittest.TestCase):

    def test_the_default_is_off_and_empty(self):
        self.assertEqual(IA.DEFAULT_POLICY["mode"], "off")
        self.assertEqual(IA.DEFAULT_POLICY["include"], [])
        self.assertEqual(IA.stored_policy(None), IA.DEFAULT_POLICY)

    def test_the_modes(self):
        for mode in ("off", "shadow"):
            self.assertEqual(IA.clean_policy({"mode": mode})[0]["mode"], mode)
        self.assertEqual(IA.clean_policy({"mode": " ON ", "include": ["a/*"]})[0]["mode"], "on")
        for bad in ("auto", "", None, 1, True, ["on"]):
            policy, err = IA.clean_policy({"mode": bad})
            self.assertIsNone(policy, repr(bad))
            self.assertEqual(err, "mode must be off, shadow or on")

    def test_on_needs_a_list(self):
        policy, err = IA.clean_policy({"mode": "on"})
        self.assertIsNone(policy)
        self.assertIn("at least one image pattern", err)
        self.assertIsNone(IA.clean_policy({"mode": "on", "include": []})[0])
        self.assertIsNone(IA.clean_policy({"mode": "on", "include": ["a/*"]})[1])
        self.assertIsNone(IA.clean_policy({"mode": "shadow"})[1], "shadow may be tried before a list is written")

    def test_patterns_come_as_a_list_or_as_text_lowercased_without_repeats(self):
        got = IA.clean_policy({"include": "GHCR.io/Acme/*\nnginx:1.*, nginx:1.*\n\n  linuxserver/*  "})[0]["include"]
        self.assertEqual(got, ["ghcr.io/acme/*", "nginx:1.*", "linuxserver/*"])
        self.assertEqual(IA.clean_policy({"include": ["A/B", "a/b", "", "c"]})[0]["include"], ["a/b", "c"])
        self.assertEqual(IA.clean_policy({"exclude": None})[0]["exclude"], [])

    def test_a_pattern_that_is_not_an_image_pattern_is_refused_and_named(self):
        for bad in ("a b", "a;b", "$(x)", "a\\b", "../x", "é", "-start", "x" * 201, "a|b"):
            policy, err = IA.clean_policy({"include": [bad]})
            self.assertIsNone(policy, repr(bad))
            self.assertIn("is not an image pattern", err)
        self.assertIn("include must be a list", IA.clean_policy({"include": 5})[1])
        self.assertIn("include must be a list", IA.clean_policy({"include": [1]})[1])
        self.assertIn("at most 50", IA.clean_policy({"exclude": ["a%d/*" % i for i in range(51)]})[1])
        self.assertEqual(len(IA.clean_policy({"exclude": ["a%d/*" % i for i in range(50)]})[0]["exclude"]), 50)

    def test_the_numbers_are_bounded_and_a_boolean_is_not_a_number(self):
        self.assertEqual(IA.clean_policy({"max_hosts_per_run": "5", "verify_after_min": 30})[0]["max_hosts_per_run"], 5)
        for key, lo, hi in (("max_hosts_per_run", 1, 10), ("verify_after_min", 5, 120)):
            for bad in (lo - 1, hi + 1, "x", None, True, 10 ** 400, 1.5e99):
                policy, err = IA.clean_policy({key: bad})
                self.assertIsNone(policy, (key, bad))
                self.assertIn("whole number from %d to %d" % (lo, hi), err)
            self.assertEqual(IA.clean_policy({key: lo})[0][key], lo)
            self.assertEqual(IA.clean_policy({key: hi})[0][key], hi)

    def test_a_time_period_must_exist_and_blank_means_any_time(self):
        exists = lambda pid: pid == "night"
        self.assertEqual(IA.clean_policy({"period": "night"}, period_exists=exists)[0]["period"], "night")
        self.assertEqual(IA.clean_policy({"period": ""}, period_exists=exists)[0]["period"], "")
        self.assertEqual(IA.clean_policy({"period": "nope"}, period_exists=exists)[1], "period is not a time period")
        self.assertEqual(IA.clean_policy({"period": "x" * 65})[1], "period is not a time period")

    def test_keys_that_are_not_sent_keep_what_they_had_and_unknown_keys_are_ignored(self):
        base = dict(IA.DEFAULT_POLICY, include=["a/*"], max_hosts_per_run=7)
        got = IA.clean_policy({"mode": "shadow", "surprise": 1}, base=base)[0]
        self.assertEqual((got["include"], got["max_hosts_per_run"], got["mode"]), (["a/*"], 7, "shadow"))
        self.assertNotIn("surprise", got)
        self.assertEqual(IA.clean_policy([1])[1], "the policy must be an object")

    def test_a_stored_policy_that_is_damaged_is_read_key_by_key_and_never_acts_on_a_guess(self):
        got = IA.stored_policy({"mode": "on", "include": 5, "exclude": ["ok/*"], "period": 7, "max_hosts_per_run": "lots", "verify_after_min": 15})
        self.assertEqual(got["mode"], "off", "on without a readable list is off")
        self.assertEqual((got["exclude"], got["verify_after_min"], got["max_hosts_per_run"]), (["ok/*"], 15, 2))
        self.assertEqual(IA.stored_policy({"mode": "on", "include": ["a/*"]})["mode"], "on")
        self.assertEqual(IA.stored_policy({"mode": "banana"})["mode"], "off")
        self.assertEqual(IA.stored_policy({"mode": "shadow"})["mode"], "shadow")
        self.assertEqual(IA.stored_policy("junk"), IA.DEFAULT_POLICY)

    def test_match_is_a_case_insensitive_glob_on_the_whole_reference(self):
        self.assertTrue(IA.match("GHCR.io/Acme/web:1", ["ghcr.io/acme/*"]))
        self.assertTrue(IA.match("nginx:1.25", ["nginx:1.*"]))
        self.assertFalse(IA.match("nginx:2.0", ["nginx:1.*"]))
        self.assertFalse(IA.match("evil/ghcr.io/acme/web:1", ["ghcr.io/acme/*"]), "a pattern anchors at the start")
        self.assertTrue(IA.match("a:b", ["?:?"]))
        self.assertFalse(IA.match("a:b", []))
        self.assertFalse(IA.match("a:b", None))
        self.assertTrue(IA.match("anything:at-all", ["*"]))

    def test_the_fingerprint_depends_on_the_images_and_their_digests_and_not_on_their_order(self):
        a = IA.fingerprint({"x:1": REG, "y:1": OLD})
        self.assertEqual(a, IA.fingerprint({"y:1": OLD, "x:1": REG}))
        self.assertNotEqual(a, IA.fingerprint({"x:1": OLD, "y:1": OLD}))
        self.assertNotEqual(a, IA.fingerprint({"x:1": REG}))
        self.assertEqual(len(a), 16)


class TestThePlan(unittest.TestCase):

    def plan(self, rows, policy=None, receipts=None, devices=None, **kw):
        return IA.plan(rows, devices if devices is not None else {"d1": {}, "d2": {}}, policy or POLICY_ON, receipts or [], **kw)

    def test_off_plans_nothing(self):
        self.assertEqual(self.plan([row()], dict(POLICY_ON, mode="off")), [])
        self.assertEqual(IA.plan([row()], {}, {}, []), [])

    def test_only_what_is_on_the_list_is_queued_and_the_rest_says_why(self):
        rows = [row("ghcr.io/acme/web:1"), row("docker.io/other/db:2", hosts=[host("d2", "db01", "/srv/db", container="db")])]
        decisions = self.plan(rows)
        by = {d["device_name"]: d for d in decisions}
        self.assertEqual(by["web01"]["action"], "queue")
        self.assertEqual(by["web01"]["refs"], ["ghcr.io/acme/web:1"])
        self.assertEqual(by["db01"]["action"], "skip")
        self.assertEqual(by["db01"]["reason"], "not on the list: docker.io/other/db:2")

    def test_exclude_wins_over_include(self):
        d = self.plan([row()], dict(POLICY_ON, exclude=["*:1"]))[0]
        self.assertEqual((d["action"], d["reason"]), ("skip", "excluded: ghcr.io/acme/web:1"))

    def test_a_project_with_a_stale_image_that_is_not_allowed_is_left_alone_as_a_whole(self):
        rows = [row("ghcr.io/acme/web:1", hosts=[host(container="web")]), row("docker.io/other/cache:7", hosts=[host(container="cache")])]
        decisions = self.plan(rows)
        self.assertEqual(len(decisions), 1, "one project on one host")
        self.assertEqual(decisions[0]["action"], "skip")
        self.assertEqual(decisions[0]["reason"], "not on the list: docker.io/other/cache:7")
        self.assertEqual(decisions[0]["refs"], ["docker.io/other/cache:7", "ghcr.io/acme/web:1"])
        self.assertEqual(decisions[0]["containers"], ["cache", "web"])

    def test_the_same_project_with_every_stale_image_allowed_is_one_update(self):
        rows = [row("ghcr.io/acme/web:1", hosts=[host(container="web")]), row("ghcr.io/acme/worker:3", hosts=[host(container="worker")])]
        decisions = self.plan(rows)
        self.assertEqual([(d["action"], d["refs"]) for d in decisions], [("queue", ["ghcr.io/acme/web:1", "ghcr.io/acme/worker:3"])])

    def test_two_hosts_and_two_directories_are_separate_updates_in_a_fixed_order(self):
        rows = [row(hosts=[host("d2", "zeta", "/srv/b"), host("d1", "alpha", "/srv/z"), host("d1", "alpha", "/srv/a")])]
        got = [(d["device_name"], d["dir"]) for d in self.plan(rows)]
        self.assertEqual(got, [("alpha", "/srv/a"), ("alpha", "/srv/z"), ("zeta", "/srv/b")])

    def test_what_is_not_an_update_is_not_considered(self):
        hosts = [host(stale=False), host("d2", "db01", cdir="")]
        for kw in ({"update_available": False}, {"ignored": True}, {"local": True}):
            self.assertEqual(self.plan([row(**kw)]), [], kw)
        self.assertEqual(self.plan([row(hosts=hosts)]), [], "a host that is not stale, and one with no compose project, have nothing to update here")

    def test_a_receipt_for_the_same_images_at_the_same_digests_ends_it_and_a_new_digest_starts_it_again(self):
        fp = IA.fingerprint({"ghcr.io/acme/web:1": REG})
        receipts = [{"device_id": "d1", "dir": "/srv/web", "fingerprint": fp, "state": "ok"}]
        self.assertEqual(self.plan([row()], receipts=receipts), [])
        newer = row(registry_digest="sha256:" + "d" * 64)
        self.assertEqual(self.plan([newer], receipts=receipts)[0]["action"], "queue")
        other_host = [{"device_id": "d2", "dir": "/srv/web", "fingerprint": fp}]
        self.assertEqual(self.plan([row()], receipts=other_host)[0]["action"], "queue", "a receipt for another host does not count")

    def test_an_agentless_host_an_offline_host_and_a_closed_period_hold_it_back_and_say_so(self):
        d = self.plan([row()], devices={"d1": {"agentless": True}})[0]
        self.assertEqual((d["action"], d["reason"]), ("skip", "agentless host"))
        d = self.plan([row()], online=lambda dev: False)[0]
        self.assertEqual((d["action"], d["reason"]), ("skip", "host offline"))
        d = self.plan([row()], period_active=False)[0]
        self.assertEqual((d["action"], d["reason"]), ("skip", "outside the time period"))
        self.assertEqual(self.plan([row()], online=lambda dev: True, period_active=True)[0]["action"], "queue")

    def test_shadow_plans_like_on(self):
        self.assertEqual([d["action"] for d in self.plan([row()], dict(POLICY_ON, mode="shadow"))], ["queue"])


def receipt(**kw):
    r = {"id": "r1", "device_id": "d1", "dir": "/srv/web", "digests": {"ghcr.io/acme/web:1": REG}, "before": {"web": 0}, "queued_at": NOW, "verify_at": NOW + 600, "state": "queued"}
    r.update(kw)
    return r


def report(items, at=NOW + 700):
    return {"reported_at": at, "items": items}


def box(status="Up 3 minutes", health="", digest=REG, restarts=0, name="web", cdir="/srv/web", image="ghcr.io/acme/web", tag="1"):
    return {"name": name, "image": image, "tag": tag, "status": status, "health": health, "repo_digest": digest, "restart_count": restarts, "compose_dir": cdir}


class TestTheVerification(unittest.TestCase):

    def v(self, rec, now=NOW + 800, **kw):
        return IA.verify(receipt(**kw), rec, now)

    def test_it_waits_until_the_time_to_look(self):
        self.assertEqual(self.v(report([box()]), now=NOW + 599), ("pending", ""))

    def test_a_container_on_the_new_image_that_runs_is_ok(self):
        self.assertEqual(self.v(report([box()])), ("ok", ""))
        self.assertEqual(self.v(report([box(status="running", health="healthy")])), ("ok", ""))

    def test_a_report_from_before_the_update_was_queued_is_not_evidence(self):
        self.assertEqual(self.v(report([box()], at=NOW - 5)), ("pending", ""))
        self.assertEqual(self.v(report([box()], at=NOW), ), ("pending", ""), "at the moment it was queued is not after")
        state, detail = self.v(report([box()], at=NOW - 5), now=NOW + 600 + IA.VERIFY_GRACE_S)
        self.assertEqual(state, "unverified")
        self.assertIn("reported nothing", detail)
        self.assertEqual(self.v(None)[0], "pending")

    def test_a_container_that_still_runs_the_old_image_is_not_updated(self):
        state, detail = self.v(report([box(digest=OLD)]))
        self.assertEqual(state, "not_updated")
        self.assertIn("web still runs the old image of ghcr.io/acme/web:1", detail)

    def test_a_stopped_or_unhealthy_or_restarting_container_is_not_healthy(self):
        for status in ("Exited (1) 3 seconds ago", "dead", "Created"):
            state, detail = self.v(report([box(status=status)]))
            self.assertEqual(state, "unhealthy", status)
            self.assertIn("is not running", detail)
        self.assertIn("health check", self.v(report([box(health="unhealthy")]))[1])
        state, detail = self.v(report([box(restarts=2)]))
        self.assertEqual((state, "keeps restarting" in detail), ("unhealthy", True))
        self.assertEqual(self.v(report([box(restarts=1)]))[0], "ok", "one restart is not a loop")
        self.assertEqual(self.v(report([box(restarts=5)]), before={"web": 4})[0], "ok", "restarts are counted from before the update")

    def test_a_health_check_that_is_still_starting_settles_or_fails_after_the_grace(self):
        self.assertEqual(self.v(report([box(health="starting")]))[0], "pending")
        state, detail = self.v(report([box(health="starting")]), now=NOW + 600 + IA.VERIFY_GRACE_S)
        self.assertEqual((state, "never settled" in detail), ("unhealthy", True))

    def test_the_updated_containers_must_be_in_the_report_and_others_are_not_looked_at(self):
        self.assertEqual(self.v(report([box(cdir="/srv/other")]))[0], "pending")
        late = self.v(report([box(cdir="/srv/other")]), now=NOW + 600 + IA.VERIFY_GRACE_S)
        self.assertEqual(late[0], "unverified")
        mixed = report([box(), box(name="other", image="x/y", tag="2", status="Exited", digest=OLD)])
        self.assertEqual(self.v(mixed)[0], "ok", "a container of the project whose image was not part of the update is not judged")

    def test_a_tag_that_is_missing_reads_as_latest(self):
        r = receipt(digests={"ghcr.io/acme/web:latest": REG})
        self.assertEqual(IA.verify(r, report([box(tag="")]), NOW + 800)[0], "ok")

    def test_a_missing_digest_on_either_side_is_not_stale(self):
        self.assertEqual(self.v(report([box(digest="")]))[0], "ok")
        self.assertEqual(IA.verify(receipt(digests={"ghcr.io/acme/web:1": ""}), report([box(digest=OLD)]), NOW + 800)[0], "ok")


# ── the server part ────────────────────────────────────────────────────────────────────────────────────────────────────────
def _seed(config=None, containers=None, devices=None):
    now = int(time.time())
    api.save(api.CONFIG_FILE, dict({"image_autoupdate": POLICY_ON, "last_image_autoupdate": 0}, **(config or {})))
    api.save(api.USERS_FILE, {"alice": {"role": "admin", "password_hash": "x", "created": 1}})
    api.save(api.DEVICES_FILE, devices or {
        "d1": {"id": "d1", "name": "web01", "last_seen": now, "token": "t1", "sysinfo": {}},
        "d2": {"id": "d2", "name": "db01", "last_seen": now, "token": "t2", "sysinfo": {}}})
    api.save(api.CONTAINERS_FILE, containers if containers is not None else {
        "d1": {"reported_at": now, "items": [box(digest=OLD)]},
        "d2": {"reported_at": now, "items": [box(name="db", digest=OLD2, image="docker.io/other/db", tag="2", cdir="/srv/db")]}})
    api.save(api.IMAGE_UPDATES_FILE, {"images": {"ghcr.io/acme/web:1": {"registry_digest": REG, "last_checked": now, "registry": "ghcr.io"},
                                                 "docker.io/other/db:2": {"registry_digest": REG, "last_checked": now, "registry": "docker.io"}}, "last_full_scan": now})
    api.save(api.CMDS_FILE, {})
    api.save(api.CONFIRMATIONS_FILE, {"confirmations": []})
    api._LOAD_CACHE.clear()


class _Sweep(unittest.TestCase):

    def setUp(self):
        _seed()
        self.fired = []
        self.audits = []
        self._fw, self._al = api.fire_webhook, api.audit_log
        api.fire_webhook = lambda event, payload=None, *a, **k: self.fired.append((event, dict(payload or {})))
        api.audit_log = lambda *a, **k: self.audits.append(a)

    def tearDown(self):
        api.fire_webhook, api.audit_log = self._fw, self._al

    def sweep(self, **config):
        cfg = api.load(api.CONFIG_FILE)
        cfg["last_image_autoupdate"] = 0
        cfg.update(config)
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()
        api.run_image_autoupdate_if_due()
        api._LOAD_CACHE.clear()

    def receipts(self):
        api._LOAD_CACHE.clear()
        return ((api.load(api.IMAGE_UPDATES_FILE) or {}).get("autoupdate") or {}).get("receipts") or []

    def queue(self):
        api._LOAD_CACHE.clear()
        return api.load(api.CMDS_FILE) or {}

    def last_run(self):
        api._LOAD_CACHE.clear()
        return ((api.load(api.IMAGE_UPDATES_FILE) or {}).get("autoupdate") or {}).get("last_run") or {}

    def set_policy(self, **kw):
        cfg = api.load(api.CONFIG_FILE)
        cfg["image_autoupdate"] = dict(POLICY_ON, **kw)
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()

    def failures(self):
        """The alerts about a failed update. Queueing a command is itself an event (command_queued), as it is for the Update button."""
        return [(e, p) for e, p in self.fired if e == "image_autoupdate_failed"]


class TestTheSweep(_Sweep):

    def test_off_does_nothing_at_all(self):
        self.set_policy(mode="off")
        self.sweep()
        self.assertEqual((self.queue(), self.receipts(), self.last_run()), ({}, [], {}))
        self.assertEqual(self.fired, [], "off fires nothing at all")

    def test_no_policy_in_the_settings_is_off(self):
        api.save(api.CONFIG_FILE, {"last_image_autoupdate": 0})
        api._LOAD_CACHE.clear()
        api.run_image_autoupdate_if_due()
        self.assertEqual((self.queue(), self.receipts()), ({}, []))

    def test_shadow_records_what_it_would_have_done_and_queues_nothing(self):
        self.set_policy(mode="shadow")
        self.sweep()
        self.assertEqual(self.queue(), {})
        rows = self.receipts()
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["state"], rows[0]["device_id"], rows[0]["dir"], rows[0]["mode"]), ("shadow", "d1", "/srv/web", "shadow"))
        self.assertEqual(rows[0]["command"], "compose:update:/srv/web")
        self.sweep()
        self.assertEqual(len(self.receipts()), 1, "shadow does not repeat itself every sweep")

    def test_on_queues_the_update_command_for_the_image_on_the_list_and_not_for_the_one_that_is_not(self):
        self.sweep()
        self.assertEqual(self.queue(), {"d1": ["compose:update:/srv/web"]})
        rows = self.receipts()
        self.assertEqual([r["state"] for r in rows], ["queued"])
        self.assertGreater(rows[0]["verify_at"], rows[0]["queued_at"])
        self.assertEqual(rows[0]["verify_at"] - rows[0]["queued_at"], 600)
        self.assertEqual(rows[0]["before"], {"web": 0})
        held = self.last_run()["held"]
        self.assertEqual([h["reason"] for h in held], ["not on the list: docker.io/other/db:2"])
        self.assertEqual(self.last_run()["made"], 1)

    def test_it_is_audited_as_the_loop_and_the_command_is_logged_under_its_name(self):
        self.sweep()
        self.assertIn(("image-autoupdate", "image_autoupdate_queued", "host=d1 dir=/srv/web images=ghcr.io/acme/web:1"), self.audits)

    def test_a_second_sweep_does_not_queue_the_same_release_again(self):
        self.sweep()
        self.sweep()
        self.assertEqual(self.queue(), {"d1": ["compose:update:/srv/web"]})
        self.assertEqual(len(self.receipts()), 1)

    def test_max_hosts_per_run_bounds_one_sweep_and_the_next_one_takes_the_rest(self):
        now = int(time.time())
        containers = {d: {"reported_at": now, "items": [box(digest=OLD)]} for d in ("d1", "d2", "d3")}
        devices = {d: {"id": d, "name": "h" + d, "last_seen": now, "token": "t", "sysinfo": {}} for d in ("d1", "d2", "d3")}
        _seed(containers=containers, devices=devices)
        self.set_policy(max_hosts_per_run=2)
        self.sweep()
        self.assertEqual(sorted(self.queue()), ["d1", "d2"])
        self.sweep()
        self.assertEqual(sorted(self.queue()), ["d1", "d2", "d3"])

    def test_the_sweep_is_not_due_again_within_the_cadence(self):
        cfg = api.load(api.CONFIG_FILE)
        cfg["last_image_autoupdate"] = int(time.time()) - 30
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()
        api.run_image_autoupdate_if_due()
        self.assertEqual(self.queue(), {})

    def test_a_sweep_that_ran_stamps_the_cadence_and_the_next_request_does_not_sweep_again(self):
        self.sweep()
        self.assertEqual(len(self.receipts()), 1)
        self.assertAlmostEqual(api.load(api.CONFIG_FILE)["last_image_autoupdate"], time.time(), delta=30)
        api.save(api.CMDS_FILE, {})                  # what it queued is gone, and its receipt too: only the cadence is left to hold the next sweep back
        store = api.load(api.IMAGE_UPDATES_FILE)
        store["autoupdate"]["receipts"] = []
        api.save(api.IMAGE_UPDATES_FILE, store)
        api._LOAD_CACHE.clear()
        api.run_image_autoupdate_if_due()
        self.assertEqual((self.queue(), self.receipts()), ({}, []), "a request a moment later does not sweep")

    def test_an_offline_host_is_not_sent_a_command_that_would_wait_for_it(self):
        devs = json.loads((Path(api.DEVICES_FILE)).read_text())
        devs["d1"]["last_seen"] = 1                 # save() refuses to move last_seen back, so the file is written directly
        Path(api.DEVICES_FILE).write_text(json.dumps(devs))
        api._LOAD_CACHE.clear()
        self.sweep()
        self.assertEqual(self.queue(), {})
        self.assertEqual([h["reason"] for h in self.last_run()["held"] if h["device"] == "web01"], ["host offline"])

    def test_a_closed_time_period_holds_it_and_an_open_one_lets_it_go(self):
        always = {"id": "always", "name": "Always", "weekly": {str(d): [[0, 1440]] for d in range(7)}}
        never = {"id": "never", "name": "Never", "weekly": {}}
        self.set_policy(period="never")
        self.sweep(time_periods=[always, never])
        self.assertEqual(self.queue(), {})
        self.assertEqual({h["device"]: h["reason"] for h in self.last_run()["held"]}["web01"], "outside the time period")
        self.set_policy(period="always")
        self.sweep(time_periods=[always, never])
        self.assertEqual(list(self.queue()), ["d1"])

    def test_a_period_that_was_deleted_is_a_closed_window(self):
        self.set_policy(period="gone")
        self.sweep(time_periods=[])
        self.assertEqual(self.queue(), {})

    def test_maintenance_mode_refuses_and_records_nothing_and_it_goes_through_when_it_ends(self):
        self.sweep(maintenance_mode=True, maintenance_reason="upgrade")
        self.assertEqual((self.queue(), self.receipts()), ({}, []))
        held = self.last_run()["held"]
        self.assertTrue(any("maintenance" in h["reason"].lower() for h in held), held)
        self.sweep(maintenance_mode=False)
        self.assertEqual(list(self.queue()), ["d1"])
        self.assertEqual(len(self.receipts()), 1)

    def test_a_quarantined_host_is_refused_and_nothing_is_recorded(self):
        devs = api.load(api.DEVICES_FILE)
        devs["d1"]["quarantined"] = True
        api.save(api.DEVICES_FILE, devs)
        api._LOAD_CACHE.clear()
        self.sweep()
        self.assertEqual((self.queue(), self.receipts()), ({}, []))
        self.assertTrue(any("quarantined" in h["reason"] for h in self.last_run()["held"]))

    def test_change_approval_parks_it_once_and_follows_the_decision(self):
        self.sweep(change_approval_enabled=True, approval_gated_kinds=["compose"])
        self.assertEqual(self.queue(), {}, "nothing was queued: a second admin has to approve it")
        rows = self.receipts()
        self.assertEqual([r["state"] for r in rows], ["awaiting_approval"])
        cid = rows[0]["confirmation_id"]
        self.assertTrue(cid)
        confs = api.load(api.CONFIRMATIONS_FILE)["confirmations"]
        self.assertEqual([(c["id"], c["status"], c.get("params", {}).get("command")) for c in confs], [(cid, "pending", "compose:update:/srv/web")])
        self.assertEqual(confs[0].get("requested_by") or confs[0].get("actor") or "image-autoupdate", "image-autoupdate")
        self.sweep()
        self.assertEqual(len(api.load(api.CONFIRMATIONS_FILE)["confirmations"]), 1, "a pending approval is not asked for again")
        self.assertEqual([r["state"] for r in self.receipts()], ["awaiting_approval"])
        # a second admin approves it: the sweep sees it and starts the clock
        api._LOAD_CACHE.clear()
        store = api.load(api.CONFIRMATIONS_FILE)
        store["confirmations"][0]["status"] = "approved"
        api.save(api.CONFIRMATIONS_FILE, store)
        self.sweep()
        rows = self.receipts()
        self.assertEqual([r["state"] for r in rows], ["queued"])
        self.assertGreater(rows[0]["verify_at"], rows[0]["queued_at"])
        self.assertEqual(rows[0]["verify_at"] - rows[0]["queued_at"], 600)
        self.assertAlmostEqual(rows[0]["queued_at"], time.time(), delta=30, msg="the clock starts when it was approved, so a report from before is no evidence")

    def test_a_rejected_or_expired_approval_ends_it_and_it_is_not_asked_for_again(self):
        for status in ("rejected", "expired", "failed"):
            _seed()
            self.sweep(change_approval_enabled=True, approval_gated_kinds=["compose"])
            store = api.load(api.CONFIRMATIONS_FILE)
            store["confirmations"][0]["status"] = status
            api.save(api.CONFIRMATIONS_FILE, store)
            api._LOAD_CACHE.clear()
            self.sweep()
            rows = self.receipts()
            self.assertEqual([r["state"] for r in rows], ["declined"], status)
            self.assertIn(status, rows[0]["detail"])
            self.sweep()
            self.assertEqual(len(api.load(api.CONFIRMATIONS_FILE)["confirmations"]), 1, status)

    def test_a_parked_change_whose_request_was_removed_is_declined(self):
        self.sweep(change_approval_enabled=True, approval_gated_kinds=["compose"])
        api.save(api.CONFIRMATIONS_FILE, {"confirmations": []})
        api._LOAD_CACHE.clear()
        self.sweep()
        self.assertEqual([r["state"] for r in self.receipts()], ["declined"])

    def test_a_stored_policy_that_is_garbage_does_not_break_the_sweep_or_act(self):
        api.save(api.CONFIG_FILE, {"image_autoupdate": "junk", "last_image_autoupdate": 0})
        api._LOAD_CACHE.clear()
        api.run_image_autoupdate_if_due()
        api.save(api.CONFIG_FILE, {"image_autoupdate": {"mode": "on", "include": "nonsense;;", "max_hosts_per_run": [1]}, "last_image_autoupdate": 0})
        api._LOAD_CACHE.clear()
        api.run_image_autoupdate_if_due()
        self.assertEqual((self.queue(), self.receipts()), ({}, []))

    def test_the_sweep_is_in_the_request_cadence_and_the_out_of_band_scheduler(self):
        main_src = (Path(api.__file__).read_text() if False else (Path(__file__).resolve().parent.parent / "server" / "cgi-bin" / "api.py").read_text())
        self.assertIn("_safe(run_image_autoupdate_if_due, 'run_image_autoupdate_if_due')", main_src)
        import scheduler
        self.assertIn("run_image_autoupdate_if_due", scheduler.CADENCE)


class TestFollowingWhatWasQueued(_Sweep):

    def queued(self):
        self.sweep()
        rows = self.receipts()
        self.assertEqual([r["state"] for r in rows], ["queued"])
        return rows[0]

    def host_reports(self, items, ahead=0):
        cstore = api.load(api.CONTAINERS_FILE)
        cstore["d1"] = {"reported_at": int(time.time()) + ahead, "items": items}
        api.save(api.CONTAINERS_FILE, cstore)
        api._LOAD_CACHE.clear()

    def due(self, rec_id):
        store = api.load(api.IMAGE_UPDATES_FILE)
        for r in store["autoupdate"]["receipts"]:
            if r["id"] == rec_id:
                r["verify_at"] = int(time.time()) - 1
                r["queued_at"] = int(time.time()) - 400
        api.save(api.IMAGE_UPDATES_FILE, store)
        api._LOAD_CACHE.clear()

    def state(self):
        return self.receipts()[0]

    def test_nothing_is_decided_before_the_time_to_look(self):
        rec = self.queued()
        self.host_reports([box()])
        self.sweep()
        self.assertEqual(self.state()["state"], "queued")
        self.assertEqual(self.failures(), [])
        self.assertTrue(rec["verify_at"] > int(time.time()))

    def test_an_update_that_worked_is_ok_and_says_nothing(self):
        rec = self.queued()
        self.due(rec["id"])
        self.host_reports([box(digest=REG)])
        self.sweep()
        self.assertEqual((self.state()["state"], self.state()["detail"]), ("ok", ""))
        self.assertEqual(self.failures(), [])

    def test_an_image_that_did_not_change_is_an_alert_with_the_host_the_image_and_the_reason(self):
        rec = self.queued()
        self.due(rec["id"])
        self.host_reports([box(digest=OLD)])
        self.sweep()
        self.assertEqual(self.state()["state"], "not_updated")
        self.assertEqual(len(self.failures()), 1)
        event, payload = self.failures()[0]
        self.assertEqual(event, "image_autoupdate_failed")
        self.assertEqual((payload["name"], payload["device_id"], payload["label"]), ("web01", "d1", "ghcr.io/acme/web:1"))
        self.assertIn("still runs the old image", payload["detail"])
        self.assertTrue(any(a[1] == "image_autoupdate_failed" for a in self.audits))

    def test_containers_that_are_stopped_unhealthy_or_looping_are_an_alert(self):
        for items, words in (([box(status="Exited (1) 1 minute ago")], "is not running"), ([box(health="unhealthy")], "health check"), ([box(restarts=3)], "keeps restarting")):
            _seed()
            self.fired.clear()
            rec = self.queued()
            self.due(rec["id"])
            self.host_reports(items)
            self.sweep()
            self.assertEqual(self.state()["state"], "unhealthy", words)
            self.assertEqual(len(self.failures()), 1, words)
            self.assertIn(words, self.failures()[0][1]["detail"])

    def test_a_host_that_never_reports_again_is_unverified_after_the_grace_and_is_an_alert(self):
        rec = self.queued()
        store = api.load(api.IMAGE_UPDATES_FILE)
        store["autoupdate"]["receipts"][0].update(verify_at=int(time.time()) - IA.VERIFY_GRACE_S - 1, queued_at=int(time.time()) - IA.VERIFY_GRACE_S - 700)
        api.save(api.IMAGE_UPDATES_FILE, store)
        api._LOAD_CACHE.clear()
        cstore = api.load(api.CONTAINERS_FILE)
        cstore["d1"]["reported_at"] = 1
        api.save(api.CONTAINERS_FILE, cstore)
        api._LOAD_CACHE.clear()
        self.sweep()
        self.assertEqual(self.state()["state"], "unverified")
        self.assertEqual(len(self.failures()), 1)
        self.assertEqual(rec["id"], self.state()["id"])

    def test_the_alert_is_raised_once_and_a_decided_receipt_is_not_looked_at_again(self):
        rec = self.queued()
        self.due(rec["id"])
        self.host_reports([box(digest=OLD)])
        self.sweep()
        self.sweep()
        self.assertEqual(len(self.failures()), 1)

    def test_following_goes_on_after_the_policy_is_switched_off(self):
        rec = self.queued()
        self.due(rec["id"])
        self.host_reports([box(digest=REG)])
        self.set_policy(mode="off")
        self.sweep()
        self.assertEqual(self.state()["state"], "ok", "an update that was queued is still checked")
        self.assertEqual(len(self.receipts()), 1)

    def test_receipts_are_capped_and_the_newest_are_kept(self):
        self.set_policy(mode="shadow")
        rows = [{"id": "old%d" % i, "device_id": "dx", "dir": "/x", "fingerprint": "f%d" % i, "state": "ok", "ts": i} for i in range(IA.MAX_RECEIPTS)]
        store = api.load(api.IMAGE_UPDATES_FILE)
        store["autoupdate"] = {"receipts": rows}
        api.save(api.IMAGE_UPDATES_FILE, store)
        api._LOAD_CACHE.clear()
        self.sweep()
        kept = self.receipts()
        self.assertEqual(len(kept), IA.MAX_RECEIPTS)
        self.assertEqual(kept[-1]["device_id"], "d1")
        self.assertEqual(kept[0]["id"], "old1", "the oldest went")


# ── the routes ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
class _Routes(unittest.TestCase):

    def setUp(self):
        _seed(config={"image_autoupdate": dict(IA.DEFAULT_POLICY)})
        api.save(api.USERS_FILE, {"alice": {"role": "admin", "password_hash": "x", "created": 1},
                                  "tadmin": {"role": "admin", "tenant_id": "tenantA", "password_hash": "x", "created": 1},
                                  "viewer": {"role": "viewer", "password_hash": "x", "created": 1}})
        self._entry = api._step_up_token_entry
        self.step_up = True
        api._step_up_token_entry = lambda: (("k", {"step_up_at": int(time.time())}, {}) if self.step_up else (None, None, None))
        api._LOAD_CACHE.clear()

    def tearDown(self):
        api._step_up_token_entry = self._entry

    def get(self, user="alice"):
        return _call(api.handle_image_autoupdate_get, {}, user=user, verb="GET")

    def post(self, body, user="alice"):
        return _call(api.handle_image_autoupdate_set, body, user=user)

    def stored(self):
        api._LOAD_CACHE.clear()
        return api.load(api.CONFIG_FILE).get("image_autoupdate")


class TestSavingThePolicy(_Routes):

    def test_the_platform_operator_saves_off_and_shadow_with_no_step_up(self):
        self.step_up = False
        for mode in ("shadow", "off"):
            box_ = self.post({"mode": mode, "include": ["ghcr.io/acme/*"]})
            self.assertEqual(box_["status"], 200, box_)
            self.assertEqual(self.stored()["mode"], mode)
        self.assertEqual(self.stored()["include"], ["ghcr.io/acme/*"])

    def test_on_asks_for_a_fresh_sign_in_and_is_refused_without_one_and_stores_nothing(self):
        self.step_up = False
        box_ = self.post({"mode": "on", "include": ["ghcr.io/acme/*"]})
        self.assertEqual(box_["status"], 403, box_)
        self.assertEqual(box_["body"].get("code"), "step_up_required")
        self.assertEqual(self.stored()["mode"], "off")
        self.step_up = True
        self.assertEqual(self.post({"mode": "on", "include": ["ghcr.io/acme/*"]})["status"], 200)
        self.assertEqual(self.stored()["mode"], "on")

    def test_changing_a_policy_that_is_on_to_off_needs_no_step_up_but_staying_on_does(self):
        self.post({"mode": "on", "include": ["a/*"]})
        self.step_up = False
        self.assertEqual(self.post({"include": ["a/*", "b/*"], "mode": "on"})["status"], 403, "a wider list is a change of what it may do")
        self.assertEqual(self.post({"mode": "off"})["status"], 200)

    def test_an_api_key_cannot_switch_it_on_because_it_cannot_step_up(self):
        self.step_up = False
        self.assertEqual(self.post({"mode": "on", "include": ["a/*"]})["status"], 403)

    def test_a_tenant_administrator_and_a_viewer_are_refused_and_nothing_is_stored(self):
        api.save(api.CONFIG_FILE, dict(api.load(api.CONFIG_FILE), tenancy_enforced=True))
        api.save(api.TENANTS_FILE, {"tenantA": {"name": "A", "status": "active", "created": 1}})
        api._LOAD_CACHE.clear()
        box_ = self.post({"mode": "shadow"}, user="tadmin")
        self.assertEqual(box_["status"], 403, box_)
        self.assertIn("platform operator", json.dumps(box_["body"]))
        self.assertEqual(self.post({"mode": "shadow"}, user="viewer")["status"], 403)
        self.assertEqual(self.stored()["mode"], "off")
        self.assertEqual(self.post({"mode": "shadow"}, user="alice")["status"], 200)

    def test_nobody_signed_in_is_a_401_whatever_the_body_says_and_nothing_is_stored(self):
        for body in ({"mode": "auto"}, {"mode": "shadow"}, {}):
            box_ = _anonymous(api.handle_image_autoupdate_set, body)
            self.assertEqual(box_["status"], 401, "%r: the sign-in is asked for before the body is read, so a bad body is not answered with 400" % body)
        self.assertEqual(self.stored(), IA.DEFAULT_POLICY)

    def test_only_a_post_saves(self):
        box_ = _call(api.handle_image_autoupdate_set, {"mode": "shadow"}, verb="GET")
        self.assertEqual(box_["status"], 405)
        self.assertEqual(self.stored(), IA.DEFAULT_POLICY)

    def test_what_is_wrong_is_a_400_in_the_words_of_the_check_and_nothing_is_stored(self):
        for body, words in (({"mode": "on"}, "at least one image pattern"), ({"mode": "auto"}, "mode must be"), ({"include": ["a b"]}, "is not an image pattern"),
                            ({"max_hosts_per_run": 99}, "whole number from 1 to 10"), ({"period": "nope"}, "period is not a time period")):
            box_ = self.post(body)
            self.assertEqual(box_["status"], 400, body)
            self.assertIn(words, box_["body"]["error"])
        self.assertEqual(self.stored(), IA.DEFAULT_POLICY)

    def test_an_existing_time_period_is_accepted(self):
        cfg = api.load(api.CONFIG_FILE)
        cfg["time_periods"] = [{"id": "night", "name": "Night", "weekly": {}}]
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()
        self.assertEqual(self.post({"mode": "shadow", "period": "night"})["status"], 200)
        self.assertEqual(self.stored()["period"], "night")

    def test_a_save_is_in_the_audit_trail_and_a_get_is_not_a_save(self):
        box_ = self.post({"mode": "shadow", "include": ["a/*", "b/*"], "exclude": ["*:latest"]})
        line = json.dumps(box_["audit"])
        self.assertIn("image_autoupdate_set", line)
        self.assertIn("mode=shadow include=2 exclude=1", line)
        self.assertIsNone(self.get().get("audit"))

    def test_keys_that_are_not_sent_keep_what_they_had(self):
        self.post({"mode": "shadow", "include": ["a/*"], "max_hosts_per_run": 5})
        self.post({"verify_after_min": 40})
        got = self.stored()
        self.assertEqual((got["include"], got["max_hosts_per_run"], got["verify_after_min"], got["mode"]), (["a/*"], 5, 40, "shadow"))


class TestReadingThePolicy(_Routes):

    def test_it_answers_the_policy_the_receipts_newest_first_what_it_would_do_and_the_periods(self):
        cfg = api.load(api.CONFIG_FILE)
        cfg["image_autoupdate"] = dict(POLICY_ON, mode="shadow")
        cfg["time_periods"] = [{"id": "night", "name": "Night", "weekly": {}}, {"name": "no id"}]
        api.save(api.CONFIG_FILE, cfg)
        store = api.load(api.IMAGE_UPDATES_FILE)
        store["autoupdate"] = {"receipts": [{"id": "r1", "device_id": "d2", "device_name": "db01", "ts": 1, "state": "ok"},
                                            {"id": "r2", "device_id": "d1", "device_name": "web01", "ts": 2, "state": "shadow"}],
                               "last_run": {"ts": 5, "mode": "shadow", "made": 0, "held": []}}
        api.save(api.IMAGE_UPDATES_FILE, store)
        api._LOAD_CACHE.clear()
        box_ = self.get()
        self.assertEqual(box_["status"], 200, box_)
        body = box_["body"]
        self.assertEqual(body["policy"]["mode"], "shadow")
        self.assertEqual([r["id"] for r in body["receipts"]], ["r2", "r1"])
        self.assertEqual(body["periods"], [{"id": "night", "name": "Night"}])
        self.assertEqual(body["last_run"]["ts"], 5)
        self.assertEqual([(d["device_name"], d["action"]) for d in body["preview"]], [("db01", "skip"), ("web01", "queue")])
        self.assertEqual(body["cadence_s"], 300)

    def test_the_preview_is_empty_while_it_is_off(self):
        self.assertEqual(self.get()["body"]["preview"], [])

    def test_nobody_signed_in_reads_nothing(self):
        """_confined_host_ids() says 'not confined' for a caller with no token, so without the sign-in check this answered everything."""
        cfg = api.load(api.CONFIG_FILE)
        cfg["image_autoupdate"] = dict(POLICY_ON, mode="shadow")
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()
        box_ = _anonymous(api.handle_image_autoupdate_get, {}, verb="GET")
        self.assertEqual(box_["status"], 401)
        self.assertNotIn("receipts", json.dumps(box_["body"]))
        self.assertEqual(self.get()["status"], 200, "control: the same read, signed in, is answered")

    def test_the_preview_costs_nothing_while_it_is_off_and_is_built_in_shadow(self):
        calls = []
        real = api._image_update_view
        api._image_update_view = lambda *a, **k: calls.append(1) or real(*a, **k)
        try:
            self.get()
            self.assertEqual(calls, [], "off builds no view of the images")
            cfg = api.load(api.CONFIG_FILE)
            cfg["image_autoupdate"] = dict(POLICY_ON, mode="shadow")
            api.save(api.CONFIG_FILE, cfg)
            api._LOAD_CACHE.clear()
            self.get()
            self.assertTrue(calls, "control: shadow does build it, so the spy sees a call when there is one")
        finally:
            api._image_update_view = real

    def test_a_tenant_sees_the_receipts_and_the_preview_of_its_own_hosts_only(self):
        cfg = api.load(api.CONFIG_FILE)
        cfg.update(tenancy_enforced=True, image_autoupdate=dict(POLICY_ON, mode="shadow", include=["*"]))
        api.save(api.CONFIG_FILE, cfg)
        api.save(api.TENANTS_FILE, {"tenantA": {"name": "A", "status": "active", "created": 1}, "tenantB": {"name": "B", "status": "active", "created": 1}})
        devs = api.load(api.DEVICES_FILE)
        devs["d1"]["tenant"], devs["d2"]["tenant"] = "tenantA", "tenantB"
        api.save(api.DEVICES_FILE, devs)
        store = api.load(api.IMAGE_UPDATES_FILE)
        store["autoupdate"] = {"receipts": [{"id": "r1", "device_id": "d2", "device_name": "db01", "ts": 1}, {"id": "r2", "device_id": "d1", "device_name": "web01", "ts": 2}],
                               "last_run": {"ts": 5, "made": 0, "held": [{"device": "db01", "reason": "x"}, {"device": "web01", "reason": "y"}]}}
        api.save(api.IMAGE_UPDATES_FILE, store)
        api._LOAD_CACHE.clear()
        mine = self.get(user="tadmin")["body"]
        self.assertEqual([r["id"] for r in mine["receipts"]], ["r2"])
        self.assertEqual([d["device_name"] for d in mine["preview"]], ["web01"])
        self.assertEqual([h["device"] for h in mine["last_run"]["held"]], ["web01"])
        both = self.get(user="alice")["body"]
        self.assertEqual(sorted(r["id"] for r in both["receipts"]), ["r1", "r2"])
        self.assertEqual(sorted(d["device_name"] for d in both["preview"]), ["db01", "web01"])


class TestWiring(unittest.TestCase):

    def test_the_two_routes_are_in_the_table_and_answer_with_the_handlers(self):
        routes = api._build_exact_routes()
        self.assertIs(routes[("GET", "/api/image-updates/auto")], api.handle_image_autoupdate_get)
        self.assertIs(routes[("POST", "/api/image-updates/auto")], api.handle_image_autoupdate_set)


if __name__ == "__main__":
    unittest.main()

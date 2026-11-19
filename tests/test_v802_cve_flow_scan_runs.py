#!/usr/bin/env python3
"""The scan slot is taken once, and the runners that share the findings store do not write over one another.

`handle_cve_scan` read the marker ("a scan is already running"), tested it and wrote it with nothing held between, so a burst of
requests was answered 202 three or four at a time (16 requests from two organisations' administrators, 12 rounds: 1 to 5 runners a
round), and every 202 is a runner process of its own that loads the whole package store (about half a gigabyte for one host on a
100-host data directory). The worker read the whole findings store when it started and wrote the whole of it back at every
checkpoint, so a runner that finished later wrote its older copy over what a newer scan had stored: a host that had installed its
fix and been scanned again came back as vulnerable, with an alert that says the finding exists.

What this holds, on the real WSGI app with real API keys and the real worker (a process of its own; the advisory service is a stand-in
that answers by package version, and the runner process is recorded rather than started):

* a burst of 16 starts is answered 202 once, from any mix of administrators, and the marker carries the id of that run;
* a run whose marker went stale and was taken over writes no more into the marker, and the scan stops at its next checkpoint, while a
  worker started by hand (no id) is never handed on;
* two scans that overlap on one host: the result made from the older list is not written over the newer one, and no alert is raised
  for a finding that was fixed before it was stored;
* the rules of the slot, as a function: busy, stale, cooling, a marker that holds junk.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v802-sr-"))
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
_TMP = []


def tearDownModule():
    import shutil
    for d in _TMP:
        shutil.rmtree(d, ignore_errors=True)


_DRIVER = r"""
import json, sys, threading, time
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


put("CONFIG_FILE", {"tenancy_enforced": True})
put("TENANTS_FILE", {"tenantA": {"name": "Tenant A"}, "tenantB": {"name": "Tenant B"}})
put("USERS_FILE", {"op": {"role": "admin", "tenant_id": "default", "created": 1},
                   "adminA": {"role": "admin", "tenant_id": "tenantA", "created": 1},
                   "adminB": {"role": "admin", "tenant_id": "tenantB", "created": 1}})
put("APIKEYS_FILE", {"k1": key("T-OP", "op", "admin", "default"), "k2": key("T-ADMIN-A", "adminA", "admin", "tenantA"),
                     "k4": key("T-ADMIN-B", "adminB", "admin", "tenantB")})
TOK = {"op": "T-OP", "adminA": "T-ADMIN-A", "adminB": "T-ADMIN-B"}


def call(who, method, path, body=None):
    c = wsgi.application.test_client()
    kw = {"headers": {"X-Token": TOK[who]} if who else {}}
    if body is not None:
        kw["data"] = json.dumps(body)
        kw["content_type"] = "application/json"
    r = getattr(c, method.lower())(path, **kw)
    try:
        return [r.status_code, json.loads(r.data.decode("utf-8", "replace"))]
    except ValueError:
        return [r.status_code, None]


def marker():
    api._invalidate_load_cache(api.CVE_SCAN_STATUS_FILE)
    return api.load(api.CVE_SCAN_STATUS_FILE)


def findings():
    api._invalidate_load_cache(api.CVE_FINDINGS_FILE)
    return api.load(api.CVE_FINDINGS_FILE) or {}


HOSTS = ["host-1", "host-2", "host-3", "host-4", "host-5"]
put("DEVICES_FILE", {h: {"name": h.upper(), "hostname": h, "os": "Debian 12", "monitored": True, "last_seen": now, "token": "T-" + h,
                         "group": "g", "ip": "10.0.0.1", "tenant": "tenantA"} for h in HOSTS})


def packages_body(host, version):
    return {"device_id": host, "token": "T-" + host, "pkg_manager": "apt", "sources": True,
            "ecosystem_hint": {"ID": "debian", "VERSION_ID": "12", "ID_LIKE": "", "UBUNTU_CODENAME": "", "DEBIAN_CODENAME": "",
                               "VERSION_CODENAME": ""},
            "packages": [{"name": "libssl3", "version": version, "arch": "amd64", "source": "openssl", "source_version": version}]}


OLD, NEW = "3.0.11-1~deb12u1", "3.0.15-1~deb12u1"
for h in HOSTS:
    st = call(None, "POST", "/api/packages", packages_body(h, OLD))
    assert st[0] == 200, st
# the lists were received a while ago, so that a list received now is later by more than the second the clock counts in
store = api.load(api.PACKAGES_FILE)
for h in HOSTS:
    store[h]["collected_at"] = now - 100
put("PACKAGES_FILE", store)


def querybatch(queries):
    out = []
    for q in queries:
        if q["package"]["name"] == "openssl" and q["version"] == OLD:
            out.append({"vulns": [{"id": "DEBIAN-CVE-2024-openssl-%d" % i, "modified": "2026-11-10T08:00:00.000000Z"} for i in range(5)]})
        else:
            out.append({})
    return out


def details(vid):
    return {"id": vid, "modified": "2026-11-10T08:00:00.000000Z", "published": "2024-03-01T10:00:00Z", "upstream": ["CVE-2024-1%s" % vid[-1]],
            "summary": "a flaw in openssl", "details": "A flaw was found in openssl.",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}], "references": [],
            "affected": [{"package": {"ecosystem": eco, "name": "openssl", "purl": "pkg:deb/debian/openssl?arch=source"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.9-1~deb%du1" % n}]}],
                          "ecosystem_specific": {"urgency": "not yet assigned"}}
                         for eco, n in (("Debian:11", 11), ("Debian:12", 12), ("Debian:13", 13))]}


api.cve_scanner._osv_querybatch = querybatch
api.cve_scanner._osv_vuln_details = details
spawned = []
spawn_lock = threading.Lock()


def record(actor, target):
    with spawn_lock:
        spawned.append([actor, target])


api._spawn_cve_scan = record
fired = []
real_fire = api.fire_webhook


def fire(event, payload, *a, **k):
    fired.append([event, payload.get("name"), payload.get("device_id")])
    return real_fire(event, payload, *a, **k)


api.fire_webhook = fire
out = {}

# 1. a burst of starts. The look at the marker before the slot is taken is slowed, so that every request passes it: only the
# claim under the lock can tell them apart.
api.cve_handlers_mod._SCAN_COOLDOWN_S = 0
real_load = api.load


def slow_load(path, *a, **k):
    if str(path).endswith("cve_scan_status.json"):
        time.sleep(0.05)
    return real_load(path, *a, **k)


api.load = slow_load
rounds = []
for rnd in range(6):
    put("CVE_SCAN_STATUS_FILE", {"running": False})
    del spawned[:]
    answers = []

    def go(i):
        answers.append(call(("adminA", "adminB", "op")[i % 3], "POST", "/api/cve/scan")[0])

    ts = [threading.Thread(target=go, args=(i,)) for i in range(16)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    rounds.append({"accepted": answers.count(202), "refused": answers.count(409), "other": [a for a in answers if a not in (202, 409)],
                   "spawned": len(spawned), "run": isinstance(marker().get("run"), str) and len(marker()["run"]) >= 8})
api.load = real_load
api.cve_handlers_mod._SCAN_COOLDOWN_S = 30
out["bursts"] = rounds

real_scan = api.cve_scanner.scan_device
seen = []


def section(fn):
    try:
        fn()
    except Exception as e:      # the code before 8.0.2 has no lease and no claim function: say that, and let the other sections answer
        out["missing_" + fn.__name__] = repr(e)
    return fn


@section
def lease():
    # 2. the lease
    put("CVE_SCAN_STATUS_FILE", {"running": True, "updated": now - 400, "run": "old-run", "owner": None, "total": 3})
    out["takeover"] = call("op", "POST", "/api/cve/scan")[0]
    new_run = marker()["run"]
    out["new_run_differs"] = new_run != "old-run"
    try:
        api._scan_marker_write({"running": True, "done": 1, "total": 3, "updated": now}, run="old-run")
        out["old_run_writes"] = True
    except api._ScanLeaseLost:
        out["old_run_writes"] = False
    out["marker_run_after_old_write"] = marker()["run"] == new_run
    out["marker_done_after_old_write"] = marker().get("done")
    out["new_run_writes"] = api._scan_marker_write({"running": True, "done": 2, "total": 3, "updated": now}, run=new_run)
    out["marker_done_after_new_write"] = marker().get("done")
    out["by_hand_writes"] = api._scan_marker_write({"running": True, "done": 3, "total": 3, "updated": now}, run=None)
    out["owner_and_run_kept"] = [marker().get("run") == new_run, "owner" in marker()]

    # 2b. a worker whose slot is taken over while it scans stops at its next checkpoint
    reached, release = threading.Event(), threading.Event()

    def gated(dev_id, *a, **k):
        seen.append([threading.current_thread().name, dev_id])
        result = real_scan(dev_id, *a, **k)
        if threading.current_thread().name == "X" and dev_id == "host-2":
            reached.set()
            release.wait(60)
        return result


    api.cve_scanner.scan_device = gated
    put("CVE_FINDINGS_FILE", {})
    put("CVE_SCAN_STATUS_FILE", {"running": True, "updated": int(time.time()), "run": "run-x", "owner": None})
    x = threading.Thread(target=api._cve_scan_worker, args=("X", None), name="X")
    x.start()
    reached.wait(60)
    put("CVE_SCAN_STATUS_FILE", {"running": True, "updated": int(time.time()), "run": "run-y", "owner": None, "done": 0})
    release.set()
    x.join(120)
    out["handed_on_hosts_with_a_record"] = sorted(findings())
    out["handed_on_marker"] = {k: marker().get(k) for k in ("run", "running", "done")}
    api.cve_scanner.scan_device = real_scan



@section
def overlap():
    # 3. two scans that overlap on one host: X is the fleet scan, Y the scan of host-2 alone, after host-2 installed its fix
    put("CVE_FINDINGS_FILE", {})
    put("CVE_SCAN_STATUS_FILE", {"running": False})
    store = api.load(api.PACKAGES_FILE)
    for h in HOSTS:
        store[h]["collected_at"] = now - 100
    put("PACKAGES_FILE", store)
    del fired[:]
    reached, release = threading.Event(), threading.Event()
    del seen[:]


    def gated3(dev_id, *a, **k):
        seen.append([threading.current_thread().name, dev_id])
        result = real_scan(dev_id, *a, **k)
        if threading.current_thread().name == "X" and dev_id == "host-3":
            reached.set()
            release.wait(60)
        return result


    api.cve_scanner.scan_device = gated3
    x = threading.Thread(target=api._cve_scan_worker, args=("X", None), name="X")
    x.start()
    reached.wait(60)
    # host-2 installs the fixed library and sends its list; a scan of host-2 alone stores the clean result
    out["fixed_list"] = call(None, "POST", "/api/packages", packages_body("host-2", NEW))[0]
    y = threading.Thread(target=api._cve_scan_worker, args=("Y", "host-2"), name="Y")
    y.start()
    y.join(120)
    after_y = findings().get("host-2", {})
    out["after_y"] = {"findings": len(after_y.get("findings", [])), "packages_at": after_y.get("packages_at")}
    release.set()
    x.join(120)
    rec2 = findings().get("host-2", {})
    out["after_x"] = {"findings": len(rec2.get("findings", [])), "packages_at": rec2.get("packages_at")}
    out["host_1_findings"] = len(findings().get("host-1", {}).get("findings", []))
    out["host_3_findings"] = len(findings().get("host-3", {}).get("findings", []))
    out["alerts_for_host_2"] = [e for e, n, d in fired if d == "host-2"]
    out["alerts_for_host_1"] = [e for e, n, d in fired if d == "host-1"]
    out["fixed_list_collected_at_is_later"] = (rec2.get("packages_at") or 0) > now - 100



@section
def deleted_hosts():
    # 5. hosts deleted while a fleet scan runs: one already stored, the one being scanned, one still to be scanned
    api.cve_scanner.scan_device = real_scan
    put("CVE_FINDINGS_FILE", {})
    put("CVE_SCAN_STATUS_FILE", {"running": False})
    del fired[:]
    reached, release = threading.Event(), threading.Event()

    def gated5(dev_id, *a, **k):
        result = real_scan(dev_id, *a, **k)
        if threading.current_thread().name == "X" and dev_id == "host-2":
            reached.set()
            release.wait(60)
        return result

    api.cve_scanner.scan_device = gated5
    # the lists of all hosts are the old ones again (the section before this one left host-2 with the fixed list)
    for h in HOSTS:
        st = call(None, "POST", "/api/packages", packages_body(h, OLD))
        assert st[0] == 200, st
    store = api.load(api.PACKAGES_FILE)
    for h in HOSTS:
        store[h]["collected_at"] = now - 100
    put("PACKAGES_FILE", store)
    x = threading.Thread(target=api._cve_scan_worker, args=("X", None), name="X")
    x.start()
    reached.wait(60)
    out["deleted"] = {h: call("op", "DELETE", "/api/devices/" + h)[0] for h in ("host-1", "host-2", "host-3")}
    release.set()
    x.join(120)
    api.cve_scanner.scan_device = real_scan
    api._invalidate_load_cache(api.PACKAGES_FILE)
    api._invalidate_load_cache(api.DEVICES_FILE)
    out["deleted_hosts_with_a_record"] = sorted(h for h in findings() if h in ("host-1", "host-2", "host-3"))
    out["deleted_hosts_with_a_list"] = sorted(h for h in api.load(api.PACKAGES_FILE) if h in ("host-1", "host-2", "host-3"))
    out["remaining_hosts_with_a_record"] = sorted(h for h in findings() if h in ("host-4", "host-5"))
    out["alerts_for_deleted_hosts"] = sorted({d for e, n, d in fired if e == "cve_found" and d in ("host-2", "host-3")})
    # the control: the alert of a host that stays is in the same list, so that a list that cannot see any alert cannot pass
    out["alerts_for_remaining_hosts"] = sorted({d for e, n, d in fired if e == "cve_found" and d in ("host-4", "host-5")})


@section
def claim_rules():
    # 4. the slot as a function
    claim = api.cve_handlers_mod._claim_scan_slot
    cases = {}
    st = {}
    cases["free_operator"] = [claim(st, None, 5, "r1", now), st.get("run"), st.get("owner"), st.get("starts")]
    st = {"running": True, "updated": now - 5, "run": "busy-run"}
    cases["busy"] = [(claim(st, None, 5, "r2", now) or [None])[0], st.get("run")]
    st = {"running": True, "updated": now - 301, "run": "stale-run"}
    cases["stale"] = [claim(st, None, 5, "r3", now), st.get("run")]
    st = {"running": False, "updated": now - 5, "starts": {"t1": now - 5}}
    why = claim(st, "t1", 5, "r4", now)
    cases["cooling"] = [why[0], why[1]]
    st = {"running": False, "updated": now - 5, "starts": {"t1": now - 5}}
    cases["other_tenant"] = [claim(st, "t2", 5, "r5", now), sorted(st["starts"])]
    st = {"running": False, "updated": now - 5, "starts": {"t1": now - 5}}
    cases["operator_has_no_clock"] = [claim(st, None, 5, "r6", now), st.get("run")]
    st = {"running": "yes", "updated": "yesterday", "starts": "junk", "run": 5}
    cases["junk"] = [claim(st, "t1", 5, "r7", now), st.get("run")]
    st = {"running": False, "updated": now - 5, "starts": {"t1": "x", 7: now, "t3": True, "t4": now - 7200}}
    cases["junk_starts"] = [claim(st, "t1", 5, "r8", now), sorted(st["starts"])]
    out["claim"] = cases

print(json.dumps(out))
"""


class TestOnTheRealWorker(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        try:
            import flask  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("flask is not installed")
        d = Path(tempfile.mkdtemp(prefix="rp-v802-sr-run-"))
        _TMP.append(d)
        (d / "driver.py").write_text(_DRIVER, encoding="utf-8")
        data = d / "data"
        data.mkdir()
        env = {k: v for k, v in os.environ.items() if not k.startswith(("REQUEST_", "HTTP_", "PATH_INFO", "QUERY_", "CONTENT_"))}
        env["RP_DATA_DIR"] = str(data)
        proc = subprocess.run([sys.executable, str(d / "driver.py"), str(_CGI)], capture_output=True, text=True, env=env, timeout=900)
        if proc.returncode != 0:
            raise AssertionError("the driver failed:\n" + proc.stderr[-2500:])
        cls.o = json.loads(proc.stdout.strip().splitlines()[-1])

    # ── the slot ─────────────────────────────────────────────────────────────────────────────────────────────
    def test_a_burst_of_starts_is_answered_202_once(self):
        bursts = self.o["bursts"]
        self.assertEqual(len(bursts), 6)
        for n, b in enumerate(bursts):
            self.assertEqual(b["accepted"], 1, "round %d: %d requests were answered 202, and each is a runner process" % (n, b["accepted"]))
            self.assertEqual(b["spawned"], 1, "round %d" % n)
            self.assertEqual(b["other"], [], "round %d" % n)
            self.assertEqual(b["accepted"] + b["refused"], 16)
            self.assertTrue(b["run"], "the marker carries the id of the run")

    def test_the_rules_of_the_slot(self):
        c = self.o["claim"]
        self.assertEqual(c["free_operator"], [None, "r1", None, {}])
        self.assertEqual(c["busy"], ["busy", "busy-run"], "a scan that checkpointed seconds ago keeps the slot, and the marker is not touched")
        self.assertEqual(c["stale"], [None, "r3"], "a marker that has been silent for five minutes is taken over")
        self.assertEqual(c["cooling"][0], "cooling")
        self.assertIn(c["cooling"][1], range(20, 30))
        self.assertEqual(c["other_tenant"], [None, ["t1", "t2"]])
        self.assertEqual(c["operator_has_no_clock"], [None, "r6"])

    def test_a_marker_that_holds_junk_is_replaced_not_trusted(self):
        c = self.o["claim"]
        self.assertEqual(c["junk"], [None, "r7"])
        self.assertEqual(c["junk_starts"], [None, ["t1"]], "only a name with a recent time is kept")

    # ── the lease ────────────────────────────────────────────────────────────────────────────────────────────
    def test_a_stale_marker_is_taken_over_with_a_new_run(self):
        self.assertEqual(self.o["takeover"], 202)
        self.assertTrue(self.o["new_run_differs"])

    def test_the_run_that_lost_the_slot_writes_no_more(self):
        o = self.o
        self.assertFalse(o["old_run_writes"])
        self.assertTrue(o["marker_run_after_old_write"], "the new scan's marker was written over")
        self.assertNotEqual(o["marker_done_after_old_write"], 1)

    def test_the_run_that_holds_the_slot_writes_and_keeps_its_bookkeeping(self):
        o = self.o
        self.assertTrue(o["new_run_writes"])
        self.assertEqual(o["marker_done_after_new_write"], 2)
        self.assertEqual(o["owner_and_run_kept"], [True, True])

    def test_a_worker_started_by_hand_is_never_handed_on(self):
        self.assertTrue(self.o["by_hand_writes"])

    def test_a_worker_whose_slot_was_taken_stops_at_its_next_checkpoint(self):
        o = self.o
        self.assertEqual(o["handed_on_hosts_with_a_record"], ["host-1", "host-2", "host-3", "host-4"],
                         "the checkpoints are at hosts 1, 4 and 5: the scan noticed at 4 and did not scan 5")
        self.assertEqual(o["handed_on_marker"], {"run": "run-y", "running": True, "done": 0},
                         "the new scan's marker is the one that stands")

    # ── two scans that overlap on a host ─────────────────────────────────────────────────────────────────────
    def test_the_result_made_from_the_older_list_does_not_replace_the_newer(self):
        o = self.o
        self.assertEqual(o["fixed_list"], 200)
        self.assertEqual(o["after_y"]["findings"], 0, "the scan of the host after its fix stored a clean result")
        self.assertEqual(o["after_x"]["findings"], 0,
                         "the fleet scan finished later and wrote its older copy over it: the host showed as vulnerable again")
        self.assertEqual(o["after_x"]["packages_at"], o["after_y"]["packages_at"])
        self.assertTrue(o["fixed_list_collected_at_is_later"])

    def test_no_alert_is_raised_for_a_finding_that_was_fixed_before_it_was_stored(self):
        self.assertEqual(self.o["alerts_for_host_2"], [], "an alert says the finding exists; the host had installed its fix")

    # ── hosts deleted while a scan runs ──────────────────────────────────────────────────────────────────────
    def test_a_host_deleted_while_a_scan_runs_does_not_come_back(self):
        o = self.o
        self.assertEqual(o["deleted"], {"host-1": 200, "host-2": 200, "host-3": 200})
        self.assertEqual(o["deleted_hosts_with_a_record"], [],
                         "the scan held the store as it was when it started, and wrote the deleted hosts' findings back")
        self.assertEqual(o["deleted_hosts_with_a_list"], [])

    def test_the_hosts_that_remain_have_their_results(self):
        self.assertEqual(self.o["remaining_hosts_with_a_record"], ["host-4", "host-5"])

    def test_no_alert_is_raised_for_a_host_that_no_longer_exists(self):
        self.assertEqual(self.o["alerts_for_remaining_hosts"], ["host-4", "host-5"], "control: the alerts of the hosts that stay are seen")
        self.assertEqual(self.o["alerts_for_deleted_hosts"], [])

    def test_the_hosts_nobody_touched_have_their_results(self):
        o = self.o
        self.assertEqual(o["host_1_findings"], 5)
        self.assertEqual(o["host_3_findings"], 5)
        self.assertEqual(o["alerts_for_host_1"], ["cve_found"])


if __name__ == "__main__":
    unittest.main()

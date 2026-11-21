#!/usr/bin/env python3
"""A CVE scan covers the caller's own hosts, and its progress is the caller's own business.

`POST /api/cve/scan` with no host queued a scan of every host of every organisation for anyone who could start one: a tenant's
administrator (`require_admin_auth()` passes one) sent the OSV requests and raised the cve_found alerts of other organisations'
hosts through the operator's channels, and was answered with the number of hosts the installation holds. `GET /api/cve/scan-status`
read the whole marker for any signed-in user, so a tenant's viewer read how many hosts the other organisations have and how many of
them can be scanned; and one scan runs at a time for the whole installation, so a tenant's administrator who started scans of its own
hosts back to back held the slot and every other organisation was answered 409 for as long as it did.

What this holds, on the real WSGI app with real API keys (a process of its own, nothing stubbed but the advisory service and the
spawn of the runner process, which is recorded):

* a tenant's administrator's scan is queued for the hosts of its own tenant (`tenant:<id>`), counts those, and the worker walks
  those hosts only: no other organisation's host gets a findings record;
* the operator's scan still covers every host, and an installation without tenancy is unchanged;
* the status marker shows a caller the numbers of its own organisation's scan and, for another organisation's, whether one is
  running and nothing else, in the status route and in the 409 that a refused start carries;
* an organisation can start a scan every 30 seconds, and the clock of one organisation is not another's;
* a single host's scan is refused for a host of another organisation.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v802-ss-"))
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
tenancy = sys.argv[2] == "on"


def put(attr, obj):
    api.save(getattr(api, attr), obj)
    api._invalidate_load_cache(getattr(api, attr))


def key(token, user, role, tenant):
    return {"name": token, "key_hash": api._apikey_hash(token), "user": user, "role": role, "active": True, "created": 1,
            "tenant_id": tenant}


put("CONFIG_FILE", {"tenancy_enforced": True} if tenancy else {})
put("TENANTS_FILE", {"tenantA": {"name": "Tenant A"}, "tenantB": {"name": "Tenant B"}})
put("USERS_FILE", {"op": {"role": "admin", "tenant_id": "default", "created": 1},
                   "adminA": {"role": "admin", "tenant_id": "tenantA", "created": 1},
                   "viewerA": {"role": "viewer", "tenant_id": "tenantA", "created": 1},
                   "adminB": {"role": "admin", "tenant_id": "tenantB", "created": 1}})
put("APIKEYS_FILE", {"k1": key("T-OP", "op", "admin", "default"), "k2": key("T-ADMIN-A", "adminA", "admin", "tenantA"),
                     "k3": key("T-VIEWER-A", "viewerA", "viewer", "tenantA"), "k4": key("T-ADMIN-B", "adminB", "admin", "tenantB")})
TOK = {"op": "T-OP", "adminA": "T-ADMIN-A", "viewerA": "T-VIEWER-A", "adminB": "T-ADMIN-B"}


def host(dev_id, name, tenant, os_name="Debian 12"):
    rec = {"name": name, "hostname": name, "os": os_name, "monitored": True, "last_seen": now, "token": "T-" + dev_id, "group": "g",
           "ip": "10.0.0.1"}
    if tenant:
        rec["tenant"] = tenant
    return rec


HOSTS = {"a1": host("a1", "alpha-web", "tenantA"), "a2": host("a2", "alpha-win", "tenantA", "Windows 11"),
         "b1": host("b1", "bravo-1", "tenantB"), "b2": host("b2", "bravo-2", "tenantB"), "b3": host("b3", "bravo-3", "tenantB"),
         "o1": host("o1", "operator-box", None)}
put("DEVICES_FILE", HOSTS)
deb = [{"name": "openssl", "version": "3.0.11-1", "arch": "amd64"}]
store = {d: {"hash": "h", "collected_at": now, "ecosystem": "Debian:12", "pkg_manager": "apt", "count": 1, "packages": deb,
             "os_id": "debian", "version_id": "12"} for d in ("a1", "b1", "b2", "b3", "o1")}
store["a2"] = {"hash": "h", "collected_at": now, "ecosystem": "", "pkg_manager": "windows", "count": 1,
               "packages": [{"name": "Git", "version": "2.43", "manager": "windows"}]}
put("PACKAGES_FILE", store)
api.cve_scanner._osv_querybatch = lambda body: [{} for _ in body]      # no advisory service: nothing is found, nothing is fetched
spawned = []
api._spawn_cve_scan = lambda actor, target: spawned.append([actor, target])


def call(who, method, path, body=None):
    c = wsgi.application.test_client()
    kw = {"headers": {"X-Token": TOK[who]}}
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


def finish_the_scan(who):
    # what the runner does with the word it was started with
    actor, spec = spawned[-1]
    api._cve_scan_worker(actor, spec)
    api._invalidate_load_cache(api.CVE_FINDINGS_FILE)
    return sorted(api.load(api.CVE_FINDINGS_FILE))


out = {}
out["status_before_viewerA"] = call("viewerA", "GET", "/api/cve/scan-status")
out["adminA_scan"] = call("adminA", "POST", "/api/cve/scan")
out["spawned_for_A"] = list(spawned)
out["adminB_during"] = call("adminB", "POST", "/api/cve/scan")
out["status_during_viewerA"] = call("viewerA", "GET", "/api/cve/scan-status")
out["status_during_adminB"] = call("adminB", "GET", "/api/cve/scan-status")
out["status_during_op"] = call("op", "GET", "/api/cve/scan-status")
out["marker_during"] = sorted(marker())
out["findings_after_A"] = finish_the_scan("adminA")
out["status_after_viewerA"] = call("viewerA", "GET", "/api/cve/scan-status")
out["status_after_adminB"] = call("adminB", "GET", "/api/cve/scan-status")
out["status_after_op"] = call("op", "GET", "/api/cve/scan-status")

# the second start of one organisation, and the first of another
out["adminA_again"] = call("adminA", "POST", "/api/cve/scan")[0:2]
out["adminB_first"] = call("adminB", "POST", "/api/cve/scan")
finish_the_scan("adminB")
out["adminB_again"] = call("adminB", "POST", "/api/cve/scan")[0]
# thirty seconds later (the clock of the marker is turned back, so that the test does not wait)
st = marker()
st["starts"] = {k: v - 31 for k, v in (st.get("starts") or {}).items()}
st["running"] = False
put("CVE_SCAN_STATUS_FILE", st)
out["adminA_later"] = call("adminA", "POST", "/api/cve/scan")[0]
finish_the_scan("adminA")

# a scan of one host
st = marker()
st["starts"] = {}
put("CVE_SCAN_STATUS_FILE", dict(st, running=False))
out["adminA_own_host"] = call("adminA", "POST", "/api/cve/scan", {"device_id": "a1"})
out["spawned_for_own_host"] = spawned[-1]
finish_the_scan("adminA")
st = marker()
put("CVE_SCAN_STATUS_FILE", dict(st, running=False, starts={}))
out["adminA_foreign_host"] = call("adminA", "POST", "/api/cve/scan", {"device_id": "b1"})[0]

# the operator's scan
st = marker()
put("CVE_SCAN_STATUS_FILE", dict(st, running=False, starts={}))
out["op_scan"] = call("op", "POST", "/api/cve/scan")
out["spawned_for_op"] = spawned[-1]
put("CVE_FINDINGS_FILE", {})
out["findings_after_op"] = finish_the_scan("op")
out["op_again"] = call("op", "POST", "/api/cve/scan")[0]
print(json.dumps(out))
"""


def _run(tenancy):
    d = Path(tempfile.mkdtemp(prefix="rp-v802-ss-run-"))
    _TMP.append(d)
    (d / "driver.py").write_text(_DRIVER, encoding="utf-8")
    data = d / "data"
    data.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith(("REQUEST_", "HTTP_", "PATH_INFO", "QUERY_", "CONTENT_"))}
    env["RP_DATA_DIR"] = str(data)
    proc = subprocess.run([sys.executable, str(d / "driver.py"), str(_CGI), "on" if tenancy else "off"], capture_output=True,
                          text=True, env=env, timeout=600)
    if proc.returncode != 0:
        raise AssertionError("the driver failed:\n" + proc.stderr[-2500:])
    return json.loads(proc.stdout.strip().splitlines()[-1])


_PRIVATE = {"run", "owner", "starts"}


class TestWithTenancy(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        try:
            import flask  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("flask is not installed")
        cls.o = _run(True)

    def test_a_tenant_administrators_scan_is_queued_for_its_own_tenant(self):
        o = self.o
        self.assertEqual(o["adminA_scan"][0], 202)
        self.assertEqual(o["spawned_for_A"], [["adminA", "tenant:tenantA"]],
                         "None here is a scan of every host of every organisation")

    def test_its_answer_counts_its_own_hosts(self):
        self.assertEqual(self.o["adminA_scan"][1]["total"], 2, "A holds two package lists; the installation holds six")

    def test_the_worker_walks_the_hosts_of_that_tenant_only(self):
        self.assertEqual(self.o["findings_after_A"], ["a1"], "a2 is a Windows host (listed, not scanned); b1 to b3 and o1 are not A's")

    def test_the_numbers_of_a_scan_belong_to_the_organisation_that_started_it(self):
        o = self.o
        self.assertEqual(o["status_during_viewerA"][1]["total"], 2)
        self.assertEqual(o["status_after_viewerA"][1]["total"], 2)
        self.assertEqual((o["status_after_viewerA"][1]["scanned"], o["status_after_viewerA"][1]["skipped"]), (1, 1))
        self.assertTrue(_PRIVATE.isdisjoint(o["status_after_viewerA"][1]), "the marker's own bookkeeping is not part of the answer")

    def test_another_organisation_learns_that_a_scan_runs_and_nothing_else(self):
        o = self.o
        for name in ("status_during_adminB", "status_after_adminB"):
            keys = set(o[name][1])
            self.assertLessEqual(keys, {"running", "updated", "started_at", "finished_at"}, name)
            self.assertIn("running", keys)
        self.assertTrue(o["status_during_adminB"][1]["running"])
        self.assertFalse(o["status_after_adminB"][1]["running"])

    def test_the_refusal_of_a_start_carries_the_same_reduced_view(self):
        o = self.o
        self.assertEqual(o["adminB_during"][0], 409)
        self.assertLessEqual(set(o["adminB_during"][1]["status"]), {"running", "updated", "started_at", "finished_at"})
        for name in ("total", "done", "scanned", "owner", "starts", "run"):
            self.assertNotIn(name, o["adminB_during"][1]["status"])

    def test_the_operator_reads_the_numbers_of_every_scan(self):
        o = self.o
        self.assertEqual(o["status_during_op"][1]["total"], 2)
        self.assertTrue(_PRIVATE.isdisjoint(o["status_during_op"][1]))

    def test_an_organisation_can_start_a_scan_every_thirty_seconds(self):
        o = self.o
        self.assertEqual(o["adminA_again"][0], 429)
        self.assertEqual(o["adminA_again"][1]["error"], "Your last scan started a moment ago. Try again shortly.")
        self.assertLessEqual(o["adminA_again"][1]["retry_after_seconds"], 30)
        self.assertGreater(o["adminA_again"][1]["retry_after_seconds"], 0)
        self.assertEqual(o["adminA_later"], 202)

    def test_the_clock_of_one_organisation_is_not_anothers(self):
        o = self.o
        self.assertEqual(o["adminB_first"][0], 202, "B had not started one: A's start does not hold B back")
        self.assertEqual(o["adminB_again"], 429)

    def test_a_scan_of_one_host_is_for_a_host_of_its_own_organisation(self):
        o = self.o
        self.assertEqual(o["adminA_own_host"][0], 202)
        self.assertEqual(o["adminA_own_host"][1]["total"], 1)
        self.assertEqual(o["spawned_for_own_host"], ["adminA", "a1"])
        # 8.0.2: a host of another tenant is answered as a host that does not exist (404 "Host not found"), not 403 (tests/test_v802_host_of_another_tenant_is_not_found.py)
        self.assertEqual(o["adminA_foreign_host"], 404)

    def test_the_operators_scan_covers_every_host_and_is_not_held_back(self):
        o = self.o
        self.assertEqual(o["op_scan"][0], 202)
        self.assertEqual(o["op_scan"][1]["total"], 6)
        self.assertEqual(o["spawned_for_op"], ["op", None])
        self.assertEqual(o["findings_after_op"], ["a1", "b1", "b2", "b3", "o1"])
        self.assertEqual(o["op_again"], 202, "the cool-down is a limit on organisations that share the operator's installation")


class TestWithoutTenancy(unittest.TestCase):
    """An installation without tenancy has one organisation: nothing changes."""

    @classmethod
    def setUpClass(cls):
        try:
            import flask  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("flask is not installed")
        cls.o = _run(False)

    def test_every_administrator_scans_every_host_and_reads_every_number(self):
        o = self.o
        self.assertEqual(o["adminA_scan"][0], 202)
        self.assertEqual(o["adminA_scan"][1]["total"], 6)
        self.assertEqual(o["spawned_for_A"], [["adminA", None]])
        self.assertEqual(o["status_during_adminB"][1]["total"], 6)
        self.assertTrue(_PRIVATE.isdisjoint(o["status_during_adminB"][1]))

    def test_there_is_no_cool_down(self):
        o = self.o
        self.assertEqual(o["adminA_again"][0], 202)
        self.assertEqual(o["adminB_again"], 202)


if __name__ == "__main__":
    unittest.main()

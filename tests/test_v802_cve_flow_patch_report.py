#!/usr/bin/env python3
"""A total that adds up a store must add up the caller's part of it.

`GET /api/patch-report` lists the hosts the caller can see, each with the number of critical and high findings a pending patch would fix,
and sums them into `summary.cve_fixable_total`. The hosts were filtered; the sum was `sum(_cve_fixable_by_device().values())`, and that
map is built from the whole findings store, so a tenant's viewer was handed the fixable findings of every organisation's hosts as one
number (18 where its own four hosts held 6), and could subtract its own to get the other organisations'. The Prometheus scrape of a
signed-in user (`GET /api/metrics`) carries the same total and had the same sum.

What this holds, on the real WSGI app with real API keys (a process of its own, nothing stubbed):

* the total of the patch report is the sum of the per-host figures the same report lists, for a tenant's viewer, a tenant's
  administrator and the operator, who sees every host;
* the scrape of a signed-in tenant user carries its own organisation's total, and the operator's the whole installation's;
* the function takes the hosts to count, and counts only those.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v802-pr-"))
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
_TMP = []


def tearDownModule():
    import shutil
    for d in _TMP:
        shutil.rmtree(d, ignore_errors=True)


_DRIVER = r"""
import json, re, sys, time
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
                   "viewerA": {"role": "viewer", "tenant_id": "tenantA", "created": 1},
                   "adminB": {"role": "admin", "tenant_id": "tenantB", "created": 1}})
put("APIKEYS_FILE", {"k1": key("T-OP", "op", "admin", "default"), "k2": key("T-ADMIN-A", "adminA", "admin", "tenantA"),
                     "k3": key("T-VIEWER-A", "viewerA", "viewer", "tenantA"), "k4": key("T-ADMIN-B", "adminB", "admin", "tenantB")})
TOK = {"op": "T-OP", "adminA": "T-ADMIN-A", "viewerA": "T-VIEWER-A", "adminB": "T-ADMIN-B"}


def host(dev_id, name, tenant):
    rec = {"name": name, "hostname": name, "os": "Debian 12", "monitored": True, "last_seen": now, "token": "T-" + dev_id,
           "group": "g", "ip": "10.0.0.1", "sysinfo": {"packages": {"upgradable": 3}}}
    if tenant:
        rec["tenant"] = tenant
    return rec


HOSTS = {"alpha-1": host("alpha-1", "ALPHA-1", "tenantA"), "alpha-2": host("alpha-2", "ALPHA-2", "tenantA"),
         "bravo-1": host("bravo-1", "BRAVO-1", "tenantB"), "bravo-2": host("bravo-2", "BRAVO-2", "tenantB"),
         "op-1": host("op-1", "OP-1", None), "op-2": host("op-2", "OP-2", None)}
put("DEVICES_FILE", HOSTS)


def finding(n, sev="critical"):
    return {"package": "openssl", "version": "3.0.11-1", "vuln_id": "CVE-2024-%d" % n, "severity": sev, "fix_status": "fixed",
            "fixed_version": "3.0.15", "aliases": []}


put("CVE_FINDINGS_FILE", {h: {"scanned_at": now, "ecosystem": "Debian:12",
                              "findings": [finding(1), finding(2), finding(3), finding(4, "medium")]} for h in HOSTS})


def call(who, path):
    r = wsgi.application.test_client().get(path, headers={"X-Token": TOK[who]})
    return r.status_code, r.data.decode("utf-8", "replace")


out = {}
for who in ("viewerA", "adminA", "adminB", "op"):
    st, text = call(who, "/api/patch-report")
    rep = json.loads(text)
    out[who] = {"status": st, "hosts": sorted(d["device_id"] if "device_id" in d else d["id"] for d in rep["devices"]),
                "listed_sum": sum(d.get("cve_fixable") or 0 for d in rep["devices"]),
                "total": rep["summary"]["cve_fixable_total"]}
    st, text = call(who, "/api/metrics")
    m = re.search(r"^remotepower_cve_fixable_total (\d+)", text, re.M)
    out[who]["metrics_status"] = st
    out[who]["metrics_total"] = int(m.group(1)) if m else None

api._invalidate_load_cache(api.CVE_FINDINGS_FILE)


def fn(*args):
    try:
        return api._cve_fixable_by_device(*args)
    except TypeError as e:          # the function before 8.0.2 takes no hosts
        return "TypeError: " + str(e)


out["fn_all"] = fn()
out["fn_some"] = fn({"alpha-1": {}, "bravo-2": {}, "nobody": {}})
out["fn_set"] = fn({"alpha-2"})
out["fn_none"] = fn(set())
print(json.dumps(out))
"""


class TestOnTheRealStack(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        try:
            import flask  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("flask is not installed")
        d = Path(tempfile.mkdtemp(prefix="rp-v802-pr-run-"))
        _TMP.append(d)
        (d / "driver.py").write_text(_DRIVER, encoding="utf-8")
        data = d / "data"
        data.mkdir()
        env = {k: v for k, v in os.environ.items() if not k.startswith(("REQUEST_", "HTTP_", "PATH_INFO", "QUERY_", "CONTENT_"))}
        env["RP_DATA_DIR"] = str(data)
        proc = subprocess.run([sys.executable, str(d / "driver.py"), str(_CGI)], capture_output=True, text=True, env=env, timeout=600)
        if proc.returncode != 0:
            raise AssertionError("the driver failed:\n" + proc.stderr[-2500:])
        cls.o = json.loads(proc.stdout.strip().splitlines()[-1])

    def test_each_caller_is_listed_its_own_hosts(self):
        o = self.o
        self.assertEqual(o["viewerA"]["hosts"], ["alpha-1", "alpha-2"])
        self.assertEqual(o["adminB"]["hosts"], ["bravo-1", "bravo-2"])
        self.assertEqual(len(o["op"]["hosts"]), 6, "the operator sees every host")

    def test_the_total_is_the_sum_of_the_figures_the_report_lists(self):
        o = self.o
        for who in ("viewerA", "adminA", "adminB", "op"):
            self.assertEqual(o[who]["status"], 200, who)
            self.assertEqual(o[who]["total"], o[who]["listed_sum"],
                             "%s: the total adds up hosts the report does not list" % who)
        self.assertEqual((o["viewerA"]["total"], o["adminB"]["total"], o["op"]["total"]), (6, 6, 18))

    def test_the_scrape_of_a_signed_in_user_carries_its_own_total(self):
        o = self.o
        for who in ("viewerA", "adminA", "adminB", "op"):
            self.assertEqual(o[who]["metrics_status"], 200, who)
        self.assertEqual((o["viewerA"]["metrics_total"], o["adminA"]["metrics_total"], o["adminB"]["metrics_total"]), (6, 6, 6))
        self.assertEqual(o["op"]["metrics_total"], 18)

    def test_the_function_counts_the_hosts_it_is_given(self):
        o = self.o
        self.assertEqual(sorted(o["fn_all"]), ["alpha-1", "alpha-2", "bravo-1", "bravo-2", "op-1", "op-2"])
        self.assertEqual(o["fn_some"], {"alpha-1": 3, "bravo-2": 3}, "a host that is not in the findings store is not an entry")
        self.assertEqual(o["fn_set"], {"alpha-2": 3})
        self.assertEqual(o["fn_none"], {}, "an empty set of hosts is no host, not every host")


if __name__ == "__main__":
    unittest.main()

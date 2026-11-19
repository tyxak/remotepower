#!/usr/bin/env python3
"""Every reader of the accepted-risk store asks for the tenant of the host it is deciding about.

A record that a tenant's user writes carries the tenant (7.0.3), and `checks.cve_ignore_applies` lets it reach that tenant's hosts only.
It errs toward showing a finding when the host's tenant is not given. `cve_scanner.apply_ignore_list` takes the tenant as an
optional fourth argument, and none of its nine callers passed it, so under multi-tenancy a tenant's accepted risk applied on the CVE
page and the sidebar badge (which go through `cve_ignore_applies` with the host) and nowhere else: the host's own page showed the
finding as open, Needs attention, the risk score, the compliance control, the fleet report, the timeline, the campaigns and the SBOM
counted it. Found while counting the readers of the store for the 8.0.2 review: 0 of 9 asked.

What this holds:

* on the real WSGI app with real API keys, a tenant's accepted risk is applied by the host page, Needs attention, the fleet report and
  the risk score for that tenant's hosts, and not for another tenant's;
* a syntax-tree census of every call of `apply_ignore_list` and `decorated_cve_findings`: each names the host's tenant. The count of
  sites is asserted, so a scan that finds none cannot pass.
"""
import ast
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v802-ht-"))
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


put("CONFIG_FILE", {"tenancy_enforced": True})
put("TENANTS_FILE", {"tenantA": {"name": "Tenant A"}, "tenantB": {"name": "Tenant B"}})
put("USERS_FILE", {"adminA": {"role": "admin", "tenant_id": "tenantA", "created": 1},
                   "adminB": {"role": "admin", "tenant_id": "tenantB", "created": 1}})
put("APIKEYS_FILE", {"k2": key("T-ADMIN-A", "adminA", "admin", "tenantA"), "k4": key("T-ADMIN-B", "adminB", "admin", "tenantB")})
TOK = {"adminA": "T-ADMIN-A", "adminB": "T-ADMIN-B"}
HOST = {"adminA": "alpha-host-1", "adminB": "bravo-host-1"}


def host(dev_id, name, tenant):
    return {"name": name, "hostname": name, "os": "Debian 12", "monitored": True, "last_seen": now, "token": "T-" + dev_id,
            "group": "g", "ip": "10.0.0.1", "tenant": tenant}


put("DEVICES_FILE", {"alpha-host-1": host("alpha-host-1", "ALPHA-WEB-1", "tenantA"),
                     "bravo-host-1": host("bravo-host-1", "BRAVO-WEB-1", "tenantB")})
put("PACKAGES_FILE", {d: {"hash": "h", "collected_at": now, "ecosystem": "Debian:12", "pkg_manager": "apt", "count": 1,
                          "packages": [{"name": "openssl", "version": "3.0.11-1", "source": "openssl", "source_version": "3.0.11-1"}],
                          "os_id": "debian", "version_id": "12", "sources": True} for d in ("alpha-host-1", "bravo-host-1")})
put("CVE_FINDINGS_FILE", {d: {"scanned_at": now, "ecosystem": "Debian:12", "findings": [
    {"package": "openssl", "version": "3.0.11-1", "vuln_id": "CVE-2024-6387", "severity": "critical", "fix_status": "fixed",
     "fixed_version": "3.0.15", "aliases": []}]} for d in ("alpha-host-1", "bravo-host-1")})


def call(who, method, path, body=None):
    c = wsgi.application.test_client()
    kw = {"headers": {"X-Token": TOK[who]}}
    if body is not None:
        kw["data"] = json.dumps(body)
        kw["content_type"] = "application/json"
    r = getattr(c, method.lower())(path, **kw)
    try:
        return r.status_code, json.loads(r.data.decode("utf-8", "replace"))
    except ValueError:
        return r.status_code, None


out = {}
out["accept"] = call("adminA", "POST", "/api/cve/ignore", {"vuln_id": "CVE-2024-6387", "reason": "alpha accepts", "scope": "global"})[0]
for who in ("adminA", "adminB"):
    row = {}
    st, d = call(who, "GET", "/api/devices/%s/cve" % HOST[who])
    row["host_page"] = [[f["vuln_id"], f.get("ignored"), f.get("ignore_reason")] for f in d["findings"]]
    st, a = call(who, "GET", "/api/attention")
    row["attention_cve_items"] = [i["summary"] for i in a["items"] if i.get("kind") == "cve"]
    st, rep = call(who, "GET", "/api/report/fleet")
    row["report_critical"] = rep["cve"]["critical"]
    st, rk = call(who, "GET", "/api/risk")
    row["risk_factors"] = sorted({f["kind"] for r in (rk.get("devices") or []) for f in r.get("factors", [])})
    out[who] = row
print(json.dumps(out))
"""


class TestOnTheRealStack(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        try:
            import flask  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("flask is not installed")
        d = Path(tempfile.mkdtemp(prefix="rp-v802-ht-run-"))
        _TMP.append(d)
        (d / "driver.py").write_text(_DRIVER, encoding="utf-8")
        data = d / "data"
        data.mkdir()
        env = {k: v for k, v in os.environ.items() if not k.startswith(("REQUEST_", "HTTP_", "PATH_INFO", "QUERY_", "CONTENT_"))}
        env["RP_DATA_DIR"] = str(data)
        proc = subprocess.run([sys.executable, str(d / "driver.py"), str(_CGI)], capture_output=True, text=True, env=env, timeout=600)
        if proc.returncode != 0:
            raise AssertionError("the driver failed:\n" + proc.stderr[-2500:])
        cls.out = json.loads(proc.stdout.strip().splitlines()[-1])

    def test_setup_worked(self):
        self.assertEqual(self.out["accept"], 200)

    def test_the_host_page_shows_the_finding_as_accepted_for_the_tenant_that_accepted_it(self):
        self.assertEqual(self.out["adminA"]["host_page"], [["CVE-2024-6387", True, "alpha accepts"]],
                         "the CVE page counted the finding as accepted and the host's own page showed it open")

    def test_another_tenants_host_still_shows_it(self):
        self.assertEqual(self.out["adminB"]["host_page"], [["CVE-2024-6387", False, None]])

    def test_needs_attention_leaves_an_accepted_risk_out(self):
        self.assertEqual(self.out["adminA"]["attention_cve_items"], [])
        self.assertEqual(len(self.out["adminB"]["attention_cve_items"]), 1, "control: the other tenant's finding is not accepted")

    def test_the_fleet_report_leaves_an_accepted_risk_out(self):
        self.assertEqual(self.out["adminA"]["report_critical"], 0)
        self.assertEqual(self.out["adminB"]["report_critical"], 1)

    def test_the_risk_score_leaves_an_accepted_risk_out(self):
        self.assertNotIn("cve_critical", self.out["adminA"]["risk_factors"])
        self.assertIn("cve_critical", self.out["adminB"]["risk_factors"])


def _calls_named(name):
    """Every call of a function with this name in the server, as (file, line, positional count, keywords)."""
    found = []
    for path in sorted(_CGI.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                called = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
                if called == name:
                    found.append((path.name, node.lineno, len(node.args), {k.arg for k in node.keywords}))
    return found


class TestEveryCallNamesTheHostsTenant(unittest.TestCase):

    def test_the_population_was_found(self):
        sites = _calls_named("apply_ignore_list")
        self.assertGreaterEqual(len(sites), 9, "found %d call sites of apply_ignore_list: the scan is measuring nothing" % len(sites))
        self.assertGreaterEqual(len(_calls_named("decorated_cve_findings")), 2)

    def test_every_call_of_apply_ignore_list_passes_the_hosts_tenant(self):
        sites = _calls_named("apply_ignore_list")
        missing = [s for s in sites if s[2] < 4 and "dev_tenant" not in s[3]]
        self.assertEqual(missing, [], "%d of %d calls leave the tenant out, so a tenant's accepted risk does not apply there: %s"
                         % (len(missing), len(sites), missing))

    def test_every_call_of_decorated_cve_findings_passes_the_hosts_tenant(self):
        # `**kw` (a keyword whose name is None in the syntax tree) is a wrapper that hands on what its caller gave
        sites = _calls_named("decorated_cve_findings")
        missing = [s for s in sites if "dev_tenant" not in s[3] and None not in s[3]]
        self.assertEqual(missing, [], "calls that leave the tenant out: %s" % missing)


if __name__ == "__main__":
    unittest.main()

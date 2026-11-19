#!/usr/bin/env python3
"""A remediation campaign is one organisation's, and listing them costs what the findings cost, not what the findings cost times the campaigns.

Two defects of the campaign routes came out of the 8.0.2 review:

* the limit of 200 campaigns was `len(camps) >= 200` over the one store, so one tenant's administrator could make 200 and the operator
  and every other organisation were refused from then on ("campaign limit reached"), until the operator deleted another
  organisation's campaigns;
* every campaign walked every finding of every host the caller can see (`_campaign_affected`), once per campaign and once per
  opening of the CVE page: 200 campaigns over 60 hosts of 300 findings were 3.6 million visits and 5.5 seconds for the operator, and
  `apply_ignore_list` copied each finding for each campaign. The daily sample did the same.

What this holds, on the real WSGI app with real API keys (a process of its own, nothing stubbed):

* the limit is an organisation's own: when one holds its limit the others can still make a campaign, the operator's count includes the
  campaigns of the installation that carry no tenant, and replacing nothing counts nothing;
* the operator is shown who owns each row, a tenant is not shown a field it has no use for, and an installation without tenancy sees
  the rows it always did;
* a list is answered from tallies: the ignore rule runs once per host for a list of 30 campaigns, not 30 times;
* the tallies answer what a walk of the findings answered, for every shape of campaign (a list of ids with aliases and lower-case
  spelling, severities, all severities, known-exploited only), over several organisations' hosts, with accepted risks and a
  known-exploited list: random data against the walk, and the daily sample against the same walk per organisation.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v802-cp-"))
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
import cve_fixes  # noqa: E402

_TMP = []


def tearDownModule():
    import shutil
    for d in _TMP:
        shutil.rmtree(d, ignore_errors=True)


_DRIVER = r"""
import json, random, sys, time
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
rng = random.Random(20261119)
OWNER = {}
devices = {}
for i in range(18):
    tenant = ("tenantA", "tenantB", None)[i % 3]
    rec = {"name": "H%d" % i, "hostname": "h%d" % i, "os": "Debian 12", "monitored": True, "last_seen": now, "token": "T-h%d" % i,
           "group": "g", "ip": "10.0.0.1"}
    if tenant:
        rec["tenant"] = tenant
    devices["h%d" % i] = rec
put("DEVICES_FILE", devices)
IDS = ["DEBIAN-CVE-2024-%d" % n for n in range(40)]
SEV = ["critical", "high", "medium", "low", "unknown", "CRITICAL", "", None, "odd"]
cve_all = {}
for h in devices:
    findings = []
    for k in range(25):
        vid = rng.choice(IDS)
        f = {"package": "pkg%d" % rng.randrange(6), "version": "1.0", "vuln_id": vid, "severity": rng.choice(SEV),
             "aliases": ["CVE-2024-%s" % vid.rsplit("-", 1)[1]] + (["GHSA-%d" % rng.randrange(9)] if rng.random() < 0.3 else [])}
        if rng.random() < 0.1:
            f["cve_id"] = "cve-2024-%d" % rng.randrange(40)
        if rng.random() < 0.05:
            f["id"] = IDS[rng.randrange(40)].lower()
        if rng.random() < 0.1:
            f["kev"] = True
        if rng.random() < 0.05:
            f["known_exploited"] = True
        findings.append(f)
    cve_all[h] = {"scanned_at": now, "ecosystem": "Debian:12", "findings": findings}
put("CVE_FINDINGS_FILE", cve_all)
ignores = {IDS[0]: {"scope": "global", "reason": "r", "actor": "op", "ts": 1},
           IDS[1]: {"scope": "h1", "reason": "r", "actor": "op", "ts": 1},
           IDS[2]: {"scope": "global", "tenant": "tenantA", "reason": "r", "actor": "adminA", "ts": 1,
                    "others": [{"scope": "global", "tenant": "tenantB", "reason": "r", "actor": "adminB", "ts": 1}]}}
put("CVE_IGNORE_FILE", ignores)
KEV = {IDS[3].upper(), "CVE-2024-4", "GHSA-1"}


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


out = {}
# 1. the limit is an organisation's own
api.cve_handlers_mod.MAX_CAMPAIGNS_PER_OWNER = 4
put("CVE_CAMPAIGNS_FILE", {"campaigns": [
    {"id": "camp_legacy1", "name": "legacy one", "cve_ids": [], "severities": ["critical"], "created_at": 1, "samples": []},
    {"id": "camp_legacy2", "name": "legacy two", "cve_ids": [], "severities": ["high"], "created_at": 2, "samples": []}]})
make = lambda who, n: call(who, "POST", "/api/cve/campaigns", {"name": "c-%s-%d" % (who, n), "severities": ["critical", "high"]})
out["A_makes"] = [make("adminA", n)[0] for n in range(6)]
out["B_makes_after_A_is_full"] = [make("adminB", n)[0] for n in range(6)]
out["op_makes_after_both"] = [make("op", n)[0] for n in range(4)]
out["limit_message"] = make("adminA", 99)[1]
api.cve_handlers_mod.MAX_CAMPAIGNS_PER_OWNER = 200

# 2. what the lists show
rows_op = call("op", "GET", "/api/cve/campaigns")[1]["campaigns"]
rows_a = call("adminA", "GET", "/api/cve/campaigns")[1]["campaigns"]
out["op_rows"] = len(rows_op)
out["op_row_owners"] = sorted({r.get("tenant") for r in rows_op if r.get("tenant")})
out["op_legacy_rows_have_no_owner"] = all("tenant" not in r for r in rows_op if r["id"].startswith("camp_legacy"))
out["a_rows_have_an_owner_field"] = any("tenant" in r for r in rows_a)
out["a_rows"] = len(rows_a)

# 3. the work of a list: the ignore rule runs once per host, not once per host and campaign
store = api.load(api.CVE_CAMPAIGNS_FILE)
store["campaigns"] = [{"id": "camp_w%d" % n, "name": "w%d" % n, "cve_ids": [], "severities": ["critical"], "created_at": n,
                       "samples": [], "tenant": None} for n in range(30)]
put("CVE_CAMPAIGNS_FILE", store)
real = api.cve_scanner.apply_ignore_list
calls = {"n": 0}


def counting(*a, **k):
    calls["n"] += 1
    return real(*a, **k)


api.cve_scanner.apply_ignore_list = counting
rows = call("op", "GET", "/api/cve/campaigns")[1]["campaigns"]
api.cve_scanner.apply_ignore_list = real
out["list_rows"] = len(rows)
out["ignore_rule_calls_for_a_list"] = calls["n"]
out["hosts"] = len(devices)


# 4. the tallies against the walk
def walk(camp, hosts_map):
    hosts, count = set(), 0
    for did, rec in cve_all.items():
        if did not in hosts_map:
            continue
        for f in real((rec or {}).get("findings") or [], ignores, did, api._device_tenant(hosts_map.get(did))):
            if f.get("ignored"):
                continue
            if api._campaign_matches_finding(camp, f, KEV):
                count += 1
                hosts.add(did)
    return sorted(hosts), count


def shapes():
    out_ = []
    for _ in range(80):
        pick = rng.random()
        if pick < 0.35:
            wanted = [rng.choice(IDS + [i.lower() for i in IDS] + ["CVE-2024-%d" % rng.randrange(40), "GHSA-%d" % rng.randrange(9), "nothing"])
                      for _ in range(rng.randrange(1, 5))]
            out_.append({"cve_ids": wanted, "severities": rng.sample(["critical", "high"], rng.randrange(0, 3)), "kev_only": rng.random() < 0.5})
        else:
            sevs = rng.sample(["critical", "high", "medium", "low"], rng.randrange(0, 5))
            out_.append({"cve_ids": [], "severities": sevs, "kev_only": rng.random() < 0.4})
    out_ += [{"cve_ids": [], "severities": [], "kev_only": False}, {"cve_ids": [], "severities": [], "kev_only": True},
             {"cve_ids": [7, None, "x"], "severities": [], "kev_only": False}]
    return out_


def section(fn):
    try:
        fn()
    except Exception as e:      # the code before 8.0.2 has no index: say that, and let the other sections answer
        out["missing_" + fn.__name__] = repr(e)
    return fn


@section
def equivalence():
    mismatches, checked = [], 0
    subsets = {"all": devices, "A": {k: v for k, v in devices.items() if v.get("tenant") == "tenantA"},
               "B": {k: v for k, v in devices.items() if v.get("tenant") == "tenantB"},
               "operator": {k: v for k, v in devices.items() if not v.get("tenant")}}
    for name, subset in subsets.items():
        index = api._campaign_index(cve_all, ignores, subset, KEV)
        for camp in shapes():
            a = api._campaign_affected(camp, cve_all, ignores, subset, KEV, index)
            b = walk(camp, subset)
            checked += 1
            if (sorted(a[0]), a[1]) != (b[0], b[1]):
                mismatches.append([name, camp, [sorted(a[0]), a[1]], b])
    out["equivalence"] = {"checked": checked, "mismatches": mismatches[:3], "n_mismatches": len(mismatches)}
    out["equivalence_has_content"] = [sum(1 for _ in walk({"cve_ids": [], "severities": ["critical"], "kev_only": False}, devices)[0]),
                                      walk({"cve_ids": [], "severities": [], "kev_only": True}, devices)[1],
                                      walk({"cve_ids": [IDS[5]], "severities": []}, devices)[1]]



@section
def sample():
    # 5. the daily sample against the walk, per organisation
    camps = []
    for owner in ("tenantA", "tenantB", None):
        for n in range(3):
            camps.append({"id": "camp_s%s%d" % (owner or "op", n), "name": "s", "tenant": owner, "cve_ids": [IDS[n + 4]] if n == 0 else [],
                          "severities": ["critical"] if n == 1 else [], "kev_only": n == 2, "created_at": n, "completed_at": None, "samples": []})
    put("CVE_CAMPAIGNS_FILE", {"campaigns": camps})
    api._cve_kev_ids = lambda: KEV
    api.run_cve_campaign_sample_if_due()
    api._invalidate_load_cache(api.CVE_CAMPAIGNS_FILE)
    sampled = {c["id"]: c["samples"][-1]["affected"] for c in api.load(api.CVE_CAMPAIGNS_FILE)["campaigns"]}
    want = {}
    for c in camps:
        own = c["tenant"]
        hosts_map = devices if own is None else {k: v for k, v in devices.items() if v.get("tenant") == own}
        want[c["id"]] = len(walk(c, hosts_map)[0])
    out["sample"] = {"got": sampled, "want": want}

print(json.dumps(out))
"""


def _run(tenancy):
    d = Path(tempfile.mkdtemp(prefix="rp-v802-cp-run-"))
    _TMP.append(d)
    (d / "driver.py").write_text(_DRIVER, encoding="utf-8")
    data = d / "data"
    data.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith(("REQUEST_", "HTTP_", "PATH_INFO", "QUERY_", "CONTENT_"))}
    env["RP_DATA_DIR"] = str(data)
    proc = subprocess.run([sys.executable, str(d / "driver.py"), str(_CGI), "on" if tenancy else "off"], capture_output=True,
                          text=True, env=env, timeout=900)
    if proc.returncode != 0:
        raise AssertionError("the driver failed:\n" + proc.stderr[-2500:])
    return json.loads(proc.stdout.strip().splitlines()[-1])


class TestWithTenancy(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        try:
            import flask  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("flask is not installed")
        cls.o = _run(True)

    def test_one_organisation_holding_its_limit_does_not_stop_the_others(self):
        o = self.o
        self.assertEqual(o["A_makes"], [200, 200, 200, 200, 400, 400])
        self.assertEqual(o["B_makes_after_A_is_full"], [200, 200, 200, 200, 400, 400],
                         "tenant A used the installation's campaigns and tenant B was refused")

    def test_the_operators_count_includes_the_campaigns_of_the_installation(self):
        self.assertEqual(self.o["op_makes_after_both"], [200, 200, 400, 400], "two campaigns of the installation were there already")
        self.assertEqual(self.o["limit_message"], {"error": "campaign limit reached"})

    def test_the_operator_is_shown_who_owns_each_row(self):
        o = self.o
        self.assertEqual(o["op_row_owners"], ["tenantA", "tenantB"])
        self.assertTrue(o["op_legacy_rows_have_no_owner"])
        self.assertFalse(o["a_rows_have_an_owner_field"], "a tenant's rows carry no owner field")
        self.assertEqual(o["op_rows"], 4 + 4 + 2 + 2, "every organisation's rows, and the installation's two")
        self.assertEqual(o["a_rows"], 4 + 2 + 2, "its own four, and the four of the installation (two that were there, two the operator made)")

    def test_a_list_runs_the_ignore_rule_once_per_host(self):
        o = self.o
        self.assertEqual(o["list_rows"], 30)
        self.assertLessEqual(o["ignore_rule_calls_for_a_list"], o["hosts"],
                             "%d runs of the rule for 30 campaigns over %d hosts" % (o["ignore_rule_calls_for_a_list"], o["hosts"]))
        self.assertGreater(o["ignore_rule_calls_for_a_list"], 0, "control: the rule ran at all")

    def test_the_tallies_answer_what_a_walk_of_the_findings_answered(self):
        e = self.o["equivalence"]
        self.assertEqual(e["checked"], 4 * 83)
        self.assertEqual(e["n_mismatches"], 0, e["mismatches"])
        crit_hosts, kev_findings, one_id = self.o["equivalence_has_content"]
        self.assertGreater(crit_hosts, 3, "control: the data holds critical findings on several hosts")
        self.assertGreater(kev_findings, 0, "control: the data holds known-exploited findings")
        self.assertGreater(one_id, 0, "control: an id that is in the data is found")

    def test_the_daily_sample_counts_each_organisations_own_hosts_from_the_tallies(self):
        s = self.o["sample"]
        self.assertEqual(s["got"], s["want"])
        self.assertGreater(sum(s["want"].values()), 0, "control: some campaign has an affected host")


class TestWithoutTenancy(unittest.TestCase):
    """One organisation: the limit is the one it always was, and the rows carry no owner."""

    @classmethod
    def setUpClass(cls):
        try:
            import flask  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("flask is not installed")
        cls.o = _run(False)

    def test_the_limit_counts_every_campaign(self):
        o = self.o
        # two campaigns of the installation were there, so the one organisation has room for two more
        self.assertEqual(o["A_makes"], [200, 200, 400, 400, 400, 400])
        self.assertEqual(o["B_makes_after_A_is_full"], [400] * 6)
        self.assertEqual(o["op_makes_after_both"], [400] * 4)

    def test_the_rows_carry_no_owner(self):
        self.assertEqual(self.o["op_row_owners"], [])

    def test_the_tallies_answer_what_a_walk_answered(self):
        self.assertEqual(self.o["equivalence"]["n_mismatches"], 0)


class TestTheIndexAlone(unittest.TestCase):
    """cve_fixes.CampaignIndex with no api around it."""

    @staticmethod
    def _live():
        return [("h1", [{"vuln_id": "CVE-1", "severity": "critical", "aliases": ["GHSA-1"]}, {"vuln_id": "CVE-2", "severity": "high", "kev": True}]),
                ("h2", [{"vuln_id": "CVE-1", "severity": "critical"}, "junk", None]), ("h3", [])]

    def test_ids_match_by_alias_and_case_and_count_findings(self):
        idx = cve_fixes.CampaignIndex(self._live())
        self.assertEqual(idx.affected({"cve_ids": ["ghsa-1"]}), ({"h1"}, 1))
        self.assertEqual(idx.affected({"cve_ids": ["cve-1"]}), ({"h1", "h2"}, 2))
        self.assertEqual(idx.affected({"cve_ids": ["nope", 5]}), (set(), 0))

    def test_ids_win_over_severities(self):
        idx = cve_fixes.CampaignIndex(self._live())
        self.assertEqual(idx.affected({"cve_ids": ["CVE-2"], "severities": ["critical"], "kev_only": False}), ({"h1"}, 1))

    def test_severities_and_known_exploited(self):
        idx = cve_fixes.CampaignIndex(self._live(), kev={"CVE-1"})
        self.assertEqual(idx.affected({"severities": ["critical"]}), ({"h1", "h2"}, 2))
        self.assertEqual(idx.affected({"severities": ["high"]}), ({"h1"}, 1))
        self.assertEqual(idx.affected({"severities": [], "kev_only": True}), ({"h1", "h2"}, 3), "two by the list, one stamped on the finding")
        self.assertEqual(idx.affected({}), ({"h1", "h2"}, 3))

    def test_an_empty_set_of_hosts_affects_nothing(self):
        self.assertEqual(cve_fixes.CampaignIndex([]).affected({"severities": []}), (set(), 0))


if __name__ == "__main__":
    unittest.main()

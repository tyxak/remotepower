#!/usr/bin/env python3
"""The accepted-risk store: who may read a record, and what one organisation can do to another's.

`cve_ignore.json` is one map keyed by the id of the vulnerability, shared by every organisation. A record holds the host it names
(`scope`), a free-text reason, the account that wrote it and, for a tenant's, the tenant. Two defects came out of the 8.0.2 review:

* `GET /api/suppressions` ("why isn't this alerting?") listed every organisation's accepted risks, with the reason, to any signed-in
  user. The block read `meta['device_id']`, a key a record never holds, so its host filter passed every row, and it never asked the rule
  that the owning page uses (`_ignore_entry_visible`). The sweep that found it listed 28 functions that name the store, five of which
  hand a record's content to a caller; two of the five asked the rule.
* the store had one slot per id. The first organisation to accept an id made it impossible for every other one (the add answered 404),
  and the 404 told which ids were taken. An id was free text, and there was no limit on the records an organisation could hold.

An id that a second organisation accepts is kept beside the first record (`others`), so each organisation has a record of its own and
neither learns of the other's.

What this holds, on the real WSGI app with real API keys (a process of its own, nothing stubbed):

* the roll-up shows a caller its own organisation's records and no one else's, in the rows and anywhere in the answer;
* a second organisation can accept an id the first holds, each sees its own record, a delete lifts the caller's own and leaves the
  other, and a delete of an id nobody holds answers a tenant what a delete of someone else's does;
* an id that names no vulnerability is refused, and an organisation's records have a ceiling that is its own;
* two administrators who accept a risk at the same moment both have their record;
* a census, by syntax tree, of every function that names the store, each with the way it reads a record.
"""
import ast
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v802-ar-"))
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
import checks  # noqa: E402
import cve_scanner  # noqa: E402

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
                   "viewerA": {"role": "viewer", "tenant_id": "tenantA", "created": 1},
                   "adminB": {"role": "admin", "tenant_id": "tenantB", "created": 1}})
put("APIKEYS_FILE", {"k1": key("T-OP", "op", "admin", "default"), "k2": key("T-ADMIN-A", "adminA", "admin", "tenantA"),
                     "k3": key("T-VIEWER-A", "viewerA", "viewer", "tenantA"), "k4": key("T-ADMIN-B", "adminB", "admin", "tenantB")})
TOK = {"op": "T-OP", "adminA": "T-ADMIN-A", "viewerA": "T-VIEWER-A", "adminB": "T-ADMIN-B"}


def host(dev_id, name, tenant):
    rec = {"name": name, "hostname": name, "os": "Debian 12", "monitored": True, "last_seen": now, "token": "T-" + dev_id,
           "group": "g", "ip": "10.0.0.1"}
    if tenant:
        rec["tenant"] = tenant
    return rec


put("DEVICES_FILE", {"alpha-host-1": host("alpha-host-1", "ALPHA-WEB-1", "tenantA"),
                     "bravo-host-1": host("bravo-host-1", "BRAVO-WEB-1", "tenantB"),
                     "op-host-1": host("op-host-1", "OP-WEB-1", None)})


def finding(vid, sev="critical"):
    return {"package": "openssl", "version": "3.0.11-1", "vuln_id": vid, "severity": sev, "fix_status": "fixed",
            "fixed_version": "3.0.15", "aliases": []}


put("CVE_FINDINGS_FILE", {d: {"scanned_at": now, "ecosystem": "Debian:12",
                              "findings": [finding("CVE-2024-6387"), finding("CVE-2024-3094")]}
                          for d in ("alpha-host-1", "bravo-host-1", "op-host-1")})


def call(who, method, path, body=None):
    c = wsgi.application.test_client()
    kw = {"headers": {"X-Token": TOK[who]}}
    if body is not None:
        kw["data"] = json.dumps(body)
        kw["content_type"] = "application/json"
    r = getattr(c, method.lower())(path, **kw)
    text = r.data.decode("utf-8", "replace")
    try:
        return [r.status_code, json.loads(text), text]
    except ValueError:
        return [r.status_code, None, text]


def accept(who, vid, reason, scope="global"):
    r = call(who, "POST", "/api/cve/ignore", {"vuln_id": vid, "reason": reason, "scope": scope})
    return [r[0], r[1]]


def rows(who):
    r = call(who, "GET", "/api/cve/ignore")
    return sorted([[i["vuln_id"], i.get("reason"), i.get("scope")] for i in r[1]["ignores"]])


def roll_up(who):
    r = call(who, "GET", "/api/suppressions")
    got = [[s["label"], s["detail"], s["device_id"]] for s in r[1]["suppressions"] if s["kind"] == "cve_accepted"]
    return {"status": r[0], "rows": sorted(got), "text": r[2]}


def page(who):
    r = call(who, "GET", "/api/cve/findings")
    return {d["device_id"]: d["counts"]["ignored"] for d in r[1]["devices"]}


def store():
    api._invalidate_load_cache(api.CVE_IGNORE_FILE)
    return api.load(api.CVE_IGNORE_FILE)


out = {}
# 1. the roll-up
out["bravo_accepts"] = accept("adminB", "CVE-2024-3094", "bravo-secret: xz is only on BRAVO-WEB-1, the payroll batch breaks", "bravo-host-1")
out["operator_accepts"] = accept("op", "CVE-2023-4863", "operator-secret: accepted until the Q1 window, ticket OPS-4411")
out["alpha_accepts"] = accept("adminA", "CVE-2024-6387", "alpha-own: accepted for the web tier")
out["rollup_viewerA"] = roll_up("viewerA")
out["rollup_adminA"] = roll_up("adminA")
out["rollup_adminB"] = roll_up("adminB")
out["rollup_op"] = roll_up("op")
out["list_viewerA"] = rows("viewerA")

# 2. a second organisation accepts an id the first holds
out["bravo_same_id"] = accept("adminB", "CVE-2024-6387", "bravo-second: accepted for the bravo web tier", "bravo-host-1")
out["list_adminA"] = rows("adminA")
out["list_adminB"] = rows("adminB")
out["list_op"] = rows("op")
out["page_adminA"] = page("adminA")
out["page_adminB"] = page("adminB")
out["stored_under_the_id"] = store().get("CVE-2024-6387")
# 3. the answers of a delete: another organisation's id, an id nobody holds, and the operator's
out["bravo_deletes_the_operators"] = call("adminB", "DELETE", "/api/cve/ignore/CVE-2023-4863")[:2]
out["bravo_deletes_nobodys"] = call("adminB", "DELETE", "/api/cve/ignore/CVE-9999-0001")[:2]
out["operator_deletes_nobodys"] = call("op", "DELETE", "/api/cve/ignore/CVE-9999-0001")[:2]
# 4. a delete lifts the caller's own record and leaves the other organisation's
out["alpha_deletes"] = call("adminA", "DELETE", "/api/cve/ignore/CVE-2024-6387")[:2]
out["list_adminA_after"] = rows("adminA")
out["list_adminB_after"] = rows("adminB")
out["page_adminA_after"] = page("adminA")
out["page_adminB_after"] = page("adminB")
out["stored_after"] = store().get("CVE-2024-6387")
out["bravo_deletes_its_own"] = call("adminB", "DELETE", "/api/cve/ignore/CVE-2024-6387")[:2]
out["key_gone"] = "CVE-2024-6387" not in store()

# 5. what an id may look like
bad = ["CVE 2024 6387", "CVE-2024/6387", "../etc/passwd", "<script>", "-CVE-2024-1", "a b", "CVE-2024-1;rm", "CVE-2024-1\n2"]
out["bad_ids"] = {v: accept("adminA", v, "r")[0] for v in bad}
good = ["CVE-2024-3094", "DEBIAN-CVE-2024-3094", "GHSA-xxxx-xxxx-xxxx", "ALSA-2024:1234", "openSUSE-SU-2024:1234-1", "USN-6000-1",
        "RUSTSEC-2024-0001", "x" * 64]
out["good_ids"] = {v: accept("adminA", v, "r")[0] for v in good}
for v in good:
    call("adminA", "DELETE", "/api/cve/ignore/" + v)

# 6. a ceiling per organisation
api.cve_handlers_mod.MAX_IGNORES_PER_OWNER = 3
out["ceiling"] = [accept("adminA", "CAP-%d" % i, "r")[0] for i in range(5)]
out["ceiling_replace"] = accept("adminA", "CAP-0", "changed reason")[0]
out["ceiling_message"] = accept("adminA", "CAP-9", "r")[1]
out["ceiling_other_org"] = accept("adminB", "CAP-0", "r")[0]
out["ceiling_operator"] = accept("op", "CAP-0", "r")[0]
for i in range(5):
    call("adminA", "DELETE", "/api/cve/ignore/CAP-%d" % i)
call("adminB", "DELETE", "/api/cve/ignore/CAP-0")
call("op", "DELETE", "/api/cve/ignore/CAP-0")
api.cve_handlers_mod.MAX_IGNORES_PER_OWNER = 5000

# 7. two administrators accept a risk at the same moment. The save of this store is slowed, which makes the overlap certain for a
# handler that reads, then saves: a locked read-modify-write does not go through it.
real_save = api.save


def slow_save(path, data, *a, **k):
    if str(path).endswith("cve_ignore.json"):
        time.sleep(0.15)
    return real_save(path, data, *a, **k)


api.save = slow_save
ids = ["RACE-%02d" % i for i in range(8)]
res = []


def go(i):
    who = "adminA" if i % 2 == 0 else "adminB"
    res.append(accept(who, ids[i], "race %d" % i)[0])


ts = [threading.Thread(target=go, args=(i,)) for i in range(8)]
for t in ts:
    t.start()
for t in ts:
    t.join()
api.save = real_save
api._invalidate_load_cache(api.CVE_IGNORE_FILE)
out["race_answers"] = sorted(res)
out["race_kept"] = sorted(i for i in ids if i in store())
print(json.dumps(out))
"""


class TestOnTheRealStack(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        try:
            import flask  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("flask is not installed")
        d = Path(tempfile.mkdtemp(prefix="rp-v802-ar-run-"))
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

    # ── the roll-up ──────────────────────────────────────────────────────────────────────────────────────────
    def test_setup_worked(self):
        for name in ("bravo_accepts", "operator_accepts", "alpha_accepts"):
            self.assertEqual(self.out[name][0], 200, name)

    def test_the_roll_up_shows_a_user_the_records_of_its_own_organisation(self):
        o = self.out
        self.assertEqual(o["rollup_viewerA"]["rows"], [["CVE-2024-6387", "Accepted risk — alpha-own: accepted for the web tier", ""]])
        self.assertEqual(o["rollup_adminA"]["rows"], o["rollup_viewerA"]["rows"])
        self.assertEqual([r[0] for r in o["rollup_adminB"]["rows"]], ["CVE-2024-3094"])
        self.assertEqual(o["rollup_adminB"]["rows"][0][2], "bravo-host-1")

    def test_no_other_organisations_text_is_anywhere_in_the_answer(self):
        text = self.out["rollup_viewerA"]["text"] + self.out["rollup_adminA"]["text"]
        for marker in ("bravo", "BRAVO", "operator-secret", "OPS-4411", "CVE-2023-4863", "CVE-2024-3094"):
            self.assertNotIn(marker, text, "the roll-up carried %r to another organisation's user" % marker)

    def test_the_operator_sees_every_record(self):
        self.assertEqual(sorted(r[0] for r in self.out["rollup_op"]["rows"]), ["CVE-2023-4863", "CVE-2024-3094", "CVE-2024-6387"])

    def test_the_owning_page_and_the_roll_up_agree(self):
        self.assertEqual([r[0] for r in self.out["list_viewerA"]], ["CVE-2024-6387"])

    # ── a second organisation accepts an id the first holds ──────────────────────────────────────────────────
    def test_an_id_another_organisation_holds_can_be_accepted(self):
        self.assertEqual(self.out["bravo_same_id"][0], 200, "a refusal tells this organisation that another one holds the id")

    def test_each_organisation_sees_its_own_record_of_the_id(self):
        o = self.out
        self.assertEqual(o["list_adminA"], [["CVE-2024-6387", "alpha-own: accepted for the web tier", "global"]])
        self.assertEqual(o["list_adminB"], [["CVE-2024-3094", "bravo-secret: xz is only on BRAVO-WEB-1, the payroll batch breaks", "bravo-host-1"],
                                            ["CVE-2024-6387", "bravo-second: accepted for the bravo web tier", "bravo-host-1"]])
        self.assertEqual(len([r for r in o["list_op"] if r[0] == "CVE-2024-6387"]), 2, "the operator reads both records")

    def test_the_first_record_is_kept_as_it_was_and_the_second_is_beside_it(self):
        held = self.out["stored_under_the_id"]
        recs = checks.cve_ignore_records(held)
        self.assertEqual(sorted(r["tenant"] for r in recs), ["tenantA", "tenantB"])
        self.assertEqual(held["reason"], "alpha-own: accepted for the web tier")

    def test_each_record_applies_to_its_own_organisations_hosts_only(self):
        o = self.out
        self.assertEqual(o["page_adminA"]["alpha-host-1"], 1, "A accepted CVE-2024-6387")
        self.assertEqual(o["page_adminB"]["bravo-host-1"], 2, "B accepted CVE-2024-3094 and CVE-2024-6387")
        self.assertNotIn("bravo-host-1", o["page_adminA"])

    # ── the answers of a delete ──────────────────────────────────────────────────────────────────────────────
    def test_a_delete_of_an_id_a_tenant_cannot_see_and_of_one_nobody_holds_answer_alike(self):
        o = self.out
        self.assertEqual(o["bravo_deletes_the_operators"], [404, {"error": "Not found"}])
        self.assertEqual(o["bravo_deletes_nobodys"], o["bravo_deletes_the_operators"],
                         "a different answer for a free id tells a tenant which ids other organisations hold")

    def test_the_operator_keeps_the_answer_of_an_idempotent_delete(self):
        self.assertEqual(self.out["operator_deletes_nobodys"], [200, {"ok": True}])

    def test_a_delete_lifts_the_callers_record_and_leaves_the_other_organisations(self):
        o = self.out
        self.assertEqual(o["alpha_deletes"], [200, {"ok": True}])
        self.assertEqual(o["list_adminA_after"], [])
        self.assertEqual([r[0] for r in o["list_adminB_after"]], ["CVE-2024-3094", "CVE-2024-6387"])
        self.assertEqual(o["page_adminB_after"]["bravo-host-1"], 2, "B's records still apply")
        self.assertEqual(o["page_adminA_after"]["alpha-host-1"], 0, "A's record is gone, so its host shows the finding again")
        self.assertEqual(o["stored_after"]["tenant"], "tenantB")
        self.assertNotIn("others", o["stored_after"])

    def test_the_last_record_under_an_id_takes_the_key_with_it(self):
        self.assertEqual(self.out["bravo_deletes_its_own"], [200, {"ok": True}])
        self.assertTrue(self.out["key_gone"])

    # ── what an id may look like, and how many an organisation may hold ──────────────────────────────────────
    def test_an_id_that_names_no_vulnerability_is_refused(self):
        self.assertEqual(len(self.out["bad_ids"]), 8)
        for value, status in self.out["bad_ids"].items():
            self.assertEqual(status, 400, repr(value))

    def test_the_ids_of_the_advisory_databases_are_accepted(self):
        self.assertEqual(len(self.out["good_ids"]), 8)
        for value, status in self.out["good_ids"].items():
            self.assertEqual(status, 200, repr(value))

    def test_an_organisation_has_a_ceiling_of_its_own(self):
        o = self.out
        self.assertEqual(o["ceiling"], [200, 200, 200, 400, 400])
        self.assertEqual(o["ceiling_replace"], 200, "replacing a record adds none")
        self.assertEqual(o["ceiling_message"]["error"], "Too many accepted risks. Remove some first.")
        self.assertEqual(o["ceiling_other_org"], 200, "the count of one organisation is not another's")
        self.assertEqual(o["ceiling_operator"], 200)

    def test_two_administrators_who_accept_at_the_same_moment_both_keep_their_record(self):
        self.assertEqual(self.out["race_answers"], [200] * 8)
        self.assertEqual(self.out["race_kept"], ["RACE-%02d" % i for i in range(8)],
                         "a read, then a save, loses the record of whoever saved first")


class TestTheRecordsOfOneId(unittest.TestCase):
    """The pure functions: no store, no request."""

    def test_a_value_that_never_had_a_second_owner_is_the_record_alone(self):
        rec = {"scope": "global", "reason": "r"}
        self.assertEqual(checks.cve_ignore_records(rec), [rec])

    def test_anything_that_is_not_a_map_is_no_record(self):
        for junk in (None, "x", 4, [], [{"scope": "global"}], True):
            self.assertEqual(checks.cve_ignore_records(junk), [])
            self.assertFalse(checks.cve_ignore_applies(junk, "d1", "t1"))

    def test_the_others_list_is_read_defensively(self):
        rec = {"scope": "global", "tenant": "t1", "others": [{"scope": "global", "tenant": "t2"}, "x", None, 3, ["y"]]}
        self.assertEqual([r.get("tenant") for r in checks.cve_ignore_records(rec)], ["t1", "t2"])
        for junk in ("x", 5, {"scope": "global"}, None):
            self.assertEqual(len(checks.cve_ignore_records({"scope": "global", "others": junk})), 1)

    def test_a_finding_is_accepted_when_any_record_of_its_hosts_organisation_applies(self):
        held = {"scope": "global", "tenant": "t1", "reason": "one", "others": [{"scope": "d2", "tenant": "t2", "reason": "two"}]}
        self.assertTrue(checks.cve_ignore_applies(held, "d1", "t1"))
        self.assertTrue(checks.cve_ignore_applies(held, "d2", "t2"))
        self.assertFalse(checks.cve_ignore_applies(held, "d3", "t2"), "t2 accepted the risk for d2 only")
        self.assertFalse(checks.cve_ignore_applies(held, "d1", "t3"))
        self.assertFalse(checks.cve_ignore_applies(held, "d1", None), "an unknown tenant errs toward showing the finding")

    def test_a_host_shows_the_reason_of_its_own_organisations_record(self):
        held = {"scope": "global", "tenant": "t1", "reason": "one", "others": [{"scope": "global", "tenant": "t2", "reason": "two"}]}
        findings = [{"vuln_id": "CVE-1"}]
        got = cve_scanner.apply_ignore_list(findings, {"CVE-1": held}, "d9", "t2")
        self.assertEqual((got[0]["ignored"], got[0]["ignore_reason"]), (True, "two"))
        got = cve_scanner.apply_ignore_list(findings, {"CVE-1": held}, "d9", "t1")
        self.assertEqual(got[0]["ignore_reason"], "one")
        got = cve_scanner.apply_ignore_list(findings, {"CVE-1": held}, "d9", "t3")
        self.assertFalse(got[0]["ignored"])


# ── the census ───────────────────────────────────────────────────────────────────────────────────────────────
# Every function of the server that names CVE_IGNORE_FILE (a name in the code, not a word in a docstring), with the way it reads a
# record. A reader that hands a record's content (reason, account, host) to a caller must ask which records that caller may see; a
# reader that decides whether a finding is accepted must go through a rule that knows the records of several organisations. Found at
# 8.0.2 by listing them: 28 functions, five that show content, two of the five that asked.
SHOWS = "shows a record's content to the caller: asks which records the caller may see"
DECIDES = "decides whether a finding is accepted, or calls the function that does"
HOLDS = "loads the store for a consumer that decides (named)"
WRITES = "changes the store, under its lock"
RAW = "the operator's own document of the whole installation (an instance-wide route)"
STAMP = "reads the modification time only"

CENSUS = {
    ("advisory_handlers.py", "_build_advisory"): (DECIDES, None),
    ("api.py", "_declarative_collections"): (RAW, None),
    ("api.py", "_declarative_meta"): (RAW, None),
    ("api.py", "_compliance_facts"): (DECIDES, None),
    ("api.py", "_cve_high_counts"): (DECIDES, None),
    ("api.py", "_fleet_checks_fp"): (STAMP, None),
    ("api.py", "_compute_attention"): (DECIDES, None),
    ("api.py", "_risk_fingerprint"): (STAMP, None),
    ("api.py", "_compute_fleet_risk"): (DECIDES, None),
    ("api.py", "handle_home"): (DECIDES, None),
    ("api.py", "_cve_fixable_by_device"): (DECIDES, None),
    ("api.py", "handle_nav_counts"): (DECIDES, None),
    ("api.py", "_timeline_collect"): (DECIDES, None),
    ("api.py", "_timeline_etag_source"): (STAMP, None),
    ("api.py", "_build_posture_digest"): (DECIDES, None),
    ("api.py", "_detect_new_cve_and_fire_webhook"): (DECIDES, None),
    ("api.py", "run_cve_campaign_sample_if_due"): (DECIDES, None),
    ("api.py", "_sbom_stores"): (HOLDS, ("api.py", "_build_sbom_doc")),
    ("api.py", "_build_metrics_ctx"): (HOLDS, ("prometheus_export.py", "generate_metrics")),
    ("attention_handlers.py", "handle_suppressions"): (SHOWS, None),
    ("cve_handlers.py", "handle_cve_realert"): (DECIDES, None),
    ("cve_handlers.py", "handle_cve_campaigns"): (DECIDES, None),
    ("cve_handlers.py", "handle_cve_findings"): (DECIDES, None),
    ("cve_handlers.py", "handle_cve_device"): (DECIDES, None),
    ("cve_handlers.py", "drop_host_acceptance"): (WRITES, None),
    ("cve_handlers.py", "handle_cve_host_accept"): (WRITES, None),
    ("cve_handlers.py", "handle_cve_host_unaccept"): (WRITES, None),
    ("cve_handlers.py", "handle_cve_ignore_add"): (WRITES, None),
    ("cve_handlers.py", "handle_cve_ignore_delete"): (WRITES, None),
    ("cve_handlers.py", "handle_cve_ignore_list"): (SHOWS, None),
    ("reports_handlers.py", "_build_fleet_report"): (DECIDES, None),
}
_DECIDERS = ("cve_ignore_applies", "cve_ignored_ids", "apply_ignore_list", "_counted_cve_findings", "_campaign_public", "_campaign_affected",
             "decorated_cve_findings", "live_cve_findings", "_cve_count_rule")
_VISIBILITY = ("visible_ignore_records", "_ignore_entry_visible")
_STAMPS = ("backend_mtime",)


def _top_level_functions():
    out = {}
    for path in sorted(_CGI.glob("*.py")):
        for node in ast.parse(path.read_text(encoding="utf-8")).body:
            if isinstance(node, ast.FunctionDef):
                out[(path.name, node.name)] = node
    return out


def _names_the_store(node):
    for sub in ast.walk(node):
        if (isinstance(sub, ast.Name) and sub.id == "CVE_IGNORE_FILE") or (isinstance(sub, ast.Attribute) and sub.attr == "CVE_IGNORE_FILE"):
            return True
    return False


def _calls(node):
    names = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            fn = sub.func
            names.add(fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", ""))
    return names


class TestTheCensusOfTheReaders(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.functions = _top_level_functions()
        cls.found = {k: n for k, n in cls.functions.items() if _names_the_store(n)}

    def test_the_population_was_found(self):
        self.assertGreater(len(self.found), 20, "the scan found %d functions: it is measuring nothing" % len(self.found))
        self.assertIn(("cve_handlers.py", "handle_cve_ignore_add"), self.found)
        self.assertIn(("attention_handlers.py", "handle_suppressions"), self.found)

    def test_every_function_that_names_the_store_is_in_the_census_and_every_entry_still_names_it(self):
        new = sorted(set(self.found) - set(CENSUS))
        stale = sorted(set(CENSUS) - set(self.found))
        self.assertEqual(new, [], "a function now reads the accepted-risk store: say how it reads a record in CENSUS "
                                  "(and make it ask which records its caller may see, if it shows their content): %s" % new)
        self.assertEqual(stale, [], "an entry of CENSUS no longer names the store: %s" % stale)

    def test_the_way_a_function_reads_a_record_is_what_the_census_says(self):
        wrong = []
        for key, (how, delegate) in sorted(CENSUS.items()):
            node = self.found.get(key)
            if node is None:
                continue
            calls = _calls(node)
            if how == SHOWS and not calls & set(_VISIBILITY):
                wrong.append((key, "shows records and never asks which the caller may see"))
            if how == DECIDES and not calls & set(_DECIDERS):
                wrong.append((key, "decides on records and calls none of %s" % (_DECIDERS,)))
            if how == WRITES and "_LockedUpdate" not in calls:
                wrong.append((key, "changes the store without its lock"))
            if how == STAMP and not calls & set(_STAMPS):
                wrong.append((key, "is listed as reading the modification time and does not"))
            if how == HOLDS:
                consumer = self.functions.get(delegate)
                if consumer is None or not _calls(consumer) & set(_DECIDERS):
                    wrong.append((key, "its consumer %s does not decide with a rule that knows several organisations" % (delegate,)))
        self.assertEqual(wrong, [], "\n".join("%s: %s" % w for w in wrong))

    def test_the_shows_class_is_the_two_routes_that_list_records(self):
        shows = sorted(k for k, (how, _d) in CENSUS.items() if how == SHOWS)
        self.assertEqual(shows, [("attention_handlers.py", "handle_suppressions"), ("cve_handlers.py", "handle_cve_ignore_list")])

    def test_no_function_outside_the_census_hands_record_text_to_a_caller(self):
        """The second half of the census: a function that reads `reason` or `actor` of a record, anywhere in the server, is in the
        SHOWS class or a writer. The names are read from the syntax tree, whatever the function is called."""
        text_keys = {"reason", "actor"}
        offenders = []
        for key, node in self.found.items():
            if CENSUS.get(key, (None,))[0] in (SHOWS, WRITES):
                continue
            for sub in ast.walk(node):
                if isinstance(sub, ast.Subscript) and isinstance(sub.slice, ast.Constant) and sub.slice.value in text_keys:
                    offenders.append((key, sub.slice.value))
                if (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) and sub.func.attr == "get" and sub.args
                        and isinstance(sub.args[0], ast.Constant) and sub.args[0].value in text_keys):
                    offenders.append((key, sub.args[0].value))
        self.assertEqual(offenders, [], "these read the text of a record and are not in the SHOWS class: %s" % offenders)


if __name__ == "__main__":
    unittest.main()

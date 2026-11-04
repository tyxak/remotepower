#!/usr/bin/env python3
"""Critical CVEs in the images of running containers are a finding where CVEs are judged, not a number on one page.

The agent scans the images of a host's running containers with trivy (opt-in) and sends a summary per image. The server kept
it and showed it on the Image CVE page, in the risk score and in the AI index. It raised no alert, the Security Advisory had no
finding for it, the compliance vulnerability control counted host findings only (so a fleet running a vulnerable image passed
PCI 6.3.1, and a fleet that scanned only its images read Not assessed), and the fleet report's CVE section left it out.

The records are the agent's own `collect_image_cves` run over canned trivy JSON. The alert is driven through the real heartbeat
and the real alert ledger, so the recovery has to resolve the real open row.
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v742_container_recovery import DEV, _Base, _Captured, _Stdin, api  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
import advisory  # noqa: E402
import compliance  # noqa: E402

APP = "registry.example/app:1.4"
NGINX = "docker.io/library/nginx:1.25"
PG = "docker.io/library/postgres:16"


def _trivy(crit, high, med):
    """What `trivy image --format json` prints for an image with this many findings."""
    vulns = []
    for sev, n in (("CRITICAL", crit), ("HIGH", high), ("MEDIUM", med)):
        for i in range(n):
            vulns.append({"VulnerabilityID": f"CVE-2026-{sev[0]}{i:04d}", "PkgName": "openssl", "Severity": sev,
                          "InstalledVersion": "3.0.1", "FixedVersion": "3.0.9"})
    return json.dumps({"Results": [{"Target": "x", "Vulnerabilities": vulns}]})


def _agent_images(spec):
    """The agent's own collector over `{image: (critical, high, medium)}`; trivy itself is the only thing stood in for."""
    s = importlib.util.spec_from_file_location("rp_agent_v750_img", ROOT / "client" / "remotepower-agent.py")
    agent = importlib.util.module_from_spec(s)
    s.loader.exec_module(agent)
    agent._which = lambda name: "/usr/bin/trivy" if name == "trivy" else None

    def fake_run(argv, **kw):
        return types.SimpleNamespace(returncode=0, stdout=_trivy(*spec[argv[-1]]), stderr="")

    agent.subprocess = types.SimpleNamespace(run=fake_run, TimeoutExpired=Exception, CalledProcessError=Exception,
                                             DEVNULL=-3, PIPE=-1, STDOUT=-2)
    return agent.collect_image_cves(list(spec))


class _Beats(_Base):

    def beat_images(self, spec):
        body = {"device_id": DEV, "token": "tok", "image_cves": _agent_images(spec)}
        raw = json.dumps(body).encode()
        os.environ.update({"REQUEST_METHOD": "POST", "PATH_INFO": "/api/heartbeat",
                           "QUERY_STRING": "", "CONTENT_LENGTH": str(len(raw))})
        for k in ("HTTP_X_TOKEN", "HTTP_X_RP_VAULT_KEY"):
            os.environ.pop(k, None)
        api.sys.stdin = _Stdin(raw)
        api._LOAD_CACHE.clear()
        try:
            api.handle_heartbeat()
        except _Captured as c:
            self.assertEqual(c.status, 200, c.body)
            return
        self.fail("heartbeat did not answer")

    def setUp(self):
        super().setUp()
        api.save(api.IMAGE_CVE_FILE, {})
        api._LOAD_CACHE.clear()

    def sent(self, event):
        return [p for e, p in self.events if e == event]

    def open_rows(self, event="image_cve_critical"):
        return [a for a in self.alerts(event) if not a.get("resolved_at")]


class TestTheProducer(unittest.TestCase):

    def test_the_premise_the_agent_counts_each_severity_per_image(self):
        got = {i["image"]: (i["critical"], i["high"], i["medium"]) for i in _agent_images({APP: (3, 5, 7), NGINX: (0, 2, 0)})}
        self.assertEqual(got, {APP: (3, 5, 7), NGINX: (0, 2, 0)})


class TestTheAlert(_Beats):

    def test_the_first_scan_with_a_critical_finding_fires_once_with_the_counts(self):
        self.beat_images({APP: (3, 5, 7), NGINX: (0, 2, 0)})
        got = self.sent("image_cve_critical")
        self.assertEqual(len(got), 1, self.events)
        self.assertEqual((got[0]["critical"], got[0]["high"], got[0]["count"]), (3, 7, 1))
        self.assertEqual((got[0]["device_id"], got[0]["name"]), (DEV, "serverbox"))

    def test_it_reaches_the_inbox_as_one_high_row_with_a_readable_title(self):
        self.beat_images({APP: (3, 5, 7)})
        rows = self.open_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["severity"], "high")
        self.assertEqual(rows[0]["title"], "Container image CVEs on serverbox: 3 critical, 5 high")
        self.assertEqual(rows[0]["device_id"], DEV)

    def test_the_same_report_again_is_not_a_rise(self):
        self.beat_images({APP: (3, 5, 7)})
        self.events.clear()
        self.beat_images({APP: (3, 5, 7)})
        self.assertEqual(self.sent("image_cve_critical"), [])

    def test_a_rise_fires_again_and_keeps_one_open_row(self):
        self.beat_images({APP: (3, 5, 7)})
        self.events.clear()
        self.beat_images({APP: (4, 5, 7)})
        self.assertEqual([p["critical"] for p in self.sent("image_cve_critical")], [4])
        self.assertEqual(len(self.open_rows()), 1)

    def test_fewer_but_not_none_leaves_the_alert_alone(self):
        self.beat_images({APP: (3, 5, 7)})
        self.events.clear()
        self.beat_images({APP: (1, 5, 7)})
        self.assertEqual(self.sent("image_cve_critical") + self.sent("image_cve_cleared"), [])
        self.assertEqual(len(self.open_rows()), 1)

    def test_falling_to_zero_clears_and_resolves_the_open_row(self):
        self.beat_images({APP: (3, 5, 7)})
        self.assertEqual(len(self.open_rows()), 1)
        self.beat_images({APP: (0, 5, 7)})
        self.assertEqual(len(self.sent("image_cve_cleared")), 1)
        self.assertEqual(self.open_rows(), [], "the recovery must close the real open alert")

    def test_zero_to_zero_and_a_first_scan_without_a_critical_say_nothing(self):
        self.beat_images({APP: (0, 5, 7)})
        self.beat_images({APP: (0, 4, 7)})
        self.assertEqual(self.sent("image_cve_critical") + self.sent("image_cve_cleared"), [])
        self.assertEqual(self.alerts("image_cve_critical"), [])

    def test_a_critical_finding_returning_after_a_clear_fires_again(self):
        self.beat_images({APP: (2, 0, 0)})
        self.beat_images({APP: (0, 0, 0)})
        self.events.clear()
        self.beat_images({APP: (1, 0, 0)})
        self.assertEqual(len(self.sent("image_cve_critical")), 1)
        self.assertEqual(len(self.open_rows()), 1)

    def test_a_muted_host_gets_the_event_but_no_inbox_row(self):
        api.save(api.ALERT_MUTES_FILE, {"mutes": [{"id": "m1", "device_id": DEV, "event": "image_cve_critical"}]})
        api._ALERT_MUTE_SET_CACHE.update(mtime=None, checked=0)
        try:
            self.beat_images({APP: (3, 5, 7)})
            self.assertEqual(self.open_rows(), [])
        finally:
            api.save(api.ALERT_MUTES_FILE, {"mutes": []})
            api._ALERT_MUTE_SET_CACHE.update(mtime=None, checked=0)

    def test_the_heartbeat_hands_the_host_name_over(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("_ingest_image_cves(dev_id, body['image_cves'], saved_dev.get('name'))", src)


class TestRegistries(unittest.TestCase):

    def test_the_pair_is_registered_with_a_severity_and_a_recovery(self):
        reg = api.EVENT_REGISTRY
        self.assertEqual(reg["image_cve_critical"]["severity"], "high")
        self.assertEqual(reg["image_cve_critical"]["kind"], "cve")
        self.assertEqual(reg["image_cve_cleared"]["resolves"], ("image_cve_critical",))
        self.assertEqual(api._ALERT_RECOVER["image_cve_cleared"], "image_cve_critical")
        self.assertIn("image_cve_critical", api.SUPPRESSIBLE_EVENTS)
        self.assertIn("image_cve_cleared", api.SUPPRESSIBLE_EVENTS)

    def test_the_message_names_the_host_and_the_counts(self):
        import notify
        msg = notify._webhook_message("image_cve_critical", {"name": "web01", "critical": 3, "high": 5, "count": 2})
        self.assertIn("web01", msg)
        self.assertIn("3 critical and 5 high", msg)
        cleared = notify._webhook_message("image_cve_cleared", {"name": "web01"})
        self.assertIn("no critical CVEs left", cleared)

    def test_the_dashboard_feed_and_the_click_through_know_both(self):
        js = (ROOT / "server/html/static/js/app.js").read_text()
        feed = js[js.index("const FLEET_EVENTS = new Set(["):]
        feed = feed[:feed.index("]);")]
        for ev in ("image_cve_critical", "image_cve_cleared"):
            self.assertIn(f"'{ev}'", feed)
        route = js[js.index("case 'image_cve_critical'"):][:260]
        self.assertIn("case 'image_cve_cleared'", route)
        self.assertIn('data-home-act="cve"', route)

    def test_the_labels_and_titles_are_in_six_languages(self):
        i18n = (ROOT / "server/html/static/js/i18n.js").read_text()
        import re
        for key in (api.EVENT_REGISTRY["image_cve_critical"]["label"], api.EVENT_REGISTRY["image_cve_cleared"]["label"],
                    api.EVENT_REGISTRY["image_cve_critical"]["title"], api.EVENT_REGISTRY["image_cve_cleared"]["title"]):
            m = re.search(r'^\s*"' + re.escape(key) + r'":\s*\{([^\n]*)\}', i18n, re.M)
            self.assertTrue(m, key)
            for lang in ("fr", "de", "zh", "hi", "es", "ar"):
                self.assertIn(f'"{lang}":', m.group(1), (key, lang))


# ── the readers beside the alert ─────────────────────────────────────────────

NOW = int(time.time())


def _fresh_api():
    os.environ["RP_DATA_DIR"] = tempfile.mkdtemp(prefix="rp-v750-img-api-")
    spec = importlib.util.spec_from_file_location("api_v750_img", _CGI / "api.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Fleet(unittest.TestCase):
    """web01: an app image with 3 critical and 5 high and a clean-ish nginx. db01: scanned, a high only. clean01: scanned, mediums
    only. bare01: never scanned. lab02: unmonitored, one critical."""

    @classmethod
    def setUpClass(cls):
        cls.api = a = _fresh_api()
        a.fire_webhook = lambda *x, **k: None
        dev = lambda name, **kw: {"name": name, "last_seen": NOW, "monitored": True, "sysinfo": {"cpu_percent": 1}, **kw}  # noqa: E731
        a.save(a.DEVICES_FILE, {"web": dev("web01"), "db": dev("db01"), "clean": dev("clean01"), "bare": dev("bare01"),
                                "lab": dev("lab02", monitored=False)})
        a._ingest_image_cves("web", _agent_images({APP: (3, 5, 7), NGINX: (0, 2, 0)}), "web01")
        a._ingest_image_cves("db", _agent_images({PG: (0, 1, 4)}), "db01")
        a._ingest_image_cves("clean", _agent_images({PG: (0, 0, 2)}), "clean01")
        a._ingest_image_cves("lab", _agent_images({PG: (1, 0, 0)}), "lab02")
        a.get_token_from_request = lambda: "tok"
        a.verify_token = lambda _t=None: ("alice", "admin")
        a._LOAD_CACHE.clear()

    def devices(self, *ids):
        self.api._LOAD_CACHE.clear()
        d = self.api.load(self.api.DEVICES_FILE)
        return {k: v for k, v in d.items() if not ids or k in ids}


class TestCompliance(_Fleet):

    def facts(self, *ids):
        return self.api._compliance_facts(self.devices(*ids))

    def test_the_image_findings_and_the_scanned_hosts_are_counted(self):
        f = self.facts()
        self.assertEqual(f["image_cve_critical_high"], (3 + 5 + 2) + 1 + 1)       # web01 + db01 + lab02 (a CVE fact counts them all)
        self.assertEqual(f["image_scanned_devices"], 4)                           # a scanned host with only mediums is assessed

    def test_a_view_limits_both(self):
        f = self.facts("db")
        self.assertEqual((f["image_cve_critical_high"], f["image_scanned_devices"]), (1, 1))
        f = self.facts("bare")
        self.assertEqual((f["image_cve_critical_high"], f["image_scanned_devices"]), (0, 0))

    def test_the_control_fails_and_names_the_images(self):
        status, text = compliance._cve_control(self.facts())
        self.assertEqual(status, compliance.FAIL)
        self.assertIn("12 critical/high CVEs in container images", text)

    def test_host_findings_and_images_both_show(self):
        status, text = compliance._cve_control({"devices": 3, "cve_critical_high": 2, "cve_scanned_devices": 3,
                                                "image_cve_critical_high": 4, "image_scanned_devices": 1})
        self.assertEqual(status, compliance.FAIL)
        self.assertEqual(text, "2 critical/high CVE findings and 4 critical/high CVEs in container images outstanding across "
                               "the fleet.")

    def test_the_host_only_wording_is_unchanged(self):
        status, text = compliance._cve_control({"devices": 3, "cve_critical_high": 1, "cve_scanned_devices": 3})
        self.assertEqual((status, text), (compliance.FAIL, "1 critical/high CVE finding outstanding across the fleet."))

    def test_one_source_alone_assesses_it_and_no_source_is_not_assessed(self):
        base = {"devices": 3, "cve_critical_high": 0, "image_cve_critical_high": 0}
        self.assertEqual(compliance._cve_control({**base, "cve_scanned_devices": 2, "image_scanned_devices": 0}),
                         (compliance.PASS, "No outstanding critical or high CVEs."))
        status, text = compliance._cve_control({**base, "cve_scanned_devices": 0, "image_scanned_devices": 2})
        self.assertEqual(status, compliance.PASS)
        self.assertIn("in the container images that were scanned", text)
        self.assertIn("No host has a CVE scan on record", text)
        status, _ = compliance._cve_control({**base, "cve_scanned_devices": 0, "image_scanned_devices": 0})
        self.assertEqual(status, compliance.NOT_ASSESSED)

    def test_an_empty_fleet_is_not_a_blind_spot(self):
        self.assertEqual(compliance._cve_control({"devices": 0})[0], compliance.PASS)


class TestAdvisory(_Fleet):

    def build(self, *ids):
        a = self.api
        a._LOAD_CACHE.clear()
        return advisory.build(self.devices(*ids), img_by_dev=a.load(a.IMAGE_CVE_FILE), now=NOW)

    def finding(self, adv):
        return {g["id"]: g for g in adv["findings"]}.get("os.imagecve")

    def test_a_critical_image_is_a_high_finding_with_the_images_in_the_evidence(self):
        g = self.finding(self.build("web"))
        self.assertEqual(g["severity"], "high")
        self.assertEqual(g["title"], "3 critical CVEs in container images")
        self.assertEqual(g["evidence"][0], f"{APP}: 3 critical, 5 high")
        self.assertEqual([d["device"] for d in g["devices"]], ["web01"])

    def test_a_high_only_host_is_medium(self):
        g = self.finding(self.build("db"))
        self.assertEqual((g["severity"], g["title"]), ("medium", "1 high CVE in container images"))

    def test_a_host_never_scanned_has_no_finding(self):
        self.assertIsNone(self.finding(self.build("bare")))

    def test_the_group_takes_the_worst_severity_and_lists_both_hosts(self):
        g = self.finding(self.build("web", "db"))
        self.assertEqual(g["severity"], "high")
        self.assertEqual(sorted(d["device"] for d in g["devices"]), ["db01", "web01"])

    def test_the_ai_brief_has_counts_and_no_image_or_host(self):
        brief = advisory.summarize_for_ai(self.build("web", "db"), "the fleet")
        self.assertIn("container images", brief)
        for secret in (APP, "registry.example", "web01", "db01"):
            self.assertNotIn(secret, brief)

    def test_through_the_real_handler_and_its_view(self):
        a = self.api
        ids = {f["id"] for f in a._build_advisory(self.devices("web"))["findings"]}
        self.assertIn("os.imagecve", ids)
        ids = {f["id"] for f in a._build_advisory(self.devices("bare"))["findings"]}
        self.assertNotIn("os.imagecve", ids)
        names = {d["device"] for g in a._build_advisory(self.devices("db"))["findings"] if g["id"] == "os.imagecve"
                 for d in g["devices"]}
        self.assertEqual(names, {"db01"}, "a host outside the view must not appear")


class TestReport(_Fleet):

    def test_the_cve_section_carries_the_image_counts_for_the_hosts_in_view(self):
        rep = self.api._build_fleet_report()
        self.assertEqual(rep["cve"]["images"], {"critical": 3 + 0 + 1, "high": 5 + 2 + 1 + 0, "hosts": 3})

    def test_a_scoped_reader_does_not_add_up_the_others(self):
        a = self.api
        real = a._scope_filter_devices
        a._scope_filter_devices = lambda d: {k: v for k, v in d.items() if k == "db"}
        try:
            rep = a._build_fleet_report()
        finally:
            a._scope_filter_devices = real
        self.assertEqual(rep["cve"]["images"], {"critical": 0, "high": 1, "hosts": 1})

    def test_the_section_projection_keeps_it_and_the_csv_and_email_print_it(self):
        a = self.api
        rep = a._build_fleet_report()
        self.assertIn("images", a._filter_report_sections(rep, ["cve"])["cve"])
        csv = a._fleet_report_csv_bytes(rep).decode().replace("\r", "")
        self.assertIn("CVE,Container image critical,4", csv)
        self.assertIn("CVE,Container image high,8", csv)
        _subj, body = a._render_report_email(rep)
        self.assertIn("Container images   : 4 critical, 8 high (3 hosts running them)", body)

    def test_a_fleet_with_nothing_scanned_prints_no_image_line(self):
        a = self.api
        a.save(a.IMAGE_CVE_FILE, {})
        a._LOAD_CACHE.clear()
        try:
            rep = a._build_fleet_report()
            self.assertEqual(rep["cve"]["images"], {"critical": 0, "high": 0, "hosts": 0})
            _subj, body = a._render_report_email(rep)
            self.assertNotIn("Container images", body)
        finally:
            for did, spec in (("web", {APP: (3, 5, 7), NGINX: (0, 2, 0)}), ("db", {PG: (0, 1, 4)}), ("clean", {PG: (0, 0, 2)}),
                              ("lab", {PG: (1, 0, 0)})):
                a._ingest_image_cves(did, _agent_images(spec), did)

    def test_the_printable_page_shows_the_image_numbers(self):
        js = (ROOT / "server/html/static/js/report.js").read_text()
        self.assertIn("in images", js)
        self.assertIn("c.images", js)


_HARNESS = r"""
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
const rep = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
const els = {};
function el(id) {
  if (!els[id]) els[id] = {innerHTML: '', textContent: '', addEventListener() {}, classList: {add() {}, remove() {}}};
  return els[id];
}
global.document = {readyState: 'complete', getElementById: el, querySelector: () => null,
                   documentElement: {style: {setProperty() {}}}, title: '', addEventListener() {}};
global.localStorage = {getItem: () => 'tok'};
global.sessionStorage = {getItem: () => 'tok'};
global.window = {print() {}};
global.fetch = async (path) => ({ok: true, json: async () => (path.indexOf('baseline') >= 0 ? {} : rep)});
(0, eval)(src);
setTimeout(() => {
  process.stdout.write(JSON.stringify({all: Object.keys(els).map(k => els[k].innerHTML).join('\n')}));
}, 50);
"""


@unittest.skipUnless(shutil.which("node"), "node not installed")
class TestThePrintedReport(_Fleet):
    """report.js, run for real against the server's own JSON."""

    def render(self, rep):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "h.js").write_text(_HARNESS)
            (Path(d) / "rep.json").write_text(json.dumps(rep))
            r = subprocess.run([shutil.which("node"), str(Path(d) / "h.js"), str(ROOT / "server/html/static/js/report.js"),
                                str(Path(d) / "rep.json")], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr[-600:])
        return json.loads(r.stdout)["all"]

    def test_the_cve_tile_adds_the_image_numbers(self):
        html = self.render(self.api._build_fleet_report())
        self.assertIn("0 crit \u00b7 0 high \u00b7 4 crit / 8 high in images", html)

    def test_a_fleet_without_image_findings_adds_nothing(self):
        rep = json.loads(json.dumps(self.api._build_fleet_report()))
        rep["cve"]["images"] = {"critical": 0, "high": 0, "hosts": 0}
        self.assertNotIn("in images", self.render(rep))
        del rep["cve"]["images"]
        self.assertNotIn("in images", self.render(rep))


class TestTheSummaryContext(_Fleet):

    def test_the_ai_summary_sees_the_image_counts_and_nothing_with_a_name(self):
        a = self.api
        ctx = a._report_summary_context(a._build_fleet_report())
        self.assertEqual(ctx["cve"]["images"], {"critical": 4, "high": 8, "hosts": 3})
        blob = json.dumps(ctx)
        for secret in (APP, "web01", "db01", "registry.example"):
            self.assertNotIn(secret, blob)


class TestTheDocs(unittest.TestCase):

    def test_the_cve_guide_lists_every_reader(self):
        doc = (ROOT / "docs" / "cve.md").read_text()
        for phrase in ("Critical CVEs found in the container images of a host", "Security Advisory", "PCI DSS 6.3.1",
                       "Fleet report", "never scanned"):
            self.assertIn(phrase, doc)

    def test_the_event_count_in_features_follows_the_registry(self):
        feat = (ROOT / "docs" / "features.md").read_text()
        self.assertIn(f"| Webhook event registry | {len(api.WEBHOOK_EVENTS)} event types", feat)


if __name__ == "__main__":
    unittest.main()

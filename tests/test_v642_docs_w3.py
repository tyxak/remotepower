#!/usr/bin/env python3
"""Guardrails for the docs this wave rewrote.

The failure mode these exist to catch is a doc that describes a field, endpoint
or behaviour the code does not have. So wherever the claim is behavioural it is
DRIVEN — `_persist_integration_results`, `in_maintenance` and `_alert_muted` are
called for real against a seeded store, because a substring proves a line exists
and never that it works. Where the claim is structural (a kind name, a metric
family, an index entry) the code side is PARSED out of the real source rather
than restated here, so the pin rots loudly when either side moves.

Covers:
  * docs/integrations.md — the v6.4.2 host/site binding, and the two things it
    was added to buy (maintenance suppression and per-(host, event) mutes
    reaching `integration_down`).
  * docs/attention.md — the Needs Attention page and the kind/mute/health
    relationships it documents.
  * docs/monitors.md + docs/prometheus-metrics-sample.txt — every metric family
    named in the prose exists in the exporter.
  * docs/README.md — the index and the docs tree agree in both directions.
"""

import importlib.util
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

_ROOT = Path(__file__).resolve().parents[1]
_DOCS = _ROOT / "docs"
_CGI = _ROOT / "server" / "cgi-bin"
_HTML = _ROOT / "server" / "html"
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location("api_v642_docs_w3", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import integrations as integrations_mod  # noqa: E402


def _read(p):
    return p.read_text(encoding="utf-8")


def _reset_stores():
    """Every test here seeds the stores it reads — a shared store left populated
    by another module (or another test in this one) is the order-dependent
    false-failure class, not flake."""
    api.save(api.DEVICES_FILE, {})
    api.save(api.MAINT_FILE, {"windows": []})
    api.save(api.ALERT_MUTES_FILE, {"mutes": []})
    api.save(api.INTEG_STATE_FILE, {})
    cfg = api.load(api.CONFIG_FILE) or {}
    cfg["integrations"] = []
    cfg["integration_notified"] = {}
    api.save(api.CONFIG_FILE, cfg)
    api._LOAD_CACHE.clear()


# ── docs/integrations.md — the host/site binding ────────────────────────────

class TestIntegrationBinding(unittest.TestCase):
    """docs/integrations.md claims an instance takes an optional device_id/site,
    that the up/down events then carry it, and that maintenance windows and
    per-(host, event) mutes consequently apply. All four are driven."""

    def setUp(self):
        _reset_stores()
        self.doc = _read(_DOCS / "integrations.md")

    def _seed(self, bound=True):
        now = int(time.time())
        api.save(api.DEVICES_FILE,
                 {"d1": {"name": "nas-1", "group": "lab", "token": "t",
                         "last_seen": now}})
        inst = {"id": "i1", "type": "truenas", "label": "NAS",
                "url": "https://nas.lan", "enabled": True}
        if bound:
            inst["device_id"] = "d1"
            inst["site"] = "hq"
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg["integrations"] = [inst]
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()

    def _fire(self):
        """Drive the real persist path, capturing what it would have fired."""
        fired = []
        orig = api.fire_webhook
        api.fire_webhook = lambda event, payload: fired.append((event, payload))
        try:
            api._persist_integration_results([{
                "id": "i1", "label": "NAS", "type": "truenas",
                "status": integrations_mod.CRIT, "detail": "pool DEGRADED",
                "checked": int(time.time()), "metrics": {},
            }])
        finally:
            api.fire_webhook = orig      # never leak the stub into a later test
        return fired

    def test_doc_names_the_fields_the_instance_actually_stores(self):
        for field in ("device_id", "site"):
            self.assertIn(field, api.INTEGRATION_FIELDS,
                          "docs/integrations.md documents an instance field the "
                          "backend does not persist")
            self.assertIn("`%s`" % field, self.doc)

    def test_bound_instance_puts_device_id_on_the_event(self):
        self._seed(bound=True)
        fired = self._fire()
        self.assertEqual([e for e, _ in fired], ["integration_down"])
        payload = fired[0][1]
        self.assertEqual(payload.get("device_id"), "d1")
        self.assertEqual(payload.get("site"), "hq")

    def test_unbound_instance_fires_exactly_the_old_keys(self):
        """The doc promises an unbound instance behaves as it always did."""
        self._seed(bound=False)
        fired = self._fire()
        self.assertEqual([e for e, _ in fired], ["integration_down"])
        payload = fired[0][1]
        self.assertNotIn("device_id", payload)
        self.assertNotIn("site", payload)

    def test_maintenance_window_suppresses_a_bound_integration(self):
        self._seed(bound=True)
        api.save(api.MAINT_FILE, {"windows": [
            {"scope": "device", "target": "d1", "cron": "* * * * *",
             "duration": 60, "reason": "reboot"}]})
        api._LOAD_CACHE.clear()
        for event in ("integration_down", "integration_recovered"):
            self.assertIn(event, api.SUPPRESSIBLE_EVENTS)
            self.assertTrue(
                api.in_maintenance(event, {"device_id": "d1", "label": "NAS"}),
                "%s is documented as suppressible by a device window" % event)
        # …and the same event with no binding still falls outside a DEVICE
        # window, which is exactly why the binding had to be added.
        self.assertIsNone(
            api.in_maintenance("integration_down", {"label": "NAS"}))

    def test_per_host_event_mute_reaches_a_bound_integration(self):
        self._seed(bound=True)
        api.save(api.ALERT_MUTES_FILE, {"mutes": [
            {"id": "m1", "device_id": "d1", "event": "integration_down"}]})
        api._LOAD_CACHE.clear()
        self.assertTrue(api._alert_muted("integration_down", {"device_id": "d1"}))
        self.assertFalse(api._alert_muted("integration_down", {"label": "NAS"}))

    def test_site_survives_onto_the_alert_row(self):
        """The doc says the inbox can say where the failing service lives, which
        depends on `site` being in _record_alert's payload whitelist."""
        self._seed(bound=True)
        api.save(api.ALERTS_FILE, {"alerts": []})
        api._LOAD_CACHE.clear()
        api._record_alert("integration_down", {
            "device_id": "d1", "label": "NAS", "site": "hq",
            "severity": "high", "integration_id": "i1"})
        alerts = (api.load(api.ALERTS_FILE) or {}).get("alerts") or []
        self.assertTrue(alerts, "_record_alert stored nothing")
        self.assertEqual(alerts[-1].get("payload", {}).get("site"), "hq")

    def test_unmonitored_host_silences_its_bound_integration(self):
        """Documented consequence of the binding: an integration on a host the
        operator marked unmonitored stops reaching the inbox."""
        api.save(api.DEVICES_FILE, {"d1": {"name": "nas-1", "token": "t",
                                           "monitored": False}})
        api.save(api.ALERTS_FILE, {"alerts": []})
        api._LOAD_CACHE.clear()
        api._record_alert("integration_down", {
            "device_id": "d1", "label": "NAS", "severity": "high",
            "integration_id": "i1"})
        self.assertEqual((api.load(api.ALERTS_FILE) or {}).get("alerts"), [])

    def test_documented_endpoints_exist(self):
        routes = api._build_exact_routes()
        found = re.findall(r"`(GET|POST)\s+(/api/integrations[a-z/]*)`", self.doc)
        self.assertGreaterEqual(len(found), 4, "the API section vanished")
        for method, path in found:
            self.assertIn((method, path.rstrip("/")), routes,
                          "docs/integrations.md documents %s %s, which is not a "
                          "route" % (method, path))

    def test_every_documented_connector_label_is_registered(self):
        labels = {c["label"] for c in integrations_mod.CONNECTORS.values()}
        # The catalogue table bolds each supported target.
        table = self.doc.split("## Supported targets", 1)[1].split("\n### ", 1)[0]
        names = [b.strip() for b in re.findall(r"\*\*([^*]+)\*\*", table)]
        self.assertGreaterEqual(len(names), 40, "the target catalogue shrank")
        for name in names:
            self.assertTrue(
                any(name in lbl or lbl in name for lbl in labels),
                "docs/integrations.md lists a target no connector registers: %r"
                % name)


# ── docs/attention.md ───────────────────────────────────────────────────────

def _compute_attention_source():
    src = _read(_CGI / "api.py")
    start = src.index("def _compute_attention()")
    return src[start:src.index("\n_NA_MUTE_EVENTS", start)]


class TestAttentionDoc(unittest.TestCase):
    def setUp(self):
        _reset_stores()
        self.doc = _read(_DOCS / "attention.md")

    def _documented_kinds(self):
        table = self.doc.split("## All attention kinds", 1)[1].split("\n## ", 1)[0]
        return {m for m in re.findall(r"^\| `([a-z_0-9]+)` \|", table, re.M)}

    def test_kind_table_matches_the_kinds_the_code_emits(self):
        emitted = set(re.findall(r"'kind':\s*'([a-z_0-9]+)'",
                                 _compute_attention_source()))
        documented = self._documented_kinds()
        self.assertEqual(
            sorted(emitted - documented), [],
            "_compute_attention emits kinds docs/attention.md never lists")
        self.assertEqual(
            sorted(documented - emitted), [],
            "docs/attention.md lists kinds _compute_attention never emits")

    def test_mute_map_only_names_real_events(self):
        """The doc's claim that _NA_MUTE_EVENTS translates a kind to the webhook
        event(s) it represents is worthless if a named event does not exist."""
        unknown = sorted({ev for evs in api._NA_MUTE_EVENTS.values()
                          for ev in evs if ev not in api.EVENT_REGISTRY})
        self.assertEqual(unknown, [],
                         "_NA_MUTE_EVENTS names events absent from EVENT_REGISTRY")

    def test_documented_health_deductions_are_the_real_defaults(self):
        for sev, points in (("critical", 25), ("warning", 8), ("info", 2)):
            self.assertEqual(api._HEALTH_WEIGHTS[sev], points,
                             "docs/attention.md quotes %d points for a %s item"
                             % (points, sev))

    def test_digest_payload_has_the_documented_shape(self):
        api.save(api.DEVICES_FILE, {"d1": {"name": "old-1", "token": "t",
                                           "last_seen": 1}})
        api._LOAD_CACHE.clear()
        payload = api._attention_payload(use_cache=False)
        for key in ("items", "counts", "total"):
            self.assertIn(key, payload,
                          "GET /api/attention is documented as returning %r" % key)
        self.assertEqual(payload["total"], len(payload["items"]))
        self.assertTrue(any(i["kind"] == "offline" for i in payload["items"]),
                        "a device outside its TTL should raise an `offline` item")

    def test_maintenance_does_not_remove_an_item_from_the_digest(self):
        """docs/attention.md states a window suppresses outbound notification but
        does NOT clear a card. Driven, because the opposite is what an operator
        would assume (and what docs/maintenance.md still claims)."""
        api.save(api.DEVICES_FILE, {"d1": {"name": "old-1", "token": "t",
                                           "last_seen": 1}})
        api.save(api.MAINT_FILE, {"windows": [
            {"scope": "global", "cron": "* * * * *", "duration": 60,
             "reason": "patching"}]})
        api._LOAD_CACHE.clear()
        # The window really is active for this event…
        self.assertTrue(api.in_maintenance("device_offline",
                                           {"device_id": "d1"}))
        # …and the item is still in the digest anyway.
        items = api._attention_payload(use_cache=False)["items"]
        self.assertTrue(any(i["kind"] == "offline" for i in items))

    def test_muting_an_item_lifts_the_health_score(self):
        """The doc's central claim: health is derived purely from these items, so
        silencing one raises the score. Driven end to end."""
        api.save(api.DEVICES_FILE, {"d1": {"name": "old-1", "token": "t",
                                           "last_seen": 1}})
        api._LOAD_CACHE.clear()
        before = api._fleet_health(use_cache=False)["score"]
        api.save(api.ALERT_MUTES_FILE, {"mutes": [
            {"id": "m1", "device_id": "d1", "event": "device_offline"}]})
        api._LOAD_CACHE.clear()
        after = api._fleet_health(use_cache=False)["score"]
        self.assertLess(before, after,
                        "muting the offline alert did not lift the health score")

    def test_documented_endpoints_exist(self):
        routes = api._build_exact_routes()
        for path in ("/api/attention", "/api/na-suppress"):
            self.assertIn(("GET", path), routes)

    def test_the_page_the_doc_describes_exists_and_is_wired(self):
        html = _read(_HTML / "index.html")
        js = _read(_HTML / "static" / "js" / "app.js")
        self.assertIn('id="page-attention"', html)
        self.assertIn('data-page="attention"', html,
                      "the page has no sidebar entry")
        self.assertIn("function loadAttentionPage(", js)
        # Documented as sortable: every sortable <th> must carry a data-col the
        # sorter actually knows, or that header renders inert.
        head = html.split('id="page-attention"', 1)[1].split("</thead>", 1)[0]
        cols = set(re.findall(r'data-col="([a-z_]+)"', head))
        self.assertTrue(cols, "the Needs Attention table has no sortable columns")
        self.assertIn("sortHeaders: 'attention-thead'", js)
        known = set(re.findall(
            r"([a-z_]+):",
            js.split("getColumns: (i) => ({", 1)[1].split("}),", 1)[0]))
        self.assertEqual(sorted(cols - known), [],
                         "a Needs Attention <th> sorts on a key getColumns never "
                         "returns")
        # The filter controls the doc describes, with the ids the loader binds.
        for ident in ("attention-sev-filter", "attention-kind-filter",
                      "attention-device-filter", "attention-filter",
                      "attention-counts"):
            self.assertIn('id="%s"' % ident, html)
            self.assertIn("'%s'" % ident, js,
                          "#%s is in the markup but nothing reads it" % ident)

    def test_page_for_routes_every_kind_the_doc_lists(self):
        """The doc tells contributors to add a PAGE_FOR entry; an unrouted kind
        silently sends the click to the dashboard."""
        js = _read(_HTML / "static" / "js" / "app.js")
        block = js.split("const PAGE_FOR = {", 1)[1].split("};", 1)[0]
        # Several entries share a line, so this is deliberately not anchored.
        routed = set(re.findall(r"([a-z_0-9]+):\s*'", block))
        # Fleet-level or catch-all kinds with no page of their own by design.
        exempt = {"after_hours", "cred_rotation", "apikey_rotation_due",
                  "os_eol", "proxmox_backup", "agent_integrity", "reliability",
                  "failed_units", "av_posture"}
        unrouted = sorted(self._documented_kinds() - routed - exempt)
        self.assertEqual(unrouted, [],
                         "documented NA kinds with no PAGE_FOR route: %r"
                         % unrouted)


# ── docs/monitors.md + the Prometheus sample ────────────────────────────────

class TestPrometheusDoc(unittest.TestCase):
    def setUp(self):
        self.doc = _read(_DOCS / "monitors.md")
        self.exporter = _read(_CGI / "prometheus_export.py")

    def test_every_metric_named_in_the_prose_exists(self):
        named = set(re.findall(r"remotepower_[a-z_0-9]+", self.doc))
        missing = sorted(n for n in named if n not in self.exporter)
        self.assertEqual(missing, [],
                         "docs/monitors.md names metrics the exporter does not "
                         "emit: %r" % missing)

    def test_sample_is_still_generated_not_hand_written(self):
        sample = _DOCS / "prometheus-metrics-sample.txt"
        if not sample.exists():
            self.skipTest("excluded from this tree")
        self.assertIn("tools/gen-prometheus-sample.py", _read(sample))


# ── docs/README.md is the index ─────────────────────────────────────────────

class TestDocsIndex(unittest.TestCase):
    def setUp(self):
        self.index = _read(_DOCS / "README.md")

    def _links(self):
        return set(re.findall(r"\]\((?!\.\./|https?:|#)([A-Za-z0-9_.\-/]+)\)",
                              self.index))

    def test_no_dangling_links(self):
        missing = sorted(l for l in self._links() if not (_DOCS / l).exists())
        self.assertEqual(missing, [],
                         "docs/README.md links to files that do not exist: %r"
                         % missing)

    def test_every_doc_is_indexed(self):
        present = {p.name for p in _DOCS.glob("*.md")}
        present |= {p.name for p in _DOCS.glob("*.txt")}
        present.discard("README.md")          # the index itself
        orphans = sorted(present - self._links())
        self.assertEqual(orphans, [],
                         "docs/ holds files the index never links — a doc nobody "
                         "can find is a doc nobody reads: %r" % orphans)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""A certificate file that has lapsed is a finding everywhere certificates are judged, not an event.

The agent has inventoried the certificate files a host's services read since v3.14.0 (`hardware.json[id].cert_files`). The only
reader was the `cert_file_expiring` alert, which names the soonest file and says "soon". An expired /etc/nginx/ssl/site.pem was
missing from the compliance report (the TLS control read the monitor's targets alone), cost the host nothing in its risk score,
had no Checks row, no Needs-attention item and no line in the Security Advisory.

The records here are built the way the product builds them: the agent's own collector runs over canned `openssl x509` output and
its result goes through the real hardware ingest. Every reader then reads what the ingest stored. One switch (certificate expiry
alerts) and one CA-bundle rule serve all of them (`posture_signals`).
"""
import importlib.util
import os
import re
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-cert-"))

import advisory  # noqa: E402
import compliance  # noqa: E402
import posture_signals as ps  # noqa: E402

DAY = 86400
NOW = int(time.time())
SITE = "/etc/nginx/ssl/site.pem"
LE = "/etc/letsencrypt/live/www.example/fullchain.pem"
FAR = "/etc/apache2/ssl/old.crt"
CA = "/etc/ssl/certs/ca-example.crt"


def _when(days_from_now):
    return NOW + int(days_from_now * DAY)


def _openssl_text(ts, cn):
    """What `openssl x509 -noout -enddate -subject -issuer` prints."""
    return (f"notAfter={time.strftime('%b %d %H:%M:%S %Y', time.gmtime(ts))} GMT\n"
            f"subject=CN = {cn}\nissuer=C = US, O = Example CA, CN = Example CA R3\n")


def _agent_certs(files):
    """The agent's own collector over `{path: notAfter epoch}`: glob and openssl are stood in for, everything else is the agent's."""
    spec = importlib.util.spec_from_file_location("rp_agent_v750_cert", ROOT / "client" / "remotepower-agent.py")
    agent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(agent)
    agent._which = lambda name: "/usr/bin/openssl" if name == "openssl" else None
    agent.host_glob = lambda pat: [p for p in files if re.fullmatch(re.escape(pat).replace(r"\*", "[^/]*"), p)
                                   or (pat == "/etc/ssl/*.crt" and p == CA)]      # CA: an older agent that scanned the bundle
    agent.host_path = lambda p: p

    def fake_run(argv, **kw):
        path = argv[argv.index("-in") + 1]
        return types.SimpleNamespace(returncode=0, stdout=_openssl_text(files[path], Path(path).stem), stderr="")

    agent.subprocess = types.SimpleNamespace(run=fake_run, TimeoutExpired=Exception, CalledProcessError=Exception,
                                             DEVNULL=-3, PIPE=-1, STDOUT=-2)
    return agent.get_cert_files()


def _fresh_api():
    os.environ["RP_DATA_DIR"] = tempfile.mkdtemp(prefix="rp-v750-cert-api-")
    spec = importlib.util.spec_from_file_location("api_v750_cert", _CGI / "api.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


WEB_FILES = {SITE: _when(-3), LE: _when(5), FAR: _when(400), CA: _when(-10)}
DB_FILES = {"/etc/nginx/ssl/ok.pem": _when(200)}


class _Base(unittest.TestCase):
    """web01: one file expired, one expiring in 5 days, one far off, one under the CA bundle (an older agent). db01: healthy.
    win01: reported no certificate files. vm02: unmonitored, one file expired."""

    @classmethod
    def setUpClass(cls):
        cls.api = api = _fresh_api()
        cls.events = []
        cls._real_fire = api.fire_webhook
        api.fire_webhook = lambda ev, p=None, **k: cls.events.append((ev, p))
        cls._build(api, {})

    @classmethod
    def _build(cls, api, cfg):
        cls.events.clear()
        api.save(api.CONFIG_FILE, cfg)
        api._invalidate_load_cache(api.CONFIG_FILE)
        api.save(api.HARDWARE_FILE, {})
        api._invalidate_load_cache(api.HARDWARE_FILE)
        dev = lambda name, **kw: {"name": name, "last_seen": NOW, "monitored": True, "sysinfo": {"cpu_percent": 1}, **kw}  # noqa: E731
        api.save(api.DEVICES_FILE, {"web": dev("web01"), "db": dev("db01"), "win": dev("win01"),
                                    "vm": dev("vm02", monitored=False)})
        api._invalidate_load_cache(api.DEVICES_FILE)
        cls.web_certs = _agent_certs(WEB_FILES)
        api._ingest_hardware("web", "web01", {"cert_files": cls.web_certs}, NOW)
        api._ingest_hardware("db", "db01", {"cert_files": _agent_certs(DB_FILES)}, NOW)
        api._ingest_hardware("win", "win01", {"cert_files": []}, NOW)
        api._ingest_hardware("vm", "vm02", {"cert_files": _agent_certs({SITE: _when(-30)})}, NOW)
        api._LOAD_CACHE.clear()

    @classmethod
    def tearDownClass(cls):
        cls.api.fire_webhook = cls._real_fire

    def hw(self, did):
        self.api._LOAD_CACHE.clear()
        return self.api.load(self.api.HARDWARE_FILE)[did]

    def dev(self, did):
        self.api._LOAD_CACHE.clear()
        return self.api.load(self.api.DEVICES_FILE)[did]


class TestTheProducer(_Base):

    def test_the_premise_the_agent_reports_all_four_files(self):
        got = {c["path"]: c for c in self.web_certs}
        self.assertEqual(set(got), set(WEB_FILES))
        self.assertAlmostEqual(got[SITE]["not_after"], WEB_FILES[SITE], delta=1)

    def test_the_premise_the_ingest_kept_them_with_a_number(self):
        stored = {c["path"]: c["not_after"] for c in self.hw("web")["cert_files"]}
        self.assertEqual(set(stored), set(WEB_FILES))
        self.assertTrue(all(isinstance(v, int) and v > 0 for v in stored.values()))

    def test_the_alert_still_fires_once_with_the_soonest_file_and_a_count(self):
        fired = [p for ev, p in self.events if ev == "cert_file_expiring" and p["device_id"] == "web"]
        self.assertEqual(len(fired), 1, self.events)
        self.assertEqual(fired[0]["path"], SITE)           # the lapsed one is the soonest
        self.assertEqual(fired[0]["count"], 2)             # the CA-bundle file and the far one are not counted
        self.assertEqual(fired[0]["days"], 0)


class TestTheHelpers(unittest.TestCase):

    def test_the_window_and_the_switch(self):
        self.assertEqual(ps.cert_file_days({}), 21)
        self.assertEqual(ps.cert_file_days({"cert_file_expiring_days": 45}), 45)
        self.assertIsNone(ps.cert_file_days({"cert_expiry_alerts_enabled": False}))
        self.assertEqual(ps.cert_file_days({"cert_expiry_alerts_enabled": True}), 21)
        for junk in (None, [], "x", 5):
            self.assertEqual(ps.cert_file_days(junk), 21, junk)
        for bad in ("soon", None, 0, -4, float("nan"), float("inf"), [], {}):
            self.assertEqual(ps.cert_file_days({"cert_file_expiring_days": bad}), 21, bad)

    def test_the_ca_bundle_is_left_out_by_all_four_prefixes(self):
        for pre in ps.CA_BUNDLE_PREFIXES:
            self.assertEqual(ps.expiring_cert_files([{"path": pre + "/x.pem", "not_after": NOW - 5}], NOW, 21), [], pre)
        self.assertEqual(len(ps.CA_BUNDLE_PREFIXES), 4)
        self.assertEqual(len(ps.expiring_cert_files([{"path": "/etc/ssl/private/site.pem", "not_after": NOW - 5}], NOW, 21)), 1)

    def test_sorted_soonest_first_with_the_expired_flag(self):
        rows = ps.expiring_cert_files([{"path": "/b", "not_after": NOW + 5 * DAY}, {"path": "/a", "not_after": NOW - 9},
                                       {"path": "/c", "not_after": NOW + 40 * DAY}, {"path": "/d", "not_after": NOW + DAY}],
                                      NOW, 21)
        self.assertEqual([r["path"] for r in rows], ["/a", "/d", "/b"])
        self.assertEqual([r["expired"] for r in rows], [True, False, False])
        self.assertEqual([r["days_left"] for r in rows], [0, 1, 5])

    def test_the_window_edge_is_in(self):
        edge = [{"path": "/e", "not_after": NOW + 21 * DAY}]
        self.assertEqual(len(ps.expiring_cert_files(edge, NOW, 21)), 1)
        self.assertEqual(ps.expiring_cert_files(edge, NOW, 20), [])

    def test_a_file_that_expires_this_second_has_expired(self):
        got = ps.expiring_cert_files([{"path": "/e", "not_after": NOW}], NOW, 21)
        self.assertEqual([(r["expired"], r["days_left"]) for r in got], [(True, 0)])
        got = ps.expiring_cert_files([{"path": "/e", "not_after": NOW + 1}], NOW, 21)
        self.assertEqual([(r["expired"], r["days_left"]) for r in got], [(False, 0)])

    def test_off_returns_nothing_and_expired_ignores_the_window(self):
        c = [{"path": "/a", "not_after": NOW - 9}, {"path": "/b", "not_after": NOW + DAY}]
        self.assertEqual(ps.expiring_cert_files(c, NOW, None), [])
        self.assertEqual([r["path"] for r in ps.expired_cert_files(c, NOW)], ["/a"])

    def test_junk_in_the_list_is_skipped_not_fatal(self):
        junk = [None, 5, "x", {}, {"path": ""}, {"path": "/a"}, {"path": "/a", "not_after": "soon"}, {"path": "/a", "not_after": 0},
                {"path": "/a", "not_after": -5}, {"path": "/a", "not_after": True}, {"path": 7, "not_after": 5},
                {"path": "/a", "not_after": float("nan")}, {"path": "/a", "not_after": float("inf")},
                {"path": "/ok", "not_after": NOW - 1}]
        self.assertEqual([r["path"] for r in ps.expiring_cert_files(junk, NOW, 21)], ["/ok"])
        self.assertEqual([c["path"] for c in ps.service_cert_files(junk)], ["/ok"])      # the coverage count reads this one
        for notalist in (None, "x", 5, {}, {"a": 1}):
            self.assertEqual(ps.expiring_cert_files(notalist, NOW, 21), [])

    def test_a_long_list_is_capped(self):
        many = [{"path": f"/p{i}", "not_after": NOW - 1} for i in range(900)]
        self.assertEqual(len(ps.expiring_cert_files(many, NOW, 21)), 500)


class TestTheAlert(_Base):
    """The alert keeps its behaviour on the shared helper: the switch, the window, one event per host, and the recovery."""

    def fired(self, cfg):
        self._build(self.api, cfg)
        try:
            return [p for ev, p in self.events if ev == "cert_file_expiring" and p["device_id"] == "web"]
        finally:
            self._build(self.api, {})

    def test_the_switch_silences_it(self):
        self.assertEqual(self.fired({"cert_expiry_alerts_enabled": False}), [])

    def test_the_window_is_the_operators(self):
        got = self.fired({"cert_file_expiring_days": 3})
        self.assertEqual([(p["count"], p["path"]) for p in got], [(1, SITE)])            # the 5-day file is outside 3 days
        got = self.fired({"cert_file_expiring_days": 7})
        self.assertEqual([p["count"] for p in got], [2])

    def test_it_recovers_when_the_files_are_renewed(self):
        self._build(self.api, {})
        self.events.clear()
        self.api._ingest_hardware("web", "web01", {"cert_files": _agent_certs({FAR: _when(400)})}, NOW)
        self.assertIn(("cert_file_renewed", {"device_id": "web", "name": "web01"}), self.events)
        self._build(self.api, {})

    def test_the_same_set_does_not_fire_twice(self):
        self._build(self.api, {})
        self.events.clear()
        self.api._ingest_hardware("web", "web01", {"cert_files": self.web_certs}, NOW)
        self.assertEqual([e for e in self.events if e[0] == "cert_file_expiring"], [])


class TestCompliance(_Base):

    def facts(self, devices=None):
        self.api._LOAD_CACHE.clear()
        return self.api._compliance_facts(devices if devices is not None else self.api.load(self.api.DEVICES_FILE))

    def test_the_facts_name_the_files_by_host_and_mark_the_expired(self):
        f = self.facts()
        self.assertEqual(f["tls_expiring"], [f"web01:{SITE} (expired)", f"web01:{LE}"])

    def test_the_hosts_that_reported_a_file_are_counted_and_the_ca_bundle_and_unmonitored_are_not(self):
        f = self.facts()
        self.assertEqual(f["tls_file_hosts"], 2)           # web01 and db01; win01 sent none; vm02 is unmonitored

    def test_the_control_fails_and_says_which(self):
        status, text = compliance._tls_control(self.facts())
        self.assertEqual(status, compliance.FAIL)
        self.assertIn(f"web01:{SITE} (expired)", text)
        self.assertIn("2 certificates expiring soon", text)

    def test_a_host_outside_the_view_is_not_named(self):
        """The facts embed host names, so a caller's view limits them (the tenant rule of the whole function)."""
        only_db = {k: v for k, v in self.api.load(self.api.DEVICES_FILE).items() if k == "db"}
        f = self.facts(only_db)
        self.assertEqual(f["tls_expiring"], [])
        self.assertEqual(f["tls_file_hosts"], 1)

    def test_the_compliance_window_is_the_reports_own(self):
        self.api.save(self.api.CONFIG_FILE, {"compliance_tls_expiring_days": 3})
        self.api._invalidate_load_cache(self.api.CONFIG_FILE)
        try:
            f = self.facts()
            self.assertEqual(f["tls_expiring"], [f"web01:{SITE} (expired)"])      # the 5-day file is outside a 3-day window
        finally:
            self.api.save(self.api.CONFIG_FILE, {})
            self.api._invalidate_load_cache(self.api.CONFIG_FILE)

    def test_the_switch_takes_the_files_out_of_the_report(self):
        self.api.save(self.api.CONFIG_FILE, {"cert_expiry_alerts_enabled": False})
        self.api._invalidate_load_cache(self.api.CONFIG_FILE)
        try:
            f = self.facts()
            self.assertEqual(f["tls_expiring"], [])
            self.assertEqual(f["tls_file_hosts"], 0)
        finally:
            self.api.save(self.api.CONFIG_FILE, {})
            self.api._invalidate_load_cache(self.api.CONFIG_FILE)


class TestTheControl(unittest.TestCase):
    """The control over hand-made facts: each source assesses it alone, and neither source is Not assessed (never a pass)."""

    def ctl(self, **facts):
        return compliance._tls_control(facts)

    def test_no_source_is_not_assessed_not_a_pass(self):
        self.assertEqual(self.ctl()[0], compliance.NOT_ASSESSED)
        self.assertEqual(self.ctl(tls_monitored=0, tls_file_hosts=0)[0], compliance.NOT_ASSESSED)

    def test_files_alone_assess_it(self):
        status, text = self.ctl(tls_monitored=0, tls_file_hosts=3)
        self.assertEqual(status, compliance.PASS)
        self.assertEqual(text, "The certificate files that hosts report are within their validity window.")

    def test_the_monitor_alone_reads_as_before(self):
        status, text = self.ctl(tls_monitored=2, tls_file_hosts=0)
        self.assertEqual((status, text), (compliance.PASS, "All monitored certificates are within their validity window."))

    def test_both_sources_say_so(self):
        status, text = self.ctl(tls_monitored=2, tls_file_hosts=1)
        self.assertEqual(status, compliance.PASS)
        self.assertEqual(text, "All monitored certificates and the certificate files that hosts report are within their validity "
                               "window.")

    def test_an_expiring_label_fails_whatever_the_coverage(self):
        self.assertEqual(self.ctl(tls_expiring=["a:/x"], tls_monitored=0, tls_file_hosts=0)[0], compliance.FAIL)


class TestRisk(_Base):

    def risk(self, did, **kw):
        a = self.api
        return a._device_risk(did, self.dev(did), {}, {}, {}, NOW, 180, hw_rec=self.hw(did), **kw)

    def factors(self, did, **kw):
        return {f["kind"]: f for f in self.risk(did, **kw)["factors"]}

    def test_an_expired_file_scores_once_for_the_host_with_the_path(self):
        f = self.factors("web")["cert_file_expired"]
        self.assertEqual(f["points"], self.api._RISK_WEIGHTS["cert_file_expired"])
        self.assertIn("1 certificate file expired", f["detail"])
        self.assertIn(SITE, f["detail"])
        self.assertNotIn(LE, f["detail"])                   # expiring soon is the alert's, this scores the lapsed
        self.assertNotIn(CA, f["detail"])

    def test_a_healthy_host_and_a_host_with_no_files_score_nothing(self):
        self.assertNotIn("cert_file_expired", self.factors("db"))
        self.assertNotIn("cert_file_expired", self.factors("win"))

    def test_the_cap_stops_a_long_list(self):
        w, cap = self.api._RISK_WEIGHTS["cert_file_expired"], self.api._RISK_CAPS["cert_file_expired"]
        many = {"cert_files": [{"path": f"/etc/nginx/ssl/{i}.pem", "not_after": NOW - 1} for i in range(9)]}
        f = {x["kind"]: x for x in self.api._device_risk("web", self.dev("web"), {}, {}, {}, NOW, 180, hw_rec=many)["factors"]}
        self.assertEqual(f["cert_file_expired"]["points"], cap)
        self.assertLess(w * 9, 10 ** 6)
        self.assertGreater(w * 9, cap)
        self.assertIn("9 certificate files expired", f["cert_file_expired"]["detail"])

    def test_the_weight_is_tunable_and_zero_turns_it_off(self):
        a = self.api
        a.save(a.CONFIG_FILE, {"risk_weight_cert_file_expired": 4})
        a._invalidate_load_cache(a.CONFIG_FILE)
        try:
            self.assertEqual(self.factors("web", weights=a._risk_weights())["cert_file_expired"]["points"], 4)
            a.save(a.CONFIG_FILE, {"risk_weight_cert_file_expired": 0})
            a._invalidate_load_cache(a.CONFIG_FILE)
            self.assertNotIn("cert_file_expired", self.factors("web", weights=a._risk_weights()))
        finally:
            a.save(a.CONFIG_FILE, {})
            a._invalidate_load_cache(a.CONFIG_FILE)

    def test_the_switch_takes_it_out_of_the_score(self):
        a = self.api
        a.save(a.CONFIG_FILE, {"cert_expiry_alerts_enabled": False})
        a._invalidate_load_cache(a.CONFIG_FILE)
        try:
            self.assertNotIn("cert_file_expired", self.factors("web"))
        finally:
            a.save(a.CONFIG_FILE, {})
            a._invalidate_load_cache(a.CONFIG_FILE)

    def test_junk_in_the_record_does_not_break_the_score(self):
        for junk in (None, {}, {"cert_files": "x"}, {"cert_files": [None, 5, {"path": "/a", "not_after": "x"}]}):
            r = self.api._device_risk("web", self.dev("web"), {}, {}, {}, NOW, 180, hw_rec=junk)
            self.assertNotIn("cert_file_expired", {f["kind"] for f in r["factors"]}, junk)


class TestChecksRow(_Base):

    def rows(self, did, cfg=None, **kw):
        a = self.api
        cfg = cfg or {}
        out = a._host_checks(did, self.dev(did), self.hw(did), [], NOW, 180, **{**a._checks_threshold_kwargs(cfg), **kw})
        return {r["key"]: r for r in out}

    def test_an_expired_file_is_a_critical_row_naming_it(self):
        r = self.rows("web")["cert_files"]
        self.assertEqual((r["status"], r["group"], r["name"]), ("critical", "security", "Certificate files"))
        self.assertIn("1 certificate file expired", r["output"])
        self.assertIn(SITE, r["output"])

    def test_a_file_inside_the_window_alone_is_a_warning(self):
        a = self.api
        hw = {"cert_files": [{"path": LE, "not_after": _when(5)}, {"path": FAR, "not_after": _when(400)}]}
        out = {r["key"]: r for r in a._host_checks("web", self.dev("web"), hw, [], NOW, 180, **a._checks_threshold_kwargs({}))}
        self.assertEqual(out["cert_files"]["status"], "warning")
        self.assertIn("1 certificate file expiring within 21 days", out["cert_files"]["output"])
        self.assertIn(LE, out["cert_files"]["output"])

    def test_the_window_is_the_operators(self):
        a = self.api
        hw = {"cert_files": [{"path": LE, "not_after": _when(5)}]}
        for days, want in ((3, "ok"), (7, "warning")):
            out = {r["key"]: r for r in a._host_checks(
                "web", self.dev("web"), hw, [], NOW, 180, **a._checks_threshold_kwargs({"cert_file_expiring_days": days}))}
            self.assertEqual(out["cert_files"]["status"], want, days)

    def test_a_healthy_host_is_a_green_row_that_counts_the_files(self):
        r = self.rows("db")["cert_files"]
        self.assertEqual(r["status"], "ok")
        self.assertIn("1 certificate file, none expiring within 21 days", r["output"])

    def test_no_files_no_row(self):
        self.assertNotIn("cert_files", self.rows("win"))

    def test_only_the_ca_bundle_is_no_row(self):
        a = self.api
        hw = {"cert_files": [{"path": CA, "not_after": NOW - 9}]}
        out = {r["key"] for r in a._host_checks("web", self.dev("web"), hw, [], NOW, 180, **a._checks_threshold_kwargs({}))}
        self.assertNotIn("cert_files", out)

    def test_the_switch_removes_the_row(self):
        self.assertNotIn("cert_files", self.rows("web", {"cert_expiry_alerts_enabled": False}))

    def test_a_disabled_check_is_flagged_not_dropped(self):
        a = self.api
        out = {r["key"]: r for r in a._host_checks("web", self.dev("web"), self.hw("web"), ["cert_files"], NOW, 180,
                                                  **a._checks_threshold_kwargs({}))}
        self.assertFalse(out["cert_files"]["enabled"])

    def test_every_real_caller_threads_the_window(self):
        """The window rides in _checks_threshold_kwargs, which the page, the fleet matrix, the preview and autonomy all spread."""
        src = (_CGI / "api.py").read_text()
        body = src[src.index("def _checks_threshold_kwargs("):]
        body = body[:body.index("\ndef handle_device_checks")]
        self.assertIn("'cert_file_days':", body)
        for f in ("api.py", "attention_handlers.py", "autonomy_ops_handlers.py"):
            self.assertIn("_checks_threshold_kwargs(", (_CGI / f).read_text(), f)


class TestNeedsAttention(_Base):

    def items(self):
        a = self.api
        a._LOAD_CACHE.clear()
        return [i for i in a._compute_attention() if i.get("kind") == "cert_files"]

    def test_a_lapsed_host_is_one_critical_item_with_the_path_and_no_day_count(self):
        got = self.items()
        self.assertEqual(len(got), 1, got)
        i = got[0]
        self.assertEqual((i["device"], i["severity"], i["device_id"]), ("web01", "critical", "web"))
        self.assertEqual(i["summary"], f"1 certificate file expired: {SITE}")
        self.assertFalse(re.search(r"\d+ days?", i["summary"]), "an 'ignore' is keyed by this text, so it must not change daily")

    def test_expiring_only_is_a_warning(self):
        a = self.api
        a.save(a.HARDWARE_FILE, {"web": {"cert_files": [{"path": LE, "not_after": _when(5)}]}})
        a._invalidate_load_cache(a.HARDWARE_FILE)
        try:
            i = self.items()[0]
            self.assertEqual((i["severity"], i["summary"]), ("warning", f"1 certificate file expiring soon: {LE}"))
        finally:
            a.save(a.HARDWARE_FILE, {})
            self._rebuild()

    def _rebuild(self):
        self._build(self.api, {})

    def test_a_muted_host_event_removes_it(self):
        a = self.api
        a.save(a.ALERT_MUTES_FILE, {"mutes": [{"id": "m1", "device_id": "web", "event": "cert_file_expiring"}]})
        a._ALERT_MUTE_SET_CACHE.update(mtime=None, checked=0)
        try:
            muted = [i for i in a._compute_attention() if i.get("kind") == "cert_files"]
            self.assertEqual(muted, [], "the mute row for kind cert_files is missing or does not match the event")
            a.save(a.ALERT_MUTES_FILE, {"mutes": [{"id": "m2", "device_id": "db", "event": "cert_file_expiring"}]})
            a._ALERT_MUTE_SET_CACHE.update(mtime=None, checked=0)
            self.assertEqual(len([i for i in a._compute_attention() if i.get("kind") == "cert_files"]), 1,
                             "a mute for another host must leave this one standing")
        finally:
            a.save(a.ALERT_MUTES_FILE, {"mutes": []})
            a._ALERT_MUTE_SET_CACHE.update(mtime=None, checked=0)

    def test_the_mute_rows_exist_for_both_severities(self):
        for sev in ("critical", "warning"):
            self.assertEqual(self.api._NA_MUTE_EVENTS[("cert_files", sev)], ("cert_file_expiring",))

    def test_the_switch_removes_it(self):
        a = self.api
        a.save(a.CONFIG_FILE, {"cert_expiry_alerts_enabled": False})
        a._invalidate_load_cache(a.CONFIG_FILE)
        try:
            self.assertEqual([i for i in a._compute_attention() if i.get("kind") == "cert_files"], [])
        finally:
            a.save(a.CONFIG_FILE, {})
            a._invalidate_load_cache(a.CONFIG_FILE)

    def test_an_unmonitored_host_raises_no_item(self):
        self.assertNotIn("vm02", [i["device"] for i in self.items()])

    def test_the_page_route_exists_for_the_kind(self):
        js = (ROOT / "server/html/static/js/app.js").read_text()
        self.assertTrue(re.search(r"cert_files:\s*'devices'", js))


class TestAdvisory(_Base):

    def build(self, days=21, hosts=("web", "db", "win")):
        a = self.api
        a._LOAD_CACHE.clear()
        devs = {k: v for k, v in a.load(a.DEVICES_FILE).items() if k in hosts}
        return advisory.build(devs, hw_by_dev=a.load(a.HARDWARE_FILE), cert_file_days=days, now=NOW)

    def by_id(self, adv):
        return {g["id"]: g for g in adv["findings"]}

    def test_a_lapsed_file_is_a_high_finding_for_that_host_only(self):
        g = self.by_id(self.build())["exp.certfile.expired"]
        self.assertEqual(g["severity"], "high")
        self.assertEqual([d["device"] for d in g["devices"]], ["web01"])
        self.assertEqual(g["evidence"], [SITE])
        self.assertIn("1 certificate file expired", g["title"])

    def test_a_file_inside_the_window_is_a_second_finding_with_its_own_severity(self):
        g = self.by_id(self.build())["exp.certfile"]
        self.assertEqual(g["severity"], "medium")                  # 5 days left
        self.assertEqual(g["evidence"], [LE])
        self.assertIn("expiring within 21 days", g["title"])

    def test_three_days_or_fewer_raises_it_to_high(self):
        a = self.api
        for days, want in ((2, "high"), (3, "high"), (4, "medium")):
            hw = {"web": {"cert_files": [{"path": LE, "not_after": _when(days)}]}}
            adv = advisory.build({"web": a.load(a.DEVICES_FILE)["web"]}, hw_by_dev=hw, cert_file_days=21, now=NOW)
            self.assertEqual(self.by_id(adv)["exp.certfile"]["severity"], want, days)

    def test_the_ca_bundle_file_never_appears(self):
        blob = repr(self.build())
        self.assertNotIn(CA, blob)

    def test_a_healthy_host_and_a_host_with_no_files_have_none(self):
        adv = self.build(hosts=("db", "win"))
        self.assertFalse([f for f in adv["findings"] if f["id"].startswith("exp.certfile")])

    def test_off_means_none(self):
        adv = self.build(days=None)
        self.assertFalse([f for f in adv["findings"] if f["id"].startswith("exp.certfile")])

    def test_the_default_for_a_caller_that_does_not_pass_the_window_is_none(self):
        a = self.api
        adv = advisory.build({"web": a.load(a.DEVICES_FILE)["web"]}, hw_by_dev=a.load(a.HARDWARE_FILE), now=NOW)
        self.assertFalse([f for f in adv["findings"] if f["id"].startswith("exp.certfile")])

    def test_the_ai_brief_carries_counts_and_never_a_path_or_a_host(self):
        brief = advisory.summarize_for_ai(self.build(), "the fleet")
        self.assertIn("certificate file", brief)                  # the control: the finding is in the brief at all
        for secret in (SITE, LE, "web01"):
            self.assertNotIn(secret, brief)

    def test_through_the_real_handler_with_the_operators_window(self):
        a = self.api
        a.save(a.CONFIG_FILE, {"cert_file_expiring_days": 3})
        a._invalidate_load_cache(a.CONFIG_FILE)
        try:
            devs = {k: v for k, v in a.load(a.DEVICES_FILE).items() if k == "web"}
            ids = {f["id"] for f in a._build_advisory(devs)["findings"]}
            self.assertIn("exp.certfile.expired", ids)
            self.assertNotIn("exp.certfile", ids)                   # 5 days is outside a 3-day window
            a.save(a.CONFIG_FILE, {"cert_expiry_alerts_enabled": False})
            a._invalidate_load_cache(a.CONFIG_FILE)
            ids = {f["id"] for f in a._build_advisory(devs)["findings"]}
            self.assertFalse({i for i in ids if i.startswith("exp.certfile")})
        finally:
            a.save(a.CONFIG_FILE, {})
            a._invalidate_load_cache(a.CONFIG_FILE)


class TestDashboardWidget(_Base):
    """The Expiring certificates widget had its own copy of the CA-bundle rule, a fixed 30-day window and no switch, and it read the
    whole hardware store: for a host outside the caller's view it printed the device id as the name. The three hardware counts
    (SMART, UPS, temperature) added up every tenant's hosts."""

    def widget(self, visible, cfg=None, want=("tls",)):
        a = self.api
        a._LOAD_CACHE.clear()
        devices = {k: v for k, v in a.load(a.DEVICES_FILE).items() if k in visible}
        return a._dashboard_extra_widgets(devices, cfg or {}, NOW, want=set(want))

    def test_rows_name_the_host_and_the_days_and_leave_out_the_ca_bundle(self):
        got = self.widget({"web", "db"})["tls"]
        self.assertEqual(got, [{"name": "web01", "days": 0}, {"name": "web01", "days": 5}])

    def test_a_host_outside_the_view_is_not_named_even_by_its_id(self):
        got = self.widget({"db"})["tls"]
        self.assertEqual(got, [])
        out = self.widget({"db"}, want=("tls", "smart", "ups", "temp"))
        self.assertNotIn("web", repr(out))
        self.assertNotIn("vm", repr(out["tls"]))

    def test_the_counts_cover_only_the_view(self):
        a = self.api
        a.save(a.HARDWARE_FILE, {"web": {"_smart_failed": True, "_temp_high": True, "_ups_on_battery": True},
                                 "db": {}, "vm": {"_smart_failed": True}})
        a._invalidate_load_cache(a.HARDWARE_FILE)
        try:
            mine = self.widget({"db"}, want=("smart", "ups", "temp"))
            self.assertEqual((mine["smart"]["count"], mine["ups"]["count"], mine["temp"]["count"]), (0, 0, 0))
            both = self.widget({"db", "web"}, want=("smart", "ups", "temp"))
            self.assertEqual((both["smart"]["count"], both["ups"]["count"], both["temp"]["count"]), (1, 1, 1))
        finally:
            self._build(a, {})

    def test_the_switch_empties_it(self):
        self.assertEqual(self.widget({"web"}, {"cert_expiry_alerts_enabled": False})["tls"], [])

    def test_it_looks_thirty_days_ahead_whatever_the_alert_window_is(self):
        a = self.api
        a.save(a.HARDWARE_FILE, {"web": {"cert_files": [{"path": LE, "not_after": _when(25)}, {"path": FAR, "not_after": _when(35)}]}})
        a._invalidate_load_cache(a.HARDWARE_FILE)
        try:
            self.assertEqual(self.widget({"web"}, {"cert_file_expiring_days": 3})["tls"], [{"name": "web01", "days": 25}])
        finally:
            self._build(a, {})

    def test_it_shows_the_six_soonest(self):
        a = self.api
        a.save(a.HARDWARE_FILE, {"web": {"cert_files": [{"path": f"/etc/nginx/ssl/{i}.pem", "not_after": _when(i + 1)}
                                                          for i in range(9)]}})
        a._invalidate_load_cache(a.HARDWARE_FILE)
        try:
            self.assertEqual([r["days"] for r in self.widget({"web"})["tls"]], [1, 2, 3, 4, 5, 6])
        finally:
            self._build(a, {})


class TestOneDefinition(unittest.TestCase):

    def test_the_ca_bundle_prefixes_are_written_once_on_the_server(self):
        """The alert had its own copy of the prefixes; six readers sharing one is the point."""
        for needle in ("/usr/share/ca-certificates", "/etc/pki/ca-trust"):
            owners = sorted(p.name for p in _CGI.glob("*.py") if needle in p.read_text())
            self.assertEqual(owners, ["posture_signals.py"], (needle, owners))

    def test_every_reader_goes_through_the_helper(self):
        users = {name: (_CGI / name).read_text() for name in
                 ("api.py", "checks.py", "advisory.py", "advisory_handlers.py")}
        self.assertGreaterEqual(users["api.py"].count("posture_signals.expiring_cert_files("), 3)   # ingest, compliance, attention
        self.assertIn("posture_signals.expired_cert_files(", users["api.py"])                      # risk
        self.assertIn("posture_signals.expiring_cert_files(", users["checks.py"])
        self.assertIn("posture_signals.expiring_cert_files(", users["advisory.py"])
        self.assertIn("posture_signals.cert_file_days(", users["advisory_handlers.py"])

    def test_the_risk_factor_is_in_every_registry(self):
        api = _fresh_api()
        js = (ROOT / "server/html/static/js/app.js").read_text()
        html = (ROOT / "server/html/index.html").read_text()
        i18n = (ROOT / "server/html/static/js/i18n.js").read_text()
        self.assertEqual(api._RISK_WEIGHTS["cert_file_expired"], 10)
        self.assertEqual(api._RISK_CAPS["cert_file_expired"], 20)
        self.assertIn("cert_file_expired: 10", js)
        self.assertTrue(re.search(r"cert_file_expired:\s*'Expired certificate file'", js))
        self.assertIn('id="ap-rw-cert_file_expired"', html)
        self.assertIn('"Expired certificate file":', i18n)

    def test_the_new_wording_is_in_the_dictionary_in_six_languages(self):
        i18n = (ROOT / "server/html/static/js/i18n.js").read_text()
        for key in ("Expired certificate file",
                    "Certificate files",
                    "The certificate files that hosts report are within their validity window.",
                    "All monitored certificates and the certificate files that hosts report are within their validity window."):
            m = re.search(r'^\s*"' + re.escape(key) + r'":\s*\{([^\n]*)\}', i18n, re.M)
            self.assertTrue(m, key)
            for lang in ("fr", "de", "zh", "hi", "es", "ar"):
                self.assertIn(f'"{lang}":', m.group(1), (key, lang))

    def test_the_docs_say_so(self):
        for name, phrase in (("compliance.md", "certificate files"), ("risk.md", "expired certificate file"),
                             ("checks.md", "Certificate files"), ("security-advisory.md", "certificate file")):
            self.assertIn(phrase, (ROOT / "docs" / name).read_text(), name)


if __name__ == "__main__":
    unittest.main()

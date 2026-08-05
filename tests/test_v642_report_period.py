"""v6.4.2: reports say what CHANGED, not only where things stand.

Every section was a live counter, so two consecutive weekly reports were
indistinguishable — the recipient could not tell whether the team was winning.
No new collection was needed: MTTR/MTTA come from the alert store, the deltas
from the daily health/compliance samplers, update runs from the update log.

Run: python3 -m pytest tests/test_v642_report_period.py -q
"""
import os
import sys
import time
import tempfile
import unittest
import importlib.util
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v642_period", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_D = 86400


class TestExtractedResolutionStats(unittest.TestCase):
    """The blocker: handle_alert_resolution_stats ends in respond(), which
    raises, so a report builder could not call it. The computation is now a
    pure helper and the handler is a thin scoped wrapper."""

    def test_it_computes_from_first_seen_not_ts(self):
        """`ts` is rewritten on every coalesced re-fire, so measuring from it
        flatters a noisy incident — the noisier it was, the better it looked."""
        now = int(time.time())
        alerts = [{"id": "a1", "device_name": "web01",
                   "first_seen": now - 7200, "ts": now - 600,
                   "resolved_at": now - 1800, "severity": "high", "event": "x"}]
        s = api._alert_resolution_stats(alerts, 30)
        self.assertEqual(s["resolved_count"], 1)
        self.assertEqual(s["mttr_mean"], 5400)   # from first_seen, not ts

    def test_it_takes_an_already_filtered_list(self):
        """Filtering inside would hide the scope decision from the call site,
        which is how the cross-tenant leak this guards against happened."""
        import inspect
        src = inspect.getsource(api._alert_resolution_stats)
        self.assertNotIn("_filter_alerts_for_caller", src)
        self.assertIn("_filter_alerts_for_caller",
                      inspect.getsource(api.handle_alert_resolution_stats))

    def test_open_alerts_are_not_counted_as_resolved(self):
        now = int(time.time())
        s = api._alert_resolution_stats(
            [{"id": "a", "first_seen": now - 100, "severity": "low", "event": "e"}], 30)
        self.assertEqual(s["resolved_count"], 0)


class TestPeriodSection(unittest.TestCase):
    def setUp(self):
        self.now = now = int(time.time())
        api.save(api.DEVICES_FILE, {
            "d1": {"name": "web01", "token": "t", "monitored": True, "last_seen": now}})
        api.save(api.ALERTS_FILE, {"alerts": [
            {"id": "a1", "device_id": "d1", "first_seen": now - 6 * _D, "ts": now - 6 * _D,
             "resolved_at": now - 6 * _D + 5400, "acknowledged_at": now - 6 * _D + 1800,
             "severity": "high", "event": "x"},
            {"id": "a2", "device_id": "d1", "first_seen": now - 3 * _D, "ts": now - 3 * _D,
             "resolved_at": now - 3 * _D + 7200, "severity": "low", "event": "y"},
            {"id": "a3", "device_id": "d1", "first_seen": now - 2 * _D, "ts": now - 2 * _D,
             "severity": "low", "event": "z"},                      # still open
            {"id": "a4", "device_id": "d1", "first_seen": now - 200 * _D,
             "ts": now - 200 * _D, "severity": "low", "event": "old"},   # outside window
        ]})
        # Both samplers write {'fleet': [{date, ts, score, ...}]} — verified
        # against _maybe_sample_health / _maybe_sample_compliance, not assumed.
        api.save(api.HEALTH_HIST_FILE, {"fleet": [
            {"date": "a", "ts": now - 40 * _D, "score": 79},
            {"date": "b", "ts": now - 1 * _D, "score": 86}]})
        api.save(api.COMPLIANCE_HIST_FILE, {"fleet": [
            {"date": "a", "ts": now - 40 * _D, "score": 91},
            {"date": "b", "ts": now - 1 * _D, "score": 94}]})
        api.save(api.UPDATE_LOGS_FILE, {"d1": [
            {"ts": now - 5 * _D}, {"ts": now - 2 * _D}, {"ts": now - 90 * _D}]})
        api._LOAD_CACHE.clear()
        self.rep = api._build_fleet_report()
        self.per = self.rep.get("period") or {}

    def test_the_section_is_built(self):
        self.assertTrue(self.per, "no period section in the report")

    def test_activity_counts(self):
        self.assertEqual(self.per["alerts_opened"], 3)    # a4 is outside the window
        self.assertEqual(self.per["alerts_resolved"], 2)  # a3 is still open

    def test_deltas_measure_against_the_start_of_the_window(self):
        self.assertEqual(self.per["delta"]["health_score"], 7)
        self.assertEqual(self.per["delta"]["compliance_pct"], 3)
        self.assertEqual(self.per["previous"]["health_score"], 79)

    def test_update_runs_are_windowed(self):
        self.assertEqual(self.per["patches_applied_runs"], 2)   # the 90d run is out

    def test_no_history_yields_no_delta_rather_than_zero(self):
        """A 0 would read as 'no change' when the truth is 'not enough
        history' — a materially different statement to a customer."""
        api.save(api.HEALTH_HIST_FILE, {"fleet": [
            {"date": "b", "ts": self.now - 1 * _D, "score": 86}]})
        api._LOAD_CACHE.clear()
        per = api._build_fleet_report().get("period") or {}
        self.assertIsNone(per["delta"]["health_score"])

    def test_it_is_a_real_selectable_section(self):
        self.assertIn("period", api._REPORT_SECTIONS)
        sub = api._filter_report_sections(self.rep, ["devices", "period"])
        self.assertIn("period", sub)
        self.assertNotIn("compliance", sub)


class TestRenderers(TestPeriodSection):
    def test_the_email_carries_it(self):
        _subj, body = api._render_report_email(self.rep)
        self.assertIn("Last 30 days", body)
        self.assertIn("Alerts", body)
        self.assertIn("+7", body)

    def test_the_email_still_carries_everything_else(self):
        """The period block was inserted mid-renderer; pin the neighbours so a
        future edit there cannot quietly delete them."""
        _subj, body = api._render_report_email(self.rep)
        for expected in ("Fleet health score", "Devices", "Needs attention",
                         "Patches", "CVEs", "Lowest-scoring devices"):
            self.assertIn(expected, body, f"{expected!r} lost from the email body")

    def test_the_csv_carries_it(self):
        csv = api._fleet_report_csv_bytes(self.rep).decode()
        rows = [l for l in csv.splitlines() if l.startswith("Period")]
        self.assertTrue(rows)
        self.assertIn("Period,Alerts resolved,2", csv)

    def test_the_csv_blanks_an_absent_delta(self):
        api.save(api.HEALTH_HIST_FILE, {"fleet": [
            {"date": "b", "ts": self.now - 1 * _D, "score": 86}]})
        api._LOAD_CACHE.clear()
        csv = api._fleet_report_csv_bytes(api._build_fleet_report()).decode()
        self.assertIn("Period,Health score change,\r\n", csv)


if __name__ == "__main__":
    unittest.main(verbosity=2)

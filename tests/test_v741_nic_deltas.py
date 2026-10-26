#!/usr/bin/env python3
"""v7.4.1, issue #37: NIC errors and drops are judged apart, and a long gap between
samples no longer reads as a burst.

The reporter's media server drops about 80 packets per 10 s while it streams, with
no errors, and paged as "a failing cable, dirty SFP or dying switch port": the agent
sends rx/tx errors and rx/tx drops as four counters, and the server added all four
together and compared the sum with one fleet-wide floor. Raising the floor hid real
errors on every host. Their follow-up: after a two-minute restart the same host
showed +1020, because a missed sample slot makes the next delta cover twice the time.

Pure helpers (checks.py), the real heartbeat ingest, and the real alert path.
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_CGI = Path(__file__).resolve().parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v741-nic-"))
os.environ.setdefault("REQUEST_METHOD", "GET")
os.environ.setdefault("PATH_INFO", "/")
os.environ.setdefault("CONTENT_LENGTH", "0")
_spec = importlib.util.spec_from_file_location("api_v741_nic", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
import checks  # noqa: E402  (server/cgi-bin is on sys.path)


class TestGapScale(unittest.TestCase):
    def test_nothing_is_scaled_without_history(self):
        self.assertEqual(checks.nic_gap_scale(600, []), 1.0)
        self.assertEqual(checks.nic_gap_scale(600, [60, 600]), 1.0)     # two gaps: too few

    def test_a_normal_gap_changes_nothing(self):
        self.assertEqual(checks.nic_gap_scale(60, [60, 60, 60, 60]), 1.0)
        self.assertEqual(checks.nic_gap_scale(89, [60, 60, 60, 89]), 1.0)   # within half again

    def test_a_missed_slot_is_scaled_back_to_the_usual_gap(self):
        self.assertEqual(checks.nic_gap_scale(120, [60, 60, 60, 120]), 0.5)
        self.assertAlmostEqual(checks.nic_gap_scale(600, [60, 60, 60, 600]), 0.1)

    def test_it_never_scales_up(self):
        self.assertEqual(checks.nic_gap_scale(5, [60, 60, 60, 5]), 1.0)

    def test_the_median_is_not_dragged_by_one_outage(self):
        self.assertEqual(checks.nic_gap_scale(1200, [600, 600, 600, 1200]), 0.5)

    def test_two_long_gaps_in_a_row_are_the_new_normal(self):
        self.assertEqual(checks.nic_gap_scale(1200, [600, 1200, 1200]), 1.0)

    def test_nonsense_is_ignored(self):
        for gap in (0, -5, None, "x", True):
            self.assertEqual(checks.nic_gap_scale(gap, [60, 60, 60]), 1.0)


class TestPartsAndBreach(unittest.TestCase):
    def test_an_entry_from_before_the_split_is_read_as_errors(self):
        self.assertEqual(checks.nic_parts({"err_delta": 12}), (12, 0))

    def test_split_fields_win(self):
        self.assertEqual(checks.nic_parts({"err_delta": 99, "errors_delta": 2, "drops_delta": 7}), (2, 7))

    def test_garbage_counts_as_nothing(self):
        for n in (None, {}, {"errors_delta": -3, "drops_delta": True}, {"err_delta": "9"}):
            self.assertEqual(checks.nic_parts(n), (0, 0))

    def test_without_a_drops_floor_errors_and_drops_are_added_as_before(self):
        self.assertIsNotNone(checks.nic_breach({"errors_delta": 3, "drops_delta": 3}, 5, None))
        self.assertIsNone(checks.nic_breach({"errors_delta": 2, "drops_delta": 2}, 5, None))

    def test_with_a_drops_floor_they_are_judged_apart(self):
        n = {"errors_delta": 3, "drops_delta": 3}
        self.assertIsNone(checks.nic_breach(n, 5, 5))               # neither reaches its own floor
        self.assertEqual(checks.nic_breach({"errors_delta": 5, "drops_delta": 0}, 5, 500),
                         {"errors": 5, "drops": 0})
        self.assertEqual(checks.nic_breach({"errors_delta": 0, "drops_delta": 500}, 5, 500),
                         {"errors": 0, "drops": 500})

    def test_the_reporters_media_server_does_not_breach(self):
        # ~80 drops per 10 s sample, no errors, drops floor 500, errors floor 5
        self.assertIsNone(checks.nic_breach({"errors_delta": 0, "drops_delta": 340}, 5, 500))

    def test_a_drops_floor_of_zero_means_drops_never_breach(self):
        self.assertIsNone(checks.nic_breach({"errors_delta": 0, "drops_delta": 10 ** 9}, 5, 0))
        self.assertIsNotNone(checks.nic_breach({"errors_delta": 5, "drops_delta": 10 ** 9}, 5, 0))

    def test_summary_names_what_rose(self):
        self.assertEqual(checks.nic_summary(12, 0), "+12 errors")
        self.assertEqual(checks.nic_summary(1, 0), "+1 error")
        self.assertEqual(checks.nic_summary(0, 340), "+340 drops")
        self.assertEqual(checks.nic_summary(2, 1), "+2 errors, +1 drop")


class TestFloors(unittest.TestCase):
    def test_the_fleet_values_apply_to_a_host_with_none_of_its_own(self):
        self.assertEqual(checks.nic_floors({}, 5, None), (5, None))
        self.assertEqual(checks.nic_floors({"metric_thresholds": {}}, 20, 300), (20, 300))

    def test_a_hosts_own_values_win(self):
        dev = {"metric_thresholds": {"nic_err_alert_min": 2, "nic_drop_alert_min": 900}}
        self.assertEqual(checks.nic_floors(dev, 5, 100), (2, 900))

    def test_a_hosts_own_zero_turns_its_drops_off_whatever_the_fleet_says(self):
        dev = {"metric_thresholds": {"nic_drop_alert_min": 0}}
        self.assertEqual(checks.nic_floors(dev, 5, 100), (5, 0))
        self.assertEqual(checks.nic_floors(dev, 5, None), (5, 0))

    def test_a_bad_own_value_falls_back_to_the_fleet(self):
        dev = {"metric_thresholds": {"nic_err_alert_min": 0, "nic_drop_alert_min": "x"}}
        self.assertEqual(checks.nic_floors(dev, 5, 100), (5, 100))
        self.assertEqual(checks.nic_floors(None, 5, None), (5, None))


class _Base(unittest.TestCase):
    _NAMES = ("DEVICES_FILE", "CONFIG_FILE", "get_json_body", "method", "respond", "fire_webhook")

    def setUp(self):
        self._saved = {n: getattr(api, n) for n in self._NAMES}
        tmp = Path(tempfile.mkdtemp(prefix="rp-v741-nic-t-"))
        for n in ("DEVICES_FILE", "CONFIG_FILE"):
            setattr(api, n, tmp / self._saved[n].name)
        api.save(api.CONFIG_FILE, {})
        api._invalidate_load_cache(api.CONFIG_FILE)
        api.respond = lambda status, body: (_ for _ in ()).throw(SystemExit(0))
        self.fired = []
        api.fire_webhook = lambda ev, payload: self.fired.append((ev, payload))

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(api, n, v)

    def events(self):
        return [e for e, _ in self.fired]


class TestIngest(_Base):
    """The real heartbeat, reading back what landed in the device store."""

    def seed(self, sysinfo):
        api.save(api.DEVICES_FILE, {"d1": {"id": "d1", "name": "web01", "token": "tok",
                                           "monitored": True, "sysinfo": sysinfo}})

    def beat(self, nio):
        api.get_json_body = lambda: {"device_id": "d1", "token": "tok",
                                     "sysinfo": {"network_io": nio}}
        api.method = lambda: "POST"
        try:
            api.handle_heartbeat()
        except SystemExit:
            pass
        api._invalidate_load_cache(api.DEVICES_FILE)
        return api.load(api.DEVICES_FILE)["d1"]["sysinfo"]

    def prior(self, counters, ago, gaps):
        self.seed({"network_io": [dict(iface="eth0", **counters)],
                   "network_io_ts": int(time.time()) - ago, "network_io_gaps": gaps})

    def test_errors_and_drops_are_kept_apart(self):
        self.prior({"rx_err": 10, "tx_err": 0, "rx_drop": 100, "tx_drop": 50}, 600, [])
        si = self.beat([dict(iface="eth0", rx_err=13, tx_err=2, rx_drop=190, tx_drop=60)])
        row = si["network_io"][0]
        self.assertEqual((row["errors_delta"], row["drops_delta"]), (5, 100))
        self.assertEqual(row["err_delta"], 105, "err_delta stays the plain sum")

    def test_one_group_resetting_does_not_hide_the_other(self):
        self.prior({"rx_err": 900, "tx_err": 0, "rx_drop": 10, "tx_drop": 0}, 600, [])
        si = self.beat([dict(iface="eth0", rx_err=3, tx_err=0, rx_drop=30, tx_drop=0)])
        row = si["network_io"][0]
        self.assertEqual((row["errors_delta"], row["drops_delta"]), (0, 20))

    def test_a_normal_gap_is_not_scaled(self):
        self.prior({"rx_drop": 1000}, 600, [600, 600, 600])
        row = self.beat([dict(iface="eth0", rx_drop=1800)])["network_io"][0]
        self.assertEqual(row["drops_delta"], 800)
        self.assertNotIn("delta_scale", row)

    def test_a_missed_slot_is_scaled_back(self):
        # the reporter's case: a steady ~8 drops/s, and one slot missed in a restart
        self.prior({"rx_drop": 1000}, 1200, [600, 600, 600])
        si = self.beat([dict(iface="eth0", rx_drop=2020)])
        row = si["network_io"][0]
        self.assertEqual(row["err_delta"], 1020, "the raw number is still what the host reported")
        self.assertEqual(row["drops_delta"], 510)
        self.assertEqual(row["delta_scale"], 0.5)

    def test_the_gap_history_is_kept_and_capped(self):
        self.prior({"rx_drop": 0}, 600, [600] * 9)
        si = self.beat([dict(iface="eth0", rx_drop=0)])
        self.assertEqual(len(si["network_io_gaps"]), 5)
        self.assertAlmostEqual(si["network_io_ts"], int(time.time()), delta=5)
        self.assertLessEqual(si["network_io_gaps"][-1] - 600, 5)

    def test_the_first_sample_has_nothing_to_scale_or_diff(self):
        self.seed({})
        row = self.beat([dict(iface="eth0", rx_err=5000, rx_drop=5000)])["network_io"][0]
        self.assertEqual((row["err_delta"], row["errors_delta"], row["drops_delta"]), (0, 0, 0))

    def test_the_bookkeeping_is_not_sent_to_every_open_page(self):
        self.assertTrue({"network_io_ts", "network_io_gaps"} <= api._ROSTER_SYSINFO_OMIT)


class TestAlertPath(_Base):
    """_ingest_posture_v3110 and the real _record_alert, as the heartbeat runs them."""

    def setUp(self):
        super().setUp()
        self.dev = "dev-nic-v741"
        try:
            api._entity_write_one(api.POSTURE_STATE_FILE, self.dev, None)
        except Exception:
            pass

    def cfg(self, **kw):
        api.save(api.CONFIG_FILE, kw)
        api._invalidate_load_cache(api.CONFIG_FILE)

    def ingest(self, nio, dev=None):
        api._ingest_posture_v3110(self.dev, "media01", {"mounts": [], "network_io": nio}, dev=dev or {})

    def two(self, quiet, noisy, **kw):
        self.cfg(**kw)
        self.ingest([dict(iface="eth0", **quiet)])
        self.fired.clear()
        self.ingest([dict(iface="eth0", **noisy)])

    def detail(self):
        return [p["detail"] for e, p in self.fired if e == "nic_errors"]

    def test_the_reporters_case_today_it_pages_as_a_failing_cable(self):
        # no drops floor set: errors and drops are added, exactly as before
        self.two({"err_delta": 0}, {"errors_delta": 0, "drops_delta": 80, "err_delta": 80})
        self.assertEqual(self.events(), ["nic_errors"])
        self.assertNotIn("failing cable, dirty SFP", self.detail()[0],
                         "drops alone must not be blamed on the cable")
        self.assertIn("+80 drops", self.detail()[0])

    def test_with_a_drops_floor_the_media_server_stays_quiet(self):
        self.two({"err_delta": 0}, {"errors_delta": 0, "drops_delta": 340, "err_delta": 340},
                 nic_drop_alert_min=500)
        self.assertEqual(self.events(), [])

    def test_and_a_real_error_still_pages_at_the_small_count(self):
        self.two({"err_delta": 0}, {"errors_delta": 7, "drops_delta": 340, "err_delta": 347},
                 nic_drop_alert_min=500)
        self.assertEqual(self.events(), ["nic_errors"])
        self.assertIn("+7 errors", self.detail()[0])
        self.assertIn("failing cable, dirty SFP", self.detail()[0])

    def test_a_drops_floor_of_zero_turns_drop_alerts_off(self):
        self.two({"err_delta": 0}, {"errors_delta": 0, "drops_delta": 10 ** 6, "err_delta": 10 ** 6},
                 nic_drop_alert_min=0)
        self.assertEqual(self.events(), [])

    def test_a_hosts_own_floors_beat_the_fleets(self):
        dev = {"metric_thresholds": {"nic_drop_alert_min": 100000}}
        self.cfg(nic_drop_alert_min=50)
        self.ingest([dict(iface="eth0", err_delta=0)], dev=dev)
        self.fired.clear()
        self.ingest([dict(iface="eth0", errors_delta=0, drops_delta=5000, err_delta=5000)], dev=dev)
        self.assertEqual(self.events(), [])
        # the fleet's own value would have paged the same sample on another host
        api._entity_write_one(api.POSTURE_STATE_FILE, self.dev, None)
        self.ingest([dict(iface="eth0", err_delta=0)], dev={})
        self.fired.clear()
        self.ingest([dict(iface="eth0", errors_delta=0, drops_delta=5000, err_delta=5000)], dev={})
        self.assertEqual(self.events(), ["nic_errors"])

    def test_a_scaled_sample_does_not_page_where_the_raw_one_would(self):
        # +1020 raw, scaled to 510 by a gap of twice the usual: below a floor of 600
        self.two({"err_delta": 0}, {"errors_delta": 0, "drops_delta": 510, "err_delta": 1020,
                                    "delta_scale": 0.5}, nic_err_alert_min=600)
        self.assertEqual(self.events(), [])

    def test_the_alert_row_that_lands_in_the_inbox_carries_the_wording(self):
        api.save(api.ALERTS_FILE, {"alerts": []})
        api._invalidate_load_cache(api.ALERTS_FILE)
        api._record_alert("nic_errors", {"device_id": "d1", "name": "media01", "iface": "eth0",
                                         "detail": api._nic_alert_detail("eth0", {"errors": 0, "drops": 80})})
        rows = (api.load(api.ALERTS_FILE) or {}).get("alerts", [])
        self.assertEqual(len(rows), 1)
        self.assertIn("+80 drops", rows[0]["payload"].get("detail", ""))


class TestReliabilityAndCheckRow(_Base):
    def score(self, nio, dev=None, **cfg):
        api.save(api.CONFIG_FILE, cfg)
        api._invalidate_load_cache(api.CONFIG_FILE)
        d = {"name": "h", "monitored": True, "last_seen": time.time(),
             "sysinfo": {"network_io": nio}}
        d.update(dev or {})
        r = api._device_reliability("d", d, {}, {}, {}, {}, {}, {}, int(time.time()))
        return r["score"]

    def row(self, nio, dev=None, **kw):
        d = {"id": "d1", "name": "h", "sysinfo": {"network_io": nio}}
        d.update(dev or {})
        rows = checks._host_checks("d1", d, **kw)
        return [r for r in rows if r["key"] == "nic_errors"]

    def test_the_reliability_score_follows_the_same_floors(self):
        drops = [dict(iface="eth0", errors_delta=0, drops_delta=340, err_delta=340)]
        errors = [dict(iface="eth0", errors_delta=7, drops_delta=0, err_delta=7)]
        self.assertGreater(self.score(drops), 0, "no drops floor: added to errors, as before")
        self.assertEqual(self.score(drops, nic_drop_alert_min=500), 0)
        self.assertGreater(self.score(errors, nic_drop_alert_min=500), 0)
        own = {"metric_thresholds": {"nic_drop_alert_min": 500}}
        self.assertEqual(self.score(drops, dev=own), 0, "the host's own drops floor counts")

    def test_the_check_row_warns_on_any_error_but_not_on_a_few_drops_when_drops_have_a_floor(self):
        quiet = self.row([dict(iface="eth0", errors_delta=0, drops_delta=3, err_delta=3)],
                         nic_drop_min=500)
        self.assertEqual(quiet, [])
        one_error = self.row([dict(iface="eth0", errors_delta=1, drops_delta=0, err_delta=1)],
                             nic_drop_min=500)
        self.assertEqual(len(one_error), 1)
        self.assertIn("+1 error", one_error[0]["output"])

    def test_without_a_drops_floor_the_row_warns_on_any_movement_as_before(self):
        rows = self.row([dict(iface="eth0", err_delta=2)])
        self.assertEqual(len(rows), 1)
        self.assertIn("+2 errors", rows[0]["output"])

    def test_the_row_uses_the_hosts_own_drops_floor(self):
        dev = {"metric_thresholds": {"nic_drop_alert_min": 100}}
        nio = [dict(iface="eth0", errors_delta=0, drops_delta=60, err_delta=60)]
        self.assertEqual(self.row(nio, dev=dev), [])
        self.assertEqual(len(self.row(nio, dev={"metric_thresholds": {"nic_drop_alert_min": 50}})), 1)

    def test_the_row_text_says_what_rose(self):
        rows = self.row([dict(iface="eth0", errors_delta=2, drops_delta=40, err_delta=42)],
                        nic_drop_min=10)
        self.assertIn("+2 errors, +40 drops", rows[0]["output"])

    def test_the_fleet_floors_reach_the_checks_engine_through_the_shared_kwargs(self):
        self.assertEqual(api._checks_threshold_kwargs({"nic_drop_alert_min": 300})["nic_drop_min"], 300)
        self.assertIsNone(api._checks_threshold_kwargs({})["nic_drop_min"])
        self.assertIsNone(api._checks_threshold_kwargs({"nic_drop_alert_min": "-4"})["nic_drop_min"])
        self.assertEqual(api._checks_threshold_kwargs({"nic_drop_alert_min": 0})["nic_drop_min"], 0)


if __name__ == "__main__":
    unittest.main()

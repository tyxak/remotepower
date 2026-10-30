"""Monitor -> Host metrics says when its figures were reported.

The agent sends the cpu, memory and disk figures with its system information, which goes with every tenth poll:
about every ten minutes at the default poll interval. Nothing on the page said so, so a figure that had not moved
for nine minutes read as stuck. The host record now carries `metrics_ts`, the time the figures were last reported,
and the table prints it under the host's name.

Held here through the real heartbeat handler: a report that carries the figures moves it, and a report that does
not (a report with other system information, a partial one that merges over the stored record, none at all) leaves
it where it was, because it must say how old the figures on the page are and not how old the last heartbeat is.
"""
import json
import os
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v742_container_recovery import DEV, _Base, _Captured, _Stdin, api  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
FIGURES = {"cpu_percent": 12.5, "mem_percent": 41.0, "disk_percent": 49.7,
           "mounts": [{"path": "/", "percent": 49.7, "used_gb": 454.35, "total_gb": 927.4, "fstype": "btrfs"}]}


class _Beats(_Base):

    def beat_with(self, sysinfo=None, partial=False):
        body = {"device_id": DEV, "token": "tok"}
        if sysinfo is not None:
            body["sysinfo"] = sysinfo
        if partial:
            body["sysinfo_partial"] = True
        raw = json.dumps(body).encode()
        os.environ.update({"REQUEST_METHOD": "POST", "PATH_INFO": "/api/heartbeat", "QUERY_STRING": "",
                           "CONTENT_LENGTH": str(len(raw))})
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

    def stored(self):
        api._LOAD_CACHE.clear()
        return (api.load(api.DEVICES_FILE) or {}).get(DEV, {})

    def set_stored(self, **fields):
        with api._LockedUpdate(api.DEVICES_FILE) as devs:
            devs[DEV].update(fields)
        api._LOAD_CACHE.clear()


class TestWhenTheFiguresWereReported(_Beats):

    def test_a_report_with_the_figures_stamps_the_time(self):
        before = int(time.time())
        self.beat_with(dict(FIGURES, uptime="1d"))
        got = self.stored().get("metrics_ts")
        self.assertIsNotNone(got)
        self.assertGreaterEqual(got, before)
        self.assertLessEqual(got, int(time.time()))

    def test_any_one_of_the_figures_is_enough(self):
        for key in ("cpu_percent", "mem_percent", "disk_percent", "mounts"):
            with self.subTest(key=key):
                self.set_stored(metrics_ts=0)
                self.beat_with({key: FIGURES[key]})
                self.assertGreater(self.stored().get("metrics_ts") or 0, 0)

    def test_a_report_without_them_leaves_the_time_alone(self):
        self.set_stored(metrics_ts=1234)
        self.beat_with({"uptime": "2d", "kernel": "7.3.0"})
        self.assertEqual(self.stored().get("metrics_ts"), 1234)

    def test_a_partial_report_does_not_make_the_old_figures_look_new(self):
        """A partial report merges over the stored record. The figures in it are from the last full report, and
        the table must keep saying so."""
        self.set_stored(metrics_ts=1234, sysinfo=dict(FIGURES))
        self.beat_with({"custom_check_results": {}}, partial=True)
        stored = self.stored()
        self.assertEqual(stored.get("metrics_ts"), 1234)
        self.assertEqual(stored["sysinfo"].get("mem_percent"), 41.0, "the merge kept the old figures")

    def test_a_heartbeat_with_no_system_information_leaves_the_time_alone(self):
        self.set_stored(metrics_ts=1234)
        self.beat_with(None)
        self.assertEqual(self.stored().get("metrics_ts"), 1234)

    def test_a_figure_the_server_refuses_does_not_count(self):
        """cpu_percent is kept only between 0 and 100: a report whose only figure is refused reports nothing."""
        self.set_stored(metrics_ts=1234)
        self.beat_with({"cpu_percent": 4000.0})
        self.assertEqual(self.stored().get("metrics_ts"), 1234)


class TestTheHostListCarriesIt(_Beats):

    def rows(self, slim):
        cap = {}

        def _resp(status, body=None):
            cap["s"], cap["b"] = status, body
            raise _Captured(status, body)

        saved = (api.respond, api.require_auth, api._caller_scope)
        api.respond, api.require_auth, api._caller_scope = _resp, (lambda: "jakob"), (lambda: None)
        os.environ["QUERY_STRING"] = "slim=1" if slim else ""
        api._LOAD_CACHE.clear()
        try:
            api.handle_devices_list()
        except _Captured:
            pass
        finally:
            api.respond, api.require_auth, api._caller_scope = saved
            os.environ.pop("QUERY_STRING", None)
        self.assertEqual(cap["s"], 200)
        return {r["id"]: r for r in cap["b"]}

    def test_the_full_list_carries_the_time(self):
        self.set_stored(metrics_ts=1790000000)
        self.assertEqual(self.rows(slim=False)[DEV]["metrics_ts"], 1790000000)

    def test_a_host_that_never_reported_figures_says_zero(self):
        self.assertEqual(self.rows(slim=False)[DEV]["metrics_ts"], 0)

    def test_the_slim_list_that_the_pages_poll_every_minute_does_not_grow(self):
        self.set_stored(metrics_ts=1790000000)
        self.assertNotIn("metrics_ts", self.rows(slim=True)[DEV])


class TestThePageSaysSo(unittest.TestCase):

    APP = (ROOT / "server/html/static/js/app.js").read_text()

    def test_the_host_cell_has_a_line_with_the_time_in_the_one_rule_for_times_in_markup(self):
        body = self.APP[self.APP.index("function _registerDeviceMetricsTable()"):]
        body = body[:body.index("// v3.2.0 follow-up: SNMP devices table")]
        self.assertIn("${d.metrics_ts ? `<div class=\"hint fs-10\"><span>Reported</span> ${timeAgoHtml(d.metrics_ts, { clamp: true })}</div>` : ''}", body)

    def test_the_word_is_translated(self):
        import re
        i18n = (ROOT / "server/html/static/js/i18n.js").read_text()
        m = re.search(r'^    "Reported": \{(.*)\},$', i18n, re.M)
        self.assertIsNotNone(m)
        for lang in ("fr", "de", "zh", "hi", "es", "ar"):
            self.assertIn(f'"{lang}": "', m.group(1))


if __name__ == "__main__":
    unittest.main()

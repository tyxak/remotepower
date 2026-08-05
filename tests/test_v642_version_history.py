"""v6.4.2 — the controller records that IT was upgraded.

RemotePower tracks every package upgrade on every managed device (update_logs
.json, ten runs per host) and kept no history of its own version. So the first
question an operator asks when alert volume triples on the 14th, or heartbeat
p95 doubles — "did we change anything?" — was unanswerable in-app about the one
host RemotePower manages least. The Timeline, the metric charts and the
fleet-events feed all covered the window with no marker for the 6.4.1 → 6.4.2
upgrade that happened that morning, and the audit log (if the guided path was
even used, which is one of four ways this actually gets upgraded) recorded only
`cmd=/usr/local/sbin/remotepower-server-update`.

Deliberately NOT `cfg['server_version']` — that was abandoned earlier as a
stale-value trap. This compares the LIVE constant against the last value
observed and writes only on a CHANGE, so the store is a change log and never a
claim about what is running now.
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-verhist642-"))

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
_JS = ROOT / "server" / "html" / "static" / "js"
sys.path.insert(0, str(_CGI))

_SPEC = importlib.util.spec_from_file_location("api", str(_CGI / "api.py"))
api = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("api", api)
_SPEC.loader.exec_module(api)


class TestVersionChangeIsRecorded(unittest.TestCase):
    def setUp(self):
        self._ver = api.SERVER_VERSION
        self._fire = api.fire_webhook
        self.fired = []
        api.fire_webhook = lambda ev, p=None, **k: self.fired.append((ev, dict(p or {})))
        api.save(api.SERVER_VERSION_FILE, {})
        api._invalidate_load_cache(api.SERVER_VERSION_FILE)

    def tearDown(self):
        api.SERVER_VERSION = self._ver
        api.fire_webhook = self._fire

    def _store(self):
        api._invalidate_load_cache(api.SERVER_VERSION_FILE)
        return api.load(api.SERVER_VERSION_FILE) or {}

    def _run(self):
        api._invalidate_load_cache(api.SERVER_VERSION_FILE)
        api._record_server_version_change()

    def test_first_boot_records_a_baseline(self):
        self._run()
        st = self._store()
        self.assertEqual(st["current"], api.SERVER_VERSION)
        self.assertTrue(st["since"])

    def test_first_boot_does_not_announce(self):
        """A fresh install is not an upgrade. Recording it is right — the store
        needs a baseline — announcing it is not."""
        self._run()
        self.assertEqual([e for e, _ in self.fired], [])

    def test_an_unchanged_version_is_a_no_op(self):
        """This runs on the request path; a write per beat would be absurd."""
        self._run()
        self.fired.clear()
        self._run()
        self.assertEqual(self.fired, [])
        self.assertEqual(len(self._store()["history"]), 1)

    def test_an_upgrade_is_recorded_and_announced(self):
        self._run()
        was = api.SERVER_VERSION
        api.SERVER_VERSION = "9.9.9"
        self.fired.clear()
        self._run()
        st = self._store()
        self.assertEqual(st["current"], "9.9.9")
        self.assertEqual(st["history"][-1], {"from": was, "to": "9.9.9",
                                             "at": st["since"]})
        self.assertEqual([e for e, _ in self.fired], ["server_upgraded"])
        p = self.fired[0][1]
        self.assertEqual((p["from"], p["to"]), (was, "9.9.9"))

    def test_a_downgrade_is_recorded_too(self):
        """A rollback is a change, and it is exactly the change an operator is
        trying to correlate against."""
        self._run()
        api.SERVER_VERSION = "0.0.1"
        self._run()
        self.assertEqual(self._store()["current"], "0.0.1")

    def test_the_history_is_bounded(self):
        for i in range(api.SERVER_VERSION_HISTORY_MAX + 5):
            api.SERVER_VERSION = f"1.0.{i}"
            self._run()
        self.assertLessEqual(len(self._store()["history"]),
                             api.SERVER_VERSION_HISTORY_MAX)

    def test_a_broken_store_does_not_break_the_request(self):
        api.save(api.SERVER_VERSION_FILE, "garbage")
        self.addCleanup(api.save, api.SERVER_VERSION_FILE, {})
        api._invalidate_load_cache(api.SERVER_VERSION_FILE)
        api._record_server_version_change()   # must not raise


class TestItIsWiredEverywhereItMustBe(unittest.TestCase):
    def test_the_event_is_registered(self):
        self.assertIn("server_upgraded", api.EVENT_REGISTRY)
        self.assertIn("severity", api.EVENT_REGISTRY["server_upgraded"],
                      "no severity key means it never reaches the inbox")

    def test_it_annotates_the_metric_charts(self):
        """The concrete "did we change anything?" — a marker on the chart whose
        shape just changed. Fleet-level, so it annotates EVERY device's chart."""
        self.assertIn("server_upgraded", api._METRIC_ANNOTATION_EVENTS)

    def test_the_message_builder_has_a_branch(self):
        import notify
        msg = notify._webhook_message("server_upgraded",
                                      {"name": "rp", "from": "6.4.1",
                                       "to": "6.4.2"})
        self.assertIn("6.4.1", msg)
        self.assertIn("6.4.2", msg)
        self.assertNotIn("unknown", msg.lower())

    def test_it_is_in_the_scheduler_cadence(self):
        """CADENCE is the SECOND registry — a sweep in main()'s _safe block and
        not here reds test_v600_scheduler, and silently never runs under the
        out-of-band scheduler."""
        src = (_CGI / "scheduler.py").read_text()
        self.assertIn("_record_server_version_change", src)

    def test_it_is_in_mains_safe_block(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("_safe(_record_server_version_change", src)

    def test_the_frontend_registries_have_it(self):
        js = (_JS / "app.js").read_text()
        self.assertIn("'server_upgraded'", js,
                      "missing from FLEET_EVENTS — absent from the activity feed")
        self.assertIn("case 'server_upgraded':", js,
                      "no _homeActivityAttrs case — the feed item is a dead click")

    def test_self_status_reports_it(self):
        saved = {k: getattr(api, k, None) for k in ("require_auth", "_env",
                                                    "method")}
        api.require_auth = lambda *a, **k: "admin"
        api._env = lambda k, d="": d
        api.method = lambda: "GET"
        api.save(api.SERVER_VERSION_FILE,
                 {"current": api.SERVER_VERSION, "since": 1700000000,
                  "history": [{"from": "6.4.1", "to": api.SERVER_VERSION,
                               "at": 1700000000}]})
        api._invalidate_load_cache(api.SERVER_VERSION_FILE)
        try:
            api.handle_self_status()
            self.fail("handler did not respond")
        except api.HTTPError as e:
            body = e.body
        finally:
            for k, v in saved.items():
                if v is not None:
                    setattr(api, k, v)
        self.assertEqual(body.get("version_since"), 1700000000)
        self.assertTrue(body.get("version_history"))

    def test_the_self_page_renders_it(self):
        js = (_JS / "app-self.js").read_text()
        self.assertIn("_versionSinceHtml", js)
        self.assertIn("_versionHistoryRow", js)
        self.assertIn("s.version_history", js)

    def test_the_baseline_row_is_not_shown_as_an_upgrade(self):
        """The first-boot row has from=None. Rendering "null → 6.4.2" would be
        the product inventing an upgrade that never happened."""
        js = (_JS / "app-self.js").read_text()
        fn = js[js.index("function _versionHistoryRow"):]
        fn = fn[:fn.index("\n}\n")]
        self.assertIn("filter(e => e && e.from)", fn)


if __name__ == "__main__":
    unittest.main()

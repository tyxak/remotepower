#!/usr/bin/env python3
"""`docker system df` sent on its own is kept.

The agent sends the disk-footprint report on its first poll after a start, so a host
that restarts its agent more often than the hourly cadence still reports it (the 6.2.2
fix). That poll carries no container list, and the server read the figures only inside
the branch that handles one. They were dropped, and the panel waited for the next hourly
report. For a host whose agent restarts every half hour that was every report.

Through the real heartbeat. The control cases matter as much as the fix: a made-up entry
for a host that never reported containers would age into a containers_stale alert.
"""
import json
import os
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v742_container_recovery import DEV, _Base, _Captured, _Stdin, api, ctr  # noqa: E402

DF_OLD = {"images": {"size": "10GB", "reclaimable": "1GB (10%)", "total": "9", "active": "4"}}
DF_NEW = {"images": {"size": "14GB", "reclaimable": "6GB (42%)", "total": "11", "active": "4"},
          "volumes": [{"name": "nextcloud", "size": "210GB", "links": 1}]}


class _Beats(_Base):

    def beat_body(self, **extra):
        body = {"device_id": DEV, "token": "tok"}
        body.update(extra)
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


class TestDfOnItsOwn(_Beats):

    def test_the_premise_a_full_report_stores_both(self):
        self.beat_body(containers=[ctr("web")], docker_df=DF_OLD)
        e = self.entry()
        self.assertEqual([c["name"] for c in e["items"]], ["web"])
        self.assertEqual(e["df"]["images"]["size"], "10GB")

    def test_a_df_report_alone_updates_the_figures_on_the_existing_entry(self):
        """The restart case: the entry is there from before the agent restarted."""
        self.beat_body(containers=[ctr("web")], docker_df=DF_OLD)
        # Make the container report ten minutes old, so a time that moved is
        # visible (within one second the new and the old time are the same number).
        old = self.entry()
        old["ts"] = int(time.time()) - 600
        api.save(api.CONTAINERS_FILE, {DEV: old})
        api._LOAD_CACHE.clear()
        ts = old["ts"]
        self.beat_body(docker_df=DF_NEW)
        e = self.entry()
        self.assertEqual(e["df"]["images"]["size"], "14GB")
        self.assertEqual(e["df"]["volumes"][0]["name"], "nextcloud")
        # Nothing else about the entry moved: the list and the time are the last
        # container report's, and the page says how old they are.
        self.assertEqual([c["name"] for c in e["items"]], ["web"])
        self.assertEqual(e["ts"], ts)

    def test_it_does_not_touch_the_restart_loop_state(self):
        self.beat_body(containers=[ctr("web", restart_count=1)])
        self.beat_body(containers=[ctr("web", restart_count=9)])
        before = self.entry().get("restarting_alerted")
        self.assertEqual(before, ["web"])
        self.beat_body(docker_df=DF_NEW)
        self.assertEqual(self.entry().get("restarting_alerted"), ["web"])

    def test_a_host_with_no_entry_gets_no_made_up_one(self):
        self.beat_body(docker_df=DF_NEW)
        self.assertEqual(self.entry(), {})
        self.assertNotIn(DEV, api.load(api.CONTAINERS_FILE) or {})

    def _stale_alerts(self):
        return [e for e, _p in self.events if e == "containers_stale"]

    def test_the_stale_sweep_does_fire_for_an_old_report(self):
        """Control: the sweep is live in this harness, so the next test's silence
        is the sweep saying nothing and not the sweep being unable to speak."""
        api.save(api.CONTAINERS_FILE, {DEV: {"ts": int(time.time()) - 86400,
                                             "items": [ctr("web")]}})
        api._LOAD_CACHE.clear()
        api.check_container_webhooks()
        self.assertEqual(len(self._stale_alerts()), 1)

    def test_so_it_can_never_age_into_a_stale_containers_alert(self):
        self.beat_body(docker_df=DF_NEW)
        api.check_container_webhooks()
        self.assertEqual(self._stale_alerts(), [])

    def test_junk_in_the_figures_changes_nothing(self):
        self.beat_body(containers=[ctr("web")], docker_df=DF_OLD)
        for junk in ("lots", 7, [1, 2], {}, {"evil": {"size": "x"}}):
            self.beat_body(docker_df=junk)
            self.assertEqual(self.entry()["df"]["images"]["size"], "10GB", junk)

    def test_an_entry_without_a_time_is_left_alone(self):
        """An entry no container report made (cleared by hand, say) is not
        revived by a df report."""
        api.save(api.CONTAINERS_FILE, {DEV: {"items": []}})
        api._LOAD_CACHE.clear()
        self.beat_body(docker_df=DF_NEW)
        self.assertNotIn("df", self.entry())

    def test_the_next_full_report_keeps_the_newer_figures(self):
        """A container report without figures carries the stored ones forward."""
        self.beat_body(containers=[ctr("web")], docker_df=DF_OLD)
        self.beat_body(docker_df=DF_NEW)
        self.beat_body(containers=[ctr("web"), ctr("db")])
        e = self.entry()
        self.assertEqual(e["df"]["images"]["size"], "14GB")
        self.assertEqual(len(e["items"]), 2)

    def test_a_report_with_neither_changes_nothing(self):
        self.beat_body(containers=[ctr("web")], docker_df=DF_OLD)
        before = self.entry()
        self.beat_body()
        self.assertEqual(self.entry(), before)


if __name__ == "__main__":
    unittest.main()

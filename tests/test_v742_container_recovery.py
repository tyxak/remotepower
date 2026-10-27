#!/usr/bin/env python3
"""v7.4.2, issue #45: a container_stopped alert closes when the container runs again.

"A nightly backup job stops each app's containers with docker stop, archives its data, then
starts them with docker start. RemotePower raises 'Container stopped' for every one with
status 'gone', and none of the alerts ever resolve after the containers are running again."

The agent lists RUNNING containers, so a stopped container is simply absent from the next
report and the server reads that as "gone". The recover branch only looked at containers
that were in the previous report and not running, which a gone container never is, so a
container that came back was a brand-new name and nothing closed the alert.

Everything here goes through the real heartbeat, the real diff and the real alert ledger. A
hand-built alert row would skip the one thing under test: which name the recovery matches.
"""
import importlib.util
import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v742-ctr-"))
_spec = importlib.util.spec_from_file_location("api_v742_ctr", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

DEV = "d1"


class _Captured(SystemExit):
    def __init__(self, status, body):
        super().__init__(0)
        self.status, self.body = status, body


class _Stdin:
    def __init__(self, data):
        self.buffer = io.BytesIO(data)


def ctr(name, status="Up 2 hours", image="ghcr.io/acme/app", tag="1.0", **kw):
    d = {"name": name, "image": image, "tag": tag, "status": status, "namespace": "",
         "runtime": "docker", "ports": [], "started_at": 0, "uptime_seconds": 0,
         "restart_count": 0}
    d.update(kw)
    return d


class _Base(unittest.TestCase):
    def setUp(self):
        for f, empty in ((api.ALERTS_FILE, {"alerts": []}), (api.CONTAINERS_FILE, {}),
                         (api.CONFIG_FILE, {}), (api.MAINT_FILE, {"windows": []}),
                         (api.MAINT_SUPPRESS_LOG, {"entries": []})):
            api.save(f, empty)
        api.save(api.DEVICES_FILE, {DEV: {
            "id": DEV, "name": "serverbox", "hostname": "serverbox", "token": "tok",
            "last_seen": int(time.time()), "enrolled": int(time.time()), "tags": [],
            "group": "", "sysinfo": {}, "monitored": True}})
        api._LOAD_CACHE.clear()
        self.events = []
        self._real_fire = api.fire_webhook

        def spy(event, payload):
            self.events.append((event, dict(payload)))
            return self._real_fire(event, payload)
        api.fire_webhook = spy
        self._real_respond = api.respond

        def fake(status, data):
            raise _Captured(status, data)
        api.respond = fake

    def tearDown(self):
        api.fire_webhook = self._real_fire
        api.respond = self._real_respond

    def beat(self, items):
        """One heartbeat carrying this container list, through the real handler."""
        raw = json.dumps({"device_id": DEV, "token": "tok", "containers": items}).encode()
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

    def alerts(self, event="container_stopped"):
        api._LOAD_CACHE.clear()
        return [a for a in (api.load(api.ALERTS_FILE) or {}).get("alerts", [])
                if a.get("event") == event]

    def open_names(self):
        return sorted((a.get("payload") or {}).get("container")
                      for a in self.alerts() if not a.get("resolved_at"))

    def fired(self, event):
        return [p.get("container") for e, p in self.events if e == event]

    def entry(self):
        api._LOAD_CACHE.clear()
        return (api.load(api.CONTAINERS_FILE) or {}).get(DEV) or {}


class TestAStoppedContainerThatComesBack(_Base):

    def test_docker_stop_then_docker_start_closes_the_alert(self):
        """The reporter's sequence, beat by beat."""
        self.beat([ctr("web"), ctr("db")])
        self.beat([ctr("db")])                       # docker stop web
        self.assertEqual(self.open_names(), ["web"], "the stop should be an open alert")
        self.assertEqual(self.alerts()[0]["payload"].get("status"), "gone")
        self.beat([ctr("db")])                       # several heartbeats later
        self.assertEqual(self.open_names(), ["web"])
        self.beat([ctr("db"), ctr("web")])           # docker start web
        self.assertEqual(self.open_names(), [], "the alert stayed open after the container ran again")
        self.assertTrue(self.alerts()[0].get("resolved_at"))

    def test_only_the_container_that_came_back_is_closed(self):
        self.beat([ctr("web"), ctr("db"), ctr("cache")])
        self.beat([ctr("cache")])                    # web and db stopped
        self.assertEqual(self.open_names(), ["db", "web"])
        self.beat([ctr("cache"), ctr("web")])        # only web is back
        self.assertEqual(self.open_names(), ["db"])

    def test_a_container_that_never_returns_keeps_its_alert(self):
        """The control: closing on any report would make the alert useless."""
        self.beat([ctr("web"), ctr("db")])
        self.beat([ctr("db")])
        for _ in range(5):
            self.beat([ctr("db")])
        self.assertEqual(self.open_names(), ["web"])

    def test_every_container_stopped_at_once_then_started(self):
        """A backup that stops them all leaves an EMPTY list, and the report after it has
        no previous list to diff against. The recovery must not depend on that diff."""
        self.beat([ctr("web"), ctr("db")])
        self.beat([])
        self.assertEqual(self.open_names(), ["db", "web"])
        self.beat([ctr("web"), ctr("db")])
        self.assertEqual(self.open_names(), [])

    def test_removed_and_recreated_under_the_same_name(self):
        self.beat([ctr("web", tag="1.0"), ctr("db")])
        self.beat([ctr("db")])                       # docker rm -f web
        self.beat([ctr("db"), ctr("web", tag="1.1", status="Up 3 seconds")])   # docker run --name web
        self.assertEqual(self.open_names(), [])

    def test_one_recovery_notice_per_container_and_not_repeated(self):
        self.beat([ctr("web"), ctr("db")])
        self.beat([ctr("db")])
        self.beat([ctr("db"), ctr("web")])
        self.beat([ctr("db"), ctr("web")])
        self.beat([ctr("db"), ctr("web")])
        self.assertEqual(self.fired("container_recovered"), ["web"])
        self.assertEqual(self.fired("container_stopped"), ["web"])

    def test_a_container_that_returns_before_the_next_report_is_never_alerted(self):
        self.beat([ctr("web"), ctr("db")])
        self.beat([ctr("web", status="Up 1 minute"), ctr("db")])   # restarted between reports
        self.assertEqual(self.alerts(), [])
        self.assertEqual(self.fired("container_recovered"), [])

    def test_a_container_listed_as_exited_then_running_is_recovered_once(self):
        """The path that already worked (a runtime that lists stopped containers): the
        new code must not make it fire twice."""
        self.beat([ctr("web"), ctr("db")])
        self.beat([ctr("web", status="Exited (137) 5 seconds ago"), ctr("db")])
        self.assertEqual(self.open_names(), ["web"])
        self.beat([ctr("web"), ctr("db")])
        self.assertEqual(self.open_names(), [])
        self.assertEqual(self.fired("container_recovered"), ["web"])

    def test_a_container_that_is_listed_but_still_stopped_stays_open(self):
        """Only RUNNING closes the alert. A runtime that lists stopped containers must not
        close it by merely listing the name."""
        self.beat([ctr("web"), ctr("db")])
        self.beat([ctr("db")])
        self.beat([ctr("db"), ctr("web", status="Exited (0) 1 minute ago")])
        self.assertEqual(self.open_names(), ["web"])
        self.assertEqual(self.fired("container_recovered"), [])
        self.beat([ctr("db"), ctr("web", status="Up 5 seconds")])
        self.assertEqual(self.open_names(), [])

    def test_listed_as_exited_then_removed_then_recreated(self):
        """A runtime that lists stopped containers: the stop alert is raised while the
        container is still listed, the container is then removed (no longer listed at all),
        and later run again under the same name. Only the waiting list can connect those."""
        self.beat([ctr("web"), ctr("db")])
        self.beat([ctr("web", status="Exited (1) 5 seconds ago"), ctr("db")])
        self.beat([ctr("db")])                              # docker rm web
        self.assertEqual(self.open_names(), ["web"])
        self.beat([ctr("db"), ctr("web", status="Up 4 seconds")])
        self.assertEqual(self.open_names(), [])

    def test_the_names_waiting_for_a_recovery_are_stored_with_the_host(self):
        self.beat([ctr("web"), ctr("db")])
        self.beat([ctr("db")])
        self.assertEqual(self.entry().get("stopped_alerted"), ["web"])
        self.beat([ctr("db"), ctr("web")])
        self.assertEqual(self.entry().get("stopped_alerted"), [],
                         "an empty list, not a missing key: a missing key means 'never recorded'")


class TestInsideAMaintenanceWindow(_Base):
    """The reporter's backup runs inside a window. The alert is recorded and the notice held;
    the recovery has to close the alert and be held the same way, or every backup ends with
    a 'Container recovered' page for each container nobody was told had stopped."""

    def window(self):
        now = int(time.time())
        api.save(api.MAINT_FILE, {"windows": [{
            "id": "mw_backup", "scope": "device", "target": DEV, "reason": "nightly backup",
            "start": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 600)),
            "end": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 3600))}]})

    def held(self):
        api._LOAD_CACHE.clear()
        return [e["event"] for e in (api.load(api.MAINT_SUPPRESS_LOG) or {}).get("entries", [])]

    def test_the_alert_closes_and_the_recovery_notice_is_held(self):
        self.window()
        self.beat([ctr("web"), ctr("db")])
        self.beat([ctr("db")])
        self.assertEqual(self.open_names(), ["web"], "the inbox still records the stop")
        self.assertIn("container_stopped", self.held())
        self.beat([ctr("db"), ctr("web")])
        self.assertEqual(self.open_names(), [])
        self.assertIn("container_recovered", self.held(),
                      "the recovery notice was delivered inside the window that held the stop")

    def test_a_recovery_rides_its_firing_events_window(self):
        self.assertIn("container_recovered", api.SUPPRESSIBLE_EVENTS)


class TestAlertsOpenedByAnEarlierVersion(_Base):
    """7.4.1 and before never recorded which containers had an open stop alert. A host with
    alerts already open must not wait for its next backup to see them close."""

    def seed_open(self, *names):
        for n in names:
            api._record_alert("container_stopped", {
                "device_id": DEV, "name": "serverbox", "container": n, "runtime": "docker",
                "image": "ghcr.io/acme/app", "status": "gone", "previous_status": "Up 2 hours"})
        self.assertEqual(self.open_names(), sorted(names))

    def written_by_7_4_1(self, items):
        api._entity_write_one(api.CONTAINERS_FILE, DEV, {"ts": int(time.time()) - 60, "items": items})
        self.assertNotIn("stopped_alerted", self.entry())

    def test_the_first_report_after_the_upgrade_closes_what_is_running(self):
        self.seed_open("grafana", "prometheus")
        self.written_by_7_4_1([ctr("grafana"), ctr("nextcloud")])
        self.beat([ctr("grafana"), ctr("nextcloud")])
        self.assertEqual(self.open_names(), ["prometheus"],
                         "grafana runs again and should close; prometheus is still gone")
        self.assertEqual(self.entry().get("stopped_alerted"), ["prometheus"])

    def test_the_ledger_is_read_once_per_host_not_per_report(self):
        calls = []
        real = api._open_container_stopped_names
        api._open_container_stopped_names = lambda d: (calls.append(d), real(d))[1]
        try:
            self.beat([ctr("web")])
            for _ in range(4):
                self.beat([ctr("web")])
        finally:
            api._open_container_stopped_names = real
        self.assertEqual(calls, [DEV], "the alert ledger is read on every container report")

    def test_an_alert_that_is_already_closed_is_not_waiting_for_anything(self):
        """The ledger keeps resolved alerts. Seeding from one would announce a recovery
        for a container whose stop was dealt with long ago."""
        self.seed_open("old-job")
        with api._LockedUpdate(api.ALERTS_FILE) as store:
            for a in store["alerts"]:
                a["resolved_at"] = int(time.time()) - 3600
        api._LOAD_CACHE.clear()
        self.written_by_7_4_1([ctr("old-job")])
        self.beat([ctr("old-job")])
        self.assertEqual(self.entry().get("stopped_alerted"), [])
        self.assertEqual(self.fired("container_recovered"), [])

    def test_another_hosts_open_alert_is_not_this_hosts_to_close(self):
        """The ledger holds every host's alerts. A grafana that stopped on ANOTHER host is
        not made recoverable by a grafana that happens to be running here."""
        other = dict(api.load(api.DEVICES_FILE)[DEV], id="d2", name="otherbox", token="tok2")
        devs = api.load(api.DEVICES_FILE)
        devs["d2"] = other
        api.save(api.DEVICES_FILE, devs)
        api._record_alert("container_stopped", {
            "device_id": "d2", "name": "otherbox", "container": "grafana", "runtime": "docker",
            "image": "grafana/grafana", "status": "gone", "previous_status": "Up 2 hours"})
        self.written_by_7_4_1([ctr("grafana")])
        self.beat([ctr("grafana")])
        self.assertEqual(self.entry().get("stopped_alerted"), [])
        self.assertEqual(self.fired("container_recovered"), [])
        self.assertEqual(self.open_names(), ["grafana"], "d2's alert must still be open")

    def test_clearing_a_hosts_container_data_does_not_orphan_its_alerts(self):
        self.beat([ctr("web"), ctr("db")])
        self.beat([ctr("db")])
        store = api.load(api.CONTAINERS_FILE)
        store.pop(DEV)                                # DELETE /api/devices/<id>/containers
        api.save(api.CONTAINERS_FILE, store)
        self.beat([ctr("db")])
        self.assertEqual(self.entry().get("stopped_alerted"), ["web"],
                         "the cleared host re-reads the ledger and still knows web is waiting")
        self.beat([ctr("db"), ctr("web")])
        self.assertEqual(self.open_names(), [])


class TestAListThatWasEditedByHand(_Base):

    def test_duplicates_and_junk_in_the_stored_list_do_no_harm(self):
        self.beat([ctr("web")])
        api._entity_write_one(api.CONTAINERS_FILE, DEV, {
            "ts": int(time.time()) - 60, "items": [ctr("web")],
            "stopped_alerted": ["web", "web", None, ""]})
        self.seed_alert_for_web()
        self.beat([ctr("web")])
        self.assertEqual(self.fired("container_recovered"), ["web"], "once, not once per copy")
        self.assertEqual(self.entry().get("stopped_alerted"), [])

    def seed_alert_for_web(self):
        api._record_alert("container_stopped", {
            "device_id": DEV, "name": "serverbox", "container": "web", "runtime": "docker",
            "status": "gone"})


class TestTheWaitingListIsBounded(_Base):

    def test_a_host_whose_containers_never_return_cannot_grow_it_without_limit(self):
        """A report holds at most 100 containers, so names that never come back arrive in
        rounds: three rounds of 90 is 270 names against a cap of 200."""
        for r in range(3):
            names = [f"run{r}-{i:02d}" for i in range(90)]
            self.beat([ctr(n) for n in names])
            self.beat([])
        waiting = self.entry().get("stopped_alerted")
        self.assertEqual(len(waiting), 200)
        self.assertEqual(waiting[-1], "run2-89", "the newest names are the ones kept")
        self.assertNotIn("run0-00", waiting)


class TestExcludedContainers(_Base):

    def test_an_excluded_container_never_waits_for_a_recovery(self):
        api.save(api.CONFIG_FILE, {"container_alert_excludes": ["scratch-"]})
        api._LOAD_CACHE.clear()
        self.beat([ctr("scratch-1"), ctr("web")])
        self.beat([ctr("web")])
        self.assertEqual(self.alerts(), [])
        self.assertEqual(self.entry().get("stopped_alerted"), [])


if __name__ == "__main__":
    unittest.main()

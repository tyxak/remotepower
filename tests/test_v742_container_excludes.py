#!/usr/bin/env python3
"""v7.4.2, issue #43: keep a container out of alerts by its image, not only its name.

"Arcane starts short-lived helper containers from its ghcr.io/getarcaneapp/tools image every
night at midnight on each managed host, and Docker gives them random names (loving_engelbart,
gifted_raman, boring_bohr). They exit by design, and RemotePower raises 'container stopped ...
gone' for each one on every host, every night. With random names there is nothing for a name
exclude to match."

An entry of `container_alert_excludes` that starts with `image:` is read against the
container's image instead of its name. Four places judge a listed container as a problem: the
stop alert and the restart-loop alert (both honoured the list), and the Needs-Attention digest
and the dashboard's stopped-containers widget (neither did). All four are covered here.
"""
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v742_container_recovery import DEV, _Base, api, ctr  # noqa: E402
import attention_isolation  # noqa: E402

HELPER_IMAGE = "ghcr.io/getarcaneapp/tools"


def helper(name, **kw):
    return ctr(name, image=HELPER_IMAGE, tag="latest", **kw)


def exclude(*entries):
    api.save(api.CONFIG_FILE, {"container_alert_excludes": list(entries)})
    api._LOAD_CACHE.clear()


class TestTheMatcher(_Base):

    def test_a_name_entry_behaves_as_before(self):
        exclude("ephemeral-")
        self.assertTrue(api._container_alert_excluded("ephemeral-worker-7"))
        self.assertFalse(api._container_alert_excluded("seerr"))

    def test_a_name_entry_is_never_read_against_the_image(self):
        exclude("tools")
        self.assertFalse(api._container_alert_excluded("web", HELPER_IMAGE, "latest"))

    def test_the_scan_containers_are_still_excluded(self):
        exclude()
        self.assertTrue(api._container_alert_excluded("rp-scan-abc123", "x", "1"))

    def test_an_image_entry_matches_the_image_whatever_the_name_or_tag(self):
        exclude("image:" + HELPER_IMAGE)
        for name in ("loving_engelbart", "gifted_raman", "boring_bohr"):
            self.assertTrue(api._container_alert_excluded(name, HELPER_IMAGE, "latest"), name)
        self.assertTrue(api._container_alert_excluded("x", HELPER_IMAGE, ""))
        self.assertTrue(api._container_alert_excluded("x", HELPER_IMAGE, "v1.2.3"))
        self.assertFalse(api._container_alert_excluded("x", "ghcr.io/getarcaneapp/arcane", "latest"))

    def test_an_image_entry_is_never_read_against_the_name(self):
        exclude("image:tools")
        self.assertFalse(api._container_alert_excluded("tools-1", "nginx", "1"))

    def test_an_entry_with_a_tag_is_read_against_the_tag(self):
        exclude("image:" + HELPER_IMAGE + ":1.2")
        self.assertTrue(api._container_alert_excluded("x", HELPER_IMAGE, "1.2"))
        self.assertFalse(api._container_alert_excluded("x", HELPER_IMAGE, "1.3"))
        self.assertFalse(api._container_alert_excluded("x", HELPER_IMAGE, ""))

    def test_a_bare_tag_word_does_not_match_every_container_on_that_tag(self):
        exclude("image:latest")
        self.assertFalse(api._container_alert_excluded("x", "nginx", "latest"))

    def test_a_registry_with_a_port(self):
        exclude("image:registry.lan:5000/ops/tools")
        self.assertTrue(api._container_alert_excluded("x", "registry.lan:5000/ops/tools", "1.0"))
        exclude("image:registry.lan:5000/ops/tools:1.0")
        self.assertTrue(api._container_alert_excluded("x", "registry.lan:5000/ops/tools", "1.0"))
        self.assertFalse(api._container_alert_excluded("x", "registry.lan:5000/ops/tools", "2.0"))

    def test_case_and_spaces_are_forgiven_in_an_image_entry(self):
        exclude("  Image:  GHCR.io/GetArcaneApp/Tools  ")
        self.assertTrue(api._container_alert_excluded("x", HELPER_IMAGE, "latest"))

    def test_the_prefix_with_nothing_after_it_excludes_nothing(self):
        for entry in ("image:", "image:   ", "IMAGE:"):
            exclude(entry)
            self.assertFalse(api._container_alert_excluded("web", "nginx", "1"), entry)

    def test_a_container_without_an_image_is_not_swept_up(self):
        exclude("image:" + HELPER_IMAGE)
        self.assertFalse(api._container_alert_excluded("web"))
        self.assertFalse(api._container_alert_excluded("web", "", ""))
        exclude("image::1.0")      # an entry that is only a tag must not match "no image, tag 1.0"
        self.assertFalse(api._container_alert_excluded("web", "", "1.0"))


class TestThroughTheHeartbeat(_Base):

    def test_helper_containers_of_an_excluded_image_raise_nothing(self):
        exclude("image:" + HELPER_IMAGE)
        self.beat([ctr("web"), helper("loving_engelbart"), helper("gifted_raman")])
        self.beat([ctr("web")])                                   # the helpers exit
        self.assertEqual(self.alerts(), [])
        self.assertEqual(self.events and [e for e, _ in self.events if e == "container_stopped"], [])
        self.assertEqual(self.entry().get("stopped_alerted"), [])

    def test_the_same_vanishing_on_another_image_still_alerts(self):
        """The control: the exclusion is the image, not the host or the shape of the name."""
        exclude("image:" + HELPER_IMAGE)
        self.beat([ctr("web"), ctr("loving_engelbart", image="nginx")])
        self.beat([ctr("web")])
        self.assertEqual(self.open_names(), ["loving_engelbart"])

    def test_without_the_entry_the_helpers_alert_as_the_reporter_saw(self):
        exclude()
        self.beat([ctr("web"), helper("loving_engelbart"), helper("gifted_raman")])
        self.beat([ctr("web")])
        self.assertEqual(self.open_names(), ["gifted_raman", "loving_engelbart"])

    def test_a_restart_loop_of_an_excluded_name_raises_nothing(self):
        """Since v4.2.0: the restart-loop alert honours the name list, as the stop alert does."""
        exclude("ephemeral-")
        self.beat([ctr("ephemeral-1", restart_count=0)])
        self.beat([ctr("ephemeral-1", restart_count=50)])
        self.assertEqual([e for e, _ in self.events if e == "container_restarting"], [])
        self.beat([ctr("web", restart_count=0)])
        self.beat([ctr("web", restart_count=50)])
        self.assertEqual([e for e, _ in self.events if e == "container_restarting"],
                         ["container_restarting"], "the control: a container not on the list fires")

    def test_a_restart_loop_of_an_excluded_image_raises_nothing(self):
        exclude("image:" + HELPER_IMAGE)
        self.beat([helper("loving_engelbart", restart_count=0)])
        self.beat([helper("loving_engelbart", restart_count=50)])
        self.assertEqual([e for e, _ in self.events if e == "container_restarting"], [])
        exclude()
        self.beat([helper("loving_engelbart", restart_count=120)])
        self.assertEqual([e for e, _ in self.events if e == "container_restarting"],
                         ["container_restarting"], "the control: with no exclusion it fires")


class TestTheDigestAndTheWidget(_Base):

    def setUp(self):
        super().setUp()
        self._tmp = tempfile.mkdtemp(prefix="rp-v742-exc-")
        self._saved = attention_isolation.isolate(api, self._tmp)
        api.save(api.DEVICES_FILE, {DEV: {
            "name": "serverbox", "group": "g", "monitored": True,
            "last_seen": int(time.time()), "sysinfo": {}}})
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        attention_isolation.restore(api, self._saved)
        super().tearDown()

    def listed(self):
        """A runtime that lists stopped containers: one helper that exited by design and
        one job that failed."""
        api.save(api.CONTAINERS_FILE, {DEV: {"ts": int(time.time()), "items": [
            ctr("web"),
            helper("loving_engelbart", status="Exited (0) 2 hours ago"),
            ctr("nightly-job", image="acme/job", status="Exited (1) 2 hours ago"),
        ]}})
        api._LOAD_CACHE.clear()

    def stopped_item(self):
        api._LOAD_CACHE.clear()
        for i in api._compute_attention():
            if i.get("kind") == "container" and "stopped" in (i.get("summary") or ""):
                return i["summary"]
        return None

    def test_the_digest_counts_both_without_an_exclusion(self):
        self.listed()
        self.assertEqual(self.stopped_item(), "2 containers stopped")

    def test_the_digest_leaves_out_what_the_operator_excluded(self):
        self.listed()
        exclude("image:" + HELPER_IMAGE)
        self.assertEqual(self.stopped_item(), "1 container stopped")

    def test_the_digest_says_nothing_when_everything_stopped_is_excluded(self):
        self.listed()
        exclude("image:" + HELPER_IMAGE, "nightly-")
        self.assertIsNone(self.stopped_item())

    def widget(self):
        api._LOAD_CACHE.clear()
        devs = api.load(api.DEVICES_FILE)
        return api._dashboard_extra_widgets(devs, api.load(api.CONFIG_FILE), int(time.time()),
                                            want={"containers"})["containers"]["stopped"]

    def test_the_dashboard_widget_counts_both_without_an_exclusion(self):
        self.listed()
        self.assertEqual(self.widget(), 2)

    def test_the_dashboard_widget_leaves_out_what_the_operator_excluded(self):
        self.listed()
        exclude("image:" + HELPER_IMAGE)
        self.assertEqual(self.widget(), 1)
        exclude("image:" + HELPER_IMAGE, "nightly-")
        self.assertEqual(self.widget(), 0)


if __name__ == "__main__":
    unittest.main()

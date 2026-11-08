#!/usr/bin/env python3
"""8.0.0: the Sonarr, Radarr, Lidarr and Readarr connector also reads what the download client is stuck on.

The connector read the app's health list and version. A download that failed to import sits in the queue while the app reports no problem, so a stuck queue was invisible. `GET /api/<v>/queue/status`
(Sonarr and Radarr on v3, Lidarr and Readarr on v1; Prowlarr has no queue) answers the counts and four flags (errors, warnings, unknownErrors, unknownWarnings). The property names are the
vendor's own, read from the QueueStatusResource of Sonarr's published OpenAPI description on 2026-11-08 (id, totalCount, count, unknownCount, errors, warnings, unknownErrors, unknownWarnings),
and `connector-spec-check.py` (remotepower-internal-docs/dev-tools) confirms the route exists in the Sonarr, Radarr and Lidarr descriptions.

The connector is run against a fake client that answers by method and path; no Sonarr is available here.
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server" / "cgi-bin"))
import integrations as I  # noqa: E402


class Fake(I.HTTPClient):
    def __init__(self, routes, base="http://x"):
        super().__init__(base)
        self.routes, self.calls = routes, []

    def request(self, method, path, headers=None, params=None, body=None):
        key = (method, path.split("?")[0])
        self.calls.append(key)
        v = self.routes.get(key)
        if v is None:
            return I.Resp(404, "")
        if isinstance(v, Exception):
            raise v
        st, payload = v
        return I.Resp(st, payload if isinstance(payload, str) else json.dumps(payload))


def poll(app, api, queue, health=(), name=None):
    routes = {("GET", f"/api/{api}/system/status"): (200, {"appName": name or app.title(), "version": "4.0.1"}), ("GET", f"/api/{api}/health"): (200, list(health))}
    if queue is not None:
        routes[("GET", f"/api/{api}/queue/status")] = queue if isinstance(queue, Exception) else (200, queue)
    c = Fake(routes)
    return I.poll_instance({"type": app, "url": "http://x", "secret": "KEY"}, c), c


def q(total=0, errors=False, warnings=False, unknown_errors=False, unknown_warnings=False):
    return {"id": 1, "totalCount": total, "count": total, "unknownCount": 0, "errors": errors, "warnings": warnings, "unknownErrors": unknown_errors, "unknownWarnings": unknown_warnings}


class TestTheQueueIsRead(unittest.TestCase):
    def test_a_quiet_queue_changes_nothing(self):
        r, c = poll("sonarr", "v3", q(0))
        self.assertEqual((r["status"], r["detail"]), (I.OK, "Sonarr 4.0.1 · healthy"))
        self.assertEqual((r["metrics"]["queue_total"], r["metrics"]["queue_problems"]), (0, 0))
        self.assertIn(("GET", "/api/v3/queue/status"), c.calls)

    def test_a_queue_with_items_says_how_many(self):
        r, _ = poll("radarr", "v3", q(4))
        self.assertEqual((r["status"], r["detail"]), (I.OK, "Radarr 4.0.1 · healthy · 4 in queue"))
        self.assertEqual(r["metrics"]["queue_total"], 4)

    def test_the_card_shows_the_queue_as_a_chip_for_every_app_that_has_one(self):
        for app, api in (("sonarr", "v3"), ("radarr", "v3"), ("lidarr", "v1"), ("readarr", "v1")):
            with self.subTest(app=app):
                r, _ = poll(app, api, q(7))
                self.assertIn({"label": "Queue", "value": "7"}, I.format_stats(app, r["metrics"]))

    def test_an_empty_queue_is_a_zero_chip_and_not_a_missing_one(self):
        r, _ = poll("sonarr", "v3", q(0))
        self.assertIn({"label": "Queue", "value": "0"}, I.format_stats("sonarr", r["metrics"]))

    def test_downloads_with_errors_warn_while_the_app_says_it_is_healthy(self):
        r, _ = poll("sonarr", "v3", q(3, errors=True))
        self.assertEqual(r["status"], I.WARN)
        self.assertIn("3 in queue", r["detail"])
        self.assertTrue(r["detail"].endswith("downloads with errors"), r["detail"])
        self.assertEqual(r["metrics"]["queue_problems"], 1)

    def test_downloads_with_warnings_warn_too_and_say_so(self):
        r, _ = poll("sonarr", "v3", q(2, warnings=True))
        self.assertEqual(r["status"], I.WARN)
        self.assertTrue(r["detail"].endswith("downloads with warnings"), r["detail"])

    def test_the_flags_for_items_the_app_cannot_match_count_as_well(self):
        self.assertEqual(poll("sonarr", "v3", q(1, unknown_errors=True))[0]["detail"].split(" · ")[-1], "downloads with errors")
        self.assertEqual(poll("sonarr", "v3", q(1, unknown_warnings=True))[0]["detail"].split(" · ")[-1], "downloads with warnings")

    def test_an_error_flag_outranks_a_warning_flag_in_the_words(self):
        r, _ = poll("sonarr", "v3", q(5, errors=True, warnings=True))
        self.assertTrue(r["detail"].endswith("downloads with errors"))
        self.assertNotIn("warnings", r["detail"])

    def test_a_health_error_stays_critical_and_keeps_its_words_first(self):
        r, _ = poll("sonarr", "v3", q(2, errors=True), health=[{"type": "error", "message": "No indexers available"}])
        self.assertEqual(r["status"], I.CRIT)
        self.assertIn("1 error: No indexers available", r["detail"])
        self.assertTrue(r["detail"].endswith("downloads with errors"))

    def test_a_health_warning_and_a_clean_queue_is_still_a_warning_as_before(self):
        r, _ = poll("sonarr", "v3", q(0), health=[{"type": "warning", "message": "Update available"}])
        self.assertEqual(r["status"], I.WARN)
        self.assertEqual(r["metrics"]["queue_problems"], 0)


class TestTheAppsThatDoNotHaveAQueue(unittest.TestCase):
    def test_prowlarr_has_no_route_and_is_unchanged(self):
        r, c = poll("prowlarr", "v1", None)
        self.assertEqual((r["status"], r["detail"]), (I.OK, "Prowlarr 4.0.1 · healthy"))
        self.assertNotIn("queue_total", r["metrics"], "no queue, so no Queue chip rather than a zero")
        self.assertEqual([c["label"] for c in I.format_stats("prowlarr", r["metrics"])], ["Errors", "Warnings"], "the chips it always had, and no Queue")
        self.assertIn(("GET", "/api/v1/queue/status"), c.calls, "it asked, and a 404 is an answer")

    def test_lidarr_asks_on_its_own_api_version(self):
        r, c = poll("lidarr", "v1", q(1, errors=True))
        self.assertEqual(r["status"], I.WARN)
        self.assertIn(("GET", "/api/v1/queue/status"), c.calls)
        self.assertNotIn(("GET", "/api/v3/queue/status"), c.calls)


class TestAnAnswerThatDoesNotComeOrCannotBeRead(unittest.TestCase):
    def test_a_transport_error_on_the_queue_does_not_take_the_connector_down(self):
        r, _ = poll("sonarr", "v3", I.IntegrationError("connection reset"))
        self.assertEqual((r["status"], r["detail"]), (I.OK, "Sonarr 4.0.1 · healthy"))
        self.assertNotIn("queue_total", r["metrics"])

    def test_a_refusal_on_the_queue_is_ignored(self):
        r, _ = poll("sonarr", "v3", (403, "forbidden"))
        self.assertEqual((r["status"], r["detail"]), (I.OK, "Sonarr 4.0.1 · healthy"))
        self.assertNotIn("queue_total", r["metrics"])

    def test_a_body_that_is_not_an_object_is_ignored(self):
        for body in ([], "not json at all", 7, None):
            with self.subTest(body=body):
                c = Fake({("GET", "/api/v3/system/status"): (200, {"appName": "Sonarr", "version": "4"}), ("GET", "/api/v3/health"): (200, []), ("GET", "/api/v3/queue/status"): (200, body)})
                got = I.poll_instance({"type": "sonarr", "url": "http://x", "secret": "KEY"}, c)
                self.assertEqual(got["status"], I.OK)
                self.assertNotIn("queue_total", got["metrics"], "an answer that is not an object is no answer")

    def test_a_count_that_is_not_a_sane_number_is_zero(self):
        for bad in ("3", -5, 10**12, float("nan"), True, None, [1]):
            with self.subTest(total=bad):
                c = Fake({("GET", "/api/v3/system/status"): (200, {"appName": "Sonarr", "version": "4"}), ("GET", "/api/v3/health"): (200, []),
                          ("GET", "/api/v3/queue/status"): (200, '{"totalCount": %s}' % ("NaN" if bad != bad else json.dumps(bad)))})
                got = I.poll_instance({"type": "sonarr", "url": "http://x", "secret": "KEY"}, c)
                self.assertEqual(got["metrics"]["queue_total"], 0, bad)


if __name__ == "__main__":
    unittest.main()

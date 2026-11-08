#!/usr/bin/env python3
"""8.0.0: the UniFi connector speaks the Integration API, which UniFi OS consoles answer, and keeps the older login for a self-hosted controller.

The connector logged in at /api/login and read /api/s/<site>/stat/health: the classic controller only. A UniFi OS console (UDM, UDR, Cloud Gateway, Cloud Key) answers neither, and that is where nearly
every UniFi network runs now. With an API key (made under Integrations in the Network application, sent as X-API-KEY) it asks /proxy/network/integration/v1 instead and reports what a person
wants to know: which adopted devices are down.

The facts are the vendor's own, from its OpenAPI file for Network 10.4.57 (developer.ui.com/network/v10.4.57/openapi.json, read on 2026-11-08): every path is under
/proxy/network/integration; GET /v1/info answers {applicationVersion}; GET /v1/sites is a page {offset, limit (default 25, at most 200), count, totalCount, data} of
{id (a UUID), internalReference (the older name of the site), name}; GET /v1/sites/{siteId}/devices is a page of {id, macAddress, ipAddress, name, model, state, supported,
firmwareUpdatable, firmwareVersion, features, interfaces} with `state` one of ONLINE, OFFLINE, PENDING_ADOPTION, UPDATING, GETTING_READY, ADOPTING, DELETING, CONNECTION_INTERRUPTED, ISOLATED,
U5G_INCORRECT_TOPOLOGY; GET /v1/sites/{siteId}/clients is a page whose totalCount is the number of clients. The first two answers also match a capture of a 10.6.109 console (info
`{"applicationVersion": "10.6.109"}`, one site `default`). `connector-spec-check.py` (remotepower-internal-docs/dev-tools) confirms the four paths exist in the vendor's file.

The connector is run against a fake client; no UniFi console is available here.
"""
import json
import sys
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server" / "cgi-bin"))
import integrations as I  # noqa: E402

BASE = "/proxy/network/integration/v1"
SITE_ID = "88f7af54-98f8-306a-a1c7-c9349722b1f6"          # the id format and the name of the single site in the capture of a real 10.6.109 console
SITE = {"id": SITE_ID, "internalReference": "default", "name": "Default"}


class Fake(I.HTTPClient):
    """Answers by (method, path); a route is (status, payload), a function of the query, or an exception to raise. Anything else is a 404. Every call is kept with its query and headers."""

    def __init__(self, routes, base="https://console"):
        super().__init__(base)
        self.routes, self.calls = routes, []

    def request(self, method, path, headers=None, params=None, body=None):
        u = urlparse(path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        self.calls.append({"method": method, "path": u.path, "query": q, "headers": dict(headers or {}), "body": body})
        v = self.routes.get((method, u.path))
        if v is None:
            return I.Resp(404, "")
        if callable(v):
            v = v(q)
        if isinstance(v, Exception):
            raise v
        st, payload = v
        return I.Resp(st, payload if isinstance(payload, str) else json.dumps(payload))

    def paths(self):
        return [(c["method"], c["path"]) for c in self.calls]


def page(rows, total=None, offset=0, limit=200):
    return {"offset": offset, "limit": limit, "count": len(rows), "totalCount": len(rows) if total is None else total, "data": rows}


def dev(name, state="ONLINE", updatable=False, supported=True, i=0):
    return {"id": f"11111111-1111-4111-8111-{i:012d}", "macAddress": "aa:bb:cc:00:00:%02x" % i, "ipAddress": "192.168.1.%d" % (10 + i), "name": name, "model": "U6-Pro", "state": state,
            "supported": supported, "firmwareUpdatable": updatable, "firmwareVersion": "6.6.55", "features": ["accessPoint"], "interfaces": ["radios"]}


def routes(devices, clients=17, sites=None, info=None, **extra):
    r = {
        ("GET", BASE + "/info"): info or (200, {"applicationVersion": "10.6.109"}),
        ("GET", BASE + "/sites"): (200, page(sites if sites is not None else [SITE])),
        ("GET", BASE + f"/sites/{SITE_ID}/devices"): (200, page(devices)) if not callable(devices) else devices,
        ("GET", BASE + f"/sites/{SITE_ID}/clients"): (200, page([{}], total=clients, limit=1)),
    }
    r.update(extra)
    return r


def poll(rts, slug="", username=""):
    c = Fake(rts)
    inst = {"type": "unifi", "url": "https://console", "secret": "THE-KEY"}
    if slug:
        inst["slug"] = slug
    if username:
        inst["username"] = username
    return I.poll_instance(inst, c), c


class TestTheDevicesOfAnApiKeyConsole(unittest.TestCase):
    def test_a_healthy_site_is_ok_with_the_version_and_the_counts(self):
        r, c = poll(routes([dev("Office AP", i=1), dev("Switch", i=2), dev("Gateway", i=3)]))
        self.assertEqual((r["status"], r["detail"], r["version"]), (I.OK, "3 devices online", "10.6.109"))
        self.assertEqual(r["metrics"], {"devices": 3, "devices_down": 0, "firmware_updates": 0, "clients": 17})
        self.assertEqual(c.paths(), [("GET", BASE + "/info"), ("GET", BASE + "/sites"), ("GET", BASE + f"/sites/{SITE_ID}/devices"), ("GET", BASE + f"/sites/{SITE_ID}/clients")])

    def test_the_key_goes_in_x_api_key_on_every_call_and_the_pages_are_asked_for_at_the_vendors_limit(self):
        _r, c = poll(routes([dev("AP", i=1)]))
        self.assertTrue(all(call["headers"].get("X-API-KEY") == "THE-KEY" for call in c.calls), [call["headers"] for call in c.calls])
        by_path = {call["path"]: call["query"] for call in c.calls}
        self.assertEqual(by_path[BASE + "/sites"], {"offset": "0", "limit": "200"})
        self.assertEqual(by_path[BASE + f"/sites/{SITE_ID}/devices"], {"offset": "0", "limit": "200"})
        self.assertEqual(by_path[BASE + f"/sites/{SITE_ID}/clients"], {"offset": "0", "limit": "1"}, "only the total of the clients is wanted")

    def test_no_login_is_made_without_a_username(self):
        _r, c = poll(routes([dev("AP", i=1)]))
        self.assertNotIn(("POST", "/api/login"), c.paths())
        self.assertFalse([p for m, p in c.paths() if p.startswith("/api/")])

    def test_a_device_that_is_offline_interrupted_or_isolated_is_critical_and_named(self):
        for state in ("OFFLINE", "CONNECTION_INTERRUPTED", "ISOLATED"):
            with self.subTest(state=state):
                r, _ = poll(routes([dev("Office AP", i=1), dev("Garage AP", state, i=2)]))
                self.assertEqual(r["status"], I.CRIT)
                self.assertEqual(r["detail"], "1 of 2 devices down: Garage AP")
                self.assertEqual((r["metrics"]["devices"], r["metrics"]["devices_down"]), (2, 1))

    def test_the_states_that_are_a_step_on_the_way_are_not_a_fault(self):
        for state in ("PENDING_ADOPTION", "UPDATING", "GETTING_READY", "ADOPTING", "DELETING"):
            with self.subTest(state=state):
                r, _ = poll(routes([dev("AP", state, i=1)]))
                self.assertEqual(r["status"], I.OK)
                self.assertEqual(r["metrics"]["devices_down"], 0)

    def test_an_incorrect_u5g_topology_is_a_warning(self):
        r, _ = poll(routes([dev("LTE", "U5G_INCORRECT_TOPOLOGY", i=1)]))
        self.assertEqual((r["status"], r["detail"]), (I.WARN, "1 device(s) with an incorrect topology (U5G)"))

    def test_more_than_three_down_are_named_three_and_counted_all(self):
        r, _ = poll(routes([dev("AP %d" % i, "OFFLINE", i=i) for i in range(1, 6)]))
        self.assertEqual(r["detail"], "5 of 5 devices down: AP 1, AP 2, AP 3 …")

    def test_a_device_with_no_name_is_named_by_its_mac(self):
        d = dev("", "OFFLINE", i=9)
        r, _ = poll(routes([d]))
        self.assertIn("aa:bb:cc:00:00:09", r["detail"])

    def test_firmware_updates_are_counted_and_do_not_change_the_status(self):
        r, _ = poll(routes([dev("A", updatable=True, i=1), dev("B", updatable=True, i=2), dev("C", updatable=True, supported=False, i=3), dev("D", i=4)]))
        self.assertEqual(r["status"], I.OK)
        self.assertEqual(r["metrics"]["firmware_updates"], 2, "a device the application does not support is not counted")
        self.assertTrue(r["detail"].endswith("2 firmware updates available"), r["detail"])
        r1, _ = poll(routes([dev("A", updatable=True, i=1)]))
        self.assertTrue(r1["detail"].endswith("1 firmware update available"))

    def test_no_adopted_device_is_said_in_words(self):
        r, _ = poll(routes([]))
        self.assertEqual((r["status"], r["detail"]), (I.OK, "no adopted devices"))

    def test_the_card_shows_four_chips(self):
        r, _ = poll(routes([dev("A", updatable=True, i=1), dev("B", "OFFLINE", i=2)]))
        chips = {x["label"]: x["value"] for x in I.format_stats("unifi", r["metrics"])}
        self.assertEqual(chips, {"Devices": "2", "Down": "1", "Clients": "17", "Updates": "1"})


class TestWhichSite(unittest.TestCase):
    OTHER = {"id": "22222222-2222-4222-8222-222222222222", "internalReference": "branch", "name": "Branch office"}

    def test_the_site_is_chosen_by_the_name_the_older_api_used(self):
        rts = routes([dev("Hq AP", i=1)], sites=[self.OTHER, SITE])
        r, c = poll(rts)
        self.assertEqual(r["detail"], "1 devices online")
        self.assertIn(("GET", BASE + f"/sites/{SITE_ID}/devices"), c.paths())

    def test_another_site_by_its_reference(self):
        oid = self.OTHER["id"]
        rts = routes([dev("Hq AP", i=1)], sites=[SITE, self.OTHER])
        rts[("GET", BASE + f"/sites/{oid}/devices")] = (200, page([dev("Branch AP", "OFFLINE", i=5)]))
        rts[("GET", BASE + f"/sites/{oid}/clients")] = (200, page([{}], total=3, limit=1))
        r, _ = poll(rts, slug="branch")
        self.assertEqual((r["status"], r["detail"], r["metrics"]["clients"]), (I.CRIT, "1 of 1 devices down: Branch AP", 3))

    def test_a_site_that_is_not_there_names_the_ones_that_are(self):
        r, _ = poll(routes([dev("AP", i=1)], sites=[SITE, self.OTHER]), slug="nowhere")
        self.assertEqual(r["status"], I.CRIT)
        self.assertIn("'nowhere' not found", r["detail"])
        self.assertIn("branch, default", r["detail"])

    def test_a_single_site_is_used_when_none_was_named_even_if_it_is_not_called_default(self):
        only = dict(SITE, internalReference="main")
        r, _ = poll(routes([dev("AP", i=1)], sites=[only]))
        self.assertEqual(r["status"], I.OK)

    def test_a_named_site_that_does_not_match_the_only_site_is_not_guessed(self):
        only = dict(SITE, internalReference="main")
        r, _ = poll(routes([dev("AP", i=1)], sites=[only]), slug="default")
        self.assertEqual(r["status"], I.CRIT)

    def test_a_site_id_that_is_not_an_id_is_refused_before_it_reaches_a_path(self):
        for bad in ("../../etc", "a/b", "x" * 80, "short", ""):
            with self.subTest(site_id=bad):
                r, c = poll(routes([dev("AP", i=1)], sites=[dict(SITE, id=bad)]))
                self.assertEqual(r["status"], I.CRIT)
                self.assertIn("not one", r["detail"])
                self.assertFalse([p for m, p in c.paths() if "/devices" in p], "no request went out with it")


class TestPages(unittest.TestCase):
    def test_every_page_is_read_until_the_total(self):
        rows = [dev("AP %d" % i, i=i) for i in range(450)]

        def devices(q):
            off, lim = int(q["offset"]), int(q["limit"])
            return 200, page(rows[off:off + lim], total=450, offset=off, limit=lim)

        r, c = poll(routes(devices))
        self.assertEqual(r["metrics"]["devices"], 450)
        self.assertEqual([call["query"]["offset"] for call in c.calls if call["path"].endswith("/devices")], ["0", "200", "400"])

    def test_a_site_with_more_than_the_budget_says_it_counted_the_first_part(self):
        rows = [dev("AP %d" % i, i=i % 900) for i in range(1100)]

        def devices(q):
            off, lim = int(q["offset"]), int(q["limit"])
            return 200, page(rows[off:off + lim], total=1500, offset=off, limit=lim)

        r, c = poll(routes(devices))
        self.assertEqual(r["metrics"]["devices"], 1000)
        self.assertIn("counted the first 1000 of 1500", r["detail"])
        self.assertEqual(len([1 for call in c.calls if call["path"].endswith("/devices")]), 5, "five pages, and no more")

    def test_a_page_that_stops_giving_rows_does_not_loop(self):
        def devices(q):
            return 200, page([] if int(q["offset"]) else [dev("AP", i=1)], total=999)

        r, c = poll(routes(devices))
        self.assertEqual(r["metrics"]["devices"], 1)
        self.assertEqual(len([1 for call in c.calls if call["path"].endswith("/devices")]), 2)


class TestWhatGoesWrong(unittest.TestCase):
    def test_a_key_the_console_refuses_says_so(self):
        for status in (401, 403):
            with self.subTest(status=status):
                r, _ = poll(routes([dev("AP", i=1)], info=(status, {"error": "no"})))
                self.assertEqual(r["status"], I.CRIT)
                self.assertIn(f"unauthorized (HTTP {status})", r["detail"])
                self.assertIn("API key", r["detail"])

    def test_a_console_that_does_not_have_the_api_says_what_to_check(self):
        r, _ = poll({})
        self.assertEqual(r["status"], I.CRIT)
        self.assertIn("is this a UniFi OS console or a Network application from 9.0", r["detail"])

    def test_the_devices_refused_after_the_info_was_not_is_still_said(self):
        r, _ = poll(routes([], **{}) | {("GET", BASE + f"/sites/{SITE_ID}/devices"): (403, "")})
        self.assertEqual(r["status"], I.CRIT)
        self.assertIn("unauthorized (HTTP 403)", r["detail"])

    def test_a_body_that_is_not_a_page_is_an_error_and_not_an_empty_list(self):
        for body in ({"nope": 1}, [], "text"):
            with self.subTest(body=body):
                r, _ = poll(routes([]) | {("GET", BASE + f"/sites/{SITE_ID}/devices"): (200, body)})
                self.assertEqual(r["status"], I.CRIT)
                self.assertTrue("did not answer a page" in r["detail"] or "invalid JSON" in r["detail"], r["detail"])

    def test_the_client_count_is_a_nicety_and_its_failure_does_not_matter(self):
        r, _ = poll(routes([dev("AP", i=1)]) | {("GET", BASE + f"/sites/{SITE_ID}/clients"): (500, "boom")})
        self.assertEqual(r["status"], I.OK)
        self.assertNotIn("clients", r["metrics"])
        self.assertEqual(I.format_stats("unifi", r["metrics"])[0]["label"], "Devices")

    def test_a_count_that_is_not_a_sane_number_is_the_length_of_the_page(self):
        for bad in ("many", -3, 10**12, True, None):
            with self.subTest(total=bad):
                rts = routes([dev("AP", i=1)]) | {("GET", BASE + f"/sites/{SITE_ID}/devices"): (200, {"data": [dev("AP", i=1)], "totalCount": bad})}
                r, _ = poll(rts)
                self.assertEqual((r["status"], r["metrics"]["devices"]), (I.OK, 1))

    def test_rows_that_are_not_objects_are_left_out(self):
        def devices(q):
            return 200, ({"data": [dev("AP", i=1), "x", 7, None], "totalCount": 4} if q["offset"] == "0" else {"data": [], "totalCount": 4})

        r, _ = poll(routes(devices))
        self.assertEqual(r["metrics"]["devices"], 1)


class TestTheOlderLoginIsStillThere(unittest.TestCase):
    def test_a_username_means_the_classic_controller_and_the_old_answer(self):
        rts = {("POST", "/api/login"): (200, {}), ("GET", "/api/s/default/stat/health"): (200, {"data": [{"subsystem": "wlan", "status": "ok"}, {"subsystem": "wan", "status": "error"}]})}
        c = Fake(rts)
        r = I.poll_instance({"type": "unifi", "url": "https://console", "secret": "pw", "username": "admin"}, c)
        self.assertEqual((r["status"], r["detail"], r["metrics"]), (I.CRIT, "degraded: wan", {"subsystems": 2, "subsystems_bad": 1}))
        self.assertEqual(c.paths(), [("POST", "/api/login"), ("GET", "/api/s/default/stat/health")])
        self.assertEqual(json.loads(c.calls[0]["body"])["username"], "admin")
        self.assertFalse([p for m, p in c.paths() if "integration" in p], "the older mode does not touch the Integration API")

    def test_the_old_site_name_is_used_in_the_old_path(self):
        c = Fake({("POST", "/api/login"): (200, {}), ("GET", "/api/s/branch/stat/health"): (200, {"data": []})})
        I.poll_instance({"type": "unifi", "url": "https://console", "secret": "pw", "username": "admin", "slug": "branch"}, c)
        self.assertIn(("GET", "/api/s/branch/stat/health"), c.paths())


class TestTheFormsAndTheWords(unittest.TestCase):
    def test_the_key_is_the_required_field_and_the_older_login_is_optional(self):
        fields = {f["key"]: f for f in I.CONNECTORS["unifi"]["fields"]}
        self.assertEqual(list(fields), ["secret", "username", "slug"])
        self.assertFalse(fields["secret"]["optional"])
        self.assertEqual(fields["secret"]["kind"], I.PASSWORD)
        self.assertTrue(fields["username"]["optional"] and fields["slug"]["optional"])
        self.assertIn("X-API-KEY", I.CONNECTORS["unifi"]["notes"])
        self.assertIn("older login", I.CONNECTORS["unifi"]["notes"])


if __name__ == "__main__":
    unittest.main()

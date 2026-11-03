#!/usr/bin/env python3
"""7.4.9: Mattermost, Rocket.Chat, Google Chat and Gotify are destinations of their own, and ntfy reads the priority.

Before this, those four services got the generic JSON body (Google Chat refuses it, Mattermost and Rocket.Chat show an
empty message, Gotify shows a quiet one), or the operator picked "Slack" and hoped. Each builder is checked for the shape
the service documents, then the real dispatcher is driven with a recording opener so a builder that is never called cannot
pass. ntfy got a fix on the way: its priority table only knew 0 to 2, while RemotePower sends 3, 4 and 5, so every alert
reached ntfy as the default priority.
"""
import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v749-chat-"))
_spec = importlib.util.spec_from_file_location("api_v749_chat", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
notify = sys.modules["notify"]

NEW = ("mattermost", "rocketchat", "googlechat", "gotify")


class _Resp:
    status = 200

    def read(self, *_a):
        return b""


class _Opener:
    """Records the request the dispatcher would have sent."""

    def __init__(self):
        self.sent = []

    def open(self, req, timeout=None):
        self.sent.append(req)
        return _Resp()


class TestTheBuilders(unittest.TestCase):

    def test_mattermost_has_a_bold_first_line_and_a_coloured_attachment(self):
        body, headers, ctype = notify._build_mattermost_body("device_offline", "Host down", "web1 is down")
        data = json.loads(body)
        self.assertEqual(ctype, "application/json")
        self.assertEqual(headers, {})
        self.assertEqual(data["text"], "**Host down**")
        att = data["attachments"][0]
        self.assertEqual(att["text"], "web1 is down")
        self.assertEqual(att["color"], "#EF4444")
        self.assertIn("Host down", att["fallback"])

    def test_the_bar_is_green_for_a_recovery_and_blue_for_the_rest(self):
        self.assertEqual(json.loads(notify._build_mattermost_body("device_online", "t", "m")[0])["attachments"][0]["color"], "#22C55E")
        # container_healthy is not in the colour table; it is a recovery of an alert, so it is green
        self.assertIn("container_healthy", notify._RECOVER_EVENTS)
        self.assertEqual(json.loads(notify._build_rocketchat_body("container_healthy", "t", "m")[0])["attachments"][0]["color"], "#22C55E")
        self.assertEqual(json.loads(notify._build_rocketchat_body("some_unlisted_event", "t", "m")[0])["attachments"][0]["color"], "#3B7EFF")

    def test_rocketchat_shape(self):
        data = json.loads(notify._build_rocketchat_body("cve_found", "CVE", "1 critical")[0])
        self.assertEqual(data["alias"], "RemotePower")
        self.assertEqual(data["text"], "*CVE*")
        self.assertEqual(data["attachments"], [{"color": "#EF4444", "text": "1 critical"}])

    def test_google_chat_is_text_only_and_cut_below_the_limit(self):
        data = json.loads(notify._build_googlechat_body("device_offline", "Host down", "x" * 9000)[0])
        self.assertEqual(list(data), ["text"])
        self.assertTrue(data["text"].startswith("*Host down*\n"))
        self.assertLessEqual(len(data["text"]), 4000)

    def test_gotify_priorities_ring_where_the_app_rings(self):
        got = {p: json.loads(notify._build_gotify_body("e", "T", "M", p)[0])["priority"] for p in (3, 4, 5)}
        self.assertEqual(got, {3: 5, 4: 8, 5: 10})
        for low in (0, 1, 2):
            self.assertEqual(json.loads(notify._build_gotify_body("e", "T", "M", low)[0])["priority"], 3)
        for junk in (None, "4", 99, -1, 4.5):
            self.assertIsInstance(json.loads(notify._build_gotify_body("e", "T", "M", junk)[0])["priority"], int)

    def test_none_and_unicode_do_not_raise(self):
        for fn in (notify._build_mattermost_body, notify._build_rocketchat_body, notify._build_googlechat_body):
            for title, message in (("", None), (None, ""), ("Hôte ⚠", "ünïcode 主机   \x00")):
                body = fn("device_offline", title, message)[0]
                json.loads(body)
        json.loads(notify._build_gotify_body("e", None, None, 4)[0])


class TestNtfyPriority(unittest.TestCase):

    def prio(self, p):
        return notify._build_ntfy_body("device_offline", "T", "M", p)[1]["Priority"]

    def test_the_real_scale_goes_through(self):
        self.assertEqual([self.prio(p) for p in (3, 4, 5)], ["3", "4", "5"])

    def test_the_old_zero_to_two_scale_still_maps_as_it_did(self):
        self.assertEqual([self.prio(p) for p in (0, 1, 2)], ["3", "4", "5"])

    def test_junk_is_the_default(self):
        for junk in (None, "5", 99, -1, True, 4.5):
            self.assertEqual(self.prio(junk), "3", junk)

    def test_a_critical_event_reaches_ntfy_as_urgent(self):
        # drive it from the event, the way the dispatcher does: metric_critical is priority 5
        self.assertEqual(api._webhook_priority("metric_critical"), 5)
        self.assertEqual(self.prio(api._webhook_priority("metric_critical")), "5")
        self.assertEqual(self.prio(api._webhook_priority("device_offline")), "4")


class TestDetection(unittest.TestCase):

    def test_hosted_services_are_recognised(self):
        for url, fmt in (("https://chat.googleapis.com/v1/spaces/AAA/messages?key=k&token=t", "googlechat"),
                         ("https://acme.cloud.mattermost.com/hooks/abc", "mattermost"),
                         ("https://open.rocket.chat/hooks/a/b", "rocketchat")):
            self.assertEqual(api._auto_detect_format(url), fmt, url)

    def test_a_look_alike_host_is_not(self):
        for url in ("https://chat.googleapis.com.evil.example/x", "https://evilcloud.mattermost.com.example/x",
                    "https://notrocket.chat.example/x", "https://example.com/chat.googleapis.com"):
            self.assertEqual(api._auto_detect_format(url), "generic", url)


class TestTheDispatcher(unittest.TestCase):
    """The real _dispatch_one_webhook with a recording opener: a builder nobody calls cannot pass."""

    def setUp(self):
        api.save(api.CONFIG_FILE, {"webhook_block_local": False})
        api._LOAD_CACHE.clear()
        self.opener = _Opener()
        self._patch = mock.patch.object(api, "_ssrf_safe_opener", return_value=self.opener)
        self._patch.start()
        self.addCleanup(self._patch.stop)

    def send(self, fmt, url="https://chat.example.com/hook?token=t", event="device_offline", priority=4):
        dest = {"id": "d1", "url": url, "format": fmt, "enabled": True}
        api._dispatch_one_webhook(event, dest, {"name": "web1"}, "web1 is down", "Host down", priority)
        self.assertEqual(len(self.opener.sent), 1, fmt)
        return self.opener.sent[0]

    def test_each_new_format_sends_its_own_body_to_the_given_url(self):
        shapes = {"mattermost": lambda d: d["attachments"][0]["color"] == "#EF4444" and d["text"] == "**Host down**",
                  "rocketchat": lambda d: d["alias"] == "RemotePower" and d["text"] == "*Host down*",
                  "googlechat": lambda d: list(d) == ["text"] and "web1 is down" in d["text"],
                  "gotify": lambda d: d == {"title": "Host down", "message": "web1 is down", "priority": 8}}
        for fmt, ok in shapes.items():
            with self.subTest(fmt=fmt):
                self.opener.sent.clear()
                req = self.send(fmt)
                self.assertEqual(req.full_url, "https://chat.example.com/hook?token=t")
                self.assertEqual(req.get_method(), "POST")
                self.assertTrue(ok(json.loads(req.data)), req.data)
                self.assertNotIn("schema_version", json.loads(req.data))      # not the generic contract

    def test_the_format_a_stored_destination_carries_is_the_one_used(self):
        # a legacy destination with no format falls back to detection on its URL
        self.opener.sent.clear()
        dest = {"id": "d2", "url": "https://chat.googleapis.com/v1/spaces/A/messages?key=k&token=t", "enabled": True}
        api._dispatch_one_webhook("device_offline", dest, {}, "m", "t", 4)
        self.assertEqual(list(json.loads(self.opener.sent[0].data)), ["text"])

    def test_ntfy_goes_out_with_the_events_real_priority(self):
        req = self.send("ntfy", url="https://ntfy.example.com/alerts", event="metric_critical", priority=5)
        self.assertEqual(req.get_header("Priority"), "5")


class TestTheLists(unittest.TestCase):

    def test_the_server_accepts_the_new_formats(self):
        for f in NEW:
            self.assertIn(f, api._WEBHOOK_FORMATS)

    def test_the_editor_offers_exactly_the_formats_the_server_accepts(self):
        js = (ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()
        block = js[js.index("const _WEBHOOK_FORMATS = ["):]
        block = block[:block.index("];")]
        offered = set(re.findall(r"^\s*\['([a-z]+)',", block, re.M))
        self.assertEqual(offered, set(api._WEBHOOK_FORMATS))

    def test_api_exports_the_builders(self):
        for name in ("_build_mattermost_body", "_build_rocketchat_body", "_build_googlechat_body", "_build_gotify_body"):
            self.assertIs(getattr(api, name), getattr(notify, name))

    def test_the_webhook_guide_lists_every_format(self):
        doc = (ROOT / "docs" / "webhooks.md").read_text()
        for f in NEW:
            self.assertRegex(doc, r"\| `%s` \|" % f)


if __name__ == "__main__":
    unittest.main()

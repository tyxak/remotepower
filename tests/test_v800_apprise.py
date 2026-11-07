#!/usr/bin/env python3
"""8.0.0: Apprise is a destination of its own.

Apprise puts one URL scheme in front of ninety-odd services and is run as an API server, so a homelab that already has one can send every
RemotePower alert there and keep the choice of services in one place. The body is `POST <server>/notify/<key>` with a title, a body, a type
and a format. The type is what the receiving service turns into a colour or an icon, so the three levels RemotePower sends (3 normal, 4 high,
5 urgent) become info, warning and failure, and the recovery of an alert is a success. The builder is checked for that shape, then the real
dispatcher is driven with a recording opener so a builder that is never called cannot pass, then the lists (what the server accepts, what the
editor offers, what the guide documents, what the wizard shows) are held together.
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
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v800-apprise-"))
_spec = importlib.util.spec_from_file_location("api_v800_apprise", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
notify = sys.modules["notify"]
JS = ROOT / "server" / "html" / "static" / "js"


class _Resp:
    status = 200

    def read(self, *_a):
        return b""


class _Opener:
    def __init__(self):
        self.sent = []

    def open(self, req, timeout=None):
        self.sent.append(req)
        return _Resp()


class TestTheBuilder(unittest.TestCase):

    def build(self, event="device_offline", title="Host down", message="web1 is down", priority=4):
        body, headers, ctype = notify._build_apprise_body(event, title, message, priority)
        self.assertEqual(ctype, "application/json")
        self.assertEqual(headers, {}, "the key is in the URL: nothing to send as a header")
        return json.loads(body)

    def test_the_shape_apprise_documents(self):
        self.assertEqual(self.build(), {"title": "Host down", "body": "web1 is down", "type": "warning", "format": "text"})

    def test_the_three_levels_become_info_warning_and_failure(self):
        self.assertEqual([self.build(priority=p)["type"] for p in (3, 4, 5)], ["info", "warning", "failure"])

    def test_a_recovery_is_a_success_whatever_its_priority(self):
        self.assertIn("device_online", notify._RECOVER_EVENTS)
        for p in (3, 4, 5):
            self.assertEqual(self.build(event="device_online", priority=p)["type"], "success", p)

    def test_a_priority_that_is_not_one_of_the_three_is_info(self):
        for p in (0, 1, 2, 6, 99, -1, None, True, False, "5", 4.0, [], {}):
            with self.subTest(p=repr(p)):
                self.assertEqual(self.build(priority=p)["type"], "info")

    def test_text_is_sent_as_text_so_the_service_does_not_read_markup_into_it(self):
        self.assertEqual(self.build()["format"], "text")

    def test_long_text_is_cut_and_missing_text_is_empty(self):
        d = self.build(title="t" * 400, message="m" * 9000)
        self.assertEqual((len(d["title"]), len(d["body"])), (250, 4000))
        d = self.build(title=None, message=None)
        self.assertEqual((d["title"], d["body"]), ("", ""))

    def test_non_ascii_text_survives(self):
        d = self.build(title="Værten er nede", message="サーバーが停止 — 2 hosts")
        self.assertEqual((d["title"], d["body"]), ("Værten er nede", "サーバーが停止 — 2 hosts"))

    def test_what_a_host_chose_to_call_itself_does_nothing_behind_the_key(self):
        # the words in an alert come from the hosts, and Apprise passes them to Slack, Discord, Telegram and the rest: each of those acts on
        # something (a mention, a labelled link, a "<"), so nothing of the kind may be left in the title or the body
        from test_v749_chat_text import HOSTILE, active
        self.assertTrue(HOSTILE, "the population is not empty")
        for text in HOSTILE:
            d = self.build(title=text, message=text)
            for s in (d["title"], d["body"]):
                self.assertEqual(active("apprise", s), [], (text, s))
        # and the control: the same text unchanged WOULD be acted on, so the check above can fail
        self.assertTrue(any(active("apprise", t) for t in HOSTILE))

    def test_the_words_stay_readable(self):
        d = self.build(title="web1 @channel", message="see [the log](http://e.example) <b>x</b>")
        self.assertEqual(d["title"].replace("\u200b", ""), "web1 @channel")
        self.assertEqual(d["body"].replace("\u200b", ""), "see [the log](http://e.example) <b>x</b>")

    def test_it_is_not_the_generic_contract(self):
        d = self.build()
        for k in ("schema_version", "event", "ts", "priority"):
            self.assertNotIn(k, d)


class TestTheDispatcher(unittest.TestCase):
    """The real _dispatch_one_webhook with a recording opener."""

    def setUp(self):
        api.save(api.CONFIG_FILE, {"webhook_block_local": False})
        api._LOAD_CACHE.clear()
        self.opener = _Opener()
        self._patch = mock.patch.object(api, "_ssrf_safe_opener", return_value=self.opener)
        self._patch.start()
        self.addCleanup(self._patch.stop)

    def send(self, event="device_offline", priority=4, url="https://apprise.example.com/notify/home"):
        dest = {"id": "a1", "url": url, "format": "apprise", "enabled": True}
        api._dispatch_one_webhook(event, dest, {"name": "web1"}, "web1 is down", "Host down", priority)
        self.assertEqual(len(self.opener.sent), 1)
        return self.opener.sent[0]

    def test_it_posts_the_apprise_body_to_the_given_address(self):
        req = self.send()
        self.assertEqual(req.full_url, "https://apprise.example.com/notify/home")
        self.assertEqual(req.get_method(), "POST")
        self.assertEqual(json.loads(req.data), {"title": "Host down", "body": "web1 is down", "type": "warning", "format": "text"})
        self.assertEqual(req.get_header("Content-type"), "application/json")

    def test_a_recovery_and_an_urgent_alert_carry_their_own_type(self):
        self.assertEqual(json.loads(self.send(event="device_online", priority=3).data)["type"], "success")
        self.opener.sent.clear()
        self.assertEqual(json.loads(self.send(priority=5).data)["type"], "failure")

    def test_an_apprise_server_on_the_lan_is_reachable_and_the_metadata_address_is_not(self):
        # the default keeps a destination from being aimed at a cloud metadata service and still lets a homelab Apprise on a private address
        # work, which is how nearly every one is run
        api.save(api.CONFIG_FILE, {"webhook_block_local": True})
        api._LOAD_CACHE.clear()
        lan = {"id": "a2", "url": "http://192.168.1.20:8000/notify/home", "format": "apprise", "enabled": True}
        api._dispatch_one_webhook("device_offline", lan, {}, "m", "t", 4)
        self.assertEqual(len(self.opener.sent), 1)
        self.opener.sent.clear()
        meta = {"id": "a3", "url": "http://169.254.169.254/notify/home", "format": "apprise", "enabled": True}
        api._dispatch_one_webhook("device_offline", meta, {}, "m", "t", 4)
        self.assertEqual(self.opener.sent, [])


class TestTheLists(unittest.TestCase):

    def test_the_server_accepts_it_and_exports_the_builder(self):
        self.assertIn("apprise", api._WEBHOOK_FORMATS)
        self.assertIs(api._build_apprise_body, notify._build_apprise_body)

    def test_the_editor_offers_it_with_an_example_address(self):
        js = (JS / "app.js").read_text()
        block = js[js.index("const _WEBHOOK_FORMATS = ["):]
        block = block[:block.index("];")]
        self.assertRegex(block, r"\['apprise',\s+'Apprise',\s+'https://[^']*/notify/<key>'\]")
        offered = set(re.findall(r"^\s*\['([a-z]+)',", block, re.M))
        self.assertEqual(offered, set(api._WEBHOOK_FORMATS))

    def test_the_wizard_shows_it_under_one_heading_with_a_hint_and_no_fields(self):
        wiz = (JS / "app-wizard.js").read_text()
        groups = wiz[wiz.index("const _WIZ_NOTIFY_GROUPS = ["):]
        groups = groups[:groups.index("];")]
        self.assertEqual(groups.count("'apprise'"), 1)
        row = re.search(r"^\s*apprise:\s*\{(.*?)\},?\s*$", wiz, re.M)
        self.assertTrue(row, "the wizard has no entry for it")
        self.assertIn("hint:", row.group(1))
        self.assertNotIn("fields:", row.group(1), "the key is part of the address: nothing else to ask")

    def test_the_guides_list_it(self):
        self.assertRegex((ROOT / "docs" / "webhooks.md").read_text(), r"\| `apprise` \|")
        self.assertIn("Apprise", (ROOT / "docs" / "settings.md").read_text())
        self.assertIn("Nineteen services", (ROOT / "docs" / "wizards.md").read_text())

    def test_every_format_the_server_accepts_is_documented_in_the_webhook_guide(self):
        doc = (ROOT / "docs" / "webhooks.md").read_text()
        missing = [f for f in api._WEBHOOK_FORMATS if f != "generic" and not re.search(r"\| `%s` \|" % f, doc)]
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""7.4.9: what a host writes into an alert does not ping anyone and does not hide a link.

An alert is built from what the hosts report: a host's name, a container, a service, a line of a log. Whoever runs on the
host chose those words, and a chat service acts on some of them: a mention pings people, a labelled link sends them to an
address the label does not show. Until now the text went into the body as written. Each builder for a service that reads
mentions or links now passes it through notify.defuse(), and a host named "@channel" is shown as "@channel" and pings
nobody.

The checks are made from the receiving side. For each service the helper carries its own idea of "active" (what Slack,
Mattermost, Telegram, Google Chat and the others document as a mention or a link), and it is held against what the real
dispatcher sends for a hostile host name. The list of formats is read from the product, so a new format has to be placed on
one of the two lists below before the suite passes.
"""
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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v749-chat-text-"))
import api  # noqa: E402
import notify  # noqa: E402

ZW = "\u200b"

# what a chat service reads the text for. A format is on the first list when it does either, and the second when it does
# neither, with the reason.
DEFUSED = ("slack", "discord", "teams", "googlechat", "mattermost", "rocketchat", "telegram", "matrix", "github")
PLAIN = {
    "generic": "a JSON body for a program; the receiver decides what a name means (docs/webhooks.md says so)",
    "ntfy": "plain text, and Markdown is off unless the sender asks for it, which RemotePower does not",
    "gotify": "plain text, and the message type is not set to Markdown",
    "pushover": "plain text, and html and monospace are not set",
    "pagerduty": "fields of an incident; nothing in them pings",
    "opsgenie": "fields of an alert; nothing in them pings",
    "jira": "fields of a ticket that is filed, not a message that is sent to a room",
    "servicenow": "fields of a ticket that is filed, not a message that is sent to a room",
    "zendesk": "fields of a ticket that is filed, not a message that is sent to a room",
}

# what a host can be named, a container called, a log line say
HOSTILE = [
    "@channel",
    "@here",
    "@all",
    "@everyone",
    "@room",
    "@jane",
    "web1 @channel is down",
    "ping:@here",
    "(@channel)",
    '"@channel"',
    "line one\n@channel",
    "@@here",
    ".@here",
    "@CHANNEL",
    "@jørgen",
    "<!channel>",
    "<!here|here>",
    "<!everyone>",
    "<@U024BE7LH>",
    "<@U024BE7LH|jane>",
    "<!subteam^S0614TZR7>",
    "<#C024BE7LR>",
    "<http://evil.example|Update your password>",
    "<users/all>",
    "<users/1234567890>",
    "<https://evil.example|label>",
    "[Sign in again](http://evil.example)",
    "![x](http://evil.example/p.png)",
    "[Sign in again][1]\n\n[1]: http://evil.example",
    "[1]: http://evil.example",
    "<img src=x onerror=alert(1)>",
    "<a href='http://evil.example'>x</a>",
    "a & b < c > d",
    "&lt;!channel&gt;",
    "mixed @channel <!here> [x](http://e) <users/all>",
    "",
]
# text that is not hostile and has to come out unchanged
INNOCENT = [
    "web1 is down",
    "ops@example.org",
    "first.last@example.org is the owner",
    "disk /dev/sda1 at 91% (limit 90%)",
    "CPU 412.5% (alert at 100%)",
    "Hôte ⚠ 主机 مضيف",
    "tab\tand\nnewline",
    "price is $5 #1 ~ ok",
    "[ok] all fine",
    "mail me @ noon, a @ b, and 5 @ 3",
    "array[0] = 1, f(x)",
]


def _undone(fmt, s):
    """`s` as a reader of the service sees it: the zero-width spaces gone and, for Slack, the three entities decoded."""
    s = s.replace(ZW, "")
    if fmt == "slack":
        s = s.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
    return s


# what the service itself would act on, written independently of notify.defuse
_AT_WORD = re.compile(r"(?<!\w)@\w")
_MD_LINK = re.compile(r"\]([(\[:])")
_SLACK_CONTROL = re.compile(r"[<>]|&(?!amp;|lt;|gt;)")
_GCHAT_CONTROL = re.compile(r"<(?!" + ZW + ")")


def active(fmt, s):
    """The things in `s` that service `fmt` would act on. Empty means nothing."""
    out = []
    if fmt == "slack":
        out += _SLACK_CONTROL.findall(s)
    if fmt == "googlechat":
        out += _GCHAT_CONTROL.findall(s)
    if fmt in ("mattermost", "rocketchat", "github", "telegram"):
        out += _AT_WORD.findall(s)
    if fmt in ("mattermost", "rocketchat", "github", "teams", "discord"):
        out += _MD_LINK.findall(s)
    if fmt in ("github", "teams"):
        out += _GCHAT_CONTROL.findall(s)
    return out


def _strings(node):
    """Every string in a body that a person reads: all of them, except the keys."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from _strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _strings(v)


def _readable(fmt, data):
    """The strings of a body that a person reads as text. A GitHub issue is read in its body only: its title is plain
    text where nothing is rendered or notified, and after the separator the body holds the raw payload in a fenced block,
    which is not rendered either."""
    if fmt == "github":
        yield data["body"].split("\n\n---\n\n")[0]
        return
    yield from _strings(data)


class TestDefuse(unittest.TestCase):

    def test_nothing_the_service_would_act_on_is_left(self):
        for fmt in DEFUSED:
            for text in HOSTILE:
                with self.subTest(fmt=fmt, text=text):
                    self.assertEqual(active(fmt, notify.defuse(text, fmt)), [])

    def test_the_words_are_the_same_to_a_reader(self):
        for fmt in DEFUSED:
            for text in HOSTILE + INNOCENT:
                with self.subTest(fmt=fmt, text=text):
                    self.assertEqual(_undone(fmt, notify.defuse(text, fmt)), text)

    def test_text_that_is_not_hostile_is_not_touched(self):
        # the formats that rewrite text only where a service would act on it leave an ordinary line alone, byte for byte
        for fmt in ("googlechat", "mattermost", "rocketchat", "telegram", "discord", "teams", "github"):
            for text in INNOCENT:
                with self.subTest(fmt=fmt, text=text):
                    self.assertEqual(notify.defuse(text, fmt), text)

    def test_slack_changes_only_the_three_characters_it_asks_for(self):
        for text in INNOCENT:
            self.assertEqual(notify.defuse(text, "slack"), text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
        self.assertEqual(notify.defuse("a & b", "slack"), "a &amp; b")
        self.assertEqual(notify.defuse("&lt;", "slack"), "&amp;lt;", "an entity in the text is text, so its ampersand is escaped too")

    def test_an_address_is_not_a_mention(self):
        for fmt in ("mattermost", "rocketchat", "telegram", "github"):
            self.assertEqual(notify.defuse("mail ops@example.org now", fmt), "mail ops@example.org now")
            self.assertEqual(notify.defuse("mail @ops now", fmt), "mail @" + ZW + "ops now")

    def test_every_form_a_markdown_link_takes_is_broken(self):
        for fmt in ("mattermost", "rocketchat", "github", "teams", "discord"):
            for text in ("[a](http://e)", "[a][r]", "[r]: http://e", "![a](http://e)"):
                with self.subTest(fmt=fmt, text=text):
                    out = notify.defuse(text, fmt)
                    self.assertNotRegex(out, r"\][(\[:]")
                    self.assertIn("a]" + ZW if text.startswith(("[a", "![a")) else "r]" + ZW, out)

    def test_other_formats_and_odd_input_come_back_as_text(self):
        for fmt in ("generic", "ntfy", "nonsense", "", None):
            self.assertEqual(notify.defuse("@channel <!here>", fmt), "@channel <!here>")
        for value, out in ((None, ""), (7, "7"), (b"x", "b'x'"), (["a"], "['a']")):
            self.assertEqual(notify.defuse(value, "slack"), out)

    def test_a_long_line_of_the_dangerous_characters_stays_in_the_time_it_takes_to_read_it(self):
        import time

        t = time.time()
        for fmt in DEFUSED:
            notify.defuse("@" * 200000 + "<" * 200000 + "]" * 200000 + "[" * 200000, fmt)
        self.assertLess(time.time() - t, 5.0, "no pattern in the helper backtracks")


class TestTheBuilders(unittest.TestCase):
    """Each builder, called as the dispatcher calls it, with a hostile name in the title and in the message."""

    def body(self, fmt, title, message):
        dest = {"telegram_chat_id": "1", "matrix_token": "t"}
        fn = {
            "slack": lambda: notify._build_slack_body("device_offline", title, message),
            "discord": lambda: notify._build_discord_body("device_offline", title, message),
            "teams": lambda: notify._build_teams_body("device_offline", title, message),
            "googlechat": lambda: notify._build_googlechat_body("device_offline", title, message),
            "mattermost": lambda: notify._build_mattermost_body("device_offline", title, message),
            "rocketchat": lambda: notify._build_rocketchat_body("device_offline", title, message),
            "telegram": lambda: notify._build_telegram_body("device_offline", title, message, dest),
            "matrix": lambda: notify._build_matrix_body("device_offline", title, message, dest),
            "github": lambda: notify._build_github_body("device_offline", title, message, {"token": "t"}, {}),
        }[fmt]
        return json.loads(fn()[0])

    def test_no_string_in_any_body_carries_an_active_mention_or_link(self):
        hostile = "web1 @channel <!here> <@U1> [x](http://e) <users/all> [r]: http://e"
        for fmt in DEFUSED:
            data = self.body(fmt, hostile, hostile)
            for s in _readable(fmt, data):
                with self.subTest(fmt=fmt, string=s[:60]):
                    self.assertEqual(active(fmt, s), [])

    def test_the_text_is_still_there(self):
        for fmt in DEFUSED:
            data = self.body(fmt, "Host down", "web1 @channel is down")
            joined = " ".join(_strings(data))
            self.assertIn("web1", joined, fmt)
            self.assertIn("channel", joined, fmt)
            self.assertIn("Host down" if fmt != "github" else "web1", joined, fmt)

    def test_discord_switches_every_mention_off_in_the_body(self):
        data = self.body("discord", "t", "@everyone <@1> <@&2>")
        self.assertEqual(data["allowed_mentions"], {"parse": []})
        self.assertNotIn("content", data, "nothing is sent as plain content, which is where a mention would ring")

    def test_matrix_says_it_mentions_nobody(self):
        self.assertEqual(self.body("matrix", "t", "@room Alice")["m.mentions"], {})

    def test_mattermost_push_preview_is_clean_too(self):
        data = self.body("mattermost", "@here", "@channel")
        att = data["attachments"][0]
        self.assertEqual(active("mattermost", att["fallback"]), [])
        self.assertEqual(active("mattermost", data["text"]), [])

    def test_github_keeps_its_own_markup_and_clears_the_message(self):
        data = self.body("github", "t", "@octo-org/admins [x](http://e) <img src=x>")
        text = data["body"]
        self.assertIn("<details><summary>Payload</summary>", text, "the markup the builder writes itself is left alone")
        message_part = text.split("\n\n---\n\n")[0]
        self.assertEqual(active("github", message_part), [])

    def test_none_does_not_raise_and_the_body_is_json(self):
        for fmt in DEFUSED:
            for title, message in ((None, None), ("", None), (None, ""), ("Hôte ⚠", "ünïcode 主机   \x00")):
                with self.subTest(fmt=fmt, title=title):
                    self.body(fmt, title, message)


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


class TestTheRealPath(unittest.TestCase):
    """fire_webhook, with a destination for every chat format and a recording opener in place of the network."""

    def setUp(self):
        self.dests = [
            {"id": f"d-{f}", "name": f, "url": f"https://chat.example.com/{f}", "format": f, "enabled": True,
             "telegram_chat_id": "1", "matrix_token": "t", "token": "t"}
            for f in DEFUSED
        ]
        api.save(api.CONFIG_FILE, {"webhook_block_local": False, "webhook_urls": self.dests})
        api._LOAD_CACHE.clear()
        self.opener = _Opener()
        p = mock.patch.object(api, "_ssrf_safe_opener", return_value=self.opener)
        p.start()
        self.addCleanup(p.stop)

    def sent_by_format(self):
        out = {}
        for req in self.opener.sent:
            out[req.full_url.rsplit("/", 1)[1]] = json.loads(req.data)
        return out

    def test_a_host_named_like_a_mention_pings_nobody_through_any_format(self):
        name = "web1 @channel <!here> [Sign in](http://evil.example) <users/all>"
        api.fire_webhook("device_offline", {"name": name, "device_id": "dev-x", "device_name": name})
        got = self.sent_by_format()
        self.assertEqual(sorted(got), sorted(DEFUSED), "every destination was reached")
        for fmt, data in got.items():
            seen = list(_readable(fmt, data))
            self.assertTrue(any("web1" in s for s in seen), f"{fmt}: the name is in the message")
            for s in seen:
                with self.subTest(fmt=fmt, string=s[:70]):
                    self.assertEqual(active(fmt, s), [])

    def test_a_container_and_a_log_line_go_the_same_way(self):
        api.fire_webhook("container_stopped", {"name": "web1", "device_id": "dev-x", "container": "@here<!channel>"})
        api.fire_webhook("log_alert", {"name": "web1", "device_id": "dev-x", "rule": "ssh", "line": "@channel [x](http://e)"})
        self.assertGreaterEqual(len(self.opener.sent), len(DEFUSED))
        for req in self.opener.sent:
            fmt = req.full_url.rsplit("/", 1)[1]
            for s in _readable(fmt, json.loads(req.data)):
                self.assertEqual(active(fmt, s), [], (fmt, s[:70]))

    def test_the_digest_summary_is_cleaned_with_the_rest(self):
        # a digest line is made from queued messages, so the summary goes through the same builders
        dest = self.dests[0]
        api._dispatch_one_webhook("notification_digest", dest, {}, "• web1 @channel <!here>", "RemotePower digest", 3)
        data = json.loads(self.opener.sent[-1].data)
        for s in _readable(dest["format"], data):
            self.assertEqual(active(dest["format"], s), [], s)


class TestEveryFormatIsPlaced(unittest.TestCase):
    """The rule is half-applied the day a format is added and nobody asks which list it belongs on."""

    def test_every_format_the_product_accepts_is_on_one_list(self):
        formats = set(api._WEBHOOK_FORMATS)
        self.assertTrue(formats, "the population is not empty")
        placed = set(DEFUSED) | set(PLAIN)
        self.assertEqual(formats - placed, set(), "a new format has to be placed: does the service read mentions or links?")
        self.assertEqual(placed - formats, set(), "a listed format the product no longer has")
        self.assertEqual(set(DEFUSED) & set(PLAIN), set())

    def test_every_listed_builder_calls_the_helper(self):
        src = (_CGI / "notify.py").read_text()
        for fmt in DEFUSED:
            m = re.search(r"^def _build_%s_body\(.*?(?=^def |\Z)" % fmt, src, re.M | re.S)
            self.assertIsNotNone(m, fmt)
            body = m.group(0)
            if fmt == "matrix":
                self.assertIn('"m.mentions"', body)
            else:
                self.assertIn("defuse(", body, f"_build_{fmt}_body does not pass the text through defuse()")
        self.assertEqual(len(list(re.finditer(r"^def defuse\(", src, re.M))), 1)

    def test_the_plain_formats_say_why(self):
        for fmt, why in PLAIN.items():
            self.assertGreater(len(why), 20, fmt)

    def test_the_docs_say_what_is_done(self):
        doc = (ROOT / "docs" / "webhooks.md").read_text()
        self.assertRegex(doc, r"(?i)pings? nobody|does not ping|do not ping")


if __name__ == "__main__":
    unittest.main()

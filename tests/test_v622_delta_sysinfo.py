"""v6.2.2 "Pu1seMatters" — delta sysinfo (heartbeat payload slimming).

The agent may omit heavy, slow-moving sysinfo fields (`sysinfo_omitted`) once
the server has advertised `delta_ok`; the server merges its stored copy back
in at ingest so every downstream consumer still sees a complete sysinfo, and
lists anything it could not merge in `delta_resend`. Tested by driving the
REAL handle_heartbeat — protocol bugs here are exactly the "looks wired in
review" class, so no source-grep-only coverage for the ingest path.
"""

import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v622-delta-"))
os.environ.setdefault("REQUEST_METHOD", "GET")
os.environ.setdefault("PATH_INFO", "/")
os.environ.setdefault("CONTENT_LENGTH", "0")
_spec = importlib.util.spec_from_file_location("api_v622_delta", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_AGENT_SRC = (_ROOT / "client" / "remotepower-agent.py").read_text()


class _Captured(SystemExit):
    def __init__(self, status, body):
        super().__init__(0)
        self.status = status
        self.body = body


class _StdinShim:
    def __init__(self, data: bytes):
        self.buffer = io.BytesIO(data)


class TestDeltaIngest(unittest.TestCase):
    PKGS = {"manager": "apt", "upgradable": 3,
            "upgradable_names": ["curl", "vim", "zsh"]}

    def setUp(self):
        def fake_respond(status, data):
            raise _Captured(status, data)
        self._real_respond, api.respond = api.respond, fake_respond
        self._real_fire, api.fire_webhook = api.fire_webhook, lambda *a, **k: None
        api.save(api.DEVICES_FILE, {
            "devd1": {"name": "delta-host", "token": "tok-d1",
                      "enrolled_at": int(time.time())},
        })
        api._invalidate_load_cache(api.DEVICES_FILE)

    def tearDown(self):
        api.respond = self._real_respond
        api.fire_webhook = self._real_fire

    def _hb(self, body):
        body.setdefault("device_id", "devd1")
        body.setdefault("token", "tok-d1")
        raw = json.dumps(body).encode()
        os.environ["REQUEST_METHOD"] = "POST"
        os.environ["QUERY_STRING"] = ""
        os.environ["CONTENT_LENGTH"] = str(len(raw))
        api.sys.stdin = _StdinShim(raw)
        try:
            api.handle_heartbeat()
        except _Captured as c:
            return c
        self.fail("respond not called")

    def _stored_si(self):
        api._invalidate_load_cache(api.DEVICES_FILE)
        return (api.load(api.DEVICES_FILE)["devd1"].get("sysinfo")) or {}

    def test_response_advertises_delta_ok(self):
        c = self._hb({"sysinfo": {"uptime": "up 1 day"}})
        self.assertEqual(c.status, 200)
        self.assertTrue(c.body.get("delta_ok"))

    def test_omitted_field_is_merged_from_previous_beat(self):
        self._hb({"sysinfo": {"uptime": "up 1 day", "packages": self.PKGS}})
        self.assertEqual(self._stored_si().get("packages", {}).get("upgradable"), 3)
        c = self._hb({"sysinfo": {"uptime": "up 2 days"},
                      "sysinfo_omitted": {"packages": "abcd1234"}})
        si = self._stored_si()
        self.assertEqual(si.get("packages", {}).get("upgradable"), 3,
                         "omitted field must be carried over from the previous "
                         "stored sysinfo — downstream consumers need a complete dict")
        self.assertEqual(si.get("packages", {}).get("upgradable_names"),
                         ["curl", "vim", "zsh"])
        self.assertNotIn("delta_resend", c.body)

    def test_unmergeable_field_lands_on_delta_resend(self):
        """Fresh server state (no stored value): the response must ask for the
        field full next beat instead of silently losing it forever."""
        c = self._hb({"sysinfo": {"uptime": "up 1 day"},
                      "sysinfo_omitted": {"packages": "abcd1234"}})
        self.assertIn("packages", c.body.get("delta_resend", []))
        self.assertNotIn("packages", self._stored_si())

    def test_non_whitelisted_field_is_ignored(self):
        """An arbitrary field named in sysinfo_omitted must be neither merged
        nor resend-requested — the whitelist is the trust boundary."""
        self._hb({"sysinfo": {"uptime": "up 1 day", "packages": self.PKGS}})
        c = self._hb({"sysinfo": {"uptime": "up 2 days"},
                      "sysinfo_omitted": {"journal": "x", "token": "y"}})
        self.assertNotIn("journal", c.body.get("delta_resend", []))
        self.assertNotIn("token", self._stored_si())

    def test_field_sent_full_wins_over_omitted_claim(self):
        """A contradictory body (field present AND omitted) keeps the sent value."""
        self._hb({"sysinfo": {"uptime": "u", "packages": self.PKGS}})
        newer = dict(self.PKGS, upgradable=9)
        self._hb({"sysinfo": {"uptime": "u", "packages": newer},
                  "sysinfo_omitted": {"packages": "stale-hash"}})
        self.assertEqual(self._stored_si().get("packages", {}).get("upgradable"), 9)

    def test_downstream_checks_see_the_merged_field(self):
        """End-to-end: the Checks engine reads the merged sysinfo, so the
        'Pending updates' row survives a beat that omitted `packages`."""
        self._hb({"sysinfo": {"uptime": "u", "packages": self.PKGS}})
        self._hb({"sysinfo": {"uptime": "u"},
                  "sysinfo_omitted": {"packages": "h"}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        dev = api.load(api.DEVICES_FILE)["devd1"]
        rows = api._host_checks("devd1", dev, {}, [], int(time.time()), 180)
        patch_rows = [r for r in rows if r["key"] == "patches"]
        self.assertEqual(len(patch_rows), 1)
        self.assertIn("3 update(s)", patch_rows[0]["output"])


class TestProtocolLockstep(unittest.TestCase):
    """Agent and server must agree on the delta field set, and the agent's
    ordering rules (capability-gated, commit-on-confirmed-only) must hold."""

    def _agent_fields(self):
        m = re.search(r"_DELTA_SYSINFO_FIELDS = \(([^)]*)\)", _AGENT_SRC)
        self.assertIsNotNone(m, "agent lost its _DELTA_SYSINFO_FIELDS tuple")
        return tuple(re.findall(r"'([a-z_]+)'", m.group(1)))

    def test_field_sets_are_identical(self):
        self.assertEqual(set(self._agent_fields()),
                         set(api._DELTA_SYSINFO_FIELDS),
                         "agent and server delta field sets diverged — a field "
                         "only one side knows is either never omitted (waste) "
                         "or never merged (data loss)")

    def test_every_delta_field_survives_safe_si(self):
        """A delta field the sanitizer drops would resend forever: the server
        stores nothing, so it can never merge, so it always asks again."""
        src = (_CGI / "api.py").read_text()
        for f in api._DELTA_SYSINFO_FIELDS:
            self.assertIn(f"safe_si['{f}']", src,
                          f"delta field {f!r} is not persisted by safe_si")

    def test_agent_omits_only_after_capability_and_commits_only_on_confirm(self):
        """Ordering pins for the two protocol-safety rules:
        1. `if delta_ok:` guards the omit block — a new agent against an old
           server (which never advertises delta_ok) keeps sending full payloads.
        2. delta_hashes is committed from _delta_sent_full only on a non-busy
           response — a dropped beat can never leave the server holding stale
           data the agent then stops sending."""
        i = _AGENT_SRC.index("payload['sysinfo_omitted']")
        block = _AGENT_SRC[max(0, i - 1200):i]
        self.assertIn("if delta_ok:", block)
        j = _AGENT_SRC.index("delta_hashes.update(_delta_sent_full)")
        guard = _AGENT_SRC[max(0, j - 300):j]
        self.assertIn("busy", guard)

    def test_agent_relearns_capability_from_every_response(self):
        self.assertIn("delta_ok = bool(resp.get('delta_ok'))", _AGENT_SRC)
        self.assertIn("resp.get('delta_resend')", _AGENT_SRC)


if __name__ == "__main__":
    unittest.main()

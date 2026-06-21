"""v5.0.0 batch B:
  - WebUI backup encryption migration (encrypt existing plaintext archives)
  - Network map scope filter (per site/tag/group) for big fleets
  - lightweight ITSM ticketing (Jira/ServiceNow/Zendesk ack-webhook + ticket link)
  - Settings -> Install update (version check + guided self-update)
  - extra settings (login banner)
"""
import importlib.util
import os
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

_DATA = tempfile.mkdtemp(prefix="rp-v500b-")
os.environ["RP_DATA_DIR"] = _DATA
_spec = importlib.util.spec_from_file_location("api_v500b", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
import backup_crypto  # noqa: E402

API_SRC = (_CGI / "api.py").read_text()
HTML = (_ROOT / "server" / "html" / "index.html").read_text()
APP = (_ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()
APP_NET = (_ROOT / "server" / "html" / "static" / "js" / "app-network.js").read_text()


class _Stop(Exception):
    pass


def _capture():
    box = {}

    def _cap(status, body=None):
        box["status"], box["body"] = status, body
        raise _Stop()

    api.respond = _cap
    return box


# ───────────────────────── ITSM ticketing (lightweight) ─────────────────────────
class TestItsmTicketing(unittest.TestCase):
    def test_formats_registered(self):
        for f in ("jira", "servicenow", "zendesk"):
            self.assertIn(f, api._WEBHOOK_FORMATS)
            self.assertIn(f, api.ITSM_FORMATS)

    def test_jira_body_and_auth(self):
        b, h, _ = api._build_jira_body("e", "Disk full", "msg", {
            "jira_project": "OPS", "itsm_user": "me@x.com", "itsm_secret": "tok"})
        self.assertIn(b'"key": "OPS"', b)
        self.assertTrue(h["Authorization"].startswith("Basic "))

    def test_jira_requires_project_and_secret(self):
        self.assertIsNone(api._build_jira_body("e", "t", "m", {"itsm_user": "u"})[0])
        self.assertIsNone(api._build_jira_body("e", "t", "m", {"jira_project": "OPS"})[0])

    def test_parse_responses(self):
        self.assertEqual(
            api._parse_itsm_response("jira", "https://x.atlassian.net/y", b'{"key":"OPS-1"}'),
            {"ticket_ref": "OPS-1", "ticket_url": "https://x.atlassian.net/browse/OPS-1"})
        self.assertEqual(
            api._parse_itsm_response("zendesk", "https://x.zendesk.com/y",
                                     b'{"ticket":{"id":7,"url":"u"}}')["ticket_ref"], "7")
        self.assertEqual(
            api._parse_itsm_response("servicenow", "https://x.service-now.com/y",
                                     b'{"result":{"number":"INC9","sys_id":"s"}}')["ticket_ref"], "INC9")
        self.assertIsNone(api._parse_itsm_response("jira", "u", b"not json"))

    def test_ack_stores_ticket_on_alert(self):
        # _fire_ack_webhooks must persist the returned ticket ref on the alert.
        self.assertIn("a['ticket_ref'] = ticket['ticket_ref']", API_SRC)
        self.assertIn("if res and isinstance(res, dict) and res.get('ticket_ref')", API_SRC)

    def test_secret_redacted_but_flagged(self):
        # itsm_secret is dropped from the redacted GET; a *_set flag is echoed.
        self.assertIn("'itsm_secret'", API_SRC)
        self.assertIn("r['itsm_secret_set']", API_SRC)

    def test_frontend_formats_and_link(self):
        self.assertIn("'jira'", APP)
        self.assertIn("data-field=\"itsm_secret\"", APP)
        self.assertIn("ticket_ref", APP)        # ticket link on the alert row


# ───────────────────────── network-map scope filter ────────────────────────────
class TestNetmapScope(unittest.TestCase):
    def setUp(self):
        api.save(api.DEVICES_FILE, {
            "a": {"name": "a", "group": "web", "site": "s1", "tags": ["edge"], "last_seen": 9e9},
            "b": {"name": "b", "group": "db", "site": "s1", "tags": [], "last_seen": 9e9},
            "c": {"name": "c", "group": "web", "site": "s2", "tags": ["edge"], "last_seen": 9e9},
        })
        self._auth, self._scope = api.require_auth, api._scope_filter_devices
        api.require_auth = lambda *a, **k: "t"
        api._scope_filter_devices = lambda d, *a, **k: d

    def tearDown(self):
        api.require_auth, api._scope_filter_devices = self._auth, self._scope
        os.environ["QUERY_STRING"] = ""

    def _call(self, qs):
        os.environ["QUERY_STRING"] = qs
        box = _capture()
        with self.assertRaises(_Stop):
            api.handle_network_map()
        return box["body"]

    def test_no_scope_returns_all(self):
        out = self._call("")
        self.assertEqual(len(out["nodes"]), 3)
        self.assertEqual(out["total"], 3)
        self.assertIn("web", out["scopes"]["groups"])
        self.assertIn("s1", out["scopes"]["sites"])

    def test_group_filter(self):
        out = self._call("group=web")
        self.assertEqual({n["id"] for n in out["nodes"]}, {"a", "c"})
        self.assertEqual(out["total"], 3)          # total stays the full count

    def test_site_filter(self):
        out = self._call("site=s2")
        self.assertEqual({n["id"] for n in out["nodes"]}, {"c"})

    def test_tag_filter(self):
        out = self._call("tag=edge")
        self.assertEqual({n["id"] for n in out["nodes"]}, {"a", "c"})

    def test_frontend_picker(self):
        self.assertIn('id="netmap-scope-site"', HTML)
        self.assertIn("_netmapScopeQuery", APP_NET)


# ───────────────────────── backup encryption migration ─────────────────────────
@unittest.skipUnless(backup_crypto.available(), "cryptography not installed")
class TestBackupEncryptMigration(unittest.TestCase):
    def setUp(self):
        self._bdir = Path(tempfile.mkdtemp(prefix="rp-bk-"))
        # a plaintext archive to migrate
        self._arc = self._bdir / "remotepower_data_20260101_000000.tar.gz"
        with tarfile.open(self._arc, "w:gz") as t:
            f = self._bdir / "x.txt"
            f.write_text("hello")
            t.add(f, arcname="x.txt")
        api.save(api.CONFIG_FILE, {"backup": {"path": str(self._bdir)}})
        self._auth, self._method, self._body, self._audit = (
            api.require_admin_auth, api.method, api.get_json_obj, api.audit_log)
        api.require_admin_auth = lambda *a, **k: "admin"
        api.method = lambda: "POST"
        api.audit_log = lambda *a, **k: None

    def tearDown(self):
        (api.require_admin_auth, api.method, api.get_json_obj, api.audit_log) = (
            self._auth, self._method, self._body, self._audit)

    def test_encrypts_existing_plaintext(self):
        api.get_json_obj = lambda: {"passphrase": "correct horse battery"}
        box = _capture()
        with self.assertRaises(_Stop):
            api.handle_backup_encrypt_existing()
        self.assertEqual(box["status"], 200)
        self.assertEqual(box["body"]["encrypted"], 1)
        self.assertFalse(self._arc.exists())                       # plaintext removed
        enc = self._arc.with_suffix(self._arc.suffix + ".enc")
        self.assertTrue(enc.exists())
        self.assertTrue(backup_crypto.is_encrypted(enc))           # really encrypted

    def test_short_passphrase_rejected(self):
        api.get_json_obj = lambda: {"passphrase": "short"}
        box = _capture()
        with self.assertRaises(_Stop):
            api.handle_backup_encrypt_existing()
        self.assertEqual(box["status"], 400)

    def test_route_registered(self):
        from routing_harness import resolve_route
        self.assertEqual(resolve_route("POST", "/api/self/backup-encrypt")[0],
                         "handle_backup_encrypt_existing")

    def test_frontend_button(self):
        self.assertIn("encryptExistingBackups", APP)


class TestBackupClear(unittest.TestCase):
    """DELETE /api/self/backup-state must remove BOTH plaintext (*.tar.gz) and
    encrypted (*.tar.gz.enc) archives — the glob `*.tar.gz` does not match
    `*.tar.gz.enc`, so an encryption-armed instance used to clear nothing."""

    def setUp(self):
        self._bdir = Path(tempfile.mkdtemp(prefix="rp-bkc-"))
        (self._bdir / "remotepower_data_20260101_000000.tar.gz").write_text("plain")
        (self._bdir / "remotepower_data_20260102_000000.tar.gz.enc").write_text("enc1")
        (self._bdir / "remotepower_data_20260103_000000.tar.gz.enc").write_text("enc2")
        (self._bdir / "unrelated.txt").write_text("keep me")
        api.save(api.CONFIG_FILE, {"backup": {"path": str(self._bdir)}})
        self._auth, self._method, self._audit = (
            api.require_admin_auth, api.method, api.audit_log)
        api.require_admin_auth = lambda *a, **k: "admin"
        api.method = lambda: "DELETE"
        api.audit_log = lambda *a, **k: None

    def tearDown(self):
        (api.require_admin_auth, api.method, api.audit_log) = (
            self._auth, self._method, self._audit)

    def test_clears_plaintext_and_encrypted(self):
        box = _capture()
        with self.assertRaises(_Stop):
            api.handle_backup_clear()
        self.assertEqual(box["status"], 200)
        self.assertEqual(box["body"]["deleted"], 3)              # 1 plaintext + 2 enc
        left = {p.name for p in self._bdir.glob("remotepower_data_*")}
        self.assertEqual(left, set())                           # all archives gone
        self.assertTrue((self._bdir / "unrelated.txt").exists())  # non-archive kept


# ───────────────────────── install update + extra settings ──────────────────────
class TestUpdateAndSettings(unittest.TestCase):
    def test_self_update_route(self):
        from routing_harness import resolve_route
        self.assertEqual(resolve_route("POST", "/api/server/self-update")[0],
                         "handle_server_self_update")

    def test_self_update_requires_config(self):
        api.save(api.CONFIG_FILE, {})
        _a, _m = api.require_admin_auth, api.method
        api.require_admin_auth = lambda *a, **k: "admin"
        api.method = lambda: "POST"
        try:
            box = _capture()
            with self.assertRaises(_Stop):
                api.handle_server_self_update()
            self.assertEqual(box["status"], 400)
            self.assertFalse(box["body"].get("configured"))
        finally:
            api.require_admin_auth, api.method = _a, _m

    def test_self_update_path_must_be_absolute(self):
        # the config-set validator rejects a relative path
        self.assertIn("self_update_command must be an absolute path", API_SRC)

    def test_version_check_exposes_configured(self):
        self.assertIn("'self_update_configured': bool", API_SRC)

    def test_login_banner_in_public_info(self):
        self.assertIn("'login_banner':        str(cfg.get('login_banner')", API_SRC)

    def test_login_banner_frontend(self):
        self.assertIn('id="login-banner"', HTML)
        self.assertIn('id="cfg-login-banner"', HTML)
        self.assertIn("login_banner", APP)

    def test_update_panel_frontend(self):
        self.assertIn('id="settings-pane-install"', HTML)
        self.assertIn("function loadUpdatePanel(", APP)
        self.assertIn("function runSelfUpdate(", APP)


if __name__ == "__main__":
    unittest.main()

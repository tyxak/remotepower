#!/usr/bin/env python3
"""7.4.9: the server's own backup, copied to an S3-compatible bucket.

The store is the one written for test_v749_s3_client (it verifies the signature of every request). The backup is the real one:
`_run_data_backup` tars this test's data directory, encrypts it, copies it, prunes the copies that are old, and records what
happened. The drill reads the copy back. The settings go through the real settings save, and the connection test through its
handler. Nothing here is a stub of the code that is being tested; the passphrase and the secret key come from the environment, as
they do on a server.
"""
import importlib.machinery
import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v749-s3b-"))
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
_ldr = importlib.machinery.SourceFileLoader("api_s3b", str(ROOT / "server" / "cgi-bin" / "api.py"))
_spec = importlib.util.spec_from_loader("api_s3b", _ldr)
api: Any = importlib.util.module_from_spec(_spec)         # type: ignore[arg-type]
_ldr.exec_module(api)                                     # type: ignore[union-attr]

import test_v749_s3_client as fixtures  # noqa: E402

AK, SK = fixtures.AK, fixtures.SK
PASSPHRASE = "correct horse battery staple"


class _Base(unittest.TestCase):

    def setUp(self):
        self.store = fixtures.FakeStore()
        self.srv = fixtures.make_server(self.store)
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.tmp = Path(tempfile.mkdtemp(prefix="rp-s3b-"))
        self.endpoint = f"http://127.0.0.1:{self.srv.server_address[1]}"
        self.cap: dict = {}
        self._real = {n: getattr(api, n) for n in ("respond", "verify_token", "audit_log", "_env", "method", "get_json_obj", "_backup_passphrase")}

        def _resp(status, body=None):
            self.cap["s"], self.cap["b"] = status, body
            raise api.HTTPError(status, body)
        api.respond = _resp
        api.audit_log = lambda *a, **k: self.audit.append((a, k))
        self.audit: list = []
        api.verify_token = lambda *a, **k: ("admin", "admin")
        api._backup_passphrase = lambda: PASSPHRASE
        env = mock.patch.dict(os.environ, {"RP_BACKUP_S3_SECRET_KEY": SK})
        env.start()
        self.addCleanup(env.stop)
        self.settings = {"enabled": True, "endpoint": self.endpoint, "region": "us-east-1", "bucket": "bkt", "prefix": "rp/", "access_key_id": AK,
                         "path_style": True, "verify_tls": True}
        self.save_config()
        api.save(api.DATA_DIR / "self_backup_state.json", {})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._real.items():
            setattr(api, n, v)
        api._LOAD_CACHE.clear()

    def save_config(self, **backup):
        bk = dict({"enabled": True, "path": str(self.tmp / "backups"), "retain_days": 14, "s3": self.settings}, **backup)
        api.save(api.CONFIG_FILE, {"backup": bk})
        api._LOAD_CACHE.clear()

    def run_backup(self):
        api._LOAD_CACHE.clear()
        return api._run_data_backup(triggered_by="manual")

    def state(self):
        api._LOAD_CACHE.clear()
        return api.load(api.DATA_DIR / "self_backup_state.json") or {}

    def call(self, fn, body=None):
        api.get_json_obj = lambda: body or {}
        api.method = lambda: "POST"
        self.cap.clear()
        try:
            fn()
        except api.HTTPError:
            pass
        return self.cap.get("s"), self.cap.get("b") or {}


class TestTheCopy(_Base):

    def test_a_backup_is_encrypted_and_copied_under_the_prefix(self):
        r = self.run_backup()
        self.assertTrue(r["ok"] and r["encrypted"], r)
        self.assertTrue(r["s3_ok"])
        names = list(self.store.objects)
        self.assertEqual(len(names), 1)
        self.assertRegex(names[0], r"^rp/remotepower_data_\d{8}_\d{6}\.tar\.gz\.enc$")
        local = Path(r["file"])
        self.assertEqual(self.store.objects[names[0]]["data"], local.read_bytes(), "the copy is the archive")
        st = self.state()
        self.assertEqual((st["s3_ok"], st["s3_error"], st["s3_bucket"]), (True, "", "bkt"))
        self.assertEqual(self.store.bad_auth, 0)

    def test_what_the_store_got_is_ciphertext(self):
        self.run_backup()
        data = next(iter(self.store.objects.values()))["data"]
        self.assertNotEqual(data[:2], b"\x1f\x8b", "not a gzip stream: it is encrypted")
        self.assertNotIn(b"remotepower/", data[:4096])

    def test_a_plaintext_archive_is_not_sent(self):
        api._backup_passphrase = lambda: ""
        r = self.run_backup()
        self.assertTrue(r["ok"], "the backup itself is fine")
        self.assertFalse(r["encrypted"])
        self.assertIs(r["s3_ok"], False)
        self.assertEqual(self.store.requests, [], "nothing was sent")
        self.assertIn("RP_BACKUP_PASSPHRASE", self.state()["s3_error"])

    def test_without_the_secret_key_the_copy_says_so(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("RP_BACKUP_S3_SECRET_KEY", None)
            os.environ.pop("RP_BACKUP_S3_SECRET_KEY_CMD", None)
            r = self.run_backup()
        self.assertTrue(r["ok"])
        self.assertIs(r["s3_ok"], False)
        self.assertIn("RP_BACKUP_S3_SECRET_KEY", self.state()["s3_error"])
        self.assertEqual(self.store.requests, [])

    def test_a_store_that_refuses_does_not_fail_the_backup(self):
        self.store.deny = {"put"}
        r = self.run_backup()
        self.assertTrue(r["ok"])
        self.assertIs(r["s3_ok"], False)
        self.assertIn("AccessDenied", self.state()["s3_error"])
        self.assertTrue(Path(r["file"]).is_file(), "the local archive is there")

    def test_a_wrong_secret_key_is_a_failure_that_does_not_show_the_key(self):
        with mock.patch.dict(os.environ, {"RP_BACKUP_S3_SECRET_KEY": SK + "x"}):
            r = self.run_backup()
        self.assertIs(r["s3_ok"], False)
        st = json.dumps(self.state()) + json.dumps(r, default=str)
        self.assertIn("SignatureDoesNotMatch", st)
        self.assertNotIn(SK, st)

    def test_the_settings_in_the_config_that_cannot_be_used_are_a_failure_not_silence(self):
        for broken in ({"endpoint": "ftp://x", "bucket": "bkt"}, {"bucket": "X"}, {"access_key_id": ""}):
            self.settings = dict(self.settings, **broken)
            self.save_config()
            r = self.run_backup()
            self.assertIs(r["s3_ok"], False, broken)
            self.assertIn("can not be used", self.state()["s3_error"])
        self.assertEqual(self.store.requests, [])

    def test_only_a_real_true_switches_it_on(self):
        for odd in ("yes", "true", 1, [1], {"a": 1}):
            self.settings = dict(self.settings, enabled=odd)
            self.save_config()
            r = self.run_backup()
            self.assertIsNone(r["s3_ok"], odd)
        self.assertEqual(self.store.requests, [])

    def test_an_unexpected_failure_is_recorded_by_its_kind_and_not_its_text(self):
        real = api._s3_offsite_copy

        def boom(*a, **k):
            raise RuntimeError("detail with /srv/secret/path and a token abc123")
        api._s3_offsite_copy = boom
        self.addCleanup(setattr, api, "_s3_offsite_copy", real)
        r = self.run_backup()
        self.assertTrue(r["ok"] and r["s3_ok"] is False)
        err = self.state()["s3_error"]
        self.assertEqual(err, "RuntimeError while talking to the store")
        self.assertNotIn("abc123", json.dumps(self.state()))

    def test_when_it_is_off_nothing_is_sent_and_the_state_says_none(self):
        self.settings = dict(self.settings, enabled=False)
        self.save_config()
        r = self.run_backup()
        self.assertIsNone(r["s3_ok"])
        self.assertEqual(self.store.requests, [])
        self.assertIsNone(self.state()["s3_ok"])

    def test_old_copies_are_pruned_and_nothing_else(self):
        old = 1_700_000_000
        for name in ("rp/remotepower_data_20231101_030000.tar.gz.enc", "rp/remotepower_data_20231102_030000.tar.gz"):
            self.store.objects[name] = {"data": b"old", "mtime": old, "meta": None}
        for name in ("rp/notes.txt", "other/remotepower_data_20231101_030000.tar.gz.enc", "rp/sub/remotepower_data_20231101_030000.tar.gz.enc"):
            self.store.objects[name] = {"data": b"keep", "mtime": old, "meta": None}
        r = self.run_backup()
        self.assertTrue(r["s3_ok"])
        left = sorted(self.store.objects)
        self.assertNotIn("rp/remotepower_data_20231101_030000.tar.gz.enc", left)
        self.assertNotIn("rp/remotepower_data_20231102_030000.tar.gz", left)
        for kept in ("rp/notes.txt", "other/remotepower_data_20231101_030000.tar.gz.enc", "rp/sub/remotepower_data_20231101_030000.tar.gz.enc"):
            self.assertIn(kept, left)
        self.assertEqual(len([k for k in left if k.startswith("rp/remotepower_data_2026") or k.startswith("rp/remotepower_data_2027")]), 1, left)

    def test_a_prune_that_fails_is_a_note_and_the_copy_still_counts(self):
        self.store.objects["rp/remotepower_data_20231101_030000.tar.gz.enc"] = {"data": b"old", "mtime": 1_700_000_000, "meta": None}
        self.store.deny = {"delete"}
        r = self.run_backup()
        self.assertTrue(r["s3_ok"])
        st = self.state()
        self.assertIn("were not pruned", st["s3_note"])
        self.assertIn("AccessDenied", st["s3_note"])

    def test_retention_follows_the_days_setting(self):
        three_days = int(time.time()) - 3 * 86400
        self.store.objects["rp/remotepower_data_20261101_030000.tar.gz.enc"] = {"data": b"x", "mtime": three_days, "meta": None}
        self.save_config(retain_days=2)
        self.run_backup()
        self.assertNotIn("rp/remotepower_data_20261101_030000.tar.gz.enc", self.store.objects)
        self.store.objects["rp/remotepower_data_20261101_030000.tar.gz.enc"] = {"data": b"x", "mtime": three_days, "meta": None}
        self.save_config(retain_days=5)
        self.run_backup()
        self.assertIn("rp/remotepower_data_20261101_030000.tar.gz.enc", self.store.objects)

    def test_the_secret_key_is_not_in_the_archive_or_the_state_or_the_config(self):
        r = self.run_backup()
        blob = json.dumps(self.state()) + json.dumps(api.load(api.CONFIG_FILE))
        self.assertNotIn(SK, blob)
        self.assertNotIn(SK.encode(), Path(r["file"]).read_bytes())


class TestTheDrill(_Base):

    def test_a_good_copy_passes_and_is_named_in_the_result(self):
        self.run_backup()
        r = api._restore_drill_core()
        self.assertTrue(r["ok"], r)
        self.assertTrue(r["s3"]["ok"])
        self.assertEqual(r["s3"]["bucket"], "bkt")
        self.assertGreater(r["s3"]["bytes"], 0)
        self.assertGreater(r["s3"]["stores"], 0)

    def test_a_copy_that_changed_in_the_store_fails_the_drill(self):
        self.run_backup()
        self.store.tamper = True
        r = api._restore_drill_core()
        self.assertFalse(r["ok"])
        self.assertIn("S3 bucket did not verify", r["error"])
        self.assertIn("not the one that was uploaded", r["error"])

    def test_an_empty_bucket_fails_the_drill(self):
        self.run_backup()
        self.store.objects.clear()
        r = api._restore_drill_core()
        self.assertFalse(r["ok"])
        self.assertIn("no archive found in the bucket", r["error"])
        self.assertTrue(r["s3"]["no_archives"])

    def test_a_store_that_cannot_be_read_fails_the_drill_with_its_answer(self):
        self.run_backup()
        self.store.deny = {"get"}
        r = api._restore_drill_core()
        self.assertFalse(r["ok"])
        self.assertIn("AccessDenied", r["error"])

    def test_the_local_failure_and_the_bucket_failure_are_both_told(self):
        self.run_backup()
        for f in (self.tmp / "backups").glob("remotepower_data_*"):
            f.unlink()
        self.store.objects.clear()
        r = api._restore_drill_core()
        self.assertFalse(r["ok"])
        self.assertIn("no backup archives found", r["error"])
        self.assertIn("S3 bucket did not verify", r["error"])

    def test_the_drill_leaves_nothing_behind(self):
        self.run_backup()
        api._restore_drill_core()
        self.assertEqual([p.name for p in (self.tmp / "backups").iterdir() if p.name.startswith(".s3drill_")], [])

    def test_with_the_copy_off_the_drill_is_as_it_was(self):
        self.run_backup()
        self.settings = dict(self.settings, enabled=False)
        self.save_config()
        r = api._restore_drill_core()
        self.assertTrue(r["ok"])
        self.assertNotIn("s3", r)

    def test_a_copy_of_a_plaintext_archive_that_somehow_exists_is_still_checked(self):
        # a bucket that someone filled by hand: the drill reads it and says what is wrong with it
        self.store.objects["rp/remotepower_data_20261102_030000.tar.gz.enc"] = {"data": b"not an archive at all", "mtime": int(time.time()), "meta": None}
        self.run_backup()                       # newer, so the real one is the newest
        self.assertTrue(api._restore_drill_core()["ok"])
        for k in list(self.store.objects):
            if "20261102" not in k:
                del self.store.objects[k]
        r = api._restore_drill_core()
        self.assertFalse(r["ok"])
        self.assertIn("S3 bucket did not verify", r["error"])


class TestTheSettings(_Base):

    def save(self, s3, **extra):
        return self.call(api.handle_config_save, {"backup": dict({"s3": s3}, **extra)})

    def test_good_settings_are_stored_in_one_shape(self):
        st, body = self.save(dict(self.settings, prefix="/rp/main", region=" eu-west-1 "))
        self.assertEqual(st, 200, body)
        api._LOAD_CACHE.clear()
        stored = api.load(api.CONFIG_FILE)["backup"]["s3"]
        self.assertEqual((stored["prefix"], stored["region"], stored["endpoint"]), ("rp/main/", "eu-west-1", self.endpoint))
        self.assertEqual(stored["enabled"], True)

    def test_a_secret_in_the_body_is_not_stored(self):
        st, _ = self.save(dict(self.settings, secret_access_key="TOPSECRET", secret="TOPSECRET", password="TOPSECRET", extra="x"))
        self.assertEqual(st, 200)
        api._LOAD_CACHE.clear()
        self.assertNotIn("TOPSECRET", json.dumps(api.load(api.CONFIG_FILE)))
        self.assertEqual(set(api.load(api.CONFIG_FILE)["backup"]["s3"]), {"enabled", "endpoint", "bucket", "region", "prefix", "access_key_id", "path_style", "verify_tls"})

    def test_settings_that_cannot_be_used_are_refused_with_the_reason(self):
        for broken, word in ((dict(endpoint="ftp://x"), "endpoint"), (dict(endpoint="https://u:p@host"), "endpoint"), (dict(bucket="X"), "bucket"),
                             (dict(prefix="../x"), "prefix"), (dict(region="a b"), "region"), (dict(access_key_id=""), "access key"),
                             (dict(endpoint="http://s3.public.example"), "https")):
            st, body = self.save(dict(self.settings, **broken))
            self.assertEqual(st, 400, broken)
            self.assertTrue(body["error"].startswith("backup.s3: "), body)
            self.assertIn(word, body["error"], broken)

    def test_an_address_that_is_never_connected_to_is_refused_when_saved(self):
        real = socket.getaddrinfo
        self.addCleanup(setattr, socket, "getaddrinfo", real)
        socket.getaddrinfo = lambda host, *a, **k: ([(socket.AF_INET, 1, 6, "", ("169.254.169.254", 0))] if host == "meta.example" else real(host, *a, **k))
        for endpoint in ("https://169.254.169.254", "https://meta.example", "http://169.254.169.254"):
            st, body = self.save(dict(self.settings, endpoint=endpoint))
            self.assertEqual(st, 400, endpoint)
            self.assertTrue("link-local" in body["error"] or "use https" in body["error"], body)

    def test_the_settings_read_shows_the_settings_and_whether_a_secret_is_there_but_never_the_secret(self):
        self.save_config()
        api.method = lambda: "GET"
        self.cap.clear()
        try:
            api.handle_config_get()
        except api.HTTPError:
            pass
        body = self.cap["b"]
        self.assertEqual(body["backup"]["s3"]["bucket"], "bkt")
        self.assertEqual(body["backup"]["s3"]["access_key_id"], AK, "an access key id is not a secret and the form shows it")
        self.assertIs(body["backup_s3_secret_set"], True)
        self.assertNotIn(SK, json.dumps(body))
        with mock.patch.dict(os.environ, {}):
            os.environ.pop("RP_BACKUP_S3_SECRET_KEY", None)
            os.environ.pop("RP_BACKUP_S3_SECRET_KEY_CMD", None)
            self.cap.clear()
            try:
                api.handle_config_get()
            except api.HTTPError:
                pass
        self.assertIs(self.cap["b"]["backup_s3_secret_set"], False)

    def test_a_reader_who_is_not_an_administrator_gets_no_access_key_id(self):
        self.save_config()
        for role in ("viewer", "auditor", "mcp"):
            api.verify_token = lambda *a, role=role, **k: ("someone", role)
            api.method = lambda: "GET"
            self.cap.clear()
            try:
                api.handle_config_get()
            except api.HTTPError:
                pass
            s3cfg = self.cap["b"]["backup"]["s3"]
            self.assertEqual((s3cfg["access_key_id"], s3cfg["access_key_id_set"]), ("", True), role)
            self.assertEqual(s3cfg["bucket"], "bkt", role)
            self.assertNotIn(AK, json.dumps(self.cap["b"]), role)

    def test_turning_it_off_keeps_the_settings(self):
        st, _ = self.save(dict(self.settings, enabled=False))
        self.assertEqual(st, 200)
        api._LOAD_CACHE.clear()
        s = api.load(api.CONFIG_FILE)["backup"]["s3"]
        self.assertEqual((s["enabled"], s["bucket"]), (False, "bkt"))

    def test_other_backup_settings_are_left_alone(self):
        self.save_config(retain_days=21, offsite_dir="/mnt/x")
        st, _ = self.save(dict(self.settings, region="eu-west-1"))
        self.assertEqual(st, 200)
        api._LOAD_CACHE.clear()
        bk = api.load(api.CONFIG_FILE)["backup"]
        self.assertEqual((bk["retain_days"], bk["offsite_dir"]), (21, "/mnt/x"))


class TestTheConnectionTest(_Base):

    def test_it_reports_the_steps(self):
        st, body = self.call(api.handle_backup_s3_test, {})
        self.assertEqual((st, body["ok"]), (200, True), body)
        self.assertEqual(body["steps"], ["write", "read", "delete", "list"])
        self.assertTrue(body["encrypted_archives"])
        self.assertEqual(self.store.objects, {})
        self.assertEqual(self.audit[-1][0][1], "backup_s3_test")

    def test_the_form_as_it_stands_can_be_tried_without_saving(self):
        self.save_config(s3={})
        st, body = self.call(api.handle_backup_s3_test, {"s3": self.settings})
        self.assertEqual((st, body["ok"]), (200, True), body)
        api._LOAD_CACHE.clear()
        self.assertEqual(api.load(api.CONFIG_FILE)["backup"]["s3"], {}, "and it was not saved")

    def test_a_failure_is_a_200_with_the_step_and_the_answer(self):
        self.store.deny = {"delete"}
        st, body = self.call(api.handle_backup_s3_test, {})
        self.assertEqual((st, body["ok"]), (200, False))
        self.assertIn("cannot delete", body["error"])
        self.assertIn("AccessDenied", body["error"])

    def test_no_secret_key(self):
        with mock.patch.dict(os.environ, {}):
            os.environ.pop("RP_BACKUP_S3_SECRET_KEY", None)
            os.environ.pop("RP_BACKUP_S3_SECRET_KEY_CMD", None)
            st, body = self.call(api.handle_backup_s3_test, {})
        self.assertEqual((st, body["ok"]), (200, False))
        self.assertIn("RP_BACKUP_S3_SECRET_KEY", body["error"])

    def test_nothing_set_up_and_settings_that_do_not_validate(self):
        self.save_config(s3={})
        st, body = self.call(api.handle_backup_s3_test, {})
        self.assertEqual(st, 400)
        self.assertIn("not set up", body["error"])
        st, body = self.call(api.handle_backup_s3_test, {"s3": dict(self.settings, bucket="X")})
        self.assertEqual(st, 400)
        self.assertIn("bucket", body["error"])
        for junk in ("x", 5, [1], None):
            st, _ = self.call(api.handle_backup_s3_test, {"s3": junk})
            self.assertEqual(st, 400, junk)

    def test_an_address_that_is_never_connected_to_is_refused(self):
        st, body = self.call(api.handle_backup_s3_test, {"s3": dict(self.settings, endpoint="https://169.254.169.254")})
        self.assertEqual(st, 400)
        self.assertIn("link-local", body["error"])
        self.assertEqual(self.store.requests, [])

    def test_only_an_administrator(self):
        for role in ("viewer", "auditor", "mcp"):
            api.verify_token = lambda *a, role=role, **k: ("someone", role)
            st, _ = self.call(api.handle_backup_s3_test, {})
            self.assertIn(st, (401, 403), role)
        self.assertEqual(self.store.requests, [])

    def test_a_tenant_administrator_can_not_make_the_server_connect_anywhere(self):
        """The address comes from the request, and loopback and private addresses are allowed for the operator's own store, so
        under tenancy only the platform operator may ask."""
        with mock.patch.object(api, "_tenancy_enforced", lambda: True), mock.patch.object(api, "_caller_is_superadmin", lambda: False):
            api.verify_token = lambda *a, **k: ("tenantadmin", "admin")
            st, body = self.call(api.handle_backup_s3_test, {"s3": self.settings})
        self.assertEqual(st, 403)
        self.assertIn("platform operator", body["error"])
        self.assertEqual(self.store.requests, [])

    def test_wrong_method(self):
        api.get_json_obj = lambda: {}
        api.method = lambda: "GET"
        self.cap.clear()
        try:
            api.handle_backup_s3_test()
        except api.HTTPError:
            pass
        self.assertEqual(self.cap["s"], 405)


class TestTheConnectionGuard(_Base):
    """The client talks through the product's own guarded opener: a name that turns out to be the metadata address is not connected to,
    and a redirect is not followed."""

    def test_a_name_that_resolves_to_the_metadata_address_is_not_connected_to(self):
        real = socket.getaddrinfo
        self.addCleanup(setattr, socket, "getaddrinfo", real)
        # the name looks fine when the settings are saved and changes its answer afterwards
        socket.getaddrinfo = lambda host, *a, **k: real("127.0.0.1", *a, **k) if host == "s3.rebind.example" else real(host, *a, **k)
        self.settings = dict(self.settings, endpoint=f"http://s3.rebind.example:{self.srv.server_address[1]}")
        self.save_config()
        self.assertTrue(self.run_backup()["s3_ok"], "while it answers with a private address it works")
        self.store.objects.clear()
        socket.getaddrinfo = lambda host, *a, **k: [(socket.AF_INET, 1, 6, "", ("169.254.169.254", a[0] if a else 0))] if host == "s3.rebind.example" else real(host, *a, **k)
        n = len(self.store.requests)
        r = self.run_backup()
        self.assertIs(r["s3_ok"], False)
        self.assertEqual(len(self.store.requests), n, "nothing more reached the store")

    def test_a_redirect_of_a_read_is_not_followed(self):
        other = fixtures.FakeStore()
        other_srv = fixtures.make_server(other)
        self.addCleanup(other_srv.server_close)
        self.addCleanup(other_srv.shutdown)
        self.run_backup()
        self.store.redirect_gets_to = f"http://127.0.0.1:{other_srv.server_address[1]}/bkt/rp/elsewhere"
        r = api._restore_drill_core()
        self.assertFalse(r["ok"])
        self.assertIn("307", r["error"])
        self.assertEqual(other.requests, [], "the place it pointed to was never asked")
        st, body = self.call(api.handle_backup_s3_test, {})
        self.assertEqual((st, body["ok"]), (200, False))
        self.assertEqual(other.requests, [])

    def test_a_redirect_is_not_followed(self):
        seen = []

        class Redirector(fixtures.http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def do_PUT(self):
                seen.append(self.path)
                self.send_response(307)
                self.send_header("Location", f"http://127.0.0.1:{self.server.server_address[1]}/elsewhere")
                self.send_header("Content-Length", "0")
                self.end_headers()
            do_GET = do_DELETE = do_PUT

        srv = fixtures.http.server.ThreadingHTTPServer(("127.0.0.1", 0), Redirector)
        srv.daemon_threads = True
        fixtures.threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        self.settings = dict(self.settings, endpoint=f"http://127.0.0.1:{srv.server_address[1]}")
        self.save_config()
        r = self.run_backup()
        self.assertIs(r["s3_ok"], False)
        self.assertEqual(len(seen), 1, "the first answer was the last request")
        self.assertIn("307", self.state()["s3_error"])


class TestTheCertificate(_Base):

    def setUp(self):
        super().setUp()
        if not shutil.which("openssl"):
            self.skipTest("openssl is not installed")
        crt, key = str(self.tmp / "c.pem"), str(self.tmp / "k.pem")
        r = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt, "-days", "2", "-subj", "/CN=localhost",
                            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], capture_output=True)
        if r.returncode != 0:
            self.skipTest("openssl could not make a certificate")
        self.tls = fixtures.make_server(self.store, tls=(crt, key))
        self.addCleanup(self.tls.server_close)
        self.addCleanup(self.tls.shutdown)
        self.settings = dict(self.settings, endpoint=f"https://127.0.0.1:{self.tls.server_address[1]}")

    def test_a_self_signed_certificate_is_refused_until_the_check_is_turned_off(self):
        self.save_config()
        r = self.run_backup()
        self.assertIs(r["s3_ok"], False)
        self.assertIn("could not connect", self.state()["s3_error"])
        self.assertEqual(self.store.requests, [], "no request was made over a connection that could not be trusted")
        self.settings = dict(self.settings, verify_tls=False)
        self.save_config()
        r = self.run_backup()
        self.assertTrue(r["s3_ok"], self.state())
        self.assertEqual(self.store.bad_auth, 0)

    def test_the_connection_test_follows_the_same_rule(self):
        st, body = self.call(api.handle_backup_s3_test, {"s3": self.settings})
        self.assertEqual((st, body["ok"]), (200, False))
        st, body = self.call(api.handle_backup_s3_test, {"s3": dict(self.settings, verify_tls=False)})
        self.assertEqual((st, body["ok"]), (200, True), body)


class TestTheRoute(unittest.TestCase):

    def test_the_test_is_routed_to_its_handler(self):
        self.assertIs(api._build_exact_routes()[("POST", "/api/backup/s3-test")], api.handle_backup_s3_test)

    def test_it_is_under_the_prefix_a_tenant_administrator_cannot_reach(self):
        prefixes = [r[0] for r in api._PLATFORM_ROUTES]
        self.assertIn("/api/backup", prefixes)


class TestThePostureRow(_Base):

    def row(self):
        api._LOAD_CACHE.clear()
        api.method = lambda: "GET"
        self.cap.clear()
        try:
            api.handle_security_posture()
        except api.HTTPError:
            pass
        rows = {r["key"]: r for r in self.cap["b"]["checks"]}
        return rows["backup_offsite"]

    def test_the_row_follows_the_last_run_of_each_destination(self):
        row = self.row()
        self.assertEqual(row["status"], "warn")
        self.assertEqual(row["detail"], "S3 bucket bkt — configured, no backup has run yet")
        self.run_backup()
        row = self.row()
        self.assertEqual((row["status"], row["detail"]), ("ok", "S3 bucket bkt"))
        self.store.deny = {"put"}
        self.run_backup()
        row = self.row()
        self.assertEqual(row["status"], "warn")
        self.assertEqual(row["detail"], "S3 bucket bkt — LAST MIRROR FAILED")

    def test_two_destinations_both_have_to_have_worked(self):
        self.save_config(offsite_dir=str(self.tmp / "mirror"))
        self.run_backup()
        row = self.row()
        self.assertEqual(row["status"], "ok")
        self.assertEqual(row["detail"], f"{self.tmp / 'mirror'}, S3 bucket bkt")
        self.store.deny = {"put"}
        self.run_backup()
        row = self.row()
        self.assertEqual(row["status"], "warn")
        self.assertEqual(row["detail"], "S3 bucket bkt — LAST MIRROR FAILED", "the directory copy worked and is not blamed")

    def test_with_nothing_set_it_is_local_only(self):
        self.save_config(s3={})
        row = self.row()
        self.assertEqual((row["status"], row["detail"]), ("warn", "local-host only"))

    def test_only_the_directory_reads_as_it_always_did(self):
        self.save_config(s3={}, offsite_dir=str(self.tmp / "mirror"))
        self.assertEqual(self.row()["detail"], f"{self.tmp / 'mirror'} — configured, no backup has run yet")
        self.run_backup()
        self.assertEqual((self.row()["status"], self.row()["detail"]), ("ok", str(self.tmp / "mirror")))


if __name__ == "__main__":
    unittest.main()

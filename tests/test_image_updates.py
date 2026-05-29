#!/usr/bin/env python3
"""v3.3.4: container image-update detection — scan orchestration + parsing.

Network-free: image_registry.remote_digest is stubbed so these tests never
touch a real registry. (The live token-auth flow against Docker Hub / GHCR /
lscr.io / Quay was validated by hand during development; baking real network
calls into CI would be flaky and rate-limited.)
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_CGI_BIN = Path(__file__).parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_TMPDIR = tempfile.mkdtemp()
os.environ["RP_DATA_DIR"] = _TMPDIR
os.environ["REQUEST_METHOD"] = "GET"
os.environ["PATH_INFO"] = "/"
os.environ["CONTENT_LENGTH"] = "0"

_spec = importlib.util.spec_from_file_location("api_imgupd", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import image_registry

LOCAL = "sha256:" + "a" * 64
NEWER = "sha256:" + "b" * 64


def _patch_respond():
    def fake(status, data):
        raise _Captured(status, data)
    api.respond = fake


class _Captured(Exception):
    def __init__(self, status, body):
        super().__init__(f"HTTP {status}")
        self.status = status
        self.body = body


def _seed_containers(digest=LOCAL):
    api.save(api.DEVICES_FILE, {"dev1": {"name": "host-a"}, "dev2": {"name": "host-b"}})
    api.save(api.CONTAINERS_FILE, {
        "dev1": {"ts": 1, "items": [
            {"name": "radarr", "image": "lscr.io/linuxserver/radarr",
             "tag": "latest", "repo_digest": digest},
            # locally-built image with no digest -> must be skipped, not guessed
            {"name": "built-local", "image": "myapp", "tag": "dev", "repo_digest": ""},
        ]},
        "dev2": {"ts": 1, "items": [
            # same image on a second host -> must dedup to one registry check
            {"name": "radarr2", "image": "lscr.io/linuxserver/radarr",
             "tag": "latest", "repo_digest": digest},
        ]},
    })


def _seed_cfg(enabled=True):
    cfg = api.load(api.CONFIG_FILE) or {}
    cfg["image_updates_enabled"] = enabled
    cfg["webhook_block_local"] = False   # skip the DNS-based SSRF check in tests
    cfg["last_image_scan"] = 0
    api.save(api.CONFIG_FILE, cfg)


class TestCollectAndScan(unittest.TestCase):
    def setUp(self):
        _patch_respond()
        _seed_cfg(True)
        _seed_containers(LOCAL)
        api.save(api.IMAGE_UPDATES_FILE, {})

    def test_collect_dedups_and_skips_digestless(self):
        fleet = api._collect_fleet_images()
        self.assertEqual(list(fleet.keys()), ["lscr.io/linuxserver/radarr:latest"])
        self.assertEqual(
            fleet["lscr.io/linuxserver/radarr:latest"]["local_digests"], {LOCAL})

    def test_update_available_when_registry_newer(self):
        api.image_registry_mod.remote_digest = lambda *a, **k: NEWER
        cfg = api.load(api.CONFIG_FILE)
        fleet = api._collect_fleet_images()
        checked = api._scan_images(list(fleet.keys()), fleet, cfg, force=True)
        self.assertEqual(checked, 1)          # deduped to one registry call
        rows = api._image_update_view()
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["update_available"])
        self.assertEqual(len(rows[0]["hosts"]), 2)
        self.assertTrue(all(h["stale"] for h in rows[0]["hosts"]))

    def test_no_update_when_registry_matches(self):
        api.image_registry_mod.remote_digest = lambda *a, **k: LOCAL
        cfg = api.load(api.CONFIG_FILE)
        fleet = api._collect_fleet_images()
        api._scan_images(list(fleet.keys()), fleet, cfg, force=True)
        rows = api._image_update_view()
        self.assertFalse(rows[0]["update_available"])

    def test_registry_error_recorded_not_treated_as_stale(self):
        def boom(*a, **k):
            raise RuntimeError("503 from registry")
        api.image_registry_mod.remote_digest = boom
        cfg = api.load(api.CONFIG_FILE)
        fleet = api._collect_fleet_images()
        api._scan_images(list(fleet.keys()), fleet, cfg, force=True)
        rows = api._image_update_view()
        self.assertIn("503", rows[0]["last_error"])
        self.assertFalse(rows[0]["update_available"])   # unknown is not stale

    def test_disabled_short_circuits_before_any_work(self):
        _seed_cfg(False)
        calls = {"n": 0}
        orig = api._collect_fleet_images

        def spy():
            calls["n"] += 1
            return orig()
        api._collect_fleet_images = spy
        try:
            api.run_image_scan_if_due()
        finally:
            api._collect_fleet_images = orig
        self.assertEqual(calls["n"], 0)


class TestImageAlerts(unittest.TestCase):
    def setUp(self):
        _patch_respond()
        _seed_cfg(True)
        _seed_containers(LOCAL)
        api.save(api.IMAGE_UPDATES_FILE, {})
        api.save(api.ALERTS_FILE, {"alerts": []})

    def _scan(self, registry_digest):
        api.image_registry_mod.remote_digest = lambda *a, **k: registry_digest
        cfg = api.load(api.CONFIG_FILE)
        fleet = api._collect_fleet_images()
        api._scan_images(list(fleet.keys()), fleet, cfg, force=True)

    def _open_image_alerts(self):
        alerts = (api.load(api.ALERTS_FILE) or {}).get("alerts", [])
        return [a for a in alerts
                if a.get("event") == "image_update_available" and not a.get("resolved_at")]

    def test_fires_low_alert_when_stale(self):
        self._scan(NEWER)
        opens = self._open_image_alerts()
        self.assertEqual(len(opens), 1)
        a = opens[0]
        self.assertEqual(a["severity"], "low")
        self.assertIn("radarr", a["title"])
        self.assertEqual(a["payload"].get("image"), "lscr.io/linuxserver/radarr")
        self.assertEqual(a["payload"].get("tag"), "latest")
        self.assertEqual(a["payload"].get("hosts_count"), 2)

    def test_debounced_no_duplicate_same_digest(self):
        self._scan(NEWER)
        self._scan(NEWER)   # same registry digest -> must not re-fire
        fired = [a for a in (api.load(api.ALERTS_FILE) or {}).get("alerts", [])
                 if a.get("event") == "image_update_available"]
        self.assertEqual(len(fired), 1)

    def test_auto_resolves_when_hosts_catch_up(self):
        self._scan(NEWER)                       # stale -> alert open
        self.assertEqual(len(self._open_image_alerts()), 1)
        _seed_containers(NEWER)                 # every host now on NEWER
        self._scan(NEWER)                       # not stale -> image_updated
        self.assertEqual(len(self._open_image_alerts()), 0)

    def test_no_alert_when_up_to_date(self):
        self._scan(LOCAL)                       # registry == local
        self.assertEqual(len(self._open_image_alerts()), 0)


class TestParseRef(unittest.TestCase):
    def test_variants(self):
        self.assertEqual(image_registry.parse_image_ref("nginx", "1.25"),
                         ("registry-1.docker.io", "library/nginx", "1.25"))
        self.assertEqual(image_registry.parse_image_ref("linuxserver/sonarr", ""),
                         ("registry-1.docker.io", "linuxserver/sonarr", "latest"))
        self.assertEqual(image_registry.parse_image_ref("lscr.io/linuxserver/radarr", ""),
                         ("lscr.io", "linuxserver/radarr", "latest"))
        self.assertIsNone(image_registry.parse_image_ref("", "x"))
        self.assertIsNone(image_registry.parse_image_ref("repo@sha256:abc", ""))


class TestContainersPreservesDigest(unittest.TestCase):
    def test_normalize_keeps_repo_digest(self):
        import containers as c
        out = c.normalize_container(
            {"name": "x", "image": "nginx", "tag": "1.25", "repo_digest": LOCAL})
        self.assertEqual(out["repo_digest"], LOCAL)


class TestImageUpdatesUI(unittest.TestCase):
    """The Containers-page Image-updates panel + its renderer must stay wired."""

    @classmethod
    def setUpClass(cls):
        root = Path(__file__).parent.parent / "server" / "html"
        cls.html = (root / "index.html").read_text()
        cls.appjs = (root / "static" / "js" / "app.js").read_text()

    def test_panel_and_sortable_headers_present(self):
        self.assertIn('id="image-updates-tbody"', self.html)
        self.assertIn('id="image-updates-thead"', self.html)
        for col in ("image", "tag", "hosts", "status", "registry", "checked"):
            self.assertIn(f'data-col="{col}"', self.html)

    def test_handlers_present(self):
        for fn in ("function loadImageUpdates", "function renderImageUpdates",
                   "function scanImageUpdatesNow", "_registerImageUpdatesTable"):
            self.assertIn(fn, self.appjs)

    def test_registers_sortable_table(self):
        self.assertIn("name: 'image-updates'", self.appjs)
        self.assertIn("sortHeaders: 'image-updates-thead'", self.appjs)

    def test_loaded_from_containers_page(self):
        self.assertIn("loadImageUpdates()", self.appjs)
        # and the scan button routes to the force-scan handler
        self.assertIn('data-action-btn="scanImageUpdatesNow"', self.html)


if __name__ == "__main__":
    unittest.main()

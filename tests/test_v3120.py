#!/usr/bin/env python3
"""
Tests for v3.12.0 — pluggable storage backend (SQLite alongside flat JSON),
strict version-bump pins.

The backend behaviour itself is covered in depth by tests/test_storage_backend.py;
this file holds the strict version-surface pins (loosened to regex on the next
bump) plus a few wiring smoke checks specific to this release.
"""
import os
import tempfile
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

import importlib.util
import sys
import unittest
from pathlib import Path

_ROOT    = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_spec = importlib.util.spec_from_file_location("api_v3120", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

VERSION = "3.12.0"


class TestVersionBumps(unittest.TestCase):
    def test_server_version(self):
        self.assertEqual(api.SERVER_VERSION, VERSION)

    def test_agent_version(self):
        txt = (_ROOT / "client/remotepower-agent.py").read_text()
        self.assertIn(f"VERSION      = '{VERSION}'", txt)

    def test_agent_extensionless_matches_py(self):
        a = (_ROOT / "client/remotepower-agent.py").read_bytes()
        b = (_ROOT / "client/remotepower-agent").read_bytes()
        self.assertEqual(a, b, "agent .py and extensionless copy diverged "
                               "(run cp client/remotepower-agent.py client/remotepower-agent)")

    def test_sw_cache_name(self):
        txt = (_ROOT / "server/html/sw.js").read_text()
        self.assertIn(f"remotepower-shell-v{VERSION}", txt)

    def test_index_cache_bust(self):
        txt = (_ROOT / "server/html/index.html").read_text()
        self.assertIn(f"?v={VERSION}", txt)
        self.assertNotIn("?v=3.11.0", txt)

    def test_readme_badge(self):
        txt = (_ROOT / "README.md").read_text()
        self.assertIn(f"version-{VERSION}-blue", txt)

    def test_changelog_top_entry(self):
        txt = (_ROOT / "CHANGELOG.md").read_text()
        self.assertIn(f"v{VERSION}", txt[:2000])

    def test_version_doc_exists(self):
        self.assertTrue((_ROOT / f"docs/v{VERSION}.md").exists())

    def test_whats_new_card_present(self):
        html = (_ROOT / "server/html/index.html").read_text()
        self.assertIn("What's new — v3.12.0", html)


class TestStorageBackendWiring(unittest.TestCase):
    def test_routes_registered(self):
        routes = api._build_exact_routes()
        self.assertIn(('GET', '/api/storage-backend/status'), routes)
        self.assertIn(('POST', '/api/storage-backend/migrate'), routes)

    def test_seam_helpers_exist(self):
        for name in ('backend_exists', 'backend_iter_files', '_storage_backend',
                     '_invalidate_backend_cache'):
            self.assertTrue(hasattr(api, name), name)

    def test_default_backend_is_json(self):
        # With no marker and no env override, the default must be flat JSON so
        # existing installs are unaffected until an operator opts in.
        os.environ.pop('RP_STORAGE_BACKEND', None)
        api._invalidate_backend_cache()
        # A throwaway marker path that doesn't exist -> default json.
        old = api.STORAGE_MARKER_FILE
        api.STORAGE_MARKER_FILE = Path(tempfile.mkdtemp()) / 'storage_backend.json'
        try:
            self.assertEqual(api._storage_backend(), 'json')
        finally:
            api.STORAGE_MARKER_FILE = old
            api._invalidate_backend_cache()

    def test_migrate_storage_module_importable(self):
        import storage
        for fn in ('migrate_run', 'verify_migration', 'migrate_json_to_sqlite',
                   'migrate_sqlite_to_json'):
            self.assertTrue(callable(getattr(storage, fn)), fn)


if __name__ == '__main__':
    unittest.main()

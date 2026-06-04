#!/usr/bin/env python3
"""
Tests for v3.13.0 — "bind it together" round four: surface collected-but-hidden
host signals, cap overflowing panels, plus performance and security hardening.

Holds the strict version-surface pins for this release (loosened to regex on the
next bump) plus wiring smoke checks for the new bindings and hardening.
"""
import os
import tempfile

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

import importlib.util
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))
sys.path.insert(0, str(Path(__file__).parent))

_spec = importlib.util.spec_from_file_location("api_v3130", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

from clientjs import client_js

VERSION = "3.13.0"


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
        self.assertNotIn("?v=3.12.0", txt)

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
        self.assertIn(f"What's new — v{VERSION}", html)


class TestDataBindings(unittest.TestCase):
    """The new device-drawer / device-card bindings exist in the front-end."""

    def setUp(self):
        self.js = client_js()

    def test_recent_logins_binding(self):
        self.assertIn("Access — recent logins", self.js)
        self.assertIn("recent_logins", self.js)

    def test_timers_binding(self):
        self.assertIn("Scheduled jobs / timers", self.js)

    def test_storage_health_binding(self):
        self.assertIn("Pools / arrays", self.js)
        self.assertIn("storage_health", self.js)

    def test_ports_scope_and_addr(self):
        # The drawer Ports card now renders the scope badge + bind address.
        self.assertIn("scopeBadge", self.js)

    def test_firewall_fingerprint_binding(self):
        self.assertIn("firewall_fp", self.js)
        self.assertIn("fpLine", self.js)

    def test_brute_force_badge(self):
        self.assertIn("brute_force_active", self.js)


class TestOverflowCaps(unittest.TestCase):
    """Panels cap and scroll instead of growing unbounded."""

    def setUp(self):
        self.css = (_ROOT / "server/html/static/css/styles.css").read_text()
        self.js = client_js()

    def test_audit_scroll_class_defined(self):
        self.assertIn(".audit-scroll", self.css)

    def test_audit_section_body_capped(self):
        # The drawer card body now has a max-height + overflow.
        body = self.css.split(".audit-section-body")[1].split("}")[0]
        self.assertIn("max-height", body)
        self.assertIn("overflow", body)

    def test_clip_bugs_fixed(self):
        # isl-654 (host-config dump) and isl-382 (patch history) had max-height
        # with no overflow — both must now scroll.
        for cls in (".isl-654", ".isl-382", ".isl-636"):
            rule = self.css.split(cls + " {")[1].split("}")[0]
            self.assertIn("overflow", rule, f"{cls} still clips without overflow")


class TestFleetRiskCache(unittest.TestCase):
    def test_cache_helpers_exist(self):
        self.assertTrue(callable(getattr(api, "_fleet_risk_cached", None)))
        self.assertTrue(callable(getattr(api, "_fleet_risk_cache_file", None)))

    def test_callers_use_cache(self):
        src = (_CGI_BIN / "api.py").read_text()
        # Both the risk endpoint and fleet health route through the cache.
        self.assertIn("risks = _fleet_risk_cached()", src)
        self.assertIn("_fleet_risk_cached(use_cache=use_cache)", src)


class TestSecurityHardening(unittest.TestCase):
    def setUp(self):
        self.src = (_CGI_BIN / "api.py").read_text()

    def test_scap_report_sandboxed_csp(self):
        # The agent-supplied SCAP HTML is served under a self-contained
        # sandboxed CSP (in the report download handler) regardless of the
        # upstream policy.
        block = self.src.split("def handle_scap_report_download")[1][:2000]
        self.assertIn("Content-Security-Policy", block)
        self.assertIn("sandbox;", block)
        self.assertIn("X-Frame-Options: DENY", block)

    def test_oidc_claim_checks(self):
        self.assertIn("id_token expired", self.src)
        self.assertIn("id_token issuer mismatch", self.src)
        self.assertIn("id_token audience mismatch", self.src)

    def test_syslog_resolve_once(self):
        # The syslog forwarder resolves once and connects to the literal IP.
        self.assertIn("getaddrinfo(host, port", self.src)


class TestStaticCacheImmutable(unittest.TestCase):
    def test_nginx_static_immutable(self):
        # The tracked reference config — deploy/nginx/* is gitignored
        # (environment-specific) and absent from a clean checkout / dist tarball.
        conf = (_ROOT / "server/conf/remotepower.conf").read_text()
        self.assertIn("location ^~ /static/", conf)
        self.assertIn("immutable", conf)


if __name__ == "__main__":
    unittest.main()

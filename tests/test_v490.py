#!/usr/bin/env python3
"""Tests for v4.9.0 — the DNS dashboard (read/write DNS records via provider APIs).

Covers the pure provider clients in dns_zones.py (Cloudflare / DigitalOcean /
Hetzner / deSEC / Porkbun) with a fake HTTP client (no network), the api.py
wiring (routes registered, handlers admin-gated, credential reuse from the ACME
DNS-01 store), and the version-surface pins.
"""
import importlib.util
import inspect
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

import dns_zones as dz
from integrations import Resp

_spec = importlib.util.spec_from_file_location("api_v490", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class FakeClient:
    """Stands in for the SSRF-safe HTTP client. ``fn(method, path, body)``
    returns ``(status, json_obj)``; every call is recorded for assertions."""

    def __init__(self, fn):
        self._fn = fn
        self.calls = []

    def request(self, method, path, headers=None, params=None, body=None):
        parsed = json.loads(body) if body else None
        self.calls.append({"method": method, "path": path,
                           "headers": headers or {}, "body": parsed})
        status, obj = self._fn(method, path, parsed)
        return Resp(status, json.dumps(obj) if obj is not None else "")


class TestHelpers(unittest.TestCase):
    def test_subname_apex_and_host(self):
        self.assertEqual(dz._subname("ex.com", "ex.com"), "@")
        self.assertEqual(dz._subname("ex.com", "ex.com", apex=""), "")
        self.assertEqual(dz._subname("www.ex.com", "ex.com"), "www")
        self.assertEqual(dz._subname("www", "ex.com"), "www")

    def test_fqdn_apex_and_host(self):
        self.assertEqual(dz._fqdn("@", "ex.com"), "ex.com")
        self.assertEqual(dz._fqdn("", "ex.com"), "ex.com")
        self.assertEqual(dz._fqdn("www", "ex.com"), "www.ex.com")
        self.assertEqual(dz._fqdn("www.ex.com", "ex.com"), "www.ex.com")

    def test_provider_catalog(self):
        keys = [p["key"] for p in dz.list_providers()]
        self.assertEqual(set(keys),
                         {"cloudflare", "digitalocean", "hetzner", "desec", "porkbun"})
        cf = next(p for p in dz.list_providers() if p["key"] == "cloudflare")
        self.assertTrue(cf["supports_proxied"])
        self.assertEqual(cf["acme_provider"], "dns_cf")


class TestCloudflare(unittest.TestCase):
    def _prov(self, fn, creds=None):
        return dz.Cloudflare(FakeClient(fn), creds if creds is not None else {"CF_Token": "tok"})

    def test_missing_token_raises(self):
        p = self._prov(lambda m, pa, b: (200, {"success": True, "result": []}), creds={})
        with self.assertRaises(dz.DNSError):
            p.list_zones()

    def test_list_records_normalized_and_authed(self):
        c = FakeClient(lambda m, pa, b: (200, {"success": True, "result": [
            {"id": "r1", "type": "A", "name": "www.ex.com", "content": "1.2.3.4",
             "ttl": 1, "proxied": True}]}))
        recs = dz.Cloudflare(c, {"CF_Token": "tok"}).list_records("z1", "ex.com")
        self.assertEqual(recs[0]["name"], "www.ex.com")
        self.assertTrue(recs[0]["proxied"])
        self.assertEqual(c.calls[0]["headers"].get("Authorization"), "Bearer tok")

    def test_create_builds_body_and_checks_success(self):
        seen = {}

        def fn(m, pa, b):
            seen["body"] = b
            return (200, {"success": True, "result": {}})

        self._prov(fn).create_record("z1", "ex.com",
                                     {"type": "A", "name": "www", "content": "1.2.3.4",
                                      "ttl": 120, "proxied": True})
        self.assertEqual(seen["body"]["name"], "www.ex.com")
        self.assertEqual(seen["body"]["ttl"], 120)
        self.assertTrue(seen["body"]["proxied"])

    def test_api_error_raises(self):
        p = self._prov(lambda m, pa, b: (200, {"success": False,
                                               "errors": [{"message": "bad token"}]}))
        with self.assertRaises(dz.DNSError) as ctx:
            p.list_zones()
        self.assertIn("bad token", str(ctx.exception))


class TestDigitalOcean(unittest.TestCase):
    def test_apex_name_collapses_and_data_field(self):
        seen = {}

        def fn(m, pa, b):
            seen["body"] = b
            return (201, {"domain_record": {}})

        dz.DigitalOcean(FakeClient(fn), {"DO_API_KEY": "k"}).create_record(
            "ex.com", "ex.com", {"type": "A", "name": "ex.com", "content": "1.2.3.4"})
        self.assertEqual(seen["body"]["name"], "@")
        self.assertEqual(seen["body"]["data"], "1.2.3.4")


class TestHetzner(unittest.TestCase):
    def test_auth_header_and_zone_id_in_body(self):
        c = FakeClient(lambda m, pa, b: (200, {"record": {}}))
        dz.Hetzner(c, {"HETZNER_Token": "t"}).create_record(
            "zone9", "ex.com", {"type": "A", "name": "www", "content": "1.2.3.4", "ttl": 0})
        self.assertEqual(c.calls[0]["headers"].get("Auth-API-Token"), "t")
        self.assertEqual(c.calls[0]["body"]["zone_id"], "zone9")
        self.assertEqual(c.calls[0]["body"]["value"], "1.2.3.4")


class TestDesec(unittest.TestCase):
    def test_list_groups_rrsets(self):
        c = FakeClient(lambda m, pa, b: (200, [
            {"subname": "www", "type": "A", "ttl": 3600, "records": ["1.2.3.4"]},
            {"subname": "", "type": "A", "ttl": 3600, "records": ["5.6.7.8", "9.9.9.9"]}]))
        recs = dz.Desec(c, {"DEDYN_TOKEN": "t"}).list_records("ex.com", "ex.com")
        by_id = {r["id"]: r for r in recs}
        self.assertEqual(by_id["www|A"]["name"], "www.ex.com")
        self.assertEqual(by_id["|A"]["name"], "ex.com")
        self.assertEqual(by_id["|A"]["content"], "5.6.7.8\n9.9.9.9")

    def test_delete_sends_empty_records_patch(self):
        c = FakeClient(lambda m, pa, b: (200, []))
        dz.Desec(c, {"DEDYN_TOKEN": "t"}).delete_record("ex.com", "ex.com", "www|A")
        self.assertEqual(c.calls[0]["method"], "PATCH")
        self.assertEqual(c.calls[0]["body"], [{"subname": "www", "type": "A", "records": []}])

    def test_min_ttl_enforced(self):
        c = FakeClient(lambda m, pa, b: (200, []))
        dz.Desec(c, {"DEDYN_TOKEN": "t"}).create_record(
            "ex.com", "ex.com", {"type": "A", "name": "www", "content": "1.2.3.4", "ttl": 60})
        self.assertGreaterEqual(c.calls[0]["body"][0]["ttl"], 3600)


class TestPorkbun(unittest.TestCase):
    def test_keys_in_body_and_subdomain(self):
        seen = {}

        def fn(m, pa, b):
            seen.setdefault("calls", []).append((pa, b))
            return (200, {"status": "SUCCESS"})

        dz.Porkbun(FakeClient(fn), {"PORKBUN_API_KEY": "a", "PORKBUN_SECRET_API_KEY": "s"}
                   ).create_record("ex.com", "ex.com",
                                   {"type": "A", "name": "www.ex.com", "content": "1.2.3.4", "ttl": 600})
        path, body = seen["calls"][0]
        self.assertEqual(path, "/dns/create/ex.com")
        self.assertEqual(body["apikey"], "a")
        self.assertEqual(body["secretapikey"], "s")
        self.assertEqual(body["name"], "www")

    def test_non_success_status_raises(self):
        p = dz.Porkbun(FakeClient(lambda m, pa, b: (200, {"status": "ERROR", "message": "nope"})),
                       {"PORKBUN_API_KEY": "a", "PORKBUN_SECRET_API_KEY": "s"})
        with self.assertRaises(dz.DNSError):
            p.list_zones()


class TestApiWiring(unittest.TestCase):
    def test_routes_registered(self):
        routes = api._build_exact_routes()
        for r in (("GET", "/api/dns/providers"), ("GET", "/api/dns/zones"),
                  ("GET", "/api/dns/records"), ("POST", "/api/dns/records"),
                  ("POST", "/api/dns/records/update"), ("POST", "/api/dns/records/delete")):
            self.assertIn(r, routes)

    def test_handlers_admin_gated(self):
        for fn in (api.handle_dns_providers, api.handle_dns_zones, api.handle_dns_records,
                   api.handle_dns_record_create, api.handle_dns_record_update,
                   api.handle_dns_record_delete):
            self.assertIn("require_admin_auth", inspect.getsource(fn))

    def test_writes_audit_logged(self):
        for fn in (api.handle_dns_record_create, api.handle_dns_record_update,
                   api.handle_dns_record_delete):
            self.assertIn("audit_log", inspect.getsource(fn))

    def test_make_provider_reuses_acme_creds(self):
        api.save(api.CONFIG_FILE, {"acme_dns_credentials": {"dns_cf": {"CF_Token": "x"}}})
        prov = api._dns_make_provider("cloudflare")
        self.assertIsInstance(prov, dz.Cloudflare)
        self.assertEqual(prov.creds.get("CF_Token"), "x")

    def test_make_provider_unknown_400(self):
        with self.assertRaises(api.HTTPError) as ctx:
            api._dns_make_provider("nope")
        self.assertEqual(ctx.exception.status, 400)

    def test_make_provider_no_creds_400_with_hint(self):
        api.save(api.CONFIG_FILE, {"acme_dns_credentials": {}})
        with self.assertRaises(api.HTTPError) as ctx:
            api._dns_make_provider("hetzner")
        self.assertEqual(ctx.exception.status, 400)
        self.assertIn("cred_hint", ctx.exception.body)


class TestVersionBumps(unittest.TestCase):
    """Strict version-surface pins for v4.9.0 — loosen to regex on the next bump
    (see tests/test_v480.py for the loosened pattern)."""
    V = "4.9.0"

    def test_server_version(self):
        self.assertEqual(api.SERVER_VERSION, self.V)

    def test_agent_versions(self):
        self.assertIn(f"VERSION      = '{self.V}'",
                      (_ROOT / "client/remotepower-agent.py").read_text())
        for rel in ("client/remotepower-agent-win.py", "client/remotepower-agent-mac.py"):
            self.assertIn(f"VERSION = '{self.V}'", (_ROOT / rel).read_text(), rel)

    def test_agent_extensionless_in_sync(self):
        self.assertEqual((_ROOT / "client/remotepower-agent.py").read_bytes(),
                         (_ROOT / "client/remotepower-agent").read_bytes())

    def test_sw_and_cachebust(self):
        self.assertIn(f"remotepower-shell-v{self.V}",
                      (_ROOT / "server/html/sw.js").read_text())
        self.assertIn(f"?v={self.V}", (_ROOT / "server/html/index.html").read_text())

    def test_no_stale_cachebust(self):
        html = (_ROOT / "server/html/index.html").read_text()
        self.assertEqual(set(re.findall(r"\?v=(4\.8\.0[^\"&]*)", html)), set(),
                         "stale ?v=4.8.0 cache-busts left")

    def test_readme_and_changelog(self):
        self.assertIn(f"version-{self.V}-blue", (_ROOT / "README.md").read_text())
        self.assertIn(f"v{self.V}", (_ROOT / "CHANGELOG.md").read_text()[:2000])

    def test_version_doc_exists(self):
        self.assertTrue((_ROOT / f"docs/v{self.V}.md").exists())

    def test_old_version_doc_pruned(self):
        self.assertFalse((_ROOT / "docs/v4.5.0.md").exists(),
                         "docs/v4.5.0.md should be pruned to keep last 5")

    def test_doc_set_keeps_five_versions(self):
        vdocs = sorted(p.name for p in (_ROOT / "docs").glob("v*.md"))
        self.assertEqual(len(vdocs), 5, f"expected exactly 5 version docs, got {vdocs}")

    def test_whats_new_card_present(self):
        self.assertIn(f"What's new — v{self.V}",
                      (_ROOT / "server/html/index.html").read_text())


if __name__ == "__main__":
    unittest.main()

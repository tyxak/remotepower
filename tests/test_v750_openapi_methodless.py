#!/usr/bin/env python3
"""Every routed operation is in the OpenAPI document (7.5.0 docs review).

Six routes enforce their method inside the handler (route-table entries with no method). The dispatcher reconstruction needs an
explicit `m == '<VERB>'` and the stub pass needs a method, so both skipped them and /api/openapi.json did not list `/enroll/pin`,
`/patch-snapshots`, `/netscan-schedules`, `/me/avatar`, `/software-policy` and `/wol`. They are written by hand from what their handlers
enforce, and this holds the class: a route with no method that the document does not list fails here.
"""
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-oas-"))
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))
import api  # noqa: E402
import openapi_spec  # noqa: E402

SIX = {"/enroll/pin": {"post"}, "/patch-snapshots": {"get", "post"}, "/netscan-schedules": {"get", "post"},
       "/me/avatar": {"get", "post", "delete"}, "/software-policy": {"get", "post"}, "/wol": {"post"}}


def spec():
    routes = list(api._build_exact_routes().keys()) + api._dispatcher_routes()
    return openapi_spec.build_spec(api.SERVER_VERSION, routes), routes


class TestTheSixAreListed(unittest.TestCase):

    def test_each_with_the_methods_its_handler_enforces(self):
        paths = spec()[0]["paths"]
        for p, methods in SIX.items():
            self.assertIn(p, paths, p)
            self.assertEqual({m for m in paths[p] if m in ("get", "post", "put", "patch", "delete")}, methods, p)

    def test_every_operation_has_a_summary_a_tag_and_a_response(self):
        paths = spec()[0]["paths"]
        for p in SIX:
            for m, o in paths[p].items():
                self.assertTrue(o.get("summary") and o.get("tags") and "200" in o.get("responses", {}), (p, m))
                self.assertNotIn("Auto-generated stub", o.get("description", ""), (p, m))

    def test_the_admin_gated_ones_say_so(self):
        paths = spec()[0]["paths"]
        for p, m in (("/enroll/pin", "post"), ("/patch-snapshots", "post"), ("/netscan-schedules", "post"),
                     ("/software-policy", "post"), ("/wol", "post")):
            self.assertIn("403", paths[p][m]["responses"], (p, m))
            self.assertIn("Admin only", paths[p][m]["description"], (p, m))

    def test_the_methods_match_the_handlers_source(self):
        """The methods are what each handler enforces, read from its own body."""
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from apisrc import api_source
        from srcpin import py_function
        text = api_source()
        for handler, methods in (("handle_enroll_pin", {"POST"}), ("handle_wol", {"POST"}),
                                 ("handle_patch_snapshots", {"GET", "POST"}), ("handle_netscan_schedules", {"GET", "POST"}),
                                 ("handle_software_policy", {"GET", "POST"}), ("handle_me_avatar", {"GET", "POST", "DELETE"})):
            body = py_function(text, handler)
            found = set(re.findall(r"""(?:method\(\)\s*(?:==|!=)\s*|\bm\s*==\s*)['"]([A-Z]+)['"]""", body))
            self.assertEqual(found, methods, handler)


class TestNoRouteIsLeftOut(unittest.TestCase):

    def test_every_route_with_no_method_is_documented(self):
        doc, routes = spec()
        paths = doc["paths"]
        methodless = [p for m, p in routes if m is None]
        self.assertGreaterEqual(len(methodless), 10, "the population is empty: this check would measure nothing")
        missing = [p for p in methodless if (p[4:] if p.startswith("/api") else p) not in paths
                   and not any(re.sub(r"\{[^}]+\}", "{}", k) == re.sub(r"\{[^}]+\}", "{}", p[4:]) for k in paths)]
        self.assertEqual(missing, [], "routed, any-method and not in /api/openapi.json")

    def test_the_control_a_route_nobody_documented_would_be_found(self):
        doc, routes = spec()
        fake = routes + [(None, "/api/not-documented-anywhere")]
        paths = openapi_spec.build_spec(api.SERVER_VERSION, fake)["paths"]
        self.assertNotIn("/not-documented-anywhere", paths)           # the builder still skips it: the test above is what catches it

    def test_the_document_counts_in_the_api_guide_are_the_documents(self):
        doc = spec()[0]
        n = len(doc["paths"])
        self.assertIn(f"**{n} paths**", (ROOT / "docs" / "api.md").read_text())


if __name__ == "__main__":
    unittest.main()

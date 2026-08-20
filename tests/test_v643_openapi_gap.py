"""v6.4.3: close the last OpenAPI coverage gaps, and stop double-documenting.

Two defects, found by comparing the dispatcher's own route table against the
built spec rather than by reading either:

1. **The same endpoint documented twice under two parameter names.**
   `_path_ingest()` (added earlier this release) documents
   `/itsm/in/{token}`; the dispatcher reconstruction independently emits
   `/itsm/in/{id}` for the same branch. Swagger renders both, so the reader
   sees two endpoints where there is one, and cannot tell which is real.

2. **Any-method dispatcher branches were skipped entirely.** The
   reconstruction reads the branch's condition TEXT looking for `m == 'X'`,
   and a branch that accepts any verb has no such text — so `/enroll/register`
   and the whole SCIM 2.0 surface were absent from the spec while being live,
   authenticated routes.

The measured numbers matter here: the standing note claimed ~48 missing paths.
Measured, it was 9, of which 3 were this duplicate-naming artefact. Verify,
don't quote.
"""

import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))


def _spec():
    os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
    spec = importlib.util.spec_from_file_location("api_oas_gap", str(_CGI / "api.py"))
    api = importlib.util.module_from_spec(spec)
    sys.modules["api_oas_gap"] = api
    spec.loader.exec_module(api)
    import openapi_spec

    routes = list(api._build_exact_routes().keys()) + api._dispatcher_routes()
    return api, openapi_spec.build_spec(api.SERVER_VERSION, routes=routes)


class TestNoEndpointIsDocumentedTwice(unittest.TestCase):
    """A path's SHAPE — its literal segments with every {param} normalised — is
    the identity. Two entries with the same shape are one endpoint rendered
    twice, and a reader has no way to tell which name is the real one."""

    @classmethod
    def setUpClass(cls):
        cls.api, cls.spec = _spec()

    def test_no_two_paths_share_a_shape(self):
        shapes = {}
        for p in self.spec["paths"]:
            shape = re.sub(r"\{[^}]+\}", "{}", p)
            shapes.setdefault(shape, []).append(p)
        dupes = {k: sorted(v) for k, v in shapes.items() if len(v) > 1}
        self.assertEqual(
            {},
            dupes,
            "the same endpoint is documented under more than one parameter " f"name: {dupes}",
        )

    def test_the_shape_check_can_actually_see_a_duplicate(self):
        """Positive control — the normaliser must collapse differing parameter
        names, or the assertion above is vacuous."""
        self.assertEqual(
            re.sub(r"\{[^}]+\}", "{}", "/itsm/in/{token}"),
            re.sub(r"\{[^}]+\}", "{}", "/itsm/in/{id}"),
        )


class TestEveryDispatcherRouteIsDocumented(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api, cls.spec = _spec()
        cls.shapes = {re.sub(r"\{[^}]+\}", "{}", p) for p in cls.spec["paths"]}

    def _wanted(self):
        """Every concrete path the dispatcher table names, as a shape.

        This used to build a prefix branch's shape as `prefix + "/{}"` and stop
        there — the SAME truncation `_dispatcher_routes` had. So a branch like
        `pi.startswith('/api/alerts/') and pi.endswith('/ack')` entered the
        wanted-set as `/alerts/{}`, matched the (wrong) published path, and the
        real one was never in the population. 60 branches were affected: not
        failing, invisible. The sub-resource comes from the condition text, the
        same place the spec builder reads it, so the two cannot drift apart
        again without this going red.
        """
        out = set()
        for row in self.api._PATTERN_ROUTE_DEFS:
            kind, _methods, prefix = row[0], row[1], row[2]
            if not prefix or not str(prefix).startswith("/api/"):
                continue
            if str(prefix).startswith("/api/devices/"):
                continue  # device sub-resources are templated separately
            p = str(prefix)[4:]
            if kind == "eq":
                out.add(p)
                continue
            # A negated endswith carves a sub-path OUT of the branch
            # (`not pi.endswith('/passwd')`), so it names /users/{}, not
            # /users/{}/passwd.
            subs = [
                m.group(2)
                for m in re.finditer(
                    r"(not\s+)?pi\.endswith\('(/[^']+)'\)", str(row[5])
                )
                if not m.group(1)
            ]
            base = p.rstrip("/") + "/{}"
            out.update(base + s for s in subs) if subs else out.add(base)
        return out

    def test_the_population_includes_sub_resources(self):
        """Positive control for the fix above. Without it every assertion about
        a sub-resource below is vacuous — the path is simply not asked about."""
        wanted = self._wanted()
        for p in ("/alerts/{}/ack", "/virt/{}/vms", "/scripts/{}/dry-run"):
            self.assertIn(p, wanted, "the sub-resource dimension is missing "
                                     "from the enumeration again")
        self.assertGreater(len(wanted), 100)

    def test_a_negated_endswith_is_not_read_as_a_sub_resource(self):
        """`pi.startswith('/api/users/') and not pi.endswith('/passwd')` carves
        the sub-path OUT. Read as a sub-resource it publishes DELETE
        /users/{id}/passwd — a route that deletes nothing, next to the real one
        it would have replaced. Asserted on the SPEC, because those two rows
        declare no prefix and so never enter _wanted() above."""
        self.assertNotIn("/users/{id}/passwd", self.spec["paths"])
        got = self.spec["paths"].get("/users/{id}") or {}
        self.assertEqual({"delete", "patch"}, {m for m in got if m in
                                               ("get", "post", "put", "patch", "delete")})

    def test_the_enumeration_is_not_empty(self):
        """Positive control: this reads a live table through a private name."""
        self.assertGreater(len(self._wanted()), 100)

    def test_every_named_route_appears_in_the_spec(self):
        missing = sorted(p for p in self._wanted() if p not in self.shapes)
        self.assertEqual(
            [],
            missing,
            "live authenticated routes are absent from the published API " f"reference: {missing}",
        )

    def test_the_scim_surface_is_documented(self):
        """Named explicitly because it is a standards-defined surface an
        identity provider is pointed at — undocumented, it is undiscoverable."""
        for p in (
            "/scim/v2/Users",
            "/scim/v2/Groups",
            "/scim/v2/ServiceProviderConfig",
            "/scim/v2/ResourceTypes",
            "/scim/v2/Schemas",
        ):
            self.assertIn(p, self.spec["paths"], f"{p} is live but undocumented")

    def test_the_documented_routes_carry_operations(self):
        """A path entry with no verb under it renders as an empty row."""
        verbs = {"get", "post", "put", "patch", "delete", "head", "options"}
        empty = [p for p, ops in self.spec["paths"].items() if not (set(ops) & verbs)]
        self.assertEqual([], empty, f"path entries with no operation: {empty}")


if __name__ == "__main__":
    unittest.main()

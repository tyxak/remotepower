"""v6.4.2: saved queries share one store, one sharing model, one tenant gate.

Three surfaces save queries. The Data Explorer persisted server-side WITH tenant
isolation and visibility; the Fleet Query page and the Metric explorer kept
theirs in `localStorage`. So a team's fleet-interrogation knowledge was trapped
in one browser profile, and the two newer surfaces silently had no tenant model
at all — the divergence mattered more than the missing persistence.

Rather than a second store (and a second sharing model to get wrong), the
existing `query_templates` trio gained a `kind` discriminator.

Run: python3 -m pytest tests/test_v642_saved_queries.py -q
"""
import os
import re
import sys
import tempfile
import unittest
import importlib.util
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v642_sq", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Base(unittest.TestCase):
    def setUp(self):
        self._orig = {n: getattr(api, n) for n in
                      ("require_auth", "verify_token", "get_token_from_request")}
        api.require_auth = lambda *a, **k: "jakob"
        api.verify_token = lambda *a, **k: ("jakob", "admin")
        api.get_token_from_request = lambda: "tok"
        api.save(api.QUERY_TEMPLATES_FILE, {})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        api.save(api.QUERY_TEMPLATES_FILE, {})
        api._LOAD_CACHE.clear()

    def _call(self, fn, method="POST", body=None, qs=""):
        api._RCTX.environ = {"REQUEST_METHOD": method,
                             "PATH_INFO": "/api/query/templates", "QUERY_STRING": qs}
        if body is not None:
            api.get_json_obj = lambda: body
            api.get_json_body = lambda: body
        try:
            fn()
        except (SystemExit, api.HTTPError) as e:
            return getattr(e, "status", None), getattr(e, "body", None)
        return None, None

    def _list(self, qs=""):
        _st, b = self._call(api.handle_query_templates, "GET", qs=qs)
        return (b or {}).get("templates") or []


class TestKindDiscriminator(_Base):
    def test_all_three_kinds_save(self):
        for body in ({"name": "P", "entity": "devices"},
                     {"name": "F", "kind": "fleet", "params": {"group": "prod"}},
                     {"name": "M", "kind": "metric", "params": {"metrics": ["mem"]}}):
            st, b = self._call(api.handle_query_template_create, body=body)
            self.assertEqual(st, 201, f"{body['name']}: {b}")

    def test_a_bare_list_returns_only_predicates(self):
        """THE regression guard. The Data Explorer calls this endpoint bare and
        assigns t.entity to its entity picker — without the default it would
        list fleet/metric queries it cannot run and show an undefined entity."""
        self._call(api.handle_query_template_create, body={"name": "P", "entity": "devices"})
        self._call(api.handle_query_template_create,
                   body={"name": "F", "kind": "fleet", "params": {"group": "prod"}})
        names = [t["name"] for t in self._list()]
        self.assertEqual(names, ["P"])

    def test_each_kind_is_filterable(self):
        self._call(api.handle_query_template_create,
                   body={"name": "F", "kind": "fleet", "params": {"group": "prod"}})
        self.assertEqual([t["name"] for t in self._list("kind=fleet")], ["F"])
        self.assertEqual(self._list("kind=metric"), [])

    def test_a_legacy_record_with_no_kind_reads_as_predicate(self):
        """Every template saved before this change — nothing may disappear."""
        api.save(api.QUERY_TEMPLATES_FILE, {"old": {
            "id": "old", "name": "Legacy", "entity": "devices",
            "owner": "jakob", "visibility": "shared"}})
        api._LOAD_CACHE.clear()
        self.assertEqual([t["name"] for t in self._list()], ["Legacy"])

    def test_an_unknown_kind_is_rejected(self):
        st, _b = self._call(api.handle_query_template_create,
                            body={"name": "x", "kind": "wat", "params": {"group": "p"}})
        self.assertEqual(st, 400)


class TestParamWhitelist(_Base):
    def test_unknown_facets_are_dropped_not_stored(self):
        """These params are replayed into a query the SERVER runs."""
        self._call(api.handle_query_template_create, body={
            "name": "F", "kind": "fleet",
            "params": {"group": "prod", "pending_gt": 5, "bogus": "x", "__proto__": "y"}})
        stored = self._list("kind=fleet")[0]["params"]
        self.assertEqual(stored, {"group": "prod", "pending_gt": 5})

    def test_a_fleet_query_with_no_recognised_facet_is_rejected(self):
        st, _b = self._call(api.handle_query_template_create,
                            body={"name": "F", "kind": "fleet", "params": {"nope": 1}})
        self.assertEqual(st, 400)

    def test_the_server_facet_list_matches_the_client(self):
        """Two registries. A facet added to one side only is silently dropped
        on save with no error — the user's query just quietly loses a filter."""
        js = (_ROOT / "server/html/static/js/app.js").read_text()
        m = re.search(r"const _FQ_FIELDS = \{(.*?)\n\};", js, re.S)
        self.assertIsNotNone(m, "_FQ_FIELDS not found in app.js")
        client = set(re.findall(r"(\w+):\s*'fq-", m.group(1)))
        server = set(api._FQ_PARAMS)
        self.assertEqual(client - server, set(),
                         f"client facets the server will drop: {sorted(client - server)}")
        self.assertEqual(server - client, set(),
                         f"server facets no client control produces: {sorted(server - client)}")


class TestCapIsPerKind(_Base):
    def test_one_kind_cannot_crowd_out_another(self):
        store = {}
        for i in range(200):
            store[f"m{i}"] = {"id": f"m{i}", "name": f"m{i}", "kind": "metric",
                              "owner": "jakob", "visibility": "private"}
        api.save(api.QUERY_TEMPLATES_FILE, store)
        api._LOAD_CACHE.clear()
        st, _b = self._call(api.handle_query_template_create,
                            body={"name": "F", "kind": "fleet", "params": {"group": "p"}})
        self.assertEqual(st, 201, "a full metric store blocked a fleet query")
        st, b = self._call(api.handle_query_template_create,
                           body={"name": "M2", "kind": "metric", "params": {"metrics": ["mem"]}})
        self.assertEqual(st, 400, b)


class TestSharingModelIsInherited(_Base):
    def test_a_new_query_is_private_unless_shared(self):
        self._call(api.handle_query_template_create,
                   body={"name": "F", "kind": "fleet", "params": {"group": "prod"}})
        self.assertEqual(self._list("kind=fleet")[0]["visibility"], "private")

    def test_the_tenant_is_server_stamped(self):
        """The whole point of reusing this store: the two newer surfaces had no
        tenant model at all."""
        self._call(api.handle_query_template_create,
                   body={"name": "F", "kind": "fleet", "params": {"group": "prod"},
                         "tenant": "someone-elses"})
        self.assertNotEqual(self._list("kind=fleet")[0]["tenant"], "someone-elses")


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestClientMovedOffLocalStorage(unittest.TestCase):
    """The client half. A server store nothing calls is the dead end this
    release keeps finding."""

    @classmethod
    def setUpClass(cls):
        cls.app = (_ROOT / "server/html/static/js/app.js").read_text()

    def _fn(self, name):
        m = re.search(r"(?:async )?function " + re.escape(name) + r"\(.*?\n\}", self.app, re.S)
        self.assertIsNotNone(m, f"{name} not found")
        return m.group(0)

    def test_the_loader_reads_the_server(self):
        self.assertIn("/query/templates?kind=fleet", self._fn("loadFleetQuery"))

    def test_saving_posts_to_the_server(self):
        body = self._fn("saveFleetQuery")
        self.assertIn("'/query/templates'", body)
        self.assertIn("kind: 'fleet'", body)
        self.assertNotIn("localStorage", body)

    def test_nothing_still_writes_the_old_key(self):
        """Except the one-time migration, which only REMOVES it."""
        writes = re.findall(r"localStorage\.setItem\('rp_fleet_queries'", self.app)
        self.assertEqual(writes, [], "still persisting fleet queries to localStorage")

    def test_existing_local_queries_are_migrated(self):
        """Silently losing what an operator already saved is a worse first
        impression of the feature than not shipping it."""
        body = self._fn("_migrateLocalFleetQueries")
        self.assertIn("rp_fleet_queries", body)
        self.assertIn("removeItem", body)

    def test_the_local_key_is_only_cleared_once_everything_moved(self):
        body = self._fn("_migrateLocalFleetQueries")
        self.assertRegex(body, r"if \(moved === local\.filter")

    def test_an_edit_creates_before_it_deletes(self):
        """The store has no update endpoint, so an edit is re-save + delete.
        The reverse order can lose the query outright."""
        body = self._fn("_fqResave")
        post_at = body.index("api('POST'")
        del_at = body.index("api('DELETE'")
        self.assertLess(post_at, del_at, "delete precedes create — an edit can lose the query")

    def test_rename_survived_the_move(self):
        """It existed before this change; dropping it would be a regression
        dressed up as a feature."""
        self.assertIn("data-action=\"renameFleetQuery\"", self.app)
        self.assertIn("_fqResave", self._fn("renameFleetQuery"))

    def test_the_chip_id_is_non_numeric_by_construction(self):
        """The data-action dispatcher coerces `!isNaN(v) ? Number(v) : v`, and
        token_hex(8) can be all digits — an unprefixed id would arrive as a
        Number (or Infinity) and match nothing."""
        body = self._fn("_renderSavedQueries")
        self.assertIn("'q-' + q.id", body)
        self.assertIn("replace(/^q-/", self._fn("_fqById"))

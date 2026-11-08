#!/usr/bin/env python3
"""8.0.0: the AI executor's catalog lists the scripts an operator saved, and the approval row names the script.

The saved-script library is `{'scripts': [{id, name, description, body, ...}]}`, a wrapped list: that is what `handle_scripts_add` writes. Three readers took it for a dict keyed by
script id, which it has never been:

  * `_ai_exec_catalog` listed no saved script at all (only the built-in playbooks), though the guide says the executor picks from "your saved scripts";
  * `_ai_exec_resolve`, which re-reads the script when an approved proposal runs, could never find one;
  * `handle_confirmations_list` never put `script_name` on a row, so the second administrator who approves an MCP `run_saved_script` saw the action and no name.

The same slip had already cost the MCP `run_saved_script` tool its life at 7.0.2, and `_script_by_id` / `_visible_scripts` were written for it. The executor's three sites were not moved
onto them. The fixtures of tests/test_v613_ai_exec.py wrote the dict the readers expected, so every test was green. Here the library is filled by the real producer, and the tenant
filter the library's own list applies is part of the contract: reading the right shape would otherwise show one tenant's script names to every other tenant.

The last class enumerates the readers of the library by syntax tree and prints the ratio, because the rule was half applied: it fails on a reader that neither names the `scripts` key nor
asks the lookup helper.
"""
import ast
import hashlib
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v800aix-"))
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v800aix", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

BODY = "systemctl restart nginx"


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="rp-aix-"))
        self._saved = {n: getattr(api, n) for n in ("SCRIPTS_FILE", "DEVICES_FILE", "USERS_FILE", "CONFIG_FILE", "TENANTS_FILE", "CONFIRMATIONS_FILE")}
        for n in self._saved:
            # the basename is the storage key: keep the product's own file names
            setattr(api, n, self.d / self._saved[n].name)
        self._fns = {
            n: getattr(api, n)
            for n in (
                "respond",
                "method",
                "get_json_obj",
                "get_json_body",
                "audit_log",
                "log_command",
                "fire_webhook",
                "get_token_from_request",
                "verify_token",
                "_tenant_gate",
                "_tenancy_enforced",
                "_caller_is_superadmin",
            )
        }
        self._cap = {}

        def _respond(status, data=None, *a, **k):
            self._cap["status"], self._cap["data"] = status, data
            raise api.HTTPError(status, data)

        api.respond = _respond
        for n in ("audit_log", "log_command", "fire_webhook"):
            setattr(api, n, lambda *a, **k: None)
        api.get_token_from_request = lambda: "tok"
        api._LOAD_CACHE.clear()
        api.save(api.DEVICES_FILE, {"a1": {"name": "a", "tenant": "tenant-a"}, "b1": {"name": "b", "tenant": "tenant-b"}})
        api.save(api.USERS_FILE, {"aadmin": {"tenant_id": "tenant-a"}, "badmin": {"tenant_id": "tenant-b"}, "root": {}})
        api.save(api.CONFIG_FILE, {"tenancy_enforced": True})
        # keyed by tenant id: a tenant missing from this store resolves to 'default', which quietly makes the fixture's tenant admin a superadmin
        api.save(api.TENANTS_FILE, {"tenant-a": {"name": "A", "status": "active"}, "tenant-b": {"name": "B", "status": "active"}})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in list(self._saved.items()) + list(self._fns.items()):
            setattr(api, n, v)
        api._LOAD_CACHE.clear()

    def call(self, fn, *a):
        self._cap.clear()
        try:
            return 200, fn(*a)
        except api.HTTPError:
            return self._cap.get("status"), self._cap.get("data")

    def as_(self, tenant, user="root", role="admin"):
        api.verify_token = lambda _t=None: (user, role)
        api._tenant_gate = lambda: tenant
        api._tenancy_enforced = lambda: tenant is not None
        api._caller_is_superadmin = lambda: tenant is None

    def add(self, tenant=None, user="root", name="Restart nginx", body=BODY, description="bounce the proxy"):
        """The script goes in through the library's own handler, so the stored shape is the producer's."""
        self.as_(tenant, user)
        api.method = lambda: "POST"
        api.get_json_body = lambda: {"name": name, "description": description, "body": body}
        api.get_json_obj = api.get_json_body
        status, data = self.call(api.handle_scripts_add)
        self.assertEqual(status, 201, data)
        return data["script"]

    def catalog_ids(self, tenant=None, user="root"):
        self.as_(tenant, user)
        return [c["id"] for c in api._ai_exec_catalog()]


class TestTheCatalogListsSavedScripts(_Base):
    def test_a_script_saved_through_the_library_is_in_the_catalog(self):
        s = self.add()
        self.as_(None)
        row = next((c for c in api._ai_exec_catalog() if c["id"] == "script:" + s["id"]), None)
        self.assertIsNotNone(row, "the catalog holds no saved script: " + repr([c["id"] for c in api._ai_exec_catalog()]))
        self.assertEqual((row["kind"], row["label"], row["description"]), ("script", "Restart nginx", "bounce the proxy"))
        self.assertEqual(row["body_sha256"], hashlib.sha256(BODY.encode()).hexdigest())

    def test_the_route_answers_it_to_any_signed_in_user(self):
        s = self.add()
        self.as_(None, "vera", "viewer")
        api.method = lambda: "GET"
        status, data = self.call(api.handle_ai_exec_catalog)
        self.assertEqual(status, 200, data)
        self.assertIn("script:" + s["id"], [c["id"] for c in data["catalog"]])

    def test_the_built_in_playbooks_are_still_listed(self):
        self.add()
        self.as_(None)
        kinds = {c["kind"] for c in api._ai_exec_catalog()}
        self.assertEqual(kinds, {"script", "playbook"})

    def test_a_script_with_no_body_is_left_out(self):
        s = self.add()
        store = api.load(api.SCRIPTS_FILE)
        store["scripts"].append({"id": "empty01", "name": "Nothing", "description": "", "body": "   ", "created": 1, "tenant_gate": None})
        api.save(api.SCRIPTS_FILE, store)
        api._LOAD_CACHE.clear()
        ids = self.catalog_ids()
        self.assertIn("script:" + s["id"], ids)
        self.assertNotIn("script:empty01", ids)

    def test_no_more_than_the_cap_are_listed_and_the_oldest_come_first(self):
        first = self.add(name="one")
        self.add(name="two")
        self.add(name="three")
        saved = api._AI_EXEC_MAX_CATALOG
        api._AI_EXEC_MAX_CATALOG = 2
        try:
            ids = [i for i in self.catalog_ids() if i.startswith("script:")]
        finally:
            api._AI_EXEC_MAX_CATALOG = saved
        self.assertEqual(len(ids), 2)
        self.assertEqual(ids[0], "script:" + first["id"])


class TestTheResolverFindsTheScriptAtExecutionTime(_Base):
    def test_it_returns_the_command_and_the_hash_of_the_body(self):
        s = self.add()
        self.as_(None)
        self.assertEqual(api._ai_exec_resolve("script:" + s["id"]), ("exec:" + BODY, hashlib.sha256(BODY.encode()).hexdigest()))

    def test_an_edit_made_after_the_proposal_changes_the_hash_the_approval_was_checked_against(self):
        s = self.add()
        self.as_(None)
        before = api._ai_exec_resolve("script:" + s["id"])
        api.method = lambda: "PUT"
        api.get_json_body = lambda: {"body": "systemctl stop nginx"}
        status, data = self.call(api.handle_scripts_update, s["id"])
        self.assertEqual(status, 200, data)
        api._LOAD_CACHE.clear()
        after = api._ai_exec_resolve("script:" + s["id"])
        self.assertEqual(after[0], "exec:systemctl stop nginx")
        self.assertNotEqual(before[1], after[1])

    def test_a_deleted_script_resolves_to_nothing(self):
        s = self.add()
        self.as_(None)
        api.method = lambda: "DELETE"
        status, data = self.call(api.handle_scripts_delete, s["id"])
        self.assertEqual(status, 200, data)
        api._LOAD_CACHE.clear()
        self.assertEqual(api._ai_exec_resolve("script:" + s["id"]), (None, None))

    def test_an_unknown_id_and_a_playbook_behave_as_they_did(self):
        self.as_(None)
        self.assertEqual(api._ai_exec_resolve("script:nope"), (None, None))
        self.assertEqual(api._ai_exec_resolve("anything:else"), (None, None))
        key = next(k for k, pb in api._MITIGATE_PLAYBOOKS.items() if (pb or {}).get("fix"))
        self.assertIsNotNone(api._ai_exec_resolve("playbook:" + key)[0])


class TestOneTenantDoesNotSeeAnothersScripts(_Base):
    """Reading the right shape must not turn the catalog into a window on the other tenants' script names."""

    def test_the_catalog_is_the_callers_own_scripts(self):
        mine = self.add("tenant-a", "aadmin", name="mine")
        theirs = self.add("tenant-b", "badmin", name="theirs")
        ids = self.catalog_ids("tenant-a", "aadmin")
        self.assertIn("script:" + mine["id"], ids)
        self.assertNotIn("script:" + theirs["id"], ids, "a tenant was offered another tenant's script")

    def test_the_catalog_route_does_not_leak_a_name_or_a_hash(self):
        theirs = self.add("tenant-b", "badmin", name="payroll restore", body="curl -H 'Authorization: Bearer s3cr3t' https://internal/x")
        self.as_("tenant-a", "aadmin")
        api.method = lambda: "GET"
        status, data = self.call(api.handle_ai_exec_catalog)
        self.assertEqual(status, 200, data)
        text = repr(data)
        self.assertNotIn("payroll restore", text)
        self.assertNotIn(hashlib.sha256(b"curl -H 'Authorization: Bearer s3cr3t' https://internal/x").hexdigest(), text)
        self.assertNotIn(theirs["id"], text)

    def test_the_resolver_will_not_run_another_tenants_script(self):
        theirs = self.add("tenant-b", "badmin")
        self.as_("tenant-a", "aadmin")
        self.assertEqual(api._ai_exec_resolve("script:" + theirs["id"]), (None, None))

    def test_a_script_nobody_owns_is_shared_as_the_library_shares_it(self):
        store = {"scripts": [{"id": "old01", "name": "Old job", "description": "", "body": "uptime", "created": 1}]}  # no tenant stamp and no author
        api.save(api.SCRIPTS_FILE, store)
        api._LOAD_CACHE.clear()
        self.assertIn("script:old01", self.catalog_ids("tenant-a", "aadmin"))
        self.assertIn("script:old01", self.catalog_ids("tenant-b", "badmin"))

    def test_the_operator_sees_every_tenants_scripts(self):
        a = self.add("tenant-a", "aadmin", name="a")
        b = self.add("tenant-b", "badmin", name="b")
        ids = self.catalog_ids(None, "root")
        self.assertTrue({"script:" + a["id"], "script:" + b["id"]} <= set(ids))


class TestTheApprovalRowNamesTheScript(_Base):
    def test_a_saved_script_approval_carries_the_script_name(self):
        s = self.add(name="Restart nginx")
        self.as_(None)
        api._create_confirmation("run_saved_script", "a1", {"script_id": s["id"]}, "mcp", "claude", "restart it")
        api._LOAD_CACHE.clear()
        api.method = lambda: "GET"
        status, data = self.call(api.handle_confirmations_list)
        self.assertEqual(status, 200, data)
        rows = data["confirmations"]
        self.assertEqual([r.get("script_name") for r in rows], ["Restart nginx"], rows)

    def test_a_script_of_another_tenant_is_not_named_to_this_one(self):
        theirs = self.add("tenant-b", "badmin", name="payroll restore")
        self.as_(None)
        api._create_confirmation("run_saved_script", "a1", {"script_id": theirs["id"]}, "mcp", "claude", "x")
        api._LOAD_CACHE.clear()
        self.as_("tenant-a", "aadmin")
        api.method = lambda: "GET"
        status, data = self.call(api.handle_confirmations_list)
        self.assertEqual(status, 200, data)
        self.assertNotIn("payroll restore", repr(data))

    def test_a_confirmation_with_no_script_is_unchanged(self):
        self.as_(None)
        api._create_confirmation("reboot_device", "a1", {}, "mcp", "claude", "x")
        api._LOAD_CACHE.clear()
        api.method = lambda: "GET"
        _status, data = self.call(api.handle_confirmations_list)
        self.assertNotIn("script_name", data["confirmations"][0])


def _functions_naming_the_library():
    """(file, function) for every function in the server that reads the saved-script library, derived from the syntax tree: a reference to SCRIPTS_FILE, as a name or as A.SCRIPTS_FILE."""
    population = []
    for path in sorted(_CGI.glob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            named = any(
                (isinstance(n, ast.Name) and n.id == "SCRIPTS_FILE") or (isinstance(n, ast.Attribute) and n.attr == "SCRIPTS_FILE")
                for n in ast.walk(fn)
            )
            if named:
                population.append((path.name, fn))
    return population


def _knows_the_shape(fn):
    """It names the `scripts` key of the wrapped list, or asks the shared lookup. Compared as a whole string constant, so a docstring that mentions scripts does not count."""
    for n in ast.walk(fn):
        if isinstance(n, ast.Constant) and n.value == "scripts":
            return True
        if isinstance(n, ast.Call):
            callee = n.func.id if isinstance(n.func, ast.Name) else getattr(n.func, "attr", "")
            if callee in ("_script_by_id", "_visible_scripts"):
                return True
    return False


class TestEveryReaderOfTheLibraryKnowsItsShape(unittest.TestCase):
    def test_the_population_is_not_empty(self):
        names = [f"{p}:{fn.name}" for p, fn in _functions_naming_the_library()]
        self.assertGreater(len(names), 15, names)
        # control: readers that name the file directly are in the population, the two that were wrong among them (the resolver asks the lookup helper now and no longer names it)
        for expected in ("api.py:handle_scripts_list", "api.py:_ai_exec_catalog", "api.py:handle_confirmations_list", "api.py:_script_by_id"):
            self.assertIn(expected, names)

    def test_no_reader_takes_the_library_for_a_dict_keyed_by_id(self):
        population = _functions_naming_the_library()
        wrong = [f"{p}:{fn.name}" for p, fn in population if not _knows_the_shape(fn)]
        yes = len(population) - len(wrong)
        self.assertEqual(wrong, [], f"{yes} of {len(population)} readers of the saved-script library know it is `{{'scripts': [...]}}`; these do not: {wrong}")


def _function(source):
    return ast.parse(source).body[0]


class TestTheRatchetItselfCanSeeTheDefect(unittest.TestCase):
    """The population test above passes when nothing is wrong, so it needs a control that fails when it cannot see: the same predicate, fed the shapes it exists to tell apart."""

    def test_the_reading_that_shipped_is_flagged(self):
        fn = _function("def f():\n    scripts = load(SCRIPTS_FILE) or {}\n    for sid, s in list(scripts.items()):\n        pass\n")
        self.assertFalse(_knows_the_shape(fn))

    def test_a_lookup_by_id_on_the_store_is_flagged(self):
        fn = _function("def f(sid):\n    return (load(SCRIPTS_FILE) or {}).get(sid)\n")
        self.assertFalse(_knows_the_shape(fn))

    def test_a_docstring_that_mentions_the_scripts_does_not_count_as_knowing_the_key(self):
        fn = _function('def f(sid):\n    """Reads the saved scripts."""\n    return (load(SCRIPTS_FILE) or {}).get(sid)\n')
        self.assertFalse(_knows_the_shape(fn))

    def test_naming_the_wrapped_list_counts(self):
        self.assertTrue(_knows_the_shape(_function("def f():\n    return load(SCRIPTS_FILE).get('scripts', [])\n")))

    def test_asking_the_shared_lookup_counts_as_a_name_or_a_method(self):
        self.assertTrue(_knows_the_shape(_function("def f(sid):\n    return _script_by_id(sid)\n")))
        self.assertTrue(_knows_the_shape(_function("def f(rows):\n    return A._visible_scripts(rows)\n")))


if __name__ == "__main__":
    unittest.main()

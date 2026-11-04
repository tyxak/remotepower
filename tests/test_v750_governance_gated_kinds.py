#!/usr/bin/env python3
"""v7.5.0 (docs cross-check): narrowing the gated command kinds needs a fresh step-up, like switching change approval off.

`approval_gated_kinds` says which command kinds wait for a second approver. Saving it narrower than the gate in force switched the
four-eyes control off for reboot and shutdown, and the save answered 200 with no re-authentication, while
`change_approval_enabled: false` answered 403 step_up_required. The declarative import also listed the key as settable, and that
import runs under a plain admin check, so it was a second way round the same gate.

What this holds:

* A save that drops a kind which is gated now asks for the step-up and changes nothing.
* A save that posts the unchanged default (the stored value is empty until the first save), an empty list (the save turns it back
  into the default) or a wider list does not ask: a prompt that fires when nothing sensitive changed is one operators click through.
* With a fresh step-up the narrowing goes through and is stored.
* The declarative import cannot set the key, and does not export it.
"""

import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-gov-"))

_spec = importlib.util.spec_from_file_location("api_v750_gov", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Base(unittest.TestCase):

    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp(prefix="rp-v750-gov-cfg-"))
        self._cf = api.CONFIG_FILE
        api.CONFIG_FILE = self.d / "config.json"
        self.addCleanup(self._restore)
        api.save(api.CONFIG_FILE, {"change_approval_enabled": True})
        api._invalidate_load_cache(api.CONFIG_FILE)
        for name, value in (("verify_token", lambda token=None, *a, **k: ("root", "admin")),
                            ("get_token_from_request", lambda: "t"),
                            ("method", lambda: "POST")):
            p = mock.patch.object(api, name, value)
            p.start()
            self.addCleanup(p.stop)

    def _restore(self):
        api.CONFIG_FILE = self._cf
        api._invalidate_load_cache(api.CONFIG_FILE)

    def post(self, body):
        with mock.patch.object(api, "_read_valid", lambda model, *a, **k: dict(body)), \
                mock.patch.object(api, "get_json_obj", lambda: dict(body)):
            try:
                api.handle_config_save()
            except api.HTTPError as e:
                return e.status, e.body
        self.fail("handle_config_save answered nothing")

    def stored(self):
        api._invalidate_load_cache(api.CONFIG_FILE)
        return api.load(api.CONFIG_FILE) or {}


class TestNarrowingAsksForAStepUp(_Base):

    def test_the_control_group_is_a_population_worth_testing(self):
        """Control: the default set holds reboot and shutdown, so a narrowing to ['scan'] really drops them."""
        self.assertIn("reboot", api._APPROVAL_GATED_KINDS)
        self.assertIn("shutdown", api._APPROVAL_GATED_KINDS)

    def test_switching_the_control_off_asks(self):
        """Control on the gate itself: the neighbour key was always protected."""
        status, body = self.post({"change_approval_enabled": False})
        self.assertEqual((status, body.get("code")), (403, "step_up_required"))

    def test_narrowing_the_kinds_asks_and_changes_nothing(self):
        status, body = self.post({"approval_gated_kinds": ["scan"]})
        self.assertEqual((status, body.get("code")), (403, "step_up_required"))
        self.assertNotIn("approval_gated_kinds", self.stored())
        self.assertTrue(api._needs_approval("reboot"))
        self.assertTrue(api._needs_approval("shutdown"))

    def test_dropping_one_kind_from_a_stored_list_asks(self):
        api.save(api.CONFIG_FILE, {"change_approval_enabled": True, "approval_gated_kinds": ["reboot", "shutdown", "upgrade"]})
        api._invalidate_load_cache(api.CONFIG_FILE)
        status, body = self.post({"approval_gated_kinds": ["reboot", "shutdown"]})
        self.assertEqual((status, body.get("code")), (403, "step_up_required"))
        self.assertEqual(self.stored()["approval_gated_kinds"], ["reboot", "shutdown", "upgrade"])


class TestOtherSavesDoNotAsk(_Base):

    def test_the_unchanged_default_does_not_ask(self):
        status, _ = self.post({"approval_gated_kinds": list(api._APPROVAL_GATED_KINDS)})
        self.assertEqual(status, 200)

    def test_an_empty_list_becomes_the_default_and_does_not_ask(self):
        status, _ = self.post({"approval_gated_kinds": []})
        self.assertEqual(status, 200)
        self.assertEqual(self.stored()["approval_gated_kinds"], list(api._APPROVAL_GATED_KINDS))

    def test_a_wider_list_does_not_ask(self):
        extra = [k for k in api._APPROVAL_KINDS_ALL if k not in api._APPROVAL_GATED_KINDS]
        self.assertTrue(extra, "control: some offerable kind is not gated by default")
        status, _ = self.post({"approval_gated_kinds": list(api._APPROVAL_GATED_KINDS) + extra[:1]})
        self.assertEqual(status, 200)
        self.assertIn(extra[0], self.stored()["approval_gated_kinds"])

    def test_a_value_that_is_not_a_list_is_refused_by_the_save(self):
        status, _ = self.post({"approval_gated_kinds": "scan"})
        self.assertEqual(status, 400)


class TestWithAFreshStepUp(_Base):

    def test_the_narrowing_goes_through_and_is_stored(self):
        with mock.patch.object(api, "require_step_up", lambda: "root"):
            status, _ = self.post({"approval_gated_kinds": ["scan"]})
        self.assertEqual(status, 200)
        self.assertEqual(self.stored()["approval_gated_kinds"], ["scan"])


class TestTheDeclarativeImport(unittest.TestCase):

    def test_the_key_is_a_governance_key(self):
        self.assertIn("approval_gated_kinds", api._GOVERNANCE_CONFIG_KEYS)

    def test_the_import_cannot_set_it_and_the_export_does_not_carry_it(self):
        self.assertNotIn("approval_gated_kinds", api._declarative_settings_allowed())


if __name__ == "__main__":
    unittest.main()

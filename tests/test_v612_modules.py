"""v6.1.2 — optional modules (Settings → Advanced).

v6.0.0 declared tickets/billing/KB "standard, always-on" and deleted their
toggles (_tickets_enabled() was literally `return True`). That's wrong for a
small homelab, which shouldn't have to carry a helpdesk, an alert inbox, billing
and compliance it never opens. These are switchable again — and switching one
off is REAL: the module's whole API prefix 404s at the dispatcher, so the UI
isn't the enforcement boundary.

Defaults are chosen so an install that never touches a switch behaves exactly as
it does today: opt-OUT modules (alerts/tickets/compliance/pentest) default ON,
opt-IN ones (billing/kb) default OFF.
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v612-mod-"))
_spec = importlib.util.spec_from_file_location("api_v612_mod", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestModuleDefaults(unittest.TestCase):
    def setUp(self):
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()

    def test_untouched_install_keeps_todays_behaviour(self):
        state = api._modules_state()
        self.assertEqual(
            state,
            {
                "alerts": True,
                "tickets": True,
                "billing": False,
                "kb": False,
                "compliance": True,
                "pentest": True,
                # v6.2.0: the governed AI executor ships OFF. An install that
                # never opts in must have no AI-initiated action path at all.
                "ai_exec": False,
            },
        )

    def test_unknown_module_is_never_gated(self):
        self.assertTrue(api._module_on("something-that-does-not-exist"))

    def test_legacy_tickets_enabled_false_does_NOT_disable_tickets(self):
        """The upgrade hazard this design exists to avoid.

        Pre-v6.0.0, tickets were opt-IN and `tickets_enabled` defaulted to false,
        so any install whose admin saved Settings without ticking the box has
        `tickets_enabled: false` persisted. v6.0.0 then made tickets always-on
        and ignored the key — so those installs have been running a helpdesk ever
        since, with a stale `false` still sitting in their config.

        If the module switch reused that key, upgrading to v6.1.2 would silently
        delete a ticket system people actively use. It must be inert.
        """
        api.save(api.CONFIG_FILE, {"tickets_enabled": False})
        api._LOAD_CACHE.clear()
        self.assertTrue(
            api._module_on("tickets"),
            "a stale pre-v6.0.0 `tickets_enabled: false` must NOT disable tickets",
        )

    def test_the_module_switch_uses_a_fresh_key(self):
        self.assertEqual(api._MODULES["tickets"][0], "tickets_module_enabled")

    def test_tickets_helper_honours_the_switch_again(self):
        # It was hard-coded `return True` in v6.0.0.
        import tickets_handlers

        tickets_handlers.bind(vars(api))
        self.assertTrue(tickets_handlers._tickets_enabled())
        api.save(api.CONFIG_FILE, {"tickets_module_enabled": False})
        api._LOAD_CACHE.clear()
        self.assertFalse(tickets_handlers._tickets_enabled())


class TestModuleGateBlocksTheApi(unittest.TestCase):
    """The gate must run at the dispatcher chokepoint, not per-handler."""

    def setUp(self):
        api._LOAD_CACHE.clear()

    def _gate(self, path):
        """Return the status the module gate would raise, or None if it passes."""
        try:
            api._enforce_module_gate(path)
        except api.HTTPError as e:
            return e.status, e.body
        return None

    def test_enabled_module_passes(self):
        api.save(api.CONFIG_FILE, {"alerts_enabled": True})
        api._LOAD_CACHE.clear()
        self.assertIsNone(self._gate("/api/alerts"))

    def test_disabled_module_404s_its_whole_prefix(self):
        api.save(api.CONFIG_FILE, {"alerts_enabled": False})
        api._LOAD_CACHE.clear()
        for path in ("/api/alerts", "/api/alerts/123/ack", "/api/alert-mutes",
                     "/api/alert-tuning"):
            got = self._gate(path)
            self.assertIsNotNone(got, f"{path} must be gated")
            self.assertEqual(got[0], 404)
            self.assertEqual(got[1].get("module_disabled"), "alerts")

    def test_disabling_one_module_does_not_affect_others(self):
        api.save(api.CONFIG_FILE, {"alerts_enabled": False})
        api._LOAD_CACHE.clear()
        self.assertIsNone(self._gate("/api/devices"))
        self.assertIsNone(self._gate("/api/tickets"))

    def test_prefix_match_is_not_a_substring_match(self):
        # /api/alertsomething must NOT be captured by the /api/alerts prefix.
        api.save(api.CONFIG_FILE, {"alerts_enabled": False})
        api._LOAD_CACHE.clear()
        self.assertIsNone(self._gate("/api/alertsomething"))

    def test_non_api_paths_are_never_gated(self):
        api.save(api.CONFIG_FILE, {"alerts_enabled": False})
        api._LOAD_CACHE.clear()
        self.assertIsNone(self._gate("/index.html"))


class TestAlertsOffStopsInboxRowsOnly(unittest.TestCase):
    def setUp(self):
        api._LOAD_CACHE.clear()

    def test_record_alert_is_a_noop_when_the_module_is_off(self):
        api.save(api.CONFIG_FILE, {"alerts_enabled": False})
        api._LOAD_CACHE.clear()
        self.assertIsNone(api._record_alert("device_offline", {"device_id": "d1"}))

    def test_record_alert_works_when_on(self):
        api.save(api.CONFIG_FILE, {"alerts_enabled": True})
        api.save(api.ALERTS_FILE, [])
        api.save(api.ALERT_MUTES_FILE, {"mutes": []})
        api._LOAD_CACHE.clear()
        self.assertIsNotNone(api._record_alert("device_offline", {"device_id": "d1"}))


class TestModuleSwitchesPersist(unittest.TestCase):
    """The classic trap in this handler: a fixed key list that silently drops
    a new setting, so the toggle appears to work and reverts on reload."""

    def test_every_module_key_is_saved_from_the_registry(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn(
            "for _mname, (_mkey, _mdefault, _mprefixes) in _MODULES.items():\n"
            "        if _mkey in body:",
            src,
        )

    def test_frontend_defaults_mirror_the_server(self):
        # A mismatched default would silently switch an opt-out module OFF on
        # the operator's next Save (the checkbox would render unchecked).
        import re

        js = (_ROOT / "server/html/static/js/app.js").read_text()
        block = js[js.index("const MODULE_SETTINGS") :]
        block = block[: block.index("];")]
        found = dict(
            (m.group(1), m.group(2) == "true")
            for m in re.finditer(r"'[\w-]+',\s*'(\w+)',\s*(true|false)", block)
        )
        expected = {key: default for (key, default, _p) in api._MODULES.values()}
        self.assertEqual(found, expected)

    def test_every_module_has_a_settings_checkbox_and_a_nav_page(self):
        """Every module must be accounted for in BOTH frontend maps.

        v6.2.0: MODULE_PAGES may now map a module to `null` — the AI executor
        gates an API prefix but owns no page (its proposals land in the existing
        Confirmations queue, which must NOT be hidden when the executor is off,
        since MCP maker-checker uses the same queue). A page-less module is spelled
        out as `null` rather than omitted, so this parity check still catches a
        module someone forgot to wire up. The slice is sized from the block itself
        rather than a fixed 400 chars — a fixed source window silently stops
        covering the tail of the map the moment a comment is added to it.
        """
        html = (_ROOT / "server/html/index.html").read_text()
        js = (_ROOT / "server/html/static/js/app.js").read_text()
        block = js[js.index("const MODULE_PAGES") :]
        block = block[: block.index("};")]
        for name in api._MODULES:
            self.assertIn(f'id="cfg-mod-{name}"', html, f"{name} has no Settings toggle")
            self.assertIn(f"{name}:", block, f"{name} is missing from MODULE_PAGES")


if __name__ == "__main__":
    unittest.main()

"""v6.4.2: the three notification/integration surfaces that shipped API-only.

The server side of all three landed earlier in this cycle and round-trips
correctly; what was missing was any way to set them outside the API:

  (a) binding an integration instance to the host / site it runs on
  (b) a per-destination delivery ``scope_filter`` (+ ``tenants``)
  (c) additional ``email_routes``

Two classes are pinned here, because both fail silently and look fine:

  * The SERVER round trip — a value the UI posts must persist AND come back on
    read, or the control renders, accepts input, toasts "Saved" and forgets.
    Driven through the real ``handle_config_save`` / ``handle_config_get``.
  * The CLIENT compose — ``scope_filter`` is an OBJECT, and both existing
    read-back loops assign scalars (``d[f] = el.value``). Wiring the control
    straight to ``data-field="scope_filter"`` would store the string
    "[object Object]"; ``_clean_scope_filter`` returns None for a non-dict, so
    the filter would never apply and nothing would report an error.

Run: python3 -m pytest tests/test_v642_integration_ui.py -q
"""

import re
import unittest
from pathlib import Path

# Reuse the real save-handler harness (tmp CONFIG_FILE, drives the REAL
# handle_config_save, captures respond()).
import sys as _rp_sys, pathlib as _rp_pl  # noqa: E402
# This module imports a sibling from tests/. `unittest discover -s tests`
# puts that directory on sys.path for free, so the omission is invisible
# there — but `python3 -m unittest tests.<this>` does not, and the module
# then fails to import at all. Make it runnable on its own.
_rp_sys.path.insert(0, str(_rp_pl.Path(__file__).resolve().parent))
from test_v622_alert_params import _SaveBase, api, ROOT, _CGI

_APP = ROOT / "server/html/static/js/app.js"


class TestDestinationScopePersists(_SaveBase):
    """(b) A scoped shared destination must survive save → read."""

    def _dest(self, **kw):
        d = {"id": "wh_1", "name": "Tenant A Slack", "format": "slack",
             "url": "https://hooks.example.com/x", "enabled": True}
        d.update(kw)
        return d

    def test_scope_filter_and_tenants_persist(self):
        cfg = self._save({"webhook_urls": [self._dest(
            scope_filter={"type": "sites", "values": ["dc1", "hq"]},
            tenants=["t1"])]})
        dests = cfg.get("webhook_urls") or []
        self.assertTrue(dests, "destination did not persist at all")
        self.assertEqual(dests[0].get("scope_filter"),
                         {"type": "sites", "values": ["dc1", "hq"]})
        self.assertEqual(dests[0].get("tenants"), ["t1"])

    def test_all_clears_the_filter(self):
        """The UI sends {'type':'all'} to mean "stop scoping" — that must clear,
        not persist a filter that matches nothing."""
        cfg = self._save({"webhook_urls": [self._dest(
            scope_filter={"type": "tags", "values": ["prod"]})]})
        self.assertEqual((cfg["webhook_urls"][0].get("scope_filter") or {}).get("type"), "tags")
        cfg = self._save({"webhook_urls": [self._dest(scope_filter={"type": "all"})]})
        self.assertFalse(cfg["webhook_urls"][0].get("scope_filter"),
                         "an explicit all/empty scope must clear the filter")

    def test_unscoped_destination_is_unchanged(self):
        cfg = self._save({"webhook_urls": [self._dest()]})
        self.assertNotIn("scope_filter", cfg["webhook_urls"][0])


class TestEmailRoutesPersist(_SaveBase):
    """(c) email_routes is a whole-list replace on the server — so the client
    must never post it before its loader has populated the editor."""

    def test_routes_persist_with_scope(self):
        cfg = self._save({"email_routes": [
            {"name": "DC1 ops", "recipients": ["ops@example.com"],
             "scope_filter": {"type": "sites", "values": ["dc1"]}},
        ]})
        routes = cfg.get("email_routes") or []
        self.assertTrue(routes, "email_routes did not persist")
        self.assertEqual(routes[0].get("scope_filter"),
                         {"type": "sites", "values": ["dc1"]})

    def test_posting_an_empty_list_replaces_not_merges(self):
        """Pins WHY the client needs a loaded-guard: this is a destructive
        replace, so an unpopulated editor that saves would wipe API-set routes."""
        self._save({"email_routes": [{"name": "a", "recipients": ["a@example.com"]}]})
        cfg = self._save({"email_routes": []})
        self.assertEqual(cfg.get("email_routes") or [], [])

    def test_a_route_with_no_recipients_is_rejected(self):
        """The server 400s the whole save for a recipient-less route, so the
        client must drop half-filled rows rather than post them."""
        self._save({"email_routes": [{"name": "half typed", "recipients": []}]})
        self.assertEqual(self.cap.get("s"), 400)

    def test_smtp_scope_filter_persists(self):
        cfg = self._save({"smtp_scope_filter": {"type": "sites", "values": ["dc1"]}})
        self.assertEqual(cfg.get("smtp_scope_filter"),
                         {"type": "sites", "values": ["dc1"]})

    def test_smtp_scope_all_clears(self):
        self._save({"smtp_scope_filter": {"type": "tags", "values": ["prod"]}})
        cfg = self._save({"smtp_scope_filter": {"type": "all"}})
        self.assertFalse(cfg.get("smtp_scope_filter"))


class TestClientSendsOnlyWhatItLoaded(unittest.TestCase):
    """The destructive half of (c): saveSettings must not post `email_routes`
    or `smtp_scope_filter` before their loader ran."""

    @classmethod
    def setUpClass(cls):
        cls.app = _APP.read_text()
        m = re.search(r"async function saveSettings\(.*?\n\}", cls.app, re.S)
        assert m, "saveSettings not found"
        cls.save_src = m.group(0)

    def test_email_routes_is_gated_on_the_loaded_flag(self):
        self.assertRegex(self.save_src, r"_emailRoutesLoaded\s*&&")
        self.assertIn("payload.email_routes", self.save_src)

    def test_smtp_scope_is_gated_on_the_loaded_flag(self):
        self.assertIn("if (_smtpScopeLoaded)", self.save_src)
        self.assertIn("payload.smtp_scope_filter", self.save_src)

    def test_half_filled_routes_are_dropped_before_posting(self):
        """A blank row the operator added but never filled would 400 the whole
        Settings save if posted."""
        self.assertRegex(self.save_src, r"\.filter\(r =>.*recipients")

    def test_the_loaders_actually_set_the_flags(self):
        self.assertIn("_emailRoutesLoaded = true", self.app)
        self.assertIn("_smtpScopeLoaded = true", self.app)

    def test_the_editor_is_rendered_and_reachable(self):
        # A renderer nobody calls, or a data-action with no function, is the
        # documented "feature that can never fire" shape.
        self.assertIn("renderEmailRoutes();", self.app)
        self.assertIn("function addEmailRoute()", self.app)
        self.assertIn("async function removeEmailRoute(", self.app)
        html = (ROOT / "server/html/index.html").read_text()
        self.assertIn('id="email-routes"', html)
        self.assertIn('data-action="addEmailRoute"', html)


class TestClientWiring(unittest.TestCase):
    """Source pins for the two client-side classes that fail silently."""

    @classmethod
    def setUpClass(cls):
        cls.app = _APP.read_text()

    # -- (a) integration binding ----------------------------------------
    def test_integration_card_renders_the_binding_controls(self):
        self.assertIn("_integrationBindHtml(it, idx)", self.app,
                      "the binding block is defined but never rendered")
        m = re.search(r"function _integrationBindHtml\(.*?\n\}", self.app, re.S)
        self.assertIsNotNone(m, "_integrationBindHtml not found")
        block = m.group(0)
        self.assertIn('data-ifield="device_id"', block)
        self.assertIn('data-ifield="site"', block)

    def test_binding_survives_a_save_that_never_opened_the_card(self):
        """_readIntegrationCards only overwrites keys carrying data-ifield, so a
        binding set through the API is not wiped by pressing Save. Pin the loop
        shape that guarantees it."""
        m = re.search(r"function _readIntegrationCards\(\).*?\n\}", self.app, re.S)
        self.assertIsNotNone(m)
        self.assertIn("[data-ifield]", m.group(0))

    def test_binding_keeps_an_id_the_operator_cannot_see(self):
        """A device_id naming a host outside this operator's view must stay
        selectable, or Save silently unbinds it."""
        m = re.search(r"function _integrationBindHtml\(.*?\n\}", self.app, re.S)
        self.assertIn("not in your view", m.group(0))

    # -- (b) destination scope ------------------------------------------
    def test_dest_scope_block_is_rendered(self):
        self.assertIn("_destScopeHtml(d)", self.app,
                      "the scope block is defined but never rendered")

    def test_scope_filter_is_composed_as_an_object_not_a_scalar(self):
        m = re.search(r"function _readWebhookDestCard\(.*?\n\}", self.app, re.S)
        self.assertIsNotNone(m, "_readWebhookDestCard not found")
        block = m.group(0)
        # The transient form fields must be excluded from the generic
        # `d[f] = el.value` branch...
        self.assertIn("f === 'scope_type'", block)
        # ...and recomposed into the object shape the server understands.
        self.assertRegex(block, r"d\.scope_filter\s*=")
        self.assertIn("type: 'all'", block)

    def test_tenant_control_is_gated_on_tenancy(self):
        self.assertIn("_tenancyOn", self.app)
        # And the flag must be set before the destinations first render, or the
        # control can never appear.
        set_at = self.app.index("_tenancyOn = !!data.tenancy_enforced")
        render_at = self.app.index("  renderWebhookDests();")
        self.assertLess(set_at, render_at,
                        "_tenancyOn is set after renderWebhookDests — the tenant "
                        "control would never render on load")


class TestServerSideNeedsNoNewHandler(unittest.TestCase):
    """All three surfaces ride existing endpoints. api.py's inline handler count
    is ratcheted, so a new handler here would fail the build — pin the intent."""

    def test_integration_fields_carry_the_binding(self):
        src = (_CGI / "api.py").read_text()
        m = re.search(r"INTEGRATION_FIELDS = \((.*?)\)\n", src, re.S)
        self.assertIsNotNone(m)
        self.assertIn("'device_id'", m.group(1))
        self.assertIn("'site'", m.group(1))


if __name__ == "__main__":
    unittest.main(verbosity=2)

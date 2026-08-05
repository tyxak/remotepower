"""v6.4.2 — saved filter views work on more than the Devices page.

Named, per-account, URL-shareable filter views were implemented once and
hardcoded to Devices. The storage schema already carried a `page` field that
only ever held `'devices'`; every accessor filtered `v.page === 'devices'`; and
`_DEVICE_VIEW_CONTROLS` hardcoded the five Devices inputs. No other filtered
page (CVE, alerts, checks) could save or share its filter state, and the only
URL-addressable filter state in the whole SPA was `#devices?view=`.

An MSP operator wants "Critical CVEs, customer Acme, unpatched" as a saved lens
and wants to paste it into a ticket for the customer's own admin. Today they
re-set four filters by hand each visit, and the link they paste (`#cve`) opens
the unfiltered fleet-wide page. The schema, the per-account persistence, the
dropdown, the undo-on-delete and the `#page?view=` hash handler were ALL already
written for one page.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_JS = ROOT / "server" / "html" / "static" / "js"
_HTML = ROOT / "server" / "html" / "index.html"


class TestTheRegistry(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js = (_JS / "app.js").read_text()
        cls.html = _HTML.read_text()

    def _registry(self):
        i = self.js.index("const _VIEW_PAGES = {")
        return self.js[i:self.js.index("\n};", i)]

    def test_more_than_one_page_is_registered(self):
        reg = self._registry()
        for page in ("devices", "cve", "alerts", "checks"):
            with self.subTest(page=page):
                self.assertRegex(reg, r"\b%s:\s*\{" % page)

    def test_every_registered_control_id_exists(self):
        """A view that captures an id nothing renders silently saves nothing —
        the same shape as the finding, one level down."""
        missing = []
        for m in re.finditer(r"'([a-z0-9-]+)'\s*[,}]", self._registry()):
            cid = m.group(1)
            if "-" not in cid:
                continue           # a state key, not an element id
            if f'id="{cid}"' not in self.html:
                missing.append(cid)
        self.assertEqual(missing, [],
                         "registered control ids that do not exist: "
                         + ", ".join(missing))

    def test_the_hardcoded_devices_constant_is_gone(self):
        self.assertNotIn("_DEVICE_VIEW_CONTROLS", self.js)

    def test_no_accessor_still_hardcodes_devices(self):
        """Every one of the five accessors filtered `v.page === 'devices'`.

        Comments stripped first — the fix's own explanation quotes the old
        expression, and asserting on prose is how these pins go wrong."""
        code = re.sub(r"^\s*//.*$", "", self.js, flags=re.M)
        self.assertNotIn("v.page === 'devices'", code)
        self.assertNotIn("x.page === 'devices'", code)


class TestBackwardCompatibility(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js = (_JS / "app.js").read_text()

    def test_an_existing_view_with_no_page_still_matches(self):
        """A view saved before the field meant anything has page:'devices' or no
        page at all. Reading it strictly would make an operator's saved views
        vanish from the menu on upgrade."""
        self.assertGreaterEqual(self.js.count("(v.page || 'devices')")
                                + self.js.count("(x.page || 'devices')"), 3)

    def test_the_dispatch_names_are_unchanged(self):
        """The dropdown markup calls applyDeviceView / saveDeviceView /
        deleteDeviceView. Renaming them would be a dead click for anyone whose
        cached index.html predates the JS."""
        for fn in ("applyDeviceView", "saveDeviceView", "deleteDeviceView"):
            with self.subTest(fn=fn):
                self.assertRegex(self.js, r"function %s\s*\(" % fn)


class TestStateCapture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js = (_JS / "app.js").read_text()

    def _fn(self, name):
        body = self.js[self.js.index("function %s(" % name):]
        return body[:body.index("\n}\n")]

    def test_a_checkbox_is_captured_as_a_boolean(self):
        """`.value` on a checkbox yields the string "on", which restores as
        truthy on EVERY box — so a view would silently tick them all."""
        body = self._fn("_captureViewState")
        self.assertIn("el.checked", body)
        self.assertIn("type === 'checkbox'", body)

    def test_a_checkbox_is_restored_as_a_boolean(self):
        body = self._fn("_applyViewState")
        self.assertIn("el.checked = !!st[k]", body)

    def test_restoring_drives_the_controls_own_wiring(self):
        """Rather than naming a renderer per page — `renderCveTable` does not
        exist, the CVE table is tableCtl-managed, and an invented global dies
        silently in JS. Dispatching the control's own event re-filters the page
        and means a page added later needs no renderer lookup."""
        body = self._fn("_applyViewState")
        self.assertIn("dispatchEvent", body)
        self.assertIn("'input'", body)
        self.assertIn("'change'", body)


class TestTheDropdownIsPerPage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js = (_JS / "app.js").read_text()
        cls.html = _HTML.read_text()

    def test_every_registered_page_has_a_button(self):
        self.assertEqual(self.html.count('data-action="toggleViewsMenu"'), 4)
        self.assertEqual(self.html.count('class="views-dropdown hidden"'), 4)

    def test_the_lookup_is_scoped_to_the_active_page(self):
        """With more than one dropdown in the DOM, a bare
        getElementById('views-dropdown') opens the Devices one from the CVE
        page."""
        body = self.js[self.js.index("function _viewsDropdown"):]
        body = body[:body.index("\n}\n")]
        self.assertIn(".page.active .views-dropdown", body)

    def test_no_accessor_uses_the_bare_id_any_more(self):
        for fn in ("toggleViewsMenu", "renderViewsMenu"):
            with self.subTest(fn=fn):
                body = self.js[self.js.index("function %s(" % fn):]
                body = body[:body.index("\n}\n")]
                self.assertNotIn("getElementById('views-dropdown')", body)


class TestTheShareableLink(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js = (_JS / "app.js").read_text()

    def test_the_hash_handler_takes_any_registered_page(self):
        body = self.js[self.js.index("function _applyInitialViewHash"):]
        body = body[:body.index("\n}\n")]
        self.assertNotIn("#devices\\?view=", body,
                         "the deep link is still devices-only")
        self.assertIn("_VIEW_PAGES[m[1]]", body,
                      "an unregistered page in the hash must not navigate")

    def test_applying_writes_the_pages_own_hash(self):
        body = self.js[self.js.index("function applyDeviceView("):]
        body = body[:body.index("\n}\n")]
        self.assertIn("#${pg}?view=", body,
                      "a view saved on CVE would still write #devices?view=")


if __name__ == "__main__":
    unittest.main()

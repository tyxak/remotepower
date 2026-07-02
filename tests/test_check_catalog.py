"""v5.6.0 — Check catalog: systemd_unit check type + ready-made catalog.

"Custom checks" became a "Check catalog" of ~70 ready-made templates that
pre-fill the form, plus a new agent-side `systemd_unit` check (is a named unit
active?) so RemotePower's own services (wsgi/scheduler/api/satellite) and any
service are first-class. A host target is a device-search typeahead, and a
systemd_unit host check can also be added to the device's Services watch-list.
"""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-catalog-'))

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_spec = importlib.util.spec_from_file_location('api_catalog', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
_API_SRC = (_CGI / 'api.py').read_text()
_AGENT_SRC = (_ROOT / 'client' / 'remotepower-agent.py').read_text()
from clientjs import client_js
_APP_JS = client_js()   # checks-page JS moved to app-checks.js in the app.js split
_HTML = (_ROOT / 'server' / 'html' / 'index.html').read_text()


class TestSystemdUnitType(unittest.TestCase):
    def test_registered_as_agent_check(self):
        self.assertIn('systemd_unit', api.AGENT_CHECK_TYPES)
        self.assertIn('systemd_unit', api.CUSTOM_CHECK_TYPES)
        self.assertNotIn('systemd_unit', api.SERVER_CHECK_TYPES)

    def test_agent_evaluates_systemd_unit(self):
        # the agent branch runs `systemctl is-active <unit>` (list form, no shell)
        self.assertIn("ctype == 'systemd_unit'", _AGENT_SRC)
        self.assertIn("'systemctl', 'is-active'", _AGENT_SRC)

    def test_extensionless_agent_in_sync(self):
        ext = (_ROOT / 'client' / 'remotepower-agent').read_text()
        self.assertEqual(ext, _AGENT_SRC, 'remotepower-agent must match the .py')


class TestServicesWire(unittest.TestCase):
    def test_save_handler_wires_to_services_watchlist(self):
        seg = _API_SRC[_API_SRC.index('def handle_custom_checks_save'):
                       _API_SRC.index('def handle_custom_checks_delete')]
        self.assertIn("watch_service", seg)
        self.assertIn("services_watched", seg)
        # the device write must be its own lock, NOT nested in the CONFIG_FILE lock
        self.assertIn('_LockedUpdate(DEVICES_FILE)', seg)


class TestCatalogFrontend(unittest.TestCase):
    def test_catalog_and_helpers_exist(self):
        self.assertIn('const CHECK_CATALOG', _APP_JS)
        for fn in ('function ccCatalogSearch', 'function ccPickCatalog',
                   'function ccHostSearch', 'function pickCcHost'):
            self.assertIn(fn, _APP_JS)

    def test_remotepower_self_infra_in_catalog(self):
        for unit in ('remotepower-api.service', 'remotepower-wsgi.service',
                     'remotepower-scheduler.service', 'remotepower-satellite.service'):
            self.assertIn(unit, _APP_JS, f'catalog missing {unit}')

    def test_catalog_is_substantial(self):
        # ~70 entries — count the category-tagged objects
        self.assertGreaterEqual(_APP_JS.count("{ c: '"), 60)

    def test_modal_wired(self):
        self.assertIn('id="cc-catalog-search"', _HTML)   # searchable catalog combobox
        self.assertIn('id="cc-host-search"', _HTML)        # device search typeahead
        self.assertIn('id="cc-watch-svc"', _HTML)          # services-watch toggle
        self.assertIn('<option value="systemd_unit">', _HTML)
        self.assertIn('Check catalog', _HTML)              # renamed title/button


if __name__ == '__main__':
    unittest.main()

"""v5.8.0 (B3.4): configurable four-eyes approval gate. The gated command-kind
set is now tunable (default = the historical tuple); an admin can broaden it to
arbitrary-exec / compose / service / process or narrow it."""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location('api_appr', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestGatedKinds(unittest.TestCase):
    def test_default_is_historical_tuple(self):
        self.assertEqual(api._approval_gated_kinds({}), api._APPROVAL_GATED_KINDS)

    def test_config_overrides(self):
        cfg = {'approval_gated_kinds': ['exec', 'reboot']}
        self.assertEqual(set(api._approval_gated_kinds(cfg)), {'exec', 'reboot'})

    def test_invalid_kinds_filtered_out(self):
        cfg = {'approval_gated_kinds': ['exec', 'bogus', 'reboot']}
        self.assertEqual(set(api._approval_gated_kinds(cfg)), {'exec', 'reboot'})

    def test_non_list_falls_back_to_default(self):
        self.assertEqual(api._approval_gated_kinds({'approval_gated_kinds': 'exec'}),
                         api._APPROVAL_GATED_KINDS)

    def test_all_is_superset_of_default(self):
        self.assertTrue(set(api._APPROVAL_GATED_KINDS).issubset(set(api._APPROVAL_KINDS_ALL)))
        # the new gateable kinds are present
        for k in ('exec', 'compose', 'service', 'process', 'scan'):
            self.assertIn(k, api._APPROVAL_KINDS_ALL)


class TestNeedsApproval(unittest.TestCase):
    def test_disabled_never_gates(self):
        cfg = {'change_approval_enabled': False,
               'approval_gated_kinds': ['exec']}
        self.assertFalse(api._needs_approval('exec', cfg))

    def test_exec_gated_only_when_configured(self):
        # exec is NOT in the default set → not gated with default config
        self.assertFalse(api._needs_approval('exec', {'change_approval_enabled': True}))
        # ...but gated when the admin adds it
        cfg = {'change_approval_enabled': True, 'approval_gated_kinds': ['exec']}
        self.assertTrue(api._needs_approval('exec', cfg))

    def test_default_reboot_still_gated(self):
        self.assertTrue(api._needs_approval('reboot', {'change_approval_enabled': True}))

    def test_narrowing_removes_gate(self):
        # admin narrows to only 'exec' → reboot no longer gated
        cfg = {'change_approval_enabled': True, 'approval_gated_kinds': ['exec']}
        self.assertFalse(api._needs_approval('reboot', cfg))


class TestConfigSaveValidation(unittest.TestCase):
    def test_source_validates_subset(self):
        src = (_CGI / 'api.py').read_text()
        self.assertIn("if 'approval_gated_kinds' in body:", src)
        self.assertIn('k in _APPROVAL_KINDS_ALL', src)
        # empty list falls back to default (can't silently disable the gate)
        self.assertIn('list(_APPROVAL_GATED_KINDS)', src)

    def test_safe_config_surfaces_both(self):
        src = (_CGI / 'api.py').read_text()
        self.assertIn("safe['approval_kinds_all']", src)
        self.assertIn("safe.setdefault('approval_gated_kinds'", src)


class TestFrontend(unittest.TestCase):
    def test_ui_renders_and_saves_kinds(self):
        js = (_ROOT / 'server/html/static/js/app.js').read_text()
        self.assertIn('cfg-approval-kind', js)
        self.assertIn('payload.approval_gated_kinds', js)
        html = (_ROOT / 'server/html/index.html').read_text()
        self.assertIn('cfg-approval-kinds', html)


if __name__ == '__main__':
    unittest.main()

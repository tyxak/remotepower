"""v5.8.0 batch-1 quick wins: alert mitigation tagging (B1.2), broadened
maintenance suppression (B1.4), and PIN-hashing at rest (B3.1)."""
import hashlib
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

_spec = importlib.util.spec_from_file_location('api_qw', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestAlertMitigationTagging(unittest.TestCase):
    """B1.2: _annotate_alert_mitigation tags open alerts whose event maps to a
    remediation playbook and that name a device."""

    def _tag(self, alerts):
        api._annotate_alert_mitigation(alerts)
        return alerts

    def test_maps_event_to_playbook_kind(self):
        a = {'id': '1', 'event': 'reboot_required', 'device_id': 'd1',
             'device_name': 'web1', 'payload': {}}
        self._tag([a])
        self.assertEqual(a['mitigation_kind'], 'reboot')

    def test_service_down_carries_unit_target(self):
        a = {'id': '2', 'event': 'service_down', 'device_id': 'd1',
             'payload': {'unit': 'nginx'}}
        self._tag([a])
        self.assertEqual(a['mitigation_kind'], 'service_down')
        self.assertEqual(a['mitigation_target'], 'nginx')

    def test_metric_alert_resolves_by_metric_field(self):
        a = {'id': '3', 'event': 'metric_critical', 'device_id': 'd1',
             'payload': {'metric': 'memory'}}
        self._tag([a])
        self.assertEqual(a['mitigation_kind'], 'memory')

    def test_no_device_no_tag(self):
        a = {'id': '4', 'event': 'reboot_required', 'payload': {}}
        self._tag([a])
        self.assertNotIn('mitigation_kind', a)

    def test_resolved_alert_not_tagged(self):
        a = {'id': '5', 'event': 'reboot_required', 'device_id': 'd1',
             'resolved_at': 123, 'payload': {}}
        self._tag([a])
        self.assertNotIn('mitigation_kind', a)

    def test_unmapped_event_not_tagged(self):
        a = {'id': '6', 'event': 'github_new_issue', 'device_id': 'd1',
             'payload': {}}
        self._tag([a])
        self.assertNotIn('mitigation_kind', a)

    def test_every_mapped_kind_is_a_real_playbook(self):
        pb = set(api._MITIGATE_PLAYBOOKS)
        for k in set(api._EVENT_TO_MITIGATION.values()) | set(api._METRIC_TO_MITIGATION.values()):
            self.assertIn(k, pb, k)


class TestSuppressibleBroadened(unittest.TestCase):
    """B1.4: the maintenance-window suppression set now covers patch/maintenance
    churn without dropping the original members."""

    def test_originals_retained(self):
        for ev in ('device_offline', 'service_down', 'patch_alert', 'log_alert'):
            self.assertIn(ev, api.SUPPRESSIBLE_EVENTS)

    def test_new_members_present(self):
        for ev in ('metric_warning', 'config_drift', 'failed_unit',
                   'reboot_required', 'container_stopped', 'backup_stale'):
            self.assertIn(ev, api.SUPPRESSIBLE_EVENTS)


class TestPinHashing(unittest.TestCase):
    """B3.1: enrollment PINs are stored hashed, never plaintext."""

    def _sha(self, s):
        return hashlib.sha256(s.encode()).hexdigest()

    def test_hash_helper_is_sha256(self):
        # PINs reuse _hash_device_token; pin the mechanism so a change is noticed.
        self.assertEqual(api._hash_device_token('123456'), self._sha('123456'))

    def test_stored_key_is_hashed_not_plaintext(self):
        api.save(api.PINS_FILE, {})
        # Simulate the create path: store keyed by hash.
        pin = '424242'
        pins = api.load(api.PINS_FILE)
        pins[api._hash_device_token(pin)] = {'created': int(__import__('time').time())}
        api.save(api.PINS_FILE, pins)
        raw = api.load(api.PINS_FILE)
        self.assertIn(self._sha(pin), raw)
        self.assertNotIn(pin, raw)              # no 6-digit plaintext key

    def test_source_uses_hash_on_both_paths(self):
        src = (_CGI / 'api.py').read_text()
        self.assertIn("pins[_hash_device_token(pin)] = {'created': now}", src)
        self.assertIn('pin_hash = _hash_device_token(pin)', src)
        # legacy plaintext-keyed entries still accepted on verify (upgrade grace)
        self.assertIn('if not entry and pin in pins:', src)


class TestFrontendWiring(unittest.TestCase):
    def test_alerts_page_has_fix_button(self):
        js = (_ROOT / 'server/html/static/js/app-alerts.js').read_text()
        self.assertIn("data-action=\"mitigateAlert\"", js)
        self.assertIn('function mitigateAlert(', js)
        self.assertIn('openMitigateModal(', js)

    def test_devices_empty_state_ctas(self):
        js = (_ROOT / 'server/html/static/js/app.js').read_text()
        self.assertIn('Add your first device', js)
        self.assertIn('data-action="openEnrollModal"', js)
        self.assertIn('function clearDeviceFilters(', js)


if __name__ == '__main__':
    unittest.main()

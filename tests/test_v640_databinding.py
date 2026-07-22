"""v6.4.0 data-binding sweep: agent-collected data now reaches RAG + alerts.

- build_hardware_corpus surfaces SMART/kernel/UPS/GPU/accounts to the AI (the
  whole HARDWARE_FILE was previously AI-blind).
- macOS endpoint posture reaches the alert path at Windows parity (a disabled
  FileVault/Gatekeeper/SIP/firewall previously paged nobody).
"""
import os
import importlib.machinery
import importlib.util
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
_CGI = Path(__file__).parent.parent / 'server' / 'cgi-bin'
import sys
sys.path.insert(0, str(_CGI))
import rag_index  # noqa: E402

_ldr = importlib.machinery.SourceFileLoader('api', str(_CGI / 'api.py'))
_spec = importlib.util.spec_from_loader('api', _ldr)
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestHardwareCorpus(unittest.TestCase):
    STORE = {
        'd1': {
            'collected_at': 100,
            '_smart_failed': True, '_smart_failed_devs': ['/dev/sda'],
            'smart': [{'disk': '/dev/sda', 'wear_pct': 92, 'temperature_c': 51,
                       'reallocated': 8}],
            'kernel': {'reboot_for_kernel': True, 'running': '6.1.0',
                       'latest_installed': '6.1.9'},
            'ups': {'state': 'onbattery', 'battery_pct': 40, 'runtime_s': 300},
            'gpus': [{'model': 'RTX', 'util': 30, 'temp_c': 60}],
            '_temp_high': True,
            '_priv_users': ['root', 'deploy'],
        },
        'd2': {'collected_at': 100},   # nothing notable -> no chunk
    }

    def test_emits_per_device_hardware_chunk(self):
        docs = rag_index.build_hardware_corpus(
            self.STORE, devices={'d1': {'name': 'web01'}}, now=1)
        by = {d['id']: d for d in docs}
        self.assertIn('live/d1#hardware', by)
        txt = by['live/d1#hardware']['text']
        self.assertIn('SMART: FAILING', txt)
        self.assertIn('wear 92%', txt)
        self.assertIn('reboot needed', txt)
        self.assertIn('UPS', txt)
        self.assertIn('privileged', txt)
        self.assertEqual(by['live/d1#hardware']['device'], 'd1')
        # a device with no notable hardware signal produces no chunk
        self.assertNotIn('live/d2#hardware', by)

    def test_malformed_safe(self):
        self.assertEqual(rag_index.build_hardware_corpus(None), [])
        self.assertEqual(rag_index.build_hardware_corpus({'d': 42}), [])


class TestMacPostureAlerts(unittest.TestCase):
    DEV = 'dev-mac-1'

    def setUp(self):
        self.fired = []
        self._fw = api.fire_webhook
        api.fire_webhook = lambda ev, payload=None: self.fired.append((ev, payload))

    def tearDown(self):
        api.fire_webhook = self._fw

    def _ingest(self, mac_posture):
        api.save(api.DEVICES_FILE, {self.DEV: {'name': 'mac1',
                 'sysinfo': {'mac_posture': mac_posture}}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        self.fired.clear()
        api._ingest_posture_v3110(self.DEV, 'mac1',
                                  {'mac_posture': mac_posture})
        return [e for e, _ in self.fired]

    def test_filevault_off_fires_on_first_contact(self):
        events = self._ingest({'filevault': False, 'gatekeeper': True,
                               'sip': True, 'firewall': True})
        self.assertIn('mac_filevault_off', events)
        # a healthy posture on first contact fires nothing
        events2 = self._ingest({'filevault': True, 'gatekeeper': True,
                                'sip': True, 'firewall': True})
        self.assertNotIn('mac_filevault_off', events2)

    def test_absent_field_never_fires(self):
        # tri-state: the mac agent omits a field it can't determine — absence
        # must never fire (only an explicit False is "bad").
        events = self._ingest({'filevault': True})   # gatekeeper/sip/firewall absent
        self.assertEqual([e for e in events if e.startswith('mac_')], [])

    def test_events_registered(self):
        for ev in ('mac_filevault_off', 'mac_firewall_off', 'mac_gatekeeper_off',
                   'mac_sip_disabled', 'mac_filevault_on', 'mac_sip_enabled'):
            self.assertIn(ev, api.EVENT_REGISTRY, ev)


if __name__ == '__main__':
    unittest.main()

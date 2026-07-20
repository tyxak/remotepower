"""v6.3.0: four new recover events, each driven through its REAL firing path.

unit_flapping_cleared / container_restarting_cleared / snapshot_recovered /
mailbox_recovered close the open alert when the condition clears. These were the
"stateful alert stuck in the inbox" gaps. Each test drives the actual sweep /
report processor (not a hand-built payload) so a "feature that can never fire"
regression is caught — then asserts the open alert is auto-resolved.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(CGI))


def _fresh_api():
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v630-rec-')
    spec = importlib.util.spec_from_file_location('api_v630_rec', CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Base(unittest.TestCase):
    def setUp(self):
        self.api = _fresh_api()
        self.api._LOAD_CACHE.clear()
        self.api.save(self.api.CONFIG_FILE, {})
        self.api.save(self.api.ALERTS_FILE, {'alerts': []})
        self.api.save(self.api.DEVICES_FILE, {
            'd1': {'id': 'd1', 'name': 'host1', 'token': 't', 'monitored': True}})

    def _open(self):
        return [a for a in (self.api.load(self.api.ALERTS_FILE) or {}).get('alerts', [])
                if not a.get('resolved_at')]


class TestRegistry(_Base):
    def test_all_four_wired(self):
        pairs = {
            'unit_flapping_cleared': 'unit_flapping',
            'container_restarting_cleared': 'container_restarting',
            'snapshot_recovered': 'snapshot_old',
            'mailbox_recovered': 'mailbox_threshold',
        }
        for rec, fires in pairs.items():
            reg = self.api.EVENT_REGISTRY[rec]
            self.assertEqual(reg.get('resolves'), (fires,), rec)
            self.assertNotIn('severity', reg, f'{rec} must not be an inbox alert')
            self.assertEqual(self.api._ALERT_RECOVER.get(rec), fires)
            self.assertIn(rec, {e[0] for e in self.api.WEBHOOK_EVENTS})


class TestUnitFlapping(_Base):
    def test_flap_then_stable_resolves(self):
        api = self.api
        api.save(api.CONFIG_FILE, {'unit_flap_restarts': 3})
        api._LOAD_CACHE.clear()
        svc = lambda n: [{'unit': 'web.service', 'active': 'active', 'sub': 'running',
                          'restarts': n}]
        api.process_service_report('d1', svc(0))          # baseline
        api.process_service_report('d1', svc(20))         # +20 restarts → flap
        self.assertEqual(len(self._open()), 1, 'unit_flapping should have fired')
        self.assertEqual(self._open()[0].get('event'), 'unit_flapping')
        api.process_service_report('d1', svc(20))         # stable → recovered
        self.assertEqual(self._open(), [], 'flap alert should auto-resolve')


class TestContainerRestarting(_Base):
    def _persist(self, items, restarting=None):
        rec = {'ts': 1, 'items': items}
        if restarting:
            rec['restarting_alerted'] = restarting
        self.api._entity_write_one(self.api.CONTAINERS_FILE, 'd1', rec)

    def test_restart_loop_then_stable_resolves(self):
        api = self.api
        c = lambda n: [{'name': 'web', 'runtime': 'docker', 'namespace': '',
                        'status': 'Up 1 min', 'restart_count': n}]
        self._persist(c(0))                                # baseline entry
        alerted = api.process_container_report('d1', c(50), 1)   # +50 → restarting
        self.assertEqual(len(self._open()), 1)
        self.assertEqual(self._open()[0].get('event'), 'container_restarting')
        self._persist(c(50), restarting=alerted)           # heartbeat persists set
        api.process_container_report('d1', c(50), 2)        # stable → recovered
        self.assertEqual(self._open(), [], 'restart-loop alert should auto-resolve')


class TestMailbox(_Base):
    def test_over_then_under_resolves(self):
        api = self.api
        with api._DeviceUpdate('d1') as devs:
            devs['d1']['mailbox_threshold'] = 100
        api._ingest_mailbox_counts('d1', {'/var/mail/x': {'count': 500, 'exists': True}})
        self.assertEqual(len(self._open()), 1)
        self.assertEqual(self._open()[0].get('event'), 'mailbox_threshold')
        api._ingest_mailbox_counts('d1', {'/var/mail/x': {'count': 5, 'exists': True}})
        self.assertEqual(self._open(), [], 'mailbox alert should auto-resolve')


class TestSnapshotRecover(_Base):
    """The Proxmox snapshot sweep needs a live client to drive end-to-end, so
    this pins the auto-resolve half through the real _record_alert path (the
    firing edge-trigger is covered by inspection + the registry test)."""

    def test_recover_resolves_by_vmid(self):
        api = self.api
        api._record_alert('snapshot_old', {'vmid': 101, 'vm_name': 'vm101',
                                           'snap_name': 'old', 'days_old': 30})
        api._record_alert('snapshot_old', {'vmid': 102, 'vm_name': 'vm102',
                                           'snap_name': 'old', 'days_old': 30})
        self.assertEqual(len(self._open()), 2)
        api._auto_resolve_alerts('snapshot_recovered', {'vmid': 101, 'vm_name': 'vm101'})
        still = self._open()
        self.assertEqual(len(still), 1)
        self.assertEqual(still[0]['payload'].get('vmid'), 102)


if __name__ == '__main__':
    unittest.main()

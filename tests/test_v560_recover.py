"""v5.6.0 — alert-lifecycle: container_recovered / backup_recovered.

Two state events that fired an alert but never auto-resolved (so a restarted
container or a fresh backup left the alert open forever) now have recover events.
Per the CLAUDE.md webhook rule, the regression MUST build the open alert via the
real _record_alert path (the whitelist stores the match key) — a hand-built
{'payload': {...}} dict would false-green.
"""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-recover-'))

_CGI = Path(__file__).parent.parent / 'server' / 'cgi-bin'
_spec = importlib.util.spec_from_file_location('api_recover', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestRecoverEvents(unittest.TestCase):
    def setUp(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'host1', 'monitored': True}})
        api.save(api.ALERTS_FILE, {'alerts': []})

    def _open(self):
        return [a for a in (api.load(api.ALERTS_FILE) or {}).get('alerts', [])
                if not a.get('resolved_at')]

    def test_registered(self):
        names = {e[0] for e in api.WEBHOOK_EVENTS}
        self.assertIn('container_recovered', names)
        self.assertIn('backup_recovered', names)
        self.assertEqual(api._ALERT_RECOVER['container_recovered'], 'container_stopped')
        self.assertEqual(api._ALERT_RECOVER['backup_recovered'], 'backup_stale')

    def test_container_recovered_resolves_by_name(self):
        api._record_alert('container_stopped', {'device_id': 'd1', 'name': 'host1', 'container': 'web1'})
        api._record_alert('container_stopped', {'device_id': 'd1', 'name': 'host1', 'container': 'db1'})
        self.assertEqual(len(self._open()), 2)
        self.assertEqual(self._open()[0]['payload'].get('container'), 'web1')
        # recovering web1 resolves ONLY web1 (db1 on the same host stays open)
        api._auto_resolve_alerts('container_recovered', {'device_id': 'd1', 'container': 'web1'})
        still = self._open()
        self.assertEqual(len(still), 1)
        self.assertEqual(still[0]['payload'].get('container'), 'db1')

    def test_backup_recovered_resolves_by_path(self):
        api._record_alert('backup_stale', {'device_id': 'd1', 'name': 'host1',
                                           'path': '/mnt/a', 'label': 'A', 'age_hours': 50})
        api._record_alert('backup_stale', {'device_id': 'd1', 'name': 'host1',
                                           'path': '/mnt/b', 'label': 'B', 'age_hours': 99})
        self.assertEqual(len(self._open()), 2)
        # a fresh /mnt/a resolves only its alert, not /mnt/b
        api._auto_resolve_alerts('backup_recovered', {'device_id': 'd1', 'path': '/mnt/a'})
        still = self._open()
        self.assertEqual(len(still), 1)
        self.assertEqual(still[0]['payload'].get('path'), '/mnt/b')

    def test_recover_does_not_create_its_own_alert(self):
        # recover events must not themselves land in the inbox
        api._record_alert('container_recovered', {'device_id': 'd1', 'container': 'web1'})
        api._record_alert('backup_recovered', {'device_id': 'd1', 'path': '/mnt/a'})
        self.assertEqual(len(self._open()), 0)


if __name__ == '__main__':
    unittest.main()

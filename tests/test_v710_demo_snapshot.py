#!/usr/bin/env python3
"""v7.1.0: the public demo answers live platform reads from canned data.

The demo's integrations point at hosts that do not exist, so the
Virtualization guest list and the DNS blockers' status answered 502 on every
visit. The seeder now gives those records a `demo_snapshot` keyed by driver
operation. The snapshot must be:

  * honoured in read-only demo mode for a GET, through the real dispatchers;
  * ignored on a normal install, even if a record somehow carries one;
  * ignored for a write, so a demo never pretends a power action happened;
  * never sent to the browser with the integration record.
"""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / 'server' / 'cgi-bin'
_SEEDER = ROOT / 'packaging' / 'seed-demo-data.py'


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestDemoSnapshot(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v710demo-')
        cls.api = _load('api_v710demo', _CGI / 'api.py')
        if not _SEEDER.exists():
            raise unittest.SkipTest('seeder excluded from this tree')
        cls.seed = _load('seed_v710demo', _SEEDER)

    def setUp(self):
        self._env = {k: os.environ.get(k) for k in ('RP_READ_ONLY', 'REQUEST_METHOD')}

    def tearDown(self):
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def _inst(self, typ):
        found = [i for i in self.seed._DEMO_INTEGRATIONS if i['type'] == typ]
        self.assertTrue(found, f'the demo seeds no {typ} integration')
        return found[0]

    def test_seeder_attaches_snapshots(self):
        vc = self._inst('vcenter')
        vms = vc['demo_snapshot']['list_vms']
        self.assertGreaterEqual(len(vms), 10)
        for vm in vms:
            self.assertEqual(set(vm), {'id', 'name', 'status', 'cpu', 'mem_mb', 'host'},
                             'not the shape vsphere_list_vms returns')
        for typ in ('pihole', 'adguard'):
            if any(i['type'] == typ for i in self.seed._DEMO_INTEGRATIONS):
                self.assertIn('status', self._inst(typ)['demo_snapshot'])

    def test_read_only_get_is_answered_from_the_snapshot(self):
        os.environ['RP_READ_ONLY'] = '1'
        os.environ['REQUEST_METHOD'] = 'GET'
        vc = self._inst('vcenter')
        self.assertEqual(self.api._virt_dispatch(vc, 'list_vms'), vc['demo_snapshot']['list_vms'])

    def test_a_normal_install_never_uses_it(self):
        os.environ.pop('RP_READ_ONLY', None)
        os.environ['REQUEST_METHOD'] = 'GET'
        self.assertIsNone(self.api._demo_snapshot(self._inst('vcenter'), 'list_vms'))

    def test_a_write_is_never_faked(self):
        os.environ['RP_READ_ONLY'] = '1'
        os.environ['REQUEST_METHOD'] = 'POST'
        vc = dict(self._inst('vcenter'))
        vc['demo_snapshot'] = dict(vc['demo_snapshot'], power={'ok': True})
        self.assertIsNone(self.api._demo_snapshot(vc, 'power'))

    def test_snapshot_is_not_sent_to_the_browser(self):
        safe = self.api._redact_integration(self._inst('vcenter'), admin=True)
        self.assertNotIn('demo_snapshot', safe)


if __name__ == '__main__':
    unittest.main()

"""v5.8.0 (B1.3): staged auto-patch (patch rings). A policy with `rings` spawns
a health-gated rollout (reusing the rollout engine) instead of a flat fan-out;
a policy without rings behaves exactly as before.
"""
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

_spec = importlib.util.spec_from_file_location('api_pr', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Base(unittest.TestCase):
    def setUp(self):
        api.save(api.DEVICES_FILE, {
            'd1': {'name': 'canary1', 'tags': ['canary'], 'group': 'web'},
            'd2': {'name': 'web1', 'tags': [], 'group': 'web'},
            'd3': {'name': 'web2', 'tags': [], 'group': 'web'},
        })
        api.save(api.ROLLOUTS_FILE, {'rollouts': []})
        api.save(api.CMDS_FILE, {})

    def _rolls(self):
        return (api.load(api.ROLLOUTS_FILE) or {}).get('rollouts') or []


class TestRingValidation(_Base):
    def test_clean_rings_filters_bad(self):
        rings = api._autopatch_clean_rings([
            {'name': 'canary', 'selector': {'type': 'tag', 'value': 'canary'}},
            {'selector': {'type': 'bogus'}},               # dropped
            {'name': 'rest', 'selector': {'type': 'group', 'value': 'web'}},
        ])
        self.assertEqual([r['name'] for r in rings], ['canary', 'rest'])

    def test_health_gate_defaults(self):
        g = api._autopatch_clean_health_gate({'enabled': True, 'threshold': 500})
        self.assertTrue(g['enabled'])
        self.assertEqual(g['threshold'], 100)      # clamped


class TestSpawn(_Base):
    def _policy(self, **kw):
        pol = {'id': 'pol1', 'name': 'Sunday patch',
               'rings': [
                   {'name': 'canary', 'selector': {'type': 'tag', 'value': 'canary'}},
                   {'name': 'rest', 'selector': {'type': 'group', 'value': 'web'}},
               ],
               'auto_promote': True, 'reboot': False,
               'health_gate': {'enabled': True, 'threshold': 70},
               'verify_minutes': 15}
        pol.update(kw)
        return pol

    def test_staged_policy_spawns_rollout(self):
        n = api._autopatch_queue(self._policy(), 'tester')
        rolls = self._rolls()
        self.assertEqual(len(rolls), 1)
        r = rolls[0]
        self.assertEqual(r['action'], 'upgrade')
        self.assertEqual(r['state'], 'running')
        self.assertEqual(r['_autopatch_id'], 'pol1')
        self.assertEqual([ring['name'] for ring in r['rings']], ['canary', 'rest'])
        self.assertTrue(r['health_gate']['enabled'])
        self.assertEqual(n, 3)                    # canary(d1) + web(d1,d2,d3) deduped

    def test_reboot_flag_propagates(self):
        api._autopatch_queue(self._policy(reboot=True), 'tester')
        self.assertTrue(self._rolls()[0]['reboot'])

    def test_no_duplicate_rollout_while_active(self):
        api._autopatch_queue(self._policy(), 'tester')
        api._autopatch_queue(self._policy(), 'tester')   # cron fires again
        self.assertEqual(len(self._rolls()), 1)          # still one

    def test_flat_policy_does_not_spawn(self):
        # No rings → legacy batch path, no rollout created.
        api.save(api.CMDS_FILE, {})
        pol = {'id': 'flat', 'name': 'flat', 'target': {'type': 'all', 'value': ''},
               'reboot': False}
        api._autopatch_queue(pol, 'tester')
        self.assertEqual(self._rolls(), [])
        cmds = api.load(api.CMDS_FILE)
        self.assertTrue(any(cmds.get(d) for d in ('d1', 'd2', 'd3')))


class TestRebootDispatch(_Base):
    def test_upgrade_ring_uses_reboot_cmd_when_flagged(self):
        # Drive one ring dispatch and confirm the reboot command is queued.
        # v6.1.3: the ACTUAL per-device command now lives in cmds[dev_id] (the
        # dispatch is OS-aware — a Linux host, which d1 is by default, gets the
        # bash upgrade+reboot); `queued` is only a representative log label.
        api._autopatch_queue({
            'id': 'p', 'name': 'p', 'reboot': True, 'auto_promote': False,
            'rings': [{'name': 'r1', 'selector': {'type': 'tag', 'value': 'canary'}}],
            'health_gate': {'enabled': False, 'threshold': 70}, 'verify_minutes': 15,
        }, 'tester')
        roll = self._rolls()[0]
        devices = api.load(api.DEVICES_FILE)
        cmds = {}
        dispatched, _queued = api._rollout_dispatch_ring(roll, 0, devices, cmds)
        self.assertIn('d1', dispatched)
        self.assertIn(f'exec:{api._SCHED_UPGRADE_REBOOT_CMD}', cmds['d1'])

    def test_upgrade_ring_bare_when_no_reboot(self):
        api._autopatch_queue({
            'id': 'p2', 'name': 'p2', 'reboot': False, 'auto_promote': False,
            'rings': [{'name': 'r1', 'selector': {'type': 'tag', 'value': 'canary'}}],
            'health_gate': {'enabled': False, 'threshold': 70}, 'verify_minutes': 15,
        }, 'tester')
        roll = self._rolls()[0]
        devices = api.load(api.DEVICES_FILE)
        cmds = {}
        api._rollout_dispatch_ring(roll, 0, devices, cmds)
        # Linux host: bare upgrade command, and no reboot appended.
        self.assertIn(f'exec:{api._UPGRADE_CMD}', cmds['d1'])
        self.assertNotIn('reboot', cmds['d1'])

    def test_windows_ring_gets_bare_upgrade_not_bash(self):
        # v6.1.3: a Windows host in the ring must get the bare `upgrade` verb
        # (its agent self-detects), never a bash exec: script, plus `reboot`
        # when the rollout is reboot-flagged (Windows agents never auto-reboot).
        devs = api.load(api.DEVICES_FILE)
        devs['d1']['os'] = 'Windows 11 (Build 22631)'
        api.save(api.DEVICES_FILE, devs)
        api._autopatch_queue({
            'id': 'pw', 'name': 'pw', 'reboot': True, 'auto_promote': False,
            'rings': [{'name': 'r1', 'selector': {'type': 'tag', 'value': 'canary'}}],
            'health_gate': {'enabled': False, 'threshold': 70}, 'verify_minutes': 15,
        }, 'tester')
        roll = self._rolls()[0]
        cmds = {}
        api._rollout_dispatch_ring(roll, 0, api.load(api.DEVICES_FILE), cmds)
        self.assertIn('upgrade', cmds['d1'])
        self.assertIn('reboot', cmds['d1'])
        self.assertFalse(any(c.startswith('exec:') for c in cmds['d1']),
                         'a Windows host must never be sent a bash exec: script')


class TestWiring(unittest.TestCase):
    def test_frontend_ring_config(self):
        js = (_ROOT / 'server/html/static/js/app.js').read_text()
        self.assertIn('function _autopatchParseRings(', js)
        self.assertIn('function onAutopatchStagedToggle(', js)
        html = (_ROOT / 'server/html/index.html').read_text()
        self.assertIn('autopatch-staged', html)
        self.assertIn('autopatch-rings', html)

    def test_dispatch_reboot_branch_in_source(self):
        # v6.1.3: dispatch is OS-aware — the reboot command is chosen per device.
        src = (_CGI / 'provisioning_handlers.py').read_text()
        self.assertIn("_device_os_family(dev)", src)          # OS branch present
        self.assertIn("_SCHED_UPGRADE_REBOOT_CMD}' if reboot", src)  # linux reboot path


if __name__ == '__main__':
    unittest.main()

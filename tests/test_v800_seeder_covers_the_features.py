#!/usr/bin/env python3
"""8.0.0: the demo seeder shows every feature this release adds, in the shape the server itself writes.

The rendered gates (axe, box overflow, icon gaps, the click sweeps) and the public demo all measure the SEEDED instance, so a feature the seeder leaves out is invisible to all of
them: an empty table renders cleanly and proves nothing. Found in the precheck of 8.0.0: the four new monitor types, the Apprise destination and the automatic image updates had
no seeded data at all. The monitor types are read from the Type select of the Add monitor dialog, so a fifth type that nobody seeds fails here; the other features are listed, each
checked against the server's own definition of its shape.
"""

import ast
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-seedcov-'))
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'server' / 'cgi-bin'))

import image_autoupdate as IA  # noqa: E402
import protocol_probes  # noqa: E402
import store_shapes  # noqa: E402

_spec = importlib.util.spec_from_file_location('seed_demo_cov', ROOT / 'packaging' / 'seed-demo-data.py')
seed = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(seed)

RECEIPT_STATES = ('shadow', 'queued', 'awaiting_approval', 'ok', 'not_updated', 'unhealthy', 'unverified', 'declined', 'rollback_awaiting_approval', 'rolling_back', 'rolled_back',
                  'rollback_failed')


def ui_monitor_types():
    html = (ROOT / 'server' / 'html' / 'index.html').read_text()
    m = re.search(r'<select id="mon-type"[^>]*>(.*?)</select>', html, re.S)
    return re.findall(r'<option value="([^"]+)"', m.group(1))


def receipt_keys_the_sweep_writes():
    """The keys of the receipt dict literal in image_autoupdate_handlers._apply_policy, read by syntax tree."""
    tree = ast.parse((ROOT / 'server' / 'cgi-bin' / 'image_autoupdate_handlers.py').read_text())
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == '_apply_policy')
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'receipt' for t in node.targets) and isinstance(node.value, ast.Dict):
            return {k.value for k in node.value.keys if isinstance(k, ast.Constant)}
    raise AssertionError('the receipt literal was not found')


class TestTheMonitors(unittest.TestCase):

    def test_every_type_the_dialog_offers_has_a_seeded_monitor(self):
        offered = ui_monitor_types()
        self.assertGreaterEqual(len(offered), 12, offered)
        seeded = {m['type'] for m in seed._demo_monitors()}
        self.assertEqual(sorted(set(offered) - seeded), [], 'monitor types with no seeded monitor')

    def test_the_four_handshake_types_are_the_servers_and_carry_what_the_server_keeps(self):
        mons = {m['type']: m for m in seed._demo_monitors()}
        for t in protocol_probes.TYPES:
            self.assertIn(t, mons)
            self.assertTrue(mons[t]['target'].rsplit(':', 1)[0], t)
        self.assertIn(mons['smtp']['tls'], protocol_probes.TLS_MODES)
        self.assertIn(mons['imap']['tls'], protocol_probes.TLS_MODES)
        self.assertTrue(0 < mons['ntp']['max_offset_ms'] <= protocol_probes.MAX_OFFSET_MS)

    def test_each_seeded_monitor_has_a_history_under_its_label(self):
        hist = seed.build_monitor_history()
        for m in seed._demo_monitors():
            self.assertIn(m['label'], hist, m['label'])


class TestTheDestinations(unittest.TestCase):

    def test_an_apprise_destination_is_seeded_and_valid(self):
        api_src = (ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        formats = set(re.findall(r"'([a-z]+)'", re.search(r'_WEBHOOK_FORMATS = \((.*?)\)', api_src, re.S).group(1)))
        self.assertIn('apprise', formats, 'control: the server knows the format')
        dests = seed.build_config()['webhook_urls']
        apprise = [d for d in dests if d['format'] == 'apprise']
        self.assertEqual(len(apprise), 1)
        self.assertTrue(apprise[0]['url'].startswith('https://'))
        for d in dests:
            self.assertIn(d['format'], formats, d)


class TestTheImageUpdates(unittest.TestCase):

    def test_the_policy_is_one_the_server_accepts_unchanged(self):
        policy = seed.build_config()['image_autoupdate']
        cleaned, err = IA.clean_policy(policy, base=IA.DEFAULT_POLICY, period_exists=lambda _pid: False)
        self.assertFalse(err, err)
        self.assertEqual(cleaned, policy, 'the server would store it differently')
        self.assertEqual(policy['mode'], 'shadow', 'the demo queues no command for a host that has no agent to run it')

    def test_the_receipts_carry_every_key_the_sweep_writes_and_a_state_the_page_knows(self):
        block = seed.build_image_updates()['autoupdate']
        keys = receipt_keys_the_sweep_writes()
        self.assertGreaterEqual(len(keys), 14, keys)
        devices = set(seed.build_devices())
        states = set()
        for r in block['receipts']:
            self.assertEqual(sorted(keys - set(r)), [], 'a key the sweep writes is missing from a seeded receipt')
            self.assertIn(r['state'], RECEIPT_STATES)
            states.add(r['state'])
            self.assertIn(r['device_id'], devices, 'a receipt for a host the demo does not have')
        self.assertGreaterEqual(len(states), 4, 'a history, not one row: %s' % sorted(states))
        self.assertIn('rolled_back', states, 'the rollback is the part of the feature worth showing')
        last = block['last_run']
        self.assertEqual(set(last), {'ts', 'mode', 'made', 'made_ids', 'held'})
        self.assertTrue(all(h.get('device_id') for h in last['held']))

    def test_the_store_passes_the_shape_registry_without_a_repair(self):
        data = seed.build_image_updates()
        before = repr(data)
        out = store_shapes.normalize('image_updates.json', data)
        self.assertEqual(repr(out), before, 'the registry changed what the seeder wrote')


class TestTheOtherFeatures(unittest.TestCase):

    def test_traffic_discovery_connectors_and_layouts_are_seeded(self):
        cfg = seed.build_config()
        self.assertTrue(cfg['traffic_module_enabled'])
        self.assertTrue(cfg['traffic_watch'])
        types = {i['type'] for i in cfg['integrations']}
        self.assertTrue({'unifi', 'tailscale', 'headscale'} <= types, types)
        devices = seed.build_devices()
        found = [d for d in devices.values() if isinstance((d.get('sysinfo') or {}).get('discovered'), list) and d['sysinfo']['discovered']]
        self.assertGreaterEqual(len(found), 6, 'hosts that report the apps the agent found')
        sets = seed._demo_dashboard_sets()
        self.assertGreaterEqual(len(sets), 2)


class TestTheTimesheet(unittest.TestCase):

    def test_the_current_week_has_an_entry_on_every_day_of_the_week(self):
        """The Timesheet opens on the current week (Monday to Sunday). An entry is dated some days before the day the seed runs, so the week holds one on a Monday only
        when one is dated today: the newest entry was a day old and the demo's Timesheet was empty every Monday until the week before was opened."""
        import datetime
        today = datetime.date.today()
        entries = seed.build_time_entries()['entries']
        ages = sorted((today - datetime.date.fromisoformat(e['date'])).days for e in entries)
        self.assertGreaterEqual(len(entries), 12, 'control: the ledger was read')
        self.assertEqual(ages[0], 0, 'an entry dated today: the newest of %s days old' % ages[:3])
        for weekday in range(7):                      # the seed run on a Monday (0) to a Sunday (6): the week so far is the last `weekday` days and today
            self.assertTrue(any(a <= weekday for a in ages), 'no entry in the week so far on weekday %d' % weekday)
        for e in entries:
            self.assertTrue(e['id'] and e['user'] and e['hours'] > 0, e)

    def test_every_entry_has_its_own_number_and_the_counter_is_ahead_of_them(self):
        ledger = seed.build_time_entries()
        numbers = [e['number'] for e in ledger['entries']]
        self.assertEqual(len(set(numbers)), len(numbers))
        self.assertEqual(ledger['seq'], max(numbers))


if __name__ == '__main__':
    unittest.main()

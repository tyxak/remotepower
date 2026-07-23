"""v6.4.0 — counter the ignored-items pile-up (5 measures).

#1 self-pruning ignores (GC moot ones), #2 device-scoped prune on removal,
#3 auto-heal recheck resolves patch_alert/cve_found when the condition clears,
#4 class-level suppression rules, #5 last-active hygiene annotation. These drive
the real helpers so a regression re-opens the pile-up.
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
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v640-ig-')
    spec = importlib.util.spec_from_file_location('api_v640_ig', CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestGcMootIgnores(unittest.TestCase):
    """#1: an ignore whose raw NA item is gone is GC'd after the grace window."""

    def setUp(self):
        self.api = _fresh_api()

    def test_moot_ignore_pruned_live_ignore_kept(self):
        api = self.api
        old = int(api.time.time()) - api._NA_GC_GRACE - 100
        api.save(api.IGNORED_ITEMS_FILE, {'needs_attention': [
            {'key': 'LIVE', 'ts': old, 'last_seen': old},   # still active this round
            {'key': 'GONE', 'ts': old, 'last_seen': old},   # condition cleared long ago
        ], 'stale_containers': [], 'devices': []})
        api._LOAD_CACHE.clear()
        api._stash_live_attention_keys({'LIVE'})   # only LIVE is a live raw key
        api._prune_ignored_items()
        keys = {e['key'] for e in (api.load(api.IGNORED_ITEMS_FILE) or {}).get('needs_attention', [])}
        self.assertIn('LIVE', keys)
        self.assertNotIn('GONE', keys)

    def test_recently_absent_ignore_kept_within_grace(self):
        api = self.api
        now = int(api.time.time())
        api.save(api.IGNORED_ITEMS_FILE, {'needs_attention': [
            {'key': 'RECENT', 'ts': now, 'last_seen': now},   # absent but within grace
        ], 'stale_containers': [], 'devices': []})
        api._LOAD_CACHE.clear()
        api._stash_live_attention_keys(set())   # nothing live
        api._prune_ignored_items()
        keys = {e['key'] for e in (api.load(api.IGNORED_ITEMS_FILE) or {}).get('needs_attention', [])}
        self.assertIn('RECENT', keys)   # grace not elapsed


class TestDeviceScopedPrune(unittest.TestCase):
    """#2: removing a device drops its ignores + cleared-log-lines."""

    def setUp(self):
        self.api = _fresh_api()

    def test_device_ignores_and_logacks_pruned(self):
        api = self.api
        api.save(api.IGNORED_ITEMS_FILE, {
            'needs_attention': [{'key': 'k1', 'device_id': 'devA'},
                                {'key': 'k2', 'device_id': 'devB'}],
            'stale_containers': [{'device_id': 'devA', 'container': 'c'}],
            'devices': [{'id': 'devA'}, {'id': 'devB'}],
        })
        api.save(api.LOG_ACKS_FILE, {'acks': {
            'devA|u|s': {'device_id': 'devA'}, 'devB|u|s': {'device_id': 'devB'}}})
        api._LOAD_CACHE.clear()
        api._prune_ignores_for_device('devA')
        ig = api.load(api.IGNORED_ITEMS_FILE) or {}
        self.assertEqual([e['key'] for e in ig['needs_attention']], ['k2'])
        self.assertEqual(ig['stale_containers'], [])
        self.assertEqual([e['id'] for e in ig['devices']], ['devB'])
        acks = (api.load(api.LOG_ACKS_FILE) or {}).get('acks', {})
        self.assertEqual(list(acks.keys()), ['devB|u|s'])


class TestAutohealRecheck(unittest.TestCase):
    """#3: patch_alert / cve_found auto-resolve when current state is clear."""

    def setUp(self):
        self.api = _fresh_api()

    def test_patch_and_cve_resolve_when_cleared(self):
        api = self.api
        api.save(api.CONFIG_FILE, {'patch_alert_threshold': 10})
        api.save(api.DEVICES_FILE, {
            'd1': {'name': 'd1', 'sysinfo': {'packages': {'upgradable': 2}}},   # now under threshold
            'd2': {'name': 'd2', 'sysinfo': {'packages': {'upgradable': 50}}},  # still over
        })
        api.save(api.CVE_FINDINGS_FILE, {'d1': {'findings': []}})   # all patched
        now = int(api.time.time())
        api.save(api.ALERTS_FILE, {'alerts': [
            {'id': 'p1', 'event': 'patch_alert', 'device_id': 'd1', 'payload': {'threshold': 10}},
            {'id': 'p2', 'event': 'patch_alert', 'device_id': 'd2', 'payload': {'threshold': 10}},
            {'id': 'c1', 'event': 'cve_found', 'device_id': 'd1', 'payload': {}},
        ]})
        api._LOAD_CACHE.clear()
        api._autoheal_recheck(now)
        alerts = {a['id']: a for a in (api.load(api.ALERTS_FILE) or {}).get('alerts', [])}
        self.assertTrue(alerts['p1'].get('resolved_at'))   # under threshold now
        self.assertFalse(alerts['p2'].get('resolved_at'))  # still breaching
        self.assertTrue(alerts['c1'].get('resolved_at'))   # no findings left


class TestClassSuppression(unittest.TestCase):
    """#4: a class rule silences a whole kind at a scope."""

    def setUp(self):
        self.api = _fresh_api()

    def test_suppress_by_kind_and_scope(self):
        api = self.api
        devices = {'d1': {'name': 'web1', 'group': 'prod', 'tags': ['edge']}}
        n2i = {'web1': 'd1'}
        rules_all = [{'kind': 'drift', 'scope': 'all', 'value': ''}]
        item = {'kind': 'drift', 'device': 'web1', 'device_id': 'd1'}
        self.assertTrue(api._na_item_suppressed(item, rules_all, devices, n2i))
        # wrong kind not suppressed
        self.assertFalse(api._na_item_suppressed({'kind': 'cve_found', 'device': 'web1', 'device_id': 'd1'},
                                                 rules_all, devices, n2i))
        # group scope
        rules_grp = [{'kind': '*', 'scope': 'group', 'value': 'prod'}]
        self.assertTrue(api._na_item_suppressed(item, rules_grp, devices, n2i))
        rules_grp2 = [{'kind': '*', 'scope': 'group', 'value': 'staging'}]
        self.assertFalse(api._na_item_suppressed(item, rules_grp2, devices, n2i))
        # tag scope
        self.assertTrue(api._na_item_suppressed(item, [{'kind': '*', 'scope': 'tag', 'value': 'edge'}], devices, n2i))


if __name__ == '__main__':
    unittest.main()

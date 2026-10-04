"""A role scoped to a smart group does not copy the smart-group store once per device.

`_device_in_scope` asks `_smart_group_rules(name)` for the group's rules for every device it tests, and that
lookup called load(SMART_GROUPS_FILE), a deep copy of the whole store (every group's materialised `members`
list included). `_scope_filter_devices` tests every device, and nearly every list endpoint calls it, so a
caller whose role was scoped to a smart group paid one store copy per device on each request. The lookup reads
the store through _load_ro now; both callers only read the rules.

This runs the real scope filter and counts load() calls on the smart-group store, and checks who ends up
in scope, because the point of the lookup is the membership answer.
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
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v710-smart-')
    spec = importlib.util.spec_from_file_location('api_v710_smart', CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestSmartScope(unittest.TestCase):

    def setUp(self):
        self.api = _fresh_api()
        api = self.api
        api.save(api.CONFIG_FILE, {})
        members = ['d%04d' % i for i in range(300)]
        api.save(api.SMART_GROUPS_FILE, {
            'prod-web': {'rules': {'group': 'web', 'tag': 'prod'}, 'members': members},
            'empty': {'rules': {}, 'members': []},
        })
        self.devices = {}
        for i in range(60):
            self.devices['d%04d' % i] = {'name': 'h%d' % i, 'group': 'web' if i % 3 == 0 else 'db',
                                         'tags': ['prod'] if i % 2 == 0 else ['dev'], 'token': 't'}
        api._LOAD_CACHE.clear()

    def filtered(self, scope):
        """({ids in scope}, {store file name: load() calls}) for one real _scope_filter_devices."""
        api = self.api
        api._LOAD_CACHE.clear()
        calls = {}
        real = api.load

        def counting(path, *a, **k):
            name = Path(str(path)).name
            calls[name] = calls.get(name, 0) + 1
            return real(path, *a, **k)

        api.load = counting
        try:
            out = api._scope_filter_devices(self.devices, scope)
        finally:
            api.load = real
        return set(out), calls

    def test_the_store_is_not_copied_per_device(self):
        scope = {'type': 'groups', 'values': ['smart:prod-web']}
        ids, calls = self.filtered(scope)
        self.assertTrue(ids, 'control: some devices should match the smart group')
        self.assertEqual(0, calls.get('smart_groups.json', 0),
                         'the smart-group store was copied %r times for %d devices' % (calls.get('smart_groups.json'), len(self.devices)))

    def test_membership_follows_the_group_rules(self):
        scope = {'type': 'groups', 'values': ['smart:prod-web']}
        ids, _ = self.filtered(scope)
        want = {did for did, d in self.devices.items() if d['group'] == 'web' and 'prod' in d['tags']}
        self.assertEqual(want, ids)
        self.assertTrue(0 < len(want) < len(self.devices))

    def test_a_plain_group_value_alongside_a_smart_one_still_counts(self):
        scope = {'type': 'groups', 'values': ['smart:prod-web', 'db']}
        ids, _ = self.filtered(scope)
        want = {did for did, d in self.devices.items()
                if (d['group'] == 'web' and 'prod' in d['tags']) or d['group'] == 'db'}
        self.assertEqual(want, ids)

    def test_an_unknown_smart_group_admits_nothing_by_itself(self):
        ids, _ = self.filtered({'type': 'groups', 'values': ['smart:no-such-group']})
        self.assertEqual(set(), ids)

    def test_the_stored_rules_are_not_edited_by_matching(self):
        import json
        before = json.dumps(self.api.load(self.api.SMART_GROUPS_FILE), sort_keys=True)
        self.filtered({'type': 'groups', 'values': ['smart:prod-web']})
        self.assertEqual(before, json.dumps(self.api.load(self.api.SMART_GROUPS_FILE), sort_keys=True))


if __name__ == '__main__':
    unittest.main()

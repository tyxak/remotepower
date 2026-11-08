#!/usr/bin/env python3
"""8.0.0: a deleted host leaves none of the settings that are a map of host id to something.

`_purge_device` cleared four of the settings the code keeps by host id and missed the other four (the patch alert flag, the disabled checks, the DNS result and, new in
8.0.0, the hidden apps). The population here is read from the code: every server module is parsed, and a setting counts when the code indexes it by a name that holds a host id
(`dev_id`, `device_id`, ...). The control cases check that the scan sees a setting the purge always cleared and the one 8.0.0 added.
"""

import ast
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-purgecfg-'))
_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_TESTS.parent / 'server' / 'cgi-bin'))

from test_ip_intel import _fresh_api  # noqa: E402

CGI = _TESTS.parent / 'server' / 'cgi-bin'
CFG_NAMES = ('cfg', 'config', 'cfg_w', 'c', 'conf')
HOST_NAMES = ('dev_id', 'device_id', 'did', 'hid', 'host_id', 'devid')

# a setting the code indexes by a host id that a deleted host may keep, with the reason
EXEMPT = {}


def _constants(tree):
    out = {}
    for n in tree.body:
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str):
            out[n.targets[0].id] = n.value.value
    return out


def _key(node, consts):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return consts.get(node.id)
    return None


def _setting_read(value, consts):
    """The setting an expression reads out of the settings dict (cfg.get('k'), cfg['k'], cfg.setdefault('k', ..)), looking through `or` and a conditional."""
    if isinstance(value, ast.BoolOp):
        return _setting_read(value.values[0], consts)
    if isinstance(value, ast.IfExp):
        return _setting_read(value.body, consts) or _setting_read(value.orelse, consts)
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute) and value.func.attr in ('get', 'setdefault') and value.args and isinstance(value.func.value, ast.Name) \
            and value.func.value.id in CFG_NAMES:
        return _key(value.args[0], consts)
    if isinstance(value, ast.Subscript) and isinstance(value.value, ast.Name) and value.value.id in CFG_NAMES:
        return _key(value.slice, consts)
    return None


def settings_keyed_by_host():
    """{setting: sorted module names} for every setting some function indexes by a host id."""
    found = {}
    for path in sorted(CGI.glob('*.py')):
        try:
            tree = ast.parse(path.read_text())
        except SyntaxError:
            continue
        consts = _constants(tree)
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            bound = {}
            for n in ast.walk(fn):
                if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                    k = _setting_read(n.value, consts)
                    if k:
                        bound[n.targets[0].id] = k
            for n in ast.walk(fn):
                base = None
                if isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Name) and n.slice.id in HOST_NAMES:
                    base = n.value
                elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ('get', 'pop', 'setdefault') and n.args \
                        and isinstance(n.args[0], ast.Name) and n.args[0].id in HOST_NAMES:
                    base = n.func.value
                if base is None:
                    continue
                k = bound.get(base.id) if isinstance(base, ast.Name) else _setting_read(base, consts)
                if k:
                    found.setdefault(k, set()).add(path.name)
    return {k: sorted(v) for k, v in found.items()}


def purged_settings():
    """The settings `_purge_device` clears, read from its own source: the tuple of the loop that runs under the settings lock."""
    tree = ast.parse((CGI / 'api.py').read_text())
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == '_purge_device')
    for node in ast.walk(fn):
        if isinstance(node, ast.With) and 'CONFIG_FILE' in ast.unparse(node.items[0].context_expr):
            for inner in ast.walk(node):
                if isinstance(inner, ast.For) and isinstance(inner.iter, ast.Tuple):
                    return {str(e.value) for e in inner.iter.elts if isinstance(e, ast.Constant)}
    return set()


class TestThePopulation(unittest.TestCase):

    def test_the_scan_sees_a_setting_the_purge_always_cleared_and_the_one_8_0_0_added(self):
        found = settings_keyed_by_host()
        self.assertIn('offline_notified', found, 'control: cleared since 2.6.0')
        self.assertIn('app_discovery_dismissed', found, 'control: read through a conditional expression, which a plainer scan does not follow')
        self.assertGreaterEqual(len(found), 7, sorted(found))

    def test_the_purge_reads_back_its_own_list(self):
        purged = purged_settings()
        self.assertIn('offline_pending', purged)
        self.assertGreaterEqual(len(purged), 4, sorted(purged))

    def test_every_setting_kept_by_host_id_is_cleared_when_the_host_is_deleted(self):
        found, purged = settings_keyed_by_host(), purged_settings()
        missing = sorted(k for k in found if k not in purged and k not in EXEMPT)
        self.assertEqual(missing, [], '%d of %d settings keyed by a host id are cleared by _purge_device; these are not: %s' % (len(found) - len(missing), len(found), missing))

    def test_an_exemption_names_a_setting_the_code_still_keeps_by_host(self):
        found = settings_keyed_by_host()
        for k in EXEMPT:
            self.assertIn(k, found, '%s is listed as exempt and no code indexes it by a host id any more' % k)


class TestTheBehaviour(unittest.TestCase):

    def setUp(self):
        self.api = _fresh_api()

    def test_a_deleted_host_takes_its_entry_and_leaves_the_other_host_alone(self):
        api = self.api
        keys = sorted(set(settings_keyed_by_host()) | purged_settings())
        api.save(api.DEVICES_FILE, {'a1': {'id': 'a1', 'name': 'a1', 'token': 't1'}, 'b2': {'id': 'b2', 'name': 'b2', 'token': 't2'}})
        api.save(api.CONFIG_FILE, {k: {'a1': ['x'], 'b2': ['y']} for k in keys})
        api._LOAD_CACHE.clear()
        self.assertTrue(api._purge_device('a1'))
        api._LOAD_CACHE.clear()
        cfg = api.load(api.CONFIG_FILE)
        for k in keys:
            self.assertEqual(cfg.get(k), {'b2': ['y']}, '%s: the deleted host\'s entry must go and the other host\'s stay' % k)

    def test_a_setting_that_is_not_a_map_is_left_as_it_is(self):
        api = self.api
        api.save(api.DEVICES_FILE, {'a1': {'id': 'a1', 'name': 'a1', 'token': 't1'}})
        api.save(api.CONFIG_FILE, {'app_discovery_dismissed': ['a1'], 'patch_alerted': 'a1', 'host_checks_disabled': None})
        api._LOAD_CACHE.clear()
        self.assertTrue(api._purge_device('a1'))
        api._LOAD_CACHE.clear()
        cfg = api.load(api.CONFIG_FILE)
        self.assertEqual((cfg.get('app_discovery_dismissed'), cfg.get('patch_alerted')), (['a1'], 'a1'), 'a damaged value is not this function\'s to rewrite')


if __name__ == '__main__':
    unittest.main()

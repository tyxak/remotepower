"""v6.2.3 baseline checks: a shipped catalog of recommended checks the admin
applies to a scope; each becomes a scoped custom_check (reusing the whole checks
engine). The checks analogue of Service baselines."""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v623-bc-'))
_spec = importlib.util.spec_from_file_location('api_v623_bc', CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestCatalog(unittest.TestCase):
    def test_catalog_is_well_formed(self):
        cat = api.CHECK_BASELINE_CATALOG
        self.assertGreaterEqual(len(cat), 12)
        ids = [t['id'] for t in cat]
        self.assertEqual(len(ids), len(set(ids)), 'catalog ids must be unique')
        types = set(api.SERVER_CHECK_TYPES) | set(api.AGENT_CHECK_TYPES)
        for t in cat:
            for k in ('cat', 'id', 'type', 'param', 'name', 'desc'):
                self.assertTrue(t.get(k), f'{t.get("id")} missing {k}')
            self.assertIn(t['type'], types, f'{t["id"]} has unknown check type')

    def test_all_four_categories_present(self):
        cats = {t['cat'] for t in api.CHECK_BASELINE_CATALOG}
        for c in ('Core liveness', 'Security posture', 'Filesystem / OS', 'Role-tagged'):
            self.assertIn(c, cats)


class _ApplyBase(unittest.TestCase):
    def setUp(self):
        api.save(api.CONFIG_FILE, {})
        api._invalidate_load_cache(api.CONFIG_FILE)
        self.cap = {}
        self._r, self._a, self._au = api.respond, api.require_admin_auth, api.audit_log

        def resp(s, d=None):
            self.cap['s'], self.cap['d'] = s, d
            raise SystemExit
        api.respond = resp
        api.require_admin_auth = lambda: 'admin'
        api.audit_log = lambda *a, **k: None
        api.method = lambda: 'POST'

    def tearDown(self):
        api.respond, api.require_admin_auth, api.audit_log = self._r, self._a, self._au
        for a in ('method', 'get_json_obj', 'get_json_body'):
            if hasattr(api, a):
                try:
                    delattr(api, a)
                except Exception:
                    pass

    def _apply(self, ids, tk='all', tv=''):
        api.get_json_obj = lambda: {'ids': ids, 'target_kind': tk, 'target': tv}
        api.get_json_body = api.get_json_obj
        try:
            api.handle_check_baselines_apply()
        except SystemExit:
            pass
        return (api.load(api.CONFIG_FILE) or {}).get('custom_checks', [])


class TestApply(_ApplyBase):
    def test_apply_creates_scoped_custom_checks(self):
        checks = self._apply(['agent_running', 'ssh_reachable'], 'group', 'servers')
        self.assertEqual(self.cap['s'], 200)
        self.assertEqual(self.cap['d']['added'], 2)
        by_param = {c['param']: c for c in checks}
        self.assertEqual(by_param['remotepower-agent.service']['type'], 'systemd_unit')
        self.assertEqual(by_param['remotepower-agent.service']['target_kind'], 'group')
        self.assertEqual(by_param['remotepower-agent.service']['target'], 'servers')

    def test_role_tagged_template_keeps_its_tag_when_applied_fleet_wide(self):
        checks = self._apply(['docker_running'], 'all', '')
        d = next(c for c in checks if c['param'] == 'docker.service')
        self.assertEqual(d['target_kind'], 'tag')
        self.assertEqual(d['target'], 'docker')

    def test_apply_is_idempotent(self):
        self._apply(['agent_running'], 'all', '')
        checks = self._apply(['agent_running'], 'all', '')   # again
        self.assertEqual(self.cap['d']['added'], 0)
        self.assertEqual(sum(1 for c in checks
                             if c['param'] == 'remotepower-agent.service'), 1)

    def test_log_errors_template_carries_its_extras(self):
        checks = self._apply(['no_oom'], 'all', '')
        oom = next(c for c in checks if c['id'] and c['type'] == 'log_errors')
        self.assertIn('window_min', oom)
        self.assertIn('crit', oom)

    def test_empty_ids_rejected(self):
        self._apply([], 'all', '')
        self.assertEqual(self.cap['s'], 400)

    def test_group_scope_requires_a_target(self):
        self._apply(['agent_running'], 'group', '')
        self.assertEqual(self.cap['s'], 400)

    def test_applied_check_is_a_valid_custom_check(self):
        # the produced entry must evaluate through the real checks engine
        checks = self._apply(['agent_running'], 'all', '')
        cdef = checks[0]
        dev = {'sysinfo': {'services_watched_state': {}}}
        status, _out = api._eval_custom_check(cdef, dev)
        self.assertIn(status, ('ok', 'warning', 'critical', 'unknown'))


if __name__ == '__main__':
    unittest.main()

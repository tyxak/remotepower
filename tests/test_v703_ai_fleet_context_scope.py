#!/usr/bin/env python3
"""Anything that ships a fleet roster to a model provider must scope it first.

`ai_context.build_combined_system_prompt(devices=…)` renders a "Fleet snapshot"
block naming every host and its state into the system prompt, which is then sent
to whatever provider is configured — possibly a third party.

There are two callers. `handle_ai_chat` has filtered its roster through
`_scope_filter_devices` since v3.13.0. `handle_runbook_generate` passed the raw
store, so a tenant admin generating a runbook for a host they legitimately own
named every other tenant's hosts in the prompt. `_enforce_device_scope` vets the
device in the PATH before dispatch and says nothing about a roster attached
alongside it.

Two gates, because either alone is weak: a behavioural one that drives the real
handler and reads what the prompt builder was handed, and a source-level one
that enumerates every call site — the ratio was 1 of 2, and the correct site is
what makes the file read as though the rule is enforced.
"""
import ast
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v703-aictx-'))
for _k, _v in (('REQUEST_METHOD', 'POST'), ('PATH_INFO', '/'),
               ('CONTENT_LENGTH', '0')):
    os.environ.setdefault(_k, _v)
_spec = importlib.util.spec_from_file_location('api_v703_aictx', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
import ai_context


class TestTheRosterIsScoped(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='rp-aictx-'))
        self._saved = {}
        for name in ('DEVICES_FILE', 'CONFIG_FILE', 'TENANTS_FILE',
                     'RUNBOOKS_FILE'):
            self._saved[name] = getattr(api, name)
            # The basename IS the storage key on SQLite/Postgres.
            setattr(api, name, self.tmp / Path(str(self._saved[name])).name)
        self._real_builder = ai_context.build_combined_system_prompt
        self._real_method = api.method
        self._real_write = api.require_write_role
        self._real_auth = api.require_auth
        self._real_gate = api._tenant_gate
        self._real_scope = api._caller_scope
        self._real_json = api.get_json_obj
        self._real_rate = api._ai_rate_limit_check
        api._invalidate_load_cache(None)
        api.save(api.TENANTS_FILE, {'t1': {'id': 't1', 'name': 'One'},
                                    't2': {'id': 't2', 'name': 'Two'}})
        api.save(api.CONFIG_FILE, {
            'tenancy_enforced': True,
            'ai': {'enabled': True, 'provider': 'none',
                   'context': {'include_fleet_context': True}}})
        api.save(api.DEVICES_FILE, {
            'a': {'id': 'a', 'name': 'a-host', 'tenant': 't1',
                  'last_seen': 9e9, 'sysinfo': {}},
            'b': {'id': 'b', 'name': 'b-host', 'tenant': 't2',
                  'last_seen': 9e9, 'sysinfo': {}}})
        api._invalidate_load_cache(None)

    def tearDown(self):
        for name, value in self._saved.items():
            setattr(api, name, value)
        ai_context.build_combined_system_prompt = self._real_builder
        api.method, api.require_write_role = self._real_method, self._real_write
        api.require_auth, api._tenant_gate = self._real_auth, self._real_gate
        api._caller_scope, api.get_json_obj = self._real_scope, self._real_json
        api._ai_rate_limit_check = self._real_rate
        api._invalidate_load_cache(None)

    def _capture(self, tenant, fn, *args):
        """Run a handler as `tenant`'s admin and return what the prompt builder
        was handed. Stops before any provider call."""
        seen = {}
        real = self._real_builder

        def spy(base, **kw):
            seen['devices'] = [d.get('name') for d in (kw.get('devices') or [])]
            seen['prompt'] = real(base, **kw)
            raise SystemExit(0)

        ai_context.build_combined_system_prompt = spy
        api.ai_context = ai_context
        api.method = lambda: 'POST'
        api.require_write_role = lambda *a, **k: 'admin1'
        api.require_auth = lambda **k: 'admin1'
        api._tenant_gate = lambda: tenant
        api._caller_scope = lambda: None
        api.get_json_obj = lambda: {}
        api._ai_rate_limit_check = lambda *a, **k: (True, 0, 100)
        try:
            fn(*args)
        except (SystemExit, api.HTTPError):
            pass
        return seen

    def test_runbook_generation_sends_only_the_callers_own_hosts(self):
        seen = self._capture('t1', api.handle_runbook_generate, 'a')
        self.assertEqual(seen.get('devices'), ['a-host'],
                         'the fleet roster in the prompt is not tenant-scoped')
        self.assertNotIn('b-host', seen.get('prompt') or '',
                         "another tenant's host name reached the model prompt")

    def test_the_capture_can_see_the_leak(self):
        """The control. If the spy never fires, or the prompt never contains a
        host name, the assertion above is true for the wrong reason."""
        seen = self._capture('t1', api.handle_runbook_generate, 'a')
        self.assertIn('devices', seen, 'the prompt builder was never reached')
        self.assertIn('a-host', seen.get('prompt') or '',
                      'the prompt carries no host names at all, so an absence '
                      'proves nothing')

    def test_a_superadmin_still_gets_the_whole_fleet(self):
        """The other direction. Filtering everyone would pass the first test
        and make the feature worse."""
        seen = self._capture(None, api.handle_runbook_generate, 'a')
        self.assertEqual(sorted(seen.get('devices') or []),
                         ['a-host', 'b-host'])


class TestEveryCallSiteScopesItsRoster(unittest.TestCase):
    """The class, not the instance. One of the two call sites was correct,
    which is what made the file read as though the rule was enforced."""

    _SCOPING = ('_scope_filter_devices', 'fleet_devices')

    def _call_sites(self):
        src = (_CGI / 'api.py').read_text()
        tree = ast.parse(src)
        out = []
        for fn in ast.walk(tree):
            if not isinstance(fn, ast.FunctionDef):
                continue
            body = ast.unparse(fn)
            if 'build_combined_system_prompt' in body:
                out.append((fn.name, body))
        return out

    def test_the_enumeration_is_not_empty(self):
        names = [n for n, _ in self._call_sites()]
        self.assertGreaterEqual(len(names), 2,
                                f'call-site enumeration collapsed: {names}')
        self.assertIn('handle_runbook_generate', names)

    def test_every_caller_scopes_the_devices_it_passes(self):
        bad = []
        for name, body in self._call_sites():
            if not any(tok in body for tok in self._SCOPING):
                bad.append(name)
        self.assertEqual(
            bad, [],
            'these handlers build an AI system prompt from an unfiltered '
            'device store — the roster is sent to the model provider, so it '
            f'must go through _scope_filter_devices first: {bad}')

    def test_the_detector_reports_an_unscoped_body_as_unscoped(self):
        """The control for the source scan: a body with no scoping token must
        be reported, or the check above passes by never matching anything."""
        fake = "def h():\n    ai_context.build_combined_system_prompt(x, devices=load(DEVICES_FILE))\n"
        self.assertFalse(any(t in fake for t in self._SCOPING))


if __name__ == '__main__':
    unittest.main()

"""Router dispatch-table regression guard (v3.4.0 router refactor).

main()'s 300-branch elif chain was extracted into _dispatch(pi, m) and the
fixed-path routes lifted into the _EXACT_ROUTES table (consulted before the
ordered pattern chain). The refactor was proven behaviour-preserving against a
311-probe snapshot of the old chain; these tests lock the result in:

- the exact-route table has no duplicate (method, path) keys (a dict literal
  would silently keep the last, hiding a shadowed route);
- every tabled handler actually exists and is callable;
- a representative corpus — including the bespoke conditional routes (delete
  guard, bulk-save, type-confirm delete, host-config) — resolves to the right
  handler, so a future edit that mis-orders or mis-wires a route fails CI.
"""
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'server' / 'cgi-bin'))

import api  # noqa: E402

API_SRC = (ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()


class _Sentinel(Exception):
    def __init__(self, name, args):
        self.name = name
        self.handler_args = args


class TestExactRouteTable(unittest.TestCase):
    def test_no_duplicate_keys_in_source(self):
        # Parse the literal keys in _build_exact_routes so a duplicated
        # (method, path) — which a dict literal silently collapses — is caught.
        start = API_SRC.index('def _build_exact_routes()')
        end = API_SRC.index('\n\n', API_SRC.index('return {', start))
        block = API_SRC[start:end]
        keys = re.findall(r"\n\s*(\((?:None|'[A-Z]+'), '[^']+'\)):", block)
        self.assertGreater(len(keys), 100, "exact route table looks empty")
        dupes = sorted({k for k in keys if keys.count(k) > 1})
        self.assertEqual(dupes, [], f"duplicate exact-route keys: {dupes}")

    def test_all_handlers_exist_and_callable(self):
        table = api._build_exact_routes()
        self.assertGreater(len(table), 100)
        for (method, path), handler in table.items():
            self.assertTrue(callable(handler), f"{method} {path} -> non-callable")


class TestRouteResolution(unittest.TestCase):
    """Drive _dispatch with handlers replaced by recorders and assert the right
    one fires. Covers exact routes AND the conditional/bespoke pattern routes."""

    CASES = [
        # exact-table routes
        ('POST', '/api/login', 'handle_login'),
        ('GET',  '/api/devices', 'handle_devices_list'),
        ('GET',  '/api/health', 'handle_health'),
        ('GET',  '/api/public-info', 'handle_public_info'),
        # v3.14.0: per-account favorites + fleet thermal roll-up
        ('POST', '/api/favorites', 'handle_favorites_set'),
        ('GET',  '/api/fleet/thermal', 'handle_fleet_thermal'),
        # v3.14.0: active session management
        ('GET',    '/api/me/sessions', 'handle_me_sessions'),
        ('POST',   '/api/me/sessions/revoke-others', 'handle_me_sessions_revoke_others'),
        ('DELETE', '/api/me/sessions/abc123', 'handle_me_session_revoke'),
        # v3.14.0: Tier-2 net-new
        ('GET',    '/api/ssh-keys', 'handle_ssh_keys_fleet'),
        ('GET',    '/api/fleet/power', 'handle_fleet_power'),
        ('GET',    '/api/fleet/disk-health', 'handle_disk_health'),
        ('GET',    '/api/report/definitions', 'handle_report_defs_list'),
        ('POST',   '/api/report/definitions', 'handle_report_defs_save'),
        ('DELETE', '/api/report/definitions/abc123', 'handle_report_def_delete'),
        # v3.14.0: Tier-2 gap mop-up
        ('GET',    '/api/drift-policies', 'handle_drift_policies_get'),
        ('PUT',    '/api/drift-policies', 'handle_drift_policies_set'),
        # v3.14.0: Pass A — metrics push
        ('GET',    '/api/metrics/push/config', 'handle_metrics_push_get'),
        ('PUT',    '/api/metrics/push/config', 'handle_metrics_push_set'),
        # bespoke conditional routes (the ones the elif ordering used to gate)
        ('DELETE', '/api/devices/abc123', 'handle_device_delete'),
        ('POST',   '/api/devices/abc123', 'handle_device_save_bulk'),
        ('PATCH',  '/api/devices/abc123/tags', 'handle_device_tags'),
        ('GET',    '/api/devices/abc/host-config/current',
         'handle_device_host_config_current'),
        # create must beat the generic /lxc/<vmid> action route
        ('POST',   '/api/proxmox/lxc/create', 'handle_proxmox_lxc_create'),
        ('DELETE', '/api/proxmox/lxc/123', 'handle_proxmox_lxc_delete'),
        ('POST',   '/api/proxmox/lxc/123', 'handle_proxmox_action'),
    ]

    def setUp(self):
        self._orig = {}
        for name in dir(api):
            if name.startswith('handle_') and callable(getattr(api, name)):
                self._orig[name] = getattr(api, name)

                def mk(n):
                    def rec(*a, **k):
                        raise _Sentinel(n, list(a))
                    return rec
                setattr(api, name, mk(name))
        # Force the lazy table to rebuild capturing the recorders (a prior test
        # or the real app may have built it with the live handlers).
        self._orig_table = api._EXACT_ROUTES
        api._EXACT_ROUTES = None
        # Same for the pattern table (v5.6.x: the elif chain is data now) —
        # a cached build would hold stale handler objects across the swap.
        self._orig_patterns = api._PATTERN_ROUTES
        api._PATTERN_ROUTES = None

    def tearDown(self):
        for name, fn in self._orig.items():
            setattr(api, name, fn)
        api._EXACT_ROUTES = self._orig_table
        api._PATTERN_ROUTES = self._orig_patterns

    def _resolve(self, method, path):
        os.environ['REQUEST_METHOD'] = method
        os.environ['PATH_INFO'] = path
        try:
            api._dispatch(path, method)
        except _Sentinel as s:
            return s.name
        except api.HTTPError as e:
            return f'__http__{e.status}'
        return '__nocall__'

    def test_cases_resolve_to_expected_handler(self):
        for method, path, expected in self.CASES:
            self.assertEqual(self._resolve(method, path), expected,
                             f"{method} {path} routed wrong")

    def test_unknown_path_404s(self):
        self.assertEqual(self._resolve('GET', '/api/definitely-not-a-route'),
                         '__http__404')


if __name__ == '__main__':
    unittest.main()

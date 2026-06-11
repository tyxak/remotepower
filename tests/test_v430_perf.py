#!/usr/bin/env python3
"""v4.3.0 perf-regression guardrail.

The single-device endpoints must NOT reconstruct the whole devices store on the
SQLite/Postgres backends — that's the O(fleet)->O(1) win device_get exists for.
This counts full-document loads of DEVICES_FILE while a single-device handler
runs and asserts it stays at zero. Without it, a future edit that reintroduces
`devices = load(DEVICES_FILE); dev = devices.get(id)` silently regresses the
optimization and nothing would notice until a big-fleet operator did.
"""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
import sys
sys.path.insert(0, str(_CGI))
import storage  # noqa: E402
_spec = importlib.util.spec_from_file_location("api_v430p", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestSingleDeviceReadsAvoidFullLoad(unittest.TestCase):
    """Forced SQLite backend; a single-device handler must never call
    load(DEVICES_FILE) (which reconstructs every device's row)."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        storage.close_connection()
        api._invalidate_backend_cache()
        api._LOAD_CACHE.clear()
        self._files = {}
        for attr in ('DEVICES_FILE', 'CONFIG_FILE', 'USERS_FILE', 'HARDWARE_FILE',
                     'CVE_FINDINGS_FILE', 'CVE_IGNORE_FILE', 'PACKAGES_FILE',
                     'METRICS_FILE', 'STORAGE_MARKER_FILE'):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        storage.write_marker(self.d, 'sqlite')
        self._env = os.environ.pop('RP_STORAGE_BACKEND', None)
        # Stub auth + respond.
        self._orig = {n: getattr(api, n) for n in
                      ('require_auth', 'verify_token', 'get_token_from_request',
                       'respond', 'method', '_caller_scope')}
        api.require_auth = lambda require_admin=False: 'jakob'
        api.verify_token = lambda t: ('jakob', 'admin')
        api.get_token_from_request = lambda: 't'
        api._caller_scope = lambda: None
        api.method = lambda: 'GET'
        self.cap = {}

        def _resp(s, b=None):
            self.cap['s'] = s; self.cap['b'] = b
            raise api.HTTPError(s, b)
        api.respond = _resp
        # Seed a fleet so a full reconstruction would be obviously expensive.
        fleet = {f'd{i}': {'name': f'host{i}', 'last_seen': 1,
                           'sysinfo': {'mounts': [{'path': '/', 'percent': 10}]}}
                 for i in range(50)}
        api.save(api.DEVICES_FILE, fleet)
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for attr, v in self._files.items():
            setattr(api, attr, v)
        if self._env is not None:
            os.environ['RP_STORAGE_BACKEND'] = self._env
        api._invalidate_backend_cache()
        api._LOAD_CACHE.clear()
        storage.close_connection()

    def _count_devices_loads(self, fn, *a):
        """Run fn, counting how many times the WHOLE devices document was
        loaded (api.load(DEVICES_FILE)). device_get must not trigger one."""
        n = [0]
        real = api.load

        def counting_load(path):
            if path == api.DEVICES_FILE:
                n[0] += 1
            return real(path)
        api.load = counting_load
        self.cap.clear()
        try:
            try:
                fn(*a)
            except api.HTTPError:
                pass
        finally:
            api.load = real
        return n[0], self.cap.get('b')

    def test_backend_is_sqlite(self):
        self.assertEqual(api._storage_backend(), 'sqlite')

    def test_device_get_does_not_reconstruct_fleet(self):
        n, _ = self._count_devices_loads(lambda: api.device_get('d7'))
        self.assertEqual(n, 0, 'device_get reconstructed the whole devices store')

    def test_handle_sysinfo_single_row(self):
        n, body = self._count_devices_loads(api.handle_sysinfo, 'd7')
        self.assertEqual(n, 0,
                         'handle_sysinfo reconstructed the whole devices store')
        self.assertIn('sysinfo', body)

    def test_handle_device_checks_single_row(self):
        n, body = self._count_devices_loads(api.handle_device_checks, 'd7')
        self.assertEqual(n, 0,
                         'handle_device_checks reconstructed the whole devices store')
        self.assertEqual(body['device_id'], 'd7')

    def test_handle_cve_device_single_row(self):
        api.save(api.CVE_FINDINGS_FILE, {'d7': {'findings': []}})
        api._LOAD_CACHE.clear()
        n, _ = self._count_devices_loads(api.handle_cve_device, 'd7')
        self.assertEqual(n, 0,
                         'handle_cve_device reconstructed the whole devices store')


if __name__ == '__main__':
    unittest.main()

"""v5.6.0 — virtualization lifecycle parity (vSphere/vCenter, OpenShift, vCloud).

Covers the pure hypervisor.py drivers (list / power / snapshots normalization),
the SSRF + path-traversal hardening on admin-supplied vm/snapshot ids, and the
api.py handlers + route wiring (/api/virt/*).
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-virt-'))

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))   # so hypervisor.py can `from integrations import …`

_hspec = importlib.util.spec_from_file_location('hypervisor', _CGI / 'hypervisor.py')
H = importlib.util.module_from_spec(_hspec)
_hspec.loader.exec_module(H)

_aspec = importlib.util.spec_from_file_location('api_virt', _CGI / 'api.py')
api = importlib.util.module_from_spec(_aspec)
_aspec.loader.exec_module(api)
_API = (_CGI / 'api.py').read_text()
_APPVIRT = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-virt.js').read_text()
_INDEX = (_ROOT / 'server' / 'html' / 'index.html').read_text()


class _Resp:
    def __init__(self, status=200, text='', headers=None, jd=None):
        self.status = status
        self.text = text
        self.ok = 200 <= status < 300
        self.headers = headers or {}
        self._j = jd

    def json(self):
        return self._j


class FakeClient:
    """Records requests; returns canned responses keyed by (method, path-prefix)."""
    def __init__(self, json_map=None, req_map=None):
        self.json_map = json_map or {}
        self.req_map = req_map or {}
        self.calls = []

    def get_json(self, path, headers=None, params=None):
        self.calls.append(('GET', path))
        for k, v in self.json_map.items():
            if path.startswith(k):
                return v
        return {}

    def request(self, method, path, headers=None, params=None, body=None):
        self.calls.append((method, path))
        for k, v in self.req_map.items():
            if path.startswith(k):
                return v
        return _Resp(200)


# ── driver normalization ──────────────────────────────────────────────────────
class TestVsphereDriver(unittest.TestCase):
    def _client(self):
        return FakeClient(
            json_map={'/api/vcenter/vm': [
                {'vm': 'vm-1', 'name': 'web', 'power_state': 'POWERED_ON',
                 'cpu_count': 4, 'memory_size_MiB': 4096, 'host': 'esx1'}]},
            req_map={'/api/session': _Resp(200, text='"sess-token"')})

    def test_list_vms_normalizes(self):
        rows = H.vsphere_list_vms({'username': 'u', 'secret': 'p'}, self._client())
        self.assertEqual(rows, [{'id': 'vm-1', 'name': 'web', 'status': 'running',
                                 'cpu': 4, 'mem_mb': 4096, 'host': 'esx1'}])

    def test_power_uses_hard_path(self):
        c = self._client()
        c.req_map['/api/vcenter/vm/vm-1/power'] = _Resp(204)
        res = H.vsphere_power({'username': 'u', 'secret': 'p'}, c, 'vm-1', 'start')
        self.assertTrue(res['ok'])
        self.assertTrue(any('/power?action=start' in p for _, p in c.calls))


class TestOpenshiftDriver(unittest.TestCase):
    def test_list_vms_cluster_wide(self):
        c = FakeClient(json_map={'/apis/kubevirt.io/v1/virtualmachines': {'items': [
            {'metadata': {'namespace': 'prod', 'name': 'db'},
             'status': {'printableStatus': 'Running'},
             'spec': {'template': {'spec': {'domain': {
                 'cpu': {'cores': 2},
                 'resources': {'requests': {'memory': '2Gi'}}}}}}}]}})
        rows = H.openshift_list_vms({'secret': 'tok'}, c)
        self.assertEqual(rows[0]['id'], 'prod/db')
        self.assertEqual(rows[0]['status'], 'running')
        self.assertEqual(rows[0]['cpu'], 2)
        self.assertEqual(rows[0]['mem_mb'], 2048)


class TestVcloudDriver(unittest.TestCase):
    def test_list_vms_records(self):
        c = FakeClient(
            json_map={'/api/query': {'record': [
                {'href': 'https://vcd/api/vApp/vm-abc', 'name': 'app',
                 'status': 'POWERED_OFF', 'numberOfCpus': 1, 'memoryMB': 512,
                 'containerName': 'vapp-x'}]}},
            req_map={'/api/sessions': _Resp(
                200, headers={'X-VMWARE-VCLOUD-ACCESS-TOKEN': 'tok'})})
        rows = H.vcloud_list_vms({'username': 'u', 'secret': 'p'}, c)
        self.assertEqual(rows[0]['id'], 'vm-abc')
        self.assertEqual(rows[0]['status'], 'stopped')


# ── SSRF + traversal hardening (the security-critical bit) ────────────────────
class TestIdHardening(unittest.TestCase):
    def test_seg_single_segment(self):
        self.assertEqual(H._seg('../../etc/passwd'), 'passwd')
        self.assertEqual(H._seg('vm-101'), 'vm-101')

    def test_vcloud_base_never_absolute_url(self):
        # An absolute-URL id must NOT become a passthrough (token-exfil SSRF).
        self.assertEqual(H._vcloud_base('http://attacker.example/steal'),
                         '/api/vApp/steal')
        self.assertTrue(H._vcloud_base('urn:x').startswith('/api/vApp/'))

    def test_vcloud_base_traversal_collapsed(self):
        base = H._vcloud_base('a/../../session')
        self.assertNotIn('..', base)
        self.assertTrue(base.startswith('/api/vApp/'))

    def test_openshift_split_rejects_traversal(self):
        with self.assertRaises(H.IntegrationError):
            H._os_split_id('default/../../session')
        with self.assertRaises(H.IntegrationError):
            H._os_split_id('Up/Per')          # uppercase not RFC-1123
        self.assertEqual(H._os_split_id('prod/db'), ('prod', 'db'))

    def test_vsphere_snapshot_delete_quotes_segment(self):
        c = FakeClient()
        c.req_map['/api/vcenter/vm/vm-1/snapshots/'] = _Resp(200)
        c.req_map['/api/session'] = _Resp(200, text='"t"')
        H.vsphere_snapshot_action({'username': 'u', 'secret': 'p'}, c,
                                  'vm-1', 'delete', 'a/../x', '')
        # the snapshot id is quoted into a single segment — no raw '/../'
        self.assertFalse(any('/../' in p for _, p in c.calls))


# ── registry + power-action map ───────────────────────────────────────────────
class TestRegistry(unittest.TestCase):
    def test_lifecycle_platforms(self):
        self.assertEqual(set(H.LIFECYCLE), {'vcenter', 'vcloud', 'openshift'})
        for caps in H.LIFECYCLE.values():
            self.assertEqual(set(caps), {'list_vms', 'power', 'list_snapshots',
                                         'snapshot_action'})

    def test_has_lifecycle_and_power_actions(self):
        self.assertTrue(H.has_lifecycle('openshift'))
        self.assertFalse(H.has_lifecycle('pihole'))
        self.assertFalse(H.has_lifecycle('proxmox'))
        self.assertEqual(H.power_actions('openshift'), ['start', 'stop', 'restart'])
        self.assertEqual(H.power_actions('nope'), [])


# ── api.py handlers + route wiring ────────────────────────────────────────────
class _AuthStub:
    """Context manager that stubs auth/audit so handlers run headless."""
    def __init__(self, integrations, client):
        self.integrations = integrations
        self.client = client
        self._saved = {}

    def __enter__(self):
        for name, fn in {
            'require_auth': lambda *a, **k: 'tester',
            'require_admin_auth': lambda *a, **k: 'admin',
            'audit_log': lambda *a, **k: None,
            '_get_integrations': lambda *a, **k: self.integrations,
            '_integration_client': lambda inst: self.client,
            'load': lambda *a, **k: {'proxmox_enabled': True},
        }.items():
            self._saved[name] = getattr(api, name)
            setattr(api, name, fn)
        return self

    def __exit__(self, *a):
        for name, fn in self._saved.items():
            setattr(api, name, fn)


def _capture(fn, *args):
    try:
        fn(*args)
    except api.HTTPError as e:
        return e.status, e.body
    return None, None


_VC = {'id': 'abc123', 'type': 'vcenter', 'label': 'vc', 'url': 'https://vc',
       'username': 'u', 'secret': 'p', 'verify_tls': True}


class TestApiHandlers(unittest.TestCase):
    def test_platforms_lists_only_lifecycle_and_no_secrets(self):
        with _AuthStub([_VC, {'id': 'p1', 'type': 'pihole'}], FakeClient()):
            st, body = _capture(api.handle_virt_platforms)
        self.assertEqual(st, 200)
        self.assertEqual([p['id'] for p in body['platforms']], ['abc123'])
        self.assertNotIn('secret', body['platforms'][0])
        self.assertNotIn('url', body['platforms'][0])
        self.assertEqual(body['platforms'][0]['power_actions'],
                         H.power_actions('vcenter'))

    def test_vms_handler(self):
        c = FakeClient(
            json_map={'/api/vcenter/vm': [{'vm': 'vm-9', 'name': 'x',
                      'power_state': 'POWERED_ON', 'cpu_count': 1,
                      'memory_size_MiB': 256, 'host': 'h'}]},
            req_map={'/api/session': _Resp(200, text='"t"')})
        with _AuthStub([_VC], c):
            st, body = _capture(api.handle_virt_vms, 'abc123')
        self.assertEqual(st, 200)
        self.assertEqual(body['vms'][0]['id'], 'vm-9')

    def test_unknown_platform_404(self):
        with _AuthStub([_VC], FakeClient()):
            st, body = _capture(api.handle_virt_vms, 'nope')
        self.assertEqual(st, 404)

    def test_non_lifecycle_integration_400(self):
        with _AuthStub([{'id': 'p1', 'type': 'pihole'}], FakeClient()):
            st, body = _capture(api.handle_virt_vms, 'p1')
        self.assertEqual(st, 400)

    def test_power_rejects_unknown_action(self):
        with _AuthStub([_VC], FakeClient()):
            api.get_json_obj = lambda: {'vm_id': 'vm-1', 'action': 'frobnicate'}
            st, body = _capture(api.handle_virt_power, 'abc123')
        self.assertEqual(st, 400)

    def test_power_ok(self):
        c = FakeClient(req_map={'/api/session': _Resp(200, text='"t"'),
                                '/api/vcenter/vm/vm-1/power': _Resp(204)})
        with _AuthStub([_VC], c):
            api.get_json_obj = lambda: {'vm_id': 'vm-1', 'action': 'start'}
            st, body = _capture(api.handle_virt_power, 'abc123')
        self.assertEqual(st, 200)
        self.assertTrue(body['ok'])

    def test_snapshot_action_requires_name_for_delete(self):
        with _AuthStub([_VC], FakeClient()):
            api.get_json_obj = lambda: {'vm_id': 'vm-1', 'action': 'delete', 'name': ''}
            st, body = _capture(api.handle_virt_snapshot_action, 'abc123')
        self.assertEqual(st, 400)


class TestRouteWiring(unittest.TestCase):
    def test_routes_present(self):
        for needle in (
            "pi == '/api/virt/platforms' and m == 'GET'",
            "pi.endswith('/vms') and m == 'GET'",
            "pi.endswith('/power') and m == 'POST'",
            "pi.endswith('/snapshots') and m == 'GET'",
            "pi.endswith('/snapshot') and m == 'POST'",
        ):
            self.assertIn(needle, _API)

    def test_handlers_gate_correctly(self):
        # reads = require_auth; mutations = require_admin_auth + audit_log
        for fn, gate in (('handle_virt_vms', 'require_auth'),
                         ('handle_virt_snapshots', 'require_auth'),
                         ('handle_virt_power', 'require_admin_auth'),
                         ('handle_virt_snapshot_action', 'require_admin_auth')):
            seg = _API[_API.index('def ' + fn): _API.index('def ' + fn) + 1150]
            self.assertIn(gate, seg)
        for fn in ('handle_virt_power', 'handle_virt_snapshot_action'):
            seg = _API[_API.index('def ' + fn): _API.index('def ' + fn) + 1150]
            self.assertIn('audit_log', seg)


class TestFrontendWiring(unittest.TestCase):
    def test_app_virt_overrides_filter(self):
        self.assertIn('function filterVirtualization', _APPVIRT)
        self.assertIn('loadVirtPlatform', _APPVIRT)
        self.assertIn('virtSelectPlatform', _APPVIRT)

    def test_index_includes_module_and_bar(self):
        self.assertIn('app-virt.js?v=', _INDEX)
        self.assertIn('id="virt-platform-bar"', _INDEX)
        self.assertIn('data-action="loadVirtualizationPage"', _INDEX)

    def test_module_loads_after_app_js(self):
        self.assertLess(_INDEX.index('app.js?v='), _INDEX.index('app-virt.js?v='))


if __name__ == '__main__':
    unittest.main()

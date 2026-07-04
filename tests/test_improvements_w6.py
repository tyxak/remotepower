"""Wave-6 improvement-program guardrails (big rocks & decide-first items)."""
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

import importlib.util
import sys

ROOT = Path(__file__).resolve().parent.parent
_CGI_BIN = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_spec = importlib.util.spec_from_file_location("api_w6", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _HandlerBase(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ('USERS_FILE', 'ALERTS_FILE', 'CONFIG_FILE', 'DEVICES_FILE',
                     'CMDB_FILE', 'WARRANTY_CACHE_FILE'):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ('require_auth', 'require_admin_auth', 'verify_token',
                       'get_token_from_request', 'audit_log', 'fire_webhook',
                       'respond', 'method', 'get_json_body', 'get_json_obj')}
        api.require_auth = lambda require_admin=False: 'jakob'
        api.require_admin_auth = lambda: 'jakob'
        api.audit_log = lambda *a, **k: None
        api.fire_webhook = lambda *a, **k: None

        def _resp(s, b=None):
            self.cap['s'] = s
            self.cap['b'] = b
            raise api.HTTPError(s, b)
        api.respond = _resp

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for attr, v in self._files.items():
            setattr(api, attr, v)

    def call(self, fn, *a):
        try:
            fn(*a)
        except api.HTTPError:
            pass
        return self.cap.get('b')


class TestGeoAnomaly(_HandlerBase):
    """W6-41: impossible-travel detector + config."""

    def test_anomaly_pure(self):
        now = 1_000_000
        # different country within window → anomaly
        self.assertTrue(api._geo_anomaly({'country': 'US', 'ts': now - 3600}, 'GB', now, 2))
        # same country → not
        self.assertFalse(api._geo_anomaly({'country': 'US', 'ts': now - 3600}, 'US', now, 2))
        # outside window → not
        self.assertFalse(api._geo_anomaly({'country': 'US', 'ts': now - 4 * 3600}, 'GB', now, 2))
        # no prior → not
        self.assertFalse(api._geo_anomaly(None, 'GB', now, 2))

    def test_config_saves_geoip_paths(self):
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'geoip_db_path': '/var/lib/GeoLite2-Country.mmdb',
                                    'geo_anomaly_enabled': True, 'geo_anomaly_hours': 6}
        try:
            api.handle_config_save()
        except api.HTTPError:
            pass
        cfg = api.load(api.CONFIG_FILE) or {}
        self.assertEqual(cfg['geoip_db_path'], '/var/lib/GeoLite2-Country.mmdb')
        self.assertTrue(cfg['geo_anomaly_enabled'])
        self.assertEqual(cfg['geo_anomaly_hours'], 6)

    def test_geo_enrich_empty_when_unconfigured(self):
        api.save(api.CONFIG_FILE, {})
        api._invalidate_load_cache(api.CONFIG_FILE)
        self.assertEqual(api.geo_enrich('8.8.8.8'), {})

    def test_event_registered(self):
        self.assertIn('login_geo_anomaly', api.EVENT_REGISTRY)
        self.assertEqual(api.EVENT_REGISTRY['login_geo_anomaly']['severity'], 'high')


class _FakeResp:
    def __init__(self, body):
        self._b = body.encode() if isinstance(body, str) else body
    def read(self):
        return self._b
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False


class TestCloudProviders(unittest.TestCase):
    """W6-44: Hetzner + DigitalOcean importers (pure, injected opener)."""

    def setUp(self):
        sys.path.insert(0, str(_CGI_BIN))
        import cloud_import
        self.ci = cloud_import

    def test_hetzner_parse(self):
        body = ('{"servers":[{"id":42,"name":"web1","status":"running",'
                '"server_type":{"name":"cx21"},'
                '"public_net":{"ipv4":{"ip":"5.6.7.8"}},'
                '"private_net":[{"ip":"10.0.0.2"}],'
                '"datacenter":{"location":{"name":"fsn1"}}}]}')
        insts = self.ci.import_hetzner('tok', _opener=lambda req, timeout=15: _FakeResp(body))
        self.assertEqual(len(insts), 1)
        i = insts[0]
        self.assertEqual(i['instance_id'], '42')
        self.assertEqual(i['public_ip'], '5.6.7.8')
        self.assertEqual(i['private_ip'], '10.0.0.2')
        self.assertEqual(i['type'], 'cx21')
        self.assertEqual(i['az'], 'fsn1')

    def test_digitalocean_parse(self):
        body = ('{"droplets":[{"id":99,"name":"db1","status":"active",'
                '"size_slug":"s-1vcpu-1gb","region":{"slug":"nyc3"},'
                '"networks":{"v4":[{"ip_address":"1.2.3.4","type":"public"},'
                '{"ip_address":"10.1.1.1","type":"private"}]}}]}')
        insts = self.ci.import_digitalocean('tok', _opener=lambda req, timeout=15: _FakeResp(body))
        i = insts[0]
        self.assertEqual(i['instance_id'], '99')
        self.assertEqual(i['private_ip'], '10.1.1.1')
        self.assertEqual(i['az'], 'nyc3')

    def test_instance_to_device_shape(self):
        did, frag = self.ci.instance_to_device('hetzner', 'fsn1',
            {'instance_id': '42', 'name': 'web1', 'private_ip': '10.0.0.2', 'type': 'cx21'})
        self.assertEqual(did, 'hetzner-42')
        self.assertTrue(frag['agentless'])
        self.assertEqual(frag['ip'], '10.0.0.2')


class TestCloudSync(_HandlerBase):
    """W6-44: shared import runner + mark-gone reconcile."""

    def test_mark_gone_decommissions(self):
        # one existing cloud device that WON'T be returned this run
        api.save(api.DEVICES_FILE, {
            'hetzner-1': {'name': 'old', 'source': 'cloud:hetzner',
                          'cloud': {'provider': 'hetzner'}, 'agentless': True}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        saved = api._cloud_fetch_instances
        # fetch returns a DIFFERENT device (hetzner-2), so hetzner-1 is "gone"
        api._cloud_fetch_instances = lambda a: (
            {'hetzner-2': {'name': 'new', 'source': 'cloud:hetzner',
                           'cloud': {'provider': 'hetzner'}, 'agentless': True}}, None)
        try:
            res = api._cloud_import_run([{'provider': 'hetzner'}], 'jakob', mark_gone=True)
        finally:
            api._cloud_fetch_instances = saved
        self.assertEqual(res['imported'], 1)
        self.assertEqual(res['decommissioned'], 1)
        devs = api.load(api.DEVICES_FILE)
        self.assertTrue(devs['hetzner-1']['decommissioned'])
        self.assertIn('hetzner-2', devs)

    def test_error_run_does_not_decommission(self):
        api.save(api.DEVICES_FILE, {
            'hetzner-1': {'name': 'x', 'source': 'cloud:hetzner',
                          'cloud': {'provider': 'hetzner'}, 'agentless': True}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        saved = api._cloud_fetch_instances
        api._cloud_fetch_instances = lambda a: ({}, 'API error')
        try:
            res = api._cloud_import_run([{'provider': 'hetzner'}], 'jakob', mark_gone=True)
        finally:
            api._cloud_fetch_instances = saved
        self.assertEqual(res['decommissioned'], 0)   # never reconcile on error
        self.assertFalse(api.load(api.DEVICES_FILE)['hetzner-1'].get('decommissioned'))


def _load_agent():
    s = importlib.util.spec_from_file_location(
        "rpagent_w6", ROOT / "client" / "remotepower-agent.py")
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


class TestImageCves(_HandlerBase):
    """W6-34: trivy container-image CVE scan (agent parse + server aggregate)."""

    def setUp(self):
        super().setUp()
        self._icf = api.IMAGE_CVE_FILE
        api.IMAGE_CVE_FILE = self.d / 'image_cves.json'

    def tearDown(self):
        api.IMAGE_CVE_FILE = self._icf
        super().tearDown()

    def test_agent_parses_trivy_json(self):
        agent = _load_agent()
        report = ('{"Results":[{"Target":"x","Vulnerabilities":['
                  '{"VulnerabilityID":"CVE-1","PkgName":"openssl","Severity":"CRITICAL",'
                  '"InstalledVersion":"1.0","FixedVersion":"1.1"},'
                  '{"VulnerabilityID":"CVE-2","PkgName":"bash","Severity":"HIGH"},'
                  '{"VulnerabilityID":"CVE-3","PkgName":"zlib","Severity":"MEDIUM"}]}]}')

        class _P:
            returncode = 0
            stdout = report
        import subprocess
        orig_run, orig_which = subprocess.run, agent._which
        subprocess.run = lambda *a, **k: _P()
        agent._which = lambda prog, _cache={}: '/usr/bin/trivy'
        try:
            rows = agent.collect_image_cves(['nginx:latest'])
        finally:
            subprocess.run = orig_run
            agent._which = orig_which
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['critical'], 1)
        self.assertEqual(rows[0]['high'], 1)
        self.assertEqual(rows[0]['medium'], 1)
        self.assertEqual(len(rows[0]['top']), 2)   # only CRITICAL+HIGH in top

    def test_agent_skips_without_trivy(self):
        agent = _load_agent()
        orig = agent._which
        agent._which = lambda prog, _cache={}: None
        try:
            self.assertEqual(agent.collect_image_cves(['nginx']), [])
        finally:
            agent._which = orig

    def test_server_ingest_and_aggregate(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'h1'}, 'd2': {'name': 'h2'}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        api._ingest_image_cves('d1', [{'image': 'nginx:latest', 'critical': 2, 'high': 1,
                                       'medium': 0, 'top': [{'id': 'CVE-1', 'severity': 'CRITICAL'}]}])
        api._ingest_image_cves('d2', [{'image': 'nginx:latest', 'critical': 1, 'high': 0, 'medium': 3}])
        saved = api._scope_filter_devices
        api._scope_filter_devices = lambda d: d
        try:
            out = self.call(api.handle_image_cves)
        finally:
            api._scope_filter_devices = saved
        self.assertEqual(len(out['images']), 1)
        img = out['images'][0]
        self.assertEqual(img['image'], 'nginx:latest')
        self.assertEqual(img['critical'], 3)      # 2 + 1 across hosts
        self.assertEqual(len(img['hosts']), 2)

    def test_config_saves_flag(self):
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'image_scan_enabled': True}
        try:
            api.handle_config_save()
        except api.HTTPError:
            pass
        self.assertTrue((api.load(api.CONFIG_FILE) or {}).get('image_scan_enabled'))


class TestWarrantyLookup(_HandlerBase):
    """W6-4: warranty auto-lookup framework."""

    def test_parse_lenovo(self):
        data = {'Warranty': [{'End': '2024-01-01'}, {'End': '2026-05-15T00:00:00'}]}
        self.assertEqual(api._parse_lenovo_warranty(data), '2026-05-15')
        self.assertEqual(api._parse_lenovo_warranty({}), '')

    def test_device_hw_system(self):
        dev = {'hardware': {'system': {'serial': 'PF0ABC', 'manufacturer': 'LENOVO'}}}
        serial, manuf = api._device_hw_system(dev)
        self.assertEqual(serial, 'PF0ABC')
        self.assertEqual(manuf, 'lenovo')

    def test_lookup_autofills_only_empty_or_auto(self):
        api.save(api.CONFIG_FILE, {'warranty_lookup_enabled': True, 'warranty_provider': 'lenovo',
                                   'warranty_lenovo_client_id': 'cid'})
        api.save(api.DEVICES_FILE, {
            'd1': {'hardware': {'system': {'serial': 'S1', 'manufacturer': 'Lenovo'}}},
            'd2': {'hardware': {'system': {'serial': 'S2', 'manufacturer': 'Lenovo'}}},
            'd3': {'hardware': {'system': {'serial': 'S3', 'manufacturer': 'Lenovo'}}}})
        # d2 has an OPERATOR-set date (no warranty_auto) → must NOT be clobbered.
        # d3 was previously auto-filled → may be refreshed.
        api.save(api.CMDB_FILE, {
            'd2': dict(api._cmdb_record_default(), warranty_expiry='2030-01-01'),
            'd3': dict(api._cmdb_record_default(), warranty_expiry='2020-01-01',
                       warranty_auto=True)})
        for f in (api.CONFIG_FILE, api.DEVICES_FILE, api.CMDB_FILE, api.WARRANTY_CACHE_FILE):
            api._invalidate_load_cache(f)
        saved = api._warranty_lookup_serial
        api._warranty_lookup_serial = lambda serial, cfg: '2027-12-31'
        try:
            api.run_warranty_lookup_if_due()
        finally:
            api._warranty_lookup_serial = saved
        cmdb = api._cmdb_load()
        self.assertEqual(cmdb['d1']['warranty_expiry'], '2027-12-31')   # was empty → filled
        self.assertTrue(cmdb['d1']['warranty_auto'])
        self.assertEqual(cmdb['d2']['warranty_expiry'], '2030-01-01')   # operator date kept
        self.assertEqual(cmdb['d3']['warranty_expiry'], '2027-12-31')   # auto → refreshed

    def test_noop_without_client_id(self):
        api.save(api.CONFIG_FILE, {'warranty_lookup_enabled': True, 'warranty_provider': 'lenovo'})
        api._invalidate_load_cache(api.CONFIG_FILE)
        # should return without touching anything (no credential)
        api.run_warranty_lookup_if_due()
        self.assertEqual(api.load(api.WARRANTY_CACHE_FILE) or {}, {})

    def test_config_get_withholds_client_id(self):
        api.save(api.CONFIG_FILE, {'warranty_lenovo_client_id': 'secret-cid'})
        api._invalidate_load_cache(api.CONFIG_FILE)
        api.verify_token = lambda t: ('jakob', 'admin')
        api.get_token_from_request = lambda: 't'
        out = self.call(api.handle_config_get)
        self.assertNotIn('warranty_lenovo_client_id', out)
        self.assertTrue(out['warranty_lenovo_configured'])


class TestRestoreDrills(_HandlerBase):
    """W6-43: sandboxed restore drills (agent runner + server ingest)."""

    def test_verify_restored_tree(self):
        agent = _load_agent()
        d = Path(tempfile.mkdtemp())
        (d / 'sub').mkdir()
        (d / 'sub' / 'file.txt').write_text('hello world')
        (d / 'empty').write_text('')
        nbytes, sha, count = agent._verify_restored_tree(str(d))
        self.assertEqual(nbytes, 11)      # the non-empty file wins
        self.assertEqual(len(sha), 64)
        self.assertEqual(count, 2)

    def test_verify_empty_tree(self):
        agent = _load_agent()
        d = Path(tempfile.mkdtemp())
        nbytes, sha, count = agent._verify_restored_tree(str(d))
        self.assertEqual(nbytes, 0)
        self.assertEqual(sha, '')

    def _agent_sandboxed(self):
        agent = _load_agent()
        agent.STATE_DIR = Path(tempfile.mkdtemp())
        agent._safe_state_read = lambda name: '{}'
        agent._safe_state_write = lambda name, data: None
        return agent

    def test_drill_tool_missing(self):
        agent = self._agent_sandboxed()
        orig = agent._which
        agent._which = lambda prog, _cache={}: None
        try:
            rows = agent.run_restore_drills([{
                'path': '/backups/x.tar', 'tool': 'tar', 'restore_drill_enabled': True,
                'restore_sample_path': 'etc/hostname', 'restore_drill_max_age_hours': 168}])
        finally:
            agent._which = orig
        self.assertEqual(rows[0]['drill_status'], 'tool_missing')

    def test_drill_ok(self):
        agent = self._agent_sandboxed()
        import subprocess
        orig_run, orig_which = subprocess.run, agent._which
        agent._which = lambda prog, _cache={}: '/bin/tar'

        class _P:
            returncode = 0
            stdout = stderr = ''

        def _fake_run(cmd, **kw):
            # tar -xf <archive> -C <sandbox> <member> — write a file into -C dir
            if '-C' in cmd:
                sandbox = cmd[cmd.index('-C') + 1]
                (Path(sandbox) / 'restored.bin').write_bytes(b'x' * 500)
            return _P()
        subprocess.run = _fake_run
        try:
            rows = agent.run_restore_drills([{
                'path': '/backups/x.tar', 'tool': 'tar', 'restore_drill_enabled': True,
                'restore_sample_path': 'etc/hostname', 'restore_drill_max_age_hours': 168}])
        finally:
            subprocess.run = orig_run
            agent._which = orig_which
        self.assertEqual(rows[0]['drill_status'], 'ok')
        self.assertEqual(rows[0]['restored_bytes'], 500)
        self.assertTrue(rows[0]['sha256'])

    def test_event_registered(self):
        self.assertIn('restore_drill_failed', api.EVENT_REGISTRY)
        self.assertIn('restore_drill_failed',
                      api.EVENT_REGISTRY['restore_drill_ok'].get('resolves', ()))


if __name__ == '__main__':
    unittest.main()

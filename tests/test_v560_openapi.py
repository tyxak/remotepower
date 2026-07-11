"""v5.6.0 — the OpenAPI spec must cover the WHOLE API surface.

Before v5.6.0 only the literal `_build_exact_routes()` table was stubbed; every
prefix (`pi.startswith`) and templated (`{id}`) route — ~280 of them, including
every device sub-resource and whole new subsystems (virt, tickets, billing,
blueprints, wg, scoped-creds, alert-mutes) — was silently undocumented, and no
test caught it. `_dispatcher_routes()` now parses the dispatcher chain and feeds
those routes to the stubber (which handles templated paths). This pins it.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-oas-'))
_CGI = Path(__file__).parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

_a = importlib.util.spec_from_file_location('api_oas', _CGI / 'api.py')
api = importlib.util.module_from_spec(_a)
_a.loader.exec_module(api)
import openapi_spec


def _spec():
    routes = list(api._build_exact_routes().keys()) + api._dispatcher_routes()
    return openapi_spec.build_spec(api.SERVER_VERSION, routes=routes)


class TestFullSurfaceCoverage(unittest.TestCase):
    def setUp(self):
        self.paths = _spec()['paths']

    def test_dispatcher_routes_extracted(self):
        # the parser must find the bulk of the prefix/templated surface
        self.assertGreater(len(api._dispatcher_routes()), 150,
                           'dispatcher route extraction looks broken')

    def test_covers_the_whole_surface(self):
        self.assertGreater(len(self.paths), 400,
                           'spec should cover the whole API surface')

    def test_new_subsystems_documented(self):
        # each previously-zero-presence subsystem now has a spec entry
        for p in ('/virt/{id}/power', '/virt/platforms', '/tickets/{id}',
                  '/invoices/{id}', '/provisioning/blueprints/{id}',
                  '/alert-mutes/{id}', '/scoped-credentials/{id}', '/kb/{id}',
                  '/contacts/{id}'):
            self.assertIn(p, self.paths, f'{p} missing from OpenAPI spec')

    def test_device_subresources_documented(self):
        for p in ('/devices/{device_id}/checks', '/devices/{device_id}/metrics',
                  '/devices/{device_id}/drift', '/devices/{device_id}/firewall-rule'):
            self.assertIn(p, self.paths, f'{p} missing from OpenAPI spec')

    def test_chain_only_literals_documented(self):
        for p in ('/fleet/health', '/compliance', '/inventory/search',
                  '/ai/rag/search'):
            self.assertIn(p, self.paths, f'{p} missing from OpenAPI spec')

    def test_templated_stub_declares_path_params(self):
        op = self.paths['/tickets/{id}'].get('get') or self.paths['/tickets/{id}'].get('delete')
        names = {p['name'] for p in op.get('parameters', []) if p.get('in') == 'path'}
        self.assertIn('id', names, 'templated stub must declare its path parameter')

    def test_virt_richly_documented(self):
        # _path_virt() gives virt a real schema, not just a stub
        post = self.paths['/virt/{id}/power']['post']
        self.assertEqual(post['tags'], ['Virtualization'])
        self.assertIn('requestBody', post)


class TestRefsAreValidCodegenTargets(unittest.TestCase):
    """v6.1.1 (#43) -- /reboot, /upgrade-device and /update-device used to
    $ref "#/paths/~1shutdown/post/requestBody" / ".../responses". OpenAPI's
    requestBody field DOES support a $ref, but only into
    components/requestBodies (or an inline object) -- a $ref into #/paths/...
    is not a valid target for any spec-consuming tool. This broke
    `openapi-python-client generate` outright (confirmed live this session)
    before the fix, i.e. it would break ANY strict OpenAPI-consuming tool,
    not just that one. A whole `responses` MAP has no valid $ref target at
    all in OpenAPI 3.x (only individual components/responses entries do),
    so that half was fixed differently -- a shared Python helper returning a
    fresh inline dict per operation, not a spec-level $ref."""

    def setUp(self):
        self.spec = openapi_spec.build_spec(api.SERVER_VERSION,
                                            routes=list(api._build_exact_routes().keys()))
        self.paths = self.spec['paths']

    def test_no_ref_points_into_paths(self):
        # A $ref into #/paths/... is invalid everywhere in this spec, not
        # just the 3 sites that used to do it -- guard the whole surface.
        def _walk(node, where):
            if isinstance(node, dict):
                ref = node.get('$ref')
                if isinstance(ref, str):
                    self.assertFalse(ref.startswith('#/paths/'),
                                     f'{where}: invalid $ref into #/paths/ ({ref!r})')
                for k, v in node.items():
                    _walk(v, f'{where}.{k}')
            elif isinstance(node, list):
                for i, v in enumerate(node):
                    _walk(v, f'{where}[{i}]')
        _walk(self.spec, 'spec')

    def test_device_command_endpoints_share_one_request_body_component(self):
        component = self.spec['components']['requestBodies']['DeviceCommand']
        self.assertIn('device_id', component['content']['application/json']['schema']['properties'])
        for p in ('/shutdown', '/reboot', '/upgrade-device', '/update-device'):
            self.assertEqual(self.paths[p]['post']['requestBody'],
                             {'$ref': '#/components/requestBodies/DeviceCommand'},
                             f'{p} should reuse the shared DeviceCommand request body')

    def test_device_command_endpoints_have_consistent_responses(self):
        for p in ('/shutdown', '/reboot', '/upgrade-device', '/update-device'):
            responses = self.paths[p]['post']['responses']
            self.assertEqual(set(responses), {'200', '400', '401'})
            self.assertEqual(responses['200']['content']['application/json']['schema'],
                             {'$ref': '#/components/schemas/Ok'})


if __name__ == '__main__':
    unittest.main()

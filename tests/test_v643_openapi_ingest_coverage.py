#!/usr/bin/env python3
"""The spec documented 661 paths and not the one every agent calls.

`_dispatcher_routes()` reconstructs a path only when its branch carries an
explicit `m == '<VERB>'`. Routes that accept any method are skipped — documented
behaviour, and exactly why nobody noticed that five of them were missing from
the published API spec:

    /heartbeat            every agent in the fleet, every poll interval
    /syslog/in/{token}    what an operator points a syslog forwarder at
    /snmp/trap/{token}    ditto, for trap sinks
    /webhook/in/{token}   ditto, for third-party webhooks
    /itsm/in/{token}      ditto, for ticket systems

A spec that is complete everywhere except the endpoints people integrate
against is complete where it does not matter. Found by extracting every
`GET/POST /api/...` from docs/*.md and checking each against the spec — which
took SIX attempts to get right (route table vs dispatcher, templated vs literal,
and finally the fact that spec paths are relative to the `/api` server base, so
comparing them to the full path reported 313 phantom gaps).
"""
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v643spec-'))
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))

import importlib.util  # noqa: E402
_spec = importlib.util.spec_from_file_location(
    'api_v643_spec', _ROOT / 'server' / 'cgi-bin' / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('api', api)
_spec.loader.exec_module(api)
import openapi_spec as osp  # noqa: E402

MUST_BE_DOCUMENTED = {
    '/heartbeat': 'the endpoint every agent calls on every poll',
    '/syslog/in/{token}': 'the syslog ingest an operator configures a forwarder against',
    '/snmp/trap/{token}': 'the SNMP trap sink',
    '/webhook/in/{token}': 'inbound webhooks from third-party systems',
    '/itsm/in/{token}': 'inbound ITSM ticket events',
}


def _paths():
    routes = list(api._build_exact_routes().keys()) + api._dispatcher_routes()
    return osp.build_spec(api.SERVER_VERSION, routes)['paths']


class TestTheIntegrationSurfaceIsDocumented(unittest.TestCase):
    def setUp(self):
        self.paths = _paths()

    def test_the_spec_is_substantial(self):
        """Positive control: a spec that failed to build would make every
        membership assertion below fail for the wrong reason, and an empty one
        would make an absence assertion pass for the wrong reason."""
        self.assertGreater(len(self.paths), 600)

    def test_every_any_method_route_people_integrate_with_is_present(self):
        missing = sorted(p for p in MUST_BE_DOCUMENTED if p not in self.paths)
        self.assertEqual(missing, [], '\n'.join([
            'These paths are absent from the OpenAPI spec:',
            *(f'  {p} — {MUST_BE_DOCUMENTED[p]}' for p in missing),
            '',
            'They accept any method, so _dispatcher_routes() skips them by '
            'design. Add a hand-written path in _path_ingest().']))

    def test_the_heartbeat_documents_its_credential(self):
        """A spec entry that omits how to authenticate is a stub, not
        documentation — and this is the one endpoint every integrator meets."""
        hb = self.paths['/heartbeat']['post']
        self.assertIn('security', hb)
        self.assertTrue(hb.get('requestBody'))
        self.assertIn('401', hb['responses'])

    def test_each_ingest_path_documents_its_token(self):
        for p in ('/syslog/in/{token}', '/snmp/trap/{token}',
                  '/webhook/in/{token}', '/itsm/in/{token}'):
            with self.subTest(path=p):
                op = self.paths[p]['post']
                names = [q['name'] for q in op.get('parameters', [])]
                self.assertIn('token', names)
                self.assertIn('403', op['responses'],
                              'an unknown ingest token must be a documented outcome')

    def test_the_bare_array_ingest_shapes_are_documented(self):
        """CLAUDE.md carves these out of the get_json_obj() sweep because they
        legitimately accept a top-level JSON ARRAY. If the spec only describes
        the object form, an integrator writing to the spec sends the shape the
        handler was carved out to keep supporting — and never learns the other
        one exists."""
        for p in ('/syslog/in/{token}', '/snmp/trap/{token}'):
            with self.subTest(path=p):
                self.assertIn('array', self.paths[p]['post']['description'].lower())


# DELIBERATELY NOT A TEST YET — the reverse check, "does every documented
# endpoint exist", is written and does not ship. Pointed at the spec it
# reported 313 phantom gaps (spec paths are relative to the /api base);
# pointed at the real route table it reports 48, and spot-checking those shows
# most ARE real routes that `_dispatcher_routes()` cannot reconstruct —
# multi-segment templated paths like /virt/{id}/vms, and any-method branches.
#
# So the honest finding is that the reconstructor under-reports the surface by
# roughly 48 paths, not that the docs are wrong. Shipping a 48-entry failing
# gate I cannot adjudicate is how a gate gets switched off, taking the working
# half with it. Recorded as open work instead; the ingest coverage above is
# the part that was verified and fixed.

if __name__ == '__main__':
    unittest.main()

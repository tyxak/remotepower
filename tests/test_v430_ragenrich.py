#!/usr/bin/env python3
"""v4.3.0: RAG live-state enrichment — index the operational state the AI most
needs ("what's wrong with the fleet"): open alerts (per device + a fleet
rollup) and local TLS cert expiry, on top of the existing summary / hardware /
ports / patches / drift / cves / containers / snmp chunks.
"""
import importlib.util
import inspect
import os
import sys
import tempfile
from pathlib import Path
import unittest

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

_ri_spec = importlib.util.spec_from_file_location("rag_index_e", _CGI / "rag_index.py")
ri = importlib.util.module_from_spec(_ri_spec)
_ri_spec.loader.exec_module(ri)

_api_spec = importlib.util.spec_from_file_location("api_rage", _CGI / "api.py")
api = importlib.util.module_from_spec(_api_spec)
_api_spec.loader.exec_module(api)


class TestLiveStateIndexesNewFacets(unittest.TestCase):
    def _build(self):
        devices = [{
            'id': 'web01', 'name': 'web01',
            'sysinfo': {'cert_files': [{'path': '/etc/ssl/x.pem',
                                        'not_after': '2026-09-01'}]},
        }]
        facets = {'web01': {
            'open_alerts': ['[high] Device offline', '[medium] Disk / above 90%'],
            'cert_expiry': [{'path': '/etc/ssl/x.pem', 'not_after': '2026-09-01'}],
            'services': [{'unit': 'nginx.service', 'active': 'active'}],
        }}
        return {d['id']: d for d in
                ri.build_live_state_corpus(devices, facets=facets, now=1000)}

    def test_open_alerts_chunk(self):
        docs = self._build()
        self.assertIn('live/web01#open_alerts', docs)
        self.assertIn('Device offline', docs['live/web01#open_alerts']['text'])

    def test_cert_expiry_chunk(self):
        docs = self._build()
        self.assertIn('live/web01#cert_expiry', docs)
        self.assertIn('2026-09-01', docs['live/web01#cert_expiry']['text'])

    def test_services_chunk_comes_from_the_facet_exactly_once(self):
        # Unit state is supplied by the caller from services.json. It used to
        # ALSO be read inline off dev['services'] — a key no producer writes,
        # falling back to the configured watch list — so the chunk either
        # duplicated or described the wrong thing. One source, one chunk.
        devices = [{'id': 'web01', 'name': 'web01',
                    'services': [{'unit': 'ghost.service', 'active': 'active'}]}]
        facets = {'web01': {'services': [{'unit': 'nginx.service',
                                          'active': 'active'}]}}
        docs = ri.build_live_state_corpus(devices, facets=facets, now=1)
        ids = [d['id'] for d in docs]
        self.assertEqual(ids.count('live/web01#services'), 1)
        text = next(d for d in docs if d['id'] == 'live/web01#services')['text']
        self.assertIn('nginx.service', text)
        self.assertNotIn('ghost.service', text)   # the record is not a source
        # With no facet there is no chunk, rather than one built from a key
        # nothing writes.
        self.assertNotIn('live/web01#services',
                         [d['id'] for d in
                          ri.build_live_state_corpus(devices, facets={}, now=1)])

    def test_fleet_rollup_doc(self):
        d = ri.make_doc('live/fleet#open_alerts', 'live_state', 'fleet_alerts',
                        'Fleet open alerts:\n- web01: device_offline [high]',
                        title='Fleet — open alerts', device=None, ts=1)
        self.assertEqual(d['id'], 'live/fleet#open_alerts')
        self.assertIsNone(d['device'])


class TestCmdbDocumentationIsIndexed(unittest.TestCase):
    """CRITICAL: the per-asset CMDB Documentation attachments (Markdown docs)
    must be fed to RAG. Proven end-to-end: store shape → corpus chunks →
    wired into the reindex by default → credentials vault excluded."""

    def _cmdb(self):
        return {'web01': {
            'function': 'web frontend',
            'docs': [{
                'id': 'a1b2c3', 'title': 'Runbook: restart procedure',
                'body': "# Restart\nStop nginx, flush cache, start nginx.\n\n"
                        "## Rollback\nRestore /etc/nginx from backup.",
                'updated_at': 123,
            }],
            # secret subtree that MUST NOT be indexed
            'credentials': {'root_pw': 'hunter2'},
        }}

    def test_doc_body_becomes_chunks(self):
        docs = ri.build_cmdb_corpus(self._cmdb())
        doc_chunks = [d for d in docs if d['type'] == 'cmdb_doc']
        self.assertTrue(doc_chunks, 'CMDB documentation produced no cmdb_doc chunks')
        joined = '\n'.join(d['text'] for d in doc_chunks)
        self.assertIn('Stop nginx, flush cache', joined)
        self.assertIn('Restore /etc/nginx from backup', joined)   # second heading too
        # device association (so "docs on web01" retrieves it)
        self.assertTrue(all(d['device'] == 'web01' for d in doc_chunks))

    def test_credentials_vault_never_indexed(self):
        docs = ri.build_cmdb_corpus(self._cmdb())
        blob = '\n'.join(d['text'] for d in docs)
        self.assertNotIn('hunter2', blob)
        self.assertNotIn('root_pw', blob)

    def test_resolve_device_remaps_store_key(self):
        # The CMDB store may be keyed by internal id while live_state keys by a
        # canonical id — the resolver must remap so docs attach to the host.
        store = {'internal-xyz': {'docs': [{'id': 'd1', 'title': 't',
                                            'body': 'hello'}]}}
        docs = ri.build_cmdb_corpus(store, resolve_device=lambda k: 'web01')
        self.assertTrue(any(d['device'] == 'web01' for d in docs))

    def test_reindex_wires_cmdb_with_resolver(self):
        src = inspect.getsource(api._rag_build_corpus)
        self.assertIn('build_cmdb_corpus', src)
        self.assertIn('resolve_device=resolve_dev', src)
        self.assertIn("sources.get('cmdb')", src)

    def test_cmdb_source_on_by_default(self):
        # The default rag config must enable the cmdb source.
        defaults = inspect.getsource(api)
        # the default block sets 'cmdb': True
        self.assertRegex(defaults, r"'cmdb':\s*True")


class TestReindexCallerWiring(unittest.TestCase):
    def test_caller_gathers_new_facets(self):
        src = inspect.getsource(api._rag_build_corpus)
        self.assertIn("open_alerts", src)
        self.assertIn("cert_expiry", src)
        self.assertIn("live/fleet#open_alerts", src)
        # open = unresolved
        self.assertIn("a.get('resolved_at')", src)

    def test_caller_supplies_services_from_its_own_store(self):
        # Inverted at v7.0.2: the corpus builder no longer reads a `services`
        # key off the device record (nothing writes one), so the caller is now
        # the only source and must read the live store.
        src = inspect.getsource(api._rag_build_corpus)
        self.assertIn("f['services']", src)
        self.assertIn("SERVICES_FILE", src)

    def test_ai_chat_retrieves_rag(self):
        self.assertIn('_rag_retrieve', inspect.getsource(api.handle_ai_chat))


if __name__ == '__main__':
    unittest.main()

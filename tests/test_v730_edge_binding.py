#!/usr/bin/env python3
"""v7.3.0: what the edge sources and the Cloudflare list hold reaches the surfaces
that read the rest of the fleet's posture.

Threat intel's host data was bound to the AI index, the Data Explorer, the report,
the metrics export and the timeline in v7.1.0. The edge feeds and the IP list were
added after that, and none of those surfaces knew them: an address only the edge
saw has no host, so every host-keyed reader skipped it, and "is the honeypot
catching anything", "which addresses are in the blocklist" and "has the Cloudflare
feed stopped" could not be asked of the assistant, the explorer or Prometheus.

Each surface is driven for real against one seeded store. The edge belongs to the
instance, so every surface is also checked from the other side: a reader who is
not the platform operator gets none of it.
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v730eb-'))
_CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

import prometheus_export  # noqa: E402
import rag_index  # noqa: E402

TRAP = '192.0.2.20'     # only the honeypot saw it; reported; in the list
CF = '192.0.2.24'       # only Cloudflare saw it; not reported
HOST = '185.220.101.7'  # a host's own brute-force source


def _fresh_api():
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v730eb-api-')
    spec = importlib.util.spec_from_file_location('api_v730eb', _CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Seeded(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = api = _fresh_api()
        now = int(time.time())
        cls.now = now
        api.save(api.DEVICES_FILE, {
            'd1': {'name': 'web01', 'os': 'Debian 12', 'last_seen': now}})
        ev_trap = {'ip': TRAP, 'first': now - 600, 'last': now - 60, 'ans': 0, 'blk': 0,
                   'ban': [], 'dec': 0, 'trp': 1, 'cve': [], 'src': {'trap': 3},
                   'tok': {'trap': {'trap:bait': 3}}}
        api.save(api.IPINTEL_FILE, {
            'attackers': {
                TRAP: {'verdict': {'score': 88, 'country': 'NL', 'isp': 'Sample Telecom'},
                       'devices': {'edge:trap': {'count': 3, 'unit': 'edge-feed', 'at': now - 60}},
                       'reported': {'abuseipdb': now - 60}, 'last_seen': now - 60,
                       'in_list': now - 30, 'ev': ev_trap},
                CF: {'verdict': {'score': 21, 'country': 'RU'},
                     'devices': {'edge:cloudflare': {'count': 5, 'unit': 'edge-feed', 'at': now - 90}},
                     'last_seen': now - 90},
                HOST: {'verdict': {'score': 100},
                       'devices': {'d1': {'count': 30, 'unit': 'sshd.service', 'at': now}},
                       'last_seen': now},
            },
            'blocks': {},
            'edge': {'polled': now - 120,
                     'cf': {'state': 'ok', 'at': now - 120, 'rows': 38, 'kept': 16,
                            'ignored': {'not_a_refusal': 57}},
                     'trap': {'state': 'refused', 'at': now - 3000, 'hits': 0, 'kept': 0,
                              'error': 'Authentication error'}},
            'edgelist': {'last': {'mode': 'apply', 'at': now - 900, 'state': 'ok',
                                  'list': {'name': 'remotepower_blocklist', 'items': 168},
                                  'added': 12, 'removed': 3, 'kept': {'own': 9, 'abuseipdb': 118}}},
            'edgeban': {'203.0.113.40': {'at': now - 3600, 'until': now + 3600, 'by': 'alice'},
                        '203.0.113.41': {'at': now - 9000, 'until': now - 10, 'by': 'alice'}},
        })
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg['ip_intel'] = {'edge_enabled': True, 'edgelist_enabled': True}
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()
        api.get_token_from_request = lambda: 'tok'
        api.verify_token = lambda _t=None: ('alice', 'admin')


class TestRag(_Seeded):
    def _docs(self):
        return rag_index.build_threats_corpus(
            self.api._load_ro(self.api.DEVICES_FILE),
            intel=self.api.load(self.api.IPINTEL_FILE), now=self.now)

    def test_the_feeds_and_the_list_are_described(self):
        by_id = {d['id']: d for d in self._docs()}
        self.assertIn('live/fleet#edge_sources', by_id)
        text = by_id['live/fleet#edge_sources']['text']
        self.assertIn('Cloudflare firewall events: reading normally', text)
        self.assertIn('the honeypot Worker log: refused by Cloudflare', text)
        self.assertIn('Authentication error', text)
        self.assertIn('Edge blocklist (remotepower_blocklist): ok', text)
        self.assertIn('168 entries now', text)
        self.assertIn('1 address(es) banned at the edge', text,
                      'the expired ban must not be counted')
        self.assertIsNone(by_id['live/fleet#edge_sources']['device'])

    def test_an_address_only_the_edge_saw_is_listed_with_what_was_done_about_it(self):
        by_id = {d['id']: d for d in self._docs()}
        text = by_id['live/fleet#edge_addresses']['text']
        self.assertIn(f'{TRAP}: reputation 88/100', text)
        self.assertIn('probing for exposed files', text)
        self.assertIn('seen by the honeypot', text)
        self.assertIn('reported to abuseipdb', text)
        self.assertIn('in the edge blocklist', text)
        self.assertIn(f'{CF}: reputation 21/100', text)
        self.assertIn('not reported', text)
        self.assertNotIn(HOST, text, 'a host-seen address belongs to the host docs')

    def test_junk_in_the_store_is_not_a_crash(self):
        for junk in ({}, None, [], {'edge': 'x', 'edgelist': [], 'edgeban': 5,
                                     'attackers': {'1.2.3.4': 'z', '5.6.7.8': {'devices': 'x'}}}):
            with self.subTest(junk=str(junk)[:30]):
                self.assertIsInstance(rag_index.build_edge_threats_corpus(junk, now=1), list)


class TestDataExplorer(_Seeded):
    def _rows(self):
        return self.api._qe_attackers_rows()

    def test_the_operator_asks_about_the_edge(self):
        rows = {(r['ip'], r['device_id']): r for r in self._rows()}
        r = rows[(TRAP, 'edge:trap')]
        self.assertEqual(r['source'], 'edge')
        self.assertEqual(r['device_name'], 'Edge honeypot')
        self.assertTrue(r['in_edge_list'])
        self.assertEqual(r['reported_to'], 'abuseipdb')
        self.assertIn('probe', r['classes'])
        self.assertFalse(rows[(CF, 'edge:cloudflare')]['reported'])
        self.assertEqual(rows[(HOST, 'd1')]['source'], 'host')

    def test_the_query_engine_filters_on_the_new_columns(self):
        st, d = self.api._query_run_one({'entity': 'attackers', 'where': {
            'field': 'in_edge_list', 'op': 'eq', 'value': True}})
        self.assertEqual(st, 200, d)
        self.assertEqual({r['ip'] for r in d['rows']}, {TRAP})
        st, d = self.api._query_run_one({'entity': 'attackers', 'where': {
            'field': 'source', 'op': 'eq', 'value': 'edge'}})
        self.assertEqual({r['ip'] for r in d['rows']}, {TRAP, CF})

    def test_everyone_else_gets_host_rows_only(self):
        for who, role in (('bob', 'viewer'), ('carol', 'auditor')):
            self.api.verify_token = lambda _t=None, w=who, r=role: (w, r)
            try:
                rows = self._rows()
            finally:
                self.api.verify_token = lambda _t=None: ('alice', 'admin')
            self.assertEqual({r['device_id'] for r in rows}, {'d1'}, role)
            self.assertTrue(all(r['in_edge_list'] is None and r['edge_banned'] is None
                                for r in rows), role)

    def test_a_tenant_admin_is_not_the_platform_operator(self):
        saved = {k: getattr(self.api, k) for k in ('_tenancy_enforced', '_caller_is_superadmin')}
        self.api._tenancy_enforced = lambda: True
        self.api._caller_is_superadmin = lambda: False
        try:
            rows = self._rows()
        finally:
            for k, v in saved.items():
                setattr(self.api, k, v)
        self.assertNotIn('edge', {r['source'] for r in rows})


class TestMetrics(_Seeded):
    def _text(self, visible=None):
        return prometheus_export.generate_metrics(self.api._build_metrics_ctx(visible=visible))

    def test_the_families_are_exported(self):
        out = self._text()
        self.assertIn('remotepower_edge_feed_up{feed="cloudflare"} 1', out)
        self.assertIn('remotepower_edge_feed_up{feed="honeypot"} 0', out,
                      'a refused feed must read as down')
        self.assertIn('remotepower_edge_blocklist_entries 168', out)
        self.assertIn('remotepower_edge_blocklist_held 0', out)
        self.assertIn('remotepower_edge_bans_active 1', out)
        self.assertRegex(out, r'remotepower_edge_feed_age_seconds\{feed="honeypot"\} 3\d\d\d')

    def test_a_held_sync_reads_as_held(self):
        st = self.api.load(self.api.IPINTEL_FILE)
        st['edgelist']['last']['state'] = 'held'
        self.api.save(self.api.IPINTEL_FILE, st)
        self.api._LOAD_CACHE.clear()
        try:
            out = self._text()
        finally:
            st['edgelist']['last']['state'] = 'ok'
            self.api.save(self.api.IPINTEL_FILE, st)
            self.api._LOAD_CACHE.clear()
        self.assertIn('remotepower_edge_blocklist_held 1', out)

    def test_off_means_absent(self):
        cfg = self.api.load(self.api.CONFIG_FILE)
        saved = dict(cfg['ip_intel'])
        cfg['ip_intel'] = {}
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api._LOAD_CACHE.clear()
        try:
            out = self._text()
        finally:
            cfg['ip_intel'] = saved
            self.api.save(self.api.CONFIG_FILE, cfg)
            self.api._LOAD_CACHE.clear()
        self.assertNotIn('remotepower_edge_feed_up', out)
        self.assertNotIn('remotepower_edge_blocklist_entries', out)

    def test_a_scoped_reader_does_not_get_the_instances_edge(self):
        self.api.verify_token = lambda _t=None: ('bob', 'viewer')
        try:
            out = self._text(visible={'d1'})
        finally:
            self.api.verify_token = lambda _t=None: ('alice', 'admin')
        self.assertNotIn('remotepower_edge_', out)


class TestReport(_Seeded):
    def test_the_report_carries_the_edge_for_an_unrestricted_reader(self):
        rep = self.api._build_fleet_report()
        eg = rep['threats']['edge']
        self.assertEqual((eg['seen'], eg['reported'], eg['in_list'], eg['bans']), (2, 1, 1, 1))
        self.assertEqual(eg['list_entries'], 168)
        csv = self.api._fleet_report_csv_bytes(rep).decode()
        self.assertIn('Addresses seen at the edge', csv)
        _subj, body = self.api._render_report_email(rep)
        self.assertIn('2 address(es) seen, 1 reported, 1 in the Cloudflare list', body)

    def test_a_site_report_has_none(self):
        rep = self.api._build_fleet_report(site_id='nowhere')
        self.assertIsNone(rep['threats']['edge'])

    def test_a_tenant_admin_gets_none(self):
        saved = {k: getattr(self.api, k) for k in ('_tenancy_enforced', '_caller_is_superadmin',
                                                   '_caller_tenant')}
        self.api._tenancy_enforced = lambda: True
        self.api._caller_is_superadmin = lambda: False
        self.api._caller_tenant = lambda *a, **k: 'acme'
        try:
            rep = self.api._build_fleet_report()
        finally:
            for k, v in saved.items():
                setattr(self.api, k, v)
        self.assertIsNone(rep['threats']['edge'])


class TestTimeline(_Seeded):
    def test_a_ban_and_a_list_change_are_timeline_events(self):
        for action in ('ip_intel_ban', 'ip_intel_unban', 'edge_list_sync'):
            self.assertTrue(action.startswith(self.api._TIMELINE_AUDIT_PREFIXES), action)
        self.assertFalse('edge_list_preview'.startswith(self.api._TIMELINE_AUDIT_PREFIXES),
                         'a preview changes nothing')


if __name__ == '__main__':
    unittest.main()

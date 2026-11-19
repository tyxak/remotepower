"""8.0.2: the Cloudflare list is the operator's, and a tenant's host does not write to it.

The Edge blocklist keeps one IP list in the operator's Cloudflare account, and its "found by RemotePower" source takes the addresses that were reported or that
scored high from the table of addresses, whichever host saw them. The sweep already refused to copy a tenant's host block into the list ("a tenant's host does
not write to it"), and this source did not: one invented line from a tenant's host (a fail2ban jail in its summary, for an address that host never saw) was a
report, and the next sync put the address in a list that the operator's rule blocks at every zone that uses it, the other tenants' sites among them, without
the fifty an hour that edge bans are capped at.

With tenants an address is taken from the table only when the edge feeds or a host of the operator's own organisation saw it. Everything runs for real (the
intake, the sweep, the sync, the clear); the two services and Cloudflare are one small fake.
"""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v802-edgelist-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import ipintel_store  # noqa: E402
from request_harness import RequestCase  # noqa: E402

import edge_blocklist  # noqa: E402
import ip_intel  # noqa: E402
import threat_evidence  # noqa: E402

NOW = int(time.time())
ACCT, LIST_ID, OP = 'a' * 32, 'c' * 32, 'd' * 32
FROM_TENANT = '45.77.10.77'       # invented by a tenant's host, which never saw it
FROM_OTHER = '45.77.10.78'        # the same, from another tenant's host
FROM_OPERATOR = '185.220.101.7'   # a host of the operator's own organisation saw it
FROM_EDGE = '185.220.101.8'       # Cloudflare's own firewall refused it
FROM_BOTH = '185.220.101.9'       # a tenant's host and the operator's host both saw it
HOSTS = {
    'hD': {'id': 'hD', 'name': 'web-operator', 'os': 'Ubuntu 24.04', 'token': 'tokD', 'tenant': 'default', 'last_seen': NOW},
    'hA': {'id': 'hA', 'name': 'web-acme', 'os': 'Ubuntu 24.04', 'token': 'tokA', 'tenant': 'acme', 'last_seen': NOW},
    'hG': {'id': 'hG', 'name': 'web-globex', 'os': 'Ubuntu 24.04', 'token': 'tokG', 'tenant': 'globex', 'last_seen': NOW},
}


def banned(ip, src=None):
    return threat_evidence.normalize_event({'ip': ip, 'first': NOW - 60, 'last': NOW - 5, 'src': src or {'f2b': 1},
                                            'tok': {'f2b': {'jail:sshd': 1}}, 'ban': ['sshd']}, now=NOW)


def cloudflare_refused(ip):
    return threat_evidence.normalize_event({'ip': ip, 'first': NOW - 60, 'last': NOW - 5, 'src': {'cf': 3}, 'tok': {'cf': {'cf:waf': 3}}, 'blk': 3},
                                           now=NOW, families=threat_evidence.EDGE_SOURCES)


class _List(RequestCase):
    TENANCY = True

    def setUp(self):
        super().setUp()
        cfg = {'abuseipdb_api_key': 'a' * 80, 'sniffcat_api_key': 's' * 40, 'edge_list_token': 'L' * 40,
               'ip_intel': {'sensor_enabled': True, 'report_enabled': True, 'edgelist_enabled': True, 'edge_account_id': ACCT,
                            'edgelist_abuseipdb': False, 'edgelist_sniffcat': False}}
        if self.TENANCY:
            cfg['tenancy_enforced'] = True
        self.put(devices=HOSTS, **cfg)
        self.sent = []

        def http(req):
            self.sent.append(req)
            url, method = req['url'], req['method']
            if 'api.cloudflare.com' in url:
                if url.endswith('/rules/lists') and method == 'GET':
                    return 200, {'success': True, 'result': []}
                if url.endswith('/rules/lists') and method == 'POST':
                    return 200, {'success': True, 'result': {'id': LIST_ID}}
                if url.endswith('/items') and method == 'PUT':
                    return 200, {'success': True, 'result': {'operation_id': OP}}
                if 'bulk_operations' in url:
                    return 200, {'success': True, 'result': {'status': 'completed'}}
                return 200, {'success': True, 'result': {}}
            return 200, {'success': True, 'data': {}}
        self.api._ip_intel_http = http

    def note(self, dev, events):
        self.api.ip_intel_note_evidence(dev, events, {'sources': [], 'ignored': {}, 'dropped': 0}, NOW - 30)
        self.api._LOAD_CACHE.clear()

    def sweep(self):
        ipintel_store.update(self.api, last_sweep=0)
        self.api._LOAD_CACHE.clear()
        self.api.run_ip_intel_if_due()
        self.api._LOAD_CACHE.clear()

    def feed_everything(self):
        self.note('hA', [banned(FROM_TENANT), banned(FROM_BOTH)])
        self.note('hG', [banned(FROM_OTHER)])
        self.note('hD', [banned(FROM_OPERATOR), banned(FROM_BOTH)])
        self.note('edge:cloudflare', [cloudflare_refused(FROM_EDGE)])
        self.sweep()

    def uploaded(self):
        self.api.run_edge_blocklist_if_due()
        self.api._LOAD_CACHE.clear()
        puts = [r for r in self.sent if r['method'] == 'PUT' and r['url'].endswith('/items')]
        return sorted(e['ip'] for r in puts for e in json.loads(r['body']))


class TestWithTenants(_List):
    def test_the_instrument_every_address_was_reported(self):
        self.feed_everything()
        att = self.api.load(self.api.IPINTEL_FILE)['attackers']
        for ip in (FROM_TENANT, FROM_OTHER, FROM_OPERATOR, FROM_EDGE, FROM_BOTH):
            self.assertTrue(att[ip].get('reported'), f'{ip} was reported: the list reads that, and not who saw it')

    def test_an_address_only_a_tenants_host_saw_is_not_listed(self):
        self.feed_everything()
        got = self.uploaded()
        self.assertNotIn(FROM_TENANT, got)
        self.assertNotIn(FROM_OTHER, got)

    def test_what_the_edge_or_the_operators_own_hosts_saw_is_listed(self):
        self.feed_everything()
        self.assertEqual(self.uploaded(), sorted([FROM_OPERATOR, FROM_EDGE, FROM_BOTH]),
                         'the operator\'s host, the edge, and the address the operator\'s host saw as well as a tenant\'s')

    def test_the_status_counts_what_the_list_would_hold(self):
        self.feed_everything()
        res = self.api.edge_blocklist_handlers_mod._sync(self.api.ip_intel_policy(), NOW, 'preview')
        self.assertEqual(sorted(res['_listed']), sorted([FROM_OPERATOR, FROM_EDGE, FROM_BOTH]))
        self.assertEqual(res['offered']['own'], 3)

    def test_a_clear_does_not_keep_what_the_list_does_not_take(self):
        """A clear keeps a row the list takes (so the list does not shrink) and forgets the rest: it must not keep a tenant's invention."""
        self.feed_everything()
        st, body = self.call(self.api.handle_ip_intel_clear, body={}, method='POST', token='k')
        self.assertEqual(st, 200, body)
        self.api._LOAD_CACHE.clear()
        att = self.api.load(self.api.IPINTEL_FILE).get('attackers') or {}
        self.assertEqual(set(att.get(FROM_TENANT) or {}), {'reported'}, 'only the day\'s report marker stays: the row the list would read (last sighting, score) is gone')
        self.assertIn('last_seen', att.get(FROM_OPERATOR) or {}, 'what the list takes is kept by the clear')

    def test_a_row_a_clear_kept_for_the_list_is_still_listed(self):
        self.feed_everything()
        self.call(self.api.handle_ip_intel_clear, body={}, method='POST', token='k')
        self.api._LOAD_CACHE.clear()
        self.assertEqual(self.uploaded(), sorted([FROM_OPERATOR, FROM_EDGE, FROM_BOTH]))


class TestWithOneOrganisation(_List):
    TENANCY = False

    def test_every_host_is_the_operators_and_nothing_changes(self):
        self.feed_everything()
        self.assertEqual(self.uploaded(), sorted([FROM_TENANT, FROM_OTHER, FROM_OPERATOR, FROM_EDGE, FROM_BOTH]))


class TestThePredicate(unittest.TestCase):
    NOW = NOW

    @classmethod
    def setUpClass(cls):
        from test_ip_intel import _fresh_api
        cls.api = _fresh_api()
        cls.h = cls.api.ip_intel_handlers_mod

    def rows(self):
        mk = lambda devs: {'last_seen': NOW - 10, 'verdict': {'score': 90}, 'devices': {d: {'count': 1} for d in devs}}
        return {'1.1.1.1': mk(['hA']), '2.2.2.2': mk(['edge:cloudflare']), '3.3.3.3': mk(['hD']), '4.4.4.4': mk(['hA', 'hD']),
                '5.5.5.5': {'last_seen': NOW - 10, 'verdict': {'score': 90}}, '6.6.6.6': mk(['edge:trap'])}

    def listable(self, tenancy):
        self.api.save(self.api.CONFIG_FILE, {'tenancy_enforced': tenancy})
        self.api._LOAD_CACHE.clear()
        return self.h._own_listable({}, HOSTS)

    def test_with_tenants_only_the_edge_and_the_operators_hosts_count(self):
        ok = self.listable(True)
        got = {ip: ok(ip, row) for ip, row in self.rows().items()}
        self.assertEqual(got, {'1.1.1.1': False, '2.2.2.2': True, '3.3.3.3': True, '4.4.4.4': True, '5.5.5.5': True, '6.6.6.6': True})

    def test_without_tenants_every_row_is_listable(self):
        ok = self.listable(False)
        self.assertTrue(all(ok(ip, row) for ip, row in self.rows().items()))

    def test_the_function_that_chooses_asks_the_predicate_and_without_one_chooses_as_before(self):
        atts = self.rows()
        everything = edge_blocklist.own_candidates(atts, NOW, 75, 14)
        self.assertEqual(sorted(everything), sorted(atts))
        only_edge = edge_blocklist.own_candidates(atts, NOW, 75, 14, listable=lambda ip, row: 'edge:cloudflare' in (row.get('devices') or {}))
        self.assertEqual(only_edge, ['2.2.2.2'])


if __name__ == '__main__':
    unittest.main()

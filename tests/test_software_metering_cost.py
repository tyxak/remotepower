#!/usr/bin/env python3
"""Licence cost and true-up in software metering.

A metering rule had a name, a limit (the licences owned; 0 means "just count") and aliases. It can now carry the cost of one licence, and the report says for
each rule how many installs are above the licences owned (short) and what buying them costs, how many licences are above the installs (spare) and what they
cost, and adds the rules up.

Driven through the real handlers and the real dispatcher, and held to:

  * exact amounts: whole cents and `Decimal`, never a float (0.1 x 3 is 0.30, 19.99 x 3 is 59.97), with the totals worked out by hand;
  * a rule with no cost has no amount (None), a rule that is free has 0.00, a rule that owns nothing (limit 0) is neither short nor spare;
  * hostile costs (negative, 1e308, NaN, a string, three decimals, a sign, an exponent, a separator, a non-ASCII digit, a boolean, a list) refuse the whole save and
    leave the stored rules as they were; a stored cost that is not an amount (a hand edit) is read as no cost;
  * so does a cost written as a number the body reader cannot hold (NaN, Infinity, 1e999, an integer of 21 digits or more), which the reader turns into null: the save is
    told apart from "no cost" by reading the body a second time, and an explicit null, an empty text and a blank are still no cost;
  * the currency is the one of the billing settings;
  * the amounts go to an administrator and to finance of the operator's own organisation, and to nobody else: not to a viewer, not to a tenant's administrator,
    and neither the report nor `GET /api/config` carries them; the counts still go to everyone, for the hosts they may see.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-metering-cost-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import request_harness  # noqa: E402
from request_harness import RequestCase  # noqa: E402

HOSTS = {          # id -> tenant
    'm1': 'acme', 'm2': 'acme', 'm3': 'acme', 'g1': 'globex', 'g2': 'globex', 'd1': None,
}
INSTALLED = {      # package -> the hosts that have it
    'nginx': ['m1', 'm2', 'm3', 'g1'], 'teamviewer': ['m1', 'g2'], 'libssl3': ['m1'], 'openssl-libs': ['m2'], 'postgresql': ['d1', 'g1', 'g2', 'm1', 'm2'],
    'tinytool': ['m3'], 'redis': ['m1', 'm2', 'm3'], 'tools': ['m1', 'm2', 'm3', 'g1', 'g2'],
}
RULES = [
    {'name': 'nginx', 'limit': 3, 'unit_cost': '49.99'},
    {'name': 'teamviewer', 'limit': 5, 'unit_cost': '0.10'},
    {'name': 'openssl', 'limit': 0, 'unit_cost': '10.00', 'aliases': ['libssl3', 'openssl-libs']},
    {'name': 'postgresql', 'limit': 3},
    {'name': 'tinytool', 'limit': 1, 'unit_cost': '0.00'},
    {'name': 'redis', 'limit': 10, 'unit_cost': '123.45'},
    {'name': 'tools', 'limit': 2, 'unit_cost': '19.99'},
]


def host(dev_id, tenant):
    rec = {'name': dev_id, 'group': 'dev', 'monitored': True, 'last_seen': 1_800_000_000, 'sysinfo': {}}
    if tenant:
        rec['tenant'] = tenant
    return rec


class _Metering(RequestCase):

    def setUp(self):
        super().setUp()
        self.addCleanup(request_harness.TOKENS.pop, 'tf', None)
        self.addCleanup(request_harness.TENANT.pop, 'tess', None)
        request_harness.TOKENS['tf'] = ('tess', 'finance')        # a finance user of the tenant acme
        request_harness.TENANT['tess'] = 'acme'
        self.devices = {k: host(k, t) for k, t in HOSTS.items()}
        self.store(RULES)

    def store(self, rules, **cfg):
        self.api.save(self.api.DEVICES_FILE, self.devices)
        self.api.save(self.api.CONFIG_FILE, dict(cfg, software_meters=rules))
        self.api.save(self.api.PACKAGES_FILE, {k: {'packages': [{'name': n, 'version': '1.0'} for n, hosts in INSTALLED.items() if k in hosts]} for k in HOSTS})
        self.api._LOAD_CACHE.clear()

    def report(self, token='k'):
        st, out = self.request('/api/inventory/metering', token=token)
        self.assertEqual(st, 200, out)
        return out

    def rows(self, token='k'):
        return {r['name']: r for r in self.report(token)['meters']}

    def saved(self):
        self.api._LOAD_CACHE.clear()
        return self.api.load(self.api.CONFIG_FILE).get('software_meters')

    def save_rules(self, rules, token='k'):
        return self.request('/api/config', 'POST', token=token, body={'software_meters': rules})

    def save_raw(self, text, token='k'):
        """The body as raw text, for what json.dumps cannot write: 1e999, and a number of 21 digits as its sender wrote it."""
        raw = text.encode()

        def go():
            os.environ.update(PATH_INFO='/api/config')
            self.api._RCTX.stdin = raw
            self.api.main()
        try:
            return request_harness._run(self.api, go, None, method='POST', env={'HTTP_AUTHORIZATION': 'Bearer ' + token, 'QUERY_STRING': '', 'CONTENT_LENGTH': str(len(raw))})
        finally:
            self.api._RCTX.stdin = None


class TestTheAmounts(_Metering):

    def test_the_counts_and_the_amounts_of_each_rule_are_the_hand_computed_ones(self):
        r = self.rows()
        got = {n: (x['installed'], x['owned'], x['shortfall'], x['shortfall_cost'], x['surplus'], x['surplus_cost'], x['unit_cost']) for n, x in r.items()}
        self.assertEqual(got, {
            'nginx':      (4, 3, 1, '49.99', 0, '0.00', '49.99'),          # four hosts, three licences: one to buy
            'teamviewer': (2, 5, 0, '0.00', 3, '0.30', '0.10'),            # 3 x 0.10 is 0.30 and not 0.30000000000000004
            'openssl':    (2, None, None, None, None, None, '10.00'),      # limit 0 is "just count": nothing is owned, so nothing is short or spare
            'postgresql': (5, 3, 2, None, 0, None, None),                  # no cost is no amount: not 0.00
            'tinytool':   (1, 1, 0, '0.00', 0, '0.00', '0.00'),            # a cost of 0 is a rule that is free: 0.00, not nothing
            'redis':      (3, 10, 0, '0.00', 7, '864.15', '123.45'),       # 7 x 123.45
            'tools':      (5, 2, 3, '59.97', 0, '0.00', '19.99'),          # 3 x 19.99 is 59.97 and not 59.96999999999999
        })

    def test_the_fleet_total_adds_up_the_rules_that_have_a_cost_and_counts_the_ones_that_have_none(self):
        t = self.report()['totals']
        # short: 1 + 0 + 2 + 0 + 0 + 3 units, 49.99 + 0 + 0 + 0 + 59.97 = 109.96 (postgresql has no cost); spare: 0 + 3 + 0 + 0 + 7 + 0 units, 0.30 + 864.15 = 864.45
        self.assertEqual(t, {'shortfall': 6, 'surplus': 10, 'shortfall_cost': '109.96', 'surplus_cost': '864.45', 'rules_without_cost': 1})

    def test_the_currency_is_the_one_of_the_billing_settings(self):
        self.assertEqual(self.report()['currency'], 'USD', 'the default of the billing settings')
        for stored, shown in (('EUR', 'EUR'), ('NOKNOKNOKNOK', 'NOKNOKNO'), ('', 'USD'), (None, 'USD')):
            self.api.save(self.api.BILLING_FILE, {'currency': stored})
            self.api._LOAD_CACHE.clear()
            self.assertEqual(self.report()['currency'], shown, stored)

    def test_the_rules_keep_their_order_and_the_old_fields(self):
        out = self.report()['meters']
        names = [r['name'] for r in out]
        over = [r['over'] for r in out]
        self.assertEqual(over, sorted(over, reverse=True), 'the rules over their limit first')
        counts = [r['installed'] for r in out if r['over']]
        self.assertEqual(counts, sorted(counts, reverse=True), 'the most installed first among them')
        self.assertEqual(sorted(names), sorted(r['name'] for r in RULES))
        nginx = {r['name']: r for r in out}['nginx']
        self.assertEqual((nginx['limit'], nginx['over'], nginx['devices'], nginx['aliases']), (3, True, ['g1', 'm1', 'm2', 'm3'], []))
        self.assertEqual({r['name']: r for r in out}['openssl']['aliases'], ['libssl3', 'openssl-libs'])

    def test_a_stored_cost_that_is_not_an_amount_is_read_as_no_cost(self):
        self.store([{'name': 'nginx', 'limit': 3, 'unit_cost': 'abc'}, {'name': 'tools', 'limit': 2, 'unit_cost': -5}, {'name': 'redis', 'limit': 2, 'unit_cost': 1e308},
                    {'name': 'teamviewer', 'limit': 1, 'unit_cost': '49.999'}, {'name': 'postgresql', 'limit': 1, 'unit_cost': True}, {'name': 'tinytool', 'limit': 5, 'unit_cost': [1]}])
        for n, x in self.rows().items():
            self.assertEqual((x['unit_cost'], x['shortfall_cost'], x['surplus_cost']), (None, None, None), n)
        self.assertEqual(self.report()['totals']['rules_without_cost'], 6)


class TestTheCostsAreSaved(_Metering):

    def test_a_cost_is_stored_as_text_with_two_decimals_whichever_way_it_was_sent(self):
        forms = [('49.99', '49.99'), (49.99, '49.99'), (49.9, '49.90'), ('49.9', '49.90'), (50, '50.00'), ('0', '0.00'), (0, '0.00'), (0.0, '0.00'), (' 12.5 ', '12.50'),
                 ('1000000', '1000000.00'), (1000000.0, '1000000.00'), ('0.01', '0.01'), (0.1, '0.10'), ('007', '7.00'), ('1000000.00', '1000000.00')]    # a list: 0 and 0.0 are one key of a dict
        for sent, stored in forms:
            st, out = self.save_rules([{'name': 'nginx', 'limit': 3, 'unit_cost': sent}])
            self.assertEqual(st, 200, (sent, out))
            self.assertEqual(self.saved(), [{'name': 'nginx', 'limit': 3, 'unit_cost': stored}], sent)
            self.assertIsInstance(self.saved()[0]['unit_cost'], str)

    def test_no_cost_is_no_key(self):
        # an explicit null, an empty text and a blank say there is no cost. NaN, Infinity and a number of 21 digits are not null, though the body reader reads them as
        # null: they are refused (test_a_cost_the_body_reader_cannot_hold_is_refused_and_is_not_read_as_no_cost)
        for sent in (None, '', '   '):
            st, out = self.save_rules([{'name': 'nginx', 'limit': 3, 'unit_cost': sent}])
            self.assertEqual(st, 200, out)
            self.assertEqual(self.saved(), [{'name': 'nginx', 'limit': 3}], repr(sent))
        st, out = self.save_rules([{'name': 'nginx', 'limit': 3}])
        self.assertEqual((st, self.saved()), (200, [{'name': 'nginx', 'limit': 3}]))

    def test_a_cost_the_body_reader_cannot_hold_is_refused_and_is_not_read_as_no_cost(self):
        before = self.saved()
        self.assertTrue(before, 'control: there are stored rules for a refusal to leave alone')
        for cost in ('NaN', 'Infinity', '-Infinity', '1e999', '-1e999', '1E+400', '1' + '0' * 20, '9' * 40, '-' + '1' * 21, '12.5e9999'):
            with self.subTest(cost=cost[:30]):
                st, out = self.save_raw('{"software_meters":[{"name":"nginx","limit":3,"unit_cost":%s}]}' % cost)
                self.assertEqual(st, 400, (cost, out))
                self.assertIn('software meter cost', out['error'])
                self.assertEqual(self.saved(), before, 'nothing was stored')
        for sent in (float('nan'), float('inf'), -float('inf'), 10 ** 30):         # the same through json.dumps
            st, out = self.save_rules([{'name': 'nginx', 'limit': 3, 'unit_cost': sent}])
            self.assertEqual(st, 400, (sent, out))
            self.assertEqual(self.saved(), before)

    def test_the_same_numbers_anywhere_else_in_the_body_are_not_a_cost_and_are_not_refused(self):
        control = '{"software_meters":[{"name":"nginx","limit":3,"unit_cost":%s}]}'
        for cost, want in (('null', None), ('""', None), ('49.99', '49.99'), ('"49.99"', '49.99')):
            st, out = self.save_raw(control % cost)
            self.assertEqual(st, 200, (cost, out))
            self.assertEqual(self.saved(), [dict({'name': 'nginx', 'limit': 3}, **({'unit_cost': want} if want else {}))], cost)
        for text in ('{"software_meters":[{"name":"Infinity","limit":3,"unit_cost":5}]}',               # a word of the name
                     '{"software_meters":[{"name":"nginx","limit":1e999,"unit_cost":5}]}',               # a limit the reader cannot hold is 0, as it was
                     '{"software_meters":[{"name":"nginx","limit":3,"unit_cost":5,"aliases":["NaN"]}]}',
                     '{"server_name":"NaN","software_meters":[{"name":"nginx","limit":3,"unit_cost":5}]}'):
            st, out = self.save_raw(text)
            self.assertEqual(st, 200, (text, out))

    def test_the_refusal_points_at_the_meter_that_has_the_cost_and_not_at_its_neighbours(self):
        before = self.saved()
        bad = '{"software_meters":[{"name":"","limit":1,"unit_cost":NaN},{"name":"nginx","limit":3,"unit_cost":NaN}]}'
        st, out = self.save_raw(bad)
        self.assertEqual(st, 400, out)                                   # the second meter has the cost, whatever the first one is
        self.assertEqual(self.saved(), before)
        skipped = '{"software_meters":[{"name":"","limit":1,"unit_cost":NaN},{"name":"nginx","limit":3,"unit_cost":5}]}'
        st, out = self.save_raw(skipped)
        self.assertEqual(st, 200, out)                                   # a meter with no name is not kept, so it is not looked at, as before
        self.assertEqual(self.saved(), [{'name': 'nginx', 'limit': 3, 'unit_cost': '5.00'}])

    def test_a_cost_that_is_not_an_amount_refuses_the_whole_save_and_changes_nothing(self):
        before = self.saved()
        hostile = [-1, '-1', -0.01, '-0', 1e308, 'NaN', 'nan', 'inf', 'Infinity', 'abc', 'free', '49.999', 49.999, 0.30000000000000004,
                   '1e3', '1E3', 1e3 + 0.5 * 1e-3, '1,000.00', '49,99', '$49.99', '49.99 USD', '1000000.01', 1000000.01, 1e16, 10 ** 19, True, False, [], {}, [1], {'a': 1},
                   '٣٤', '４９.９９', '49.99\n49', '0x10', '1_000', '.5', '5.', '--5', '+5', '1 000', '49.99;', '49.99\x00', 'None', 'null', '0.001', 5e-324]
        for sent in hostile:
            st, out = self.save_rules([{'name': 'nginx', 'limit': 3, 'unit_cost': '10.00'}, {'name': 'tools', 'limit': 2, 'unit_cost': sent}])
            self.assertEqual(st, 400, (sent, out))
            self.assertIn('software meter cost', out['error'], sent)
            self.assertEqual(self.saved(), before, ('nothing was stored', sent))

    def test_the_old_fields_are_clamped_as_before(self):
        st, out = self.save_rules([{'name': 'a' * 300, 'limit': 5000000, 'aliases': ['x', 'x', '', 'y']}, {'name': 'b', 'limit': 'many'}, {'name': '', 'limit': 3}, 'junk'])
        self.assertEqual(st, 200, out)
        saved = self.saved()
        self.assertEqual([(len(r['name']), r['limit'], r.get('aliases'), r.get('unit_cost')) for r in saved], [(128, 1000000, ['x', 'y'], None), (1, 0, None, None)])

    def test_a_cost_round_trips_through_the_settings_the_administrator_reads(self):
        self.save_rules([{'name': 'nginx', 'limit': 3, 'unit_cost': 49.99}])
        st, out = self.request('/api/config')
        self.assertEqual((st, out['software_meters']), (200, [{'name': 'nginx', 'limit': 3, 'unit_cost': '49.99'}]))

    def test_a_tenant_administrator_cannot_save_the_rules(self):
        self.put(self.devices, tenancy_enforced=True, software_meters=RULES)
        st, out = self.save_rules([{'name': 'nginx', 'limit': 3, 'unit_cost': '1.00'}], token='ta')
        self.assertEqual(st, 403, out)
        self.assertEqual(self.saved(), RULES)


class TestWhoReadsTheCosts(_Metering):

    def money(self, token):
        out = self.report(token)
        rows = out['meters']
        any_money = any(r[k] is not None for r in rows for k in ('unit_cost', 'shortfall_cost', 'surplus_cost'))
        t = out['totals']
        return {'currency': out['currency'], 'any': any_money, 'totals': (t['shortfall_cost'], t['surplus_cost'], t['rules_without_cost'])}

    def test_an_administrator_and_finance_read_the_amounts_and_nobody_else_does(self):
        # with isolation off every administrator and every finance user is of the one organisation
        self.assertEqual({t: self.money(t)['any'] for t in ('k', 'fi', 'ta', 'tf', 'v', 'mc', 'au', 'ops', 'rw', 'ro', 'tv')},
                         {'k': True, 'fi': True, 'ta': True, 'tf': True, 'v': False, 'mc': False, 'au': False, 'ops': False, 'rw': False, 'ro': False, 'tv': False})
        for token in ('v', 'mc', 'au', 'ops', 'rw'):
            self.assertEqual(self.money(token), {'currency': None, 'any': False, 'totals': (None, None, None)}, token)
        self.assertEqual(self.money('fi')['currency'], 'USD')

    def test_with_isolation_on_the_operators_own_organisation_still_reads_them_and_a_tenant_does_not(self):
        self.put(self.devices, tenancy_enforced=True, software_meters=RULES)
        self.assertEqual({t: self.money(t)['any'] for t in ('k', 'fi', 'ta', 'tb', 'tv', 'tf', 'v')},
                         {'k': True, 'fi': True, 'ta': False, 'tb': False, 'tv': False, 'tf': False, 'v': False})

    def test_the_counts_go_to_everyone_for_the_hosts_they_may_see(self):
        self.put(self.devices, tenancy_enforced=True, software_meters=RULES)
        mine = {t: {n: (x['installed'], x['shortfall'], x['surplus'], x['devices']) for n, x in self.rows(t).items()} for t in ('ta', 'tb', 'k')}
        self.assertEqual(mine['ta']['nginx'], (3, 0, 0, ['m1', 'm2', 'm3']), 'acme: three installs against three licences')
        self.assertEqual(mine['tb']['nginx'], (1, 0, 2, ['g1']), 'globex: one install, two licences to spare')
        self.assertEqual(mine['k']['nginx'], (4, 1, 0, ['g1', 'm1', 'm2', 'm3']))
        for other in ('g1', 'g2'):
            self.assertNotIn(other, json.dumps(self.report('ta')), 'a tenant reads no host of another')
        for other in ('m1', 'm2', 'm3'):
            self.assertNotIn(other, json.dumps(self.report('tb')))

    def test_a_tenant_report_has_no_amount_anywhere_in_its_text(self):
        self.put(self.devices, tenancy_enforced=True, software_meters=RULES)
        for token in ('ta', 'tb', 'tv', 'tf', 'v'):
            text = json.dumps(self.report(token))
            for amount in ('49.99', '0.30', '864.15', '59.97', '109.96', '864.45', '123.45', '19.99'):
                self.assertNotIn(amount, text, (token, amount))

    def test_the_settings_document_carries_the_costs_to_the_same_callers_only(self):
        seen = {}
        for token in ('k', 'fi', 'v', 'mc', 'au', 'ops', 'rw', 'ro'):
            st, out = self.request('/api/config', token=token)
            self.assertEqual(st, 200, (token, out))
            seen[token] = sorted({m.get('unit_cost') for m in out['software_meters'] if m.get('unit_cost')})
        self.assertEqual(seen['k'], seen['fi'])
        self.assertIn('49.99', seen['k'])
        for token in ('v', 'mc', 'au', 'ops', 'rw', 'ro'):
            self.assertEqual(seen[token], [], token)
        st, out = self.request('/api/config', token='v')
        self.assertEqual([m['name'] for m in out['software_meters']], [r['name'] for r in RULES], 'the rules themselves are as before')

    def test_the_settings_document_of_a_tenant_has_no_cost(self):
        self.put(self.devices, tenancy_enforced=True, software_meters=RULES)
        for token in ('ta', 'tv', 'tf'):
            st, out = self.request('/api/config', token=token)
            self.assertEqual(st, 200, (token, out))
            self.assertNotIn('unit_cost', json.dumps(out), token)

    def test_a_caller_with_no_token_reads_nothing(self):
        st, out = self.request('/api/inventory/metering', token='nobody')
        self.assertEqual(st, 401, out)


if __name__ == '__main__':
    unittest.main()

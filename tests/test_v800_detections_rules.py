#!/usr/bin/env python3
"""8.0.0: Detections -- the rules (server/cgi-bin/detections.py), which are pure functions.

The fixtures come from the producers, not from hand-built dicts: a host's rows go through `traffic.clean_sample` and `traffic.merge` (so `seen`, `seen_out` and `first` are what
the server really keeps) and the events have the shape `_record_fleet_event` writes ({ts, event, payload}). Every rule has its positive case and the control that must stay quiet:
a rule that fires on everything and a rule that fires on nothing both pass a test that only has one of the two.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-detections-rules-'))
_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_TESTS.parent / 'server' / 'cgi-bin'))

import detections as D  # noqa: E402
import traffic as T  # noqa: E402

NOW = 1_900_000_000
PUB, PUB2, PUB3, LAN = '93.184.216.34', '8.8.8.8', '1.1.1.1', '10.0.0.7'
HOUR, DAY = 3600, 86400


def row(d='out', ip=PUB, port=443, proc='curl', n=1, tx=1000, rx=5000):
    return {'d': d, 'ip': ip, 'port': port, 'proc': proc, 'n': n, 'tx': tx, 'rx': rx}


def ev(name, ago, **payload):
    return {'event': name, 'ts': NOW - ago, 'payload': payload}


def ctx(rows, base=None, events=(), intel=None, first_ago=2 * HOUR, now=NOW, name='web01', seen_before=None):
    """One host's context: a first sample `first_ago` seconds back with the `base` rows (the baseline), then the sample of `rows` now. `seen_before` is a list of
    (ip, seconds ago, direction) the host used earlier still: each is merged in as a sample of its own at that time."""
    start = now - first_ago
    rec = T.merge(None, T.clean_sample({'win': 60, 'rows': base if base is not None else [row(ip=PUB3)]}, start), start)
    for ip, ago, d in sorted(seen_before or [], key=lambda t: -t[1]):
        at = now - ago
        rec = T.merge(rec, T.clean_sample({'win': 60, 'rows': [row(d=d, ip=ip)]}, at), at)
    sample = T.clean_sample({'win': 60, 'rows': rows}, now)
    rec = T.merge(rec, sample, now)
    return {'host': {'id': 'web01', 'name': name}, 'now': now, 'rec': rec, 'rows': T.stored_rows(sample), 'events': list(events), 'intel': intel or {}}


def only(findings, rule):
    return [f for f in findings if f['rule'] == rule]


def run(rule, c, **params):
    rules = D.settings({rid: {'enabled': rid == rule} for rid in D.RULES})
    for k, v in params.items():
        rules[rule][k] = v
    return D.evaluate(c, rules)


class TestTheCatalog(unittest.TestCase):

    def test_every_rule_names_what_it_is_and_what_it_needs(self):
        self.assertEqual(len(D.RULES), 6)
        for rid, spec in D.RULES.items():
            self.assertTrue(spec['title'] and spec['why'] and spec['needs'], rid)
            self.assertIn(spec['severity'], D.RANK, rid)
            self.assertIn(rid, D._RULE_FUNCS, 'a rule with no function behind it never fires')
            for name, (dflt, lo, hi, label) in spec['params'].items():
                self.assertTrue(lo <= dflt <= hi and label, (rid, name))
        self.assertEqual(set(D._RULE_FUNCS), set(D.RULES), 'a function with no rule is dead code')

    def test_the_events_the_sweep_reads_are_events_the_server_has(self):
        import re
        src = (_TESTS.parent / 'server' / 'cgi-bin' / 'api.py').read_text()
        registry = set(re.findall(r"^    '([a-z0-9_]+)': dict\(", src, re.M))
        self.assertTrue(D.EVENT_NAMES)
        self.assertEqual(sorted(D.EVENT_NAMES - registry), [], 'the rule would wait for an event nothing fires (a name that does not exist reads like a quiet fleet)')

    def test_the_catalog_lists_every_rule_with_its_values(self):
        cat = D.catalog({'known_bad_contact': {'enabled': False, 'min_score': 90}})
        self.assertEqual([r['id'] for r in cat], list(D.RULES))
        kb = next(r for r in cat if r['id'] == 'known_bad_contact')
        self.assertFalse(kb['enabled'])
        self.assertEqual({p['name']: (p['value'], p['default'], p['min'], p['max']) for p in kb['params']}, {'min_score': (90, 75, 1, 100), 'days': (14, 14, 1, 90)})
        self.assertTrue(all(r['enabled'] for r in cat if r['id'] != 'known_bad_contact'))


class TestSettings(unittest.TestCase):

    def test_nothing_stored_is_every_rule_on_with_its_defaults(self):
        s = D.settings(None)
        self.assertTrue(all(row['enabled'] for row in s.values()))
        self.assertEqual(s['known_bad_contact'], {'enabled': True, 'min_score': 75, 'days': 14})
        self.assertEqual(s['interpreter_egress'], {'enabled': True})

    def test_a_stored_document_of_the_wrong_kind_reads_as_the_defaults(self):
        for junk in ('x', 5, [], [1], {'known_bad_contact': 'x'}, {'known_bad_contact': {'enabled': 'no', 'min_score': True, 'days': '5'}},
                     {'known_bad_contact': {'min_score': 0}}, {'known_bad_contact': {'min_score': 101}}, {'known_bad_contact': {'days': 10 ** 400}},
                     {'known_bad_contact': {'min_score': 1.5}}, {'nope': {'enabled': False}}):
            self.assertEqual(D.settings(junk), D.settings(None), repr(junk))

    def test_a_value_in_range_is_kept_and_one_out_of_range_is_not(self):
        self.assertEqual(D.settings({'known_bad_contact': {'min_score': 1, 'days': 90}})['known_bad_contact'], {'enabled': True, 'min_score': 1, 'days': 90})
        self.assertEqual(D.settings({'known_bad_contact': {'min_score': 100, 'days': 91}})['known_bad_contact'], {'enabled': True, 'min_score': 100, 'days': 14})
        self.assertFalse(D.settings({'interpreter_egress': {'enabled': False}})['interpreter_egress']['enabled'])

    def test_an_update_is_checked_and_a_refused_one_keeps_nothing(self):
        ok, err = D.clean_update({'known_bad_contact': {'min_score': 80, 'enabled': False}, 'exposed_port_in_use': {'hours': 12}})
        self.assertEqual((ok, err), ({'known_bad_contact': {'min_score': 80, 'enabled': False}, 'exposed_port_in_use': {'hours': 12}}, ''))
        bad = [None, {}, [], 'x', {'nope': {'enabled': True}}, {'known_bad_contact': {}}, {'known_bad_contact': 'x'}, {'known_bad_contact': {'nope': 1}},
               {'known_bad_contact': {'min_score': 0}}, {'known_bad_contact': {'min_score': 101}}, {'known_bad_contact': {'min_score': True}}, {'known_bad_contact': {'min_score': 80.0}},
               {'known_bad_contact': {'min_score': '80'}}, {'known_bad_contact': {'enabled': 1}}, {'known_bad_contact': {'enabled': 'true'}},
               {'interpreter_egress': {'hours': 3}}, {'exposed_port_in_use': {'hours': 49}},
               {'known_bad_contact': {'min_score': 80}, 'nope': {'enabled': True}}]
        for b in bad:
            got, err = D.clean_update(b)
            self.assertTrue(err and got == {}, repr(b))

    def test_an_update_is_merged_into_the_whole_document(self):
        stored = {'known_bad_contact': {'enabled': False}}
        got = D.merged(stored, {'exposed_port_in_use': {'hours': 3}})
        self.assertEqual(set(got), set(D.RULES), 'every rule has its full row, so a default that moves later does not change a saved document')
        self.assertEqual((got['known_bad_contact']['enabled'], got['exposed_port_in_use']['hours']), (False, 3))
        self.assertEqual(got['known_bad_contact']['min_score'], 75)
        self.assertEqual(stored, {'known_bad_contact': {'enabled': False}}, 'the stored document is not changed in place')


class TestInterpreterEgress(unittest.TestCase):

    def test_a_shell_holding_a_connection_to_a_public_address_is_high(self):
        got = run('interpreter_egress', ctx([row(ip=PUB2, port=4444, proc='bash')]))
        self.assertEqual([(f['severity'], f['ip'], f['port'], f['process']) for f in got], [('high', PUB2, 4444, 'bash')])
        self.assertIn('bash on web01 is connected to %s:4444' % PUB2, got[0]['detail'])

    def test_every_shell_counts_and_a_path_is_cut_off(self):
        for sh in ('sh', 'dash', 'zsh', 'ash', 'ksh', 'csh', 'tcsh', 'fish', '/usr/bin/bash'):
            self.assertEqual([f['severity'] for f in run('interpreter_egress', ctx([row(proc=sh)]))], ['high'], sh)

    def test_a_network_tool_is_medium(self):
        for tool in ('nc', 'ncat', 'netcat', 'socat', 'telnet'):
            self.assertEqual([f['severity'] for f in run('interpreter_egress', ctx([row(proc=tool)]))], ['medium'], tool)

    def test_a_program_that_is_neither_is_not_a_finding(self):
        for proc in ('curl', 'nginx', 'python3', 'sshd', 'busybox', '', '-'):
            self.assertEqual(run('interpreter_egress', ctx([row(proc=proc)])), [], proc)

    def test_a_private_address_or_an_inbound_connection_is_not_a_finding(self):
        self.assertEqual(run('interpreter_egress', ctx([row(ip=LAN, proc='bash')])), [], 'the local network')
        self.assertEqual(run('interpreter_egress', ctx([row(d='in', proc='bash')])), [], 'somebody connected to the host: that is not the host calling out')

    def test_two_addresses_are_two_findings(self):
        got = run('interpreter_egress', ctx([row(proc='bash'), row(ip=PUB2, proc='bash')]))
        self.assertEqual(len(got), 2)
        self.assertEqual(len({f['key'] for f in got}), 2)

    def test_the_same_program_to_the_same_address_on_two_ports_is_one_finding(self):
        got = run('interpreter_egress', ctx([row(port=4444, proc='bash'), row(port=5555, proc='bash')]))
        self.assertEqual(len(got), 1, 'one thing found twice is one alert, not two: the key is the program and the address')


class TestServiceNewDestination(unittest.TestCase):

    def test_a_database_calling_an_address_it_never_used_is_medium(self):
        got = run('service_new_destination', ctx([row(ip=PUB2, port=8443, proc='mysqld')]))
        self.assertEqual([(f['severity'], f['ip'], f['process']) for f in got], [('medium', PUB2, 'mysqld')])

    def test_the_programs_that_answer_other_programs_count(self):
        for p in ('mysqld', 'mariadbd', 'postgres', 'mongod', 'redis-server', 'memcached', 'dovecot', 'sshd'):
            self.assertEqual(len(run('service_new_destination', ctx([row(ip=PUB2, proc=p)]))), 1, p)

    def test_a_program_that_calls_new_addresses_all_week_does_not(self):
        for p in ('nginx', 'apache2', 'httpd', 'php-fpm8.2', 'php-fpm', 'named', 'vsftpd', 'curl', 'python3'):
            self.assertEqual(run('service_new_destination', ctx([row(ip=PUB2, proc=p)])), [], p)

    def test_the_first_hour_of_a_host_is_its_baseline(self):
        self.assertEqual(run('service_new_destination', ctx([row(ip=PUB2, proc='mysqld')], first_ago=1800)), [], 'every address is new to a host that has just started to report')

    def test_an_address_the_host_used_yesterday_is_not_new(self):
        c = ctx([row(ip=PUB2, proc='mysqld')], seen_before=[(PUB2, 2 * DAY, 'out')], first_ago=3 * DAY)
        self.assertEqual(run('service_new_destination', c), [])

    def test_a_private_address_or_an_inbound_connection_is_not_a_finding(self):
        self.assertEqual(run('service_new_destination', ctx([row(ip=LAN, proc='mysqld')])), [])
        self.assertEqual(run('service_new_destination', ctx([row(d='in', ip=PUB2, proc='mysqld')])), [], 'a client of the database')


class TestKnownBadContact(unittest.TestCase):

    def intel(self, ip=PUB2, score: int | None = 90, last: int | None = None):
        return {ip: {'score': score, 'last': last}}

    def test_a_connection_to_an_address_with_a_high_score_is_high(self):
        got = run('known_bad_contact', ctx([row(ip=PUB2, proc='curl')], intel=self.intel(score=90)))
        self.assertEqual([(f['severity'], f['ip'], f['evidence']['connected']) for f in got], [('high', PUB2, True)])
        self.assertIn('scores 90 at Threat Intel', got[0]['detail'])

    def test_the_line_is_the_one_the_rule_is_set_to(self):
        c = ctx([row(ip=PUB2)], intel=self.intel(score=74))
        self.assertEqual(run('known_bad_contact', c), [], 'one under the default line of 75')
        self.assertEqual(len(run('known_bad_contact', c, min_score=74)), 1)
        self.assertEqual(run('known_bad_contact', ctx([row(ip=PUB2)], intel=self.intel(score=75)), min_score=76), [])
        self.assertEqual(len(run('known_bad_contact', ctx([row(ip=PUB2)], intel=self.intel(score=75)))), 1, 'the line itself counts')

    def test_an_address_that_attacked_this_installation_lately_counts_without_a_score(self):
        got = run('known_bad_contact', ctx([row(ip=PUB2)], intel=self.intel(score=None, last=NOW - 2 * DAY)))
        self.assertEqual([f['severity'] for f in got], ['high'])
        self.assertIn('has attacked this installation lately', got[0]['detail'])
        self.assertTrue(got[0]['evidence']['attacked'])

    def test_an_attack_that_is_older_than_the_window_does_not(self):
        c = ctx([row(ip=PUB2)], intel=self.intel(score=None, last=NOW - 20 * DAY))
        self.assertEqual(run('known_bad_contact', c), [], 'the default window is 14 days')
        self.assertEqual(len(run('known_bad_contact', c, days=30)), 1)

    def test_only_a_call_the_host_made_counts(self):
        c = ctx([row(d='in', ip=PUB2, port=22, proc='sshd')], intel=self.intel(score=99), seen_before=[])
        self.assertEqual(run('known_bad_contact', c), [], 'a scanner connected to the host: the brute-force alerts already name it')
        c = ctx([row(d='out', ip=LAN)], intel={LAN: {'score': 99, 'last': NOW}})
        self.assertEqual(run('known_bad_contact', c), [], 'a private address is no one else\'s')

    def test_an_address_the_host_called_earlier_is_found_when_it_has_since_been_marked(self):
        c = ctx([row(ip=PUB)], seen_before=[(PUB2, 3 * DAY, 'out')], first_ago=4 * DAY, intel=self.intel(score=88))
        got = run('known_bad_contact', c)
        self.assertEqual([(f['severity'], f['ip'], f['evidence']['connected']) for f in got], [('medium', PUB2, False)])
        self.assertIn('first called %s 3 days ago' % PUB2, got[0]['detail'])

    def test_an_address_that_only_visited_the_host_is_not_a_call(self):
        c = ctx([row(ip=PUB)], seen_before=[(PUB2, 3 * DAY, 'in')], first_ago=4 * DAY, intel=self.intel(score=88))
        self.assertIn(PUB2, c['rec']['seen'], 'control: the host did see the address')
        self.assertNotIn(PUB2, c['rec']['seen_out'])
        self.assertEqual(run('known_bad_contact', c), [], 'a web server has thousands of visitors, and a visitor is not something the host called')

    def test_an_address_in_the_store_that_is_not_one_is_read_as_nothing(self):
        for junk in ({PUB2: 'x'}, {PUB2: {'score': 'high', 'last': 'x'}}, {PUB2: {'score': float('nan'), 'last': True}}, {PUB2: None}, 'x', [], None, {5: {'score': 99}}):
            self.assertEqual(run('known_bad_contact', ctx([row(ip=PUB2)], intel=junk)), [], repr(junk))


class TestPersistenceThenEgress(unittest.TestCase):

    def test_a_new_ssh_key_and_then_a_first_connection_to_a_new_address_is_high(self):
        c = ctx([row(ip=PUB2, proc='curl')], events=[ev('ssh_key_added', 600, user='root')])
        got = run('persistence_then_egress', c)
        self.assertEqual([(f['severity'], f['ip'], f['evidence']['event']) for f in got], [('high', PUB2, 'ssh_key_added')])

    def test_each_way_back_in_counts(self):
        for name in ('ssh_key_added', 'empty_password_account', 'firewall_changed'):
            got = run('persistence_then_egress', ctx([row(ip=PUB2)], events=[ev(name, 600)]))
            self.assertEqual([f['evidence']['event'] for f in got], [name], name)

    def test_a_program_that_fetches_updates_does_not_count(self):
        for p in ('apt', 'apt-get', 'http', 'dnf', 'pacman', 'chronyd', 'snapd'):
            self.assertEqual(run('persistence_then_egress', ctx([row(ip=PUB2, proc=p)], events=[ev('ssh_key_added', 600)])), [], p)

    def test_the_connection_has_to_come_after_the_event_and_within_the_window(self):
        later = ctx([row(ip=PUB2)], events=[ev('ssh_key_added', 600)], seen_before=[(PUB2, HOUR, 'out')])
        self.assertTrue(T.is_new(later['rec'], PUB2, NOW), 'control: the address is still new, it was first used an hour ago')
        self.assertEqual(run('persistence_then_egress', later), [], 'the key came ten minutes ago, after the first use of the address: not a way back in followed by a destination')
        self.assertEqual(run('persistence_then_egress', ctx([row(ip=PUB2)], events=[ev('ssh_key_added', 600)])) != [], True, 'control: with the first use after the key it is a finding')
        old = ctx([row(ip=PUB2)], events=[ev('ssh_key_added', 3 * HOUR)], first_ago=6 * HOUR)
        self.assertEqual(run('persistence_then_egress', old), [], 'three hours is outside the default two')
        self.assertEqual(len(run('persistence_then_egress', old, hours=4)), 1, 'the address is first used now, three hours after the key: inside a window of four')

    def test_an_address_the_host_already_used_is_not_a_new_destination(self):
        c = ctx([row(ip=PUB2)], events=[ev('ssh_key_added', 600)], seen_before=[(PUB2, 2 * DAY, 'out')], first_ago=3 * DAY)
        self.assertEqual(run('persistence_then_egress', c), [])

    def test_no_event_no_finding(self):
        self.assertEqual(run('persistence_then_egress', ctx([row(ip=PUB2)])), [])
        self.assertEqual(run('persistence_then_egress', ctx([row(ip=PUB2)], events=[ev('brute_force_detected', 600)])), [], 'a burst of failed logins is not a way back in')


class TestBruteforceThenLogin(unittest.TestCase):

    def test_the_address_that_guessed_and_then_got_in_is_critical(self):
        c = ctx([], events=[ev('brute_force_detected', 1200, source_ip=PUB2, count=212), ev('login_new_source', 300, source=PUB2, user='root')])
        got = run('bruteforce_then_login', c)
        self.assertEqual([(f['severity'], f['ip'], f['evidence']['same_address'], f['evidence']['failed_logins'], f['evidence']['user']) for f in got], [('critical', PUB2, True, 212, 'root')])
        self.assertIn('The address that guessed passwords on web01', got[0]['detail'])

    def test_a_burst_from_somewhere_else_and_a_login_from_a_new_address_is_high(self):
        c = ctx([], events=[ev('brute_force_detected', 1200, source_ip=PUB3, count=40), ev('login_new_source', 300, source=PUB2, user='jo')])
        got = run('bruteforce_then_login', c)
        self.assertEqual([(f['severity'], f['evidence']['same_address']) for f in got], [('high', False)])

    def test_the_match_is_looked_for_in_every_burst_of_the_window(self):
        c = ctx([], events=[ev('brute_force_detected', 2400, source_ip=PUB2, count=10), ev('brute_force_detected', 600, source_ip=PUB3, count=10), ev('login_new_source', 300, source=PUB2)])
        self.assertEqual([f['severity'] for f in run('bruteforce_then_login', c)], ['critical'], 'the newer burst was from somebody else, the older one from the address that got in')

    def test_a_login_before_the_burst_or_a_long_time_after_it_is_not_a_finding(self):
        before = ctx([], events=[ev('login_new_source', 1200, source=PUB2), ev('brute_force_detected', 300, source_ip=PUB2)])
        self.assertEqual(run('bruteforce_then_login', before), [])
        late = ctx([], events=[ev('brute_force_detected', 3 * HOUR, source_ip=PUB2), ev('login_new_source', 600, source=PUB2)])
        self.assertEqual(run('bruteforce_then_login', late), [], 'the window is an hour')
        self.assertEqual(len(run('bruteforce_then_login', late, hours=3)), 1)

    def test_two_logins_are_two_findings(self):
        c = ctx([], events=[ev('brute_force_detected', 1500, source_ip=PUB2), ev('login_new_source', 900, source=PUB2), ev('login_new_source', 300, source=PUB3)])
        self.assertEqual(sorted(f['severity'] for f in run('bruteforce_then_login', c)), ['critical', 'high'])

    def test_events_that_are_not_events_are_ignored(self):
        junk = [None, 'x', 5, {}, {'event': 'login_new_source'}, {'event': 'login_new_source', 'ts': 'x', 'payload': {}}, {'event': 'login_new_source', 'ts': True, 'payload': {}},
                {'event': 5, 'ts': NOW}, {'event': 'brute_force_detected', 'ts': NOW - 10, 'payload': 'x'}]
        self.assertEqual(run('bruteforce_then_login', ctx([], events=junk)), [])


class TestExposedPortInUse(unittest.TestCase):

    def test_a_new_port_that_a_public_address_is_already_connected_to_is_medium(self):
        c = ctx([row(d='in', ip=PUB2, port=8081, proc='python3')], events=[ev('new_port_detected', 900, port=8081, proto='tcp')])
        got = run('exposed_port_in_use', c)
        self.assertEqual([(f['severity'], f['ip'], f['port'], f['process']) for f in got], [('medium', PUB2, 8081, 'python3')])

    def test_a_port_exposed_to_the_world_counts_too(self):
        c = ctx([row(d='in', ip=PUB2, port=8081)], events=[ev('port_exposed_world', 900, port=8081)])
        self.assertEqual(len(run('exposed_port_in_use', c)), 1)

    def test_another_port_a_private_client_or_an_outbound_row_is_not_a_finding(self):
        ev1 = [ev('new_port_detected', 900, port=8081)]
        self.assertEqual(run('exposed_port_in_use', ctx([row(d='in', ip=PUB2, port=8082)], events=ev1)), [], 'another port')
        self.assertEqual(run('exposed_port_in_use', ctx([row(d='in', ip=LAN, port=8081)], events=ev1)), [], 'the local network')
        self.assertEqual(run('exposed_port_in_use', ctx([row(d='out', ip=PUB2, port=8081)], events=ev1)), [], 'the host called out to a port 8081 somewhere else')

    def test_the_port_has_to_be_new(self):
        old = ctx([row(d='in', ip=PUB2, port=8081)], events=[ev('new_port_detected', 8 * HOUR, port=8081)])
        self.assertEqual(run('exposed_port_in_use', old), [], 'the default is six hours')
        self.assertEqual(len(run('exposed_port_in_use', old, hours=12)), 1)

    def test_a_port_that_is_not_a_number_is_ignored(self):
        for port in ('8081', None, True, 8081.0, [8081]):
            c = ctx([row(d='in', ip=PUB2, port=8081)], events=[ev('new_port_detected', 900, port=port)])
            self.assertEqual(run('exposed_port_in_use', c), [], repr(port))


class TestEvaluate(unittest.TestCase):

    def busy(self):
        return ctx([row(proc='bash'), row(ip=PUB2, port=3306, proc='mysqld'), row(ip=PUB3, proc='nc')], events=[ev('ssh_key_added', 600)], intel={PUB3: {'score': 99, 'last': None}})

    def test_the_most_severe_comes_first_and_a_key_is_there_once(self):
        got = D.evaluate(self.busy())
        self.assertGreaterEqual(len(got), 4)
        ranks = [D.RANK[f['severity']] for f in got]
        self.assertEqual(ranks, sorted(ranks))
        self.assertEqual(len({f['key'] for f in got}), len(got))
        for f in got:
            self.assertIn(f['rule'], D.RULES)
            self.assertLessEqual(len(f['key']), 200)
            self.assertLessEqual(len(f['detail']), 300)
            self.assertTrue(f['repeat_s'] <= D.KEEP_S)

    def test_a_rule_that_is_switched_off_finds_nothing(self):
        rules = D.settings({'interpreter_egress': {'enabled': False}})
        self.assertEqual(only(D.evaluate(self.busy(), rules), 'interpreter_egress'), [])
        self.assertTrue(only(D.evaluate(self.busy()), 'interpreter_egress'), 'control: it found something with the rule on')
        self.assertEqual(D.evaluate(self.busy(), {rid: {'enabled': False} for rid in D.RULES}), [])

    def test_a_rule_that_raises_does_not_stop_the_others(self):
        real = D._RULE_FUNCS['interpreter_egress']

        def boom(c, p):
            raise RuntimeError('a rule that fails on one host')
        D._RULE_FUNCS['interpreter_egress'] = boom
        errors = []
        try:
            got = D.evaluate(self.busy(), None, errors)
            quiet = D.evaluate(self.busy())
        finally:
            D._RULE_FUNCS['interpreter_egress'] = real
        self.assertEqual(only(got, 'interpreter_egress'), [])
        self.assertTrue(got and only(got, 'known_bad_contact'), 'the others ran')
        self.assertEqual(errors, [('interpreter_egress', 'RuntimeError: a rule that fails on one host')], 'the caller can say that a rule failed')
        self.assertEqual(quiet, got, 'a caller that passes no list gets the same findings')

    def test_the_findings_are_not_cut_here_and_the_caller_shows_five(self):
        many = ctx([row(ip='9.9.%d.%d' % (i // 200, i % 200 + 1), proc='bash') for i in range(30)])
        self.assertEqual(len(D.evaluate(many)), 30)
        self.assertEqual(D.MAX_PER_HOST, 5)

    def test_a_context_that_is_missing_parts_finds_nothing_and_does_not_raise(self):
        for c in ({}, {'rows': None}, {'rows': 'x', 'events': 'x', 'rec': 'x', 'intel': 'x', 'host': 'x', 'now': 'x'}, {'rows': [None, 5, {'ip': 5}], 'events': [None, {}], 'rec': [], 'intel': 5}):
            self.assertEqual(D.evaluate(c), [], repr(c))
            for rid, fn in D._RULE_FUNCS.items():
                try:
                    fn(c, D.settings(None)[rid])
                except Exception as e:
                    self.fail('%s raised %r on %r' % (rid, e, c))


class TestWhatWasRaised(unittest.TestCase):

    def finding(self, key='k', repeat=6 * HOUR):
        return {'rule': 'interpreter_egress', 'key': key, 'severity': 'high', 'detail': 'x', 'repeat_s': repeat}

    def test_a_finding_is_due_when_it_was_never_raised_or_its_interval_has_passed(self):
        f = self.finding()
        self.assertTrue(D.is_due({}, f, NOW))
        self.assertTrue(D.is_due(None, f, NOW))
        self.assertFalse(D.is_due({'k': NOW - HOUR}, f, NOW))
        self.assertTrue(D.is_due({'k': NOW - 6 * HOUR}, f, NOW))
        self.assertFalse(D.is_due({'k': NOW - 6 * HOUR + 1}, f, NOW))
        self.assertTrue(D.is_due({'k': NOW + 5000}, f, NOW), 'a time in the future (a clock that was set back) does not silence it')
        self.assertTrue(D.is_due({'k': 'x'}, f, NOW))
        self.assertTrue(D.is_due({'k': True}, f, NOW))

    def test_what_was_raised_is_remembered_for_a_week_and_no_more_than_the_cap(self):
        got = D.remember({'old': NOW - 8 * DAY, 'mid': NOW - 3 * DAY, 5: NOW, 'bad': 'x'}, [self.finding('new')], NOW)
        self.assertEqual(got, {'mid': NOW - 3 * DAY, 'new': NOW})
        many = D.remember({'k%d' % i: NOW - i for i in range(150)}, [self.finding('new')], NOW, cap=100)
        self.assertEqual(len(many), 100)
        self.assertIn('new', many)
        self.assertNotIn('k149', many, 'the oldest go first')

    def test_remember_does_not_change_what_it_was_given(self):
        before = {'a': NOW - 10}
        D.remember(before, [self.finding('b')], NOW)
        self.assertEqual(before, {'a': NOW - 10})


class TestWhatTheTrafficRecordKeeps(unittest.TestCase):
    """`seen_out` is the one change to the Traffic record: the addresses the host itself called, which is what a later look at Threat Intel needs."""

    def test_only_a_public_address_the_host_called_is_in_seen_out(self):
        s = T.clean_sample({'win': 60, 'rows': [row('out', PUB), row('in', PUB2, 22), row('out', LAN)]}, NOW)
        rec = T.merge(None, s, NOW)
        self.assertEqual(sorted(rec['seen']), sorted([PUB, PUB2]))
        self.assertEqual(list(rec['seen_out']), [PUB])

    def test_the_first_time_is_kept_and_carried_forward(self):
        rec = T.merge(None, T.clean_sample({'win': 60, 'rows': [row('out', PUB)]}, NOW), NOW)
        rec = T.merge(rec, T.clean_sample({'win': 60, 'rows': [row('out', PUB), row('out', PUB2)]}, NOW + 600), NOW + 600)
        self.assertEqual(rec['seen_out'], {PUB: NOW, PUB2: NOW + 600})

    def test_it_is_bounded_and_a_record_of_the_wrong_kind_starts_over(self):
        rec = {'seen_out': {'9.9.%d.%d' % (i // 200, i % 200 + 1): i for i in range(T.SEEN_MAX + 40)}}
        out = T.merge(rec, T.clean_sample({'win': 60, 'rows': [row('out', PUB)]}, 10 ** 6), 10 ** 6)
        self.assertEqual(len(out['seen_out']), T.SEEN_MAX)
        self.assertIn(PUB, out['seen_out'])
        for junk in ('x', 5, [], {'a': 'x', 5: 1, 'b': True}):
            got = T.merge({'seen_out': junk}, T.clean_sample({'win': 60, 'rows': [row('out', PUB)]}, NOW), NOW)
            self.assertEqual(got['seen_out'], {PUB: NOW}, repr(junk))


if __name__ == '__main__':
    unittest.main()

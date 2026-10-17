"""What an operator tells Threat intel not to report (v7.3.0).

A report is public and filed under the operator's account, so the ways to say
"not this one" matter. There are two: an address or a network, and a kind of attack
(an address is held back when everything it did is a kind you ignore).

Three things have to hold, and each is a place a half-applied rule would hide:

  * it holds at every place a report can come from (the claim that rations network
    calls, the catch-up that revisits a qualified ledger, and the report itself,
    for both the host logs' evidence and the brute-force counter's own entries);
  * it only ever does LESS: an ignored address is still recorded, looked up and,
    with blocking on, blocked, and the evidence is kept so that taking it off the
    list reports it on its next sighting;
  * only the person who owns the instance's settings can change it.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v730-ignore-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import ip_intel  # noqa: E402
import threat_evidence as te  # noqa: E402
from test_ip_intel import ATTACKER  # noqa: E402
from test_v720_threat_report_engine import SECOND, _Engine, raw_event, web  # noqa: E402
from test_v730_edge_blocklist_sync import T, _Lists  # noqa: E402

OTHER_NET = '203.0.113.50'


class TestTheListsAreValidated(unittest.TestCase):
    def test_addresses_networks_and_a_mask_with_host_bits_come_out_canonical(self):
        out, bad = ip_intel.clean_ignore_addresses(
            '203.0.113.7\n198.51.100.9/24, 2001:DB8::1\n203.0.113.7\n\n   ')
        self.assertIsNone(bad)
        self.assertEqual(out, ['203.0.113.7', '198.51.100.0/24', '2001:db8::1'])

    def test_a_list_of_values_is_read_like_the_textarea(self):
        self.assertEqual(ip_intel.clean_ignore_addresses(['203.0.113.7', ' 198.51.100.0/24 ']),
                         (['203.0.113.7', '198.51.100.0/24'], None))

    def test_garbage_a_zone_id_and_a_range_that_would_silence_everything_are_refused(self):
        for bad in ('hello', '203.0.113.999', 'fe80::1%eth0', '2606:4700::1%$(id)', '0.0.0.0/0', '10.0.0.0/7',
                    '::/0', '2001:db8::/15', 'a.example.com'):
            out, err = ip_intel.clean_ignore_addresses(bad)
            self.assertTrue(err, bad)
            self.assertEqual(out, [])

    def test_the_narrowest_allowed_widths_are_accepted(self):
        self.assertEqual(ip_intel.clean_ignore_addresses('10.0.0.0/8')[1], None)
        self.assertEqual(ip_intel.clean_ignore_addresses('2001::/16')[1], None)

    def test_the_list_has_a_ceiling(self):
        many = '\n'.join('198.51.%d.%d' % (i // 250, i % 250 + 1) for i in range(ip_intel.IGNORE_MAX + 1))
        out, err = ip_intel.clean_ignore_addresses(many)
        self.assertEqual(len(out), ip_intel.IGNORE_MAX)
        self.assertIn('At most', err)

    def test_only_a_kind_of_attack_the_vocabulary_has(self):
        self.assertEqual(ip_intel.clean_ignore_classes(['bad_bot', 'probe', 'bad_bot']),
                         (['bad_bot', 'probe'], None))
        for bad in (['nope'], ['bad_bot', '__proto__'], 'ssh brute force'):
            self.assertTrue(ip_intel.clean_ignore_classes(bad)[1], bad)
        self.assertEqual(ip_intel.clean_ignore_classes([]), ([], None))
        self.assertEqual(ip_intel.clean_ignore_classes(None), ([], None))

    def test_every_class_in_the_vocabulary_can_be_ignored(self):
        ids = list(te.CLASSES)
        self.assertEqual(ip_intel.clean_ignore_classes(ids), (ids, None))


class TestTheReason(unittest.TestCase):
    NETS = ip_intel.parse_cidrs(['203.0.113.0/24', '2001:db8::/32'])

    def test_an_address_on_the_list_or_inside_a_network_on_it(self):
        for ip in ('203.0.113.7', '203.0.113.254', '2001:db8::5'):
            self.assertEqual(ip_intel.ignore_reason(ip, self.NETS, set(), set()), 'on the ignore list', ip)
        for ip in ('203.0.114.1', '2001:db9::1', '198.51.100.1'):
            self.assertEqual(ip_intel.ignore_reason(ip, self.NETS, set(), set()), '', ip)

    def test_a_kind_holds_an_address_back_only_when_it_is_everything_it_did(self):
        r = ip_intel.ignore_reason
        self.assertEqual(r('8.8.8.8', [], {'bad_bot'}, {'bad_bot', 'probe'}), 'only attacks you ignore')
        self.assertEqual(r('8.8.8.8', [], {'bad_bot', 'probe'}, {'bad_bot', 'probe'}), 'only attacks you ignore')
        self.assertEqual(r('8.8.8.8', [], {'bad_bot', 'sqli'}, {'bad_bot', 'probe'}), '')
        self.assertEqual(r('8.8.8.8', [], {'sqli'}, {'bad_bot'}), '')

    def test_nothing_it_can_name_means_nothing_is_held_back(self):
        r = ip_intel.ignore_reason
        self.assertEqual(r('8.8.8.8', [], set(), {'bad_bot'}), '')
        self.assertEqual(r('8.8.8.8', [], {'?'}, {'bad_bot'}), '', 'an entry that fits no class is never covered')
        self.assertEqual(r('8.8.8.8', [], {'bad_bot'}, set()), '')
        self.assertEqual(r('8.8.8.8', [], {'bad_bot'}, None), '')

    def test_the_generic_waf_class_steps_aside_like_it_does_in_a_report(self):
        waf_and_bot = te.normalize_event(
            raw_event(src={'waf': 9, 'web': 9}, tok={'web': {'req:probe': 9}, 'waf': {'crs:920350': 9}}),
            now=int(__import__('time').time()))
        self.assertIn('waf', te.classes(waf_and_bot))
        self.assertNotIn('waf', te.report_classes(waf_and_bot))
        self.assertEqual(te.report_classes(waf_and_bot), {'probe'})
        only_waf = te.normalize_event(raw_event(src={'waf': 9}, tok={'waf': {'crs:920350': 9}}),
                                      now=int(__import__('time').time()))
        self.assertEqual(te.report_classes(only_waf), {'waf'})


class TestTheSweepHonoursIt(_Engine):
    """The real sweep, the real queue, the real ledger; the providers faked at the
    one seam that touches the network."""

    def test_control_an_address_that_is_not_ignored_is_reported(self):
        self.feed(web(n=12))
        self.sweep()
        self.assertEqual(len(self.posts()), 2)

    def test_an_address_on_the_list_is_not_reported(self):
        self.policy(ignore_addresses=[ATTACKER])
        self.feed(web(n=12))
        self.sweep()
        self.assertEqual(self.posts(), [])
        att = self.att()
        self.assertNotIn('reported', att)
        self.assertEqual(att['errors'], {'abuseipdb': 'not reported: on the ignore list',
                                         'sniffcat': 'not reported: on the ignore list'})

    def test_a_network_covers_every_address_in_it_and_no_other(self):
        self.policy(ignore_addresses=['185.220.101.0/24'])
        for ip in (ATTACKER, SECOND):
            self.feed(web(ip, n=12))
        self.feed(web('185.220.102.9', n=12))
        self.sweep()
        reported = {c['body'].decode() if isinstance(c['body'], bytes) else c['body'] for c in self.posts()}
        text = ' '.join(reported)
        self.assertIn('185.220.102.9', text)
        self.assertNotIn(ATTACKER, text)
        self.assertNotIn(SECOND, text)
        self.assertEqual(len(self.posts()), 2, 'one address, two services')

    def test_it_is_still_recorded_looked_up_and_blocked(self):
        """Ignoring can only do less in public. It must not leave a host less
        protected, which is the difference from a never-block entry."""
        self.policy(ignore_addresses=[ATTACKER], block_enabled=True)
        self.feed(web(n=12))
        self.sweep()
        att = self.att()
        self.assertEqual(att['verdict']['score'], 100, 'looked up')
        self.assertIn('d1', att['devices'], 'recorded against the host that saw it')
        self.assertEqual(self.posts(), [])
        self.assertIn(ATTACKER, (self.store().get('blocks') or {}).get('d1', {}), 'blocked as usual')

    def test_a_kind_it_did_nothing_else_of_is_not_reported(self):
        self.policy(ignore_classes=['probe'])
        self.feed(web(n=12, kind='probe'))
        self.sweep()
        self.assertEqual(self.posts(), [])
        self.assertIn('only attacks you ignore', str(self.att()['errors']))

    def test_one_other_kind_and_it_is_reported_as_usual(self):
        self.policy(ignore_classes=['probe'])
        self.feed(raw_event(src={'web': 41}, tok={'web': {'req:sqli': 30, 'req:probe': 11}}))
        self.sweep()
        self.assertEqual(len(self.posts()), 2)

    def test_a_kind_that_is_not_ignored_is_reported(self):
        self.policy(ignore_classes=['bad_bot'])
        self.feed(web(n=12, kind='probe'))
        self.sweep()
        self.assertEqual(len(self.posts()), 2)

    def test_the_wafs_generic_class_does_not_reopen_a_kind_that_is_ignored(self):
        self.policy(ignore_classes=['probe'])
        self.feed(raw_event(src={'web': 12, 'waf': 12},
                            tok={'web': {'req:probe': 12}, 'waf': {'crs:920350': 12}}))
        self.sweep()
        self.assertEqual(self.posts(), [], 'refused by the WAF 12 times, but all of it probing')

    def test_the_brute_force_counters_own_entries_are_covered_too(self):
        self.policy(ignore_classes=['ssh_brute'], report_min_count=10)
        self.attack(count=25, unit='sshd.service')
        self.sweep()
        self.assertEqual(self.posts(), [])
        self.assertIn('only attacks you ignore', str(self.att()['errors']))

    def test_a_counter_entry_that_fits_no_class_is_never_held_back_by_a_kind(self):
        self.policy(ignore_classes=list(te.CLASSES), report_min_count=10)
        self.attack(count=25, unit='custom.service')
        self.sweep()
        self.assertEqual(len(self.posts()), 2)

    def test_the_address_list_covers_the_counters_entries_as_well(self):
        self.policy(ignore_addresses=[ATTACKER], report_min_count=10)
        self.attack(count=25, unit='sshd.service')
        self.sweep()
        self.assertEqual(self.posts(), [])

    def test_the_evidence_is_kept_so_taking_it_off_the_list_reports_it(self):
        self.policy(ignore_addresses=[ATTACKER])
        self.feed(web(n=12))
        self.sweep()
        self.assertEqual(self.posts(), [])
        self.assertTrue(self.att().get('ev'), 'the day\'s evidence is still there')
        self.policy(ignore_addresses=[])
        self.api._LOAD_CACHE.clear()
        self.feed(web(n=3))
        self.sweep()
        self.assertEqual(len(self.posts()), 2)

    def test_what_was_reported_before_stays_reported(self):
        self.feed(web(n=12))
        self.sweep()
        before = dict(self.att()['reported'])
        self.assertEqual(set(before), {'abuseipdb', 'sniffcat'})
        self.policy(ignore_addresses=[ATTACKER])
        self.api._LOAD_CACHE.clear()
        self.feed(web(n=12))
        self.sweep()
        self.assertEqual(self.att()['reported'], before)
        self.assertEqual(len(self.posts()), 2, 'and nothing more was sent')

    def test_the_catch_up_does_not_revisit_an_address_that_is_ignored(self):
        """A ledger that qualifies is taken up again by the next sweep when a
        service has not been told. For an ignored address that would be an entry
        every sweep that did nothing but write the same refusal."""
        api = self.api
        self.policy(report_enabled=False)
        self.feed(web(n=30))
        self.sweep()
        self.policy(report_enabled=True, report_min_count=10)
        api._LOAD_CACHE.clear()
        mod = api.ip_intel_handlers_mod
        st = self.store()
        now = int(__import__('time').time())
        self.assertEqual(len(mod._ledger_catchup(st, mod._policy(), now)), 1, 'the control: it is taken up')
        self.policy(ignore_addresses=[ATTACKER])
        api._LOAD_CACHE.clear()
        self.assertEqual(mod._ledger_catchup(st, mod._policy(), now), [])

    def test_an_ignored_address_does_not_spend_the_networks_per_sweep_allowance(self):
        api = self.api
        mod = api.ip_intel_handlers_mod
        self.policy(report_min_count=10)
        api._LOAD_CACHE.clear()
        item = {'ip': ATTACKER, 'device_id': 'd1', 'unit': 'sshd.service', 'count': 40, 'window_s': 600,
                'at': int(__import__('time').time())}
        now = int(__import__('time').time())
        self.assertTrue(mod._may_report(item, {}, mod._policy(), now))
        self.policy(ignore_addresses=[ATTACKER])
        api._LOAD_CACHE.clear()
        self.assertFalse(mod._may_report(item, {}, mod._policy(), now))

    def test_with_nothing_ignored_the_decision_points_do_no_extra_work(self):
        """The list is empty on every install that has not asked for it, and then
        none of the three places may so much as build the merged evidence."""
        mod = self.api.ip_intel_handlers_mod
        with mock.patch.object(te, 'report_classes', side_effect=AssertionError('built evidence for nothing')):
            self.feed(web(n=12))
            self.sweep()
            self.assertEqual(mod._ignore_why(ATTACKER, None, [], mod._policy()), '')
        self.assertEqual(len(self.posts()), 2)


class TestTheOperatorsControls(_Lists):
    def setUp(self):
        super().setUp()
        api = self.api
        api.save(api.DEVICES_FILE, {
            'd1': {'name': 'web01', 'os': 'Ubuntu 24.04', 'token': 't', 'ip': '10.0.0.5', 'tenant': 't1'},
        })
        st = api.load(api.IPINTEL_FILE) or {}
        st['attackers'] = {
            '185.220.101.11': {'first_seen': T - 900, 'last_seen': T - 10, 'verdict': {'score': 40},
                               'devices': {'d1': {'count': 30, 'unit': 'sshd.service', 'at': T - 10}}},
            '185.220.101.12': {'first_seen': T - 900, 'last_seen': T - 20, 'verdict': {'score': 40},
                               'devices': {'d1': {'count': 30, 'unit': 'sshd.service', 'at': T - 20}}},
        }
        api.save(api.IPINTEL_FILE, st)
        api._LOAD_CACHE.clear()

    def config(self):
        self.api._LOAD_CACHE.clear()
        return (self.api.load(self.api.CONFIG_FILE) or {}).get('ip_intel') or {}

    def settings(self, role='admin', **body):
        return self.call(self.api.handle_ip_intel_settings, body, role=role)

    def ignore(self, ip, role='admin'):
        return self.call(self.api.handle_ip_intel_ignore, {'ip': ip}, role=role)

    def tenanted(self, superadmin=False):
        self.api._tenancy_enforced = lambda: True
        self.api._caller_is_superadmin = lambda: superadmin

    def view(self, role='admin'):
        return self.call(self.api.handle_ip_intel, method='GET', role=role)[1]

    # ── the settings ──
    def test_the_lists_are_saved_canonical_and_returned(self):
        st, d = self.settings(ignore_addresses='203.0.113.7\n198.51.100.9/24', ignore_classes=['bad_bot', 'probe'])
        self.assertEqual(st, 200, d)
        self.assertEqual(self.config()['ignore_addresses'], ['203.0.113.7', '198.51.100.0/24'])
        self.assertEqual(self.config()['ignore_classes'], ['bad_bot', 'probe'])
        self.assertEqual(d['settings']['ignore_addresses'], ['203.0.113.7', '198.51.100.0/24'])
        self.assertEqual(d['settings']['ignore_classes'], ['bad_bot', 'probe'])

    def test_a_bad_entry_is_a_400_and_nothing_is_stored(self):
        self.settings(ignore_addresses='203.0.113.7')
        for body in ({'ignore_addresses': 'not-an-address'}, {'ignore_addresses': '0.0.0.0/0'},
                     {'ignore_classes': ['nope']}):
            st, d = self.settings(**body)
            self.assertEqual(st, 400, body)
            self.assertTrue(d.get('error'))
        self.assertEqual(self.config()['ignore_addresses'], ['203.0.113.7'], 'the old list stands')

    def test_an_empty_list_clears_it_and_an_omitted_one_leaves_it(self):
        self.settings(ignore_addresses='203.0.113.7', ignore_classes=['probe'])
        self.settings(never_block='198.51.100.0/24')
        self.assertEqual(self.config()['ignore_addresses'], ['203.0.113.7'])
        self.settings(ignore_addresses='', ignore_classes=[])
        self.assertEqual((self.config()['ignore_addresses'], self.config()['ignore_classes']), ([], []))

    def test_a_default_install_has_both_lists_empty(self):
        s = self.api.ip_intel_policy()
        self.assertEqual((s['ignore_addresses'], s['ignore_classes']), ([], []))

    def test_a_corrupt_stored_value_is_read_as_empty_not_as_a_crash(self):
        cfg = self.api.load(self.api.CONFIG_FILE)
        cfg['ip_intel'] = dict(cfg.get('ip_intel') or {}, ignore_addresses='203.0.113.7', ignore_classes={'x': 1})
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api._LOAD_CACHE.clear()
        pol = self.api.ip_intel_handlers_mod._policy()
        self.assertEqual((pol['ignore_nets'], pol['ignore_kinds']), ([], set()))
        self.assertEqual(self.call(self.api.handle_ip_intel, method='GET')[0], 200)

    # ── the row button ──
    def test_it_adds_one_address_and_says_it_did(self):
        st, d = self.ignore('185.220.101.11')
        self.assertEqual((st, d.get('ok'), d.get('already')), (200, True, False))
        self.assertEqual(self.config()['ignore_addresses'], ['185.220.101.11'])
        line = ' '.join(str(x) for x in next(a for a in self.audit if a[1] == 'ip_intel_ignore'))
        self.assertIn('ip=185.220.101.11', line)

    def test_a_second_press_and_a_covered_address_change_nothing(self):
        self.ignore('185.220.101.11')
        st, d = self.ignore('185.220.101.11')
        self.assertEqual((st, d['already']), (200, True))
        self.settings(ignore_addresses='185.220.101.0/24')
        st, d = self.ignore('185.220.101.12')
        self.assertTrue(d['already'])
        self.assertEqual(self.config()['ignore_addresses'], ['185.220.101.0/24'])
        self.assertEqual(len([a for a in self.audit if a[1] == 'ip_intel_ignore']), 1, 'only a change is audited')

    def test_it_keeps_the_rest_of_the_policy(self):
        self.settings(block_min_score=77, ignore_classes=['probe'])
        self.ignore('185.220.101.11')
        self.assertEqual(self.config()['block_min_score'], 77)
        self.assertEqual(self.config()['ignore_classes'], ['probe'])

    def test_it_will_not_take_what_is_not_an_address(self):
        for ip in ('', 'hello', '185.220.101.0/24', '185.220.101.999', 'fe80::1%eth0'):
            self.assertEqual(self.ignore(ip)[0], 400, ip)
        self.assertEqual(self.config().get('ignore_addresses') or [], [])

    def test_the_list_has_a_ceiling_for_the_button_too(self):
        cfg = self.api.load(self.api.CONFIG_FILE)
        cfg['ip_intel'] = dict(cfg.get('ip_intel') or {}, ignore_addresses=[
            '198.51.%d.%d' % (i // 250, i % 250 + 1) for i in range(ip_intel.IGNORE_MAX)])
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api._LOAD_CACHE.clear()
        st, d = self.ignore('185.220.101.11')
        self.assertEqual(st, 409)
        self.assertIn(str(ip_intel.IGNORE_MAX), d['error'])

    def test_only_the_instances_administrator(self):
        for role in ('viewer', 'auditor', 'finance'):
            self.assertEqual(self.ignore('185.220.101.11', role=role)[0], 403, role)
        self.tenanted(superadmin=False)
        self.assertEqual(self.ignore('185.220.101.11')[0], 403)
        self.assertEqual(self.settings(ignore_addresses='203.0.113.7')[0], 403)
        self.assertEqual(self.config().get('ignore_addresses') or [], [])
        self.tenanted(superadmin=True)
        self.assertEqual(self.ignore('185.220.101.11')[0], 200)

    def test_not_anonymously_and_not_by_get(self):
        api = self.api
        self.assertEqual(self.call(api.handle_ip_intel_ignore, {'ip': '185.220.101.11'}, method='GET')[0], 405)
        api.verify_token = lambda _t=None: (None, None)
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'ip': '185.220.101.11'}
        self.cap.clear()
        try:
            api.handle_ip_intel_ignore()
        except api.HTTPError:
            pass
        self.assertEqual(self.cap.get('status'), 401)
        self.assertEqual(self.config().get('ignore_addresses') or [], [])

    def test_a_non_public_address_is_refused_and_nothing_is_stored(self):
        """The row button only ever sees public attackers; a request for any other
        address stored an entry that could never match anything (v7.4.0)."""
        self.assertEqual(self.ignore('185.220.101.11')[0], 200, 'control: a public address')
        before = list(self.config()['ignore_addresses'])
        for ip in ('::', '0.0.0.0', '127.0.0.1', '10.0.0.5', '192.168.1.1', '203.0.113.7', 'fe80::1'):
            st, d = self.ignore(ip)
            self.assertEqual((st, d.get('error')), (400, 'Not a public address'), ip)
        self.assertEqual(self.config()['ignore_addresses'], before)

    def test_a_body_of_the_wrong_type_is_a_400_not_a_500(self):
        for body in ({'ip': 5}, {'ip': ['185.220.101.11']}, {'ip': {'a': 1}}, {'ip': None}):
            st, _ = self.call(self.api.handle_ip_intel_ignore, body)
            self.assertIn(st, (200, 400), body)
            self.assertNotEqual(st, 500, body)

    def test_it_is_a_post_only_route(self):
        routes = self.api._build_exact_routes()
        self.assertIs(routes[('POST', '/api/ip-intel/ignore')], self.api.handle_ip_intel_ignore)
        self.assertEqual([k for k in routes if k[1] == '/api/ip-intel/ignore'], [('POST', '/api/ip-intel/ignore')])

    # ── what the page is told ──
    def test_a_row_says_whether_it_is_ignored_including_by_a_network(self):
        self.settings(ignore_addresses=['185.220.101.11'])
        rows = {a['ip']: a for a in self.view()['attackers']}
        self.assertTrue(rows['185.220.101.11']['ignored'])
        self.assertFalse(rows['185.220.101.12']['ignored'])
        self.settings(ignore_addresses=['185.220.101.0/24'])
        rows = {a['ip']: a for a in self.view()['attackers']}
        self.assertTrue(rows['185.220.101.11']['ignored'] and rows['185.220.101.12']['ignored'])

    def test_only_the_operator_is_told_it_may_add(self):
        self.assertTrue(self.view()['can_ignore'])
        self.assertFalse(self.view(role='viewer')['can_ignore'])
        self.tenanted(superadmin=False)
        self.assertFalse(self.view()['can_ignore'])
        self.tenanted(superadmin=True)
        self.assertTrue(self.view()['can_ignore'])


if __name__ == '__main__':
    unittest.main()

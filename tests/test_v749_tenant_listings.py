#!/usr/bin/env python3
"""Listings that showed one tenant another tenant's hosts, and the operator's own data (7.4.9, authorization matrix F6).

The matrix scanned every response for the host names, ids and cloned object ids of tenants the caller must not see. Besides the
history, the schedule and the image view (tests/test_tenant_instance_gate.py), it found these, each reproduced here through the
real handler with the tenancy switch on:

* the ticket list, a single ticket, its hours, its attachments, its e-mail, the dashboard's open-ticket count and host markers;
* the home aggregate: links, the calendar, the on-call roster, scheduled jobs on the upcoming card;
* the knowledge base: the hosts an article is linked to;
* the digest (the last ten commands), discovery (what another tenant's agents found), the custom script list, maintenance
  windows and automation rules that name a host;
* the monitors, SLO figures, links, calendar, mail round trip, Proxmox, diagnostics, configuration as code, and the business side
  (time tracking, invoices, quotes, sites, contacts), which belong to the organisation running the installation.

A ticket has no tenant column. Its tenant is the one of the host it names (while that host exists), otherwise the one of the
account that opened it. The controls: the platform operator sees everything, a user of the default tenant sees the default
tenant's, and with the tenancy switch off nothing changes.
"""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_tenant_instance_gate import _Base, api  # noqa: E402


def _qs(value=''):
    os.environ['QUERY_STRING'] = value


class _Tenants(_Base):
    """_Base plus the files these handlers read and two more accounts."""
    STORES = _Base.STORES + ('TICKETS_FILE', 'KB_FILE', 'CALENDAR_FILE', 'LINKS_FILE', 'MAINT_FILE', 'RULES_FILE', 'DISCOVERY_FILE',
                             'CUSTOM_SCRIPTS_FILE', 'TIME_ENTRIES_FILE', 'ALERTS_FILE', 'FLEET_EVENTS_FILE')

    def setUp(self):
        super().setUp()
        _qs('')
        users = api.load(api.USERS_FILE)
        users['dviewer'] = {'role': 'viewer', 'tenant_id': 'default'}
        users['bviewer'] = {'role': 'viewer', 'tenant_id': 'tenantB'}
        api.save(api.USERS_FILE, users)
        devs = api.load(api.DEVICES_FILE)
        devs['devD'] = {'name': 'd1', 'token_hash': 'x'}                       # the default tenant's own host
        api.save(api.DEVICES_FILE, devs)
        api._LOAD_CACHE.clear()


def _ticket(tid, number, device_id='', created_by='platform', **kw):
    t = {'id': tid, 'number': number, 'subject': 'subject ' + tid, 'type': 'incident', 'status': 'ongoing', 'priority': 3,
         'device_id': device_id, 'device_name': '', 'created_by': created_by, 'created_at': 1, 'updated_at': 1,
         'affected_devices': [device_id] if device_id else [], 'messages': []}
    t.update(kw)
    return t


class TestTicketsStayInTheTenant(_Tenants):

    def setUp(self):
        super().setUp()
        api.save(api.TICKETS_FILE, {'ticket_seq': 4, 'tickets': [
            _ticket('tkB', 1, 'devB'),                       # about tenant B's host
            _ticket('tkC', 2, 'devC'),                       # about tenant C's host
            _ticket('tkP', 3),                               # opened by the operator, about no host
            _ticket('tkBu', 4, created_by='badmin')]})       # opened by a tenant B account, about no host

    def ids(self, who):
        st, d = self.call(api.handle_tickets, m='GET', who=who)
        self.assertEqual(st, 200)
        return sorted(t['id'] for t in d['tickets'])

    def test_a_tenant_lists_its_own_tickets_only(self):
        self.assertEqual(self.ids('badmin'), ['tkB', 'tkBu'])
        self.assertEqual(self.ids('cadmin'), ['tkC'])

    def test_the_operator_lists_all_of_them_and_a_default_tenant_user_the_operators(self):
        self.assertEqual(self.ids('platform'), ['tkB', 'tkBu', 'tkC', 'tkP'])
        self.assertEqual(self.ids('dviewer'), ['tkP'])

    def test_a_single_ticket_of_another_tenant_answers_not_found(self):
        st, _ = self.call(api.handle_ticket_get, 'tkC', m='GET')
        self.assertEqual(st, 404)
        st, d = self.call(api.handle_ticket_get, 'tkB', m='GET')
        self.assertEqual(st, 200)
        self.assertEqual(d['ticket']['id'], 'tkB')

    def test_another_tenants_ticket_cannot_be_changed_or_deleted(self):
        st, _ = self.call(api.handle_ticket_update, 'tkC', body={'status': 'closed', 'message': 'x'}, m='POST')
        self.assertEqual(st, 404)
        st, _ = self.call(api.handle_ticket_delete, 'tkC', m='DELETE')
        self.assertEqual(st, 404)
        left = {t['id']: t for t in api.load(api.TICKETS_FILE)['tickets']}
        self.assertIn('tkC', left)
        self.assertEqual(left['tkC']['status'], 'ongoing')
        self.assertEqual(left['tkC']['messages'], [])

    def test_a_ticket_cannot_be_moved_to_a_host_the_caller_cannot_see(self):
        """The name was read from the whole fleet, so any id gave back that host's name, and the ticket then belonged to
        that host's tenant."""
        self.call(api.handle_ticket_update, 'tkB', body={'device_id': 'devC'}, m='POST')
        t = {x['id']: x for x in api.load(api.TICKETS_FILE)['tickets']}['tkB']
        self.assertEqual(t['device_id'], '')
        self.assertNotEqual(t['device_name'], 'c1')

    def test_a_ticket_cannot_be_opened_about_another_tenants_host(self):
        st, d = self.call(api.handle_tickets, body={'subject': 'x', 'device_id': 'devC'}, m='POST')
        self.assertEqual(st, 404)
        self.assertEqual(len(api.load(api.TICKETS_FILE)['tickets']), 4)
        st, d = self.call(api.handle_tickets, body={'subject': 'mine', 'device_id': 'devB'}, m='POST')
        self.assertEqual(st, 200)
        self.assertIn(d['id'], self.ids('badmin'))
        self.assertNotIn(d['id'], self.ids('cadmin'))

    def test_a_parent_is_looked_up_among_the_tickets_the_caller_sees(self):
        st, d = self.call(api.handle_tickets, body={'subject': 'child', 'parent_number': '2'}, m='POST')       # #2 is tenant C's
        self.assertEqual(st, 200)
        child = {t['id']: t for t in api.load(api.TICKETS_FILE)['tickets']}[d['id']]
        self.assertFalse(child.get('parent'), 'a link to another tenant\'s ticket was stored')

    def test_the_hours_of_a_ticket_are_the_operators_business(self):
        st, _ = self.call(api.handle_ticket_hours, 'tkB', m='GET')
        self.assertEqual(st, 403)
        st, _ = self.call(api.handle_ticket_hours, 'tkB', m='GET', who='platform')
        self.assertEqual(st, 200)
        st, _ = self.call(api.handle_ticket_hours, 'tkC', m='GET')
        self.assertEqual(st, 404)

    def test_the_hosts_with_an_open_ticket_are_the_callers_own(self):
        api.save(api.TICKETS_FILE, {'tickets': [_ticket('tkM', 5, 'devB', affected_devices=['devB', 'devC'])]})
        self.who = 'badmin'
        api._LOAD_CACHE.clear()
        self.assertEqual(api._open_ticket_device_ids(), ['devB'])
        self.who = 'platform'
        api._LOAD_CACHE.clear()
        self.assertEqual(api._open_ticket_device_ids(), ['devB', 'devC'])

    def test_a_ticket_that_names_only_affected_hosts_belongs_to_the_first_that_exists(self):
        t = _ticket('tkA', 6, 'devB')
        t['device_id'] = ''
        t['affected_devices'] = ['gone', 'devC']
        self.assertEqual(api._ticket_tenant(t), 'tenantC')

    def test_control_without_the_filter_the_other_tenants_ticket_is_listed(self):
        saved = api._visible_tickets
        setattr(api, '_visible_tickets', lambda rows: [t for t in (rows or []) if isinstance(t, dict)])
        try:
            self.assertIn('tkC', self.ids('badmin'))
        finally:
            setattr(api, '_visible_tickets', saved)

    def test_control_with_tenancy_off_everyone_sees_everything(self):
        self.tenancy(False)
        self.assertEqual(self.ids('badmin'), ['tkB', 'tkBu', 'tkC', 'tkP'])


class TestTheOperatorsOwnDataIsClosedToOtherTenants(_Tenants):

    def enforce(self, pi, who='badmin'):
        self.who = who
        api._LOAD_CACHE.clear()
        self.cap.clear()
        try:
            api._enforce_operator_org_routes(pi)
        except api.HTTPError:
            pass
        return self.cap.get('status')

    def test_every_listed_prefix_matches_a_real_route(self):
        routes = {p for (_method, p) in api._build_exact_routes()}
        patterns = ' '.join(str(r) for r in api._PATTERN_ROUTE_DEFS)
        for prefix in api._OPERATOR_ORG_ROUTES:
            with self.subTest(prefix=prefix):
                self.assertTrue(any(r == prefix or r.startswith(prefix + '/') for r in routes) or prefix in patterns,
                                f'{prefix} matches no route')

    def test_a_tenant_user_is_refused_on_each_and_the_operators_organisation_is_not(self):
        for prefix in api._OPERATOR_ORG_ROUTES:
            for sub in ('', '/x'):
                with self.subTest(path=prefix + sub):
                    self.assertEqual(self.enforce(prefix + sub, 'badmin'), 403)
                    self.assertEqual(self.enforce(prefix + sub, 'bviewer'), 403)
                    self.assertIsNone(self.enforce(prefix + sub, 'platform'))
                    self.assertIsNone(self.enforce(prefix + sub, 'dviewer'))

    def test_other_routes_are_not_decided_here(self):
        for pi in ('/api/devices', '/api/tickets', '/api/monitoring-profiles', '/api/export', '/api/slo-x', '/api/home'):
            with self.subTest(pi=pi):
                self.assertIsNone(self.enforce(pi, 'badmin'))

    def test_with_tenancy_off_and_with_no_signed_in_user_nothing_is_decided(self):
        self.tenancy(False)
        self.assertIsNone(self.enforce('/api/links'))
        self.tenancy(True)
        setattr(api, 'verify_token', lambda _token=None: (None, None))
        self.assertIsNone(self.enforce('/api/links'))

    def test_the_calendar_feed_and_the_payment_webhook_paths(self):
        self.assertEqual(self.enforce('/api/calendar.ics'), 403)
        setattr(api, 'verify_token', lambda _token=None: (None, None))
        self.assertIsNone(self.enforce('/api/billing/payment-webhook'), 'a provider\'s webhook has no signed-in user')


class TestTheHomeAggregate(_Tenants):

    def setUp(self):
        super().setUp()
        now = int(time.time())
        api.save(api.LINKS_FILE, {'l1': {'title': 'Operator wiki', 'url': 'https://wiki.example/', 'category': 'docs'}})
        iso = lambda ts: time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(ts))
        api.save(api.CALENDAR_FILE, {'events': [{'title': 'Patch night for devB', 'start': iso(now + 3600),
                                                 'end': iso(now + 7200)}]})
        api.save(api.SCHEDULE_FILE, {'jobs': [
            {'id': 'j1', 'command': 'reboot', 'device_id': 'devB', 'device_name': 'b1', 'run_at': now + 600},
            {'id': 'j2', 'command': 'reboot', 'device_id': 'devC', 'device_name': 'c1', 'run_at': now + 700}]})
        api.save(api.MAINT_FILE, {'windows': []})
        api.save(api.TICKETS_FILE, {'tickets': [_ticket('tkB', 1, 'devB'), _ticket('tkC', 2, 'devC'), _ticket('tkC2', 3, 'devC')]})

    def home(self, who):
        _qs('')
        st, d = self.call(api.handle_home, m='GET', who=who)
        self.assertEqual(st, 200, d)
        return d

    def test_a_tenant_user_gets_no_links_no_calendar_and_no_on_call_roster(self):
        d = self.home('badmin')
        self.assertEqual(d['links'], [])
        self.assertFalse(any(i['kind'] == 'calendar' for i in d['upcoming']))
        self.assertFalse(d['oncall']['enabled'])

    def test_the_operator_and_its_own_viewer_do_get_them(self):
        for who in ('platform', 'dviewer'):
            with self.subTest(who=who):
                d = self.home(who)
                self.assertEqual([x['title'] for x in d['links']], ['Operator wiki'])
                self.assertTrue(any(i['kind'] == 'calendar' for i in d['upcoming']))

    def test_the_card_shows_scheduled_jobs_of_the_callers_own_hosts_only(self):
        titles = [i['title'] for i in self.home('badmin')['upcoming'] if i['kind'] == 'job']
        self.assertEqual(len(titles), 1)
        self.assertIn('b1', titles[0])
        both = [i['title'] for i in self.home('platform')['upcoming'] if i['kind'] == 'job']
        self.assertEqual(len(both), 2)

    def test_the_open_ticket_count_is_the_tenants_own(self):
        self.assertEqual(self.home('badmin')['tickets_open'], 1)
        self.assertEqual(self.home('cadmin')['tickets_open'], 2)
        self.assertEqual(self.home('platform')['tickets_open'], 3)
        self.assertEqual(self.home('badmin')['ticket_devices'], ['devB'])


class TestTheKnowledgeBase(_Tenants):

    def setUp(self):
        super().setUp()
        api.save(api.KB_FILE, {'articles': [
            {'id': 'kb1', 'title': 'Restart nginx', 'body': 'x', 'linked_devices': ['devB', 'devC', 'devD'], 'author': 'platform'}]})
        os.environ.setdefault('RP_KB', '1')
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg['kb_enabled'] = True
        cfg['tenancy_enforced'] = True
        api.save(api.CONFIG_FILE, cfg)

    def test_an_article_lists_the_hosts_the_caller_can_see(self):
        _st, d = self.call(api.handle_kb, m='GET')
        self.assertEqual(d['articles'][0]['linked_devices'], ['devB'])
        _st, d = self.call(api.handle_kb_article, 'kb1', m='GET')
        self.assertEqual(d['article']['linked_devices'], ['devB'])

    def test_the_operator_sees_all_of_them(self):
        _st, d = self.call(api.handle_kb, m='GET', who='platform')
        self.assertEqual(d['articles'][0]['linked_devices'], ['devB', 'devC', 'devD'])

    def test_a_tenant_administrator_does_not_write_the_shared_library(self):
        st, d = self.call(api.handle_kb, body={'title': 'x', 'body': 'y'}, m='POST')
        self.assertEqual(st, 403)
        st, d = self.call(api.handle_kb_article, 'kb1', body={'title': 'x'}, m='PATCH')
        self.assertEqual(st, 403)
        st, d = self.call(api.handle_kb_article, 'kb1', m='DELETE')
        self.assertEqual(st, 403)
        self.assertEqual(len(api.load(api.KB_FILE)['articles']), 1)
        st, d = self.call(api.handle_kb, body={'title': 'x', 'body': 'y'}, m='POST', who='platform')
        self.assertEqual(st, 200)


class TestOtherListingsNameOnlyTheCallersHosts(_Tenants):

    def test_the_digest_lists_the_last_commands_on_the_callers_hosts(self):
        api.save(api.HISTORY_FILE, {'entries': [
            {'ts': 1, 'device_id': 'devB', 'device_name': 'b1', 'command': 'reboot'},
            {'ts': 2, 'device_id': 'devC', 'device_name': 'c1', 'command': 'reboot'}]})
        st, d = self.call(api.handle_digest, m='GET')
        self.assertEqual([e['device_id'] for e in d['recent_commands']], ['devB'])
        st, d = self.call(api.handle_digest, m='GET', who='platform')
        self.assertEqual(len(d['recent_commands']), 2)

    def test_discovery_reports_what_the_callers_own_agents_found(self):
        api.save(api.DISCOVERY_FILE, {
            'devB': {'hosts': [{'ip': '10.0.0.5', 'mac': 'aa', 'hostname': 'printer-b'}]},
            'devC': {'hosts': [{'ip': '10.0.9.5', 'mac': 'bb', 'hostname': 'printer-c'}]}})
        st, d = self.call(api.handle_discovery, m='GET')
        self.assertEqual([h['hostname'] for h in d['hosts']], ['printer-b'])
        self.assertEqual(d['hosts'][0]['seen_by'], ['b1'])
        st, d = self.call(api.handle_discovery, m='GET', who='platform')
        self.assertEqual(len(d['hosts']), 2)

    def test_a_script_list_names_only_hosts_the_caller_can_see(self):
        api.save(api.CUSTOM_SCRIPTS_FILE, {'cs1': {'id': 'cs1', 'name': 's', 'body': 'true', 'assigned_devices': ['devB']}})
        dv = api.load(api.DEVICES_FILE)
        dv['devB']['custom_script_results'] = {'cs1': {'ok': True, 'output': '', 'rc': 0, 'ran_at': 1}}
        dv['devC']['custom_script_results'] = {'cs1': {'ok': True, 'output': '', 'rc': 0, 'ran_at': 1}}
        api.save(api.DEVICES_FILE, dv)
        api.save(api.CUSTOM_SCRIPTS_FILE, {'cs1': {'id': 'cs1', 'name': 's', 'body': 'true', 'assigned_devices': ['devB']},
                                           'cs2': {'id': 'cs2', 'name': 't', 'body': 'true', 'assigned_devices': []}})
        st, d = self.call(api.handle_custom_scripts_results, m='GET')
        self.assertEqual([r['device_id'] for r in d['results']], ['devB'])
        self.assertEqual({s['id']: s['assigned_devices'] for s in d['scripts']}, {'cs1': ['devB'], 'cs2': []})

    def test_a_script_results_listing_hides_a_host_the_script_is_assigned_to_but_the_caller_cannot_see(self):
        api.save(api.CUSTOM_SCRIPTS_FILE, {'cs1': {'id': 'cs1', 'name': 's', 'body': 'true', 'assigned_devices': ['devB', 'devC']}})
        st, d = self.call(api.handle_custom_scripts_results, m='GET')
        self.assertEqual(d['scripts'][0]['assigned_devices'], ['devB'])

    def test_a_maintenance_window_that_names_a_host_out_of_sight_is_not_listed(self):
        def win(wid, target, by):
            return {'id': wid, 'scope': 'device', 'target': target, 'reason': wid, 'created_by': by, 'cron': '0 3 * * *'}
        api.save(api.MAINT_FILE, {'windows': [
            win('w1', 'devB', 'platform'),       # the operator's window on a tenant B host
            win('w2', 'devC', 'platform'),       # the operator's window on a tenant C host
            win('w4', 'devC', 'badmin'),         # a tenant B account that named tenant C's host
            win('w5', 'devB', 'badmin'),         # a tenant B account, about its own host
            win('w6', 'devD', 'platform')]})     # the operator's, about the operator's host
        ids = lambda who: sorted(w['id'] for w in self.call(api.handle_maintenance_list, m='GET', who=who)[1]['windows'])
        self.assertEqual(ids('dviewer'), ['w6'], 'a default-tenant viewer sees no tenant host in a window')
        self.assertEqual(ids('badmin'), ['w5'], 'a window by the operator is the operator\'s, and a foreign host is out of sight')
        self.assertEqual(ids('platform'), ['w1', 'w2', 'w4', 'w5', 'w6'])

    def test_a_rule_that_matches_a_host_out_of_sight_is_not_listed(self):
        def rule(rid, dev):
            return {'id': rid, 'name': rid, 'enabled': True, 'actions': [],
                    'match': {'events': ['service_down'], 'device_match': {'device_id': dev}}}
        api.save(api.RULES_FILE, {'rules': [rule('r1', 'devB'), rule('r2', 'devC'), rule('r3', '')]})
        st, d = self.call(api.handle_automation_rules_list, m='GET')
        self.assertEqual(sorted(r['id'] for r in d['rules']), ['r1', 'r3'])
        st, d = self.call(api.handle_automation_rules_list, m='GET', who='platform')
        self.assertEqual(sorted(r['id'] for r in d['rules']), ['r1', 'r2', 'r3'])


class TestLldpSuggestions(_Tenants):
    def test_both_ends_of_a_suggested_link_are_hosts_the_caller_can_see(self):
        dv = api.load(api.DEVICES_FILE)
        dv['devB']['ip'] = '10.1.0.1'
        dv['devC']['ip'] = '10.2.0.1'
        api.save(api.DEVICES_FILE, dv)
        api.save(api.LLDP_NEIGHBORS_FILE, {'devB': {'neighbors': [{'mgmt_ip': '10.2.0.1', 'peer_name': 'c1', 'local_if': 'eth0'}]}})
        api._LOAD_CACHE.clear()
        sugg, _unresolved = api._lldp_suggestions()
        self.assertEqual(sugg, [], 'a link from a tenant host to another tenant\'s host was suggested')


if __name__ == '__main__':
    unittest.main()

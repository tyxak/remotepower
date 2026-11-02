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


class TestWhatNamesNoHostBelongsToTheInstallation(_Tenants):
    """An alert, a fleet event or a Needs-Attention item that names no host is about the installation: a monitor that fails, an
    integration that is down, a certificate that expires, the webhook queue. They were kept for every caller, so a tenant's users read
    the operator's monitor labels and target addresses on the home page, in the inbox and in the activity feed (the final run of the
    authorization matrix, "Public site - nginx.lab" and its URL in a tenant administrator's answers). The organisation that runs the
    installation still sees them."""

    def setUp(self):
        super().setUp()
        api.save(api.ALERTS_FILE, {'alerts': [
            {'id': 'aB', 'event': 'device_offline', 'device_id': 'devB', 'status': 'open', 'ts': 1, 'payload': {}},
            {'id': 'aC', 'event': 'device_offline', 'device_id': 'devC', 'status': 'open', 'ts': 1, 'payload': {}},
            {'id': 'aM', 'event': 'monitor_down', 'status': 'open', 'ts': 1, 'payload': {'label': 'Public site', 'target': 'https://nginx.lab/'}}]})
        api.save(api.FLEET_EVENTS_FILE, {'events': [
            {'event': 'device_offline', 'ts': 1, 'payload': {'device_id': 'devB'}},
            {'event': 'device_offline', 'ts': 2, 'payload': {'device_id': 'devC'}},
            {'event': 'monitor_down', 'ts': 3, 'payload': {'label': 'Public site'}}]})

    def alert_ids(self, who):
        st, d = self.call(api.handle_alerts_list, m='GET', who=who)
        self.assertEqual(st, 200, d)
        return sorted(a['id'] for a in d['alerts'])

    def event_names(self, who):
        # the conditional GET raises the HTTPError itself (it carries headers), so the stubbed respond() never sees the answer
        self.who, self.m = who, 'GET'
        api._LOAD_CACHE.clear()
        try:
            api.handle_fleet_events()
        except api.HTTPError as e:
            self.assertEqual(e.status, 200)
            return sorted((ev['event'], (ev.get('payload') or {}).get('device_id') or '') for ev in e.body)
        raise AssertionError('the handler did not answer')

    def test_the_alert_inbox_of_a_tenant_holds_its_own_hosts_only(self):
        self.assertEqual(self.alert_ids('badmin'), ['aB'])
        self.assertEqual(self.alert_ids('bviewer'), ['aB'])

    def test_the_operators_organisation_sees_the_monitor_alert_too(self):
        self.assertEqual(self.alert_ids('platform'), ['aB', 'aC', 'aM'])
        self.assertEqual(self.alert_ids('dviewer'), ['aM'], 'a default-tenant viewer sees no tenant host, and the installation\'s own alert')

    def test_a_tenant_cannot_act_on_the_installations_alert(self):
        st, d = self.call(api.handle_alert_ack, 'aM', body={}, who='badmin')
        self.assertEqual(st, 404, d)

    def test_the_activity_feed(self):
        self.assertEqual(self.event_names('badmin'), [('device_offline', 'devB')])
        self.assertEqual(self.event_names('platform'), [('device_offline', 'devB'), ('device_offline', 'devC'), ('monitor_down', '')])
        self.assertIn(('monitor_down', ''), self.event_names('dviewer'))

    def test_the_needs_attention_digest(self):
        payload = {'items': [{'kind': 'monitor_down', 'severity': 'critical', 'device': 'Public site', 'device_id': None, 'summary': 'x'},
                             {'kind': 'offline', 'severity': 'warning', 'device': 'b1', 'device_id': 'devB', 'summary': 'x'},
                             {'kind': 'offline', 'severity': 'warning', 'device': 'c1', 'device_id': 'devC', 'summary': 'x'}],
                   'counts': {}, 'total': 3}

        def ids(who):
            self.who = who
            api._LOAD_CACHE.clear()
            return [i['device_id'] for i in api._attention_for_caller(dict(payload))['items']]
        self.assertEqual(ids('badmin'), ['devB'])
        self.assertEqual(sorted(i or '' for i in ids('platform')), ['', 'devB', 'devC'])
        self.assertEqual(ids('dviewer'), [None], 'the operator\'s own viewer keeps the monitor item')


class TestTheSettingsAndTheScrapeCarryNoOperatorData(_Tenants):
    """The settings document and the Prometheus scrape of a tenant's user: the final run of the authorization matrix found the
    operator's monitors (label and target address), integrations, backup monitors, custom checks, drift profiles and mail hosts in
    both."""
    STORES = _Tenants.STORES + ('CONFIG_FILE', 'MON_HIST_FILE', 'MAINT_FILE', 'HARDWARE_FILE')

    def setUp(self):
        super().setUp()
        api.save(api.CONFIG_FILE, {
            'tenancy_enforced': True, 'metric_thresholds': {'cpu': 90}, 'online_ttl': 300, 'proxmox_host': 'proxmox.lab',
            'smtp_host': 'mail.operator.example', 'backup_path': '/srv/backups',
            'monitors': [{'label': 'Public site', 'type': 'http', 'target': 'https://nginx.lab/'}],
            'integrations': [{'type': 'jellyfin', 'url': 'http://jf.lab'}], 'custom_checks': [{'target': 'devD', 'name': 'x'}],
            'drift': {'assignments': [{'scope_value': 'devD'}]}, 'backup_monitors': [{'device_id': 'devD', 'path': '/x'}]})

    def config(self, who):
        st, d = self.call(api.handle_config_get, m='GET', who=who)
        self.assertEqual(st, 200, d)
        return d

    def test_a_tenant_reads_the_numbers_and_not_the_installations_collections(self):
        for who in ('badmin', 'bviewer'):
            with self.subTest(who=who):
                c = self.config(who)
                for key in ('monitors', 'integrations', 'custom_checks', 'backup_monitors'):
                    self.assertEqual(c[key], [], key)
                self.assertEqual(c['drift'], {})
                self.assertEqual((c['proxmox_host'], c['smtp_host'], c['backup_path']), ('', '', ''))
                self.assertEqual(c['metric_thresholds'], {'cpu': 90}, 'the limits their pages draw stay')
                self.assertEqual(c['online_ttl'], 300)

    def test_the_operators_organisation_reads_all_of_it(self):
        for who in ('platform', 'dviewer'):
            with self.subTest(who=who):
                c = self.config(who)
                self.assertEqual(len(c['monitors']), 1)
                self.assertEqual(c['proxmox_host'], 'proxmox.lab')
                self.assertEqual(len(c['integrations']), 1)

    def test_with_tenancy_off_nothing_changes(self):
        cfg = api.load(api.CONFIG_FILE)
        cfg['tenancy_enforced'] = False
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()
        self.assertEqual(len(self.config('badmin')['monitors']), 1)

    def test_a_tenants_scrape_has_no_monitor_families_and_the_operators_has(self):
        def ctx_for(who):
            self.who = who
            api._LOAD_CACHE.clear()
            return api._build_metrics_ctx(visible={'devB'})
        c = ctx_for('badmin')
        self.assertEqual((c['monitors'], c['monitor_state'], c['backup_monitors']), ([], {}, []))
        self.assertIsNone(c['slo'])
        c = ctx_for('platform')
        self.assertEqual(len(c['monitors']), 1)
        text = api.prometheus_export.generate_metrics(ctx_for('badmin'))
        self.assertNotIn('nginx.lab', text)
        self.assertNotIn('Public site', text)


class TestTheAuditTrailIsTheInstallationsAndATenantReadsItsOwnPart(_Tenants):
    """The whole audit log went to anyone who could pass the administrator-or-auditor check: every tenant's actions and the
    operator's, with host names and addresses in their detail. A tenant's administrator now reads what its own accounts did."""
    STORES = _Tenants.STORES + ('AUDIT_LOG_FILE',)

    def setUp(self):
        super().setUp()
        api.save(api.AUDIT_LOG_FILE, {'entries': [
            {'ts': 1, 'actor': 'platform', 'action': 'config_save', 'detail': 'proxmox_host=proxmox.lab'},
            {'ts': 2, 'actor': 'badmin', 'action': 'device_add', 'detail': 'device=devB'},
            {'ts': 3, 'actor': 'cadmin', 'action': 'device_add', 'detail': 'device=devC'},
            {'ts': 4, 'actor': 'dviewer', 'action': 'login', 'detail': ''},
            {'ts': 5, 'actor': 'system', 'action': 'backup', 'detail': 'written'}]})
        users = api.load(api.USERS_FILE)
        users['bauditor'] = {'role': 'auditor', 'tenant_id': 'tenantB'}
        users['dauditor'] = {'role': 'auditor', 'tenant_id': 'default'}
        api.save(api.USERS_FILE, users)

    def actors(self, who):
        st, d = self.call(api.handle_audit_log, m='GET', who=who)
        self.assertEqual(st, 200, d)
        rows = d['items'] if isinstance(d, dict) and 'items' in d else d
        return sorted(e['actor'] for e in rows)

    def test_a_tenant_admin_and_auditor_read_their_own_accounts_only(self):
        self.assertEqual(self.actors('badmin'), ['badmin'])
        self.assertEqual(self.actors('bauditor'), ['badmin'])

    def test_the_operators_organisation_reads_all_of_it(self):
        self.assertEqual(self.actors('platform'), ['badmin', 'cadmin', 'dviewer', 'platform', 'system'])
        self.assertEqual(self.actors('dauditor'), ['badmin', 'cadmin', 'dviewer', 'platform', 'system'])

    def test_with_tenancy_off_everyone_who_may_read_it_reads_all(self):
        self.tenancy(False)
        self.assertEqual(len(self.actors('badmin')), 5)

    def test_the_timeline_rows_without_a_host_are_the_installations(self):
        def titles(who):
            self.who = who
            api._LOAD_CACHE.clear()
            return sorted(r['title'] for r in api._timeline_audit_rows({'devB'}, {'devB': 'b1'}))
        self.assertEqual(titles('badmin'), ['badmin: device_add'])
        self.assertEqual(titles('platform'), ['badmin: device_add', 'platform: config_save'])


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

    def test_a_script_results_listing_hides_a_script_that_also_runs_on_a_host_the_caller_cannot_see(self):
        """The list endpoint hides such a script (_custom_script_reachable); the `scripts` key of the results listing named every
        script, so another tenant's script, its name and its description, reached everyone. The matrix found it as a marker of the
        other tenants' scripts in the answer for a default-tenant viewer and for tenant A's administrator."""
        api.save(api.CUSTOM_SCRIPTS_FILE, {
            'cs1': {'id': 'cs1', 'name': 'spans two tenants', 'body': 'true', 'assigned_devices': ['devB', 'devC']},
            'cs2': {'id': 'cs2', 'name': 'only here', 'body': 'true', 'assigned_devices': ['devB']},
            'cs3': {'id': 'cs3', 'name': 'only elsewhere', 'body': 'true', 'assigned_devices': ['devC']},
            'cs4': {'id': 'cs4', 'name': 'unassigned', 'body': 'true', 'assigned_devices': []}})
        st, d = self.call(api.handle_custom_scripts_results, m='GET')
        self.assertEqual(sorted(s['id'] for s in d['scripts']), ['cs2', 'cs4'])
        st, d = self.call(api.handle_custom_scripts_list, m='GET')
        self.assertEqual(sorted(s['id'] for s in d['scripts']), ['cs2', 'cs4'], 'the two listings agree')

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
        def rule(rid, dev, gate='tenantB'):
            return {'id': rid, 'name': rid, 'enabled': True, 'actions': [], 'tenant_gate': gate,
                    'match': {'events': ['service_down'], 'device_match': {'device_id': dev}}}
        api.save(api.RULES_FILE, {'rules': [rule('r1', 'devB'), rule('r2', 'devC'), rule('r3', ''),
                                            rule('o1', 'devB', None), rule('o2', 'devC', None)]})
        st, d = self.call(api.handle_automation_rules_list, m='GET')
        self.assertEqual(sorted(r['id'] for r in d['rules']), ['r1', 'r3'], 'a rule naming a foreign host stays out')
        st, d = self.call(api.handle_automation_rules_list, m='GET', who='platform')
        self.assertEqual(sorted(r['id'] for r in d['rules']), ['o1', 'o2'], 'the operator reads its own rules')


class TestWhatTheOperatorConfiguresReachesATenantThroughItsOwnHostsOnly(_Tenants):
    """Custom checks and drift profiles are the operator's settings. A tenant reads those that apply to every host and those
    aimed at a host, tag or group of its own; the targets of the others (another tenant's host id, a tag only it has) stay out."""

    def setUp(self):
        super().setUp()
        dv = api.load(api.DEVICES_FILE)
        dv['devB'].update({'tags': ['blue'], 'group': 'gb'})
        dv['devC'].update({'tags': ['red'], 'group': 'gc'})
        api.save(api.DEVICES_FILE, dv)
        cfg = api.load(api.CONFIG_FILE)
        cfg['custom_checks'] = [
            {'id': 'k-all', 'target_kind': 'all'}, {'id': 'k-none'},
            {'id': 'k-b', 'target_kind': 'host', 'target': 'devB'}, {'id': 'k-c', 'target_kind': 'host', 'target': 'devC'},
            {'id': 'k-blue', 'target_kind': 'tag', 'target': 'blue'}, {'id': 'k-red', 'target_kind': 'tag', 'target': 'red'},
            {'id': 'k-gb', 'target_kind': 'group', 'target': 'gb'}, {'id': 'k-gc', 'target_kind': 'group', 'target': 'gc'}]
        cfg['drift'] = {'profiles': [{'id': 'p1'}, {'id': 'p2'}, {'id': 'p3'}],
                        'assignments': [
                            {'scope_type': 'device', 'scope_value': 'devB', 'profile_id': 'p1'},
                            {'scope_type': 'device', 'scope_value': 'devC', 'profile_id': 'p2'},
                            {'scope_type': 'tag', 'scope_value': 'blue', 'profile_id': 'p3'}]}
        api.save(api.CONFIG_FILE, cfg)

    def checks(self, who):
        st, d = self.call(api.handle_custom_checks_list, m='GET', who=who)
        self.assertEqual(st, 200, d)
        return sorted(c['id'] for c in d['checks'])

    def drift(self, who):
        st, d = self.call(api.handle_drift_profiles, m='GET', who=who)
        self.assertEqual(st, 200, d)
        return (sorted(p['id'] for p in d['profiles']),
                sorted((a['scope_value'], a['profile_id']) for a in d['assignments']))

    def test_a_tenant_reads_the_checks_that_reach_its_own_hosts(self):
        self.assertEqual(self.checks('badmin'), ['k-all', 'k-b', 'k-blue', 'k-gb', 'k-none'])
        self.assertEqual(self.checks('cadmin'), ['k-all', 'k-c', 'k-gc', 'k-none', 'k-red'])

    def test_the_operators_organisation_reads_all_of_them(self):
        every = ['k-all', 'k-b', 'k-blue', 'k-c', 'k-gb', 'k-gc', 'k-none', 'k-red']
        self.assertEqual(self.checks('platform'), every)
        self.assertEqual(self.checks('dviewer'), every)

    def test_a_tenant_reads_the_profiles_assigned_to_its_own_hosts(self):
        self.assertEqual(self.drift('badmin'), (['p1', 'p3'], [('blue', 'p3'), ('devB', 'p1')]))
        self.assertEqual(self.drift('cadmin'), (['p2'], [('devC', 'p2')]))
        self.assertEqual(self.drift('platform')[0], ['p1', 'p2', 'p3'])

    def test_with_tenancy_off_nothing_is_filtered(self):
        self.tenancy(False)
        self.assertEqual(len(self.checks('badmin')), 8)
        self.assertEqual(len(self.drift('badmin')[1]), 3)


class TestTheGatewaySessionsThatNameNoHostAreTheInstallations(_Tenants):
    STORES = _Tenants.STORES + ('SSHGW_SESSIONS_FILE',)

    def setUp(self):
        super().setUp()
        api.save(api.SSHGW_SESSIONS_FILE, {'sessions': [
            {'id': 's1', 'device_id': 'devB', 'started': 3}, {'id': 's2', 'device_id': 'devC', 'started': 2},
            {'id': 's3', 'device_id': '', 'started': 1}]})          # a refused attempt names no host
        cfg = api.load(api.CONFIG_FILE)
        cfg['sshgw_enabled'] = True
        api.save(api.CONFIG_FILE, cfg)

    def listed(self, who):
        st, d = self.call(api.handle_sshgw_sessions, m='GET', who=who)
        self.assertEqual(st, 200, d)
        return sorted(r['id'] for r in d['sessions'])

    def kept(self):
        return sorted(r['id'] for r in api.load(api.SSHGW_SESSIONS_FILE)['sessions'])

    def test_the_list(self):
        self.assertEqual(self.listed('badmin'), ['s1'])
        self.assertEqual(self.listed('platform'), ['s1', 's2', 's3'])

    def test_a_tenant_clears_its_own_rows_and_leaves_the_installations(self):
        st, d = self.call(api.handle_sshgw_sessions_clear, m='DELETE', who='badmin')
        self.assertEqual((st, d.get('removed')), (200, 1), d)
        self.assertEqual(self.kept(), ['s2', 's3'], 'the refused attempt that names no host is not the tenant\'s to clear')

    def test_the_operator_clears_all_of_them(self):
        st, d = self.call(api.handle_sshgw_sessions_clear, m='DELETE', who='platform')
        self.assertEqual((st, d.get('removed')), (200, 3), d)

    def test_with_tenancy_off_nothing_is_filtered(self):
        self.tenancy(False)
        self.assertEqual(self.listed('badmin'), ['s1', 's2', 's3'])


class TestAMuteIsLiftedOnlyByWhoSeesItsHost(_Tenants):
    """DELETE /api/alert-mutes/{id} lifted any mute by id: the operator's, another tenant's, and one for the whole installation."""
    STORES = _Tenants.STORES + ('ALERT_MUTES_FILE',)

    def setUp(self):
        super().setUp()
        api.save(api.ALERT_MUTES_FILE, {'mutes': [
            {'id': 'mB', 'device_id': 'devB', 'event': 'service_down'}, {'id': 'mC', 'device_id': 'devC', 'event': 'service_down'},
            {'id': 'mD', 'device_id': 'devD', 'event': 'service_down'},      # the operator's own host
            {'id': 'mF', 'device_id': '', 'event': 'new_port'}]})            # a mute that names no host

    def lift(self, mute_id, who):
        return self.call(api.handle_alert_mute_delete, mute_id, m='DELETE', who=who)[0]

    def left(self):
        return sorted(m['id'] for m in api.load(api.ALERT_MUTES_FILE)['mutes'])

    def test_a_tenant_lifts_the_mutes_of_its_own_hosts_only(self):
        self.assertEqual([self.lift(i, 'badmin') for i in ('mC', 'mD', 'mF')], [404, 404, 404])
        self.assertEqual(self.left(), ['mB', 'mC', 'mD', 'mF'], 'nothing of the others was lifted')
        self.assertEqual(self.lift('mB', 'badmin'), 200)
        self.assertEqual(self.left(), ['mC', 'mD', 'mF'])

    def test_the_operator_lifts_any_of_them_including_the_one_for_the_whole_installation(self):
        self.assertEqual([self.lift(i, 'platform') for i in ('mF', 'mC', 'mD')], [200, 200, 200])

    def test_with_tenancy_off_nothing_is_decided_here(self):
        self.tenancy(False)
        self.assertEqual(self.lift('mC', 'badmin'), 200)

    def test_an_id_that_does_not_exist_answers_the_same_as_one_that_is_not_the_callers(self):
        self.assertEqual(self.lift('nope', 'badmin'), self.lift('mC', 'badmin'))


class TestTheOperatorsAcceptedRisksAreItsOwn(_Tenants):
    """The operator's `global` records were listed to every tenant (with who wrote them and why) and a tenant administrator
    could delete one, which lifts the acceptance for the whole installation."""
    STORES = _Tenants.STORES + ('CVE_IGNORE_FILE',)

    def setUp(self):
        super().setUp()
        api.save(api.CVE_IGNORE_FILE, {
            'CVE-1': {'scope': 'global', 'reason': 'ours', 'actor': 'platform', 'ts': 5},
            'CVE-2': {'scope': 'global', 'reason': 'theirs', 'actor': 'badmin', 'ts': 4, 'tenant': 'tenantB'},
            'CVE-3': {'scope': 'global', 'reason': 'old', 'actor': 'badmin', 'ts': 3},          # before the tenant was stamped
            'CVE-4': {'scope': 'devB', 'reason': 'the operator, on their host', 'actor': 'platform', 'ts': 2},
            'CVE-5': {'scope': 'devC', 'reason': 'the operator, on another tenant\'s host', 'actor': 'platform', 'ts': 1},
            'CVE-6': {'scope': 'devD', 'reason': 'the operator, on its own host', 'actor': 'platform', 'ts': 0}})

    def listed(self, who):
        st, d = self.call(api.handle_cve_ignore_list, m='GET', who=who)
        self.assertEqual(st, 200, d)
        return sorted(i['vuln_id'] for i in d['ignores'])

    def kept(self):
        return sorted(api.load(api.CVE_IGNORE_FILE))

    def test_a_tenant_reads_its_own_records_and_the_operators_for_its_hosts(self):
        self.assertEqual(self.listed('badmin'), ['CVE-2', 'CVE-3', 'CVE-4'])
        self.assertEqual(self.listed('cadmin'), ['CVE-5'])

    def test_the_operators_organisation_reads_its_own(self):
        self.assertEqual(self.listed('platform'), ['CVE-1', 'CVE-2', 'CVE-3', 'CVE-4', 'CVE-5', 'CVE-6'])
        self.assertEqual(self.listed('dviewer'), ['CVE-1', 'CVE-6'], 'the operator\'s global record and the one on its own host')

    def test_a_tenant_cannot_lift_the_operators_record(self):
        st, d = self.call(api.handle_cve_ignore_delete, 'CVE-1', m='DELETE', who='badmin')
        self.assertEqual(st, 404, d)
        self.assertIn('CVE-1', self.kept())
        st, d = self.call(api.handle_cve_ignore_delete, 'CVE-3', m='DELETE', who='badmin')
        self.assertEqual(st, 200, d)
        self.assertNotIn('CVE-3', self.kept())

    def test_with_tenancy_off_everyone_who_may_read_the_list_reads_all(self):
        self.tenancy(False)
        self.assertEqual(len(self.listed('badmin')), 6)


class TestTheOperatorsAutomationRulesAreItsOwn(_Tenants):
    """The operator's rules (stamped with no tenant) were shown to, edited and deleted by every tenant administrator."""

    def setUp(self):
        super().setUp()

        def rule(rid, **kw):
            r = {'id': rid, 'name': rid, 'enabled': True, 'actions': [{'type': 'run_script', 'script_id': 's1'}],
                 'match': {'events': ['device_offline'], 'device_match': {}}, 'cooldown_seconds': 0}
            r.update(kw)
            return r
        api.save(api.RULES_FILE, {'rules': [
            rule('r-op', tenant_gate=None, actor='platform'), rule('r-b', tenant_gate='tenantB', actor='badmin'),
            rule('r-old-op', actor='platform'),           # written before the stamp, by the operator
            rule('r-old-b', actor='badmin'),              # written before the stamp, by a tenant B account
            rule('r-old-gone', actor='nobody')]})         # its author was deleted: it is the operator's

    def listed(self, who):
        st, d = self.call(api.handle_automation_rules_list, m='GET', who=who)
        self.assertEqual(st, 200, d)
        return sorted(r['id'] for r in d['rules'])

    def test_who_reads_which(self):
        self.assertEqual(self.listed('badmin'), ['r-b', 'r-old-b'])
        self.assertEqual(self.listed('cadmin'), [])
        self.assertEqual(self.listed('platform'), ['r-old-gone', 'r-old-op', 'r-op'])
        self.assertEqual(self.listed('dviewer'), ['r-old-gone', 'r-old-op', 'r-op'], 'the operator\'s other users read its rules')

    def test_a_tenant_cannot_change_or_delete_the_operators_rule(self):
        body = {'name': 'taken over', 'match': {'events': ['device_offline']}, 'actions': [{'type': 'run_script', 'script_id': 's1'}]}
        st, d = self.call(api.handle_automation_rule_update, 'r-op', body=body, m='PUT')
        self.assertEqual(st, 404, d)
        st, d = self.call(api.handle_automation_rule_delete, 'r-op', m='DELETE')
        self.assertEqual(st, 404, d)
        names = {r['id']: r['name'] for r in api.load(api.RULES_FILE)['rules']}
        self.assertEqual(names['r-op'], 'r-op')
        st, d = self.call(api.handle_automation_rule_delete, 'r-old-b', m='DELETE')
        self.assertEqual(st, 200, d)

    def test_a_rule_written_before_the_stamp_by_a_tenant_account_stays_in_that_tenant(self):
        """It fires from a webhook with no request around it, so the stamp is the only tenancy signal. An unstamped rule of a
        tenant account matched every host of the installation, and run_script queues its body as root on the match."""
        api.save(api.SCRIPTS_FILE, {'scripts': [{'id': 's1', 'name': 'x', 'body': 'echo legacy'}]})
        api.save(api.RULES_FILE, {'rules': [{
            'id': 'r-old-b', 'enabled': True, 'name': 'legacy', 'actor': 'badmin',
            'match': {'events': ['device_offline'], 'device_match': {}},
            'actions': [{'type': 'run_script', 'script_id': 's1'}], 'cooldown_seconds': 0}]})
        api._LOAD_CACHE.clear()
        api._run_automation_rules('device_offline', {'device_id': 'devC'}, api.load(api.CONFIG_FILE) or {})
        self.assertEqual((api.load(api.CMDS_FILE) or {}).get('devC') or [], [], 'it ran on another tenant\'s host')
        api._run_automation_rules('device_offline', {'device_id': 'devB'}, api.load(api.CONFIG_FILE) or {})
        self.assertEqual(len((api.load(api.CMDS_FILE) or {}).get('devB') or []), 1, 'control: it runs on its own tenant\'s host')

    def test_with_tenancy_off_a_rule_written_by_a_tenant_account_is_shown(self):
        self.tenancy(False)
        self.assertEqual(self.listed('badmin'), ['r-old-b', 'r-old-gone', 'r-old-op', 'r-op'])


class TestABatchJobAndATunnelBelongToTheirHosts(_Tenants):
    STORES = _Tenants.STORES + ('BATCH_JOBS_FILE', 'TUNNELS_FILE', 'CMDS_FILE', 'CMD_OUTPUT_FILE', 'SCRIPTS_FILE')

    def setUp(self):
        super().setUp()
        now = int(time.time())
        job = lambda jid, hosts: {'id': jid, 'script_id': '', 'script_name': 'rotate ' + jid, 'actor': 'platform',   # noqa: E731
                                  'created': now, 'targets': hosts, 'dangerous': [],
                                  'per_device': {h: {'queued': True} for h in hosts}}
        api.save(api.BATCH_JOBS_FILE, {'jobs': {'jB': job('jB', ['devB']), 'jC': job('jC', ['devC']),
                                                'jBC': job('jBC', ['devB', 'devC'])}})
        dv = api.load(api.DEVICES_FILE)
        dv['devB2'] = {'name': 'b2', 'tenant': 'tenantB', 'token_hash': 'x'}
        dv['devC2'] = {'name': 'c2', 'tenant': 'tenantC', 'token_hash': 'x'}
        api.save(api.DEVICES_FILE, dv)
        api.save(api.TUNNELS_FILE, {'tun_b': {'endpoints': ['devB', 'devB2']}, 'tun_bc': {'endpoints': ['devB', 'devC']},
                                    'tun_c': {'endpoints': ['devC', 'devC2']}, 'tun_gone': {'endpoints': ['devB', 'devX']}})

    def job(self, jid, who):
        st, d = self.call(api.handle_exec_batch_status, jid, m='GET', who=who)
        return st, sorted((d.get('per_device') or {}))

    def test_a_job_none_of_whose_hosts_the_caller_sees_is_not_found(self):
        self.assertEqual(self.job('jC', 'badmin'), (404, []))
        self.assertEqual(self.job('nope', 'badmin')[0], 404)

    def test_a_job_shows_the_callers_hosts_only(self):
        self.assertEqual(self.job('jB', 'badmin'), (200, ['devB']))
        self.assertEqual(self.job('jBC', 'badmin'), (200, ['devB']))
        self.assertEqual(self.job('jBC', 'platform'), (200, ['devB', 'devC']))
        self.assertEqual(self.job('jC', 'platform'), (200, ['devC']))

    def test_with_tenancy_off_nothing_is_filtered(self):
        self.tenancy(False)
        self.assertEqual(self.job('jC', 'badmin'), (200, ['devC']))

    def delete(self, tid, who):
        return self.call(api.handle_tunnel_delete, tid, m='DELETE', who=who)[0]

    def test_a_tenant_removes_a_tunnel_whose_two_ends_it_sees_and_no_other(self):
        self.assertEqual([self.delete(t, 'badmin') for t in ('tun_bc', 'tun_c', 'tun_gone', 'tun_nope')], [404] * 4)
        self.assertEqual(sorted(api.load(api.TUNNELS_FILE)), ['tun_b', 'tun_bc', 'tun_c', 'tun_gone'])
        self.assertEqual(self.delete('tun_b', 'badmin'), 200)
        self.assertEqual(sorted(api.load(api.TUNNELS_FILE)), ['tun_bc', 'tun_c', 'tun_gone'])

    def test_the_operator_removes_any_tunnel_including_one_with_a_dangling_end(self):
        self.assertEqual([self.delete(t, 'platform') for t in ('tun_bc', 'tun_c', 'tun_gone')], [200] * 3)


class TestTheComplianceEvidenceNamesTheCallersHostsOnly(_Tenants):
    """The backup control printed `<host id>:<path>` for every failing backup of the installation."""

    def setUp(self):
        super().setUp()
        self._data_dir = api.DATA_DIR
        api.DATA_DIR = self.d
        api.save(self.d / 'backup_state.json', {'devB:/srv/b': {'ok': False, 'age_h': 90}, 'devC:/srv/c': {'ok': False, 'age_h': 99},
                                                'devD:/srv/d': {'ok': True, 'age_h': 1}, 'devGone:/srv/x': {'ok': False}})
        cfg = api.load(api.CONFIG_FILE)
        cfg['backup_monitors'] = [{'path': '/srv/b'}, {'path': '/srv/c'}, {'path': '/srv/d'}]
        api.save(api.CONFIG_FILE, cfg)

    def tearDown(self):
        api.DATA_DIR = self._data_dir
        super().tearDown()

    def facts(self, who):
        self.who = who
        api._LOAD_CACHE.clear()
        return api._compliance_facts(api._scope_filter_devices(api.load(api.DEVICES_FILE)))

    def test_a_tenant_reads_its_own_failing_backups_and_counts_its_own_paths(self):
        f = self.facts('badmin')
        self.assertEqual(f['failed_backups'], ['devB:/srv/b'])
        self.assertEqual(f['backup_monitors'], 1, 'the operator\'s monitor list is not the tenant\'s to count')

    def test_the_operator_reads_all_of_them(self):
        f = self.facts('platform')
        self.assertEqual(sorted(f['failed_backups']), ['devB:/srv/b', 'devC:/srv/c'])
        self.assertEqual(f['backup_monitors'], 3)

    def test_the_system_path_with_no_caller_is_unchanged(self):
        self.who = None
        api._LOAD_CACHE.clear()
        f = api._compliance_facts(None)
        self.assertEqual(sorted(f['failed_backups']), ['devB:/srv/b', 'devC:/srv/c'])
        self.assertEqual(f['backup_monitors'], 3)


class TestTheCmdbFunctionHintsAreTheCallersOwn(_Tenants):
    STORES = _Tenants.STORES + ('CMDB_FILE',)

    def test_a_tenant_reads_the_functions_of_its_own_assets(self):
        api.save(api.CMDB_FILE, {'devB': {'server_function': 'web'}, 'devC': {'server_function': 'billing-db'},
                                 'devD': {'server_function': 'router'}})
        st, d = self.call(api.handle_cmdb_server_functions, m='GET')
        self.assertEqual(d, ['web'])
        st, d = self.call(api.handle_cmdb_server_functions, m='GET', who='platform')
        self.assertEqual(d, ['billing-db', 'router', 'web'])


class TestThingsAnAdministratorOfOneTenantDidToTheOthers(_Tenants):
    """The sweep of the handlers that carry no tenant test found these, each answering a tenant administrator as it answers the
    operator's."""
    STORES = _Tenants.STORES + ('DEADMAN_FILE', 'ACME_STATE_FILE', 'CMDS_FILE')

    def test_a_tenant_moves_its_own_nodes_on_the_network_map_and_not_another_tenants(self):
        positions = [{'id': 'devB', 'x': 10, 'y': 20}, {'id': 'devC', 'x': 30, 'y': 40}, {'id': 'devD', 'x': 50, 'y': 60}]
        st, d = self.call(api.handle_network_positions, body={'positions': positions}, m='PUT')
        self.assertEqual((st, d.get('updated')), (200, 1), d)
        dv = api.load(api.DEVICES_FILE)
        self.assertEqual((dv['devB'].get('pos_x'), dv['devC'].get('pos_x'), dv['devD'].get('pos_x')), (10, None, None))
        st, d = self.call(api.handle_network_positions, body={'positions': positions}, m='PUT', who='platform')
        self.assertEqual((st, d.get('updated')), (200, 3), d)

    def test_a_tenants_administrator_reads_whether_the_assistant_is_on_and_not_the_operators_provider(self):
        cfg = api.load(api.CONFIG_FILE)
        cfg['ai'] = {'enabled': True, 'provider': 'openai', 'base_url': 'https://operator-gateway.example/v1',
                     'api_key': 'sk-operator-secret-1234', 'model': 'm1'}
        api.save(api.CONFIG_FILE, cfg)
        st, d = self.call(api.handle_ai_config_get, m='GET')
        self.assertEqual((st, d), (200, {'enabled': True, 'restricted': True}))
        st, d = self.call(api.handle_ai_config_get, m='GET', who='platform')
        self.assertEqual(d['provider'], 'openai')
        self.assertTrue(d['api_key'].endswith('1234'))

    def test_a_read_only_role_is_shown_a_dead_man_job_and_not_the_address_that_reports_it_alive(self):
        api.save(api.DEADMAN_FILE, {'jobs': [{'id': 'j1', 'name': 'nightly backup', 'token': 'tok-secret-77',
                                              'period_minutes': 60, 'grace_minutes': 10, 'last_ping': int(time.time())}]})
        st, d = self.call(api.handle_deadman_jobs, m='GET', who='dviewer')
        self.assertEqual(st, 200)
        self.assertEqual([j['name'] for j in d['jobs']], ['nightly backup'])
        self.assertNotIn('tok-secret-77', str(d))
        st, d = self.call(api.handle_deadman_jobs, m='GET', who='platform')
        self.assertIn('tok-secret-77', str(d), 'control: an administrator still gets the address')

    def test_the_operators_dns_credentials_go_into_commands_for_its_own_hosts_only(self):
        cfg = api.load(api.CONFIG_FILE)
        cfg['acme_dns_credentials'] = {'dns_cf': {'CF_Token': 'OPERATOR-CF-TOKEN'}}
        api.save(api.CONFIG_FILE, cfg)
        body = {'domain': 'app.example.com', 'dns_provider': 'dns_cf'}

        def queued(host, who):
            api.save(api.CMDS_FILE, {})
            st, d = self.call(api.handle_acme_issue, host, body=body, who=who)
            self.assertEqual(st, 200, d)
            return ' '.join(api.load(api.CMDS_FILE).get(host) or [])
        self.assertNotIn('OPERATOR-CF-TOKEN', queued('devB', 'badmin'), 'the tenant\'s host was handed the operator\'s token')
        self.assertIn('--issue', queued('devB', 'badmin'))
        self.assertIn('OPERATOR-CF-TOKEN', queued('devD', 'platform'), 'control: the operator\'s own host gets it')
        self.tenancy(False)
        self.assertIn('OPERATOR-CF-TOKEN', queued('devB', 'badmin'), 'with tenancy off nothing changes')


class TestSmallListingsThatNamedAnotherTenantsHostsOrTheOperatorsSettings(_Tenants):
    STORES = _Tenants.STORES + ('MAINT_SUPPRESS_LOG', 'ALERT_MUTES_FILE')

    def setUp(self):
        super().setUp()
        dv = api.load(api.DEVICES_FILE)
        dv['devB'].update({'tags': ['blue'], 'group': 'gb'})
        dv['devC'].update({'tags': ['red'], 'group': 'gc'})
        api.save(api.DEVICES_FILE, dv)

    def test_the_suppression_trail_lists_the_callers_hosts_and_the_entries_that_name_none_to_the_operators_organisation(self):
        api.save(api.MAINT_SUPPRESS_LOG, {'entries': [
            {'ts': 1, 'event': 'service_down', 'device_id': 'devB', 'window_id': 'w1'},
            {'ts': 2, 'event': 'service_down', 'device_id': 'devC', 'window_id': 'w1'},
            {'ts': 3, 'event': 'monitor_down', 'device_id': '', 'window_id': 'w1'},
            {'ts': 4, 'event': 'service_down', 'device_id': 'devD', 'window_id': 'w1'}]})
        ids = lambda who: [e['ts'] for e in self.call(api.handle_maintenance_suppressions, m='GET', who=who)[1]['entries']]  # noqa
        self.assertEqual(ids('badmin'), [1])
        self.assertEqual(ids('platform'), [4, 3, 2, 1])
        self.assertEqual(ids('dviewer'), [4, 3])

    def test_the_sla_targets_a_tenant_reads_reach_its_own_hosts(self):
        cfg = api.load(api.CONFIG_FILE)
        cfg['sla_targets'] = {'default': 99.0, 'groups': {'gb': 99.9, 'gc': 95.0}, 'tags': {'blue': 99.5, 'red': 90.0},
                              'devices': {'devB': 99.99, 'devC': 80.0}}
        api.save(api.CONFIG_FILE, cfg)
        st, d = self.call(api.handle_sla_targets_get, m='GET')
        self.assertEqual((d['default'], d['groups'], d['tags'], d['devices']),
                         (99.0, {'gb': 99.9}, {'blue': 99.5}, {'devB': 99.99}))
        st, d = self.call(api.handle_sla_targets_get, m='GET', who='platform')
        self.assertEqual((len(d['groups']), len(d['tags']), len(d['devices'])), (2, 2, 2))

    def test_the_drift_policies_a_tenant_reads_reach_its_own_hosts(self):
        cfg = api.load(api.CONFIG_FILE)
        cfg['drift_enforce_policies'] = [{'scope': 'tag', 'value': 'blue', 'mode': 'apply'},
                                         {'scope': 'tag', 'value': 'red', 'mode': 'enforce'},
                                         {'scope': 'group', 'value': 'gc', 'mode': 'apply'}]
        api.save(api.CONFIG_FILE, cfg)
        st, d = self.call(api.handle_drift_policies_get, m='GET')
        self.assertEqual([(p['scope'], p['value']) for p in d['policies']], [('tag', 'blue')])
        st, d = self.call(api.handle_drift_policies_get, m='GET', who='platform')
        self.assertEqual(len(d['policies']), 3)

    def test_a_tenant_reads_a_patch_decision_and_not_who_made_it_or_why(self):
        saved = api._patch_approvals
        api._patch_approvals = lambda: {'openssl': {'state': 'approved', 'actor': 'platform', 'ts': 5, 'note': 'after the audit'}}
        try:
            st, d = self.call(api.handle_patch_approvals_list, m='GET')
            self.assertEqual((d['approvals'][0]['state'], d['approvals'][0]['actor'], d['approvals'][0]['note']), ('approved', '', ''))
            st, d = self.call(api.handle_patch_approvals_list, m='GET', who='platform')
            self.assertEqual((d['approvals'][0]['actor'], d['approvals'][0]['note']), ('platform', 'after the audit'))
        finally:
            api._patch_approvals = saved


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

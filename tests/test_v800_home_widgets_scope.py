#!/usr/bin/env python3
"""8.0.0: the Home page's server-side widgets count and list what the caller may see.

`_dashboard_extra_widgets` builds the summaries behind the Home widgets from stores that are not keyed by host. The authorization matrix of the 8.0.0 review found that a tenant's
administrator was answered with the whole installation's figures: every open alert by severity, the monitors, the backup jobs and their stale checks, the VPN totals, the fleet
checks roll-up, and the list of integrations with their labels, versions and the addresses in their error text. The other widgets (the hardware, maintenance, container and
brute-force ones) already worked from the caller's own hosts, which is why the page looked right on one tenant.

This file fills every store those widgets read for two organisations and the operator, asks for the Home page as each, and checks each widget against what the caller's own hosts
and rights give. It also asks in both orders, because the checks roll-up is cached for 15 seconds for the whole fleet and a first caller with a narrow view must not fill it.
"""

import json
import sys
import time
import unittest
from pathlib import Path

_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_TESTS.parent / 'server' / 'cgi-bin'))

from test_v800_traffic import _Server, device  # noqa: E402

TOKENS = {'ta': ('alice', 'admin'), 'tb': ('bob', 'admin'), 'op': ('root', 'admin'), 'tv': ('vic', 'viewer')}
TENANT_OF = {'alice': 'acme', 'bob': 'globex', 'root': 'default', 'vic': 'acme'}
SECRET = 'prometheus.operator-internal:3000'


def alert(aid, dev, sev, now):
    return {'id': aid, 'event': 'host_offline', 'severity': sev, 'device_id': dev, 'created_at': now, 'payload': {'name': dev}}


class _Home(_Server):
    def put(self, devices, **cfg):
        # A home request runs the per-request sweeps, and one of them raises "server_disk_low" (high) when the disk under the data directory is 85% full. On a machine whose
        # temporary directory is that full (a RAM-backed /tmp holding a few hundred thousand leftovers of earlier test runs, here) the alert was a third high one and the test
        # counted it: it failed alone, on both backends, and in no run before the directory filled. The watchdog is not what this test is about, so it is off in every config it writes.
        cfg.setdefault('disk_watchdog_pct', 0)
        super().put(devices, **cfg)


    def setUp(self):
        super().setUp()
        api = self.api
        NOW = int(time.time())          # taken now: a full run reaches this test long after the module was imported, and a VPN client is 'connected' for a few minutes
        api.verify_token = lambda token: TOKENS.get(token, (None, None))
        api._caller_effective_tenant = lambda user: TENANT_OF[user]
        self.put({'web01': device(tenant='acme'), 'web02': device(id='web02', name='web02', token='t2', tenant='globex'), 'ops01': device(id='ops01', name='ops01', token='t3', tenant='default')},
                 tenancy_enforced=True, backup_monitors=[{'path': '/srv/backup', 'label': 'nightly'}],
                 monitors=[{'label': 'operator site', 'type': 'http', 'target': 'https://operator.example/'}])
        save = api.save
        save(api.ALERTS_FILE, {'alerts': [alert('a1', 'web01', 'critical', NOW), alert('a2', 'web02', 'critical', NOW), alert('a3', 'web02', 'high', NOW), alert('a4', 'ops01', 'medium', NOW),
                                          {'id': 'a5', 'event': 'monitor_down', 'severity': 'high', 'created_at': NOW, 'payload': {'name': 'operator site'}}]})
        save(api.INTEG_STATE_FILE, {'latest': {'g1': {'id': 'g1', 'label': 'Operator Grafana', 'type': 'grafana', 'status': 'critical', 'detail': 'Could not reach ' + SECRET,
                                                      'version': '11.1', 'checked': NOW, 'metrics': {}}}})
        save(api.MON_HIST_FILE, {'operator site': [{'ts': NOW, 'ok': False}], 'second': [{'ts': NOW, 'ok': True}]})
        save(api.BACKUP_JOBS_FILE, {'jobs': [{'id': 'j1', 'name': 'acme nightly', 'device_ids': ['web01'], 'last_run': NOW}, {'id': 'j2', 'name': 'globex nightly', 'device_ids': ['web02'], 'last_run': NOW},
                                             {'id': 'j3', 'name': 'operator nightly', 'device_ids': ['ops01'], 'last_run': NOW}]})
        save(api.DATA_DIR / 'backup_state.json', {'web01:/srv/backup': {'ok': False}, 'web02:/srv/backup': {'ok': False}, 'ops01:/srv/backup': {'ok': False}})
        save(api.VPN_FILE, {'tunnels': [{'id': 't1', 'clients': [{'last_handshake': NOW}, {'last_handshake': 0}]}]})
        api._LOAD_CACHE.clear()

    def widgets(self, tok):
        st, got = self.request('/api/home', token=tok)
        self.assertEqual(st, 200, got)
        return got.get('widgets') or {}


class TestEveryWidgetIsTheCallers(_Home):

    def test_the_open_alerts_by_severity_are_the_callers(self):
        self.assertEqual(self.widgets('ta')['alertsev'], {'critical': 1, 'high': 0, 'medium': 0, 'low': 0}, 'acme has one alert, on web01')
        self.assertEqual(self.widgets('tb')['alertsev'], {'critical': 1, 'high': 1, 'medium': 0, 'low': 0}, 'globex has two, on web02')
        self.assertEqual(self.widgets('tv')['alertsev'], {'critical': 1, 'high': 0, 'medium': 0, 'low': 0}, 'a viewer of acme sees what its administrator sees')
        op = self.widgets('op')['alertsev']
        self.api._LOAD_CACHE.clear()
        stored = [a for a in (self.api.load(self.api.ALERTS_FILE) or {}).get('alerts', []) if not (a.get('acknowledged_at') or a.get('resolved_at'))]
        self.assertEqual(op, {s: sum(1 for a in stored if a.get('severity') == s) for s in ('critical', 'high', 'medium', 'low')}, 'the operator sees every open alert, the ones with no host included')
        self.assertGreaterEqual(sum(op.values()), 5, 'control: the five that were stored are in it')

    def test_the_organisations_own_widgets_are_not_built_for_a_tenant(self):
        for tok in ('ta', 'tb', 'tv'):
            w = self.widgets(tok)
            self.assertEqual(w.get('monitors'), {}, tok)
            self.assertNotIn('integrations', w, tok)
            self.assertNotIn('vpn', w, tok)
            self.assertNotIn(SECRET, json.dumps(w), tok)
            self.assertNotIn('Operator Grafana', json.dumps(w), tok)
        w = self.widgets('op')
        self.assertEqual(w['monitors'], {'total': 2, 'up': 1, 'down': 1})
        self.assertEqual([i['label'] for i in w['integrations']['items']], ['Operator Grafana'])
        self.assertIn(SECRET, w['integrations']['items'][0]['detail'])
        self.assertEqual(w['vpn'], {'connected': 1, 'total': 2, 'tunnels': 1})

    def test_the_backup_widget_counts_the_callers_jobs_and_stale_checks(self):
        self.assertEqual(self.widgets('ta')['backups'], {'total': 1, 'ran24h': 1, 'monitors': 0, 'monitors_stale': 1}, 'acme: one job, one stale check on web01, and no list of monitors')
        self.assertEqual(self.widgets('tb')['backups'], {'total': 1, 'ran24h': 1, 'monitors': 0, 'monitors_stale': 1})
        self.assertEqual(self.widgets('op')['backups'], {'total': 3, 'ran24h': 3, 'monitors': 1, 'monitors_stale': 3})

    def test_the_checks_roll_up_adds_up_the_callers_hosts_in_either_order(self):
        api = self.api
        rows = api._fleet_checks_rows(api._load_ro(api.DEVICES_FILE) or {}, api.load(api.CONFIG_FILE) or {}, api._load_custom_scripts(), api._fleet_checks_fp(api.load(api.CONFIG_FILE) or {}, api._load_custom_scripts()))

        def total(ids):
            roll = {'ok': 0, 'warning': 0, 'critical': 0, 'unknown': 0}
            for h in rows:
                if h.get('device_id') in ids and h.get('monitored') is not False:
                    for k in roll:
                        roll[k] += ((h.get('summary') or {}).get('counts') or {}).get(k, 0)
            return roll
        self.assertTrue(sum(total({'web01', 'web02', 'ops01'}).values()) > sum(total({'web01'}).values()) > 0, 'control: the hosts have checks, and the fleet has more than one host\'s')
        for order in (('op', 'ta', 'tb'), ('ta', 'op', 'tb'), ('tb', 'ta', 'op')):
            api._LOAD_CACHE.clear()
            self.fresh_checks_cache()
            got = {}
            for tok in order:
                got[tok] = self.widgets(tok)['checksrollup']
            self.assertEqual(got['ta'], total({'web01'}), order)
            self.assertEqual(got['tb'], total({'web02'}), order)
            self.assertEqual(got['op'], total({'web01', 'web02', 'ops01'}), order)

    def test_a_tenant_that_asks_first_does_not_leave_its_view_in_the_cache_the_operator_reads(self):
        self.fresh_checks_cache()
        self.widgets('ta')                      # the first caller after the cache went stale has a narrow view
        st, got = self.request('/api/checks', token='op')
        self.assertEqual(st, 200, got)
        self.assertEqual(sorted(h['device_id'] for h in got['hosts']), ['ops01', 'web01', 'web02'], 'the operator\'s Checks page lists every host')

    def fresh_checks_cache(self):
        api = self.api
        try:
            api.save(api._fleet_checks_cache_file(), {})
        except Exception:                                  # a backend with no such file: nothing to empty
            pass
        api._LOAD_CACHE.clear()

    def test_on_an_installation_with_no_tenants_every_widget_is_built_for_everyone(self):
        self.put({'web01': device(), 'web02': device(id='web02', name='web02', token='t2')}, backup_monitors=[{'path': '/srv/backup', 'label': 'nightly'}])
        self.api.verify_token = lambda token: {'k': ('admin', 'admin'), 'v': ('vera', 'viewer')}.get(token, (None, None))
        for tok in ('k', 'v'):
            w = self.widgets(tok)
            self.assertIn('integrations', w, tok)
            self.assertEqual(w['monitors'].get('total'), 2, tok)
            self.assertEqual(w['alertsev'], {'critical': 2, 'high': 2, 'medium': 1, 'low': 0}, tok + ': with no tenants every alert is the caller\'s')
            self.assertEqual(w['backups'], {'total': 3, 'ran24h': 3, 'monitors': 1, 'monitors_stale': 3}, tok)


if __name__ == '__main__':
    unittest.main()

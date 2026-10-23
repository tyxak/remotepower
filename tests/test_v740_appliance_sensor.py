"""The appliance sensor, through the syslog intake (7.4.0).

A firewall or router has no agent, but it can send its syslog to RemotePower: as UDP
through `remotepower-syslogd`, or as an HTTP post. Either way the lines reach
`handle_syslog_in`, which stores them in the device's log buffer and then hands them
to `appliance_sensor_ingest`. These tests drive that path with the real handler, the
real store and the real sweep; only the two reputation services are faked.

The readers themselves (what a pf, RouterOS, Suricata or CrowdSec line means) are in
test_v740_appliance_evidence.py. What is held here is what happens around them:

  * the sensor is off until the operator turns it on, and a request with nothing
    for it to read costs no write;
  * a scan counted over several requests becomes one queue entry, kept in a
    document of its own;
  * what is queued is something the sweep reports, in the firewall's own words;
  * a request cannot fail the intake, whatever its lines say;
  * no write holds two locks at once;
  * a post that is not CrowdSec's is stored exactly as it always was.
"""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v740-appsensor-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))
import ipintel_store  # noqa: E402

import ip_intel  # noqa: E402
import srcpin  # noqa: E402
from test_ip_intel import ATTACKER, _Case, _fresh_api  # noqa: E402
from test_v740_appliance_evidence import (  # noqa: E402
    FIREWALL, cs_alert, pf, ros, stamp, suricata_fast)
from test_v740_ipintel_intake import _Held  # noqa: E402

CLOUDFLARE = '104.16.0.5'          # inside Cloudflare's published ranges: never queued, never reported
HANDLERS = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'


def wire(msg, app='filterlog', n=1):
    """A line as the syslog daemon forwards it: a priority, the RFC 5424 header, the message."""
    return '<134>' + stamp(msg, app=app, n=n)


def routeros(msg):
    """A RouterOS line as its UDP syslog sends it: a priority, a BSD header, the topics, the message."""
    return '<134>Oct 17 09:42:22 MikroTik ' + msg


class _Fw(_Case):
    """An OPNsense (`fw1`) and a MikroTik (`rt1`), each with a syslog token pinned to it, and the
    appliance sensor switched on."""
    TOKENS = {'fw1': 'rpwi_' + 'a' * 32, 'rt1': 'rpwi_' + 'b' * 32}

    def setUp(self):
        super().setUp()
        api = self.api
        devs = api.load(api.DEVICES_FILE)
        devs['fw1'] = {'name': 'opnsense01', 'os': 'OPNsense', 'agentless': True, 'ip': FIREWALL}
        devs['rt1'] = {'name': 'mikrotik01', 'os': 'RouterOS', 'agentless': True, 'ip': '192.0.2.2'}
        api.save(api.DEVICES_FILE, devs)
        api.save(api.LOG_WATCH_FILE, {})
        api.save(api.INBOUND_WEBHOOKS_FILE, {'tokens': [
            {'id': f'iwh_{d}', 'label': f'{d}-syslog', 'token': t, 'kind': 'syslog', 'scope_device_id': d,
             'enabled': True, 'created_at': 0, 'hit_count': 0} for d, t in self.TOKENS.items()]})
        env = mock.patch.dict(os.environ, {'REQUEST_METHOD': 'POST', 'CONTENT_TYPE': 'application/json'})
        env.start()
        self.addCleanup(env.stop)
        self.policy(appliance_enabled=True, report_enabled=True, report_min_count=10)
        api._brute_config = lambda: (True, 3, 600)
        api._LOAD_CACHE.clear()

    # ── driving the real handler ───────────────────────────────────────────────

    def post(self, lines=None, dev='fw1', body=None, ctype='application/json', raw=None):
        """POST to /api/syslog/in/<token> as the daemon does ({'lines': [...]}), or with any body."""
        api = self.api
        os.environ['CONTENT_TYPE'] = ctype
        payload = {'lines': lines} if body is None else body
        api.get_json_body = lambda: payload
        if raw is not None:
            os.environ['CONTENT_LENGTH'] = str(len(raw))
            api._read_request_body = lambda n: raw[:n]
        self.cap.clear()
        try:
            api.handle_syslog_in(self.TOKENS[dev])
        except api.HTTPError:
            pass
        api._LOAD_CACHE.clear()
        return self.cap.get('status'), self.cap.get('data') or {}

    def call(self, fn, method='POST', body=None, role='admin'):
        api = self.api
        api.verify_token = lambda _t=None: ('alice', role)
        api.method = lambda: method
        api.get_json_obj = lambda: dict(body or {})
        self.cap.clear()
        try:
            fn()
        except api.HTTPError:
            pass
        api._LOAD_CACHE.clear()
        return self.cap.get('status'), self.cap.get('data') or {}

    def scan(self, ip=ATTACKER, ports=10, base=1000, **kw):
        return [wire(pf(ip, dport=base + i, **kw), n=i) for i in range(ports)]

    # ── reading the result back ────────────────────────────────────────────────

    def store(self):
        self.api._LOAD_CACHE.clear()
        return ipintel_store.read(self.api)

    def queue(self):
        return self.store().get('queue') or []

    def row(self, dev='fw1'):
        return (self.store().get('sensors') or {}).get(dev) or {}

    def buffer(self, dev='fw1'):
        self.api._LOAD_CACHE.clear()
        return (((self.api.load(self.api.LOG_WATCH_FILE) or {}).get(dev) or {}).get('units') or {}).get('syslog') or []

    def scan_doc(self):
        api = self.api
        api._LOAD_CACHE.clear()
        return (api.load(api.IPINTEL_SCAN_FILE) or {}) if api.backend_exists(api.IPINTEL_SCAN_FILE) else {}

    def token_row(self, dev='fw1'):
        """The Inbound webhooks row of a device's syslog token: Hits and Last seen."""
        api = self.api
        api._LOAD_CACHE.clear()
        return [t for t in api.load(api.INBOUND_WEBHOOKS_FILE)['tokens'] if t['scope_device_id'] == dev][0]

    def inbound_log(self):
        api = self.api
        api._LOAD_CACHE.clear()
        return (api.load(api.INBOUND_WEBHOOK_LOG_FILE) or {}).get('entries') or []

    def abuse_posts(self):
        return [parse_qs(c['body'].decode()) for c in self.calls
                if c['method'] == 'POST' and 'abuseipdb' in c['url']]

    def sniff_posts(self):
        return [json.loads(c['body']) for c in self.calls if c['method'] == 'POST' and 'sniffcat' in c['url']]

    def view(self, role='admin'):
        return self.call(self.api.handle_ip_intel, 'GET', role=role)[1]


# ── off until asked ───────────────────────────────────────────────────────────

class TestOffUntilAsked(_Fw):
    def test_the_default_is_off(self):
        self.assertIs(ip_intel.DEFAULTS['appliance_enabled'], False)

    def test_off_stores_the_lines_and_reads_nothing(self):
        self.policy(appliance_enabled=False)
        st, d = self.post(self.scan(ports=30))
        self.assertEqual((st, d.get('lines_received')), (200, 30))
        self.assertEqual(len(self.buffer()), 30, 'the Logs tab is the same with the sensor off')
        self.assertEqual(self.queue(), [])
        self.assertEqual(self.scan_doc(), {})
        self.assertEqual(self.row(), {})

    def test_on_with_nothing_to_read_leaves_no_trace(self):
        st, d = self.post([wire('Accepted publickey for root from 10.0.0.9 port 51234 ssh2', app='sshd')])
        self.assertEqual((st, d.get('lines_received')), (200, 1))
        self.assertEqual((self.queue(), self.scan_doc(), self.row()), ([], {}, {}))

    def test_a_login_failure_is_not_counted_while_it_is_off(self):
        self.policy(appliance_enabled=False)
        bad = routeros(f'system,error,critical login failure for user admin from {ATTACKER} via ssh')
        self.post([bad] * 6, dev='rt1')
        self.assertEqual(self.queue(), [])

    def test_off_reads_one_scalar_and_builds_no_policy(self):
        """The check runs on every syslog batch from every device, and the switch is off by
        default, so it must not build the whole policy (a copy of every setting and a parse
        of the ignore list) to find that out."""
        self.policy(appliance_enabled=False)
        with mock.patch.object(self.api, 'ip_intel_policy', side_effect=AssertionError('the policy was built')):
            self.api.appliance_sensor_ingest('fw1', self.api.device_get('fw1'), self.scan(ports=30))
        self.assertEqual(self.queue(), [])
        self.policy(appliance_enabled=True)
        self.api.appliance_sensor_ingest('fw1', self.api.device_get('fw1'), self.scan(ports=30))
        self.assertEqual([x['ip'] for x in self.queue()], [ATTACKER], 'control: on, the same call queues the scan')


class TestTheSwitch(_Fw):
    def test_it_saves_reads_back_and_is_audited(self):
        self.policy(appliance_enabled=False)
        st, d = self.call(self.api.handle_ip_intel_settings, 'POST', {'appliance_enabled': True})
        self.assertEqual(st, 200, d)
        view = self.view()
        self.assertIs(view['settings']['appliance_enabled'], True)
        self.assertIs(view['appliance_enabled'], True)
        self.assertTrue(any('appliance_enabled=True' in a[2] for a in self.audit if a[1] == 'ip_intel_settings'))
        self.call(self.api.handle_ip_intel_settings, 'POST', {'appliance_enabled': False})
        self.assertIs(self.view()['appliance_enabled'], False)

    def test_it_and_the_host_sensor_are_independent(self):
        self.policy(sensor_enabled=True, appliance_enabled=False)
        self.call(self.api.handle_ip_intel_settings, 'POST', {'appliance_enabled': True})
        s = self.view()['settings']
        self.assertEqual((s['sensor_enabled'], s['appliance_enabled']), (True, True))
        self.call(self.api.handle_ip_intel_settings, 'POST', {'sensor_enabled': False})
        s = self.view()['settings']
        self.assertEqual((s['sensor_enabled'], s['appliance_enabled']), (False, True))

    def test_only_admins_change_it(self):
        st, _ = self.call(self.api.handle_ip_intel_settings, 'POST', {'appliance_enabled': False}, role='viewer')
        self.assertEqual(st, 403)
        self.assertIs(self.view()['appliance_enabled'], True)

    def test_everyone_sees_whether_it_is_on_but_only_admins_the_settings(self):
        d = self.view(role='viewer')
        self.assertIs(d['appliance_enabled'], True)
        self.assertEqual(d['settings'], {})


# ── port scans ────────────────────────────────────────────────────────────────

class TestPortScan(_Fw):
    def test_a_scan_is_one_queue_entry_carrying_the_firewalls_evidence(self):
        st, d = self.post(self.scan(ports=12))
        self.assertEqual((st, d.get('lines_received')), (200, 12))
        q = self.queue()
        self.assertEqual([(x['ip'], x['device_id'], x['unit']) for x in q], [(ATTACKER, 'fw1', 'threat-sensor')])
        ev = q[0]['evidence']
        self.assertGreaterEqual(ev['src']['fw'], 10)
        self.assertEqual(list(ev['tok']['fw']), ['fw:scan'])
        self.assertEqual(self.row()['sources'],
                         [{'kind': 'fw', 'path': 'syslog', 'lines': 12, 'parsed': 12, 'events': 1, 'state': 'ok'}])

    def test_nine_ports_are_not_a_scan(self):
        self.post(self.scan(ports=9))
        self.assertEqual(self.queue(), [])
        self.assertEqual(self.row()['sources'][0]['events'], 0, 'the lines are counted, the address is not queued')

    def test_a_slow_scan_is_counted_across_requests_in_a_document_of_its_own(self):
        api = self.api
        t0 = int(time.time()) - 1700
        for i in range(10):
            lines = [wire(pf(ATTACKER, dport=2000 + i), n=i)]
            api.appliance_sensor_ingest('fw1', api.device_get('fw1'), lines, now=t0 + 150 * i)
            api._LOAD_CACHE.clear()
            if i == 4:
                self.assertEqual(self.queue(), [], 'five ports in, nothing yet')
                held = self.scan_doc()['fw1']['scan'][ATTACKER]
                self.assertEqual(len(held['p']), 5, 'the half-counted scan waits in the scan document')
        q = self.queue()
        self.assertEqual([(x['ip'], x['device_id']) for x in q], [(ATTACKER, 'fw1')])
        self.assertEqual((q[0]['evidence']['first'], q[0]['evidence']['last']), (t0, t0 + 150 * 9))

    def test_the_same_scan_in_the_next_request_adds_nothing(self):
        self.post(self.scan(ports=10))
        before = self.queue()[0]
        self.post(self.scan(ports=10, base=5000))
        self.assertEqual(len(self.queue()), 1)
        self.assertEqual(self.queue()[0]['evidence']['src'], before['evidence']['src'])

    def test_the_table_of_addresses_is_never_written_for_a_scan(self):
        ipintel_store.update(self.api, attackers={'45.7.0.1': {'first_seen': 1, 'last_seen': 2, 'devices': {}}})
        before = self.api.load(self.api.IPINTEL_FILE)
        self.post(self.scan(ports=12))
        self.api._LOAD_CACHE.clear()
        self.assertEqual(self.api.load(self.api.IPINTEL_FILE), before)

    def test_private_and_reserved_sources_are_never_queued(self):
        for src in ('10.0.0.5', '192.168.1.9', '127.0.0.1', '169.254.1.1', '100.64.0.7'):
            self.post(self.scan(ip=src, ports=12))
        self.assertEqual(self.queue(), [])

    def test_a_cloudflare_address_is_counted_as_set_aside_and_not_queued(self):
        self.post(self.scan(ip=CLOUDFLARE, ports=12))
        self.assertEqual(self.queue(), [])
        self.assertEqual(self.row()['ignored'], {'cloudflare': 1})

    def test_the_sweep_reports_the_scanner_once_in_the_firewalls_words(self):
        self.post(self.scan(ports=12))
        self.sweep()
        self.assertEqual(len(self.abuse_posts()), 1)
        form = self.abuse_posts()[0]
        self.assertEqual(form['ip'], [ATTACKER])
        self.assertEqual(form['categories'], ['14'], 'AbuseIPDB: port scan')
        self.assertTrue(form['comment'][0].startswith('port scanning: '), form['comment'])
        self.assertIn('seen by firewall log (reported by RemotePower)', form['comment'][0])
        self.assertEqual(self.sniff_posts()[0]['categories'], [4], 'SniffCat: port scan')
        att = self.store()['attackers'][ATTACKER]
        self.assertEqual(sorted(att['devices']), ['fw1'])

    def test_a_scanner_that_keeps_going_is_not_reported_again_within_the_day(self):
        api = self.api
        now = int(time.time())
        api.appliance_sensor_ingest('fw1', api.device_get('fw1'), self.scan(ports=10), now=now - 4000)
        self.sweep()
        self.assertEqual(len(self.abuse_posts()), 1)
        api.appliance_sensor_ingest('fw1', api.device_get('fw1'), self.scan(ports=10, base=7000), now=now - 1000)
        self.assertEqual(len(self.queue()), 1, 'the next window queues it again ...')
        self.sweep()
        self.assertEqual(len(self.abuse_posts()), 1, '... and the sweep reports an address once a day')

    def test_the_evidence_view_names_the_source(self):
        self.post(self.scan(ports=12))
        self.sweep()
        att = [a for a in self.view()['attackers'] if a['ip'] == ATTACKER][0]
        self.assertEqual([(s['id']) for s in att['evidence']['sources']], ['fw'])
        self.assertEqual([c['id'] for c in att['evidence']['classes']], ['port_scan'])


# ── the decoy port ────────────────────────────────────────────────────────────

class TestDecoyPort(_Fw):
    def hit(self, n=2, ip=ATTACKER, prefix='rp-trap', **kw):
        return [routeros(ros(prefix, ip, 2222, **kw)) for _ in range(n)]

    def test_two_hits_are_queued_as_a_decision(self):
        st, _ = self.post(self.hit(2), dev='rt1')
        self.assertEqual(st, 200)
        q = self.queue()
        self.assertEqual([(x['ip'], x['device_id']) for x in q], [(ATTACKER, 'rt1')])
        self.assertEqual((q[0]['evidence']['src'], q[0]['evidence']['trp']), ({'dp': 2}, 1))

    def test_one_hit_is_not_enough(self):
        self.post(self.hit(1), dev='rt1')
        self.assertEqual(self.queue(), [])
        self.assertEqual(self.row('rt1')['sources'][0]['kind'], 'fw')

    def test_it_is_reported_at_once_however_high_the_operator_set_the_count(self):
        self.policy(report_min_count=1000)
        self.post(self.hit(2), dev='rt1')
        self.sweep()
        self.assertEqual(len(self.abuse_posts()), 1)
        form = self.abuse_posts()[0]
        self.assertEqual(form['categories'], ['14'])
        self.assertIn('connecting to a decoy port', form['comment'][0])
        self.assertIn('seen by decoy port', form['comment'][0])
        att = [a for a in self.view()['attackers'] if a['ip'] == ATTACKER][0]
        self.assertEqual(att['evidence']['confirmed'], 'a decoy port')

    def test_a_drop_rule_is_not_a_decoy(self):
        self.post([routeros(ros('drop-in', ATTACKER, 2222)) for _ in range(5)], dev='rt1')
        self.assertEqual(self.queue(), [], 'five refused packets on one port are below the scan line')

    def test_an_ack_to_the_decoy_port_is_not_a_hit(self):
        self.post(self.hit(6, flags='ACK'), dev='rt1')
        self.assertEqual(self.queue(), [])

    def test_the_hits_may_arrive_in_separate_requests(self):
        self.post(self.hit(1), dev='rt1')
        self.post(self.hit(1), dev='rt1')
        self.assertEqual([x['ip'] for x in self.queue()], [ATTACKER])

    def test_a_private_address_on_the_decoy_port_is_the_operators_own(self):
        self.post(self.hit(4, ip='192.168.88.20'), dev='rt1')
        self.assertEqual(self.queue(), [])


# ── intrusion detection ───────────────────────────────────────────────────────

class TestIds(_Fw):
    def alerts(self, n, sig='ET SCAN Nmap Scripting Engine User-Agent Detected', ip=ATTACKER):
        return [wire(suricata_fast(sig, 'Web Application Attack', src=ip), app='suricata', n=i) for i in range(n)]

    def test_alerts_for_one_address_are_one_queue_entry(self):
        self.post(self.alerts(5) + self.alerts(2, sig='ET SCAN Potential SSH Scan'))
        q = self.queue()
        self.assertEqual([(x['ip'], x['device_id']) for x in q], [(ATTACKER, 'fw1')])
        self.assertEqual(q[0]['evidence']['src'], {'ids': 7})
        self.assertEqual(q[0]['evidence']['tok']['ids'], {'ids:scanner': 5, 'ids:port_scan': 2})
        self.assertEqual(self.row()['sources'],
                         [{'kind': 'ids', 'path': 'syslog', 'lines': 7, 'parsed': 7, 'events': 1, 'state': 'ok'}])

    def test_twelve_scanner_alerts_are_reported_as_vulnerability_scanning(self):
        self.post(self.alerts(12))
        self.sweep()
        form = self.abuse_posts()[0]
        self.assertTrue(form['comment'][0].startswith('vulnerability scanning: '), form['comment'])
        self.assertIn('seen by intrusion detection (reported by RemotePower)', form['comment'][0])
        self.assertEqual(form['categories'], ['19,21'], 'AbuseIPDB: bad web bot, web app attack')

    def test_twelve_scan_alerts_are_reported_as_port_scanning(self):
        self.post(self.alerts(12, sig='ET SCAN Potential SSH Scan'))
        self.sweep()
        form = self.abuse_posts()[0]
        self.assertTrue(form['comment'][0].startswith('port scanning: '), form['comment'])
        self.assertEqual(form['categories'], ['14'], 'AbuseIPDB: port scan')

    def test_a_few_alerts_wait_for_the_operators_count_like_any_other_probing(self):
        self.post(self.alerts(4))
        self.sweep()
        self.assertEqual(self.abuse_posts(), [])

    def test_alerts_that_name_no_attack_are_read_and_dropped(self):
        lines = [wire(suricata_fast('ET INFO Observed DNS Query to .biz TLD', 'Misc activity'),
                      app='suricata', n=i) for i in range(20)]
        self.post(lines)
        self.assertEqual(self.queue(), [])
        self.assertEqual(self.row()['sources'][0]['parsed'], 20)

    def test_a_reputation_list_alone_is_dropped_when_the_bar_is_off(self):
        self.policy(report_listed_after=0)
        lines = [wire(suricata_fast('ET DROP Dshield Block Listed Source group 1', 'Misc Attack'),
                      app='suricata', n=i) for i in range(20)]
        self.post(lines)
        self.assertEqual(self.queue(), [])
        self.assertEqual(self.row()['sources'][0]['parsed'], 20)

    def test_an_eve_alert_is_read(self):
        eve = ('{"timestamp":"2026-10-17T09:42:22.123456+0200","event_type":"alert",'
               f'"src_ip":"{ATTACKER}","src_port":40222,"dest_ip":"{FIREWALL}","dest_port":22,"proto":"TCP",'
               '"alert":{"signature":"ET SCAN Potential SSH Scan","category":"Attempted Information Leak"}}')
        self.post([wire(eve, app='suricata', n=i) for i in range(10)])
        self.assertEqual([x['ip'] for x in self.queue()], [ATTACKER])

    def test_an_eve_alert_cut_at_the_intake_limit_is_counted_as_unread(self):
        """The intake keeps 2,048 characters of a line, so a long EVE record arrives cut
        off. It must show on the Log sources card as not read, not as a quiet source."""
        pad = 'x' * 2100
        eve = ('{"timestamp":"2026-10-17T09:42:22.123456+0200","event_type":"alert",'
               f'"src_ip":"{ATTACKER}","dest_port":22,"proto":"TCP","payload_printable":"{pad}",'
               '"alert":{"signature":"ET SCAN Potential SSH Scan","category":"Attempted Information Leak"}}')
        self.post([wire(eve, app='suricata')])
        self.assertEqual(self.queue(), [])
        src = self.row()['sources'][0]
        self.assertEqual((src['kind'], src['lines'], src['parsed'], src['state']), ('ids', 1, 0, 'unparsed'))


# ── CrowdSec ──────────────────────────────────────────────────────────────────

class TestCrowdSec(_Fw):
    def test_an_alert_post_becomes_a_line_and_a_queue_entry(self):
        st, d = self.post(body=[cs_alert(events=6)])
        self.assertEqual((st, d.get('lines_received')), (200, 1))
        self.assertEqual([e['line'] for e in self.buffer()],
                         [f'crowdsec alert scenario=crowdsecurity/ssh-bf src={ATTACKER} events=6 decision=ban'])
        q = self.queue()
        self.assertEqual([(x['ip'], x['device_id']) for x in q], [(ATTACKER, 'fw1')])
        self.assertEqual((q[0]['evidence']['src'], q[0]['evidence']['dec']), ({'cs': 6}, 1))

    def test_a_decision_is_reported_at_once_as_ssh_brute_force(self):
        self.policy(report_min_count=1000)
        self.post(body=[cs_alert(events=6)])
        self.sweep()
        form = self.abuse_posts()[0]
        self.assertEqual(form['categories'], ['18,22'])
        self.assertIn('seen by CrowdSec (reported by RemotePower)', form['comment'][0])

    def test_one_alert_object_is_read_as_a_list_of_one(self):
        st, d = self.post(body=cs_alert())
        self.assertEqual((st, d.get('lines_received')), (200, 1))

    def test_simulated_alerts_are_answered_ok_and_keep_nothing(self):
        st, d = self.post(body=[cs_alert(simulated=True)])
        self.assertEqual((st, d.get('ok'), d.get('lines_received')), (200, True, 0))
        self.assertEqual((self.buffer(), self.queue()), ([], []))

    def test_a_post_with_nothing_to_keep_still_counts_as_a_delivery(self):
        """CrowdSec's own test notification, and any simulated alert, is read and dropped.
        The token has to show that it arrived, or a setup that works looks dead."""
        self.assertEqual(self.token_row()['hit_count'], 0)
        st, d = self.post(body=[cs_alert(simulated=True)])
        self.assertEqual((st, d.get('lines_received')), (200, 0))
        row = self.token_row()
        self.assertEqual(row['hit_count'], 1)
        self.assertGreater(row['last_seen'], 0)
        last = self.inbound_log()[-1]
        self.assertEqual((last['kind'], last['status']), ('syslog', '200'))
        self.assertIn('nothing to keep', last['detail'])
        self.assertEqual(self.token_row('rt1')['hit_count'], 0, 'only the pinned device\'s token counts')
        self.post(body=[cs_alert(events=6)])
        self.assertEqual(self.token_row()['hit_count'], 2, 'control: a post that is kept counts as before')

    def test_alerts_from_the_community_list_alone_are_not_this_firewalls_finding(self):
        capi = [{'origin': 'CAPI', 'type': 'ban', 'value': ATTACKER}]
        self.policy(report_min_count=1000)
        self.post(body=[cs_alert(events=3, decisions=capi)])
        self.sweep()
        self.assertEqual(self.abuse_posts(), [], 'three events, no local decision: below the operator\'s count')

    def test_a_forged_address_or_scenario_keeps_nothing(self):
        bad = [cs_alert(ip='1.2.3.4\nevil'), cs_alert(scenario='x\nsrc=8.8.8.8'), cs_alert(ip='not an address')]
        st, d = self.post(body=bad)
        self.assertEqual((st, d.get('lines_received')), (200, 0))
        self.assertEqual((self.buffer(), self.queue()), ([], []))


# ── a body that is not CrowdSec's ─────────────────────────────────────────────

class TestWhatTheBodyMayBe(_Fw):
    """The syslog endpoint takes {"lines": [...]}, a bare array, and plain text. CrowdSec's
    JSON must not change what any of those do."""

    def test_the_daemons_own_shape(self):
        st, d = self.post(['a line', 'another'])
        self.assertEqual((st, d.get('lines_received')), (200, 2))
        self.assertEqual([e['line'] for e in self.buffer()], ['a line', 'another'])

    def test_a_bare_array_of_lines(self):
        st, d = self.post(body=['one', 'two', 'three'])
        self.assertEqual((st, d.get('lines_received')), (200, 3))

    def test_an_array_of_records_from_a_log_shipper_is_kept_as_text(self):
        """fluent-bit's HTTP output posts an array of objects. The endpoint has always
        kept each one as a line; reading CrowdSec's alerts must not make it drop them."""
        records = [{'date': 1792230000.5, 'log': 'first record'}, {'date': 1792230001.0, 'log': 'second record'}]
        st, d = self.post(body=records)
        self.assertEqual((st, d.get('lines_received')), (200, 2), 'the records were answered as if they were nothing')
        self.assertEqual(len(self.buffer()), 2)
        self.assertIn('first record', self.buffer()[0]['line'])

    def test_plain_text(self):
        raw = b'one line\nanother line\n'
        st, d = self.post(body={}, ctype='text/plain', raw=raw)
        self.assertEqual((st, d.get('lines_received')), (200, 2))

    def test_an_object_without_lines_is_still_no_lines(self):
        st, d = self.post(body={'hello': 'world'}, raw=b'')
        self.assertEqual(st, 400)
        self.assertEqual(self.buffer(), [])

    def test_a_mixed_array_is_not_taken_for_crowdsec(self):
        st, d = self.post(body=[cs_alert(), 'a plain line'])
        self.assertEqual((st, d.get('lines_received')), (200, 2))
        self.assertIn('plain line', ' '.join(e['line'] for e in self.buffer()))


# ── logins ────────────────────────────────────────────────────────────────────

class TestLogins(_Fw):
    def test_failed_routeros_ssh_logins_are_counted_as_ssh_brute_force(self):
        bad = routeros(f'system,error,critical login failure for user admin from {ATTACKER} via ssh')
        self.post([bad] * 5, dev='rt1')
        self.assertEqual([(x['ip'], x['device_id'], x['unit']) for x in self.queue()],
                         [(ATTACKER, 'rt1', 'sshd.service')])

    def test_and_reported_as_ssh_brute_force_once_they_reach_the_operators_count(self):
        """The counter queues an address when it crosses its own threshold, and the sweep
        reports it when the count reaches the operator's (10 here)."""
        self.api._brute_config = lambda: (True, 10, 600)
        bad = routeros(f'system,error,critical login failure for user admin from {ATTACKER} via ssh')
        self.post([bad] * 12, dev='rt1')
        self.sweep()
        self.assertEqual(self.abuse_posts()[0]['categories'], ['18,22'])

    def test_failed_winbox_and_web_logins_are_counted_too(self):
        for via in ('winbox', 'web'):
            bad = routeros(f'system,error,critical login failure for user admin from {ATTACKER} via {via}')
            self.post([bad] * 5, dev='rt1')
        q = self.queue()
        self.assertEqual({(x['ip'], x['unit']) for x in q}, {(ATTACKER, 'syslog')})

    def test_failed_opnsense_web_logins_are_counted(self):
        bad = wire(f"/index.php: Web GUI authentication error for 'root' from {ATTACKER}", app='php-fpm')
        self.post([bad] * 5)
        self.assertEqual([(x['ip'], x['device_id'], x['unit']) for x in self.queue()],
                         [(ATTACKER, 'fw1', 'syslog')])

    def test_a_user_name_cannot_name_the_victim(self):
        """RouterOS writes the user name before the address. A login as 'x from 8.8.4.4 via ssh'
        must not credit the address it names."""
        victim = '8.8.4.4'
        bad = routeros(f'system,error,critical login failure for user x from {victim} via ssh '
                       f'from {ATTACKER} via ssh')
        self.post([bad] * 5, dev='rt1')
        self.assertEqual({x['ip'] for x in self.queue()}, {ATTACKER})

    def test_a_host_with_an_agent_is_not_counted_twice(self):
        """A Linux host that has an agent and also forwards its syslog has its failed SSH
        logins counted from the journal. Counting the forwarded copies as well would halve
        the threshold. Without an agent the syslog is all there is, so it counts."""
        api = self.api
        devs = api.load(api.DEVICES_FILE)
        devs['h1'] = {'name': 'web01', 'os': 'Linux', 'ip': '192.0.2.3'}                  # an agent reports for it
        devs['h2'] = {'name': 'nas01', 'os': 'Linux', 'agentless': True, 'ip': '192.0.2.4'}
        api.save(api.DEVICES_FILE, devs)
        bad = f'<38>Oct 17 09:42:22 host sshd[123]: Failed password for root from {ATTACKER} port 51234 ssh2'
        api.appliance_sensor_ingest('h1', api.device_get('h1'), [bad] * 6)
        self.assertEqual(self.queue(), [], 'a host with an agent counts its own logins')
        api.appliance_sensor_ingest('h2', api.device_get('h2'), [bad] * 6)
        self.assertEqual([(x['device_id'], x['unit']) for x in self.queue()], [('h2', 'sshd.service')],
                         'control: a device without an agent is counted from its syslog')

    def test_a_login_from_a_private_address_is_not_queued(self):
        bad = routeros('system,error,critical login failure for user admin from 192.168.88.20 via winbox')
        self.post([bad] * 6, dev='rt1')
        self.assertEqual(self.queue(), [])


# ── the intake must not fail ──────────────────────────────────────────────────

class TestTheIntakeNeverFails(_Fw):
    def test_a_sensor_that_raises_does_not_fail_the_post(self):
        logged = []
        self.api.log_json = lambda *a, **k: logged.append((a, k))
        with mock.patch.object(self.api, 'appliance_sensor_ingest', side_effect=RuntimeError('boom')):
            st, d = self.post(self.scan(ports=3))
        self.assertEqual((st, d.get('lines_received')), (200, 3))
        self.assertEqual(len(self.buffer()), 3, 'the lines were stored before the sensor ran')
        self.assertTrue(any(a[1] == 'appliance sensor failed' for a, _ in logged), logged)

    def test_hostile_lines_are_stored_and_answered(self):
        junk = ['\x00' * 50, 'x' * 5000, '<999>' + 'y' * 100, '1 ' * 3000, '{"event_type":"alert"',
                wire('8,,,t,vtnet0,match,block,in,4,' + 'x,' * 40), wire(',' * 3000),
                wire('[1:2:3] x [Classification: ] {TCP} a -> b', app='suricata'),
                routeros('firewall,info ' + '->' * 500)]
        st, d = self.post(junk)
        self.assertEqual(st, 200, d)
        self.assertEqual(d.get('lines_received'), len(junk))

    def test_a_device_that_is_not_a_dict_does_not_matter(self):
        self.api.appliance_sensor_ingest('fw1', None, self.scan(ports=10))
        self.assertEqual([x['ip'] for x in self.queue()], [ATTACKER])


# ── locks ─────────────────────────────────────────────────────────────────────

class TestLocks(_Fw):
    """The SQL backends share one connection per directory, so a write that locks a second
    document inside the first fails there while the JSON backend lets it pass. These hold
    the shape, not the backend."""

    def ingest(self, lines, now=None):
        api = self.api
        held = _Held(api)
        with mock.patch.object(api, '_LockedUpdate', held):
            api.appliance_sensor_ingest('fw1', api.device_get('fw1'), lines, now=now)
        return held

    def test_a_scan_takes_the_scan_document_then_the_intake_and_never_both_nor_the_table(self):
        held = self.ingest(self.scan(ports=10))
        api = self.api
        self.assertEqual(held.deepest, 1, 'two documents were locked at once')
        self.assertEqual((held.named(api.IPINTEL_SCAN_FILE), held.named(api.IPINTEL_INTAKE_FILE)), (1, 1))
        self.assertEqual(held.named(api.IPINTEL_FILE), 0, 'the table of addresses must not be locked by a heartbeat-rate write')

    def test_lines_of_other_programs_take_no_lock_at_all(self):
        held = self.ingest([wire('Accepted publickey for root', app='sshd'), 'plain text'])
        self.assertEqual(held.taken, {})

    def test_a_batch_that_settles_nothing_takes_no_lock_once_the_status_is_written(self):
        now = int(time.time())
        self.ingest([wire(pf(ATTACKER, action='pass'))], now=now)
        held = self.ingest([wire(pf(ATTACKER, action='pass'))], now=now + 5)
        self.assertEqual(held.taken, {}, 'a pass line, five seconds after the status was written, cost a write')

    def test_the_status_is_written_again_after_a_minute(self):
        now = int(time.time())
        self.ingest([wire(pf(ATTACKER, action='pass'))], now=now)
        held = self.ingest([wire(pf(ATTACKER, action='pass'))], now=now + 61)
        self.assertEqual(held.named(self.api.IPINTEL_INTAKE_FILE), 1)

    def test_the_days_counts_add_up_across_requests(self):
        now = int(time.time())
        self.ingest([wire(pf(ATTACKER, action='pass'))] * 3, now=now)
        self.ingest(self.scan(ports=10), now=now + 70)
        src = self.row()['sources'][0]
        self.assertEqual((src['kind'], src['lines'], src['parsed']), ('fw', 13, 13))
        self.assertEqual(src['events'], 1)


# ── the Log sources card ──────────────────────────────────────────────────────

class TestTheLogSourcesCard(_Fw):
    def test_the_card_lists_the_firewall_and_what_was_read_from_its_syslog(self):
        self.post(self.scan(ports=10) + self.scan(ports=3, base=9000))
        sensors = self.view()['sensors']
        self.assertEqual([r['name'] for r in sensors], ['opnsense01'])
        self.assertEqual(sensors[0]['sources'][0]['path'], 'syslog')

    def test_a_caller_who_cannot_see_the_firewall_does_not_see_its_row(self):
        self.post(self.scan(ports=10))
        self.api._scope_filter_devices = lambda devs, scope=None: {}
        self.assertEqual(self.view()['sensors'], [])

    def test_a_source_that_arrives_and_cannot_be_read_says_so(self):
        self.post([wire('garbage,not,a,pf,line')])
        src = self.row()['sources'][0]
        self.assertEqual((src['kind'], src['lines'], src['parsed'], src['state']), ('fw', 1, 0, 'unparsed'))

    def test_two_firewalls_are_two_rows(self):
        self.post(self.scan(ports=3))
        self.post([routeros(ros('rp-trap', ATTACKER, 2222))], dev='rt1')
        self.assertEqual(sorted(r['name'] for r in self.view()['sensors']), ['mikrotik01', 'opnsense01'])


# ── how it is wired ───────────────────────────────────────────────────────────

class TestWiring(unittest.TestCase):
    API = (HANDLERS / 'api.py').read_text(encoding='utf-8')

    def test_the_intake_calls_the_sensor_after_the_rules_and_never_lets_it_fail_the_post(self):
        body = srcpin.py_function(self.API, 'handle_syslog_in')
        rules, sensor, bump = (body.index(x) for x in (
            '_eval_syslog_rules(dev_id, dev, new_msgs)',
            'appliance_sensor_ingest(dev_id, dev, new_msgs, now)',
            'Bump token stats'))
        self.assertLess(rules, sensor)
        self.assertLess(sensor, bump)
        around = body[body.rindex('try:', 0, sensor):sensor + 200]
        self.assertIn('except Exception', around, 'the sensor call is not guarded')

    def test_the_names_are_bound_from_the_module_and_it_is_not_a_second_copy(self):
        api = _fresh_api()
        for name in ('appliance_sensor_ingest', 'crowdsec_alert_lines'):
            self.assertEqual(getattr(api, name).__module__, 'appliance_sensor_handlers', name)
        self.assertIsNotNone(api.appliance_sensor_handlers_mod.A, 'bind() was never called')

    def test_the_brute_force_counter_knows_the_syslog_unit(self):
        api = _fresh_api()
        self.assertIn('syslog', api._SYSLOG_UNITS)
        self.assertTrue(api._BRUTE_PATTERNS['syslog'])
        self.assertTrue(any(p.search('login failure for user a from 1.2.3.4 via ssh') for p in api._BRUTE_PATTERNS['ssh']))
        self.assertFalse(any(p.search('login failure for user a from 1.2.3.4 via ssh') for p in api._BRUTE_PATTERNS['syslog']),
                         'a RouterOS ssh failure would be counted twice')

    def test_the_scan_document_has_a_home_that_is_not_the_table(self):
        api = _fresh_api()
        self.assertEqual(api.IPINTEL_SCAN_FILE.name, 'ip_intel_scan.json')
        self.assertNotEqual(api.IPINTEL_SCAN_FILE, api.IPINTEL_FILE)
        self.assertNotEqual(api.IPINTEL_SCAN_FILE, api.IPINTEL_INTAKE_FILE)


if __name__ == '__main__':
    unittest.main()

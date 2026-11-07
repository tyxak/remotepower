"""The agent reads the alerts of a Suricata that runs on its own host.

Suricata writes eve.json (an EVE record per event, alerts among flows, DNS and stats) and fast.log (one line per alert). The
Linux agent's threat sensor reads either, counts an address for each alert that names an attack, and sends the server the same
summary it sends for a web log: counts and tokens from the fixed list, never a line, a signature or a path.

What matters here: that the two copies of the signature classification (this agent and the server's reader of a firewall's
Suricata) say the same thing; that an alert is read from a record too long to parse or cut short; that an alert written to both
files counts once; that a line chosen by an attacker cannot hold the thread; and that the server takes the family from an agent
without taking what only the appliance reader may say.
"""
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import appliance_evidence as ae  # noqa: E402
import threat_evidence as te  # noqa: E402
from test_v720_threat_sensor_agent import A1, A2, A6, NOW, load_agent  # noqa: E402
from test_v749_agent_threat_regex import run_child  # noqa: E402


def iso(t):
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(t)) + '.123456+0000'


def eve_alert(ip, sig='ET SCAN Potential SSH Scan', cat='Attempted Information Leak', t=NOW - 30, proto='TCP', dport=22,
              tail='"app_proto":"failed","payload":"AAAA"}'):
    return ('{"timestamp":"%s","flow_id":1234567890,"in_iface":"eth0","event_type":"alert","src_ip":"%s","src_port":40222,'
            '"dest_ip":"192.0.2.1","dest_port":%d,"proto":"%s","pkt_src":"wire/pcap","alert":{"action":"allowed","gid":1,'
            '"signature_id":2001219,"rev":20,"signature":"%s","category":"%s","severity":2,"metadata":{"created_at":["2010_07_30"]}},%s'
            % (iso(t), ip, dport, proto, sig, cat, tail))


def fast_alert(ip, sig='ET SCAN Potential SSH Scan', cat='Attempted Information Leak', t=NOW - 30, proto='TCP', port=40222,
               action='', dst='192.0.2.1:22', noport=False):
    stamp = time.strftime('%m/%d/%Y-%H:%M:%S', time.localtime(t)) + '.123456'
    # Suricata prints an IPv6 address and its port with no brackets, and no port at all for a protocol that has none
    src = ip if noport else '%s:%d' % (ip, port)
    return '%s  %s[**] [1:2001219:20] %s [**] [Classification: %s] [Priority: 2] {%s} %s -> %s' % (
        stamp, (action + ' ') if action else '', sig, cat, proto, src, dst)


class _Agent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.agent = load_agent('agent_suricata')

    def agg(self):
        return self.agent._TsAgg(NOW)

    def events(self, agg):
        ev, dropped = agg.events()
        return {e['ip']: e for e in ev}, dropped


# ── the same words as the server's reader ──────────────────────────────────────

class TestTheTwoClassificationsAreOne(_Agent):
    def test_the_patterns_are_the_same_text(self):
        self.assertEqual(self.agent._TS_IDS_SKIP.pattern, ae._IDS_SKIP.pattern)
        self.assertEqual([(c, r.pattern) for c, r in self.agent._TS_IDS_RULES], [(c, r.pattern) for c, r in ae._IDS_RULES])

    SIGNATURES = [
        ('ET EXPLOIT Apache Log4j RCE Attempt (CVE-2021-44228)', 'Attempted Administrator Privilege Gain'),
        ('ET WEB_SERVER SQL Injection Attempt UNION SELECT', 'Web Application Attack'),
        ('ET WEB_SERVER Possible XSS Attempt', 'Web Application Attack'),
        ('ET WEB_SERVER Directory Traversal /etc/passwd', 'Web Application Attack'),
        ('ET DOS Possible SSDP Amplification Flood', 'Attempted Denial of Service'),
        ('ET SCAN Nmap Scripting Engine User-Agent Detected', 'Web Application Attack'),
        ('ET SCAN Nikto Web App Scan', 'Web Application Attack'),
        ('ET SCAN Potential SSH Scan', 'Attempted Information Leak'),
        ('ET SCAN Suspicious inbound to MSSQL port 1433', 'Potentially Bad Traffic'),
        ('ET INFO Observed DNS Query to .biz TLD', 'Misc activity'),
        ('ET POLICY Outgoing Basic Auth Base64 HTTP Password detected unencrypted', 'Potential Corporate Privacy Violation'),
        ('ET DROP Dshield Block Listed Source group 1', 'Misc Attack'),
        ('ET CNC Feodo Tracker Reported CnC Server group 4', 'A Network Trojan was detected'),
        ('ET MALWARE Possible Outbound Beacon', 'A Network Trojan was detected'),
        ('SURICATA STREAM ESTABLISHED SYN resend with different seq', 'Generic Protocol Command Decode'),
        ('GPL ATTACK_RESPONSE id check returned root', 'Potentially Bad Traffic'),
        ('ET FTP FTP login brute force attempt', 'Attempted User Privilege Gain'),
        ('ET SMTP SMTP auth brute force', 'Attempted User Privilege Gain'),
        ('ET RDP Brute force login attempt', 'Attempted User Privilege Gain'),
        ('some local rule', 'Attempted Information Leak'),
        ('some local rule', ''),
        ('', ''),
    ]

    def test_every_signature_is_read_the_same_way(self):
        for sig, cat in self.SIGNATURES:
            self.assertEqual(self.agent._ts_ids_class(sig, cat), ae.classify_ids(sig, cat), (sig, cat))

    def test_the_corpus_reaches_every_class_the_rules_can_say_and_the_skip(self):
        got = {ae.classify_ids(s, c) for s, c in self.SIGNATURES}
        self.assertEqual({c for c, _rx in ae._IDS_RULES} - got, set(), 'a rule with no signature in the corpus is not held')
        self.assertIn(None, got)

    def test_every_class_the_agent_can_say_is_one_the_server_knows(self):
        for cls, _rx in self.agent._TS_IDS_RULES:
            self.assertIn(cls, te.IDS_CLASSES)
            self.assertTrue(te.token_valid('ids:' + cls), cls)


# ── eve.json ───────────────────────────────────────────────────────────────────

class TestEve(_Agent):
    def scan(self, lines):
        agg = self.agg()
        n, parsed = self.agent._ts_scan_eve(lines, agg, '/var/log/suricata/eve.json', NOW)
        return agg, n, parsed

    def test_an_alert_that_names_an_attack_counts_for_its_source(self):
        agg, n, parsed = self.scan([eve_alert(A1)] * 3)
        ev, dropped = self.events(agg)
        self.assertEqual((n, parsed), (3, 3))
        self.assertEqual(ev[A1]['src'], {'ids': 3})
        self.assertEqual(ev[A1]['tok'], {'ids': {'ids:port_scan': 3}})

    def test_the_class_follows_the_signature(self):
        agg, *_ = self.scan([eve_alert(A1, 'ET EXPLOIT Apache Log4j RCE Attempt (CVE-2021-44228)',
                                       'Attempted Administrator Privilege Gain')] * 3)
        ev, _ = self.events(agg)
        self.assertEqual(ev[A1]['tok'], {'ids': {'ids:rce': 3}})
        self.assertEqual(ev[A1]['cve'], ['CVE-2021-44228'])

    def test_an_alert_that_names_no_attack_is_read_and_dropped(self):
        agg, n, parsed = self.scan([eve_alert(A1, 'ET INFO Observed DNS Query to .biz TLD', 'Misc activity')] * 20
                                   + [eve_alert(A2, 'ET DROP Dshield Block Listed Source', 'Misc Attack')] * 20)
        self.assertEqual((n, parsed), (40, 40))
        self.assertEqual(self.events(agg)[0], {})

    def test_the_other_event_types_are_lines_it_understands_and_does_not_use(self):
        flows = ['{"timestamp":"%s","event_type":"flow","src_ip":"%s","dest_ip":"192.0.2.1","flow":{"pkts_toserver":3}}' % (iso(NOW), A1),
                 '{"timestamp":"%s","event_type":"dns","src_ip":"%s","dns":{"rrname":"example.org"}}' % (iso(NOW), A1),
                 '{"timestamp":"%s","event_type":"stats","stats":{"uptime":1}}' % iso(NOW)]
        agg, n, parsed = self.scan(flows)
        self.assertEqual((n, parsed), (3, 3))
        self.assertEqual(self.events(agg)[0], {})

    def test_a_flow_that_carries_an_alert_object_is_not_an_alert(self):
        line = ('{"timestamp":"%s","event_type":"flow","src_ip":"%s","alert":{"signature":"ET SCAN Potential SSH Scan",'
                '"category":"x"},"flow":{"pkts_toserver":3}}' % (iso(NOW), A1))
        self.assertEqual(self.events(self.scan([line] * 5)[0])[0], {})

    def test_what_is_not_a_record_is_a_line_that_was_not_understood(self):
        agg, n, parsed = self.scan(['', 'plain text', '{"no":"type"}', '[1,2]', eve_alert(A1)])
        self.assertEqual((n, parsed), (4, 1))

    def test_a_private_or_reserved_source_is_somebodys_own_network(self):
        agg, *_ = self.scan([eve_alert(ip) for ip in ('10.1.2.3', '192.168.0.9', '127.0.0.1', '169.254.1.1', '224.0.0.5')] * 5)
        self.assertEqual(self.events(agg)[0], {})

    def test_an_ipv6_source(self):
        agg, *_ = self.scan([eve_alert(A6)] * 3)
        self.assertEqual(self.events(agg)[0][A6]['src'], {'ids': 3})

    def test_a_record_longer_than_the_line_limit_is_read_from_its_head(self):
        long_tail = '"app_proto":"failed","payload":"' + 'A' * 20000 + '"}'
        line = eve_alert(A1, tail=long_tail)
        self.assertGreater(len(line), self.agent.THREAT_MAX_LINE)
        agg, n, parsed = self.scan([line] * 3)
        self.assertEqual(self.events(agg)[0][A1]['src'], {'ids': 3})

    def test_a_record_cut_after_its_signature_still_counts_and_one_cut_before_it_does_not(self):
        line = eve_alert(A1)
        after = line[:line.index('"app_proto"') + 8]
        before = line[:line.index('Potential') + 4]
        self.assertEqual(self.events(self.scan([after] * 3)[0])[0][A1]['src'], {'ids': 3})
        self.assertEqual(self.events(self.scan([before] * 3)[0])[0], {})

    def test_the_time_of_the_alert_is_the_records_not_the_passes(self):
        agg, *_ = self.scan([eve_alert(A1, t=NOW - 3000)] * 3)
        e = self.events(agg)[0][A1]
        self.assertEqual((e['first'], e['last']), (NOW - 3000, NOW - 3000))

    def test_an_alert_older_than_the_look_back_is_not_evidence(self):
        agg, *_ = self.scan([eve_alert(A1, t=NOW - self.agent.THREAT_LOOKBACK_S - 60)] * 5)
        self.assertEqual(self.events(agg)[0], {})

    def test_an_alert_stamped_in_the_future_is_taken_at_the_edge_of_now(self):
        agg, *_ = self.scan([eve_alert(A1, t=NOW + 99999)] * 3)
        self.assertLessEqual(self.events(agg)[0][A1]['last'], NOW + 300)

    def test_one_or_two_alerts_wait_for_a_third_like_any_plain_address(self):
        agg, *_ = self.scan([eve_alert(A1)] * 2)
        ev, dropped = self.events(agg)
        self.assertEqual((ev, dropped), ({}, 1))
        self.assertEqual(agg.carry_out[A1]['src'], {'ids': 2}, 'what it saw is carried to the next pass')


class TestTheFieldReader(_Agent):
    def test_a_key_is_told_from_the_same_word_as_a_value(self):
        msg = '{"event_type":"alert","src_ip":"%s","alert":{"signature":"ET SCAN x","category":"y"},"app_proto":"' % A1
        val, at = self.agent._ts_json_field(msg, 'alert')
        self.assertEqual(val, {'signature': 'ET SCAN x', 'category': 'y'})
        self.assertEqual(msg[at:at + 8], '"alert":')
        self.assertEqual(self.agent._ts_json_field(msg, 'src_ip')[0], A1)
        self.assertEqual(self.agent._ts_json_field(msg, 'dest_port'), (None, -1))
        self.assertEqual(self.agent._ts_json_field('{"a": "b", "k" :   7, ', 'k')[0], 7, 'spaces around the colon')

    def test_it_reads_a_value_after_a_given_position_only(self):
        msg = '{"signature":"first","alert":{"signature":"second"}'
        self.assertEqual(self.agent._ts_json_field(msg, 'signature')[0], 'first')
        _, at = self.agent._ts_json_field(msg, 'alert')
        self.assertEqual(self.agent._ts_json_field(msg, 'signature', at)[0], 'second')


# ── fast.log ───────────────────────────────────────────────────────────────────

class TestFastLog(_Agent):
    def scan(self, lines):
        agg = self.agg()
        n, parsed = self.agent._ts_scan_fastlog(lines, agg, '/var/log/suricata/fast.log', NOW)
        return agg, n, parsed

    def test_an_alert_line(self):
        agg, n, parsed = self.scan([fast_alert(A1)] * 3)
        e = self.events(agg)[0][A1]
        self.assertEqual((n, parsed), (3, 3))
        self.assertEqual((e['src'], e['tok']), ({'ids': 3}, {'ids': {'ids:port_scan': 3}}))

    def test_the_stamp_is_the_hosts_local_time(self):
        agg, *_ = self.scan([fast_alert(A1, t=NOW - 3000)] * 3)
        e = self.events(agg)[0][A1]
        self.assertEqual((e['first'], e['last']), (NOW - 3000, NOW - 3000))

    def test_a_dropping_rule_has_its_action_in_front(self):
        agg, *_ = self.scan([fast_alert(A1, action='[Drop]')] * 3)
        self.assertEqual(self.events(agg)[0][A1]['src'], {'ids': 3})

    def test_a_null_classification_and_a_signature_that_names_the_attack(self):
        agg, *_ = self.scan([fast_alert(A1, 'ET WEB_SERVER SQL Injection Attempt', '(null)')] * 3)
        self.assertEqual(self.events(agg)[0][A1]['tok'], {'ids': {'ids:sqli': 3}})

    def test_an_ipv6_source_is_not_split_at_its_last_colon(self):
        line = fast_alert(A6, port=40222)
        self.assertIn(A6 + ':40222', line)
        agg, *_ = self.scan([line] * 3)
        self.assertEqual(self.events(agg)[0][A6]['src'], {'ids': 3})

    def test_a_source_without_a_port_is_read_whole(self):
        # a protocol with no ports (ICMP) prints the address alone, and an IPv6 address ends in what looks like a port
        for ip in (A1, A6):
            agg, n, parsed = self.scan([fast_alert(ip, proto='ICMP', noport=True, dst='192.0.2.1')] * 3)
            self.assertEqual(self.events(agg)[0][ip]['src'], {'ids': 3}, ip)

    def test_a_bracketed_source_too(self):
        line = fast_alert(A6).replace(A6 + ':40222', '[' + A6 + ']:40222')
        self.assertEqual(self.events(self.scan([line] * 3)[0])[0][A6]['src'], {'ids': 3})

    def test_an_alert_that_names_no_attack_is_read_and_dropped(self):
        agg, n, parsed = self.scan([fast_alert(A1, 'ET INFO Observed DNS Query to .biz TLD', 'Misc activity')] * 9)
        self.assertEqual((n, parsed), (9, 9))
        self.assertEqual(self.events(agg)[0], {})

    def test_a_line_that_is_not_an_alert_line_is_not_understood(self):
        agg, n, parsed = self.scan(['', 'plain text', '11/07/2026-12:00:00.1  [**] no tag [**] x', fast_alert(A1)])
        self.assertEqual((n, parsed), (3, 1))

    def test_a_private_source_is_not_counted(self):
        agg, *_ = self.scan([fast_alert('10.0.0.7')] * 9)
        self.assertEqual(self.events(agg)[0], {})


# ── both files ─────────────────────────────────────────────────────────────────

class TestBothFiles(_Agent):
    def test_an_alert_in_eve_json_and_in_fast_log_counts_once(self):
        agg = self.agg()
        self.agent._ts_scan_eve([eve_alert(A1)] * 4, agg, '/var/log/suricata/eve.json', NOW)
        self.agent._ts_scan_fastlog([fast_alert(A1)] * 4, agg, '/var/log/suricata/fast.log', NOW)
        e = self.events(agg)[0][A1]
        self.assertEqual((e['src'], e['tok']), ({'ids': 4}, {'ids': {'ids:port_scan': 4}}))

    def test_one_file_that_has_more_decides_the_number(self):
        agg = self.agg()
        self.agent._ts_scan_eve([eve_alert(A1)] * 3, agg, '/var/log/suricata/eve.json', NOW)
        self.agent._ts_scan_fastlog([fast_alert(A1)] * 5, agg, '/var/log/suricata/fast.log', NOW)
        self.assertEqual(self.events(agg)[0][A1]['src'], {'ids': 5})

    def test_it_is_one_family_beside_the_others(self):
        agg = self.agg()
        self.agent._ts_scan_eve([eve_alert(A1)] * 3, agg, '/var/log/suricata/eve.json', NOW)
        agg.hit('web', '/var/log/nginx/access.log', A1, NOW, ['req:probe'], 4)
        self.assertEqual(self.events(agg)[0][A1]['src'], {'ids': 3, 'web': 4})


# ── finding the files ──────────────────────────────────────────────────────────

class TestDiscovery(_Agent):
    def disc(self, exists=(), conf='', paths=()):
        a = self.agent
        saved = (a._ts_exists, a._safe_read, a._which, a._ts_operator_path)
        a._ts_exists = lambda p: p in exists
        a._safe_read = lambda p, n=0: conf if p == '/etc/suricata/suricata.yaml' else ''
        a._which = lambda name: None
        a._ts_operator_path = lambda p: p if p in paths else None
        try:
            return a._ts_discover({'paths': list(paths)}, NOW)
        finally:
            a._ts_exists, a._safe_read, a._which, a._ts_operator_path = saved

    def test_the_two_files_of_the_default_directory(self):
        d = self.disc(exists={'/var/log/suricata/eve.json', '/var/log/suricata/fast.log'})
        self.assertEqual([e['path'] for e in d['ids']], ['/var/log/suricata/eve.json', '/var/log/suricata/fast.log'])

    def test_only_the_files_that_are_there(self):
        d = self.disc(exists={'/var/log/suricata/fast.log'})
        self.assertEqual([e['path'] for e in d['ids']], ['/var/log/suricata/fast.log'])
        self.assertEqual(self.disc()['ids'], [])

    def test_a_host_without_suricata_has_no_source_for_it(self):
        d = self.disc(exists={'/var/log/ufw.log'})
        self.assertEqual(d['ids'], [])
        self.assertEqual([e['path'] for e in d['fw']], ['/var/log/ufw.log'])

    def test_the_directory_comes_from_suricatas_own_configuration(self):
        conf = '%YAML 1.1\n---\n# a comment: default-log-dir: /nowhere\ndefault-log-dir: /srv/suricata/\n'
        d = self.disc(exists={'/srv/suricata/eve.json'}, conf=conf)
        self.assertEqual([e['path'] for e in d['ids']], ['/srv/suricata/eve.json'])

    def test_a_quoted_directory(self):
        d = self.disc(exists={'/data/ids/fast.log'}, conf='default-log-dir: "/data/ids"\n')
        self.assertEqual([e['path'] for e in d['ids']], ['/data/ids/fast.log'])

    def test_an_extra_file_the_operator_named_is_read_by_what_it_is_called(self):
        d = self.disc(paths={'/var/log/suricata-extra/eve-2026.json', '/var/log/ids/fast-eth1.log'})
        self.assertEqual(sorted(e['path'] for e in d['ids']),
                         ['/var/log/ids/fast-eth1.log', '/var/log/suricata-extra/eve-2026.json'])

    def test_kinds_of_files_by_name(self):
        k = self.agent._ts_kind_of
        for name in ('/var/log/suricata/eve.json', '/x/eve-2026-11.json', '/x/fast.log', '/x/fast-eth0.log'):
            self.assertEqual(k(name), 'ids', name)
        for name in ('/var/log/suricata/suricata.log', '/var/log/suricata/stats.log', '/var/log/nginx/access.log',
                     '/var/log/ufw.log', '/var/log/fail2ban.log', '/var/log/modsec_audit.log', '/var/log/nginx/error.log'):
            self.assertNotEqual(k(name), 'ids', name)


# ── a whole pass over real files ───────────────────────────────────────────────

class TestAPass(_Agent):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='rp-v800-suricata-')
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.eve = os.path.join(self.dir, 'eve.json')
        self.fast = os.path.join(self.dir, 'fast.log')

    def write(self, path, lines):
        with open(path, 'a') as f:
            f.write('\n'.join(lines) + '\n')

    def run_pass(self, state=None, files=None):
        disc = {'at': NOW, 'psig': [], 'web': [], 'err': [], 'waf': [], 'f2b': [], 'fw': [], 'cs': False, 'proxied': False,
                'ids': [{'path': p, 'configured': False} for p in (files or (self.eve, self.fast))]}
        st = dict(state or {})
        st['disc'] = disc
        return self.agent.collect_threat_events({}, st, NOW)

    def test_a_pass_sends_the_address_and_says_how_each_file_went(self):
        self.write(self.eve, [eve_alert(A1)] * 4 + ['{"timestamp":"%s","event_type":"flow","src_ip":"%s"}' % (iso(NOW), A2)])
        self.write(self.fast, [fast_alert(A1)] * 4)
        events, sources, dropped, new = self.run_pass()
        self.assertEqual([e['ip'] for e in events], [A1])
        self.assertEqual(events[0]['src'], {'ids': 4})
        self.assertEqual(events[0]['tok'], {'ids': {'ids:port_scan': 4}})
        rows = {s['path']: s for s in sources}
        self.assertEqual((rows[self.eve]['kind'], rows[self.eve]['state'], rows[self.eve]['lines'], rows[self.eve]['parsed']),
                         ('ids', 'ok', 5, 5))
        self.assertEqual((rows[self.fast]['kind'], rows[self.fast]['state'], rows[self.fast]['lines'], rows[self.fast]['parsed']),
                         ('ids', 'ok', 4, 4))
        self.assertEqual(rows[self.eve]['events'], 4, 'the hostile alerts of this file, as the web logs count requests')

    def test_nothing_new_is_idle_and_what_was_read_is_not_read_again(self):
        self.write(self.eve, [eve_alert(A1)] * 4)
        _ev, _src, _d, new = self.run_pass(files=(self.eve,))
        events, sources, _d, _new = self.run_pass(state=new, files=(self.eve,))
        self.assertEqual(events, [])
        self.assertEqual(sources[0]['state'], 'idle')

    def test_alerts_that_come_slowly_add_up_across_passes(self):
        self.write(self.eve, [eve_alert(A1)] * 2)
        events, _s, _d, new = self.run_pass(files=(self.eve,))
        self.assertEqual(events, [])
        self.write(self.eve, [eve_alert(A1)])
        events, _s, _d, _new = self.run_pass(state=new, files=(self.eve,))
        self.assertEqual([(e['ip'], e['src']) for e in events], [(A1, {'ids': 3})])

    def test_a_file_the_agent_may_not_read_says_so(self):
        self.write(self.eve, [eve_alert(A1)] * 4)
        os.chmod(self.eve, 0)
        try:
            if os.access(self.eve, os.R_OK):
                self.skipTest('running as a user that reads anything')
            _e, sources, _d, _n = self.run_pass(files=(self.eve,))
        finally:
            os.chmod(self.eve, 0o600)
        self.assertEqual((sources[0]['kind'], sources[0]['state']), ('ids', 'denied'))

    def test_a_missing_file_says_so(self):
        _e, sources, _d, _n = self.run_pass(files=(os.path.join(self.dir, 'gone.json'),))
        self.assertEqual((sources[0]['kind'], sources[0]['state']), ('ids', 'missing'))

    def test_a_log_that_is_all_noise_is_not_understood(self):
        self.write(self.fast, ['garbage line %d' % i for i in range(30)])
        _e, sources, _d, _n = self.run_pass(files=(self.fast,))
        self.assertEqual((sources[0]['state'], sources[0]['lines'], sources[0]['parsed']), ('unparsed', 30, 0))


# ── lines an attacker may influence ────────────────────────────────────────────

class TestHostileLinesAreCheap(unittest.TestCase):
    def test_the_readers_finish_at_once_on_hostile_lines(self):
        out, timed_out = run_child('''
            now = 1790000000
            hostile_eve = [
                '{"event_type":"alert","src_ip":"185.220.101.7","alert":{' + ' ' * 7000 + '"signature":"x',
                '{"alert"' * 900,
                '{"event_type":"alert","src_ip":"185.220.101.7","alert":' + '"signature":' * 600,
                '{"event_type":"alert","src_ip":"185.220.101.7","alert":{"signature":"' + 'a\\\\\\\\' * 3000,
                '{"event_type":"alert","src_ip":"185.220.101.7","alert":{"signature":"' + 'ftp ' * 2000 + '","category":"x"}}',
                '{"event_type":"alert","src_ip":"185.220.101.7","alert":{"signature":"' + 'et scan ' * 1000 + '"}}',
                '{' + '"event_type"' * 500,
            ]
            hostile_fast = [
                '11/07/2026-12:00:00.1  ' + '[**] ' * 3000,
                '11/07/2026-12:00:00.1  [**] [1:2:3] ' + 'ET SCAN ' * 900 + '[**] [Classification: ' + 'x' * 5000,
                '11/07/2026-12:00:00.1  [**] [1:2:3] x [**] ' + '{TCP} ' * 1500,
                '11/07/2026-12:00:00.1  [**] [1:2:3] x [**] {TCP} ' + ' ' * 6000 + '1.2.3.4 -> 5.6.7.8',
                '11/07/2026-12:00:00.1  [**] [1:2:3] x [**] {TCP} ' + 'a:' * 3000,
                '11/07/2026-12:00:00.1  [**] [1:2:3] ftp ' + 'ftp ' * 1500 + ' [**] [Classification: x] {TCP} 185.220.101.7:1 -> 1.1.1.1:2',
            ]
            t = time.perf_counter()
            agg = agent._TsAgg(now)
            a = agent._ts_scan_eve(hostile_eve, agg, "/var/log/suricata/eve.json", now)
            b = agent._ts_scan_fastlog(hostile_fast, agg, "/var/log/suricata/fast.log", now)
            print(json.dumps({"seconds": time.perf_counter() - t, "eve": a, "fast": b}))
        ''', timeout=60)
        self.assertFalse(timed_out, 'a line in Suricata\'s log froze the reader')
        res = json.loads(out)
        self.assertLess(res['seconds'], 2.0, res)


# ── what the server takes from an agent ────────────────────────────────────────

class TestTheServerTakesTheFamily(unittest.TestCase):
    def test_an_agents_ids_summary_is_accepted_as_it_is_for_its_own_waf(self):
        raw = {'ip': A1, 'first': NOW - 600, 'last': NOW, 'src': {'ids': 12}, 'tok': {'ids': {'ids:rce': 12, 'ids:nonsense': 4}},
               'cve': ['CVE-2021-44228']}
        ev = te.normalize_event(raw, now=NOW)
        self.assertEqual(ev['src'], {'ids': 12})
        self.assertEqual(ev['tok'], {'ids': {'ids:rce': 12}})
        self.assertEqual(ev['cve'], ['CVE-2021-44228'])
        self.assertEqual(te.qualifies(ev, 10)[0], True)
        self.assertEqual(te.qualifies(ev, 13)[0], False)

    def test_what_only_the_appliance_reader_may_say_is_still_dropped(self):
        raw = {'ip': A1, 'first': NOW - 600, 'last': NOW, 'src': {'ids': 2, 'dp': 9}, 'tok': {'ids': {'ids:rce': 2}, 'dp': {'dp:hit': 9}},
               'trp': 3, 'rep': 40}
        ev = te.normalize_event(raw, now=NOW)
        self.assertEqual((ev['src'], ev['trp'], ev['rep']), ({'ids': 2}, 0, 0))
        self.assertFalse(te.qualifies(ev, 10)[0], 'two alerts are not a report, whatever the sender says a list decided')

    def test_the_appliance_reader_keeps_what_it_always_could(self):
        raw = {'ip': A1, 'first': NOW - 600, 'last': NOW, 'src': {'ids': 2, 'dp': 2}, 'tok': {'dp': {'dp:hit': 2}}, 'trp': 1, 'rep': 40}
        ev = te.normalize_event(raw, now=NOW, families=te.APPLIANCE_SOURCES)
        self.assertEqual((ev['trp'], ev['rep']), (1, 40))


if __name__ == '__main__':
    unittest.main()

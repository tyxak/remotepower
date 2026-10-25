"""Threat evidence from the syslog of firewalls and routers (7.4.0), the pure half.

`appliance_evidence` reads stored syslog lines and returns what an agent's log
sensor would have sent. These tests hold the readers (pf `filterlog`, RouterOS,
Suricata, CrowdSec), the rules that decide what counts as a probe, and the
counting that decides when a probe becomes a scan. The handler that stores the
result, and the whole path through the syslog intake to a report, are in
test_v740_appliance_sensor.py.

The pf lines are built in the layout of a real OPNsense buffer (RFC 5424 header,
the `filterlog` message fields in the order pf writes them), with documentation
and well-known addresses in place of the captured ones. The RouterOS, Suricata
and CrowdSec lines follow those products' documented formats; no device of those
kinds has been read yet.
"""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v740-appliance-'))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import appliance_evidence as ae  # noqa: E402
import threat_evidence as te  # noqa: E402

SCANNER = '185.220.101.7'
SECOND = '185.220.101.9'
SCANNER6 = '2a0b:f4c0:16c:1::77'
FIREWALL = '192.0.2.1'


# ── lines, built the way the products write them ──────────────────────────────

def pf(src, dport=22, flags='S', action='block', direction='in', proto='tcp', iface='vtnet0',
       sport=51234, dst=FIREWALL):
    """A pf `filterlog` message for an IPv4 packet."""
    head = f'8,,,02f4bab031b57d1e30553ce08e0ec131,{iface},match,{action},{direction},4,0x0,,64,16955,0,DF,'
    if proto == 'tcp':
        return head + f'6,tcp,52,{src},{dst},{sport},{dport},0,{flags},2909759651,,64240,,mss;nop;nop;sackOK;nop;wscale'
    if proto == 'udp':
        return head + f'17,udp,80,{src},{dst},{sport},{dport},60'
    return head + f'1,icmp,84,{src},{dst},request,1,2'


def pf6(src, dport=22, flags='S', action='block', direction='in', dst='2001:db8::1'):
    """The same for an IPv6 packet, whose header has fewer fields before the addresses."""
    return (f'8,,,02f4bab031b57d1e30553ce08e0ec131,vtnet0,match,{action},{direction},6,0x00,0x00000,64,'
            f'tcp,6,40,{src},{dst},51234,{dport},0,{flags},2909759651,,64240,,mss')


def stamp(msg, app='filterlog', n=1):
    """A stored line: RFC 5424 header, as the syslog receiver keeps it."""
    return f'1 2026-10-17T09:42:22+02:00 OPNsense01.example.org {app} 66335 - [meta sequenceId="{n}"] {msg}'


def ros(prefix, src, dport, flags='SYN', sport=51234, dst=FIREWALL, chain='input', proto='TCP'):
    """A RouterOS firewall log message: topics, prefix, chain, then the packet."""
    pre = f'{prefix} ' if prefix else ''
    fl = f' ({flags})' if flags else ''
    return (f'firewall,info {pre}{chain}: in:ether1 out:(unknown 0), src-mac 00:11:22:33:44:55, '
            f'proto {proto}{fl}, {src}:{sport}->{dst}:{dport}, len 60')


def suricata_fast(sig, cls, src=SCANNER, dst=FIREWALL + ':22', sid=2001219, prio=2):
    return f'[1:{sid}:20] {sig} [Classification: {cls}] [Priority: {prio}] {{TCP}} {src}:40222 -> {dst}'


# ── the line header ───────────────────────────────────────────────────────────

class TestSplitLine(unittest.TestCase):
    def test_rfc5424_gives_the_program_and_the_message(self):
        self.assertEqual(ae.split_line(stamp('a,b,c')), ('filterlog', 'a,b,c'))

    def test_rfc3164_with_a_pid(self):
        self.assertEqual(ae.split_line('Oct 17 09:42:22 fw01 filterlog[66335]: a,b,c'), ('filterlog', 'a,b,c'))

    def test_a_priority_prefix_is_ignored(self):
        self.assertEqual(ae.split_line('<134>' + stamp('x')), ('filterlog', 'x'))

    def test_routeros_puts_its_topics_where_the_program_would_be(self):
        # bare, with a BSD header, and as RFC 5424 with the topics in the program field
        body = 'rp-trap input: in:ether1 out:(unknown 0), proto TCP (SYN), 1.2.3.4:5->6.7.8.9:80, len 60'
        for line in ('firewall,info ' + body,
                     'Oct 17 09:42:22 MikroTik firewall,info ' + body,
                     '<134>1 2026-10-17T09:42:22+02:00 MikroTik firewall,info - - - ' + body):
            app, msg = ae.split_line(line)
            self.assertEqual(app, 'routeros', line)
            self.assertTrue(msg.startswith('firewall,info rp-trap input:'), (line, msg))

    def test_a_line_without_a_header_comes_back_whole(self):
        self.assertEqual(ae.split_line('just some text'), ('', 'just some text'))

    def test_an_enormous_line_is_cut_before_it_is_read(self):
        app, msg = ae.split_line(stamp('x' * 100_000))
        self.assertLessEqual(len(msg), ae.MAX_LINE)

    def test_not_a_string_is_an_empty_line(self):
        self.assertEqual(ae.split_line(None), ('', ''))


# ── pf ────────────────────────────────────────────────────────────────────────

class TestPf(unittest.TestCase):
    def test_a_refused_ipv4_syn(self):
        r = ae.parse_pf(pf(SCANNER, dport=2222))
        self.assertEqual((r['src'], r['dst'], r['proto'], r['dport'], r['sport']),
                         (SCANNER, FIREWALL, 'tcp', 2222, 51234))
        self.assertEqual((r['action'], r['dir'], r['flags'], r['iface']), ('block', 'in', {'S'}, 'vtnet0'))

    def test_the_ipv6_header_has_its_own_layout(self):
        r = ae.parse_pf(pf6(SCANNER6, dport=443))
        self.assertEqual((r['src'], r['dst'], r['proto'], r['dport'], r['flags']),
                         (SCANNER6, '2001:db8::1', 'tcp', 443, {'S'}))

    def test_udp_has_ports_and_no_flags(self):
        r = ae.parse_pf(pf(SCANNER, dport=1985, proto='udp'))
        self.assertEqual((r['proto'], r['dport']), ('udp', 1985))
        self.assertNotIn('flags', r)

    def test_icmp_has_no_ports(self):
        r = ae.parse_pf(pf(SCANNER, proto='icmp'))
        self.assertEqual(r['proto'], 'icmp')
        self.assertNotIn('dport', r)

    def test_the_ecn_bits_of_a_modern_stack_do_not_hide_a_syn(self):
        # a Linux client with ECN on sends SYN with E and W set
        self.assertEqual(ae.parse_pf(pf(SCANNER, flags='SEW'))['flags'], {'S'})

    def test_what_is_not_a_pf_line_is_none(self):
        for bad in ('', 'a,b,c', '8,,,t,vtnet0,match,block,in,5,rest,of,it,here,more,fields,to,pad,out,to,twenty',
                    None):
            self.assertIsNone(ae.parse_pf(bad), bad)

    def test_a_truncated_ipv4_line_is_none_not_an_error(self):
        full = pf(SCANNER)
        for n in range(0, 20):
            ae.parse_pf(','.join(full.split(',')[:n]))        # must not raise


# ── RouterOS ──────────────────────────────────────────────────────────────────

class TestRouterOS(unittest.TestCase):
    def test_a_rule_whose_prefix_says_drop(self):
        r = ae.parse_routeros_firewall(ros('drop-in', SCANNER, 22))
        self.assertEqual((r['src'], r['dst'], r['proto'], r['dport'], r['flags']),
                         (SCANNER, FIREWALL, 'tcp', 22, {'S'}))
        self.assertEqual((r['action'], r['trap'], r['prefix']), ('block', False, 'drop-in'))

    def test_the_decoy_rule_is_named_by_its_prefix(self):
        r = ae.parse_routeros_firewall(ros('rp-trap', SCANNER, 2222))
        self.assertTrue(r['trap'])
        self.assertEqual(r['action'], 'log', 'a decoy rule only logs, so it is not a refusal by itself')

    def test_a_rule_with_no_prefix_is_only_a_log(self):
        r = ae.parse_routeros_firewall(ros('', SCANNER, 22))
        self.assertEqual((r['action'], r['trap'], r['prefix']), ('log', False, ''))

    def test_flags_are_read_from_the_parentheses(self):
        self.assertEqual(ae.parse_routeros_firewall(ros('drop', SCANNER, 22, flags='SYN,ACK'))['flags'], {'S', 'A'})
        self.assertEqual(ae.parse_routeros_firewall(ros('drop', SCANNER, 22, flags='FIN,PSH,URG'))['flags'],
                         {'F', 'P', 'U'})

    def test_nat_and_a_mac_address_do_not_confuse_the_address_match(self):
        msg = ('firewall,info drop forward: in:ether1 out:ether2, src-mac aa:bb:cc:dd:ee:ff, proto TCP (SYN), '
               f'{SCANNER}:51234->198.51.100.7:80, NAT {SCANNER}:51234->(10.0.0.5:80), len 60')
        r = ae.parse_routeros_firewall(msg)
        self.assertEqual((r['src'], r['dst'], r['dport']), (SCANNER, '198.51.100.7', 80))

    def test_an_ipv6_packet(self):
        msg = ('firewall,info drop-in input: in:ether1 out:(unknown 0), proto TCP (SYN), '
               f'[{SCANNER6}]:51234->[2001:db8::1]:22, len 80')
        r = ae.parse_routeros_firewall(msg)
        self.assertEqual((r['src'], r['dst'], r['dport']), (SCANNER6, '2001:db8::1', 22))

    def test_icmp_in_parentheses_is_not_a_flag_set(self):
        msg = (f'firewall,info drop input: in:ether1 out:(unknown 0), proto ICMP (type 8, code 0), '
               f'{SCANNER}->{FIREWALL}, len 84')
        r = ae.parse_routeros_firewall(msg)
        self.assertEqual((r['proto'], r['src']), ('icmp', SCANNER))
        self.assertNotIn('flags', r)

    def test_other_topics_are_not_firewall_logs(self):
        self.assertIsNone(ae.parse_routeros_firewall('system,info,account user admin logged in from 1.2.3.4 via ssh'))
        self.assertIsNone(ae.parse_routeros_firewall('firewall,info nothing that looks like a packet'))
        self.assertIsNone(ae.parse_routeros_firewall(None))

    def test_the_prefix_is_kept_short(self):
        r = ae.parse_routeros_firewall(ros('drop-' + 'x' * 500, SCANNER, 22))
        self.assertLessEqual(len(r['prefix']), 64)

    def test_a_prefix_cannot_make_a_packet(self):
        # an attacker controls nothing in the prefix, but a rule name might contain an arrow
        r = ae.parse_routeros_firewall(ros('drop 9.9.9.9:1->8.8.8.8:2', SCANNER, 22))
        self.assertEqual(r['src'], SCANNER)


# ── what counts as a probe ────────────────────────────────────────────────────

class TestProbeOf(unittest.TestCase):
    def rec(self, **kw):
        return ae.parse_pf(pf(SCANNER, **kw))

    def test_a_refused_inbound_syn_is_a_probe_on_its_port(self):
        self.assertEqual(ae.probe_of(self.rec(dport=2222)), (2222, False))

    def test_fin_and_xmas_scans_count(self):
        self.assertEqual(ae.probe_of(self.rec(flags='F'))[1], False)
        self.assertIsNotNone(ae.probe_of(self.rec(flags='FPU')))

    def test_a_syn_ack_is_somebody_elses_reply_and_blames_nobody(self):
        # backscatter: the flood's victim answers a spoofed SYN, the answer reaches us
        self.assertIsNone(ae.probe_of(self.rec(flags='SA')))

    def test_an_ack_or_a_reset_is_not_a_probe(self):
        for fl in ('A', 'R', 'RA', 'PA', 'FA'):
            self.assertIsNone(ae.probe_of(self.rec(flags=fl)), fl)

    def test_udp_and_icmp_never_count(self):
        # the source address of both is whatever the sender wrote, and floods forge them
        self.assertIsNone(ae.probe_of(ae.parse_pf(pf(SCANNER, proto='udp'))))
        self.assertIsNone(ae.probe_of(ae.parse_pf(pf(SCANNER, proto='icmp'))))

    def test_outbound_packets_are_not_probes(self):
        self.assertIsNone(ae.probe_of(self.rec(direction='out')))

    def test_a_pass_is_not_a_refusal(self):
        self.assertIsNone(ae.probe_of(self.rec(action='pass')))

    def test_a_reject_is_a_refusal(self):
        self.assertIsNotNone(ae.probe_of(self.rec(action='reject')))

    def test_a_decoy_hit_counts_although_its_rule_only_logs(self):
        r = ae.parse_routeros_firewall(ros('rp-trap', SCANNER, 2222))
        self.assertEqual(ae.probe_of(r), (2222, True))

    def test_a_decoy_hit_still_needs_a_syn(self):
        r = ae.parse_routeros_firewall(ros('rp-trap', SCANNER, 2222, flags='ACK'))
        self.assertIsNone(ae.probe_of(r))

    def test_a_log_rule_that_is_not_the_decoy_is_not_a_refusal(self):
        self.assertIsNone(ae.probe_of(ae.parse_routeros_firewall(ros('', SCANNER, 22))))

    def test_nothing_is_not_a_probe(self):
        self.assertIsNone(ae.probe_of(None))
        self.assertIsNone(ae.probe_of({}))
        self.assertIsNone(ae.probe_of({'kind': 'ids', 'proto': 'tcp', 'dir': 'in'}))


# ── counting probes into scans ────────────────────────────────────────────────

class TestTrack(unittest.TestCase):
    def test_ten_different_ports_within_the_window_are_a_scan(self):
        t = {}
        ev = ae.track(t, [(SCANNER, 1000 + i, False) for i in range(ae.SCAN_PORTS)], 100)
        self.assertEqual(len(ev), 1)
        self.assertEqual((ev[0]['ip'], ev[0]['src'], ev[0]['tok']),
                         (SCANNER, {'fw': 10}, {'fw': {'fw:scan': 10}}))

    def test_nine_ports_are_not(self):
        self.assertEqual(ae.track({}, [(SCANNER, 1000 + i, False) for i in range(ae.SCAN_PORTS - 1)], 100), [])

    def test_the_same_port_over_and_over_is_a_scan_after_enough_packets(self):
        t = {}
        self.assertEqual(ae.track(t, [(SCANNER, 22, False)] * (ae.SCAN_PACKETS - 1), 100), [])
        self.assertEqual(len(ae.track(t, [(SCANNER, 22, False)], 101)), 1)

    def test_a_slow_scanner_is_caught_across_batches(self):
        # one port every 100 seconds: ten ports in 900. A one-minute window sees one packet at a time.
        t, events = {}, []
        for i in range(ae.SCAN_PORTS):
            events += ae.track(t, [(SCANNER, 2000 + i, False)], 100 * i)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['first'], 0)
        self.assertEqual(events[0]['last'], 100 * (ae.SCAN_PORTS - 1))

    def test_the_same_scan_is_one_event_not_one_per_batch(self):
        t, events = {}, []
        for i in range(60):
            events += ae.track(t, [(SCANNER, 3000 + i, False)], 10 + i)
        self.assertEqual(len(events), 1)

    def test_a_scanner_that_goes_quiet_is_forgotten_and_counted_afresh(self):
        t = {}
        ae.track(t, [(SCANNER, 1000 + i, False) for i in range(5)], 0)
        ae.track(t, [(SECOND, 1, False)], ae.WINDOW_S + 1)
        self.assertNotIn(SCANNER, t)
        self.assertEqual(ae.track(t, [(SCANNER, 1000 + i, False) for i in range(5)], ae.WINDOW_S + 2), [])

    def test_ports_spread_over_more_than_a_window_do_not_add_up(self):
        t = {}
        ae.track(t, [(SCANNER, 1000 + i, False) for i in range(6)], 0)
        self.assertEqual(ae.track(t, [(SCANNER, 2000 + i, False) for i in range(6)], ae.WINDOW_S + 5), [])

    def test_a_persistent_scanner_is_reported_again_in_its_next_window(self):
        t, events = {}, []
        for w in range(3):
            events += ae.track(t, [(SCANNER, 1000 + i, False) for i in range(12)], w * (ae.WINDOW_S + 10))
        self.assertEqual(len(events), 3)

    def test_two_hits_on_the_decoy_port_are_enough(self):
        t = {}
        self.assertEqual(ae.track(t, [(SCANNER, 2222, True)], 10), [])
        ev = ae.track(t, [(SCANNER, 2222, True)], 20)
        self.assertEqual(len(ev), 1)
        self.assertEqual((ev[0]['src'], ev[0]['tok'], ev[0]['trp']), ({'dp': 2}, {'dp': {'dp:hit': 2}}, 1))

    def test_decoy_hits_are_not_counted_as_scan_packets(self):
        t = {}
        events = ae.track(t, [(SCANNER, 2222, True)] * (ae.SCAN_PACKETS + 5), 10)
        self.assertEqual([next(iter(e['src'])) for e in events], ['dp'])

    def test_a_scan_and_a_decoy_hit_are_two_events(self):
        t = {}
        events = ae.track(t, [(SCANNER, 1000 + i, False) for i in range(10)] + [(SCANNER, 2222, True)] * 2, 10)
        self.assertEqual(sorted(next(iter(e['src'])) for e in events), ['dp', 'fw'])

    def test_each_address_is_counted_on_its_own(self):
        t = {}
        events = ae.track(t, [(SCANNER, 1000 + i, False) for i in range(6)]
                          + [(SECOND, 2000 + i, False) for i in range(6)], 10)
        self.assertEqual(events, [])

    def test_the_table_is_bounded_and_the_oldest_go_first(self):
        t = {}
        for i in range(ae.MAX_TRACKED + 50):
            ae.track(t, [(f'45.7.{i // 250}.{i % 250 + 1}', 22, False)], 1000 + i // 100)
        self.assertLessEqual(len(t), ae.MAX_TRACKED)
        newest = f'45.7.{(ae.MAX_TRACKED + 49) // 250}.{(ae.MAX_TRACKED + 49) % 250 + 1}'
        self.assertIn(newest, t)

    def test_the_ports_remembered_per_address_are_bounded(self):
        t = {}
        ae.track(t, [(SCANNER, 5000 + i, False) for i in range(ae.SCAN_PORTS - 1)], 10)
        ae.track(t, [(SCANNER, 9000 + i, False) for i in range(200)], 11)
        self.assertLessEqual(len(t[SCANNER]['p']), ae.MAX_PORTS)

    def test_port_zero_is_a_packet_but_not_a_port(self):
        t = {}
        ae.track(t, [(SCANNER, 0, False)] * 3, 10)
        self.assertEqual((t[SCANNER]['n'], t[SCANNER]['p']), (3, []))


# ── Suricata ──────────────────────────────────────────────────────────────────

class TestSuricata(unittest.TestCase):
    def test_lines_read_from_a_real_opnsense(self):
        # OPNsense 26 / Suricata 8.0.7 with "Enable syslog alerts", as RemotePower stored them
        # (2026-10-23; addresses replaced by documentation ranges). The action in front of the
        # signature id is `[Drop]` on a blocking rule, and the classification can be `(null)`.
        pre = '1 2026-10-23T11:05:00+02:00 OPNsense01.example suricata 68879 - [meta sequenceId="335950"] '
        r = ae.read_line(pre + '[Drop] [1:4294967273:1] RP test [Classification: (null)] [Priority: 3] '
                               '{UDP} 203.0.113.9:123 -> 10.0.0.3:123')
        self.assertEqual(r, ('ids', {'kind': 'ids', 'src': '203.0.113.9', 'proto': 'udp', 'dport': 123,
                                     'cls': None, 'cves': [], 'rep': None}))
        r = ae.read_line(pre + '[Drop] [1:2006380:17] ET POLICY Outgoing Basic Auth Base64 HTTP Password '
                               'detected unencrypted [Classification: Potential Corporate Privacy Violation] '
                               '[Priority: 1] {TCP} 10.0.0.2:46816 -> 192.168.2.100:6789')
        self.assertEqual((r[0], r[1]['src'], r[1]['dport'], r[1]['cls']), ('ids', '10.0.0.2', 6789, None))

    def test_the_engines_own_messages_are_none_of_our_business(self):
        # the rule-loading errors that fill the log at every restart: 1,000 of 1,000 lines seen live
        for tail in ('[100733] <Error> -- Duplicate signature "drop http any any -> $HOME_NET any '
                     '(msg:"ET EXPLOIT Possible Vacron NVR Remote Command Execution"; sid:2023000;)"',
                     '[100733] <Notice> -- rule reload complete'):
            line = '1 2026-10-23T02:12:38+02:00 OPNsense01.example suricata 50608 - [meta sequenceId="1"] ' + tail
            self.assertEqual(ae.read_line(line), (None, None))

    def test_engine_messages_do_not_make_a_source_unreadable(self):
        # opnsense01 2026-10-25: 13,852 `suricata` lines, none an alert (the IDS had logged no
        # alert at all), and the source read "Not understood" because each counted as a line the
        # reader failed to parse. Lines from the live log, and the EVE events that are not alerts.
        pre = '1 2026-10-25T13:07:04+02:00 OPNsense01.example suricata 31682 - [meta sequenceId="9"] '
        lines = [pre + " [100491] <Warning> -- flowbit 'is_proto_irc' is checked but not set. Checked in 2002029 and 4 other sigs",
                 pre + " [100491] <Notice> -- Threads created -> W: 2 FM: 1 FR: 1   Engine started.",
                 pre + '{"timestamp":"2026-10-25T13:08:00","event_type":"flow","src_ip":"203.0.113.9"}',
                 pre + '{"event_type":"stats","stats":{}}']
        for ln in lines:
            self.assertEqual(ae.read_line(ln), (None, None), ln)
        self.assertEqual(ae.scan(lines)[2], {})
        # an alert beside them still counts, as parsed
        alert = pre + '[Drop] [1:2001219:20] ET SCAN Potential SSH Scan [Classification: Attempted Information Leak] [Priority: 2] {TCP} ' + SCANNER + ':4444 -> 10.0.0.5:22'
        self.assertEqual(ae.scan(lines + [alert])[2], {'ids': {'lines': 1, 'parsed': 1, 'events': 1}})
        # an alert that cannot be read is still a line that was not understood
        self.assertEqual(ae.scan([pre + '[1:2001219:20] ET SCAN broken, no tail'])[2]['ids']['parsed'], 0)

    def test_a_fast_log_alert(self):
        r = ae.parse_suricata(suricata_fast('ET SCAN Potential SSH Scan', 'Attempted Information Leak'))
        self.assertEqual((r['src'], r['proto'], r['dport'], r['cls']), (SCANNER, 'tcp', 22, 'port_scan'))

    def test_an_eve_alert(self):
        r = ae.parse_suricata(
            '{"timestamp":"2026-10-17T09:42:22.123456+0200","event_type":"alert",'
            f'"src_ip":"{SCANNER}","src_port":40222,"dest_ip":"{FIREWALL}","dest_port":22,"proto":"TCP",'
            '"alert":{"action":"allowed","gid":1,"signature_id":2001219,"rev":20,'
            '"signature":"ET SCAN Potential SSH Scan","category":"Attempted Information Leak","severity":2}}')
        self.assertEqual((r['src'], r['proto'], r['dport'], r['cls']), (SCANNER, 'tcp', 22, 'port_scan'))

    def test_eve_events_that_are_not_alerts_are_not_read(self):
        self.assertIsNone(ae.parse_suricata('{"event_type":"flow","src_ip":"1.2.3.4"}'))
        self.assertIsNone(ae.parse_suricata('{"event_type":"alert"'))                 # cut off
        self.assertIsNone(ae.parse_suricata('{"event_type":"alert","alert":{}}'))     # no source

    def test_an_ipv6_source_is_printed_without_brackets(self):
        line = f'[1:2001219:20] ET SCAN Potential SSH Scan [Classification: Attempted Information Leak] ' \
               f'[Priority: 2] {{TCP}} {SCANNER6}:40222 -> 2001:db8::1:22'
        r = ae.parse_suricata(line)
        self.assertEqual((r['src'], r['dport']), (SCANNER6, 22))

    def test_the_cve_a_signature_names_is_kept(self):
        r = ae.parse_suricata(suricata_fast('ET EXPLOIT Apache log4j RCE Attempt (http ldap) (CVE-2021-44228)',
                                            'Attempted Administrator Privilege Gain', dst=FIREWALL + ':8080'))
        self.assertEqual((r['cls'], r['cves']), ('rce', ['CVE-2021-44228']))

    def test_other_text_is_not_an_alert(self):
        self.assertIsNone(ae.parse_suricata('engine started'))
        self.assertIsNone(ae.parse_suricata(''))
        self.assertIsNone(ae.parse_suricata(None))

    def test_signatures_become_the_class_their_name_says(self):
        for sig, cls, want in (
                ('ET SCAN Nmap Scripting Engine User-Agent Detected', 'Web Application Attack', 'scanner'),
                ('ET SCAN Suspicious inbound to MSSQL port 1433', 'Potentially Bad Traffic', 'port_scan'),
                ('ET WEB_SERVER Possible SQL Injection Attempt SELECT FROM', 'Web Application Attack', 'sqli'),
                ('ET WEB_SERVER Script tag in URI, Possible Cross Site Scripting Attempt', '', 'xss'),
                # reading a file is path traversal; calling it code execution would accuse the address of more
                ('ET WEB_SERVER /etc/passwd Detected in URI', 'Attempted Information Leak', 'traversal'),
                ('ET WEB_SPECIFIC_APPS WordPress wp-config.php directory traversal', '', 'traversal'),
                ('ET DOS Possible NTP DDoS Inbound Frequent Un-Authed MON_LIST Requests', '', 'flood'),
                ('ET SCAN Hydra User-Agent', '', 'port_scan'),
                ('ET POLICY Suspicious inbound to Oracle SQL port 1521', 'Potentially Bad Traffic', None),
        ):
            self.assertEqual(ae.classify_ids(sig, cls), want, sig)

    def test_a_short_name_inside_a_longer_word_is_not_that_name(self):
        """`rce` ends "force" and "source". With no boundary in front of it the pattern filed
        "brute force" and "external source" as remote code execution, and a public report said so."""
        for sig, want in (('ET FTP login brute force', 'ftp_brute'),
                          ('ET TELNET Telnet brute force', 'service_brute'),
                          ('ET SCAN Possible Nmap Scan from external source', 'scanner'),
                          ('ET WEB_SERVER Resource exhaustion attempt', None),
                          ('ET WEB_SERVER Enforce the policy', None)):
            self.assertEqual(ae.classify_ids(sig, ''), want, sig)
        for name in ('rce', 'xss', 'lfi', 'rfi', 'dos', 'sqli'):
            for word in (f'a{name}', f'{name}a', f'xx{name}yy'):
                self.assertIsNone(ae.classify_ids(f'ET WEB {word} thing', ''), word)
        for sig in ('ET EXPLOIT Apache Log4j RCE Attempt', 'ET EXPLOIT Struts2 RCE',
                    'ET EXPLOIT Shellshock Attempt', 'ET WEB_SERVER Spring4Shell RCE'):
            self.assertEqual(ae.classify_ids(sig, ''), 'rce', f'control: {sig}')

    def test_what_names_no_attack_has_no_class(self):
        # the engine's own events, reputation lists, policy, outbound malware, chatter
        for sig in ('SURICATA STREAM ESTABLISHED packet out of window',
                    'SURICATA TCPv4 invalid checksum',
                    'ET DROP Dshield Block Listed Source group 1',
                    'ET CINS Active Threat Intelligence Poor Reputation IP group 53',
                    'ET COMPROMISED Known Compromised or Hostile Host Traffic group 7',
                    'ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 3',
                    'ET INFO Session Traversal Utilities for NAT (STUN Binding Request)',
                    'ET POLICY IP Check Domain (whatismyip in HTTP Host)',
                    'ET MALWARE Win32/Foo CnC Checkin',
                    'ET TROJAN Observed Malicious UA',
                    'ET CURRENT_EVENTS Phishing Landing',
                    'GPL ATTACK_RESPONSE id check returned root'):
            self.assertIsNone(ae.classify_ids(sig, ''), sig)

    def test_a_signature_name_cannot_bring_in_a_class_by_its_wording_alone_when_it_is_the_engine(self):
        # "scan" in an engine event must not make a port scan out of it
        self.assertIsNone(ae.classify_ids('SURICATA scan of the rules file', ''))

    def test_every_class_it_can_return_is_one_the_vocabulary_accepts(self):
        produced = {cls for cls, _ in ae._IDS_RULES}
        self.assertTrue(produced <= set(te.IDS_CLASSES), produced - set(te.IDS_CLASSES))
        self.assertTrue(set(te.IDS_CLASSES) <= set(te.CLASSES))


# ── CrowdSec ──────────────────────────────────────────────────────────────────

def cs_alert(scenario='crowdsecurity/ssh-bf', ip=SCANNER, events=6, decisions=None, **extra):
    a = {'scenario': scenario, 'source': {'ip': ip, 'scope': 'Ip'}, 'events_count': events,
         'decisions': [{'origin': 'crowdsec', 'type': 'ban', 'value': ip}] if decisions is None else decisions}
    a.update(extra)
    return a


class TestHostileLinesAreCheap(unittest.TestCase):
    """These lines come off the network, up to 2,048 characters each and 200 to a post. A reader
    that backtracks quadratically turns one forged datagram into seconds of CPU: the first
    Suricata pattern (a lazy `.*?` before `\\s+` and two optional groups) took 165 ms for the
    first line below, 33 seconds for a post of them."""

    N = 2048
    HEAD = '1 2026-10-17T09:42:22+02:00 h suricata 1 - - '
    BUDGET_S = 0.04            # the worst line now takes about 3 ms; the old pattern took 165 ms

    LINES = {
        'a signature, then a long run of spaces, then an open brace': HEAD + '[1:2:3] a' + ' ' * 1900 + '{',
        'the alert header repeated': HEAD + '[1:2:3] ' * 250,
        'a run of braces after the header': HEAD + '[1:2:3] a ' + '{a} ' * 480,
        'braces and spaces and words, never an arrow': HEAD + '[1:2:3] a ' + '{a} b ' * 380,
        'classification openers that never close': HEAD + '[1:2:3] a ' + '[Classification: ' * 110 + '{T} a -> b',
        'a long signature': HEAD + '[1:2:3] ' + 'a ' * 900 + '{T} a -> b',
        'arrows after the protocol': HEAD + '[1:2:3] a {T} ' + 'x -> ' * 380,
        'RouterOS: the packet marker repeated': 'firewall,info ' + 'proto TCP, ' * 180,
        'RouterOS: a long hex and colon run': 'firewall,info proto TCP, ' + 'a:' * 900,
        'RouterOS: address starts after address starts': 'firewall,info proto TCP, ' + '1.2.3.4:1->' * 160,
        'RouterOS: a long prefix': 'firewall,info ' + 'a b ' * 500 + ': in:',
        'pf: an enormous structured-data field': '1 2026-10-17T09:42:22+02:00 h filterlog 1 - ' + '[a="b"]' * 200,
        'a sign-in line with "from" repeated': 'login failure for user ' + 'x from ' * 280 + 'via',
        'a sign-in line with a long tail': 'login failure for user x from ' + 'a ' * 900,
    }

    def cost(self, line):
        t = time.perf_counter()
        ae.read_line(line)
        ae.parse_suricata(line.split(' - - ', 1)[-1])
        ae.parse_routeros_firewall(line if line.startswith('firewall') else 'firewall,info ' + line)
        for group in ae.LOGIN_PATTERNS.values():
            for pat in group:
                pat.search(line)
        return time.perf_counter() - t

    def test_no_line_costs_more_than_a_few_milliseconds(self):
        self.assertGreaterEqual(len(self.LINES), 12, 'control: the population is not empty')
        for name, line in self.LINES.items():
            line = line[:self.N]
            self.assertLess(self.cost(line), self.BUDGET_S, name)

    def test_a_post_of_the_worst_lines_is_read_in_a_fraction_of_a_second(self):
        lines = [ln[:self.N] for ln in self.LINES.values()] * 15        # 210 lines, one post's worth
        t = time.perf_counter()
        ae.scan(lines)
        self.assertLess(time.perf_counter() - t, 0.5, 'a forged post must not hold a worker for seconds')

    def test_the_instrument_sees_the_pattern_that_was_replaced(self):
        """The control. The old pattern on its worst line is slow on this machine, so a budget
        that the new reader meets is not one that nothing could miss."""
        import re
        old = re.compile(
            r"\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+(?P<sig>.*?)\s+"
            r"(?:\[Classification:\s*(?P<cls>[^\]]*)\]\s*)?(?:\[Priority:\s*(?P<prio>\d+)\]\s*)?"
            r"\{(?P<proto>[A-Za-z0-9_-]+)\}\s+(?P<src>\S+)\s+->\s+(?P<dst>\S+)")
        line = ('[1:2:3] a' + ' ' * 1900 + '{')[:self.N]
        t = time.perf_counter()
        old.search(line)
        slow = time.perf_counter() - t
        self.assertGreater(slow, 0.01, 'the old pattern should take tens of milliseconds on this line')
        self.assertGreater(slow, 3 * self.cost(self.HEAD + line), 'the reader in use is not the slow one')


class TestCrowdSec(unittest.TestCase):
    def test_an_alert_becomes_one_line_in_a_fixed_shape(self):
        self.assertEqual(ae.crowdsec_lines([cs_alert()]),
                         [f'crowdsec alert scenario=crowdsecurity/ssh-bf src={SCANNER} events=6 decision=ban'])

    def test_a_single_alert_is_read_as_a_list_of_one(self):
        self.assertEqual(len(ae.crowdsec_lines(cs_alert())), 1)

    def test_the_line_reads_back(self):
        r = ae.parse_crowdsec(ae.crowdsec_lines([cs_alert(events=11)])[0])
        self.assertEqual((r['src'], r['scenario'], r['events'], r['decision']),
                         (SCANNER, 'crowdsecurity/ssh-bf', 11, True))

    def test_an_alert_without_a_decision_says_none(self):
        line = ae.crowdsec_lines([cs_alert(decisions=[])])[0]
        self.assertTrue(line.endswith('decision=none'))
        self.assertFalse(ae.parse_crowdsec(line)['decision'])

    def test_a_decision_from_the_community_list_is_not_this_hosts_finding(self):
        capi = [{'origin': 'CAPI', 'type': 'ban', 'value': SCANNER}]
        self.assertTrue(ae.crowdsec_lines([cs_alert(decisions=capi)])[0].endswith('decision=none'))

    def test_a_ban_added_by_hand_is_not_a_decision_either(self):
        """`cscli decisions add` writes origin `cscli`. The host sensor and its guide count only
        a local scenario's ban (origin `crowdsec`), and a firewall must not be easier to report from."""
        for origin in ('cscli', 'lists', 'console', ''):
            by_hand = [{'origin': origin, 'type': 'ban', 'value': SCANNER}]
            self.assertTrue(ae.crowdsec_lines([cs_alert(decisions=by_hand)])[0].endswith('decision=none'), origin)
        local = [{'origin': 'crowdsec', 'type': 'ban', 'value': SCANNER}]
        self.assertTrue(ae.crowdsec_lines([cs_alert(decisions=local)])[0].endswith('decision=ban'),
                        'control: a local scenario\'s ban is a decision')

    def test_a_simulated_alert_or_decision_is_not_a_decision(self):
        self.assertEqual(ae.crowdsec_lines([cs_alert(simulated=True)]), [])
        sim = [{'origin': 'crowdsec', 'type': 'ban', 'simulated': True}]
        self.assertTrue(ae.crowdsec_lines([cs_alert(decisions=sim)])[0].endswith('decision=none'))

    def test_a_scenario_or_an_address_that_is_not_what_it_should_be_is_dropped(self):
        for bad in (cs_alert(scenario='x y'), cs_alert(scenario='x\nsrc=8.8.8.8'), cs_alert(scenario=''),
                    cs_alert(ip='not an address'), cs_alert(ip='1.2.3.4\nevil'), cs_alert(ip=''),
                    {'scenario': 'a/b', 'source': 'nope'}, 'text', 7, None):
            self.assertEqual(ae.crowdsec_lines([bad]), [], bad)

    def test_the_decision_type_is_a_short_word_or_ban(self):
        d = [{'origin': 'crowdsec', 'type': 'x y; rm -rf /'}]
        self.assertTrue(ae.crowdsec_lines([cs_alert(decisions=d)])[0].endswith('decision=ban'))
        d = [{'origin': 'crowdsec', 'type': 'captcha'}]
        self.assertTrue(ae.crowdsec_lines([cs_alert(decisions=d)])[0].endswith('decision=captcha'))

    def test_the_event_count_is_a_sane_number(self):
        for given, want in ((0, 1), (-5, 1), ('x', 1), (None, 1), (10 ** 12, 1_000_000), (float('inf'), 1)):
            line = ae.crowdsec_lines([cs_alert(events=given)])[0]
            self.assertEqual(ae.parse_crowdsec(line)['events'], want, given)

    def test_what_is_not_a_list_of_alerts_gives_no_lines(self):
        for body in (None, 'x', 5, {}, {'a': 1}, [], [None]):
            self.assertEqual(ae.crowdsec_lines(body), [], body)


# ── a batch ───────────────────────────────────────────────────────────────────

class TestScan(unittest.TestCase):
    def test_a_mixed_batch_is_counted_per_source(self):
        lines = [stamp(pf(SCANNER, dport=1000 + i), n=i) for i in range(12)]
        lines += [stamp(pf(SCANNER, dport=22, action='pass'))]                       # allowed
        lines += [stamp(suricata_fast('ET SCAN Potential SSH Scan', 'Attempted Information Leak'), app='suricata')]
        lines += ['crowdsec alert scenario=crowdsecurity/ssh-bf src=%s events=6 decision=ban' % SECOND]
        lines += [stamp('Accepted publickey for root', app='sshd')]                  # none of ours
        hits, events, stats = ae.scan(lines)
        self.assertEqual(len(hits), 12)
        self.assertEqual(stats['fw'], {'lines': 13, 'parsed': 13, 'events': 0})
        self.assertEqual(stats['ids'], {'lines': 1, 'parsed': 1, 'events': 1})
        self.assertEqual(stats['cs'], {'lines': 1, 'parsed': 1, 'events': 1})
        self.assertEqual(sorted(next(iter(e['src'])) for e in events), ['cs', 'ids'])

    def test_lines_of_other_programs_leave_no_trace(self):
        hits, events, stats = ae.scan([stamp('Accepted publickey', app='sshd'), 'plain text'])
        self.assertEqual((hits, events, stats), ([], [], {}))

    def test_a_line_of_a_source_it_could_not_read_is_counted_but_not_parsed(self):
        hits, events, stats = ae.scan([stamp('garbage,not,a,pf,line')])
        self.assertEqual((hits, events), ([], []))
        self.assertEqual(stats['fw'], {'lines': 1, 'parsed': 0, 'events': 0})

    def test_private_and_reserved_sources_are_never_probes(self):
        for src in ('10.0.0.5', '192.168.1.9', '172.16.3.4', '127.0.0.1', '169.254.1.1', '203.0.113.9',
                    '100.64.0.7', '224.0.0.1', '0.0.0.0'):
            hits, _, _ = ae.scan([stamp(pf(src))])
            self.assertEqual(hits, [], src)

    def test_a_public_source_is_a_probe(self):
        hits, _, _ = ae.scan([stamp(pf(SCANNER, dport=8080))])
        self.assertEqual(hits, [(SCANNER, 8080, False)])

    def test_ids_alerts_for_one_address_are_one_event_with_its_classes_counted(self):
        sigs = ['ET SCAN Nmap Scripting Engine User-Agent Detected'] * 3 + ['ET SCAN Potential SSH Scan'] * 2
        lines = [stamp(suricata_fast(s, 'x'), app='suricata') for s in sigs]
        _, events, stats = ae.scan(lines)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['src'], {'ids': 5})
        self.assertEqual(events[0]['tok'], {'ids': {'ids:scanner': 3, 'ids:port_scan': 2}})
        self.assertEqual(stats['ids'], {'lines': 5, 'parsed': 5, 'events': 1})

    def test_an_ids_alert_that_names_no_attack_is_read_but_makes_no_event(self):
        line = stamp(suricata_fast('ET DROP Dshield Block Listed Source group 1', 'Misc Attack'), app='suricata')
        _, events, stats = ae.scan([line])
        self.assertEqual(events, [])
        self.assertEqual(stats['ids'], {'lines': 1, 'parsed': 1, 'events': 0})

    def test_a_crowdsec_decision_is_carried(self):
        _, events, _ = ae.scan(['crowdsec alert scenario=crowdsecurity/ssh-bf src=%s events=6 decision=ban' % SCANNER,
                                'crowdsec alert scenario=crowdsecurity/http-probing src=%s events=4 decision=none' % SCANNER])
        self.assertEqual(len(events), 1)
        self.assertEqual((events[0]['src'], events[0]['dec']), ({'cs': 10}, 1))

    def test_a_crowdsec_scenario_that_names_no_attack_makes_no_event(self):
        _, events, _ = ae.scan(['crowdsec alert scenario=local/internal-chatter src=%s events=6 decision=ban' % SCANNER])
        self.assertEqual(events, [])

    def test_the_scan_keeps_no_state_between_calls(self):
        lines = [stamp(pf(SCANNER, dport=1000 + i)) for i in range(5)]
        self.assertEqual(ae.scan(lines)[0], ae.scan(lines)[0])

    def test_hostile_lines_do_not_raise(self):
        junk = ['', None, 7, '\x00' * 50, stamp('\x00,\x00'), stamp(',' * 5000), '<<<>>>', '1 ' * 3000,
                stamp('8,,,t,vtnet0,match,block,in,4,' + 'x,' * 40), stamp('{"event_type":"alert","src_ip":5}', app='suricata'),
                stamp('[1:2:3] x [Classification: ] {TCP} a -> b', app='suricata')]
        ae.scan(junk)


class TestRead(unittest.TestCase):
    def test_scan_and_track_together(self):
        table = {}
        lines = [stamp(pf(SCANNER, dport=1000 + i)) for i in range(10)]
        events, stats = ae.read(lines, table, 500)
        self.assertEqual(len(events), 1)
        self.assertEqual((events[0]['first'], events[0]['last']), (500, 500))
        self.assertEqual(stats['fw'], {'lines': 10, 'parsed': 10, 'events': 1})

    def test_the_second_batch_of_the_same_scan_adds_nothing(self):
        table = {}
        ae.read([stamp(pf(SCANNER, dport=1000 + i)) for i in range(10)], table, 500)
        events, _ = ae.read([stamp(pf(SCANNER, dport=2000 + i)) for i in range(10)], table, 510)
        self.assertEqual(events, [])


# ── the vocabulary the readers write in ───────────────────────────────────────

class TestVocabulary(unittest.TestCase):
    def test_the_families_and_who_may_claim_them(self):
        self.assertEqual(te.APPLIANCE_SOURCES, ('fw', 'cs', 'ids', 'dp'))
        self.assertTrue({'ids', 'dp'} <= set(te.SOURCES))
        self.assertFalse({'ids', 'dp'} & set(te.AGENT_SOURCES), 'an agent can claim neither')
        self.assertFalse({'ids', 'dp'} & set(te.EDGE_SOURCES))

    def test_an_agent_cannot_say_a_decoy_port_or_an_ids_decided(self):
        raw = {'ip': SCANNER, 'first': 1, 'last': 2, 'src': {'web': 4, 'dp': 9, 'ids': 9},
               'tok': {'web': {'req:sqli': 4}, 'dp': {'dp:hit': 9}, 'ids': {'ids:rce': 9}}, 'trp': 1}
        ev = te.normalize_event(raw, now=10)
        self.assertEqual(ev['src'], {'web': 4})
        self.assertEqual(ev['tok'], {'web': {'req:sqli': 4}})
        self.assertEqual(ev['trp'], 0, 'only a reader that knows the decoy port may say it decided')

    def test_the_server_reads_them_with_the_appliance_families(self):
        raw = {'ip': SCANNER, 'first': 1, 'last': 2, 'src': {'dp': 2}, 'tok': {'dp': {'dp:hit': 2}}, 'trp': 1}
        ev = te.normalize_event(raw, now=10, families=te.APPLIANCE_SOURCES)
        self.assertEqual((ev['src'], ev['trp']), ({'dp': 2}, 1))

    def test_tokens_map_to_their_classes(self):
        self.assertEqual(te.token_class('dp:hit'), 'decoy_port')
        self.assertEqual(te.token_class('ids:rce'), 'rce')
        self.assertEqual(te.token_class('fw:scan'), 'port_scan')
        self.assertIsNone(te.token_class('dp:other'))
        self.assertIsNone(te.token_class('ids:nonsense'))

    def test_every_ids_class_is_a_class_with_a_category_at_both_services(self):
        for c in te.IDS_CLASSES:
            self.assertIn(c, te.CLASSES, c)
            self.assertTrue(te.CLASSES[c]['abuseipdb'] and te.CLASSES[c]['sniffcat'], c)
        self.assertTrue(te.CLASSES['decoy_port']['abuseipdb'] and te.CLASSES['decoy_port']['sniffcat'])

    def ev(self, **kw):
        return te.normalize_event(dict({'ip': SCANNER, 'first': 1, 'last': 601}, **kw), now=700,
                                  families=te.APPLIANCE_SOURCES)

    def test_a_scan_reads_as_port_scanning_and_a_decoy_hit_as_its_own_thing(self):
        scan = self.ev(src={'fw': 38}, tok={'fw': {'fw:scan': 38}})
        decoy = self.ev(src={'dp': 2}, tok={'dp': {'dp:hit': 2}}, trp=1)
        self.assertEqual(te.attack_phrase(scan), 'port scanning')
        self.assertEqual(te.attack_phrase(decoy), 'connecting to a decoy port')
        self.assertEqual((te.seen_by(scan), te.seen_by(decoy)), ('firewall log', 'decoy port'))

    def test_a_decoy_hit_is_a_decision_and_needs_no_count(self):
        decoy = self.ev(src={'dp': 2}, tok={'dp': {'dp:hit': 2}}, trp=1)
        ok, why = te.qualifies(decoy, 10)
        self.assertTrue(ok, why)
        self.assertEqual(te.confirmed_by(decoy), 'a decoy port')

    def test_the_honeypot_keeps_its_own_wording(self):
        trap = te.normalize_event({'ip': SCANNER, 'first': 1, 'last': 2, 'src': {'trap': 1},
                                   'tok': {'trap': {'trap:bait': 1}}, 'trp': 1}, now=10,
                                  families=te.EDGE_SOURCES)
        self.assertEqual(te.confirmed_by(trap), 'the edge honeypot')
        both = te.merge(trap, self.ev(src={'dp': 2}, tok={'dp': {'dp:hit': 2}}, trp=1))
        self.assertEqual(te.trap_family(both), 'trap', 'an address both saw is the honeypot\'s to describe')

    def test_a_scan_needs_the_operators_count_like_any_other_probing(self):
        self.assertFalse(te.qualifies(self.ev(src={'fw': 9}, tok={'fw': {'fw:scan': 9}}), 10)[0])
        self.assertTrue(te.qualifies(self.ev(src={'fw': 10}, tok={'fw': {'fw:scan': 10}}), 10)[0])

    def test_a_firewall_scan_is_never_confirmed_by_anyone(self):
        self.assertEqual(te.confirmed_by(self.ev(src={'fw': 38}, tok={'fw': {'fw:scan': 38}})), '')

    def test_the_decoy_hit_names_a_port_in_the_comment(self):
        self.assertEqual(te.what_word(self.ev(src={'dp': 2}, tok={'dp': {'dp:hit': 2}}, trp=1)), 'port')


if __name__ == '__main__':
    unittest.main()

"""The agent's firewall-log source (v7.3.0): UFW and kernel LOG records.

A blocked packet is background noise on any public address, so the questions are
the opposite of the web logs': does one stray packet ever count, does an allowed
or outbound record, and does the log's text reach what is sent. The reader is run
for real, over realistic records, and through discovery and a whole pass.
"""
import json
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_v720_threat_sensor_agent import A1, A2, A3, A6, NOW, load_agent  # noqa: E402
from test_v720_threat_sensor_cycle import _Host  # noqa: E402

_MON = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')


def bsd(e):                              # Oct 10 22:50:38 (the host's local time, no year)
    t = time.localtime(e)
    return f'{_MON[t.tm_mon - 1]} {t.tm_mday:2d} {t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d}'


def iso(e):                              # 2026-10-10T22:50:38.491116+00:00 (rsyslog's file format)
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(e)) + '.491116+00:00'


def rec(src, dport, e=NOW - 30, tag='UFW BLOCK', iface='ens18', out='', proto='TCP', stamp=bsd,
        host='tviweb01'):
    return (f'{stamp(e)} {host} kernel: [123456.789012] [{tag}] IN={iface} OUT={out} '
            f'MAC=aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:08:00 SRC={src} DST=10.0.0.4 LEN=44 TOS=0x00 '
            f'PREC=0x00 TTL=240 ID=54321 PROTO={proto} SPT=40000 DPT={dport} WINDOW=1024 RES=0x00 SYN URGP=0')


def scan(agent, lines, now=NOW, fkey='/var/log/ufw.log'):
    agg = agent._TsAgg(now)
    n, parsed = agent._ts_scan_firewall(lines, agg, fkey, now)
    ev, dropped = agg.events()
    return {e['ip']: e for e in ev}, n, parsed


class TestWhatIsAScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.agent = load_agent('agent_fw')

    def test_a_sweep_of_ports_is_one_event_with_the_packet_count(self):
        lines = [rec(A1, p) for p in (22, 23, 80, 443, 3389, 5900)]
        ev, n, parsed = scan(self.agent, lines)
        self.assertEqual((n, parsed), (6, 6))
        e = ev[A1]
        self.assertEqual(e['src'], {'fw': 6})
        self.assertEqual(e['tok'], {'fw': {'fw:scan': 6}})
        self.assertEqual(e['blk'], 6)

    def test_one_port_hammered_is_a_scan_too(self):
        ev, _, _ = scan(self.agent, [rec(A1, 22) for _ in range(15)])
        self.assertEqual(ev[A1]['src'], {'fw': 15})

    def test_a_stray_packet_is_nothing(self):
        ev, n, parsed = scan(self.agent, [rec(A1, 22), rec(A1, 22), rec(A1, 23), rec(A2, 80)])
        self.assertEqual(ev, {})
        self.assertEqual((n, parsed), (4, 4))

    def test_the_thresholds_are_the_documented_ones(self):
        self.assertEqual((self.agent.THREAT_FW_PORTS, self.agent.THREAT_FW_PACKETS), (4, 15))
        ev, _, _ = scan(self.agent, [rec(A1, p) for p in (22, 23, 80)] * 2)
        self.assertEqual(ev, {}, 'three ports, six packets')
        ev, _, _ = scan(self.agent, [rec(A1, p) for p in (22, 23, 80, 81)])
        self.assertIn(A1, ev, 'four ports')

    def test_only_inbound_refusals_count(self):
        sweep = (22, 23, 80, 443, 3389, 5900)
        for kw in ({'tag': 'UFW ALLOW'}, {'tag': 'UFW AUDIT'}, {'tag': 'UFW ALLOW IN'},
                   {'out': 'ens18'}, {'iface': ''}, {'tag': 'ACCEPT'}, {'tag': 'NEW CONNECTION'}):
            ev, _, _ = scan(self.agent, [rec(A1, p, **kw) for p in sweep])
            self.assertEqual(ev, {}, kw)
        for tag in ('UFW BLOCK', 'UFW LIMIT BLOCK', 'RP-DROP', 'iptables denied', 'FW-REJECT', 'INVALID'):
            ev, _, _ = scan(self.agent, [rec(A1, p, tag=tag) for p in sweep])
            self.assertIn(A1, ev, tag)

    def test_nobody_private_or_malformed_is_a_source(self):
        sweep = (22, 23, 80, 443, 3389, 5900)
        for src in ('10.0.0.9', '192.168.1.5', '127.0.0.1', '169.254.1.1', '224.0.0.1', 'not-an-ip', ''):
            ev, _, _ = scan(self.agent, [rec(src, p) for p in sweep])
            self.assertEqual(ev, {}, src)

    def test_ipv6_and_both_stamp_formats(self):
        ev, _, _ = scan(self.agent, [rec(A6, p, stamp=iso) for p in (22, 23, 80, 443)])
        self.assertIn(A6, ev)
        ev, _, _ = scan(self.agent, [rec(A1, p, stamp=bsd) for p in (22, 23, 80, 443)])
        self.assertIn(A1, ev)

    def test_the_hostname_is_not_a_verdict(self):
        """`blockhost` sits just before the rule's own prefix; only the prefix is read."""
        line = rec(A1, 22, tag='UFW AUDIT', host='blockhost')
        ev, _, _ = scan(self.agent, [line.replace('[UFW AUDIT] ', '')] * 20)
        self.assertEqual(ev, {})

    def test_old_lines_are_not_evidence(self):
        ev, _, _ = scan(self.agent, [rec(A1, p, e=NOW - 8 * 3600) for p in (22, 23, 80, 443)])
        self.assertEqual(ev, {})

    def test_the_year_less_stamp_across_new_year(self):
        # a line stamped December 31, read on January 1: still last night, not next year
        jan1 = time.mktime((2027, 1, 1, 0, 5, 0, 0, 0, -1))
        dec31 = time.mktime((2026, 12, 31, 23, 58, 0, 0, 0, -1))
        self.assertEqual(self.agent._ts_time_syslog(bsd(dec31) + ' x', int(jan1)), int(dec31))

    def test_a_kernel_log_full_of_other_things_is_understood_not_unparsed(self):
        other = [f'{bsd(NOW - 10)} tviweb01 kernel: [ 99.1] usb 1-1: new high-speed USB device {i}'
                 for i in range(40)]
        ev, n, parsed = scan(self.agent, other + [rec(A1, p) for p in (22, 23, 80, 443)])
        self.assertEqual((n, parsed), (44, 44))
        self.assertIn(A1, ev)

    def test_only_counts_and_one_token_leave(self):
        line = rec(A1, 22).replace('SYN', 'SYN SECRET-PAYLOAD-<script>')
        ev, _, _ = scan(self.agent, [line] * 20)
        blob = json.dumps(ev)
        self.assertNotIn('SECRET', blob)
        self.assertNotIn('tviweb01', blob)
        self.assertNotIn('MAC', blob)
        self.assertEqual(set(ev[A1]['tok']['fw']), {'fw:scan'})

    def test_a_flood_of_addresses_is_bounded(self):
        many = [rec(f'45.{i // 250 % 250}.{i % 250}.7', p) for i in range(6000) for p in (22,)]
        agg = self.agent._TsAgg(NOW)
        self.agent._ts_scan_firewall(many, agg, '/var/log/ufw.log', NOW)
        self.assertLessEqual(len(agg.acc), 5000)


class TestDiscoveryAndAPass(_Host):
    def test_ufw_log_is_found_and_kern_log_only_when_there_is_none(self):
        self.put('/var/log/ufw.log', '')
        self.put('/var/log/kern.log', '')
        disc = self.agent._ts_discover({}, NOW)
        self.assertEqual(self.paths(disc, 'fw'), ['/var/log/ufw.log'])
        (self.tmp / 'var/log/ufw.log').unlink()
        disc = self.agent._ts_discover({}, NOW)
        self.assertEqual(self.paths(disc, 'fw'), ['/var/log/kern.log'])
        (self.tmp / 'var/log/kern.log').unlink()
        self.assertEqual(self.agent._ts_discover({}, NOW)['fw'], [])

    def test_an_operator_file_is_classified_by_name(self):
        for name, kind in (('/var/log/ufw.log', 'fw'), ('/var/log/firewall.log', 'fw'),
                           ('/var/log/kern.log', 'fw'), ('/var/log/iptables.log', 'fw'),
                           ('/var/log/nginx/access.log', 'web'), ('/var/log/fail2ban.log', 'f2b')):
            self.assertEqual(self.agent._ts_kind_of(name), kind, name)
        self.put('/var/log/custom/fw-drops.log', '')
        self.put('/var/log/custom/firewall.log', '')
        disc = self.agent._ts_discover({'paths': ['/var/log/custom/firewall.log']}, NOW)
        self.assertIn('/var/log/custom/firewall.log', self.paths(disc, 'fw'))

    def test_a_whole_pass_reads_the_log_and_says_how_it_went(self):
        lines = [rec(A1, p) for p in (22, 23, 80, 443, 8080)] + [rec(A2, 22)]
        self.put('/var/log/ufw.log', '\n'.join(lines) + '\n')
        events, sources, dropped, state = self.agent.collect_threat_events({}, {}, now=NOW)
        by = {e['ip']: e for e in events}
        self.assertEqual(set(by), {A1})
        self.assertEqual(by[A1]['src'], {'fw': 5})
        fw = [s for s in sources if s['kind'] == 'fw']
        self.assertEqual(len(fw), 1)
        self.assertEqual((fw[0]['path'], fw[0]['state'], fw[0]['lines'], fw[0]['parsed'], fw[0]['events']),
                         ('/var/log/ufw.log', 'ok', 6, 6, 5))
        # nothing new: the same log is quiet, not re-counted
        events, sources, _, _ = self.agent.collect_threat_events({}, state, now=NOW)
        self.assertEqual(events, [])
        self.assertEqual([s['state'] for s in sources if s['kind'] == 'fw'], ['idle'])

    def test_an_empty_ufw_log_is_quiet_not_broken(self):
        """UFW off, and the file left behind empty: it reads as a quiet log, which
        is true, and the Log sources card shows it instead of nothing."""
        self.put('/var/log/ufw.log', '')
        _, sources, _, _ = self.agent.collect_threat_events({}, {}, now=NOW)
        self.assertEqual([(s['kind'], s['state']) for s in sources], [('fw', 'idle')])

    def test_the_server_accepts_what_the_agent_sends(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))
        import threat_evidence as te
        import threat_sensor_handlers as tsh
        self.put('/var/log/ufw.log', '\n'.join(rec(A3, p) for p in (22, 23, 80, 443)) + '\n')
        events, sources, _, _ = self.agent.collect_threat_events({}, {}, now=NOW)
        got = te.normalize_event(events[0], now=NOW)
        self.assertEqual(got['src'], {'fw': 4})
        self.assertEqual(te.classes(got), {'port_scan': 4})
        self.assertEqual(len(tsh._clean_sources(sources)), len(sources))


if __name__ == '__main__':
    unittest.main()

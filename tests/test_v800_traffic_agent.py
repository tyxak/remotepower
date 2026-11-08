#!/usr/bin/env python3
"""8.0.0: the Linux agent's side of the Traffic view -- the connection sample it builds from `ss`.

The parser is read against the layouts the real tool prints (captured on a machine with iproute2 7.3, the addresses replaced by documentation ranges). The sampler is
driven with a stand-in for the `ss` binary only, so its content is in the real layout and the delta, direction and cap rules run on it. One test runs the real `ss` over
real sockets, and one sends what the agent builds through the real heartbeat handler and reads it back from the host's page: the producer's own output is the consumer's input.
"""

import ast
import importlib.machinery
import importlib.util
import os
import shutil
import socket
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-traffic-agent-'))
_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))

from test_heartbeat_key_parity import _declared_not_honoured, _reads  # noqa: E402
from test_v800_traffic import LAN, PUB, PUB2, _Server  # noqa: E402

ROOT = _TESTS.parent
AGENT = ROOT / 'client' / 'remotepower-agent.py'


def load_agent():
    loader = importlib.machinery.SourceFileLoader('rp_agent_traffic', str(AGENT))
    spec = importlib.util.spec_from_loader('rp_agent_traffic', loader)
    mod = importlib.util.module_from_spec(spec)             # type: ignore[arg-type]
    loader.exec_module(mod)
    return mod


# What `ss -H -t -i -n -p state established` printed on a real machine, the addresses replaced: a socket line, then the info line that starts with a tab and a space.
REAL_NOUSER = (
    '0      0                              192.0.2.10:39946             203.0.113.7:443 \n'
    '\t bbr wscale:7,10 rto:224 rtt:23.161/4.128 ato:40 mss:1460 pmtu:1500 rcvmss:1460 advmss:1460 cwnd:26 bytes_sent:15383 bytes_retrans:0 bytes_acked:15384 '
    'bytes_received:7676 segs_out:24 segs_in:15 data_segs_out:16 data_segs_in:9 bbr:(bw:4278032bps,mrtt:21.593) send 13111696bps lastsnd:2105 delivered:17 app_limited busy:101ms\n'
)
REAL_USER = (
    '0      0                              192.0.2.10:36790            198.51.100.20:443  users:(("claude",pid=4633,fd=25))\n'
    '\t cubic wscale:13,10 rto:209 rtt:8.036/5.638 ato:40 mss:1448 pmtu:1500 rcvmss:1448 advmss:1448 cwnd:10 bytes_sent:7901 bytes_acked:7902 bytes_received:26223 '
    'segs_out:70 segs_in:80 data_segs_out:8 data_segs_in:59 send 14415132bps lastsnd:208623 lastrcv:208404 lastack:38314 pacing_rate 28830264bps delivered:9 app_limited busy:78ms\n'
)
REAL_V6 = (
    '0      0      [2001:db8:1::5896]:36782          [2001:db8:2::10]:443  users:(("chrome",pid=4032,fd=54))\n'
    '\t cubic wscale:13,10 rto:227 rtt:26.89/0.623 ato:40 mss:1348 pmtu:1500 rcvmss:1348 advmss:1428 cwnd:10 bytes_sent:6252 bytes_acked:6253 bytes_received:7022 segs_out:215 segs_in:113\n'
)
REAL_HEADER = 'Recv-Q Send-Q                         Local Address:Port              Peer Address:Port Process\n'
# `ss -H -t -l -n` on the same machine
REAL_LISTEN = (
    'LISTEN 0      10         127.0.0.1:50881 0.0.0.0:*\n'
    'LISTEN 0      4096      127.0.0.54:53    0.0.0.0:*\n'
    'LISTEN 0      4096         0.0.0.0:5355  0.0.0.0:*\n'
    'LISTEN 0      4096   127.0.0.53%lo:53    0.0.0.0:*\n'
    'LISTEN 0      50                 *:1716        *:*\n'
    'LISTEN 0      4096            [::]:5355     [::]:*\n'
    'LISTEN 0      128          0.0.0.0:22      0.0.0.0:*\n'
)


def est_text(socks):
    """`ss -H -t -i -n -p state established` for these sockets, in the real layout: (local ip, local port, remote ip, remote port, program, acked, received)."""
    out = []
    for lip, lport, rip, rport, prog, acked, recv in socks:
        loc = '[%s]:%d' % (lip, lport) if ':' in lip else '%s:%d' % (lip, lport)
        rem = '[%s]:%d' % (rip, rport) if ':' in rip else '%s:%d' % (rip, rport)
        users = ' users:(("%s",pid=100,fd=3))' % prog if prog else ''
        out.append('0      0      %-32s %-26s%s\n' % (loc, rem, users))
        info = '\t cubic wscale:7,7 rto:204 mss:1448 pmtu:1500 rcvmss:1448 advmss:1448 cwnd:10'
        if acked is not None:
            info += ' bytes_sent:%d bytes_acked:%d' % (acked, acked)
        if recv is not None:
            info += ' bytes_received:%d' % recv
        out.append(info + ' segs_out:1 segs_in:1\n')
    return ''.join(out)


class TestTheParser(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.agent = load_agent()

    def test_the_real_layouts_are_read_to_the_same_sockets(self):
        body = REAL_NOUSER + REAL_USER + REAL_V6
        bare, _ = self.agent._ss_sockets(body)
        with_header, _ = self.agent._ss_sockets(REAL_HEADER + body)
        with_state, _ = self.agent._ss_sockets(body.replace('0      0 ', 'ESTAB  0      0 '))
        self.assertEqual(bare, with_header, 'a header line is skipped')
        self.assertEqual(bare, with_state, 'a State column is skipped')
        self.assertEqual(bare, [
            ('192.0.2.10', 39946, '203.0.113.7', 443, '', 15384, 7676),
            ('192.0.2.10', 36790, '198.51.100.20', 443, 'claude', 7902, 26223),
            ('2001:db8:1::5896', 36782, '2001:db8:2::10', 443, 'chrome', 6253, 7022),
        ])

    def test_a_socket_without_byte_counts_or_a_program_has_none(self):
        old_kernel = '0      0      192.0.2.10:1000 203.0.113.7:80 \n\t cubic wscale:7,7 rto:204 mss:1448\n'
        self.assertEqual(self.agent._ss_sockets(old_kernel)[0], [('192.0.2.10', 1000, '203.0.113.7', 80, '', None, None)])
        one_line = '0      0      192.0.2.10:1000 203.0.113.7:80 users:(("nc",pid=1,fd=3))\n'
        self.assertEqual(self.agent._ss_sockets(one_line)[0], [('192.0.2.10', 1000, '203.0.113.7', 80, 'nc', None, None)])

    def test_an_address_is_written_short_and_loses_its_interface_and_its_mapping(self):
        f = self.agent._ss_ip_port
        self.assertEqual(f('203.0.113.7:443'), ('203.0.113.7', 443))
        self.assertEqual(f('[2001:0db8:0:0:0:0:0:1]:22'), ('2001:db8::1', 22))
        self.assertEqual(f('[fe80::1%eth0]:22'), ('fe80::1', 22))
        self.assertEqual(f('[::ffff:203.0.113.9]:80'), ('203.0.113.9', 80))
        for bad in ('*:22', '203.0.113.7:*', '203.0.113.7', ':443', '[nope]:1', '', 'x:y:z'):
            self.assertIsNone(f(bad), bad)

    def test_the_first_program_is_kept_and_a_long_name_is_cut(self):
        two = '0      0      192.0.2.10:1 203.0.113.7:80  users:(("sshd",pid=1,fd=3),("sshd",pid=2,fd=3))\n'
        self.assertEqual(self.agent._ss_sockets(two)[0][0][4], 'sshd')
        long_name = '0      0      192.0.2.10:1 203.0.113.7:80  users:(("%s",pid=1,fd=3))\n' % ('x' * 200)
        self.assertEqual(len(self.agent._ss_sockets(long_name)[0][0][4]), 48)

    def test_what_is_not_a_socket_is_skipped_and_a_flood_is_cut_at_the_limit(self):
        junk = 'Netid State\nnonsense\n\n   \n0 0 notanaddress:x 203.0.113.7:80\nESTAB 0 0 192.0.2.10:1 203.0.113.7:80\n\t cubic bytes_acked:5 bytes_received:6\n'
        self.assertEqual(self.agent._ss_sockets(junk)[0], [('192.0.2.10', 1, '203.0.113.7', 80, '', 5, 6)])
        self.assertEqual(self.agent._ss_sockets('')[0], [])
        many = est_text([('192.0.2.10', 2000 + i, '203.0.113.7', 80, '', i, i) for i in range(30)])
        socks, trunc = self.agent._ss_sockets(many, limit=10)
        self.assertEqual((len(socks), trunc), (10, True))
        self.assertEqual(socks[-1][5], 9, 'the last socket kept still has its byte counts')
        self.assertEqual(self.agent._ss_sockets(many, limit=30)[1], False)

    def test_the_listening_ports_come_from_every_address_form(self):
        self.assertEqual(self.agent._ss_listening(REAL_LISTEN), {50881, 53, 5355, 1716, 22})
        self.assertEqual(self.agent._ss_listening(''), set())
        self.assertEqual(self.agent._ss_listening('State Recv-Q Send-Q Local Address:Port Peer Address:Port\nLISTEN x y z:1 q'), set())


class TestTheSettingAndTheCadence(unittest.TestCase):

    def setUp(self):
        self.agent = load_agent()
        self.tool = {'est': '', 'lis': REAL_LISTEN, 'present': True, 'fail': False}
        self.agent._which = lambda prog: '/usr/bin/ss' if prog == 'ss' and self.tool['present'] else None
        self.agent._ss_run = lambda args: None if self.tool['fail'] else (self.tool['lis'] if '-l' in args else self.tool['est'])

    def set(self, socks):
        self.tool['est'] = est_text(socks)

    def test_the_interval_is_held_to_its_range_and_anything_that_is_not_a_number_turns_it_off(self):
        for given, want in ((10, 30), (45, 45), (99999, 3600), (3600, 3600), (30, 30), (0, 0), (-5, 0), (True, 0), ('60', 0), (None, 0), (60.0, 0), ([60], 0), (10 ** 30, 3600)):
            self.agent._set_traffic_every(given)
            self.assertEqual(self.agent._TRAFFIC_EVERY, want, repr(given))

    def test_it_does_nothing_until_the_server_says_how_often(self):
        self.set([('192.0.2.10', 40000, '203.0.113.7', 443, 'curl', 100, 100)])
        self.assertEqual(self.agent._TRAFFIC_EVERY, 0)
        self.assertIsNone(self.agent.traffic_sample(now=1000.0))
        self.assertIsNone(self.agent._TRAFFIC_PREV, 'off means no reading at all, not a baseline')

    def test_the_first_reading_only_sets_the_baseline_and_the_next_one_is_a_sample(self):
        self.agent._set_traffic_every(60)
        self.set([('192.0.2.10', 40000, '203.0.113.7', 443, 'curl', 1000, 5000)])
        self.assertIsNone(self.agent.traffic_sample(now=1000.0))
        self.assertIsNone(self.agent.traffic_sample(now=1030.0), 'not due yet')
        self.assertIsNone(self.agent.traffic_sample(now=1000.0 + 60 * 0.9 - 0.1), 'a tenth early is still early')
        self.set([('192.0.2.10', 40000, '203.0.113.7', 443, 'curl', 7000, 6000)])
        got = self.agent.traffic_sample(now=1000.0 + 60 * 0.9)
        self.assertEqual((got['win'], got['conns'], got['trunc']), (54.0, 1, False))
        self.assertEqual(got['rows'], [{'d': 'out', 'ip': '203.0.113.7', 'port': 443, 'proc': 'curl', 'n': 1, 'tx': 6000, 'rx': 1000}])
        self.assertEqual(got['other'], {'n': 0, 'tx': 0, 'rx': 0, 'rows': 0})
        self.assertNotIn('err', got)

    def test_each_reading_is_measured_from_the_one_before_it_and_not_from_the_start(self):
        self.agent._set_traffic_every(60)
        sock = ('192.0.2.10', 40000, '203.0.113.7', 443, 'curl')
        self.set([sock + (100, 100)])
        self.agent.traffic_sample(now=0.0)
        self.set([sock + (1100, 600)])
        first = self.agent.traffic_sample(now=60.0)
        self.set([sock + (1400, 650)])
        second = self.agent.traffic_sample(now=120.0)
        self.assertEqual((first['rows'][0]['tx'], first['rows'][0]['rx']), (1000, 500))
        self.assertEqual((second['rows'][0]['tx'], second['rows'][0]['rx']), (300, 50))

    def test_a_connection_that_is_new_counts_all_of_its_bytes_and_a_reused_pair_starts_over(self):
        self.agent._set_traffic_every(60)
        old = ('192.0.2.10', 40000, '203.0.113.7', 443, 'curl')
        self.set([old + (900, 900)])
        self.agent.traffic_sample(now=0.0)
        self.set([old + (50, 20), ('192.0.2.10', 40001, '203.0.113.7', 443, 'curl', 70, 30)])
        got = self.agent.traffic_sample(now=60.0)
        row = got['rows'][0]
        self.assertEqual((row['n'], row['tx'], row['rx']), (2, 50 + 70, 20 + 30), 'the count that went down is a new connection, and so is the new socket')

    def test_a_quiet_connection_is_still_a_row_with_a_connection_and_no_bytes(self):
        self.agent._set_traffic_every(60)
        sock = ('192.0.2.10', 40000, '203.0.113.7', 5432, 'psql', 500, 500)
        self.set([sock])
        self.agent.traffic_sample(now=0.0)
        got = self.agent.traffic_sample(now=60.0)
        self.assertEqual(got['rows'], [{'d': 'out', 'ip': '203.0.113.7', 'port': 5432, 'proc': 'psql', 'n': 1, 'tx': 0, 'rx': 0}])
        self.assertEqual(got['conns'], 1)

    def test_a_socket_the_host_listens_on_is_inbound_and_its_row_names_the_local_port(self):
        self.agent._set_traffic_every(60)
        self.set([('192.0.2.10', 22, '198.51.100.9', 51234, 'sshd', 10, 10), ('192.0.2.10', 40000, '203.0.113.7', 22, 'ssh', 10, 10)])
        self.agent.traffic_sample(now=0.0)
        self.set([('192.0.2.10', 22, '198.51.100.9', 51234, 'sshd', 110, 310), ('192.0.2.10', 40000, '203.0.113.7', 22, 'ssh', 20, 30)])
        rows = {(r['d'], r['ip']): r for r in self.agent.traffic_sample(now=60.0)['rows']}
        self.assertEqual((rows[('in', '198.51.100.9')]['port'], rows[('in', '198.51.100.9')]['tx'], rows[('in', '198.51.100.9')]['rx']), (22, 100, 300))
        self.assertEqual((rows[('out', '203.0.113.7')]['port'], rows[('out', '203.0.113.7')]['tx'], rows[('out', '203.0.113.7')]['rx']), (22, 10, 20))

    def test_connections_to_nobody_else_are_left_out(self):
        self.agent._set_traffic_every(60)
        socks = [('127.0.0.1', 40000, '127.0.0.1', 5432, 'psql', 5, 5), ('::1', 40001, '::1', 80, 'curl', 5, 5), ('192.0.2.10', 40002, '192.0.2.10', 8080, 'curl', 5, 5),
                 ('192.0.2.10', 40003, '224.0.0.251', 5353, 'avahi', 5, 5), ('192.0.2.10', 40004, '::ffff:127.0.0.1', 80, 'x', 5, 5), ('192.0.2.10', 40005, '203.0.113.7', 443, 'curl', 5, 5)]
        self.set(socks)
        self.agent.traffic_sample(now=0.0)
        self.set([s[:5] + (50, 50) for s in socks])
        got = self.agent.traffic_sample(now=60.0)
        self.assertEqual([r['ip'] for r in got['rows']], ['203.0.113.7'])
        self.assertEqual(got['conns'], 1, 'the count is of the connections that are somebody else\'s')

    def test_rows_of_one_program_to_one_address_and_port_are_added_together(self):
        self.agent._set_traffic_every(60)
        a = [('192.0.2.10', 40000 + i, '203.0.113.7', 443, 'curl', 10, 10) for i in range(3)] + [('192.0.2.10', 41000, '203.0.113.7', 443, 'wget', 10, 10)]
        self.set(a)
        self.agent.traffic_sample(now=0.0)
        self.set([s[:5] + (110, 210) for s in a])
        rows = {r['proc']: r for r in self.agent.traffic_sample(now=60.0)['rows']}
        self.assertEqual((rows['curl']['n'], rows['curl']['tx'], rows['curl']['rx']), (3, 300, 600))
        self.assertEqual((rows['wget']['n'], rows['wget']['tx']), (1, 100))

    def test_the_busiest_rows_are_sent_and_the_rest_are_added_into_other(self):
        self.agent._set_traffic_every(60)
        a = [('192.0.2.10', 40000 + i, '198.51.100.%d' % (i % 250 + 1), 1000 + i, 'p', 0, 0) for i in range(self.agent.TRAFFIC_ROWS + 25)]
        self.set(a)
        self.agent.traffic_sample(now=0.0)
        self.set([s[:5] + (100 + i, 0) for i, s in enumerate(a)])
        got = self.agent.traffic_sample(now=60.0)
        self.assertEqual(len(got['rows']), self.agent.TRAFFIC_ROWS)
        self.assertEqual(got['other']['rows'], 25)
        self.assertEqual(got['other']['tx'] + sum(r['tx'] for r in got['rows']), sum(100 + i for i in range(len(a))), 'nothing falls out of the total')
        self.assertGreater(min(r['tx'] for r in got['rows']), 100 + 24, 'every row that was kept moved more than every row that was added into other')
        self.assertEqual(got['conns'], len(a))

    def test_a_gap_longer_than_an_hour_is_not_a_window_and_the_sample_starts_over(self):
        self.agent._set_traffic_every(60)
        sock = ('192.0.2.10', 40000, '203.0.113.7', 443, 'curl')
        self.set([sock + (100, 100)])
        self.agent.traffic_sample(now=0.0)
        self.set([sock + (50000, 60000)])
        self.assertIsNone(self.agent.traffic_sample(now=7200.0), 'a suspended host would report two hours as one window')
        self.set([sock + (51000, 60200)])
        got = self.agent.traffic_sample(now=7260.0)
        self.assertEqual((got['rows'][0]['tx'], got['rows'][0]['rx']), (1000, 200), 'the baseline is the reading after the gap, not the one before it')

    def test_switching_it_off_forgets_the_baseline(self):
        self.agent._set_traffic_every(60)
        sock = ('192.0.2.10', 40000, '203.0.113.7', 443, 'curl')
        self.set([sock + (100, 100)])
        self.agent.traffic_sample(now=0.0)
        self.agent._set_traffic_every(0)
        self.assertIsNone(self.agent._TRAFFIC_PREV)
        self.agent._set_traffic_every(60)
        self.set([sock + (5000, 5000)])
        self.assertIsNone(self.agent.traffic_sample(now=600.0), 'a restart after a pause primes again instead of measuring across it')

    def test_a_host_without_ss_says_so_at_once_and_does_not_ask_again_until_it_is_due(self):
        self.agent._set_traffic_every(60)
        self.tool['present'] = False
        got = self.agent.traffic_sample(now=0.0)
        self.assertEqual((got['err'], got['rows'], got['conns'], got['win']), ('no-ss', [], 0, 60))
        self.assertIsNone(self.agent.traffic_sample(now=10.0))

    def test_a_tool_that_fails_is_reported_and_the_reading_after_it_is_a_baseline_not_a_total(self):
        self.agent._set_traffic_every(60)
        sock = ('192.0.2.10', 40000, '203.0.113.7', 443, 'curl')
        self.tool['fail'] = True
        self.assertEqual(self.agent.traffic_sample(now=0.0)['err'], 'ss-failed')
        self.tool['fail'] = False
        self.set([sock + (5000000, 5000000)])
        self.assertIsNone(self.agent.traffic_sample(now=60.0), 'five megabytes of lifetime counters are not one minute of traffic')
        self.set([sock + (5000100, 5000200)])
        got = self.agent.traffic_sample(now=120.0)
        self.assertEqual((got['rows'][0]['tx'], got['rows'][0]['rx']), (100, 200))

    def test_a_kernel_without_byte_counts_still_shows_the_connections_and_says_why(self):
        self.agent._set_traffic_every(60)
        a = [('192.0.2.10', 40000, '203.0.113.7', 443, 'curl', None, None)]
        self.set(a)
        self.agent.traffic_sample(now=0.0)
        got = self.agent.traffic_sample(now=60.0)
        self.assertEqual((got['err'], got['conns'], got['rows'][0]['n'], got['rows'][0]['tx']), ('no-counters', 1, 1, 0))

    def test_a_host_with_no_connections_at_all_is_a_sample_and_not_an_error(self):
        self.agent._set_traffic_every(60)
        self.set([])
        self.agent.traffic_sample(now=0.0)
        got = self.agent.traffic_sample(now=60.0)
        self.assertEqual((got['rows'], got['conns']), ([], 0))
        self.assertNotIn('err', got)

    def test_the_sample_is_what_the_server_asks_of_one(self):
        import traffic as T
        self.agent._set_traffic_every(60)
        a = [('192.0.2.10', 40000, '203.0.113.7', 443, 'curl', 10, 10)]
        self.set(a)
        self.agent.traffic_sample(now=0.0)
        self.set([a[0][:5] + (1010, 2010)])
        raw = self.agent.traffic_sample(now=60.0)
        clean = T.clean_sample(raw, now=1234)
        self.assertEqual(clean['rows'], raw['rows'], 'the server keeps every row the agent sent, unchanged')
        self.assertEqual((clean['tx'], clean['rx'], clean['conns'], clean['win']), (1000, 2000, 1, 60.0))


@unittest.skipUnless(shutil.which('ss') and sys.platform.startswith('linux'), 'needs iproute2 ss on Linux')
class TestTheRealTool(unittest.TestCase):

    def test_the_real_ss_counts_what_two_real_sockets_moved_in_the_right_direction(self):
        agent = load_agent()
        agent._traffic_remote_skipped = lambda remote, local: False      # both ends are on loopback here; the rule has its own test
        agent._set_traffic_every(60)
        srv = socket.socket()
        srv.bind(('127.0.0.1', 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        cli = socket.create_connection(('127.0.0.1', port))
        conn, _ = srv.accept()
        try:
            self.assertIsNone(agent.traffic_sample(now=1000.0), 'the baseline, taken with both sockets open')
            out_bytes, in_bytes = 200_000, 50_000
            cli.sendall(b'x' * out_bytes)
            got = 0
            while got < out_bytes:
                got += len(conn.recv(65536))
            conn.sendall(b'y' * in_bytes)
            got = 0
            while got < in_bytes:
                got += len(cli.recv(65536))
            time.sleep(0.6)                                              # the last ACK may be delayed
            sample = agent.traffic_sample(now=1060.0)
        finally:
            for s in (cli, conn, srv):
                s.close()
        self.assertIsNotNone(sample)
        self.assertNotIn('err', sample, 'this machine\'s kernel reports byte counts')
        mine = {r['d']: r for r in sample['rows'] if r['port'] == port and r['ip'] == '127.0.0.1'}
        self.assertEqual(sorted(mine), ['in', 'out'], 'the connecting end is outbound and the accepting end is inbound, both on the service port')
        comm = Path('/proc/self/comm').read_text().strip()
        self.assertEqual((mine['out']['tx'], mine['out']['rx'], mine['out']['n'], mine['out']['proc']), (out_bytes, in_bytes, 1, comm))
        self.assertEqual((mine['in']['tx'], mine['in']['rx'], mine['in']['n'], mine['in']['proc']), (in_bytes, out_bytes, 1, comm))

    def test_with_the_loopback_rule_on_the_same_two_sockets_are_not_a_remote_host(self):
        agent = load_agent()
        agent._set_traffic_every(60)
        srv = socket.socket()
        srv.bind(('127.0.0.1', 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        cli = socket.create_connection(('127.0.0.1', port))
        conn, _ = srv.accept()
        try:
            agent.traffic_sample(now=0.0)
            cli.sendall(b'x' * 1000)
            conn.recv(2000)
            time.sleep(0.2)
            sample = agent.traffic_sample(now=60.0)
        finally:
            for s in (cli, conn, srv):
                s.close()
        self.assertEqual([r for r in sample['rows'] if r['port'] == port], [])


class TestARealRound(_Server):
    """What the agent builds goes through the real heartbeat handler and comes back from the host's page and the fleet's."""

    def test_what_the_agent_sends_is_what_the_server_shows(self):
        agent = load_agent()
        agent._set_traffic_every(60)
        tool = {}
        agent._which = lambda prog: '/usr/bin/ss' if prog == 'ss' else None
        agent._ss_run = lambda args: REAL_LISTEN if '-l' in args else tool['est']
        socks = [('192.0.2.10', 40000, PUB, 443, 'curl', 100, 100), ('192.0.2.10', 40001, PUB2, 53, 'unbound', 10, 10), ('192.0.2.10', 22, LAN, 51000, 'sshd', 5, 5),
                 ('192.0.2.10', 40002, '2001:db8:9::1', 443, 'curl', 7, 7)]
        tool['est'] = est_text(socks)
        self.assertIsNone(agent.traffic_sample(now=0.0))
        tool['est'] = est_text([s[:5] + (s[5] + 6000 * (i + 1), s[6] + 100 * (i + 1)) for i, s in enumerate(socks)])
        payload = agent.traffic_sample(now=60.0)
        resp = self.beat(traffic=payload)
        self.assertEqual(resp['traffic_every'], 60)
        got = self.host()
        self.assertEqual(got['state'], 'reporting')
        by = {(r['d'], r['ip']): r for r in got['rows']}
        self.assertEqual(sorted(by), sorted([('out', PUB), ('out', PUB2), ('in', LAN), ('out', '2001:db8:9::1')]))
        self.assertEqual((by[('out', PUB)]['tx'], by[('out', PUB)]['rx'], by[('out', PUB)]['service'], by[('out', PUB)]['scope']), (6000, 100, 'https', 'public'))
        self.assertEqual((by[('out', PUB2)]['service'], by[('out', PUB2)]['proc']), ('dns', 'unbound'))
        self.assertEqual((by[('in', LAN)]['port'], by[('in', LAN)]['service'], by[('in', LAN)]['scope']), (22, 'ssh', 'private'))
        self.assertEqual((got['conns'], got['tx'], got['rx']), (4, 6000 + 12000 + 18000 + 24000, 100 + 200 + 300 + 400))
        fleet = self.fleet()
        self.assertEqual((fleet['totals']['hosts'], fleet['totals']['conns']), (1, 4))

    def test_an_agent_that_could_not_read_shows_its_reason_on_the_host(self):
        agent = load_agent()
        agent._set_traffic_every(60)
        agent._which = lambda prog: None
        self.beat(traffic=agent.traffic_sample(now=0.0))
        got = self.host()
        self.assertEqual((got['state'], got['err'], got['rows']), ('error', 'no-ss', []))


class TestWhereTheAgentCallsIt(unittest.TestCase):
    """Structure: the sampler is called from the report loop outside the sysinfo block, the answer is read, and no other agent claims the key."""

    @staticmethod
    def _inside_send_sysinfo(tree, callee):
        parents = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parents[child] = node
        found = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == callee:
                p, inside = node, False
                while p in parents:
                    p = parents[p]
                    if isinstance(p, ast.If) and 'send_sysinfo' in ast.dump(p.test):
                        inside = True
                found.append(inside)
        return found

    def test_the_sampler_runs_on_its_own_cadence_and_not_only_on_the_sysinfo_polls(self):
        tree = ast.parse(AGENT.read_text())
        self.assertEqual(self._inside_send_sysinfo(tree, 'collect_peer_connections'), [True], 'control: the detector sees a collector that IS inside the block')
        self.assertEqual(self._inside_send_sysinfo(tree, 'traffic_sample'), [False], 'sysinfo rides every tenth poll; a sample due every minute would reach the server every ten')

    def test_the_agent_reads_the_key_the_server_sends_and_no_other_agent_does(self):
        src = AGENT.read_text()
        self.assertEqual(src.count("if 'traffic_every' in resp:"), 1)
        self.assertEqual(src.count("_set_traffic_every(resp.get('traffic_every'))"), 1)
        for other in ('remotepower-agent-win.py', 'remotepower-agent-mac.py'):
            path = ROOT / 'client' / other
            self.assertFalse(_reads(path, 'traffic_every'), other + ' samples nothing, so it must not act on the key')
            self.assertIn('traffic_every', _declared_not_honoured(path), other + ' says so, in the list the parity gate reads')
        server = (ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertEqual(server.count("common_resp['traffic_every'] = traffic_handlers_mod.sampling_every()"), 1)

    def test_the_sample_travels_under_the_key_the_server_ingests(self):
        self.assertEqual(AGENT.read_text().count("payload['traffic'] = _traffic"), 1)
        self.assertEqual((ROOT / 'server' / 'cgi-bin' / 'api.py').read_text().count("traffic_handlers_mod.ingest(dev_id, body['traffic'], now)"), 1)

    def test_the_extensionless_agent_is_the_same_file(self):
        self.assertEqual(AGENT.read_bytes(), (ROOT / 'client' / 'remotepower-agent').read_bytes())


if __name__ == '__main__':
    unittest.main()

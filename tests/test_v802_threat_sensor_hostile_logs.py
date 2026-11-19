"""8.0.2: what the sender of a request can make the threat sensor believe, and what can make it fail.

The sensor reads logs that a remote client writes into: the request line, the path, a user name, the body of a POST. A reader is run over
text that someone chose, so the tests here are of two kinds: a hostile line must never stop the sensor of the whole host (a reader that
raises left the log's position where it was, and the next pass read the same bytes and raised again), and a hostile line must never name
the address that is reported (a request that writes a line of the log of its own).

The readers, the pass and the aggregate are the agent's own; only the files are scratch ones.
"""
import ast
import json
import os
import random
import signal
import string
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'server' / 'cgi-bin'))

from test_v720_threat_sensor_agent import (  # noqa: E402
    A1, A2, A3, NOW, _Agent, audit_native, ts_ctime, ts_iso_local, ts_nginx, ts_nginx_err,
)
from test_v720_threat_sensor_cycle import _Host  # noqa: E402

AGENT_SOURCE = (HERE.parent / 'client' / 'remotepower-agent.py').read_text()

_MON = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')
ODD = ['²', '٣', '１', '①', '999999999999999999999999', '-1', '1e9', 'NaN', '', ' ', '\x00', '\x1b[31m', '‮', '%', '%zz', '"', '\\', '\\"', '[', ']',
       '{', '}', 'a' * 5000, '9' * 5000, '::', '1.2.3.4', '8.8.4.4:99999', '[::1]:80', '0.0.0.0', '999.1.1.1', '1.2.3', 'GET', 'POST', '/', '//',
       '\t', '\r', 'HTTP/1.1', 'HTTP/²']


class _Gen:
    """Hostile lines in the shapes the readers expect, with each field replaced by text that is not what the field should hold. Seeded, so a
    failure is the same failure on the next run."""

    def __init__(self, seed):
        self.rnd = random.Random(seed)

    def odd(self):
        r = self.rnd.random()
        if r < .5:
            return self.rnd.choice(ODD)
        if r < .8:
            return ''.join(self.rnd.choice(string.printable) for _ in range(self.rnd.randint(0, 40)))
        return ''.join(chr(self.rnd.randint(1, 0x2fff)) for _ in range(self.rnd.randint(0, 12)))

    def ip(self):
        return self.rnd.choice([A1, '8.8.4.4', self.odd(), '2a0b:f4c0:16c:1::77'])

    def access(self):
        return (f'{self.ip()} - {self.odd()} [{self.rnd.choice([ts_nginx(NOW - 5), self.odd()])}] '
                f'"{self.rnd.choice(["GET", "POST", self.odd()])} {self.odd()} {self.rnd.choice(["HTTP/1.1", self.odd()])}" '
                f'{self.rnd.choice(["404", "403", "200", self.odd(), "429"])} {self.odd()} "{self.odd()}" "{self.odd()}"')

    def nginx_error(self):
        msg = self.rnd.choice(['open() "%s" failed (2: No such file or directory)' % self.odd(),
                               'limiting requests, excess: %s by zone "z"' % self.odd(), 'user "%s" was not found in "/x"' % self.odd(),
                               'access forbidden by rule', 'ModSecurity: Access denied %s [id "%s"]' % (self.odd(), self.odd()),
                               "[lua] crowdsec.lua:850: Allow(): [Crowdsec] denied '%s' with '%s' (by appsec)" % (self.ip(), self.odd())])
        return (f'{ts_nginx_err(NOW - 5)} [{self.rnd.choice(["error", "alert", "crit"])}] 1#1: *{self.odd()} {msg}, client: {self.ip()}, '
                f'server: {self.odd()}, request: "{self.odd()} {self.odd()} HTTP/1.1", host: "{self.odd()}"')

    def apache_error(self):
        return (f'[{time.strftime("%a %b %d %H:%M:%S", time.localtime(NOW - 5))}.123456 {time.localtime(NOW - 5).tm_year}] '
                f'[core:info] [pid 1:tid 2] [client {self.ip()}:{self.odd()}] '
                + self.rnd.choice(['AH00128: File does not exist: %s' % self.odd(), 'AH01630: client denied by server configuration: %s' % self.odd(),
                                   'AH01617: user %s: authentication failure' % self.odd(), 'ModSecurity: Access denied [id "%s"] %s' % (self.odd(), self.odd())]))

    def native(self):
        uid = self.rnd.choice(['c4d8b66b', self.odd()[:8] or 'x1x1x1x1'])
        parts = []
        for p in self.rnd.sample('ABIFEHZ', self.rnd.randint(1, 7)):
            parts.append(f'--{uid}-{p}--')
            if p == 'A':
                parts.append(f'[{self.rnd.choice([ts_nginx(NOW - 5), self.odd()])}] {self.odd()} {self.ip()} {self.odd()} {self.odd()} {self.odd()}')
            elif p == 'B':
                parts += [f'{self.rnd.choice(["GET", self.odd()])} {self.odd()} HTTP/1.1', f'User-Agent: {self.odd()}']
            elif p == 'F':
                parts.append(f'HTTP/1.1 {self.rnd.choice(["403", self.odd()])}')
            elif p == 'H':
                parts += [f'Message: {self.odd()} [id "{self.odd()}"] [tag "{self.odd()}"]',
                          self.rnd.choice(['Action: Intercepted (phase 2)', self.odd()])]
            elif p == 'Z':
                parts.append('')
        return '\n'.join(parts)

    def json_audit(self):
        return json.dumps({'transaction': {
            'client_ip': self.ip(), 'time_stamp': self.rnd.choice([ts_ctime(NOW - 5), self.odd()]), 'unique_id': self.odd(),
            'request': {'method': self.odd(), 'uri': self.odd(), 'headers': {'User-Agent': self.odd()}},
            'response': {'http_code': self.rnd.choice([403, self.odd(), None, [], 10 ** 30])},
            'messages': [{'message': self.odd(), 'details': {'ruleId': self.rnd.choice(['942100', self.odd(), 942100, None]), 'tags': [self.odd()]}}]}})

    def fail2ban(self):
        return (f'{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(NOW - 5))},{self.rnd.choice(["123", self.odd()])} fail2ban.actions        '
                f'[{self.rnd.choice(["1234", self.odd()])}]: NOTICE  [{self.odd()}] {self.rnd.choice(["Ban", "Found", self.odd()])} {self.ip()}')

    def ufw(self):
        return (f'{time.strftime("%b %d %H:%M:%S", time.localtime(NOW - 5))} host kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00 SRC={self.ip()} '
                f'DST=10.0.0.5 LEN=60 PROTO={self.rnd.choice(["TCP", self.odd()])} SPT={self.odd()} DPT={self.rnd.choice(["22", self.odd()])} WINDOW=1')

    def eve(self):
        return json.dumps({'timestamp': self.rnd.choice([time.strftime('%Y-%m-%dT%H:%M:%S.000000+0000'), self.odd()]),
                           'event_type': self.rnd.choice(['alert', self.odd()]), 'src_ip': self.ip(), 'src_port': self.odd(), 'proto': self.odd(),
                           'alert': {'signature': self.odd(), 'category': self.odd()}})

    def fastlog(self):
        return (f'{time.strftime("%m/%d/%Y-%H:%M:%S", time.localtime(NOW - 5))}.123456  [**] [1:2002910:6] {self.odd()} [**] '
                f'[Classification: {self.odd()}] [Priority: 2] {{TCP}} {self.ip()}:{self.odd()} -> 192.0.2.1:22')


def readers(agent, gen):
    """name of the agent's function -> (call it over a list of lines and an aggregate, one hostile line). Derived from the agent below, so a
    reader added later without a row here fails the population test."""
    return {
        '_ts_scan_access': (lambda ls, agg: agent._ts_scan_access(ls, agent._ts_access_parser(None)[1], agg, 'a', NOW), gen.access),
        '_ts_scan_nginx_error': (lambda ls, agg: agent._ts_scan_nginx_error(ls, agg, 'e', NOW), gen.nginx_error),
        '_ts_scan_apache_error': (lambda ls, agg: agent._ts_scan_apache_error(ls, agg, 'e', NOW), gen.apache_error),
        '_ts_scan_modsec_native': (lambda ls, agg: agent._ts_scan_modsec_native('\n'.join(ls).split('\n'), agg, 'm', NOW), gen.native),
        '_ts_scan_modsec_json': (lambda ls, agg: agent._ts_scan_modsec_json(ls, agg, 'm', NOW), gen.json_audit),
        '_ts_scan_f2b': (lambda ls, agg: agent._ts_scan_f2b(ls, agg, 'f', NOW), gen.fail2ban),
        '_ts_scan_firewall': (lambda ls, agg: agent._ts_scan_firewall(ls, agg, 'u', NOW), gen.ufw),
        '_ts_scan_eve': (lambda ls, agg: agent._ts_scan_eve(ls, agg, 'x.json', NOW), gen.eve),
        '_ts_scan_fastlog': (lambda ls, agg: agent._ts_scan_fastlog(ls, agg, 'x.log', NOW), gen.fastlog),
    }


# ── F10: one line must not stop the sensor of the host ──────────────────────────────────────────────────────────────────────────────────

class TestOneLineDoesNotStopTheSensor(_Agent):
    def test_the_battery_covers_every_reader_of_the_agent(self):
        found = {n for n in dir(self.agent) if n.startswith('_ts_scan_') and callable(getattr(self.agent, n))}
        found.discard('_ts_scan_cscli')           # asks the local CrowdSec for JSON and takes no lines of a log
        rows = readers(self.agent, _Gen(1))
        self.assertEqual(found, set(rows), 'a reader with no row here has never been shown a hostile line')
        self.assertEqual(len(rows), 9)

    def test_no_reader_raises_on_a_hostile_line(self):
        for name in sorted(readers(self.agent, _Gen(0))):
            gen = _Gen(80212)
            scan, make = readers(self.agent, gen)[name]
            raised, lines_read = {}, 0
            for _ in range(150):
                lines = [make() for _ in range(gen.rnd.choice([1, 5, 30]))]
                agg = self.agent._TsAgg(NOW)
                agg.want_samples = True
                lines_read += len(lines)
                try:
                    scan(lines, agg)
                    agg.events()
                except Exception as e:
                    raised[f'{type(e).__name__}: {str(e)[:60]}'] = raised.get(f'{type(e).__name__}: {str(e)[:60]}', 0) + 1
            self.assertEqual(raised, {}, f'{name} raised on a hostile line')
            self.assertGreater(lines_read, 400, name)

    def test_a_status_that_is_not_ascii_digits_in_the_audit_log(self):
        for status in ('²', '²²²', '٤٠٣', '４０３', '9' * 5000, '4' * 4):
            text = audit_native(NOW - 20, A1, 'c4d8b66b').replace('HTTP/1.1 403', f'HTTP/1.1 {status}')
            agg = self.agent._TsAgg(NOW)
            n, parsed = self.agent._ts_scan_modsec_native(text.split('\n'), agg, '/var/log/modsec_audit.log', NOW)
            self.assertEqual((n, parsed), (1, 1), status[:8])
            ev, _ = agg.events()
            self.assertEqual([e['ip'] for e in ev], [A1], 'the entry is still read; only the status that is not a number is not used')
        agg = self.agent._TsAgg(NOW)
        agg.want_samples = True
        self.agent._ts_scan_modsec_native(audit_native(NOW - 20, A1, 'c4d8b66b', status=404).split('\n'), agg, 'm', NOW)
        self.assertEqual([s['c'] for s in agg.samples[A1]], [404], 'control: a status of three ASCII digits is read as it was')

    def test_a_port_that_is_not_ascii_digits_in_a_firewall_line(self):
        def line(i, dpt):
            return (f'{time.strftime("%b %d %H:%M:%S", time.localtime(NOW - 20 + i))} host kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00 SRC={A2} '
                    f'DST=10.0.0.5 LEN=60 PROTO=TCP SPT=4000 DPT={dpt} WINDOW=1')
        for dpt in ('²', '٤٤٣', '９９', '9' * 5000, '4' * 6):
            agg = self.agent._TsAgg(NOW)
            lines = [line(i, '22') for i in range(16)] + [line(20, dpt)]
            n, parsed = self.agent._ts_scan_firewall(lines, agg, '/var/log/ufw.log', NOW)
            self.assertEqual(n, 17, dpt[:8])
            ev, _ = agg.events()
            self.assertEqual([e['ip'] for e in ev], [A2], 'sixteen refusals of port 22 are a scan, with or without the odd one')
        agg = self.agent._TsAgg(NOW)
        self.agent._ts_scan_firewall([line(i, str(20 + i)) for i in range(4)], agg, '/var/log/ufw.log', NOW)
        self.assertEqual([e['ip'] for e in agg.events()[0]], [A2], 'control: four different real ports are a scan')

    def test_every_isdigit_of_the_sensor_is_an_ascii_check(self):
        """The population is the agent's own: each `_ts_*` function that calls `.isdigit()` and converts a number also calls `.isascii()` (the
        8.0.0 scan matched one expression with another and so missed `f.get('DPT', '').isdigit()` followed by `int(f['DPT'])`)."""
        tree = ast.parse(AGENT_SOURCE)
        uses, bare = 0, []
        for fn in ast.walk(tree):
            if isinstance(fn, ast.FunctionDef) and fn.name.startswith('_ts_'):
                calls = [c for c in ast.walk(fn) if isinstance(c, ast.Call)]
                methods = [c for c in calls if isinstance(c.func, ast.Attribute)]
                digits = [c for c in methods if c.func.attr in ('isdigit', 'isnumeric', 'isdecimal')]
                converts = any(isinstance(c.func, ast.Name) and c.func.id in ('int', 'float') for c in calls)
                if digits and converts:
                    uses += len(digits)
                    if not any(c.func.attr == 'isascii' for c in methods):
                        bare.append(fn.name)
        self.assertGreaterEqual(uses, 3, 'control: the sensor has sites to look at (the audit log, the firewall log, the JSON audit rule id)')
        self.assertEqual(bare, [])


class _Hung(BaseException):
    """Not an Exception, so the guard under test cannot swallow it."""


class _Bounded:
    """A test that would otherwise wait forever fails after 20 seconds: a guard that loops on the line that made a reader raise is the
    regression this module is about, and it must show as a failure and not as a gate that never ends."""

    def setUp(self):
        super().setUp()

        def hung(signum, frame):
            raise _Hung('the test did not end in 20 seconds')
        self._old_alarm = signal.signal(signal.SIGALRM, hung)
        signal.alarm(20)
        self.addCleanup(signal.signal, signal.SIGALRM, self._old_alarm)
        self.addCleanup(signal.alarm, 0)


class TestAReaderThatRaisesCostsOneLine(_Bounded, _Agent):
    def test_the_feed_moves_past_a_line_when_it_hands_it_out(self):
        feed = self.agent._TsLines(['a', 'b', 'c'])
        it = iter(feed)
        self.assertEqual((next(it), feed.i), ('a', 1))
        self.assertEqual((next(it), feed.i), ('b', 2))
        self.assertEqual(list(iter(feed)), ['c'], 'a reader started again gets what follows the line it stopped at')

    def test_the_line_is_left_out_and_the_reader_goes_on(self):
        a = self.agent
        seen = []

        def scan(lines, path):
            n = 0
            for line in lines:
                if line == 'POISON':
                    raise ValueError('a line the reader did not expect')
                seen.append(line)
                n += 1
            return n, n, 'x'

        lines = ['a', 'b', 'POISON', 'c', 'd', 'POISON', 'e']
        n, parsed, fmt = a._ts_guarded(scan, lines, '/var/log/x.log')
        self.assertEqual(seen, ['a', 'b', 'c', 'd', 'e'], 'the two lines that made the reader raise are the only ones left out')
        self.assertEqual((n, parsed, fmt), (3, 1, 'x'), 'a reader that raised loses what it had counted; each refused line counts as one read')

    def test_a_reader_that_raises_on_every_line_ends(self):
        def scan(lines, path):
            for _ in lines:
                raise RuntimeError('every line')
            return 0, 0, ''

        n, parsed, fmt = self.agent._ts_guarded(scan, ['x'] * 5000, '/var/log/x.log')
        self.assertEqual(parsed, 0)
        self.assertLessEqual(n, self.agent.THREAT_BAD_LINES, 'it gave up after a bounded number of refusals instead of walking 5,000 lines')

    def test_a_reader_that_does_not_raise_is_not_touched(self):
        n, parsed, fmt = self.agent._ts_guarded(lambda lines, path: (sum(1 for _ in lines), 1, 'combined'), ['a', '', 'b'], 'p')
        self.assertEqual((n, parsed, fmt), (3, 1, 'combined'))


class TestThePositionMovesOnWhenAReaderRaised(_Bounded, _Host):
    """A whole pass over files: the reader that raises on one line costs that line, the other logs and the other addresses are sent, and the
    next pass does not read the same bytes again."""

    def setUp(self):
        super().setUp()
        t = ts_iso_local
        self.put('/etc/fail2ban/fail2ban.conf', '[Definition]\nloglevel = INFO\nlogtarget = /var/log/fail2ban.log\n')
        self.put('/var/log/fail2ban.log', ''.join([
            f'{t(NOW - 50)} fail2ban.actions        [1]: NOTICE  [sshd] Ban {A1}\n',
            f'{t(NOW - 49)} fail2ban.actions        [1]: NOTICE  [sshd] Ban 203.0.113.250 POISON\n',
            f'{t(NOW - 48)} fail2ban.actions        [1]: NOTICE  [nginx-botsearch] Ban {A2}\n']))
        self.cfg = {'enabled': True, 'paths': []}

    def reader_that_raises_on_poison(self):
        real = self.agent._ts_scan_f2b

        def scan(lines, agg, fkey, now):
            return real((ln for ln in lines if self._check(ln)), agg, fkey, now)
        return scan

    @staticmethod
    def _check(line):
        if 'POISON' in line:
            raise ValueError('a line the reader did not expect')
        return True

    def test_the_rest_of_the_log_is_read_and_the_next_pass_starts_after_it(self):
        with mock.patch.object(self.agent, '_ts_scan_f2b', self.reader_that_raises_on_poison()):
            events, sources, dropped, state = self.agent.collect_threat_events(self.cfg, {}, NOW)
            self.assertEqual(sorted(e['ip'] for e in events), sorted([A1, A2]), 'the two lines either side of the one that raised')
            row = [s for s in sources if s['kind'] == 'f2b'][0]
            self.assertEqual(row['state'], 'ok')
            size = os.path.getsize(self.tmp / 'var/log/fail2ban.log')
            self.assertEqual(state['files']['/var/log/fail2ban.log']['pos'], size, 'the position moved to the end of what was read')
            again = self.agent.collect_threat_events(self.cfg, state, NOW + 60)
            self.assertEqual(again[0], [], 'the same bytes are not read again')

    def test_a_pass_whose_reader_gives_up_still_finishes_with_the_position_moved(self):
        def scan(lines, agg, fkey, now):
            for line in lines:
                self._check(line)
            return 0, 0
        with mock.patch.object(self.agent, '_ts_scan_f2b', scan):
            events, sources, dropped, state = self.agent.collect_threat_events(self.cfg, {}, NOW)     # before the guard this raised
            self.assertEqual(state['files']['/var/log/fail2ban.log']['pos'], os.path.getsize(self.tmp / 'var/log/fail2ban.log'))



# ── F7: the body of a request writes into the audit log ─────────────────────────────────────────────────────────────────────────────────

VICTIM = '8.8.4.4'


def stamp(e):
    t = time.gmtime(e)
    return f'[{t.tm_mday:02d}/{_MON[t.tm_mon - 1]}/{t.tm_year}:{t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d} +0000]'


def forged_transaction(ip, uid='deadbeef', status='403'):
    """What a sender writes into the body of a POST: one complete transaction of somebody else, refused by the WAF."""
    return (f'--{uid}-A--\n{stamp(NOW - 5)} {uid}.1 {ip} 54321 192.0.2.10 443\n'
            f'--{uid}-B--\nGET /index.php HTTP/1.1\nUser-Agent: Mozilla/5.0\n\n'
            f'--{uid}-F--\nHTTP/1.1 {status}\n\n'
            f'--{uid}-H--\nMessage: Access denied with code 403 (phase 2). [id "949110"] [tag "attack-sqli"]\nAction: Intercepted (phase 2)\n\n'
            f'--{uid}-Z--\n')


def real_transaction(ip, body, uid='c4d8b66b', end=True):
    """The log's own entry for a POST, with the request body in part I as ModSecurity writes it (`SecAuditLogParts ABIJDEFHZ`)."""
    return (f'--{uid}-A--\n{stamp(NOW - 5)} {uid}.1 {ip} 54321 192.0.2.10 443\n'
            f'--{uid}-B--\nPOST /login HTTP/1.1\nHost: example.com\nUser-Agent: curl/8.5\nContent-Type: text/plain\n\n'
            f'--{uid}-I--\n{body}\n'
            f'--{uid}-F--\nHTTP/1.1 403\nContent-Length: 146\n\n'
            f'--{uid}-H--\nMessage: Access denied with code 403 (phase 2). [id "949110"] [tag "attack-sqli"]\nAction: Intercepted (phase 2)\n\n'
            + (f'--{uid}-Z--\n\n' if end else ''))


class TestABodyCannotWriteATransaction(_Agent):
    def read(self, text, samples=False):
        agg = self.agent._TsAgg(NOW)
        agg.want_samples = samples
        n, parsed = self.agent._ts_scan_modsec_native(text.split('\n'), agg, '/var/log/modsec_audit.log', NOW)
        return n, parsed, {e['ip']: e for e in agg.events()[0]}, agg

    def test_control_an_honest_blocked_post_is_the_senders(self):
        n, parsed, ev, _ = self.read(real_transaction(A1, "username=admin&password=x' OR '1'='1"))
        self.assertEqual((n, parsed, sorted(ev)), (1, 1, [A1]))
        self.assertEqual(ev[A1]['src'], {'waf': 1})

    def test_a_transaction_written_into_the_body_is_not_read(self):
        n, parsed, ev, _ = self.read(real_transaction(A1, forged_transaction(VICTIM)))
        self.assertEqual(sorted(ev), [A1], 'the address the body names is not an address of this host\'s log')
        self.assertEqual((n, parsed), (1, 1), 'one entry')
        self.assertEqual(ev[A1]['src'], {'waf': 1}, 'the sender is still the sender of what the log recorded')
        self.assertIn('crs:949110', ev[A1]['tok']['waf'], 'read from the part H of the real entry')

    def test_the_forged_part_h_adds_nothing_to_the_sender_either(self):
        """A body that writes only a part H after its own marker: its message is a line of the body, not a rule that matched."""
        body = '--deadbeef-H--\nMessage: Access denied [id "942100"] [tag "attack-xss"] CVE-2021-44228\nAction: Intercepted (phase 2)\n'
        text = real_transaction(A1, body).replace('Message: Access denied with code 403 (phase 2). [id "949110"] [tag "attack-sqli"]', 'Message: Warning. [id "930100"]')
        _, _, ev, _ = self.read(text)
        self.assertEqual(sorted(t for t in ev[A1]['tok']['waf'] if t.startswith('crs')), ['crs:930100'], 'only the rule of the real part H')
        self.assertEqual(ev[A1]['cve'], [])

    def test_a_marker_with_another_id_does_not_end_the_entry(self):
        body = '--deadbeef-Z--\n--deadbeef-A--\n' + stamp(NOW - 5) + f' deadbeef.1 {VICTIM} 1 2.2.2.2 443\n--deadbeef-Z--\n'
        _, _, ev, _ = self.read(real_transaction(A1, body) + real_transaction(A2, 'honest', uid='f00dcafe'))
        self.assertEqual(sorted(ev), sorted([A1, A2]), 'the real entry went on to its own end, and the one after it is read')
        self.assertEqual(ev[A1]['src'], {'waf': 1})

    def test_the_markers_of_the_real_entry_are_still_read_when_the_body_holds_lookalikes(self):
        body = '\n'.join(f'--{i:08x}-{part}--' for i, part in enumerate('ABFHZ', 1)) + '\n'
        _, _, ev, _ = self.read(real_transaction(A3, body), samples=True)
        self.assertEqual(sorted(ev), [A3])
        self.assertEqual(ev[A3]['smp'][0]['m'], 'POST', 'the request line is the one of the real part B')

    def test_an_entry_that_never_ended_does_not_swallow_the_next_one(self):
        """A write cut short leaves an entry with no end. The next A is then the start of the next entry (the open one has no end in this
        read), where a forged A inside a body that does end is a line of that body."""
        torn = real_transaction(A1, 'x', end=False)
        n, parsed, ev, _ = self.read(torn + real_transaction(A2, 'honest', uid='f00dcafe'))
        self.assertEqual(sorted(ev), [A2], 'the cut-short entry has no end and is not counted; the one after it is')
        self.assertEqual((n, parsed), (2, 1))

    def test_a_read_that_starts_inside_an_entry_waits_for_its_end(self):
        """The first read of a long log, or an entry larger than a read, starts in the middle of an entry. An A in what is left of it is
        not believed: the entry's own end comes first."""
        whole = real_transaction(A1, forged_transaction(VICTIM))
        middle = whole[whole.index('--c4d8b66b-I--'):]               # what is left after the first half of the entry was read
        n, parsed, ev, _ = self.read(middle + real_transaction(A2, 'honest', uid='f00dcafe'))
        self.assertEqual(sorted(ev), [A2], 'neither the forged entry nor the half of the real one: the entry that follows is read')
        self.assertEqual(n, 1)

    def test_a_read_that_starts_at_an_entry_reads_it(self):
        n, parsed, ev, _ = self.read('\n\n' + real_transaction(A1, 'x'))
        self.assertEqual((n, parsed, sorted(ev)), (1, 1, [A1]), 'blank lines before the first marker do not make the read look like the middle of an entry')

    def test_a_line_that_makes_the_reader_raise_costs_that_line(self):
        agg = self.agent._TsAgg(NOW)
        calls = {'n': 0}
        real = self.agent._ts_time_local

        def raising(text):
            calls['n'] += 1
            if calls['n'] == 1:
                raise ValueError('a time the reader did not expect')
            return real(text)
        with mock.patch.object(self.agent, '_ts_time_local', raising):
            n, parsed = self.agent._ts_scan_modsec_native((real_transaction(A1, 'x') + real_transaction(A2, 'y', uid='f00dcafe')).split('\n'),
                                                         agg, 'm', NOW)
        self.assertEqual(n, 2)
        self.assertEqual([e['ip'] for e in agg.events()[0]], [A2], 'the entry whose A line raised has no client and is not an event; the next is')


class TestAForgedBodyInAWholePass(_Host):
    def test_the_sensor_reports_what_the_log_recorded(self):
        """A log file with the forged body, read by the real pass: the addresses sent are the ones of the real entries."""
        self.put('/var/log/modsec_audit.log', real_transaction(A1, forged_transaction(VICTIM)) + real_transaction(A2, 'honest', uid='f00dcafe'))
        events, sources, dropped, state = self.agent.collect_threat_events({'enabled': True, 'paths': ['/var/log/modsec_audit.log']}, {}, NOW)
        self.assertEqual(sorted(e['ip'] for e in events), sorted([A1, A2]))
        row = [s for s in sources if s['kind'] == 'waf'][0]
        self.assertEqual((row['state'], row['fmt'], row['events']), ('ok', 'native', 2))
        self.assertNotIn(VICTIM, json.dumps(events))


if __name__ == '__main__':
    unittest.main()

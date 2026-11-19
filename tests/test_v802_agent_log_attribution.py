"""The Linux agent's log sensor names the host that sent a request, never one that the text of a request names (8.0.2).

Every log the sensor reads holds two kinds of text: what the web server or the firewall wrote about the connection (the address of the peer) and what the visitor
wrote into the request (the path, the arguments, the user name, the headers, the body). The sensor counts an address, and the server reports it to AbuseIPDB and
SniffCat under the operator's keys, so an address read from the second kind of text is a third party named as an attacker.

nginx wrote the address AFTER its message, and the message copies the decoded request path (`open() "..." failed`), the argument a ModSecurity rule matched and the
user name of a login attempt. The reader took the first `, client: <address>,` of the line, which is the visitor's whenever the visitor wrote one into the message.
It now reads the address only from a line that names its client once and whole (a visitor can add a second, never remove the real one, except by writing so much
that nginx's cut of the line takes the real one away), and a CrowdSec sentence only when the address it quotes is the client's.

The last class here derives its population from the agent (every `_ts_scan_*` reader) and asks the same question of each: could text the visitor wrote make the
reader credit another address? A reader nobody has asked about fails the build.
"""
import json
import random
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from test_v720_threat_sensor_agent import A1, NOW, combined, load_agent, ngx_modsec, ts_apache_err, ts_ctime, ts_nginx_err  # noqa: E402
from test_v730_firewall_log import rec as fw_rec  # noqa: E402
from test_v800_agent_suricata import eve_alert  # noqa: E402

REAL = A1                  # the visitor: the address nginx writes after its message
VICTIM = '8.8.4.4'         # a public address that is nobody the visitor controls
SITE = 'shop.example.test'
ERRLOG = '/var/log/nginx/error.log'
DOCROOT = '/usr/share/nginx/html'
NOT_FOUND = '(2: No such file or directory)'
BOUNCER = "[Crowdsec] denied '%s' with 'ban' (by appsec)"


def nginx_line(msg, req='GET /x', client=REAL, e=NOW - 5, level='error', tail=''):
    """One line as nginx writes it: time, level, pid#tid, *connection, the message, then `, client:`, `, server:`, the raw request line and the Host."""
    return (f'{ts_nginx_err(e)} [{level}] 1#1: *7 {msg}, client: {client}, server: {SITE}, request: "{req} HTTP/1.1", host: "{SITE}"{tail}')


def probe_msg(path):
    return f'open() "{DOCROOT}{path}" failed {NOT_FOUND}'


class _Agent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.agent = load_agent('agent_attribution')

    def setUp(self):
        # what each line means is the subject here; the three-hit minimum of a plain address has its own tests
        self.addCleanup(setattr, self.agent, 'THREAT_MIN_HITS', self.agent.THREAT_MIN_HITS)
        self.agent.THREAT_MIN_HITS = 1


class _NginxBase(_Agent):
    def credited(self, lines, now=NOW):
        agg = self.agent._TsAgg(now)
        agg.want_samples = True
        self.agent._ts_scan_nginx_error(lines, agg, ERRLOG, now)
        events, _ = agg.events()
        return {e['ip']: e for e in events}


# ── the nginx error log ───────────────────────────────────────────────────────

class TestNginxNamesItsClientOnce(_NginxBase):
    def test_an_honest_probe_is_credited_to_the_visitor(self):
        # the control of every test below: the instrument sees a real event, so an empty answer is the rule and not a blind reader
        got = self.credited([nginx_line(probe_msg('/.env'), 'GET /.env')])
        self.assertEqual(sorted(got), [REAL])
        self.assertEqual(got[REAL]['tok'], {'err': {'req:config': 1}})

    def test_a_client_field_written_into_the_path_credits_nobody(self):
        # `GET /.env/x%2C%20client%3A%208.8.4.4%2C`: nginx decodes it into the message in front of its own `, client:`
        path = '/.env/x, client: %s,' % VICTIM
        lines = [nginx_line(probe_msg(path), 'GET /.env/x%2C%20client:%20' + VICTIM + '%2C')] * 3
        self.assertEqual(self.credited(lines), {})

    def test_the_crowdsec_sentence_and_a_client_field_in_the_path_credit_nobody(self):
        path = "/.env/" + BOUNCER % VICTIM + ", client: %s," % VICTIM
        got = self.credited([nginx_line(probe_msg(path), 'GET /.env/x')])
        self.assertEqual(got, {})
        self.assertNotIn(VICTIM, json.dumps(got))

    def test_a_client_field_in_the_argument_a_modsecurity_rule_matched_credits_nobody(self):
        arg = "1' or 1=1-- , client: %s," % VICTIM
        line = (f'{ts_nginx_err(NOW - 5)} [warn] 1234#1234: *5678 ModSecurity: Access denied with code 403 (phase 2). Matched "Operator `Ge\' with parameter `5\' '
                f'against variable `TX:BLOCKING_INBOUND_ANOMALY_SCORE\' (Value: `5\' ) [file "/etc/nginx/modsec/rules/REQUEST-949.conf"] [line "80"] [id "949110"] '
                f'[msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [data "Matched Data: {arg} found within ARGS:id: {arg}"] [severity "2"] '
                f'[tag "attack-sqli"] [hostname "{SITE}"] [uri "/index.php"] [unique_id "1790000001.1"] [ref ""], client: {REAL}, server: {SITE}, '
                f'request: "GET /index.php?id=1 HTTP/1.1", host: "{SITE}"')
        self.assertEqual(self.credited([line]), {})

    def test_a_modsecurity_refusal_without_a_forgery_is_credited_to_the_visitor(self):
        # the control of the test above, from the repository's own builder of the connector's line
        got = self.credited([ngx_modsec(NOW - 5, REAL, '1790000001.1', 942100, 'attack-sqli', 'SQL Injection Attack Detected via libinjection', denied=True)])
        self.assertEqual(sorted(got), [REAL])
        self.assertEqual(got[REAL]['src'], {'waf': 1})

    def test_a_client_field_in_a_user_name_credits_nobody(self):
        # the name of a failed login is the base64 text of an Authorization header, decoded into the message
        name = 'bob" , client: %s, "' % VICTIM
        got = self.credited([nginx_line('user "%s" was not found in "/etc/nginx/.htpasswd"' % name, 'GET /admin/')])
        self.assertEqual(got, {})

    def test_a_failed_login_without_a_forgery_is_credited_to_the_visitor(self):
        got = self.credited([nginx_line('user "bob" was not found in "/etc/nginx/.htpasswd"', 'GET /admin/')])
        self.assertEqual(got[REAL]['tok'], {'err': {'req:login': 1}})

    def test_a_second_client_field_after_the_real_one_credits_nobody_either(self):
        # the Referer is written after the request and is the visitor's whole: the line names two clients, so it is read for nobody
        tail = ', referrer: "https://x.example/, client: %s, server: s"' % VICTIM
        got = self.credited([nginx_line(probe_msg('/.env'), 'GET /.env', tail=tail)])
        self.assertEqual(got, {})

    def test_the_address_the_bouncer_quotes_is_the_one_nginx_names(self):
        # honest: the bouncer was handed $remote_addr and nginx writes the same text after the message
        ok = (f"{ts_nginx_err(NOW - 5)} [alert] 1122606#0: *30321 [lua] crowdsec.lua:850: Allow(): {BOUNCER % REAL}, client: {REAL}, server: {SITE}, "
              f'request: "GET /x HTTP/2.0", host: "{SITE}"')
        self.assertEqual(self.credited([ok])[REAL]['tok'], {'waf': {'cs:appsec': 1}})
        # a sentence that quotes another address than the client's is somebody's text in the message
        other = ok.replace(BOUNCER % REAL, BOUNCER % VICTIM)
        got = self.credited([other])
        self.assertNotIn(VICTIM, got)
        self.assertNotIn('waf', got.get(REAL, {}).get('src', {}), 'and it does not make the visitor look as if AppSec had banned him')

    def test_the_request_is_read_from_after_the_client_not_from_the_message(self):
        # a `, request: "..."` written into the message (the name of a failed login is the visitor's) must not become the request the sample shows
        name = 'x, request: "GET /.git/config HTTP/1.1"'
        got = self.credited([nginx_line('user "%s" was not found in "/etc/nginx/.htpasswd"' % name, 'GET /admin/')])
        self.assertEqual([(s['m'], s['p']) for s in got[REAL]['smp']], [('GET', '/admin/')])

    def test_ipv6_clients_are_read_the_same_way(self):
        got = self.credited([nginx_line(probe_msg('/.env'), 'GET /.env', client='2a0b:f4c0:16c:1::77')])
        self.assertEqual(sorted(got), ['2a0b:f4c0:16c:1::77'])
        bad = nginx_line(probe_msg('/.env/x, client: %s,' % VICTIM), 'GET /.env/x', client='2a0b:f4c0:16c:1::77')
        self.assertEqual(self.credited([bad]), {})


class TestALineNginxCutIsNotRead(_NginxBase):
    """nginx writes at most 2,047 bytes of a line and writes the client field last, so a long enough message takes the real field off the end and leaves
    whatever the visitor wrote as the only one."""

    KINDS = ('waf', 'login')

    def forged_cut_line(self, filler='A', kind='waf'):
        """A message the visitor made as long as nginx writes: the words of a verdict and his own client field near the front, filler, and the end of nginx's message,
        and no room left for the real field. The filler may be a character of several bytes; the line is made exactly as long in bytes as nginx's limit.

        `waf` is an `open() "..." failed` whose decoded path says what a ModSecurity refusal says (the reader looks for those words anywhere in the line), `login` a
        failed login whose user name is the visitor's."""
        marker = ', client: %s, server: %s' % (VICTIM, SITE)
        if kind == 'waf':
            head = f'{ts_nginx_err(NOW - 5)} [error] 1#1: *7 open() "{DOCROOT}/x ModSecurity: Access denied with code 403 (phase 2). [id "949110"]{marker}'
            tail = f'" failed {NOT_FOUND}'
        else:
            head = f'{ts_nginx_err(NOW - 5)} [error] 1#1: *7 user "x{marker}'
            tail = '" was not found in "/etc/nginx/.htpasswd"'
        pad = self.agent._TS_NGX_LINE_CAP - len((head + tail).encode())
        whole, rest = divmod(pad, len(filler.encode()))
        return head + filler * whole + 'A' * rest + tail

    def test_the_forged_line_is_cut_where_nginx_would_cut_it_and_has_no_real_field(self):
        for kind in self.KINDS:
            with self.subTest(kind=kind):
                line = self.forged_cut_line(kind=kind)
                self.assertEqual(len(line.encode()), self.agent._TS_NGX_LINE_CAP)
                self.assertEqual(line.count(', client: '), 1, 'the real field is gone: the one left is the visitor\'s')

    def test_it_credits_nobody(self):
        for kind in self.KINDS:
            with self.subTest(kind=kind):
                self.assertEqual(self.credited([self.forged_cut_line(kind=kind)] * 3), {})

    def test_it_credits_nobody_when_the_filler_is_made_of_characters_of_several_bytes(self):
        # the cut is of bytes: the same line is shorter in characters, and still at the limit
        for kind in self.KINDS:
            with self.subTest(kind=kind):
                line = self.forged_cut_line('€', kind)
                self.assertEqual(len(line.encode()), self.agent._TS_NGX_LINE_CAP)
                self.assertLess(len(line), self.agent._TS_NGX_LINE_CAP - 500)
                self.assertEqual(self.credited([line] * 3), {})

    def test_without_the_cut_the_same_text_is_a_well_formed_line_the_reader_credits(self):
        # the control of the tests above: they are empty because of the line's length and for no other reason (an earlier version of this class passed with the
        # rule taken out, because the forged `open()` path was over the 300 characters the file pattern reads, and credited nobody on its own)
        for kind in self.KINDS:
            with self.subTest(kind=kind):
                line = self.forged_cut_line(kind=kind)
                shorter = line.replace('AAAA', '', 1)           # four bytes of filler fewer: under the limit, and still one client field
                self.assertLess(len(shorter.encode()), self.agent._TS_NGX_LINE_CAP)
                self.assertIn(VICTIM, self.credited([shorter]))

    def test_a_line_just_under_the_limit_with_its_real_field_is_credited(self):
        msg = f'open() "{DOCROOT}/.env" failed {NOT_FOUND}'
        short = nginx_line(msg, 'GET /.env')
        pad = self.agent._TS_NGX_LINE_CAP - 1 - len(short.encode())
        long_line = nginx_line(msg, 'GET /.env', tail=', referrer: "' + 'r' * (pad - 15) + '"')
        self.assertLess(len(long_line.encode()), self.agent._TS_NGX_LINE_CAP)
        self.assertEqual(sorted(self.credited([long_line])), [REAL])


class TestTheNginxReaderUnderRandomText(_NginxBase):
    """Whatever text lands in the message, the forged address is never credited, and the instrument does see a probe that carries no forgery."""

    FRAGMENTS = [', client: %s,' % VICTIM, ', client: %s, server: s' % VICTIM, BOUNCER % VICTIM, 'ModSecurity: Access denied with code 403 (phase 2).',
                 'limiting requests, excess: 5.100 by zone "perip"', 'user "x" was not found in "/e"', 'access forbidden by rule', '[id "949110"]',
                 '/.env', '/wp-login.php', ', request: "GET /x"', 'a', ' ', '/', '"', '%s' % VICTIM, 'client: %s' % VICTIM, ', client:' + VICTIM]
    KINDS = [
        'open() "{root}{f}" failed {nf}',
        'ModSecurity: Access denied with code 403 (phase 2). [id "949110"] [data "{f}"] [uri "/x"] [unique_id "1790000001.1"] [ref ""]',
        'user "{f}" was not found in "/etc/nginx/.htpasswd"',
        '[lua] crowdsec.lua:850: Allow(): {f}',
        'limiting requests, excess: 1.000 by zone "{f}"',
        'access forbidden by rule {f}',
    ]

    def test_a_random_message_never_credits_the_forged_address(self):
        rnd = random.Random(8021)
        seen_visitor = 0
        for i in range(3000):
            frag = ''.join(rnd.choice(self.FRAGMENTS) for _ in range(rnd.randint(1, 6)))
            msg = rnd.choice(self.KINDS).format(root=DOCROOT, f=frag, nf=NOT_FOUND)
            req = rnd.choice(['GET /.env', 'GET /x', 'POST /wp-login.php'])
            got = self.credited([nginx_line(msg, req)])
            self.assertNotIn(VICTIM, got, msg)
            seen_visitor += REAL in got
        # a population of lines that credit nobody would pass this test too: some of them must be read for the visitor
        self.assertGreater(seen_visitor, 50)


# ── every reader, one question ────────────────────────────────────────────────

def _scan_with(agent, fn, lines, *, parse=False, now=NOW):
    agg = agent._TsAgg(now)
    if parse:
        fn(lines, agent._ts_access_parser(None)[1], agg, '/var/log/x.log', now)
    else:
        fn(lines, agg, '/var/log/x.log', now)
    events, _ = agg.events()
    return sorted(e['ip'] for e in events)


class TestEveryReaderNamesTheSenderNotTheText(_Agent):
    """Population: every `_ts_scan_*` function of the agent. Each reader has a case (honest lines, the same lines with the victim's address written into the
    text a visitor controls) or a reason it has none. The honest lines are the control: they must credit the visitor, or the empty answer proves nothing."""

    EXEMPT = {
        '_ts_scan_cscli': 'it reads the JSON of the local CrowdSec through a command the operator runs; no visitor text sits in front of the address it reads',
        '_ts_scan_f2b': "it reads fail2ban's own log, whose lines hold the jail and the address fail2ban decided on; the pattern is anchored at the start of the line",
        '_ts_scan_fastlog': "the message of a Suricata alert is the rule author's text; Suricata writes no request data into it",
        '_ts_scan_modsec_native': 'the rule that one record is read at a time has its own commit and tests',
    }

    def cases(self):
        a = self.agent
        t = NOW - 3
        T = ts_apache_err
        ufw_ports = range(1, 8)
        return {
            '_ts_scan_nginx_error': (
                lambda L: _scan_with(a, a._ts_scan_nginx_error, L),
                [nginx_line(probe_msg('/.env'), 'GET /.env')],
                [nginx_line(probe_msg('/.env/x, client: %s,' % VICTIM), 'GET /.env/x')]),
            '_ts_scan_apache_error': (
                lambda L: _scan_with(a, a._ts_scan_apache_error, L),
                [f'{T(t)} [core:error] [pid 1:tid 2] [client {REAL}:5555] AH00128: File does not exist: /var/www/.env'],
                [f'{T(t)} [core:error] [pid 1:tid 2] [client {REAL}:5555] AH00128: File does not exist: /var/www/.env/x [client {VICTIM}:1] client: {VICTIM},']),
            '_ts_scan_access': (
                lambda L: _scan_with(a, a._ts_scan_access, L, parse=True),
                [combined(REAL, t, 'GET /.env HTTP/1.1', 404)],
                [combined(REAL, t, 'GET /.env HTTP/1.1', 404, ua=f'x {VICTIM} \\x22GET /.env HTTP/1.1\\x22 404', ref=f'http://{VICTIM}/ \\x22GET /.env HTTP/1.1\\x22 404 1')]),
            '_ts_scan_firewall': (
                lambda L: _scan_with(a, a._ts_scan_firewall, L),
                [fw_rec(REAL, p) for p in ufw_ports],
                [fw_rec(REAL, p).replace('PROTO=TCP', f'SRC={VICTIM} PROTO=TCP') for p in ufw_ports]),
            '_ts_scan_modsec_json': (
                lambda L: _scan_with(a, a._ts_scan_modsec_json, L),
                [json.dumps(self._modsec_json(REAL))],
                [json.dumps(self._modsec_json(REAL, body=json.dumps(self._modsec_json(VICTIM)), header='"client_ip":"%s"' % VICTIM))]),
            '_ts_scan_eve': (
                lambda L: _scan_with(a, a._ts_scan_eve, L),
                [eve_alert(REAL, sig='ET SCAN Nmap Scripting Engine User-Agent Detected', cat='Web Application Attack', t=t)],
                [eve_alert(REAL, sig='ET SCAN Nmap Scripting Engine User-Agent Detected', cat='Web Application Attack', t=t,
                           tail='"http":{"hostname":"x","url":"/\\"src_ip\\":\\"%s\\"","http_user_agent":"\\"src_ip\\": \\"%s\\""}}' % (VICTIM, VICTIM))]),
        }

    @staticmethod
    def _modsec_json(ip, body='', header=''):
        return {'transaction': {'client_ip': ip, 'time_stamp': ts_ctime(NOW - 5), 'unique_id': 'u1',
                                'request': {'method': 'POST', 'uri': '/x', 'headers': {'User-Agent': 'curl', 'X-Test': header}, 'body': body},
                                'response': {'http_code': 403},
                                'messages': [{'message': 'Access denied', 'details': {'ruleId': '949110', 'tags': ['attack-sqli']}}]}}

    def test_the_population_is_every_reader_the_agent_has(self):
        readers = sorted(n for n in dir(self.agent) if n.startswith('_ts_scan_') and callable(getattr(self.agent, n)))
        self.assertGreaterEqual(len(readers), 10, 'the derivation found the readers')
        self.assertEqual(sorted(set(self.cases()) | set(self.EXEMPT)), readers,
                         'a reader without a case or a stated reason: ask it the question (or the list of readers has gone stale)')
        self.assertFalse(set(self.cases()) & set(self.EXEMPT))

    def test_every_reader_credits_the_visitor_and_not_the_address_in_his_text(self):
        for name, (run, honest, forged) in sorted(self.cases().items()):
            with self.subTest(reader=name):
                self.assertIn(REAL, run(honest), 'the control: the honest lines credit the visitor')
                got = run(forged)
                self.assertNotIn(VICTIM, got)
                if name != '_ts_scan_nginx_error':          # a line that names two clients is read for nobody; every other reader still reads its visitor
                    self.assertIn(REAL, got)


if __name__ == '__main__':
    unittest.main()
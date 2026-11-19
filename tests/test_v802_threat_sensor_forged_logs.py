"""8.0.2: nginx's error log holds text that a request chose, and the client part of a line is where nginx names who sent it.

The sensor reports and blocks the address it reads from a log. nginx writes the decoded path of a file that is not there, the user name
of a failed login, the request line and the Referer into its error log as they came, so a request can write a client part of its own
into a line (`, client: 8.8.4.4,`) and, with `%0A` in the path, a whole line. These tests run the agent's reader over those lines, then
over a file through the real pass, and hold the same rule for every other reader of the agent: the address is the one the server wrote.

The readers and the pass are the agent's own; only the files are scratch ones.
"""
import json
import sys
import time
import unittest
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'server' / 'cgi-bin'))

from test_v720_threat_sensor_agent import (  # noqa: E402
    A1, A2, A3, A4, NOW, _Agent, audit_native, combined, ts_apache_err, ts_ctime, ts_nginx_err,
)
from test_v720_threat_sensor_cycle import _Host  # noqa: E402

VICTIM = '8.8.4.4'
VICTIM2 = '45.77.10.98'
ERRLOG = '/var/log/nginx/error.log'
ROOT = '/usr/share/nginx/html'
WORDS = 'Victim-Corp-is-compromised-see-evil.example'


def tail(peer, target, ref=None, host='example.com'):
    """The part nginx puts at the end of every message of a request."""
    return (f', client: {peer}, server: {host}, request: "GET {target} HTTP/1.1", host: "{host}"'
            + (f', referrer: "{ref}"' if ref is not None else ''))


def static_miss(e, peer, raw_target, ref=None, conn=14):
    """What nginx writes for a request that names a file that is not there. The path is decoded and written as it is, so a line break
    in it is a line break in the log. The result is the text of the log: more than one physical line when the path has a break."""
    decoded = urllib.parse.unquote(raw_target.split('?')[0])
    return (f'{ts_nginx_err(e)} [error] 29458#29458: *{conn} open() "{ROOT}{decoded}" failed (2: No such file or directory)'
            + tail(peer, raw_target, ref))


def quoted(text):
    """Text as a request can carry it in a path: everything that matters to a log line is percent-encoded."""
    return urllib.parse.quote(text, safe="/:[]'(),")


class _Base(_Agent):
    def setUp(self):
        # a plain error-log address needs three hits to be sent (the sensor's own tests hold that); these tests are about the address
        self.addCleanup(setattr, self.agent, 'THREAT_MIN_HITS', self.agent.THREAT_MIN_HITS)
        self.agent.THREAT_MIN_HITS = 1

    def scan(self, text, samples=False):
        rows = text.split('\n') if isinstance(text, str) else list(text)
        agg = self.agent._TsAgg(NOW)
        agg.want_samples = samples
        n, parsed = self.agent._ts_scan_nginx_error(rows, agg, ERRLOG, NOW)
        return n, parsed, {e['ip']: e for e in agg.events()[0]}


# ── the client part of one line ─────────────────────────────────────────────────────────────────────────────────────────────────────────

class TestTheClientPartIsTheOneNginxWrote(_Base):
    def test_control_an_honest_miss_is_the_senders(self):
        _, _, ev = self.scan('\n'.join([static_miss(NOW - 5, A1, '/.env')] * 12))
        self.assertEqual(sorted(ev), [A1])
        self.assertEqual(ev[A1]['src'], {'err': 12})

    def test_a_client_part_written_into_the_path_is_not_read(self):
        target = '/x,%20client:%20' + VICTIM + ',%20/.env'
        text = static_miss(NOW - 5, A1, target)
        self.assertEqual(text.count(', client: '), 2, 'the instrument: the line holds the real part and the one in the path')
        _, _, ev = self.scan('\n'.join([text] * 12))
        self.assertEqual(ev, {}, 'neither the address of the path nor the sender is read from a line that has two client parts')

    def test_the_words_of_the_bouncer_written_into_the_path_name_nobody(self):
        target = "/x%5BCrowdsec%5D%20denied%20'" + VICTIM + "'%20with%20'ban'%20(by%20appsec),%20client:%20" + VICTIM + ',%20'
        _, _, ev = self.scan(static_miss(NOW - 5, A1, target))
        self.assertEqual(ev, {})

    def test_a_second_request_part_written_into_the_path_gives_no_words_to_a_report(self):
        words = '/' + WORDS
        target = ("/x%5BCrowdsec%5D%20denied%20'" + VICTIM2 + "'%20with%20'ban'%20(by%20appsec)%2C%20client%3A%20" + VICTIM2
                  + '%2C%20server%3A%20s%2C%20request%3A%20%22GET%20' + words + '%20HTTP%2F1.1%22%2C%20host%3A%20%22x%22')
        _, _, ev = self.scan(static_miss(NOW - 5, A1, target), samples=True)
        self.assertEqual(ev, {})

    def test_a_request_part_written_into_the_message_is_not_the_request_of_the_sample(self):
        """One client part, but a user name that holds a `request:` part: the sample is the request of the tail, which nginx wrote last."""
        user = 'x, request: "GET /' + WORDS + ' HTTP/1.1", '
        line = (f'{ts_nginx_err(NOW - 5)} [error] 1234#1234: *9 user "{user}" was not found in "/etc/nginx/.htpasswd"'
                + tail(A1, '/admin/'))
        self.assertEqual(line.count(', client: '), 1, 'the instrument: one client part, and two request parts')
        self.assertEqual(line.count(', request: "'), 2)
        _, _, ev = self.scan(line, samples=True)
        self.assertEqual(sorted(ev), [A1])
        self.assertEqual([s['p'] for s in ev[A1]['smp']], ['/admin/'])
        self.assertNotIn('Victim', json.dumps(ev))

    def test_a_client_part_written_into_the_referrer_is_not_read(self):
        ref = f'https://x.example/, client: {VICTIM}, server: s'
        text = static_miss(NOW - 5, A1, '/.env', ref=ref)
        self.assertEqual(text.count(', client: '), 2)
        _, _, ev = self.scan(text)
        self.assertEqual(ev, {})

    def test_a_client_part_beyond_the_cut_is_still_counted(self):
        """The raw URI of a request is in the message of a ModSecurity line. A long one puts the real client part past THREAT_MAX_LINE, and
        cut there, a forged part in front of the cut is the only one: one request is a WAF refusal of the address it names."""
        uri = '/x, client: ' + VICTIM + ', server: s, ' + 'a' * 8100
        line = (f'{ts_nginx_err(NOW - 5)} [error] 1#1: *5 ModSecurity: Access denied with code 403 (phase 2). [id "949110"] '
                f'[tag "attack-sqli"] [uri "{uri}"] [unique_id "1790000001.1"] [ref ""]' + tail(A1, '/'))
        self.assertGreater(line.rfind(', client: '), self.agent.THREAT_MAX_LINE, 'the instrument: the real part is beyond the cut')
        self.assertEqual(line[:self.agent.THREAT_MAX_LINE].count(', client: '), 1, 'the instrument: a cut line holds only the forged one')
        _, _, ev = self.scan(line)
        self.assertEqual(ev, {})

    def test_the_message_says_what_the_event_was_not_the_request_that_follows(self):
        """The referrer is the sender's text. A message that is a plain miss stays one, whatever the referrer says."""
        ref = 'ModSecurity: Access denied with code 403 [id "942100"] [tag "attack-sqli"] limiting requests'
        _, _, ev = self.scan(static_miss(NOW - 5, A1, '/.env', ref=ref))
        self.assertEqual(sorted(ev), [A1])
        self.assertEqual(ev[A1]['src'], {'err': 1}, 'no WAF refusal and no flood came out of a referrer')

    def test_a_modsecurity_line_is_still_read_by_its_message(self):
        line = (f'{ts_nginx_err(NOW - 5)} [error] 1#1: *5 ModSecurity: Access denied with code 403 (phase 2). [id "949110"] '
                '[tag "attack-sqli"] [uri "/"] [unique_id "1790000001.1"] [ref ""]' + tail(A2, '/?q=1'))
        _, _, ev = self.scan(line)
        self.assertEqual(ev[A2]['src'], {'waf': 1})
        self.assertIn('crs:949110', ev[A2]['tok']['waf'])

    def test_the_unique_id_of_a_transaction_is_the_one_modsecurity_wrote_last(self):
        """`[data]` and `[uri]` hold request text and come before the id. A request that writes `[unique_id "..."]` there must not
        be able to pick the id its own hit is counted under (and so merge into another transaction's count)."""
        forged = '[data "[unique_id \\"1790000001.1\\"]"] '
        mk = lambda uid, ip: (f'{ts_nginx_err(NOW - 5)} [error] 1#1: *5 ModSecurity: Access denied with code 403 (phase 2). [id "949110"] '
                              f'{forged}[unique_id "{uid}"] [ref ""]' + tail(ip, '/?q=1'))
        _, _, ev = self.scan([mk('1790000001.1', A2), mk('1790000099.9', A3)])
        self.assertEqual(sorted(ev), sorted([A2, A3]))
        self.assertEqual((ev[A2]['src'], ev[A3]['src']), ({'waf': 1}, {'waf': 1}), 'each transaction counted under its own id')


# ── a line break inside a message ───────────────────────────────────────────────────────────────────────────────────────────────────────

def forged_line(ip=VICTIM, e=NOW - 5):
    """A line that is complete in every way: a time, a worker, a message of the kind the sensor counts, and a client of its own."""
    return static_miss(e, ip, '/.env', conn=15)


class TestALineBreakInAMessage(_Base):
    def carry(self, *lines, last_break=True):
        """The target of one request that writes `lines` (whole lines of its own) into the log after its own first part."""
        return '/x' + ''.join('%0A' + quoted(line) for line in lines) + ('%0A' if last_break else '')

    def between(self, text):
        """The events of a read that holds `text` between an honest line before it and one after it."""
        _, _, ev = self.scan('\n'.join([static_miss(NOW - 20, A2, '/.env', conn=1), text, static_miss(NOW - 3, A3, '/.env', conn=2)]))
        return ev

    def test_the_instrument_a_break_in_the_path_is_a_break_in_the_log(self):
        text = static_miss(NOW - 5, A1, self.carry(forged_line()))
        rows = text.split('\n')
        self.assertEqual(len(rows), 3)
        self.assertTrue(rows[1].startswith(ts_nginx_err(NOW - 5)) and VICTIM in rows[1], 'the second row is a whole line that names the victim')
        self.assertTrue(rows[2].startswith('" failed (2: '), "and the last holds nginx's own words and the real client part")
        self.assertIn(f'client: {A1}', rows[2])

    def test_a_line_written_between_the_real_parts_is_not_an_entry(self):
        _, _, ev = self.scan(static_miss(NOW - 5, A1, self.carry(forged_line())))
        self.assertEqual(ev, {}, 'the forged line is not read, and the lines it came with are no entries')

    def test_a_line_written_with_the_real_part_after_it_on_the_same_row_is_not_read(self):
        text = static_miss(NOW - 5, A1, self.carry(forged_line(), last_break=False))
        self.assertEqual(len(text.split('\n')), 2)
        _, _, ev = self.scan(text)
        self.assertEqual(ev, {})

    def test_several_forged_lines_are_not_entries(self):
        lines = [forged_line(VICTIM), forged_line(VICTIM2), forged_line('91.92.241.99')]
        _, _, ev = self.scan(static_miss(NOW - 5, A1, self.carry(*lines)))
        self.assertEqual(ev, {})

    def test_a_message_whose_end_is_dressed_as_a_whole_line_is_still_a_message(self):
        """The last piece of the path starts with a time and a worker, so the row that ends the message has the look of an entry."""
        head = f'{ts_nginx_err(NOW - 5)} [error] 29458#29458: *16 open() "x'
        text = static_miss(NOW - 5, A1, self.carry(forged_line(), head, last_break=False))
        rows = text.split('\n')
        self.assertTrue(rows[-1].startswith(ts_nginx_err(NOW - 5)), 'the instrument: the end of the message is a row with a time in front')
        self.assertEqual(sorted(self.between('\n'.join(rows))), sorted([A2, A3]), 'the request line says two breaks: the three rows are one message')

    def test_a_forged_client_part_in_the_last_piece_does_not_hide_the_message(self):
        piece = f', client: {VICTIM}, server: s'
        text = static_miss(NOW - 5, A1, '/x%0A' + quoted(forged_line()) + '%0A' + quoted(piece))
        self.assertEqual(text.split('\n')[-1].count(', client: '), 2, 'the instrument: the row that ends the message holds two client parts')
        self.assertEqual(sorted(self.between(text)), sorted([A2, A3]))

    def test_a_referrer_that_looks_like_the_end_of_a_message_cannot_lower_the_count(self):
        ref = '" failed (2: x), client: 1.2.3.4, server: s, request: "GET /a HTTP/1.1'
        text = static_miss(NOW - 5, A1, self.carry(forged_line()), ref=ref)
        self.assertEqual(sorted(self.between(text)), sorted([A2, A3]), 'the count is the one of the real request line, not the lowest of the two')

    def test_a_quote_in_the_target_does_not_end_the_count(self):
        text = static_miss(NOW - 5, A1, '/a"' + self.carry(forged_line(), forged_line(VICTIM2))[2:])
        self.assertIn('request: "GET /a"%0A', text)
        self.assertEqual(sorted(self.between(text)), sorted([A2, A3]))

    def test_two_spaces_after_the_method_do_not_hide_the_count(self):
        text = static_miss(NOW - 5, A1, self.carry(forged_line())).replace('request: "GET /', 'request: "GET  /')
        self.assertIn('request: "GET  /x%0A', text)
        self.assertEqual(sorted(self.between(text)), sorted([A2, A3]), 'exactly the message is left out')

    def test_a_long_request_line_counts_every_break(self):
        text = static_miss(NOW - 5, A1, '/' + 'b' * 3000 + self.carry(forged_line(), forged_line(VICTIM2))[2:])
        self.assertEqual(sorted(self.between(text)), sorted([A2, A3]), 'the breaks after the first 2048 characters of a target are counted too')

    def test_a_plain_miss_whose_referrer_holds_breaks_costs_no_line(self):
        text = '\n'.join([static_miss(NOW - 20, A2, '/.env', conn=1), static_miss(NOW - 5, A1, '/.env', ref='%0a%0a%0a%0a%0a', conn=2),
                          static_miss(NOW - 3, A3, '/.env', conn=3)])
        _, _, ev = self.scan(text)
        self.assertEqual(sorted(ev), sorted([A1, A2, A3]), 'only the path of the request says how many breaks a message has')

    def test_the_lines_before_and_after_the_message_are_still_read(self):
        text = '\n'.join([static_miss(NOW - 20, A2, '/.env', conn=1), static_miss(NOW - 5, A1, self.carry(forged_line())),
                          static_miss(NOW - 3, A3, '/.git/config', conn=2)])
        _, _, ev = self.scan(text)
        self.assertEqual(sorted(ev), sorted([A2, A3]), 'only the message that held the breaks is left out')

    def test_the_forged_line_does_not_hide_when_the_message_is_in_the_middle_of_a_busy_read(self):
        lines = [static_miss(NOW - 40 + i, A4, '/wp-config.php.bak', conn=i) for i in range(5)]
        lines.append(static_miss(NOW - 5, A1, self.carry(forged_line(), forged_line(VICTIM2))))
        lines += [static_miss(NOW - 3 + i, A2, '/.env', conn=20 + i) for i in range(2)]
        _, parsed, ev = self.scan('\n'.join(lines))
        self.assertEqual(sorted(ev), sorted([A4, A2]))
        self.assertEqual(ev[A4]['src'], {'err': 5})
        self.assertEqual(ev[A2]['src'], {'err': 2})
        self.assertGreaterEqual(parsed, 9, 'a line that is left out was still understood: the source is not reported as unreadable')

    def test_a_scanner_that_sends_a_carriage_return_and_a_line_feed_costs_only_its_own_lines(self):
        crlf = static_miss(NOW - 5, A1, '/%0d%0aSet-Cookie:crlf=injection', conn=30)
        self.assertEqual(len(crlf.split('\n')), 2, 'the instrument: one request, two rows')
        text = '\n'.join([static_miss(NOW - 20, A2, '/.env', conn=1), crlf, static_miss(NOW - 3, A3, '/.env', conn=2)])
        _, _, ev = self.scan(text)
        self.assertEqual(sorted(ev), sorted([A2, A3]), 'the lines of the others in the same read are kept: the rows are told exactly')

    def test_the_count_is_the_one_of_the_request_line_whatever_nginx_did_to_the_path(self):
        """nginx merges the slashes of a path before it writes it, so the row holds `x/y` where the request says `x//y`. Breaks are counted
        in the request line, not in what the rows spell, so the message is still told exactly."""
        text = static_miss(NOW - 5, A1, '/a%0Ax//y%0Ab', conn=30).replace('x//y', 'x/y')
        self.assertIn('\nx/y\n', text)
        forged = static_miss(NOW - 5, A1, '/a%0A' + quoted(forged_line()) + '%0Ab', conn=31).split('\n')
        _, _, ev = self.scan('\n'.join([static_miss(NOW - 20, A2, '/.env', conn=1), text, '\n'.join(forged), static_miss(NOW - 3, A3, '/.env', conn=2)]))
        self.assertEqual(sorted(ev), sorted([A2, A3]))

    def test_a_user_name_with_a_line_break_leaves_out_the_read_before_it(self):
        user_head = f'{ts_nginx_err(NOW - 5)} [error] 1234#1234: *9 user "admin'
        rest = '" was not found in "/etc/nginx/.htpasswd"' + tail(A1, '/admin/')
        text = '\n'.join([static_miss(NOW - 20, A2, '/.env', conn=1), user_head, forged_line(), rest,
                          static_miss(NOW - 3, A3, '/.env', conn=2)])
        _, _, ev = self.scan(text)
        self.assertEqual(sorted(ev), [A3], 'no forged line, and what came before it in the read is not trusted either')

    def test_the_multi_line_error_of_an_application_is_not_a_sign(self):
        php = (f'{ts_nginx_err(NOW - 6)} [error] 1234#1234: *11 FastCGI sent in stderr: "PHP message: PHP Warning:  foo in /var/www/a.php on '
               'line 3\nPHP message: PHP Stack trace:\nPHP message: PHP   1. {main}() /var/www/a.php:0" while reading response header '
               'from upstream' + tail(A1, '/a.php').replace('host: "example.com"', 'upstream: "fastcgi://unix:/run/php.sock:", host: "example.com"'))
        text = '\n'.join([static_miss(NOW - 20, A2, '/.env', conn=1), php, static_miss(NOW - 3, A3, '/.env', conn=2)])
        _, _, ev = self.scan(text)
        self.assertEqual(sorted(ev), sorted([A2, A3]), 'the lines around a PHP error are kept')

    def test_a_read_that_begins_with_the_end_of_a_message_leaves_out_what_it_has_before_it(self):
        full = static_miss(NOW - 5, A1, self.carry(forged_line(), forged_line(VICTIM2)), conn=40).split('\n')
        read = full[2:] + [static_miss(NOW - 3, A3, '/.env', conn=2)]            # the first part of the message was in the pass before
        _, _, ev = self.scan(read)
        self.assertEqual(sorted(ev), [A3])

    def test_a_line_that_starts_the_read_with_the_sign_and_nothing_before_it(self):
        _, _, ev = self.scan(['" failed (2: No such file or directory)' + tail(A1, '/x%0A'), static_miss(NOW - 3, A3, '/.env', conn=2)])
        self.assertEqual(sorted(ev), [A3])


class TestAForgedLineInAWholePass(_Host):
    def test_the_sensor_reports_what_nginx_wrote(self):
        target = '/x%0A' + quoted(forged_line()) + '%0A'
        text = '\n'.join([static_miss(NOW - 30, A2, '/.env', conn=1), static_miss(NOW - 5, A1, target),
                          static_miss(NOW - 3, A3, '/.git/config', conn=2)]) + '\n'
        self.put(ERRLOG, text)
        self.addCleanup(setattr, self.agent, 'THREAT_MIN_HITS', self.agent.THREAT_MIN_HITS)
        self.agent.THREAT_MIN_HITS = 1
        events, sources, dropped, state = self.agent.collect_threat_events({'enabled': True, 'paths': [ERRLOG]}, {}, NOW)
        self.assertEqual(sorted(e['ip'] for e in events), sorted([A2, A3]))
        self.assertNotIn(VICTIM, json.dumps(events))
        row = [s for s in sources if s['path'] == ERRLOG][0]
        self.assertEqual(row['state'], 'ok')


# ── every reader of the agent: the address is the one the server wrote ──────────────────────────────────────────────────────────────────

class TestEveryReaderNamesTheSender(_Agent):
    """The same rule for the nine readers, each with a line whose sender-written text holds what that reader looks for. A reader whose
    address is found by a search over the whole line is the shape of a finding; one anchored at a field the server wrote is not."""

    def setUp(self):
        self.addCleanup(setattr, self.agent, 'THREAT_MIN_HITS', self.agent.THREAT_MIN_HITS)
        self.agent.THREAT_MIN_HITS = 1

    def rows(self):
        a = self.agent
        t = NOW - 5
        mk_access = lambda text: combined(A1, t, f'GET /x{text} HTTP/1.1', 404)
        nginx_forged = ('%20%2C%20client%3A%20' + VICTIM)
        return {
            # the server writes the address first and escapes the request: a `"` is \x22 and a line break is \x0A
            '_ts_scan_access': (lambda ls, agg: a._ts_scan_access(ls, a._ts_access_parser(None)[1], agg, 'a', NOW),
                                [mk_access('/../../etc/passwd%20' + VICTIM + '%20-%20-%20[x]\\x22GET%20/.env')]),
            # the client part: the message and the request are the sender's, the part nginx wrote is one (see the classes above)
            '_ts_scan_nginx_error': (lambda ls, agg: a._ts_scan_nginx_error(ls, agg, 'e', NOW),
                                     [static_miss(t, A1, '/.env'), static_miss(t, A1, '/.env' + nginx_forged)]),
            # Apache writes `[client <peer>]` before any message text, so the first one is its own
            '_ts_scan_apache_error': (lambda ls, agg: a._ts_scan_apache_error(ls, agg, 'e', NOW),
                                      [f'{ts_apache_err(t)} [core:info] [pid 1:tid 2] [client {A1}:5555] AH00128: File does not exist: '
                                       f'/var/www/html/.env [client {VICTIM}:1] AH01630: client denied by server configuration: x']),
            '_ts_scan_modsec_native': (lambda ls, agg: a._ts_scan_modsec_native('\n'.join(ls).split('\n'), agg, 'm', NOW),
                                       [audit_native(t, A1, 'c4d8b66b')]),
            # a JSON record names its address in a field, and what the request holds is a string inside it
            '_ts_scan_modsec_json': (lambda ls, agg: a._ts_scan_modsec_json(ls, agg, 'm', NOW),
                                     [json.dumps({'transaction': {
                                         'client_ip': A1, 'time_stamp': ts_ctime(t), 'unique_id': 'u1',
                                         'request': {'method': 'GET', 'uri': '/x","client_ip":"' + VICTIM + '"', 'headers': {'User-Agent': 'x'}},
                                         'response': {'http_code': 403},
                                         'messages': [{'message': 'SQL', 'details': {'ruleId': '942100', 'tags': ['attack-sqli']}}]}})]),
            # the lines of these four hold no text that a remote sender wrote; the row is the control that each names its own address
            '_ts_scan_f2b': (lambda ls, agg: a._ts_scan_f2b(ls, agg, 'f', NOW),
                             [f'{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))},123 fail2ban.actions        '
                              f'[1234]: NOTICE  [sshd] Ban {A1}']),
            '_ts_scan_firewall': (lambda ls, agg: a._ts_scan_firewall(ls, agg, 'u', NOW),
                                  [f'{time.strftime("%b %d %H:%M:%S", time.localtime(t))} host kernel: [UFW BLOCK] '
                                   f'IN=eth0 OUT= MAC=00 SRC={A1} DST=10.0.0.5 LEN=60 PROTO=TCP SPT=1 DPT={22 + i} WINDOW=1' for i in range(5)]),
            '_ts_scan_eve': (lambda ls, agg: a._ts_scan_eve(ls, agg, 'x.json', NOW),
                             [json.dumps({'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S.000000+0000', time.gmtime(t)),
                                          'event_type': 'alert', 'src_ip': A1, 'proto': 'TCP',
                                          'alert': {'signature': 'ET SCAN Potential SSH Scan', 'category': 'Attempted Information Leak'},
                                          'http': {'url': '/", "src_ip": "' + VICTIM + '", "x": "'}})]),
            '_ts_scan_fastlog': (lambda ls, agg: a._ts_scan_fastlog(ls, agg, 'x.log', NOW),
                                 [f'{time.strftime("%m/%d/%Y-%H:%M:%S", time.localtime(t))}.123456  [**] [1:2002910:6] '
                                  f'ET SCAN Potential SSH Scan [**] [Classification: Attempted Information Leak] [Priority: 2] '
                                  f'{{TCP}} {A1}:4444 -> 192.0.2.1:22']),
        }

    def test_the_table_covers_every_reader_of_the_agent(self):
        found = {n for n in dir(self.agent) if n.startswith('_ts_scan_') and callable(getattr(self.agent, n)) and n != '_ts_scan_cscli'}
        self.assertEqual(found, set(self.rows()), 'a reader added to the agent without a row here, or a row for one that is gone')
        self.assertGreaterEqual(len(found), 9)

    def test_each_reader_names_the_sender_and_nobody_the_sender_wrote(self):
        for name, (run, lines) in self.rows().items():
            with self.subTest(reader=name):
                agg = self.agent._TsAgg(NOW)
                run(lines, agg)
                ips = sorted(e['ip'] for e in agg.events()[0])
                self.assertEqual(ips, [A1], f'{name}: the address of a reader is the one the server wrote')


if __name__ == '__main__':
    unittest.main()

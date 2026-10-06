"""The threat sensor as a whole: finding the logs, one pass over them, and the
thread that runs the passes.

A fake host root stands in for the machine (the agent reads every path through
host_path(), the same mechanism a containerized agent uses for its Docker host),
so discovery, the reader and the scanners run against real files.
"""
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_v720_threat_sensor_agent import (  # noqa: E402
    A1, A2, A3, A4, NOW, audit_native, combined, load_agent, ngx_modsec, ts_iso_local, ts_nginx,
    ts_nginx_err,
)

_ROOT = Path(__file__).resolve().parent.parent


class _Host(unittest.TestCase):
    """A scratch machine: self.put('/etc/nginx/nginx.conf', text)."""

    @classmethod
    def setUpClass(cls):
        cls.agent = load_agent('agent_threat_cycle')

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='rp-ts-host-'))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.agent.HOST_ROOT = str(self.tmp)
        self.addCleanup(setattr, self.agent, 'HOST_ROOT', '')
        self._which = self.agent._which
        self.agent._which = lambda prog, _c={}: None
        self.addCleanup(setattr, self.agent, '_which', self._which)

    def put(self, path, text, mode=None):
        p = self.tmp / path.lstrip('/')
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p

    def paths(self, found, kind):
        return sorted(e['path'] for e in found[kind])


NGINX_CONF = '''
user www-data;
events { worker_connections 768; }
http {
    log_format seclog '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" "$http_user_agent" rt=$request_time';
    log_format reqlen '$remote_addr $request_length';
    access_log /var/log/nginx/access.log seclog;
    error_log  /var/log/nginx/error.log warn;
    real_ip_header CF-Connecting-IP;   # restore the visitor behind the proxy
    set_real_ip_from 173.245.48.0/20;
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/main.conf;
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
'''


def tree_nginx(host):
    host.put('/etc/nginx/nginx.conf', NGINX_CONF)
    host.put('/etc/nginx/conf.d/01-request-length.conf', 'access_log /var/log/nginx/request-length.log reqlen;\n')
    host.put('/etc/nginx/sites-enabled/example', '''
server {
    server_name example.com;
    access_log /var/log/nginx/example.access.log;
    include snippets/block-exploits.conf;
}
''')
    host.put('/etc/nginx/snippets/block-exploits.conf',
             'location ~* "(union.*select|\\.\\./)" { access_log /var/log/nginx/blocked.log; deny all; }\n')
    host.put('/etc/nginx/modsec/main.conf', 'Include /etc/nginx/modsec/modsecurity.conf\n'
             'Include /etc/nginx/modsec/crs-setup.conf\n')
    host.put('/etc/nginx/modsec/modsecurity.conf',
             'SecRuleEngine On\nSecAuditEngine RelevantOnly\nSecAuditLogParts ABIJDEFHZ\n'
             'SecAuditLogType Serial\nSecAuditLog /var/log/modsec_audit.log\n')
    host.put('/etc/nginx/modsec/crs-setup.conf', '# nothing about logs here\nSecDefaultAction "phase:1,log,auditlog,pass"\n')
    host.put('/etc/fail2ban/fail2ban.conf', '[Definition]\nloglevel = INFO\nlogtarget = /var/log/fail2ban.log\n')


class TestConfigReading(_Host):
    def test_nginx_directives_quotes_comments_and_nesting(self):
        st = self.agent._ts_nginx_statements(NGINX_CONF)
        names = [n for n, _ in st]
        self.assertIn('log_format', names)
        self.assertEqual(names.count('access_log'), 1)
        fmt = [a for n, a in st if n == 'log_format'][0]
        self.assertEqual(fmt[0], 'seclog')
        self.assertIn('$remote_addr', ''.join(fmt[1:]))
        self.assertNotIn('restore', json.dumps(st), 'a comment leaked into a directive')
        self.assertEqual([a for n, a in st if n == 'error_log'], [['/var/log/nginx/error.log', 'warn']])

    def test_a_hash_inside_quotes_is_not_a_comment_and_escapes_work(self):
        st = self.agent._ts_nginx_statements("log_format x '$remote_addr # \"$request\" \\' end'; # real comment\n")
        self.assertEqual(st[0][0], 'log_format')
        self.assertIn('#', st[0][1][1])
        self.assertIn("' end", st[0][1][1])

    def test_apache_directives_continuations_and_quotes(self):
        text = ('# a comment\nServerRoot "/etc/apache2"\n'
                'LogFormat "%h %l %u %t \\"%r\\" %>s %b" common\n'
                'CustomLog ${APACHE_LOG_DIR}/access.log \\\n    combined\n'
                '<VirtualHost *:80>\n  ErrorLog ${APACHE_LOG_DIR}/error.log\n</VirtualHost>\n')
        st = self.agent._ts_apache_statements(text)
        d = {n.lower(): a for n, a in st}
        self.assertEqual(d['logformat'], ['%h %l %u %t "%r" %>s %b', 'common'])
        self.assertEqual(d['customlog'], ['${APACHE_LOG_DIR}/access.log', 'combined'])
        self.assertEqual(d['errorlog'], ['${APACHE_LOG_DIR}/error.log'])

    def test_includes_are_followed_and_bounded(self):
        a = self.agent
        self.put('/etc/nginx/nginx.conf', 'include /etc/nginx/loop.conf;\n')
        self.put('/etc/nginx/loop.conf', 'include /etc/nginx/nginx.conf;\ninclude /etc/nginx/loop.conf;\naccess_log /var/log/nginx/x.log;\n')
        st = a._ts_conf_statements([('/etc/nginx/nginx.conf', 'nginx', '/etc/nginx')])
        self.assertEqual([n for n, _, _ in st].count('access_log'), 1, 'a loop must not repeat or hang')

    def test_a_directive_in_a_huge_config_cannot_hang_the_reader(self):
        t0 = time.monotonic()
        self.agent._ts_nginx_statements('a ' * 400_000 + ';')
        self.agent._ts_apache_statements('x y\n' * 200_000)
        self.assertLess(time.monotonic() - t0, 5)


class TestDiscovery(_Host):
    def test_nginx_with_a_custom_format_waf_and_fail2ban(self):
        tree_nginx(self)
        for n in ('access.log', 'error.log', 'example.access.log', 'blocked.log', 'request-length.log'):
            self.put(f'/var/log/nginx/{n}', '')
        self.put('/var/log/modsec_audit.log', '')
        self.put('/var/log/fail2ban.log', '')
        d = self.agent._ts_discover({}, NOW)
        self.assertEqual(self.paths(d, 'web'), sorted(f'/var/log/nginx/{n}' for n in (
            'access.log', 'example.access.log', 'blocked.log', 'request-length.log')))
        self.assertEqual(self.paths(d, 'err'), ['/var/log/nginx/error.log'])
        self.assertEqual(self.paths(d, 'waf'), ['/var/log/modsec_audit.log'])
        self.assertEqual(self.paths(d, 'f2b'), ['/var/log/fail2ban.log'])
        self.assertTrue(d['proxied'], 'real_ip_header means visitors arrive through a proxy')
        by = {e['path']: e['spec'] for e in d['web']}
        self.assertIn('rt=$request_time', by['/var/log/nginx/access.log']['format'])
        self.assertEqual(by['/var/log/nginx/blocked.log']['format'], self.agent._TS_NGX_COMBINED,
                         'no format named means combined')
        self.assertEqual(by['/var/log/nginx/request-length.log']['format'], '$remote_addr $request_length')
        self.assertFalse(d['cs'])

    def test_apache_with_variables_and_the_vhost_log(self):
        self.put('/etc/apache2/apache2.conf',
                 'ServerRoot "/etc/apache2"\nErrorLog ${APACHE_LOG_DIR}/error.log\n'
                 'LogFormat "%v:%p %h %l %u %t \\"%r\\" %>s %O \\"%{Referer}i\\" \\"%{User-Agent}i\\"" vhost_combined\n'
                 'LogFormat "%h %l %u %t \\"%r\\" %>s %O \\"%{Referer}i\\" \\"%{User-Agent}i\\"" combined\n'
                 'IncludeOptional sites-enabled/*.conf\n')
        self.put('/etc/apache2/sites-enabled/000-default.conf',
                 '<VirtualHost *:80>\n  CustomLog ${APACHE_LOG_DIR}/access.log combined\n</VirtualHost>\n'
                 '<VirtualHost *:443>\n  CustomLog ${APACHE_LOG_DIR}/other_vhosts_access.log vhost_combined\n</VirtualHost>\n')
        for n in ('access.log', 'other_vhosts_access.log', 'error.log'):
            self.put(f'/var/log/apache2/{n}', '')
        d = self.agent._ts_discover({}, NOW)
        self.assertEqual(self.paths(d, 'web'), ['/var/log/apache2/access.log', '/var/log/apache2/other_vhosts_access.log'])
        by = {e['path']: e['spec'] for e in d['web']}
        self.assertTrue(by['/var/log/apache2/other_vhosts_access.log']['format'].startswith('%v:%p'))
        self.assertEqual(self.paths(d, 'err'), ['/var/log/apache2/error.log'])
        self.assertEqual([e['kind'] for e in d['err']], ['apache'])
        self.assertFalse(d['proxied'])

    def test_a_variable_in_a_path_becomes_the_files_that_exist(self):
        self.put('/etc/nginx/nginx.conf', 'http { access_log /var/log/nginx/$host.access.log; }\n')
        for n in ('a.example.access.log', 'b.example.access.log', 'unrelated.log'):
            self.put(f'/var/log/nginx/{n}', '')
        d = self.agent._ts_discover({}, NOW)
        self.assertEqual(self.paths(d, 'web'), ['/var/log/nginx/a.example.access.log', '/var/log/nginx/b.example.access.log'])

    def test_a_stock_install_with_no_config_is_found_by_its_default_files(self):
        self.put('/var/log/nginx/access.log', '')
        self.put('/var/log/nginx/error.log', '')
        self.put('/var/log/fail2ban.log', '')
        d = self.agent._ts_discover({}, NOW)
        self.assertEqual(self.paths(d, 'web'), ['/var/log/nginx/access.log'])
        self.assertEqual(self.paths(d, 'f2b'), ['/var/log/fail2ban.log'])
        self.assertEqual(d['waf'], [])
        self.assertFalse(d['proxied'])

    def test_a_host_without_a_web_server_lists_nothing_and_reports_nothing_missing(self):
        d = self.agent._ts_discover({}, NOW)
        self.assertEqual((d['web'], d['err'], d['waf'], d['f2b']), ([], [], [], []))

    def test_a_logfile_the_config_names_but_that_does_not_exist_is_still_listed(self):
        self.put('/etc/nginx/nginx.conf', 'http { access_log /var/log/nginx/gone.log; }\n')
        d = self.agent._ts_discover({}, NOW)
        self.assertEqual(self.paths(d, 'web'), ['/var/log/nginx/gone.log'])

    def test_off_syslog_pipes_and_devices_are_not_files(self):
        self.put('/etc/nginx/nginx.conf', 'http { access_log off; access_log syslog:server=1.2.3.4 main;\n'
                 ' access_log /dev/stdout; error_log stderr; error_log syslog:server=x; }\n')
        d = self.agent._ts_discover({}, NOW)
        self.assertEqual((d['web'], d['err']), ([], []))

    def test_fail2ban_logging_somewhere_a_file_reader_cannot_go(self):
        self.put('/etc/fail2ban/fail2ban.local', '[Definition]\nlogtarget = SYSLOG\n')
        self.agent._which = lambda prog, _c={}: '/usr/bin/fail2ban-client' if prog == 'fail2ban-client' else None
        d = self.agent._ts_discover({}, NOW)
        self.assertEqual(d['f2b'], [{'path': '', 'configured': True, 'unsupported': True}])

    def test_the_stock_audit_log_locations_are_found_without_a_config(self):
        self.put('/var/log/modsecurity/modsec_audit.log', '')
        self.assertEqual(self.paths(self.agent._ts_discover({}, NOW), 'waf'), ['/var/log/modsecurity/modsec_audit.log'])


class TestOperatorPaths(_Host):
    """The one path that arrives over the network is held to the narrowest rule."""

    def test_a_file_under_var_log_is_accepted_and_routed_by_name(self):
        for n in ('app/access.log', 'app/error.log', 'app/modsec_audit.log', 'app/fail2ban-extra.log'):
            self.put(f'/var/log/{n}', '')
        d = self.agent._ts_discover({'paths': ['/var/log/app/access.log', '/var/log/app/error.log',
                                               '/var/log/app/modsec_audit.log', '/var/log/app/fail2ban-extra.log']}, NOW)
        self.assertEqual(self.paths(d, 'web'), ['/var/log/app/access.log'])
        self.assertEqual(self.paths(d, 'err'), ['/var/log/app/error.log'])
        self.assertEqual(self.paths(d, 'waf'), ['/var/log/app/modsec_audit.log'])
        self.assertEqual(self.paths(d, 'f2b'), ['/var/log/app/fail2ban-extra.log'])
        self.assertIsNone(d['web'][0]['spec'], 'no format is known, so every reader is tried')

    def test_nothing_outside_var_log_is_ever_read(self):
        self.put('/etc/shadow', 'root:$6$x:1:0:99999:7:::\n')
        self.put('/srv/app/access.log', '')
        self.put('/var/lib/x.log', '')
        (self.tmp / 'var/log').mkdir(parents=True, exist_ok=True)
        os.symlink(self.tmp / 'etc/shadow', self.tmp / 'var/log/shadow.log')      # a symlink out of /var/log
        os.symlink(self.tmp / 'etc', self.tmp / 'var/log/etc-dir')
        (self.tmp / 'var/log/adir').mkdir()
        bad = ['/etc/shadow', '/srv/app/access.log', '/var/lib/x.log', '/var/log/shadow.log',
               '/var/log/etc-dir/shadow', '/var/log/../../etc/shadow', '/var/log/adir', '/var/log/missing.log',
               'var/log/relative.log', '', None, 7, ['/var/log/x'], '/var/log/' + 'a' * 400, '/var/log/x\x00.log']
        d = self.agent._ts_discover({'paths': bad}, NOW)
        self.assertEqual((d['web'], d['err'], d['waf'], d['f2b']), ([], [], [], []), bad)
        for p in bad:
            self.assertIsNone(self.agent._ts_operator_path(p), p)

    def test_at_most_twenty_paths(self):
        for i in range(30):
            self.put(f'/var/log/many/{i}.log', '')
        d = self.agent._ts_discover({'paths': [f'/var/log/many/{i}.log' for i in range(30)]}, NOW)
        self.assertEqual(len(d['web']), 20)


# ── one pass over a tviweb01-shaped host ───────────────────────────────────────

class TestOnePass(_Host):
    def setUp(self):
        super().setUp()
        tree_nginx(self)
        T = ts_nginx
        seclog = ''.join(
            combined(A1, NOW - 90 + i, 'GET /.env HTTP/1.1', 404, 'zgrab/0.x') + f' rt=0.00{i % 10}\n' for i in range(6))
        seclog += ''.join(combined(A3, NOW - 80 + i, "GET /?id=1' union select 1,2-- HTTP/1.1", 403) + ' rt=0.001\n'
                          for i in range(4))
        seclog += combined('10.0.0.5', NOW - 5, 'GET /.env HTTP/1.1', 404) + ' rt=0.001\n'
        seclog += combined(A4, NOW - 4, 'GET / HTTP/1.1', 200) + ' rt=0.001\n'
        self.put('/var/log/nginx/access.log', seclog)
        self.put('/var/log/nginx/blocked.log', ''.join(
            combined(A2, NOW - 70 + i, 'GET /wp-config.php.bak HTTP/1.1', 403) + '\n' for i in range(5)))
        self.put('/var/log/nginx/request-length.log', ''.join(f'{A1} {i}\n' for i in range(30)))
        self.put('/var/log/nginx/example.access.log', '')
        self.put('/var/log/nginx/error.log', ''.join([
            ngx_modsec(NOW - 60, A1, '1790000001.1', 942100, 'attack-sqli', 'SQL Injection Attack Detected', denied=True),
            f'{ts_nginx_err(NOW - 50)} [error] 1#1: *9 user "admin" was not found in "/etc/nginx/.htpasswd", client: {A4}, server: example.com\n'.rstrip('\n'),
        ]) + '\n')
        self.put('/var/log/modsec_audit.log', ''.join(audit_native(NOW - 55 + i, A1, f'a{i:07d}') for i in range(3)))
        self.put('/var/log/fail2ban.log', ''.join([
            f'{ts_iso_local(NOW - 40)} fail2ban.actions        [1]: NOTICE  [nginx-blocked] Ban {A2}\n',
            f'{ts_iso_local(NOW - 39)} fail2ban.actions        [1]: NOTICE  [sshd] Ban {A3}\n']))

    def cfg(self):
        return {'enabled': True, 'paths': []}

    def test_every_source_is_read_and_summarised(self):
        events, sources, dropped, st = self.agent.collect_threat_events(self.cfg(), {}, NOW)
        ev = {e['ip']: e for e in events}
        self.assertEqual(set(ev), {A1, A2, A3}, 'the private source, the one-line visitor and the 1-hit login are not')
        a1 = ev[A1]
        self.assertEqual(a1['src']['web'], 6)
        self.assertEqual(a1['src']['waf'], 3, 'three audit transactions; the error-log line is one of them')
        self.assertIn('req:probe', a1['tok']['web'])
        self.assertIn('crs:942100', a1['tok']['waf'])
        self.assertEqual(ev[A2]['ban'], ['nginx-blocked'])
        self.assertEqual(ev[A2]['src']['web'], 5, 'blocked.log was discovered from the config')
        self.assertEqual(ev[A3]['ban'], ['sshd'])
        by = {(s['kind'], s['path']): s for s in sources}
        self.assertEqual(by[('web', '/var/log/nginx/access.log')]['state'], 'ok')
        self.assertEqual(by[('web', '/var/log/nginx/access.log')]['fmt'], 'custom')
        self.assertTrue(by[('web', '/var/log/nginx/access.log')]['proxied'])
        self.assertEqual(by[('web', '/var/log/nginx/example.access.log')]['state'], 'idle')
        self.assertEqual(by[('waf', '/var/log/modsec_audit.log')]['fmt'], 'native')
        self.assertEqual(by[('waf', '/var/log/modsec_audit.log')]['events'], 3)
        self.assertEqual(by[('f2b', '/var/log/fail2ban.log')]['parsed'], 2)
        self.assertEqual(by[('err', '/var/log/nginx/error.log')]['state'], 'ok')

    def test_a_log_in_a_layout_it_cannot_read_says_unparsed_instead_of_silently_counting_nothing(self):
        events, sources, _, _ = self.agent.collect_threat_events(self.cfg(), {}, NOW)
        rl = [s for s in sources if s['path'].endswith('request-length.log')][0]
        self.assertEqual((rl['lines'] >= 30, rl['parsed'], rl['state']), (True, 0, 'unparsed'))

    def test_the_second_pass_sees_nothing_new_and_a_retry_sees_the_same(self):
        a = self.agent
        events, sources, dropped, st = a.collect_threat_events(self.cfg(), {}, NOW)
        again = a.collect_threat_events(self.cfg(), st, NOW)
        self.assertEqual(again[0], [], 'every line was consumed')
        self.assertTrue(all(s['state'] in ('idle', 'unparsed') or s['lines'] == 0 for s in again[1]
                            if s['kind'] != 'web' or not s['path'].endswith('request-length.log')), again[1])
        retry = a.collect_threat_events(self.cfg(), {}, NOW)       # the first submission failed
        self.assertEqual([e['ip'] for e in retry[0]], [e['ip'] for e in events])
        self.assertEqual(retry[0][0]['src'], events[0]['src'], 'a retry from the same place is the same answer')

    def test_state_is_not_modified_by_a_pass(self):
        st = {'files': {}, 'cs_last_id': 5}
        before = json.dumps(st, sort_keys=True)
        self.agent.collect_threat_events(self.cfg(), st, NOW)
        self.assertEqual(json.dumps(st, sort_keys=True), before)

    def test_lines_written_after_a_pass_are_the_only_ones_in_the_next(self):
        a = self.agent
        _, _, _, st = a.collect_threat_events(self.cfg(), {}, NOW)
        with open(self.tmp / 'var/log/nginx/access.log', 'a') as f:
            for i in range(5):
                f.write(combined(A4, NOW + i, 'GET /.git/config HTTP/1.1', 404) + ' rt=0.001\n')
        events, sources, _, st2 = a.collect_threat_events(self.cfg(), st, NOW + 10)
        self.assertEqual([e['ip'] for e in events], [A4])
        self.assertEqual(events[0]['src'], {'web': 5})

    def test_discovery_is_cached_between_passes_and_redone_when_stale_or_the_paths_change(self):
        a = self.agent
        calls = []
        real = a._ts_discover
        a._ts_discover = lambda cfg, now: (calls.append(1), real(cfg, now))[1]
        self.addCleanup(setattr, a, '_ts_discover', real)
        _, _, _, st = a.collect_threat_events(self.cfg(), {}, NOW)
        a.collect_threat_events(self.cfg(), st, NOW + 30)
        self.assertEqual(len(calls), 1)
        a.collect_threat_events(self.cfg(), st, NOW + a.THREAT_DISCOVER_S + 1)
        self.assertEqual(len(calls), 2)
        a.collect_threat_events({'enabled': True, 'paths': ['/var/log/x.log']}, st, NOW + 30)
        self.assertEqual(len(calls), 3)

    def test_out_of_time_defers_the_rest_to_the_next_pass(self):
        events, sources, _, st = self.agent.collect_threat_events(self.cfg(), {}, NOW, budget_s=-1)
        self.assertEqual(events, [])
        self.assertTrue(all(s['state'] == 'idle' and s['lines'] == 0 for s in sources if s['kind'] != 'cs'), sources)
        later = self.agent.collect_threat_events(self.cfg(), st, NOW)
        self.assertTrue(later[0], 'nothing was lost by running out of time')

    def test_rotation_between_passes(self):
        a = self.agent
        _, _, _, st = a.collect_threat_events(self.cfg(), {}, NOW)
        log = self.tmp / 'var/log/nginx/access.log'
        os.rename(log, str(log) + '.1')
        log.write_text(''.join(combined(A4, NOW + i, 'GET /.env HTTP/1.1', 404) + ' rt=0.001\n' for i in range(4)))
        events, *_ = a.collect_threat_events(self.cfg(), st, NOW + 5)
        self.assertEqual({e['ip'] for e in events}, {A4})

    def test_the_summary_is_small(self):
        events, sources, dropped, _ = self.agent.collect_threat_events(self.cfg(), {}, NOW)
        self.assertLess(len(json.dumps({'events': events, 'sources': sources})), 20_000)


class TestNothingLeaks(_Host):
    """Everything an attacker or a visitor wrote stays on the host."""

    MARKERS = ('LEAKUA', 'leak-ref.example', 'LEAKPATH', 'leakuser', 'leak-vhost.example', 'LEAKQUERY',
               'leak-server.example', 'LEAKHEADER', 'LEAKBODY')

    def test_no_log_text_reaches_what_is_sent(self):
        a = self.agent
        tree_nginx(self)
        fmt_line = lambda ip, i, req, st: (  # noqa: E731
            f'{ip} - leakuser [{ts_nginx(NOW - 30 + i)}] "{req}" {st} 153 "https://leak-ref.example/" '
            f'"Mozilla/5.0 LEAKUA zgrab" rt=0.001')
        self.put('/var/log/nginx/access.log', ''.join(
            fmt_line(A1, i, 'GET /LEAKPATH/.env?LEAKQUERY=1 HTTP/1.1', 404) + '\n' for i in range(6)))
        self.put('/var/log/nginx/error.log', ngx_modsec(
            NOW - 20, A1, '1790000001.1', 942100, 'attack-sqli', 'SQL Injection LEAKHEADER',
            denied=True, uri='/LEAKPATH/leak-vhost.example').replace('example.com', 'leak-server.example') + '\n')
        self.put('/var/log/modsec_audit.log', audit_native(
            NOW - 25, A1, 'bbbb0001', ua='LEAKUA', uri='/LEAKPATH/x?LEAKQUERY=1').replace(
            'a response body that must never be read or kept', 'LEAKBODY'))
        events, sources, dropped, _ = a.collect_threat_events({'enabled': True}, {}, NOW)
        self.assertTrue(events, 'the control: something was found')
        wire = json.dumps({'events': events, 'sources': sources, 'dropped': dropped})
        for marker in self.MARKERS:
            self.assertNotIn(marker, wire, f'{marker} left the host')
        # and what IS there is the vocabulary
        te_dir = str(_ROOT / 'server' / 'cgi-bin')
        sys.path.insert(0, te_dir)
        import threat_evidence as te
        for e in events:
            norm = te.normalize_event(e, now=NOW)
            self.assertIsNotNone(norm)
            for fam, toks in e['tok'].items():
                for t in toks:
                    self.assertTrue(te.token_valid(t), f'{t} is not in the vocabulary')
            self.assertEqual(norm['tok'], e['tok'], 'the server would keep every token the agent sent')


# ── the thread ─────────────────────────────────────────────────────────────────

class TestThread(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.agent = load_agent('agent_threat_thread')

    def setUp(self):
        a = self.agent
        self.tmp = Path(tempfile.mkdtemp(prefix='rp-ts-thread-'))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        a.THREAT_STATE_FILE = self.tmp / 'state.json'
        self.seen_states, self.submits, self.saved = [], [], []
        self.outcomes = []
        self.events = [{'ip': A1, 'src': {'web': 5}, 'tok': {'web': {'req:probe': 5}}}]
        self.step = 0

        def fake_collect(cfg, state, now=None, budget_s=0):
            self.seen_states.append(dict(state))
            self.step += 1
            ev = self.events if self.step == 1 else []
            return ev, [{'kind': 'web', 'path': '/var/log/a', 'state': 'ok'}], 0, {'files': {'n': self.step}, 'sig': state.get('sig', '')}

        def fake_submit(creds, events, sources, dropped, now):
            self.submits.append((list(events), list(sources)))
            return self.outcomes.pop(0) if self.outcomes else 'ok'
        self.real = (a.collect_threat_events, a._ts_submit, a._ts_state_save)
        a.collect_threat_events, a._ts_submit = fake_collect, fake_submit
        a._ts_state_save = lambda st: self.saved.append(json.loads(json.dumps(st)))
        self.addCleanup(lambda: (setattr(a, 'collect_threat_events', self.real[0]),
                                 setattr(a, '_ts_submit', self.real[1]), setattr(a, '_ts_state_save', self.real[2])))

    def run_thread(self, cfg, until, timeout=5):
        stop = threading.Event()
        holder = {'cfg': cfg}
        t = threading.Thread(target=self.agent._threat_sensor_thread,
                             args=({'server_url': 'https://x', 'device_id': 'd', 'token': 't'}, holder, stop, 0.01, 0.01),
                             daemon=True)
        t.start()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not until():
            time.sleep(0.01)
        stop.set()
        t.join(timeout=3)
        self.assertFalse(t.is_alive(), 'the thread did not stop')
        return holder

    def test_offsets_move_only_after_the_server_has_the_result(self):
        self.outcomes = ['retry', 'retry', 'ok']
        self.run_thread({'enabled': True}, lambda: len(self.saved) >= 1)
        self.assertGreaterEqual(len(self.submits), 3)
        # the failed tries were all handed the SAME starting state: nothing moved
        self.assertEqual(self.seen_states[0], self.seen_states[1])
        self.assertEqual(self.seen_states[1], self.seen_states[2])
        # it was saved once, after the third attempt went through, with that attempt's result
        self.assertEqual(self.saved[0]['files'], {'n': 3})

    def test_a_submission_the_server_refuses_for_good_is_dropped_not_repeated(self):
        self.outcomes = ['drop']
        self.run_thread({'enabled': True}, lambda: len(self.saved) >= 1)
        self.assertEqual(self.saved[0]['files'], {'n': 1})
        self.assertEqual(len(self.submits), 1)

    def test_a_quiet_pass_with_unchanged_sources_sends_nothing_but_still_moves_on(self):
        self.outcomes = ['ok']
        self.run_thread({'enabled': True}, lambda: len(self.saved) >= 3)
        self.assertEqual(len(self.submits), 1, 'only the pass with news (and the first status) was sent')
        self.assertGreaterEqual(len(self.saved), 3)

    def test_disabled_means_the_logs_are_not_touched(self):
        holder = self.run_thread({'enabled': False}, lambda: False, timeout=0.3)
        self.assertEqual((self.seen_states, self.submits), ([], []))

    def test_a_collector_that_raises_does_not_kill_the_thread(self):
        a = self.agent
        n = []

        def boom(*args, **kw):
            n.append(1)
            raise RuntimeError('a log was not what it looked like')
        a.collect_threat_events = boom
        self.run_thread({'enabled': True}, lambda: len(n) >= 3)
        self.assertGreaterEqual(len(n), 3, 'it kept trying')

    def test_a_pass_that_cannot_reach_the_server_backs_off(self):
        self.outcomes = ['retry'] * 50
        times = []
        inner = self.agent._ts_submit

        def stamped(*args, **kw):
            times.append(time.monotonic())
            return inner(*args, **kw)
        self.agent._ts_submit = stamped
        self.run_thread({'enabled': True}, lambda: len(times) >= 5)
        self.assertGreaterEqual(len(times), 5)
        gaps = [b - a for a, b in zip(times, times[1:])]
        self.assertGreater(gaps[3], gaps[0] * 2, f'the wait did not grow: {gaps}')


class TestSubmit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.agent = load_agent('agent_threat_submit')

    def run_with(self, exc=None, result=None):
        a = self.agent
        sent = []

        def fake_post(url, data, timeout=10):
            sent.append((url, data))
            if exc:
                raise exc
            return result or {'ok': True}
        real = a.http_post
        a.http_post = fake_post
        try:
            out = a._ts_submit({'server_url': 'https://rp.example', 'device_id': 'd1', 'token': 'tok'},
                               [{'ip': A1}], [{'kind': 'web'}], 2, NOW)
        finally:
            a.http_post = real
        return out, sent

    def test_the_payload_and_the_outcomes(self):
        import urllib.error
        out, sent = self.run_with()
        self.assertEqual(out, 'ok')
        url, body = sent[0]
        self.assertEqual(url, 'https://rp.example/api/threat-events')
        self.assertEqual((body['device_id'], body['token'], body['at'], body['dropped']), ('d1', 'tok', NOW, 2))
        self.assertEqual(set(body), {'device_id', 'token', 'at', 'sources', 'events', 'dropped'})
        for code, want in ((500, 'retry'), (503, 'retry'), (429, 'retry'), (408, 'retry'),
                           (400, 'drop'), (403, 'drop'), (404, 'drop'), (422, 'drop')):
            err = urllib.error.HTTPError('u', code, 'x', {}, io.BytesIO(b''))
            self.addCleanup(err.close)
            self.assertEqual(self.run_with(exc=err)[0], want, code)
        self.assertEqual(self.run_with(exc=OSError('unreachable'))[0], 'retry')
        self.assertEqual(self.run_with(exc=ValueError('Server URL must use HTTPS'))[0], 'retry')


# ── pins: what must stay true of the source ────────────────────────────────────

class TestSourcePins(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = (_ROOT / 'client' / 'remotepower-agent.py').read_text()
        a = cls.src.index('# Threat sensor (v7.2.0)')
        cls.block = cls.src[a:cls.src.index('def heartbeat(creds, interval=POLL_INTERVAL):')]

    def test_the_twin_is_identical(self):
        self.assertEqual((_ROOT / 'client' / 'remotepower-agent.py').read_bytes(),
                         (_ROOT / 'client' / 'remotepower-agent').read_bytes())

    def test_the_block_was_found_and_is_substantial(self):
        self.assertGreater(len(self.block.splitlines()), 800)
        self.assertIn('def collect_threat_events', self.block)
        self.assertIn('def _threat_sensor_thread', self.block)

    def test_the_heartbeat_reads_the_setting_and_a_busy_reply_cannot_switch_it_off(self):
        i = self.src.index("resp.get('threat_sensor')")
        guard = self.src[self.src.rindex("if resp.get('busy') is not True:", 0, i):i]
        self.assertIn("resp.get('busy') is not True", guard)
        tail = self.src[i:i + 900]
        self.assertIn("_tsc.get('enabled')", tail)
        self.assertIn('daemon=True', tail)
        self.assertIn('_threat_stop.set()', tail)

    def test_nothing_in_the_sensor_runs_a_shell_or_evaluates_text(self):
        import re
        for bad in ('shell=True', 'os.system', 'os.popen', '__import__', 'pickle', 'yaml.load', 'marshal'):
            self.assertNotIn(bad, self.block, bad)
        # calls to the builtins, not `re.compile(` (the lookbehind skips a dotted name)
        self.assertEqual(re.findall(r'(?<![\w.])(?:eval|exec|compile)\(', self.block), [])

    def test_the_only_programs_it_runs_are_named_in_the_source(self):
        import re
        runs = re.findall(r'subprocess\.\w+\(\s*\[([^\]]+)\]', self.block)
        self.assertEqual(len(runs), 1, runs)
        self.assertTrue(runs[0].startswith('cscli,'), runs[0])

    def test_the_only_thing_it_sends_over_the_network_is_the_threat_events_post(self):
        import re
        self.assertEqual(re.findall(r'http_(?:post|get|get_binary)\(([^)]*)\)', self.block),
                         ["f\"{creds['server_url']}/api/threat-events\", payload, timeout=20"])
        for bad in ('urlopen', 'socket.', 'requests.', 'http.client', '_OPENER'):
            self.assertNotIn(bad, self.block, bad)

    def test_the_log_root_and_the_caps_are_what_the_docs_say(self):
        import re

        def const(name):
            return re.search(rf'^{name}\s*=\s*(.+?)(?:\s+#.*)?$', self.block, re.M).group(1)
        self.assertEqual(const('THREAT_LOG_ROOT'), "'/var/log'")
        self.assertEqual(const('THREAT_MAX_EVENTS'), '300')
        self.assertEqual(const('THREAT_MIN_HITS'), '3')
        self.assertEqual(const('THREAT_LOOKBACK_S'), '6 * 3600')
        self.assertEqual(const('THREAT_READ_CAP'), '8_000_000')


class TestThroughput(_Host):
    def test_sixty_thousand_lines_in_a_few_seconds(self):
        """A smoke alarm, not a benchmark: a regex that backtracks, or a scan that
        went quadratic, shows up here as seconds."""
        a = self.agent
        import random
        rng = random.Random(7)
        legit = ['GET / HTTP/1.1', 'GET /assets/app.js?v=7 HTTP/1.1', 'GET /api/v1/items?page=3 HTTP/1.1',
                 'POST /api/orders HTTP/1.1', 'GET /blog/2026/10/some-long-article-title HTTP/1.1']
        bad = ['GET /.env HTTP/1.1', "GET /?id=1' union select 1,2-- HTTP/1.1", 'GET /../../etc/passwd HTTP/1.1',
               'POST /wp-login.php HTTP/1.1', 'GET /phpmyadmin/ HTTP/1.1']
        lines = []
        for i in range(60_000):
            ip = f'45.{rng.randint(1, 250)}.{rng.randint(1, 250)}.{rng.randint(1, 250)}'
            req = rng.choice(bad if i % 6 == 0 else legit)
            lines.append(combined(ip, NOW - rng.randint(0, 600), req, rng.choice((200, 200, 404, 403)),
                                  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36'))
        agg = a._TsAgg(NOW)
        parse = a._ts_access_parser(None)[1]
        t0 = time.monotonic()
        n, parsed = a._ts_scan_access(lines, parse, agg, 'x', NOW)
        took = time.monotonic() - t0
        self.assertEqual((n, parsed), (60_000, 60_000))
        self.assertLess(took, 8.0, f'60k lines took {took:.1f}s')


if __name__ == '__main__':
    unittest.main()

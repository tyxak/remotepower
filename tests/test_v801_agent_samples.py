"""The agent's samples: what the logs show an address asking for (8.0.1).

The sensor sent counts and tokens. For an address that CrowdSec had banned on an AppSec rule it sent a decision and nothing about the request,
so the page could not say what the address had done and the server could not class it. The agent now keeps up to three samples for an address
(method, path without its query string, status, the log) when the server's `threat_sensor` setting says `samples`, and sends them with it.

Three kinds of request become samples:
  * the request that was the evidence: a hostile one in the access log, a ModSecurity or AppSec refusal, a request the web server refused;
  * the CrowdSec bouncer's own line, "[Crowdsec] denied ... (by appsec)", which is a WAF refusal and is read from the part of the line before
    `, client:` (what follows is the request, which its sender wrote);
  * for an address a ban engine decided on, the refused requests it made in the last few minutes (the ring). Nothing else leaves the host: a
    refused request from an address nobody flagged is remembered for a few minutes and dropped.

The lines below are shaped like the ones read on a live host; names are replaced and the addresses are ones the sensor accepts as public.
"""
import json
import os
import random
import shutil
import string
import sys
import tempfile
import types
import unittest
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'server' / 'cgi-bin'))

from test_v720_threat_sensor_agent import A1, A2, A3, NOW, audit_native, combined, cs_alert, ngx_modsec, ts_nginx_err  # noqa: E402
from test_v720_threat_sensor_cycle import _Host, tree_nginx  # noqa: E402
from test_v749_agent_threat_regex import run_child  # noqa: E402
from test_v801_evidence_samples import PATHS  # noqa: E402

import threat_evidence as te  # noqa: E402

ERRLOG = '/var/log/nginx/error.log'
ACCESS = '/var/log/nginx/access.log'
# a srcset list glued into an image URL, then the same with a trailing slash: the request pair read on a live host
SRCSET = ('/wp-content/uploads/2024/11/Photo-768x1024.jpg%20768w,%20https:/shop.example.test/wp-content/uploads/2024/11/'
          'Photo-225x300.jpg%20225w/')
SRCSET_CLEAN = '/wp-content/uploads/2024/11/Photo-768x1024.jpg%20768w...'


def bouncer(e, ip, by='appsec', target=SRCSET):
    return (f"{ts_nginx_err(e)} [alert] 1122606#0: *30321 [lua] crowdsec.lua:850: Allow(): [Crowdsec] denied '{ip}' with 'ban' (by {by}), "
            f'client: {ip}, server: shop.example.test, request: "GET {target} HTTP/2.0", host: "shop.example.test", '
            'referrer: "https://shop.example.test/"')


def errline(e, ip, msg, req):
    return f'{ts_nginx_err(e)} [error] 1#1: *7 {msg}, client: {ip}, server: shop.example.test, request: "{req} HTTP/1.1", host: "shop.example.test"'


def server_agrees(test, events):
    """Every sample an event carries is what the server would rebuild it as: the two cleaners, end to end."""
    n = 0
    for e in events:
        for s in e.get('smp') or ():
            test.assertEqual(te.normalize_sample(s, now=NOW), s)
            n += 1
    return n


class _Base(_Host):
    def agg(self, samples=True, now=NOW):
        a = self.agent._TsAgg(now)
        a.want_samples = samples
        return a

    @staticmethod
    def by_ip(agg):
        return {e['ip']: e for e in agg.events()[0]}


class TestTheTwoCleanersAgree(_Base):
    def test_every_target_of_the_server_table(self):
        for raw, _want in PATHS:
            self.assertEqual(self.agent._ts_clean_path(raw), te.clean_path(raw), repr(raw))

    def test_fuzz(self):
        rnd = random.Random(8011)
        pool = string.printable + '\u00e9\u202e\uff0f\x00\x7f%?#;:<>"\'`${}()[]\\|^~' * 3
        for _ in range(3000):
            raw = rnd.choice(('', '/', '/a/', '/b/c')) + ''.join(rnd.choice(pool) for _ in range(rnd.choice((0, 3, 40, 100, 300))))
            self.assertEqual(self.agent._ts_clean_path(raw), te.clean_path(raw), repr(raw))

    def test_the_numbers_and_lists_are_the_same(self):
        a = self.agent
        self.assertEqual(a.THREAT_SAMPLES, te.MAX_SAMPLES)
        self.assertEqual(a.THREAT_PATH_MAX, te.SAMPLE_PATH_MAX)
        self.assertEqual(set(a._TS_SAMPLE_METHODS), set(te._SAMPLE_METHODS))
        for raw in (403, '404', 99, 600, 'x', None, True, 403.9, 10 ** 30):
            self.assertEqual(a._ts_status(raw), te._sample_status(raw), repr(raw))


class TestSamplesFromEachLog(_Base):
    def setUp(self):
        super().setUp()
        # a plain web or error-log address needs three hits to be sent (TestAccessScan holds that); these tests are about the samples
        self.addCleanup(setattr, self.agent, 'THREAT_MIN_HITS', self.agent.THREAT_MIN_HITS)
        self.agent.THREAT_MIN_HITS = 1

    def scan_err(self, agg, lines):
        self.agent._ts_scan_nginx_error(lines, agg, ERRLOG, NOW)

    def scan_access(self, agg, lines):
        self.agent._ts_scan_access(lines, self.agent._ts_access_parser(None)[1], agg, ACCESS, NOW)

    # ── CrowdSec's bouncer ──────────────────────────────────────────────────────
    def test_the_bouncers_appsec_line_is_a_waf_refusal_with_its_request(self):
        agg = self.agg()
        self.scan_err(agg, [bouncer(NOW - 30, A1)])
        ev = self.by_ip(agg)[A1]
        self.assertEqual(ev['src'], {'waf': 1})
        self.assertEqual(ev['tok'], {'waf': {'cs:appsec': 1}})
        self.assertEqual(ev['blk'], 1)
        self.assertEqual(ev['smp'], [{'f': 'waf', 'm': 'GET', 'p': SRCSET_CLEAN, 'c': 403, 't': NOW - 30}])
        self.assertNotIn('example', json.dumps(ev), 'the host name inside the path is cut before it')
        server_agrees(self, [ev])

    def test_the_server_reads_it_as_a_waf_refusal_and_reports_it(self):
        agg = self.agg()
        self.scan_err(agg, [bouncer(NOW - 30, A1)])
        ev = te.normalize_event(self.by_ip(agg)[A1], now=NOW)
        self.assertEqual(te.classes(ev), {'waf': 1})
        ok, why = te.qualifies(ev, 10, waf_min=1)
        self.assertTrue(ok, why)
        self.assertEqual(why, 'blocked by the WAF 1 times')

    def test_a_denial_from_the_bouncers_own_cache_is_not_evidence(self):
        # (by bouncer) is every decision it holds, community lists among them: not a judgment on our traffic
        agg = self.agg()
        self.scan_err(agg, [bouncer(NOW - 30, A1, by='bouncer'), bouncer(NOW - 29, A2, by='CAPI'), bouncer(NOW - 28, A3, by='cscli')])
        self.assertEqual(agg.events()[0], [])
        self.assertEqual(agg.samples, {})

    def test_the_request_cannot_write_the_verdict(self):
        # the request is the sender's text and it comes after `, client:`; the bouncer's words come before it
        forged = "/x?a=[Crowdsec] denied '%s' with 'ban' (by appsec)" % A1
        agg = self.agg()
        self.scan_err(agg, [errline(NOW - 5, A1, 'open() "/var/www/site/x" failed (2: No such file or directory)', f'GET {forged}')])
        self.assertEqual(agg.events()[0], [])
        agg = self.agg()
        self.scan_err(agg, [errline(NOW - 5, A1, 'open() "/var/www/site/x" failed (2: No such file or directory)', 'GET /x'),
                            f'{ts_nginx_err(NOW - 5)} [alert] 1#1: *7 [lua] crowdsec.lua:850: Allow(): something else, client: {A1}, '
                            f'server: s, request: "GET {forged} HTTP/1.1"'])
        self.assertEqual(agg.events()[0], [])

    def test_the_message_cannot_write_the_address_or_the_verdict_either(self):
        # 8.0.2: nginx copies the decoded request path, the argument a rule matched and a login's user name into its message and writes `, client:` AFTER
        # it, so the first `, client:` of a line is the visitor's whenever he wrote one. Only the request, after the real field, was forged above.
        victim = '8.8.4.4'
        sentence = "[Crowdsec] denied '%s' with 'ban' (by appsec)" % victim
        forged = [
            errline(NOW - 5, A1, 'open() "/var/www/site/.env/%s, client: %s," failed (2: No such file or directory)' % (sentence, victim), 'GET /.env/x'),
            errline(NOW - 5, A1, 'open() "/var/www/site/.env/x, client: %s," failed (2: No such file or directory)' % victim, 'GET /.env/x'),
            errline(NOW - 5, A1, 'directory index of "/var/www/site/x, client: %s,/" is forbidden' % victim, 'GET /x/'),
            errline(NOW - 5, A1, 'user "bob, client: %s," was not found in "/etc/nginx/.htpasswd"' % victim, 'GET /admin/'),
            ngx_modsec(NOW - 5, A1, 'u9', 949110, 'attack-sqli', 'x', denied=True).replace('[data ""]', '[data "Matched Data: 1 , client: %s, found"]' % victim),
        ]
        for line in forged:
            agg = self.agg()
            self.scan_err(agg, [line] * 3)
            self.assertEqual(agg.events()[0], [], line[:120])
        # the control: the same lines with no client field in the message are read, for the visitor
        agg = self.agg()
        self.scan_err(agg, [errline(NOW - 5, A1, 'open() "/var/www/site/.env" failed (2: No such file or directory)', 'GET /.env')])
        self.assertEqual(sorted(self.by_ip(agg)), [A1])

    def test_a_pattern_over_hostile_text_is_linear(self):
        out, timed_out = run_child('''
            import re
            texts = ["[Crowdsec] denied '" * 3000, "[Crowdsec] denied '1.1.1.1' with '" * 600, "(by appsec" * 5000,
                     "x" * 8000 + "[Crowdsec] denied '", ":" * 8000]
            worst = 0.0
            for t in texts:
                t0 = time.perf_counter()
                agent._TS_CS_APPSEC_RE.search(t[:8192])
                worst = max(worst, time.perf_counter() - t0)
            for t in ("/" + "a:/" * 600, "/" + "a" * 100000 + "?", "/" + "%" * 5000, "/" + "https:/" * 300, "/" + "-" * 9000):
                t0 = time.perf_counter()
                agent._ts_clean_path(t)
                worst = max(worst, time.perf_counter() - t0)
            print(json.dumps({"worst": worst}))
        ''', timeout=30)
        self.assertFalse(timed_out)
        self.assertLess(json.loads(out)['worst'], 0.5)

    # ── the other lines of the error log ────────────────────────────────────────
    def test_a_modsecurity_refusal_carries_the_request_without_its_query(self):
        agg = self.agg()
        self.scan_err(agg, [ngx_modsec(NOW - 10, A2, 'u1', 942100, 'attack-sqli', 'SQL Injection', denied=True)])
        ev = self.by_ip(agg)[A2]
        self.assertEqual(ev['smp'], [{'f': 'waf', 'm': 'GET', 'p': '/index.php', 'c': 403, 't': NOW - 10}])
        self.assertNotIn('union', json.dumps(ev).lower(), 'the query string, which holds the payload, stays home')

    def test_a_warning_that_blocked_nothing_has_no_status(self):
        agg = self.agg()
        self.scan_err(agg, [ngx_modsec(NOW - 10, A2, 'u2', 942100, 'attack-sqli', 'SQL Injection', denied=False)])
        self.assertEqual(self.by_ip(agg)[A2]['smp'][0]['c'], 0)

    def test_a_forbidden_request_a_rate_limit_and_a_failed_login(self):
        agg = self.agg()
        self.scan_err(agg, [
            errline(NOW - 9, A1, 'access forbidden by rule', 'GET /.git/config'),
            errline(NOW - 8, A2, 'limiting requests, excess: 5.100 by zone "perip"', 'GET /api/search?q=x'),
            errline(NOW - 7, A3, 'user "admin" was not found in "/etc/nginx/.htpasswd"', 'GET /admin/'),
        ])
        got = {ip: e['smp'] for ip, e in self.by_ip(agg).items()}
        self.assertEqual(got[A1], [{'f': 'err', 'm': 'GET', 'p': '/.git/config', 'c': 403, 't': NOW - 9}])
        self.assertEqual(got[A2], [{'f': 'err', 'm': 'GET', 'p': '/api/search', 'c': 0, 't': NOW - 8}])
        self.assertEqual(got[A3], [{'f': 'err', 'm': 'GET', 'p': '/admin/', 'c': 401, 't': NOW - 7}])

    def test_a_file_probe_names_the_request_never_the_path_on_disk(self):
        agg = self.agg()
        self.scan_err(agg, [errline(NOW - 5, A1, 'open() "/var/www/site/.env" failed (2: No such file or directory)', 'GET /.env')])
        ev = self.by_ip(agg)[A1]
        self.assertEqual(ev['smp'], [{'f': 'err', 'm': 'GET', 'p': '/.env', 'c': 404, 't': NOW - 5}])
        self.assertNotIn('/var/www', json.dumps(ev), 'the document root is in the message and does not leave')

    # ── the access log ──────────────────────────────────────────────────────────
    def test_a_hostile_request_is_a_sample_and_its_query_stays_home(self):
        agg = self.agg()
        self.scan_access(agg, [combined(A1, NOW - 20, "GET /index.php?id=1' union select 1,2,password from users-- HTTP/1.1", 200),
                               combined(A1, NOW - 19, 'GET /.env HTTP/1.1', 404),
                               combined(A1, NOW - 18, 'GET /wp-config.php.bak HTTP/1.1', 404)])
        ev = self.by_ip(agg)[A1]
        self.assertEqual([(s['m'], s['p'], s['c']) for s in ev['smp']],
                         [('GET', '/index.php', 200), ('GET', '/.env', 404), ('GET', '/wp-config.php.bak', 404)])
        self.assertNotIn('union', json.dumps(ev).lower())
        self.assertNotIn('password', json.dumps(ev).lower())

    def test_the_first_three_distinct_requests_are_kept(self):
        agg = self.agg()
        lines = [combined(A1, NOW - 30 + i, f'GET /backup{i}.sql HTTP/1.1', 404) for i in range(8)]
        lines.append(combined(A1, NOW - 1, 'GET /backup0.sql HTTP/1.1', 404))
        self.scan_access(agg, lines)
        smp = self.by_ip(agg)[A1]['smp']
        self.assertEqual([s['p'] for s in smp], ['/backup0.sql', '/backup1.sql', '/backup2.sql'])

    def test_nothing_is_kept_unless_the_server_asks(self):
        agg = self.agg(samples=False)
        self.scan_access(agg, [combined(A1, NOW - 20 + i, f'GET /backup{i}.sql HTTP/1.1', 404) for i in range(5)])
        self.scan_err(agg, [bouncer(NOW - 5, A2)])
        self.assertTrue(all('smp' not in e for e in agg.events()[0]))
        self.assertEqual((agg.samples, agg.ring, agg.ring_out()), ({}, {}, {}))

    def test_a_modsecurity_audit_transaction_is_a_sample(self):
        agg = self.agg()
        lines = audit_native(NOW - 12, A2, 'abcd1234').splitlines()
        self.agent._ts_scan_modsec_native(lines, agg, '/var/log/modsec_audit.log', NOW)
        ev = self.by_ip(agg)[A2]
        self.assertEqual([(s['f'], s['m'], s['p'], s['c']) for s in ev['smp']], [('waf', 'GET', '/index.php', 403)])
        server_agrees(self, [ev])

    # ── the refused requests an engine's decision is about ─────────────────────
    def test_a_refused_request_is_remembered_and_nothing_more(self):
        agg = self.agg()
        self.scan_access(agg, [combined(A1, NOW - 20, 'GET /old-page HTTP/1.1', 404), combined(A2, NOW - 19, 'GET /index.html HTTP/1.1', 200)])
        self.assertEqual(agg.events()[0], [], 'a 404 is not evidence; nobody flagged the address')
        self.assertEqual(list(agg.ring), [A1], 'only the refused one, and only in memory')
        self.assertEqual(agg.ring[A1][0][2:], ('/old-page', 404))

    def test_a_ban_engines_decision_brings_the_refused_requests_with_it(self):
        agg = self.agg()
        self.scan_access(agg, [combined(A1, NOW - 21, 'GET /wp-content/uploads/2024/11/photo.jpg HTTP/1.1', 301),
                               combined(A1, NOW - 20, 'GET /wp-content/uploads/2024/11/photo.jpg/ HTTP/1.1', 403)])
        alerts = [cs_alert(7, 'crowdsecurity/generic-wordpress-uploads-listing', A1, events=1)]
        self.agent._ts_cscli_alerts(json.dumps(alerts), agg, NOW, 0)
        ev = self.by_ip(agg)[A1]
        self.assertEqual(ev['dec'], 1)
        self.assertEqual(ev['smp'], [{'f': 'web', 'm': 'GET', 'p': '/wp-content/uploads/2024/11/photo.jpg/', 'c': 403, 't': NOW - 20}])
        server_agrees(self, [ev])

    def test_the_decision_can_arrive_a_pass_later(self):
        first = self.agg()
        self.scan_access(first, [combined(A1, NOW - 20, 'GET /gone/ HTTP/1.1', 403)])
        carried = first.ring_out()
        second = self.agg(now=NOW + 60)
        second.ring_prev = carried
        self.agent._ts_cscli_alerts(json.dumps([cs_alert(8, 'crowdsecurity/ssh-bf', A1, events=9, e=NOW + 50)]), second, NOW + 60, 0)
        ev = self.by_ip(second)[A1]
        self.assertEqual([s['p'] for s in ev['smp']], ['/gone/'])

    def test_what_is_old_is_dropped(self):
        first = self.agg()
        self.scan_access(first, [combined(A1, NOW - 20, 'GET /gone/ HTTP/1.1', 403)])
        late = self.agg(now=NOW + self.agent.THREAT_RING_KEEP_S + 60)
        late.ring_prev = first.ring_out()
        self.agent._ts_cscli_alerts(json.dumps([cs_alert(9, 'crowdsecurity/ssh-bf', A1, events=9, e=NOW + 900)]), late, late.now, 0)
        self.assertNotIn('smp', self.by_ip(late)[A1])
        self.assertEqual(late.ring_out(), {})

    def test_a_ring_of_a_pass_that_asked_for_nothing_is_never_read(self):
        agg = self.agg(samples=False)
        agg.ring_prev = {A1: [(NOW - 5, 'GET', '/x', 403)]}
        self.agent._ts_cscli_alerts(json.dumps([cs_alert(9, 'crowdsecurity/ssh-bf', A1, events=9)]), agg, NOW, 0)
        self.assertNotIn('smp', self.by_ip(agg)[A1])

    def test_the_ring_is_bounded(self):
        agg = self.agg()
        for i in range(self.agent.THREAT_RING_ADDRS + 500):
            agg.refused_request(f'45.{i // 65536 % 256}.{i // 256 % 256}.{i % 256}', 'GET', '/x', 404, NOW)
        self.assertEqual(len(agg.ring), self.agent.THREAT_RING_ADDRS)
        agg.refused_request(next(iter(agg.ring)), 'GET', '/a', 404, NOW)
        for n in range(10):
            agg.refused_request('45.0.0.0', 'GET', f'/p{n}', 404, NOW + n)
        self.assertEqual(len(agg.ring['45.0.0.0']), self.agent.THREAT_SAMPLES)
        self.assertEqual([e[2] for e in agg.ring['45.0.0.0']], ['/p7', '/p8', '/p9'], 'the newest few')
        self.assertLessEqual(len(agg.ring_out()), self.agent.THREAT_RING_ADDRS)

    def test_a_request_seen_twice_is_one_sample(self):
        agg = self.agg()
        for i in range(4):
            agg.refused_request(A1, 'GET', '/same', 404, NOW - 10 + i)
        self.assertEqual(len(agg.ring[A1]), 1)
        self.assertEqual(agg.ring[A1][0][0], NOW - 7)

    def test_a_plain_web_address_gets_only_the_requests_that_were_hostile(self):
        # the ring is for an address an engine decided on; one that was only counted for hostile requests is sent what was hostile.
        # One hostile request, so two of the three places are free: a fill from the ring would show in them.
        agg = self.agg()
        lines = [combined(A1, NOW - 40, 'GET /backup0.sql HTTP/1.1', 404)]
        lines += [combined(A1, NOW - 30 + i, f'GET /harmless-{i} HTTP/1.1', 404) for i in range(5)]
        self.scan_access(agg, lines)
        self.assertEqual(len(agg.ring[A1]), self.agent.THREAT_SAMPLES, 'the control: the ring does hold harmless requests of this address')
        ev = self.by_ip(agg)[A1]
        self.assertEqual(ev['src'], {'web': 1})
        self.assertEqual([s['p'] for s in ev['smp']], ['/backup0.sql'])
        self.assertNotIn('harmless', json.dumps(ev))

    def test_the_evidence_comes_first_and_the_ring_fills_the_rest(self):
        agg = self.agg()
        self.scan_access(agg, [combined(A1, NOW - 30, 'GET /a HTTP/1.1', 404), combined(A1, NOW - 29, 'GET /b HTTP/1.1', 404),
                               combined(A1, NOW - 28, 'GET /c HTTP/1.1', 404)])
        self.scan_err(agg, [bouncer(NOW - 5, A1)])
        smp = self.by_ip(agg)[A1]['smp']
        self.assertEqual(smp[0]['f'], 'waf')
        self.assertEqual(len(smp), 3)
        self.assertEqual(len({(s['m'], s['p']) for s in smp}), 3)


class TestWhatIsWrittenToDisk(_Base):
    def test_the_state_file_leaves_the_ring_out(self):
        tmp = Path(tempfile.mkdtemp(prefix='rp-ts-state-'))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        saved = self.agent.THREAT_STATE_FILE
        self.agent.THREAT_STATE_FILE = tmp / 'state.json'
        self.addCleanup(setattr, self.agent, 'THREAT_STATE_FILE', saved)
        self.agent._ts_state_save({'files': {'/x': {'pos': 3}}, 'carry': {}, '_ring': {A1: [(NOW, 'GET', '/x', 403)]}})
        on_disk = json.loads((tmp / 'state.json').read_text())
        self.assertEqual(set(on_disk), {'files', 'carry'})
        self.assertNotIn('/x', json.dumps({k: v for k, v in on_disk.items() if k != 'files'}))


class TestOnePassOverARealLayout(_Base):
    CFG: Any = {'enabled': True, 'paths': [], 'samples': True}

    def lay_out(self):
        tree_nginx(self)
        self.put(ACCESS, '\n'.join([
            combined(A1, NOW - 40, f'GET {SRCSET[:-1]} HTTP/2.0', 301),
            combined(A1, NOW - 39, f'GET {SRCSET} HTTP/2.0', 403),
            combined(A2, NOW - 38, 'GET /gone HTTP/1.1', 404),
        ]) + '\n')
        self.put(ERRLOG, bouncer(NOW - 39, A1) + '\n')

    def test_the_address_the_bouncer_refused_comes_with_what_it_asked_for(self):
        self.lay_out()
        events, _sources, _dropped, state = self.agent.collect_threat_events(self.CFG, {}, NOW)
        got = {e['ip']: e for e in events}
        self.assertEqual(set(got), {A1}, 'the visitor who got a 404 is not evidence of anything')
        self.assertEqual(got[A1]['src'], {'waf': 1})
        # the bouncer's line and the access log's 403 are one request: it is one sample, from the line that was the evidence
        self.assertEqual([(s['f'], s['p'], s['c']) for s in got[A1]['smp']], [('waf', SRCSET_CLEAN, 403)])
        self.assertIn(A2, state['_ring'], 'the 404 is remembered for the next pass')
        server_agrees(self, events)

    def test_the_refused_requests_cross_to_the_next_pass_through_the_state(self):
        a = self.agent
        self.lay_out()
        out = {'text': '[]'}

        def fake_run(argv, **kw):
            return types.SimpleNamespace(returncode=0, stdout=out['text'], stderr='')

        a._which = lambda prog, _c={}: '/usr/bin/cscli'            # found when the logs are discovered, so it is asked every pass
        real = a.subprocess.run
        a.subprocess.run = fake_run
        self.addCleanup(setattr, a.subprocess, 'run', real)
        _e, _s, _d, state1 = a.collect_threat_events(self.CFG, {}, NOW)
        self.assertIn(A2, state1['_ring'], 'pass one remembered the 404')
        # a minute later nothing new is in the logs, and CrowdSec has now decided on the address that asked
        out['text'] = json.dumps([cs_alert(21, 'crowdsecurity/ssh-bf', A2, events=9, e=NOW + 50)])
        events, _s, _d, state2 = a.collect_threat_events(self.CFG, state1, NOW + 60)
        got = {e['ip']: e for e in events}
        self.assertEqual([x['p'] for x in got[A2]['smp']], ['/gone'], 'the state carried the request to the pass that needed it')
        self.assertEqual(state2['_ring'][A2][0][2], '/gone')

    def test_without_the_servers_say_nothing_is_added(self):
        self.lay_out()
        events, _s, _d, state = self.agent.collect_threat_events({'enabled': True, 'paths': []}, {}, NOW)
        self.assertEqual({e['ip'] for e in events}, {A1}, 'the AppSec refusal is still a WAF refusal')
        self.assertTrue(all('smp' not in e for e in events))
        self.assertNotIn('_ring', state)

    def test_the_whole_submission_stays_small(self):
        a = self.agent
        agg = a._TsAgg(NOW)
        agg.want_samples = True
        for i in range(a.THREAT_MAX_EVENTS + 40):
            ip = f'45.{i // 256}.{i % 256}.9'
            for n in range(5):
                agg.hit('waf', ERRLOG, ip, NOW, ['cs:appsec'], 1, blk=1)
                agg.sample(ip, 'waf', 'GET', f'/{n}' + '.' * 300, 403, NOW)       # dots: a run of letters and digits that long is read as a token since 8.0.2 and the five samples would be one
        events, dropped = agg.events()
        self.assertEqual(len(events), a.THREAT_MAX_EVENTS)
        self.assertGreater(dropped, 0)
        self.assertLess(len(json.dumps(events)), 250_000)
        self.assertTrue(all(len(e['smp']) == a.THREAT_SAMPLES for e in events))


class TestTheAddressesThatWereStuck(_Base):
    """The case that started it: CrowdSec banned the address on an AppSec rule, and Threat Intel said "nothing recognisable in the logs"."""

    def stuck(self, scenario):
        agg = self.agg()
        self.agent._ts_scan_access([combined(A1, NOW - 40, f'GET {SRCSET[:-1]} HTTP/2.0', 301),
                                    combined(A1, NOW - 39, f'GET {SRCSET} HTTP/2.0', 403)],
                                   self.agent._ts_access_parser(None)[1], agg, ACCESS, NOW)
        self.agent._ts_cscli_alerts(json.dumps([cs_alert(11, scenario, A1, events=1, e=NOW - 39)]), agg, NOW, 0)
        return te.normalize_event(self.by_ip(agg)[A1], now=NOW)

    def test_the_uploads_listing_rule_is_wordpress_probing_and_reports(self):
        ev = self.stuck('crowdsecurity/generic-wordpress-uploads-listing')
        self.assertEqual(te.classes(ev), {'wordpress': 1})
        self.assertEqual(te.attack_phrase(ev), 'WordPress probing', 'a kind of probing, named')
        self.assertEqual(te.qualifies(ev, 10), (True, 'confirmed by CrowdSec'))
        self.assertEqual([s['p'] for s in ev['smp']], [SRCSET_CLEAN])

    def test_a_name_with_no_category_says_so_and_still_shows_the_request(self):
        ev = self.stuck('crowdsecurity/http-generic-test')
        self.assertEqual(te.qualifies(ev, 10), (False, 'no attack category for the CrowdSec scenario crowdsecurity/http-generic-test'))
        self.assertEqual(len(ev['smp']), 1)


if __name__ == '__main__':
    os.environ.setdefault('TMPDIR', tempfile.gettempdir())
    unittest.main()

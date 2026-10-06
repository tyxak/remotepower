"""ip_intel: what a report says and how the services answer it.

Pure parts only (the sweep that uses them is covered with the engine). A report
is public and filed under the operator's account, so the words come from fixed
phrases and numbers; and a repeat report is an answer, not a failure.
"""
import json
import sys
import time
import unittest
from pathlib import Path
from urllib.parse import parse_qs

_CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

import ip_intel  # noqa: E402
import threat_evidence as te  # noqa: E402

ATTACKER = '185.220.101.7'
NOW = 1_790_000_000


def ev(**kw):
    raw = {'ip': ATTACKER, 'first': NOW - 600, 'last': NOW}
    raw.update(kw)
    out = te.normalize_event(raw, now=NOW)
    assert out is not None, raw
    return out


SQLI = dict(src={'web': 41, 'waf': 12},
            tok={'web': {'req:sqli': 30, 'req:traversal': 11}, 'waf': {'crs:942100': 12}})


class TestPlaceholders(unittest.TestCase):
    def test_the_five_placeholders(self):
        self.assertEqual(ip_intel.COMMENT_PLACEHOLDERS,
                         ('what', 'count', 'minutes', 'attack', 'seen_by'))
        self.assertIsNone(ip_intel.comment_template_error('{attack}: {count} tries, seen by {seen_by}'))

    def test_a_host_a_user_or_an_address_still_cannot_be_named(self):
        for bad in ('{hostname} attacked', '{device} x{count} tries', '{ip} {count} tries here',
                    '{user} {attack} here', '{path} {attack} here'):
            self.assertIsNotNone(ip_intel.comment_template_error(bad), bad)

    def test_the_shortest_rendering_must_clear_sniffcats_minimum(self):
        # `{seen_by}` alone can be as short as "WAF" and `{what}` as "SSH"
        self.assertIsNotNone(ip_intel.comment_template_error('{seen_by}'))
        self.assertIsNotNone(ip_intel.comment_template_error('{what}'))
        self.assertIsNone(ip_intel.comment_template_error('{attack}'))
        self.assertIsNone(ip_intel.comment_template_error('{what} abc {count} {minutes}'))

    def test_the_older_report_still_says_what_it_said_and_takes_the_new_placeholders(self):
        self.assertEqual(ip_intel.report_comment('ssh', 42, 600),
                         'SSH brute force: 42 failed attempts within 10 minutes (reported by RemotePower)')
        t = '{attack}, {count} tries in {minutes}m, seen by {seen_by}'
        self.assertEqual(ip_intel.report_comment('ssh', 42, 600, t),
                         'SSH brute force, 42 tries in 10m, seen by system log')
        self.assertEqual(ip_intel.report_comment('web', 5, 120, t),
                         'web login brute force, 5 tries in 2m, seen by web server log')


class TestEvidenceComment(unittest.TestCase):
    def test_default_wording(self):
        self.assertEqual(
            ip_intel.evidence_comment(ev(**SQLI)),
            'SQL injection and path traversal: 41 attempts within 10 minutes, '
            'seen by web server log and WAF (reported by RemotePower)')

    def test_a_cve_the_logs_named_rides_along(self):
        e = ev(src={'waf': 4}, tok={'waf': {'crs:944150': 4}}, cve=['CVE-2021-44228'])
        self.assertIn('remote code execution attempts (CVE-2021-44228)', ip_intel.evidence_comment(e))

    def test_the_operators_wording_is_used_for_both_kinds_of_report(self):
        t = '{what} attack: {attack}, {count} tries in {minutes}m'
        self.assertEqual(ip_intel.evidence_comment(ev(**SQLI), t),
                         'web attack: SQL injection and path traversal, 41 tries in 10m')
        self.assertEqual(ip_intel.evidence_comment(ev(ban=['sshd']), t),
                         'SSH attack: SSH brute force, 1 tries in 10m')

    def test_an_unusable_template_falls_back_to_the_evidence_default(self):
        for bad in ('x', '{host} bad {count}', 'y' * 301, '{seen_by}'):
            self.assertTrue(ip_intel.evidence_comment(ev(**SQLI), bad).endswith('(reported by RemotePower)'), bad)

    def test_one_line_and_inside_the_services_limits(self):
        c = ip_intel.evidence_comment(ev(**SQLI), 'first line here\nsecond {attack}')
        self.assertNotIn('\n', c)
        stuffed = ('{attack}' * 37)[:300]
        big = ev(src={'web': 50}, cve=['CVE-2021-44228', 'CVE-2022-22965'],
                 tok={'web': {f'req:{k}': 50 for k in ('sqli', 'xss', 'rce', 'probe', 'scanner')}},
                 ban=['sshd'], dec=1)
        for t in (None, stuffed):
            c = ip_intel.evidence_comment(big, t)
            self.assertLessEqual(len(c), 1000)
            self.assertGreaterEqual(len(c), 10)

    def test_attacker_text_never_reaches_the_comment(self):
        marker = 'ZZPWNEDZZ'
        e = te.normalize_event({
            'ip': ATTACKER, 'src': {'web': 9, 'waf': 4, 'f2b': 2, 'cs': 1},
            'tok': {'web': {'req:sqli': 9, f'jail:{marker}': 9, f'cs:{marker}/x': 9,
                            f'crstag:attack-{marker.lower()}': 9, f'req:{marker}': 9},
                    'f2b': {f'jail:{marker}': 2}},
            'ban': [marker + 'jail', 'sshd'], 'cve': [marker, 'CVE-2021-44228'],
            'first': NOW - 60, 'last': NOW}, now=NOW)
        for t in (None, '{what} {attack} {seen_by} {count} {minutes}'):
            self.assertNotIn(marker.lower(), ip_intel.evidence_comment(e, t).lower())


class TestProviderOutcomes(unittest.TestCase):
    ABUSE_DUP = {'errors': [{'detail': 'You can only report the same IP address (`185.220.101.7`) '
                                       'once in 15 minutes.', 'status': 429}]}
    ABUSE_DAILY = {'errors': [{'detail': 'Daily rate limit of 1000 requests exceeded for this endpoint.',
                               'status': 429}]}
    SNIFF_429 = {'success': False, 'status': 429,
                 'message': 'Submission rate limit exceeded or repeated report for the same IP'}
    # The body SniffCat returned for a repeat, as it appears in a live fail2ban log.
    SNIFF_DUP = {'success': False, 'status': 429,
                 'message': 'You can only report this IP once every 20 minutes. Try again in 426 seconds.'}

    def test_abuseipdb_repeat_is_a_duplicate_not_a_failure(self):
        r = ip_intel.abuseipdb_parse_report(429, self.ABUSE_DUP)
        self.assertEqual((r['ok'], r.get('duplicate')), (False, True))
        self.assertEqual(r['error'], 'already reported a moment ago')

    def test_abuseipdbs_daily_limit_is_still_a_rate_limit(self):
        r = ip_intel.abuseipdb_parse_report(429, self.ABUSE_DAILY)
        self.assertFalse(r.get('duplicate'))
        self.assertTrue(r['rate_limited'])
        self.assertEqual(r['error'], 'rate limited')
        self.assertFalse(ip_intel.abuseipdb_parse_report(429, {})['ok'])

    def test_sniffcat_429_is_ambiguous_and_says_so(self):
        r = ip_intel.sniffcat_parse_report(429, self.SNIFF_429)
        self.assertEqual((r['ok'], r['rate_limited'], r.get('duplicate')), (False, True, None))
        self.assertEqual(r['error'], 'rate limited or already reported')

    def test_a_sniffcat_repeat_that_says_so_is_a_duplicate(self):
        r = ip_intel.sniffcat_parse_report(429, self.SNIFF_DUP)
        self.assertEqual((r['ok'], r.get('duplicate'), r['rate_limited']), (False, True, True))
        self.assertEqual(r['error'], 'already reported a moment ago')

    def test_a_sniffcat_429_with_no_such_sentence_stays_ambiguous(self):
        for body in (self.SNIFF_429, {}, {'message': 'Too many requests'}, 'rate limited', None):
            r = ip_intel.sniffcat_parse_report(429, body)
            self.assertFalse(r.get('duplicate'), body)
            self.assertEqual(r['error'], 'rate limited or already reported', body)

    def test_success_and_the_other_errors_are_as_before(self):
        self.assertTrue(ip_intel.abuseipdb_parse_report(200, {})['ok'])
        self.assertTrue(ip_intel.sniffcat_parse_report(200, {'success': True})['ok'])
        self.assertFalse(ip_intel.sniffcat_parse_report(200, {'success': False})['ok'])
        self.assertTrue(ip_intel.abuseipdb_parse_report(401, {})['auth'])
        self.assertEqual(ip_intel.abuseipdb_parse_report(422, {'errors': [{'detail': 'bad category'}]})['error'],
                         'bad category')
        self.assertEqual(ip_intel.abuseipdb_parse_report(403, {})['error'], 'refused by the provider (HTTP 403)')
        # a lookup that is rate limited keeps its older shape
        self.assertTrue(ip_intel.abuseipdb_parse_check(429, {})['rate_limited'])

    def test_the_retry_wait_outlasts_each_services_repeat_window(self):
        self.assertGreater(ip_intel.REPORT_RETRY_S['abuseipdb'], 15 * 60)
        self.assertGreater(ip_intel.REPORT_RETRY_S['sniffcat'], 20 * 60)
        self.assertEqual(set(ip_intel.REPORT_RETRY_S), set(ip_intel.PROVIDERS))


class TestTimestamp(unittest.TestCase):
    def test_iso_utc_bounds(self):
        self.assertEqual(ip_intel.iso_utc(NOW - 90, now=NOW), time.strftime(
            '%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(NOW - 90)))
        self.assertTrue(ip_intel.iso_utc(NOW - 90, now=NOW).endswith('+00:00'))
        self.assertIsNone(ip_intel.iso_utc(NOW + 5, now=NOW), 'a future time')
        self.assertIsNone(ip_intel.iso_utc(NOW - 86401, now=NOW), 'older than a day')
        for bad in (None, 'x', [], float('inf')):
            self.assertIsNone(ip_intel.iso_utc(bad, now=NOW), bad)

    def test_abuseipdb_gets_the_time_only_when_given_and_recent(self):
        t = int(time.time()) - 400
        form = parse_qs(ip_intel.abuseipdb_report_request(ATTACKER, 'k' * 80, [21], 'a comment here', t)['body'].decode())
        self.assertRegex(form['timestamp'][0], r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00$')
        plain = parse_qs(ip_intel.abuseipdb_report_request(ATTACKER, 'k' * 80, [21], 'a comment here')['body'].decode())
        self.assertNotIn('timestamp', plain)
        old = parse_qs(ip_intel.abuseipdb_report_request(
            ATTACKER, 'k' * 80, [21], 'a comment here', int(time.time()) - 3 * 86400)['body'].decode())
        self.assertNotIn('timestamp', old)

    def test_sniffcat_accepts_the_argument_and_never_sends_it(self):
        body = json.loads(ip_intel.sniffcat_report_request(
            ATTACKER, 's' * 40, [12, 21], 'a comment here', int(time.time()) - 400)['body'])
        self.assertEqual(set(body), {'ip', 'categories', 'comment'})
        self.assertEqual(body['categories'], [12, 21])


class TestInfrastructureIsNeverReported(unittest.TestCase):
    def test_a_cloudflare_edge_address_is_refused_with_its_own_reason(self):
        self.assertEqual(ip_intel.never_block_reason('104.16.5.5', []), 'a Cloudflare edge address')
        self.assertEqual(ip_intel.never_block_reason('2606:4700::1111', []), 'a Cloudflare edge address')

    def test_the_other_reasons_are_as_before(self):
        self.assertEqual(ip_intel.never_block_reason(ATTACKER, []), '')
        self.assertEqual(ip_intel.never_block_reason('10.0.0.5', []), 'not a public address')
        nets = ip_intel.parse_cidrs(['185.220.101.0/24'])
        self.assertEqual(ip_intel.never_block_reason(ATTACKER, nets), 'on the never-block list')


if __name__ == '__main__':
    unittest.main()

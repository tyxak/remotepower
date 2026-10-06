"""Threat intel: the report message is the operator's to write, and the API usage limits are settable.

Reports went out with one fixed sentence and only the lookup limit could be changed
(not from the page). The message is now a template with placeholders, none
of which can carry a host name; reports have their own daily limit like lookups do;
and the settings handler takes all of it.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs
import json

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-ipi-msg-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import ip_intel  # noqa: E402
from test_ip_intel import _Case, ATTACKER  # noqa: E402

SECOND = '185.220.101.8'
DEFAULT = 'SSH brute force: 40 failed attempts within 10 minutes (reported by RemotePower)'


class TestTemplate(unittest.TestCase):
    def test_default_wording_is_unchanged(self):
        self.assertEqual(DEFAULT, ip_intel.report_comment('ssh', 40, 600))
        self.assertEqual(DEFAULT, ip_intel.report_comment('ssh', 40, 600, ''))
        self.assertIn('web login brute force', ip_intel.report_comment('web', 3, 120))

    def test_placeholders_render(self):
        t = '{what}: {count} tries in {minutes} min, handled automatically'
        self.assertEqual('SSH: 40 tries in 10 min, handled automatically',
                         ip_intel.report_comment('ssh', 40, 600, t))

    def test_only_the_named_placeholders_exist_so_a_host_cannot_leak_in(self):
        # v7.2.0: five of them now (what, count, minutes, attack, seen_by), still
        # all counts or fixed phrases; none can name a host, a user or an address.
        for bad in ('{hostname} attacked', 'attack on {device} x{count}', '{ip} {count} tries here'):
            self.assertIsNotNone(ip_intel.comment_template_error(bad), bad)
        self.assertIsNone(ip_intel.comment_template_error('{what} brute force, {count} attempts'))

    def test_length_limits_and_control_characters(self):
        self.assertIsNotNone(ip_intel.comment_template_error('short'))
        self.assertIsNotNone(ip_intel.comment_template_error('x' * 301))
        self.assertEqual('line one line two', ip_intel.clean_comment_template(' line one\nline two '))
        self.assertNotIn('\n', ip_intel.report_comment('ssh', 5, 600, 'first line here\nsecond line {count}'))

    def test_an_unusable_stored_template_falls_back_to_the_default(self):
        self.assertEqual(DEFAULT, ip_intel.report_comment('ssh', 40, 600, 'x'))
        self.assertEqual(DEFAULT, ip_intel.report_comment('ssh', 40, 600, '{host} bad {count}'))


class TestSweepUsesThem(_Case):
    def _posts(self):
        return [c for c in self.calls if c['method'] == 'POST']

    def test_the_custom_message_reaches_both_services(self):
        self.policy(report_enabled=True, report_min_count=1,
                    report_comment='{what} attack, {count} tries in {minutes}m')
        self.attack(count=40)
        self.sweep()
        posts = self._posts()
        self.assertEqual(2, len(posts))
        ab = [p for p in posts if 'abuseipdb' in p['url']][0]
        sc = [p for p in posts if 'sniffcat' in p['url']][0]
        self.assertEqual('SSH attack, 40 tries in 10m', parse_qs(ab['body'].decode())['comment'][0])
        self.assertEqual('SSH attack, 40 tries in 10m', json.loads(sc['body'])['comment'])

    def test_without_a_template_the_default_is_sent(self):
        self.policy(report_enabled=True, report_min_count=1)
        self.attack(count=40)
        self.sweep()
        ab = [p for p in self._posts() if 'abuseipdb' in p['url']][0]
        self.assertEqual(DEFAULT, parse_qs(ab['body'].decode())['comment'][0])

    def test_the_daily_report_limit_stops_reports_and_is_counted(self):
        self.policy(report_enabled=True, report_min_count=1, daily_report_budget=1)
        self.attack(count=40)
        self.attack(ip=SECOND, count=40)
        st = self.sweep()
        self.assertEqual(2, len(self._posts()), 'one report per service, then the limit')
        self.assertEqual(1, st['budget']['report:abuseipdb'])
        self.assertEqual(1, st['budget']['report:sniffcat'])
        errs = [str(a.get('errors')) for a in st['attackers'].values()]
        self.assertTrue(any('daily report limit' in e for e in errs), errs)

    def test_a_zero_report_limit_sends_nothing_but_lookups_still_run(self):
        self.policy(report_enabled=True, report_min_count=1, daily_report_budget=0)
        self.attack(count=40)
        st = self.sweep()
        self.assertEqual([], self._posts())
        self.assertEqual(100, st['attackers'][ATTACKER]['verdict']['score'])


class TestSettingsHandler(_Case):
    def call(self, fn, method='GET', body=None, role='admin'):
        self.api.verify_token = lambda _t=None: ('alice', role)
        self.api.method = lambda: method
        self.api.get_json_obj = lambda: dict(body or {})
        self.cap.clear()
        try:
            fn()
        except self.api.HTTPError:
            pass
        self.api._LOAD_CACHE.clear()
        return self.cap.get('status'), self.cap.get('data') or {}

    def _save(self, **body):
        return self.call(self.api.handle_ip_intel_settings, 'POST', body)

    def _view(self):
        return self.call(self.api.handle_ip_intel)[1]['settings']

    def test_the_view_shows_the_default_message_and_both_limits(self):
        s = self._view()
        self.assertEqual(ip_intel.REPORT_COMMENT_DEFAULT, s['report_comment'])
        self.assertEqual((900, 900, 24), (s['daily_lookup_budget'], s['daily_report_budget'], s['cache_hours']))

    def test_a_custom_message_and_limits_are_saved(self):
        st, d = self._save(report_comment='{what} brute force x{count}', daily_report_budget='50',
                           daily_lookup_budget='200', cache_hours='6')
        self.assertEqual(200, st, d)
        s = self._view()
        self.assertEqual('{what} brute force x{count}', s['report_comment'])
        self.assertEqual((200, 50, 6), (s['daily_lookup_budget'], s['daily_report_budget'], s['cache_hours']))

    def test_limits_are_clamped_not_trusted(self):
        self._save(daily_report_budget='99999999', cache_hours='0')
        s = self._view()
        self.assertEqual(1000000, s['daily_report_budget'])
        self.assertEqual(1, s['cache_hours'])

    def test_a_bad_message_is_refused_and_changes_nothing(self):
        self._save(report_comment='{what} first version here')
        for bad in ('{hostname} hit', 'tiny', 'x' * 400):
            st, d = self._save(report_comment=bad)
            self.assertEqual(400, st, bad)
            self.assertIn('error', d)
        self.assertEqual('{what} first version here', self._view()['report_comment'])

    def test_blank_or_the_default_text_goes_back_to_the_default(self):
        self._save(report_comment='{what} custom wording {count}')
        self._save(report_comment='')
        self.assertEqual(ip_intel.REPORT_COMMENT_DEFAULT, self._view()['report_comment'])
        self._save(report_comment='{what} custom wording {count}')
        self._save(report_comment=ip_intel.REPORT_COMMENT_DEFAULT)
        cfg = self.api.load(self.api.CONFIG_FILE)
        self.assertNotIn('report_comment', cfg['ip_intel'])

    def test_only_admins_can_change_it(self):
        st, _ = self.call(self.api.handle_ip_intel_settings, 'POST', {'report_comment': '{what} hello there'}, role='viewer')
        self.assertEqual(403, st)


if __name__ == '__main__':
    unittest.main()

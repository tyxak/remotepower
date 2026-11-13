"""Each service has limits of its own, and the day's counts an older version kept are corrected once (8.0.1).

Found on a live instance: SniffCat allows far more than 900 reports a day (8,800 on that key) and AbuseIPDB's free plan about 1,000, but one number
(900) applied to both, the blocklist's four downloads a day was a constant (SniffCat allowed 16), and a day of failed tries had filled the report count
of an older version. Now:

  * `limit_<service>_<lookups|reports|downloads>` (blank = the general number, or 4 downloads), read by ip_intel.limit_for at every place a limit is read;
  * a day's record written before 8.0.1 (it has no `v`) reads its report counts as empty and the next write drops them, once.

The sweep, the blocklist sync and the settings handler run for real; only the socket is replaced.
"""
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v801-limits-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))
import ipintel_store  # noqa: E402
from test_v710_i18n_glue import dict_rows  # noqa: E402
from test_v710_ipintel_settings_js import TestPage as _SettingsPage  # noqa: E402
from test_v801_provider_down import MIN, T, _Sweep  # noqa: E402
from test_v730_edge_blocklist_sync import _Lists  # noqa: E402

import edge_blocklist  # noqa: E402
import ip_intel  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def today(at=T):
    return time.strftime('%Y-%m-%d', time.gmtime(at))


class TestWhichLimitApplies(unittest.TestCase):
    POL = dict(ip_intel.DEFAULTS, daily_lookup_budget=900, daily_report_budget=900)

    def test_a_service_without_a_limit_of_its_own_uses_the_general_number(self):
        for p in ip_intel.PROVIDERS:
            self.assertEqual(ip_intel.limit_for(self.POL, p, 'lookups'), 900)
            self.assertEqual(ip_intel.limit_for(self.POL, p, 'reports'), 900)
            self.assertEqual(ip_intel.limit_for(self.POL, p, 'downloads'), ip_intel.DOWNLOADS_PER_DAY)
        self.assertEqual(ip_intel.DOWNLOADS_PER_DAY, 4)
        self.assertEqual(edge_blocklist.CALLS_PER_DAY, ip_intel.DOWNLOADS_PER_DAY)

    def test_its_own_wins_and_zero_is_a_limit(self):
        pol = dict(self.POL, limit_sniffcat_reports=8800, limit_abuseipdb_lookups=0, limit_sniffcat_downloads=16)
        self.assertEqual(ip_intel.limit_for(pol, 'sniffcat', 'reports'), 8800)
        self.assertEqual(ip_intel.limit_for(pol, 'abuseipdb', 'reports'), 900, 'the other service is not touched')
        self.assertEqual(ip_intel.limit_for(pol, 'abuseipdb', 'lookups'), 0)
        self.assertEqual(ip_intel.limit_for(pol, 'sniffcat', 'downloads'), 16)
        self.assertEqual(ip_intel.limit_for(pol, 'abuseipdb', 'downloads'), 4)

    def test_a_value_that_is_not_a_limit_is_not_read_as_one(self):
        for junk in (None, '', 'x', -1, True, 3.5, [], {}):
            pol = dict(self.POL, limit_sniffcat_reports=junk)
            self.assertEqual(ip_intel.limit_for(pol, 'sniffcat', 'reports'), 900, repr(junk))

    def test_none_of_the_six_is_set_by_default(self):
        for p in ip_intel.PROVIDERS:
            for kind in ip_intel.LIMIT_KINDS:
                self.assertIsNone(ip_intel.DEFAULTS['limit_%s_%s' % (p, kind)])


class TestTheSweepReadsThem(_Sweep):
    def setUp(self):
        super().setUp()
        self.sniff_report = None                       # healthy: this is about the limits
        self.policy(report_enabled=True, lookup_enabled=True, block_enabled=False)

    def test_a_service_with_a_higher_limit_keeps_being_reported_to(self):
        """The case that started it: the general number is small, one service's own is large."""
        self.policy(daily_report_budget=1, limit_sniffcat_reports=5)
        self.queue(3)
        st = self.sweep_at(T + MIN)
        self.assertEqual(len(self.posts('abuseipdb')), 1)
        self.assertEqual(len(self.posts('sniffcat')), 3)
        self.assertEqual((st['budget']['report:abuseipdb'], st['budget']['report:sniffcat']), (1, 3))

    def test_a_service_with_a_lower_limit_stops_at_it_and_the_other_does_not(self):
        self.policy(daily_report_budget=50, limit_sniffcat_reports=1)
        self.queue(3)
        st = self.sweep_at(T + MIN)
        self.assertEqual((len(self.posts('abuseipdb')), len(self.posts('sniffcat'))), (3, 1))
        said = sorted((a.get('errors') or {}).get('sniffcat') or '' for a in st['attackers'].values())
        self.assertEqual(said.count('not reported: the daily report limit is used up'), 2)

    def test_lookups_follow_their_own_limit_too(self):
        self.policy(limit_sniffcat_lookups=2)
        self.queue(3)
        self.sweep_at(T + MIN)
        self.assertEqual((len(self.gets('abuseipdb')), len(self.gets('sniffcat'))), (3, 2))

    def test_with_none_of_them_set_the_general_number_applies_to_both_as_before(self):
        self.policy(daily_report_budget=2)
        self.queue(3)
        self.sweep_at(T + MIN)
        self.assertEqual((len(self.posts('abuseipdb')), len(self.posts('sniffcat'))), (2, 2))

    def test_zero_for_one_service_means_nothing_is_sent_to_it(self):
        self.policy(limit_sniffcat_reports=0)
        self.queue(2)
        self.sweep_at(T + MIN)
        self.assertEqual((len(self.posts('abuseipdb')), len(self.posts('sniffcat'))), (2, 0))


class TestTheBlocklistReadsThem(_Lists):
    def setUp(self):
        super().setUp()
        self.policy(edgelist_abuseipdb=True, edgelist_sniffcat=True)
        cfg = self.api.load(self.api.CONFIG_FILE)
        cfg['abuseipdb_api_key'], cfg['sniffcat_api_key'] = 'a' * 80, 's' * 40
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api._LOAD_CACHE.clear()

    def stale_syncs(self, n):
        """The copy a day old each time and a sync made due again, as every new edge ban does."""
        el = {}
        for i in range(n):
            ipintel_store.update(self.api, edgelist=dict(ipintel_store.read(self.api).get('edgelist') or {}, attempt=0, src={}))
            el = self.tick(at=T + i * 11 * MIN)
        return el

    def test_each_service_downloads_as_often_as_its_own_limit_allows(self):
        self.policy(limit_sniffcat_downloads=1, limit_abuseipdb_downloads=6)
        el = self.stale_syncs(5)
        self.assertEqual(self.downloads['sniffcat'], 1, 'one download, then the limit')
        self.assertEqual(self.downloads['abuseipdb'], 5)
        err = (el['last']['sources'].get('sniffcat') or {}).get('error') or (el['last'].get('failed') or {}).get('sniffcat') or ''
        self.assertIn('used up', err)

    def test_without_a_limit_of_its_own_it_is_four_as_before(self):
        self.stale_syncs(6)
        self.assertEqual((self.downloads['abuseipdb'], self.downloads['sniffcat']), (4, 4))

    def test_the_status_says_what_each_service_may_do(self):
        self.policy(limit_sniffcat_downloads=16)
        st = ipintel_store.read(self.api)
        pol = self.api.ip_intel_policy()
        out = self.api.edge_list_status(st, pol)
        self.assertEqual(out['per_day'], 4)
        self.assertEqual(out['per_day_by'], {'abuseipdb': 4, 'sniffcat': 16})


class TestTheSettings(_Sweep):
    KEYS = ('limit_abuseipdb_lookups', 'limit_abuseipdb_reports', 'limit_abuseipdb_downloads',
            'limit_sniffcat_lookups', 'limit_sniffcat_reports', 'limit_sniffcat_downloads')

    def shown(self):
        return self.call(self.api.handle_ip_intel)[1]['settings']

    def save(self, **body):
        return self.call(self.api.handle_ip_intel_settings, 'POST', body)

    def test_unset_shows_as_none_and_a_number_is_saved_and_shown(self):
        s = self.shown()
        for k in self.KEYS:
            self.assertIn(k, s)
            self.assertIsNone(s[k], k)
        st, d = self.save(limit_sniffcat_reports='8800', limit_sniffcat_downloads=16, limit_abuseipdb_lookups='0')
        self.assertEqual(st, 200, d)
        s = self.shown()
        self.assertEqual((s['limit_sniffcat_reports'], s['limit_sniffcat_downloads'], s['limit_abuseipdb_lookups']), (8800, 16, 0))
        self.assertIsNone(s['limit_abuseipdb_reports'])

    def test_blank_takes_the_limit_away_and_a_save_that_does_not_name_it_leaves_it(self):
        self.save(limit_sniffcat_reports=8800)
        self.save(block_min_score=80)
        self.assertEqual(self.shown()['limit_sniffcat_reports'], 8800)
        self.save(limit_sniffcat_reports='')
        self.assertIsNone(self.shown()['limit_sniffcat_reports'])

    def test_a_number_is_held_to_what_a_service_could_use(self):
        self.save(limit_sniffcat_downloads=99999, limit_abuseipdb_reports=-5, limit_abuseipdb_lookups=10 ** 9)
        s = self.shown()
        self.assertEqual((s['limit_sniffcat_downloads'], s['limit_abuseipdb_reports'], s['limit_abuseipdb_lookups']), (1000, 0, 1000000))

    def test_something_that_is_not_a_number_is_refused_and_changes_nothing(self):
        st, d = self.save(limit_sniffcat_reports='lots')
        self.assertEqual(st, 400, d)
        self.assertEqual(d['error'], 'limit must be a number', 'a fixed sentence the dictionary translates')
        self.assertEqual(d['field'], 'limit_sniffcat_reports', 'the box that was wrong travels in its own field')
        self.assertIsNone(self.shown()['limit_sniffcat_reports'])

    def test_only_an_administrator_changes_them(self):
        st, _ = self.call(self.api.handle_ip_intel_settings, 'POST', {'limit_sniffcat_reports': 5}, role='viewer')
        self.assertEqual(st, 403)
        self.assertIsNone(self.shown()['limit_sniffcat_reports'])

    def test_the_request_model_declares_the_keys(self):
        import request_models
        for k in self.KEYS:
            self.assertIn(k, request_models.IpIntelSettingsRequest.model_fields, k)


@unittest.skipUnless(shutil.which('node'), 'node not installed')
class TestThePage(unittest.TestCase):
    _run = _SettingsPage._run

    def test_the_six_boxes_and_their_words(self):
        html = (ROOT / 'server' / 'html' / 'index.html').read_text()
        card = html[html.index('id="ipintel-limits-card"'):html.index('id="ipintel-report-budget"') + 3000]
        for p in ('abuseipdb', 'sniffcat'):
            for kind in ('lookups', 'reports', 'downloads'):
                self.assertIn('id="ipintel-lim-%s-%s"' % (p, kind), card)
                self.assertIn('for="ipintel-lim-%s-%s"' % (p, kind), card)
        rows = dict_rows()
        for phrase in ('Lookups per day', 'Reports per day', 'Blacklist downloads per day',
                       'Each service can have limits of its own, for example when your plan allows more than the numbers above. '
                       'Leave a box blank to use the number above; blacklist downloads then use 4 a day.'):
            self.assertTrue(rows.get(phrase) and all(rows[phrase].get(l) for l in ('de', 'fr', 'es', 'zh', 'hi', 'ar')), phrase)

    def test_the_page_shows_what_is_stored_and_says_what_a_blank_box_uses(self):
        got = self._run('''
          _ipiFillSettings({daily_lookup_budget: 700, daily_report_budget: 600, limit_sniffcat_reports: 8800, limit_sniffcat_downloads: 16}, {});
          const v = id => els[id].value;
          console.log(JSON.stringify({sr: v('ipintel-lim-sniffcat-reports'), sd: v('ipintel-lim-sniffcat-downloads'), ar: v('ipintel-lim-abuseipdb-reports'),
            al: v('ipintel-lim-abuseipdb-lookups'), ph: [els['ipintel-lim-abuseipdb-reports'].placeholder, els['ipintel-lim-abuseipdb-lookups'].placeholder]}));''')
        self.assertEqual(got, {'sr': 8800, 'sd': 16, 'ar': '', 'al': '', 'ph': ['600', '700']})

    def test_the_page_sends_each_box_and_a_blank_one_goes_as_blank(self):
        got = self._run('''
          for (const id of ['ipintel-lookup-budget', 'ipintel-report-budget']) el(id).value = '900';
          el('ipintel-lim-sniffcat-reports').value = '8800'; el('ipintel-lim-sniffcat-downloads').value = '16';
          el('ipintel-lim-abuseipdb-reports').value = '';
          await saveIpIntelSettings();
          const b = sent.body;
          console.log(JSON.stringify({sr: b.limit_sniffcat_reports, sd: b.limit_sniffcat_downloads, ar: b.limit_abuseipdb_reports,
            keys: Object.keys(b).filter(k => k.startsWith('limit_')).sort()}));''')
        self.assertEqual(got['sr'], '8800')
        self.assertEqual(got['sd'], '16')
        self.assertEqual(got['ar'], '', 'blank must reach the server as blank, which takes the limit away')
        self.assertEqual(len(got['keys']), 6)

    def test_the_usage_line_counts_against_each_services_own_cap(self):
        got = self._run('''
          _ipiFillSettings({daily_lookup_budget: 900, daily_report_budget: 900, limit_sniffcat_reports: 8800},
                           {abuseipdb: 3, sniffcat: 2, 'report:abuseipdb': 7, 'report:sniffcat': 1});
          console.log(JSON.stringify(els['ipintel-budget'].textContent));''')
        self.assertIn('Reports today: AbuseIPDB 7 / 900, SniffCat 1 / 8800', got)
        self.assertIn('Lookups today: AbuseIPDB 3 / 900, SniffCat 2 / 900', got)


class TestTheDaysCountsAnOlderVersionKept(_Sweep):
    def stored(self, **counts):
        ipintel_store.update(self.api, budget=dict({'day': today(T + MIN)}, **counts))

    def setUp(self):
        super().setUp()
        self.sniff_report = None
        self.policy(report_enabled=True, lookup_enabled=True, block_enabled=False)

    def test_what_is_read_from_a_record_with_no_version(self):
        old = {'day': today(T), 'abuseipdb': 49, 'sniffcat': 49, 'report:abuseipdb': 32, 'report:sniffcat': 900}
        got = self.api.ip_intel_handlers_mod._budget_today(old, today(T))
        self.assertEqual(got, {'day': today(T), 'abuseipdb': 49, 'sniffcat': 49, 'v': ip_intel.BUDGET_VERSION})
        self.assertIn('report:sniffcat', old, 'the stored record is not changed by reading it')

    def test_a_record_of_this_version_and_a_new_day_are_read_as_they_are(self):
        cur = {'day': today(T), 'v': ip_intel.BUDGET_VERSION, 'report:sniffcat': 900}
        self.assertIs(self.api.ip_intel_handlers_mod._budget_today(cur, today(T)), cur)
        self.assertEqual(self.api.ip_intel_handlers_mod._budget_today(cur, today(T + 86400)),
                         {'day': today(T + 86400), 'v': ip_intel.BUDGET_VERSION})
        self.assertEqual(self.api.ip_intel_handlers_mod._budget_today(None, today(T))['v'], ip_intel.BUDGET_VERSION)

    def test_a_day_that_a_service_was_down_for_does_not_stop_the_reports_after_the_upgrade(self):
        """What the live instance had: the whole report allowance counted, none of it delivered."""
        self.stored(abuseipdb=49, sniffcat=49, **{'report:abuseipdb': 32, 'report:sniffcat': 900})
        self.queue(2)
        st = self.sweep_at(T + MIN)
        self.assertEqual(len(self.posts('sniffcat')), 2, 'the old count must not hold the reports back')
        self.assertFalse(any('daily report limit' in str((a.get('errors') or {}).get('sniffcat') or '') for a in st['attackers'].values()))
        b = st['budget']
        self.assertEqual(b['v'], ip_intel.BUDGET_VERSION)
        self.assertEqual((b['report:sniffcat'], b['report:abuseipdb']), (2, 2), 'the old report counts are gone, the new ones are in')
        self.assertEqual((b['abuseipdb'], b['sniffcat']), (49 + 2, 49 + 2), 'lookups were not the fault: they stay')

    def test_it_happens_once_and_after_it_the_limit_holds(self):
        self.stored(v=ip_intel.BUDGET_VERSION, **{'report:sniffcat': 900})
        self.queue(2)
        self.sweep_at(T + MIN)
        self.assertEqual(self.posts('sniffcat'), [], 'a count of this version is believed')

    def test_the_page_is_sent_the_days_counts_as_the_sweep_reads_them(self):
        self.stored(sniffcat=49, **{'report:sniffcat': 900})
        st, d = self.call(self.api.handle_ip_intel)
        self.assertEqual(st, 200, d)
        with mock.patch('time.time', return_value=T + MIN):
            st, d = self.call(self.api.handle_ip_intel)
        self.assertNotIn('report:sniffcat', d['budget'])
        self.assertEqual(d['budget']['sniffcat'], 49)
        ipintel_store.update(self.api, budget={'day': today(T - 3 * 86400), 'sniffcat': 700})
        with mock.patch('time.time', return_value=T + MIN):
            st, d = self.call(self.api.handle_ip_intel)
        self.assertEqual(d['budget'].get('sniffcat', 0), 0, "another day's counts are not today's")


if __name__ == '__main__':
    unittest.main()

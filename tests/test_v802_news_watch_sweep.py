#!/usr/bin/env python3
"""8.0.2: the security news watch through the real handlers -- the sweep, what a critical item does, the scan it may start, the three routes and the fetch.

Nothing stands in for fire_webhook: an alert goes through `_record_alert`'s whitelist and `_alert_severity`, which is where a payload key or a severity is lost. Only
`verify_token` is replaced (a stand-in for `require_admin_auth` would pass a handler with no gate), the fetch is a function that returns the bytes of a feed, and the process that
runs a scan is a list that remembers it was asked. The watch is off until an operator switches it on, the feeds and the scan describe the whole installation and are not a tenant's,
and a feed is untrusted input: each of those has its control case here.
"""
import http.server
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from datetime import datetime, timezone
from email.utils import format_datetime
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-newswatch-sweep-'))
_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_TESTS.parent / 'server' / 'cgi-bin'))

import news_watch as N  # noqa: E402
from test_ip_intel import _fresh_api  # noqa: E402
from test_v800_push_mark import _run  # noqa: E402

FEED = 'https://news.example.net/security.xml'
FEED2 = 'https://other.example.org/feed.atom'
HOUR = 3600
EVENT = 'security_news_critical'


def entry(t, title, summary='', guid=None, age=120):
    """One <item> published `age` seconds before the test clock `t`."""
    pub = format_datetime(datetime.fromtimestamp(t - age, tz=timezone.utc), usegmt=True)
    return (f'<item><title><![CDATA[{title}]]></title><description><![CDATA[{summary}]]></description><link>https://news.example.net/{guid or abs(hash(title))}</link>'
            f'<guid isPermaLink="false">{guid or title}</guid><pubDate>{pub}</pubDate></item>')


def feed(*items, title='Example Security News'):
    return f'<?xml version="1.0"?><rss version="2.0"><channel><title>{title}</title>{"".join(items)}</channel></rss>'.encode()


class _Server(unittest.TestCase):

    def setUp(self):
        self.api = _fresh_api()
        self.mod = self.api.news_watch_handlers_mod
        self.api.verify_token = lambda token: {'k': ('admin', 'admin'), 'v': ('vera', 'viewer'), 'b': ('badmin', 'admin')}.get(token, (None, None))
        self.audits = []
        self.api.audit_log = lambda *a, **k: self.audits.append(a)
        self.spawned = []
        self.api._spawn_cve_scan = lambda actor, target: self.spawned.append((actor, target))
        # a request runs the whole cadence, and the other detached jobs (the daily CISA and EPSS download among them) must not reach the network from a test: only the poll is run
        self.api._run_detached = lambda fn: fn() if getattr(fn, '__name__', '') == 'poll_once' else None
        self.t = int(time.time())
        self.feeds = {}
        self.fetched = []

        def fetch(url):
            self.fetched.append(url)
            got = self.feeds[url]
            if isinstance(got, Exception):
                raise got
            return got
        self.real_fetch = self.mod._fetch
        self.mod._fetch = fetch
        self.settings(enabled=True)
        self.packages({'web01': ['php8.3-fpm', 'nginx', 'patch'], 'db01': ['postgresql-16', 'linux-image-6.8.0-45-generic']})

    # ── the installation ──
    def settings(self, **kw):
        cfg = dict(self.api.load(self.api.CONFIG_FILE) or {})
        watch = dict(cfg.get('news_watch') or {'enabled': False, 'feeds': [FEED], 'scope': 'relevant', 'action': 'scan'})
        watch.update(kw)
        cfg['news_watch'] = watch
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api._LOAD_CACHE.clear()

    def config(self, **kw):
        cfg = dict(self.api.load(self.api.CONFIG_FILE) or {})
        cfg.update(kw)
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api._LOAD_CACHE.clear()

    def packages(self, hosts):
        self.api.save(self.api.PACKAGES_FILE, {h: {'ecosystem': 'Debian:12', 'packages': [{'name': n, 'version': '1'} for n in names]} for h, names in hosts.items()})
        self.api._LOAD_CACHE.clear()

    def hosts(self, hosts, age=0):
        """The hosts as their agents report them: {id: ([process names], [(program, port, scope)])}, each last heard from `age` seconds ago. The age is given when the host is
        first saved: a second save of a host keeps the newer last_seen, so a heartbeat is never put back."""
        devs = {h: {'id': h, 'name': h, 'last_seen': int(time.time()) - age,
                    'sysinfo': {'proc_names': list(procs), 'listening_ports': [{'process': pr, 'port': n, 'scope': sc, 'proto': 'tcp'} for pr, n, sc in ports]}}
                for h, (procs, ports) in hosts.items()}
        self.api.save(self.api.DEVICES_FILE, devs)
        self.api._LOAD_CACHE.clear()

    def get_page(self):
        """The page as the operator reads it. A request runs the cadence first, so the sweep is made not due: what is read is what the test set up."""
        self.config(last_news_watch_run=int(time.time()))
        st, got = self.request('/api/news-watch')
        self.assertEqual(st, 200, got)
        return got

    def tenancy(self):
        self.api.save(self.api.TENANTS_FILE, {'default': {'name': 'Default', 'status': 'active', 'builtin': True}, 'tenantB': {'name': 'B', 'status': 'active'}})
        self.api.save(self.api.USERS_FILE, {'admin': {'role': 'admin', 'tenant_id': 'default'}, 'vera': {'role': 'viewer', 'tenant_id': 'default'},
                                            'badmin': {'role': 'admin', 'tenant_id': 'tenantB'}})
        self.config(tenancy_enforced=True)

    # ── what happened ──
    def poll(self, *specs, url=FEED, advance=0):
        """One read of FEED holding the items `specs` (title, summary, age) at the test clock, after moving the clock on."""
        self.t += advance
        self.feeds[url] = feed(*[entry(self.t, s[0], s[1] if len(s) > 1 else '', age=s[2] if len(s) > 2 else 120) for s in specs])
        self.api._LOAD_CACHE.clear()
        out = self.mod.poll_once(self.t)
        self.api._LOAD_CACHE.clear()
        return out

    def state(self):
        self.api._LOAD_CACHE.clear()
        return self.api.load(self.api.NEWS_WATCH_FILE) or {}

    def outcomes(self):
        return {i['title']: i['outcome'] for i in self.state().get('items', [])}

    def alerts(self):
        self.api._LOAD_CACHE.clear()
        store = self.api.load(self.api.ALERTS_FILE) or {}
        return [a for a in (store.get('alerts') if isinstance(store, dict) else store) or [] if a.get('event') == EVENT]

    def events(self):
        self.api._LOAD_CACHE.clear()
        store = self.api.load(self.api.FLEET_EVENTS_FILE) or {}
        return [e for e in store.get('events', []) if e.get('event') == EVENT]

    def finish_the_scan(self):
        """The runner of the scan that was started has finished: the marker no longer says running."""
        self.api.save(self.api.CVE_SCAN_STATUS_FILE, {'running': False, 'finished_at': self.t})
        self.api._LOAD_CACHE.clear()

    def call(self, fn, *args, body=None, method='GET', token='k'):
        return _run(self.api, lambda: fn(*args), body, method=method, env={'HTTP_AUTHORIZATION': 'Bearer ' + token})

    def request(self, path, method='GET', token='k', body=None):
        """A request through main(): the dispatcher, with the gates that run before a handler does."""
        names = ('REQUEST_METHOD', 'PATH_INFO', 'REMOTE_ADDR', 'CONTENT_LENGTH', 'QUERY_STRING', 'HTTP_AUTHORIZATION', 'HTTP_X_TOKEN')
        saved = {n: os.environ.get(n) for n in names}

        def go():
            os.environ.update(PATH_INFO=path)
            self.api.main()
        try:
            return _run(self.api, go, body, method=method, env={'HTTP_AUTHORIZATION': 'Bearer ' + token} if token else {})
        finally:
            for n, v in saved.items():
                if v is None:
                    os.environ.pop(n, None)
                else:
                    os.environ[n] = v


PHP = ('PHP Fixes 7 Critical Flaws, Including Bugs That Could Allow Remote Code Execution', 'The PHP project released fixes.')
NGINX = ('Critical NGINX HTTP/2 Flaw Lets Unauthenticated Attackers Execute Code', 'Update nginx now.')
CISCO = ('Hackers Exploit Critical Cisco Expressway Flaw', 'Four devices were breached.')
QUIET = ('The Path to AI Autonomy in the SOC', 'A survey.')
SECOND = ('Critical NGINX flaw, a second one', 'nginx')


# ── off until switched on ────────────────────────────────────────────────────

class TestOffUntilSwitchedOn(_Server):

    def test_the_sweep_does_nothing_and_leaves_no_mark(self):
        self.settings(enabled=False)
        self.api.run_news_watch_if_due()
        self.assertEqual((self.fetched, self.spawned, self.alerts()), ([], [], []))
        self.assertNotIn('last_news_watch_run', self.api.load(self.api.CONFIG_FILE))
        self.assertFalse(self.api.backend_exists(self.api.NEWS_WATCH_FILE))

    def test_an_installation_that_never_heard_of_it_has_no_settings_and_no_sweep(self):
        cfg = dict(self.api.load(self.api.CONFIG_FILE))
        cfg.pop('news_watch')
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api._LOAD_CACHE.clear()
        self.api.run_news_watch_if_due()
        self.assertEqual(self.fetched, [])

    def test_on_with_no_feed_reads_nothing(self):
        self.settings(feeds=[])
        self.api.run_news_watch_if_due()
        self.assertEqual(self.fetched, [])


# ── the sweep ────────────────────────────────────────────────────────────────

class TestTheSweep(_Server):

    def test_a_due_sweep_claims_the_slot_and_reads_the_feed(self):
        self.feeds[FEED] = feed(entry(self.t, 'Quiet', guid='q'))
        self.api.run_news_watch_if_due()
        self.assertEqual(self.fetched, [FEED])
        stamp = self.api.load(self.api.CONFIG_FILE)['last_news_watch_run']
        self.assertLessEqual(abs(stamp - int(time.time())), 5)
        self.assertEqual(self.state()['feeds'][FEED]['baselined'], True)

    def test_it_is_not_due_again_for_half_an_hour(self):
        self.feeds[FEED] = feed(entry(self.t, 'Quiet', guid='q'))
        self.api.run_news_watch_if_due()
        self.api._LOAD_CACHE.clear()
        self.api.run_news_watch_if_due()
        self.assertEqual(len(self.fetched), 1)
        self.config(last_news_watch_run=int(time.time()) - self.mod.EVERY_S - 5)
        self.api.run_news_watch_if_due()
        self.assertEqual(len(self.fetched), 2)

    def test_a_stamp_that_is_not_a_number_does_not_stop_the_sweep(self):
        self.feeds[FEED] = feed(entry(self.t, 'Quiet', guid='q'))
        for junk in ('soon', None, True, [1], {'a': 1}, -5):
            self.config(last_news_watch_run=junk)
            before = len(self.fetched)
            self.api.run_news_watch_if_due()
            self.assertEqual(len(self.fetched), before + 1, junk)

    def test_requests_that_find_it_due_at_the_same_moment_start_one_read(self):
        self.feeds[FEED] = feed(entry(self.t, 'Quiet', guid='q'))
        barrier, errors = threading.Barrier(6), []

        def go():
            try:
                barrier.wait(timeout=10)
                self.api.run_news_watch_if_due()
            except Exception as e:      # pragma: no cover
                errors.append(e)
        threads = [threading.Thread(target=go) for _ in range(6)]
        [th.start() for th in threads]
        [th.join(30) for th in threads]
        self.assertEqual(errors, [])
        self.assertEqual(len(self.fetched), 1, 'six requests, one read')

    def test_switching_it_on_makes_the_next_sweep_read_at_once(self):
        self.config(last_news_watch_run=int(time.time()))
        st, got = self.call(self.api.handle_news_watch_config_set, body={'enabled': True, 'feeds': [FEED2]}, method='POST')
        self.assertEqual(st, 200, got)
        self.assertNotIn('last_news_watch_run', self.api.load(self.api.CONFIG_FILE))


# ── what a critical item does ────────────────────────────────────────────────

class TestWhatIsDone(_Server):

    def test_the_first_read_records_every_critical_item_and_raises_nothing(self):
        out = self.poll(PHP, NGINX, CISCO, QUIET)
        self.assertEqual((out['new_critical'], out['alerts'], out['scan']), (3, 0, None))
        self.assertEqual(self.outcomes(), {PHP[0]: 'baseline', NGINX[0]: 'baseline', CISCO[0]: 'baseline'}, 'Quiet is not critical, so it is not listed')
        self.assertEqual((self.alerts(), self.spawned), ([], []))
        self.assertEqual(self.state()['feeds'][FEED]['baselined'], True)

    def test_a_new_critical_item_that_names_installed_software_alerts_and_starts_a_scan(self):
        self.poll(QUIET)
        out = self.poll(QUIET, PHP, advance=1800)
        self.assertEqual((out['new_critical'], out['alerts'], out['scan']), (1, 1, 'started'))
        self.assertEqual(self.spawned, [('news-watch', None)], 'the scan of every host, by the news watch')
        (a,) = self.alerts()
        self.assertEqual((a['severity'], a['title']), ('high', 'Critical security news: ' + PHP[0]))
        p = a['payload']
        self.assertEqual((p['title'], p['source'], p['severity']), (PHP[0], 'Example Security News', 'high'))
        self.assertTrue(p['url'].startswith('https://news.example.net/'))
        self.assertIn('It names software installed on your hosts.', p['detail'])
        self.assertIn('A scan of all hosts was started.', p['detail'])
        self.assertIn('called critical', p['detail'])
        self.assertEqual(self.outcomes(), {PHP[0]: 'scanned'})
        self.assertEqual(self.state()['items'][0]['software'], ['php'])
        self.assertEqual(self.audits[-1][:2], ('news-watch', 'news_watch_scan'))
        (e,) = self.events()
        self.assertEqual((e['payload']['title'], e['payload']['source']), (PHP[0], 'Example Security News'))
        marker = self.api.load(self.api.CVE_SCAN_STATUS_FILE)
        self.assertEqual((marker['running'], marker['total'], marker.get('owner')), (True, 2, None))

    def test_a_second_item_inside_six_hours_alerts_and_does_not_scan_again(self):
        self.poll(QUIET)
        self.poll(QUIET, PHP, advance=1800)
        self.finish_the_scan()
        out = self.poll(QUIET, PHP, NGINX, advance=1800)
        self.assertEqual((out['alerts'], out['scan']), (1, 'waiting'))
        self.assertEqual(len(self.spawned), 1)
        self.assertEqual(self.outcomes()[NGINX[0]], 'scan_waiting')
        nginx_alert = [a for a in self.alerts() if a['payload']['title'] == NGINX[0]]
        self.assertEqual(len(nginx_alert), 1)
        self.assertNotIn('A scan of all hosts was started.', nginx_alert[0]['payload']['detail'])
        out = self.poll(QUIET, PHP, NGINX, ('Critical RCE flaw in PostgreSQL', 'x'), advance=self.mod.SCAN_GAP_S)
        self.assertEqual((out['alerts'], out['scan']), (1, 'started'), 'after six hours the next one scans')
        self.assertEqual(len(self.spawned), 2)

    def test_a_critical_item_that_names_nothing_installed_is_listed_only(self):
        self.poll(QUIET)
        out = self.poll(QUIET, CISCO, advance=1800)
        self.assertEqual((out['new_critical'], out['alerts'], out['scan']), (1, 0, None))
        self.assertEqual(self.outcomes(), {CISCO[0]: 'listed'})
        self.assertEqual((self.alerts(), self.spawned), ([], []))
        self.assertEqual(self.state()['items'][0]['software'], [])

    def test_every_critical_item_counts_when_the_operator_chose_that(self):
        self.settings(scope='all')
        self.poll(QUIET)
        out = self.poll(QUIET, CISCO, advance=1800)
        self.assertEqual((out['alerts'], out['scan']), (1, 'started'))
        (a,) = self.alerts()
        self.assertEqual(a['severity'], 'medium', 'it names nothing the hosts have')
        self.assertIn('It is not matched to software on your hosts.', a['payload']['detail'])

    def test_the_action_decides_between_list_alert_and_scan(self):
        for action, alerts, scans in (('list', 0, 0), ('alert', 1, 0), ('scan', 1, 1)):
            with self.subTest(action):
                self.setUp()
                self.settings(action=action)
                self.poll(QUIET)
                self.poll(QUIET, PHP, advance=1800)
                self.assertEqual((len(self.alerts()), len(self.spawned)), (alerts, scans))
                self.assertEqual(self.outcomes(), {PHP[0]: {'list': 'listed', 'alert': 'alerted', 'scan': 'scanned'}[action]})

    def test_an_item_that_is_old_is_listed_and_not_acted_on(self):
        self.poll(QUIET)
        out = self.poll(QUIET, PHP[:2] + (N.MAX_AGE_S + 3600,), advance=1800)
        self.assertEqual((out['alerts'], self.spawned), (0, []))
        self.assertEqual(self.outcomes(), {PHP[0]: 'stale'})

    def test_one_read_raises_at_most_five_alerts(self):
        self.poll(QUIET)
        many = [(f'Critical RCE flaw in PHP number {i}', 'php') for i in range(8)]
        out = self.poll(QUIET, *many, advance=1800)
        self.assertEqual((out['new_critical'], out['alerts'], len(self.alerts())), (8, 5, 5))
        counted = sorted(self.outcomes().values())
        self.assertEqual((counted.count('over_limit'), counted.count('scanned')), (3, 5))

    def test_the_same_item_is_never_raised_twice(self):
        self.poll(QUIET)
        self.poll(QUIET, PHP, advance=1800)
        for _ in range(3):
            out = self.poll(QUIET, PHP, advance=1800)
            self.assertEqual((out['new_critical'], out['alerts']), (0, 0))
        self.assertEqual(len(self.alerts()), 1)

    def test_a_scan_that_is_already_running_is_not_started_again_and_the_item_says_so(self):
        self.api.save(self.api.CVE_SCAN_STATUS_FILE, {'running': True, 'updated': int(time.time()), 'run': 'someone-elses', 'total': 2})
        self.poll(QUIET)
        out = self.poll(QUIET, PHP, advance=1800)
        self.assertEqual((out['alerts'], out['scan'], self.spawned), (1, 'busy', []))
        self.assertEqual(self.outcomes(), {PHP[0]: 'scan_refused'})
        self.assertNotIn('last_scan_at', self.state(), 'the clock is put back: the next item may try again')
        self.assertNotIn('A scan of all hosts was started.', self.alerts()[0]['payload']['detail'])
        self.assertEqual(self.api.load(self.api.CVE_SCAN_STATUS_FILE)['run'], 'someone-elses', 'the running scan is left alone')

    def test_no_host_with_a_package_list_means_no_scan(self):
        self.api.save(self.api.PACKAGES_FILE, {})
        self.api._LOAD_CACHE.clear()
        self.poll(QUIET)
        out = self.poll(QUIET, PHP, advance=1800)
        self.assertEqual((out['alerts'], out['scan'], self.spawned), (0, None, []), 'no package list, so no software to match: listed')
        self.assertEqual(self.outcomes(), {PHP[0]: 'listed'})
        self.settings(scope='all')
        out = self.poll(QUIET, PHP, NGINX, advance=1800)
        self.assertEqual((out['alerts'], out['scan'], self.spawned), (1, 'none', []))
        self.assertEqual(self.outcomes()[NGINX[0]], 'scan_refused')

    def test_a_scan_that_cannot_be_started_does_not_lose_the_alert(self):
        def boom(actor, target):
            raise OSError('no process')
        self.api._spawn_cve_scan = boom
        self.poll(QUIET)
        out = self.poll(QUIET, PHP, advance=1800)
        self.assertEqual((out['alerts'], out['scan']), (1, 'error'))
        self.assertEqual(self.outcomes(), {PHP[0]: 'scan_refused'})

    def test_a_known_exploited_cve_makes_an_item_critical_with_no_critical_word(self):
        self.api.save(self.api.KEV_EPSS_FILE, {'kev': ['CVE-2026-4242'], 'epss': {}})
        self.api._LOAD_CACHE.clear()
        self.poll(QUIET)
        out = self.poll(QUIET, ('A library update', 'Fixes CVE-2026-4242 in PHP.'), advance=1800)
        self.assertEqual(out['alerts'], 1)
        self.assertEqual(self.state()['items'][0]['reasons'], ['kev'])
        self.assertIn('CVE-2026-4242', self.alerts()[0]['payload']['detail'])


# ── what runs, and what is only installed ────────────────────────────────────

class TestRunningSoftware(_Server):

    def test_an_item_that_names_what_runs_says_so_in_the_alert_and_on_the_page(self):
        self.hosts({'web01': (['nginx', 'sshd'], [('nginx', 443, 'world')]), 'web02': (['nginx'], [('nginx', 80, 'lan')])})
        self.poll(QUIET)
        out = self.poll(QUIET, NGINX, advance=1800)
        self.assertEqual((out['alerts'], out['scan']), (1, 'started'))
        (a,) = self.alerts()
        self.assertIn('It names software that runs on your hosts: nginx.', a['payload']['detail'])
        self.assertNotIn('installed on your hosts', a['payload']['detail'])
        self.assertEqual(a['payload']['severity'], 'high')
        (item,) = self.get_page()['items']
        self.assertEqual(item['running'], [{'name': 'nginx', 'hosts': 2, 'world': True}])
        self.assertEqual(item['software'], [], 'what runs is shown apart from what is only installed')
        self.assertEqual(self.state()['items'][0]['software'], ['nginx'], 'the store keeps the word, and the page reads it against the hosts as they are')

    def test_software_that_is_only_installed_is_said_to_be_installed(self):
        self.hosts({'web01': (['sshd', 'cron'], [])})
        self.poll(QUIET)
        self.poll(QUIET, PHP, advance=1800)
        (a,) = self.alerts()
        self.assertIn('It names software installed on your hosts.', a['payload']['detail'])
        self.assertEqual(a['payload']['severity'], 'high', 'installed is still software the hosts have')
        (item,) = self.get_page()['items']
        self.assertEqual((item['running'], item['software']), ([], ['php']))

    def test_a_host_that_stops_running_it_loses_the_mark_the_next_time_the_page_is_read(self):
        self.hosts({'web01': (['nginx'], [('nginx', 443, 'world')])})
        self.poll(QUIET)
        self.poll(QUIET, NGINX, advance=1800)
        self.assertEqual([r['name'] for r in self.get_page()['items'][0]['running']], ['nginx'])
        self.hosts({'web01': (['sshd'], [])})
        item = self.get_page()['items'][0]
        self.assertEqual((item['running'], item['software']), ([], ['nginx']), 'installed, not running: the word stays, the mark goes')
        self.hosts({})
        self.assertEqual(self.get_page()['items'][0]['running'], [])

    def test_a_host_that_has_not_reported_for_a_week_is_not_evidence_of_what_runs(self):
        self.hosts({'web01': (['nginx'], [])}, age=N.RUNNING_STALE_S + 3600)
        self.assertGreater(time.time() - self.api.load(self.api.DEVICES_FILE)['web01']['last_seen'], N.RUNNING_STALE_S, 'control: the host is stored as stale')
        self.poll(QUIET)
        self.poll(QUIET, NGINX, advance=1800)
        (item,) = self.get_page()['items']
        self.assertEqual((item['running'], item['software']), ([], ['nginx']))

    def test_everyday_package_words_do_not_make_an_item_relevant(self):
        """The report: the first words of these package names made console, command, software, xml and firmware 'software on your hosts', so a story about a
        management console raised an alert and started a scan of a fleet that has no such product."""
        self.packages({'web01': ['console-setup', 'command-not-found', 'software-properties-common', 'xml-core', 'firmware-sof-signed', 'liburi-perl', 'amd64-microcode',
                                 'language-pack-en', 'libhttp-date-perl', 'intel-microcode']})
        self.poll(QUIET)
        vmware = ('Critical VMware vCenter Zero-Day Flaw Lets Network Attackers Bypass Authentication',
                  'The management console and the command line are affected, with XML over HTTP to a URI, firmware and software updates on AMD and Intel hardware.')
        out = self.poll(QUIET, vmware, advance=1800)
        self.assertEqual((out['new_critical'], out['alerts'], out['scan'], self.spawned), (1, 0, None, []))
        self.assertEqual(self.outcomes(), {vmware[0]: 'listed'})
        self.assertEqual(self.state()['items'][0]['software'], [])
        self.assertEqual(self.alerts(), [])

    def test_items_stored_by_the_earlier_matcher_are_read_again(self):
        self.poll(QUIET)
        st = self.state()
        st['items'] = [{'id': 'old1', 'feed': 'F', 'title': 'An old item', 'link': '', 'published': self.t, 'seen_at': self.t, 'reasons': ['critical'], 'cves': [], 'cvss': None,
                        'software': ['console', 'command', 'php', 'unrealircd'], 'outcome': 'listed'}]
        self.api.save(self.api.NEWS_WATCH_FILE, st)
        self.api._LOAD_CACHE.clear()
        item = self.get_page()['items'][0]
        self.assertEqual((item['software'], item['running']), (['php'], []), 'console and command are not software, php is, and unrealircd is neither in the list nor running')
        self.hosts({'web01': (['unrealircd'], [])})
        item = self.get_page()['items'][0]
        self.assertEqual((item['software'], [r['name'] for r in item['running']]), (['php'], ['unrealircd']), 'a program that runs counts whatever it is called')

    def test_a_kernel_thread_is_not_a_program_an_item_can_name(self):
        self.packages({'web01': ['patch', 'file']})
        self.hosts({'web01': (['migration/0', 'watchdog/0', 'kworker/0:1'], [])})
        self.poll(QUIET)
        out = self.poll(QUIET, ('Critical flaw in a data migration tool lets attackers run code', 'A watchdog timer is involved.'), advance=1800)
        self.assertEqual((out['alerts'], self.spawned), (0, []))
        self.assertEqual(self.get_page()['items'][0]['running'], [])


# ── what counts: the three choices, and the names an operator adds ───────────

class TestWhatCounts(_Server):

    def setUp(self):
        super().setUp()
        # nginx runs and listens to the Internet; php is a package and nothing runs under that name
        self.hosts({'web01': (['nginx'], [('nginx', 443, 'world')])})

    def test_the_third_choice_alerts_for_what_runs_and_only_lists_what_is_installed(self):
        self.settings(scope='running')
        self.poll(QUIET)
        out = self.poll(QUIET, NGINX, PHP, advance=1800)
        self.assertEqual((out['new_critical'], out['alerts'], out['scan']), (2, 1, 'started'))
        self.assertEqual(self.outcomes(), {NGINX[0]: 'scanned', PHP[0]: 'listed'})
        (a,) = self.alerts()
        self.assertEqual(a['payload']['title'], NGINX[0])
        self.assertEqual(len(self.spawned), 1)

    def test_the_middle_choice_counts_installed_software_too(self):
        self.settings(scope='relevant')
        self.poll(QUIET)
        out = self.poll(QUIET, NGINX, PHP, advance=1800)
        self.assertEqual((out['alerts'], sorted(self.outcomes().values())), (2, ['scanned', 'scanned']))

    def test_with_nothing_running_the_third_choice_alerts_for_nothing(self):
        self.hosts({'web01': (['sshd'], [])})
        self.settings(scope='running')
        self.poll(QUIET)
        out = self.poll(QUIET, NGINX, PHP, advance=1800)
        self.assertEqual((out['alerts'], out['scan'], self.spawned, self.alerts()), (0, None, [], []))
        self.assertEqual(sorted(self.outcomes().values()), ['listed', 'listed'])

    def test_a_name_the_operator_added_makes_installed_software_count(self):
        self.packages({'web01': ['unrealircd', 'nginx']})
        unreal = ('Attackers Exploit UnrealIRCd Flaw That Enables Server-Level Command Injection', 'A critical RCE in the IRC server.')
        again = ('Another UnrealIRCd Flaw Lets Attackers Run Code', 'It is critical.')
        self.poll(QUIET)
        out = self.poll(QUIET, unreal, advance=1800)
        self.assertEqual((out['alerts'], self.outcomes()[unreal[0]]), (0, 'listed'), 'installed, not on the list, not running')
        self.settings(words=['unrealircd'])
        out = self.poll(QUIET, unreal, again, advance=1800)
        self.assertEqual((out['alerts'], self.outcomes()[again[0]]), (1, 'scanned'))
        (a,) = self.alerts()
        self.assertIn('It names software installed on your hosts.', a['payload']['detail'])
        item = self.get_page()['items'][0]
        self.assertEqual((item['title'], item['software']), (again[0], ['unrealircd']))
        self.settings(words=[])
        self.assertEqual(self.get_page()['items'][0]['software'], [], 'a name taken out is no longer shown on the items that had it')

    def test_the_names_are_saved_normalised_and_one_bad_name_refuses_the_whole_save(self):
        st, got = self.request('/api/news-watch/config', 'POST', body={'words': 'UnrealIRCd6\nsquidguard, unrealircd', 'scope': 'running'})
        self.assertEqual((st, got['words'], got['scope'], got['max_words']), (200, ['unrealircd', 'squidguard'], 'running', N.MAX_WORDS))
        self.api._LOAD_CACHE.clear()
        self.assertEqual(self.api.load(self.api.CONFIG_FILE)['news_watch']['words'], ['unrealircd', 'squidguard'])
        self.assertIn('words=2', self.audits[-1][2])
        st, got = self.request('/api/news-watch/config', 'POST', body={'words': ['console'], 'scope': 'all'})
        self.assertEqual(st, 400, got)
        self.assertIn('everyday word', got['error'])
        self.api._LOAD_CACHE.clear()
        stored = self.api.load(self.api.CONFIG_FILE)['news_watch']
        self.assertEqual((stored['scope'], stored['words']), ('running', ['unrealircd', 'squidguard']), 'nothing of the refused save was kept')
        self.assertEqual(self.request('/api/news-watch')[1]['words'], ['unrealircd', 'squidguard'])


# ── the mark of the tab and of the sidebar ───────────────────────────────────

class TestTheMark(_Server):

    def setUp(self):
        super().setUp()
        self.hosts({'web01': (['nginx'], [('nginx', 443, 'world')])})

    def nav(self, token='k', clear=True):
        """The sidebar's poll. Its answer is cached for 15 seconds, so a test that changed the hosts asks for a fresh one. The cache is a file under the JSON backend and a row under SQLite and
        Postgres, so it is not looked for in the data directory: the poll is told that no cache is there. (Deleting files left it in place under SQLite, and two tests read an old answer.)"""
        real = self.api.backend_exists
        if clear:
            self.api.backend_exists = lambda path, *a, **k: False if 'nav_counts_cache_' in str(path) else real(path, *a, **k)
        self.api._LOAD_CACHE.clear()
        try:
            try:
                st, got = self.request('/api/nav-counts', token=token)
            except self.api.HTTPError as e:      # a conditional GET raises its answer itself (_respond_with_etag), which the stand-in for respond() never sees
                st, got = e.status, e.body
        finally:
            self.api.backend_exists = real
        self.assertEqual(st, 200, got)
        return got

    def found(self):
        self.poll(QUIET)
        self.poll(QUIET, NGINX, advance=1800)
        return self.state()['items'][0]['seen_at']

    def test_the_operators_poll_carries_how_many_and_the_newest_item_that_names_software_that_runs(self):
        at = self.found()
        got = self.nav()
        self.assertEqual((got['news_running'], got['news_running_at']), (1, at))
        page = self.get_page()
        self.assertEqual((page['needs_a_look'], page['attention_at']), (1, at), 'the tab and the sidebar count the same thing')

    def test_software_that_is_only_installed_is_not_a_mark(self):
        self.hosts({'web01': (['sshd'], [])})
        self.poll(QUIET)
        self.poll(QUIET, PHP, advance=1800)
        got = self.nav()
        self.assertNotIn('news_running', got)
        self.assertNotIn('news_running_at', got)
        self.assertEqual(self.get_page()['needs_a_look'], 0)

    def test_the_first_read_an_item_too_old_to_act_on_and_one_older_than_three_days_are_not_a_mark(self):
        self.poll(NGINX)                                            # the first read of the feed: recorded, nothing raised
        self.assertEqual(self.state()['items'][0]['outcome'], 'baseline')
        self.assertNotIn('news_running', self.nav())
        self.poll(NGINX, ('Critical NGINX flaw, old news', 'nginx', N.MAX_AGE_S + 3600), advance=1800)
        self.assertEqual(self.state()['items'][0]['outcome'], 'stale')
        self.assertNotIn('news_running', self.nav())
        self.found_again = self.poll(NGINX, ('Critical NGINX flaw, new this time', 'nginx'), advance=1800)
        got = self.nav()
        self.assertEqual(got['news_running'], 1, 'only the new one')
        st = self.state()
        st['items'][0]['seen_at'] = int(time.time()) - N.MAX_AGE_S - 60          # the same item, found more than three days ago
        self.api.save(self.api.NEWS_WATCH_FILE, st)
        self.api._LOAD_CACHE.clear()
        self.assertNotIn('news_running', self.nav())

    def test_a_watch_that_is_off_has_no_mark(self):
        self.found()
        self.assertIn('news_running', self.nav())
        self.settings(enabled=False)
        self.assertNotIn('news_running', self.nav())

    def test_the_mark_follows_the_hosts(self):
        self.found()
        self.assertIn('news_running', self.nav())
        self.hosts({'web01': (['sshd'], [])})
        self.assertNotIn('news_running', self.nav(), 'nothing runs nginx any more')
        self.hosts({'web01': (['nginx'], [])})
        self.assertIn('news_running', self.nav())

    def test_nobody_but_the_platform_operator_gets_it(self):
        self.found()
        self.assertIn('news_running', self.nav('k'))
        got = self.nav('v', clear=False)               # the same 15 seconds: the operator's answer must not be what a viewer is given
        self.assertNotIn('news_running', got)
        self.tenancy()
        for token, who in (('v', 'a viewer'), ('b', 'the administrator of a tenant')):
            self.assertNotIn('news_running', self.nav(token, clear=False), who)
            self.assertNotIn('news_running_at', self.nav(token), who)
        self.assertIn('news_running', self.nav('k'), 'control: the platform operator still gets it')

    def test_a_new_item_shows_in_the_sidebar_poll_before_its_15_seconds_are_over(self):
        self.found()
        first = self.nav()['news_running_at']
        time.sleep(0.05)
        self.poll(NGINX, ('Critical NGINX flaw, a second one', 'nginx'), advance=1800)
        got = self.nav(clear=False)                    # the cache is not cleared: the store changed, and that busts it
        self.assertEqual(got['news_running'], 2)
        self.assertGreater(got['news_running_at'], first)


# ── clearing the red ! ───────────────────────────────────────────────────────

class TestClearTheBang(_Server):
    """An item shows a red ! while it names software that runs on a host. An operator can clear it: the item stays in the list with what runs, loses its !, and stops counting for
    the mark of the sidebar. The clear is kept in the store, so it holds for every browser and every operator account."""

    def setUp(self):
        super().setUp()
        self.hosts({'web01': (['nginx'], [('nginx', 443, 'world')])})
        self.poll(QUIET)
        self.poll(QUIET, NGINX, PHP, SECOND, advance=1800)

    def items(self):
        return {i['title']: i for i in self.get_page()['items']}

    def nav(self, token='k', clear=True):
        return TestTheMark.nav(self, token, clear)

    def clear(self, body, token='k'):
        self.config(last_news_watch_run=int(time.time()))      # a request runs the cadence first: the feeds are not read again under a test of the clear
        return self.request('/api/news-watch/clear', 'POST', token=token, body=body)

    def stored(self):
        return {i['title']: i.get('cleared_at') for i in self.state()['items']}

    def test_the_setup_has_two_items_with_a_bang_and_one_without(self):
        got = self.items()
        self.assertEqual({t: bool(i['running']) for t, i in got.items()}, {NGINX[0]: True, PHP[0]: False, SECOND[0]: True}, 'nginx runs, php is only installed')
        self.assertEqual(self.nav()['news_running'], 2)

    def test_one_item_is_cleared_by_its_id_and_nothing_else_is(self):
        got = self.items()
        st, answer = self.clear({'ids': [got[NGINX[0]]['id']]})
        self.assertEqual((st, answer['ok'], answer['cleared']), (200, True, 1), answer)
        after = {i['title']: i for i in answer['items']}
        self.assertIsInstance(after[NGINX[0]]['cleared_at'], int)
        self.assertLessEqual(abs(after[NGINX[0]]['cleared_at'] - int(time.time())), 5, 'stamped with the time of the clear, which is real time and not the clock the polls were moved on')
        self.assertEqual(after[NGINX[0]]['running'], got[NGINX[0]]['running'], 'what runs on the hosts is still shown on a cleared item')
        self.assertIsNone(after[SECOND[0]]['cleared_at'])
        self.assertIsNone(after[PHP[0]]['cleared_at'])
        self.assertEqual(self.stored(), {NGINX[0]: after[NGINX[0]]['cleared_at'], PHP[0]: None, SECOND[0]: None}, 'kept in the store, on that item only')
        self.assertEqual(self.audits[-1][1:], ('news_watch_clear', 'items=1'))
        self.assertEqual(self.audits[-1][0], 'admin', 'the audit log says who')

    def test_all_clears_every_item_that_shows_a_bang_and_leaves_an_item_that_shows_none(self):
        st, answer = self.clear({'all': True})
        self.assertEqual((st, answer['cleared']), (200, 2), answer)
        stored = self.stored()
        self.assertIsNotNone(stored[NGINX[0]])
        self.assertIsNotNone(stored[SECOND[0]])
        self.assertIsNone(stored[PHP[0]], 'it showed no !, so it has none to clear')
        self.assertEqual(self.audits[-1][1:], ('news_watch_clear', 'items=2'))
        self.hosts({'web01': (['nginx', 'php-fpm8.3'], [('nginx', 443, 'world')])})
        got = self.items()
        self.assertEqual([r['name'] for r in got[PHP[0]]['running']], ['php'], 'a host starts to run php')
        self.assertIsNone(got[PHP[0]]['cleared_at'], 'the ! of that item is news, and Clear all had not cleared it')
        self.assertEqual(self.nav()['news_running'], 1, 'and it is the one thing the mark counts')

    def test_an_id_that_shows_no_bang_clears_nothing_and_is_not_logged(self):
        got = self.items()
        before = len(self.audits)
        st, answer = self.clear({'ids': [got[PHP[0]]['id']]})
        self.assertEqual((st, answer['cleared']), (200, 0))
        self.assertIsNone(self.stored()[PHP[0]])
        self.assertEqual(len(self.audits), before, 'nothing changed, so nothing is logged')

    def test_clearing_twice_clears_nothing_the_second_time_and_keeps_the_first_time(self):
        got = self.items()
        ident = got[NGINX[0]]['id']
        self.clear({'ids': [ident]})
        first = self.stored()[NGINX[0]]
        time.sleep(1.1)
        st, answer = self.clear({'ids': [ident]})
        self.assertEqual((st, answer['cleared']), (200, 0))
        self.assertEqual(self.stored()[NGINX[0]], first, 'the time of the first clear is kept')

    def test_the_mark_and_the_count_follow_a_clear_in_every_browser(self):
        before = self.get_page()
        self.assertEqual((before['needs_a_look'], self.nav()['news_running']), (2, 2))
        got = self.items()
        self.clear({'ids': [got[NGINX[0]]['id']]})
        page = self.get_page()
        self.assertEqual(page['needs_a_look'], 1)
        self.assertEqual(self.nav(clear=False)['news_running'], 1, 'the store changed, and that ends the 15 seconds the sidebar answer is kept')
        self.assertEqual(page['attention_at'], self.stored_at(SECOND[0]), 'what is left to look at is the other item')
        self.clear({'all': True})
        self.assertEqual(self.get_page()['needs_a_look'], 0)
        gone = self.nav(clear=False)
        self.assertNotIn('news_running', gone)
        self.assertNotIn('news_running_at', gone)

    def stored_at(self, title):
        return {i['title']: i['seen_at'] for i in self.state()['items']}[title]

    def test_a_clear_is_kept_when_the_feeds_are_read_again_and_a_new_item_has_its_own_bang(self):
        self.clear({'all': True})
        cleared = self.stored()
        self.poll(QUIET, NGINX, PHP, SECOND, ('Critical NGINX flaw, a third one', 'nginx'), advance=1800)
        after = self.stored()
        self.assertEqual({t: after[t] for t in cleared}, cleared, 'the items that were cleared are still cleared')
        self.assertIsNone(after['Critical NGINX flaw, a third one'], 'a new item shows its own !')
        self.assertEqual(self.nav()['news_running'], 1)

    def test_a_body_that_names_nothing_is_refused_and_changes_nothing(self):
        for body in ({}, {'ids': []}, {'ids': 'abc'}, {'ids': [7, None, '', {'a': 1}, ['n']]}, {'all': 'yes'}, {'all': 1}, {'all': False}, {'ids': {}, 'all': None}):
            st, answer = self.clear(body)
            self.assertEqual((st, answer.get('error')), (400, 'Say which items to clear'), body)
        for junk in ([], 'x', 7, None):
            st, answer = self.clear(junk)
            self.assertEqual(st, 400, junk)
        self.assertEqual(set(self.stored().values()), {None}, 'a refused request cleared nothing')

    def test_ids_that_are_not_listed_or_not_text_are_ignored_and_the_list_is_capped(self):
        ident = self.items()[NGINX[0]]['id']
        st, answer = self.clear({'ids': ['nope', 'x' * 500, '<script>', {'a': 1}, ['n'], 1, True, None, ident]})
        self.assertEqual((st, answer['cleared']), (200, 1), 'only the id of a listed item counts')
        self.assertIsNotNone(self.stored()[NGINX[0]])
        other = self.items()[SECOND[0]]['id']
        junk = ['x'] * self.mod.MAX_CLEAR_IDS
        st, answer = self.clear({'ids': junk + [other]})
        self.assertEqual((st, answer['cleared']), (200, 0), 'ids past the cap are not read: a list holds %d items, so no honest request has that many' % N.MAX_LISTED)
        st, answer = self.clear({'ids': [other] + junk})
        self.assertEqual((st, answer['cleared']), (200, 1), 'control: the same id inside the cap is read')

    def test_ids_and_all_together_are_both_honoured(self):
        ident = self.items()[NGINX[0]]['id']
        st, answer = self.clear({'ids': [ident], 'all': True})
        self.assertEqual((st, answer['cleared']), (200, 2))

    def test_nobody_but_the_platform_operator_may_clear(self):
        ident = self.items()[NGINX[0]]['id']
        st, answer = self.clear({'ids': [ident]}, token='v')
        self.assertEqual(st, 403, 'a viewer')
        self.tenancy()
        for token, who in (('v', 'a viewer'), ('b', 'the administrator of a tenant')):
            st, answer = self.clear({'all': True}, token=token)
            self.assertEqual(st, 403, (who, answer))
        self.assertIn('platform operator', answer['error'])
        st, _ = self.clear({'all': True}, token=None)
        self.assertEqual(st, 401)
        self.assertEqual(set(self.stored().values()), {None}, 'nothing was cleared by a request that was refused')
        st, answer = self.clear({'all': True}, token='k')
        self.assertEqual((st, answer['cleared']), (200, 2), 'control: the platform operator can')

    def test_only_post_is_routed(self):
        for method in ('GET', 'DELETE', 'PUT'):
            st, _ = self.request('/api/news-watch/clear', method)
            self.assertIn(st, (404, 405), method)

    def test_a_stored_cleared_at_that_is_not_a_whole_number_reads_as_not_cleared(self):
        st = self.state()
        for junk, item in zip(('x', True, 1.5), st['items']):
            item['cleared_at'] = junk
        self.api.save(self.api.NEWS_WATCH_FILE, st)
        self.api._LOAD_CACHE.clear()
        got = self.items()
        self.assertEqual({i['cleared_at'] for i in got.values()}, {None}, 'text, a boolean and a fraction are no time')
        self.assertEqual(self.nav()['news_running'], 2, 'and they hide nothing from the mark')

    def test_an_item_cleared_while_no_host_runs_it_has_nothing_to_show_and_nothing_to_hide(self):
        self.clear({'all': True})
        self.hosts({'web01': (['sshd'], [])})
        got = self.items()
        self.assertEqual([i['running'] for i in got.values()], [[], [], []])
        self.assertNotIn('news_running', self.nav())



class TestBringTheBangBack(_Server):
    """A clear can be undone (8.0.2): the same route with `undo: true`. The item loses the time it was cleared at and shows its ! again, for every browser and every operator account,
    in the state it had before; the mark of the sidebar and the tab goes by that state."""

    def setUp(self):
        super().setUp()
        self.hosts({'web01': (['nginx'], [('nginx', 443, 'world')])})
        self.poll(QUIET)
        self.poll(QUIET, NGINX, PHP, SECOND, advance=1800)

    items = TestClearTheBang.items
    nav = TestClearTheBang.nav
    clear = TestClearTheBang.clear
    stored = TestClearTheBang.stored
    stored_at = TestClearTheBang.stored_at

    def undo(self, body, token='k'):
        return self.clear(dict(body, undo=True), token=token)

    def test_one_cleared_item_gets_its_bang_back_by_its_id_and_no_other_does(self):
        got = self.items()
        self.clear({'all': True})
        st, answer = self.undo({'ids': [got[NGINX[0]]['id']]})
        self.assertEqual((st, answer['ok'], answer['restored']), (200, True, 1), answer)
        self.assertNotIn('cleared', answer, 'an undo answers with what it restored, not with a count of clears')
        after = {i['title']: i for i in answer['items']}
        self.assertIsNone(after[NGINX[0]]['cleared_at'])
        self.assertIsInstance(after[SECOND[0]]['cleared_at'], int, 'the other item is still cleared')
        stored = self.stored()
        self.assertIsNone(stored[NGINX[0]])
        self.assertIsNotNone(stored[SECOND[0]])
        self.assertNotIn('cleared_at', {i['title']: i for i in self.state()['items']}[NGINX[0]], 'the time is taken out of the store, not set to null')
        self.assertEqual(self.audits[-1][1:], ('news_watch_unclear', 'items=1'))
        self.assertEqual(self.audits[-1][0], 'admin', 'the audit log says who')

    def test_all_brings_back_every_cleared_item_and_the_mark_comes_back_with_them(self):
        self.clear({'all': True})
        self.assertEqual(self.get_page()['needs_a_look'], 0)
        self.assertNotIn('news_running', self.nav())
        st, answer = self.undo({'all': True})
        self.assertEqual((st, answer['restored']), (200, 2), answer)
        self.assertEqual(set(self.stored().values()), {None})
        page = self.get_page()
        self.assertEqual(page['needs_a_look'], 2, 'the page counts them again')
        self.assertEqual(self.nav()['news_running'], 2, 'and so does the sidebar')
        self.assertEqual(page['attention_at'], max(self.stored_at(NGINX[0]), self.stored_at(SECOND[0])), 'by the time the items were found: what a browser has shown decides whether it is told')
        self.assertEqual(self.audits[-1][1:], ('news_watch_unclear', 'items=2'))

    def test_an_item_that_is_not_cleared_is_left_alone_and_nothing_is_logged(self):
        got = self.items()
        before = len(self.audits)
        st, answer = self.undo({'ids': [got[NGINX[0]]['id'], got[PHP[0]]['id']]})
        self.assertEqual((st, answer['restored']), (200, 0))
        st, answer = self.undo({'all': True})
        self.assertEqual((st, answer['restored']), (200, 0))
        self.assertEqual(set(self.stored().values()), {None})
        self.assertEqual(len(self.audits), before, 'nothing changed, so nothing is logged')

    def test_a_clear_after_an_undo_works_and_stamps_its_own_time(self):
        ident = self.items()[NGINX[0]]['id']
        self.clear({'ids': [ident]})
        first = self.stored()[NGINX[0]]
        self.undo({'ids': [ident]})
        time.sleep(1.1)
        st, answer = self.clear({'ids': [ident]})
        self.assertEqual((st, answer['cleared']), (200, 1), 'an item that was brought back can be cleared again')
        self.assertGreater(self.stored()[NGINX[0]], first, 'with the time of this clear')

    def test_an_item_cleared_while_no_host_ran_it_can_still_be_brought_back(self):
        self.clear({'all': True})
        self.hosts({'web01': (['sshd'], [])})
        st, answer = self.undo({'all': True})
        self.assertEqual((st, answer['restored']), (200, 2), 'an item that no host runs now has no ! to show, and the clear on it is still taken off')
        self.assertEqual(set(self.stored().values()), {None})
        self.hosts({'web01': (['nginx'], [('nginx', 443, 'world')])})
        self.assertEqual(self.nav()['news_running'], 2, 'when a host runs it again, the ! is there')

    def test_a_body_that_names_nothing_is_refused_with_its_own_words_and_changes_nothing(self):
        self.clear({'all': True})
        before = self.stored()
        for body in ({}, {'ids': []}, {'ids': 'abc'}, {'ids': [7, None, '', {'a': 1}, ['n']]}, {'all': 'yes'}, {'all': 1}, {'all': False}):
            st, answer = self.undo(body)
            self.assertEqual((st, answer.get('error')), (400, 'Say which items to bring back'), body)
        self.assertEqual(self.stored(), before, 'a refused request brought nothing back')

    def test_only_a_true_undo_undoes(self):
        ident = self.items()[NGINX[0]]['id']
        for odd in ('yes', 1, 'true', [True], {'a': 1}):
            self.assertEqual(self.clear({'ids': [ident], 'undo': odd})[1]['cleared'], 1, odd)       # not true: it is a clear, as it was before this field existed
            self.assertIsNotNone(self.stored()[NGINX[0]], odd)
            st, answer = self.undo({'ids': [ident]})
            self.assertEqual((st, answer['restored']), (200, 1), odd)

    def test_nobody_but_the_platform_operator_may_bring_it_back(self):
        self.clear({'all': True})
        before = self.stored()
        st, answer = self.undo({'all': True}, token='v')
        self.assertEqual(st, 403, 'a viewer')
        self.tenancy()
        for token, who in (('v', 'a viewer'), ('b', 'the administrator of a tenant')):
            st, answer = self.undo({'all': True}, token=token)
            self.assertEqual(st, 403, (who, answer))
        self.assertIn('platform operator', answer['error'])
        st, _ = self.undo({'all': True}, token=None)
        self.assertEqual(st, 401)
        self.assertEqual(self.stored(), before, 'nothing was brought back by a request that was refused')
        st, answer = self.undo({'all': True}, token='k')
        self.assertEqual((st, answer['restored']), (200, 2), 'control: the platform operator can')

    def test_a_stored_cleared_at_that_is_not_a_whole_number_is_not_a_clear_and_is_left_as_it_is(self):
        st = self.state()
        st['items'][0]['cleared_at'] = 'x'
        self.api.save(self.api.NEWS_WATCH_FILE, st)
        self.api._LOAD_CACHE.clear()
        st, answer = self.undo({'all': True})
        self.assertEqual((st, answer['restored']), (200, 0), 'text is no time: the item was never cleared, and there is nothing to bring back')

# ── feeds that fail, and the state that is kept ──────────────────────────────

class TestTheFeeds(_Server):

    def test_a_feed_that_fails_is_recorded_and_the_others_are_still_read(self):
        self.settings(feeds=[FEED, FEED2])
        self.feeds[FEED] = OSError('connection refused')
        self.feeds[FEED2] = feed(entry(self.t, 'Quiet', guid='q'), title='Other')
        out = self.mod.poll_once(self.t)
        self.assertEqual((out['feeds'], out['failed']), (2, 1))
        st = self.state()['feeds']
        self.assertEqual((st[FEED]['last_error'], st[FEED]['fail_streak'], st[FEED2]['baselined'], st[FEED2]['title']), ('connection refused', 1, True, 'Other'))
        self.mod.poll_once(self.t + 1800)
        self.assertEqual(self.state()['feeds'][FEED]['fail_streak'], 2)
        self.feeds[FEED] = feed(entry(self.t, 'Quiet', guid='q'))
        self.mod.poll_once(self.t + 3600)
        st = self.state()['feeds'][FEED]
        self.assertEqual((st['last_error'], st['fail_streak'], st['baselined']), ('', 0, True), 'a read that works clears the failure')

    def test_the_reasons_a_read_fails_are_short_sentences_without_markup(self):
        import urllib.error
        for exc, want in ((urllib.error.HTTPError(FEED, 403, 'Forbidden', {}, None), 'HTTP 403'), (TimeoutError('The read operation timed out'), 'did not answer in time'),
                          (ValueError('this is not an RSS or Atom feed'), 'not an RSS'), (urllib.error.URLError('<b>name not known</b>\x07'), 'could not connect'),
                          (RuntimeError('x' * 900), 'RuntimeError')):
            self.feeds[FEED] = exc
            self.mod.poll_once(self.t)
            why = self.state()['feeds'][FEED]['last_error']
            self.assertIn(want, why)
            self.assertLessEqual(len(why), 160)
            self.assertNotIn('<', why)
            self.assertNotIn('\x07', why)

    def test_a_feed_that_is_not_a_feed_fails_and_a_hostile_one_changes_nothing(self):
        for bad in (b'<html><body>blocked</body></html>', b'<!DOCTYPE x [<!ENTITY a "b">]><rss version="2.0"><channel/></rss>', b''):
            self.feeds[FEED] = bad
            out = self.mod.poll_once(self.t)
            self.assertEqual(out['failed'], 1)
            self.assertEqual(self.state()['items'] if 'items' in self.state() else [], [])
            self.assertNotIn('baselined', self.state()['feeds'][FEED], 'a feed that never answered was not baselined')

    def test_a_feed_taken_out_of_the_list_loses_its_record(self):
        self.settings(feeds=[FEED, FEED2])
        self.feeds[FEED], self.feeds[FEED2] = feed(entry(self.t, 'a', guid='a')), feed(entry(self.t, 'b', guid='b'))
        self.mod.poll_once(self.t)
        self.assertEqual(sorted(self.state()['feeds']), sorted([FEED, FEED2]))
        self.settings(feeds=[FEED])
        self.mod.poll_once(self.t + 1800)
        self.assertEqual(list(self.state()['feeds']), [FEED])

    def test_a_feed_put_back_is_read_as_new_and_does_not_alert_for_what_it_holds(self):
        self.settings(feeds=[FEED, FEED2])
        for u in (FEED, FEED2):
            self.feeds[u] = feed(entry(self.t, 'q', guid='q'))
        self.mod.poll_once(self.t)
        self.settings(feeds=[FEED])
        self.mod.poll_once(self.t + 1800)
        self.settings(feeds=[FEED, FEED2])
        self.feeds[FEED2] = feed(entry(self.t, PHP[0], PHP[1], guid='p'))
        out = self.mod.poll_once(self.t + 3600)
        self.assertEqual((out['alerts'], self.alerts()), (0, []), 'its first read after being put back only records')

    def test_the_list_of_items_is_bounded_and_newest_first(self):
        self.poll(QUIET)
        for i in range(N.MAX_LISTED + 15):
            self.poll(QUIET, (f'Critical RCE flaw in PHP number {i}', 'php'), advance=1800)
        items = self.state()['items']
        self.assertEqual(len(items), N.MAX_LISTED)
        self.assertEqual(items[0]['title'], f'Critical RCE flaw in PHP number {N.MAX_LISTED + 14}')

    def test_the_store_passes_the_shape_registry_unchanged(self):
        import store_shapes
        self.poll(QUIET)
        self.poll(QUIET, PHP, CISCO, advance=1800)
        data = self.state()
        self.assertTrue(data['items'] and data['feeds'], 'control: there is something to check')
        self.assertEqual(repr(store_shapes.normalize('news_watch.json', json.loads(json.dumps(data)))), repr(json.loads(json.dumps(data))))


# ── the routes ───────────────────────────────────────────────────────────────

class TestTheRoutes(_Server):

    def test_the_operator_reads_the_page(self):
        self.poll(QUIET)
        self.poll(QUIET, PHP, advance=1800)
        st, got = self.request('/api/news-watch')
        self.assertEqual(st, 200, got)
        self.assertEqual((got['editable'], got['enabled'], got['feeds'], got['scope'], got['action']), (True, True, [FEED], 'relevant', 'scan'))
        self.assertEqual((got['every'], got['scan_gap'], got['max_feeds']), (1800, 6 * HOUR, N.MAX_FEEDS))
        (item,) = got['items']
        self.assertEqual((item['title'], item['reasons'], item['software'], item['outcome']), (PHP[0], ['critical'], ['php'], 'scanned'))
        self.assertEqual({k for k in item}, {'id', 'feed', 'title', 'link', 'published', 'seen_at', 'reasons', 'cves', 'cvss', 'software', 'running', 'outcome', 'cleared_at'})
        self.assertIsNone(item['cleared_at'], 'nobody has cleared it')
        self.assertEqual(item['running'], [], 'no host reports a process')
        (feed_state,) = got['status']
        self.assertEqual((feed_state['url'], feed_state['title'], feed_state['baselined'], feed_state['last_error']), (FEED, 'Example Security News', True, ''))
        self.assertNotIn('"seen"', json.dumps(got), 'the memory of ids is not sent to a page')

    def test_nobody_but_the_operator_reads_anything(self):
        self.poll(QUIET)
        self.poll(QUIET, PHP, advance=1800)
        self.tenancy()
        for token, who in (('v', 'a viewer'), ('b', 'the administrator of a tenant')):
            st, got = self.request('/api/news-watch', token=token)
            self.assertEqual((st, got), (200, {'editable': False}), who)
        st, got = self.request('/api/news-watch', token='k')
        self.assertEqual((st, got['editable'], len(got['items'])), (200, True, 1), 'control: the platform operator still reads it')
        st, _ = self.request('/api/news-watch', token=None)
        self.assertEqual(st, 401)

    def test_the_settings_are_the_platform_operators_to_change(self):
        self.tenancy()
        before = self.api.load(self.api.CONFIG_FILE)['news_watch']
        for token, want in (('v', 403), ('b', 403)):
            st, got = self.request('/api/news-watch/config', 'POST', token=token, body={'enabled': False, 'feeds': ['https://x.example/rss']})
            self.assertEqual(st, want, (token, got))
        st, got = self.request('/api/news-watch/run', 'POST', token='b')
        self.assertEqual(st, 403, got)
        self.assertIn('platform operator', got['error'])
        self.api._LOAD_CACHE.clear()
        self.assertEqual(self.api.load(self.api.CONFIG_FILE)['news_watch'], before, 'nothing was changed by a request that was refused')
        st, got = self.request('/api/news-watch/config', 'POST', token='k', body={'scope': 'all'})
        self.assertEqual((st, got['scope']), (200, 'all'))

    def test_a_save_changes_what_it_names_and_keeps_the_rest(self):
        st, got = self.request('/api/news-watch/config', 'POST', body={'action': 'alert', 'feeds': f'{FEED2}\n\n{FEED}'})
        self.assertEqual((st, got['ok'], got['action'], got['feeds'], got['scope'], got['enabled']), (200, True, 'alert', [FEED2, FEED], 'relevant', True))
        self.api._LOAD_CACHE.clear()
        self.assertEqual(self.api.load(self.api.CONFIG_FILE)['news_watch'], {'enabled': True, 'feeds': [FEED2, FEED], 'scope': 'relevant', 'action': 'alert', 'words': []})
        a = self.audits[-1]
        self.assertEqual(a[1], 'news_watch_config')
        self.assertIn('feeds=news.example.net,other.example.org', a[2])
        self.assertNotIn('security.xml', a[2], 'the audit log holds the hosts of the feeds and not their paths')

    def test_a_save_that_names_one_bad_value_is_refused_whole(self):
        self.api._LOAD_CACHE.clear()
        before = self.api.load(self.api.CONFIG_FILE)['news_watch']
        for body, word in (({'enabled': False, 'scope': 'nope'}, 'scope'), ({'feeds': ['https://u:p@x.example/rss']}, 'user name'), ({'feeds': ['https://x.example/rss?token=1']}, 'token'),
                           ({'feeds': ['ftp://x.example/rss']}, 'http'), ({'feeds': [f'https://h{i}.example/x' for i in range(N.MAX_FEEDS + 1)]}, 'at most'),
                           ({'action': 'delete'}, 'action'), ({'enabled': 'perhaps'}, 'enabled')):
            st, got = self.request('/api/news-watch/config', 'POST', body=body)
            self.assertEqual(st, 400, body)
            self.assertIn(word, got['error'])
            self.api._LOAD_CACHE.clear()
            self.assertEqual(self.api.load(self.api.CONFIG_FILE)['news_watch'], before, 'one bad value saves none of the others: %s' % body)
        for junk in ([], 'x', 7, None):
            st, got = self.request('/api/news-watch/config', 'POST', body=junk)
            self.assertIn(st, (200, 400), junk)

    def test_the_methods_are_the_ones_the_routes_name(self):
        for path, method in (('/api/news-watch', 'DELETE'), ('/api/news-watch/config', 'GET'), ('/api/news-watch/run', 'GET')):
            st, _got = self.request(path, method)
            self.assertIn(st, (404, 405), (path, method))

    def test_check_now_reads_acts_and_answers_with_the_page(self):
        self.config(last_news_watch_run=int(time.time()))      # a request runs the cadence first: the sweep is not due, so the read below is the button's
        self.poll(QUIET)
        self.feeds[FEED] = feed(entry(self.t, QUIET[0], guid=QUIET[0]), entry(self.t, PHP[0], PHP[1], guid='php'))
        self.api.save(self.api.NEWS_WATCH_FILE, dict(self.state(), last_run=int(time.time()) - 3600))
        self.api._LOAD_CACHE.clear()
        st, got = self.request('/api/news-watch/run', 'POST', body={})
        self.assertEqual(st, 200, got)
        self.assertEqual((got['ok'], got['result']['alerts'], got['result']['scan'], got['items'][0]['outcome']), (True, 1, 'started', 'scanned'))

    def test_check_now_is_refused_when_the_watch_is_off_and_when_the_feeds_were_just_read(self):
        self.settings(enabled=False)
        st, got = self.request('/api/news-watch/run', 'POST', body={})
        self.assertEqual((st, self.fetched), (409, []))
        self.settings(enabled=True)
        self.config(last_news_watch_run=int(time.time()))
        self.feeds[FEED] = feed(entry(self.t, 'Quiet', guid='q'))
        self.mod.poll_once(self.t)
        st, got = self.request('/api/news-watch/run', 'POST', body={})
        self.assertEqual(st, 429, got)
        self.assertLessEqual(got['retry_after_seconds'], self.mod.MANUAL_GAP_S)
        self.assertEqual(len(self.fetched), 1, 'a refused request read nothing')


# ── the alert, as the inbox and the channels see it ──────────────────────────

class TestTheAlert(_Server):

    def test_the_severity_follows_whether_the_item_names_software_on_the_hosts(self):
        self.assertEqual(self.api._alert_severity(EVENT, {'severity': 'high'}), 'high')
        self.assertEqual(self.api._alert_severity(EVENT, {'severity': 'medium'}), 'medium')
        for junk in ('critical', 'low', '', None, 7, 'HIGH '):
            self.assertIn(self.api._alert_severity(EVENT, {'severity': junk}), ('medium', 'high'), junk)
        self.assertEqual(self.api._alert_severity(EVENT, {'severity': 'critical'}), 'medium', 'a feed cannot make a headline critical')
        self.assertEqual(self.api._alert_severity(EVENT, {}), 'medium')

    def test_the_event_is_registered_as_something_that_happened_and_is_never_a_fault_of_a_host(self):
        reg = self.api.EVENT_REGISTRY[EVENT]
        self.assertEqual((reg['lifecycle'], reg['kind'], reg['title'], reg['severity']), ('point', 'security_news', 'Critical Security News', None))
        self.assertIn(EVENT, {ev for ev, _label, _default in self.api.WEBHOOK_EVENTS})
        slot = self.api._kind_default('security_news')
        self.assertFalse(slot['needs_attention'], 'news about the world is not on the list of what is broken')

    def test_the_message_a_channel_gets_carries_the_headline_the_source_the_reason_and_the_link(self):
        import notify
        msg = notify._webhook_message(EVENT, {'title': 'PHP Fixes 7 Critical Flaws', 'source': 'Example Security News', 'detail': 'called critical.', 'url': 'https://news.example.net/php'})
        self.assertEqual(msg, 'PHP Fixes 7 Critical Flaws (Example Security News): called critical. https://news.example.net/php')
        self.assertTrue(notify._webhook_message(EVENT, {}).startswith('A critical flaw was reported'))

    def test_a_headline_with_markup_is_stored_as_text(self):
        self.poll(QUIET)
        self.poll(QUIET, ('Critical <script>alert(1)</script> flaw in PHP', '<img src=x onerror=alert(1)> php'), advance=1800)
        (a,) = self.alerts()
        self.assertNotIn('<', a['title'] + json.dumps(a['payload']))

    def test_two_headlines_are_two_rows_in_the_inbox(self):
        self.poll(QUIET)
        self.poll(QUIET, PHP, NGINX, advance=1800)
        titles = sorted(a['payload']['title'] for a in self.alerts())
        self.assertEqual(titles, sorted([PHP[0], NGINX[0]]))


# ── reading a feed over the network ──────────────────────────────────────────

class TestTheFetch(_Server):

    def setUp(self):
        super().setUp()
        self.mod._fetch = self.real_fetch        # the real one: the fixture put a stand-in on the instance
        self.real = self.mod._fetch

    def test_an_address_that_is_not_somewhere_a_feed_comes_from_is_refused_before_a_connection_is_made(self):
        for url in ('http://127.0.0.1:1/feed', 'http://localhost/feed', 'http://169.254.169.254/latest/meta-data/', 'http://0.0.0.0/x', 'http://[::1]/feed'):
            with self.assertRaises(ValueError, msg=url):
                self.real(url)

    def test_the_connection_is_checked_at_connect_time_too(self):
        """The pre-flight resolves a name once and a rebinding server can answer differently the second time, so the opener the fetch builds looks at the address the
        connection really reached. A server that answers is on loopback here: the guard must close the connection before a byte of the response is read."""
        import urllib.error

        class Hello(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'reached')

            def log_message(self, *a):
                pass
        base = self._serve(Hello)
        op = self.api._ssrf_safe_opener(allow_loopback=False, ssl_ctx=self.api._get_ssl_context(), no_redirect=False, enforce_ip=True)
        with self.assertRaises(urllib.error.URLError) as cm:
            op.open(urllib.request.Request(base + '/'), timeout=3)
        self.assertIn('SSRF guard', str(cm.exception))
        open_op = urllib.request.build_opener()
        self.assertEqual(open_op.open(urllib.request.Request(base + '/'), timeout=3).read(), b'reached', 'control: the server does answer when nothing guards the connection')
        with self.assertRaises(urllib.error.URLError):
            op.open(urllib.request.Request('file:///etc/passwd'), timeout=3)

    def _serve(self, handler_cls):
        srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler_cls)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(lambda: (srv.shutdown(), srv.server_close()))
        return f'http://127.0.0.1:{srv.server_address[1]}'

    def _open_to_loopback(self):
        """The guard refuses loopback, which is where a test server lives: let it through for the checks of the read itself."""
        self.api._url_targets_local_or_meta = lambda parsed, allow_loopback=True: False
        self.api._ssrf_safe_opener = lambda **kw: urllib.request.build_opener()

    def test_a_feed_over_the_size_limit_is_refused_while_it_is_read(self):
        class Big(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Type', 'application/xml')
                self.end_headers()
                try:
                    for _ in range(60):
                        self.wfile.write(b'<!-- ' + b'x' * 65000 + b' -->')
                except OSError:
                    pass

            def log_message(self, *a):
                pass
        base = self._serve(Big)
        self._open_to_loopback()
        with self.assertRaises(ValueError) as cm:
            self.real(base + '/feed')
        self.assertIn('larger than', str(cm.exception))

    def test_a_server_that_sends_a_byte_at_a_time_is_cut_off_by_the_deadline(self):
        class Drip(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                try:
                    for _ in range(100):
                        self.wfile.write(b'x')
                        self.wfile.flush()
                        time.sleep(0.05)
                except OSError:
                    pass

            def log_message(self, *a):
                pass
        base = self._serve(Drip)
        self._open_to_loopback()
        self.mod.FETCH_DEADLINE_S = 0.4
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            self.real(base + '/feed')
        self.assertLess(time.monotonic() - started, 3, 'the read ended at its deadline and not when the server was done')

    def test_a_feed_is_read_through_a_redirect_with_the_right_headers(self):
        seen = {}

        class Redirect(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/start':
                    self.send_response(302)
                    self.send_header('Location', '/final')
                    self.end_headers()
                    return
                seen['ua'], seen['accept'] = self.headers.get('User-Agent'), self.headers.get('Accept')
                body = feed(entry(int(time.time()), 'Quiet', guid='q'))
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        base = self._serve(Redirect)
        self._open_to_loopback()
        got = N.parse_feed(self.real(base + '/start'))
        self.assertEqual([i['title'] for i in got['items']], ['Quiet'])
        self.assertTrue(seen['ua'].startswith('RemotePower/'))
        self.assertIn('rss+xml', seen['accept'])

    def test_a_server_that_answers_an_error_is_an_error(self):
        class Gone(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(403)
                self.end_headers()

            def log_message(self, *a):
                pass
        base = self._serve(Gone)
        self._open_to_loopback()
        import urllib.error
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.real(base + '/feed')
        cm.exception.close()


if __name__ == '__main__':
    unittest.main()

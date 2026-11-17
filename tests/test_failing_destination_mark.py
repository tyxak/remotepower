#!/usr/bin/env python3
"""A notification destination that keeps failing is marked in Settings.

The third failed delivery in a row to one destination raises `notify_dest_failing` and keeps the streak in notify_health.json (never the address). The alert and the
delivery log said so; the destination list in Settings did not. `GET /api/config` (the route that list is drawn from) now carries two fields on a failing
destination: `fail_streak` (how many in a row) and `fail_class` (the kind of the last error, one word of a closed list). Never the address, and never the text a
remote system answered.

Failures come through the real fan-out (`fire_webhook`, the delivery, the streak) with the network replaced by an opener that refuses, times out, fails to resolve,
refuses the certificate or answers an HTTP status by host name. Held to:

  * a streak of three shows through the real route, two does not, four says four, and a destination that recovered shows nothing;
  * the class is the right word for each kind of failure (a connection refused, a timeout, a name that does not resolve, a certificate, 401, 404, 503, a blocked
    address, a destination missing its credentials) and `other` for anything else, whatever junk the stored text holds;
  * the two fields hold no address, no host, no part of the path (which is a credential) and nothing a remote system said;
  * editing what a destination is delivered with clears its streak and closes its alert; renaming it or changing its filters does not. Each of the fields in
    `_NOTIFY_DELIVERY_FIELDS` is edited in turn through the real Settings save (a list of cases that must cover the whole tuple), and a streak that never raised an alert
    is forgotten without an announcement;
  * a settings document exported and applied back unchanged keeps every streak, with a config master key armed (the only case in which the destinations are importable and
    the address is ciphertext, new on every export) as much as without one, and one real change in it still clears;
  * a destination that is removed or switched off is forgotten when the list is saved, by the Settings save, an applied document and a restored revision alike, and a stale
    streak of a switched-off destination is not drawn;
  * the administrator of the operator's organisation sees the mark, and a read-only user, an mcp key, an auditor, a finance user, a custom role and a tenant's
    administrator read the list exactly as before, with a streak or without.
"""
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-failing-dest-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from request_harness import RequestCase  # noqa: E402

SECRET = 'T0PS3CRETPATH'
A = {'id': 'wh_a', 'name': 'Chat ops', 'url': f'https://down.example.org/services/{SECRET}', 'format': 'generic', 'enabled': True}
B = {'id': 'wh_b', 'name': 'Pager', 'url': 'https://up.example.org/hook', 'format': 'generic', 'enabled': True}
EVENT = 'server_disk_low'


class _Response:
    status = 200

    def read(self, *_a):
        return b'{}'


class Network:
    """The opener the product asks for. `behave[host]` is 'ok', 'refuse', 'timeout', 'dns', 'tls', 'boom' or 'http<code>'."""

    def __init__(self):
        self.behave = {'down.example.org': 'refuse', 'up.example.org': 'ok'}

    def opener(self, *_a, **_k):
        return self

    def open(self, req, timeout=10):
        host = req.full_url.split('/')[2]
        how = self.behave.get(host, 'ok')
        if how == 'refuse':
            raise urllib.error.URLError(f'[Errno 111] Connection refused while reaching {req.full_url}')
        if how == 'timeout':
            raise urllib.error.URLError('timed out')
        if how == 'dns':
            raise urllib.error.URLError('[Errno -2] Name or service not known')
        if how == 'tls':
            raise urllib.error.URLError('[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate')
        if how == 'boom':
            raise RuntimeError(f'broken pipe to {req.full_url}')
        if how.startswith('http'):
            raise urllib.error.HTTPError(req.full_url, int(how[4:]), 'Reason: ' + SECRET, {}, None)
        return _Response()


class _Failing(RequestCase):
    FAKE_FIRE = False

    def setUp(self):
        super().setUp()
        self.net = Network()
        self.told = []
        real = self.api.fire_webhook

        def spy(event, payload=None, *a, **k):
            self.told.append((event, dict(payload or {})))
            return real(event, payload, *a, **k)
        self.api.fire_webhook = spy
        self.api._ssrf_safe_opener = self.net.opener
        self.real_target_check = self.api._url_targets_local_or_meta
        self.api._url_targets_local_or_meta = lambda parsed, allow_loopback=True: False        # no name lookups in a test: the one test of the real check puts it back
        self.destinations([A, B])

    def destinations(self, dests, **cfg):
        self.api.save(self.api.CONFIG_FILE, dict({'webhook_urls': dests, 'webhook_block_local': False}, **cfg))
        self.api._LOAD_CACHE.clear()

    def event(self, n=1):
        """n real events through the whole firing path."""
        for _ in range(n):
            self.api.save(self.api.WEBHOOK_RATELIMIT_FILE, {})                   # the send cap is not what these tests are about
            self.api._LOAD_CACHE.clear()
            self.api.fire_webhook(EVENT, {'name': 'server', 'percent': 97})
        self.api._LOAD_CACHE.clear()

    def health(self):
        self.api._LOAD_CACHE.clear()
        return self.api.load(self.api.NOTIFY_HEALTH_FILE) or {}

    def fails(self, dest='wh_a'):
        """The streak the product itself recorded. The third failure raises the alert, and the alert is delivered through every destination, the failing one
        included, so the streak of a destination that failed three events is four."""
        return (self.health().get('wh:' + dest) or {}).get('fails')

    def plant(self, fails, error='URLError [generic]: [Errno 111] Connection refused', dest='wh_a'):
        self.api.save(self.api.NOTIFY_HEALTH_FILE, {'wh:' + dest: {'fails': fails, 'since': 1, 'last': 2, 'error': error, 'label': 'Chat ops', 'alerted': fails >= 3}})
        self.api._LOAD_CACHE.clear()

    def config(self, token='k'):
        st, out = self.request('/api/config', token=token)
        self.assertEqual(st, 200, out)
        return out

    def mark(self, dest='wh_a', token='k'):
        got = {d['id']: d for d in self.config(token)['webhook_urls']}[dest]
        return got.get('fail_streak'), got.get('fail_class')

    def open_alerts(self):
        self.api._LOAD_CACHE.clear()
        return [a for a in (self.api.load(self.api.ALERTS_FILE) or {}).get('alerts', []) if a.get('event') == 'notify_dest_failing' and not a.get('resolved_at')]

    def save(self, dests, token='k'):
        return self.request('/api/config', 'POST', token=token, body={'webhook_urls': dests})


class TestTheMarkThroughTheRoute(_Failing):

    def test_a_streak_of_three_shows_with_its_count_and_the_kind_of_the_last_error(self):
        self.plant(3)
        self.assertEqual(self.mark(), (3, 'unreachable'))

    def test_the_real_fan_out_records_a_streak_that_shows(self):
        self.event(3)
        self.assertGreaterEqual(self.fails(), 3, 'control: the product counted the failures')
        self.assertEqual(self.mark(), (self.fails(), 'unreachable'))

    def test_two_do_not_and_four_say_four(self):
        self.event(2)
        self.assertEqual((self.fails(), self.mark()), (2, (None, None)))
        self.plant(4)
        self.assertEqual(self.mark(), (4, 'unreachable'))
        self.plant(2)
        self.assertEqual(self.mark(), (None, None), 'below three it is not a mark however it got there')

    def test_a_destination_that_delivers_has_no_mark(self):
        self.event(4)
        self.assertEqual(self.mark('wh_b'), (None, None))
        self.assertEqual(sorted(d['id'] for d in self.config()['webhook_urls']), ['wh_a', 'wh_b'])

    def test_a_destination_that_recovered_shows_nothing(self):
        self.event(3)
        self.assertGreaterEqual(self.mark()[0], 3)
        self.net.behave['down.example.org'] = 'ok'
        self.event(1)
        self.assertNotIn('wh:wh_a', self.health())
        self.assertEqual(self.mark(), (None, None))
        self.assertEqual(self.open_alerts(), [])

    def test_the_route_adds_two_fields_and_no_others(self):
        before = {d['id']: d for d in self.config()['webhook_urls']}['wh_a']
        self.plant(3)
        after = {d['id']: d for d in self.config()['webhook_urls']}['wh_a']
        self.assertEqual(sorted(set(after) - set(before)), ['fail_class', 'fail_streak'])
        self.assertEqual({k: v for k, v in after.items() if k not in ('fail_class', 'fail_streak')}, before)

    def test_the_two_fields_hold_no_address_no_host_and_nothing_a_remote_system_said(self):
        self.net.behave['down.example.org'] = 'http503'               # the reason phrase carries the secret path
        self.event(3)
        got = {d['id']: d for d in self.config()['webhook_urls']}['wh_a']
        self.assertEqual((got['fail_streak'], got['fail_class']), (self.fails(), 'http_5xx'))
        text = json.dumps([got['fail_streak'], got['fail_class']])
        for leak in (SECRET, 'down.example.org', 'https', 'Reason', '503'):
            self.assertNotIn(leak, text)
        self.assertIn(self.api._notify_error_class(self.health()['wh:wh_a']['error']), self.api_classes())

    def api_classes(self):
        return ('timeout', 'unreachable', 'dns', 'tls', 'auth', 'http_4xx', 'http_5xx', 'blocked', 'config', 'other')

    def test_each_kind_of_failure_through_the_real_fan_out_is_the_right_word(self):
        for how, want in (('refuse', 'unreachable'), ('timeout', 'timeout'), ('dns', 'dns'), ('tls', 'tls'), ('boom', 'unreachable'), ('http401', 'auth'), ('http403', 'auth'),
                          ('http404', 'http_4xx'), ('http429', 'http_4xx'), ('http500', 'http_5xx'), ('http503', 'http_5xx')):
            self.api.save(self.api.NOTIFY_HEALTH_FILE, {})
            self.net.behave['down.example.org'] = how
            self.event(3)
            self.assertEqual(self.mark(), (self.fails(), want), how)
            self.assertGreaterEqual(self.fails(), 3, how)

    def test_a_blocked_address_has_its_word(self):
        self.api._url_targets_local_or_meta = self.real_target_check               # the real pre-flight check, over a loopback address
        self.destinations([dict(A, url='http://127.0.0.1:9/hook')], webhook_block_local=True, webhook_allow_loopback=False)
        self.event(3)
        self.assertEqual(self.mark('wh_a'), (self.fails('wh_a'), 'blocked'))
        self.assertGreaterEqual(self.fails('wh_a'), 3)

    def test_a_destination_missing_its_credentials_has_its_word(self):
        self.destinations([A, dict(B, id='wh_p', name='Push', format='pushover', url='https://api.pushover.net/1/messages.json')])
        self.event(3)
        self.assertEqual(self.mark('wh_p'), (self.fails('wh_p'), 'config'))
        self.assertGreaterEqual(self.fails('wh_p'), 3)

    def test_the_stored_text_is_read_into_a_word_whatever_it_holds(self):
        for text, want in (
                ('HTTP 401 [generic]: Unauthorized', 'auth'), ('HTTP 404 [slack]: Not Found', 'http_4xx'), ('HTTP 502 [generic]: Bad Gateway', 'http_5xx'),
                ('URLError [generic]: [Errno 111] Connection refused', 'unreachable'), ('URLError [generic]: _ssl.c:1011: The handshake operation timed out', 'timeout'),
                ('URLError [discord]: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed', 'tls'), ('URLError [ntfy]: [Errno -3] Temporary failure in name resolution', 'dns'),
                ('URLError [generic]: [Errno 101] Network is unreachable', 'unreachable'), ('URLError [generic]: [Errno 113] No route to host', 'unreachable'),
                ('blocked: target resolves to a metadata or local address', 'blocked'), ('invalid scheme (must be http or https)', 'config'),
                ('Pushover destination missing token/user — set them in Settings → Notifications', 'config'), ('TimeoutError [generic]: timed out', 'timeout'),
                ('ValueError [generic]: something nobody planned for', 'other'), ('', 'other'), (None, 'other'), (0, 'other'), ([1, 2], 'other'), ({'a': 1}, 'other'),
                ('HTTP 999 [generic]: nonsense', 'other'), ('HTTP 200 [generic]: odd', 'other'), ('x' * 100000, 'other'), ('\u0000\ud800', 'other'),
                ('HTTP 4', 'other'), ('http 503', 'http_5xx'), ('HTTP 503', 'http_5xx')):
            self.assertEqual(self.api._notify_error_class(text), want, repr(text)[:80])
        self.assertEqual(set(self.api_classes()) - {'other'}, {self.api._notify_error_class(t) for t in (
            'HTTP 401', 'HTTP 404', 'HTTP 502', 'Connection refused', 'timed out', 'certificate', 'Name or service not known', 'blocked: target resolves x',
            'invalid scheme')}, 'control: every word of the list is reached')

    def test_a_stored_streak_that_is_junk_is_not_a_mark_and_not_an_error(self):
        for fails in ('three', None, [3], {'n': 3}, -5, 1.5, 2, True):
            self.api.save(self.api.NOTIFY_HEALTH_FILE, {'wh:wh_a': {'fails': fails, 'error': 'timed out', 'alerted': True}})
            self.api._LOAD_CACHE.clear()
            got = self.mark()
            self.assertEqual(got, (None, None), fails)
        self.api.save(self.api.NOTIFY_HEALTH_FILE, {'wh:wh_a': {'fails': 7, 'error': ['x'], 'alerted': True}, 'wh:wh_b': 'junk', 'email': {'fails': 9}})
        self.api._LOAD_CACHE.clear()
        self.assertEqual(self.mark(), (7, 'other'))
        self.assertEqual(self.mark('wh_b'), (None, None))

    def test_the_two_fields_the_page_posts_back_are_not_stored(self):
        """The page keeps the list it read and posts all of it on save, the two fields with it. They describe the deliveries, not the destination."""
        self.plant(3)
        listed = self.config()['webhook_urls']
        self.assertTrue(any(d.get('fail_streak') for d in listed), 'control: the page reads the mark')
        st, out = self.save(listed)
        self.assertEqual(st, 200, out)
        self.api._LOAD_CACHE.clear()
        stored = self.api.load(self.api.CONFIG_FILE)['webhook_urls']
        self.assertEqual(sorted(d['id'] for d in stored), ['wh_a', 'wh_b'], 'control: both destinations were saved')
        for d in stored:
            self.assertNotIn('fail_streak', d)
            self.assertNotIn('fail_class', d)
        self.assertEqual(self.mark(), (3, 'unreachable'), 'and saving the same settings leaves the streak where it was')

    def test_reading_the_list_writes_nothing(self):
        self.event(3)
        before = json.dumps(self.health(), sort_keys=True)
        self.config()
        self.config()
        self.assertEqual(json.dumps(self.health(), sort_keys=True), before)


class TestEditingClearsIt(_Failing):

    def failing(self):
        self.event(3)
        self.assertGreaterEqual(self.mark()[0], 3, 'control')
        self.assertEqual(len(self.open_alerts()), 1, 'control: the alert is open')

    def edited(self, **change):
        st, out = self.save([dict(A, **change), B])
        self.assertEqual(st, 200, out)

    def test_a_new_address_clears_the_mark_and_closes_the_alert(self):
        self.failing()
        self.edited(url='https://elsewhere.example.org/hook')
        self.assertEqual(self.mark(), (None, None))
        self.assertNotIn('wh:wh_a', self.health())
        self.assertEqual(self.open_alerts(), [])
        closed = [p for e, p in self.told if e == 'notify_dest_recovered']
        self.assertEqual(len(closed), 1)
        self.assertIn('was edited', closed[0]['detail'])
        self.assertNotIn(SECRET, json.dumps(closed))

    def test_a_new_format_or_credential_clears_it_too(self):
        for change in ({'format': 'discord'}, {'hmac_secret': 's3cret'}, {'headers': {'X-Api-Key': 'k'}}):
            self.api.save(self.api.NOTIFY_HEALTH_FILE, {})
            self.destinations([A, B])
            self.failing_quiet()
            st, out = self.save([dict(A, **change), B])
            self.assertEqual(st, 200, (change, out))
            self.assertEqual(self.mark(), (None, None), change)

    def failing_quiet(self):
        self.api.save(self.api.ALERTS_FILE, {'alerts': []})
        self.event(3)
        self.assertGreaterEqual(self.mark()[0], 3)

    def test_a_new_name_or_filter_does_not(self):
        for change in ({'name': 'Chat operations'}, {'min_priority': 4}, {'events': [EVENT]}, {'digest_minutes': 5}, {'on_ack': True}, {'enabled': True}):
            self.api.save(self.api.NOTIFY_HEALTH_FILE, {})
            self.destinations([A, B])
            self.failing_quiet()
            st, out = self.save([dict(A, **change), B])
            self.assertEqual(st, 200, (change, out))
            self.assertGreaterEqual(self.mark()[0] or 0, 3, change)

    def test_saving_the_list_unchanged_does_not(self):
        self.failing()
        had = self.mark()
        st, out = self.save([A, B])
        self.assertEqual(st, 200, out)
        self.assertEqual(self.mark(), had)
        self.assertEqual(len(self.open_alerts()), 1)

    def test_editing_one_destination_leaves_the_streak_of_another(self):
        self.destinations([A, dict(B, url='https://also-down.example.org/hook')])
        self.net.behave['also-down.example.org'] = 'timeout'
        self.event(3)
        both = (self.mark('wh_a')[0], self.mark('wh_b')[0])
        self.assertTrue(all(n and n >= 3 for n in both), both)
        st, out = self.save([dict(A, url='https://elsewhere.example.org/hook'), dict(B, url='https://also-down.example.org/hook')])
        self.assertEqual(st, 200, out)
        # the edit's own announcement ("it was edited, the streak is cleared") is delivered through the destination that still fails, which counts one more
        self.assertIsNone(self.mark('wh_a')[0], 'the edited destination starts over')
        self.assertGreaterEqual(self.mark('wh_b')[0] or 0, both[1], 'and the other keeps what it had')

    def test_a_destination_that_fails_again_after_an_edit_is_marked_again(self):
        self.failing()
        self.edited(url='https://still-down.example.org/hook')
        self.net.behave['still-down.example.org'] = 'timeout'
        self.event(3)
        self.assertEqual(self.mark(), (self.fails(), 'timeout'))
        self.assertGreaterEqual(self.fails(), 3)
        self.assertEqual(len(self.open_alerts()), 1, 'and told again')


class TestTheOtherWritersOfTheList(_Failing):
    """The settings save is not the only thing that changes a destination's address: a settings document applied from a file replaces the list, and so does a
    restored revision. Both start the destination again, as the save does, and both leave one that kept its address alone."""

    def failing(self):
        self.event(3)
        self.assertGreaterEqual(self.mark()[0], 3, 'control')
        self.assertEqual(len(self.open_alerts()), 1, 'control: the alert is open')

    def importable(self):
        """The destinations of a settings document are importable once a config master key is armed (the export is lossless then). The import step is the same code
        either way, so the test lifts that one flag and arms no key."""
        real = self.api._declarative_meta

        def meta():
            m = real()
            m['webhook_destinations'] = dict(m['webhook_destinations'], importable=True)
            return m
        self.api._declarative_meta = meta

    def apply(self, dests):
        doc = {'schema': self.api.DECLARATIVE_SCHEMA, 'resources': {'webhook_destinations': dests}}
        res = self.api._declarative_apply(doc, 'tester', dry_run=False)
        self.assertTrue(res['ok'], res)
        self.assertNotIn('skipped', res['report']['webhook_destinations'], res)
        self.api._LOAD_CACHE.clear()

    def restore(self, dests):
        self.api.save(self.api.CONFIG_REVS_FILE, {'revisions': [{'id': 'rev-1', 'ts': 1, 'user': 'x', 'changed_keys': ['webhook_urls'],
                                                                 'config': {'webhook_urls': dests, 'webhook_block_local': False}}]})
        self.api._LOAD_CACHE.clear()
        st, out = self.request('/api/config/revisions/restore', 'POST', body={'id': 'rev-1'})
        self.assertEqual(st, 200, out)

    def test_applying_a_settings_document_with_a_new_address_starts_it_again(self):
        self.importable()
        self.failing()
        self.apply([dict(A, url='https://elsewhere.example.org/hook'), B])
        self.assertEqual(self.api.load(self.api.CONFIG_FILE)['webhook_urls'][0]['url'], 'https://elsewhere.example.org/hook', 'control: the document was applied')
        self.assertEqual(self.mark(), (None, None))
        self.assertNotIn('wh:wh_a', self.health())
        self.assertEqual(self.open_alerts(), [])

    def test_applying_a_settings_document_that_keeps_the_address_leaves_it(self):
        self.importable()
        self.failing()
        had = self.mark()
        self.apply([dict(A, name='Chat operations', min_priority=4), B])
        self.assertEqual(self.api.load(self.api.CONFIG_FILE)['webhook_urls'][0]['name'], 'Chat operations', 'control: the document was applied')
        self.assertEqual(self.mark(), had)
        self.assertEqual(len(self.open_alerts()), 1)

    def test_a_dry_run_of_a_settings_document_leaves_it(self):
        self.importable()
        self.failing()
        had = self.mark()
        doc = {'schema': self.api.DECLARATIVE_SCHEMA, 'resources': {'webhook_destinations': [dict(A, url='https://elsewhere.example.org/hook'), B]}}
        res = self.api._declarative_apply(doc, 'tester', dry_run=True)
        self.assertTrue(res['ok'], res)
        self.assertEqual(self.mark(), had)

    def test_restoring_a_revision_with_another_address_starts_it_again(self):
        self.failing()
        self.restore([dict(A, url='https://earlier.example.org/hook'), B])
        self.assertEqual(self.api.load(self.api.CONFIG_FILE)['webhook_urls'][0]['url'], 'https://earlier.example.org/hook', 'control: the revision is live')
        self.assertEqual(self.mark(), (None, None))
        self.assertNotIn('wh:wh_a', self.health())
        self.assertEqual(self.open_alerts(), [])

    def test_restoring_a_revision_that_keeps_the_address_leaves_it(self):
        self.failing()
        had = self.mark()
        self.restore([dict(A, name='Chat operations'), B])
        self.assertEqual(self.api.load(self.api.CONFIG_FILE)['webhook_urls'][0]['name'], 'Chat operations', 'control: the revision is live')
        self.assertEqual(self.mark(), had)
        self.assertEqual(len(self.open_alerts()), 1)

    def test_lists_of_any_kind_are_read_without_raising_and_clear_nothing_they_do_not_name(self):
        self.failing()
        had = self.mark()
        for before, after in ((None, None), (5, [A]), ([A], 5), ('x', 'y'), ({'wh_a': A}, {'wh_a': A}), ([A], {'wh_a': A}), (True, False),
                              ([None, 3, 'x', {'id': ['wh_a']}, {'id': None}, {}], [None, 3, {'id': None, 'url': 'x'}, {'id': ['wh_a'], 'url': 'y'}, {}]),
                              ([{'id': 'None', 'url': 'a'}], [{'url': 'b'}])):
            self.api._notify_health_forget_edited(before, after)
            self.assertEqual(self.mark(), had, repr((before, after))[:80])
        # a list that does name it clears it, whatever else is odd about the entry
        self.api._notify_health_forget_edited([{'id': 'wh_a', 'headers': {'a': {1}}}], [{'id': 'wh_a', 'headers': {'a': {2}}, 'url': 5}])
        self.assertEqual(self.mark(), (None, None), 'control')


class TestWhoSeesTheMark(_Failing):

    NOT_THE_OPERATOR = ('v', 'mc', 'au', 'fi', 'ops', 'rw', 'ro')           # every kind of caller of the harness except the administrator

    def lists(self, tokens):
        return {t: json.dumps(self.config(t)['webhook_urls'], sort_keys=True) for t in tokens}

    def test_the_administrator_sees_it_and_nobody_else_reads_anything_new(self):
        quiet = self.lists(('k',) + self.NOT_THE_OPERATOR)
        self.event(3)
        loud = self.lists(('k',) + self.NOT_THE_OPERATOR)
        self.assertNotEqual(quiet['k'], loud['k'], 'control: the administrator reads the mark')
        for token in self.NOT_THE_OPERATOR:
            self.assertEqual(loud[token], quiet[token], token)
            self.assertNotIn('fail_', loud[token], token)

    def test_with_isolation_on_the_operator_sees_it_and_a_tenants_administrator_and_user_do_not(self):
        self.destinations([A, B], tenancy_enforced=True)
        quiet = self.lists(('ta', 'tb', 'tv'))
        self.event(3)
        self.assertEqual(self.mark('wh_a', 'k'), (self.fails('wh_a'), 'unreachable'), 'the platform operator')
        self.assertGreaterEqual(self.fails('wh_a'), 3)
        loud = self.lists(('ta', 'tb', 'tv'))
        self.assertEqual(loud, quiet)
        for token, text in loud.items():
            self.assertNotIn('fail_', text, token)

    def test_a_viewer_reads_the_same_list_as_before_down_to_the_last_field(self):
        before = self.config('v')['webhook_urls']
        self.event(5)
        after = self.config('v')['webhook_urls']
        self.assertEqual(after, before)
        self.assertTrue(all(d.get('url_set') is True and d.get('url') == '' for d in after), 'and as before it has no address')

    def test_the_mark_is_not_in_any_other_answer(self):
        self.event(3)
        self.assertGreaterEqual(self.mark()[0], 3, 'control: there is a mark to find')
        for path in ('/api/me', '/api/home', '/api/nav-counts', '/api/self/status', '/api/webhook/log', '/api/alerts'):
            try:
                st, out = self.request(path)
            except self.api.HTTPError as e:                  # a conditional GET raises its answer directly
                st, out = e.status, e.body
            self.assertEqual(st, 200, path)
            self.assertTrue(out, 'control: %s answered with something to read' % path)
            text = json.dumps(out, default=str)
            self.assertNotIn('fail_streak', text, path)
            self.assertNotIn('fail_class', text, path)


# What each field of `_NOTIFY_DELIVERY_FIELDS` needs to be edited for real: a destination of a format that uses it, and the change. The list is held to the tuple by a test of its
# own, so a field added to the tuple without a case here fails instead of going unchecked. The destinations are on addresses that deliver (the fake network answers every host
# but `down.example.org`): the announcement that an edit cleared a streak is delivered through the destinations too, and one that still failed would start a streak of its own
# a moment later, which is true and is not what is being looked at here.
HEALTHY = dict(A, url='https://up.example.org/hook')
DELIVERY_CASES = {
    'url': (dict(A), {'url': 'https://elsewhere.example.org/hook'}),
    'format': (dict(HEALTHY), {'format': 'discord'}),
    'pushover_token': (dict(A, format='pushover', url='https://api.pushover.net/1/messages.json', pushover_token='tok1', pushover_user='usr1'), {'pushover_token': 'tok2'}),
    'pushover_user': (dict(A, format='pushover', url='https://api.pushover.net/1/messages.json', pushover_token='tok1', pushover_user='usr1'), {'pushover_user': 'usr2'}),
    'token': (dict(A, format='github', url='https://api.github.com/repos/o/r/issues', token='pat1'), {'token': 'pat2'}),
    'itsm_user': (dict(A, format='servicenow', url='https://x.service-now.com/api/now/table/incident', itsm_user='u1', itsm_secret='s1'), {'itsm_user': 'u2'}),
    'itsm_secret': (dict(A, format='servicenow', url='https://x.service-now.com/api/now/table/incident', itsm_user='u1', itsm_secret='s1'), {'itsm_secret': 's2'}),
    'jira_project': (dict(A, format='jira', url='https://x.atlassian.net/rest/api/2/issue', itsm_user='u1', itsm_secret='s1', jira_project='OPS', jira_issuetype='Task'),
                     {'jira_project': 'SEC'}),
    'jira_issuetype': (dict(A, format='jira', url='https://x.atlassian.net/rest/api/2/issue', itsm_user='u1', itsm_secret='s1', jira_project='OPS', jira_issuetype='Task'),
                       {'jira_issuetype': 'Bug'}),
    'telegram_chat_id': (dict(A, format='telegram', url='https://api.telegram.org/bot1/sendMessage', telegram_chat_id='111'), {'telegram_chat_id': '222'}),
    'matrix_token': (dict(A, format='matrix', url='https://hs.example.org/_matrix/client/v3/rooms/r/send/m.room.message', matrix_token='m1'), {'matrix_token': 'm2'}),
    'hmac_secret': (dict(HEALTHY, hmac_secret='s3cret'), {'hmac_secret': 's3cret-2'}),
    'headers': (dict(HEALTHY, headers={'X-Api-Key': 'k1'}), {'headers': {'X-Api-Key': 'k2'}}),
}


class TestEveryDeliveryFieldClearsIt(_Failing):

    def recovered(self):
        return [p for e, p in self.told if e == 'notify_dest_recovered']

    def start_over(self, dest, fails=4):
        self.api.save(self.api.ALERTS_FILE, {'alerts': []})
        self.api.save(self.api.NOTIFY_HEALTH_FILE, {})
        self.destinations([dest, B])
        self.plant(fails)
        del self.told[:]

    def test_the_cases_cover_every_field_of_the_tuple_and_nothing_else(self):
        self.assertEqual(sorted(DELIVERY_CASES), sorted(self.api._NOTIFY_DELIVERY_FIELDS),
                         'a field of _NOTIFY_DELIVERY_FIELDS with no case here is a field nobody has watched clear a streak')
        self.assertEqual(len(set(self.api._NOTIFY_DELIVERY_FIELDS)), len(self.api._NOTIFY_DELIVERY_FIELDS), 'no field twice')

    def test_each_case_changes_the_field_it_is_named_for(self):
        for field, (dest, change) in DELIVERY_CASES.items():
            with self.subTest(field):
                self.assertEqual(sorted(change), [field])
                self.assertNotEqual(dest.get(field), change[field], 'the edit is a change')

    def test_saving_each_destination_as_it_is_leaves_the_streak(self):
        """The control of the test below: what is saved here is stored as it was sent, so a clear after an edit is the edit's doing and not the form's."""
        for field, (dest, _change) in DELIVERY_CASES.items():
            with self.subTest(field):
                self.start_over(dest)
                st, out = self.save([dest, B])
                self.assertEqual(st, 200, out)
                self.assertEqual(self.mark(), (4, 'unreachable'), 'saving it unchanged leaves the streak')
                self.assertEqual(self.recovered(), [])

    def test_editing_each_field_clears_the_streak_and_announces_that_it_was_edited(self):
        for field, (dest, change) in DELIVERY_CASES.items():
            with self.subTest(field):
                self.start_over(dest)
                self.assertEqual(self.mark(), (4, 'unreachable'), 'control: the destination is failing')
                st, out = self.save([dict(dest, **change), B])
                self.assertEqual(st, 200, out)
                self.assertEqual(self.mark(), (None, None), f'editing {field} left the mark')
                self.assertNotIn('wh:wh_a', self.health())
                got = self.recovered()
                self.assertEqual(len(got), 1, f'editing {field} announced {len(got)} recoveries')
                self.assertIn('was edited', got[0]['detail'])

    def test_a_streak_that_never_raised_an_alert_is_forgotten_by_an_edit_and_nothing_is_announced(self):
        for fails in (1, 2):
            with self.subTest(fails=fails):
                self.start_over(dict(A), fails=fails)
                self.assertFalse(self.health()['wh:wh_a']['alerted'], 'control: no alert was raised for it')
                st, out = self.save([dict(A, url='https://elsewhere.example.org/hook'), B])
                self.assertEqual(st, 200, out)
                self.assertNotIn('wh:wh_a', self.health(), 'the count starts again')
                self.assertEqual(self.recovered(), [], 'and nobody is told something recovered that was never reported as failing')

    def test_a_streak_that_never_raised_an_alert_is_forgotten_by_a_switch_off_and_nothing_is_announced(self):
        self.start_over(dict(A), fails=2)
        st, out = self.save([dict(A, enabled=False), B])
        self.assertEqual(st, 200, out)
        self.assertNotIn('wh:wh_a', self.health())
        self.assertEqual(self.recovered(), [])


class TestAnImportThatChangesNothing(_Failing):
    """A settings document can be applied back only when a config master key is armed: the export then holds the address, the header values and the Pushover user as
    ciphertext (a new nonce on every export) where the store holds the text. The first version compared the two as they were and cleared every streak on an import that
    changed nothing, and sent a recovery for each of them."""

    def setUp(self):
        saved = os.environ.get('RP_CONFIG_KEY')
        os.environ['RP_CONFIG_KEY'] = 'k' * 40

        def back():
            if saved is None:
                os.environ.pop('RP_CONFIG_KEY', None)
            else:
                os.environ['RP_CONFIG_KEY'] = saved
        self.addCleanup(back)
        super().setUp()
        self.assertTrue(self.api.backup_crypto.available(), 'cryptography is a dependency of the test job: without it this module proves nothing')
        # wh_a delivers (its streak is planted: a delivery that got through would end it), wh_p still fails (a delivery to it counts one more and does not end it)
        self.rich = dict(A, url=f'https://up.example.org/services/{SECRET}', headers={'X-Api-Key': 'abc123'}, hmac_secret='s3cret')
        self.push = dict(B, id='wh_p', name='Push', format='pushover', url='https://api.pushover.net/1/messages.json', pushover_token='tok', pushover_user='usr')
        self.net.behave['api.pushover.net'] = 'refuse'
        self.destinations([self.rich, B, self.push])
        self.api.save(self.api.NOTIFY_HEALTH_FILE, {
            'wh:wh_a': {'fails': 5, 'since': 1, 'last': 2, 'error': 'URLError [generic]: [Errno 111] Connection refused', 'label': 'Chat ops', 'alerted': True},
            'wh:wh_p': {'fails': 3, 'since': 1, 'last': 2, 'error': 'HTTP 401 [pushover]: nope', 'label': 'Push', 'alerted': True}})
        self.api._LOAD_CACHE.clear()
        del self.told[:]

    def export(self):
        doc = self.api._build_declarative_config()
        self.assertTrue(self.api._declarative_meta()['webhook_destinations']['importable'], 'control: the destinations are importable with the key armed')
        return doc

    def apply(self, doc):
        res = self.api._declarative_apply(doc, 'tester', dry_run=False)
        self.assertTrue(res['ok'], res)
        self.assertNotIn('skipped', res['report']['webhook_destinations'], res)
        self.api._LOAD_CACHE.clear()

    def streaks(self):
        return {k: v['fails'] for k, v in self.health().items()}

    def test_the_document_holds_ciphertext_and_the_store_the_text(self):
        doc = self.export()
        dests = {d['id']: d for d in doc['resources']['webhook_destinations']}
        self.assertTrue(dests['wh_a']['url'].startswith('enc:v2:'))
        self.assertTrue(dests['wh_a']['headers']['X-Api-Key'].startswith('enc:v2:'))
        self.assertTrue(dests['wh_p']['pushover_user'].startswith('enc:v2:'))
        stored = {d['id']: d for d in self.api.load(self.api.CONFIG_FILE)['webhook_urls']}
        self.assertEqual(stored['wh_a']['url'], self.rich['url'], 'the store reads back as text')
        self.assertNotEqual(self.export()['resources']['webhook_destinations'][0]['url'], dests['wh_a']['url'], 'and no two exports are the same: the nonce is new each time')

    def test_an_export_applied_back_untouched_keeps_every_streak_and_says_nothing(self):
        for round_ in range(2):                     # the second export is another set of ciphertexts for the same text
            with self.subTest(round=round_):
                self.apply(self.export())
                self.assertEqual(self.streaks(), {'wh:wh_a': 5, 'wh:wh_p': 3})
                self.assertEqual([p for e, p in self.told if e == 'notify_dest_recovered'], [])
                self.assertEqual(self.mark('wh_a'), (5, 'unreachable'))

    def test_an_export_with_one_address_changed_clears_that_destination_and_no_other(self):
        doc = self.export()
        for d in doc['resources']['webhook_destinations']:
            if d['id'] == 'wh_a':
                d['url'] = self.api._cfg_enc('https://elsewhere.example.org/hook')
        self.apply(doc)
        self.assertNotIn('wh:wh_a', self.streaks(), 'control: a real change through the same path still clears')
        self.assertGreaterEqual(self.streaks().get('wh:wh_p', 0), 3, 'and the other destination keeps its own (the announcement fails through it once more)')
        self.assertEqual(len([1 for e, _p in self.told if e == 'notify_dest_recovered']), 1)

    def test_a_changed_header_or_pushover_user_clears_it_and_a_re_sealed_one_does_not(self):
        doc = self.export()
        for d in doc['resources']['webhook_destinations']:
            if d['id'] == 'wh_a':
                d['headers'] = {'X-Api-Key': self.api._cfg_enc('abc123')}           # the same text, sealed again
            if d['id'] == 'wh_p':
                d['pushover_user'] = self.api._cfg_enc('usr')
        self.apply(doc)
        self.assertEqual(self.streaks(), {'wh:wh_a': 5, 'wh:wh_p': 3})
        doc = self.export()
        for d in doc['resources']['webhook_destinations']:
            if d['id'] == 'wh_a':
                d['headers'] = {'X-Api-Key': self.api._cfg_enc('another')}
        self.apply(doc)
        self.assertNotIn('wh:wh_a', self.streaks())
        self.assertGreaterEqual(self.streaks().get('wh:wh_p', 0), 3)

    def test_the_view_compares_ciphertext_and_text_of_the_same_value_as_equal(self):
        view = self.api._notify_delivery_view
        sealed = dict(self.rich, url=self.api._cfg_enc(self.rich['url']), headers={'X-Api-Key': self.api._cfg_enc('abc123')})
        self.assertEqual(view(sealed), view(self.rich))
        self.assertNotEqual(view(dict(sealed, url=self.api._cfg_enc('https://other.example.org/hook'))), view(self.rich))
        self.assertEqual(view({'id': 'x'}), view({'id': 'y', 'url': None}), 'a field that is missing reads as None on both sides')
        self.assertNotIn('name', view(self.rich), 'only what it is delivered with')


class TestTheViewWithoutAKey(_Failing):

    def test_without_a_key_the_text_is_compared_as_it_is(self):
        self.assertFalse(self.api._config_master_key(), 'control: no key is armed here')
        view = self.api._notify_delivery_view
        self.assertEqual(view(A), view(dict(A, name='Renamed')))
        self.assertNotEqual(view(A), view(dict(A, url='https://elsewhere.example.org/hook')))
        self.assertEqual(view(dict(A, url='enc:v2:abc')), view(dict(A, url='enc:v2:abc')), 'a value that looks sealed is only text when there is no key to open it')
        self.assertNotEqual(view(dict(A, url='enc:v2:abc')), view(dict(A, url='enc:v2:abd')))


class TestSwitchedOffIsForgottenWhenTheListIsSaved(_Failing):

    def failing(self):
        self.event(3)
        self.assertGreaterEqual(self.mark()[0], 3, 'control: it is failing')
        self.assertEqual(len(self.open_alerts()), 1, 'control: the alert is open')
        del self.told[:]

    def recovered(self):
        return [p for e, p in self.told if e == 'notify_dest_recovered']

    def test_a_switch_off_by_the_settings_save_takes_the_mark_and_the_alert_at_once(self):
        self.failing()
        st, out = self.save([dict(A, enabled=False), B])
        self.assertEqual(st, 200, out)
        listed = {d['id']: d for d in self.config()['webhook_urls']}['wh_a']
        self.assertIs(listed['enabled'], False)
        self.assertNotIn('fail_streak', listed)
        self.assertNotIn('fail_class', listed)
        self.assertNotIn('wh:wh_a', self.health())
        self.assertEqual(self.open_alerts(), [])
        got = self.recovered()
        self.assertEqual(len(got), 1)
        self.assertIn('removed or switched off', got[0]['detail'])
        self.assertNotIn(SECRET, json.dumps(got))

    def test_removing_the_destination_does_the_same(self):
        self.failing()
        st, out = self.save([B])
        self.assertEqual(st, 200, out)
        self.assertNotIn('wh:wh_a', self.health())
        self.assertEqual(self.open_alerts(), [])
        self.assertEqual(len(self.recovered()), 1)

    def test_switching_it_on_again_starts_the_count_at_nothing(self):
        self.failing()
        self.save([dict(A, enabled=False), B])
        self.save([A, B])
        self.assertEqual(self.mark(), (None, None))
        self.event(1)
        self.assertEqual(self.fails(), 1, 'the first failure after it came back is the first')

    def test_the_other_destination_keeps_its_streak(self):
        self.destinations([A, dict(B, url='https://also-down.example.org/hook')])
        self.net.behave['also-down.example.org'] = 'timeout'
        self.event(3)
        both = (self.mark('wh_a')[0], self.mark('wh_b')[0])
        self.assertTrue(all(n and n >= 3 for n in both), both)
        st, out = self.save([dict(A, enabled=False), dict(B, url='https://also-down.example.org/hook')])
        self.assertEqual(st, 200, out)
        self.assertNotIn('wh:wh_a', self.health())
        self.assertGreaterEqual(self.mark('wh_b')[0] or 0, both[1])

    def test_a_save_that_does_not_touch_the_list_touches_no_streak(self):
        self.failing()
        had = self.health()
        st, out = self.request('/api/config', 'POST', body={'server_name': 'renamed-server'})
        self.assertEqual(st, 200, out)
        self.assertEqual(self.health(), had)
        self.assertEqual(self.recovered(), [])

    def test_a_streak_stored_for_a_switched_off_destination_is_not_drawn(self):
        """However it got there (a switch-off made by editing the store, or a streak that landed just before the save): the card of a destination that delivers nothing
        is not marked as failing."""
        self.destinations([dict(A, enabled=False), B])
        self.plant(4)
        self.assertIn('wh:wh_a', self.health(), 'control: the streak is stored')
        listed = {d['id']: d for d in self.config()['webhook_urls']}['wh_a']
        self.assertIs(listed['enabled'], False)
        self.assertNotIn('fail_streak', listed)
        self.assertNotIn('fail_class', listed)
        self.destinations([dict(A, enabled=True), B])
        self.assertEqual(self.mark(), (4, 'unreachable'), 'control: switched on, the same stored streak is drawn')

    def test_the_hook_reads_the_saved_settings_and_not_the_lists_it_was_handed(self):
        """Code that decides what still exists reads the settings as saved. The two lists a writer hands over are what changed, and they name one destination."""
        self.failing()
        had = self.health()
        self.api._notify_destinations_changed([B], [dict(B, name='Renamed')])
        self.assertEqual(self.health(), had, 'a list that does not mention the failing destination does not forget it')
        self.assertEqual(self.recovered(), [])


class TestSwitchedOffByTheOtherWritersOfTheList(_Failing):

    def failing(self):
        self.event(3)
        self.assertGreaterEqual(self.mark()[0], 3, 'control')
        self.assertEqual(len(self.open_alerts()), 1, 'control: the alert is open')

    def test_a_settings_document_that_switches_it_off_forgets_it(self):
        real = self.api._declarative_meta

        def meta():
            m = real()
            m['webhook_destinations'] = dict(m['webhook_destinations'], importable=True)
            return m
        self.api._declarative_meta = meta
        self.failing()
        doc = {'schema': self.api.DECLARATIVE_SCHEMA, 'resources': {'webhook_destinations': [dict(A, enabled=False), B]}}
        res = self.api._declarative_apply(doc, 'tester', dry_run=False)
        self.assertTrue(res['ok'], res)
        self.assertNotIn('skipped', res['report']['webhook_destinations'], res)
        self.api._LOAD_CACHE.clear()
        self.assertNotIn('wh:wh_a', self.health())
        self.assertEqual(self.open_alerts(), [])

    def test_a_restored_revision_that_has_it_switched_off_forgets_it(self):
        self.failing()
        self.api.save(self.api.CONFIG_REVS_FILE, {'revisions': [{'id': 'rev-1', 'ts': 1, 'user': 'x', 'changed_keys': ['webhook_urls'],
                                                                 'config': {'webhook_urls': [dict(A, enabled=False), B], 'webhook_block_local': False}}]})
        self.api._LOAD_CACHE.clear()
        st, out = self.request('/api/config/revisions/restore', 'POST', body={'id': 'rev-1'})
        self.assertEqual(st, 200, out)
        self.assertNotIn('wh:wh_a', self.health())
        self.assertEqual(self.open_alerts(), [])


if __name__ == '__main__':
    unittest.main()

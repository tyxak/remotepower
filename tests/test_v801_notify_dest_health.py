"""A notification destination that keeps failing is reported (8.0.1).

A webhook whose address was revoked, or a mail server whose password expired, failed quietly: each failed
delivery was a line in the delivery log and an entry in the dead-letter list, and nothing told anyone. From
then on the alerts simply stopped arriving, which looks exactly like a quiet day.

Now the third failed delivery in a row to one destination raises `notify_dest_failing`: an alert in the inbox,
and a notification through every other destination. The next delivery that gets through raises
`notify_dest_recovered`, which closes it. A destination that is removed or switched off takes its alert with
it. What was not tried (filtered, held for a digest, a dry run, over the send rate) is neither.

Driven through the real fan-out (`fire_webhook`, `_send_webhook_to_url`, `_dispatch_one_webhook`, the mail
channel) with the network replaced: an opener that refuses, answers 404 or answers 200 by host name.
"""
import importlib.util
import os
import re
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v801-notify-'))
_spec = importlib.util.spec_from_file_location('api_v801_notify', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import srcpin  # noqa: E402

_APP = (ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
SECRET = 'T0PS3CRETPATH'
A = {'id': 'wh_a', 'name': 'Chat ops', 'url': f'https://down.example.org/services/{SECRET}', 'format': 'generic'}
B = {'id': 'wh_b', 'name': 'Pager', 'url': 'https://up.example.org/hook', 'format': 'generic'}
EVENT = 'server_disk_low'


class _Response:
    status = 200

    def read(self, *_a):
        return b'{}'


class Network:
    """The opener the product asks for. `behave[host]` is 'ok', 'refuse', 'http404' or 'boom'."""

    def __init__(self):
        self.behave = {'down.example.org': 'refuse', 'up.example.org': 'ok'}
        self.posts = []          # (host, the event named in the request's X-Title or body)

    def opener(self, *_a, **_k):
        return self

    def open(self, req, timeout=10):
        host = req.full_url.split('/')[2]
        self.posts.append((host, (req.data or b'').decode('utf-8', 'replace')))
        how = self.behave.get(host, 'ok')
        if how == 'refuse':
            raise urllib.error.URLError(f'connection refused while reaching {req.full_url}')
        if how == 'http404':
            raise urllib.error.HTTPError(req.full_url, 404, 'Not Found', {}, None)
        if how == 'boom':
            raise RuntimeError(f'broken pipe to {req.full_url}')
        return _Response()

    def to(self, host):
        return [body for h, body in self.posts if h == host]


class _Base(unittest.TestCase):
    CONFIG = {'webhook_urls': [A, B], 'webhook_block_local': False}

    def setUp(self):
        self.net = Network()
        self.fired = []
        real_fire = api.fire_webhook

        def spy(event, payload):
            self.fired.append((event, dict(payload)))
            return real_fire(event, payload)
        patches = [mock.patch.object(api, '_ssrf_safe_opener', self.net.opener),
                   mock.patch.object(api, 'fire_webhook', spy),
                   mock.patch.object(api, '_url_targets_local_or_meta', lambda parsed, allow_loopback=True: False)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.config(self.CONFIG)
        for f, empty in ((api.ALERTS_FILE, {'alerts': []}), (api.NOTIFY_HEALTH_FILE, {}),
                         (api.WEBHOOK_LOG_FILE, {'entries': []}), (api.WEBHOOK_DLQ_FILE, {'entries': []}),
                         (api.WEBHOOK_RATELIMIT_FILE, {}), (api.MAINT_FILE, {'windows': []})):
            api.save(f, empty)
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for f, empty in ((api.CONFIG_FILE, {}), (api.ALERTS_FILE, {'alerts': []}), (api.NOTIFY_HEALTH_FILE, {})):
            api.save(f, empty)
        api._LOAD_CACHE.clear()

    def config(self, cfg):
        api.save(api.CONFIG_FILE, dict(cfg))
        api._LOAD_CACHE.clear()

    def event(self, n=1, name=EVENT):
        """n real events through the whole firing path."""
        for _ in range(n):
            api._LOAD_CACHE.clear()
            api.fire_webhook(name, {'name': 'server', 'percent': 97})
        api._LOAD_CACHE.clear()

    def health(self):
        api._LOAD_CACHE.clear()
        return api.load(api.NOTIFY_HEALTH_FILE) or {}

    def alerts(self, open_only=True):
        api._LOAD_CACHE.clear()
        rows = [a for a in (api.load(api.ALERTS_FILE) or {}).get('alerts', []) if a.get('event') == 'notify_dest_failing']
        return [a for a in rows if not a.get('resolved_at')] if open_only else rows

    def announced(self, event='notify_dest_failing'):
        return [p for e, p in self.fired if e == event]


class TestAWebhookThatKeepsFailing(_Base):
    def watch_the_health_store(self):
        """The list of times the health store is opened for writing, from now to the end of the test."""
        opened, real = [], api._LockedUpdate

        def guard(path, *a, **k):
            if Path(str(path)).name == 'notify_health.json':
                opened.append(str(path))
            return real(path, *a, **k)
        patch = mock.patch.object(api, '_LockedUpdate', guard)
        patch.start()
        self.addCleanup(patch.stop)
        return opened

    def test_two_failures_are_not_yet_news(self):
        self.event(2)
        self.assertEqual(self.health()['wh:wh_a']['fails'], 2)
        self.assertEqual(self.announced(), [])
        self.assertEqual(self.alerts(), [])

    def test_the_third_is(self):
        self.event(3)
        (payload,) = self.announced()
        self.assertEqual(payload['label'], 'Chat ops')
        self.assertIn('has failed 3 deliveries in a row', payload['detail'])
        (alert,) = self.alerts()
        self.assertEqual(alert['severity'], 'high')
        self.assertEqual(alert['payload']['label'], 'Chat ops')
        self.assertIn('has failed 3 deliveries in a row', alert['summary'] if 'summary' in alert else alert['payload']['detail'])

    def test_the_other_destination_is_told(self):
        self.event(3)
        told = [b for b in self.net.to('up.example.org') if 'notify_dest_failing' in b or 'Chat ops' in b]
        self.assertEqual(len(told), 1, self.net.to('up.example.org'))
        self.assertIn('Chat ops', told[0])

    def test_it_is_said_once_however_long_it_lasts(self):
        self.event(9)
        self.assertEqual(len(self.announced()), 1)
        self.assertEqual(len(self.alerts(open_only=False)), 1)
        self.assertGreaterEqual(self.health()['wh:wh_a']['fails'], 9)

    def test_the_address_is_never_in_what_is_said(self):
        self.event(4)
        said = repr(self.announced()) + repr(self.alerts()) + repr(self.health())
        self.assertNotIn(SECRET, said)
        self.assertNotIn('down.example.org/services', said)
        # 8.0.2: what is kept of a failure is its kind, not its text. This line said the reason was kept with the address cut out of it ('connection refused' and
        # '[address]'), which is a scrub that knew one way of writing an address; tests/test_v802_notify_dest_secret.py holds the rest of it
        self.assertEqual(self.health()['wh:wh_a']['error'], 'connection refused or unreachable')

    def test_a_destination_that_delivers_writes_nothing(self):
        """The common case: no failure on record, so the health store is not opened for writing at all."""
        self.config({'webhook_urls': [B], 'webhook_block_local': False})
        opened = self.watch_the_health_store()
        self.event(5)
        self.assertEqual(len(self.net.to('up.example.org')), 5)
        self.assertEqual(opened, [])
        self.assertEqual(self.health(), {})

    def test_and_a_failure_does_open_it(self):
        """The control for the test above: the guard sees the store when there is something to write."""
        opened = self.watch_the_health_store()
        self.event(1)
        self.assertEqual(len(opened), 1)

    def test_an_answer_of_404_counts_too(self):
        self.net.behave['down.example.org'] = 'http404'
        self.event(3)
        (payload,) = self.announced()
        self.assertIn('HTTP 404', payload['detail'])

    def test_a_send_that_breaks_counts_too_and_the_alert_says_what_kind_it_was(self):
        self.net.behave['down.example.org'] = 'boom'            # RuntimeError('broken pipe to <the address>')
        self.event(3)
        (payload,) = self.announced()
        self.assertIn('connection refused or unreachable', payload['detail'])
        self.assertNotIn(SECRET, payload['detail'])
        self.assertNotIn('broken pipe', payload['detail'], 'what the exception said is not copied into the alert')


class TestWhatWasNotTriedIsNotAFailure(_Base):
    def streak(self):
        return (self.health().get('wh:wh_a') or {}).get('fails', 0)

    def test_an_event_the_destination_does_not_take(self):
        self.config({'webhook_urls': [dict(A, events=['device_offline']), B], 'webhook_block_local': False})
        self.event(5)
        self.assertEqual((self.streak(), self.announced()), (0, []))

    def test_a_dry_run(self):
        self.config({'webhook_urls': [dict(A, dry_run=True), B], 'webhook_block_local': False})
        self.event(5)
        self.assertEqual((self.streak(), self.announced()), (0, []))

    def test_an_event_held_for_a_digest(self):
        self.config({'webhook_urls': [dict(A, digest_minutes=30), B], 'webhook_block_local': False})
        self.event(5, name='device_online')
        self.assertEqual((self.streak(), self.announced()), (0, []))

    def test_a_send_over_the_rate(self):
        with mock.patch.object(api, '_webhook_rate_limit_ok', lambda: False):
            self.event(5)
        self.assertEqual((self.streak(), self.announced()), (0, []))
        self.assertEqual(self.net.posts, [])

    def test_the_digest_itself_is_a_delivery(self):
        """What is held is not tried. The summary that goes out later is, and a destination that only ever
        gets summaries is watched through them."""
        self.config({'webhook_urls': [dict(A, digest_minutes=1), B], 'webhook_block_local': False})
        for _round in range(3):
            self.event(1, name='device_online')
            api.save(api.WEBHOOK_DIGEST_FILE, {k: dict(v, first_ts=1) if isinstance(v, dict) else v
                                               for k, v in (api.load(api.WEBHOOK_DIGEST_FILE) or {}).items()})
            api._LOAD_CACHE.clear()
            api.run_webhook_digests_if_due()
            api._LOAD_CACHE.clear()
        summaries = [b for b in self.net.to('down.example.org') if 'notifications held over the last' in b]
        self.assertEqual(len(summaries), 3)
        self.assertEqual(len(self.announced()), 1)

    def test_and_none_of_them_ends_a_streak(self):
        self.event(2)
        self.config({'webhook_urls': [dict(A, dry_run=True), B], 'webhook_block_local': False})
        self.event(3)
        self.assertEqual(self.streak(), 2)
        self.config(self.CONFIG)
        self.event(1)
        self.assertEqual(len(self.announced()), 1)

    def test_the_reading_of_one_delivery(self):
        read = api._delivery_outcome
        self.assertIsNone(read([]))
        self.assertIsNone(read(None))
        self.assertIsNone(read([('digest', 'queued'), ('dry-run', 'x'), ('filtered', 'x'), ('suppressed', 'x'),
                                ('disabled', 'x'), ('error', 'rate-limited: over 30 webhooks/60s')]))
        self.assertEqual(read([(200, 'OK')]), (True, ''))
        self.assertEqual(read([('204', 'OK')]), (True, ''))
        # 8.0.2: a 3xx is a redirect the opener refused (urllib raises an HTTPError, which the dead-letter list files), so it is a failure; this line said
        # (True, '') for 399 and was true to the reading it pinned, which called every status under 400 delivered
        self.assertEqual(read([(399, '')]), (False, ''))
        self.assertEqual(read([(302, 'HTTP 302')]), (False, 'HTTP 302'))
        self.assertEqual(read([(400, 'HTTP 400')]), (False, 'HTTP 400'))
        self.assertEqual(read([(503, 'HTTP 503 [generic]: x')]), (False, 'HTTP 503 [generic]: x'))
        self.assertEqual(read([('error', 'URLError: refused')]), (False, 'URLError: refused'))
        self.assertEqual(read([('error', 'invalid scheme (must be http or https)')])[0], False)
        self.assertEqual(read([('٢٠٠', 'not a status')]), None)


class TestADestinationThatCannotWorkAsItIsSet(_Base):
    """A wrong scheme, an address the filter refuses and a missing key never reach the network, and are
    failures all the same: the destination delivers nothing."""

    def three(self, dest, **cfg):
        self.config(dict({'webhook_urls': [dest, B], 'webhook_block_local': False}, **cfg))
        self.event(3)
        return self.announced()

    def test_a_scheme_that_is_not_http(self):
        (payload,) = self.three(dict(A, url='ftp://files.example.org/in'))
        self.assertIn('invalid scheme', payload['detail'])

    def test_a_missing_key(self):
        (payload,) = self.three(dict(A, format='pushover'))
        self.assertIn('missing settings', payload['detail'])

    def test_an_address_the_filter_refuses(self):
        refused = lambda parsed, allow_loopback=True: parsed.hostname == 'down.example.org'   # noqa: E731
        with mock.patch.object(api, '_url_targets_local_or_meta', refused):
            (payload,) = self.three(dict(A), webhook_block_local=True)
        self.assertIn('blocked', payload['detail'])


class TestItRecovers(_Base):
    def test_the_first_delivery_that_gets_through_closes_it(self):
        self.event(3)
        self.assertEqual(len(self.alerts()), 1)
        self.net.behave['down.example.org'] = 'ok'
        self.event(1)
        (payload,) = self.announced('notify_dest_recovered')
        self.assertEqual(payload['label'], 'Chat ops')
        self.assertEqual(self.alerts(), [])
        self.assertEqual(len(self.alerts(open_only=False)), 1)             # kept as history, resolved
        self.assertNotIn('wh:wh_a', self.health())

    def test_a_streak_that_never_reached_three_ends_without_a_word(self):
        self.event(2)
        self.net.behave['down.example.org'] = 'ok'
        self.event(1)
        self.assertEqual(self.health(), {})
        self.assertEqual(self.announced('notify_dest_recovered'), [])
        self.net.behave['down.example.org'] = 'refuse'
        self.event(2)                                                      # two again, not four
        self.assertEqual(self.announced(), [])

    def test_it_can_fail_again_and_is_said_again(self):
        self.event(3)
        self.net.behave['down.example.org'] = 'ok'
        self.event(1)
        self.net.behave['down.example.org'] = 'refuse'
        self.event(3)
        self.assertEqual(len(self.announced()), 2)
        self.assertEqual(len(self.alerts()), 1)

    def test_a_retry_from_the_dead_letter_list_that_gets_through_closes_it(self):
        self.event(3)
        self.net.behave['down.example.org'] = 'ok'
        api._LOAD_CACHE.clear()
        entry = (api.load(api.WEBHOOK_DLQ_FILE) or {}).get('entries')[0]
        self.assertEqual(entry['dest']['id'], 'wh_a')
        self.assertTrue(api._dlq_retry_entry(entry))
        self.assertEqual(self.alerts(), [])
        self.assertEqual(len(self.announced('notify_dest_recovered')), 1)

    def test_two_failing_destinations_are_two_alerts_and_each_closes_its_own(self):
        self.net.behave['up.example.org'] = 'http404'
        self.event(3)
        self.assertEqual(sorted(a['payload']['label'] for a in self.alerts()), ['Chat ops', 'Pager'])
        self.net.behave['up.example.org'] = 'ok'
        self.event(1)
        self.assertEqual([a['payload']['label'] for a in self.alerts()], ['Chat ops'])


class TestADestinationThatIsGone(_Base):
    def test_removing_it_closes_its_alert(self):
        self.event(3)
        self.config({'webhook_urls': [B], 'webhook_block_local': False})
        self.event(1)
        (payload,) = self.announced('notify_dest_recovered')
        self.assertIn('was removed or switched off', payload['detail'])
        self.assertEqual(self.alerts(), [])
        self.assertEqual(self.health(), {})

    def test_switching_it_off_does_too(self):
        self.event(3)
        self.config({'webhook_urls': [dict(A, enabled=False), B], 'webhook_block_local': False})
        self.event(1)
        self.assertEqual(self.alerts(), [])

    def test_a_streak_that_was_never_announced_is_forgotten_quietly(self):
        self.event(2)
        self.config({'webhook_urls': [B], 'webhook_block_local': False})
        self.event(1)
        self.assertEqual(self.health(), {})
        self.assertEqual(self.announced('notify_dest_recovered'), [])

    def test_a_destination_that_is_still_there_is_left_alone(self):
        self.event(3)
        self.event(1)
        self.assertEqual(len(self.alerts()), 1)
        self.assertEqual(self.announced('notify_dest_recovered'), [])


class TestSendTestOnOneDestination(_Base):
    """The button sends through a config that holds only the destination it was pressed on."""

    def press(self, dest):
        api._LOAD_CACHE.clear()
        cfg = api.load(api.CONFIG_FILE)
        synthetic = {**cfg, 'webhook_url': '', 'webhook_urls': [{**dest, 'enabled': True}]}
        api._fire_webhook_with_cfg('test', {'server_version': api.SERVER_VERSION, 'triggered_by': 'admin'}, synthetic)
        api._LOAD_CACHE.clear()

    def test_a_test_of_another_destination_leaves_the_failing_one_as_it_is(self):
        self.event(3)
        self.press(B)
        self.assertEqual(len(self.alerts()), 1)
        self.assertEqual(self.announced('notify_dest_recovered'), [])
        self.assertGreaterEqual(self.health()['wh:wh_a']['fails'], 3)

    def test_a_test_that_gets_through_closes_the_alert(self):
        self.event(3)
        self.net.behave['down.example.org'] = 'ok'
        self.press(A)
        self.assertEqual(self.alerts(), [])
        self.assertEqual(len(self.announced('notify_dest_recovered')), 1)

    def test_a_test_that_fails_counts(self):
        self.press(A)
        self.press(A)
        self.press(A)
        self.assertEqual(len(self.announced()), 1)

    def test_the_handler_sends_through_that_path(self):
        src = (_CGI / 'api.py').read_text()
        self.assertIn('_fire_webhook_with_cfg(', srcpin.py_function(src, 'handle_webhook_test'))
        self.assertIn('_send_webhook_to_url(event, safe_payload, message, cfg)',
                      srcpin.py_function(src, '_fire_webhook_with_cfg'))
        self.assertIn('_notify_health_prune(_config_ro())', srcpin.py_function(src, '_send_webhook_to_url'))


class TestTheNamesADestinationGoesBy(unittest.TestCase):
    def test_the_key_is_the_id_and_never_the_address(self):
        key = api._notify_dest_key
        self.assertEqual(key(A), 'wh:wh_a')
        self.assertEqual(key({'id': 'legacy', 'url': 'https://x.example.org/a'}), 'wh:legacy')
        no_id = key({'url': f'https://hooks.example.org/{SECRET}'})
        self.assertRegex(no_id, r'^wh:[0-9a-f]{16}$')
        self.assertNotIn(SECRET, no_id)
        self.assertEqual(no_id, key({'url': f'https://hooks.example.org/{SECRET}', 'name': 'renamed'}))
        self.assertNotEqual(no_id, key({'url': 'https://hooks.example.org/other'}))
        self.assertLessEqual(len(key({'id': 'x' * 500})), 64)

    def test_the_label_is_the_given_name_or_the_host(self):
        label = api._notify_dest_label
        self.assertEqual(label(A), 'Chat ops')
        self.assertEqual(label({'url': f'https://hooks.example.org:8443/{SECRET}?token={SECRET}'}),
                         'https://hooks.example.org:8443')
        self.assertEqual(label({'url': f'https://user:{SECRET}@hooks.example.org/x'}), 'https://hooks.example.org')
        self.assertEqual(label({}), 'Webhook')
        self.assertLessEqual(len(label({'name': 'n' * 500})), 80)


class TestTheMailServer(_Base):
    CONFIG = {'smtp_enabled': True, 'smtp_host': 'mail.example.org', 'smtp_recipients': 'ops@example.org',
              'webhook_urls': [B], 'webhook_block_local': False}

    def setUp(self):
        super().setUp()
        self.mail = []
        self.mail_fails = True

        def send_email(cfg, recipients, subject, body, **_kw):
            self.mail.append(subject)
            if self.mail_fails:
                raise api.smtp_notifier.SmtpError('authentication failed: 535 5.7.8 bad credentials')
        patches = [mock.patch.object(api.smtp_notifier, 'send_email', send_email),
                   mock.patch.object(api, 'is_email_event_enabled', lambda event, cfg=None: True),
                   mock.patch.object(api, '_event_email_routes', lambda cfg, payload: [['ops@example.org']])]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_three_mails_that_were_not_accepted(self):
        self.event(3)
        (payload,) = self.announced()
        self.assertEqual(payload['label'], 'Email')
        self.assertIn('auth failed', payload['detail'])
        self.assertNotIn('bad credentials', payload['detail'], 'what the mail server answered is not copied into the alert')
        self.assertEqual(self.health()['email']['fails'] >= 3, True)
        (alert,) = self.alerts()
        self.assertEqual(alert['payload']['label'], 'Email')
        self.assertTrue([b for b in self.net.to('up.example.org') if 'Email' in b], 'the webhook is told')

    def test_a_mail_that_is_accepted_closes_it(self):
        self.event(3)
        self.mail_fails = False
        self.event(1)
        self.assertEqual(self.alerts(), [])
        self.assertEqual(self.announced('notify_dest_recovered')[0]['label'], 'Email')

    def test_switching_mail_off_closes_it(self):
        self.event(3)
        self.config(dict(self.CONFIG, smtp_enabled=False))
        with mock.patch.object(api, 'is_email_event_enabled', lambda event, cfg=None: False):
            self.event(1)
        self.assertEqual(self.alerts(), [])


class TestTheWiring(unittest.TestCase):
    def test_the_two_events(self):
        failing, recovered = api.EVENT_REGISTRY['notify_dest_failing'], api.EVENT_REGISTRY['notify_dest_recovered']
        self.assertEqual((failing['kind'], failing['severity']), ('health', 'high'))
        self.assertEqual(recovered['resolves'], ('notify_dest_failing',))
        self.assertNotIn('severity', recovered)                      # a recovery is not an alert of its own
        self.assertIn('label', api._ALERT_IDENTITY_FIELDS)           # what tells two destinations' alerts apart

    def test_the_activity_feed_knows_them(self):
        events = re.search(r'const FLEET_EVENTS = new Set\(\[(.*?)\]\);', _APP, re.S).group(1)
        for name in ('notify_dest_failing', 'notify_dest_recovered'):
            self.assertIn(f"'{name}'", events)
        attrs = srcpin.js_function(_APP, '_homeActivityAttrs')
        case = attrs[attrs.index("case 'notify_dest_failing':"):]
        self.assertIn('data-home-act="self"', case[:case.index('return') + 80])

    def test_the_message_is_the_sentence(self):
        import notify
        for event in ('notify_dest_failing', 'notify_dest_recovered'):
            self.assertEqual(notify._webhook_message(event, {'name': 'srv', 'label': 'Chat ops', 'detail': 'the sentence'}),
                             'the sentence')

    def test_the_fan_out_and_the_retry_are_watched(self):
        src = (_CGI / 'api.py').read_text()
        self.assertIn('with _watch_delivery(_notify_dest_key(dest), _notify_dest_label(dest)):',
                      srcpin.py_function(src, '_send_webhook_to_url'))
        self.assertIn('with _watch_delivery(', srcpin.py_function(src, '_dlq_retry_entry'))
        self.assertIn('with _watch_delivery(', srcpin.py_function(src, 'run_webhook_digests_if_due'))
        reports = (_CGI / 'reports_handlers.py').read_text()
        self.assertIn('with A._watch_delivery(A._notify_dest_key(dest), A._notify_dest_label(dest)):', reports)
        notify_action = src[src.index("elif atype == 'notify':"):]
        self.assertIn('with _watch_delivery(', notify_action[:notify_action.index("elif atype == 'open_ticket':")])
        self.assertIn('_notify_health_prune(', srcpin.py_function(src, '_send_webhook_to_url'))

    def test_the_labels_are_in_six_languages(self):
        from test_v710_i18n_glue import dict_rows
        rows = dict_rows()
        for name in ('notify_dest_failing', 'notify_dest_recovered'):
            text = api.EVENT_REGISTRY[name]['label']
            self.assertTrue(rows.get(text) and all(rows[text].get(lang) for lang in ('zh', 'hi', 'es', 'ar', 'de', 'fr')),
                            text)


if __name__ == '__main__':
    unittest.main()

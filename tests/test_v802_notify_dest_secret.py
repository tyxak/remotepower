"""An alert about a failed request never carries the address or the header the request was made with (8.0.2).

The third failed delivery raises `notify_dest_failing`, and the reason it named was the failure text of the delivery with every `scheme://...` in it replaced by
`[address]`. That scrub knew one way of writing an address. The failure text of a request that http.client refuses (an address with a space or a control character in
it, which Settings accepts) names the TARGET, the path and the query, with no scheme:

    InvalidURL [slack]: URL can't contain control characters. '/services/T0/B0/xoxb-...?title=Server down' (found at least ' ')

and for a Slack, Discord or Teams webhook that path is the credential. It went to the alert detail, the inbox (every role that reads alerts), every other destination and the
mail, and it stayed in the streak kept for the destination. A header value http.client refuses (`Invalid header value b'Bearer ...'`) is quoted the same way.

The reason is built from what is safe instead (`_failure_reason`): the HTTP status when the receiver answered one, one phrase for each kind of failure, and the name of the
exception class for a failure of no known kind. Two more alerts took the text of an exception as it came and had the same hole, found by listing every literal fire site whose
payload is built from a failure text: `audit_forward_failed` (the collector's address and its bearer token, in the alert, in the stored reason and in the Compliance row) and
`integration_down` (the address of an integration, whose query string can hold its key). They use the same helper.

Driven through the real fan-out, the real retry sweep of the audit forwarder and the real poll of an integration. The refusals come out of http.client itself (`putrequest` and
`putheader` on a real connection object), not out of a made-up message:

* an address with a space in its query: the path and the query are in none of the alert, the inbox, the stored streak, the deliveries of the other destination, or the mail;
  the kind of the failure is still said, and the Settings card reads the same word from what is stored;
* a header value with a line break, a failure that echoes the SMTP password, and the failure shapes that were already right (a refused connection, a 404, a send that broke);
* the reason is always one of a closed set of shapes, whatever text it is made from: hostile texts of every shape the secret can take, and none of them survives;
* the audit forwarder and an integration with an address http.client refuses: the alert, the store and the detail carry the class of the exception and nothing else, and what the
  forwarder says itself when it declines, and what a connector says itself, is unchanged;
* a ratchet over the literal fire sites whose payload is made from a failure text: each is listed with why it cannot name an address or a credential, so a new one is a decision.
"""
import ast
import http.client
import importlib.util
import io
import os
import re
import sys
import tempfile
import time
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v802-notify-secret-'))
_spec = importlib.util.spec_from_file_location('api_v802_notify_secret', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
import srcpin  # noqa: E402

EVENT = 'server_disk_low'
TOKEN = 'xoxb-SECRET-TOKEN-1234567890'
TOKEN_PATH = f'/services/T0/B0/{TOKEN}'
QUERY = 'title=Server down'
SLACK = {'id': 'wh_s', 'name': 'Chat', 'url': f'https://hooks.example.org{TOKEN_PATH}?{QUERY}', 'format': 'slack'}
PAGER = {'id': 'wh_p', 'name': 'Pager', 'url': 'https://up.example.org/hook', 'format': 'generic'}
BEARER = 'SECRETBEARERVALUE'
HEADERED = {'id': 'wh_h', 'name': 'Gateway', 'url': 'https://gw.example.org/in', 'format': 'generic', 'headers': {'Authorization': f'Bearer {BEARER}\nX-Injected: 1'}}
SECRETS = (TOKEN, TOKEN_PATH, QUERY, BEARER, 'T0/B0', 'Server down')


class _Response:
    status = 200

    def read(self, *_a):
        return b'{}'


class Network:
    """A fake opener whose refusals are the real ones: http.client validates the request target and the header values."""

    def __init__(self):
        self.posts = []

    def opener(self, *_a, **_k):
        return self

    def open(self, req, timeout=10):
        self.posts.append((req.full_url, (req.data or b'').decode('utf-8', 'replace')))
        if req.full_url.startswith('https://up.example.org'):
            return _Response()
        conn = http.client.HTTPConnection('example.invalid')
        conn.putrequest('POST', req.selector)            # raises InvalidURL for a space or a control character
        for name, value in req.header_items():
            conn.putheader(name, value)                  # raises ValueError for a value with a line break in it
        return _Response()


class _Base(unittest.TestCase):
    CONFIG = {'webhook_urls': [SLACK, PAGER], 'webhook_block_local': False}

    def setUp(self):
        self.net = Network()
        self.fired = []
        real_fire = api.fire_webhook

        def spy(event, payload):
            self.fired.append((event, dict(payload)))
            return real_fire(event, payload)
        for p in (mock.patch.object(api, '_ssrf_safe_opener', self.net.opener), mock.patch.object(api, 'fire_webhook', spy),
                  mock.patch.object(api, '_url_targets_local_or_meta', lambda parsed, allow_loopback=True: False)):
            p.start()
            self.addCleanup(p.stop)
        api.save(api.CONFIG_FILE, dict(self.CONFIG))
        for f, empty in ((api.ALERTS_FILE, {'alerts': []}), (api.NOTIFY_HEALTH_FILE, {}), (api.WEBHOOK_LOG_FILE, {'entries': []}),
                         (api.WEBHOOK_DLQ_FILE, {'entries': []}), (api.WEBHOOK_RATELIMIT_FILE, {}), (api.MAINT_FILE, {'windows': []})):
            api.save(f, empty)
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for f, empty in ((api.CONFIG_FILE, {}), (api.ALERTS_FILE, {'alerts': []}), (api.NOTIFY_HEALTH_FILE, {})):
            api.save(f, empty)
        api._LOAD_CACHE.clear()

    def events(self, n):
        for _ in range(n):
            api._LOAD_CACHE.clear()
            api.fire_webhook(EVENT, {'name': 'server', 'percent': 97})
        api._LOAD_CACHE.clear()

    def everything_said(self):
        """Everything the failure was said in, outside the delivery log that only an administrator reads: the alert ledger, the streak store, the events fired (which every
        other destination is sent), and what the other destination received."""
        api._LOAD_CACHE.clear()
        said = [api.load(api.ALERTS_FILE), api.load(api.NOTIFY_HEALTH_FILE), self.fired,
                [body for url, body in self.net.posts if url.startswith('https://up.example.org')]]
        return repr(said)

    def announced(self):
        return [p for e, p in self.fired if e == 'notify_dest_failing']


class TestAnAddressHttpClientRefuses(_Base):
    def test_the_real_library_names_the_target_in_its_refusal(self):
        """The control for the setup: this is the text the product has to deal with, and it does carry the credential."""
        try:
            http.client.HTTPConnection('example.invalid').putrequest('POST', f'{TOKEN_PATH}?{QUERY}')
        except http.client.InvalidURL as exc:
            self.assertIn(TOKEN, str(exc))
        else:
            self.fail('http.client accepted a target with a space in it')

    def test_the_path_and_the_query_are_in_none_of_what_is_said(self):
        self.events(4)
        said = self.everything_said()
        self.assertIn('InvalidURL', said, 'the control: the failure was recorded, and the instrument can see what was said')
        for secret in SECRETS:
            self.assertNotIn(secret, said, secret)

    def test_the_kind_of_the_failure_is_still_said(self):
        self.events(3)
        (payload,) = self.announced()
        self.assertEqual(payload['detail'], 'Notification destination "Chat" has failed 3 deliveries in a row: delivery error (InvalidURL)')
        self.assertEqual(payload['label'], 'Chat')

    def test_the_stored_streak_holds_the_reason_and_the_card_reads_the_same_word(self):
        self.events(3)
        api._LOAD_CACHE.clear()
        row = (api.load(api.NOTIFY_HEALTH_FILE) or {})['wh:wh_s']
        self.assertEqual(row['error'], 'delivery error (InvalidURL)')
        fails, kind = api._notify_failing_destinations()['wh:wh_s']
        self.assertGreaterEqual(fails, 3)
        self.assertEqual(kind, api._notify_error_class('InvalidURL [slack]: URL can\'t contain control characters'), 'the word is the one of the text it was made from')

    def test_the_delivery_log_is_where_the_full_text_stays(self):
        """Only the alert and the store are told the reason. The delivery log is read by administrators, as it always was, and keeps the text."""
        self.events(1)
        api._LOAD_CACHE.clear()
        detail = ' '.join(e.get('detail', '') for e in (api.load(api.WEBHOOK_LOG_FILE) or {}).get('entries', []))
        self.assertIn('InvalidURL', detail)
        self.assertIn('control characters', detail)


class TestAHeaderValueHttpClientRefuses(_Base):
    CONFIG = {'webhook_urls': [HEADERED, PAGER], 'webhook_block_local': False}

    def test_the_value_is_in_none_of_what_is_said(self):
        self.events(4)
        said = self.everything_said()
        self.assertNotIn(BEARER, said)
        self.assertNotIn('X-Injected', said)
        (payload,) = self.announced()
        self.assertTrue(payload['detail'].endswith('in a row: delivery error (ValueError)'), payload['detail'])


class TestTheMailChannel(_Base):
    CONFIG = {'webhook_urls': [PAGER], 'webhook_block_local': False, 'smtp_enabled': True, 'smtp_recipients': 'ops@example.org', 'smtp_password': 'SMTPPASSWORD-1234'}

    def failing_mail(self, exc):
        def send_email(cfg, recipients, subject, body, **_kw):
            raise exc
        for p in (mock.patch.object(api.smtp_notifier, 'send_email', send_email), mock.patch.object(api, 'is_email_event_enabled', lambda event, cfg=None: True),
                  mock.patch.object(api, '_event_email_routes', lambda cfg, payload: [['ops@example.org']])):
            p.start()
            self.addCleanup(p.stop)

    def test_a_failure_that_echoes_the_password_is_not_repeated(self):
        self.failing_mail(RuntimeError('login with SMTPPASSWORD-1234 failed'))
        self.events(3)
        self.assertNotIn('SMTPPASSWORD', self.everything_said())
        (payload,) = self.announced()
        self.assertTrue(payload['detail'].endswith('in a row: delivery error (RuntimeError)'), payload['detail'])

    def test_a_refused_login_is_told_as_one(self):
        self.failing_mail(api.smtp_notifier.SmtpError('auth failed: 535 5.7.8 Username and Password not accepted'))
        self.events(3)
        (payload,) = self.announced()
        self.assertTrue(payload['detail'].endswith('in a row: auth failed'), payload['detail'])
        self.assertEqual(api._notify_failing_destinations()['email'][1], 'auth', 'the same word the card gives a webhook that answered 401')


class TestTheShapesThatWereAlreadyRight(_Base):
    CONFIG = {'webhook_urls': [dict(SLACK, url='https://down.example.org/services/T0PS3CRETPATH', format='generic'), PAGER], 'webhook_block_local': False}

    def check(self, how, expect):
        def open_(req, timeout=10):
            if how == 'refuse':
                raise urllib.error.URLError(f'connection refused while reaching {req.full_url}')
            if how == 'http404':
                raise urllib.error.HTTPError(req.full_url, 404, 'Not Found', {}, None)
            if how == 'pipe':
                raise OSError(f'broken pipe to {req.full_url}')
            raise RuntimeError(f'something broke while sending to {req.full_url}')
        real_open = self.net.open
        self.net.open = lambda req, timeout=10: real_open(req) if req.full_url.startswith('https://up.example.org') else open_(req)
        self.events(3)
        (payload,) = self.announced()
        self.assertTrue(payload['detail'].endswith('in a row: ' + expect), payload['detail'])
        self.assertNotIn('T0PS3CRETPATH', self.everything_said())

    def test_a_refused_connection_is_still_said(self):
        self.check('refuse', 'connection refused or unreachable')

    def test_an_answer_of_404_is_still_said(self):
        self.check('http404', 'HTTP 404')

    def test_a_send_that_broke_is_still_said_by_its_class(self):
        self.check('boom', 'delivery error (RuntimeError)')

    def test_a_broken_pipe_is_a_connection_that_went(self):
        self.check('pipe', 'connection refused or unreachable')


# ── the reason is built from a closed set, whatever the text is ─────────────────────────────

CLASS_NAME = r'[A-Za-z_][A-Za-z0-9_]{0,60}'


def shape():
    """The shapes a reason can have: a status, a phrase of the list, or `delivery error` / `the request failed` with the name of a class."""
    phrases = '|'.join(re.escape(p) for p in sorted(set(api._FAILURE_PHRASES.values())))
    return re.compile(r'^(HTTP \d{3}|%s|(delivery error|the request failed)( \(%s\))?)$' % (phrases, CLASS_NAME))


def hostile_texts():
    """Texts of every shape a secret can take: raw, quoted the way repr prints it, percent-encoded, with a scheme and without, in the middle of the words of a known kind, in a
    class name's place, very long, and not text at all."""
    forms = [TOKEN, TOKEN_PATH, f'{TOKEN_PATH}?{QUERY}', repr(f'{TOKEN_PATH}?{QUERY}'), repr(f'{TOKEN_PATH}?{QUERY}')[1:-1], 'https://hooks.example.org' + TOKEN_PATH,
             TOKEN_PATH.replace('/', '%2F'), f'b{BEARER!r}', f'Bearer {BEARER}\\n X-Injected: 1', 'alice:HUNTER2PASS@up.example.org']
    out = []
    for f in forms:
        out += [f, f'InvalidURL [slack]: URL can\'t contain control characters. {f!r} (found at least \' \')', f'RuntimeError [generic]: {f}', f'HTTP 502 [generic]: {f}',
                f'URLError [generic]: connection refused while reaching {f}', f'ValueError: Invalid header value {f!r}', f'timed out talking to {f}', f'SSL: certificate verify failed for {f}',
                f'auth failed: 535 {f}', f'blocked: target resolves to {f}', f'missing {f} in settings', f'{f}: {f}', f'{f} [{f}]: {f}', f'x{f} [slack]: {f}']
    out += ['x' * 100000, '\u0000\ud800', 'HTTP ' + TOKEN, 'HTTP 4' + TOKEN, '', None, 0, [1, 2], {'a': TOKEN}, b'bytes', 'A' * 61 + ' [generic]: ' + TOKEN, 'Ünïcode [generic]: ' + TOKEN]
    return out


class TestTheReasonIsMadeFromAClosedSet(unittest.TestCase):
    def test_every_hostile_text_comes_out_as_a_known_shape_without_the_secret(self):
        texts, known = hostile_texts(), shape()
        self.assertGreater(len(texts), 120, 'the derivation measured nothing')
        for other in ('delivery error', 'the request failed'):
            for text in texts:
                reason = api._failure_reason(text, other=other)
                self.assertTrue(reason == '' or known.match(reason), repr(reason)[:120])
                for secret in SECRETS + ('HUNTER2PASS', 'X-Injected'):
                    self.assertNotIn(secret, reason, repr(text)[:80])

    def test_the_one_word_a_reason_can_carry_is_the_name_of_an_exception_class(self):
        """A failure text starts with the class of its exception. The reason carries that word and only when it is a class that exists in the process: the first word of any other text
        can be anything, a credential among it."""
        for word in ('RuntimeError', 'InvalidURL', 'ValueError', 'URLError', 'RemoteDisconnected', 'JSONDecodeError'):
            self.assertEqual(api._failure_reason(f'{word} [generic]: x'), f'delivery error ({word})', word)
            self.assertEqual(api._failure_reason(f'{word}: x', other='the request failed'), f'the request failed ({word})', word)
        for word in ('xoxb', 'SECRETIDENT', 'A' * 60, 'abc123', 'Ünïcode', 'A' * 61, 'notanerror'):
            for text in (f'{word} [generic]: x', f'{word}: x'):
                self.assertEqual(api._failure_reason(text), 'delivery error', text)

        class RpTestOnlyError(Exception):
            pass
        self.assertEqual(api._failure_reason('RpTestOnlyError [generic]: x'), 'delivery error (RpTestOnlyError)', 'a class defined in the process is one')

    def test_each_phrase_is_read_back_as_the_kind_it_stands_for(self):
        for kind, phrase in api._FAILURE_PHRASES.items():
            self.assertEqual(api._notify_error_class(phrase), kind, phrase)
            self.assertEqual(api._failure_reason(phrase), phrase, 'a reason made from its own phrase is the same phrase')
        for code, kind in ((401, 'auth'), (403, 'auth'), (404, 'http_4xx'), (429, 'http_4xx'), (500, 'http_5xx'), (503, 'http_5xx'), (302, 'other'), (999, 'other')):
            self.assertEqual(api._notify_error_class(api._failure_reason(f'HTTP {code} [generic]: x')), kind, code)
        for tail in ('delivery error', 'delivery error (RuntimeError)', 'the request failed (InvalidURL)'):
            self.assertEqual(api._notify_error_class(tail), 'other', tail)

    def test_every_kind_the_classifier_has_is_a_phrase_or_a_status(self):
        sent = set(re.findall(r"return '(\w+)'", srcpin.py_function((_CGI / 'api.py').read_text(encoding='utf-8'), '_notify_error_class')))
        self.assertEqual(sorted(sent - set(api._FAILURE_PHRASES) - {'other', 'http_4xx', 'http_5xx'}), [], 'a kind of failure that has no phrase')

    def test_what_a_text_of_a_known_kind_says(self):
        for text, want in (('HTTP 404 [slack]: Not Found', 'HTTP 404'), ('HTTP 302 [generic]: Found', 'HTTP 302'), ('URLError [generic]: [Errno 111] Connection refused', 'connection refused or unreachable'),
                           ('TimeoutError [generic]: timed out', 'timed out'), ('URLError [ntfy]: [Errno -3] Temporary failure in name resolution', 'name or service not known'),
                           ('URLError [discord]: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed', 'TLS or certificate error'),
                           ('blocked: target resolves to a metadata or local address', 'blocked: target resolves to a metadata or local address'),
                           ('invalid scheme (must be http or https)', 'invalid scheme or missing settings'),
                           ('Pushover destination missing token/user — set them in Settings → Notifications', 'invalid scheme or missing settings'),
                           ('RuntimeError [generic]: something nobody planned for', 'delivery error (RuntimeError)'), ('something nobody planned for', 'delivery error'), ('', '')):
            self.assertEqual(api._failure_reason(text), want, text)


# ── the two other alerts that took an exception's text as it came ───────────────────────────

class TestTheAuditForwarder(unittest.TestCase):
    URL = f'http://collector.example.org/hec/{TOKEN}?index=a b'

    def setUp(self):
        self.fired = []
        for p in (mock.patch.object(api, 'fire_webhook', lambda event, payload: self.fired.append((event, dict(payload)))),
                  mock.patch.object(api, '_url_targets_local_or_meta', lambda parsed, allow_loopback=True: False)):
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(self.clean)

    @staticmethod
    def clean():
        for f, empty in ((api.CONFIG_FILE, {}), (api.AUDIT_FORWARD_SPOOL_FILE, {})):
            api.save(f, empty)
        api._LOAD_CACHE.clear()

    def sweep(self, **cfg):
        now = int(time.time())
        api.save(api.CONFIG_FILE, dict({'audit_forward_enabled': True, 'audit_forward_mode': 'http', 'audit_forward_url': self.URL, 'audit_forward_token': BEARER,
                                        'webhook_block_local': False}, **cfg))
        api.save(api.AUDIT_FORWARD_SPOOL_FILE, {'entries': [{'ts': now - 3000, 'actor': 'a', 'action': 'login'}], 'failing_since': now - 3000, 'last_retry': 0, 'dropped': 0})
        api._LOAD_CACHE.clear()
        api.run_audit_forward_retry_if_due()
        api._LOAD_CACHE.clear()
        alert = [p for e, p in self.fired if e == 'audit_forward_failed']
        return alert, (api.load(api.AUDIT_FORWARD_SPOOL_FILE) or {}).get('last_error')

    def test_an_address_http_client_refuses_is_told_as_its_class(self):
        alert, stored = self.sweep()
        self.assertEqual(len(alert), 1, 'the control: the failure was long enough to raise the alert')
        self.assertEqual((alert[0]['error'], stored), ('the request failed (InvalidURL)', 'the request failed (InvalidURL)'))
        for secret in SECRETS[:3] + ('index=a b',):
            self.assertNotIn(secret, repr((alert, stored)))

    def test_a_bearer_token_with_a_line_break_is_told_as_its_class(self):
        alert, stored = self.sweep(audit_forward_url='http://collector.example.org/hec', audit_forward_token=f'{BEARER}\nX-Injected: 1')
        self.assertEqual((alert[0]['error'], stored), ('the request failed (ValueError)', 'the request failed (ValueError)'))
        self.assertNotIn(BEARER, repr((alert, stored)))

    def test_what_the_forwarder_says_when_it_declines_is_its_own_text(self):
        alert, stored = self.sweep(audit_forward_url='')
        self.assertEqual((alert[0]['error'], stored), ('no audit_forward_url configured', 'no audit_forward_url configured'))

    def test_a_failure_the_inline_path_spools_is_told_the_same_way(self):
        """`audit_log` forwards inline, and spools the entry with the exception when it fails."""
        api.save(api.CONFIG_FILE, {'audit_forward_enabled': True, 'audit_forward_mode': 'http', 'audit_forward_url': self.URL, 'webhook_block_local': False})
        api.save(api.AUDIT_FORWARD_SPOOL_FILE, {})
        api._LOAD_CACHE.clear()
        err = io.StringIO()
        with mock.patch.object(sys, 'stderr', err):
            api.audit_log('tester', 'login', 'one entry, forwarded inline')
        api._LOAD_CACHE.clear()
        spool = api.load(api.AUDIT_FORWARD_SPOOL_FILE) or {}
        self.assertEqual(len(spool.get('entries') or []), 1, 'the control: the inline forward failed and the entry was spooled')
        self.assertEqual(spool.get('last_error'), 'the request failed (InvalidURL)')
        self.assertIn('audit forward failed: the request failed (InvalidURL)', err.getvalue())
        self.assertNotIn(TOKEN, err.getvalue(), 'nor is it written to the server log')


class TestAnIntegration(unittest.TestCase):
    def poll(self, url):
        return api._poll_one_integration({'id': 'int1', 'type': 'pihole', 'label': 'Pi-hole', 'url': url, 'enabled': True, 'secret': 'x'})

    def test_an_address_http_client_refuses_is_told_as_its_class(self):
        res = self.poll(f'http://93.184.216.34/admin?api_key={TOKEN}&name=my pi')
        self.assertEqual(res['detail'], 'the request failed (InvalidURL)')
        self.assertEqual(res['status'], api.integrations_mod.CRIT)
        self.assertNotIn('SECRET', repr(res))

    def test_what_a_connector_says_itself_is_unchanged(self):
        res = self.poll('http://127.0.0.1:9/admin')
        self.assertEqual(res['detail'], 'target is a blocked address')


# ── a ratchet over the fire sites whose payload is made from a failure text ─────────────────

# Each literal fire site whose payload value is built from a name that carries a failure or a reason (err, error, why, reason, detail, ...), with why it cannot name an address
# or a credential. A site that is not here is new: decide, and put it here or give it `_failure_reason`.
FAILURE_TEXT_SITES = {
    ('vault_break_glass', 'reason'): 'the words the operator typed into the break-glass dialog',
    ('control_plane_security_change', 'detail'): 'a sentence of _CONTROL_PLANE_CHANGES',
    ('notify_dest_failing', 'detail'): 'built from _failure_reason',
    ('audit_forward_failed', 'error'): 'an exception goes through _audit_forward_reason; what the forwarder says when it declines is its own text',
    ('integration_down', 'detail'): 'a connector\'s own status text; the exception of a request goes through _failure_reason in _SSRFIntegrationClient',
    ('integration_recovered', 'detail'): 'same',
    ('remediation_failed', 'detail'): 'what a command the operator wrote printed on a host; no address of the installation is part of the request',
    ('edge_feed_down', 'detail'): 'a fixed phrase and the message of the Cloudflare API; an exception is told as its class name only (_safely)',
    ('security_news_feed_failing', 'detail'): 'the feed by its title or host and the last answer of the read (_why, cut to 160 characters), with any address in it replaced by "an address" (_feed_event); the address of a feed holds no credential, a user name or a token parameter being refused when it is saved',
    ('security_news_feed_recovered', 'detail'): 'a fixed sentence with the title or host of the feed, and no failure text',
    ('ip_reported', 'detail'): 'a count and the addresses that were reported',
}
CARRIERS = {'err', 'error', 'why', 'reason', 'exc', 'e', 'detail', 'msg', 'text', 'errtxt', 'last_error', '_e', 'ex', 'emsg'}
FIRE = {'fire_webhook', '_fire', '_fire_service_webhook', '_fire_container_webhook', '_record_alert'}


def failure_text_sites():
    found = set()
    sites = 0
    for path in sorted(_CGI.glob('*.py')):
        tree = ast.parse(path.read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            cand = None
            if isinstance(node, ast.Call):
                fn = node.func.id if isinstance(node.func, ast.Name) else node.func.attr if isinstance(node.func, ast.Attribute) else ''
                if fn in FIRE and len(node.args) >= 2 and isinstance(node.args[1], ast.Dict) and isinstance(node.args[0], ast.Constant):
                    cand = (node.args[0].value, node.args[1])
            elif isinstance(node, ast.Tuple) and len(node.elts) == 2 and isinstance(node.elts[0], ast.Constant) and isinstance(node.elts[0].value, str) \
                    and isinstance(node.elts[1], ast.Dict) and node.elts[0].value.isidentifier():
                cand = (node.elts[0].value, node.elts[1])
            if not cand:
                continue
            sites += 1
            event, payload = cand
            for k, v in zip(payload.keys, payload.values):
                if isinstance(k, ast.Constant) and any(isinstance(n, ast.Name) and n.id in CARRIERS for n in ast.walk(v)):
                    found.add((event, k.value))
    return found, sites


class TestEveryFireSiteThatCarriesAFailureText(unittest.TestCase):
    def test_the_derivation_reads_the_sites(self):
        found, sites = failure_text_sites()
        self.assertGreater(sites, 150, 'the derivation read too few fire sites')
        self.assertGreaterEqual(len(found), 5, found)

    def test_each_is_listed_with_its_reason_and_the_list_has_no_stale_entry(self):
        found, _ = failure_text_sites()
        self.assertEqual(sorted(found - set(FAILURE_TEXT_SITES)), [], 'an alert payload made from a failure text: say why it cannot name an address or a credential')
        self.assertEqual(sorted(set(FAILURE_TEXT_SITES) - found), [], 'a listed site that is no longer one')

    def test_the_three_that_take_an_exception_pass_it_through_the_helper(self):
        src = (_CGI / 'api.py').read_text(encoding='utf-8')
        tree = ast.parse(src)
        for name in ('_note_delivery', '_audit_forward_reason', '_SSRFIntegrationClient'):
            node = next(n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name == name)
            calls = {c.func.id for c in ast.walk(node) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}
            self.assertIn('_failure_reason', calls, name)


if __name__ == '__main__':
    unittest.main()

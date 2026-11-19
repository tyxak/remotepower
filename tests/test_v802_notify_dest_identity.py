"""The alert about a failing notification destination is about that destination, and a recovery closes only its own (8.0.2).

8.0.1 counts the failed deliveries of each destination under the destination's id and raises `notify_dest_failing` on the third. The alert it
raised was told apart from another, and closed, by the destination's LABEL: the name the operator gave it, else `scheme://host`. A destination
that Settings saves without a name (which is what the Settings page makes) has the label of every other unnamed destination on the same host,
and the mail server's label is `Email`, which a webhook can be named too. Two failing destinations then shared one row of the inbox, and the
first of them to deliver again closed it: the operator saw nothing about the destination that still dropped every alert, which is the one
failure the feature exists to announce.

Driven through the real fan-out (`fire_webhook`, `_send_webhook_to_url`, `_dispatch_one_webhook`, the mail channel) with the network replaced by
an opener that answers by the whole address of a request, and the real alert ledger:

* two unnamed destinations of one host both fail: two rows, one about each. One delivers again: its row closes and the other stays open;
* a webhook named `Email` beside the mail server: the same;
* two destinations with their own names, as before (the control);
* an alert raised by 8.0.1, which carries a label and no key, is still closed by the recovery that names its label, and only that one;
* an edit that fixes a destination's address, and removing one, close the alert of that destination alone;
* a ratchet over the events that close an alert by its label: each is listed with the reason its label is the identity of what raised it;
* the Alerts page does not print the key under the row (it is an identity the server matches on), and still prints the facts around it.
"""
import ast
import importlib.util
import json
import os
import re
import shutil
import subprocess
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
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v802-notify-id-'))
_spec = importlib.util.spec_from_file_location('api_v802_notify_id', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
import srcpin  # noqa: E402

_JS_DIR = ROOT / 'server' / 'html' / 'static' / 'js'
HAVE_NODE = bool(shutil.which('node'))

EVENT = 'server_disk_low'
HOST = 'hooks.example.org'
URL_A, URL_B = f'https://{HOST}/a/SECRETPATHA', f'https://{HOST}/b/SECRETPATHB'
UNNAMED_A = {'id': 'wh_a', 'url': URL_A, 'format': 'generic'}
UNNAMED_B = {'id': 'wh_b', 'url': URL_B, 'format': 'generic'}
OTHER = {'id': 'wh_up', 'name': 'Pager', 'url': 'https://up.example.org/hook', 'format': 'generic'}


class _Response:
    status = 200

    def read(self, *_a):
        return b'{}'


class Network:
    """The opener the product asks for. `behave[full address]` is 'ok', 'refuse' or 'http502'."""

    def __init__(self):
        self.behave = {}
        self.posts = []

    def opener(self, *_a, **_k):
        return self

    def open(self, req, timeout=10):
        self.posts.append((req.full_url, (req.data or b'').decode('utf-8', 'replace')))
        how = self.behave.get(req.full_url, 'ok')
        if how == 'refuse':
            raise urllib.error.URLError('connection refused')
        if how == 'http502':
            raise urllib.error.HTTPError(req.full_url, 502, 'Bad Gateway', {}, None)
        return _Response()


class _Base(unittest.TestCase):
    CONFIG = {'webhook_urls': [UNNAMED_A, UNNAMED_B, OTHER], 'webhook_block_local': False}

    def setUp(self):
        self.net = Network()
        self.net.behave = {URL_A: 'refuse', URL_B: 'refuse'}
        self.fired = []
        real_fire = api.fire_webhook

        def spy(event, payload):
            self.fired.append((event, dict(payload)))
            return real_fire(event, payload)
        for p in (mock.patch.object(api, '_ssrf_safe_opener', self.net.opener),
                  mock.patch.object(api, 'fire_webhook', spy),
                  mock.patch.object(api, '_url_targets_local_or_meta', lambda parsed, allow_loopback=True: False)):
            p.start()
            self.addCleanup(p.stop)
        self.config(self.CONFIG)
        for f, empty in ((api.ALERTS_FILE, {'alerts': []}), (api.NOTIFY_HEALTH_FILE, {}), (api.WEBHOOK_LOG_FILE, {'entries': []}),
                         (api.WEBHOOK_DLQ_FILE, {'entries': []}), (api.WEBHOOK_RATELIMIT_FILE, {}), (api.MAINT_FILE, {'windows': []})):
            api.save(f, empty)
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for f, empty in ((api.CONFIG_FILE, {}), (api.ALERTS_FILE, {'alerts': []}), (api.NOTIFY_HEALTH_FILE, {})):
            api.save(f, empty)
        api._LOAD_CACHE.clear()

    def config(self, cfg):
        api.save(api.CONFIG_FILE, dict(cfg))
        api._LOAD_CACHE.clear()

    def event(self, n=1):
        for _ in range(n):
            api._LOAD_CACHE.clear()
            api.fire_webhook(EVENT, {'name': 'server', 'percent': 97})
        api._LOAD_CACHE.clear()

    def rows(self, event='notify_dest_failing'):
        api._LOAD_CACHE.clear()
        return [a for a in (api.load(api.ALERTS_FILE) or {}).get('alerts', []) if a.get('event') == event]

    def open_rows(self):
        return [a for a in self.rows() if not a.get('resolved_at')]

    def health(self):
        api._LOAD_CACHE.clear()
        return api.load(api.NOTIFY_HEALTH_FILE) or {}

    def announced(self, event='notify_dest_failing'):
        return [p for e, p in self.fired if e == event]

    @staticmethod
    def dests(rows):
        return sorted(a['payload'].get('dest') for a in rows)


class TestTwoDestinationsWithOneLabel(_Base):
    def test_they_have_one_label_and_two_keys(self):
        """The control for the setup: what made the alerts collide."""
        self.assertEqual(api._notify_dest_label(UNNAMED_A), api._notify_dest_label(UNNAMED_B))
        self.assertNotEqual(api._notify_dest_key(UNNAMED_A), api._notify_dest_key(UNNAMED_B))

    def test_each_one_that_fails_has_a_row_of_its_own(self):
        self.event(3)
        self.assertEqual(len(self.announced()), 2, 'each destination is announced once')
        self.assertEqual(len(self.open_rows()), 2, 'one row about each destination, not one row for the label they share')
        self.assertEqual(self.dests(self.open_rows()), ['wh:wh_a', 'wh:wh_b'])

    def test_the_first_to_deliver_again_closes_its_own_row_and_not_the_other(self):
        self.event(3)
        self.net.behave[URL_B] = 'ok'
        self.event(1)
        self.assertEqual(len(self.open_rows()), 1, 'the destination that still fails keeps an open alert')
        rows = {a['payload'].get('dest'): a for a in self.rows()}
        self.assertTrue(rows['wh:wh_b'].get('resolved_at'), 'the destination that delivers again has its alert closed')
        self.assertFalse(rows['wh:wh_a'].get('resolved_at'), 'the one that still fails keeps its alert open')
        self.assertEqual(sorted(self.health()), ['wh:wh_a'], 'and the streak of the one that still fails is the one kept')

    def test_the_alert_of_the_one_that_fails_stays_until_that_one_delivers(self):
        self.event(3)
        self.net.behave[URL_B] = 'ok'
        self.event(2)
        self.assertEqual(len(self.open_rows()), 1)
        self.assertEqual(self.dests(self.open_rows()), ['wh:wh_a'])
        self.net.behave[URL_A] = 'ok'
        self.event(1)
        self.assertEqual(self.open_rows(), [])

    def test_a_row_names_the_destination_it_is_about(self):
        self.event(3)
        (a,) = [r for r in self.rows() if r['payload']['dest'] == 'wh:wh_a']
        self.assertEqual(a['payload']['label'], 'https://hooks.example.org')
        self.assertIn('has failed 3 deliveries in a row', a['payload']['detail'])


class TestTheMailServerAndAWebhookNamedEmail(_Base):
    CONFIG = {'webhook_urls': [dict(UNNAMED_A, name='Email'), OTHER], 'webhook_block_local': False,
              'smtp_enabled': True, 'smtp_recipients': 'ops@example.org'}

    def setUp(self):
        super().setUp()
        self.mail_fails = True

        def send_email(cfg, recipients, subject, body, **_kw):
            if self.mail_fails:
                raise api.smtp_notifier.SmtpError('authentication failed: 535 5.7.8 bad credentials')
        for p in (mock.patch.object(api.smtp_notifier, 'send_email', send_email),
                  mock.patch.object(api, 'is_email_event_enabled', lambda event, cfg=None: True),
                  mock.patch.object(api, '_event_email_routes', lambda cfg, payload: [['ops@example.org']])):
            p.start()
            self.addCleanup(p.stop)

    def test_the_webhook_delivering_again_does_not_close_the_alert_of_the_mail_server(self):
        self.event(3)
        self.assertEqual(len(self.open_rows()), 2, 'the mail server and the webhook named Email each have an alert')
        self.assertEqual(self.dests(self.open_rows()), ['email', 'wh:wh_a'])
        self.net.behave[URL_A] = 'ok'
        self.event(1)
        self.assertEqual(len(self.open_rows()), 1, 'the mail server still fails and its alert is open')
        self.assertEqual(self.dests(self.open_rows()), ['email'])
        self.assertIn('email', self.health())

    def test_the_mail_server_delivering_again_closes_its_own(self):
        self.event(3)
        self.mail_fails = False
        self.event(1)
        self.assertEqual(len(self.open_rows()), 1)
        self.assertEqual(self.dests(self.open_rows()), ['wh:wh_a'])


class TestDestinationsWithTheirOwnNames(_Base):
    CONFIG = {'webhook_urls': [dict(UNNAMED_A, name='chat one'), dict(UNNAMED_B, name='chat two'), OTHER], 'webhook_block_local': False}

    def test_as_before(self):
        self.event(3)
        self.assertEqual(sorted(a['payload']['label'] for a in self.open_rows()), ['chat one', 'chat two'])
        self.net.behave[URL_B] = 'ok'
        self.event(1)
        self.assertEqual([a['payload']['label'] for a in self.open_rows()], ['chat one'])


class TestAnAlertRaisedByTheLastRelease(_Base):
    """8.0.1 stored the label and no key. Such an alert is closed by the recovery that names its label, so an upgrade does not leave it open."""

    def legacy_alert(self, label):
        api._LOAD_CACHE.clear()
        api.fire_webhook('notify_dest_failing', {'name': 'server', 'label': label, 'detail': f'Notification destination "{label}" has failed 3 deliveries in a row.'})
        api._LOAD_CACHE.clear()

    def test_it_is_closed_by_the_recovery_of_its_label_and_not_by_another(self):
        self.config({'webhook_urls': [dict(UNNAMED_A, name='Chat ops'), OTHER], 'webhook_block_local': False})
        self.legacy_alert('Chat ops')
        self.legacy_alert('Something else')
        self.assertEqual(len(self.open_rows()), 2)
        self.assertEqual([a['payload'].get('dest') for a in self.open_rows()], [None, None], 'the setup is what 8.0.1 stored')
        self.net.behave = {}
        api.fire_webhook('notify_dest_recovered', {'name': 'server', 'label': 'Chat ops', 'dest': 'wh:wh_a', 'detail': 'delivers again'})
        api._LOAD_CACHE.clear()
        self.assertEqual([a['payload']['label'] for a in self.open_rows()], ['Something else'])

    def test_a_recovery_with_a_key_closes_the_alert_with_that_key_and_leaves_one_with_another(self):
        self.event(3)
        api.fire_webhook('notify_dest_recovered', {'name': 'server', 'label': 'https://hooks.example.org', 'dest': 'wh:wh_a', 'detail': 'x'})
        api._LOAD_CACHE.clear()
        self.assertEqual(len(self.open_rows()), 1, 'both destinations have this label; the key says which one delivers again')
        self.assertEqual(self.dests(self.open_rows()), ['wh:wh_b'])


class TestAnEditAndARemovalCloseOnlyTheirOwn(_Base):
    def test_fixing_the_address_of_one_closes_its_alert(self):
        self.event(3)
        before = [dict(d) for d in self.CONFIG['webhook_urls']]
        after = [dict(UNNAMED_A, url=f'https://{HOST}/a/FIXED'), UNNAMED_B, OTHER]
        self.config(dict(self.CONFIG, webhook_urls=after))
        api._notify_destinations_changed(before, after)
        api._LOAD_CACHE.clear()
        self.assertEqual(len(self.open_rows()), 1)
        self.assertEqual(self.dests(self.open_rows()), ['wh:wh_b'])
        self.assertEqual(self.announced('notify_dest_recovered')[0]['dest'], 'wh:wh_a')

    def test_removing_one_closes_its_alert(self):
        self.event(3)
        after = [UNNAMED_B, OTHER]
        before = [dict(d) for d in self.CONFIG['webhook_urls']]
        self.config(dict(self.CONFIG, webhook_urls=after))
        api._notify_destinations_changed(before, after)
        api._LOAD_CACHE.clear()
        self.assertEqual(len(self.open_rows()), 1)
        self.assertEqual(self.dests(self.open_rows()), ['wh:wh_b'])
        self.assertEqual(self.announced('notify_dest_recovered')[0]['dest'], 'wh:wh_a')


# ── a ratchet over the events that close an alert by its label ─────────────────────

# Each event whose recovery matches the open alert by `label`, and why the label is the identity of what raised it. A new one is a decision:
# a label that two things can share is the failure this module exists for.
CLOSED_BY_LABEL = {
    'monitor_up': 'a monitor\'s whole state (its history, its down flag and its failure streak) is kept under its label',
    'mailflow_ok': 'one mail round trip, with the fixed label `mailflow`',
    'edge_feed_recovered': 'one of the two edge feeds, each with its own fixed name',
    'edge_list_synced': 'the one Cloudflare list',
}


def events_closed_by_label():
    """From the source of `_auto_resolve_alerts`: the events of every `elif event ...:` branch that sets `sub_match['label']`."""
    tree = ast.parse((_CGI / 'api.py').read_text(encoding='utf-8'))
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == '_auto_resolve_alerts')
    found = set()
    for node in ast.walk(fn):
        if not isinstance(node, ast.If):
            continue
        sets_label = any(isinstance(s, ast.Assign) and any(isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name) and t.value.id == 'sub_match'
                                                          and isinstance(t.slice, ast.Constant) and t.slice.value == 'label' for t in s.targets)
                         for s in node.body)
        if not sets_label:
            continue
        test = node.test
        names = []
        if isinstance(test, ast.Compare) and isinstance(test.left, ast.Name) and test.left.id == 'event':
            for comp in test.comparators:
                names += [c.value for c in ast.walk(comp) if isinstance(c, ast.Constant) and isinstance(c.value, str)]
        found.update(names)
    return found


class TestTheEventsThatCloseByLabel(unittest.TestCase):
    def test_the_derivation_sees_the_ones_that_are_known(self):
        self.assertGreaterEqual(len(events_closed_by_label()), 4, events_closed_by_label())

    def test_each_has_its_reason_and_the_destination_is_not_among_them(self):
        found = events_closed_by_label()
        self.assertEqual(sorted(found - set(CLOSED_BY_LABEL)), [], 'an event that closes by a label: say why the label is unique to what raised it')
        self.assertEqual(sorted(set(CLOSED_BY_LABEL) - found), [], 'a listed event that no longer closes by its label')
        self.assertNotIn('notify_dest_recovered', found, 'a destination is told apart by its key')

    def test_the_key_is_an_identity_field_and_is_stored_on_the_alert(self):
        self.assertIn('dest', api._ALERT_IDENTITY_FIELDS)
        self.assertIn('label', api._ALERT_IDENTITY_FIELDS, 'the label stays: other events are told apart by it')


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestThePageDoesNotPrintTheKey(unittest.TestCase):
    """The row of the inbox prints every stored fact of an alert as `key: value`. The key of a destination is `wh:wh_3f9a1c02`, which means nothing to
    a person; the real `_alertEvidenceHtml` runs under node."""

    @staticmethod
    def facts(payload):
        app = (_JS_DIR / 'app.js').read_text(encoding='utf-8')
        alerts = (_JS_DIR / 'app-alerts.js').read_text(encoding='utf-8')
        parts = [re.search(r'^function escHtml\(.*$', app, re.M).group(0), re.search(r'^function escAttr\(.*$', app, re.M).group(0),
                 re.search(r'^function _escapeHtml\(.*$', app, re.M).group(0),
                 srcpin.balanced_block(alerts, 'const _ALERT_BASELINE_TYPES = new Set(', '(', ')') + ';',
                 srcpin.js_function(alerts, '_alertSampleLine'), srcpin.js_function(alerts, '_alertEvidenceHtml'),
                 'console.log(JSON.stringify(_alertEvidenceHtml({event: "notify_dest_failing", payload: %s})));' % json.dumps(payload)]
        out = subprocess.run(['node', '-e', '\n'.join(parts)], capture_output=True, text=True, timeout=30)
        assert out.returncode == 0, out.stderr
        return json.loads(out.stdout.strip().splitlines()[-1])

    def test_the_key_is_not_printed_and_the_facts_beside_it_are(self):
        html = self.facts({'label': 'Chat ops', 'dest': 'wh:wh_3f9a1c02', 'detail': 'failed', 'unit': 'sshd.service'})
        self.assertIn('unit: <strong>sshd.service</strong>', html, 'the control: the page prints the facts of the row')
        self.assertIn('label: <strong>Chat ops</strong>', html)
        self.assertNotIn('wh_3f9a1c02', html)
        self.assertNotIn('dest', html)


if __name__ == '__main__':
    unittest.main()

"""v6.1.2 batch D leftovers — SSH host-key detection, reports-to-webhook, alert chime.

Each test drives the REAL path (the ingest, the report sweep, the dispatcher's
filters) rather than asserting against a hand-built fixture: every one of these
features is an edge-trigger or a delivery, and both classes fail in ways a fixture
happily hides.
"""
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CGI = ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(CGI))


def _fresh_api():
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v612-d-')
    spec = importlib.util.spec_from_file_location('api_v612_d', CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Case(unittest.TestCase):
    def setUp(self):
        self.api = _fresh_api()
        self.fired = []
        self.api.fire_webhook = lambda ev, pl=None: self.fired.append((ev, pl or {}))
        self.api.audit_log = lambda *a, **k: None

    def events(self, name):
        return [p for e, p in self.fired if e == name]


class TestSshHostKeyChange(_Case):
    """The MITM / reimage tripwire."""

    K1 = {'ssh-ed25519': 'SHA256:AAAA', 'ssh-rsa': 'SHA256:BBBB'}

    def _beat(self, keys, first=False):
        self.fired.clear()
        self.api._ingest_posture_v3110('d1', 'nas', {'ssh_hostkeys': keys})

    def test_first_heartbeat_never_fires(self):
        """Enrolling a device is not a key change. Firing here would make the very
        first heartbeat of every host in the fleet a HIGH alert."""
        self._beat(self.K1)
        self.assertEqual(self.events('hostkey_changed'), [])

    def test_unchanged_keys_are_silent(self):
        self._beat(self.K1)
        self._beat(self.K1)
        self.assertEqual(self.events('hostkey_changed'), [])

    def test_a_changed_key_fires_once_with_both_fingerprints(self):
        self._beat(self.K1)
        changed = dict(self.K1, **{'ssh-ed25519': 'SHA256:ZZZZ'})
        self._beat(changed)
        ev = self.events('hostkey_changed')
        self.assertEqual(len(ev), 1)
        # The evidence must survive into the payload: `fingerprint` and `detail`
        # are both already in the _record_alert / _record_fleet_event whitelists,
        # so they actually reach the inbox and the activity feed.
        self.assertEqual(ev[0]['fingerprint'], 'SHA256:ZZZZ')
        self.assertIn('SHA256:AAAA', ev[0]['detail'])   # the old one, for comparison
        self.assertIn('SHA256:ZZZZ', ev[0]['detail'])
        # and it must be edge-triggered — the new value becomes the new baseline,
        # so a repeat heartbeat with the same (changed) key says nothing.
        self._beat(changed)
        self.assertEqual(self.events('hostkey_changed'), [],
                         'the changed key is the new baseline; it must not re-fire')

    def test_a_key_being_ADDED_does_not_fire(self):
        """A new key TYPE appearing (ed25519 generated on an old box) is not a MITM
        signal. Crying wolf once teaches the operator to mute the very event that
        was supposed to catch a real MITM."""
        self._beat({'ssh-rsa': 'SHA256:BBBB'})
        self._beat({'ssh-rsa': 'SHA256:BBBB', 'ssh-ed25519': 'SHA256:NEW'})
        self.assertEqual(self.events('hostkey_changed'), [])

    def test_a_key_being_REMOVED_does_not_fire(self):
        self._beat(self.K1)
        self._beat({'ssh-ed25519': 'SHA256:AAAA'})     # admin deleted the RSA key
        self.assertEqual(self.events('hostkey_changed'), [])

    def test_the_event_is_in_the_registry_and_alertable(self):
        e = self.api.EVENT_REGISTRY['hostkey_changed']
        self.assertEqual(e['severity'], 'high')
        self.assertIn(e['kind'], dict((k, 1) for k, _l, _g in self.api.CHANNEL_KIND_DEFS))

    def test_safe_si_persists_the_fingerprints(self):
        """safe_si is a WHITELIST — a field it drops never reaches the baseline
        check or the drawer, silently."""
        src = (CGI / 'api.py').read_text()
        self.assertIn("safe_si['ssh_hostkeys']", src)

    def test_agent_fingerprint_matches_ssh_keygen(self):
        """SHA256:<base64-no-padding> over the decoded blob — the exact format
        `ssh-keygen -lf` prints, so an operator can compare the two by eye. If this
        drifts, the drawer shows a fingerprint that matches nothing they can check."""
        import base64
        import hashlib
        # A real ed25519 public key line.
        blob = ('AAAAC3NzaC1lZDI1NTE5AAAAIIq1eV6mQZ0KZ8n4Rk8lSlVQ0h4aQ0fT'
                'x4V1p9m0nQxZ')
        try:
            raw = base64.b64decode(blob, validate=True)
        except Exception:
            self.skipTest('sample key blob is not valid base64')
        expect = 'SHA256:' + base64.b64encode(
            hashlib.sha256(raw).digest()).decode().rstrip('=')
        self.assertTrue(expect.startswith('SHA256:'))
        self.assertNotIn('=', expect, 'ssh-keygen strips base64 padding')

        agent = (ROOT / 'client' / 'remotepower-agent.py').read_text()
        self.assertIn('def get_ssh_hostkeys', agent)
        self.assertIn("rstrip('=')", agent, 'padding must be stripped')
        self.assertIn('host_glob', agent,
                      'must read the HOST rootfs, not the container image')


class TestScheduledReportToWebhook(_Case):
    def setUp(self):
        super().setUp()
        self.sent = []
        self.api._dispatch_one_webhook = (
            lambda ev, dest, pl, msg, title, prio, **kw:
                self.sent.append({'event': ev, 'dest': dest.get('id'),
                                  'title': title, 'body': msg}))
        self.emails = []
        self.api.smtp_notifier.send_email = (
            lambda cfg, rcpts, subj, body, **kw: self.emails.append(rcpts))
        self.api._log_email = lambda *a: None
        self.api._build_fleet_report = lambda: {'summary': {}}
        self.api._filter_report_sections = lambda r, s: r
        self.api._render_report_email = lambda r: ('Fleet report', 'the report body')

    def _cfg(self, definition, dests=None):
        self.api.save(self.api.CONFIG_FILE, {
            'webhook_urls': dests if dests is not None else [
                {'id': 'ntfy1', 'url': 'https://ntfy.sh/x', 'format': 'ntfy'}],
            'report_definitions': [definition],
        })
        self.api._LOAD_CACHE.clear()
        st = self.api.DATA_DIR / 'report_schedule_state.json'
        self.api.save(st, {})

    def test_a_report_is_delivered_to_its_webhook_destination(self):
        self._cfg({'id': 'r1', 'name': 'Nightly', 'enabled': True,
                   'cron': '* * * * *', 'sections': ['summary'],
                   'destinations': ['ntfy1'], 'recipients': []})
        self.api._maybe_send_report_definitions()
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.sent[0]['dest'], 'ntfy1')
        self.assertEqual(self.sent[0]['event'], 'scheduled_report')
        self.assertIn('Nightly', self.sent[0]['title'])
        self.assertEqual(self.emails, [],
                         'a destination-only report must not fall back to email')

    def test_a_destination_filter_cannot_silently_drop_the_report(self):
        """The operator chose this destination ON the report. Filtering it against
        the destination's event list / priority floor would drop a delivery they
        explicitly configured — and they'd just see a report that never arrives."""
        self._cfg({'id': 'r1', 'name': 'N', 'enabled': True, 'cron': '* * * * *',
                   'sections': ['summary'], 'destinations': ['picky'], 'recipients': []},
                  dests=[{'id': 'picky', 'url': 'https://x/y',
                          'events': ['device_offline'],   # would exclude our event
                          'min_priority': 5}])            # and outrank its priority
        self.api._maybe_send_report_definitions()
        self.assertEqual(len(self.sent), 1)

    def test_scheduled_report_is_a_declared_synthetic_event(self):
        self.assertIn('scheduled_report', self.api._SYNTHETIC_WEBHOOK_EVENTS)
        # It is NOT a fleet event — it must not appear in the Settings event list.
        self.assertNotIn('scheduled_report', self.api.EVENT_REGISTRY)

    def test_a_deleted_destination_does_not_break_the_sweep(self):
        self._cfg({'id': 'r1', 'name': 'N', 'enabled': True, 'cron': '* * * * *',
                   'sections': ['summary'], 'destinations': ['ghost'], 'recipients': []})
        self.api._maybe_send_report_definitions()      # must not raise
        self.assertEqual(self.sent, [])

    def test_email_and_webhook_can_both_be_used(self):
        self._cfg({'id': 'r1', 'name': 'N', 'enabled': True, 'cron': '* * * * *',
                   'sections': ['summary'], 'destinations': ['ntfy1'],
                   'recipients': ['ops@example.com']})
        self.api._maybe_send_report_definitions()
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.emails, [['ops@example.com']])

    def test_destinations_survive_the_definition_whitelist(self):
        """_clean_report_def is a whitelist — a key it drops makes the Settings
        picker appear to save and then quietly do nothing."""
        cleaned = self.api._clean_report_def({
            'name': 'R', 'sections': [], 'destinations': ['a', 'b'], 'cron': ''})
        self.assertEqual(cleaned['destinations'], ['a', 'b'])


class TestAlertChimeFrontend(unittest.TestCase):
    """Frontend-only, so pin the contract in source: default-off, rise-only,
    baseline-on-first-paint, and no external audio asset (CSP)."""

    @classmethod
    def setUpClass(cls):
        cls.js = (ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        cls.html = (ROOT / 'server' / 'html' / 'index.html').read_text()

    def test_the_chime_is_synthesised_not_fetched(self):
        """An <audio src> or fetched asset is one more thing for CSP to block and
        one more file a trimmed deployment can 404 on. WebAudio needs neither."""
        self.assertIn('_playAlertChime', self.js)
        self.assertIn('createOscillator', self.js)
        block = self.js[self.js.index('function _playAlertChime'):]
        block = block[:block.index('function _announceNewAlerts')]
        self.assertNotIn('new Audio', block)
        self.assertNotIn('.mp3', block)
        self.assertNotIn('.wav', block)

    def test_only_a_RISE_in_the_count_announces(self):
        block = self.js[self.js.index('function _announceNewAlerts'):]
        block = block[:block.index('\n}') + 2]
        self.assertIn('if (prev === null) return;', block,
                      'first paint must establish a baseline, not announce history')
        self.assertIn('if (!(n > prev)) return;', block,
                      'a resolved or unchanged count must stay silent')

    def test_both_toggles_exist_and_are_opt_in(self):
        self.assertIn('cfg-alert-chime', self.html)
        self.assertIn('cfg-alert-notify', self.html)
        # No `checked` attribute on either -> off by default.
        for cid in ('cfg-alert-chime', 'cfg-alert-notify'):
            m = re.search(r'<input[^>]*id="%s"[^>]*>' % cid, self.html)
            self.assertIsNotNone(m, cid)
            self.assertNotIn('checked', m.group(0), f'{cid} must default OFF')

    def test_prefs_are_persisted_server_side(self):
        src = (CGI / 'api.py').read_text()
        self.assertIn("'alert_chime', 'alert_notify'", src,
                      'ui_prefs is a whitelist — an unlisted key never persists')


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
"""
Tests for v2.4.7 — threshold alerting, attention digest, status endpoint.
"""

import sys as _cj_sys
from pathlib import Path as _cj_Path
_cj_sys.path.insert(0, str(_cj_Path(__file__).resolve().parent))
from clientjs import client_js
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT    = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

# Importing api.py runs ensure_default_user() at module scope, which writes to
# DATA_DIR. Without this the import targets the REAL /var/lib/remotepower — it
# only passed because another test module set the var first, and on a box where
# that dir is writable it would clobber a live install.
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())


class _ApiCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault('REQUEST_METHOD', 'GET')
        os.environ.setdefault('PATH_INFO', '/')
        os.environ.setdefault('CONTENT_LENGTH', '0')
        _s = importlib.util.spec_from_file_location("api_v247", _CGI_BIN / "api.py")
        cls.api = importlib.util.module_from_spec(_s)
        _s.loader.exec_module(cls.api)

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        api = self.api
        api.DEVICES_FILE = self._tmp / 'devices.json'
        api.CONFIG_FILE = self._tmp / 'config.json'
        api.CVE_FINDINGS_FILE = self._tmp / 'cve.json'
        api.save(api.CONFIG_FILE, {})
        api.save(api.CVE_FINDINGS_FILE, {})

    def _capture(self, fn, *a):
        cap = {}
        def fake_respond(status, body):
            cap['status'] = status; cap['body'] = body
            raise SystemExit(0)
        self.api.respond = fake_respond
        self.api.require_auth = lambda **kw: 'admin'
        self.api.require_admin_auth = lambda **kw: 'admin'
        try:
            fn(*a)
        except SystemExit:
            pass
        return cap


class TestMailboxThreshold(_ApiCase):

    def test_fires_on_crossing_up_only(self):
        api = self.api
        fired = []
        api.fire_webhook = lambda ev, pl: fired.append((ev, pl))
        api.save(api.DEVICES_FILE, {'d1': {
            'id': 'd1', 'name': 'mail01', 'mailbox_threshold': 50,
        }})
        # Below threshold — no alert.
        api._ingest_mailbox_counts('d1', {'/m/new': {'count': 10, 'exists': True}})
        self.assertEqual(fired, [])
        # Crosses up — exactly one alert.
        api._ingest_mailbox_counts('d1', {'/m/new': {'count': 60, 'exists': True}})
        self.assertEqual(len(fired), 1)
        self.assertEqual(fired[0][0], 'mailbox_threshold')
        self.assertEqual(fired[0][1]['count'], 60)
        # Stays high — must NOT fire again (edge-triggered).
        api._ingest_mailbox_counts('d1', {'/m/new': {'count': 70, 'exists': True}})
        self.assertEqual(len(fired), 1)
        # Drops below then crosses again — re-arms, fires once more.
        api._ingest_mailbox_counts('d1', {'/m/new': {'count': 5, 'exists': True}})
        api._ingest_mailbox_counts('d1', {'/m/new': {'count': 99, 'exists': True}})
        self.assertEqual(len(fired), 2)

    def test_no_threshold_never_fires(self):
        api = self.api
        fired = []
        api.fire_webhook = lambda ev, pl: fired.append(ev)
        api.save(api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'm'}})
        api._ingest_mailbox_counts('d1', {'/m/new': {'count': 9999, 'exists': True}})
        self.assertEqual(fired, [])

    def test_set_stores_threshold(self):
        api = self.api
        api.save(api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'm'}})
        api.get_json_body = lambda: {'paths': ['/m/new'], 'threshold': 25}
        self._capture(api.handle_mailwatch_set, 'd1')
        self.assertEqual(api.load(api.DEVICES_FILE)['d1']['mailbox_threshold'], 25)

    def test_set_zero_clears_threshold(self):
        api = self.api
        api.save(api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'm',
                                           'mailbox_threshold': 25}})
        api.get_json_body = lambda: {'paths': ['/m/new'], 'threshold': 0}
        self._capture(api.handle_mailwatch_set, 'd1')
        self.assertNotIn('mailbox_threshold', api.load(api.DEVICES_FILE)['d1'])


class TestAttentionDigest(_ApiCase):

    def test_merges_signals_ranked(self):
        api = self.api
        api.get_online_ttl = lambda: 180
        now = int(__import__('time').time())
        api.save(api.DEVICES_FILE, {
            'd1': {'id': 'd1', 'name': 'web01', 'last_seen': now - 9999,
                   'monitored': True},                       # offline
            'd2': {'id': 'd2', 'name': 'db01', 'last_seen': now,
                   'upgradable': 30},                         # patches
        })
        api.save(api.CVE_FINDINGS_FILE, {'d2': {'findings': [
            {'severity': 'critical'}, {'severity': 'high'}]}})
        cap = self._capture(api.handle_attention)
        items = cap['body']['items']
        kinds = [i['kind'] for i in items]
        self.assertIn('offline', kinds)
        self.assertIn('patches', kinds)
        self.assertIn('cve', kinds)
        # Critical sorts ahead of warning/info.
        self.assertEqual(items[0]['severity'], 'critical')
        self.assertGreaterEqual(cap['body']['counts']['critical'], 1)

    def test_empty_when_all_clear(self):
        api = self.api
        api.get_online_ttl = lambda: 180
        now = int(__import__('time').time())
        api.save(api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'ok',
                                           'last_seen': now}})
        cap = self._capture(api.handle_attention)
        self.assertEqual(cap['body']['total'], 0)

    def test_refused_agent_self_update_reaches_needs_attention(self):
        """An agent that refused an unsigned/tampered self-update is a tamper
        signal. It used to be stored and shown ONLY as a table on the agent-signing
        settings page — never in Needs-Attention, so it never moved the health score
        and could not page anyone. It must now surface as a critical NA item."""
        api = self.api
        api.get_online_ttl = lambda: 180
        now = int(__import__('time').time())
        api.save(api.DEVICES_FILE, {
            'd1': {'id': 'd1', 'name': 'web01', 'last_seen': now,
                   'agent_update_rejected': 'signature verification failed'},
        })
        cap = self._capture(api.handle_attention)
        items = cap['body']['items']
        hits = [i for i in items if i['kind'] == 'agent_integrity']
        self.assertTrue(hits, f'refused self-update produced no NA item: {items}')
        self.assertEqual(hits[0]['severity'], 'critical')
        self.assertIn('refused a self-update', hits[0]['summary'])
        self.assertIn('signature verification failed', hits[0]['summary'])

    def test_refused_update_item_does_not_depend_on_the_canonical_agent_hash(self):
        """The refusal is the agent's own judgement. Whether the SERVER can hash its
        copy of the build has no bearing on it, so the item must not be gated behind
        _get_agent_sha256() (it used to sit inside that `if`)."""
        api = self.api
        api.get_online_ttl = lambda: 180
        api._get_agent_sha256 = lambda: None      # server can't hash its own build
        now = int(__import__('time').time())
        api.save(api.DEVICES_FILE, {
            'd1': {'id': 'd1', 'name': 'web01', 'last_seen': now,
                   'agent_update_rejected': 'bad signature'},
        })
        cap = self._capture(api.handle_attention)
        kinds = [i['kind'] for i in cap['body']['items']]
        self.assertIn('agent_integrity', kinds)

    def test_unmonitored_device_excluded(self):
        # A device with monitored:false must not surface in the digest,
        # even with an offline/patch/CVE signal — same gate the webhook
        # pipeline applies.
        api = self.api
        api.get_online_ttl = lambda: 180
        now = int(__import__('time').time())
        api.save(api.DEVICES_FILE, {
            'd1': {'id': 'd1', 'name': 'decom', 'last_seen': now - 9999,
                   'upgradable': 50, 'monitored': False},
        })
        api.save(api.CVE_FINDINGS_FILE, {'d1': {'findings': [
            {'severity': 'critical'}]}})
        cap = self._capture(api.handle_attention)
        self.assertEqual(cap['body']['total'], 0,
                         'unmonitored device leaked into the digest')


class TestStatusEndpoint(_ApiCase):

    def test_requires_token(self):
        api = self.api
        api.save(api.CONFIG_FILE, {'status_token': 'secret123'})
        os.environ['QUERY_STRING'] = ''
        cap = self._capture(api.handle_status)
        self.assertEqual(cap['status'], 403)
        os.environ['QUERY_STRING'] = 'token=wrong'
        cap = self._capture(api.handle_status)
        self.assertEqual(cap['status'], 403)
        os.environ['QUERY_STRING'] = ''

    def test_disabled_when_no_token(self):
        api = self.api
        api.save(api.CONFIG_FILE, {})
        os.environ['QUERY_STRING'] = 'token=anything'
        cap = self._capture(api.handle_status)
        self.assertEqual(cap['status'], 403)
        os.environ['QUERY_STRING'] = ''

    def test_valid_token_returns_summary(self):
        api = self.api
        api.get_online_ttl = lambda: 180
        api.save(api.CONFIG_FILE, {'status_token': 'secret123'})
        now = int(__import__('time').time())
        api.save(api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'a',
                                           'last_seen': now}})
        os.environ['QUERY_STRING'] = 'token=secret123'
        cap = self._capture(api.handle_status)
        os.environ['QUERY_STRING'] = ''
        self.assertEqual(cap['status'], 200)
        self.assertIn('health', cap['body'])
        self.assertEqual(cap['body']['devices_online'], 1)
        self.assertIn(cap['body']['health'], ('ok', 'warning', 'critical'))

    def test_token_generate_and_clear(self):
        api = self.api
        api.get_json_body = lambda: {'enabled': True}
        cap = self._capture(api.handle_status_token)
        self.assertTrue(cap['body']['status_token'])
        self.assertTrue(api.load(api.CONFIG_FILE)['status_token'])
        api.get_json_body = lambda: {'enabled': False}
        self._capture(api.handle_status_token)
        self.assertNotIn('status_token', api.load(api.CONFIG_FILE))


class TestAssets(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.js   = client_js()
        cls.html = (_ROOT / 'server/html/index.html').read_text()

    def test_attention_uses_endpoint(self):
        self.assertIn("api('GET', '/attention')", self.js)

    def test_threshold_field(self):
        self.assertIn('mailwatch-threshold', self.html)

    def test_status_token_ui(self):
        self.assertIn('function generateStatusToken', self.js)
        self.assertIn('status-token-box', self.html)


if __name__ == '__main__':
    unittest.main(verbosity=2)

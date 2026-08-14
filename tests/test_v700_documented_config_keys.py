#!/usr/bin/env python3
"""A config key the docs tell you to set must actually be settable.

Three keys were described in the documentation as things an operator
configures, and no save path ever wrote any of them:

  container_alert_excludes  docs/containers.md — "the config key
                            `container_alert_excludes` takes a list of name
                            substrings and suppresses matching containers on
                            every host"
  webterm_daemon_url        docs/remote-access.md — "the daemon URL and shared
                            secret are set with the `webterm_daemon_url` /
                            `webterm_daemon_secret` config keys"
  slow_handler_ms           CHANGELOG

They were read, so they looked configurable to a reviewer. They were never
written, so on the enterprise default — where the config store is a database
row rather than a file — there was no supported way to set them at all. Not
merely undocumented: impossible.

Making the documented promise true is the fix. Trimming the docs would have
taken away a capability operators had been told they had.

The save-whitelist silent drop is a documented trap in this codebase (a
Settings toggle that appears to work and does not persist), so these tests
DRIVE handle_config_save and read the store back rather than asserting the
source contains a key name.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-cfgkeys-'))

import importlib.util  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_spec = importlib.util.spec_from_file_location('api', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules['api'] = api
_spec.loader.exec_module(api)


class _Base(unittest.TestCase):

    def setUp(self):
        api._LOAD_CACHE.clear()
        api.save(api.CONFIG_FILE, {})
        self._real = {n: getattr(api, n) for n in
                      ('respond', 'require_admin_auth', 'require_auth',
                       'audit_log', '_tenant_gate', 'method',
                       'get_json_body', 'get_json_obj', '_read_valid')}
        self.captured = []

        def _respond(status, data=None, *a, **k):
            self.captured.append((status, data))
            raise api.HTTPError(status, data)
        api.respond = _respond
        api.require_admin_auth = lambda *a, **k: 'root'
        api.require_auth = lambda *a, **k: ('root', 'admin')
        api.audit_log = lambda *a, **k: None
        api._tenant_gate = lambda *a, **k: None
        api.method = lambda: 'POST'

    def tearDown(self):
        for n, f in self._real.items():
            setattr(api, n, f)

    def save(self, body):
        self.captured = []
        api.get_json_body = lambda: body
        api.get_json_obj = lambda: body
        api._read_valid = lambda *a, **k: body
        api._LOAD_CACHE.clear()
        try:
            api.handle_config_save()
        except (api.HTTPError, SystemExit):
            pass
        api._LOAD_CACHE.clear()
        status = self.captured[-1][0] if self.captured else None
        return status, (api.load(api.CONFIG_FILE) or {})

    def read(self):
        self.captured = []
        api.method = lambda: 'GET'
        api._LOAD_CACHE.clear()
        try:
            api.handle_config_get()
        except (api.HTTPError, SystemExit):
            pass
        api.method = lambda: 'POST'
        return self.captured[-1][1] if self.captured else {}


class TestTheHarnessCanDetectADrop(_Base):
    """Every test below asserts a value PERSISTED. A harness whose save never
    runs would fail loudly, but one whose read is wrong would not — so prove
    the round trip on a key that has always worked."""

    def test_a_long_standing_key_round_trips(self):
        st, cfg = self.save({'fleet_note': 'hello'})
        self.assertEqual(st, 200)
        self.assertEqual(cfg.get('fleet_note'), 'hello')

    def test_an_unknown_key_is_not_persisted(self):
        """The whitelist is real: this is what a dropped key looks like, and
        it is what all three keys below used to do."""
        _st, cfg = self.save({'definitely_not_a_real_key_xyz': 'v'})
        self.assertIsNone(cfg.get('definitely_not_a_real_key_xyz'))


class TestTheDocumentedKeysPersist(_Base):

    def test_container_alert_excludes(self):
        st, cfg = self.save({'container_alert_excludes': ['pause', 'k8s_POD']})
        self.assertEqual(st, 200)
        self.assertEqual(cfg.get('container_alert_excludes'), ['pause', 'k8s_POD'])

    def test_container_alert_excludes_rejects_a_non_list(self):
        st, _cfg = self.save({'container_alert_excludes': 'pause'})
        self.assertEqual(st, 400)

    def test_webterm_daemon_url(self):
        st, cfg = self.save({'webterm_daemon_url': 'https://term.example.com:8443'})
        self.assertEqual(st, 200)
        self.assertEqual(cfg.get('webterm_daemon_url'), 'https://term.example.com:8443')

    def test_webterm_daemon_url_must_be_http(self):
        st, _cfg = self.save({'webterm_daemon_url': 'file:///etc/passwd'})
        self.assertEqual(st, 400)

    def test_slow_handler_ms(self):
        st, cfg = self.save({'slow_handler_ms': 250})
        self.assertEqual(st, 200)
        self.assertEqual(cfg.get('slow_handler_ms'), 250)

    def test_slow_handler_ms_rejects_junk(self):
        st, _cfg = self.save({'slow_handler_ms': 'soon'})
        self.assertEqual(st, 400)


class TestTheSecretIsNeverEchoedBack(_Base):
    """`webterm_daemon_secret` is a shared secret. The rule in this codebase is
    that a secret-bearing field is withheld on read for EVERYONE, admins
    included, and re-entered to change."""

    def test_it_persists(self):
        st, cfg = self.save({'webterm_daemon_secret': 's3cr3t'})
        self.assertEqual(st, 200)
        self.assertEqual(cfg.get('webterm_daemon_secret'), 's3cr3t')

    def test_it_is_withheld_on_read(self):
        self.save({'webterm_daemon_secret': 's3cr3t'})
        got = self.read()
        self.assertNotEqual(got.get('webterm_daemon_secret'), 's3cr3t',
                            'GET /api/config echoes the web-terminal shared '
                            'secret back in the response body')

    def test_a_blank_secret_keeps_the_current_one(self):
        """Otherwise saving any other Settings field would silently clear it —
        the same opt-in-update idiom the OIDC secret uses."""
        self.save({'webterm_daemon_secret': 's3cr3t'})
        _st, cfg = self.save({'webterm_daemon_secret': ''})
        self.assertEqual(cfg.get('webterm_daemon_secret'), 's3cr3t')

    def test_a_non_secret_sibling_still_reads_back(self):
        """Control: the withholding must be about the SECRET, not about the
        whole group failing to serialise."""
        self.save({'container_alert_excludes': ['pause']})
        self.assertEqual(self.read().get('container_alert_excludes'), ['pause'])


if __name__ == '__main__':
    unittest.main()

"""The stored hash of a credential is not the credential.

`tokens.json` is keyed by SHA-256 of each bearer token so that a leaked copy (a
backup, a database dump, a support bundle) yields no usable session. A fallback
for sessions minted before that change looked a presented value up as a raw key
as well, so the hash read from the file, presented as the bearer token, signed
the reader in: the hashing protected nothing. The enrollment-token store had the
same fallback and let a stored hash enroll a device.

Both fallbacks stay for real legacy (raw) entries and refuse a value shaped like
a stored hash. Shown red by removing that refusal.
"""
import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-hashcred-'))
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))

import api  # noqa: E402


class _Captured(Exception):
    def __init__(self, status, body):
        self.status = status
        self.body = body


class _Stdin:
    def __init__(self, raw):
        self.buffer = io.BytesIO(raw)


def _call(fn, method='POST', body=None, token=None):
    api._begin_request()
    os.environ['REQUEST_METHOD'] = method
    os.environ['PATH_INFO'] = '/api/x'
    os.environ['REMOTE_ADDR'] = '203.0.113.50'
    raw = b'' if body is None else json.dumps(body).encode()
    os.environ['CONTENT_LENGTH'] = str(len(raw))
    api.sys.stdin = _Stdin(raw)
    if token:
        os.environ['HTTP_X_TOKEN'] = token
    else:
        os.environ.pop('HTTP_X_TOKEN', None)
    os.environ.pop('HTTP_AUTHORIZATION', None)

    def fake(status, data=None, *a, **k):
        raise _Captured(status, data)
    orig = api.respond
    api.respond = fake
    try:
        fn()
        return None, None
    except _Captured as c:
        return c.status, c.body
    finally:
        api.respond = orig


class TestHashIsNotACredential(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp(prefix='rp-hashcred-')
        os.environ['RP_DATA_DIR'] = d
        for name in ('USERS_FILE', 'TOKENS_FILE', 'DEVICES_FILE', 'AUDIT_LOG_FILE', 'CONFIG_FILE',
                     'ENROLL_TOKENS_FILE', 'PINS_FILE'):
            if hasattr(api, name):
                setattr(api, name, Path(d) / Path(getattr(api, name)).name)
        api._begin_request()
        api.ensure_default_user()

    def _session(self, raw_keyed=False):
        token = api.make_token()
        key = token if raw_keyed else api._token_hash(token)
        api.save(api.TOKENS_FILE, {key: {
            'user': 'admin', 'created': int(time.time()), 'ttl': 3600,
            'admin': True, 'remember': False, 'last_seen': int(time.time())}})
        api._begin_request()
        return token, key

    # ── sessions ──
    def test_the_token_signs_in(self):
        token, _key = self._session()
        self.assertEqual(api.verify_token(token)[0], 'admin')

    def test_the_stored_hash_does_not(self):
        _token, key = self._session()
        self.assertEqual(len(key), 64)
        self.assertEqual(api.verify_token(key), (None, None))

    def test_a_legacy_raw_keyed_session_still_resolves(self):
        token, key = self._session(raw_keyed=True)
        self.assertEqual(token, key)
        self.assertEqual(api.verify_token(token)[0], 'admin')

    def test_the_hash_is_not_an_authenticated_request_either(self):
        _token, key = self._session()
        status, _ = _call(api.require_auth, method='GET', token=key)
        self.assertEqual(status, 401)
        self.assertIn(key, api.load(api.TOKENS_FILE))     # and it did not end the session

    # ── enrollment tokens ──
    def _enroll_body(self, secret):
        return {'enrollment_token': secret, 'hostname': 'rogue-host', 'name': 'rogue',
                'os': 'Linux', 'version': '7.3.0'}

    def test_a_stored_enrollment_hash_does_not_enrol_a_device(self):
        raw = 'enroll-' + 'a' * 40
        h = api._hash_device_token(raw)
        now = int(time.time())
        api.save(api.ENROLL_TOKENS_FILE, {h: {'created': now, 'expires': now + 600, 'actor': 'admin',
                                              'prefix': raw[:8]}})
        status, body = _call(api.handle_enroll_register, body=self._enroll_body(h))
        self.assertEqual(status, 403, body)
        self.assertIn(h, api.load(api.ENROLL_TOKENS_FILE))   # untouched, still usable by its owner
        self.assertEqual(api.load(api.DEVICES_FILE) or {}, {})

    def test_the_real_enrollment_token_still_works(self):
        raw = 'enroll-' + 'b' * 40
        h = api._hash_device_token(raw)
        now = int(time.time())
        api.save(api.ENROLL_TOKENS_FILE, {h: {'created': now, 'expires': now + 600, 'actor': 'admin',
                                              'prefix': raw[:8]}})
        status, body = _call(api.handle_enroll_register, body=self._enroll_body(raw))
        self.assertEqual(status, 201, body)
        self.assertNotIn(h, api.load(api.ENROLL_TOKENS_FILE))   # one use


class TestPublicTokensDoNotCrashOnNonAscii(unittest.TestCase):
    """hmac.compare_digest raises TypeError on a non-ASCII str, and these values come
    off a URL or a header. A crafted link used to be a 500 (an uncaught exception
    in the handler) instead of the same refusal any wrong token gets."""

    def setUp(self):
        d = tempfile.mkdtemp(prefix='rp-nonascii-')
        os.environ['RP_DATA_DIR'] = d
        for name in ('USERS_FILE', 'TOKENS_FILE', 'DEVICES_FILE', 'AUDIT_LOG_FILE', 'CONFIG_FILE',
                     'INBOUND_WEBHOOKS_FILE', 'ALERTS_FILE'):
            if hasattr(api, name):
                setattr(api, name, Path(d) / Path(getattr(api, name)).name)
        api._begin_request()
        api.ensure_default_user()

    def _run(self, fn, *args, query=''):
        api._begin_request()
        os.environ['REQUEST_METHOD'] = 'GET'
        os.environ['PATH_INFO'] = '/api/x'
        os.environ['QUERY_STRING'] = query
        os.environ['CONTENT_LENGTH'] = '0'
        api.sys.stdin = _Stdin(b'')

        def fake(status, data=None, *a, **k):
            raise _Captured(status, data)
        orig = api.respond
        api.respond = fake
        try:
            fn(*args)
        except (_Captured, SystemExit):
            return 'refused'
        finally:
            api.respond = orig
            os.environ['QUERY_STRING'] = ''
        return 'returned'

    def test_signed_alert_link(self):
        out = self._run(api.handle_alert_act, query='a=x&op=ack&s=%E2%80%A6&e=99999999999')
        self.assertEqual(out, 'refused')

    def test_inbound_webhook_token_in_the_path(self):
        api.save(api.INBOUND_WEBHOOKS_FILE, {'tokens': [{'token': 'a' * 40, 'enabled': True,
                                                         'id': 't1', 'label': 'x'}]})
        for name in ('handle_inbound_webhook', 'handle_syslog_in'):
            fn = getattr(api, name)
            self.assertEqual(self._run(fn, 'caf\u00e9-token'), 'refused', name)

    def test_compare_helper_is_false_not_an_error(self):
        self.assertFalse(api._ct_token_eq('\u2026', 'abc'))
        self.assertFalse(api._ct_token_eq('abc', ''))
        self.assertTrue(api._ct_token_eq('abc', 'abc'))


if __name__ == '__main__':
    unittest.main()

"""D7 (slice) — per-key source-IP allowlist.

An API key may carry an optional `ip_allow` (IPs/CIDRs); a request presenting that
key from any other source IP is rejected at auth. Opt-in: a key without `ip_allow`
is unaffected (the key feature). Locks a CI / service-account key to its egress IP.
"""
import os
import secrets
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-keyip-test-"))

import api  # noqa: E402


class TestIpInCidrs(unittest.TestCase):
    def test_exact_and_cidr(self):
        self.assertTrue(api._ip_in_cidrs('203.0.113.7', ['203.0.113.7']))
        self.assertTrue(api._ip_in_cidrs('10.0.0.42', ['10.0.0.0/24']))
        self.assertFalse(api._ip_in_cidrs('10.0.1.42', ['10.0.0.0/24']))
        self.assertTrue(api._ip_in_cidrs('2001:db8::5', ['2001:db8::/32']))

    def test_fails_closed_on_bad_input(self):
        self.assertFalse(api._ip_in_cidrs('not-an-ip', ['10.0.0.0/8']))
        self.assertFalse(api._ip_in_cidrs('', ['10.0.0.0/8']))
        self.assertFalse(api._ip_in_cidrs('10.0.0.1', ['garbage']))


class TestValidateIpAllow(unittest.TestCase):
    def test_none_and_empty(self):
        self.assertIsNone(api._validate_ip_allow(None))
        self.assertIsNone(api._validate_ip_allow(''))
        self.assertIsNone(api._validate_ip_allow([]))

    def test_string_and_list(self):
        self.assertEqual(api._validate_ip_allow('203.0.113.7, 10.0.0.0/24'),
                         ['203.0.113.7', '10.0.0.0/24'])
        self.assertEqual(api._validate_ip_allow(['10.0.0.0/8']), ['10.0.0.0/8'])

    def test_bad_entry_400(self):
        with self.assertRaises(api.HTTPError) as cm:
            api._validate_ip_allow(['10.0.0.0/24', 'nope'])
        self.assertEqual(cm.exception.status, 400)


class TestVerifyTokenIpAllow(unittest.TestCase):
    def setUp(self):
        self._orig = api.APIKEYS_FILE
        self._gip = api._get_client_ip
        self._d = tempfile.mkdtemp()
        api.APIKEYS_FILE = api.Path(self._d) / 'apikeys.json'
        self._tok = secrets.token_urlsafe(40)
        api.save(api.APIKEYS_FILE, {'k1': {
            'name': 'ci', 'key_hash': api._apikey_hash(self._tok), 'user': 'api',
            'role': 'admin', 'active': True, 'ip_allow': ['10.0.0.0/24']}})

    def tearDown(self):
        api.APIKEYS_FILE = self._orig
        api._get_client_ip = self._gip

    def test_allowed_ip_authenticates(self):
        api._get_client_ip = lambda: '10.0.0.5'
        self.assertEqual(api.verify_token(self._tok), ('api', 'admin'))

    def test_disallowed_ip_rejected(self):
        api._get_client_ip = lambda: '198.51.100.9'
        self.assertEqual(api.verify_token(self._tok), (None, None))

    def test_key_without_allowlist_unrestricted(self):
        tok2 = secrets.token_urlsafe(40)
        store = api.load(api.APIKEYS_FILE)
        store['k2'] = {'name': 'open', 'key_hash': api._apikey_hash(tok2),
                       'user': 'api', 'role': 'admin', 'active': True}
        api.save(api.APIKEYS_FILE, store)
        api._get_client_ip = lambda: '198.51.100.9'   # any IP
        self.assertEqual(api.verify_token(tok2), ('api', 'admin'))


class TestSourceWiring(unittest.TestCase):
    def test_wiring(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("not _ip_in_cidrs(_get_client_ip(), _ipallow)", src)        # verify_token
        self.assertIn("key_ipallow = _validate_ip_allow(body.get('ip_allow'))", src)  # create
        self.assertIn("'ip_allow': v.get('ip_allow'),", src)                      # list


if __name__ == '__main__':
    unittest.main()

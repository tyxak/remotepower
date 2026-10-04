"""IP-intel calls carry a RemotePower User-Agent, and a 403 does not claim the key was bad.

SniffCat sits behind Cloudflare, which refuses urllib's default `Python-urllib/3.x`
with a 403 (error 1010) before the API token is read. The provider code mapped
every 403 to "API key rejected", so a correct key looked wrong.
"""
import os
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-ipintel-ua-'))
_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_TESTS.parent / 'server' / 'cgi-bin'))

import ip_intel  # noqa: E402
from test_ip_intel import _fresh_api  # noqa: E402


class _Resp:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n=-1):
        return b'{"success": true}'


class TestUserAgent(unittest.TestCase):
    def test_every_provider_request_is_sent_with_a_remotepower_user_agent(self):
        api = _fresh_api()
        seen = []

        class _Opener:
            def open(self, req, timeout=None):
                seen.append(req)
                return _Resp()
        saved = api._ssrf_safe_opener
        api._ssrf_safe_opener = lambda **k: _Opener()
        try:
            reqs = [ip_intel.CHECK[p][0]('203.0.113.9', 'k' * 40) for p in ip_intel.PROVIDERS]
            reqs += [ip_intel.REPORT[p][0]('203.0.113.9', 'k' * 40, [18], 'ssh brute force x10') for p in ip_intel.PROVIDERS]
            for r in reqs:
                api._ip_intel_http(r)
        finally:
            api._ssrf_safe_opener = saved
        self.assertEqual(len(reqs), len(seen))
        for r in seen:
            ua = r.get_header('User-agent') or ''
            self.assertTrue(ua.startswith('RemotePower/'), (r.full_url, ua))
            self.assertNotIn('urllib', ua)
        self.assertTrue(all(isinstance(r, urllib.request.Request) for r in seen))


class TestForbiddenIsNotABadKey(unittest.TestCase):
    def test_401_is_a_rejected_key_and_403_is_not_named_as_one(self):
        for prov in ip_intel.PROVIDERS:
            parse = ip_intel.CHECK[prov][1]
            r401, r403 = parse(401, {'message': 'Invalid API token.'}), parse(403, None)
            self.assertEqual('API key rejected', r401['error'])
            self.assertTrue(r401.get('auth'))
            self.assertNotIn('key', r403['error'].lower(), prov)
            self.assertFalse(r403.get('auth'), prov)
            self.assertFalse(r403['ok'])


if __name__ == '__main__':
    unittest.main()

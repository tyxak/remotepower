#!/usr/bin/env python3
"""v6.4.1: live mode (high-res metric burst) on the Windows and macOS agents.

The device drawer's Live tab asks the server to set `live_until`; the agent then
posts 1-second samples until it expires. Only the Linux agent read the flag, so
opening the Live tab on a Mac or a Windows host showed an empty chart forever
with no indication why — the server set the flag and nothing consumed it. The
same silent-failure shape as the agent-checks, canary and custom-script gaps.

Driven against the real `api.handle_device_live_sample` so the payload contract
is exercised rather than assumed.
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("REQUEST_METHOD", "GET")
os.environ.setdefault("PATH_INFO", "/")
os.environ.setdefault("CONTENT_LENGTH", "0")
_PRIOR_AGENT_LOG = os.environ.get("RP_AGENT_LOG")
os.environ["RP_AGENT_LOG"] = os.path.join(tempfile.mkdtemp(), "a.log")
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))

import api  # noqa: E402

# v6.4.1: live mode is a psutil feature BY DESIGN — both ported agents return 0
# samples without it ("no psutil on this host → no samples to send"), which is
# correct graceful degradation, not a bug. This file drives the real sampler, so
# it needs psutil to have anything to assert on. Prod CI installs only the
# ci.yml dependency list, which does NOT include psutil, so without this guard
# every test here errors with an empty `posted` list on the release push — the
# exact class `make ci-parity` exists to catch, found by it.
try:
    import psutil as _psutil  # noqa: F401
    _HAVE_PSUTIL = True
except ImportError:
    _HAVE_PSUTIL = False


def tearDownModule():
    # Restore: a module-level env var leaks into every later module under
    # `unittest discover`, which is how the RP_STORAGE_BACKEND gate failure
    # happened. Set it, always put it back.
    if _PRIOR_AGENT_LOG is None:
        os.environ.pop("RP_AGENT_LOG", None)
    else:
        os.environ["RP_AGENT_LOG"] = _PRIOR_AGENT_LOG


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, _ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Captured(SystemExit):
    def __init__(self, status, body):
        super().__init__(0)
        self.status, self.body = status, body


class _LiveContract:
    AGENT_REL = None

    def setUp(self):
        self.ag = _load(f'live_{self.__class__.__name__}', self.AGENT_REL)
        self.posted = []
        self._orig_post = self.ag._post_json
        self.ag._post_json = lambda url, payload, timeout=None: (
            self.posted.append((url, payload)) or {'ok': True})
        self.addCleanup(setattr, self.ag, '_post_json', self._orig_post)
        self.dev = f'{self.__class__.__name__}-live'
        self.creds = {'device_id': self.dev, 'token': 'devtoken',
                      'server_url': 'https://rp.example'}

    def test_posts_samples_until_the_deadline(self):
        n = self.ag._burst_live_samples('https://rp.example', self.creds,
                                        int(time.time()) + 5, max_iters=3)
        self.assertEqual(n, 3)
        self.assertEqual(len(self.posted), 3)

    def test_hits_the_right_endpoint(self):
        self.ag._burst_live_samples('https://rp.example/', self.creds,
                                    int(time.time()) + 5, max_iters=1)
        url = self.posted[0][0]
        self.assertEqual(url, f'https://rp.example/api/devices/{self.dev}/live-sample')
        self.assertNotIn('//api', url.replace('https://', ''))  # trailing slash handled

    def test_payload_is_exactly_what_the_server_reads(self):
        self.ag._burst_live_samples('https://rp.example', self.creds,
                                    int(time.time()) + 5, max_iters=1)
        p = self.posted[0][1]
        self.assertEqual(set(p), {'token', 'cpu', 'mem', 'disk', 'swap'})
        for k in ('cpu', 'mem', 'disk', 'swap'):
            self.assertIsInstance(p[k], (int, float), k)

    def test_expired_deadline_sends_nothing(self):
        n = self.ag._burst_live_samples('https://rp.example', self.creds,
                                        int(time.time()) - 1, max_iters=5)
        self.assertEqual((n, self.posted), (0, []))

    def test_max_iters_bounds_a_far_future_deadline(self):
        # The deadline comes from the SERVER. Without the iteration bound a
        # large live_until parks the heartbeat loop for its whole duration.
        #
        # The mock aborts past the expected count rather than letting the test
        # rely on the loop terminating: with the bound removed this test would
        # otherwise HANG for 24h and block the gate instead of failing it —
        # verified by actually removing the bound and watching it hang.
        LIMIT = 2

        def counting_post(url, payload, timeout=None):
            self.posted.append((url, payload))
            if len(self.posted) > LIMIT:
                raise AssertionError(
                    f'burst exceeded max_iters={LIMIT} — an unbounded loop '
                    f'would run until live_until, parking the heartbeat')
            return {'ok': True}
        self.ag._post_json = counting_post
        n = self.ag._burst_live_samples('https://rp.example', self.creds,
                                        int(time.time()) + 86400, max_iters=LIMIT)
        self.assertEqual(n, LIMIT)
        self.assertEqual(len(self.posted), LIMIT)

    def test_the_default_iteration_bound_is_sane(self):
        # A default in the thousands would be the same hazard with extra steps.
        self.assertTrue(1 <= self.ag.LIVE_BURST_MAX_ITERS <= 120,
                        self.ag.LIVE_BURST_MAX_ITERS)

    def test_missing_credentials_send_nothing(self):
        self.assertEqual(self.ag._burst_live_samples('https://x', {}, 2**31), 0)
        self.assertEqual(
            self.ag._burst_live_samples('https://x', {'device_id': 'd'}, 2**31), 0)
        self.assertEqual(self.posted, [])

    def test_a_post_failure_stops_the_burst_quietly(self):
        # A live chart is a convenience; it must never break the heartbeat.
        def boom(*a, **k):
            raise RuntimeError('network down')
        self.ag._post_json = boom
        self.assertEqual(
            self.ag._burst_live_samples('https://rp.example', self.creds,
                                        int(time.time()) + 5, max_iters=3), 0)

    def test_response_handler_starts_a_burst(self):
        src = (_ROOT / self.AGENT_REL).read_text()
        hb = src[src.index('def heartbeat_once('):]
        hb = hb[:hb.index('\ndef ', 1)]
        self.assertIn("resp.get('live_until')", hb)
        self.assertIn('_burst_live_samples(', hb)

    def test_a_bad_live_until_does_not_raise(self):
        orig = self.ag._post_json
        try:
            self.ag._post_json = lambda *a, **k: {'ok': True,
                                                  'live_until': 'not-a-number'}
            self.ag.heartbeat_once(dict(self.creds), 2)
        finally:
            self.ag._post_json = orig


@unittest.skipUnless(_HAVE_PSUTIL, "live mode samples require psutil")
class TestMacLiveMode(_LiveContract, unittest.TestCase):
    AGENT_REL = 'client/remotepower-agent-mac.py'


@unittest.skipUnless(_HAVE_PSUTIL, "live mode samples require psutil")
class TestWindowsLiveMode(_LiveContract, unittest.TestCase):
    AGENT_REL = 'client/remotepower-agent-win.py'


@unittest.skipUnless(_HAVE_PSUTIL, "live mode samples require psutil")
class TestServerAcceptsTheAgentSample(unittest.TestCase):
    """The payload must survive the real ingest, not just look right."""

    def setUp(self):
        self._orig = {n: getattr(api, n)
                      for n in ('respond', 'get_json_obj', 'method')}
        self.addCleanup(
            lambda: [setattr(api, n, v) for n, v in self._orig.items()])
        api.method = lambda: 'POST'
        self.dev = 'live-ingest-host'
        api.save(api.DEVICES_FILE, {self.dev: {
            'name': self.dev, 'token': 'devtoken', 'os': 'test',
            'last_seen': int(time.time()), 'enrolled': int(time.time()),
            'tags': [], 'group': '', 'sysinfo': {}, 'agentless': False}})
        api.save(api.LIVE_SAMPLES_FILE, {})

    def _ingest(self, payload):
        api.get_json_obj = lambda: payload

        def fake(status, data=None):
            raise _Captured(status, data)
        api.respond = fake
        try:
            api.handle_device_live_sample(self.dev)
        except _Captured as c:
            return c.status, c.body
        raise AssertionError('no respond()')

    def _agent_payload(self, rel):
        ag = _load('live_ing', rel)
        posted = []
        orig = ag._post_json
        try:
            ag._post_json = lambda url, p, timeout=None: (posted.append(p)
                                                          or {'ok': True})
            ag._burst_live_samples('https://x',
                                   {'device_id': self.dev, 'token': 'devtoken'},
                                   int(time.time()) + 5, max_iters=1)
        finally:
            ag._post_json = orig
        return posted[0]

    def test_mac_payload_is_stored(self):
        status, _ = self._ingest(self._agent_payload('client/remotepower-agent-mac.py'))
        self.assertEqual(status, 200)
        ring = (api.load(api.LIVE_SAMPLES_FILE) or {}).get(self.dev) or []
        self.assertEqual(len(ring), 1)
        self.assertIsNotNone(ring[0]['cpu'])

    def test_windows_payload_is_stored(self):
        status, _ = self._ingest(self._agent_payload('client/remotepower-agent-win.py'))
        self.assertEqual(status, 200)
        ring = (api.load(api.LIVE_SAMPLES_FILE) or {}).get(self.dev) or []
        self.assertEqual(len(ring), 1)
        self.assertIsNotNone(ring[0]['mem'])

    def test_a_wrong_token_is_refused(self):
        p = self._agent_payload('client/remotepower-agent-mac.py')
        p['token'] = 'wrong'
        status, _ = self._ingest(p)
        self.assertEqual(status, 403)


if __name__ == '__main__':
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""v6.4.1: delta sysinfo on the Windows and macOS agents.

Delta sysinfo shipped in v6.2.2 on the Linux agent only, so every Windows and
macOS host had been re-sending its full package list, listening-port table and
interface list on every sysinfo beat since — the server already advertised
`delta_ok` to them and already knew how to merge, so this was pure waste.

The protocol has one property that matters more than the saving, and it is what
most of this file tests: **a field is never omitted on the strength of a send
the server did not confirm.** Get that wrong and the server permanently holds
stale data the agent has stopped sending — silent, and invisible until someone
reads a stale package count.

Both agents are driven for real against `api.handle_heartbeat`, so the merge is
exercised end to end rather than assumed. Runs under both storage backends.
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
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))

import api  # noqa: E402


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, _ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Captured(SystemExit):
    def __init__(self, status, body):
        super().__init__(0)
        self.status, self.body = status, body


class _DeltaContract:
    """Shared contract. Both agents must satisfy all of it, so a future
    divergence fails rather than drifts."""

    AGENT_REL = None

    def setUp(self):
        self.ag = _load(f'delta_{self.__class__.__name__}', self.AGENT_REL)
        self.ag._delta_ok = False
        self.ag._delta_hashes.clear()
        self.ag._delta_pending.clear()
        self._orig = {n: getattr(api, n)
                      for n in ("respond", "get_json_obj", "method")}
        self.addCleanup(
            lambda: [setattr(api, n, v) for n, v in self._orig.items()])
        api.method = lambda: "POST"
        self.dev_id = f'{self.__class__.__name__}-host'
        api.save(api.DEVICES_FILE, {self.dev_id: {
            'name': self.dev_id, 'hostname': self.dev_id, 'os': 'test',
            'token': 'devtoken', 'last_seen': int(time.time()),
            'enrolled': int(time.time()), 'tags': [], 'group': '',
            'sysinfo': {}, 'agentless': False}})
        self.pkgs = {'manager': 'test', 'upgradable': 200,
                     'upgradable_names': [f'pkg{i}' for i in range(200)]}

    def _payload(self):
        return {'device_id': self.dev_id, 'token': 'devtoken',
                'sysinfo': {'hostname': self.dev_id, 'os': 'test',
                            'packages': dict(self.pkgs),
                            'listening_ports': [{'port': 443, 'proto': 'tcp'}],
                            'network': [{'iface': 'eth0'}]}}

    def _beat(self, body):
        api.get_json_obj = lambda: body

        def fake(status, data=None):
            raise _Captured(status, data)
        api.respond = fake
        try:
            api.handle_heartbeat()
        except _Captured as c:
            return c.status, c.body
        raise AssertionError('handle_heartbeat did not respond()')

    def _full_cycle(self):
        """One real beat: apply delta, POST, commit. Returns (payload, resp)."""
        p = self.ag._apply_sysinfo_delta(self._payload())
        status, resp = self._beat(p)
        self.assertEqual(status, 200, resp)
        self.ag._commit_sysinfo_delta(resp)
        return p, resp

    def _stored(self):
        return api.load(api.DEVICES_FILE)[self.dev_id].get('sysinfo') or {}

    # ── the protocol ─────────────────────────────────────────────────────────

    def test_only_lists_fields_this_agent_actually_sends(self):
        # The Linux set also has ssh_hostkeys/usb/autoupdate/ssh_config, which
        # neither of these agents produces. Claiming them would be a lie about
        # what this agent does, and every entry must be server-whitelisted or
        # the omission is silently dropped and the field lost.
        self.assertEqual(set(self.ag._DELTA_SYSINFO_FIELDS),
                         {'packages', 'listening_ports', 'network'})
        for f in self.ag._DELTA_SYSINFO_FIELDS:
            self.assertIn(f, api._DELTA_SYSINFO_FIELDS,
                          f'{f} is not in the server whitelist — omitting it '
                          f'would silently lose the field')

    def test_nothing_omitted_before_the_server_advertises_the_capability(self):
        p = self.ag._apply_sysinfo_delta(self._payload())
        self.assertIn('packages', p['sysinfo'])
        self.assertNotIn('sysinfo_omitted', p)

    def test_unchanged_fields_are_omitted_once_confirmed(self):
        self._full_cycle()          # learns delta_ok
        self._full_cycle()          # first confirmed full send
        p = self.ag._apply_sysinfo_delta(self._payload())
        self.assertNotIn('packages', p['sysinfo'])
        self.assertEqual(set(p['sysinfo_omitted']),
                         {'packages', 'listening_ports', 'network'})

    def test_server_merges_the_omitted_field_back(self):
        self._full_cycle()
        self._full_cycle()
        self._full_cycle()          # this one omits
        self.assertEqual(self._stored()['packages']['upgradable'], 200,
                         'the server lost the omitted field')
        self.assertEqual(len(self._stored()['listening_ports']), 1)

    def test_changed_content_is_sent_full_again(self):
        self._full_cycle()
        self._full_cycle()
        self.pkgs['upgradable'] = 201
        self.pkgs['upgradable_names'].append('newpkg')
        p, _ = self._full_cycle()
        self.assertIn('packages', p['sysinfo'], 'stale content was omitted')
        self.assertEqual(self._stored()['packages']['upgradable'], 201)

    def test_a_busy_response_never_confirms(self):
        """The property that prevents silent data loss."""
        self._full_cycle()
        self._full_cycle()
        self.pkgs['upgradable'] = 202
        self.ag._apply_sysinfo_delta(self._payload())     # full, pending
        self.ag._commit_sysinfo_delta({'busy': True, 'delta_ok': True})
        p = self.ag._apply_sysinfo_delta(self._payload())
        self.assertIn('packages', p['sysinfo'],
                      'omitted after a busy response — the server would hold '
                      'stale packages forever')

    def test_delta_resend_forces_a_full_send(self):
        self._full_cycle()
        self._full_cycle()
        p = self.ag._apply_sysinfo_delta(self._payload())
        self.assertNotIn('packages', p['sysinfo'])
        self.ag._commit_sysinfo_delta({'delta_ok': True,
                                       'delta_resend': ['packages']})
        p = self.ag._apply_sysinfo_delta(self._payload())
        self.assertIn('packages', p['sysinfo'])
        # only the named field is re-sent; the others stay omitted
        self.assertNotIn('network', p['sysinfo'])

    def test_a_server_that_stops_advertising_gets_full_payloads_again(self):
        # Downgrade / restore-from-backup: the server may no longer hold what
        # we stopped sending, so omission must stop from the very next beat.
        self._full_cycle()
        self._full_cycle()
        self.ag._commit_sysinfo_delta({})
        p = self.ag._apply_sysinfo_delta(self._payload())
        self.assertNotIn('sysinfo_omitted', p)
        self.assertIn('packages', p['sysinfo'])

    def test_a_beat_without_sysinfo_is_untouched(self):
        self.ag._delta_ok = True
        p = self.ag._apply_sysinfo_delta({'device_id': 'x', 'token': 't'})
        self.assertNotIn('sysinfo_omitted', p)

    def test_pending_does_not_leak_across_beats(self):
        # A light (no-sysinfo) beat must not commit a previous beat's hashes.
        self._full_cycle()
        self.ag._apply_sysinfo_delta(self._payload())      # records pending
        self.ag._apply_sysinfo_delta({'device_id': 'x'})   # light beat, clears
        self.assertEqual(self.ag._delta_pending, {})
        self.ag._commit_sysinfo_delta({'delta_ok': True})
        self.assertEqual(self.ag._delta_hashes, {},
                         'a light beat committed a prior beat’s hashes')

    def test_malformed_response_does_not_raise(self):
        for bad in (None, [], 'nope', 42):
            self.ag._commit_sysinfo_delta(bad)

    def test_builder_applies_the_delta(self):
        """The wiring: build_heartbeat must actually route through it."""
        src = (_ROOT / self.AGENT_REL).read_text()
        body = src[src.index('def build_heartbeat('):]
        body = body[:body.index('\ndef ', 1)]
        self.assertIn('_apply_sysinfo_delta(payload)', body)

    def test_response_handler_commits_the_delta(self):
        src = (_ROOT / self.AGENT_REL).read_text()
        body = src[src.index('def heartbeat_once('):]
        body = body[:body.index('\ndef ', 1)]
        self.assertIn('_commit_sysinfo_delta(resp)', body)


class TestWindowsDeltaSysinfo(_DeltaContract, unittest.TestCase):
    AGENT_REL = 'client/remotepower-agent-win.py'


class TestMacDeltaSysinfo(_DeltaContract, unittest.TestCase):
    AGENT_REL = 'client/remotepower-agent-mac.py'


if __name__ == '__main__':
    unittest.main(verbosity=2)

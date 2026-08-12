#!/usr/bin/env python3
"""Signals the fleet collects that fleet-knowledge could not answer questions about.

CLAUDE.md: "a signal collected but shown nowhere is the prize." The RAG corpus
is where an operator's question meets what the product knows, and 21 of the 55
sysinfo fields `safe_si` persists were named nowhere in rag_index — including
two shipped in this very release. So "which hosts are unencrypted?" and "is
anything thermally throttled?" could not be answered from fleet knowledge while
the Checks page displayed both answers.

Seven families are added here. The rest of the 21 stay out deliberately and are
listed below with reasons: high-cardinality telemetry churns the embedding cache
on every heartbeat for no retrieval value, which is the same argument the corpus
already makes for excluding load and cpu_percent.

Each assertion DRIVES the real builder. A test that greps rag_index for the
string would pass against a builder that never emits the chunk — and the first
run of this drive returned ZERO docs because the fixture was a dict keyed by id
while the builder takes an iterable of device dicts. The fixture was wrong, not
the code, and a source-grep would have hidden that in both directions.
"""
import sys
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))
import rag_index  # noqa: E402

NOW = int(time.time())

# Persisted sysinfo fields deliberately NOT in the corpus, with the reason.
DELIBERATELY_UNINDEXED = {
    'top_processes': 'changes every heartbeat; re-embeds the device chunk for '
                     'no retrieval value',
    'network_io': 'per-interface counters, same churn argument',
    'custom_metrics': 'operator-defined numeric series — belongs in the metrics '
                      'corpus, not the prose one',
    'uptime_seconds': 'duplicate of `uptime`',
    'pkg_scan_ts': 'a timestamp, not a fact anyone asks about',
    'psutil': 'a capability flag the UI reads; not a fleet question',
    'modules_visible': 'internal agent bookkeeping',
    '_batt_low': 'internal derived flag, prefixed to say so',
    'firewall_fp': 'a fingerprint hash; the firewall corpus carries the rules',
    'auth': 'covered by the dedicated posture and access-review corpora',
    'ssh_hostkeys': 'key fingerprints — high churn, and the SSH-key baseline '
                    'already surfaces changes',
    'usb': 'device inventory lives in the hardware chunk',
    'uptime': 'volatile; the corpus excludes live telemetry by design',
}


def _device(**si):
    return [{'id': 'd1', 'name': 'web01', 'os': 'linux', 'last_seen': NOW,
             'monitored': True, 'sysinfo': si}]


def _text(**si):
    docs = rag_index.build_live_state_corpus(_device(**si), now=NOW)
    return '\n'.join(d.get('text', '') for d in docs)


class TestTheNewSignalsReachFleetKnowledge(unittest.TestCase):
    def test_the_builder_emits_anything_at_all(self):
        """Positive control. The first version of this drive passed a dict
        keyed by device id; the builder takes an ITERABLE of device dicts, so
        it iterated the keys, matched no dict, and returned zero docs — every
        assertion below would have been vacuously false in the same way a
        wrong fixture makes an 'is absent' assertion vacuously true."""
        self.assertGreater(len(rag_index.build_live_state_corpus(
            _device(reboot_required=True), now=NOW)), 0)

    def test_disk_encryption_on(self):
        t = _text(disk_encryption={'encrypted': True, 'encrypted_mounts': ['/', '/var']})
        self.assertIn('disk encryption at rest: on', t)
        self.assertIn('encrypted mount: /var', t)

    def test_disk_encryption_off_says_off(self):
        """The direction that matters — an unencrypted host must be findable."""
        self.assertIn('disk encryption at rest: OFF',
                      _text(disk_encryption={'encrypted': False}))

    def test_disk_encryption_unknown_says_nothing(self):
        """`{}` is the agent's 'I cannot see device-mapper'. Claiming either
        answer there would put a fabricated fact into fleet knowledge."""
        t = _text(disk_encryption={})
        self.assertNotIn('disk encryption at rest', t)

    def test_platform_health(self):
        t = _text(platform_health={'throttle': {'status': 'under-voltage detected'},
                                   'fans': [{'name': 'cpu', 'rpm': 2400}],
                                   'wifi': {'signal_dbm': -71, 'ssid': 'lab'}})
        self.assertIn('platform throttling: under-voltage detected', t)
        self.assertIn('fan cpu: 2400 rpm', t)
        self.assertIn('wifi signal: -71 dBm on lab', t)

    def test_canary_and_guard(self):
        t = _text(canary_status={'tripped': True},
                  guard_quarantine=[{'path': '/tmp/x'}, {'path': '/tmp/y'}])
        self.assertIn('canary/honeytoken file TRIPPED', t)
        self.assertIn('quarantined 2 file', t)

    def test_an_untripped_canary_is_not_reported(self):
        self.assertNotIn('TRIPPED', _text(canary_status={'tripped': False}))

    def test_sshd_config_and_sessions(self):
        t = _text(ssh_config={'PermitRootLogin': 'no', 'PasswordAuthentication': 'no'},
                  logged_in=['alice', 'bob'], chassis='rack-mount', zram=True)
        self.assertIn('sshd PermitRootLogin: no', t)
        self.assertIn('logged-in users: alice, bob', t)
        self.assertIn('chassis type: rack-mount', t)
        self.assertIn('zram compressed swap', t)

    def test_a_secret_named_sshd_field_is_never_embedded(self):
        """rag_index's own rule: substring-match secret-looking names, because
        an exact set misses api_key / passphrase / token. With a cloud
        embedding provider the corpus leaves the box."""
        t = _text(ssh_config={'PermitRootLogin': 'no',
                              'TrustedUserCAKeys': 'x',
                              'host_private_key': 'SUPERSECRET',
                              'api_token': 'sk_live_zzz'})
        self.assertNotIn('SUPERSECRET', t)
        self.assertNotIn('sk_live_zzz', t)
        self.assertIn('sshd PermitRootLogin: no', t)


class TestTheExclusionsAreDeclared(unittest.TestCase):
    """Whatever is left out is left out on purpose, with a reason — an
    undeclared omission is indistinguishable from a forgotten one, which is
    exactly how these 21 accumulated."""

    def _persisted(self):
        import re
        api = (_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        hb = re.search(r'def handle_heartbeat\(.*?\n(?=def |class )', api, re.S).group(0)
        return set(re.findall(r"safe_si\[['\"]([a-z_0-9]+)['\"]\]\s*=", hb))

    def test_every_persisted_signal_is_indexed_or_declared(self):
        rag = (_ROOT / 'server' / 'cgi-bin' / 'rag_index.py').read_text()
        missing = sorted(k for k in self._persisted()
                         if f"'{k}'" not in rag and k not in DELIBERATELY_UNINDEXED)
        self.assertEqual(missing, [], '\n'.join([
            'These sysinfo signals are collected and persisted but appear '
            'nowhere in the RAG corpus, so fleet knowledge cannot answer a '
            'question about them:', *('  ' + m for m in missing),
            '', 'Index the signal, or add it to DELIBERATELY_UNINDEXED with '
            'the reason it is not worth embedding.']))

    def test_no_declared_exclusion_is_actually_indexed(self):
        """A stale exclusion reads as a decision and is none."""
        rag = (_ROOT / 'server' / 'cgi-bin' / 'rag_index.py').read_text()
        import re
        m = re.search(r'def build_live_state_corpus\(.*?\n(?=def )', rag, re.S).group(0)
        stale = sorted(k for k in DELIBERATELY_UNINDEXED if f"si.get('{k}')" in m)
        self.assertEqual(stale, [], f'declared unindexed but indexed: {stale}')

    def test_every_exclusion_states_a_reason(self):
        for k, why in DELIBERATELY_UNINDEXED.items():
            with self.subTest(signal=k):
                self.assertGreater(len(why), 20, f'{k} has no real reason')


if __name__ == '__main__':
    unittest.main()

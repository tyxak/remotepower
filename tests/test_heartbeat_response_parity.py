#!/usr/bin/env python3
"""Every key the heartbeat response carries must be read by the agents it targets.

`tests/test_force_flag_wiring.py` guards ONE direction: every `force_*` flag an
agent reads must be set by the server somewhere. This is the converse, and it
is the direction that keeps producing shipped-dead features — the server sends
a key, an agent silently ignores it, the operator gets a success toast and
nothing happens.

That is not hypothetical. v6.4.3 fixed five of them by hand after a survey:
`force_image_scan` auto-targeted Windows hosts that never read it,
`force_iac_collect` timed out after three minutes and blamed the agent,
`host_scan` (lynis) was claimed and marked *running* on hosts that cannot run
it, and `force_acme_rescan` / `harvest_dns_creds` reported "queued" forever.
Every one was found by reading, not by a check, and nothing stopped the sixth.

WHAT THIS TEST IS NOT: a demand that every agent implement everything. Most of
the gaps below are correct — SCAP, acme.sh and mDNS are Linux-only by design.
The point is that each gap is DECLARED rather than accidental, exactly like
`api._VERB_OS_SUPPORT` for the command channel and `_DELIBERATE_ENGLISH` for
translations. A key whose row says `('linux',)` is a decision somebody made; a
key nobody listed is a decision nobody made.

It fails in BOTH directions:
  * server sends it, a declared reader does not read it  → the dead-feature bug
  * an agent reads it, the table does not list that agent → the table is stale,
    and a stale exemption is how a real gap hides

When adding a heartbeat-response key, add a row. When an agent grows support,
widen the row. If the server should not SEND the key to a platform that cannot
read it, gate it at the source too — `_verb_unsupported_on` and the several
`_device_os_family` checks added in v6.4.3 are the precedent.
"""
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_API = _ROOT / 'server' / 'cgi-bin' / 'api.py'
_AGENTS = {
    'linux':   _ROOT / 'client' / 'remotepower-agent.py',
    'windows': _ROOT / 'client' / 'remotepower-agent-win.py',
    'darwin':  _ROOT / 'client' / 'remotepower-agent-mac.py',
}
_ALL = ('linux', 'windows', 'darwin')

# key → the agents expected to READ it. Anything not _ALL carries its reason.
DECLARED = {
    'agent_checks':         _ALL,
    'backup_monitors':      _ALL,
    'delta_resend':         _ALL,
    'force_agent_upgrade':  _ALL,
    'force_log_sweep':      _ALL,
    'force_package_scan':   _ALL,
    'force_pii_scan':       _ALL,
    'force_secrets_scan':   _ALL,
    'live_until':           _ALL,
    'pii_scan_enabled':     _ALL,
    'pii_scan_paths':       _ALL,
    'secrets_scan_enabled': _ALL,
    'secrets_scan_paths':   _ALL,

    # du (disk-usage) walk: POSIX `du` semantics; Windows has no equivalent
    # collector. Linux + macOS only, deliberately.
    'du_scan_enabled':      ('linux', 'darwin'),
    'du_scan_paths':        ('linux', 'darwin'),
    'force_du_scan':        ('linux', 'darwin'),

    # acme.sh reads on-disk certificate state — a Linux-only layout. v6.4.3
    # gates the server side so these are refused rather than queued forever.
    'force_acme_rescan':    ('linux',),
    'harvest_dns_creds':    ('linux',),

    # OpenSCAP: no Windows/macOS binary. Server refuses at handle_scap_scan.
    'force_scap_scan':      ('linux',),
    'scap_profile':         ('linux',),

    # trivy image scanning is driven by the Linux agent alone. v6.4.3 stopped
    # the fleet-wide scan auto-targeting Windows hosts that report containers.
    'force_image_scan':     ('linux',),
    'image_scan_enabled':   ('linux',),

    # IaC collection: reads Linux config trees. Server refuses others (v6.4.3).
    'force_iac_collect':    ('linux',),

    # lynis on-host audit. Refused at create AND at _claim_agent_scan (v6.4.3),
    # so a job queued by an older client cannot be flipped to `running`.
    'host_scan':            ('linux',),

    # Desired-state apply (users/sudoers/motd) is implemented in the Linux
    # agent only; the server answers `supported:false` + a note for the rest.
    'host_config_desired':  ('linux',),

    # Autonomous guard actions — deliberately NOT ported (v6.4.1 parity sweep
    # closed every PORTABLE gap and left this one open on purpose).
    'guard_actions':        ('linux',),

    # mDNS discovery and the push-channel listener: Linux agent features.
    'mdns_enabled':         ('linux',),
    'push_enabled':         ('linux',),
}


def _server_keys():
    return set(re.findall(r"common_resp\[['\"]([a-z_0-9]+)['\"]\]", _API.read_text()))


def _reads(src, key):
    """The agent consumes this key off the response dict."""
    return bool(re.search(r"\.get\(\s*['\"]%s['\"]" % re.escape(key), src)
                or re.search(r"['\"]%s['\"]\s*(?:in|not in)\b" % re.escape(key), src))


@unittest.skipUnless(_API.exists() and all(p.exists() for p in _AGENTS.values()),
                     'excluded from dist tree')
class TestHeartbeatResponseParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = {n: p.read_text() for n, p in _AGENTS.items()}
        cls.keys = _server_keys()

    def test_the_scan_finds_the_response_keys(self):
        """Without this, a changed idiom would empty `keys` and every
        assertion below would pass against nothing."""
        self.assertGreater(len(self.keys), 20)
        self.assertIn('agent_checks', self.keys)

    def test_every_response_key_is_declared(self):
        undeclared = sorted(self.keys - set(DECLARED))
        self.assertEqual(undeclared, [], '\n'.join([
            'these heartbeat-response keys have no row in DECLARED:', *undeclared,
            '', 'Add one naming the agents expected to read it. A key nobody '
            'listed is a platform decision nobody made — which is how five '
            'features shipped dead and were found by reading rather than by '
            'a check.']))

    def test_no_declared_row_is_stale(self):
        stale = sorted(set(DECLARED) - self.keys)
        self.assertEqual(stale, [], f'declared but no longer sent: {stale}')

    def test_each_declared_reader_actually_reads_it(self):
        missing = []
        for key, readers in sorted(DECLARED.items()):
            for fam in readers:
                if not _reads(self.src[fam], key):
                    missing.append(f'{key}: declared for {fam}, not read there')
        self.assertEqual(missing, [], '\n'.join([
            'the server sends these to agents that ignore them:', *missing,
            '', 'Either implement it on that agent, or narrow the row AND gate '
            'the server so the key is not sent to a platform that drops it — '
            'otherwise the operator gets a success toast for nothing.']))

    def test_no_agent_reads_a_key_the_table_does_not_grant_it(self):
        """The other direction. An agent that grew support silently leaves the
        table describing a narrower product than exists, and the next person
        reads the table."""
        extra = []
        for key, readers in sorted(DECLARED.items()):
            for fam, src in self.src.items():
                if fam not in readers and _reads(src, key):
                    extra.append(f'{key}: read by {fam}, not declared for it')
        self.assertEqual(extra, [], '\n'.join([
            'these agents read a key the table does not list them for:', *extra,
            '', 'Widen the row — and check whether the server still refuses '
            'that platform, because the refusal is now wrong.']))


if __name__ == '__main__':
    unittest.main()

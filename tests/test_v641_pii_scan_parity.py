#!/usr/bin/env python3
"""v6.4.1: the PII inventory scan runs on Windows and macOS.

`pii_scan_enabled` / `pii_scan_paths` / `force_pii_scan` were Linux-only, so a
Windows file server — the place regulated data most often actually lives — could
be opted into the scan from Settings and report nothing, forever.

The class of bug this file exists to prevent is narrower than "does it scan".
The server's `_ingest_pii_findings` builds each stored entry from a **whitelist**
of four fields and drops any finding whose `kind` is not in `_PII_KINDS`, with no
error and no log line. So an agent that emits a kind the server does not know
loses those findings silently — which is exactly what happened while porting
this: the collector emitted `card` where the server expects `credit_card`, and
every credit-card hit vanished at ingest. Nothing in the agent, the payload or a
source review would have shown it; only comparing what the agent produced with
what the server *stored*.

Hence `test_every_kind_the_agent_emits_survives_ingest`, which is the point of
the file. Everything else is supporting cover.
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


def tearDownModule():
    if _PRIOR_AGENT_LOG is None:
        os.environ.pop("RP_AGENT_LOG", None)
    else:
        os.environ["RP_AGENT_LOG"] = _PRIOR_AGENT_LOG


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, _ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# One row carrying every kind, plus a 16-digit number that is NOT a valid card.
_FIXTURE = (
    "name,email,ssn,card,iban,phone,order_id\n"
    "Ada,ada@example.com,123-45-6789,4111 1111 1111 1111,"
    "GB82WEST12345698765432,+441234567890,1234567890123456\n"
)


class _PiiContract:
    AGENT_REL = None

    def setUp(self):
        self.ag = _load(f'pii_{self.__class__.__name__}', self.AGENT_REL)
        self.d = tempfile.mkdtemp()
        with open(os.path.join(self.d, 'customers.csv'), 'w') as f:
            f.write(_FIXTURE)

    def _scan(self):
        return self.ag.collect_pii_findings([self.d])

    # ── the one that matters ────────────────────────────────────────────────

    def test_every_kind_the_agent_emits_survives_ingest(self):
        """The server drops an unknown `kind` silently. Compare agent output to
        what is actually STORED — not to the payload, which always looks fine."""
        found = self._scan()
        agent_kinds = {f['kind'] for f in found}
        self.assertTrue(agent_kinds, 'the fixture produced no findings at all')

        dev = f'pii-{self.__class__.__name__}'
        api.save(api.DEVICES_FILE, {dev: {
            'name': dev, 'token': 't', 'os': 'test',
            'last_seen': int(time.time()), 'enrolled': int(time.time()),
            'tags': [], 'group': '', 'sysinfo': {}, 'agentless': False}})
        api.save(api.PII_FILE, {})
        api._ingest_pii_findings(dev, found)
        stored = (api.load(api.PII_FILE) or {}).get(dev, {}).get('findings') or []
        stored_kinds = {f['kind'] for f in stored}

        self.assertEqual(agent_kinds, stored_kinds,
                         f'the server dropped {sorted(agent_kinds - stored_kinds)} '
                         f'— a kind not in api._PII_KINDS is discarded with no '
                         f'error, so those findings are lost silently')

    def test_kind_names_match_the_server_whitelist(self):
        # Static counterpart to the above: catches a bad kind even if the
        # fixture happens not to produce it.
        for kind, _rx in self.ag._PII_RULES:
            self.assertIn(kind, api._PII_KINDS, kind)
        self.assertIn('credit_card', api._PII_KINDS)

    # ── detection quality ───────────────────────────────────────────────────

    def test_finds_each_kind(self):
        kinds = {f['kind'] for f in self._scan()}
        for k in ('email', 'ssn', 'iban', 'credit_card', 'phone'):
            self.assertIn(k, kinds, k)

    def test_luhn_rejects_a_non_card_16_digit_number(self):
        # Without the checksum every order id and timestamp reads as a card and
        # the operator learns to ignore the report.
        cards = [f for f in self._scan() if f['kind'] == 'credit_card']
        self.assertEqual(len(cards), 1)
        self.assertEqual(cards[0]['count'], 1,
                         'the decoy 1234567890123456 was counted as a card')

    # ── the privacy contract ────────────────────────────────────────────────

    def test_never_returns_a_matched_value(self):
        """The feature finds where PII lives without making a second copy of it
        in the monitoring system. No preview, no fingerprint, no value."""
        for f in self._scan():
            self.assertEqual(set(f), {'path', 'kind', 'count', 'lines'}, f)
        blob = repr(self._scan())
        for secret in ('ada@example.com', '123-45-6789', '4111',
                       'GB82WEST', '441234567890'):
            self.assertNotIn(secret, blob, f'{secret} leaked into a finding')

    # ── bounds ──────────────────────────────────────────────────────────────

    def test_line_numbers_are_capped(self):
        with open(os.path.join(self.d, 'many.txt'), 'w') as f:
            f.writelines(f'a{i}@example.com\n' for i in range(50))
        email = [f for f in self._scan()
                 if f['kind'] == 'email' and f['path'].endswith('many.txt')]
        self.assertEqual(len(email), 1)
        self.assertLessEqual(len(email[0]['lines']), 5)

    def test_findings_are_capped(self):
        for n in range(40):
            with open(os.path.join(self.d, f'f{n}.txt'), 'w') as f:
                f.write('x@example.com\ny@example.org\n')
        self.assertLessEqual(len(self.ag.collect_pii_findings([self.d],
                                                              max_findings=10)), 10)

    def test_time_budget_is_honoured(self):
        started = time.monotonic()
        self.ag.collect_pii_findings(['/'], time_budget=0.5, max_files=10**9)
        self.assertLess(time.monotonic() - started, 20,
                        'the walk ignored its time budget')

    def test_missing_path_is_not_an_error(self):
        self.assertEqual(self.ag.collect_pii_findings(['/nonexistent-xyz']), [])
        self.assertEqual(self.ag.collect_pii_findings([None, 42]), [])

    # ── wiring ──────────────────────────────────────────────────────────────

    def test_defaults_point_at_data_not_config(self):
        # A report that opens with 400 hits from config files is one nobody
        # reads twice.
        paths = self.ag._PII_DEFAULT_PATHS
        self.assertTrue(paths)
        for bad in ('/etc', '/private/etc', 'C:\\Windows'):
            self.assertNotIn(bad, paths)

    def test_uses_a_persisted_due_time_not_a_poll_modulo(self):
        # poll_count % N resets on every agent restart, so a restart-churny host
        # would never scan — the v6.1.2 image-scan bug.
        src = (_ROOT / self.AGENT_REL).read_text()
        self.assertIn('_load_pii_scan_ts()', src)
        self.assertIn('_save_pii_scan_ts(', src)

    def test_response_handler_stores_the_config(self):
        orig = self.ag._post_json
        try:
            self.ag._post_json = lambda *a, **k: {
                'ok': True, 'pii_scan_enabled': True,
                'pii_scan_paths': [self.d], 'force_pii_scan': True}
            self.ag.heartbeat_once({'server_url': 'http://x', 'device_id': 'd'}, 2)
        finally:
            self.ag._post_json = orig
        self.assertTrue(self.ag._pii_cfg['on'])
        self.assertEqual(self.ag._pii_cfg['paths'], [self.d])
        self.assertTrue(self.ag._pii_cfg['force'])

    def test_builder_emits_the_payload_key(self):
        src = (_ROOT / self.AGENT_REL).read_text()
        build = src[src.index('def build_heartbeat('):]
        build = build[:build.index('\ndef ', 1)]
        self.assertIn("payload['pii_findings']", build)


class TestMacPiiScan(_PiiContract, unittest.TestCase):
    AGENT_REL = 'client/remotepower-agent-mac.py'


class TestWindowsPiiScan(_PiiContract, unittest.TestCase):
    AGENT_REL = 'client/remotepower-agent-win.py'


class TestAllThreeAgentsAgreeOnKinds(unittest.TestCase):
    """The Linux agent is the reference. If the three ever disagree about a kind
    name, one of them is silently losing findings at ingest."""

    def test_rule_kinds_are_identical_across_agents(self):
        sets = {}
        for name, rel in (('linux', 'client/remotepower-agent.py'),
                          ('mac', 'client/remotepower-agent-mac.py'),
                          ('win', 'client/remotepower-agent-win.py')):
            src = (_ROOT / rel).read_text()
            block = src[src.index('_PII_RULES = ['):]
            block = block[:block.index(']')]
            import re as _re
            sets[name] = set(_re.findall(r"\('([a-z_]+)',", block))
            # the card kind is counted outside _PII_RULES (it needs Luhn)
            self.assertIn("counts['credit_card']", src,
                          f'{name} does not emit credit_card')
        self.assertEqual(sets['linux'], sets['mac'], sets)
        self.assertEqual(sets['linux'], sets['win'], sets)


if __name__ == '__main__':
    unittest.main(verbosity=2)

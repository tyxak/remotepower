"""Guardrails for bugs found in the whole-project deep-testing sweep (v6.1.2).

Sources: Hypothesis fuzz (containers overflow, importers non-dict), the semgrep
XML finding (billion-laughs), and the code-review subagents (audit-chain tamper
bypass, scanner token-redirect, secrets-scan dead feature).
"""
import importlib
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CGI = ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(CGI))


def _fresh_api():
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-hm-')
    spec = importlib.util.spec_from_file_location('api_hm', CGI / 'api.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class TestAuditChainTamperDetection(unittest.TestCase):
    """Dropping an entry's `_hash` used to reset the chain anchor, letting the
    NEXT entry be edited while verify still said ok — a tamper-evidence bypass."""

    def setUp(self):
        self.api = _fresh_api()
        for i in range(4):
            self.api.audit_log('admin', f'action{i}', f'detail{i}')

    def _entries(self):
        return (self.api.load(self.api.AUDIT_LOG_FILE) or {}).get('entries')

    def test_clean_chain_verifies(self):
        _c, broken = self.api._audit_chain_walk(self._entries())
        self.assertIsNone(broken)

    def test_dropping_a_hash_to_edit_the_next_entry_is_detected(self):
        e = self._entries()
        del e[1]['_hash']
        e[2]['detail'] = 'TAMPERED'
        _c, broken = self.api._audit_chain_walk(e)
        self.assertIsNotNone(broken, 'a deleted hash mid-chain must be flagged as tampering')

    def test_a_legacy_head_entry_without_hash_is_still_allowed(self):
        """A pre-chain (legacy) entry with no _hash is legitimate ONLY at the head."""
        api = _fresh_api()
        api.save(api.AUDIT_LOG_FILE, {'entries': [{'action': 'legacy'}]})
        for i in range(3):
            api.audit_log('admin', f'a{i}', f'd{i}')
        _c, broken = api._audit_chain_walk((api.load(api.AUDIT_LOG_FILE) or {})['entries'])
        self.assertIsNone(broken, 'a legacy head entry must not read as tampering')

    def test_classic_edit_with_hash_intact_still_detected(self):
        e = self._entries()
        e[2]['detail'] = 'edited but hash left'
        _c, broken = self.api._audit_chain_walk(e)
        self.assertIsNotNone(broken)


class TestContainersOverflowFuzzFix(unittest.TestCase):
    """_int_or_zero(inf) raised OverflowError; _float_or_zero(inf) returned inf.
    json.loads accepts Infinity/NaN, so an agent CAN send them."""

    def setUp(self):
        self.c = importlib.import_module('containers')

    def test_int_or_zero_handles_non_finite(self):
        for v in (float('inf'), float('-inf'), float('nan'), 1e400):
            self.assertEqual(self.c._int_or_zero(v), 0)

    def test_float_or_zero_returns_zero_for_non_finite(self):
        for v in (float('inf'), float('-inf'), float('nan')):
            self.assertEqual(self.c._float_or_zero(v), 0.0)

    def test_normal_values_unaffected(self):
        self.assertEqual(self.c._int_or_zero(42), 42)
        self.assertEqual(self.c._float_or_zero(3.5), 3.5)


class TestImportersHardening(unittest.TestCase):
    def setUp(self):
        self.imp = importlib.import_module('importers')

    def test_remotepower_format_with_json_array_does_not_crash(self):
        """A JSON array body for a dict-shaped format used to AttributeError
        (unhandled → 500). Must be the documented ValueError instead."""
        with self.assertRaises(ValueError):
            self.imp.parse('[1,2,3]', 'remotepower')

    def test_kuma_format_with_json_array_does_not_crash(self):
        with self.assertRaises(ValueError):
            self.imp.parse('[]', 'kuma')

    def test_zabbix_billion_laughs_is_rejected(self):
        bomb = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY a "x">'
                '<!ENTITY b "&a;&a;&a;">]><zabbix_export>&b;</zabbix_export>')
        r = self.imp.parse(bomb, 'zabbix')
        self.assertTrue(any('DTD' in u.get('reason', '') or 'entity' in u.get('reason', '')
                            for u in r['unmapped']),
                        'a DTD/entity payload must be refused, not expanded')


class TestSafeXml(unittest.TestCase):
    def setUp(self):
        self.sx = importlib.import_module('safe_xml')

    def test_rejects_dtd_anywhere_in_the_buffer(self):
        # a DOCTYPE hidden behind a large leading comment (the 4KB-window bypass)
        payload = '<!--%s--><!DOCTYPE r [<!ENTITY x "y">]><r/>' % ('c' * 5000)
        with self.assertRaises(ValueError):
            self.sx.fromstring(payload)

    def test_parses_clean_xml(self):
        r = self.sx.fromstring('<root><a>1</a></root>')
        self.assertEqual(r.tag, 'root')

    def test_external_entity_is_rejected_by_stdlib(self):
        xxe = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]><r>&x;</r>'
        with self.assertRaises((ValueError,)):
            self.sx.fromstring(xxe)


class TestScannerNoRedirect(unittest.TestCase):
    def test_scanner_api_refuses_redirects(self):
        """The scanner posts X-RP-Satellite: <token>; a 3xx must not replay it."""
        src = (ROOT / 'client' / 'remotepower-scanner.py').read_text()
        self.assertIn('class _NoRedirect', src)
        self.assertIn('_opener().open(', src)
        self.assertNotIn('urllib.request.urlopen(req', src,
                         'the token-bearing call must not use the redirect-following default')


class TestSecretsScanReachable(unittest.TestCase):
    """force_secrets_scan was honoured by the agent but NEVER set by the server,
    and the cadence was poll_count%N (resets on restart) — the feature could
    silently never run and had no manual trigger."""

    def setUp(self):
        self.api = _fresh_api()
        self.api.require_write_role = lambda *a, **k: 'admin'
        self.api.audit_log = lambda *a, **k: None
        self.api.method = lambda: 'POST'
        self.cap = {}

        def _r(s, d=None):
            self.cap['s'] = s
            self.cap['d'] = d
            raise self.api.HTTPError(s, d)
        self.api.respond = _r

    def test_scan_now_sets_the_force_flag(self):
        self.api.save(self.api.CONFIG_FILE, {'secrets_scan_enabled': True})
        self.api._LOAD_CACHE.clear()
        self.api.save(self.api.DEVICES_FILE, {'d1': {'name': 'n', 'token': 't'}})
        self.api.get_json_obj = lambda: {}
        try:
            self.api.handle_secrets_scan_now()
        except self.api.HTTPError:
            pass
        self.assertEqual(self.cap['s'], 200)
        self.assertTrue((self.api.load(self.api.DEVICES_FILE))['d1'].get('force_secrets_scan'))

    def test_scan_now_requires_the_feature_enabled(self):
        self.api.save(self.api.DEVICES_FILE, {'d1': {'name': 'n'}})
        self.api.get_json_obj = lambda: {}
        try:
            self.api.handle_secrets_scan_now()
        except self.api.HTTPError:
            pass
        self.assertEqual(self.cap['s'], 400)

    def test_agent_uses_persisted_timestamp_not_poll_count_modulo(self):
        agent = (ROOT / 'client' / 'remotepower-agent.py').read_text()
        self.assertIn('_load_secrets_scan_ts', agent)
        self.assertIn('SECRETS_SCAN_INTERVAL_S', agent)
        # the old fragile gate must be gone from the secrets block
        self.assertNotIn('poll_count % SECRETS_SCAN_EVERY', agent)

    def test_route_registered(self):
        src = (CGI / 'api.py').read_text()
        self.assertIn("('POST', '/api/secrets-scan/scan'): handle_secrets_scan_now", src)


if __name__ == '__main__':
    unittest.main()


class TestFrontendRoutingFixes(unittest.TestCase):
    """The JS sweep found network activity-feed clicks routing to the wrong page
    (missing switch cases), plus two nonexistent CSS classes."""

    @classmethod
    def setUpClass(cls):
        cls.app = (ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        cls.css = (ROOT / 'server' / 'html' / 'static' / 'css' / 'styles.css').read_text()

    def test_home_act_dispatch_handles_netmap_and_sites(self):
        # _homeActivityAttrs emits these; the dispatch switch must have the cases
        # or the click falls through to the Devices page.
        self.assertIn("data-home-act=\"netmap\"", self.app)
        self.assertIn("case 'netmap':", self.app)
        self.assertIn("data-home-act=\"sites\"", self.app)
        self.assertIn("case 'sites':", self.app)

    def test_no_reference_to_nonexistent_css_classes(self):
        import re
        # bare .is-active / .c-danger are not defined (only .c-danger-outline is);
        # a \b-based grep gives a false hit, so check for the standalone rule.
        self.assertFalse(re.search(r'^\.is-active\b', self.css, re.M))
        self.assertNotIn("'is-active'", self.app)
        virt = (ROOT / 'server' / 'html' / 'static' / 'js' / 'app-virt.js').read_text()
        self.assertNotIn('is-active', virt, "virt tab must use .active (which exists)")
        tickets = (ROOT / 'server' / 'html' / 'static' / 'js' / 'app-tickets.js').read_text()
        self.assertNotIn("toggle('c-danger'", tickets, "use c-red (c-danger isn't a class)")

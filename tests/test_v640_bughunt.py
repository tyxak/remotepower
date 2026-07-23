"""v6.4.0 adversarial bug-hunt — regression guards for the non-rollout findings.

Covers the fixes for: the ReDoS save-time linter on operator log patterns, the
gateway_latency_high_ms=0 disable regression, the space/dash-free storage token,
and the alert mutation-path scope helper. (The CRITICAL cross-tenant
rollout/autopatch RCE has its own file, test_v640_rollout_tenant_isolation.)
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(CGI))


def _fresh_api():
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v640-bh-')
    spec = importlib.util.spec_from_file_location('api_v640_bh', CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestRedosGuard(unittest.TestCase):
    def setUp(self):
        self.api = _fresh_api()

    def test_catastrophic_patterns_rejected(self):
        for p in ('(a+)+', '(.*)+$', '(?:x+)*', r'(\d+)+', '(ab+)+', '(a+){2,}'):
            self.assertTrue(self.api._regex_redos_risky(p), p)

    def test_legit_patterns_accepted(self):
        for p in ('error', '(error|warn|crit)', 'failed password',
                  r'\bsshd\b.*Failed', r'user=\w+', r'[0-9]{1,3}\.',
                  'CRIT.*disk', '(GET|POST) /', 'oom-killer', '.*timeout.*'):
            self.assertFalse(self.api._regex_redos_risky(p), p)

    def test_global_rule_validation_rejects_redos(self):
        rule, err = self.api._validate_global_rule(
            {'unit': '*', 'pattern': '(a+)+', 'threshold': 1})
        self.assertIsNone(rule)
        self.assertIn('ReDoS', err or '')

    def test_global_rule_validation_accepts_normal(self):
        rule, err = self.api._validate_global_rule(
            {'unit': '*', 'pattern': 'Failed password', 'threshold': 1})
        self.assertIsNone(err)
        self.assertIsNotNone(rule)


class TestStorageToken(unittest.TestCase):
    def setUp(self):
        self.api = _fresh_api()

    def test_rejects_arg_injection(self):
        for bad in ('tank -r other@snap', '-rf tank', 'pool@a pool@b',
                    'a b', ' leadingspace'):
            self.assertFalse(self.api._STORAGE_TOKEN_RE.match(bad), bad)

    def test_accepts_real_names(self):
        for good in ('tank', 'tank/data', 'tank/data@snap', '/mnt/pool',
                     'rpool/ROOT/pve-1'):
            self.assertTrue(self.api._STORAGE_TOKEN_RE.match(good), good)


class TestGatewayLatencyDisable(unittest.TestCase):
    """gateway_latency_high_ms=0 must DISABLE (was overridden to 150 by `or 150`)."""

    def test_source_has_no_or_fallback(self):
        src = (CGI / 'api.py').read_text()
        self.assertNotIn("get('gateway_latency_high_ms', 150) or 150", src)
        # the disable guard is present
        self.assertIn('_lat_thr > 0', src)


class TestAlertScopeHelper(unittest.TestCase):
    def setUp(self):
        self.api = _fresh_api()

    def test_helper_exists_and_enforces_scope(self):
        self.assertTrue(callable(self.api._alert_mutable_by_caller))
        # with a role scope set, an out-of-scope device alert is not mutable
        self.api._caller_scope = lambda: {'groups': ['A']}
        self.api._tenant_gate = lambda: None
        self.api._device_in_scope = lambda scope, dev: (dev or {}).get('group') in scope.get('groups', [])
        self.api.device_get = lambda did: {'group': 'B'} if did == 'devB' else {'group': 'A'}
        self.assertFalse(self.api._alert_mutable_by_caller({'id': 'x', 'device_id': 'devB'}))
        self.assertTrue(self.api._alert_mutable_by_caller({'id': 'y', 'device_id': 'devA'}))


if __name__ == '__main__':
    unittest.main()

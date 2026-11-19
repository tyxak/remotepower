"""8.0.2: an address that a person signed in from is never blocked, reported or listed, whichever way they signed in.

The protection read the audit log for the action `login` only. That is what the password form writes. A passkey writes `login_webauthn`, SAML
`login_saml` and OIDC `login_oidc`, so on an installation where people sign in with SSO the protection was empty: one ban of an administrator's own
address (a mistyped ssh password, or a forged line) was a block on the hosts, a ban at the Cloudflare edge and a public report.

The population is derived from the code: every function that mints a session is listed by syntax tree, with the audit actions it writes. The sweep, the
intake and the audit log run for real; only the socket is replaced.
"""
import ast
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v802-signins-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import ipintel_store  # noqa: E402
from request_harness import RequestCase  # noqa: E402

import ip_intel  # noqa: E402
import ip_intel_handlers  # noqa: E402
import threat_evidence  # noqa: E402

CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
T = 1_790_000_000
DAY = 86400
# a sign-in of each kind, from an address of its own
FROM = {'login': '45.77.30.1', 'login_webauthn': '45.77.30.2', 'login_saml': '45.77.30.3', 'login_oidc': '45.77.30.4'}
FAILED = '45.77.30.9'
# written by a function that mints a session, and not the record of a sign-in: LDAP and a recovery code are passed on the way to `login`
STAGES = {'login_ldap', 'login_recovery_code'}
FAILURE_WORDS = ('failed', 'blocked', 'error', 'required', 'denied', 'refused')
MINTERS = ('make_token', '_mint_session')


def session_minters():
    """{(module, function): {audit actions that begin with `login`}} for every function of the server that mints a session."""
    out = {}
    for path in sorted(CGI.glob('*.py')):
        tree = ast.parse(path.read_text(encoding='utf-8'))
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call)]
            names = {(c.func.attr if isinstance(c.func, ast.Attribute) else getattr(c.func, 'id', '')) for c in calls}
            if not names & set(MINTERS) or fn.name in MINTERS:
                continue
            actions = {c.args[1].value for c in calls
                       if (c.func.attr if isinstance(c.func, ast.Attribute) else getattr(c.func, 'id', '')) == 'audit_log'
                       and len(c.args) >= 2 and isinstance(c.args[1], ast.Constant) and isinstance(c.args[1].value, str)
                       and c.args[1].value.startswith('login')}
            out[(path.name, fn.name)] = actions
    return out


class TestEverySessionMinterIsRead(unittest.TestCase):
    def test_the_population_is_not_empty_and_has_the_four_places(self):
        found = session_minters()
        self.assertEqual({fn for _m, fn in found}, {'handle_login', 'handle_webauthn_login_complete', 'handle_saml_acs', 'handle_oidc_callback'},
                         'a place that mints a session and is not here (or one that is gone): read what it writes, then list it')

    def test_what_they_write_is_what_the_protection_reads(self):
        writes = set()
        for (_mod, fn), actions in session_minters().items():
            record = {a for a in actions if a not in STAGES and not any(w in a for w in FAILURE_WORDS)}
            self.assertTrue(record, f'{fn} mints a session and writes no sign-in action')
            writes |= record
        self.assertEqual(set(ip_intel_handlers.SIGN_IN_ACTIONS), writes,
                         'the actions of ip_intel_handlers.SIGN_IN_ACTIONS are the ones the places that mint a session write')

    def test_a_failure_or_a_stage_is_never_a_protected_sign_in(self):
        for a in ip_intel_handlers.SIGN_IN_ACTIONS:
            self.assertFalse(any(w in a for w in FAILURE_WORDS) or a in STAGES, a)


class TestTheEntriesAreTheOnesTheProductWrites(unittest.TestCase):
    def test_audit_log_writes_the_keys_the_protection_reads_and_this_module_stores(self):
        tree = ast.parse((CGI / 'api.py').read_text(encoding='utf-8'))
        fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'audit_log')
        keys = {k.value for n in ast.walk(fn) if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name) and n.targets[0].id == 'entry'
                and isinstance(n.value, ast.Dict) for k in n.value.keys if isinstance(k, ast.Constant)}
        self.assertTrue({'ts', 'actor', 'action', 'detail', 'source_ip', 'user_agent'} <= keys, keys)


class _Sweep(RequestCase):
    def setUp(self):
        super().setUp()
        self.put(devices={'web1': {'id': 'web1', 'name': 'web01', 'os': 'Ubuntu 24.04', 'token': 'tok', 'tenant': 'default', 'last_seen': T}},
                 abuseipdb_api_key='a' * 80, sniffcat_api_key='s' * 40, edge_list_token='L' * 40,
                 ip_intel={'sensor_enabled': True, 'block_enabled': True, 'block_confirmed': True, 'report_enabled': True,
                           'edgelist_enabled': True, 'edge_account_id': 'a' * 32})
        self.sent = []
        self.api._ip_intel_http = lambda req: (self.sent.append(req) or (200, {'success': True, 'data': {}}))

    def sign_in(self, action, ip, ago):
        """One audit entry, in the shape `audit_log` writes (the harness replaces that function, so the entry is stored the way it stores it)."""
        entries = list((self.api.load(self.api.AUDIT_LOG_FILE) or {}).get('entries') or [])
        entries.append({'ts': T - ago, 'actor': 'admin-' + action, 'action': action, 'detail': 'sign in', 'source_ip': ip, 'user_agent': ''})
        self.api.save(self.api.AUDIT_LOG_FILE, {'entries': entries})
        self.api._LOAD_CACHE.clear()

    def ban(self, ips):
        events = [threat_evidence.normalize_event({'ip': ip, 'first': T - 60, 'last': T - 5, 'src': {'f2b': 1},
                                                   'tok': {'f2b': {'jail:sshd': 1}}, 'ban': ['sshd']}, now=T) for ip in ips]
        with mock.patch('time.time', return_value=T - 60):
            self.api.ip_intel_note_evidence('web1', events, {'sources': [], 'ignored': {}, 'dropped': 0}, T - 60)
        self.api._LOAD_CACHE.clear()
        ipintel_store.update(self.api, last_sweep=0)
        with mock.patch('time.time', return_value=T):
            self.api.run_ip_intel_if_due()
        self.api._LOAD_CACHE.clear()
        st = self.api.load(self.api.IPINTEL_FILE)
        reported = set()
        for r in self.sent:
            if r['method'] == 'POST' and 'report' in r['url']:
                body = r['body'].decode()
                reported.add(body.split('ip=')[1].split('&')[0] if 'abuseipdb' in r['url'] else body.split('"ip": "')[1].split('"')[0])
        return st, reported


class TestTheProtectionHolds(_Sweep):
    def protected(self, ip):
        with mock.patch('time.time', return_value=T):
            mod = self.api.ip_intel_handlers_mod
            nets = mod._protected_networks(mod._policy(), self.api._load_ro(self.api.DEVICES_FILE) or {})
        return bool(ip_intel.never_block_reason(ip, nets))

    def test_every_kind_of_sign_in_protects_its_address(self):
        for action, ip in FROM.items():
            self.sign_in(action, ip, 2 * DAY)
        for action, ip in FROM.items():
            self.assertTrue(self.protected(ip), f'a sign-in written as {action} does not protect {ip}')

    def test_a_failed_sign_in_protects_nothing(self):
        self.sign_in('login_failed', FAILED, 2 * DAY)
        self.sign_in('login_webauthn_required', FAILED, 2 * DAY)
        self.sign_in('login_ldap', FAILED, 2 * DAY)
        self.assertFalse(self.protected(FAILED), 'the failures of a sign-in are what a block is for')

    def test_a_sign_in_older_than_thirty_days_protects_nothing(self):
        for action, ip in FROM.items():
            self.sign_in(action, ip, 31 * DAY)
        for action, ip in FROM.items():
            self.assertFalse(self.protected(ip), action)

    def test_a_ban_of_each_address_is_neither_a_block_nor_a_report_nor_a_list_entry(self):
        for action, ip in FROM.items():
            self.sign_in(action, ip, 2 * DAY)
        st, reported = self.ban(list(FROM.values()) + [FAILED])
        blocked, edge = set((st.get('blocks') or {}).get('web1', {})), set(st.get('edgeban') or {})
        self.assertEqual(sorted(blocked), [FAILED], 'only the address nobody signed in from is blocked on the host')
        self.assertEqual(sorted(edge), [FAILED], '... and banned at the edge')
        self.assertEqual(sorted(reported), [FAILED], '... and reported')
        for action, ip in FROM.items():
            why = (((st.get('attackers') or {}).get(ip) or {}).get('devices') or {}).get('web1', {}).get('not_blocked')
            self.assertTrue(why, f'{action}: the page says why the address was left alone')


if __name__ == '__main__':
    unittest.main()

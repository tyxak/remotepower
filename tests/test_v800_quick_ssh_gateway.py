#!/usr/bin/env python3
"""8.0.0: the quick SSH icon of the Hosts page also goes through the SSH gateway, run as the real functions of app.js under node.

A server that allows the gateway (module on, host opted in) shows a second icon that builds `ssh user@name.rp`, the form docs/sshgw.md gives, in place of `ssh user@ip`. The
gateway reads the part before `.rp` as a host id, else a unique host name, else a unique hostname, and refuses a name two hosts answer to, so the page offers the name only when no
other server the person can reach through the gateway answers to it (as a name, or as an id), and the id otherwise. The icon is for people who may use ssh (admins always may) and
for Linux servers. The direct icon is unchanged (tests/test_v242.py holds it).
"""

import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
import srcpin  # noqa: E402

_NODE = shutil.which('node')
APP = (_TESTS.parent / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text(encoding='utf-8')
FUNCS = ('escAttr', '_sshGatewayTarget', '_sshGatewayIcon', 'sshLinkIcon', 'quickSshGateway')


def setUpModule():
    __import__("sys").path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import env_guard

    env_guard.save(__name__)


def tearDownModule():
    import env_guard

    env_guard.restore(__name__)


def dev(i, name=None, **kw):
    return dict({'id': i, 'name': name if name is not None else i, 'os': 'Ubuntu 24.04', 'ip': '10.0.0.%d' % (hash(i) % 200 + 1), 'hostname': (name or i) + '.lab', 'sshgw_enabled': True}, **kw)


def run(script, devices=(), modules=None, me=None, user='root'):
    esc = __import__('re').search(r'^function escHtml\(s\)[^\n]*$', APP, __import__('re').M).group(0)
    parts = [esc] + [srcpin.js_function(APP, n) for n in FUNCS]
    code = (
        'const window = {_modules: %s, _devicesCache: %s, location: {href: ""}};\n'
        'let _meCache = %s;\n'
        'const _log = [];\nlet _copied = null;\n'
        'function getDefaultSshUsername() { return %s; }\n'
        'function toast(m, t) { _log.push([m, t]); }\n'
        'const navigator = {clipboard: {writeText: s => { _copied = s; return Promise.resolve(); }}};\n'
        '%s\n%s\n'
    ) % (json.dumps({'sshgw': True} if modules is None else modules), json.dumps(list(devices)), json.dumps({'admin': True, 'permissions': []} if me is None else me), json.dumps(user), '\n'.join(parts), script)
    r = subprocess.run([_NODE, '-'], input=code, capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise AssertionError(r.stderr[-1500:])
    return json.loads(r.stdout)


@unittest.skipUnless(_NODE, 'node not installed')
class TestWhoGetsTheIcon(unittest.TestCase):

    def target(self, d, devices=None, **kw):
        devices = [d] if devices is None else devices
        return run('console.log(JSON.stringify(_sshGatewayTarget(%s)));' % json.dumps(d), devices, **kw)

    def test_a_server_that_allows_the_gateway_gets_its_name(self):
        self.assertEqual(self.target(dev('gt01', 'gitea.lab')), 'gitea.lab')

    def test_a_host_without_the_flag_or_a_windows_host_gets_none(self):
        # the host list carries the flag only while the module is on and only to a person who may use ssh (tests/test_v800_devices_sshgw_flag.py), so the page asks for nothing else
        self.assertEqual(self.target(dev('gt01', sshgw_enabled=False)), '')
        d = dev('gt01')
        del d['sshgw_enabled']
        self.assertEqual(self.target(d), '')
        self.assertEqual(self.target(dev('gt01', os='Windows 11')), '')
        self.assertEqual(self.target({'name': 'x', 'sshgw_enabled': True}), '', 'no id, no target')

    def test_the_page_does_not_wait_for_the_module_list_or_the_roles(self):
        self.assertEqual(self.target(dev('gt01'), modules={}, me=False), 'gt01', 'the first table is drawn before /api/home and /api/me have answered')

    def test_two_servers_of_one_name_get_their_ids(self):
        a, b = dev('gt01', 'gitea'), dev('gt02', 'Gitea')
        self.assertEqual(self.target(a, [a, b]), 'gt01')
        self.assertEqual(self.target(b, [a, b]), 'gt02')

    def test_a_name_that_is_another_servers_id_is_not_used(self):
        a, b = dev('gt01', 'gitea'), dev('gitea', 'other')
        self.assertEqual(self.target(a, [a, b]), 'gt01', 'the gateway would read `gitea` as the id of the other one')
        self.assertEqual(self.target(b, [a, b]), 'other', 'its own name is free: no other server answers to `other`')

    def test_a_server_that_is_not_opted_in_does_not_count_against_a_name(self):
        a, b = dev('gt01', 'gitea'), dev('gt02', 'gitea', sshgw_enabled=False)
        self.assertEqual(self.target(a, [a, b]), 'gitea', 'the gateway resolves among the servers it may reach')

    def test_a_name_the_gateway_would_refuse_falls_back_to_the_id(self):
        for bad in ('web server', 'web/01', '-web', 'ünï', ''):
            self.assertEqual(self.target(dev('gt01', bad)), 'gt01', repr(bad))
        self.assertEqual(self.target(dev('bad id', 'web server')), '', 'neither is a name the gateway accepts')


@unittest.skipUnless(_NODE, 'node not installed')
class TestTheIcons(unittest.TestCase):

    def icons(self, d, **kw):
        return run('console.log(JSON.stringify(sshLinkIcon(%s)));' % json.dumps(d), [d], **kw)

    def test_a_server_that_allows_the_gateway_has_both_icons_and_the_direct_one_is_as_it_was(self):
        h = self.icons(dev('gt01', 'gitea.lab'))
        self.assertEqual(h.count('<a '), 2)
        self.assertIn('data-action="quickSsh"', h)
        self.assertIn('data-action="quickSshGateway" data-arg="gitea.lab"', h)
        self.assertIn('title="Quick SSH through the gateway"', h)
        self.assertLess(h.index('quickSsh"'), h.index('quickSshGateway'), 'the direct icon first')

    def test_without_the_flag_there_is_the_direct_icon_only(self):
        h = self.icons(dev('gt01', sshgw_enabled=False))
        self.assertEqual((h.count('<a '), 'quickSshGateway' in h), (1, False))

    def test_a_server_with_no_address_still_has_the_gateway_icon(self):
        h = self.icons(dev('gt01', ip='', hostname=''))
        self.assertEqual((h.count('<a '), 'quickSshGateway' in h, 'data-action="quickSsh"' in h), (1, True, False))

    def test_a_windows_host_has_neither(self):
        self.assertEqual(self.icons(dev('w01', os='Windows 11')), '')

    def test_a_name_is_an_attribute_value_and_cannot_break_out_of_it(self):
        h = self.icons(dev('gt01', 'x"onmouseover="1'))
        self.assertNotIn('onmouseover', h.split('data-action="quickSshGateway"', 1)[1].split('>', 1)[0].replace('&quot;', ''), 'the name is not a name the gateway accepts: the id is used')
        self.assertIn('data-arg="gt01"', h)


@unittest.skipUnless(_NODE, 'node not installed')
class TestTheAction(unittest.TestCase):

    def act(self, target, user='root'):
        return run('quickSshGateway(%s); console.log(JSON.stringify({href: window.location.href, copied: _copied, log: _log}));' % json.dumps(target), user=user)

    def test_it_hands_off_the_link_and_copies_the_command_with_the_gateway_name(self):
        got = self.act('web01')
        self.assertEqual(got['href'], 'ssh://root@web01.rp')
        self.assertEqual(got['copied'], 'ssh root@web01.rp')
        self.assertEqual(got['log'], [])

    def test_no_default_username_says_where_to_set_it_and_does_nothing_else(self):
        got = self.act('web01', user='')
        self.assertEqual((got['href'], got['copied']), ('', None))
        self.assertEqual(got['log'][0][1], 'error')
        self.assertIn('SSH preferences', got['log'][0][0])

    def test_the_link_is_encoded(self):
        got = self.act('web 01', user='a b')
        self.assertEqual(got['href'], 'ssh://a%20b@web%2001.rp')


class TestTheSource(unittest.TestCase):

    def test_the_direct_quick_ssh_function_is_untouched(self):
        body = srcpin.js_function(APP, 'quickSsh')
        self.assertIn('ssh://', body)
        self.assertIn('navigator.clipboard', body)
        self.assertNotIn('.rp', body)

    def test_the_suffix_is_the_one_the_gateway_uses(self):
        gw = (_TESTS.parent / 'server' / 'cgi-bin' / 'sshgw.py').read_text()
        self.assertIn("TARGET_SUFFIX = '.rp'", gw)
        self.assertIn('${target}.rp', srcpin.js_function(APP, 'quickSshGateway'))


if __name__ == '__main__':
    unittest.main()

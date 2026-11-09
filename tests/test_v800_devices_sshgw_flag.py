#!/usr/bin/env python3
"""8.0.0: the host list says which hosts allow the SSH gateway, to the people who may use it.

The Hosts page shows a second quick SSH icon (`ssh user@name.rp`) for a host that allows the gateway. The page needs one fact for it, `sshgw_enabled` on the row, and the fact is
sent only when the gateway module is on, only to an administrator or a role with the `ssh` permission, and only for a host that is opted in. A role without `ssh` never learns which
hosts are opted in from the host list, which is what the page's own check (no icon) and the gateway's (refuses) already say.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v800-devsshgw-'))
_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_TESTS.parent / 'server' / 'cgi-bin'))

from test_v800_traffic import _Server, device  # noqa: E402

TOKENS = {'adm': ('root', 'admin'), 'ssh': ('sam', 'sshops'), 'nossh': ('nia', 'rebooter'), 'view': ('vic', 'viewer')}


def setUpModule():
    __import__("sys").path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import env_guard

    env_guard.save(__name__)


def tearDownModule():
    import env_guard

    env_guard.restore(__name__)


class _List(_Server):

    def setUp(self):
        super().setUp()
        api = self.api
        api.verify_token = lambda token: TOKENS.get(token, (None, None))
        self.put({'a': device(id='a', name='a', sshgw_enabled=True), 'b': device(id='b', name='b', token='t2'), 'c': device(id='c', name='c', token='t3', sshgw_enabled=True)}, sshgw_enabled=True)
        api.save(api.ROLES_FILE, {'roles': [{'name': 'sshops', 'permissions': ['ssh'], 'scope': {'type': 'all'}}, {'name': 'rebooter', 'permissions': ['reboot'], 'scope': {'type': 'all'}}]})
        api._LOAD_CACHE.clear()

    def flags(self, tok):
        st, rows = self.request('/api/devices', token=tok)
        self.assertEqual(st, 200, rows)
        return {r['id']: r.get('sshgw_enabled') for r in rows}


class TestTheFlag(_List):

    def test_an_administrator_and_a_role_with_ssh_get_it_for_the_opted_in_hosts_only(self):
        for tok in ('adm', 'ssh'):
            self.assertEqual(self.flags(tok), {'a': True, 'b': None, 'c': True}, tok)

    def test_a_role_without_ssh_and_a_viewer_never_learn_it(self):
        for tok in ('nossh', 'view'):
            self.assertEqual(self.flags(tok), {'a': None, 'b': None, 'c': None}, tok)

    def test_with_the_module_off_nobody_gets_it(self):
        cfg = self.cfg()
        cfg['sshgw_enabled'] = False
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api._LOAD_CACHE.clear()
        self.assertEqual(self.flags('adm'), {'a': None, 'b': None, 'c': None})

    def test_the_flag_is_the_host_record_and_never_something_the_caller_sent(self):
        st, rows = self.request('/api/devices', token='adm', query='sshgw_enabled=1&slim=1')
        self.assertEqual(st, 200)
        self.assertEqual({r['id']: r.get('sshgw_enabled') for r in rows}, {'a': True, 'b': None, 'c': True})

    def test_a_broken_role_store_gives_no_flag_and_not_an_error(self):
        self.api.save(self.api.ROLES_FILE, {'roles': 'junk'})
        self.api._LOAD_CACHE.clear()
        st, rows = self.request('/api/devices', token='ssh')
        self.assertEqual(st, 200)
        self.assertTrue(all('sshgw_enabled' not in r for r in rows))


if __name__ == '__main__':
    unittest.main()

"""The software policy does not read a cut list as a compliant one, and does not take an account's own folder for the system's (8.0.2).

The Windows and macOS agents send the applications of a host, and the server judges the fleet's software policy (banned, required and minimum-version rules) against that list. Two things
let a standard user of a Mac flip the verdict of the host: the agent cut its list at 5,000 rows by name and told nobody, so 4,999 bundles named to sort first pushed an
administrator's TeamViewer out of the report (a rule that bans it then found nothing); and the list took bundles from the Applications folder of every account, which each person writes, so
a bundle named like a required product met the rule that requires it.

An agent now says `cut` when it left out rows that exist (the walk of the folders ran out of its budget, the report holds no more), and the server says so too when a list is over its own
cap. A rule that needs an application to be absent (`banned`, `min_version`) is not judged compliant on a list that is cut: it is a violation that says the list is cut. A row of an account's own
folder (`in_user_folder`) shows what is on the Mac, bans still find it, and it neither meets a `required` rule nor stands in for the system's copy of a minimum-version rule.

This module drives the real handler and the real policy over lists in the shapes the agents write, and the real macOS agent over a scratch tree into the real handler.
"""
import importlib.util
import json
import os
import plistlib
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-listcut-'))

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CGI = ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(CGI))

_spec = importlib.util.spec_from_file_location('api_list_cut', CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
import software_inventory as si  # noqa: E402

_mspec = importlib.util.spec_from_file_location('rp_mac_list_cut_agent', ROOT / 'client' / 'remotepower-agent-mac.py')
mac = importlib.util.module_from_spec(_mspec)
_mspec.loader.exec_module(mac)

RULES = [{'type': 'banned', 'package': 'TeamViewer', 'id': 'r-banned'},
         {'type': 'required', 'package': 'EDR Agent', 'tags': ['mac'], 'id': 'r-edr'},
         {'type': 'min_version', 'package': 'Google Chrome', 'version': '120', 'id': 'r-chrome'}]


class Server(unittest.TestCase):
    HOST = 'mac1'

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix='rp-listcut-data-'))
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))
        self._saved = {n: getattr(api, n) for n in ('DEVICES_FILE', 'PACKAGES_FILE', 'SOFTWARE_POLICY_FILE', 'SOFTWARE_VIOLATIONS_FILE', 'CONFIG_FILE')}
        for n, v in self._saved.items():
            setattr(api, n, self.dir / v.name)
        self._data_dir = api.DATA_DIR
        api.DATA_DIR = self.dir
        self.fired = []

        class Captured(Exception):
            def __init__(self, status, body):
                super().__init__(status)
                self.status, self.body = status, body
        self.Captured = Captured

        def respond(status, data=None, headers=None):
            raise Captured(status, data)
        for name, value in (('respond', respond), ('method', lambda: 'POST'), ('fire_webhook', lambda event, payload: self.fired.append((event, dict(payload)))),
                            ('audit_log', lambda *a, **k: None)):
            p = mock.patch.object(api, name, value)
            p.start()
            self.addCleanup(p.stop)
        now = int(time.time())
        api.save(api.DEVICES_FILE, {self.HOST: {'id': self.HOST, 'name': 'MacBook', 'hostname': 'MacBook', 'os': 'macOS 14.2', 'token': 'tok-' + self.HOST, 'last_seen': now,
                                                'enrolled': now, 'tags': ['mac'], 'group': '', 'sysinfo': {}, 'agentless': False, 'monitored': True}})
        api.save(api.CONFIG_FILE, {})
        api.save(api.SOFTWARE_POLICY_FILE, {'rules': RULES})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(api, n, v)
        api.DATA_DIR = self._data_dir
        api._LOAD_CACHE.clear()

    def submit(self, rows, cut=None, manager='macos', skipped=0, extra=None):
        body = {'device_id': self.HOST, 'token': 'tok-' + self.HOST, 'pkg_manager': manager, 'packages': rows, 'skipped': skipped}
        if cut is not None:
            body['cut'] = cut
        body.update(extra or {})
        with mock.patch.object(api, 'get_json_obj', lambda: json.loads(json.dumps(body))):
            api._LOAD_CACHE.clear()
            try:
                api.handle_packages_submit()
            except self.Captured as c:
                self.assertEqual(c.status, 200, c.body)
        api._LOAD_CACHE.clear()

    def stored(self):
        return (api.load(api.PACKAGES_FILE) or {}).get(self.HOST) or {}

    def violations(self):
        api._LOAD_CACHE.clear()
        return {v['rule_id']: v for v in ((api.load(api.SOFTWARE_VIOLATIONS_FILE) or {}).get(self.HOST) or {}).get('violations', [])}


def app(name, version='1.0', user=False, ident=None):
    r = {'name': name, 'version': version, 'manager': 'macos'}
    if ident:
        r['id'] = ident
    if user:
        r['in_user_folder'] = True
    return r


GOOD = [app('Safari', '17.2'), app('Google Chrome', '120.0.6099.129'), app('EDR Agent', '9.1')]


class TestACompleteListIsJudgedAsAlways(Server):
    def test_a_whole_list_with_nothing_wrong_is_compliant_and_a_banned_application_that_is_absent_is_no_violation(self):
        self.submit(GOOD)
        self.assertEqual(self.violations(), {})
        self.assertNotIn('cut', self.stored(), 'the record of a whole list has no mark')

    def test_a_whole_list_that_holds_a_banned_application_is_a_violation(self):
        self.submit(GOOD + [app('TeamViewer', '15.50')])
        v = self.violations()
        self.assertEqual(sorted(v), ['r-banned'])
        self.assertEqual(v['r-banned']['found'], '15.50')


class TestACutListIsNotACompliantOne(Server):
    def test_what_a_cut_list_does_not_hold_is_not_read_as_not_installed(self):
        self.submit([app('Safari', '17.2'), app('EDR Agent', '9.1')], cut=True)       # Chrome and TeamViewer are not in it: it is cut
        v = self.violations()
        self.assertEqual(sorted(v), ['r-banned', 'r-chrome'])
        self.assertEqual(v['r-banned']['found'], 'not known')
        self.assertEqual(v['r-banned']['expected'], 'not installed')
        self.assertIn('cut', v['r-banned']['detail'])
        self.assertEqual(v['r-chrome']['expected'], '>= 120')
        self.assertEqual(v['r-chrome']['found'], 'not known')
        self.assertIs(self.stored().get('cut'), True)

    def test_what_a_cut_list_does_hold_is_judged_as_always(self):
        self.submit(GOOD + [app('TeamViewer', '15.50')], cut=True)
        v = self.violations()
        self.assertEqual(sorted(v), ['r-banned'])
        self.assertEqual(v['r-banned']['found'], '15.50', 'the application is there: the list being cut changes nothing about that')
        self.submit([app('Google Chrome', '110.0'), app('EDR Agent', '9.1')], cut=True)
        v = self.violations()
        self.assertEqual(v['r-chrome']['found'], '110.0', 'below the minimum is below the minimum')
        self.assertEqual(v['r-banned']['found'], 'not known')

    def test_a_required_application_that_is_not_in_a_cut_list_is_a_violation_as_it_was_and_says_why(self):
        self.submit([app('Safari', '17.2'), app('Google Chrome', '120.1')], cut=True)
        v = self.violations()
        self.assertEqual(v['r-edr']['found'], 'missing')
        self.assertIn('cut', v['r-edr']['detail'])

    def test_only_the_boolean_true_says_a_list_is_cut(self):
        for junk in ('true', 'yes', 1, [True], {'a': 1}, None, 0, ''):
            with self.subTest(cut=junk):
                self.submit(GOOD, cut=junk)
                self.assertNotIn('cut', self.stored())
                self.assertEqual(self.violations(), {})

    def test_a_list_over_the_cap_of_the_server_is_cut_here_whatever_the_agent_says(self):
        rows = GOOD + [app('Filler %05d' % i) for i in range(si.MAX_PACKAGES + 10)]
        self.submit(rows)
        self.assertEqual(self.stored()['count'], si.MAX_PACKAGES)
        self.assertIs(self.stored().get('cut'), True)
        self.assertEqual(sorted(self.violations()), ['r-banned'], 'TeamViewer is not in what the server kept, and Chrome and the EDR agent sorted into it')

    def test_a_list_that_is_whole_again_clears_what_the_cut_list_said_and_the_operator_is_told(self):
        self.submit([app('Safari', '17.2'), app('EDR Agent', '9.1')], cut=True)
        self.assertEqual(sorted(self.violations()), ['r-banned', 'r-chrome'])
        self.fired.clear()
        self.submit(GOOD)
        self.assertEqual(self.violations(), {})
        self.assertNotIn('cut', self.stored())
        cleared = sorted(p['rule'] for e, p in self.fired if e == 'policy_compliant')
        self.assertEqual(cleared, ['r-banned', 'r-chrome'])

    def test_a_cut_list_that_arrives_again_is_not_a_new_violation_and_a_new_one_alerts_once(self):
        self.submit([app('Safari', '17.2'), app('EDR Agent', '9.1')], cut=True)
        told = sorted(p['rule'] for e, p in self.fired if e == 'software_policy_violation')
        self.assertEqual(told, ['r-banned', 'r-chrome'])
        self.fired.clear()
        self.submit([app('Safari', '17.3'), app('EDR Agent', '9.1')], cut=True)
        self.assertEqual([e for e, _p in self.fired if e == 'software_policy_violation'], [], 'the same two, still undecided')

    def test_the_rules_are_judged_again_with_the_mark_after_the_policy_is_edited(self):
        self.submit([app('Safari', '17.2'), app('EDR Agent', '9.1')], cut=True)
        api.save(api.SOFTWARE_POLICY_FILE, {'rules': [{'type': 'banned', 'package': 'Zoom', 'id': 'r-zoom'}]})
        api._LOAD_CACHE.clear()
        self.assertEqual(api._reeval_software_policy_all(), 1)
        v = self.violations()
        self.assertEqual(list(v), ['r-zoom'])
        self.assertEqual(v['r-zoom']['found'], 'not known', 'the stored record still says the list is cut')

    def test_a_min_version_rule_with_no_version_is_no_rule_and_says_nothing_about_a_cut_list(self):
        api.save(api.SOFTWARE_POLICY_FILE, {'rules': [{'type': 'min_version', 'package': 'Google Chrome', 'id': 'r-nov'}]})
        api._LOAD_CACHE.clear()
        self.submit([app('Safari', '17.2')], cut=True)
        self.assertEqual(self.violations(), {})

    def test_a_linux_list_takes_no_cut_from_its_body(self):
        api.save(api.SOFTWARE_POLICY_FILE, {'rules': [{'type': 'banned', 'package': 'telnet', 'id': 'r-telnet'}]})
        api._LOAD_CACHE.clear()
        self.submit([{'name': 'bash', 'version': '5.2', 'arch': 'amd64'}], cut=True, manager='apt')
        self.assertNotIn('cut', self.stored())
        self.assertEqual(self.violations(), {}, 'a package of a distribution is judged as it always was')


class TestAnApplicationOnlyAnAccountHoldsDoesNotMeetARequiredRule(Server):
    def test_a_required_application_that_only_an_account_folder_holds_is_missing(self):
        self.submit([app('Safari', '17.2'), app('Google Chrome', '120.1'), app('EDR Agent', '9.9', user=True)])
        v = self.violations()
        self.assertEqual(sorted(v), ['r-edr'])
        self.assertEqual(v['r-edr']['found'], 'missing')

    def test_a_required_application_the_system_holds_too_is_met(self):
        self.submit([app('Safari', '17.2'), app('Google Chrome', '120.1'), app('EDR Agent', '9.9', user=True), app('EDR Agent', '9.1')])
        self.assertEqual(self.violations(), {})

    def test_a_banned_application_is_found_in_an_accounts_folder_too(self):
        self.submit(GOOD + [app('TeamViewer', '15.50', user=True)])
        self.assertEqual(sorted(self.violations()), ['r-banned'])

    def test_the_minimum_version_is_judged_on_the_systems_copy_when_there_is_one(self):
        self.submit([app('Safari', '17.2'), app('EDR Agent', '9.1'), app('Google Chrome', '110.0'), app('Google Chrome', '130.0', user=True)])
        v = self.violations()
        self.assertEqual(sorted(v), ['r-chrome'])
        self.assertEqual(v['r-chrome']['found'], '110.0', 'a newer copy in a folder a person writes does not stand in for the system\'s old one')

    def test_an_application_only_an_account_holds_is_still_judged_for_its_version(self):
        self.submit([app('Safari', '17.2'), app('EDR Agent', '9.1'), app('Google Chrome', '110.0', user=True)])
        self.assertEqual(self.violations()['r-chrome']['found'], '110.0')
        self.submit([app('Safari', '17.2'), app('EDR Agent', '9.1'), app('Google Chrome', '130.0', user=True)])
        self.assertNotIn('r-chrome', self.violations(), 'it is the only copy and it is new enough')

    def test_the_mark_is_kept_in_the_stored_rows_and_only_as_the_boolean_true_and_only_on_a_mac_application(self):
        self.submit([app('Mine', user=True), dict(app('String'), in_user_folder='true'), dict(app('Brew'), manager='brew', in_user_folder=True),
                     dict(app('Number'), in_user_folder=1)])
        got = {r['name']: r for r in self.stored()['packages']}
        self.assertIs(got['Mine'].get('in_user_folder'), True)
        for name in ('String', 'Brew', 'Number'):
            self.assertNotIn('in_user_folder', got[name], name)
        self.submit([{'name': 'Tool', 'version': '1', 'manager': 'windows', 'in_user_folder': True}], manager='windows')
        self.assertNotIn('in_user_folder', self.stored()['packages'][0], 'a Windows list has no such folder')

    def test_the_mark_is_a_field_the_readers_of_the_store_may_hold(self):
        self.assertTrue(si.in_account_folder({'name': 'x', 'in_user_folder': True}))
        for value in (False, None, 'true', 1, [], {}):
            self.assertFalse(si.in_account_folder({'name': 'x', 'in_user_folder': value}))
        self.assertFalse(si.in_account_folder('not a row'))
        self.assertFalse(si.in_account_folder(None))
        self.assertIs(si.clean_cut(True), True)
        self.assertFalse(si.clean_cut('true'))
        self.assertFalse(si.clean_cut(1))


class TestTheMacAgentIntoTheHandler(Server):
    """The scene of the review: a standard user fills their own Applications folder with decoys that sort before every real application and adds a bundle named like
    the product the fleet requires. The real agent walks a scratch tree and the real handler judges what it sent."""

    def bundle(self, folder, folder_name, display, version='1.0'):
        d = Path(folder) / (folder_name + '.app') / 'Contents'
        d.mkdir(parents=True, exist_ok=True)
        (d / 'Info.plist').write_bytes(plistlib.dumps({'CFBundleDisplayName': display, 'CFBundleShortVersionString': version,
                                                      'CFBundleIdentifier': 'com.example.' + folder_name.replace(' ', '')}))

    def agent_sends(self, forged, decoys=40):
        root = Path(tempfile.mkdtemp(prefix='rp-listcut-mac-'))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        system, user = root / 'Applications', root / 'Users' / 'bob' / 'Applications'
        system.mkdir(parents=True)
        user.mkdir(parents=True)
        self.bundle(system, 'Safari', 'Safari', '17.1')
        self.bundle(system, 'Chrome', 'Google Chrome', '121.0')
        self.bundle(system, 'TeamViewer', 'TeamViewer', '15.50')
        if forged:
            for i in range(decoys):
                self.bundle(user, 'decoy%04d' % i, '0 decoy %04d' % i)
            self.bundle(user, 'EDR Agent', 'EDR Agent', '9.9')
        sent = []
        tmp = root / 'agentdata'
        tmp.mkdir()
        with mock.patch.object(mac, '_application_folders', lambda: [str(system), str(user)]), \
                mock.patch.object(mac, 'collect_brew_packages', lambda: []), \
                mock.patch.object(mac, '_post_json', lambda url, payload, timeout=0: sent.append(payload) or {}), \
                mock.patch.object(mac, '_data_dir', lambda: str(tmp)), \
                mock.patch.object(mac, 'MAX_INVENTORY_SEND', 30):
            self.assertTrue(mac.send_package_list({'device_id': 'x', 'token': 't', 'server_url': 'https://srv.invalid'}, force=True))
        return sent[0]

    def test_the_forged_host_is_judged_as_the_honest_one_is(self):
        honest = self.agent_sends(forged=False)
        self.assertNotIn('cut', honest)
        self.submit(honest['packages'], cut=honest.get('cut'))
        before = sorted(self.violations())
        self.assertEqual(before, ['r-banned', 'r-edr'], 'TeamViewer is installed and there is no EDR agent')
        forged = self.agent_sends(forged=True)
        self.assertIs(forged['cut'], True, 'the agent had 43 rows and a report that holds 30')
        names = [p['name'] for p in forged['packages']]
        self.assertIn('TeamViewer', names, 'the rows of the system are kept before an account\'s')
        self.assertIn('Safari', names)
        self.submit(forged['packages'], cut=forged.get('cut'))
        self.assertEqual(sorted(self.violations()), before, 'the decoys and the bundle named like the required product change nothing')

    def test_a_list_cut_so_far_that_the_ban_cannot_be_judged_is_a_violation_and_not_a_pass(self):
        # more rows of the system than a report holds: nothing a person does in their own folder is needed for this
        rows = [app('System App %04d' % i) for i in range(30)]
        self.submit(rows, cut=True)
        v = self.violations()
        self.assertEqual(v['r-banned']['found'], 'not known')


if __name__ == '__main__':
    unittest.main()

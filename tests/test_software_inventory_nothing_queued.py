#!/usr/bin/env python3
"""A request that queues nothing is an error that says why, not a success that says "queued on 0 hosts".

Install, uninstall and hold are shell scripts for apt, dnf, yum, zypper, pacman and apk. Since the Windows and macOS agents send
their applications, those hosts are on the pages that offer the buttons, and the server refuses to queue the script for them
("unsupported" per host). It still answered 202 {ok: true, queued: 0}, and the four page functions that call it printed
"Install queued for htop on 0 hosts" in the colour of a success and closed the dialog. The comment that justified the refusal
says the point is to avoid "an error nobody reads, after a success toast".

The server now answers 400 when nothing went anywhere and nothing waits for approval, with one of two fixed sentences (each a key of
the dictionary, in six languages) and the reasons per host. The page functions are held under node with the real answers, and the
job list prints a sentence for a host that was skipped.
"""
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / 'server' / 'cgi-bin'
_JS = ROOT / 'server' / 'html' / 'static' / 'js'
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(Path(__file__).resolve().parent))
_TMP = []


def _tmp(prefix):
    d = tempfile.mkdtemp(prefix=prefix)
    _TMP.append(d)
    return d


os.environ.setdefault('RP_DATA_DIR', _tmp('rp-nothingq-'))
_spec = importlib.util.spec_from_file_location('api_nothing_queued', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import srcpin  # noqa: E402
from i18n_engine import LANGS, dict_rows, unchanged_by_engine  # noqa: E402

_APP = (_JS / 'app.js').read_text(encoding='utf-8')
_PAGE = (_JS / 'app-compliance.js').read_text(encoding='utf-8')


def tearDownModule():
    for d in _TMP:
        shutil.rmtree(d, ignore_errors=True)


ONLY_LINUX = 'Install, uninstall and hold run on Linux hosts only. Nothing was queued.'
NO_HOST = 'No host accepted the command, so nothing was queued. Rollouts → Recent jobs lists the reason for each host.'
SKIPPED = 'Skipped: not a Linux host'
WIN, MAC, LNX, LNXQ = 'nqwin', 'nqmac', 'nqlinux', 'nqlinuxq'
HANDLERS = (('install', 'handle_install_packages'), ('uninstall', 'handle_uninstall_packages'),
            ('hold', 'handle_hold_packages'), ('unhold', 'handle_unhold_packages'))


class _Captured(Exception):
    def __init__(self, status, body):
        super().__init__(status)
        self.status, self.body = status, body


def _device(name, os_name, **extra):
    return dict({'id': name, 'name': name, 'tenant': 'default', 'os': os_name, 'token': 'tok-' + name, 'monitored': True,
                 'group': '', 'tags': [], 'last_seen': 2_000_000_000}, **extra)


class _Fleet(unittest.TestCase):
    def setUp(self):
        def respond(status, data=None, headers=None):
            raise _Captured(status, data)
        self._patches = [mock.patch.object(api, 'respond', respond), mock.patch.object(api, 'audit_log', lambda *a, **k: None),
                         mock.patch.object(api, 'fire_webhook', lambda *a, **k: None),
                         mock.patch.object(api, 'log_command', lambda *a, **k: None),
                         mock.patch.object(api, 'get_token_from_request', lambda: 'x')]
        for p in self._patches:
            p.start()
        self.addCleanup(self._stop)
        api.save(api.CONFIG_FILE, {})
        api.save(api.TENANTS_FILE, {})
        api.save(api.USERS_FILE, {'root': {'tenant_id': 'default', 'role': 'admin'}})
        api.save(api.DEVICES_FILE, {
            WIN: _device(WIN, 'Windows 11 (Build 22631)'), MAC: _device(MAC, 'macOS 14.5 (23F79)'),
            LNX: _device(LNX, 'Ubuntu 22.04'), LNXQ: _device(LNXQ, 'Ubuntu 22.04', quarantined=True)})
        for store in (api.CMDS_FILE, api.BATCH_JOBS_FILE):
            api.save(store, {})
        api._LOAD_CACHE.clear()

    def _stop(self):
        for p in reversed(self._patches):
            p.stop()
        for store in (api.DEVICES_FILE, api.CMDS_FILE, api.BATCH_JOBS_FILE, api.CONFIG_FILE, api.USERS_FILE, api.TENANTS_FILE):
            api.save(store, {})
        api._LOAD_CACHE.clear()

    def post(self, handler, device_ids, packages='htop', user=('root', 'admin')):
        api._LOAD_CACHE.clear()
        with mock.patch.object(api, 'method', lambda: 'POST'), \
                mock.patch.object(api, 'get_json_obj', lambda: {'device_ids': device_ids, 'packages': packages}), \
                mock.patch.object(api, 'verify_token', lambda tok=None: user):
            try:
                getattr(api, handler)()
            except _Captured as c:
                api._LOAD_CACHE.clear()
                return c.status, c.body
        self.fail('the handler did not answer')

    def queue(self):
        api._LOAD_CACHE.clear()
        return {d: q for d, q in (api.load(api.CMDS_FILE) or {}).items() if q}


class TestTheServerAnswer(_Fleet):
    def test_targets_that_are_all_windows_or_mac_hosts_are_refused_with_the_reason(self):
        for kind, handler in HANDLERS:
            status, answer = self.post(handler, [WIN, MAC])
            self.assertEqual(status, 400, (kind, answer))
            self.assertIs(answer['ok'], False)
            self.assertEqual(answer['error'], ONLY_LINUX)
            self.assertEqual((answer['queued'], answer['total'], answer['parked']), (0, 2, 0))
            self.assertEqual(answer['skipped'], [MAC, WIN])
            self.assertEqual({d: p['reason'] for d, p in answer['per_device'].items()}, {WIN: 'unsupported', MAC: 'unsupported'})
            self.assertEqual(self.queue(), {}, 'nothing was put in any queue')
            # the record of the attempt stays: the job lists both hosts as skipped
            api._LOAD_CACHE.clear()
            job = api.load(api.BATCH_JOBS_FILE)['jobs'][answer['job_id']]
            self.assertEqual(job['kind'], kind)
            self.assertEqual(sorted(job['per_device']), [MAC, WIN])
            self.assertEqual(job['targets'], [])

    def test_a_request_that_no_host_accepts_for_another_reason_says_so(self):
        status, answer = self.post('handle_install_packages', [LNXQ])
        self.assertEqual(status, 400, answer)
        self.assertEqual(answer['error'], NO_HOST)
        self.assertEqual(answer['per_device'][LNXQ]['reason'], 'quarantined')
        self.assertEqual((answer['queued'], answer['skipped']), (0, []))
        self.assertEqual(self.queue(), {})

    def test_an_unsupported_host_and_one_that_refuses_for_another_reason_give_the_general_sentence(self):
        status, answer = self.post('handle_install_packages', [WIN, LNXQ])
        self.assertEqual(status, 400, answer)
        self.assertEqual(answer['error'], NO_HOST)
        self.assertEqual({d: p['reason'] for d, p in answer['per_device'].items()}, {WIN: 'unsupported', LNXQ: 'quarantined'})
        self.assertEqual(answer['skipped'], [WIN])

    def test_a_host_that_does_not_exist_is_a_refusal_too(self):
        status, answer = self.post('handle_install_packages', ['nqnosuchhost'])
        self.assertEqual(status, 400, answer)
        self.assertEqual(answer['per_device']['nqnosuchhost']['reason'], 'not_found')
        self.assertEqual(answer['error'], NO_HOST)

    def test_a_request_with_one_linux_host_in_it_is_still_accepted(self):
        """The control: the refusal is for nothing queued, and a mixed request keeps queueing what it can."""
        for kind, handler in HANDLERS:
            api.save(api.CMDS_FILE, {})
            status, answer = self.post(handler, [WIN, MAC, LNX])
            self.assertEqual(status, 202, (kind, answer))
            self.assertIs(answer['ok'], True)
            self.assertEqual((answer['queued'], answer['total']), (1, 3))
            self.assertEqual(sorted(self.queue()), [LNX])
            self.assertEqual(answer['per_device'][WIN]['reason'], 'unsupported')
            self.assertNotIn('error', answer)

    def test_a_request_parked_for_approval_is_not_refused(self):
        """Nothing is queued yet and the answer is still a success: a second administrator can approve it."""
        def parked(ids, command, actor, **kw):
            return {i: {'approval_required': True, 'confirmation_id': 'c-' + i} for i in ids}
        with mock.patch.object(api, '_queue_command_batch', parked):
            status, answer = self.post('handle_uninstall_packages', [LNX])
        self.assertEqual(status, 202, answer)
        self.assertIs(answer['ok'], True)
        self.assertEqual((answer['queued'], answer['parked'], answer['approval_required']), (0, 1, True))

    def test_the_two_sentences_are_in_the_dictionary_in_six_languages_and_the_engine_translates_them(self):
        rows = dict_rows()
        for text in (ONLY_LINUX, NO_HOST, SKIPPED):
            self.assertEqual(sorted(rows.get(text, ())), sorted(LANGS), text)
        unchanged = unchanged_by_engine([ONLY_LINUX, NO_HOST, SKIPPED])
        if unchanged is not None:
            self.assertEqual({lang: s for lang, s in unchanged.items() if s}, {})


class TestTheCallers(_Fleet):
    """The answer names the hosts that were skipped, so it is read as each kind of caller: a tenant administrator sees the hosts of
    its own tenant and no others, and a read-only user is refused before anything is recorded."""

    def setUp(self):
        super().setUp()
        api.save(api.CONFIG_FILE, {'tenancy_enforced': True})
        api.save(api.TENANTS_FILE, {'tenantA': {'name': 'Tenant A', 'status': 'active'},
                                    'tenantB': {'name': 'Tenant B', 'status': 'active'}})
        api.save(api.USERS_FILE, {'alice': {'tenant_id': 'tenantA', 'role': 'admin'},
                                  'carol': {'tenant_id': 'tenantA', 'role': 'viewer'},
                                  'root': {'tenant_id': 'default', 'role': 'admin'}})
        api.save(api.DEVICES_FILE, {
            WIN: _device(WIN, 'Windows 11 (Build 22631)', tenant='tenantA'),
            LNX: _device(LNX, 'Ubuntu 22.04', tenant='tenantA'),
            MAC: _device(MAC, 'macOS 14.5 (23F79)', tenant='tenantB')})
        api._LOAD_CACHE.clear()

    def test_a_tenant_administrator_is_told_about_its_own_hosts_only(self):
        status, answer = self.post('handle_install_packages', [WIN, MAC], user=('alice', 'admin'))
        self.assertEqual(status, 400, answer)
        self.assertEqual(answer['error'], ONLY_LINUX)
        self.assertEqual(answer['skipped'], [WIN])
        self.assertEqual(sorted(answer['per_device']), [WIN])
        self.assertNotIn(MAC, json.dumps(answer))                   # the other tenant's host is in no field of the answer

    def test_a_tenant_administrator_cannot_name_a_host_of_another_tenant_at_all(self):
        status, answer = self.post('handle_install_packages', [MAC], user=('alice', 'admin'))
        self.assertEqual(status, 400, answer)
        self.assertEqual(answer, {'error': 'No valid host targets'})
        self.assertEqual(self.queue(), {})
        api._LOAD_CACHE.clear()
        self.assertEqual((api.load(api.BATCH_JOBS_FILE) or {}).get('jobs') or {}, {})

    def test_a_read_only_user_is_refused_and_nothing_is_recorded(self):
        for handler in ('handle_install_packages', 'handle_uninstall_packages', 'handle_hold_packages'):
            status, answer = self.post(handler, [WIN], user=('carol', 'viewer'))
            self.assertEqual(status, 403, (handler, answer))
            self.assertNotIn('per_device', answer)
        self.assertEqual(self.queue(), {})
        api._LOAD_CACHE.clear()
        self.assertEqual((api.load(api.BATCH_JOBS_FILE) or {}).get('jobs') or {}, {})


# ── the pages, under node, with the real answers ─────────────────────────────────────────────────────────────────────────
def _fn(source, name):
    body = srcpin.js_function(source, name)
    return ('async ' if re.search(r'^async function ' + re.escape(name) + r'\(', source, re.M) else '') + body


def _node(script):
    r = subprocess.run(['node', '-e', script], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def _run(call, answer, announced=False, confirm=True):
    """Run one page function with the answer the server gave. `announced` is what api() does on a failed request: it has
    already toasted the reason and leaves a mark, which failToast reads so that the reason is not said twice."""
    script = '\n'.join([
        re.search(r'^function escHtml\(.*$', _APP, re.M).group(0),
        re.search(r'^function plural\(.*?^}', _APP, re.M | re.S).group(0),
        srcpin.js_function(_APP, 'parkedForApproval'),
        srcpin.js_function(_APP, 'failText'),
        srcpin.js_function(_APP, 'failToast'),
        _fn(_PAGE, 'runInstall'), _fn(_PAGE, 'runUninstall'), _fn(_PAGE, '_runHold'), _fn(_PAGE, 'runOneTimeInstall'),
        '''
const out = {toasts: [], closed: [], jobs: 0, asked: []};
let _apiFailureShown = {};
let _apiSignedOutAt = 0;
const _batchExpanded = new Set();
const vals = {'install-pkgs': 'htop', 'install-target-type': 'device', 'install-target-value': 'x',
              'oti-pkgs': 'htop', 'oti-target-type': 'device', 'oti-device': 'x'};
const document = {getElementById: id => ({value: vals[id] || ''})};
const toast = (m, kind) => out.toasts.push([kind, m]);
const uiConfirm = async () => %s;
const _fleetTargetBody = async () => ({device_ids: ['x']});
const closeModal = id => out.closed.push(id);
const loadBatchJobs = () => { out.jobs += 1; };
const answer = %s;
const api = async (method, path) => { out.asked.push(method + ' ' + path); if (%s) _apiFailureShown = {body: answer, at: Date.now()}; return answer; };
%s.then(() => console.log(JSON.stringify(out)));
''' % ('true' if confirm else 'false', json.dumps(answer), 'true' if announced else 'false', call)])
    return _node(script)


REFUSED = {'ok': False, 'error': ONLY_LINUX, 'queued': 0, 'total': 1, 'parked': 0, 'approval_required': False,
           'packages': ['htop'], 'job_id': 'abc', 'skipped': ['nqwin'],
           'per_device': {'nqwin': {'queued': False, 'reason': 'unsupported', 'name': 'nqwin'}}}
ACCEPTED = {'ok': True, 'queued': 1, 'total': 1, 'parked': 0, 'approval_required': False, 'packages': ['htop'], 'job_id': 'abc',
            'per_device': {'nqlinux': {'queued': True, 'name': 'nqlinux'}}}
CALLS = {'install': 'runInstall()', 'uninstall': 'runUninstall()', 'hold': '_runHold(true)', 'unhold': '_runHold(false)',
         'one-time install': 'runOneTimeInstall()'}


class TestThePages(unittest.TestCase):
    def test_a_refusal_is_an_error_and_never_a_success(self):
        for name, call in CALLS.items():
            out = _run(call, REFUSED)
            self.assertEqual(out['toasts'], [['error', ONLY_LINUX]], name)
            self.assertEqual(out['closed'], [], f'{name}: the dialog stays open so the person can change the target')
            self.assertEqual(out['jobs'], 0, name)

    def test_the_reason_is_said_once_when_the_request_helper_has_already_said_it(self):
        """api() toasts every failed request. A page that toasts the same reason again shows two."""
        for name, call in CALLS.items():
            self.assertEqual(_run(call, REFUSED, announced=True)['toasts'], [], name)

    def test_an_answer_that_queued_something_is_the_success_it_was(self):
        """The control of the two above: the same functions, the same stubs, an answer with one host queued."""
        for name, call in CALLS.items():
            out = _run(call, ACCEPTED)
            self.assertEqual([k for k, _ in out['toasts']], ['success'], name)
            self.assertIn('on 1 host', out['toasts'][0][1], name)
            self.assertNotIn('0 hosts', out['toasts'][0][1], name)
        out = _run('runOneTimeInstall()', ACCEPTED)
        self.assertEqual(out['closed'], ['one-time-install-modal'])
        self.assertEqual(out['jobs'], 1)

    def test_a_request_that_could_not_be_sent_says_the_server_did_not_answer(self):
        for name, call in CALLS.items():
            self.assertEqual(_run(call, None)['toasts'], [['error', 'The server did not answer.']], name)


class TestTheJobList(unittest.TestCase):
    def render(self, per_device):
        script = '\n'.join([
            re.search(r'^function escHtml\(.*$', _APP, re.M).group(0),
            srcpin.js_function(_APP, '_JOB_ICON') + ';',
            srcpin.js_function(_APP, '_JOB_REASON_TEXT') + ';',
            _fn(_APP, '_renderJobDetail'),
            '''
const out = {html: ''};
const box = {set innerHTML(v) { out.html = v; }};
const document = {getElementById: id => box};
let _batchDetailPrev = {};
const api = async () => ({per_device: %s});
_renderJobDetail('j1').then(() => console.log(JSON.stringify(out)));
''' % json.dumps(per_device)])
        return _node(script)['html']

    def test_a_host_that_was_skipped_for_its_os_has_a_sentence_and_not_the_code(self):
        html = self.render({'w': {'queued': False, 'reason': 'unsupported', 'name': 'win-host'},
                            'q': {'queued': False, 'reason': 'quarantined', 'name': 'quarantined-host'}})
        rows = re.findall(r'<div class="batch-host">.*?</div>', html)
        self.assertEqual(len(rows), 2)
        self.assertIn('win-host', rows[0])
        self.assertIn('>' + SKIPPED + '<', rows[0])
        self.assertNotIn('unsupported', rows[0])
        self.assertIn('(quarantined)', rows[1])              # the other codes are shown as they come
        self.assertNotIn(SKIPPED, rows[1])

    def test_a_reason_that_is_the_name_of_something_on_every_object_is_text_and_not_a_function(self):
        html = self.render({'a': {'queued': False, 'reason': 'constructor', 'name': 'h1'},
                            'b': {'queued': False, 'reason': '__proto__', 'name': 'h2'},
                            'c': {'queued': False, 'name': 'h3'}})
        self.assertIn('(constructor)', html)
        self.assertIn('(__proto__)', html)
        self.assertIn('(skipped)', html)
        self.assertNotIn('function', html)
        self.assertNotIn('[object', html)

    def test_the_text_of_a_reason_and_of_a_host_is_escaped(self):
        html = self.render({'a': {'queued': False, 'reason': '<img src=x onerror=alert(1)>', 'name': '<b>x</b>'}})
        self.assertNotIn('<img', html)
        self.assertNotIn('<b>', html)


if __name__ == '__main__':
    unittest.main()

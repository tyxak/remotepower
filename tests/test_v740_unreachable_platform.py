"""A platform that cannot be reached says so, in words, and the page does not call it empty.

Found with the seeded stack: a vCenter whose host does not resolve answered
502 {"error": "URLError: <urlopen error [Errno -2] Name or service not known>"},
and the Virtualization page painted "No VMs.", as if the platform had answered
with none. (The public demo answers from canned snapshots in read-only mode, so
it never showed there; a real install whose vCenter is down did.)
"""
import importlib.util
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v740-unreach-'))

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import integrations  # noqa: E402
import srcpin  # noqa: E402

_spec = importlib.util.spec_from_file_location('api_v740_unreach', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_NODE = shutil.which('node')
_VC = {'id': 'abc123', 'type': 'vcenter', 'label': 'vCenter lab', 'url': 'https://vc.lab',
       'username': 'u', 'secret': 'p', 'verify_tls': True}


def _gai():
    return socket.gaierror(-2, 'Name or service not known')


class TestTheReasonInWords(unittest.TestCase):

    def test_each_kind_of_failure(self):
        d = integrations.describe_network_error
        cases = [
            (urllib.error.URLError(_gai()), 'the host name does not resolve'),
            (socket.gaierror(-3, 'Temporary failure in name resolution'), 'the host name does not resolve'),
            (urllib.error.URLError(ConnectionRefusedError(111, 'Connection refused')), 'the connection was refused'),
            (urllib.error.URLError(TimeoutError('timed out')), 'it did not answer in time'),
            (TimeoutError('The read operation timed out'), 'it did not answer in time'),
            (urllib.error.URLError(ssl.SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed')),
             'its certificate was not accepted'),
            (urllib.error.HTTPError('https://vc.lab/x', 503, 'Service Unavailable', {}, None), 'it answered HTTP 503'),
            (urllib.error.URLError(OSError(101, 'Network is unreachable')), 'the network is unreachable'),
            (ConnectionResetError(104, 'Connection reset by peer'), 'the connection was dropped'),
        ]
        for exc, want in cases:
            self.assertEqual(d(exc), want, repr(exc))

    def test_anything_else_keeps_its_message_and_never_its_class_name(self):
        self.assertEqual(integrations.describe_network_error(ValueError('odd reply')), 'odd reply')
        self.assertEqual(integrations.describe_network_error(urllib.error.URLError('weird')), 'weird')
        self.assertEqual(integrations.describe_network_error(RuntimeError('')), 'the request failed')


class _Unreachable:
    """An integration client whose every call fails as a dead DNS name does,
    whichever method a driver uses (get_json, post_json, request, ...)."""

    def __getattr__(self, name):
        def fail(*a, **k):
            raise urllib.error.URLError(_gai())
        return fail


class TestTheHandlerSaysWhichAndWhy(unittest.TestCase):

    def setUp(self):
        self._saved = {}
        for name, fn in {'require_auth': lambda *a, **k: 'tester',
                         '_get_integrations': lambda *a, **k: [_VC],
                         '_integration_client': lambda *a, **k: _Unreachable()}.items():
            self._saved[name] = getattr(api, name)
            setattr(api, name, fn)

    def tearDown(self):
        for name, fn in self._saved.items():
            setattr(api, name, fn)

    def call(self, fn, *args):
        try:
            fn(*args)
        except api.HTTPError as e:
            return e.status, e.body
        self.fail('no response')

    def test_a_dead_host_is_a_502_naming_the_platform_and_the_reason(self):
        status, body = self.call(api.handle_virt_vms, 'abc123')
        self.assertEqual(status, 502)
        self.assertEqual(body['error'], 'Could not reach vCenter lab: the host name does not resolve')

    def test_the_dns_blockers_say_it_the_same_way(self):
        api._get_integrations = lambda *a, **k: [{'id': 'ph1', 'type': 'pihole', 'label': 'Pi-hole',
                                                  'url': 'http://pi.lab', 'secret': 'x'}]
        status, body = self.call(api.handle_dns_blocking_get, 'ph1')
        self.assertEqual((status, body['error']), (502, 'Could not reach Pi-hole: the host name does not resolve'))


@unittest.skipUnless(_NODE, 'node not installed')
class TestThePageShowsTheReason(unittest.TestCase):
    """The real loadVirtPlatform from app-virt.js, under node with stubs for the
    few globals it touches."""

    def run_page(self, answer):
        fn = srcpin.js_function((_ROOT / 'server/html/static/js/app-virt.js').read_text(), 'loadVirtPlatform')
        fn = fn if fn.startswith('async') else 'async ' + fn   # srcpin starts at `function`
        render = srcpin.js_function((_ROOT / 'server/html/static/js/app-virt.js').read_text(), '_renderVirtVmList')
        script = (
            'const els = {"virtualization-body": {innerHTML: ""}, "virtualization-node": {textContent: ""},\n'
            '             "virt-search": {value: ""}};\n'
            'const document = { getElementById: (id) => els[id] || null };\n'
            'const window = { _virtActive: {id: "abc123", type: "vcenter"} };\n'
            'const calls = [];\n'
            'async function api(m, p, b, extra) { calls.push([m, p, extra || null]); return %s; }\n'
            'function _skeletonBlock() { return "…"; }\n'
            'function escHtml(s) { return String(s); }\n'
            'function _renderVirtVm(v) { return "<row>" + v.name + "</row>"; }\n'
            '%s\n%s\n'
            '(async () => { await loadVirtPlatform("abc123");\n'
            '  process.stdout.write(JSON.stringify({html: els["virtualization-body"].innerHTML, calls})); })();\n'
        ) % (json.dumps(answer), render, fn)
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / 'run.js').write_text(script)
            p = subprocess.run([_NODE, 'run.js'], cwd=td, capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr[-1500:])
        return json.loads(p.stdout)

    def test_an_error_answer_is_shown_not_called_empty(self):
        out = self.run_page({'error': 'Could not reach vCenter lab: the host name does not resolve'})
        self.assertIn('Could not reach vCenter lab', out['html'])
        self.assertNotIn('No VMs', out['html'])

    def test_the_page_says_it_itself_so_the_generic_toast_stays_quiet(self):
        out = self.run_page({'error': 'x'})
        self.assertEqual(out['calls'][0][2], {'quiet': True})

    def test_control_an_empty_platform_is_still_empty(self):
        self.assertIn('No VMs', self.run_page({'ok': True, 'vms': []})['html'])
        self.assertIn('<row>web</row>', self.run_page({'ok': True, 'vms': [{'name': 'web', 'id': '1'}]})['html'])


if __name__ == '__main__':
    unittest.main()

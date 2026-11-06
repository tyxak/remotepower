#!/usr/bin/env python3
"""A call that fails over the network says why, in words, on every page that shows it.

`integrations.describe_network_error` has put a failure in words since 6.4.2, and 7.4.0 used it for the platform that
cannot be reached. It was applied in one place. Driving the seeded stack found the rest: the Virtualization page read
`URLError: <urlopen error [Errno -2] Name or service not known>`, the Live Monitor and Alerts read `error: URLError` for a monitor
that was down, a Pi-hole tile read `unknown` with both its buttons showing and a red toast for the 502 that outlived the page.

Why the older test passed: it handed `_virt_dispatch` a client that raised a bare URLError, and the real client never does.
`_SSRFIntegrationClient.request` turns every failure into an IntegrationError whose text was `URLError: <urlopen error ...>`, so
the branch the test covered was never the branch that ran. These tests use the real client and replace only the network.
"""
import importlib.util
import json
import os
import pathlib
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import unittest
import urllib.error

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-netfail-'))
_ROOT = pathlib.Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_JS = _ROOT / 'server' / 'html' / 'static' / 'js'
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import integrations  # noqa: E402
import srcpin  # noqa: E402

_spec = importlib.util.spec_from_file_location('api_netfail', _CGI / 'api.py')
assert _spec is not None and _spec.loader is not None
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_NODE = shutil.which('node')
_VC = {'id': 'abc123', 'type': 'vcenter', 'label': 'vCenter lab', 'url': 'https://vc.lab', 'username': 'u', 'secret': 'p', 'verify_tls': True}


def _gai():
    return socket.gaierror(-2, 'Name or service not known')


class TestTheReason(unittest.TestCase):

    def test_a_network_failure_has_a_reason(self):
        r = integrations.network_error_reason
        self.assertEqual(r(urllib.error.URLError(_gai())), 'the host name does not resolve')
        self.assertEqual(r(urllib.error.URLError(ConnectionRefusedError(111, 'refused'))), 'the connection was refused')
        self.assertEqual(r(TimeoutError('timed out')), 'it did not answer in time')
        self.assertEqual(r(urllib.error.URLError(ssl.SSLCertVerificationError(1, 'certificate verify failed'))), 'its certificate was not accepted')
        self.assertEqual(r(urllib.error.URLError(OSError(101, 'Network is unreachable'))), 'the network is unreachable')

    def test_anything_else_has_none_so_the_caller_keeps_its_own_words(self):
        for e in (ValueError('odd reply'), KeyError('x'), RuntimeError('boom'), urllib.error.URLError('weird')):
            self.assertIsNone(integrations.network_error_reason(e), repr(e))

    def test_describe_is_unchanged_for_what_it_always_covered(self):
        self.assertEqual(integrations.describe_network_error(ValueError('odd reply')), 'odd reply')
        self.assertEqual(integrations.describe_network_error(RuntimeError('')), 'the request failed')
        self.assertEqual(integrations.describe_network_error(urllib.error.URLError(_gai())), 'the host name does not resolve')

    def test_explain_failure_puts_a_network_failure_in_words_and_leaves_a_message_alone(self):
        self.assertEqual(integrations.explain_failure(urllib.error.URLError(_gai())), 'the host name does not resolve')
        self.assertEqual(integrations.explain_failure(ValueError('Cloudflare: invalid token')), 'Cloudflare: invalid token')
        self.assertEqual(len(integrations.explain_failure(ValueError('x' * 500))), 200)
        self.assertEqual(len(integrations.explain_failure(ValueError('x' * 500), 50)), 50)


class _FailingOpener:
    """What `_ssrf_safe_opener` returns, with only the network replaced: it raises what urllib raises."""

    def __init__(self, exc):
        self.exc = exc

    def add_handler(self, handler):
        pass

    def open(self, req, timeout=None):
        raise self.exc


class _RealClientFailing(unittest.TestCase):
    """The real _SSRFIntegrationClient, the real handlers, and a network that fails."""

    EXC = urllib.error.URLError(_gai())

    def setUp(self):
        self._saved = {}
        for name, fn in {'require_auth': lambda *a, **k: 'tester',
                         '_get_integrations': lambda *a, **k: [_VC],
                         '_url_targets_local_or_meta': lambda *a, **k: False,
                         '_ssrf_safe_opener': lambda **k: _FailingOpener(self.EXC)}.items():
            self._saved[name] = getattr(api, name)
            setattr(api, name, fn)
        self.addCleanup(self._restore)

    def _restore(self):
        for name, fn in self._saved.items():
            setattr(api, name, fn)

    def call(self, fn, *args):
        try:
            fn(*args)
        except api.HTTPError as e:
            return e.status, e.body
        self.fail('no response')


class TestTheIntegrationClientAndTheVirtualizationPage(_RealClientFailing):

    def test_the_client_names_the_host_and_the_reason(self):
        client = api._SSRFIntegrationClient('https://vc.lab', verify_tls=True, timeout=1)
        with self.assertRaises(integrations.IntegrationError) as cm:
            client.request('GET', '/api/x')
        self.assertEqual(str(cm.exception), 'Could not reach vc.lab: the host name does not resolve')

    def test_each_kind_of_failure_through_the_client(self):
        for exc, want in ((urllib.error.URLError(ConnectionRefusedError(111, 'refused')), 'the connection was refused'),
                          (TimeoutError('timed out'), 'it did not answer in time'),
                          (urllib.error.URLError(ssl.SSLCertVerificationError(1, 'certificate verify failed')), 'its certificate was not accepted')):
            with self.subTest(want=want):
                type(self).EXC = exc
                self.addCleanup(setattr, type(self), 'EXC', urllib.error.URLError(_gai()))
                client = api._SSRFIntegrationClient('https://vc.lab:8443', verify_tls=True, timeout=1)
                with self.assertRaises(integrations.IntegrationError) as cm:
                    client.request('GET', '/api/x')
                self.assertEqual(str(cm.exception), 'Could not reach vc.lab:8443: ' + want)

    def test_an_exception_that_is_not_a_network_failure_keeps_its_class_and_text(self):
        type(self).EXC = RuntimeError('boom')
        self.addCleanup(setattr, type(self), 'EXC', urllib.error.URLError(_gai()))
        client = api._SSRFIntegrationClient('https://vc.lab', verify_tls=True, timeout=1)
        with self.assertRaises(integrations.IntegrationError) as cm:
            client.request('GET', '/api/x')
        self.assertEqual(str(cm.exception), 'RuntimeError: boom')

    def test_the_virtualization_handler_answers_with_the_words_not_the_exception(self):
        status, body = self.call(api.handle_virt_vms, 'abc123')
        self.assertEqual(status, 502)
        self.assertEqual(body['error'], 'Could not reach vc.lab: the host name does not resolve')
        self.assertNotIn('URLError', body['error'])
        self.assertNotIn('urlopen', body['error'])


class TestTheMonitorDetail(_RealClientFailing):

    def _probe(self, exc, **monitor):
        type(self).EXC = exc
        self.addCleanup(setattr, type(self), 'EXC', urllib.error.URLError(_gai()))
        return api._run_one_monitor_check('http', 'http://nginx.lab/', 't', dict(monitor))

    def test_a_dead_name_a_refusal_and_a_timeout_read_differently(self):
        self.assertEqual(self._probe(urllib.error.URLError(_gai()))['detail'], 'error: the host name does not resolve')
        self.assertEqual(self._probe(urllib.error.URLError(ConnectionRefusedError(111, 'x')))['detail'], 'error: the connection was refused')
        self.assertEqual(self._probe(urllib.error.URLError(TimeoutError('timed out')))['detail'], 'error: it did not answer in time')

    def test_an_exception_that_is_not_a_network_failure_keeps_the_class_name(self):
        self.assertEqual(self._probe(RuntimeError('boom'))['detail'], 'error: RuntimeError')


@unittest.skipUnless(_NODE, 'node not installed')
class TestTheBlockerTile(unittest.TestCase):
    """The real _dnsControlRow of app.js, under node with a small fake DOM."""

    def _run(self, answer, last_poll='unknown'):
        app = (_JS / 'app.js').read_text(encoding='utf-8')
        fn = srcpin.js_function(app, '_dnsControlRow')
        script = '''
class El {
  constructor(tag) { this.tag = tag; this.children = []; this.className = ''; this.textContent = ''; this.title = ''; this.value = '';
    this.disabled = false; this.attrs = {}; this.listeners = {};
    const cls = new Set(); this._cls = cls;
    this.classList = { add: (c) => cls.add(c), remove: (c) => cls.delete(c), toggle: (c, on) => { if (on === undefined ? !cls.has(c) : on) cls.add(c); else cls.delete(c); }, contains: (c) => cls.has(c) }; }
  setAttribute(k, v) { this.attrs[k] = v; }
  appendChild(c) { this.children.push(c); return c; }
  addEventListener(t, f) { this.listeners[t] = f; }
}
const document = { createElement: (t) => new El(t) };
function Option(label, value) { const o = new El('option'); o.textContent = label; o.value = value; return o; }
globalThis.Option = Option;
const _meCache = { admin: true };
const calls = [];
async function api(m, p, b, extra) { calls.push({m, p, extra: extra || null}); return %s; }
%s
const _DNS_WINDOWS = [[300, '5 minutes'], [900, '15 minutes']];
(async () => {
  const row = _dnsControlRow({id: 'ph1', label: 'Pi-hole', type: 'pihole', status: %s}, {max_seconds: 900, default_seconds: 300});
  await new Promise(r => setTimeout(r, 20));
  const [state, sel, off, on, checkNow] = row.children;
  process.stdout.write(JSON.stringify({calls, state: state.textContent, stateClass: state.className,
    hidden: {sel: sel._cls.has('hidden'), off: off._cls.has('hidden'), on: on._cls.has('hidden'), checkNow: checkNow._cls.has('hidden')}}));
})();
''' % (json.dumps(answer), fn if fn.startswith('async') else fn, json.dumps(last_poll))
        script = script.replace('const _DNS_WINDOWS = [[300', 'var _DNS_WINDOWS = [[300')
        with tempfile.TemporaryDirectory() as td:
            (pathlib.Path(td) / 'run.js').write_text('var _DNS_WINDOWS = [[300, "5 minutes"], [900, "15 minutes"]];\n' + script.replace("const _DNS_WINDOWS = [[300, '5 minutes'], [900, '15 minutes']];", ''))
            p = subprocess.run([str(_NODE), 'run.js'], cwd=td, capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr[-1500:])
        return json.loads(p.stdout)

    def test_a_blocker_that_does_not_answer_shows_why_and_offers_nothing_it_cannot_do(self):
        r = self._run({'error': 'Could not reach pi.lab: the host name does not resolve'})
        self.assertEqual(r['state'], 'Could not reach pi.lab: the host name does not resolve')
        self.assertEqual(r['hidden'], {'sel': True, 'off': True, 'on': True, 'checkNow': False})
        self.assertTrue(r['calls'][0]['extra'] and r['calls'][0]['extra']['quiet'], 'the probe is quiet: its 502 is the answer, not a failure to announce')

    def test_an_answer_without_a_reason_still_reads_unknown(self):
        self.assertEqual(self._run(None)['state'], 'unknown')

    def test_a_blocker_that_answers_is_painted_as_before(self):
        r = self._run({'ok': True, 'blocking': True})
        self.assertEqual(r['state'], 'Blocking on')
        self.assertTrue(r['hidden']['on'] and not r['hidden']['off'])

    def test_no_probe_is_sent_when_the_last_poll_said_down(self):
        r = self._run({'ok': True, 'blocking': True}, last_poll='critical')
        self.assertEqual(r['calls'], [])


class TestTheOtherWrappersUseIt(unittest.TestCase):
    """The client modules that wrapped a network failure in their own error with the raw text."""

    def test_each_wrapper_asks_for_the_reason_first(self):
        for name, token in (('dns_zones.py', 'raise DNSError((integrations.network_error_reason(e)'),
                            ('proxmox_client.py', 'integrations.network_error_reason(e) or reason'),
                            ('proxmox_client.py', 'integrations.network_error_reason(e) or e'),
                            ('opnsense.py', 'OPNsenseError(integrations.network_error_reason(e) or str(e))'),
                            ('routeros.py', 'RouterOSError(integrations.network_error_reason(e) or str(e))')):
            self.assertIn(token, (_CGI / name).read_text(encoding='utf-8'), name)


_GENERIC_502 = re.compile(r"respond\(502, \{'error': .*\bstr\(e\)")


def raw_exception_502s(src):
    """Lines that answer a 502 with str(e) of an exception caught as plain `Exception` (or nothing narrower)."""
    lines = src.split('\n')
    out = []
    for i, line in enumerate(lines):
        if not _GENERIC_502.search(line) or 'network_error_reason(' in line or 'explain_failure(' in line:
            continue
        j = i
        while j > 0 and not lines[j].lstrip().startswith('except'):
            j -= 1
        if re.match(r'\s*except Exception as e\b', lines[j]):
            out.append(i + 1)
    return out


class TestNoGenericHandlerAnswersWithTheRawException(unittest.TestCase):

    def test_a_502_for_a_failed_call_goes_through_explain_failure(self):
        found, sites = {}, 0
        for f in sorted(_CGI.glob('*.py')):
            src = f.read_text(encoding='utf-8')
            sites += len(re.findall(r'explain_failure\(', src))
            hits = raw_exception_502s(src)
            if hits:
                found[f.name] = hits
        self.assertEqual(found, {}, 'a 502 that says str(e) of any exception puts "<urlopen error [Errno -2] ...>" in front of a person: '
                                    'use integrations.explain_failure(e)')
        self.assertGreaterEqual(sites, 12, 'control: the sites that use the helper were not found')

    def test_the_scan_sees_the_pattern_and_spares_a_narrow_except(self):
        bad = "    except Exception as e:\n        respond(502, {'error': str(e)[:200]})\n"
        ok = "    except proxmox_client.ProxmoxError as e:\n        respond(502, {'error': str(e)})\n"
        fixed = "    except Exception as e:\n        respond(502, {'error': integrations_mod.explain_failure(e)})\n"
        self.assertEqual(raw_exception_502s(bad), [2])
        self.assertEqual(raw_exception_502s(ok), [])
        self.assertEqual(raw_exception_502s(fixed), [])


if __name__ == '__main__':
    unittest.main()

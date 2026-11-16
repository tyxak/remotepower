"""The readers of a scan result are handed what a scan writes (8.0.1).

Found while Debian and Ubuntu were moved to matching by source package, each by reading a real scan result and
not a fixture made for the reader:

  * a remediation campaign over a list of CVE ids, or over known-exploited findings, matched nothing. It read
    `cve_id`, `id` and a `kev` flag off a finding; a scan writes `vuln_id` and `aliases`, and `kev` is put on a
    finding only while a page is built. The campaign counted no host and its first daily sample marked it completed.
    Its tests seeded `cve_id`;
  * both MCP tools asked for /api/devices/<id>/cves. The route is /cve, so `get_cves` failed for every host name;
  * the assistant's fleet summary of the worst CVEs printed "?" for every id (it read `id` and `cve_id`);
  * an SBOM vulnerability pointed at no component when its finding is filed under a source package, or carries the
    epoch of an RPM version: the component map was keyed by installed name and version;
  * a host whose scan lists nothing and counts a few hundred per package was called clean: by the host drawer, the
    dashboard tile, the assistant's triage tool, the text of a ticket and the runbook snapshot.

The scan results here come from `cve_scanner.scan_device` over the recording in tests/osv_recording.py.
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
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v801-readers-'))
_spec = importlib.util.spec_from_file_location('api_v801_readers', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
cve_scanner = api.cve_scanner
cve_fixes = api.cve_fixes

import mcp_http  # noqa: E402
import rag_index  # noqa: E402
import sbom  # noqa: E402
import srcpin  # noqa: E402
from osv_recording import BEHIND, DEB, PATCHED, Database  # noqa: E402

_mcp_spec = importlib.util.spec_from_file_location('rp_mcp_v801', ROOT / 'mcp' / 'remotepower-mcp.py')
sidecar = importlib.util.module_from_spec(_mcp_spec)
_mcp_spec.loader.exec_module(sidecar)

_APP = (ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
HAVE_NODE = shutil.which('node') is not None
BEHIND_HOST, PATCHED_HOST, OTHER_HOST = 'v801rdbehind', 'v801rdpatched', 'v801rdother'
SSHD = 'DEBIAN-CVE-2024-6387'


def scan(packages, **kw):
    """A real scan of a Debian 12 host against the recording."""
    db = Database(DEB)
    with mock.patch.object(cve_scanner, '_osv_querybatch', db.querybatch), \
            mock.patch.object(cve_scanner, '_osv_vuln_details', db.details), \
            mock.patch.object(cve_scanner, '_debian_severity_fallback', lambda cve: None):
        result = cve_scanner.scan_device('h', packages, 'Debian:12', Path(tempfile.mkdtemp(prefix='rp-v801-rd-')),
                                         has_meta=True, **kw)
    assert 'error' not in result, result.get('error')
    return result


class _Captured(Exception):
    def __init__(self, status, body):
        super().__init__(status)
        self.status, self.body = status, body


class _Stored(unittest.TestCase):
    """Three hosts: one behind on its updates, one patched (its scan lists a few and counts the rest), one with nothing."""

    @classmethod
    def setUpClass(cls):
        cls.behind = scan(BEHIND)
        cls.patched = scan(PATCHED)

    def setUp(self):
        self._saved = {n: getattr(api, n) for n in ('respond', 'require_auth', 'require_admin_auth', 'audit_log',
                                                    'fire_webhook', 'method', 'get_json_body')}

        def respond(status, data):
            raise _Captured(status, data)
        self.fired = []
        api.respond = respond
        api.require_auth = api.require_admin_auth = lambda *a, **k: 'admin'
        api.audit_log = lambda *a, **k: None
        api.fire_webhook = lambda event, payload: self.fired.append((event, dict(payload)))
        api.save(api.DEVICES_FILE, {h: {'id': h, 'name': n, 'token': 't', 'monitored': True}
                                    for h, n in ((BEHIND_HOST, 'behind01'), (PATCHED_HOST, 'patched01'),
                                                 (OTHER_HOST, 'other01'))})
        api.save(api.CVE_FINDINGS_FILE, {BEHIND_HOST: json.loads(json.dumps(self.behind)),
                                         PATCHED_HOST: json.loads(json.dumps(self.patched))})
        api.save(api.PACKAGES_FILE, {BEHIND_HOST: {'ecosystem': 'Debian:12', 'sources': True, 'pkg_manager': 'apt',
                                                   'os_id': 'debian', 'count': len(BEHIND), 'packages': BEHIND}})
        for store in (api.CVE_IGNORE_FILE, api.CVE_CAMPAIGNS_FILE, api.KEV_EPSS_FILE):
            api.save(store, {})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for name, value in self._saved.items():
            setattr(api, name, value)
        for store in (api.DEVICES_FILE, api.CVE_FINDINGS_FILE, api.PACKAGES_FILE, api.CVE_IGNORE_FILE,
                      api.CVE_CAMPAIGNS_FILE, api.KEV_EPSS_FILE):
            api.save(store, {})
        api._LOAD_CACHE.clear()

    def call(self, handler, *args, method='GET', body=None):
        api._LOAD_CACHE.clear()
        api.method = lambda: method
        api.get_json_body = lambda: body
        try:
            handler(*args)
        except _Captured as c:
            return c.status, c.body
        self.fail('the handler did not answer')

    def finding(self, vid=SSHD):
        (found,) = [f for f in self.behind['findings'] if f['vuln_id'] == vid]
        return found


class TestWhatAScanWrites(_Stored):
    """The premise of this file: the shape the readers below are handed."""

    def test_a_finding_is_known_by_vuln_id_and_aliases(self):
        f = self.finding()
        self.assertEqual((f['vuln_id'], f['aliases']), (SSHD, ['CVE-2024-6387']))
        for never_written in ('cve_id', 'id', 'kev', 'known_exploited', 'pkg'):
            self.assertNotIn(never_written, f)

    def test_the_patched_host_lists_little_and_counts_the_rest(self):
        self.assertGreater(self.patched['rollup']['total'], len(self.patched['findings']))
        self.assertGreater(len(self.behind['findings']), 30)


class TestACampaign(_Stored):
    def create(self, **body):
        status, answer = self.call(api.handle_cve_campaigns, method='POST', body=dict({'name': 'c'}, **body))
        self.assertEqual(status, 200, answer)
        return answer['id']

    def row(self, cid):
        status, answer = self.call(api.handle_cve_campaigns)
        self.assertEqual(status, 200)
        (row,) = [r for r in answer['campaigns'] if r['id'] == cid]
        return row

    def test_over_a_cve_id_it_finds_the_distributions_record_of_it(self):
        row = self.row(self.create(cve_ids=['CVE-2024-6387']))
        self.assertEqual((row['affected_hosts'], row['finding_count']), (1, 1))

    def test_read_as_before_it_found_nothing(self):
        """The control: the two keys the campaign read are in no scan result."""
        f = self.finding()
        self.assertEqual(str(f.get('cve_id') or f.get('id') or ''), '')

    def test_by_the_records_own_id_and_in_any_case(self):
        for asked in (['DEBIAN-CVE-2024-6387'], ['cve-2024-6387'], ['CVE-1999-0001', 'debian-cve-2024-6387']):
            row = self.row(self.create(cve_ids=asked))
            self.assertEqual((row['affected_hosts'], row['finding_count']), (1, 1), asked)
        self.assertEqual(self.row(self.create(cve_ids=['CVE-1999-0001']))['affected_hosts'], 0)

    def test_an_id_list_still_overrides_the_severities(self):
        f = self.finding()
        other = next(s for s in ('critical', 'high', 'medium', 'low') if s != f['severity'])
        row = self.row(self.create(cve_ids=['CVE-2024-6387'], severities=[other]))
        self.assertEqual(row['affected_hosts'], 1)

    def test_known_exploited_only(self):
        cid = self.create(kev_only=True)
        self.assertEqual(self.row(cid)['affected_hosts'], 0)             # nothing on the list yet
        api.save(api.KEV_EPSS_FILE, {'kev': ['CVE-2024-6387'], 'epss': {}})
        row = self.row(cid)
        self.assertEqual((row['affected_hosts'], row['finding_count']), (1, 1))

    def test_by_severity_as_before(self):
        high = len([f for f in self.behind['findings'] if f['severity'] == 'high'])
        self.assertGreater(high, 3)
        row = self.row(self.create(severities=['high']))
        self.assertEqual(row['finding_count'],
                         high + len([f for f in self.patched['findings'] if f['severity'] == 'high']))

    def test_the_daily_sample_does_not_complete_a_campaign_that_still_has_a_host(self):
        cid = self.create(cve_ids=['CVE-2024-6387'])
        now = [2_000_000_000]
        with mock.patch.object(api.time, 'time', lambda: now[0]):
            api._LOAD_CACHE.clear()
            api.run_cve_campaign_sample_if_due()
            api._LOAD_CACHE.clear()
            (camp,) = [c for c in api.load(api.CVE_CAMPAIGNS_FILE)['campaigns'] if c['id'] == cid]
            self.assertIsNone(camp['completed_at'])
            self.assertEqual(camp['samples'][-1]['affected'], 1)
            self.assertEqual(self.fired, [])
            # the host is patched: now it completes, and says so once
            store = api.load(api.CVE_FINDINGS_FILE)
            store[BEHIND_HOST]['findings'] = [f for f in store[BEHIND_HOST]['findings'] if f['vuln_id'] != SSHD]
            api.save(api.CVE_FINDINGS_FILE, store)
            now[0] += 2 * 86400
            api._LOAD_CACHE.clear()
            api.run_cve_campaign_sample_if_due()
            api._LOAD_CACHE.clear()
            (camp,) = [c for c in api.load(api.CVE_CAMPAIGNS_FILE)['campaigns'] if c['id'] == cid]
        self.assertEqual(camp['completed_at'], now[0])
        self.assertEqual([e for e, _p in self.fired], ['campaign_completed'])

    def test_the_daily_sample_reads_the_known_exploited_list(self):
        cid = self.create(kev_only=True)
        api.save(api.KEV_EPSS_FILE, {'kev': ['CVE-2024-6387'], 'epss': {}})
        with mock.patch.object(api.time, 'time', lambda: 2_000_000_000):
            api._LOAD_CACHE.clear()
            api.run_cve_campaign_sample_if_due()
            api._LOAD_CACHE.clear()
            (camp,) = [c for c in api.load(api.CVE_CAMPAIGNS_FILE)['campaigns'] if c['id'] == cid]
        self.assertEqual(camp['samples'][-1]['affected'], 1)
        self.assertIsNone(camp['completed_at'])
        self.assertEqual(self.fired, [])

    def test_what_is_not_a_finding_matches_nothing(self):
        camp = {'cve_ids': ['CVE-2024-6387']}
        for junk in (None, 'CVE-2024-6387', 7, [], {}, {'vuln_id': None, 'aliases': 'CVE-2024-6387'}):
            self.assertFalse(api._campaign_matches_finding(camp, junk), junk)
        self.assertTrue(api._campaign_matches_finding(camp, {'cve_id': 'CVE-2024-6387'}))     # an older caller's shape
        self.assertFalse(api._campaign_matches_finding({'cve_ids': [None, 7]}, self.finding()))


def routes():
    """(method, pattern) for every route the server answers, as tests/test_ui_wiring.py derives them."""
    out = []
    for method, path in list(api._build_exact_routes().keys()) + list(api._dispatcher_routes()):
        rx = re.sub(r'\{[^}]+\}', '[^/]+', re.escape(path).replace(r'\{', '{').replace(r'\}', '}'))
        out.append((method, re.compile('^' + rx + '$')))
    return out


class TestEveryPathAnMcpToolAsksForIsARoute(unittest.TestCase):
    """Both MCP servers name the paths they read. A path no route answers fails only when the tool is used."""

    DEVICES = [{'id': 'devabc123', 'name': 'web01', 'snmp_enabled': True, 'snmp': {'enabled': True}, 'os': 'Debian',
                'ip': '192.0.2.1', 'tags': [], 'group': ''}]
    ARGS = ({'name': 'web01'}, {}, {'name': 'web01', 'query': 'nginx', 'script': 'x', 'alert_id': 'a1', 'top_n': 3},
            {'query': 'nginx'})

    @classmethod
    def setUpClass(cls):
        cls.routes = routes()

    def served(self, method, path):
        path = path.partition('?')[0]
        return any(m == method and rx.match(path) for m, rx in self.routes)

    def answer(self, path):
        return {'devices': self.DEVICES} if path.partition('?')[0] == '/api/devices' else {}

    def hosted(self):
        asked = set()

        def fetch(path, method='GET', body=None):
            asked.add((method, path))
            return self.answer(path)
        ran = 0
        for name, tool in mcp_http.TOOLS.items():
            for args in self.ARGS:
                try:
                    tool['run'](dict(args), fetch)
                    ran += 1
                except Exception:      # a tool that wants more than the stand-in answers; what it asked for is kept
                    pass
        return asked, ran

    def sidecar(self):
        asked = set()

        def fake(method, path, body=None, mcp_prompt=None):
            asked.add((method, path))
            return self.answer(path)
        ran = 0
        with mock.patch.object(sidecar, '_api', fake):
            for name in sorted(n for n in dir(sidecar) if n.startswith('tool_')):
                for args in self.ARGS:
                    try:
                        getattr(sidecar, name)(dict(args))
                        ran += 1
                    except Exception:
                        pass
        return asked, ran

    def test_the_hosted_endpoint(self):
        asked, ran = self.hosted()
        self.assertGreater(ran, 20)
        self.assertGreater(len(asked), 12, sorted(asked))
        self.assertIn(('GET', '/api/devices/devabc123/cve'), asked)
        self.assertEqual(sorted(a for a in asked if not self.served(*a)), [])

    def test_the_sidecar(self):
        asked, ran = self.sidecar()
        self.assertGreater(ran, 25)
        self.assertGreater(len(asked), 15, sorted(asked))
        self.assertIn(('GET', '/api/devices/devabc123/cve'), asked)
        self.assertEqual(sorted(a for a in asked if not self.served(*a)), [])

    def test_the_check_sees_a_path_that_no_route_answers(self):
        """The control, on the path both tools asked for until 8.0.1."""
        self.assertFalse(self.served('GET', '/api/devices/devabc123/cves'))
        self.assertTrue(self.served('GET', '/api/devices/devabc123/cve'))
        self.assertFalse(self.served('POST', '/api/devices/devabc123/cve'))


class TestTheMcpToolsReturnAHostsFindings(_Stored):
    def fetch(self, path, method='GET', body=None):
        if path == '/api/devices':
            return {'devices': [dict(d) for d in api.load(api.DEVICES_FILE).values()]}
        match = re.fullmatch(r'/api/devices/([^/]+)/cve', path)
        if not match:
            raise AssertionError('a path this test does not know: ' + path)
        with mock.patch.object(api, '_kev_epss', lambda: (set(), {})):
            status, answer = self.call(api.handle_cve_device, match.group(1))
        self.assertEqual(status, 200, answer)
        return answer

    def test_the_hosted_tool(self):
        out = mcp_http.tool_get_cves({'name': 'behind01'}, self.fetch)
        self.assertEqual(out['device'], 'behind01')
        self.assertIn(SSHD, {f['vuln_id'] for f in out['findings']})
        self.assertEqual(out['counted']['total'], self.behind['rollup']['total'])
        patched = mcp_http.tool_get_cves({'name': 'patched01'}, self.fetch)
        self.assertEqual(patched['counted']['total'], self.patched['rollup']['total'])
        self.assertNotIn('counted', mcp_http.tool_get_cves({'name': 'other01'}, self.fetch))

    def test_the_sidecar_tool(self):
        with mock.patch.object(sidecar, '_api', lambda method, path, body=None, mcp_prompt=None: self.fetch(path)):
            out = sidecar.tool_get_cves({'name': 'behind01'})
            nothing = sidecar.tool_get_cves({'name': 'other01'})
        self.assertIn(SSHD, {f['vuln_id'] for f in out['findings']})
        self.assertEqual(out['counted']['total'], self.behind['rollup']['total'])
        self.assertEqual(nothing, {'device': 'other01', 'findings': []})


class TestTheAssistantsFleetSummary(_Stored):
    def summary(self, findings):
        docs = rag_index.build_live_state_corpus([{'id': BEHIND_HOST, 'name': 'behind01'}],
                                                 {BEHIND_HOST: {'cves': findings}})
        hits = [d['text'] for d in docs if 'Fleet CVE summary' in d.get('text', '')]
        self.assertEqual(len(hits), 1, 'the summary chunk was not built')
        return hits[0]

    def test_it_names_the_advisories(self):
        text = self.summary(self.behind['findings'])
        worst = [f for f in self.behind['findings'] if f['severity'] in ('critical', 'high')]
        self.assertGreater(len(worst), 5)
        self.assertIn(f'- {BEHIND_HOST}: {SSHD} (high in openssh)', text)
        self.assertEqual(text.count(': ? ('), 0)
        for f in worst[:80]:
            self.assertIn(f['vuln_id'], text)

    def test_a_row_without_any_id_still_prints(self):
        text = self.summary([{'severity': 'critical', 'package': 'p'}, {'severity': 'high', 'id': 'OLD-1'}])
        self.assertIn(f'- {BEHIND_HOST}: ? (critical in p)', text)
        self.assertIn('OLD-1', text)


class TestAnSbomPointsAtTheInstalledPackages(_Stored):
    def bom(self, packages, findings, pkg_manager='apt', os_id='debian'):
        entry = {'packages': packages, 'pkg_manager': pkg_manager, 'os_id': os_id, 'ecosystem': 'Debian:12'}
        doc = sbom.build_cyclonedx({'id': 'h', 'name': 'h'}, entry, findings)
        names = {c['bom-ref']: c['name'] for c in doc['components']}
        return {v['id']: sorted(names[a['ref']] for a in v.get('affects', [])) for v in doc.get('vulnerabilities', [])}

    def test_a_finding_filed_under_a_source_package(self):
        affects = self.bom(BEHIND, self.behind['findings'])
        self.assertEqual(affects[SSHD], ['openssh-client', 'openssh-server'])
        glibc = next(f['vuln_id'] for f in self.behind['findings'] if f['package'] == 'glibc')
        self.assertEqual(affects[glibc], ['libc-bin', 'libc6'])
        self.assertEqual([v for v, names in affects.items() if not names], [])       # none points at nothing

    def test_before_it_pointed_at_nothing(self):
        """The control: no installed package has the name and version a source-package finding carries."""
        f = self.finding()
        self.assertNotIn((f['package'], f['version']), {(p['name'], p['version']) for p in BEHIND})

    def test_a_package_named_like_its_source_is_found_as_before(self):
        sudo = next(f for f in self.behind['findings'] if f['package'] == 'sudo')
        self.assertEqual(self.bom(BEHIND, [sudo])[sudo['vuln_id']], ['sudo'])

    def test_an_rpm_finding_whose_version_carries_the_epoch(self):
        packages = [{'name': 'openssl-libs', 'version': '3.0.7-16.el9', 'arch': 'x86_64', 'epoch': '1', 'source': 'openssl'},
                    {'name': 'openssl', 'version': '3.0.7-16.el9', 'arch': 'x86_64', 'epoch': '1', 'source': 'openssl'},
                    {'name': 'bash', 'version': '5.1.8-9.el9', 'arch': 'x86_64', 'source': 'bash'}]
        finding = {'vuln_id': 'ALSA-2024:1', 'package': 'openssl', 'version': '1:3.0.7-16.el9', 'severity': 'high',
                   'binaries': ['openssl', 'openssl-libs']}
        self.assertEqual(self.bom(packages, [finding], 'dnf', 'almalinux')['ALSA-2024:1'], ['openssl', 'openssl-libs'])
        # from the list alone, when the finding names no installed package
        bare = {'vuln_id': 'ALSA-2024:2', 'package': 'openssl', 'version': '1:3.0.7-16.el9', 'severity': 'high'}
        self.assertEqual(self.bom(packages, [bare], 'dnf', 'almalinux')['ALSA-2024:2'], ['openssl', 'openssl-libs'])

    def test_two_installed_versions_of_one_name(self):
        """An RPM host keeps its old kernels. A finding about one version is about that one."""
        kernels = [{'name': 'kernel', 'version': '5.14.0-362.el9', 'arch': 'x86_64'},
                   {'name': 'kernel', 'version': '5.14.0-427.el9', 'arch': 'x86_64'}]
        entry = {'packages': kernels, 'pkg_manager': 'dnf', 'os_id': 'almalinux'}
        doc = sbom.build_cyclonedx({'id': 'h', 'name': 'h'}, entry, [
            {'vuln_id': 'ALSA-2024:9', 'package': 'kernel', 'version': '5.14.0-362.el9', 'severity': 'high'}])
        versions = {c['bom-ref']: c['version'] for c in doc['components']}
        (vuln,) = doc['vulnerabilities']
        self.assertEqual([versions[a['ref']] for a in vuln['affects']], ['5.14.0-362.el9'])

    def test_a_list_from_an_older_agent_and_a_finding_about_nothing_installed(self):
        plain = [{'name': 'curl', 'version': '7.88.1-10', 'arch': 'amd64'}]
        self.assertEqual(self.bom(plain, [{'vuln_id': 'X-1', 'package': 'curl', 'version': '7.88.1-10+deb12u5',
                                           'severity': 'low'}])['X-1'], ['curl'])
        self.assertEqual(self.bom(plain, [{'vuln_id': 'X-2', 'package': 'gone', 'version': '1', 'severity': 'low'}])['X-2'],
                         [])
        for odd in ({'binaries': 'curl'}, {'binaries': [None, 7]}, {'package': None}, {'package': 7}):
            f = dict({'vuln_id': 'X-3', 'package': 'curl', 'version': '9', 'severity': 'low'}, **odd)
            self.assertIsInstance(self.bom(plain, [f])['X-3'], list, odd)

    def test_a_vulnerability_points_at_a_bounded_number_of_components(self):
        many = [{'name': f'linux-thing-{i}', 'version': '6.1.0-1', 'arch': 'amd64', 'source': 'linux'} for i in range(500)]
        finding = {'vuln_id': 'X-9', 'package': 'linux', 'version': '6.1.76-1', 'severity': 'high'}
        self.assertEqual(len(self.bom(many, [finding])['X-9']), sbom.MAX_AFFECTS)


class TestAHostWithOnlyACountIsNotClean(_Stored):
    def setUp(self):
        super().setUp()
        store = api.load(api.CVE_FINDINGS_FILE)
        store[PATCHED_HOST] = dict(store[PATCHED_HOST], findings=[])      # nothing listed, the count stays
        api.save(api.CVE_FINDINGS_FILE, store)
        api._LOAD_CACHE.clear()
        self.counted = self.patched['rollup']['total']

    def test_the_assistants_triage_tool(self):
        source = srcpin.py_function((_CGI / 'ai_triage_handlers.py').read_text(), '_cves')
        self.assertIn('A.cve_fixes.rollup_total(rec)', source)
        self.assertIn("return f'(no CVE findings listed for this host; {more})' if more else", source)
        self.assertIn("'(no open CVE findings for this host)'", source)
        self.assertIn('lines.append(more)', source)

    def test_the_text_of_a_ticket(self):
        text = '\n'.join(self.ticket(PATCHED_HOST))
        self.assertIn('Open CVEs on this host: 0 total', text)
        self.assertIn(f'Counted per package and not listed one by one: {self.counted} more', text)
        self.assertNotIn('Counted per package', '\n'.join(self.ticket(OTHER_HOST)))
        behind = '\n'.join(self.ticket(BEHIND_HOST))
        self.assertIn(f"Counted per package and not listed one by one: {self.behind['rollup']['total']} more", behind)
        self.assertIn(SSHD, behind)

    def ticket(self, host):
        api._LOAD_CACHE.clear()
        text = api._alert_ticket_detail({'event': 'cve_found', 'device_id': host, 'title': 'New CVEs',
                                         'payload': {'device_id': host}})
        self.assertIsInstance(text, str)
        return text.splitlines()

    def test_the_runbook_snapshot(self):
        source = srcpin.py_function((_CGI / 'api.py').read_text(), '_build_runbook_snapshot')
        self.assertIn('cve_counted = cve_fixes.rollup_total(cve)', source)
        self.assertIn("'cve_counted':    cve_counted,", source)
        import ai_provider
        prompt = next(v for v in ai_provider.SYSTEM_PROMPTS.values() if isinstance(v, str) and 'cve_findings' in v
                      and 'No risks flagged in this snapshot.' in v)
        self.assertIn('cve_counted is zero', prompt)

    def test_the_dashboard_is_handed_the_count(self):
        source = srcpin.py_function((_CGI / 'api.py').read_text(), 'handle_home')
        self.assertIn("'counted': cve_fixes.rollup_total(entry)", source)
        self.assertIn("countedCves > 0 ? `${countedCves} counted per package` : 'No active CVEs'", _APP)
        self.assertIn('acc.counted  += (Number.isInteger(d.counted) && d.counted > 0) ? d.counted : 0;', _APP)

    def test_the_host_view_carries_it(self):
        with mock.patch.object(api, '_kev_epss', lambda: (set(), {})):
            status, answer = self.call(api.handle_cve_device, PATCHED_HOST)
        self.assertEqual((status, answer['findings'], answer['rollup']['total']), (200, [], self.counted))


@unittest.skipUnless(HAVE_NODE, 'node not installed')
class TestTheDrawerBadge(unittest.TestCase):
    """The badge and the closing line of the host drawer's CVE block, cut out of app.js and run."""

    def run_case(self, data):
        block = _APP[_APP.index("      case 'cve': {"):]
        block = block[:block.index('        // Cross-feature: CVE findings')]
        body = block[block.index('        const findings = data.findings || [];'):]
        script = '''
const escHtml = s => String(s).replace(/[&<>"']/g, c => '&#' + c.charCodeAt(0) + ';');
const badge = {}, body = {};
const data = %s;
%s
console.log(JSON.stringify({badge: badge.innerHTML, body: body.innerHTML}));
''' % (json.dumps(data), body)
        r = subprocess.run(['node', '-e', script], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def test_a_host_with_a_count_and_nothing_listed(self):
        out = self.run_case({'scanned_at': 5, 'findings': [], 'rollup': {'total': 412}})
        self.assertEqual(out['badge'], '412 counted')
        self.assertIn('Known vulnerabilities counted per package and not listed one by one:</span> <strong>412</strong>',
                      out['body'])
        self.assertNotIn('No CVEs found.', out['body'])

    def test_a_scanned_host_with_nothing(self):
        out = self.run_case({'scanned_at': 5, 'findings': []})
        self.assertEqual(out['badge'], 'clean')
        self.assertIn('<div class="c-green">No CVEs found.</div>', out['body'])     # this line was never printed

    def test_a_host_that_was_never_scanned_is_not_clean(self):
        for unscanned in ({'findings': []}, {'scanned_at': 0, 'findings': []}, {'scanned_at': None, 'findings': []}):
            out = self.run_case(unscanned)
            self.assertEqual(out['badge'], 'not scanned', unscanned)
            self.assertNotIn('No CVEs found.', out['body'])

    def test_findings_and_a_count(self):
        out = self.run_case({'scanned_at': 5, 'rollup': {'total': 9},
                             'findings': [{'vuln_id': 'CVE-2024-1', 'severity': 'high', 'package': 'p', 'version': '1'}]})
        self.assertIn('1 high', out['badge'])
        self.assertIn('CVE-2024-1', out['body'])
        self.assertIn('<strong>9</strong>', out['body'])

    def test_a_count_of_another_shape_is_no_count(self):
        for odd in (None, 7, 'many', [], {'total': '9'}, {'total': -1}, {'total': 1.5}, {'total': '<img src=x>'}):
            out = self.run_case({'scanned_at': 5, 'findings': [], 'rollup': odd})
            self.assertEqual(out['badge'], 'clean', odd)
            self.assertNotIn('counted per package', out['body'])


class TestTheCountersReadWithoutCopying(unittest.TestCase):
    """Three counters only count. They read the shared store: a Debian or Ubuntu fleet matched by source package holds
    up to 300 findings a host, and the sidebar count runs on every poll of every open tab."""

    def test_they_use_the_shared_read(self):
        src = (_CGI / 'api.py').read_text()
        for name in ('_cve_high_counts', 'handle_nav_counts', '_compute_compliance'):
            body = srcpin.py_function(src, name)
            self.assertIn('_load_ro(CVE_FINDINGS_FILE)', body, name)
            self.assertNotIn('load(CVE_FINDINGS_FILE) or {}).items()', body.replace('_load_ro(CVE_FINDINGS_FILE)', ''), name)

    def test_and_they_do_not_write_to_what_they_read(self):
        store = {'h1': {'findings': [{'vuln_id': 'CVE-2024-1', 'severity': 'critical', 'fix_status': 'none'},
                                     {'vuln_id': 'CVE-2024-2', 'severity': 'high', 'fix_status': 'fixed',
                                      'fixed_version': '2'}]}}
        api.save(api.DEVICES_FILE, {'h1': {'id': 'h1', 'name': 'h1', 'token': 't', 'monitored': True}})
        api.save(api.CVE_FINDINGS_FILE, store)
        api.save(api.CVE_IGNORE_FILE, {})
        api._LOAD_CACHE.clear()
        try:
            before = json.dumps(api._load_ro(api.CVE_FINDINGS_FILE), sort_keys=True)
            self.assertEqual(api._cve_high_counts(), {'h1': 2})
            self.assertEqual(json.dumps(api._load_ro(api.CVE_FINDINGS_FILE), sort_keys=True), before)
        finally:
            for f in (api.DEVICES_FILE, api.CVE_FINDINGS_FILE):
                api.save(f, {})
            api._LOAD_CACHE.clear()


if __name__ == '__main__':
    unittest.main()

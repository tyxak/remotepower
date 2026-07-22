#!/usr/bin/env python3
"""Tests for the v4.2.0 (B5) scanner-satellite worker output parsers.

The worker (client/remotepower-scanner.py) shells out to nuclei/nikto/nmap in a
sandboxed container; the dual-use tools can't run here, so we test the pure
PARSE step (tool stdout -> normalised findings) with representative fixtures.
"""
import importlib.util
import json
import os
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
os.environ.setdefault('RP_SERVER_URL', 'https://x')
os.environ.setdefault('RP_SATELLITE_TOKEN', 't')

_spec = importlib.util.spec_from_file_location(
    'rp_scanner', _ROOT / 'client' / 'remotepower-scanner.py')
sc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sc)


class TestReportWorkdirPerms(unittest.TestCase):
    """CWE-732 regression: the world-writable scan work dir must sit inside a
    0700 parent so local users can't reach it. On the OLD code (a 0777 dir
    directly in /tmp, whose parent is 1777) the parent-mode assertion fails."""

    def test_workdir_under_0700_parent(self):
        captured = {}

        def fake_argv(target, profile, intensity, workdir, report):
            captured['workdir_mode'] = os.stat(workdir).st_mode & 0o777
            captured['parent_mode'] = os.stat(os.path.dirname(workdir)).st_mode & 0o777
            with open(os.path.join(workdir, report), 'w') as fh:
                fh.write('{}')
            return ['true']

        orig_run = sc._run
        sc._run = lambda argv: ('', '', '')
        try:
            sc._run_report_tool(fake_argv, lambda text: [], 'example.com', 'passive', 'quick')
        finally:
            sc._run = orig_run
        self.assertEqual(captured.get('parent_mode'), 0o700,
                         'work-dir parent must be 0700 (local users blocked)')
        self.assertEqual(captured.get('workdir_mode'), 0o777,
                         'inner work dir stays 0777 so the container uid can write')


class TestNucleiParser(unittest.TestCase):
    def test_jsonl(self):
        text = ('{"template-id":"tls-version","info":{"name":"Old TLS",'
                '"severity":"High","reference":["http://x"]},"matched-at":"h:443"}\n'
                'garbage line\n'
                '{"template-id":"hdr","info":{"name":"Header","severity":"low"}}\n')
        f = sc._parse_nuclei(text)
        self.assertEqual(len(f), 2)
        self.assertEqual(f[0]['severity'], 'high')
        self.assertEqual(f[0]['rule_id'], 'tls-version')
        self.assertEqual(f[0]['reference'], 'http://x')


class TestNiktoParser(unittest.TestCase):
    def test_object(self):
        text = ('{"host":"h","vulnerabilities":[{"id":"999103","method":"GET",'
                '"url":"/admin","msg":"Admin dir found"}]}')
        f = sc._parse_nikto(text)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]['severity'], 'medium')
        self.assertEqual(f[0]['rule_id'], '999103')
        self.assertIn('/admin', f[0]['evidence'])

    def test_bad_json(self):
        self.assertEqual(sc._parse_nikto('not json'), [])


class TestNmapParser(unittest.TestCase):
    def test_open_ports_and_vuln_script(self):
        xml = (
            '<nmaprun><host><address addr="10.0.0.5"/><ports>'
            '<port portid="443"><state state="open"/>'
            '<service name="https" product="nginx" version="1.25"/>'
            '<script id="ssl-enum-ciphers" output="TLSv1.0 enabled"/>'
            '<script id="http-vuln-cve2021" output="VULNERABLE: foo"/>'
            '</port>'
            '<port portid="22"><state state="closed"/></port>'
            '</ports></host></nmaprun>')
        f = sc._parse_nmap_xml(xml)
        ids = {x['rule_id']: x for x in f}
        self.assertIn('open-port-443', ids)
        self.assertEqual(ids['open-port-443']['severity'], 'info')
        self.assertIn('nginx', ids['open-port-443']['evidence'])
        # the vuln NSE script becomes a medium finding; closed port skipped
        self.assertIn('http-vuln-cve2021', ids)
        self.assertEqual(ids['http-vuln-cve2021']['severity'], 'medium')
        self.assertFalse(any('22' in x['rule_id'] for x in f))

    def test_bad_xml(self):
        self.assertEqual(sc._parse_nmap_xml('<broken'), [])


class TestZapParser(unittest.TestCase):
    def test_alerts(self):
        text = ('{"site":[{"alerts":[{"pluginid":"40012","name":"XSS",'
                '"riskcode":"3","instances":[{"uri":"http://h/x"}]}]}]}')
        f = sc._parse_zap(text)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]['severity'], 'high')
        self.assertEqual(f[0]['rule_id'], '40012')
        self.assertIn('http://h/x', f[0]['evidence'])


class TestReferenceClean(unittest.TestCase):
    def test_strips_html_extracts_url(self):
        # ZAP references are HTML; we want a clean URL, not "<p>https…</p>"
        ref = '<p>https://developer.mozilla.org/en-US/docs/Web/Security</p><p>x</p>'
        self.assertEqual(sc._clean_reference(ref),
                         'https://developer.mozilla.org/en-US/docs/Web/Security')

    def test_no_url_returns_empty(self):
        self.assertEqual(sc._clean_reference('<p>see the manual</p>'), '')

    def test_zap_finding_uses_clean_reference(self):
        text = ('{"site":[{"alerts":[{"pluginid":"90003","name":"SRI",'
                '"riskcode":"1","reference":"<p>https://example.com/sri</p>"}]}]}')
        f = sc._parse_zap(text)
        self.assertEqual(f[0]['reference'], 'https://example.com/sri')


class TestWapitiParser(unittest.TestCase):
    def test_vulns(self):
        text = ('{"vulnerabilities":{"SQL Injection":[{"level":3,"info":"param id"}],'
                '"Backup file":[{"level":1,"info":"/x.bak"}]}}')
        f = sc._parse_wapiti(text)
        sev = sorted(x['severity'] for x in f)
        self.assertEqual(sev, ['high', 'low'])


class TestProfileFlags(unittest.TestCase):
    def test_nmap_active_adds_vuln_scripts(self):
        self.assertIn('safe', sc._nmap_argv('h', 'passive', 'quick'))
        self.assertIn('safe,vuln', sc._nmap_argv('h', 'active', 'quick'))

    def test_nuclei_passive_excludes_intrusive(self):
        self.assertIn('-exclude-tags', sc._nuclei_argv('h', 'passive', 'quick'))
        self.assertNotIn('-exclude-tags', sc._nuclei_argv('h', 'active', 'quick'))

    def test_nuclei_fetches_templates(self):
        # -disable-update-check would leave nuclei with ZERO templates (image
        # ships none) → 0 findings. Must be absent; templates cached in a volume.
        argv = sc._nuclei_argv('h', 'passive', 'quick')
        self.assertNotIn('-disable-update-check', argv)
        if sc.RUNNER in ('docker', 'podman'):
            self.assertIn('rp-nuclei-templates:/root/nuclei-templates', argv)

    def test_intensity_tunes_depth(self):
        # nmap: quick = fast (top ports), full = every port
        self.assertIn('-F', sc._nmap_argv('h', 'passive', 'quick'))
        self.assertIn('-p-', sc._nmap_argv('h', 'passive', 'full'))
        # nuclei: quick limits severities, full = all
        self.assertIn('medium,high,critical', sc._nuclei_argv('h', 'passive', 'quick'))
        # zap: quick = baseline, full = full-scan
        self.assertIn('zap-baseline.py', sc._zap_argv('h', 'active', 'quick', '/w', 'r.json'))
        self.assertIn('zap-full-scan.py', sc._zap_argv('h', 'active', 'full', '/w', 'r.json'))

    def test_zap_redirects_home_to_writable_mount(self):
        # v4.3.0 fix: ZAP's intermediate summary (zap_out.json) goes to $HOME;
        # newer images fail writing it to /home/zap under the locked container
        # ("Failed to access summary file") → 0 findings. HOME + cwd must point
        # at the writable /zap/wrk mount so the -J report is produced.
        argv = sc._zap_argv('h', 'active', 'quick', '/w', 'r.json')
        if sc.RUNNER in ('docker', 'podman'):
            self.assertIn('-w', argv)
            self.assertIn('/zap/wrk', argv)
            self.assertIn('HOME=/zap/wrk', argv)


class TestAgentSide(unittest.TestCase):
    """B5 P3: the agent's lynis host-audit (importlib-loaded worker shares the
    parse helpers? No — these live in the agent). Load the agent module."""
    @classmethod
    def setUpClass(cls):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            'rp_agent', _ROOT / 'client' / 'remotepower-agent.py')
        cls.agent = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.agent)

    def test_parse_lynis_report(self):
        import tempfile, os
        data = ("warning[]=AUTH-9282|Password aging|-|-|\n"
                "suggestion[]=SSH-7408|Harden sshd|-|-|\n"
                "hardening_index=64\n"
                "ignored line\n")
        p = os.path.join(tempfile.mkdtemp(), 'report.dat')
        open(p, 'w').write(data)
        # v4.2.0 sweep: returns (findings, hardening_index) — the 0–100 score
        # used to be discarded at parse time.
        f, hardening = self.agent._parse_lynis_report(p)
        self.assertEqual(len(f), 2)
        self.assertEqual(f[0]['rule_id'], 'AUTH-9282')
        self.assertEqual(f[0]['severity'], 'medium')   # warning
        self.assertEqual(f[1]['severity'], 'low')      # suggestion
        self.assertEqual(hardening, 64)

    def test_parse_lynis_report_no_hardening_index(self):
        import tempfile, os
        p = os.path.join(tempfile.mkdtemp(), 'report.dat')
        open(p, 'w').write("warning[]=X-1|A|-|-|\n")
        f, hardening = self.agent._parse_lynis_report(p)
        self.assertEqual(len(f), 1)
        self.assertIsNone(hardening)

    def test_run_host_scan_unsupported_tool(self):
        r = self.agent.run_host_scan({'id': 's1', 'tool': 'metasploit'})
        self.assertEqual(r['status'], 'failed')
        self.assertIn('unsupported', r['error'])

    def test_run_host_scan_no_lynis(self):
        # lynis almost certainly isn't installed in CI → graceful failure
        orig = self.agent._which
        self.agent._which = lambda p: None
        try:
            r = self.agent.run_host_scan({'id': 's1', 'tool': 'lynis'})
        finally:
            self.agent._which = orig
        self.assertEqual(r['status'], 'failed')
        self.assertIn('lynis', r['error'])


class TestContainerLifecycle(unittest.TestCase):
    def test_timeout_names_and_force_removes_container(self):
        import subprocess as _sp
        calls = []
        orig = sc.subprocess.run

        def fake(argv, **kw):
            calls.append(list(argv))
            raise _sp.TimeoutExpired(argv, 1)
        sc.subprocess.run = fake
        try:
            _o, _e, err = sc._run([sc.RUNNER, 'run', '--rm', 'img', 'tool'])
        finally:
            sc.subprocess.run = orig
        self.assertIn('budget', err)
        if sc.RUNNER in ('docker', 'podman'):
            self.assertIn('--name', calls[0])                     # named the container
            name = calls[0][calls[0].index('--name') + 1]
            self.assertTrue(name.startswith('rp-scan-'))
            self.assertTrue(any('rm' in c and '-f' in c and name in c for c in calls))  # rm -f it


class TestDispatch(unittest.TestCase):
    def test_known_tools(self):
        self.assertEqual(set(sc.TOOL_RUNNERS),
                         {'nuclei', 'nikto', 'nmap', 'wpscan', 'zap', 'wapiti'})

    def test_unknown_tool(self):
        findings, err = sc._run_tool('metasploit', 'h', 'passive')
        self.assertEqual(findings, [])
        self.assertIn('unsupported', err)

    def test_sandbox_is_locked_down(self):
        # NB: deliberately NOT --read-only (it blocks the tools' scratch writes →
        # 0 findings). The other hardening flags must still be present.
        for tool_argv in (sc._nmap_argv('10.0.0.5', 'active', 'quick'),
                          sc._zap_argv('example.com', 'active', 'quick', '/tmp/wd', 'report.json')):
            if sc.RUNNER in ('docker', 'podman'):
                for flag in ('--rm', '--cap-drop', 'ALL', '--pids-limit',
                             '--security-opt', 'no-new-privileges'):
                    self.assertIn(flag, tool_argv)
                self.assertNotIn('--read-only', tool_argv)

    def test_report_tools_mount_workdir(self):
        # zap/wapiti write a report FILE; the runner mounts a host workdir and
        # passes a report path the worker reads back.
        if sc.RUNNER in ('docker', 'podman'):
            zap = sc._zap_argv('example.com', 'active', 'quick', '/tmp/wd', 'report.json')
            # :z relabels the bind mount for SELinux hosts (v4.3.0 fix).
            self.assertIn('/tmp/wd:/zap/wrk:rw,z', zap)
            self.assertIn('report.json', zap)
            wap = sc._wapiti_argv('example.com', 'active', 'quick', '/tmp/wd', 'report.json')
            self.assertIn('/tmp/wd:/output:rw', wap)

    def test_nikto_does_not_force_ssl(self):
        self.assertNotIn('-ssl', sc._nikto_argv('example.com', 'passive', 'quick'))

    def test_nmap_gets_raw_socket_capabilities(self):
        # Found live: a blanket --cap-drop ALL silently broke nearly every nmap
        # probe -- nsock_pcap_open() failed on lo/docker0/the host iface, and the
        # "safe" NSE script set (always included, see _nmap_argv) includes
        # dhcp-discover, which needs NET_BIND_SERVICE to bind 0.0.0.0:68. nmap's
        # -sV + "safe" scripts genuinely need raw sockets; every other tool here
        # is pure HTTP/L7 and must NOT get capabilities back.
        if sc.RUNNER not in ('docker', 'podman'):
            self.skipTest('RUNNER is not a container runtime')
        nmap_argv = sc._nmap_argv('10.0.0.5', 'passive', 'quick')
        self.assertIn('--cap-add', nmap_argv)
        self.assertIn('NET_RAW', nmap_argv)
        self.assertIn('NET_BIND_SERVICE', nmap_argv)
        # cap-add must come after cap-drop ALL, or docker treats it as a no-op.
        self.assertLess(nmap_argv.index('--cap-drop'), nmap_argv.index('--cap-add'))

        for other in (sc._nuclei_argv('example.com', 'passive', 'quick'),
                      sc._nikto_argv('example.com', 'passive', 'quick'),
                      sc._zap_argv('example.com', 'active', 'quick', '/tmp/wd', 'report.json'),
                      sc._wapiti_argv('example.com', 'active', 'quick', '/tmp/wd', 'report.json')):
            self.assertNotIn('--cap-add', other)

class TestWpscanParser(unittest.TestCase):
    """WordPress scanner: core/plugin/theme vulns, plus the enumerable-users
    signal that precedes most real WordPress compromises."""

    DOC = {
        "version": {"number": "6.4.1", "vulnerabilities": [
            {"id": "aaaa-1111", "title": "Core XSS", "fixed_in": "6.4.2",
             "references": {"cve": ["2024-1234"],
                            "url": ["https://example.test/adv"]}}]},
        "plugins": {"wp-file-manager": {"vulnerabilities": [
            {"id": "bbbb-2222", "title": "Unauthenticated RCE", "fixed_in": "6.9",
             "references": {"cve": ["2020-25213"], "url": []}}]}},
        "themes": {"twentyten": {"vulnerabilities": []}},
        "interesting_findings": [
            {"to_s": "XML-RPC seems to be enabled", "url": "http://t/xmlrpc.php"}],
        "users": {"admin": {}, "editor": {}},
    }

    def _by_id(self):
        return {f['rule_id']: f for f in sc._parse_wpscan(json.dumps(self.DOC))}

    def test_core_vulnerability(self):
        f = self._by_id()['aaaa-1111']
        self.assertEqual(f['severity'], 'high')
        self.assertIn('Core XSS', f['title'])
        self.assertEqual(f['reference'], 'https://example.test/adv')
        self.assertIn('6.4.2', f['evidence'])

    def test_plugin_vulnerability_is_labelled_and_falls_back_to_cve_ref(self):
        f = self._by_id()['bbbb-2222']
        self.assertIn('plugin wp-file-manager', f['title'])
        self.assertIn('cve.mitre.org', f['reference'])   # no url -> CVE fallback

    def test_enumerable_users_reported(self):
        f = self._by_id()['wpscan-user-enum']
        self.assertEqual(f['severity'], 'medium')
        self.assertIn('admin', f['evidence'])

    def test_interesting_findings_are_info(self):
        self.assertEqual(self._by_id()['wpscan-interesting']['severity'], 'info')

    def test_bad_and_empty_input(self):
        self.assertEqual(sc._parse_wpscan('not json'), [])
        self.assertEqual(sc._parse_wpscan('[]'), [])
        self.assertEqual(sc._parse_wpscan('{}'), [])


class TestWpscanArgv(unittest.TestCase):
    def test_password_attack_is_never_wired(self):
        """wpscan CAN brute-force logins. That is intrusive, trips lockouts and
        fills the target's auth log — it must not be reachable from here."""
        for profile in ('passive', 'active'):
            argv = ' '.join(sc._wpscan_argv('http://t', profile, 'full'))
            self.assertNotIn('--passwords', argv)
            self.assertNotIn('--usernames', argv)

    def test_passive_does_not_enumerate_users(self):
        argv = sc._wpscan_argv('http://t', 'passive', 'quick')
        enum = argv[argv.index('--enumerate') + 1]
        self.assertNotIn('u', enum.split(','))
        self.assertIn('vp', enum.split(','))
        self.assertIn('passive', argv)          # plugin detection stays passive

    def test_active_enumerates_users_and_probes_harder(self):
        argv = sc._wpscan_argv('http://t', 'active', 'full')
        self.assertIn('u', argv[argv.index('--enumerate') + 1].split(','))
        self.assertIn('aggressive', argv)

    def test_registered_as_a_stdout_tool(self):
        self.assertIn('wpscan', sc.STDOUT_TOOLS)
        self.assertIn('wpscan', sc.TOOL_RUNNERS)



class TestTheFixIsSpelledOut(unittest.TestCase):
    """Naming a missing setting is not a resolution if the operator has to work
    out where it goes. The scan detail view must give the real paths."""

    def _js(self):
        return (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()

    def test_the_note_gives_the_env_file_the_installer_actually_writes(self):
        js = self._js()
        i = js.index('wpscan_vuln_db === false')
        blk = js[i:i + 2200]
        self.assertIn('/etc/remotepower/scanner.env', blk)
        self.assertIn('RP_WPSCAN_API_TOKEN', blk)
        self.assertIn('systemctl restart remotepower-scanner', blk)
        self.assertIn('wpscan.com/api', blk)

    def test_that_path_is_the_one_scanner_setup_writes(self):
        setup = (_ROOT / 'packaging' / 'scanner-setup.sh').read_text()
        self.assertIn('ENVF=/etc/remotepower/scanner.env', setup,
                      'the UI would be telling operators about a path that does '
                      'not exist')

    def test_the_unit_name_matches_the_installed_one(self):
        setup = (_ROOT / 'packaging' / 'scanner-setup.sh').read_text()
        self.assertIn('remotepower-scanner.service', setup)

    def test_the_docs_carry_the_same_steps(self):
        doc = (_ROOT / 'docs' / 'security-scans.md').read_text()
        for bit in ('/etc/remotepower/scanner.env', 'RP_WPSCAN_API_TOKEN',
                    'systemctl restart remotepower-scanner', 'wpscan.com/api'):
            self.assertIn(bit, doc)


class TestSatelliteCapabilities(unittest.TestCase):
    """A zero-finding scan is ambiguous: "genuinely clean" or "the tool never
    actually checked". The satellite reports what it COULD do so the detail view
    can say which — as a static fact about the satellite, never as a per-scan
    message. An earlier version put it in the per-scan `error` field and one
    unconfigured token produced an endless stream of identical notices."""

    def setUp(self):
        self._tok = os.environ.pop('RP_WPSCAN_API_TOKEN', None)

    def tearDown(self):
        os.environ.pop('RP_WPSCAN_API_TOKEN', None)
        if self._tok is not None:
            os.environ['RP_WPSCAN_API_TOKEN'] = self._tok

    def test_missing_wpscan_token_is_reported_as_a_capability(self):
        self.assertEqual(sc._capabilities()['wpscan_vuln_db'], False)

    def test_configured_token_flips_the_capability(self):
        os.environ['RP_WPSCAN_API_TOKEN'] = 'tok'
        self.assertEqual(sc._capabilities()['wpscan_vuln_db'], True)

    def test_capabilities_ride_with_the_results_post(self):
        src = (_ROOT / 'client' / 'remotepower-scanner.py').read_text()
        body = src[src.index('def _process_one('):]
        self.assertIn("'capabilities': _capabilities()", body)

    def test_the_note_is_NOT_stuffed_into_the_per_scan_error_field(self):
        """The regression that made it spam: `error` is surfaced per run, so a
        static config fact placed there repeats forever."""
        src = (_ROOT / 'client' / 'remotepower-scanner.py').read_text()
        self.assertNotIn('_caveat', src)
        self.assertNotIn('RP_WPSCAN_API_TOKEN', src[src.index('def _process_one('):])

    def test_status_is_still_decided_by_the_real_error_alone(self):
        src = (_ROOT / 'client' / 'remotepower-scanner.py').read_text()
        body = src[src.index('def _process_one('):]
        self.assertIn("status = 'failed' if err else 'done'", body)

    def test_run_tool_still_dispatches_to_both_runner_families(self):
        src = (_ROOT / 'client' / 'remotepower-scanner.py').read_text()
        fn = src[src.index('def _run_tool('):src.index('def _capabilities(')]
        self.assertIn('STDOUT_TOOLS', fn)
        self.assertIn('REPORT_TOOLS', fn)
        self.assertIn('unsupported tool', fn)


if __name__ == '__main__':
    unittest.main()

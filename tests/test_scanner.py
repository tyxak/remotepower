#!/usr/bin/env python3
"""Tests for the v4.2.0 (B5) scanner-satellite worker output parsers.

The worker (client/remotepower-scanner.py) shells out to nuclei/nikto/nmap in a
sandboxed container; the dual-use tools can't run here, so we test the pure
PARSE step (tool stdout -> normalised findings) with representative fixtures.
"""
import importlib.util
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


class TestWapitiParser(unittest.TestCase):
    def test_vulns(self):
        text = ('{"vulnerabilities":{"SQL Injection":[{"level":3,"info":"param id"}],'
                '"Backup file":[{"level":1,"info":"/x.bak"}]}}')
        f = sc._parse_wapiti(text)
        sev = sorted(x['severity'] for x in f)
        self.assertEqual(sev, ['high', 'low'])


class TestProfileFlags(unittest.TestCase):
    def test_nmap_active_adds_vuln_scripts(self):
        self.assertIn('safe', sc._nmap_argv('h', 'passive'))
        self.assertIn('safe,vuln', sc._nmap_argv('h', 'active'))

    def test_nuclei_passive_excludes_intrusive(self):
        self.assertIn('-exclude-tags', sc._nuclei_argv('h', 'passive'))
        self.assertNotIn('-exclude-tags', sc._nuclei_argv('h', 'active'))

    def test_nuclei_fetches_templates(self):
        # -disable-update-check would leave nuclei with ZERO templates (image
        # ships none) → 0 findings. Must be absent; templates cached in a volume.
        argv = sc._nuclei_argv('h', 'passive')
        self.assertNotIn('-disable-update-check', argv)
        if sc.RUNNER in ('docker', 'podman'):
            self.assertIn('rp-nuclei-templates:/root/nuclei-templates', argv)


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
                "ignored line\n")
        p = os.path.join(tempfile.mkdtemp(), 'report.dat')
        open(p, 'w').write(data)
        f = self.agent._parse_lynis_report(p)
        self.assertEqual(len(f), 2)
        self.assertEqual(f[0]['rule_id'], 'AUTH-9282')
        self.assertEqual(f[0]['severity'], 'medium')   # warning
        self.assertEqual(f[1]['severity'], 'low')      # suggestion

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


class TestDispatch(unittest.TestCase):
    def test_known_tools(self):
        self.assertEqual(set(sc.TOOL_RUNNERS),
                         {'nuclei', 'nikto', 'nmap', 'zap', 'wapiti'})

    def test_unknown_tool(self):
        findings, err = sc._run_tool('metasploit', 'h', 'passive')
        self.assertEqual(findings, [])
        self.assertIn('unsupported', err)

    def test_sandbox_is_locked_down(self):
        # NB: deliberately NOT --read-only (it blocks the tools' scratch writes →
        # 0 findings). The other hardening flags must still be present.
        for tool_argv in (sc._nmap_argv('10.0.0.5', 'active'),
                          sc._zap_argv('example.com', 'active')):
            if sc.RUNNER in ('docker', 'podman'):
                for flag in ('--rm', '--cap-drop', 'ALL', '--pids-limit',
                             '--security-opt', 'no-new-privileges'):
                    self.assertIn(flag, tool_argv)
                self.assertNotIn('--read-only', tool_argv)

    def test_nikto_does_not_force_ssl(self):
        self.assertNotIn('-ssl', sc._nikto_argv('example.com', 'passive'))


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
"""
Unit tests for the CVE scanner and Prometheus exporter (v1.7.0).
Run: python3 -m pytest tests/test_cve_scanner.py -v

These tests cover the pure-logic modules without hitting the network.
"""

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / 'server' / 'cgi-bin'))

import cve_scanner
import prometheus_export


class TestEcosystemDetection(unittest.TestCase):

    def test_debian_version_parsing(self):
        self.assertEqual(
            cve_scanner.detect_ecosystem({'ID': 'debian', 'VERSION_ID': '12'}, 'apt'),
            'Debian:12'
        )
        self.assertEqual(
            cve_scanner.detect_ecosystem({'ID': 'debian', 'VERSION_ID': '11.5'}, 'apt'),
            'Debian:11'
        )

    def test_ubuntu(self):
        self.assertEqual(
            cve_scanner.detect_ecosystem({'ID': 'ubuntu', 'VERSION_ID': '24.04'}, 'apt'),
            'Ubuntu'
        )

    def test_debian_derivative_via_id_like(self):
        # Raspbian, Kali, etc.
        self.assertEqual(
            cve_scanner.detect_ecosystem(
                {'ID': 'raspbian', 'ID_LIKE': 'debian', 'VERSION_ID': '12'}, 'apt'
            ),
            'Debian:12'
        )

    def test_rhel_family(self):
        self.assertEqual(
            cve_scanner.detect_ecosystem({'ID': 'rocky', 'VERSION_ID': '9'}, 'dnf'),
            'Rocky Linux'
        )
        self.assertEqual(
            cve_scanner.detect_ecosystem({'ID': 'almalinux', 'VERSION_ID': '9'}, 'dnf'),
            'AlmaLinux'
        )
        self.assertEqual(
            cve_scanner.detect_ecosystem({'ID': 'rhel', 'VERSION_ID': '9'}, 'dnf'),
            'Red Hat'
        )

    def test_fedora_unsupported(self):
        # OSV doesn't reliably cover Fedora
        self.assertIsNone(
            cve_scanner.detect_ecosystem({'ID': 'fedora', 'VERSION_ID': '39'}, 'dnf')
        )

    def test_arch_unsupported(self):
        # v1.7.0 (tyxak): OSV's Arch Linux coverage is too spotty; treat as unsupported.
        self.assertIsNone(
            cve_scanner.detect_ecosystem({'ID': 'arch'}, 'pacman')
        )

    def test_alpine(self):
        self.assertEqual(
            cve_scanner.detect_ecosystem({'ID': 'alpine', 'VERSION_ID': '3.19'}, 'apk'),
            'Alpine:v3.19'
        )

    def test_empty_input(self):
        self.assertIsNone(cve_scanner.detect_ecosystem({}, 'apt'))
        self.assertIsNone(cve_scanner.detect_ecosystem({'ID': 'debian'}, 'unknown'))


class TestPackageHash(unittest.TestCase):

    def test_stable_across_order(self):
        pkgs1 = [
            {'name': 'openssl', 'version': '3.0.11'},
            {'name': 'curl',    'version': '8.1.2'},
        ]
        pkgs2 = list(reversed(pkgs1))
        self.assertEqual(
            cve_scanner.packages_hash(pkgs1),
            cve_scanner.packages_hash(pkgs2),
        )

    def test_changes_with_version(self):
        h1 = cve_scanner.packages_hash([{'name': 'openssl', 'version': '3.0.11'}])
        h2 = cve_scanner.packages_hash([{'name': 'openssl', 'version': '3.0.12'}])
        self.assertNotEqual(h1, h2)

    def test_hash_length(self):
        h = cve_scanner.packages_hash([{'name': 'a', 'version': '1'}])
        self.assertEqual(len(h), 16)

    def test_empty_list(self):
        # Should not raise
        h = cve_scanner.packages_hash([])
        self.assertEqual(len(h), 16)


class TestSeverityExtraction(unittest.TestCase):

    def test_explicit_labels(self):
        s = cve_scanner._severity_from_vuln
        self.assertEqual(s({'database_specific': {'severity': 'CRITICAL'}}), 'critical')
        self.assertEqual(s({'database_specific': {'severity': 'High'}}),     'high')
        self.assertEqual(s({'database_specific': {'severity': 'Important'}}), 'high')
        self.assertEqual(s({'database_specific': {'severity': 'Moderate'}}), 'medium')
        self.assertEqual(s({'database_specific': {'severity': 'Low'}}),      'low')
        self.assertEqual(s({'database_specific': {'severity': 'negligible'}}), 'low')

    def test_cvss_buckets(self):
        # v1.7.0 (tyxak): parser now requires a proper CVSS vector (score + /CVSS:...)
        # to avoid misinterpreting bare numbers. Use valid vectors here.
        s = cve_scanner._severity_from_vuln
        self.assertEqual(s({'severity': [{'score': '9.8/CVSS:3.1/AV:N/AC:L'}]}), 'critical')
        self.assertEqual(s({'severity': [{'score': '7.5/CVSS:3.1/AV:N'}]}),      'high')
        self.assertEqual(s({'severity': [{'score': '5.0/CVSS:3.1/AV:L'}]}),      'medium')
        self.assertEqual(s({'severity': [{'score': '2.0/CVSS:3.1/AV:L'}]}),      'low')
        # Bare numbers no longer count
        self.assertEqual(s({'severity': [{'score': '7.5'}]}), 'unknown')

    def test_unknown_fallback(self):
        self.assertEqual(cve_scanner._severity_from_vuln({}), 'unknown')
        self.assertEqual(cve_scanner._severity_from_vuln({'severity': [{'score': 'garbage'}]}), 'unknown')


class TestSummarize(unittest.TestCase):

    def test_basic(self):
        findings = [
            {'vuln_id': 'CVE-1', 'severity': 'critical'},
            {'vuln_id': 'CVE-2', 'severity': 'high'},
            {'vuln_id': 'CVE-3', 'severity': 'high'},
            {'vuln_id': 'CVE-4', 'severity': 'medium'},
            {'vuln_id': 'CVE-5', 'severity': 'low'},
        ]
        s = cve_scanner.summarize_findings(findings, set())
        self.assertEqual(s['critical'], 1)
        self.assertEqual(s['high'], 2)
        self.assertEqual(s['medium'], 1)
        self.assertEqual(s['low'], 1)
        self.assertEqual(s['ignored'], 0)

    def test_with_ignored(self):
        findings = [
            {'vuln_id': 'CVE-1', 'severity': 'critical'},
            {'vuln_id': 'CVE-2', 'severity': 'high'},
        ]
        s = cve_scanner.summarize_findings(findings, {'CVE-1'})
        self.assertEqual(s['critical'], 0)
        self.assertEqual(s['high'], 1)
        self.assertEqual(s['ignored'], 1)


class TestFixedVersionExtraction(unittest.TestCase):

    def test_single(self):
        vuln = {
            'affected': [{
                'package': {'name': 'openssl'},
                'ranges': [{'events': [{'introduced': '0'}, {'fixed': '3.0.12'}]}]
            }]
        }
        self.assertEqual(
            cve_scanner._extract_fixed_versions(vuln),
            {'openssl': '3.0.12'}
        )

    def test_multiple_fixes(self):
        vuln = {
            'affected': [{
                'package': {'name': 'openssl'},
                'ranges': [
                    {'events': [{'fixed': '3.0.12'}]},
                    {'events': [{'fixed': '1.1.1w'}]},
                ]
            }]
        }
        result = cve_scanner._extract_fixed_versions(vuln)
        self.assertIn('openssl', result)
        self.assertIn('3.0.12', result['openssl'])
        self.assertIn('1.1.1w', result['openssl'])


class TestPrometheusOutput(unittest.TestCase):

    def _mk_ctx(self, **overrides):
        ctx = {
            'server_version': '1.7.0',
            'now': 1700000000,
            'online_ttl': 180,
            'devices': {},
            'monitors': [],
            'monitor_state': {},
            'schedule': [],
            'pending_cmds': {},
            'webhook_log': [],
            'webhook_log_cap': 100,
            'cve_findings': {},
            'cve_ignore': {},
        }
        ctx.update(overrides)
        return ctx

    def test_empty_output_is_valid(self):
        out = prometheus_export.generate_metrics(self._mk_ctx())
        self.assertIn('remotepower_info', out)
        self.assertIn('remotepower_devices_total 0', out)
        self.assertIn('remotepower_devices_online 0', out)

    def test_help_and_type_lines_present(self):
        out = prometheus_export.generate_metrics(self._mk_ctx())
        for family in ('remotepower_devices_total', 'remotepower_device_online',
                       'remotepower_monitor_up', 'remotepower_webhook_deliveries_total'):
            self.assertIn(f'# HELP {family}', out)
            self.assertIn(f'# TYPE {family}', out)

    def test_label_injection_escaped(self):
        ctx = self._mk_ctx(devices={
            'a': {'name': 'in"ject', 'group': '', 'last_seen': 1700000000, 'sysinfo': {}},
        })
        out = prometheus_export.generate_metrics(ctx)
        self.assertIn('name="in\\"ject"', out)
        # Must not contain unescaped double-quote in label
        self.assertNotIn('name="in"ject"', out)

    def test_online_ttl_classification(self):
        ctx = self._mk_ctx(devices={
            'fresh': {'name': 'f', 'group': '', 'last_seen': 1700000000, 'sysinfo': {}},
            'stale': {'name': 's', 'group': '', 'last_seen': 1700000000 - 300, 'sysinfo': {}},
        })
        out = prometheus_export.generate_metrics(ctx)
        self.assertIn('remotepower_devices_online 1', out)

    def test_cve_severity_emission(self):
        ctx = self._mk_ctx(
            devices={'d1': {'name': 'd1', 'group': '', 'last_seen': 1700000000, 'sysinfo': {}}},
            cve_findings={'d1': {'findings': [
                {'vuln_id': 'CVE-1', 'severity': 'critical'},
                {'vuln_id': 'CVE-2', 'severity': 'high'},
                {'vuln_id': 'CVE-3', 'severity': 'high'},
            ]}},
        )
        out = prometheus_export.generate_metrics(ctx)
        self.assertIn('severity="critical"} 1', out)
        self.assertIn('severity="high"} 2', out)
        self.assertIn('severity="medium"} 0', out)

    def test_cve_ignore_respected_in_metrics(self):
        ctx = self._mk_ctx(
            devices={'d1': {'name': 'd1', 'group': '', 'last_seen': 1700000000, 'sysinfo': {}}},
            cve_findings={'d1': {'findings': [
                {'vuln_id': 'CVE-1', 'severity': 'critical'},
                {'vuln_id': 'CVE-2', 'severity': 'critical'},
            ]}},
            cve_ignore={'CVE-1': {'scope': 'global'}},
        )
        out = prometheus_export.generate_metrics(ctx)
        self.assertIn('severity="critical"} 1', out)


if __name__ == '__main__':
    unittest.main()

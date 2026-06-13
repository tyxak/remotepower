#!/usr/bin/env python3
"""Strict version-surface pins + TLS-feature guardrails for v4.5.0 "TrustMatters".

The self-signed-CA story is the headline. The functional test below actually
runs tools/gen-ca.sh and verifies the chain (skipped where openssl is absent);
the rest pin the rollout wiring (agent CA fallback, --ca-fingerprint verification,
the shared nginx snippet, Docker opt-in TLS).

Loosen the TestVersionBumps strict pins to regex on the next bump (see
tests/test_v441.py for the pattern).
"""
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v450", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestVersionBumps(unittest.TestCase):
    """v4.5.0 — loosened to regex on the v4.6.0 bump (live strict pins moved to
    tests/test_v460.py). Doc-housekeeping invariants below stay version-agnostic."""

    def test_server_version(self):
        self.assertRegex(api.SERVER_VERSION, r'^\d+\.\d+\.\d+$')

    def test_agent_versions(self):
        self.assertRegex((_ROOT / 'client/remotepower-agent.py').read_text(),
                         r"\nVERSION\s*=\s*'\d+\.\d+\.\d+'")
        for rel in ('client/remotepower-agent-win.py', 'client/remotepower-agent-mac.py'):
            self.assertRegex((_ROOT / rel).read_text(),
                             r"VERSION\s*=\s*'\d+\.\d+\.\d+'", rel)

    def test_agent_extensionless_in_sync(self):
        self.assertEqual((_ROOT / 'client/remotepower-agent.py').read_bytes(),
                         (_ROOT / 'client/remotepower-agent').read_bytes())

    def test_sw_and_cachebust(self):
        self.assertRegex((_ROOT / 'server/html/sw.js').read_text(),
                         r'remotepower-shell-v\d+\.\d+\.\d+')
        self.assertRegex((_ROOT / 'server/html/index.html').read_text(),
                         r'\?v=\d+\.\d+\.\d+')

    def test_doc_set_keeps_five_versions(self):
        vdocs = sorted(p.name for p in (_ROOT / 'docs').glob('v*.md'))
        self.assertEqual(len(vdocs), 5, f'expected exactly 5 version docs, got {vdocs}')

    def test_v410_rotated_out(self):
        self.assertFalse((_ROOT / 'docs/v4.1.0.md').exists(),
                         'v4.1.0.md should have rotated out of the kept set')

    def test_no_dangling_v410_links(self):
        # Shipped docs must not link the rotated-out v4.1.0.md (CHANGELOG excepted).
        for p in (list((_ROOT / 'docs').rglob('*.md')) + list((_ROOT / 'docs').rglob('*.html'))
                  + [_ROOT / 'README.md']):
            if '-internal' in p.name or p.name == 'CHANGELOG.md':
                continue
            self.assertNotIn('v4.1.0.md', p.read_text(), f'{p} links rotated-out v4.1.0.md')


@unittest.skipUnless(shutil.which('openssl'), 'openssl CLI not available')
class TestGenCaScript(unittest.TestCase):
    """tools/gen-ca.sh must produce a CA + a leaf that verifies against it, and
    --renew must keep the CA stable so enrolled clients keep trust."""

    SCRIPT = _ROOT / 'tools' / 'gen-ca.sh'

    def _fp(self, crt):
        out = subprocess.run(['openssl', 'x509', '-in', str(crt), '-noout',
                              '-fingerprint', '-sha256'], capture_output=True, text=True)
        return out.stdout.split('=', 1)[1].strip()

    def test_generates_verifiable_chain(self):
        d = Path(tempfile.mkdtemp())
        r = subprocess.run(['bash', str(self.SCRIPT), '--host', 'rp.test',
                            '--host', '10.9.8.7', '--dir', str(d)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        for f in ('ca.crt', 'ca.key', 'server.crt', 'server.key'):
            self.assertTrue((d / f).exists(), f'missing {f}')
        # leaf verifies against the CA
        v = subprocess.run(['openssl', 'verify', '-CAfile', str(d / 'ca.crt'),
                            str(d / 'server.crt')], capture_output=True, text=True)
        self.assertIn('OK', v.stdout, v.stderr)
        # SAN carries both the DNS name and the IP
        ext = subprocess.run(['openssl', 'x509', '-in', str(d / 'server.crt'),
                              '-noout', '-ext', 'subjectAltName'],
                             capture_output=True, text=True).stdout
        self.assertIn('rp.test', ext)
        self.assertIn('10.9.8.7', ext)
        # the private keys are not world-readable
        self.assertEqual(oct((d / 'ca.key').stat().st_mode)[-3:], '600')

    def test_renew_keeps_ca_changes_leaf(self):
        d = Path(tempfile.mkdtemp())
        subprocess.run(['bash', str(self.SCRIPT), '--host', 'rp.test', '--dir', str(d)],
                       capture_output=True, text=True, check=True)
        ca1 = self._fp(d / 'ca.crt'); leaf1 = self._fp(d / 'server.crt')
        subprocess.run(['bash', str(self.SCRIPT), '--renew', '--dir', str(d)],
                       capture_output=True, text=True, check=True)
        ca2 = self._fp(d / 'ca.crt'); leaf2 = self._fp(d / 'server.crt')
        self.assertEqual(ca1, ca2, 'CA changed on --renew — clients would lose trust')
        self.assertNotEqual(leaf1, leaf2, 'leaf not re-issued on --renew')


class TestAgentCaTrust(unittest.TestCase):
    """All three agents must add (never replace) a CA trust path and keep strict
    verification, with a fallback to the conventional self-signed CA location."""

    def test_agents_keep_strict_verification_and_fallback(self):
        for rel in ('client/remotepower-agent.py', 'client/remotepower-agent-mac.py'):
            src = (_ROOT / rel).read_text()
            self.assertIn('create_default_context', src, rel)
            self.assertIn('CERT_REQUIRED', src, rel)
            self.assertIn('check_hostname = True', src, rel)
            self.assertIn('load_verify_locations', src, rel)
            self.assertIn('/etc/remotepower/ca.crt', src, rel)  # v4.5.0 fallback
        win = (_ROOT / 'client/remotepower-agent-win.py').read_text()
        self.assertIn('RemotePower', win)
        self.assertIn("'ca.crt'", win)
        self.assertIn('load_verify_locations', win)


class TestInstallerFingerprintVerify(unittest.TestCase):
    """The CA-aware installers must verify a pinned fingerprint and REFUSE on
    mismatch — never trust blindly when --ca-fingerprint is given."""

    def test_linux_and_mac_installers_refuse_on_mismatch(self):
        for rel in ('install-client.sh', 'client/install-macos.sh'):
            src = (_ROOT / rel).read_text()
            self.assertIn('--ca-fingerprint', src, rel)
            self.assertIn('FINGERPRINT MISMATCH', src, rel)
            self.assertIn('RP_CA_BUNDLE', src, rel)

    def test_windows_installer_verifies(self):
        src = (_ROOT / 'client/install-windows.ps1').read_text()
        self.assertIn('CaFingerprint', src)
        self.assertIn('GetCertHashString', src)
        self.assertIn('MISMATCH', src)


class TestNginxSharedSnippet(unittest.TestCase):
    """HTTP and HTTPS server blocks must share one location snippet (no drift),
    and it must serve /ca.crt."""

    def test_shared_locations_snippet(self):
        snip = _ROOT / 'server/conf/remotepower-locations.conf'
        self.assertTrue(snip.exists())
        self.assertIn('location = /ca.crt', snip.read_text())
        conf = (_ROOT / 'server/conf/remotepower.conf').read_text()
        self.assertIn('include snippets/remotepower-locations.conf;', conf)

    def test_installer_ships_snippet(self):
        ins = (_ROOT / 'install-server.sh').read_text()
        self.assertIn('remotepower-locations.conf', ins)
        self.assertIn('/etc/nginx/snippets', ins)


class TestDockerOptInTls(unittest.TestCase):
    def test_entrypoint_and_compose_wire_tls(self):
        ep = (_ROOT / 'docker/entrypoint.sh').read_text()
        self.assertIn('RP_TLS_SELFSIGNED', ep)
        self.assertIn('rp-gen-ca', ep)
        self.assertTrue((_ROOT / 'docker/nginx-docker-tls.conf').exists())
        self.assertTrue((_ROOT / 'docker/nginx-docker-locations.conf').exists())
        df = (_ROOT / 'Dockerfile').read_text()
        self.assertIn('openssl', df)
        self.assertIn('gen-ca.sh', df)


if __name__ == '__main__':
    unittest.main()

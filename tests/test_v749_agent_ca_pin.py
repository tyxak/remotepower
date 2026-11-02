#!/usr/bin/env python3
"""7.4.9 agent security pass: pinning a CA by its fingerprint must pin the whole file that gets trusted.

The installers can trust a self-signed CA. They fetch `ca.crt` without checking the server's certificate (the CA that signed it is
the thing being fetched), and the only authentication is a fingerprint the operator typed from `tools/gen-ca.sh`. The check was
`openssl x509 -in ca.crt -noout -fingerprint -sha256`, and `openssl x509` reads the FIRST certificate of a file and says nothing
about the rest. The file was then installed as it was and loaded by the agent with `load_verify_locations(cafile=...)`, which
trusts every certificate in it. The real CA certificate is public (the server hands it to anyone), so whoever sits between the
installer and the server on that first fetch can send "the real CA, then my own CA": the fingerprint of the first matches, and
the agent trusts both. That is the man-in-the-middle the fingerprint exists to stop, and from there the agent's token, its
telemetry and every command it is given belong to the attacker.

Each installer now writes out only the certificate whose fingerprint it checked, and so does the one-line installer that the
server renders (`_AGENT_INSTALL_SH` in server/cgi-bin/api.py), which had the same defect and is held below.

The shell installers run for real against the rig in tests/installer_harness.py. The macOS installer needs Darwin and root, so its
CA block is cut out of the script and run on its own; the PowerShell installer's likewise, under PowerShell if it is installed.
"""
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import installer_harness as H  # noqa: E402

ROOT = H.ROOT
INSTALL_CLIENT = Path(os.environ.get('RP_TEST_INSTALL_CLIENT') or ROOT / 'install-client.sh')
ENTRYPOINT = Path(os.environ.get('RP_TEST_AGENT_ENTRYPOINT') or ROOT / 'docker' / 'agent-entrypoint.sh')
INSTALL_MACOS = Path(os.environ.get('RP_TEST_INSTALL_MACOS') or ROOT / 'client' / 'install-macos.sh')
INSTALL_WINDOWS = Path(os.environ.get('RP_TEST_INSTALL_WINDOWS') or ROOT / 'client' / 'install-windows.ps1')
SERVER_API = Path(os.environ.get('RP_TEST_API') or ROOT / 'server' / 'cgi-bin' / 'api.py')

TOOLS = bool(shutil.which('openssl') and shutil.which('curl') and shutil.which('bash'))
PWSH = shutil.which('pwsh')


def count_certs(pem_bytes):
    return len(re.findall(rb'-----BEGIN CERTIFICATE-----', pem_bytes))


def fingerprints(pem_bytes):
    """SHA-256 fingerprint of every certificate in a PEM bundle, as 'AA:BB:...'."""
    out = []
    for block in re.findall(rb'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', pem_bytes, re.S):
        r = subprocess.run(['openssl', 'x509', '-noout', '-fingerprint', '-sha256'], input=block, capture_output=True,
                           check=True)
        out.append(r.stdout.decode().strip().split('=', 1)[1])
    return out


@unittest.skipUnless(TOOLS, 'needs openssl, curl and bash')
class _Pair(unittest.TestCase):
    """The operator's CA, an attacker's CA, and the file a man in the middle serves: the real one first, then his."""

    @classmethod
    def setUpClass(cls):
        cls.root_tmp = Path(tempfile.mkdtemp(prefix='rp-v749-ca-'))
        (cls.root_tmp / 'a').mkdir()
        (cls.root_tmp / 'b').mkdir()
        cls.tls, cls.fp = H.make_ca(cls.root_tmp / 'a')
        cls.evil_tls, cls.evil_fp = H.make_ca(cls.root_tmp / 'b', host='attacker.example')
        cls.real = (cls.tls / 'ca.crt').read_bytes()
        cls.evil = (cls.evil_tls / 'ca.crt').read_bytes()
        cls.bundle = cls.real + cls.evil

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root_tmp, ignore_errors=True)

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='rp-v749-inst-'))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def assertOnlyTheCheckedCertificate(self, installed, what):
        self.assertEqual(count_certs(installed), 1, f'{what} installed {count_certs(installed)} certificates')
        self.assertEqual(fingerprints(installed), fingerprints(self.real), f'{what} installed a different certificate')


class TestThePremise(_Pair):
    """The control: the attack is real, so a pass below means something."""

    def test_openssl_checks_only_the_first_certificate_of_a_bundle(self):
        self.assertEqual(len(fingerprints(self.bundle)), 2)
        r = subprocess.run(['openssl', 'x509', '-noout', '-fingerprint', '-sha256'], input=self.bundle, capture_output=True)
        self.assertEqual(r.stdout.decode().strip().split('=', 1)[1], self.fp,
                         'the fingerprint the installers compare is the first certificate only')

    def test_the_agents_tls_context_trusts_every_certificate_in_the_file(self):
        bundle = self.tmp / 'bundle.crt'
        bundle.write_bytes(self.bundle)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cafile=str(bundle))
        self.assertEqual(ctx.cert_store_stats().get('x509_ca'), 2)


class TestInstallClient(_Pair):

    def setUp(self):
        super().setUp()
        self.srv = H.Server(self.tls)
        self.addCleanup(self.srv.close)
        self.srv.ca_body = self.bundle
        self.sb = H.Sandbox(self.tmp)
        self.dist = self.tmp / 'dist'
        (self.dist / 'client').mkdir(parents=True)
        shutil.copy(INSTALL_CLIENT, self.dist / 'install-client.sh')
        agent = self.dist / 'client' / 'remotepower-agent'
        agent.write_text(H.AGENT_STUB)
        agent.chmod(0o755)
        shutil.copy(ROOT / 'client' / 'remotepower-agent.service', self.dist / 'client' / 'remotepower-agent.service')

    def run_installer(self, *args):
        return self.sb.run(shutil.which('bash'), self.dist / 'install-client.sh', args)

    def test_a_bundle_that_starts_with_the_real_ca_installs_only_the_real_ca(self):
        r = self.run_installer('--server', self.srv.url, '--pin', '123456', '--ca-fingerprint', self.fp)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertOnlyTheCheckedCertificate((self.sb.root / 'etc/remotepower/ca.crt').read_bytes(), 'install-client.sh')

    def test_the_ordinary_single_certificate_is_installed_as_it_was(self):
        self.srv.ca_body = None
        r = self.run_installer('--server', self.srv.url, '--pin', '123456', '--ca-fingerprint', self.fp)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual((self.sb.root / 'etc/remotepower/ca.crt').read_bytes(), self.real)

    def test_a_bundle_whose_first_certificate_is_not_the_pinned_one_is_refused(self):
        self.srv.ca_body = self.evil + self.real
        r = self.run_installer('--server', self.srv.url, '--pin', '123456', '--ca-fingerprint', self.fp)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('MISMATCH', r.stdout + r.stderr)
        self.assertFalse((self.sb.root / 'etc/remotepower/ca.crt').exists())


class TestAgentEntrypoint(_Pair):
    """docker/agent-entrypoint.sh fetches the CA over plain HTTP, so the fingerprint is all there is. Its install_ca function
    is run on its own with the paths pointed at a scratch directory."""

    def run_install_ca(self, body):
        text = ENTRYPOINT.read_text()
        m = re.search(r'^install_ca\(\) \{.*?^\}\n', text, re.S | re.M)
        self.assertIsNotNone(m, 'install_ca() not found in the entrypoint')
        conf = self.tmp / 'etc-remotepower'
        conf.mkdir()
        func = m.group(0).replace('/etc/remotepower', str(conf))
        served = self.tmp / 'served.crt'
        served.write_bytes(body)
        stub = self.tmp / 'bin'
        stub.mkdir()
        curl = stub / 'curl'
        curl.write_text('#!/bin/sh\nout=""\nwhile [ $# -gt 0 ]; do [ "$1" = "-o" ] && out="$2"; shift; done\ncp "$SERVED" "$out"\n')
        curl.chmod(0o755)
        for tool in ('openssl', 'sed', 'tr', 'mktemp', 'rm', 'chmod', 'mv', 'cat', 'cp', 'printf', 'sh'):
            real = shutil.which(tool)
            if real and not (stub / tool).exists():
                (stub / tool).symlink_to(real)
        script = 'set -eu\nlog() { echo "[entrypoint] $*"; }\n' + func + '\ninstall_ca\n'
        env = {'PATH': str(stub), 'RP_SERVER': 'https://rp.example', 'RP_CA_FINGERPRINT': self.fp, 'SERVED': str(served),
               'HOME': str(self.tmp)}
        r = subprocess.run([shutil.which('sh'), '-c', script], env=env, capture_output=True, text=True, timeout=60)
        return r, conf / 'ca.crt'

    def test_a_bundle_that_starts_with_the_real_ca_installs_only_the_real_ca(self):
        r, ca = self.run_install_ca(self.bundle)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertOnlyTheCheckedCertificate(ca.read_bytes(), 'agent-entrypoint.sh')

    def test_the_ordinary_certificate_is_installed(self):
        r, ca = self.run_install_ca(self.real)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(fingerprints(ca.read_bytes()), fingerprints(self.real))

    def test_a_wrong_first_certificate_is_refused(self):
        r, ca = self.run_install_ca(self.evil + self.real)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(ca.exists())


class TestMacInstaller(_Pair):
    """The CA block of install-macos.sh, cut out and run (the rest of the script needs Darwin, root and launchd)."""

    def test_a_bundle_that_starts_with_the_real_ca_installs_only_the_real_ca(self):
        text = INSTALL_MACOS.read_text()
        helpers = re.search(r"^RED=.*?^die\(\).*?\n", text, re.S | re.M)
        block = re.search(r"^norm_fp\(\).*?(?=^info \"Installing agent to)", text, re.S | re.M)
        self.assertTrue(helpers and block, 'could not cut the CA block out of install-macos.sh')
        conf = self.tmp / 'etc-remotepower'
        served = self.tmp / 'ca-file.crt'
        served.write_bytes(self.bundle)
        script = ('set -euo pipefail\n' + helpers.group(0) +
                  f'SERVER=https://rp.example; CA_FP="{self.fp}"; CA_SRC="{served}"\n' +
                  block.group(0).replace('/etc/remotepower', str(conf)))
        r = subprocess.run([shutil.which('bash'), '-c', script], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertOnlyTheCheckedCertificate((conf / 'ca.crt').read_bytes(), 'install-macos.sh')


class TestServerRenderedInstaller(_Pair):
    """The CA block of the one-line installer the server renders at /install, cut out of api.py and run in bash."""

    def run_block(self, served_bytes, fingerprint=None):
        text = SERVER_API.read_text()
        block = re.search(r"^# Optional self-signed CA pin\..*?^  echo \"\[\+\] CA fingerprint verified\"\nfi\n", text, re.S | re.M)
        self.assertIsNotNone(block, 'could not cut the CA block out of _AGENT_INSTALL_SH')
        served = self.tmp / 'served.crt'
        served.write_bytes(served_bytes)
        conf = self.tmp / 'conf'
        script = (
            'set -uo pipefail\n'
            'die() { echo "$*" >&2; exit 1; }\n'
            'have() { command -v "$1" >/dev/null 2>&1; }\n'
            f'_dl_unchecked() {{ cp "{served}" "$2"; }}\n'
            f'CONF="{conf}"; CA_FP="{fingerprint or self.fp}"; RP_SERVER=https://rp.example\n'
            'mkdir -p "$CONF"\n' + block.group(0))
        r = subprocess.run([shutil.which('bash'), '-c', script], capture_output=True, text=True, timeout=60)
        return r, conf / 'ca.crt'

    def test_a_bundle_that_starts_with_the_real_ca_installs_only_the_real_ca(self):
        r, installed = self.run_block(self.bundle)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertOnlyTheCheckedCertificate(installed.read_bytes(), 'the server-rendered installer')

    def test_the_ordinary_single_certificate_is_installed(self):
        r, installed = self.run_block(self.real)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(fingerprints(installed.read_bytes()), fingerprints(self.real))
        self.assertEqual(count_certs(installed.read_bytes()), 1)

    def test_a_bundle_whose_first_certificate_is_not_the_pinned_one_is_refused(self):
        r, installed = self.run_block(self.evil + self.real)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('mismatch', r.stdout + r.stderr)
        self.assertFalse(installed.exists(), 'a refused CA never lands where the agent would trust it')

    def test_a_file_that_is_not_a_certificate_is_refused(self):
        r, installed = self.run_block(b'not a certificate\n')
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(installed.exists())


@unittest.skipUnless(PWSH and TOOLS, 'needs PowerShell (pwsh) and openssl')
class TestWindowsInstaller(_Pair):
    """The CA block of install-windows.ps1, cut out and run under PowerShell."""

    def test_a_bundle_that_starts_with_the_real_ca_installs_only_the_real_ca(self):
        text = INSTALL_WINDOWS.read_text()
        m = re.search(r"^\$caPath = Join-Path.*?(?=^# ── Get the agent)", text, re.S | re.M)
        self.assertIsNotNone(m, 'could not cut the CA block out of install-windows.ps1')
        data = self.tmp / 'data'
        data.mkdir()
        served = self.tmp / 'ca-file.crt'
        served.write_bytes(self.bundle)
        script = (f"$ErrorActionPreference = 'Stop'\n$dataDir = '{data}'\n$env:TEMP = '{self.tmp}'\n"
                  f"$Server = 'https://rp.example'\n$Ca = '{served}'\n$CaFingerprint = '{self.fp}'\n" + m.group(0))
        r = subprocess.run([PWSH, '-NoProfile', '-NonInteractive', '-Command', script], capture_output=True, text=True,
                           timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertOnlyTheCheckedCertificate((data / 'ca.crt').read_bytes(), 'install-windows.ps1')


if __name__ == '__main__':
    unittest.main()

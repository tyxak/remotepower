#!/usr/bin/env python3
"""8.0.0: a certificate that a CA of this product signs names the key that signed it.

RFC 5280, 4.2.1.1, asks every CA to put the authority key identifier into the certificates it issues. OpenSSL 4.1 refuses a certificate without it
("certificate verify failed: Missing Authority Key Identifier"), and so does Python from 3.13 on, which verifies in strict mode and is what the agent
runs. The two generators of this product, `tools/gen-ca.sh` (the installers and the Docker image run it) and the Settings button that calls
`_tls_gen_self_signed`, issued a server certificate without it. Nothing noticed for years: the tests that were to hold "a chain that verifies" ran
`openssl verify` without `-x509_strict`, which accepts such a certificate. A system update in the middle of a release run moved this machine to
OpenSSL 4.1.0 and Python 3.14.9, and the one test that runs a real agent against a real HTTPS server then failed every time (no heartbeat in 90 s).

Three layers: what each generator issues, read back; a handshake made the way the agent makes it, with strict checking switched on by name so that
the result does not depend on the Python version's default; and a census of every place in the product that signs a certificate, by syntax, so a
third generator cannot be added without it.
"""
import ast
import importlib.util
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
except ImportError:                                         # pragma: no cover
    x509 = hashes = None

_API = None


def api():
    global _API
    if _API is None:
        spec = importlib.util.spec_from_file_location("api_v800_certs", _CGI / "api.py")
        _API = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_API)
    return _API


def handshake(cert, key, ca, host):
    """The server presents `cert`; a client verifies it against `ca` the way the agent does (create_default_context), strict checking on.
    Returns None when the handshake worked and the client's error text when it did not."""
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(str(cert), str(key))
    client = ssl.create_default_context(cafile=str(ca))
    client.verify_flags |= ssl.VERIFY_X509_STRICT
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(15)

    def serve():
        try:
            conn, _ = listener.accept()
            with server.wrap_socket(conn, server_side=True) as tls:
                tls.recv(1)
        except (OSError, ssl.SSLError):
            pass                                            # the client refused the certificate: its error is the one that matters

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        raw = socket.create_connection(("127.0.0.1", listener.getsockname()[1]), timeout=15)
        with client.wrap_socket(raw, server_hostname=host) as tls:
            tls.send(b"x")
        return None
    except ssl.SSLError as exc:
        return str(exc)
    finally:
        listener.close()
        thread.join(timeout=5)


def extension(cert, cls):
    return cert.extensions.get_extension_for_class(cls).value


@unittest.skipUnless(x509 is not None, "cryptography is not installed")
class CertificatesNameTheirIssuer:
    """What a generator issues. The subclasses say which generator, `issue(dir)` writes ca.crt, server.crt and server.key into it."""

    HOST = "127.0.0.1"

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="rp-v800-certs-"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.issue(self.dir)
        self.leaf = x509.load_pem_x509_certificate((self.dir / "server.crt").read_bytes())
        self.ca = x509.load_pem_x509_certificate((self.dir / "ca.crt").read_bytes())

    def test_the_server_certificate_names_the_key_of_the_ca_that_signed_it(self):
        akid = extension(self.leaf, x509.AuthorityKeyIdentifier)
        self.assertEqual(akid.key_identifier, extension(self.ca, x509.SubjectKeyIdentifier).digest)

    def test_the_server_certificate_has_its_own_subject_key_identifier(self):
        ski = extension(self.leaf, x509.SubjectKeyIdentifier)
        self.assertEqual(ski.digest, x509.SubjectKeyIdentifier.from_public_key(self.leaf.public_key()).digest)

    def test_a_client_that_verifies_strictly_accepts_the_chain(self):
        self.assertIsNone(handshake(self.dir / "server.crt", self.dir / "server.key", self.dir / "ca.crt", self.HOST))


class TestTheSettingsGenerator(CertificatesNameTheirIssuer, unittest.TestCase):

    def issue(self, out):
        api()._tls_gen_self_signed([self.HOST, "rp.test"], out)

    def test_a_second_issue_keeps_the_ca_and_still_names_it(self):
        fingerprint = self.ca.fingerprint(hashes.SHA256())
        api()._tls_gen_self_signed([self.HOST], self.dir)
        again = x509.load_pem_x509_certificate((self.dir / "server.crt").read_bytes())
        self.assertEqual(x509.load_pem_x509_certificate((self.dir / "ca.crt").read_bytes()).fingerprint(hashes.SHA256()), fingerprint)
        self.assertEqual(extension(again, x509.AuthorityKeyIdentifier).key_identifier, extension(self.ca, x509.SubjectKeyIdentifier).digest)
        self.assertIsNone(handshake(self.dir / "server.crt", self.dir / "server.key", self.dir / "ca.crt", self.HOST))


@unittest.skipUnless(shutil.which("openssl") and shutil.which("bash"), "needs openssl and bash")
class TestTheInstallerTool(CertificatesNameTheirIssuer, unittest.TestCase):

    def issue(self, out):
        r = subprocess.run(["bash", str(_ROOT / "tools" / "gen-ca.sh"), "--host", self.HOST, "--dir", str(out)], capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


# ── every place that signs a certificate ────────────────────────────────────────────────────────────────────────────────────────────

def issued_without_identifier(source):
    """The functions of `source` that build a certificate whose issuer is not its own subject (a CA signing another's) and never name an
    AuthorityKeyIdentifier. Returns (certificates built by a CA, names of the functions that fail)."""
    tree = ast.parse(source)
    issued, bad = 0, []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for stmt in ast.walk(fn):
            if not isinstance(stmt, (ast.Assign, ast.Return, ast.Expr)):
                continue
            subjects, issuers, has_builder = [], [], False
            for n in ast.walk(stmt):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                    if n.func.attr == "CertificateBuilder":
                        has_builder = True
                    elif n.func.attr == "subject_name" and n.args:
                        subjects.append(ast.dump(n.args[0]))
                    elif n.func.attr == "issuer_name" and n.args:
                        issuers.append(ast.dump(n.args[0]))
            if not has_builder or not issuers:
                continue
            if issuers != subjects:                         # signed by another certificate: a CA's leaf
                issued += 1
                names = {n.attr for n in ast.walk(fn) if isinstance(n, ast.Attribute)} | {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
                if "AuthorityKeyIdentifier" not in names:
                    bad.append(fn.name)
    return issued, bad


OLD_LEAF = """
def old(ca_cert, ca_key, leaf_key, name):
    return (x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256()))
"""

SELF_SIGNED = """
def root(key, name):
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).sign(key, hashes.SHA256()))
"""


class TestEveryCaNamesItself(unittest.TestCase):

    def test_the_census_sees_a_certificate_that_a_ca_signs_without_the_identifier(self):
        """The control: the shape of the old leaf, which this census exists to find, and a self-signed one, which it leaves alone."""
        self.assertEqual(issued_without_identifier(OLD_LEAF), (1, ["old"]))
        self.assertEqual(issued_without_identifier(SELF_SIGNED), (0, []))

    def test_every_certificate_the_server_signs_for_another_names_its_issuer(self):
        issued, bad, signers = 0, [], []
        for path in sorted(_CGI.glob("*.py")):
            text = path.read_text()
            if "CertificateBuilder" not in text:
                continue
            n, failing = issued_without_identifier(text)
            issued += n
            if n:
                signers.append(path.name)
            bad += ["%s:%s" % (path.name, f) for f in failing]
        # The two CAs (this one's and the KMIP one) sign themselves, so what is counted is the leaves: the KMIP client and server certificates
        # and the Settings generator's server certificate. A count below that means the scan has stopped seeing them.
        self.assertTrue({"api.py", "kmip_handlers.py"} <= set(signers), "the census sees signed certificates only in %s" % signers)
        self.assertGreaterEqual(issued, 2, "the census found %d certificates signed by a CA, in %s" % (issued, signers))
        self.assertEqual(bad, [], "%d of %d certificates signed by a CA name no authority key identifier" % (len(bad), issued))

    def test_every_script_that_signs_a_request_puts_the_identifier_in_its_extensions(self):
        scripts, bad = [], []
        for path in sorted(list(_ROOT.glob("*.sh")) + list(_ROOT.glob("tools/*.sh")) + list(_ROOT.glob("packaging/*.sh")) + list(_ROOT.glob("docker/*.sh"))
                           + list(_ROOT.glob("client/*.sh"))):
            text = path.read_text(errors="replace")
            if re.search(r"openssl\s+x509\s+-req\b", text):
                scripts.append(path.name)
                if not re.search(r"^\s*authorityKeyIdentifier\s*=", text, re.M):
                    bad.append(path.name)
        self.assertIn("gen-ca.sh", scripts, "the census no longer finds the CA tool: %s" % scripts)
        self.assertEqual(bad, [], "%d of %d scripts that sign a request leave out the authority key identifier" % (len(bad), len(scripts)))


if __name__ == "__main__":
    unittest.main()

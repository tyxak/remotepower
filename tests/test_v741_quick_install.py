#!/usr/bin/env python3
"""v7.4.1, issue #34: Add host -> Quick install on a server with its own CA.

The line the dashboard showed, `wget -qO- "<server>/install?t=..." | sudo sh`,
cannot work against a server whose certificate no trust store holds: wget refuses
it, `-q` hides why, and `sh` is fed an empty script, so nothing happens and
nothing says so. A server that has its own CA (the Docker image with
RP_TLS_SELFSIGNED=1, or Settings -> Security -> Self-signed certificate) now
reports the CA's fingerprint when a token is minted, and the dashboard shows a
second line that pins it.

Everything here runs the strings the dashboard function builds, against a real
HTTPS server signed by a CA no trust store holds.
"""
import importlib.util
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import installer_harness as H  # noqa: E402
from srcpin import js_function  # noqa: E402

try:
    from py_mini_racer import MiniRacer
    _HAVE_V8 = True
except Exception:                                  # pragma: no cover - env dependent
    _HAVE_V8 = False

ROOT = H.ROOT
APP_JS = (ROOT / "server/html/static/js/app.js").read_text()
BASH = shutil.which("bash")
TOOLS = bool(shutil.which("openssl") and shutil.which("curl") and shutil.which("wget") and BASH)


def lines(server, token, fp):
    ctx = MiniRacer()
    ctx.eval(js_function(APP_JS, "quickInstallLines"))
    return json.loads(ctx.eval(
        "JSON.stringify(quickInstallLines(%s, %s, %s))"
        % (json.dumps(server), json.dumps(token), json.dumps(fp))))


@unittest.skipUnless(_HAVE_V8, "py_mini_racer (V8) not installed")
class TestTheLinesTheDashboardBuilds(unittest.TestCase):
    FP = ":".join(["AB"] * 32)

    def test_the_standard_line_is_what_it_was(self):
        got = lines("https://rp.example:8460", "tok", "")
        self.assertEqual(got["linux"], 'wget -qO- "https://rp.example:8460/install?t=tok" | sudo sh')
        self.assertTrue(got["win"].startswith("powershell -ExecutionPolicy Bypass"))

    def test_there_is_no_pinned_line_for_a_server_without_a_ca(self):
        self.assertEqual(lines("https://rp.example", "tok", "")["linuxPinned"], "")

    def test_the_pinned_line_carries_the_port_the_token_and_both_forms_of_the_fingerprint(self):
        line = lines("https://rp.example:8460", "tok", self.FP)["linuxPinned"]
        self.assertIn('"https://rp.example:8460/ca.crt"', line)
        self.assertIn('"https://rp.example:8460/install?t=tok"', line)
        self.assertIn("--ca-fingerprint " + self.FP, line)
        self.assertIn('= "' + "AB" * 32 + '"', line)             # the compare, without colons
        # The certificate check is off for ONE fetch, the CA, which the compare then
        # authenticates. The installer is fetched trusting that CA and nothing else.
        self.assertEqual(len(re.findall(r"curl -\w*k\b", line)), 1, line)
        self.assertEqual(line.count("--cacert"), 1)
        self.assertLess(line.index('curl -fsSLk'), line.index("--cacert"))

    def test_the_dashboard_shows_the_second_line_only_when_the_server_reported_a_ca(self):
        fn = js_function(APP_JS, "generateQuickInstall")
        self.assertIn("quickInstallLines(server, token, (data && data.ca_fingerprint) || '')", fn)
        self.assertIn("if (linuxPinned)", fn)


@unittest.skipUnless(_HAVE_V8 and TOOLS, "needs V8, openssl, curl, wget and bash")
class TestRunningThem(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ca_tmp = Path(tempfile.mkdtemp(prefix="rp-v741-qi-"))
        cls.tls, cls.fp = H.make_ca(cls.ca_tmp)
        other = cls.ca_tmp / "other"
        other.mkdir()
        cls.other_tls, cls.other_fp = H.make_ca(other)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.ca_tmp, ignore_errors=True)

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rp-v741-qirun-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.srv = H.Server(self.tls)
        self.addCleanup(self.srv.close)
        self.sb = H.Sandbox(self.tmp)

    def run_line(self, line):
        return self.sb.run(BASH, "-c", [line])

    def test_the_pinned_line_enrols_a_host_against_a_self_signed_server(self):
        line = lines(self.srv.url, "tok-qi", self.fp)["linuxPinned"]
        r = self.run_line(line)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual((self.sb.root / "etc/remotepower/ca.crt").read_bytes(),
                         (self.tls / "ca.crt").read_bytes())
        self.assertIn(f"AGENT enroll-token --server {self.srv.url} --token tok-qi", self.sb.calls())
        self.assertEqual(self.sb.running_creds(), "tok-qi-credentials")
        paths = [p for p, _h in self.srv.requests]
        self.assertLess(paths.index("/ca.crt"), paths.index("/install"),
                        "the installer was fetched before the CA was checked")

    def test_a_substituted_ca_is_refused_before_the_installer_is_fetched(self):
        """The property the line exists for: nothing the server sends is run, or
        even asked for, until the CA matches the fingerprint the dashboard gave."""
        self.srv.ca_body = (self.other_tls / "ca.crt").read_bytes()
        line = lines(self.srv.url, "tok-qi", self.fp)["linuxPinned"]
        r = self.run_line(line)
        self.assertNotEqual(r.returncode, 0, "a CA with the wrong fingerprint was accepted")
        paths = [p for p, _h in self.srv.requests]
        self.assertNotIn("/install", paths, "the installer was fetched from an unverified server")
        self.assertFalse((self.sb.root / "etc/remotepower").exists())
        self.assertNotIn("AGENT", self.sb.calls())

    def test_the_standard_line_fails_silently_against_a_self_signed_server(self):
        """The report, reproduced: wget refuses the certificate, -q says nothing,
        sh is fed an empty script and exits 0. This is why the second line exists."""
        line = lines(self.srv.url, "tok-qi", "")["linux"]
        r = self.run_line(line)
        self.assertEqual((r.returncode, r.stdout.strip(), r.stderr.strip()), (0, "", ""),
                         "the standard line is expected to fail without a word here")
        self.assertFalse((self.sb.root / "usr/local/bin/remotepower-agent").exists())
        self.assertNotIn("AGENT", self.sb.calls())


class TestTheServerReportsItsCa(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ca_tmp = Path(tempfile.mkdtemp(prefix="rp-v741-srvca-"))
        cls.tls, cls.fp = H.make_ca(cls.ca_tmp) if (shutil.which("openssl") and BASH) else (None, None)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.ca_tmp, ignore_errors=True)

    def fresh_api(self, with_ca):
        d = Path(tempfile.mkdtemp(prefix="rp-v741-data-"))
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        if with_ca:
            (d / "tls").mkdir()
            shutil.copy(self.tls / "ca.crt", d / "tls" / "ca.crt")
        os.environ["RP_DATA_DIR"] = str(d)
        sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))
        spec = importlib.util.spec_from_file_location("api_v741_qi", ROOT / "server/cgi-bin/api.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m

    def mint(self, api):
        cap = {}

        def respond(status, data=None):
            cap["status"], cap["data"] = status, data
            raise api.HTTPError(status, data)
        api.respond = respond
        api.audit_log = lambda *a, **k: None
        api.require_admin_auth = lambda *a, **k: "admin"
        api.method = lambda: "POST"
        api.get_json_obj = lambda: {"label": "quick-install", "expires_in": 3600}
        try:
            api.handle_enroll_token_create()
        except api.HTTPError:
            pass
        return cap["status"], cap["data"]

    @unittest.skipUnless(shutil.which("openssl") and BASH, "needs openssl")
    def test_a_server_with_a_ca_reports_its_fingerprint_with_the_token(self):
        st, body = self.mint(self.fresh_api(with_ca=True))
        self.assertEqual(st, 201)
        self.assertEqual(body["ca_fingerprint"], self.fp)
        self.assertTrue(body["token"])

    def test_a_server_without_one_reports_none(self):
        st, body = self.mint(self.fresh_api(with_ca=False))
        self.assertEqual(st, 201)
        self.assertEqual(body["ca_fingerprint"], "")

    def test_a_file_that_is_not_a_certificate_is_none_not_an_error(self):
        api = self.fresh_api(with_ca=False)
        (api.DATA_DIR / "tls").mkdir()
        (api.DATA_DIR / "tls" / "ca.crt").write_text("not a certificate")
        st, body = self.mint(api)
        self.assertEqual(st, 201)
        self.assertEqual(body["ca_fingerprint"], "")

    @unittest.skipUnless(shutil.which("openssl") and BASH, "needs openssl")
    def test_the_format_is_the_one_the_installer_and_openssl_use(self):
        api = self.fresh_api(with_ca=True)
        self.assertRegex(api._self_signed_ca_fingerprint(), r"^([0-9A-F]{2}:){31}[0-9A-F]{2}$")


if __name__ == "__main__":
    unittest.main()

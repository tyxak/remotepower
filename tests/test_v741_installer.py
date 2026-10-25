#!/usr/bin/env python3
"""v7.4.1, issue #34 and the re-enroll report: the served agent installer.

Run for real, as a user runs it (the script piped into `sh -s`), against an
HTTPS server whose certificate is signed by a CA that no trust store holds: the
Docker server with RP_TLS_SELFSIGNED=1. The rig is tests/installer_harness.py.

What broke, and what each test holds:

  * `--ca-fingerprint` fetched ca.crt over verified HTTPS, so curl refused the
    very certificate it was about to pin (curl error 60). Every later download
    also ignored the pinned CA.
  * The unverified ca.crt was written to the agent's default CA path BEFORE the
    fingerprint was compared, and a mismatch exited and left it there.
  * A download that failed said nothing under `wget -q`.
  * Re-enrolling a host whose agent was running wrote the new credentials and
    left the agent on the old ones: `enable --now` does nothing for a unit that
    is already running, and this script never restarted it.

The assertions are about the host afterwards (is the RUNNING agent holding the
new credentials?), not about what the script text contains.
"""
import os
import shutil
import ssl
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import installer_harness as H  # noqa: E402

SH = shutil.which("sh")
DASH = shutil.which("dash") or os.environ.get("RP_DASH_BIN")
HAVE_TLS_TOOLS = bool(shutil.which("openssl") and shutil.which("curl") and SH)


def _fetch_script(srv, token):
    """The served script, fetched the way the Quick-install line fetches it. The
    fetch is not what is under test, so the certificate is not checked here."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(f"{srv.url}/install?t={token}", context=ctx) as r:
        return r.read().decode()


@unittest.skipUnless(HAVE_TLS_TOOLS, "needs openssl, curl and sh")
class _Rig(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ca_tmp = Path(tempfile.mkdtemp(prefix="rp-v741-ca-"))
        cls.tls, cls.fp = H.make_ca(cls.ca_tmp)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.ca_tmp, ignore_errors=True)

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rp-v741-inst-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.srv = H.Server(self.tls)
        self.addCleanup(self.srv.close)

    def install(self, token="tok-new", args=("--ca-fingerprint",), shell=SH,
                with_curl=True, with_wget=True, env=None, fp=None, sandbox=None):
        sb = sandbox or H.Sandbox(self.tmp, with_curl=with_curl, with_wget=with_wget)
        script = _fetch_script(self.srv, token)
        a = list(args)
        if a and a[-1] == "--ca-fingerprint":
            a.append(fp if fp is not None else self.fp)
        r = sb.run_piped(shell, script, a, env=env)
        return sb, r

    def paths(self, sb):
        return {"ca": sb.root / "etc/remotepower/ca.crt",
                "env": sb.root / "etc/remotepower/agent.env",
                "bin": sb.root / "usr/local/bin/remotepower-agent",
                "unit": sb.root / "etc/systemd/system/remotepower-agent.service"}


class TestPinningASelfSignedServer(_Rig):

    def check_enrols(self, **kw):
        sb, r = self.install(**kw)
        out = r.stdout + r.stderr
        self.assertEqual(r.returncode, 0, out)
        p = self.paths(sb)
        self.assertEqual(p["ca"].read_bytes(), (self.tls / "ca.crt").read_bytes(),
                         "the verified CA was not installed")
        self.assertIn("RP_CA_BUNDLE=/etc/remotepower/ca.crt", p["env"].read_text())
        self.assertTrue(p["bin"].exists())
        calls = sb.calls()
        self.assertIn(f"AGENT enroll-token --server {self.srv.url} --token tok-new", calls)
        self.assertIn(f"AGENT-ENV RP_CA_BUNDLE={p['ca']}", calls,
                      "the enrol step did not trust the pinned CA")
        # The unit names the REAL binary path, not the staging root.
        self.assertIn("ExecStart=/usr/local/bin/remotepower-agent run", p["unit"].read_text())
        paths = [pth for pth, _h in self.srv.requests]
        for need in ("/install", "/ca.crt", "/api/agent/download", "/api/agent/version"):
            self.assertIn(need, paths, f"{need} was never requested: {paths}")
        return sb

    def test_enrols_with_the_fingerprint_alone_using_curl(self):
        self.check_enrols(with_wget=False)

    @unittest.skipUnless(shutil.which("wget"), "wget not installed")
    def test_enrols_with_the_fingerprint_alone_using_wget(self):
        self.check_enrols(with_curl=False)

    @unittest.skipUnless(DASH, "dash not installed")
    def test_the_script_is_dash_clean(self):
        self.check_enrols(shell=DASH)

    def test_the_fingerprint_may_be_given_as_openssl_prints_it(self):
        self.check_enrols(fp="sha256 Fingerprint=" + self.fp)

    def test_the_fingerprint_may_be_lower_case_without_colons(self):
        self.check_enrols(fp=self.fp.replace(":", "").lower())

    def test_a_remapped_port_stays_in_every_request(self):
        """The server is on an ephemeral port, not 443. The script must use the
        address it was served from for the CA, the binary and the version."""
        self.check_enrols()
        self.assertNotEqual(self.srv.port, 443)
        hosts = {h for _p, h in self.srv.requests}
        self.assertEqual(hosts, {f"127.0.0.1:{self.srv.port}"}, hosts)

    def test_without_the_fingerprint_it_is_refused_and_says_how(self):
        sb, r = self.install(args=())
        self.assertNotEqual(r.returncode, 0, "a self-signed server was accepted unpinned")
        self.assertIn("--ca-fingerprint", r.stderr,
                      "the failure does not say how to enrol against a self-signed server")
        self.assertFalse(self.paths(sb)["bin"].exists())
        self.assertNotIn("AGENT", sb.calls())

    def test_a_wrong_fingerprint_installs_nothing_and_leaves_no_ca_behind(self):
        """The old script wrote the unverified file to the agent's default CA path
        first and exited on a mismatch, leaving it there, trusted by default."""
        wrong = self.fp[:-1] + ("0" if self.fp[-1] != "0" else "1")
        sb, r = self.install(fp=wrong)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("mismatch", r.stderr)
        p = self.paths(sb)
        self.assertFalse(p["ca"].exists(), "a refused CA was left at the default path")
        self.assertFalse(p["env"].exists())
        self.assertFalse(p["bin"].exists(), "the agent was downloaded after a refused CA")
        self.assertNotIn("/api/agent/download", [pth for pth, _h in self.srv.requests])
        self.assertNotIn("AGENT", sb.calls())

    def test_something_that_is_not_a_certificate_is_refused(self):
        self.srv.ca_body = b"<html>not a certificate</html>"
        sb, r = self.install()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not a certificate", r.stderr)
        self.assertFalse(self.paths(sb)["ca"].exists())

    def test_a_tampered_binary_is_refused(self):
        import hashlib
        self.srv.published_sha = hashlib.sha256(self.srv.agent).hexdigest()
        self.srv.agent = self.srv.agent + b"# tampered\n"
        sb, r = self.install()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("checksum mismatch", r.stdout + r.stderr)
        self.assertFalse(self.paths(sb)["bin"].exists())
        self.assertNotIn("AGENT enroll-token", sb.calls())


class TestEnrollingAHostThatIsAlreadyRunning(_Rig):
    """The user's report: new credentials written, the running agent never
    restarted, "Credentials rejected - re-enroll" until someone ran
    `systemctl restart remotepower-agent` by hand."""

    def test_the_running_agent_ends_up_holding_the_new_credentials(self):
        sb = H.Sandbox(self.tmp)
        sb.set_running("OLD-credentials")
        sb, r = self.install(token="tok-again", sandbox=sb)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(
            sb.running_creds(), "tok-again-credentials",
            "the service is still running on the old credentials: the installer "
            "wrote the new ones and did not restart it\n" + sb.calls())
        calls = sb.calls()
        self.assertLess(calls.index("AGENT enroll-token"),
                        calls.index("SYSTEMCTL restart remotepower-agent"),
                        "the restart came before the credentials were written")

    def test_a_stopped_agent_is_started(self):
        sb, r = self.install()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue((sb.state / "active").exists(), "the agent was left stopped")
        self.assertEqual(sb.running_creds(), "tok-new-credentials")

    def test_inside_the_agents_own_service_the_restart_is_detached(self):
        """Run from the agent's exec channel the script lives in the agent's
        cgroup, and a direct restart would kill it before it finished."""
        cg = self.tmp / "cgroup"
        cg.write_text("0::/system.slice/remotepower-agent.service\n")
        sb = H.Sandbox(self.tmp)
        sb.set_running("OLD-credentials")
        sb, r = self.install(sandbox=sb, env={"RP_CGROUP_FILE": str(cg)})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        calls = sb.calls()
        self.assertIn("SYSTEMD-RUN --unit=rp-installer-restart --on-active=5 "
                      "systemctl restart remotepower-agent", calls)
        self.assertNotIn("SYSTEMCTL restart", calls,
                         "a direct restart from inside the agent's cgroup kills the script")

    def test_control_outside_it_the_restart_is_direct(self):
        cg = self.tmp / "cgroup"
        cg.write_text("0::/user.slice/user-1000.slice/session-3.scope\n")
        sb, r = self.install(env={"RP_CGROUP_FILE": str(cg)})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("SYSTEMCTL restart remotepower-agent", sb.calls())
        self.assertNotIn("SYSTEMD-RUN", sb.calls())

    def test_without_systemd_the_agent_is_run_in_the_background(self):
        sb, r = self.install(env={"RP_TEST_NO_SYSTEMD": "1"})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("SYSTEMCTL restart", sb.calls())
        self.assertIn("AGENT run", sb.calls())


@unittest.skipUnless((H.ROOT / "install-client.sh").exists(), "excluded from dist tree")
class TestInstallClientAgainstASelfSignedServer(_Rig):
    """install-client.sh builds the CA address itself. It used to be
    http://<host>/ca.crt with the port cut off: port 80, whatever port the
    server is published on. It is the server's own address now."""

    def setUp(self):
        super().setUp()
        self.sb = H.Sandbox(self.tmp)
        self.dist = self.tmp / "dist"
        (self.dist / "client").mkdir(parents=True)
        shutil.copy(H.ROOT / "install-client.sh", self.dist / "install-client.sh")
        agent = self.dist / "client" / "remotepower-agent"
        agent.write_text(H.AGENT_STUB)
        agent.chmod(0o755)
        shutil.copy(H.ROOT / "client" / "remotepower-agent.service",
                    self.dist / "client" / "remotepower-agent.service")

    def run_installer(self, *args, env=None):
        return self.sb.run(shutil.which("bash"), self.dist / "install-client.sh", args, env=env)

    def test_enrols_with_the_fingerprint_alone_on_the_servers_own_port(self):
        r = self.run_installer("--server", self.srv.url, "--pin", "123456",
                               "--ca-fingerprint", self.fp)
        out = r.stdout + r.stderr
        self.assertEqual(r.returncode, 0, out)
        ca = self.sb.root / "etc/remotepower/ca.crt"
        self.assertEqual(ca.read_bytes(), (self.tls / "ca.crt").read_bytes())
        calls = self.sb.calls()
        self.assertIn(f"AGENT enroll --server {self.srv.url} --pin 123456", calls)
        self.assertIn(f"AGENT-ENV RP_CA_BUNDLE={ca}", calls)
        ca_requests = [h for p, h in self.srv.requests if p == "/ca.crt"]
        self.assertEqual(ca_requests, [f"127.0.0.1:{self.srv.port}"],
                         "the CA was not fetched from the server's own port")

    def test_a_wrong_fingerprint_is_refused_and_nothing_is_installed(self):
        wrong = self.fp[:-1] + ("0" if self.fp[-1] != "0" else "1")
        r = self.run_installer("--server", self.srv.url, "--pin", "123456",
                               "--ca-fingerprint", wrong)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("MISMATCH", r.stdout + r.stderr)
        self.assertFalse((self.sb.root / "etc/remotepower/ca.crt").exists())
        self.assertNotIn("AGENT enroll", self.sb.calls())

    def test_enrolling_a_running_host_again_restarts_it_onto_the_new_credentials(self):
        self.sb.set_running("OLD-credentials")
        r = self.run_installer("--server", self.srv.url, "--pin", "654321",
                               "--ca-fingerprint", self.fp, "--re-enroll")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(
            self.sb.running_creds(), "654321-credentials",
            "--re-enroll left the running agent on its old credentials\n" + self.sb.calls())

    def test_a_first_install_starts_the_agent(self):
        r = self.run_installer("--server", self.srv.url, "--pin", "111111",
                               "--ca-fingerprint", self.fp)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.sb.running_creds(), "111111-credentials")


class TestNoInstallerBuildsTheCaAddressFromAPortlessHost(unittest.TestCase):
    """The same defect was written three times, in the three installers that read a
    CA from the server: http://<host>/ca.crt with the port cut off, which is port
    80 whatever port the server is published on. Enumerate, do not spot-check."""

    FILES = ("install-client.sh", "client/install-macos.sh", "client/install-windows.ps1")
    # A confirmed gap, not a refuted one: PowerShell 5.1 (a Windows host's own) has
    # no -SkipCertificateCheck, and the replacement is a certificate callback that
    # has not been run on Windows. Listed with the reason so it can only shrink.
    KNOWN_OPEN = {"client/install-windows.ps1":
                  "PowerShell 5.1 certificate-check bypass is unverified on a real Windows host"}
    PORTLESS = r'CA_SRC="http://\$\{host\}/ca\.crt"|http://\$\(\(\[uri\]\$Server\)\.Host\)/ca\.crt'

    def code(self, rel):
        out = []
        for ln in (H.ROOT / rel).read_text().splitlines():
            if not ln.lstrip().startswith("#"):
                out.append(ln)
        return "\n".join(out)

    def test_the_population_is_the_three_installers(self):
        for rel in self.FILES:
            self.assertTrue((H.ROOT / rel).exists(), rel)

    def test_the_fixed_ones_use_the_servers_own_address(self):
        import re
        for rel in self.FILES:
            if rel in self.KNOWN_OPEN:
                continue
            code = self.code(rel)
            self.assertIsNone(re.search(self.PORTLESS, code),
                              f"{rel} builds the CA address from a host with the port cut off")
            self.assertRegex(code, r'CA_SRC="\$\{(SERVER_URL|SERVER)%/\}/ca\.crt"', rel)

    def test_the_known_gap_still_has_the_defect_so_the_list_can_only_shrink(self):
        for rel in self.KNOWN_OPEN:
            self.assertRegex(self.code(rel), self.PORTLESS,
                             f"{rel} no longer has the defect: remove it from KNOWN_OPEN")


class TestUninstall(_Rig):

    def test_uninstall_removes_the_unit_the_binary_and_the_config(self):
        sb, r = self.install()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        p = self.paths(sb)
        self.assertTrue(p["bin"].exists())
        script = _fetch_script(self.srv, "x")
        r = sb.run_piped(SH, script, ["--uninstall"])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse(p["bin"].exists())
        self.assertFalse(p["unit"].exists())
        self.assertFalse((sb.root / "etc/remotepower").exists())


if __name__ == "__main__":
    unittest.main()

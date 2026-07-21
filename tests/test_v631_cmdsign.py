"""v6.3.1 wave 4 — signed command channel (end-to-end with a real GPG key).

The server detach-signs every dispatched command with the release signing key,
binding it to the target device and an issue timestamp; agents that pin
release.pub and touch `require-signed-commands` verify fail-closed. What that
buys: tampering with the command queue at rest (DB compromise) or replaying a
captured command to another host / at a later time executes nothing.
"""

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v631sig-"))
_spec = importlib.util.spec_from_file_location("api_v631_sig", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_GPG = shutil.which("gpg")


def _load_agent():
    spec = importlib.util.spec_from_file_location(
        "rpagent_v631sig", _ROOT / "client/remotepower-agent.py")
    ag = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ag)
    return ag


@unittest.skipUnless(_GPG, "gpg not available")
class TestSignedCommandChannel(unittest.TestCase):
    """Real key, real signatures: server signs → agent verifies."""

    @classmethod
    def setUpClass(cls):
        cls.home = Path(tempfile.mkdtemp(prefix="rp-signhome-"))
        os.chmod(cls.home, 0o700)
        env = dict(os.environ, GNUPGHOME=str(cls.home))
        r = subprocess.run(
            [_GPG, "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
             "--quick-gen-key", "RP Test <rp-test@example.invalid>",
             "ed25519", "sign", "0"],
            env=env, capture_output=True, timeout=60)
        assert r.returncode == 0, r.stderr.decode()
        cls._orig_home = api._SIGNING_GNUPGHOME
        api._SIGNING_GNUPGHOME = cls.home
        cls.fpr, cls.pub = api._signing_key_info()
        assert cls.fpr and cls.pub
        # Agent side: pin the matching public key + set the enforcement flag.
        cls.ag = _load_agent()
        cls.pub_file = Path(tempfile.mkdtemp()) / "release.pub"
        cls.pub_file.write_text(cls.pub)
        cls.flag_file = cls.pub_file.parent / "require-signed-commands"
        cls.flag_file.touch()
        cls._orig_pub = cls.ag.RELEASE_PUBKEY_FILE
        cls._orig_flag = cls.ag.REQUIRE_SIGNED_CMDS_FILE
        cls.ag.RELEASE_PUBKEY_FILE = cls.pub_file
        cls.ag.REQUIRE_SIGNED_CMDS_FILE = cls.flag_file

    @classmethod
    def tearDownClass(cls):
        api._SIGNING_GNUPGHOME = cls._orig_home
        cls.ag.RELEASE_PUBKEY_FILE = cls._orig_pub
        cls.ag.REQUIRE_SIGNED_CMDS_FILE = cls._orig_flag
        shutil.rmtree(cls.home, ignore_errors=True)

    def test_sign_then_verify_roundtrip(self):
        sig, ts = api._sign_command_for_agent("dev1", "exec:uptime")
        self.assertTrue(sig and "BEGIN PGP SIGNATURE" in sig)
        ok, detail = self.ag._command_sig_ok("exec:uptime", sig, ts, "dev1")
        self.assertTrue(ok, detail)

    def test_tampered_command_fails(self):
        sig, ts = api._sign_command_for_agent("dev1", "exec:uptime")
        ok, _ = self.ag._command_sig_ok("exec:rm -rf /", sig, ts, "dev1")
        self.assertFalse(ok)

    def test_wrong_device_fails(self):
        # Replay to another host: the device id is inside the signed payload.
        sig, ts = api._sign_command_for_agent("dev1", "exec:uptime")
        ok, _ = self.ag._command_sig_ok("exec:uptime", sig, ts, "dev2")
        self.assertFalse(ok)

    def test_stale_timestamp_fails(self):
        # Replay later: even a correctly-signed old payload dies on freshness.
        old_ts = int(time.time()) - 2000
        payload = f"rp-cmd\nv1\ndev1\n{old_ts}\nexec:uptime".encode()
        env = dict(os.environ, GNUPGHOME=str(self.home))
        r = subprocess.run(
            [_GPG, "--batch", "--yes", "--armor", "-u", self.fpr,
             "--detach-sign", "-o", "-"],
            input=payload, env=env, capture_output=True, timeout=20)
        sig = r.stdout.decode()
        ok, detail = self.ag._command_sig_ok("exec:uptime", sig, old_ts, "dev1")
        self.assertFalse(ok)
        self.assertIn("freshness", detail)

    def test_unsigned_fails_when_flag_set(self):
        ok, detail = self.ag._command_sig_ok("exec:uptime", None, None, "dev1")
        self.assertFalse(ok)
        self.assertIn("unsigned", detail)

    def test_no_pinned_key_fails_closed(self):
        orig = self.ag.RELEASE_PUBKEY_FILE
        self.ag.RELEASE_PUBKEY_FILE = Path("/nonexistent/release.pub")
        try:
            ok, detail = self.ag._command_sig_ok("exec:uptime", "sig", 1, "dev1")
        finally:
            self.ag.RELEASE_PUBKEY_FILE = orig
        self.assertFalse(ok)
        self.assertIn("release.pub", detail)


class TestNoKeyDegradesGracefully(unittest.TestCase):
    def test_signer_returns_none_without_a_key(self):
        orig = api._SIGNING_GNUPGHOME
        api._SIGNING_GNUPGHOME = Path(tempfile.mkdtemp()) / "no-such-home"
        try:
            sig, ts = api._sign_command_for_agent("dev1", "exec:uptime")
        finally:
            api._SIGNING_GNUPGHOME = orig
        self.assertIsNone(sig)
        self.assertIsNone(ts)


class TestWiring(unittest.TestCase):
    def test_heartbeat_delivers_signature_fields(self):
        from tests import apisrc
        src = apisrc.api_source()
        self.assertIn("_sign_command_for_agent(dev_id, dispatch_cmd)", src)
        self.assertIn("'command_sig': _cmd_sig", src)
        self.assertIn("'command_sig_ts': _cmd_sig_ts", src)

    def test_all_three_agents_gate_on_the_flag(self):
        for rel, marks in (
            ("client/remotepower-agent.py",
             ("_require_signed_commands()", "_command_sig_ok(")),
            ("client/remotepower-agent-win.py",
             ("_require_signed_commands_win()", "_command_sig_ok_win(")),
            ("client/remotepower-agent-mac.py",
             ("_require_signed_commands_mac()", "_command_sig_ok_mac(")),
        ):
            src = (_ROOT / rel).read_text()
            for m in marks:
                self.assertIn(m, src, f"{rel} missing {m}")
            # canonical payload string must be identical everywhere
            self.assertIn("rp-cmd\\nv1\\n", src.replace("'", '"'), rel)
            # refusal must be REPORTED (rc 126), not silently dropped
            self.assertIn("126", src, rel)

    def test_canonical_payload_matches_server(self):
        from tests import apisrc
        self.assertIn("f'rp-cmd\\nv1\\n{dev_id}\\n{ts}\\n{cmd}'",
                      apisrc.api_source())

    def test_flag_defaults_off(self):
        ag = _load_agent()
        # The default conf path won't exist on a dev box — enforcement is
        # opt-in, so a fresh agent must not require signatures.
        self.assertFalse(ag._require_signed_commands())


if __name__ == "__main__":
    unittest.main()

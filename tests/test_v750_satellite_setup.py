#!/usr/bin/env python3
"""7.5.0 agent review (NF-2): the satellite relay can read its own settings, key and certificate.

`packaging/satellite-setup.sh --self-signed` put the relay's files in /etc/remotepower, a root:root 0750 directory (and the host
agent sets it to 0700 when it saves its credentials). The service runs as `remotepower-sat`, which is neither the owner nor in the
group, so it could not open its own key at start. The relay's files now live in /etc/remotepower-satellite (root:remotepower-sat
0750), and its unit carries the cheap sandbox options.

The script runs for real, as a normal user, with the system paths moved under a temporary directory and the privileged commands
(useradd, id, chgrp, systemctl, openssl, and install's -o/-g) stood in for by recorders, so what is asserted is the order of the
calls and what was written.
"""
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = Path(os.environ.get("RP_TEST_SATELLITE_SETUP") or ROOT / "packaging" / "satellite-setup.sh")

STUBS = {
    "id": '#!/bin/sh\necho "id $*" >> "$RP_LOG"\ncase "$1" in -u) echo 0; exit 0;; esac\nexit 1\n',
    "useradd": '#!/bin/sh\necho "useradd $*" >> "$RP_LOG"\n',
    "chgrp": '#!/bin/sh\necho "chgrp $*" >> "$RP_LOG"\n',
    "systemctl": '#!/bin/sh\necho "systemctl $*" >> "$RP_LOG"\n',
    "sleep": "#!/bin/sh\nexit 0\n",
    "openssl": ('#!/bin/sh\necho "openssl $*" >> "$RP_LOG"\n'
                'while [ $# -gt 0 ]; do case "$1" in -keyout) echo KEY > "$2";; -out) echo CERT > "$2";; esac; shift; done\n'),
    # install(1) as a normal user cannot -o root or -g a group that is not ours: record, drop those two, run the rest
    "install": ('#!/bin/sh\necho "install $*" >> "$RP_LOG"\nargs=""\n'
                'while [ $# -gt 0 ]; do case "$1" in -o|-g) shift;; *) args="$args $1";; esac; shift; done\n'
                'exec /usr/bin/install $args\n'),
}


@unittest.skipUnless(shutil.which("bash") and Path("/usr/bin/install").exists(), "needs bash and /usr/bin/install")
class TestTheSetupScript(unittest.TestCase):

    def run_script(self, *args, **env):
        td = Path(tempfile.mkdtemp(prefix="rp-v750-sat-"))
        self.addCleanup(shutil.rmtree, td, True)
        (td / "packaging").mkdir()
        (td / "client").mkdir()
        (td / "client" / "remotepower-satellite.py").write_text("# stand-in\n")
        (td / "etc" / "systemd" / "system").mkdir(parents=True)
        (td / "opt").mkdir()
        text = SCRIPT.read_text().replace("/etc/", f"{td}/etc/").replace("/opt/", f"{td}/opt/")
        script = td / "packaging" / "satellite-setup.sh"
        script.write_text(text)
        stubs = td / "stubs"
        stubs.mkdir()
        for name, body in STUBS.items():
            p = stubs / name
            p.write_text(body)
            p.chmod(p.stat().st_mode | stat.S_IXUSR)
        log = td / "calls.log"
        e = {"PATH": f"{stubs}:{os.environ['PATH']}", "RP_LOG": str(log), "RP_UPSTREAM": "https://rp.example",
             "RP_SATELLITE_TOKEN": "tok", "HOME": str(td)}
        e.update(env)
        r = subprocess.run(["bash", str(script), *args], env=e, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout[-400:] + r.stderr[-400:])
        calls = log.read_text().splitlines() if log.exists() else []
        return td, calls

    def test_the_relay_files_go_where_its_account_can_read_them(self):
        td, calls = self.run_script("--self-signed", "sat.lan")
        conf = td / "etc" / "remotepower-satellite"
        self.assertTrue((conf / "satellite.env").is_file())
        self.assertTrue((conf / "satellite.key").is_file())
        self.assertTrue((conf / "satellite.crt").is_file())
        self.assertFalse((td / "etc" / "remotepower").exists(), "nothing may go into the host agent's directory")
        env = (conf / "satellite.env").read_text()
        self.assertIn(f"RP_TLS_CERT={conf}/satellite.crt", env)
        self.assertIn(f"RP_TLS_KEY={conf}/satellite.key", env)
        self.assertEqual(stat.S_IMODE((conf / "satellite.env").stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE((conf / "satellite.key").stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE(conf.stat().st_mode), 0o750)
        # the directory, the env file and the key all go to the relay's group
        self.assertTrue(any(c.startswith("install -d -m 0750 -o root -g remotepower-sat") and c.endswith("remotepower-satellite")
                            for c in calls), calls)
        chgrps = [c for c in calls if c.startswith("chgrp remotepower-sat")]
        self.assertTrue(any(c.endswith("satellite.env") for c in chgrps), calls)
        self.assertTrue(any(c.endswith("satellite.key") for c in chgrps), calls)

    def test_the_account_exists_before_the_directory_is_given_to_it(self):
        _td, calls = self.run_script()
        i_user = next(i for i, c in enumerate(calls) if c.startswith("useradd"))
        i_dir = next(i for i, c in enumerate(calls) if "-g remotepower-sat" in c and c.startswith("install -d"))
        self.assertLess(i_user, i_dir)

    def test_the_unit_reads_the_new_directory_and_is_sandboxed(self):
        td, _calls = self.run_script()
        unit = (td / "etc" / "systemd" / "system" / "remotepower-satellite.service").read_text()
        conf = td / "etc" / "remotepower-satellite"
        self.assertIn(f"EnvironmentFile={conf}/satellite.env", unit)
        self.assertIn(f"ReadOnlyPaths={conf}", unit)
        for line in ("User=remotepower-sat", "NoNewPrivileges=true", "ProtectSystem=strict", "PrivateDevices=true",
                     "ProtectKernelTunables=true", "ProtectKernelModules=true", "ProtectKernelLogs=true",
                     "ProtectControlGroups=true", "RestrictSUIDSGID=true", "RestrictRealtime=true", "LockPersonality=true",
                     "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX", "CapabilityBoundingSet=\n", "AmbientCapabilities=\n"):
            self.assertIn(line, unit)

    def test_a_privileged_port_keeps_the_one_capability_it_needs(self):
        td, _calls = self.run_script(RP_LISTEN="0.0.0.0:443")
        unit = (td / "etc" / "systemd" / "system" / "remotepower-satellite.service").read_text()
        self.assertIn("CapabilityBoundingSet=CAP_NET_BIND_SERVICE", unit)
        self.assertIn("AmbientCapabilities=CAP_NET_BIND_SERVICE", unit)

    def test_the_default_port_has_no_capability_at_all(self):
        td, _calls = self.run_script()
        unit = (td / "etc" / "systemd" / "system" / "remotepower-satellite.service").read_text()
        self.assertNotIn("CAP_NET_BIND_SERVICE", unit)

    def test_without_a_certificate_no_key_is_made(self):
        td, calls = self.run_script()
        self.assertFalse((td / "etc" / "remotepower-satellite" / "satellite.key").exists())
        self.assertFalse(any(c.startswith("openssl") for c in calls))

    def test_the_script_is_valid_shell(self):
        r = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_the_docs_say_where_the_files_are(self):
        doc = (ROOT / "docs" / "satellites.md").read_text()
        self.assertIn("/etc/remotepower-satellite", doc)


if __name__ == "__main__":
    unittest.main()

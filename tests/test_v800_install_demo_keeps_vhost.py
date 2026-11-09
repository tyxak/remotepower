#!/usr/bin/env python3
"""8.0.0: the demo installer keeps an nginx vhost that is already there.

`install-demo.sh` is run again to re-seed and to re-render the systemd units, and its header called a re-run idempotent. It wrote the port-80 skeleton over the vhost every time, so a
vhost that certbot had edited (the 443 server block, the certificate paths) lost that block at the next run and the demo went off HTTPS until certbot ran again. Now an existing
vhost stays as it is, and `--rewrite-vhost` replaces it when that is what the person wants.

The one caller that needs the old behaviour is `convert-to-wsgi.sh`: a demo that has no process of its own is still on the old per-request model, and its vhost points at the transport
that script retires. It passes the flag for that demo and for no other.

The runs are dry runs (nothing is written, no root is needed) with the two nginx directories moved into a temporary directory by the installer's own environment variables.
"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT =Path(__file__).resolve().parent.parent
INSTALLER = ROOT / "packaging" / "install-demo.sh"
CONVERT = ROOT / "packaging" / "convert-to-wsgi.sh"
HOST = "demo.example.test"
CERTBOT_VHOST = (
    "server {\n    listen 443 ssl;\n    server_name %s;\n"
    "    ssl_certificate /etc/letsencrypt/live/%s/fullchain.pem; # managed by Certbot\n}\n" % (HOST, HOST)
)


def _whoami():
    r = subprocess.run(["id", "-un"], capture_output=True, text=True, timeout=10)
    return r.stdout.strip()


@unittest.skipUnless(shutil.which("bash") and shutil.which("id"), "bash and id are needed")
class TestTheInstallerKeepsAVhostThatIsThere(unittest.TestCase):

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="rp-demo-vhost-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        (self.dir / "htdocs" / "cgi-bin").mkdir(parents=True)
        (self.dir / "avail").mkdir()
        (self.dir / "enabled").mkdir()
        self.vhost = self.dir / "avail" / "remotepower-demo"

    def dry_run(self, *flags):
        env = dict(os.environ, RP_DEMO_NGINX_SITES_AVAIL=str(self.dir / "avail"), RP_DEMO_NGINX_SITES_ENABL=str(self.dir / "enabled"))
        r = subprocess.run(
            ["bash", str(INSTALLER), HOST, "--dry-run", "--skip-reseed", *flags, "--cgi-user", _whoami(),
             "--htdocs", str(self.dir / "htdocs"), "--data-dir", str(self.dir / "data")],
            capture_output=True, text=True, timeout=60, env=env,
        )
        self.assertEqual(r.returncode, 0, (r.stderr + r.stdout)[-600:])
        return r.stdout

    def test_a_vhost_that_is_there_is_kept_and_not_written(self):
        self.vhost.write_text(CERTBOT_VHOST)
        out = self.dry_run()
        self.assertIn("Keeping the nginx config that is already at %s" % self.vhost, out)
        self.assertIn("would keep %s as it is" % self.vhost, out)
        self.assertNotIn("would write to %s" % self.vhost, out, "the skeleton must not be written over a vhost that is there")
        self.assertIn("the nginx vhost that was already there is kept", out)
        self.assertEqual(self.vhost.read_text(), CERTBOT_VHOST, "a dry run changes nothing")

    def test_without_a_vhost_the_skeleton_is_written(self):
        out = self.dry_run()
        self.assertIn("Writing nginx config to %s" % self.vhost, out)
        self.assertIn("would write to %s" % self.vhost, out)
        self.assertNotIn("Keeping the nginx config", out)
        self.assertIn("Demo vhost installed.", out)

    def test_rewrite_vhost_replaces_the_one_that_is_there(self):
        self.vhost.write_text(CERTBOT_VHOST)
        out = self.dry_run("--rewrite-vhost")
        self.assertIn("would write to %s" % self.vhost, out)
        self.assertNotIn("Keeping the nginx config", out)
        self.assertEqual(self.vhost.read_text(), CERTBOT_VHOST, "a dry run changes nothing, with the flag too")

    def test_the_help_names_the_flag_and_why(self):
        r = subprocess.run(["bash", str(INSTALLER), "--help"], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0)
        self.assertIn("--rewrite-vhost", r.stdout)
        self.assertIn("certbot", r.stdout.lower())

    def test_the_two_directories_can_be_moved_only_by_the_installers_own_variables(self):
        src = INSTALLER.read_text()
        self.assertIn('NGINX_SITES_AVAIL="${RP_DEMO_NGINX_SITES_AVAIL:-/etc/nginx/sites-available}"', src)
        self.assertIn('NGINX_SITES_ENABL="${RP_DEMO_NGINX_SITES_ENABL:-/etc/nginx/sites-enabled}"', src)

    def test_the_header_no_longer_says_a_rerun_renders_the_vhost(self):
        head = INSTALLER.read_text().split("set -euo pipefail")[0]       # the header comment, bounded by what follows it and not by a character count
        self.assertIn("Idempotent", head)
        self.assertNotIn("re-renders the nginx", head)
        self.assertIn("--rewrite-vhost", head)


class TestTheConversionReplacesTheVhostOfTheOldModelOnly(unittest.TestCase):

    SRC = CONVERT.read_text()

    def test_it_passes_the_flag_when_the_demo_has_no_process_of_its_own(self):
        self.assertRegex(
            self.SRC,
            r"systemctl is-active --quiet remotepower-wsgi-demo[^\n]*\|\| demo_vhost_flag=\(--rewrite-vhost\)",
            "a demo without remotepower-wsgi-demo is on the old model: its vhost points at the transport this script retires",
        )

    def test_the_flag_reaches_the_installer_and_the_dry_run_line(self):
        self.assertIn('bash "$ROOT/packaging/install-demo.sh" "$DEMO_HOST" "${demo_pg_flag[@]}" "${demo_vhost_flag[@]}"', self.SRC)
        self.assertIn("${demo_pg_flag[*]:-} ${demo_vhost_flag[*]:-}", self.SRC)

    def test_the_flag_is_set_in_one_place_and_only_when_the_unit_is_not_active(self):
        """A demo that already runs its own process keeps the vhost certbot edited; only its storage backend is brought in line."""
        self.assertIn("demo_vhost_flag=()", self.SRC, "the array starts empty")
        sets = re.findall(r"^.*demo_vhost_flag=\(--rewrite-vhost\).*$", self.SRC, re.M)
        self.assertEqual(len(sets), 1, sets)
        self.assertIn("|| demo_vhost_flag=(--rewrite-vhost)", sets[0])
        self.assertIn("is-active --quiet remotepower-wsgi-demo", sets[0])


if __name__ == "__main__":
    unittest.main()

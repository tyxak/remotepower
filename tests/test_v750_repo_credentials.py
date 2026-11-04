#!/usr/bin/env python3
"""A repository address with a password in it is not shown to a viewer.

apt and pacman take `https://user:password@host/` in the line itself, a dnf .repo
file takes `username=` and `password=` (and the same for the proxy), and a mirror can
ask for a token in the query of its URL. The repository inventory stored the text as
the agent sent it and `GET /api/repositories` printed the URL to every signed-in role
(a viewer included). The agent takes the credential out before it sends since 7.5.0,
and the server does it again, because a host on an older agent has not and because
what is stored ends up in every backup. The patch preview's raw text and first error
carry the addresses the package manager could not reach, so they go through the same
function.

Held through the real ingest, the real listing handler and the real heartbeat.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-repocred-"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_v749_repo_inventory import _RI, TestThroughTheHeartbeat  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))
import patch_plan  # noqa: E402
import repo_inventory as RI  # noqa: E402

APT = "deb https://deploy:hunter2-token@packages.example.com/apt stable main\n"
DEB822 = "Types: deb\nURIs: https://user:pa/ss@mirror.example/ubuntu/\nSuites: noble\nComponents: main\n"
REPO = ("[vendor]\nname=Vendor\nbaseurl=https://svc:S3cr3tPw@repo.vendor.example/rpm/\n"
        "username=svc\npassword=S3cr3tPw\nproxy=http://px:ProxyPw@proxy.example:3128\n"
        "proxy_password=ProxyPw\ngpgcheck=1\nenabled=1\n")
PACMAN = "[options]\nSigLevel = Required\n\n[custom]\nServer = https://u:ArchPw@arch.example/$repo/os/$arch\n"
TOKEN = "deb https://repo.example/apt?token=Tok3n123&dist=stable stable main\n"

SECRETS = ("hunter2-token", "pa/ss", "S3cr3tPw", "ProxyPw", "ArchPw", "Tok3n123", "deploy:", "svc:")
FILES = {
    "/etc/apt/sources.list.d/private.list": APT,
    "/etc/apt/sources.list.d/private.sources": DEB822,
    "/etc/yum.repos.d/vendor.repo": REPO,
    "/etc/pacman.conf": PACMAN,
    "/etc/apt/sources.list": TOKEN,
}


class TestRedact(unittest.TestCase):

    def test_the_forms(self):
        cases = {
            "deb https://deploy:hunter2-token@packages.example.com/apt stable main":
                "deb https://packages.example.com/apt stable main",
            "baseurl=https://svc:S3cr3tPw@repo.vendor.example/rpm/":
                "baseurl=https://repo.vendor.example/rpm/",
            "Server = https://u:p@mirror.example/$repo/os/$arch":
                "Server = https://mirror.example/$repo/os/$arch",
            "URIs: https://user:pa/ss@host.example/ubuntu/":
                "URIs: https://host.example/ubuntu/",
            "https://repo.example/apt?token=abc&dist=stable":
                "https://repo.example/apt?token=***&dist=stable",
            "username=svc": "username=***",
            "password=S3cr3tPw": "password=***",
            "proxy_password = x": "proxy_password = ***",
            "proxy_username=px": "proxy_username=***",
        }
        for src, want in cases.items():
            self.assertEqual(RI.redact(src), want, src)

    def test_every_url_on_a_line_is_redacted_not_only_the_first(self):
        out = RI.redact("deb https://a:SECRET1@h1.example/x https://c:SECRET2@h2.example/y main")
        self.assertEqual(out, "deb https://h1.example/x https://h2.example/y main")

    def test_an_ordinary_line_is_unchanged(self):
        """The control: a redaction that touched every line would pass the cases above."""
        for line in ("deb http://deb.debian.org/debian bookworm main", "[fedora]",
                     "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg",
                     "gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-fedora", "enabled=1",
                     "https://mirror:8080/path", "Types: deb",
                     "metalink=https://mirrors.fedoraproject.org/metalink?repo=fedora-$releasever&arch=$basearch",
                     "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu noble stable"):
            self.assertEqual(RI.redact(line), line, line)

    def test_only_the_credential_goes_the_host_and_path_stay(self):
        out = RI.redact(APT)
        self.assertIn("packages.example.com/apt stable main", out)

    def test_it_keeps_line_breaks_and_is_total(self):
        text = "a\r\nb\n\nc"
        self.assertEqual(RI.redact(text).count("\n"), text.count("\n"))
        for junk in (None, 5, [], {}, b"x"):
            self.assertEqual(RI.redact(junk), "")
        self.assertEqual(RI.redact(""), "")

    def test_idempotent(self):
        for text in FILES.values():
            once = RI.redact(text)
            self.assertEqual(RI.redact(once), once)

    def test_a_very_long_line_costs_one_pass(self):
        import time
        line = "https://" + "a:" * 20000 + "x@host/" + "?k=v&" * 20000
        t = time.time()
        RI.redact(line)
        self.assertLess(time.time() - t, 2.0)


class TestWhatIsStoredAndShown(_RI):

    def test_the_stored_text_holds_no_secret(self):
        self.report("devB", FILES)
        blob = json.dumps(self.stored("devB"))
        for s in SECRETS:
            self.assertNotIn(s, blob, s)
        self.assertIn("packages.example.com", blob, "the host name is what the inventory is for")

    def test_the_listing_shows_no_secret_to_any_role(self):
        self.report("devB", FILES)
        for who in ("badmin", "bviewer"):
            st, d = self.listing(who)
            self.assertEqual(st, 200)
            blob = json.dumps(d)
            for s in SECRETS:
                self.assertNotIn(s, blob, (who, s))

    def test_the_rows_still_judge_the_repository(self):
        """Taking the credential out must not change what the finding says about it."""
        self.report("devB", FILES)
        st, d = self.listing()
        hosts = {r["host"] for r in d["repositories"]}
        self.assertTrue({"packages.example.com", "repo.vendor.example",
                         "mirror.example", "arch.example"} <= hosts, hosts)
        row = [r for r in d["repositories"] if r["host"] == "repo.vendor.example"][0]
        self.assertEqual(row["url"], "https://repo.vendor.example/rpm/")
        self.assertEqual(row["scheme"], "https")

    def test_the_url_of_a_row_is_redacted_even_if_the_stored_text_were_not(self):
        """Defence in depth: a store written by 7.4.9 holds the original text."""
        scheme_host = RI._row("/etc/x.list", "deb", "https://u:SECRETPW@host.example/apt")
        self.assertNotIn("SECRETPW", scheme_host["url"])
        self.assertEqual(scheme_host["host"], "host.example")

    def test_clean_files_redacts_before_it_caps(self):
        out = RI.clean_files({"/etc/apt/sources.list": APT * 3})
        self.assertNotIn("hunter2", json.dumps(out))


class TestThroughTheAgentsBody(TestThroughTheHeartbeat):
    """The real heartbeat with an old agent's body (the original text)."""

    def test_the_credential_never_reaches_the_store(self):
        rec = self.beat({"repo_files": FILES})
        self.assertIsNotNone(rec)
        blob = json.dumps(rec)
        for s in SECRETS:
            self.assertNotIn(s, blob, s)


def _dnf(plan, rc=1):
    """The host's answer as the preview script prints it (same framing as test_v749_patch_plan)."""
    return f"##now 1000\n##manager dnf\n##rc {rc}\n##plan\n{plan}\n##security\n\n##end\n"


class TestThePatchPreview(unittest.TestCase):
    """The preview's raw text and first error come from the host's package manager,
    which prints the repository address it could not reach."""

    ERR = ("Error: Failed to download metadata for repo 'private': Cannot download "
           "repomd.xml: https://deploy:hunter2-token@packages.example.com/rpm/repodata/repomd.xml "
           "- Status code: 401")

    def test_the_error_is_redacted_and_still_says_what_failed(self):
        p = patch_plan.parse(_dnf(self.ERR))
        self.assertEqual(p["status"], "failed")
        self.assertIn("Failed to download metadata", p["error"])
        self.assertNotIn("hunter2", p["error"])
        self.assertIn("packages.example.com", p["error"])

    def test_the_raw_text_is_redacted(self):
        p = patch_plan.parse(_dnf(self.ERR + "\nBaseurl: https://svc:S3cr3tPw@repo.example/rpm/"))
        self.assertNotIn("hunter2", p["raw"])
        self.assertNotIn("S3cr3tPw", p["raw"])
        self.assertIn("repo.example/rpm/", p["raw"])

    def test_a_plan_with_no_credentials_is_unchanged(self):
        plain = "Last metadata expiration check: 0:01:00 ago.\nDependencies resolved.\nNothing to do.\nComplete!"
        p = patch_plan.parse(_dnf(plain))
        self.assertEqual(p["status"], "done")
        self.assertEqual(p["raw"], plain)

    def test_the_raw_cap_still_holds_after_the_redaction(self):
        p = patch_plan.parse(_dnf("x" * 20000))
        self.assertLessEqual(len(p["raw"]), patch_plan.RAW_KEEP)


if __name__ == "__main__":
    unittest.main()

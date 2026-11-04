#!/usr/bin/env python3
"""7.5.0 agent review: package repository definitions leave the host without their credentials.

The agent sends the repository definition files (apt, dnf, yum, pacman) for the repository inventory, and the server shows their URLs
to every signed-in user. apt and pacman take `https://user:password@host/` in the line itself, a dnf or yum .repo file takes
`username=` and `password=` (and `proxy_password=`), and a mirror can ask for a token in the query of its URL. The server needs the
scheme, the host and the path to judge a repository and none of this, so it is removed on the host. (Confirmed against the server's
own parser: a URL with a password in it came back in the rows of GET /api/repositories as it was written.)

RP_TEST_AGENT points the test at another copy (a `git show HEAD:` of the old file shows it fail).
"""
import importlib.machinery
import importlib.util
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-data-"))

ROOT = Path(__file__).resolve().parent.parent
AGENT = Path(os.environ.get("RP_TEST_AGENT") or ROOT / "client" / "remotepower-agent.py")


def load_agent(name="agent_v750_repos"):
    loader = importlib.machinery.SourceFileLoader(name, str(AGENT))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


agent = load_agent()

SECRETS = ("AptPass123", "S3cretPW", "Hunter2Password", "ProxyPW", "TOKEN123", "abc123zzz", "pxpw", "ArchPw9")
FILES = {
    "/etc/apt/sources.list.d/priv.list":
        "# private mirror\n"
        "deb [signed-by=/usr/share/keyrings/x.gpg] https://apt_user:AptPass123@apt.example.com/debian stable main\n"
        "deb https://deb.debian.org/debian bookworm main contrib\n",
    "/etc/apt/sources.list.d/pc.sources":
        "Types: deb\nURIs: https://TOKEN123:@packagecloud.io/org/repo/ubuntu/\nSuites: noble\nComponents: main\n",
    "/etc/yum.repos.d/corp.repo":
        "[corp]\nname=Corp\nbaseurl=https://svc_user:S3cretPW@mirror.corp.example/rhel/9/\nenabled=1\ngpgcheck=1\n"
        "username=svc_user\npassword=Hunter2Password\nproxy=http://px:pxpw@proxy.corp:3128\nproxy_username=px\n"
        "proxy_password=ProxyPW\nsslclientkey=/etc/pki/entitlement/1234-key.pem\n"
        "gpgkey=https://mirror.corp.example/RPM-GPG-KEY\n"
        "mirrorlist=https://m.example/list?arch=x86_64&token=abc123zzz&repo=os\n",
    "/etc/pacman.conf":
        "[options]\nHoldPkg = pacman glibc\n[custom]\nServer = https://u:ArchPw9@arch.example.org/$repo/os/$arch\n",
}


class TestRepositoryDefinitionsLoseTheirCredentials(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory(prefix="rp-v750-repo-")
        self.addCleanup(self._td.cleanup)
        self.root = Path(self._td.name).resolve()
        for rel, text in FILES.items():
            f = self.root / rel.lstrip("/")
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(text)
        root = str(self.root)
        for target, value in (
                ("host_path", lambda p: root + p if isinstance(p, str) and p.startswith("/") else p),
                ("unhost_path", lambda p: str(p)[len(root):] if str(p).startswith(root) else str(p))):
            patcher = mock.patch.object(agent, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        agent._REPO_STATE.update({"hash": "", "sent": 0})

    def test_what_the_agent_sends_holds_none_of_the_credentials(self):
        files = agent.get_repo_files(force=True)
        self.assertTrue(files, "no repository file was read: the test measures nothing")
        blob = json.dumps(files)
        leaked = [s for s in SECRETS if s in blob]
        self.assertEqual(leaked, [], f"credentials were sent: {leaked}")

    def test_the_hosts_and_paths_the_server_judges_by_are_kept(self):
        files = agent.get_repo_files(force=True)
        self.assertIn("https://apt.example.com/debian stable main", files["/etc/apt/sources.list.d/priv.list"])
        self.assertIn("https://deb.debian.org/debian bookworm main contrib", files["/etc/apt/sources.list.d/priv.list"])
        self.assertIn("URIs: https://packagecloud.io/org/repo/ubuntu/", files["/etc/apt/sources.list.d/pc.sources"])
        corp = files["/etc/yum.repos.d/corp.repo"]
        for kept in ("baseurl=https://mirror.corp.example/rhel/9/", "enabled=1", "gpgcheck=1", "proxy=http://proxy.corp:3128",
                     "gpgkey=https://mirror.corp.example/RPM-GPG-KEY", "sslclientkey=/etc/pki/entitlement/1234-key.pem",
                     "arch=x86_64", "repo=os"):
            self.assertIn(kept, corp)
        self.assertIn("Server = https://arch.example.org/$repo/os/$arch", files["/etc/pacman.conf"])

    def test_a_setting_that_holds_a_secret_keeps_its_name_and_loses_its_value(self):
        corp = agent.get_repo_files(force=True)["/etc/yum.repos.d/corp.repo"]
        self.assertIn("password=***", corp)
        self.assertIn("proxy_password=***", corp)

    def test_odd_but_real_urls(self):
        f = agent._compact_repo_text
        self.assertEqual(f("baseurl=https://user:pa/ss@host.example/path/x"), "baseurl=https://host.example/path/x")
        self.assertEqual(f("baseurl=https://u:p%40ss@host/x a b"), "baseurl=https://host/x a b")
        self.assertEqual(f("baseurl=https://a:b@h1/x https://c:d@h2/y"), "baseurl=https://h1/x https://h2/y")
        self.assertEqual(f("baseurl=https://host:8080/repo@v2/stuff"), "baseurl=https://host:8080/repo@v2/stuff")
        self.assertEqual(f("baseurl=https://m.example/r?auth_token=zzz;foo=bar"), "baseurl=https://m.example/r?auth_token=***;foo=bar")

    def test_a_line_that_was_clean_comes_back_unchanged(self):
        for line in ("deb http://deb.debian.org/debian bookworm main", "enabled=1", "gpgcheck=1",
                     "name=Fedora $releasever - $basearch", "Include = /etc/pacman.d/mirrorlist",
                     "mirrorlist=https://mirrors.fedoraproject.org/metalink?repo=fedora-$releasever&arch=$basearch"):
            with self.subTest(line=line):
                self.assertEqual(agent._compact_repo_text(line), line)

    def test_a_hostile_line_costs_no_more_than_its_length(self):
        t0 = time.monotonic()
        for line in ("a" * 60000, "://" * 20000, "https://" + "@" * 50000, "https://" + "a:" * 20000 + "/x@", "password=" + "=" * 50000):
            agent._compact_repo_text(line)
        self.assertLess(time.monotonic() - t0, 1.0)


if __name__ == "__main__":
    unittest.main()

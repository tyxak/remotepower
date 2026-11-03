#!/usr/bin/env python3
"""7.4.9: an inventory of the package repositories each Linux host uses, and what is wrong with them.

An update only comes from a repository the host trusts. The agent reads the repository definition files (apt, dnf and yum, pacman)
and sends them with the comments taken out; repo_inventory.py reads them into one row per repository and works out the findings
(signature checking switched off, certificate checking switched off, plain http, a source that is not a distribution's, a repository
defined twice). The Patches page lists the repositories of the fleet with the hosts that use each.

What is real and what is not: the apt, dnf and pacman samples below are written the way the distributions ship them (Ubuntu 24.04's
ubuntu.sources, Debian 12's sources.list, Docker's apt list, Fedora's fedora.repo and Arch's pacman.conf), from memory of those
files, and not captured from hosts. This machine runs Arch, so its own /etc/pacman.conf is read for real, when it is there.
"""
import importlib.machinery
import importlib.util
import json
import os
import random
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v749-ri-"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_tenant_instance_gate import _Base, api  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))
import repo_inventory as RI  # noqa: E402
import store_shapes  # noqa: E402

UBUNTU_SOURCES = """Types: deb
URIs: http://archive.ubuntu.com/ubuntu/
Suites: noble noble-updates noble-backports
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb
URIs: http://security.ubuntu.com/ubuntu/
Suites: noble-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
"""
DEBIAN_LIST = """deb http://deb.debian.org/debian bookworm main non-free-firmware
deb-src http://deb.debian.org/debian bookworm main non-free-firmware
deb http://deb.debian.org/debian-security bookworm-security main non-free-firmware
"""
DOCKER_LIST = "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu noble stable\n"
FEDORA_REPO = """[fedora]
name=Fedora $releasever - $basearch
metalink=https://mirrors.fedoraproject.org/metalink?repo=fedora-$releasever&arch=$basearch
enabled=1
repo_gpgcheck=0
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-$releasever-$basearch

[fedora-debuginfo]
name=Fedora debuginfo
metalink=https://mirrors.fedoraproject.org/metalink?repo=fedora-debug-$releasever&arch=$basearch
enabled=0
gpgcheck=1
"""
PACMAN_CONF = """[options]
HoldPkg     = pacman glibc
Architecture = auto
SigLevel    = Required DatabaseOptional
LocalFileSigLevel = Optional

[core]
Include = /etc/pacman.d/mirrorlist

[extra]
Include = /etc/pacman.d/mirrorlist

[chaotic-aur]
Server = https://cdn-mirror.chaotic.cx/$repo/$arch
SigLevel = Required DatabaseOptional

[homebrew]
Server = http://repo.example.net/$repo/$arch
SigLevel = Never
"""


def one(files):
    return RI.parse(RI.clean_files(files))


def finds(files):
    rows = one(files)
    return rows, RI.evaluate(rows)


# ── reading the files ─────────────────────────────────────────────────────────────────────────────────────────────────
class TestApt(unittest.TestCase):

    def test_one_line_entries_with_their_options(self):
        rows = one({"/etc/apt/sources.list.d/docker.list": DOCKER_LIST})
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual((r["kind"], r["host"], r["scheme"], r["suite"], r["components"], r["types"]),
                         ("apt", "download.docker.com", "https", "noble", ["stable"], ["deb"]))
        self.assertTrue(r["signed"] and r["enabled"] and r["tls_verify"])

    def test_deb_src_and_comments(self):
        rows = one({"/etc/apt/sources.list": "# a comment\n\n" + DEBIAN_LIST + "  # indented comment\n"})
        self.assertEqual([(r["types"][0], r["suite"]) for r in rows], [("deb", "bookworm"), ("deb-src", "bookworm"), ("deb", "bookworm-security")])

    def test_trusted_and_insecure_options_switch_signing_off(self):
        for opt in ("trusted=yes", "allow-insecure=yes", "allow-weak=yes", "TRUSTED=YES"):
            r = one({"/etc/apt/sources.list": f"deb [{opt}] http://x.example/ubuntu noble main\n"})[0]
            self.assertFalse(r["signed"], opt)
        self.assertTrue(one({"/etc/apt/sources.list": "deb [trusted=no] http://x.example/ubuntu noble main\n"})[0]["signed"])
        self.assertTrue(one({"/etc/apt/sources.list": "deb [arch=amd64 signed-by=/k.gpg] http://x.example/u noble main\n"})[0]["signed"])

    def test_options_with_a_space_inside_the_brackets(self):
        r = one({"/etc/apt/sources.list": "deb [ arch=amd64 trusted=yes ] http://x.example/u noble main contrib\n"})[0]
        self.assertEqual((r["host"], r["suite"], r["components"], r["signed"]), ("x.example", "noble", ["main", "contrib"], False))

    def test_deb822(self):
        rows = one({"/etc/apt/sources.list.d/ubuntu.sources": UBUNTU_SOURCES})
        self.assertEqual(len(rows), 4, "one row per URI and suite")
        self.assertEqual([r["suite"] for r in rows], ["noble", "noble-updates", "noble-backports", "noble-security"])
        self.assertTrue(all(r["kind"] == "deb822" and r["signed"] and r["enabled"] for r in rows))
        self.assertEqual(rows[0]["components"], ["main", "restricted", "universe", "multiverse"])

    def test_deb822_enabled_no_and_trusted(self):
        text = "Types: deb\nURIs: https://a.example/u https://b.example/u\nSuites: stable\nComponents: main\nEnabled: no\nTrusted: yes\n"
        rows = one({"/etc/apt/sources.list.d/x.sources": text})
        self.assertEqual([(r["host"], r["enabled"], r["signed"]) for r in rows], [("a.example", False, False), ("b.example", False, False)])

    def test_deb822_with_an_inline_key_is_still_one_stanza(self):
        text = ("Types: deb\nURIs: https://repo.example/apt\nSuites: stable\nComponents: main\nSigned-By:\n"
                " -----BEGIN PGP PUBLIC KEY BLOCK-----\n .\n mQINBGabc\n -----END PGP PUBLIC KEY BLOCK-----\n")
        rows = one({"/etc/apt/sources.list.d/x.sources": text})
        self.assertEqual((len(rows), rows[0]["host"], rows[0]["signed"]), (1, "repo.example", True))

    def test_a_malformed_line_is_skipped_not_fatal(self):
        rows = one({"/etc/apt/sources.list": "deb\ndeb [\ndeb http://x\nrpm http://x/ y main\nnonsense here\ndeb http://ok.example/u noble main\n"})
        self.assertEqual([r["host"] for r in rows], ["ok.example"])


class TestYum(unittest.TestCase):

    def test_sections(self):
        rows = one({"/etc/yum.repos.d/fedora.repo": FEDORA_REPO})
        by = {r["id"]: r for r in rows}
        self.assertEqual(set(by), {"fedora", "fedora-debuginfo"})
        self.assertEqual((by["fedora"]["host"], by["fedora"]["scheme"], by["fedora"]["enabled"], by["fedora"]["signed"]),
                         ("mirrors.fedoraproject.org", "https", True, True))
        self.assertFalse(by["fedora-debuginfo"]["enabled"])

    def test_gpgcheck_and_sslverify(self):
        text = "[a]\nbaseurl=http://x.example/a\ngpgcheck=0\nsslverify=0\n[b]\nbaseurl=https://y.example/b\ngpgcheck=1\nsslverify=1\n"
        by = {r["id"]: r for r in one({"/etc/yum.repos.d/x.repo": text})}
        self.assertEqual((by["a"]["signed"], by["a"]["tls_verify"]), (False, False))
        self.assertEqual((by["b"]["signed"], by["b"]["tls_verify"]), (True, True))

    def test_the_default_comes_from_the_main_configuration(self):
        repo = "[a]\nbaseurl=https://x.example/a\n"
        self.assertTrue(one({"/etc/yum.repos.d/x.repo": repo})[0]["signed"], "no main file: checking is on, as dnf's default is")
        off = one({"/etc/yum.repos.d/x.repo": repo, "/etc/dnf/dnf.conf": "[main]\ngpgcheck=0\n"})[0]
        self.assertFalse(off["signed"])
        on = one({"/etc/yum.repos.d/x.repo": repo + "gpgcheck=1\n", "/etc/dnf/dnf.conf": "[main]\ngpgcheck=0\n"})[0]
        self.assertTrue(on["signed"], "a repository's own setting wins")

    def test_the_url_comes_from_baseurl_then_mirrorlist_then_metalink(self):
        text = "[a]\nmirrorlist=https://m.example/list\n[b]\nbaseurl=https://b.example/x https://c.example/x\n[c]\nname=no url\n"
        by = {r["id"]: r["host"] for r in one({"/etc/yum.repos.d/x.repo": text})}
        self.assertEqual(by, {"a": "m.example", "b": "b.example"}, "the first of several, and none for a section without one")


class TestPacman(unittest.TestCase):

    def test_repositories_and_their_signature_levels(self):
        by = {r["id"]: r for r in one({"/etc/pacman.conf": PACMAN_CONF})}
        self.assertEqual(set(by), {"core", "extra", "chaotic-aur", "homebrew"})
        self.assertTrue(by["core"]["signed"], "the global level applies")
        self.assertTrue(by["chaotic-aur"]["signed"])
        self.assertFalse(by["homebrew"]["signed"], "SigLevel = Never")
        self.assertEqual((by["chaotic-aur"]["host"], by["chaotic-aur"]["scheme"], by["chaotic-aur"]["url"]),
                         ("cdn-mirror.chaotic.cx", "https", "https://cdn-mirror.chaotic.cx/chaotic-aur/x86_64"))

    def test_an_include_is_a_local_file_not_a_host(self):
        by = {r["id"]: r for r in one({"/etc/pacman.conf": PACMAN_CONF})}
        self.assertEqual((by["core"]["scheme"], by["core"]["host"]), ("file", ""))

    def test_trustall_and_a_global_never(self):
        r = one({"/etc/pacman.conf": "[options]\nSigLevel = Optional TrustAll\n[x]\nServer = https://x.example/$repo\n"})[0]
        self.assertFalse(r["signed"])
        r = one({"/etc/pacman.conf": "[options]\nSigLevel = Never\n[x]\nServer = https://x.example/$repo\nSigLevel = Required\n"})[0]
        self.assertTrue(r["signed"])

    @unittest.skipUnless(Path("/etc/pacman.conf").exists(), "this machine does not run pacman")
    def test_the_real_pacman_conf_of_this_machine_reads(self):
        text = Path("/etc/pacman.conf").read_text()
        compact = "\n".join(l for l in text.splitlines() if l.strip() and not l.strip().startswith("#"))
        rows = one({"/etc/pacman.conf": compact})
        self.assertGreaterEqual(len(rows), 2, "core and extra at least")
        names = {r["id"] for r in rows}
        self.assertTrue({"core", "extra"} <= names, names)
        self.assertTrue(all(r["kind"] == "pacman" for r in rows))


# ── the findings ──────────────────────────────────────────────────────────────────────────────────────────────────────
def rules_of(files):
    rows, found = finds(files)
    return [{f["rule"]: f["severity"] for f in x} for x in found]


class TestFindings(unittest.TestCase):

    def test_the_distributions_own_repositories_have_no_findings_apart_from_http(self):
        r = rules_of({"/etc/apt/sources.list.d/ubuntu.sources": UBUNTU_SOURCES})
        for x in r:
            self.assertEqual(x, {"plain_http": "low"}, "signed over http: the metadata is verified")
        self.assertEqual(rules_of({"/etc/apt/sources.list": DEBIAN_LIST.replace("http://", "https://")})[0], {})

    def test_a_third_party_source(self):
        r = rules_of({"/etc/apt/sources.list.d/docker.list": DOCKER_LIST})
        self.assertEqual(r, [{"third_party": "low"}])
        f = finds({"/etc/apt/sources.list.d/docker.list": DOCKER_LIST})[1][0][0]
        self.assertEqual((f["title"], f["detail"]), ("Not a distribution repository", "download.docker.com"))

    def test_a_personal_package_archive_says_so(self):
        for host in ("ppa.launchpadcontent.net", "ppa.launchpad.net"):
            f = finds({"/etc/apt/sources.list": f"deb https://{host}/user/repo/ubuntu noble main\n"})[1][0][0]
            self.assertIn("personal package archive", f["detail"], host)

    def test_no_signature_check_is_high_and_makes_http_worse(self):
        r = rules_of({"/etc/apt/sources.list": "deb [trusted=yes] http://x.example/u noble main\ndeb [trusted=yes] https://y.example/u noble main\n"})
        self.assertEqual(r[0], {"no_signature_check": "high", "plain_http": "medium", "third_party": "low"})
        self.assertEqual(r[1], {"no_signature_check": "high", "third_party": "low"})

    def test_certificate_checking(self):
        r = rules_of({"/etc/yum.repos.d/x.repo": "[a]\nbaseurl=https://x.example/a\nsslverify=0\n"})[0]
        self.assertEqual(r["insecure_tls"], "high")

    def test_yum_without_signature_checks(self):
        r = rules_of({"/etc/yum.repos.d/x.repo": "[a]\nbaseurl=http://x.example/a\ngpgcheck=0\n"})[0]
        self.assertEqual((r["no_signature_check"], r["plain_http"]), ("high", "medium"))
        f = finds({"/etc/yum.repos.d/x.repo": "[a]\nbaseurl=http://x.example/a\ngpgcheck=0\n"})[1][0]
        self.assertIn("gpgcheck", [x["detail"] for x in f if x["rule"] == "no_signature_check"][0])

    def test_a_disabled_repository_is_listed_and_has_no_findings(self):
        text = "[live]\nbaseurl=http://x.example/a\ngpgcheck=0\nsslverify=0\n[off]\nbaseurl=http://x.example/b\ngpgcheck=0\nsslverify=0\nenabled=0\n"
        rows, found = finds({"/etc/yum.repos.d/f.repo": text})
        by = {r["id"]: f for r, f in zip(rows, found)}
        self.assertEqual(sorted(x["rule"] for x in by["live"]), ["insecure_tls", "no_signature_check", "plain_http", "third_party"])
        self.assertEqual(by["off"], [], "listed, with everything that would be wrong with it, and not counted")
        self.assertFalse([r for r in rows if r["id"] == "off"][0]["enabled"])

    def test_pacman_without_signatures(self):
        r = rules_of({"/etc/pacman.conf": PACMAN_CONF})
        by = dict(zip([x["id"] for x in one({"/etc/pacman.conf": PACMAN_CONF})], r))
        self.assertEqual(by["homebrew"], {"no_signature_check": "high", "plain_http": "medium", "third_party": "low"})
        self.assertEqual(by["chaotic-aur"], {"third_party": "low"})
        self.assertEqual(by["core"], {})

    def test_a_repository_defined_twice(self):
        files = {"/etc/apt/sources.list": DEBIAN_LIST, "/etc/apt/sources.list.d/again.list": "deb http://deb.debian.org/debian bookworm main\n"}
        rows, found = finds(files)
        dup = [(r["file"], [x["rule"] for x in f]) for r, f in zip(rows, found) if "duplicate" in [x["rule"] for x in f]]
        self.assertEqual(len(dup), 1, "a deb line and a deb-src line for one archive are not a repeat, the second deb line is")
        self.assertEqual(dup[0][0], "/etc/apt/sources.list.d/again.list")

    def test_which_hosts_are_third_party(self):
        for h in ("deb.debian.org", "archive.ubuntu.com", "mirrors.fedoraproject.org", "mirror.kernel.org", "mirrors.kernel.org",
                  "geo.mirror.pkgbuild.com".replace("pkgbuild.com", "archlinux.org"), "dl.rockylinux.org", "ftp.us.debian.org"):
            self.assertFalse(RI.is_third_party(h), h)
        for h in ("download.docker.com", "repo.example.net", "apt.releases.hashicorp.com", "evil-debian.org.example", "notdebian.org",
                  "debian.org.evil.example", "192.168.1.5"):
            self.assertTrue(RI.is_third_party(h), h)
        self.assertFalse(RI.is_third_party(""), "a local path or a mirror list has no host")

    def test_worst_first_and_count(self):
        rows, found = finds({"/etc/apt/sources.list": "deb [trusted=yes] http://x.example/u noble main\n"})
        ranks = [RI.RANK[x["severity"]] for x in found[0]]
        self.assertEqual(ranks, sorted(ranks))
        self.assertEqual(RI.worst(found[0]), "high")
        self.assertEqual(RI.count(found[0]), {"critical": 0, "high": 1, "medium": 1, "low": 1})
        self.assertEqual(RI.worst([]), "")

    def test_every_rule_is_reachable(self):
        seen = set()
        for files in ({"/etc/apt/sources.list": "deb [trusted=yes] http://x.example/u noble main\ndeb [trusted=yes] http://x.example/u noble main\n"},
                      {"/etc/yum.repos.d/x.repo": "[a]\nbaseurl=https://x.example/a\nsslverify=0\n"}):
            seen |= {x["rule"] for f in finds(files)[1] for x in f}
        self.assertEqual(seen, set(RI.RULES))

    def test_the_rule_table(self):
        for rid, (sev, title) in RI.RULES.items():
            self.assertIn(sev, RI.SEVERITIES, rid)
            self.assertTrue(title[0].isupper() and not title.endswith("."), rid)


# ── what a host sends ─────────────────────────────────────────────────────────────────────────────────────────────────
class TestWhatIsKept(unittest.TestCase):

    def test_only_places_repositories_live(self):
        good = {"/etc/apt/sources.list": "a", "/etc/apt/sources.list.d/x.list": "a", "/etc/apt/sources.list.d/y.sources": "a",
                "/etc/yum.repos.d/z.repo": "a", "/etc/dnf/dnf.conf": "a", "/etc/yum.conf": "a", "/etc/pacman.conf": "a"}
        bad = {"/etc/shadow": "x", "/etc/apt/../shadow": "x", "/etc/apt/sources.list.d/../../shadow.list": "x", "/etc/apt/sources.list.d/x.txt": "x",
               "/root/.ssh/id_rsa": "x", "/etc/yum.repos.d/": "x", "relative.list": "x", "/etc/apt/sources.list.d/a b.list": "x",
               "/etc/apt/sources.list.d/x.list\n": "x", "/etc/pacman.conf.bak": "x", 5: "x", None: "x"}
        self.assertEqual(set(RI.clean_files(dict(good, **{k: v for k, v in bad.items() if isinstance(k, str)}))), set(good))

    def test_sizes_are_capped(self):
        f = RI.clean_files({"/etc/apt/sources.list": "x" * 100_000})
        self.assertEqual(len(f["/etc/apt/sources.list"]), RI.MAX_FILE_BYTES)
        many = {f"/etc/apt/sources.list.d/{i}.list": "y" * 9_000 for i in range(30)}
        out = RI.clean_files(many)
        self.assertLessEqual(sum(len(v) for v in out.values()), RI.MAX_TOTAL_BYTES)
        self.assertLessEqual(len(RI.clean_files({f"/etc/apt/sources.list.d/{i}.list": "a" for i in range(200)})), RI.MAX_FILES)

    def test_control_characters_and_non_text(self):
        f = RI.clean_files({"/etc/apt/sources.list": "deb http://x\x00y/ z main\x07\n", "/etc/pacman.conf": 5, "/etc/yum.conf": None})
        self.assertEqual(list(f), ["/etc/apt/sources.list"])
        self.assertNotRegex(f["/etc/apt/sources.list"], r"[\x00\x07]")
        for junk in (None, 5, [], "x", {}, {"a": 1}):
            self.assertEqual(RI.clean_files(junk), {})

    def test_rows_are_capped(self):
        text = "\n".join(f"deb http://h{i}.example/u noble main" for i in range(2000))
        self.assertLessEqual(len(RI.parse({"/etc/apt/sources.list": text})), RI.MAX_ROWS)

    def test_a_hostile_url_is_text(self):
        r = one({"/etc/apt/sources.list": "deb http://<img src=x onerror=alert(1)>/u noble main\ndeb http://[::1/u noble main\n"})
        for x in r:
            self.assertEqual(x["host"], "", "what is not a host name is not matched against the known names")
            json.dumps(x)

    def test_long_lines_are_not_slow(self):
        t0 = time.time()
        for text in ("deb [" + "a=b " * 20000, "deb " + "x" * 200000 + " y z", "[" * 100000, "Types: deb\n" + "URIs: " + "h " * 50000 + "\n",
                     "deb [" * 20000):
            RI.parse(RI.clean_files({"/etc/apt/sources.list": text, "/etc/yum.repos.d/a.repo": text, "/etc/pacman.conf": text,
                                     "/etc/apt/sources.list.d/a.sources": text}))
        self.assertLess(time.time() - t0, 3.0)

    def test_random_text_never_raises(self):
        rnd = random.Random(3)
        frags = ["deb ", "deb-src ", "[", "]", "trusted=yes ", "http://", "https://", "x.example", " ", "\n", "\n\n", "Types: ", "URIs: ",
                 "Suites: ", "[core]", "[options]", "Server = ", "Include = ", "SigLevel = Never", "baseurl=", "gpgcheck=0", "enabled=", "=", "#", "é", "\x00"]
        paths = ["/etc/apt/sources.list", "/etc/apt/sources.list.d/a.sources", "/etc/yum.repos.d/a.repo", "/etc/pacman.conf", "/etc/dnf/dnf.conf"]
        for _ in range(300):
            files = {p: "".join(rnd.choice(frags) for _ in range(rnd.randint(1, 50))) for p in paths if rnd.random() < 0.8}
            rows = RI.parse(RI.clean_files(files))
            for found in RI.evaluate(rows):
                json.dumps(found)


# ── the agent ─────────────────────────────────────────────────────────────────────────────────────────────────────────
def load_agent():
    loader = importlib.machinery.SourceFileLoader("agent_ri_under_test", str(ROOT / "client" / "remotepower-agent.py"))
    spec = importlib.util.spec_from_loader("agent_ri_under_test", loader)
    agent = importlib.util.module_from_spec(spec)           # type: ignore[arg-type]
    loader.exec_module(agent)                                # type: ignore[union-attr]
    return agent


class TestTheAgent(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.agent = load_agent()

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="rp-ri-agent-"))
        (self.root / "etc" / "apt" / "sources.list.d").mkdir(parents=True)
        (self.root / "etc" / "yum.repos.d").mkdir(parents=True)
        self._patches = [mock.patch.object(self.agent, "host_path", lambda p: str(self.root) + p),
                         mock.patch.object(self.agent, "unhost_path", lambda p: p[len(str(self.root)):] if p.startswith(str(self.root)) else p)]
        for p in self._patches:
            p.start()
        self.agent._REPO_STATE.update(hash="", sent=0)

    def tearDown(self):
        for p in self._patches:
            p.stop()

    def put(self, rel, text):
        f = self.root / rel.lstrip("/")
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)

    def test_comments_and_blank_runs_are_dropped_and_one_blank_line_kept(self):
        t = self.agent._compact_repo_text("# top\n\nTypes: deb\nURIs: http://a\n\n\n\n# mid\n; also\nTypes: deb\n\n")
        self.assertEqual(t, "Types: deb\nURIs: http://a\n\nTypes: deb")
        self.assertEqual(self.agent._compact_repo_text("x" * 500)[:301], "x" * 300, "a line is cut at 300")
        self.assertEqual(self.agent._compact_repo_text(None), "")

    def test_the_files_are_found_and_named_without_the_host_root(self):
        self.put("/etc/apt/sources.list", "deb http://deb.debian.org/debian bookworm main\n")
        self.put("/etc/apt/sources.list.d/docker.list", DOCKER_LIST)
        self.put("/etc/apt/sources.list.d/ubuntu.sources", UBUNTU_SOURCES)
        self.put("/etc/apt/sources.list.d/notes.txt", "not a repository")
        self.put("/etc/yum.repos.d/f.repo", FEDORA_REPO)
        self.put("/etc/pacman.conf", PACMAN_CONF)
        self.put("/etc/dnf/dnf.conf", "[main]\ngpgcheck=1\n# c\n")
        files = self.agent.get_repo_files()
        self.assertEqual(set(files), {"/etc/apt/sources.list", "/etc/apt/sources.list.d/docker.list", "/etc/apt/sources.list.d/ubuntu.sources",
                                      "/etc/yum.repos.d/f.repo", "/etc/pacman.conf", "/etc/dnf/dnf.conf"})
        self.assertEqual(files["/etc/dnf/dnf.conf"], "[main]\ngpgcheck=1")
        self.assertEqual(RI.clean_files(files).keys(), files.keys(), "every path the agent sends is one the server keeps")
        rows = RI.parse(RI.clean_files(files))
        self.assertTrue({"apt", "deb822", "yum", "pacman"} <= {r["kind"] for r in rows})

    def test_nothing_is_sent_when_nothing_changed(self):
        self.put("/etc/apt/sources.list", "deb http://deb.debian.org/debian bookworm main\n")
        self.assertIsNotNone(self.agent.get_repo_files())
        self.assertIsNone(self.agent.get_repo_files(), "the same text is not sent again")
        self.put("/etc/apt/sources.list", "deb http://deb.debian.org/debian trixie main\n")
        self.assertIsNotNone(self.agent.get_repo_files(), "a change is")

    def test_it_is_sent_again_after_a_while_and_when_forced(self):
        self.put("/etc/apt/sources.list", "deb http://deb.debian.org/debian bookworm main\n")
        self.agent.get_repo_files()
        self.agent._REPO_STATE["sent"] -= self.agent.REPO_RESEND_S + 5
        self.assertIsNotNone(self.agent.get_repo_files())
        self.assertIsNotNone(self.agent.get_repo_files(force=True))

    def test_a_host_with_no_repositories_sends_nothing(self):
        self.assertIsNone(self.agent.get_repo_files())
        self.put("/etc/apt/sources.list", "# only a comment\n\n")
        self.assertIsNone(self.agent.get_repo_files())

    def test_a_file_that_is_too_big_is_cut(self):
        self.put("/etc/apt/sources.list", "\n".join(f"deb http://h{i}.example/u noble main" for i in range(2000)))
        files = self.agent.get_repo_files()
        self.assertLessEqual(len(files["/etc/apt/sources.list"]), self.agent._REPO_FILE_MAX)

    def test_extensionless_agent_is_the_same_file(self):
        self.assertEqual((ROOT / "client" / "remotepower-agent").read_bytes(), (ROOT / "client" / "remotepower-agent.py").read_bytes())


# ── the server ────────────────────────────────────────────────────────────────────────────────────────────────────────
class _RI(_Base):
    STORES = _Base.STORES + ("REPO_INVENTORY_FILE", "ROLES_FILE")

    def setUp(self):
        super().setUp()
        os.environ["QUERY_STRING"] = ""
        api.save(api.REPO_INVENTORY_FILE, {})
        devs = api.load(api.DEVICES_FILE)
        devs["devB2"] = {"name": "b2", "tenant": "tenantB", "token_hash": "x", "monitored": False}
        api.save(api.DEVICES_FILE, devs)
        api.save(api.USERS_FILE, dict(api.load(api.USERS_FILE), bviewer={"role": "viewer", "tenant_id": "tenantB"}))
        api.save(api.ROLES_FILE, {"roles": []})
        api._LOAD_CACHE.clear()

    def report(self, dev, files, now=None):
        return api.repo_inventory_ingest(dev, files, now or int(time.time()))

    def listing(self, who="badmin", query=""):
        os.environ["QUERY_STRING"] = query
        r = self.call(api.handle_repositories, m="GET", who=who)
        os.environ["QUERY_STRING"] = ""
        return r

    def stored(self, dev):
        api._LOAD_CACHE.clear()
        return (api.load(api.REPO_INVENTORY_FILE) or {}).get(dev)


class TestIngest(_RI):

    def test_it_is_stored_once_and_not_rewritten_while_it_is_the_same(self):
        files = {"/etc/apt/sources.list.d/docker.list": DOCKER_LIST}
        self.assertTrue(self.report("devB", files, now=1000))
        first = self.stored("devB")
        self.assertEqual((first["ts"], list(first["files"])), (1000, ["/etc/apt/sources.list.d/docker.list"]))
        self.assertFalse(self.report("devB", files, now=1500), "unchanged, and reported lately")
        self.assertEqual(self.stored("devB")["ts"], 1000)
        self.assertTrue(self.report("devB", files, now=1000 + api.repo_inventory_handlers_mod.TOUCH_EVERY_S + 1), "the time is refreshed now and then")
        self.assertTrue(self.report("devB", {"/etc/apt/sources.list": DEBIAN_LIST}, now=1600), "a change is written at once")
        self.assertEqual(list(self.stored("devB")["files"]), ["/etc/apt/sources.list"])

    def test_nothing_usable_changes_nothing(self):
        self.report("devB", {"/etc/apt/sources.list": DEBIAN_LIST}, now=1000)
        for junk in (None, {}, [], "x", 5, {"/etc/shadow": "root:x"}, {"/etc/apt/sources.list": 5}):
            self.assertFalse(self.report("devB", junk, now=9999), repr(junk))
        self.assertEqual(self.stored("devB")["ts"], 1000)
        self.assertNotIn("/etc/shadow", json.dumps(self.stored("devB")))

    def test_the_stored_text_is_capped(self):
        self.report("devB", {f"/etc/apt/sources.list.d/{i}.list": "z" * 12000 for i in range(40)})
        self.assertLessEqual(sum(len(v) for v in self.stored("devB")["files"].values()), RI.MAX_TOTAL_BYTES)

    def test_a_deleted_host_takes_its_repositories_with_it(self):
        self.report("devB", {"/etc/apt/sources.list": DEBIAN_LIST})
        api._purge_device("devB")
        self.assertIsNone(self.stored("devB"))


class TestTheListing(_RI):

    def setUp(self):
        super().setUp()
        self.report("devB", {"/etc/apt/sources.list": DEBIAN_LIST, "/etc/apt/sources.list.d/docker.list": DOCKER_LIST})
        self.report("devB2", {"/etc/apt/sources.list": DEBIAN_LIST, "/etc/apt/sources.list.d/docker.list": DOCKER_LIST.replace("signed-by=/etc/apt/keyrings/docker.asc", "trusted=yes")})
        self.report("devC", {"/etc/apt/sources.list.d/c-secret.list": "deb https://c-secret.example/u noble main\n"})

    def test_one_row_per_repository_with_the_hosts_that_use_it(self):
        st, d = self.listing()
        self.assertEqual(st, 200)
        by = {(r["host"], r["suite"], r["signed"], tuple(r["types"])): r for r in d["repositories"]}
        deb = by[("deb.debian.org", "bookworm", True, ("deb",))]
        self.assertEqual(deb["host_count"], 2)
        self.assertEqual(sorted(h["device"] for h in deb["hosts"]), ["b1", "b2"])
        src = [r for r in d["repositories"] if r["types"] == ["deb-src"]]
        self.assertEqual(len(src), 1, "the source line is its own row")
        self.assertEqual(src[0]["host_count"], 2)
        self.assertEqual(d["hosts_reporting"], 2)

    def test_the_same_repository_configured_differently_is_two_rows(self):
        st, d = self.listing()
        docker = [r for r in d["repositories"] if r["host"] == "download.docker.com"]
        self.assertEqual(sorted(r["signed"] for r in docker), [False, True])
        worst = max(docker, key=lambda r: r["counts"]["high"])
        self.assertEqual((worst["signed"], worst["worst"]), (False, "high"))
        self.assertEqual(d["repositories"][0]["key"], worst["key"], "the worst row leads")

    def test_summary_and_the_floor(self):
        st, d = self.listing()
        s = d["summary"]
        self.assertEqual((s["high"], s["third_party"]), (1, 2))
        st, d2 = self.listing(query="min=high")
        self.assertEqual([r["host"] for r in d2["repositories"]], ["download.docker.com"])
        self.assertEqual(d2["summary"], d["summary"], "the header does not move with the filter")
        st, d3 = self.listing(query="min=nonsense")
        self.assertEqual(len(d3["repositories"]), len(d["repositories"]))

    def test_the_filter_and_one_host(self):
        for q, n in (("docker", 2), ("DEBIAN", 3), ("b2", 4), ("no-such", 0)):
            st, d = self.listing(query=f"q={q}")
            self.assertEqual(len(d["repositories"]), n, q)
        st, d = self.listing(query="host=devB2")
        self.assertEqual(d["hosts_reporting"], 1)
        self.assertTrue(all([h["device_id"] for h in r["hosts"]] == ["devB2"] for r in d["repositories"]))

    def test_a_tenant_sees_only_its_own_hosts(self):
        for who in ("badmin", "bviewer"):
            blob = json.dumps(self.listing(who)[1])
            self.assertNotIn("c-secret", blob, who)
            self.assertNotIn("devC", blob, who)
        st, d = self.listing("cadmin")
        self.assertEqual([r["host"] for r in d["repositories"]], ["c-secret.example"])
        self.assertNotIn("download.docker.com", json.dumps(d))
        self.assertIn("c-secret", json.dumps(self.listing("platform")[1]))

    def test_a_host_that_lists_one_repository_twice_is_one_host_of_it(self):
        self.report("devB", {"/etc/apt/sources.list": DEBIAN_LIST, "/etc/apt/sources.list.d/again.list": "deb http://deb.debian.org/debian bookworm main\n"})
        st, d = self.listing()
        deb = [r for r in d["repositories"] if r["host"] == "deb.debian.org" and r["suite"] == "bookworm" and r["types"] == ["deb"] and r["signed"]][0]
        self.assertEqual(deb["host_count"], 2, "b1 and b2, not b1 twice")
        self.assertEqual(len(deb["hosts"]), 2)
        self.assertEqual(sorted(h["device_id"] for h in deb["hosts"]), ["devB", "devB2"])

    def test_the_other_verbs_and_anonymous(self):
        self.assertEqual(self.listing(None)[0], 401)
        self.assertEqual(self.call(api.handle_repositories, m="POST")[0], 405)
        self.assertEqual(self.listing("bviewer")[0], 200)

    def test_an_unmonitored_host_is_listed_and_flagged(self):
        st, d = self.listing()
        flagged = [h for r in d["repositories"] for h in r["hosts"] if h["device_id"] == "devB2"]
        self.assertTrue(flagged and not any(h["monitored"] for h in flagged))

    def test_a_hand_edited_store_does_not_break_it(self):
        api.save(api.REPO_INVENTORY_FILE, {"devB": {"ts": "x", "files": {"/etc/apt/sources.list": 5, "/etc/shadow": "x"}}, "devB2": "junk", "devC": {"files": "nope"}})
        st, d = self.listing()
        self.assertEqual(st, 200, d)

    def test_the_answer_is_capped(self):
        text = "\n".join(f"deb http://h{i}.example/u noble main" for i in range(400))
        devs = api.load(api.DEVICES_FILE)
        for i in range(3):
            devs[f"big{i}"] = {"name": f"big{i}", "tenant": "tenantB", "token_hash": "x"}
            self.report(f"big{i}", {"/etc/apt/sources.list": text.replace("h", f"g{i}h")})
        api.save(api.DEVICES_FILE, devs)
        st, d = self.listing()
        self.assertEqual(len(d["repositories"]), 500)
        self.assertTrue(d["truncated"])


class TestThroughTheHeartbeat(unittest.TestCase):
    """The hook in handle_heartbeat, with the agent's own request body."""

    DEV = "r1"

    def setUp(self):
        self._saved = {"respond": api.respond}
        self._env = dict(os.environ)
        for f, empty in ((api.ALERTS_FILE, {"alerts": []}), (api.CONTAINERS_FILE, {}), (api.CONFIG_FILE, {}), (api.MAINT_FILE, {"windows": []}),
                         (api.MAINT_SUPPRESS_LOG, {"entries": []}), (api.CMD_OUTPUT_FILE, {}), (api.REPO_INVENTORY_FILE, {})):
            api.save(f, empty)
        now = int(time.time())
        api.save(api.DEVICES_FILE, {self.DEV: {"id": self.DEV, "name": "rbox", "hostname": "rbox", "token": "tok", "last_seen": now, "enrolled": now,
                                                "tags": [], "group": "", "sysinfo": {}, "monitored": True}})
        api._LOAD_CACHE.clear()

        class _Captured(SystemExit):
            def __init__(self, status, body):
                super().__init__(0)
                self.status, self.body = status, body
        self.Captured = _Captured

        def fake(status, data):
            raise _Captured(status, data)
        api.respond = fake

    def tearDown(self):
        api.respond = self._saved["respond"]
        os.environ.clear()
        os.environ.update(self._env)
        api._LOAD_CACHE.clear()

    def beat(self, sysinfo):
        import io
        raw = json.dumps({"device_id": self.DEV, "token": "tok", "sysinfo": sysinfo}).encode()
        os.environ.update({"REQUEST_METHOD": "POST", "PATH_INFO": "/api/heartbeat", "QUERY_STRING": "", "CONTENT_LENGTH": str(len(raw))})
        for k in ("HTTP_X_TOKEN", "HTTP_X_RP_VAULT_KEY"):
            os.environ.pop(k, None)

        class _Stdin:
            def __init__(self, data):
                self.buffer = io.BytesIO(data)
        api.sys.stdin = _Stdin(raw)
        api._LOAD_CACHE.clear()
        try:
            api.handle_heartbeat()
        except self.Captured:
            pass
        api._LOAD_CACHE.clear()
        return (api.load(api.REPO_INVENTORY_FILE) or {}).get(self.DEV)

    def test_the_files_land_in_their_own_store_and_not_in_the_host_record(self):
        rec = self.beat({"repo_files": {"/etc/apt/sources.list.d/docker.list": DOCKER_LIST}})
        self.assertEqual(list(rec["files"]), ["/etc/apt/sources.list.d/docker.list"])
        self.assertNotIn("repo_files", (api.load(api.DEVICES_FILE)[self.DEV].get("sysinfo") or {}), "the device record is rewritten every beat; this is not in it")

    def test_a_report_without_them_leaves_the_store_alone(self):
        self.beat({"repo_files": {"/etc/apt/sources.list": DEBIAN_LIST}})
        rec = self.beat({"uptime": "up 1 day"})
        self.assertEqual(list(rec["files"]), ["/etc/apt/sources.list"], "a beat the agent sent nothing new in is not a change")

    def test_hostile_values_do_not_fail_the_beat(self):
        for junk in ("x", 5, [], {"/etc/shadow": "x"}, {"/etc/apt/sources.list": {"a": 1}}):
            self.beat({"repo_files": junk})      # must not raise out of the handler
        self.assertIsNone((api.load(api.REPO_INVENTORY_FILE) or {}).get(self.DEV))


class TestRegistration(unittest.TestCase):

    def test_routes_store_and_baselines(self):
        import storage
        src = (ROOT / "server" / "cgi-bin" / "api.py").read_text()
        self.assertIn("('GET', '/api/repositories'): handle_repositories", src)
        self.assertIn("repo_inventory_ingest(dev_id, body['sysinfo']['repo_files']", src)
        self.assertIn("REPO_INVENTORY_FILE,            # 7.4.9", src)
        self.assertIn("repo_inventory.json", storage.ENTITY_FILES)
        self.assertIn("repo_inventory.json", store_shapes.SHAPES)
        self.assertEqual((ROOT / "Makefile").read_text().count("server/cgi-bin/repo_inventory.py"), 2)

    def test_the_shape_of_the_store(self):
        fixed = store_shapes.normalize("repo_inventory.json", {"h1": {"ts": "5", "files": {"/etc/pacman.conf": "x"}}, "h2": "junk", "h3": {"files": "x"}})
        self.assertEqual(fixed["h1"]["ts"], 5)
        self.assertNotIn("h2", fixed)
        self.assertEqual(fixed["h3"].get("files", {}), {}, "a files entry that is not a map is repaired to one")


if __name__ == "__main__":
    unittest.main()

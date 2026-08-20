#!/usr/bin/env python3
"""Three supply-chain gaps in the things this product downloads and depends on.

1. The web terminal's pip fallback printed `asyncssh>=2.10`. asyncssh below
   2.14.2 is an SSH CLIENT with known session-hijack and algorithm-downgrade
   flaws (CVE-2023-46445, CVE-2023-46446 "Rogue Session", Terrapin prefix
   truncation). remotepower-webterm IS that client and it is the operator's
   interactive gateway into every managed host, so an attacker on the path
   between the gateway and a target is exactly the threat model those describe.
   The distro-package branches are current on supported releases; the pip
   fallback was the hole.

2. Dockerfile.scanner pinned nuclei 3.3.5 (upstream is 3.11.1) and unzipped it
   straight into /usr/local/bin with no integrity check. Two faults: a
   vulnerability scanner on a stale engine reports clean and means nothing,
   because current template packs assume a newer engine and their detections
   are skipped in silence; and everywhere else in this repo a downloaded
   artifact is verified — the agent one-liner pins a sha256, both PKGBUILDs
   PGP-verify the tarball — while this one became a root-owned binary on the
   strength of an HTTPS fetch alone.

3. The Dependabot pip watcher pointed at "/", which holds no Python manifest —
   pyproject.toml has only tool config, no [project]. The only manifest is
   packaging/requirements-server.txt. So the one mechanism meant to surface a
   drifting dependency resolved nothing and opened zero PRs, and it failed
   silently because a watcher with nothing to watch looks exactly like a
   watcher with nothing to report.
"""
import pathlib
import re
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _text(rel):
    p = _ROOT / rel
    return p.read_text() if p.exists() else None


class TestTheWebTerminalRefusesAVulnerableSshClient(unittest.TestCase):

    def setUp(self):
        self.sh = _text('packaging/install-webterm.sh')
        if self.sh is None:
            self.skipTest('excluded from dist tree')

    def test_the_printed_pip_line_names_a_safe_floor(self):
        self.assertNotIn("asyncssh>=2.10", self.sh)
        self.assertIn("asyncssh>=2.14.2", self.sh)

    def test_the_installer_asserts_the_version_it_got(self):
        """Printing a floor is advice. The distro branches install whatever the
        distro has, so the check has to run against what is actually
        importable."""
        self.assertIn('asyncssh.__version__', self.sh)
        self.assertIn('(2,14,2)', self.sh)

    def test_the_gate_accepts_and_rejects_the_right_versions(self):
        """Run the same comparison the installer runs. A version gate that is
        wrong in either direction is worse than none: too strict blocks a
        current distro package, too loose is the bug."""
        def ok(v):
            t = tuple(int(x) for x in v.split('.')[:3])
            return t >= (2, 14, 2)
        for bad in ('2.10.0', '2.13.2', '2.14.0', '2.14.1'):
            self.assertFalse(ok(bad), bad)
        for good in ('2.14.2', '2.15.0', '2.21.0', '3.0.0'):
            self.assertTrue(ok(good), good)

    def test_the_failure_message_says_why(self):
        # From the version comparison to the end of its guard block.
        i = self.sh.index('(2,14,2)')
        seg = self.sh[i:self.sh.index('\n  fi\n', i)]
        self.assertIn('CVE-2023-46445', seg)


class TestTheScannerBinaryIsVerified(unittest.TestCase):

    def setUp(self):
        self.df = _text('Dockerfile.scanner')
        if self.df is None:
            self.skipTest('excluded from dist tree')

    def test_the_download_is_checksummed_before_it_is_unpacked(self):
        self.assertIn('checksums.txt', self.df)
        self.assertIn('sha256sum -c', self.df)
        # Anchor on the EXTRACTION, not the first 'unzip' in the file — that
        # one is the apt-get install line, and comparing against it reported a
        # correct Dockerfile as unverified.
        self.assertLess(self.df.index('sha256sum -c'), self.df.index('unzip -q'),
                        'the archive is unpacked before it is verified')

    def test_the_checksum_line_is_selected_for_the_built_arch(self):
        """A whole-file `sha256sum -c` would try to verify every artifact in
        the release and fail on the ones that were never downloaded."""
        self.assertRegex(self.df, r'grep\s+"[^"]*nuclei_\$\{NUCLEI_VERSION\}_linux_\$\{NARCH\}\.zip')

    def test_the_pinned_version_is_not_the_stale_one(self):
        m = re.search(r'ARG NUCLEI_VERSION=([0-9.]+)', self.df)
        self.assertTrue(m, 'the version pin is gone')
        got = tuple(int(x) for x in m.group(1).split('.'))
        self.assertGreaterEqual(
            got, (3, 11, 1),
            'nuclei is pinned behind 3.11.1 — a scanner on a stale engine '
            'reports clean and means nothing')


class TestTheDependencyWatcherPointsAtAManifest(unittest.TestCase):

    def setUp(self):
        self.yml = _text('.github/dependabot.yml')
        if self.yml is None:
            self.skipTest('excluded from dist tree')

    def _pip_directory(self):
        m = re.search(r'package-ecosystem:\s*"pip"\s*\n\s*directory:\s*"([^"]+)"',
                      self.yml)
        self.assertTrue(m, 'no pip watcher in dependabot.yml')
        return m.group(1)

    def test_the_pip_watcher_directory_contains_a_manifest(self):
        d = self._pip_directory().strip('/')
        base = _ROOT / d if d else _ROOT
        manifests = ('requirements.txt', 'requirements-server.txt', 'Pipfile',
                     'setup.py', 'pyproject.toml')
        found = [m for m in manifests if (base / m).exists()]
        # pyproject.toml only counts if it actually declares dependencies.
        if found == ['pyproject.toml']:
            body = (base / 'pyproject.toml').read_text()
            self.assertIn('[project]', body,
                          'pyproject.toml has only tool config, so Dependabot '
                          'resolves nothing here')
        self.assertTrue(found,
                        f'dependabot points pip at "{self._pip_directory()}" '
                        f'which holds no Python manifest — the watcher opens '
                        f'zero PRs and looks the same as having nothing to '
                        f'report')

    def test_the_repo_root_still_has_no_manifest(self):
        """The control for the check above. If a manifest ever lands at the
        root, pointing pip at "/" becomes correct again and this test should be
        the thing that says so rather than silently passing."""
        body = _text('pyproject.toml') or ''
        root_has = any((_ROOT / m).exists() for m in
                       ('requirements.txt', 'Pipfile', 'setup.py'))
        self.assertFalse(root_has or '[project]' in body,
                         'a manifest now exists at the repo root — revisit '
                         'whether the pip watcher should point at "/" again')


if __name__ == '__main__':
    unittest.main()

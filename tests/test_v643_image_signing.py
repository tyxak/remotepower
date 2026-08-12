#!/usr/bin/env python3
"""The artifact most people actually run was the unsigned one.

The release tarball has been GPG-signed since v4.6.0 — checksum, detached
`.asc`, AUR packages PGP-verifying it at build time, agents able to refuse an
unsigned binary. The container image, which is how anyone using Docker actually
gets RemotePower, had no signature at all. It carried SLSA build provenance
(v5.4.1) and nothing that says "this is ours".

v6.4.3 signs both images with cosign, keyless. Keyless is the point rather than
a convenience: the whole reason the GPG key is generated and used LOCALLY is
that CI must not hold a signing key, so putting a cosign key in CI would
reintroduce exactly the thing the local-signing rule exists to avoid. A keyless
signature binds to the workflow's OIDC identity, and there is nothing to leak.

The tests below pin the four things that make this a real control rather than a
box tick:

  1. Both images are signed, not just the server one.
  2. Signing is BY DIGEST. A tag is a mutable pointer; signing `:latest`
     attests to whatever it points at next.
  3. `id-token: write` is present — without it the keyless signature cannot be
     obtained and the step fails at release time, which is the worst moment.
  4. The documented verification passes BOTH --certificate-identity-regexp and
     --certificate-oidc-issuer. A bare `cosign verify` accepts a signature from
     any Sigstore identity, i.e. anyone with a GitHub account. It proves the
     image was signed, not by whom — which is not a check, and would be worse
     than no signature because it reads like one.
"""
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_WF = _ROOT / '.github' / 'workflows' / 'release.yml'


def _load():
    try:
        import yaml
    except ImportError:
        return None
    return yaml.safe_load(_WF.read_text())


class TestBothImagesAreSigned(unittest.TestCase):
    def setUp(self):
        if not _WF.exists():
            self.skipTest('.github excluded from dist tree')
        self.doc = _load()
        if self.doc is None:
            self.skipTest('PyYAML unavailable')

    def _sign_steps(self, job):
        return [s for s in self.doc['jobs'][job]['steps']
                if 'cosign sign' in (s.get('run') or '')]

    def test_the_server_image_is_signed(self):
        self.assertTrue(self._sign_steps('docker'))

    def test_the_agent_image_is_signed_too(self):
        """The agent image runs on every managed host — the wider blast radius
        of the two, and the easier one to forget."""
        self.assertTrue(self._sign_steps('docker-agent'))

    def test_each_job_signs_its_own_image(self):
        self.assertIn('${{ github.repository }}@',
                      self._sign_steps('docker')[0]['run'])
        self.assertIn('${{ github.repository }}-agent@',
                      self._sign_steps('docker-agent')[0]['run'])

    def test_signing_is_by_digest_not_by_tag(self):
        """A tag is a mutable pointer. Signing `:latest` attests to whatever it
        points at next; signing the digest covers every tag pushed to it."""
        for job in ('docker', 'docker-agent'):
            with self.subTest(job=job):
                run = self._sign_steps(job)[0]['run']
                self.assertIn('@${DIGEST}', run)
                self.assertNotRegex(run, r'cosign sign[^\n]*:\$\{\{')
                self.assertNotRegex(run, r'cosign sign[^\n]*:latest')

    def test_the_digest_comes_from_the_build_step(self):
        for job in ('docker', 'docker-agent'):
            with self.subTest(job=job):
                step = self._sign_steps(job)[0]
                self.assertEqual((step.get('env') or {}).get('DIGEST'),
                                 '${{ steps.build.outputs.digest }}')
                ids = [s.get('id') for s in self.doc['jobs'][job]['steps']]
                self.assertIn('build', ids,
                              'the build step needs id: build or the digest '
                              'expression resolves to empty and cosign signs '
                              'the literal string "@"')

    def test_cosign_is_installed_before_it_is_used(self):
        for job in ('docker', 'docker-agent'):
            with self.subTest(job=job):
                steps = self.doc['jobs'][job]['steps']
                inst = [i for i, s in enumerate(steps)
                        if 'cosign-installer' in (s.get('uses') or '')]
                sign = [i for i, s in enumerate(steps)
                        if 'cosign sign' in (s.get('run') or '')]
                self.assertTrue(inst, 'cosign is never installed')
                self.assertLess(inst[0], sign[0])

    def test_id_token_write_is_granted(self):
        """Keyless signing needs an OIDC token. Without this permission the
        step fails at release time — the worst possible moment to find out."""
        perms = self.doc.get('permissions') or {}
        self.assertEqual(perms.get('id-token'), 'write')

    def test_signing_stays_on_the_production_repo_only(self):
        for job in ('docker', 'docker-agent'):
            with self.subTest(job=job):
                self.assertIn("github.repository == 'tyxak/remotepower'",
                              self.doc['jobs'][job]['if'])

    def test_no_signing_key_is_introduced_into_ci(self):
        """The premise of keyless. A cosign key in CI would defeat the reason
        the GPG key is kept local."""
        src = _WF.read_text()
        self.assertNotIn('COSIGN_PRIVATE_KEY', src)
        self.assertNotIn('cosign.key', src)
        self.assertNotRegex(src, r'cosign sign[^\n]*--key')


class TestTheDocumentedVerificationIsActuallyACheck(unittest.TestCase):
    """A verify command missing either flag proves the image was signed, not by
    whom — for a keyless signature that means anyone with a GitHub account. It
    would read like a check while being none, which is worse than omitting it."""

    FILES = ('docs/security.md', 'docs/install.md')

    def _verify_commands(self, text):
        """Each `cosign verify` invocation inside a FENCED CODE BLOCK, with its
        `\\`-continued lines.

        Code blocks only, deliberately. The prose right below each example says
        "a bare `cosign verify` accepts a signature from any identity" — which
        is the sentence explaining why both flags are required. Scanning raw
        text makes this test fail on its own rationale, the same
        assert-against-comments trap that has bitten source pins twice.
        """
        blocks = re.findall(r'```[a-z]*\n(.*?)```', text, re.S)
        out = []
        for b in blocks:
            out += [m.group(0) for m in
                    re.finditer(r'cosign verify(?:[^\n]*\\\n)*[^\n]*', b)]
        return out

    def test_every_documented_verify_pins_the_identity(self):
        found = 0
        for rel in self.FILES:
            p = _ROOT / rel
            if not p.exists():
                continue
            for cmd in self._verify_commands(p.read_text()):
                found += 1
                with self.subTest(file=rel, cmd=cmd[:60]):
                    self.assertIn('--certificate-identity', cmd)
                    self.assertIn('--certificate-oidc-issuer', cmd)
        self.assertGreater(found, 0, 'no cosign verify example is documented '
                                     'anywhere — an unverifiable signature is '
                                     'a signature nobody checks')

    def test_the_identity_names_this_repo_and_workflow(self):
        src = (_ROOT / 'docs' / 'security.md').read_text()
        self.assertIn('github.com/tyxak/remotepower/', src)
        self.assertIn('release', src)

    def test_nobody_documents_skipping_the_transparency_log(self):
        for rel in self.FILES + ('docs/features.md', 'README.md'):
            p = _ROOT / rel
            if p.exists():
                with self.subTest(file=rel):
                    self.assertNotIn('--insecure-ignore-tlog', p.read_text())

    def test_the_pull_instructions_mention_verification(self):
        """Nobody reads security.md before `docker pull`. The check has to be
        next to the command it applies to."""
        src = (_ROOT / 'docs' / 'install.md').read_text()
        i = src.find('docker pull ghcr.io/tyxak/remotepower')
        self.assertGreater(i, 0)
        self.assertIn('cosign verify', src[i:i + 2500])


if __name__ == '__main__':
    unittest.main()

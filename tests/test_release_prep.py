"""tools/release-prep.py — bump / prune / counts / verify against a minimal
fixture tree (NEVER --apply against the real repo from tests)."""
import contextlib
import importlib.util
import io
import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-relprep-t-'))

_ROOT = Path(__file__).resolve().parent.parent
_TOOL = _ROOT / 'tools' / 'release-prep.py'

_spec = importlib.util.spec_from_file_location('release_prep', _TOOL)
rp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rp)

EM = '—'  # —


def build_fixture(root: Path):
    """Minimal repo tree carrying every surface the tool touches."""
    (root / 'server/cgi-bin').mkdir(parents=True)
    (root / 'server/html').mkdir(parents=True)
    (root / 'client').mkdir()
    (root / 'docs').mkdir()
    (root / 'tools').mkdir()
    (root / 'tests').mkdir()

    # api.py: version + a real WEBHOOK_EVENT_NAMES, padded to ~3000 lines so
    # the README line-count rounds to a non-zero thousand.
    api = ["SERVER_VERSION = '5.6.0'",
           "WEBHOOK_EVENT_NAMES = ('a_event', 'b_event', 'c_event')"]
    api += ['# pad'] * 2960
    (root / 'server/cgi-bin/api.py').write_text('\n'.join(api) + '\n')

    (root / 'server/cgi-bin/integrations.py').write_text(
        'def _register(*a, **k):\n'
        '    def deco(fn):\n'
        '        return fn\n'
        '    return deco\n\n\n'
        '@_register(\n    "pihole",\n    "Pi-hole",\n)\n'
        'def pihole(inst, http):\n    return {}\n\n\n'
        '@_register(\n    "truenas",\n    "TrueNAS",\n)\n'
        'def truenas(inst, http):\n    return {}\n\n\n'
        '@_register(\n    "custom_probe",\n    "Custom HTTP",\n)\n'
        'def custom_probe(inst, http):\n    return {}\n')

    agent = "#!/usr/bin/env python3\nVERSION      = '5.6.0'\nprint('agent')\n"
    (root / 'client/remotepower-agent.py').write_text(agent)
    (root / 'client/remotepower-agent').write_text(agent)
    (root / 'client/remotepower-agent-win.py').write_text(
        "VERSION = '5.6.0'\n")
    (root / 'client/remotepower-agent-mac.py').write_text(
        "VERSION = '5.6.0'\n")

    (root / 'server/html/sw.js').write_text(
        "const CACHE_NAME = 'remotepower-shell-v5.6.0-50';   // bump\n")

    (root / 'server/html/index.html').write_text(
        '<link href="styles.css?v=5.6.0">\n'
        '<script src="app.js?v=5.6.0-48"></script>\n'
        '<script src="app-ai.js?v=5.6.0"></script>\n'
        f'<summary><strong>What\'s new {EM} v5.6.0 "HeapMatters"</strong>'
        '</summary>\n'
        '<a href="docs/security-review-5.2.0.md">old review</a>\n')

    bullets = '\n'.join(
        f'- **v5.{i}.0 {EM} Name{i}** {EM} blurb for 5.{i}.0.'
        for i in range(6, -1, -1))          # 7 bullets, newest first
    (root / 'README.md').write_text(
        '# RemotePower\n\n'
        '[![Version](https://img.shields.io/badge/version-5.6.0-blue.svg)]'
        '(x)\n\n'
        '**~2,000 lines** of server Python, one HTML file.\n\n'
        '| **Integrate** | 9 **homelab-app** health connectors (Pi-hole) |\n\n'
        f'### Recent releases\n\n{bullets}\n\n'
        'Old notes: [v5.0.0 notes](docs/v5.0.0.md) and '
        '[review](docs/security-review-5.2.0.md).\n')

    (root / 'CHANGELOG.md').write_text(
        f'# Changelog\n\n## v5.6.0 {EM} "HeapMatters" {EM} 2026-07-01\n\n'
        '- stuff\n')

    # 7 version docs (keep-3 → delete 4 oldest), 4 public reviews (keep-3 →
    # delete 1), one -internal review that must never be touched.
    for i in range(7):
        (root / f'docs/v5.{i}.0.md').write_text(f'# v5.{i}.0\n')
    for v in ('5.2.0', '5.3.0', '5.5.0', '5.6.0'):
        (root / f'docs/security-review-{v}.md').write_text(f'# review {v}\n')
    (root / 'docs/security-review-4.8.0-internal.md').write_text('# internal\n')

    idx_entries = '\n'.join(
        f'- **[v5.{i}.0.md](v5.{i}.0.md)** {EM} "Name{i}": blurb line one\n'
        ' wrapped continuation line.'
        for i in range(6, -1, -1))          # 7 multi-line entries
    (root / 'docs/README.md').write_text(
        '# Docs\n\nThe five most recent per-release notes are kept here:\n\n'
        f'{idx_entries}\n\n'
        'Older: [CHANGELOG.md](../CHANGELOG.md). '
        'See also [review](security-review-5.2.0.md).\n')

    (root / 'docs/features.md').write_text(
        '| Feature | Notes |\n|---|---|\n'
        '| Webhook event registry | 93 event types, per-event toggles |\n'
        '| 9 connectors (+ Custom HTTP) | Pi-hole, TrueNAS |\n')

    (root / 'docs/security.md').write_text('# Security\n')

    (root / 'tools/gen-wiki.py').write_text(
        'lines = [\n'
        '    f"Current release: **{newest} \\"HeapMatters\\"** '
        '— see the",\n]\n')

    (root / 'tests/test_v560.py').write_text('# pins\n')


def run(args):
    """Run the tool's main(); return (exit_code, stdout)."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = rp.main(args)
    return rc, buf.getvalue()


class FixtureCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='rp-relprep-fix-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        build_fixture(self.tmp)

    def root_args(self, *rest, apply=False):
        a = list(rest) + ['--root', str(self.tmp)]
        if apply:
            a.append('--apply')
        return a


class TestBump(FixtureCase):
    def test_dry_run_changes_nothing(self):
        before = {p: p.read_bytes()
                  for p in self.tmp.rglob('*') if p.is_file()}
        rc, out = run(self.root_args('bump', 'v5.7.0', 'TestName'))
        after = {p: p.read_bytes()
                 for p in self.tmp.rglob('*') if p.is_file()}
        self.assertEqual(before, after, 'dry-run must not write files')
        self.assertIn("SERVER_VERSION = '5.6.0'", out)
        self.assertIn('5.7.0', out)
        self.assertIn('dry-run', out)
        # warnings expected: missing test_v570.py, CHANGELOG entry,
        # what's-new card, gen-wiki codename mismatch → exit 1
        self.assertEqual(rc, 1)
        self.assertIn('test_v570.py', out)
        self.assertIn('gen-wiki.py', out)
        self.assertIn('CHANGELOG.md', out)
        self.assertIn("What's new", out)

    def test_apply_edits_all_surfaces(self):
        rc, out = run(self.root_args('bump', 'v5.7.0', 'TestName',
                                     apply=True))
        self.assertIn("SERVER_VERSION = '5.7.0'",
                      (self.tmp / 'server/cgi-bin/api.py').read_text())
        agent_py = (self.tmp / 'client/remotepower-agent.py').read_bytes()
        self.assertIn(b"VERSION      = '5.7.0'", agent_py)
        self.assertEqual(agent_py,
                         (self.tmp / 'client/remotepower-agent').read_bytes(),
                         'extensionless copy must be byte-identical')
        for a in ('client/remotepower-agent-win.py',
                  'client/remotepower-agent-mac.py'):
            self.assertIn("VERSION = '5.7.0'", (self.tmp / a).read_text())
        self.assertIn("remotepower-shell-v5.7.0-1'",
                      (self.tmp / 'server/html/sw.js').read_text(),
                      'CACHE_NAME counter must reset to -1')
        idx = (self.tmp / 'server/html/index.html').read_text()
        self.assertNotIn('?v=5.6.0', idx)
        self.assertNotRegex(idx, r'\?v=5\.7\.0-\d')
        self.assertEqual(idx.count('?v=5.7.0'), 3)
        self.assertIn('version-5.7.0-blue',
                      (self.tmp / 'README.md').read_text())
        self.assertEqual(rc, 1, 'judgment items still missing → exit 1')

    def test_apply_clean_when_judgment_items_present(self):
        (self.tmp / 'tests/test_v570.py').write_text('# pins\n')
        ch = self.tmp / 'CHANGELOG.md'
        ch.write_text(f'# Changelog\n\n## v5.7.0 {EM} "TestName" {EM} '
                      'unreleased (test)\n\n' + ch.read_text().split('\n\n', 1)[1])
        idx = self.tmp / 'server/html/index.html'
        idx.write_text(idx.read_text().replace(
            f"What's new {EM} v5.6.0", f"What's new {EM} v5.7.0"))
        gw = self.tmp / 'tools/gen-wiki.py'
        gw.write_text(gw.read_text().replace('HeapMatters', 'TestName'))
        rc, out = run(self.root_args('bump', 'v5.7.0', 'TestName',
                                     apply=True))
        self.assertEqual(rc, 0, out)
        self.assertNotIn('WARN', out)

    def test_rejects_bad_version(self):
        rc, out = run(self.root_args('bump', 'lol'))
        self.assertEqual(rc, 1)
        self.assertIn('bad version', out)


class TestPrune(FixtureCase):
    def test_dry_run_deletes_nothing_and_reports(self):
        rc, out = run(self.root_args('prune'))
        self.assertEqual(rc, 1, 'pending work → non-zero')
        for f in ('docs/v5.0.0.md', 'docs/v5.1.0.md', 'docs/v5.2.0.md',
                  'docs/v5.3.0.md', 'docs/security-review-5.2.0.md'):
            self.assertTrue((self.tmp / f).exists())
            self.assertIn(f'{f}: DELETE', out)
        # keep-3 → v5.4.0 and newer are kept
        self.assertNotIn('v5.4.0.md: DELETE', out)
        self.assertNotIn('internal', out.replace('-internal.md', ''))

    def test_apply_prunes_and_repoints(self):
        rc, out = run(self.root_args('prune', apply=True))
        # keep-3 version docs / keep-3 public reviews
        for i in range(0, 4):
            self.assertFalse((self.tmp / f'docs/v5.{i}.0.md').exists())
        for i in range(4, 7):
            self.assertTrue((self.tmp / f'docs/v5.{i}.0.md').exists())
        self.assertFalse(
            (self.tmp / 'docs/security-review-5.2.0.md').exists())
        for v in ('5.3.0', '5.5.0', '5.6.0'):
            self.assertTrue(
                (self.tmp / f'docs/security-review-{v}.md').exists())
        self.assertTrue(
            (self.tmp / 'docs/security-review-4.8.0-internal.md').exists(),
            'internal reviews are never pruned')
        # review links auto-repointed to docs/security.md
        readme = (self.tmp / 'README.md').read_text()
        self.assertNotIn('security-review-5.2.0.md', readme)
        self.assertIn('docs/security.md', readme)
        self.assertNotIn('security-review-5.2.0.md',
                         (self.tmp / 'docs/README.md').read_text())
        self.assertNotIn('security-review-5.2.0.md',
                         (self.tmp / 'server/html/index.html').read_text())
        # version-doc link only reported, not rewritten → exit 1
        self.assertIn('docs/v5.0.0.md', readme)
        self.assertIn('repoint by hand', out)
        self.assertEqual(rc, 1)
        # README recent releases trimmed to 5 (newest kept)
        self.assertEqual(len(re.findall(r'^- \*\*v', readme, re.M)), 5)
        self.assertIn('- **v5.6.0', readme)
        self.assertNotIn('- **v5.0.0', readme)
        # docs/README.md index trimmed to 5 whole blocks (no orphan wraps)
        didx = (self.tmp / 'docs/README.md').read_text()
        self.assertEqual(len(re.findall(r'^- \*\*\[v', didx, re.M)), 5)
        self.assertNotIn('[v5.0.0.md]', didx)
        self.assertNotIn('[v5.1.0.md]', didx)
        self.assertEqual(didx.count('wrapped continuation line.'), 5)

    def test_apply_idempotent_after_link_fix(self):
        run(self.root_args('prune', apply=True))
        # fix the one manual item, then a second run must be clean
        readme = self.tmp / 'README.md'
        readme.write_text(
            readme.read_text().replace('docs/v5.0.0.md', 'CHANGELOG.md'))
        rc, out = run(self.root_args('prune', apply=True))
        self.assertEqual(rc, 0, out)
        self.assertIn('nothing to trim', out)


class TestCounts(FixtureCase):
    def test_dry_run_reports_drift(self):
        rc, out = run(self.root_args('counts'))
        self.assertEqual(rc, 1, 'drift pending → non-zero')
        self.assertIn('~2,000 lines**', out)          # old value in README
        self.assertIn('~3,000 lines**', out)          # recount (~2970 lines)
        self.assertIn('homelab connectors (excl. custom probe): 2', out)
        self.assertIn('3 event types', out)
        # dry run: files untouched
        self.assertIn('~2,000 lines**',
                      (self.tmp / 'README.md').read_text())

    def test_apply_rewrites_counts(self):
        rc, out = run(self.root_args('counts', apply=True))
        self.assertEqual(rc, 0, out)
        readme = (self.tmp / 'README.md').read_text()
        self.assertIn('**~3,000 lines** of server Python', readme)
        self.assertIn('| 2 **homelab-app** health connectors', readme)
        feats = (self.tmp / 'docs/features.md').read_text()
        self.assertIn('| 3 event types', feats)
        self.assertIn('| 2 connectors (+ Custom HTTP)', feats)


class TestVerify(FixtureCase):
    def _make_clean(self):
        """Fixture starts intentionally dirty (7 docs, 7 bullets) — prune it."""
        run(self.root_args('prune', apply=True))
        readme = self.tmp / 'README.md'
        readme.write_text(
            readme.read_text().replace('docs/v5.0.0.md', 'CHANGELOG.md'))

    def test_clean_tree_passes(self):
        self._make_clean()
        rc, out = run(self.root_args('verify'))
        self.assertEqual(rc, 0, out)
        self.assertNotIn('FAIL', out)
        for name in ('features-md-purity', 'agent-extensionless-sync',
                     'docs-keep-3', 'reviews-keep-3',
                     'readme-recent-releases', 'index-cache-bust',
                     'changelog-top-header', 'version-consistency'):
            self.assertIn(f'PASS: {name}', out)

    def test_unreleased_top_header_is_accepted(self):
        self._make_clean()
        ch = self.tmp / 'CHANGELOG.md'
        ch.write_text('# Changelog\n\n## Unreleased (test)\n\n'
                      + ch.read_text().split('\n\n', 1)[1])
        rc, out = run(self.root_args('verify'))
        self.assertIn('PASS: changelog-top-header', out)

    def test_failures_detected(self):
        self._make_clean()
        # break features.md purity, agent sync, cache-bust, changelog shape
        feats = self.tmp / 'docs/features.md'
        feats.write_text(feats.read_text()
                         + '\n## v9.9.9 additions\n```\ncurl x\n```\n')
        (self.tmp / 'client/remotepower-agent').write_text('drifted\n')
        idx = self.tmp / 'server/html/index.html'
        idx.write_text(idx.read_text()
                       .replace('app.js?v=5.6.0-48', 'app.js?v=5.5.0'))
        ch = self.tmp / 'CHANGELOG.md'
        ch.write_text('# Changelog\n\n## v5.7.0: NoQuotes\n')
        # and overflow the docs cap again
        for i in range(7, 10):
            (self.tmp / f'docs/v5.{i}.0.md').write_text('x\n')
        rc, out = run(self.root_args('verify'))
        self.assertEqual(rc, 1)
        for name in ('features-md-purity', 'agent-extensionless-sync',
                     'docs-keep-3', 'index-cache-bust',
                     'changelog-top-header'):
            self.assertIn(f'FAIL: {name}', out)
        self.assertIn('stale ?v= versions: 5.5.0', out)


class TestRealRepoSmoke(unittest.TestCase):
    """Dry-run only against the real repo — a good smoke test, never --apply."""

    def test_verify_runs(self):
        rc, out = run(['verify', '--root', str(_ROOT)])
        # don't pin the verdict (repo state drifts); pin that all checks ran
        self.assertIn('== verify done:', out)
        self.assertIn('agent-extensionless-sync', out)

    def test_bump_dry_run_writes_nothing(self):
        api = _ROOT / 'server/cgi-bin/api.py'
        before = api.read_bytes()
        rc, out = run(['bump', 'v9.9.9', '--root', str(_ROOT)])
        self.assertEqual(api.read_bytes(), before)
        self.assertIn('dry-run', out)
        self.assertIn('9.9.9', out)


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
"""The release tarball's leak-check must actually match a leak.

`make dist` packs the WORKING TREE, not `git archive` output, so a gitignored
file ships unless the Makefile's hand-maintained `--exclude` list names it.
`tools/promote.sh` greps the finished tarball as the net under that list — and
the net is the important half, because the exclude list is the thing most
likely to be wrong. `.claude/` shipped in the published v5.2.0 through v5.7.0
tarballs exactly that way.

The net had a hole of its own. `make dist` renames members with
`--transform 's,^\\.,remotepower-X.Y.Z,'`, so every path in the archive reads
`remotepower-6.4.3/site/index.html`. The check's `^site/`, `^deploy/` and
`^design/` patterns were anchored at the start of the line and could not match
anything in the archive they were checking. Those three directories — the
marketing site, the deploy scripts, and the design sources — were unguarded for
as long as the check had existed, and the failure mode is silent by
construction: a pattern that matches nothing prints "leak-check clean".

That is why this file plants files rather than reading the script: a regex
reviewed by eye is how the anchors passed review in the first place. Each case
below builds a real tarball with the real `--transform` and runs the real
pattern lifted out of promote.sh.
"""
import pathlib
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_PROMOTE = _ROOT / 'tools' / 'promote.sh'
_DIST_NAME = 'remotepower-6.4.3'

# One of each class the exclude list promises to strip. A path here that the
# pattern misses is a file that would be published on GitHub Releases.
MUST_BE_CAUGHT = (
    'CLAUDE.md',
    'opencode.md',
    'MEMORY.md',
    'memory/project_notes.md',
    'docs/ops-site-deploy-internal.md',
    '.claude/settings.json',
    '.cursor/rules',
    'site/index.html',
    'deploy/deploy-server.sh',
    'design/chosen-design.html',
    'api.env',
    'secrets.enc',
    'server.key',
    'server.pem',
    '.ssh/id_ed25519',
)

# Real files that MUST ship. A leak-check that also fires on these is worse
# than none: it cannot be satisfied, so it gets bypassed.
MUST_NOT_BE_CAUGHT = (
    'server/cgi-bin/api.py',
    'docs/security.md',
    'docs/deployment.md',        # ends in .md but is not an -internal.md
    'README.md',
    'client/remotepower-agent.py',
    'server/html/static/js/app.js',
    'packaging/aur/remotepower-agent/PKGBUILD',
    'tests/test_promote_leak_check.py',
    'docs/screenshots/dash.png',
)


def _leak_pattern():
    """The grep -E pattern out of promote.sh, so the test cannot drift from
    the script by being updated on its own."""
    if not _PROMOTE.exists():
        return None                      # excluded from the dist tree
    src = _PROMOTE.read_text(encoding='utf-8')
    m = re.search(r"leaks=\"\$\(tar -tzf [^|]+\| grep -E \\\n\s*'([^']+)'", src)
    return m.group(1) if m else None


class TestPromoteTarballLeakCheck(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pattern = _leak_pattern()

    def setUp(self):
        if self.pattern is None:
            self.skipTest('tools/promote.sh not in this tree, or its '
                          'leak-check no longer matches the expected shape')

    def _archive_names(self, relpaths):
        """Build a tarball the way `make dist` does — including the transform,
        which is the whole point — and return its member names."""
        tmp = pathlib.Path(tempfile.mkdtemp(prefix='rp-leakcheck-'))
        self.addCleanup(shutil.rmtree, tmp, True)
        src = tmp / 'tree'
        for rel in relpaths:
            p = src / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text('x')
        tarball = tmp / 'out.tar.gz'
        subprocess.run(
            ['tar', '-czf', str(tarball),
             '--transform', f's,^\\.,{_DIST_NAME},', '.'],
            cwd=src, check=True, capture_output=True)
        with tarfile.open(tarball) as tf:
            # getmembers(), not getnames() — tarfile reports a directory
            # WITHOUT the trailing slash `tar -tzf` shows, so filtering on
            # endswith('/') keeps every directory and the assertions below then
            # test paths the real check never sees.
            return [m.name for m in tf.getmembers() if m.isfile()]

    def _matched(self, names):
        rx = re.compile(self.pattern)
        return {n for n in names if rx.search(n)}

    def test_every_internal_path_is_caught(self):
        names = self._archive_names(MUST_BE_CAUGHT)
        matched = self._matched(names)
        missed = sorted(n for n in names if n not in matched)
        self.assertEqual(missed, [], '\n'.join([
            'these would ship in the published release tarball and the '
            'leak-check does not see them:', *('  ' + m for m in missed),
            '',
            'Remember every member is prefixed with the dist directory name '
            f'({_DIST_NAME}/) by --transform, so a pattern anchored with a '
            'bare ^ can never match. Use (^|/).']))

    def test_no_shipping_file_is_caught(self):
        """The other direction. A check that fires on `docs/security.md` gets
        worked around within one release, and then guards nothing."""
        names = self._archive_names(MUST_NOT_BE_CAUGHT)
        wrong = sorted(self._matched(names))
        self.assertEqual(wrong, [], '\n'.join([
            'the leak-check fires on files that MUST ship:', *('  ' + w for w in wrong),
            '', 'An unsatisfiable gate is bypassed, not fixed.']))

    def test_the_transform_prefix_is_what_makes_this_subtle(self):
        """Pin the mechanism itself, so the next person to touch the pattern
        sees why bare ^ anchors are wrong rather than rediscovering it."""
        names = self._archive_names(('site/index.html',))
        self.assertTrue(all(n.startswith(_DIST_NAME + '/') for n in names), names)
        self.assertFalse(re.compile(r'^site/').search(names[0]),
                         'a bare ^site/ pattern must NOT match — this is the '
                         'exact bug the check shipped with')
        self.assertTrue(re.compile(r'(^|/)site/').search(names[0]))

    def test_the_makefile_exclude_list_covers_the_same_classes(self):
        """The Makefile is the primary defence and this grep is the net under
        it. They are maintained by hand in two files, so check they still name
        the same sensitive classes — not every exclusion (most are build noise
        excluded for SIZE: __pycache__, .venv, node_modules), just the ones
        that exist because the content must not be published."""
        makefile = _ROOT / 'Makefile'
        if not makefile.exists():
            self.skipTest('Makefile excluded from this tree')
        # re.sub, not lstrip('./') — lstrip strips CHARACTERS, so `./.claude`
        # comes back as `claude` and the assertion below looks for the wrong
        # string. (Cost one confusing failure to notice.)
        excluded = {re.sub(r'^\./', '', e).rstrip('/')
                    for e in re.findall(r"--exclude='([^']+)'",
                                        makefile.read_text())}
        for path in ('CLAUDE.md', 'opencode.md', '.claude', '.cursor',
                     'memory', 'MEMORY.md', 'site', 'deploy', 'design',
                     'docs/*-internal.md'):
            self.assertIn(path, excluded,
                          f'{path} is no longer excluded from the tarball — '
                          'the leak-check is a net, not the primary defence')


if __name__ == '__main__':
    unittest.main()

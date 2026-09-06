#!/usr/bin/env python3
"""Nothing that ships may point at a document that does not.

The `*-internal.md` set lives outside the repo — planning notes, scoping
documents, ops runbooks with hostnames and key paths in them. CLAUDE.md keeps
them out of every session's context and `make dist` strips them from the release
tarball.

Four comments in shipped JavaScript cited them by name: "see
docs/feature-buildout-scoping-internal.md #3 for why". A reader who follows that
finds nothing, and the filename itself tells them a document exists that they
cannot have. Each comment already made its point; only the citation went.

This is about what ships, so the scan is scoped to what ships: the served HTML
and JavaScript, the public docs, and the README. CLAUDE.md and the `docs/*-
internal.md` files themselves reference each other on purpose and are excluded
by construction — they are not in the tarball.
"""
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent

# What a user receives. Deliberately not the whole tree: the internal set is
# allowed to talk about itself.
_SHIPPED = (
    ('server/html', ('*.html',)),
    ('server/html/static/js', ('*.js',)),
    ('server/html/static/css', ('*.css',)),
    ('docs', ('*.md',)),
)

_INTERNAL = re.compile(r'[\w./-]*-internal\.md')

# Public docs that name the internal set as a thing that exists, without
# pointing a reader at one. Each needs its reason.
_ALLOWED = {
    # Names the pattern as part of the release-tarball exclude list. It is
    # describing what is kept OUT, not pointing a reader at one.
    'docs/threat-model.md',
}


def shipped_files():
    out = []
    for rel, patterns in _SHIPPED:
        base = _ROOT / rel
        if not base.exists():
            continue
        for pattern in patterns:
            for path in sorted(base.glob(pattern)):
                if path.name.endswith('-internal.md'):
                    continue
                out.append(path)
    return out


class TestNoShippedFileCitesAnInternalDoc(unittest.TestCase):

    def test_no_citations(self):
        offenders = []
        for path in shipped_files():
            rel = str(path.relative_to(_ROOT))
            if rel in _ALLOWED:
                continue
            for i, line in enumerate(path.read_text(encoding='utf-8',
                                                    errors='replace').splitlines(), 1):
                for m in _INTERNAL.finditer(line):
                    offenders.append(f'{rel}:{i} -> {m.group(0)}')
        self.assertEqual(
            offenders, [],
            'shipped files pointing at a document that is not shipped — the '
            'reader cannot follow it, and the filename tells them something '
            f'exists that they cannot have: {offenders}')

    def test_the_scan_reads_a_useful_number_of_files(self):
        """The control. An empty file list passes the check above."""
        files = shipped_files()
        self.assertGreater(len(files), 150, len(files))
        names = {f.name for f in files}
        for known in ('index.html', 'app.js', 'features.md'):
            self.assertIn(known, names)

    def test_the_pattern_recognises_the_shape_it_looks_for(self):
        sample = '// See docs/feature-buildout-scoping-internal.md #3 for why.'
        m = _INTERNAL.search(sample)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(0), 'docs/feature-buildout-scoping-internal.md')
        self.assertIsNone(_INTERNAL.search('// see docs/cmdb.md for the vault'))


if __name__ == '__main__':
    unittest.main()

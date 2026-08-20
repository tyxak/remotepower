#!/usr/bin/env python3
"""docs/cookbook.md was the one doc surface with no guard.

Every other one has something watching it: version docs are held at three, the
What's-new cards at three, features.md has a hygiene grep, the MCP inventory got
a gate this release because it had drifted on every surface that carried a
count. Nothing referenced the cookbook, and it showed — it claimed tags and
sites scope maintenance windows when only groups did, and it had no recipe for
the feature this release is named after.

The claim came true by accident (v7.0.2 added site/tag/smart-group targeting),
which is the worst way for documentation to become correct.

This checks the properties that actually rot: an index that has drifted from the
headings, a recipe pointing at a reference guide that no longer exists, and a
targeting vocabulary the server does not accept.
"""
import importlib.util
import os
import pathlib
import re
import sys
import tempfile
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_DOCS = _ROOT / 'docs'
_CB = _DOCS / 'cookbook.md'
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-cb-'))
_spec = importlib.util.spec_from_file_location('api_cookbook', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _slug(heading):
    return re.sub(r'[^a-z0-9 -]', '', heading.lower()).replace(' ', '-')


class TestItIsStillThere(unittest.TestCase):
    def setUp(self):
        if not _CB.exists():
            self.skipTest('excluded from dist tree')
        self.text = _CB.read_text()

    def test_it_has_recipes(self):
        """Positive control: an empty or renamed file would make every
        assertion below vacuous."""
        self.assertGreaterEqual(len(re.findall(r'^## ', self.text, re.M)), 8)

    def test_readme_and_docs_index_still_point_at_it(self):
        for rel in ('README.md', 'docs/README.md'):
            p = _ROOT / rel
            if p.exists():
                self.assertIn('cookbook.md', p.read_text(), rel)


class TestTheIndexMatchesTheRecipes(unittest.TestCase):
    """The list at the top is hand-maintained. An entry whose anchor does not
    resolve is a dead link in the first thing a reader sees."""

    def setUp(self):
        if not _CB.exists():
            self.skipTest('excluded from dist tree')
        self.text = _CB.read_text()
        self.headings = [h.strip() for h in
                         re.findall(r'^## (.+)$', self.text, re.M)]

    def test_every_index_anchor_resolves(self):
        anchors = re.findall(r'\]\(#([a-z0-9-]+)\)', self.text)
        self.assertTrue(anchors, 'the index is gone')
        slugs = {_slug(h) for h in self.headings}
        dead = [a for a in anchors if a not in slugs]
        self.assertEqual([], dead, f'index entries with no heading: {dead}')

    def test_every_recipe_is_in_the_index(self):
        anchors = set(re.findall(r'\]\(#([a-z0-9-]+)\)', self.text))
        missing = [h for h in self.headings if _slug(h) not in anchors]
        self.assertEqual([], missing,
                         f'recipes absent from the index: {missing}')


class TestEveryReferenceLinkResolves(unittest.TestCase):
    """Each recipe ends with links to its reference guides. A deleted or renamed
    doc turns those into 404s, and the keep-3 retention policy deletes docs
    every release."""

    def setUp(self):
        if not _CB.exists():
            self.skipTest('excluded from dist tree')
        self.text = _CB.read_text()

    def test_the_scan_finds_reference_links(self):
        self.assertGreater(len(re.findall(r'\]\(([a-z0-9-]+\.md)\)', self.text)),
                           10)

    def test_they_all_exist(self):
        dead = sorted({t for t in re.findall(r'\]\(([a-z0-9-]+\.md)\)', self.text)
                       if not (_DOCS / t).exists()})
        self.assertEqual([], dead, f'cookbook links a doc that is gone: {dead}')


class TestItDescribesTheProductAsItIs(unittest.TestCase):

    def setUp(self):
        if not _CB.exists():
            self.skipTest('excluded from dist tree')
        self.text = _CB.read_text()

    def test_the_maintenance_targeting_it_promises_is_real(self):
        """It listed site and tag as things that scope a maintenance window
        while the server accepted device, group and global only. The claim came
        true by accident in v7.0.2; this makes it a checked one."""
        i = self.text.index('maintenance window')
        seg = self.text[i:self.text.index('\n\n', i)]
        for scope in ('site', 'tag'):
            if scope in seg:
                self.assertIn(scope, api._MAINTENANCE_SCOPES,
                              f'the cookbook offers a {scope}-scoped window and '
                              f'the server rejects it')

    def test_the_headline_feature_has_a_recipe(self):
        """Autonomy appeared in none of the ten recipes, for the feature this
        release is named after — and the cookbook is the "how do I do X"
        surface, so its adoption path had nowhere to live."""
        self.assertIn('autonomy.md', self.text)
        # re.M, and anchored on a HEADING: without the flag this matches against
        # the first line of the file, and the index entry at the top contains
        # the same words as the heading 160 lines below it.
        self.assertRegex(self.text,
                         re.compile(r'^## .*by itself', re.M | re.I))

    def test_the_autonomy_recipe_leads_with_shadow_mode(self):
        """docs/autonomy.md's recommended rollout is shadow first, read the
        receipts, then grant. A recipe that opened with "enable it" would
        contradict the reference guide it links to."""
        # From the HEADING, not the index entry that shares its wording — the
        # first hit is the link at the top of the file and slicing from there
        # takes in every other recipe.
        m = re.search(r'^## .*by itself.*$', self.text, re.M | re.I)
        self.assertTrue(m, 'the recipe heading is gone')
        recipe = self.text[m.end():]
        recipe = recipe[:recipe.index('\nReference:')]
        self.assertIn('shadow', recipe.lower())
        self.assertLess(recipe.lower().index('shadow'),
                        recipe.lower().index('enabled'),
                        'the recipe reaches "enabled" before "shadow"')


class TestHouseStyle(unittest.TestCase):
    def setUp(self):
        if not _CB.exists():
            self.skipTest('excluded from dist tree')
        self.text = _CB.read_text()

    def test_no_banned_words(self):
        hits = re.findall(r'\b(deliberately|deliberate|genuinely|genuine|verbatim)\b',
                          self.text, re.I)
        self.assertEqual([], hits)

    def test_no_infra_detail_leaks_into_a_public_doc(self):
        for bad in ('tvipper.com', '/home/jaove', 'X-Token: '):
            self.assertNotIn(bad, self.text)


if __name__ == '__main__':
    unittest.main()

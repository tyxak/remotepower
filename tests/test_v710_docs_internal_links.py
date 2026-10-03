#!/usr/bin/env python3
"""Links between the docs resolve: the file exists and so does the #anchor.

`test_v642_doc_links` and `test_v702_doc_pointers` check the "Documentation"
pointers in index.html. Nothing looked at the links the docs make to each other,
and two of them were dead on arrival:

  integrity-guard.md   `(#why-is-everything-unknown)` — the heading is
                       `Why is everything "unknown / not yet reported by agent"?`,
                       whose anchor is `why-is-everything-unknown--not-yet-reported-by-agent`
  windows-client.md    `(#services-msc-cant-start-...)` — a heading with
                       `services.msc` has no hyphen where the dot was, so the
                       anchor is `servicesmsc-cant-start-...`

Both read as correct in the source. A link to a heading that is not there does
nothing, silently, which is why this is checked from the headings rather than
from the link text.

The anchor rule is GitHub's, because that is where the docs are read as well as
in the wiki: lower-case, markup and punctuation dropped (not replaced), each
space a hyphen, and a repeated heading numbered `-1`, `-2`.
"""

import re
import unittest
from pathlib import Path

_DOCS = Path(__file__).resolve().parent.parent / "docs"

# A link in running text. A target with a space or a ")" never occurs in these
# docs, so the non-greedy form is enough and keeps the scan simple.
_LINK = re.compile(r"\]\(([^)\s]+)\)")
_EXTERNAL = re.compile(r"^(?:[a-z][a-z0-9+.-]*:|//)", re.I)


def _slug(heading):
    """GitHub's anchor for one heading line (text only, no leading #'s)."""
    h = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading)   # [text](url) -> text
    h = re.sub(r"<[^>]+>", "", h).replace("`", "").strip().lower()
    h = re.sub(r"[^\w\- ]", "", h, flags=re.U)
    return h.replace(" ", "-")


def anchors(text):
    """Every anchor a document defines, with GitHub's -1/-2 for repeats."""
    seen, out, fence = {}, set(), False
    for ln in text.splitlines():
        if ln.lstrip().startswith("```"):
            fence = not fence
            continue
        if fence:
            continue
        m = re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", ln)
        if not m:
            continue
        s = _slug(m.group(1))
        n = seen.get(s, 0)
        seen[s] = n + 1
        out.add(s if n == 0 else "%s-%d" % (s, n))
    return out


def links(text):
    """(line number, target) for every link outside fenced code and code spans."""
    out, fence = [], False
    for i, ln in enumerate(text.splitlines(), 1):
        if ln.lstrip().startswith("```"):
            fence = not fence
            continue
        if fence:
            continue
        plain = re.sub(r"`[^`]*`", "", ln)
        out.extend((i, m.group(1)) for m in _LINK.finditer(plain))
    return out


def broken(path, text, all_anchors):
    """Why each internal link in `text` does not resolve, as 'file:line target'."""
    bad = []
    for line, target in links(text):
        if _EXTERNAL.match(target):
            continue
        name, _, frag = target.partition("#")
        if name:
            dest = (path.parent / name).resolve()
            # A link out of docs/ (../contrib/..., ../README.md) names part of
            # the repo that the release tarball may not carry, so only links
            # that stay inside docs/ are decidable here.
            if _DOCS not in dest.parents and dest != _DOCS:
                continue
            if not dest.exists():
                bad.append("%s:%d %s (no such file)" % (path.name, line, target))
                continue
            have = all_anchors(dest)
        else:
            have = all_anchors(path)
        if frag and frag not in have:
            bad.append("%s:%d %s (no such heading)" % (path.name, line, target))
    return bad


class TestDocsLinkToRealHeadings(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _DOCS.is_dir():
            raise unittest.SkipTest("docs/ is excluded from this tree")
        cls.files = sorted(_DOCS.glob("*.md"))
        cls._cache = {}

    def _anchors(self, path):
        if path not in self._cache:
            self._cache[path] = anchors(path.read_text(encoding="utf-8"))
        return self._cache[path]

    def test_the_population_is_not_empty(self):
        """Without this a broken glob or regex passes every assertion below."""
        total = sum(len(links(p.read_text(encoding="utf-8"))) for p in self.files)
        self.assertGreater(len(self.files), 100, "docs/*.md glob lost most of the docs")
        self.assertGreater(total, 300, "the link scan found almost nothing")

    def test_every_doc_link_resolves(self):
        bad = []
        for p in self.files:
            bad.extend(broken(p, p.read_text(encoding="utf-8"), self._anchors))
        self.assertEqual(bad, [], "\n".join(
            ["these doc links point at a file or heading that is not there:", *bad]))

    # ---- controls: the instrument must be able to fail -------------------

    def test_a_missing_heading_is_reported(self):
        p = self.files[0]
        text = "# Title\n\nSee [x](#not-a-heading) and [y](README.md#nope).\n"
        found = broken(p, text, self._anchors)
        self.assertEqual(len(found), 2, found)

    def test_a_missing_file_is_reported(self):
        p = self.files[0]
        found = broken(p, "[x](no-such-doc.md)\n", self._anchors)
        self.assertEqual(len(found), 1, found)

    def test_the_slug_rule_matches_the_two_cases_that_broke(self):
        self.assertEqual(
            _slug('Why is everything "unknown / not yet reported by agent"?'),
            "why-is-everything-unknown--not-yet-reported-by-agent")
        self.assertEqual(
            _slug("`services.msc` can't Start, Stop, or Restart the service"),
            "servicesmsc-cant-start-stop-or-restart-the-service")

    def test_a_repeated_heading_is_numbered(self):
        a = anchors("# A\n\n## Setup\n\n## Setup\n")
        self.assertTrue({"setup", "setup-1"} <= a, a)

    def test_links_in_code_are_not_followed(self):
        text = "```\n[x](#nope)\n```\n\nand `[y](#nope)` inline\n"
        self.assertEqual(links(text), [])


if __name__ == "__main__":
    unittest.main()

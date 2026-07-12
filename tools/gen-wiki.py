#!/usr/bin/env python3
"""Regenerate the GitHub wiki pages from docs/*.md (the 7th doc surface).

The wiki at https://github.com/tyxak/remotepower/wiki is GENERATED from docs/ —
not hand-edited (except the curated Home.md / _Sidebar.md / _Footer.md nav, which
this script version-bumps in place). Run it on every release, then commit+push
the wiki checkout.

Usage:
    git clone https://github.com/tyxak/remotepower.wiki.git /tmp/rp-wiki
    python3 tools/gen-wiki.py /tmp/rp-wiki <version>     # e.g. 4.8.0
    cd /tmp/rp-wiki && git add -A && git commit -m "docs: sync wiki to v<version>" && git push

What it does:
  * Copies every docs/*.md into the wiki, EXCLUDING the internal/non-public set
    (*-internal.md, security-review-*.md, maintaining-docs.md, README.md).
  * Rewrites intra-doc links for the wiki's flat namespace: `foo.md` -> `foo`,
    `foo.md#a` -> `foo#a`; `../README.md` / `../CHANGELOG.md` -> GitHub blob URLs;
    `README.md` (docs index) -> `Home`; links to the excluded set are de-linked;
    trailing `.md` is stripped from link TEXT.
  * Version-bumps the curated Home.md / _Sidebar.md (current-release line + the
    last-5 release-notes list) to <version>. _Footer.md is left untouched.
"""
import re
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DOCS = REPO / "docs"
BLOB = "https://github.com/tyxak/remotepower/blob/main"

# Pages that must never reach the public wiki, plus the docs index (-> Home).
EXCLUDE = {"README.md", "maintaining-docs.md"}
EXCLUDE_RE = (re.compile(r".*-internal\.md$"), re.compile(r"security-review-.*\.md$"))

LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")


def _excluded(name: str) -> bool:
    return name in EXCLUDE or any(rx.match(name) for rx in EXCLUDE_RE)


def _rewrite_target(target: str):
    """Return the rewritten link target, or None to de-link (excluded page)."""
    if target.startswith(("http://", "https://", "#", "mailto:")):
        return target
    base, _, anchor = target.partition("#")
    anchor = ("#" + anchor) if anchor else ""
    if base in ("../README.md", "../CHANGELOG.md"):
        return f"{BLOB}/{base[3:]}{anchor}"
    if base in ("README.md", "./README.md"):
        return f"Home{anchor}"
    if base.endswith(".md"):
        name = base.split("/")[-1]
        if _excluded(name):
            return None  # de-link
        return name[:-3] + anchor
    return target  # non-md relative (e.g. an image) — leave as-is


def _rewrite_links(text: str) -> str:
    def repl(m):
        label, target = m.group(1), m.group(2).strip()
        # strip a trailing .md from the visible label (e.g. "features.md")
        label = re.sub(r"\.md\b", "", label)
        new = _rewrite_target(target)
        if new is None:
            return label  # de-linked
        return f"[{label}]({new})"
    return LINK.sub(repl, text)


def _last5_versions():
    vers = sorted(
        (p.stem for p in DOCS.glob("v*.md")
         if re.fullmatch(r"v\d+\.\d+\.\d+", p.stem)),
        key=lambda s: [int(x) for x in s[1:].split(".")],
        reverse=True,
    )
    return vers[:5]


def _bump_nav(wiki: Path, version: str):
    last5 = _last5_versions()
    newest = f"v{version}" if not version.startswith("v") else version
    # _Sidebar.md: rebuild the "- [vX](vX)" release list to the last 5.
    sb = wiki / "_Sidebar.md"
    if sb.exists():
        lines = sb.read_text().splitlines()
        out, in_rel, done = [], False, False
        for ln in lines:
            if re.match(r"\s*-\s*\[v\d+\.\d+\.\d+\]", ln):
                if not done:
                    out += [f"- [{v}]({v})" for v in last5]
                    done = True
                in_rel = True
                continue
            out.append(ln)
        sb.write_text("\n".join(out) + "\n")
    # Home.md: current-release line + inline last-5 list.
    hm = wiki / "Home.md"
    if hm.exists():
        t = hm.read_text()
        t = re.sub(r"Current release: \*\*v\d+\.\d+\.\d+[^\n]*",
                   f"Current release: **{newest} \"HardenMatters\"** — see the",
                   t, count=1)
        t = re.sub(r"\[v\d+\.\d+\.\d+ release notes\]\(v\d+\.\d+\.\d+\)",
                   f"[{newest} release notes]({newest})", t, count=1)
        # the inline "**[vX](vX)** · ..." history line
        t = re.sub(r"(\*\*\[v\d+\.\d+\.\d+\][^\n]*?)(\n)",
                   " · ".join(f"**[{v}]({v})**" for v in last5) + r"\2",
                   t, count=1)
        hm.write_text(t)


def main():
    if len(sys.argv) < 3:
        sys.exit("usage: gen-wiki.py <wiki-checkout-dir> <version>")
    wiki = Path(sys.argv[1])
    version = sys.argv[2].lstrip("v")
    if not (wiki / ".git").exists():
        sys.exit(f"{wiki} is not a git checkout — clone the .wiki.git repo first")

    # Wipe generated pages (keep curated nav + .git), then regenerate.
    keep = {"Home.md", "_Sidebar.md", "_Footer.md"}
    for p in wiki.glob("*.md"):
        if p.name not in keep:
            p.unlink()

    n = 0
    pages = []
    for src in sorted(DOCS.glob("*.md")):
        if _excluded(src.name):
            continue
        dst = wiki / src.name
        dst.write_text(_rewrite_links(src.read_text()))
        pages.append(src.stem)
        n += 1

    _bump_nav(wiki, version)
    print(f"wiki: wrote {n} doc pages + bumped nav to v{version} in {wiki}")

    # _Sidebar.md is CURATED — this script only version-bumps its release list, it
    # does NOT auto-add new feature pages to the topical nav. So every NEW doc gets a
    # wiki page but is invisible in the sidebar until someone hand-links it. Warn
    # loudly here so a new feature page (wg-access, ticket-system, …) is never left
    # orphaned in the nav again. Version notes (vX.Y.Z) live in the release list, skip.
    sidebar = (wiki / "_Sidebar.md").read_text() if (wiki / "_Sidebar.md").exists() else ""
    missing = [p for p in pages
               if not re.fullmatch(r"v\d+\.\d+\.\d+", p)
               and f"]({p})" not in sidebar]
    if missing:
        print("\n  ⚠ WARNING: these wiki pages are NOT linked in the curated _Sidebar.md")
        print("    (hand-add them to a section in _Sidebar.md, then re-push the wiki):")
        for p in sorted(missing):
            print(f"      - {p}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""release-prep.py — automate the mechanical release chores (CLAUDE.md).

Subcommands (all DRY-RUN by default; pass --apply AFTER the subcommand to
actually edit files; --root points at an alternate repo tree, used by tests):

  bump vX.Y.Z ["Codename"]   version-bump checklist mechanical items
  prune                      version-docs keep-3 / security-review keep-3 + link scan
  counts                     refresh drifting counts (lines / connectors / events)
  verify                     run the checklist greps, print PASS/FAIL

Never touches git. stdlib-only, Python 3.9+.

Exit status: 0 = clean / applied cleanly; 1 = verify failed, pending changes
in dry-run, or inconsistencies that need a human (printed as WARN lines).
"""
import argparse
import os
import re
import sys
import tempfile
from pathlib import Path

VER_RE = r'\d+\.\d+\.\d+'
EMDASH = '—'
KEEP_VERSION_DOCS = 3       # docs/vX.Y.Z.md — keep 3 (was 5; policy changed 2026-07-13)
KEEP_REVIEW_DOCS = 3
KEEP_RECENT_RELEASES = 5    # README "Recent releases" + docs/README index stay keep-5

# Files scanned for links to pruned docs (CLAUDE.md docs-housekeeping rule).
LINK_SCAN_FILES = ('README.md', 'docs/README.md', 'docs/features.md',
                   'server/html/index.html')


def parse_ver(s):
    return tuple(int(x) for x in s.split('.'))


class Concern:
    """Base: dry-run-aware file editing with `file: old → new` reporting."""

    def __init__(self, root, apply=False):
        self.root = Path(root)
        self.apply = apply
        self.n_changes = 0       # files that would change / changed
        self.warnings = []       # human-attention items → exit 1

    def rel(self, path):
        try:
            return str(Path(path).relative_to(self.root))
        except ValueError:
            return str(path)

    def warn(self, msg):
        self.warnings.append(msg)
        print(f'WARN: {msg}')

    def note(self, msg):
        print(f'      {msg}')

    def edit(self, path, pattern, repl, min_hits=1, flags=re.M):
        """Regex-replace in one file; print every unique old → new pair."""
        if not path.exists():
            self.warn(f'{self.rel(path)}: file missing')
            return 0
        text = path.read_text()
        pairs = {}

        def _sub(m):
            new = m.expand(repl) if isinstance(repl, str) else repl(m)
            key = (m.group(0), new)
            pairs[key] = pairs.get(key, 0) + 1
            return new

        new_text, n = re.subn(pattern, _sub, text, flags=flags)
        if n < min_hits:
            self.warn(f'{self.rel(path)}: expected >= {min_hits} match(es) '
                      f'for {pattern!r}, found {n}')
            return 0
        changed = False
        for (old, new), count in pairs.items():
            if old != new:
                changed = True
                sfx = f'  (x{count})' if count > 1 else ''
                print(f'{self.rel(path)}: {old} → {new}{sfx}')
        if changed:
            self.n_changes += 1
            if self.apply:
                path.write_text(new_text)
        else:
            print(f'{self.rel(path)}: already up to date')
        return n

    def write_text(self, path, new_text, what):
        print(f'{self.rel(path)}: {what}')
        self.n_changes += 1
        if self.apply:
            path.write_text(new_text)

    def mode_line(self):
        print('MODE: apply' if self.apply else
              'MODE: dry-run (no files written; pass --apply to edit)')


# --------------------------------------------------------------------------
# bump
# --------------------------------------------------------------------------

class Bumper(Concern):
    """Version-bump checklist, mechanical items only (CLAUDE.md)."""

    def run(self, version, codename=None):
        version = version.lstrip('v')
        if not re.fullmatch(VER_RE, version):
            self.warn(f'bad version {version!r} (want X.Y.Z)')
            return 1
        self.mode_line()
        print(f'== bump → v{version}'
              + (f' "{codename}"' if codename else ''))

        # 1. SERVER_VERSION in api.py
        self.edit(self.root / 'server/cgi-bin/api.py',
                  rf"^(SERVER_VERSION = ')({VER_RE})(')",
                  rf'\g<1>{version}\g<3>')

        # 2. agent VERSIONs (linux keeps its aligned spacing)
        for agent in ('client/remotepower-agent.py',
                      'client/remotepower-agent-win.py',
                      'client/remotepower-agent-mac.py'):
            self.edit(self.root / agent,
                      rf"^(VERSION\s*=\s*')({VER_RE})(')",
                      rf'\g<1>{version}\g<3>')

        # 2b. sync the byte-identical extensionless copy
        self._sync_extensionless()

        # 3. sw.js CACHE_NAME — reset trailing counter to -1
        self.edit(self.root / 'server/html/sw.js',
                  rf"(CACHE_NAME = 'remotepower-shell-v){VER_RE}(?:-\d+)?(')",
                  rf'\g<1>{version}-1\g<2>')

        # 4. every ?v= cache-bust in index.html (drop -N suffixes)
        self.edit(self.root / 'server/html/index.html',
                  rf'\?v={VER_RE}(?:-\d+)?',
                  f'?v={version}')

        # 5. README version badge
        self.edit(self.root / 'README.md',
                  rf'(badge/version-){VER_RE}(-)',
                  rf'\g<1>{version}\g<2>')

        # -- verify-only warnings (judgment items stay manual) --
        self._warn_checks(version, codename)

        print(f'== bump done: {self.n_changes} file(s) '
              + ('changed' if self.apply else 'would change')
              + f', {len(self.warnings)} warning(s)')
        return 1 if self.warnings else 0

    def _sync_extensionless(self):
        py = self.root / 'client/remotepower-agent.py'
        ext = self.root / 'client/remotepower-agent'
        if not py.exists() or not ext.exists():
            self.warn('agent .py/extensionless pair incomplete')
            return
        if self.apply:
            if py.read_bytes() != ext.read_bytes():
                ext.write_bytes(py.read_bytes())
                print('client/remotepower-agent: synced byte-identical '
                      'from remotepower-agent.py')
                self.n_changes += 1
            else:
                print('client/remotepower-agent: already byte-identical')
        else:
            print('client/remotepower-agent: would sync byte-identical '
                  'from remotepower-agent.py after edit')

    def _warn_checks(self, version, codename):
        # tests/test_vXYZ.py existence
        test_name = 'test_v' + version.replace('.', '') + '.py'
        if not (self.root / 'tests' / test_name).exists():
            self.warn(f'tests/{test_name} does not exist yet '
                      '(create it with strict pins; loosen the previous one)')

        # CHANGELOG top entry
        chlog = self.root / 'CHANGELOG.md'
        want = f'## v{version} {EMDASH} '
        text = chlog.read_text() if chlog.exists() else ''
        line = next((ln for ln in text.splitlines()
                     if ln.startswith(want)), None)
        if line is None:
            self.warn(f'CHANGELOG.md: no `## v{version} {EMDASH} "Codename" '
                      f'{EMDASH} unreleased (test)` entry yet')
        elif codename and f'"{codename}"' not in line:
            self.warn(f'CHANGELOG.md: v{version} entry does not carry '
                      f'codename "{codename}": {line}')

        # in-app "What's new" card
        idx = self.root / 'server/html/index.html'
        if idx.exists() and \
                f"What's new {EMDASH} v{version}" not in idx.read_text():
            self.warn(f"index.html: no \"What's new {EMDASH} v{version}\" "
                      'card yet (in-app Documentation page)')

        # gen-wiki.py hardcoded codename
        genwiki = self.root / 'tools/gen-wiki.py'
        if genwiki.exists():
            m = re.search(r'Current release:.*?\\"([^"\\]+)\\"',
                          genwiki.read_text())
            if not m:
                self.warn('tools/gen-wiki.py: could not locate the hardcoded '
                          '"Current release" codename literal')
            elif codename and m.group(1) != codename:
                self.warn(f'tools/gen-wiki.py: hardcoded codename is '
                          f'"{m.group(1)}", expected "{codename}" '
                          '(bump the string literal)')
            elif not codename:
                self.note(f'tools/gen-wiki.py hardcoded codename: '
                          f'"{m.group(1)}" (no codename given; verify by hand)')


# --------------------------------------------------------------------------
# prune
# --------------------------------------------------------------------------

class Pruner(Concern):
    """Docs keep-N enforcement + dangling-link scan (CLAUDE.md housekeeping)."""

    def run(self):
        self.mode_line()
        print('== prune (version docs keep-3 / reviews keep-3; '
              'README + docs/README index keep-5)')
        deleted_versions = self._prune_set(
            r'v(\d+\.\d+\.\d+)\.md$', KEEP_VERSION_DOCS, 'version docs')
        deleted_reviews = self._prune_set(
            r'security-review-(\d+\.\d+\.\d+)\.md$', KEEP_REVIEW_DOCS,
            'public security reviews')
        self._link_scan(deleted_versions, deleted_reviews)
        self._trim_readme_recent()
        self._trim_docs_readme_index()
        pending = self.n_changes and not self.apply
        print(f'== prune done: {self.n_changes} change(s) '
              + ('applied' if self.apply else 'pending')
              + f', {len(self.warnings)} warning(s)')
        return 1 if (self.warnings or pending) else 0

    def _prune_set(self, name_re, keep, label):
        docs = self.root / 'docs'
        found = []
        for p in sorted(docs.glob('*.md')):
            if '-internal' in p.name:           # never touch internal docs
                continue
            m = re.fullmatch(name_re, p.name)
            if m:
                found.append((parse_ver(m.group(1)), p))
        found.sort(reverse=True)
        doomed = [p for _, p in found[keep:]]
        print(f'{label}: {len(found)} found, keep {keep}, '
              f'delete {len(doomed)}')
        for p in doomed:
            print(f'{self.rel(p)}: DELETE')
            self.n_changes += 1
            if self.apply:
                p.unlink()
        return doomed

    def _link_scan(self, deleted_versions, deleted_reviews):
        """Report links to pruned files; auto-repoint review links (--apply)."""
        for relf in LINK_SCAN_FILES:
            path = self.root / relf
            if not path.exists():
                continue
            text = path.read_text()
            # Review links → docs/security.md (the durable target, house rule).
            for doomed in deleted_reviews:
                name = doomed.name
                if name not in text:
                    continue
                new_text = text.replace(f'docs/{name}', 'docs/security.md')
                new_text = new_text.replace(name, 'security.md')
                print(f'{relf}: link to deleted docs/{name} '
                      f'→ repoint to docs/security.md')
                self.n_changes += 1
                text = new_text
                if self.apply:
                    path.write_text(text)
            # Version-doc links: report only (no single durable target —
            # usually CHANGELOG.md; needs a human).
            for doomed in deleted_versions:
                if doomed.name in text:
                    self.warn(f'{relf}: live link to deleted '
                              f'docs/{doomed.name} — repoint by hand '
                              '(CHANGELOG.md is the usual target)')

    def _trim_readme_recent(self):
        """README "Recent releases" caps at 5 bullets."""
        path = self.root / 'README.md'
        if not path.exists():
            return
        lines = path.read_text().splitlines(keepends=True)
        try:
            start = next(i for i, ln in enumerate(lines)
                         if re.match(r'#{2,4} Recent releases\s*$', ln))
        except StopIteration:
            self.warn('README.md: no "Recent releases" heading found')
            return
        bullets = []           # (line_idx, version)
        for i in range(start + 1, len(lines)):
            m = re.match(rf'- \*\*v({VER_RE})', lines[i])
            if m:
                bullets.append((i, parse_ver(m.group(1))))
            elif bullets and lines[i].strip() and not lines[i].startswith(' '):
                break          # section over
        if len(bullets) <= KEEP_RECENT_RELEASES:
            print(f'README.md: Recent releases has {len(bullets)} bullet(s) '
                  f'(<= {KEEP_RECENT_RELEASES}), nothing to trim')
            return
        keep = set(i for i, _ in
                   sorted(bullets, key=lambda t: t[1],
                          reverse=True)[:KEEP_RECENT_RELEASES])
        drop = [i for i, _ in bullets if i not in keep]
        for i in drop:
            print(f'README.md: drop Recent-releases bullet '
                  f'{lines[i].strip()[:72]}...')
        new = [ln for i, ln in enumerate(lines) if i not in set(drop)]
        self.write_text(path, ''.join(new),
                        f'trim Recent releases {len(bullets)} '
                        f'→ {KEEP_RECENT_RELEASES} bullets')

    def _trim_docs_readme_index(self):
        """docs/README.md per-release-notes index caps at 5 (multi-line bullets)."""
        path = self.root / 'docs' / 'README.md'
        if not path.exists():
            return
        lines = path.read_text().splitlines(keepends=True)
        blocks = []            # (start, end, version)
        i = 0
        while i < len(lines):
            m = re.match(rf'- \*\*\[v({VER_RE})\.md\]', lines[i])
            if m:
                j = i + 1
                while j < len(lines) and lines[j].strip() \
                        and lines[j][0] in ' \t':
                    j += 1     # wrapped continuation lines
                blocks.append((i, j, parse_ver(m.group(1))))
                i = j
            else:
                i += 1
        if len(blocks) <= KEEP_RECENT_RELEASES:
            print(f'docs/README.md: release index has {len(blocks)} '
                  f'entr(ies) (<= {KEEP_RECENT_RELEASES}), nothing to trim')
            return
        keep = set(id(b) for b in
                   sorted(blocks, key=lambda b: b[2],
                          reverse=True)[:KEEP_RECENT_RELEASES])
        dead_ranges = [(s, e) for b in blocks if id(b) not in keep
                       for s, e in (b[:2],)]
        for s, e in dead_ranges:
            print(f'docs/README.md: drop index entry {lines[s].strip()[:60]}...')
        dead_lines = set()
        for s, e in dead_ranges:
            dead_lines.update(range(s, e))
        new = [ln for i, ln in enumerate(lines) if i not in dead_lines]
        self.write_text(path, ''.join(new),
                        f'trim release index {len(blocks)} '
                        f'→ {KEEP_RECENT_RELEASES} entries')


# --------------------------------------------------------------------------
# counts
# --------------------------------------------------------------------------

class Counter(Concern):
    """Refresh drifting counts: README server-Python lines + connector count,
    docs/features.md connector + webhook-event counts."""

    def run(self):
        self.mode_line()
        print('== counts')
        self._line_count()
        self._connector_count()
        self._event_count()
        pending = self.n_changes and not self.apply
        print(f'== counts done: {self.n_changes} change(s) '
              + ('applied' if self.apply else 'pending')
              + f', {len(self.warnings)} warning(s)')
        return 1 if (self.warnings or pending) else 0

    def _line_count(self):
        cgi = self.root / 'server' / 'cgi-bin'
        total = sum(len(p.read_text(errors='replace').splitlines())
                    for p in sorted(cgi.rglob('*.py')))
        rounded = int(round(total / 1000.0)) * 1000
        print(f'server Python line count: {total} → ~{rounded:,}')
        # exactly ONE spot in README ("What is it?" para) per the checklist
        self.edit(self.root / 'README.md',
                  r'(\*\*~)[\d,]+( lines\*\*)',
                  rf'\g<1>{rounded:,}\g<2>')

    def _connectors(self):
        """Count @_register(...) connectors, excluding the custom probe
        (the README/features counts list 'custom' separately: '(+ Custom HTTP)')."""
        src = (self.root / 'server/cgi-bin/integrations.py').read_text()
        ids = re.findall(r"^@_register\(\s*\n\s*[\"']([a-z0-9_]+)[\"']",
                         src, flags=re.M)
        return [i for i in ids if not i.startswith('custom')]

    def _connector_count(self):
        n = len(self._connectors())
        print(f'homelab connectors (excl. custom probe): {n}')
        self.edit(self.root / 'README.md',
                  r'\d+( \*\*homelab-app\*\* health connectors)',
                  rf'{n}\g<1>')
        self.edit(self.root / 'docs/features.md',
                  r'(\| )\d+( connectors \(\+ Custom HTTP\))',
                  rf'\g<1>{n}\g<2>')

    def _event_count(self):
        n = self._webhook_event_count()
        if n is None:
            return
        print(f'webhook event registry: {n} events')
        self.edit(self.root / 'docs/features.md',
                  r'\d+( event types)', rf'{n}\g<1>')

    def _webhook_event_count(self):
        """Import api.py the way the tests do (importlib + RP_DATA_DIR tmpdir)."""
        import importlib.util
        os.environ.setdefault('RP_DATA_DIR',
                              tempfile.mkdtemp(prefix='rp-relprep-'))
        cgi = self.root / 'server' / 'cgi-bin'
        api_py = cgi / 'api.py'
        sys.path.insert(0, str(cgi))
        try:
            spec = importlib.util.spec_from_file_location(
                'rp_relprep_api', api_py)
            api = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(api)
            return len(api.WEBHOOK_EVENT_NAMES)
        except Exception as e:                          # pragma: no cover
            self.warn(f'could not import {self.rel(api_py)} for '
                      f'WEBHOOK_EVENT_NAMES: {e}')
            return None
        finally:
            sys.path.remove(str(cgi))


# --------------------------------------------------------------------------
# verify
# --------------------------------------------------------------------------

class Verifier(Concern):
    """All the checklist greps, as PASS/FAIL lines."""

    def __init__(self, root, apply=False):
        super().__init__(root, apply)
        self.failed = 0

    def check(self, ok, name, detail):
        print(f'{"PASS" if ok else "FAIL"}: {name} — {detail}')
        if not ok:
            self.failed += 1

    def run(self):
        print('== verify')
        self._features_purity()
        self._agent_sync()
        self._docs_keep_n()
        self._readme_recent()
        self._cache_bust()
        self._changelog_header()
        self._version_consistency()
        print(f'== verify done: {self.failed} failure(s)')
        return 1 if self.failed else 0

    def _server_version(self):
        src = (self.root / 'server/cgi-bin/api.py').read_text()
        m = re.search(rf"^SERVER_VERSION = '({VER_RE})'", src, flags=re.M)
        return m.group(1) if m else None

    def _features_purity(self):
        path = self.root / 'docs/features.md'
        if not path.exists():
            self.check(False, 'features-md-purity', 'docs/features.md missing')
            return
        bad = [ln for ln in path.read_text().splitlines()
               if re.match(r"^### |^## (v[0-9]|What.s new|Added in)", ln)
               or '```' in ln]
        self.check(not bad, 'features-md-purity',
                   'tables-only (no prose headers / changelog sections / '
                   'code fences)' if not bad else
                   f'{len(bad)} offending line(s), e.g. {bad[0][:60]!r}')

    def _agent_sync(self):
        py = self.root / 'client/remotepower-agent.py'
        ext = self.root / 'client/remotepower-agent'
        ok = py.exists() and ext.exists() and \
            py.read_bytes() == ext.read_bytes()
        self.check(ok, 'agent-extensionless-sync',
                   'client/remotepower-agent.py == client/remotepower-agent'
                   if ok else 'agent copies differ (cp .py over extensionless)')

    def _docs_keep_n(self):
        docs = self.root / 'docs'
        vdocs = [p for p in docs.glob('v*.md')
                 if re.fullmatch(rf'v{VER_RE}\.md', p.name)]
        self.check(len(vdocs) <= KEEP_VERSION_DOCS, 'docs-keep-3',
                   f'{len(vdocs)} docs/vX.Y.Z.md (cap {KEEP_VERSION_DOCS})')
        reviews = [p for p in docs.glob('security-review-*.md')
                   if '-internal' not in p.name]
        self.check(len(reviews) <= KEEP_REVIEW_DOCS, 'reviews-keep-3',
                   f'{len(reviews)} public docs/security-review-*.md '
                   f'(cap {KEEP_REVIEW_DOCS})')

    def _readme_recent(self):
        text = (self.root / 'README.md').read_text()
        lines = text.splitlines()
        n = 0
        in_sec = False
        for ln in lines:
            if re.match(r'#{2,4} Recent releases\s*$', ln):
                in_sec = True
                continue
            if in_sec:
                if re.match(rf'- \*\*v{VER_RE}', ln):
                    n += 1
                elif ln.startswith('#'):
                    break
        self.check(n <= KEEP_RECENT_RELEASES, 'readme-recent-releases',
                   f'{n} bullet(s) (cap {KEEP_RECENT_RELEASES})')

    def _cache_bust(self):
        cur = self._server_version()
        if cur is None:
            self.check(False, 'index-cache-bust', 'SERVER_VERSION not found')
            return
        text = (self.root / 'server/html/index.html').read_text()
        vers = set(re.findall(rf'\?v=({VER_RE})(?:-\d+)?', text))
        stale = sorted(vers - {cur})
        self.check(not stale, 'index-cache-bust',
                   f'all ?v= strings are v{cur}' if not stale else
                   f'stale ?v= versions: {", ".join(stale)} '
                   f'(SERVER_VERSION is {cur})')

    def _changelog_header(self):
        text = (self.root / 'CHANGELOG.md').read_text()
        top = next((ln for ln in text.splitlines()
                    if ln.startswith('## ')), '')
        shape = re.fullmatch(
            rf'## (Unreleased \(test\)|v{VER_RE} {EMDASH} "[^"]+" {EMDASH} '
            rf'(unreleased \(test\)|\d{{4}}-\d{{2}}-\d{{2}}.*))', top)
        self.check(bool(shape), 'changelog-top-header',
                   f'top entry: {top!r}')

    def _version_consistency(self):
        cur = self._server_version()
        bad = []
        readme = (self.root / 'README.md').read_text()
        m = re.search(rf'badge/version-({VER_RE})-', readme)
        if not m or m.group(1) != cur:
            bad.append(f'README badge={m.group(1) if m else "?"}')
        sw = (self.root / 'server/html/sw.js').read_text()
        m = re.search(rf"CACHE_NAME = 'remotepower-shell-v({VER_RE})", sw)
        if not m or m.group(1) != cur:
            bad.append(f'sw.js CACHE_NAME={m.group(1) if m else "?"}')
        for agent in ('client/remotepower-agent.py',
                      'client/remotepower-agent-win.py',
                      'client/remotepower-agent-mac.py'):
            m = re.search(rf"^VERSION\s*=\s*'({VER_RE})'",
                          (self.root / agent).read_text(), flags=re.M)
            if not m or m.group(1) != cur:
                bad.append(f'{agent}={m.group(1) if m else "?"}')
        self.check(not bad, 'version-consistency',
                   f'badge / sw.js / agents all v{cur}' if not bad else
                   f'out of step with SERVER_VERSION {cur}: {"; ".join(bad)}')


# --------------------------------------------------------------------------

def main(argv=None):
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--apply', action='store_true',
                        help='actually edit files (default: dry-run)')
    common.add_argument('--root', default=None,
                        help='repo root (default: parent of tools/)')

    ap = argparse.ArgumentParser(
        prog='release-prep.py',
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)

    b = sub.add_parser('bump', parents=[common],
                       help='apply the version-bump checklist mechanical items')
    b.add_argument('version', help='new version, e.g. v5.7.0')
    b.add_argument('codename', nargs='?', help='release codename')
    sub.add_parser('prune', parents=[common],
                   help='version-docs keep-3 / security-review keep-3 + link scan')
    sub.add_parser('counts', parents=[common],
                   help='refresh line / connector / webhook-event counts')
    sub.add_parser('verify', parents=[common],
                   help='run the checklist greps, PASS/FAIL')

    args = ap.parse_args(argv)
    root = Path(args.root) if args.root else \
        Path(__file__).resolve().parent.parent

    if args.cmd == 'bump':
        return Bumper(root, args.apply).run(args.version, args.codename)
    if args.cmd == 'prune':
        return Pruner(root, args.apply).run()
    if args.cmd == 'counts':
        return Counter(root, args.apply).run()
    if args.cmd == 'verify':
        return Verifier(root, args.apply).run()
    return 2                                            # pragma: no cover


if __name__ == '__main__':
    sys.exit(main())

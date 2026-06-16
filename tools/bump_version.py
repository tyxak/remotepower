#!/usr/bin/env python3
"""Automate the mechanical part of the version-bump checklist (CLAUDE.md).

Usage:
    python3 tools/bump_version.py 4.4.0 [--dry-run]
    make bump VERSION=4.4.0

Edits, in place (or just prints with --dry-run):
  1. SERVER_VERSION in server/cgi-bin/api.py
  2. VERSION in client/remotepower-agent.py (+ syncs the extensionless copy)
  3. VERSION in client/remotepower-agent-win.py / -mac.py
  4. CACHE_NAME in server/html/sw.js
  5. every ?v=<old> cache-bust in server/html/index.html
  6. the README version badge
  7. prepends a CHANGELOG.md section template
  8. creates docs/v<NEW>.md from a template

It does NOT do the judgment steps — it prints them as a checklist instead:
new tests/test_vXYZ.py strict pins, loosening the previous release's pins,
the in-app Docs page "What's new" cards, and the docs housekeeping rule
(keep the 5 most recent docs/vX.Y.Z.md).

The existing guardrail (test_vXYZ.TestVersionBumps) still verifies the
result — this script removes the typo-prone editing, not the review.
"""
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _current_version():
    src = (ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
    m = re.search(r"SERVER_VERSION = '(\d+\.\d+\.\d+)'", src)
    if not m:
        sys.exit('cannot find SERVER_VERSION in api.py')
    return m.group(1)


def _sub_file(path, pattern, repl, expect_min=1, dry=False):
    """Regex-replace in one file; returns the hit count (asserted >= expect_min)."""
    text = path.read_text()
    new, n = re.subn(pattern, repl, text, flags=re.M)
    if n < expect_min:
        sys.exit(f'{path}: expected >= {expect_min} match(es) for {pattern!r}, got {n}')
    print(f'  {path.relative_to(ROOT)}: {n} replacement(s)')
    if not dry:
        path.write_text(new)
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('version', help='new version, e.g. 4.4.0')
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args()
    new = args.version
    if not re.fullmatch(r'\d+\.\d+\.\d+', new):
        sys.exit(f'not a x.y.z version: {new}')
    old = _current_version()
    if new == old:
        sys.exit(f'already at {old}')
    dry = args.dry_run
    print(f'{"DRY RUN — " if dry else ""}bumping {old} -> {new}\n')

    _sub_file(ROOT / 'server' / 'cgi-bin' / 'api.py',
              rf"SERVER_VERSION = '{re.escape(old)}'",
              f"SERVER_VERSION = '{new}'", dry=dry)
    for agent in ('remotepower-agent.py', 'remotepower-agent-win.py',
                  'remotepower-agent-mac.py'):
        _sub_file(ROOT / 'client' / agent,
                  rf"^VERSION(\s*)= '{re.escape(old)}'",
                  rf"VERSION\g<1>= '{new}'", dry=dry)
    if not dry:
        # extensionless copy must stay byte-identical (release-gated test)
        src = (ROOT / 'client' / 'remotepower-agent.py').read_bytes()
        (ROOT / 'client' / 'remotepower-agent').write_bytes(src)
        print('  client/remotepower-agent: synced from .py')
    _sub_file(ROOT / 'server' / 'html' / 'sw.js',
              rf"remotepower-shell-v{re.escape(old)}",
              f"remotepower-shell-v{new}", dry=dry)
    _sub_file(ROOT / 'server' / 'html' / 'index.html',
              rf"\?v={re.escape(old)}", f"?v={new}", expect_min=5, dry=dry)
    _sub_file(ROOT / 'README.md',
              rf"badge/version-{re.escape(old)}-",
              f"badge/version-{new}-", dry=dry)

    changelog = ROOT / 'CHANGELOG.md'
    if f'## v{new}' not in changelog.read_text():
        print(f'  CHANGELOG.md: prepending v{new} template')
        if not dry:
            text = changelog.read_text()
            head, _, rest = text.partition('\n## ')
            template = (f'\n## v{new} — "CODENAME" — YYYY-MM-DD\n\n'
                        f'One-paragraph release summary.\n\n'
                        f'- **Headline change.** Description.\n')
            changelog.write_text(head + template + '\n## ' + rest)

    reldoc = ROOT / 'docs' / f'v{new}.md'
    if not reldoc.exists():
        print(f'  docs/v{new}.md: creating template')
        if not dry:
            reldoc.write_text(
                f'# RemotePower v{new} — "CODENAME"\n\n'
                f'One-paragraph release summary.\n\n'
                f'After upgrading, hard-reload the dashboard once so the new '
                f'front-end loads\n(service-worker cache '
                f'`remotepower-shell-v{new}`).\n\n## Section\n\n- **Change.**\n')

    print(f"""
Mechanical edits done. STILL MANUAL (judgment steps):
  [ ] tests/test_v{new.replace('.', '')}.py — strict pins for this release
  [ ] loosen the previous release's strict pins to regex
  [ ] fill in CHANGELOG.md + docs/v{new}.md templates (codename, content)
  [ ] in-app Docs page "What's new" card (server/html/index.html ~Documentation)
  [ ] docs housekeeping: keep only the 5 most recent docs/vX.Y.Z.md
  [ ] run: make check   (the TestVersionBumps guardrail verifies this script's work)
""")


if __name__ == '__main__':
    main()

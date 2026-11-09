#!/usr/bin/env python3
"""Move the client asset stamp (`X.Y.Z-N`) up by one: CACHE_NAME in sw.js and every ?v= in the pages of server/html, in lockstep.

The stamp is what a browser and a CDN key a script or style on. `deploy-server.sh` hashes only the stylesheet and the dictionary, so a deploy that changes a script under
the same stamp leaves the old file in every cache that holds it (the demo showed the new page with the first deploy's app.js for a day). Run this in any commit that changes a
file under server/html, or let `tools/git-hooks/pre-commit` tell you to. `--check` exits 1 when such a file is staged and the stamp is not.
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HTML = ROOT / 'server' / 'html'
STAMP = re.compile(r"(\d+\.\d+\.\d+)-(\d+)")


def _current():
    sw = (HTML / 'sw.js').read_text(encoding='utf-8')
    m = re.search(r"CACHE_NAME\s*=\s*'remotepower-shell-v(\d+\.\d+\.\d+)-(\d+)'", sw)
    if not m:
        sys.exit('bump-stamp: CACHE_NAME not found in sw.js')
    return m.group(1), int(m.group(2))


def bump():
    ver, n = _current()
    old, new = f'{ver}-{n}', f'{ver}-{n + 1}'
    changed = 0
    for path in sorted(HTML.glob('*.html')) + [HTML / 'sw.js']:
        text = path.read_text(encoding='utf-8')
        out = re.sub(r"(\?v=|remotepower-shell-v)" + re.escape(old) + r"(?![\w.\-])", lambda m: m.group(1) + new, text)
        if out != text:
            path.write_text(out, encoding='utf-8')
            changed += 1
    print(f'{old} -> {new} in {changed} files')


def _staged():
    out = subprocess.run(['git', '-C', str(ROOT), 'diff', '--cached', '--name-only'], capture_output=True, text=True).stdout.split('\n')
    return [p for p in out if p.startswith('server/html/') and not p.startswith('server/html/static/vendor/')]


def check():
    staged = _staged()
    assets = [p for p in staged if p != 'server/html/sw.js']
    if not assets:
        return 0
    diff = subprocess.run(['git', '-C', str(ROOT), 'diff', '--cached', '-U0', '--', 'server/html/sw.js'], capture_output=True, text=True).stdout
    if re.search(r"^\+.*CACHE_NAME", diff, re.M):
        return 0
    print('A file under server/html is staged and the asset stamp is not: run `python3 tools/bump-stamp.py` and stage its files.\n  ' + '\n  '.join(assets[:8]), file=sys.stderr)
    return 1


if __name__ == '__main__':
    if '--check' in sys.argv:
        sys.exit(check())
    bump()

"""Runs a honeypot Worker script under node the way the Workers runtime calls fetch().

Shared by the tests of docs/honeypot-worker.md and docs/honeypot-traps.md. It is a helper,
not a test module: both guides hand a stranger a script to paste, so the script is executed,
and what it prints is the input the tests give to RemotePower's own reader.

The request is a plain object with no body methods unless a case gives a `body`. A script
that reads a body it should not throws here, which is how "never reads a request body" is
pinned. `fetch` is a stub standing in for the visitor's site: the number of times one visit
calls it (`fetched`, counted again from zero for each visit) is what tells a decoy answer (0)
from a pass-through (1).
"""
import ipaddress
import json
import re
import shutil
import subprocess
import tempfile
import tomllib
from pathlib import Path

NODE = shutil.which('node')
ATK = '185.220.101.7'       # a routable address: RemotePower sets aside documentation ranges


def blocks(text, lang):
    """The fenced code blocks of one language, in order."""
    out, cur, name = [], None, ''
    for line in text.split('\n'):
        m = re.match(r'^```(\w*)\s*$', line)
        if m:
            if cur is None:
                cur, name = [], m.group(1)
            else:
                if name == lang:
                    out.append('\n'.join(cur) + '\n')
                cur = None
            continue
        if cur is not None:
            cur.append(line)
    return out


def script_of(text):
    """The one script a guide holds."""
    found = blocks(text, 'js')
    assert len(found) == 1, 'a guide holds exactly one script, found %d' % len(found)
    return found[0]


def config_text_of(text):
    """The one wrangler.toml a guide holds: the toml block that names the Worker."""
    found = [b for b in blocks(text, 'toml') if re.search(r'(?m)^name\s*=', b)]
    assert len(found) == 1, 'a guide holds exactly one wrangler.toml, found %d' % len(found)
    return found[0]


def config_of(text):
    return tomllib.loads(config_text_of(text))


def traps_of(script):
    """[(kind, lower-case path prefix)] read from the TRAPS array of a script."""
    m = re.search(r'const TRAPS = \[(.*?)^\];', script, re.S | re.M)
    assert m, 'no TRAPS array in the script'
    return re.findall(r'\["(\w+)",\s*"([^"]+)"\]', m.group(1))


def const_of(script, name):
    """The number in `const NAME = <number>;` in a script."""
    m = re.search(r'^const %s = (\d+);' % name, script, re.M)
    assert m, 'no const %s in the script' % name
    return int(m.group(1))


def section(text, title):
    """The body of the `## title` section of a page."""
    m = re.search(r'^## %s\n(.*?)(?=^## |\Z)' % re.escape(title), text, re.S | re.M)
    assert m, 'no section "%s"' % title
    return m.group(1)


def table(text):
    """The first pipe table in `text` as rows of cells, the header and the rule dropped."""
    rows = []
    for line in text.splitlines():
        if re.match(r'^\s*\|.*\|\s*$', line):
            cells = [c.strip() for c in line.strip().strip('|').split('|')]
            if all(re.fullmatch(r':?-{2,}:?', c) for c in cells):
                continue
            rows.append(cells)
        elif rows:
            break
    return rows[1:]


_DRIVER = r"""
import fs from 'node:fs';
import worker from './worker.mjs';
const cases = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const results = [];
let fetched = 0;
let current = {};
globalThis.fetch = async () => {
  fetched += 1;
  if (current.originFail) throw new Error('origin down');
  return new Response(current.originBody === undefined ? 'origin page' : current.originBody,
                      { status: current.originStatus || 200 });
};
const realNow = Date.now;
for (const c of cases) {
  const logs = [];
  current = c;
  fetched = 0;
  let bodyReads = 0;
  console.log = (...a) => { logs.push(a.join(' ')); };
  Date.now = c.now === undefined ? realNow : () => c.now;
  const req = { url: c.url, method: c.method || 'GET', headers: new Headers(c.headers || {}), cf: c.cf };
  if (c.body !== undefined) req.text = async () => { bodyReads += 1; return c.body; };
  let out;
  try {
    const res = await worker.fetch(req, c.env === undefined ? {} : c.env);
    out = { status: res.status, type: res.headers.get('content-type'),
            cache: res.headers.get('cache-control'), robots: res.headers.get('x-robots-tag'),
            body: await res.text(), logs, fetched, bodyReads };
  } catch (e) {
    out = { error: String(e), logs, fetched, bodyReads };
  }
  results.push(out);
}
process.stdout.write(JSON.stringify(results));
"""


def run(script, cases):
    """Each case is a dict: url, method, headers, cf, env, now, body, originBody,
    originStatus, originFail. Returns one result per case, in order."""
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        (td / 'worker.mjs').write_text(script)
        (td / 'driver.mjs').write_text(_DRIVER)
        (td / 'cases.json').write_text(json.dumps(cases))
        p = subprocess.run([NODE, 'driver.mjs', 'cases.json'], cwd=td, capture_output=True,
                           text=True, timeout=120)
    assert p.returncode == 0, p.stderr[-2000:]
    return json.loads(p.stdout)


def case(path, ip=ATK, host='example.com', **kw):
    """One visit. `ip=None` sends no CF-Connecting-IP header."""
    headers = {'user-agent': 'scanner/1.0'}
    if ip is not None:
        headers['cf-connecting-ip'] = ip
    headers.update(kw.pop('headers', {}))
    c = {'url': 'https://%s%s' % (host, path), 'headers': headers, 'cf': {'country': 'DK'}}
    c.update(kw)
    return c


# ── checks every public honeypot page has to pass ──────────────────────────────

_DOC_NETS = [ipaddress.ip_network(n) for n in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24',
                                               '127.0.0.0/8', '2001:db8::/32')]


def voice_problems(text):
    """What a public page may not say: an internal file, a real id, a house-style word, or
    a name that belongs to the maintainer's own install."""
    out = []
    if re.search(r'-internal\.md', text):
        out.append('names an internal file')
    if re.search(r'\b[0-9a-f]{32}\b', text):
        out.append('holds a 32 digit hex id, as a real zone or account id would be')
    for word in ('genuine', 'genuinely', 'verbatim', 'deliberate', 'deliberately'):
        if re.search(r'(?i)\b%s\b' % word, text):
            out.append('uses "%s"' % word)
    if re.search(r'(?i)tviweb|tvipper|bymanden|atramentum', text):
        out.append('names a host of the maintainer')
    if re.search(r'(?i)trap_(bait|robots|login|impostor|private)|trap-edge|trap-watch|SINK_KEY', text):
        out.append('names a part of the maintainer\'s own install')
    return out


def address_problems(text):
    """(how many addresses were checked, those that are neither a documentation range nor
    loopback). A guide copied from a working install is where a real address slips in."""
    found = re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', text)
    found += re.findall(r'(?<![\w:])[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7}(?![\w:])', text)
    bad = []
    for a in found:
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            continue
        if not any(ip in n for n in _DOC_NETS):
            bad.append(a)
    return len(found), bad


def viewer_problems(text):
    """The in-app viewer matches bold, code and links one line at a time and renders no
    horizontal rule, image or HTML, outside a code fence."""
    fence, plain = False, []
    for line in text.split('\n'):
        if line.strip().startswith('```'):
            fence = not fence
            continue
        if not fence:
            plain.append(line)
    joined = '\n'.join(plain)
    out = []
    if re.search(r'(?m)^\s*(---|\*\*\*)\s*$', joined):
        out.append('a horizontal rule')
    if re.search(r'!\[', joined):
        out.append('an image')
    if re.search(r'</?[a-z]+[^>]*>', joined):
        out.append('HTML')
    for ln in plain:
        if len(re.findall(r'\*\*', ln)) % 2 or ln.count('`') % 2 or ln.count('[') != ln.count(']'):
            out.append('a span over two lines: ' + ln.strip()[:60])
    return out

#!/usr/bin/env python3
"""RemotePower scanner satellite — v4.2.0 (B5) P1.

A long-polling worker that claims authorized scan jobs from a RemotePower
server and runs them with a vetted security toolchain, posting normalised
findings back. It is the scanner-satellite "default worker" from the B5 plan:
the offensive toolchain lives HERE, on a dedicated/hardened node, NOT on the
managed fleet hosts.

Authorization is enforced server-side: this worker only ever scans the target
the server hands it (derived from an enrolled, in-scope device). It never picks
its own targets. The server authenticates this worker by its satellite token.

P1: one safe tool — `nuclei` in a passive/non-intrusive profile. By default the
tool runs inside a pinned container (Docker/Podman) so the dual-use binary is
sandboxed; set RP_SCAN_RUNNER=nuclei to use a locally installed binary instead.

Environment:
  RP_SERVER_URL       e.g. https://remotepower.example.com   (required)
  RP_SATELLITE_TOKEN  the scanner satellite's token           (required)
  RP_CA_BUNDLE        optional extra CA bundle (added to the system store)
  RP_SCAN_RUNNER      'docker' (default) | 'podman' | 'nuclei'
  RP_NUCLEI_IMAGE     pinned image (default projectdiscovery/nuclei:v3@<digest>)
  RP_SCAN_POLL_SECS   idle long-poll interval (default 15)
  RP_SCAN_RATELIMIT   nuclei -rl requests/sec (default 50)
  RP_SCAN_TIMEOUT     per-scan wall-clock budget seconds (default 900)

This is intentionally dependency-free (stdlib only) and uses the argv-list form
for every subprocess — no shell, no string interpolation into a command line.
"""
import json
import os
import ssl
import subprocess
import sys
import time
import urllib.request
import urllib.error

VERSION = '4.2.0'

SERVER       = os.environ.get('RP_SERVER_URL', '').rstrip('/')
TOKEN        = os.environ.get('RP_SATELLITE_TOKEN', '')
CA_BUNDLE    = os.environ.get('RP_CA_BUNDLE', '')
RUNNER       = os.environ.get('RP_SCAN_RUNNER', 'docker')
NUCLEI_IMAGE = os.environ.get('RP_NUCLEI_IMAGE', 'projectdiscovery/nuclei:v3')
POLL_SECS    = int(os.environ.get('RP_SCAN_POLL_SECS', '15'))
RATELIMIT    = str(int(os.environ.get('RP_SCAN_RATELIMIT', '50')))
SCAN_TIMEOUT = int(os.environ.get('RP_SCAN_TIMEOUT', '900'))

# nuclei severities we collect; intrusive/dos/fuzz template tags are EXCLUDED so
# the P1 profile stays passive/non-intrusive against owned assets.
_SEVERITIES   = 'info,low,medium,high,critical'
_EXCLUDE_TAGS = 'intrusive,dos,fuzz'


def _ssl_ctx():
    ctx = ssl.create_default_context()
    # Explicit TLS 1.2 floor (matches RemotePower's server floor). The default
    # is already >=1.2 on modern Python, but pin it so an old interpreter or a
    # tampered default can't silently negotiate TLS 1.0/1.1.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if CA_BUNDLE and os.path.exists(CA_BUNDLE):
        # Trust an internal CA IN ADDITION to the system store, never instead.
        ctx.load_verify_locations(CA_BUNDLE)
    return ctx


def _api(method, path, body=None):
    """Call the RemotePower API authenticated as a scanner satellite."""
    url = f'{SERVER}{path}'
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header('X-RP-Satellite', TOKEN)
    req.add_header('Content-Type', 'application/json')
    with urllib.request.urlopen(req, timeout=60, context=_ssl_ctx()) as r:
        return json.loads(r.read().decode() or '{}')


# --- tool runners -----------------------------------------------------------
# Each runner: build a sandboxed argv, run it, parse stdout into the common
# finding shape {rule_id,title,severity,evidence,reference}. The PARSE step is
# split out (pure, no I/O) so it's unit-testable without the tool installed.

_TOOL_IMAGE = {
    'nuclei': os.environ.get('RP_NUCLEI_IMAGE', 'projectdiscovery/nuclei:v3'),
    'nikto':  os.environ.get('RP_NIKTO_IMAGE',  'frapsoft/nikto'),
    'nmap':   os.environ.get('RP_NMAP_IMAGE',   'instrumentisto/nmap'),
    'zap':    os.environ.get('RP_ZAP_IMAGE',    'zaproxy/zap-stable'),
    'wapiti': os.environ.get('RP_WAPITI_IMAGE', 'cyberwatch/wapiti'),
}


def _sandbox(image, tool_argv):
    """Wrap a tool's argv in a locked-down container (or run it bare when
    RP_SCAN_RUNNER names a local binary)."""
    if RUNNER in ('docker', 'podman'):
        return [RUNNER, 'run', '--rm', '--network', 'host', '--cap-drop', 'ALL',
                '--security-opt', 'no-new-privileges', '--read-only',
                '--pids-limit', '256', image] + tool_argv
    return tool_argv   # RP_SCAN_RUNNER is a local binary name (advanced)


def _run(argv):
    """Run a tool argv with the wall-clock budget. Returns (stdout, err)."""
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=SCAN_TIMEOUT)
    except subprocess.TimeoutExpired:
        return '', f'scan exceeded {SCAN_TIMEOUT}s budget'
    except FileNotFoundError:
        return '', f'runner not found: {argv[0]}'
    return proc.stdout or '', ''


def _parse_nuclei(text):
    """nuclei JSONL -> findings (one JSON object per line)."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        info = ev.get('info') or {}
        refs = info.get('reference') or []
        out.append({
            'rule_id':   str(ev.get('template-id') or ev.get('templateID') or ''),
            'title':     str(info.get('name') or ev.get('template-id') or ''),
            'severity':  str(info.get('severity') or 'unknown').lower(),
            'evidence':  str(ev.get('matched-at') or ev.get('host') or '')[:1000],
            'reference': (refs[0] if isinstance(refs, list) and refs else '')[:500],
        })
    return out


def _parse_nikto(text):
    """nikto -Format json -> findings. nikto doesn't rank severity → medium."""
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    # nikto emits either an object or a list of host objects.
    hosts = doc if isinstance(doc, list) else [doc]
    out = []
    for h in hosts:
        for v in (h.get('vulnerabilities') or []):
            out.append({
                'rule_id':   str(v.get('id') or v.get('OSVDB') or 'nikto'),
                'title':     str(v.get('msg') or '')[:300],
                'severity':  'medium',
                'evidence':  f"{v.get('method', '')} {v.get('url', '')}".strip()[:1000],
                'reference': str(v.get('references') or '')[:500],
            })
    return out


def _parse_nmap_xml(text):
    """nmap -oX -> findings. Open services as info; NSE vuln-script hits medium."""
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    out = []
    for host in root.findall('host'):
        addr_el = host.find('address')
        addr = addr_el.get('addr', '') if addr_el is not None else ''
        for port in host.findall('./ports/port'):
            state = port.find('state')
            if state is None or state.get('state') != 'open':
                continue
            pid = port.get('portid', '')
            svc = port.find('service')
            sname = svc.get('name', '') if svc is not None else ''
            prod = (svc.get('product', '') + ' ' + svc.get('version', '')).strip() if svc is not None else ''
            out.append({
                'rule_id': f'open-port-{pid}', 'severity': 'info',
                'title': f'Open {sname or "service"} on port {pid}',
                'evidence': f'{addr}:{pid} {prod}'.strip()[:1000], 'reference': '',
            })
            for scr in port.findall('script'):
                sid = scr.get('id', '')
                sout = (scr.get('output', '') or '').strip()
                low = sout.lower()
                if 'vuln' in sid and sout and 'error' not in low and "couldn't" not in low:
                    out.append({
                        'rule_id': sid, 'severity': 'medium',
                        'title': f'{sid} on port {pid}',
                        'evidence': sout[:1000], 'reference': '',
                    })
    return out


def _target_url(target, scheme='https'):
    return target if '://' in target else f'{scheme}://{target}'


def _parse_zap(text):
    """ZAP JSON report -> findings. riskcode 3=High 2=Medium 1=Low 0=Info."""
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    sev = {'3': 'high', '2': 'medium', '1': 'low', '0': 'info'}
    out = []
    for site in (doc.get('site') or []):
        for a in (site.get('alerts') or []):
            inst = a.get('instances') or []
            out.append({
                'rule_id':   str(a.get('pluginid') or a.get('alertRef') or 'zap'),
                'title':     str(a.get('name') or a.get('alert') or '')[:300],
                'severity':  sev.get(str(a.get('riskcode', '0')), 'unknown'),
                'evidence':  str((inst[0].get('uri') if inst else '') or a.get('url', ''))[:1000],
                'reference': str(a.get('reference') or '')[:500],
            })
    return out


def _parse_wapiti(text):
    """Wapiti JSON report -> findings. level 3=high 2=medium else low."""
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    sev = {3: 'high', 2: 'medium', 1: 'low'}
    out = []
    for category, items in (doc.get('vulnerabilities') or {}).items():
        for v in (items or []):
            lvl = v.get('level')
            out.append({
                'rule_id':   str(category)[:200],
                'title':     str(category)[:300],
                'severity':  sev.get(lvl if isinstance(lvl, int) else 0, 'low'),
                'evidence':  str(v.get('info') or v.get('http_request') or '')[:1000],
                'reference': '',
            })
    return out


def _nuclei_argv(target, profile):
    args = ['-u', target, '-severity', _SEVERITIES, '-jsonl', '-silent',
            '-rate-limit', RATELIMIT, '-disable-update-check']
    if profile != 'active':   # passive excludes intrusive/dos/fuzz templates
        args += ['-exclude-tags', _EXCLUDE_TAGS]
    return _sandbox(_TOOL_IMAGE['nuclei'], args)


def _nikto_argv(target, profile):
    tuning = [] if profile == 'active' else ['-Tuning', 'x6']  # x6 drops the DoS plugin
    return _sandbox(_TOOL_IMAGE['nikto'], [
        '-host', target, '-ssl', '-Format', 'json', '-output', '/dev/stdout',
        '-nointeractive', '-maxtime', str(SCAN_TIMEOUT)] + tuning)


def _nmap_argv(target, profile):
    scripts = 'safe,vuln' if profile == 'active' else 'safe'   # vuln NSE = active
    return _sandbox(_TOOL_IMAGE['nmap'], [
        '-sV', '-Pn', '-T3', '--script', scripts, '-oX', '-', target])


def _zap_argv(target, profile):
    # ACTIVE-only: zap-full-scan runs a real active scan; JSON to stdout.
    return _sandbox(_TOOL_IMAGE['zap'], [
        'zap-full-scan.py', '-t', _target_url(target), '-J', '/dev/stdout', '-I'])


def _wapiti_argv(target, profile):
    # ACTIVE-only: wapiti fuzzes; JSON report to stdout.
    return _sandbox(_TOOL_IMAGE['wapiti'], [
        '-u', _target_url(target), '--flush-session', '-f', 'json',
        '-o', '/dev/stdout', '--max-scan-time', str(SCAN_TIMEOUT)])


TOOL_RUNNERS = {
    'nuclei': (_nuclei_argv, _parse_nuclei),
    'nikto':  (_nikto_argv,  _parse_nikto),
    'nmap':   (_nmap_argv,   _parse_nmap_xml),
    'zap':    (_zap_argv,    _parse_zap),
    'wapiti': (_wapiti_argv, _parse_wapiti),
}


def _run_tool(tool, target, profile='passive'):
    """Dispatch to a tool runner. Returns (findings, error)."""
    spec = TOOL_RUNNERS.get(tool)
    if not spec:
        return [], f'unsupported tool {tool}'
    argv_fn, parse_fn = spec
    stdout, err = _run(argv_fn(target, profile))
    if err:
        return [], err
    return parse_fn(stdout), ''


# --- main loop --------------------------------------------------------------

def _process_one():
    """Claim at most one scan; run it; post results. Returns True if it did
    work, False if the queue was empty."""
    claim = _api('POST', '/api/scans/claim')
    job = (claim or {}).get('scan')
    if not job:
        return False
    sid, target, tool = job['id'], job['target'], job.get('tool', 'nuclei')
    print(f'[scanner] claimed {sid} tool={tool} target={target}', flush=True)
    if tool not in TOOL_RUNNERS:
        _api('POST', f'/api/scans/{sid}/results',
             {'status': 'failed', 'error': f'unsupported tool {tool}', 'findings': []})
        return True
    findings, err = _run_tool(tool, target, job.get('profile', 'passive'))
    status = 'failed' if err else 'done'
    _api('POST', f'/api/scans/{sid}/results',
         {'status': status, 'error': err, 'findings': findings})
    print(f'[scanner] {sid} {status} findings={len(findings)} {err}', flush=True)
    return True


def main():
    if not SERVER or not TOKEN:
        sys.stderr.write('RP_SERVER_URL and RP_SATELLITE_TOKEN are required\n')
        sys.exit(2)
    print(f'[scanner] RemotePower scanner satellite v{VERSION} → {SERVER} '
          f'(runner={RUNNER})', flush=True)
    while True:
        try:
            did_work = _process_one()
        except urllib.error.HTTPError as e:
            sys.stderr.write(f'[scanner] HTTP {e.code}: {e.reason}\n')
            did_work = False
        except urllib.error.URLError as e:
            sys.stderr.write(f'[scanner] connection error: {e.reason}\n')
            did_work = False
        except Exception as e:                       # never let the loop die
            sys.stderr.write(f'[scanner] unexpected: {e}\n')
            did_work = False
        if not did_work:
            time.sleep(POLL_SECS)


if __name__ == '__main__':
    main()

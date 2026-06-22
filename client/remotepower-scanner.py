#!/usr/bin/env python3
"""RemotePower scanner satellite — v4.3.0 (B5).

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

VERSION = '4.3.0'

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


def _sandbox(image, tool_argv, volumes=None, workdir=None, env=None):
    """Wrap a tool's argv in a locked-down container (or run it bare when
    RP_SCAN_RUNNER names a local binary). `volumes` (list of 'name:/path') are
    persistent named volumes — used to cache nuclei's template store so it isn't
    re-downloaded every run. `workdir` sets the container working dir (-w) and
    `env` (dict) sets environment vars (-e) — used to point a tool's HOME/cwd at
    a writable mount so its scratch files don't hit a read-only container path."""
    if RUNNER in ('docker', 'podman'):
        # Hardened but NOT --read-only: the tools must write scratch/report files
        # (zap /zap/wrk, wapiti session, nmap NSE temp) — a read-only rootfs makes
        # them silently produce nothing (0 findings). Ephemeral (--rm) +
        # cap-drop + no-new-privileges + pids cap keep it locked down.
        cmd = [RUNNER, 'run', '--rm', '--network', 'host', '--cap-drop', 'ALL',
               '--security-opt', 'no-new-privileges', '--pids-limit', '512']
        for v in (volumes or []):
            cmd += ['-v', v]
        if workdir:
            cmd += ['-w', workdir]
        for k, val in (env or {}).items():
            cmd += ['-e', f'{k}={val}']
        return cmd + [image] + tool_argv
    return tool_argv   # RP_SCAN_RUNNER is a local binary name (advanced)


MAX_FINDINGS = int(os.environ.get('RP_SCAN_MAX_FINDINGS', '200'))


def _force_remove(name):
    if not name or RUNNER not in ('docker', 'podman'):
        return
    try:
        subprocess.run([RUNNER, 'rm', '-f', name], capture_output=True, timeout=30)
    except Exception:
        pass


def _cleanup_orphans():
    """Remove any leftover rp-scan-* containers (worker crash / prior timeout).
    Called at startup and after each scan so the scanner never piles up."""
    if RUNNER not in ('docker', 'podman'):
        return
    try:
        r = subprocess.run([RUNNER, 'ps', '-aq', '--filter', 'name=rp-scan-'],
                           capture_output=True, text=True, timeout=30)
        ids = [x for x in (r.stdout or '').split() if x]
        if ids:
            subprocess.run([RUNNER, 'rm', '-f'] + ids, capture_output=True, timeout=60)
    except Exception:
        pass


def _run(argv):
    """Run a tool argv with the wall-clock budget. Returns (stdout, stderr, err).

    For container runs we inject a unique --name so the container can be
    force-removed when the budget is exceeded. subprocess timeout only kills the
    `docker run` CLIENT — the container keeps running (the orphan that pinned the
    target host at load 8). rm -f on timeout stops it for real."""
    name = None
    if RUNNER in ('docker', 'podman') and len(argv) >= 2 and argv[0] == RUNNER and argv[1] == 'run':
        name = 'rp-scan-' + os.urandom(6).hex()
        argv = [argv[0], argv[1], '--name', name] + argv[2:]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=SCAN_TIMEOUT)
    except subprocess.TimeoutExpired:
        _force_remove(name)   # kill the still-running container, not just the client
        return '', '', f'scan exceeded {SCAN_TIMEOUT}s budget'
    except FileNotFoundError:
        return '', '', f'runner not found: {argv[0]}'
    return proc.stdout or '', proc.stderr or '', ''


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


def _clean_reference(ref):
    """ZAP reference fields are HTML (e.g. "<p>https://…</p><p>…</p>"). Strip the
    markup and return the FIRST real URL, so the UI gets a clean link instead of
    a mangled "/<p>https…</p>" string."""
    import re
    text = re.sub(r'<[^>]+>', ' ', str(ref or ''))
    m = re.search(r'https?://[^\s"\'<>]+', text)
    return (m.group(0) if m else '')[:500]


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
                'reference': _clean_reference(a.get('reference')),
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


def _quick(intensity):
    return intensity != 'full'


def _nuclei_argv(target, profile, intensity):
    # NB: do NOT pass -disable-update-check — the nuclei image ships WITHOUT
    # templates, and -duc also blocks the template download, so nuclei runs with
    # zero templates and finds nothing. Letting it manage templates (cached in a
    # named volume so it's downloaded once) is what makes it actually scan.
    # quick = medium+ severities (fast, low-noise); full = every severity.
    sev = 'medium,high,critical' if _quick(intensity) else _SEVERITIES
    args = ['-u', target, '-severity', sev, '-jsonl', '-silent',
            '-rate-limit', RATELIMIT]
    if profile != 'active':   # passive excludes intrusive/dos/fuzz templates
        args += ['-exclude-tags', _EXCLUDE_TAGS]
    return _sandbox(_TOOL_IMAGE['nuclei'], args,
                    volumes=['rp-nuclei-templates:/root/nuclei-templates'])


def _nikto_argv(target, profile, intensity):
    tuning = [] if profile == 'active' else ['-Tuning', 'x6']  # x6 drops the DoS plugin
    maxtime = '180' if _quick(intensity) else str(SCAN_TIMEOUT)
    # Don't force -ssl (it pins HTTPS/443 and finds nothing on a plain-HTTP or
    # non-443 target). nikto auto-detects from the host/URL.
    return _sandbox(_TOOL_IMAGE['nikto'], [
        '-host', target, '-Format', 'json', '-output', '/dev/stdout',
        '-nointeractive', '-maxtime', maxtime] + tuning)


def _nmap_argv(target, profile, intensity):
    scripts = 'safe,vuln' if profile == 'active' else 'safe'   # vuln NSE = active
    # quick = top 100 ports (-F); full = every port (-p-).
    ports = ['-F'] if _quick(intensity) else ['-p-']
    return _sandbox(_TOOL_IMAGE['nmap'],
                    ['-sV', '-Pn', '-T3'] + ports + ['--script', scripts, '-oX', '-', target])


def _zap_argv(target, profile, intensity, workdir, report):
    # quick = zap-baseline (fast, passive spider); full = zap-full-scan (active).
    # Both write a JSON report into the work dir (/zap/wrk); mount + read it back.
    # -I = don't fail the container on warnings.
    script = 'zap-baseline.py' if _quick(intensity) else 'zap-full-scan.py'
    # Point ZAP's HOME + working dir at the writable /zap/wrk mount. Newer
    # zaproxy/zap-stable images write an intermediate summary (zap_out.json) to
    # $HOME, which fails under the locked-down container and produces 0 findings
    # with no report. Redirecting HOME to the mounted dir keeps all ZAP scratch
    # on a writable path so the -J report is actually produced.
    #
    # :z relabels the bind mount for SELinux — without it, an SELinux-enforcing
    # host (RHEL/Fedora/CentOS) denies the container's write to the mounted dir,
    # so the scan runs but the report write fails ("Failed to access summary
    # file /zap/wrk/zap_out.json"). Harmless on non-SELinux hosts.
    return _sandbox(_TOOL_IMAGE['zap'], [
        script, '-t', _target_url(target), '-J', report, '-I'],
        volumes=[f'{workdir}:/zap/wrk:rw,z'],
        workdir='/zap/wrk', env={'HOME': '/zap/wrk'})


def _wapiti_argv(target, profile, intensity, workdir, report):
    # wapiti fuzzes and writes a JSON report to -o; mount /output and read back.
    maxtime = '180' if _quick(intensity) else str(SCAN_TIMEOUT)
    return _sandbox(_TOOL_IMAGE['wapiti'], [
        '-u', _target_url(target), '--flush-session', '-f', 'json',
        '-o', f'/output/{report}', '--max-scan-time', maxtime],
        volumes=[f'{workdir}:/output:rw'])


# Tools that stream their report to stdout (argv_fn(target, profile, intensity)).
STDOUT_TOOLS = {
    'nuclei': (_nuclei_argv, _parse_nuclei),
    'nikto':  (_nikto_argv,  _parse_nikto),
    'nmap':   (_nmap_argv,   _parse_nmap_xml),
}
# Tools that write a JSON report FILE (argv_fn(target, profile, workdir, report)).
REPORT_TOOLS = {
    'zap':    (_zap_argv,    _parse_zap),
    'wapiti': (_wapiti_argv, _parse_wapiti),
}
# Union, for membership checks (the worker + UI ask "is this a known tool?").
TOOL_RUNNERS = {**STDOUT_TOOLS, **REPORT_TOOLS}
_REPORT_NAME = 'report.json'


def _run_stdout_tool(argv, parse_fn):
    stdout, stderr, err = _run(argv)
    if err:
        return [], err
    findings = parse_fn(stdout)
    # Distinguish "scanned, genuinely clean" from "tool produced nothing" — if
    # there's no parseable output but the tool wrote to stderr, surface the last
    # line so the operator isn't left guessing at a silent 0.
    if not findings and not stdout.strip() and stderr.strip():
        return [], 'tool produced no output: ' + stderr.strip().splitlines()[-1][:200]
    return findings, ''


def _run_report_tool(argv_fn, parse_fn, target, profile, intensity):
    """For tools that write a JSON report FILE (zap, wapiti): mount a fresh host
    temp dir as the container work dir, run, read the report back, parse, clean
    up. The dir is world-writable so a tool running as a non-root container uid
    (e.g. ZAP's uid 1000) can write into it."""
    import shutil
    import tempfile
    # CWE-732: the work dir must be world-writable so a non-root *container* uid
    # (e.g. ZAP's 1000) can write its report into the bind mount — but a 0777 dir
    # directly in shared /tmp lets any local user read it or race a symlink at the
    # report path. Nest it under a 0700 parent that only we can traverse: the
    # Docker bind-mount still maps the inner dir straight into the container
    # (the daemon resolves it as root), while local users can't reach it.
    parent = tempfile.mkdtemp(prefix='rp-scan-')   # 0700, unique, owned by us
    workdir = os.path.join(parent, 'wrk')
    os.mkdir(workdir)
    try:
        try:
            # nosec B103 — 0o777 on the INNER 'wrk' dir only, nested under the
            # 0700 mkdtemp parent above (local users can't traverse it). The wide
            # mode lets a containerized scanner (e.g. ZAP UID 1000, resolved by
            # the Docker daemon as root) write its report into the bind mount; the
            # 0700 parent prevents any local-user read / symlink race.
            os.chmod(workdir, 0o777)  # nosec B103
        except OSError:
            pass
        stdout, stderr, err = _run(argv_fn(target, profile, intensity, workdir, _REPORT_NAME))
        if err:
            return [], err
        try:
            with open(os.path.join(workdir, _REPORT_NAME), 'r', errors='replace') as f:
                text = f.read()
        except FileNotFoundError:
            # Surface the last few lines of the tool's OWN output (stdout+stderr,
            # ZAP logs to both) — not just one line — so a report-generation
            # failure is actually diagnosable from the scanner journal.
            blob = ((stdout or '') + '\n' + (stderr or '')).strip()
            lines = [l for l in blob.splitlines() if l.strip()]
            tail = ' | '.join(lines[-6:])[:600] if lines else ''
            return [], 'no report produced' + (f': {tail}' if tail else '')
        return parse_fn(text), ''
    finally:
        shutil.rmtree(parent, ignore_errors=True)


def _run_tool(tool, target, profile='passive', intensity='quick'):
    """Dispatch to a tool runner. Returns (findings, error)."""
    if tool in STDOUT_TOOLS:
        argv_fn, parse_fn = STDOUT_TOOLS[tool]
        return _run_stdout_tool(argv_fn(target, profile, intensity), parse_fn)
    if tool in REPORT_TOOLS:
        argv_fn, parse_fn = REPORT_TOOLS[tool]
        return _run_report_tool(argv_fn, parse_fn, target, profile, intensity)
    return [], f'unsupported tool {tool}'


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
    try:
        findings, err = _run_tool(tool, target, job.get('profile', 'passive'),
                                  job.get('intensity', 'quick'))
    finally:
        _cleanup_orphans()   # belt-and-braces: nothing rp-scan-* left behind
    status = 'failed' if err else 'done'
    total = len(findings)
    findings = findings[:MAX_FINDINGS]   # keep the POST under the 2 MB body cap
    note = err
    if total > MAX_FINDINGS:
        note = (note + '; ' if note else '') + f'showing {MAX_FINDINGS} of {total} findings'
    _api('POST', f'/api/scans/{sid}/results',
         {'status': status, 'error': note, 'findings': findings})
    print(f'[scanner] {sid} {status} findings={len(findings)}/{total} {err}', flush=True)
    return True


def main():
    if not SERVER or not TOKEN:
        sys.stderr.write('RP_SERVER_URL and RP_SATELLITE_TOKEN are required\n')
        sys.exit(2)
    print(f'[scanner] RemotePower scanner satellite v{VERSION} → {SERVER} '
          f'(runner={RUNNER})', flush=True)
    _cleanup_orphans()   # clear any rp-scan-* left by a crashed/killed prior run
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

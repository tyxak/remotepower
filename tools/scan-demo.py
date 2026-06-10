#!/usr/bin/env python3
"""scan-demo.py — watch a B5 security scan go queued → done, end to end.

It logs in, mints a scanner satellite, queues a scan against the first enrolled
device, then ACTS as the scanner worker (claims the job and posts a couple of
canned findings) so you see the whole pipeline complete in the UI — without
installing nuclei/Docker-in-Docker.

Run it against a running RemotePower (e.g. the docker compose stack):

    python3 tools/scan-demo.py

Environment (all optional):
    RP_URL   default http://localhost:8085
    RP_USER  default admin
    RP_PASS  default changeme

Then refresh Monitoring → Scans in the browser: the scan is `done` with findings.
"""
import json
import os
import sys
import urllib.request
import urllib.error

URL  = os.environ.get('RP_URL',  'http://localhost:8085').rstrip('/')
USER = os.environ.get('RP_USER', 'admin')
PASS = os.environ.get('RP_PASS', 'changeme')


def call(method, path, body=None, token=None, sat=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(URL + path, data=data, method=method)
    req.add_header('Content-Type', 'application/json')
    if token:
        req.add_header('X-Token', token)
    if sat:
        req.add_header('X-RP-Satellite', sat)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode() or '{}')
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or '{}')
        except Exception:
            return e.code, {'error': e.reason}
    except urllib.error.URLError as e:
        print(f"\n  Can't reach {URL} — is the server up? ({e.reason})")
        sys.exit(1)


def step(label, st, data):
    s = json.dumps(data)
    print(f"  {label:34} → [{st}] {s[:150]}")
    return data


def main():
    print(f"\n=== B5 scan demo against {URL} ===\n")

    # 1. log in
    st, d = call('POST', '/api/login', {'username': USER, 'password': PASS})
    token = d.get('token')
    step('log in', st, {'token': (token[:8] + '…') if token else None, **{k: v for k, v in d.items() if k != 'token'}})
    if not token:
        print("\n  Login failed — check RP_USER / RP_PASS.")
        sys.exit(1)

    # 2. mint a scanner satellite
    st, d = call('POST', '/api/satellites', {'name': 'demo-scanner', 'scanner': True}, token=token)
    sat = d.get('token')
    step('mint scanner satellite', st, {'id': d.get('id'), 'scanner': d.get('scanner')})
    if not sat:
        print("\n  Could not mint a scanner satellite (need admin).")
        sys.exit(1)

    # 3. pick an enrolled device with an address
    st, devs = call('GET', '/api/devices?slim=1', token=token)
    devlist = devs if isinstance(devs, list) else (devs.get('devices') or [])
    dev = next((x for x in devlist if x.get('ip')), None)
    if not dev:
        print("\n  No enrolled device with an address found. Seed the demo fleet "
              "first:\n    docker compose exec remotepower \\\n"
              "      python3 /var/www/remotepower/.../seed-demo-data.py --apply")
        sys.exit(1)
    step('pick a device', 200, {'id': dev.get('id'), 'name': dev.get('name'), 'ip': dev.get('ip')})

    # 4. queue a scan (target is derived server-side from the device)
    st, d = call('POST', '/api/scans', {'device_id': dev['id'], 'tool': 'nuclei'}, token=token)
    sid = d.get('id')
    step('queue scan', st, d.get('scan', d))

    # 5. act as the scanner worker: claim the job
    st, d = call('POST', '/api/scans/claim', sat=sat)
    step('satellite claims job', st, d.get('scan'))

    # 6. post a couple of canned findings + mark done
    findings = [
        {'rule_id': 'tls-version', 'title': 'TLS 1.0 supported', 'severity': 'high',
         'evidence': f"{dev['ip']}:443", 'reference': 'https://example.com'},
        {'rule_id': 'missing-hsts', 'title': 'HSTS header missing', 'severity': 'low'},
    ]
    st, d = call('POST', f'/api/scans/{sid}/results',
                 {'status': 'done', 'findings': findings}, sat=sat)
    step('satellite posts findings', st, d)

    # 7. read it back
    st, d = call('GET', f'/api/scans/{sid}', token=token)
    step('scan detail', st, {'status': d.get('status'),
                             'severity_counts': d.get('severity_counts'),
                             'findings': len(d.get('findings') or [])})

    print(f"\n  Done. Open {URL} → Monitoring → Scans to see it (status: "
          f"{d.get('status')}, {len(d.get('findings') or [])} findings).\n")


if __name__ == '__main__':
    main()

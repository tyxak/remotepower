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
# Bug fix: 'finance' (the read-only billing login, build_users()) was added
# after this set and never added here — every re-seed after the first was
# refused ("contains real (non-demo) account: finance"), silently breaking
# the documented cron re-seed workflow.
_DEMO_ACCOUNTS = {'demo', 'alice', 'bob', 'finance'}


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

    prod_path = resolved in PROTECTED_DATA_DIRS

    # 2. Real accounts present → always block, even with override or a marker.
    # A never-used default admin (must_change_password=True) does NOT count:
    # the app auto-creates exactly that the first time the demo vhost serves a
    # request, and refusing to seed because of it would make a fresh demo
    # instance un-seedable. A *real* admin (password changed, so no
    # must_change_password flag) still blocks — that's the production guard.
    users = target / 'users.json'
    # Path.exists() itself can raise PermissionError (Python 3.12+) when the
    # target is a real, restrictive install dir (mode 0700 owned by another
    # user) that we can't even stat — so guard the stat, not just the read.
    try:
        users_exist = users.exists()
    except OSError:
        users_exist = None
    if users_exist:
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
    elif users_exist is None and not prod_path:
        # Can't even stat the dir (inaccessible real install), and it isn't a
        # known production path we can name — refuse rather than crash or risk it.
        return (False, f"{users} is present but not accessible — refusing to "
                       f"risk overwriting a real data dir.")

    if override:
        return (True, 'override')

    # 1. Canonical production path.
    if prod_path:
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

# v6.1.0 coverage fill: rack ids, referenced by both build_cmdb() (rack_id on
# each placed asset) and build_racks() (the rack records themselves).
RACK_DC = _stable_id('rack', 'dc-frankfurt-r1')
RACK_HQ = _stable_id('rack', 'hq-copenhagen-r1')

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
            'ui_prefs':      {'team': 'Infrastructure'},
        },
        # v5.4.0 — the Billing / invoices / worksheet pages are admin/finance
        # only by design (viewers get a 403). So the demo ships a dedicated
        # read-only 'finance' login (password 'demo') that CAN see billing —
        # otherwise the newly-seeded billing data would be invisible to visitors.
        'finance': {
            'role': 'finance',
            'password_hash': demo_hash,
            'totp_secret':   '',
            'created_at':    now() - 86400 * 60,
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
            # btrfs carries a mountpoint so the Storage page's "Maintain…"
            # actions (scrub / balance / snapshots) have a target.
            {'name': 'btrfs:data', 'kind': 'btrfs', 'state': 'online',
             'mount': '/mnt/vault', 'capacity': rng.randint(45, 88)},
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

    # ── v5.0.0: per-interface network throughput (Network Metrics page) ──
    # The agent reports rx/tx bits-per-second + lifetime totals per NIC; the
    # /api/network-metrics roll-up sums them. Busier roles push more traffic.
    _busy = 1.0
    if any(t in (dev.get('tags') or []) for t in ('proxy', 'web', 'media', 'streaming')):
        _busy = 6.0
    elif any(t in (dev.get('tags') or []) for t in ('nas', 'backup', 'storage')):
        _busy = 4.0
    _rx = int(rng.uniform(0.2, 3.0) * _busy * 1e6)   # ~0.2–18 Mbps
    _tx = int(rng.uniform(0.1, 2.0) * _busy * 1e6)
    si['network_io'] = [{
        'iface':    'eth0',
        'rx_bps':   _rx,
        'tx_bps':   _tx,
        'rx_total': _rx * rng.randint(50_000, 500_000),
        'tx_total': _tx * rng.randint(50_000, 500_000),
    }]


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
            'version':     '4.7.0' if not dev['agentless'] else None,
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
                'packages':     (lambda u: {'upgradable': u, 'security_updates': rng.randint(0, u) if u else 0})(rng.choices([0, 0, 0, 1, 3, 7, 12, 23], k=1)[0]),
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
        else:
            # Agentless network gear is SNMP-polled. device_list only attaches
            # an snmp_status snapshot when the device record itself has
            # snmp.enabled (api.py ~7058); the per-device cache lives in
            # snmp_data.json (build_snmp_data). Without this the SNMP pill and
            # the SNMP-Metrics page stay blank even with the cache populated.
            rec['snmp'] = {'enabled': True, 'community': 'public',
                           'port': 161, 'version': '2c'}

        # v6.1.0 coverage fill: per-interface MAC list (device drawer network
        # panel — distinct from cmdb.json's NAT-focused `interfaces`, see
        # build_cmdb()). Only the multi-NIC hosts, so it looks deliberate
        # rather than padded onto every device.
        if dev['id'] == 'pmx01':
            rec.setdefault('sysinfo', {})['network'] = [
                {'iface': 'eno1', 'ip': '10.0.1.10', 'mac': dev['mac']},
                {'iface': 'eno2', 'ip': '10.0.1.11', 'mac': '52:54:00:11:01:11'},
            ]
        elif dev['id'] == 'tnas':
            rec.setdefault('sysinfo', {})['network'] = [
                {'iface': 'mgmt0', 'ip': '10.0.1.20', 'mac': dev['mac']},
                {'iface': 'stor0', 'ip': '10.0.1.21', 'mac': '52:54:00:11:01:21'},
            ]
        elif dev['id'] == 'fw01':
            rec.setdefault('sysinfo', {})['network'] = [
                {'iface': 'em0', 'ip': '203.0.113.7',  'mac': dev['mac']},
                {'iface': 'em1', 'ip': '10.0.0.254',   'mac': '52:54:00:11:00:ff'},
                {'iface': 'em2', 'ip': '10.0.99.1',    'mac': '52:54:00:11:00:fd'},
            ]

        # v6.1.0 coverage fill: guided CIS remediation is a per-host opt-in
        # (default off) — a couple of package-manager hosts have it on so the
        # Compliance page shows the fix-it action, most stay off to show the
        # gate itself.
        if dev['id'] in ('ng01', 'gt01'):
            rec['remediation_enabled'] = True

        # v6.1.0 coverage fill: OPNsense connector — DISABLED. Even in
        # read-only demo mode, GET requests reach the live connector code
        # (_enforce_read_only only blocks mutations), so enabled:true here
        # would make ordinary page loads fire a real outbound HTTPS call to
        # a fake host. enabled:false short-circuits before any network I/O
        # while still showing the connector as "configured" in the UI.
        if dev['id'] == 'fw01':
            rec['opnsense'] = {'enabled': False, 'api_key': 'demo-key-not-real',
                                'api_secret': 'demo-secret-not-real',
                                'port': 443, 'verify': False}

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
        'business_function': 'OS Operation',
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
        'business_function': 'Server Camp',
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
            # v5.0.0: coarse operational-ownership bucket. App-facing services →
            # Application Operation; OS/platform hosts → OS Operation; the rest
            # (infra/storage/network appliances) → Server Camp.
            'business_function': (
                'Application Operation' if function in (
                    'web', 'proxy', 'media', 'streaming', 'files', 'cloud',
                    'git', 'dev', 'home', 'iot', 'secrets')
                else 'OS Operation' if function in (
                    'dns', 'monitoring', 'metrics')
                else 'Server Camp'),
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

    # v6.1.0 coverage fill: rack placement (rack_id/rack_unit/rack_height_u —
    # rack_unit is the BOTTOM U, 1-based) and per-interface NAT mappings
    # (iface/ip/nat_ip/primary — distinct from the agent-reported MAC list in
    # devices.json[id]['sysinfo']['network'], see build_devices()). Rack ids
    # match build_racks() below (both derived from the same stable key).
    for dev_id, rack_id, bottom_u, height_u in (
        ('sw02',  RACK_DC, 1, 1),
        ('pr01',  RACK_DC, 3, 1),
        ('bk01',  RACK_DC, 5, 2),
        ('tnas',  RACK_DC, 10, 4),
        ('pmx01', RACK_DC, 20, 3),
        ('sw01',  RACK_HQ, 1, 1),
        ('fw01',  RACK_HQ, 3, 1),
    ):
        if dev_id not in out:
            out[dev_id] = {'asset_id': '', 'server_function': '', 'business_function': '',
                            'hypervisor_url': '', 'ssh_port': 22, 'documentation': '',
                            'docs': [], 'warranty_expiry': '', 'license_expiry': '',
                            'support_contract_expiry': '', 'credentials': [],
                            'updated_by': 'demo', 'updated_at': now() - 86400 * 5}
        out[dev_id]['rack_id'] = rack_id
        out[dev_id]['rack_unit'] = bottom_u
        out[dev_id]['rack_height_u'] = height_u

    out['fw01']['interfaces'] = [
        {'iface': 'em0', 'ip': '203.0.113.7',   'nat_ip': '', 'primary': False},  # WAN
        {'iface': 'em1', 'ip': '10.0.0.254',    'nat_ip': '', 'primary': True},   # LAN
        {'iface': 'em2', 'ip': '10.0.99.1',     'nat_ip': '', 'primary': False},  # DMZ
    ]
    out['nc01']['interfaces'] = [
        {'iface': 'eth0', 'ip': '10.0.2.60', 'nat_ip': '203.0.113.7', 'primary': True},
    ]
    return out


def build_history() -> dict:
    """Command dispatch history shown on the History page. Shape verified
    against handle_history/_record_command_history (api.py ~5195-5210,
    ~21853-21856): {"entries": [{ts, actor, device_id, device_name,
    command}]} -- NOT a bare list (that shape only round-trips through the
    JSON backend by accident; the Postgres "wrapped-list" storage class
    (storage.py's _classify) expects the {"entries": [...]} wrapper and a
    bare list fails migration verification with "content differs after
    migrate"). Field names also matter: the History table
    (_registerHistoryTable, app.js) reads device_name/command specifically,
    not device/action/detail -- the old shape rendered blank columns."""
    name_of = {d['id']: d['name'] for d in FAKE_DEVICES}
    plan = [
        (1,  'pmx01', 'reboot — scheduled: kernel update'),
        (4,  'jf01',  'systemctl restart jellyfin'),
        (8,  'nc01',  'apt-get upgrade — 12 packages'),
        (24, 'gt01',  'docker compose pull && docker compose up -d'),
        (48, 'tnas',  'zpool scrub tank'),
        (72, 'pi1',   'reboot — manual'),
        (120, 'pmx01', 'apt-get upgrade — 7 packages'),
        (168, None,   'fleet-wide agent update to v2.2.0'),
    ]
    entries = []
    for hours_ago, dev_id, command in plan:
        entries.append({
            'ts': now() - 3600 * hours_ago, 'actor': 'demo',
            'device_id': dev_id or '', 'device_name': name_of.get(dev_id, 'all devices'),
            'command': command,
        })
    return {'entries': entries}


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
        'server_version':    '5.6.0',
        'agent_version':     '5.6.0',
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

        # v3.14.0 — exposed-secrets scanning on (so the Secrets page shows the
        # seeded findings as active rather than "scanning is off").
        'secrets_scan_enabled': True,

        # v3.4.2 — access watch: events fired outside business hours surface in
        # Needs-Attention. Window + watched events match build_after_hours_hits.
        'after_hours': {
            'enabled':  True,
            'events':   ['recent_login', 'new_port_detected', 'command_run'],
            'start':    '09:00',
            'end':      '17:00',
            'workdays': [0, 1, 2, 3, 4],
        },

        # v4.7.0 — homelab software integrations. show_homelab is the enterprise
        # kill switch (default on). The instances + their last poll results live
        # in _DEMO_INTEGRATIONS / build_integrations_state; integration_notified
        # marks the already-down ones so the first real poll doesn't re-alert.
        'show_homelab':          True,
        'integrations_interval': 300,
        'integrations':          _DEMO_INTEGRATIONS,
        'integration_notified':  {i['id']: True for i in _DEMO_INTEGRATIONS
                                  if _DEMO_INTEG_RESULTS[i['id']][0] != 'ok'},

        # ── v5.1–v5.6 opt-in features — enabled so the demo shows them
        # populated. The demo runs read-only (RP_READ_ONLY=1) so no mutation /
        # execution actually happens regardless of these being on.

        # v5.3.0 — built-in helpdesk. Mailbox ingest is OFF (no real IMAP in the
        # demo) but the SLA policy + auto-reply are configured so the page is
        # fully populated.
        'tickets_enabled':       True,
        'ticket_sla':            {'1': 1.0, '2': 4.0, '3': 24.0, '4': 72.0},
        'ticket_imap': {
            'enabled':    False,
            'host':       'mail.acme-hosting.example',
            'port':       993,
            'username':   'support@acme-hosting.example',
            'folder':     'INBOX',
            'use_ssl':    True,
            'verify_tls': True,
            'interval':   300,
        },
        'ticket_autoreply': {
            'enabled': True,
            'subject': 'We received your request — [#{{number}}]',
            'body':    'Thanks for contacting support. Your ticket #{{number}} is '
                       'logged and a technician will follow up shortly.',
        },

        # v5.4.0 — Billing / time-tracking. The Billing page is admin/finance
        # only by design; the demo ships a read-only 'finance' login so visitors
        # can see it (see build_users). Time-logging on tickets + the weekly
        # timesheet stay available to everyone regardless.
        'billing_enabled':       True,

        # v5.6.0 — Provisioning blueprint catalog. iac_execute shows the
        # server-side Terraform plan/apply UI; harmless in the read-only demo
        # (no terraform binary, no real cloud creds).
        'show_provisioning':     True,
        'iac_execute_enabled':   True,

        # v5.6.0 — Knowledge base (also a RAG source).
        'kb_enabled':            True,

        # Host file manager — browse/read/edit host files from the device drawer
        # under an allow-listed set of roots (command-perm gated, audited).
        'file_manager': {
            'enabled': True,
            'roots':   ['/etc', '/var/log', '/opt', '/srv', '/home', '/usr/local'],
        },

        # ── v6.1.0 coverage fill: previously-unseeded config surfaces ──────
        # Schemas verified directly against the handlers that read them
        # (handle_config_save / _execute_monitor_checks / etc in api.py) —
        # field names below are NOT guesses (e.g. it's `via_satellite`, not
        # `satellite_id`; `steps`, not `http_flow_steps`; escalation/oncall
        # are two separate keys, not one).

        # Active monitors (Monitor page + satellite-probed checks).
        'monitors': [
            {'label': 'Public site — nginx.lab', 'type': 'http',
             'target': 'https://nginx.lab/', 'target_kind': 'host',
             'expect_status': 200, 'max_latency_ms': 800},
            {'label': 'Nextcloud status endpoint', 'type': 'http',
             'target': 'https://nextcloud.lab/status.php', 'target_kind': 'host',
             'body_match': {'mode': 'contains', 'value': 'installed'}},
            {'label': 'Gitea Postgres', 'type': 'db',
             'target': 'gitea.lab:5432', 'target_kind': 'host', 'db_kind': 'postgres'},
            {'label': 'Vaultwarden cache', 'type': 'db',
             'target': 'vaultwarden.lab:6379', 'target_kind': 'host', 'db_kind': 'redis'},
            {'label': 'Pi-hole resolves itself', 'type': 'dns',
             'target': 'pihole.lab', 'target_kind': 'host', 'expect': '10.0.2.10'},
            {'label': 'Core switch reachability', 'type': 'icmp',
             'target': 'switch-core', 'target_kind': 'host',
             'max_latency_ms': 20, 'max_loss_pct': 5},
            {'label': 'Critical hosts — tag ping sweep', 'type': 'ping',
             'target': 'critical', 'target_kind': 'tag'},
            {'label': 'Route to Frankfurt DC', 'type': 'path',
             'target': 'truenas.lab', 'target_kind': 'host'},
            {'label': 'Nextcloud login flow', 'type': 'http_flow', 'steps': [
                {'url': 'https://nextcloud.lab/login', 'method': 'GET', 'expect_status': 200},
                {'url': 'https://nextcloud.lab/status.php', 'method': 'GET',
                 'expect_contains': 'installed'},
            ]},
            {'label': 'Edge site — probed from the HQ relay', 'type': 'ping',
             'target': 'nginx.lab', 'target_kind': 'host',
             'via_satellite': _stable_hex('satellite', 'hq-relay', nbytes=8)},
        ],

        # Backup freshness watch (device-drawer Backups card + 3-2-1 score).
        # State lives in backup_state.json, keyed "<device_id>:<path>".
        'backup_monitors': [
            {'path': '/mnt/backup/restic-repo', 'label': 'Restic repo (backup.lab)',
             'max_age_hours': 26, 'tool': 'restic',
             'verify_enabled': True, 'verify_max_age_hours': 168},
            {'path': '/mnt/data/nextcloud-dump.sql.gz', 'label': 'Nextcloud DB dump',
             'max_age_hours': 24, 'tool': 'tar', 'verify_enabled': False},
            {'path': '/tank/backups', 'label': 'TrueNAS replicated snapshots',
             'max_age_hours': 48, 'tool': 'auto',
             'verify_enabled': True, 'verify_max_age_hours': 168,
             'restore_drill_enabled': True, 'restore_sample_path': '/tank/backups/latest',
             'restore_drill_max_age_hours': 336},
        ],

        # Mail round-trip probe (single global probe).
        'mailflow': {
            'enabled': True, 'to_address': 'mailcheck@nginx.lab',
            'imap_host': 'nginx.lab', 'imap_port': 993, 'imap_user': 'mailcheck',
            'imap_folder': 'INBOX', 'imap_ssl': True, 'imap_verify_tls': True,
            'max_latency_seconds': 120,
        },

        # Certificate-Transparency watch.
        'ct_watch_domains': ['nginx.lab'],

        # Quiet hours (do-not-disturb window for notifications).
        'quiet_hours': {'enabled': True, 'start': '22:00', 'end': '07:00',
                         'min_severity': 'high'},

        # Escalation tiers + on-call rotation (two separate config keys).
        'escalation': {'enabled': True,
                        'tiers': [{'after_minutes': 15},
                                  {'after_minutes': 60, 'target': 'wh_pushover_demo'}],
                        'severities': ['critical', 'high']},
        'oncall': {'enabled': True, 'contacts': ['alice', 'bob'],
                   'rotation_days': 7, 'anchor': now() - 86400 * 3},

        # Alert → runbook links (event name, or "check:<id>", -> KB article id).
        'alert_runbooks': {
            'backup_stale':  'kb_' + _stable_hex('kb', 5, nbytes=3)[:5],
            'monitor_down':  'kb_' + _stable_hex('kb', 2, nbytes=3)[:5],
        },

        # Patch-compliance SLA rules (state lives in patch_age.json).
        'patch_sla': [
            {'match_type': 'tag', 'pattern': 'critical', 'sec_days': 7, 'all_days': 30},
            {'match_type': 'all', 'sec_days': 14, 'all_days': 60},
        ],

        # Container-image CVE scanning toggle (findings live in image_cves.json).
        'image_scan_enabled': True,

        # Saved custom-check bundles (script_ids must exist in custom_scripts.json
        # — reuses the ids build_custom_scripts() already mints).
        'monitoring_profiles': [
            {'id': 'mp_' + _stable_id('monprofile', 'storage-baseline', length=8),
             'name': 'Storage baseline',
             'script_ids': ['cs_' + _stable_id('custom_script', 'Check ZFS scrub age', length=11),
                             'cs_' + _stable_id('custom_script', 'Backup repo integrity', length=11)],
             'created': now() - 86400 * 40, 'created_by': 'alice'},
        ],

        # RDP remote-access action + customer self-service portal.
        'rdp_enabled':     True,
        'portal_enabled':  True,
        'portal_base_url': 'https://demoremote.tvipper.example/portal',

        # Proxmox connector — cosmetically "configured" but DISABLED (no
        # token secret, proxmox_enabled False), so Containers/Virtualization
        # pages never make a live outbound call to the fake host even on a
        # plain GET (read-only mode only blocks mutations, not GETs — see the
        # opnsense note on the fw01 device record in build_devices()).
        'proxmox_enabled':            False,
        'proxmox_lifecycle_enabled':  False,
        'proxmox_host':               'proxmox.lab',
        'proxmox_node':               'pmx01',
        'proxmox_token_id':           'root@pam!remotepower',
        'proxmox_token_secret':       '',
        'proxmox_verify_tls':         True,
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
    # GPUs report util/memory/temp/power/fan (feeds the fleet GPU page + Thermal
    # + Power). A rich NVIDIA + AMD spread: a gaming card, a passthrough compute
    # card running HOT, an idle media-transcode card, and an AMD render card.
    gpus_map = {
        'gt01':  [{'vendor': 'nvidia', 'name': 'NVIDIA GeForce RTX 3060',
                   'util_pct': 99, 'mem_used_mb': 9900, 'mem_total_mb': 12288,
                   'temp_c': 86.0, 'power_w': 168.0, 'fan_pct': 84}],   # HOT (≥85°C)
        'pmx01': [{'vendor': 'nvidia', 'name': 'NVIDIA RTX A2000',
                   'util_pct': 88, 'mem_used_mb': 5200, 'mem_total_mb': 6144,
                   'temp_c': 78.0, 'power_w': 64.0, 'fan_pct': 70}],   # HOT
        'jf01':  [{'vendor': 'nvidia', 'name': 'NVIDIA Quadro P2000',
                   'util_pct': 12, 'mem_used_mb': 900, 'mem_total_mb': 5120,
                   'temp_c': 44.0, 'power_w': 18.0, 'fan_pct': 30}],   # transcode idle
        'pr01':  [{'vendor': 'amd', 'name': 'AMD Radeon RX 7900 XT',
                   'util_pct': 35, 'mem_used_mb': 8000, 'mem_total_mb': 20480,
                   'temp_c': 58.0, 'power_w': 120.0, 'fan_pct': 40}],
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
    # Build a record for every host with ANY hardware signal — disks, sensors,
    # GPUs or UPS — not just the disk owners (e.g. jf01/pr01 have a GPU but no
    # tracked disk). Disk owners keep their exact _seeded_random draw order so
    # build_smart_history can re-derive the same serials.
    all_ids = list(dict.fromkeys(
        list(specs) + list(temps_map) + list(gpus_map) + list(ups_map)))
    for dev_id in all_ids:
        disk_specs, reboot = specs.get(dev_id, ([], False))
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
        # lat/lng (v6.1.0 coverage fill) — required together for a site to
        # appear as a dot on the NOC map (handle_sites_map skips either-None).
        SITE_HQ:   {'name': 'HQ - Copenhagen', 'slug': slug('HQ - Copenhagen'),
                    'created': now() - 86400 * 300, 'created_by': 'demo',
                    'lat': 55.6761, 'lng': 12.5683},
        SITE_DC:   {'name': 'DC - Frankfurt',  'slug': slug('DC - Frankfurt'),
                    'created': now() - 86400 * 280, 'created_by': 'demo',
                    'lat': 50.1109, 'lng': 8.6821},
        SITE_EDGE: {'name': 'Edge - London',   'slug': slug('Edge - London'),
                    'created': now() - 86400 * 120, 'created_by': 'demo',
                    'lat': 51.5074, 'lng': -0.1278},
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


# ════════════════════════════════════════════════════════════════════════════
# Previously-unseeded subsystems (v3.x → v4.7.0) — so the demo shows EVERY
# feature populated, not just the recent ones. Each builder was schema-verified
# against the api.py handler that consumes the file (cited per-builder).
# ════════════════════════════════════════════════════════════════════════════

# ─── Homelab software integrations (v4.7.0) ─────────────────────────────────
# Single source of truth: (type, label, url, status, detail, version, metrics).
# _DEMO_INTEGRATIONS (the instances saved in config.json) and
# build_integrations_state() (last poll results in integrations_state.json) are
# both derived from it, so they stay in lockstep. status ∈ ok/warning/critical
# (integrations.OK/WARN/CRIT); metrics keys match integrations._STATS so
# format_stats() renders the rich-tile chips. A few are warning/critical so the
# dashboard roll-up, worst-first ordering, and integration_down alerts populate.
_DEMO_INTEG_DEFS = [
    ('pihole', 'Pi-hole', 'https://pihole.lab/admin', 'ok',
     'blocking 132,418 domains', '6.0.4',
     {'queries_today': 84213, 'blocked_pct': 18.7, 'domains_blocked': 132418}),
    ('adguard', 'AdGuard Home', 'https://10.0.2.12', 'ok',
     'protection enabled', '0.107.52',
     {'queries': 88210, 'blocked': 15234}),
    ('truenas', 'TrueNAS', 'https://truenas.lab', 'ok',
     '2 pools healthy', '24.04.2',
     {'pools': 2, 'pools_bad': 0, 'alerts_crit': 0}),
    ('unifi', 'UniFi Network', 'https://10.0.0.50:8443', 'ok',
     '5 subsystems ok', '8.4.59',
     {'subsystems': 5, 'subsystems_bad': 0}),
    ('homeassistant', 'Home Assistant', 'https://home-assistant.lab:8123', 'ok',
     '412 entities, 3 unavailable', '2024.6.4',
     {'entities': 412, 'unavailable': 3}),
    ('pbs', 'Proxmox Backup Server', 'https://10.0.1.30:8007', 'ok',
     '2 datastores, fullest 71%', '3.2-7',
     {'datastores': 2, 'fullest_pct': 71}),
    ('jellyfin', 'Jellyfin', 'https://jellyfin.lab:8096', 'ok',
     '2 streaming (1 transcoding)', '10.9.6',
     {'sessions_active': 2, 'transcoding': 1}),
    ('nextcloud', 'Nextcloud', 'https://nextcloud.lab', 'ok',
     '14 users — update available', '30.0.1',
     {'users': 14, 'update_available': True}),
    ('grafana', 'Grafana', 'https://prometheus.lab:3000', 'ok',
     'database ok', '11.1.0',
     {'database_ok': True}),
    ('uptimekuma', 'Uptime Kuma', 'https://status.lab', 'warning',
     '1 of 24 monitors down', '1.23.13',
     {'monitors': 24, 'down': 1}),
    ('npm', 'Nginx Proxy Manager', 'http://10.0.2.20:81', 'warning',
     '1 certificate expires within 14 days', '2.11.3',
     {'proxy_hosts': 12, 'certs_expiring': 1}),
    ('sabnzbd', 'SABnzbd', 'http://10.0.2.30:8081', 'ok',
     '3 in queue, 1.8 GB left', '4.3.2',
     {'queue': 3, 'mb_left': 1840, 'paused': False}),
    ('qbittorrent', 'qBittorrent', 'http://10.0.2.30:8080', 'critical',
     'connection refused', None, {}),
    ('sonarr', 'Sonarr', 'http://10.0.2.30:8989', 'warning',
     '1 health warning', '4.0.9',
     {'health_errors': 0, 'health_warnings': 1}),
    ('radarr', 'Radarr', 'http://10.0.2.30:7878', 'ok',
     'healthy', '5.7.0',
     {'health_errors': 0, 'health_warnings': 0}),
    ('prowlarr', 'Prowlarr', 'http://10.0.2.30:9696', 'warning',
     '2 health errors', '1.21.2',
     {'health_errors': 2, 'health_warnings': 1}),
    ('bazarr', 'Bazarr', 'http://10.0.2.30:6767', 'ok',
     'no issues', '1.4.3',
     {'health_issues': 0}),
    ('overseerr', 'Overseerr', 'https://overseerr.lab', 'ok',
     '5 pending requests', '1.33.2',
     {'pending_requests': 5, 'update_available': False}),
]

_DEMO_INTEGRATIONS = [
    {
        'id':         _stable_id('integration', typ, label),
        'type':       typ,
        'label':      label,
        'url':        url,
        'enabled':    True,
        'verify_tls': url.startswith('https://'),
        'username':   '',
        'slug':       '',
        'interval':   0,
        # Placeholder secret — auto-redacted by _scrub_config_secrets; the demo
        # is read-only so it grants nothing and never drives a real poll.
        'secret':     'demo-secret-' + _stable_id('integsecret', typ, length=20),
    }
    for (typ, label, url, status, detail, version, metrics) in _DEMO_INTEG_DEFS
]

_DEMO_INTEG_RESULTS = {
    _stable_id('integration', typ, label): (status, detail, metrics, version)
    for (typ, label, url, status, detail, version, metrics) in _DEMO_INTEG_DEFS
}


def build_integrations_state() -> dict:
    """v4.7.0 last integration poll results + short history → integrations_state.json.

    Mirrors what _persist_integration_results writes (api.py ~11968):
    {'latest': {id: result}, 'history': {id: [{ts,status,detail}]}}. Each result
    matches the _poll_one_integration shape (id/type/label/status/detail/checked/
    metrics/version) so handle_integrations_list renders the rich tile chips via
    format_stats. Derived from _DEMO_INTEG_DEFS to stay in lockstep with config."""
    latest, history = {}, {}
    for inst in _DEMO_INTEGRATIONS:
        key = inst['id']
        status, detail, metrics, version = _DEMO_INTEG_RESULTS[key]
        rng = _seeded_random('integ', key)
        checked = now() - rng.randint(20, 280)   # polled within the last ~5 min
        latest[key] = {
            'id': key, 'type': inst['type'], 'label': inst['label'],
            'status': status, 'detail': detail, 'metrics': metrics,
            'version': version, 'checked': checked,
        }
        hist = []
        for i in range(7, -1, -1):               # 8 points, oldest → newest
            ts = checked - i * 300
            st = status if i == 0 else 'ok'       # only the latest reflects a fault
            hist.append({'ts': ts, 'status': st,
                         'detail': detail if i == 0 else 'ok'})
        history[key] = hist
    return {'latest': latest, 'history': history}


# ─── SNMP poll cache (snmp_data.json) ───────────────────────────────────────
# Schema verified against _snmp_poll_device (api.py:33310) + the snmp_status
# summary the Devices/SNMP-Metrics pages read (api.py:7057). The device record's
# snmp.enabled gate is set in build_devices() (agentless branch). Only the four
# agentless network devices are SNMP-polled.
def build_snmp_data() -> dict:
    """Per-device SNMP poll cache for the agentless switches/APs.

    Keyed by device id; each value mirrors the dict _snmp_poll_device writes:
    sys-group scalars + hrProcessorTable (per-core load) + hrStorageTable
    (memory + filesystems) + vendor MIB block."""
    profiles = {
        'sw01': {'descr': 'Juniper Networks, Inc. ex3400-24t Ethernet Switch, '
                          'kernel JUNOS 21.4R3-S4.9',
                 'oid': '1.3.6.1.4.1.2636.1.1.1.2.82', 'name': 'switch-core',
                 'location': 'HQ Copenhagen / rack A',
                 'mem_total_mb': 2048, 'fs': [('/var', 4096, 38)]},
        'sw02': {'descr': 'USW-Pro-24-PoE, 6.6.55.14934, Linux 3.6.5',
                 'oid': '1.3.6.1.4.1.41112.1.6', 'name': 'switch-rack',
                 'location': 'DC Frankfurt / rack 4',
                 'mem_total_mb': 512, 'fs': [('/persist', 256, 22)]},
        'ap01': {'descr': 'U6-Pro, 6.6.55.14934, Linux 4.4.153',
                 'oid': '1.3.6.1.4.1.41112.1.6', 'name': 'ap-living',
                 'location': 'HQ Copenhagen / living',
                 'mem_total_mb': 512, 'fs': [('/tmp', 128, 31)]},
        'ap02': {'descr': 'U6-Lite, 6.6.55.14934, Linux 4.4.153',
                 'oid': '1.3.6.1.4.1.41112.1.6', 'name': 'ap-office',
                 'location': 'HQ Copenhagen / office',
                 'mem_total_mb': 256, 'fs': [('/tmp', 64, 19)]},
    }
    out = {}
    for dev_id, p in profiles.items():
        rng = _seeded_random('snmp', dev_id)
        uptime_s = rng.randint(86400 * 5, 86400 * 240)
        cores = rng.choice([1, 2, 4])
        processors = [{'index': i + 1, 'load_pct': rng.randint(2, 47)}
                      for i in range(cores)]
        mem_total_kb = p['mem_total_mb'] * 1024
        mem_pct = rng.randint(28, 71)
        mem_used_kb = int(mem_total_kb * mem_pct / 100)
        storage = [{'index': 1, 'descr': 'Physical memory',
                    'size_bytes': mem_total_kb * 1024,
                    'used_bytes': mem_used_kb * 1024, 'used_pct': mem_pct}]
        for fi, (mount, size_mb, used_pct) in enumerate(p['fs'], start=2):
            size_bytes = size_mb * 1024 * 1024
            storage.append({'index': fi, 'descr': mount, 'size_bytes': size_bytes,
                            'used_bytes': int(size_bytes * used_pct / 100),
                            'used_pct': used_pct})
        out[dev_id] = {
            'host': next(d['ip'] for d in FAKE_DEVICES if d['id'] == dev_id),
            'port': 161, 'last_ok': now() - rng.randint(20, 280),
            'last_error': None, 'consecutive_fails': 0,
            'sysDescr': p['descr'], 'sysObjectID': p['oid'],
            'sysUpTime': uptime_s * 100, 'sysContact': 'netops@demo.lab',
            'sysName': p['name'], 'sysLocation': p['location'],
            'processors': processors, 'storage': storage,
            'vendor': {}, 'synology': {},
        }
    return out


def build_speedtest() -> dict:
    """Recent speed-test results for the WAN-facing hosts → speedtest.json.

    Schema verified against _ingest_speedtest (api.py:22587): keyed by dev_id →
    list of {ts, download_mbps, upload_mbps, ping_ms, jitter_ms, server, ok}.
    Newest entry last (the device-drawer Diagnostics card reads the tail)."""
    out = {}
    servers = ['Telia (Copenhagen)', 'init7 (Zurich)', 'Hetzner (Falkenstein)']
    for dev_id in ('fw01', 'ng01'):
        rng = _seeded_random('speedtest', dev_id)
        hist = []
        n = rng.randint(4, 9)
        for i in range(n):
            age_s = (n - 1 - i) * 86400 + rng.randint(60, 3600)
            down = round(rng.uniform(180, 940), 2)
            hist.append({'ts': now() - age_s, 'download_mbps': down,
                         'upload_mbps': round(down * rng.uniform(0.08, 0.55), 2),
                         'ping_ms': round(rng.uniform(3, 28), 2),
                         'jitter_ms': round(rng.uniform(0.3, 4.5), 2),
                         'server': rng.choice(servers), 'ok': True})
        out[dev_id] = hist
    return out


def build_discovery() -> dict:
    """LAN-scan results from the scanning hosts → discovery.json.

    Schema verified against _ingest_netscan (api.py:22607) + handle_discovery
    (api.py:21103): keyed by dev_id → {ts, method, hosts:[{ip, mac, hostname,
    managed}]}. `managed` is precomputed here the way the server does at ingest
    (cross-referencing enrolled IPs) so the unmanaged-hosts rollup is non-empty."""
    known_ips = {d['ip'] for d in FAKE_DEVICES}
    unmanaged_pool = [
        ('10.0.3.21', '02:00:5e:00:03:21', 'hp-laserjet'),
        ('10.0.3.40', '02:00:5e:00:03:40', 'esp-thermostat'),
        ('10.0.3.41', '02:00:5e:00:03:41', 'esp-garage'),
        ('10.0.3.55', '02:00:5e:00:03:55', 'android-pixel'),
        ('10.0.3.70', '02:00:5e:00:03:70', 'shelly-plug'),
        ('10.0.3.88', '02:00:5e:00:03:88', 'roku-livingroom'),
        ('10.0.3.99', '02:00:5e:00:03:99', ''),
        ('10.0.2.110', '02:00:5e:00:02:aa', 'unifi-doorbell'),
    ]
    out = {}
    for dev_id, method in (('fw01', 'arp'), ('pi1', 'nmap-sweep')):
        rng = _seeded_random('discovery', dev_id)
        hosts = []
        for d in FAKE_DEVICES:
            if d['id'] == dev_id:
                continue
            if rng.random() < 0.8:
                hosts.append({'ip': d['ip'], 'mac': d['mac'],
                              'hostname': d['name'], 'managed': True})
        for ip, mac, hostname in rng.sample(unmanaged_pool,
                                             k=rng.randint(3, len(unmanaged_pool))):
            hosts.append({'ip': ip, 'mac': mac, 'hostname': hostname,
                          'managed': ip in known_ips})
        out[dev_id] = {'ts': now() - rng.randint(300, 86400),
                       'method': method, 'hosts': hosts}
    return out


def build_tunnels() -> dict:
    """VPN-style peer tunnels between devices → tunnels.json (Network Map edges).

    Schema verified against handle_tunnels_list/add (api.py:18819) +
    handle_network_map (api.py:18737): {'tun_<hex>': {endpoints:[id_a,id_b]
    (sorted), created_at, created_by}}. Both endpoints reference real devices."""
    pairs = [('fw01', 'pmx01'), ('fw01', 'ng01'), ('ng01', 'nc01')]
    out = {}
    for a, b in pairs:
        endpoints = sorted([a, b])
        tid = 'tun_' + _stable_hex('tunnel', endpoints[0], endpoints[1], nbytes=6)
        out[tid] = {'endpoints': endpoints,
                    'created_at': now() - 86400 * 30, 'created_by': 'alice'}
    return out


def build_satellites() -> dict:
    """Relay satellites → satellites.json (Settings → Satellites + Scans picker).

    Schema verified against handle_satellites_create/list (api.py:27158/27133):
    {sid: {name, token_hash (sha256 hex of the token), created, last_seen,
    last_ip, scanner}}. One plain relay + one scanner-enabled (the Scans page
    targets scanner:true satellites)."""
    out = {}
    defs = [('hq-relay', 'hq-relay', False, 95, '10.0.0.50'),
            ('dc-scanner', 'dc-scanner', True, 240, '10.0.1.99')]
    for key, name, scanner, age, last_ip in defs:
        sid = _stable_hex('satellite', key, nbytes=8)
        token = _stable_id('satellite-token', key, length=32)
        out[sid] = {'name': name,
                    'token_hash': hashlib.sha256(token.encode('utf-8')).hexdigest(),
                    'created': now() - 86400 * 60, 'last_seen': now() - age,
                    'last_ip': last_ip, 'scanner': scanner}
    return out


# ─── Security / scan / compliance content ───────────────────────────────────
def build_secret_findings() -> dict:
    """Exposed-secrets findings (redacted, per device) → secret_findings.json.

    Schema verified against _ingest_secret_findings (api.py:17079) + the
    /fleet/secrets reader (api.py:35734): {dev_id: {findings:[{fingerprint,rule,
    path,preview,muted,line}], ts, _seen}}. Values are never stored — only a
    masked preview. Needs config secrets_scan_enabled=True (set in build_config)."""
    catalog = {
        'ng01': [('aws-access-key-id', '/etc/nginx/.env',
                  'AWS_ACCESS_KEY_ID=AKIA****************'),
                 ('generic-api-key', '/opt/app/config/prod.yml',
                  'api_key: "sk_live_****************"')],
        'nc01': [('mysql-uri', '/var/www/nextcloud/config/config.php',
                  "'dbpassword' => '****************'"),
                 ('private-key', '/home/deploy/.ssh/id_rsa',
                  '-----BEGIN RSA PRIVATE KEY----- ****')],
        'gt01': [('github-pat', '/home/git/.netrc',
                  'password ghp_********************************')],
        'jf01': [('generic-secret', '/etc/jellyfin/network.xml',
                  '<ApiKey>****************</ApiKey>')],
        'vw01': [('admin-token', '/opt/vaultwarden/.env',
                  'ADMIN_TOKEN=****************')],
    }
    out = {}
    for dev_id, rows in catalog.items():
        if not any(d['id'] == dev_id for d in FAKE_DEVICES):
            continue
        rng = _seeded_random('secrets', dev_id)
        findings = []
        for rule, path, preview in rows:
            findings.append({
                'fingerprint': _stable_hex('secret', dev_id, rule, path, nbytes=12),
                'rule': rule, 'path': path, 'preview': preview,
                'muted': (dev_id == 'vw01'), 'line': rng.randint(3, 240)})
        out[dev_id] = {'findings': findings,
                       'ts': now() - rng.randint(1800, 6 * 3600),
                       '_seen': sorted(f['fingerprint'] for f in findings)}
    return out


def build_after_hours_hits() -> dict:
    """Off-hours access-watch events (rolling 24h) → after_hours_hits.json.

    Schema verified against _record_after_hours (api.py:4800) + the NA reader
    (api.py:24497): {'hits': [{ts, event, device}]} where `device` is the host
    NAME. Events match the after_hours.events config in build_config."""
    rng = _seeded_random('after_hours', 'fleet')
    seeds = [('fw01', 'recent_login'), ('pmx01', 'recent_login'),
             ('nc01', 'new_port_detected'), ('gt01', 'command_run'),
             ('ng01', 'recent_login'), ('pmx01', 'command_run')]
    name_of = {d['id']: d['name'] for d in FAKE_DEVICES}
    hits = []
    for dev_id, event in seeds:
        ts = now() - rng.randint(1, 22) * 3600 - rng.randint(0, 3000)
        hits.append({'ts': ts, 'event': event, 'device': name_of.get(dev_id, dev_id)})
    hits.sort(key=lambda h: h['ts'])
    return {'hits': hits[-500:]}


def build_scan_targets() -> dict:
    """Ownership-verified non-enrolled scan targets → scan_targets.json.

    Schema verified against the scan-target record + _scan_target_public
    (api.py:27796/27760): {id: {id,target,kind,token,verified,verified_at,
    method,created,actor}}."""
    rows = [('status.lab', 'domain', True, 'dns'),
            ('203.0.113.7', 'ip', True, 'file'),
            ('legacy.lab', 'domain', False, '')]
    out = {}
    for target, kind, verified, method in rows:
        tid = _stable_hex('scan_target', target)
        created = now() - _seeded_random('scan_target', target).randint(3, 40) * 86400
        out[tid] = {'id': tid, 'target': target, 'kind': kind,
                    'token': 'rpscan-' + _stable_id('scan_token', target, length=32),
                    'verified': verified,
                    'verified_at': (created + 3600) if verified else None,
                    'method': method, 'created': created, 'actor': 'alice'}
    return out


def build_scans() -> dict:
    """Authorized vulnerability scans + findings → scans.json.

    Schema verified against the scan record + _scan_public + _scan_sev_counts
    (api.py:27460/27252/27244): {id: {target_device_id,target_name,target,tool,
    profile,intensity,status,runner,satellite_id,created,actor,claimed_by,
    claimed_at,finished_at,findings,error,...}}. Findings carry `severity`."""
    plan = [
        ('ng01', 'nuclei', 'passive', 'quick', 'done',
         [('high', 'tls-version: TLS 1.0 enabled', 'https://10.0.2.20:443'),
          ('medium', 'missing-security-headers: CSP absent', 'https://10.0.2.20/'),
          ('low', 'http-missing-hsts', 'https://10.0.2.20/'),
          ('info', 'http-trace-method', 'https://10.0.2.20/')]),
        ('nc01', 'nikto', 'passive', 'full', 'done',
         [('medium', 'OSVDB-3092: /backup/ may reveal sensitive info',
           'http://10.0.2.60/backup/'),
          ('low', 'X-Frame-Options header not present', 'http://10.0.2.60/')]),
        ('jf01', 'nmap', 'passive', 'quick', 'done',
         [('info', '8096/tcp open  http  Jellyfin', '10.0.2.30:8096'),
          ('info', '22/tcp open  ssh', '10.0.2.30:22')]),
        ('fw01', 'nuclei', 'active', 'full', 'running', []),
        ('gt01', 'nikto', 'passive', 'quick', 'queued', []),
        ('pmx01', 'nuclei', 'passive', 'quick', 'failed', []),
    ]
    name_of = {d['id']: d['name'] for d in FAKE_DEVICES}
    out = {}
    for dev_id, tool, profile, intensity, status, finds in plan:
        sid = _stable_hex('scan', dev_id, tool, profile)
        rng = _seeded_random('scan', sid)
        created = now() - rng.randint(1, 9) * 86400 - rng.randint(0, 3600)
        terminal = status in ('done', 'failed')
        running = status == 'running'
        findings = [{'severity': sev, 'name': nm, 'matched-at': where,
                     'template-id': nm.split(':')[0].strip().lower().replace(' ', '-')}
                    for sev, nm, where in finds]
        out[sid] = {
            'id': sid, 'target_device_id': dev_id,
            'target_name': name_of.get(dev_id, dev_id),
            'target': next((d['ip'] for d in FAKE_DEVICES if d['id'] == dev_id), dev_id),
            'tool': tool, 'profile': profile, 'intensity': intensity,
            'status': status, 'runner': 'satellite', 'satellite_id': '',
            'created': created, 'actor': 'alice',
            'claimed_by': ('dc-scanner' if (terminal or running) else None),
            'claimed_at': (created + 30) if (terminal or running) else None,
            'finished_at': (created + rng.randint(60, 1800)) if terminal else None,
            'findings': findings,
            'error': ('scanner unreachable (demo)' if status == 'failed' else ''),
            'attested': (profile == 'active'), 'window_overridden': False,
        }
    return out


def build_compliance_history() -> dict:
    """CIS/compliance fleet-% daily samples → compliance_history.json.

    Schema verified against _maybe_sample_compliance + handle_compliance_baseline
    (api.py:29415/29394): {'fleet': [{date, ts, score}]}. ~90 daily points
    trending gently upward to today."""
    rng = _seeded_random('compliance_history', 'fleet')
    fleet = []
    base = 71.0
    for d in range(-89, 1):
        ts = now() + d * 86400
        base += rng.uniform(-0.6, 0.9)
        fleet.append({'date': _iso_in_days(d), 'ts': ts,
                      'score': round(max(60.0, min(96.0, base)), 1)})
    return {'fleet': fleet[-180:]}


def build_apikeys() -> dict:
    """API keys → apikeys.json (Settings → API Keys). FAKE placeholder tokens —
    the demo is public + read-only, so they grant nothing real.

    Schema verified against handle_apikeys_create/list (api.py:28198/28154):
    {id: {name,key,user,role,created,active,expires_at}}."""
    rows = [('CI deploy pipeline', 'ci-bot', 'admin', 365, True),
            ('Grafana read-only', 'grafana', 'viewer', None, True),
            ('Claude MCP host', 'mcp', 'mcp', 90, True),
            ('Old laptop (rotate me)', 'jmo', 'admin', -5, True)]
    out = {}
    for name, user, role, exp_days, active in rows:
        kid = _stable_hex('apikey', name, nbytes=8)
        created = now() - _seeded_random('apikey', name).randint(20, 300) * 86400
        out[kid] = {'name': name,
                    'key': 'rpk_demo_' + _stable_id('apikey_value', name, length=40),
                    'user': user, 'role': role, 'created': created,
                    'active': active,
                    'expires_at': (now() + exp_days * 86400) if exp_days is not None else None}
    return out


# ─── Service monitoring / images / stacks / custom scripts / SMART trend ─────
def build_services() -> dict:
    """Current systemd service state per device → services.json.

    Schema verified against handle_services_get + _sanitize_service_entry
    (api.py ~38434/37546): {dev_id: {updated_at, services:[{unit,active,sub,
    since}]}}. Reuses build_device_services' tag map so the watched list and the
    failing jellyfin unit stay consistent."""
    out = {}
    for dev in FAKE_DEVICES:
        if dev['agentless']:
            continue
        rng = _seeded_random('svc', dev['id'])
        unit_states = build_device_services(dev, rng)
        services = []
        for unit, active in sorted(unit_states.items()):
            if active == 'failed':
                sub = 'failed'
            elif unit.endswith('.timer'):
                sub = 'waiting'
            else:
                sub = 'running'
            services.append({'unit': unit, 'active': active, 'sub': sub,
                             'since': now() - rng.randint(3600, 86400 * 21)})
        out[dev['id']] = {'updated_at': now() - rng.randint(20, 240),
                          'services': services}
    return out


def build_service_history() -> dict:
    """Service state transitions per (device,unit) → service_history.json.

    Schema verified against _record_service_transition (api.py ~37569): keyed
    'dev_id:unit' → [{ts, from, to}] (last 100). Seeds a flap history only for
    units build_services left 'failed' so the drawer sparkline has content."""
    out = {}
    for dev_id, entry in build_services().items():
        for s in entry['services']:
            if s['active'] != 'failed':
                continue
            key = f"{dev_id}:{s['unit']}"
            base = now() - 86400 * 4
            out[key] = [
                {'ts': base, 'from': 'active', 'to': 'failed'},
                {'ts': base + 3600, 'from': 'failed', 'to': 'active'},
                {'ts': s['since'] - 60, 'from': 'active', 'to': 'failed'},
            ]
    return out


def build_image_updates() -> dict:
    """Registry-digest cache for container images → image_updates.json.

    Schema verified against _scan_images/_image_update_view (api.py:33520/33667):
    {'images': {ref: {registry, registry_digest, last_checked, last_error}},
    'last_full_scan': ts}. Refs are taken from build_containers' catalogue."""
    refs = ['nginx:1.27', 'jellyfin/jellyfin:latest', 'gitea/gitea:1.22',
            'postgres:16', 'nextcloud:30-apache', 'mariadb:11', 'redis:7',
            'vaultwarden/server:latest', 'homeassistant/home-assistant:stable',
            'eclipse-mosquitto:2', 'zwavejs/zwave-js-ui:latest',
            'pihole/pihole:latest', 'prom/prometheus:latest',
            'grafana/grafana:latest', 'prom/node-exporter:latest']
    images = {}
    for ref in refs:
        rng = _seeded_random('imgupd', ref)
        images[ref] = {'registry': 'registry-1.docker.io',
                       'registry_digest': 'sha256:' + _stable_hex('imgdig', ref, nbytes=32),
                       'last_checked': now() - rng.randint(1800, 86400),
                       'last_error': ''}
    images['jellyfin/jellyfin:latest']['registry_digest'] = ''
    images['jellyfin/jellyfin:latest']['last_error'] = 'HTTPError: 429 Too Many Requests'
    return {'images': images, 'last_full_scan': now() - 3600}


def build_compose_stacks() -> dict:
    """docker-compose stack definitions → compose_stacks.json.

    Schema verified against handle_compose_stacks_list/get/create (api.py:33858):
    {s-<hex>: {name, device_id, yaml, status, created_by, created_ts,
    last_action, last_action_ts, last_rc, last_output}}."""
    plan = [
        ('nc01', 'nextcloud',
         "services:\n  app:\n    image: nextcloud:30-apache\n"
         "    ports:\n      - 8080:80\n  db:\n    image: mariadb:11\n"),
        ('ha01', 'home-assistant',
         "services:\n  homeassistant:\n    image: homeassistant/home-assistant:stable\n"
         "    network_mode: host\n  mqtt:\n    image: eclipse-mosquitto:2\n"),
        ('pr01', 'monitoring',
         "services:\n  prometheus:\n    image: prom/prometheus:latest\n"
         "  grafana:\n    image: grafana/grafana:latest\n    ports:\n      - 3000:3000\n"),
        ('vw01', 'vaultwarden',
         "services:\n  vaultwarden:\n    image: vaultwarden/server:latest\n"
         "    ports:\n      - 8000:80\n"),
    ]
    out = {}
    for dev_id, name, yaml in plan:
        rng = _seeded_random('compose', dev_id, name)
        sid = 's-' + _stable_hex('compose', dev_id, name)
        last_act_ts = now() - rng.randint(3600, 86400 * 14)
        out[sid] = {'name': name, 'device_id': dev_id, 'yaml': yaml,
                    'status': 'running', 'created_by': 'alice',
                    'created_ts': last_act_ts - rng.randint(86400, 86400 * 60),
                    'last_action': rng.choice(['up', 'redeploy']),
                    'last_action_ts': last_act_ts, 'last_rc': 0,
                    'last_output': 'Container started\nContainer started\n'}
    return out


def build_helm() -> dict:
    """Helm releases per device → helm.json.

    Schema verified against handle_device_helm + _ingest_helm (api.py:21211/22566):
    {dev_id: {releases:[{name,namespace,revision,status,chart,app_version,
    updated}], ts}}. Seeded on pmx01 (stands in for a small k3s host)."""
    rels = [
        {'name': 'traefik', 'namespace': 'kube-system', 'revision': '3',
         'status': 'deployed', 'chart': 'traefik-28.3.0', 'app_version': '3.0.4'},
        {'name': 'cert-manager', 'namespace': 'cert-manager', 'revision': '2',
         'status': 'deployed', 'chart': 'cert-manager-v1.15.1', 'app_version': '1.15.1'},
        {'name': 'prometheus', 'namespace': 'monitoring', 'revision': '5',
         'status': 'deployed', 'chart': 'kube-prometheus-stack-61.3.0',
         'app_version': '0.75.1'},
    ]
    for i, r in enumerate(rels):
        r['updated'] = _iso_in_days(-(7 + i * 9)) + ' 14:0%d:11 +0000 UTC' % i
    return {'pmx01': {'releases': rels, 'ts': now() - 1800}}


def build_gitops_state() -> dict:
    """Last GitOps reconcile status → gitops_state.json.

    Schema verified against handle_gitops_get + _gitops_sync (api.py:37091/37039):
    {last_sync, last_attempt, last_status, last_error, last_summary:{added,
    updated, removed, assignments, skipped, dry}}."""
    ts = now() - 540
    return {'last_sync': ts, 'last_attempt': ts, 'last_status': 'ok',
            'last_error': '',
            'last_summary': {'added': 2, 'updated': 1, 'removed': 0,
                             'assignments': 3, 'skipped': [], 'dry': False}}


def build_custom_scripts() -> dict:
    """Custom-script DEFINITIONS → custom_scripts.json (distinct from scripts.json).

    Schema verified against handle_custom_scripts_list/get/create (api.py:23056):
    {cs_<id>: {id,name,description,body,assigned_devices,timeout,created_at,
    updated_at,created_by}}."""
    plan = [
        ('Check ZFS scrub age',
         'Warn if the last completed scrub on tank is older than 35 days.',
         "#!/bin/sh\nlast=$(zpool status tank | grep -oE 'scrub repaired.*')\n"
         "echo \"$last\"\n[ -n \"$last\" ] || exit 1\n",
         ['tnas', 'bk01']),
        ('Certificate expiry (local)',
         'Fail when any cert under /etc/ssl/private expires within 14 days.',
         "#!/bin/sh\nfor c in /etc/ssl/private/*.pem; do\n"
         "  openssl x509 -checkend 1209600 -noout -in \"$c\" || exit 1\ndone\n",
         ['ng01', 'nc01']),
        ('Docker disk pressure',
         'Alert if /var/lib/docker is over 85% full.',
         "#!/bin/sh\nuse=$(df --output=pcent /var/lib/docker | tail -1 | tr -dc 0-9)\n"
         "echo \"docker fs at ${use}%\"\n[ \"$use\" -lt 85 ]\n",
         ['jf01', 'nc01', 'ha01', 'vw01', 'gt01']),
        ('Backup repo integrity',
         'Run a quick restic snapshot count sanity check.',
         "#!/bin/sh\nn=$(restic snapshots --json 2>/dev/null | grep -c '\"time\"')\n"
         "echo \"$n snapshots\"\n[ \"$n\" -gt 0 ]\n",
         ['bk01']),
    ]
    out = {}
    for i, (name, desc, body, assigned) in enumerate(plan):
        sid = 'cs_' + _stable_id('custom_script', name, length=11)
        created = now() - 86400 * (40 - i * 7)
        out[sid] = {'id': sid, 'name': name, 'description': desc, 'body': body,
                    'assigned_devices': assigned, 'timeout': 30,
                    'created_at': created, 'updated_at': created + 86400,
                    'created_by': 'alice' if i % 2 == 0 else 'bob'}
    return out


def build_smart_history() -> dict:
    """Per-disk SMART attribute trend history → smart_history.json.

    Schema verified against _maybe_sample_smart/_disk_key/_disk_health_view
    (api.py:22723/22717/22772): {dev_id: {serial: {device, model, samples:[{date,
    ts, realloc, pending, wear, temp}]}}}. disk_key is the SERIAL — re-derived by
    replaying build_hardware's _seeded_random('hardware', dev_id) draw order
    (serial → pending → temp → power_on_hours), so it MUST stay in lockstep with
    build_hardware. tnas /dev/sdc shows growing reallocated sectors → a high-risk
    predictive row; the rest trend flat."""
    import datetime as _dt
    _UTC = _dt.timezone.utc
    DAY = 86400
    specs = {
        'tnas':  [('/dev/sda', 'PASSED', 'WDC WD40EFRX', 0),
                  ('/dev/sdb', 'PASSED', 'WDC WD40EFRX', 0),
                  ('/dev/sdc', 'FAILED', 'WDC WD40EFRX', 24),
                  ('/dev/sdd', 'PASSED', 'WDC WD40EFRX', 0)],
        'pmx01': [('/dev/nvme0n1', 'PASSED', 'Samsung SSD 980 1TB', 0)],
        'nc01':  [('/dev/sda', 'PASSED', 'Crucial MX500', 0)],
        'bk01':  [('/dev/sda', 'PASSED', 'Seagate IronWolf', 0),
                  ('/dev/sdb', 'PASSED', 'Seagate IronWolf', 0)],
        'gt01':  [('/dev/sda', 'PASSED', 'Samsung SSD 870', 0)],
    }
    n = 30
    out = {}
    for dev_id, disk_specs in specs.items():
        hw_rng = _seeded_random('hardware', dev_id)
        rec = {}
        for device, health, model, realloc in disk_specs:
            serial = f"S{hw_rng.randint(10**9, 10**10 - 1)}"   # draw 1
            pending0 = hw_rng.randint(1, 4) if realloc else 0  # draw 2 (only if realloc)
            hw_rng.randint(30, 44)                             # draw 3: temp (consume)
            hw_rng.randint(8000, 41000)                        # draw 4: power_on_hours
            srng = _seeded_random('smarthist', dev_id, serial)
            samples = []
            for i in range(n):
                ts = now() - (n - 1 - i) * DAY
                day = _dt.datetime.fromtimestamp(ts, _UTC).strftime('%Y-%m-%d')
                if realloc:
                    samples.append({'date': day, 'ts': ts,
                                    'realloc': realloc + int(round((i / (n - 1)) * 14)),
                                    'pending': pending0 + (1 if i > n // 2 else 0),
                                    'wear': None, 'temp': srng.randint(36, 44)})
                else:
                    samples.append({'date': day, 'ts': ts, 'realloc': 0,
                                    'pending': 0, 'wear': None,
                                    'temp': srng.randint(30, 40)})
            rec[serial] = {'device': device, 'model': model, 'samples': samples}
        out[dev_id] = rec
    return out


# ─── Runbooks / automation / maintenance / inbound webhooks / misc ──────────
def build_runbooks() -> dict:
    """AI-generated per-device runbooks → runbooks.json (Runbook drawer tab).

    Schema verified against handle_runbook_get/generate (api.py ~21742/21831):
    {dev_id: {content, generated_at, generated_by, model, tokens_in, tokens_out,
    elapsed_ms}}. Seeded on the critical-infra hosts."""
    bodies = {
        'pmx01': ("# Runbook — proxmox.lab\n\n## Overview\n"
                  "Primary Proxmox VE hypervisor (Debian 12), group `infra`, tags "
                  "`hypervisor`, `critical`. Hosts the lab's VMs and LXC containers.\n\n"
                  "## Health checks\n- `systemctl status pve-cluster pvedaemon pveproxy`\n"
                  "- `pvecm status` — quorum + node membership\n- `zpool status -x`\n\n"
                  "## Common incidents\n1. **pveproxy 8006 unreachable** — "
                  "`systemctl restart pveproxy`; check `journalctl -u pveproxy -n 50`.\n"
                  "2. **High load** — find the noisy guest with `qm list` / `pct list`.\n\n"
                  "## Escalation\nTagged `critical` — page on-call before rebooting; "
                  "live-migrate or shut down guests cleanly first."),
        'tnas': ("# Runbook — truenas.lab\n\n## Overview\n"
                 "Storage / NAS host (Debian 12), tags `nas`, `critical`, `backup`. "
                 "Serves the `tank` ZFS pool over NFS/SMB.\n\n## Health checks\n"
                 "- `zpool status tank` — pool state + last scrub\n"
                 "- `zfs list -o name,used,avail tank`\n- `smartctl -H /dev/sdX`\n\n"
                 "## Common incidents\n1. **Pool DEGRADED** — `zpool status -v tank` to "
                 "find the faulted vdev; `zpool replace` and resilver.\n"
                 "2. **Scrub overdue** — `zpool scrub tank`.\n\n## Escalation\n"
                 "Holds fleet backups — never offline the pool without a confirmed "
                 "second copy on backup.lab."),
        'fw01': ("# Runbook — opnsense.lab\n\n## Overview\n"
                 "Edge firewall (Debian 12), tags `firewall`, `critical`. Default "
                 "gateway 10.0.0.254.\n\n## Health checks\n- `ping 10.0.0.254` from "
                 "inside\n- `nft list ruleset | head`\n- WAN up + DNS resolving\n\n"
                 "## Common incidents\n1. **gateway_unreachable** — confirm the box is "
                 "up before assuming a WAN outage.\n2. **firewall_changed drift** — "
                 "review the rule diff in the drawer; revert unexpected changes.\n\n"
                 "## Escalation\nLoss of this host isolates the lab — any reboot is a "
                 "change-window event."),
    }
    out = {}
    for i, (dev_id, content) in enumerate(bodies.items()):
        rng = _seeded_random('runbook', dev_id)
        out[dev_id] = {'content': content,
                       'generated_at': now() - 86400 * (3 + i) - rng.randint(0, 7200),
                       'generated_by': rng.choice(['alice', 'bob']),
                       'model': 'claude-opus-4-8',
                       'tokens_in': rng.randint(1800, 3200),
                       'tokens_out': rng.randint(600, 1100),
                       'elapsed_ms': rng.randint(9000, 42000)}
    return out


def build_automation_rules() -> dict:
    """Event→action automation rules → automation_rules.json (Automation page).

    Schema verified against handle_automation_rules_list + _validate_rule
    (api.py:4981/4943): {'rules': [...]}. Events are real WEBHOOK_EVENTS;
    run_script.script_id references scripts.json ids; notify.dest_id references
    config.json webhook_urls[].id — all seeded elsewhere here."""
    base = now() - 86400 * 25
    return {'rules': [
        {'id': 'r-' + _stable_hex('autorule', 'svc-restart'),
         'name': 'Restart nginx when it goes down', 'enabled': True,
         'match': {'events': ['service_down'], 'severities': ['high', 'critical'],
                   'device_match': {'device_id': '', 'group': '', 'tags': ['web']}},
         'actions': [{'type': 'run_script', 'script_id': 'demo-rotate-nginx-logs'}],
         'cooldown_seconds': 300, 'created': base, 'actor': 'alice',
         'last_fired': now() - 86400 * 2, 'fire_count': 3},
        {'id': 'r-' + _stable_hex('autorule', 'crit-notify'),
         'name': 'Page ops on any critical metric', 'enabled': True,
         'match': {'events': ['metric_critical', 'device_offline'],
                   'severities': ['critical'],
                   'device_match': {'device_id': '', 'group': 'infra', 'tags': []}},
         'actions': [{'type': 'notify', 'dest_id': 'wh_pushover_demo'}],
         'cooldown_seconds': 120, 'created': base + 86400 * 4, 'actor': 'bob',
         'last_fired': now() - 3600 * 9, 'fire_count': 11},
        {'id': 'r-' + _stable_hex('autorule', 'storage-notify'),
         'name': 'Notify on storage degradation', 'enabled': True,
         'match': {'events': ['storage_degraded', 'scrub_overdue', 'smart_failure'],
                   'severities': [],
                   'device_match': {'device_id': '', 'group': '',
                                    'tags': ['storage', 'nas']}},
         'actions': [{'type': 'notify', 'dest_id': 'wh_discord_demo'}],
         'cooldown_seconds': 600, 'created': base + 86400 * 9, 'actor': 'alice',
         'last_fired': 0, 'fire_count': 0},
        {'id': 'r-' + _stable_hex('autorule', 'cert-prune-disabled'),
         'name': 'Prune ZFS snapshots when disk fills', 'enabled': False,
         'match': {'events': ['metric_warning'], 'severities': ['medium', 'high'],
                   'device_match': {'device_id': 'tnas', 'group': '', 'tags': []}},
         'actions': [{'type': 'run_script', 'script_id': 'demo-zfs-snapshot-prune'}],
         'cooldown_seconds': 1800, 'created': base + 86400 * 12, 'actor': 'bob',
         'last_fired': 0, 'fire_count': 0},
    ]}


def build_maintenance() -> dict:
    """Maintenance / change windows → maintenance.json.

    Schema verified against handle_maintenance_list/add (api.py:37337/37363):
    {'windows': [{id, reason, scope, target, start, end, cron, duration, events,
    gate_exec, created_by, created_at}]}. `active`/`target_name` are reader-added.
    events ⊆ SUPPRESSIBLE_EVENTS."""
    base = now() - 86400 * 20
    return {'windows': [
        {'id': _stable_hex('maint', 'nightly-storage', nbytes=8),
         'reason': 'Nightly backup window — suppress storage churn',
         'scope': 'group', 'target': 'storage', 'start': '', 'end': '',
         'cron': '0 2 * * *', 'duration': 7200,
         'events': ['service_down', 'service_up', 'cve_found'],
         'gate_exec': False, 'created_by': 'alice', 'created_at': base},
        {'id': _stable_hex('maint', 'pmx-upgrade', nbytes=8),
         'reason': 'Proxmox kernel upgrade + reboot', 'scope': 'device',
         'target': 'pmx01', 'start': _iso_in_days(3) + 'T01:00:00Z',
         'end': _iso_in_days(3) + 'T03:00:00Z', 'cron': '', 'duration': 0,
         'events': ['device_offline', 'device_online', 'monitor_down', 'monitor_up'],
         'gate_exec': False, 'created_by': 'bob', 'created_at': base + 86400 * 6},
        {'id': _stable_hex('maint', 'fw-change', nbytes=8),
         'reason': 'Firewall change window (exec gated)', 'scope': 'device',
         'target': 'fw01', 'start': '', 'end': '', 'cron': '0 3 * * 0',
         'duration': 3600, 'events': [], 'gate_exec': True,
         'created_by': 'alice', 'created_at': base + 86400 * 11},
    ]}


def build_inbound_webhooks() -> dict:
    """Inbound webhook / syslog receiver tokens → inbound_webhooks.json.

    Schema verified against handle_inbound_webhooks_list/create (api.py:32084):
    {'tokens': [{id, label, token (rpwi_…), kind, scope_device_id, scope_tag,
    enabled, created_by, created_at, last_seen, hit_count}]}. The list handler
    strips `token` and emits token_preview. syslog kind MUST set scope_device_id."""
    base = now() - 86400 * 18
    return {'tokens': [
        {'id': 'iwh_' + _stable_hex('inwh', 'grafana', nbytes=4),
         'label': 'Grafana Alertmanager',
         'token': 'rpwi_' + _stable_hex('intok', 'grafana', nbytes=18),
         'kind': 'alert', 'scope_device_id': None, 'scope_tag': None,
         'enabled': True, 'created_by': 'alice', 'created_at': base,
         'last_seen': now() - 3600 * 5, 'hit_count': 42},
        {'id': 'iwh_' + _stable_hex('inwh', 'uptimekuma', nbytes=4),
         'label': 'Uptime Kuma',
         'token': 'rpwi_' + _stable_hex('intok', 'uptimekuma', nbytes=18),
         'kind': 'alert', 'scope_tag': 'web', 'scope_device_id': None,
         'enabled': True, 'created_by': 'bob', 'created_at': base + 86400 * 5,
         'last_seen': now() - 86400 * 2, 'hit_count': 7},
        {'id': 'iwh_' + _stable_hex('inwh', 'syslog-fw', nbytes=4),
         'label': 'opnsense syslog',
         'token': 'rpwi_' + _stable_hex('intok', 'syslog-fw', nbytes=18),
         'kind': 'syslog', 'scope_device_id': 'fw01', 'scope_tag': None,
         'enabled': True, 'created_by': 'alice', 'created_at': base + 86400 * 8,
         'last_seen': now() - 1800, 'hit_count': 318},
        {'id': 'iwh_' + _stable_hex('inwh', 'old-disabled', nbytes=4),
         'label': 'Old Prometheus (disabled)',
         'token': 'rpwi_' + _stable_hex('intok', 'old-disabled', nbytes=18),
         'kind': 'alert', 'scope_device_id': None, 'scope_tag': None,
         'enabled': False, 'created_by': 'bob', 'created_at': base - 86400 * 30,
         'last_seen': now() - 86400 * 40, 'hit_count': 159},
    ]}


def build_cmd_library() -> dict:
    """Saved one-liner command library → cmd_library.json.

    Schema verified against handle_cmd_library_list/add (api.py:19093):
    {'snippets': [{id, name, cmd, description, created}]}."""
    base = now() - 86400 * 22
    rows = [
        ('Disk usage by mount', 'df -hT -x tmpfs -x devtmpfs',
         'Human-readable filesystem usage, excluding pseudo filesystems'),
        ('Top 10 memory hogs', 'ps -eo pid,comm,%mem,%cpu --sort=-%mem | head -n 11',
         'Quickly find what is eating RAM'),
        ('Listening sockets', 'ss -tulpn',
         'All listening TCP/UDP sockets with owning process'),
        ('Failed systemd units', 'systemctl --failed --no-legend',
         'List units in the failed state'),
        ('Recent auth failures',
         "journalctl -u ssh -p warning --since '24h ago' --no-pager",
         'SSH auth warnings in the last day'),
        ('Docker disk reclaim', 'docker system df',
         'Show reclaimable Docker image/volume/build-cache space'),
    ]
    snippets = [{'id': _stable_hex('cmdlib', name, nbytes=6), 'name': name,
                 'cmd': cmd, 'description': desc, 'created': base + i * 3600}
                for i, (name, cmd, desc) in enumerate(rows)]
    return {'snippets': snippets}


def build_ai_usage() -> dict:
    """AI per-user-per-day request counter → ai_usage.json (rate-limit ledger).

    Schema verified against _ai_rate_limit_check (api.py:19940): flat dict keyed
    '<YYYY-MM-DD>:<actor>' → count. Non-today keys are GC'd on the next AI
    request, so only today's are seeded."""
    today = datetime.date.today().isoformat()
    return {f'{today}:alice': 6, f'{today}:bob': 2, f'{today}:demo': 1}


def build_rollouts() -> dict:
    """Staged agent/script rollouts → rollouts.json (canary→pilot→broad).

    Schema verified against handle_rollouts_list/create/_rollout_advance
    (api.py:29055/29065/28940): {'rollouts': [{id, name, action, script_id,
    rings:[{name, selector}], rings_state:[{state, dispatched_ids, ...}],
    auto_promote, verify_minutes, state, current_ring, history:[{ts,msg}],
    created_by, created_at, updated_at}]}. One in-flight 4.7.0 agent upgrade +
    one completed script rollout."""
    t0 = now() - 86400 * 2

    def ring(name, sel_type, sel_val=None, ids=None):
        s = {'type': sel_type}
        if sel_type == 'ids':
            s['ids'] = ids or []
        else:
            s['value'] = sel_val or ''
        return {'name': name, 'selector': s}

    upgrade = {
        'id': _stable_hex('rollout', 'agent-470', nbytes=8),
        'name': 'Agent 4.7.0 — fleet upgrade', 'action': 'upgrade', 'script_id': '',
        'rings': [ring('canary', 'ids', ids=['gt01', 'ha01']),
                  ring('pilot', 'group', 'services'),
                  ring('broad', 'group', 'infra')],
        'rings_state': [
            {'state': 'done', 'dispatched_ids': ['gt01', 'ha01'],
             'dispatched_at': t0, 'done_at': t0 + 1800, 'total': 2,
             'ok_count': 2, 'failed_count': 0, 'queued': 2},
            {'state': 'verifying', 'dispatched_ids': ['pi1', 'ng01', 'nc01', 'vw01'],
             'dispatched_at': now() - 1200, 'total': 4, 'ok_count': 3,
             'failed_count': 0, 'queued': 4},
            {'state': 'pending', 'dispatched_ids': [], 'total': 0,
             'ok_count': 0, 'failed_count': 0}],
        'auto_promote': False, 'verify_minutes': 30, 'state': 'running',
        'current_ring': 1,
        'history': [
            {'ts': t0, 'msg': 'created — upgrade, 3 ring(s), manual promote'},
            {'ts': t0, 'msg': 'started'},
            {'ts': t0 + 60, 'msg': 'ring 1/3 "canary" dispatched to 2 device(s)'},
            {'ts': t0 + 1800, 'msg': 'ring 1 done — 2/2 verified'},
            {'ts': now() - 1260, 'msg': 'manually promoted to ring 2'},
            {'ts': now() - 1200, 'msg': 'ring 2/3 "pilot" dispatched to 4 device(s)'}],
        'created_by': 'alice', 'created_at': t0, 'updated_at': now() - 1200,
    }
    script_done = {
        'id': _stable_hex('rollout', 'logrotate', nbytes=8),
        'name': 'Rotate nginx logs — web tier', 'action': 'script',
        'script_id': 'demo-rotate-nginx-logs',
        'rings': [ring('web', 'tag', 'web')],
        'rings_state': [
            {'state': 'done', 'dispatched_ids': ['ng01'],
             'dispatched_at': now() - 86400 * 5,
             'done_at': now() - 86400 * 5 + 600, 'total': 1, 'ok_count': 1,
             'failed_count': 0, 'queued': 1}],
        'auto_promote': True, 'verify_minutes': 15, 'state': 'done',
        'current_ring': 0,
        'history': [
            {'ts': now() - 86400 * 5 - 120, 'msg': 'created — script, 1 ring(s), auto promote'},
            {'ts': now() - 86400 * 5 - 60, 'msg': 'started'},
            {'ts': now() - 86400 * 5, 'msg': 'ring 1/1 "web" dispatched to 1 device(s)'},
            {'ts': now() - 86400 * 5 + 600, 'msg': 'ring 1 done — 1/1 verified'},
            {'ts': now() - 86400 * 5 + 600, 'msg': 'rollout complete'}],
        'created_by': 'bob', 'created_at': now() - 86400 * 5 - 120,
        'updated_at': now() - 86400 * 5 + 600,
    }
    return {'rollouts': [upgrade, script_done]}


def build_gpu_history() -> dict:
    """Per-GPU telemetry trend samples → gpu_history.json (GPU-page sparklines).

    Mirrors what _maybe_sample_gpu writes: {dev_id: {gpu_idx: {name, vendor,
    samples:[{ts, temp, util, mem}]}}}. ~48 samples (~4h at the 5-min hardware
    cadence) per GPU, oscillating around the CURRENT reading from build_hardware
    and ending exactly on it, so the sparkline looks alive and matches the card."""
    hw = build_hardware()
    n, step = 48, 300
    out = {}
    for dev_id, rec in hw.items():
        gpus = rec.get('gpus') or []
        if not gpus:
            continue
        g_out = {}
        for idx, g in enumerate(gpus):
            rng = _seeded_random('gpuhist', dev_id, idx)
            cur_t, cur_u = g.get('temp_c'), g.get('util_pct')
            mu, mt = g.get('mem_used_mb'), g.get('mem_total_mb')
            cur_m = round(100.0 * mu / mt, 1) if mu and mt else None
            samples = []
            for i in range(n):
                ts = now() - (n - 1 - i) * step
                if i == n - 1:                      # newest sample == live value
                    t, u, m = cur_t, cur_u, cur_m
                else:
                    t = (round((cur_t or 0) + rng.uniform(-8, 4), 1)
                         if cur_t is not None else None)
                    u = (max(0, min(100, round((cur_u or 0) + rng.uniform(-25, 15))))
                         if cur_u is not None else None)
                    m = (max(0.0, min(100.0, round((cur_m or 0) + rng.uniform(-10, 8), 1)))
                         if cur_m is not None else None)
                samples.append({'ts': ts, 'temp': t, 'util': u, 'mem': m})
            g_out[str(idx)] = {'name': g.get('name', ''),
                               'vendor': g.get('vendor', ''), 'samples': samples}
        out[dev_id] = g_out
    return out


def build_thermal_history() -> dict:
    """Per-host hottest-temperature trend → thermal_history.json (v5.0.0 Thermal
    page sparkline). Mirrors _maybe_sample_temp: {dev_id: {samples:[{ts, temp}]}}.
    The hottest reading is max(board sensors, SMART disks, GPUs) from
    build_hardware, so the trend ends exactly on what the Thermal table shows.
    ~48 samples (~4h at the 5-min hardware cadence)."""
    hw = build_hardware()
    n, step = 48, 300
    out = {}
    for dev_id, rec in hw.items():
        vals = [t.get('current_c') for t in (rec.get('temps') or [])
                if isinstance(t.get('current_c'), (int, float))]
        vals += [d.get('temperature_c') for d in (rec.get('smart') or [])
                 if isinstance(d.get('temperature_c'), (int, float))]
        vals += [g.get('temp_c') for g in (rec.get('gpus') or [])
                 if isinstance(g.get('temp_c'), (int, float))]
        if not vals:
            continue
        cur = float(max(vals))
        rng = _seeded_random('temphist', dev_id)
        samples = []
        for i in range(n):
            ts = now() - (n - 1 - i) * step
            temp = cur if i == n - 1 else round(max(20.0, cur + rng.uniform(-6, 3)), 1)
            samples.append({'ts': ts, 'temp': temp})
        out[dev_id] = {'samples': samples}
    return out


# ─── Reputation / DMARC / Resolver-health monitors (v4.8.0 / v4.9.0) ─────────
# These are standalone monitors (not per-device), so the demo seeds a small,
# realistic watchlist with a mix of healthy / weak / failing results — otherwise
# the pages render empty. Target and result builders share stable ids.

_DMARC_DOMAINS = [
    # (domain, dkim_selector, label, status, policy)
    ('tvipper.com',      'default', 'Primary domain',  'ok',   'reject'),
    ('lab.local',        'mail',    'Internal mail',    'weak', 'none'),
    ('old-shop.example', '',        'Legacy storefront','fail', ''),
]


def _dmarc_id(domain):
    return 'dmarc_' + _stable_hex('dmarc', domain)


def build_dmarc_targets() -> dict:
    return {_dmarc_id(d): {'domain': d, 'dkim_selector': sel, 'label': lbl}
            for d, sel, lbl, _s, _p in _DMARC_DOMAINS}


def build_dmarc_results() -> dict:
    out = {}
    for d, _sel, _lbl, status, pol in _DMARC_DOMAINS:
        tid = _dmarc_id(d)
        if status == 'ok':
            out[tid] = {
                'status': 'ok', 'reasons': [],
                'dmarc': {'record': f'v=DMARC1; p={pol}; rua=mailto:dmarc@{d}', 'policy': pol},
                'spf':   {'record': 'v=spf1 include:_spf.google.com -all', 'all': '-all'},
                'dkim':  {'record': 'v=DKIM1; k=rsa; p=MIIBIjANBgkq...', 'present': True},
                'errors': {}, 'checked_at': now() - 3600}
        elif status == 'weak':
            out[tid] = {
                'status': 'weak',
                'reasons': ['DMARC policy is p=none (monitor only, not enforced)',
                            'SPF ends with ~all (softfail rather than -all)'],
                'dmarc': {'record': 'v=DMARC1; p=none', 'policy': 'none'},
                'spf':   {'record': 'v=spf1 include:mailgun.org ~all', 'all': '~all'},
                'dkim':  {'record': 'v=DKIM1; k=rsa; p=MIIBIjANBgkq...', 'present': True},
                'errors': {}, 'checked_at': now() - 7200}
        else:
            out[tid] = {
                'status': 'fail',
                'reasons': ['No DMARC record found', 'No SPF record found'],
                'dmarc': {}, 'spf': {}, 'dkim': {}, 'errors': {},
                'checked_at': now() - 10800}
    return out


# RFC-5737 documentation IPs — valid-looking public addresses that can never be
# real, so the demo never implies a real host is blacklisted.
_REP_IPS = [
    # (ip, label, listed_on)
    ('203.0.113.10',  'Mail relay (prod)', []),
    ('198.51.100.25', 'Web edge',          []),
    ('192.0.2.50',    'Old VPS (retired)', ['zen.spamhaus.org', 'bl.spamcop.net']),
]


def _rep_id(ip):
    return 'iprep_' + _stable_hex('iprep', ip)


def build_ip_reputation_targets() -> dict:
    return {_rep_id(ip): {'ip': ip, 'label': lbl} for ip, lbl, _l in _REP_IPS}


def build_ip_reputation_results() -> dict:
    return {_rep_id(ip): {'listed_count': len(listed), 'listed_on': listed,
                          'errors': {}, 'error': '', 'checked_at': now() - 1800}
            for ip, _lbl, listed in _REP_IPS}


_RESOLVER_NAMES = [
    # (name, type, label, healthy, down)
    ('tvipper.com',      'A', 'Primary site',       True,  False),
    ('lab.local',        'A', 'Internal zone',      True,  False),
    ('retired.example',  'A', 'Decommissioned host', False, True),
]


def _rslv_id(name, rtype):
    return 'rslv_' + _stable_hex('rslv', name, rtype)


def build_resolver_health_targets() -> dict:
    return {_rslv_id(n, t): {'name': n, 'type': t, 'label': lbl}
            for n, t, lbl, _h, _d in _RESOLVER_NAMES}


def build_resolver_health_results() -> dict:
    out = {}
    pub = [('Cloudflare', '1.1.1.1'), ('Google', '8.8.8.8'), ('Quad9', '9.9.9.9')]
    for name, rtype, _lbl, healthy, down in _RESOLVER_NAMES:
        tid = _rslv_id(name, rtype)
        per = []
        for rname, rip in pub:
            if healthy:
                per.append({'resolver': rname, 'ip': rip, 'status': 'ok',
                            'error': '', 'latency_ms': _seeded_random('rslv', name, rip).randint(8, 40),
                            'answers': ['203.0.113.7']})
            else:
                per.append({'resolver': rname, 'ip': rip, 'status': 'nxdomain',
                            'error': 'NXDOMAIN', 'latency_ms': 0, 'answers': []})
        total = len(per)
        ok_count = total if healthy else 0
        lat = [p['latency_ms'] for p in per if p['latency_ms']]
        out[tid] = {
            'healthy': healthy, 'down': down,
            'ok_count': ok_count, 'total': total,
            'nxdomain_count': 0 if healthy else total,
            'fail_count': 0 if healthy else total,
            'latency_ms': round(sum(lat) / len(lat)) if lat else 0,
            'max_latency_ms': max(lat) if lat else 0,
            'per_resolver': per, 'checked_at': now() - 900}
    return out


# ════════════════════════════════════════════════════════════════════════════
# v5.1–v5.6 subsystems — seeded so the demo shows the newer opt-in features
# populated instead of an empty "not configured" page: helpdesk tickets +
# contacts, Knowledge Base, provisioning blueprints, billing / time-tracking,
# WG Access, schedule, calendar, DMARC reports, alert tuning, custom app
# catalog, scan schedules, SCAP. All reference the existing demo devices /
# sites / users. Every enable flag lives in build_config().
# ════════════════════════════════════════════════════════════════════════════

def _demo_dev_names() -> dict:
    """{device_id: display name} for the seeded fleet (denormalised into records)."""
    return {did: d.get('name', did) for did, d in build_devices().items()}


# ─── v5.3.0: Helpdesk tickets + contacts ─────────────────────────────────────

def build_tickets() -> dict:
    """Helpdesk tickets (viewer-visible). A realistic spread of incident/
    request/change across priorities + lifecycle states, some linked to
    devices, one parent with a sub-ticket, threaded messages."""
    names = _demo_dev_names()

    def _msg(author, body, direction='note', channel='web', hours_ago=0):
        return {'ts': now() - 3600 * hours_ago, 'author': author, 'body': body,
                'channel': channel, 'direction': direction}

    def _tk(seq, subject, typ, status, prio, dev, group, assignee,
            created_days, updated_hours, messages, **extra):
        did = dev or ''
        return {
            'id': _stable_id('ticket', seq),
            'number': 900000 + seq,
            'subject': subject,
            'type': typ,
            'status': status,
            'priority': prio,
            'device_id': did,
            'device_name': names.get(did, ''),
            'alert_id': extra.get('alert_id', ''),
            'alertid': extra.get('alertid', ''),
            'to_email': extra.get('to_email', ''),
            'affected_devices': ([did] if did else []) + extra.get('also', []),
            'parent': extra.get('parent', ''),
            'group': group,
            'assignee': assignee,
            'created_by': extra.get('created_by', 'alice'),
            'created_at': now() - 86400 * created_days,
            'updated_at': now() - 3600 * updated_hours,
            'new_reply': extra.get('new_reply', False),
            'messages': messages,
        }

    tickets = [
        _tk(1, 'Nextcloud slow for external users', 'incident', 'ongoing', 2,
            'nc01', 'Infrastructure', 'alice', 3, 5, [
                _msg('email', 'Uploads to the shared folder time out from home.',
                     'in', 'email', 72),
                _msg('alice', 'Confirmed high php-fpm latency; checking the reverse proxy.',
                     'note', 'web', 30),
                _msg('alice', "We've raised the php-fpm worker count — please retry and let us know.",
                     'out', 'email', 5),
            ], to_email='ops@acme-hosting.example', created_by='email'),
        _tk(2, 'Add a read-only VPN account for the auditor', 'request',
            'pending_customer', 3, None, 'Sales', 'bob', 6, 20, [
                _msg('bob', 'Auditor needs read-only reach to the Frankfurt DC subnet only.',
                     'note'),
                _msg('bob', 'Sent the WireGuard config + QR to the auditor; awaiting confirmation.',
                     'out', 'email', 20),
            ], to_email='auditor@client.example'),
        _tk(3, 'Quarterly kernel + package maintenance window', 'change',
            'pending_internal', 3, 'pmx01', 'Infrastructure', 'alice', 2, 8, [
                _msg('alice', 'Change request: patch + reboot the Proxmox host during the '
                     'Sun 02:00–04:00 window. Guests live-migrate first.', 'note'),
                _msg('bob', 'Approved. Snapshot the critical guests before the reboot.',
                     'note', 'web', 8),
            ], also=['tnas']),
        _tk(4, 'TrueNAS SMART warning on da3', 'incident', 'ongoing', 1,
            'tnas', 'Infrastructure', 'alice', 1, 2, [
                _msg('alice', 'da3 reporting reallocated sectors climbing. RMA the disk; '
                     'pool is still redundant (raidz2).', 'note'),
            ], new_reply=False),
        _tk(5, 'Jellyfin transcoding stutters on 4K', 'incident', 'resolved', 3,
            'jf01', 'Support', 'bob', 9, 96, [
                _msg('email', '4K films buffer every few minutes on the living-room TV.',
                     'in', 'email', 216),
                _msg('bob', 'Enabled NVENC hardware transcoding + bumped the cache.',
                     'out', 'email', 100),
                _msg('email', 'Perfect now, thanks!', 'in', 'email', 96),
            ], to_email='family@home.example', created_by='email'),
        _tk(6, 'Onboard new marketing laptop', 'request', 'closed', 4, None,
            'Sales', 'bob', 20, 300, [
                _msg('bob', 'Imaged, enrolled the agent, joined the office Wi-Fi VLAN.',
                     'note'),
            ]),
        # Parent change with a sub-ticket (child references parent id).
        _tk(7, 'Migrate web tier to the London edge', 'change', 'ongoing', 2,
            'ng01', 'Infrastructure', 'alice', 5, 12, [
                _msg('alice', 'Umbrella change for the edge cutover. Sub-tasks track '
                     'DNS, TLS and the reverse-proxy config.', 'note'),
            ], also=['jf01', 'nc01']),
        _tk(8, 'Cut over DNS + propagate for the edge move', 'change',
            'pending_internal', 2, 'pi1', 'Infrastructure', 'alice', 4, 12, [
                _msg('alice', 'Lower the TTLs 24h ahead, then flip the A/AAAA records.',
                     'note'),
            ], parent=_stable_id('ticket', 7)),
    ]
    return {'tickets': tickets, 'ticket_seq': len(tickets),
            'imap_last_uid': 0, 'imap_last_fetch': 0}


def build_contacts() -> dict:
    """Internal contacts directory (viewer-visible; admin-mutate)."""
    def _ct(seq, name, role, company, email, phone, notes, created_days,
            site='', portal_enabled=False):
        c = {'id': _stable_id('contact', seq), 'name': name, 'role': role,
             'company': company, 'email': email, 'phone': phone, 'notes': notes,
             'created_at': now() - 86400 * created_days,
             'updated_at': now() - 86400 * max(0, created_days - 2)}
        # v6.1.0 coverage fill: customer portal access — magic-link auth only
        # (no password field), gated on portal_enabled + a matching site.
        if site or portal_enabled:
            c['site'] = site
            c['portal_enabled'] = portal_enabled
        return c
    contacts = [
        _ct(1, 'Mette Sørensen', 'Account manager', 'Acme Hosting ApS',
            'mette@acme-hosting.example', '+45 20 12 34 56',
            'Primary contact for the HQ-Copenhagen site. Escalate P1s here first.', 60,
            site=SITE_HQ, portal_enabled=True),
        _ct(2, 'Priya Nair', 'DC operations lead', 'FrankfurtColo GmbH',
            'priya@fra-colo.example', '+49 69 1234 5678',
            'Frankfurt remote-hands + smart-hands. 24/7 NOC line.', 45),
        _ct(3, 'Tom Fletcher', 'ISP escalation', 'NorthLink Telecom',
            'noc@northlink.example', '+44 20 7946 0000',
            'Transit + BGP peering issues for the London edge.', 30),
        _ct(4, 'Datera RMA desk', 'Hardware RMA', 'Datera Storage',
            'rma@datera.example', '+31 20 555 0100',
            'Disk / controller RMAs for the TrueNAS array.', 20),
    ]
    return {'contacts': contacts}


# ─── v5.6.0: Knowledge base ──────────────────────────────────────────────────

def build_kb() -> dict:
    """Operator-authored KB articles (viewer-read; also a RAG source)."""
    def _kb(seq, title, category, tags, body, pinned=False, linked=None,
            author='alice', created_days=40):
        return {'id': 'kb_' + _stable_hex('kb', seq, nbytes=3)[:5],
                'title': title, 'category': category, 'tags': tags, 'body': body,
                'pinned': pinned, 'linked_devices': linked or [], 'author': author,
                'created_at': now() - 86400 * created_days,
                'updated_at': now() - 86400 * max(0, created_days - 3)}
    articles = [
        _kb(1, 'Fleet onboarding checklist', 'SOPs/Onboarding',
            ['onboarding', 'agent', 'checklist'],
            '## New host onboarding\n\n1. Install the agent: run the one-liner from '
            '**Settings → Install**.\n2. Approve the enrolment PIN.\n3. Assign a '
            '**group** and **tags** (site, role).\n4. Set metric thresholds if it '
            'differs from the group default.\n5. Add it to the right **drift profile**.\n',
            pinned=True, created_days=50),
        _kb(2, 'Proxmox host patch + reboot runbook', 'Runbooks/Virtualization',
            ['proxmox', 'patching', 'maintenance'],
            '## Patch window\n\n1. Snapshot critical guests.\n2. `qm migrate` HA guests '
            'to another node (or shut them down cleanly).\n3. `apt update && apt '
            'full-upgrade`.\n4. Reboot; confirm all guests auto-start.\n5. Verify the '
            'Ceph/ZFS pool is healthy before clearing the maintenance window.\n',
            linked=['pmx01'], created_days=35),
        _kb(3, 'TrueNAS disk RMA procedure', 'Runbooks/Storage',
            ['truenas', 'zfs', 'disk', 'rma'],
            '## Replacing a failed disk\n\n1. Identify the disk: **Storage → Disks** '
            '(match the serial from the SMART alert).\n2. Offline it: `zpool offline '
            'tank <disk>`.\n3. Physically swap, then `zpool replace tank <old> <new>`.\n'
            '4. Watch resilver to 100%.\n5. File the RMA with the Datera RMA desk.\n',
            linked=['tnas'], created_days=25),
        _kb(4, 'Incident severity + SLA matrix', 'SOPs/Support',
            ['sla', 'incident', 'priority'],
            '## Priorities\n\n| Priority | Example | First response |\n|---|---|---|\n'
            '| P1 | Site/service down | 1 hour |\n| P2 | Degraded, workaround exists | '
            '4 hours |\n| P3 | Minor / single user | 1 business day |\n| P4 | Request / '
            'cosmetic | 3 business days |\n', pinned=True, created_days=48),
        _kb(5, 'Restoring from an encrypted backup', 'Runbooks/Backup',
            ['backup', 'restore', 'dr'],
            '## Disaster recovery\n\n1. Fetch the latest `remotepower_data_*.tar.gz.enc` '
            'from off-host storage.\n2. Decrypt with the passphrase from the vault '
            '(`RP_BACKUP_PASSPHRASE`).\n3. Stop the server, restore the data dir, '
            '`systemctl start`.\n4. Run **restore-verify** and confirm device count + '
            'last-seen look right.\n', author='bob', created_days=18),
    ]
    return {'articles': articles}


# ─── v5.6.0: Provisioning blueprints ─────────────────────────────────────────

def build_blueprints() -> dict:
    """Provisioning blueprint catalog (terraform / cloud-init / ansible / ipxe)."""
    def _bp(seq, name, folder, kind, content, variables, created_days=30,
            author='alice'):
        return {'id': _stable_id('blueprint', seq), 'name': name, 'folder': folder,
                'kind': kind, 'content': content, 'variables': variables,
                'created': now() - 86400 * created_days,
                'updated': now() - 86400 * max(0, created_days - 4),
                'created_by': author}
    blueprints = [
        _bp(1, 'Proxmox LXC — Debian base', 'Infra/Proxmox', 'terraform',
            'variable "hostname" { default = "ct-new" }\n'
            'variable "cores"    { default = 2 }\n'
            'resource "proxmox_lxc" "ct" {\n'
            '  hostname    = var.hostname\n'
            '  ostemplate  = "local:vztmpl/debian-12-standard_amd64.tar.zst"\n'
            '  cores       = var.cores\n'
            '  memory      = 2048\n'
            '  rootfs { storage = "local-lvm"  size = "16G" }\n'
            '  network { name = "eth0"  bridge = "vmbr0"  ip = "dhcp" }\n}\n',
            [{'name': 'hostname', 'label': 'Container hostname', 'default': 'ct-new',
              'secret': False},
             {'name': 'cores', 'label': 'vCPU cores', 'default': '2', 'secret': False}],
            created_days=40),
        _bp(2, 'Cloud-init — enrol RemotePower agent', 'Onboarding', 'cloud-init',
            '#cloud-config\n'
            'package_update: true\n'
            'packages: [curl, ca-certificates]\n'
            'runcmd:\n'
            '  - curl -fsSL ${rp_server_url}/install | sh -s -- agent \\\n'
            '      --server ${rp_server_url} --name ${rp_device_name}\n',
            [{'name': 'rp_device_name', 'label': 'Device name', 'default': '',
              'secret': False}], created_days=32),
        _bp(3, 'Ansible — baseline hardening', 'Config/Ansible', 'ansible',
            '---\n- hosts: all\n  become: true\n  vars:\n'
            '    ssh_port: ${ssh_port}\n  tasks:\n'
            '    - name: Install fail2ban + unattended-upgrades\n'
            '      apt: { name: [fail2ban, unattended-upgrades], state: present }\n'
            '    - name: Harden sshd (no root, key-only)\n'
            '      lineinfile:\n        path: /etc/ssh/sshd_config\n'
            '        regexp: "^#?PermitRootLogin"\n        line: "PermitRootLogin no"\n',
            [{'name': 'ssh_port', 'label': 'SSH port', 'default': '22',
              'secret': False}], created_days=28),
        _bp(4, 'iPXE — netboot Debian installer', 'Infra/Netboot', 'ipxe',
            '#!ipxe\n'
            'set base http://${rp_server_host}/netboot/debian\n'
            'kernel ${base}/linux\n'
            'initrd ${base}/initrd.gz\n'
            'imgargs linux auto=true priority=critical\n'
            'boot\n',
            [], created_days=22),
        _bp(5, 'Terraform — Cloudflare DNS record', 'Infra/DNS', 'terraform',
            'variable "record"  { default = "app" }\n'
            'variable "cf_token" { default = "" }\n'
            'provider "cloudflare" { api_token = var.cf_token }\n'
            'resource "cloudflare_record" "r" {\n'
            '  zone_id = data.cloudflare_zone.z.id\n'
            '  name    = var.record\n  type = "A"\n  value = "203.0.113.10"\n'
            '  proxied = true\n}\n',
            [{'name': 'record', 'label': 'Record name', 'default': 'app',
              'secret': False},
             {'name': 'cf_token', 'label': 'Cloudflare API token', 'default': '',
              'secret': True}], created_days=15),
    ]
    return {'blueprints': blueprints}


# ─── v5.4.0: Billing / time-tracking ─────────────────────────────────────────

def build_time_entries() -> dict:
    """Time ledger — billable (customer) + internal hours across the team."""
    names = _demo_dev_names()
    inv1 = _stable_id('invoice', 1)     # entries locked into the 'paid' invoice

    def _te(seq, days_ago, user, hours, billable, site, dev='', ticket_seq=None,
            category='', rate_name='', note='', locked=False, invoice_id=''):
        return {
            'id': _stable_id('timeentry', seq),
            'number': seq,
            'date': _iso_in_days(-days_ago),
            'user': user,
            'hours': hours,
            'billable': billable,
            'site_id': site if billable else '',
            'device_id': dev,
            'device_name': names.get(dev, ''),
            'tag': '',
            'ticket_id': _stable_id('ticket', ticket_seq) if ticket_seq else '',
            'ticket_number': str(900000 + ticket_seq) if ticket_seq else '',
            'category': category if not billable else '',
            'rate_name': rate_name,
            'note': note,
            'invoice_id': invoice_id,
            'locked': locked,
            'created_at': now() - 86400 * days_ago,
            'updated_at': now() - 86400 * days_ago,
        }
    entries = [
        # Locked into the paid invoice (last month, HQ).
        _te(1, 34, 'alice', 3.0, True, SITE_HQ, 'nc01', 1, rate_name='Standard',
            note='Investigated + fixed Nextcloud reverse-proxy latency', locked=True,
            invoice_id=inv1),
        _te(2, 33, 'bob', 2.5, True, SITE_HQ, 'pi1', rate_name='Standard',
            note='DNS TTL lowering ahead of the edge cutover', locked=True,
            invoice_id=inv1),
        _te(3, 32, 'alice', 4.0, True, SITE_HQ, 'pmx01', 3, rate_name='After-hours',
            note='Out-of-hours patch window on the Proxmox host', locked=True,
            invoice_id=inv1),
        # This month — open, billable.
        _te(4, 9, 'alice', 2.0, True, SITE_DC, 'tnas', 4, rate_name='Standard',
            note='TrueNAS SMART triage + RMA paperwork'),
        _te(5, 7, 'bob', 5.0, True, SITE_EDGE, 'ng01', 7, rate_name='Project',
            note='Edge migration — reverse-proxy + TLS config'),
        _te(6, 5, 'bob', 3.0, True, SITE_EDGE, 'jf01', 5, rate_name='Standard',
            note='Jellyfin NVENC transcoding fix'),
        _te(7, 3, 'alice', 1.5, True, SITE_DC, 'pmx01', rate_name='Standard',
            note='Guest live-migration + snapshot verification'),
        _te(8, 2, 'bob', 4.0, True, SITE_EDGE, 'nc01', 7, rate_name='Project',
            note='Edge cutover rehearsal'),
        # Internal / non-billable.
        _te(9, 8, 'alice', 2.0, False, '', category='meeting',
            note='Weekly ops sync + capacity planning'),
        _te(10, 6, 'bob', 1.0, False, '', category='education',
            note='WireGuard hardening reading'),
        _te(11, 4, 'alice', 1.5, False, '', category='internal',
            note='Demo environment upkeep'),
        _te(12, 1, 'bob', 0.5, False, '', category='admin',
            note='Timesheet + invoice review'),
    ]
    return {'entries': entries, 'seq': len(entries)}


def build_billing() -> dict:
    """Rate card + per-site billing config (currency, VAT, recurring fees)."""
    return {
        'currency': 'EUR',
        'default_rate': 110.0,
        'default_vat': 25.0,                    # Danish VAT
        'invoice_prefix': 'INV-',
        'rate_card': [
            {'name': 'Standard',    'rate': 110.0},
            {'name': 'After-hours', 'rate': 165.0},
            {'name': 'Project',     'rate': 130.0},
        ],
        'sites': {
            SITE_HQ: {
                'default_rate': 110.0, 'vat': 25.0,
                'billing_contact': 'mette@acme-hosting.example',
                'billing_address': 'Acme Hosting ApS\nRådhuspladsen 1\n1550 København',
                'recurring': [
                    {'id': _stable_id('fee', 1), 'label': 'Managed-fleet retainer',
                     'kind': 'service', 'amount': 750.0, 'qty': 1.0,
                     'cadence': 'monthly', 'active': True},
                    {'id': _stable_id('fee', 2), 'label': 'Backup storage (per TB)',
                     'kind': 'operation', 'amount': 12.0, 'qty': 8.0,
                     'cadence': 'monthly', 'active': True},
                ],
            },
            SITE_DC: {
                'default_rate': 120.0, 'vat': 19.0,     # German VAT
                'billing_contact': 'priya@fra-colo.example',
                'billing_address': 'FrankfurtColo GmbH\nKleyerstraße 90\n60326 Frankfurt',
                'recurring': [
                    {'id': _stable_id('fee', 3), 'label': 'Rack + power (½ rack)',
                     'kind': 'service', 'amount': 480.0, 'qty': 1.0,
                     'cadence': 'monthly', 'active': True},
                ],
            },
            SITE_EDGE: {
                'default_rate': 130.0, 'vat': 20.0,     # UK VAT
                'billing_contact': 'noc@northlink.example',
                'billing_address': 'Edge - London\n10 Techspace\nEC2A 4NE London',
                'recurring': [
                    {'id': _stable_id('fee', 4), 'label': 'Managed transit',
                     'kind': 'license', 'amount': 220.0, 'qty': 1.0,
                     'cadence': 'monthly', 'active': True},
                ],
            },
        },
    }


def build_invoices() -> dict:
    """Issued invoices across the draft → sent → paid lifecycle."""
    def _li(kind, label, qty, unit):
        return {'kind': kind, 'label': label, 'qty': qty, 'unit': unit,
                'amount': round(qty * unit, 2)}

    def _inv(seq, site, status, vat, line_items, from_days, to_days,
             issued_days, snapshot_ids=None, notes=''):
        subtotal = round(sum(li['amount'] for li in line_items), 2)
        vat_amount = round(subtotal * vat / 100, 2)
        return {
            'id': _stable_id('invoice', seq),
            'number': f'INV-{seq:05d}',
            'site_id': site,
            'period': {'from': _iso_in_days(-from_days), 'to': _iso_in_days(-to_days)},
            'status': status,
            'currency': 'EUR',
            'vat_rate': vat,
            'line_items': line_items,
            'snapshot_entry_ids': snapshot_ids or [],
            'subtotal': subtotal,
            'vat_amount': vat_amount,
            'total': round(subtotal + vat_amount, 2),
            'issued_at': now() - 86400 * issued_days,
            'created_by': 'alice',
            'notes': notes,
        }
    invoices = [
        # Paid — last month's HQ work (the three locked time entries + retainer).
        _inv(1, SITE_HQ, 'paid', 25.0, [
            _li('hours', 'Billable hours — Standard', 5.5, 110.0),
            _li('hours', 'Billable hours — After-hours', 4.0, 165.0),
            _li('service', 'Managed-fleet retainer', 1.0, 750.0),
            _li('operation', 'Backup storage (per TB)', 8.0, 12.0),
        ], from_days=61, to_days=32, issued_days=30, notes='Paid via bank transfer.',
            snapshot_ids=[_stable_id('timeentry', 1), _stable_id('timeentry', 2),
                          _stable_id('timeentry', 3)]),
        # Sent — Frankfurt DC, awaiting payment.
        _inv(2, SITE_DC, 'sent', 19.0, [
            _li('hours', 'Billable hours — Standard', 3.5, 120.0),
            _li('service', 'Rack + power (½ rack)', 1.0, 480.0),
        ], from_days=30, to_days=1, issued_days=3),
        # Draft — London edge migration in progress.
        _inv(3, SITE_EDGE, 'draft', 20.0, [
            _li('hours', 'Billable hours — Project', 9.0, 130.0),
            _li('hours', 'Billable hours — Standard', 3.0, 130.0),
            _li('license', 'Managed transit', 1.0, 220.0),
        ], from_days=14, to_days=0, issued_days=0, notes='Draft — edge cutover ongoing.'),
    ]
    return {'invoices': invoices, 'invoice_seq': len(invoices)}


def build_timesheet_watch() -> dict:
    """Timesheet visibility grants (a lead who can view a teammate's hours)."""
    return {'grants': [
        {'id': _stable_id('tswatch', 1), 'watcher': 'bob', 'scope': 'user',
         'value': 'alice', 'created': now() - 86400 * 40, 'created_by': 'alice'},
    ]}


# ─── v5.2.0: WG Access (WireGuard road-warrior VPN) ──────────────────────────

def build_vpn() -> dict:
    """WG Access tunnels + clients (Admin → WG Access)."""
    hub = 'demoremote.tvipper.com'
    t1 = {
        'id': _stable_id('wgtunnel', 1), 'name': 'Staff — full tunnel',
        'iface': 'rpwg0', 'listen_port': 51820, 'pool': '10.7.0.0/24',
        'endpoint': f'{hub}:51820', 'dns': '10.0.0.2',
        'hub_pubkey': _stable_id('wgpub', 'hub1', length=43) + '=',
        'allow_internet': True, 'reach_scope_type': 'all', 'reach_scope_value': '',
        'enabled': True, 'expires_at': None, 'created_by': 'alice',
        'created_at': now() - 86400 * 40,
        'clients': [
            {'id': _stable_id('wgclient', 1), 'name': 'alice-laptop',
             'pubkey': _stable_id('wgpub', 'c1', length=43) + '=',
             'address': '10.7.0.2/32', 'enabled': True, 'expires_at': None,
             'created_by': 'alice', 'created_at': now() - 86400 * 38,
             'last_handshake': now() - 340, 'rx_bytes': 184_320_512,
             'tx_bytes': 42_115_003, 'endpoint': '203.0.113.44:51012'},
            {'id': _stable_id('wgclient', 2), 'name': 'bob-phone',
             'pubkey': _stable_id('wgpub', 'c2', length=43) + '=',
             'address': '10.7.0.3/32', 'enabled': True, 'expires_at': None,
             'created_by': 'bob', 'created_at': now() - 86400 * 30,
             'last_handshake': now() - 7200, 'rx_bytes': 9_115_002,
             'tx_bytes': 3_004_881, 'endpoint': '198.51.100.7:44210'},
        ],
    }
    t2 = {
        'id': _stable_id('wgtunnel', 2), 'name': 'Auditor — Frankfurt DC only',
        'iface': 'rpwg1', 'listen_port': 51821, 'pool': '10.7.1.0/24',
        'endpoint': f'{hub}:51821', 'dns': '',
        'hub_pubkey': _stable_id('wgpub', 'hub2', length=43) + '=',
        'allow_internet': False, 'reach_scope_type': 'site',
        'reach_scope_value': SITE_DC, 'enabled': True,
        'expires_at': now() + 86400 * 14, 'created_by': 'bob',
        'created_at': now() - 86400 * 6,
        'clients': [
            {'id': _stable_id('wgclient', 3), 'name': 'auditor-laptop',
             'pubkey': _stable_id('wgpub', 'c3', length=43) + '=',
             'address': '10.7.1.2/32', 'enabled': True,
             'expires_at': now() + 86400 * 14, 'created_by': 'bob',
             'created_at': now() - 86400 * 6, 'last_handshake': 0,
             'rx_bytes': 0, 'tx_bytes': 0, 'endpoint': ''},
        ],
    }
    return {'tunnels': [t1, t2]}


# ─── Scheduled jobs / maintenance calendar ───────────────────────────────────

def build_schedule() -> dict:
    """Scheduled power/patch actions (Schedule page)."""
    names = _demo_dev_names()

    def _job(seq, dev, command, run_at=None, cron=None, actor='alice'):
        return {'id': _stable_hex('schedjob', seq), 'device_id': dev,
                'device_name': names.get(dev, ''), 'command': command,
                'run_at': run_at, 'cron': cron, 'actor': actor,
                'created': now() - 86400 * 12, 'recurring': cron is not None}
    jobs = [
        _job(1, 'pmx01', 'upgrade_packages', cron='0 3 * * 0'),      # Sun 03:00
        _job(2, 'tnas', 'reboot', run_at=now() + 86400 * 3 + 3600),  # one-shot
        _job(3, 'ng01', 'upgrade_packages', cron='30 2 * * 1'),      # Mon 02:30
        _job(4, 'jf01', 'reboot', cron='0 5 1 * *', actor='bob'),    # 1st of month
    ]
    return {'jobs': jobs}


def build_calendar() -> dict:
    """Maintenance / events calendar."""
    def _ev(seq, title, desc, start_days, dur_hours, color, recur='none',
            all_day=False, author='alice'):
        start = datetime.datetime.now() + datetime.timedelta(days=start_days)
        end = start + datetime.timedelta(hours=dur_hours)
        return {'id': _stable_hex('calevt', seq), 'title': title,
                'description': desc, 'start': start.replace(microsecond=0).isoformat(),
                'end': end.replace(microsecond=0).isoformat(), 'all_day': all_day,
                'color': color, 'recur': recur, 'created_by': author,
                'created_at': now() - 86400 * 10}
    events = [
        _ev(1, 'Proxmox patch window', 'Patch + reboot pmx01; guests migrate first.',
            3, 2, 'red'),
        _ev(2, 'Edge cutover — London', 'DNS flip + reverse-proxy move to ng01.',
            5, 4, 'blue', author='bob'),
        _ev(3, 'Quarterly DR restore test', 'Restore-verify from the latest encrypted backup.',
            14, 3, 'green'),
        _ev(4, 'Certificate renewals due', 'ACME renew sweep for public endpoints.',
            21, 0, 'orange', all_day=True),
        _ev(5, 'Monthly maintenance', 'Rolling reboots + firmware review.',
            30, 6, 'purple', recur='monthly'),
    ]
    return {'events': events}


# ─── DMARC aggregate reports (targets/results already seeded) ────────────────

def build_dmarc_reports() -> dict:
    """Ingested DMARC RUA aggregate reports + per-source pass/fail rollup."""
    reports = [
        {'org_name': 'google.com', 'domain': 'acme-hosting.example',
         'report_id': _stable_hex('dmarc', 'g1'), 'policy': 'quarantine',
         'date_begin': now() - 86400 * 2, 'date_end': now() - 86400,
         'summary': {'pass': 1284, 'fail': 12}, 'received_at': now() - 86400},
        {'org_name': 'Microsoft Corporation', 'domain': 'acme-hosting.example',
         'report_id': _stable_hex('dmarc', 'm1'), 'policy': 'quarantine',
         'date_begin': now() - 86400 * 3, 'date_end': now() - 86400 * 2,
         'summary': {'pass': 642, 'fail': 3}, 'received_at': now() - 86400 * 2},
        {'org_name': 'Yahoo', 'domain': 'acme-hosting.example',
         'report_id': _stable_hex('dmarc', 'y1'), 'policy': 'none',
         'date_begin': now() - 86400 * 4, 'date_end': now() - 86400 * 3,
         'summary': {'pass': 96, 'fail': 1}, 'received_at': now() - 86400 * 3},
    ]
    sources = {
        '203.0.113.10': {'pass': 1980, 'fail': 0,
                         'domains': ['acme-hosting.example'], 'last_seen': now() - 86400},
        '198.51.100.25': {'pass': 42, 'fail': 15,
                          'domains': ['acme-hosting.example'], 'last_seen': now() - 86400 * 2},
    }
    return {'reports': reports, 'sources': sources,
            'mailbox': {'checked_at': now() - 3600, 'error': '', 'messages': 3,
                        'unseen': 0},
            'last_uid': 128, 'last_fetch': now() - 3600, 'updated': now() - 3600}


# ─── v5.6.0: Alert mutes (Monitoring → Tuning) ───────────────────────────────

def build_alert_mutes() -> dict:
    """Per-(device,event) alert mutes shown on the Tuning page."""
    names = _demo_dev_names()

    def _mute(seq, dev, event, days_ago, actor='alice'):
        return {'id': _stable_id('mute', seq), 'device_id': dev,
                'device_name': names.get(dev, ''), 'event': event,
                'created': now() - 86400 * days_ago, 'created_by': actor}
    return {'mutes': [
        _mute(1, 'jf01', 'container_stopped', 6),      # known-noisy transcoder restarts
        _mute(2, 'ap02', 'device_offline', 3, 'bob'),  # AP on a switched-off timer
    ]}


# ─── v5.1.0: Custom app-catalog templates ────────────────────────────────────

def build_app_catalog_custom() -> dict:
    """Operator-added compose templates alongside the built-in catalog."""
    def _app(slug, name, category, desc, port, yaml):
        return {'id': slug, 'name': name, 'category': category,
                'description': desc, 'port': port, 'yaml': yaml}
    return {
        'uptime-kuma': _app('uptime-kuma', 'Uptime Kuma', 'Custom',
            'Self-hosted status/uptime monitor.', 3001,
            'services:\n  uptime-kuma:\n    image: louislam/uptime-kuma:1\n'
            '    volumes: [uptime-kuma:/app/data]\n    ports: ["3001:3001"]\n'
            '    restart: unless-stopped\nvolumes:\n  uptime-kuma:\n'),
        'linkding': _app('linkding', 'Linkding', 'Custom',
            'Minimal self-hosted bookmark manager.', 9090,
            'services:\n  linkding:\n    image: sissbruecker/linkding:latest\n'
            '    ports: ["9090:9090"]\n    volumes: [linkding:/etc/linkding/data]\n'
            '    restart: unless-stopped\nvolumes:\n  linkding:\n'),
    }


# ─── Scheduled security scans ────────────────────────────────────────────────

def build_scan_schedules() -> dict:
    """Recurring security-scan schedules (Scans view)."""
    names = _demo_dev_names()

    def _sch(seq, name, dev, tool, profile, intensity, cron, last_days, next_days):
        return {'id': _stable_hex('scansched', seq), 'name': name, 'device_id': dev,
                'device_name': names.get(dev, ''),
                'scan_target_id': _stable_id('scantarget', dev),
                'tool': tool, 'profile': profile, 'intensity': intensity,
                'satellite_id': '', 'cron': cron, 'enabled': True,
                'created': now() - 86400 * 30, 'actor': 'alice',
                'last_run': now() - 86400 * last_days, 'next_run': now() + 86400 * next_days}
    return {
        _stable_hex('scansched', 1): _sch(1, 'Weekly edge web scan', 'ng01',
            'nuclei', 'active', 'balanced', '0 4 * * 1', 3, 4),
        _stable_hex('scansched', 2): _sch(2, 'Monthly perimeter nmap', 'fw01',
            'nmap', 'host', 'thorough', '0 2 1 * *', 12, 18),
    }


# ─── OpenSCAP compliance (per-host detail; history already seeded) ───────────

def build_scap() -> dict:
    """Per-device OpenSCAP results backing the Compliance page detail cards."""
    def _rec(dev, profile, score, npass, nfail, failed, days_ago=2):
        return {'ts': now() - 86400 * days_ago, 'profile': profile, 'available': True,
                'reason': '', 'datastream': 'ssg-debian12-ds.xml',
                'available_profiles': ['cis', 'standard', 'pci-dss'],
                'score': score, 'counts': {'pass': npass, 'fail': nfail},
                'pass': npass, 'fail': nfail, 'failed_rules': failed,
                'has_report': True, 'report_ts': now() - 86400 * days_ago,
                'report_bytes': 148_221}
    return {
        'ng01': _rec('ng01', 'cis', 82.4, 176, 38, [
            {'id': 'xccdf_org.ssgproject.content_rule_sshd_disable_root_login',
             'severity': 'high'},
            {'id': 'xccdf_org.ssgproject.content_rule_package_aide_installed',
             'severity': 'medium'}]),
        'pmx01': _rec('pmx01', 'standard', 91.0, 203, 20, [
            {'id': 'xccdf_org.ssgproject.content_rule_audit_rules_time_adjtimex',
             'severity': 'low'}], days_ago=5),
        'nc01': _rec('nc01', 'cis', 76.9, 165, 49, [
            {'id': 'xccdf_org.ssgproject.content_rule_mount_option_tmp_nodev',
             'severity': 'medium'},
            {'id': 'xccdf_org.ssgproject.content_rule_firewalld_sshd_port_enabled',
             'severity': 'high'}], days_ago=1),
    }


# ─── v6.1.0 coverage fill: previously-unseeded subsystems ───────────────────
# Every builder below has its exact on-disk shape verified against the
# handler that reads it in server/cgi-bin/api.py (noted in each docstring),
# not guessed from docs/features.md's prose.

def build_tasks() -> dict:
    """Fleet task board → tasks.json. Shape verified against
    handle_tasks_add (api.py ~52362): {"tasks": [{id,title,description,
    state,device_id,created_by,created_at,updated_at,updated_by?}]}.
    state in TASK_STATES = (upcoming, ongoing, pending, closed)."""
    plan = [
        ('Rotate Nextcloud admin credentials', 'Overdue per the CMDB rotation reminder.',
         'pending', 'nc01', 'alice', 30),
        ('Verify offsite Restic replica', 'Confirm backup.lab -> off-host copy still lands nightly.',
         'ongoing', 'bk01', 'bob', 4),
        ('Replace TrueNAS disk (RMA in progress)', 'Serial matched from the SMART alert; RMA filed with Datera.',
         'ongoing', 'tnas', 'alice', 12),
        ('Plan Proxmox host reboot window', 'Kernel upgrade pending; needs a maintenance window.',
         'upcoming', 'pmx01', 'alice', 1),
        ('Decommission backup.lab', 'Migrating to a newer box; unmonitored while mid-migration.',
         'upcoming', 'bk01', 'bob', 2),
        ('Onboard new Gitea CI runner', 'Deploy key rotated; runner registered.',
         'closed', 'gt01', 'bob', 45),
    ]
    tasks = []
    for i, (title, desc, state, dev_id, actor, days_ago) in enumerate(plan):
        created = now() - 86400 * days_ago
        t = {'id': _stable_hex('task', i, nbytes=8), 'title': title,
             'description': desc, 'state': state, 'device_id': dev_id,
             'created_by': actor, 'created_at': created, 'updated_at': created}
        if state == 'closed':
            t['updated_at'] = created + 86400 * (days_ago - 1) if days_ago > 1 else created
            t['updated_by'] = actor
        tasks.append(t)
    return {'tasks': tasks}


def build_racks() -> dict:
    """Rack elevation view → racks.json. Shape verified against
    handle_racks/handle_rack (api.py ~11010/11053): {rack_id: {name, site,
    height_u, created}}. Placement (rack_id/rack_unit/rack_height_u) lives on
    the CMDB record — see build_cmdb()."""
    return {
        RACK_DC: {'name': 'DC-Frankfurt Rack 1', 'site': SITE_DC,
                  'height_u': 42, 'created': now() - 86400 * 280},
        RACK_HQ: {'name': 'HQ-Copenhagen Rack 1', 'site': SITE_HQ,
                  'height_u': 12, 'created': now() - 86400 * 300},
    }


def build_subnets() -> dict:
    """IPAM subnets → subnets.json. Shape verified against
    handle_ipam_subnets/handle_ipam_subnet (api.py ~11191/11234):
    {subnet_id: {cidr, site, vlan, notes, reservations: {ip: label}, created}}.
    Occupancy is derived live from device/CMDB-interface IPs falling inside
    the CIDR — not stored here."""
    return {
        _stable_id('subnet', 'core-10.0.0.0-24'): {
            'cidr': '10.0.0.0/24', 'site': SITE_HQ, 'vlan': 'VLAN 1 - Core',
            'notes': 'Office network + core network gear.',
            'reservations': {'10.0.0.1': 'switch-core', '10.0.0.254': 'firewall LAN'},
            'created': now() - 86400 * 300,
        },
        _stable_id('subnet', 'services-10.0.2.0-24'): {
            'cidr': '10.0.2.0/24', 'site': SITE_EDGE, 'vlan': 'VLAN 20 - Services',
            'notes': 'App/service hosts — web, media, git, cloud.',
            'reservations': {'10.0.2.254': 'reserved - future DR host'},
            'created': now() - 86400 * 280,
        },
        _stable_id('subnet', 'infra-10.0.1.0-24'): {
            'cidr': '10.0.1.0/24', 'site': SITE_DC, 'vlan': 'VLAN 10 - Infra',
            'notes': 'Hypervisor + storage management network.',
            'reservations': {},
            'created': now() - 86400 * 280,
        },
    }


def build_device_profiles() -> dict:
    """Saved metric-threshold/monitoring bundles → device_profiles.json.
    Shape verified against handle_device_profiles (api.py ~10759). Distinct
    from the unrelated drift profiles (cfg['drift']['profiles'], ids
    dp_web/dp_db) despite the similar naming — these are a separate
    subsystem, so ids here use a different prefix on purpose."""
    return {
        _stable_id('deviceprofile', 'critical-infra'): {
            'name': 'Critical infra', 'created': now() - 86400 * 60,
            'poll_interval': 30,
            'services_watched': ['nginx', 'postgresql', 'docker'],
            'log_watch': ['/var/log/syslog'],
            'metric_thresholds': {
                'disk_warn_percent': 75, 'disk_crit_percent': 88,
                'mem_warn_percent': 80, 'mem_crit_percent': 92,
            },
        },
        _stable_id('deviceprofile', 'lightweight-iot'): {
            'name': 'Lightweight / IoT', 'created': now() - 86400 * 40,
            'poll_interval': 120,
            'services_watched': [],
            'metric_thresholds': {
                'mem_warn_percent': 88, 'mem_crit_percent': 97,
            },
        },
    }


def build_smart_groups() -> dict:
    """Saved dynamic device-group predicates → smart_groups.json. Shape
    verified against handle_smart_groups (api.py ~10907) + _smart_group_match
    (~4767). Keyed by lowercase name; members/evaluated_ts are normally
    server-materialized, precomputed here since the seed runs offline."""
    def _ids(pred):
        out = []
        for d in FAKE_DEVICES:
            ok = True
            if 'tag' in pred and pred['tag'] not in d['tags']:
                ok = False
            if 'group' in pred and d['group'] != pred['group']:
                ok = False
            if 'agentless' in pred and d['agentless'] != pred['agentless']:
                ok = False
            if ok:
                out.append(d['id'])
        return out
    groups = {
        'critical-infra':    {'rules': {'tag': 'critical'}},
        'agentless-network': {'rules': {'agentless': True, 'group': 'network'}},
        'backup-fleet':      {'rules': {'tag': 'backup'}},
    }
    ts = now() - 3600
    return {
        **{name: {**g, 'members': _ids(g['rules']), 'evaluated_ts': ts,
                  'created': now() - 86400 * 50}
           for name, g in groups.items()},
        '_meta': {'last_run': ts},
    }


def build_backup_state() -> dict:
    """Per-path backup freshness → backup_state.json, keyed "<device_id>:
    <path>" matching config.json['backup_monitors']. Shape verified against
    the agent-heartbeat ingest (api.py ~16131-16290)."""
    return {
        'bk01:/mnt/backup/restic-repo': {
            'ok': True, 'age_h': 2.3, 'size': 812_000_000_000,
            'size_hist': [780, 795, 801, 806, 812],
            'size_anom': False, 'verify_status': 'ok',
            'verify_output': 'restic check: no errors', 'verify_at': now() - 3600 * 20,
            'verify_tool': 'restic',
        },
        'nc01:/mnt/data/nextcloud-dump.sql.gz': {
            'ok': False, 'age_h': 41.0, 'size': 2_400_000_000,
            'size_hist': [2300, 2350, 2380, 2400],
            'size_anom': False, 'verify_status': 'unknown', 'verify_output': '',
            'verify_at': 0, 'verify_tool': '',
        },
        'tnas:/tank/backups': {
            'ok': True, 'age_h': 6.1, 'size': 6_100_000_000_000,
            'size_hist': [5800, 5900, 6000, 6050, 6100],
            'size_anom': False, 'verify_status': 'ok',
            'verify_output': 'zfs receive: resilvered clean', 'verify_at': now() - 3600 * 5,
            'verify_tool': 'auto',
        },
    }


def build_mailflow_state() -> dict:
    """Mail round-trip probe state → mailflow_state.json (flat dict, ONE
    probe). Shape verified against run_mailflow_if_due/_mailflow_step
    (api.py ~28298)."""
    return {'sent_ts': now() - 300, 'last_latency': 14,
            'last_ok_ts': now() - 300, 'alerted': False, 'last_tick': now() - 60}


def build_ct_watch() -> dict:
    """Certificate-Transparency watch state → ct_watch.json, keyed by domain
    (matching config.json['ct_watch_domains']). Shape verified against
    run_ct_watch_if_due (tls_ct_handlers.py ~354)."""
    return {
        'nginx.lab': {
            'seen': {_stable_hex('ct-cert', 'nginx.lab', 1, nbytes=16): now() - 86400 * 60},
            'baselined': True, 'last_check': now() - 3600 * 4, 'fail_streak': 0,
        },
    }


def build_patch_age() -> dict:
    """Patch-compliance SLA aging → patch_age.json. Shape verified against
    run_patch_sla_if_due/_eval_patch_sla (api.py ~28196): {device_id:
    {all_first?, sec_first?}, "_last_run", "_breaching"}."""
    breaching = ['tnas']
    return {
        'tnas': {'sec_first': now() - 86400 * 10, 'all_first': now() - 86400 * 25},
        'ng01': {'all_first': now() - 86400 * 3},
        '_last_run': now() - 3600,
        '_breaching': breaching,
    }


def build_image_cves() -> dict:
    """Container image CVE findings → image_cves.json. Shape verified
    against _ingest_image_cves/_sanitize_image_cves (api.py ~26036-26093):
    {device_id: {ts, images: [{image, critical, high, medium, top:
    [{id, pkg, severity, installed, fixed}]}]}}."""
    return {
        'gt01': {'ts': now() - 3600 * 6, 'images': [
            {'image': 'gitea/gitea:1.22', 'critical': 0, 'high': 1, 'medium': 3,
             'top': [{'id': 'CVE-2024-23456', 'pkg': 'libssl3', 'severity': 'high',
                      'installed': '3.0.11', 'fixed': '3.0.13'}]},
        ]},
        'nc01': {'ts': now() - 3600 * 5, 'images': [
            {'image': 'nextcloud:30-apache', 'critical': 1, 'high': 2, 'medium': 4,
             'top': [{'id': 'CVE-2023-99999', 'pkg': 'libxml2', 'severity': 'critical',
                      'installed': '2.9.14', 'fixed': '2.11.7'}]},
        ]},
        'ha01': {'ts': now() - 3600 * 8, 'images': [
            {'image': 'redis:7', 'critical': 0, 'high': 0, 'medium': 1, 'top': []},
        ]},
    }


def build_cve_campaigns() -> dict:
    """CVE remediation campaigns → cve_campaigns.json. Shape verified
    against handle_cve_campaigns/handle_cve_campaign (api.py ~48781-48886):
    {"campaigns": [{id,name,owner,cve_ids,severities,kev_only,target_date,
    created_at,completed_at,samples:[{ts,affected}]}], "_last_sample"}."""
    created = now() - 86400 * 21
    return {
        'campaigns': [
            {'id': 'camp_' + _stable_hex('campaign', 'kev-burndown', nbytes=5),
             'name': 'Critical KEV burn-down Q3', 'owner': 'alice',
             'cve_ids': [], 'severities': ['critical'], 'kev_only': True,
             'target_date': _iso_in_days(21), 'created_at': created,
             'completed_at': None,
             'samples': [{'ts': created + 86400 * i, 'affected': max(0, 6 - i)}
                         for i in range(0, 21, 3)]},
        ],
        '_last_sample': now() - 3600 * 12,
    }


def build_lldp_neighbors() -> dict:
    """LLDP topology discovery → lldp_neighbors.json. Shape verified
    against the heartbeat ingest (api.py ~16380-16395): {device_id: {ts,
    neighbors: [{local_if, peer_name, peer_port, mgmt_ip}]}}. Mirrors the
    real connected_to topology so it reads as confirmation, not noise."""
    ts = now() - 900
    return {
        'pmx01': {'ts': ts, 'neighbors': [
            {'local_if': 'eno1', 'peer_name': 'switch-rack',
             'peer_port': 'GigabitEthernet1/0/3', 'mgmt_ip': '10.0.0.2'}]},
        'tnas': {'ts': ts, 'neighbors': [
            {'local_if': 'mgmt0', 'peer_name': 'switch-rack',
             'peer_port': 'GigabitEthernet1/0/4', 'mgmt_ip': '10.0.0.2'}]},
        'fw01': {'ts': ts, 'neighbors': [
            {'local_if': 'em1', 'peer_name': 'switch-core',
             'peer_port': 'GigabitEthernet1/0/1', 'mgmt_ip': '10.0.0.1'}]},
    }


def build_sudo_log() -> dict:
    """Sudo audit trail → sudo_log.json. Shape verified against the
    heartbeat ingest + _redact_sudo_command (api.py ~16322-16348, ~28644):
    {device_id: [{ts, user, tty, pwd, target, command}]}."""
    entries = [
        ('pmx01', 'alice', 'pts/0', '/root', 'root', 'apt-get update && apt-get -y upgrade'),
        ('pmx01', 'alice', 'pts/0', '/root', 'root', 'systemctl restart pveproxy'),
        ('tnas',  'bob',   'pts/1', '/home/bob', 'root', 'zpool status tank'),
        ('fw01',  'alice', '',      '/root', 'root', 'visudo -c'),
        ('gt01',  'bob',   'pts/0', '/opt/gitea', 'root', 'useradd -m deploy'),
    ]
    out = {}
    for i, (dev_id, user, tty, pwd, target, command) in enumerate(entries):
        out.setdefault(dev_id, []).append({
            'ts': now() - 3600 * (48 - i * 6), 'user': user, 'tty': tty,
            'pwd': pwd, 'target': target, 'command': command,
        })
    return out


def build_incidents() -> dict:
    """Status-page incidents → incidents.json. Shape verified against
    handle_incidents/handle_incident_update (api.py ~36894-36934):
    {"incidents": [{id,title,impact,status,created_at,updated_at,
    updates:[{ts,status,body}]}]}. impact in (minor,major,maintenance),
    status in (investigating,identified,monitoring,resolved)."""
    t0 = now() - 86400 * 18
    return {'incidents': [
        {'id': 'inc_' + _stable_hex('incident', 1, nbytes=5),
         'title': 'Elevated latency — Frankfurt DC',
         'impact': 'minor', 'status': 'resolved',
         'created_at': t0, 'updated_at': t0 + 3600 * 3,
         'updates': [
             {'ts': t0, 'status': 'investigating',
              'body': 'Investigating elevated response times on Frankfurt-hosted services.'},
             {'ts': t0 + 3600, 'status': 'identified',
              'body': 'Identified as a saturated uplink on the DC rack switch.'},
             {'ts': t0 + 3600 * 3, 'status': 'resolved',
              'body': 'Uplink capacity restored; latency back to baseline.'},
         ]},
        {'id': 'inc_' + _stable_hex('incident', 2, nbytes=5),
         'title': 'Scheduled maintenance — Nextcloud upgrade',
         'impact': 'maintenance', 'status': 'resolved',
         'created_at': t0 + 86400 * 10, 'updated_at': t0 + 86400 * 10 + 3600,
         'updates': [
             {'ts': t0 + 86400 * 10, 'status': 'monitoring',
              'body': 'Nextcloud upgraded to 30.x; monitoring for regressions.'},
             {'ts': t0 + 86400 * 10 + 3600, 'status': 'resolved',
              'body': 'No issues observed; maintenance window closed.'},
         ]},
    ]}


def build_commands() -> dict:
    """Pending command queue → commands.json. Shape verified against
    handle_command_queue/_queue_command (api.py ~17458/17310): a FLAT dict
    of device_id -> [raw command strings] — NOT a list of objects. Dispatch
    history lives separately in history.json (see build_history)."""
    return {'ng01': ['exec:systemctl restart nginx'], 'pmx01': ['reboot']}


def build_update_logs() -> dict:
    """Rolling apt/dnf update-run history → update_logs.json. Shape
    verified against the heartbeat ingest (api.py ~15955-15972): {device_id:
    [{started_at,finished_at,exit_code,output,package_manager,triggered_by}]}."""
    def _run(dev_id, offset_days, ok, pm, extra=''):
        started = now() - 86400 * offset_days
        return {'started_at': started, 'finished_at': started + 38,
                'exit_code': 0 if ok else 1,
                'output': (f'Reading package lists...\nBuilding dependency tree...\n'
                           f'{extra or "0 upgraded, 3 newly installed, 0 to remove."}'),
                'package_manager': pm, 'triggered_by': ''}
    return {
        'ng01':  [_run('ng01', 14, True, 'apt'), _run('ng01', 3, True, 'apt')],
        'gt01':  [_run('gt01', 20, True, 'apt'),
                  _run('gt01', 6, False, 'apt', 'E: Unable to fetch some archives.')],
        'pi1':   [_run('pi1', 9, True, 'apt')],
    }


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
    # ── coverage fill: previously-unseeded subsystems (v3.x → v4.7.0) ──
    # v4.7.0 homelab software integrations
    'integrations_state.json':     build_integrations_state,
    # network / agentless
    'snmp_data.json':              build_snmp_data,
    'speedtest.json':              build_speedtest,
    'discovery.json':              build_discovery,
    'tunnels.json':                build_tunnels,
    'satellites.json':             build_satellites,
    # security / scan / compliance
    'secret_findings.json':        build_secret_findings,
    'after_hours_hits.json':       build_after_hours_hits,
    'scans.json':                  build_scans,
    'scan_targets.json':           build_scan_targets,
    'compliance_history.json':     build_compliance_history,
    'apikeys.json':                build_apikeys,
    # service monitoring / images / stacks / custom scripts / SMART trend
    'services.json':               build_services,
    'service_history.json':        build_service_history,
    'image_updates.json':          build_image_updates,
    'compose_stacks.json':         build_compose_stacks,
    'helm.json':                   build_helm,
    'gitops_state.json':           build_gitops_state,
    'custom_scripts.json':         build_custom_scripts,
    'smart_history.json':          build_smart_history,
    'gpu_history.json':            build_gpu_history,
    'thermal_history.json':        build_thermal_history,
    'dmarc_targets.json':          build_dmarc_targets,
    'dmarc_results.json':          build_dmarc_results,
    'ip_reputation_targets.json':  build_ip_reputation_targets,
    'ip_reputation_results.json':  build_ip_reputation_results,
    'resolver_health_targets.json': build_resolver_health_targets,
    'resolver_health_results.json': build_resolver_health_results,
    # runbooks / automation / maintenance / inbound webhooks / misc
    'runbooks.json':               build_runbooks,
    'automation_rules.json':       build_automation_rules,
    'maintenance.json':            build_maintenance,
    'inbound_webhooks.json':       build_inbound_webhooks,
    'cmd_library.json':            build_cmd_library,
    'ai_usage.json':               build_ai_usage,
    'rollouts.json':               build_rollouts,
    # v5.1–v5.6 opt-in subsystems (enabled in build_config so the demo shows
    # them populated instead of an empty "not configured" page).
    'tickets.json':                build_tickets,
    'contacts.json':               build_contacts,
    'kb.json':                     build_kb,
    'blueprints.json':             build_blueprints,
    'time_entries.json':           build_time_entries,
    'billing.json':                build_billing,
    'invoices.json':               build_invoices,
    'timesheet_watch.json':        build_timesheet_watch,
    'vpn.json':                    build_vpn,
    'schedule.json':               build_schedule,
    'calendar.json':               build_calendar,
    'dmarc_reports.json':          build_dmarc_reports,
    'alert_mutes.json':            build_alert_mutes,
    'app_catalog_custom.json':     build_app_catalog_custom,
    'scan_schedules.json':         build_scan_schedules,
    'scap.json':                   build_scap,
    # ── v6.1.0 coverage fill ──────────────────────────────────────────────
    'tasks.json':                  build_tasks,
    'racks.json':                  build_racks,
    'subnets.json':                build_subnets,
    'device_profiles.json':        build_device_profiles,
    'smart_groups.json':           build_smart_groups,
    'backup_state.json':           build_backup_state,
    'mailflow_state.json':         build_mailflow_state,
    'ct_watch.json':               build_ct_watch,
    'patch_age.json':              build_patch_age,
    'image_cves.json':             build_image_cves,
    'cve_campaigns.json':          build_cve_campaigns,
    'lldp_neighbors.json':         build_lldp_neighbors,
    'sudo_log.json':               build_sudo_log,
    'incidents.json':              build_incidents,
    'commands.json':               build_commands,
    'update_logs.json':            build_update_logs,
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

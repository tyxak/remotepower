#!/usr/bin/env python3
"""seed-uptime.py — back-fill 7 days of synthetic uptime history.

The Fleet roster's 7-day status stripe is derived from
``/var/lib/remotepower/uptime.json``. RemotePower only records events
from agent heartbeats, so a freshly-deployed server (or one upgraded
from before the uptime tracker existed) will show "unknown" for every
device's status until real history accumulates. This script seeds
synthetic "up" events at the start of each of the past 7 days for
every (monitored) device, with a "down" blip optionally inserted in
the middle to make the stripe look realistic rather than perfectly
green.

Once real heartbeats resume, ``_record_uptime_event`` will continue
appending — the synthetic history is preserved and naturally ages out
of the 7-day window after a week. No "transition" code path is needed:
the same handler renders both fake and real events identically.

Usage::

    sudo -u www-data python3 packaging/seed-uptime.py --apply

By default, all monitored agented devices get seeded. Pass ``--device-id``
one or more times to limit. ``--realistic`` inserts one short down blip
per device on a random day (otherwise every day shows a clean "up").

Re-running is safe: if a device already has events spanning the 7-day
window, this script skips it. Pass ``--force`` to overwrite anyway.
"""

import argparse
import hashlib
import json
import os
import random
import sys
import time
from pathlib import Path


DEFAULT_DATA_DIR = Path('/var/lib/remotepower')


def _load(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _save_atomic(path: Path, data: dict) -> None:
    """Atomic write with the same pattern api.py uses: temp file in the same
    directory, fsync, rename. Owner/group preserved by writing as the
    current user — script must be run as the CGI user (www-data).
    """
    tmp = path.with_suffix(path.suffix + f'.tmp.{os.getpid()}.{random.randint(0, 1<<32)}')
    try:
        tmp.write_text(json.dumps(data, indent=2))
        os.replace(str(tmp), str(path))
    finally:
        if tmp.exists():
            try: tmp.unlink()
            except OSError: pass


def _seeded_random(*key) -> random.Random:
    """Deterministic per-device randomness — re-running produces the same
    synthetic history. Makes the script idempotent."""
    h = hashlib.sha256(repr(key).encode()).hexdigest()
    return random.Random(int(h[:16], 16))


def _build_events(dev_id: str, now: int, realistic: bool) -> list:
    """Generate a synthetic event series spanning the past 7 days.

    One 'up' transition at midnight of each of the past 7 days, plus a
    closing 'up' a few minutes before `now` so the device is currently
    online. With ``--realistic``, one randomly-placed short outage per
    device is inserted (down → up bracket).
    """
    DAY = 86400
    today_start = now - (now % DAY)
    events = []
    rng = _seeded_random(dev_id, 'uptime')
    # Pick a random day in [0..5] (skip today) for the optional outage
    blip_day_idx = rng.randint(0, 5) if realistic else -1
    for i in range(7):
        day_start = today_start - (6 - i) * DAY
        # Slight jitter so the event timeline doesn't all look like
        # midnight-on-the-dot — implausible
        offset = rng.randint(60, 1800)
        events.append({'ts': day_start + offset, 'online': True})
        if i == blip_day_idx:
            # 5–25 minute outage somewhere in the day
            outage_start = day_start + rng.randint(7200, 64800)
            outage_dur   = rng.randint(300, 1500)
            events.append({'ts': outage_start,                'online': False})
            events.append({'ts': outage_start + outage_dur, 'online': True})
    # Final event: device is currently online (≤ 60s ago — within ttl)
    events.append({'ts': now - 30, 'online': True})
    return events


def _already_seeded(record: dict, now: int) -> bool:
    """Heuristic: does this device already have events spanning the full
    7-day window? If so, skip unless --force."""
    DAY = 86400
    events = (record or {}).get('events') or []
    if not events:
        return False
    oldest = min(e.get('ts', 0) for e in events)
    return (now - oldest) >= (7 * DAY - 3600)   # within an hour of full coverage


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--data-dir', default=str(DEFAULT_DATA_DIR),
                   help=f'RemotePower data directory (default: {DEFAULT_DATA_DIR})')
    p.add_argument('--apply', action='store_true',
                   help='Actually write uptime.json (default is dry-run)')
    p.add_argument('--device-id', action='append', default=[],
                   help='Limit to specific device(s); repeatable. Default: all monitored.')
    p.add_argument('--realistic', action='store_true',
                   help='Insert one short outage per device on a random day')
    p.add_argument('--force', action='store_true',
                   help='Overwrite even if a device already has 7d of events')
    p.add_argument('--quiet', action='store_true',
                   help='Suppress per-device output')
    args = p.parse_args()

    data_dir = Path(args.data_dir)
    if not data_dir.exists():
        print(f'ERROR: data dir does not exist: {data_dir}', file=sys.stderr)
        sys.exit(1)

    devices_file = data_dir / 'devices.json'
    uptime_file  = data_dir / 'uptime.json'

    devices = _load(devices_file)
    if not devices:
        print(f'ERROR: no devices found in {devices_file}', file=sys.stderr)
        sys.exit(1)

    uptime = _load(uptime_file)
    now = int(time.time())

    targets = []
    for dev_id, dev in devices.items():
        if not isinstance(dev, dict):
            continue
        if args.device_id and dev_id not in args.device_id:
            continue
        if dev.get('agentless'):
            continue                           # agentless devices have no heartbeats
        if not dev.get('monitored', True):
            continue                           # respect the monitored flag
        targets.append((dev_id, dev))

    if not targets:
        print('ERROR: no matching devices to seed', file=sys.stderr)
        sys.exit(1)

    seeded, skipped = [], []
    for dev_id, dev in targets:
        existing = uptime.get(dev_id) or {}
        if _already_seeded(existing, now) and not args.force:
            skipped.append(dev_id)
            if not args.quiet:
                print(f'  skip {dev_id} ({dev.get("name")}) — already has 7d coverage')
            continue
        events = _build_events(dev_id, now, args.realistic)
        if args.apply:
            uptime[dev_id] = {
                'name':   dev.get('name', dev_id),
                'events': events,
            }
        seeded.append(dev_id)
        if not args.quiet:
            print(f'  seed {dev_id} ({dev.get("name")}) — {len(events)} events')

    if args.apply:
        _save_atomic(uptime_file, uptime)
        print(f'\nWrote {len(seeded)} device(s) to {uptime_file}')
        if skipped:
            print(f'Skipped {len(skipped)} already-seeded device(s); pass --force to overwrite')
    else:
        print(f'\nWould seed {len(seeded)} device(s). Re-run with --apply.')
        if skipped:
            print(f'Would skip {len(skipped)} already-seeded device(s); --force would overwrite')


if __name__ == '__main__':
    main()

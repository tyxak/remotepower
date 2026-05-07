#!/usr/bin/env python3
"""recover-corrupted-json.py — fix files corrupted by the v1.12.0 race.

Symptom: a JSON file in /var/lib/remotepower/ that fails to parse with
"Extra data: line N column M (char K)". Cause: two CGI processes wrote
to the same .tmp filename concurrently; their bytes interleaved.

This script trims the trailing garbage off any such file and recovers
the leading valid JSON document. Makes a backup before doing anything.

Usage:
    sudo -u www-data python3 recover-corrupted-json.py [--apply] [PATH ...]

Without paths: scans /var/lib/remotepower/*.json for corruption.
Without --apply: dry-run, just shows what would happen.
With --apply: actually overwrites the corrupted files.

v1.12.1 added flock-based serialisation around save() so this race
can't happen again. This tool is for cleaning up after the original
v1.12.0 incident.
"""

import argparse
import json
import shutil
import sys
import time
from pathlib import Path


def try_recover(path: Path):
    """Return (status, data_or_None, garbage_bytes).

    status is one of:
        'ok'         — file parses cleanly, no recovery needed
        'recovered'  — leading JSON parses, trailing garbage exists
        'unrecover'  — first bytes don't form a valid JSON object
        'missing'    — file doesn't exist
    """
    if not path.exists():
        return ('missing', None, 0)

    raw = path.read_text()

    try:
        data = json.loads(raw)
        return ('ok', data, 0)
    except json.JSONDecodeError:
        pass

    # Try raw_decode — this returns the first valid JSON and the index
    # where it ended. If there's trailing garbage, this still succeeds
    # (regular json.loads doesn't, because it requires the whole input
    # to be one document).
    decoder = json.JSONDecoder()
    try:
        data, end = decoder.raw_decode(raw)
        return ('recovered', data, len(raw) - end)
    except json.JSONDecodeError:
        return ('unrecover', None, 0)


def main():
    p = argparse.ArgumentParser(description='Recover JSON files corrupted by the v1.12.0 race')
    p.add_argument('paths', nargs='*', help='Files to check (default: /var/lib/remotepower/*.json)')
    p.add_argument('--apply', action='store_true', help='Actually fix files (default is dry-run)')
    p.add_argument('--data-dir', default='/var/lib/remotepower',
                   help='Where to look for *.json (default: /var/lib/remotepower)')
    args = p.parse_args()

    if args.paths:
        files = [Path(x) for x in args.paths]
    else:
        files = sorted(Path(args.data_dir).glob('*.json'))

    if not files:
        print(f"No JSON files to check in {args.data_dir}.")
        return 0

    needs_action = []
    for path in files:
        status, data, trash = try_recover(path)
        if status == 'ok':
            continue   # quiet on the happy path
        if status == 'missing':
            print(f"  {path}: missing (skipped)")
            continue
        if status == 'unrecover':
            print(f"✗ {path}: completely unparseable — manual intervention needed")
            continue
        # status == 'recovered'
        size = path.stat().st_size
        print(f"⚠  {path}: {trash} bytes of trailing garbage (file is {size} bytes)")
        if isinstance(data, dict):
            print(f"   Recovered dict with {len(data)} entries")
        elif isinstance(data, list):
            print(f"   Recovered list with {len(data)} items")
        else:
            print(f"   Recovered {type(data).__name__}")
        needs_action.append((path, data))

    if not needs_action:
        print("\n✓ All files clean.")
        return 0

    if not args.apply:
        print(f"\n{len(needs_action)} file(s) need recovery. Re-run with --apply to fix.")
        return 0

    # Apply mode
    ts = int(time.time())
    print()
    for path, data in needs_action:
        backup = path.with_name(f'{path.name}.broken-{ts}')
        shutil.copy2(str(path), str(backup))
        with path.open('w') as f:
            json.dump(data, f, indent=2)
        print(f"✓ {path}: fixed (backup → {backup.name})")
    print(f"\nRecovered {len(needs_action)} file(s).")
    return 0


if __name__ == '__main__':
    sys.exit(main())

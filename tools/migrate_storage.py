#!/usr/bin/env python3
"""
RemotePower storage migration — flat JSON  <->  SQLite (CLI wrapper).

The migration logic lives in server/cgi-bin/storage.py so the in-app migrate
endpoint and this CLI share one code path. This wrapper just parses args and
calls storage.migrate_run().

Usage:
    tools/migrate_storage.py --to sqlite [--data-dir /var/lib/remotepower]
    tools/migrate_storage.py --to json   [--data-dir ...]
    tools/migrate_storage.py --to sqlite --dry-run
    tools/migrate_storage.py --to sqlite --verify-only

A mandatory pre-migration snapshot (unless --no-snapshot) is written to
<data-dir>/backups/ for rollback. Exit code is non-zero on verification
mismatch — the active backend is only switched after verification passes.
"""

import os
import sys
import json
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))
import storage  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(description='Migrate RemotePower storage backend.')
    ap.add_argument('--to', dest='target', required=True,
                    choices=['json', 'sqlite'], help='target backend')
    ap.add_argument('--data-dir',
                    default=os.environ.get('RP_DATA_DIR', '/var/lib/remotepower'))
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--verify-only', action='store_true')
    ap.add_argument('--no-snapshot', action='store_true',
                    help='skip the pre-migration snapshot (not recommended)')
    ap.add_argument('--no-flip', action='store_true',
                    help='migrate data but do not switch the active backend')
    args = ap.parse_args(argv)

    storage.configure(args.data_dir)
    result = storage.migrate_run(
        args.data_dir, args.target,
        dry_run=args.dry_run, verify_only=args.verify_only,
        do_snapshot=not args.no_snapshot, flip=not args.no_flip,
        log=print)
    print(json.dumps(result, indent=2))
    return 0 if result.get('ok') else 1


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""
RemotePower storage migration — flat JSON <-> SQLite <-> PostgreSQL (CLI).

The migration logic lives in the server code so the in-app migrate endpoint,
the Docker entrypoint's auto-migration and this CLI share one code path:
  * JSON <-> SQLite:   storage.migrate_run()
  * to/from Postgres:  api._migrate_storage_pg()  (v6.3.0: now reachable here —
    previously the ONLY supported paths onto the enterprise Postgres backend
    were a fresh install-server.sh or the Docker entrypoint, so an existing
    JSON/SQLite install had no upgrade path.)

Usage:
    tools/migrate_storage.py --to sqlite   [--data-dir /var/lib/remotepower]
    tools/migrate_storage.py --to json     [--data-dir ...]
    tools/migrate_storage.py --to postgres --dsn 'postgresql://rp:pw@127.0.0.1/remotepower'
    tools/migrate_storage.py --to sqlite --dry-run
    tools/migrate_storage.py --to sqlite --verify-only

Stop the app server (and scheduler/scanner) before migrating; restart after.
A mandatory pre-migration snapshot (unless --no-snapshot; JSON/SQLite paths
only) is written to <data-dir>/backups/ for rollback. Exit code is non-zero on
verification mismatch — the active backend is only switched after
verification passes.
"""

import os
import sys
import json
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))
import storage  # noqa: E402


def _load_api(data_dir):
    """exec api.py against `data_dir` — needed for the Postgres migration path
    (api._migrate_storage_pg), which the docker entrypoint uses the same way."""
    import importlib.util
    os.environ['RP_DATA_DIR'] = str(data_dir)
    cgi = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
    spec = importlib.util.spec_from_file_location('api_migrate_cli', cgi / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main(argv=None):
    ap = argparse.ArgumentParser(description='Migrate RemotePower storage backend.')
    ap.add_argument('--to', dest='target', required=True,
                    choices=['json', 'sqlite', 'postgres'], help='target backend')
    ap.add_argument('--data-dir',
                    default=os.environ.get('RP_DATA_DIR', '/var/lib/remotepower'))
    ap.add_argument('--dsn', default=os.environ.get('RP_PG_DSN', ''),
                    help="Postgres DSN — required for --to postgres "
                         "(e.g. postgresql://rp:pw@127.0.0.1/remotepower)")
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--verify-only', action='store_true')
    ap.add_argument('--no-snapshot', action='store_true',
                    help='skip the pre-migration snapshot (not recommended; '
                         'JSON/SQLite paths only)')
    ap.add_argument('--no-flip', action='store_true',
                    help='migrate data but do not switch the active backend '
                         '(JSON/SQLite paths only)')
    args = ap.parse_args(argv)

    src = (storage.read_marker(args.data_dir) or {}).get('backend', 'json')
    if args.target == src and not args.verify_only:
        print(f"active backend is already '{src}' — nothing to migrate "
              f"(use --verify-only to re-check integrity)")
        return 0

    # Postgres on either side goes through api._migrate_storage_pg — the same
    # code path the in-app endpoint and the Docker entrypoint use.
    if args.target == 'postgres' or src == 'postgres':
        if args.target == 'postgres' and not args.dsn:
            ap.error('--to postgres requires --dsn (or RP_PG_DSN in the environment)')
        if args.no_snapshot or args.no_flip:
            print('note: --no-snapshot/--no-flip are not supported on the '
                  'Postgres path (it verifies before flipping, atomically)')
        api = _load_api(args.data_dir)
        result = api._migrate_storage_pg(args.target, args.dsn,
                                         dry_run=args.dry_run,
                                         verify_only=args.verify_only,
                                         log=print)
    else:
        storage.configure(args.data_dir)
        result = storage.migrate_run(
            args.data_dir, args.target,
            dry_run=args.dry_run, verify_only=args.verify_only,
            do_snapshot=not args.no_snapshot, flip=not args.no_flip,
            log=print)
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get('ok') else 1


if __name__ == '__main__':
    sys.exit(main())

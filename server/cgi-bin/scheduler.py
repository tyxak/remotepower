"""RemotePower — Phase-5 "keystone" Stage D: out-of-band maintenance scheduler.

Runs api.py's ~33 ``run_*_if_due`` maintenance sweeps on a fixed interval from a
DEDICATED process instead of piggy-backing on request traffic. Two wins:

  * maintenance runs even with **zero** UI/agent traffic (the CGI model only runs
    the cadence when a request happens to arrive), and
  * a **leader lock** means N app nodes don't each double-run the sweeps.

It's opt-in and pairs with the request-path guard ``_external_scheduler_active()``:
set ``RP_EXTERNAL_SCHEDULER=1`` (or config ``external_scheduler: true``) so the
request path stops running the cadence, then run this as a systemd service / a
container sidecar — exactly one per deployment is enough, but you may run one per
node for HA (only the leader executes the sweeps):

    RP_EXTERNAL_SCHEDULER=1 RP_DATA_DIR=/var/lib/remotepower python3 scheduler.py

Leave the flag unset and DON'T run this and nothing changes — the request path runs
the cadence as it always has (the default, and the right model for small installs).

Leader election:
  * a host-level OS file lock (flock) in the data dir — coordinates schedulers on
    one host (the SQLite / single-node case), and
  * for multi-node Postgres, a best-effort ``pg_advisory_lock`` so only ONE node's
    scheduler is the global leader.

The sweeps are the SAME functions ``main()`` calls and are individually
``_if_due``-gated + idempotent, so a short poll interval just means "check what's
due"; nothing runs more often than its own cadence.
"""
import fcntl
import os
import sys
import time
import traceback

import api

# The cadence: the run_*_if_due sweeps main() wraps in _safe(...). Every one takes
# no required args. A guardrail test (test_v600_scheduler) asserts this set equals
# the _safe-wrapped set parsed from main(), so a newly-added sweep can't be missed.
CADENCE = (
    'check_offline_webhooks',
    'check_container_webhooks',
    'run_monitors_if_due',
    'run_integrations_if_due',
    'run_vpn_stats_if_due',
    'run_dmarc_imap_if_due',
    'run_ticket_imap_if_due',
    'run_ticket_sla_if_due',
    'run_ticket_schedules_if_due',       # W1-27 recurring tickets
    'run_invoice_reminders_if_due',      # W1-30 overdue-invoice reminders
    'run_patch_sla_if_due',              # W1-33 patch-compliance SLA
    'run_webhook_digests_if_due',        # W2-22 notification digest flush
    'run_reputation_scan_if_due',
    'run_resolver_health_if_due',
    'run_tls_scan_if_due',
    'run_ct_watch_if_due',               # W1-17 certificate-transparency watch
    'run_snmp_polls_if_due',
    'run_agentless_reachability_if_due',
    'run_routeros_update_check_if_due',
    'run_image_scan_if_due',
    'refresh_kev_epss_if_due',
    '_maybe_check_disk_predictions',
    '_maybe_push_metrics',
    '_maybe_gitops_sync',
    'process_schedule',
    'process_backup_jobs',
    'process_autopatch',
    '_maybe_send_scheduled_report',
    '_maybe_send_report_definitions',
    '_maybe_sample_health',
    '_check_health_webhooks',
    '_maybe_sample_compliance',
    '_rollout_tick_if_due',
    '_escalation_tick_if_due',
    'ping_healthchecks_if_due',
    '_run_posture_digest_if_due',
    '_sqlite_maintenance_if_due',
    '_retention_sweep_if_due',
    '_record_self_alive',
)

# A stable 63-bit key for the Postgres advisory lock (multi-node leader election).
_PG_ADVISORY_KEY = 0x52504D41494E       # "RPMAIN"


def run_cadence_once():
    """Run every cadence sweep once, each guarded so one failure can't stop the
    rest (mirrors main()'s _safe). Returns the number that ran without raising."""
    ok = 0
    api._begin_request()                # reset per-call process-local state (no request)
    try:
        for name in CADENCE:
            fn = getattr(api, name, None)
            if fn is None:
                sys.stderr.write(f"[remotepower-scheduler] missing cadence fn: {name}\n")
                continue
            try:
                fn()
                ok += 1
            except Exception as exc:
                sys.stderr.write(f"[remotepower-scheduler] {name} failed: "
                                 f"{exc.__class__.__name__}: {exc}\n")
                traceback.print_exc(file=sys.stderr)
    finally:
        api._end_request()
    return ok


def acquire_host_leader_lock():
    """Host-level leader lock (flock). Returns the open file object (hold it for the
    process lifetime) when this process is the host leader, else None. The fd must
    stay open — closing it releases the lock."""
    path = str(api.DATA_DIR / '.scheduler.lock')
    try:
        fd = open(path, 'w')
    except OSError as e:
        sys.stderr.write(f"[remotepower-scheduler] cannot open lock {path}: {e}\n")
        return None
    try:
        fcntl.flock(fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fd.close()
        return None                     # another scheduler on this host holds it
    try:
        fd.seek(0); fd.truncate(); fd.write(str(os.getpid())); fd.flush()
    except OSError:
        pass
    return fd


def acquire_pg_leader_lock():
    """Best-effort cross-node leader lock via pg_advisory_lock — only when the
    Postgres backend is active. Returns the held connection (keep it open) when this
    node won the lock, the string 'n/a' when PG isn't in use (no cross-node lock
    needed), or None when another node already holds it. Never raises."""
    try:
        if (os.environ.get('RP_STORAGE_BACKEND', '') or '').lower() not in ('pg', 'postgres', 'postgresql'):
            return 'n/a'
        import storage_pg
        conn = storage_pg._new_conn(storage_pg._dsn(), read_write=True)
        with conn.cursor() as cur:
            cur.execute('SELECT pg_try_advisory_lock(%s)', (_PG_ADVISORY_KEY,))
            got = cur.fetchone()
            got = list(got.values())[0] if isinstance(got, dict) else got[0]
        if got:
            return conn                 # keep the connection open to hold the lock
        conn.close()
        return None
    except Exception as e:
        # PG not reachable / psycopg missing: fall back to host-only leadership.
        sys.stderr.write(f"[remotepower-scheduler] pg advisory lock skipped: {e}\n")
        return 'n/a'


def _interval():
    try:
        return max(5, int(os.environ.get('RP_SCHEDULER_INTERVAL', '60') or 60))
    except (TypeError, ValueError):
        return 60


def main():                             # pragma: no cover - the long-running loop
    interval = _interval()
    sys.stderr.write(f"[remotepower-scheduler] starting (interval={interval}s, "
                     f"data_dir={api.DATA_DIR})\n")
    host_lock = None
    pg_lock = None
    while True:
        if host_lock is None:
            host_lock = acquire_host_leader_lock()
        if host_lock is None:
            time.sleep(interval)        # not the host leader — idle + retry
            continue
        if pg_lock is None:
            pg_lock = acquire_pg_leader_lock()
        if pg_lock is None:
            time.sleep(interval)        # another node is the global leader — idle
            continue
        try:
            run_cadence_once()
        except Exception as exc:        # the loop must never die
            sys.stderr.write(f"[remotepower-scheduler] cadence error: {exc}\n")
            traceback.print_exc(file=sys.stderr)
        # v5.6.x: heartbeat so /api/self/status can show the scheduler is actually
        # ALIVE (not merely configured) on the Server-status "Serving" panel.
        try:
            api.save(api.SCHEDULER_STATE_FILE, {
                'ts': int(time.time()), 'pid': os.getpid(),
                'interval': interval, 'host_leader': True,
            })
        except Exception as exc:
            sys.stderr.write(f"[remotepower-scheduler] heartbeat write failed: {exc}\n")
        time.sleep(interval)


if __name__ == '__main__':              # pragma: no cover
    main()

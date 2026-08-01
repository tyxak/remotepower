"""RemotePower — metric and thermal roll-up folding + the two tiered read
endpoints.

A bound-module carve-out of api.py's roll-up subsystem, following the
tls_ct_handlers / dmarc_handlers / rack_ipam_handlers / attention_handlers
pattern:

  - api.py execs a PRIVATE instance and binds its own ``globals()`` here, so
    every api service is reached as ``A.<name>`` — a DYNAMIC attribute lookup,
    which keeps the test suite's monkeypatching of api.respond / api.load /
    api.save working, and resolves identically under the CGI (__main__) and
    imported-module (wsgi.py/scheduler.py) models.
  - api.py then from-imports every public + private name back into its own
    globals, so the route tables, main()'s _safe() cadence and scheduler.py's
    CADENCE tuple keep resolving the names unchanged, and the behavioural tests
    that call api.run_metric_rollup_if_due / api._rollup_merge see them.
  - Calls BETWEEN these functions ALSO go through ``A.`` so a test that patches
    one of them is seen by its caller (ai_triage_handlers already reaches
    ``A._rollup_read_shape`` this way).

Constants stay in api.py and are read here through A: _ROLLUP_KEYS,
_THERMAL_ROLLUP_KEYS, METRIC_ROLLUP_INTERVAL, THERMAL_ROLLUP_INTERVAL,
ROLLUP_{5MIN,HOURLY,DAILY}_{SEC,KEEP}, METRICS_ROLLUP_FILE and
THERMAL_ROLLUP_FILE. The raw-sample reader for the metric side
(_raw_metric_samples) also stays in api.py, next to the metrics window it
derives from, and is reached as A._raw_metric_samples.

NB the ``keys=`` defaults: a default argument is evaluated at def time, which
is BEFORE bind() runs, so ``keys=_ROLLUP_KEYS`` cannot be spelled here. The
default is None and resolved to A._ROLLUP_KEYS in the body — behaviourally
identical for every caller (no call site passes keys=None).
"""
import time
import urllib.parse


class _ApiNamespace:
    __slots__ = ('_g',)

    def __init__(self, g):
        self._g = g

    def __getattr__(self, name):
        try:
            return self._g[name]
        except KeyError:
            raise AttributeError(f'api namespace has no {name!r}') from None


A = None


def bind(api_globals):
    """Called once per api instance, with api's ``globals()``."""
    global A
    A = _ApiNamespace(api_globals)


# ─── W4-10: long-term metric roll-ups ────────────────────────────────────────
# The raw metrics.json window holds only the last MAX_METRICS (~24h) samples per
# device. This folds those raw points, incrementally, into hourly (kept 30d) and
# daily (kept 2y) aggregate buckets with min/avg/max per series — an ADDITIVE
# read path; the raw store is untouched. Buckets store sum+n internally so a
# later run can extend a partial bucket without re-reading raw history.
# The key tuples, tier widths and retention constants stay in api.py (A.).


def _rollup_merge(buckets, samples, bucket_sec, keys=None):
    """Fold raw {ts, <series>…} samples into aggregate buckets keyed by
    bucket-start ts. Each bucket keeps, per series, {min,sum,max,n} so avg is
    derivable and a partial bucket can be extended on a later run. Returns the
    merged bucket list sorted by ts. Pure.

    `keys` is the series tuple to fold — _ROLLUP_KEYS (cpu/mem/swap/disk) for the
    metric roll-up, _THERMAL_ROLLUP_KEYS (temp) for the thermal one. It defaults
    to the metric set so every existing 3-arg call site is unchanged."""
    if keys is None:
        keys = A._ROLLUP_KEYS
    by = {b['ts']: b for b in (buckets or [])}
    for s in samples or []:
        try:
            ts = int(s.get('ts'))
        except (TypeError, ValueError):
            continue
        if ts <= 0:
            continue
        bstart = ts - (ts % bucket_sec)
        b = by.get(bstart)
        if b is None:
            b = {'ts': bstart}
            by[bstart] = b
        for k in keys:
            v = s.get(k)
            if not isinstance(v, (int, float)):
                continue
            agg = b.get(k)
            if agg is None:
                b[k] = {'min': v, 'sum': float(v), 'max': v, 'n': 1}
            else:
                agg['min'] = min(agg['min'], v)
                agg['max'] = max(agg['max'], v)
                agg['sum'] += v
                agg['n'] += 1
    return sorted(by.values(), key=lambda b: b['ts'])


def _rollup_prune(buckets, keep_sec, now):
    cutoff = now - keep_sec
    return [b for b in buckets if b.get('ts', 0) >= cutoff]


def _rollup_read_shape(buckets, keys=None):
    """Public per-point shape: {ts, cpu:{min,avg,max}, …} (avg = sum/n).
    `keys` selects the series, as in _rollup_merge — the thermal roll-up reuses
    this shaper with _THERMAL_ROLLUP_KEYS so both endpoints answer in one shape."""
    if keys is None:
        keys = A._ROLLUP_KEYS
    out = []
    for b in buckets or []:
        row = {'ts': b.get('ts')}
        for k in keys:
            agg = b.get(k)
            if agg and agg.get('n'):
                row[k] = {'min': round(agg['min'], 2),
                          'avg': round(agg['sum'] / agg['n'], 2),
                          'max': round(agg['max'], 2)}
        out.append(row)
    return out


def run_metric_rollup_if_due():
    """W4-10 cadence: fold each device's new raw metric samples into hourly/daily
    roll-up stores. Cheap + idempotent — only samples newer than the per-device
    high-water mark are folded, and buckets outside the retention window pruned.

    v6.1.1 (#21 follow-up, adversarial self-review): _rollup_prune is a real
    age-based DELETION of historical metric data, but this cadence sweep ran
    entirely independent of _purge_old_data's litigation-hold gate -- the
    hold's own docstring calls _purge_old_data "the single choke point," which
    was false for this sweep. While a hold is active, new samples still fold
    in (purely additive, preserves MORE evidence, never a problem to keep),
    but pruning is skipped so no aggregated history is destroyed."""
    now = int(time.time())
    # v6.1.2 (perf #5): read ONLY the _meta row for the is-it-due? check. This is
    # a cadence gate — it runs on every request — and it used to load()+parse the
    # whole fleet's hourly+daily rollup history just to read one integer, on the
    # NOT-due path, which is the path taken ~99% of the time.
    meta = A._entity_read_one(A.METRICS_ROLLUP_FILE, '_meta', {}) or {}
    if not isinstance(meta, dict):
        meta = {}
    if now - int(meta.get('last_run', 0) or 0) < A.METRIC_ROLLUP_INTERVAL:
        return
    _hold = A._litigation_hold_active()
    devices = A.load(A.DEVICES_FILE) or {}
    # v6.1.2: hold the lock across the read-modify-write. This was a bare
    # load()/mutate/save() RMW, harmless while save() overwrote the whole cold
    # blob — but promoting metrics_rollup.json to an ENTITY store changed save()
    # to a reconcile-with-DELETE (it drops any device row absent from the passed
    # dict). This sweep is the only writer today, so there is no live race; the
    # lock keeps it that way, so a future per-device rollup writer can't have its
    # row deleted by a concurrent full-set save here.
    with A._LockedUpdate(A.METRICS_ROLLUP_FILE) as state:
        # v6.4.2: claim the slot — advance the due-stamp INSIDE the lock, BEFORE
        # any work. It used to be written only on the folded-something path
        # (`if changed or not meta`), so on an idle fleet (all-agentless/SNMP
        # hosts, a fleet-wide agent outage, metrics history off) nothing folded,
        # the stamp kept its original value, and the gate above stayed
        # permanently open — this locked O(fleet) sweep then ran on EVERY cadence
        # tick, i.e. one METRICS_ROLLUP_FILE write lock per request when the
        # out-of-band scheduler is disabled. Re-reading the stamp under the lock
        # also stops two workers double-sweeping the same hour.
        prev = state.get('_meta') if isinstance(state.get('_meta'), dict) else {}
        if now - int(prev.get('last_run', 0) or 0) < A.METRIC_ROLLUP_INTERVAL:
            return                      # another worker claimed this slot
        state['_meta'] = {'last_run': now}
        for dev_id in list(devices.keys()):
            rec = state.get(dev_id) if isinstance(state.get(dev_id), dict) else {}
            last_ts = int(rec.get('last_ts', 0) or 0)
            new = A._raw_metric_samples(dev_id, last_ts)
            if not new:
                continue
            fivemin = A._rollup_merge(rec.get('fivemin') or [], new, A.ROLLUP_5MIN_SEC)
            hourly = A._rollup_merge(rec.get('hourly') or [], new, A.ROLLUP_HOURLY_SEC)
            daily = A._rollup_merge(rec.get('daily') or [], new, A.ROLLUP_DAILY_SEC)
            state[dev_id] = {
                'last_ts': max([last_ts] + [int(s.get('ts') or 0) for s in new]),
                'fivemin': fivemin if _hold else A._rollup_prune(fivemin, A.ROLLUP_5MIN_KEEP, now),
                'hourly':  hourly if _hold else A._rollup_prune(hourly, A.ROLLUP_HOURLY_KEEP, now),
                'daily':   daily if _hold else A._rollup_prune(daily, A.ROLLUP_DAILY_KEEP, now),
            }
        # prune roll-ups for deleted devices
        for k in [k for k in state.keys() if k != '_meta' and k not in devices]:
            del state[k]


def handle_device_metric_rollup(dev_id):
    """GET /api/devices/<id>/metrics/rollup?tier=fivemin|hourly|daily —
    aggregated metric series (min/avg/max per bucket). Auth: require_auth,
    scoped. Complements the raw /metrics-history read: fivemin (~8d) is the
    incident-zoom band between raw-24h and hourly-30d; daily keeps ~2y."""
    A.require_auth()
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'Device not found'})
    scope = A._caller_scope()
    if scope is not None:
        dev = A.device_get(dev_id) or {}
        if not A._device_in_scope(scope, dev):
            A.respond(403, {'error': 'Device outside your role scope'})
    qs = urllib.parse.parse_qs(A._env('QUERY_STRING', '') or '')
    tier = (qs.get('tier') or ['daily'])[0]
    if tier not in ('fivemin', 'hourly', 'daily'):
        tier = 'daily'
    # v6.1.2 (perf #5): metrics_rollup is an ENTITY store now, so answering for
    # ONE device is one row read. It used to load()+parse the WHOLE fleet's
    # hourly(30d)+daily(2y) history to serve a single host's chart — the store
    # grows O(devices x 2 years), so that only ever got worse.
    rec = A._entity_read_one(A.METRICS_ROLLUP_FILE, dev_id, {}) or {}
    A.respond(200, {'device_id': dev_id, 'tier': tier,
                    'points': A._rollup_read_shape(rec.get(tier) or [])})


# ─── v6.4.2: long-range THERMAL roll-ups ─────────────────────────────────────
# Same shape, same machinery, one series. THERMAL_HIST_FILE is a
# MAX_TEMP_SAMPLES ring (~24h at the ~5-min hardware cadence) — the Thermal
# page's column is literally headed "Trend (~24h)" because that is all there
# was. This folds those samples into the metric roll-up's fivemin/hourly/daily
# tiers so "was this host running this hot last month?" is answerable.
def _raw_temp_samples(hist_rec, since_ts):
    """Hottest-temperature samples newer than since_ts for ONE device, from its
    THERMAL_HIST_FILE ring record ({'samples': [{ts, temp}, …]}). Defensive about
    the record shape: the ring is written by _maybe_sample_temp but read here
    long after, and a hand-edited / half-migrated store must not abort the
    fleet-wide sweep."""
    out = []
    for s in (hist_rec or {}).get('samples') or []:
        if not isinstance(s, dict) or not isinstance(s.get('temp'), (int, float)):
            continue
        try:
            ts = int(s.get('ts'))
        except (TypeError, ValueError):
            continue
        if ts > since_ts:
            out.append(s)
    return out


def run_thermal_rollup_if_due():
    """v6.4.2 cadence: fold each device's new hottest-temperature samples into
    fivemin/hourly/daily roll-up buckets, exactly as run_metric_rollup_if_due
    does for cpu/mem/swap/disk. Cheap + idempotent — only samples newer than the
    per-device high-water mark are folded. Purely ADDITIVE: THERMAL_HIST_FILE's
    288-sample ring and the fleet sparkline that reads it are untouched.

    Litigation hold (the v6.1.1 rule run_metric_rollup_if_due documents):
    _rollup_prune is a real age-based DELETION of historical data, so it is
    skipped while a hold is active. Folding still runs — it is additive and
    preserves MORE evidence, which is never a problem to keep."""
    now = int(time.time())
    # Cadence gate: read ONLY the _meta row. This runs on EVERY request, so the
    # not-due path must not load()+parse the whole fleet's thermal history to
    # read one integer (the mistake perf #5 fixed for the metric roll-up).
    meta = A._entity_read_one(A.THERMAL_ROLLUP_FILE, '_meta', {}) or {}
    if not isinstance(meta, dict):
        meta = {}
    if now - int(meta.get('last_run', 0) or 0) < A.THERMAL_ROLLUP_INTERVAL:
        return
    _hold = A._litigation_hold_active()
    devices = A.load(A.DEVICES_FILE) or {}
    hist = A.load(A.THERMAL_HIST_FILE) or {}
    # Hold the lock across the read-modify-write: this is an ENTITY store, so
    # save() reconciles-with-DELETE (any device row absent from the dict written
    # back is dropped). A bare load/mutate/save would let a concurrent writer's
    # row vanish.
    with A._LockedUpdate(A.THERMAL_ROLLUP_FILE) as state:
        prev = state.get('_meta') if isinstance(state.get('_meta'), dict) else {}
        if now - int(prev.get('last_run', 0) or 0) < A.THERMAL_ROLLUP_INTERVAL:
            return                      # another worker claimed this slot
        # Claim the slot on EVERY path, before any work — NOT only when something
        # folded. A stamp written only on the changed path leaves an idle fleet
        # (no agents reporting temperatures at all) permanently un-gated, so this
        # locked O(fleet) sweep would run on every cadence tick. That exact defect
        # shipped in the metric roll-up; it is not reproduced here.
        state['_meta'] = {'last_run': now}
        for dev_id in list(devices.keys()):
            rec = state.get(dev_id) if isinstance(state.get(dev_id), dict) else {}
            last_ts = int(rec.get('last_ts', 0) or 0)
            new = A._raw_temp_samples(hist.get(dev_id), last_ts)
            if not new:
                continue
            fivemin = A._rollup_merge(rec.get('fivemin') or [], new,
                                      A.ROLLUP_5MIN_SEC, A._THERMAL_ROLLUP_KEYS)
            hourly = A._rollup_merge(rec.get('hourly') or [], new,
                                     A.ROLLUP_HOURLY_SEC, A._THERMAL_ROLLUP_KEYS)
            daily = A._rollup_merge(rec.get('daily') or [], new,
                                    A.ROLLUP_DAILY_SEC, A._THERMAL_ROLLUP_KEYS)
            state[dev_id] = {
                'last_ts': max([last_ts] + [int(s['ts']) for s in new]),
                'fivemin': fivemin if _hold else A._rollup_prune(fivemin, A.ROLLUP_5MIN_KEEP, now),
                'hourly':  hourly if _hold else A._rollup_prune(hourly, A.ROLLUP_HOURLY_KEEP, now),
                'daily':   daily if _hold else A._rollup_prune(daily, A.ROLLUP_DAILY_KEEP, now),
            }
        # prune roll-ups for deleted devices
        for k in [k for k in state.keys() if k != '_meta' and k not in devices]:
            del state[k]


def handle_device_thermal_rollup(dev_id):
    """GET /api/devices/<id>/thermal/rollup?tier=fivemin|hourly|daily —
    aggregated hottest-temperature series (min/avg/max per bucket), in the SAME
    shape as /metrics/rollup so one chart renderer serves both. Auth:
    require_auth, scoped. Complements the raw ~24h thermal ring: fivemin (~8d)
    is the incident-zoom band, hourly keeps 30d, daily ~2y."""
    A.require_auth()
    if not A._validate_id(dev_id):
        A.respond(404, {'error': 'Device not found'})
    scope = A._caller_scope()
    if scope is not None:
        dev = A.device_get(dev_id) or {}
        if not A._device_in_scope(scope, dev):
            A.respond(403, {'error': 'Device outside your role scope'})
    qs = urllib.parse.parse_qs(A._env('QUERY_STRING', '') or '')
    tier = (qs.get('tier') or ['daily'])[0]
    if tier not in ('fivemin', 'hourly', 'daily'):
        tier = 'daily'
    # ENTITY store → answering for one device is one row read, not a parse of the
    # whole fleet's ~2y of buckets.
    rec = A._entity_read_one(A.THERMAL_ROLLUP_FILE, dev_id, {}) or {}
    A.respond(200, {'device_id': dev_id, 'tier': tier,
                    'points': A._rollup_read_shape(rec.get(tier) or [],
                                                   A._THERMAL_ROLLUP_KEYS)})

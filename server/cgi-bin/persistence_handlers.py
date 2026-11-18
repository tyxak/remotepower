"""RemotePower — the autostart inventory of a Windows host and what changed in it (8.0.2)

A bound-module carve-out following the tls_ct_handlers / dmarc_handlers /
rack_ipam_handlers pattern:

  - api.py execs a PRIVATE instance and binds its own ``globals()`` here, so
    every api service is reached as ``A.<name>`` — a DYNAMIC attribute lookup,
    which keeps the test suite's monkeypatching of api.respond / api.save / …
    working, and resolves identically under the CGI (__main__) and
    imported-module (wsgi.py/scheduler.py) models.
  - api.py then from-imports every public + private name back into its own
    globals, so the route tables, main()'s _safe() cadence and scheduler.py's
    CADENCE tuple keep resolving the names unchanged.
  - Calls BETWEEN these functions ALSO go through ``A.`` so a test that patches
    one of them is seen by its caller.

Constants stay in api.py and are read here through A. Pure logic goes in a
sibling module (imported directly, like dmarc_monitor / tls_monitor).
"""


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
    """Called once by api.py right after importing this module, with
    api's ``globals()``."""
    global A
    A = _ApiNamespace(api_globals)


# ── the heartbeat side and the host's page ───────────────────────────────────
# A Windows agent sends its autostart inventory under `sysinfo.persistence` at most every 15 minutes. The server cleans it, compares it with the one it kept for the host,
# writes what is new and what is gone into the host's change log and raises `persistence_added` for what is new (persistence.py says how a snapshot is read, what counts as
# a change and when an alert is due). The record of a host is one row of `persistence.json`: the last inventory by place, the change log, the time of the first inventory
# (the baseline: nothing in it alerts) and the time of the last alert.

import sys

import persistence as P


def _persistence_ingest(dev_id, dev_name, raw, now):
    """Keep the inventory a host's agent sent, log the entries that are new and gone, and raise an alert for the new ones that are due one.

    Called from the heartbeat after the devices lock is released. A snapshot that is not one of this version, or not a map, is dropped; nothing here raises, so a bad one
    cannot fail the heartbeat that carried it. The row is written the way the other per-host stores are (one row, best effort, skipped under lock contention), and the alert
    goes out only once the row that remembers it has been read back: a skipped write leaves the stored inventory as it was, the same new entries show again at the next
    snapshot, and an alert sent for a row that was not kept would be sent a second time."""
    sent = []
    try:
        snap = P.clean_snapshot(raw)
        if snap is None:
            return
        prev = A._entity_read_one(A.PERSISTENCE_FILE, dev_id, {})
        if not isinstance(prev, dict):
            prev = {}  # a row that is not a map is replaced, not read
        rec, _added, _removed = P.apply_snapshot(prev, snap, now)
        due, gone = P.due_alert(rec, now)
        if due or gone:
            P.mark_alerted(rec, due, gone, now)
        A._entity_write_one(A.PERSISTENCE_FILE, dev_id, rec)
        if due:
            kept = A._entity_read_one(A.PERSISTENCE_FILE, dev_id, {}) or {}
            if isinstance(kept, dict) and kept.get("ts") == now and kept.get("alert_ts") == now:
                sent = due
    except Exception as e:
        sys.stderr.write(f"[remotepower] persistence ingest failed dev={dev_id}: {type(e).__name__}: {e}\n")
        return
    if not sent:
        return
    try:
        payload = P.alert_payload(sent)
        payload.update({"device_id": dev_id, "name": dev_name or dev_id})
        A.fire_webhook("persistence_added", payload)
    except Exception as e:
        sys.stderr.write(f"[remotepower] persistence alert failed dev={dev_id}: {type(e).__name__}: {e}\n")


def handle_device_persistence(dev_id):
    """GET /api/devices/<id>/persistence -- the inventory of what starts by itself on this Windows host and the log of what was added and removed (8.0.2).

    Read-only, any signed-in role: it says nothing the host's own page does not already say about the host. The path is under /api/devices/<id>/, so the pre-dispatch
    gate has already refused a host the caller may not see (another tenant's, or outside a scoped role). `persistence` is null for a host that has sent no inventory yet.
    Everything in it was cleaned when it was stored (a host's word is cut, and a password in a command line is replaced); the page writes it as text."""
    A.require_auth()
    if A.method() != "GET":
        A.respond(405, {"error": "Method not allowed"})
    if not A._validate_id(dev_id):
        A.respond(404, {"error": "Host not found"})
    dev = A.device_get(dev_id)
    if not isinstance(dev, dict):
        A.respond(404, {"error": "Host not found"})
    rec = A._entity_read_one(A.PERSISTENCE_FILE, dev_id, None)
    A.respond(200, {"device_id": dev_id, "windows": A._device_os_family(dev) == "windows", "persistence": P.view(rec)})

"""RemotePower: the autostart inventory of a Windows host, and what changed in it (pure).

What starts by itself is where a person who has got in leaves a way back. The Windows agent lists five places in a snapshot at most every 15 minutes: the Run and RunOnce
keys of HKLM (both registry views), the Winlogon Shell and Userinit values, the services whose program sits in a temporary or user folder, the scheduled tasks that are not
Microsoft's, and the startup folders. Nothing is verified: the agent reads paths and names, never a signature.

This module is the one place that says what a snapshot may hold and what a change is. The server cleans every snapshot (it is a host's word and cut to size here, not
trusted), compares it with the one it kept, writes the entries that are new or gone into a change log, and says which new entries are due an alert.

  * The first inventory of a place is its baseline. Nothing in it is a change, so a host that has just enrolled, or whose agent has just been updated to read more, raises
    nothing.
  * A place that could not be read (access denied, out of time) or whose list was cut at its cap is not read whole. The last whole read of it stays the baseline until a
    whole read has been compared with it: a read that was cut, or that failed half way, never replaces it. What such a read still shows is compared with the baseline, and
    an entry in it that the baseline does not hold is new. Nothing is read as removed from a read that was not whole (an empty answer is not "everything was removed", and
    a cut list would report the entries that happen to fall at its edge); removals are found when the place is read whole again. A place that was not read whole three
    inventories in a row is reported once, because the entries past the cut are not seen until then.
  * An entry is its place, its name and what it runs. A changed command is a new entry beside a removed one, so a Run value or a Shell that was pointed at something else is
    a new entry and alerts.
  * An entry that is gone is recorded and does not alert.
  * One alert at most for a host in an hour, and an entry that arrived while the hour was running is not lost: it stays unsent and goes out with the next alert, if it is
    still on the host by then.

Nothing here reads a store or the request.
"""

import re

# the layout of a snapshot; a snapshot of another version is not read, and a changed one starts the baselines again
VERSION = 1
CATEGORIES = ("run", "winlogon", "services", "tasks", "startup")
# entries kept for one place
CAPS = {"run": 100, "winlogon": 4, "services": 100, "tasks": 200, "startup": 100}
FIELD_MAX = (120, 120, 240)  # characters kept of an entry's place, its name and what it runs
WINLOGON_NAMES = ("Shell", "Userinit")
LOG_MAX = 200  # changes kept for a host, the oldest dropped first
# changes of each kind written to the log from one snapshot; the entries past it are counted in `over` (by place), and the alert for the entries that are due counts them too
PER_SNAPSHOT_MAX = 50
ALERT_EVERY_S = 3600  # an alert for a host at most this often
# inventories in a row in which a place was not read whole before the host is told
UNREAD_AFTER = 3
# entries kept beside a baseline for a place that stays cut, as a multiple of its cap
EXTRA_FACTOR = 3
# the count of inventories in a row that did not read a place whole stops here
MISSED_MAX = 1000000
SAMPLE_LINES = 3  # entries an alert quotes
SAMPLE_CHARS = 200
LABELS = {
    "run": "Run key",
    "winlogon": "Winlogon value",
    "services": "service",
    "tasks": "scheduled task",
    "startup": "startup folder file",
}
# the places by name, for the notice that one was not read whole
PLACES = {
    "run": "Run keys",
    "winlogon": "Winlogon values",
    "services": "services",
    "tasks": "scheduled tasks",
    "startup": "startup folders",
}

_HIDDEN = frozenset("­​‌‍‎‏  ‪‫‬‭‮⁠⁦⁧⁨⁩﻿")
_SECRET_NAME = r"(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|apikey|private[_-]?key|client[_-]?secret|access[_-]?key|credential|authorization|auth[_-]?(?:token|key|secret)|bearer)"
# `--password hunter2`, `/token:abc`, `-ApiKey=abc` and `password=abc`: the value goes, the name stays
_SECRET_FLAG = re.compile(
    r"(?i)((?:^|\s)(?:--?|/)[\w.-]*"
    + _SECRET_NAME
    + r"[\w.-]*)(\s*[=:]\s*|\s+)(\"[^\"]*\"|'[^']*'|\S+)"
)
_SECRET_KV = re.compile(
    r"(?i)(\b[\w.-]*" + _SECRET_NAME + r"[\w.-]*)(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)"
)
_URL_CREDENTIAL = re.compile(r"(://[^/\s:@]{1,64}:)[^/\s@]{1,128}(@)")


def clean_text(value, limit):
    """Text from a host for a page or a log: control characters, the line and paragraph separators and the characters that reorder or hide text become spaces, runs of
    white space become one, and it is cut at `limit` characters. Anything that is not text is read as its text, None as nothing.
    """
    s = "" if value is None else str(value)
    s = "".join(" " if (ord(c) < 32 or 0x7F <= ord(c) <= 0x9F or c in _HIDDEN) else c for c in s)
    return " ".join(s.split())[:limit]


def redact_command(text):
    """What a command line says, without a password or a key it carries: the value after a name that looks like a secret, and the password of a URL. Not a guarantee, a
    second line of defence: the Run value of an installer can hold anything, and an alert, a page and an export would repeat it.
    """
    s = _SECRET_FLAG.sub(r"\1\2[REDACTED]", text)
    s = _SECRET_KV.sub(r"\1\2[REDACTED]", s)
    return _URL_CREDENTIAL.sub(r"\1[REDACTED]\2", s)


def _entry(item, category):
    """[place, name, command] cleaned, or None when `item` is not an entry. Two texts are an entry without a command."""
    if isinstance(item, dict):
        item = [item.get("loc"), item.get("name"), item.get("data")]
    if not isinstance(item, (list, tuple)) or len(item) < 2 or len(item) > 3:
        return None
    for part in item:
        if part is not None and not isinstance(part, (str, int, float)):
            return None
    loc = clean_text(item[0], FIELD_MAX[0])
    name = clean_text(item[1], FIELD_MAX[1])
    data = redact_command(clean_text(item[2] if len(item) == 3 else "", FIELD_MAX[2]))[
        : FIELD_MAX[2]
    ]
    if not name:
        return None
    if category == "winlogon" and name not in WINLOGON_NAMES:
        return None
    return [loc, name, data]


def clean_snapshot(raw):
    """A snapshot as a host sent it -> {"v", category: {"ok", "cut", "items"}} for each of the five places, or None when it is not one of this version.

    `ok` is true only when the host says it read the place whole; a place it does not mention is not read. Items are cleaned (see clean_text, redact_command), without
    duplicates, sorted, and cut at the cap of the place (a place over its cap is marked `cut`, whatever the host said).
    """
    if not isinstance(raw, dict):
        return None
    v = raw.get("v")
    if isinstance(v, bool) or v != VERSION:
        return None
    out = {"v": VERSION}
    for cat in CATEGORIES:
        part = raw.get(cat)
        if not isinstance(part, dict):
            out[cat] = {"ok": False, "cut": False, "items": []}
            continue
        items_in = part.get("items") if isinstance(part.get("items"), list) else []
        seen, items = set(), []
        reach = CAPS[cat] * 3  # a host that sends a million rows is read as far as it could matter
        for it in items_in[:reach]:
            e = _entry(it, cat)
            if e is None or tuple(e) in seen:
                continue
            seen.add(tuple(e))
            items.append(e)
        items.sort(key=lambda e: (e[0].lower(), e[1].lower(), e[2]))
        cut = part.get("cut") is True or len(items) > CAPS[cat] or len(items_in) > reach
        out[cat] = {"ok": part.get("ok") is True, "cut": bool(cut), "items": items[: CAPS[cat]]}
    return out


def _is_entry(e):
    return isinstance(e, list) and len(e) == 3 and all(isinstance(x, str) for x in e)


def _stored(place, key="items"):
    """The entries a stored place holds under `key`, without anything that is not an entry (a stored row is read, not trusted)."""
    v = place.get(key) if isinstance(place, dict) else None
    return [e for e in v if _is_entry(e)] if isinstance(v, list) else []


def _count(v):
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else 0


def _reference(old):
    """The entries a new read of a place is compared with, or None when the place has no whole read yet.

    That is the last whole read of it (`base` while cut or failed reads have come since, else `items` of a place whose last read was whole) and the entries those reads
    showed and that were reported as new (`extra`), so that an entry is reported once and not again at every read that is not whole.
    """
    if not isinstance(old, dict):
        return None
    if isinstance(old.get("base"), list):
        base = _stored(old, "base")
    elif old.get("complete") is True:
        base = _stored(old)
    else:
        return None
    return base + _stored(old, "extra")


def apply_snapshot(prev, snap, now):
    """(record, added, removed): the record of a host after a snapshot, and the entries that are new and gone since the one before.

    `prev` is the stored record (anything that is not a map is no record), `snap` a cleaned snapshot. A place read whole is compared with its baseline (the last whole read
    of it and what later reads that were not whole showed) when the layout is the same, and is the baseline from then on. A place that was cut at its cap or could not be
    read whole is compared for what it shows: an entry the baseline does not hold is added. It is not compared for what it lacks, so `removed` only ever comes from a whole
    read, and the baseline stays where it was (`base`) until a whole read has been compared with it. `added` and `removed` are lists of (category, entry).

    For each place the record keeps `items` (what the last read showed, or what the last read that worked showed when the place could not be read), when that was,
    whether it was whole (`complete`), `miss` (the inventories in a row that did not read it whole), `warned` (the host has been told about this stretch), and while
    the place is not read whole the baseline (`base`) and the entries reported since (`extra`).
    """
    prev = prev if isinstance(prev, dict) else {}
    old_inv = prev.get("inv") if isinstance(prev.get("inv"), dict) else {}
    same_layout = prev.get("v") == snap["v"]
    inv, added, removed = {}, [], []
    for cat in CATEGORIES:
        new = snap[cat]
        old = old_inv.get(cat) if same_layout and isinstance(old_inv.get(cat), dict) else None
        ref = _reference(old)
        if new["ok"] and not new["cut"]:
            inv[cat] = {
                "ok": True,
                "complete": True,
                "ts": now,
                "items": new["items"],
                "miss": 0,
                "warned": False,
            }
            if ref is not None:
                now_set, was_set = {tuple(e) for e in new["items"]}, {tuple(e) for e in ref}
                added += [(cat, e) for e in new["items"] if tuple(e) not in was_set]
                removed += [(cat, e) for e in ref if tuple(e) not in now_set]
            continue
        # not read whole: cut at its cap, or it could not be read (what it still shows is compared, never what it lacks)
        was_set = {tuple(e) for e in ref} if ref is not None else set()
        fresh = [e for e in new["items"] if tuple(e) not in was_set] if ref is not None else []
        if new["ok"]:
            state = {"ok": True, "complete": False, "ts": now, "items": new["items"]}
            if ref is not None:
                base = _stored(old, "base") if isinstance(old.get("base"), list) else _stored(old)
                state["base"] = base
        else:
            state = dict(old) if old else {"ts": 0, "complete": False, "items": []}
            state["ok"] = False
            state["items"] = _stored(old)
        extra = (
            (_stored(old, "extra") + fresh)[-CAPS[cat] * EXTRA_FACTOR :] if ref is not None else []
        )
        if extra:
            state["extra"] = extra
        else:
            state.pop("extra", None)
        state["miss"] = min(_count((old or {}).get("miss")) + 1, MISSED_MAX)
        state["warned"] = (old or {}).get("warned") is True
        inv[cat] = state
        added += [(cat, e) for e in fresh]
    log = (
        [e for e in prev.get("log", []) if isinstance(e, dict)]
        if isinstance(prev.get("log"), list)
        else []
    )
    # the new entries past what one snapshot may write to the log are not lost to the alert: they are counted here, by place, until the alert for the entries that were
    # logged goes out. Nothing is carried when no logged entry is waiting for an alert, so a count cannot outlive the entries it was made for.
    over = {}
    if _unsent(log) and isinstance(prev.get("over"), dict):
        over = {c: n for c, n in prev["over"].items() if c in CATEGORIES and _count(n) > 0}
    for op, entries in (("added", added), ("removed", removed)):
        for cat, e in entries[:PER_SNAPSHOT_MAX]:
            log.append(
                {
                    "ts": now,
                    "op": op,
                    "cat": cat,
                    "loc": e[0],
                    "name": e[1],
                    "data": e[2],
                    "alerted": op == "removed",
                }
            )
        if op == "added":
            for cat, _e in entries[PER_SNAPSHOT_MAX:]:
                over[cat] = over.get(cat, 0) + 1
    rec = {
        "v": snap["v"],
        "ts": now,
        "baseline": (
            prev.get("baseline")
            if isinstance(prev.get("baseline"), int) and not isinstance(prev.get("baseline"), bool)
            else now
        ),
        "alert_ts": (
            prev.get("alert_ts")
            if isinstance(prev.get("alert_ts"), int) and not isinstance(prev.get("alert_ts"), bool)
            else 0
        ),
        "inv": inv,
        "log": log[-LOG_MAX:],
    }
    if over:
        rec["over"] = over
    return rec, added, removed


def _unsent(log):
    return [
        e for e in log if isinstance(e, dict) and e.get("op") == "added" and not e.get("alerted")
    ]


def _present(rec, entry):
    """Whether a logged entry is still on the host as far as the last reads say: it is in what the place showed last, or it was reported while the place was not read whole
    and no whole read has been taken since (then nothing says it left)."""
    cat = (rec.get("inv") or {}).get(entry.get("cat")) or {}
    e = [entry.get("loc"), entry.get("name"), entry.get("data")]
    return e in (cat.get("items") or []) or e in (cat.get("extra") or [])


def due_alert(rec, now):
    """(due, gone): the logged entries an alert is due for, and the unsent ones that have left the host since.

    Due is every added entry that was not sent and is still on the host, once the hour since the last alert is over. Nothing is due inside the hour, and nothing is due
    when the log has no unsent entry; `gone` is returned either way so that they can be marked and do not wait for ever.
    """
    pending = _unsent(rec.get("log", []))
    gone = [e for e in pending if not _present(rec, e)]
    live = [e for e in pending if e not in gone]
    last = (
        rec.get("alert_ts")
        if isinstance(rec.get("alert_ts"), int) and not isinstance(rec.get("alert_ts"), bool)
        else 0
    )
    if not live or now - last < ALERT_EVERY_S:
        return [], gone
    return live, gone


def mark_alerted(rec, sent, gone, now):
    """The record with the entries that went out and the ones that left marked as dealt with, and the hour started again if something went out. The count of entries that
    were past the log (`over`) goes out with the alert, so it is cleared with it: read it before this call.
    """
    ids = {id(e) for e in list(sent) + list(gone)}
    for e in rec.get("log", []):
        if id(e) in ids:
            e["alerted"] = True
    if sent:
        rec["alert_ts"] = now
        rec.pop("over", None)
    return rec


def alert_payload(entries, over=None):
    """The facts an alert quotes for these entries: how many, what kinds, and the first few as one line each. All of it was cleaned when it was stored.

    `over` is the record's count of new entries that were past the log (by place): they are counted with the others, so that 80 new entries are 80 in the alert and not the
    50 the log holds. They are not quoted: only the logged ones have a line."""
    kinds = {}
    for e in entries:
        kinds[e["cat"]] = kinds.get(e["cat"], 0) + 1
    for c, k in (over if isinstance(over, dict) else {}).items():
        if c in CATEGORIES and _count(k) > 0:
            kinds[c] = kinds.get(c, 0) + k
    parts = [
        "%d %s" % (n, LABELS.get(c, c) + ("" if n == 1 else "s"))
        for c, n in sorted(
            kinds.items(), key=lambda kv: CATEGORIES.index(kv[0]) if kv[0] in CATEGORIES else 9
        )
    ]
    n = sum(kinds.values())
    detail = "%d new startup %s (%s)" % (n, "entry" if n == 1 else "entries", ", ".join(parts))
    sample = []
    for e in entries[:SAMPLE_LINES]:
        label = LABELS.get(e["cat"], e["cat"])
        line = "%s: %s" % (label[:1].upper() + label[1:], e["name"])
        if e.get("data"):
            line += " = " + e["data"]
        sample.append(line[:SAMPLE_CHARS])
    return {"count": n, "detail": detail, "sample": sample}


def due_unread(rec):
    """The places that were not read whole for UNREAD_AFTER inventories in a row and that the host has not been told about yet: a list of {cat, why, missed}.

    `why` is "cut" when the place was read but held more entries than are kept, and "unread" when it could not be read. The entries past a cut, and what a place that cannot
    be read holds, are not compared, so this is the one thing that says the place is not watched in full. It is due once for a stretch: a whole read starts the count again.
    """
    out = []
    inv = rec.get("inv") if isinstance(rec, dict) and isinstance(rec.get("inv"), dict) else {}
    for cat in CATEGORIES:
        c = inv.get(cat)
        if not isinstance(c, dict) or c.get("warned") is True:
            continue
        missed = _count(c.get("miss"))
        if missed >= UNREAD_AFTER:
            out.append(
                {"cat": cat, "why": "cut" if c.get("ok") is True else "unread", "missed": missed}
            )
    return out


def mark_unread(rec, due):
    """The record with the places that are being reported marked as reported for this stretch."""
    for d in due:
        c = (rec.get("inv") or {}).get(d["cat"])
        if isinstance(c, dict):
            c["warned"] = True
    return rec


def unread_payload(due):
    """The facts an alert quotes for places that were not read whole: how many, and one line for each."""
    n = len(due)
    missed = min((d["missed"] for d in due), default=0)
    names = ", ".join(
        "%s (%s)"
        % (
            PLACES.get(d["cat"], d["cat"]),
            "cut at its limit" if d["why"] == "cut" else "could not be read",
        )
        for d in due
    )
    detail = "%d startup %s not read whole for %d inventories in a row: %s" % (
        n,
        "place was" if n == 1 else "places were",
        missed,
        names,
    )
    sample = []
    for d in due[:SAMPLE_LINES]:
        place = PLACES.get(d["cat"], d["cat"])
        if d["why"] == "cut":
            line = "%s: more entries than the %d that are kept, so the rest are not seen" % (
                place[:1].upper() + place[1:],
                CAPS.get(d["cat"], 0),
            )
        else:
            line = "%s: could not be read" % (place[:1].upper() + place[1:])
        sample.append(line[:SAMPLE_CHARS])
    return {"count": n, "detail": detail, "sample": sample}


def view(rec):
    """What the host's page is given: the inventory by place (entries as maps), the changes newest first, and the times. A record that is not one gives None."""
    if not isinstance(rec, dict) or not isinstance(rec.get("inv"), dict):
        return None
    inv = {}
    for cat in CATEGORIES:
        c = rec["inv"].get(cat) if isinstance(rec["inv"].get(cat), dict) else {}
        inv[cat] = {
            "ok": c.get("ok") is True,
            "complete": c.get("complete") is True,
            "missed": _count(c.get("miss")),
            "ts": (
                c.get("ts")
                if isinstance(c.get("ts"), int) and not isinstance(c.get("ts"), bool)
                else 0
            ),
            "items": [
                {"loc": e[0], "name": e[1], "data": e[2]}
                for e in c.get("items", [])
                if isinstance(e, list) and len(e) == 3
            ],
        }
    changes = [
        {
            "ts": (
                e.get("ts")
                if isinstance(e.get("ts"), int) and not isinstance(e.get("ts"), bool)
                else 0
            ),
            "op": "removed" if e.get("op") == "removed" else "added",
            "cat": e.get("cat") if e.get("cat") in CATEGORIES else "run",
            "loc": str(e.get("loc") or ""),
            "name": str(e.get("name") or ""),
            "data": str(e.get("data") or ""),
            "alerted": e.get("alerted") is True,
        }
        for e in reversed(rec.get("log") or [])
        if isinstance(e, dict)
    ]
    # newest first, and within one inventory what came in before what went out
    changes.sort(key=lambda c: (-c["ts"], c["op"] != "added"))
    return {
        "ts": (
            rec.get("ts")
            if isinstance(rec.get("ts"), int) and not isinstance(rec.get("ts"), bool)
            else 0
        ),
        "baseline": (
            rec.get("baseline")
            if isinstance(rec.get("baseline"), int) and not isinstance(rec.get("baseline"), bool)
            else 0
        ),
        "alert_every_s": ALERT_EVERY_S,
        "inventory": inv,
        "changes": changes,
    }

"""RemotePower: the autostart inventory of a Windows host, and what changed in it (pure).

What starts by itself is where a person who has got in leaves a way back. The Windows agent lists five places in a snapshot at most every 15 minutes: the Run and RunOnce
keys of HKLM (both registry views), the Winlogon Shell and Userinit values, the services whose program sits in a temporary or user folder, the scheduled tasks that are not
Microsoft's, and the startup folders. Nothing is verified: the agent reads paths and names, never a signature.

This module is the one place that says what a snapshot may hold and what a change is. The server cleans every snapshot (it is a host's word and cut to size here, not
trusted), compares it with the one it kept, writes the entries that are new or gone into a change log, and says which new entries are due an alert.

  * The first inventory of a place is its baseline. Nothing in it is a change, so a host that has just enrolled, or whose agent has just been updated to read more, raises
    nothing.
  * A place that could not be read (access denied, out of time) or whose list was cut at its cap is not compared: an empty answer is not "everything was removed", and a
    cut list would report the entries that happen to fall at its edge. It is kept as it was and marked, and what it holds next time it is read whole is its new baseline.
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
# changes of each kind written from one snapshot; the alert still counts them all
PER_SNAPSHOT_MAX = 50
ALERT_EVERY_S = 3600  # an alert for a host at most this often
SAMPLE_LINES = 3  # entries an alert quotes
SAMPLE_CHARS = 200
LABELS = {
    "run": "Run key",
    "winlogon": "Winlogon value",
    "services": "service",
    "tasks": "scheduled task",
    "startup": "startup folder file",
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


def _complete(cat):
    return isinstance(cat, dict) and cat.get("complete") is True


def apply_snapshot(prev, snap, now):
    """(record, added, removed): the record of a host after a snapshot, and the entries that are new and gone since the one before.

    `prev` is the stored record (anything that is not a map is no record), `snap` a cleaned snapshot. A place is compared only when this snapshot and the earlier one
    both read it whole and the layout is the same; otherwise it is stored as it stands and is the baseline from then on. `added` and `removed` are lists of
    (category, entry). The record keeps, for each place, the entries of its last whole read and when that was, so a place that cannot be read is shown as it was.
    """
    prev = prev if isinstance(prev, dict) else {}
    old_inv = prev.get("inv") if isinstance(prev.get("inv"), dict) else {}
    same_layout = prev.get("v") == snap["v"]
    inv, added, removed = {}, [], []
    for cat in CATEGORIES:
        new, old = snap[cat], old_inv.get(cat) if isinstance(old_inv.get(cat), dict) else None
        old_items = (
            [e for e in (old or {}).get("items", []) if isinstance(e, list) and len(e) == 3]
            if old
            else []
        )
        if not new["ok"]:
            kept = dict(old) if old else {"ts": 0, "complete": False, "items": []}
            kept["ok"] = False
            kept["items"] = old_items
            inv[cat] = kept
            continue
        inv[cat] = {"ok": True, "complete": not new["cut"], "ts": now, "items": new["items"]}
        if new["cut"] or not old or not same_layout or not _complete(old):
            continue
        now_set, was_set = {tuple(e) for e in new["items"]}, {tuple(e) for e in old_items}
        added += [(cat, e) for e in new["items"] if tuple(e) not in was_set]
        removed += [(cat, e) for e in old_items if tuple(e) not in now_set]
    log = (
        [e for e in prev.get("log", []) if isinstance(e, dict)]
        if isinstance(prev.get("log"), list)
        else []
    )
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
    return rec, added, removed


def _present(rec, entry):
    cat = (rec.get("inv") or {}).get(entry.get("cat")) or {}
    return [entry.get("loc"), entry.get("name"), entry.get("data")] in (cat.get("items") or [])


def due_alert(rec, now):
    """(due, gone): the logged entries an alert is due for, and the unsent ones that have left the host since.

    Due is every added entry that was not sent and is still on the host, once the hour since the last alert is over. Nothing is due inside the hour, and nothing is due
    when the log has no unsent entry; `gone` is returned either way so that they can be marked and do not wait for ever.
    """
    pending = [
        e
        for e in rec.get("log", [])
        if isinstance(e, dict) and e.get("op") == "added" and not e.get("alerted")
    ]
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
    """The record with the entries that went out and the ones that left marked as dealt with, and the hour started again if something went out."""
    ids = {id(e) for e in list(sent) + list(gone)}
    for e in rec.get("log", []):
        if id(e) in ids:
            e["alerted"] = True
    if sent:
        rec["alert_ts"] = now
    return rec


def alert_payload(entries):
    """The facts an alert quotes for these entries: how many, what kinds, and the first few as one line each. All of it was cleaned when it was stored."""
    kinds = {}
    for e in entries:
        kinds[e["cat"]] = kinds.get(e["cat"], 0) + 1
    parts = [
        "%d %s" % (n, LABELS.get(c, c) + ("" if n == 1 else "s"))
        for c, n in sorted(
            kinds.items(), key=lambda kv: CATEGORIES.index(kv[0]) if kv[0] in CATEGORIES else 9
        )
    ]
    n = len(entries)
    detail = "%d new startup %s (%s)" % (n, "entry" if n == 1 else "entries", ", ".join(parts))
    sample = []
    for e in entries[:SAMPLE_LINES]:
        label = LABELS.get(e["cat"], e["cat"])
        line = "%s: %s" % (label[:1].upper() + label[1:], e["name"])
        if e.get("data"):
            line += " = " + e["data"]
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

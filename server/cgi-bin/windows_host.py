"""What a Windows agent tells the server about the host itself (pure).

Four small facts, each from one probe of the Windows agent (client/remotepower-agent-win.py):

* Windows Update. A Defender definition update is told apart from the updates an operator installs
  (`is_definition_update`), and the outcome of the search is a state of its own (`clean_search_state`):
  when it ran, whether it worked and, when it did not, one word for why.
* The build: the build number, the revision, the display version, the edition, the product name and the
  installation type that the registry keeps (`clean_win_build`, `os_label`).
* The file shares the host exports (`clean_shares`).
* The TPM (`clean_tpm`).

All of it comes from a host and none of it is trusted. A type is checked, a text is capped and stripped of
control characters, a count is a whole number inside a bound, and a word that has to be one of a fixed set
is `unknown` when it is not. Nothing here reads storage, the request or api.py, so checks.py, api.py and the
tests all import it.
"""

from __future__ import annotations

import copy
import re
import time
from typing import Any

from textfmt import plural

MAX_COUNT = 100000
MAX_SHARES = 100  # the shares one host lists; a host with more says so in `count`

# ── Windows Update ────────────────────────────────────────────────────────────────────────────────────
#
# A Defender definition update is a signature file that Windows Update offers several times a day. It is
# not a patch anyone schedules, so counting it put one or two pending updates on every Windows host at all
# times: over every patch threshold, into the patch SLA and into the risk score. Windows names these
# updates like this (the agent's `_is_definition_update` keeps the same rule, and a test holds the two to
# one table of titles):
#
#   Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.405.1070.0)
#   Security Intelligence Update for Windows Defender Antivirus - KB2267602 (Version 1.273.1234.0)
#   Definition Update for Windows Defender Antivirus - KB2267602 (Definition 1.243.123.0)
#   Definition Update for Windows Defender - KB915597 (Definition 1.171.123.0)
#
# The Defender platform update ("Update for Microsoft Defender Antivirus antimalware platform -
# KB4052623") is a program update and is not matched.


def is_definition_update(title: object) -> bool:
    """True for the title of a Defender definition update, and for nothing else (a value that is not text is not one)."""
    if not isinstance(title, str):
        return False
    text = title.lower()
    if "security intelligence update" in text or "kb2267602" in text:
        return True
    return "definition update for" in text and ("defender" in text or "antivirus" in text)


def _count(value: object, cap: int = MAX_COUNT) -> int | None:
    """A whole number from 0 to `cap`, or None. A bool is not a number here."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value <= cap else None


def settle_update_packages(safe_pkg: dict[str, Any], raw: object) -> None:
    """Take the definition updates out of a Windows Update report, in place.

    A current agent has done it already: `upgradable` and `upgradable_names` leave them out and
    `definition_updates` counts them. An older agent sends them with the rest, so a name that is one is
    removed here, the count comes down by one for each, and `definition_updates` counts them, so that
    every reader of the stored count reads the same number whichever agent sent it. A report of another
    manager is left as it is."""
    if safe_pkg.get("manager") != "windows-update":
        return
    reported = _count(raw.get("definition_updates")) if isinstance(raw, dict) else None
    definitions = reported or 0
    names = safe_pkg.get("upgradable_names")
    if isinstance(names, list):
        kept = [n for n in names if not is_definition_update(n)]
        removed = len(names) - len(kept)
        if removed:
            safe_pkg["upgradable_names"] = kept
            count = safe_pkg.get("upgradable")
            if isinstance(count, int):
                safe_pkg["upgradable"] = max(0, count - removed)
            definitions += removed
    safe_pkg["definition_updates"] = min(definitions, MAX_COUNT)


# The search is a state: when it ran, whether it worked, where it asked and, when it failed, why. The words
# are a fixed set; the agent never sends the text of an error.
SEARCH_CLASSES = ("timeout", "access", "service", "network", "unknown")
SEARCH_SOURCES = ("windows-update-agent", "wsus", "unknown")
# How far from the heartbeat a time the agent reports is believed. The search runs just before the report
# is sent, so a time outside this window is a wrong clock and the server's own time is used.
AT_BEFORE = 900
AT_AFTER = 60
# A row of the Checks page turns amber after this many days without a successful search, and red after more.
SEARCH_WARN_DAYS = 3
SEARCH_CRIT_DAYS = 14


MAX_STAMP = 4102444800  # 2100-01-01: a time past it is not a time (and time.gmtime() raises on a number of 30 digits)


def _stamp(value: object) -> int:
    """A stored time as a whole number of seconds from 1970 to 2100, else 0."""
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= MAX_STAMP:
        return 0
    return value


def clean_search_state(raw: object, now: int, prev_si: object = None) -> dict[str, Any] | None:
    """The state of the last Windows Update search, as it is stored with the host; None when the agent
    did not send one it can be trusted with (no state, or `ok` that is not a true or false).

    `ok_at` is when the count was last taken: this search when it worked, else the time the stored state
    gave for the last one that did (an agent from before this state existed left only `pkg_scan_ts`).
    `fail_since` is when the run of failures began, for a host that has never had a search that worked.
    """
    if not isinstance(raw, dict) or not isinstance(raw.get("ok"), bool):
        return None
    ok = raw["ok"]
    at = raw.get("at")
    if (
        isinstance(at, bool)
        or not isinstance(at, int)
        or not now - AT_BEFORE <= at <= now + AT_AFTER
    ):
        at = now
    source = raw.get("source")
    error_class = ""
    if not ok:
        reported = raw.get("error_class")
        error_class = (
            reported if isinstance(reported, str) and reported in SEARCH_CLASSES else "unknown"
        )
    prev = prev_si.get("wu_search") if isinstance(prev_si, dict) else None
    prev = prev if isinstance(prev, dict) else {}
    if ok:
        ok_at, fail_since = at, 0
    else:
        ok_at = _stamp(prev.get("ok_at"))
        if not ok_at and prev.get("ok") is True:
            ok_at = _stamp(prev.get("at"))
        if not ok_at and isinstance(prev_si, dict):
            ok_at = _stamp(prev_si.get("pkg_scan_ts"))
        fail_since = _stamp(prev.get("fail_since")) if prev.get("ok") is False else 0
        fail_since = fail_since or at
    return {
        "at": at,
        "ok": ok,
        "source": source if source in SEARCH_SOURCES else "unknown",
        "error_class": error_class,
        "ok_at": ok_at,
        "fail_since": fail_since,
    }


def keep_last_count(safe_si: dict[str, Any], prev_si: object) -> bool:
    """A search that failed neither clears nor refreshes the count. The stored sysinfo is replaced by
    each report, so the count (`packages`) and the time it was taken (`pkg_scan_ts`) are copied from the
    stored record into this one when this one has none. True when something was kept."""
    if not isinstance(prev_si, dict):
        return False
    kept = False
    for key in ("packages", "pkg_scan_ts"):
        if key not in safe_si and key in prev_si:
            safe_si[key] = copy.deepcopy(prev_si[key])
            kept = True
    return kept


def kept_count_time(si: object) -> int | None:
    """When the pending-update count a host carries was taken, if it is a count `keep_last_count` kept (the last
    search of the host failed). None when it is not a kept count: the last search worked, or the host sent no
    search state (a Linux or macOS host, an agent from before the state existed), and the count is read as it
    always was. 0 when it is a kept count and nothing says when it was taken."""
    if not isinstance(si, dict):
        return None
    state = si.get("wu_search")
    if not isinstance(state, dict) or state.get("ok") is not False:
        return None
    return _stamp(state.get("ok_at")) or _stamp(si.get("pkg_scan_ts"))


def count_predates(si: object, since: int) -> bool:
    """True when the count a host carries is a kept one that was taken before `since`. An upgrade that was queued at
    `since` cannot be told to have worked, or not, from a count that is older than the upgrade."""
    taken = kept_count_time(si)
    return taken is not None and taken < since


def readable_count(
    si: object, count: Any, now: int, days: int = SEARCH_WARN_DAYS
) -> tuple[Any, dict[str, Any] | None]:
    """(the count a report may print as the host's count now, the record of the count it may not).

    A host whose last search failed keeps the count it had. For `days` days that is still the best count there
    is; past them it is not the count the host has now, and a report that says "fully patched" from a zero of 40
    days ago, or counts the host's pending updates from it, says what nobody knows. The count is then None, as it
    was before a failed search kept it, and the second value says what it was and when it was taken
    ({"upgradable": 3, "taken_at": 1731400000}); `taken_at` is 0 when nothing says. Every other count comes
    back as it is, with None beside it."""
    if isinstance(count, bool) or not isinstance(count, int):
        return count, None
    taken = kept_count_time(si)
    if taken is None or now - taken < days * 86400:
        return count, None
    return None, {"upgradable": count, "taken_at": taken}


def _ago(seconds: int) -> str:
    """'12 minutes', '3 hours', '5 days' for a span of seconds."""
    seconds = max(0, int(seconds))
    if seconds < 3600:
        return plural(max(1, seconds // 60), "minute")
    if seconds < 172800:
        return plural(seconds // 3600, "hour")
    return plural(seconds // 86400, "day")


def _day(ts: int) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(ts))


def search_row(
    state: object,
    now: int,
    warn_days: int = SEARCH_WARN_DAYS,
    crit_days: int = SEARCH_CRIT_DAYS,
) -> tuple[str, str] | None:
    """(status, text) of the Checks row 'Windows Update search', or None when the host sent no state.

    The row goes amber after `warn_days` without a successful search and red after `crit_days`; a failed
    search on its own is not a finding, since the next one may work. The time it counts from is the last
    search that worked, else the start of the failures, else the last search."""
    if not isinstance(state, dict) or not isinstance(state.get("ok"), bool):
        return None
    at = _stamp(state.get("at")) or now
    ok_at = _stamp(state.get("ok_at"))
    since = ok_at or _stamp(state.get("fail_since")) or at
    days = max(0, now - since) / 86400
    status = "critical" if days >= crit_days else "warning" if days >= warn_days else "ok"
    if state["ok"]:
        text = f"last search {_ago(now - at)} ago, ok"
        if status != "ok":
            text += " (nothing newer has been reported)"
        return status, text
    why = state.get("error_class") if state.get("error_class") in SEARCH_CLASSES else "unknown"
    text = f"last search failed ({why}) {_ago(now - at)} ago; "
    text += f"the count is from {_day(ok_at)}" if ok_at else "no search has worked yet"
    if status != "ok":
        text = f"no successful search for {_ago(now - since)}; " + text
    return status, text


# ── the build ─────────────────────────────────────────────────────────────────────────────────────────
#
# The registry key HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion holds CurrentBuildNumber, UBR (the
# revision, which changes with every cumulative update), DisplayVersion (ReleaseId before 20H2), ProductName
# and EditionID.

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f  ]")
# ASCII digits only. `\d` takes the decimal digits of every script, and `str.isdigit()` takes a superscript two as well, which `int()`
# refuses: a build read with either could be a number to one function and an error to the next.
_BUILD = re.compile(r"[0-9]{3,6}")
_DISPLAY = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,15}")
# InstallationType says what kind of system this is. It is a fixed set, and the stored word is the registry's own spelling of it.
_INSTALLATIONS = {
    "client": "Client",
    "server": "Server",
    "server core": "Server Core",
    "nano server": "Nano Server",
    "embedded": "Embedded",
}


def _text(value: object, limit: int) -> str:
    """A text from a host: control characters become spaces, the ends are trimmed, the length is capped."""
    if not isinstance(value, str):
        return ""
    return _CONTROL.sub(" ", value).strip()[:limit]


def clean_win_build(raw: object) -> dict[str, Any] | None:
    """The build as it is stored with the host: build (digits), ubr (a whole number), display_version,
    edition, product and installation_type (one of a fixed set). A field that is not what it should be is
    left out; None when nothing is left.

    The readers (`os_label`, `win_family`, `build_fields`) take the stored record through this function as
    well, so a record that a hand edit, an import or a restore left with a value that ingest would have
    refused is read the way ingest would have stored it.
    """
    if not isinstance(raw, dict):
        return None
    out: dict[str, Any] = {}
    build = _text(raw.get("build"), 8)
    if _BUILD.fullmatch(build):
        out["build"] = build
    ubr = _count(raw.get("ubr"), 999999)
    if ubr is not None:
        out["ubr"] = ubr
    display = _text(raw.get("display_version"), 16)
    if _DISPLAY.fullmatch(display):
        out["display_version"] = display
    for key, limit in (("edition", 40), ("product", 80)):
        text = _text(raw.get(key), limit)
        if text:
            out[key] = text
    installation = _INSTALLATIONS.get(_text(raw.get("installation_type"), 24).lower())
    if installation:
        out["installation_type"] = installation
    return out or None


# Windows 11 still writes "Windows 10 ..." into ProductName on many builds, so the family of a client
# system comes from its build number: 22000 and up is Windows 11. A server keeps the name of its product,
# because a server and a client share build numbers (Windows Server 2025 and Windows 11 24H2 are both
# 26100). Whether a system is a server is what its installation type says: an EditionID that starts with
# "Server" is not enough, because Windows 10 and 11 Enterprise multi-session (Azure Virtual Desktop) is a
# client edition and its EditionID is "ServerRdsh".
_CLIENT_FAMILIES = (
    (22000, "Windows 11"),
    (10240, "Windows 10"),
    (9600, "Windows 8.1"),
    (9200, "Windows 8"),
    (7600, "Windows 7"),
)
_CLIENT_PREFIX = re.compile(r"^Windows\s+(?:11|10|8\.1|8|7)\b\s*", re.IGNORECASE)
_CLIENT_NAME = re.compile(
    r"^Windows\s+\S+", re.IGNORECASE
)  # the family a build below the table still names
_EDITIONS = {
    "Professional": "Pro",
    "Core": "Home",
    "CoreSingleLanguage": "Home Single Language",
    "ProfessionalWorkstation": "Pro for Workstations",
    "ProfessionalEducation": "Pro Education",
    "Enterprise": "Enterprise",
    "EnterpriseS": "Enterprise LTSC",
    "Education": "Education",
    "IoTEnterprise": "IoT Enterprise",
}


def _is_server(win_build: dict[str, Any]) -> bool:
    """Whether a build record that `clean_win_build` cleaned is a server.

    The installation type says it ("Server", "Server Core" and "Nano Server" are servers, "Client" and
    "Embedded" are not). A record from an agent that does not send it is read from the product name, and
    from the edition id too, except for the multi-session edition "ServerRdsh", which is a client.
    """
    installation = str(win_build.get("installation_type", "")).lower()
    if installation:
        return "server" in installation
    edition = str(win_build.get("edition", "")).lower()
    return "server" in str(win_build.get("product", "")).lower() or (
        edition.startswith("server") and not edition.startswith("serverrdsh")
    )


def _family(wb: dict[str, Any]) -> str:
    """`win_family` for a record that `clean_win_build` has cleaned."""
    if _is_server(wb):
        return str(wb.get("product", ""))
    build = wb.get("build")
    if isinstance(build, str) and _BUILD.fullmatch(build):
        for first, family in _CLIENT_FAMILIES:
            if int(build) >= first:
                return family
    named = _CLIENT_NAME.match(str(wb.get("product", "")))
    return named.group(0) if named else ""


def win_family(win_build: object) -> str:
    """'Windows 11', 'Windows 10', ... for a client system; the product name for a server; '' when the
    build says nothing. The record is cleaned first, as ingest cleans it: a stored value that ingest
    would have refused is not read."""
    return _family(clean_win_build(win_build) or {})


def _client_edition(win_build: dict[str, Any], family: str) -> str:
    """The edition of a client system as people say it ("Pro", "Home"): the product name without the family in front of it, else the
    edition id in its own words."""
    product = str(win_build.get("product", ""))
    if family and product.lower().startswith(family.lower()):
        text = product[len(family) :].strip()
    else:
        text = _CLIENT_PREFIX.sub("", product).strip()
    edition = str(win_build.get("edition", ""))
    return text or _EDITIONS.get(edition, "") or edition


def os_label(win_build: object) -> str:
    """'Windows 11 Pro 23H2 (build 22631.3593)' for a host that reported its build, else ''. The record is
    cleaned first, as ingest cleans it (a build that is not digits is no build, a text is capped).
    """
    wb = clean_win_build(win_build) or {}
    if not wb.get("build"):
        return ""
    family = _family(wb)
    parts = [family] if family else []
    if not _is_server(wb):
        edition = _client_edition(wb, family)
        if edition.lower().startswith("windows"):
            # a product name this table does not know: it names itself, so it replaces the family
            parts = []
        if edition:
            parts.append(edition)
    if wb.get("display_version"):
        parts.append(str(wb["display_version"]))
    number = str(wb["build"])
    if "ubr" in wb:
        number += f".{wb['ubr']}"
    parts.append(f"(build {number})")
    return " ".join(parts)


def build_fields(si: object) -> dict[str, Any]:
    """The Data Explorer's six fields for the build; None for what the host never reported. The record is
    cleaned first, as ingest cleans it."""
    wb = clean_win_build(si.get("win_build") if isinstance(si, dict) else None) or {}
    return {
        "win_build": wb.get("build") or None,
        "win_ubr": wb.get("ubr"),
        "win_display_version": wb.get("display_version") or None,
        "win_edition": wb.get("edition") or None,
        "win_product": wb.get("product") or None,
        "win_family": _family(wb) or None,
    }


# ── file shares ───────────────────────────────────────────────────────────────────────────────────────


def clean_shares(raw: object) -> dict[str, Any] | None:
    """The shares the host exports, as they are stored: `count` (the shares an operator made, all of them),
    `admin_count` (the names that end in $: the default shares and any other hidden one, counted and not
    listed) and `items`, at most MAX_SHARES rows of name, path, description and whether the share is
    encrypted. None when `raw` is not a report."""
    if not isinstance(raw, dict) or not any(k in raw for k in ("items", "count", "admin_count")):
        return None
    rows = raw.get("items")
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        name = _text(row.get("name"), 80)
        if not name or name.endswith("$") or name.lower() in seen:
            continue
        seen.add(name.lower())
        item: dict[str, Any] = {
            "name": name,
            "path": _text(row.get("path"), 260),
            "description": _text(row.get("description"), 200),
        }
        if isinstance(row.get("encrypted"), bool):
            item["encrypted"] = row["encrypted"]
        items.append(item)
        if len(items) >= MAX_SHARES:
            break
    count = _count(raw.get("count"))
    return {
        "count": max(len(items), count if count is not None else 0),
        "admin_count": _count(raw.get("admin_count")) or 0,
        "items": items,
    }


def shares_count(si: object) -> int | None:
    """The number of shares an operator made on the host; None when it never reported them."""
    shares = si.get("shares") if isinstance(si, dict) else None
    count = shares.get("count") if isinstance(shares, dict) else None
    return count if isinstance(count, int) and not isinstance(count, bool) else None


# ── the TPM ───────────────────────────────────────────────────────────────────────────────────────────

_SPEC = re.compile(r"[0-9]{1,2}(?:\.[0-9]{1,2})?")  # ASCII digits, as `_BUILD`


def clean_tpm(raw: object) -> dict[str, Any] | None:
    """The TPM as it is stored: `present`, `ready` and `enabled` when they are true or false (a probe that
    could not tell leaves its key out, which is not the same as false) and `spec`, the version of the
    specification ("2.0"). None when nothing is left."""
    if not isinstance(raw, dict):
        return None
    out: dict[str, Any] = {}
    for key in ("present", "ready", "enabled"):
        if isinstance(raw.get(key), bool):
            out[key] = raw[key]
    spec = _text(raw.get("spec"), 16)
    if _SPEC.fullmatch(spec):
        out["spec"] = spec
    return out or None


def tpm_flag(si: object, key: str) -> bool | None:
    """`present` or `ready` of the TPM, True or False as reported; None when the host never said."""
    tpm = si.get("tpm") if isinstance(si, dict) else None
    value = tpm.get(key) if isinstance(tpm, dict) else None
    return value if isinstance(value, bool) else None

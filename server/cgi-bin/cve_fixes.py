"""RemotePower — does a CVE finding have a fix for the host's own release? (v7.4.6, issue #57)

OSV keeps one `affected` entry per package and per release of a distribution. A Debian record for curl
reads: Debian 12 has no fix, Debian 13 and 14 are fixed in 8.7.1-1. The scanner folded those entries
together, so a host on Debian 12 was shown "fixed in 8.7.1-1", a version it cannot install, and counted
as fixable. This module keeps the entries apart and answers, for the release one host runs:

  fixed          an update to the fixed version of the host's own release clears it
  newer_release  the host's release has no fix, a newer release does
  none           no release has a fix yet
  pro            (8.0.1) the fix for the host's release is in Ubuntu Pro only
  unknown        the release the host runs is not known (an Ubuntu derivative with a version of its
                 own, Red Hat), the distribution publishes an advisory per release together with its
                 fix (Rocky, Alma), or the record was cached before the entries were kept apart

A release is told apart by the name its entries carry: Debian:12, Alpine:v3.19, and since 8.0.1
Ubuntu:22.04:LTS with Ubuntu:Pro:22.04:LTS beside it. A host scanned under the bare name "Ubuntu" is
classified under the name of its own release, which the scanner works out from the version the host
reported.

8.0.1 also keeps here the rule for what a scan stores one by one (`kept`, `split`): OSV lists every
known CVE of a Debian or Ubuntu release, fixed or not. The kernel of a Debian 12 host alone answers
with more than a thousand, and seven common packages of a fully patched one with 150 that no update
clears (read on 2026-11-15).

Nothing here imports api or the network code. The scanner and the alert paths hand in what they hold.
"""

from __future__ import annotations

import re
from typing import Any

FIXED = "fixed"
NEWER_RELEASE = "newer_release"
NONE = "none"
PRO = "pro"
UNKNOWN = "unknown"
STATUSES = (FIXED, NEWER_RELEASE, NONE, PRO, UNKNOWN)

# Fixed versions kept for one package in one release, and newer releases named on a finding. A record
# rarely has more than one of either; the caps keep a hand-made or hostile record from filling the cache.
MAX_FIXED_PER_ENTRY = 3
MAX_ELSEWHERE = 3

# What one OSV record may add to the details cache. A record names a few packages in a few releases; a
# kernel update names a few hundred packages. Past these bounds a string or an entry is left out and the
# finding falls back to the status "unknown", which is the older behaviour, so a record that is hostile or
# merely enormous cannot grow the cache or the findings without limit.
MAX_ENTRIES = 1024
MAX_VERSION_LEN = 128
MAX_NAME_LEN = 200

_DEBIAN = re.compile(r"^Debian:(\d{1,4})$")
_ALPINE = re.compile(r"^Alpine:v(\d{1,4})\.(\d{1,4})$")
# Ubuntu names a release "Ubuntu:22.04:LTS" or, between two long-term ones, "Ubuntu:24.10". The fixes of
# Ubuntu Pro are entries of their own, "Ubuntu:Pro:22.04:LTS". A FIPS name (Ubuntu:Pro:FIPS-updates:...)
# matches neither pattern: those are other builds of the package with fixes of their own.
_UBUNTU = re.compile(r"^Ubuntu:(\d{1,2})\.(\d{2})(?::LTS)?$")
_UBUNTU_PRO = re.compile(r"^Ubuntu:Pro:(\d{1,2})\.(\d{2}):LTS$")
_UBUNTU_VERSION = re.compile(r"^(\d{1,2})\.(\d{2})$")


def release_of(ecosystem: Any) -> tuple[str, tuple[int, ...]] | None:
    """The distribution and release in an OSV ecosystem name, or None when the name has no release.

    "Debian:12" is ("Debian", (12,)) and "Alpine:v3.19" is ("Alpine", (3, 19)). "Ubuntu", "Rocky Linux" and
    the rest name a distribution only, and a name that is not understood is treated the same way."""
    if not isinstance(ecosystem, str):
        return None
    match = _DEBIAN.match(ecosystem)
    if match:
        return "Debian", (int(match.group(1)),)
    match = _ALPINE.match(ecosystem)
    if match:
        return "Alpine", (int(match.group(1)), int(match.group(2)))
    match = _UBUNTU.match(ecosystem)
    if match:
        return "Ubuntu", (int(match.group(1)), int(match.group(2)))
    match = _UBUNTU_PRO.match(ecosystem)
    if match:
        return "Ubuntu Pro", (int(match.group(1)), int(match.group(2)))
    return None


def ubuntu_release_name(version_id: Any) -> str:
    """The name an Ubuntu release has in a record, from the VERSION_ID of the host: "22.04" gives
    "Ubuntu:22.04:LTS", "24.10" gives "Ubuntu:24.10". Empty for anything that is not an Ubuntu version
    (a derivative reports a version of its own, such as 21.3)."""
    match = _UBUNTU_VERSION.match(str(version_id or "").strip())
    if not match:
        return ""
    major, minor = int(match.group(1)), match.group(2)
    if minor not in ("04", "10") or major < 14:
        return ""
    long_term = minor == "04" and major % 2 == 0
    return f"Ubuntu:{major}.{minor}:LTS" if long_term else f"Ubuntu:{major}.{minor}"


def pro_name(ecosystem: Any) -> str:
    """The name of the Ubuntu Pro entries beside a long-term release, "" for any other name."""
    if not isinstance(ecosystem, str):
        return ""
    match = _UBUNTU.match(ecosystem)
    if not match or not ecosystem.endswith(":LTS"):
        return ""
    return f"Ubuntu:Pro:{match.group(1)}.{match.group(2)}:LTS"


def minor(vuln: Any) -> dict[str, list[str]]:
    """{ecosystem: [packages]} for the entries of a record that the distribution marks "unimportant": its
    own judgement that the package is not affected in a way that matters. Debian puts it on the entry of
    each release (ecosystem_specific.urgency)."""
    out: dict[str, list[str]] = {}
    for entry in _as_list(vuln.get("affected") if isinstance(vuln, dict) else None):
        package = entry.get("package") if isinstance(entry, dict) else None
        specific = entry.get("ecosystem_specific") if isinstance(entry, dict) else None
        if not isinstance(package, dict) or not isinstance(specific, dict):
            continue
        ecosystem, name, urgency = (
            package.get("ecosystem"),
            package.get("name"),
            specific.get("urgency"),
        )
        if (
            not isinstance(ecosystem, str)
            or not isinstance(name, str)
            or not name
            or len(name) > MAX_NAME_LEN
            or not isinstance(urgency, str)
            or urgency.strip().lower().rstrip("*").strip() not in ("unimportant", "negligible")
            or release_of(ecosystem) is None
        ):
            continue
        names = out.setdefault(ecosystem, [])
        if name not in names and sum(len(v) for v in out.values()) < MAX_ENTRIES:
            names.append(name)
    return out


def is_minor(minors: Any, ecosystem: Any, package: str) -> bool:
    """Does the `minor` map of a record name this package in this release?"""
    names = (
        minors.get(ecosystem) if isinstance(minors, dict) and isinstance(ecosystem, str) else None
    )
    return isinstance(names, list) and package in names


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def extract(vuln: Any) -> dict[str, dict[str, list[str]]]:
    """{ecosystem: {package: [fixed versions]}} for the entries of an OSV record whose ecosystem names a release.

    An empty list means the entry exists, so the package is affected in that release, and it has no fix.
    """
    out: dict[str, dict[str, list[str]]] = {}
    for entry in _as_list(vuln.get("affected") if isinstance(vuln, dict) else None):
        package = entry.get("package") if isinstance(entry, dict) else None
        if not isinstance(package, dict):
            continue
        ecosystem, name = package.get("ecosystem"), package.get("name")
        if (
            not isinstance(ecosystem, str)
            or not isinstance(name, str)
            or not name
            or len(name) > MAX_NAME_LEN
        ):
            continue
        if release_of(ecosystem) is None:
            continue
        if name not in out.get(ecosystem, {}) and sum(len(p) for p in out.values()) >= MAX_ENTRIES:
            continue
        fixed = out.setdefault(ecosystem, {}).setdefault(name, [])
        for rng in _as_list(entry.get("ranges")):
            for event in _as_list(rng.get("events") if isinstance(rng, dict) else None):
                version = event.get("fixed") if isinstance(event, dict) else None
                if (
                    isinstance(version, str)
                    and version
                    and len(version) <= MAX_VERSION_LEN
                    and version not in fixed
                    and len(fixed) < MAX_FIXED_PER_ENTRY
                ):
                    fixed.append(version)
    return out


def _fixes_in(fixes: dict[str, Any], ecosystem: str, package: str) -> list[str] | None:
    """The fixed versions of one package in one release, [] for affected with no fix, None for no entry."""
    entry = fixes.get(ecosystem)
    versions = entry.get(package) if isinstance(entry, dict) else None
    if not isinstance(versions, list):
        return None
    return [v for v in versions if isinstance(v, str) and v]


def newer_fixes(fixes: Any, ecosystem: Any, package: str) -> dict[str, list[str]]:
    """{ecosystem: [fixed versions]} for the releases of the same distribution newer than `ecosystem` that
    fix `package`, nearest release first."""
    release = release_of(ecosystem)
    if release is None or not isinstance(fixes, dict):
        return {}
    found: list[tuple[tuple[int, ...], str, list[str]]] = []
    for other in fixes:
        other_release = release_of(other)
        if (
            other_release is None
            or other_release[0] != release[0]
            or other_release[1] <= release[1]
        ):
            continue
        versions = _fixes_in(fixes, other, package)
        if versions:
            found.append((other_release[1], other, versions))
    found.sort()
    return {eco: versions for _, eco, versions in found[:MAX_ELSEWHERE]}


def classify(fixes: Any, ecosystem: Any, package: str, pro: bool = False) -> dict[str, Any]:
    """The status of one package in one host's release, from the `extract` map of its record.

    Returns {"status": ..., "fixed": [versions in the host's release], "elsewhere": {ecosystem: [versions]}}.
    "elsewhere" is filled for newer_release and for pro (the Ubuntu Pro entry and its versions). `pro` says the
    host has Ubuntu Pro: a fix in the Pro entry of its release is then one an update installs."""
    unknown: dict[str, Any] = {"status": UNKNOWN, "fixed": [], "elsewhere": {}}
    if (
        release_of(ecosystem) is None
        or not isinstance(fixes, dict)
        or not isinstance(ecosystem, str)
    ):
        return unknown
    here = _fixes_in(fixes, ecosystem, package)
    channel = pro_name(ecosystem)
    beside = _fixes_in(fixes, channel, package) if channel else None
    if here is None and beside is None:
        return unknown  # the record names no entry for this package in this release: cannot say
    if here:
        return {"status": FIXED, "fixed": here, "elsewhere": {}}
    if beside:
        # A release past its standard support is listed under the Pro name only, and so is a fix that
        # Ubuntu ships to Pro alone. Without Pro no update brings it.
        if pro:
            return {"status": FIXED, "fixed": beside, "elsewhere": {}}
        return {"status": PRO, "fixed": [], "elsewhere": {channel: beside[:MAX_FIXED_PER_ENTRY]}}
    elsewhere = newer_fixes(fixes, ecosystem, package)
    if elsewhere:
        return {"status": NEWER_RELEASE, "fixed": [], "elsewhere": elsewhere}
    return {"status": NONE, "fixed": [], "elsewhere": {}}


def patched_by(fixes: Any, ecosystem: Any, package: str) -> list[str]:
    """The versions that mean "already patched" when the installed package is at or past one of them: the
    fixes of the host's own release and of the newer releases. Never an older release: a package in a newer
    release is normally past an older release's fix without containing the fix its own release lacks.
    Empty when the distribution cannot be told apart, and the caller keeps its older rule."""
    if (
        release_of(ecosystem) is None
        or not isinstance(fixes, dict)
        or not isinstance(ecosystem, str)
    ):
        return []
    out = list(_fixes_in(fixes, ecosystem, package) or [])
    channel = pro_name(ecosystem)
    if channel:
        # a host that is at or past the Pro fix has it, whether or not anything said it has Pro
        out.extend(v for v in (_fixes_in(fixes, channel, package) or []) if v not in out)
    for versions in newer_fixes(fixes, ecosystem, package).values():
        out.extend(v for v in versions if v not in out)
    return out


def is_fixable(finding: Any) -> bool:
    """Can an update clear this finding now? A finding scanned before 7.4.6 has no status and keeps the
    meaning its fixed version always had."""
    if not isinstance(finding, dict):
        return False
    status = finding.get("fix_status")
    if status == FIXED:
        return True
    if status in (NEWER_RELEASE, NONE, PRO):
        return False
    return bool(str(finding.get("fixed_version") or "").strip())


def finding_ids(finding: Any) -> list[str]:
    """The finding's own id and its aliases, upper-case: the names the known-exploited list and the
    exploit-probability feed are keyed by."""
    if not isinstance(finding, dict):
        return []
    ids = [str(finding.get("vuln_id") or "").upper()]
    ids += [str(a).upper() for a in _as_list(finding.get("aliases")) if isinstance(a, str)]
    return ids


def finding_is_kev(finding: Any, kev: Any) -> bool:
    """Is the finding on the known-exploited list, by its id or by any alias? `kev` holds upper-case ids."""
    if not kev:
        return False
    return any(i in kev for i in finding_ids(finding))


def counted(finding: Any, fixable_only: bool, kev: Any = None) -> bool:
    """Does this finding count toward a number an operator reads: the sidebar badge, the severity tiles,
    Needs attention, the risk score and Checks? With the option off every finding counts, as before. With it
    on, only one an update can clear counts, and one on the known-exploited list, whatever its fix status.
    A finding that was already stamped `kev` counts without a lookup; `kev` is the set of upper-case ids
    for a finding that was not."""
    if not fixable_only:
        return True
    stamped = isinstance(finding, dict) and bool(finding.get("kev"))
    return is_fixable(finding) or stamped or finding_is_kev(finding, kev)


def alert_candidate(finding: Any, fixable_only: bool, kev: Any) -> bool:
    """Should this finding be able to raise cve_found? With the option off every finding is a candidate and
    the severity filter and the accepted-risk list decide, as before. With it on, only one an update can
    clear, or one on the known-exploited list, which alerts whatever its fix status. The same rule as
    `counted`: the alert option and the count option leave out the same findings."""
    return counted(finding, fixable_only, kev)


FIX_KEYS = ("fixable", NEWER_RELEASE, NONE, PRO, "unchecked")


def fix_key(finding: Any) -> str:
    """The tile one finding counts in: fixable, newer_release, none, pro or unchecked."""
    if is_fixable(finding):
        return "fixable"
    status = finding.get("fix_status") if isinstance(finding, dict) else None
    return status if status in (NEWER_RELEASE, NONE, PRO) else "unchecked"


def summarize(findings: Any, ignore_ids: Any) -> dict[str, int]:
    """How many findings an update can clear now, how many are fixed only in a newer release, how many have
    no fix yet, how many need Ubuntu Pro and how many cannot be told. They add up to the findings that are
    not ignored."""
    out = dict.fromkeys(FIX_KEYS, 0)
    for finding in _as_list(findings):
        if not isinstance(finding, dict) or finding.get("vuln_id") in ignore_ids:
            continue
        out[fix_key(finding)] += 1
    return out


# ── 8.0.1: what a scan stores one by one ─────────────────────────────────────────────────────────────────
#
# A finding is stored when an update for the host's release clears it, when it is critical or high, or when it
# is on the known-exploited list. That alone does not bound a host: 113 of the 255 Debian records read on
# 2026-11-15 are critical or high by their CVSS score, and a patched Debian 12 host kept 16 for four source
# packages out of the several hundred it has. So a host keeps at most KEEP_PER_HOST and a package at most
# KEEP_PER_PACKAGE, the most pressing first, and
# everything else is counted in a roll-up that says how many, of which severity, of which fix status and in
# which packages. Nothing is dropped without being counted.
KEEP_PER_HOST = 300
KEEP_PER_PACKAGE = 50
ROLLUP_PACKAGES = 20
SEVERITIES = ("critical", "high", "medium", "low", "unknown")
_ID_NUMBER = re.compile(r"(\d{4})-(\d+)(?:-\d+)?$")


def kept(finding: Any, kev: Any = None) -> bool:
    """The rule: is this finding one a scan stores one by one (while there is room)?"""
    if not isinstance(finding, dict):
        return False
    return (
        is_fixable(finding)
        or finding.get("severity") in ("critical", "high")
        or bool(finding.get("kev"))
        or finding_is_kev(finding, kev)
    )


def _pressing(finding: dict[str, Any], kev: Any) -> tuple[int, int, int]:
    """The order in which findings take the room: known-exploited, critical, then what an update clears by
    severity, then high without a fix; within one, the newest CVE first."""
    severity = finding.get("severity")
    if bool(finding.get("kev")) or finding_is_kev(finding, kev):
        rank = 0
    elif severity == "critical":
        rank = 1
    elif is_fixable(finding):
        rank = {"high": 2, "medium": 3}.get(str(severity), 4)
    else:
        rank = 5
    match = _ID_NUMBER.search(str(finding.get("vuln_id") or ""))
    year, number = (int(match.group(1)), int(match.group(2))) if match else (0, 0)
    return rank, -year, -number


def rollup(findings: Any) -> dict[str, Any]:
    """The count of the findings that are not stored one by one: the total, by severity, by fix status, and
    the ROLLUP_PACKAGES packages that hold the most, with a line for the rest. {} for none."""
    rows = [f for f in _as_list(findings) if isinstance(f, dict)]
    if not rows:
        return {}
    severity = dict.fromkeys(SEVERITIES, 0)
    fix = dict.fromkeys(FIX_KEYS, 0)
    packages: dict[tuple[str, str], int] = {}
    for finding in rows:
        level = finding.get("severity")
        severity[level if level in severity else "unknown"] += 1
        fix[fix_key(finding)] += 1
        name = str(finding.get("package") or "")[:MAX_NAME_LEN]
        version = str(finding.get("version") or "")[:MAX_VERSION_LEN]
        packages[(name, version)] = packages.get((name, version), 0) + 1
    ordered = sorted(packages.items(), key=lambda item: (-item[1], item[0]))
    named = ordered[:ROLLUP_PACKAGES]
    return {
        "total": len(rows),
        "severity": {k: v for k, v in severity.items() if v},
        "fix": {k: v for k, v in fix.items() if v},
        "packages": [{"name": n, "version": v, "count": c} for (n, v), c in named],
        "more": {
            "packages": len(ordered) - len(named),
            "count": sum(c for _, c in ordered[len(named) :]),
        },
    }


def split(
    findings: Any,
    kev: Any = None,
    per_host: int = KEEP_PER_HOST,
    per_package: int = KEEP_PER_PACKAGE,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """(the findings stored one by one, the roll-up of the rest). The stored ones keep the order they came in."""
    usable = [f for f in _as_list(findings) if isinstance(f, dict)]
    wanted = sorted((f for f in usable if kept(f, kev)), key=lambda f: _pressing(f, kev))
    room: dict[str, int] = {}
    chosen: set[int] = set()
    for finding in wanted:
        if len(chosen) >= per_host:
            break
        package = str(finding.get("package") or "")
        if room.get(package, 0) >= per_package:
            continue
        room[package] = room.get(package, 0) + 1
        chosen.add(id(finding))
    stored = [f for f in usable if id(f) in chosen]
    return stored, rollup([f for f in usable if id(f) not in chosen])


def rollup_total(record: Any) -> int:
    """The roll-up's total in a stored scan result, 0 for a result without one or with a damaged one."""
    roll = record.get("rollup") if isinstance(record, dict) else None
    total = roll.get("total") if isinstance(roll, dict) else None
    return total if isinstance(total, int) and not isinstance(total, bool) and total > 0 else 0

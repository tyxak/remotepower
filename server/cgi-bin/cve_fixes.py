"""RemotePower — does a CVE finding have a fix for the host's own release? (v7.4.6, issue #57)

OSV keeps one `affected` entry per package and per release of a distribution. A Debian record for curl
reads: Debian 12 has no fix, Debian 13 and 14 are fixed in 8.7.1-1. The scanner folded those entries
together, so a host on Debian 12 was shown "fixed in 8.7.1-1", a version it cannot install, and counted
as fixable. This module keeps the entries apart and answers, for the release one host runs:

  fixed          an update to the fixed version of the host's own release clears it
  newer_release  the host's release has no fix, a newer release does
  none           no release has a fix yet
  pro            (8.0.1) the fix for the host's release is in Ubuntu Pro only
  reboot         (8.0.2) a kernel that is installed and not running holds the fix: a reboot applies it
  unknown        the release the host runs is not known (an Ubuntu derivative with a version of its
                 own, Red Hat), the distribution publishes an advisory per release together with its
                 fix (Rocky, Alma), or the record was cached before the entries were kept apart

A release is told apart by the name its entries carry: Debian:12, Alpine:v3.19, and since 8.0.1
Ubuntu:22.04:LTS with Ubuntu:Pro:22.04:LTS beside it. A host scanned under the bare name "Ubuntu" is
classified under the name of its own release, which the scanner works out from the version the host
reported.

8.0.1 also keeps here the rule for what a scan stores one by one (`kept`, `split`): OSV lists every
known CVE of a Debian or Ubuntu release, fixed or not. On 2026-11-16 the newest Debian 12 kernel alone
answered with 744, none of which an update clears, and one from early 2024 with 8,882; seven common
packages of a fully patched host answered with 150 that no update clears.

Nothing here imports api or the network code. The scanner and the alert paths hand in what they hold.
"""

from __future__ import annotations

import re
from typing import Any

FIXED = "fixed"
NEWER_RELEASE = "newer_release"
NONE = "none"
PRO = "pro"
REBOOT = "reboot"
UNKNOWN = "unknown"
# `classify` never answers REBOOT: it needs the kernels the host has installed, which only the scan holds (it sets
# the status on a finding of the running kernel that an installed kernel would clear).
STATUSES = (FIXED, NEWER_RELEASE, NONE, PRO, REBOOT, UNKNOWN)

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


def standard_name(ecosystem: Any) -> str:
    """The standard release beside an Ubuntu Pro name ("Ubuntu:Pro:22.04:LTS" gives "Ubuntu:22.04:LTS"),
    "" for any other name."""
    if not isinstance(ecosystem, str):
        return ""
    match = _UBUNTU_PRO.match(ecosystem)
    return f"Ubuntu:{match.group(1)}.{match.group(2)}:LTS" if match else ""


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
        # The record names no entry for this package in this release. For Debian and Alpine that cannot be
        # said more about. An Ubuntu host is matched by the version it has, so it got here through another
        # release's entry: its own release is no longer followed (an interim release past its nine months)
        # and has the same version. If a newer release has the fix, that is where the fix is.
        if release_of(ecosystem)[0] == "Ubuntu":  # type: ignore[index]
            elsewhere = newer_fixes(fixes, ecosystem, package)
            if elsewhere:
                return {"status": NEWER_RELEASE, "fixed": [], "elsewhere": elsewhere}
        return unknown
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
    if status in (NEWER_RELEASE, NONE, PRO, REBOOT):
        return False
    return bool(str(finding.get("fixed_version") or "").strip())


def is_clearable(finding: Any) -> bool:
    """Can the operator clear this finding now: by an update (`is_fixable`), or, when an installed kernel already holds
    the fix, by a reboot? A reboot is something to do, so the findings it clears count where the ones an update clears
    do, and are stored one by one beside them. They are not "fixable" for the Patches link, which counts what a
    pending patch installs."""
    return is_fixable(finding) or (
        isinstance(finding, dict) and finding.get("fix_status") == REBOOT
    )


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


class CampaignIndex:
    """The live findings of a set of hosts, tallied once, so that a remediation campaign is answered from the tallies and not by
    walking every finding. A list of campaigns walked every finding of every visible host once per campaign: 200 campaigns over
    60 hosts of 300 findings were 3.6 million visits and 5.5 seconds, for the operator, on every opening of the CVE page.

    `live` is the findings to count, as (host id, list of findings that are not accepted as risk) pairs, and `kev` the upper-case
    ids of the known-exploited list. `affected(camp)` answers what a walk of those findings with the campaign's own rule answered:
    the ids of the hosts with a finding in the campaign's scope, and how many findings that is. A campaign over a list of ids
    (`cve_ids`) is about the findings that go by one of them (the id or an alias) and nothing else; otherwise it is about the
    severities it names (all when it names none), only the known-exploited ones when `kev_only` is set.
    """

    def __init__(self, live: Any, kev: Any = None) -> None:
        self._by_name: dict[str, set[tuple[str, int]]] = {}
        # severity word -> [hosts, findings, hosts with a known-exploited one, known-exploited findings]
        self._by_severity: dict[str, list[Any]] = {}
        for host, findings in live:
            for n, f in enumerate(findings):
                if not isinstance(f, dict):
                    continue
                names = set(finding_ids(f))
                names.update(str(f.get(k)).upper() for k in ("cve_id", "id") if f.get(k))
                for name in names:
                    self._by_name.setdefault(name, set()).add((host, n))
                slot = self._by_severity.setdefault(
                    str(f.get("severity", "")).lower(), [set(), 0, set(), 0]
                )
                slot[0].add(host)
                slot[1] += 1
                if f.get("kev") or f.get("known_exploited") or finding_is_kev(f, kev):
                    slot[2].add(host)
                    slot[3] += 1

    def affected(self, camp: Any) -> tuple[set[str], int]:
        ids = camp.get("cve_ids") or []
        if ids:
            wanted = {str(i).upper() for i in ids if isinstance(i, str)}
            found: set[tuple[str, int]] = set()
            for name in wanted:
                found |= self._by_name.get(name, set())
            return {host for host, _n in found}, len(found)
        severities = camp.get("severities") or []
        hosts: set[str] = set()
        count = 0
        for word, slot in self._by_severity.items():
            if severities and word not in severities:
                continue
            if camp.get("kev_only"):
                hosts |= slot[2]
                count += slot[3]
            else:
                hosts |= slot[0]
                count += slot[1]
        return hosts, count


def counted(finding: Any, fixable_only: bool, kev: Any = None) -> bool:
    """Does this finding count toward a number an operator reads: the sidebar badge, the severity tiles,
    Needs attention, the risk score and Checks? With the option off every finding counts, as before. With it
    on, only one an update can clear counts (or, when an installed kernel holds the fix, a reboot: it is
    something to do), and one on the known-exploited list, whatever its fix status.
    A finding that was already stamped `kev` counts without a lookup; `kev` is the set of upper-case ids
    for a finding that was not."""
    if not fixable_only:
        return True
    stamped = isinstance(finding, dict) and bool(finding.get("kev"))
    return is_clearable(finding) or stamped or finding_is_kev(finding, kev)


def alert_candidate(finding: Any, fixable_only: bool, kev: Any) -> bool:
    """Should this finding be able to raise cve_found? With the option off every finding is a candidate and
    the severity filter and the accepted-risk list decide, as before. With it on, only one an update can
    clear, or one on the known-exploited list, which alerts whatever its fix status. The same rule as
    `counted`: the alert option and the count option leave out the same findings."""
    return counted(finding, fixable_only, kev)


FIX_KEYS = ("fixable", REBOOT, NEWER_RELEASE, NONE, PRO, "unchecked")


def fix_key(finding: Any) -> str:
    """The tile one finding counts in: fixable, reboot, newer_release, none, pro or unchecked."""
    if is_fixable(finding):
        return "fixable"
    status = finding.get("fix_status") if isinstance(finding, dict) else None
    return status if status in (REBOOT, NEWER_RELEASE, NONE, PRO) else "unchecked"


def summarize(findings: Any, ignore_ids: Any) -> dict[str, int]:
    """How many findings an update can clear now, how many are fixed only in a newer release, how many have
    no fix yet, how many need Ubuntu Pro and how many cannot be told. They add up to the findings that are
    not ignored."""
    out = dict.fromkeys(FIX_KEYS, 0)
    for finding in _as_list(findings):
        if not isinstance(finding, dict):
            continue
        vid = finding.get("vuln_id")
        if isinstance(vid, str) and vid in ignore_ids:
            continue
        out[fix_key(finding)] += 1
    return out


# ── 8.0.1: what a scan stores one by one ─────────────────────────────────────────────────────────────────
#
# A finding is stored when an update for the host's release clears it (or, since 8.0.2, an installed kernel holds
# the fix and a reboot applies it: a finding that goes from the first to the second must not leave the list, or it
# would read as cleared), when it is critical or high, or when it is on the known-exploited list. That alone does not bound a host: 113 of the 255 Debian records read on
# 2026-11-15 are critical or high by their CVSS score, and a patched Debian 12 host kept 16 for four source
# packages out of the several hundred it has. So a host keeps at most KEEP_PER_HOST and a package at most
# KEEP_PER_PACKAGE, the most pressing first, and
# everything else is counted in a roll-up that says how many, of which severity, of which fix status and in
# which packages. Nothing is dropped without being counted.
KEEP_PER_HOST = 300
KEEP_PER_PACKAGE = 50
ROLLUP_PACKAGES = 20
SEVERITIES = ("critical", "high", "medium", "low", "unknown")
# The year and the number of a CVE id, also inside DEBIAN-CVE-2024-6387. A notice has none: "USN-6663-1"
# read the same way would be the year 6663.
_ID_NUMBER = re.compile(r"CVE-(\d{4})-(\d+)$", re.IGNORECASE)


def kept(finding: Any, kev: Any = None) -> bool:
    """The rule: is this finding one a scan stores one by one (while there is room)?"""
    if not isinstance(finding, dict):
        return False
    return (
        is_clearable(finding)
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
    elif is_clearable(finding):
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
        severity[level if isinstance(level, str) and level in severity else "unknown"] += 1
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


def select(
    findings: Any,
    kev: Any = None,
    per_host: int = KEEP_PER_HOST,
    per_package: int = KEEP_PER_PACKAGE,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    """(the findings stored one by one, the roll-up of the rest, the mark). The stored ones keep the order
    they came in.

    The mark says how far the room reached: for a package that had more to store than its ceiling, and for
    the host when it had more than its own, the `_pressing` order of the last finding that was stored. A
    later scan needs it to tell a finding that is new from one that was there all along, counted, and is
    listed now only because more pressing ones went away (see `beyond`). {} when nothing was cut."""
    usable = [f for f in _as_list(findings) if isinstance(f, dict)]
    wanted = sorted((f for f in usable if kept(f, kev)), key=lambda f: _pressing(f, kev))
    room: dict[str, int] = {}
    last: dict[str, list[int]] = {}
    cut: set[str] = set()
    host_cut = False
    reached: list[int] = []
    chosen: set[int] = set()
    for finding in wanted:
        if len(chosen) >= per_host:
            host_cut = True
            break
        package = str(finding.get("package") or "")
        if room.get(package, 0) >= per_package:
            cut.add(package)
            continue
        room[package] = room.get(package, 0) + 1
        chosen.add(id(finding))
        reached = list(_pressing(finding, kev))
        last[package] = reached
    stored = [f for f in usable if id(f) in chosen]
    mark: dict[str, Any] = {}
    if host_cut and reached:
        mark["host"] = reached
    if cut:
        mark["packages"] = {name: last[name] for name in sorted(cut) if name in last}
    return stored, rollup([f for f in usable if id(f) not in chosen]), mark


def split(
    findings: Any,
    kev: Any = None,
    per_host: int = KEEP_PER_HOST,
    per_package: int = KEEP_PER_PACKAGE,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """(the findings stored one by one, the roll-up of the rest): `select` without the mark."""
    stored, counted_rest, _mark = select(findings, kev, per_host, per_package)
    return stored, counted_rest


# A host whose findings `select` does not choose (an Alpine or an RPM host, or an Ubuntu host whose release is not known) has every
# finding stored one by one, and a host sends its own package list: 1,000 origins that answer 20 advisories each stored 20,000
# findings, 12 MB, in the store that most pages read whole. A host keeps at most this many, the most pressing first, and the rest are
# counted in a roll-up as they are for a Debian host, which keeps 300 (KEEP_PER_HOST). The ceiling is sixteen times that, so a host
# whose findings are all listed is not cut unless its list was built to.
KEEP_UNRULED_PER_HOST = 5000


def cap(
    findings: Any,
    kev: Any = None,
    per_host: int | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    """(the findings stored one by one, the roll-up of the rest, the mark) for a host that stores every finding up to a
    ceiling (`per_host`, KEEP_UNRULED_PER_HOST when it is not given, read when this is called). Within the ceiling the
    findings come back as they are, with no roll-up and no mark. Past it the most pressing ones are stored, in the order they
    came in, and the rest are counted (`rollup`); the mark is the `_pressing` order of the last one that was stored, which a
    later scan needs to tell a finding that is new from one that was counted (`beyond`)."""
    rows = findings if isinstance(findings, list) else []
    per_host = max(1, KEEP_UNRULED_PER_HOST if per_host is None else per_host)
    if len(rows) <= per_host:
        return rows, {}, {}
    usable = [f for f in rows if isinstance(f, dict)]
    if len(usable) <= per_host:
        return usable, {}, {}
    ordered = sorted(usable, key=lambda f: _pressing(f, kev))
    chosen = {id(f) for f in ordered[:per_host]}
    stored = [f for f in usable if id(f) in chosen]
    mark = {"host": list(_pressing(ordered[per_host - 1], kev))}
    return stored, rollup([f for f in usable if id(f) not in chosen]), mark


def _order(value: Any) -> list[int] | None:
    """A stored `_pressing` order, or None for anything else."""
    if (
        isinstance(value, list)
        and len(value) == 3
        and all(isinstance(n, int) and not isinstance(n, bool) for n in value)
    ):
        return value
    return None


def beyond(finding: Any, mark: Any, kev: Any = None) -> bool:
    """Was this finding past the room of the scan that left `mark`? Then it may have been there already,
    counted and not listed, and a list it enters now is no news.

    A finding that is more pressing than the last one a full package (or a full host) had room for would
    have been stored then, so it is new. One that is as pressing or less cannot be told from the ones that
    were counted, and is taken for one of them: an alert that names findings a host had all along, after
    the host installed its updates, is worse than one new advisory that is listed without an alert.
    """
    if not isinstance(finding, dict) or not isinstance(mark, dict):
        return False
    here = list(_pressing(finding, kev))
    host = _order(mark.get("host"))
    if host is not None and here >= host:
        return True
    packages = mark.get("packages")
    package = _order(
        packages.get(str(finding.get("package") or "")) if isinstance(packages, dict) else None
    )
    return package is not None and here >= package


def _count(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def rollup_has(counted_rest: Any, severities: Any) -> bool:
    """Does a roll-up count a finding of one of these severities?"""
    by_severity = counted_rest.get("severity") if isinstance(counted_rest, dict) else None
    if not isinstance(by_severity, dict):
        return False
    return any(_count(by_severity.get(s)) for s in severities if isinstance(s, str))


def rollup_words(record: Any) -> str:
    """One sentence about what a stored scan result counted and did not list, from the roll-up's own
    numbers, "" for a result without one. For the texts that are not a page: a ticket, the assistant.
    """
    total = rollup_total(record)
    if not total:
        return ""
    roll = record["rollup"]
    by_severity = roll.get("severity") if isinstance(roll.get("severity"), dict) else {}
    by_fix = roll.get("fix") if isinstance(roll.get("fix"), dict) else {}
    parts = []
    pressing = _count(by_severity.get("critical")) + _count(by_severity.get("high"))
    if pressing:
        parts.append(f"{pressing} critical or high")
    if _count(by_fix.get("fixable")):
        parts.append(f"{_count(by_fix.get('fixable'))} cleared by an update")
    if _count(by_fix.get(PRO)):
        parts.append(f"{_count(by_fix.get(PRO))} fixed with Ubuntu Pro")
    if _count(by_fix.get(REBOOT)):
        parts.append(f"{_count(by_fix.get(REBOOT))} fixed by an installed kernel, reboot to apply")
    said = f"{total} more known vulnerabilities are counted per package and not listed one by one"
    return said + (f" ({', '.join(parts)})" if parts else "")


def rollup_total(record: Any) -> int:
    """The roll-up's total in a stored scan result, 0 for a result without one or with a damaged one."""
    roll = record.get("rollup") if isinstance(record, dict) else None
    return _count(roll.get("total")) if isinstance(roll, dict) else 0


# ── 8.0.2: what was checked, per package ─────────────────────────────────────────────────────────────────
#
# A scan of a host says what it found. That reads as "the rest is clean" unless it also says how much of the
# host it looked at: the packages a host lists are not all asked about under a name the advisory data is filed
# under, and a package that was not asked about has no findings whatever is wrong with it. Each package a host
# listed is checked, or it is not and one of these is why:
#
#   no_source      the data is filed under the source package and the list names none for this package
#   no_matcher     nothing is matched against this host's packages at all (Arch, openSUSE, the applications of a
#                  Windows or macOS host)
#   no_release     a Debian or Ubuntu derivative whose release is not known: the data is kept per release
#   ceiling        it comes after the first 10,000 packages, which is as many as a scan reads
#   unanswered     the data source did not finish its answer for it (a list of advisories cut at the last page)
#
# `cve_scanner.package_coverage` builds the block a scan stores on the host's record, as `covered`:
# {'listed', 'checked', 'not_checked', 'reasons': {reason: n}, 'packages': [first 200 not checked], 'more'}.
# Everything below reads such a block, which a store may hold in any shape.
NO_SOURCE = "no_source"
NO_MATCHER = "no_matcher"
NO_RELEASE = "no_release"
CEILING = "ceiling"
UNANSWERED = "unanswered"
REASONS = (NO_SOURCE, NO_MATCHER, NO_RELEASE, CEILING, UNANSWERED)
MAX_NOT_CHECKED_LISTED = 200
MAX_PACKAGES_READ = 10000

# The reasons as the end of a sentence about N packages, for the texts that are not a page (a ticket, the
# assistant, the MCP tools). The page holds its own, so that they are translated.
REASON_WORDS = {
    NO_SOURCE: "have no source name",
    NO_MATCHER: "have no matcher for this host's package manager",
    NO_RELEASE: "cannot be checked because the release is not known",
    CEILING: f"come after the first {MAX_PACKAGES_READ:,} packages, which is as many as a scan reads",
    UNANSWERED: "were not answered in full by the data source",
}


def covered_view(value: Any, with_packages: bool = True) -> dict[str, Any] | None:
    """The per-package coverage block of a stored scan result as a page or a tool gets it, or None when there is
    none (a result stored before 8.0.2) or it cannot be read.

    Numbers are whole and not negative, a reason that is not one of REASONS is left out, and the list is cut to
    MAX_NOT_CHECKED_LISTED rows of a name, a version and a reason. `checked` and `not_checked` are made to add up
    to `listed`: a block that says otherwise is read by what its reasons add up to."""
    if not isinstance(value, dict):
        return None
    listed = _count(value.get("listed"))
    raw_reasons = value.get("reasons")
    raw: dict[str, Any] = raw_reasons if isinstance(raw_reasons, dict) else {}
    reasons = {r: _count(raw.get(r)) for r in REASONS if _count(raw.get(r))}
    not_checked = sum(reasons.values())
    if not listed and not not_checked:
        return None
    listed = max(listed, not_checked)
    out: dict[str, Any] = {
        "listed": listed,
        "checked": listed - not_checked,
        "not_checked": not_checked,
        "reasons": reasons,
    }
    if with_packages:
        rows: list[dict[str, str]] = []
        for row in _as_list(value.get("packages")):
            if (
                len(rows) >= MAX_NOT_CHECKED_LISTED
                or not isinstance(row, dict)
                or not isinstance(row.get("name"), str)
                or not row["name"]
                or row.get("reason") not in REASONS
            ):
                continue
            version = row.get("version")
            rows.append(
                {
                    "name": row["name"][:128],
                    "version": version[:64] if isinstance(version, str) else "",
                    "reason": row["reason"],
                }
            )
        out["packages"] = rows
        out["more"] = max(not_checked - len(rows), 0)
    return out


# Why a scan did not check a package, as it bears on "the findings are cleared". These belong to the host: the scan asked
# the wrong question for the packages it could not match (the advisories are filed under a source name the list does not
# carry, or under a release that is not known), or asked none, so a scan that lists nothing says nothing about them.
HOST_LEVEL_REASONS = (NO_SOURCE, NO_RELEASE, NO_MATCHER)
# These belong to the answer: it was cut at the last page, or the package came after the ones a scan reads.
ANSWER_LEVEL_REASONS = (CEILING, UNANSWERED)


def clear_is_trusted(before: Any, now: Any) -> bool:
    """May a scan that lists none of what the scan before listed announce the findings cleared?

    A host's findings leave the list because its packages were patched or removed, or because the scan stopped looking: an
    agent that sends no source package names (older than 8.0.1, or one whose `dpkg-query` timed out), a release that is not
    known, an answer that was cut. The Debian advisories are filed under the source package, so the scan of the same packages
    without the source names asks for `libssl3` where it found five advisories under `openssl`, and finds none. `before` and
    `now` are the `covered` blocks of the scan before and of this one.

    Not when this scan could not match packages for a reason that belongs to the host (HOST_LEVEL_REASONS): "none found" is not
    evidence then. Not when more packages went without an answer than at the scan before (ANSWER_LEVEL_REASONS). A package that
    was removed is a clear, since a package that is not listed is not counted as unchecked. A scan with no block, which is a
    scan the scanner of this version did not make, is judged as it always was."""
    after = covered_view(now, with_packages=False)
    if after is None:
        return True
    reasons = after["reasons"]
    if any(reasons.get(r) for r in HOST_LEVEL_REASONS):
        return False
    prior = covered_view(before, with_packages=False)
    held = sum(prior["reasons"].get(r, 0) for r in ANSWER_LEVEL_REASONS) if prior else 0
    return sum(reasons.get(r, 0) for r in ANSWER_LEVEL_REASONS) <= held


def covered_add(total: dict[str, Any], block: Any) -> None:
    """Add one host's block (a `covered_view`) to the fleet's: listed, checked, not_checked and the reasons."""
    if not isinstance(block, dict):
        return
    for key in ("listed", "checked", "not_checked"):
        total[key] = total.get(key, 0) + _count(block.get(key))
    reasons = total.setdefault("reasons", {})
    held = block.get("reasons")
    for reason, n in (held if isinstance(held, dict) else {}).items():
        if reason in REASONS and _count(n):
            reasons[reason] = reasons.get(reason, 0) + _count(n)


def _packages(n: int) -> str:
    return f"{n:,} package" + ("" if n == 1 else "s")


def coverage_words(block: Any) -> str:
    """One sentence about how much of a host a scan looked at, "" when it looked at all of it (or there is no
    block). "Checked 1,834 of 1,901 packages; 67 not checked: 52 have no source name, 15 are not published by
    the distribution." For the texts that are not a page."""
    view = covered_view(block, with_packages=False)
    if not view or not view["not_checked"]:
        return ""
    why = ", ".join(f"{n:,} {REASON_WORDS[r]}" for r, n in view["reasons"].items())
    return (
        f"Checked {view['checked']:,} of {_packages(view['listed'])}; "
        f"{view['not_checked']:,} not checked: {why}."
    )


def none_found_words(block: Any) -> str:
    """What "none found" has to say when some of the packages were not checked, "" when all of them were (or
    there is no block) and the plain "none found" is true. "none found in the 1,834 packages that could be
    checked"; with nothing checked at all, "none found, but none of the 1,901 packages could be checked".
    """
    view = covered_view(block, with_packages=False)
    if not view or not view["not_checked"]:
        return ""
    if not view["checked"]:
        return f"none found, but none of the {_packages(view['listed'])} could be checked"
    n = view["checked"]
    return f"none found in the {n:,} package{'' if n == 1 else 's'} that could be checked"


# ── 8.0.2: the kernel a host runs ────────────────────────────────────────────────────────────────────────
#
# A finding against the kernel is matched against a kernel package, and a host keeps several: the one it runs and the
# ones it kept. The agent reports the release it runs and, for each installed kernel image, the release that image
# owns (the file /boot/vmlinuz-<release>, or the modules directory on Alpine). When exactly one installed package owns
# the running release, the scan matches the kernel's findings against that package's version alone, leaves out the
# findings of the kernels that are installed and do not run, and marks a finding that one of those would clear as
# `reboot`. When it cannot say which package the running kernel is, it matches every installed kernel as it did before,
# and the block it stores says that and why. `cve_scanner.kernel_state` builds the block, as `kernel`.
KERNEL_MATCHED = "matched"
KERNEL_UNKNOWN = "unknown"
KERNEL_WHY = ("not_reported", "no_images", "no_owner", "several_owners", "not_in_list")
KERNEL_WHY_WORDS = {
    "not_reported": "the agent of this host does not report its running kernel",
    "no_images": "the agent found no installed kernel package",
    "no_owner": "no installed kernel package owns the files of the running kernel",
    "several_owners": "more than one installed package owns the running kernel, and they are built from different versions",
    "not_in_list": "the package that owns the running kernel is not in the package list the host sent",
}


def kernel_view(value: Any) -> dict[str, Any] | None:
    """The `kernel` block of a stored scan result as a page or a tool gets it, None when there is none or it cannot be
    read. Text is cut, a state or a reason that is not one of the above is left out, and `left_out` is a whole number.
    """
    if not isinstance(value, dict) or value.get("state") not in (KERNEL_MATCHED, KERNEL_UNKNOWN):
        return None

    def text(key: str, limit: int) -> str:
        found = value.get(key)
        return found[:limit] if isinstance(found, str) else ""

    out: dict[str, Any] = {"state": value["state"], "running": text("running", 80)}
    if value["state"] == KERNEL_MATCHED:
        out["package"] = text("package", 128)
        out["version"] = text("version", 64)
        out["newer"] = text("newer", 200)
    else:
        out["why"] = value.get("why") if value.get("why") in KERNEL_WHY else ""
    out["left_out"] = _count(value.get("left_out"))
    return out


def kernel_words(block: Any) -> str:
    """One sentence about which kernel a host runs and how it was matched, "" when the scan has no account of it. For
    the texts that are not a page."""
    view = kernel_view(block)
    if not view:
        return ""
    running = view["running"] or "unknown"
    if view["state"] == KERNEL_MATCHED:
        said = f"The host runs kernel {running}, the package {view['package']} {view['version']}."
        if view["newer"]:
            said += f" A newer kernel is installed and not running ({view['newer']}): a reboot starts it."
        return said
    why = KERNEL_WHY_WORDS.get(view["why"], "")
    return (
        f"The running kernel ({running}) could not be matched to an installed package"
        + (f": {why}" if why else "")
        + ". Findings against the kernel are matched against every installed kernel."
    )

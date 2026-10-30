"""RemotePower — does a CVE finding have a fix for the host's own release? (v7.4.6, issue #57)

OSV keeps one `affected` entry per package and per release of a distribution. A Debian record for curl
reads: Debian 12 has no fix, Debian 13 and 14 are fixed in 8.7.1-1. The scanner folded those entries
together, so a host on Debian 12 was shown "fixed in 8.7.1-1", a version it cannot install, and counted
as fixable. This module keeps the entries apart and answers, for the release one host runs:

  fixed          an update to the fixed version of the host's own release clears it
  newer_release  the host's release has no fix, a newer release does
  none           no release has a fix yet
  unknown        the scan name of the distribution does not say which release the host runs (Ubuntu,
                 Rocky, Alma, Red Hat), or the record was cached before the entries were kept apart

Only the distributions whose OSV name carries the release (Debian:12, Alpine:v3.19) can be told apart.

Nothing here imports api or the network code. The scanner and the alert paths hand in what they hold.
"""

from __future__ import annotations

import re
from typing import Any

FIXED = "fixed"
NEWER_RELEASE = "newer_release"
NONE = "none"
UNKNOWN = "unknown"
STATUSES = (FIXED, NEWER_RELEASE, NONE, UNKNOWN)

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
    return None


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


def classify(fixes: Any, ecosystem: Any, package: str) -> dict[str, Any]:
    """The status of one package in one host's release, from the `extract` map of its record.

    Returns {"status": ..., "fixed": [versions in the host's release], "elsewhere": {ecosystem: [versions]}}.
    "elsewhere" is filled only for newer_release."""
    unknown: dict[str, Any] = {"status": UNKNOWN, "fixed": [], "elsewhere": {}}
    if (
        release_of(ecosystem) is None
        or not isinstance(fixes, dict)
        or not isinstance(ecosystem, str)
    ):
        return unknown
    here = _fixes_in(fixes, ecosystem, package)
    if here is None:
        return unknown  # the record names no entry for this package in this release: cannot say
    if here:
        return {"status": FIXED, "fixed": here, "elsewhere": {}}
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
    if status in (NEWER_RELEASE, NONE):
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


def alert_candidate(finding: Any, fixable_only: bool, kev: Any) -> bool:
    """Should this finding be able to raise cve_found? With the option off every finding is a candidate and
    the severity filter and the accepted-risk list decide, as before. With it on, only one an update can
    clear, or one on the known-exploited list, which alerts whatever its fix status."""
    if not fixable_only:
        return True
    return is_fixable(finding) or finding_is_kev(finding, kev)


def summarize(findings: Any, ignore_ids: Any) -> dict[str, int]:
    """How many findings an update can clear now, how many are fixed only in a newer release, how many have
    no fix yet and how many cannot be told. They add up to the findings that are not ignored."""
    out = {"fixable": 0, NEWER_RELEASE: 0, NONE: 0, "unchecked": 0}
    for finding in _as_list(findings):
        if not isinstance(finding, dict) or finding.get("vuln_id") in ignore_ids:
            continue
        if is_fixable(finding):
            out["fixable"] += 1
        elif finding.get("fix_status") == NEWER_RELEASE:
            out[NEWER_RELEASE] += 1
        elif finding.get("fix_status") == NONE:
            out[NONE] += 1
        else:
            out["unchecked"] += 1
    return out

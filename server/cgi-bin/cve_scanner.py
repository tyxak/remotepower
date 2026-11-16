#!/usr/bin/env python3
"""
RemotePower CVE Scanner — v1.7.0
(Full version with Ubuntu priority, Debian fallback, Arch unsupported)
"""
import json
import os
import time
import hashlib
import re
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import checks        # v7.0.3: the shared accepted-risk predicate
import cve_fixes     # v7.4.6 (#57): which release of the host a fix is in (pure)
import pkg_versions  # 8.0.1: the version order of RPM and Alpine packages (pure)
import safe_opener   # v6.4.3: no file/ftp/data on an outbound opener
import urllib.error
import urllib.parse
from pathlib import Path


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse 3xx. The vuln-DB hosts below are fixed public constants, so a
    redirect can only be an attempt to bounce the request to an unintended
    (possibly internal) host — blind SSRF. Fail closed instead of following."""
    def redirect_request(self, *a, **k):  # noqa: D401
        return None


# No-redirect opener for every outbound vuln-DB fetch. Defense in depth: the
# hosts are hardcoded, no credential is sent and the response is never
# reflected, but a poisoned DNS answer / 302 must not be followed regardless.
_OPENER = safe_opener.strip_local_schemes(urllib.request.build_opener(_NoRedirect))

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL       = "https://api.osv.dev/v1/vulns/"

OSV_BATCH_SIZE     = 500
OSV_TIMEOUT        = 30
OSV_DETAIL_TIMEOUT = 10

DETAILS_CACHE_TTL  = 7 * 86400
MAX_PACKAGES       = 10000
MAX_RESP_BYTES     = 32 * 1024 * 1024   # cap upstream OSV/Debian responses (memory-DoS guard)

SEVERITY_ORDER = ('critical', 'high', 'medium', 'low', 'unknown')

# List of ecosystems that OSV actually supports
OSV_SUPPORTED_ECOSYSTEMS = (
    'Ubuntu',
    'Debian:',      # Debian:11, Debian:12, etc.
    'Rocky Linux',
    'AlmaLinux',
    'Red Hat',
    'Alpine:',      # Alpine:v3.18, etc.
)


# ── OSV ecosystem detection ───────────────────────────────────────────────────

_RELEASED_BY_MAJOR = ('Rocky Linux', 'AlmaLinux')


def _with_major(name: str, major: str) -> str:
    """'AlmaLinux' and '9' give 'AlmaLinux:9'. Without a usable number the bare name is kept: it answers
    for every release, which is more findings than the host has and never fewer."""
    major = str(major or '').strip()
    if major.isascii() and major.isdigit() and len(major) <= 3 and int(major) > 0:
        return f'{name}:{int(major)}'
    return name


def entry_ecosystem(entry) -> str:
    """The name to scan a stored package list under. A list stored before 8.0.1 says 'AlmaLinux' or
    'Rocky Linux' with no release; the release is in the entry's `version_id`, so the scan does not have
    to wait for the host to send its list again."""
    if not isinstance(entry, dict):
        return ''
    ecosystem = entry.get('ecosystem')
    if not isinstance(ecosystem, str):
        return ''
    if ecosystem in _RELEASED_BY_MAJOR:
        return _with_major(ecosystem, str(entry.get('version_id') or '').split('.')[0])
    return ecosystem


def entry_release(entry) -> str:
    """The name the host's own release has inside an advisory record, '' when it is not known.

    Debian and Alpine are scanned under that name already. Ubuntu is scanned under the bare name
    "Ubuntu", which answers for whichever release holds the version asked; its records then list one
    entry per release, and the host's is found by the version the host reported: 22.04 is
    "Ubuntu:22.04:LTS". Pop!_OS numbers its releases as Ubuntu does. Any other derivative reports a
    version of its own (Linux Mint 21.3), which names no Ubuntu release."""
    ecosystem = entry_ecosystem(entry)
    if ecosystem == 'Ubuntu':
        if str(entry.get('os_id') or '').strip().lower() in ('ubuntu', 'pop'):
            return cve_fixes.ubuntu_release_name(entry.get('version_id'))
        return ''
    return ecosystem if cve_fixes.release_of(ecosystem) is not None else ''


def by_source(ecosystem, release) -> bool:
    """Is a Debian or Ubuntu host asked for by source package? Only when its release is known: what
    comes back is every known CVE of the release, fixed or not, and without the release the scan
    cannot tell the two apart."""
    return family(ecosystem) == 'deb' and cve_fixes.release_of(release or ecosystem) is not None


def family(ecosystem) -> str:
    """Which package format an ecosystem name stands for: 'deb', 'rpm', 'apk' or ''."""
    if not isinstance(ecosystem, str):
        return ''
    if ecosystem == 'Ubuntu' or ecosystem.startswith(('Ubuntu:', 'Debian')):
        return 'deb'
    if ecosystem.startswith(('Rocky Linux', 'AlmaLinux', 'Red Hat')):
        return 'rpm'
    if ecosystem.startswith('Alpine'):
        return 'apk'
    return ''


def coverage(ecosystem, has_meta: bool = False, release: str = '') -> str:
    """What a scan of this host leaves out, as a word the page turns into a sentence.

    'needs_agent'  the advisories are filed under the source package and the list comes from an agent
                   that does not report source packages (Debian, Ubuntu, Alpine, Rocky), so a package
                   named otherwise than its source is not checked
    'no_release'   an Ubuntu derivative whose own version names no Ubuntu release: it is asked for by
                   installed name for the same effect, whatever its agent reports
    ''             nothing known to be left out"""
    fam = family(ecosystem)
    if fam == 'deb':
        if not by_source(ecosystem, release):
            return 'no_release'
        return '' if has_meta else 'needs_agent'
    if not has_meta and (fam == 'apk' or (fam == 'rpm' and ecosystem.startswith('Rocky Linux'))):
        return 'needs_agent'
    return ''


def detect_ecosystem(os_release: dict, pkg_manager: str) -> str | None:
    """Map /etc/os-release + pkg_manager to OSV ecosystem string."""
    if not os_release:
        return None
    os_id     = str(os_release.get('ID') or '').lower().strip()
    id_like   = str(os_release.get('ID_LIKE') or '').lower().strip()
    ver_id    = str(os_release.get('VERSION_ID') or '').strip()
    ver_major = ver_id.split('.')[0] if ver_id else ''

    if pkg_manager == 'apt':
        if os_id == 'debian' and ver_major:
            return f'Debian:{ver_major}'
        if os_id == 'ubuntu':
            return 'Ubuntu'
        # Ubuntu derivatives (Zorin, Linux Mint, Pop!_OS, elementary, …) carry
        # ID_LIKE="ubuntu debian" and track Ubuntu's package versions, so they
        # map to the Ubuntu ecosystem. Check 'ubuntu' BEFORE 'debian': their
        # ID_LIKE contains both, and their VERSION_ID is the derivative's own
        # (e.g. Zorin 18), which is meaningless as a Debian release number.
        if 'ubuntu' in id_like:
            return 'Ubuntu'
        if 'debian' in id_like and ver_major:
            return f'Debian:{ver_major}'
        return None

    if pkg_manager == 'dnf':
        # 8.0.1: Rocky and Alma are asked for with their major release. The bare name answers for every
        # release at once, and an el9 package is older than most el10 fixes of the same package, so a
        # host on release 9 was shown the advisories of release 10 (7 of 20 for openssl-libs).
        if os_id == 'rocky':
            return _with_major('Rocky Linux', ver_major)
        if os_id == 'almalinux':
            return _with_major('AlmaLinux', ver_major)
        if os_id in ('rhel', 'redhat'):
            return 'Red Hat'
        return None

    if pkg_manager == 'pacman':
        # OSV does NOT support Arch Linux
        return None

    if pkg_manager == 'apk':
        if ver_id:
            # OSV keys Alpine by major.minor (Alpine:v3.18), not the full
            # VERSION_ID (3.18.4) — using the full string misses every match.
            mm = '.'.join(str(ver_id).split('.')[:2])
            return f'Alpine:v{mm}'
        return None
    return None


# ── OSV API helpers ──────────────────────────────────────────────────────────

def _osv_querybatch(queries: list) -> list:
    body = json.dumps({'queries': queries}).encode('utf-8')
    req = urllib.request.Request(
        OSV_QUERYBATCH_URL,
        data=body,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    with _OPENER.open(req, timeout=OSV_TIMEOUT) as resp:
        return json.loads(resp.read(MAX_RESP_BYTES).decode('utf-8')).get('results', [])


# 8.0.1: a long answer comes in pages. The kernel of an old release has more than a thousand advisories,
# and the first page was read as the whole answer.
OSV_MAX_PAGES = 10


def _osv_query_all(queries: list) -> list:
    """One {'vulns': [...]} per query, in order, with every page of a long answer followed.

    An answer that is still not finished after OSV_MAX_PAGES pages is marked 'truncated': True, so the
    scan can say that the list is cut instead of presenting it as whole. A transport failure raises, as
    `_osv_querybatch` does, and so does an answer of another shape than one result per query: read as
    "no advisories" it would empty a host's findings and announce them cleared."""
    results = [{'vulns': []} for _ in queries]
    owed = list(range(len(queries)))
    tokens: dict = {}
    for _page in range(OSV_MAX_PAGES):
        if not owed:
            break
        still = []
        for start in range(0, len(owed), OSV_BATCH_SIZE):
            chunk = owed[start:start + OSV_BATCH_SIZE]
            body = [dict(queries[k], page_token=tokens[k]) if k in tokens else queries[k] for k in chunk]
            answers = _osv_querybatch(body)
            if not isinstance(answers, list) or len(answers) != len(chunk):
                raise ValueError('OSV did not answer every query of a batch')
            for k, answer in zip(chunk, answers):
                vulns = answer.get('vulns', []) if isinstance(answer, dict) else None
                if not isinstance(vulns, list) or not all(isinstance(v, dict) for v in vulns):
                    raise ValueError('an OSV answer is not a list of advisories')
                results[k]['vulns'].extend(vulns)
                token = answer.get('next_page_token')
                if isinstance(token, str) and token:
                    tokens[k] = token
                    still.append(k)
        owed = still
    for k in owed:
        results[k]['truncated'] = True
    return results


# ── 8.0.1: what to ask for ───────────────────────────────────────────────────
#
# The advisory database files an advisory under the name the distribution's own security data uses, and
# that is not always the name of the installed package. Measured 2026-11-15, one query per name:
#
#   Alpine       the origin: "openssl" answers, "libcrypto3" and "libssl3" answer nothing
#   Rocky Linux  the source package in the older advisories, every built package in the newer ones
#   AlmaLinux    every built package: "krb5-libs" answers, the source name "krb5" answers nothing
#   Red Hat      both
#   Debian and Ubuntu  the source package: "glibc" answers, "libc6" answers nothing
#
# So a host is asked for in units. A unit is one (name, version) question, the package its findings are
# filed under, and the installed packages it speaks for. Alpine is asked by origin, Debian and Ubuntu by
# source package and its version, Rocky by both names, and the findings of one source package are one
# finding however many packages were built from it. That needs what an 8.0.1 agent reports (the source
# package and the epoch); a list without them is asked for name by name, as before. A Debian or Ubuntu
# host is asked by source only when its release is known (see `by_source`).

MAX_BINARIES_SHOWN = 30


def _text(value) -> str:
    return str(value or '').strip()


def plan(packages, ecosystem, has_meta: bool = False, deb_by_source: bool = False) -> list:
    """The units to ask the advisory database for, for one host's package list. `deb_by_source` is
    `by_source(ecosystem, release)` of the host.

    Each unit is {'name', 'version'} (the question), 'package' and 'shown' (the name and version on a
    finding), 'epoch_known' (whether the version carries its epoch) and 'binaries' (the installed packages
    the unit speaks for; empty when the unit is the installed package itself)."""
    fam = family(ecosystem)
    units: dict = {}

    def unit(name, version, package, epoch_known, binary):
        key = (name, version)
        found = units.get(key)
        if found is None:
            found = units[key] = {'name': name, 'version': version, 'package': package, 'shown': version,
                                  'epoch_known': epoch_known, 'binaries': []}
        if binary and binary not in found['binaries']:
            found['binaries'].append(binary)

    grouped = bool(has_meta) and (fam in ('apk', 'rpm') or (fam == 'deb' and bool(deb_by_source)))
    both_names = grouped and fam == 'rpm' and isinstance(ecosystem, str) and ecosystem.startswith('Rocky Linux')
    sources: dict = {}   # (source, its version-release) -> {'binaries': [...], 'epochs': set()}
    for p in (packages if isinstance(packages, list) else [])[:MAX_PACKAGES]:
        if not isinstance(p, dict):
            continue
        name, version = _text(p.get('name')), _text(p.get('version'))
        if not name or not version:
            continue
        if not grouped:
            # an RPM list without epochs: the version is asked for as it is, which answers with every
            # advisory of a package that has an epoch, and the "already patched" check sorts them out
            unit(name, version, name, fam != 'rpm', None)
            continue
        source = _text(p.get('source')) or name
        if fam == 'apk':
            unit(source, version, source, True, name)   # a subpackage has its origin's version
            continue
        if fam == 'deb':
            # a Debian package may have another version than its source ("12.2.0-14+b1" of "12.2.0-14")
            unit(source, _text(p.get('source_version')) or version, source, True, name)
            continue
        epoch = _text(p.get('epoch'))
        if not (epoch.isascii() and epoch.isdigit()) or int(epoch) == 0:
            epoch = ''
        unit(name, f'{epoch}:{version}' if epoch else version, source, True, name)
        if both_names:
            source_version = _text(p.get('source_version')) or version
            group = sources.setdefault((source, source_version), {'binaries': [], 'epochs': set()})
            group['binaries'].append(name)
            if version == source_version:
                group['epochs'].add(epoch)
    for (source, source_version), group in sources.items():
        # The source package's own epoch is not in what a host can report. It is the epoch of a package
        # built from it with the source's version, when they agree on one; otherwise the source is not
        # asked for by name and its packages still are.
        if len(group['epochs']) != 1:
            continue
        epoch = next(iter(group['epochs']))
        for binary in group['binaries']:
            unit(source, f'{epoch}:{source_version}' if epoch else source_version, source, True, binary)
    return list(units.values())


def _osv_vuln_details(vuln_id: str) -> dict | None:
    try:
        req = urllib.request.Request(
            OSV_VULN_URL + urllib.parse.quote(vuln_id, safe=''),
            headers={'Accept': 'application/json'},
        )
        with _OPENER.open(req, timeout=OSV_DETAIL_TIMEOUT) as resp:
            return json.loads(resp.read(MAX_RESP_BYTES).decode('utf-8'))
    except Exception:
        return None


# ── v5.0.0 (#R5): OSV circuit breaker ────────────────────────────────────────
# When OSV.dev is unreachable, a fleet scan would otherwise hammer it once per
# device (thundering herd) and stall every scan on the timeout. After
# OSV_FAIL_THRESHOLD consecutive failures the breaker OPENS for OSV_COOLDOWN
# seconds: scan_device returns immediately (skipped) without touching OSV, and
# the next attempt after the cooldown probes again (half-open). State is a tiny
# file in the same cache dir as the details cache.
OSV_FAIL_THRESHOLD = 3
OSV_COOLDOWN = 600  # 10 minutes


def _breaker_path(cache_dir: Path) -> Path:
    return cache_dir / "cve_osv_breaker.json"


def osv_breaker_open(cache_dir: Path, now: int = None) -> bool:
    """True when the breaker is open — callers should skip OSV work."""
    now = now if now is not None else int(time.time())
    st = _load_json(_breaker_path(cache_dir))
    return int(st.get("open_until", 0) or 0) > now


def osv_breaker_record(cache_dir: Path, ok: bool, now: int = None) -> dict:
    """Record one OSV outcome. A success resets the breaker; consecutive
    failures past the threshold open it for OSV_COOLDOWN. Returns the new state."""
    now = now if now is not None else int(time.time())
    if ok:
        st = {"failures": 0, "open_until": 0, "last_ok": now}
    else:
        st = _load_json(_breaker_path(cache_dir))
        st["failures"] = int(st.get("failures", 0)) + 1
        st["last_fail"] = now
        if st["failures"] >= OSV_FAIL_THRESHOLD:
            st["open_until"] = now + OSV_COOLDOWN
    _save_json(_breaker_path(cache_dir), st)
    return st


def _ecosystem_supported(ecosystem: str) -> bool:
    return bool(ecosystem) and any(
        ecosystem.startswith(p) for p in OSV_SUPPORTED_ECOSYSTEMS)


# ── v5.0.0 (#S1): cross-device OSV batching ──────────────────────────────────
# A naive fleet scan calls OSV once per device. On a homogeneous fleet (same
# distro → the same package set) that's hugely redundant. prefetch_osv collects
# the DEDUPLICATED (ecosystem, name, version) union across every device, queries
# OSV once per ecosystem, and returns a {(eco, name, ver): result} map that
# scan_device consults instead of making its own calls — O(unique packages)
# OSV traffic instead of O(devices × packages).
def prefetch_osv(store: dict, cache_dir: Path) -> dict | None:
    """Build the shared OSV result map for a whole fleet. Returns {} if the breaker is open or nothing is
    scannable (scan_device then skips), and None when a query failed part-way: the caller then scans each
    host with its own queries. Records breaker outcomes like a normal scan.

    8.0.1: a failure used to return what had been collected so far. scan_device reads a name that is not
    in the map as "no advisories", so one failed request emptied the findings of every host in the scan
    and each of them announced that its vulnerabilities were cleared."""
    if osv_breaker_open(cache_dir):
        return {}
    by_eco = {}   # ecosystem -> ordered unique [(name, version)]
    seen = set()
    for entry in (store or {}).values():
        if not isinstance(entry, dict):
            continue
        eco = entry_ecosystem(entry)
        if not _ecosystem_supported(eco):
            continue
        for unit in plan(entry.get("packages") or [], eco, entry.get("sources") is True,
                         by_source(eco, entry_release(entry))):
            key = (eco, unit['name'], unit['version'])
            if key in seen:
                continue
            seen.add(key)
            by_eco.setdefault(eco, []).append((unit['name'], unit['version']))
    result_map = {}
    for eco, pkgs in by_eco.items():
        queries = [{"package": {"name": n, "ecosystem": eco}, "version": v}
                   for (n, v) in pkgs]
        try:
            res = _osv_query_all(queries)
        except Exception:
            osv_breaker_record(cache_dir, ok=False)
            return None
        for (n, v), r in zip(pkgs, res):
            result_map[(eco, n, v)] = r or {}
    if result_map:
        osv_breaker_record(cache_dir, ok=True)
    return result_map


# ── CVSS vector parser ───────────────────────────────────────────────────────
#
# v2.3.4: the previous implementation did naive substring matching on the
# vector string — e.g. `'c:h' in vector` — which matched `AC:H` (Attack
# Complexity: High) as if it were `C:H` (Confidentiality: High). The result:
# ANY CVSS v3 vuln with high attack complexity scored 7.5 / HIGH regardless
# of its real impact. A LOW CVE (CVSS 2.9) with AC:H was reported
# as HIGH. This is now a proper tokenised parse + the real CVSS 3.1 base
# score formula.

# CVSS 3.x metric weights (from the CVSS v3.1 specification).
_CVSS3_AV = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
_CVSS3_AC = {'L': 0.77, 'H': 0.44}
_CVSS3_UI = {'N': 0.85, 'R': 0.62}
_CVSS3_CIA = {'N': 0.0, 'L': 0.22, 'H': 0.56}
# Privileges Required depends on Scope.
_CVSS3_PR_UNCHANGED = {'N': 0.85, 'L': 0.62, 'H': 0.27}
_CVSS3_PR_CHANGED   = {'N': 0.85, 'L': 0.68, 'H': 0.5}


def _cvss3_roundup(value: float) -> float:
    """CVSS v3.1 roundup: smallest number, to one decimal place, >= value.
    Uses integer arithmetic to avoid float artefacts, as the spec does."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (int_input // 10000 + 1) / 10.0


def _parse_cvss_vector(vector: str) -> dict:
    """Tokenise a CVSS vector string into a {METRIC: VALUE} dict.
    Splits strictly on '/' and ':' — no substring matching."""
    metrics = {}
    for token in vector.split('/'):
        if ':' in token:
            k, _, v = token.partition(':')
            metrics[k.strip().upper()] = v.strip().upper()
    return metrics


def _cvss3_base_score(metrics: dict) -> float | None:
    """Compute the CVSS v3.1 base score from parsed metrics. Returns None
    if the required base metrics aren't all present."""
    required = ('AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A')
    if not all(m in metrics for m in required):
        return None
    try:
        scope_changed = metrics['S'] == 'C'
        c = _CVSS3_CIA[metrics['C']]
        i = _CVSS3_CIA[metrics['I']]
        a = _CVSS3_CIA[metrics['A']]
        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss
        pr_table = _CVSS3_PR_CHANGED if scope_changed else _CVSS3_PR_UNCHANGED
        exploitability = (8.22
                          * _CVSS3_AV[metrics['AV']]
                          * _CVSS3_AC[metrics['AC']]
                          * pr_table[metrics['PR']]
                          * _CVSS3_UI[metrics['UI']])
        if impact <= 0:
            return 0.0
        if scope_changed:
            return _cvss3_roundup(min(1.08 * (impact + exploitability), 10.0))
        return _cvss3_roundup(min(impact + exploitability, 10.0))
    except (KeyError, ValueError, TypeError):
        return None


def _cvss_base_score(vector: str) -> float | None:
    """Extract a CVSS base score from an OSV severity 'score' field.

    OSV reports the score either as a bare number, a "<number>/CVSS:..."
    string, or a full CVSS vector. v2.3.4: vectors are properly parsed and
    scored via the real formula instead of substring-guessed.
    """
    if not vector:
        return None
    vector = vector.strip()

    # Case 1: a bare numeric score, possibly suffixed with the vector.
    head = vector.split('/')[0]
    try:
        score = float(head)
        if 0.0 <= score <= 10.0:
            return score
    except ValueError:
        pass

    # Case 2: a CVSS v3.x vector — parse and compute the real base score.
    if vector.upper().startswith('CVSS:3'):
        metrics = _parse_cvss_vector(vector)
        score = _cvss3_base_score(metrics)
        if score is not None:
            return score

    # Case 2b: a CVSS v4.0 vector. NVD and OSV have been publishing these since
    # 2023, and advisories increasingly carry ONLY a v4 vector — which fell
    # through every branch here and scored `unknown`, so a 9.3 filed as neither
    # critical nor high: no risk points, no CVE alert, invisible to the SLA and
    # compliance views. Silence about a critical CVE is the worst possible
    # failure mode for this function.
    #
    # v4's real formula is a MacroVector lookup table, which is a large thing to
    # vendor and get right. This maps the v4 BASE metrics onto the v3.1 formula
    # instead: AV/AC/PR/UI carry over unchanged, the v4 subsequent-system
    # metrics (SC/SI/SA) stand in for v3's scope change, and VC/VI/VA are v3's
    # C/I/A. The result is an approximation — labelled as one by
    # `_cvss_source()` — but it lands in the right severity band, which is the
    # decision this score actually drives.
    if vector.upper().startswith('CVSS:4'):
        m = _parse_cvss_vector(vector)
        # UI is the one metric whose VOCABULARY changed: v3 is N|R, v4 is
        # N|P|A (none / passive / active). Passing 'A' through unmapped made
        # _cvss3_base_score reject the whole vector and fall back to unknown —
        # which is how a low/medium v4 advisory stayed invisible even after the
        # branch above existed. Both v4 values that require a user map to 'R'.
        _ui = {'N': 'N', 'P': 'R', 'A': 'R'}.get(m.get('UI', 'N'), 'R')
        # v4 split impact into vulnerable-system (VC/VI/VA) and subsequent-system
        # (SC/SI/SA); v3.1 has ONE impact triple and expresses "it reaches beyond
        # the vulnerable component" with the scope flag. So take the worst of the
        # two per dimension. Mapping only the vulnerable-system half scored 0.0
        # for a vector like `VC:N/VI:N/VA:N/SC:H/SI:H/SA:H` — a real shape (an
        # official 9.3 CRITICAL) that v3.1's impact term reads as no impact at
        # all, so it was filed `low` while PRESENTING as a computed score.
        _rank = {'N': 0, 'L': 1, 'H': 2}

        def _worst(vuln_key, subseq_key):
            a, b = m.get(vuln_key, 'N'), m.get(subseq_key, 'N')
            return a if _rank.get(a, 0) >= _rank.get(b, 0) else b

        approx = {
            'AV': m.get('AV', 'N'), 'AC': m.get('AC', 'L'),
            'PR': m.get('PR', 'N'), 'UI': _ui,
            'C': _worst('VC', 'SC'), 'I': _worst('VI', 'SI'), 'A': _worst('VA', 'SA'),
            # v4 replaced the scope flag with explicit subsequent-system impact;
            # any of them non-None is what v3 called a scope change.
            'S': 'C' if any(m.get(k, 'N') != 'N' for k in ('SC', 'SI', 'SA')) else 'U',
        }
        score = _cvss3_base_score(approx)
        if score is not None:
            return score

    # Case 3: a CVSS v2 vector. We don't implement the full v2 formula;
    # derive a conservative score from the impact metrics via EXACT
    # token lookup (no substring matching). v2 metrics: C/I/A = N|P|C.
    if vector.upper().startswith('CVSS:2') or '/C:' in vector.upper():
        metrics = _parse_cvss_vector(vector)
        impacts = [metrics.get(k, 'N') for k in ('C', 'I', 'A')]
        if 'C' in impacts:        # at least one Complete impact
            return 7.5
        if 'P' in impacts:        # at least one Partial impact
            return 5.0
        return 2.0                # all None — low

    # Unparseable — signal "unknown" rather than guessing a number.
    return None


# ── Debian Security Tracker fallback ─────────────────────────────────────────

def _debian_severity_fallback(cve_id: str) -> str | None:
    """Map a Debian Security Tracker 'urgency' to a severity band.

    IMPORTANT: Debian's `urgency` is NOT a CVSS severity. It is a
    *patching-priority* signal — Debian's triage of how soon they want
    a fix out, which factors in exploit availability and exposure, not
    just impact. Debian routinely marks something `high` urgency that
    CVSS rates Medium (the v2.4.0 trigger: DEBIAN-CVE-2018-1000021 —
    Debian urgency high, OSV CVSS 5.0 Medium).

    So this fallback — which only runs when there is no real CVSS
    score and no distro severity rating — is CAPPED at
    `medium`. It can never return `high` or `critical`: claiming a
    HIGH severity requires an actual CVSS score or a distro's explicit
    severity rating, not an urgency hint. Returning `medium` for a
    high/medium urgency, and `low` for low/negligible, is the honest
    conservative mapping when urgency is all we have.
    """
    if cve_id.startswith('DEBIAN-'):
        cve_id = cve_id[7:]
    try:
        url = f"https://security-tracker.debian.org/api/json/cve/{urllib.parse.quote(cve_id, safe='')}"
        req = urllib.request.Request(url, headers={'User-Agent': 'RemotePower'})
        with _OPENER.open(req, timeout=10) as resp:
            data = json.loads(resp.read(MAX_RESP_BYTES).decode('utf-8'))
        # Debian urgency can carry a '**' suffix (postponed / end-of-life
        # — e.g. 'low**'); strip it before matching.
        urgency = str(data.get('urgency', '')).lower().rstrip('*').strip()
        # high / medium urgency → capped at 'medium' (see docstring)
        if urgency in ('high', 'medium'):
            return 'medium'
        if urgency in ('low', 'unimportant', 'negligible'):
            return 'low'
    except Exception:
        pass
    return None


# ── Severity extraction (prioritizes Ubuntu priority) ────────────────────────

# CVSS base-score → severity-band cutoffs. Operator-configurable (Settings →
# Forecast & CVE tuning). This module has no `api` import (it runs in the detached
# cve_scan_runner process too), so the api-side scan worker calls set_cvss_bands()
# with the persisted config values before a scan; defaults reproduce the standard
# CVSS 3.1 mapping so an unconfigured server classifies identically.
# The _DEFAULT_* constants are IMMUTABLE (the "reset" target + what api-side code
# reports as the default); the bare names are the LIVE mutable values that
# set_cvss_bands rewrites and _severity_from_vuln reads — never treat those as the
# default in a persistent worker (a prior scan may have moved them).
_CVSS_BAND_DEFAULT_CRITICAL = 9.0
_CVSS_BAND_DEFAULT_HIGH     = 7.0
_CVSS_BAND_DEFAULT_MEDIUM   = 4.0
_CVSS_BAND_CRITICAL = _CVSS_BAND_DEFAULT_CRITICAL
_CVSS_BAND_HIGH     = _CVSS_BAND_DEFAULT_HIGH
_CVSS_BAND_MEDIUM   = _CVSS_BAND_DEFAULT_MEDIUM


def set_cvss_bands(critical=_CVSS_BAND_DEFAULT_CRITICAL,
                   high=_CVSS_BAND_DEFAULT_HIGH,
                   medium=_CVSS_BAND_DEFAULT_MEDIUM):
    """Override the CVSS→severity band cutoffs (called once per scan from the
    api-side worker with the operator's config). Floats; no persistence."""
    global _CVSS_BAND_CRITICAL, _CVSS_BAND_HIGH, _CVSS_BAND_MEDIUM
    _CVSS_BAND_CRITICAL = float(critical)
    _CVSS_BAND_HIGH     = float(high)
    _CVSS_BAND_MEDIUM   = float(medium)


def _severity_from_vuln(vuln: dict, ecosystem: str = None) -> tuple:
    """Extract (severity, source) for a vuln.

    `source` records WHERE the severity came from — per the v2.3.4
    spec requirement to log the classification source. One of:
    'database_specific', 'ubuntu_priority', 'cvss_v3', 'cvss_v4_approx', 'cvss_v2',
    'debian_urgency', 'unknown'.

    Priority order: distro's own rating (database_specific, then
    Ubuntu priority) wins over CVSS, because distros downgrade/upgrade
    based on how a CVE actually affects their packages. CVSS is the
    fallback. The CVSS→band mapping is the standard one and a score
    below 4.0 can never become 'high'.
    """
    # 1. database_specific fields (Debian, Arch, etc.)
    db_spec = vuln.get('database_specific') or {}
    for field in ('severity', 'priority'):
        raw = str(db_spec.get(field) or '').lower()
        if raw in SEVERITY_ORDER:
            return raw, 'database_specific'
        if raw in ('important',):
            return 'high', 'database_specific'
        if raw in ('moderate',):
            return 'medium', 'database_specific'
        if raw in ('negligible', 'unimportant'):
            return 'low', 'database_specific'

    # 2. Ubuntu priority (type 'Ubuntu') — before CVSS.
    for sev in vuln.get('severity') if isinstance(vuln.get('severity'), list) else []:
        if isinstance(sev, dict) and sev.get('type') == 'Ubuntu':
            ubuntu_score = str(sev.get('score', '')).lower()
            if ubuntu_score in SEVERITY_ORDER:
                return ubuntu_score, 'ubuntu_priority'
            if ubuntu_score in ('important',):
                return 'high', 'ubuntu_priority'
            if ubuntu_score in ('moderate',):
                return 'medium', 'ubuntu_priority'
            if ubuntu_score in ('negligible', 'unimportant'):
                return 'low', 'ubuntu_priority'

    # 3. CVSS base score — standardised band mapping. Note <4.0 maps
    #    to 'low'/'medium' only; it can never become 'high'.
    rated = _cvss_first(vuln)
    if rated is not None:
        return _cvss_band(rated[0]), rated[1]

    # 4. Debian, a record with no score. 8.0.1: the record carries the tracker's urgency on every
    #    entry (755 of 755 entries of the DEBIAN-CVE records read on 2026-11-15), so the tracker is
    #    asked only for a record that carries none. It was one request per record, in the scan.
    #    The urgencies of every release are read, not those of the host's: the result is kept in a
    #    cache that hosts of several releases share. What one release calls unimportant is applied
    #    per host when a finding is made (cve_fixes.minor).
    if ecosystem and ecosystem.startswith('Debian:'):
        urgencies = _record_urgencies(vuln)
        if urgencies:
            if all(u in ('unimportant', 'negligible') for u in urgencies):
                return 'low', 'debian_urgency'
            # an urgency the tracker did assign reads as the tracker's answer did: never above medium
            # (see _debian_severity_fallback). None was among the records read on 2026-11-15.
            if any(u in ('high', 'medium') for u in urgencies):
                return 'medium', 'debian_urgency'
            if any(u == 'low' for u in urgencies):
                return 'low', 'debian_urgency'
        else:
            vuln_id = str(vuln.get('id') or '')
            # the tracker knows CVE ids; an advisory id (DSA-, DLA-) was sent to it as one
            if vuln_id.startswith(('DEBIAN-CVE-', 'CVE-')):
                deb_sev = _debian_severity_fallback(vuln_id)
                if deb_sev:
                    return deb_sev, 'debian_urgency'

    return 'unknown', 'unknown'


def _cvss_first(vuln: dict) -> tuple | None:
    """(base score, source) of the first CVSS entry of a record that can be scored, None for a
    record without one."""
    entries = vuln.get('severity') if isinstance(vuln, dict) else None
    for sev in entries if isinstance(entries, list) else []:
        vec = sev.get('score') if isinstance(sev, dict) else None
        if not isinstance(vec, str):
            continue
        score = _cvss_base_score(vec)
        if score is None:
            continue
        vtype = str(sev.get('type') or '').upper()
        # v6.4.2: name the v4 source honestly. The score is the v3.1 formula
        # applied to v4's base metrics, not an official v4 base score, and a
        # consumer that reads the source deserves to know which it got.
        if vtype.startswith('CVSS_V2'):
            return score, 'cvss_v2'
        if vtype.startswith('CVSS_V4') or vec.upper().startswith('CVSS:4'):
            return score, 'cvss_v4_approx'
        return score, 'cvss_v3'
    return None


def _cvss_band(score: float) -> str:
    """The severity band of a CVSS base score under the bands in force (set_cvss_bands)."""
    if score >= _CVSS_BAND_CRITICAL:
        return 'critical'
    if score >= _CVSS_BAND_HIGH:
        return 'high'
    if score >= _CVSS_BAND_MEDIUM:
        return 'medium'
    return 'low'


def _record_urgencies(vuln: dict) -> list:
    """The urgency a record gives its Debian entries, of every release ('unimportant',
    'not yet assigned'), lower-case. Empty when the record carries none."""
    out = []
    for entry in vuln.get('affected') or []:
        if not isinstance(entry, dict):
            continue
        package = entry.get('package')
        specific = entry.get('ecosystem_specific')
        if not isinstance(package, dict) or not isinstance(specific, dict):
            continue
        if not str(package.get('ecosystem') or '').startswith('Debian:'):
            continue
        urgency = specific.get('urgency')
        if isinstance(urgency, str) and urgency.strip():
            out.append(urgency.strip().lower().rstrip('*').strip())
    return out


# Debian and Ubuntu: a record per CVE, and the notices that repeat them
_PER_CVE_IDS = ('DEBIAN-CVE-', 'UBUNTU-CVE-')
_NOTICE_IDS = ('DSA-', 'DLA-', 'USN-', 'LSN-')


def _without_repeated_notices(hits, details: dict, release: str) -> tuple:
    """(the hits without the notices that repeat other findings, how many were left out).

    Debian and Ubuntu answer with one record per CVE and, a second time, with the notices that
    announced the fixes (a DSA, a USN). A notice is left out when the per-CVE records of the same
    package already tell the host to install a version at or past the notice's own fix: it is
    those findings again. A notice whose fix nothing else reaches stays a finding. Of the 81
    notices that came back on 2026-11-15, 78 had a per-CVE record with the same fix for the same
    release and three had none: an update without a CVE of its own, which would have been lost
    for a host that needs exactly that update.

    `release` is the name of the host's release in a record, '' when it is not known; then every
    release the notice names has to be reached."""
    reach: dict = {}    # id(unit) -> {ecosystem: [fixed versions its per-CVE records carry]}
    for unit, vid in hits:
        if not str(vid).startswith(_PER_CVE_IDS):
            continue
        mine = reach.setdefault(id(unit), {})
        fixes = (details.get(vid) or {}).get('eco_fix')
        for eco, packages in (fixes if isinstance(fixes, dict) else {}).items():
            versions = packages.get(unit['name']) if isinstance(packages, dict) else None
            mine.setdefault(eco, []).extend(v for v in (versions if isinstance(versions, list) else [])
                                            if isinstance(v, str))
    kept, left_out = [], 0
    for unit, vid in hits:
        if (str(vid).startswith(_NOTICE_IDS) and id(unit) in reach
                and _notice_repeats(details.get(vid), unit['name'], reach[id(unit)], release)):
            left_out += 1
            continue
        kept.append((unit, vid))
    return kept, left_out


def _notice_repeats(det, package: str, reach: dict, release: str) -> bool:
    """Does every fix this notice names for the package have a per-CVE fix at or past it, in the
    same release? False for a notice whose record was not read: what cannot be compared is kept.

    A notice that names no fix for the host's own release is about a package left over from another
    release (after an upgrade), or the release the host reported is stale. It is then compared in
    every release it names, as for a host whose release is not known."""
    fixes = det.get('eco_fix') if isinstance(det, dict) else None
    if not isinstance(fixes, dict):
        return False
    if release:
        verdict = _reached(fixes, package, reach, [release, cve_fixes.pro_name(release)])
        if verdict is not None:
            return verdict
    return _reached(fixes, package, reach, list(fixes)) is True


def _reached(fixes: dict, package: str, reach: dict, names) -> bool | None:
    """True when every fix `fixes` names for the package under `names` has a per-CVE fix at or past
    it, False when one has none, None when it names no fix there.

    A fix named under Ubuntu Pro is also reached by a standard update of the same release: a
    Livepatch notice (LSN) names the kernel that no longer needs the patch under the Pro name, and the
    records of its CVEs name the same kernel as a standard update. Never the other way round: a
    standard fix is not reached by one that needs Pro."""
    named = False
    for eco in names:
        packages = fixes.get(eco) if eco else None
        versions = packages.get(package) if isinstance(packages, dict) else None
        for version in versions if isinstance(versions, list) else []:
            if not isinstance(version, str) or not version:
                continue
            named = True
            carried = list(reach.get(eco, []))
            standard = cve_fixes.standard_name(eco)
            if standard:
                carried += reach.get(standard, [])
            if not any(_deb_reaches(c, version) for c in carried):
                return False
    return True if named else None


def _deb_reaches(carried: str, version: str) -> bool:
    try:
        return pkg_versions.deb_compare(carried, version) >= 0
    except ValueError:
        return False


# ── The record of one advisory, and when to read it again ────────────────────
#
# A query answer holds ids. Everything else (severity, fixed versions, the CVE names) is in the
# advisory's own record, one request each, kept in cve_details_cache.json.
#
# 8.0.1, measured on 2026-11-15: one request takes about 0.27 s, and a Debian or Ubuntu host asked
# by source package needs up to 3,000 on its first scan. One after the other that is 12 minutes
# inside one host's scan, past the five minutes after which the scan marker counts as dead and a
# second scan can be started beside the first. So the records are read several at once, the marker
# is refreshed from inside, the cache is written as the work goes (a runner that is killed keeps
# what it read), and a dead endpoint ends the reading after a few failures in a row.
DETAILS_FORMAT = 2            # an entry written under another number is read again
DETAIL_FETCHES_AT_ONCE = 8
DETAIL_FAILURES_IN_A_ROW = 20
DETAIL_SAVE_EVERY = 250
MAX_ALIASES = 40
SUMMARY_LEN = 240           # of a description, for a record that has no summary: a kernel record's runs to pages
_STAMP_RE = re.compile(r'^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?')
_PRO_VERSION = re.compile(r'[+~]esm\d')


def _instant(stamp) -> str:
    """An RFC 3339 stamp cut to the microsecond. A query answer writes six fraction digits and the
    record nine for the same instant, so the two differ as text."""
    match = _STAMP_RE.match(str(stamp or '').strip())
    if not match:
        return ''
    return match.group(1) + '.' + (match.group(2) or '')[:6].ljust(6, '0')


def _needs_fetch(cached, seen_modified, ttl: int, now: int) -> bool:
    """Read the record again? Yes when it is not held, when the entry was written by an older
    format (it lacks something the scan needs: v2.4.1 the severity source, v7.4.6 the fixes per
    release, 8.0.1 the CVE names), and when the record changed since. The query answer says when a
    record last changed, so an unchanged record is not read again however old the entry: with the
    age alone, every entry of a first scan ran out on the same day and was fetched again. The age
    decides only when one of the two stamps is missing."""
    if not isinstance(cached, dict):
        return True
    if cached.get('v') != DETAILS_FORMAT or 'severity_source' not in cached or 'eco_fix' not in cached:
        return True
    seen, held = _instant(seen_modified), _instant(cached.get('modified'))
    if seen and held:
        return seen != held
    try:
        age = now - int(cached.get('cached_at') or 0)
    except (TypeError, ValueError, OverflowError):
        return True
    return age > ttl


def _cve_names(vuln: dict) -> list:
    """The other names of an advisory: its aliases and the CVE ids it lists under `upstream`.

    A distribution's record (DEBIAN-CVE-, UBUNTU-CVE-, ALSA-, RLSA-) has no aliases; its CVE id is
    in `upstream`. Only `aliases` was kept, so the known-exploited list and the EPSS scores, which
    go by CVE id, matched nothing on any host of those distributions."""
    out = []
    for key in ('aliases', 'upstream'):
        names = vuln.get(key)
        for name in names if isinstance(names, list) else []:
            if not isinstance(name, str) or not name or len(name) > 64 or name in out:
                continue
            if key == 'upstream' and not name.upper().startswith('CVE-'):
                continue
            out.append(name)
    return out[:MAX_ALIASES]


def _detail_entry(vuln: dict, ecosystem: str) -> dict:
    """What the cache keeps of one record."""
    severity, severity_source = _severity_from_vuln(vuln, ecosystem)
    summary = str(vuln.get('summary') or '').strip()
    if not summary:
        # a DEBIAN-CVE or UBUNTU-CVE record has no summary, only the description
        summary = ' '.join(str(vuln.get('details') or '').split())
    entry = {
        'v': DETAILS_FORMAT,
        'summary': summary[:SUMMARY_LEN],
        'severity': severity,
        'severity_source': severity_source,   # v2.3.4: classification provenance
        'aliases': _cve_names(vuln),
        'published': vuln.get('published', ''),
        'modified': vuln.get('modified', ''),
        'refs': [r.get('url', '') for r in (vuln.get('references') or [])[:10] if isinstance(r, dict)],
        'cached_at': int(time.time()),
        'fixed_versions': _extract_fixed_versions(vuln),
        # v7.4.6 (#57): the fixes of every release the record names, apart
        # (_extract_fixed_versions folds them into one string per package).
        'eco_fix': cve_fixes.extract(vuln),
        # 8.0.1: the packages a distribution marks "unimportant", per release
        'minor': cve_fixes.minor(vuln),
    }
    if severity_source.startswith('cvss'):
        # 8.0.1: the score itself. An unchanged record is no longer read again, so a severity kept as
        # a word would stay what the bands of that day made it. See _severity_now.
        rated = _cvss_first(vuln)
        if rated is not None:
            entry['score'] = rated[0]
    return entry


def _severity_now(det: dict) -> tuple:
    """(severity, source) of a cached record. A severity that came from a CVSS score is banded by
    the bands in force now, so a change under Settings shows on the next scan."""
    severity, source = det.get('severity', 'unknown'), det.get('severity_source', 'unknown')
    score = det.get('score')
    if (isinstance(source, str) and source.startswith('cvss')
            and isinstance(score, (int, float)) and not isinstance(score, bool)):
        severity = _cvss_band(score)
    return severity, source


def _fetch_details(wanted, ecosystem: str, details_cache: dict, cache_path: Path, tick=None) -> int:
    """Read the records of `wanted` into `details_cache`, DETAIL_FETCHES_AT_ONCE at a time, and
    write the cache. Returns how many could not be read.

    `tick` is called between rounds; the scan worker uses it to keep its marker alive. After
    DETAIL_FAILURES_IN_A_ROW failures in a row the endpoint is taken to be down and the rest is
    not asked for: each request waits ten seconds, and 3,000 of those would be eight hours."""
    ids = sorted(str(v) for v in wanted)
    unread = streak = since_save = 0
    changed = False
    if ids:
        with ThreadPoolExecutor(max_workers=DETAIL_FETCHES_AT_ONCE) as pool:
            for start in range(0, len(ids), DETAIL_FETCHES_AT_ONCE):
                if streak >= DETAIL_FAILURES_IN_A_ROW:
                    unread += len(ids) - start
                    break
                chunk = ids[start:start + DETAIL_FETCHES_AT_ONCE]
                for vid, vuln in zip(chunk, pool.map(_osv_vuln_details, chunk)):
                    if not isinstance(vuln, dict) or not vuln:
                        unread += 1
                        streak += 1
                        continue
                    streak = 0
                    try:
                        details_cache[vid] = _detail_entry(vuln, ecosystem)
                    except Exception:
                        unread += 1       # a record of a shape this cannot read: one finding without
                        continue          # its details, not the end of the host's scan
                    changed = True
                    since_save += 1
                if since_save >= DETAIL_SAVE_EVERY:
                    _save_json(cache_path, details_cache)
                    since_save = 0
                if tick is not None:
                    try:
                        tick()
                    except Exception:
                        pass      # keeping the marker alive must not end the scan
    if changed:
        _save_json(cache_path, details_cache)
    return unread


# ── Main scan entrypoint ─────────────────────────────────────────────────────

def load_details(cache_dir: Path) -> dict:
    """The advisory records read so far, for a caller that scans many hosts and hands the same map to
    each scan (`details=`). A scan reads the file itself otherwise, once per host: with the records of
    one Debian 12 kernel in it (8,867 on 2026-11-16) that is 6.5 MB parsed for every host of a fleet scan."""
    return _load_json(Path(cache_dir) / 'cve_details_cache.json')


def scan_device(dev_id: str, packages: list, ecosystem: str, cache_dir: Path,
                cache_ttl: int = None, osv_prefetch: dict = None, has_meta: bool = False,
                tick=None, release: str = None, kev=None, details: dict = None) -> dict:
    """
    Scan one device's package list against OSV (if ecosystem supported).

    `has_meta` says the list came from an agent that reports the source package and the epoch of each
    package (8.0.1); see `plan` for what that changes. `tick` is called from time to time while the
    advisory records are read, so a caller can show that the scan is alive. `release` is the name the
    host's own release has in a record (`entry_release`); without it the ecosystem's own name is used.
    `kev` is the set of known-exploited CVE ids, for the rule of what is stored one by one.
    `details` is the map of `load_details`, shared by the scans of one run; it is added to in place.
    """
    if not packages or not ecosystem:
        return {
            'scanned_at': int(time.time()),
            'ecosystem': ecosystem or 'unsupported',
            'findings': [],
            'error': 'missing packages or unsupported ecosystem',
        }

    # Check if ecosystem is supported by OSV
    supported = False
    for prefix in OSV_SUPPORTED_ECOSYSTEMS:
        if ecosystem.startswith(prefix):
            supported = True
            break
    if not supported:
        return {
            'scanned_at': int(time.time()),
            'ecosystem': ecosystem,
            'findings': [],
            'error': f'Unsupported ecosystem for CVE scanning: {ecosystem}. OSV does not support this distribution.',
        }

    if len(packages) > MAX_PACKAGES:
        packages = packages[:MAX_PACKAGES]

    # v5.0.0 (#R5): if the OSV circuit breaker is open (OSV.dev down), skip the
    # scan entirely instead of hammering an unreachable service per device.
    if osv_breaker_open(cache_dir):
        return {
            'scanned_at': int(time.time()),
            'ecosystem': ecosystem,
            'findings': [],
            'error': 'OSV unavailable — circuit breaker open, scan skipped',
            'skipped': True,
            'partial': True,
        }

    details_cache = details if isinstance(details, dict) else _load_json(cache_dir / 'cve_details_cache.json')
    findings = []

    # 8.0.1: what to ask for is the plan, not the list (see `plan`)
    fam = family(ecosystem)
    fix_eco = release or ecosystem          # the name of the host's release inside a record
    release_known = cve_fixes.release_of(fix_eco) is not None
    units = plan(packages, ecosystem, has_meta, by_source(ecosystem, release))
    # A host with Ubuntu Pro has a package from it, and a Pro version ends in "+esm1" or "~esm1".
    pro_host = ecosystem == 'Ubuntu' and any(
        isinstance(p, dict) and _PRO_VERSION.search(str(p.get('version') or '')) for p in packages)
    queries = [{'package': {'name': u['name'], 'ecosystem': ecosystem}, 'version': u['version']}
               for u in units]

    # v5.0.0 (#S1): serve every package from the fleet-wide prefetch map (one OSV sweep already covered
    # the whole fleet), with no per-device OSV traffic.
    # 8.0.1: a question the map does not hold is asked now. It used to be read as "no advisories", so
    # anything that made the map and the scan disagree emptied the host's findings without a word.
    held = osv_prefetch if isinstance(osv_prefetch, dict) else {}
    all_results = [held.get((ecosystem, u['name'], u['version'])) for u in units]
    owed = [i for i, answer in enumerate(all_results) if not isinstance(answer, dict)]
    if owed:
        try:
            for i, answer in zip(owed, _osv_query_all([queries[i] for i in owed])):
                all_results[i] = answer
        except Exception as e:
            # v5.0.0 (#R5): record the failure — repeated ones trip the breaker
            # so the rest of the fleet scan stops hammering a dead OSV.
            osv_breaker_record(cache_dir, ok=False)
            return {
                'scanned_at': int(time.time()),
                'ecosystem': ecosystem,
                'findings': findings,
                'error': f'OSV query failed: {e}',
                'partial': True,
            }
        # All batches succeeded → the breaker resets (half-open probe recovered).
        osv_breaker_record(cache_dir, ok=True)

    # v1.8.4: cache TTL is configurable via the server's settings
    effective_ttl = cache_ttl if cache_ttl is not None else DETAILS_CACHE_TTL

    # Collect hits and the advisories whose record has to be read
    vuln_ids_to_fetch = set()
    hits = []
    cut = []      # 8.0.1: the names whose advisory list was longer than the pages that are read
    duplicates = 0
    now = int(time.time())
    for idx, result in enumerate(all_results):
        if idx >= len(units):
            break
        unit = units[idx]
        if not isinstance(result, dict):
            continue
        if result.get('truncated') and unit['package'] not in cut:
            cut.append(unit['package'])
        # an id is text: one of another kind (a list, a map) cannot be looked up and ended the scan
        answered = [v for v in (result.get('vulns') or [])
                    if isinstance(v, dict) and isinstance(v.get('id'), str) and v['id']]
        for v in answered:
            vid = v['id']
            hits.append((unit, vid))
            if _needs_fetch(details_cache.get(vid), v.get('modified'), effective_ttl, now):
                vuln_ids_to_fetch.add(vid)

    # Read them, several at once
    unread = _fetch_details(vuln_ids_to_fetch, ecosystem, details_cache,
                            cache_dir / 'cve_details_cache.json', tick)

    if fam == 'deb':
        hits, duplicates = _without_repeated_notices(hits, details_cache, fix_eco if release_known else '')

    # Build findings list
    # v2.2.6: gate each finding on a version comparison. OSV returns a
    # vuln whenever the package name matches an advisory's affected
    # range — but its range model doesn't always line up with how
    # Debian/Ubuntu revision the same package (e.g. an installed
    # `5.1.5-9build2` is NEWER than an ESM fix `5.1.5-8.1ubuntu0.22.04.1~esm1`
    # but OSV still flags it). Without this gate the scanner reports
    # already-patched packages as vulnerable — a false positive that
    # trains operators to ignore the CVE page entirely.
    #
    # For each finding: if we have a fixed version AND the installed
    # version is >= that fixed version, the package is already patched
    # — suppress the finding. If `fixed` is empty (OSV gave no fix), or
    # the comparison can't be made reliably, KEEP the finding (fail
    # safe — better a false positive than a missed CVE).
    #
    # v7.4.6 (#57): for a distribution whose OSV name carries the release
    # (Debian:12, Alpine:v3.19) the record keeps one fix per release, so the
    # finding says whether the fix reached THIS host's release and
    # `fixed_version` is that release's own. "Already patched" then looks at
    # the host's release and the newer ones, never an older one: a package of
    # a newer release is normally past an older release's fix without holding
    # the fix its own release lacks. Other distributions keep the folded
    # string and the old rule, with the status "unknown".
    # 8.0.1: a finding is one advisory against one package as the plan files it, so the packages built
    # from one source (Alpine, and RPM from an agent that reports the source) are one finding that names
    # them, and a package listed twice (two architectures) is no longer two findings.
    suppressed = 0
    filed = {}
    for unit, vid in hits:
        det = details_cache.get(vid, {})
        eco_fix = det.get('eco_fix')
        asked = unit['name']
        fix = cve_fixes.classify(eco_fix, fix_eco, asked, pro=pro_host)
        if fix['status'] == cve_fixes.UNKNOWN:
            fixed = det.get('fixed_versions', {}).get(asked) or ''
            patched_spec = fixed
        else:
            fixed = ', '.join(fix['fixed'])
            patched_spec = ', '.join(cve_fixes.patched_by(eco_fix, fix_eco, asked))
        if patched_spec and _already_patched(unit['version'], patched_spec, ecosystem,
                                             epoch_known=unit['epoch_known']):
            suppressed += 1
            continue
        key = (unit['package'], vid)
        finding = filed.get(key)
        if finding is not None:
            for name in unit['binaries']:
                if name not in finding['_binaries']:
                    finding['_binaries'].append(name)
            continue
        severity, severity_source = _severity_now(det)
        if cve_fixes.is_minor(det.get('minor'), fix_eco, asked):
            # the distribution's own rating wins over a score: Debian calls this package unaffected
            # in a way that matters, in the host's release
            severity, severity_source = 'low', 'debian_urgency'
        finding = {
            'package': unit['package'],
            'version': unit['shown'],
            'vuln_id': vid,
            'severity': severity,
            'severity_source': severity_source,
            'summary': det.get('summary', ''),
            'fixed_version': fixed,
            'fix_status': fix['status'],
            'aliases': det.get('aliases', []),
            'refs': det.get('refs', []),
            'published': det.get('published', ''),
            '_binaries': list(unit['binaries']),
        }
        if fix['elsewhere']:
            finding['fixed_elsewhere'] = {eco: ', '.join(vs) for eco, vs in fix['elsewhere'].items()}
        filed[key] = finding
        findings.append(finding)
    for finding in findings:
        names = sorted(finding.pop('_binaries'))
        # named only when it says more than the package name does
        if names and names != [finding['package']]:
            finding['binaries'] = names[:MAX_BINARIES_SHOWN]
            if len(names) > MAX_BINARIES_SHOWN:
                finding['binaries_more'] = len(names) - MAX_BINARIES_SHOWN

    # Sort: critical > high > medium > low > unknown
    findings.sort(key=lambda f: (
        SEVERITY_ORDER.index(f['severity']) if f['severity'] in SEVERITY_ORDER else 99,
        f['package'],
    ))

    # 8.0.1: what is stored one by one, and what is counted (cve_fixes.split). Only where the scan can
    # tell whether an update for the host's release clears a finding: Debian, and Ubuntu with a known
    # release. Those two list every known CVE of the release, fixed or not.
    ruled = fam == 'deb' and release_known
    counted, listed_to = {}, {}
    if ruled:
        findings, counted, listed_to = cve_fixes.select(findings, kev)

    result = {
        'scanned_at': int(time.time()),
        'ecosystem': ecosystem,
        'findings': findings,
        # v2.2.6: how many OSV hits were dropped as already-patched.
        # Surfaced for transparency — operators can see the scanner
        # is filtering, and a suspiciously high number is a hint the
        # comparator might be over-suppressing.
        'suppressed_patched': suppressed,
        # 8.0.1: the packages whose advisory list was cut (see OSV_MAX_PAGES); empty for a whole list
        'cut': cut[:20],
    }
    if ruled:
        result['ruled'] = True          # the alert path compares like with like (see cve_fixes.kept)
    if counted:
        result['rollup'] = counted
    if listed_to:
        # how far the ceilings reached, for the next scan's alert comparison (cve_fixes.beyond)
        result['listed_to'] = listed_to
    if duplicates:
        result['duplicates'] = duplicates
    if unread:
        # Their severity and fix are not known, so they sit in the count until they are read. With an
        # error and no finding at all the caller keeps the host's last result instead.
        result['partial'] = True
        result['unread'] = unread
        result['error'] = (f'{unread} of the advisory records could not be read from OSV. Their severity '
                           'and fix are unknown until the next scan.')
    return result


# ── v2.2.6: version comparison — suppress already-patched findings ───────────

def _already_patched(installed: str, fixed_spec: str, ecosystem: str, epoch_known: bool = True) -> bool:
    """Return True if `installed` is >= the fixed version, i.e. the
    package is already patched and the OSV hit is a false positive.

    `fixed_spec` may be a comma-joined list of fixed versions (see
    _extract_fixed_versions, which joins up to 3). The package counts
    as patched if the installed version is >= ANY one of them — a
    fix landing in any branch the host could be on means it's covered.

    Debian/Ubuntu use `dpkg --compare-versions`, the authoritative
    implementation of Debian version ordering (handles `~`, `+bN`,
    `ubuntuN`, `~esmN`, epoch, etc. — none of which a naive split
    gets right). 8.0.1: RPM and Alpine versions are compared in their own
    order (`pkg_versions`). The tuple comparison they used read the epoch of
    "1:3.0.7-28.el9_4" as the first number of the version, so an installed
    3.0.7-16.el9 counted as past every fix and a host that needed the update
    showed nothing; and it read "-r5" and the letter of "1.1.1w" as nothing.
    `epoch_known` is False for an RPM list collected without epochs: the
    installed version is then compared as if it had the fix's epoch. Anything
    else still falls through to the tuple comparison.

    Fail-safe: any uncertainty (no fixed version, comparison error,
    unparseable version) returns False so the finding is KEPT. A
    false positive is annoying; a suppressed real CVE is dangerous.
    """
    if not installed or not fixed_spec:
        return False
    candidates = [v.strip() for v in fixed_spec.split(',') if v.strip()]
    if not candidates:
        return False

    fam = family(ecosystem)
    for fixed in candidates:
        try:
            if fam == 'deb':
                patched = _dpkg_ge(installed, fixed)
            elif fam == 'rpm':
                patched = pkg_versions.rpm_ge(installed, fixed, assume_same_epoch=not epoch_known)
            elif fam == 'apk':
                patched = pkg_versions.apk_ge(installed, fixed)
            else:
                patched = _tuple_ge(installed, fixed)
            if patched:
                return True
        except Exception:
            # Comparison failed — don't suppress on this candidate
            continue
    return False


def _dpkg_ge(installed: str, fixed: str) -> bool:
    """installed >= fixed in Debian's version order.

    8.0.1: computed here (pkg_versions.deb_ge). It used to run `dpkg --compare-versions`: one
    process per comparison (1,375 for one host of 2,500 advisories, on every scan), and on a
    server without dpkg it raised, so no Debian or Ubuntu finding was ever left out as already
    patched there. A version that cannot be read raises ValueError and the caller keeps the
    finding."""
    return pkg_versions.deb_ge(installed, fixed)


def _tuple_ge(installed: str, fixed: str) -> bool:
    """Conservative installed >= fixed for non-Debian ecosystems.

    Splits on dots and non-digit boundaries, compares numeric
    components. Simple — for PyPI / npm / etc. a more
    correct comparator (PEP 440, semver) would be ideal, but this is
    only a fallback and erring toward 'not patched' (keep the finding)
    is the safe failure mode.
    """
    def parts(v):
        out = []
        for chunk in re.split(r'[.\-+~]', v):
            m = re.match(r'(\d+)', chunk)
            out.append(int(m.group(1)) if m else 0)
        return out
    a, b = parts(installed), parts(fixed)
    # Pad to equal length
    n = max(len(a), len(b))
    a += [0] * (n - len(a))
    b += [0] * (n - len(b))
    if a != b:
        return a > b
    # Equal numeric tuples: a prerelease (installed carries a -alpha/-beta/-rc
    # suffix that the fixed version doesn't) sorts BELOW the release, so it is
    # NOT patched — keep the finding (the documented "err toward keeping" intent;
    # the old `>=` wrongly suppressed e.g. installed=1.2.0-beta vs fixed=1.2.0).
    inst_pre = re.search(r'[-~][A-Za-z]', installed) is not None
    fix_pre  = re.search(r'[-~][A-Za-z]', fixed) is not None
    if inst_pre and not fix_pre:
        return False
    return True


# ── Helper functions for fixed versions, JSON storage, etc. ──────────────────

def _extract_fixed_versions(vuln: dict) -> dict:
    out = {}
    for aff in vuln.get('affected') or []:
        pkg = aff.get('package') or {}
        name = pkg.get('name')
        if not name:
            continue
        fixed_list = []
        for r in aff.get('ranges') or []:
            for e in r.get('events') or []:
                if 'fixed' in e:
                    fixed_list.append(e['fixed'])
        if fixed_list:
            out[name] = ', '.join(fixed_list[:3])
    return out


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def _save_json(path: Path, data: dict) -> None:
    # 8.0.1: a temporary name of this process. With one fixed name, two scanners writing at once
    # replaced each other's file mid-write and one of them raised FileNotFoundError.
    tmp = path.with_suffix(path.suffix + f'.{os.getpid()}.tmp')
    tmp.write_text(json.dumps(data, separators=(',', ':')))
    tmp.replace(path)
    _sweep_stale_tmp(path)


STALE_TMP_SECONDS = 900


def _sweep_stale_tmp(path: Path) -> None:
    """Remove the temporary files that scanners left beside `path` when they were killed while
    writing (a restart, the OOM killer). Each is a whole copy of the cache, the next scanner has
    another process id, and nothing else would ever take them away. One that was written to in the
    last quarter of an hour may belong to a scanner that is still writing, and is left."""
    try:
        now = time.time()
        for leftover in path.parent.glob(path.name + '.*.tmp'):
            try:
                if now - leftover.stat().st_mtime > STALE_TMP_SECONDS:
                    leftover.unlink()
            except OSError:
                continue
    except OSError:
        pass


def packages_hash(packages: list) -> str:
    """The fingerprint of a package list; the agent computes the same one to decide whether to send.

    8.0.1: a package that names its source package or its epoch is hashed with them, so a list from an
    agent that reports them differs from the same packages reported without, and is sent once. A list
    that names neither (pacman, or an older agent) hashes as it always did."""
    rows = []
    for p in packages:
        row = (p.get('name', ''), p.get('version', ''))
        more = (p.get('source', ''), p.get('source_version', ''), p.get('epoch', ''))
        rows.append(row + more if any(more) else row)
    normalized = sorted(rows)
    return hashlib.sha256(
        json.dumps(normalized, separators=(',', ':')).encode()
    ).hexdigest()[:16]


def summarize_findings(findings: list, ignore_ids: set) -> dict:
    out = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'unknown': 0, 'ignored': 0}
    for f in findings:
        if not isinstance(f, dict):      # v7.4.6: a hand-edited store; one bad row must not fail the report
            continue
        vid = f.get('vuln_id')
        if isinstance(vid, str) and vid in ignore_ids:
            out['ignored'] += 1
            continue
        sev = f.get('severity', 'unknown')
        if not isinstance(sev, str):     # 8.0.1: a list or a map is no key, and ended the report
            sev = 'unknown'
        out[sev] = out.get(sev, 0) + 1
    return out


def apply_ignore_list(findings: list, ignore_data: dict, dev_id: str,
                      dev_tenant: str = None) -> list:
    """v7.0.3: `dev_tenant` lets a tenant-owned accepted-risk record apply only
    to that tenant's hosts. Callers that do not pass it keep the pre-tenancy
    behaviour for records with no tenant, which is every record written before
    this release."""
    out = []
    for f in findings:
        if not isinstance(f, dict):      # v7.4.6: a hand-edited store; the row is not a finding
            continue
        # .get() — a malformed finding without a vuln_id simply can't
        # be on the ignore list (the list is keyed by vuln_id), and
        # must not raise.
        ig = ignore_data.get(f.get('vuln_id'))
        # Copy in BOTH branches: never mutate the caller's input list (the
        # findings often come straight from a cached load() and are reused by
        # other callers — e.g. the timeline merge).
        f = dict(f)
        if checks.cve_ignore_applies(ig, dev_id, dev_tenant):
            f['ignored'] = True
            f['ignore_reason'] = ig.get('reason', '')
        else:
            f['ignored'] = False
        out.append(f)
    return out

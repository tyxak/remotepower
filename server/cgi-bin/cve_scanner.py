#!/usr/bin/env python3
"""
RemotePower CVE Scanner — v1.7.0
(Full version with Ubuntu priority, Debian fallback, Arch unsupported)
"""
import json
import time
import hashlib
import re
import shutil
import urllib.request

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


def coverage(ecosystem, has_meta: bool = False) -> str:
    """What a scan of this host leaves out, as a word the page turns into a sentence.

    'own_name'     Debian and Ubuntu: a package is asked for under its own name, and the advisories are
                   filed under the source package, so a package named otherwise is not checked
    'needs_agent'  Alpine and Rocky with a list from an agent that does not report source packages
    ''             nothing known to be left out"""
    fam = family(ecosystem)
    if fam == 'deb':
        return 'own_name'
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
# filed under, and the installed packages it speaks for. Alpine is asked by origin, Rocky by both names,
# and the findings of one source package are one finding however many packages were built from it. That
# needs what an 8.0.1 agent reports (the source package and the epoch); a list without them is asked for
# name by name, as before. Debian and Ubuntu are still asked for by the installed name: docs/cve.md says
# what that leaves out and why it is not switched on here.

MAX_BINARIES_SHOWN = 30


def _text(value) -> str:
    return str(value or '').strip()


def plan(packages, ecosystem, has_meta: bool = False) -> list:
    """The units to ask the advisory database for, for one host's package list.

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

    grouped = bool(has_meta) and fam in ('apk', 'rpm')
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
        for unit in plan(entry.get("packages") or [], eco, entry.get("sources") is True):
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
    for sev in vuln.get('severity', []):
        if sev.get('type') == 'Ubuntu':
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
    for sev in vuln.get('severity', []):
        vec = sev.get('score', '')
        score = _cvss_base_score(vec)
        if score is not None:
            vtype = str(sev.get('type') or '').upper()
            # v6.4.2: name the v4 source honestly. The score is the v3.1 formula
            # applied to v4's base metrics, not an official v4 base score, and a
            # consumer that reads the source deserves to know which it got.
            if vtype.startswith('CVSS_V2'):
                src = 'cvss_v2'
            elif vtype.startswith('CVSS_V4') or vec.upper().startswith('CVSS:4'):
                src = 'cvss_v4_approx'
            else:
                src = 'cvss_v3'
            if score >= _CVSS_BAND_CRITICAL:   return 'critical', src
            if score >= _CVSS_BAND_HIGH:       return 'high', src
            if score >= _CVSS_BAND_MEDIUM:     return 'medium', src
            if score > 0:      return 'low', src
            return 'low', src

    # 4. Debian Security Tracker fallback (Debian ecosystems only).
    if ecosystem and ecosystem.startswith('Debian:'):
        vuln_id = vuln.get('id', '')
        if vuln_id:
            deb_sev = _debian_severity_fallback(vuln_id)
            if deb_sev:
                return deb_sev, 'debian_urgency'

    return 'unknown', 'unknown'


# ── Main scan entrypoint ─────────────────────────────────────────────────────

def scan_device(dev_id: str, packages: list, ecosystem: str, cache_dir: Path,
                cache_ttl: int = None, osv_prefetch: dict = None, has_meta: bool = False) -> dict:
    """
    Scan one device's package list against OSV (if ecosystem supported).

    `has_meta` says the list came from an agent that reports the source package and the epoch of each
    package (8.0.1); see `plan` for what that changes.
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

    details_cache = _load_json(cache_dir / 'cve_details_cache.json')
    findings = []

    # 8.0.1: what to ask for is the plan, not the list (see `plan`)
    units = plan(packages, ecosystem, has_meta)
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

    # Collect hits and uncached vuln IDs
    vuln_ids_to_fetch = set()
    hits = []
    cut = []      # 8.0.1: the names whose advisory list was longer than the pages that are read
    for idx, result in enumerate(all_results):
        if idx >= len(units):
            break
        unit = units[idx]
        if not isinstance(result, dict):
            continue
        if result.get('truncated') and unit['package'] not in cut:
            cut.append(unit['package'])
        for v in result.get('vulns') or []:
            vid = v.get('id') if isinstance(v, dict) else None
            if vid:
                hits.append((unit, vid))
                cached = details_cache.get(vid)
                # Re-fetch (and so re-classify) a vuln when:
                #   - it isn't cached at all, OR
                #   - its cache entry has aged past the TTL, OR
                #   - v2.4.1: the entry was written by a pre-2.3.4
                #     RemotePower. Such entries carry a `severity`
                #     computed by the OLD, BUGGY classifier (the
                #     AC:H-as-C:H substring bug; un-capped Debian
                #     urgency) and have NO `severity_source` field.
                #     A TTL refresh alone never reaches them — the
                #     entry looks "fresh" — so a stale severity gets
                #     re-served on every scan. Keying on the absence
                #     of `severity_source` forces a one-time re-fetch
                #     and re-classification with the current code.
                #     Self-healing: no manual cache wipe needed.
                #   - v7.4.6 (#57): the entry predates the per-release fixes
                #     (`eco_fix`), so a host cannot be told whether the fix
                #     reached its own release. Same self-healing refetch.
                stale_version = cached is not None and (
                    'severity_source' not in cached or 'eco_fix' not in cached)
                if cached is None \
                   or stale_version \
                   or (int(time.time()) - cached.get('cached_at', 0)) > effective_ttl:
                    vuln_ids_to_fetch.add(vid)

    # Fetch missing details
    for vid in vuln_ids_to_fetch:
        vuln = _osv_vuln_details(vid)
        if not vuln:
            continue
        severity, severity_source = _severity_from_vuln(vuln, ecosystem)
        details_cache[vid] = {
            'summary': str(vuln.get('summary') or '')[:500],
            'details': str(vuln.get('details') or '')[:2000],
            'severity': severity,
            'severity_source': severity_source,   # v2.3.4: classification provenance
            'aliases': (vuln.get('aliases') or [])[:10],
            'published': vuln.get('published', ''),
            'modified': vuln.get('modified', ''),
            'refs': [r.get('url', '') for r in (vuln.get('references') or [])[:10]],
            'cached_at': int(time.time()),
            'fixed_versions': _extract_fixed_versions(vuln),
            # v7.4.6 (#57): the fixes of every release the record names, apart
            # (_extract_fixed_versions folds them into one string per package).
            'eco_fix': cve_fixes.extract(vuln),
        }

    _save_json(cache_dir / 'cve_details_cache.json', details_cache)

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
        fix = cve_fixes.classify(eco_fix, ecosystem, asked)
        if fix['status'] == cve_fixes.UNKNOWN:
            fixed = det.get('fixed_versions', {}).get(asked) or ''
            patched_spec = fixed
        else:
            fixed = ', '.join(fix['fixed'])
            patched_spec = ', '.join(cve_fixes.patched_by(eco_fix, ecosystem, asked))
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
        finding = {
            'package': unit['package'],
            'version': unit['shown'],
            'vuln_id': vid,
            'severity': det.get('severity', 'unknown'),
            'severity_source': det.get('severity_source', 'unknown'),
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

    return {
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
    """installed >= fixed using `dpkg --compare-versions`.

    dpkg is the canonical Debian version comparator. If the binary
    isn't present (scanner running on a non-Debian host), raise so
    the caller's except-branch keeps the finding rather than guessing.
    """
    import subprocess
    exe = shutil.which('dpkg')
    if not exe:
        # No dpkg on this box — signal "can't tell" to the caller
        raise RuntimeError('dpkg not available for version comparison')
    # `dpkg --compare-versions A ge B` exits 0 if A >= B, 1 otherwise.
    # v5.8.0: `--` terminates option parsing so a version string beginning with
    # '-' can't be mistaken for a dpkg flag and skew the comparison (integrity).
    rc = subprocess.run(
        [exe, '--compare-versions', '--', installed, 'ge', fixed],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=5,
    ).returncode
    return rc == 0


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
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(data, indent=2))
    tmp.replace(path)


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
        if f.get('vuln_id') in ignore_ids:
            out['ignored'] += 1
            continue
        sev = f.get('severity', 'unknown')
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

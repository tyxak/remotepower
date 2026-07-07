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
_OPENER = urllib.request.build_opener(_NoRedirect)

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

def detect_ecosystem(os_release: dict, pkg_manager: str) -> str | None:
    """Map /etc/os-release + pkg_manager to OSV ecosystem string."""
    if not os_release:
        return None
    os_id     = (os_release.get('ID') or '').lower().strip()
    id_like   = (os_release.get('ID_LIKE') or '').lower().strip()
    ver_id    = (os_release.get('VERSION_ID') or '').strip()
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
        if os_id == 'rocky':
            return 'Rocky Linux'
        if os_id == 'almalinux':
            return 'AlmaLinux'
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
def prefetch_osv(store: dict, cache_dir: Path) -> dict:
    """Build the shared OSV result map for a whole fleet. Returns {} if the
    breaker is open or nothing is scannable (scan_device then falls back / skips).
    Records breaker outcomes like a normal scan."""
    if osv_breaker_open(cache_dir):
        return {}
    by_eco = {}   # ecosystem -> ordered unique [(name, version)]
    seen = set()
    for entry in (store or {}).values():
        if not isinstance(entry, dict):
            continue
        eco = entry.get("ecosystem")
        if not _ecosystem_supported(eco):
            continue
        for p in (entry.get("packages") or [])[:MAX_PACKAGES]:
            name = (p.get("name") or "").strip()
            version = (p.get("version") or "").strip()
            if not name or not version:
                continue
            key = (eco, name, version)
            if key in seen:
                continue
            seen.add(key)
            by_eco.setdefault(eco, []).append((name, version))
    result_map = {}
    any_ok = False
    for eco, pkgs in by_eco.items():
        queries = [{"package": {"name": n, "ecosystem": eco}, "version": v}
                   for (n, v) in pkgs]
        for i in range(0, len(queries), OSV_BATCH_SIZE):
            chunk = queries[i:i + OSV_BATCH_SIZE]
            try:
                res = _osv_querybatch(chunk)
            except Exception:
                osv_breaker_record(cache_dir, ok=False)
                return result_map   # partial; callers handle the gaps
            for j, r in enumerate(res):
                n, v = pkgs[i + j]
                result_map[(eco, n, v)] = r or {}
            any_ok = True
    if any_ok:
        osv_breaker_record(cache_dir, ok=True)
    return result_map


# ── CVSS vector parser ───────────────────────────────────────────────────────
#
# v2.3.4: the previous implementation did naive substring matching on the
# vector string — e.g. `'c:h' in vector` — which matched `AC:H` (Attack
# Complexity: High) as if it were `C:H` (Confidentiality: High). The result:
# ANY CVSS v3 vuln with high attack complexity scored 7.5 / HIGH regardless
# of its real impact. A genuinely LOW CVE (CVSS 2.9) with AC:H was reported
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
    score and no distro severity rating — is deliberately CAPPED at
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
        urgency = data.get('urgency', '').lower().rstrip('*').strip()
        # high / medium urgency → capped at 'medium' (see docstring)
        if urgency in ('high', 'medium'):
            return 'medium'
        if urgency in ('low', 'unimportant', 'negligible'):
            return 'low'
    except Exception:
        pass
    return None


# ── Severity extraction (prioritizes Ubuntu priority) ────────────────────────

def _severity_from_vuln(vuln: dict, ecosystem: str = None) -> tuple:
    """Extract (severity, source) for a vuln.

    `source` records WHERE the severity came from — per the v2.3.4
    spec requirement to log the classification source. One of:
    'database_specific', 'ubuntu_priority', 'cvss_v3', 'cvss_v2',
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
        raw = (db_spec.get(field) or '').lower()
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
            ubuntu_score = sev.get('score', '').lower()
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
            vtype = (sev.get('type') or '').upper()
            src = 'cvss_v2' if vtype.startswith('CVSS_V2') else 'cvss_v3'
            if score >= 9.0:   return 'critical', src
            if score >= 7.0:   return 'high', src
            if score >= 4.0:   return 'medium', src
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
                cache_ttl: int = None, osv_prefetch: dict = None) -> dict:
    """
    Scan one device's package list against OSV (if ecosystem supported).
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
    pkg_by_index = []

    # Build queries
    queries = []
    for p in packages:
        name = (p.get('name') or '').strip()
        version = (p.get('version') or '').strip()
        if not name or not version:
            continue
        queries.append({
            'package': {'name': name, 'ecosystem': ecosystem},
            'version': version,
        })
        pkg_by_index.append((name, version))

    all_results = []
    if osv_prefetch is not None:
        # v5.0.0 (#S1): serve every package from the fleet-wide prefetch map (one
        # OSV sweep already covered the whole fleet) — no per-device OSV traffic.
        # A package the prefetch missed → empty result (treated as no vulns).
        all_results = [osv_prefetch.get((ecosystem, n, v), {}) for (n, v) in pkg_by_index]
    else:
        # Submit batches
        for i in range(0, len(queries), OSV_BATCH_SIZE):
            batch = queries[i:i+OSV_BATCH_SIZE]
            try:
                batch_results = _osv_querybatch(batch)
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
            all_results.extend(batch_results)
        # All batches succeeded → the breaker resets (half-open probe recovered).
        osv_breaker_record(cache_dir, ok=True)

    # v1.8.4: cache TTL is configurable via the server's settings
    effective_ttl = cache_ttl if cache_ttl is not None else DETAILS_CACHE_TTL

    # Collect hits and uncached vuln IDs
    vuln_ids_to_fetch = set()
    hits = []
    for idx, result in enumerate(all_results):
        if idx >= len(pkg_by_index):
            break
        pkg_name, pkg_version = pkg_by_index[idx]
        for v in result.get('vulns') or []:
            vid = v.get('id')
            if vid:
                hits.append((pkg_name, pkg_version, vid))
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
                stale_version = cached is not None and \
                    'severity_source' not in cached
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
            'summary': (vuln.get('summary') or '')[:500],
            'details': (vuln.get('details') or '')[:2000],
            'severity': severity,
            'severity_source': severity_source,   # v2.3.4: classification provenance
            'aliases': (vuln.get('aliases') or [])[:10],
            'published': vuln.get('published', ''),
            'modified': vuln.get('modified', ''),
            'refs': [r.get('url', '') for r in (vuln.get('references') or [])[:10]],
            'cached_at': int(time.time()),
            'fixed_versions': _extract_fixed_versions(vuln),
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
    suppressed = 0
    for pkg_name, pkg_version, vid in hits:
        det = details_cache.get(vid, {})
        fixed = det.get('fixed_versions', {}).get(pkg_name) or ''
        if fixed and _already_patched(pkg_version, fixed, ecosystem):
            suppressed += 1
            continue
        findings.append({
            'package': pkg_name,
            'version': pkg_version,
            'vuln_id': vid,
            'severity': det.get('severity', 'unknown'),
            'severity_source': det.get('severity_source', 'unknown'),
            'summary': det.get('summary', ''),
            'fixed_version': fixed,
            'aliases': det.get('aliases', []),
            'refs': det.get('refs', []),
            'published': det.get('published', ''),
        })

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
    }


# ── v2.2.6: version comparison — suppress already-patched findings ───────────

def _already_patched(installed: str, fixed_spec: str, ecosystem: str) -> bool:
    """Return True if `installed` is >= the fixed version, i.e. the
    package is already patched and the OSV hit is a false positive.

    `fixed_spec` may be a comma-joined list of fixed versions (see
    _extract_fixed_versions, which joins up to 3). The package counts
    as patched if the installed version is >= ANY one of them — a
    fix landing in any branch the host could be on means it's covered.

    Debian/Ubuntu use `dpkg --compare-versions`, the authoritative
    implementation of Debian version ordering (handles `~`, `+bN`,
    `ubuntuN`, `~esmN`, epoch, etc. — none of which a naive split
    gets right). Other ecosystems fall through to a conservative
    tuple comparison.

    Fail-safe: any uncertainty (no fixed version, comparison error,
    unparseable version) returns False so the finding is KEPT. A
    false positive is annoying; a suppressed real CVE is dangerous.
    """
    if not installed or not fixed_spec:
        return False
    candidates = [v.strip() for v in fixed_spec.split(',') if v.strip()]
    if not candidates:
        return False

    is_deb = ecosystem == 'Ubuntu' or (ecosystem or '').startswith('Debian')
    for fixed in candidates:
        try:
            if is_deb:
                if _dpkg_ge(installed, fixed):
                    return True
            else:
                if _tuple_ge(installed, fixed):
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
    components. Deliberately simple — for PyPI / npm / etc. a more
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
    normalized = sorted((p.get('name', ''), p.get('version', '')) for p in packages)
    return hashlib.sha256(
        json.dumps(normalized, separators=(',', ':')).encode()
    ).hexdigest()[:16]


def summarize_findings(findings: list, ignore_ids: set) -> dict:
    out = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'unknown': 0, 'ignored': 0}
    for f in findings:
        if f.get('vuln_id') in ignore_ids:
            out['ignored'] += 1
            continue
        sev = f.get('severity', 'unknown')
        out[sev] = out.get(sev, 0) + 1
    return out


def apply_ignore_list(findings: list, ignore_data: dict, dev_id: str) -> list:
    out = []
    for f in findings:
        # .get() — a malformed finding without a vuln_id simply can't
        # be on the ignore list (the list is keyed by vuln_id), and
        # must not raise.
        ig = ignore_data.get(f.get('vuln_id'))
        # Copy in BOTH branches: never mutate the caller's input list (the
        # findings often come straight from a cached load() and are reused by
        # other callers — e.g. the timeline merge).
        f = dict(f)
        if ig and (ig.get('scope') == 'global' or ig.get('scope') == dev_id):
            f['ignored'] = True
            f['ignore_reason'] = ig.get('reason', '')
        else:
            f['ignored'] = False
        out.append(f)
    return out

#!/usr/bin/env python3
"""
RemotePower CVE Scanner — v1.7.0
(Full version with Ubuntu priority, Debian fallback, Arch unsupported)
"""
import json
import time
import hashlib
import urllib.request
import urllib.error
from pathlib import Path

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL       = "https://api.osv.dev/v1/vulns/"

OSV_BATCH_SIZE     = 500
OSV_TIMEOUT        = 30
OSV_DETAIL_TIMEOUT = 10

DETAILS_CACHE_TTL  = 7 * 86400
MAX_PACKAGES       = 10000

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
            return f'Alpine:v{ver_id}'
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
    with urllib.request.urlopen(req, timeout=OSV_TIMEOUT) as resp:
        return json.loads(resp.read().decode('utf-8')).get('results', [])


def _osv_vuln_details(vuln_id: str) -> dict | None:
    try:
        req = urllib.request.Request(
            OSV_VULN_URL + vuln_id,
            headers={'Accept': 'application/json'},
        )
        with urllib.request.urlopen(req, timeout=OSV_DETAIL_TIMEOUT) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except Exception:
        return None


# ── CVSS vector parser ───────────────────────────────────────────────────────

def _cvss_base_score(vector: str) -> float | None:
    """Extract base score from a CVSS vector string."""
    if not vector:
        return None
    # Some OSV entries have score as "<number>/CVSS:..."
    if '/' in vector and vector[0].isdigit():
        try:
            return float(vector.split('/')[0])
        except ValueError:
            pass
    # Fallback coarse mapping
    vector_lower = vector.lower()
    if 'cvss:3' in vector_lower:
        if 'c:h' in vector_lower:
            if 's:c' in vector_lower:
                return 9.0
            return 7.5
        if 'c:l' in vector_lower or 'i:l' in vector_lower:
            return 4.5
        return 5.0
    if 'cvss:2' in vector_lower:
        if 'c:c' in vector_lower:
            return 10.0
        if 'c:p' in vector_lower:
            return 7.5
        return 5.0
    if 'high' in vector_lower:
        return 7.5
    if 'medium' in vector_lower:
        return 5.0
    if 'low' in vector_lower:
        return 2.0
    return None


# ── Debian Security Tracker fallback ─────────────────────────────────────────

def _debian_severity_fallback(cve_id: str) -> str | None:
    """Query Debian Security Tracker for urgency (low/medium/high)."""
    if cve_id.startswith('DEBIAN-'):
        cve_id = cve_id[7:]
    try:
        url = f"https://security-tracker.debian.org/api/json/cve/{cve_id}"
        req = urllib.request.Request(url, headers={'User-Agent': 'RemotePower'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode('utf-8'))
        urgency = data.get('urgency', '').lower()
        if urgency in ('critical', 'high', 'medium', 'low'):
            return urgency
        if urgency == 'unimportant':
            return 'low'
    except Exception:
        pass
    return None


# ── Severity extraction (prioritizes Ubuntu priority) ────────────────────────

def _severity_from_vuln(vuln: dict, ecosystem: str = None) -> str:
    """
    Extract severity, giving highest priority to Ubuntu's official 'priority'
    (type 'Ubuntu'), then database_specific fields, then CVSS.
    """
    # 1. database_specific fields (Debian, Arch, etc.)
    db_spec = vuln.get('database_specific') or {}
    for field in ('severity', 'priority'):
        raw = (db_spec.get(field) or '').lower()
        if raw in SEVERITY_ORDER:
            return raw
        if raw in ('important',):
            return 'high'
        if raw in ('moderate',):
            return 'medium'
        if raw in ('negligible', 'unimportant'):
            return 'low'

    # 2. Look specifically for Ubuntu priority (type 'Ubuntu') – this must come before CVSS
    for sev in vuln.get('severity', []):
        if sev.get('type') == 'Ubuntu':
            ubuntu_score = sev.get('score', '').lower()
            if ubuntu_score in SEVERITY_ORDER:
                return ubuntu_score
            if ubuntu_score in ('important',):
                return 'high'
            if ubuntu_score in ('moderate',):
                return 'medium'
            if ubuntu_score in ('negligible', 'unimportant'):
                return 'low'

    # 3. Fall back to CVSS base score (only if no Ubuntu priority was found)
    for sev in vuln.get('severity', []):
        vec = sev.get('score', '')
        score = _cvss_base_score(vec)
        if score is not None:
            if score >= 9.0:   return 'critical'
            if score >= 7.0:   return 'high'
            if score >= 4.0:   return 'medium'
            if score > 0:      return 'low'

    # 4. Debian-specific fallback (only if ecosystem is Debian)
    if ecosystem and ecosystem.startswith('Debian:'):
        vuln_id = vuln.get('id', '')
        if vuln_id:
            deb_sev = _debian_severity_fallback(vuln_id)
            if deb_sev:
                return deb_sev

    return 'unknown'


# ── Main scan entrypoint ─────────────────────────────────────────────────────

def scan_device(dev_id: str, packages: list, ecosystem: str, cache_dir: Path,
                cache_ttl: int = None) -> dict:
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

    # Submit batches
    all_results = []
    for i in range(0, len(queries), OSV_BATCH_SIZE):
        batch = queries[i:i+OSV_BATCH_SIZE]
        try:
            batch_results = _osv_querybatch(batch)
        except Exception as e:
            return {
                'scanned_at': int(time.time()),
                'ecosystem': ecosystem,
                'findings': findings,
                'error': f'OSV query failed: {e}',
                'partial': True,
            }
        all_results.extend(batch_results)

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
                if vid not in details_cache or \
                   (int(time.time()) - details_cache[vid].get('cached_at', 0)) > effective_ttl:
                    vuln_ids_to_fetch.add(vid)

    # Fetch missing details
    for vid in vuln_ids_to_fetch:
        vuln = _osv_vuln_details(vid)
        if not vuln:
            continue
        severity = _severity_from_vuln(vuln, ecosystem)
        details_cache[vid] = {
            'summary': (vuln.get('summary') or '')[:500],
            'details': (vuln.get('details') or '')[:2000],
            'severity': severity,
            'aliases': (vuln.get('aliases') or [])[:10],
            'published': vuln.get('published', ''),
            'modified': vuln.get('modified', ''),
            'refs': [r.get('url', '') for r in (vuln.get('references') or [])[:10]],
            'cached_at': int(time.time()),
            'fixed_versions': _extract_fixed_versions(vuln),
        }

    _save_json(cache_dir / 'cve_details_cache.json', details_cache)

    # Build findings list
    for pkg_name, pkg_version, vid in hits:
        det = details_cache.get(vid, {})
        fixed = det.get('fixed_versions', {}).get(pkg_name) or ''
        findings.append({
            'package': pkg_name,
            'version': pkg_version,
            'vuln_id': vid,
            'severity': det.get('severity', 'unknown'),
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
    }


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
        if f['vuln_id'] in ignore_ids:
            out['ignored'] += 1
            continue
        sev = f.get('severity', 'unknown')
        out[sev] = out.get(sev, 0) + 1
    return out


def apply_ignore_list(findings: list, ignore_data: dict, dev_id: str) -> list:
    out = []
    for f in findings:
        ig = ignore_data.get(f['vuln_id'])
        if ig and (ig.get('scope') == 'global' or ig.get('scope') == dev_id):
            f = dict(f)
            f['ignored'] = True
            f['ignore_reason'] = ig.get('reason', '')
        else:
            f['ignored'] = False
        out.append(f)
    return out

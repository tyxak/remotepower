#!/usr/bin/env python3
"""
RemotePower CVE Scanner — v1.7.0
(Only queries OSV for supported ecosystems)
"""
import json
import re
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

# List of ecosystems that OSV actually supports (case-sensitive as used by OSV)
OSV_SUPPORTED_ECOSYSTEMS = (
    'Ubuntu',
    'Debian:',      # e.g., Debian:11, Debian:12
    'Rocky Linux',
    'AlmaLinux',
    'Red Hat',
    'Alpine:',      # e.g., Alpine:v3.18
)


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
        # OSV does NOT support Arch Linux; return None to mark unsupported
        return None

    if pkg_manager == 'apk':
        if ver_id:
            return f'Alpine:v{ver_id}'
        return None
    return None


def _osv_querybatch(queries: list) -> list:
    body = json.dumps({'queries': queries}).encode('utf-8')
    req = urllib.request.Request(OSV_QUERYBATCH_URL, data=body, headers={'Content-Type': 'application/json'}, method='POST')
    with urllib.request.urlopen(req, timeout=OSV_TIMEOUT) as resp:
        return json.loads(resp.read().decode('utf-8')).get('results', [])


def _osv_vuln_details(vuln_id: str) -> dict | None:
    try:
        req = urllib.request.Request(OSV_VULN_URL + vuln_id, headers={'Accept': 'application/json'})
        with urllib.request.urlopen(req, timeout=OSV_DETAIL_TIMEOUT) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except Exception:
        return None


def _parse_cvss_score(vector: str) -> float | None:
    """Extract CVSS base score from a vector string (simplified)."""
    if not vector:
        return None
    if '/' in vector and vector[0].isdigit():
        try:
            return float(vector.split('/')[0])
        except ValueError:
            pass
    # Fallback to rough mapping
    vector_lower = vector.lower()
    if 'cvss:3' in vector_lower:
        if 'critical' in vector or 'c:h' in vector_lower:
            return 9.0
        if 'c:h' in vector_lower:
            if 's:c' in vector_lower:
                return 9.0
            return 7.5
        if 'c:l' in vector_lower or 'i:l' in vector_lower or 'a:l' in vector_lower:
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


def _debian_severity_fallback(cve_id: str) -> str | None:
    """Query Debian Security Tracker for urgency."""
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


def _severity_from_vuln(vuln: dict, ecosystem: str = None) -> str:
    """Extract severity from OSV data, with Debian fallback."""
    # database_specific fields
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

    # severity array entries
    for sev in vuln.get('severity', []) or []:
        score = sev.get('score', '')
        if not score:
            continue
        score_lower = score.lower().strip()
        if score_lower in SEVERITY_ORDER:
            return score_lower
        if score_lower in ('important',):
            return 'high'
        if score_lower in ('moderate',):
            return 'medium'
        if score_lower in ('negligible', 'unimportant'):
            return 'low'
        cvss_score = _parse_cvss_score(score)
        if cvss_score is not None:
            if cvss_score >= 9.0:
                return 'critical'
            if cvss_score >= 7.0:
                return 'high'
            if cvss_score >= 4.0:
                return 'medium'
            if cvss_score > 0:
                return 'low'

    # Debian fallback
    if ecosystem and ecosystem.startswith('Debian:'):
        vuln_id = vuln.get('id', '')
        if vuln_id:
            deb_sev = _debian_severity_fallback(vuln_id)
            if deb_sev:
                return deb_sev

    return 'unknown'


def scan_device(dev_id: str, packages: list, ecosystem: str, cache_dir: Path) -> dict:
    """Scan one device's package list against OSV (only if ecosystem supported)."""
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
            'error': f'Unsupported ecosystem for CVE scanning: {ecosystem}. OSV does not support Arch Linux or other non-listed distros.',
        }

    if len(packages) > MAX_PACKAGES:
        packages = packages[:MAX_PACKAGES]

    details_cache = _load_json(cache_dir / 'cve_details_cache.json')
    findings = []
    pkg_by_index = []

    queries = []
    for p in packages:
        name = (p.get('name') or '').strip()
        version = (p.get('version') or '').strip()
        if not name or not version:
            continue
        queries.append({'package': {'name': name, 'ecosystem': ecosystem}, 'version': version})
        pkg_by_index.append((name, version))

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
                if vid not in details_cache or (int(time.time()) - details_cache[vid].get('cached_at', 0)) > DETAILS_CACHE_TTL:
                    vuln_ids_to_fetch.add(vid)

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

    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f['severity']) if f['severity'] in SEVERITY_ORDER else 99, f['package']))
    return {'scanned_at': int(time.time()), 'ecosystem': ecosystem, 'findings': findings}


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
    return hashlib.sha256(json.dumps(normalized, separators=(',', ':')).encode()).hexdigest()[:16]


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

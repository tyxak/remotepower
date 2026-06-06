"""SBOM (Software Bill of Materials) generation — v3.5.0.

Turns the per-host installed-package inventory RemotePower already collects
(``packages.json``) into a standards-compliant SBOM document, optionally
enriched with the CVE findings (``cve_findings.json``) as a VEX-style
``vulnerabilities`` section. Two formats are supported:

  * CycloneDX 1.5 JSON  (primary — carries vulnerabilities natively)
  * SPDX 2.3 JSON       (interchange — packages + relationships only)

This is a pure-serialisation leaf module: it takes already-loaded dicts and
returns a JSON-serialisable dict. No disk or network I/O lives here, so it is
trivially unit-testable. The api.py handlers load the data, call one of the
``build_*`` functions, and stream the result as a file download.

purl (package URL) mapping mirrors the ecosystem the package manager belongs
to, so downstream tools (Dependency-Track, Grype, …) can re-resolve vulns:

    apt    -> pkg:deb/<distro>/<name>@<version>?arch=<arch>
    dnf    -> pkg:rpm/<distro>/<name>@<version>?arch=<arch>
    apk    -> pkg:apk/alpine/<name>@<version>?arch=<arch>
    pacman -> pkg:alpm/arch/<name>@<version>?arch=<arch>
"""

from __future__ import annotations

import hashlib
import time
from urllib.parse import quote

SPEC_CYCLONEDX = '1.5'
SPEC_SPDX = 'SPDX-2.3'

# pkg_manager (as stored on the package entry) -> purl "type" + a default
# namespace when the OS id is unknown.
_PURL_TYPE = {
    'apt':    ('deb', 'debian'),
    'dpkg':   ('deb', 'debian'),
    'dnf':    ('rpm', 'redhat'),
    'yum':    ('rpm', 'redhat'),
    'rpm':    ('rpm', 'redhat'),
    'zypper': ('rpm', 'opensuse'),
    'apk':    ('apk', 'alpine'),
    'pacman': ('alpm', 'arch'),
}


def _purl(name: str, version: str, arch: str, pkg_manager: str, os_id: str) -> str:
    """Build a package URL (purl) for one package. Falls back to the generic
    ``pkg:generic/`` type when the package manager isn't recognised."""
    ptype, default_ns = _PURL_TYPE.get((pkg_manager or '').lower(), ('generic', ''))
    ns = (os_id or default_ns or '').lower().strip()
    qn = quote(name, safe='')
    qv = quote(version, safe='')
    base = f'pkg:{ptype}/{quote(ns, safe="")}/{qn}@{qv}' if ns else f'pkg:{ptype}/{qn}@{qv}'
    if arch:
        base += f'?arch={quote(arch, safe="")}'
    return base


def _purl_container(image: str, tag: str, digest: str) -> str:
    """PackageURL for a running container image: pkg:docker/<image>@<digest|tag>.
    Prefers the immutable repo digest; falls back to the tag, then 'latest'."""
    img = (image or '').strip()
    if not img:
        return ''
    ver = (digest or '').strip() or (tag or '').strip() or 'latest'
    return f'pkg:docker/{quote(img, safe="/")}@{quote(ver, safe=":")}'


def _stable_serial(dev_id: str, collected_at) -> str:
    """Deterministic urn:uuid for the document — same host + same inventory
    snapshot yields the same serial, so re-exports are reproducible (and tests
    don't need to mock the clock)."""
    h = hashlib.sha256(f'{dev_id}:{collected_at}'.encode()).hexdigest()
    return (f'urn:uuid:{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}')


def _ts(epoch=None) -> str:
    epoch = int(epoch if epoch else time.time())
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(epoch))


# CycloneDX severity vocabulary is lowercase; our findings already use it, but
# normalise unknown/none to "unknown" which is a valid CycloneDX rating.
_CDX_SEV = {'critical', 'high', 'medium', 'low', 'info', 'none', 'unknown'}


def build_cyclonedx(dev, pkg_entry, findings, *, server_version='', containers=None) -> dict:
    """CycloneDX 1.5 BOM for one device.

    ``dev`` is the device record, ``pkg_entry`` the packages.json entry, and
    ``findings`` the (ignore-filtered) CVE finding list. ``findings`` may be
    empty — the vulnerabilities section is then omitted. ``containers`` (v3.14.0),
    when given, adds each running container image as a ``container`` component."""
    dev_id = dev.get('id') or dev.get('_id') or ''
    packages = pkg_entry.get('packages') or []
    pkg_manager = pkg_entry.get('pkg_manager', '')
    os_id = pkg_entry.get('os_id', '')
    collected_at = pkg_entry.get('collected_at', 0)

    # bom-ref per component, plus an index so vulnerabilities can point back to
    # the affected component by (name, version).
    components = []
    ref_by_nv = {}
    for i, p in enumerate(packages):
        name = p.get('name', '')
        version = p.get('version', '')
        arch = p.get('arch', '')
        if not name or not version:
            continue
        purl = _purl(name, version, arch, pkg_manager, os_id)
        ref = f'comp-{i}'
        ref_by_nv.setdefault((name, version), ref)
        comp = {
            'type': 'library',
            'bom-ref': ref,
            'name': name,
            'version': version,
            'purl': purl,
        }
        if arch:
            comp['properties'] = [{'name': 'remotepower:arch', 'value': arch}]
        components.append(comp)

    # v3.14.0: running container images as components.
    for j, c in enumerate(containers or []):
        image = (c.get('image') or '').strip()
        if not image:
            continue
        purl = _purl_container(image, c.get('tag', ''), c.get('repo_digest', ''))
        comp = {
            'type': 'container',
            'bom-ref': f'ctr-{j}',
            'name': image,
            'version': (c.get('repo_digest') or c.get('tag') or 'latest'),
            'purl': purl,
        }
        props = []
        if c.get('name'):
            props.append({'name': 'remotepower:container', 'value': c['name']})
        if c.get('runtime'):
            props.append({'name': 'remotepower:runtime', 'value': c['runtime']})
        if props:
            comp['properties'] = props
        components.append(comp)

    host_ref = f'host-{dev_id or "device"}'
    doc = {
        'bomFormat': 'CycloneDX',
        'specVersion': SPEC_CYCLONEDX,
        'serialNumber': _stable_serial(dev_id, collected_at),
        'version': 1,
        'metadata': {
            'timestamp': _ts(),
            'tools': [{
                'vendor': 'RemotePower',
                'name': 'RemotePower SBOM',
                'version': server_version or '',
            }],
            'component': {
                'type': 'operating-system',
                'bom-ref': host_ref,
                'name': dev.get('name') or dev.get('hostname') or dev_id or 'host',
                'version': dev.get('os', ''),
                'properties': [
                    {'name': 'remotepower:hostname', 'value': dev.get('hostname', '')},
                    {'name': 'remotepower:ecosystem', 'value': pkg_entry.get('ecosystem', '')},
                    {'name': 'remotepower:collected_at', 'value': _ts(collected_at) if collected_at else ''},
                ],
            },
        },
        'components': components,
    }

    vulns = _cyclonedx_vulns(findings, ref_by_nv)
    if vulns:
        doc['vulnerabilities'] = vulns
    return doc


def _cyclonedx_vulns(findings, ref_by_nv) -> list:
    out = []
    for f in (findings or []):
        vid = f.get('vuln_id')
        if not vid:
            continue
        sev = (f.get('severity') or 'unknown').lower()
        if sev not in _CDX_SEV:
            sev = 'unknown'
        affected_ref = ref_by_nv.get((f.get('package', ''), f.get('version', '')))
        v = {
            'id': vid,
            'ratings': [{
                'severity': sev,
                'source': {'name': (f.get('severity_source') or 'unknown')},
            }],
        }
        if f.get('summary'):
            v['description'] = f['summary'][:1000]
        refs = f.get('refs') or []
        if refs:
            v['advisories'] = [{'url': u} for u in refs[:8] if isinstance(u, str)]
        if f.get('aliases'):
            v['references'] = [
                {'id': a, 'source': {'name': 'alias'}}
                for a in f['aliases'][:8] if isinstance(a, str)
            ]
        if affected_ref:
            analysis_note = ''
            if f.get('fixed_version'):
                analysis_note = f"Fixed in {f['fixed_version']}"
            v['affects'] = [{'ref': affected_ref}]
            if analysis_note:
                v['analysis'] = {'detail': analysis_note}
        out.append(v)
    return out


def _spdx_id(prefix: str, i: int) -> str:
    return f'SPDXRef-{prefix}-{i}'


def build_spdx(dev, pkg_entry, findings, *, server_version='', containers=None) -> dict:
    """SPDX 2.3 JSON for one device. SPDX has no first-class vulnerability
    object in 2.3, so CVEs are attached as ExternalRefs (SECURITY / cpe-or
    advisory URLs) on the affected package where we can resolve it; otherwise
    they're summarised in the document comment."""
    dev_id = dev.get('id') or dev.get('_id') or ''
    packages = pkg_entry.get('packages') or []
    pkg_manager = pkg_entry.get('pkg_manager', '')
    os_id = pkg_entry.get('os_id', '')
    collected_at = pkg_entry.get('collected_at', 0)
    name = dev.get('name') or dev.get('hostname') or dev_id or 'host'

    # group findings by (pkg, version) so we can attach security refs
    sec_by_nv = {}
    for f in (findings or []):
        key = (f.get('package', ''), f.get('version', ''))
        if f.get('vuln_id'):
            sec_by_nv.setdefault(key, []).append(f['vuln_id'])

    spdx_packages = []
    relationships = []
    root_id = 'SPDXRef-DOCUMENT'
    host_id = _spdx_id('Host', 0)
    spdx_packages.append({
        'SPDXID': host_id,
        'name': name,
        'versionInfo': dev.get('os', ''),
        'downloadLocation': 'NOASSERTION',
        'filesAnalyzed': False,
        'copyrightText': 'NOASSERTION',
    })
    relationships.append({
        'spdxElementId': root_id,
        'relatedSpdxElement': host_id,
        'relationshipType': 'DESCRIBES',
    })

    for i, p in enumerate(packages):
        pname = p.get('name', '')
        pver = p.get('version', '')
        if not pname or not pver:
            continue
        pid = _spdx_id('Package', i)
        purl = _purl(pname, pver, p.get('arch', ''), pkg_manager, os_id)
        ext_refs = [{
            'referenceCategory': 'PACKAGE-MANAGER',
            'referenceType': 'purl',
            'referenceLocator': purl,
        }]
        for vid in sec_by_nv.get((pname, pver), [])[:16]:
            ext_refs.append({
                'referenceCategory': 'SECURITY',
                'referenceType': 'advisory',
                'referenceLocator': f'https://osv.dev/vulnerability/{quote(vid, safe="")}',
            })
        spdx_packages.append({
            'SPDXID': pid,
            'name': pname,
            'versionInfo': pver,
            'downloadLocation': 'NOASSERTION',
            'filesAnalyzed': False,
            'copyrightText': 'NOASSERTION',
            'externalRefs': ext_refs,
        })
        relationships.append({
            'spdxElementId': host_id,
            'relatedSpdxElement': pid,
            'relationshipType': 'CONTAINS',
        })

    # v3.14.0: running container images as SPDX packages.
    for j, c in enumerate(containers or []):
        image = (c.get('image') or '').strip()
        if not image:
            continue
        cid = _spdx_id('Container', j)
        purl = _purl_container(image, c.get('tag', ''), c.get('repo_digest', ''))
        spdx_packages.append({
            'SPDXID': cid,
            'name': image,
            'versionInfo': (c.get('repo_digest') or c.get('tag') or 'latest'),
            'downloadLocation': 'NOASSERTION',
            'filesAnalyzed': False,
            'copyrightText': 'NOASSERTION',
            'externalRefs': [{
                'referenceCategory': 'PACKAGE-MANAGER',
                'referenceType': 'purl',
                'referenceLocator': purl,
            }],
        })
        relationships.append({
            'spdxElementId': host_id,
            'relatedSpdxElement': cid,
            'relationshipType': 'CONTAINS',
        })

    doc = {
        'spdxVersion': SPEC_SPDX,
        'dataLicense': 'CC0-1.0',
        'SPDXID': root_id,
        'name': f'remotepower-sbom-{name}',
        'documentNamespace': _stable_serial(dev_id, collected_at).replace('urn:uuid:', 'https://remotepower/sbom/'),
        'creationInfo': {
            'created': _ts(),
            'creators': [f'Tool: RemotePower-SBOM-{server_version or "dev"}'],
        },
        'packages': spdx_packages,
        'relationships': relationships,
    }
    return doc


def filename_for(dev, fmt: str) -> str:
    """Safe download filename for a device's SBOM."""
    base = (dev.get('name') or dev.get('hostname') or 'host')
    safe = ''.join(c if (c.isalnum() or c in '-_.') else '-' for c in base)[:48] or 'host'
    ext = 'cdx.json' if fmt == 'cyclonedx' else 'spdx.json'
    return f'sbom-{safe}.{ext}'

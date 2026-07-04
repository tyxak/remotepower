"""RemotePower — monitor importers (W2-45).

Parse-only converters that turn a legacy monitoring config export into
RemotePower monitor definitions ({label, type, target, ...}) for review before
they are applied. Pure functions (no I/O, no api.* dependency) so they unit-test
against fixture files; api.py owns the endpoint that validates + merges the
proposal.

Supported inputs:
  - Uptime Kuma  — its Settings → Backup JSON export (`monitorList`)
  - Nagios / Icinga — object config (`define host`/`define service` blocks)
  - Zabbix       — Configuration → Export XML (hosts + interfaces)

Every parser is defensive: anything it can't map to one of RemotePower's
monitor types (ping / icmp / tcp / http / dns) is returned in `unmapped` with a
reason, never silently dropped.
"""
import json
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple


def detect_format(text: str) -> Optional[str]:
    """Best-effort format sniff. Returns 'kuma' | 'nagios' | 'zabbix' | None."""
    t = (text or '').lstrip()
    if not t:
        return None
    if t[0] in '{[':
        try:
            doc = json.loads(t)
        except ValueError:
            return None
        if isinstance(doc, dict) and 'monitorList' in doc:
            return 'kuma'
        return None
    if '<zabbix_export' in t or ('<hosts>' in t and '<zabbix' in t):
        return 'zabbix'
    if re.search(r'define\s+(host|service)\s*\{', t):
        return 'nagios'
    if t.startswith('<'):
        return 'zabbix'
    return None


def _mon(label: str, mtype: str, target: str, **extra: Any) -> Dict[str, Any]:
    m: Dict[str, Any] = {'label': (label or target or '')[:128], 'type': mtype,
                         'target': str(target)[:255], 'target_kind': 'host'}
    m.update(extra)
    return m


# ── Uptime Kuma ─────────────────────────────────────────────────────────────

def _parse_kuma(doc: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, str]]]:
    monitors, unmapped = [], []
    raw = doc.get('monitorList')
    items = raw.values() if isinstance(raw, dict) else (raw or [])
    for m in items:
        if not isinstance(m, dict):
            continue
        name = str(m.get('name') or '').strip()
        kind = str(m.get('type') or '').lower()
        if kind in ('http', 'keyword', 'json-query'):
            url = str(m.get('url') or '').strip()
            if not url:
                unmapped.append({'name': name, 'reason': 'http monitor without url'})
                continue
            mon = _mon(name, 'http', url)
            kw = (m.get('keyword') or '').strip()
            if kind == 'keyword' and kw:
                mon['body_match'] = {'mode': 'contains', 'value': kw[:200]}
            monitors.append(mon)
        elif kind in ('port', 'tcp'):
            host = str(m.get('hostname') or '').strip()
            port = m.get('port')
            if host and port:
                monitors.append(_mon(name, 'tcp', f'{host}:{int(port)}'))
            else:
                unmapped.append({'name': name, 'reason': 'port monitor without host/port'})
        elif kind == 'ping':
            host = str(m.get('hostname') or '').strip()
            if host:
                monitors.append(_mon(name, 'ping', host))
            else:
                unmapped.append({'name': name, 'reason': 'ping monitor without host'})
        elif kind == 'dns':
            host = str(m.get('hostname') or '').strip()
            if host:
                monitors.append(_mon(name, 'dns', host))
            else:
                unmapped.append({'name': name, 'reason': 'dns monitor without host'})
        else:
            unmapped.append({'name': name, 'reason': f'unsupported Kuma type: {kind}'})
    return monitors, unmapped


# ── Nagios / Icinga object config ───────────────────────────────────────────

def _nagios_blocks(text: str, kind: str):
    """Yield {directive: value} dicts for each `define <kind> { ... }` block."""
    for body in re.findall(r'define\s+%s\s*\{(.*?)\}' % kind, text, re.S):
        d = {}
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith('#') or line.startswith(';'):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                d[parts[0].lower()] = parts[1].strip()
        yield d


def _parse_nagios(text: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, str]]]:
    monitors, unmapped = [], []
    # host_name → address, so a service can resolve its target
    addr = {}
    for h in _nagios_blocks(text, 'host'):
        hn = h.get('host_name') or h.get('name') or ''
        a = h.get('address') or hn
        if hn:
            addr[hn] = a
    seen_service_hosts = set()
    for s in _nagios_blocks(text, 'service'):
        hn = s.get('host_name') or ''
        cmd = (s.get('check_command') or '').strip()
        target = addr.get(hn, hn)
        desc = s.get('service_description') or cmd or hn
        base = cmd.split('!', 1)[0].lower()
        if not target:
            unmapped.append({'name': desc, 'reason': 'service without a resolvable host'})
            continue
        if base in ('check_http', 'check_ssl_cert', 'check_https'):
            scheme = 'https' if 'https' in base or 'ssl' in base else 'http'
            monitors.append(_mon(f'{hn}:{desc}', 'http', f'{scheme}://{target}'))
        elif base in ('check_tcp', 'check_port'):
            port = cmd.split('!', 1)[1].split('!')[0] if '!' in cmd else ''
            if port.isdigit():
                monitors.append(_mon(f'{hn}:{desc}', 'tcp', f'{target}:{port}'))
            else:
                unmapped.append({'name': desc, 'reason': 'check_tcp without a port arg'})
        elif base in ('check_ping', 'check-host-alive', 'check_icmp'):
            monitors.append(_mon(f'{hn}:{desc}', 'ping', target))
            seen_service_hosts.add(hn)
        elif base in ('check_dns', 'check_dig'):
            monitors.append(_mon(f'{hn}:{desc}', 'dns', target))
        else:
            unmapped.append({'name': desc, 'reason': f'unmapped check_command: {base}'})
    # hosts with no ping-ish service get a plain reachability ping
    for hn, a in addr.items():
        if hn not in seen_service_hosts:
            monitors.append(_mon(hn, 'ping', a))
    return monitors, unmapped


# ── Zabbix XML export ───────────────────────────────────────────────────────

def _parse_zabbix(text: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, str]]]:
    monitors, unmapped = [], []
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        return [], [{'name': 'parse', 'reason': f'invalid XML: {e}'}]
    for host in root.iter('host'):
        # NB: an ElementTree Element with no children is falsy, so `find(..) or
        # find(..)` misfires — test each result explicitly against None.
        name_el = host.find('name')
        if name_el is None:
            name_el = host.find('host')
        name = (name_el.text or '').strip() if name_el is not None else ''
        ip = ''
        for iface in host.iter('interface'):
            ip_el = iface.find('ip')
            dns_el = iface.find('dns')
            ip = (ip_el.text or '').strip() if ip_el is not None else ''
            if not ip and dns_el is not None:
                ip = (dns_el.text or '').strip()
            if ip:
                break
        target = ip or name
        if target:
            monitors.append(_mon(name or target, 'ping', target))
        else:
            unmapped.append({'name': name, 'reason': 'host without an interface IP/DNS'})
    return monitors, unmapped


def parse(text: str, fmt: Optional[str] = None) -> Dict[str, Any]:
    """Parse `text` into {format, monitors:[...], unmapped:[...]}. Raises
    ValueError on an unrecognised / unparseable format."""
    fmt = fmt or detect_format(text)
    if fmt == 'kuma':
        doc = json.loads(text)
        mons, un = _parse_kuma(doc)
    elif fmt == 'nagios':
        mons, un = _parse_nagios(text)
    elif fmt == 'zabbix':
        mons, un = _parse_zabbix(text)
    else:
        raise ValueError('unrecognised import format (expected Uptime Kuma JSON, '
                         'Nagios object config, or Zabbix XML export)')
    # de-dup by (type, target) keeping the first label
    seen, deduped = set(), []
    for m in mons:
        key = (m['type'], m['target'])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(m)
    return {'format': fmt, 'monitors': deduped, 'unmapped': un}

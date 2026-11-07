#!/usr/bin/env python3
"""A hosted, read-only MCP endpoint (8.0.0): the protocol and the tools, with no knowledge of how a request is served.

The Model Context Protocol is JSON-RPC 2.0. This module answers one message at a time over the "streamable HTTP" transport's plain form: a POST
that carries one request and gets one JSON answer, and a notification that gets nothing. It issues no session, streams nothing and offers no
server-initiated message, which that transport allows.

It holds no authority of its own. A tool names the GET paths it reads and asks fetch(path) for them; the host (mcp_http_handlers) answers
each through the same gates and handlers that serve the caller's own requests, as the caller, so a viewer's token sees what a viewer sees and a
host scope or a tenant limit applies exactly as it does in the dashboard. A tool cannot name a method other than GET, a path outside /api/, or an
id it did not read from the server first.

Only read tools exist here. The five write tools of mcp/remotepower-mcp.py (reboot, run a script, force a scan, force an ACME rescan,
acknowledge an alert) are not offered over HTTP: they act on the fleet, and the confirmation and attribution they carry belong to the local bridge.

Stdlib only. handle(message, fetch, server_version) returns (http_status, answer) where the answer is a dict to send as JSON, or None for a
notification.
"""
import json
import re
import urllib.parse

PROTOCOL_VERSIONS = ('2025-06-18', '2025-03-26', '2024-11-05')       # newest first; the client's own is answered when it is one of these
SERVER_NAME = 'remotepower'
MAX_RESULT_CHARS = 60000        # what one tool result may weigh: a model's context is the budget, and a whole fleet is more than it needs
MAX_ROWS = 200
MAX_ARGUMENT_CHARS = 200

# JSON-RPC error codes
PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS = -32700, -32600, -32601, -32602

_SAFE_ID = re.compile(r'^[A-Za-z0-9_.:-]{1,128}$')
_SECRETISH = re.compile(r'(token|secret|password|passphrase)', re.I)


class ToolError(Exception):
    """A request the tool cannot satisfy (no such host, a wrong argument): shown to the model as the tool's own answer."""


class FetchError(Exception):
    """The server answered a read with a status that is not a success.  is the server's own text."""

    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


# The text the model reads for each tool. These are the descriptions and schemas of mcp/remotepower-mcp.py, word for word: a model that
# is connected both ways sees one tool, and tests/test_v800_mcp_http.py fails when the two drift apart.
SPECS = {
    'list_alerts': {
        'description':
            'The Alerts inbox: open (or acknowledged/resolved) alerts, newest first, with severity, the host, when it FIRST '
            'fired, who acked it, and the correlation flags — whether it is the root cause on its host, which upstream it '
            'is collateral from, and any declared incident it belongs to. This is the right first call for "what is wrong '
            'right now?" — list_devices only shows up/down. Filter with status=open|acknowledged|resolved|all and '
            'severity=critical|high|medium|low.',
        'inputSchema': {"type": "object", "properties": {"status": {"type": "string", "description": "open (default), acknowledged, resolved, all"}, "severity": {"type": "string", "description": "critical, high, medium or low"}, "limit": {"type": "integer", "description": "max rows, default 50, cap 200"}}},
    },
    'get_attention': {
        'description':
            'The Needs-attention digest — everything the fleet wants looked at, ranked, including things that never became '
            'an alert (stale backups, expiring certificates, drifted config, posture gaps). Broader than list_alerts and '
            'the better call for "what should I work on?".',
        'inputSchema': {"type": "object", "properties": {"limit": {"type": "integer", "description": "max items, default 50"}}},
    },
    'list_devices': {
        'description':
            'List all hosts in the RemotePower fleet with current online status, OS, group, tags, IP. Always start here to '
            'know which hosts exist before querying specific ones.',
        'inputSchema': {"type": "object", "properties": {}},
    },
    'get_device': {
        'description':
            'Get full detail for one host by name. Includes sysinfo (uptime, OS, kernel, memory, disks), watched services, '
            'containers, recent journal, tags, group, notes. Use after list_devices to drill into a specific host.',
        'inputSchema': {"type": "object", "properties": {"name": {"type": "string", "description": "Host name (prefix or substring OK)"}}, "required": ["name"]},
    },
    'get_services': {
        'description':
            'List of systemd units being watched on a host, with their current active/inactive/failed state. Watched units '
            'are configured per-host in the dashboard.',
        'inputSchema': {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]},
    },
    'get_containers': {
        'description':
            'Docker / Podman container state for a host. Returns running containers with image, state, status, ports.',
        'inputSchema': {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]},
    },
    'get_cves': {
        'description':
            'CVE findings for a host, or fleet-wide if no name is given. Returns vulnerability id, severity, affected '
            'package, fixed version, and summary. Backed by OSV.dev. Use to identify outstanding security issues.',
        'inputSchema': {"type": "object", "properties": {"name": {"type": "string", "description": "Host name; omit for fleet-wide"}}},
    },
    'get_patches': {
        'description':
            "Pending OS package updates. With a host name returns that host's patch status and pending count; without a "
            'name returns all hosts with pending updates.',
        'inputSchema': {"type": "object", "properties": {"name": {"type": "string"}}},
    },
}


# ── arguments ────────────────────────────────────────────────────────────────────────────────────────────────────────────
def _text(args, key, required=False):
    v = args.get(key)
    if v is None or v == '':
        if required:
            raise ToolError("'%s' argument required" % key)
        return ''
    if not isinstance(v, str):
        raise ToolError("'%s' must be text" % key)
    v = v.strip()
    if len(v) > MAX_ARGUMENT_CHARS:
        raise ToolError("'%s' is too long" % key)
    return v


def _limit(args, default=50):
    v = args.get('limit')
    if v is None or isinstance(v, bool):
        return default
    try:
        return max(1, min(MAX_ROWS, int(v)))
    except (TypeError, ValueError):
        return default


def _scrub(obj):
    """What a model is shown carries no credential: a key that names one is dropped at any depth."""
    if isinstance(obj, dict):
        return {k: _scrub(v) for k, v in obj.items() if not (isinstance(k, str) and _SECRETISH.search(k))}
    if isinstance(obj, list):
        return [_scrub(v) for v in obj]
    return obj


# ── hosts ────────────────────────────────────────────────────────────────────────────────────────────────────────────────
def _devices(fetch):
    data = fetch('/api/devices')
    devs = data if isinstance(data, list) else (data or {}).get('devices') or []
    return [d for d in devs if isinstance(d, dict)]


def _find(fetch, name):
    """A host by name: the exact name, else the one that starts with it, else the one that contains it; several are an error that names them."""
    devs = _devices(fetch)
    low = name.lower()
    for d in devs:
        if str(d.get('name') or '').lower() == low:
            return d
    for test in (lambda n: n.startswith(low), lambda n: low in n):
        hits = [d for d in devs if test(str(d.get('name') or '').lower())]
        if len(hits) == 1:
            return hits[0]
        if len(hits) > 1:
            raise ToolError("Host name '%s' is ambiguous. Matches: %s. Provide a more specific name." % (name, ', '.join(str(d.get('name') or '?') for d in hits[:5])))
    raise ToolError("No host named '%s'" % name)


def _id_of(dev):
    """The id a host's own page is reached by. It came from the server, and it is still checked, because it goes into a path."""
    dev_id = str(dev.get('id') or dev.get('device_id') or '')
    if not _SAFE_ID.match(dev_id):
        raise ToolError("The host has an id this endpoint will not use")
    return dev_id


def _host_path(dev, tail):
    return '/api/devices/%s/%s' % (urllib.parse.quote(_id_of(dev), safe=''), tail)


# ── the tools ────────────────────────────────────────────────────────────────────────────────────────────────────────────
def tool_list_alerts(args, fetch):
    qs = []
    status = (_text(args, 'status') or 'open').lower()
    if status in ('open', 'acknowledged', 'resolved', 'all'):
        qs.append('status=' + status)
    sev = _text(args, 'severity').lower()
    if sev in ('critical', 'high', 'medium', 'low'):
        qs.append('severity=' + sev)
    qs.append('limit=%d' % _limit(args))
    data = fetch('/api/alerts?' + '&'.join(qs))
    rows = data if isinstance(data, list) else (data or {}).get('alerts') or []
    # trimmed hard: a stored alert carries its whole payload and an AI-triage blob
    return [{
        'id': r.get('id'), 'ref': r.get('alertid'), 'severity': r.get('severity'), 'event': r.get('event'), 'title': r.get('title'),
        'device': r.get('device_name') or r.get('device_id') or '', 'first_seen': r.get('first_seen') or r.get('ts'),
        'acknowledged_by': r.get('acknowledged_by'), 'resolved_at': r.get('resolved_at'),
        'root_cause': bool(r.get('_root_cause')), 'collateral_of': r.get('_collateral_of') or None, 'incident_id': r.get('incident_id') or None,
    } for r in rows if isinstance(r, dict)]


def tool_get_attention(args, fetch):
    data = fetch('/api/attention') or {}
    items = data.get('items') if isinstance(data, dict) else None
    if not isinstance(items, list):
        items = data if isinstance(data, list) else []
    return [{'kind': i.get('kind'), 'severity': i.get('severity'), 'title': i.get('title') or i.get('label'), 'detail': i.get('detail') or '',
             'device': i.get('device_name') or i.get('device_id') or ''} for i in items[:_limit(args)] if isinstance(i, dict)]


def tool_list_devices(args, fetch):
    return [{
        'name': d.get('name'), 'os': d.get('os'), 'online': d.get('online', False), 'last_seen': d.get('last_seen'), 'group': d.get('group', ''),
        'tags': d.get('tags', []), 'ip': d.get('ip', ''), 'pkg_manager': ((d.get('sysinfo') or {}).get('packages') or {}).get('manager', ''),
        'agentless': d.get('agentless', False),
    } for d in _devices(fetch)[:MAX_ROWS]]


def tool_get_device(args, fetch):
    dev = _find(fetch, _text(args, 'name', required=True))
    return _scrub(dev)


def tool_get_services(args, fetch):
    dev = _find(fetch, _text(args, 'name', required=True))
    data = fetch(_host_path(dev, 'services')) or {}
    rows = [{k: s.get(k) for k in ('unit', 'active', 'sub', 'since', 'restarts') if s.get(k) is not None}
            for s in (data.get('services') or []) if isinstance(s, dict)]
    return {'device': dev.get('name'), 'updated_at': data.get('updated_at'), 'services': rows[:MAX_ROWS]}


def tool_get_containers(args, fetch):
    dev = _find(fetch, _text(args, 'name', required=True))
    data = fetch(_host_path(dev, 'containers')) or {}
    keep = ('name', 'image', 'tag', 'status', 'health', 'restart_count', 'runtime', 'namespace', 'uptime_seconds')
    rows = [{k: c.get(k) for k in keep if c.get(k) not in (None, '')} for c in (data.get('items') or []) if isinstance(c, dict)]
    return {'device': dev.get('name'), 'reported_at': data.get('reported_at'), 'is_stale': data.get('is_stale'), 'summary': data.get('summary'),
            'containers': rows[:MAX_ROWS]}


def tool_get_cves(args, fetch):
    name = _text(args, 'name')
    if name:
        dev = _find(fetch, name)
        data = fetch(_host_path(dev, 'cves'))
        return {'device': dev.get('name'), 'findings': ((data or {}).get('findings') or [])[:MAX_ROWS]}
    data = fetch('/api/cve/findings')
    return data or {'findings': []}


def tool_get_patches(args, fetch):
    name = _text(args, 'name')
    data = fetch('/api/patch-report') or {}
    rows = [d for d in (data.get('devices') or []) if isinstance(d, dict)]
    keep = ('name', 'pkg_manager', 'upgradable', 'security_updates', 'patch_status', 'reboot_required', 'online')
    if name:
        dev = _find(fetch, name)
        row = next((d for d in rows if d.get('device_id') == _id_of(dev)), None) or {}
        return {'device': dev.get('name'), **{k: row.get(k) for k in keep if k != 'name'}}
    return {'fleet': [{k: d.get(k) for k in keep} for d in rows if (d.get('upgradable') or 0) > 0][:MAX_ROWS], 'summary': data.get('summary')}


TOOLS = {n: dict(SPECS[n], run=f) for n, f in (
    ('list_alerts', tool_list_alerts), ('get_attention', tool_get_attention), ('list_devices', tool_list_devices), ('get_device', tool_get_device),
    ('get_services', tool_get_services), ('get_containers', tool_get_containers), ('get_cves', tool_get_cves), ('get_patches', tool_get_patches))}


# ── the protocol ─────────────────────────────────────────────────────────────────────────────────────────────────────────
def _error(msg_id, code, message):
    return {'jsonrpc': '2.0', 'id': msg_id, 'error': {'code': code, 'message': message}}


def _fit(obj):
    """A result as JSON text that fits the budget. A list that is too long is cut from the end and says so, and the text stays valid JSON."""
    text = json.dumps(obj, ensure_ascii=False, separators=(',', ':'), default=str)
    if len(text) <= MAX_RESULT_CHARS:
        return text
    key = None
    rows = obj if isinstance(obj, list) else None
    if rows is None and isinstance(obj, dict):
        key = max((k for k, v in obj.items() if isinstance(v, list)), key=lambda k: len(obj[k]), default=None)
        rows = obj[key] if key else None
    if rows:
        keep = len(rows)
        while keep > 1:
            keep //= 2
            cut = list(rows[:keep])
            if key is None:
                wrapped = {'truncated': True, 'shown': keep, 'total': len(rows), 'items': cut}
            else:
                wrapped = dict(obj, **{key: cut, 'truncated': True, 'shown': keep, 'total': len(rows)})
            text = json.dumps(wrapped, ensure_ascii=False, separators=(',', ':'), default=str)
            if len(text) <= MAX_RESULT_CHARS:
                return text
    return json.dumps({'truncated': True, 'note': 'The answer is larger than the %d characters one tool result may carry; ask for one host.' % MAX_RESULT_CHARS})


def _call(params, fetch):
    name = params.get('name')
    if not isinstance(name, str) or name not in TOOLS:
        return None, (INVALID_PARAMS, 'Unknown tool: %s' % (name[:60] if isinstance(name, str) else ''))
    args = params.get('arguments')
    if args is None:
        args = {}
    if not isinstance(args, dict):
        return None, (INVALID_PARAMS, "'arguments' must be an object")
    try:
        text = _fit(TOOLS[name]['run'](args, fetch))
        is_error = False
    except ToolError as e:
        text, is_error = str(e), True
    except FetchError as e:
        text, is_error = 'HTTP %s: %s' % (e.status, e.message), True
    return {'content': [{'type': 'text', 'text': text}], 'isError': is_error}, None


def tool_listing():
    return [{'name': n, 'description': t['description'], 'inputSchema': t['inputSchema'],
             'annotations': {'title': n.replace('_', ' '), 'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False}}
            for n, t in TOOLS.items()]


def negotiate(requested):
    return requested if requested in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0]


def handle(message, fetch, server_version):
    """One JSON-RPC message in, (http_status, answer) out. A notification gets (202, None). A request gets (200, result-or-error)."""
    if not isinstance(message, dict):
        return 400, _error(None, INVALID_REQUEST, 'Send one JSON-RPC request object, not a batch')
    msg_id = message.get('id')
    is_request = 'id' in message
    if message.get('jsonrpc') != '2.0' or not isinstance(message.get('method'), str):
        return 400, _error(msg_id if isinstance(msg_id, (str, int)) and not isinstance(msg_id, bool) else None, INVALID_REQUEST, 'Not a JSON-RPC 2.0 request')
    if not is_request:
        return 202, None
    if isinstance(msg_id, bool) or not isinstance(msg_id, (str, int)):
        return 400, _error(None, INVALID_REQUEST, 'The id must be a string or an integer')
    method = message['method']
    params = message.get('params')
    if params is None:
        params = {}
    if not isinstance(params, dict):
        return 200, _error(msg_id, INVALID_PARAMS, "'params' must be an object")
    if method == 'initialize':
        return 200, {'jsonrpc': '2.0', 'id': msg_id, 'result': {
            'protocolVersion': negotiate(params.get('protocolVersion')),
            'capabilities': {'tools': {'listChanged': False}},
            'serverInfo': {'name': SERVER_NAME, 'version': server_version},
            'instructions': 'Read-only access to this RemotePower fleet, with the permissions of the token that is calling. Start with list_alerts or get_attention.'}}
    if method == 'ping':
        return 200, {'jsonrpc': '2.0', 'id': msg_id, 'result': {}}
    if method == 'tools/list':
        return 200, {'jsonrpc': '2.0', 'id': msg_id, 'result': {'tools': tool_listing()}}
    if method == 'tools/call':
        result, bad = _call(params, fetch)
        if bad:
            return 200, _error(msg_id, bad[0], bad[1])
        return 200, {'jsonrpc': '2.0', 'id': msg_id, 'result': result}
    return 200, _error(msg_id, METHOD_NOT_FOUND, 'Method not found: %s' % method[:60])

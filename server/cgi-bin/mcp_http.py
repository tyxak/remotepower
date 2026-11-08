#!/usr/bin/env python3
"""A hosted, read-only MCP endpoint (8.0.0): the protocol and the tools, with no knowledge of how a request is served.

The Model Context Protocol is JSON-RPC 2.0. This module answers one message at a time over the "streamable HTTP" transport's plain form: a POST
that carries one request and gets one JSON answer, and a notification that gets nothing. It issues no session, streams nothing and offers no
server-initiated message, which that transport allows.

It holds no authority of its own. A tool names the paths it reads and asks fetch(path) for them; the host (mcp_http_handlers) answers
each through the same gates and handlers that serve the caller's own requests, as the caller, so a viewer's token sees what a viewer sees and a
host scope or a tenant limit applies exactly as it does in the dashboard. A tool cannot name a method other than GET, a path outside /api/, or an
id it did not read from the server first. The one exception is a POST that only reads: the knowledge-index search takes its question in a body, so
fetch(path, 'POST', body) exists, and the host refuses every path that is not in READ_POSTS.

Only read tools exist here. The five write tools of mcp/remotepower-mcp.py (reboot, run a script, force a scan, force an ACME rescan,
acknowledge an alert) are not offered over HTTP: they act on the fleet, and the confirmation and attribution they carry belong to the local bridge.

Stdlib only. handle(message, fetch, server_version) returns (http_status, answer) where the answer is a dict to send as JSON, or None for a
notification.
"""

import json
import re
import urllib.parse

PROTOCOL_VERSIONS = (
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
)  # newest first; the client's own is answered when it is one of these
SERVER_NAME = "remotepower"
MAX_RESULT_CHARS = 60000  # what one tool result may weigh: a model's context is the budget, and a whole fleet is more than it needs
MAX_ROWS = 200
MAX_ARGUMENT_CHARS = 200

# JSON-RPC error codes
PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS = -32700, -32600, -32601, -32602

_SAFE_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_SECRETISH = re.compile(r"(token|secret|password|passphrase|community|api_?key)", re.I)
READ_POSTS = (
    "/api/ai/rag/search",
)  # the paths a tool may POST to: each only reads, and the host enforces this list, not the tool

# What goes to a model is free text from the fleet (journal lines, command output). Passwords and tokens that are written as name=value, as
# an option or as an Authorization header are masked; this is best effort, and text can still hold other private data (the docs say so).
_MASK_PAIR = re.compile(
    r"""(\b[\w.-]*(?:token|secret|passw(?:or)?d|passphrase|api[_-]?key|community)[\w.-]*\s*[=:]\s*)("[^"\n]*"|'[^'\n]*'|[^\s,;]+)""",
    re.I,
)
_MASK_FLAG = re.compile(
    r"(--?(?:token|secret|passw(?:or)?d|passphrase|api[_-]?key|community)\s+)\S+", re.I
)
_MASK_AUTH = re.compile(r'(authorization\s*:\s*(?:bearer|basic)\s+)[^\s"\']+', re.I)


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
    "list_alerts": {
        "description": "The Alerts inbox: open (or acknowledged/resolved) alerts, newest first, with severity, the host, when it FIRST "
        "fired, who acked it, and the correlation flags — whether it is the root cause on its host, which upstream it "
        'is collateral from, and any declared incident it belongs to. This is the right first call for "what is wrong '
        'right now?" — list_devices only shows up/down. Filter with status=open|acknowledged|resolved|all and '
        "severity=critical|high|medium|low.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "description": "open (default), acknowledged, resolved, all",
                },
                "severity": {"type": "string", "description": "critical, high, medium or low"},
                "limit": {"type": "integer", "description": "max rows, default 50, cap 200"},
            },
        },
    },
    "get_attention": {
        "description": "The Needs-attention digest — everything the fleet wants looked at, ranked, including things that never became "
        "an alert (stale backups, expiring certificates, drifted config, posture gaps). Broader than list_alerts and "
        'the better call for "what should I work on?".',
        "inputSchema": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "description": "max items, default 50"}},
        },
    },
    "list_devices": {
        "description": "List all hosts in the RemotePower fleet with current online status, OS, group, tags, IP. Always start here to "
        "know which hosts exist before querying specific ones.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    "get_device": {
        "description": "Get full detail for one host by name. Includes sysinfo (uptime, OS, kernel, memory, disks), watched services, "
        "containers, recent journal, tags, group, notes. Use after list_devices to drill into a specific host.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Host name (prefix or substring OK)"}
            },
            "required": ["name"],
        },
    },
    "get_services": {
        "description": "List of systemd units being watched on a host, with their current active/inactive/failed state. Watched units "
        "are configured per-host in the dashboard.",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
    },
    "get_containers": {
        "description": "Docker / Podman container state for a host. Returns running containers with image, state, status, ports.",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
    },
    "get_cves": {
        "description": "CVE findings for a host, or fleet-wide if no name is given. Returns vulnerability id, severity, affected "
        "package, fixed version, and summary. Backed by OSV.dev. Use to identify outstanding security issues.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Host name; omit for fleet-wide"}
            },
        },
    },
    "get_patches": {
        "description": "Pending OS package updates. With a host name returns that host's patch status and pending count; without a "
        "name returns all hosts with pending updates.",
        "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}},
    },
    "get_journal": {
        "description": "Recent systemd journal entries from a host. Useful for debugging service issues or recent errors. The agent ships the "
        "most recent journal lines on each heartbeat.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Host name"},
                "limit": {"type": "integer", "description": "Max lines (default 30)"},
            },
            "required": ["name"],
        },
    },
    "get_drift": {
        "description": "Configuration drift state for a host, or fleet-wide overview if no name is given. Returns the watched config files "
        "whose current hash diverges from the stored baseline (potential unauthorised changes).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Host name; omit for fleet overview"}
            },
        },
    },
    "get_recent_commands": {
        "description": "Recent commands run on a host, with output and exit code. Useful for 'what was done on this host recently' questions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "limit": {"type": "integer", "description": "Max entries (default 10)"},
            },
            "required": ["name"],
        },
    },
    "get_runbook": {
        "description": "AI-generated operations runbook for a host (v2.1.7+). Describes purpose, services, exposure, recent activity, risks, "
        "operating notes. Returns exists=false if no runbook has been generated for this host yet.",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
    },
    "get_tls": {
        "description": "TLS / DNS expiry watchlist status. Lists hosts being probed for certificate expiry and DNS resolution, with current "
        "days-until-expiry and warning/critical state.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    "get_snmp_data": {
        "description": "Latest SNMP poll for an agentless host (switches, APs, IPMI, printers). Returns sysDescr / sysName / sysUpTime / "
        "sysContact / sysLocation / sysObjectID. Includes last_ok / last_error so the AI can tell whether the box is currently "
        "reachable. Returns ok=false if SNMP isn't enabled.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Host name (prefix/substring OK)"}
            },
            "required": ["name"],
        },
    },
    "search_devices": {
        "description": "Search hosts by free-text query. Matches name, OS, group, tags, hostname, IP, and operator notes. Returns a compact "
        "list of matches.",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    "search_fleet": {
        "description": "Search the RAG knowledge index across ALL fleet state, CMDB, runbooks, recent history, and product docs in one call. "
        "Prefer this for broad or cross-host questions ('worst CVEs in the fleet', 'which hosts need a reboot', 'what ports "
        "are listening on tviapp01', 'how do I configure X in RemotePower') instead of calling list_devices + several get_* "
        "tools and aggregating yourself. Returns ranked chunks with citation ids and excerpts; fleet-wide rollups (worst CVEs, "
        "pending updates/reboots, config drift, cert expiry) come back as single chunks. Use the granular get_* tools when you "
        "need one host's complete structured record.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Natural-language question or keywords"},
                "top_n": {"type": "integer", "description": "Max chunks to return (default 6)"},
            },
            "required": ["query"],
        },
    },
}


# ── arguments ────────────────────────────────────────────────────────────────────────────────────────────────────────────
def _text(args, key, required=False):
    v = args.get(key)
    if v is None or v == "":
        if required:
            raise ToolError("'%s' argument required" % key)
        return ""
    if not isinstance(v, str):
        raise ToolError("'%s' must be text" % key)
    v = v.strip()
    if len(v) > MAX_ARGUMENT_CHARS:
        raise ToolError("'%s' is too long" % key)
    return v


def _limit(args, default=50):
    v = args.get("limit")
    if v is None or isinstance(v, bool):
        return default
    try:
        return max(1, min(MAX_ROWS, int(v)))
    except (TypeError, ValueError):
        return default


def _mask_text(value, limit):
    """Free text as a model may see it: passwords and tokens masked, then cut to `limit` characters."""
    text = str(value if value is not None else "")
    text = _MASK_PAIR.sub(lambda m: m.group(1) + "***", text)
    text = _MASK_FLAG.sub(lambda m: m.group(1) + "***", text)
    text = _MASK_AUTH.sub(lambda m: m.group(1) + "***", text)
    return text[:limit]


def _scrub(obj):
    """What a model is shown carries no credential: a key that names one is dropped at any depth."""
    if isinstance(obj, dict):
        return {
            k: _scrub(v)
            for k, v in obj.items()
            if not (isinstance(k, str) and _SECRETISH.search(k))
        }
    if isinstance(obj, list):
        return [_scrub(v) for v in obj]
    return obj


# ── hosts ────────────────────────────────────────────────────────────────────────────────────────────────────────────────
def _devices(fetch):
    data = fetch("/api/devices")
    devs = data if isinstance(data, list) else (data or {}).get("devices") or []
    return [d for d in devs if isinstance(d, dict)]


def _find(fetch, name):
    """A host by name: the exact name, else the one that starts with it, else the one that contains it; several are an error that names them."""
    devs = _devices(fetch)
    low = name.lower()
    for d in devs:
        if str(d.get("name") or "").lower() == low:
            return d
    for test in (lambda n: n.startswith(low), lambda n: low in n):
        hits = [d for d in devs if test(str(d.get("name") or "").lower())]
        if len(hits) == 1:
            return hits[0]
        if len(hits) > 1:
            raise ToolError(
                "Host name '%s' is ambiguous. Matches: %s. Provide a more specific name."
                % (name, ", ".join(str(d.get("name") or "?") for d in hits[:5]))
            )
    raise ToolError("No host named '%s'" % name)


def _id_of(dev):
    """The id a host's own page is reached by. It came from the server, and it is still checked, because it goes into a path."""
    dev_id = str(dev.get("id") or dev.get("device_id") or "")
    if not _SAFE_ID.match(dev_id):
        raise ToolError("The host has an id this endpoint will not use")
    return dev_id


def _host_path(dev, tail):
    return "/api/devices/%s/%s" % (urllib.parse.quote(_id_of(dev), safe=""), tail)


# ── the tools ────────────────────────────────────────────────────────────────────────────────────────────────────────────
def tool_list_alerts(args, fetch):
    qs = []
    status = (_text(args, "status") or "open").lower()
    if status in ("open", "acknowledged", "resolved", "all"):
        qs.append("status=" + status)
    sev = _text(args, "severity").lower()
    if sev in ("critical", "high", "medium", "low"):
        qs.append("severity=" + sev)
    qs.append("limit=%d" % _limit(args))
    data = fetch("/api/alerts?" + "&".join(qs))
    rows = data if isinstance(data, list) else (data or {}).get("alerts") or []
    # trimmed hard: a stored alert carries its whole payload and an AI-triage blob
    return [
        {
            "id": r.get("id"),
            "ref": r.get("alertid"),
            "severity": r.get("severity"),
            "event": r.get("event"),
            "title": r.get("title"),
            "device": r.get("device_name") or r.get("device_id") or "",
            "first_seen": r.get("first_seen") or r.get("ts"),
            "acknowledged_by": r.get("acknowledged_by"),
            "resolved_at": r.get("resolved_at"),
            "root_cause": bool(r.get("_root_cause")),
            "collateral_of": r.get("_collateral_of") or None,
            "incident_id": r.get("incident_id") or None,
        }
        for r in rows
        if isinstance(r, dict)
    ]


def tool_get_attention(args, fetch):
    data = fetch("/api/attention") or {}
    items = data.get("items") if isinstance(data, dict) else None
    if not isinstance(items, list):
        items = data if isinstance(data, list) else []
    return [
        {
            "kind": i.get("kind"),
            "severity": i.get("severity"),
            "title": i.get("title") or i.get("label"),
            "detail": i.get("detail") or "",
            "device": i.get("device_name") or i.get("device_id") or "",
        }
        for i in items[: _limit(args)]
        if isinstance(i, dict)
    ]


def tool_list_devices(args, fetch):
    return [
        {
            "name": d.get("name"),
            "os": d.get("os"),
            "online": d.get("online", False),
            "last_seen": d.get("last_seen"),
            "group": d.get("group", ""),
            "tags": d.get("tags", []),
            "ip": d.get("ip", ""),
            "pkg_manager": ((d.get("sysinfo") or {}).get("packages") or {}).get("manager", ""),
            "agentless": d.get("agentless", False),
        }
        for d in _devices(fetch)[:MAX_ROWS]
    ]


def tool_get_device(args, fetch):
    dev = _find(fetch, _text(args, "name", required=True))
    return _scrub(dev)


def tool_get_services(args, fetch):
    dev = _find(fetch, _text(args, "name", required=True))
    data = fetch(_host_path(dev, "services")) or {}
    rows = [
        {
            k: s.get(k)
            for k in ("unit", "active", "sub", "since", "restarts")
            if s.get(k) is not None
        }
        for s in (data.get("services") or [])
        if isinstance(s, dict)
    ]
    return {
        "device": dev.get("name"),
        "updated_at": data.get("updated_at"),
        "services": rows[:MAX_ROWS],
    }


def tool_get_containers(args, fetch):
    dev = _find(fetch, _text(args, "name", required=True))
    data = fetch(_host_path(dev, "containers")) or {}
    keep = (
        "name",
        "image",
        "tag",
        "status",
        "health",
        "restart_count",
        "runtime",
        "namespace",
        "uptime_seconds",
    )
    rows = [
        {k: c.get(k) for k in keep if c.get(k) not in (None, "")}
        for c in (data.get("items") or [])
        if isinstance(c, dict)
    ]
    return {
        "device": dev.get("name"),
        "reported_at": data.get("reported_at"),
        "is_stale": data.get("is_stale"),
        "summary": data.get("summary"),
        "containers": rows[:MAX_ROWS],
    }


def tool_get_cves(args, fetch):
    name = _text(args, "name")
    if name:
        dev = _find(fetch, name)
        data = fetch(_host_path(dev, "cves"))
        return {
            "device": dev.get("name"),
            "findings": ((data or {}).get("findings") or [])[:MAX_ROWS],
        }
    data = fetch("/api/cve/findings")
    return data or {"findings": []}


def tool_get_patches(args, fetch):
    name = _text(args, "name")
    data = fetch("/api/patch-report") or {}
    rows = [d for d in (data.get("devices") or []) if isinstance(d, dict)]
    keep = (
        "name",
        "pkg_manager",
        "upgradable",
        "security_updates",
        "patch_status",
        "reboot_required",
        "online",
    )
    if name:
        dev = _find(fetch, name)
        row = next((d for d in rows if d.get("device_id") == _id_of(dev)), None) or {}
        return {"device": dev.get("name"), **{k: row.get(k) for k in keep if k != "name"}}
    return {
        "fleet": [{k: d.get(k) for k in keep} for d in rows if (d.get("upgradable") or 0) > 0][
            :MAX_ROWS
        ],
        "summary": data.get("summary"),
    }


def tool_get_journal(args, fetch):
    dev = _find(fetch, _text(args, "name", required=True))
    journal = (fetch(_host_path(dev, "sysinfo")) or {}).get("journal") or []
    lines = [
        _mask_text(j, 400) if isinstance(j, str) else _scrub(j)
        for j in journal[-_limit(args, 30) :]
    ]
    return {"device": dev.get("name"), "journal": lines}


def tool_get_drift(args, fetch):
    name = _text(args, "name")
    if not name:
        return _scrub(fetch("/api/drift") or {"devices": []})
    return _scrub(fetch(_host_path(_find(fetch, name), "drift")))


def tool_get_recent_commands(args, fetch):
    dev = _find(fetch, _text(args, "name", required=True))
    outputs = (fetch(_host_path(dev, "output")) or {}).get("outputs") or []
    # a command and what it printed can hold anything: trimmed so one dump cannot drown the answer, and masked where it names a credential
    cmds = [
        {
            "ts": c.get("ts"),
            "cmd": _mask_text(c.get("cmd"), 500),
            "rc": c.get("rc"),
            "output": _mask_text(c.get("output"), 2000),
        }
        for c in outputs[-_limit(args, 10) :]
        if isinstance(c, dict)
    ]
    return {"device": dev.get("name"), "commands": cmds}


def tool_get_runbook(args, fetch):
    return _scrub(fetch(_host_path(_find(fetch, _text(args, "name", required=True)), "runbook")))


def tool_get_tls(args, fetch):
    return _scrub(fetch("/api/tls/targets") or {"targets": []})


def tool_get_snmp_data(args, fetch):
    name = _text(args, "name") or _text(args, "device")
    if not name:
        raise ToolError("'name' argument required")
    devs = _devices(fetch)
    target = next((d for d in devs if d.get("name") == name or d.get("id") == name), None)
    if target is None:
        hits = [d for d in devs if name in str(d.get("name") or "")]
        target = hits[0] if len(hits) == 1 else None
    if target is None:
        return {"ok": False, "error": 'No host matching "%s"' % name}
    return _scrub(fetch(_host_path(target, "snmp")))


def tool_search_devices(args, fetch):
    query = _text(args, "query", required=True).lower()
    matched = []
    for d in _devices(fetch):
        haystack = " ".join(
            [
                str(d.get("name") or ""),
                str(d.get("os") or ""),
                str(d.get("group") or ""),
                str(d.get("ip") or ""),
                str(d.get("hostname") or ""),
                " ".join(str(t) for t in (d.get("tags") or [])),
                str(d.get("notes") or "")[:500],
            ]
        ).lower()
        if query in haystack:
            matched.append(
                {
                    "name": d.get("name"),
                    "os": d.get("os"),
                    "online": d.get("online", False),
                    "group": d.get("group", ""),
                    "tags": d.get("tags", []),
                    "ip": d.get("ip", ""),
                }
            )
    return {"query": query, "matches": matched[:MAX_ROWS], "count": len(matched)}


def tool_search_fleet(args, fetch):
    query = _text(args, "query", required=True)
    top_n = args.get("top_n")
    body = {"query": query}
    if isinstance(top_n, int) and not isinstance(top_n, bool):
        body["top_n"] = (
            top_n  # the server keeps it between 1 and 30 and uses its own default for anything else
        )
    data = fetch("/api/ai/rag/search", "POST", body) or {}
    return {
        "query": query,
        "semantic": data.get("semantic", False),
        "results": (data.get("results") or [])[:30],
    }


TOOLS = {
    n: dict(SPECS[n], run=f)
    for n, f in (
        ("list_alerts", tool_list_alerts),
        ("get_attention", tool_get_attention),
        ("list_devices", tool_list_devices),
        ("get_device", tool_get_device),
        ("get_services", tool_get_services),
        ("get_containers", tool_get_containers),
        ("get_cves", tool_get_cves),
        ("get_patches", tool_get_patches),
        ("get_journal", tool_get_journal),
        ("get_drift", tool_get_drift),
        ("get_recent_commands", tool_get_recent_commands),
        ("get_runbook", tool_get_runbook),
        ("get_tls", tool_get_tls),
        ("get_snmp_data", tool_get_snmp_data),
        ("search_devices", tool_search_devices),
        ("search_fleet", tool_search_fleet),
    )
}


# ── the protocol ─────────────────────────────────────────────────────────────────────────────────────────────────────────
def _error(msg_id, code, message):
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def _fit(obj):
    """A result as JSON text that fits the budget. A list that is too long is cut from the end and says so, and the text stays valid JSON."""
    text = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str)
    if len(text) <= MAX_RESULT_CHARS:
        return text
    key = None
    rows = obj if isinstance(obj, list) else None
    if rows is None and isinstance(obj, dict):
        key = max(
            (k for k, v in obj.items() if isinstance(v, list)),
            key=lambda k: len(obj[k]),
            default=None,
        )
        rows = obj[key] if key else None
    if rows:
        keep = len(rows)
        while keep > 1:
            keep //= 2
            cut = list(rows[:keep])
            if key is None:
                wrapped = {"truncated": True, "shown": keep, "total": len(rows), "items": cut}
            else:
                wrapped = dict(
                    obj, **{key: cut, "truncated": True, "shown": keep, "total": len(rows)}
                )
            text = json.dumps(wrapped, ensure_ascii=False, separators=(",", ":"), default=str)
            if len(text) <= MAX_RESULT_CHARS:
                return text
    return json.dumps(
        {
            "truncated": True,
            "note": "The answer is larger than the %d characters one tool result may carry; ask for one host."
            % MAX_RESULT_CHARS,
        }
    )


def _call(params, fetch):
    name = params.get("name")
    if not isinstance(name, str) or name not in TOOLS:
        return None, (
            INVALID_PARAMS,
            "Unknown tool: %s" % (name[:60] if isinstance(name, str) else ""),
        )
    args = params.get("arguments")
    if args is None:
        args = {}
    if not isinstance(args, dict):
        return None, (INVALID_PARAMS, "'arguments' must be an object")
    try:
        text = _fit(TOOLS[name]["run"](args, fetch))
        is_error = False
    except ToolError as e:
        text, is_error = str(e), True
    except FetchError as e:
        text, is_error = "HTTP %s: %s" % (e.status, e.message), True
    except (
        Exception
    ) as e:  # a tool that meets a reply it did not expect is a failed call, not an HTTP 500 for the model's host to puzzle over
        text, is_error = "The tool could not read the answer (%s)." % type(e).__name__, True
    return {"content": [{"type": "text", "text": text}], "isError": is_error}, None


def tool_listing():
    return [
        {
            "name": n,
            "description": t["description"],
            "inputSchema": t["inputSchema"],
            "annotations": {
                "title": n.replace("_", " "),
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False,
            },
        }
        for n, t in TOOLS.items()
    ]


def negotiate(requested):
    return requested if requested in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0]


def handle(message, fetch, server_version):
    """One JSON-RPC message in, (http_status, answer) out. A notification gets (202, None). A request gets (200, result-or-error)."""
    if not isinstance(message, dict):
        return 400, _error(None, INVALID_REQUEST, "Send one JSON-RPC request object, not a batch")
    msg_id = message.get("id")
    is_request = "id" in message
    if message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
        return 400, _error(
            msg_id if isinstance(msg_id, (str, int)) and not isinstance(msg_id, bool) else None,
            INVALID_REQUEST,
            "Not a JSON-RPC 2.0 request",
        )
    if not is_request:
        return 202, None
    if isinstance(msg_id, bool) or not isinstance(msg_id, (str, int)):
        return 400, _error(None, INVALID_REQUEST, "The id must be a string or an integer")
    method = message["method"]
    params = message.get("params")
    if params is None:
        params = {}
    if not isinstance(params, dict):
        return 200, _error(msg_id, INVALID_PARAMS, "'params' must be an object")
    if method == "initialize":
        return 200, {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": negotiate(params.get("protocolVersion")),
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": server_version},
                "instructions": "Read-only access to this RemotePower fleet, with the permissions of the token that is calling. Start with list_alerts or get_attention.",
            },
        }
    if method == "ping":
        return 200, {"jsonrpc": "2.0", "id": msg_id, "result": {}}
    if method == "tools/list":
        return 200, {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": tool_listing()}}
    if method == "tools/call":
        result, bad = _call(params, fetch)
        if bad:
            return 200, _error(msg_id, bad[0], bad[1])
        return 200, {"jsonrpc": "2.0", "id": msg_id, "result": result}
    return 200, _error(msg_id, METHOD_NOT_FOUND, "Method not found: %s" % method[:60])

#!/usr/bin/env python3
"""
RemotePower MCP server — v2.2.0

Implements the Model Context Protocol (Anthropic, Nov 2024; Linux
Foundation stewardship 2025) so AI tools like Claude Desktop, Cursor,
VS Code Copilot, and any other MCP-compatible host can query a
RemotePower fleet through natural language.

Architecture:
    +---------------+         +----------------------+
    | AI host (this |         |   RemotePower server |
    | runs on op's  |◀───────▶|   (HTTPS / API)      |
    | laptop)       |  HTTPS  |                      |
    +---------------+         +----------------------+
            ▲
            │ stdio JSON-RPC 2.0
            ▼
    +-----------------+
    | This MCP server |
    | (stdlib Python) |
    +-----------------+

This script runs on the *operator's* laptop, not on the RemotePower
server. The AI host spawns it as a subprocess and exchanges JSON-RPC
2.0 frames over stdin/stdout. The MCP server in turn makes HTTPS
calls to RemotePower's REST API on behalf of the AI.

Configuration:
    Set environment variables before spawning:
        REMOTEPOWER_URL    — base URL, e.g. https://remote.example.com
        REMOTEPOWER_TOKEN  — API token (create one in Settings → API keys)
        REMOTEPOWER_VERIFY_SSL — set to '0' for self-signed certs (default 1)

Example Claude Desktop config (claude_desktop_config.json):

    {
      "mcpServers": {
        "remotepower": {
          "command": "python3",
          "args": ["/path/to/remotepower-mcp.py"],
          "env": {
            "REMOTEPOWER_URL":   "https://remote.tvipper.com",
            "REMOTEPOWER_TOKEN": "rpk_..."
          }
        }
      }
    }

Security note: this server exposes READ-ONLY tools. Mutating
operations (run command, run script, edit device) are deliberately
NOT exposed via MCP in v1 of this server. An LLM running with
unconstrained shell access to a fleet is a real risk; the AI host's
own consent/approval flow does not substitute for a server-side
allow-list, which we'll add in a future release before unlocking
write surfaces.

Pure stdlib — no pip dependencies. Tested against Python 3.10+.

Protocol version: 2024-11-05 (the version Anthropic stabilised
shortly after the spec was first published; widely supported by
hosts as of mid-2026).
"""

import json
import os
import ssl
import sys
import traceback
import urllib.error
import urllib.parse
import urllib.request


# ── Configuration ──────────────────────────────────────────────────────────

SERVER_NAME    = "remotepower"
SERVER_VERSION = "2.2.0"
PROTOCOL_VER   = "2024-11-05"

API_URL    = (os.environ.get("REMOTEPOWER_URL") or "").rstrip("/")
API_TOKEN  = os.environ.get("REMOTEPOWER_TOKEN") or ""
VERIFY_SSL = os.environ.get("REMOTEPOWER_VERIFY_SSL", "1") != "0"

HTTP_TIMEOUT = 30  # seconds


def _ssl_ctx():
    """Build SSL context. Honours REMOTEPOWER_VERIFY_SSL=0 for self-signed
    deployments — operator's responsibility to know what they're doing."""
    if VERIFY_SSL:
        return ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _api(method, path, body=None):
    """Make an authenticated request to RemotePower's REST API. Returns
    the parsed JSON response. Raises on HTTP error.

    All API calls go through this single point so token handling, SSL
    config, and error mapping stay consistent."""
    if not API_URL:
        raise RuntimeError(
            "REMOTEPOWER_URL not set. Add it to the MCP server's env config."
        )
    url = f"{API_URL}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if API_TOKEN:
        req.add_header("Authorization", f"Bearer {API_TOKEN}")
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=_ssl_ctx()) as resp:
            raw = resp.read()
            if not raw:
                return None
            return json.loads(raw)
    except urllib.error.HTTPError as e:
        body_text = ""
        try:
            body_text = e.read().decode("utf-8", errors="replace")[:500]
        except Exception:
            pass
        raise RuntimeError(f"HTTP {e.code} {e.reason}: {body_text}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Network error reaching {API_URL}: {e.reason}")


def _find_device_by_name(name):
    """Resolve a device name (or partial name match) to a device dict.
    Tools accept names for friendliness — operators say 'pmg01' not
    'WKFB3BZphiohNVVT'."""
    data = _api("GET", "/api/devices")
    devs = data if isinstance(data, list) else (data or {}).get("devices") or []
    if not devs:
        return None
    name_low = name.lower()
    # Exact match first
    for d in devs:
        if (d.get("name") or "").lower() == name_low:
            return d
    # Prefix match
    matches = [d for d in devs if (d.get("name") or "").lower().startswith(name_low)]
    if len(matches) == 1:
        return matches[0]
    # Substring match if still no unique result
    matches = [d for d in devs if name_low in (d.get("name") or "").lower()]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        names = ", ".join(d.get("name", "?") for d in matches[:5])
        raise RuntimeError(
            f"Device name '{name}' is ambiguous. Matches: {names}. "
            f"Provide a more specific name."
        )
    return None


# ── Tool implementations ───────────────────────────────────────────────────
#
# Each tool returns a Python object that will be JSON-serialised into the
# MCP tool result. Tools should be read-only and side-effect-free — the
# whole point of this v1 is that an over-eager LLM can't break the fleet.

def tool_list_devices(args):
    """List all devices in the fleet with current status."""
    data = _api("GET", "/api/devices")
    devs = data if isinstance(data, list) else (data or {}).get("devices") or []
    # Trim to fields a model actually wants to see — full payload includes
    # ~30 fields per device and would blow context budget.
    return [{
        "name":         d.get("name"),
        "os":           d.get("os"),
        "online":       d.get("online", False),
        "last_seen":    d.get("last_seen"),
        "group":        d.get("group", ""),
        "tags":         d.get("tags", []),
        "ip":           d.get("ip", ""),
        "pkg_manager":  d.get("pkg_manager", ""),
        "agentless":    d.get("agentless", False),
    } for d in devs]


def tool_get_device(args):
    """Get detailed information about a device by name."""
    name = (args or {}).get("name") or ""
    if not name:
        raise RuntimeError("'name' argument required")
    dev = _find_device_by_name(name)
    if not dev:
        raise RuntimeError(f"No device named '{name}'")
    # Return everything except the auth token
    return {k: v for k, v in dev.items() if k != "token"}


def tool_get_journal(args):
    """Recent journal entries for a device."""
    name = (args or {}).get("name") or ""
    dev = _find_device_by_name(name) if name else None
    if not dev:
        raise RuntimeError(f"No device named '{name}'")
    dev_id = dev.get("id") or dev.get("device_id")
    data = _api("GET", f"/api/devices/{urllib.parse.quote(dev_id)}/sysinfo")
    journal = (data or {}).get("journal") or []
    limit = int((args or {}).get("limit", 30))
    return {"device": dev.get("name"), "journal": journal[-limit:]}


def tool_get_services(args):
    """Watched systemd unit states for a device."""
    name = (args or {}).get("name") or ""
    dev = _find_device_by_name(name) if name else None
    if not dev:
        raise RuntimeError(f"No device named '{name}'")
    services = dev.get("services_watched_state") or dev.get("services") or []
    return {"device": dev.get("name"), "services": services}


def tool_get_containers(args):
    """Container state (Docker/Podman) for a device."""
    name = (args or {}).get("name") or ""
    dev = _find_device_by_name(name) if name else None
    if not dev:
        raise RuntimeError(f"No device named '{name}'")
    return {"device": dev.get("name"), "containers": dev.get("containers") or []}


def tool_get_cves(args):
    """CVE findings for a device, or fleet-wide."""
    name = (args or {}).get("name") or ""
    if name:
        dev = _find_device_by_name(name)
        if not dev:
            raise RuntimeError(f"No device named '{name}'")
        dev_id = dev.get("id") or dev.get("device_id")
        data = _api("GET", f"/api/devices/{urllib.parse.quote(dev_id)}/cves")
        findings = (data or {}).get("findings") or []
        return {"device": dev.get("name"), "findings": findings}
    # Fleet-wide
    data = _api("GET", "/api/cve/findings")
    return data or {"findings": []}


def tool_get_drift(args):
    """Configuration drift state for a device or fleet-wide overview."""
    name = (args or {}).get("name") or ""
    if not name:
        data = _api("GET", "/api/drift")
        return data or {"devices": []}
    dev = _find_device_by_name(name)
    if not dev:
        raise RuntimeError(f"No device named '{name}'")
    dev_id = dev.get("id") or dev.get("device_id")
    return _api("GET", f"/api/devices/{urllib.parse.quote(dev_id)}/drift")


def tool_get_recent_commands(args):
    """Recent commands run on a device, with output and return codes."""
    name = (args or {}).get("name") or ""
    dev = _find_device_by_name(name) if name else None
    if not dev:
        raise RuntimeError(f"No device named '{name}'")
    dev_id = dev.get("id") or dev.get("device_id")
    data = _api("GET", f"/api/devices/{urllib.parse.quote(dev_id)}/output")
    outputs = (data or {}).get("outputs") or []
    limit = int((args or {}).get("limit", 10))
    # Trim large outputs so a model isn't drowned by a single 2 MB log dump
    cmds = []
    for c in outputs[-limit:]:
        cmds.append({
            "ts":     c.get("ts"),
            "cmd":    c.get("cmd"),
            "rc":     c.get("rc"),
            "output": (c.get("output") or "")[:2000],
        })
    return {"device": dev.get("name"), "commands": cmds}


def tool_get_runbook(args):
    """AI-generated runbook for a device, if one exists."""
    name = (args or {}).get("name") or ""
    dev = _find_device_by_name(name) if name else None
    if not dev:
        raise RuntimeError(f"No device named '{name}'")
    dev_id = dev.get("id") or dev.get("device_id")
    return _api("GET", f"/api/devices/{urllib.parse.quote(dev_id)}/runbook")


def tool_get_patches(args):
    """Pending OS package updates across the fleet (or one device)."""
    name = (args or {}).get("name") or ""
    if name:
        dev = _find_device_by_name(name)
        if not dev:
            raise RuntimeError(f"No device named '{name}'")
        return {
            "device":       dev.get("name"),
            "patch_status": dev.get("patch_status"),
            "upgradable":   dev.get("upgradable"),
        }
    # Fleet summary
    data = _api("GET", "/api/devices")
    devs = data if isinstance(data, list) else (data or {}).get("devices") or []
    return {
        "fleet": [{
            "name":         d.get("name"),
            "upgradable":   d.get("upgradable"),
            "patch_status": d.get("patch_status"),
        } for d in devs if (d.get("upgradable") or 0) > 0]
    }


def tool_get_tls(args):
    """TLS / DNS expiry watchlist status. No arguments — returns the whole list."""
    data = _api("GET", "/api/tls/targets")
    return data or {"targets": []}


def tool_search_devices(args):
    """Search devices by free-text query (matches name, os, group, tags, notes)."""
    query = ((args or {}).get("query") or "").lower().strip()
    if not query:
        raise RuntimeError("'query' argument required")
    data = _api("GET", "/api/devices")
    devs = data if isinstance(data, list) else (data or {}).get("devices") or []
    matched = []
    for d in devs:
        haystack = " ".join([
            d.get("name") or "", d.get("os") or "", d.get("group") or "",
            d.get("ip") or "", d.get("hostname") or "",
            " ".join(d.get("tags") or []),
            (d.get("notes") or "")[:500],
        ]).lower()
        if query in haystack:
            matched.append({
                "name":    d.get("name"),
                "os":      d.get("os"),
                "online":  d.get("online", False),
                "group":   d.get("group", ""),
                "tags":    d.get("tags", []),
                "ip":      d.get("ip", ""),
            })
    return {"query": query, "matches": matched, "count": len(matched)}


# ── Tool registry ──────────────────────────────────────────────────────────

TOOLS = {
    "list_devices": {
        "description":
            "List all devices in the RemotePower fleet with current online "
            "status, OS, group, tags, IP. Always start here to know which "
            "devices exist before querying specific ones.",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": tool_list_devices,
    },
    "get_device": {
        "description":
            "Get full detail for one device by name. Includes sysinfo "
            "(uptime, OS, kernel, memory, disks), watched services, "
            "containers, recent journal, tags, group, notes. Use after "
            "list_devices to drill into a specific host.",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string",
                                     "description": "Device name (prefix or substring OK)"}},
            "required": ["name"],
        },
        "handler": tool_get_device,
    },
    "get_journal": {
        "description":
            "Recent systemd journal entries from a device. Useful for "
            "debugging service issues or recent errors. The agent ships "
            "the most recent journal lines on each heartbeat.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name":  {"type": "string", "description": "Device name"},
                "limit": {"type": "integer", "description": "Max lines (default 30)"},
            },
            "required": ["name"],
        },
        "handler": tool_get_journal,
    },
    "get_services": {
        "description":
            "List of systemd units being watched on a device, with their "
            "current active/inactive/failed state. Watched units are "
            "configured per-device in the dashboard.",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
        "handler": tool_get_services,
    },
    "get_containers": {
        "description":
            "Docker / Podman container state for a device. Returns running "
            "containers with image, state, status, ports.",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
        "handler": tool_get_containers,
    },
    "get_cves": {
        "description":
            "CVE findings for a device, or fleet-wide if no name is given. "
            "Returns vulnerability id, severity, affected package, fixed "
            "version, and summary. Backed by OSV.dev. Use to identify "
            "outstanding security issues.",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string",
                                     "description": "Device name; omit for fleet-wide"}},
        },
        "handler": tool_get_cves,
    },
    "get_drift": {
        "description":
            "Configuration drift state for a device, or fleet-wide overview "
            "if no name is given. Returns the watched config files whose "
            "current hash diverges from the stored baseline (potential "
            "unauthorised changes).",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string",
                                     "description": "Device name; omit for fleet overview"}},
        },
        "handler": tool_get_drift,
    },
    "get_recent_commands": {
        "description":
            "Recent commands run on a device, with output and exit code. "
            "Useful for 'what was done on this host recently' questions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name":  {"type": "string"},
                "limit": {"type": "integer", "description": "Max entries (default 10)"},
            },
            "required": ["name"],
        },
        "handler": tool_get_recent_commands,
    },
    "get_runbook": {
        "description":
            "AI-generated operations runbook for a device (v2.1.7+). "
            "Describes purpose, services, exposure, recent activity, "
            "risks, operating notes. Returns exists=false if no runbook "
            "has been generated for this device yet.",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
        "handler": tool_get_runbook,
    },
    "get_patches": {
        "description":
            "Pending OS package updates. With a device name returns that "
            "device's patch status and pending count; without a name "
            "returns all devices with pending updates.",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
        },
        "handler": tool_get_patches,
    },
    "get_tls": {
        "description":
            "TLS / DNS expiry watchlist status. Lists hosts being probed "
            "for certificate expiry and DNS resolution, with current "
            "days-until-expiry and warning/critical state.",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": tool_get_tls,
    },
    "search_devices": {
        "description":
            "Search devices by free-text query. Matches name, OS, group, "
            "tags, hostname, IP, and operator notes. Returns a compact "
            "list of matches.",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
        "handler": tool_search_devices,
    },
}


# ── JSON-RPC handlers ──────────────────────────────────────────────────────

def handle_initialize(params):
    """The MCP handshake. Returns server info and the protocol version we
    speak. The host then sends `notifications/initialized` (no response
    expected from us)."""
    return {
        "protocolVersion": PROTOCOL_VER,
        "capabilities":    {"tools": {"listChanged": False}},
        "serverInfo":      {"name": SERVER_NAME, "version": SERVER_VERSION},
    }


def handle_tools_list(params):
    """Advertise our tools and their input schemas."""
    return {
        "tools": [{
            "name":        name,
            "description": t["description"],
            "inputSchema": t["inputSchema"],
        } for name, t in TOOLS.items()],
    }


def handle_tools_call(params):
    """Dispatch a tool call to the relevant handler."""
    name = params.get("name") or ""
    args = params.get("arguments") or {}
    tool = TOOLS.get(name)
    if not tool:
        return {
            "content": [{"type": "text", "text": f"Unknown tool: {name}"}],
            "isError": True,
        }
    try:
        result = tool["handler"](args)
    except Exception as e:
        return {
            "content": [{"type": "text", "text": f"Tool error: {e}"}],
            "isError": True,
        }
    # MCP requires tool results to be wrapped in a content array. Text
    # content is the universal currency; some hosts also support image
    # or resource blocks, but read-only fleet queries are always text.
    return {
        "content": [{
            "type": "text",
            "text": json.dumps(result, default=str, indent=2),
        }],
    }


HANDLERS = {
    "initialize":   handle_initialize,
    "tools/list":   handle_tools_list,
    "tools/call":   handle_tools_call,
}


# ── Main loop ──────────────────────────────────────────────────────────────

def main():
    """Read JSON-RPC frames from stdin, dispatch, write responses to
    stdout. Notifications (no `id`) get no response, per spec."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception as e:
            # Per JSON-RPC: send a parse error response if we can't read
            # what they sent. We don't know the id, so use null.
            sys.stdout.write(json.dumps({
                "jsonrpc": "2.0", "id": None,
                "error": {"code": -32700, "message": f"Parse error: {e}"},
            }) + "\n")
            sys.stdout.flush()
            continue

        method  = msg.get("method")
        params  = msg.get("params") or {}
        msg_id  = msg.get("id")
        is_notification = (msg_id is None)

        # Notifications get no response (per JSON-RPC 2.0)
        if is_notification:
            # The 'notifications/initialized' that hosts send after the
            # handshake lands here; nothing to do.
            continue

        if method not in HANDLERS:
            response = {
                "jsonrpc": "2.0", "id": msg_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }
        else:
            try:
                result = HANDLERS[method](params)
                response = {"jsonrpc": "2.0", "id": msg_id, "result": result}
            except Exception as e:
                # Log the traceback to stderr for the operator; return a
                # generic internal-error to the host.
                sys.stderr.write(traceback.format_exc())
                response = {
                    "jsonrpc": "2.0", "id": msg_id,
                    "error": {"code": -32603,
                              "message": f"Internal error: {e}"},
                }

        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()

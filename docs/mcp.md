# MCP server — natural-language fleet queries

*(v2.2.0)*

RemotePower ships an [MCP](https://modelcontextprotocol.io)
(Model Context Protocol) server in `mcp/remotepower-mcp.py`. Once
connected to an MCP-compatible AI host (Claude Desktop, Cursor,
VS Code Copilot, etc.), you can query the fleet in plain English:

> *Which of my devices have pending security updates?*
>
> *Show me the journal for pmg01 from the last hour.*
>
> *Is the SSH config on tviweb01 still at its baseline?*
>
> *Which devices haven't been patched in 30 days?*

The AI host invokes the appropriate RemotePower API endpoints,
formats the result, and answers naturally. No dashboard click
required.

## The architecture

```
+---------------+ +----------------------+
| AI host (this | | RemotePower server |
| runs on op's |◀───────▶| (HTTPS / API) |
| laptop) | HTTPS | |
+---------------+ +----------------------+
 ▲
 │ stdio JSON-RPC 2.0
 ▼
+-----------------+
| This MCP server |
| (stdlib Python) |
+-----------------+
```

**The MCP server runs on the operator's laptop, not on the
RemotePower server.** The AI host (e.g. Claude Desktop) spawns it
as a subprocess and exchanges JSON-RPC 2.0 frames over
stdin/stdout. The MCP server makes HTTPS calls to RemotePower's
REST API on behalf of the AI, using a token you provision.

This split is important for the security story:

- Credentials live on **your** laptop, in your AI host's config
 (a plain JSON file).
- They never travel to the AI provider — only the tool *results*
 do.
- The MCP server speaks to your RemotePower instance over HTTPS
 with normal token auth — no special privileges.

## Setup

### 1. Generate an API token

In the dashboard: **Settings → API keys → Generate new key**.
Give it a name like `mcp-laptop`, role `viewer` (more than enough
for the read-only tools), and copy the resulting `rpk_...` value.
It's shown once and not recoverable; if you lose it, generate a
new one.

### 2. Copy the MCP server to your laptop

```bash
scp remotepower-server:/var/www/remotepower/mcp/remotepower-mcp.py \
 ~/remotepower-mcp.py
chmod +x ~/remotepower-mcp.py
```

It's a single self-contained Python file (~470 lines, stdlib
only). Python 3.10+.

### 3. Configure your AI host

#### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`
on macOS, or `%APPDATA%\Claude\claude_desktop_config.json` on
Windows (create the file if it doesn't exist):

```json
{
 "mcpServers": {
 "remotepower": {
 "command": "python3",
 "args": ["/Users/you/remotepower-mcp.py"],
 "env": {
 "REMOTEPOWER_URL": "https://remote.tvipper.com",
 "REMOTEPOWER_TOKEN": "rpk_xxxxxxxxxxxxxxxxxxxx"
 }
 }
 }
}
```

Restart Claude Desktop. The hammer-and-wrench tool icon at the
bottom of the chat input will show **remotepower** with all
tools enabled.

#### Cursor / VS Code Copilot / others

Same JSON shape — refer to your host's MCP server documentation
for where the config file lives. Every MCP-compliant host
supports the same `command + args + env` setup.

### 4. Verify

Open a chat and ask: *"What devices are in my RemotePower fleet?"*

The host should show a "tool use" indicator (Claude Desktop calls
it ) and return a list of your devices.

## Available tools

All read-only in v1. Each tool takes a small JSON arguments object;
the AI host generates these from your natural-language question.

| Tool | What it returns |
|---|---|
| `list_devices` | Every device with status, OS, group, tags, IP |
| `get_device` | Full detail for one device (name match) |
| `get_journal` | Recent systemd journal entries |
| `get_services` | Watched systemd unit states |
| `get_containers` | Docker / Podman container state |
| `get_cves` | CVE findings (per-device or fleet-wide) |
| `get_drift` | Configuration drift (per-device or fleet-wide) |
| `get_recent_commands` | Recent commands run on a device |
| `get_runbook` | AI-generated device runbook (v2.1.7+) |
| `get_patches` | Pending OS package updates |
| `get_tls` | TLS / DNS expiry watchlist |
| `search_devices` | Free-text search by name / OS / group / tags / notes |
| `search_fleet` | RAG retrieval across all fleet state, CMDB, runbooks, history, and docs — one call for broad/cross-host questions ("worst CVEs in the fleet", "which hosts need a reboot"). Returns ranked, cited chunks incl. fleet-wide rollups. (v3.4.0) |

> `search_fleet` is the bridge between MCP and the RAG knowledge index: where
> the granular `get_*` tools each fetch one host's structured record,
> `search_fleet` answers a natural-language question in one shot and lets the
> fleet rollups (worst CVEs, pending reboots, drift, cert expiry) do the
> aggregation the model would otherwise have to do by hand. Requires the RAG
> index to be enabled (Settings → AI → Knowledge index).

### Device-name resolution

The tools accept friendly names. The MCP server does:

1. **Exact match** — `pmg01` matches a device named `pmg01`.
2. **Prefix match** — `tviweb01` matches `tviweb01.tvipper.com`
 if there's only one device starting with it.
3. **Substring match** — `web` matches `tviweb01.tvipper.com`
 if there's only one device containing it.
4. **Ambiguous** — `web` raises an error if it matches multiple
 devices; the model is told to ask for more specifics.

You can also pass full names. The matching is conservative — it
only auto-disambiguates when there's exactly one match.

## What's not there (deliberately)

**No write tools.** No `run_command`, no `run_script`, no
`reboot_device`, no `edit_device`. An LLM running with
unconstrained shell access to a fleet is a real risk. The
test suite explicitly asserts that no write-shaped tool names
slipped in. The host's own consent flow ("Allow this tool to
run? [y/n]") does **not** substitute for a server-side allow-list.

Write tools will land in a future release with:

- A server-side allow-list of safe operations (`run_script
 <library-id>` rather than `run_command <arbitrary>`).
- A separate per-MCP-token role (`mcp` instead of `viewer` /
 `admin`).
- An optional "require confirmation" flag per device, defaulting
 to on for prod devices.
- Audit log entries that record both the AI host name and the
 natural-language prompt that led to the action.

Until those are in place, write tools are not a feature this
server should have. The whole point of v1 is that the worst
outcome of an LLM getting confused is "it gave you a slightly
wrong fleet summary," not "it shut down a prod box."

## Security model

| Concern | Mitigation |
|---|---|
| Token leakage | Stored in your AI host's config file, never sent to the LLM provider. Read-only role. Generate per laptop; revoke any time. |
| Prompt injection | Tool *outputs* contain operator-controlled text (device names, notes, journal entries). A malicious operator note could try to "instruct" the AI to do something silly. But since all tools are read-only and bounded, the worst outcome is a confused summary. |
| Self-signed TLS | Set `REMOTEPOWER_VERIFY_SSL=0` in the MCP env if you must, but prefer to install your CA's root cert in the laptop's trust store. |
| Data sensitivity | Same as the AI privacy redaction toggles in Settings → AI assistant: when in doubt, run a local model (Ollama) as the AI host. |

## Troubleshooting

### "Tool failed: REMOTEPOWER_URL not set"

Your AI host's config doesn't have the env vars set, or they're
empty strings. Re-check the JSON config and restart the host.

### "Network error: getaddrinfo failed"

The MCP server can't reach the RemotePower URL from your laptop.
Common causes: VPN not connected, wrong URL scheme (use `https://`
not `http://`), corporate proxy.

### "HTTP 401" on every tool

The API token was rejected. Either it's wrong, or it was revoked,
or its expiry passed. Generate a new one.

### "HTTP 403: read-only role" on a tool that *should* work

The MCP server should only be calling read-only endpoints with a
`viewer` token. If you're seeing this, it's a bug in the tool —
file an issue with the tool name + endpoint.

### Tools show up in Claude Desktop but every call hangs

The MCP server is being spawned but stdin/stdout aren't flowing.
Try running it manually to verify it starts:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
 | REMOTEPOWER_URL=https://remote.tvipper.com \
 REMOTEPOWER_TOKEN=rpk_test \
 python3 ~/remotepower-mcp.py
```

You should get a JSON response on stdout within a second. If you
don't, check Python is installed and on `PATH`.

### Claude Desktop says "MCP server quit unexpectedly"

Check `~/Library/Logs/Claude/mcp*.log` (macOS) or the equivalent
location on your OS. Most often it's a Python syntax error from
an edit, or an unhandled exception in a tool. Stack traces from
the server go to stderr, which Claude Desktop captures into those
logs.

## A note on the protocol

MCP version pinned: **`2024-11-05`**.

This is the version Anthropic stabilised shortly after first
publishing the spec, and the one that's widely supported by hosts
as of mid-2026. The protocol has continued to evolve — there's a
2026 roadmap covering stateless HTTP transport, async tasks,
enterprise auth — but those features aren't yet universal in
hosts, and the 2024-11-05 surface is sufficient for read-only
fleet queries. We'll bump when there's a concrete reason.

## See also

- [Model Context Protocol spec](https://modelcontextprotocol.io)
- [MCP Linux Foundation governance](https://modelcontextprotocol.io/community/governance)
- [Claude Desktop MCP docs](https://docs.claude.com/claude/desktop)
- [ai.md](ai.md) — the existing in-RemotePower AI assistant
 (different feature: dashboard buttons + AI page chat).

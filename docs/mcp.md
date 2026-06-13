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
> *Is the SSH config on web01 still at its baseline?*
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

It's a single self-contained Python file (~880 lines, stdlib
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
 "REMOTEPOWER_URL": "https://remotepower.example.com",
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

**18 tools — 14 read, 4 guarded write.** Each takes a small JSON arguments
object; the AI host generates these from your natural-language question. The
read tools are always available; the four write tools only work when an admin
has added them to the per-token allow-list (see *Guarded write tools* below).

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
| `get_snmp_data` | SNMP data collected from a network appliance / device |
| `search_devices` | Free-text search by name / OS / group / tags / notes |
| `search_fleet` | RAG retrieval across all fleet state, CMDB, runbooks, history, and docs — one call for broad/cross-host questions ("worst CVEs in the fleet", "which hosts need a reboot"). Returns ranked, cited chunks incl. fleet-wide rollups. (v3.4.0) |

> `search_fleet` is the bridge between MCP and the RAG knowledge index: where
> the granular `get_*` tools each fetch one host's structured record,
> `search_fleet` answers a natural-language question in one shot and lets the
> fleet rollups (worst CVEs, pending reboots, drift, cert expiry) do the
> aggregation the model would otherwise have to do by hand. Requires the RAG
> index to be enabled (Settings → AI → Knowledge index).

The four **write tools** are off unless explicitly allow-listed for the token:

| Write tool | What it does |
|---|---|
| `reboot_device` | Queue a reboot for one device |
| `run_saved_script` | Run a script **from the saved library** (by id) — never an arbitrary command |
| `force_package_scan` | Ask an agent to push its installed-package list now |
| `force_acme_rescan` | Re-check a host's ACME / TLS / DNS expiry now |

Every write call is gated by the per-token allow-list and the token's role
scope, and is recorded in the audit log alongside the AI host name.

### Device-name resolution

The tools accept friendly names. The MCP server does:

1. **Exact match** — `pmg01` matches a device named `pmg01`.
2. **Prefix match** — `web01` matches `web01.example.com`
 if there's only one device starting with it.
3. **Substring match** — `web` matches `web01.example.com`
 if there's only one device containing it.
4. **Ambiguous** — `web` raises an error if it matches multiple
 devices; the model is told to ask for more specifics.

You can also pass full names. The matching is conservative — it
only auto-disambiguates when there's exactly one match.

## Guarded write tools — and what's still deliberately absent

The four write tools (`reboot_device`, `run_saved_script`,
`force_package_scan`, `force_acme_rescan`) ship with exactly the guard rails an
LLM acting on a fleet needs:

- **A server-side allow-list.** A token can call a write tool only if an admin
 has added it to that token's allow-list — the host's own "Allow this tool to
 run? [y/n]" consent prompt is **not** the control; the server is.
- **Pre-saved actions only.** `run_saved_script` runs a script from the library
 by id — there is deliberately **no `run_command`** and **no `edit_device`**, so
 the model can never assemble an arbitrary shell command.
- **Per-token roles + scope.** Write calls are checked against the token's role
 permissions and device scope, just like any other action.
- **Audit logging.** Every write call is recorded with the AI host name.

So the worst outcome of a confused model is bounded: it can reboot a host or run
a vetted library script you already trust — never run an arbitrary command or
shut a box down off-script. If you want a purely read-only assistant, simply
leave the write tools off the token's allow-list (the default).

## Security model

| Concern | Mitigation |
|---|---|
| Token leakage | Stored in your AI host's config file, never sent to the LLM provider. Scoped to its role + write allow-list; generate per laptop and revoke any time. |
| Prompt injection | Tool *outputs* contain operator-controlled text (device names, notes, journal entries). A malicious note could try to "instruct" the AI. Read tools are bounded (worst case: a confused summary); write tools are limited to the allow-listed, pre-saved actions above, so an injected instruction still can't run an arbitrary command. Leave write tools off the allow-list for a read-only token. |
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
 | REMOTEPOWER_URL=https://remotepower.example.com \
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

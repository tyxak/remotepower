"""
RemotePower AI context module — v2.1.7

Level-1 RAG: hand-curated context that gets prepended to AI requests
so the model knows what RemotePower is and what the fleet looks like
without having to ask. No embeddings, no vector store — just two
functions that build short text blocks from existing JSON state.

The decision rationale lives in the v2.1.7 release notes; the short
version is: for ~5000 lines of docs and ~10 devices, dumping a
2-KB always-true preamble is cheaper, simpler, and just as effective
as a real RAG pipeline. If we hit specific question types that this
fails on, we can add Level-2 keyword retrieval over docs/ next, and
Level-3 embeddings only if that still falls short.

Two functions used by api.handle_ai_chat:

  build_project_context()                  → ~1 KB, static text
  build_fleet_context(devices, options)    → ~50-200 bytes per device

Both return plain text suitable for prepending to the system prompt.
The combined preamble is wrapped in <system_context>...</system_context>
tags so the model can tell where the preamble ends and the operator's
actual task begins.
"""

import json
import time


# ── Project context ────────────────────────────────────────────────────────
#
# Hand-curated. Updated when the architecture changes — not on every
# release. Worth keeping concise: this text travels with every AI
# request, so each unnecessary word costs latency and (on cloud
# providers) money.

_PROJECT_CONTEXT = """\
You are an operations assistant inside RemotePower, a self-hosted
Linux fleet management tool. Key facts about the environment you
are operating in:

- The operator runs a small fleet of Linux servers and workstations.
  Agents on each host poll the server every 60 seconds (configurable
  per device). Commands are queued and execute on the next heartbeat,
  with output returning on the heartbeat after that.
- Storage is flat JSON files, not a database. Configuration lives in
  config.json; device state in devices.json; webhook events in
  webhook_log.json; scheduled jobs in schedule.json.
- The server is pure-stdlib Python under nginx + fcgiwrap. No pip
  dependencies are allowed in suggestions unless explicitly asked.
- There is a script library (multi-line bash, stored in scripts.json)
  that goes through bash -n syntax checking and a dangerous-pattern
  detector before save. Scripts can be batch-run across devices,
  scheduled (one-shot or cron), and version-tracked.
- There is a CMDB built in (asset metadata, encrypted credentials
  vault with AES-GCM + PBKDF2, Markdown docs per asset, network
  topology map, agentless device records).
- CVE scanning is OSV.dev-backed; results have severity, fixed
  version, references, and a per-CVE ignore list per device.
- TLS / DNS expiry monitor runs server-side; alerts via webhook.

When the operator asks for diagnostics, prefer concrete shell
commands (systemctl, journalctl, ss, find, awk) over abstract advice.
When suggesting scripts, target bash with set -euo pipefail. Avoid
inventing tools or paths you don't have evidence for — if you don't
know whether something is installed, say "check whether X is
installed, then ..." rather than assuming.

The operator can see the dashboard, the device's recent commands,
the device's journal, watched services, containers, CVE findings,
patch status, and metrics. Don't ask them to look at things they
likely already see; cut to what to do."""


def build_project_context():
    """Return the static project context block."""
    return _PROJECT_CONTEXT


# ── Fleet context ──────────────────────────────────────────────────────────

def _is_online(d, now, ttl):
    """Compute online status canonically from the device dict, matching
    the same formula used by handle_devices_list. The `online` field
    is *not* persisted in devices.json — it's a derived value. Reading
    `d.get('online')` directly returns None for every device, which
    incorrectly reports the entire fleet as offline (the original
    v2.1.7 bug where the AI told users their online host was offline).

    Agentless devices have no heartbeat; their state is operator-set
    via `manual_status` (defaulting to True/online).
    """
    if d.get('agentless'):
        return bool(d.get('manual_status', True))
    last_seen = d.get('last_seen') or 0
    if not last_seen:
        return False
    return (now - last_seen) < ttl


def _device_one_liner(d, now=None, ttl=300):
    """Compact one-line summary of a single device.

    Format: "name (os, pkg, status, group=...): notes"
    Aim for <= ~120 chars per device so 50 devices = ~6 KB max.
    """
    if now is None:
        now = int(time.time())

    parts = []
    name = d.get('name', d.get('id', '?'))
    parts.append(name)

    bits = []
    os_str = d.get('os', '')
    if os_str:
        # Trim long OS strings ("Debian GNU/Linux 13 (trixie)" → "Debian 13")
        # Just take first two whitespace-separated tokens for compactness.
        os_short = ' '.join(os_str.split()[:2])
        bits.append(os_short)
    pkg = d.get('pkg_manager') or d.get('package_manager')
    if pkg and pkg != 'unknown':
        bits.append(pkg)
    if _is_online(d, now, ttl):
        bits.append('online')
    else:
        bits.append('offline')
    if d.get('group'):
        bits.append(f"group={d['group']}")
    if d.get('agentless'):
        bits.append('agentless')

    if bits:
        parts.append('(' + ', '.join(bits) + ')')

    # Notes / role from the device's notes field (operator-curated)
    notes = (d.get('notes') or '').strip()
    if notes:
        # First line only, truncated. Notes can be long; we just want
        # the operator's one-liner about the role.
        first_line = notes.split('\n', 1)[0][:80]
        parts.append(': ' + first_line)

    # Tags as a short suffix
    tags = d.get('tags') or []
    if tags:
        parts.append('[' + ','.join(tags[:5]) + ']')

    return ' '.join(parts)


def build_fleet_context(devices, max_devices=80, now=None, ttl=300):
    """Return a multi-line fleet summary suitable for inclusion in
    the system prompt.

    devices: list of device dicts (typically load(DEVICES_FILE).values()
             or .get('devices', []) depending on caller).
    max_devices: hard cap to bound token cost. At 80 devices and
                 ~120 chars/device that's ~10 KB; for the typical
                 5-15 device deployment this is a non-issue.
    now, ttl:    used for the canonical online-status calculation —
                 caller passes get_online_ttl() so we match the rest
                 of the codebase. Defaults to current time + 300s
                 (DEFAULT_ONLINE_TTL) when not supplied.

    Returns empty string if devices is empty — caller decides whether
    to include the resulting block.
    """
    if not devices:
        return ''
    if now is None:
        now = int(time.time())

    # Sort: online first, then by name, so the model sees live state
    # at the top of the list (cheaper to attend to under length pressure)
    devs = sorted(
        devices,
        key=lambda d: (
            0 if _is_online(d, now, ttl) else 1,
            d.get('name', d.get('id', '')).lower(),
        ),
    )

    lines = [f"Fleet snapshot ({len(devs)} devices):"]
    for d in devs[:max_devices]:
        lines.append('- ' + _device_one_liner(d, now=now, ttl=ttl))
    if len(devs) > max_devices:
        lines.append(f"... ({len(devs) - max_devices} more devices omitted)")

    return '\n'.join(lines)


# ── Retrieved context (v3.4.0: Level-2/3 RAG) ───────────────────────────────

def build_retrieved_context(chunks):
    """Render retrieved corpus chunks into a prompt block.

    `chunks` is the list of doc dicts returned by rag_index.InfraIndex.
    search() — each has id, title, ts, text. We prefix every chunk with a
    bracketed citation header `[id · date]` and instruct the model to cite
    those ids, so an operator can trace any claim back to the indexed
    source (a device facet, a runbook section, a CMDB doc). Returns '' for
    an empty list so the caller can decide whether to include the block.
    """
    if not chunks:
        return ''
    lines = [
        "The following snippets were retrieved from this deployment's own "
        "infrastructure index (device state, docs, CMDB, history) because "
        "they appear relevant to the operator's request. Treat them as "
        "ground truth about THIS fleet. When you rely on one, cite it by "
        "its bracketed id, e.g. [live/web01#cves]. If they don't cover the "
        "question, say so rather than guessing.",
        "",
    ]
    for c in chunks:
        ts = c.get('ts') or 0
        when = time.strftime('%Y-%m-%d', time.gmtime(ts)) if ts else 'static'
        title = c.get('title') or c.get('id')
        lines.append(f"[{c.get('id')} · {when}] {title}")
        lines.append(c.get('text', '').strip())
        lines.append('')
    return '\n'.join(lines).rstrip()


# ── Composition ────────────────────────────────────────────────────────────

def build_combined_system_prompt(base_prompt, *, devices=None,
                                  include_project=True, include_fleet=True,
                                  retrieved=None, now=None, ttl=300):
    """Stitch base_prompt with optional project + fleet context.

    base_prompt is the per-action system prompt (e.g. SYSTEM_PROMPTS[
    'investigate_device']). We prepend the context blocks if requested
    and wrap them in <system_context> tags so the model sees a clear
    separation between background information and the actual task
    framing.

    `now` and `ttl` are passed through to build_fleet_context so the
    online-status calculation matches the rest of the codebase. The
    caller (handle_ai_chat) should pass get_online_ttl() as ttl so
    the AI sees the same online/offline status the dashboard does.

    Returns the combined prompt string (or just base_prompt if neither
    context block is requested or both are empty).
    """
    blocks = []
    if include_project:
        blocks.append(build_project_context())
    if include_fleet and devices is not None:
        fleet = build_fleet_context(devices, now=now, ttl=ttl)
        if fleet:
            blocks.append(fleet)

    # Retrieved context lives in its own tagged block, after the always-true
    # <system_context>: it's per-query and authoritative-about-this-fleet,
    # so the model should weight it differently from the static preamble.
    retrieved_block = build_retrieved_context(retrieved) if retrieved else ''

    if not blocks and not retrieved_block:
        return base_prompt

    out = ''
    if blocks:
        out += ('<system_context>\n' + '\n\n'.join(blocks)
                + '\n</system_context>\n\n')
    if retrieved_block:
        out += ('<retrieved_context>\n' + retrieved_block
                + '\n</retrieved_context>\n\n')
    return out + (base_prompt or '')

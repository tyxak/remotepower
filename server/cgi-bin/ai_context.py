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

import re
import time

import checks
import posture_signals


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
  per host). Commands are queued and execute on the next heartbeat,
  with output returning on the heartbeat after that.
- Storage is flat JSON files, not a database. Configuration lives in
  config.json; host state in devices.json; webhook events in
  webhook_log.json; scheduled jobs in schedule.json.
- The server runs under nginx + gunicorn/Flask (server/cgi-bin/wsgi.py).
  Feature code stays near-stdlib Python — flask/gunicorn/psycopg are the
  only required third-party packages; don't suggest new pip
  dependencies for a feature unless explicitly asked.
- There is a script library (multi-line bash, stored in scripts.json)
  that goes through bash -n syntax checking and a dangerous-pattern
  detector before save. Scripts can be batch-run across hosts,
  scheduled (one-shot or cron), and version-tracked.
- There is a CMDB built in (asset metadata, encrypted credentials
  vault with AES-GCM + PBKDF2, Markdown docs per asset, network
  topology map, agentless host records).
- CVE scanning is OSV.dev-backed; results have severity, fixed
  version, references, and a per-CVE ignore list per host.
- TLS / DNS expiry monitor runs server-side; alerts via webhook.

When the operator asks for diagnostics, prefer concrete shell
commands (systemctl, journalctl, ss, find, awk) over abstract advice.
When suggesting scripts, target bash with set -euo pipefail. Avoid
inventing tools or paths you don't have evidence for — if you don't
know whether something is installed, say "check whether X is
installed, then ..." rather than assuming.

The operator can see the dashboard, the host's recent commands,
the host's journal, watched services, containers, CVE findings,
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


# v7.0.0: how many notable conditions one host may contribute to the preamble.
# A host with fifteen problems is still one host; without a cap a single very
# sick machine could crowd out the other seventy-nine.
_MAX_FLAGS_PER_DEVICE = 4


# 7.5.0: how urgent a condition is, so the cap of four keeps the worst of them. Before, the order was the order the conditions were
# written in, and a host with a degraded pool, a full disk and a pending reboot lost the pool to the cap if it was the fifth.
_FAULT, _POSTURE, _SHORT, _HOUSE = 0, 1, 2, 3

# The window the Checks row and the risk score use for "an out-of-memory kill happened lately" (api.OOM_RECENT_WINDOW_SECONDS).
_OOM_RECENT_SECONDS = 86400
# The defaults of the alerts the same conditions raise: inodes (Checks) and battery wear (battery_health_low_pct).
_INODE_LIMIT = 95
_BATTERY_WORN_PCT = 50


def _is_num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _device_flags(d, now=None):
    """Short notable-condition flags for the fleet preamble, or [].

    The ALWAYS-ON context was pure INVENTORY — name, OS, package manager,
    online, group, notes, tags — with no health signal on any host. So an
    advisor asked "what should I fix first" started from a list of machines and
    nothing about their state, and only saw posture when RAG retrieval happened
    to fire. The fleet rollup carried offline and reboot counts and nothing else.

    Emitted only when NOTABLE, which is what keeps this affordable: a healthy
    fleet adds zero characters, and a fleet in trouble spends its tokens on
    exactly the hosts worth attending to. Thresholds match the ones the product
    already alerts on, so the model never sees a "problem" the operator's own
    pages call fine.

    7.5.0: eight more conditions the agents report and the product already judges elsewhere (a pool that is not healthy, swap,
    inodes, an out-of-memory kill in the last day, failed timers, interface errors, a worn battery), and the flags are ranked
    before the cap: a failing component first, then security posture, then a resource running short, then housekeeping.
    Pool states, interface names and the like come from the host, so the text of a flag is built from the numbers and from a few
    fixed words, never from a string the host sent.
    """
    si = d.get('sysinfo') or {}
    now = time.time() if now is None else now
    ranked = []

    def _flag(rank, text):
        ranked.append((rank, text))

    def _pct(key, label, limit=90):
        v = si.get(key)
        if _is_num(v) and v >= limit:
            _flag(_SHORT, f'{label} {int(v)}%')

    _pct('cpu_percent', 'cpu')
    _pct('mem_percent', 'mem')
    _pct('swap_percent', 'swap')
    _pct('disk_percent', 'disk')
    _inodes = [m['inode_percent'] for m in (si.get('mounts') or [])
               if isinstance(m, dict) and not m.get('network') and _is_num(m.get('inode_percent'))
               and m['inode_percent'] >= _INODE_LIMIT]
    if _inodes:
        _flag(_SHORT, f'inodes {int(max(_inodes))}%')
    if si.get('reboot_required') is True:
        _flag(_HOUSE, 'reboot pending')
    # 7.4.9: updates the distro itself flags as security, which the digest did not carry although the Patch Report, the Advisory and
    # the alerts do. A count only; the model asks for names through the other context when it needs them.
    _sec = (si.get('packages') or {}).get('security_updates') if isinstance(si.get('packages'), dict) else None
    if isinstance(_sec, int) and not isinstance(_sec, bool) and _sec > 0:
        _flag(_POSTURE, f'{_sec} security update' + ('s' if _sec != 1 else '') + ' pending')
    units = si.get('failed_units') or []
    if units:
        _flag(_SHORT, f'{len(units)} failed unit' + ('s' if len(units) != 1 else ''))
    _timers = [t for t in (si.get('timers') or []) if isinstance(t, dict) and t.get('failed')]
    if _timers:
        _flag(_HOUSE, f'{len(_timers)} failed timer' + ('s' if len(_timers) != 1 else ''))
    if si.get('mount_issues'):
        _flag(_SHORT, 'mount issues')
    # 7.4.9: memory errors the hardware could not correct, and a gateway that does not answer: both raise an alert and a Checks row,
    # and neither reached the digest. The shapes are the agent's own ({ce, ue} and {reachable}); only an explicit state counts.
    _ecc = si.get('ecc')
    if isinstance(_ecc, dict) and isinstance(_ecc.get('ue'), int) and not isinstance(_ecc.get('ue'), bool) and _ecc['ue'] > 0:
        _flag(_FAULT, 'ECC uncorrectable errors')
    _gw = si.get('gateway')
    if isinstance(_gw, dict) and _gw.get('reachable') is False:
        _flag(_FAULT, 'gateway unreachable')
    # 7.5.0: a pool or array whose state is not one of the healthy words (the one rule the alert, the Storage page, the risk score and
    # the Checks row share), named by its first word when that is three to sixteen lower-case letters, else "unhealthy".
    _pools = [h for h in (si.get('storage_health') or [])
              if isinstance(h, dict) and isinstance(h.get('state'), str) and posture_signals.pool_unhealthy(h['state'])]
    if _pools:
        if len(_pools) == 1:
            _m = re.match(r'\s*([a-z]{3,16})\b', str(_pools[0].get('state') or '').lower())
            _flag(_FAULT, f"storage pool {_m.group(1) if _m else 'unhealthy'}")
        else:
            _flag(_FAULT, f'{len(_pools)} storage pools unhealthy')
    # 7.5.0: a battery worn below the line that raises battery_health_low (50%, the default of its setting).
    _wear = [b['health_pct'] for b in (si.get('battery') or [])
             if isinstance(b, dict) and _is_num(b.get('health_pct')) and b['health_pct'] < _BATTERY_WORN_PCT]
    if _wear:
        _flag(_SHORT, f'battery worn to {int(min(_wear))}%')
    # 7.5.0: an out-of-memory kill in the last day (the Checks row's window), and errors on an interface since the last report. Drops
    # are not counted: they rise with traffic on a healthy link (#37).
    _oom = si.get('last_oom_ts')
    if _is_num(_oom) and _oom > 0 and 0 <= now - _oom < _OOM_RECENT_SECONDS:
        _flag(_SHORT, 'out-of-memory kill in the last day')
    _nics = [n for n in (si.get('network_io') or []) if isinstance(n, dict) and checks.nic_breach(n, 1, 0)]
    if _nics:
        _flag(_HOUSE, f'errors on {len(_nics)} network interface' + ('s' if len(_nics) != 1 else ''))
    # v7.3.0: the three platforms and the tri-state, through the shared helper.
    # The old test was "backends exist and none is active", which read a Linux
    # host whose probes all failed as a host with no firewall, and knew nothing
    # of Windows or macOS.
    pf = checks.posture_flags(si)
    if pf['firewall_active'] is False:
        _flag(_POSTURE, 'firewall off')
    if pf['disk_encrypted'] is False:
        _flag(_POSTURE, 'disks unencrypted')
    ck = si.get('clock')
    if isinstance(ck, dict) and ck.get('synced') is False:
        _flag(_HOUSE, 'clock unsynced')
    if si.get('guard_quarantine'):
        _flag(_POSTURE, 'quarantined files')
    # An explicit "my metrics are limited" beats an empty percentage the model
    # would otherwise read as healthy.
    if si.get('psutil') is False:
        _flag(_HOUSE, 'limited metrics')
    # v7.1.0: conditions that live outside the device record (brute force, IP
    # intel), attached by the caller to a copy as `_extra_flags`. They go first:
    # being attacked right now outranks a full disk. 7.5.0: a caller may attach a (rank, text) pair instead of a bare string to
    # have its flag placed among the others (the hardware faults and the open ports do); a bare string still goes first.
    for f in d.get('_extra_flags') or []:
        if isinstance(f, (tuple, list)) and len(f) == 2 and isinstance(f[0], int) and not isinstance(f[0], bool) and f[1]:
            ranked.append((f[0], str(f[1])[:60]))
        elif f and not isinstance(f, (tuple, list)):
            ranked.append((-1, str(f)[:60]))
    out = [text for _rank, text in sorted(ranked, key=lambda f: f[0])]
    return out[:_MAX_FLAGS_PER_DEVICE]


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
    notes = str(d.get('notes') or '').strip()
    if notes:
        # First line only, truncated. Notes can be long; we just want
        # the operator's one-liner about the role.
        first_line = notes.split('\n', 1)[0][:80]
        parts.append(': ' + first_line)

    # Tags as a short suffix
    tags = d.get('tags') or []
    if tags:
        parts.append('[' + ','.join(tags[:5]) + ']')

    # v7.0.0: notable conditions last, so a length-pressured model still reads
    # the identity first and the problems are the thing nearest the next host.
    flags = _device_flags(d, now)
    if flags:
        parts.append('!! ' + '; '.join(flags))

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

    # v6.4.0: a compact fleet-health rollup line so the ALWAYS-ON preamble
    # carries health, not just inventory (the per-device one-liners are
    # health-blind, and RAG only fills this in when retrieval fires). Cheap —
    # computed from the devices already in hand.
    _offline = sum(1 for d in devs if not _is_online(d, now, ttl)
                   and not d.get('agentless') and d.get('monitored') is not False)
    _reboot = sum(1 for d in devs
                  if (d.get('sysinfo') or {}).get('reboot_required') is True)
    # v7.0.0: the rollup carried offline + reboot and nothing else, so a fleet
    # with a dozen hosts out of disk read as healthy at the top of the prompt.
    # Each of these is a count the product already alerts on.
    _flagged = sum(1 for d in devs if _device_flags(d, now))
    _units = sum(1 for d in devs
                 if ((d.get('sysinfo') or {}).get('failed_units') or []))
    _rollup = []
    if _offline:
        _rollup.append(f"{_offline} offline")
    if _reboot:
        _rollup.append(f"{_reboot} need reboot")
    if _units:
        _rollup.append(f"{_units} with failed units")
    if _flagged:
        _rollup.append(f"{_flagged} with notable conditions")
    head = f"Fleet snapshot ({len(devs)} devices"
    head += (', ' + ', '.join(_rollup)) if _rollup else ''
    head += '):'
    lines = [head]
    for d in devs[:max_devices]:
        lines.append('- ' + _device_one_liner(d, now=now, ttl=ttl))
    if len(devs) > max_devices:
        lines.append(f"... ({len(devs) - max_devices} more hosts omitted)")

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
        "infrastructure index (host state, docs, CMDB, history) because "
        "they appear relevant to the operator's request. Treat them as "
        "ground truth about THIS fleet. When you rely on one, cite it by "
        "its bracketed id, e.g. [live/web01#cves].",
        # The model was observed punting cross-fleet questions back to the
        # operator ("call the get_cves tool", "run jq ...") even when the
        # answer was sitting in the retrieved context. Answer from the data.
        "Answer directly from these snippets. Do NOT tell the operator to "
        "run an MCP tool, a `jq` filter, or a shell command to fetch data "
        "that is already provided here — read it out of the snippets and "
        "answer. Only if the snippets do not contain the answer, "
        "say so briefly (and then you may suggest how to obtain it).",
        "",
    ]
    for c in chunks:
        ts = c.get('ts') or 0
        when = time.strftime('%Y-%m-%d', time.gmtime(ts)) if ts else 'static'
        title = c.get('title') or c.get('id')
        lines.append(f"[{c.get('id')} · {when}] {title}")
        lines.append(str(c.get('text', '')).strip())
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

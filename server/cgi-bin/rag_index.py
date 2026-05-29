"""
RemotePower RAG index — v3.4.0

Level-2/3 RAG: retrieval over the operator's actual infrastructure.

The roadmap for this module was written into ai_context.py back at
v2.1.7: Level-1 was a hand-curated always-true preamble; Level-2 is
"keyword retrieval over docs/"; Level-3 is "embeddings only if that
still falls short". This module implements both Level-2 and Level-3
in one place, with Level-2 (lexical BM25) as the always-on base and
Level-3 (embeddings) as an optional rerank layer.

Design constraints that shaped every decision here:

  * Pure stdlib. The server runs under nginx + fcgiwrap with no pip
    deps allowed, so there is no faiss / chromadb / numpy. BM25 runs
    over a hand-built inverted index; cosine similarity is a plain
    Python dot product. At the scale this tool targets (~10 devices,
    a few dozen docs → low thousands of chunks) that is sub-millisecond
    for lexical and tens of milliseconds for a full cosine sweep.

  * Anthropic — the default provider — has no embeddings endpoint.
    So lexical retrieval MUST stand on its own; embeddings are layered
    in only when an embedding-capable provider (OpenAI / Ollama /
    LocalAI) is configured. When both signals are present we fuse them
    with Reciprocal Rank Fusion rather than trusting either alone.

  * This module is pure and side-effect free. It does NOT read the
    data-source JSON files, does NOT import ai_provider, and does NOT
    persist itself. The caller (api.py) owns all I/O: it loads the
    source files, hands already-shaped data to the corpus builders,
    calls ai_provider.embed for vectors, and persists the index dict
    via its own load()/save() helpers (which give us locking + .bak).
    That keeps this module trivially unit-testable with plain dicts.

Public surface used by api.py:

  tokenize(text)                          → list[str]
  chunk_markdown(text, ...)               → list[(heading_path, chunk)]
  make_doc(...)                           → one normalized doc dict
  build_docs_corpus(files)                → list[doc]
  build_runbooks_corpus(runbooks)         → list[doc]
  build_cmdb_corpus(cmdb_store)           → list[doc]   (vault excluded)
  build_live_state_corpus(devices, ...)   → list[doc]
  build_history_corpus(...)               → list[doc]
  InfraIndex                              → build / search / persist
"""

import re
import math
import hashlib


# ── Tokenisation ─────────────────────────────────────────────────────────────
#
# A naive `\w+` tokenizer destroys exactly the tokens an operator
# searches for: CVE-2024-3094 becomes "cve 2024 3094", 192.168.1.10
# becomes four numbers, nginx-1.25.3 loses its version. So we extract
# "rich" tokens that keep internal . - _ / : + and, for any rich token
# that carries those separators, ALSO emit its alphanumeric sub-pieces.
# That way "CVE-2024-3094" matches a query for "cve" or "3094" or the
# exact id, and "nginx/1.25.3" matches "nginx" and "1.25.3".

_RICH_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/:+\-]*[A-Za-z0-9]|[A-Za-z0-9]")
_SUBSPLIT_RE = re.compile(r"[._/:+\-]+")

# A deliberately small stopword set. We only strip these from the
# *simple* alphanumeric tokens — rich/technical tokens are always kept,
# because "in", "on", "up" can be substrings of real signal but the
# bare words carry none. Keeping the list short avoids dropping words
# that matter in an ops context ("down", "fail", "error" stay).
_STOPWORDS = frozenset("""
a an and are as at be by for from has have in into is it its of on
or that the their then there these this to was were will with
""".split())


def tokenize(text):
    """Lowercase, technical-token-preserving tokenizer.

    Returns a list (not a set) so the caller can count term frequency.
    Rich tokens are kept whole AND split into sub-pieces for recall.
    Stopwords are dropped only from bare alphanumeric tokens.
    """
    if not text:
        return []
    out = []
    for m in _RICH_TOKEN_RE.finditer(text.lower()):
        tok = m.group(0)
        has_sep = bool(_SUBSPLIT_RE.search(tok))
        if has_sep:
            # Keep the whole technical token (exact-match recall) ...
            if len(tok) >= 2:
                out.append(tok)
            # ... and its pieces (partial recall).
            for piece in _SUBSPLIT_RE.split(tok):
                if len(piece) >= 2 and piece not in _STOPWORDS:
                    out.append(piece)
        else:
            if len(tok) >= 2 and tok not in _STOPWORDS:
                out.append(tok)
    return out


# ── Markdown chunking ────────────────────────────────────────────────────────

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")


def _slug(text, fallback='section'):
    s = re.sub(r"[^a-z0-9]+", "-", (text or '').lower()).strip("-")
    return s[:60] or fallback


def chunk_markdown(text, max_chars=1200):
    """Split Markdown into (heading_path, chunk_text) pairs.

    Splits on ATX headings (#..######). A section longer than max_chars
    is further split on blank-line paragraph boundaries so no single
    chunk blows the per-chunk budget. Heading path is the breadcrumb of
    enclosing headings ("Install > Debian"), which becomes useful chunk
    title context for retrieval and citations.

    Returns [] for empty input. A document with no headings yields one
    or more chunks under the empty heading path "".
    """
    if not text or not text.strip():
        return []
    lines = text.splitlines()
    # Build sections: each is (heading_path, body_lines)
    sections = []
    stack = []          # list of (level, title)
    cur_body = []

    def _flush():
        if cur_body and any(l.strip() for l in cur_body):
            path = ' > '.join(t for _, t in stack)
            sections.append((path, '\n'.join(cur_body).strip()))

    for line in lines:
        hm = _HEADING_RE.match(line)
        if hm:
            _flush()
            cur_body = []
            level = len(hm.group(1))
            title = hm.group(2).strip()
            while stack and stack[-1][0] >= level:
                stack.pop()
            stack.append((level, title))
            # Heading text itself is useful retrieval signal — seed the body
            cur_body.append(title)
        else:
            cur_body.append(line)
    _flush()

    if not sections:
        sections = [('', text.strip())]

    # Enforce the per-chunk size budget by paragraph splitting.
    out = []
    for path, body in sections:
        if len(body) <= max_chars:
            out.append((path, body))
            continue
        para = []
        size = 0
        for block in re.split(r"\n\s*\n", body):
            block = block.strip()
            if not block:
                continue
            if size + len(block) > max_chars and para:
                out.append((path, '\n\n'.join(para)))
                para, size = [], 0
            para.append(block)
            size += len(block) + 2
        if para:
            out.append((path, '\n\n'.join(para)))
    return out


# ── Document model ───────────────────────────────────────────────────────────

def _hash(text):
    return hashlib.sha256((text or '').encode('utf-8', 'replace')).hexdigest()[:16]


def make_doc(doc_id, source, dtype, text, title=None, device=None, ts=0, meta=None):
    """Build one normalized corpus document.

    doc_id   stable id, also the citation key (e.g. "live/web01#cves")
    source   one of: docs | live_state | cmdb | history
    dtype    finer type for UI grouping (e.g. "device_cves", "doc_md")
    text     the searchable/embeddable body
    title    human label for citations
    device   device id/name if device-scoped, else None
    ts       freshness epoch seconds (0 = unknown / static)
    """
    text = (text or '').strip()
    return {
        'id':     doc_id,
        'source': source,
        'type':   dtype,
        'device': device,
        'title':  title or doc_id,
        'text':   text,
        'ts':     int(ts or 0),
        'hash':   _hash(text),
        'meta':   meta or {},
    }


# ── Corpus builders ──────────────────────────────────────────────────────────
#
# Each builder takes already-loaded, in-memory data (never a file path)
# and returns a list of docs. api.py owns the file reads and the shape
# knowledge for the live stores; these builders stay defensive about
# missing/odd shapes so a single malformed record can't sink a reindex.

def build_docs_corpus(files):
    """files: iterable of (name, markdown_text) — product docs + manuals."""
    docs = []
    for name, text in (files or []):
        for path, chunk in chunk_markdown(text):
            sec = _slug(path) if path else 'body'
            title = f"{name}" + (f" — {path}" if path else "")
            docs.append(make_doc(
                f"docs/{name}#{sec}", 'docs', 'doc_md', chunk,
                title=title, meta={'doc': name, 'heading': path}))
    return docs


def build_runbooks_corpus(runbooks):
    """runbooks: dict device_id -> {'content': markdown, 'generated_at': ts}."""
    docs = []
    if not isinstance(runbooks, dict):
        return docs
    for dev_id, rec in runbooks.items():
        if not isinstance(rec, dict):
            continue
        content = rec.get('content') or rec.get('markdown') or rec.get('text') or ''
        ts = rec.get('generated_at') or rec.get('updated_at') or 0
        for path, chunk in chunk_markdown(content):
            sec = _slug(path) if path else 'body'
            docs.append(make_doc(
                f"runbook/{dev_id}#{sec}", 'docs', 'runbook', chunk,
                title=f"Runbook: {dev_id}" + (f" — {path}" if path else ""),
                device=dev_id, ts=ts, meta={'heading': path}))
    return docs


# Field names that must NEVER be indexed. The credentials vault is
# AES-GCM encrypted at rest (cmdb_vault.py); even though what lands in
# cmdb.json is ciphertext, we exclude the whole subtree by name so a
# future plaintext field or a decrypted cache can't silently leak into
# the prompt (and, worse, into a cloud embedding request).
_CMDB_SECRET_KEYS = frozenset({'credentials', 'secrets', 'vault', 'password',
                               'passwords', 'fields'})


def build_cmdb_corpus(cmdb_store):
    """cmdb_store: dict device_id -> record. Indexes asset metadata and
    per-asset Markdown docs. The credentials vault is excluded by key."""
    docs = []
    if not isinstance(cmdb_store, dict):
        return docs
    for dev_id, rec in cmdb_store.items():
        if not isinstance(rec, dict):
            continue
        # Asset metadata: everything except secret subtrees and the docs
        # list (handled separately below).
        meta_lines = []
        for k, v in rec.items():
            if k in _CMDB_SECRET_KEYS or k == 'docs' or k == 'documentation':
                continue
            if v in (None, '', [], {}):
                continue
            if isinstance(v, (list, tuple)):
                v = ', '.join(str(x) for x in v)
            elif isinstance(v, dict):
                v = ', '.join(f"{kk}={vv}" for kk, vv in v.items()
                              if kk not in _CMDB_SECRET_KEYS)
            meta_lines.append(f"{k}: {v}")
        if meta_lines:
            docs.append(make_doc(
                f"cmdb/{dev_id}#meta", 'cmdb', 'cmdb_asset',
                f"CMDB asset {dev_id}\n" + '\n'.join(meta_lines),
                title=f"CMDB: {dev_id}", device=dev_id,
                ts=rec.get('updated_at') or 0))
        # Per-asset Markdown docs.
        for d in (rec.get('docs') or []):
            if not isinstance(d, dict):
                continue
            body = d.get('body') or ''
            did = d.get('id') or _slug(d.get('title', ''))
            for path, chunk in chunk_markdown(body):
                sec = _slug(path) if path else 'body'
                title = d.get('title') or 'doc'
                docs.append(make_doc(
                    f"cmdb/{dev_id}/doc/{did}#{sec}", 'cmdb', 'cmdb_doc', chunk,
                    title=f"CMDB doc ({dev_id}): {title}", device=dev_id,
                    ts=d.get('updated_at') or 0, meta={'heading': path}))
    return docs


def _format_facet(data, max_items=40):
    """Render an arbitrary live-state value into compact, readable lines.

    Retrieval and embedding quality both suffer from raw JSON, so we
    flatten lists of dicts into 'k=v, k=v' lines and dicts into 'k: v'.
    Bounded by max_items so a 500-container host can't bloat one chunk.
    """
    if data is None:
        return ''
    if isinstance(data, str):
        return data.strip()
    if isinstance(data, (int, float, bool)):
        return str(data)
    lines = []
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, (list, dict)):
                v = _format_facet(v, max_items)
                lines.append(f"{k}:\n{v}")
            else:
                lines.append(f"{k}: {v}")
    elif isinstance(data, (list, tuple)):
        for item in data[:max_items]:
            if isinstance(item, dict):
                lines.append(', '.join(f"{k}={v}" for k, v in item.items()
                                       if not isinstance(v, (list, dict))))
            else:
                lines.append(str(item))
        if len(data) > max_items:
            lines.append(f"... ({len(data) - max_items} more)")
    return '\n'.join(l for l in lines if l)


def build_live_state_corpus(devices, facets=None, now=0):
    """Build per-(device, facet) chunks of current fleet state.

    devices : iterable of device dicts (from devices.json values).
    facets  : optional dict device_id -> {facet_name -> data} for state
              that lives outside the device record (cves, patches,
              containers, tls, snmp). Whatever the caller supplies gets
              its own chunk; missing facets are simply skipped.
    """
    docs = []
    facets = facets or {}
    # Fleet-wide aggregates, collected during the per-device pass and emitted
    # as rollup chunks afterwards so cross-fleet questions ("which hosts need
    # a reboot / have pending updates / have drifted?") have a single chunk to
    # retrieve instead of relying on the model to fan out over every device.
    reboot_hosts = []
    patch_hosts = []
    drift_hosts = []
    for dev in (devices or []):
        if not isinstance(dev, dict):
            continue
        dev_id = dev.get('id') or dev.get('name')
        if not dev_id:
            continue
        name = dev.get('name', dev_id)
        ts = dev.get('last_seen') or now or 0

        # Summary chunk from the device record + sysinfo. We deliberately
        # index only *stable* fields here — os, kernel, platform, group,
        # tags, notes. Volatile telemetry (uptime, load, cpu_percent,
        # memory) is excluded: it churns the embedding cache on every
        # heartbeat for no retrieval value (a bare current load number is
        # noise, and live metrics are better answered from the dashboard
        # than from a stale index). Disk usage gets its own hardware chunk.
        si = dev.get('sysinfo') or {}
        summary = [f"Device {name} (id {dev_id})"]
        # Network identity — the operator routinely asks "what IP / hostname
        # does X have". These are stable enough to embed (an IP changes far
        # less often than load/cpu) and are exactly what a who/where question
        # needs. NOTE: at chat time ai_provider.chat still redacts IPs/
        # hostnames per the AI privacy toggles, so the model only sees them
        # when 'send_ips' / 'send_hostnames' are enabled; the Test-retrieval
        # box (no provider) always shows them.
        for k in ('hostname', 'fqdn', 'ip', 'host', 'mac'):
            v = dev.get(k)
            if v:
                summary.append(f"{k}: {v}")
        for k in ('os', 'os_pretty', 'group'):
            if dev.get(k):
                summary.append(f"{k}: {dev[k]}")
        for k in ('kernel', 'platform', 'os_pretty'):
            if si.get(k):
                summary.append(f"{k}: {si[k]}")
        if dev.get('tags'):
            summary.append("tags: " + ', '.join(map(str, dev['tags'])))
        if (dev.get('notes') or '').strip():
            summary.append("notes: " + dev['notes'].strip())
        docs.append(make_doc(
            f"live/{dev_id}#summary", 'live_state', 'device_summary',
            '\n'.join(summary), title=f"{name} — summary", device=dev_id, ts=ts))

        # Disks / hardware from sysinfo.
        if si.get('disks'):
            docs.append(make_doc(
                f"live/{dev_id}#hardware", 'live_state', 'device_hardware',
                f"{name} disks / hardware:\n" + _format_facet(si.get('disks')),
                title=f"{name} — hardware", device=dev_id, ts=ts))

        # Listening ports from sysinfo. The agent already collects these
        # (sysinfo.listening_ports); indexing them answers "what ports are
        # listening on X" from real data instead of the model suggesting
        # `ss`/`netstat`. Ports are stable enough to embed (a service's
        # listen set rarely changes between heartbeats). We do NOT index
        # top_processes — those are as volatile as load/cpu (see summary).
        if si.get('listening_ports'):
            docs.append(make_doc(
                f"live/{dev_id}#ports", 'live_state', 'device_ports',
                f"{name} listening ports (open TCP/UDP sockets):\n"
                + _format_facet(si.get('listening_ports')),
                title=f"{name} — listening ports", device=dev_id, ts=ts))

        # Resources / specs — stable hardware + capacity facts the operator
        # asks about ("how much memory/disk/cpu does X have", "how long has
        # X been up"). Totals are stable; we keep current free/percent out of
        # the embedded text (volatile, see the summary note).
        res = []
        for label, key in (('cpu', 'cpu'), ('cpu cores', 'cores'),
                           ('cpu cores', 'cpu_count'),
                           ('total memory (MB)', 'mem_total_mb'),
                           ('total disk (GB)', 'disk_total_gb'),
                           ('uptime (seconds)', 'uptime_seconds'),
                           ('boot time', 'boot_time'),
                           ('last boot', 'last_boot')):
            v = si.get(key)
            if v not in (None, '', 0):
                res.append(f"{label}: {v}")
        if res:
            docs.append(make_doc(
                f"live/{dev_id}#resources", 'live_state', 'device_resources',
                f"{name} resources / hardware specs:\n" + '\n'.join(res),
                title=f"{name} — resources", device=dev_id, ts=ts))

        # Patch / reboot status. `upgradable` is a pending-update count on the
        # device record; reboot_required comes from sysinfo. Both answer
        # high-value operational questions and feed the fleet rollups below.
        upgradable = dev.get('upgradable')
        reboot_required = bool(si.get('reboot_required'))
        patch_lines = []
        if isinstance(upgradable, int):
            patch_lines.append(f"pending package updates: {upgradable}")
            if upgradable > 0:
                patch_hosts.append((name, upgradable))
        if dev.get('patch_status'):
            patch_lines.append(f"patch status: {dev['patch_status']}")
        if (dev.get('sysinfo') or {}).get('packages', {}).get('manager'):
            patch_lines.append(f"package manager: {si['packages']['manager']}")
        if reboot_required:
            patch_lines.append("reboot required: yes"
                               + (f" ({si.get('reboot_reason')})"
                                  if si.get('reboot_reason') else ""))
            reboot_hosts.append(name)
        if patch_lines:
            docs.append(make_doc(
                f"live/{dev_id}#patches", 'live_state', 'device_patches',
                f"{name} patch & reboot status:\n" + '\n'.join(patch_lines),
                title=f"{name} — patches", device=dev_id, ts=ts))

        # Configuration drift — files that differ from their captured baseline.
        drift = dev.get('drift_state') or {}
        drifted = [f for f, st in drift.items()
                   if isinstance(st, dict) and st.get('status') == 'drifted'
                   and not st.get('ignored')]
        if drifted:
            drift_hosts.append((name, len(drifted)))
            docs.append(make_doc(
                f"live/{dev_id}#drift", 'live_state', 'device_drift',
                f"{name} config drift — config files that have drifted / "
                f"changed from their captured baseline:\n"
                + '\n'.join(f"- {f}" for f in drifted[:50]),
                title=f"{name} — config drift", device=dev_id, ts=ts))

        # Inline device facets that live on the record itself.
        inline = {
            'services': dev.get('services_watched_state') or dev.get('services'),
            'journal':  (dev.get('journal') or [])[-30:] or None,
        }
        # Caller-supplied external facets win / extend.
        ext = facets.get(dev_id) or {}
        for fname, fdata in list(inline.items()) + list(ext.items()):
            if not fdata:
                continue
            body = _format_facet(fdata)
            if not body.strip():
                continue
            docs.append(make_doc(
                f"live/{dev_id}#{fname}", 'live_state', f'device_{fname}',
                f"{name} {fname}:\n{body}",
                title=f"{name} — {fname}", device=dev_id, ts=ts))

    # Fleet-wide CVE rollup. Cross-fleet aggregate questions ("what are the
    # worst CVEs in the fleet?") have no single device to focus on, so the
    # per-device #cves chunks don't surface well and the model ends up
    # punting to the get_cves tool. A single rollup chunk of the worst
    # (critical + high) CVEs across every host gives the model authoritative
    # data to answer from directly. Built from the caller-supplied `cves`
    # facets so the shape knowledge stays in one place.
    worst = []
    for dev_id, f in (facets or {}).items():
        for c in (f.get('cves') or []):
            if not isinstance(c, dict):
                continue
            sev = str(c.get('severity', '')).lower()
            if sev in ('critical', 'high'):
                worst.append((sev, dev_id,
                              c.get('id') or c.get('cve_id') or '?',
                              c.get('package') or c.get('pkg') or ''))
    if worst:
        rank = {'critical': 0, 'high': 1}
        worst.sort(key=lambda x: (rank.get(x[0], 9), x[1]))
        n_crit = sum(1 for w in worst if w[0] == 'critical')
        lines = [f"- {dev}: {cid} ({sev}{' in ' + pkg if pkg else ''})"
                 for sev, dev, cid, pkg in worst[:80]]
        text = ("Fleet CVE summary — the worst (critical and high severity) "
                f"vulnerabilities / CVEs across the whole fleet "
                f"({n_crit} critical, {len(worst) - n_crit} high):\n"
                + '\n'.join(lines))
        docs.append(make_doc(
            "live/_fleet#cves", 'live_state', 'fleet_cves', text,
            title="Fleet CVE summary (worst CVEs)", device=None, ts=now))

    # Fleet patch & reboot rollup — "which hosts have pending updates / need a
    # reboot?" Both are common cross-fleet questions with no single device.
    if patch_hosts or reboot_hosts:
        parts = []
        if patch_hosts:
            patch_hosts.sort(key=lambda x: x[1], reverse=True)
            parts.append("Hosts with pending package updates (most first):\n"
                         + '\n'.join(f"- {n}: {c} pending update"
                                     f"{'s' if c != 1 else ''}"
                                     for n, c in patch_hosts))
        if reboot_hosts:
            parts.append("Hosts that require a reboot:\n"
                         + '\n'.join(f"- {n}" for n in sorted(reboot_hosts)))
        docs.append(make_doc(
            "live/_fleet#patches", 'live_state', 'fleet_patches',
            "Fleet patch & reboot status — pending package updates and "
            "pending reboots across the fleet:\n" + '\n\n'.join(parts),
            title="Fleet patch & reboot status", device=None, ts=now))

    # Fleet config-drift rollup — "which hosts have drifted from baseline?"
    if drift_hosts:
        drift_hosts.sort(key=lambda x: x[1], reverse=True)
        docs.append(make_doc(
            "live/_fleet#drift", 'live_state', 'fleet_drift',
            "Fleet configuration drift — hosts with config files changed "
            "from their captured baseline:\n"
            + '\n'.join(f"- {n}: {c} drifted file{'s' if c != 1 else ''}"
                        for n, c in drift_hosts),
            title="Fleet config drift", device=None, ts=now))
    return docs


def build_history_corpus(commands=None, alerts=None, events=None,
                         limits=None, redactor=None, now=0):
    """Recent operational history: commands, alerts, fleet events.

    Bounded hard by `limits` and intentionally lossy — this is the most
    sensitive and most voluminous source. `redactor`, if given, is a
    callable applied to each rendered chunk before it is stored, so the
    operator's AI privacy settings are honoured at index time (not just
    at prompt-assembly time).
    """
    limits = limits or {}
    max_cmds = int(limits.get('commands_per_device', 20))
    max_age = int(limits.get('max_age_days', 14)) * 86400
    cutoff = (now - max_age) if (now and max_age) else 0
    docs = []

    def _emit(doc_id, dtype, title, text, device=None, ts=0):
        if redactor:
            text = redactor(text)
        if text and text.strip():
            docs.append(make_doc(doc_id, 'history', dtype, text,
                                  title=title, device=device, ts=ts))

    # Commands: dict device_id -> list[entry] OR flat list with device field.
    if isinstance(commands, dict):
        for dev_id, entries in commands.items():
            entries = [e for e in (entries or []) if isinstance(e, dict)]
            entries = [e for e in entries
                       if (e.get('ts') or e.get('time') or 0) >= cutoff]
            entries = sorted(entries,
                             key=lambda e: e.get('ts') or e.get('time') or 0,
                             reverse=True)[:max_cmds]
            if not entries:
                continue
            body = _format_facet([
                {'cmd': e.get('cmd') or e.get('command') or '',
                 'rc': e.get('rc', e.get('exit_code', '')),
                 'when': e.get('ts') or e.get('time') or ''}
                for e in entries])
            _emit(f"history/{dev_id}#commands", 'commands',
                  f"Recent commands: {dev_id}", body, device=dev_id,
                  ts=entries[0].get('ts') or entries[0].get('time') or 0)

    # Alerts + fleet events: flat lists.
    for label, rows, dtype in (('alerts', alerts, 'alert'),
                               ('events', events, 'fleet_event')):
        rows = [r for r in (rows or []) if isinstance(r, dict)]
        rows = [r for r in rows if (r.get('ts') or r.get('time') or 0) >= cutoff]
        rows = sorted(rows, key=lambda r: r.get('ts') or r.get('time') or 0,
                      reverse=True)[:200]
        if not rows:
            continue
        body = _format_facet([
            {k: r.get(k) for k in ('type', 'severity', 'device', 'message',
                                   'event', 'state') if r.get(k)}
            for r in rows])
        _emit(f"history/_{label}", dtype, f"Recent {label}", body,
              ts=rows[0].get('ts') or rows[0].get('time') or 0)
    return docs


# ── Vector helpers ───────────────────────────────────────────────────────────

def cosine(a, b):
    """Cosine similarity of two equal-length vectors. 0.0 on degenerate
    input (empty, mismatched length, or a zero vector)."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = 0.0
    na = 0.0
    nb = 0.0
    for x, y in zip(a, b):
        dot += x * y
        na += x * x
        nb += y * y
    if na <= 0.0 or nb <= 0.0:
        return 0.0
    return dot / (math.sqrt(na) * math.sqrt(nb))


def rrf_fuse(rank_lists, k=60):
    """Reciprocal Rank Fusion over several ranked id lists.

    score(id) = sum over lists of 1/(k + rank), rank starting at 1.
    Returns {id: score}. RRF is rank-based so it needs no score
    normalisation between the (unbounded) BM25 scores and the [-1,1]
    cosine scores — which is exactly why we use it instead of a
    weighted sum of raw scores.
    """
    scores = {}
    for ranked in rank_lists:
        for rank, doc_id in enumerate(ranked, start=1):
            scores[doc_id] = scores.get(doc_id, 0.0) + 1.0 / (k + rank)
    return scores


# ── The index ────────────────────────────────────────────────────────────────

# Above this many chunks we stop sweeping cosine over the entire corpus
# and instead rerank only the lexical prefilter. Below it, a full sweep
# is cheap and gives embeddings a chance to surface docs the lexical
# stage missed entirely.
_FULL_COSINE_MAX_DOCS = 2000

# BM25 parameters. The textbook defaults; our corpus is too small to
# justify tuning them.
_BM25_K1 = 1.2
_BM25_B = 0.75


class InfraIndex:
    """Lexical (BM25) index with an optional embedding rerank layer.

    Persisted as a plain dict via to_dict()/from_dict(); api.py writes
    that through its own load()/save(). Embedding vectors are cached by
    content hash so a reindex only re-embeds chunks whose text changed.
    """

    def __init__(self):
        self.docs = []                 # list of doc dicts
        self._by_id = {}               # id -> doc
        self._postings = {}            # term -> {doc_id: tf}
        self._doc_len = {}             # doc_id -> token count
        self._avgdl = 0.0
        self._n = 0
        self.emb_cache = {}            # content_hash -> {'v': [...]}
        self.emb_model = ''            # model that produced the cached vectors
        self.built_at = 0
        self._device_tokens = {}       # dev_id -> set of identifying tokens

    # -- construction ----------------------------------------------------------

    def _index_device_tokens(self):
        """Map each device-scoped chunk's device id to the query tokens that
        should "focus" on it: the full id plus its first hostname label.

        We deliberately exclude shared labels like the domain (`tvipper`,
        `com`) — those would make every `*.tvipper.com` device match a query
        that merely contains "com". The short hostname (`tviweb01`) and the
        full id are specific enough to be a reliable focus signal.
        """
        self._device_tokens = {}
        for d in self.docs:
            dev = d.get('device')
            if not dev:
                continue
            if dev in self._device_tokens:
                continue
            low = str(dev).lower()
            toks = {low, low.split('.')[0]}
            self._device_tokens[dev] = {t for t in toks if len(t) >= 2}

    def build(self, docs, built_at=0):
        """(Re)build the lexical index from a list of docs. Embedding
        cache is preserved across rebuilds (keyed by content hash)."""
        self.docs = [d for d in docs if d.get('text')]
        self._by_id = {d['id']: d for d in self.docs}
        self._postings = {}
        self._doc_len = {}
        total = 0
        for d in self.docs:
            toks = tokenize(d['text'])
            self._doc_len[d['id']] = len(toks)
            total += len(toks)
            tf = {}
            for t in toks:
                tf[t] = tf.get(t, 0) + 1
            for t, c in tf.items():
                self._postings.setdefault(t, {})[d['id']] = c
        self._n = len(self.docs)
        self._avgdl = (total / self._n) if self._n else 0.0
        self.built_at = int(built_at or 0)
        self._index_device_tokens()
        # Drop cache entries for chunks that no longer exist, so the file
        # doesn't grow unbounded across many reindexes.
        live = {d['hash'] for d in self.docs}
        self.emb_cache = {h: v for h, v in self.emb_cache.items() if h in live}
        return self

    # -- embeddings ------------------------------------------------------------

    def missing_embeddings(self):
        """Return [(hash, text)] for chunks not yet embedded. The caller
        embeds these (deduped by hash) and feeds the result back via
        set_embeddings()."""
        seen = set()
        out = []
        for d in self.docs:
            h = d['hash']
            if h in self.emb_cache or h in seen:
                continue
            seen.add(h)
            out.append((h, d['text']))
        return out

    def set_embeddings(self, hash_to_vec, model=''):
        """Merge freshly computed vectors into the cache."""
        for h, v in (hash_to_vec or {}).items():
            if v:
                self.emb_cache[h] = {'v': list(v)}
        if model:
            self.emb_model = model

    def has_embeddings(self):
        return bool(self.emb_cache)

    # -- search ----------------------------------------------------------------

    def _bm25_search(self, qtokens, top_n):
        if not qtokens or not self._n:
            return []
        qset = list(dict.fromkeys(qtokens))      # unique, order-preserving
        scores = {}
        for term in qset:
            postings = self._postings.get(term)
            if not postings:
                continue
            df = len(postings)
            # BM25 idf with the +1 inside the log to keep it non-negative.
            idf = math.log(1 + (self._n - df + 0.5) / (df + 0.5))
            for doc_id, tf in postings.items():
                dl = self._doc_len.get(doc_id, 0)
                denom = tf + _BM25_K1 * (1 - _BM25_B + _BM25_B * dl / (self._avgdl or 1))
                scores[doc_id] = scores.get(doc_id, 0.0) + idf * (tf * (_BM25_K1 + 1)) / (denom or 1)
        ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
        return ranked[:top_n]

    def _semantic_rank(self, candidate_ids, query_vec, top_n):
        sims = []
        for doc_id in candidate_ids:
            doc = self._by_id.get(doc_id)
            if not doc:
                continue
            ent = self.emb_cache.get(doc['hash'])
            if not ent:
                continue
            sims.append((doc_id, cosine(query_vec, ent['v'])))
        sims.sort(key=lambda kv: kv[1], reverse=True)
        return sims[:top_n]

    def _focus_devices(self, qtokens):
        """Devices the query explicitly names (by id or short hostname).
        Returns a set of device ids — empty when the query isn't about a
        specific host."""
        if not self._device_tokens:
            return set()
        qset = set(qtokens)
        return {dev for dev, toks in self._device_tokens.items() if toks & qset}

    # A bonus that dwarfs any RRF score (~1/61 max per list) so a named
    # device's own chunks always sort above generic matches, while their
    # relative order (by underlying relevance) is preserved.
    _FOCUS_BONUS = 1.0

    def search(self, query, top_n=6, query_vec=None, prefilter_n=50):
        """Return up to top_n doc dicts most relevant to `query`.

        Scoring is rank-based (RRF) so lexical and optional semantic signals
        combine without normalising raw scores. When the query names a
        specific device, that device's chunks are boosted to the top — a
        "what is web01 doing / what IP does web01 have" question should be
        answered from web01's own state, not from whichever product doc
        happens to share a word with the query.
        """
        qtokens = tokenize(query)
        lex = self._bm25_search(qtokens, top_n=max(top_n, prefilter_n))
        lex_ids = [doc_id for doc_id, _ in lex]

        if query_vec and self.emb_cache:
            if self._n <= _FULL_COSINE_MAX_DOCS:
                candidates = [d['id'] for d in self.docs]
            else:
                # Large corpus: rerank the lexical prefilter only.
                candidates = lex_ids or [d['id'] for d in self.docs[:prefilter_n]]
            sem = self._semantic_rank(candidates, query_vec, top_n=max(top_n, prefilter_n))
            sem_ids = [doc_id for doc_id, _ in sem]
            score = rrf_fuse([lex_ids, sem_ids])
        else:
            # Rank-based lexical score, so the focus bonus is comparable to
            # the RRF path above (both ~1/(60+rank)).
            score = {doc_id: 1.0 / (60 + rank)
                     for rank, doc_id in enumerate(lex_ids, start=1)}

        focus = self._focus_devices(qtokens)
        if focus:
            for doc_id in list(score):
                doc = self._by_id.get(doc_id)
                if doc and doc.get('device') in focus:
                    score[doc_id] += self._FOCUS_BONUS
            # Surface the named device's chunks even if a particular facet
            # didn't lexically match the rest of the query.
            for doc in self.docs:
                if doc.get('device') in focus and doc['id'] not in score:
                    score[doc['id']] = self._FOCUS_BONUS

        ranked_ids = sorted(score, key=lambda i: score[i], reverse=True)[:top_n]
        return [self._by_id[i] for i in ranked_ids if i in self._by_id]

    # -- stats / persistence ---------------------------------------------------

    def stats(self):
        by_source = {}
        for d in self.docs:
            by_source[d['source']] = by_source.get(d['source'], 0) + 1
        return {
            'docs':       self._n,
            'terms':      len(self._postings),
            'embedded':   len(self.emb_cache),
            'emb_model':  self.emb_model,
            'by_source':  by_source,
            'built_at':   self.built_at,
        }

    def to_dict(self):
        return {
            'v':         1,
            'built_at':  self.built_at,
            'avgdl':     self._avgdl,
            'n':         self._n,
            'docs':      self.docs,
            'postings':  self._postings,
            'doc_len':   self._doc_len,
            'emb_cache': self.emb_cache,
            'emb_model': self.emb_model,
        }

    @classmethod
    def from_dict(cls, data):
        idx = cls()
        if not isinstance(data, dict):
            return idx
        idx.docs = data.get('docs') or []
        idx._by_id = {d['id']: d for d in idx.docs if isinstance(d, dict) and 'id' in d}
        idx._postings = data.get('postings') or {}
        idx._doc_len = data.get('doc_len') or {}
        idx._avgdl = data.get('avgdl') or 0.0
        idx._n = data.get('n') or len(idx.docs)
        idx.emb_cache = data.get('emb_cache') or {}
        idx.emb_model = data.get('emb_model') or ''
        idx.built_at = data.get('built_at') or 0
        idx._index_device_tokens()     # derived, not persisted
        return idx

"""RemotePower — notification-channel payload builders (webhook / push / ITSM).

Pure, side-effect-free formatters carved out of api.py (same model as
integrations.py / hypervisor.py): every function here turns
(event, title, message, payload, dest) into (body, headers, content_type)
for one downstream service — Discord, Slack, Teams, ntfy, GitHub Issues,
PagerDuty, Opsgenie, Pushover, Telegram, Matrix, the generic JSON contract,
and the ITSM ticket adapters (Jira / ServiceNow / Zendesk) — plus the
human-readable _webhook_message() renderer they all share.

No storage, no network, no request context: delivery (SSRF-guarded POST,
rate limiting, DLQ, logging) stays in api.py's _dispatch_one_webhook /
_send_webhook_to_url. api.py injects the few registry-derived lookups via
configure() at import time; tests can inject doubles the same way.
Unit-tested in tests/test_notify_module.py and part of the Makefile
LINT + TYPECHECK baseline.
"""

import json
import re
import time
import urllib.parse

# ── injected by api.configure() ─────────────────────────────────────────────
SERVER_VERSION = "0"  # api.SERVER_VERSION
WEBHOOK_SCHEMA_VERSION = "1"  # api.WEBHOOK_SCHEMA_VERSION (payload contract)
_RECOVER_EVENTS: frozenset = frozenset()  # events that RESOLVE an alert (PagerDuty action)
_tags_fn = lambda event: "bell"  # noqa: E731 — EVENT_REGISTRY tags lookup


def configure(server_version, schema_version, recover_events, tags_fn):
    """Called once by api.py after the EVENT_REGISTRY derivations exist."""
    global SERVER_VERSION, WEBHOOK_SCHEMA_VERSION, _RECOVER_EVENTS, _tags_fn
    SERVER_VERSION = server_version
    WEBHOOK_SCHEMA_VERSION = schema_version
    _RECOVER_EVENTS = frozenset(recover_events)
    _tags_fn = tags_fn


def _auto_detect_format(url):
    """Guess the format from the URL hostname. Used for legacy webhook_url
    entries that don't carry a `format` field. Operators with the new
    multi-webhook UI pick the format explicitly."""
    try:
        host = (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return "generic"

    def _host_in(*domains):
        # Anchored host match — exact apex or a real subdomain. Substring
        # checks (`'discord.com' in host`) are spoofable by
        # `discord.com.attacker.tld`, so match the apex or a dotted suffix.
        return any(host == d or host.endswith("." + d) for d in domains)

    if _host_in("discord.com", "discordapp.com"):
        return "discord"
    if _host_in("hooks.slack.com", "slack.com"):
        return "slack"
    if _host_in("api.pushover.net", "pushover.net"):
        return "pushover"
    if _host_in("outlook.office.com", "webhook.office.com", "office.com"):
        return "teams"
    if _host_in("ntfy.sh"):
        return "ntfy"
    if _host_in("events.pagerduty.com", "pagerduty.com"):
        return "pagerduty"
    if _host_in("opsgenie.com"):
        return "opsgenie"
    if _host_in("api.telegram.org", "telegram.org"):
        return "telegram"
    return "generic"


# Allowed format adapters — anything else falls back to generic.


def _build_discord_body(event, title, message):
    colors = {
        "device_offline": 0xEF4444,
        "device_online": 0x22C55E,
        "monitor_down": 0xEF4444,
        "monitor_up": 0x22C55E,
        "service_down": 0xEF4444,
        "service_up": 0x22C55E,
        "patch_alert": 0xF59E0B,
        "command_queued": 0x3B7EFF,
        "command_executed": 0x3B7EFF,
        "test": 0x7C3AED,
        "container_stopped": 0xEF4444,
        "container_restarting": 0xF59E0B,
        "containers_stale": 0xF59E0B,
        "cve_found": 0xEF4444,
        "log_alert": 0xF59E0B,
        "brute_force_detected": 0xEF4444,
        "tls_expiry": 0xF59E0B,
    }
    body = json.dumps(
        {
            "username": "RemotePower",
            "embeds": [
                {
                    "title": title,
                    "description": message,
                    "color": colors.get(event, 0x3B7EFF),
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "footer": {"text": f"RemotePower {SERVER_VERSION}"},
                }
            ],
        }
    ).encode()
    return body, {}, "application/json"


def _build_slack_body(event, title, message):
    body = json.dumps({"text": f"*{title}*\n{message}"}).encode()
    return body, {}, "application/json"


def _build_teams_body(event, title, message):
    """Microsoft Teams uses MessageCard schema. Severity drives the theme color."""
    severity_colors = {
        "device_offline": "EF4444",
        "monitor_down": "EF4444",
        "service_down": "EF4444",
        "cve_found": "EF4444",
        "brute_force_detected": "EF4444",
        "device_online": "22C55E",
        "monitor_up": "22C55E",
        "service_up": "22C55E",
        "patch_alert": "F59E0B",
        "log_alert": "F59E0B",
        "tls_expiry": "F59E0B",
    }
    body = json.dumps(
        {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": title,
            "themeColor": severity_colors.get(event, "3B7EFF"),
            "title": title,
            "text": message,
        }
    ).encode()
    return body, {}, "application/json"


def _build_ntfy_body(event, title, message, priority):
    """ntfy.sh takes a plain-text body + headers for title/priority/tags.

    Priority mapping: our 0-2 internal → ntfy 3-5 (min=1, default=3, urgent=5).
    """
    ntfy_prio = {0: 3, 1: 4, 2: 5}.get(priority, 3)
    body = (message or "").encode()
    headers = {
        "Title": title,
        "Priority": str(ntfy_prio),
        "Tags": _tags_fn(event),
    }
    return body, headers, "text/plain; charset=utf-8"


def _build_github_body(event, title, message, dest, safe_payload):
    """Create a GitHub issue for the alert.

    v3.3.0: target the GitHub REST API at the URL the operator
    configures (https://api.github.com/repos/<owner>/<repo>/issues).
    Auth uses a fine-grained Personal Access Token stored in the
    destination's `token` field. Returns (None, None, None) when
    the token is missing — caller logs an error.

    The PAT scope needs: `issues:write` on the target repo. Operators
    typically create a fine-grained PAT scoped to one repo.

    Body shape (POST application/json):
      {
        "title":  "<event title>",
        "body":   "<details + JSON payload>",
        "labels": ["remotepower", "<event>", "<severity if set>"]
      }
    """
    pat = (dest.get("token") or "").strip()
    if not pat:
        return None, None, None
    labels = ["remotepower", str(event)[:32]]
    sev = (safe_payload or {}).get("severity")
    if isinstance(sev, str) and sev:
        labels.append(sev[:32])
    # Compose the issue body — operator-readable details on top, then
    # the raw payload in a fenced JSON block for grep/parse downstream.
    body_md = (message or "").strip()
    body_md += "\n\n---\n\n"
    body_md += "Raised by RemotePower v" + SERVER_VERSION + "\n\n"
    body_md += "<details><summary>Payload</summary>\n\n```json\n"
    try:
        body_md += json.dumps(safe_payload or {}, indent=2, sort_keys=True)[:8000]
    except Exception:
        body_md += "(payload not serialisable)"
    body_md += "\n```\n\n</details>"
    payload = {
        "title": (title or str(event))[:240],
        "body": body_md[:60000],
        "labels": labels,
    }
    return (
        json.dumps(payload).encode(),
        {
            "Authorization": f"Bearer {pat}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        "application/json",
    )


def _build_pagerduty_body(event, title, message, priority, dest, safe_payload):
    """PagerDuty Events API v2 — trigger (or resolve) an incident.

    The routing/integration key comes from the destination's `routing_key`
    field, falling back to the shared `token` field the UI already exposes.
    Recover events (device_online, service_recover, …) send event_action
    'resolve' against a stable dedup_key so the incident closes itself.
    URL: https://events.pagerduty.com/v2/enqueue. Returns (None,…) if no key."""
    key = (dest.get("routing_key") or dest.get("token") or "").strip()
    if not key:
        return None, None, None
    sev = (
        "critical"
        if priority >= 5
        else "error" if priority >= 4 else "warning" if priority >= 3 else "info"
    )
    action = "resolve" if event in _RECOVER_EVENTS else "trigger"
    p = safe_payload or {}
    dedup = f"remotepower-{event}-{p.get('device_id', '')}"[:255]
    body = json.dumps(
        {
            "routing_key": key,
            "event_action": action,
            "dedup_key": dedup,
            "payload": {
                "summary": (title or message or str(event))[:1024],
                "severity": sev,
                "source": p.get("device_name") or p.get("_server_name") or "RemotePower",
                "custom_details": {"message": message, "event": event},
            },
        }
    ).encode()
    return body, {}, "application/json"


def _build_opsgenie_body(event, title, message, priority, dest, safe_payload):
    """Opsgenie Alerts API v2 — create an alert. The API key (GenieKey) comes
    from the destination's `api_key`, falling back to the shared `token` field.
    URL: https://api.opsgenie.com/v2/alerts (or the EU endpoint). Returns
    (None,…) when no key is set."""
    key = (dest.get("api_key") or dest.get("token") or "").strip()
    if not key:
        return None, None, None
    pri = "P1" if priority >= 5 else "P2" if priority >= 4 else "P3" if priority >= 3 else "P4"
    p = safe_payload or {}
    body = json.dumps(
        {
            "message": (title or message or str(event))[:130],
            "description": (message or "")[:15000],
            "priority": pri,
            "alias": f"remotepower-{event}-{p.get('device_id', '')}"[:512],
            "source": "RemotePower",
            "tags": ["remotepower", str(event)[:48]],
            "details": {"event": event, "device": p.get("device_name", "")},
        }
    ).encode()
    return body, {"Authorization": f"GenieKey {key}"}, "application/json"


def _build_pushover_body(event, title, message, priority, dest):
    """Pushover API: POST application/x-www-form-urlencoded with
    token + user + message + optional title/priority.

    Reference: https://pushover.net/api

    Priority mapping (our 0-2 → Pushover -2..2):
      0 (normal)   → 0
      1 (warning)  → 1
      2 (critical) → 1  (NOT 2 — Pushover priority=2 requires retry/expire and
                         escalates to emergency tier with mandatory ack. Reserve
                         that for caller-explicit configuration.)
    """
    token = (dest.get("pushover_token") or "").strip()
    user = (dest.get("pushover_user") or "").strip()
    if not token or not user:
        return None, None, None
    p_prio = {0: 0, 1: 1, 2: 1}.get(priority, 0)
    form = {
        "token": token,
        "user": user,
        "title": title[:250],
        "message": (message or title)[:1024],
        "priority": str(p_prio),
    }
    body = urllib.parse.urlencode(form).encode()
    return body, {}, "application/x-www-form-urlencoded"


# ── v5.0.0: lightweight ITSM ticket adapters (Jira / ServiceNow / Zendesk) ───
# These POST a create-ticket payload to the provider's REST API using HTTP Basic
# auth from the destination's `itsm_user` + `itsm_secret`. They're wired to the
# on-ACK opt-in (open a ticket when an operator acknowledges an alert). The
# response is parsed for the new ticket's id/url (see _parse_itsm_response) and
# stored on the alert so the UI can link straight to it.
ITSM_FORMATS = ("jira", "servicenow", "zendesk")


def _itsm_basic(user, secret, zendesk=False):
    import base64

    if not secret:
        return None
    ident = f"{user}/token" if zendesk else user
    return "Basic " + base64.b64encode(f"{ident}:{secret}".encode()).decode()


def _build_jira_body(event, title, message, dest):
    """Jira Cloud/Server: POST <base>/rest/api/2/issue. Needs a project key +
    user(email)/secret(API token). issuetype defaults to Task."""
    proj = (dest.get("jira_project") or "").strip()
    auth = _itsm_basic(
        (dest.get("itsm_user") or "").strip(), (dest.get("itsm_secret") or "").strip()
    )
    if not (proj and auth):
        return None, None, None
    itype = (dest.get("jira_issuetype") or "Task").strip() or "Task"
    body = json.dumps(
        {
            "fields": {
                "project": {"key": proj},
                "summary": (title or str(event))[:250],
                "description": message or "",
                "issuetype": {"name": itype},
            }
        }
    ).encode()
    return body, {"Authorization": auth}, "application/json"


def _build_servicenow_body(event, title, message, dest):
    """ServiceNow: POST <base>/api/now/table/incident. user/secret basic auth."""
    auth = _itsm_basic(
        (dest.get("itsm_user") or "").strip(), (dest.get("itsm_secret") or "").strip()
    )
    if not auth:
        return None, None, None
    body = json.dumps(
        {
            "short_description": (title or str(event))[:160],
            "description": message or "",
        }
    ).encode()
    return body, {"Authorization": auth, "Accept": "application/json"}, "application/json"


def _build_zendesk_body(event, title, message, dest):
    """Zendesk: POST <base>/api/v2/tickets.json. email/token basic auth."""
    auth = _itsm_basic(
        (dest.get("itsm_user") or "").strip(), (dest.get("itsm_secret") or "").strip(), zendesk=True
    )
    if not auth:
        return None, None, None
    body = json.dumps(
        {
            "ticket": {
                "subject": (title or str(event))[:250],
                "comment": {"body": message or ""},
            }
        }
    ).encode()
    return body, {"Authorization": auth}, "application/json"


def _parse_itsm_response(fmt, url, raw):
    """Extract {ticket_ref, ticket_url} from a provider's create-ticket response."""
    try:
        data = json.loads((raw or b"").decode("utf-8", "replace"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    u = urllib.parse.urlparse(url)
    base = f"{u.scheme}://{u.netloc}"
    try:
        if fmt == "jira":
            key = data.get("key")
            if key:
                return {"ticket_ref": str(key), "ticket_url": f"{base}/browse/{key}"}
        elif fmt == "servicenow":
            res = data.get("result") or {}
            num, sid = res.get("number"), res.get("sys_id")
            if num:
                link = f"{base}/nav_to.do?uri=incident.do?sys_id={sid}" if sid else ""
                return {"ticket_ref": str(num), "ticket_url": link}
        elif fmt == "zendesk":
            t = data.get("ticket") or {}
            tid = t.get("id")
            if tid:
                return {
                    "ticket_ref": str(tid),
                    "ticket_url": t.get("url") or f"{base}/agent/tickets/{tid}",
                }
    except Exception:
        return None
    return None


def _build_generic_body(event, title, message, priority, safe_payload):
    """Generic JSON body + push-friendly extension headers. Catches anything
    that isn't a recognised hosted service — your homelab Gotify, an internal
    aggregator, custom scripts via webhook.site, etc."""
    body = json.dumps(
        {
            "schema_version": WEBHOOK_SCHEMA_VERSION,  # v5.4.1 (E4): payload contract version
            "event": str(event)[:64],
            "ts": int(time.time()),
            "title": title,
            "message": message,
            "priority": priority,
            **safe_payload,
        }
    ).encode()
    headers = {
        "X-Title": title,
        "X-Priority": str(priority),
        "X-Tags": _tags_fn(event),
    }
    return body, headers, "application/json"


def _build_telegram_body(event, title, message, dest):
    """Telegram Bot API: POST https://api.telegram.org/bot<TOKEN>/sendMessage —
    the bot token lives in the destination URL (like a Slack/Discord webhook
    URL); chat_id is a non-secret destination field."""
    chat_id = (dest.get("telegram_chat_id") or "").strip()
    if not chat_id:
        return None, None, None
    text = (f"{title}\n\n{message}" if title else (message or str(event)))[:4000]
    body = json.dumps(
        {
            "chat_id": chat_id,
            "text": text,
            "disable_web_page_preview": True,
        }
    ).encode()
    return body, {}, "application/json"


def _build_matrix_body(event, title, message, dest):
    """Matrix Client-Server API: POST <homeserver>/_matrix/client/v3/rooms/
    <room>/send/m.room.message — the room is in the destination URL; the access
    token is a masked destination field sent as a bearer header."""
    token = (dest.get("matrix_token") or "").strip()
    if not token:
        return None, None, None
    text = (f"{title}\n\n{message}" if title else (message or str(event)))[:8000]
    body = json.dumps({"msgtype": "m.text", "body": text}).encode()
    return body, {"Authorization": f"Bearer {token}"}, "application/json"


def _webhook_message(event, payload):
    """Build a human-readable message string for push notifications."""
    # Prefer the friendly hostname; only fall back to the internal device_id
    # when neither name nor device_name is present (some events — e.g.
    # drift_detected — carry device_name, not name).
    name = payload.get("name") or payload.get("device_name") or payload.get("device_id", "unknown")
    if event == "device_offline":
        return f'{name} went offline (last seen: {_ts_fmt(payload.get("last_seen", 0))})'
    elif event == "device_online":
        return f"{name} is back online"
    elif event in ("vpn_client_connected", "vpn_client_disconnected", "vpn_handshake_stale"):
        cn = payload.get("client_name") or payload.get("client_id") or "client"
        tn = payload.get("tunnel_name") or "?"
        verbs = {
            "vpn_client_connected": "connected",
            "vpn_client_disconnected": "disconnected",
            "vpn_handshake_stale": "handshake went stale",
        }
        return f'WG Access client "{cn}" on tunnel "{tn}" {verbs.get(event, event)}'
    elif event in ("ticket_opened", "ticket_resolved"):
        # portal/email tickets have no device — never fall through to the
        # generic device-name fallback (it rendered "ticket_opened: unknown")
        who = payload.get("requester") or payload.get("assignee") or ""
        src = payload.get("source") or ""
        verb = "opened" if event == "ticket_opened" else "resolved"
        msg = (
            f'Ticket #RP{int(payload.get("number") or 0):06d} '
            f'"{(payload.get("subject") or "")[:80]}" {verb}'
        )
        if who:
            msg += f" by {who}"
        if src and src not in ("operator",):
            msg += f" via {src}"
        if payload.get("site_name"):
            msg += f' — site {payload.get("site_name")}'
        elif payload.get("device_name"):
            msg += f' — {payload.get("device_name")}'
        return msg
    elif event == "ticket_sla_breached":
        return (
            f'Ticket #RP{int(payload.get("number") or 0):06d} '
            f'"{(payload.get("subject") or "")[:80]}" (P{payload.get("priority", 4)}) '
            f"breached its SLA target"
            + (
                f' — assigned to {payload.get("assignee")}'
                if payload.get("assignee")
                else " — unassigned"
            )
        )
    elif event == "command_queued":
        return f'{payload.get("actor", "system")} queued "{payload.get("command", "?")}" on {name}'
    elif event == "command_executed":
        return f'{name} executed "{payload.get("command", "?")}"'
    elif event == "patch_alert":
        return f'{name} has {payload.get("upgradable", "?")} pending updates (threshold: {payload.get("threshold", "?")})'
    elif event == "cve_found":
        sev_summary = f'{payload.get("critical", 0)} critical, {payload.get("high", 0)} high'
        return f'{name}: {payload.get("count", "?")} new CVEs ({sev_summary})'
    elif event == "monitor_down":
        return f'Monitor "{payload.get("label", "?")}" ({payload.get("type", "?")}: {payload.get("target", "?")}) is DOWN — {payload.get("detail", "")}'
    elif event == "monitor_up":
        return f'Monitor "{payload.get("label", "?")}" ({payload.get("type", "?")}: {payload.get("target", "?")}) recovered'
    elif event == "service_down":
        return f'{name}: {payload.get("unit", "?")} is {payload.get("active", "down")} (was {payload.get("previous", "active")})'
    elif event == "service_up":
        return f'{name}: {payload.get("unit", "?")} is active again'
    elif event == "custom_check_failed":
        return f'{name}: check "{payload.get("check_name", "?")}" failed' + (
            f' — {payload.get("output")}' if payload.get("output") else ""
        )
    elif event == "custom_check_recovered":
        return f'{name}: check "{payload.get("check_name", "?")}" recovered'
    elif event == "log_alert":
        # v2.1.1: include the first matched line in the message. Field
        # report: "pattern matched 1 times" is useless on its own — the
        # operator wants to see WHICH line tripped the rule so they can
        # decide if it's a real alert or noise. We truncate aggressively
        # (200 chars) because Discord/Slack message limits + multi-line
        # journald entries can blow up the embed.
        sample = payload.get("sample") or []
        head = f'{name}/{payload.get("unit", "?")}: pattern "{payload.get("pattern", "")}" matched {payload.get("count", "?")} time(s)'
        if isinstance(sample, list) and sample:
            first = str(sample[0]).strip().replace("\n", " ")
            if len(first) > 200:
                first = first[:200] + "…"
            head += f"\n→ {first}"
            extra = len(sample) - 1
            if extra > 0:
                head += f'\n(+ {extra} more matching line{"s" if extra > 1 else ""})'
        return head
    # ── v1.11.4: container events ──────────────────────────────────────────
    elif event == "container_stopped":
        return (
            f'{name}: container "{payload.get("container", "?")}" '
            f'({payload.get("runtime", "?")}) stopped '
            f'(was {payload.get("previous_status", "?")}, now {payload.get("status", "gone")})'
        )
    elif event == "container_restarting":
        return (
            f'{name}: container "{payload.get("container", "?")}" '
            f'restarted {payload.get("delta", "?")} time(s) since last report '
            f'(total restart_count={payload.get("restart_count", "?")})'
        )
    elif event == "containers_stale":
        return (
            f'{name}: no container report for {payload.get("age_minutes", "?")} '
            f'minutes (TTL: {payload.get("ttl_minutes", "?")} min). '
            f'Last seen {_ts_fmt(payload.get("reported_at", 0))}.'
        )
    # ── v1.11.10: metric thresholds ────────────────────────────────────────
    elif event in ("metric_warning", "metric_critical"):
        kind = payload.get("kind", "?")
        target = payload.get("target", "")
        sev = "CRITICAL" if event == "metric_critical" else "WARNING"
        # Disk has a target (mount path); other kinds don't.
        if kind == "disk" and target:
            return (
                f"{name}: {sev} — disk {target} at "
                f'{payload.get("value", "?")}% '
                f'(threshold: {payload.get("threshold", "?")}%)'
            )
        if kind == "cpu":
            return (
                f"{name}: {sev} — load avg "
                f'{payload.get("value", "?")} on {payload.get("cpu_count", "?")} '
                f'CPUs (threshold ratio: {payload.get("threshold", "?")})'
            )
        return (
            f"{name}: {sev} — {kind} at "
            f'{payload.get("value", "?")}% (threshold: {payload.get("threshold", "?")}%)'
        )
    elif event == "metric_recovered":
        kind = payload.get("kind", "?")
        target = payload.get("target", "")
        if kind == "disk" and target:
            return f"{name}: disk {target} recovered to " f'{payload.get("value", "?")}%'
        if kind == "cpu":
            return f'{name}: cpu load recovered to {payload.get("value", "?")}'
        return f'{name}: {kind} recovered to {payload.get("value", "?")}%'
    elif event == "test":
        return f'This is a test notification from RemotePower ({payload.get("server_version", "?")}). If you see this, webhooks are working!'
    # ── v2.5.0: custom monitoring scripts ─────────────────────────────────
    elif event == "custom_script_fail":
        out = str(payload.get("output", "")).strip()
        snippet = f" — {out[:120]}" if out else ""
        return f'{name}: script "{payload.get("script_name", "?")}" FAILED (exit {payload.get("rc", "?")}){snippet}'
    elif event == "custom_script_recover":
        return f'{name}: script "{payload.get("script_name", "?")}" recovered (OK)'
    elif event == "config_drift":
        sections = payload.get("sections", [])
        sec_str = ", ".join(sections[:5]) if sections else "unknown"
        return f"{name}: host config drift in {sec_str}"
    elif event == "drift_detected":
        verb = "removed" if not payload.get("exists", True) else "changed"
        return f'{name}: watched file {payload.get("path", "?")} {verb}'
    elif event == "tls_expiry":
        host = payload.get("host", "?")
        days = payload.get("days_left", "?")
        sev = payload.get("severity", "warning")
        return f'{host}: certificate expires in {days} day{"s" if days != 1 else ""} ({sev})'
    elif event == "reboot_required":
        return f"{name}: pending reboot — /run/reboot-required exists"
    elif event == "snapshot_old":
        vm = payload.get("vm_name", payload.get("vmid", "?"))
        snap = payload.get("snap_name", "?")
        days = payload.get("days_old", "?")
        return f'Proxmox snapshot "{snap}" on {vm} is {days} days old'
    elif event == "new_port_detected":
        port = payload.get("port", "?")
        proto = payload.get("proto", "tcp")
        proc = payload.get("process", "")
        extra = f" ({proc})" if proc else ""
        return f"{name}: new listening port {proto}/{port}{extra}"
    elif event == "ssh_key_added":
        user = payload.get("user", "?")
        fp = payload.get("fingerprint", "")
        extra = f" fingerprint {fp}" if fp else ""
        return f"{name}: SSH key added for user {user}{extra}"
    elif event == "brute_force_detected":
        unit = payload.get("unit", "?")
        src_ip = payload.get("source_ip", "?")
        count = payload.get("count", "?")
        return f"{name}: {count} failed login attempts from {src_ip} on {unit}"
    elif event == "backup_stale":
        label = payload.get("label", payload.get("path", "?"))
        age_h = payload.get("age_hours", "?")
        max_h = payload.get("max_age_hours", "?")
        return f'{name}: backup "{label}" is {age_h}h old (threshold: {max_h}h)'
    elif event == "port_exposed_world":
        proc = payload.get("process", "")
        extra = f" ({proc})" if proc else ""
        return (
            f'{name}: {payload.get("proto","tcp")}/{payload.get("port","?")} '
            f"is exposed to the world — bound to "
            f'{payload.get("addr","0.0.0.0")}{extra}'
        )
    elif event == "software_policy_violation":
        return f'{name}: software policy — {payload.get("detail", payload.get("rule","?"))}'
    elif event == "storage_degraded":
        return (
            f'{name}: storage pool {payload.get("pool","?")} is '
            f'{payload.get("state","degraded")} ({payload.get("kind","")})'
        )
    elif event == "storage_recovered":
        return f'{name}: storage pool {payload.get("pool","?")} returned to healthy'
    elif event == "scrub_overdue":
        return (
            f'{name}: pool {payload.get("pool","?")} scrub is '
            f'{payload.get("age_days","?")} days old'
        )
    elif event == "login_new_source":
        return (
            f'{name}: login by {payload.get("user","?")} from new source '
            f'{payload.get("source","?")}'
        )
    elif event == "firewall_changed":
        return (
            f'{name}: host firewall ({payload.get("backend","?")}) ruleset '
            f'changed — now {payload.get("rules","?")} rules'
        )
    elif event == "db_integrity_failed":
        return (
            "SQLite integrity_check failed — the database may be corrupt. "
            f'Restore from a backup. Detail: {payload.get("detail","?")}'
        )
    elif event == "mount_issue":
        _iw = (
            "is stalled (server not responding)"
            if payload.get("issue") == "stalled"
            else "is not mounted"
        )
        return f'{name}: mount {payload.get("path","?")} ' f'({payload.get("fstype","?")}) {_iw}'
    elif event == "timer_failed":
        act = payload.get("activates", "")
        extra = f" → {act}" if act else ""
        return f'{name}: scheduled job {payload.get("unit","?")} failed{extra}'
    elif event == "timer_failed_cleared":
        return f'{name}: scheduled job {payload.get("unit","?")} recovered'
    elif event == "unit_flapping_cleared":
        return f'{name}: unit {payload.get("unit","?")} stopped flapping'
    elif event == "container_restarting_cleared":
        return f'{name}: container {payload.get("container","?")} stopped restart-looping'
    elif event == "snapshot_recovered":
        return f'{name}: {payload.get("vm_name","?")} snapshots now current'
    elif event == "mailbox_recovered":
        return f'{name}: mailbox {payload.get("path","?")} back below threshold'
    elif event == "disk_predict_fail":
        eta = payload.get("eta_days")
        when = f" (~{eta}d to failure)" if isinstance(eta, int) else ""
        return (
            f'{name}: disk {payload.get("disk","?")} predicted to fail{when} — '
            f'{payload.get("reason","SMART trend")}'
        )
    elif event == "ups_on_battery":
        return (
            f'{name}: UPS {payload.get("ups","?")} on battery '
            f'(battery {payload.get("battery_pct","?")}%)'
        )
    elif event == "ups_on_line":
        return f'{name}: UPS {payload.get("ups","?")} back on line power'
    elif event == "temp_high":
        return (
            f'{name}: {payload.get("sensor","sensor")} at {payload.get("temp_c","?")}°C '
            f'(threshold {payload.get("threshold_c","?")}°C)'
        )
    elif event == "temp_normal":
        return f"{name}: temperature back to normal"
    elif event == "clock_skew":
        return f"{name}: clock skew — " + (
            "not synchronised"
            if payload.get("synced") is False
            else f'offset {payload.get("offset_ms","?")}ms'
        )
    elif event == "clock_synced":
        return f"{name}: clock back in sync"
    elif event == "gateway_unreachable":
        return f'{name}: default gateway {payload.get("gateway","?")} not responding'
    elif event == "gateway_reachable":
        return f"{name}: default gateway reachable again"
    elif event == "oom_detected":
        return f"{name}: kernel OOM-killer fired" + (
            f' (killed {payload.get("process")})' if payload.get("process") else ""
        )
    elif event == "cert_file_expiring":
        return (
            f'{name}: certificate {payload.get("path","?")} expires in '
            f'{payload.get("days","?")} days'
        )
    elif event == "rogue_uid0":
        return (
            f'{name}: account {payload.get("user","?")} has UID 0 '
            f"(root-equivalent) — verify it is expected"
        )
    elif event == "priv_group_added":
        return (
            f'{name}: {payload.get("user","?")} gained privileged-group '
            f"membership (sudo/wheel/Administrators) — verify it was intentional"
        )
    elif event == "usb_device_added":
        return f'{name}: {payload.get("detail", "a USB device was connected")}'
    elif event == "integration_down":
        # Integrations carry no device name — title off the integration label,
        # else the message fell through to "integration_down: unknown".
        return f'Integration "{payload.get("label", "?")}" is unhealthy' + (
            f' — {payload.get("detail")}' if payload.get("detail") else ""
        )
    elif event == "integration_recovered":
        return f'Integration "{payload.get("label", "?")}" recovered'
    elif event == "github_new_issue":
        num = payload.get("number")
        return (
            f'New GitHub issue {f"#{num} " if num else ""}in '
            f'{payload.get("repo", "?")}: {payload.get("title", "?")}'
        )
    elif event == "ip_blacklisted":
        return (
            f'IP {payload.get("ip","?")} is listed on '
            f'{payload.get("listed_count","?")} blocklist(s): {payload.get("blocklists","?")}'
        )
    elif event == "ip_blacklist_cleared":
        return f'IP {payload.get("ip","?")} is no longer blocklisted'
    elif event == "resolver_unhealthy":
        return (
            f'DNS name {payload.get("rtype","?")} {payload.get("target","?")} stopped '
            f'resolving ({payload.get("fail_count",0)} fail / '
            f'{payload.get("nxdomain_count",0)} NXDOMAIN of {payload.get("total",0)})'
        )
    elif event == "resolver_recovered":
        return f'DNS name {payload.get("rtype","?")} {payload.get("target","?")} resolves again'
    elif event == "fail2ban_ban":
        _fn = payload.get("new_count") or 1
        return (
            f'{name}: fail2ban jail {payload.get("jail","?")} banned '
            f'{payload.get("first_ip","?")}'
            + (f" (+{_fn - 1} more new this cycle)" if _fn > 1 else "")
        )
    elif event == "failed_unit":
        _un = payload.get("new_count") or 1
        return f'{name}: systemd unit {payload.get("unit","?")} entered the failed state' + (
            f" (+{_un - 1} more new this cycle)" if _un > 1 else ""
        )
    elif event == "failed_unit_cleared":
        _cn = payload.get("cleared_count") or 1
        return f'{name}: systemd unit {payload.get("unit","?")} left the failed state' + (
            f" (+{_cn - 1} more)" if _cn > 1 else ""
        )
    # v6.2.2 — no hand-written branch: prefer the fire-site's human `detail` over
    # a bare "event: host" so a webhook/push consumer still gets an explanation.
    # (The notification TITLE separately carries the event's registry title.)
    _dtl = payload.get("detail") if isinstance(payload, dict) else None
    if _dtl:
        return f"{name}: {_dtl}" if name else str(_dtl)
    # Humanize the raw event key so even a branch-less, detail-less event reads
    # as a sentence ("smart_failure" → "Smart failure") rather than a machine token,
    # AND name the specific resource the payload carries (unit/disk/pool/…) so the
    # body isn't a vague "Smart failure: host". Mirrors _alert_title's fallback.
    _human = event.replace("_", " ").capitalize()
    _rid = None
    if isinstance(payload, dict):
        for _k in (
            "unit",
            "service",
            "container",
            "pool",
            "process",
            "iface",
            "mount",
            "path",
            "paths",
            "target",
            "disk",
            "disks",
            "ups",
            "image",
            "domain",
            "check_name",
            "vm_name",
            "snap_name",
            "rule",
            "jail",
            "label",
            "ip",
            "mac",
        ):
            _v = payload.get(_k)
            if not _v:
                continue
            if isinstance(_v, (list, tuple)):
                _v = ", ".join(str(x) for x in _v[:3]) + ("…" if len(_v) > 3 else "")
            _rid = str(_v)
            break
    if name and _rid:
        return f"{name}: {_human} ({_rid})"
    if _rid:
        return f"{_human}: {_rid}"
    return f"{_human}: {name}" if name else _human


def _ts_fmt(ts):
    """Format a unix timestamp to human-readable string."""
    if not ts:
        return "never"
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(ts)))
    except Exception:
        return str(ts)

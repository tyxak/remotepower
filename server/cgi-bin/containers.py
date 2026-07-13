"""
RemotePower container awareness — v1.11.0.

Stores container/pod listings reported by agents on heartbeat. This
module is storage-only — it surfaces "is `nginx-proxy` running and how
many times has it restarted" without anyone needing to SSH in. Lifecycle
actions (start / stop / restart / fetch logs, Docker & Podman) queue to
the agent elsewhere (handle_device_container_action); RemotePower still
doesn't build, deploy, or exec into containers — that's Portainer /
k9s / kubectl's job.

Three runtimes supported by detection-on-the-agent-side:
  - Docker  (``docker ps --format '{{json .}}'``)
  - Podman  (``podman ps --format json``)
  - Kubernetes (``kubectl get pods --all-namespaces -o json``)

The agent picks whatever is detected and posts a normalised list in the
heartbeat body under ``containers``. The shape is identical regardless
of runtime — runtime difference is just a tag.

Storage:
  ``/var/lib/remotepower/containers.json``

  ``{device_id -> {ts: <unix>, items: [<container>, ...]}}``

  Last-write-wins. We do NOT keep history — the next heartbeat overwrites
  the previous list. Container state changes too often for a rolling
  buffer to be useful, and "show me when this restarted" is answered
  cheaply by ``restart_count`` deltas.

Per-device cap: 100 items. Some users run a lot of containers; some run
the same image 30 times in different namespaces; either way, the
heartbeat body shouldn't be unbounded. The agent enforces the cap as
well, but the server enforces it again as a defence in depth.
"""

from __future__ import annotations

from typing import Any

# Hard caps applied at the server-side validation layer. The agent applies
# the same caps before posting; we duplicate here so a misbehaving agent
# can't bloat containers.json.
MAX_CONTAINERS_PER_DEVICE = 100
MAX_CONTAINER_NAME_LEN = 256
MAX_CONTAINER_IMAGE_LEN = 512
MAX_CONTAINER_DIGEST_LEN = 256
MAX_CONTAINER_STATUS_LEN = 64
MAX_CONTAINER_NAMESPACE_LEN = 128
MAX_PORT_STRING_LEN = 128
MAX_PORTS_PER_CONTAINER = 20

# Allowed runtime tags. Anything else falls through to 'unknown'.
ALLOWED_RUNTIMES = ("docker", "podman", "kubernetes", "unknown")

# v1.11.4: how old a container report can be before we consider it stale
# and surface that in the UI / fire a webhook. 900s = 15 minutes, which
# leaves comfortable headroom over the agent's CONTAINER_CHECK_EVERY=5
# polls (≈5 minutes at default 60s poll). Servers can override via the
# ``container_stale_ttl`` config key.
DEFAULT_STALE_TTL = 900


def is_stale(reported_at: int, now: int, ttl: int = DEFAULT_STALE_TTL) -> bool:
    """Return True if a container report is older than ``ttl`` seconds.

    Args:
        reported_at: Unix timestamp from the last heartbeat that posted
            containers. Zero means "never reported", which counts as stale.
        now: Current Unix time.
        ttl: Threshold in seconds. Reports older than this are stale.

    Returns:
        True if ``reported_at`` is missing or older than ``now - ttl``.
    """
    if not reported_at:
        return True
    try:
        return (int(now) - int(reported_at)) > int(ttl)
    except (TypeError, ValueError):
        return True


def _str(value: Any, cap: int) -> str:
    """Coerce to string, strip, truncate. Returns empty for None/non-str."""
    if value is None:
        return ""
    s = str(value).strip()
    return s[:cap] if len(s) > cap else s


def _int_or_zero(value: Any) -> int:
    """Coerce to non-negative int. Anything weird becomes 0.

    NB: int(float('inf')) raises OverflowError, not ValueError — and json.loads
    parses non-standard `Infinity`/`NaN` by default, so a buggy/hostile agent CAN
    send them. Catch OverflowError too, or the whole container normaliser crashes.
    """
    try:
        n = int(value)
        return n if n >= 0 else 0
    except (TypeError, ValueError, OverflowError):
        return 0


def _float_or_zero(value: Any) -> float:
    """v6.1.2: coerce to a non-negative FINITE float. Anything weird — including
    inf/nan (which json.loads accepts as Infinity/NaN) — becomes 0, which is
    docker's own encoding of "no limit", so a bad value degrades to the truthful
    'unlimited' rather than passing inf through as a nonsensical cap."""
    try:
        n = float(value)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    # inf and nan are not sane limits. `n == n` is False only for nan; the
    # inequalities reject the infinities. Avoids importing math for one check.
    if n != n or n in (float('inf'), float('-inf')) or n < 0:
        return 0.0
    return n


def _pct_or_none(value: Any):
    """Coerce to a clamped 0–100 float, or None if absent/unparseable. Used for
    container cpu_percent / mem_percent, which the agent may omit (no `stats`)."""
    if value is None:
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    if f < 0:
        return 0.0
    return 100.0 if f > 100 else f


def _normalize_runtime(runtime: Any) -> str:
    """Map agent-reported runtime string to one of ALLOWED_RUNTIMES."""
    if not runtime:
        return "unknown"
    r = str(runtime).strip().lower()
    if r in ("docker", "podman", "kubernetes", "k8s", "kube"):
        return "kubernetes" if r in ("k8s", "kube") else r
    return "unknown"


def normalize_container(item: Any) -> dict | None:
    """Validate and normalise a single container record from a heartbeat.

    Returns ``None`` if the input is unusable (caller should skip it
    rather than 400 the whole heartbeat — partial data is better than
    no data).

    The expected shape is loose on purpose: the agent normalises across
    three different runtimes' output formats, and we don't want
    server-side validation to be brittle when the agent has done its
    best with weird Docker JSON.
    """
    if not isinstance(item, dict):
        return None
    name = _str(item.get("name"), MAX_CONTAINER_NAME_LEN)
    if not name:
        return None
    image = _str(item.get("image"), MAX_CONTAINER_IMAGE_LEN)
    tag = _str(item.get("tag"), 128)
    repo_digest = _str(item.get("repo_digest"), MAX_CONTAINER_DIGEST_LEN)
    status = _str(item.get("status"), MAX_CONTAINER_STATUS_LEN)
    namespace = _str(item.get("namespace"), MAX_CONTAINER_NAMESPACE_LEN)
    runtime = _normalize_runtime(item.get("runtime"))

    # Ports come as a list of strings ("443/tcp", "80:8080/tcp", etc.)
    raw_ports = item.get("ports") or []
    ports: list[str] = []
    if isinstance(raw_ports, list):
        for p in raw_ports[:MAX_PORTS_PER_CONTAINER]:
            ps = _str(p, MAX_PORT_STRING_LEN)
            if ps:
                ports.append(ps)

    return {
        "name": name,
        "image": image,
        "tag": tag,
        "repo_digest": repo_digest,
        "status": status,
        "namespace": namespace,
        "runtime": runtime,
        # v3.9.0: compose project working dir (from the agent's label parse),
        # so the server can offer a one-click pull+recreate update.
        "compose_dir": _str(item.get("compose_dir"), 512),
        "ports": ports,
        "started_at": _int_or_zero(item.get("started_at")),
        "uptime_seconds": _int_or_zero(item.get("uptime_seconds")),
        "restart_count": _int_or_zero(item.get("restart_count")),
        # v3.4.2: the agent already reports these (docker health substring +
        # `docker stats`), but the normaliser used to drop them so the UI could
        # never show a container's health badge or live CPU/mem. Preserve them.
        "health": _str(item.get("health"), 32),
        "cpu_percent": _pct_or_none(item.get("cpu_percent")),
        "mem_percent": _pct_or_none(item.get("mem_percent")),
        "mem_usage": _str(item.get("mem_usage"), 48),
        # v6.1.2: the configured LIMITS (0 = unlimited, docker's own convention).
        # Usage without a limit is half a story: "using 3 GB" means something
        # entirely different capped at 4 GB vs uncapped — an uncapped container
        # can OOM the whole host, which is how a homelab box actually falls over.
        # This normaliser is a whitelist; an unlisted key never reaches the UI.
        "mem_limit_bytes": _int_or_zero(item.get("mem_limit_bytes")),
        "cpu_limit_cores": _float_or_zero(item.get("cpu_limit_cores")),
    }


def normalize_listing(items: Any) -> list[dict]:
    """Validate, normalise, and cap a heartbeat's container list.

    Args:
        items: The agent's ``containers`` field. Expected to be a list,
            but we tolerate ``None`` and unexpected types by returning
            an empty list.

    Returns:
        Up to :data:`MAX_CONTAINERS_PER_DEVICE` normalised records,
        ordered as received. Invalid entries are dropped silently.
    """
    if not isinstance(items, list):
        return []
    out: list[dict] = []
    for item in items[:MAX_CONTAINERS_PER_DEVICE]:
        n = normalize_container(item)
        if n is not None:
            out.append(n)
    return out


def summarise(items: list[dict]) -> dict:
    """Return aggregate counts for the device-list overview.

    Used by the Devices page sidebar / CMDB list to show
    "12 containers (10 running, 2 stopped)" without sending the full
    list. Light enough to compute on every devices-list request.

    Args:
        items: A device's normalised container list.

    Returns:
        Dict with ``total``, ``running``, ``stopped``, ``restarting``,
        ``by_runtime`` (dict of runtime -> count).
    """
    total = len(items)
    running = 0
    stopped = 0
    restarting = 0
    by_runtime: dict[str, int] = {}
    for c in items:
        status = (c.get("status") or "").lower()
        # Status strings vary by runtime — be permissive
        if any(t in status for t in ("running", "up ", "up\t", "ready")):
            running += 1
        elif any(t in status for t in ("exited", "stopped", "dead", "terminated")):
            stopped += 1
        if c.get("restart_count", 0) >= 5:
            restarting += 1
        rt = c.get("runtime") or "unknown"
        by_runtime[rt] = by_runtime.get(rt, 0) + 1
    return {
        "total": total,
        "running": running,
        "stopped": stopped,
        "restarting": restarting,
        "by_runtime": by_runtime,
    }

"""DNS-blocker control — the write half of the Pi-hole / AdGuard connectors (v6.2.0).

The health connectors in ``integrations.py`` are read-only: they tell you the
blocker is up and how much it blocked. The single most common thing an operator
then wants to *do* is the one thing they had to leave RemotePower to do —
"something's broken, is it the ad-blocker?" — so this module adds exactly that:
read the blocking state, and turn blocking off for a bounded window (or back on).

Design mirrors ``hypervisor.py`` (the precedent for adding write actions to the
integrations layer): pure ``fn(inst, c, ...) -> dict`` drivers over the SSRF-safe
client, a per-type registry, and nothing else. ``api.py`` owns the client, the
admin gate and the audit log; this module never decides who may call it.

THE SAFETY PROPERTY THAT SHAPES THE API: a DNS blocker disabled *indefinitely*
and then forgotten is a silent, permanent security regression — which is the
exact opposite of what this product exists to do. So "disable" is modelled as a
TIMED action: the driver always sends a timer, callers must pass one, and it is
clamped to ``MAX_DISABLE_SECONDS``. The blocker itself re-enables when the timer
lapses, so the safe state is restored by the *remote* device, not by a sweep here
that might never run. There is deliberately no "disable forever" verb.
"""

import base64

from integrations import IntegrationError

# A blocker may be switched off for a while to debug something. It may not be
# switched off and forgotten — that is a security regression wearing a
# maintenance hat. Four hours is a generous upper bound on "I am debugging this".
MAX_DISABLE_SECONDS = 4 * 3600
MIN_DISABLE_SECONDS = 30
DEFAULT_DISABLE_SECONDS = 300


def clamp_seconds(value):
    """Clamp a requested disable window into the allowed range.

    A non-numeric / missing value falls back to the default rather than raising:
    the caller has already been through the request model, and refusing to act on
    a fat-fingered timer is worse than acting on a safe default one."""
    try:
        n = int(float(value))
    except (TypeError, ValueError):
        return DEFAULT_DISABLE_SECONDS
    return max(MIN_DISABLE_SECONDS, min(MAX_DISABLE_SECONDS, n))


# ── Pi-hole (v6 API) ─────────────────────────────────────────────────────────
def _pihole_sid(inst, c):
    """Authenticate and return the session id. Pi-hole v6 gates writes on it."""
    try:
        auth = c.post_json("/api/auth", {"password": inst.get("secret") or ""}).json()
    except IntegrationError:
        raise IntegrationError("Pi-hole authentication failed")
    sid = (((auth or {}).get("session") or {}).get("sid")) or ""
    if not sid:
        raise IntegrationError("Pi-hole did not return a session (wrong app password?)")
    return sid


def pihole_status(inst, c):
    sid = _pihole_sid(inst, c)
    s = c.get_json("/api/dns/blocking", headers={"X-FTL-SID": sid})
    # Pi-hole reports blocking as the string "enabled"/"disabled", and `timer` as
    # the seconds left on a temporary disable (null when not counting down).
    blocking = str((s or {}).get("blocking", "")).lower() == "enabled"
    timer = (s or {}).get("timer")
    try:
        remaining = int(float(timer)) if timer is not None else 0
    except (TypeError, ValueError):
        remaining = 0
    return {"blocking": blocking, "remaining": max(0, remaining)}


def pihole_set_blocking(inst, c, enabled, seconds):
    sid = _pihole_sid(inst, c)
    # A timer is meaningless when turning blocking back ON — Pi-hole wants null.
    body: dict = {
        "blocking": bool(enabled),
        "timer": None if enabled else clamp_seconds(seconds),
    }
    r = c.post_json("/api/dns/blocking", body, headers={"X-FTL-SID": sid})
    if not r.ok:
        raise IntegrationError(f"Pi-hole refused the change (HTTP {r.status})")
    return pihole_status(inst, c)


# ── AdGuard Home ─────────────────────────────────────────────────────────────
def _adguard_auth(inst):
    raw = f"{inst.get('username','')}:{inst.get('secret','')}".encode()
    return {"Authorization": "Basic " + base64.b64encode(raw).decode()}


def adguard_status(inst, c):
    s = c.get_json("/control/status", headers=_adguard_auth(inst))
    blocking = bool((s or {}).get("protection_enabled"))
    # AdGuard counts down in MILLIseconds; the rest of this module is seconds.
    try:
        ms = int(float((s or {}).get("protection_disabled_duration") or 0))
    except (TypeError, ValueError):
        ms = 0
    return {"blocking": blocking, "remaining": max(0, ms // 1000)}


def adguard_set_blocking(inst, c, enabled, seconds):
    body: dict = {"enabled": bool(enabled)}
    if not enabled:
        body["duration"] = clamp_seconds(seconds) * 1000  # AdGuard wants ms
    r = c.post_json("/control/protection", body, headers=_adguard_auth(inst))
    if not r.ok:
        raise IntegrationError(f"AdGuard refused the change (HTTP {r.status})")
    return adguard_status(inst, c)


# ── registry ─────────────────────────────────────────────────────────────────
CONTROL = {
    "pihole": {
        "status": pihole_status,
        "set_blocking": pihole_set_blocking,
    },
    "adguard": {
        "status": adguard_status,
        "set_blocking": adguard_set_blocking,
    },
}


def has_control(type_):
    return type_ in CONTROL

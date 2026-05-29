"""
RemotePower RouterOS REST client — v3.3.4.

Talks to MikroTik RouterOS **v7+** over the REST API (HTTPS + HTTP Basic
auth): https://<host>/rest/<path>. Pure stdlib (urllib + ssl + base64),
same posture as snmp.py.

Two surfaces:
  - overview(): read-only visibility — system resource, routerboard +
    firmware, package-update state, interfaces (incl. traffic counters),
    DHCP leases, firewall/NAT rule counts, route count, and (best-effort)
    wireless registration. Each section degrades independently — a path
    the box doesn't expose lands in `errors`, the rest still returns.
  - action(): a small allowlist of management commands (enable/disable an
    interface, reboot, run a saved script, export the config).

TLS: RouterOS ships a self-signed cert, so verification is OFF by default
(it's LAN management of the operator's own router, behind a per-device
opt-in). Callers can pass verify=True if they've installed a trusted cert.

Credentials should be a dedicated RouterOS user — a read-only group for
visibility-only, a write group only if management actions are wanted.
"""

from __future__ import annotations

import base64
import json
import socket
import ssl
import urllib.error
import urllib.request

DEFAULT_TIMEOUT = 6.0


class RouterOSError(Exception):
    pass


def _ctx(verify):
    if verify:
        # Operator installed a trusted cert — keep modern, strict defaults.
        return ssl.create_default_context()
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    # RouterOS commonly serves legacy TLS ciphers that the default
    # SECLEVEL=2 rejects (the SSL_ERROR_NO_CYPHER_OVERLAP a modern browser
    # shows). We're already not verifying the self-signed cert, so the
    # trust model here is "LAN + RouterOS credentials", not the cert —
    # dropping the cipher floor (matching `curl -k`) keeps the connection
    # encrypted while letting Python negotiate with old RouterOS TLS.
    try:
        c.set_ciphers('DEFAULT@SECLEVEL=1')
    except ssl.SSLError:
        pass
    try:
        c.minimum_version = ssl.TLSVersion.TLSv1
    except (ValueError, AttributeError):
        pass
    return c


def _request(host, user, password, method, path, body=None,
             verify=False, timeout=DEFAULT_TIMEOUT):
    """One REST call. Returns parsed JSON (list/dict/str) or raises
    RouterOSError. `path` starts with '/'."""
    url = f"https://{host}/rest{path}"
    data = None
    headers = {
        "Authorization": "Basic " + base64.b64encode(
            f"{user}:{password}".encode()).decode(),
        "Accept": "application/json",
    }
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx(verify)) as r:
            raw = r.read(2 * 1024 * 1024)
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", "replace")[:300]
        except Exception:
            pass
        raise RouterOSError(f"HTTP {e.code}: {detail or e.reason}")
    except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as e:
        raise RouterOSError(str(e))
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except (json.JSONDecodeError, ValueError):
        # /export and a few command endpoints can return non-JSON text
        return raw.decode("utf-8", "replace")


def _one(v):
    """RouterOS returns single-entry menus as either an object or a
    1-element array depending on version/path — normalise to a dict."""
    if isinstance(v, list):
        return v[0] if v else {}
    return v if isinstance(v, dict) else {}


def check(host, user, password, verify=False, timeout=DEFAULT_TIMEOUT):
    """Lightweight credential/reachability probe — GET system/resource."""
    res = _one(_request(host, user, password, "GET", "/system/resource",
                        verify=verify, timeout=timeout))
    return {"version": res.get("version"), "board": res.get("board-name"),
            "uptime": res.get("uptime")}


def overview(host, user, password, verify=False, timeout=DEFAULT_TIMEOUT):
    """Read-only visibility aggregate. Per-section best-effort."""
    out = {"errors": {}}

    def section(key, fn):
        try:
            out[key] = fn()
        except RouterOSError as e:
            out["errors"][key] = str(e)[:200]

    def _get(path):
        return _request(host, user, password, "GET", path,
                        verify=verify, timeout=timeout)

    def _system():
        r = _one(_get("/system/resource"))
        return {
            "version":      r.get("version"),
            "uptime":       r.get("uptime"),
            "cpu_load":     r.get("cpu-load"),
            "free_memory":  r.get("free-memory"),
            "total_memory": r.get("total-memory"),
            "board_name":   r.get("board-name"),
            "architecture": r.get("architecture-name"),
        }

    def _routerboard():
        r = _one(_get("/system/routerboard"))
        return {
            "model":            r.get("model"),
            "current_firmware": r.get("current-firmware"),
            "upgrade_firmware": r.get("upgrade-firmware"),
        }

    def _update():
        r = _one(_get("/system/package/update"))
        return {
            "channel":           r.get("channel"),
            "installed_version": r.get("installed-version"),
            "latest_version":    r.get("latest-version"),
            "status":            r.get("status"),
        }

    def _interfaces():
        rows = _get("/interface")
        if not isinstance(rows, list):
            return []
        out_rows = []
        for i in rows[:128]:
            out_rows.append({
                "id":       i.get(".id"),
                "name":     i.get("name"),
                "type":     i.get("type"),
                "running":  i.get("running") in (True, "true", "yes"),
                "disabled": i.get("disabled") in (True, "true", "yes"),
                "rx_byte":  _int(i.get("rx-byte")),
                "tx_byte":  _int(i.get("tx-byte")),
                "comment":  i.get("comment"),
            })
        return out_rows

    def _leases():
        rows = _get("/ip/dhcp-server/lease")
        if not isinstance(rows, list):
            return []
        return [{
            "address":   l.get("address"),
            "mac":       l.get("mac-address"),
            "hostname":  l.get("host-name"),
            "status":    l.get("status"),
            "dynamic":   l.get("dynamic") in (True, "true", "yes"),
        } for l in rows[:256]]

    def _firewall():
        f = _get("/ip/firewall/filter")
        n = _get("/ip/firewall/nat")
        return {
            "filter": len(f) if isinstance(f, list) else 0,
            "nat":    len(n) if isinstance(n, list) else 0,
        }

    def _routes():
        r = _get("/ip/route")
        return len(r) if isinstance(r, list) else 0

    def _wireless():
        # wifi path varies by RouterOS package (legacy wireless vs
        # wifiwave2/wifi). Try them in turn, return the first that answers.
        for path in ("/interface/wifi/registration-table",
                     "/interface/wireless/registration-table",
                     "/interface/wifiwave2/registration-table"):
            try:
                rows = _request(host, user, password, "GET", path,
                                verify=verify, timeout=timeout)
            except RouterOSError:
                continue
            if isinstance(rows, list):
                return [{
                    "interface": r.get("interface"),
                    "mac":       r.get("mac-address"),
                    "signal":    r.get("signal") or r.get("signal-strength"),
                    "uptime":    r.get("uptime"),
                } for r in rows[:128]]
        return []

    section("system", _system)
    section("routerboard", _routerboard)
    section("update", _update)
    section("interfaces", _interfaces)
    section("dhcp_leases", _leases)
    section("firewall", _firewall)
    section("routes", _routes)
    section("wireless", _wireless)
    return out


# ── Management actions (allowlist) ────────────────────────────────────────
# Each maps to (HTTP method, path-template, body-builder). Anything not in
# this table is rejected — the REST user's own permissions are the second
# line of defence.
def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


ACTIONS = ("enable_interface", "disable_interface", "reboot",
           "run_script", "export")


def action(host, user, password, act, arg=None, verify=False,
           timeout=10.0):
    """Run one allowlisted management command. `arg` is the interface .id /
    script id where relevant. Returns the REST response (or {'ok': True})."""
    if act not in ACTIONS:
        raise RouterOSError(f"action {act!r} not allowed")
    if act == "reboot":
        _request(host, user, password, "POST", "/system/reboot", body={},
                 verify=verify, timeout=timeout)
        return {"ok": True}
    if act in ("enable_interface", "disable_interface"):
        if not arg:
            raise RouterOSError("interface id required")
        verb = "enable" if act == "enable_interface" else "disable"
        _request(host, user, password, "POST", f"/interface/{verb}",
                 body={".id": str(arg)}, verify=verify, timeout=timeout)
        return {"ok": True}
    if act == "run_script":
        if not arg:
            raise RouterOSError("script id/name required")
        r = _request(host, user, password, "POST", "/system/script/run",
                     body={".id": str(arg)}, verify=verify, timeout=timeout)
        return {"ok": True, "result": r}
    if act == "export":
        r = _request(host, user, password, "POST", "/export", body={},
                     verify=verify, timeout=timeout)
        text = r if isinstance(r, str) else "\n".join(
            x if isinstance(x, str) else json.dumps(x)
            for x in (r if isinstance(r, list) else []))
        return {"ok": True, "export": text[:256 * 1024]}
    raise RouterOSError(f"unhandled action {act!r}")

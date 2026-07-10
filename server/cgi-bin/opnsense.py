"""
RemotePower OPNsense REST client — v3.4.0.

The OPNsense counterpart to routeros.py. Talks to the OPNsense firewall
API over HTTPS with HTTP Basic auth, where the username is the API **key**
and the password is the API **secret** (Generate from System → Access →
Users → API keys). Base path is https://<host>/api/<module>/<controller>/…
Pure stdlib (urllib + ssl + base64), same posture as routeros.py / snmp.py.

Reference: https://docs.opnsense.org/development/api.html

Two surfaces, mirroring the RouterOS client so the console UI is identical:
  - overview(): read-only visibility — firmware/version + a firewall rule
    count + DHCP leases (Kea plugin). Sections degrade independently into
    `errors`.
  - firewall(): read filter rules (filter/searchRule) + NAT rules
    (source_nat/searchRule) in detail for the console Firewall view.
  - action(): a small allowlist — add / enable / disable / delete a filter
    or NAT rule. Every mutation is followed by an `apply` so it takes
    effect, and (like RouterOS) freshly added rules land DISABLED for review.

TLS: OPNsense ships a self-signed cert by default, so verification is OFF
by default (LAN management of the operator's own firewall, behind a
per-device opt-in). Pass verify=True once a trusted cert is installed.

The API key/secret should belong to a dedicated OPNsense user scoped to the
firewall pages — read-only for visibility, write only if management is
wanted.
"""

from __future__ import annotations

import base64
import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_TIMEOUT = 6.0
# A quick TCP reachability check runs before the real (TLS) requests so an
# unreachable GUI fails in a few seconds with a clear message instead of
# hanging the per-section timeout × N. SNMP working while this fails almost
# always means the firewall blocks this host from the web GUI, or the GUI
# isn't on the configured port.
PROBE_TIMEOUT = 3.0


class OPNsenseError(Exception):
    pass


def _probe(host_port, timeout=PROBE_TIMEOUT):
    """Fail fast if the GUI port isn't reachable over TCP."""
    h, _, p = str(host_port).partition(":")
    port = int(p or 443)
    try:
        with socket.create_connection((h, port), timeout=timeout) as _s:
            # v5.6.0 pentest: refuse a rebound loopback/metadata peer here too.
            try:
                if _peer_ip_blocked(_s.getpeername()[0]):
                    raise OPNsenseError("refusing blocked peer for %s" % host_port)
            except (OSError, AttributeError, IndexError):
                pass
            return True
    except OSError as e:
        raise OPNsenseError(
            f"cannot reach {host_port} over TCP ({e}). Check that the GUI "
            f"port is correct and that OPNsense allows this server to reach "
            f"the web UI/API (a firewall rule, not just SNMP).")


def _ctx(verify):
    if verify:
        return ssl.create_default_context()
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    # OPNsense's self-signed default cert + occasionally legacy TLS — same
    # "LAN + API credentials" trust model as routeros.py, so relax the cipher
    # floor (matches `curl -k`) while keeping the channel encrypted.
    try:
        c.set_ciphers('DEFAULT@SECLEVEL=1')
    except ssl.SSLError:
        pass
    try:
        c.minimum_version = ssl.TLSVersion.TLSv1_2
    except (ValueError, AttributeError):
        pass
    return c



# v5.6.0 pentest fix — SSRF: the saved host is re-resolved each call, leaving a
# DNS-rebinding window (save a public host once → later rebind to loopback /
# 169.254.169.254 to steal the stored creds). Guard the PEER IP at connect time
# and refuse redirects. RFC1918/LAN stays allowed (these devices live on the LAN).
import http.client as _httpclient
import ipaddress as _ipaddress


def _peer_ip_blocked(ip_str):
    try:
        ip = _ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    # v5.7.0 SSRF: unwrap v4-mapped/6to4/NAT64 v6 forms and re-classify the
    # inner v4, then block cloud-metadata IPs is_link_local misses — mirrors
    # the canonical api._ip_class_blocked (this hand-rolled copy had drifted).
    if isinstance(ip, _ipaddress.IPv6Address):
        inner = ip.ipv4_mapped or ip.sixtofour
        if inner is None and (int(ip) >> 32) == (0x0064ff9b << 64):
            inner = _ipaddress.IPv4Address(int(ip) & 0xffffffff)
        if inner is not None:
            ip = inner
    if str(ip) in ('fd00:ec2::254', '100.100.100.200', '192.0.0.192'):
        return True
    return bool(ip.is_loopback or ip.is_link_local or ip.is_unspecified
                or ip.is_multicast or ip.is_reserved)


class _SSRFGuardHTTPSConnection(_httpclient.HTTPSConnection):
    def connect(self):
        super().connect()
        try:
            peer = self.sock.getpeername()[0]
        except (OSError, AttributeError, IndexError):
            return
        if _peer_ip_blocked(peer):
            self.close()
            raise OSError("SSRF guard: peer %s is a blocked address" % peer)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _ssrf_opener(ctx):
    class _GuardHTTPSHandler(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(_SSRFGuardHTTPSConnection, req, context=ctx)
    return urllib.request.build_opener(_NoRedirectHandler, _GuardHTTPSHandler())

def _request(host, key, secret, method, path, body=None,
             verify=False, timeout=DEFAULT_TIMEOUT):
    """One OPNsense API call. Returns parsed JSON (dict/list/str) or raises
    OPNsenseError. `path` starts with '/' and is appended to /api."""
    url = f"https://{host}/api{path}"
    data = None
    headers = {
        "Authorization": "Basic " + base64.b64encode(
            f"{key}:{secret}".encode()).decode(),
        "Accept": "application/json",
    }
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    elif method == "POST":
        # OPNsense POST controllers expect a JSON body even when empty.
        data = b"{}"
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with _ssrf_opener(_ctx(verify)).open(req, timeout=timeout) as r:
            raw = r.read(2 * 1024 * 1024)
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", "replace")[:300]
        except Exception:
            pass
        if e.code in (401, 403):
            raise OPNsenseError("authentication failed (check API key/secret)")
        raise OPNsenseError(f"HTTP {e.code}: {detail or e.reason}")
    except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as e:
        raise OPNsenseError(str(e))
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except (json.JSONDecodeError, ValueError):
        return raw.decode("utf-8", "replace")


# Which OPNsense controller backs each logical firewall table. NAT maps to
# source_nat (outbound NAT) — the well-supported firewall-plugin controller;
# port-forward (d_nat) follows the identical add/del/toggle contract if a
# deployment wants it later.
_TABLES = {"filter": "filter", "nat": "source_nat"}


def check(host, key, secret, verify=False, timeout=DEFAULT_TIMEOUT):
    """Cheap auth/connectivity probe. Returns True or raises OPNsenseError."""
    _probe(host)
    _request(host, key, secret, "POST", "/firewall/filter/searchRule",
             body={"current": 1, "rowCount": 1}, verify=verify, timeout=timeout)
    return True


def _firmware_status(host, key, secret, verify=False, timeout=DEFAULT_TIMEOUT):
    """Normalised firmware/update state.

    Uses GET /core/firmware/status: against a live 26.1 box, GET returns the
    static product info (product_version + product_latest) reliably, whereas
    POST returns a check-result shape that nulls product_version until a
    `check` has refreshed the repos. We still read the package lists for the
    update count, and fall back to the nested `product` block for the version.
    """
    fw = _request(host, key, secret, "GET", "/core/firmware/status",
                  verify=verify, timeout=timeout)
    if not isinstance(fw, dict):
        return {}
    prod = fw.get("product") if isinstance(fw.get("product"), dict) else {}
    n_upd = len(fw.get("upgrade_packages") or []) + len(fw.get("new_packages") or [])
    if not n_upd and str(fw.get("status", "")).lower() in ("update", "upgrade"):
        n_upd = 1
    return {
        "version":           (fw.get("product_version") or prod.get("product_version")
                              or fw.get("product_name")),
        "latest":            fw.get("product_latest") or prod.get("product_latest"),
        "status":            fw.get("status"),
        "needs_reboot":      _truthy(fw.get("needs_reboot")),
        "updates_available": n_upd,
    }


def _dhcp_leases(host, key, secret, verify=False, timeout=DEFAULT_TIMEOUT):
    """DHCP leases via the Kea plugin — OPNsense 24.7+'s default DHCPv4
    backend (ISC dhcpd was removed upstream, so this targets a current
    install, same posture as `_firmware_status`'s 26.1 target). Same
    searchXXX grid shape as `_search()`; normalised to the shape RouterOS's
    `_leases()` uses so one console table renders both (routeros.py:232-241)."""
    resp = _request(host, key, secret, "POST", "/kea/leases4/search",
                    body={"current": 1, "rowCount": 1000},
                    verify=verify, timeout=timeout)
    rows = resp.get("rows") if isinstance(resp, dict) else resp
    if not isinstance(rows, list):
        rows = []
    out = []
    for r in rows[:256]:
        if not isinstance(r, dict):
            continue

        def g(*names):
            for n in names:
                v = r.get(n)
                if v not in (None, ""):
                    return v
            return ""
        out.append({
            "address":  g("address", "ip-address", "ip"),
            "mac":      g("hwaddr", "hw-address", "mac"),
            "hostname": g("hostname"),
            "status":   str(g("state_label", "state") or "active").lower(),
            "dynamic":  True,   # Kea leases are all dynamic; reservations are a separate table
        })
    return out


def overview(host, key, secret, verify=False, timeout=DEFAULT_TIMEOUT):
    """Read-only visibility: firmware/version + filter & NAT rule counts +
    DHCP leases. Probes reachability first (fast fail), then each section
    degrades independently into `errors`."""
    out = {"firmware": {}, "counts": {}, "dhcp_leases": [], "errors": {}}
    _probe(host)   # fast, clear failure if the GUI is unreachable

    try:
        out["firmware"] = _firmware_status(host, key, secret, verify=verify,
                                           timeout=timeout)
    except OPNsenseError as e:
        out["errors"]["firmware"] = str(e)[:200]

    for key_name, ctrl in _TABLES.items():
        try:
            rows = _search(host, key, secret, ctrl, verify=verify, timeout=timeout)
            out["counts"][key_name] = len(rows)
        except OPNsenseError as e:
            out["errors"][key_name] = str(e)[:200]

    try:
        out["dhcp_leases"] = _dhcp_leases(host, key, secret, verify=verify,
                                          timeout=timeout)
    except OPNsenseError as e:
        out["errors"]["dhcp_leases"] = str(e)[:200]
    return out


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _truthy(v):
    return str(v).lower() in ("1", "true", "yes", "on")


def _search(host, key, secret, ctrl, verify=False, timeout=DEFAULT_TIMEOUT):
    """Raw searchRule rows for a controller. OPNsense returns
    {rows:[...], rowCount, total}."""
    resp = _request(host, key, secret, "POST", f"/firewall/{ctrl}/searchRule",
                    body={"current": 1, "rowCount": 1000},
                    verify=verify, timeout=timeout)
    if isinstance(resp, dict) and isinstance(resp.get("rows"), list):
        return resp["rows"]
    return resp if isinstance(resp, list) else []


def _norm_row(r, table):
    """Normalise a searchRule row into the same shape the console renders for
    RouterOS, so one UI handles both. searchRule field names vary a little by
    OPNsense version, so we look up a few aliases defensively."""
    def g(*names):
        for n in names:
            v = r.get(n)
            if v not in (None, ""):
                return v
        return ""
    row = {
        "id":           r.get("uuid"),
        "chain":        g("interface", "interface_name") or table,
        "action":      (g("action", "target") if table == "filter"
                        else (g("target", "action") or "nat")),
        "src_address":  g("source_net", "source", "src"),
        "dst_address":  g("destination_net", "destination", "dst"),
        "protocol":     g("protocol", "proto"),
        "dst_port":     g("destination_port", "dstport"),
        "in_interface": g("interface", "interface_name"),
        "comment":      g("description", "descr"),
        "disabled":     not _truthy(r.get("enabled", "1")),
    }
    if table == "nat":
        row["to_addresses"] = g("target", "target_net")
        row["to_ports"] = g("target_port")
    return row


def firewall(host, key, secret, verify=False, timeout=DEFAULT_TIMEOUT):
    """Read filter + NAT rules in detail (for the console Firewall view)."""
    out = {"filter": [], "nat": [], "errors": {}}
    _probe(host)   # fast, clear failure if the GUI is unreachable
    for table, ctrl in _TABLES.items():
        try:
            rows = _search(host, key, secret, ctrl, verify=verify, timeout=timeout)
            out[table] = [_norm_row(r, table) for r in rows[:300]]
        except OPNsenseError as e:
            out["errors"][table] = str(e)[:200]
    return out


# Allowlisted management actions. Firewall-rule ops map to (table, verb);
# system ops (reboot / firmware) are handled separately.
ACTIONS = ("add_filter_rule", "enable_filter_rule", "disable_filter_rule",
           "delete_filter_rule",
           "add_nat_rule", "enable_nat_rule", "disable_nat_rule",
           "delete_nat_rule",
           # system / firmware (v3.4.0, parity with RouterOS)
           "reboot", "check_update", "upgrade")

_SYSTEM_OPS = ("reboot", "check_update", "upgrade")

_FW_RULE_OPS = {
    "add_filter_rule":     ("filter", "add"),
    "enable_filter_rule":  ("filter", "enable"),
    "disable_filter_rule": ("filter", "disable"),
    "delete_filter_rule":  ("filter", "remove"),
    "add_nat_rule":        ("nat", "add"),
    "enable_nat_rule":     ("nat", "enable"),
    "disable_nat_rule":    ("nat", "disable"),
    "delete_nat_rule":     ("nat", "remove"),
}

# Field whitelists — keep a crafted (or AI-drafted) rule from smuggling
# arbitrary OPNsense attributes. Names are the API rule-model field names.
_FILTER_FIELDS = ("enabled", "sequence", "action", "quick", "interface",
                  "direction", "ipprotocol", "protocol", "source_net",
                  "source_port", "source_not", "destination_net",
                  "destination_port", "destination_not", "gateway", "log",
                  "description")

_NAT_FIELDS = ("enabled", "sequence", "interface", "ipprotocol", "protocol",
               "source_net", "source_port", "source_not", "destination_net",
               "destination_port", "destination_not", "target", "target_port",
               "log", "description", "nonat")


def _sanitize_rule(rule, fields):
    if not isinstance(rule, dict):
        raise OPNsenseError("rule object required")
    out = {}
    for k, v in rule.items():
        kk = str(k).replace("-", "_")
        if kk in fields and v not in (None, ""):
            # OPNsense booleans are "0"/"1" strings.
            if isinstance(v, bool):
                v = "1" if v else "0"
            out[kk] = str(v)
    return out


def _validate_uuid(u):
    """OPNsense UUIDs are hex + hyphens; reject anything else so it can't
    escape the path segment."""
    u = str(u or "")
    if not u or len(u) > 64 or not all(c in "0123456789abcdefABCDEF-" for c in u):
        raise OPNsenseError("valid rule uuid required")
    return u


def _apply(host, key, secret, verify, timeout):
    """Reload the pf ruleset so a change takes effect. The filter controller's
    apply reconfigures the whole ruleset (filter + NAT)."""
    _request(host, key, secret, "POST", "/firewall/filter/apply",
             verify=verify, timeout=timeout)


def _firewall_rule_op(host, key, secret, table, verb, arg=None, rule=None,
                      verify=False, timeout=15.0):
    """One filter/NAT rule mutation, followed by apply. add → addRule (lands
    DISABLED for review); enable/disable → toggleRule/{uuid}/{1|0};
    remove → delRule/{uuid}."""
    ctrl = _TABLES[table]
    base = f"/firewall/{ctrl}"
    if verb == "add":
        fields = _NAT_FIELDS if table == "nat" else _FILTER_FIELDS
        body = _sanitize_rule(rule, fields)
        body["enabled"] = "0"   # safety: new rules land disabled
        r = _request(host, key, secret, "POST", f"{base}/addRule",
                     body={"rule": body}, verify=verify, timeout=timeout)
        if isinstance(r, dict) and r.get("result") == "failed":
            raise OPNsenseError(f"validation failed: {json.dumps(r.get('validations', {}))[:300]}")
        _apply(host, key, secret, verify, timeout)
        return {"ok": True, "result": r}
    uuid = _validate_uuid(arg)
    if verb in ("enable", "disable"):
        flag = "1" if verb == "enable" else "0"
        _request(host, key, secret, "POST", f"{base}/toggleRule/{uuid}/{flag}",
                 verify=verify, timeout=timeout)
        _apply(host, key, secret, verify, timeout)
        return {"ok": True}
    if verb == "remove":
        _request(host, key, secret, "POST", f"{base}/delRule/{uuid}",
                 verify=verify, timeout=timeout)
        _apply(host, key, secret, verify, timeout)
        return {"ok": True}
    raise OPNsenseError(f"unknown firewall verb {verb!r}")


def _system_op(host, key, secret, act, verify=False, timeout=15.0):
    """reboot / check_update / upgrade — the RouterOS-parity system actions."""
    if act == "reboot":
        _request(host, key, secret, "POST", "/core/system/reboot",
                 verify=verify, timeout=timeout)
        return {"ok": True}
    if act == "check_update":
        # check refreshes the package metadata; status returns the verdict.
        try:
            _request(host, key, secret, "POST", "/core/firmware/check",
                     verify=verify, timeout=timeout)
        except OPNsenseError:
            pass   # check can be slow/transient; status below is what we report
        return {"ok": True, "update": _firmware_status(host, key, secret,
                                                        verify=verify, timeout=timeout)}
    if act == "upgrade":
        r = _request(host, key, secret, "POST", "/core/firmware/upgrade",
                     verify=verify, timeout=timeout)
        return {"ok": True, "result": r}
    raise OPNsenseError(f"unknown system op {act!r}")


def action(host, key, secret, act, arg=None, rule=None, verify=False,
           timeout=15.0):
    """Run one allowlisted management command. `arg` is the rule uuid; `rule`
    is the rule dict for add_*. Returns {'ok': True, ...}."""
    if act not in ACTIONS:
        raise OPNsenseError(f"action {act!r} not allowed")
    if act in _SYSTEM_OPS:
        return _system_op(host, key, secret, act, verify=verify, timeout=timeout)
    table, verb = _FW_RULE_OPS[act]
    return _firewall_rule_op(host, key, secret, table, verb,
                             arg=arg, rule=rule, verify=verify, timeout=timeout)

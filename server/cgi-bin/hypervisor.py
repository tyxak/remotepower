"""RemotePower hypervisor lifecycle drivers (v5.6.0).

Full-control (list / power / snapshots) drivers for the virtualization platforms
configured as integration instances — VMware vSphere/ESXi/vCenter, VMware Cloud
Director, and OpenShift Virtualization (KubeVirt). Proxmox keeps its own
dedicated client (proxmox_client.py); this module brings the OTHER platforms up
to comparable lifecycle functions on the same Virtualization page.

Each driver is a set of PURE functions of (inst, c[, vm_id, action, ...]) where
`inst` is the integration-instance dict (url, username, secret, verify_tls) and
`c` is the shared SSRF-safe HTTP client (api.py owns it; tests fake it). They
NEVER raise except IntegrationError for hard auth/HTTP failures. api.py owns the
routes, permission gating and audit; this module is just the per-platform API
calls + normalization, so every driver is unit-testable with a fake client.

Normalized shapes:
  VM:        {'id': str, 'name': str, 'status': running|stopped|suspended|unknown,
              'cpu': int, 'mem_mb': int, 'host': str}
  snapshot:  {'id': str, 'name': str, 'description': str, 'created': str}
  action result: {'ok': bool, 'detail': str}
"""

import base64
import json
import re
import urllib.parse

from integrations import IntegrationError


def _seg(value):
    """Reduce an id to ONE URL-quoted path segment.

    Any scheme/host/slash/traversal is stripped or percent-encoded, so an
    attacker-supplied id can never redirect the authenticated request to another
    host or a different API path (the shared SSRF guard only blocks loopback and
    cloud-metadata, NOT arbitrary public hosts — an absolute-URL id would
    otherwise exfiltrate the platform session token). Raises if nothing's left."""
    s = str(value or "").strip().rstrip("/")
    s = s.rsplit("/", 1)[-1].split("?", 1)[0].split("#", 1)[0]
    seg = urllib.parse.quote(s, safe="")
    if not seg:
        raise IntegrationError("missing or invalid id")
    return seg


# RFC-1123 label charset used by Kubernetes namespaces / resource names.
_K8S_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]{0,252}[a-z0-9]$|^[a-z0-9]$")

# Power actions each platform understands (UI filters its buttons by this).
POWER_ACTIONS = {
    "vcenter": ["start", "stop", "shutdown", "reboot", "reset", "suspend"],
    "vcloud": ["start", "stop", "shutdown", "reboot", "reset", "suspend"],
    "openshift": ["start", "stop", "restart"],
}


# ══════════════════════════════════════════════════════════════════════════════
# VMware vSphere / ESXi / vCenter  (vmware-api-session-id auth)
# ══════════════════════════════════════════════════════════════════════════════


def _vsphere_session(inst, c):
    """Authenticate to vCenter and return the session-id header dict."""
    basic = base64.b64encode(
        f"{inst.get('username') or ''}:{inst.get('secret') or ''}".encode()
    ).decode()
    resp = c.request("POST", "/api/session", headers={"Authorization": "Basic " + basic})
    if not getattr(resp, "ok", False):
        raise IntegrationError(f"vCenter auth failed: HTTP {getattr(resp, 'status', '?')}")
    token = (resp.text or "").strip().strip('"')
    if not token:
        raise IntegrationError("vCenter auth returned an empty session id")
    return {"vmware-api-session-id": token}


def vsphere_list_vms(inst, c):
    """GET /api/vcenter/vm -> normalized VM list."""
    hdr = _vsphere_session(inst, c)
    _PS = {"POWERED_ON": "running", "POWERED_OFF": "stopped", "SUSPENDED": "suspended"}
    data = c.get_json("/api/vcenter/vm", headers=hdr)
    rows = data.get("value") or data.get("vms") or [] if isinstance(data, dict) else (data or [])
    out = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        try:
            out.append(
                {
                    "id": str(r.get("vm") or ""),
                    "name": str(r.get("name") or ""),
                    "status": _PS.get(str(r.get("power_state") or "").upper(), "unknown"),
                    "cpu": int(r.get("cpu_count") or 0),
                    "mem_mb": int(r.get("memory_size_MiB") or 0),
                    "host": str(r.get("host") or ""),
                }
            )
        except (TypeError, ValueError):
            continue
    return out


def vsphere_power(inst, c, vm_id, action):
    """POST /api/vcenter/vm/{vm}/power?action=... (hard) or /guest/power (graceful)."""
    hdr = _vsphere_session(inst, c)
    if not str(vm_id or "").strip():
        return {"ok": False, "detail": "missing vm id"}
    vm = _seg(vm_id)
    hard = {"start": "start", "stop": "stop", "reset": "reset", "suspend": "suspend"}
    guest = {"shutdown": "shutdown", "reboot": "reboot"}
    if action in hard:
        path, kind = f"/api/vcenter/vm/{vm}/power?action={hard[action]}", "power"
    elif action in guest:
        path, kind = f"/api/vcenter/vm/{vm}/guest/power?action={guest[action]}", "guest"
    else:
        return {"ok": False, "detail": f"unsupported action: {action}"}
    resp = c.request("POST", path, headers=hdr)
    if getattr(resp, "ok", False):
        return {"ok": True, "detail": f"{action} ({kind}) issued for {vm}"}
    detail = f"{action} failed: HTTP {getattr(resp, 'status', '?')}"
    if kind == "guest":
        detail += " (guest power needs VMware Tools running)"
    body = (getattr(resp, "text", "") or "").strip()
    return {"ok": False, "detail": detail + (f" - {body[:200]}" if body else "")}


def vsphere_list_snapshots(inst, c, vm_id):
    """GET /api/vcenter/vm/{vm}/snapshots (thin/version-dependent) -> [] if unavailable."""
    hdr = _vsphere_session(inst, c)
    if not str(vm_id or "").strip():
        return []
    vm = _seg(vm_id)
    try:
        data = c.get_json(f"/api/vcenter/vm/{vm}/snapshots", headers=hdr)
    except IntegrationError:
        return []
    rows = (
        data.get("value") or data.get("snapshots") or [] if isinstance(data, dict) else (data or [])
    )
    out = []
    for r in rows:
        if isinstance(r, dict):
            out.append(
                {
                    "id": str(r.get("snapshot") or r.get("id") or ""),
                    "name": str(r.get("name") or ""),
                    "description": str(r.get("description") or r.get("desc") or ""),
                    "created": str(r.get("created_time") or r.get("created") or ""),
                }
            )
    return out


def vsphere_snapshot_action(inst, c, vm_id, action, name="", desc=""):
    """Create/revert/delete a snapshot via REST; degrade gracefully when unsupported."""
    hdr = _vsphere_session(inst, c)
    if not str(vm_id or "").strip():
        return {"ok": False, "detail": "missing vm id"}
    vm = _seg(vm_id)
    unsupported = {"ok": False, "detail": "snapshots require vCenter 8.x REST or SOAP"}
    snap = _seg(name) if str(name).strip() else ""
    try:
        if action == "create":
            body = json.dumps({"name": name or "snapshot", "description": desc or ""}).encode()
            resp = c.request("POST", f"/api/vcenter/vm/{vm}/snapshots", headers=hdr, body=body)
        elif action == "revert":
            if not snap:
                return {"ok": False, "detail": "revert needs a snapshot id in name"}
            resp = c.request(
                "POST", f"/api/vcenter/vm/{vm}/snapshots/{snap}?action=revert", headers=hdr
            )
        elif action == "delete":
            if not snap:
                return {"ok": False, "detail": "delete needs a snapshot id in name"}
            resp = c.request("DELETE", f"/api/vcenter/vm/{vm}/snapshots/{snap}", headers=hdr)
        else:
            return {"ok": False, "detail": f"unsupported action: {action}"}
    except IntegrationError:
        return unsupported
    if getattr(resp, "status", 0) in (404, 405, 501):
        return unsupported
    if getattr(resp, "ok", False):
        return {"ok": True, "detail": f"snapshot {action} issued for {vm}"}
    body = (getattr(resp, "text", "") or "").strip()
    return {
        "ok": False,
        "detail": f"snapshot {action} failed: HTTP {getattr(resp, 'status', '?')}"
        + (f" - {body[:200]}" if body else ""),
    }


# ══════════════════════════════════════════════════════════════════════════════
# VMware Cloud Director (vCloud)  (header-token session)
# ══════════════════════════════════════════════════════════════════════════════

_VCLOUD_ACCEPT = "application/*+json;version=37.0"


def _vcloud_hget(headers, name):
    """Case-insensitive header lookup."""
    target = name.lower()
    for k, v in (headers or {}).items():
        if isinstance(k, str) and k.lower() == target:
            return v
    return ""


def _vcloud_session(inst, c):
    """POST /api/sessions (Basic) -> token from response header."""
    basic = base64.b64encode(
        f"{inst.get('username') or ''}:{inst.get('secret') or ''}".encode()
    ).decode()
    resp = c.request(
        "POST",
        "/api/sessions",
        headers={"Authorization": "Basic " + basic, "Accept": _VCLOUD_ACCEPT},
    )
    if not getattr(resp, "ok", False):
        raise IntegrationError(f"vCloud auth failed: HTTP {getattr(resp, 'status', '?')}")
    token = _vcloud_hget(resp.headers, "X-VMWARE-VCLOUD-ACCESS-TOKEN") or _vcloud_hget(
        resp.headers, "x-vcloud-authorization"
    )
    if not token:
        raise IntegrationError("vCloud auth: no session token in response headers")
    return {"x-vcloud-authorization": token, "Accept": _VCLOUD_ACCEPT}


def _vcloud_base(vm_id):
    # Always a single quoted segment under /api/vApp/ — never a passthrough URL
    # (an absolute-URL id would exfiltrate the vCloud session token, see _seg).
    return "/api/vApp/" + _seg(vm_id)


def vcloud_list_vms(inst, c):
    """GET /api/query?type=vm&format=records -> normalized VM list."""
    auth = _vcloud_session(inst, c)
    data = c.get_json("/api/query?type=vm&format=records&pageSize=128", headers=auth)
    _PS = {"POWERED_ON": "running", "POWERED_OFF": "stopped", "SUSPENDED": "suspended"}
    recs = (data.get("record") or data.get("records") or []) if isinstance(data, dict) else []
    if isinstance(recs, dict):
        recs = [recs]
    out = []
    for r in recs or []:
        if not isinstance(r, dict):
            continue
        href = r.get("href") or ""
        vid = (str(href).rstrip("/").rsplit("/", 1)[-1] if href else "") or (r.get("id") or "")
        try:
            cpu = int(r.get("numberOfCpus") or 0)
        except (TypeError, ValueError):
            cpu = 0
        try:
            mem = int(r.get("memoryMB") or 0)
        except (TypeError, ValueError):
            mem = 0
        out.append(
            {
                "id": vid or href,
                "name": r.get("name") or "",
                "status": _PS.get(str(r.get("status") or "").upper(), "unknown"),
                "cpu": cpu,
                "mem_mb": mem,
                "host": r.get("containerName") or "",
            }
        )
    return out


def vcloud_power(inst, c, vm_id, action):
    """POST /api/vApp/{id}/power/action/{op}."""
    auth = _vcloud_session(inst, c)
    op = {
        "start": "powerOn",
        "stop": "powerOff",
        "shutdown": "shutdown",
        "reboot": "reboot",
        "reset": "reset",
        "suspend": "suspend",
    }.get(action)
    if not op:
        return {"ok": False, "detail": f"unknown power action: {action}"}
    resp = c.request("POST", _vcloud_base(vm_id) + "/power/action/" + op, headers=auth)
    return {
        "ok": bool(getattr(resp, "ok", False)),
        "detail": f"{op} -> HTTP {getattr(resp, 'status', '?')}",
    }


def vcloud_list_snapshots(inst, c, vm_id):
    """GET /api/vApp/{id}/snapshotSection (vCloud allows one snapshot per VM)."""
    auth = _vcloud_session(inst, c)
    try:
        data = c.get_json(_vcloud_base(vm_id) + "/snapshotSection", headers=auth)
    except IntegrationError:
        return []
    if not isinstance(data, dict):
        return []
    snap = data.get("snapshot")
    if isinstance(snap, list):
        snap = snap[0] if snap else None
    if not isinstance(snap, dict):
        return []
    return [
        {
            "id": str(vm_id),
            "name": snap.get("name") or "snapshot",
            "description": snap.get("description") or data.get("description") or "",
            "created": snap.get("created") or "",
        }
    ]


def vcloud_snapshot_action(inst, c, vm_id, action, name="", desc=""):
    """createSnapshot / revertToCurrentSnapshot / removeAllSnapshots."""
    auth = _vcloud_session(inst, c)
    base = _vcloud_base(vm_id)
    body = None
    if action == "create":
        path = base + "/action/createSnapshot"
        body = json.dumps(
            {
                "name": name or "snapshot",
                "description": desc or "",
                "memory": False,
                "quiesce": False,
            }
        ).encode()
    elif action == "revert":
        path = base + "/action/revertToCurrentSnapshot"
    elif action == "delete":
        path = base + "/action/removeAllSnapshots"
    else:
        return {"ok": False, "detail": f"unknown snapshot action: {action}"}
    headers = dict(auth)
    if body is not None:
        headers["Content-Type"] = _VCLOUD_ACCEPT
    resp = c.request("POST", path, headers=headers, body=body)
    return {
        "ok": bool(getattr(resp, "ok", False)),
        "detail": f"snapshot {action} -> HTTP {getattr(resp, 'status', '?')}",
    }


# ══════════════════════════════════════════════════════════════════════════════
# OpenShift Virtualization / KubeVirt  (Bearer token)
# ══════════════════════════════════════════════════════════════════════════════


def _os_hdr(inst):
    return {"Authorization": "Bearer " + str(inst.get("secret") or "")}


def _os_mem_to_mb(val):
    """Parse a Kubernetes memory quantity (e.g. '2Gi','512Mi') into integer MiB."""
    try:
        s = str(val or "").strip()
        if not s:
            return 0
        bin_u = {"Ki": 1.0 / 1024, "Mi": 1.0, "Gi": 1024.0, "Ti": 1024.0 * 1024}
        dec_u = {
            "K": 1000.0 / (1024 * 1024),
            "M": 1000.0**2 / (1024 * 1024),
            "G": 1000.0**3 / (1024 * 1024),
            "T": 1000.0**4 / (1024 * 1024),
        }
        for suf, mul in bin_u.items():
            if s.endswith(suf):
                return int(float(s[: -len(suf)]) * mul)
        for suf, mul in dec_u.items():
            if s.endswith(suf):
                return int(float(s[: -len(suf)]) * mul)
        return int(float(s) / (1024 * 1024))
    except (ValueError, TypeError):
        return 0


def _os_split_id(vm_id):
    """Split '<ns>/<name>'; raise IntegrationError if malformed."""
    s = str(vm_id or "").strip()
    if s.count("/") != 1:
        raise IntegrationError("vm_id must be '<namespace>/<name>'")
    ns, name = s.split("/", 1)
    # Both halves MUST be RFC-1123 labels — this also blocks '..', encoded
    # slashes and any other path-traversal into a different k8s API path.
    if not (_K8S_NAME.match(ns) and _K8S_NAME.match(name)):
        raise IntegrationError("namespace/name must be lowercase RFC-1123 names")
    return ns, name


def openshift_list_vms(inst, c):
    """GET /apis/kubevirt.io/v1/virtualmachines (cluster-wide)."""
    data = c.get_json("/apis/kubevirt.io/v1/virtualmachines", headers=_os_hdr(inst))
    out = []
    for item in (data.get("items") or []) if isinstance(data, dict) else []:
        try:
            meta = item.get("metadata") or {}
            ns, nm = meta.get("namespace") or "", meta.get("name") or ""
            if not nm:
                continue
            spec = item.get("spec") or {}
            printable = str((item.get("status") or {}).get("printableStatus") or "").lower()
            if "running" in printable:
                status = "running"
            elif "stopped" in printable or "halted" in printable:
                status = "stopped"
            elif isinstance(spec.get("running"), bool):
                status = "running" if spec.get("running") else "stopped"
            else:
                status = "unknown"
            domain = (((spec.get("template") or {}).get("spec") or {}).get("domain")) or {}
            try:
                cpu = int((domain.get("cpu") or {}).get("cores") or 1)
            except (ValueError, TypeError):
                cpu = 1
            mem_mb = _os_mem_to_mb(
                ((domain.get("resources") or {}).get("requests") or {}).get("memory")
            )
            out.append(
                {
                    "id": ns + "/" + nm,
                    "name": nm,
                    "status": status,
                    "cpu": cpu,
                    "mem_mb": mem_mb,
                    "host": ns,
                }
            )
        except (AttributeError, TypeError):
            continue
    return out


def openshift_power(inst, c, vm_id, action):
    """PUT subresources.kubevirt.io start/stop/restart, fallback merge-patch spec.running."""
    ns, name = _os_split_id(vm_id)
    act = str(action or "").lower()
    note = ""
    if act == "start":
        sub = "start"
    elif act in ("stop", "shutdown"):
        sub = "stop"
    elif act in ("restart", "reboot", "reset"):
        sub = "restart"
    elif act == "suspend":
        sub, note = "stop", " (suspend mapped to stop; KubeVirt has no suspend here)"
    else:
        return {"ok": False, "detail": "unknown action: " + act}
    hdr = dict(_os_hdr(inst))
    hdr["Content-Type"] = "application/json"
    sub_path = f"/apis/subresources.kubevirt.io/v1/namespaces/{ns}/virtualmachines/{name}/{sub}"
    resp = c.request("PUT", sub_path, headers=hdr, body=b"{}")
    if resp is not None and getattr(resp, "status", None) != 404:
        return {
            "ok": bool(getattr(resp, "ok", False)),
            "detail": f"{sub} {vm_id} -> HTTP {getattr(resp, 'status', '?')}{note}",
        }
    if sub == "restart":
        return {
            "ok": False,
            "detail": "restart subresource 404 and no merge-patch equivalent" + note,
        }
    phdr = dict(_os_hdr(inst))
    phdr["Content-Type"] = "application/merge-patch+json"
    body = json.dumps({"spec": {"running": sub == "start"}}).encode()
    presp = c.request(
        "PATCH",
        f"/apis/kubevirt.io/v1/namespaces/{ns}/virtualmachines/{name}",
        headers=phdr,
        body=body,
    )
    return {
        "ok": bool(getattr(presp, "ok", False)),
        "detail": f"merge-patch spec.running={sub == 'start'} -> HTTP {getattr(presp, 'status', '?')}{note}",
    }


def openshift_list_snapshots(inst, c, vm_id):
    """GET snapshot.kubevirt.io/v1beta1 virtualmachinesnapshots filtered to this VM."""
    ns, name = _os_split_id(vm_id)
    try:
        data = c.get_json(
            f"/apis/snapshot.kubevirt.io/v1beta1/namespaces/{ns}/virtualmachinesnapshots",
            headers=_os_hdr(inst),
        )
    except IntegrationError:
        return []
    out = []
    for item in (data.get("items") or []) if isinstance(data, dict) else []:
        try:
            meta, spec = item.get("metadata") or {}, item.get("spec") or {}
            if (spec.get("source") or {}).get("name") != name:
                continue
            out.append(
                {
                    "id": meta.get("name") or "",
                    "name": meta.get("name") or "",
                    "description": (
                        (item.get("status") or {}).get("phase") or spec.get("description") or ""
                    ),
                    "created": meta.get("creationTimestamp") or "",
                }
            )
        except (AttributeError, TypeError):
            continue
    return out


def openshift_snapshot_action(inst, c, vm_id, action, name="", desc=""):
    """create VirtualMachineSnapshot / revert via VirtualMachineRestore / delete."""
    ns, vm_name = _os_split_id(vm_id)
    act = str(action or "").lower()
    hdr = dict(_os_hdr(inst))
    hdr["Content-Type"] = "application/json"
    base = f"/apis/snapshot.kubevirt.io/v1beta1/namespaces/{ns}"
    snap = str(name or "").strip()
    if act == "create":
        snap = snap or f"{vm_name}-snap"
        obj = {
            "apiVersion": "snapshot.kubevirt.io/v1beta1",
            "kind": "VirtualMachineSnapshot",
            "metadata": {"name": snap, "namespace": ns},
            "spec": {
                "source": {"apiGroup": "kubevirt.io", "kind": "VirtualMachine", "name": vm_name}
            },
        }
        resp = c.request(
            "POST", base + "/virtualmachinesnapshots", headers=hdr, body=json.dumps(obj).encode()
        )
        return {
            "ok": bool(getattr(resp, "ok", False)),
            "detail": f"create snapshot {snap} -> HTTP {getattr(resp, 'status', '?')}",
        }
    if act == "revert":
        if not snap:
            return {"ok": False, "detail": "revert requires snapshot name"}
        obj = {
            "apiVersion": "snapshot.kubevirt.io/v1beta1",
            "kind": "VirtualMachineRestore",
            "metadata": {"name": f"{vm_name}-restore-{snap}", "namespace": ns},
            "spec": {
                "target": {"apiGroup": "kubevirt.io", "kind": "VirtualMachine", "name": vm_name},
                "virtualMachineSnapshotName": snap,
            },
        }
        resp = c.request(
            "POST", base + "/virtualmachinerestores", headers=hdr, body=json.dumps(obj).encode()
        )
        return {
            "ok": bool(getattr(resp, "ok", False)),
            "detail": f"revert to {snap} -> HTTP {getattr(resp, 'status', '?')}",
        }
    if act == "delete":
        if not snap:
            return {"ok": False, "detail": "delete requires snapshot name"}
        resp = c.request("DELETE", base + "/virtualmachinesnapshots/" + _seg(snap), headers=hdr)
        return {
            "ok": bool(getattr(resp, "ok", False)),
            "detail": f"delete snapshot {snap} -> HTTP {getattr(resp, 'status', '?')}",
        }
    return {"ok": False, "detail": "unknown snapshot action: " + act}


# ── lifecycle registry: connector type -> driver functions ───────────────────
LIFECYCLE = {
    "vcenter": {
        "list_vms": vsphere_list_vms,
        "power": vsphere_power,
        "list_snapshots": vsphere_list_snapshots,
        "snapshot_action": vsphere_snapshot_action,
    },
    "vcloud": {
        "list_vms": vcloud_list_vms,
        "power": vcloud_power,
        "list_snapshots": vcloud_list_snapshots,
        "snapshot_action": vcloud_snapshot_action,
    },
    "openshift": {
        "list_vms": openshift_list_vms,
        "power": openshift_power,
        "list_snapshots": openshift_list_snapshots,
        "snapshot_action": openshift_snapshot_action,
    },
}


def has_lifecycle(type_):
    return type_ in LIFECYCLE


def power_actions(type_):
    return POWER_ACTIONS.get(type_, [])

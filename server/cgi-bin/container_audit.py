"""RemotePower — a hardening audit of how each container was started (7.4.9).

A container that runs privileged, shares the host's process or network namespace, holds the container engine's socket or
mounts the host's `/etc` is as exposed as the host, whatever the image does. Nothing in the product looked at how containers
were started, only at whether they were running. The Linux agent now reads each container's run options once from `inspect`
(they cannot change while the container exists) and reports a small set of plain facts. This module keeps those facts and
works out the findings from them, so a new rule or a corrected one is a server change and needs no agent update.

The rules follow the container checks of the CIS Docker benchmark that can be decided from a container's own configuration
(privileged, capabilities, sensitive mounts, host namespaces, devices, seccomp and AppArmor, a writable root filesystem, new
privileges, user, memory limit, health check, published ports). They are a review aid: a finding says what the container can
do, not that it is wrong. Some containers need it (a metrics agent mounts `/`, a manager mounts the engine socket), so an
administrator can accept a finding for one container and it stops counting.

Everything in the facts is data from the host: names and paths are length-limited and stripped of control characters, lists are
capped, and a number is a number. Nothing here imports api.
"""

from __future__ import annotations

import re
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low")
RANK = {s: i for i, s in enumerate(SEVERITIES)}  # 0 is the worst

MAX_CAPS = 40
MAX_MOUNTS = 24
MAX_DEVICES = 16
MAX_PORTS = 24
MAX_OPTS = 16

# rule id -> (severity when it is raised without a finer verdict, title)
RULES: dict[str, tuple[str, str]] = {
    "privileged": ("critical", "Runs privileged"),
    "engine_socket": ("critical", "Container engine socket mounted"),
    "sensitive_mount": ("high", "Sensitive host directory mounted"),
    "host_pid": ("high", "Shares the host's process namespace"),
    "host_network": ("high", "Uses the host's network"),
    "caps_high": ("high", "Dangerous capabilities added"),
    "seccomp_off": ("high", "Seccomp filtering disabled"),
    "apparmor_off": ("medium", "AppArmor confinement disabled"),
    "host_ipc": ("medium", "Shares the host's IPC namespace"),
    "host_userns": ("medium", "Shares the host's user namespace"),
    "caps_medium": ("medium", "Extra network or system capabilities added"),
    "devices": ("medium", "Host hardware passed through"),
    "open_port": ("low", "Port published on all interfaces"),
    "new_privileges": ("low", "Can gain new privileges"),
    "runs_as_root": ("low", "Runs as root"),
    "writable_rootfs": ("low", "Root filesystem is writable"),
    "no_memory_limit": ("low", "No memory limit"),
    "no_healthcheck": ("low", "No health check"),
    "latest_tag": ("low", "Image tag is not pinned"),
}

_HIGH_CAPS = frozenset(
    {
        "ALL",
        "SYS_ADMIN",
        "SYS_MODULE",
        "SYS_PTRACE",
        "SYS_RAWIO",
        "BPF",
        "DAC_READ_SEARCH",
        "SYS_BOOT",
        "MKNOD",
    }
)
_MEDIUM_CAPS = frozenset(
    {
        "NET_ADMIN",
        "NET_RAW",
        "SYS_TIME",
        "SYSLOG",
        "MAC_ADMIN",
        "MAC_OVERRIDE",
        "PERFMON",
        "SYS_CHROOT",
        "LINUX_IMMUTABLE",
    }
)
_SOCKETS = frozenset(
    {
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/var/run/podman/podman.sock",
        "/run/podman/podman.sock",
        "/var/run/containerd/containerd.sock",
        "/run/containerd/containerd.sock",
        "/var/run/crio/crio.sock",
        "/run/crio/crio.sock",
    }
)
# Directories that are the host's own: mounting the directory itself hands the container the host's files. A file inside one
# (/etc/localtime) is not flagged, which matches how the CIS benchmark reads the check.
_SENSITIVE_DIRS = frozenset(
    {
        "/",
        "/boot",
        "/dev",
        "/etc",
        "/lib",
        "/lib64",
        "/proc",
        "/sys",
        "/usr",
        "/bin",
        "/sbin",
        "/root",
        "/var/lib/docker",
        "/var/lib/containers",
        "/var/run",
        "/run",
    }
)
_RISKY_DEVICE_RE = re.compile(
    r"^/dev/(?:sd[a-z]|nvme|vd[a-z]|hd[a-z]|mmcblk|loop|dm-|md\d|mapper/|disk/|mem$|kmem$|port$)"
)
# A database or admin service published on every interface is worth more than a web port.
_RISKY_PORTS = frozenset(
    {22, 23, 2375, 2376, 3306, 3389, 5432, 5900, 5984, 6379, 9200, 11211, 27017, 1433}
)
_ALL_IFACES = frozenset({"", "0.0.0.0", "::", "[::]"})
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
_MODE_OK = re.compile(r"^[A-Za-z0-9_.:/@=-]{0,64}$")


def _text(v: Any, cap: int) -> str:
    if not isinstance(v, str):
        return ""
    return _CTRL_RE.sub(" ", v).strip()[:cap]


def _strs(v: Any, n: int, cap: int) -> list[str]:
    if not isinstance(v, list):
        return []
    out: list[str] = []
    for x in v[:n]:
        t = _text(x, cap)
        if t:
            out.append(t)
    return out


def _bool(v: Any) -> bool:
    return v is True


def _path(v: Any) -> str:
    p = _text(v, 255)
    return p.rstrip("/") or ("/" if p.startswith("/") else "")


def clean_facts(raw: Any) -> dict[str, Any] | None:
    """The run options a host reported for one container, kept as plain values. None when there is nothing usable, which is
    how a container the agent could not inspect looks: the audit says "not audited" for it instead of "no findings".
    """
    # The agent leaves out every value that is the default, so a container with plain options sends little more than the marker
    # `v`. Without the marker a report with no run options at all is told apart from one that never had any inspected.
    if not isinstance(raw, dict) or isinstance(raw.get("v"), bool) or raw.get("v") != 1:
        return None  # True == 1 in Python, so a boolean is ruled out first
    mounts: list[dict[str, Any]] = []
    for m in raw.get("mounts", [])[:MAX_MOUNTS] if isinstance(raw.get("mounts"), list) else []:
        if not isinstance(m, dict):
            continue
        src = _path(m.get("src"))
        if not src:
            continue
        mounts.append(
            {
                "src": src,
                "dst": _path(m.get("dst")),
                "rw": m.get("rw") is not False,
            }
        )
    ports: list[dict[str, Any]] = []
    for p in raw.get("ports", [])[:MAX_PORTS] if isinstance(raw.get("ports"), list) else []:
        if not isinstance(p, dict):
            continue
        port = p.get("port")
        if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
            continue
        ports.append(
            {"port": port, "proto": _text(p.get("proto"), 8) or "tcp", "ip": _text(p.get("ip"), 45)}
        )
    mode_keys = ("net_mode", "pid_mode", "ipc_mode", "userns_mode")
    facts: dict[str, Any] = {
        "v": 1,
        "privileged": _bool(raw.get("privileged")),
        "readonly_rootfs": _bool(raw.get("readonly_rootfs")),
        "has_healthcheck": _bool(raw.get("has_healthcheck")),
        "cap_add": [
            c.upper().removeprefix("CAP_") for c in _strs(raw.get("cap_add"), MAX_CAPS, 32)
        ],
        "cap_drop": [
            c.upper().removeprefix("CAP_") for c in _strs(raw.get("cap_drop"), MAX_CAPS, 32)
        ],
        "security_opt": _strs(raw.get("security_opt"), MAX_OPTS, 80),
        "devices": _strs(raw.get("devices"), MAX_DEVICES, 96),
        "user": _text(raw.get("user"), 64),
        "mounts": mounts,
        "ports": ports,
    }
    for k in mode_keys:
        v = _text(raw.get(k), 64)
        facts[k] = v if _MODE_OK.match(v) else ""
    return facts


def _is_root(user: str) -> bool:
    return user.split(":", 1)[0].strip().lower() in ("", "0", "root")


def _tag_unpinned(tag: str) -> bool:
    return tag.strip().lower() in ("", "latest")


def _finding(rule: str, severity: str, detail: str = "") -> dict[str, str]:
    return {"rule": rule, "severity": severity, "title": RULES[rule][1], "detail": detail[:240]}


def evaluate(item: Any) -> list[dict[str, str]] | None:
    """The findings for one container record (as `containers.normalize_container` keeps it), worst first. None when the
    container was not audited (its run options were never reported)."""
    if not isinstance(item, dict):
        return None
    f = item.get("audit")
    if not isinstance(f, dict):
        return None
    out: list[dict[str, str]] = []

    if f.get("privileged"):
        out.append(_finding("privileged", "critical", "all capabilities and all host hardware"))
    socks = [m["src"] for m in f.get("mounts", []) if m.get("src") in _SOCKETS]
    if socks:
        out.append(_finding("engine_socket", "critical", ", ".join(dict.fromkeys(socks))))
    # a mounted host directory: the root of the host writable is as bad as privileged; the rest are worse the more writable
    sens: list[tuple[str, bool]] = [
        (m["src"], bool(m.get("rw")))
        for m in f.get("mounts", [])
        if m.get("src") in _SENSITIVE_DIRS
    ]
    if sens:
        rw_root = any(s == "/" and rw for s, rw in sens)
        any_rw = any(rw for _s, rw in sens)
        only_root_ro = all(s == "/" for s, _rw in sens) and not any_rw
        sev = "critical" if rw_root else "high" if any_rw else "medium" if only_root_ro else "low"
        out.append(
            _finding(
                "sensitive_mount",
                sev,
                ", ".join(f"{s} ({'read-write' if rw else 'read-only'})" for s, rw in sens),
            )
        )
    if f.get("pid_mode") == "host":
        out.append(_finding("host_pid", "high"))
    if f.get("net_mode") == "host":
        out.append(_finding("host_network", "high"))
    caps = [c for c in f.get("cap_add", []) if c]
    high = [c for c in caps if c in _HIGH_CAPS]
    if high and not f.get("privileged"):
        out.append(_finding("caps_high", "high", ", ".join(high)))
    med = [c for c in caps if c in _MEDIUM_CAPS]
    if med and not high and not f.get("privileged"):
        out.append(_finding("caps_medium", "medium", ", ".join(med)))
    opts = [o.lower().replace(":", "=") for o in f.get("security_opt", [])]
    if any(o == "seccomp=unconfined" for o in opts):
        out.append(_finding("seccomp_off", "high"))
    if any(o == "apparmor=unconfined" for o in opts):
        out.append(_finding("apparmor_off", "medium"))
    if f.get("ipc_mode") == "host":
        out.append(_finding("host_ipc", "medium"))
    if f.get("userns_mode") == "host":
        out.append(_finding("host_userns", "medium"))
    devs = [d for d in f.get("devices", []) if d]
    if devs:
        risky = [d for d in devs if _RISKY_DEVICE_RE.match(d)]
        out.append(_finding("devices", "medium" if risky else "low", ", ".join(devs[:8])))
    exposed = [p for p in f.get("ports", []) if str(p.get("ip", "")) in _ALL_IFACES]
    if exposed:
        sev = "medium" if any(p["port"] in _RISKY_PORTS for p in exposed) else "low"
        out.append(
            _finding(
                "open_port",
                sev,
                ", ".join(f"{p['port']}/{p.get('proto') or 'tcp'}" for p in exposed[:10]),
            )
        )
    if not f.get("privileged") and not any(
        o in ("no-new-privileges", "no-new-privileges=true") for o in opts
    ):
        out.append(_finding("new_privileges", "low"))
    if _is_root(str(f.get("user", ""))):
        out.append(_finding("runs_as_root", "low"))
    if not f.get("readonly_rootfs"):
        out.append(_finding("writable_rootfs", "low"))
    if not item.get("mem_limit_bytes"):
        out.append(_finding("no_memory_limit", "low"))
    if not f.get("has_healthcheck"):
        out.append(_finding("no_healthcheck", "low"))
    if _tag_unpinned(str(item.get("tag") or "")):
        out.append(_finding("latest_tag", "low", str(item.get("image") or "")[:120]))
    out.sort(key=lambda x: (RANK.get(x["severity"], 9), x["rule"]))
    return out


def count(findings: list[dict[str, Any]]) -> dict[str, int]:
    """{critical, high, medium, low} for a list of findings."""
    c = {s: 0 for s in SEVERITIES}
    for x in findings:
        if isinstance(x, dict) and x.get("severity") in c:
            c[x["severity"]] += 1
    return c


def worst(findings: list[dict[str, Any]]) -> str:
    """The worst severity in a list, or '' for none."""
    c = count(findings)
    return next((s for s in SEVERITIES if c[s]), "")

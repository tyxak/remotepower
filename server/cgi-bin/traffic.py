"""RemotePower: the traffic view (8.0.0).

What a host's established TCP connections moved, as its agent samples it, and the plain rules the server applies to a sample: clean it, merge it into the host's history,
name a port, say what kind of address it is, add up the fleet and match a watch list. Stdlib only. Nothing here reads a store or touches the network, so each rule is
tested with a literal.

A sample is the work of one agent between two reports: one row for each (direction, remote address, service port, program) with the number of connections and the bytes each
way since the last sample, the busiest MAX_ROWS rows, and the sum of the rest as `other`. It holds no payload, no host name and no address of this host. The bytes are the
kernel's own count for each TCP socket (`ss -i`), so UDP has no volume here, and a connection that opened and closed between two samples is not seen.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

MAX_ROWS = 100  # rows kept for a host, the busiest first
SERIES_MAX = 288  # points kept for a host's chart: a day at one every five minutes
SERIES_GAP = 300  # seconds between two points of the chart
SEEN_MAX = 300  # public remote addresses remembered for a host, to tell a new one from an old one
NEW_FOR_S = 86400  # an address counts as new for a day after a host first used it
LEARN_S = 3600  # the first hour of a host's samples is its baseline: nothing in it is new
MAX_WATCH = 100  # entries in the watch list
ALERT_REPEAT_S = (
    6 * 3600
)  # a watched connection that is still there raises its alert again after this long
ALERT_MAX = 10  # alerts one host's sample may raise; what is left comes due at the next sample
ALERTED_MAX = (
    200  # matches remembered for a host, so the record of what was raised cannot grow without bound
)
MAX_BYTES = 2**50
WATCH_KINDS = ("ip", "cidr", "port", "proc")
ERRORS = (
    "no-ss",
    "ss-failed",
    "no-counters",
)  # what an agent may say when it could not read its connections; any other text is dropped

_PROC_RX = re.compile(r"[^\x20-\x7e]")

# Names for the ports a person expects to recognise, and nothing else: a port that is not here has no name. The services file of the machine the server runs on is not read.
# It names 3000 "hbci" and 8006 "wpl-analytics" (registered once, used by Gitea and by Proxmox), and the same port would read differently on the next distribution; an empty
# name is a fair answer for a port that several things use.
SERVICES = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    69: "tftp",
    80: "http",
    88: "kerberos",
    110: "pop3",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    139: "netbios",
    143: "imap",
    161: "snmp",
    179: "bgp",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    514: "syslog",
    515: "lpd",
    587: "submission",
    636: "ldaps",
    853: "dns-over-tls",
    873: "rsync",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1194: "openvpn",
    1433: "mssql",
    1521: "oracle",
    1723: "pptp",
    1883: "mqtt",
    2049: "nfs",
    2375: "docker",
    2376: "docker-tls",
    2379: "etcd",
    3128: "squid",
    3306: "mysql",
    3389: "rdp",
    4369: "epmd",
    5060: "sip",
    5061: "sips",
    5222: "xmpp",
    5432: "postgresql",
    5672: "amqp",
    5900: "vnc",
    5984: "couchdb",
    6379: "redis",
    6443: "kubernetes-api",
    6667: "irc",
    8080: "http-alt",
    8086: "influxdb",
    8443: "https-alt",
    8883: "mqtts",
    9090: "prometheus",
    9092: "kafka",
    9200: "elasticsearch",
    9418: "git",
    10250: "kubelet",
    11211: "memcached",
    15672: "rabbitmq",
    27017: "mongodb",
    51820: "wireguard",
    548: "afp",
    631: "ipp",
    3260: "iscsi",
    5353: "mdns",
    5985: "winrm",
    5986: "winrm-tls",
    8006: "proxmox",
    8007: "proxmox-backup",
    8096: "jellyfin",
    8123: "home-assistant",
    8384: "syncthing",
    22000: "syncthing-sync",
    25565: "minecraft",
    32400: "plex",
}


def service_of(port: Any) -> str:
    """The name of a TCP port from the table above, else an empty string."""
    if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
        return ""
    return SERVICES.get(port, "")


def scope_of(ip: Any) -> str:
    """What kind of address this is: public, private (including the shared address space of a carrier), link-local, multicast, loopback, or unknown."""
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return "unknown"
    if a.is_loopback:
        return "loopback"
    if a.is_link_local:
        return "link-local"
    if a.is_multicast:
        return "multicast"
    return "public" if a.is_global else "private"


def _count(value: Any, hi: int = MAX_BYTES) -> int | None:
    """A whole number from 0 to hi, or None. A float, a boolean and text are not counts, however they print."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > hi:
        return None
    return value


def _address(value: Any) -> str | None:
    """An address as the shortest text that names it, or None. The loopback, the unspecified address and the multicast ranges are no remote host."""
    try:
        a = ipaddress.ip_address(str(value).split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped is not None:
        a = a.ipv4_mapped
    if a.is_loopback or a.is_unspecified or a.is_multicast:
        return None
    return a.compressed


def _program(value: Any) -> str:
    """The name of the program on the socket, cut to printable ASCII and 48 characters. It came from a host, so it is only ever shown with escaping."""
    return _PROC_RX.sub("", str(value or "")).strip()[:48]


def clean_row(raw: Any) -> dict[str, Any] | None:
    """One sample row as this server keeps it, or None when it is not one: a direction, a usable remote address, a port, a count of connections and the two byte counts."""
    if not isinstance(raw, dict):
        return None
    direction = raw.get("d")
    ip = _address(raw.get("ip"))
    port = _count(raw.get("port"), 65535)
    n, tx, rx = _count(raw.get("n"), 10**6), _count(raw.get("tx")), _count(raw.get("rx"))
    if (
        direction not in ("in", "out")
        or ip is None
        or not port
        or n is None
        or tx is None
        or rx is None
    ):
        return None
    return {
        "d": direction,
        "ip": ip,
        "port": port,
        "proc": _program(raw.get("proc")),
        "n": max(1, n),
        "tx": tx,
        "rx": rx,
    }


def clean_sample(raw: Any, now: int | None = None) -> dict[str, Any] | None:
    """What a host reported, as the server keeps it, or None when there is nothing usable. Rows that are not rows are dropped, the busiest MAX_ROWS are kept and the rest
    are added into `other`, the totals are the sums of the rows (the host's own totals are not read), the time is the server's (`now`, not the host's clock) and the window
    is a number of seconds from 1 to an hour."""
    if not isinstance(raw, dict):
        return None
    rows_in, other_raw = raw.get("rows"), raw.get("other")
    rows = [
        r
        for r in (
            clean_row(x) for x in (rows_in[: MAX_ROWS * 2] if isinstance(rows_in, list) else [])
        )
        if r
    ]
    rows.sort(key=lambda r: (-(r["tx"] + r["rx"]), -r["n"], r["ip"], r["port"]))
    kept, rest = rows[:MAX_ROWS], rows[MAX_ROWS:]
    other_in: dict[str, Any] = other_raw if isinstance(other_raw, dict) else {}
    other = {
        "n": (_count(other_in.get("n"), 10**7) or 0) + sum(r["n"] for r in rest),
        "tx": (_count(other_in.get("tx")) or 0) + sum(r["tx"] for r in rest),
        "rx": (_count(other_in.get("rx")) or 0) + sum(r["rx"] for r in rest),
        "rows": (_count(other_in.get("rows"), 10**7) or 0) + len(rest),
    }
    win = raw.get("win")
    # comparisons only: NaN, infinity and an integer too big for a float all fail `1 <= win <= 3600`, and math.isfinite() raises on the last
    if isinstance(win, bool) or not isinstance(win, (int, float)) or not 1 <= win <= 3600:
        return None
    conns = _count(raw.get("conns"), 10**7)
    out = {
        "at": int(now or 0),
        "win": round(float(win), 1),
        "rows": kept,
        "other": other,
        "conns": conns if conns is not None else sum(r["n"] for r in kept) + other["n"],
        "tx": sum(r["tx"] for r in kept) + other["tx"],
        "rx": sum(r["rx"] for r in kept) + other["rx"],
        "trunc": raw.get("trunc") is True,
    }
    err = raw.get("err")
    if isinstance(err, str) and err in ERRORS:
        out["err"] = err
    return out


def merge(prev: Any, sample: dict[str, Any], now: int) -> dict[str, Any]:
    """The host's stored record after this sample.

    The record keeps the latest sample, a chart of one point every SERIES_GAP seconds ([time, bytes/s out, bytes/s in, connections], SERIES_MAX points) and the first time
    each public remote address was seen (SEEN_MAX, the oldest forgotten first). `first` is the time of the host's first sample: is_new() reads the first hour after it as
    the host's baseline, so that hour does not mark every address it used as new."""
    prev = prev if isinstance(prev, dict) else {}
    series = [p for p in (prev.get("series") or []) if isinstance(p, list) and len(p) == 4]
    first = _count(prev.get("first"), 4 * 10**9) or now
    seen_in = prev.get("seen")
    seen = (
        {k: v for k, v in seen_in.items() if isinstance(k, str) and isinstance(v, int)}
        if isinstance(seen_in, dict)
        else {}
    )
    # a sample that says the connections could not be read has no volume to plot: a flat point would read as "no traffic"
    if not sample.get("err") and (not series or now - series[-1][0] >= SERIES_GAP):
        win = max(1.0, sample["win"])
        series.append([now, round(sample["tx"] / win), round(sample["rx"] / win), sample["conns"]])
    for r in sample["rows"]:
        if r["ip"] not in seen and scope_of(r["ip"]) == "public":
            seen[r["ip"]] = now
    if len(seen) > SEEN_MAX:
        seen = dict(sorted(seen.items(), key=lambda kv: kv[1])[-SEEN_MAX:])
    return {
        "first": first,
        "at": now,
        "sample": sample,
        "series": series[-SERIES_MAX:],
        "seen": seen,
    }


def is_new(record: Any, ip: str, now: int) -> bool:
    """True when this host first used the public address `ip` after its baseline hour and within the last NEW_FOR_S seconds."""
    if not isinstance(record, dict) or not isinstance(record.get("seen"), dict):
        return False
    at, first = record["seen"].get(ip), record.get("first")
    if (
        isinstance(at, bool)
        or not isinstance(at, int)
        or isinstance(first, bool)
        or not isinstance(first, int)
    ):
        return False
    return at - first >= LEARN_S and 0 <= now - at <= NEW_FOR_S


def clean_watch(raw: Any) -> tuple[list[dict[str, str]], str]:
    """(entries, error) for a watch list a person sent: each entry is {kind, value, label} with a kind of ip, cidr, port or proc. The first entry that is not one gives
    the message; nothing is kept when there is a message. At most MAX_WATCH entries."""
    if raw is None:
        return [], ""
    if not isinstance(raw, list):
        return [], "the watch list must be a list"
    out, seen = [], set()
    for i, e in enumerate(raw):
        if not isinstance(e, dict):
            return [], "entry %d is not an object" % (i + 1)
        kind, value = (
            e.get("kind"),
            str(e.get("value") if e.get("value") is not None else "").strip(),
        )
        if kind not in WATCH_KINDS:
            return [], "entry %d: the kind must be one of ip, cidr, port or proc" % (i + 1)
        if kind == "ip":
            ip = _address(value)
            if ip is None:
                return [], "entry %d: %r is not an address" % (i + 1, value[:40])
            value = ip
        elif kind == "cidr":
            try:
                net = ipaddress.ip_network(value, strict=False)
            except ValueError:
                return [], "entry %d: %r is not a network" % (i + 1, value[:40])
            value = net.compressed
        elif kind == "port":
            if not value.isdigit() or not 0 < int(value) < 65536:
                return [], "entry %d: a port is a number from 1 to 65535" % (i + 1)
            value = str(int(value))
        else:
            value = _program(value)
            if not value:
                return [], "entry %d: a program needs a name" % (i + 1)
        label = _PROC_RX.sub("", str(e.get("label") or "")).strip()[:60]
        if (kind, value) in seen:
            continue
        seen.add((kind, value))
        out.append({"kind": kind, "value": value, "label": label})
        if len(out) > MAX_WATCH:
            return [], "at most %d entries" % MAX_WATCH
    return out, ""


def watched(row: Any, watch: Any) -> list[dict[str, str]]:
    """The entries of the watch list that this row matches: its address (or a network that holds it), its service port or its program. A row or an entry that is not a
    map matches nothing: the rows come from a store and the entries from the settings, and either can have been edited by hand.
    """
    if not isinstance(row, dict) or not isinstance(watch, list):
        return []
    hits = []
    try:
        addr = ipaddress.ip_address(row["ip"])
    except (KeyError, ValueError, TypeError):
        addr = None
    prog = str(row.get("proc") or "").lower()
    for w in watch:
        if not isinstance(w, dict):
            continue
        kind, value = w.get("kind"), str(w.get("value") if w.get("value") is not None else "")
        if kind == "ip" and row.get("ip") == value:
            hits.append(w)
        elif kind == "cidr" and addr is not None:
            try:
                if addr in ipaddress.ip_network(value, strict=False):
                    hits.append(w)
            except ValueError:
                pass
        elif kind == "port" and str(row.get("port")) == value:
            hits.append(w)
        elif kind == "proc" and value and prog == value.lower():
            hits.append(w)
    return hits


def num(value: Any) -> int:
    """A count from a store: the number, or 0 when it is not a whole non-negative one (a value of another kind was put there by hand or by an older build)."""
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def stored_rows(sample: Any) -> list[dict[str, Any]]:
    """The rows of a stored sample that are rows. A reader subtracts them, sorts by them and puts their fields in a set, so each field has the type it needs; an address is not
    parsed again. On a SQL backend a record comes back as it was written, with no shape registry in between, so a reader cannot count on what ingest checked.
    """
    rows = sample.get("rows") if isinstance(sample, dict) else None
    out = []
    for r in rows if isinstance(rows, list) else []:
        if (
            isinstance(r, dict)
            and r.get("d") in ("in", "out")
            and isinstance(r.get("ip"), str)
            and isinstance(r.get("proc"), str)
            and all(
                isinstance(r.get(k), int) and not isinstance(r.get(k), bool) and r[k] >= 0
                for k in ("port", "n", "tx", "rx")
            )
        ):
            out.append(r)
    return out


def _hit_key(row: dict[str, Any], entry: dict[str, str]) -> str:
    """What one watch list match is, for the record of what a host has raised: the entry and the row (direction, remote address, port, program)."""
    return "%s:%s|%s|%s|%s|%s" % (
        entry["kind"],
        entry["value"],
        row["d"],
        row["ip"],
        row["port"],
        row["proc"],
    )


def due_hits(
    alerted: Any, rows: list[dict[str, Any]], watch: list[dict[str, str]], now: int
) -> tuple[list[tuple[dict[str, Any], dict[str, str]]], dict[str, int]]:
    """([(row, entry)], alerted) -- the watch list matches in a host's new sample that are due an alert, and the host's record of what it has raised.

    A match is one entry on one row (a row that two entries match is two). It is due when the host has not raised it within ALERT_REPEAT_S: the first time, and
    again after that long while the connection is still there. At most ALERT_MAX are due in one sample, the busiest rows first; the rest are not marked, so they
    come due at the next sample. The record forgets what is older than ALERT_REPEAT_S and keeps at most ALERTED_MAX, so a host that matches a whole port range
    cannot make it grow."""
    keep: dict[str, int] = {}
    if isinstance(alerted, dict):
        keep = {
            k: v
            for k, v in alerted.items()
            if isinstance(k, str)
            and isinstance(v, int)
            and not isinstance(v, bool)
            and 0 <= now - v < ALERT_REPEAT_S
        }
        if len(keep) > ALERTED_MAX:
            keep = dict(sorted(keep.items(), key=lambda kv: kv[1])[-ALERTED_MAX:])
    hits: list[tuple[dict[str, Any], dict[str, str]]] = []
    for r in rows:
        for w in watched(r, watch):
            if len(hits) >= ALERT_MAX or len(keep) >= ALERTED_MAX:
                return hits, keep
            k = _hit_key(r, w)
            if k not in keep:
                keep[k] = now
                hits.append((r, w))
    return hits, keep


_KIND_WORDS = {"ip": "address", "cidr": "network", "port": "port", "proc": "program"}


def hit_detail(row: dict[str, Any], entry: dict[str, str], show_entry: bool) -> str:
    """The sentence an alert carries: the direction and the port with its service name, and, when show_entry, which entry matched with the note written on it. On
    an installation with several organisations the entry stays out: it is the operator's list, and the remote address and port already say what was seen.
    """
    svc = service_of(row["port"])
    text = "%s connection on port %d%s" % (
        "Inbound" if row["d"] == "in" else "Outbound",
        row["port"],
        " (%s)" % svc if svc else "",
    )
    if not show_entry:
        return text + ", matches the watch list"
    text += ", matches the watch list entry %s %s" % (
        _KIND_WORDS.get(entry["kind"], entry["kind"]),
        entry["value"],
    )
    return text + (" (%s)" % entry["label"] if entry.get("label") else "")


def fleet_summary(
    entries: list[tuple[str, str, dict[str, Any]]], top: int = 50, is_new: Any = None
) -> dict[str, Any]:
    """Add up hosts' latest samples: [(host id, host name, sample)] become the busiest remote addresses (with the hosts that talk to each), the busiest programs and ports,
    and the totals. Hosts are counted by id, since two hosts can share a name; a remote lists at most five of them. `is_new(host id, address)`, when given, says whether
    an address is new for that host, and a remote carries `new_hosts`, how many hosts it is new for.
    """
    remotes: dict[str, dict[str, Any]] = {}
    procs: dict[str, dict[str, Any]] = {}
    ports: dict[tuple[str, int], dict[str, Any]] = {}
    total = {"tx": 0, "rx": 0, "conns": 0, "hosts": 0}
    for hid, name, sample in entries:
        if not isinstance(sample, dict):
            continue
        total["hosts"] += 1
        total["tx"] += num(sample.get("tx"))
        total["rx"] += num(sample.get("rx"))
        total["conns"] += num(sample.get("conns"))
        for r in stored_rows(sample):
            e = remotes.setdefault(
                r["ip"],
                {
                    "ip": r["ip"],
                    "hosts": {},
                    "n": 0,
                    "tx": 0,
                    "rx": 0,
                    "ports": set(),
                    "new": set(),
                },
            )
            e["hosts"].setdefault(hid, name)
            if is_new is not None and hid not in e["new"] and is_new(hid, r["ip"]):
                e["new"].add(hid)
            e["n"] += r["n"]
            e["tx"] += r["tx"]
            e["rx"] += r["rx"]
            e["ports"].add(r["port"])
            p = procs.setdefault(
                r["proc"] or "-",
                {"proc": r["proc"] or "-", "hosts": set(), "n": 0, "tx": 0, "rx": 0},
            )
            p["hosts"].add(hid)
            p["n"] += r["n"]
            p["tx"] += r["tx"]
            p["rx"] += r["rx"]
            q = ports.setdefault(
                (r["d"], r["port"]),
                {"d": r["d"], "port": r["port"], "hosts": set(), "n": 0, "tx": 0, "rx": 0},
            )
            q["hosts"].add(hid)
            q["n"] += r["n"]
            q["tx"] += r["tx"]
            q["rx"] += r["rx"]

    def busiest(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(rows, key=lambda x: (-(x["tx"] + x["rx"]), -x["n"]))[:top]

    return {
        "totals": total,
        "remotes": [
            {
                "ip": e["ip"],
                "scope": scope_of(e["ip"]),
                "hosts": [{"id": h, "name": n} for h, n in list(e["hosts"].items())[:5]],
                "hosts_n": len(e["hosts"]),
                "n": e["n"],
                "tx": e["tx"],
                "rx": e["rx"],
                "ports": [{"port": q, "service": service_of(q)} for q in sorted(e["ports"])[:6]],
                **({"new_hosts": len(e["new"])} if e["new"] else {}),
            }
            for e in busiest(list(remotes.values()))
        ],
        "programs": [
            {
                "proc": p["proc"],
                "hosts_n": len(p["hosts"]),
                "n": p["n"],
                "tx": p["tx"],
                "rx": p["rx"],
            }
            for p in busiest(list(procs.values()))
        ],
        "ports": [
            {
                "d": q["d"],
                "port": q["port"],
                "service": service_of(q["port"]),
                "hosts_n": len(q["hosts"]),
                "n": q["n"],
                "tx": q["tx"],
                "rx": q["rx"],
            }
            for q in busiest(list(ports.values()))
        ],
    }

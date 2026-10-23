"""Threat evidence from the syslog of firewalls and routers.

A Linux agent reads its own host's logs and sends RemotePower counts and tokens.
A firewall or router has no agent, but it already sends its logs to RemotePower
as syslog, and the server keeps them in the device's log buffer. This module
reads those lines on the server and turns them into the same evidence the agents
send, so an address that scans your firewall is looked up, reported and counted
like one that scans your web server.

It is stdlib-only and never opens a socket or a file. The caller passes lines in
and takes events out; `appliance_sensor_handlers` does the storing.

What it reads, and what each line can show:

  OPNsense `filterlog` (pf)   A packet the firewall refused. One refused packet
                              means nothing; an address that tried ten different
                              ports in half an hour is scanning.
  RouterOS firewall logs      The same, for a rule whose log prefix says it drops
                              (`drop`, `deny`, `block`, `reject`). A rule whose
                              prefix contains `rp-trap` is a decoy port: nothing
                              legitimate connects to it.
  Suricata alerts             OPNsense's intrusion detection, as syslog alerts or
                              EVE JSON. Only the alerts that name an attack.
  CrowdSec alerts             `crowdsec alert scenario=... src=... events=...`,
                              the line RemotePower writes for each alert CrowdSec's
                              HTTP notification posts.
  Login failures              RouterOS `login failure for user ... from ... via ...`
                              and OPNsense's web interface. These go through the
                              brute-force counter, which already has thresholds,
                              alerts and a queue; see LOGIN_PATTERNS.

Only inbound TCP counts as a probe. A source address on UDP and ICMP is whatever
the sender wrote, and what a flood forges is UDP and ICMP, so a report built on
them could name the flood's victim. For the same reason only a SYN, or a FIN or
Xmas probe, counts: a SYN-ACK or a RST refused at the firewall is the reply to
somebody else's spoofed SYN, and blaming its sender would be wrong.

The numbers below come from watching a real OPNsense on the internet. In 17
minutes it refused 431 inbound SYNs from 216 addresses. Most sent one packet. The
persistent scanners were slow, 19 ports in 16 minutes, so a one-minute window
(what the host firewall rule uses) catches almost none of them and thirty minutes
catches the ones that matter.
"""

import ipaddress
import json
import re

import threat_evidence

# ── thresholds ─────────────────────────────────────────────────────────────────

WINDOW_S = 1800            # how long an address is watched from its first refused packet
SCAN_PORTS = 10            # different ports tried within the window ...
SCAN_PACKETS = 25          # ... or packets refused within it
TRAP_HITS = 2              # hits on a decoy port; nothing innocent connects to it
MAX_TRACKED = 2000         # addresses watched per device
MAX_PORTS = 16             # ports remembered per address: enough to reach SCAN_PORTS
MAX_LINE = 4096            # characters read from one line

# TCP flag sets that make a packet a probe: a SYN, a FIN, or the Xmas scan's
# FIN+PSH+URG. Anything with ACK or RST in it answers someone else's packet.
SCAN_FLAGS = ({"S"}, {"F"}, {"F", "P", "U"})

TRAP_MARK = "rp-trap"      # a RouterOS log prefix containing this is a decoy port
DROP_WORDS = ("drop", "deny", "denied", "block", "reject", "refus")

# ── splitting a syslog line ────────────────────────────────────────────────────

_PRI = re.compile(r"^<\d{1,3}>")
_RFC5424 = re.compile(
    r"^1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<pid>\S+) (?P<mid>\S+) "
    r"(?:-|(?:\[[^\]]*\])+) ?(?P<msg>.*)$",
    re.S,
)
_RFC3164 = re.compile(
    r"^[A-Z][a-z]{2}\s+\d{1,2} \d\d:\d\d:\d\d (?P<host>\S+) "
    r"(?P<app>[^\s:\[]+)(?:\[\d+\])?: ?(?P<msg>.*)$",
    re.S,
)
_BSD_HEAD = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2} \d\d:\d\d:\d\d \S+ ")
# RouterOS puts its topics where a tag would be: `firewall,info`.
_TOPICS = re.compile(r"^(?P<topics>[a-z0-9_-]+(?:,[a-z0-9_-]+)+) (?P<msg>.*)$", re.S)
_TOPICS_AS_APP = re.compile(r"[a-z0-9_-]+(?:,[a-z0-9_-]+)+")


def _program(app, msg):
    """The program and message of a header that was read. A RouterOS that writes
    RFC 5424 puts the topics in the program field, which comes back as a RouterOS line
    so one reader handles both layouts."""
    app = app.lower()
    if _TOPICS_AS_APP.fullmatch(app):
        return "routeros", f"{app} {msg}"
    return app, msg


def split_line(line):
    """(app, message) for one stored syslog line, or ('', line) when it carries no
    program name. RFC 5424 and RFC 3164 headers are read; a RouterOS line, which has
    topics instead of a program name, comes back as ('routeros', message-with-topics)."""
    line = str(line or "")[:MAX_LINE]
    line = _PRI.sub("", line, count=1)
    m = _RFC5424.match(line)
    if m:
        return _program(m.group("app"), m.group("msg"))
    m = _RFC3164.match(line)
    if m:
        return _program(m.group("app"), m.group("msg"))
    bare = _BSD_HEAD.sub("", line, count=1)
    if _TOPICS.match(bare):
        return "routeros", bare
    return "", line


# ── pf (OPNsense, pfSense) ─────────────────────────────────────────────────────

def _port(v):
    try:
        n = int(v)
    except (TypeError, ValueError):
        return 0
    return n if 0 < n < 65536 else 0


def parse_pf(msg):
    """One `filterlog` message, or None. The fields are comma separated:
    rule, sub-rule, anchor, tracker, interface, reason, action, direction, IP
    version, then the IP header (IPv4: tos, ecn, ttl, id, offset, flags, protocol
    number, protocol name, length, source, destination; IPv6: class, flow label, hop
    limit, protocol name, protocol number, length, source, destination), then for
    TCP and UDP the ports, the data length and, for TCP, the flags."""
    f = str(msg or "").strip().split(",")
    if len(f) < 9:
        return None
    action, direction, ver = f[6], f[7], f[8]
    if ver == "4" and len(f) >= 20:
        proto, src, dst, rest = f[16].lower(), f[18], f[19], f[20:]
    elif ver == "6" and len(f) >= 17:
        proto, src, dst, rest = f[12].lower(), f[15], f[16], f[17:]
    else:
        return None
    rec: dict = {"kind": "fw", "origin": "pf", "action": action, "dir": direction,
           "proto": proto, "src": src, "dst": dst, "iface": f[4]}
    if proto in ("tcp", "udp") and len(rest) >= 2:
        rec["sport"], rec["dport"] = _port(rest[0]), _port(rest[1])
        if proto == "tcp" and len(rest) >= 4:
            # E and W are the ECN bits a modern stack sets on its SYN
            rec["flags"] = set(rest[3].upper()) - {"-", "E", "W"}
    return rec


# ── RouterOS ───────────────────────────────────────────────────────────────────

_ROS_ADDR = r"(?:\d{1,3}(?:\.\d{1,3}){3}|\[[0-9A-Fa-f:.]+\]|[0-9A-Fa-f]*:[0-9A-Fa-f:]*[0-9A-Fa-f])"
_ROS_PKT = re.compile(
    r"proto (?P<proto>[A-Za-z0-9_]+)(?: \((?P<flags>[^)]*)\))?,"
    r"(?: [^,]*,)*? (?P<src>" + _ROS_ADDR + r")(?::(?P<sport>\d+))?"
    r"->(?P<dst>" + _ROS_ADDR + r")(?::(?P<dport>\d+))?"
)
_ROS_FLAG = {"SYN": "S", "ACK": "A", "FIN": "F", "RST": "R", "PSH": "P", "URG": "U"}
_ROS_PREFIX = re.compile(r"^(?P<prefix>.*?)\s*(?P<chain>[A-Za-z0-9_.-]+): in:")


def _unbracket(a):
    return a[1:-1] if a.startswith("[") and a.endswith("]") else a


def parse_routeros_firewall(msg):
    """One RouterOS firewall log message (`firewall,info PREFIX chain: in:ether1
    out:..., proto TCP (SYN), a:p->b:p, len 60`), or None. `drop` says the log
    prefix names a refusal; `trap` says it names a decoy port."""
    t = _TOPICS.match(str(msg or ""))
    if not t or "firewall" not in t.group("topics").split(","):
        return None
    body = t.group("msg")
    p = _ROS_PKT.search(body)
    if not p:
        return None
    head = _ROS_PREFIX.match(body[:p.start()] if p.start() else body)
    prefix = (head.group("prefix") if head else "").strip().lower()
    proto = p.group("proto").lower()
    rec: dict = {"kind": "fw", "origin": "routeros", "proto": proto, "dir": "in",
           "src": _unbracket(p.group("src")), "dst": _unbracket(p.group("dst")),
           "action": "block" if any(w in prefix for w in DROP_WORDS) else "log",
           "trap": TRAP_MARK in prefix, "prefix": prefix[:64]}
    if p.group("sport"):
        rec["sport"] = _port(p.group("sport"))
    if p.group("dport"):
        rec["dport"] = _port(p.group("dport"))
    if proto == "tcp" and p.group("flags") is not None:
        rec["flags"] = {_ROS_FLAG[w] for w in re.split(r"[,\s]+", p.group("flags").upper())
                        if w in _ROS_FLAG}
    return rec


# ── Suricata ───────────────────────────────────────────────────────────────────

# `[1:2210029:2] SURICATA ... [Classification: x] [Priority: 3] {TCP} a:p -> b:p`
# Read from its two ends and take what is between: one pattern with a lazy signature in the
# middle backtracks quadratically on a long run of spaces (165 ms for one 2,048-character
# line, 33 s for the 200 lines of a POST), and these lines come off the network.
_SURI_HEAD = re.compile(r"\[\d+:\d+:\d+\]\s+")
_SURI_TAIL = re.compile(r"\{(?P<proto>[A-Za-z0-9_-]+)\}\s+(?P<src>\S+)\s+->\s+(?P<dst>\S+)")
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}")


def _split_host_port(s):
    """('203.0.113.9', 443) from '203.0.113.9:443'. Suricata prints an IPv6 address
    and its port with no brackets, so the last colon is the port only when what is
    left of it is an address."""
    s = str(s or "").strip().rstrip(",")
    if s.startswith("[") and "]" in s:
        host, _, tail = s[1:].partition("]")
        return host, _port(tail.lstrip(":"))
    head, sep, tail = s.rpartition(":")
    if sep and tail.isdigit() and _is_ip(head):
        return head, _port(tail)
    return s, 0


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# What an alert's signature and classification say it was. Ordered; the first rule
# that matches wins. A signature that names no attack gets no class, and an address
# with no class is never reported.
_IDS_SKIP = re.compile(
    r"^surica|\bsuricata\b|"
    r"\bet (?:drop|dshield|cins|compromised|tor|info|policy|chat|games|p2p|dns|"
    r"mobile_malware|malware|trojan|cnc|phishing|current_events|adware_pup|user_agents|"
    r"hunting|ja3|scada|voip)\b|"
    r"\b(?:outbound|to_client)\b|\bfrom home_net\b"
)
_IDS_RULES = tuple(
    (cls, re.compile(rx))
    for cls, rx in (
        # every short name here is bounded on both sides: an unbounded `rce` also matches the
        # end of "force" and "source", and filed "brute force" and "external source" as RCE
        ("rce", r"\blog4|\bspring4shell|\bshellshock|\bstruts|\brce\b|remote code|"
                r"command inject|code exec|webshell|\bcve-"),
        ("sqli", r"sql ?inject|\bsqli\b"),
        ("xss", r"\bxss\b|cross.?site script"),
        ("traversal", r"travers|\blfi\b|\brfi\b|/etc/passwd|\.\./"),
        ("flood", r"\bdos\b|denial of service|flood"),
        ("scanner", r"nmap|nikto|sqlmap|masscan|zmap|acunetix|nessus|openvas|wpscan|"
                    r"dirbuster|gobuster|havij|netsparker|appscan|nuclei|zgrab|sipvicious|"
                    r"friendly-scanner"),
        ("ftp_brute", r"\bftp\b.*(?:brute|login|auth)"),
        ("mail_brute", r"\b(?:smtp|imap|pop3)\b.*(?:brute|login|auth)"),
        ("service_brute", r"\b(?:telnet|rdp|vnc|mssql|mysql|postgres)\b.*(?:brute|login|auth)"),
        ("port_scan", r"\bet scan\b|detection of a network scan|network scan|port scan|"
                      r"\bscan\b"),
        ("probe", r"attempted information leak"),
    )
)


def classify_ids(signature, classification=""):
    """The attack class an IDS alert stands for, or None for one that names no
    attack (the engine's own events, reputation lists, policy, outbound malware)."""
    hay = (str(signature or "") + " | " + str(classification or "")).lower()
    if _IDS_SKIP.search(hay):
        return None
    for cls, rx in _IDS_RULES:
        if rx.search(hay):
            return cls
    return None


def parse_suricata(msg):
    """One Suricata alert, as the syslog alert line or as an EVE JSON object, or
    None. `cls` is already the RemotePower class, and `cves` the CVE ids the
    signature names."""
    msg = str(msg or "").strip()
    sig = cls_name = ""
    src = proto = ""
    if msg.startswith("{"):
        try:
            ev = json.loads(msg)
        except ValueError:
            return None
        if not isinstance(ev, dict) or ev.get("event_type") != "alert":
            return None
        a = ev.get("alert") if isinstance(ev.get("alert"), dict) else {}
        sig, cls_name = str(a.get("signature") or ""), str(a.get("category") or "")
        src, proto = str(ev.get("src_ip") or ""), str(ev.get("proto") or "")
        dport = _port(ev.get("dest_port"))
    else:
        head = _SURI_HEAD.search(msg)
        tail = _SURI_TAIL.search(msg, head.end()) if head else None
        if not (head and tail):
            return None
        body = msg[head.end():tail.start()]
        # plain str.find: a pattern that restarts at every `[Classification:` is quadratic too
        ci = body.find("[Classification:")
        cj = body.find("]", ci) if ci >= 0 else -1
        cls_name = body[ci + len("[Classification:"):cj].strip() if cj >= 0 else ""
        marks = [i for i in (ci, body.find("[Priority:")) if i >= 0]
        sig = (body[:min(marks)] if marks else body).strip()
        proto = tail.group("proto")
        src, _ = _split_host_port(tail.group("src"))
        dport = _split_host_port(tail.group("dst"))[1]
    if not src:
        return None
    return {"kind": "ids", "src": src, "proto": proto.lower(), "dport": dport,
            "cls": classify_ids(sig, cls_name), "cves": _CVE.findall(sig)[:2]}


# ── CrowdSec ───────────────────────────────────────────────────────────────────

_CS_LINE = re.compile(
    r"crowdsec alert scenario=(?P<scenario>\S+) src=(?P<src>\S+) events=(?P<events>\d+) "
    r"decision=(?P<decision>\S+)"
)
_CS_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./-]{0,95}")


def crowdsec_lines(alerts):
    """Lines for the Logs tab from the JSON CrowdSec's HTTP notification posts (a
    list of alerts, or one). Only what RemotePower needs, in a fixed shape: the
    scenario name, the address, how many events and what was decided. Nothing an
    attacker typed is copied: the scenario is checked against a name pattern and
    the address against the address parser. A simulated alert is dropped."""
    if isinstance(alerts, dict):
        alerts = [alerts]
    out = []
    for a in alerts if isinstance(alerts, list) else []:
        if not isinstance(a, dict) or a.get("simulated"):
            continue
        scenario = str(a.get("scenario") or "")
        source = a.get("source") if isinstance(a.get("source"), dict) else {}
        src = str(source.get("ip") or source.get("value") or "").strip()
        if not _CS_NAME.fullmatch(scenario) or not _is_ip(src):
            continue
        try:
            events = max(1, min(1_000_000, int(a.get("events_count") or 1)))
        except (TypeError, ValueError, OverflowError):
            events = 1
        decision = "none"
        for d in a.get("decisions") if isinstance(a.get("decisions"), list) else []:
            # a decision from a local scenario, as the host sensor counts it; the
            # community lists (CAPI) and a ban added by hand (cscli) are other
            # people's opinions and are not what this address did here
            if isinstance(d, dict) and not d.get("simulated") and d.get("origin") == "crowdsec":
                t = str(d.get("type") or "ban")
                decision = t if re.fullmatch(r"[a-z]{2,16}", t) else "ban"
                break
        out.append(f"crowdsec alert scenario={scenario} src={src} events={events} decision={decision}")
    return out


def parse_crowdsec(msg):
    m = _CS_LINE.search(str(msg or ""))
    if not m:
        return None
    return {"kind": "cs", "src": m.group("src"), "scenario": m.group("scenario"),
            "events": int(m.group("events")), "decision": m.group("decision") != "none"}


# ── login failures ─────────────────────────────────────────────────────────────

# For the brute-force counter, which counts failures per address, alerts at its
# threshold and queues the address for Threat Intel. Group 1 is the address.
LOGIN_PATTERNS = {
    # RouterOS: `login failure for user admin from 203.0.113.9 via ssh`
    "ssh": [re.compile(r"login failure for user .* from (\S+) via ssh\b", re.I)],
    "other": [
        re.compile(r"login failure for user .* from (\S+) via "
                   r"(?:winbox|web|www|telnet|ftp|api|api-ssl|romon)\b", re.I),
        # OPNsense: `/index.php: Web GUI authentication error for 'root' from 203.0.113.9`
        re.compile(r"Web GUI authentication error for .* from (\S+)", re.I),
    ],
}


# ── reading a batch ────────────────────────────────────────────────────────────

def read_line(line):
    """(kind, record) for one stored syslog line. `kind` is the source the line
    belongs to ('fw', 'ids' or 'cs'), or None when it is none of them. `record` is what
    was read from it, or None when the line belongs to a source but is not one the
    reader understands. One pass, and cheap: the program name decides which reader
    runs, and most lines are none of these."""
    app, msg = split_line(line)
    if app == "filterlog":
        return "fw", parse_pf(msg)
    if app == "suricata":
        return "ids", parse_suricata(msg)
    if app == "routeros":
        t = _TOPICS.match(msg)
        if t and "firewall" in t.group("topics").split(","):
            return "fw", parse_routeros_firewall(msg)
        return None, None
    if app in ("crowdsec", "crowdsec-agent") or msg.startswith("crowdsec alert "):
        return "cs", parse_crowdsec(msg)
    return None, None


def parse(line):
    """The record for one line, or None."""
    return read_line(line)[1]


def probe_of(rec):
    """(port, is_trap) when a firewall record is a refused inbound TCP probe from a
    public address, else None."""
    if not rec or rec.get("kind") != "fw" or rec.get("proto") != "tcp" or rec.get("dir") != "in":
        return None
    trap = bool(rec.get("trap"))
    # a decoy port's rule only logs; the log prefix is what says it was refused
    if not trap and rec.get("action") not in ("block", "reject"):
        return None
    if rec.get("flags") not in SCAN_FLAGS:
        return None            # a decoy hit counts for its SYN, not for a stray ACK
    return rec.get("dport") or 0, trap


def _entry(now):
    return {"f": now, "l": now, "n": 0, "p": [], "t": 0, "s": 0, "d": 0}


def track(table, hits, now):
    """Count refused probes per source address and say which crossed a line.

    `table` is {address: entry}, the state the caller keeps between batches, and is
    changed in place. `hits` is a list of (address, port, is_trap). Returns the
    events: one the first time an address tried SCAN_PORTS different ports or was
    refused SCAN_PACKETS times within WINDOW_S of its first refused packet, and one
    the first time it hit a decoy port TRAP_HITS times. An address that stays quiet
    for a window is forgotten; one that keeps going is counted again from a fresh
    window, so a persistent scanner is reported again the next day, not every batch."""
    events = []
    for ip, port, is_trap in hits:
        e = table.get(ip)
        if e is None or now - e["f"] > WINDOW_S:
            e = table[ip] = _entry(now)
        e["l"] = now
        if is_trap:
            e["t"] += 1
        else:
            e["n"] += 1
            if port and port not in e["p"] and len(e["p"]) < MAX_PORTS:
                e["p"].append(port)
        if not e["s"] and (len(e["p"]) >= SCAN_PORTS or e["n"] >= SCAN_PACKETS):
            e["s"] = 1
            events.append({"ip": ip, "first": e["f"], "last": e["l"], "src": {"fw": e["n"]},
                           "tok": {"fw": {"fw:scan": e["n"]}}})
        if not e["d"] and e["t"] >= TRAP_HITS:
            e["d"] = 1
            events.append({"ip": ip, "first": e["f"], "last": e["l"], "src": {"dp": e["t"]},
                           "tok": {"dp": {"dp:hit": e["t"]}}, "trp": 1})
    for ip in [k for k, v in table.items() if now - v["l"] > WINDOW_S]:
        del table[ip]
    if len(table) > MAX_TRACKED:
        for ip, _ in sorted(table.items(), key=lambda kv: kv[1]["l"])[:len(table) - MAX_TRACKED]:
            del table[ip]
    return events


def scan(lines):
    """Read a batch of stored syslog lines, with no state.

    Returns (hits, events, stats). `hits` are the refused or decoy packets, as
    (address, port, is_trap), for `track` to count over time. `events` are the
    evidence a batch settles by itself: intrusion detection and CrowdSec alerts, in the
    shape threat_evidence.normalize_event reads (the caller normalizes them, with
    threat_evidence.APPLIANCE_SOURCES). `stats` is {kind: {'lines': n, 'parsed': n,
    'events': n}} for the sources the batch touched."""
    stats = {}

    def bump(kind, key, n=1):
        stats.setdefault(kind, {"lines": 0, "parsed": 0, "events": 0})[key] += n

    hits, events = [], []
    ids, cs = {}, {}
    now = 0
    for line in lines:
        kind, rec = read_line(line)
        if not kind:
            continue
        bump(kind, "lines")
        if rec is None:
            continue
        bump(kind, "parsed")
        ip = threat_evidence.public_ip(rec.get("src"))
        if not ip:
            continue
        if kind == "fw":
            p = probe_of(rec)
            if p:
                hits.append((ip, p[0], p[1]))
        elif kind == "ids":
            if rec["cls"]:
                row = ids.setdefault(ip, {"cls": {}, "cves": []})
                row["cls"][rec["cls"]] = row["cls"].get(rec["cls"], 0) + 1
                row["cves"] += [c for c in rec["cves"] if c not in row["cves"]]
        elif kind == "cs":
            if threat_evidence.scenario_class(rec["scenario"]):
                row = cs.setdefault(ip, {"tok": {}, "n": 0, "dec": 0})
                tok = "cs:" + rec["scenario"]
                row["tok"][tok] = row["tok"].get(tok, 0) + rec["events"]
                row["n"] += rec["events"]
                row["dec"] += 1 if rec["decision"] else 0
    for ip, row in ids.items():
        events.append({"ip": ip, "first": now, "last": now, "src": {"ids": sum(row["cls"].values())},
                       "tok": {"ids": {"ids:" + c: n for c, n in row["cls"].items()}},
                       "cve": row["cves"][:5]})
    if ids:
        bump("ids", "events", len(ids))
    for ip, row in cs.items():
        events.append({"ip": ip, "first": now, "last": now, "src": {"cs": row["n"]},
                       "tok": {"cs": row["tok"]}, "dec": row["dec"]})
    if cs:
        bump("cs", "events", len(cs))
    return hits, events, stats


def read(lines, table, now):
    """`scan` and `track` together: (events, stats) for a batch, with the scan state
    `table` kept by the caller. The events carry `now` as their time."""
    hits, events, stats = scan(lines)
    for ev in events:
        ev["first"] = ev["last"] = now
    fresh = track(table, hits, now)
    if fresh:
        stats.setdefault("fw", {"lines": 0, "parsed": 0, "events": 0})["events"] += len(fresh)
    return events + fresh, stats

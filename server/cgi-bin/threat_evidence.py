"""Threat evidence — the closed vocabulary between a host's logs and a report.

The threat sensor in the Linux agent reads web server, WAF, fail2ban and
CrowdSec logs on the host and sends, per source address, a small summary of
what it saw: counts and TOKENS. A token is one of a handful of fixed shapes
(`req:sqli`, `crs:942100`, `jail:sshd`, `cs:crowdsecurity/ssh-bf`, ...). From 8.0.1 it
also sends up to MAX_SAMPLES SAMPLES: a request the logs show the address making, as a
method, a path, a status and the log it came from. Log lines as such, query strings,
host names and user names never leave the host, and a sample is never kept as it
arrived: the server rebuilds it from parts it checks itself (see "samples" below).

This module is the server's half of that contract, and it is stdlib-only and
never opens a socket:

  * `normalize_event` validates one address's summary from an agent and drops
    everything that is not in the vocabulary. An agent is root on a machine an
    attacker may already be on, so what it sends is data to check, not data
    to trust.
  * `classes` turns tokens into attack classes (SQL injection, path
    traversal, ...). The rules live here rather than in the agent so that a new
    CRS rule range or CrowdSec scenario is a server change, not an agent
    rollout.
  * `qualifies` decides whether the evidence is enough to report.
  * `categories` and the phrase helpers give the provider category ids and the
    words for the report. A report is public and filed under the operator's
    account, so its text is built from this module's fixed phrases and from
    numbers. The one thing an attacker typed that can reach it is a sample's path,
    and only when the operator has turned examples on (`report_samples`, off by
    default): it has been cut to a short, safe alphabet with its query string
    dropped.

Evidence shape (all keys optional on input, always present on output):

    {'ip': '203.0.113.9', 'first': 1790000000, 'last': 1790000600,
     'src': {'web': 40, 'waf': 12},          # events per source family
     'tok': {'web': {'req:sqli': 14}, 'waf': {'crs:942100': 9}},
     'ans': 3,                                # hostile requests answered 2xx
     'blk': 31,                               # hostile requests refused
     'ban': ['sshd'],                         # fail2ban jails that banned it
     'smp': [{'f': 'err', 'm': 'GET', 'p': '/.env', 'c': 403, 't': 1790000100}],   # requests the logs show
     'dec': 1,                                # CrowdSec decisions from local scenarios
     'cve': ['CVE-2021-44228']}

Source families are `web` (access logs), `err` (web server error logs),
`waf` (ModSecurity), `f2b` (fail2ban), `cs` (CrowdSec), `fw` (the host's
firewall log) and `ids` (Suricata's alerts on the host, from eve.json or fast.log);
these come from an agent. `cf` (Cloudflare's own firewall events)
and `trap` (the edge honeypot's hits) come from the server's edge feeds and are
never accepted from an agent. `ids` is also what the server reads from a firewall's
or router's syslog (appliance_evidence), which also reads `fw`, `cs` and `dp` (hits
on a decoy port). `dp` is never accepted from an agent, and neither is the
reputation-list repeat count (`rep`) that goes with an appliance's `ids`: an agent
may say what its own IDS alerted on, as it may say what its own WAF refused, and not
that a reputation list or a decoy port decided. The same hostile request shows up in several of
them, so the number used in a report is the LARGEST family count, never the sum.
The honeypot's own decision (it banned the address) rides in `trp`, and so does a
decoy port's (the address hit it twice). A trap reports an address; it does not block or list one on its own (`beyond_traps`).
"""

import ipaddress
import re
import time

# What an agent may send, and what the server's edge feeds may produce. The two
# sets do not overlap: an agent is root on a machine an attacker may already be
# on, so it cannot claim that Cloudflare or the honeypot decided anything.
AGENT_SOURCES = ("web", "err", "waf", "f2b", "cs", "fw", "ids")
EDGE_SOURCES = ("cf", "trap")
# What only the server's own reading of a firewall's or router's syslog produces,
# and what it may speak for: it reads firewall, CrowdSec and intrusion detection lines as well.
APPLIANCE_ONLY_SOURCES = ("dp",)
APPLIANCE_SOURCES = ("fw", "cs", "ids") + APPLIANCE_ONLY_SOURCES
SOURCES = AGENT_SOURCES + EDGE_SOURCES + APPLIANCE_ONLY_SOURCES

# Words for "seen by ...". The access log and the error log are both "the web
# server log" to a reader, so the two share a phrase and it is said once.
SOURCE_PHRASE = {
    "web": "web server log",
    "err": "web server log",
    "waf": "WAF",
    "f2b": "fail2ban",
    "cs": "CrowdSec",
    "fw": "firewall log",
    "cf": "Cloudflare WAF",
    "trap": "edge honeypot",
    "ids": "intrusion detection",
    "dp": "decoy port",
}

# Attack classes. `abuseipdb` and `sniffcat` are the category ids each service
# defines (checked against their documentation); `weight` orders classes by how
# much they should speak for the address when several apply.
#   AbuseIPDB: 4 DDoS, 5 FTP brute-force, 14 port scan, 15 hacking,
#              16 SQL injection, 18 brute-force, 19 bad web bot (its text names
#              crawlers that ignore robots.txt and user-agent spoofing),
#              21 web app attack (probing for or exploiting a CMS, phpMyAdmin
#              and the like), 22 SSH
#   SniffCat:  3 DDoS, 4 port scan, 5 mass scanner, 11 hacking (attempts to gain
#              access), 12 SQL injection, 13 command injection, 15 bad web bot
#              (ignores robots.txt or impersonates a user agent), 16 path
#              traversal, 17 brute-force, 18 SSH/SFTP, 19 FTP, 20 email,
#              21 HTTP/HTTPS, 22 RDP, 23 Telnet, 24 SMB
# Both lists were read again on 2026-11-15 (abuseipdb.com/categories, 23 ids;
# sniffcat.com/documentation/categories, 27 ids).
#
# `probe` and `service_brute` are GENERAL classes. Each has finer kinds (FAMILIES
# below) that a source names when it can tell: a request for /.env is
# `config_probe`, one for /phpmyadmin is `admin_probe`. A source that can only say
# "this was probing" still says `probe`. Until 8.0.1 every one of them was `probe`,
# and a day of reports read as the same sentence fourteen times.
CLASSES = {
    "ssh_brute": {
        "phrase": "SSH brute force",
        "abuseipdb": (18, 22),
        "sniffcat": (17, 18),
        "weight": 2,
    },
    "login_brute": {
        "phrase": "login brute force",
        "abuseipdb": (18, 21),
        "sniffcat": (17, 21),
        "weight": 2,
    },
    "sqli": {"phrase": "SQL injection", "abuseipdb": (16, 21), "sniffcat": (12, 21), "weight": 5},
    "xss": {"phrase": "cross-site scripting", "abuseipdb": (21,), "sniffcat": (21,), "weight": 3},
    "traversal": {
        "phrase": "path traversal",
        "abuseipdb": (21,),
        "sniffcat": (16, 21),
        "weight": 4,
    },
    "rce": {
        "phrase": "remote code execution attempts",
        "abuseipdb": (15, 21),
        "sniffcat": (13, 21),
        "weight": 6,
    },
    "probe": {
        "phrase": "probing for exposed files and admin pages",
        "abuseipdb": (21,),
        "sniffcat": (21,),
        "weight": 2,
    },
    "config_probe": {
        "phrase": "probing for configuration files, keys and backups",
        "abuseipdb": (15, 21),
        "sniffcat": (11, 21),
        "weight": 4,
    },
    "admin_probe": {
        "phrase": "probing for admin, login and debug pages",
        "abuseipdb": (21,),
        "sniffcat": (21,),
        "weight": 2,
    },
    "wordpress": {
        "phrase": "WordPress probing",
        "abuseipdb": (21,),
        "sniffcat": (21,),
        "weight": 2,
    },
    "user_enum": {"phrase": "user enumeration", "abuseipdb": (21,), "sniffcat": (21,), "weight": 2},
    "proxy_probe": {
        "phrase": "open proxy probing",
        "abuseipdb": (21,),
        "sniffcat": (21,),
        "weight": 2,
    },
    "host_recon": {
        "phrase": "probing private host names",
        "abuseipdb": (21,),
        "sniffcat": (21,),
        "weight": 2,
    },
    "method_probe": {
        "phrase": "probing with unusual HTTP methods",
        "abuseipdb": (21,),
        "sniffcat": (21,),
        "weight": 1,
    },
    # Walking a fake backup directory or dumping a fake .git: the visitor took what a probe only looks for.
    "decoy_loot": {
        "phrase": "downloading files from a decoy backup or repository",
        "abuseipdb": (15, 21),
        "sniffcat": (11, 21),
        "weight": 5,
    },
    "scanner": {
        "phrase": "vulnerability scanning",
        "abuseipdb": (19, 21),
        "sniffcat": (5, 21),
        "weight": 3,
    },
    "flood": {"phrase": "request flooding", "abuseipdb": (19,), "sniffcat": (15,), "weight": 1},
    "bad_bot": {
        "phrase": "unwanted web crawling",
        "abuseipdb": (19,),
        "sniffcat": (15,),
        "weight": 1,
    },
    "waf": {
        "phrase": "requests blocked by a web application firewall",
        "abuseipdb": (21,),
        "sniffcat": (21,),
        "weight": 3,
    },
    "mail_brute": {
        "phrase": "mail login brute force",
        "abuseipdb": (18,),
        "sniffcat": (17, 20),
        "weight": 2,
    },
    "ftp_brute": {
        "phrase": "FTP brute force",
        "abuseipdb": (5, 18),
        "sniffcat": (17, 19),
        "weight": 2,
    },
    "service_brute": {
        "phrase": "service login brute force",
        "abuseipdb": (18,),
        "sniffcat": (17,),
        "weight": 2,
    },
    "rdp_brute": {
        "phrase": "RDP brute force",
        "abuseipdb": (18,),
        "sniffcat": (17, 22),
        "weight": 2,
    },
    "smb_brute": {
        "phrase": "SMB brute force",
        "abuseipdb": (18,),
        "sniffcat": (17, 24),
        "weight": 2,
    },
    "telnet_brute": {
        "phrase": "Telnet brute force",
        "abuseipdb": (18,),
        "sniffcat": (17, 23),
        "weight": 2,
    },
    "db_brute": {
        "phrase": "database login brute force",
        "abuseipdb": (18,),
        "sniffcat": (17,),
        "weight": 2,
    },
    "port_scan": {"phrase": "port scanning", "abuseipdb": (14,), "sniffcat": (4,), "weight": 2},
    # A port on a firewall or router that nothing legitimate uses.
    "decoy_port": {
        "phrase": "connecting to a decoy port",
        "abuseipdb": (14,),
        "sniffcat": (4,),
        "weight": 3,
    },
    # The three below are what the edge honeypot and Cloudflare can say that a
    # host's own logs cannot.
    "canary": {
        "phrase": "using a credential planted in a decoy file",
        "abuseipdb": (15, 21),
        "sniffcat": (11, 21),
        "weight": 6,
    },
    "decoy_login": {
        "phrase": "signing in to a decoy service",
        "abuseipdb": (18, 21),
        "sniffcat": (17, 21),
        "weight": 3,
    },
    "ddos": {
        "phrase": "HTTP request flooding",
        "abuseipdb": (4,),
        "sniffcat": (3, 21),
        "weight": 3,
    },
}

# A general class and the finer kinds of it. Three things follow from one table: the general class
# steps aside in a report when one of its kinds explains the address (`report_classes`), an operator who
# ignores the general class ignores its kinds (`with_kinds`), and a source that learns to tell a kind
# apart may move a name from the general class to one of its kinds and nowhere else.
FAMILIES = {
    "probe": (
        "config_probe",
        "admin_probe",
        "wordpress",
        "user_enum",
        "proxy_probe",
        "host_recon",
        "method_probe",
        "decoy_loot",
    ),
    "service_brute": ("rdp_brute", "smb_brute", "telnet_brute", "db_brute"),
}
GENERAL_OF = {kind: general for general, kinds in FAMILIES.items() for kind in kinds}

# `{what}` in a report message, kept compatible with the older placeholder
# ('SSH', 'web login', 'login').
_WHAT = {
    "ssh_brute": "SSH",
    "login_brute": "web login",
    "mail_brute": "mail login",
    "ftp_brute": "FTP login",
    "service_brute": "login",
    "rdp_brute": "RDP",
    "smb_brute": "SMB",
    "telnet_brute": "Telnet",
    "db_brute": "database login",
    "port_scan": "port",
    "decoy_port": "port",
}
_WEB_CLASSES = (
    "sqli",
    "xss",
    "traversal",
    "rce",
    "probe",
    "config_probe",
    "admin_probe",
    "wordpress",
    "user_enum",
    "proxy_probe",
    "host_recon",
    "method_probe",
    "decoy_loot",
    "scanner",
    "flood",
    "bad_bot",
    "waf",
    "canary",
    "decoy_login",
    "ddos",
)

WAF_MIN_BLOCKS = 3  # blocked requests that count as evidence on their own
_MAX_COUNT = 1_000_000
_MAX_TOKENS = 24  # per source family
_MAX_JAILS = 8
_MAX_CVES = 5
_MAX_AGE_S = 7 * 86400
_SKEW_S = 300

# ── tokens ─────────────────────────────────────────────────────────────────────

# trap kind -> attack class. A kind that maps to None is recorded by the
# honeypot to be read and is not evidence of anything: a login cookie holder
# asking the author list, the deploy tool's own probe, an odd client.
TRAP_KINDS = {
    "bait": "config_probe",  # loot and RCE probe paths (/.env, /.git/, ...)
    "robots": "bad_bot",  # followed a path only robots.txt names
    "login": "admin_probe",  # admin and login pages the site does not have
    "private": "host_recon",  # recon against the private host names
    "impostor": "bad_bot",  # claimed to be a search crawler from the wrong network
    "wpprobe": "wordpress",  # WordPress disclosure files
    "wpenum": "user_enum",  # WordPress user enumeration
    "mazeentry": "config_probe",  # opened a fake backup directory
    "maze": "decoy_loot",  # walked the fake backup mirror
    "mazeloot": "decoy_loot",  # asked for a dump file inside it
    "gitdump": "decoy_loot",  # dumped the fake .git
    "canary": "canary",  # used a credential the honeypot handed out
    "decoy": "host_recon",  # a decoy host name only DNS brute force finds
    "decoylogin": "decoy_login",  # tried to sign in there
}

# Cloudflare mechanism -> attack class, for the event kinds that count.
CF_KINDS = {
    "waf": "waf",  # managed rules: a signature fired
    "custom": "waf",  # the operator's own rule refused it
    "ratelimit": "flood",
    "ddos": "ddos",
    "bot": "bad_bot",  # Bot Fight Mode / Bot Management / Browser Integrity Check
    "ua": "bad_bot",  # a user-agent block rule
}

# What a request was, to its class. The agent decides the first eight and, from 8.0.1, the next five; `method` and
# `recon` are what a Cloudflare rule's description can say and a host's log cannot.
_REQ_KINDS = {
    "sqli": "sqli",
    "xss": "xss",
    "traversal": "traversal",
    "rce": "rce",
    "probe": "probe",
    "scanner": "scanner",
    "login": "login_brute",
    "flood": "flood",
    "config": "config_probe",
    "admin": "admin_probe",
    "wordpress": "wordpress",
    "enum": "user_enum",
    "proxy": "proxy_probe",
    "method": "method_probe",
    "recon": "host_recon",
}

# Matched with fullmatch(), never match() with a `$`: `$` also matches before a
# trailing newline, so `req:sqli\n` would pass a `^req:sqli$` check.
# The classes an intrusion detection alert can be reduced to. The server's own reader
# picks one from the signature and the classification, so the token carries the class.
IDS_CLASSES = (
    "port_scan",
    "scanner",
    "probe",
    "sqli",
    "xss",
    "traversal",
    "rce",
    "flood",
    "ssh_brute",
    "login_brute",
    "ftp_brute",
    "mail_brute",
    "service_brute",
    "rdp_brute",
    "smb_brute",
    "telnet_brute",
    "db_brute",
)

_TOKEN_RE = {
    # built from the table above, so a kind cannot be accepted here and mean nothing there
    "req": re.compile(r"req:(" + "|".join(sorted(_REQ_KINDS)) + r")"),
    "crs": re.compile(r"crs:(\d{3,9})"),
    "crstag": re.compile(r"crstag:(attack-[a-z0-9-]{1,40})"),
    "jail": re.compile(r"jail:([A-Za-z0-9][A-Za-z0-9_.-]{0,39})"),
    "cs": re.compile(r"cs:([A-Za-z0-9][A-Za-z0-9_./-]{0,95})"),
    # The firewall log: `scan` is one source address that tried several ports or
    # many packets, decided by the agent. A blocked packet on its own is noise.
    "fw": re.compile(r"fw:(scan)"),
    # Cloudflare's firewall events, by the mechanism that refused the request.
    "cf": re.compile(r"cf:(waf|custom|ratelimit|ddos|bot|ua)"),
    # What the edge honeypot's hit was, by the trap that caught it.
    "trap": re.compile(r"trap:(" + "|".join(sorted(TRAP_KINDS)) + r")"),
    # An intrusion detection alert, by the class its signature stands for.
    "ids": re.compile(r"ids:(" + "|".join(IDS_CLASSES) + r")"),
    # A hit on a decoy port.
    "dp": re.compile(r"dp:(hit)"),
}
_JAIL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,39}")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def token_valid(token):
    """True for a token in the vocabulary. Anything else is dropped on ingest."""
    if not isinstance(token, str) or len(token) > 110:
        return False
    kind = token.split(":", 1)[0]
    rx = _TOKEN_RE.get(kind)
    return bool(rx and rx.fullmatch(token))


# ── samples ────────────────────────────────────────────────────────────────────
# A sample is one request the logs show an address making: the method, the path, the answer and the log it came from. It is there for a
# person to read, on the Threat Intel page and, when the operator turns that on, as an example in a report.
#
# The text of a request is whatever its sender typed, and an agent may be root on a machine an attacker is already on. So a sample is never
# kept as it arrived. It is rebuilt here from parts that are each checked: the method from a short list, the path cut to a safe alphabet
# with its query string dropped, the status as a number, the log from the vocabulary. What does not fit is dropped, and a path is cut where
# it stops fitting, with "..." to say so. Nothing in a sample is read as markup, a pattern or a command, and the page escapes it anyway.
#
# The alphabet is letters, digits and . _ ~ / % + -. A query string is where a request keeps what it carries (a session id, a payload, a
# password typed into the wrong form), a `;name=value` path parameter carries the same, and a URL inside the path names a host, so each of
# those ends the path.

MAX_SAMPLES = 3
SAMPLE_PATH_MAX = 80
_SAMPLE_METHODS = frozenset(
    ("GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE", "PROPFIND")
)
_SAMPLE_PATH_RE = re.compile(r"[A-Za-z0-9._~/%+-]+")
_SAMPLE_SCHEME_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]{1,9}:/")
_SAMPLE_T_MAX = 4_102_444_800  # the year 2100: a stamp bigger than that is not a time


def clean_path(raw):
    """The path of a request target, cut to what is safe to keep and show, or ''.
    The query string and fragment are dropped, the path ends where a URL scheme or a
    character outside the alphabet starts, and it is at most SAMPLE_PATH_MAX
    characters. A cut is marked with '...'. Cleaning what this returned returns it
    unchanged."""
    s = str(raw if raw is not None else "")[:2048]
    for stop in ("?", "#"):
        i = s.find(stop)
        if i != -1:
            s = s[:i]
    if not s.startswith("/") or s.startswith("//"):
        return ""  # not a path: absolute-form targets and `//host/...` name a host
    cut = False
    m = _SAMPLE_SCHEME_RE.search(s)
    if m:
        s, cut = s[: m.start()], True
    run = _SAMPLE_PATH_RE.match(s)
    ok = run.group(0) if run else ""
    if len(ok) < len(s):
        cut = True
    if len(ok) > SAMPLE_PATH_MAX:
        ok, cut = ok[:SAMPLE_PATH_MAX], True
    return (ok + "...") if (ok and cut) else ok


def _sample_status(v):
    try:
        n = int(v)
    except (TypeError, ValueError, OverflowError):
        return 0
    return n if 100 <= n <= 599 else 0


def normalize_sample(raw, now=None, families=AGENT_SOURCES):
    """One sample rebuilt from its parts, or None. `families` is what the sender
    may speak for, as in normalize_event. The path is required: a sample with
    none says nothing."""
    if not isinstance(raw, dict):
        return None
    fam = raw.get("f")
    if not isinstance(fam, str) or fam not in families:
        return None
    path = clean_path(raw.get("p"))
    if not path:
        return None
    method = raw.get("m")
    method = method if isinstance(method, str) and method in _SAMPLE_METHODS else ""
    if now is None:
        try:
            t = max(0, min(_SAMPLE_T_MAX, int(raw.get("t"))))
        except (TypeError, ValueError, OverflowError):
            t = 0
    else:
        t = _ts(raw.get("t"), int(now))
    return {"f": fam, "m": method, "p": path, "c": _sample_status(raw.get("c")), "t": t}


def normalize_samples(raw, now=None, families=AGENT_SOURCES):
    """Up to MAX_SAMPLES samples, each rebuilt, the first of each method and path."""
    out, seen = [], set()
    for item in raw if isinstance(raw, list) else []:
        smp = normalize_sample(item, now, families)
        if smp is None or (smp["m"], smp["p"]) in seen:
            continue
        seen.add((smp["m"], smp["p"]))
        out.append(smp)
        if len(out) >= MAX_SAMPLES:
            break
    return out


def sample_text(smp):
    """'GET /wp-login.php (404)': one sample as plain text for a report or a log."""
    parts = [smp.get("m") or "", smp.get("p") or ""]
    text = " ".join(x for x in parts if x)
    return f"{text} ({smp['c']})" if smp.get("c") else text


# ── token -> class ─────────────────────────────────────────────────────────────

# Ordered: the first rule that matches a name wins, so the specific ones come
# before the broad ones. Names are matched lowercase.
#
# Short tokens are matched as whole words (_W below). Without that, "rdp" is
# found inside "wordpress" and "rce" inside "force", and a WordPress jail is
# reported as an RDP brute-forcer.
_B = r"(?<![a-z0-9])"
_E = r"(?![a-z0-9])"


def _w(*words):
    """A pattern that matches any of `words` only as a whole word."""
    return _B + "(?:" + "|".join(words) + ")" + _E


_JAIL_RULES = tuple(
    (cls, re.compile(rx))
    for cls, rx in (
        ("ssh_brute", r"ssh"),
        ("waf", r"modsec|waf|appsec|mod-security"),
        ("sqli", r"sqli|sql-?inj"),
        ("traversal", _w("lfi", "rfi") + r"|travers|url-?fopen"),
        ("xss", _w("xss")),
        ("rce", _w("rce") + r"|php-?inj|injection|exploit|shellshock|log4|webshell|cve"),
        (
            "mail_brute",
            r"postfix|dovecot|exim|sendmail|smtp|imap|pop3|sasl|courier|qmail|cyrus|sieve",
        ),
        ("ftp_brute", r"ftp"),
        ("flood", _w("dos") + r"|limit-?req|req-?limit|rate-?limit|flood|limit-?conn"),
        ("bad_bot", r"bad-?bots?|unwanted|crawler|scrap|fake-?google|fake-?bot"),
        ("port_scan", r"port-?scan|iptables-?scan"),
        # The four below are where a jail gained a class or a truer one in 8.0.1: xrdp, samba and vnc had none
        # (their bans said "no attack category"), and mssql-auth was a web login by its "auth".
        ("rdp_brute", _w("rdp") + r"|xrdp"),
        ("smb_brute", _w("smb") + r"|samba|smbd"),
        ("telnet_brute", r"telnet"),
        ("db_brute", r"mysql|maria|postgres|pgsql|mongo|redis|mssql"),
        ("service_brute", r"asterisk|openvpn|" + _w("vnc")),
        ("login_brute", _w("wp") + r"|auth(?!or)|wordpress|xmlrpc|login"),
        ("proxy_probe", r"noproxy"),
        ("config_probe", r"sensitive|dotfile"),
        (
            "probe",
            r"noscript|nohome|botsearch|blocked|probe|scan|forbidden|overflow|404|4xx",
        ),
    )
)

_CS_RULES = tuple(
    (cls, re.compile(rx))
    for cls, rx in (
        ("ssh_brute", r"ssh"),
        (
            "rce",
            _w("rce")
            + r"|vpatch|cve|log4j|log4shell|spring4shell|shellshock|backdoor|webshell|exploit"
            + r"|ssti|uploads-php|vmsa",
        ),
        # `crs` is the OWASP core rule set as an AppSec rule or an anomaly-score scenario; `base-config` is AppSec's own.
        ("waf", r"appsec|modsec|base-config|" + _w("crs")),
        ("sqli", r"sqli"),
        ("xss", _w("xss")),
        ("traversal", _w("lfi", "rfi") + r"|traversal"),
        ("flood", _w("dos") + r"|req-limit|rate-limit|flood"),
        ("scanner", r"bad-user-agent|scanner|nikto|nmap|masscan"),
        (
            "login_brute",
            r"wordpress_bf|bf-wordpress|http-bf|generic-bf|401-bf|403-bf|auth-bf|login",
        ),
        ("mail_brute", r"postfix|dovecot|exim|sendmail|smtp|imap|pop3|spam"),
        ("ftp_brute", r"ftp"),
        ("port_scan", r"portscan|port-scan|iptables-scan|refused-conn|scan-multi"),
        # The finer kinds of probing come before the general one. Each takes names that were `probe` and no others
        # (tests/test_v801_attack_classes.py holds that over the frozen hub names).
        ("user_enum", r"wordpress_user-enum"),
        ("config_probe", r"sensitive-files|wpconfig"),
        ("admin_probe", r"admin-interface|sap-interface-probing"),
        ("wordpress", r"wordpress-scan|uploads-listing|xmlrpc"),
        ("proxy_probe", r"open-proxy"),
        ("probe", r"probing|user-enum|http-.*scan|w00tw00t"),
        # ... and the finer kinds of a service's login before the general one.
        ("rdp_brute", _w("rdp")),
        ("smb_brute", _w("smb")),
        ("telnet_brute", r"telnet"),
        ("db_brute", r"mysql|pgsql|mariadb|mongo|redis|mssql-bf|couchdb-bf"),
        (
            "service_brute",
            r"(^|-)bf($|-)|brute|asterisk|openvpn|cowrie|guacamole",
        ),
    )
)

_CRS_TAGS = {
    "attack-sqli": "sqli",
    "attack-xss": "xss",
    "attack-lfi": "traversal",
    "attack-rfi": "traversal",
    "attack-rce": "rce",
    "attack-injection-php": "rce",
    "attack-injection-generic": "rce",
    "attack-injection-java": "rce",
    "attack-reputation-scanner": "scanner",
    "attack-dos": "flood",
    "attack-protocol": "waf",
    "attack-generic": "waf",
    "attack-fixation": "waf",
    "attack-multipart-bypass": "waf",
    "attack-ssrf": "waf",
}


def jail_class(name):
    n = str(name or "").lower()
    for cls, rx in _JAIL_RULES:
        if rx.search(n):
            return cls
    return None


def scenario_class(name):
    n = str(name or "").lower()
    if n.startswith("crowdsecurity/"):
        n = n[len("crowdsecurity/") :]
    for cls, rx in _CS_RULES:
        if rx.search(n):
            return cls
    return None


def crs_class(rule_id):
    """Class for an OWASP CRS rule id, by the id ranges the rule set documents.
    The anomaly-score summaries (949/959/980) and the response-side leak rules
    (950-958) describe the transaction or OUR answer, not what the client
    attempted, so they name no class."""
    try:
        n = int(rule_id)
    except (TypeError, ValueError):
        return None
    if 913000 <= n < 914000:
        return "scanner"
    if 930000 <= n < 932000:
        return "traversal"
    if 932000 <= n < 935000 or 944000 <= n < 945000:
        return "rce"
    if 941000 <= n < 942000:
        return "xss"
    if 942000 <= n < 943000:
        return "sqli"
    if 900000 <= n < 913000 or 949000 <= n < 960000 or 980000 <= n < 981000:
        return None
    return "waf"


def req_token(class_id):
    """The `req:` token that stands for a class ('req:config' for config_probe), or None
    when no request kind names it. For a reader that has decided the class itself: a
    Cloudflare rule the operator described."""
    for kind, cls in _REQ_KINDS.items():
        if cls == class_id:
            return "req:" + kind
    return None


def token_class(token):
    """The attack class a valid token stands for, or None."""
    if not token_valid(token):
        return None
    kind, _, val = token.partition(":")
    if kind == "req":
        return _REQ_KINDS.get(val)
    if kind == "crs":
        return crs_class(val)
    if kind == "crstag":
        return _CRS_TAGS.get(val)
    if kind == "jail":
        return jail_class(val)
    if kind == "cs":
        return scenario_class(val)
    if kind == "fw":
        return "port_scan"
    if kind == "cf":
        return CF_KINDS.get(val)
    if kind == "trap":
        return TRAP_KINDS.get(val)
    if kind == "ids":
        return val
    if kind == "dp":
        return "decoy_port"
    return None


# ── ingest ─────────────────────────────────────────────────────────────────────


def _count(v):
    if isinstance(v, bool):
        return 0
    try:
        return max(0, min(_MAX_COUNT, int(v)))
    except (TypeError, ValueError, OverflowError):
        return 0


def _ts(v, now):
    try:
        t = int(v)
    except (TypeError, ValueError, OverflowError):
        return now
    return max(now - _MAX_AGE_S, min(now + _SKEW_S, t))


def public_ip(value):
    """Normalised address when it is globally routable unicast, else None."""
    try:
        a = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    if getattr(a, "scope_id", None):
        return None  # "2606:4700::1%anything" parses; the text after % is not an address
    if getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    if not a.is_global or a.is_multicast:
        return None
    return str(a)


def blank(ip=""):
    return {
        "ip": ip,
        "first": 0,
        "last": 0,
        "src": {},
        "tok": {},
        "ans": 0,
        "blk": 0,
        "ban": [],
        "dec": 0,
        "trp": 0,
        "rep": 0,
        "cve": [],
        "smp": [],
    }


def normalize_event(raw, now=None, families=AGENT_SOURCES):
    """One address's summary, reduced to the vocabulary, or None when there is
    nothing usable (not an address, or no evidence at all). `families` is what
    the sender may speak for: an agent's summary is read with AGENT_SOURCES, the
    server's edge feeds with EDGE_SOURCES, so a family it may not claim is
    dropped here rather than trusted."""
    if not isinstance(raw, dict):
        return None
    ip = public_ip(raw.get("ip"))
    if not ip:
        return None
    now = int(now or time.time())
    ev = blank(ip)
    first, last = _ts(raw.get("first"), now), _ts(raw.get("last"), now)
    ev["first"], ev["last"] = (first, last) if first <= last else (last, first)
    src = raw.get("src") if isinstance(raw.get("src"), dict) else {}
    for fam in families:
        n = _count(src.get(fam))
        if n:
            ev["src"][fam] = n
    tok = raw.get("tok") if isinstance(raw.get("tok"), dict) else {}
    for fam in families:
        d = tok.get(fam)
        if not isinstance(d, dict):
            continue
        out = {}
        for t, c in d.items():
            n = _count(c)
            if n and token_valid(t):
                out[t] = n
        if out:
            ev["tok"][fam] = dict(sorted(out.items(), key=lambda kv: -kv[1])[:_MAX_TOKENS])
    ev["ans"], ev["blk"] = _count(raw.get("ans")), _count(raw.get("blk"))
    if "cs" in families:
        ev["dec"] = _count(raw.get("dec"))
    if "f2b" in families:
        jails = raw.get("ban") if isinstance(raw.get("ban"), list) else []
        ev["ban"] = _uniq(j for j in jails if isinstance(j, str) and _JAIL_RE.fullmatch(j))[
            :_MAX_JAILS
        ]
    if "trap" in families or "dp" in families:
        ev["trp"] = _count(raw.get("trp"))
    if "dp" in families:
        # the reputation-list repeat count is the appliance reader's: it counts blocked hits itself. An agent has no such list
        ev["rep"] = _count(raw.get("rep"))
    cves = raw.get("cve") if isinstance(raw.get("cve"), list) else []
    ev["cve"] = _uniq(c for c in cves if isinstance(c, str) and _CVE_RE.fullmatch(c))[:_MAX_CVES]
    ev["smp"] = normalize_samples(raw.get("smp"), now, families)
    if not (ev["src"] or ev["tok"] or ev["ban"] or ev["dec"] or ev["trp"] or ev["rep"]):
        return None
    return ev


def _uniq(items):
    seen, out = set(), []
    for i in items:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def merge(a, b):
    """Two summaries of the same address added together. Neither is changed.
    The windows are different stretches of the log, so counts add."""
    out = blank((a or {}).get("ip") or (b or {}).get("ip") or "")
    a, b = a or blank(), b or blank()
    firsts = [x for x in (a.get("first"), b.get("first")) if x]
    out["first"] = min(firsts) if firsts else 0
    out["last"] = max(a.get("last") or 0, b.get("last") or 0)
    for fam in SOURCES:
        n = _count((a.get("src") or {}).get(fam)) + _count((b.get("src") or {}).get(fam))
        if n:
            out["src"][fam] = min(_MAX_COUNT, n)
        merged = {}
        for d in ((a.get("tok") or {}).get(fam) or {}, (b.get("tok") or {}).get(fam) or {}):
            for t, c in d.items():
                merged[t] = min(_MAX_COUNT, merged.get(t, 0) + _count(c))
        if merged:
            out["tok"][fam] = dict(sorted(merged.items(), key=lambda kv: -kv[1])[:_MAX_TOKENS])
    out["ans"] = min(_MAX_COUNT, _count(a.get("ans")) + _count(b.get("ans")))
    out["blk"] = min(_MAX_COUNT, _count(a.get("blk")) + _count(b.get("blk")))
    out["dec"] = min(_MAX_COUNT, _count(a.get("dec")) + _count(b.get("dec")))
    out["trp"] = min(_MAX_COUNT, _count(a.get("trp")) + _count(b.get("trp")))
    out["rep"] = min(_MAX_COUNT, _count(a.get("rep")) + _count(b.get("rep")))
    out["ban"] = _uniq(list(a.get("ban") or []) + list(b.get("ban") or []))[:_MAX_JAILS]
    out["cve"] = _uniq(list(a.get("cve") or []) + list(b.get("cve") or []))[:_MAX_CVES]
    # The earlier sample stays first; both lists are checked again, because a ledger is read back from storage.
    out["smp"] = normalize_samples(
        list(a.get("smp") or []) + list(b.get("smp") or []), None, SOURCES
    )
    return out


def slim(ev, tokens=8):
    """A copy small enough to keep per address for a day: the biggest few tokens
    per source and the first few jails and CVE ids. What a report needs (classes,
    counts, sources) survives; the long tail does not."""
    out = dict(blank(ev.get("ip", "")), **{k: v for k, v in ev.items() if k in blank()})
    out["tok"] = {
        fam: dict(sorted(t.items(), key=lambda kv: -kv[1])[:tokens])
        for fam, t in (ev.get("tok") or {}).items()
        if t
    }
    out["ban"] = list(ev.get("ban") or [])[:4]
    out["cve"] = list(ev.get("cve") or [])[:3]
    out["smp"] = list(ev.get("smp") or [])[:MAX_SAMPLES]
    return out


# ── reading evidence ───────────────────────────────────────────────────────────


def classes(ev):
    """{class: count}. A class takes the LARGEST count of any token that
    names it: the same request is seen by the access log, the WAF and the
    jail, so adding them would count it three times."""
    out = {}
    for toks in (ev.get("tok") or {}).values():
        for t, c in toks.items():
            cls = token_class(t)
            if cls:
                out[cls] = max(out.get(cls, 0), _count(c))
    for jail in ev.get("ban") or []:
        cls = jail_class(jail)
        if cls:
            out[cls] = max(out.get(cls, 0), 1)
    waf = _count((ev.get("src") or {}).get("waf"))
    if waf:
        out["waf"] = max(out.get("waf", 0), waf)
    return out


def hostile_count(ev):
    """How many hostile events: the largest source family, else the largest
    class. Never a sum."""
    src = [n for n in (ev.get("src") or {}).values() if n]
    if src:
        return max(src)
    cls = classes(ev)
    return max(cls.values()) if cls else 0


def _spoken(ev):
    """{class: count} for what a report says: `classes` without the ones that only repeat
    another. The generic WAF class steps aside when a specific class explains the blocks.
    A general class (FAMILIES) steps aside when its own kinds account for it, that is when
    its count is no larger than theirs together: a fail2ban ban for "bot search" beside
    twelve requests for /.env is the same probing seen twice, and the report says
    "probing for configuration files". When the general count is the larger one the
    address did more than its kinds say (one request for /.env and fifty the source could
    only call probing), so both are said: naming the kind alone would put all fifty-one
    under it, and under its category."""
    cls = classes(ev)
    if len(cls) > 1:
        cls.pop("waf", None)
    for general, kinds in FAMILIES.items():
        if general in cls:
            named = sum(cls[k] for k in kinds if k in cls)
            if named and cls[general] <= named:
                del cls[general]
    return cls


def dominant(ev, limit=3):
    """[(class, count)] most telling first, of the classes a report speaks for."""
    cls = _spoken(ev)
    ranked = sorted(
        cls.items(), key=lambda kv: (-(CLASSES[kv[0]]["weight"] * max(kv[1], 1)), kv[0])
    )
    return ranked[:limit]


def report_classes(ev):
    """The classes a report would speak for, as a set: what `dominant` ranks. Used to
    tell whether everything an address did is a kind of attack the operator ignores.
    The rule in `_spoken` decides it here too: a general class that its kinds account
    for is not a second thing the address did, and one they do not account for is, so
    ignoring one kind of probing never holds back an address that mostly probed in
    ways no kind names."""
    return set(_spoken(ev))


def with_kinds(class_ids):
    """`class_ids` and the finer kinds of every general class in it, as a set. An
    operator who ignores "probing" ignored every kind of it before the kinds had
    names, and still does."""
    out = set(class_ids or ())
    for general, kinds in FAMILIES.items():
        if general in out:
            out.update(kinds)
    return out


def trap_family(ev):
    """'dp' when the trap decision `trp` was a decoy port's, else 'trap'. The two
    share the counter; an address the edge honeypot also saw has the honeypot's say."""
    src, tok = ev.get("src") or {}, ev.get("tok") or {}
    if src.get("trap") or tok.get("trap"):
        return "trap"
    if src.get("dp") or tok.get("dp"):
        return "dp"
    return "trap"


def confirmed_by(ev, traps=True):
    """Who already decided this address is hostile: 'fail2ban', 'CrowdSec', 'the
    edge honeypot', 'a decoy port' or ''. A honeypot decision counts as its own ban
    for a report: the request was one that a visitor would not make on their own,
    and not a count of hits.

    `traps=False` leaves a trap's decision out. A trap is asked by whoever can get a
    request or a connection sent to it, so what it says is enough to report an
    address and is never enough to block or list one without a second source
    (`beyond_traps`)."""
    if ev.get("ban"):
        return "fail2ban"
    if _count(ev.get("dec")):
        return "CrowdSec"
    if traps and _count(ev.get("trp")):
        return "a decoy port" if trap_family(ev) == "dp" else "the edge honeypot"
    return ""


# The two sources that are traps: the honeypot Worker's log and a decoy port's. Both are visited, and a visit can be made by a third party
# (a page that makes a browser ask for an image, a service that follows a link someone posted, a connection a browser opens to any port it
# allows), so neither is the word of the address that the visit came from.
TRAP_SOURCES = ("trap", "dp")


def beyond_traps(ev):
    """True when something besides a trap says the address is hostile: a ban engine's decision, a CrowdSec decision, a reputation list
    that a firewall blocked it for, or a source that is not a trap and saw it do something. False for evidence made of traps alone (and
    for none), which is why a trap's decision reports an address and does not block or list it."""
    if not isinstance(ev, dict):
        return False
    if ev.get("ban") or _count(ev.get("dec")) or _count(ev.get("rep")):
        return True
    src = ev.get("src") if isinstance(ev.get("src"), dict) else {}
    tok = ev.get("tok") if isinstance(ev.get("tok"), dict) else {}
    for fam in set(src) | set(tok):
        if fam not in TRAP_SOURCES and (_count(src.get(fam)) or tok.get(fam)):
            return True
    return False


def cs_scenarios(ev, limit=5):
    """[(scenario, count, class or None)] for the CrowdSec scenarios and AppSec rules the
    logs named, most seen first. The name is the fixed identifier of a hub scenario or
    of one the operator wrote, and it has already passed the token check."""
    seen = {}
    for toks in (ev.get("tok") or {}).values():
        for t, c in toks.items():
            if isinstance(t, str) and t.startswith("cs:") and token_valid(t):
                seen[t[3:]] = max(seen.get(t[3:], 0), _count(c))
    ranked = sorted(seen.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]
    return [(name, n, scenario_class(name)) for name, n in ranked]


def _no_class_reason(ev):
    """Why an address with no attack class is not reported. It names the CrowdSec scenario or
    the fail2ban jail that decided on it when there is one, so the page can say what the logs
    held and the operator can see which name has no category."""
    for name, _n, cls in cs_scenarios(ev):
        if cls is None:
            return f"no attack category for the CrowdSec scenario {name}"
    for jail in ev.get("ban") or []:
        if not jail_class(jail):
            return f"no attack category for the fail2ban jail {jail}"
    return "nothing recognisable in the logs"


def qualifies(ev, min_count, cf_min=None, waf_min=None):
    """(True, why) when the evidence is enough to report, else (False, why not).
    Enough means ANY of: fail2ban banned it, a CrowdSec scenario decided on it,
    the WAF refused it `waf_min` times, Cloudflare refused it `cf_min` times, or
    it made `min_count` hostile requests. An address with no class is never
    reportable: a report needs an honest category.

    `waf_min` and `cf_min` are the operator's settings for a host's WAF and for
    the edge. A refusal is a block a rule of theirs has already made. Left out,
    both fall back to WAF_MIN_BLOCKS, the library's own default; the server
    passes its policy, which asks for one."""
    if not classes(ev):
        return False, _no_class_reason(ev)
    who = confirmed_by(ev)
    if who:
        return True, f"confirmed by {who}"
    # A firewall blocked an address on a reputation list again and again. The sensor only
    # sets `rep` once the operator's bar ("Report listed addresses after") is crossed.
    rep = _count(ev.get("rep"))
    if rep:
        return True, f"blocked {rep} times by a firewall while on a reputation list"
    waf = _count((ev.get("src") or {}).get("waf"))
    try:
        waf_need = max(1, int(waf_min)) if waf_min else WAF_MIN_BLOCKS
    except (TypeError, ValueError):
        waf_need = WAF_MIN_BLOCKS
    if waf >= waf_need:
        return True, f"blocked by the WAF {waf} times"
    cf = _count((ev.get("src") or {}).get("cf"))
    try:
        cf_need = max(1, int(cf_min)) if cf_min else WAF_MIN_BLOCKS
    except (TypeError, ValueError):
        cf_need = WAF_MIN_BLOCKS
    if cf >= cf_need:
        return True, f"blocked by Cloudflare {cf} times"
    n, need = hostile_count(ev), max(1, int(min_count or 1))
    if n >= need:
        return True, f"{n} hostile requests"
    # Nothing qualifies yet. Name the route that is nearest, so an address with
    # two WAF refusals is not told it needs ten requests.
    routes = [(need - n, f"{n} of {need} attempts so far")]
    if waf:
        routes.append((waf_need - waf, f"{waf} of {waf_need} WAF refusals so far"))
    if cf:
        routes.append((cf_need - cf, f"{cf} of {cf_need} Cloudflare refusals so far"))
    return False, min(routes, key=lambda r: r[0])[1]


def categories(ev, provider, limit=6):
    """Provider category ids for the evidence, most telling class first."""
    out = []
    for cls, _n in dominant(ev, 4):
        for c in CLASSES[cls].get(provider, ()):
            if c not in out:
                out.append(c)
    return out[:limit]


# ── words for a report ─────────────────────────────────────────────────────────


def _join(parts):
    if len(parts) <= 1:
        return "".join(parts)
    return ", ".join(parts[:-1]) + " and " + parts[-1]


def attack_phrase(ev):
    """'SQL injection and path traversal' — fixed phrases only. A CVE id the
    logs named is a public identifier, so up to two ride along."""
    parts = [CLASSES[c]["phrase"] for c, _n in dominant(ev, 3)]
    text = _join(parts)
    cves = list(ev.get("cve") or [])[:2]
    if text and cves:
        text += " (" + ", ".join(cves) + ")"
    return text


def seen_by(ev):
    """'web server log, WAF and fail2ban' — the sources that saw the address."""
    fams = []
    src, tok = ev.get("src") or {}, ev.get("tok") or {}
    for fam in SOURCES:
        saw = src.get(fam) or tok.get(fam)
        if fam == "f2b":
            saw = saw or ev.get("ban")
        if fam == "cs":
            saw = saw or ev.get("dec")
        if fam == trap_family(ev):
            saw = saw or ev.get("trp")
        if saw:
            fams.append(fam)
    return _join(_uniq(SOURCE_PHRASE[f] for f in fams))


def what_word(ev):
    """The short noun `{what}` stands for: 'SSH', 'web login', 'web', ..."""
    top = dominant(ev, 1)
    if not top:
        return "login"
    cls = top[0][0]
    if cls in _WHAT:
        return _WHAT[cls]
    return "web" if cls in _WEB_CLASSES else "login"


def window_seconds(ev):
    span = int(ev.get("last") or 0) - int(ev.get("first") or 0)
    return max(60, min(86400, span))


def web_only(ev):
    """True when every class the address was seen in is a web one."""
    cls = classes(ev)
    return bool(cls) and all(c in _WEB_CLASSES or c == "login_brute" for c in cls)


# ── addresses nobody should report or block ────────────────────────────────────

# Cloudflare's published edge ranges (cloudflare.com/ips-v4 and /ips-v6, checked
# 2026-11-07: 15 IPv4 and 7 IPv6, the same as the API's /client/v4/ips). A web server that does not restore the visitor's address logs
# these instead, and a report naming one would blame the proxy. The list is a
# floor, not a promise: the operator's never-block list covers anything else.
CLOUDFLARE_RANGES = (
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
)
_CLOUDFLARE_NETS = tuple(ipaddress.ip_network(c) for c in CLOUDFLARE_RANGES)


def infra_reason(ip):
    """A sentence saying why this is infrastructure rather than an attacker,
    or ''."""
    try:
        a = ipaddress.ip_address(str(ip or "").strip())
    except ValueError:
        return ""
    if getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    for n in _CLOUDFLARE_NETS:
        if a.version == n.version and a in n:
            return "a Cloudflare edge address"
    return ""

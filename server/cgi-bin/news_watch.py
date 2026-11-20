"""RemotePower — Security news watch: the pure part (8.0.2)

Reads an RSS or Atom feed of security news, finds the items that report a critical flaw, and keeps what it has already seen. It does no network
or storage work: `news_watch_handlers` fetches, saves and raises the alerts, and calls into here with bytes, dicts and a clock.

An item counts as critical when its headline or summary says so in one of six ways (see `classify`): the word "critical" beside a word for a flaw,
a CVSS score of 9.0 or more, a zero-day, active exploitation, code execution without signing in, or a CVE id that CISA lists as known to be exploited.
The reasons are returned as short codes, so the page can say them in the reader's language.

An item is relevant when it names software the hosts have installed (`vocabulary`, `software_in`). The package names of the fleet are reduced to
the first word of the name, and a stop list keeps the words that are also package names ("patch", "file", "which") from matching every article.

Feed text is untrusted. It is parsed through safe_xml, cut to fixed lengths, stripped of markup and control characters, and only an http or https
link is kept. Nothing here treats it as anything but text.
"""

import hashlib
import html
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import parse_qsl, urlsplit

import app_catalog
import safe_xml

DEFAULT_FEEDS = ("https://feeds.feedburner.com/TheHackersNews",)
SCOPES = (
    "running",
    "relevant",
    "all",
)  # what counts: software that runs on a host, software on a host (installed or running), every critical item
ACTIONS = ("list", "alert", "scan")
DEFAULTS = {
    "enabled": False,
    "feeds": list(DEFAULT_FEEDS),
    "scope": "relevant",
    "action": "scan",
    "words": [],
}

MAX_FEEDS = 5
MAX_WORDS = 50  # names of software an operator adds to the built-in list
MAX_URL_LEN = 300
MAX_FEED_BYTES = 2_000_000  # what one fetch may return
MAX_ITEMS_PER_FEED = 60  # items read from one feed
MAX_SEEN = 400  # ids remembered for one feed
MAX_LISTED = 60  # critical items kept for the page
MAX_AGE_S = 3 * 86400  # an item older than this is listed but never acted on
TITLE_LEN = 200
TEXT_LEN = 1500  # the part of an item's summary that is read
LINK_LEN = 500
MAX_CVES = 10

# the six reasons an item counts as critical, as the codes the page translates
REASONS = ("critical", "cvss", "zero_day", "exploited", "unauth_exec", "kev")

# the outcome recorded for each critical item
OUTCOMES = (
    "baseline",
    "listed",
    "alerted",
    "scanned",
    "scan_waiting",
    "scan_refused",
    "over_limit",
    "stale",
)


# ── settings ─────────────────────────────────────────────────────────────────

# a query parameter that looks like a credential: the address is shown to administrators, so a feed that needs one is not supported. The name is compared with its
# punctuation taken out and by its end ("access_token", "api-key", "X-Auth"), so that `author=smith` or `keyword=php` is still a feed address.
_SECRET_END = (
    "token",
    "secret",
    "password",
    "passwd",
    "apikey",
    "accesskey",
    "secretkey",
    "auth",
    "authorization",
    "signature",
)
_SECRET_NAME = ("sig", "key", "pw", "pwd", "pass")


def _looks_like_a_credential(name):
    n = re.sub(r"[^a-z0-9]", "", str(name).lower())
    return n in _SECRET_NAME or n.endswith(_SECRET_END)


_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_SPACE = re.compile(r"\s+")


def valid_feed_url(raw):
    """(url, None) for an address a feed may be read from, or (None, why). http or https, a host, no user name or password in it, no
    parameter named like a credential, no blanks or control characters, at most MAX_URL_LEN characters.
    """
    if not isinstance(raw, str):
        return None, "a feed address is text"
    url = raw.strip()
    if not url:
        return None, "a feed address is empty"
    if len(url) > MAX_URL_LEN:
        return None, f"a feed address is longer than {MAX_URL_LEN} characters"
    if _CTRL.search(url) or re.search(r"\s", url):
        return None, "a feed address has a blank or a control character in it"
    try:
        parts = urlsplit(url)
        host = parts.hostname
        parts.port  # raises ValueError for a port that is not a number
        query = parse_qsl(parts.query, keep_blank_values=True)
    except ValueError:
        return None, "a feed address is not a valid address"
    if parts.scheme not in ("http", "https"):
        return None, "a feed address starts with http:// or https://"
    if not host:
        return None, "a feed address has no host"
    if parts.username is not None or parts.password is not None:
        return (
            None,
            "a feed address has a user name or password in it; the address is shown to administrators, so use a public feed",
        )
    for name, _ in query:
        if _looks_like_a_credential(name):
            return (
                None,
                "a feed address has a parameter that looks like a token; the address is shown to administrators, so use a public feed",
            )
    return url, None


_WORD_OK = re.compile(r"^[a-z][a-z0-9]{2,31}$")


def clean_words(raw):
    """(the names, None) for a list of software names, or (None, why).

    A name is the word a package of that software starts with, in lower case and without its version: `unrealircd`, not `unrealircd6`. Text with one name on each line, or
    names split by commas or blanks, is read as a list. The names are added to the built-in list of software the watch recognises, so a package of that name counts as
    software the hosts have. A name on the stop list is refused, since the watch never counts those; at most MAX_WORDS.
    """
    if isinstance(raw, str):
        raw = [w for w in re.split(r"[\s,;]+", raw) if w]
    if not isinstance(raw, list):
        return None, "words is a list of software names"
    out = []
    for w in raw:
        if not isinstance(w, str):
            return None, "a software name is text"
        word = w.strip().lower()
        base = word.rstrip("0123456789")
        word = base if len(base) >= 3 else word  # the rule of package_tokens: "php8" is php
        if not _WORD_OK.match(word):
            return (
                None,
                f"a software name is one word of letters and digits, 3 to 32 characters: {_clean(w, 40)}",
            )
        if word in STOP:
            return None, f"{word} is an everyday word, and the watch never counts those"
        if word not in out:
            out.append(word)
    if len(out) > MAX_WORDS:
        return None, f"at most {MAX_WORDS} names"
    return out, None


def settings(raw):
    """The settings as they are stored, read defensively: a document edited by hand, or written by an older release, never raises. Anything
    that is not valid reads as the default for that field; an address that is not valid is left out of the list.
    """
    raw = raw if isinstance(raw, dict) else {}
    out = dict(DEFAULTS)
    out["feeds"] = list(DEFAULT_FEEDS)
    out["words"] = []
    if raw.get("enabled") is True:
        out["enabled"] = True
    feeds = raw.get("feeds")
    if isinstance(feeds, list):
        kept = []
        for f in feeds:
            url, _ = valid_feed_url(f)
            if url and url not in kept:
                kept.append(url)
        out["feeds"] = kept[:MAX_FEEDS]
    if raw.get("scope") in SCOPES:
        out["scope"] = raw["scope"]
    if raw.get("action") in ACTIONS:
        out["action"] = raw["action"]
    words = raw.get("words")
    if isinstance(words, list):
        for w in words:
            ok, _ = clean_words([w]) if isinstance(w, str) else (None, None)
            if ok and ok[0] not in out["words"] and len(out["words"]) < MAX_WORDS:
                out["words"].append(ok[0])
    return out


def clean_update(body):
    """(the fields to change, None) or (None, the first thing that is wrong). A field that is not in the body is left as it is. `feeds` is a
    list of addresses or text with one address on each line."""
    body = body if isinstance(body, dict) else {}
    update = {}
    if "enabled" in body:
        v = body["enabled"]
        if isinstance(v, str):
            v = {"true": True, "false": False}.get(v.strip().lower(), v)
        if not isinstance(v, bool):
            return None, "enabled is true or false"
        update["enabled"] = v
    if "feeds" in body:
        raw = body["feeds"]
        if isinstance(raw, str):
            raw = [ln for ln in raw.splitlines() if ln.strip()]
        if not isinstance(raw, list):
            return None, "feeds is a list of addresses"
        if len(raw) > MAX_FEEDS:
            return None, f"at most {MAX_FEEDS} feeds"
        feeds = []
        for f in raw:
            url, why = valid_feed_url(f)
            if why:
                return None, why
            if url not in feeds:
                feeds.append(url)
        update["feeds"] = feeds
    for name, allowed in (("scope", SCOPES), ("action", ACTIONS)):
        if name in body:
            if body[name] not in allowed:
                return None, f"{name} is one of: " + ", ".join(allowed)
            update[name] = body[name]
    if "words" in body:
        words, why = clean_words(body["words"])
        if why:
            return None, why
        update["words"] = words
    return update, None


# ── reading a feed ───────────────────────────────────────────────────────────

_TAG = re.compile(r"<[^>]*>")


def _clean(text, limit):
    """Text of a feed with its markup, entities, control characters and runs of blanks taken out, cut to `limit` characters."""
    if not isinstance(text, str):
        return ""
    text = html.unescape(_TAG.sub(" ", html.unescape(text)))
    text = _TAG.sub(" ", text)
    return _SPACE.sub(" ", _CTRL.sub(" ", text)).strip()[:limit]


def _local(tag):
    """The name of an element without its namespace, in lower case."""
    return tag.rsplit("}", 1)[-1].lower() if isinstance(tag, str) else ""


def _text(el):
    return "".join(el.itertext()) if el is not None else ""


def _child(el, name):
    """The first child of `el` with this local name, or None."""
    for c in el:
        if _local(c.tag) == name:
            return c
    return None


def parse_time(raw):
    """Seconds since the epoch for a feed date (RFC 822 in RSS, ISO 8601 in Atom), or None."""
    s = (raw or "").strip() if isinstance(raw, str) else ""
    if not s:
        return None
    dt = None
    try:
        dt = parsedate_to_datetime(s)
    except (TypeError, ValueError, IndexError, OverflowError):
        pass
    if dt is None:
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None
    try:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except (OverflowError, OSError, ValueError):
        return None


def _link(url):
    """`url` when it is an http or https address with a host, else empty."""
    url = _CTRL.sub("", url or "").strip()
    try:
        parts = urlsplit(url)
        ok = parts.scheme in ("http", "https") and bool(parts.netloc)
    except ValueError:
        ok = False
    return url[:LINK_LEN] if ok and len(url) <= LINK_LEN else ""


def item_id(raw):
    """The short stable id an item is remembered by."""
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]


def parse_feed(data):
    """{'title': str, 'items': [{id, title, link, published, summary}]} from the bytes of an RSS 2.0, RSS 1.0 or Atom feed. Raises ValueError for
    anything else, for a feed over MAX_FEED_BYTES and for XML that declares a DTD or an entity. At most MAX_ITEMS_PER_FEED items, in feed order.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("the feed is not bytes")
    if len(data) > MAX_FEED_BYTES:
        raise ValueError(f"the feed is larger than {MAX_FEED_BYTES // 1_000_000} MB")
    try:
        root = safe_xml.fromstring(bytes(data))
    except safe_xml.ParseError as e:
        raise ValueError(f"the feed is not valid XML: {e}") from None
    kind = _local(root.tag)
    if kind == "rss":
        channel = _child(root, "channel")
        holder = channel if channel is not None else root
        entries = [c for c in holder if _local(c.tag) == "item"]
    elif kind == "rdf":
        holder = _child(root, "channel") if _child(root, "channel") is not None else root
        entries = [c for c in root if _local(c.tag) == "item"]
    elif kind == "feed":
        holder = root
        entries = [c for c in root if _local(c.tag) == "entry"]
    else:
        raise ValueError("this is not an RSS or Atom feed")
    items = []
    for entry in entries[:MAX_ITEMS_PER_FEED]:
        title = _clean(_text(_child(entry, "title")), TITLE_LEN)
        link = ""
        if kind == "feed":
            for c in entry:
                if (
                    _local(c.tag) == "link"
                    and c.get("rel", "alternate") == "alternate"
                    and c.get("href")
                ):
                    link = _link(c.get("href"))
                    break
        else:
            link = _link(_text(_child(entry, "link")))
        raw_id = (
            _clean(
                _text(
                    _child(entry, "guid")
                    if _child(entry, "guid") is not None
                    else _child(entry, "id")
                ),
                600,
            )
            or link
            or title
        )
        if not raw_id:
            continue
        summary_el = None
        for name in ("description", "summary", "encoded", "content"):
            summary_el = _child(entry, name)
            if summary_el is not None:
                break
        published = None
        for name in ("pubdate", "published", "updated", "date"):
            published = parse_time(_text(_child(entry, name)))
            if published is not None:
                break
        items.append(
            {
                "id": item_id(raw_id),
                "title": title,
                "link": link,
                "published": published,
                "summary": _clean(_text(summary_el), TEXT_LEN),
            }
        )
    return {"title": _clean(_text(_child(holder, "title")), 120), "items": items}


# ── is it critical ───────────────────────────────────────────────────────────

_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_CRITICAL = re.compile(r"\bcritical\b", re.I)
# "critical infrastructure" is about what was attacked, not how bad a flaw is
_NOT_SEVERITY = re.compile(
    r"\bcritical\s+(?:infrastructures?|sectors?|industr\w+|services?|national|systems?|assets?|minerals?|operations?)\b",
    re.I,
)
_FLAW = re.compile(
    r"\b(?:flaws?|vulnerabilit\w+|bugs?|rce|remote code execution|security (?:holes?|issues?|updates?|patch\w*|fix\w*)|zero-?days?|0-days?|cve-\d{4}-\d+|patch(?:es|ed)?)\b",
    re.I,
)
# the score after the word CVSS: the version of the scale (v3.1, 4.0) is skipped, then the first number within 40 characters is the score
_CVSS = re.compile(
    r"\bcvss\b(?:\s*(?:v|version\s*)?[234](?:\.[01])?\b)?[^0-9]{0,40}?(\d{1,2}(?:\.\d)?)", re.I
)
_ZERO_DAY = re.compile(r"\b(?:zero|0)[\s-]days?\b", re.I)
_EXPLOITED = re.compile(
    r"\b(?:actively\s+exploited|(?:is|are|being|been)\s+(?:actively\s+)?exploited|exploited\s+in\s+the\s+wild|in-the-wild\s+exploitation"
    r"|under\s+(?:active\s+)?(?:exploitation|attack)|known\s+exploited|exploited\s+(?:flaws?|vulnerabilit\w+|bugs?)"
    r"|(?:hackers?|attackers?|threat\s+actors?|groups?|criminals?|botnets?)\s+(?:are\s+|is\s+|have\s+)?(?:actively\s+)?exploit(?:s|ed|ing)?)\b",
    re.I,
)
_UNAUTH = re.compile(
    r"\b(?:unauthenticated|pre-?auth(?:entication)?|without\s+(?:any\s+)?(?:authentication|logging\s+in|login|credentials))\b",
    re.I,
)
_EXEC = re.compile(
    r"\b(?:remote\s+code\s+execution|rce|execute\s+(?:arbitrary\s+)?code|run\s+(?:arbitrary\s+)?code|code\s+execution|command\s+injection|takeover|take\s+over)\b",
    re.I,
)
# a round-up, a webinar or an explainer mentions every flaw of the week and is not itself the news
_NOT_NEWS = re.compile(
    r"\b(?:weekly\s+recap|threatsday|webinar|checklist|podcast|ebook|whitepaper|survey)\b", re.I
)


def cves_in(text):
    """The CVE ids in `text`, upper case, in the order they first appear, at most MAX_CVES."""
    seen = []
    for m in _CVE.finditer(text or ""):
        cid = m.group(0).upper()
        if cid not in seen:
            seen.append(cid)
    return seen[:MAX_CVES]


def classify(title, summary, kev=()):
    """{'critical': bool, 'reasons': [code], 'cves': [CVE id], 'cvss': float or None} for an item.

    `kev` is the set of upper-case CVE ids CISA lists as known to be exploited. A round-up, webinar or checklist (by its headline) is never critical.
    """
    title, summary = title or "", summary or ""
    text = f"{title}. {summary}"
    cves = cves_in(text)
    out = {"critical": False, "reasons": [], "cves": cves, "cvss": None}
    if _NOT_NEWS.search(title):
        return out
    reasons = out["reasons"]
    plain = _NOT_SEVERITY.sub(" ", text)
    if _CRITICAL.search(plain) and _FLAW.search(plain):
        reasons.append("critical")
    scores = [float(m.group(1)) for m in _CVSS.finditer(text)]
    top = max((x for x in scores if x <= 10.0), default=None)
    if top is not None and top >= 9.0:
        out["cvss"] = top
        reasons.append("cvss")
    if _ZERO_DAY.search(text):
        reasons.append("zero_day")
    if _EXPLOITED.search(text) and _FLAW.search(text):
        reasons.append("exploited")
    if _UNAUTH.search(text) and _EXEC.search(text):
        reasons.append("unauth_exec")
    if kev and any(c in kev for c in cves):
        reasons.append("kev")
    out["critical"] = bool(reasons)
    return out


# ── does it concern the hosts ────────────────────────────────────────────────

# Package names that are also ordinary words, and words that security news is full of. A package called "patch" or "file" must not make every
# article about a patch or a file relevant. Software that is named like a word and matters ("screen", "time") is not worth the false matches.
STOP = frozenset("""
a all also and any are but can could did does for from had has have her him his how into its just may might more most new not now off old one only
other our out over own per she some such than that the their them then they this two use used uses using very was were what when which while who why
will with would you your via six ten few many much each both same first last next another
about after again against before below between down during here more once under until up
patch patches default team source sources file files shared share input accounts account make tool tools device devices power time less login mount
find user users base common core data utils util dev doc docs server servers client clients network networks security update updates access control
plugin plugins module modules library libraries cloud mail web net remote local auto open free secure attack attacks attacker attackers hack hackers
exploit exploits flaw flaws bug bugs fix fixes code run runs test tests list lists show info help check config setup install manager service services
system systems image images screen tree init dash shell script scripts session sessions memory storage backup agent agents proxy gateway router
switch firewall filter monitor report reports search store cache queue stream video audio sound music game games text editor font fonts theme themes
icon icons color colors print printer mobile desktop window version versions release releases key keys token tokens password passwords
admin root home group groups host hosts name names domain domains page pages site sites app apps application applications package packages
tracker manage manages event events log logs entry entries mode modes state status task tasks job jobs build builds tag tags lock locks link links
mirror mirrors point points range ranges rule rules policy policies profile profiles driver drivers support supports engine engines framework frameworks
platform platforms product products component components feature features option options setting settings tab tabs panel panels bar bars button buttons
menu menus table tables row rows column columns field fields form forms view views model models type types class classes object objects value values
number numbers string strings array arrays map maps set sets item items block blocks unit units case cases step steps path paths line lines word words
note notes mark marks sign signs side sides part parts piece pieces point area areas zone zones level levels layer layers stack stacks pool pools
vault vaults bridge bridges tunnel tunnels cell cells wire wires cable cables plug plugs pipe pipes flow flows trace traces probe probes sensor sensors
alert alerts message messages mailer notify notice notices guard guards watch watcher watchers sync syncs share shares drive drives disk disks
volume volumes label labels
console language languages http https command commands software xml uri url firmware
""".split())

# a package token that the news words differently, and the other way round
_ALIASES = {
    "libssl": ("openssl",),
    "ssl": ("openssl",),
    "libc": ("glibc",),
    "libpq": ("postgresql",),
    "libcurl": ("curl",),
    "httpd": ("apache",),
    "linux": ("kernel",),
    "kernel": ("linux",),
    "libxz": ("xz",),
    "liblzma": ("xz",),
    "libxml": ("libxml2",),
    "libwebp": ("webp",),
    "mariadb": ("mysql",),
    "openjdk": ("java",),
    "jre": ("java",),
    "jdk": ("java",),
    "nodejs": ("node",),
    "libnode": ("node",),
    "sshd": ("openssh",),
    "ssh": ("openssh",),
    "postgres": ("postgresql",),
    "mysqld": ("mysql",),
    "mariadbd": ("mariadb", "mysql"),
    "mongod": ("mongodb",),
    "dockerd": ("docker",),
    "kubelet": ("kubernetes",),
    "kubectl": ("kubernetes",),
    "kubeadm": ("kubernetes",),
    "policykit": ("polkit",),
    "polkitd": ("polkit",),
    "slapd": ("openldap",),
    "smbd": ("samba",),
    "nmbd": ("samba",),
    "winbindd": ("samba",),
    "named": ("bind",),
    "chronyd": ("chrony",),
    "ntpd": ("ntp",),
    "cupsd": ("cups",),
    "rsyslogd": ("rsyslog",),
    "libvirtd": ("libvirt",),
    "zlib1g": ("zlib",),
}
_TOKEN_SPLIT = re.compile(r"[-.+:~ /]")
_WORD = re.compile(r"[a-z][a-z0-9]*")
MAX_NAMES = 400_000


def package_tokens(name):
    """The words that stand for a package in a news item: the first word of its name, with trailing digits and a `lib` prefix taken off, and the
    aliases of those (`libssl3` is OpenSSL, `httpd` is Apache). Empty for a name that is only a stop word.
    """
    if not isinstance(name, str):
        return set()
    first = _TOKEN_SPLIT.split(name.strip().lower(), 1)[0]
    base = first.rstrip("0123456789")
    word = base if len(base) >= 3 else first  # "php8" is php, "x11" stays x11
    cands = {word}
    if word.startswith("lib") and len(word) > 5:
        cands.add(word[3:])
    out = set()
    for c in cands:
        if len(c) >= 3 or c == "xz":
            out.add(c)
            out.update(_ALIASES.get(c, ()))
    return {t for t in out if t not in STOP}


def vocabulary(packages_store):
    """The set of words that stand for the packages of every host in `packages_store` ({host id: {packages: [{name, ...}]}}). Reads at most
    MAX_NAMES package names."""
    vocab, seen = set(), 0
    for entry in packages_store.values() if isinstance(packages_store, dict) else ():
        pk = entry.get("packages") if isinstance(entry, dict) else None
        for p in pk if isinstance(pk, list) else ():
            name = p.get("name") if isinstance(p, dict) else p
            seen += 1
            if seen > MAX_NAMES:
                return vocab
            vocab |= package_tokens(name)
    return vocab


def software_in(text, vocab):
    """The words of `vocab` that `text` mentions, sorted: the software of the hosts that an item names. A word counts with its trailing digits
    taken off ("Ruby3" is Ruby)."""
    if not vocab or not text:
        return []
    found = set()
    for w in _WORD.findall(text.lower()):
        for c in (w, w.rstrip("0123456789")):
            if c in vocab:
                found.add(c)
    return sorted(found)


# Words for software that people write about. A package is only counted for an article when its word is in this list, or when something runs under that name:
# most of the first words of package names are everyday words (console, command, software, uri, firmware), and an article that says "management console" is
# not about console-setup. Software that is installed, is not in this list and does not run is left out; "Every critical item" still lists it.
KNOWN_SOFTWARE = frozenset("""
php nginx apache httpd lighttpd caddy traefik haproxy varnish squid tomcat jetty
python perl ruby java openjdk node nodejs
postgresql postgres mysql mariadb mongodb redis valkey memcached sqlite elasticsearch opensearch influxdb
postfix exim dovecot unbound dnsmasq bind openssh openssl gnutls openvpn wireguard strongswan openldap krb5 sssd samba rsync curl libcurl wget chrony ntp avahi cups
linux kernel glibc systemd polkit sudo bash zsh dbus udev grub busybox vim git subversion tar unzip zip zlib xz libxml2 expat pcre freetype
imagemagick ghostscript ffmpeg libwebp libpng libjpeg libtiff
docker containerd runc podman kubernetes k3s helm qemu libvirt proxmox ceph
firefox chromium thunderbird libreoffice nvidia
wordpress drupal nextcloud gitlab gitea jenkins grafana prometheus zabbix nagios roundcube phpmyadmin mediawiki keycloak consul terraform ansible puppet rabbitmq kafka activemq solr
fail2ban iptables nftables tcpdump nmap clamav rsyslog
""".split())

RUNNING_STALE_S = (
    7 * 86400
)  # a host that has not reported for this long is not evidence of what runs
_CONTAINER_DOWN = ("exited", "dead", "created", "removing", "paused")


def _image_repo(image):
    """The last path segment of a container image without its tag or digest: `grafana/grafana:10.2` is `grafana`."""
    if not isinstance(image, str):
        return ""
    return image.split("@", 1)[0].split(":", 1)[0].rsplit("/", 1)[-1]


def _catalog_tokens():
    """The words of the apps that App discovery knows (the names of their processes, services and container images): they run as these names."""
    out = set()
    for app in app_catalog.APPS:
        for name in (*app["procs"], *app["units"], *(_image_repo(i) for i in app["images"])):
            out |= package_tokens(name)
    return out


_CATALOG_TOKENS = _catalog_tokens()


def running_software(devices, containers=None, now=None):
    """{word: {'hosts': how many hosts run it, 'world': a socket of it listens to the Internet}} for what the hosts run: the process names each agent reports
    (`sysinfo.proc_names`), the programs that listen (`sysinfo.listening_ports`, whose scope says how far a socket reaches) and the containers that are up. A host
    that has not reported for RUNNING_STALE_S seconds (when `now` is given), a host without an agent and a decommissioned host are not counted. Never raises.
    """
    hosts, world = {}, set()
    for dev_id, dev in devices.items() if isinstance(devices, dict) else ():
        if not isinstance(dev, dict) or dev.get("decommissioned") or dev.get("agentless"):
            continue
        seen_at = dev.get("last_seen")
        if (
            now is not None
            and isinstance(seen_at, (int, float))
            and not isinstance(seen_at, bool)
            and now - seen_at > RUNNING_STALE_S
        ):
            continue
        si = dev.get("sysinfo") if isinstance(dev.get("sysinfo"), dict) else {}
        mine = set()
        names = si.get("proc_names")
        for n in names[:400] if isinstance(names, list) else ():
            mine |= package_tokens(n)
        ports = si.get("listening_ports")
        for port in ports[:80] if isinstance(ports, list) else ():
            if isinstance(port, dict):
                toks = package_tokens(port.get("process"))
                mine |= toks
                if port.get("scope") == "world":
                    world |= toks
        rec = containers.get(dev_id) if isinstance(containers, dict) else None
        items = rec.get("items") if isinstance(rec, dict) else None
        for c in items[:200] if isinstance(items, list) else ():
            if isinstance(c, dict) and not str(c.get("status") or "").strip().lower().startswith(
                _CONTAINER_DOWN
            ):
                mine |= package_tokens(_image_repo(c.get("image")))
        for t in mine:
            hosts.setdefault(t, set()).add(dev_id)
    return {t: {"hosts": len(h), "world": t in world} for t, h in hosts.items()}


def fleet_software(packages_store, devices=None, containers=None, now=None, extra=()):
    """What the hosts have, in the words a news item uses: {'installed': words, 'running': {word: {'hosts', 'world'}}}.

    A package counts as installed software when its word is in KNOWN_SOFTWARE, in the catalog of App discovery or in `extra` (the names an operator added). Something that
    runs counts when its word is one of those or the word of an installed package: that keeps the names of kernel threads (`migration`, `watchdog`) out, and lets software
    that is not in the list count as soon as it runs."""
    pkg = vocabulary(packages_store)
    trusted = (
        KNOWN_SOFTWARE
        | _CATALOG_TOKENS
        | set(extra if isinstance(extra, (list, tuple, set, frozenset)) else ())
    )
    running = {
        t: info
        for t, info in running_software(devices, containers, now).items()
        if t in trusted or t in pkg
    }
    return {"installed": {t for t in pkg if t in trusted}, "running": running}


_APACHE_SERVER = re.compile(r"\bapache\s+(?:http|httpd|web|server|2)|\bapache2\b|\bhttpd\b", re.I)
_NODE_JS = re.compile(r"\bnode\.?js\b", re.I)
_OTHER_KERNEL = re.compile(
    r"\b(?:windows|macos|ios|ipados|android|freebsd|openbsd|xnu|nt)\s+kernel\b", re.I
)


def _refine(text, names):
    """Takes out a word that the text uses for something else: another Apache project (Roller, Tomcat, Kafka), a node of a network, the kernel of Windows."""
    out = []
    for n in names:
        if n == "apache" and not _APACHE_SERVER.search(text):
            continue
        if n == "node" and not _NODE_JS.search(text):
            continue
        if n == "kernel" and "linux" not in names and _OTHER_KERNEL.search(text):
            continue
        out.append(n)
    return out


def mentions(text, fleet):
    """(the software `text` names that the hosts have, and the part of it that runs on some host), both sorted. `fleet` is what fleet_software returns."""
    if not text or not isinstance(fleet, dict):
        return [], []
    names = _refine(
        text, software_in(text, set(fleet.get("installed") or ()) | set(fleet.get("running") or ()))
    )
    return names, [n for n in names if n in (fleet.get("running") or {})]


# ── what has been seen ───────────────────────────────────────────────────────


def process(prev, items, now, kev=()):
    """(the feed's record after this read, the items that are new). `prev` is the record from the last read, or {} for a feed never read.

    The first read of a feed records everything it holds as seen and marks nothing fresh, so switching the watch on does not raise an alert for each
    of the last fifty headlines. After that an item is fresh when it is new and no older than MAX_AGE_S. Each new item carries its classification;
    `text` is the headline and summary together, for the relevance check, and is not meant to be stored.
    """
    prev = prev if isinstance(prev, dict) else {}
    held = prev.get("seen") if isinstance(prev.get("seen"), dict) else {}
    seen = {
        k: v
        for k, v in held.items()
        if isinstance(k, str) and isinstance(v, int) and not isinstance(v, bool)
    }
    baselined = prev.get("baselined") is True
    new = []
    for it in items:
        if it["id"] in seen:
            continue
        seen[it["id"]] = now
        c = classify(it["title"], it["summary"], kev)
        age_ok = it["published"] is None or now - it["published"] <= MAX_AGE_S
        new.append(
            {
                "id": it["id"],
                "title": it["title"],
                "link": it["link"],
                "published": it["published"],
                "critical": c["critical"],
                "reasons": c["reasons"],
                "cves": c["cves"],
                "cvss": c["cvss"],
                "fresh": baselined and age_ok,
                "text": f"{it['title']}. {it['summary']}",
            }
        )
    if len(seen) > MAX_SEEN:
        for k in sorted(seen, key=lambda k: seen[k])[: len(seen) - MAX_SEEN]:
            seen.pop(k)
    rec = dict(prev)
    rec["seen"] = seen
    rec["baselined"] = True
    return rec, new

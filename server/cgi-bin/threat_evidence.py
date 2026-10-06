"""Threat evidence — the closed vocabulary between a host's logs and a report.

The threat sensor in the Linux agent reads web server, WAF, fail2ban and
CrowdSec logs on the host and sends, per source address, a small summary of
what it saw: counts and TOKENS. A token is one of a handful of fixed shapes
(`req:sqli`, `crs:942100`, `jail:sshd`, `cs:crowdsecurity/ssh-bf`, ...). Log
lines, request paths, host names and user names never leave the host.

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
    account, so its text is built ONLY from this module's fixed phrases and from
    numbers: nothing an attacker typed can reach it.

Evidence shape (all keys optional on input, always present on output):

    {'ip': '203.0.113.9', 'first': 1790000000, 'last': 1790000600,
     'src': {'web': 40, 'waf': 12},          # events per source family
     'tok': {'web': {'req:sqli': 14}, 'waf': {'crs:942100': 9}},
     'ans': 3,                                # hostile requests answered 2xx
     'blk': 31,                               # hostile requests refused
     'ban': ['sshd'],                         # fail2ban jails that banned it
     'dec': 1,                                # CrowdSec decisions from local scenarios
     'cve': ['CVE-2021-44228']}

Source families are `web` (access logs), `err` (web server error logs),
`waf` (ModSecurity), `f2b` (fail2ban) and `cs` (CrowdSec). The same hostile
request shows up in several of them, so the number used in a report is the
LARGEST family count, never the sum.
"""

import ipaddress
import re
import time

SOURCES = ('web', 'err', 'waf', 'f2b', 'cs')

# Words for "seen by ...". The access log and the error log are both "the web
# server log" to a reader, so the two share a phrase and it is said once.
SOURCE_PHRASE = {
    'web': 'web server log',
    'err': 'web server log',
    'waf': 'WAF',
    'f2b': 'fail2ban',
    'cs': 'CrowdSec',
}

# Attack classes. `abuseipdb` and `sniffcat` are the category ids each service
# defines (checked against their documentation); `weight` orders classes by how
# much they should speak for the address when several apply.
#   AbuseIPDB: 5 FTP brute-force, 14 port scan, 15 hacking, 16 SQL injection,
#              18 brute-force, 19 bad web bot, 21 web app attack, 22 SSH
#   SniffCat:  4 port scan, 5 mass scanner, 11 hacking, 12 SQL injection,
#              13 command injection, 15 bad web bot, 16 path traversal,
#              17 brute-force, 18 SSH/SFTP, 19 FTP, 20 email, 21 HTTP/HTTPS
CLASSES = {
    'ssh_brute': {'phrase': 'SSH brute force',
                  'abuseipdb': (18, 22), 'sniffcat': (17, 18), 'weight': 2},
    'login_brute': {'phrase': 'login brute force',
                    'abuseipdb': (18, 21), 'sniffcat': (17, 21), 'weight': 2},
    'sqli': {'phrase': 'SQL injection',
             'abuseipdb': (16, 21), 'sniffcat': (12, 21), 'weight': 5},
    'xss': {'phrase': 'cross-site scripting',
            'abuseipdb': (21,), 'sniffcat': (21,), 'weight': 3},
    'traversal': {'phrase': 'path traversal',
                  'abuseipdb': (21,), 'sniffcat': (16, 21), 'weight': 4},
    'rce': {'phrase': 'remote code execution attempts',
            'abuseipdb': (15, 21), 'sniffcat': (13, 21), 'weight': 6},
    'probe': {'phrase': 'probing for exposed files and admin pages',
              'abuseipdb': (21,), 'sniffcat': (21,), 'weight': 2},
    'scanner': {'phrase': 'vulnerability scanning',
                'abuseipdb': (19, 21), 'sniffcat': (5, 21), 'weight': 3},
    'flood': {'phrase': 'request flooding',
              'abuseipdb': (19,), 'sniffcat': (15,), 'weight': 1},
    'bad_bot': {'phrase': 'unwanted web crawling',
                'abuseipdb': (19,), 'sniffcat': (15,), 'weight': 1},
    'waf': {'phrase': 'requests blocked by a web application firewall',
            'abuseipdb': (21,), 'sniffcat': (21,), 'weight': 3},
    'mail_brute': {'phrase': 'mail login brute force',
                   'abuseipdb': (18,), 'sniffcat': (17, 20), 'weight': 2},
    'ftp_brute': {'phrase': 'FTP brute force',
                  'abuseipdb': (5, 18), 'sniffcat': (17, 19), 'weight': 2},
    'service_brute': {'phrase': 'service login brute force',
                      'abuseipdb': (18,), 'sniffcat': (17,), 'weight': 2},
    'port_scan': {'phrase': 'port scanning',
                  'abuseipdb': (14,), 'sniffcat': (4,), 'weight': 2},
}

# `{what}` in a report message, kept compatible with the older placeholder
# ('SSH', 'web login', 'login').
_WHAT = {
    'ssh_brute': 'SSH', 'login_brute': 'web login', 'mail_brute': 'mail login',
    'ftp_brute': 'FTP login', 'service_brute': 'login', 'port_scan': 'port',
}
_WEB_CLASSES = ('sqli', 'xss', 'traversal', 'rce', 'probe', 'scanner', 'flood',
                'bad_bot', 'waf')

WAF_MIN_BLOCKS = 3        # blocked requests that count as evidence on their own
_MAX_COUNT = 1_000_000
_MAX_TOKENS = 24          # per source family
_MAX_JAILS = 8
_MAX_CVES = 5
_MAX_AGE_S = 7 * 86400
_SKEW_S = 300

# ── tokens ─────────────────────────────────────────────────────────────────────

_REQ_KINDS = {'sqli': 'sqli', 'xss': 'xss', 'traversal': 'traversal',
              'rce': 'rce', 'probe': 'probe', 'scanner': 'scanner',
              'login': 'login_brute', 'flood': 'flood'}

# Matched with fullmatch(), never match() with a `$`: `$` also matches before a
# trailing newline, so `req:sqli\n` would pass a `^req:sqli$` check.
_TOKEN_RE = {
    'req': re.compile(r'req:(sqli|xss|traversal|rce|probe|scanner|login|flood)'),
    'crs': re.compile(r'crs:(\d{3,9})'),
    'crstag': re.compile(r'crstag:(attack-[a-z0-9-]{1,40})'),
    'jail': re.compile(r'jail:([A-Za-z0-9][A-Za-z0-9_.-]{0,39})'),
    'cs': re.compile(r'cs:([A-Za-z0-9][A-Za-z0-9_./-]{0,95})'),
}
_JAIL_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,39}')
_CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}')


def token_valid(token):
    """True for a token in the vocabulary. Anything else is dropped on ingest."""
    if not isinstance(token, str) or len(token) > 110:
        return False
    kind = token.split(':', 1)[0]
    rx = _TOKEN_RE.get(kind)
    return bool(rx and rx.fullmatch(token))


# ── token -> class ─────────────────────────────────────────────────────────────

# Ordered: the first rule that matches a name wins, so the specific ones come
# before the broad ones. Names are matched lowercase.
#
# Short tokens are matched as whole words (_W below). Without that, "rdp" is
# found inside "wordpress" and "rce" inside "force", and a WordPress jail is
# reported as an RDP brute-forcer.
_B = r'(?<![a-z0-9])'
_E = r'(?![a-z0-9])'


def _w(*words):
    """A pattern that matches any of `words` only as a whole word."""
    return _B + '(?:' + '|'.join(words) + ')' + _E


_JAIL_RULES = tuple((cls, re.compile(rx)) for cls, rx in (
    ('ssh_brute', r'ssh'),
    ('waf', r'modsec|waf|appsec|mod-security'),
    ('sqli', r'sqli|sql-?inj'),
    ('traversal', _w('lfi', 'rfi') + r'|travers|url-?fopen'),
    ('xss', _w('xss')),
    ('rce', _w('rce') + r'|php-?inj|injection|exploit|shellshock|log4|webshell|cve'),
    ('mail_brute', r'postfix|dovecot|exim|sendmail|smtp|imap|pop3|sasl|courier|qmail|cyrus|sieve'),
    ('ftp_brute', r'ftp'),
    ('flood', _w('dos') + r'|limit-?req|req-?limit|rate-?limit|flood|limit-?conn'),
    ('bad_bot', r'bad-?bots?|unwanted|crawler|scrap|fake-?google|fake-?bot'),
    ('port_scan', r'port-?scan|iptables-?scan'),
    ('service_brute', _w('rdp', 'smb') + r'|mysql|maria|postgres|pgsql|mongo|redis|asterisk|openvpn|telnet'),
    ('login_brute', _w('wp') + r'|auth(?!or)|wordpress|xmlrpc|login'),
    ('probe', r'noscript|nohome|noproxy|botsearch|sensitive|blocked|probe|scan|forbidden|overflow|404|4xx|dotfile'),
))

_CS_RULES = tuple((cls, re.compile(rx)) for cls, rx in (
    ('ssh_brute', r'ssh'),
    ('rce', _w('rce') + r'|vpatch|cve|log4j|log4shell|spring4shell|shellshock|backdoor|webshell|exploit'),
    ('waf', r'appsec|modsec'),
    ('sqli', r'sqli'),
    ('xss', _w('xss')),
    ('traversal', _w('lfi', 'rfi') + r'|traversal'),
    ('flood', _w('dos') + r'|req-limit|rate-limit|flood'),
    ('scanner', r'bad-user-agent|scanner|nikto|nmap|masscan'),
    ('login_brute', r'wordpress_bf|bf-wordpress|http-bf|generic-bf|401-bf|403-bf|auth-bf|login'),
    ('mail_brute', r'postfix|dovecot|exim|sendmail|smtp|imap|pop3|spam'),
    ('ftp_brute', r'ftp'),
    ('port_scan', r'portscan|port-scan|iptables-scan|refused-conn|scan-multi'),
    ('probe', r'probing|sensitive-files|admin-interface|wordpress-scan|user-enum|xmlrpc|open-proxy|http-.*scan'),
    ('service_brute', _w('rdp', 'smb') + r'|(^|-)bf($|-)|brute|mysql|pgsql|mariadb|mongo|redis|telnet|asterisk|openvpn'),
))

_CRS_TAGS = {
    'attack-sqli': 'sqli', 'attack-xss': 'xss',
    'attack-lfi': 'traversal', 'attack-rfi': 'traversal',
    'attack-rce': 'rce', 'attack-injection-php': 'rce',
    'attack-injection-generic': 'rce', 'attack-injection-java': 'rce',
    'attack-reputation-scanner': 'scanner', 'attack-dos': 'flood',
    'attack-protocol': 'waf', 'attack-generic': 'waf', 'attack-fixation': 'waf',
    'attack-multipart-bypass': 'waf', 'attack-ssrf': 'waf',
}


def jail_class(name):
    n = str(name or '').lower()
    for cls, rx in _JAIL_RULES:
        if rx.search(n):
            return cls
    return None


def scenario_class(name):
    n = str(name or '').lower()
    if n.startswith('crowdsecurity/'):
        n = n[len('crowdsecurity/'):]
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
        return 'scanner'
    if 930000 <= n < 932000:
        return 'traversal'
    if 932000 <= n < 935000 or 944000 <= n < 945000:
        return 'rce'
    if 941000 <= n < 942000:
        return 'xss'
    if 942000 <= n < 943000:
        return 'sqli'
    if 900000 <= n < 913000 or 949000 <= n < 960000 or 980000 <= n < 981000:
        return None
    return 'waf'


def token_class(token):
    """The attack class a valid token stands for, or None."""
    if not token_valid(token):
        return None
    kind, _, val = token.partition(':')
    if kind == 'req':
        return _REQ_KINDS.get(val)
    if kind == 'crs':
        return crs_class(val)
    if kind == 'crstag':
        return _CRS_TAGS.get(val)
    if kind == 'jail':
        return jail_class(val)
    if kind == 'cs':
        return scenario_class(val)
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
        a = ipaddress.ip_address(str(value or '').strip())
    except ValueError:
        return None
    if getattr(a, 'ipv4_mapped', None):
        a = a.ipv4_mapped
    if not a.is_global or a.is_multicast:
        return None
    return str(a)


def blank(ip=''):
    return {'ip': ip, 'first': 0, 'last': 0, 'src': {}, 'tok': {}, 'ans': 0,
            'blk': 0, 'ban': [], 'dec': 0, 'cve': []}


def normalize_event(raw, now=None):
    """One address's summary from an agent, reduced to the vocabulary, or None
    when there is nothing usable (not an address, or no evidence at all)."""
    if not isinstance(raw, dict):
        return None
    ip = public_ip(raw.get('ip'))
    if not ip:
        return None
    now = int(now or time.time())
    ev = blank(ip)
    first, last = _ts(raw.get('first'), now), _ts(raw.get('last'), now)
    ev['first'], ev['last'] = (first, last) if first <= last else (last, first)
    src = raw.get('src') if isinstance(raw.get('src'), dict) else {}
    for fam in SOURCES:
        n = _count(src.get(fam))
        if n:
            ev['src'][fam] = n
    tok = raw.get('tok') if isinstance(raw.get('tok'), dict) else {}
    for fam in SOURCES:
        d = tok.get(fam)
        if not isinstance(d, dict):
            continue
        out = {}
        for t, c in d.items():
            n = _count(c)
            if n and token_valid(t):
                out[t] = n
        if out:
            ev['tok'][fam] = dict(sorted(out.items(), key=lambda kv: -kv[1])[:_MAX_TOKENS])
    ev['ans'], ev['blk'] = _count(raw.get('ans')), _count(raw.get('blk'))
    ev['dec'] = _count(raw.get('dec'))
    jails = raw.get('ban') if isinstance(raw.get('ban'), list) else []
    ev['ban'] = _uniq(j for j in jails if isinstance(j, str) and _JAIL_RE.fullmatch(j))[:_MAX_JAILS]
    cves = raw.get('cve') if isinstance(raw.get('cve'), list) else []
    ev['cve'] = _uniq(c for c in cves if isinstance(c, str) and _CVE_RE.fullmatch(c))[:_MAX_CVES]
    if not (ev['src'] or ev['tok'] or ev['ban'] or ev['dec']):
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
    out = blank((a or {}).get('ip') or (b or {}).get('ip') or '')
    a, b = a or blank(), b or blank()
    firsts = [x for x in (a.get('first'), b.get('first')) if x]
    out['first'] = min(firsts) if firsts else 0
    out['last'] = max(a.get('last') or 0, b.get('last') or 0)
    for fam in SOURCES:
        n = _count((a.get('src') or {}).get(fam)) + _count((b.get('src') or {}).get(fam))
        if n:
            out['src'][fam] = min(_MAX_COUNT, n)
        merged = {}
        for d in ((a.get('tok') or {}).get(fam) or {}, (b.get('tok') or {}).get(fam) or {}):
            for t, c in d.items():
                merged[t] = min(_MAX_COUNT, merged.get(t, 0) + _count(c))
        if merged:
            out['tok'][fam] = dict(sorted(merged.items(), key=lambda kv: -kv[1])[:_MAX_TOKENS])
    out['ans'] = min(_MAX_COUNT, _count(a.get('ans')) + _count(b.get('ans')))
    out['blk'] = min(_MAX_COUNT, _count(a.get('blk')) + _count(b.get('blk')))
    out['dec'] = min(_MAX_COUNT, _count(a.get('dec')) + _count(b.get('dec')))
    out['ban'] = _uniq(list(a.get('ban') or []) + list(b.get('ban') or []))[:_MAX_JAILS]
    out['cve'] = _uniq(list(a.get('cve') or []) + list(b.get('cve') or []))[:_MAX_CVES]
    return out


# ── reading evidence ───────────────────────────────────────────────────────────

def classes(ev):
    """{class: count}. A class takes the LARGEST count of any token that
    names it: the same request is seen by the access log, the WAF and the
    jail, so adding them would count it three times."""
    out = {}
    for toks in (ev.get('tok') or {}).values():
        for t, c in toks.items():
            cls = token_class(t)
            if cls:
                out[cls] = max(out.get(cls, 0), _count(c))
    for jail in ev.get('ban') or []:
        cls = jail_class(jail)
        if cls:
            out[cls] = max(out.get(cls, 0), 1)
    waf = _count((ev.get('src') or {}).get('waf'))
    if waf:
        out['waf'] = max(out.get('waf', 0), waf)
    return out


def hostile_count(ev):
    """How many hostile events: the largest source family, else the largest
    class. Never a sum."""
    src = [n for n in (ev.get('src') or {}).values() if n]
    if src:
        return max(src)
    cls = classes(ev)
    return max(cls.values()) if cls else 0


def dominant(ev, limit=3):
    """[(class, count)] most telling first. The generic WAF class steps aside
    when a specific one explains the blocks."""
    cls = classes(ev)
    if len(cls) > 1:
        cls.pop('waf', None)
    ranked = sorted(cls.items(),
                    key=lambda kv: (-(CLASSES[kv[0]]['weight'] * max(kv[1], 1)), kv[0]))
    return ranked[:limit]


def confirmed_by(ev):
    """Who already decided this address is hostile: 'fail2ban', 'CrowdSec' or ''."""
    if ev.get('ban'):
        return 'fail2ban'
    if _count(ev.get('dec')):
        return 'CrowdSec'
    return ''


def qualifies(ev, min_count):
    """(True, why) when the evidence is enough to report, else (False, why not).
    Enough means ANY of: fail2ban banned it, a CrowdSec scenario decided on it,
    the WAF refused it WAF_MIN_BLOCKS times, or it made `min_count` hostile
    requests. An address with no class is never reportable: a report needs an
    honest category."""
    if not classes(ev):
        return False, 'nothing recognisable in the logs'
    who = confirmed_by(ev)
    if who:
        return True, f'confirmed by {who}'
    waf = _count((ev.get('src') or {}).get('waf'))
    if waf >= WAF_MIN_BLOCKS:
        return True, f'blocked by the WAF {waf} times'
    n, need = hostile_count(ev), max(1, int(min_count or 1))
    if n >= need:
        return True, f'{n} hostile requests'
    return False, f'{n} of {need} attempts so far'


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
        return ''.join(parts)
    return ', '.join(parts[:-1]) + ' and ' + parts[-1]


def attack_phrase(ev):
    """'SQL injection and path traversal' — fixed phrases only. A CVE id the
    logs named is a public identifier, so up to two ride along."""
    parts = [CLASSES[c]['phrase'] for c, _n in dominant(ev, 3)]
    text = _join(parts)
    cves = list(ev.get('cve') or [])[:2]
    if text and cves:
        text += ' (' + ', '.join(cves) + ')'
    return text


def seen_by(ev):
    """'web server log, WAF and fail2ban' — the sources that saw the address."""
    fams = []
    src, tok = ev.get('src') or {}, ev.get('tok') or {}
    for fam in SOURCES:
        saw = src.get(fam) or tok.get(fam)
        if fam == 'f2b':
            saw = saw or ev.get('ban')
        if fam == 'cs':
            saw = saw or ev.get('dec')
        if saw:
            fams.append(fam)
    return _join(_uniq(SOURCE_PHRASE[f] for f in fams))


def what_word(ev):
    """The short noun `{what}` stands for: 'SSH', 'web login', 'web', ..."""
    top = dominant(ev, 1)
    if not top:
        return 'login'
    cls = top[0][0]
    if cls in _WHAT:
        return _WHAT[cls]
    return 'web' if cls in _WEB_CLASSES else 'login'


def window_seconds(ev):
    span = int(ev.get('last') or 0) - int(ev.get('first') or 0)
    return max(60, min(86400, span))


def web_only(ev):
    """True when every class the address was seen in is a web one."""
    cls = classes(ev)
    return bool(cls) and all(c in _WEB_CLASSES or c == 'login_brute' for c in cls)


# ── addresses nobody should report or block ────────────────────────────────────

# Cloudflare's published edge ranges (cloudflare.com/ips-v4 and /ips-v6, checked
# 2026-10-06). A web server that does not restore the visitor's address logs
# these instead, and a report naming one would blame the proxy. The list is a
# floor, not a promise: the operator's never-block list covers anything else.
CLOUDFLARE_RANGES = (
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
    '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
)
_CLOUDFLARE_NETS = tuple(ipaddress.ip_network(c) for c in CLOUDFLARE_RANGES)


def infra_reason(ip):
    """A sentence saying why this is infrastructure rather than an attacker,
    or ''."""
    try:
        a = ipaddress.ip_address(str(ip or '').strip())
    except ValueError:
        return ''
    if getattr(a, 'ipv4_mapped', None):
        a = a.ipv4_mapped
    for n in _CLOUDFLARE_NETS:
        if a.version == n.version and a in n:
            return 'a Cloudflare edge address'
    return ''

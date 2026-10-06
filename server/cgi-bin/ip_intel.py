"""IP threat intelligence — AbuseIPDB and SniffCat, pure helpers.

When the brute-force detector sees a source address cross its threshold, the
sweep in ip_intel_handlers.py can:

  * LOOK UP the address with AbuseIPDB and SniffCat and keep the answer
    (confidence score, report count, country, network owner);
  * REPORT it back to either service (opt-in, off by default); and
  * BLOCK it on the host that was attacked (opt-in, off by default), for a
    limited time, through the normal guarded command queue.

This module holds everything worth testing without a network: request
building and response parsing for both services, the category mapping, the
report comment, the merged verdict, the never-block rules and the firewall
commands. It is stdlib-only and never opens a socket; the caller passes an
HTTP function in.

API facts this module relies on (checked against each service's docs):

  AbuseIPDB v2   https://api.abuseipdb.com/api/v2
    GET  /check?ipAddress=&maxAgeInDays=     header `Key`
         -> {"data": {"abuseConfidenceScore", "totalReports", "countryCode",
                      "isp", "usageType", "domain", "isWhitelisted", ...}}
    POST /report  form: ip, categories="18,22", comment (<= 1024 chars),
                       timestamp (optional, ISO 8601: when the attack happened)
         The same address may be reported once per 15 minutes; a repeat is
         refused with HTTP 429 and "You can only report the same IP address
         once in 15 minutes."

  SniffCat v1    https://api.sniffcat.com/api/v1
    GET  /check?ip=                          header `X-Secret-Token`
         -> {"success", "status", "abuseConfidenceScore"}
    POST /report  JSON: {ip, categories: [..], comment (>= 10 chars)}
         The same address may be reported once per 20 minutes. A repeat and a
         rate limit share one answer, HTTP 429, so the two cannot be told apart.
         There is no timestamp field.
"""

import ipaddress
import json
import re
import time
import urllib.parse

import threat_evidence

PROVIDERS = ('abuseipdb', 'sniffcat')

ABUSEIPDB_BASE = 'https://api.abuseipdb.com/api/v2'
SNIFFCAT_BASE = 'https://api.sniffcat.com/api/v1'

# What kind of attack the detector saw → each service's category ids.
#   AbuseIPDB: 14 port scan, 15 hacking, 18 brute-force, 21 web app attack, 22 SSH
#   SniffCat:   4 port scan, 11 hacking, 17 brute-force, 18 SSH/SFTP, 21 HTTP/HTTPS
CATEGORIES = {
    'ssh': {'abuseipdb': [18, 22], 'sniffcat': [17, 18]},
    'web': {'abuseipdb': [18, 21], 'sniffcat': [17, 21]},
    'other': {'abuseipdb': [18], 'sniffcat': [17]},
}

# Defaults for the operator-tunable policy (config `ip_intel`).
DEFAULTS = {
    'lookup_enabled': False,
    'report_enabled': False,
    'block_enabled': False,
    'block_min_score': 90,        # merged confidence needed to block
    'block_ttl_hours': 24,        # blocks lift themselves after this
    'block_max_per_hour': 20,     # per host; a cap on a runaway
    'report_min_count': 10,       # failed attempts seen before reporting
    'cache_hours': 24,            # how long a lookup answer is reused
    'daily_lookup_budget': 900,   # per provider; AbuseIPDB's free tier is 1000
    'daily_report_budget': 900,   # per provider; reports have their own daily limit
    'report_comment': '',         # '' = the default text below
    'never_block': [],            # extra CIDRs that are never blocked
}

_MAX_COMMENT = 1000
_MIN_COMMENT = 10             # SniffCat refuses anything shorter
_TEMPLATE_MAX = 300

# What a report says unless the operator writes their own. The placeholders are
# counts and the kind of attack, never a host name or a user name, because the
# text is public on both services:
#   {what}     'SSH', 'web login', 'web' ...        (short noun)
#   {count}    attempts seen
#   {minutes}  the time window
#   {attack}   'SQL injection and path traversal'   (fixed phrases only)
#   {seen_by}  'web server log and WAF'             (fixed phrases only)
# REPORT_COMMENT_DEFAULT is for an address seen only by the brute-force counter;
# REPORT_COMMENT_EVIDENCE_DEFAULT for one the host's logs could describe.
REPORT_COMMENT_DEFAULT = ('{what} brute force: {count} failed attempts within '
                          '{minutes} minutes (reported by RemotePower)')
REPORT_COMMENT_EVIDENCE_DEFAULT = ('{attack}: {count} attempts within {minutes} minutes, '
                                   'seen by {seen_by} (reported by RemotePower)')
COMMENT_PLACEHOLDERS = ('what', 'count', 'minutes', 'attack', 'seen_by')
_LEGACY_ATTACK = {'ssh': 'SSH brute force', 'web': 'web login brute force'}
_LEGACY_SEEN_BY = {'ssh': 'system log', 'web': 'web server log'}
_PLACEHOLDER_RE = re.compile(r'\{(\w+)\}')
_CTRL_RE = re.compile(r'[\x00-\x1f\x7f]+')
_BLOCK_MARKER = 'rp-ipintel'


# ── addresses ──────────────────────────────────────────────────────────────────

def parse_ip(value):
    """Normalised address string, or None. Hostnames are not looked up."""
    try:
        return str(ipaddress.ip_address(str(value or '').strip()))
    except ValueError:
        return None


def is_public(ip):
    """True only for a globally routable unicast address. Private, loopback,
    link-local, multicast, reserved and documentation ranges are never looked
    up, reported or blocked: they are someone's own network."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if getattr(a, 'ipv4_mapped', None):
        a = a.ipv4_mapped
    return bool(a.is_global) and not a.is_multicast


def parse_cidrs(values):
    out = []
    for v in values or []:
        try:
            out.append(ipaddress.ip_network(str(v).strip(), strict=False))
        except ValueError:
            continue
    return out


def in_any(ip, networks):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a.version == n.version and a in n for n in networks)


# ── AbuseIPDB ──────────────────────────────────────────────────────────────────

def abuseipdb_check_request(ip, key, max_age_days=90):
    q = urllib.parse.urlencode({'ipAddress': ip, 'maxAgeInDays': int(max_age_days)})
    return {'method': 'GET', 'url': f'{ABUSEIPDB_BASE}/check?{q}',
            'headers': {'Key': key, 'Accept': 'application/json'}, 'body': None}


def abuseipdb_parse_check(status, body):
    if status != 200:
        return _error(status, body)
    data = (body or {}).get('data') if isinstance(body, dict) else None
    if not isinstance(data, dict):
        return {'ok': False, 'error': 'unexpected response'}
    return {
        'ok': True,
        'score': _clamp_score(data.get('abuseConfidenceScore')),
        'reports': _int(data.get('totalReports')),
        'country': _short(data.get('countryCode'), 2),
        'isp': _short(data.get('isp'), 120),
        'usage': _short(data.get('usageType'), 80),
        'domain': _short(data.get('domain'), 120),
        'whitelisted': bool(data.get('isWhitelisted')),
        'last_reported': _short(data.get('lastReportedAt'), 40),
    }


def iso_utc(epoch, now=None):
    """`2026-10-05T12:00:00+00:00` for a moment in the last day, else None. A
    time in the future or older than a day is left out so the service stamps the
    report itself rather than refusing it."""
    try:
        t = int(epoch)
    except (TypeError, ValueError, OverflowError):
        return None
    now = int(now or time.time())
    if t > now or now - t > 86400:
        return None
    return time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(t))


def abuseipdb_report_request(ip, key, categories, comment, timestamp=None):
    """`timestamp` (epoch seconds) says when the attack happened. It is sent
    only when given and recent; the service stamps the report with its own time
    otherwise."""
    fields = {'ip': ip, 'categories': ','.join(str(int(c)) for c in categories),
              'comment': comment[:_MAX_COMMENT]}
    when = iso_utc(timestamp)
    if when:
        fields['timestamp'] = when
    return {'method': 'POST', 'url': f'{ABUSEIPDB_BASE}/report',
            'headers': {'Key': key, 'Accept': 'application/json',
                        'Content-Type': 'application/x-www-form-urlencoded'},
            'body': urllib.parse.urlencode(fields).encode()}


# AbuseIPDB's refusal of a repeat: 429, "You can only report the same IP address
# (`x`) once in 15 minutes." Its daily limit is also a 429, with a different
# sentence, so the text is what tells them apart.
_DUPLICATE_RE = re.compile(r'once (?:in|every) \d+ minutes', re.I)


def _detail(body):
    """The provider's own sentence for an error, or ''."""
    if not isinstance(body, dict):
        return ''
    errs = body.get('errors')
    msg = ''
    if isinstance(errs, list) and errs and isinstance(errs[0], dict):
        msg = str(errs[0].get('detail') or '')
    return msg or str(body.get('message') or body.get('error') or '')


def abuseipdb_parse_report(status, body):
    if status == 200:
        return {'ok': True}
    if status == 429 and _DUPLICATE_RE.search(_detail(body)):
        # Someone reported it moments ago, often fail2ban on the same host
        # under the same key. The report exists; this is not a failure.
        return {'ok': False, 'duplicate': True, 'rate_limited': True,
                'error': 'already reported a moment ago'}
    return _error(status, body)


# ── SniffCat ───────────────────────────────────────────────────────────────────

def sniffcat_check_request(ip, key):
    q = urllib.parse.urlencode({'ip': ip})
    return {'method': 'GET', 'url': f'{SNIFFCAT_BASE}/check?{q}',
            'headers': {'X-Secret-Token': key, 'Accept': 'application/json'},
            'body': None}


def sniffcat_parse_check(status, body):
    if status != 200 or not isinstance(body, dict) or body.get('success') is False:
        return _error(status, body)
    if 'abuseConfidenceScore' not in body:
        return {'ok': False, 'error': 'unexpected response'}
    return {'ok': True, 'score': _clamp_score(body.get('abuseConfidenceScore')),
            'reports': _int(body.get('count'))}


def sniffcat_report_request(ip, key, categories, comment, timestamp=None):
    """`timestamp` is accepted so both services are called alike and is not
    sent: SniffCat's report has no such field."""
    payload = {'ip': ip, 'categories': [int(c) for c in categories],
               'comment': comment[:_MAX_COMMENT]}
    return {'method': 'POST', 'url': f'{SNIFFCAT_BASE}/report',
            'headers': {'X-Secret-Token': key, 'Accept': 'application/json',
                        'Content-Type': 'application/json'},
            'body': json.dumps(payload).encode()}


def sniffcat_parse_report(status, body):
    if status == 200 and not (isinstance(body, dict) and body.get('success') is False):
        return {'ok': True}
    if status == 429:
        # "Submission rate limit exceeded or repeated report for the same IP":
        # one answer for both, so the message says both.
        return {'ok': False, 'rate_limited': True,
                'error': 'rate limited or already reported'}
    return _error(status, body)


# How long to leave an address alone after a service answered 429 to its
# report: a little over the service's repeat window.
REPORT_RETRY_S = {'abuseipdb': 16 * 60, 'sniffcat': 21 * 60}


CHECK = {
    'abuseipdb': (abuseipdb_check_request, abuseipdb_parse_check),
    'sniffcat': (sniffcat_check_request, sniffcat_parse_check),
}
REPORT = {
    'abuseipdb': (abuseipdb_report_request, abuseipdb_parse_report),
    'sniffcat': (sniffcat_report_request, sniffcat_parse_report),
}


def _error(status, body):
    msg = _detail(body)
    if status == 429:
        return {'ok': False, 'error': 'rate limited', 'rate_limited': True}
    if status == 401:
        return {'ok': False, 'error': 'API key rejected', 'auth': True}
    if status == 403:
        # A 403 can be the provider refusing the key or its firewall refusing
        # the request, and nothing here can tell which, so it names neither.
        return {'ok': False, 'error': 'refused by the provider (HTTP 403)'}
    return {'ok': False, 'error': _short(msg or f'HTTP {status}', 160)}


def _int(v):
    try:
        return max(0, int(v))
    except (TypeError, ValueError):
        return 0


def _clamp_score(v):
    return max(0, min(100, _int(v)))


def _short(v, n):
    if v is None:
        return ''
    return ''.join(ch for ch in str(v) if ch.isprintable())[:n]


# ── verdicts, reports, comments ────────────────────────────────────────────────

def merge(results):
    """One verdict from the per-provider answers: the highest score wins, so a
    service that knows the address is never outvoted by one that does not."""
    ok = {p: r for p, r in (results or {}).items() if isinstance(r, dict) and r.get('ok')}
    if not ok:
        return {'score': None, 'reports': 0, 'providers': {}}
    best = max(ok.values(), key=lambda r: r.get('score') or 0)
    out = {'score': max(r.get('score') or 0 for r in ok.values()),
           'reports': sum(r.get('reports') or 0 for r in ok.values()),
           'providers': {p: {'score': r.get('score'), 'reports': r.get('reports')}
                         for p, r in ok.items()}}
    for k in ('country', 'isp', 'usage', 'domain'):
        val = best.get(k) or next((r.get(k) for r in ok.values() if r.get(k)), '')
        if val:
            out[k] = val
    if any(r.get('whitelisted') for r in ok.values()):
        out['whitelisted'] = True
    return out


def attack_kind(unit):
    u = str(unit or '').lower()
    if 'ssh' in u:
        return 'ssh'
    if any(w in u for w in ('nginx', 'apache', 'httpd', 'caddy', 'traefik', 'web', 'http')):
        return 'web'
    return 'other'


def _render_comment(template, what, count, mins, attack='', seen_by=''):
    values = {'what': what, 'count': str(count), 'minutes': str(mins),
              'attack': attack, 'seen_by': seen_by}
    return _PLACEHOLDER_RE.sub(lambda m: values.get(m.group(1), m.group(0)), template)


def clean_comment_template(text):
    """One line, no control characters, trimmed. Applied before the template is
    checked or stored, so what is validated is what is saved."""
    return _CTRL_RE.sub(' ', str(text or '')).strip()


# The shortest text each placeholder can ever become, so a template is only
# accepted when even its shortest rendering clears SniffCat's minimum.
_SHORTEST = {
    'what': 'SSH',
    'attack': min((c['phrase'] for c in threat_evidence.CLASSES.values()), key=len),
    'seen_by': min(threat_evidence.SOURCE_PHRASE.values(), key=len),
}


def comment_template_error(template):
    """None when the template is usable, else a sentence saying what is wrong."""
    t = clean_comment_template(template)
    if len(t) > _TEMPLATE_MAX:
        return f'The report message can be at most {_TEMPLATE_MAX} characters'
    unknown = sorted({n for n in _PLACEHOLDER_RE.findall(t) if n not in COMMENT_PLACEHOLDERS})
    if unknown:
        return ('Unknown placeholder {' + unknown[0] + '}. You can use '
                + ', '.join('{' + n + '}' for n in COMMENT_PLACEHOLDERS))
    if len(_render_comment(t, _SHORTEST['what'], 1, 1, _SHORTEST['attack'],
                           _SHORTEST['seen_by'])) < _MIN_COMMENT:
        return f'The report message must be at least {_MIN_COMMENT} characters (SniffCat refuses shorter ones)'
    return None


def report_comment(kind, count, window_s, template=None):
    """What a report says. Counts and the kind of attack only: no hostnames,
    usernames, paths or log lines, because the comment is public on both
    services and the attacked machine is ours. `template` is the operator's own
    wording; an unusable one falls back to the default rather than failing a
    report."""
    what = {'ssh': 'SSH', 'web': 'web login'}.get(kind, 'login')
    mins = max(1, int(window_s or 0) // 60)
    t = clean_comment_template(template)
    if not t or comment_template_error(t):
        t = REPORT_COMMENT_DEFAULT
    return _render_comment(t, what, int(count), mins,
                           _LEGACY_ATTACK.get(kind, 'login brute force'),
                           _LEGACY_SEEN_BY.get(kind, 'system log'))[:_MAX_COMMENT]


def evidence_comment(ev, template=None):
    """The same for an address the host's logs described. Every word comes from
    threat_evidence's fixed phrases and from numbers, so nothing the attacker
    typed can reach a public report; `template` is the operator's wording."""
    t = clean_comment_template(template)
    if not t or comment_template_error(t):
        t = REPORT_COMMENT_EVIDENCE_DEFAULT
    mins = max(1, threat_evidence.window_seconds(ev) // 60)
    return _render_comment(t, threat_evidence.what_word(ev), threat_evidence.hostile_count(ev),
                           mins, threat_evidence.attack_phrase(ev),
                           threat_evidence.seen_by(ev))[:_MAX_COMMENT]


# ── blocking ───────────────────────────────────────────────────────────────────

def block_decision(policy, verdict, local_count):
    """(True, '') when the policy says to block, else (False, reason)."""
    if not policy.get('block_enabled'):
        return False, 'auto-block is off'
    if not verdict or verdict.get('score') is None:
        return False, 'no reputation answer'
    if verdict.get('whitelisted'):
        return False, 'listed as legitimate by a provider'
    need = int(policy.get('block_min_score', DEFAULTS['block_min_score']))
    if verdict['score'] < need:
        return False, f"score {verdict['score']} is below {need}"
    if int(local_count or 0) < 1:
        return False, 'not seen attacking this host'
    return True, ''


def never_block_reason(ip, protected):
    """Why this address must not be blocked, or ''. `protected` holds the
    networks of the RemotePower server, the fleet, the operator's allow-list
    and the configured never-block list."""
    if not is_public(ip):
        return 'not a public address'
    if threat_evidence.infra_reason(ip):
        # The reason is the constant below, not infra_reason()'s own sentence,
        # so every string this function can return is visible to the test that
        # checks each one has a translation.
        return 'a Cloudflare edge address'
    if in_any(ip, protected):
        return 'on the never-block list'
    return ''


def _rule_family(ip):
    return 'ipv6' if ':' in ip else 'ipv4'


def block_command(ip):
    """Shell command that drops traffic from `ip` with whichever firewall the
    host runs. Only a validated address is interpolated, and every rule carries
    a marker so it can be found and removed again."""
    ip = parse_ip(ip)
    if not ip:
        raise ValueError('invalid address')
    fam = _rule_family(ip)
    ipt = 'ip6tables' if fam == 'ipv6' else 'iptables'
    m = _BLOCK_MARKER
    return (
        'if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then '
        f'ufw insert 1 deny from {ip} comment {m}; '
        'elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then '
        f"firewall-cmd --permanent --add-rich-rule='rule family={fam} source address={ip} drop' "
        '&& firewall-cmd --reload; '
        f'else {ipt} -C INPUT -s {ip} -j DROP -m comment --comment {m} 2>/dev/null '
        f'|| {ipt} -I INPUT -s {ip} -j DROP -m comment --comment {m}; fi')


def unblock_command(ip):
    ip = parse_ip(ip)
    if not ip:
        raise ValueError('invalid address')
    fam = _rule_family(ip)
    ipt = 'ip6tables' if fam == 'ipv6' else 'iptables'
    m = _BLOCK_MARKER
    return (
        'if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then '
        f'ufw --force delete deny from {ip} comment {m} || ufw --force delete deny from {ip}; '
        'elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then '
        f"firewall-cmd --permanent --remove-rich-rule='rule family={fam} source address={ip} drop' "
        '&& firewall-cmd --reload; '
        f'else while {ipt} -D INPUT -s {ip} -j DROP -m comment --comment {m} 2>/dev/null; '
        'do :; done; fi')


_KEY_RE = re.compile(r'^[A-Za-z0-9._~+/=-]{8,256}$')


def valid_api_key(key):
    return isinstance(key, str) and bool(_KEY_RE.match(key))

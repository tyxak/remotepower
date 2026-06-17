"""IP reputation (DNSBL / blocklist) checks for the Reputation/DMARC page.

Pure functions: given an IPv4 address and a set of DNSBL zones, query each zone
for an A record at the reversed-octet name and report which lists the IP. The
resolver is injectable so the logic is unit-testable without real DNS.

DNSBL convention (RFC 5782): to check ``1.2.3.4`` against zone ``z``, query the
A record of ``4.3.2.1.z``. An answer (typically ``127.0.0.x``) means LISTED;
NXDOMAIN means not listed. The matching TXT record carries a human reason.

NOTE: several DNSBLs (Spamhaus especially) refuse queries that arrive via large
public resolvers — for reliable results the server should query its own / a
private recursive resolver, not 8.8.8.8.
"""
import ipaddress
import re

DNS_TIMEOUT = 5.0

# A syntactically valid DNS zone name (labels of [A-Za-z0-9-], dotted, <=253).
# Used to reject a malformed/whitespace zone so the reversed-IP query name can
# never be injected or sent malformed.
_ZONE_RE = re.compile(r'^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$')


def valid_zone(zone):
    """True if `zone` is a syntactically valid DNS zone name."""
    return bool(_ZONE_RE.match(str(zone or '')))

# Default IPv4 blocklist zones. Operators can override the set in config.
DEFAULT_DNSBLS = [
    {'name': 'Spamhaus ZEN',   'zone': 'zen.spamhaus.org'},
    {'name': 'SpamCop',        'zone': 'bl.spamcop.net'},
    {'name': 'Barracuda',      'zone': 'b.barracudacentral.org'},
    {'name': 'SORBS',          'zone': 'dnsbl.sorbs.net'},
    {'name': 'UCEPROTECT L1',  'zone': 'dnsbl-1.uceprotect.net'},
    {'name': 'PSBL',           'zone': 'psbl.surriel.com'},
]


def parse_ip(s):
    """Return a normalized IPv4 string, or ``None`` if not a valid IPv4."""
    try:
        ip = ipaddress.ip_address(str(s).strip())
    except ValueError:
        return None
    if ip.version != 4:
        return None
    return str(ip)


def reverse_ip(ip):
    """``1.2.3.4`` -> ``4.3.2.1`` (the DNSBL query prefix)."""
    return '.'.join(reversed(ip.split('.')))


def parse_target(body):
    """Validate an add request -> ``{ip, label}`` or ``None``."""
    if not isinstance(body, dict):
        return None
    ip = parse_ip(body.get('ip', ''))
    if not ip:
        return None
    label = str(body.get('label', ''))[:80]
    return {'ip': ip, 'label': label}


def _make_resolver():
    import dns.resolver
    r = dns.resolver.Resolver()
    r.lifetime = DNS_TIMEOUT
    r.timeout = DNS_TIMEOUT
    return r


_LISTING_NET = ipaddress.ip_network("127.0.0.0/8")
_DNSBL_ERROR_NET = ipaddress.ip_network("127.255.255.0/24")


def _is_listing_code(code):
    """A DNSBL answer is a real LISTING only when it's in 127.0.0.0/8 AND not in
    the 127.255.255.0/24 status/error range. The error range means the query was
    REFUSED, not that the IP is listed — e.g. 127.255.255.254 = 'query came via a
    public/open resolver', 127.255.255.252 = blocked, 127.255.255.255 = volume
    limit. Counting those as listings is a false positive (and flaps → alert spam)."""
    try:
        a = ipaddress.ip_address(str(code))
    except ValueError:
        return False
    return a in _LISTING_NET and a not in _DNSBL_ERROR_NET


def _query(name, resolver):
    """Return ``(codes, txt)`` — the A-record return codes + matching TXT reasons.
    NXDOMAIN/NoAnswer -> ``([], [])`` (not listed). Lookup failures
    (timeout/SERVFAIL) raise so the caller records a zone error, not a false
    'clean'. The caller classifies codes into real listings vs status/error codes."""
    import dns.resolver
    try:
        ans = resolver.resolve(name, 'A')
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], []
    codes = [str(r) for r in ans]
    txt = []
    try:
        for r in resolver.resolve(name, 'TXT'):
            try:
                txt.append(b''.join(r.strings).decode('utf-8', 'replace'))
            except Exception:
                txt.append(str(r).strip('"'))
    except Exception:
        pass  # TXT reason is best-effort; absence doesn't change the listing
    return codes, txt


def check_ip(ip, zones=None, resolver=None):
    """Check one IPv4 against the DNSBL zones.

    Returns ``{ip, listed_on: [{name, zone, codes, reason}], errors: {zone: msg},
    listed_count, ok}`` — or ``{ip, error}`` for an invalid address. ``ok`` is
    True only when every zone answered (no timeouts), so a partial check is never
    mistaken for a clean one. The caller stamps ``checked_at``.
    """
    norm = parse_ip(ip)
    if not norm:
        return {'ip': str(ip)[:64], 'error': 'invalid IPv4 address'}
    zones = zones if zones is not None else DEFAULT_DNSBLS
    if resolver is None:
        resolver = _make_resolver()
    rev = reverse_ip(norm)
    listed_on, errors = [], {}
    for z in zones:
        zone = z.get('zone')
        name = z.get('name', zone)
        if not zone or not valid_zone(zone):
            continue
        try:
            codes, txt = _query(f'{rev}.{zone}', resolver)
        except Exception as e:
            errors[zone] = str(e)[:120]
            continue
        if not codes:
            continue  # NXDOMAIN — not listed by this zone
        listing_codes = [c for c in codes if _is_listing_code(c)]
        if listing_codes:
            listed_on.append({'name': name, 'zone': zone, 'codes': listing_codes,
                              'reason': '; '.join(txt)[:300]})
        else:
            # All codes are status/error (e.g. a public-resolver refusal) — the
            # listing status is unknown, so record a zone error rather than a
            # false 'listed' or a false 'clean'.
            errors[zone] = 'query refused / status code ' + ','.join(codes)[:80]
    return {'ip': norm, 'listed_on': listed_on, 'errors': errors,
            'listed_count': len(listed_on), 'ok': not errors}

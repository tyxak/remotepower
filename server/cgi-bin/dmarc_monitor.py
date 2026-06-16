"""RemotePower DMARC posture monitor — Flavor 1 (DNS only).

Reads the published email-authentication TXT records for a domain and grades
them. NO mailbox / SMTP needed — pure DNS:

  - DMARC: ``_dmarc.<domain>``          → policy (none/quarantine/reject), pct, rua
  - SPF:   ``<domain>`` TXT ``v=spf1``   → the ``all`` qualifier (-all hard / ~all soft)
  - DKIM:  ``<selector>._domainkey.<domain>``  (only when a selector is configured)

Uses dnspython (already a dependency for the DANE/TLSA checker). The PARSE
functions are deliberately split from the DNS query so they unit-test on
synthetic record strings without touching the network.
"""

import re
import time

DNS_TIMEOUT = 5.0


def _txt_records(name):
    """TXT strings for ``name``. NXDOMAIN / NoAnswer → ``[]`` (a *missing* record
    is a finding, not an error). Real lookup failures (timeout / SERVFAIL) raise."""
    import dns.resolver
    r = dns.resolver.Resolver()
    r.lifetime = DNS_TIMEOUT
    r.timeout = DNS_TIMEOUT
    try:
        ans = r.resolve(name, 'TXT')
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    out = []
    for rdata in ans:
        try:
            s = b''.join(rdata.strings).decode('utf-8', 'replace')
        except Exception:
            s = str(rdata).strip('"')
        out.append(s)
    return out


def _parse_tags(s):
    """Split a ``k=v; k2=v2`` record into a lowercased-key dict."""
    out = {}
    for part in s.split(';'):
        if '=' in part:
            k, v = part.split('=', 1)
            out[k.strip().lower()] = v.strip()
    return out


def _int(v, default):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def parse_dmarc(records):
    """Return the parsed v=DMARC1 record (or ``{}`` if none present)."""
    for s in records:
        if s.strip().lower().startswith('v=dmarc1'):
            tags = _parse_tags(s)
            return {
                'record':           s.strip()[:512],
                'policy':           (tags.get('p') or '').lower(),
                'subdomain_policy': (tags.get('sp') or '').lower(),
                'pct':              _int(tags.get('pct'), 100),
                'rua':              tags.get('rua', '')[:512],
                'ruf':              tags.get('ruf', '')[:512],
                'aspf':             (tags.get('aspf') or 'r').lower(),
                'adkim':            (tags.get('adkim') or 'r').lower(),
            }
    return {}


def parse_spf(records):
    """Return ``{record, all}`` for the v=spf1 record (``all`` is -/~/?/+/'')."""
    for s in records:
        if s.strip().lower().startswith('v=spf1'):
            m = re.search(r'([~\-+?])all\b', s.lower())
            return {'record': s.strip()[:512], 'all': (m.group(1) if m else '')}
    return {}


def parse_dkim(records):
    """Return ``{record, present}`` — present iff a public key (p=) is published."""
    for s in records:
        low = s.strip().lower()
        if low.startswith('v=dkim1') or 'p=' in low:
            tags = _parse_tags(s)
            return {'record': s.strip()[:256], 'present': bool(tags.get('p'))}
    return {}


def grade(dmarc, spf, dkim, dkim_checked):
    """Grade the posture → (status, reasons).

    status:  'ok'   — enforcing (p=quarantine/reject), rua set, SPF -all/~all
             'weak' — enforcing but with gaps
             'fail' — not enforcing (no DMARC, or p=none) → domain is spoofable
    """
    reasons = []
    if not dmarc:
        reasons.append('no DMARC record')
    else:
        p = dmarc.get('policy')
        if p not in ('quarantine', 'reject'):
            reasons.append(f"DMARC policy '{p or 'none'}' — monitoring only, not enforcing")
        if dmarc.get('pct', 100) < 100:
            reasons.append(f"DMARC pct={dmarc['pct']} (not all mail enforced)")
        if not dmarc.get('rua'):
            reasons.append('no aggregate-report (rua) address')
    if not spf:
        reasons.append('no SPF record')
    elif spf.get('all') not in ('-', '~'):
        reasons.append(f"SPF all-qualifier '{spf.get('all') or '?'}' (use -all or ~all)")
    if dkim_checked and not dkim.get('present'):
        reasons.append('DKIM selector has no key published')

    if not reasons:
        return 'ok', []
    if (not dmarc) or (dmarc.get('policy') not in ('quarantine', 'reject')):
        return 'fail', reasons
    return 'weak', reasons


def check_domain(domain, dkim_selector=''):
    """Full posture check for one domain. Never raises — DNS failures become
    per-record ``errors`` entries; missing records are graded, not errored."""
    out = {
        'domain': domain, 'dkim_selector': dkim_selector or '',
        'checked_at': int(time.time()),
        'dmarc': {}, 'spf': {}, 'dkim': {}, 'errors': {},
        'status': 'unknown', 'reasons': [],
    }
    try:
        out['dmarc'] = parse_dmarc(_txt_records('_dmarc.' + domain))
    except Exception as e:
        out['errors']['dmarc'] = str(e)[:120]
    try:
        out['spf'] = parse_spf(_txt_records(domain))
    except Exception as e:
        out['errors']['spf'] = str(e)[:120]
    dkim_checked = bool(dkim_selector)
    if dkim_checked:
        try:
            out['dkim'] = parse_dkim(_txt_records(f'{dkim_selector}._domainkey.{domain}'))
        except Exception as e:
            out['errors']['dkim'] = str(e)[:120]
    out['status'], out['reasons'] = grade(out['dmarc'], out['spf'], out['dkim'], dkim_checked)
    return out


_DOMAIN_RE = re.compile(r'^(?=.{1,253}$)([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$')
_SELECTOR_RE = re.compile(r'^[A-Za-z0-9._-]{1,128}$')


def parse_target(body):
    """Validate an add request → ``{domain, dkim_selector, label}`` or ``None``."""
    if not isinstance(body, dict):
        return None
    domain = str(body.get('domain', '')).strip().lower().rstrip('.')
    if not _DOMAIN_RE.match(domain):
        return None
    selector = str(body.get('dkim_selector', '')).strip()
    if selector and not _SELECTOR_RE.match(selector):
        return None
    label = str(body.get('label', ''))[:80]
    return {'domain': domain, 'dkim_selector': selector, 'label': label}

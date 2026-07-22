"""RemotePower — Security Advisory: turn collected data into things to DO.

RemotePower already knows a great deal about a host: pending patches, CVEs, EOL,
firewall state, world-reachable sockets, failed integrity checks, quarantined
files, TLS expiry, scanner findings down to the application layer (a WordPress
plugin, an exposed admin panel). All of it lives on different pages, each
answering "what is the state of X".

The advisory answers the other question — *what should I fix, in what order, and
why* — across the whole stack from OS to application, for one host or the whole
fleet.

Design notes:

  * Every finding is derived from data ALREADY STORED. No new collection, no
    outbound calls; the advisory is cheap to run on demand at any scope.
  * A finding must carry its evidence. "Harden SSH" is useless; "root login is
    permitted (PermitRootLogin yes) on 3 hosts" is actionable, and the operator
    can verify it without trusting us.
  * `fix` is what to actually do, in the imperative. If we can't say something
    concrete, the finding does not earn its place.
  * Severity drives ORDER, and order is the entire product here. An advisory
    that lists forty things in arbitrary order is a second inbox.

Pure functions: the callers pass the stores in. No api import (keeps it
unit-testable and out of the circular-import trap).
"""

import time

# Order is the product: everything sorts by this, then by how many hosts are
# affected (a problem on 30 hosts outranks the same problem on one).
SEVERITY_RANK = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}

# Layers, outermost-first. The operator thinks in these terms ("is my problem
# the app or the box?"), and the UI groups by them.
LAYERS = ('application', 'exposure', 'os', 'identity', 'integrity', 'data')


def _finding(fid, layer, severity, title, why, fix, *, device_id='', device='',
             evidence=None, source='', doc=''):
    return {
        'id': fid, 'layer': layer, 'severity': severity, 'title': title,
        'why': why, 'fix': fix, 'device_id': device_id, 'device': device,
        'evidence': list(evidence or [])[:8], 'source': source, 'doc': doc,
    }


# ── per-host builders ────────────────────────────────────────────────────────
def _os_findings(dev_id, name, dev, cve_rec, eol_rec):
    """Operating-system layer: patches, kernel, EOL, CVEs."""
    out = []
    si = dev.get('sysinfo') or {}

    findings = (cve_rec or {}).get('findings') or []
    crit = [f for f in findings if isinstance(f, dict)
            and (f.get('severity') or '').lower() == 'critical' and not f.get('ignored')]
    high = [f for f in findings if isinstance(f, dict)
            and (f.get('severity') or '').lower() == 'high' and not f.get('ignored')]
    if crit or high:
        ev = [f"{f.get('vuln_id', '?')} in {f.get('package', '?')}"
              for f in (crit + high)[:6]]
        out.append(_finding(
            'os.cve', 'os', 'critical' if crit else 'high',
            f'{len(crit) + len(high)} critical/high CVEs in installed packages',
            'These are known-exploitable flaws in software this host is running '
            'right now. Public exploit code usually appears within days of '
            'disclosure, and mass scanning follows within hours of that.',
            'Patch the named packages, then re-run the CVE scan to confirm. '
            'Use Security → CVEs → “Fix this first” for the exposure-weighted '
            'order if you cannot patch everything at once.',
            device_id=dev_id, device=name, evidence=ev, source='CVE scan',
            doc='docs/cve.md'))

    try:
        upgradable = int(((si.get('packages') or {}).get('upgradable')) or 0)
    except (TypeError, ValueError):
        upgradable = 0
    if upgradable >= 1:
        sec = ((si.get('packages') or {}).get('security')) or 0
        out.append(_finding(
            'os.patches', 'os', 'high' if sec else 'medium',
            f'{upgradable} pending package updates'
            + (f' ({sec} security)' if sec else ''),
            'Unapplied updates are the single most common way a fully-supported '
            'system gets compromised — the fix already exists and simply is not '
            'installed.',
            'Apply updates from Fleet → Patches (or schedule a patch window). '
            'Security updates first if you are staging the rollout.',
            device_id=dev_id, device=name, source='package inventory',
            doc='docs/patches.md'))

    if si.get('reboot_required'):
        out.append(_finding(
            'os.reboot', 'os', 'medium', 'Reboot required to finish applying updates',
            'A patched kernel or library on disk is not the one running. Until '
            'the reboot, the host is still executing the vulnerable code and the '
            'patch report reads as clean — the worst combination.',
            'Schedule a reboot (Fleet → Commands, or a maintenance window).',
            device_id=dev_id, device=name, source='host state'))

    eol = (eol_rec or {}).get('status') if isinstance(eol_rec, dict) else None
    if eol in ('eol', 'expired'):
        out.append(_finding(
            'os.eol', 'os', 'high',
            f"{si.get('os') or 'The operating system'} is past end-of-life",
            'No further security updates will ever be issued. Every flaw found '
            'from now on stays unpatched on this host permanently.',
            'Plan an upgrade to a supported release. Until then, treat the host '
            'as untrusted: restrict what it can reach and what can reach it.',
            device_id=dev_id, device=name, source='OS lifecycle',
            doc='docs/security.md'))
    return out


def _exposure_findings(dev_id, name, dev, exposure_mutes, muted_fn):
    """What the outside world can reach, and how well it is defended."""
    out = []
    si = dev.get('sysinfo') or {}

    world = [p for p in (si.get('listening_ports') or [])
             if isinstance(p, dict) and p.get('scope') == 'world'
             and not muted_fn(p.get('process'), p.get('proto'), p.get('port'),
                              exposure_mutes or [], dev_id)]
    if world:
        ev = [f"{p.get('proto', 'tcp')}/{p.get('port', '?')} "
              f"({p.get('process') or 'unknown process'})" for p in world[:6]]
        out.append(_finding(
            'exp.world', 'exposure', 'high' if len(world) > 2 else 'medium',
            f'{len(world)} service(s) reachable from any address',
            'Every world-reachable port is a way in. Most compromises start at '
            'a service the operator did not realise was listening publicly.',
            'For each: bind it to localhost or a private interface, put it '
            'behind the firewall, or — if it is genuinely meant to be public — '
            'mute it on the Exposure page so it stops being noise.',
            device_id=dev_id, device=name, evidence=ev,
            source='listening ports', doc='docs/exposure.md'))

    fw = si.get('firewall')
    fw_off = (isinstance(fw, dict) and fw.get('active') is False)
    if not isinstance(fw, dict):
        fp = si.get('firewall_fp')
        fw_off = isinstance(fp, dict) and (fp.get('backend') or '').lower() == 'none'
    if fw_off:
        out.append(_finding(
            'exp.firewall', 'exposure', 'high', 'No host firewall is active',
            'The host relies entirely on whatever is upstream. Anything that '
            'starts listening — deliberately or not — is immediately reachable '
            'from everywhere that can route to it.',
            'Enable nftables/ufw with a default-deny inbound policy and allow '
            'only the services you actually publish.',
            device_id=dev_id, device=name, source='firewall posture',
            doc='docs/firewall.md'))

    for c in (si.get('tls_certs') or []):
        if not isinstance(c, dict):
            continue
        try:
            days = int(c.get('days_left') or 0)
        except (TypeError, ValueError):
            continue
        if not c.get('days_left') and c.get('days_left') != 0:
            continue
        if days <= 14:
            out.append(_finding(
                'exp.tls', 'exposure', 'high' if days <= 3 else 'medium',
                f"TLS certificate for {c.get('cn') or c.get('domain') or '?'} "
                f"expires in {days} day(s)",
                'An expired certificate breaks the service outright and trains '
                'users to click through certificate warnings, which is worse '
                'than the outage.',
                'Renew it. If ACME is configured, check why the renewal did not '
                'run rather than renewing by hand.',
                device_id=dev_id, device=name, source='TLS monitor',
                doc='docs/tls-monitor.md'))
    return out


def _identity_findings(dev_id, name, dev):
    """Who can get in, and how."""
    out = []
    si = dev.get('sysinfo') or {}

    ssh = si.get('ssh_config') or {}
    if isinstance(ssh, dict):
        if str(ssh.get('permit_root_login', '')).lower() in ('yes', 'without-password'):
            out.append(_finding(
                'id.rootssh', 'identity', 'high', 'SSH permits direct root login',
                'It removes the audit trail (everything is "root") and hands a '
                'password-guessing attacker the highest-value account directly.',
                'Set PermitRootLogin no, log in as a user and escalate with sudo.',
                device_id=dev_id, device=name,
                evidence=[f"PermitRootLogin {ssh.get('permit_root_login')}"],
                source='sshd config', doc='docs/security.md'))
        if str(ssh.get('password_authentication', '')).lower() == 'yes':
            out.append(_finding(
                'id.sshpw', 'identity', 'medium', 'SSH accepts password authentication',
                'Passwords can be guessed at scale from anywhere. Key-based auth '
                'cannot, and every internet-facing host is being tried constantly.',
                'Deploy keys, then set PasswordAuthentication no.',
                device_id=dev_id, device=name, source='sshd config',
                doc='docs/security.md'))

    bf = si.get('brute_force') or {}
    if isinstance(bf, dict) and (bf.get('failed') or 0) > 50:
        out.append(_finding(
            'id.bruteforce', 'identity', 'medium',
            f"{bf.get('failed')} failed authentication attempts",
            'Sustained guessing means this host is a known target. It only has '
            'to succeed once.',
            'Confirm fail2ban (or equivalent) is running and jailing, and turn '
            'off password authentication if it is still on.',
            device_id=dev_id, device=name, source='auth log',
            doc='docs/security.md'))
    return out


def _integrity_findings(dev_id, name, dev, failed_checks):
    """Has anything on this host changed that should not have?"""
    out = []
    si = dev.get('sysinfo') or {}

    guard = si.get('guard_quarantine')
    if isinstance(guard, list) and guard:
        ev = [str(e.get('orig', ''))[:120] for e in guard[:6] if isinstance(e, dict)]
        out.append(_finding(
            'int.quarantine', 'integrity', 'critical',
            f'{len(guard)} file(s) auto-quarantined by Integrity Guard',
            'Files appeared in a watched directory that should not change. That '
            'is the signature of a web shell or a dropped payload — and it has '
            'already been moved out of the way, so the clock is on you to work '
            'out how it got there.',
            'Review each in Security → Protect → quarantine vault. Restore any '
            'false positive; for the rest, find the entry point before deleting '
            'the evidence.',
            device_id=dev_id, device=name, evidence=ev,
            source='Integrity Guard', doc='docs/integrity-guard.md'))

    for c in failed_checks or []:
        out.append(_finding(
            'int.check', 'integrity',
            'critical' if c.get('status') == 'critical' else 'medium',
            f"Protect check failing: {c.get('name') or c.get('id')}",
            'A baseline you told RemotePower to hold is no longer being held. '
            'Either something changed that should not have, or the baseline is '
            'out of date — both are worth knowing which.',
            'Open Security → Protect. If the change was legitimate, use '
            'Re-baseline to accept the current state; otherwise investigate.',
            device_id=dev_id, device=name,
            evidence=[str(c.get('output', ''))[:200]] if c.get('output') else None,
            source='protect check', doc='docs/integrity-guard.md'))
    return out


def _application_findings(dev_id, name, scans):
    """The application layer — what a scanner found in what the host serves.

    This is the layer host telemetry cannot see: a vulnerable CMS plugin is not
    a package, does not appear in a CVE feed keyed on distro packages, and does
    not open a new port.
    """
    out = []
    for s in scans or []:
        if not isinstance(s, dict):
            continue
        tool = s.get('tool') or 'scan'
        for f in (s.get('findings') or [])[:200]:
            if not isinstance(f, dict):
                continue
            sev = (f.get('severity') or '').lower()
            # MEDIUM belongs here too. A scanner's medium findings on a public
            # service are frequently the most actionable thing it reports —
            # enumerable usernames, an exposed config backup — and dropping
            # them meant the advisory could show nothing for a site whose
            # scanner output was full of real work. `info` stays out: that is
            # inventory (headers, robots.txt), not a decision. Grouping keeps
            # this to one row per finding type, and severity ordering keeps it
            # below anything critical or high.
            if sev not in ('critical', 'high', 'medium'):
                continue
            title = str(f.get('name') or f.get('title') or f.get('id') or 'finding')
            # The grouping id must identify the FINDING, not just the tool.
            # Keyed on `app.<tool>` alone, every wpscan result collapsed into a
            # single row — a vulnerable plugin and enumerable usernames became
            # one entry titled with whichever happened to come first. The rule
            # id is the tool's own stable identity for a check; fall back to the
            # title so a tool without one still separates.
            fid = str(f.get('rule_id') or f.get('id') or title)[:80]
            out.append(_finding(
                f'app.{tool}.{fid}', 'application', sev,
                f'{tool}: {title[:120]}',
                'Found by scanning the service as an outsider sees it — this is '
                'reachable without any credential on the host.',
                str(f.get('remediation') or f.get('fix')
                    or 'Update or reconfigure the affected component, then '
                       're-run the scan to confirm it is gone.')[:400],
                device_id=dev_id, device=name,
                evidence=[str(f.get('matched') or f.get('url') or f.get('detail') or '')[:200]],
                source=f'{tool} scan', doc='docs/security-scans.md'))
    return out


# ── the roll-up ──────────────────────────────────────────────────────────────
def build(devices, *, cve_by_dev=None, eol_by_dev=None, scans_by_dev=None,
          failed_checks_by_dev=None, exposure_mutes=None, muted_fn=None,
          now=None):
    """Assemble the advisory for a set of devices.

    Everything is passed in, so the caller controls scope (one host, a tag, the
    whole fleet) and this stays a pure function.

    Returns {findings, groups, counts, generated_at, device_count} with findings
    already in the order they should be acted on.
    """
    now = now or int(time.time())
    muted_fn = muted_fn or (lambda *a, **k: False)
    cve_by_dev = cve_by_dev or {}
    eol_by_dev = eol_by_dev or {}
    scans_by_dev = scans_by_dev or {}
    failed_checks_by_dev = failed_checks_by_dev or {}

    findings = []
    for dev_id, dev in (devices or {}).items():
        if not isinstance(dev, dict):
            continue
        name = dev.get('name') or dev_id
        findings += _os_findings(dev_id, name, dev, cve_by_dev.get(dev_id),
                                 eol_by_dev.get(dev_id))
        findings += _exposure_findings(dev_id, name, dev, exposure_mutes, muted_fn)
        findings += _identity_findings(dev_id, name, dev)
        findings += _integrity_findings(dev_id, name, dev,
                                        failed_checks_by_dev.get(dev_id))
        findings += _application_findings(dev_id, name, scans_by_dev.get(dev_id))

    # Group identical findings across hosts: "23 hosts have pending updates" is
    # one decision, not 23 rows. The per-host detail is kept underneath.
    groups = {}
    for f in findings:
        g = groups.setdefault(f['id'], {
            'id': f['id'], 'layer': f['layer'], 'severity': f['severity'],
            'title': f['title'], 'why': f['why'], 'fix': f['fix'],
            'source': f['source'], 'doc': f['doc'], 'devices': [], 'evidence': [],
        })
        # A group takes the worst severity any member reported.
        if SEVERITY_RANK.get(f['severity'], 9) < SEVERITY_RANK.get(g['severity'], 9):
            g['severity'] = f['severity']
        if f['device_id']:
            g['devices'].append({'device_id': f['device_id'], 'device': f['device'],
                                 'title': f['title']})
        for e in f['evidence']:
            if e and e not in g['evidence']:
                g['evidence'].append(e)
        g['evidence'] = g['evidence'][:8]

    grouped = sorted(groups.values(),
                     key=lambda g: (SEVERITY_RANK.get(g['severity'], 9),
                                    -len(g['devices']), g['title']))
    for g in grouped:
        g['device_count'] = len(g['devices'])
        g['devices'] = g['devices'][:25]          # bounded payload

    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for g in grouped:
        counts[g['severity']] = counts.get(g['severity'], 0) + 1
    return {
        'findings': grouped, 'counts': counts,
        'total_findings': len(findings),
        'device_count': len(devices or {}),
        'generated_at': now,
    }


def summarize_for_ai(advisory, scope_label):
    """A compact, redacted brief for the AI advisor.

    Only titles, severities, counts and layers — never raw evidence, which can
    carry hostnames, paths, URLs and matched log content. The model gets enough
    to prioritise and explain; it does not get the fleet's guts.
    """
    lines = [f'Security posture for {scope_label} '
             f"({advisory.get('device_count', 0)} host(s)).", '']
    for g in advisory.get('findings') or []:
        lines.append(f"- [{g['severity'].upper()}] {g['layer']}: {g['title']} "
                     f"— affects {g.get('device_count', 0)} host(s)")
    if not advisory.get('findings'):
        lines.append('- No critical or high findings from the collected data.')
    return '\n'.join(lines)[:6000]

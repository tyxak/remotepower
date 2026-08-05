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
def _os_findings(dev_id, name, dev, cve_rec, eol_rec, scap_rec=None):
    """Operating-system layer: patches, kernel, EOL, CVEs, benchmark."""
    out = []
    si = dev.get('sysinfo') or {}

    # OpenSCAP results were a parallel scoring silo with its own page and no
    # route into "what should I fix". Each failed rule already carries a
    # severity and an id, which is more actionable than most findings here.
    if isinstance(scap_rec, dict) and scap_rec.get('available'):
        rules = [r for r in (scap_rec.get('failed_rules') or [])
                 if isinstance(r, dict)]
        high = [r for r in rules
                if str(r.get('severity') or '').lower() in ('high', 'critical')]
        if rules:
            ev = [str((r.get('id') or '?')).rsplit('_', 1)[-1][:70]
                  for r in (high + [r for r in rules if r not in high])[:6]]
            score = scap_rec.get('score')
            out.append(_finding(
                'os.scap', 'os', 'high' if high else 'medium',
                f'{len(rules)} benchmark rule(s) failing'
                + (f' ({len(high)} high)' if high else '')
                + (f' — {scap_rec.get("profile") or "profile"} scored {score}%'
                   if isinstance(score, (int, float)) else ''),
                'These are the hardening controls the benchmark you chose says '
                'this host should meet and does not. Unlike a CVE, none of them '
                'will be fixed by patching — they stay failing until someone '
                'changes the configuration.',
                'Open Security → SCAP and download the report; it names the '
                'remediation for each rule. Fix the high-severity ones first, '
                'and re-scan to confirm rather than assuming.',
                device_id=dev_id, device=name, evidence=ev,
                source='OpenSCAP', doc='docs/fleet-management.md'))

    # The caller applies the CVE ignore list before handing findings over, so
    # `ignored` is already stamped where it applies. (Until v6.4.1 it never was
    # — the flag is a read-time decoration the scanner adds on a COPY, and the
    # advisory read the raw store, so an accepted-risk CVE vanished from Risk
    # and kept driving the advisory.)
    findings = (cve_rec or {}).get('findings') or []
    crit = [f for f in findings if isinstance(f, dict)
            and (f.get('severity') or '').lower() == 'critical' and not f.get('ignored')]
    high = [f for f in findings if isinstance(f, dict)
            and (f.get('severity') or '').lower() == 'high' and not f.get('ignored')]
    if crit or high:
        # KEV membership means "observed being exploited in the wild right now",
        # which outranks severity: a KEV-listed high is more urgent than a
        # critical nobody has weaponised. The scanner stamps `kev` per finding.
        kev = [f for f in (crit + high) if f.get('kev')]
        ev = [(f"{f.get('vuln_id', '?')} in {f.get('package', '?')}"
               + (' — KEV, exploited in the wild' if f.get('kev') else ''))
              for f in (kev + [f for f in (crit + high) if not f.get('kev')])[:6]]
        out.append(_finding(
            'os.cve', 'os', 'critical' if (crit or kev) else 'high',
            (f'{len(kev)} actively-exploited (KEV) '
             f'and {len(crit) + len(high) - len(kev)} other critical/high CVEs'
             if kev else
             f'{len(crit) + len(high)} critical/high CVEs in installed packages'),
            ('These are known-exploitable flaws in software this host is running '
             'right now. Public exploit code usually appears within days of '
             'disclosure, and mass scanning follows within hours of that.'
             + (' The KEV-listed ones are not a forecast — CISA lists them '
                'because exploitation has already been observed.' if kev else '')),
            ('Patch the KEV-listed packages first — those are being exploited '
             'today. Then work down the rest. '
             if kev else 'Patch the named packages, then re-run the CVE scan to confirm. ')
            + 'Use Security → CVEs → “Fix this first” for the exposure-weighted '
              'order if you cannot patch everything at once.',
            device_id=dev_id, device=name, evidence=ev, source='CVE scan',
            doc='docs/cve.md'))

    try:
        upgradable = int(((si.get('packages') or {}).get('upgradable')) or 0)
    except (TypeError, ValueError):
        upgradable = 0
    if upgradable >= 1:
        # v6.4.0 (BUG): read the whitelisted key `security_updates`, not
        # `security` — the latter is always absent, so `sec` was ALWAYS 0 and
        # the patch finding never escalated medium→high or showed "(N security)".
        sec = ((si.get('packages') or {}).get('security_updates')) or 0
        # v6.4.0: fold in the auto-update posture so the advisor distinguishes a
        # host that will patch itself from one that needs a human. A box with
        # pending updates AND no auto-patch mechanism is the one that rots.
        _au = si.get('autoupdate')
        if not isinstance(_au, dict):
            _au = {}
        _self_patches = bool(_au.get('enabled'))
        _fix = ('Apply updates from Fleet → Patches (or schedule a patch window). '
                'Security updates first if you are staging the rollout.')
        if _self_patches:
            _fix += (f' This host auto-patches via {_au.get("mechanism") or "a timer"}, '
                     'so these should apply on their own soon — investigate if the '
                     'count keeps growing.')
        else:
            _fix += (' This host does not auto-patch, so nothing will apply these '
                     'until you do — consider enabling unattended-upgrades / '
                     'dnf-automatic on hosts that can take unattended reboots.')
        out.append(_finding(
            'os.patches', 'os', 'high' if sec else 'medium',
            f'{upgradable} pending package updates'
            + (f' ({sec} security)' if sec else '')
            + ('' if _self_patches else ' — no auto-patching'),
            'Unapplied updates are the single most common way a fully-supported '
            'system gets compromised — the fix already exists and simply is not '
            'installed.',
            _fix,
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
            # The OS string lives on the device, not in sysinfo — reading
            # si['os'] always degraded this to the generic wording.
            f"{dev.get('os') or 'The operating system'} is past end-of-life",
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

    return out


def _tls_findings(tls_expiring):
    """TLS certificates about to expire — a FLEET-level finding.

    Until v6.4.1 this read `sysinfo.tls_certs`, a key no agent has ever set and
    the heartbeat sanitizer has never whitelisted, so the finding could not
    fire. The real data is the TLS monitor's own probe results, which are keyed
    by monitored target rather than by device — hence no device_id here.
    """
    out = []
    for c in tls_expiring or []:
        if not isinstance(c, dict):
            continue
        try:
            days = int(c.get('days_left'))
        except (TypeError, ValueError):
            continue
        label = str(c.get('label') or '?')
        if days < 0:
            out.append(_finding(
                'exp.tls.expired', 'exposure', 'critical',
                f'TLS certificate for {label} has expired',
                'The service is presenting an invalid certificate right now. '
                'Clients either fail outright or are being taught to click '
                'through the warning, which is the worse outcome.',
                'Renew it immediately. If ACME is configured, the renewal has '
                'been failing for weeks — fix the cause, not just this cert.',
                source='TLS monitor', doc='docs/tls-monitor.md'))
        elif days <= 14:
            out.append(_finding(
                'exp.tls', 'exposure', 'high' if days <= 3 else 'medium',
                f'TLS certificate for {label} expires in {days} day(s)',
                'An expired certificate breaks the service outright and trains '
                'users to click through certificate warnings, which is worse '
                'than the outage.',
                'Renew it. If ACME is configured, check why the renewal did not '
                'run rather than renewing by hand.',
                source='TLS monitor', doc='docs/tls-monitor.md'))
    return out


def _identity_findings(dev_id, name, dev, bf_sources=None,
                       weak_ssh_keys=None, risky_accounts=None):
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
        if str(ssh.get('permit_empty_passwords', '')).lower() == 'yes':
            # v6.4.2: the second half of this finding is now ANSWERED rather
            # than delegated — see id.emptypw below, which lists the accounts
            # that actually have a blank password on this host.
            blank_here = len((risky_accounts or {}).get('empty') or [])
            out.append(_finding(
                'id.sshempty', 'identity', 'critical',
                'SSH accepts accounts with an empty password',
                'Any account on this host with a blank password can be logged '
                'into from anywhere, with no credential at all. This is one '
                'misconfigured user away from an open shell.',
                'Set PermitEmptyPasswords no.' + (
                    f' {blank_here} account(s) on this host currently HAVE a '
                    'blank password — see "Local accounts with a blank '
                    'password" below; together these are an open shell right '
                    'now, not a latent risk.' if blank_here else
                    ' No account on this host currently has a blank password, '
                    'so nothing is exposed by it today — but the setting means '
                    'the next one that appears is immediately reachable.'),
                device_id=dev_id, device=name,
                evidence=['PermitEmptyPasswords yes'] + (
                    [f'{blank_here} blank-password account(s) present']
                    if blank_here else []),
                source='sshd config', doc='docs/security.md'))
        if str(ssh.get('password_authentication', '')).lower() == 'yes':
            out.append(_finding(
                'id.sshpw', 'identity', 'medium', 'SSH accepts password authentication',
                'Passwords can be guessed at scale from anywhere. Key-based auth '
                'cannot, and every internet-facing host is being tried constantly.',
                'Deploy keys, then set PasswordAuthentication no.',
                device_id=dev_id, device=name, source='sshd config',
                doc='docs/security.md'))

    # Brute-force pressure. Until v6.4.1 this read `sysinfo.brute_force`, which
    # nothing writes — the real data has always lived in its own store, keyed
    # per device, and is passed in by the caller.
    if bf_sources:
        attempts = sum(int(s.get('count') or 0) for s in bf_sources
                       if isinstance(s, dict))
        ev = [f"{s.get('count')} failed from {s.get('source_ip')} "
              f"({s.get('unit') or 'auth'})"
              for s in bf_sources[:6] if isinstance(s, dict)]
        # fail2ban is the fix we recommend — say whether it is even installed
        # rather than telling the operator to check something we already know.
        f2b = si.get('fail2ban')
        jails = (f2b.get('jails') or []) if isinstance(f2b, dict) else []
        if isinstance(f2b, dict) and not f2b.get('available'):
            f2b_note = (' fail2ban is not installed on this host, so nothing is '
                        'currently rate-limiting the attempts.')
        elif isinstance(f2b, dict) and not jails:
            f2b_note = (' fail2ban is installed but has no active jails, so it '
                        'is not banning anything.')
        else:
            f2b_note = ''
        out.append(_finding(
            'id.bruteforce', 'identity', 'high' if len(bf_sources) > 2 else 'medium',
            f'{attempts} failed authentication attempts from '
            f'{len(bf_sources)} source(s)',
            'Sustained guessing means this host is a known target. It only has '
            'to succeed once.',
            'Block the source addresses, confirm fail2ban (or equivalent) is '
            'jailing them, and turn off password authentication if it is still '
            'on.' + f2b_note,
            device_id=dev_id, device=name, evidence=ev, source='auth log',
            doc='docs/security.md'))

    # Authorized SSH keys using a deprecated algorithm. Unlike "a key was
    # added" — which is an event, and already an alert — this is a durable
    # state read off the same baseline, so the advisory can act on it.
    if weak_ssh_keys:
        out.append(_finding(
            'id.weakkey', 'identity', 'medium',
            f'{len(weak_ssh_keys)} authorized SSH key(s) use a deprecated algorithm',
            'DSA and RSA1 keys are weak by modern standards and are disabled '
            'outright in current OpenSSH. A key that still works today is one '
            'upgrade away from locking that account out — and weaker than the '
            'password authentication you probably turned off in its favour.',
            'Replace them with ed25519 keys and remove the old entries from '
            'authorized_keys. Check the account still authenticates before you '
            'remove the last working key.',
            device_id=dev_id, device=name,
            evidence=[str(k)[:100] for k in weak_ssh_keys[:6]],
            source='SSH key audit', doc='docs/security.md'))

    # v6.4.2: local accounts whose /etc/shadow password field is blank or
    # ancient. The agent has reported both flags since v3.14.0; until now they
    # reached a per-device drawer badge and nothing else, so answering "does any
    # host have a passwordless account?" across a fleet meant opening every
    # drawer — which is precisely what id.sshempty above used to tell the
    # operator to go and do. Same durable-state reasoning as id.weakkey.
    ra = risky_accounts if isinstance(risky_accounts, dict) else {}
    blank = ra.get('empty') or []
    stale = ra.get('stale') or []
    if blank:
        # A blank password is unconditionally serious, but the shell decides
        # whether it is remotely reachable or only locally: an account with a
        # login shell can be SSH'd into (with PermitEmptyPasswords) or su'd to;
        # a nologin one can still be su'd to with no credential.
        interactive = [b for b in blank if 'no login shell' not in b]
        out.append(_finding(
            'id.emptypw', 'identity',
            'critical' if interactive else 'high',
            f'{len(blank)} local account(s) have a blank password',
            'These accounts need no credential at all. `su - <user>` from any '
            'account on the host succeeds, and if sshd permits empty passwords '
            'they are reachable from the network. A blank password is not a '
            'weak password — there is nothing to guess.',
            'Set a password (passwd <user>) or lock the account '
            '(passwd -l <user>) for each. If the account exists only to own '
            'files, give it a nologin shell as well. Then confirm '
            'PermitEmptyPasswords is no in sshd_config.',
            device_id=dev_id, device=name, evidence=blank[:6],
            source='local account posture', doc='docs/security.md'))
    if stale:
        out.append(_finding(
            'id.stalepw', 'identity', 'low',
            f'{len(stale)} login-capable account(s) have a password older '
            'than a year',
            'A credential that has not changed in over a year has had a year '
            'of exposure to every breach corpus, shoulder-surf and reused-'
            'password leak since it was set — and if the account belongs to '
            'someone who has left, it is still live.',
            'Rotate them, or better, move the account to key-based auth and '
            'lock the password. Confirm each still belongs to someone who '
            'should have access at all.',
            device_id=dev_id, device=name, evidence=stale[:6],
            source='local account posture', doc='docs/security.md'))

    # Windows posture — the identity/endpoint controls that keep an operator
    # account from becoming an administrator one.
    wp = si.get('win_posture')
    if isinstance(wp, dict):
        gaps = []
        if wp.get('tamper_protection') is False:
            gaps.append('Defender tamper protection is off')
        if wp.get('uac_enabled') is False:
            gaps.append('UAC is disabled')
        if wp.get('secure_boot') is False:
            gaps.append('Secure Boot is off')
        if gaps:
            out.append(_finding(
                'id.winposture', 'identity',
                'high' if wp.get('tamper_protection') is False else 'medium',
                f'{len(gaps)} Windows security control(s) disabled',
                'These are the controls that stop malware from disabling the '
                'rest. With tamper protection off, the first thing a payload '
                'does is turn Defender off — and it will succeed.',
                'Re-enable them via Group Policy or Intune so a local change '
                'cannot switch them back off.',
                device_id=dev_id, device=name, evidence=gaps,
                source='Windows posture', doc='docs/security.md'))
    return out


def _integrity_findings(dev_id, name, dev, failed_checks, agent_tamper=None):
    """Has anything on this host changed that should not have?"""
    out = []
    si = dev.get('sysinfo') or {}

    # The agent binary itself. A hash mismatch against the canonical build, or
    # an agent refusing an unsigned update, is a tamper indicator — and until
    # v6.4.1 it reached nothing but a badge on the device row.
    if agent_tamper == 'mismatch':
        out.append(_finding(
            'int.agenthash', 'integrity', 'critical',
            'Agent binary does not match the published build',
            'The agent reports the current version but a different hash. That '
            'is tampering, a corrupted update, or a partial one — and the '
            'agent is the thing telling you everything else about this host, '
            'so nothing it reports can be trusted until this is resolved.',
            'Re-run the agent install from the server to restore the '
            'published binary, then confirm the hash matches. If it was not '
            'a failed update, treat the host as compromised.',
            device_id=dev_id, device=name, source='agent integrity',
            doc='docs/security.md'))
    elif agent_tamper == 'update_rejected':
        out.append(_finding(
            'int.agentupdate', 'integrity', 'high',
            'Agent refused an update it could not verify',
            'The agent rejected a self-update because the signature did not '
            'check out. That is the tripwire working — but something served '
            'this host an update it should not have.',
            'Confirm the release signing key on the server matches the one '
            'the agent trusts, and check whether the update came from where '
            'you think it did.',
            device_id=dev_id, device=name, source='agent integrity',
            doc='docs/security.md'))

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

    # Config drift. Risk counts drifted files; the advisory names them, which
    # is the actionable half. Deliberately paths only — drift_contents.json
    # holds the captured file CONTENT, and a config file's contents are exactly
    # the kind of thing that carries a credential. The Drift page already shows
    # the diff behind its own view; the advisory does not need to carry it.
    drifted = [f for f, st in (dev.get('drift_state') or {}).items()
               if isinstance(st, dict) and st.get('status') == 'drifted'
               and not st.get('ignored')]
    if drifted:
        out.append(_finding(
            'int.drift', 'integrity', 'medium',
            f'{len(drifted)} tracked config file(s) changed from baseline',
            'A file you told RemotePower to watch is no longer what it was. '
            'Most of the time that is a change someone made and did not write '
            'down — which is still worth knowing, because it is the difference '
            'between a host you can rebuild and one you cannot.',
            'Review the diff on the Drift page. If the change was intended, '
            're-baseline it so the next real change is visible; if it was not, '
            'find out who or what made it.',
            device_id=dev_id, device=name, evidence=[str(f)[:120] for f in drifted[:6]],
            source='config drift', doc='docs/drift.md'))

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


def _data_findings(dev_id, name, dev, secrets, stale_backups):
    """What is on the disk that should not be, and what is not backed up.

    The `data` layer was declared in LAYERS from the start but had no builder
    until v6.4.1, so two of the most actionable stores in the product — the
    secret scanner and backup freshness — reached the advisory nowhere.
    """
    out = []
    si = dev.get('sysinfo') or {}

    live = [f for f in (secrets or [])
            if isinstance(f, dict) and not f.get('muted')]
    if live:
        ev = [f"{f.get('rule') or 'secret'} in {f.get('path') or '?'}"
              + (f":{f.get('line')}" if f.get('line') else '')
              for f in live[:6]]
        out.append(_finding(
            'data.secrets', 'data', 'high',
            f'{len(live)} credential(s) found in files on disk',
            'A key checked into a config file or left in a script is a '
            'credential with no expiry, no audit trail and no revocation — and '
            'anyone who reads the file has it. Backups and container images '
            'carry the copies along.',
            'Rotate each one first (assume it is compromised), then remove it '
            'from the file and load it from a secret store or the environment. '
            'Mute a match on Security → Secrets only once you have confirmed '
            'it is a placeholder.',
            device_id=dev_id, device=name, evidence=ev,
            source='secret scan', doc='docs/secret-scan.md'))

    if stale_backups:
        ev = [str(b)[:120] for b in stale_backups[:6]]
        out.append(_finding(
            'data.backup', 'data', 'high',
            f'{len(stale_backups)} backup(s) stale or missing',
            'A backup you believe in and do not have is worse than no backup '
            'at all — it is the difference between planning a restore and '
            'discovering there is nothing to restore from, during the incident.',
            'Find out why the job stopped producing files. Then run a restore '
            'drill against what you do have, because an unverified backup is '
            'still an assumption.',
            device_id=dev_id, device=name, evidence=ev,
            source='backup monitor', doc='docs/backups.md'))

    # Disk encryption — the one control that makes a stolen or RMA'd disk a
    # non-event. Reported per platform; Linux has no equivalent signal yet.
    mp = si.get('mac_posture')
    if isinstance(mp, dict) and mp.get('filevault') is False:
        out.append(_finding(
            'data.filevault', 'data', 'high', 'FileVault disk encryption is off',
            'Everything on the disk is readable by anyone who can boot from '
            'external media or pull the drive — no password required.',
            'Turn FileVault on (System Settings → Privacy & Security) and '
            'escrow the recovery key somewhere you will still have access to.',
            device_id=dev_id, device=name, source='macOS posture',
            doc='docs/security.md'))
    wp = si.get('win_posture')
    if isinstance(wp, dict) and isinstance(wp.get('bitlocker'), list):
        unenc = [v for v in wp['bitlocker'] if isinstance(v, dict)
                 and str(v.get('status') or '').lower() not in
                 ('', 'fullyencrypted', 'encryptioninprogress')]
        if unenc:
            out.append(_finding(
                'data.bitlocker', 'data', 'high',
                f'{len(unenc)} volume(s) not encrypted with BitLocker',
                'Everything on the volume is readable by anyone who can boot '
                'from external media or pull the drive — no password required.',
                'Enable BitLocker on the named volumes and escrow the recovery '
                'keys in AD/Entra so an encrypted disk does not become an '
                'unrecoverable one.',
                device_id=dev_id, device=name,
                evidence=[f"{v.get('mount') or '?'} — {v.get('status') or 'unprotected'}"
                          for v in unenc[:6]],
                source='Windows posture', doc='docs/security.md'))
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
          bf_by_dev=None, secrets_by_dev=None, backups_by_dev=None,
          tls_expiring=None, scap_by_dev=None, agent_tamper_by_dev=None,
          weak_keys_by_dev=None, accounts_by_dev=None, now=None):
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
    bf_by_dev = bf_by_dev or {}
    secrets_by_dev = secrets_by_dev or {}
    backups_by_dev = backups_by_dev or {}
    scap_by_dev = scap_by_dev or {}
    agent_tamper_by_dev = agent_tamper_by_dev or {}
    weak_keys_by_dev = weak_keys_by_dev or {}
    accounts_by_dev = accounts_by_dev or {}

    findings = []
    for dev_id, dev in (devices or {}).items():
        if not isinstance(dev, dict):
            continue
        name = dev.get('name') or dev_id
        findings += _os_findings(dev_id, name, dev, cve_by_dev.get(dev_id),
                                 eol_by_dev.get(dev_id), scap_by_dev.get(dev_id))
        findings += _exposure_findings(dev_id, name, dev, exposure_mutes, muted_fn)
        findings += _identity_findings(dev_id, name, dev, bf_by_dev.get(dev_id),
                                       weak_keys_by_dev.get(dev_id),
                                       accounts_by_dev.get(dev_id))
        findings += _integrity_findings(dev_id, name, dev,
                                        failed_checks_by_dev.get(dev_id),
                                        agent_tamper_by_dev.get(dev_id))
        findings += _data_findings(dev_id, name, dev, secrets_by_dev.get(dev_id),
                                   backups_by_dev.get(dev_id))
        findings += _application_findings(dev_id, name, scans_by_dev.get(dev_id))
    # Fleet-level: the TLS monitor probes targets, not devices.
    findings += _tls_findings(tls_expiring)

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

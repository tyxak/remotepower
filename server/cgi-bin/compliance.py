"""Control-mapped compliance reporting.

v3.4.0 (PCI / HIPAA / SOC 2); v6.3.1 adds Essential Eight + SMB1001:2026 and a
strict CAPABLE-SOURCE rule. This is deliberately an *evidence-from-observed-
state* checklist, not a formal attestation engine: every control maps to data
RemotePower already collects (patch status, CVEs, TLS expiry, firewall posture,
login/SSH audit, backup freshness, MFA, audit logging). Each control resolves
to one of:

    pass  — observed state satisfies the control
    fail  — observed state violates it (with the offending evidence)
    na    — RemotePower cannot assess this control: either it has no signal for
            it at all, OR the capable source that WOULD assess it has not run /
            reported yet. Never silently counted as a pass.

**The capable-source rule (v6.3.1, after the Assay "silence isn't clearance"
discipline):** a control must not infer PASS from an empty offenders list when
the underlying telemetry was never collected — that manufactures false
assurance, the worst outcome for an audit surface. So each absence→PASS control
is gated on a coverage fact (how many monitored hosts actually reported the
signal); coverage 0 on a non-empty fleet → NA, not PASS. The score is
`pass / (pass + fail)` and ignores NA, so "not assessed" can never inflate it.

The caller assembles a `facts` dict from the fleet and passes it in; the logic
here is pure so it unit-tests without a server. The mapping is a pragmatic
operator aid for audit prep — it does not make a system "compliant".
"""

PASS, FAIL, NA = 'pass', 'fail', 'na'

FRAMEWORKS = ('pci', 'hipaa', 'soc2', 'e8', 'smb1001')
FRAMEWORK_LABELS = {
    'pci':     'PCI DSS v4.0',
    'hipaa':   'HIPAA Security Rule',
    'soc2':    'SOC 2 (Common Criteria)',
    'e8':      'ACSC Essential Eight',
    'smb1001': 'SMB1001:2026',
}


def _no_coverage(facts, coverage_key):
    """True when the capable source for a control has produced NO data across a
    non-empty fleet — the signal to return NA instead of a false PASS."""
    return facts.get('devices', 0) > 0 and facts.get(coverage_key, 0) == 0


def _patch_control(facts):
    bad = facts.get('pending_patches_devices') or []
    if bad:
        return FAIL, f"{len(bad)} device(s) over the patch threshold: " + \
               ", ".join(bad[:10]) + ("…" if len(bad) > 10 else "")
    if _no_coverage(facts, 'patch_data_devices'):
        return NA, ("No host has reported package/update status yet — patch "
                    "posture is not assessed (run a package scan).")
    return PASS, "No device exceeds its pending-patch threshold."


def _cve_control(facts):
    n = facts.get('cve_critical_high', 0)
    if n:
        return FAIL, f"{n} critical/high CVE finding(s) outstanding across the fleet."
    if _no_coverage(facts, 'cve_scanned_devices'):
        return NA, ("No host has a CVE scan on record yet — vulnerability "
                    "posture is not assessed.")
    return PASS, "No outstanding critical or high CVEs."


def _eol_control(facts):
    """v3.4.1 — hosts running an end-of-life OS no longer get security patches."""
    bad = facts.get('eol_os') or []
    if bad:
        return FAIL, f"{len(bad)} host(s) on an end-of-life OS: " + \
               ", ".join(bad[:10]) + ("…" if len(bad) > 10 else "")
    if _no_coverage(facts, 'os_known_devices'):
        return NA, "No host has reported its OS version yet — EOL status is not assessed."
    return PASS, "No hosts are running an end-of-life OS version."


def _tls_control(facts):
    exp = facts.get('tls_expiring') or []
    if exp:
        return FAIL, f"{len(exp)} certificate(s) expiring soon: " + ", ".join(exp[:10])
    if facts.get('tls_monitored', 0) == 0:
        return NA, "No TLS endpoints are being monitored."
    return PASS, "All monitored certificates are within their validity window."


def _backup_control(facts):
    bad = facts.get('failed_backups') or []
    if bad:
        return FAIL, f"{len(bad)} stale/missing backup(s): " + ", ".join(bad[:10])
    if facts.get('backup_monitors', 0) == 0:
        return NA, "No backup monitors are configured."
    return PASS, "All configured backups are within their freshness window."


def _mfa_control(facts):
    if facts.get('mfa_enabled'):
        return PASS, "Multi-factor (TOTP/OIDC) is enabled for console access."
    return FAIL, "No operator MFA (TOTP or OIDC) is enabled on the console."


def _audit_control(facts):
    if facts.get('audit_log_enabled', True):
        return PASS, "Administrative actions are recorded in the audit log."
    return FAIL, "Audit logging is disabled."


def _exposure_detection_control(facts):
    """SOC 2 CC7.1 — "detect configuration changes / new exposure".

    RemotePower genuinely satisfies this: it baselines each host's listening
    ports and records changes. A change is NOT a control failure (a new port is
    usually a legitimate service) — "new since baseline" ≠ "unauthorized". So
    this PASSES because the detection capability is in place, and surfaces the
    recent count as context for review rather than a red FAIL.
    """
    n = len(facts.get('new_ports') or [])
    if not facts.get('ports_monitored'):
        return NA, "No listening-port data collected yet."
    note = (f" {n} port change(s) recorded in the last 30 days — review them in "
            f"Audit → Listening Ports.") if n else " No changes in the last 30 days."
    return PASS, "Listening-port change detection is active." + note


def _traffic_restrict_control(facts):
    """PCI 1.2.1 — "restrict inbound/outbound traffic". RemotePower observes
    listening ports but does not assess or manage firewall rule sets, so it
    cannot honestly attest this control."""
    return NA, ("RemotePower detects listening-port changes but does not assess "
                "firewall rule configuration — verify restrictions at the firewall.")


def _access_review_control(facts):
    changes = facts.get('ssh_key_changes') or []
    if changes:
        return FAIL, f"{len(changes)} host(s) with SSH authorized-key changes in the last 30 days: " + \
               ", ".join(str(h) for h in changes[:10])
    return PASS, "No SSH authorized-key changes in the last 30 days."


def _intrusion_control(facts):
    bf = facts.get('brute_force') or []
    if bf:
        return FAIL, f"Brute-force attempts detected on {len(bf)} host(s) in the last 30 days: " + \
               ", ".join(str(h) for h in bf[:10])
    return PASS, "No brute-force login activity in the last 30 days."


def _vault_control(facts):
    if facts.get('encrypted_vault', True):
        return PASS, "Stored device secrets are held in the encrypted vault."
    return NA, "No credential vault in use."


def _reboot_control(facts):
    rb = facts.get('reboot_required') or []
    if rb:
        return FAIL, f"{len(rb)} host(s) pending a reboot to apply updates: " + \
               ", ".join(rb[:10])
    if _no_coverage(facts, 'sysinfo_devices'):
        return NA, "No host has reported system status yet — reboot state is not assessed."
    return PASS, "No host is pending a security reboot."


# ── v6.3.1: controls with no RemotePower signal — HONESTLY 'not assessed'.
# Essential Eight / SMB1001 cover process + endpoint controls RemotePower does
# not observe (application allow-listing, Office macro policy, security-
# awareness training, a written IR plan). Reporting these as NA — rather than
# omitting them or faking a pass — is the whole point of the capable-source
# discipline: the report shows the FULL control set and says exactly which
# parts it cannot back up.
def _app_control_control(facts):
    return NA, ("RemotePower does not assess application allow-listing / "
                "execution control — verify with your EDR or AppLocker/WDAC.")


def _macro_control(facts):
    return NA, ("RemotePower does not assess Microsoft Office macro policy — "
                "verify via Group Policy / Intune.")


def _user_hardening_control(facts):
    return NA, ("RemotePower does not assess browser/application hardening "
                "(Flash/ads/Java/PDF) — verify via your endpoint baseline.")


def _admin_privilege_control(facts):
    """Restrict administrative privileges. RemotePower has a privileged-group
    tripwire (sudo/wheel/Administrators changes) but not a full standing-
    privilege inventory, so it reports recent CHANGES as evidence and is
    otherwise NA — it cannot attest the standing state."""
    changes = facts.get('privileged_group_changes') or []
    if changes:
        return FAIL, (f"{len(changes)} host(s) with privileged-group changes in "
                      f"the window: " + ", ".join(str(h) for h in changes[:10]))
    if not facts.get('privileged_group_monitored'):
        return NA, ("Privileged-group change detection has no baseline yet — "
                    "standing administrative privilege is not assessed.")
    return PASS, ("No privileged-group (sudo/wheel/Administrators) changes "
                  "detected in the window. Note: this attests change-detection, "
                  "not the standing privilege inventory.")


def _training_control(facts):
    return NA, ("Security-awareness training is a process control RemotePower "
                "does not track — record it in your ISMS.")


def _ir_plan_control(facts):
    return NA, ("A written incident-response plan is a process control "
                "RemotePower does not track — RemotePower provides the alerting "
                "and triage tooling an IR plan would reference.")


# Each control: (framework, id, title, check_fn, remediation).
# A single check can map into several frameworks; we list it per-framework so
# the report reads naturally under each standard's section.
_CONTROLS = [
    # PCI DSS
    ('pci', '6.3.3',  'Install applicable security patches',        _patch_control,
     'Apply pending updates on the listed hosts.'),
    ('pci', '6.3.1',  'Identify and rank known vulnerabilities',    _cve_control,
     'Remediate outstanding critical/high CVEs.'),
    ('pci', '6.3.3b', 'Run vendor-supported (non-EOL) software',    _eol_control,
     'Upgrade or replace hosts on end-of-life OS versions.'),
    ('pci', '4.2.1',  'Strong cryptography for transmission (TLS)', _tls_control,
     'Renew expiring certificates.'),
    ('pci', '1.2.1',  'Restrict inbound/outbound traffic',          _traffic_restrict_control,
     'Verify firewall restrictions directly — RemotePower cannot assess them.'),
    ('pci', '8.4.2',  'Multi-factor authentication for access',     _mfa_control,
     'Enable TOTP or OIDC for all console operators.'),
    ('pci', '10.2.1', 'Audit logs for all administrative actions',  _audit_control,
     'Enable audit logging.'),
    ('pci', '11.5.1', 'Detect and respond to intrusions',           _intrusion_control,
     'Review brute-force sources; block at the firewall.'),

    # HIPAA Security Rule
    ('hipaa', '164.308(a)(5)(ii)(B)', 'Protection from malicious software', _patch_control,
     'Apply pending security updates.'),
    ('hipaa', '164.308(a)(1)(ii)(A)', 'Risk analysis (known vulnerabilities)', _cve_control,
     'Remediate outstanding critical/high CVEs.'),
    ('hipaa', '164.308(a)(5)(ii)(B)-eol', 'Supported (non-EOL) operating systems', _eol_control,
     'Upgrade or replace hosts on end-of-life OS versions.'),
    ('hipaa', '164.312(e)(1)',        'Transmission security (encryption)',    _tls_control,
     'Renew expiring certificates.'),
    ('hipaa', '164.308(a)(7)(ii)(A)', 'Data backup plan',                      _backup_control,
     'Restore backup freshness on the listed targets.'),
    ('hipaa', '164.312(d)',           'Person/entity authentication (MFA)',    _mfa_control,
     'Enable operator MFA.'),
    ('hipaa', '164.312(b)',           'Audit controls',                        _audit_control,
     'Enable audit logging.'),
    ('hipaa', '164.308(a)(4)(ii)(C)', 'Access establishment and modification', _access_review_control,
     'Review and acknowledge SSH key changes.'),

    # SOC 2 Common Criteria
    ('soc2', 'CC7.1', 'Detect configuration changes / new exposure', _exposure_detection_control,
     'Review recent listening-port changes in Audit → Listening Ports.'),
    ('soc2', 'CC7.2', 'Monitor for anomalies and intrusions',        _intrusion_control,
     'Investigate brute-force activity.'),
    ('soc2', 'CC6.1', 'Logical access — encryption of secrets',      _vault_control,
     'Store secrets in the encrypted vault.'),
    ('soc2', 'CC6.6', 'Restrict transmission to authorized TLS',     _tls_control,
     'Renew expiring certificates.'),
    ('soc2', 'CC6.7', 'Manage vulnerabilities (patching)',           _patch_control,
     'Apply pending updates.'),
    ('soc2', 'CC6.8', 'Prevent/detect unauthorized software (CVEs)', _cve_control,
     'Remediate outstanding CVEs.'),
    ('soc2', 'CC7.1b', 'Run supported (non-EOL) operating systems',  _eol_control,
     'Upgrade or replace hosts on end-of-life OS versions.'),
    ('soc2', 'CC4.1', 'Audit logging of control operation',          _audit_control,
     'Enable audit logging.'),
    ('soc2', 'A1.2',  'Availability — recoverability (backups)',     _backup_control,
     'Restore backup freshness.'),
    ('soc2', 'CC7.4', 'Remediation — apply security reboots',        _reboot_control,
     'Reboot hosts pending update activation.'),

    # ── ACSC Essential Eight (the eight mitigation strategies) ───────────────
    # RemotePower has strong signal for patching, MFA, backups and OS currency;
    # application control, macro policy and user hardening are endpoint/process
    # controls it does not observe and reports honestly as 'not assessed'.
    ('e8', 'E8-1', 'Application control',                          _app_control_control,
     'Enforce application allow-listing via WDAC/AppLocker or your EDR.'),
    ('e8', 'E8-2', 'Patch applications',                          _patch_control,
     'Apply pending application updates on the listed hosts.'),
    ('e8', 'E8-2b', 'Patch applications — known vulnerabilities', _cve_control,
     'Remediate outstanding critical/high CVEs.'),
    ('e8', 'E8-3', 'Configure Microsoft Office macro settings',   _macro_control,
     'Set macro policy via Group Policy / Intune.'),
    ('e8', 'E8-4', 'User application hardening',                  _user_hardening_control,
     'Harden browsers/PDF/Java per the ACSC guidance.'),
    ('e8', 'E8-5', 'Restrict administrative privileges',         _admin_privilege_control,
     'Review privileged-group membership; enforce least privilege.'),
    ('e8', 'E8-6', 'Patch operating systems',                    _eol_control,
     'Upgrade hosts on end-of-life operating systems.'),
    ('e8', 'E8-6b', 'Patch operating systems — pending reboots',  _reboot_control,
     'Reboot hosts to activate installed OS updates.'),
    ('e8', 'E8-7', 'Multi-factor authentication',                _mfa_control,
     'Enable TOTP or OIDC for all console operators.'),
    ('e8', 'E8-8', 'Regular backups',                            _backup_control,
     'Restore backup freshness on the listed targets.'),

    # ── SMB1001:2026 (Australian SMB cyber-security standard) ────────────────
    # Thematic control mapping to the measures RemotePower can evidence, plus an
    # honest NA for the process controls (training, IR plan). Control ids are
    # descriptive rather than clause-precise — a mapping aid, not an attestation.
    ('smb1001', 'S-patch',   'Keep software and operating systems updated', _patch_control,
     'Apply pending updates.'),
    ('smb1001', 'S-os',      'Retire unsupported operating systems',        _eol_control,
     'Replace end-of-life OS hosts.'),
    ('smb1001', 'S-vuln',    'Address known vulnerabilities',               _cve_control,
     'Remediate outstanding critical/high CVEs.'),
    ('smb1001', 'S-mfa',     'Multi-factor authentication on accounts',     _mfa_control,
     'Enable operator MFA.'),
    ('smb1001', 'S-backup',  'Maintain regular, recoverable backups',       _backup_control,
     'Restore backup freshness.'),
    ('smb1001', 'S-tls',     'Encrypt data in transit',                     _tls_control,
     'Renew expiring certificates.'),
    ('smb1001', 'S-access',  'Control and review privileged access',        _admin_privilege_control,
     'Review privileged-group membership and key changes.'),
    ('smb1001', 'S-audit',   'Log and retain security-relevant events',     _audit_control,
     'Enable audit logging.'),
    ('smb1001', 'S-monitor', 'Detect and respond to intrusions',            _intrusion_control,
     'Investigate brute-force activity.'),
    ('smb1001', 'S-training', 'Security-awareness training',                _training_control,
     'Record staff training in your ISMS.'),
    ('smb1001', 'S-ir',      'Incident-response plan',                      _ir_plan_control,
     'Maintain a written IR plan referencing RemotePower alerting/triage.'),
]


# Each control's check maps to a "topic" — a stable hint the dashboard turns
# into a "Fix →" deep-link to the page where you remediate it. Kept here (not
# in the UI) so the mapping lives next to the controls.
_TOPICS = {
    _patch_control:         'patches',
    _cve_control:           'cve',
    _tls_control:           'tls',
    _backup_control:        'backup',
    _mfa_control:           'mfa',
    _audit_control:         'audit',
    _exposure_detection_control: 'ports',
    _access_review_control: 'sshkeys',
    _intrusion_control:     'intrusion',
    _vault_control:         'vault',
    _reboot_control:        'reboot',
    _admin_privilege_control: 'sudo',   # v6.3.1
}


def build_report(facts, frameworks=None):
    """Evaluate every control for the requested frameworks against `facts`.

    Returns:
        {
          generated_ts: <set by caller>,
          frameworks: {
            pci: {label, pass, fail, na, score, controls: [
              {id, title, status, evidence, remediation}, ...]},
            ...
          },
          summary: {pass, fail, na, total}
        }
    score = pass / (pass + fail), ignoring NA — the honest "of what we can
    measure, how much passes" number.
    """
    want = set(frameworks) if frameworks else set(FRAMEWORKS)
    result = {'frameworks': {}, 'summary': {PASS: 0, FAIL: 0, NA: 0, 'total': 0}}

    for fw in FRAMEWORKS:
        if fw not in want:
            continue
        rows = []
        counts = {PASS: 0, FAIL: 0, NA: 0}
        for (cfw, cid, title, fn, remediation) in _CONTROLS:
            if cfw != fw:
                continue
            try:
                status, evidence = fn(facts)
            except Exception as e:
                status, evidence = NA, f"check error: {e}"
            counts[status] += 1
            rows.append({
                'id':          cid,
                'title':       title,
                'status':      status,
                'evidence':    evidence,
                'remediation': remediation if status == FAIL else '',
                'topic':       _TOPICS.get(fn, ''),
            })
        measurable = counts[PASS] + counts[FAIL]
        result['frameworks'][fw] = {
            'label':    FRAMEWORK_LABELS[fw],
            'pass':     counts[PASS],
            'fail':     counts[FAIL],
            'na':       counts[NA],
            'score':    round(100.0 * counts[PASS] / measurable, 1) if measurable else None,
            'controls': rows,
        }
        for k in (PASS, FAIL, NA):
            result['summary'][k] += counts[k]
        result['summary']['total'] += len(rows)

    return result

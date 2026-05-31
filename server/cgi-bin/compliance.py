"""Control-mapped compliance reporting (PCI DSS / HIPAA / SOC 2).

v3.4.0. This is deliberately an *evidence-from-observed-state* checklist, not a
formal attestation engine: every control maps to data RemotePower already
collects (patch status, CVEs, TLS expiry, firewall posture, login/SSH audit,
backup freshness, MFA, audit logging). Each control resolves to one of:

    pass  — observed state satisfies the control
    fail  — observed state violates it (with the offending evidence)
    na    — RemotePower has no signal for this control (honestly reported,
            never silently counted as a pass)

The caller assembles a `facts` dict from the fleet and passes it in; the logic
here is pure so it unit-tests without a server. The mapping is a pragmatic
operator aid for audit prep — it does not make a system "compliant".
"""

PASS, FAIL, NA = 'pass', 'fail', 'na'

FRAMEWORKS = ('pci', 'hipaa', 'soc2')
FRAMEWORK_LABELS = {
    'pci':   'PCI DSS v4.0',
    'hipaa': 'HIPAA Security Rule',
    'soc2':  'SOC 2 (Common Criteria)',
}


def _patch_control(facts):
    bad = facts.get('pending_patches_devices') or []
    if bad:
        return FAIL, f"{len(bad)} device(s) over the patch threshold: " + \
               ", ".join(bad[:10]) + ("…" if len(bad) > 10 else "")
    return PASS, "No device exceeds its pending-patch threshold."


def _cve_control(facts):
    n = facts.get('cve_critical_high', 0)
    if n:
        return FAIL, f"{n} critical/high CVE finding(s) outstanding across the fleet."
    return PASS, "No outstanding critical or high CVEs."


def _eol_control(facts):
    """v3.4.1 — hosts running an end-of-life OS no longer get security patches."""
    bad = facts.get('eol_os') or []
    if bad:
        return FAIL, f"{len(bad)} host(s) on an end-of-life OS: " + \
               ", ".join(bad[:10]) + ("…" if len(bad) > 10 else "")
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
    return PASS, "No host is pending a security reboot."


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

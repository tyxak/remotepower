#!/usr/bin/env python3
"""
RemotePower SMTP notifier — v1.8.6

Sibling module imported by api.py. Sends email notifications for events
that the user has opted in to in the per-event toggle table.

Stdlib only. Three TLS modes:
  - 'starttls' (port 587, modern default — secure after upgrade)
  - 'tls'      (port 465, implicit TLS — the older "SMTPS" port)
  - 'plain'    (no TLS, port 25 — only safe to localhost or trusted relays)

Auth optional. If smtp_username is empty, no AUTH is attempted (useful
for localhost relays that allow anonymous submission from 127.0.0.1).

v3.0.3: the SMTP password may be supplied via the RP_SMTP_PASSWORD
environment variable instead of config.json. When set, the env var
takes precedence; the secret then lives in the systemd unit /
container env and stays out of the data directory (and out of the
backup export). Same pattern as RP_PROXMOX_TOKEN_SECRET (v2.3.1).
"""

import os
import smtplib
import ssl
import socket
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders as _email_encoders
from email.utils import formatdate, make_msgid


# Reasonable timeouts so a misconfigured server doesn't hang the CGI request
SMTP_CONNECT_TIMEOUT = 8

# v3.0.3: env-var override for the SMTP password. Set this in the systemd
# unit (`Environment=RP_SMTP_PASSWORD=...`) or the container env to keep
# the secret out of /var/lib/remotepower/config.json entirely.
ENV_SMTP_PASSWORD = 'RP_SMTP_PASSWORD'


def resolve_smtp_password(cfg: dict) -> tuple:
    """Return (password, from_env) — env wins over config.

    Returned password may be an empty string when neither source is set.
    `from_env` is True when the env var was non-empty (used by the UI
    so it can tell the operator the config field is being ignored).
    """
    env_pw = os.environ.get(ENV_SMTP_PASSWORD, '')
    if env_pw:
        return env_pw, True
    return (cfg.get('smtp_password') or ''), False


class SmtpError(Exception):
    """Wraps any SMTP failure with a human-readable message."""


def send_email(cfg: dict, recipients: list, subject: str, body: str, extra_headers: dict = None, html_body: str = None, attachments: list = None) -> dict:
    """
    Send a plain-text email. cfg is the SMTP config dict from /api/config.
    Returns {'ok': True} on success, raises SmtpError otherwise.

    Required cfg keys:
      smtp_host (str)
      smtp_port (int)
      smtp_tls  ('starttls' | 'tls' | 'plain')
      smtp_from (str — From: address)

    Optional:
      smtp_username  (str — empty = no AUTH)
      smtp_password  (str)
      smtp_helo_name (str — overrides socket.gethostname() for HELO)
    """
    if not recipients:
        raise SmtpError('no recipients')

    # Header-injection defense-in-depth: strip CR/LF from any value that lands in
    # an email header. _sanitize_str only .strip()s, and Python's email/smtplib
    # does not sanitize header values, so a newline in an operator-supplied
    # recipient or ticket subject could smuggle extra headers/body lines.
    recipients = [str(r).replace('\r', '').replace('\n', '').strip() for r in recipients]
    recipients = [r for r in recipients if r]
    if not recipients:
        raise SmtpError('no recipients')
    subject = str(subject).replace('\r', ' ').replace('\n', ' ')

    host  = (cfg.get('smtp_host') or '').strip()
    if not host:
        raise SmtpError('smtp_host is empty')
    try:
        port = int(cfg.get('smtp_port') or 0)
    except (TypeError, ValueError):
        raise SmtpError('smtp_port must be an integer')
    if not (1 <= port <= 65535):
        raise SmtpError('smtp_port must be 1..65535')

    tls_mode = (cfg.get('smtp_tls') or 'starttls').lower()
    if tls_mode not in ('starttls', 'tls', 'plain'):
        raise SmtpError(f'unsupported smtp_tls: {tls_mode!r}')

    sender = (cfg.get('smtp_from') or '').strip()
    if not sender or '@' not in sender:
        raise SmtpError('smtp_from must be a valid email address')

    username = (cfg.get('smtp_username') or '').strip()
    # v3.0.3: env-var first, config.json fallback. resolve_smtp_password()
    # returns ('', False) if nothing is set — the SMTP server may still
    # accept the connection anonymously (helpful for localhost relays).
    password, _from_env = resolve_smtp_password(cfg)
    helo     = (cfg.get('smtp_helo_name') or '').strip() or socket.gethostname()
    # Opt-out of TLS certificate verification — for a localhost / internal relay
    # whose cert isn't valid for the connect hostname (mirrors the ticket IMAP
    # verify_tls toggle). Default ON; only disable for trusted internal relays.
    verify_tls = cfg.get('smtp_verify_tls', True) is not False

    def _tls_ctx():
        c = ssl.create_default_context()
        if not verify_tls:
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
        return c

    # When an HTML body is supplied, send multipart/alternative (plain + HTML)
    # so clients that can render HTML show the rich version (e.g. an HTML
    # signature) and the rest still get readable plain text.
    if html_body:
        content = MIMEMultipart('alternative')
        content.attach(MIMEText(body, 'plain', _charset='utf-8'))
        content.attach(MIMEText(html_body, 'html', _charset='utf-8'))
    else:
        content = MIMEText(body, _charset='utf-8')
    # v5.4.1: file attachments (ticket replies) — wrap the text/alternative body in
    # a multipart/mixed and append each file as a base64 octet-stream part. Each
    # attachment is (filename, content_type, bytes); the filename is header-safe.
    if attachments:
        msg = MIMEMultipart('mixed')
        msg.attach(content)
        for att in attachments:
            try:
                fname, ctype, raw = att
            except (ValueError, TypeError):
                continue
            if not raw:
                continue
            maintype, _, subtype = (str(ctype or 'application/octet-stream')).partition('/')
            part = MIMEBase(maintype or 'application', subtype or 'octet-stream')
            part.set_payload(raw)
            _email_encoders.encode_base64(part)
            safe_fn = str(fname or 'attachment').replace('\r', '').replace('\n', '').replace('"', '')
            part.add_header('Content-Disposition', 'attachment', filename=safe_fn)
            msg.attach(part)
    else:
        msg = content
    msg['Subject'] = subject
    msg['From']    = sender
    msg['To']      = ', '.join(recipients)
    msg['Date']    = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid()
    # Optional extra headers (e.g. Auto-Submitted loop-guard, In-Reply-To/References
    # threading for the ticket system). Skip any that overwrite the core set.
    for _hk, _hv in (extra_headers or {}).items():
        if _hk and _hk not in msg and _hv is not None:
            msg[_hk] = str(_hv)

    try:
        if tls_mode == 'tls':
            client = smtplib.SMTP_SSL(host, port, timeout=SMTP_CONNECT_TIMEOUT,
                                        context=_tls_ctx(), local_hostname=helo)
        else:
            client = smtplib.SMTP(host, port, timeout=SMTP_CONNECT_TIMEOUT,
                                    local_hostname=helo)
            if tls_mode == 'starttls':
                client.ehlo()
                if not client.has_extn('starttls'):
                    client.quit()
                    raise SmtpError('server does not advertise STARTTLS')
                client.starttls(context=_tls_ctx())
                client.ehlo()  # re-EHLO required after STARTTLS

        if username:
            try:
                client.login(username, password)
            except smtplib.SMTPAuthenticationError as e:
                client.quit()
                raise SmtpError(f'auth failed: {e.smtp_code} {e.smtp_error.decode("utf-8", "ignore") if isinstance(e.smtp_error, bytes) else e.smtp_error}')

        # Use send_message so headers ride along correctly. The envelope
        # recipients come from the args; the message's To: just decorates.
        refused = client.send_message(msg, from_addr=sender, to_addrs=recipients)
        client.quit()

        if refused:
            # Partial failure — some recipients refused
            return {'ok': True, 'refused': refused}
        return {'ok': True}

    except SmtpError:
        raise
    except (smtplib.SMTPException, ssl.SSLError, socket.timeout, socket.gaierror, OSError) as e:
        raise SmtpError(f'{type(e).__name__}: {e}')


# v5.4.1 (H4): white-label accent name → hex (mirrors api.BRAND_ACCENTS).
_BRAND_ACCENT_HEX = {
    'blue': '#3b82f6', 'emerald': '#10b981', 'violet': '#8b5cf6',
    'amber': '#f59e0b', 'rose': '#f43f5e', 'cyan': '#06b6d4',
}


def brand_html(cfg: dict, title: str, plain_body: str) -> str:
    """v5.4.1 (H4): wrap a plain-text notification in a branded, email-client-safe
    HTML body. Inline styles are REQUIRED for email and are unrelated to the web
    app's CSP (this never renders in the app). Honours the white-label `brand_name`
    + `brand_accent`. Returns the HTML string (the plain text stays the alternative)."""
    import html as _h
    cfg = cfg or {}
    product = (str(cfg.get('brand_name') or 'RemotePower'))[:40]
    accent = _BRAND_ACCENT_HEX.get(str(cfg.get('brand_accent') or '').lower(), '#3b82f6')
    p = _h.escape(product)
    safe_title = _h.escape(str(title or product))
    safe_body = _h.escape(str(plain_body or '')).replace('\n', '<br>')
    return (
        '<div style="margin:0;padding:0;background:#f4f5f7;'
        'font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        'style="background:#f4f5f7;padding:24px 0"><tr><td align="center">'
        '<table role="presentation" width="600" cellpadding="0" cellspacing="0" '
        'style="max-width:600px;background:#ffffff;border:1px solid #e2e5ea;'
        'border-radius:10px;overflow:hidden">'
        f'<tr><td style="background:{accent};padding:14px 20px;color:#ffffff;'
        f'font-size:16px;font-weight:700">{p}</td></tr>'
        '<tr><td style="padding:20px;color:#16181d;font-size:14px;line-height:1.6">'
        f'<div style="font-size:15px;font-weight:600;margin-bottom:10px">{safe_title}</div>'
        f'<div>{safe_body}</div></td></tr>'
        '<tr><td style="padding:12px 20px;background:#f7f8fa;color:#8a929d;'
        'font-size:12px;border-top:1px solid #e2e5ea">'
        f'Sent by {p} · edit recipients in Settings &rarr; Notifications</td></tr>'
        '</table></td></tr></table></div>'
    )


def render_event_email(server_name: str, event: str, payload: dict, message: str) -> tuple:
    """
    Build (subject, body) for an event. Mirrors what the webhook would send,
    but in email form. `message` is the human-readable line that
    _webhook_message() produced — we reuse that to stay consistent.
    """
    subject = f'[{server_name}] {_event_subject_prefix(event)}: {message[:120]}'

    body_lines = [
        message,
        '',
        '— RemotePower notification —',
        f'Server:  {server_name}',
        f'Event:   {event}',
    ]
    if 'device_id' in payload:
        body_lines.append(f'Device:  {payload.get("name") or payload.get("device_name") or payload["device_id"]}')
    if 'unit' in payload:
        body_lines.append(f'Unit:    {payload["unit"]}')
    if 'pattern' in payload:
        body_lines.append(f'Pattern: {payload["pattern"]}')
    if 'count' in payload:
        body_lines.append(f'Matches: {payload["count"]}')
    if 'sample' in payload and isinstance(payload['sample'], list):
        body_lines.append('')
        body_lines.append('Sample lines:')
        for s in payload['sample'][:3]:
            body_lines.append(f'  {s}')
    body_lines.append('')
    body_lines.append('To unsubscribe, edit recipients in Settings → Notifications.')
    return subject, '\n'.join(body_lines)


def _event_subject_prefix(event: str) -> str:
    return {
        'device_offline':   'Device offline',
        'device_online':    'Device online',
        'monitor_down':     'Monitor down',
        'monitor_up':       'Monitor recovered',
        'patch_alert':      'Patches available',
        'cve_found':        'CVEs detected',
        'service_down':     'Service down',
        'service_up':       'Service recovered',
        'log_alert':        'Log alert',
        'command_queued':   'Command queued',
        'command_executed': 'Command executed',
        'test':             'Test email',
    }.get(event, 'Notification')

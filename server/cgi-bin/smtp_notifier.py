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
"""

import smtplib
import ssl
import socket
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid


# Reasonable timeouts so a misconfigured server doesn't hang the CGI request
SMTP_CONNECT_TIMEOUT = 8


class SmtpError(Exception):
    """Wraps any SMTP failure with a human-readable message."""


def send_email(cfg: dict, recipients: list, subject: str, body: str) -> dict:
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
    password = (cfg.get('smtp_password') or '')
    helo     = (cfg.get('smtp_helo_name') or '').strip() or socket.gethostname()

    msg = MIMEText(body, _charset='utf-8')
    msg['Subject'] = subject
    msg['From']    = sender
    msg['To']      = ', '.join(recipients)
    msg['Date']    = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid()

    try:
        if tls_mode == 'tls':
            ctx = ssl.create_default_context()
            client = smtplib.SMTP_SSL(host, port, timeout=SMTP_CONNECT_TIMEOUT,
                                        context=ctx, local_hostname=helo)
        else:
            client = smtplib.SMTP(host, port, timeout=SMTP_CONNECT_TIMEOUT,
                                    local_hostname=helo)
            if tls_mode == 'starttls':
                client.ehlo()
                if not client.has_extn('starttls'):
                    client.quit()
                    raise SmtpError('server does not advertise STARTTLS')
                ctx = ssl.create_default_context()
                client.starttls(context=ctx)
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
        body_lines.append(f'Device:  {payload.get("name", payload["device_id"])}')
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

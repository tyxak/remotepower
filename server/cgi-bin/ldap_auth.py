#!/usr/bin/env python3
"""
RemotePower LDAPS authenticator — v1.8.6

Sibling module imported by api.py. Adds LDAP/LDAPS as an authentication
source alongside local users.json. Uses ldap3 (pure Python — no native
deps) so deployment stays simple.

Auth flow:
  1. Server-side bind as a service account (admin DN + password from config)
  2. Search for the user by their `username` field, mapped via a configurable
     filter template (e.g. (uid={u}) or (sAMAccountName={u}))
  3. Re-bind as that user with their submitted password to verify creds
  4. Optionally check group membership (login allowed) and admin group
     (admin role granted)

Server-side config (all keys live under /api/config):
    ldap_enabled         bool
    ldap_url             str   e.g. ldaps://ldap.example.com:636
    ldap_bind_dn         str   service account that can search the user tree
    ldap_bind_password   str   service account password
    ldap_user_base       str   e.g. ou=Users,dc=example,dc=com
    ldap_user_filter     str   {u} = username, e.g. (uid={u})
    ldap_required_group  str   DN; empty = anyone with valid creds may log in
    ldap_admin_group     str   DN; empty = nobody auto-promoted to admin
    ldap_tls_verify      bool  default True; set False for self-signed CAs
    ldap_timeout         int   seconds, default 5

Three failure outcomes:
  - LDAP unreachable / config bad   → LdapTransientError, caller falls through to local auth
  - Search returns nothing          → LdapAuthDenied, caller treats as wrong-username
  - User bind rejected (bad pw)     → LdapAuthDenied, caller treats as wrong-password
"""


class LdapTransientError(Exception):
    """LDAP server unreachable, TLS failure, bad service account creds, etc.
    Caller should fall back to local auth and ideally surface a warning."""


class LdapAuthDenied(Exception):
    """User not found, wrong password, or required group membership missing."""


class LdapResult:
    def __init__(self, username, role, dn, full_name='', email=''):
        self.username = username
        self.role     = role        # 'admin' | 'viewer'
        self.dn       = dn
        self.full_name = full_name
        self.email     = email


def authenticate(cfg: dict, username: str, password: str) -> LdapResult:
    """
    Authenticate a user against LDAP. Returns LdapResult on success.

    Raises LdapTransientError if anything went wrong with the LDAP server itself
    (connection failure, service account auth failure, TLS error, etc.) — the
    caller should fall back to local auth in that case.

    Raises LdapAuthDenied if LDAP is reachable but the user doesn't exist or
    their password is wrong, or they're not in the required group.
    """
    try:
        from ldap3 import Server, Connection, Tls, ALL, SUBTREE
        from ldap3.core.exceptions import LDAPException, LDAPBindError
    except ImportError:
        raise LdapTransientError('ldap3 library not installed (pip3 install ldap3)')

    if not cfg.get('ldap_enabled'):
        raise LdapAuthDenied('ldap not enabled')

    url = (cfg.get('ldap_url') or '').strip()
    if not url:
        raise LdapTransientError('ldap_url is empty')

    bind_dn   = (cfg.get('ldap_bind_dn') or '').strip()
    bind_pw   = cfg.get('ldap_bind_password') or ''
    user_base = (cfg.get('ldap_user_base') or '').strip()
    user_filter_tpl = (cfg.get('ldap_user_filter') or '(uid={u})').strip()
    required_group  = (cfg.get('ldap_required_group') or '').strip()
    admin_group     = (cfg.get('ldap_admin_group') or '').strip()
    tls_verify      = bool(cfg.get('ldap_tls_verify', True))
    try:
        timeout = int(cfg.get('ldap_timeout') or 5)
    except (TypeError, ValueError):
        timeout = 5

    if not user_base:
        raise LdapTransientError('ldap_user_base is empty')

    # Build TLS context. ldap3 picks LDAPS automatically from the URL scheme.
    import ssl as _ssl
    tls = Tls(validate=_ssl.CERT_REQUIRED if tls_verify else _ssl.CERT_NONE)

    server = Server(url, use_ssl=url.lower().startswith('ldaps://'),
                     connect_timeout=timeout, get_info=ALL, tls=tls)

    # 1) Bind as the service account
    try:
        if bind_dn:
            svc = Connection(server, user=bind_dn, password=bind_pw,
                              auto_bind=True, receive_timeout=timeout)
        else:
            # Anonymous bind — works for some directories, not most
            svc = Connection(server, auto_bind=True, receive_timeout=timeout)
    except LDAPBindError as e:
        raise LdapTransientError(f'service account bind failed: {e}')
    except LDAPException as e:
        raise LdapTransientError(f'cannot connect to LDAP: {e}')
    except Exception as e:
        raise LdapTransientError(f'LDAP error: {type(e).__name__}: {e}')

    # 2) Search for the user — escape filter chars to prevent injection
    safe_username = _escape_ldap_filter(username)
    try:
        user_filter = user_filter_tpl.format(u=safe_username)
    except (KeyError, IndexError):
        svc.unbind()
        raise LdapTransientError('ldap_user_filter must contain {u} placeholder')

    try:
        svc.search(
            search_base=user_base,
            search_filter=user_filter,
            search_scope=SUBTREE,
            attributes=['cn', 'mail', 'displayName', 'memberOf'],
            time_limit=timeout,
        )
    except LDAPException as e:
        svc.unbind()
        raise LdapTransientError(f'search failed: {e}')

    if not svc.entries:
        svc.unbind()
        raise LdapAuthDenied('user not found')

    if len(svc.entries) > 1:
        svc.unbind()
        raise LdapTransientError(f'filter matches >1 user ({len(svc.entries)} entries) — tighten ldap_user_filter')

    entry = svc.entries[0]
    user_dn = entry.entry_dn
    full_name = ''
    email = ''
    member_of = []
    try:
        full_name = str(entry.displayName) if 'displayName' in entry else (str(entry.cn) if 'cn' in entry else '')
    except Exception:
        pass
    try:
        email = str(entry.mail) if 'mail' in entry else ''
    except Exception:
        pass
    try:
        member_of = [str(g) for g in entry.memberOf] if 'memberOf' in entry else []
    except Exception:
        pass

    svc.unbind()

    # 3) Re-bind as the user with their submitted password
    try:
        user_conn = Connection(server, user=user_dn, password=password,
                                auto_bind=True, receive_timeout=timeout)
        user_conn.unbind()
    except LDAPBindError:
        raise LdapAuthDenied('invalid password')
    except LDAPException as e:
        raise LdapTransientError(f'user bind error: {e}')

    # 4) Group membership checks
    member_of_lower = [g.lower() for g in member_of]

    if required_group and required_group.lower() not in member_of_lower:
        raise LdapAuthDenied(f'user not in required group')

    role = 'admin' if (admin_group and admin_group.lower() in member_of_lower) else 'viewer'

    return LdapResult(
        username=username,
        role=role,
        dn=user_dn,
        full_name=full_name,
        email=email,
    )


def test_connection(cfg: dict) -> dict:
    """
    Server-side bind sanity check used by the "Test connection" button in
    Settings. Doesn't try to authenticate any specific user — just confirms
    the URL, TLS, and service account work.

    Returns {'ok': True, 'detail': '...'} on success, {'ok': False, 'detail': '...'} on failure.
    """
    try:
        from ldap3 import Server, Connection, Tls, ALL
        from ldap3.core.exceptions import LDAPException
    except ImportError:
        return {'ok': False, 'detail': 'ldap3 library not installed (pip3 install ldap3)'}

    url = (cfg.get('ldap_url') or '').strip()
    if not url:
        return {'ok': False, 'detail': 'ldap_url is empty'}

    bind_dn = (cfg.get('ldap_bind_dn') or '').strip()
    bind_pw = cfg.get('ldap_bind_password') or ''
    tls_verify = bool(cfg.get('ldap_tls_verify', True))
    try:
        timeout = int(cfg.get('ldap_timeout') or 5)
    except (TypeError, ValueError):
        timeout = 5

    import ssl as _ssl
    tls = Tls(validate=_ssl.CERT_REQUIRED if tls_verify else _ssl.CERT_NONE)
    server = Server(url, use_ssl=url.lower().startswith('ldaps://'),
                     connect_timeout=timeout, get_info=ALL, tls=tls)
    try:
        if bind_dn:
            conn = Connection(server, user=bind_dn, password=bind_pw,
                                auto_bind=True, receive_timeout=timeout)
        else:
            conn = Connection(server, auto_bind=True, receive_timeout=timeout)
        # Probe server info
        info_lines = []
        if server.info:
            naming_contexts = getattr(server.info, 'naming_contexts', None) or []
            if naming_contexts:
                info_lines.append(f'naming contexts: {", ".join(str(n) for n in naming_contexts[:3])}')
        conn.unbind()
        detail = 'connected and bound successfully'
        if info_lines:
            detail += '; ' + '; '.join(info_lines)
        return {'ok': True, 'detail': detail}
    except LDAPException as e:
        return {'ok': False, 'detail': f'{type(e).__name__}: {e}'}
    except Exception as e:
        return {'ok': False, 'detail': f'{type(e).__name__}: {e}'}


def _escape_ldap_filter(s: str) -> str:
    """RFC 4515 — escape filter assertion value chars to prevent injection."""
    # Bytes outside printable ASCII would also need escaping but our usernames
    # are always ASCII in practice; if you need full Unicode support, switch
    # to ldap3.utils.conv.escape_filter_chars
    return (s.replace('\\', r'\5c')
             .replace('*',  r'\2a')
             .replace('(',  r'\28')
             .replace(')',  r'\29')
             .replace('\x00', r'\00'))

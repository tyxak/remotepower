"""RemotePower: what a Linux agent can see on its host.

The agent sends one structure with its system information (client/remotepower-agent.py: collect_capabilities): whether it runs as
root, whether it runs in a container and which host paths are mapped into it, which of the tools it uses are on the host, which logs
the threat sensor found and whether the agent can open them (paths only), the distribution, the init system and the agent's own
version and Python.

This module holds three things, all pure:

* `clean(raw)` keeps what the host may say about itself: a fixed set of keys, booleans and short strings, a fixed set of tool names
  and log kinds, at most `LOG_CAP` logs. Anything else is dropped, so nothing a host sends is free text on the server.
* `TOOLS`, `LOG_KINDS` and `NOTICES`: the fixed table that says, per tool, which feature needs it and how to install it with each
  package manager. The sentences in it are server-provided labels and are translated (tests/test_v702_server_labels_i18n.py reads
  this table); an install command is a command, not a sentence, and is not translated.
* `panel(caps, packages_manager)`: the answer the host drawer draws, with each tool as present, missing, not needed on this host or
  not available in a container, and a fix only for the ones that are missing: the install command for the host's package manager,
  or a short sentence where the table has no honest command.

The agent's list of tools is the first column of its CAPABILITY_TOOLS, and tests/test_agent_capabilities.py holds the two together.
"""
import re

import sanitize

LOG_CAP = 40
PATH_CAP = 200

# install command per package manager, then the package: "apt install smartmontools". A hint, never something the server runs.
# Arch is `-Syu`, not `-S`: the agent's package scan on Arch syncs the host's databases with `pacman -Sy` (client: get_patch_info), so
# a scanned host has databases newer than its packages, and `pacman -S <package>` on it is the partial upgrade Arch warns about.
INSTALL = {'apt': 'apt install', 'dnf': 'dnf install', 'zypper': 'zypper install', 'apk': 'apk add', 'pacman': 'pacman -Syu'}
MANAGERS = tuple(INSTALL)


def _pk(apt='', dnf='', zypper='', apk='', pacman=''):
    return {m: p for m, p in (('apt', apt), ('dnf', dnf), ('zypper', zypper), ('apk', apk), ('pacman', pacman)) if p}


def _all(name):
    return _pk(name, name, name, name, name)


# key: the name the agent reports the tool under.
# feature: the sentence that says what stops working without it (a translated, server-provided label).
# group: tools that do the same job; one of them present is enough, so a missing one is "not needed".
# optional: a feature most hosts do without, so a missing tool is listed but marked optional.
# applies: '' always, 'systemd' only on a host that runs systemd, or a package manager the tool belongs to.
# pkgs: the package that provides it, per package manager (blank where there is no honest one-line answer).
# note: a short sentence for a missing tool that has no install command on this host's package manager (a translated, server-provided
#       label); a tool with a command for every manager has none.
TOOLS = (
    {'key': 'ss', 'feature': 'Listening ports and connections', 'group': '', 'optional': False, 'applies': '',
     'pkgs': _pk('iproute2', 'iproute', 'iproute2', 'iproute2', 'iproute2')},
    {'key': 'smartctl', 'feature': 'Disk health (SMART)', 'group': '', 'optional': False, 'applies': '', 'pkgs': _all('smartmontools')},
    {'key': 'lsblk', 'feature': 'Disk layout and encryption', 'group': '', 'optional': False, 'applies': '',
     'pkgs': _pk('util-linux', 'util-linux', 'util-linux', 'lsblk', 'util-linux')},
    {'key': 'ufw', 'feature': 'Host firewall state (ufw)', 'group': 'firewall', 'optional': False, 'applies': '', 'pkgs': _all('ufw')},
    {'key': 'firewalld', 'feature': 'Host firewall state (firewalld)', 'group': 'firewall', 'optional': False, 'applies': '',
     'pkgs': _all('firewalld')},
    {'key': 'iptables', 'feature': 'Host firewall state (iptables)', 'group': 'firewall', 'optional': False, 'applies': '',
     'pkgs': _all('iptables')},
    {'key': 'nft', 'feature': 'Host firewall state (nftables)', 'group': 'firewall', 'optional': False, 'applies': '',
     'pkgs': _all('nftables')},
    {'key': 'journalctl', 'feature': 'Journal and service logs', 'group': '', 'optional': False, 'applies': 'systemd', 'pkgs': {},
     'note': 'Comes with systemd.'},
    {'key': 'systemctl', 'feature': 'Service and timer monitoring', 'group': '', 'optional': False, 'applies': 'systemd', 'pkgs': {},
     'note': 'Comes with systemd.'},
    {'key': 'docker', 'feature': 'Container inventory (Docker)', 'group': 'containers', 'optional': True, 'applies': '',
     'pkgs': _pk('docker.io', '', 'docker', 'docker', 'docker'),
     'note': "Its package differs by distribution: follow Docker's installation guide."},
    {'key': 'podman', 'feature': 'Container inventory (Podman)', 'group': 'containers', 'optional': True, 'applies': '',
     'pkgs': _all('podman')},
    {'key': 'apt', 'feature': 'Pending updates and package list (apt)', 'group': 'packages', 'optional': False, 'applies': 'apt', 'pkgs': {},
     'note': 'Comes with the base system of the distribution.'},
    {'key': 'dnf', 'feature': 'Pending updates and package list (dnf)', 'group': 'packages', 'optional': False, 'applies': 'dnf', 'pkgs': {},
     'note': 'Comes with the base system of the distribution.'},
    {'key': 'zypper', 'feature': 'Pending updates and package list (zypper)', 'group': 'packages', 'optional': False, 'applies': 'zypper',
     'pkgs': {}, 'note': 'Comes with the base system of the distribution.'},
    {'key': 'apk', 'feature': 'Pending updates and package list (apk)', 'group': 'packages', 'optional': False, 'applies': 'apk', 'pkgs': {},
     'note': 'Comes with the base system of the distribution.'},
    {'key': 'pacman', 'feature': 'Pending updates and package list (pacman)', 'group': 'packages', 'optional': False, 'applies': 'pacman',
     'pkgs': {}, 'note': 'Comes with the base system of the distribution.'},
    {'key': 'needrestart', 'feature': 'Services that need a restart after an update', 'group': '', 'optional': True, 'applies': 'apt',
     'pkgs': _pk('needrestart')},
    {'key': 'dmidecode', 'feature': 'Hardware inventory (DMI)', 'group': '', 'optional': False, 'applies': '', 'pkgs': _all('dmidecode')},
    {'key': 'sensors', 'feature': 'Temperature and fan sensors', 'group': '', 'optional': False, 'applies': '',
     'pkgs': _pk('lm-sensors', 'lm_sensors', 'sensors', 'lm-sensors', 'lm_sensors')},
    {'key': 'ipmitool', 'feature': 'Out-of-band sensors (IPMI)', 'group': '', 'optional': True, 'applies': '', 'pkgs': _all('ipmitool')},
    {'key': 'lynis', 'feature': 'Host hardening scan (Lynis)', 'group': '', 'optional': True, 'applies': '', 'pkgs': _all('lynis')},
    {'key': 'oscap', 'feature': 'Compliance scan (OpenSCAP)', 'group': '', 'optional': True, 'applies': '',
     'pkgs': _pk('', 'openscap-scanner', 'openscap-utils', '', ''),
     'note': 'Its package name differs by release: search your package manager for openscap.'},
    {'key': 'auditctl', 'feature': 'Audit rules check (auditd)', 'group': '', 'optional': True, 'applies': '',
     'pkgs': _pk('auditd', 'audit', 'audit', 'audit', 'audit')},
    {'key': 'fail2ban-client', 'feature': 'fail2ban bans', 'group': '', 'optional': True, 'applies': '', 'pkgs': _all('fail2ban')},
    {'key': 'cscli', 'feature': 'CrowdSec alerts', 'group': '', 'optional': True, 'applies': '', 'pkgs': {},
     'note': "Follow CrowdSec's own installation guide."},
)
TOOL_KEYS = tuple(t['key'] for t in TOOLS)

# The kinds of log the agent's threat sensor sorts what it finds into, as the agent names them.
LOG_KINDS = {
    'web': 'Web access log',
    'err': 'Web error log',
    'waf': 'WAF audit log',
    'f2b': 'fail2ban log',
    'fw': 'Firewall log',
    'ids': 'Intrusion detection alerts',
}

# The host paths a container reports as mapped (the agent's CAPABILITY_MAPPED).
MAPPED_PATHS = ('/etc', '/proc', '/sys', '/var/lib', '/var/log')

# Sentences the panel shows beside the list, by code. Server-provided labels, translated.
NOTICES = {
    'not_root': "The agent is not running as root, so tools that read the firewall, the disks and the audit rules report nothing.",
    'container': "The agent runs in a container. It reads the host's files from the paths mapped into it and cannot run the host's own tools.",
}

# What the panel calls a tool, by status, in the order the list shows them.
STATUS_ORDER = ('missing', 'unavailable', 'present', 'not_needed')

# \Z and not $: `$` also matches in front of a trailing newline, so "debian\n" was kept as sent and no longer matched the family table.
_WORD = re.compile(r'[a-z0-9._+-]{1,32}\Z')
_VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,31}\Z')
_CTRL = re.compile(r'[\x00-\x1f\x7f-\x9f\u2028\u2029]')

# os-release ID (and ID_LIKE) to the package manager of the family.
_FAMILY = {
    'debian': 'apt', 'ubuntu': 'apt', 'linuxmint': 'apt', 'raspbian': 'apt', 'devuan': 'apt', 'kali': 'apt', 'pop': 'apt',
    'fedora': 'dnf', 'rhel': 'dnf', 'centos': 'dnf', 'rocky': 'dnf', 'almalinux': 'dnf', 'ol': 'dnf', 'amzn': 'dnf',
    'suse': 'zypper', 'opensuse': 'zypper', 'opensuse-leap': 'zypper', 'opensuse-tumbleweed': 'zypper', 'sles': 'zypper',
    'alpine': 'apk',
    'arch': 'pacman', 'manjaro': 'pacman', 'endeavouros': 'pacman', 'cachyos': 'pacman',
}


def _short(value, limit):
    """A printable string of at most `limit` characters, or None when it is not text or is empty after cleaning."""
    if not isinstance(value, str):
        return None
    out = _CTRL.sub('', sanitize.strip_hidden(value)).strip()[:limit]
    return out or None


def clean(raw):
    """The record a host may keep about what it can see, or None when `raw` is not one.

    Only the keys below survive. A boolean must be a real boolean; a name is lower-case letters, digits and . _ + - (up to 32); a tool
    is one of TOOL_KEYS with a boolean; a log is one of LOG_KINDS with a path that starts with / (up to 200 printable characters) and a
    boolean; the mapped paths are from MAPPED_PATHS; at most LOG_CAP logs. A part that is wrong is left out and the rest is kept."""
    if not isinstance(raw, dict):
        return None
    out = {}
    for flag in ('root', 'container'):
        if isinstance(raw.get(flag), bool):
            out[flag] = raw[flag]
    for name in ('init', 'distro'):
        v = raw.get(name)
        if isinstance(v, str) and _WORD.match(v):
            out[name] = v
    like = raw.get('like')
    if isinstance(like, str):
        words = [w for w in like.split()[:4] if _WORD.match(w)]
        if words:
            out['like'] = ' '.join(words)
    mapped = raw.get('mapped')
    if isinstance(mapped, list):
        out['mapped'] = [p for p in MAPPED_PATHS if p in mapped]
    tools = raw.get('tools')
    if isinstance(tools, dict):
        out['tools'] = {k: tools[k] for k in TOOL_KEYS if isinstance(tools.get(k), bool)}
    logs = raw.get('logs')
    if isinstance(logs, list):
        rows = []
        for e in logs:
            if len(rows) >= LOG_CAP:
                break
            # The kind is looked up in a dict, which hashes it: a list or a dict from a JSON body would raise and the whole heartbeat
            # with it. Only text can be a kind.
            kind = e.get('kind') if isinstance(e, dict) else None
            if not isinstance(kind, str) or kind not in LOG_KINDS or not isinstance(e.get('readable'), bool):
                continue
            path = _short(e.get('path'), PATH_CAP)
            if path and path.startswith('/'):
                rows.append({'kind': e['kind'], 'path': path, 'readable': e['readable']})
        out['logs'] = rows
    agent = raw.get('agent')
    if isinstance(agent, dict):
        a = {k: agent[k] for k in ('version', 'python') if isinstance(agent.get(k), str) and _VERSION.match(agent[k])}
        if a:
            out['agent'] = a
    return out or None


def manager_of(sysinfo):
    """The package manager a host last reported with its pending updates ('' when it reported none): the way to tell a distribution this
    module has no row for, from a stored system information record of any shape."""
    si = sysinfo if isinstance(sysinfo, dict) else {}
    pkg = si.get('packages') if isinstance(si.get('packages'), dict) else {}
    return pkg.get('manager') if isinstance(pkg.get('manager'), str) else ''


def family(caps, packages_manager=''):
    """The package manager of this host's distribution ('apt', 'dnf', 'zypper', 'apk', 'pacman') or '' when it cannot be told: from the
    os-release id, then its id-like list, then the manager the host last reported with its pending updates."""
    caps = caps if isinstance(caps, dict) else {}
    distro = caps.get('distro')
    if isinstance(distro, str) and distro in _FAMILY:    # a record read from a store may hold anything; a list cannot be looked up
        return _FAMILY[distro]
    for word in str(caps.get('like') or '').split():
        if word in _FAMILY:
            return _FAMILY[word]
    return packages_manager if packages_manager in MANAGERS else ''


def _applies(tool, caps, fam):
    rule = tool['applies']
    if not rule:
        return True
    if rule == 'systemd':
        init = caps.get('init')
        return not init or init == 'systemd'
    return not fam or fam == rule


def panel(caps, packages_manager=''):
    """What the host drawer shows for one host, from the cleaned record (or None when the host has not reported one).

    Each tool the host reported has a status: `present`; `missing` (needed here and not there); `not_needed` (another distribution's
    package manager, a systemd tool on a host that does not run systemd, or one of several tools that do the same job while another
    is there); or `unavailable` (missing inside a container, where nothing can be installed into the agent). Only a missing tool has a
    hint, the install command for this host's package manager, and only where the table has an honest one; where it has none, the
    row carries the tool's `note` instead (a sentence, or blank)."""
    caps = clean(caps) if caps is not None else None
    if not caps:
        return {'reported': False}
    tools = caps.get('tools') or {}
    fam = family(caps, packages_manager)
    container = caps.get('container') is True
    present_groups = {t['group'] for t in TOOLS if t['group'] and tools.get(t['key']) is True}
    rows = []
    for t in TOOLS:
        if t['key'] not in tools:
            continue
        if tools[t['key']]:
            status = 'present'
        elif not _applies(t, caps, fam) or (t['group'] and t['group'] in present_groups):
            status = 'not_needed'
        elif container:
            status = 'unavailable'
        else:
            status = 'missing'
        pkg = t['pkgs'].get(fam) if fam else None
        hint = f'{INSTALL[fam]} {pkg}' if status == 'missing' and pkg else ''
        rows.append({'name': t['key'], 'status': status, 'feature': t['feature'], 'optional': bool(t['optional']), 'hint': hint,
                     'note': t.get('note', '') if status == 'missing' and not hint else ''})
    rows.sort(key=lambda r: (STATUS_ORDER.index(r['status']), r['optional']))
    notices = []
    if caps.get('root') is False:
        notices.append(NOTICES['not_root'])
    if container:
        notices.append(NOTICES['container'])
    return {
        'reported': True,
        'agent': caps.get('agent') or {},
        'root': caps.get('root'),
        'container': caps.get('container'),
        'init': caps.get('init', ''),
        'distro': caps.get('distro', ''),
        'family': fam,
        'mapped': caps.get('mapped') or [],
        'tools': rows,
        'missing': sum(1 for r in rows if r['status'] == 'missing'),
        'unavailable': sum(1 for r in rows if r['status'] == 'unavailable'),
        'logs': [{'kind': e['kind'], 'label': LOG_KINDS[e['kind']], 'path': e['path'], 'readable': e['readable']}
                 for e in caps.get('logs') or []],
        'notices': notices,
    }

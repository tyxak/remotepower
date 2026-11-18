"""Windows events in the form wevtutil prints them (`wevtutil qe <log> /f:xml`), for the tests of the event log rules.

Each sample carries the fields the event has on a real host (the ones the provider documents for that event id), so the parser is shown the
noise around the fields it reads as well as the fields themselves. The values are made up; the names, the order and the shapes (a SID, a hex
status, an IP address, a task definition escaped inside a Data element, a 1102 that keeps its fields in UserData) are Windows's.

Nothing here runs on Windows: these are what a Windows host would print, written by hand from the documented schemas.

An event is stamped with the time it is built, as a real one is, because the server drops a log line that is older than its ring keeps (six hours): a sample with a stamp
written into this file turned a test that goes through the log handler red six hours after the day the file was written. A test that is about the stamp itself passes
`ts=FIXED_TS` and compares with `FIXED_TS_MS`.
"""
import time
from xml.sax.saxutils import escape

FIXED_TS = '2026-11-18T00:23:45.1234567Z'
FIXED_TS_MS = 1794961425000        # what the agent reads FIXED_TS as: milliseconds since the epoch, UTC

NS = 'http://schemas.microsoft.com/win/2004/08/events/event'

PROVIDERS = {
    'Security': ('Microsoft-Windows-Security-Auditing', '{54849625-5478-4994-a5ba-3e3b0328c30d}'),
    'System-SCM': ('Service Control Manager', '{555908d1-a6d7-4695-8e1e-26931d2012f4}'),
    'Eventlog': ('Microsoft-Windows-Eventlog', '{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}'),
}


def event_xml(eid, rid, channel, provider, data=None, userdata=None, ts=None, qualifiers=None,
              computer='DESK01.corp.example.com', level=0):
    """One <Event> element as wevtutil prints it: no XML declaration, single-quoted attributes, one line. `ts` is the stamp, now when it is not given."""
    name, guid = provider
    if ts is None:
        ts = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(time.time())) + '.1234567Z'     # time.time(), not the C clock: a test that moves the clock moves the samples with it
    q = " Qualifiers='%s'" % qualifiers if qualifiers is not None else ''
    out = ["<Event xmlns='%s'><System><Provider Name='%s' Guid='%s'/><EventID%s>%d</EventID><Version>0</Version><Level>%d</Level>"
           "<Task>12546</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='%s'/>"
           "<EventRecordID>%d</EventRecordID><Correlation/><Execution ProcessID='632' ThreadID='4928'/><Channel>%s</Channel>"
           "<Computer>%s</Computer><Security/></System>" % (NS, name, guid, q, eid, level, ts, rid, channel, computer)]
    if data is not None:
        out.append('<EventData>')
        for k, v in data:
            if k is None:
                out.append('<Data>%s</Data>' % escape(v))
            else:
                out.append("<Data Name='%s'>%s</Data>" % (k, escape(v)))
        out.append('</EventData>')
    if userdata is not None:
        out.append("<UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>")
        for k, v in userdata:
            out.append('<%s>%s</%s>' % (k, escape(v), k))
        out.append('</LogFileCleared></UserData>')
    out.append('</Event>')
    return ''.join(out)


SID_USER = 'S-1-5-21-3623811015-3361044348-30300820-1013'
TASK_DEFINITION = (
    '<?xml version="1.0" encoding="UTF-16"?>\n'
    '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
    '<RegistrationInfo><Date>2026-11-18T00:23:45.0000000</Date><Author>CORP\\bob</Author></RegistrationInfo>'
    '<Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>'
    '<Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>'
    '<Settings><Enabled>true</Enabled></Settings>'
    '<Actions Context="Author"><Exec><Command>C:\\Users\\bob\\AppData\\Local\\Temp\\upd.exe</Command><Arguments>-k run</Arguments></Exec></Actions>'
    '</Task>')


def failed_logon(rid=1048576, user='bob', domain='CORP', workstation='ATTACKBOX', ip='203.0.113.50', logon_type='3',
                 status='0xc000006d', substatus='0xc000006a', **kw):
    return event_xml(4625, rid, 'Security', PROVIDERS['Security'], [
        ('SubjectUserSid', 'S-1-0-0'), ('SubjectUserName', '-'), ('SubjectDomainName', '-'), ('SubjectLogonId', '0x0'),
        ('TargetUserSid', 'S-1-0-0'), ('TargetUserName', user), ('TargetDomainName', domain), ('Status', status),
        ('FailureReason', '%%2313'), ('SubStatus', substatus), ('LogonType', logon_type), ('LogonProcessName', 'NtLmSsp '),
        ('AuthenticationPackageName', 'NTLM'), ('WorkstationName', workstation), ('TransmittedServices', '-'),
        ('LmPackageName', '-'), ('KeyLength', '0'), ('ProcessId', '0x0'), ('ProcessName', '-'), ('IpAddress', ip), ('IpPort', '49822')], **kw)


def account_locked_out(rid=2001, user='bob', caller='ATTACKBOX', **kw):
    return event_xml(4740, rid, 'Security', PROVIDERS['Security'], [
        ('SubjectUserSid', 'S-1-5-18'), ('SubjectUserName', 'DC01$'), ('SubjectDomainName', 'CORP'), ('SubjectLogonId', '0x3e7'),
        ('TargetUserName', user), ('TargetDomainName', caller), ('TargetSid', SID_USER)], **kw)


def service_installed_system(rid=3001, name='Updater', image=r'C:\Users\bob\AppData\Local\Temp\upd.exe -k run', **kw):
    return event_xml(7045, rid, 'System', PROVIDERS['System-SCM'], [
        ('ServiceName', name), ('ImagePath', image), ('ServiceType', 'user mode service'), ('StartType', 'auto start'),
        ('AccountName', 'LocalSystem')], qualifiers='16384', **kw)


def service_installed_security(rid=4001, name='Updater', image=r'C:\Windows\Temp\upd.exe', **kw):
    return event_xml(4697, rid, 'Security', PROVIDERS['Security'], [
        ('SubjectUserSid', 'S-1-5-21-3623811015-3361044348-30300820-500'), ('SubjectUserName', 'Administrator'), ('SubjectDomainName', 'DESK01'),
        ('SubjectLogonId', '0x1a2b3c'), ('ServiceName', name), ('ServiceFileName', image), ('ServiceType', '0x10'),
        ('ServiceStartType', '2'), ('ServiceAccount', 'LocalSystem')], **kw)


def scheduled_task_created(rid=5001, name='\\Updater', by='bob', **kw):
    return event_xml(4698, rid, 'Security', PROVIDERS['Security'], [
        ('SubjectUserSid', SID_USER), ('SubjectUserName', by), ('SubjectDomainName', 'CORP'), ('SubjectLogonId', '0x5b3c2d'),
        ('TaskName', name), ('TaskContent', TASK_DEFINITION), ('ClientProcessStartKey', '2814749767106561'), ('ClientProcessId', '5128'),
        ('ParentProcessId', '1036'), ('RpcCallClientLocality', '0'), ('FQDN', 'DESK01.corp.example.com')], **kw)


def user_created(rid=6001, user='svc-backup2', domain='DESK01', by='Administrator', **kw):
    return event_xml(4720, rid, 'Security', PROVIDERS['Security'], [
        ('TargetUserName', user), ('TargetDomainName', domain), ('TargetSid', 'S-1-5-21-3623811015-3361044348-30300820-1014'),
        ('SubjectUserSid', 'S-1-5-21-3623811015-3361044348-30300820-500'), ('SubjectUserName', by), ('SubjectDomainName', 'DESK01'),
        ('SubjectLogonId', '0x1a2b3c'), ('PrivilegeList', '-'), ('SamAccountName', user), ('DisplayName', '<value not set>'),
        ('UserPrincipalName', '-'), ('HomeDirectory', '<value not set>'), ('HomePath', '<value not set>'), ('ScriptPath', '<value not set>'),
        ('ProfilePath', '<value not set>'), ('UserWorkstations', '<value not set>'), ('PasswordLastSet', '<never>'),
        ('AccountExpires', '<never>'), ('PrimaryGroupId', '513'), ('AllowedToDelegateTo', '-'), ('OldUacValue', '0x0'),
        ('NewUacValue', '0x15'), ('UserAccountControl', '%%2080 %%2082 %%2084'), ('UserParameters', '<value not set>'), ('SidHistory', '-'),
        ('LogonHours', '<value not set>')], **kw)


def member_added(rid=7001, group='Administrators', group_sid='S-1-5-32-544', member='-', member_sid=SID_USER, by='Administrator', **kw):
    return event_xml(4732, rid, 'Security', PROVIDERS['Security'], [
        ('MemberName', member), ('MemberSid', member_sid), ('TargetUserName', group), ('TargetDomainName', 'Builtin'),
        ('TargetSid', group_sid), ('SubjectUserSid', 'S-1-5-21-3623811015-3361044348-30300820-500'), ('SubjectUserName', by),
        ('SubjectDomainName', 'DESK01'), ('SubjectLogonId', '0x1a2b3c'), ('PrivilegeList', '-')], **kw)


def audit_log_cleared(rid=8001, by='Administrator', domain='DESK01', **kw):
    return event_xml(1102, rid, 'Security', PROVIDERS['Eventlog'], None, [
        ('SubjectUserSid', 'S-1-5-21-3623811015-3361044348-30300820-500'), ('SubjectUserName', by), ('SubjectDomainName', domain),
        ('SubjectLogonId', '0x1a2b3c')], level=4, **kw)


# the eight, in the order of the brief: (builder, event id, channel)
EIGHT = (
    (failed_logon, 4625, 'Security'),
    (account_locked_out, 4740, 'Security'),
    (service_installed_system, 7045, 'System'),
    (service_installed_security, 4697, 'Security'),
    (scheduled_task_created, 4698, 'Security'),
    (user_created, 4720, 'Security'),
    (member_added, 4732, 'Security'),
    (audit_log_cleared, 1102, 'Security'),
)

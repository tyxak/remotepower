# Detections

**Detections** are rules that look at what a host does, not at what a threat is called. A signature exists only after somebody has seen the attack. A shell that holds a connection to the Internet, a database that calls an address it never used, or a new open port that a stranger is already using shows the same way whatever exploit started it, so these rules can catch an attack nobody has named yet. They also look again at old connections when Threat Intel learns something new.

They collect nothing of their own. Every five minutes a sweep reads three things the server already has, and raises an alert for each finding:

- the **Traffic** samples of your Linux hosts (the connections each one holds and the addresses it has used);
- the **activity log** (a new SSH key, a new open port, a burst of failed logins, a login from a new address);
- what **Threat Intel** knows about an address.

## Turn it on

Detections is off by default, because it raises alerts.

1. Open **Settings > Advanced > Optional modules** and tick **Detections**. Tick **Traffic** too: most rules read it.
2. Save. The first sweep runs within five minutes.
3. Open **Threat Intel > Detections**.

Untick it to stop. The sweep stops, the tab disappears and the Detections API answers 404. Findings already stored stay until you turn the module on again or delete the host.

## The rules

| Rule | What it finds | Severity |
|---|---|---|
| A shell or network tool talks to the Internet | `bash`, `sh`, `dash`, `zsh` or another shell holds an established connection of its own to a public address, or `nc`, `ncat`, `socat` or `telnet` does. That is how a reverse shell looks. | High for a shell, medium for a network tool |
| A database or SSH server connects to a new address | A database, a cache, mail storage or `sshd` calls a public address the host never used before, after the host's first hour. | Medium |
| A host calls an address Threat Intel marks as bad | A host is connected to an address that scores 75 or more at Threat Intel, or that attacked you in the last 14 days. The rule also looks again at every address the host called earlier, so an address that turns bad later is found too. | High while connected, medium for an earlier call |
| A way back in, then a new destination | A new SSH key, an account with no password or a changed firewall, followed within two hours by the host's first connection to a new public address. | High |
| Password guessing, then a login from a new address | A burst of failed logins, followed within an hour by a first login from a new address. | High, critical when the address that guessed is the address that got in |
| A new open port is already used from the Internet | A port that opened in the last six hours already has a public address connected to it. | Medium |

How the rules decide:

- **Called** means the host started the connection. A server is visited by scanners all day, and the brute-force alerts already name them, so a visitor is not counted as a call.
- **New** has the same meaning as on the Traffic tab: the first hour a host reports is its baseline, and after that an address the host first used in the last 24 hours is new.
- **Public** leaves out your local network, link-local, loopback and multicast addresses.
- Programs that fetch updates and the time (`apt`, `dnf`, `pacman`, `chronyd` and a few more) do not count as a new destination after a way back in: they reach a new mirror most days.
- Web servers, PHP, DNS and FTP are not in the second rule. They call new addresses every week (certificate checks, upstream calls, recursion).

## What you see

- **Summary.** The number of findings, how many are critical, high and medium, and when the last sweep ran.
- **Findings.** One line for each finding of the last sweep: severity, host, rule, what was found, the address and when the alert was raised. A host shows its five worst. A finding stays listed while it is true, and drops off when it is not. Select a host to open its page. Type in the box to filter, and select a column heading to sort.
- **Rules.** Each rule with what it means, what it reads and its settings.

A host you marked as unmonitored shows its findings, flagged, and raises no alert.

## Where else you see them

- **The host's page.** The host drawer has a **Detections** section with that host's findings, when it has any.
- **Data Explorer.** The `detections` entity has one row for each finding: [data-explorer.md](data-explorer.md).
- **Fleet Query.** The **Detection** field finds the hosts with a finding whose rule, sentence, address, program or severity contains your text: [fleet-query.md](fleet-query.md).
- **Risk score.** A critical finding scores twice and a high one once, capped. A medium one does not score: [risk.md](risk.md).
- **Compliance.** A detection in the last 30 days fails the intrusion control, with the hosts named in its evidence.
- **Fleet report.** The Threats section counts the hosts with a finding and the findings by severity.
- **AI advisors.** They are told when a host has a serious finding.

All of them read only while the module is on, and only for the hosts you can see.

## Alerts

Each finding raises one **Detection** alert, in the severity the rule found, with the host, the rule, the address, the port and the program. It works like any other alert: acknowledge it, resolve it, mute it, route it to a channel or put the host in maintenance. Under **Settings > Notifications** the event is listed as a detection and sits under its own kind, **Detections**.

A finding is raised once, and again after a repeat interval while it is still true: six hours for a connection, a day for a new destination, a week for an address that turned bad later. A way back in or a login raises once. The same host, rule, address, port and program is one alert, not a new one each time. A host raises at most five alerts in one sweep and the whole fleet at most a hundred, the worst first; the rest follow with the next sweep, so one address that turns bad cannot flood your inbox.

## Change a rule

Switch a rule off, or change its limits:

| Rule | Setting | Default | Range |
|---|---|---|---|
| A host calls an address Threat Intel marks as bad | Lowest score that counts | 75 | 1 to 100 |
| A host calls an address Threat Intel marks as bad | Days an attack counts | 14 | 1 to 90 |
| A way back in, then a new destination | Hours between the two | 2 | 1 to 24 |
| Password guessing, then a login from a new address | Hours between the two | 1 | 1 to 24 |
| A new open port is already used from the Internet | Hours after the port opened | 6 | 1 to 48 |

Only the platform operator changes the rules, because they belong to the installation, not to an organisation. Everyone else reads them.

## What it does not do

- It reads the connection table once a minute. A connection that opens and closes between two samples is not seen.
- The rules that read Traffic apply to Linux hosts. For a Windows or macOS host only the rules that read the activity log can find something.
- It does not look for a rhythm in connections (beaconing), for a sudden change in volume, or for a chain of steps across hosts.
- It does not block anything. It tells you.

## API

| Request | Answer |
|---|---|
| `GET /api/detections` | The rules with their settings, the findings of the last sweep for the hosts you can see, and the counts. Any signed-in role. |
| `POST /api/detections/rules` | Body `{"rules": {"<rule id>": {"enabled": false, "min_score": 90}}}`. The platform operator only. A body with an unknown rule or setting, or a value out of range, is refused whole. |

Both answer 404 while the module is off. The rule ids are `interpreter_egress`, `service_new_destination`, `known_bad_contact`, `persistence_then_egress`, `bruteforce_then_login` and `exposed_port_in_use`.

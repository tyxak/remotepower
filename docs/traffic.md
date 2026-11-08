# Traffic

The Traffic tab on the **Network** page shows which addresses your Linux hosts talk to, which programs open those connections, and how much each connection moved. It works from each host's connection table. It captures no packets and reads none of the data the connections carry.

## Turn it on

Traffic is off by default, because it records the remote addresses and program names your hosts connect to.

1. Open **Settings > Advanced > Optional modules** and tick **Traffic**.
2. Save. Linux agents pick the change up with their next report and start sampling, once a minute by default.
3. Open **Network > Traffic**. The first rows appear one sample interval later.

Untick it to stop. The agents stop sampling, the tab disappears and the Traffic API answers 404. Rows already stored stay where they are until you turn the module on again or delete the host.

## What you see

- **Summary.** How many hosts report, the total sent and received per second, and the number of connections.
- **Remote addresses.** The busiest addresses across the hosts you can see: which hosts talk to each one, on which ports, how many connections, and how much went each way. A public address shows its country and organisation when you have set up the GeoLite2 files (**Settings > Security**), and a reputation score when Threat Intel has a verdict for it.
- **Programs.** Which programs moved the most.
- **Ports and services.** Each port by direction, named when it is a well-known service.
- **Hosts.** One line per host with its state and current rate. Select a host to open its own page.
- **Watch list.** See below.

A host's own page has a **Traffic** section with the same rows for that host and a chart of the last 24 hours.

Type in the search box to filter rows by address, host, program, service or country. **Export CSV** saves the table you are looking at.

A host is **reporting** (it sent a sample recently), **stale** (it stopped), **waiting** (no sample yet) or **unsupported** (not a Linux host).

## New addresses

The first hour after a host starts reporting is its baseline, and nothing in it counts as new. After that, a public address the host has not used before is marked **new** for 24 hours. Use it to spot a host that suddenly talks to somewhere it never did.

## Watch list

Add the addresses, networks, ports and program names you want to notice:

| Kind | Value | Example |
|---|---|---|
| Address | one IPv4 or IPv6 address | `203.0.113.7` |
| Network | a CIDR range | `203.0.113.0/24` |
| Port | a service port | `23` |
| Program | a program name | `nc` |

A row that matches an entry is marked, listed under **Watch list matches** and raises a **Watched connection** alert: the first time a host matches an entry, and again after six hours if the connection is still there. Give an entry a label to remember why it is there.

The watch list belongs to the whole installation, so the platform operator edits it. On an installation with several organisations, everyone sees the matches on their own hosts, and the labels stay with the operator.

## How it measures

Each Linux agent reads its established TCP connections with `ss` and takes the kernel's own byte counters for each one. A sample is what changed since the last reading, added up for each direction, remote address, service port and program. The default interval is 60 seconds. You can set 30 to 3,600 next to the watch list.

Some limits to know about:

- Only Linux agents sample. Windows and macOS hosts show as unsupported.
- Only TCP has a volume. UDP is not counted.
- A connection that opens and closes between two samples is not seen.
- Program names need the agent to run as root, which the standard install does.
- Each host keeps its 100 busiest rows. The rest are added up as **other**.
- Loopback connections and a host's connections to itself are left out.
- A sample lost to a network error is not sent again. The next one covers the next interval.
- The agent needs the `ss` tool (package `iproute2`). Without it the host shows a message instead of rows.

## Who sees what

You see the hosts your role and organisation allow, the same as everywhere else. The watch list and the interval belong to the installation: anyone signed in can read the interval and how many entries there are, and only the platform operator edits them.

## API

| Request | What it returns |
|---|---|
| `GET /api/devices/<id>/traffic` | One host: rows, the 24-hour chart and the watch matches. |
| `GET /api/traffic/fleet` | The hosts you can see, added up. |
| `GET /api/traffic/config` | The interval and the watch list. |
| `POST /api/traffic/config` | Save the interval and the watch list (platform operator). |

While the module is off, `/api/traffic/...` and the host route answer 404 with `module_disabled: traffic`.

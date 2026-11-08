# Traffic

The Traffic tab on the **Network** page shows which addresses your Linux hosts talk to, which programs open those connections, and how much each connection moved. It works from each host's connection table. It captures no packets and reads none of the data the connections carry.

## Turn it on

Traffic is off by default, because it records the remote addresses and program names your hosts connect to.

1. Open **Settings > Advanced > Optional modules** and tick **Traffic**.
2. Save. Linux agents pick the change up with their next report and start sampling, once a minute by default.
3. Open **Network > Traffic**. The first rows appear one sample interval later.

Untick it to stop. The agents stop sampling, the tab disappears and the Traffic API answers 404. The Data Explorer and Fleet Query stop answering for it too. Rows already stored stay where they are until you turn the module on again or delete the host.

## What you see

- **Summary.** How many hosts are sampling, the total sent and received per second, the number of connections and the sampling interval.
- **Remote addresses.** The busiest addresses across the hosts you can see: which hosts talk to each one, on which ports, how many connections, and how much went each way. A public address shows its country and organisation when you have set up the GeoLite2 files (**Settings > Security**). Marks next to an address: **Local network**, **New**, **Watch list** and a Threat Intel **Score** when Threat Intel has a verdict for it. The **Show** menu narrows the table to public addresses, the local network, new addresses or watch list matches.
- **Programs.** Which programs moved the most. A connection the kernel holds itself, such as a network mount, has no program and shows as **Unknown**.
- **Ports and services.** Each port by direction, with the service name when it is a well-known one.
- **Hosts.** One line per host with its state and current rate. Select a host to open its own page.
- **Watch list.** See below.

A host's own page has a **Traffic** section with the same rows for that host and a chart of the last 24 hours, one for what it sent and one for what it received.

Type in the box above a table to filter it, and select a column heading to sort. The download button under a table saves the rows you are looking at as CSV.

A host line says **Sampling** (it sent a sample recently), **Out of date** (it stopped), **Waiting** (no sample yet), **Not supported** (not a Linux host) or **Cannot read** (see below).

## New addresses

The first hour after a host starts sampling is its baseline, and nothing in it counts as new. After that, a public address the host has not used before is marked **New** for 24 hours. Use it to spot a host that suddenly talks to somewhere it never did.

## Watch list

Add the addresses, networks, ports and program names you want to notice:

| Kind | Value | Example |
|---|---|---|
| Address | one IPv4 or IPv6 address | `203.0.113.7` |
| Network | a CIDR range | `203.0.113.0/24` |
| Port | a service port | `23` |
| Program | a program name | `nc` |

A connection that matches an entry is marked, listed under **Watch list** and raises a **Watched connection** alert: the first time a host matches an entry, and again after six hours if the connection is still there. At most ten alerts go out for one report; the rest follow with the next ones. Give an entry a note to remember why it is there.

The watch list and the sampling interval belong to the whole installation, so the platform operator edits them, in the **Watch list** card (add entries, then **Save**; the interval is next to the button). On an installation with several organisations, everyone sees the matches on their own hosts, and the entries, their notes and the alert text that names them stay with the operator.

## When a host cannot be read

A host that cannot be sampled says why instead of showing an empty table:

- **The agent cannot read connections: the `ss` tool is not installed.** Install `iproute2` (on Alpine, `iproute2-ss`).
- **The agent could not read the connection table.** The tool ran and failed. The next sample tries again.
- **This kernel does not report bytes for each connection.** You still see the connections, without a volume.

## Ask about it elsewhere

- **Data Explorer.** The `traffic` entity has one row for each host, direction, remote address, port and program of each host's last sample: `device_name`, `direction`, `address`, `scope`, `port`, `service`, `program`, `connections`, `sent`, `received`, `new`, `watched`, `state` and `sampled_at`. `watched` says whether any entry matches, never which one.
- **Fleet Query.** **Talks to** matches the hosts that have a connection to an address that contains your text, to that port or service name, or by a program that contains it, for example `https`, `10.0.2.` or `nginx`.

Both show the hosts you can see, like everything else, and neither answers while the module is off.

## How it measures

Each Linux agent reads its established TCP connections with `ss` and takes the kernel's own byte counters for each one. A sample is what changed since the last reading, added up for each direction, remote address, service port and program. The default interval is 60 seconds. You can set 30 to 3,600 in the **Watch list** card.

Some limits to know about:

- Only Linux agents sample. Windows and macOS hosts show as **Not supported**.
- Only TCP has a volume. UDP is not counted.
- A connection that opens and closes between two samples is not seen.
- Program names need the agent to run as root, which the standard install does.
- Each host keeps its 100 busiest rows. The rest are added up as one line.
- Loopback connections and a host's connections to itself are left out.
- A sample lost to a network error is not sent again. The next one covers the next interval.
- A host that polls less often than it samples sends a sample with each report, and is called **Out of date** only after three of its own intervals.
- If your installation keeps its data in JSON files, each report rewrites the whole Traffic file: about 80 milliseconds with 50 hosts and 340 with 200. SQLite and PostgreSQL write one row, in under a millisecond. With more than 100 hosts on JSON files, switch to one of them or raise the interval in the **Watch list** card.

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

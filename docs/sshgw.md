# SSH gateway

The SSH gateway lets you reach your servers with the SSH client you already
use: `ssh`, `scp`, `rsync`, VS Code Remote, Ansible. You don't need to open a
port on any server, run a VPN or write a firewall rule.

```
ssh root@web01.rp
```

## How it works

```
your laptop ──SSH──> gateway (port 2222) ──WebSocket──> agent on web01 ──> web01's sshd
```

- Each server you allow runs the RemotePower agent. The agent opens **one
  outbound connection** to the gateway and keeps it open. Nothing on the server
  listens on the network for this.
- You log in to the gateway with an SSH key you registered in RemotePower. The
  gateway never gives you a shell. It forwards your connection to the server
  you named.
- Your session is **encrypted end to end with the server's own sshd**. The
  gateway relays encrypted bytes, and it never holds a password or key for any
  server.
- The server's sshd still decides who can log in and as which user. The
  gateway adds a second gate in front of it and does not replace it.

You sign in twice, to two different things. Keep them apart, because mixing
them up causes most of the problems people hit:

| | The gateway | The server |
|---|---|---|
| What it checks | Your **RemotePower account name** and a key registered on that account | Your **login on the server** and the server's own keys |
| Where you set it | `User` in the `Host rp-gateway` block | The `user@` in `ssh user@web01.rp` |
| Example | `admin` | `root`, `deploy` |

## Who can connect

Every connection is checked when it is opened, against:

- **Your key.** It must be registered on your RemotePower account.
- **Your role.** It needs the `ssh` permission, which admins always have.
  For a custom role, tick **ssh** under Users → Roles.
- **Your role's scope** (groups, tags or sites) and your **tenant**.
- **The server.** An admin must have ticked **Allow SSH** for it, and it must
  not be quarantined or decommissioned.

Since the check runs on every connection, changes apply to the next
connection without restarting anything. That covers removing a key, changing a
role and opting a server out. When a server is opted out, its tunnel also
closes within a few minutes.

## Set it up

There are five steps. A server is reachable when all five are true, so if
something doesn't work, check them in order.

### 1. Install the gateway

On the RemotePower server:

```
sudo ./install-server.sh --with-sshgw
```

The installer:

- installs `asyncssh` and `websockets`
- installs the `remotepower-sshgw` service
- generates the secret the gateway and RemotePower share, and gives it to both

**Installed from a package, or by hand?** The server package ships the
application but not the gateway, so `install-server.sh` is not the way in.
From an unpacked 7.1.0 release run:

```
sudo packaging/install-sshgw.sh
```

It installs the daemon and its service, creates the shared secret once, gives
it to both sides and starts the gateway. It is safe to run again, for example
after an upgrade. `--port 22` and `--public-host gw.example.com` set the port
and the name people connect to. Your RemotePower server must already be 7.1.0
or newer.

**Running RemotePower in Docker?** The image carries the gateway. It is off
until you ask for it:

1. In `docker-compose.yml`, uncomment `RP_WITH_SSHGW: "1"` and the
   `"${RP_SSHGW_PORT:-2222}:2222"` port mapping, then run
   `docker compose up -d`. Publishing the port is a separate step on purpose:
   it is the one public SSH port, and nothing should open it by accident.
2. The container creates the shared secret and the gateway's host key in the
   data volume (`/var/lib/remotepower/sshgw`), so both survive a rebuild. To
   use a secret you manage yourself, set `RP_SSHGW_SECRET` instead.
3. Read the host key fingerprint from the container's log:
   `docker logs remotepower 2>&1 | grep 'host key fingerprint'`.
4. The image's nginx already has the tunnel route (step 2 below), so skip that
   step. If something sits in front of the container, such as a reverse proxy,
   it must pass `/api/sshgw/tunnel` through with WebSocket upgrade, like the
   route in step 2.
5. Carry on from step 3. In **Server status** the **SSH gateway** row reads
   **Running** once the container is up. If you mapped a different host port
   with `RP_SSHGW_PORT`, put that port on the SSH gateway page.

Whichever way you installed, nothing here opens a firewall port for you. Open
**TCP 2222** (or the port you chose) yourself. That is the only new port, and it
is on the RemotePower server, not on your fleet.

The gateway creates its own host key the first time it starts. Note its
fingerprint now, so you can check it on your first connection:

```
journalctl -u remotepower-sshgw | grep 'host key fingerprint'
```

### 2. Route the agents' tunnel through your web server

Agents reach the gateway through the same web address as the dashboard, on
the path `/api/sshgw/tunnel`. The nginx configuration that `install-server.sh`
sets up, and the snippet in the server package
(`/etc/nginx/snippets/remotepower-locations.conf`), already have this route.

If you wrote your own nginx configuration, add it to the RemotePower server
block, next to the other WebSocket routes. It must be an exact match, so it
wins over the `/api/` block:

```
location = /api/sshgw/tunnel {
    proxy_pass http://127.0.0.1:8767;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_read_timeout 1d;
    proxy_send_timeout 1d;
}
```

It needs the same `map $http_upgrade $connection_upgrade` as your other
WebSocket routes. If you restrict the dashboard to an IP allow-list, include
the same list here, and make sure the addresses of your servers are on it.
Without this route, agents fail to connect and nothing on the server side says
why.

### 3. Turn it on

1. **Settings → Advanced → SSH gateway**: turn the module on.
2. Open the **SSH gateway** page (Access section of the sidebar) and set the
   public host name people will connect to, for example `gw.example.com`.
   Change the port only if you changed the service's port.

**Server status** now has an **SSH gateway** row. It says **Running** when the
gateway answers on this server, and how many of the servers you allowed have a
tunnel up. **Enabled — unreachable** means nothing is listening on the tunnel
port here; check `systemctl status remotepower-sshgw`. If you run the gateway
on another machine, that row reads unreachable even when all is well.

### 4. Allow your servers

On the **SSH gateway** page, scroll to **Servers** and tick **Allow SSH** for
each server you want to reach. Only admins can do this.

A server also needs:

- **A Linux agent, version 7.1.0 or newer.** Windows and macOS agents don't
  carry the tunnel yet.
- **The Python `websockets` package.** On Debian and Ubuntu:
  `apt install python3-websockets`, then restart the agent
  (`systemctl restart remotepower-agent`). The package is the same one the
  push channel uses. The agent writes one warning to its journal if a server
  is allowed but the package is missing.

The agent opens its tunnel on its next heartbeat. The **Tunnel** column shows
when it last did. "Never" means it hasn't.

### 5. Add your key and connect

On the **SSH gateway** page, paste your public key (the contents of
`~/.ssh/id_ed25519.pub`) and confirm with your password. The key types
accepted are ed25519, ECDSA, hardware-backed `sk-` keys, and RSA of 2048 bits
or more. Each key can belong to only one account.

The page shows a ready-made block for `~/.ssh/config`:

```
Host rp-gateway
    HostName gw.example.com
    Port 2222
    User admin
    # If you have more than one key, name the one you added on the page:
    # IdentityFile ~/.ssh/id_ed25519
    # IdentitiesOnly yes

Host *.rp
    ProxyJump rp-gateway
```

Three things about this block:

- **`User` is your RemotePower account name.** The page fills it in for you.
  It is not your login on the server.
- **The gateway has its own `Host` entry.** Options written under `Host *.rp`
  apply to the server you are reaching, not to the gateway you jump through,
  so an `IdentityFile` there is never offered to the gateway. If you have
  several keys and ssh offers the wrong one, the gateway answers `Permission
  denied (publickey)`.
- **A key you registered must be the one ssh offers.** With `IdentitiesOnly
  yes` ssh offers only the key you name.

After that, every server is `<name>.rp`:

```
ssh root@web01.rp
scp ./backup.tar.gz root@web01.rp:/srv/
rsync -a ./site/ deploy@web01.rp:/var/www/site/
```

A name matches a server's RemotePower name, its hostname (short or full), or
its device id. `web01.rp` and `web01.example.com.rp` both reach a server whose
hostname is `web01.example.com`. Use a name, not an IP address: the gateway
doesn't look up servers by address. If two servers you can reach share a name,
the gateway refuses rather than guessing. Use the device id in that case.

### The first connection asks twice

The first time you connect, ssh asks you to trust two different host keys:

1. **The gateway's**, for the first hop. Compare it with the fingerprint you
   noted in step 1.
2. **The server's own**, for the second. This is the same key you would see
   connecting to the server directly, so a fingerprint your `known_hosts`
   already holds for that server is the one you should see.

Answer `yes` only when the fingerprint matches.

## What gets recorded

Each connection writes one record: your account, the key's fingerprint, your
source address, the server, the start time, the duration, and the bytes sent
each way. Records show on the SSH gateway page for admins and auditors, and in
the audit log next to logins, refusals and key changes.

The session is encrypted end to end, so the gateway cannot record keystrokes
or output. If you need a recorded session, use the web terminal.

**Clear sessions.** Admins see a **Clear sessions** button above the list on the
SSH gateway page. It empties the list, after you confirm. It does not touch the
audit log, which keeps its own line for every connection and refusal, so the
record of who connected stays. Clearing also resets the "sessions in the last
24 hours" figure. An admin who can see only part of the fleet, or a tenant
admin, clears only the sessions they could see.

## Turning it off

| To stop… | Do this |
|---|---|
| Everything | Settings → Advanced → turn the SSH gateway module off. The gateway refuses every login. |
| One server | Untick **Allow SSH** for it. Its tunnel closes within minutes. |
| One person | Remove their key (admins can remove anyone's), or take `ssh` off their role. |
| From the server itself | `touch /etc/remotepower/sshgw-disabled`. The agent refuses to open a tunnel, whatever RemotePower says. |

The agent also refuses to open a tunnel in audit (read-only) mode, and when it
runs in a container, because a container's loopback isn't the host's sshd.

## Good to know

- **The agent connects only to its own sshd on loopback.** The port comes
  from the server (`RP_SSHGW_PORT` in the agent's environment, default 22),
  never from the gateway. You can't use the tunnel to reach other ports or
  other machines on that network.
- **Failed logins are throttled.** After 20 failed logins in 10 minutes from
  one address, the gateway refuses that address for 10 minutes.
- **Login attempts are capped, like OpenSSH's `MaxAuthTries` and
  `MaxStartups`.** One connection can offer at most 10 keys before it is
  closed, and one address can have at most 10 connections still logging in at
  the same time.
- **Port 22.** To run the gateway on port 22, add
  `AmbientCapabilities=CAP_NET_BIND_SERVICE` to the service, and set
  `SSHGW_SSH_PORT=22` in `/etc/remotepower/sshgw.env`.
- **Requirements.** The gateway needs `asyncssh` 2.14.2 or newer, and refuses
  to start on anything older.

## Troubleshooting

Start with where the error appears. A connection has two stages, and each has
its own messages.

### Stage 1: logging in to the gateway

| You see | Meaning |
|---|---|
| `Permission denied (publickey)` | One of three things. **The account name is wrong** (`User` isn't your RemotePower account name). **The key isn't registered** on that account. **ssh offered a different key** than the one you registered; it tries your default keys unless the gateway's `Host` entry names one with `IdentityFile`. The gateway's journal says which account and fingerprint it refused: `journalctl -u remotepower-sshgw \| grep refused`. Compare the fingerprint with the list on the SSH gateway page. |
| `Permission denied (publickey)` for everyone, right after install | The gateway and RemotePower don't share the secret, or the module is off. Re-run `packaging/install-sshgw.sh`, which repairs the secret, and check that the module is on. |
| The connection hangs or is refused | Port 2222 isn't open to you on the RemotePower server's firewall. |
| Refused for 10 minutes | The failed-login throttle. Wait, or fix the cause first and then retry. |

### Stage 2: reaching the server

| You see | Meaning |
|---|---|
| `channel open failed: no device named "x"` | No server you're allowed to reach has that name. Most often **Allow SSH** isn't ticked for it. Also: it's quarantined or decommissioned, your role's scope or tenant doesn't include it, or you used an IP address. |
| `… is not connected to the gateway` | The server is allowed, but its agent hasn't opened a tunnel. See the next two rows. |
| A server stays at "never" in the **Tunnel** column | On that server run `journalctl -u remotepower-agent \| grep sshgw`. The agent says when it is allowed but the `websockets` package is missing. Other usual causes: the agent is older than 7.1.0, `/etc/remotepower/sshgw-disabled` exists, or your web server has no `/api/sshgw/tunnel` route or blocks the server's address (step 2). |
| `sshd is not reachable on local port 22` | The tunnel works, but nothing listens on that port on the server. Start sshd, or set `RP_SSHGW_PORT`. |
| `the SSH gateway is turned off in RemotePower` | The module is off. |
| `Permission denied` after the server's own prompt | The gateway let you through, and the server's sshd refused you. Check your login on the server and its keys. |
| `Host key verification failed` | ssh has no stored host key for that server yet. Connect once without `BatchMode`, compare the fingerprint, and answer `yes`. |

If the **Server status** page shows the **SSH gateway** row as unreachable,
fix that first: nothing else works while the daemon is down.

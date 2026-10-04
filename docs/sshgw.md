# SSH gateway

The SSH gateway lets you reach your servers with the SSH client you already
use: `ssh`, `scp`, `rsync`, VS Code Remote, Ansible. You don't need to open a
port on any server, run a VPN or write a firewall rule.

```
ssh -J alice@gw.example.com:2222 root@web01.rp
```

## How it works

```
your laptop ──SSH──> gateway (port 2222) ──WebSocket──> agent on web01 ──> web01's sshd
```

- Each opted-in server's RemotePower agent opens **one outbound connection**
  to the gateway and keeps it open. Nothing on the server listens on the
  network for this.
- You log in to the gateway with an SSH key you registered in RemotePower.
  The gateway never gives you a shell. It only forwards your connection to
  the server you named.
- Your SSH session is **encrypted end to end with the server's own sshd**.
  The gateway relays encrypted bytes, and it never holds a password or key
  for any server.
- The server's sshd still decides who can log in and as which user. The
  gateway adds a second gate in front of it and does not replace it.

## Who can connect

Every connection is checked when it is opened, against:

- **Your key.** It must be registered on your RemotePower account.
- **Your role.** It needs the `ssh` permission, which admins always have.
  For a custom role, tick **ssh** under Users → Roles.
- **Your role's scope** (groups, tags or sites) and your **tenant**.
- **The server.** An admin must have opted it in, and it must not be
  quarantined or decommissioned.

Since the check runs on every connection, changes apply to the next
connection without restarting anything. That covers removing a key,
changing a role and opting a server out. When a server is opted out, its
tunnel also closes within a few minutes.

## Set it up

### 1. Install the gateway

On the RemotePower server:

```
sudo ./install-server.sh --with-sshgw
```

The installer:

- installs `asyncssh` and `websockets`
- installs the `remotepower-sshgw` service
- generates the secret the gateway and RemotePower share, and gives it to both

Then open **TCP 2222** in the server's firewall. That is the only new port,
and it is on the RemotePower server, not on your fleet.

**Installed from a package, or by hand?** The server package ships the
application but not the gateway, so `install-server.sh` is not the way in.
From an unpacked 7.1.0 release run:

```
sudo packaging/install-sshgw.sh
```

It installs the daemon and its service, creates the shared secret once and gives
it to both sides, and starts the gateway. It is safe to run again, for example
after an upgrade. `--port 22` and `--public-host gw.example.com` set the port
and the name people connect to. It does not open a firewall port or edit your
nginx configuration, and it prints what is left, which is the same list as
below. Your RemotePower server must already be 7.1.0 or newer.

The gateway creates its own host key the first time it starts. To find its
fingerprint so you can check it on your first connection:

```
journalctl -u remotepower-sshgw | grep 'host key fingerprint'
```

### 2. Turn it on

1. **Settings → Advanced → SSH gateway**: turn the module on.
2. **SSH gateway** page (Remote access section of the sidebar): set the public
   hostname people will connect to, for example `gw.example.com`. Change the
   port only if you changed the service's port.
3. On the same page, opt in the servers you want to reach. For now this needs
   a Linux agent. The agent opens its tunnel on its next heartbeat.

Once the module is on, **Server status** has an **SSH gateway** row. It says
**Running** when the gateway answers on this server, and how many of the hosts you
opted in have a tunnel up. **Enabled — unreachable** means nothing is listening
on the tunnel port here; check `systemctl status remotepower-sshgw`. If you run
the gateway on another machine, that row will read unreachable even when all is
well.

### 3. Add your key

On the **SSH gateway** page, paste your public key (the contents of
`~/.ssh/id_ed25519.pub`) and confirm with your password. The key types
accepted are ed25519, ECDSA, hardware-backed `sk-` keys, and RSA of 2048 bits
or more. Each key can belong to only one account.

### 4. Connect

The page shows a ready-made block for `~/.ssh/config`:

```
Host rp-gateway
    HostName gw.example.com
    Port 2222
    User alice
    # If you have more than one key, name the one you added on the page:
    # IdentityFile ~/.ssh/id_ed25519
    # IdentitiesOnly yes

Host *.rp
    ProxyJump rp-gateway
```

The gateway has its own `Host` entry on purpose. Options written under `Host *.rp`
apply to the server you are reaching, not to the gateway you jump through, so an
`IdentityFile` there would never be offered to the gateway. `User` is your
RemotePower account name, not your login on the server.

After that, every server is `<name>.rp`:

```
ssh root@web01.rp
scp ./backup.tar.gz root@web01.rp:/srv/
rsync -a ./site/ deploy@web01.rp:/var/www/site/
```

A name matches a server's RemotePower name, its hostname (short or full), or
its device id. If two servers you can reach share a name, the gateway refuses
rather than guessing. Use the device id in that case.

## What gets recorded

Each connection writes one record: your account, the key's fingerprint, your
source address, the server, the start time, the duration, and the bytes sent
each way. Records show on the SSH gateway page for admins and auditors, and
in the audit log next to logins, refusals and key changes.

The session is encrypted end to end, so the gateway cannot record keystrokes
or output. If you need a recorded session, use the web terminal.

## Turning it off

| To stop… | Do this |
|---|---|
| Everything | Settings → Advanced → turn the SSH gateway module off. The gateway refuses every login. |
| One server | Opt it out on the SSH gateway page. Its tunnel closes within minutes. |
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
  to start on anything older. The agent needs the `websockets` Python package,
  the same one the push channel uses.
- **Windows and macOS** agents don't carry the tunnel yet.

## Troubleshooting

| You see | Meaning |
|---|---|
| `Permission denied (publickey)` at the gateway | One of three things: the key isn't registered on that account, the user name isn't your RemotePower account name, or ssh offered a different key than the one you registered (it tries your default keys unless the gateway's `Host` entry names one with `IdentityFile`). The gateway's journal says which account and key fingerprint it refused: `journalctl -u remotepower-sshgw \| grep refused`. Compare the fingerprint with the list on the SSH gateway page. |
| `channel open failed: no device named "x"` | No server you're allowed to reach has that name, or it isn't opted in. |
| `… is not connected to the gateway` | The server is allowed, but its agent hasn't opened a tunnel. Check that the agent is online, has `websockets` installed, and that `/etc/remotepower/sshgw-disabled` doesn't exist. |
| `sshd is not reachable on local port 22` | The tunnel works, but nothing listens on that port on the server. Start sshd, or set `RP_SSHGW_PORT`. |
| `the SSH gateway is turned off in RemotePower` | The module is off. |

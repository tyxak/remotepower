# Installation

The fastest path. Three commands on the server, two on the client.

### Server

```bash
git clone https://github.com/tyxak/remotepower
cd remotepower
sudo bash install-server.sh        # nginx + fcgiwrap + Python deps + initial admin password
```

That's it. The installer prints the URL and the auto-generated admin password. Open it in a browser, log in, change the password under Settings → Account.

### Client (on the host you want to manage)

```bash
sudo bash install-client.sh
# Paste the server URL and the 6-digit PIN from the dashboard. Done.
```

The device shows up in the dashboard within ~60 seconds.

### Optional but recommended

```bash
sudo bash packaging/install-webterm.sh    # browser-based SSH terminal (separate daemon)
```

Auto-detects your nginx user (`www-data` / `nginx` / `http` / etc.) and wires everything up. Run with `--dry-run` first if you want to see what it'll do.

### Public demo / sandbox

If you want to host a read-only demo at e.g. `demoremote.example.com` alongside your production install:

```bash
sudo bash packaging/install-demo.sh demoremote.example.com
sudo certbot --nginx -d demoremote.example.com
```

This creates a SEPARATE vhost — different data dir (`/var/lib/remotepower-demo/`), shared CGI code, `RP_READ_ONLY=1` set per-vhost. Visitors log in as `demo` / `demo`, browse everything, but mutations get a friendly 403 toast. Your production install at `remote.<domain>` is untouched. The vhost auto-seeds 16 fake homelab devices using the unallocated `.lab` TLD.

### Docker (one-liner alternative)

```bash
git clone https://github.com/tyxak/remotepower && cd remotepower
docker compose up -d
```

Dashboard at `http://localhost:8080`. Put a TLS-terminating reverse proxy (Caddy, Traefik, nginx) in front for production.

---

---

← [Back to docs index](README.md) · [Back to main README](../README.md)

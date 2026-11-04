# HTTPS / TLS termination

RemotePower expects HTTPS. Agents check the server's certificate, and session tokens and agent
credentials must never travel in clear text. This page shows how to put your own nginx server block
in front of RemotePower when you already have a certificate. If you do not, start with the table.

## Which path?

| Your situation | Use | Guide |
| --- | --- | --- |
| New install, you want it done for you | The `install.sh` wizard (self-signed CA, or Let's Encrypt for a public domain) | [install.md](install.md) |
| Docker | `docker compose up -d` serves self-signed HTTPS on first boot | [install.md](install.md#docker-one-liner-alternative) |
| Public hostname, port 80 reachable | `certbot --nginx` | [install.md](install.md) |
| Public hostname, no inbound 80 or 443 | Let's Encrypt DNS-01 with acme.sh | [acme.md](acme.md) |
| Internal only, no public DNS | The built-in self-signed CA | [tls-selfsigned.md](tls-selfsigned.md) |
| You already have a certificate | The server block below | this page |

## Your own server block

The installer puts every `location` block RemotePower needs into one shared file,
`/etc/nginx/snippets/remotepower-locations.conf`, and the HTTP vhost includes it. Include the same
file in your HTTPS server block, so the two never drift apart:

```nginx
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name power.example.com;

    root /var/www/remotepower;
    index index.html;
    server_tokens off;

    ssl_certificate     /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
    client_max_body_size 2m;

    include snippets/remotepower-locations.conf;
}
```

The commented HTTPS block in `/etc/nginx/sites-available/remotepower` is the complete template. It also
has the security headers (frame, content-type, referrer, permissions and content-security policy) that
the HTTP vhost sets, so copy those too. A server block that does not repeat them loses them.

## What the shared file does

- `/api/` goes to the app server on `127.0.0.1:8090`. It passes `Host` as `$http_host` (not
  `$host`, which drops the port and RemotePower builds links from it), sets `X-Forwarded-For` and
  `X-Forwarded-Proto`, allows `GET`, `POST`, `PUT`, `PATCH` and `DELETE`, and waits up to 130 seconds
  so the `/api/exec/wait` long poll is not cut at nginx's default 60 seconds.
- `/api/login` has a stricter 30-second timeout and accepts only `POST`.
- `/api/push/connect` and `/api/sshgw/tunnel` are the two WebSocket routes (the agent push channel and
  the SSH gateway). They go to their own daemons on `127.0.0.1:8766` and `127.0.0.1:8767`, not to the app
  server, and they need the `$connection_upgrade` map that the installer puts in
  `/etc/nginx/conf.d/remotepower-ws-map.conf`. If you write your own server block without the shared
  file, define that map once in the `http` block.
- `/install` and `/install.ps1` serve the agent installers, and `/api/agent/download` serves the agent.
- `/ca.crt` serves the CA of a self-signed install. Keep it reachable over plain HTTP on port 80,
  because a host fetches it before it trusts the server.
- `/static/`, `/sw.js` and `/manifest.json` serve the dashboard, and `/portal` serves the customer
  portal. Any other path is looked up as a file in the web root, and an unknown path answers 404 (it
  does not fall back to `index.html`). The file also refuses `/cgi-bin/` and any stray `.json` or
  `.tmp` file outside `/api/`, `/static/` and `/manifest.json`.

## Behind a load balancer or another proxy

If a proxy terminates TLS in front of nginx, turn on `trust_proxy` so the audit log and the IP
allowlist see the real client address. See [deployment.md](deployment.md#app-nodes-horizontal-scale).
Pass `X-Forwarded-Proto: https` so RemotePower builds `https://` links.

## Troubleshooting

| Problem | What to check |
| --- | --- |
| Agents refuse to enrol | The certificate does not match the name they use, or its issuer is not trusted. For your own CA, give the agent `RP_CA_BUNDLE`, or enrol with `--ca-fingerprint`. |
| Saving a setting returns 403 from nginx | The server block's `limit_except` lacks `PUT`. Use the shared file as shown above. |
| A long-running command ends after 60 seconds | `proxy_read_timeout 130s` is missing for `/api/`. |
| Links in emails point at port 80 or the wrong port | `Host` is passed as `$host`. Use `$http_host`. |

---

← [Back to docs index](README.md) · [Back to main README](../README.md)

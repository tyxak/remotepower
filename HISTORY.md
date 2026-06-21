# A remote shutdown button that got completely out of hand

RemotePower started as a web page with a single button that turned a machine
off. I wrote it in Python one afternoon — and then scope creep did the rest,
with a lot of help from AI to speed the process up massively (sorry, AI
snobs :-)). That one button is now a self-hosted control plane for a whole
Linux fleet: monitoring and alerting, a CMDB, CVE scanning, patching,
browser-based SSH, Proxmox, drift detection — the handful of separate tools
you'd normally stitch together in a homelab, in one place.

The agents poll the server over outbound HTTPS, so there are **no inbound ports
open on the clients — ever**. Enrolling them is meant to be painless, including
bulk enrollment through the API. Underneath, it's still deliberately boring:
nginx, Python CGI, and flat JSON files — and if you grow past a thousand-or-so
agents, you can scale up to PostgreSQL with PgBouncer.

## Where I'm coming from

I'm a DevOps engineer, mostly on Linux, working somewhere with a big bunch of
servers. Before that — about ten years ago now — I spent a couple of years in an
Ops role, monitoring servers. Linux and FOSS have inspired me for as long as I
can remember, and a lot of RemotePower's "must-haves" and "nice-to-haves" are
borrowed from technologies, apps and workflows I've admired along the way.

Because managing Linux at scale isn't just jumping around in the CLI — you need
observability, the right tools, and enough swiftness to actually keep up with a
large fleet. That's the itch RemotePower was built to scratch. The architectural
ideas are mine. The code, honestly, is mostly written by AI — and I'd rather be
upfront about that than pretend otherwise.

## Why it's free, and why it stays that way

A lot of enterprise products lean on a heavy pay-per-host model. As a
homelabber, you really shouldn't have to spend money just to get familiar with
the basics — the tools, the flows, the way it all fits together — or to use
something for learning. And if you're a FOSS person managing big fleets,
per-host billing is simply not the way to go.

So use RemotePower your way, all the way — from a homelab to a big fleet — with
all of its features, from homelab niceties to enterprise functions. It's **MIT
licensed, and it will stay that way.**

If you like it, I'd love your help letting this little project grow: open an
issue if you hit a bug, send a feature request (more than welcome), or just drop
by to say hi. Under all the AI, there's still a friendly human being behind all
this. :-)

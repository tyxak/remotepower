# A remote shutdown button that got completely out of hand

RemotePower started as a web page with a single button that turned a machine
off. I wrote it in Python one afternoon, and then scope creep did the rest, with
a lot of help from AI to speed the process up massively (sorry, AI snobs :-)).
That one button is now a self-hosted control plane for a whole Linux fleet:
monitoring and alerting, a CMDB, CVE scanning, patching, browser-based SSH,
Proxmox, drift detection. The handful of separate tools you'd normally stitch
together in a homelab, all in one place.

The agents poll the server over outbound HTTPS, so there are **no inbound ports
open on the clients, ever**. Enrolling them is meant to be painless, including
bulk enrollment through the API. Underneath, it's still deliberately boring:
nginx, Python CGI, and flat JSON files. If you grow past a thousand or so agents,
you can scale up to PostgreSQL with PgBouncer.

Use it as your one tool, or use it as a supplement to whatever you already run.
It plays nicely either way, from a single homelab box all the way up to a big
fleet.

## A bit about me

I'm Jakob, 40 years old, a curious geek from Denmark. By trade I'm a DevOps
engineer, mostly on Linux, working somewhere with a big bunch of servers. Years
ago, about ten of them now, I spent a couple of years in an Ops role watching
over servers. Linux and FOSS have inspired me for as long as I can remember, and
a lot of RemotePower's "must-haves" and "nice-to-haves" are borrowed from
technologies, apps and workflows I've admired along the way.

Managing Linux at scale isn't just jumping around in the CLI. You need
observability, the right tools, and enough speed to actually keep up with a large
fleet. That's the itch RemotePower was built to scratch. The architectural ideas
are mine. The code, honestly, is mostly written by AI, and I'd rather be upfront
about that than pretend otherwise.

## Every release is a "something Matters"

A little habit I picked up along the way: every release gets a codename ending in
"Matters". VisualMatters, TrustMatters, FortifyMatters, OnboardingMatters,
ResolutionMatters, PerimeterMatters, CTRLMatters, and so on. It started as a bit
of fun and just stuck around. It turned into a nice forcing function too, because
each release gets one thing to care about most, whether that's the look of it, the
security, getting you onboarded, or tightening the perimeter. In the end it all
matters, really.

## Why it's free, and why it stays that way

A lot of enterprise products lean on a heavy pay-per-host model. As a homelabber,
you really shouldn't have to spend money just to get familiar with the basics,
the tools, the flows, the way it all fits together. Same goes for using it to
learn. And if you're a FOSS person managing big fleets, per-host billing is
simply not the way to go.

So use RemotePower your way, all the way, from a homelab to a big fleet, with all
of its features, from homelab niceties to enterprise functions. It's **MIT
licensed, and it will stay that way.**

There's no "buy me a coffee" button here. Instead there's a pull request, an
issue tracker, and a security workflow. The tool is yours. Ours, really. Use it
however you like. If you hit a bug, open an issue. If you've got an idea, send a
feature request (very welcome). And if you just want to drop by and say hi, that
is welcome too.

Under all the AI, there's still a friendly human being behind this. :-)


/jake

#!/usr/bin/env python3
"""Resolver health checks for the Admin → DNS dashboard.

v4.9.0 "ResolutionMatters", feature #3. Resolve a monitored name/type across the
vetted public resolvers, measure latency, and classify health so the dashboard
can chart resolution latency / NXDOMAIN rates and alert when a name stops
resolving. Pure functions over ``dns_resolve`` (resolver factory injectable for
tests); the api.py layer owns storage, the rate-limited cadence and the
resolver_unhealthy / resolver_recovered webhooks — mirroring the DNSBL
reputation monitor.
"""

import time

import dns_resolve


def check_target(
    name,
    rtype,
    resolvers=None,
    timeout=dns_resolve.DEFAULT_TIMEOUT,
    _resolver_factory=None,
    _clock=None,
):
    """Resolve ``name``/``rtype`` at each resolver, timing every query.

    Returns a result dict:
      total, ok_count, nxdomain_count, fail_count,
      latency_ms (mean over successful answers), max_latency_ms,
      healthy (every resolver answered), down (no resolver answered),
      per_resolver: [{resolver, ip, status, error, latency_ms, answers}]
    """
    resolvers = resolvers or dns_resolve.PUBLIC_RESOLVERS
    clock = _clock or time.monotonic
    per, lat = [], []
    nx = fail = okc = 0
    for label, ip in resolvers:
        t0 = clock()
        r = dns_resolve.resolve_at(name, rtype, ip, timeout, _resolver_factory)
        ms = int(max(0.0, clock() - t0) * 1000)
        err = r["error"]
        if err == "NXDOMAIN":
            nx += 1
            status = "nxdomain"
        elif err:
            fail += 1
            status = "fail"
        else:
            okc += 1
            lat.append(ms)
            status = "ok"
        per.append(
            {
                "resolver": label,
                "ip": ip,
                "status": status,
                "error": err,
                "latency_ms": ms,
                "answers": r["answers"],
            }
        )
    total = len(resolvers)
    return {
        "total": total,
        "ok_count": okc,
        "nxdomain_count": nx,
        "fail_count": fail,
        "latency_ms": int(sum(lat) / len(lat)) if lat else 0,
        "max_latency_ms": max(lat) if lat else 0,
        "healthy": okc == total and total > 0,
        "down": okc == 0,
        "per_resolver": per,
    }

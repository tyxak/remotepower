# Status board

**Monitoring → Status board** is the NOC wall view — built to stay readable
at fleet scale. Instead of one tile per host, it rolls up by **group / site
/ tag** into big health tiles, plus a problem-host strip that surfaces every
unhealthy host regardless of fleet size.

- **Rollup tiles** — per group/site/tag: worst state wins the tile colour;
  counts show members and problems.
- **Problem strip** — every offline / critical host, always visible.
- **Geographic site map** — sites placed on a world map with health dots.
- Designed for a fixed display: high contrast, no interaction required,
  auto-refreshing.

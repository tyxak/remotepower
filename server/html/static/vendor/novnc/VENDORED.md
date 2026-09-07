# Vendored noVNC

- Upstream: https://github.com/novnc/noVNC
- Version: v1.7.0
- License: MPL-2.0 (see LICENSE.txt)
- Contents: core/ (RFB client, ESM) + vendor/pako/ (its only dependency).
- Boot test: `tests/test_v703_vendored_vnc_boots.py` drives a real RFB 3.8
  handshake and a Raw framebuffer rectangle against these files. Run it
  before and after any bump — that is what the 1.7.0 bump waited for.
- Entry point: core/rfb.js (default export RFB).
- Loaded as native ES modules; RemotePower attaches RFB to an already-open
  WebSocket via the RFB(target, channelObject, options) raw-channel form.
- To update: replace core/ and vendor/ from the upstream tag and bump this file.

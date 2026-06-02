# Vendored noVNC

- Upstream: https://github.com/novnc/noVNC
- Version: v1.5.0
- License: MPL-2.0 (see LICENSE.txt)
- Contents: core/ (RFB client, ESM) + vendor/pako/ (its only dependency).
- Entry point: core/rfb.js (default export RFB).
- Loaded as native ES modules; RemotePower attaches RFB to an already-open
  WebSocket via the RFB(target, channelObject, options) raw-channel form.
- To update: replace core/ and vendor/ from the upstream tag and bump this file.

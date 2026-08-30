# Third-party runtimes bundled with OnionGate

This application may bundle the following third-party programs. Their licenses
apply to those components; see upstream projects for full terms and source.

## Tor (Classic) and pluggable transports

- Source / downloads: https://www.torproject.org/ / https://dist.torproject.org/
- Expert bundle version used by `scripts/download-deps.sh`: 15.0.19
- License: Tor is typically distributed under a BSD-style license; pluggable
  transports (lyrebird, conjure, etc.) have their own licenses in the expert
  bundle `docs/` folder (copied under `resources/runtime/docs/` when present).

## sing-box

- Source: https://github.com/SagerNet/sing-box
- Version: 1.13.14
- License: **GPL-3.0-or-later**
- Corresponding source: https://github.com/SagerNet/sing-box/tree/v1.13.14

When redistributing this app with sing-box included, you must provide the
sing-box license text and offer access to the corresponding source (the link
above to the exact tag is sufficient for unmodified upstream binaries).

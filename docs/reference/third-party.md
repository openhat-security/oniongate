# Third-party software

OnionGate is GPL-3.0-only. Release/source builds also use or bundle third-party
software whose own licenses continue to apply.

## Bundled runtimes

| Component | Purpose | Version/source |
| --- | --- | --- |
| Tor expert bundle | Tor client, GeoIP data, runtime libraries, transports | 15.0.19 from `dist.torproject.org` |
| lyrebird / obfs4proxy alias | obfs4, WebTunnel, and bundled transport support | From the verified Tor bundle |
| Conjure client | Refraction Networking transport, when present for the target | From the verified Tor bundle |
| OpenSSL and libevent | Tor runtime dependencies where included | From the verified Tor bundle |
| sing-box | TUN capture and routing | 1.13.14, GPL-3.0-or-later |

The exact immutable archive hashes are in
[`scripts/dependencies.sha256`](https://github.com/irruptio-security/oniongate/blob/main/scripts/dependencies.sha256).
The staging script rejects unlisted or mismatched archives.

## Prior art (not derived)

| Upstream | License | What we used |
| --- | --- | --- |
| [Objective-See LuLu](https://github.com/objective-see/LuLu) | GPL-3.0 | The Apple API pattern: a `NEFilterDataProvider` that intercepts outbound flows. OnionGate’s extension, classifier, default-drop policy, and UI are original. LuLu’s tree, rule engine, and “allow Apple / allow installed programs” defaults are not vendored. |

## Notices and source

The distributable notices are maintained in
[`src-tauri/resources/licenses/`](https://github.com/irruptio-security/oniongate/tree/main/src-tauri/resources/licenses):

- `tor.txt`
- `openssl.txt`
- `libevent.txt`
- `lyrebird.txt`
- `conjure.txt`
- `GPL-3.0.txt`
- `THIRD_PARTY.md`

Unmodified sing-box corresponding source is available at its exact upstream
[v1.13.14 tag](https://github.com/SagerNet/sing-box/tree/v1.13.14).

Release artifacts must include these notices and corresponding-source links.
Changing a bundled component requires a license-compatibility review and an
update to this page, the notices, hashes, SBOM, and release notes.

## JavaScript and Rust dependencies

The application also links the npm and Cargo packages declared in
`package-lock.json` and `src-tauri/Cargo.lock`. Release CI must generate
CycloneDX SBOMs from both lockfiles. An SBOM inventories dependencies; it does
not replace license review or vulnerability analysis.

See the [release process](/reference/release) for current automation gaps.

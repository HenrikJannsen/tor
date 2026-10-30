# Release notes

## 1.0.0

This release provides the standalone Tor integration library extracted from Bisq 2, with support for running an embedded Tor process or connecting to an external Tor instance.

### Highlights

- Run the embedded Tor process in an operating system sandbox where supported, with status reporting for the isolation level selected by the host.
- Configure onion services, SOCKS connections, bridges, and pluggable transports through the Tor service API.
- Connect to an external Tor control port, including Tor instances managed by Whonix.
- Use the stable Tor Browser 16.0 expert bundle on supported platforms, including Linux ARM64, with Tor 0.4.9.15.
- Verify downloaded Tor bundle files against Tor Project signed release checksums during the build. Preserve the signed checksum resource bytes on Windows so signature verification remains reliable across platforms.
- Build with Gradle 9 and Java 21, with dependency verification and pinned build inputs.

### Compatibility and integration

- The supported API centers on `TorService` and its transport, onion service, external Tor, and sandbox configuration types. Internal implementation classes may change between versions.
- Android hosts can use the external Tor mode on Android 13 (API 33) and newer.
- The library has no dependency on other Bisq modules.

See [README.md](README.md) for platform requirements, configuration details, and integration guidance.

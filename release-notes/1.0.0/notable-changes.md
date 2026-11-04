# Tor Library 1.0.0 Notable Changes

Based on `main` at `6edc00e7413a1a95767586abc4899a8f0202ac85`, the first release of the library. See the [full release notes](full-release-notes.md) for integration notes and limitations.

## Embedded Tor

- The library runs the Tor expert bundle of Tor Browser 16.0 with tor 0.4.9.15 on Linux x86_64 and ARM64, macOS and Windows x86_64. The build verifies each bundle against the signed checksums of the release.
- The Tor directory has the parts `bin/`, `data/` and `sandy/`. Older layouts are migrated at the first start.
- The library owns the control and SOCKS listeners, the data directory and the authentication of its Tor, and refuses torrc entries which would give another program control over Tor.
- Bootstrap warnings no longer name the relay or bridge which Tor could not reach.

## Sandbox

- The Tor which the library starts can run in the sandbox of sandy 1.0.0, with weaker fallback levels where the host cannot enforce the base level.
- A start fails when no level can be enforced; the library never falls back to Tor without the sandbox. `TorService.getSandboxStatus()` reports the level and what it gives up.
- Pluggable transports need explicit permission in the sandbox. Windows cannot run them in the sandbox.
- The build checks the sandy archive against its pinned hash and the signed checksums of the sandy release.

## External Tor, Bridges and Overrides

- External Tor uses SAFECOOKIE or a control password, and must keep `IsolateSOCKSAuth` on its SOCKS port. Whonix always uses the Tor of the Gateway, where onion-grater accepts only authentication without a secret.
- Built-in or custom bridges fail the start if they cannot run, so the Tor which the library starts never connects without them. An external Tor uses the bridges of its own configuration, and the library logs a warning if the application configures bridges as well.
- Torrc overrides which make Tor run a program or load a library are refused if they come from a configuration file which the application writes itself.
- Each stream ID gets its own SOCKS credentials, so streams of different IDs use different circuits.

## Startup and Shutdown

- An onion service counts as published when the first HSDir has stored its descriptor.
- The shutdown waits for the processes below Tor and fails with their names if some still run. The next start stops them first.
- A failed cleanup no longer hides the cause of a failed start.

## Build and Verification

- The build uses Gradle 9.0.0 and Azul Java 21.0.13. It verifies dependencies, the Gradle wrapper and the pinned GitHub Actions.
- CI builds on Linux, Intel and Apple Silicon macOS, and Windows. Integration tests start Tor on a private Tor network, and a weekly job tests the public Tor network.

## Integration Requirements

- Bisq 1 and Bisq 2 include the library as the Git submodule `tor/`. A new dependency of the library must also be added to the verification metadata of both applications.
- Android hosts can use only the external Tor mode, on Android 13 (API level 33) and newer.
- Applications which run as root, for example in a container, must run as an unprivileged user or turn the sandbox off.

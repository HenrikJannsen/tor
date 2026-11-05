# Tor Library 1.0.0 Release Notes

Proposed release notes for the first release of the Tor library. The library starts, controls and connects to Tor for Bisq 1 and Bisq 2, runs the Tor which it starts in a sandbox, and publishes onion services.

## Scope

These notes describe the state of `main` at `6edc00e7413a1a95767586abc4899a8f0202ac85`. `gradle.properties` declares version `1.0.0`. No release tag exists yet, so these are release-candidate notes, not a claim that version 1.0.0 has been published. The library was extracted from Bisq 2, where it lived in `network/tor` and then in `tor/`; its history before the extraction is in Bisq 2. Bisq 1 and Bisq 2 include this commit as their `tor` Git submodule. The notes were checked against the README, the code and the commits of this repository.

## Integration Notes

- **Modules:** `tor` contains `TorService`, which starts, controls and connects to Tor and publishes onion services. `tor-common` contains the torrc generation and the copies of the Bisq utilities which the library uses. `jsocks` is a copy of the SOCKS library under its own LGPL license. `tor-local-network` starts a private Tor network for tests, and `tor-platform` holds the dependency constraints.
- **Supported API:** the API centers on `TorService` and its configuration types: `TorTransportConfig`, `ExternalTorConfig`, `BridgeConfig`, `TorSandboxConfig`, `TorSandboxStatus` and `ConfigFileTorrcOverrides`. Internal implementation classes may change between versions.
- **No Bisq dependencies:** the library does not depend on other Bisq modules or on the `build-logic` build of Bisq. Its Gradle plugins are copies of the Bisq 2 plugins and keep their plugin IDs.
- **Use from Bisq:** Bisq 1 and Bisq 2 include the repository as the Git submodule `tor/` and as an included Gradle build. In such a composite build Gradle uses the dependency verification metadata of the application, so a new dependency of the library must also be added to the verification metadata of Bisq 1 and Bisq 2.
- **Android:** the node app of bisq-mobile uses `TorService` with an external Tor on Android 13 (API level 33) and newer. The code of this mode uses only Java APIs which Android 13 provides. The embedded Tor runs only on desktop systems.
- **Versioning:** `version` belongs to the library and follows neither Bisq 1, Bisq 2 nor the Tor version. A major version marks a change which requires a change in Bisq 1 or Bisq 2. A minor version marks a new feature, or a new Tor bundle which needs a code change. A patch version marks a fix, or a new Tor bundle without a code change.

## Notable Changes

### Embedded Tor

- The library installs and runs the Tor expert bundle of Tor Browser 16.0 with tor 0.4.9.15 on Linux x86_64, Linux ARM64, macOS x86_64, macOS arm64 and Windows x86_64. The bundle includes the pluggable transports `lyrebird` and `conjure-client`.
- Every build downloads the bundle of its platform and checks it against the signed checksum file of the Tor Browser release, which the repository pins. `verifyTorBinaryVersion` fails the build if the tor of the bundle reports a version other than `tor.binaryVersion`. Windows ARM64 has no expert bundle, so a build in an ARM64 JVM on Windows fails when it needs the bundle.
- The Tor directory has the parts `bin/` (the bundle), `data/` (the data directory of Tor) and `sandy/`. Before a start, `TorDirectoryMigration` moves the state of an older layout into `data/` and keeps unknown files, such as the onion service key of Bisq 1 in `hiddenservice/`. The library never deletes the `lock` file of Tor.
- The library owns the control and SOCKS listeners, the data directory, the control password and `DisableNetwork` of the Tor it starts. It refuses torrc entries which would give another program control over Tor, such as `ControlSocket`, `CookieAuthentication` or `__OwningControllerFD`.
- On Linux, Tor runs in a session of its own (`setsid`), so a Ctrl+C in the terminal of the application does not end Tor before the shutdown of the application has used it.
- Tor writes its log to `tor-stdout.log`. Bootstrap warnings in the application log name the summary, warning and reason of the event, not the relay or bridge which Tor could not reach.

### Sandbox

- The library can run the Tor which it starts in the sandbox of sandy 1.0.0: Landlock and seccomp on Linux, Seatbelt on macOS, an AppContainer on Windows. A TOML policy per platform decides the isolation. In the base level, Tor has a network of its own and connects out only through the egress broker of sandy, which reaches public addresses only. Tor may write only its data directory and cannot start other processes or signal processes outside the sandbox.
- The policy lists weaker fallback levels (`contained`, `host-network` and `host-network-signals`). sandy takes the first level which the host can enforce. It skips a level only for a lasting shortfall of the host, so another user of the host cannot force a weaker level. `TorService.getSandboxStatus()` names the level and what it gives up.
- If no level can be enforced, the start fails with `SandboxUnavailableException`, which names the reason and how to turn the sandbox off. The library never starts Tor without the sandbox instead. Only a status record of sandy, which Tor can neither write nor remove, leads to the advice to turn the sandbox off. A refusal for a port which another process took is retried once with other ports.
- Before Tor starts without the sandbox on a data directory which a sandboxed Tor may have written, the library clears that directory. The record `data-mode` in the Tor directory tells whether the last Tor ran in the sandbox.
- Pluggable transports are not allowed in the sandbox by default. A sandboxed start whose bridges need a transport fails with `PluggableTransportsNotAllowedException`, which names the transports. With `allowPluggableTransports` of `TorSandboxConfig`, Tor may start the programs of the configured bridges, and sandy ends them with Tor.
- The build resolves the sandy 1.0.0 archive of its platform as a dependency from the GitHub release of sandy. It checks the archive against its pinned SHA-256 hash and against the `SHA256SUMS` file of the release, which must carry a valid signature by the pinned sandy release key (`B493 3191 06CC 3D1F 252E 19CB F806 F422 E222 AA02`). `-Psandy.package=false` builds without sandy.

### External Tor and Whonix

- With `UseExternalTor 1` in `external_tor.config`, the library uses a Tor which already runs. It authenticates with SAFECOOKIE or with `ControlPassword`, and on Whonix without a secret, because onion-grater accepts nothing else. If the external Tor cannot be used, the start fails with `ExternalTorUnavailableException`; the library never starts its own Tor instead.
- The library asks the external Tor for its SOCKS listeners and uses the first one which it can reach. It refuses a SOCKS port which turns off `IsolateSOCKSAuth`. If the control port does not report the configuration, as onion-grater on Whonix does not, the library logs that it could not check the port.
- The control connection is plain TCP and carries the private keys of the onion services. An external Tor on another host must be reached only over a trusted network.
- On a Whonix-Workstation the library always uses the Tor of the Whonix-Gateway, which needs the onion-grater profile of Bisq. On the Whonix-Gateway itself the start fails and tells the user to run the application on a Workstation.

### Bridges, Torrc Overrides and Stream Isolation

- `BridgeConfig` selects no bridges, the built-in bridges of one type (`obfs4`, `snowflake` or `meek`) of the bundled Tor Browser version, or bridge lines of the user. If a bridge needs a transport without a program, the start fails with `BridgesUnavailableException`; the Tor which the library starts never connects without the configured bridges. An external Tor uses the bridges of its own configuration, and the library logs a warning if the application configures bridges as well. The library does not log bridge lines.
- Torrc overrides which make Tor start a program or load a library (`ClientTransportPlugin`, `ServerTransportPlugin`, `AccelName` and `AccelDir`, in any letter case and as abbreviations) fail the start with `TorrcOverrideNotAllowedException` if they come from a configuration file which the application also writes itself. The application names such overrides in `ConfigFileTorrcOverrides`. For Bisq 2, `TorTransportConfig.from` detects them in `bisq.conf` before its substitutions are resolved, including values from substitutions and includes. With bridges, overrides of `ClientTransportPlugin` are ignored and therefore not refused. An external Tor gets no torrc overrides.
- Numbers and booleans of the Bisq 2 configuration reach Tor as their text. A list as an override value fails with an error which names the path.
- `TorService.getSocket` sends SOCKS credentials derived from the stream ID, so Tor puts streams with different stream IDs on different circuits.

### Onion Services, Startup and Shutdown

- The publication of an onion service completes when the first HSDir has stored the descriptor (`HS_DESC UPLOADED`), not when the upload starts. It fails if no HSDir stores the descriptor within the upload timeout.
- The shutdown stops Tor and waits for the processes below it, such as the programs of pluggable transports. If processes still run after the forced stop, the shutdown fails and names them. Processes which a shutdown could not stop stay tracked: the next start stops them first and fails if they still run.
- If the cleanup after a failed start fails as well, the cleanup failure is added to the start failure as suppressed, so the cause of the failed start stays visible. The onion service targets are always closed.
- In the sandbox, Tor cannot read `/proc/meminfo`. The library therefore computes the default of `MaxMemInQueues` as Tor does, from the memory which the JVM reports, and writes it into the torrc unless an override sets it.

### Build and Verification

- The build uses Gradle 9.0.0 and Java 21.0.13 of Azul. `verifyBuildEnvironment` accepts every build of the pinned Java update; CI installs the exact pinned runtime build `21.0.13+9-LTS`.
- `./gradlew build` runs the tests, the dependency verification, the Gradle wrapper checksum check and the check of the pinned GitHub Actions. `./gradlew integrationTest` starts Tor, including a private Tor network for onion service tests. `PublicTorNetworkOnionServiceTest` runs once a week on the public Tor network.
- CI builds on Ubuntu 24.04, Intel and Apple Silicon macOS 15, and Windows Server 2025. The integration job runs on Linux x86_64 with unprivileged user namespaces, so the tests also cover the levels `base` and `contained` of the Linux policy.

Details: [README.md](../../README.md), [the sandy binary](../../tor/src/main/resources/sandy/README.md), [Tor bundle verification](../../build-logic/tor-binary/README.md) and [dependency verification](../../gradle/README.md).

## Known Limitations

- Windows cannot run pluggable transports inside the sandbox. Use bridges without them, or turn the sandbox off.
- At a sandbox level with the network of the host, and with pluggable transports other than obfs4 on Linux, Tor and its transports use the network of the host. On macOS every transport gets the network of the host.
- On macOS, a webtunnel bootstrap in the sandbox has not been measured with sandy 2.4 or newer. snowflake and conjure were not measured in the sandbox.
- sandy refuses to run as root or with capabilities on Linux, so a node which runs as root, as is common in containers, fails its sandboxed start. A Tor directory on a `noexec` mount also fails the sandboxed start.
- On Windows, a sandboxed Tor must start in a session whose window station admits AppContainers, such as a desktop session. As a service in session 0, or over SSH, it fails to start.
- The bundled tor does not run on NixOS or Guix, with or without the sandbox. These systems need an external Tor.
- macOS has no `setsid`, so there Tor stays in the process group of the application, and a Ctrl+C ends Tor at once.
- Windows ARM64 has neither a Tor expert bundle nor a sandy binary in the build.

## Verification of These Notes

The notes were checked against the README, the sandy README, the code at the stated commit, and the commit messages since the earlier `RELEASE_NOTES.md`. No build or integration test was run while writing them.

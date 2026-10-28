# Tor build

The Tor build contains the Tor integration of Bisq:

- `tor`: starts, controls and connects to Tor, and publishes onion services (`TorService`). Its `PasswordDigest`
  is a copy of the one class of jtorctl, the Java library of the Tor control protocol, which the Tor build used. It
  keeps the 3-clause BSD license of jtorctl in its header.
- `tor-common`: the torrc generation and the copies of Bisq utilities which the Tor build uses.
- `jsocks`: a copy of the SOCKS library. It keeps its own license, the LGPL. See its README.
- `tor-local-network`: a tool which starts a private Tor network for tests.
- `tor-platform`: the dependency constraints of the Tor build.

## No dependencies on other Bisq modules

This repository was extracted from Bisq 2, where it lived in `network/tor` and then in `tor/`. Its history before the
extraction is in Bisq 2.

The Tor build does not depend on other Bisq modules or on the `build-logic` build of Bisq. Do not add such a
dependency.

- `build-logic` contains the Gradle plugins of the Tor build. `tor-binary` and `gradle-tasks` exist only here. The
  other plugins are copies of plugins in the `build-logic` of Bisq 2 and keep their plugin IDs. `commons` only has
  the two convention plugins which the Tor build applies, and `COMPOSITE_PROJECTS_TO_INCLUDE` of `maven-publisher`
  names only `tor`. The copies were taken from Bisq 2 main 7767b8b319. This repository has changed
  `bisq.java-conventions`, `LocalMavenPublishPlugin` and `BisqToolchainResolver` since, so these differ from their
  originals: compare a change of a plugin in Bisq 2 with the copy here before copying it.
- The classes in the packages `bisq.network.tor.common.*`, except `torrc`, are copies of classes of `bisq.common`.
  A copy keeps the sub-package and the class name: `bisq.common.util.StringUtils` becomes
  `bisq.network.tor.common.util.StringUtils`. The exception is `FileUtils`, which combines the used methods of
  `FileMutatorUtils` and `FileReaderUtils` of `bisq.common.file`. A copy only contains the members which the Tor build
  uses. A change of an original does not change its copy. A copy never uses the package of the original, because two
  classes with the same name on one class path break the Android build of bisq-mobile and make the JVM load whichever
  comes first.
- `PlatformServices` declares the operations which depend on the platform of the host application: the own process
  ID and whether the Tor build may set POSIX file permissions. Its method for the commands of the running processes is
  deprecated, because the Tor build no longer calls it, and has a default implementation. The host passes
  an implementation to `TorService`. Bisq passes `BisqTorPlatformServices` of the network module, which uses
  `FacadeProvider` and `FileMutatorUtils` of `bisq.common`. bisq-mobile calls `FileMutatorUtils.setup(false, false)`,
  so the Tor build sets no POSIX permissions there.
- The API of the Tor build only uses types of the Tor build. `TorTransportService` of the network module adapts the
  types of Bisq: it passes the `TorKeyPair` of Bisq as `OnionServiceKey`, and its `Config` implements
  `TransportConfig` of Bisq and wraps `TorTransportConfig`.

## Android

The node app of bisq-mobile runs `TorService` with an external Tor on Android, from API level 33. Code which runs in
this mode must only use Java APIs which Android 13 provides. This is all code which an external Tor needs:
`TorService` without the start of the embedded Tor, `ExternalTorConfig`, `TorTransportConfig`, `BridgeConfig`,
`TorDirectories`, `TorSocksProxyFactory` with `jsocks`, the packages `controller` (with the events and their parsers)
and `onionservice`, and `OS`, `LinuxDistribution`, `StringUtils` and `FileUtils` of `tor-common`. Only the embedded Tor
runs on desktop systems alone: `EmbeddedTorProcess`, `BundledTorLibraries`, the packages `installer` and `bridges`,
`TorrcClientConfigFactory`, the torrc generators and `tor-local-network`. If the connection fails, `TorService` fails
with `ExternalTorUnavailableException`; it never starts its own Tor instead of a configured external Tor. For example,
`java.util.HexFormat` and `Stream.toList()` need API level 34, and `ProcessHandle` does not exist on Android. The Tor
build uses Guava instead of `HexFormat` and `collect(Collectors.toList())` instead of `toList()`. Records and switch
expressions can be used, because D8 desugars them for Android.

`FileUtils` of `tor-common` reads and writes UTF-8 strictly on Android as well. The originals in `bisq.common` replace
malformed input when the modern file API is turned off, as bisq-mobile does. With the copy, a damaged
`external_tor.config` which is no valid UTF-8 fails `TorService.initialize()` with a message which names the file,
instead of being read with replacement characters.

## External Tor

With `UseExternalTor 1` in `external_tor.config` of the Tor directory, Bisq uses a Tor which already runs instead of
starting its own. The connection to its control port is plain TCP. It carries the private keys of the onion services
of Bisq (`ADD_ONION`) and, with `ControlPassword`, the password. Use a `ControlPort` on the same system, or reach a Tor
on another host only over a network which no untrusted system can use, such as the internal network of Whonix. While
the control port refuses the connection, Bisq tries again for about two seconds, because the external Tor may not
listen yet. If the control port does not accept the connection within 10 seconds, or its host cannot be reached, the
start fails at once.

Bisq asks the external Tor for its SOCKS listeners (`GETINFO net/listeners/socks`) and uses the first TCP listener which
it can reach: one on a specific address at that address, one on a wildcard address (`0.0.0.0` or `::`) at the control
host. A loopback address is an address of the host of Tor, so Bisq uses it only if the control host is a loopback
address as well. If a Tor on another host listens for SOCKS connections only on its loopback address, the start fails.

`TorService.getSocket` sends SOCKS credentials derived from the stream ID, so that Tor puts the streams of different
stream IDs on different circuits. Tor does so on a SOCKS port with `IsolateSOCKSAuth`, which it sets by default. The
start with an external Tor fails if a `SocksPort` or `__SocksPort` entry of its configuration which may have opened the
SOCKS port that Bisq uses turns this off with `NoIsolateSOCKSAuth`. If the control port does not report the
configuration, as onion-grater on Whonix does not, Bisq logs that it could not check the port and starts.

## Onion services

A publication of an onion service completes once the first HSDir has stored its descriptor, which Tor reports with
`HS_DESC UPLOADED`, not at the start of the upload (`HS_DESC UPLOAD`), when no peer could find the onion service yet. It
fails if no HSDir has stored the descriptor within the upload timeout of `TorTransportConfig`. The exception is an
`UPLOAD` which a filter in front of Tor shortened, see "Whonix".

## Whonix

On Whonix, `TorService` always uses the Tor of the Whonix-Gateway and never starts its own Tor. The control port of the
Gateway is filtered by onion-grater, so the Gateway needs an updated system and the onion-grater profile of Bisq, which
Whonix ships: `sudo onion-grater-add 40_bisq`. The library authenticates without a secret, sends `ADD_ONION` with a bare
local port as target, which onion-grater rewrites to the address of the Workstation, and listens on all addresses.
Every profile delivers `HS_DESC UPLOADED` with the HSDir redacted, which completes a publication. Profiles before
September 2024 shorten `HS_DESC UPLOAD` to `<address> <auth> redacted redacted`, without the `HSDIR_INDEX` which Tor
sends with every upload of a v3 descriptor; there such an `UPLOAD` completes the publication, as before.
`TorServiceWhonixTest` answers like onion-grater; there is no test on Whonix itself. Both Whonix systems have the
markers by which `TorService` detects Whonix (`/usr/share/whonix/marker` and `/usr/share/anon-dist/marker`). On the
Whonix-Gateway, which has `/usr/share/anon-gw-base-files/gateway` as well, `TorService` does not start and tells the
user to run Bisq on a Whonix-Workstation.

## Bridges and pluggable transports

`TorTransportConfig` takes a `BridgeConfig`: no bridges, the built-in bridges of one type of the Tor Browser version of
the bundle (`obfs4`, `snowflake` or `meek`), or bridge lines of the user. The built-in bridges and the programs of the
transports come from `pluggable_transports/pt_config.json` of the expert bundle, which Tor Browser uses as well, so they
change with `tor.version`.

For the Tor which Bisq starts, `TorService` writes `UseBridges 1`, one `Bridge` entry per bridge and one
`ClientTransportPlugin` entry per program which the bridges need. Tor splits a `ClientTransportPlugin` entry at white
space, and the Bisq data directory of macOS is below "Application Support". Tor therefore runs in the directory of the
bundle and gets the path of a program relative to it. If a bridge needs a transport without program, the start fails
with `BridgesUnavailableException`: Tor must not connect without the bridges, because the user relies on them to get
around a block or to hide the use of Tor. With bridges in the configuration, torrc overrides of `UseBridges`, `Bridge`
and `ClientTransportPlugin` are ignored. Bisq does not log the bridge lines, because a bridge which a user got privately
is blocked once it is known.

An external Tor uses the bridges of its own configuration. `TorService` logs a warning if the configuration of Bisq has
bridges as well.

In the configuration of Bisq 2 (`TorTransportConfig.from`), `builtInBridges` names the type of the built-in bridges and
`bridges` lists bridge lines. Both are optional, and at most one may be set.

## Embedded Tor

Bisq never deletes the `lock` file of Tor in its data directory: Tor locks it while it runs, so a file which an ended
Tor left blocks no start, and a Tor which still runs on the directory makes the next one exit.

`EmbeddedTorProcess` starts Tor with the `setsid` program of the system in a session of its own, if the system has
one, as Linux does. A Ctrl+C in the terminal of Bisq then does not reach Tor, which would otherwise exit at once,
before the shutdown of Bisq has used it. macOS has no `setsid`, so there Tor stays in the process group of Bisq.

## Build

Run these commands in the repository root:

- `./gradlew build` builds the Tor build and runs its tests and checks: the dependency verification, the Gradle wrapper
  checksums and the pinned GitHub Actions.
- `./gradlew integrationTest` runs the integration tests, which start Tor; `build` does not run them. A test skips
  itself if this host lacks what it needs. They start the bundled tor of the build. `PrivateTorNetworkOnionServiceTest`
  starts a private Tor network on this host, so it needs no internet; to create the keys of its directory authorities
  it needs tor and tor-gencert in `PATH` (on Debian and Ubuntu the package `tor`), and the tor in `PATH` is also its
  external Tor. Two peers publish onion services and exchange messages, also after a restart, through the SOCKS5 proxy
  and through an external Tor. `-Ptor.publicNetworkTests=true` adds `PublicTorNetworkOnionServiceTest`, which runs
  these peers on the public Tor network.
- `./gradlew :tor:verifyTorBinary` downloads and verifies the Tor expert bundle. See
  [build-logic/tor-binary/README.md](build-logic/tor-binary/README.md).
- `./gradlew dependencySignatureReport` writes [docs/dependency-signature-report.md](docs/dependency-signature-report.md)
  after a change of the dependencies or of `gradle/verification-metadata.xml`.

The build cache is on (`org.gradle.caching=true`), so a test task whose inputs did not change takes its result from the
cache (`FROM-CACHE`) or is `UP-TO-DATE`, and a build can pass without running a test. `./gradlew test --rerun` and
`./gradlew integrationTest --rerun` run the tests again; `--rerun-tasks` would also download the Tor bundle again.

`gradle.properties` defines `version` (the version of the artifacts), `tor.version` (the version of the Tor expert
bundle) and `tor.binaryVersion` (the version of the tor daemon in the bundle, which Bisq 2 shows). Bisq 2 reads all
three from `tor/gradle.properties`. `tor.binaryVersion` is set by hand, so `verifyTorBinaryVersion`, which every build
of `tor.zip` runs, fails if the tor of the bundle reports another version. `tor.bundleSha256.<platform>` pins the bundle
of `tor.version` for each platform; a change of `tor.version` needs new pins (see
[build-logic/tor-binary/README.md](build-logic/tor-binary/README.md#pin-the-bundles-of-a-release)).

`version` belongs to the Tor build. It follows neither Bisq 1 nor Bisq 2, which both use the Tor build, nor
`tor.version`, because the code and the Tor expert bundle change independently. Raise it with every change of the
artifacts, following semantic versioning:

- major: a change which requires a change in Bisq 1 or Bisq 2, such as an incompatible change of the API;
- minor: a new feature, or a new Tor expert bundle which needs a change of the code;
- patch: a fix, or a new Tor expert bundle without a change of the code.

`gradle/libs.versions.toml` and the constraints of `tor-platform` have the versions of Bisq 2: every catalog version is
`strictly`, and the composite build of Bisq 2 accepts one version of a module. Nothing checks this automatically.
Before Bisq 2 records a new commit of `tor/`, compare them with a checkout of Bisq 2; both commands print nothing if
every version of this build equals the one of Bisq 2:

```bash
bisq2=/path/to/bisq2
sed -n '/^\[versions\]/,/^\[libraries\]/{/=/p}' gradle/libs.versions.toml |
    while IFS= read -r line; do grep -qxF "$line" "$bisq2/gradle/libs.versions.toml" || echo "differs: $line"; done
constraints() {
    tr -d '\n' < "$1" | grep -oE 'api\("[^"]+"\) *\{ *version *\{ *require\("[^"]+"\)' | sort
}
comm -23 <(constraints tor-platform/build.gradle.kts) <(constraints "$bisq2/platform/build.gradle.kts")
```

`tor.zip` and `TorBuildVersion` are generated by Gradle tasks. An IDE build which does not run Gradle tasks needs one
Gradle build first.

`tor.zip` contains the files of the Tor expert bundle of the platform of the build, which `TorService` installs into the
Tor directory: Tor, its libraries, the GeoIP files and the pluggable transports (`lyrebird` and `conjure-client` with
their configuration `pt_config.json`). Linux x86_64, macOS and Windows x86_64 take the bundle of `tor.version`. The
stable releases have no bundle for Linux ARM64, so a Linux ARM64 build takes the bundle of the alpha release
`tor.bundleVersion.linux_arm64` until a stable release has one; its tor must be `tor.binaryVersion`
(`build-logic/tor-binary/README.md`). Every build downloads and verifies the expert bundle of its platform. The download
needs archive.torproject.org; it fails if it gets no connection in 30 seconds or no data for 60 seconds, and is then
tried once more. With `--offline`, the build keeps a bundle which it downloaded before. There is no expert bundle for
Windows ARM64, and the build never packages the programs of another architecture, so a build in an ARM64 JVM on Windows
fails when it needs the bundle.

## Use in Bisq 1 and Bisq 2

Bisq 1 and Bisq 2 include this repository as the Git submodule `tor/` and as an included Gradle build. Each records one
commit of this repository. In the composite build of an app, Gradle uses the dependency verification metadata of the
app, so a new dependency of the Tor build must also be added to `gradle/verification-metadata.xml` of Bisq 1 and of
Bisq 2.

To change the Tor code for an app, commit the change here, push it, and then commit the new commit of `tor/` in the
app. The apps describe the update of `tor/` in their own documentation: Bisq 1 in `docs/build.md` ("Tor submodule"),
Bisq 2 in its `README.md` ("Tor Submodule").

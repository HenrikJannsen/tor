# The sandy binary

Bisq can start the embedded Tor through `sandy`, a command line tool which runs a program in the sandbox of the
operating system (Landlock and seccomp on Linux, Seatbelt on macOS, an AppContainer on Windows). sandy is licensed
under MIT OR Apache-2.0; the licenses are in this directory.

## Packaging

The build puts the sandy binary of the platform of the build into the jar, as `sandy/<platform name>/sandy` (on
Windows `sandy.exe`), and writes its SHA-256 hash into `sandy/SHA256SUMS`. The platform names are the values of
`Platform.getPlatformName()`: `linux_x86_64`, `linux_arm64`, `macos_x86_64`, `macos_arm64`, `win_x86_64`. Before every
sandboxed start of Tor, Bisq installs the binary into the directory `sandy` of the Tor directory, which Tor cannot
write, and checks its hash against `SHA256SUMS`.

The library needs sandy 1.1.0 or newer: it passes the policy on standard input, uses its fallback levels,
`check --json` with the IDs of its warnings, `--no-warnings` and `--show-warning`, and the status record of
`run --status-file`, and the macOS template for pluggable transports uses `macos.mach_services`. Gradle resolves the
release archive of sandy 1.2.0 for the platform of the build as a dependency, `bisq-network:sandy:1.2.0` with the
target as classifier, from an Ivy repository of the releases at
<https://github.com/bisq-network/sandy/releases/tag/v1.2.0> which only sandy comes from. The archives are checked
twice before the build reads them:

1. Gradle dependency verification checks each archive against its SHA-256 in `gradle/verification-metadata.xml`. The
   archives have no signature of their own, so they are checksum-only entries of
   `gradle/dependency-checksum-fallback-allowlist.tsv`. Each platform has a configuration of its own
   (`sandyArchive_<platform name>`), so `resolveAndVerifyDependencies` verifies the archives of all platforms on any
   host, while a build resolves only the archive of its platform.
2. `verifySandyArchive` checks that `tor/sandy/1.2.0/SHA256SUMS`, the checksum file of the release committed in this
   project, carries a valid signature (`SHA256SUMS.asc` next to it) by the key which signs the sandy releases, and that
   the archive has the hash which that file lists for it. The key is Alejandro García's
   `B493 3191 06CC 3D1F 252E  19CB F806 F422 E222 AA02`, committed in `tor/sandy/sandy-release-signing-key.asc` (from
   keys.openpgp.org; <https://github.com/alejandrogarcia83.gpg> has the same key) and pinned by its fingerprint in
   `tor/build.gradle.kts`. A signature counts only if the key could sign when the signature was made, so a release
   stays buildable after the key expires.

The build fails if either check fails. The archives of the platforms:

| Platform | Archive |
|---|---|
| `linux_x86_64` | `sandy-1.2.0-x86_64-unknown-linux-musl.tar.gz` |
| `linux_arm64` | `sandy-1.2.0-aarch64-unknown-linux-musl.tar.gz` |
| `macos_x86_64` | `sandy-1.2.0-x86_64-apple-darwin.tar.gz` |
| `macos_arm64` | `sandy-1.2.0-aarch64-apple-darwin.tar.gz` |
| `win_x86_64` | `sandy-1.2.0-x86_64-pc-windows-msvc.zip` |

`-Psandy.package=false` builds without sandy and downloads nothing; a sandboxed start of Tor then fails with
`SandboxUnavailableException`, as it does on `win_arm64`, for which no binary is packaged. Like every other dependency,
the archive is downloaded once into the Gradle user home, and `--offline` builds use that copy.

## Updating sandy

sandy confines every sandboxed Tor of Bisq 1 and Bisq 2, so a new release is not taken on its signed checksums alone.
Before `sandyVersion` in `tor/build.gradle.kts` moves to a new release:

1. Check the signature of `SHA256SUMS` of the release and the archives against it:
   `gpg --verify SHA256SUMS.asc SHA256SUMS` with the key above, then `sha256sum --check SHA256SUMS`. If the release
   is signed by another key, find out why before the key in this project changes.
2. Build the release again from its tag and compare the archives with those of the release:
   `XWIN_ACCEPT_LICENSE=true scripts/reproduce.sh vX.Y.Z DIRECTORY` in a checkout of sandy builds all of them in a
   pinned container, as the README of sandy describes. If an archive differs, find out why before the pins move.
3. Review the source diff since the pinned release (`git diff vOLD vNEW`) for what it changes in the sandbox of Tor:
   the policy and its fallback levels, the platform backends, the relays and the egress broker, and `check` and `run`
   with the options which the library passes, the status record included. Write the review down, and adapt the
   templates in `policy/` and the README of the library to what changed. Run `sandy check --json` with each template
   on each platform and decide for every new warning ID whether Bisq shows it (`Sandy.SHOWN_WARNING_IDS`): sandy
   hides every ID that the list does not name, also one that the new release adds.
4. Commit `SHA256SUMS` and `SHA256SUMS.asc` of the release in `tor/sandy/<version>/`, remove the directory of the old
   version, set `sandyVersion` and update the table above. Write the dependency verification entries of the new
   archives as `gradle/README.md`, "Adding or updating a dependency", describes, check that their hashes are those of
   the signed `SHA256SUMS`, remove the entries of the old version from `gradle/verification-metadata.xml`, update the
   checksum-only entries of `gradle/dependency-checksum-fallback-allowlist.tsv`, and write the report again. Then run
   the unit tests and the integration tests of the sandbox on Linux, and a sandboxed start on macOS and Windows where
   these systems are available.

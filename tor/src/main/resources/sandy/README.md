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

The library needs sandy 2.4.1 or newer: it passes the policy on standard input, uses its fallback levels,
`check --json` and the status record of `run --status-file` (new in 2.4.1), and the macOS template for pluggable
transports uses `macos.mach_services`. The build packages sandy 2.4.1, whose binary of each platform
`tor/build.gradle.kts` pins by its SHA-256 hash. The release archives of sandy cannot be downloaded publicly yet, so the
binaries are committed in `tor/sandy/2.4.1/<platform name>/`, and the build fails if the binary of its platform does not
have the pinned hash. `-Psandy.package=false` builds without sandy; a sandboxed start of Tor then fails with
`SandboxUnavailableException`, as it does on `win_arm64`, for which no binary is packaged.

The committed binaries were taken from the release archives of sandy 2.4.1:

| Platform | Archive |
|---|---|
| `linux_x86_64` | `sandy-2.4.1-x86_64-unknown-linux-musl.tar.gz` |
| `linux_arm64` | `sandy-2.4.1-aarch64-unknown-linux-musl.tar.gz` |
| `macos_x86_64` | `sandy-2.4.1-x86_64-apple-darwin.tar.gz` |
| `macos_arm64` | `sandy-2.4.1-aarch64-apple-darwin.tar.gz` |
| `win_x86_64` | `sandy-2.4.1-x86_64-pc-windows-msvc.zip` |

Check the archives against the signed `SHA256SUMS` of the release (OpenPGP key
`E850 152C 47E1 3655 DDF3  A62B 4CE3 8D03 67B5 3CC5`, which also signs the release tags of sandy):

```sh
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

The key is published at <https://github.com/wodoro.gpg>, by the account which owns the repository of sandy;
keys.openpgp.org and keyserver.ubuntu.com do not have it. Once the releases can be downloaded publicly, the build
should download the archive of its platform and check the signature of `SHA256SUMS` and the pinned hash, as it does for
the Tor expert bundle, and `tor/sandy/` should be removed.

## Updating sandy

sandy confines every sandboxed Tor of Bisq 1 and Bisq 2, so a new release is not taken on its signed checksums alone.
Before `sandyVersion` and `pinnedSha256` in `tor/build.gradle.kts` move to a new release:

1. Verify the signed tag of the release with the key above: `git tag -v vX.Y.Z` in a checkout of sandy.
2. Check the release archives against their signed `SHA256SUMS` as above, and the binary of each platform against the
   hash which the release notes list.
3. Build the release again from its signed tag on at least one platform and compare the binary with the one in the
   archive: `scripts/release-build.sh TARGET` in a checkout of the tag, as the README of sandy describes in "Building
   a release binary again". A Linux binary depends on the host of the toolchain: those of 2.2.1 to 2.4.1 rebuild bit
   for bit only on an x86_64 Linux host, for both Linux targets, while a build on an arm64 host has the same functions
   in another order. Both Linux binaries of 2.4.1 match their pins when rebuilt with an x86_64 host. The macOS and
   Windows binaries can be rebuilt only on those systems, with the linker versions which the release notes name. If a
   rebuild differs from the binary of the release, find out why before the pin moves.
4. Review the source diff since the pinned release (`git diff vOLD vNEW`) for what it changes in the sandbox of Tor:
   the policy and its fallback levels, the platform backends, the relays and the egress broker, and `check` and `run`
   with the options which the library passes, the status record included. Write the review down, and adapt the
   templates in `policy/` and the README of the library to what changed.
5. Commit the binaries in `tor/sandy/<version>/<platform name>/`, remove the directory of the old version, set
   `sandyVersion` and the hashes, update the table above, and run the unit tests and the integration tests of the
   sandbox on Linux, and a sandboxed start on macOS and Windows where these systems are available.

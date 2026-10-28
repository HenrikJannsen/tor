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

The library needs sandy 2.4 or newer: it passes the policy on standard input, uses its fallback levels and
`check --json`, and the macOS template for pluggable transports uses `macos.mach_services`. The build packages sandy
2.4.1, whose binary of each platform `tor/build.gradle.kts` pins by its SHA-256 hash. The release archives of sandy
cannot be downloaded publicly yet, so the binaries are committed in `tor/sandy/2.4.1/<platform name>/`, and the build
fails if the binary of its platform does not have the pinned hash. `-Psandy.package=false` builds without sandy; a
sandboxed start of Tor then fails with `SandboxUnavailableException`, as it does on `win_arm64`, for which no binary is
packaged.

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

The binaries are reproducible: `scripts/release-build.sh TARGET` in a checkout of the signed tag `v2.4.1` of sandy
builds a binary with the pinned hash again. Once the releases can be downloaded publicly, the build should download
the archive of its platform and check the signature of `SHA256SUMS` and the pinned hash, as it does for the Tor expert
bundle, and `tor/sandy/` should be removed.

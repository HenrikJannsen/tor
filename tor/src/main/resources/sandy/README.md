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

The library needs sandy 2.2 or newer: it passes the policy on standard input and uses its fallback levels and
`check --json`. The build does not download and verify sandy releases yet. The build packages a binary only
if the Gradle property `sandy.binary` names one, for example `-Psandy.binary=/path/to/sandy`, built from the signed tag
of a sandy release. A relative path is relative to the directory `tor/`. The content of the binary is an input of the
build, so a rebuilt binary at the same path is packaged again. A build without the property contains no sandy binary,
and a sandboxed start of Tor fails with
`SandboxUnavailableException`. A release build needs a build step which downloads the release archives of sandy and
checks their pinned hashes and the signature of the release, as the build does for the Tor expert bundle.

# Tor bundle signature verification

The Tor plugin verifies expert bundles using the public key in
`src/main/resources/Tor_Browser_Developers_(signing_key).asc`.
`BisqTorBinaryPlugin` pins the primary fingerprint:

```text
EF6E286DDA85EA2A4BA7DE684E2C6E8793298290
```

Tor can introduce a signing subkey without changing that primary key. Updating
`tor.version` can therefore require refreshing the bundled public key as well.
For example, 15.0.25 and 16.0 use subkey
`022DA248432D2A0E0F54E65E316C1FACD62D07D9`.

## Download and convert the official key

Run these commands from the repository root in the same Bash session. They
require `curl` and GnuPG (`gpg`). Stop if any command fails.

[Tor's verification instructions](https://support.torproject.org/tor-browser/getting-started/verifying-tor-browser/)
link to the official
[WKD key download](https://openpgpkey.torproject.org/.well-known/openpgpkey/torproject.org/hu/kounek7zrdx745qydx6p59t9mqjpuhdf).
Download that binary public key into a temporary directory:

```bash
tor_key_dir=$(mktemp -d)
tor_key_fingerprint=EF6E286DDA85EA2A4BA7DE684E2C6E8793298290
tor_key_url='https://openpgpkey.torproject.org/.well-known/openpgpkey/torproject.org/hu/kounek7zrdx745qydx6p59t9mqjpuhdf'

curl -fsSL "$tor_key_url" -o "$tor_key_dir/tor-key.pgp"
```

Convert the download to the ASCII-armored public-key format used by the
resource file:

```bash
gpg --batch --no-options --homedir "$tor_key_dir" \
    --armor --import-options import-export --import \
    < "$tor_key_dir/tor-key.pgp" > "$tor_key_dir/tor-key.asc"
```

The output starts with `-----BEGIN PGP PUBLIC KEY BLOCK-----`.
`import-export` writes the processed key to standard output without storing
it in the keyring. The temporary GnuPG home isolates this procedure from
your personal keys and configuration. Use this direct export of the
official key; merging the old bundled key first retains obsolete subkeys
and certification metadata and produces a different file.

## Check the primary key and signing subkeys

Inspect the downloaded key before using it:

```bash
gpg --batch --no-options --homedir "$tor_key_dir" \
    --show-keys --with-fingerprint --with-subkey-fingerprint \
    "$tor_key_dir/tor-key.asc"
```

Confirm that there is exactly one primary key and its fingerprint matches
`EF6E286DDA85EA2A4BA7DE684E2C6E8793298290`. The display name alone is not
sufficient. A different primary fingerprint requires a separate trust review.

Import the key into the temporary keyring and check its certification and
subkey-binding signatures:

```bash
gpg --batch --no-options --homedir "$tor_key_dir" \
    --import "$tor_key_dir/tor-key.asc"
gpg --batch --no-options --homedir "$tor_key_dir" \
    --check-sigs "$tor_key_fingerprint"
```

GnuPG marks successfully verified signatures with `sig!`. The release
signing subkey must have a valid binding signature from the pinned primary key.

## Verify the expert bundle

Read the release version from `gradle.properties`. Set `tor_platform` to
the bundle to check: `macos-aarch64`, `macos-x86_64`, `linux-aarch64`,
`linux-x86_64`, or `windows-x86_64`.

```bash
tor_version=$(sed -n 's/^tor\.version=//p' gradle.properties)
tor_platform=macos-aarch64
tor_bundle="tor-expert-bundle-${tor_platform}-${tor_version}.tar.gz"
tor_bundle_url="https://archive.torproject.org/tor-package-archive/torbrowser/$tor_version/$tor_bundle"

curl -fsSL "$tor_bundle_url" -o "$tor_key_dir/$tor_bundle"
curl -fsSL "$tor_bundle_url.asc" -o "$tor_key_dir/$tor_bundle.asc"

gpg --batch --no-options --homedir "$tor_key_dir" --no-auto-key-retrieve \
    --status-fd 1 --verify "$tor_key_dir/$tor_bundle.asc" "$tor_key_dir/$tor_bundle"
```

Require a successful exit and a `Good signature` result. The `VALIDSIG`
status line identifies the signing subkey first and its primary fingerprint
last; the latter must match the pinned fingerprint above. A warning about
the key not being personally certified is expected in this temporary keyring.
The primary fingerprint check establishes which key is trusted here.

For a key refresh, also repeat the bundle check with the previous release
version to confirm its signing subkey remains available.

## Pin the bundles of a release

A valid signature on the bundle alone would also accept another release signed
by the same key. `verifyTorBinary` verifies the bundled checksum file against
its signature, requires exactly one entry for the expected bundle filename,
checks the downloaded bundle against that hash, and then verifies the bundle's
own signature. A change of `tor.version` needs the signed checksum file of
that release. Download it in the same Bash session:

```bash
tor_sums_url="https://archive.torproject.org/tor-package-archive/torbrowser/$tor_version/sha256sums-signed-build.txt"

curl -fsSL "$tor_sums_url" -o "$tor_key_dir/sha256sums-signed-build.txt"
curl -fsSL "$tor_sums_url.asc" -o "$tor_key_dir/sha256sums-signed-build.txt.asc"

gpg --batch --no-options --homedir "$tor_key_dir" --no-auto-key-retrieve \
    --status-fd 1 --verify "$tor_key_dir/sha256sums-signed-build.txt.asc" \
    "$tor_key_dir/sha256sums-signed-build.txt"
grep -E "tor-expert-bundle-(linux-x86_64|linux-aarch64|macos-x86_64|macos-aarch64|windows-x86_64)-$tor_version\.tar\.gz\$" \
    "$tor_key_dir/sha256sums-signed-build.txt"
```

Require the same `Good signature` and `VALIDSIG` result as above. Confirm that
the file lists the bundles `linux-x86_64`, `linux-aarch64`, `macos-x86_64`,
`macos-aarch64` and `windows-x86_64`. Copy both files into
`src/main/resources/torbrowser-<tor.version>/` of this plugin. The build reads
them directly, so no hashes need to be copied into `gradle.properties`.
`TorSignedChecksumsTest` checks that the signed file covers every supported
platform.

## Install the verified ASCII key and run the build check

After the fingerprint and signature checks succeed, replace the resource
and run Bisq's verifier on the bundle for the build machine's platform:

```bash
cp "$tor_key_dir/tor-key.asc" \
    'build-logic/tor-binary/src/main/resources/Tor_Browser_Developers_(signing_key).asc'
./gradlew :tor:verifyTorBinary
```

The Gradle task must finish successfully. Keep the pinned primary fingerprint
unchanged when refreshing its subkeys. Never bypass a failed signature check.

## Offline builds and key refreshes

The download tasks honour `--offline`: a downloaded bundle is kept, and a
missing one fails the build with a message instead of opening a connection.
Run the build once online after a change of `tor.version`.

The task reads the content of the bundled key as an input, so a refreshed
key file runs the verification again.

## Which keys verify a bundle

`verifyTorBinary` accepts a signature only by a key of the pinned primary
key which was valid for signing when the signature was made: the binding
signature of the subkey and the back-signature (0x19) of the subkey must
verify, the signed key flags must allow signing, and neither the subkey nor
the primary key may have expired at the creation time of the signature.
Evaluated at that time, a bundle signed with a subkey which has expired
since, such as `157432CF78A65729` on 2026-10-26, still verifies, so that an
older release can be built again. The signer states that time, so whoever
holds the private key of an expired subkey can still sign with an earlier
time. A subkey with any revocation is never trusted, such as the 2015 subkey
`2D000988589839A3`, which was revoked as compromised, and a revocation of the
primary key fails the verification.

# Tor Library 1.0.0 Highlights

## A Standalone Tor Library

This first release provides the Tor integration of Bisq as a library of its own, without dependencies on other Bisq modules. Bisq 1 and Bisq 2 use it as a Git submodule.

## Bundled and Sandboxed Tor

The library runs the Tor expert bundle of Tor Browser 16.0 (tor 0.4.9.15) on Linux, macOS and Windows, Linux ARM64 included. Its Tor runs in the sandbox of sandy 1.0.0 when the application enables it, and the start fails instead of silently running Tor without the sandbox.

## External Tor and Bridges

The library also connects to an external Tor, including the Whonix-Gateway and Android hosts. Bridges with pluggable transports are supported, and the Tor which the library starts never connects without the configured bridges. An external Tor uses the bridges of its own configuration.

## Verified Build Inputs

The build checks the Tor bundles and the sandy archives against signed checksums and pinned hashes, and verifies every dependency.

See [notable changes](notable-changes.md) and [full release notes](full-release-notes.md) for details.

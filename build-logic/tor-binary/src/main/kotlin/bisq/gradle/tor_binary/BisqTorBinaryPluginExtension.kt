package bisq.gradle.tor_binary

import org.gradle.api.provider.MapProperty
import org.gradle.api.provider.Property

abstract class BisqTorBinaryPluginExtension {
    abstract val version: Property<String>

    // The version of tor in the expert bundle of each platform, which the build checks
    abstract val binaryVersion: Property<String>

    // The SHA-256 of the expert bundle of each platform by platform name, which the build checks
    abstract val bundleSha256: MapProperty<String, String>
}

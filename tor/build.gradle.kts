import java.util.*

// Function to read properties from a file - TODO find a way to reuse this code instead of copying when needed
fun readPropertiesFile(filePath: String): Properties {
    val properties = Properties()
    file(filePath).inputStream().use { properties.load(it) }
    return properties
}

plugins {
    id("bisq.java-conventions")
    id("bisq.java-integration-tests")
    id("bisq.gradle.tor_binary.BisqTorBinaryPlugin")
}

val properties = readPropertiesFile("../gradle.properties")

val torVersion: String = properties.getProperty("tor.version")
    ?: throw GradleException("Tor version is not defined in gradle.properties")
val torBinaryVersion: String = properties.getProperty("tor.binaryVersion")
    ?: throw GradleException("Tor binary version is not defined in gradle.properties")
val torBundleSha256: Map<String, String> = properties.stringPropertyNames()
    .filter { it.startsWith("tor.bundleSha256.") }
    .associate { it.removePrefix("tor.bundleSha256.") to properties.getProperty(it) }

tor {
    version.set(torVersion)
    binaryVersion.set(torBinaryVersion)
    bundleSha256.set(torBundleSha256)
}

/**
 * Generates TorBuildVersion with the Tor version of gradle.properties. TorInstaller uses it to detect whether the
 * installed Tor files are outdated.
 */
val generateTorBuildVersionClass by tasks.registering {
    val outputDir = layout.buildDirectory.dir("generated/source/torBuildVersion")
    inputs.property("torVersion", torVersion)
    outputs.dir(outputDir)

    doLast {
        val versionFile = outputDir.get().file("bisq/network/tor/installer/TorBuildVersion.java").asFile
        versionFile.parentFile.mkdirs()
        versionFile.writeText("""
            package bisq.network.tor.installer;

            final class TorBuildVersion {
                static final String TOR_VERSION = "$torVersion";
            }
        """.trimIndent())
    }
}

sourceSets {
    main {
        java {
            srcDir(generateTorBuildVersionClass)
        }
        resources {
            srcDir(layout.buildDirectory.file("generated/src/main/resources"))
        }
    }
}

dependencies {
    "torPlatform"(platform(project(":tor-platform")))

    // The API takes types of tor-common, such as the DirectoryAuthority entries of TorTransportConfig
    api(project(":tor-common"))

    implementation(libs.typesafe.config)

    api(project(":jsocks"))
    implementation(project(":jtorctl"))
}

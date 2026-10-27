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
    // A local copy, because the configuration cache cannot store a reference to the script object.
    val versionForTask = torVersion
    inputs.property("torVersion", versionForTask)
    outputs.dir(outputDir)

    doLast {
        val versionFile = outputDir.get().file("bisq/network/tor/installer/TorBuildVersion.java").asFile
        versionFile.parentFile.mkdirs()
        versionFile.writeText("""
            package bisq.network.tor.installer;

            final class TorBuildVersion {
                static final String TOR_VERSION = "$versionForTask";
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

    // The private Tor network of the integration tests. Not transitive: tor-local-network depends on this project,
    // whose classes and dependencies the integration tests have already.
    integrationTestImplementation(project(":tor-local-network")) {
        isTransitive = false
    }
}

tasks.named<Test>("integrationTest") {
    // The tests on the public Tor network need the internet, so they run only with -Ptor.publicNetworkTests=true
    systemProperty("tor.publicNetworkTests", providers.gradleProperty("tor.publicNetworkTests").getOrElse("false"))
}

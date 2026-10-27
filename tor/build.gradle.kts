import bisq.gradle.common.getPlatform
import org.gradle.language.jvm.tasks.ProcessResources
import java.security.MessageDigest
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
val torBundleVersion: Map<String, String> = properties.stringPropertyNames()
    .filter { it.startsWith("tor.bundleVersion.") }
    .associate { it.removePrefix("tor.bundleVersion.") to properties.getProperty(it) }
val torBundleSha256: Map<String, String> = properties.stringPropertyNames()
    .filter { it.startsWith("tor.bundleSha256.") }
    .associate { it.removePrefix("tor.bundleSha256.") to properties.getProperty(it) }

tor {
    version.set(torVersion)
    bundleVersion.set(torBundleVersion)
    binaryVersion.set(torBinaryVersion)
    bundleSha256.set(torBundleSha256)
}

/**
 * Generates TorBuildVersion with the release of the Tor expert bundle which this build packages: tor.version of
 * gradle.properties, or the tor.bundleVersion of the platform of the build. TorInstaller uses it to detect whether the
 * installed Tor files are outdated.
 */
val generateTorBuildVersionClass by tasks.registering {
    val outputDir = layout.buildDirectory.dir("generated/source/torBuildVersion")
    // A local copy, because the configuration cache cannot store a reference to the script object.
    val versionForTask = torBundleVersion[getPlatform().platformName] ?: torVersion
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

/**
 * Packages the sandy binary of the platform of the build, which the sandbox of the embedded Tor needs, with its SHA-256
 * hash. sandy has no published release yet, so the binary is packaged only if the Gradle property sandy.binary names
 * one. See src/main/resources/sandy/README.md.
 */
val packageSandyBinary by tasks.registering {
    val projectDirectory = layout.projectDirectory
    // The content of the binary is the input, not its path: a rebuilt binary at the same path is packaged again.
    val sandyBinaryFiles = objects.fileCollection().from(providers.gradleProperty("sandy.binary")
        .map { listOf(projectDirectory.file(it)) }
        .orElse(listOf()))
    val outputDir = layout.buildDirectory.dir("generated/sandy")
    val platformName = getPlatform().platformName
    inputs.files(sandyBinaryFiles).withPathSensitivity(PathSensitivity.NONE)
    inputs.property("platformName", platformName)
    outputs.dir(outputDir)

    doLast {
        val sandyDir = outputDir.get().asFile.resolve("sandy")
        sandyDir.deleteRecursively()
        val sandyBinaryFile = sandyBinaryFiles.singleOrNull() ?: return@doLast
        val fileName = if (platformName.startsWith("win")) "sandy.exe" else "sandy"
        val target = sandyDir.resolve("$platformName/$fileName")
        target.parentFile.mkdirs()
        sandyBinaryFile.copyTo(target)
        val sha256 = MessageDigest.getInstance("SHA-256").digest(target.readBytes())
            .joinToString("") { "%02x".format(it) }
        sandyDir.resolve("SHA256SUMS").writeText("$sha256  $platformName/$fileName\n")
    }
}

sourceSets {
    main {
        java {
            srcDir(generateTorBuildVersionClass)
        }
        resources {
            srcDir(layout.buildDirectory.file("generated/src/main/resources"))
            srcDir(packageSandyBinary)
        }
    }
}

tasks.named<ProcessResources>("processResources") {
    doFirst {
        // Gradle cannot copy the checksum file over a stale directory from an earlier build.
        val checksumPath = destinationDir.resolve("sandy/SHA256SUMS")
        if (checksumPath.isDirectory && !checksumPath.deleteRecursively()) {
            throw GradleException("Could not remove stale checksum directory: $checksumPath")
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

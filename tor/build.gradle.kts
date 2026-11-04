import bisq.gradle.common.getPlatform
import bisq.gradle.tasks.PgpFingerprint
import bisq.gradle.tasks.signature.SignatureVerificationTask
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
tor {
    version.set(torVersion)
    binaryVersion.set(torBinaryVersion)
}

/**
 * Generates TorBuildVersion with tor.version of gradle.properties. TorInstaller uses it to detect whether the installed
 * Tor files are outdated.
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

/*
 * The sandy binary of the platform of the build, which the sandbox of the embedded Tor needs. Gradle resolves the
 * release archive of each platform as a dependency from the sandy releases on GitHub, and dependency verification
 * checks it against its SHA-256 in gradle/verification-metadata.xml. Before the archive of the build's platform is
 * read, verifySandyArchive also checks the signature of the committed SHA256SUMS of the release by the pinned key and
 * the hash of the archive against it. A platform without a target gets no binary, and a sandboxed start of Tor fails
 * there. The Gradle property sandy.package=false builds without sandy. See src/main/resources/sandy/README.md.
 */
val sandyVersion = "1.0.0"
// The release target of each platform with a sandy binary
val sandyTargets = mapOf(
    "linux_x86_64" to "x86_64-unknown-linux-musl",
    "linux_arm64" to "aarch64-unknown-linux-musl",
    "macos_x86_64" to "x86_64-apple-darwin",
    "macos_arm64" to "aarch64-apple-darwin",
    "win_x86_64" to "x86_64-pc-windows-msvc",
)
// The key which signs SHA256SUMS of the sandy releases (Alejandro García)
val sandySigningKeyFingerprint = "B493 3191 06CC 3D1F 252E  19CB F806 F422 E222 AA02"
val packageSandy = providers.gradleProperty("sandy.package")
    .map {
        when (it) {
            "true" -> true
            "false" -> false
            else -> throw GradleException("The Gradle property sandy.package must be true or false, not $it")
        }
    }
    .getOrElse(true)
val sandyPlatformName = getPlatform().platformName
val sandyTarget = sandyTargets[sandyPlatformName]?.takeIf { packageSandy }

repositories {
    // The release archives of sandy on GitHub, which have no Ivy or Maven metadata. Only sandy comes from there, and
    // sandy comes from nowhere else.
    exclusiveContent {
        forRepository {
            ivy {
                name = "sandyReleases"
                url = uri("https://github.com/bisq-network/sandy/releases/download")
                patternLayout { artifact("v[revision]/[module]-[revision]-[classifier].[ext]") }
                metadataSources { artifact() }
            }
        }
        filter { includeModule("bisq-network", "sandy") }
    }
}

// One configuration per platform, so that resolveAndVerifyDependencies verifies the archives of all platforms on any
// host, while a build resolves only the archive of its own platform.
val sandyArchives = sandyTargets.mapValues { (platformName, target) ->
    configurations.create("sandyArchive_$platformName") {
        isCanBeConsumed = false
        isTransitive = false
    }.also {
        val extension = if (platformName.startsWith("win")) "zip" else "tar.gz"
        dependencies.add(it.name, "bisq-network:sandy:$sandyVersion:$target@$extension")
    }
}

val verifySandyArchive = sandyTarget?.let {
    val archive = sandyArchives.getValue(sandyPlatformName)
    fun base64Of(path: String) = Base64.getEncoder().encodeToString(file(path).readBytes())
    val keyFile = file("sandy/sandy-release-signing-key.asc")
    val keySha256 = MessageDigest.getInstance("SHA-256").digest(keyFile.readBytes())
        .joinToString("") { "%02x".format(it) }
    val fingerprint = PgpFingerprint.normalize(sandySigningKeyFingerprint)
    tasks.register<SignatureVerificationTask>("verifySandyArchive") {
        fileToVerify.fileProvider(archive.incoming.artifacts.resolvedArtifacts.map { it.single().file })
        signedChecksumsBase64.set(base64Of("sandy/$sandyVersion/SHA256SUMS"))
        signedChecksumsSignatureBase64.set(base64Of("sandy/$sandyVersion/SHA256SUMS.asc"))
        pgpFingerprintToKeyUrl.set(mapOf(fingerprint to keyFile.toURI().toString()))
        pgpFingerprintToKeySha256.set(mapOf(fingerprint to keySha256))
        resultFile.set(layout.buildDirectory.file("sandy/sha256.result"))
    }
}

/**
 * Packages the sandy binary of the platform of the build from its verified release archive, with its SHA-256 hash.
 */
val packageSandyBinary by tasks.registering(Sync::class) {
    // Local copies, because the configuration cache cannot store a reference to the script object.
    val version = sandyVersion
    val platformName = sandyPlatformName
    val fileName = if (platformName.startsWith("win")) "sandy.exe" else "sandy"
    val outputDir = layout.buildDirectory.dir("generated/sandy")
    into(outputDir)
    val verifyTask = verifySandyArchive ?: return@registering
    val archiveDir = "sandy-$version-$sandyTarget"
    val archiveFile = verifyTask.flatMap { it.fileToVerify }
    dependsOn(verifyTask)

    // tarTree and zipTree read the archive only when the task copies, after verifySandyArchive checked it.
    from(if (platformName.startsWith("win")) zipTree(archiveFile) else tarTree(archiveFile)) {
        include("$archiveDir/$fileName")
        eachFile { path = "sandy/$platformName/$fileName" }
        includeEmptyDirs = false
    }

    doLast {
        val sandyDir = outputDir.get().asFile.resolve("sandy")
        val binary = sandyDir.resolve("$platformName/$fileName")
        if (!binary.isFile) {
            throw GradleException("The sandy archive of $platformName has no $archiveDir/$fileName")
        }
        val sha256 = MessageDigest.getInstance("SHA-256").digest(binary.readBytes())
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

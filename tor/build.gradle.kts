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

/**
 * Packages the sandy binary of the platform of the build, which the sandbox of the embedded Tor needs, with its SHA-256
 * hash. The releases of sandy cannot be downloaded publicly yet, so the binaries of the pinned release are committed in
 * sandy/<version>/ of this project, and the build fails if the binary of its platform does not have the pinned hash.
 * The Gradle property sandy.package=false builds without sandy. See src/main/resources/sandy/README.md.
 */
val packageSandyBinary by tasks.registering {
    val sandyVersion = "2.4.1"
    // The SHA-256 of the binary in each release archive of sandy 2.4.1, as its release notes list them. The binaries
    // can be built again from the signed tag v2.4.1 and compared.
    val pinnedSha256 = mapOf(
        "linux_x86_64" to "e80d6bebae3893126f10ee8b6f76240dc343991b3b017b108af9c2a1a8553645",
        "linux_arm64" to "cea318cdd1d43dc719817864370488165494b796510d92c6a893396f9b8f1865",
        "macos_x86_64" to "56289aa444172985d09c281adff12ba7d2969b4a9080b71a4e9cc6f4aef4793f",
        "macos_arm64" to "a1153b499055b52342abe3ebc7c71d3dafe8a6478957ff230d307e7da8bd19fc",
        "win_x86_64" to "851c27f9b48ef22d316bc5c64a2b5df29e484851d044b7c3b5c135a13b0e574a",
    )
    val projectDirectory = layout.projectDirectory
    val platformName = getPlatform().platformName
    val fileName = if (platformName.startsWith("win")) "sandy.exe" else "sandy"
    val packageSandy = providers.gradleProperty("sandy.package")
        .map {
            when (it) {
                "true" -> true
                "false" -> false
                else -> throw GradleException("The Gradle property sandy.package must be true or false, not $it")
            }
        }
        .orElse(true)
    // A platform without a pinned binary gets none, and a sandboxed start of Tor fails there. The content of the
    // binary is the input, not its path: a changed binary at the same path is packaged again.
    val sandyBinaryFiles = objects.fileCollection().from(packageSandy.map {
        if (it && platformName in pinnedSha256) {
            listOf(projectDirectory.file("sandy/$sandyVersion/$platformName/$fileName"))
        } else {
            listOf()
        }
    })
    val outputDir = layout.buildDirectory.dir("generated/sandy")
    inputs.files(sandyBinaryFiles).withPathSensitivity(PathSensitivity.NONE)
    inputs.property("platformName", platformName)
    inputs.property("pinnedSha256", pinnedSha256)
    outputs.dir(outputDir)

    doLast {
        val sandyDir = outputDir.get().asFile.resolve("sandy")
        sandyDir.deleteRecursively()
        val sandyBinaryFile = sandyBinaryFiles.singleOrNull() ?: return@doLast
        val expectedSha256 = pinnedSha256.getValue(platformName)
        val target = sandyDir.resolve("$platformName/$fileName")
        target.parentFile.mkdirs()
        sandyBinaryFile.copyTo(target)
        // The hash of the copy, so that the packaged file is the file which was checked
        val sha256 = MessageDigest.getInstance("SHA-256").digest(target.readBytes())
            .joinToString("") { "%02x".format(it) }
        if (sha256 != expectedSha256) {
            sandyDir.deleteRecursively()
            throw GradleException("$sandyBinaryFile is not the binary of sandy $sandyVersion for $platformName: " +
                    "its SHA-256 is $sha256, expected $expectedSha256. See src/main/resources/sandy/README.md.")
        }
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

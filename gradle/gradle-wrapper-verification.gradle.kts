import org.gradle.api.GradleException
import java.io.File
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Properties
import java.util.TreeMap

val gradleWrapperChecksums = layout.projectDirectory.file("gradle/wrapper/gradle-wrapper.sha256")
val expectedReleaseGradleVersion = providers.gradleProperty("releaseBuild.gradleVersion")

fun sha256(file: File): String {
    val digest = MessageDigest.getInstance("SHA-256")
    file.inputStream().use { input ->
        val buffer = ByteArray(8192)
        while (true) {
            val read = input.read(buffer)
            if (read == -1) {
                break
            }
            digest.update(buffer, 0, read)
        }
    }
    return digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) }
}

fun loadGradleWrapperProperties(): Properties {
    val wrapperProperties = Properties()
    val wrapperPropertiesFile = file("gradle/wrapper/gradle-wrapper.properties")
    if (wrapperPropertiesFile.isFile) {
        wrapperPropertiesFile.inputStream().use { wrapperProperties.load(it) }
    }
    return wrapperProperties
}

fun isSafeRelativePath(path: String): Boolean {
    if (path.isBlank() || path.contains('\\') || path.startsWith("/") || path.contains(":")) {
        return false
    }

    val segments = path.split("/")
    if (segments.any { it.isBlank() || it == "." || it == ".." }) {
        return false
    }

    val rootPath = rootDir.toPath().normalize()
    return rootPath.resolve(path).normalize().startsWith(rootPath)
}

tasks.register("verifyGradleWrapperSecurity") {
    group = "verification"
    description = "Verifies Gradle wrapper checksums and pinned distribution metadata."

    val requiredPaths = listOf(
        "gradlew",
        "gradlew.bat",
        "gradle/wrapper/gradle-wrapper.jar",
        "gradle/wrapper/gradle-wrapper.properties",
    )

    inputs.file(gradleWrapperChecksums)
    inputs.property("expectedReleaseGradleVersion", expectedReleaseGradleVersion.orElse(""))
    inputs.files(requiredPaths.map { file(it) })
    outputs.upToDateWhen { false }

    doLast {
        val checksumFile = gradleWrapperChecksums.asFile
        if (!checksumFile.isFile) {
            throw GradleException("Missing $checksumFile. Record the approved Gradle wrapper file checksums first.")
        }

        val requiredPathSet = requiredPaths.toSet()
        val expectedHashes = TreeMap<String, String>()
        val duplicatePaths = mutableSetOf<String>()
        val entryRegex = Regex("""^([0-9a-f]{64}) {2}(.+)$""")

        checksumFile.useLines(StandardCharsets.UTF_8) { lines ->
            lines.forEachIndexed { index, line ->
                val lineNumber = index + 1
                val trimmed = line.trim()
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    return@forEachIndexed
                }

                val match = entryRegex.matchEntire(line)
                    ?: throw GradleException(
                        "Invalid Gradle wrapper checksum entry at $checksumFile:$lineNumber. " +
                                "Expected '<sha256>  <path>'."
                    )

                val path = match.groupValues[2]
                if (!isSafeRelativePath(path)) {
                    throw GradleException("Invalid Gradle wrapper checksum path at $checksumFile:$lineNumber: $path")
                }
                if (expectedHashes.put(path, match.groupValues[1]) != null) {
                    duplicatePaths += path
                }
            }
        }

        val missingExpectedPaths = requiredPathSet.filterNot { expectedHashes.containsKey(it) }
        val unexpectedPaths = expectedHashes.keys.filterNot { requiredPathSet.contains(it) }
        val violations = mutableListOf<String>()

        if (duplicatePaths.isNotEmpty()) {
            violations += "Duplicate checksum entries: ${duplicatePaths.sorted().joinToString(", ")}"
        }
        if (missingExpectedPaths.isNotEmpty()) {
            violations += "Missing checksum entries: ${missingExpectedPaths.sorted().joinToString(", ")}"
        }
        if (unexpectedPaths.isNotEmpty()) {
            violations += "Unexpected checksum entries: ${unexpectedPaths.sorted().joinToString(", ")}"
        }

        requiredPaths.forEach { path ->
            val wrapperFile = file(path)
            if (!wrapperFile.isFile) {
                violations += "Missing Gradle wrapper file: $path"
                return@forEach
            }

            val expectedHash = expectedHashes[path] ?: return@forEach
            val actualHash = sha256(wrapperFile)
            if (actualHash != expectedHash) {
                violations += "$path expected $expectedHash but was $actualHash"
            }
        }

        val wrapperProperties = loadGradleWrapperProperties()
        val distributionUrl = wrapperProperties.getProperty("distributionUrl")
        val distributionSha256Sum = wrapperProperties.getProperty("distributionSha256Sum")
        val expectedGradleVersion = expectedReleaseGradleVersion.orNull?.trim()
        val distributionUrlRegex =
            Regex("""^https://services[.]gradle[.]org/distributions/gradle-[A-Za-z0-9][A-Za-z0-9_.+-]*-(bin|all)[.]zip$""")
        val sha256Regex = Regex("""^[0-9a-f]{64}$""")

        if (distributionUrl == null || !distributionUrlRegex.matches(distributionUrl)) {
            violations += "Gradle wrapper distributionUrl must use " +
                    "https://services.gradle.org/distributions/gradle-<version>-bin.zip or -all.zip"
        }
        if (distributionSha256Sum == null || !sha256Regex.matches(distributionSha256Sum)) {
            violations += "Gradle wrapper distributionSha256Sum must be a pinned lowercase SHA-256 value"
        }
        if (expectedGradleVersion.isNullOrEmpty()) {
            violations += "Missing releaseBuild.gradleVersion in gradle.properties"
        } else {
            val pinnedDistributionUrlRegex =
                Regex("""^https://services[.]gradle[.]org/distributions/gradle-${Regex.escape(expectedGradleVersion)}-(bin|all)[.]zip$""")
            if (distributionUrl != null && !pinnedDistributionUrlRegex.matches(distributionUrl)) {
                violations += "Gradle wrapper distributionUrl must use releaseBuild.gradleVersion $expectedGradleVersion"
            }
        }

        if (violations.isNotEmpty()) {
            throw GradleException(
                "Gradle wrapper security verification failed:\n" +
                        violations.joinToString("\n") { "  - $it" }
            )
        }

        logger.lifecycle("Verified Gradle wrapper checksums and distribution metadata.")
    }
}

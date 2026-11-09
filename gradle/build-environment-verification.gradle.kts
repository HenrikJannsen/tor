import org.gradle.api.GradleException
import org.gradle.api.provider.Provider

val expectedBuildJavaVersion = providers.gradleProperty("releaseBuild.javaVersion")
val expectedBuildJavaVendor = providers.gradleProperty("releaseBuild.javaVendor")
val expectedBuildGradleVersion = providers.gradleProperty("releaseBuild.gradleVersion")

val verifyBuildEnvironmentTask = tasks.register("verifyBuildEnvironment") {
    group = "verification"
    description = "Verifies the local Gradle and Java runtime meet the build environment of gradle.properties."

    inputs.property("expectedBuildJavaVersion", expectedBuildJavaVersion.orElse(""))
    inputs.property("expectedBuildJavaVendor", expectedBuildJavaVendor.orElse(""))
    inputs.property("expectedBuildGradleVersion", expectedBuildGradleVersion.orElse(""))
    outputs.upToDateWhen { false }
    // Copies of the values of the script, which the configuration cache cannot store. A configuration cache entry
    // belongs to one Gradle version.
    val javaVersionProperty = expectedBuildJavaVersion
    val javaVendorProperty = expectedBuildJavaVendor
    val gradleVersionProperty = expectedBuildGradleVersion
    val actualGradleVersion = gradle.gradleVersion

    doLast {
        fun requiredBuildEnvironmentProperty(propertyName: String, property: Provider<String>): String {
            val value = property.orNull?.trim()
            if (value.isNullOrEmpty()) {
                throw GradleException("Missing $propertyName in gradle.properties")
            }
            return value
        }

        // A build suffix such as +9 would not be compared, so the minimum may only hold version numbers.
        fun minimumVersionNumbers(minimum: String): List<Int> {
            val version = runCatching { Runtime.Version.parse(minimum) }.getOrNull()
            if (version == null || version.pre().isPresent || version.build().isPresent || version.optional().isPresent) {
                throw GradleException("releaseBuild.javaVersion must be a Java version such as 21.0.13.0.3, but is $minimum")
            }
            return version.version()
        }

        // Compares the version numbers one by one, a missing number counting as 0, so 21.0.14 is above 21.0.13.0.3
        fun isAtLeast(actual: List<Int>, minimum: List<Int>): Boolean {
            for (index in 0 until maxOf(actual.size, minimum.size)) {
                val difference = actual.getOrElse(index) { 0 } - minimum.getOrElse(index) { 0 }
                if (difference != 0) {
                    return difference > 0
                }
            }
            return true
        }

        val expectedJavaVersion = requiredBuildEnvironmentProperty("releaseBuild.javaVersion", javaVersionProperty)
        val expectedJavaVendor = requiredBuildEnvironmentProperty("releaseBuild.javaVendor", javaVendorProperty)
        val expectedGradleVersion = requiredBuildEnvironmentProperty("releaseBuild.gradleVersion", gradleVersionProperty)
        val minimumJavaVersionNumbers = minimumVersionNumbers(expectedJavaVersion)
        val actualJavaVersion = Runtime.version()
        val actualJavaVendor = System.getProperty("java.vendor")
        val actualJavaVendorVersion = System.getProperty("java.vendor.version")
        val violations = mutableListOf<String>()

        // Azul builds a Java update more than once, for example 21.0.13 as 21.0.13+9 and as 21.0.13.0.3+1, and not for
        // every platform at the same time. Every build of the feature version at or above the minimum passes, so each
        // platform can use the newest build it has.
        if (actualJavaVersion.feature() != minimumJavaVersionNumbers.first() ||
            !isAtLeast(actualJavaVersion.version(), minimumJavaVersionNumbers)) {
            violations += "Java version expected Java ${minimumJavaVersionNumbers.first()} at or above " +
                    "$expectedJavaVersion but was $actualJavaVersion"
        }
        if (actualJavaVendor != expectedJavaVendor) {
            violations += "Java vendor expected $expectedJavaVendor but was $actualJavaVendor"
        }
        if (actualGradleVersion != expectedGradleVersion) {
            violations += "Gradle version expected $expectedGradleVersion but was $actualGradleVersion"
        }

        if (violations.isNotEmpty()) {
            throw GradleException(
                "Build environment verification failed:\n" +
                        violations.joinToString("\n") { "  - $it" }
            )
        }

        // The build of the JDK is not checked, so the log names it
        logger.lifecycle(
            "Verified build environment: Gradle $actualGradleVersion, Java $actualJavaVersion " +
                    "(${listOfNotNull(actualJavaVendor, actualJavaVendorVersion).joinToString(", ")})."
        )
    }
}

tasks.register("verifyReleaseEnvironment") {
    group = "verification"
    description = "Verifies the local Gradle and Java runtime meet the release build environment of gradle.properties."
    dependsOn(verifyBuildEnvironmentTask)
}

tasks.matching { it.name == "check" }.configureEach {
    dependsOn(verifyBuildEnvironmentTask)
}

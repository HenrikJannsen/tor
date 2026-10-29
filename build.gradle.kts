import java.util.*

plugins {
    java
    id("bisq.gradle.maven_publisher.LocalMavenPublishPlugin")
}

apply(from = "gradle/dependency-security-overrides.gradle.kts")
apply(from = "gradle/build-environment-verification.gradle.kts")
apply(from = "gradle/dependency-verification.gradle.kts")
apply(from = "gradle/gradle-wrapper-verification.gradle.kts")
apply(from = "gradle/github-actions-verification.gradle.kts")

val properties = Properties().apply {
    file("gradle.properties").inputStream().use { load(it) }
}
version = properties.getProperty("version", "unspecified")

tasks.named("clean") {
    dependsOn(subprojects.map {
        it.tasks.named("clean")
    })
}
tasks.named("build") {
    dependsOn(subprojects.map {
        it.tasks.named("build")
    })
}

tasks.named("check") {
    dependsOn("verifyGradleWrapperSecurity")
    dependsOn("verifyGithubActionsSecurity")
    dependsOn("verifyDependencySignaturePolicy")
    // The tests of the Gradle plugins. Run from here, their dependencies are verified with the metadata of this build.
    // An app which includes this build has its own build-logic, so the build is found by its directory, not its name.
    dependsOn(gradle.includedBuilds
        .filter { it.projectDir.canonicalFile == file("build-logic").canonicalFile }
        .map { it.task(":check") })
}

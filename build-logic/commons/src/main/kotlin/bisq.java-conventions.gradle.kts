import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.api.tasks.testing.logging.TestLogEvent

plugins {
    `java-library`
}

repositories {
    mavenCentral()
}

val pinnedJavaLanguageVersion = providers.gradleProperty("releaseBuild.javaVersion")
    .map { it.substringBefore('.').toInt() }
    .orElse(21)

java {
    toolchain {
        languageVersion.set(pinnedJavaLanguageVersion.map { JavaLanguageVersion.of(it) })
    }
}

// Holds the commit hash of common, which changes with every commit. Without this, every commit would rerun every
// test task that has common on its runtime classpath.
normalization {
    runtimeClasspath {
        ignore("bisq/common/application/build-commit.properties")
    }
}

// Shadow reads its dependencies with the normalization above, so a fat jar would keep an old commit hash. Track them by
// content as well.
pluginManager.withPlugin("com.gradleup.shadow") {
    tasks.named("shadowJar") {
        inputs.files(configurations.named("runtimeClasspath"))
            .withPropertyName("runtimeClasspathContent")
            .withPathSensitivity(PathSensitivity.NAME_ONLY)
    }
}

tasks {
    test {
        useJUnitPlatform()
        testLogging {
            events(TestLogEvent.FAILED, TestLogEvent.SKIPPED)
            exceptionFormat = TestExceptionFormat.FULL
        }
    }

    withType<Jar> {
        isPreserveFileTimestamps = false
        isReproducibleFileOrder = true
        // Pinned so the entry modes don't follow the umask of the machine that compiled the classes
        // and checked out the resources.
        dirPermissions { unix("0755") }
        filePermissions { unix("0644") }
    }
}

// The version constraints of the Tor build (tor-platform) for the class paths of its own modules. They are not
// published with a module, so they do not change the versions which an application resolves.
val torPlatform: Configuration = configurations.create("torPlatform") {
    isCanBeResolved = false
    isCanBeConsumed = false
}
configurations.matching { it.isCanBeResolved && it.name.endsWith("Classpath") }.configureEach {
    extendsFrom(torPlatform)
}

val versionCatalog = extensions.getByType<VersionCatalogsExtension>().named("libs")
dependencies {
    versionCatalog.findLibrary("google-guava").ifPresent {
        implementation(it)
    }

    versionCatalog.findLibrary("findbugs-jsr305").ifPresent {
        compileOnly(it)
        testCompileOnly(it)
    }

    versionCatalog.findLibrary("lombok").ifPresent {
        compileOnly(it)
        annotationProcessor(it)
        testAnnotationProcessor(it)
        testCompileOnly(it)
    }

    versionCatalog.findLibrary("slf4j-api").ifPresent {
        implementation(it)
    }

    // The application chooses the logging backend, on Android another one. The tests check the log output with logback.
    versionCatalog.findLibrary("logback-core").ifPresent {
        testImplementation(it)
    }
    versionCatalog.findLibrary("logback-classic").ifPresent {
        testImplementation(it)
    }

    versionCatalog.findLibrary("junit-jupiter").ifPresent {
        testImplementation(it)
    }
    versionCatalog.findLibrary("junit-platform-launcher").ifPresent {
        testRuntimeOnly(it)
    }

    versionCatalog.findLibrary("assertj-core").ifPresent {
        testImplementation(it)
    }

    versionCatalog.findLibrary("mockito").ifPresent {
        testImplementation(it)
    }
}

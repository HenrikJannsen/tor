package bisq.gradle.tor_binary

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction

/**
 * Fails the build if the tor executable of the expert bundle is not of the version which tor.binaryVersion of
 * gradle.properties names. That property is set by hand, and Bisq 2 shows it as the version of the bundled Tor.
 */
abstract class TorBinaryVersionCheckTask : DefaultTask() {
    companion object {
        // Tor compiles " (on Tor <version> <git revision>)" into every build. Other version strings of the executable,
        // for example "Tor 0.1.2.17 and later", name other versions.
        private val BUILD_VERSION = Regex("""\(on Tor (\d+\.\d+\.\d+\.\d+(?:-[0-9a-z]+)?) """)

        fun buildVersions(executable: ByteArray): Set<String> =
            BUILD_VERSION.findAll(String(executable, Charsets.ISO_8859_1))
                .map { it.groupValues[1] }
                .toSortedSet()
    }

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val torExecutable: RegularFileProperty

    @get:Input
    abstract val expectedVersion: Property<String>

    @get:OutputFile
    abstract val resultFile: RegularFileProperty

    @TaskAction
    fun verify() {
        val executable = torExecutable.get().asFile
        val versions = buildVersions(executable.readBytes())
        if (versions.size != 1) {
            throw GradleException("$executable must name exactly one Tor build version, but names $versions.")
        }
        val version = versions.single()
        if (version != expectedVersion.get()) {
            throw GradleException("The Tor expert bundle contains tor $version, but tor.binaryVersion in " +
                    "gradle.properties is ${expectedVersion.get()}.")
        }
        resultFile.get().asFile.writeText(version)
    }
}

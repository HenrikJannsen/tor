package bisq.gradle.tor_binary

import bisq.gradle.common.OS
import bisq.gradle.common.Platform
import bisq.gradle.common.getOS
import bisq.gradle.common.getPlatform
import bisq.gradle.tasks.download.SignedBinaryDownloader
import org.gradle.api.Project
import org.gradle.api.file.RegularFile
import org.gradle.api.provider.Provider
import org.gradle.api.tasks.Sync
import org.gradle.api.tasks.TaskProvider
import org.gradle.api.tasks.bundling.Zip
import org.gradle.kotlin.dsl.register

class TorBinaryPackager(
    private val project: Project,
    private val torBinaryDownloader: SignedBinaryDownloader,
    private val torBinaryVersion: Provider<String>
) {

    companion object {
        private const val ARCHIVE_EXTRACTION_DIR = "${BisqTorBinaryPlugin.DOWNLOADS_DIR}/extracted"
        private const val PROCESSED_DIR = "${BisqTorBinaryPlugin.DOWNLOADS_DIR}/processed"

        /**
         * The platform of the expert bundle which a build on [buildPlatform] packages files of. There is no bundle for
         * Linux ARM64. A Linux build packages only the pluggable transports of the bundle, and on ARM64 only their
         * configuration pt_config.json, which does not depend on the architecture, so it takes the bundle of Linux
         * x86_64. Every other platform needs the programs of its own bundle; Windows ARM64 has none.
         */
        fun bundlePlatform(buildPlatform: Platform): Platform =
            if (buildPlatform == Platform.LINUX_ARM_64) Platform.LINUX_X86_64 else buildPlatform
    }

    fun registerTasks() {
        val unpackTarTask: TaskProvider<Sync> = project.tasks.register<Sync>("unpackTorBinaryTar") {
            dependsOn(torBinaryDownloader.verifySignatureTask)

            val tarFile: Provider<RegularFile> = torBinaryDownloader.verifySignatureTask.flatMap { it.fileToVerify }
            // tarTree resolves the provider lazily. A lambda which uses the project would break the configuration cache.
            from(project.tarTree(tarFile))

            into(project.layout.buildDirectory.dir(ARCHIVE_EXTRACTION_DIR))
        }

        val verifyTorBinaryVersion: TaskProvider<TorBinaryVersionCheckTask> =
            project.tasks.register<TorBinaryVersionCheckTask>("verifyTorBinaryVersion") {
                dependsOn(unpackTarTask)
                val torExecutableName = if (getOS() == OS.WINDOWS) "tor.exe" else "tor"
                val buildDirectory = project.layout.buildDirectory
                torExecutable.set(buildDirectory.file("${ARCHIVE_EXTRACTION_DIR}/tor/$torExecutableName"))
                expectedVersion.set(torBinaryVersion)
                resultFile.set(buildDirectory.file("${BisqTorBinaryPlugin.DOWNLOADS_DIR}/tor-version.result"))
            }

        val processUnpackedTorBinaryTar: TaskProvider<Sync> =
            project.tasks.register<Sync>("processUnpackedTorBinaryTar") {
                dependsOn(unpackTarTask)

                if (getOS() == OS.LINUX) {
                    // The Bisq packages for Linux depend on the tor package of the system, so only the pluggable
                    // transports of the expert bundle are bundled. The bundle has only x86_64 programs, so on ARM64
                    // only their configuration is bundled, and the programs come from the system.
                    val isX86 = getPlatform() == Platform.LINUX_X86_64
                    from(project.layout.buildDirectory.dir("${ARCHIVE_EXTRACTION_DIR}/tor")) {
                        include("pluggable_transports/pt_config.json")
                        if (isX86) {
                            include("pluggable_transports/lyrebird", "pluggable_transports/conjure-client")
                        }
                    }
                } else {
                    from(project.layout.buildDirectory.dir("${ARCHIVE_EXTRACTION_DIR}/data"))
                    from(project.layout.buildDirectory.dir("${ARCHIVE_EXTRACTION_DIR}/tor"))
                }
                into(project.layout.buildDirectory.dir(PROCESSED_DIR))
            }

        val signMacOsTorBinary: TaskProvider<SignMacOsTorBinaryTask> =
            project.tasks.register<SignMacOsTorBinaryTask>("signMacOsTorBinary") {
                dependsOn(processUnpackedTorBinaryTar)
                onlyIf { getOS() == OS.MAC_OS }
                outputs.upToDateWhen { false }
                torBinaryDir.set(project.layout.buildDirectory.dir(PROCESSED_DIR))
            }

        val packageTorBinary: TaskProvider<Zip> =
            project.tasks.register<Zip>("packageTorBinary") {
                dependsOn(verifyTorBinaryVersion)
                dependsOn(processUnpackedTorBinaryTar)
                if (getOS() == OS.MAC_OS) {
                    dependsOn(signMacOsTorBinary)
                }

                archiveFileName.set("tor.zip")
                destinationDirectory.set(project.layout.buildDirectory.dir("generated/src/main/resources"))
                from(project.layout.buildDirectory.dir(PROCESSED_DIR))

                // This archive ends up as a resource inside tor.jar, so it has to be reproducible too.
                isPreserveFileTimestamps = false
                isReproducibleFileOrder = true
                // Pinned, so that the modes do not follow the Gradle version: the expert bundle stores 0600 and 0700,
                // which Gradle 8.9 copies and Gradle 9.0 writes as 0644 and 0755. TorBinaryZipExtractor sets the
                // executable bits of the programs by their names; it does not read these modes.
                dirPermissions { unix("0755") }
                filePermissions { unix("0644") }
            }

        val processResourcesTask = project.tasks.named("processResources")
        processResourcesTask.configure {
            dependsOn(packageTorBinary)
        }
    }
}

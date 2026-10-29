package bisq.gradle.tor_binary

import bisq.gradle.common.OS
import bisq.gradle.common.getOS
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

                from(project.layout.buildDirectory.dir("${ARCHIVE_EXTRACTION_DIR}/data"))
                from(project.layout.buildDirectory.dir("${ARCHIVE_EXTRACTION_DIR}/tor"))
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

        if (getOS() == OS.LINUX) {
            // The Bisq package depends on Tor and the OS's package manager installs Tor and its dependencies for us.
            return
        }

        val processResourcesTask = project.tasks.named("processResources")
        processResourcesTask.configure {
            dependsOn(packageTorBinary)
        }
    }
}

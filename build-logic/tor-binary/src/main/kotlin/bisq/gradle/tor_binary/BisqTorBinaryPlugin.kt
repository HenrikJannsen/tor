package bisq.gradle.tor_binary

import bisq.gradle.common.getPlatform
import bisq.gradle.tasks.PgpFingerprint
import bisq.gradle.tasks.download.SignedBinaryDownloader
import org.gradle.api.GradleException
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.create

class BisqTorBinaryPlugin : Plugin<Project> {
    companion object {
        const val DOWNLOADS_DIR = "tor_binary/downloads"
    }

    override fun apply(project: Project) {
        val extension = project.extensions.create<BisqTorBinaryPluginExtension>("tor")
        val platform = getPlatform()
        val platformName = platform.platformName

        val torBinaryDownloader = SignedBinaryDownloader(
            project = project,
            binaryName = "Tor",
            version = extension.bundleVersion.getting(platformName).orElse(extension.version),

            platform = platform,
            // A valid signature alone would also accept the signed bundle of another release
            sha256 = extension.bundleSha256.map { pins ->
                pins[platformName] ?: throw GradleException("No SHA-256 of the Tor expert bundle for " +
                        "$platformName is pinned: set tor.bundleSha256.$platformName in gradle.properties.")
            },
            perPlatformUrlProvider = { version -> TorBinaryUrlProvider(version) },
            downloadDirectory = DOWNLOADS_DIR,

            pgpFingerprintToKeyUrlMap = mapOf(
                Pair(
                    PgpFingerprint.normalize("EF6E 286D DA85 EA2A 4BA7  DE68 4E2C 6E87 9329 8290"),
                    this::class.java.getResource("/Tor_Browser_Developers_(signing_key).asc")!!.toString(),
                )
            )
        )
        torBinaryDownloader.registerTasks()

        val torBinaryPackager = TorBinaryPackager(project, torBinaryDownloader, extension.binaryVersion)
        torBinaryPackager.registerTasks()
    }
}
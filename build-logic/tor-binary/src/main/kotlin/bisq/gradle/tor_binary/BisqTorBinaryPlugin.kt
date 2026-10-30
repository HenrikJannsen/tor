package bisq.gradle.tor_binary

import bisq.gradle.common.getPlatform
import bisq.gradle.tasks.PgpFingerprint
import bisq.gradle.tasks.download.SignedBinaryDownloader
import org.gradle.api.GradleException
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.create
import java.util.Base64

class BisqTorBinaryPlugin : Plugin<Project> {
    companion object {
        const val DOWNLOADS_DIR = "tor_binary/downloads"
    }

    override fun apply(project: Project) {
        val extension = project.extensions.create<BisqTorBinaryPluginExtension>("tor")
        val platform = getPlatform()

        val torBinaryDownloader = SignedBinaryDownloader(
            project = project,
            binaryName = "Tor",
            version = extension.version,

            platform = platform,
            signedChecksumsBase64 = extension.version.map { resourceBase64(it, "sha256sums-signed-build.txt") },
            signedChecksumsSignatureBase64 = extension.version.map {
                resourceBase64(it, "sha256sums-signed-build.txt.asc")
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

private fun resourceBase64(version: String, fileName: String): String {
    val path = "/torbrowser-$version/$fileName"
    val stream = BisqTorBinaryPlugin::class.java.getResourceAsStream(path)
        ?: throw GradleException("Missing signed Tor checksums resource $path for tor.version=$version")
    return stream.use { Base64.getEncoder().encodeToString(it.readBytes()) }
}

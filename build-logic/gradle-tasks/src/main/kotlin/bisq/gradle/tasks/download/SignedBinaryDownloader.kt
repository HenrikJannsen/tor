package bisq.gradle.tasks.download

import bisq.gradle.common.Platform
import bisq.gradle.tasks.PerPlatformUrlProvider
import bisq.gradle.tasks.signature.SignatureVerificationTask
import org.gradle.api.GradleException
import org.gradle.api.Project
import org.gradle.api.provider.Provider
import org.gradle.api.tasks.TaskProvider
import org.gradle.kotlin.dsl.register
import java.net.URI
import java.security.MessageDigest

class SignedBinaryDownloader(
    private val project: Project,
    private val binaryName: String,
    private val version: Provider<String>,

    // The platform of the binary to download
    private val platform: Platform,
    // The SHA-256 of the binary of that platform and version
    private val sha256: Provider<String>,
    private val perPlatformUrlProvider: (String) -> PerPlatformUrlProvider,
    private val downloadDirectory: String,

    private val pgpFingerprintToKeyUrlMap: Map<String, String>
) {
    lateinit var verifySignatureTask: TaskProvider<SignatureVerificationTask>
    private val downloadTaskFactory = DownloadTaskFactory(project, downloadDirectory)

    fun registerTasks() {
        // Evaluated when a task needs the binary, so a build for a platform without one fails only there
        val binaryDownloadUrl: Provider<String> = version.map {
            perPlatformUrlProvider(it).urlFor(platform)
                ?: throw GradleException("There is no $binaryName binary for the platform ${platform.platformName}.")
        }
        val binaryDownloadTask =
            downloadTaskFactory.registerDownloadTask("download${binaryName}Binary", binaryDownloadUrl)

        val signatureDownloadUrl: Provider<String> = binaryDownloadUrl.map { "$it.asc" }
        val signatureDownloadTask =
            downloadTaskFactory.registerDownloadTask("download${binaryName}Signature", signatureDownloadUrl)

        verifySignatureTask = project.tasks.register<SignatureVerificationTask>("verify${binaryName}Binary") {
            dependsOn(binaryDownloadTask)

            fileToVerify.set(binaryDownloadTask.flatMap { it.outputFile })
            expectedSha256.set(sha256)
            detachedSignatureFile.set(signatureDownloadTask.flatMap { it.outputFile })
            pgpFingerprintToKeyUrl.set(pgpFingerprintToKeyUrlMap)
            pgpFingerprintToKeySha256.set(pgpFingerprintToKeyUrlMap.mapValues { (_, keyUrl) -> sha256Of(keyUrl) })

            resultFile.set(project.layout.buildDirectory.file("${downloadDirectory}/sha256.result"))
        }
    }

    private fun sha256Of(keyUrl: String): String {
        val keyBytes = URI.create(keyUrl).toURL().readBytes()
        return MessageDigest.getInstance("SHA-256").digest(keyBytes).joinToString("") { "%02x".format(it) }
    }
}

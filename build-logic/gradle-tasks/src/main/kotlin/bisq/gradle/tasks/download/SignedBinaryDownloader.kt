package bisq.gradle.tasks.download

import bisq.gradle.tasks.PerPlatformUrlProvider
import bisq.gradle.tasks.signature.SignatureVerificationTask
import org.gradle.api.Project
import org.gradle.api.provider.Property
import org.gradle.api.provider.Provider
import org.gradle.api.tasks.TaskProvider
import org.gradle.kotlin.dsl.register
import java.net.URI
import java.security.MessageDigest

class SignedBinaryDownloader(
    private val project: Project,
    private val binaryName: String,
    private val version: Property<String>,

    private val perPlatformUrlProvider: (String) -> PerPlatformUrlProvider,
    private val downloadDirectory: String,

    private val pgpFingerprintToKeyUrlMap: Map<String, String>
) {
    lateinit var verifySignatureTask: TaskProvider<SignatureVerificationTask>
    private val downloadTaskFactory = DownloadTaskFactory(project, downloadDirectory)

    fun registerTasks() {
        val binaryDownloadUrl: Provider<String> = version.map { perPlatformUrlProvider(it).url }
        val binaryDownloadTask =
            downloadTaskFactory.registerDownloadTask("download${binaryName}Binary", binaryDownloadUrl)

        val signatureDownloadUrl: Provider<String> = binaryDownloadUrl.map { "$it.asc" }
        val signatureDownloadTask =
            downloadTaskFactory.registerDownloadTask("download${binaryName}Signature", signatureDownloadUrl)

        verifySignatureTask = project.tasks.register<SignatureVerificationTask>("verify${binaryName}Binary") {
            dependsOn(binaryDownloadTask)

            fileToVerify.set(binaryDownloadTask.flatMap { it.outputFile })
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

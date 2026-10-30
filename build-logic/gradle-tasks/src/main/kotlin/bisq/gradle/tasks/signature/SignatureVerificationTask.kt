package bisq.gradle.tasks.signature

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.MapProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.TaskAction
import java.io.File
import java.security.MessageDigest
import java.util.Base64

abstract class SignatureVerificationTask : DefaultTask() {

    @get:InputFile
    abstract val fileToVerify: RegularFileProperty

    // Exact bytes of the release's signed checksum file, encoded for Gradle task input tracking
    @get:Input
    abstract val signedChecksumsBase64: Property<String>

    @get:Input
    abstract val signedChecksumsSignatureBase64: Property<String>

    @get:InputFile
    abstract val detachedSignatureFile: RegularFileProperty

    // Not an input: the URL names the jar of the build logic, which differs per checkout, and the content of the key
    // decides the result. Its hash below is the input.
    @get:Internal
    abstract val pgpFingerprintToKeyUrl: MapProperty<String, String >

    // The SHA-256 of each key file, so that a changed key, for example after Tor revoked a subkey, runs the
    // verification again instead of reusing the result of the old key.
    @get:Input
    abstract val pgpFingerprintToKeySha256: MapProperty<String, String>

    @get:OutputFile
    abstract val resultFile: RegularFileProperty

    @TaskAction
    fun verify() {
        val file = fileToVerify.get().asFile
        val signatureVerifier = SignatureVerifier(pgpFingerprintToKeyUrl.get())
        val checksums = Base64.getDecoder().decode(signedChecksumsBase64.get())
        val checksumsSignature = Base64.getDecoder().decode(signedChecksumsSignatureBase64.get())
        if (!signatureVerifier.verifySignature(checksums, checksumsSignature)) {
            fail("Signature verification failed for the Tor release checksum file.")
        }

        val checksumEntry = Regex("^([0-9a-f]{64})  (.+)$")
        val expectedHashes = checksums.toString(Charsets.UTF_8).lineSequence()
            .mapNotNull { checksumEntry.matchEntire(it) }
            .filter { it.groupValues[2] == file.name }
            .map { it.groupValues[1] }
            .toList()
        if (expectedHashes.size != 1) {
            fail("Expected exactly one signed SHA-256 entry for ${file.name}, found ${expectedHashes.size}.")
        }

        val sha256 = sha256Of(file)
        if (sha256 != expectedHashes.single()) {
            fail("${file.absolutePath} has the SHA-256 $sha256, but the signed SHA-256 is " +
                    "${expectedHashes.single()}.")
        }

        val isSignatureValid = signatureVerifier.verifySignature(
            signatureFile = detachedSignatureFile.get().asFile,
            fileToVerify = fileToVerify.get().asFile
        )

        resultFile.get().asFile.writeText("$isSignatureValid")

        if (!isSignatureValid) {
            throw GradleException(
                "Signature verification failed for ${fileToVerify.get().asFile.absolutePath}. Only a key of the " +
                        "pinned certificate which was valid for signing when the signature was made is accepted."
            )
        }
    }

    private fun fail(message: String): Nothing {
        resultFile.get().asFile.writeText("false")
        throw GradleException(message)
    }

    private fun sha256Of(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { inputStream ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val read = inputStream.read(buffer)
                if (read < 0) break
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
}

package bisq.gradle.tasks.signature

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.RegularFile
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.MapProperty
import org.gradle.api.provider.Property
import org.gradle.api.provider.Provider
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.TaskAction
import java.io.File
import java.net.URL
import java.security.MessageDigest

abstract class SignatureVerificationTask : DefaultTask() {

    @get:InputFile
    abstract val fileToVerify: RegularFileProperty

    // A valid signature alone also accepts an older release of the same signer, so the file is pinned by its hash
    @get:Input
    abstract val expectedSha256: Property<String>

    @get:InputFile
    abstract val detachedSignatureFile: RegularFileProperty

    // Not an input: the URL names the jar of the build logic, which differs per checkout, and the content of the key
    // decides the result. The hashes below are the input.
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
        val sha256 = sha256Of(file)
        if (sha256 != expectedSha256.get()) {
            resultFile.get().asFile.writeText("false")
            throw GradleException("${file.absolutePath} has the SHA-256 $sha256, but the pinned SHA-256 is " +
                    "${expectedSha256.get()}.")
        }

        val signatureVerifier = SignatureVerifier(pgpFingerprintToKeyUrl.get())
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

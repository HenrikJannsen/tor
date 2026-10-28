package bisq.gradle.tasks.signature

import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.bc.BcOpenPGPImplementation
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection
import org.bouncycastle.util.encoders.Hex
import org.gradle.api.GradleException
import java.io.ByteArrayInputStream
import java.net.URI
import java.util.Date

class PpgPublicKeyParser(
    private val primaryKeyFingerprint: String,
    private val keyUrl: String
) {
    private var certificate: OpenPGPCertificate? = null

    fun parse() {
        certificate = null
        val keyFile = URI.create(keyUrl).toURL().readBytes()
        val keyFileInputStream = ByteArrayInputStream(keyFile)
        PGPUtil.getDecoderStream(keyFileInputStream).use { decoderInputStream ->
            val rings = JcaPGPPublicKeyRingCollection(decoderInputStream).keyRings.asSequence().toList()
            // The decoder of an armored file skips the lines before the first armor header line and ends with the
            // tail line of that block, so text or a second key block around it would be ignored without a word.
            if (decoderInputStream is ArmoredInputStream &&
                hasDataOutsideTheKeyBlock(keyFile, keyFileInputStream.readAllBytes())) {
                throw GradleException("$keyUrl has data outside its armored key block, for example a second key " +
                        "block, which the build would ignore. The file must contain exactly one key block.")
            }
            if (rings.size != 1) {
                throw GradleException("$keyUrl must contain exactly one primary key, but contains ${rings.size}.")
            }
            val ring = rings.single()
            if (Hex.toHexString(ring.publicKey.fingerprint) != primaryKeyFingerprint) {
                throw GradleException("$keyUrl has invalid fingerprint.")
            }
            // A revocation of the primary key retires all its subkeys, so no key of the file can be trusted (fail closed)
            if (ring.publicKey.hasRevocation()) {
                throw GradleException("$keyUrl contains a revocation of the primary key. We do not trust any of its keys.")
            }
            certificate = OpenPGPCertificate(ring, BcOpenPGPImplementation())
        }
    }

    /**
     * The keys of the certificate which could make a valid signature at [signatureCreationTime], by their key IDs. The
     * certificate API verifies the self-signatures, the subkey bindings and the back-signatures of signing subkeys, and
     * applies the signed key flags and the expiry at that time. Evaluated at the creation time of a signature, a bundle
     * signed with a subkey which has expired since still verifies, so that an older release can be built again.
     *
     * The key file keeps revoked subkeys: the Tor key file holds a signing subkey which was revoked in 2015 as
     * compromised. A subkey with any revocation is not trusted for any signature (fail closed).
     */
    fun signingKeysAt(signatureCreationTime: Date): Map<Long, PGPPublicKey> {
        val certificate = checkNotNull(certificate) { "The key file is not parsed." }
        // getSigningKeys does not apply the expiry of the primary key to its subkeys. The expiry comes from the newest
        // self-signature of the primary key: a key file such as Tor's holds no older one, so the primary key is not
        // bound at the time of a signature which is older than that self-signature.
        val primaryKeyExpiration: Date? = certificate.expirationTime
        if (primaryKeyExpiration != null && !signatureCreationTime.before(primaryKeyExpiration)) {
            return emptyMap()
        }
        return certificate.getSigningKeys(signatureCreationTime)
            .map { key -> key.pgpPublicKey }
            .filter { key -> !key.hasRevocation() }
            .associateBy { key -> key.keyID }
    }

    private companion object {
        const val ARMOR_HEADER_LINE = "-----BEGIN PGP PUBLIC KEY BLOCK-----"

        // Blank lines around the block are no data.
        fun hasDataOutsideTheKeyBlock(keyFile: ByteArray, afterTheKeyBlock: ByteArray): Boolean =
            !String(keyFile, Charsets.US_ASCII).trimStart().startsWith(ARMOR_HEADER_LINE) ||
                    String(afterTheKeyBlock, Charsets.US_ASCII).isNotBlank()
    }
}

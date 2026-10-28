/*
 * This file is part of Bisq.
 *
 * Bisq is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at
 * your option) any later version.
 *
 * Bisq is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Bisq. If not, see <http://www.gnu.org/licenses/>.
 */

package bisq.gradle.tasks.signature;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Date;

/**
 * A primary key with one subkey, made with Bouncy Castle for the tests of the signature check. From the tests of Bisq
 * 2 commit 1360a2e3e8.
 */
record KeyFixture(PGPKeyPair primary, PGPKeyPair subkey, PGPPublicKeyRing ring) {
    static final Date CREATED = Date.from(Instant.parse("2025-01-01T00:00:00Z"));

    static KeyFixture create(long subkeyExpiry, boolean crossCertification, int flags) throws Exception {
        return create(0, subkeyExpiry, crossCertification, flags);
    }

    /**
     * @param primaryExpiry the lifetime of the primary key in seconds, 0 for none
     * @param subkeyExpiry  the lifetime of the subkey in seconds, 0 for none
     */
    static KeyFixture create(long primaryExpiry, long subkeyExpiry, boolean crossCertification, int flags)
            throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        PGPKeyPair primary = new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, generator.generateKeyPair(), CREATED);
        PGPKeyPair subkey = new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, generator.generateKeyPair(), CREATED);
        PGPSignatureSubpacketGenerator primaryPackets = new PGPSignatureSubpacketGenerator();
        primaryPackets.setKeyFlags(false, KeyFlags.CERTIFY_OTHER);
        primaryPackets.setSignatureCreationTime(false, CREATED);
        primaryPackets.setKeyExpirationTime(false, primaryExpiry);
        PGPKeyRingGenerator ring = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, primary,
                "Review fixture", new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
                primaryPackets.generate(), null, signer(), null);
        PGPSignatureSubpacketGenerator subkeyPackets = new PGPSignatureSubpacketGenerator();
        subkeyPackets.setSignatureCreationTime(false, CREATED);
        subkeyPackets.setKeyFlags(false, flags);
        subkeyPackets.setKeyExpirationTime(false, subkeyExpiry);
        if (crossCertification) {
            PGPSignatureGenerator backSignature = new PGPSignatureGenerator(signer());
            backSignature.init(PGPSignature.PRIMARYKEY_BINDING, subkey.getPrivateKey());
            PGPSignatureSubpacketGenerator backPackets = new PGPSignatureSubpacketGenerator();
            backPackets.setSignatureCreationTime(false, CREATED);
            backSignature.setHashedSubpackets(backPackets.generate());
            subkeyPackets.addEmbeddedSignature(false,
                    backSignature.generateCertification(primary.getPublicKey(), subkey.getPublicKey()));
        }
        ring.addSubKey(subkey, subkeyPackets.generate(), null);
        return new KeyFixture(primary, subkey, ring.generatePublicKeyRing());
    }

    /**
     * @param reason the revocation reason, or null for none, which makes it a hard revocation
     */
    PGPPublicKeyRing ringWithRevokedSubkey(Date time, Byte reason) throws Exception {
        PGPSignatureGenerator generator = new PGPSignatureGenerator(signer());
        generator.init(PGPSignature.SUBKEY_REVOCATION, primary.getPrivateKey());
        PGPSignatureSubpacketGenerator packets = new PGPSignatureSubpacketGenerator();
        packets.setSignatureCreationTime(false, time);
        if (reason != null) {
            packets.setRevocationReason(false, reason, "");
        }
        generator.setHashedSubpackets(packets.generate());
        PGPPublicKey revoked = PGPPublicKey.addCertification(ring.getPublicKey(subkey.getKeyID()),
                generator.generateCertification(primary.getPublicKey(), subkey.getPublicKey()));
        return PGPPublicKeyRing.insertPublicKey(ring, revoked);
    }

    PGPPublicKeyRing ringWithRevokedPrimaryKey() throws Exception {
        PGPSignatureGenerator generator = new PGPSignatureGenerator(signer());
        generator.init(PGPSignature.KEY_REVOCATION, primary.getPrivateKey());
        PGPSignatureSubpacketGenerator packets = new PGPSignatureSubpacketGenerator();
        packets.setSignatureCreationTime(false, CREATED);
        generator.setHashedSubpackets(packets.generate());
        PGPPublicKey revoked = PGPPublicKey.addCertification(ring.getPublicKey(),
                generator.generateCertification(ring.getPublicKey()));
        return PGPPublicKeyRing.insertPublicKey(ring, revoked);
    }

    /**
     * An armored detached signature of data, as the Tor Browser developers publish it next to a bundle.
     */
    static byte[] armoredSignature(PGPKeyPair signingKey, int signatureType, Date creationTime, byte[] data)
            throws Exception {
        PGPSignatureGenerator generator = new PGPSignatureGenerator(signer());
        generator.init(signatureType, signingKey.getPrivateKey());
        PGPSignatureSubpacketGenerator packets = new PGPSignatureSubpacketGenerator();
        packets.setSignatureCreationTime(false, creationTime);
        packets.setIssuerFingerprint(false, signingKey.getPublicKey());
        packets.setIssuerKeyID(false, signingKey.getKeyID());
        generator.setHashedSubpackets(packets.generate());
        generator.update(data);
        PGPSignature signature = generator.generate();
        ByteArrayOutputStream armored = new ByteArrayOutputStream();
        try (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(armored)) {
            signature.encode(armoredOutputStream);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return armored.toByteArray();
    }

    static BcPGPContentSignerBuilder signer() {
        return new BcPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA256);
    }
}

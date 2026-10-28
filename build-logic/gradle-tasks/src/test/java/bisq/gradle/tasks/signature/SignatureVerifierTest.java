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

import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Date;
import java.util.Map;

import static bisq.gradle.tasks.signature.KeyFixture.CREATED;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignatureVerifierTest {
    private static final Date BEFORE_EXPIRY = new Date(CREATED.getTime() + 30_000);
    private static final Date AFTER_EXPIRY = new Date(CREATED.getTime() + 120_000);
    private static final byte[] BUNDLE = "the bytes of a bundle".getBytes(StandardCharsets.US_ASCII);

    @TempDir
    Path directory;
    private Path bundle;

    @BeforeEach
    void writeBundle() throws Exception {
        bundle = directory.resolve("bundle.tar.gz");
        Files.write(bundle, BUNDLE);
    }

    @Test
    void verifiesASignatureOfAValidSigningSubkey() throws Exception {
        KeyFixture fixture = KeyFixture.create(60, true, KeyFlags.SIGN_DATA);

        assertTrue(verify(fixture.ring(), signature(fixture, PGPSignature.BINARY_DOCUMENT, BEFORE_EXPIRY)));
    }

    @Test
    void refusesASignatureMadeAfterTheSigningSubkeyExpired() throws Exception {
        KeyFixture fixture = KeyFixture.create(60, true, KeyFlags.SIGN_DATA);

        assertFalse(verify(fixture.ring(), signature(fixture, PGPSignature.BINARY_DOCUMENT, AFTER_EXPIRY)));
    }

    @Test
    void refusesASignatureOfARevokedSigningSubkey() throws Exception {
        KeyFixture fixture = KeyFixture.create(0, true, KeyFlags.SIGN_DATA);
        PGPPublicKeyRing revoked = fixture.ringWithRevokedSubkey(AFTER_EXPIRY, null);

        assertFalse(verify(revoked, signature(fixture, PGPSignature.BINARY_DOCUMENT, BEFORE_EXPIRY)));
    }

    @Test
    void refusesASignatureOfASubkeyWithoutBackSignature() throws Exception {
        KeyFixture fixture = KeyFixture.create(0, false, KeyFlags.SIGN_DATA);

        assertFalse(verify(fixture.ring(), signature(fixture, PGPSignature.BINARY_DOCUMENT, BEFORE_EXPIRY)));
    }

    @Test
    void refusesASignatureOfAKeyOfAnotherCertificate() throws Exception {
        KeyFixture pinned = KeyFixture.create(0, true, KeyFlags.SIGN_DATA);
        KeyFixture other = KeyFixture.create(0, true, KeyFlags.SIGN_DATA);

        assertFalse(verify(pinned.ring(), signature(other, PGPSignature.BINARY_DOCUMENT, BEFORE_EXPIRY)));
    }

    @Test
    void refusesASignatureWhichIsNotOfABinaryDocument() throws Exception {
        KeyFixture fixture = KeyFixture.create(0, true, KeyFlags.SIGN_DATA);

        assertFalse(verify(fixture.ring(), signature(fixture, PGPSignature.CANONICAL_TEXT_DOCUMENT, BEFORE_EXPIRY)));
    }

    @Test
    void refusesAChangedBundle() throws Exception {
        KeyFixture fixture = KeyFixture.create(0, true, KeyFlags.SIGN_DATA);
        Path signature = signature(fixture, PGPSignature.BINARY_DOCUMENT, BEFORE_EXPIRY);
        byte[] changed = BUNDLE.clone();
        changed[0] ^= 1;
        Files.write(bundle, changed);

        assertFalse(verify(fixture.ring(), signature));
    }

    @Test
    void failsOnAFileWhichIsNoSignature() throws Exception {
        KeyFixture fixture = KeyFixture.create(0, true, KeyFlags.SIGN_DATA);
        Path signature = directory.resolve("bundle.tar.gz.asc");
        Files.writeString(signature, "not a signature\n");

        assertThrows(RuntimeException.class, () -> verify(fixture.ring(), signature));
    }

    private Path signature(KeyFixture signer, int signatureType, Date creationTime) throws Exception {
        Path signature = directory.resolve("bundle.tar.gz.asc");
        Files.write(signature, KeyFixture.armoredSignature(signer.subkey(), signatureType, creationTime, BUNDLE));
        return signature;
    }

    private boolean verify(PGPPublicKeyRing pinnedRing, Path signature) throws Exception {
        Path keyFile = directory.resolve("key.pgp");
        Files.write(keyFile, pinnedRing.getEncoded());
        String fingerprint = Hex.toHexString(pinnedRing.getPublicKey().getFingerprint());
        return new SignatureVerifier(Map.of(fingerprint, keyFile.toUri().toString()))
                .verifySignature(bundle.toFile(), signature.toFile());
    }
}

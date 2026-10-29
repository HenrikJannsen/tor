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
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.RevocationReasonTags;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.util.encoders.Hex;
import org.gradle.api.GradleException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

import static bisq.gradle.tasks.signature.KeyFixture.CREATED;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Ported from Bisq 2 commit 1360a2e3e8. The keys are evaluated at the creation time of a signature instead of the
 * current time.
 */
class PpgPublicKeyParserTest {
    private static final Date REVOKED = Date.from(Instant.parse("2025-02-01T00:00:00Z"));
    private static final Date NOW = Date.from(Instant.parse("2026-10-03T00:00:00Z"));
    @TempDir
    Path directory;

    @Test
    void acceptsCurrentlyBoundSigningSubkey() throws Exception {
        KeyFixture fixture = KeyFixture.create(0, true, KeyFlags.SIGN_DATA);
        Map<Long, PGPPublicKey> keys = parse(fixture.ring()).signingKeysAt(NOW);
        assertTrue(keys.containsKey(fixture.subkey().getKeyID()));
        assertFalse(keys.containsKey(fixture.primary().getKeyID()));
    }

    @Test
    void acceptsAnExpiredSigningSubkeyOnlyForASignatureMadeBeforeItExpired() throws Exception {
        KeyFixture fixture = KeyFixture.create(60, true, KeyFlags.SIGN_DATA);
        PpgPublicKeyParser parser = parse(fixture.ring());
        assertTrue(parser.signingKeysAt(new Date(CREATED.getTime() + 30_000)).containsKey(fixture.subkey().getKeyID()));
        assertTrue(parser.signingKeysAt(NOW).isEmpty());
    }

    @Test
    void acceptsTheSubkeysOfAnExpiredPrimaryKeyOnlyForASignatureMadeBeforeItExpired() throws Exception {
        KeyFixture fixture = KeyFixture.create(60, 0, true, KeyFlags.SIGN_DATA);
        PpgPublicKeyParser parser = parse(fixture.ring());
        assertTrue(parser.signingKeysAt(new Date(CREATED.getTime() + 30_000)).containsKey(fixture.subkey().getKeyID()));
        assertTrue(parser.signingKeysAt(new Date(CREATED.getTime() + 120_000)).isEmpty());
    }

    @Test
    void rejectsSigningSubkeyWithoutCrossCertification() throws Exception {
        assertTrue(parse(KeyFixture.create(0, false, KeyFlags.SIGN_DATA).ring()).signingKeysAt(NOW).isEmpty());
    }

    @Test
    void rejectsSubkeyNotAuthorizedToSign() throws Exception {
        assertTrue(parse(KeyFixture.create(0, true, KeyFlags.ENCRYPT_COMMS).ring()).signingKeysAt(NOW).isEmpty());
    }

    @Test
    void rejectsRevokedSigningSubkey() throws Exception {
        KeyFixture fixture = KeyFixture.create(0, true, KeyFlags.SIGN_DATA);
        PpgPublicKeyParser parser = parse(fixture.ringWithRevokedSubkey(REVOKED, null));
        assertTrue(parser.signingKeysAt(NOW).isEmpty());
        assertTrue(parser.signingKeysAt(new Date(CREATED.getTime() + 30_000)).isEmpty());
    }

    @Test
    void rejectsSigningSubkeyRevokedAsSupersededAlsoForASignatureMadeBeforeTheRevocation() throws Exception {
        // OpenPGP would accept a signature made before a soft revocation; the key file of the build trusts no
        // revoked subkey at all
        KeyFixture fixture = KeyFixture.create(0, true, KeyFlags.SIGN_DATA);
        PpgPublicKeyParser parser = parse(fixture.ringWithRevokedSubkey(REVOKED, RevocationReasonTags.KEY_SUPERSEDED));
        assertTrue(parser.signingKeysAt(new Date(CREATED.getTime() + 30_000)).isEmpty());
        assertTrue(parser.signingKeysAt(NOW).isEmpty());
    }

    @Test
    void rejectsWrongPrimaryFingerprint() throws Exception {
        KeyFixture fixture = KeyFixture.create(0, true, KeyFlags.SIGN_DATA);
        Path file = directory.resolve("key.pgp");
        Files.write(file, fixture.ring().getEncoded());
        PpgPublicKeyParser parser = new PpgPublicKeyParser("0000000000000000000000000000000000000000", file.toUri().toString());
        assertThrows(GradleException.class, parser::parse);
        assertThrows(IllegalStateException.class, () -> parser.signingKeysAt(NOW));
    }

    @Test
    void rejectsRevokedPrimaryKey() throws Exception {
        KeyFixture fixture = KeyFixture.create(0, true, KeyFlags.SIGN_DATA);
        assertThrows(GradleException.class, () -> parse(fixture.ringWithRevokedPrimaryKey()));
    }

    @Test
    void rejectsCertificateBeforeCreation() throws Exception {
        KeyFixture fixture = KeyFixture.create(0, true, KeyFlags.SIGN_DATA);
        assertTrue(parse(fixture.ring()).signingKeysAt(new Date(CREATED.getTime() - 1000)).isEmpty());
    }

    @Test
    void rejectsAFileWithoutKey() throws Exception {
        assertThrows(GradleException.class, () -> parseFile(new byte[0], "0000000000000000000000000000000000000000"));
        assertThrows(GradleException.class, () -> parseFile("not a key\n".getBytes(StandardCharsets.US_ASCII),
                "0000000000000000000000000000000000000000"));
    }

    @Test
    void rejectsAFileWithTwoPrimaryKeys() throws Exception {
        PGPPublicKeyRing pinned = KeyFixture.create(0, true, KeyFlags.SIGN_DATA).ring();
        PGPPublicKeyRing other = KeyFixture.create(0, true, KeyFlags.SIGN_DATA).ring();
        ByteArrayOutputStream twoRings = new ByteArrayOutputStream();
        twoRings.writeBytes(pinned.getEncoded());
        twoRings.writeBytes(other.getEncoded());

        assertThrows(GradleException.class, () -> parseFile(twoRings.toByteArray(),
                Hex.toHexString(pinned.getPublicKey().getFingerprint())));
    }

    // The decoder of an armored file reads the first block alone, so the parser has to refuse what is around it.
    @Test
    void rejectsAnArmoredFileWithASecondKeyBlock() throws Exception {
        PGPPublicKeyRing pinned = KeyFixture.create(0, true, KeyFlags.SIGN_DATA).ring();
        PGPPublicKeyRing other = KeyFixture.create(0, true, KeyFlags.SIGN_DATA).ring();

        assertThrows(GradleException.class, () -> parseFile(concat(armored(pinned), armored(other)),
                Hex.toHexString(pinned.getPublicKey().getFingerprint())));
    }

    @Test
    void rejectsAnArmoredFileWithTextAfterTheKeyBlock() throws Exception {
        PGPPublicKeyRing ring = KeyFixture.create(0, true, KeyFlags.SIGN_DATA).ring();

        assertThrows(GradleException.class, () -> parseFile(concat(armored(ring), ascii("trailing text\n")),
                Hex.toHexString(ring.getPublicKey().getFingerprint())));
    }

    @Test
    void rejectsAnArmoredFileWithTextBeforeTheKeyBlock() throws Exception {
        PGPPublicKeyRing ring = KeyFixture.create(0, true, KeyFlags.SIGN_DATA).ring();

        assertThrows(GradleException.class, () -> parseFile(concat(ascii("leading text\n"), armored(ring)),
                Hex.toHexString(ring.getPublicKey().getFingerprint())));
    }

    @Test
    void acceptsBlankLinesAroundTheArmoredKeyBlock() throws Exception {
        KeyFixture fixture = KeyFixture.create(0, true, KeyFlags.SIGN_DATA);
        byte[] keyFile = concat(ascii("\n"), armored(fixture.ring()), ascii("\n \t\r\n"));

        PpgPublicKeyParser parser = parseFile(keyFile, Hex.toHexString(fixture.ring().getPublicKey().getFingerprint()));

        assertTrue(parser.signingKeysAt(NOW).containsKey(fixture.subkey().getKeyID()));
    }

    private static byte[] armored(PGPPublicKeyRing ring) throws Exception {
        ByteArrayOutputStream armored = new ByteArrayOutputStream();
        try (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(armored)) {
            ring.encode(armoredOutputStream);
        }
        return armored.toByteArray();
    }

    private static byte[] ascii(String text) {
        return text.getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream joined = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            joined.writeBytes(part);
        }
        return joined.toByteArray();
    }

    private PpgPublicKeyParser parse(PGPPublicKeyRing ring) throws Exception {
        return parseFile(ring.getEncoded(), Hex.toHexString(ring.getPublicKey().getFingerprint()));
    }

    private PpgPublicKeyParser parseFile(byte[] keyFile, String primaryKeyFingerprint) throws Exception {
        Path file = directory.resolve("key.pgp");
        Files.write(file, keyFile);
        PpgPublicKeyParser parser = new PpgPublicKeyParser(primaryKeyFingerprint, file.toUri().toString());
        parser.parse();
        return parser;
    }
}

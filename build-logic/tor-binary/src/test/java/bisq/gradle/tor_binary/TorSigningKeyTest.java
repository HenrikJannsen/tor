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

package bisq.gradle.tor_binary;

import bisq.gradle.tasks.signature.PpgPublicKeyParser;
import bisq.gradle.tasks.signature.SignatureVerifier;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The key of the Tor Browser developers which the plugin pins, checked against the release 15.0.25. Its files were
 * signed on 2026-10-12 with the subkey 316C1FACD62D07D9.
 */
class TorSigningKeyTest {
    private static final String PRIMARY_KEY_FINGERPRINT = "ef6e286dda85ea2a4ba7de684e2c6e8793298290";
    private static final long REVOKED_IN_2015_AS_COMPROMISED = 0x2D000988589839A3L;
    private static final long EXPIRED_ON_2026_10_26 = 0x157432CF78A65729L;
    private static final long SIGNED_RELEASE_15_0_25 = 0x316C1FACD62D07D9L;

    @TempDir
    Path tempDir;

    @Test
    void theSubkeyWhichSignedTheReleaseWasValidWhenItSigned() {
        Map<Long, PGPPublicKey> keys = signingKeysAt("2026-10-12T00:00:00Z");

        assertTrue(keys.containsKey(SIGNED_RELEASE_15_0_25));
        assertTrue(keys.containsKey(EXPIRED_ON_2026_10_26));
        assertFalse(keys.containsKey(REVOKED_IN_2015_AS_COMPROMISED));
    }

    @Test
    void aSubkeyCountsOnlyForSignaturesMadeBeforeItExpired() {
        assertTrue(signingKeysAt("2026-10-25T00:00:00Z").containsKey(EXPIRED_ON_2026_10_26));
        assertFalse(signingKeysAt("2026-10-27T00:00:00Z").containsKey(EXPIRED_ON_2026_10_26));
        assertFalse(signingKeysAt("2015-01-01T00:00:00Z").containsKey(REVOKED_IN_2015_AS_COMPROMISED));
    }

    @Test
    void verifiesTheSignedChecksumsOfTheRelease() throws URISyntaxException {
        SignatureVerifier verifier = new SignatureVerifier(Map.of(PRIMARY_KEY_FINGERPRINT, keyUrl()));

        assertTrue(verifier.verifySignature(resource("torbrowser-15.0.25/sha256sums-signed-build.txt"),
                resource("torbrowser-15.0.25/sha256sums-signed-build.txt.asc")));
    }

    @Test
    void refusesAChangedFile() throws Exception {
        Path changed = tempDir.resolve("sha256sums-signed-build.txt");
        byte[] content = Files.readAllBytes(resource("torbrowser-15.0.25/sha256sums-signed-build.txt").toPath());
        content[0] ^= 1;
        Files.write(changed, content);
        SignatureVerifier verifier = new SignatureVerifier(Map.of(PRIMARY_KEY_FINGERPRINT, keyUrl()));

        assertFalse(verifier.verifySignature(changed.toFile(),
                resource("torbrowser-15.0.25/sha256sums-signed-build.txt.asc")));
    }

    private static Map<Long, PGPPublicKey> signingKeysAt(String time) {
        PpgPublicKeyParser parser = new PpgPublicKeyParser(PRIMARY_KEY_FINGERPRINT, keyUrl());
        parser.parse();
        return parser.signingKeysAt(Date.from(Instant.parse(time)));
    }

    // The key file as the plugin reads it
    private static String keyUrl() {
        return BisqTorBinaryPlugin.class.getResource("/Tor_Browser_Developers_(signing_key).asc").toString();
    }

    private static File resource(String name) throws URISyntaxException {
        return new File(TorSigningKeyTest.class.getResource("/" + name).toURI());
    }
}

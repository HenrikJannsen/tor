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

package bisq.network.tor;

import bisq.network.tor.onionservice.OnionServiceKey;
import com.google.common.io.BaseEncoding;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.EdECPrivateKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;

/**
 * Creates onion service keys as Bisq does: an Ed25519 key, its onion address (rend-spec-v3, section 6) and its
 * expanded secret key, which ADD_ONION takes as ED25519-V3 key. Tor derives the onion address from the key, so a
 * publication with a wrong derivation fails.
 */
final class OnionServiceKeys {
    private static final byte VERSION = 3;
    private static final int PUBLIC_KEY_LENGTH = 32;

    private OnionServiceKeys() {
    }

    static OnionServiceKey generate() {
        try {
            KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            byte[] privateKey = ((EdECPrivateKey) keyPair.getPrivate()).getBytes().orElseThrow();
            // The X.509 encoding of an Ed25519 public key ends with the 32 bytes of the key
            byte[] encodedPublicKey = keyPair.getPublic().getEncoded();
            byte[] publicKey = Arrays.copyOfRange(encodedPublicKey, encodedPublicKey.length - PUBLIC_KEY_LENGTH,
                    encodedPublicKey.length);
            return new OnionServiceKey(toOnionAddress(publicKey), toBase64SecretScalar(privateKey));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    // base32(PUBKEY | CHECKSUM | VERSION) + ".onion", with CHECKSUM = SHA3-256(".onion checksum" | PUBKEY | VERSION)[:2]
    private static String toOnionAddress(byte[] publicKey) throws GeneralSecurityException {
        MessageDigest sha3 = MessageDigest.getInstance("SHA3-256");
        sha3.update(".onion checksum".getBytes(StandardCharsets.US_ASCII));
        sha3.update(publicKey);
        sha3.update(VERSION);
        byte[] checksum = Arrays.copyOf(sha3.digest(), 2);
        byte[] address = ByteBuffer.allocate(PUBLIC_KEY_LENGTH + 3)
                .put(publicKey)
                .put(checksum)
                .put(VERSION)
                .array();
        return BaseEncoding.base32().omitPadding().encode(address).toLowerCase(Locale.ROOT) + ".onion";
    }

    // The expanded secret key of RFC 8032, section 5.1.5: the clamped scalar and the second half of the hash
    private static String toBase64SecretScalar(byte[] privateKey) throws GeneralSecurityException {
        byte[] secretScalar = MessageDigest.getInstance("SHA-512").digest(privateKey);
        secretScalar[0] &= (byte) 248;
        secretScalar[31] &= 127;
        secretScalar[31] |= 64;
        return Base64.getEncoder().encodeToString(secretScalar);
    }
}

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

package bisq.network.tor.controller;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class PasswordDigestTest {
    // The expected values come from net.freehaven.tor.control.PasswordDigest of jtorctl 30db998, the original of the
    // copy, with the same secrets and specifiers.
    @Test
    void hashesAsTheOriginalOfJtorctl() {
        byte[] secret = new byte[20];
        for (int i = 0; i < secret.length; i++) {
            secret[i] = (byte) i;
        }
        assertThat(new PasswordDigest(secret, new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 96}).getHashedPassword())
                .isEqualTo("16:010203040506070860EF697970E6446C36ADE6FD2D91957F69214E5F4F");

        byte[] specifier = {(byte) 0xA1, (byte) 0xB2, (byte) 0xC3, (byte) 0xD4, (byte) 0xE5, (byte) 0xF6, 0x07, 0x18,
                0x60};
        assertThat(new PasswordDigest("password".getBytes(StandardCharsets.UTF_8), specifier).getHashedPassword())
                .isEqualTo("16:A1B2C3D4E5F6071860D1D5C9C27D5B3CD3B6746A5E0FF786245D8A0186");
    }

    // HashedControlPassword of a torrc: "16:", then the 9 bytes of the specifier and the 20 bytes of the hash in hex
    @Test
    void generatedDigestsHaveTheFormatOfTor() {
        assertThat(PasswordDigest.generateDigest().getHashedPassword()).matches("16:[0-9A-F]{58}");
    }
}

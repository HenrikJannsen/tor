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

package bisq.network.tor.sandbox;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class Sha256SumsTest {
    private static final String HASH_A = "6b3919d9f063f93d1909dc95bf2c4c7b0c4b075230bcf9f6ec08700825fdbb93";
    private static final String HASH_B = "a7c7d0869da45c98ab0ecb0e37e1a7002f1e678fc3a551ffcf52574a2dfe835f";

    @Test
    void parsesTextAndBinaryModeLines() {
        String content = HASH_A + "  linux_x86_64/sandy\r\n" + HASH_B + " *win_x86_64/sandy.exe\n\n";

        assertThat(Sha256Sums.parse(content))
                .containsEntry("linux_x86_64/sandy", HASH_A)
                .containsEntry("win_x86_64/sandy.exe", HASH_B)
                .hasSize(2);
    }

    @Test
    void rejectsMalformedLines() {
        assertThatThrownBy(() -> Sha256Sums.parse(HASH_A.toUpperCase() + "  sandy"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Sha256Sums.parse(HASH_A.substring(1) + "  sandy"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Sha256Sums.parse(HASH_A + "  two names"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsDuplicateNames() {
        assertThatThrownBy(() -> Sha256Sums.parse(HASH_A + "  sandy\n" + HASH_B + "  sandy\n"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Duplicate");
    }

    @Test
    void computesSha256() throws IOException {
        // sha256("abc") from FIPS 180-2
        String expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

        assertThat(Sha256Sums.sha256Hex(new ByteArrayInputStream("abc".getBytes(StandardCharsets.US_ASCII))))
                .isEqualTo(expected);
    }
}

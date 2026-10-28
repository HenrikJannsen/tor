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

import java.util.OptionalLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TorMemoryLimitTest {
    private static final long GIGABYTE = 1L << 30;

    @Test
    void takesThreeQuartersOfAMemoryBelow8Gigabytes() {
        assertThat(TorMemoryLimit.defaultMaxMemInQueues(4 * GIGABYTE)).isEqualTo(3 * GIGABYTE);
        // Tor divides before it multiplies
        assertThat(TorMemoryLimit.defaultMaxMemInQueues(8 * GIGABYTE - 1)).isEqualTo(6_442_450_941L);
    }

    @Test
    void takesTwoFifthsOfAMemoryOf8GigabytesOrMore() {
        assertThat(TorMemoryLimit.defaultMaxMemInQueues(8 * GIGABYTE)).isEqualTo(3_435_973_836L);
        assertThat(TorMemoryLimit.defaultMaxMemInQueues(16 * GIGABYTE)).isEqualTo(6_871_947_672L);
    }

    @Test
    void staysBetweenAQuarterGigabyteAnd8Gigabytes() {
        assertThat(TorMemoryLimit.defaultMaxMemInQueues(256L << 20)).isEqualTo(GIGABYTE / 4);
        assertThat(TorMemoryLimit.defaultMaxMemInQueues(1)).isEqualTo(GIGABYTE / 4);
        assertThat(TorMemoryLimit.defaultMaxMemInQueues(32 * GIGABYTE)).isEqualTo(8 * GIGABYTE);
    }

    @Test
    void refusesAMemorySizeThatIsNotPositive() {
        assertThatThrownBy(() -> TorMemoryLimit.defaultMaxMemInQueues(0)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void writesTheDefaultInBytes() {
        assertThat(TorMemoryLimit.torrcValue(OptionalLong.of(4 * GIGABYTE))).isEqualTo("3221225472 bytes");
    }

    @Test
    void fallsBackTo512MegabytesForAnUnknownMemorySize() {
        assertThat(TorMemoryLimit.torrcValue(OptionalLong.empty())).isEqualTo("512 MB");
    }

    @Test
    void derivesTheTorrcValueFromTheMemoryOfThisSystem() {
        assertThat(TorMemoryLimit.torrcValue()).matches("[0-9]+ bytes");
    }
}

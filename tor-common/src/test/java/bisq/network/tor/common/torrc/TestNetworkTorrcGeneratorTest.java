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
package bisq.network.tor.common.torrc;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class TestNetworkTorrcGeneratorTest {
    @Test
    void theNodesListenOnlyOnTheLoopbackAddressWhichTheyAdvertise() {
        Map<String, String> torrc = TestNetworkTorrcGenerator.builder()
                .baseTorrcConfigGenerator(HashMap::new)
                .orPort(Optional.of(5000))
                .dirPort(Optional.of(5001))
                .build()
                .generate();

        assertThat(torrc)
                .containsEntry("Address", "127.0.0.1")
                .containsEntry("OrPort", "127.0.0.1:5000")
                .containsEntry("DirPort", "127.0.0.1:5001");
    }
}

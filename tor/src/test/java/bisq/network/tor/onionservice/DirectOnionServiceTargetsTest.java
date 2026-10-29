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

package bisq.network.tor.onionservice;

import bisq.network.tor.process.LoopbackPorts;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

class DirectOnionServiceTargetsTest {
    private static final String ONION_A = "a".repeat(56) + ".onion";
    private static final String ONION_B = "b".repeat(56) + ".onion";

    @Test
    void torConnectsToTheServerSocket() throws IOException {
        DirectOnionServiceTargets targets = new DirectOnionServiceTargets(LoopbackPorts.IPV4_LOOPBACK);

        OnionServiceTargets.Target target = targets.bindServerSocket(ONION_A);

        assertThat(target.torTargetPort()).isEqualTo(target.serverSocket().getLocalPort());
        assertThat(targets.targetPortOf(ONION_B, 8090)).isEqualTo(8090);
        target.serverSocket().close();
    }

    @Test
    void anOnionServiceKeepsItsPortWhenItsServerSocketIsBoundAgain() throws IOException {
        DirectOnionServiceTargets targets = new DirectOnionServiceTargets(LoopbackPorts.IPV4_LOOPBACK);
        OnionServiceTargets.Target first = targets.bindServerSocket(ONION_A);
        first.serverSocket().close();

        OnionServiceTargets.Target second = targets.bindServerSocket(ONION_A);

        assertThat(second.torTargetPort()).isEqualTo(first.torTargetPort());
        second.serverSocket().close();
    }
}

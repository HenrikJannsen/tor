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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.net.InetAddress;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@Timeout(10)
class TorControlProtocolHostTest {
    private final TorControlProtocol torControlProtocol = new TorControlProtocol();
    private FakeTorControlServer server;

    @AfterEach
    void tearDown() throws Exception {
        torControlProtocol.close();
        if (server != null) {
            server.close();
        }
    }

    @Test
    void theControlConnectionGoesToTheGivenHost() throws Exception {
        // Linux routes the whole 127.0.0.0/8 network to the loopback interface, macOS only 127.0.0.1.
        InetAddress otherLoopbackAddress = InetAddress.getByName("127.0.0.2");
        try {
            server = new FakeTorControlServer(otherLoopbackAddress, command -> "250 OK\r\n");
        } catch (IOException e) {
            assumeTrue(false, "127.0.0.2 is not available: " + e.getMessage());
        }

        torControlProtocol.initialize("127.0.0.2", server.getPort());
        torControlProtocol.authenticate(new byte[0]);

        assertThat(server.getCommands()).containsExactly("AUTHENTICATE ");
    }
}

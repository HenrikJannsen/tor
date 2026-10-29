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

import static org.assertj.core.api.Assertions.assertThat;

@Timeout(10)
class TorControlProtocolDataReplyTest {
    private final TorControlProtocol torControlProtocol = new TorControlProtocol();
    private FakeTorControlServer server;

    @AfterEach
    void tearDown() throws Exception {
        torControlProtocol.close();
        server.close();
    }

    @Test
    void aDataReplyIsReadUntilItsEnd() throws Exception {
        // control-spec: the data of a "250+" line follows until a line with a single dot; a data line which starts
        // with a dot gets a second dot in front.
        server = new FakeTorControlServer(command -> command.equals("GETINFO config-text") ?
                "250+config-text=\r\nControlPort 9051\r\n\r\n..a line with a dot\r\n.\r\n250 OK\r\n" :
                "250-version=0.4.9.14\r\n250 OK\r\n");
        torControlProtocol.initialize(server.getPort());

        assertThat(torControlProtocol.getInfo("config-text"))
                .isEqualTo("250+config-text=\nControlPort 9051\n\n.a line with a dot");
        // The next command gets its own reply, not the rest of the data
        assertThat(torControlProtocol.getInfo("version")).isEqualTo("250-version=0.4.9.14");
    }
}

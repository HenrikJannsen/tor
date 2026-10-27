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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * A line end inside a command would carry further commands into the control connection, which could change the
 * configuration of Tor or stop it. The arguments of some commands can come from the network or from a configuration.
 */
@Timeout(10)
class TorControlProtocolCommandLineTest {
    private final TorControlProtocol torControlProtocol = new TorControlProtocol();
    private FakeTorControlServer server;

    @BeforeEach
    void setUp() throws IOException {
        server = new FakeTorControlServer(command -> command.startsWith("GETINFO") ?
                "250-version=0.4.9.14\r\n250 OK\r\n" :
                "250 OK\r\n");
        torControlProtocol.initialize(server.getPort());
    }

    @AfterEach
    void tearDown() throws Exception {
        torControlProtocol.close();
        server.close();
    }

    @ParameterizedTest
    @ValueSource(strings = {"\r\nSIGNAL SHUTDOWN", "\nSIGNAL SHUTDOWN", "\rSIGNAL SHUTDOWN", "\u0000", "\t", "\u007F"})
    void aControlCharacterInAnArgumentIsRefusedBeforeItReachesTor(String injected) {
        assertThatThrownBy(() -> torControlProtocol.setConfig("DisableNetwork", "0" + injected))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> torControlProtocol.resetConf("__OwningControllerProcess" + injected))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> torControlProtocol.getConf("HashedControlPassword" + injected))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> torControlProtocol.getInfo("version" + injected))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> torControlProtocol.delOnion("serviceid" + injected))
                .isInstanceOf(IllegalArgumentException.class);

        // Nothing was sent, and the connection still serves the next command.
        assertThat(torControlProtocol.getInfo("version")).isEqualTo("250-version=0.4.9.14");
        assertThat(server.getCommands()).containsExactly("GETINFO version");
    }
}

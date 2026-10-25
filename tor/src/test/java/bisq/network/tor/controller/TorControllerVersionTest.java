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
class TorControllerVersionTest {
    private final TorController torController = new TorController(1000, 1000);
    private FakeTorControlServer server;

    @AfterEach
    void tearDown() throws Exception {
        torController.shutdown();
        server.close();
    }

    @Test
    void readsTheVersionWithoutTheGitSuffix() throws Exception {
        connect("250-version=0.4.9.14 (git-0a4b1c9d2e3f4a5b)\r\n250 OK\r\n");

        assertThat(torController.getTorVersion()).contains("0.4.9.14");
    }

    @Test
    void readsAVersionWithoutSuffix() throws Exception {
        connect("250-version=0.4.8.21\r\n250 OK\r\n");

        assertThat(torController.getTorVersion()).contains("0.4.8.21");
    }

    @Test
    void readsAVersionAfterTheNameOfTheSoftware() throws Exception {
        connect("250-version=Tor 0.4.9.1-alpha\r\n250 OK\r\n");

        assertThat(torController.getTorVersion()).contains("0.4.9.1-alpha");
    }

    @Test
    void aFilteredRequestGivesNoVersion() throws Exception {
        connect("510 Command filtered\r\n");

        assertThat(torController.getTorVersion()).isEmpty();
    }

    private void connect(String reply) throws Exception {
        server = new FakeTorControlServer(command -> reply);
        torController.initialize(server.getPort());
    }
}

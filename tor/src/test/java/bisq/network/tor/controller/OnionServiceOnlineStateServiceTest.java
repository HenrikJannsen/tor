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

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Timeout(20)
class OnionServiceOnlineStateServiceTest {
    private static final String HS_DIR = "$0123456789ABCDEF0123456789ABCDEF01234567";

    private final String onionAddress = TestKeys.randomOnionServiceKey().getOnionAddress();
    private final String serviceId = onionAddress.replace(".onion", "");
    private TorController torController;
    private FakeTorControlServer server;

    @AfterEach
    void tearDown() throws Exception {
        if (torController != null) {
            torController.shutdown();
        }
        if (server != null) {
            server.close();
        }
    }

    @Test
    void aReceivedDescriptorMeansOnline() throws Exception {
        connect(command -> command.startsWith("HSFETCH") ?
                "250 OK\r\n650 HS_DESC RECEIVED " + serviceId + " NO_AUTH " + HS_DIR + " descriptorId\r\n" :
                "250 OK\r\n");

        assertThat(torController.isOnionServiceOnlineAsync(onionAddress).join()).isTrue();
        assertThat(server.getCommands()).contains("HSFETCH " + serviceId);
    }

    @Test
    void aMissingDescriptorMeansOffline() throws Exception {
        connect(command -> command.startsWith("HSFETCH") ?
                "250 OK\r\n650 HS_DESC FAILED " + serviceId + " NO_AUTH " + HS_DIR + " descriptorId REASON=NOT_FOUND\r\n" :
                "250 OK\r\n");

        assertThat(torController.isOnionServiceOnlineAsync(onionAddress).join()).isFalse();
    }

    @Test
    void theEndOfTheConnectionFailsTheLookupAtOnce() throws Exception {
        // Tor exits after it accepted HSFETCH, long before the timeout of the lookup
        connect(command -> "250 OK\r\n");
        server.closeConnectionAfter("HSFETCH");

        long start = System.currentTimeMillis();
        CompletableFuture<Boolean> lookup = torController.isOnionServiceOnlineAsync(onionAddress);
        assertThatThrownBy(lookup::join)
                .isInstanceOf(CompletionException.class)
                .hasMessageContaining("ended");
        assertThat(System.currentTimeMillis() - start).isLessThan(5000);
    }

    private void connect(Function<String, String> replyByCommand) throws Exception {
        server = new FakeTorControlServer(replyByCommand);
        torController = new TorController(1000, 1000);
        torController.initialize(server.getPort());
    }
}

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

package bisq.network.tor;

import bisq.network.tor.controller.FakeTorControlServer;
import bisq.network.tor.controller.TestKeys;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The address of a peer comes from the network: Bisq 2 accepts it in any case, and it must not carry a second command
 * into the control connection.
 */
@Timeout(30)
class TorServiceOnlineCheckTest {
    private static final PlatformServices PLATFORM_SERVICES = new PlatformServices() {
        @Override
        public String getMyPid() {
            return String.valueOf(ProcessHandle.current().pid());
        }

        @Override
        public Stream<String> getProcessCommandStream() {
            return Stream.empty();
        }

        @Override
        public boolean supportsPosixPermissions() {
            return false;
        }
    };

    private final String onionAddress = TestKeys.randomOnionServiceKey().getOnionAddress();
    private final String serviceId = onionAddress.replace(".onion", "");
    @TempDir
    Path torDir;
    private FakeTorControlServer fakeTor;
    private TorService torService;

    @AfterEach
    void tearDown() throws Exception {
        if (torService != null) {
            torService.shutdown().join();
        }
        if (fakeTor != null) {
            fakeTor.close();
        }
    }

    @Test
    void anAddressInUpperCaseIsLookedUp() throws Exception {
        start(command -> command.startsWith("HSFETCH ") ?
                "250 OK\r\n650 HS_DESC RECEIVED " + serviceId + " NO_AUTH redacted redacted\r\n" :
                reply(command));

        assertThat(torService.isOnionServiceOnlineAsync(onionAddress.toUpperCase(Locale.ROOT)).join()).isTrue();
        assertThat(fakeTor.getCommands()).contains("HSFETCH " + serviceId);
    }

    @Test
    void aLineEndInTheAddressIsRefusedBeforeItReachesTor() throws Exception {
        start(TorServiceOnlineCheckTest::reply);

        CompletableFuture<Boolean> lookup = torService.isOnionServiceOnlineAsync(onionAddress + "\r\nSIGNAL SHUTDOWN");

        assertThatThrownBy(lookup::join).hasCauseInstanceOf(IllegalArgumentException.class);
        assertThat(fakeTor.getCommands())
                .noneMatch(command -> command.startsWith("HSFETCH") || command.toUpperCase(Locale.ROOT).startsWith("SIGNAL"));
    }

    private void start(Function<String, String> replyByCommand) throws IOException {
        fakeTor = new FakeTorControlServer(replyByCommand);
        Files.writeString(torDir.resolve("external_tor.config"), "UseExternalTor 1\nCookieAuthentication 0\n" +
                "ControlPort 127.0.0.1:" + fakeTor.getPort());
        torService = new TorService(createTransportConfig(), PLATFORM_SERVICES);
        assertThat(torService.initialize().join()).isTrue();
    }

    // A Tor which has bootstrapped
    private static String reply(String command) {
        if (command.startsWith("AUTHENTICATE") || command.startsWith("SETEVENTS")) {
            return "250 OK\r\n";
        }
        if (command.equals("GETINFO status/bootstrap-phase")) {
            return "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n250 OK\r\n";
        }
        if (command.equals("GETINFO version")) {
            return "250-version=0.4.8.16\r\n250 OK\r\n";
        }
        if (command.equals("GETINFO net/listeners/socks")) {
            return "250-net/listeners/socks=\"127.0.0.1:9150\"\r\n250 OK\r\n";
        }
        return "552 Unrecognized command\r\n";
    }

    private TorTransportConfig createTransportConfig() {
        // If the test failed and TorService started its own Tor, Tor would send its connections to a closed local
        // port instead of the Tor network.
        return new TorTransportConfig(torDir, 1000, 1000, false, Set.of(),
                Map.of("Socks5Proxy", "127.0.0.1:1"), false);
    }
}

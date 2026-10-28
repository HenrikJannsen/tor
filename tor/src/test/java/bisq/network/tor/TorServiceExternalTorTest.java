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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * A configured external Tor which cannot be used must stop the start. If TorService started its own Tor instead, that
 * Tor would connect to the Tor network without the settings of the external Tor, for example its bridges.
 */
@Timeout(30)
class TorServiceExternalTorTest {
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

    @TempDir
    Path torDir;
    private TorService torService;

    @AfterEach
    void tearDown() {
        if (torService != null) {
            torService.shutdown().join();
        }
    }

    @Test
    void anExternalTorWhichDoesNotListenStopsTheStart() throws IOException {
        int closedPort = findClosedPort();
        Files.writeString(torDir.resolve("external_tor.config"), "UseExternalTor 1\nControlPort 127.0.0.1:" + closedPort);
        torService = new TorService(createTransportConfig(), PLATFORM_SERVICES);

        // The message of the cause ends with a period, which the message of the start does not repeat.
        assertThatThrownBy(() -> torService.initialize())
                .isInstanceOf(ExternalTorUnavailableException.class)
                .hasMessageContaining("127.0.0.1:" + closedPort)
                .hasMessageContaining("after 10 attempts. Bisq does not start its own Tor")
                .hasMessageNotContaining("..");
        assertThat(torDir.resolve("torrc")).doesNotExist();
    }

    @Test
    void anExternalTorWhichCannotBeAuthenticatedStopsTheStart() throws IOException {
        try (ServerSocket fakeControlPort = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            // CookieAuthentication without a cookie file
            Files.writeString(torDir.resolve("external_tor.config"), "UseExternalTor 1\nCookieAuthentication 1\n" +
                    "ControlPort 127.0.0.1:" + fakeControlPort.getLocalPort());
            torService = new TorService(createTransportConfig(), PLATFORM_SERVICES);

            assertThatThrownBy(() -> torService.initialize())
                    .isInstanceOf(ExternalTorUnavailableException.class)
                    .hasMessageContaining("CookieAuthFile");
        }
        assertThat(torDir.resolve("torrc")).doesNotExist();
    }

    @Test
    void aTorServiceCanBeStartedAgainAfterItsShutdown() throws Exception {
        try (FakeTorControlServer externalTor = new FakeTorControlServer(TorServiceExternalTorTest::replyOfABootstrappedTor)) {
            Files.writeString(torDir.resolve("external_tor.config"), "UseExternalTor 1\nCookieAuthentication 0\n" +
                    "ControlPort 127.0.0.1:" + externalTor.getPort());
            torService = new TorService(createTransportConfig(), PLATFORM_SERVICES);
            assertThat(torService.initialize().join()).isTrue();
            torService.shutdown().join();
        }

        // The external Tor is gone, so the second start has to connect again and fail, instead of reporting the
        // result of the first start.
        assertThatThrownBy(() -> torService.initialize())
                .isInstanceOf(ExternalTorUnavailableException.class);
    }

    @Test
    void aFailedPreparationOfTheStartLetsTheNextStartTryAgain() throws Exception {
        // The invalid file fails the start before any connection. The next start has to read the file again instead
        // of reporting the Tor of a start which never happened.
        Path configPath = torDir.resolve("external_tor.config");
        Files.writeString(configPath, "UseExternalTor definitely-invalid");
        torService = new TorService(createTransportConfig(), PLATFORM_SERVICES);

        assertThatThrownBy(() -> torService.initialize()).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> torService.initialize()).isInstanceOf(IllegalArgumentException.class);

        try (FakeTorControlServer externalTor = new FakeTorControlServer(TorServiceExternalTorTest::replyOfABootstrappedTor)) {
            Files.writeString(configPath, "UseExternalTor 1\nCookieAuthentication 0\nControlPort 127.0.0.1:" +
                    externalTor.getPort());

            assertThat(torService.initialize().join()).isTrue();
        }
    }

    private static String replyOfABootstrappedTor(String command) {
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

    private static int findClosedPort() throws IOException {
        try (ServerSocket serverSocket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            return serverSocket.getLocalPort();
        }
    }
}

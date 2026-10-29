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
import bisq.network.tor.controller.TorController.SocksListener;
import bisq.network.tor.process.LoopbackPorts;
import bisq.network.tor.process.TorStartupFailedException;
import com.runjva.sourceforge.jsocks.protocol.Socks5Proxy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
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
    void aCookieFileOfAnotherLengthStopsTheStart() throws IOException {
        Path cookieFile = Files.write(torDir.resolve("not_a_cookie"), new byte[]{1, 2, 3});
        try (ServerSocket fakeControlPort = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            Files.writeString(torDir.resolve("external_tor.config"), "UseExternalTor 1\nCookieAuthentication 1\n" +
                    "CookieAuthFile " + cookieFile + "\nControlPort 127.0.0.1:" + fakeControlPort.getLocalPort());
            torService = new TorService(createTransportConfig(), PLATFORM_SERVICES);

            assertThatThrownBy(() -> torService.initialize())
                    .isInstanceOf(ExternalTorUnavailableException.class)
                    .hasMessageContaining("has 3 bytes");
        }
    }

    // A read of the whole file would never end, and fill the memory on the way.
    @Test
    @EnabledOnOs({OS.LINUX, OS.MAC})
    void aCookieFileIsReadOnlyUpToTheLengthOfACookie() throws IOException {
        try (ServerSocket fakeControlPort = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            Files.writeString(torDir.resolve("external_tor.config"), "UseExternalTor 1\nCookieAuthentication 1\n" +
                    "CookieAuthFile /dev/zero\nControlPort 127.0.0.1:" + fakeControlPort.getLocalPort());
            torService = new TorService(createTransportConfig(), PLATFORM_SERVICES);

            assertThatThrownBy(() -> torService.initialize())
                    .isInstanceOf(ExternalTorUnavailableException.class)
                    .hasMessageContaining("has more than 32 bytes");
        }
    }

    @Test
    void aTorServiceCanBeStartedAgainAfterItsShutdown() throws Exception {
        try (FakeTorControlServer externalTor = new FakeTorControlServer(TorServiceExternalTorTest::replyOfABootstrappedTor)) {
            Files.writeString(torDir.resolve("external_tor.config"), "UseExternalTor 1\nCookieAuthentication 0\n" +
                    "ControlPort 127.0.0.1:" + externalTor.getPort());
            torService = new TorService(createTransportConfig(), PLATFORM_SERVICES);
            assertThat(torService.initialize().join()).isTrue();
            // Outside Whonix, an external Tor connects to the servers of the application on the loopback address.
            assertThat(torService.getOnionServiceBindAddress()).isEqualTo(LoopbackPorts.IPV4_LOOPBACK);
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

    // Bisq uses the first SOCKS listener, 127.0.0.1:9150.
    @Test
    void anExternalTorWhoseSocksPortDoesNotIsolateStreamsStopsTheStart() throws Exception {
        try (FakeTorControlServer externalTor = new FakeTorControlServer(command ->
                replyWithSocksPorts(command, "250-SocksPort=9050\r\n250 SocksPort=127.0.0.1:9150 NoIsolateSOCKSAuth\r\n"))) {
            Files.writeString(torDir.resolve("external_tor.config"), "UseExternalTor 1\nCookieAuthentication 0\n" +
                    "ControlPort 127.0.0.1:" + externalTor.getPort());
            torService = new TorService(createTransportConfig(), PLATFORM_SERVICES);

            assertThatThrownBy(() -> torService.initialize())
                    .isInstanceOf(ExternalTorUnavailableException.class)
                    .hasMessageContaining("SOCKS port 9150 does not isolate")
                    .hasMessageContaining("SocksPort 127.0.0.1:9150 NoIsolateSOCKSAuth")
                    .hasMessageNotContaining("SocksPort 9050");
        }
    }

    @Test
    void anExternalTorWhoseSocksPortIsolatesStreamsStarts() throws Exception {
        // The default SocksPort of Tor (none set), and another port without the isolation
        for (String socksPortReply : List.of("250 SocksPort\r\n",
                "250-SocksPort=127.0.0.1:9150 KeepAliveIsolateSOCKSAuth\r\n250 SocksPort=9050 NoIsolateSOCKSAuth\r\n")) {
            try (FakeTorControlServer externalTor = new FakeTorControlServer(command ->
                    replyWithSocksPorts(command, socksPortReply))) {
                Files.writeString(torDir.resolve("external_tor.config"), "UseExternalTor 1\nCookieAuthentication 0\n" +
                        "ControlPort 127.0.0.1:" + externalTor.getPort());
                torService = new TorService(createTransportConfig(), PLATFORM_SERVICES);

                assertThat(torService.initialize().join()).isTrue();
                assertThat(externalTor.getCommands()).contains("GETCONF SocksPort", "GETCONF __SocksPort");
                torService.shutdown().join();
            }
        }
    }

    @Test
    void bisqConnectsToTheSocksAddressOfTorOrOnAWildcardAddressToTheControlHost() throws Exception {
        assertThat(socksProxyOfAnExternalTorWhichListensOn("192.0.2.7:9150")).isEqualTo("192.0.2.7:9150");
        assertThat(socksProxyOfAnExternalTorWhichListensOn("0.0.0.0:9150")).isEqualTo("127.0.0.1:9150");
    }

    @Test
    void aSpecificAddressIsUsedAndAWildcardAddressMeansTheControlHost() {
        assertThat(selectSocksAddress("192.168.1.10", false, new SocksListener("192.168.1.11", 9150)))
                .isEqualTo("192.168.1.11:9150");
        assertThat(selectSocksAddress("192.168.1.10", false, new SocksListener("0.0.0.0", 9050)))
                .isEqualTo("192.168.1.10:9050");
        assertThat(selectSocksAddress("tor.example", false, new SocksListener("::", 9050)))
                .isEqualTo("tor.example:9050");
    }

    // Only Tor on this host can be reached on a loopback address, as on Whonix through the forwarders of the Workstation.
    @Test
    void aLoopbackAddressIsUsedOnlyIfTorRunsOnThisHost() {
        assertThat(selectSocksAddress("127.0.0.1", true, new SocksListener("::1", 9150))).isEqualTo("::1:9150");
        assertThat(selectSocksAddress("192.168.1.10", false, new SocksListener("127.0.0.1", 9050),
                new SocksListener("192.168.1.10", 9150))).isEqualTo("192.168.1.10:9150");

        assertThatThrownBy(() -> TorService.selectSocksAddress("192.168.1.10", false,
                List.of(new SocksListener("127.0.0.1", 9050), new SocksListener("::1", 9050))))
                .isInstanceOf(TorStartupFailedException.class)
                .hasMessageContaining("only on the loopback address of its host 192.168.1.10 (127.0.0.1:9050, [::1]:9050)")
                .hasMessageContaining("Add a SocksPort");
        assertThatThrownBy(() -> TorService.selectSocksAddress("127.0.0.1", true, List.of()))
                .isInstanceOf(TorStartupFailedException.class)
                .hasMessageContaining("no TCP SOCKS listener");
    }

    private String socksProxyOfAnExternalTorWhichListensOn(String socksListener) throws Exception {
        try (FakeTorControlServer externalTor = new FakeTorControlServer(command ->
                command.equals("GETINFO net/listeners/socks") ?
                        "250-net/listeners/socks=\"" + socksListener + "\"\r\n250 OK\r\n" :
                        replyOfABootstrappedTor(command))) {
            Files.writeString(torDir.resolve("external_tor.config"), "UseExternalTor 1\nCookieAuthentication 0\n" +
                    "ControlPort 127.0.0.1:" + externalTor.getPort());
            torService = new TorService(createTransportConfig(), PLATFORM_SERVICES);
            assertThat(torService.initialize().join()).isTrue();
            Socks5Proxy socks5Proxy = torService.getSocks5Proxy();
            torService.shutdown().join();
            return socks5Proxy.getInetAddress().getHostAddress() + ":" + socks5Proxy.getPort();
        }
    }

    private static String selectSocksAddress(String controlHost,
                                             boolean isControlHostLoopback,
                                             SocksListener... socksListeners) {
        InetSocketAddress socksAddress = TorService.selectSocksAddress(controlHost, isControlHostLoopback,
                List.of(socksListeners));
        return socksAddress.getHostString() + ":" + socksAddress.getPort();
    }

    private static String replyWithSocksPorts(String command, String socksPortReply) {
        if (command.equals("GETCONF SocksPort")) {
            return socksPortReply;
        }
        if (command.equals("GETCONF __SocksPort")) {
            return "250 __SocksPort\r\n";
        }
        return replyOfABootstrappedTor(command);
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

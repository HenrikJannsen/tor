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

import bisq.network.tor.controller.TorControlProtocol;
import bisq.network.tor.local_network.TorNetwork;
import bisq.network.tor.process.EmbeddedTorProcess;
import com.runjva.sourceforge.jsocks.protocol.SocksSocket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Runs the peers on a private Tor network of tor-local-network on this host, so the tests need neither the internet nor
 * the Tor network. The network needs tor and tor-gencert in PATH; on Debian and Ubuntu the package tor has both.
 */
@Timeout(value = 5, unit = TimeUnit.MINUTES)
class PrivateTorNetworkOnionServiceTest extends OnionServiceIntegrationTests {
    private static final String PASSPHRASE = "passphrase";
    // On the network, whose consensus lists all nodes about a minute after its start, a Tor bootstraps in seconds
    private static final int BOOTSTRAP_TIMEOUT_MS = (int) TimeUnit.MINUTES.toMillis(3);
    private static final int HS_UPLOAD_TIMEOUT_MS = (int) TimeUnit.MINUTES.toMillis(2);

    private TorNetwork torNetwork;

    @Override
    void startNetwork() throws IOException, InterruptedException {
        String path = System.getenv("PATH");
        assumeTrue(EmbeddedTorProcess.findExecutableInPath(path, "tor").isPresent() &&
                        EmbeddedTorProcess.findExecutableInPath(path, "tor-gencert").isPresent(),
                "The private Tor network needs tor and tor-gencert in PATH");
        torNetwork = new TorNetwork(Files.createDirectories(tempDir.resolve("network")), true)
                .addDirAuth(PASSPHRASE)
                .addDirAuth(PASSPHRASE)
                .addDirAuth(PASSPHRASE)

                .addRelay()
                .addRelay()
                .addRelay()
                .addRelay()
                .addRelay();
        torNetwork.start();
        // A peer which starts earlier can ask other relays for the descriptor of an onion service than those to which
        // the onion service uploaded it, so its first connections can time out.
        torNetwork.awaitConsensusWithAllNodes(Duration.ofMinutes(3));
    }

    @Override
    void stopNetwork() throws InterruptedException {
        if (torNetwork != null) {
            torNetwork.close();
        }
    }

    @Override
    TorTransportConfig createTransportConfig(Path torDir) {
        return new TorTransportConfig(torDir, BOOTSTRAP_TIMEOUT_MS, HS_UPLOAD_TIMEOUT_MS, true,
                torNetwork.getDirectoryAuthorities(), Map.of(), false);
    }

    @Override
    Duration getConnectTimeout() {
        return Duration.ofMinutes(2);
    }

    @Test
    void anOnionServiceWhichNobodyPublishedIsNotOnline() {
        String onionAddress = OnionServiceKeys.generate().getOnionAddress();

        assertThat(alice.getTorService().isOnionServiceOnlineAsync(onionAddress).join()).isFalse();
    }

    // The relays of the private network let their exits connect to the loopback addresses of this host
    @Test
    void aPeerReachesAServerOutsideTorThroughAnExitRelay() throws Exception {
        try (AckServer server = AckServer.start("server", new ServerSocket(0, 50, InetAddress.getLoopbackAddress()))) {
            String message = "hello server, this is alice";

            assertThat(alice.send("127.0.0.1", server.getPort(), message)).isEqualTo(AckServer.ackOf("server", message));
        }
    }

    // The HTTP clients of Bisq connect through the SOCKS5 proxy of TorService
    @Test
    void theSocks5ProxyOfAPeerReachesAnOnionService() throws Exception {
        // Waits until the onion service of bob is reachable
        alice.send(bob, "ping");
        String message = "hello bob, this is alice through the SOCKS5 proxy";

        try (Socket socket = new SocksSocket(alice.getTorService().getSocks5Proxy(), bob.getOnionAddress(),
                OnionPeer.ONION_SERVICE_PORT)) {
            assertThat(AckServer.exchange(socket, message)).isEqualTo(AckServer.ackOf("bob", message));
        }
    }

    // TorService gives the streams of different stream IDs different SOCKS credentials, so that Tor puts them on
    // different circuits. The peer uses an external Tor, whose control port the test can use as well.
    @Test
    void streamsOfDifferentStreamIdsUseDifferentCircuits() throws Exception {
        Path externalTorDir = Files.createDirectories(tempDir.resolve("erin-external-tor"));
        try (ExternalTorProcess externalTor = ExternalTorProcess.start(externalTorDir,
                torNetwork.getDirectoryAuthorities(), ExternalTorProcess.Authentication.PASSWORD);
             ServerSocket server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            startEchoServer(server);
            Path erinTorDir = Files.createDirectories(tempDir.resolve("erin"));
            Files.writeString(erinTorDir.resolve("external_tor.config"), externalTor.toExternalTorConfig());
            try (OnionPeer erin = startPeer("erin");
                 Socket first = openExchangedSocket(erin.getTorService(), server.getLocalPort(), "stream-a");
                 Socket second = openExchangedSocket(erin.getTorService(), server.getLocalPort(), "stream-b")) {
                TorControlProtocol torControlProtocol = externalTor.connectController();
                try {
                    // StreamID StreamStatus CircuitID Target, one line per stream. The other streams carry the
                    // descriptors of the onion service of erin. All relays of the network have the address
                    // 127.0.0.1, so Tor names the target as 127.0.0.1.$<fingerprint of the exit>.exit:<port>.
                    String streamStatus = torControlProtocol.getInfo("stream-status");
                    String targetPort = ":" + server.getLocalPort();
                    Set<String> circuitIds = Arrays.stream(streamStatus.substring(streamStatus.indexOf('=') + 1)
                                    .split("\n"))
                            .map(line -> line.trim().split(" "))
                            .filter(fields -> fields.length == 4 && fields[1].equals("SUCCEEDED") &&
                                    fields[3].startsWith("127.0.0.1") && fields[3].endsWith(targetPort))
                            .map(fields -> fields[2])
                            .collect(Collectors.toSet());
                    assertThat(circuitIds)
                            .as("circuits of the two streams to port %s in %s", server.getLocalPort(), streamStatus)
                            .hasSize(2);
                } finally {
                    torControlProtocol.close();
                }
            }
        }
    }

    // Answers each line with the same line and keeps the connection open, unlike AckServer, so that the streams stay
    // in the stream-status of Tor
    private static void startEchoServer(ServerSocket serverSocket) {
        Thread acceptThread = new Thread(() -> {
            while (!serverSocket.isClosed()) {
                try {
                    Socket socket = serverSocket.accept();
                    Thread echoThread = new Thread(() -> {
                        try (socket) {
                            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(),
                                    StandardCharsets.UTF_8));
                            OutputStream outputStream = socket.getOutputStream();
                            String line;
                            while ((line = reader.readLine()) != null) {
                                outputStream.write((line + "\n").getBytes(StandardCharsets.UTF_8));
                                outputStream.flush();
                            }
                        } catch (IOException ignore) {
                            // The test ends the connection
                        }
                    }, "echo-connection");
                    echoThread.setDaemon(true);
                    echoThread.start();
                } catch (IOException ignore) {
                    // The test closed the server
                }
            }
        }, "echo-server");
        acceptThread.setDaemon(true);
        acceptThread.start();
    }

    // A circuit of the private network can fail, so the test tries again until the connect timeout has passed.
    private Socket openExchangedSocket(TorService torService, int port, String streamId) throws Exception {
        long deadline = System.nanoTime() + getConnectTimeout().toNanos();
        while (true) {
            Socket socket = torService.getSocket("127.0.0.1", port, streamId, AckServer.SOCKET_TIMEOUT_MS);
            try {
                AckServer.exchange(socket, "hello from " + streamId);
                return socket;
            } catch (IOException e) {
                socket.close();
                if (System.nanoTime() > deadline) {
                    throw e;
                }
                Thread.sleep(1000);
            }
        }
    }

    @ParameterizedTest
    @EnumSource(ExternalTorProcess.Authentication.class)
    void aPeerOfAnExternalTorExchangesMessagesWithAPeerOfAnEmbeddedTor(ExternalTorProcess.Authentication authentication)
            throws Exception {
        String name = "dave-" + authentication.name().toLowerCase(Locale.ROOT);
        Path externalTorDir = Files.createDirectories(tempDir.resolve(name + "-external-tor"));
        try (ExternalTorProcess externalTor = ExternalTorProcess.start(externalTorDir,
                torNetwork.getDirectoryAuthorities(), authentication)) {
            Path daveTorDir = Files.createDirectories(tempDir.resolve(name));
            Files.writeString(daveTorDir.resolve("external_tor.config"), externalTor.toExternalTorConfig());

            try (OnionPeer dave = startPeer(name)) {
                assertThat(dave.getTorService().isUseExternalTor()).isTrue();
                assertThat(alice.send(dave, "hello dave")).isEqualTo(AckServer.ackOf(name, "hello dave"));
                assertThat(dave.send(alice, "hello alice")).isEqualTo(AckServer.ackOf("alice", "hello alice"));
            }
        }
    }
}

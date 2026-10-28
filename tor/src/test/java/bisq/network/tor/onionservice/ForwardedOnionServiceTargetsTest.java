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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ForwardedOnionServiceTargetsTest {
    private static final String ONION_A = "a".repeat(56) + ".onion";
    private static final String ONION_B = "b".repeat(56) + ".onion";
    private static final String ONION_C = "c".repeat(56) + ".onion";
    private static final String CONFIG_KEY = "test.onionServicePortPoolSize";

    private ForwardedOnionServiceTargets targets;
    private List<ForwardedOnionServiceTargets.PortPair> portPairs;

    @BeforeEach
    void setUp() throws IOException {
        List<ServerSocket> serverSockets = ForwardedOnionServiceTargets.bindOuterServerSockets(2);
        targets = new ForwardedOnionServiceTargets(serverSockets, LoopbackPorts.allocate(2), CONFIG_KEY);
        portPairs = targets.getPortPairs();
    }

    @AfterEach
    void tearDown() {
        targets.close();
    }

    @Test
    void theReservationAllocatesTheListenerPortsTogetherWithThePool() throws IOException {
        ForwardedOnionServiceTargets.Reservation reservation = ForwardedOnionServiceTargets.reserve(2, 4, CONFIG_KEY);
        try {
            List<ForwardedOnionServiceTargets.PortPair> pairs = reservation.targets().getPortPairs();
            Set<Integer> allPorts = new HashSet<>(reservation.listenerPorts());
            pairs.forEach(pair -> {
                allPorts.add(pair.innerPort());
                allPorts.add(pair.outerPort());
            });

            assertThat(reservation.listenerPorts()).hasSize(4);
            assertThat(pairs).hasSize(2);
            assertThat(allPorts).hasSize(8);
        } finally {
            reservation.targets().close();
        }
    }

    @Test
    void theReservationClosesTheOuterServerSocketsWhenTheAllocationFails() throws IOException {
        List<ServerSocket> serverSockets = ForwardedOnionServiceTargets.bindOuterServerSockets(2);

        assertThatThrownBy(() -> ForwardedOnionServiceTargets.reserve(serverSockets, 4, CONFIG_KEY, count -> {
            throw new IOException("no free port");
        }))
                .isInstanceOf(IOException.class)
                .hasMessage("no free port");

        assertThat(serverSockets).allMatch(ServerSocket::isClosed);
    }

    @Test
    void outerPortsAreBoundUntilUsed() {
        for (ForwardedOnionServiceTargets.PortPair portPair : portPairs) {
            assertThatThrownBy(() -> new ServerSocket(portPair.outerPort(), 1, LoopbackPorts.IPV4_LOOPBACK).close())
                    .isInstanceOf(IOException.class);
        }
    }

    @Test
    void anOnionServiceKeepsItsPortPair() throws IOException {
        OnionServiceTargets.Target first = targets.bindServerSocket(ONION_A);
        assertThat(first.torTargetPort()).isEqualTo(portPairs.get(0).innerPort());
        assertThat(first.serverSocket().getLocalPort()).isEqualTo(portPairs.get(0).outerPort());

        // The node of the onion service ends and a new node binds the server socket again.
        first.serverSocket().close();
        OnionServiceTargets.Target second = targets.bindServerSocket(ONION_A);

        assertThat(second.torTargetPort()).isEqualTo(first.torTargetPort());
        assertThat(second.serverSocket().getLocalPort()).isEqualTo(portPairs.get(0).outerPort());
        second.serverSocket().close();
    }

    @Test
    void refusesASecondOpenServerSocketForOneOnionService() throws IOException {
        OnionServiceTargets.Target target = targets.bindServerSocket(ONION_A);

        assertThatThrownBy(() -> targets.bindServerSocket(ONION_A))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("still open");
        target.serverSocket().close();
    }

    @Test
    void failsWhenThePoolIsExhausted() throws IOException {
        targets.bindServerSocket(ONION_A).serverSocket().close();
        targets.bindServerSocket(ONION_B).serverSocket().close();

        assertThatThrownBy(() -> targets.bindServerSocket(ONION_C))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("All 2 ports")
                .hasMessageContaining(CONFIG_KEY);
        assertThatThrownBy(() -> targets.targetPortOf(ONION_C, 1234))
                .isInstanceOf(IOException.class);
    }

    @Test
    void relaysToAServerOfTheApplication() throws Exception {
        try (ServerSocket apiServerSocket = new ServerSocket(0, 1, LoopbackPorts.IPV4_LOOPBACK)) {
            CompletableFuture<String> received = CompletableFuture.supplyAsync(() -> echoOnce(apiServerSocket));

            int torTargetPort = targets.targetPortOf(ONION_A, apiServerSocket.getLocalPort());
            assertThat(torTargetPort).isEqualTo(portPairs.get(0).innerPort());
            assertThat(targets.getBindAddress()).isEqualTo(apiServerSocket.getInetAddress());
            assertThat(targets.targetPortOf(ONION_A, apiServerSocket.getLocalPort())).isEqualTo(torTargetPort);

            // sandy would relay Tor's connection from the inner port to the outer port.
            try (Socket socket = new Socket(LoopbackPorts.IPV4_LOOPBACK, portPairs.get(0).outerPort())) {
                socket.getOutputStream().write("hello\n".getBytes(StandardCharsets.UTF_8));
                socket.getOutputStream().flush();
                String reply = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8)).readLine();
                assertThat(reply).isEqualTo("echo:hello");
            }
            assertThat(received.get(10, TimeUnit.SECONDS)).isEqualTo("hello");
        }
    }

    @Test
    void aRetryWithAnotherLocalPortMovesTheRelayAndKeepsThePortOfTor() throws Exception {
        // Tor keeps the target port of a published onion service, so a retry with another server of the application
        // must reach it through the same inner port.
        try (ServerSocket firstServerSocket = new ServerSocket(0, 1, LoopbackPorts.IPV4_LOOPBACK);
             ServerSocket secondServerSocket = new ServerSocket(0, 1, LoopbackPorts.IPV4_LOOPBACK)) {
            int torTargetPort = targets.targetPortOf(ONION_A, firstServerSocket.getLocalPort());
            CompletableFuture<String> received = CompletableFuture.supplyAsync(() -> echoOnce(secondServerSocket));

            assertThat(targets.targetPortOf(ONION_A, secondServerSocket.getLocalPort())).isEqualTo(torTargetPort);

            try (Socket socket = new Socket(LoopbackPorts.IPV4_LOOPBACK, portPairs.get(0).outerPort())) {
                socket.getOutputStream().write("hello\n".getBytes(StandardCharsets.UTF_8));
                socket.getOutputStream().flush();
                String reply = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8)).readLine();
                assertThat(reply).isEqualTo("echo:hello");
            }
            assertThat(received.get(10, TimeUnit.SECONDS)).isEqualTo("hello");
        }
    }

    @Test
    void anOnionServiceUsesEitherItsOwnServerSocketOrARelay() throws IOException {
        targets.targetPortOf(ONION_A, 1234);
        assertThatThrownBy(() -> targets.bindServerSocket(ONION_A)).isInstanceOf(IOException.class);

        targets.bindServerSocket(ONION_B).serverSocket().close();
        assertThatThrownBy(() -> targets.targetPortOf(ONION_B, 1234)).isInstanceOf(IOException.class);
    }

    @Test
    void closeReleasesUnusedOuterPorts() throws IOException {
        targets.close();

        for (ForwardedOnionServiceTargets.PortPair portPair : portPairs) {
            new ServerSocket(portPair.outerPort(), 1, LoopbackPorts.IPV4_LOOPBACK).close();
        }
    }

    private static String echoOnce(ServerSocket serverSocket) {
        try (Socket socket = serverSocket.accept()) {
            String line = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8)).readLine();
            OutputStream outputStream = socket.getOutputStream();
            outputStream.write(("echo:" + line + "\n").getBytes(StandardCharsets.UTF_8));
            outputStream.flush();
            return line;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}

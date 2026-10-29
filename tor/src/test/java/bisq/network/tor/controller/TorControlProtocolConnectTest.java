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

import bisq.network.tor.controller.exceptions.CannotConnectWithTorException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.List;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * A close of the protocol, for example by a shutdown during the start, ends a connect which still runs. A connect which
 * waits is modelled by a listener whose backlog is full: Linux then drops the connection request until the backlog
 * empties.
 */
@Timeout(30)
class TorControlProtocolConnectTest {
    private static final int CONNECT_TIMEOUT_MS = 300;

    private final TorControlProtocol torControlProtocol = new TorControlProtocol(10_000);
    // Also written by the threads of the tests
    private final List<AutoCloseable> resources = new CopyOnWriteArrayList<>();

    @AfterEach
    void tearDown() throws Exception {
        torControlProtocol.close();
        for (AutoCloseable resource : resources) {
            resource.close();
        }
    }

    @Test
    void aClosedProtocolDoesNotConnect() throws IOException {
        ServerSocket serverSocket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
        resources.add(serverSocket);
        torControlProtocol.close();

        assertThatThrownBy(() -> torControlProtocol.initialize(serverSocket.getLocalPort()))
                .isInstanceOf(CannotConnectWithTorException.class)
                .hasMessageContaining("closed while it was being made");
        serverSocket.setSoTimeout(500);
        assertThatThrownBy(serverSocket::accept).isInstanceOf(SocketTimeoutException.class);
    }

    // The close comes while the connect waits for a listener whose backlog is full. Once the test empties the backlog,
    // Linux accepts the repeated connection request, and the connection exists after the close.
    @Test
    void aConnectionWhichIsMadeAfterTheCloseIsClosed() throws Exception {
        ServerSocket serverSocket = listenWithFullBacklog();
        Set<Integer> portsOfTheFillers = resources.stream()
                .filter(resource -> resource instanceof Socket socket && socket.isConnected())
                .map(resource -> ((Socket) resource).getLocalPort())
                .collect(Collectors.toSet());
        TorControlProtocol slowProtocol = new TorControlProtocol(10_000);
        resources.add(slowProtocol);
        CompletableFuture<Void> connecting = CompletableFuture.runAsync(() ->
                slowProtocol.initialize(serverSocket.getLocalPort()));
        Thread.sleep(200);

        slowProtocol.close();
        BlockingQueue<Socket> acceptedSockets = new LinkedBlockingQueue<>();
        Thread acceptor = new Thread(() -> {
            try {
                while (true) {
                    Socket socket = serverSocket.accept();
                    resources.add(socket);
                    acceptedSockets.add(socket);
                }
            } catch (IOException ignore) {
                // The test closed the server socket
            }
        });
        acceptor.start();

        assertThatThrownBy(connecting::join)
                .hasCauseInstanceOf(CannotConnectWithTorException.class)
                .hasMessageContaining("closed while it was being made");
        // If the connection was made, the protocol closed it: the listener reads its end.
        Socket acceptedSocket;
        while ((acceptedSocket = acceptedSockets.poll(2, TimeUnit.SECONDS)) != null) {
            if (!portsOfTheFillers.contains(acceptedSocket.getPort())) {
                acceptedSocket.setSoTimeout(3000);
                assertThat(acceptedSocket.getInputStream().read()).isEqualTo(-1);
            }
        }
    }

    private ServerSocket listenWithFullBacklog() throws IOException {
        ServerSocket serverSocket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
        resources.add(serverSocket);
        for (int i = 0; i < 10; i++) {
            Socket socket = new Socket();
            resources.add(socket);
            try {
                socket.connect(serverSocket.getLocalSocketAddress(), CONNECT_TIMEOUT_MS);
            } catch (SocketTimeoutException e) {
                return serverSocket;
            } catch (SocketException e) {
                assumeTrue(false, "This system rejects a connection to a listener whose backlog is full: " + e);
            }
        }
        assumeTrue(false, "The backlog of the listener did not fill up");
        return serverSocket;
    }
}

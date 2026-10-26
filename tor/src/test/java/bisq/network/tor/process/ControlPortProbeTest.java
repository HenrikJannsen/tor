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

package bisq.network.tor.process;

import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class ControlPortProbeTest {
    @Test
    void torAnswersProtocolInfo() throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(0, 1, LoopbackPorts.IPV4_LOOPBACK)) {
            CompletableFuture<String> request = CompletableFuture.supplyAsync(() -> {
                try (Socket socket = serverSocket.accept()) {
                    String line = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII)).readLine();
                    socket.getOutputStream().write("250-PROTOCOLINFO 1\r\n250 OK\r\n".getBytes(StandardCharsets.US_ASCII));
                    return line;
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });

            assertThat(ControlPortProbe.isTorAnswering(serverSocket.getLocalPort())).isTrue();
            assertThat(request.get(5, TimeUnit.SECONDS)).isEqualTo("PROTOCOLINFO 1");
        }
    }

    @Test
    void relayWithoutTorClosesTheConnection() throws Exception {
        // sandy accepts on the exposed port and closes the connection while Tor does not listen yet.
        try (ServerSocket serverSocket = new ServerSocket(0, 1, LoopbackPorts.IPV4_LOOPBACK)) {
            CompletableFuture.runAsync(() -> {
                try {
                    serverSocket.accept().close();
                } catch (IOException ignore) {
                }
            });

            assertThat(ControlPortProbe.isTorAnswering(serverSocket.getLocalPort())).isFalse();
        }
    }

    @Test
    void nothingListens() throws IOException {
        int port = LoopbackPorts.allocate(1).get(0);

        assertThat(ControlPortProbe.isTorAnswering(port)).isFalse();
    }

    @Test
    void allocatesDistinctFreeLoopbackPorts() throws IOException {
        List<Integer> ports = LoopbackPorts.allocate(10);

        assertThat(ports).hasSize(10).doesNotHaveDuplicates();
        for (int port : ports) {
            new ServerSocket(port, 1, LoopbackPorts.IPV4_LOOPBACK).close();
        }
    }
}

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

import lombok.extern.slf4j.Slf4j;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Answers each connection with an acknowledgement of the first line it receives, as the peers of the peer message test
 * of netlayer do.
 */
@Slf4j
final class AckServer implements AutoCloseable {
    static final int SOCKET_TIMEOUT_MS = 60_000;

    private final String name;
    private final ServerSocket serverSocket;
    private final Thread acceptThread;

    private AckServer(String name, ServerSocket serverSocket) {
        this.name = name;
        this.serverSocket = serverSocket;
        acceptThread = new Thread(this::acceptConnections, name + "-ack-server");
        acceptThread.setDaemon(true);
    }

    static AckServer start(String name, ServerSocket serverSocket) {
        AckServer ackServer = new AckServer(name, serverSocket);
        ackServer.acceptThread.start();
        return ackServer;
    }

    static String ackOf(String name, String message) {
        return "ack from " + name + ": " + message;
    }

    /**
     * Sends the message as one line on the socket and returns the line which the server answers.
     */
    static String exchange(Socket socket, String message) throws IOException {
        socket.setSoTimeout(SOCKET_TIMEOUT_MS);
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));
        writer.write(message);
        writer.newLine();
        writer.flush();
        String reply = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8))
                .readLine();
        if (reply == null) {
            throw new EOFException("The connection ended without an answer");
        }
        return reply;
    }

    int getPort() {
        return serverSocket.getLocalPort();
    }

    private void acceptConnections() {
        while (!serverSocket.isClosed()) {
            try {
                Socket socket = serverSocket.accept();
                Thread thread = new Thread(() -> answer(socket), name + "-ack-connection");
                thread.setDaemon(true);
                thread.start();
            } catch (IOException e) {
                if (!serverSocket.isClosed()) {
                    log.warn("{} could not accept a connection", name, e);
                }
            }
        }
    }

    private void answer(Socket socket) {
        try (socket) {
            socket.setSoTimeout(SOCKET_TIMEOUT_MS);
            String message = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8))
                    .readLine();
            if (message != null) {
                BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(),
                        StandardCharsets.UTF_8));
                writer.write(ackOf(name, message));
                writer.newLine();
                writer.flush();
            }
        } catch (IOException e) {
            log.info("{} could not answer a connection: {}", name, e.toString());
        }
    }

    @Override
    public void close() throws InterruptedException {
        try {
            serverSocket.close();
        } catch (IOException e) {
            log.warn("{} could not close its server socket", name, e);
        }
        acceptThread.join(5_000);
    }
}

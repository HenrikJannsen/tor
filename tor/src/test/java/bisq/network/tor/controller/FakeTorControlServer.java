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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;

/**
 * A local control port which answers each command with the reply of a function and records the commands.
 */
public class FakeTorControlServer implements AutoCloseable {
    private final ServerSocket serverSocket;
    private final List<String> commands = new CopyOnWriteArrayList<>();
    private final Thread serverThread;
    private volatile Optional<String> closeAfterCommandStart = Optional.empty();

    public FakeTorControlServer(Function<String, String> replyByCommand) throws IOException {
        serverSocket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
        serverThread = new Thread(() -> {
            try (Socket socket = serverSocket.accept();
                 BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII));
                 OutputStream outputStream = socket.getOutputStream()) {
                String command;
                while ((command = reader.readLine()) != null) {
                    commands.add(command);
                    outputStream.write(replyByCommand.apply(command).getBytes(StandardCharsets.US_ASCII));
                    outputStream.flush();
                    String closedCommand = command;
                    if (closeAfterCommandStart.filter(closedCommand::startsWith).isPresent()) {
                        socket.close();
                        return;
                    }
                }
            } catch (IOException ignore) {
                // The test closes the sockets
            }
        }, "FakeTorControlServer");
        serverThread.start();
    }

    public int getPort() {
        return serverSocket.getLocalPort();
    }

    public List<String> getCommands() {
        return commands;
    }

    /**
     * Ends the connection after the reply to the first command which starts with {@code commandStart}, as when Tor
     * exits.
     */
    public void closeConnectionAfter(String commandStart) {
        closeAfterCommandStart = Optional.of(commandStart);
    }

    @Override
    public void close() throws Exception {
        serverSocket.close();
        serverThread.join(5000);
    }
}

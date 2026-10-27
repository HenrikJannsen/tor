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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The reply of Tor is untrusted input: a reply which arrives one line at a time, each line just before the timeout of
 * a line, must not hold a command forever.
 */
@Timeout(10)
class TorControlProtocolReplyTimeoutTest {
    private static final long REPLY_TIMEOUT_MS = 500;
    private static final long PAUSE_BETWEEN_LINES_MS = 200;
    private static final int LINES = 5;

    private ServerSocket serverSocket;
    private Thread serverThread;
    private TorControlProtocol torControlProtocol;

    @AfterEach
    void tearDown() throws Exception {
        torControlProtocol.close();
        serverSocket.close();
        serverThread.interrupt();
        serverThread.join(5000);
    }

    @Test
    void aReplyWhichDripsLineByLineEndsAtTheDeadlineOfTheReply() throws Exception {
        serverSocket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
        serverThread = new Thread(this::answerLineByLine, "DrippingTorControlServer");
        serverThread.start();
        torControlProtocol = new TorControlProtocol(REPLY_TIMEOUT_MS);
        torControlProtocol.initialize(serverSocket.getLocalPort());

        long start = System.currentTimeMillis();
        assertThatThrownBy(() -> torControlProtocol.getInfo("version"))
                .isInstanceOf(ControlCommandFailedException.class);

        // Well before the lines would have arrived with one timeout per line
        assertThat(System.currentTimeMillis() - start).isLessThan(LINES * PAUSE_BETWEEN_LINES_MS);
    }

    @Test
    void aCommandWhichTorDoesNotTakeEndsAtTheTimeout() throws Exception {
        // Tor accepts the connection and reads nothing, so the write blocks once the buffers of the sockets are full.
        serverSocket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
        serverThread = new Thread(this::acceptAndReadNothing, "SilentTorControlServer");
        serverThread.start();
        torControlProtocol = new TorControlProtocol(REPLY_TIMEOUT_MS);
        torControlProtocol.initialize(serverSocket.getLocalPort());
        // Far more than the buffers of a loopback connection. The log form of SETCONF hides the value.
        String value = "x".repeat(64 * 1024 * 1024);

        long start = System.currentTimeMillis();
        assertThatThrownBy(() -> torControlProtocol.setConfig("ContactInfo", value))
                .isInstanceOf(ControlCommandFailedException.class)
                .hasMessageContaining("did not take the command");

        assertThat(System.currentTimeMillis() - start).isLessThan(5000);
    }

    private void acceptAndReadNothing() {
        try (Socket ignored = serverSocket.accept()) {
            Thread.sleep(10_000);
        } catch (IOException | InterruptedException ignore) {
            // The test closes the connection
        }
    }

    // Answers the first command with mid reply lines which arrive within the timeout of a line, but not within the
    // timeout of the reply
    private void answerLineByLine() {
        try (Socket socket = serverSocket.accept();
             BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII));
             OutputStream outputStream = socket.getOutputStream()) {
            reader.readLine();
            for (int i = 0; i < LINES; i++) {
                outputStream.write(("250-line" + i + "=x\r\n").getBytes(StandardCharsets.US_ASCII));
                outputStream.flush();
                Thread.sleep(PAUSE_BETWEEN_LINES_MS);
            }
            outputStream.write("250 OK\r\n".getBytes(StandardCharsets.US_ASCII));
            outputStream.flush();
        } catch (IOException | InterruptedException ignore) {
            // The test closes the connection
        }
    }
}

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
import org.junit.jupiter.api.BeforeEach;
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
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

// Bisq chooses the control port and releases it before Tor binds it, so another process could answer on it.
@Timeout(10)
class TorControllerVerificationTest {
    private final PasswordDigest passwordDigest = PasswordDigest.generateDigest();
    private final TorController torController = new TorController(1000, 1000);
    private ServerSocket serverSocket;
    private Thread serverThread;

    @BeforeEach
    void setUp() throws IOException {
        serverSocket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
    }

    @AfterEach
    void tearDown() throws Exception {
        torController.shutdown();
        serverSocket.close();
        if (serverThread != null) {
            serverThread.join(5000);
        }
    }

    @Test
    void torOfThisStartReportsTheHashFromTheTorrc() {
        startControlServer(command -> command.startsWith("GETCONF") ?
                "250 HashedControlPassword=" + passwordDigest.getHashedPassword().toLowerCase() + "\r\n" :
                "250 OK\r\n");

        torController.authenticate(passwordDigest);

        assertThatCode(() -> torController.verifyHashedControlPassword(passwordDigest)).doesNotThrowAnyException();
    }

    @Test
    void anotherProcessThatAcceptsEverythingIsRefused() {
        startControlServer(command -> "250 OK\r\n");

        torController.authenticate(passwordDigest);

        assertThatThrownBy(() -> torController.verifyHashedControlPassword(passwordDigest))
                .isInstanceOf(ControlCommandFailedException.class);
    }

    @Test
    void anotherHashIsRefused() {
        String otherHash = PasswordDigest.generateDigest().getHashedPassword();
        startControlServer(command -> command.startsWith("GETCONF") ?
                "250 HashedControlPassword=" + otherHash + "\r\n" :
                "250 OK\r\n");

        torController.authenticate(passwordDigest);

        assertThatThrownBy(() -> torController.verifyHashedControlPassword(passwordDigest))
                .isInstanceOf(TorControlAuthenticationFailed.class);
    }

    // Tor names an option without a value without "=".
    @Test
    void aTorWithoutControlPasswordIsRefused() {
        startControlServer(command -> command.startsWith("GETCONF") ? "250 HashedControlPassword\r\n" : "250 OK\r\n");

        torController.authenticate(passwordDigest);

        assertThatThrownBy(() -> torController.verifyHashedControlPassword(passwordDigest))
                .isInstanceOf(TorControlAuthenticationFailed.class);
    }

    private void startControlServer(Function<String, String> replyByCommand) {
        serverThread = new Thread(() -> {
            try (Socket socket = serverSocket.accept();
                 BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII));
                 OutputStream outputStream = socket.getOutputStream()) {
                String command;
                while ((command = reader.readLine()) != null) {
                    outputStream.write(replyByCommand.apply(command).getBytes(StandardCharsets.US_ASCII));
                    outputStream.flush();
                }
            } catch (IOException ignore) {
                // The test closes the sockets
            }
        }, "FakeTorControlServer");
        serverThread.start();
        torController.initialize(serverSocket.getLocalPort());
    }
}

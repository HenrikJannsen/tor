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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Checks whether Tor answers on its control port. A successful TCP connect is not enough: sandy accepts connections
 * on the exposed port before Tor listens on the inner port, and then closes them.
 */
public final class ControlPortProbe {
    private static final int TIMEOUT_MS = 2000;
    private static final int MAX_LINE_LENGTH = 512;

    private ControlPortProbe() {
    }

    public static boolean isTorAnswering(int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(LoopbackPorts.IPV4_LOOPBACK, port), TIMEOUT_MS);
            socket.setSoTimeout(TIMEOUT_MS);
            OutputStream outputStream = socket.getOutputStream();
            // Tor answers PROTOCOLINFO before authentication.
            outputStream.write("PROTOCOLINFO 1\r\n".getBytes(StandardCharsets.US_ASCII));
            outputStream.flush();
            return readLine(socket.getInputStream()).startsWith("250");
        } catch (IOException e) {
            return false;
        }
    }

    private static String readLine(InputStream inputStream) throws IOException {
        StringBuilder line = new StringBuilder();
        int character;
        while (line.length() < MAX_LINE_LENGTH && (character = inputStream.read()) != -1 && character != '\n') {
            line.append((char) character);
        }
        return line.toString();
    }
}

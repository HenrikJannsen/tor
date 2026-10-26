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
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public final class LoopbackPorts {
    /**
     * Tor, sandy and Bisq use IPv4 loopback for the local connections between them. {@link
     * InetAddress#getLoopbackAddress()} returns the IPv6 address when the JVM prefers IPv6.
     */
    public static final InetAddress IPV4_LOOPBACK = createIpv4Loopback();

    private LoopbackPorts() {
    }

    /**
     * Returns {@code count} distinct loopback ports which are free at the time of the call. The ports are released
     * before the method returns, so another process can take one of them before Tor or sandy binds it. Tor then fails
     * to start with a bind error, and the next start uses other ports.
     */
    public static List<Integer> allocate(int count) throws IOException {
        List<ServerSocket> serverSockets = new ArrayList<>(count);
        try {
            for (int i = 0; i < count; i++) {
                // Keeping every socket open until all are chosen makes the ports distinct.
                serverSockets.add(new ServerSocket(0, 1, IPV4_LOOPBACK));
            }
            return serverSockets.stream().map(ServerSocket::getLocalPort).collect(Collectors.toList());
        } finally {
            for (ServerSocket serverSocket : serverSockets) {
                try {
                    serverSocket.close();
                } catch (IOException ignore) {
                }
            }
        }
    }

    private static InetAddress createIpv4Loopback() {
        try {
            return InetAddress.getByAddress("localhost", new byte[]{127, 0, 0, 1});
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }
}

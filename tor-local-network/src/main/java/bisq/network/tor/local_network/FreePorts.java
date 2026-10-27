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
package bisq.network.tor.local_network;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Finds free TCP ports for the nodes of the local Tor network. All ports are chosen before the Tor processes bind
 * them, and the system can return a port again after the probe socket is closed. So a port is never returned twice.
 * The probe binds the address on which the nodes listen, so it opens no port to other hosts.
 */
public class FreePorts {
    // The nodes of the local Tor network listen on this address only, see TestNetworkTorrcGenerator
    private static final String NODE_ADDRESS = "127.0.0.1";
    private static final Set<Integer> RETURNED_PORTS = ConcurrentHashMap.newKeySet();
    private static final int MAX_ATTEMPTS = 1000;

    private FreePorts() {
    }

    public static int find() {
        for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
            int port;
            try (ServerSocket serverSocket = new ServerSocket(0, 1, InetAddress.getByName(NODE_ADDRESS))) {
                port = serverSocket.getLocalPort();
            } catch (IOException e) {
                throw new UncheckedIOException("Could not find a free port", e);
            }
            if (RETURNED_PORTS.add(port)) {
                return port;
            }
        }
        throw new IllegalStateException("The system returned no new free port in " + MAX_ATTEMPTS + " attempts");
    }
}

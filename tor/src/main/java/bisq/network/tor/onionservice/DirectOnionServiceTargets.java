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

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;

/**
 * Tor connects directly to the server socket of the onion service.
 */
public final class DirectOnionServiceTargets implements OnionServiceTargets {
    private static final int BACKLOG = 50;

    private final InetAddress bindAddress;

    public DirectOnionServiceTargets(InetAddress bindAddress) {
        this.bindAddress = bindAddress;
    }

    @Override
    public synchronized Target bindServerSocket(String onionAddress) throws IOException {
        ServerSocket serverSocket = new ServerSocket(0, BACKLOG, bindAddress);
        return new Target(serverSocket, serverSocket.getLocalPort());
    }

    @Override
    public int targetPortOf(String onionAddress, int localPort) {
        return localPort;
    }

    @Override
    public void close() {
    }
}

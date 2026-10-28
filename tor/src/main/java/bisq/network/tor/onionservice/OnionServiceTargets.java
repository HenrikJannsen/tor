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
 * The local endpoints of the onion services of one Tor process: where Bisq accepts the connections of an onion
 * service, and which loopback port Tor connects to (the target port of {@code ADD_ONION}).
 * <p>
 * Tor keeps the target port of a published onion service until it ends. All calls for one onion address therefore
 * return the same target port, also after the server socket of the onion service was closed and is bound again.
 */
public interface OnionServiceTargets extends AutoCloseable {
    record Target(ServerSocket serverSocket, int torTargetPort) {
    }

    /**
     * Binds a server socket for the onion service.
     */
    Target bindServerSocket(String onionAddress) throws IOException;

    /**
     * Makes the connections of the onion service reach a server of the application that listens on the port
     * {@code localPort} of {@link #getBindAddress()}.
     *
     * @return the port that Tor connects to
     */
    int targetPortOf(String onionAddress, int localPort) throws IOException;

    /**
     * @return the address on which a server of the application has to listen for {@link #targetPortOf}, so that Tor
     * or the relay in front of Tor reaches it
     */
    InetAddress getBindAddress();

    @Override
    void close();
}

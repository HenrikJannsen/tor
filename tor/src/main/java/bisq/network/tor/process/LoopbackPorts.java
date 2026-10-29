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

import java.net.InetAddress;
import java.net.UnknownHostException;

public final class LoopbackPorts {
    /**
     * Tor and Bisq use IPv4 loopback for the local connections between them. {@link
     * InetAddress#getLoopbackAddress()} returns the IPv6 address when the JVM prefers IPv6.
     */
    public static final InetAddress IPV4_LOOPBACK = createIpv4Loopback();

    private LoopbackPorts() {
    }

    private static InetAddress createIpv4Loopback() {
        try {
            return InetAddress.getByAddress("localhost", new byte[]{127, 0, 0, 1});
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }
}

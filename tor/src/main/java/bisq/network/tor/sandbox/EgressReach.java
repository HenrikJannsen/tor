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

package bisq.network.tor.sandbox;

import java.net.Inet4Address;
import java.net.InetAddress;

/**
 * What the egress broker of sandy cannot reach with {@code reach = "public"}, the setting of every template with a
 * broker. The library tells only the addresses of this host and of the local network; the broker refuses more, for
 * example the documentation ranges and the addresses which this host has on its interfaces (sandy
 * {@code crates/sandy-core/src/destination.rs}).
 */
public final class EgressReach {
    private EgressReach() {
    }

    /**
     * @return true for a loopback, unspecified, link-local or private address, the shared address space 100.64.0.0/10
     * and the unique local addresses fc00::/7
     */
    public static boolean isOfThisHostOrLocalNetwork(InetAddress address) {
        if (address.isLoopbackAddress() || address.isAnyLocalAddress() || address.isLinkLocalAddress() ||
                address.isSiteLocalAddress()) {
            return true;
        }
        byte[] bytes = address.getAddress();
        if (address instanceof Inet4Address) {
            return (bytes[0] & 0xff) == 100 && (bytes[1] & 0xc0) == 64;
        }
        return (bytes[0] & 0xfe) == 0xfc;
    }
}

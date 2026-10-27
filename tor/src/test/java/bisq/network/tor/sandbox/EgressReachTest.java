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

import com.google.common.net.InetAddresses;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class EgressReachTest {
    @Test
    void addressesOfThisHostAndOfTheLocalNetwork() {
        for (String address : List.of("127.0.0.1", "127.8.9.10", "0.0.0.0", "10.1.2.3", "172.16.0.1", "172.31.255.255",
                "192.168.0.1", "169.254.1.1", "100.64.0.1", "100.127.255.255", "::1", "::", "fe80::1", "fc00::1",
                "fd12:3456::1", "::ffff:192.168.0.1")) {
            assertThat(EgressReach.isOfThisHostOrLocalNetwork(InetAddresses.forString(address))).as(address).isTrue();
        }
    }

    @Test
    void otherAddressesAreLeftToTheBroker() {
        for (String address : List.of("1.1.1.1", "172.32.0.1", "100.128.0.1", "192.0.2.1", "2001:4860:4860::8888",
                "fe00::1")) {
            assertThat(EgressReach.isOfThisHostOrLocalNetwork(InetAddresses.forString(address))).as(address).isFalse();
        }
    }
}

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

/**
 * The loopback ports of the control and SOCKS listeners of the embedded Tor. Bisq chooses them before it starts Tor.
 */
public record TorListenerPorts(PortMapping control, PortMapping socks) {
    /**
     * Tor listens on {@code innerPort}. Bisq connects to {@code outerPort}. Inside the sandbox they differ, because
     * sandy relays from the outer to the inner port. Without the sandbox they are equal.
     */
    public record PortMapping(int innerPort, int outerPort) {
        public boolean isRelayed() {
            return innerPort != outerPort;
        }
    }
}

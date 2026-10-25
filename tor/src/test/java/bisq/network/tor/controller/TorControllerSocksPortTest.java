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

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TorControllerSocksPortTest {
    @Test
    void theEmbeddedTorHasOneListener() {
        assertThat(TorController.parseSocksPort("250-net/listeners/socks=\"127.0.0.1:41235\"")).isEqualTo(41235);
    }

    @Test
    void theSystemTorOfDebianListsItsUnixSocketFirst() {
        // SocksPort unix:/run/tor/socks WorldWritable and SocksPort 9050 in /usr/share/tor/tor-service-defaults-torrc
        assertThat(TorController.parseSocksPort("250-net/listeners/socks=\"unix:/run/tor/socks\" \"127.0.0.1:9050\""))
                .isEqualTo(9050);
    }

    @Test
    void anIpv6ListenerAndAnEscapedPathAreRead() {
        assertThat(TorController.parseSocksPort("250-net/listeners/socks=\"[::1]:9150\"")).isEqualTo(9150);
        assertThat(TorController.parseSocksPort(
                "250-net/listeners/socks=\"unix:/home/a \\\"b\\\"/socks\" \"127.0.0.1:9050\"")).isEqualTo(9050);
    }

    @Test
    void withoutTcpListenerTheStartFails() {
        assertThatThrownBy(() -> TorController.parseSocksPort("250-net/listeners/socks=\"unix:/run/tor/socks\""))
                .isInstanceOf(ControlCommandFailedException.class);
        assertThatThrownBy(() -> TorController.parseSocksPort("250-net/listeners/socks="))
                .isInstanceOf(ControlCommandFailedException.class);
        assertThatThrownBy(() -> TorController.parseSocksPort("250 OK"))
                .isInstanceOf(ControlCommandFailedException.class);
    }
}

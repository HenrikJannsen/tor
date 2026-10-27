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

import bisq.network.tor.onionservice.OnionServiceKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Each command accepts only the reply which it expects. A reply to another command, which a broken or hostile Tor
 * could send, or a reply without its end must not pass as the answer.
 */
@Timeout(10)
class TorControlProtocolReplyValidationTest {
    private final OnionServiceKey onionServiceKey = TestKeys.randomOnionServiceKey();
    private final String serviceId = onionServiceKey.getOnionAddress().replace(".onion", "");
    private final TorControlProtocol torControlProtocol = new TorControlProtocol();
    private FakeTorControlServer server;

    @AfterEach
    void tearDown() throws Exception {
        torControlProtocol.close();
        server.close();
    }

    @Test
    void getInfoReturnsTheLineOfItsKeyword() throws Exception {
        connect(command -> "250-version=0.4.9.14\r\n250-other=x\r\n250 OK\r\n");

        assertThat(torControlProtocol.getInfo("version")).isEqualTo("250-version=0.4.9.14");
    }

    @Test
    void getInfoRefusesTheReplyToAnotherCommand() throws Exception {
        connect(command -> "250-ServiceID=" + serviceId + "\r\n250 OK\r\n");

        assertThatThrownBy(() -> torControlProtocol.getInfo("version"))
                .isInstanceOf(ControlCommandFailedException.class)
                .hasMessageContaining("Invalid GETINFO reply");
    }

    @Test
    void getInfoRefusesAReplyWhichDoesNotEndWithSuccess() throws Exception {
        connect(command -> "250-version=0.4.9.14\r\n552 Unrecognized key\r\n");

        assertThatThrownBy(() -> torControlProtocol.getInfo("version"))
                .isInstanceOf(ControlCommandFailedException.class);
    }

    @Test
    void addOnionFindsTheServiceIdAmongTheOtherLines() throws Exception {
        connect(command -> "250-PrivateKey=ED25519-V3:secret\r\n250-ServiceID=" + serviceId + "\r\n250 OK\r\n");

        assertThat(torControlProtocol.addOnion(onionServiceKey, 9999, 12345)).contains(serviceId);
    }

    @Test
    void addOnionRefusesAReplyWithTwoServiceIds() throws Exception {
        // Only one of them can belong to the key, and the reply does not say which.
        String otherServiceId = TestKeys.randomOnionServiceKey().getOnionAddress().replace(".onion", "");
        connect(command -> "250-ServiceID=" + serviceId + "\r\n250-ServiceID=" + otherServiceId + "\r\n250 OK\r\n");

        assertThatThrownBy(() -> torControlProtocol.addOnion(onionServiceKey, 9999, 12345))
                .isInstanceOf(ControlCommandFailedException.class)
                .hasMessageContaining("Invalid ADD_ONION reply");
    }

    @Test
    void addOnionRefusesAnErrorReply() throws Exception {
        connect(command -> "550 Onion address collision\r\n");

        assertThatThrownBy(() -> torControlProtocol.addOnion(onionServiceKey, 9999, 12345))
                .isInstanceOf(ControlCommandFailedException.class);
    }

    private void connect(Function<String, String> replyByCommand) throws Exception {
        server = new FakeTorControlServer(replyByCommand);
        torControlProtocol.initialize(server.getPort());
    }
}

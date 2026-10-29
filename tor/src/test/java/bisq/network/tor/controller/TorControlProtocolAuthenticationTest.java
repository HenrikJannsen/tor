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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Timeout(10)
class TorControlProtocolAuthenticationTest {
    private final TorControlProtocol torControlProtocol = new TorControlProtocol();
    private FakeTorControlServer server;

    @AfterEach
    void tearDown() throws Exception {
        torControlProtocol.close();
        if (server != null) {
            server.close();
        }
    }

    @Test
    void okIsASuccess() throws Exception {
        connect("250 OK\r\n");

        assertThatCode(() -> torControlProtocol.authenticate(PasswordDigest.generateDigest()))
                .doesNotThrowAnyException();
    }

    @Test
    void aWrongSecretFails() throws Exception {
        connect("515 Authentication failed: Password did not match HashedControlPassword value from configuration\r\n");

        assertThatThrownBy(() -> torControlProtocol.authenticate(new byte[32]))
                .isInstanceOf(TorControlAuthenticationFailed.class);
    }

    @Test
    void everyOtherReplyFails() throws Exception {
        connect("514 Authentication required.\r\n");

        assertThatThrownBy(() -> torControlProtocol.authenticate(PasswordDigest.generateDigest()))
                .isInstanceOf(TorControlAuthenticationFailed.class)
                .hasMessageContaining("514");
    }

    // A compromised Tor in its sandbox chooses the text of its reply, and Bisq 2 shows the message of the failed start.
    @Test
    void aRefusalQuotesTheReplyOfTorLabeledAndLast() throws Exception {
        connect("515 Your wallet is at risk, visit https://example.com\r\n");

        assertThatThrownBy(() -> torControlProtocol.authenticate(PasswordDigest.generateDigest()))
                .isInstanceOf(TorControlAuthenticationFailed.class)
                .hasMessage("Tor did not accept the authentication. Tor reported (not verified by Bisq): 515 Your " +
                        "wallet is at risk, visit https://example.com");
    }

    @Test
    void aPasswordIsSentAsHexOfItsUtf8Bytes() throws Exception {
        connect("250 OK\r\n");

        torControlProtocol.authenticateWithPassword("bisq \u00fc");

        assertThat(server.getCommands()).containsExactly("AUTHENTICATE 62697371" + "20" + "c3bc");
    }

    private void connect(String reply) throws Exception {
        server = new FakeTorControlServer(command -> reply);
        torControlProtocol.initialize(server.getPort());
    }
}

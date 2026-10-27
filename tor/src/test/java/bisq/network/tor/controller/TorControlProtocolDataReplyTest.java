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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Timeout(10)
class TorControlProtocolDataReplyTest {
    private final TorControlProtocol torControlProtocol = new TorControlProtocol();
    private FakeTorControlServer server;

    @AfterEach
    void tearDown() throws Exception {
        torControlProtocol.close();
        server.close();
    }

    @Test
    void aDataReplyIsReadUntilItsEnd() throws Exception {
        // control-spec: the data of a "250+" line follows until a line with a single dot; a data line which starts
        // with a dot gets a second dot in front.
        server = new FakeTorControlServer(command -> command.equals("GETINFO config-text") ?
                "250+config-text=\r\nControlPort 9051\r\n\r\n..a line with a dot\r\n.\r\n250 OK\r\n" :
                "250-version=0.4.9.14\r\n250 OK\r\n");
        torControlProtocol.initialize(server.getPort());

        assertThat(torControlProtocol.getInfo("config-text"))
                .isEqualTo("250+config-text=\nControlPort 9051\n\n.a line with a dot");
        // The next command gets its own reply, not the rest of the data
        assertThat(torControlProtocol.getInfo("version")).isEqualTo("250-version=0.4.9.14");
    }

    @Test
    void emptyDataLinesCountAgainstTheReplyLimit() throws Exception {
        // Each line of the data is kept with its line feed, so a reply of empty lines must not grow without a bound.
        String oversizedReply = "250+config-text=\r\n" +
                "\r\n".repeat(TorControlProtocol.MAX_REPLY_LENGTH + 1) +
                ".\r\n250 OK\r\n";
        server = new FakeTorControlServer(command -> command.equals("GETINFO config-text") ?
                oversizedReply :
                "250-version=0.4.9.14\r\n250 OK\r\n");
        torControlProtocol.initialize(server.getPort());

        assertThatThrownBy(() -> torControlProtocol.getInfo("config-text"))
                .isInstanceOf(ControlCommandFailedException.class)
                .hasMessageContaining("longer than");
        // The connection is closed, so the rest of the oversized reply cannot reach the next command
        assertThatThrownBy(() -> torControlProtocol.getInfo("version"))
                .isInstanceOf(ControlCommandFailedException.class);
    }

    @Test
    void blankDataLinesCountTowardTheReplySizeLimit() throws Exception {
        // The nonempty lines fit below the 1 MiB limit; the blank lines push the buffered reply over it.
        String data = ("x".repeat(1024) + "\r\n").repeat(1020) + "\r\n".repeat(4096);
        server = new FakeTorControlServer(command -> "250+config-text=\r\n" + data + ".\r\n250 OK\r\n");
        torControlProtocol.initialize(server.getPort());

        assertThatThrownBy(() -> torControlProtocol.getInfo("config-text"))
                .isInstanceOf(ControlCommandFailedException.class)
                .hasMessageContaining("reply longer than");
        // A partial reply must not be read as the response to a later command.
        assertThatThrownBy(() -> torControlProtocol.getInfo("version"))
                .isInstanceOf(ControlCommandFailedException.class)
                .hasMessageContaining("closed");
    }

    @Test
    void aLargeDataReplyBelowTheLimitIsAccepted() throws Exception {
        String data = ("x".repeat(1024) + "\r\n").repeat(1020) + "\r\n".repeat(512);
        server = new FakeTorControlServer(command -> "250+config-text=\r\n" + data + ".\r\n250 OK\r\n");
        torControlProtocol.initialize(server.getPort());

        assertThat(torControlProtocol.getInfo("config-text"))
                .isEqualTo("250+config-text=" + ("\n" + "x".repeat(1024)).repeat(1020) + "\n".repeat(512));
    }
}

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

import com.google.common.io.BaseEncoding;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Locale;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * SAFECOOKIE must not reveal the cookie to a process on the control port which does not know it. The fake control
 * port computes the hashes of the control-spec (AUTHCHALLENGE) with its own code.
 */
@Timeout(10)
class TorControlProtocolSafeCookieTest {
    private static final SecureRandom RANDOM = new SecureRandom();

    private final byte[] cookie = randomBytes(32);
    private final byte[] serverNonce = randomBytes(32);
    private final TorControlProtocol torControlProtocol = new TorControlProtocol();
    private FakeTorControlServer server;
    private volatile String expectedClientHash;

    @AfterEach
    void tearDown() throws Exception {
        torControlProtocol.close();
        server.close();
    }

    @Test
    void torWhichKnowsTheCookieAcceptsTheClientHash() throws Exception {
        connect(this::answerAsTorWithTheCookie);

        assertThatCode(() -> torControlProtocol.authenticateWithSafeCookie(cookie)).doesNotThrowAnyException();

        assertThat(server.getCommands()).hasSize(2);
        assertThat(server.getCommands().get(1)).isEqualTo("AUTHENTICATE " + expectedClientHash);
        assertThat(String.join("\n", server.getCommands()).toLowerCase(Locale.ROOT))
                .doesNotContain(BaseEncoding.base16().lowerCase().encode(cookie));
    }

    @Test
    void aProcessWhichDoesNotKnowTheCookieGetsNoAuthentication() throws Exception {
        connect(command -> "250 AUTHCHALLENGE SERVERHASH=" + BaseEncoding.base16().encode(randomBytes(32)) +
                " SERVERNONCE=" + BaseEncoding.base16().encode(serverNonce) + "\r\n");

        assertThatThrownBy(() -> torControlProtocol.authenticateWithSafeCookie(cookie))
                .isInstanceOf(TorControlAuthenticationFailed.class)
                .hasMessageContaining("does not know the authentication cookie");
        assertThat(server.getCommands()).hasSize(1).allMatch(command -> command.startsWith("AUTHCHALLENGE SAFECOOKIE "));
    }

    @Test
    void aProcessWhichAcceptsEverythingGetsNoAuthentication() throws Exception {
        connect(command -> "250 OK\r\n");

        assertThatThrownBy(() -> torControlProtocol.authenticateWithSafeCookie(cookie))
                .isInstanceOf(TorControlAuthenticationFailed.class);
        assertThat(server.getCommands()).hasSize(1);
    }

    private String answerAsTorWithTheCookie(String command) {
        if (command.startsWith("AUTHCHALLENGE SAFECOOKIE ")) {
            byte[] clientNonce = BaseEncoding.base16().decode(command.substring("AUTHCHALLENGE SAFECOOKIE ".length()));
            byte[] serverHash = hmac("Tor safe cookie authentication server-to-controller hash", clientNonce);
            expectedClientHash = BaseEncoding.base16().lowerCase()
                    .encode(hmac("Tor safe cookie authentication controller-to-server hash", clientNonce));
            return "250 AUTHCHALLENGE SERVERHASH=" + BaseEncoding.base16().encode(serverHash) +
                    " SERVERNONCE=" + BaseEncoding.base16().encode(serverNonce) + "\r\n";
        }
        return command.equals("AUTHENTICATE " + expectedClientHash) ?
                "250 OK\r\n" :
                "515 Authentication failed: Safe cookie response did not match expected value.\r\n";
    }

    private byte[] hmac(String key, byte[] clientNonce) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.US_ASCII), "HmacSHA256"));
            mac.update(cookie);
            mac.update(clientNonce);
            mac.update(serverNonce);
            return mac.doFinal();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private void connect(Function<String, String> replyByCommand) throws Exception {
        server = new FakeTorControlServer(replyByCommand);
        torControlProtocol.initialize(server.getPort());
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }
}

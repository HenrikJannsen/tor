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

import bisq.network.tor.process.EmbeddedTorProcess;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Authenticates against a tor of the system. Tor runs with DisableNetwork, so it makes no connection to the Tor
 * network. The test is skipped if no tor is installed.
 */
@Timeout(60)
class LocalTorAuthenticationTest {
    @TempDir
    static Path torDir;
    private static final PasswordDigest PASSWORD_DIGEST = PasswordDigest.generateDigest();
    private static Process torProcess;
    private static int controlPort;

    private final TorController torController = new TorController(1000, 1000);
    private final TorControlProtocol torControlProtocol = new TorControlProtocol();

    @BeforeAll
    static void startTor() throws IOException, InterruptedException {
        Optional<Path> torBinaryPath = EmbeddedTorProcess.getSystemTorPath();
        assumeTrue(torBinaryPath.isPresent(), "No tor in PATH");

        Path dataDir = Files.createDirectories(torDir.resolve("data"));
        Path controlPortFile = torDir.resolve("control-port");
        Path torrc = torDir.resolve("torrc");
        Files.writeString(torrc, String.join("\n",
                "DataDirectory " + dataDir,
                "DisableNetwork 1",
                "SocksPort 0",
                "ControlPort 127.0.0.1:auto",
                "ControlPortWriteToFile " + controlPortFile,
                "CookieAuthentication 1",
                "CookieAuthFile " + torDir.resolve("control_auth_cookie"),
                "HashedControlPassword " + PASSWORD_DIGEST.getHashedPassword(),
                "Log notice file " + torDir.resolve("tor.log")));
        Path emptyDefaults = Files.writeString(torDir.resolve("torrc-defaults"), "");
        torProcess = new ProcessBuilder(torBinaryPath.get().toString(),
                "-f", torrc.toString(),
                "--defaults-torrc", emptyDefaults.toString())
                .redirectErrorStream(true)
                .redirectOutput(torDir.resolve("tor-stdout.log").toFile())
                .start();

        long deadline = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(30);
        while (!Files.exists(controlPortFile) || Files.readString(controlPortFile).isBlank()) {
            assertThat(torProcess.isAlive()).as("tor is running").isTrue();
            assertThat(System.currentTimeMillis()).as("tor wrote the control port").isLessThan(deadline);
            Thread.sleep(100);
        }
        // PORT=127.0.0.1:<port>
        String controlPortLine = Files.readString(controlPortFile, StandardCharsets.US_ASCII).trim();
        controlPort = Integer.parseInt(controlPortLine.substring(controlPortLine.lastIndexOf(':') + 1));
    }

    @AfterAll
    static void stopTor() throws InterruptedException {
        if (torProcess != null) {
            torProcess.destroy();
            torProcess.waitFor(10, TimeUnit.SECONDS);
        }
    }

    @AfterEach
    void closeConnections() {
        torController.shutdown();
        torControlProtocol.close();
    }

    @Test
    void safeCookieAuthenticationIsAccepted() throws IOException {
        torControlProtocol.initialize(controlPort);

        torControlProtocol.authenticateWithSafeCookie(Files.readAllBytes(torDir.resolve("control_auth_cookie")));

        assertThat(torControlProtocol.getInfo("version")).startsWith("250-version=");
    }

    @Test
    void aWrongCookieIsDetectedBeforeTheAuthentication() {
        torControlProtocol.initialize(controlPort);

        assertThatThrownBy(() -> torControlProtocol.authenticateWithSafeCookie(new byte[32]))
                .isInstanceOf(TorControlAuthenticationFailed.class)
                .hasMessageContaining("does not know the authentication cookie");
    }

    @Test
    void torReportsTheHashedControlPasswordOfItsTorrc() {
        torController.initialize(controlPort);
        torController.authenticate(PASSWORD_DIGEST);

        assertThatCode(() -> torController.verifyHashedControlPassword(PASSWORD_DIGEST)).doesNotThrowAnyException();
        assertThatThrownBy(() -> torController.verifyHashedControlPassword(PasswordDigest.generateDigest()))
                .isInstanceOf(TorControlAuthenticationFailed.class);
    }
}

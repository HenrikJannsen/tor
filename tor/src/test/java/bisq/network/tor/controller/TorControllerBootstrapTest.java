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

import bisq.network.tor.controller.exceptions.TorBootstrapFailedException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Timeout(20)
class TorControllerBootstrapTest {
    private static final String DONE_EVENT = "650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n";

    private TorController torController;
    private FakeTorControlServer server;

    @AfterEach
    void tearDown() throws Exception {
        torController.shutdown();
        server.close();
    }

    @Test
    void theDoneEventCompletesTheBootstrap() throws Exception {
        connect(10_000, command -> command.startsWith("SETCONF DisableNetwork") ? "250 OK\r\n" + DONE_EVENT : "250 OK\r\n");

        assertThatCode(() -> torController.bootstrap()).doesNotThrowAnyException();
        assertThat(server.getCommands()).contains("TAKEOWNERSHIP", "SETCONF DisableNetwork=0");
    }

    @Test
    void theEndOfTheConnectionFailsTheBootstrapAtOnce() throws Exception {
        // Tor exits after it enabled the network, long before the bootstrap timeout
        connect(10_000, command -> "250 OK\r\n");
        server.closeConnectionAfter("SETCONF DisableNetwork");

        long start = System.currentTimeMillis();
        assertThatThrownBy(() -> torController.bootstrap())
                .isInstanceOf(TorBootstrapFailedException.class)
                .hasMessageContaining("ended");
        assertThat(System.currentTimeMillis() - start).isLessThan(5000);
    }

    @Test
    void aShutdownDuringTheWaitFailsTheBootstrap() throws Exception {
        connect(10_000, command -> "250 OK\r\n");
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread caller = new Thread(() -> {
            try {
                torController.bootstrap();
            } catch (Throwable t) {
                failure.set(t);
            }
        });
        caller.start();
        waitForCommand("SETCONF DisableNetwork");

        torController.shutdown();
        caller.join(5000);

        assertThat(caller.isAlive()).isFalse();
        assertThat(failure.get()).isInstanceOf(TorBootstrapFailedException.class);
    }

    @Test
    void aShutDownControllerReportsNoBootstrap() throws Exception {
        connect(10_000, command -> command.startsWith("SETCONF DisableNetwork") ? "250 OK\r\n" + DONE_EVENT : "250 OK\r\n");
        torController.shutdown();

        assertThatThrownBy(() -> torController.bootstrap())
                .isInstanceOf(TorBootstrapFailedException.class)
                .hasMessageContaining("shut down");
        assertThat(server.getCommands()).isEmpty();
    }

    private void waitForCommand(String commandStart) throws InterruptedException {
        while (server.getCommands().stream().noneMatch(command -> command.startsWith(commandStart))) {
            Thread.sleep(10);
        }
    }

    private void connect(int bootstrapTimeout, Function<String, String> replyByCommand) throws Exception {
        server = new FakeTorControlServer(replyByCommand);
        torController = new TorController(bootstrapTimeout, 1000);
        torController.initialize(server.getPort());
    }
}

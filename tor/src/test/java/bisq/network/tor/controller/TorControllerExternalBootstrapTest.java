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

import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Timeout(20)
class TorControllerExternalBootstrapTest {
    private static final String BOOTSTRAPPING = "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=50 " +
            "TAG=loading_descriptors SUMMARY=\"Loading relay descriptors\"\r\n250 OK\r\n";
    private static final String DONE = "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done " +
            "SUMMARY=\"Done\"\r\n250 OK\r\n";

    private TorController torController;
    private FakeTorControlServer server;

    @AfterEach
    void tearDown() throws Exception {
        torController.shutdown();
        server.close();
    }

    @Test
    void aBootstrappedTorIsUsedAtOnce() throws Exception {
        connect(5000, command -> DONE);

        assertThatCode(() -> torController.awaitBootstrapOfExternalTor()).doesNotThrowAnyException();
        assertThat(server.getCommands()).containsExactly("GETINFO status/bootstrap-phase");
    }

    @Test
    void aBootstrappingTorIsAwaited() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        connect(5000, command -> requests.incrementAndGet() < 3 ? BOOTSTRAPPING : DONE);

        assertThatCode(() -> torController.awaitBootstrapOfExternalTor()).doesNotThrowAnyException();
        assertThat(requests.get()).isEqualTo(3);
        assertThat(server.getCommands()).noneMatch(command -> command.startsWith("SETCONF"));
    }

    @Test
    void aTorWhichDoesNotBootstrapInTimeFailsTheStart() throws Exception {
        connect(1500, command -> BOOTSTRAPPING);

        assertThatThrownBy(() -> torController.awaitBootstrapOfExternalTor())
                .isInstanceOf(TorBootstrapFailedException.class)
                .hasMessageContaining("PROGRESS=50");
    }

    @Test
    void aFilteredRequestIsNotAwaited() throws Exception {
        connect(5000, command -> "510 Command filtered\r\n");

        assertThatCode(() -> torController.awaitBootstrapOfExternalTor()).doesNotThrowAnyException();
    }

    private void connect(int bootstrapTimeout, Function<String, String> replyByCommand) throws Exception {
        server = new FakeTorControlServer(replyByCommand);
        torController = new TorController(bootstrapTimeout, 1000);
        torController.initialize(server.getPort());
    }
}

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

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;

@Timeout(30)
class TorControlProtocolConcurrencyTest {
    private final TorControlProtocol torControlProtocol = new TorControlProtocol();
    private final ExecutorService executor = Executors.newFixedThreadPool(8);
    private FakeTorControlServer server;

    @AfterEach
    void tearDown() throws Exception {
        executor.shutdownNow();
        torControlProtocol.close();
        server.close();
    }

    private void waitForCommand(String commandStart) throws InterruptedException {
        while (server.getCommands().stream().noneMatch(command -> command.startsWith(commandStart))) {
            Thread.sleep(10);
        }
    }

    private static void awaitQuietly(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @Test
    void concurrentCommandsGetTheirOwnReplies() throws Exception {
        // Tor answers in the order of the commands. "GETINFO key-<n>" gets "250-key-<n>=value-<n>".
        server = new FakeTorControlServer(command -> {
            String key = command.substring("GETINFO ".length());
            return "250-" + key + "=value-" + key + "\r\n250 OK\r\n";
        });
        torControlProtocol.initialize(server.getPort());

        List<CompletableFuture<Boolean>> results = new ArrayList<>();
        for (int i = 0; i < 400; i++) {
            String key = "key-" + i;
            results.add(CompletableFuture.supplyAsync(() ->
                    torControlProtocol.getInfo(key).equals("250-" + key + "=value-" + key), executor));
        }

        assertThat(results).allMatch(CompletableFuture::join);
    }
}

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
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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

    @Test
    void anInterruptedCommandDoesNotLeaveItsReplyToTheNextCommand() throws Exception {
        CountDownLatch replyToFirstCommand = new CountDownLatch(1);
        server = new FakeTorControlServer(command -> {
            if (command.equals("GETINFO first")) {
                awaitQuietly(replyToFirstCommand);
                return "250-first=1\r\n250 OK\r\n";
            }
            return "250-second=2\r\n250 OK\r\n";
        });
        torControlProtocol.initialize(server.getPort());
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread caller = new Thread(() -> {
            try {
                torControlProtocol.getInfo("first");
            } catch (Throwable t) {
                failure.set(t);
            }
        });
        caller.start();
        waitForCommand("GETINFO first");

        caller.interrupt();
        caller.join(5000);
        // The late reply to the first command arrives now
        replyToFirstCommand.countDown();

        assertThat(failure.get()).isInstanceOf(ControlCommandFailedException.class);
        assertThatThrownBy(() -> torControlProtocol.getInfo("second")).isInstanceOf(ControlCommandFailedException.class);
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

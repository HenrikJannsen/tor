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

import bisq.network.tor.controller.exceptions.HsDescUploadFailedException;
import bisq.network.tor.controller.exceptions.TorBootstrapFailedException;
import bisq.network.tor.onionservice.OnionServiceKey;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.slf4j.LoggerFactory;

import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Timeout(20)
class TorControllerShutdownTest {
    private TorController torController;
    private FakeTorControlServer server;

    @AfterEach
    void tearDown() throws Exception {
        if (torController != null) {
            torController.shutdown();
        }
        server.close();
    }

    // The bootstrap, a publication and a lookup wait for events of Tor when the controller shuts down.
    @Test
    void aShutdownFailsTheRunningOperationsAsAShutdown() throws Exception {
        OnionServiceKey onionServiceKey = TestKeys.randomOnionServiceKey();
        String serviceId = onionServiceKey.getOnionAddress().replace(".onion", "");
        server = new FakeTorControlServer(command -> command.startsWith("ADD_ONION") ?
                "250-ServiceID=" + serviceId + "\r\n250 OK\r\n" :
                "250 OK\r\n");
        torController = new TorController(10_000, 10_000);
        torController.initialize(server.getPort());
        // The bootstrap runs in the thread of its caller.
        CompletableFuture<Void> bootstrap = CompletableFuture.runAsync(torController::bootstrap);
        CompletableFuture<Void> publication = torController.publishAsync(onionServiceKey, 9999, 12345);
        CompletableFuture<Boolean> lookup = torController.isOnionServiceOnlineAsync(TestKeys.randomOnionServiceKey()
                .getOnionAddress());
        awaitCommandStart("SETCONF DisableNetwork");
        awaitCommandStart("ADD_ONION");
        awaitCommandStart("HSFETCH");

        torController.shutdown();

        assertThatThrownBy(bootstrap::join).hasMessageContaining("shut down");
        assertThatThrownBy(publication::join).hasMessageContaining("shut down");
        assertThatThrownBy(lookup::join).hasMessageContaining("shut down");
    }

    // The bootstrap removes its event listener when it ends. The shutdown removed it before as well, and the second
    // removal logged a warning.
    @Test
    void aShutdownDuringTheBootstrapLogsNoWarning() throws Exception {
        Logger protocolLogger = (Logger) LoggerFactory.getLogger(TorControlProtocol.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        protocolLogger.addAppender(appender);
        try {
            server = new FakeTorControlServer(command -> "250 OK\r\n");
            torController = new TorController(10_000, 10_000);
            torController.initialize(server.getPort());
            CompletableFuture<Void> bootstrap = CompletableFuture.runAsync(torController::bootstrap);
            awaitCommandStart("SETCONF DisableNetwork");

            torController.shutdown();

            assertThatThrownBy(bootstrap::join).hasMessageContaining("shut down");
            assertThat(appender.list).noneMatch(event -> event.getLevel().isGreaterOrEqual(Level.WARN));
        } finally {
            protocolLogger.detachAppender(appender);
        }
    }

    // A publication and a lookup remove their event listener when they end. Their shutdown removed it before as well,
    // and with an open connection the second removal logged a warning and sent a second SETEVENTS.
    @Test
    void aShutdownOfAPublicationOrALookupRemovesItsListenerOnce() throws Exception {
        Logger protocolLogger = (Logger) LoggerFactory.getLogger(TorControlProtocol.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        protocolLogger.addAppender(appender);
        OnionServiceKey onionServiceKey = TestKeys.randomOnionServiceKey();
        String serviceId = onionServiceKey.getOnionAddress().replace(".onion", "");
        server = new FakeTorControlServer(command -> command.startsWith("ADD_ONION") ?
                "250-ServiceID=" + serviceId + "\r\n250 OK\r\n" :
                "250 OK\r\n");
        TorControlProtocol torControlProtocol = new TorControlProtocol();
        torControlProtocol.initialize(server.getPort());
        try {
            var publication = new PublishOnionAddressService(torControlProtocol, 10_000, onionServiceKey);
            CompletableFuture<Void> published = publication.publish(9999, 12345);
            awaitCommandStart("ADD_ONION");
            publication.shutdown();
            assertThatThrownBy(published::join).hasMessageContaining("shut down");

            var lookup = new OnionServiceOnlineStateService(torControlProtocol,
                    TestKeys.randomOnionServiceKey().getOnionAddress(), 10_000);
            CompletableFuture<Boolean> lookedUp = lookup.isOnionServiceOnlineAsync();
            awaitCommandStart("HSFETCH");
            lookup.shutdown();
            assertThatThrownBy(lookedUp::join).hasMessageContaining("shut down");

            // Each registered its listener and removed it once.
            assertThat(server.getCommands()).filteredOn(command -> command.startsWith("SETEVENTS")).hasSize(4);
            assertThat(appender.list).noneMatch(event -> event.getLevel().isGreaterOrEqual(Level.WARN));
        } finally {
            torControlProtocol.close();
            protocolLogger.detachAppender(appender);
        }
    }

    // The controller closes the connection before it shuts its services down, so the end of the connection can wake a
    // service first.
    @Test
    void theEndOfTheConnectionDuringTheShutdownOfTheControllerIsTheShutdown() throws Exception {
        OnionServiceKey onionServiceKey = TestKeys.randomOnionServiceKey();
        String serviceId = onionServiceKey.getOnionAddress().replace(".onion", "");
        server = new FakeTorControlServer(command -> command.startsWith("ADD_ONION") ?
                "250-ServiceID=" + serviceId + "\r\n250 OK\r\n" :
                "250 OK\r\n");
        server.closeConnectionAfter("ADD_ONION");
        TorControlProtocol torControlProtocol = new TorControlProtocol();
        torControlProtocol.initialize(server.getPort());
        try {
            var publication = new PublishOnionAddressService(torControlProtocol, 10_000, onionServiceKey, () -> true);

            assertThatThrownBy(() -> publication.publish(9999, 12345).join())
                    .hasRootCauseInstanceOf(HsDescUploadFailedException.class)
                    .hasMessageContaining("shut down");
        } finally {
            torControlProtocol.close();
        }
    }

    @Test
    void theEndOfTheConnectionDuringTheShutdownOfTheControllerFailsTheBootstrapAsTheShutdown() throws Exception {
        server = new FakeTorControlServer(command -> "250 OK\r\n");
        server.closeConnectionAfter("SETCONF DisableNetwork");
        TorControlProtocol torControlProtocol = new TorControlProtocol();
        torControlProtocol.initialize(server.getPort());
        try {
            var bootstrap = new BootstrapService(torControlProtocol, 10_000, () -> true);

            assertThatThrownBy(() -> bootstrap.bootstrap().join())
                    .hasRootCauseInstanceOf(TorBootstrapFailedException.class)
                    .hasMessageContaining("shut down");
        } finally {
            torControlProtocol.close();
        }
    }

    @Test
    void theEndOfTheConnectionDuringTheShutdownOfTheControllerFailsTheLookupAsTheShutdown() throws Exception {
        server = new FakeTorControlServer(command -> "250 OK\r\n");
        server.closeConnectionAfter("HSFETCH");
        TorControlProtocol torControlProtocol = new TorControlProtocol();
        torControlProtocol.initialize(server.getPort());
        try {
            var lookup = new OnionServiceOnlineStateService(torControlProtocol,
                    TestKeys.randomOnionServiceKey().getOnionAddress(), 10_000, () -> true);

            assertThatThrownBy(() -> lookup.isOnionServiceOnlineAsync().join()).hasMessageContaining("shut down");
        } finally {
            torControlProtocol.close();
        }
    }

    private void awaitCommandStart(String commandStart) throws InterruptedException {
        while (server.getCommands().stream().noneMatch(command -> command.startsWith(commandStart))) {
            Thread.sleep(10);
        }
    }

    @Test
    void theShutdownEndsAtOnceWhileACommandWaitsForItsReply() throws Exception {
        // The command holds the lock of the control protocol while it waits for the reply, here for 60 seconds. The
        // shutdown must neither wait for the lock nor for the reply.
        server = new FakeTorControlServer(command -> "");
        torController = new TorController(1000, 1000);
        torController.initialize(server.getPort());
        Thread caller = new Thread(torController::getTorVersion);
        caller.start();
        while (!server.getCommands().contains("GETINFO version")) {
            Thread.sleep(10);
        }

        long start = System.currentTimeMillis();
        torController.shutdown();
        caller.join(5000);

        assertThat(System.currentTimeMillis() - start).isLessThan(2000);
        assertThat(caller.isAlive()).isFalse();
    }
}

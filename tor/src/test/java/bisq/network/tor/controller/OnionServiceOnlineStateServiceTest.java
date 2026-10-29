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

import com.google.common.collect.Sets;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.Locale;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Timeout(20)
class OnionServiceOnlineStateServiceTest {
    private static final String HS_DIR = "$0123456789ABCDEF0123456789ABCDEF01234567";

    private final String onionAddress = TestKeys.randomOnionServiceKey().getOnionAddress();
    private final String serviceId = onionAddress.replace(".onion", "");
    private TorController torController;
    private FakeTorControlServer server;

    @AfterEach
    void tearDown() throws Exception {
        if (torController != null) {
            torController.shutdown();
        }
        if (server != null) {
            server.close();
        }
    }

    @Test
    void theThreadNameCarriesACounterInsteadOfTheOnionAddress() {
        // The thread name is in every log line of the thread, and the address of a peer must not appear in a log
        // which a user shares.
        Thread first = OnionServiceOnlineStateService.createThreadFactory().newThread(() -> {
        });
        Thread second = OnionServiceOnlineStateService.createThreadFactory().newThread(() -> {
        });

        assertThat(first.getName()).matches("OnionServiceOnlineStateService-\\d+-\\d+");
        assertThat(second.getName()).matches("OnionServiceOnlineStateService-\\d+-\\d+").isNotEqualTo(first.getName());
        assertThat(first.isDaemon()).isTrue();
    }

    @Test
    void aReceivedDescriptorMeansOnline() throws Exception {
        connect(command -> command.startsWith("HSFETCH") ?
                "250 OK\r\n650 HS_DESC RECEIVED " + serviceId + " NO_AUTH " + HS_DIR + " descriptorId\r\n" :
                "250 OK\r\n");

        assertThat(torController.isOnionServiceOnlineAsync(onionAddress).join()).isTrue();
        assertThat(server.getCommands()).contains("HSFETCH " + serviceId);
    }

    @Test
    void anAddressInUpperCaseIsLookedUp() throws Exception {
        // Bisq 2 accepts an onion address in any case. Tor names it in lower case in its events.
        connect(command -> command.startsWith("HSFETCH") ?
                "250 OK\r\n650 HS_DESC RECEIVED " + serviceId + " NO_AUTH " + HS_DIR + " descriptorId\r\n" :
                "250 OK\r\n");

        assertThat(torController.isOnionServiceOnlineAsync(onionAddress.toUpperCase(Locale.ROOT)).join()).isTrue();
        assertThat(server.getCommands()).contains("HSFETCH " + serviceId);
    }

    @Test
    void aMissingDescriptorMeansOffline() throws Exception {
        connect(command -> command.startsWith("HSFETCH") ?
                "250 OK\r\n650 HS_DESC FAILED " + serviceId + " NO_AUTH " + HS_DIR + " descriptorId REASON=NOT_FOUND\r\n" :
                "250 OK\r\n");

        assertThat(torController.isOnionServiceOnlineAsync(onionAddress).join()).isFalse();
    }

    @Test
    void aMissingDescriptorWithoutTheOptionalDescriptorIdMeansOffline() throws Exception {
        connect(command -> command.startsWith("HSFETCH") ?
                "250 OK\r\n650 HS_DESC FAILED " + serviceId + " NO_AUTH " + HS_DIR + " REASON=NOT_FOUND\r\n" :
                "250 OK\r\n");

        long start = System.currentTimeMillis();
        assertThat(torController.isOnionServiceOnlineAsync(onionAddress).join()).isFalse();
        assertThat(System.currentTimeMillis() - start).isLessThan(5000);
    }

    @Test
    void aFailureForAnotherReasonEndsTheLookupAtOnce() throws Exception {
        // Tor could not look the service up, so its state is unknown; the lookup must not wait for its timeout.
        connect(command -> command.startsWith("HSFETCH") ?
                "250 OK\r\n650 HS_DESC FAILED " + serviceId + " NO_AUTH " + HS_DIR + " descriptorId " +
                        "REASON=QUERY_RATE_LIMITED\r\n" :
                "250 OK\r\n");

        long start = System.currentTimeMillis();
        CompletableFuture<Boolean> lookup = torController.isOnionServiceOnlineAsync(onionAddress);

        assertThatThrownBy(lookup::join).hasMessageContaining("QUERY_RATE_LIMITED");
        assertThat(System.currentTimeMillis() - start).isLessThan(5000);
    }

    @Test
    void aFinishedLookupIsNotReused() throws Exception {
        connect(command -> command.startsWith("HSFETCH") ?
                "250 OK\r\n650 HS_DESC RECEIVED " + serviceId + " NO_AUTH " + HS_DIR + " descriptorId\r\n" :
                "250 OK\r\n");

        assertThat(torController.isOnionServiceOnlineAsync(onionAddress).join()).isTrue();
        assertThat(torController.isOnionServiceOnlineAsync(onionAddress).join()).isTrue();

        assertThat(server.getCommands()).filteredOn(command -> command.startsWith("HSFETCH")).hasSize(2);
    }

    @Test
    void concurrentLookupsOfOneAddressShareOneHsFetch() throws Exception {
        // The descriptor arrives with the reply to a later GETINFO, after both lookups have started.
        connect(command -> {
            if (command.equals("GETINFO version")) {
                return "250-version=0.4.9.14\r\n250 OK\r\n" +
                        "650 HS_DESC RECEIVED " + serviceId + " NO_AUTH " + HS_DIR + " descriptorId\r\n";
            }
            return "250 OK\r\n";
        });
        CompletableFuture<Boolean> first = torController.isOnionServiceOnlineAsync(onionAddress);
        waitForCommand("HSFETCH");
        CompletableFuture<Boolean> second = torController.isOnionServiceOnlineAsync(onionAddress);

        torController.getTorVersion();

        assertThat(first.join()).isTrue();
        assertThat(second.join()).isTrue();
        assertThat(server.getCommands()).filteredOn(command -> command.startsWith("HSFETCH")).hasSize(1);
    }

    @Test
    void aRefusedRemovalOfTheListenerKeepsTheResultAndEndsTheThread() throws Exception {
        // Tor confirms the SETEVENTS of the registration and refuses the one of the removal.
        AtomicInteger setEventsCommands = new AtomicInteger();
        connect(command -> {
            if (command.startsWith("HSFETCH")) {
                return "250 OK\r\n650 HS_DESC RECEIVED " + serviceId + " NO_AUTH " + HS_DIR + " descriptorId\r\n";
            }
            if (command.startsWith("SETEVENTS") && setEventsCommands.incrementAndGet() > 1) {
                return "552 Unrecognized event\r\n";
            }
            return "250 OK\r\n";
        });
        Set<Thread> threadsBefore = PublishOnionAddressServiceTest.liveThreadsNamed("OnionServiceOnlineStateService-");

        assertThat(torController.isOnionServiceOnlineAsync(onionAddress).join()).isTrue();

        assertThat(setEventsCommands).hasValue(2);
        PublishOnionAddressServiceTest.assertAllEnd(Sets.difference(
                PublishOnionAddressServiceTest.liveThreadsNamed("OnionServiceOnlineStateService-"), threadsBefore));
    }

    @Test
    void theEndOfTheConnectionFailsTheLookupAtOnce() throws Exception {
        // Tor exits after it accepted HSFETCH, long before the timeout of the lookup
        connect(command -> "250 OK\r\n");
        server.closeConnectionAfter("HSFETCH");

        long start = System.currentTimeMillis();
        CompletableFuture<Boolean> lookup = torController.isOnionServiceOnlineAsync(onionAddress);
        assertThatThrownBy(lookup::join)
                .isInstanceOf(CompletionException.class)
                .hasMessageContaining("ended");
        assertThat(System.currentTimeMillis() - start).isLessThan(5000);
    }

    @Test
    void aRefusedLookupDoesNotNameThePeerInTheMessage() throws Exception {
        // Bisq 2 logs the failure at error level, and the address of a peer must not appear in a log which a user
        // shares. Tor names the address in some refusals.
        connect(command -> command.startsWith("HSFETCH") ?
                "513 Invalid argument \"" + serviceId + "\"\r\n" :
                "250 OK\r\n");

        CompletableFuture<Boolean> lookup = torController.isOnionServiceOnlineAsync(onionAddress);

        assertThatThrownBy(lookup::join)
                .hasCauseInstanceOf(ControlCommandFailedException.class)
                .hasMessageContaining("HSFETCH")
                .hasMessageNotContaining(serviceId);
    }

    @Test
    void aShutdownFailsTheLookupInsteadOfAnsweringOffline() throws Exception {
        server = new FakeTorControlServer(command -> "250 OK\r\n");
        TorControlProtocol torControlProtocol = new TorControlProtocol();
        torControlProtocol.initialize(server.getPort());
        try {
            OnionServiceOnlineStateService service = new OnionServiceOnlineStateService(torControlProtocol,
                    onionAddress, 10_000);
            CompletableFuture<Boolean> lookup = service.isOnionServiceOnlineAsync();
            waitForCommand("HSFETCH");

            service.shutdown();

            assertThatThrownBy(lookup::join).hasMessageContaining("shut down");
        } finally {
            torControlProtocol.close();
        }
    }

    @Test
    void anythingButAServiceIdIsRefusedBeforeItReachesTor() throws Exception {
        // The address of a peer comes from the network. CR LF would carry a second command into the connection.
        connect(command -> "250 OK\r\n");

        CompletableFuture<Boolean> lookup = torController.isOnionServiceOnlineAsync(serviceId + "\r\nSIGNAL SHUTDOWN");

        assertThatThrownBy(lookup::join).hasCauseInstanceOf(IllegalArgumentException.class);
        assertThat(server.getCommands()).noneMatch(command -> command.startsWith("HSFETCH") || command.startsWith("SIGNAL"));
    }

    private void waitForCommand(String commandStart) throws InterruptedException {
        while (server.getCommands().stream().noneMatch(command -> command.startsWith(commandStart))) {
            Thread.sleep(10);
        }
    }

    private void connect(Function<String, String> replyByCommand) throws Exception {
        server = new FakeTorControlServer(replyByCommand);
        torController = new TorController(1000, 1000);
        torController.initialize(server.getPort());
    }
}

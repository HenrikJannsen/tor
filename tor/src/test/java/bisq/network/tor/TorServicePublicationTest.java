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

package bisq.network.tor;

import bisq.network.tor.controller.ControlCommandFailedException;
import bisq.network.tor.controller.FakeTorControlServer;
import bisq.network.tor.controller.TestKeys;
import bisq.network.tor.onionservice.OnionServiceKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The publication methods of TorService return futures, and the hosts wait on them. A failed publication therefore has
 * to fail the future instead of leaving the method with an exception.
 */
@Timeout(30)
class TorServicePublicationTest {
    private static final PlatformServices PLATFORM_SERVICES = new PlatformServices() {
        @Override
        public String getMyPid() {
            return String.valueOf(ProcessHandle.current().pid());
        }

        @Override
        public Stream<String> getProcessCommandStream() {
            return Stream.empty();
        }

        @Override
        public boolean supportsPosixPermissions() {
            return false;
        }
    };

    @TempDir
    Path torDir;
    private FakeTorControlServer fakeTor;
    private TorService torService;

    @AfterEach
    void tearDown() throws Exception {
        if (torService != null) {
            torService.shutdown().join();
        }
        if (fakeTor != null) {
            fakeTor.close();
        }
    }

    @Test
    void aRefusedPublicationFailsTheFutureOfPublishOnionService() throws Exception {
        startWithATorWhichRefusesOnionServices();

        CompletableFuture<String> publication = torService.publishOnionService(8080, 9999, TestKeys.randomOnionServiceKey());

        assertThat(publication).isCompletedExceptionally();
        assertThatThrownBy(publication::join).hasCauseInstanceOf(ControlCommandFailedException.class);
    }

    @Test
    void aRefusedPublicationFailsTheFutureAndClosesTheServerSocket() throws Exception {
        startWithATorWhichRefusesOnionServices();
        OnionServiceKey onionServiceKey = TestKeys.randomOnionServiceKey();

        CompletableFuture<ServerSocket> first = torService.publishOnionServiceAndCreateServerSocket(9999, onionServiceKey);
        // An onion service keeps its local port, so the second server socket can only be bound if the first one was
        // closed with the failure.
        CompletableFuture<ServerSocket> second = torService.publishOnionServiceAndCreateServerSocket(9999, onionServiceKey);

        for (CompletableFuture<ServerSocket> publication : List.of(first, second)) {
            assertThat(publication).isCompletedExceptionally();
            assertThatThrownBy(publication::join).hasCauseInstanceOf(ControlCommandFailedException.class);
        }
    }

    @Test
    void concurrentPublicationsOfOneOnionServiceSendOneAddOnion() throws Exception {
        // Tor refuses a second ADD_ONION of an address, which it keeps. It starts the upload with the reply to an
        // HSFETCH, so that both publications wait for it.
        OnionServiceKey onionServiceKey = TestKeys.randomOnionServiceKey();
        String serviceId = onionServiceKey.getOnionAddress().replace(".onion", "");
        String peerServiceId = TestKeys.randomOnionServiceKey().getOnionAddress().replace(".onion", "");
        AtomicInteger addOnionCommands = new AtomicInteger();
        start(command -> {
            if (command.startsWith("ADD_ONION ")) {
                return addOnionCommands.incrementAndGet() == 1 ?
                        "250-ServiceID=" + serviceId + "\r\n250 OK\r\n" :
                        "550 Onion address collision\r\n";
            }
            if (command.startsWith("HSFETCH ")) {
                return "250 OK\r\n" +
                        "650 HS_DESC UPLOADED " + serviceId + " UNKNOWN redacted\r\n" +
                        "650 HS_DESC RECEIVED " + peerServiceId + " NO_AUTH redacted redacted\r\n";
            }
            return reply(command);
        });

        List<CompletableFuture<String>> publications = List.of(
                CompletableFuture.supplyAsync(() -> torService.publishOnionService(8080, 9999, onionServiceKey).join()),
                CompletableFuture.supplyAsync(() -> torService.publishOnionService(8080, 9999, onionServiceKey).join()));
        while (fakeTor.getCommands().stream().noneMatch(command -> command.startsWith("ADD_ONION "))) {
            Thread.sleep(10);
        }
        torService.isOnionServiceOnlineAsync(peerServiceId + ".onion").join();

        for (CompletableFuture<String> publication : publications) {
            assertThat(publication.join()).isEqualTo(onionServiceKey.getOnionAddress());
        }
        assertThat(addOnionCommands).hasValue(1);
    }

    @Test
    void anInterruptedPublicationKeepsTheInterruptOfTheCaller() throws Exception {
        // Tor accepts the onion service and uploads nothing, so the caller waits until the test interrupts it.
        OnionServiceKey onionServiceKey = TestKeys.randomOnionServiceKey();
        String serviceId = onionServiceKey.getOnionAddress().replace(".onion", "");
        start(command -> command.startsWith("ADD_ONION ") ?
                "250-ServiceID=" + serviceId + "\r\n250 OK\r\n" :
                reply(command));
        AtomicReference<CompletableFuture<String>> publication = new AtomicReference<>();
        AtomicBoolean isInterruptedAfterwards = new AtomicBoolean();
        Thread caller = new Thread(() -> {
            publication.set(torService.publishOnionService(8080, 9999, onionServiceKey));
            isInterruptedAfterwards.set(Thread.currentThread().isInterrupted());
        });
        caller.start();
        while (fakeTor.getCommands().stream().noneMatch(command -> command.startsWith("ADD_ONION "))) {
            Thread.sleep(10);
        }

        caller.interrupt();
        caller.join(5000);

        assertThat(isInterruptedAfterwards).isTrue();
        assertThatThrownBy(publication.get()::join).hasCauseInstanceOf(InterruptedException.class);
    }

    @Test
    void theServerSocketOfAnOnionServiceListensOnIpv4Loopback() throws Exception {
        // Tor connects to 127.0.0.1. A server socket on another loopback address, such as ::1, would get nothing.
        OnionServiceKey onionServiceKey = TestKeys.randomOnionServiceKey();
        String serviceId = onionServiceKey.getOnionAddress().replace(".onion", "");
        start(command -> command.startsWith("ADD_ONION ") ?
                "250-ServiceID=" + serviceId + "\r\n250 OK\r\n650 HS_DESC UPLOADED " + serviceId +
                        " UNKNOWN redacted\r\n" :
                reply(command));

        try (ServerSocket serverSocket = torService.publishOnionServiceAndCreateServerSocket(9999, onionServiceKey).join()) {
            assertThat(serverSocket.getInetAddress()).isEqualTo(InetAddress.getByName("127.0.0.1"));
        }
    }

    private void startWithATorWhichRefusesOnionServices() throws IOException {
        start(TorServicePublicationTest::reply);
    }

    private void start(Function<String, String> replyByCommand) throws IOException {
        fakeTor = new FakeTorControlServer(replyByCommand);
        Files.writeString(torDir.resolve("external_tor.config"), "UseExternalTor 1\nCookieAuthentication 0\n" +
                "ControlPort 127.0.0.1:" + fakeTor.getPort());
        torService = new TorService(createTransportConfig(), PLATFORM_SERVICES);
        assertThat(torService.initialize().join()).isTrue();
    }

    // A Tor which has bootstrapped and refuses every onion service
    private static String reply(String command) {
        if (command.startsWith("AUTHENTICATE") || command.startsWith("SETEVENTS") || command.startsWith("DEL_ONION")) {
            return "250 OK\r\n";
        }
        if (command.equals("GETINFO status/bootstrap-phase")) {
            return "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n250 OK\r\n";
        }
        if (command.equals("GETINFO version")) {
            return "250-version=0.4.8.16\r\n250 OK\r\n";
        }
        if (command.equals("GETINFO net/listeners/socks")) {
            return "250-net/listeners/socks=\"127.0.0.1:9150\"\r\n250 OK\r\n";
        }
        if (command.startsWith("ADD_ONION ")) {
            return "550 Onion address collision\r\n";
        }
        return "552 Unrecognized command\r\n";
    }

    private TorTransportConfig createTransportConfig() {
        // If the test failed and TorService started its own Tor, Tor would send its connections to a closed local
        // port instead of the Tor network.
        return new TorTransportConfig(torDir, 1000, 1000, false, Set.of(),
                Map.of("Socks5Proxy", "127.0.0.1:1"), false);
    }
}

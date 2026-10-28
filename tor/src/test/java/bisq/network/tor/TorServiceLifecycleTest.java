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

import bisq.network.tor.controller.TorControlAuthenticationFailed;
import bisq.network.tor.controller.TorController;
import bisq.network.tor.process.TorStartupFailedException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * The callers of initialize share one initialization, and a shutdown ends it: the initialization fails, no Tor of it
 * stays, and a call during the shutdown starts again after it. The Tor is a fake one, see {@link FakeBundledTor}.
 */
@Timeout(30)
class TorServiceLifecycleTest {
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
            return true;
        }
    };

    @TempDir
    Path torDir;
    private FakeBundledTor fakeTor;
    private TorService torService;

    @BeforeEach
    void setUp() throws IOException {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));
        fakeTor = FakeBundledTor.install(torDir);
    }

    @AfterEach
    void tearDown() throws Exception {
        if (torService != null) {
            torService.shutdown().get(10, TimeUnit.SECONDS);
        }
        if (fakeTor != null) {
            fakeTor.close();
        }
    }

    @Test
    void aCallDuringTheStartGetsTheResultOfThatStart() throws Exception {
        AtomicInteger createdControllers = new AtomicInteger();
        torService = new TorService(transportConfig(), PLATFORM_SERVICES, false, () -> {
            createdControllers.incrementAndGet();
            return new TorController(10_000, 10_000, false);
        });
        FutureTask<Boolean> start = startInTheBackground();
        fakeTor.awaitStart();

        CompletableFuture<Boolean> sharedStart = torService.initialize();

        assertThat(sharedStart).isNotDone();
        fakeTor.answerControlPort();
        assertThat(start.get(10, TimeUnit.SECONDS)).isTrue();
        assertThat(sharedStart.get(10, TimeUnit.SECONDS)).isTrue();
        assertThat(torService.initialize()).isCompletedWithValue(true);
        assertThat(createdControllers).hasValue(1);
    }

    @Test
    void aCallDuringAStartWhichFailsGetsItsFailure() throws Exception {
        torService = new TorService(transportConfig(), PLATFORM_SERVICES, false);
        FutureTask<Boolean> start = startInTheBackground();
        fakeTor.awaitStart();
        CompletableFuture<Boolean> sharedStart = torService.initialize();

        fakeTor.answerControlPort(Map.of("AUTHENTICATE",
                () -> "515 Authentication failed: Password did not match\r\n"));

        Throwable failure = causeOf(() -> start.get(10, TimeUnit.SECONDS));
        assertThat(failure).isInstanceOf(TorControlAuthenticationFailed.class);
        assertThat(causeOf(() -> sharedStart.get(10, TimeUnit.SECONDS))).isSameAs(failure);
    }

    // The shutdown comes while the start creates its controller, before it starts Tor: the shutdown finds neither a
    // controller nor a process of the start, which must still not start Tor.
    @Test
    void aShutdownBeforeTheStartHasAControllerEndsTheStartBeforeTorRuns() throws Exception {
        CountDownLatch isCreatingController = new CountDownLatch(1);
        CountDownLatch isShutdownCalled = new CountDownLatch(1);
        torService = new TorService(transportConfig(), PLATFORM_SERVICES, false, () -> {
            isCreatingController.countDown();
            awaitUninterruptibly(isShutdownCalled);
            return new TorController(10_000, 10_000, false);
        });
        FutureTask<Boolean> start = startInTheBackground();
        assertThat(isCreatingController.await(10, TimeUnit.SECONDS)).isTrue();

        CompletableFuture<Boolean> shutdown = torService.shutdown();
        isShutdownCalled.countDown();

        assertThat(causeOf(() -> start.get(10, TimeUnit.SECONDS)))
                .isInstanceOf(TorStartupFailedException.class)
                .hasMessageContaining("shut down during its start");
        assertThat(shutdown.get(10, TimeUnit.SECONDS)).isTrue();
        assertThat(fakeTor.hasStarted()).isFalse();

        // After the shutdown the service starts again.
        FutureTask<Boolean> nextStart = startInTheBackground();
        long processId = fakeTor.awaitStart();
        fakeTor.answerControlPort();
        assertThat(nextStart.get(10, TimeUnit.SECONDS)).isTrue();
        assertThat(FakeBundledTor.isRunning(processId)).isTrue();
    }

    // The shutdown comes after the bootstrap, while the start asks Tor for its version, which no step of the start
    // that remains needs to succeed.
    @Test
    void aShutdownAfterTheBootstrapFailsTheStartAndStopsTor() throws Exception {
        CountDownLatch isVersionRequested = new CountDownLatch(1);
        CountDownLatch isVersionReleased = new CountDownLatch(1);
        torService = new TorService(transportConfig(), PLATFORM_SERVICES, false);
        FutureTask<Boolean> start = startInTheBackground();
        long processId = fakeTor.awaitStart();
        fakeTor.answerControlPort(Map.of("GETINFO version", () -> {
            isVersionRequested.countDown();
            awaitUninterruptibly(isVersionReleased);
            return "250-version=" + FakeBundledTor.TOR_VERSION + "\r\n250 OK\r\n";
        }));
        assertThat(isVersionRequested.await(10, TimeUnit.SECONDS)).isTrue();

        try {
            CompletableFuture<Boolean> shutdown = torService.shutdown();

            assertThat(causeOf(() -> start.get(10, TimeUnit.SECONDS)))
                    .isInstanceOf(TorStartupFailedException.class)
                    .hasMessageContaining("shut down during its start");
            assertThat(shutdown.get(10, TimeUnit.SECONDS)).isTrue();
        } finally {
            isVersionReleased.countDown();
        }
        assertThat(FakeBundledTor.isRunning(processId)).isFalse();
        assertThat(torService.getTorVersion()).isEmpty();
        assertThatThrownBy(() -> torService.getSocket("example.com", 80, "stream", 1000))
                .isInstanceOf(NoSuchElementException.class);
    }

    // Before, a call during the shutdown reported the Tor which the shutdown stopped.
    @Test
    void aCallDuringAShutdownStartsAgainAfterTheShutdown() throws Exception {
        CountDownLatch isShuttingDown = new CountDownLatch(1);
        CountDownLatch isShutdownReleased = new CountDownLatch(1);
        Deque<TorController> controllers = new ArrayDeque<>(List.of(
                new ControllerWithBlockingShutdown(isShuttingDown, isShutdownReleased),
                new TorController(10_000, 10_000, false)));
        torService = new TorService(transportConfig(), PLATFORM_SERVICES, false, controllers::removeFirst);
        FutureTask<Boolean> firstStart = startInTheBackground();
        long firstTor = fakeTor.awaitStart();
        fakeTor.answerControlPort();
        assertThat(firstStart.get(10, TimeUnit.SECONDS)).isTrue();

        CompletableFuture<Boolean> shutdown = torService.shutdown();
        assertThat(isShuttingDown.await(10, TimeUnit.SECONDS)).isTrue();
        assertThat(torService.shutdown()).isSameAs(shutdown);
        FutureTask<Boolean> startDuringTheShutdown = new FutureTask<>(() -> torService.initialize().join());
        Thread startThread = new Thread(startDuringTheShutdown, "TorService start during the shutdown");
        startThread.start();
        awaitWaiting(startThread);

        assertThat(startDuringTheShutdown.isDone()).isFalse();
        assertThat(controllers).hasSize(1);
        isShutdownReleased.countDown();
        assertThat(shutdown.get(10, TimeUnit.SECONDS)).isTrue();
        assertThat(FakeBundledTor.isRunning(firstTor)).isFalse();
        long secondTor = fakeTor.awaitStart();
        fakeTor.answerControlPort();
        assertThat(startDuringTheShutdown.get(10, TimeUnit.SECONDS)).isTrue();
        assertThat(FakeBundledTor.isRunning(secondTor)).isTrue();
    }

    private FutureTask<Boolean> startInTheBackground() {
        FutureTask<Boolean> start = new FutureTask<>(() -> torService.initialize().join());
        new Thread(start, "TorService start").start();
        return start;
    }

    // Every connection of a Tor goes to a closed port, in case a test starts a real one.
    private TorTransportConfig transportConfig() {
        return new TorTransportConfig(torDir, 10_000, 10_000, false, Set.of(), Map.of("Socks5Proxy", "127.0.0.1:1"),
                false);
    }

    private interface FutureResult {
        Object get() throws Exception;
    }

    private static Throwable causeOf(FutureResult futureResult) {
        try {
            futureResult.get();
        } catch (ExecutionException e) {
            return e.getCause();
        } catch (Exception e) {
            throw new AssertionError("The future did not fail", e);
        }
        throw new AssertionError("The future did not fail");
    }

    private static void awaitUninterruptibly(CountDownLatch latch) {
        try {
            if (!latch.await(20, TimeUnit.SECONDS)) {
                throw new IllegalStateException("The test did not release the latch");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    // Until the thread blocks without a timeout, as a wait for another future does, or ends
    private static void awaitWaiting(Thread thread) throws InterruptedException {
        while (thread.isAlive() && thread.getState() != Thread.State.WAITING) {
            Thread.sleep(10);
        }
    }

    private static class ControllerWithBlockingShutdown extends TorController {
        private final CountDownLatch isShuttingDown;
        private final CountDownLatch isShutdownReleased;

        ControllerWithBlockingShutdown(CountDownLatch isShuttingDown, CountDownLatch isShutdownReleased) {
            super(10_000, 10_000, false);
            this.isShuttingDown = isShuttingDown;
            this.isShutdownReleased = isShutdownReleased;
        }

        @Override
        public void shutdown() {
            isShuttingDown.countDown();
            awaitUninterruptibly(isShutdownReleased);
            super.shutdown();
        }
    }
}

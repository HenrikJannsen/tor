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

import bisq.network.tor.controller.TorController;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * A shutdown of TorService stops the embedded Tor in any case and leaves a service which can start again. The Tor is
 * a fake one, see {@link FakeBundledTor}.
 */
@Timeout(30)
class TorServiceShutdownTest {
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

    // The controller shuts down quietly today. Its shutdown must still not decide whether Tor stops.
    @Test
    void aShutdownStopsTorAndResetsTheServiceAlsoWhenTheShutdownOfTheControllerFails() throws Exception {
        var controller = new ControllerWithFailingShutdown();
        torService = new TorService(transportConfig(), PLATFORM_SERVICES, false, () -> controller);
        try {
            FutureTask<Boolean> start = startInTheBackground();
            long processId = fakeTor.awaitStart();
            fakeTor.answerControlPort();
            assertThat(start.get(10, TimeUnit.SECONDS)).isTrue();

            assertThat(torService.shutdown().get(10, TimeUnit.SECONDS)).isTrue();

            assertThat(FakeBundledTor.isRunning(processId)).isFalse();
            assertThat(torService.getTorVersion()).isEmpty();
            assertThat(torService.getSandboxStatus()).isEqualTo(TorSandboxStatus.NOT_STARTED);
            assertThatThrownBy(() -> torService.getSocket("example.com", 80, "stream", 1000))
                    .isInstanceOf(NoSuchElementException.class);
        } finally {
            controller.closeConnection();
        }
    }

    @Test
    void aShutdownBeforeTheFirstStartLeavesAServiceWhichStarts() throws Exception {
        torService = new TorService(transportConfig(), PLATFORM_SERVICES, false);
        assertThat(torService.shutdown().get(10, TimeUnit.SECONDS)).isTrue();

        FutureTask<Boolean> start = startInTheBackground();
        long processId = fakeTor.awaitStart();
        fakeTor.answerControlPort();

        assertThat(start.get(10, TimeUnit.SECONDS)).isTrue();
        assertThat(FakeBundledTor.isRunning(processId)).isTrue();
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

    private static class ControllerWithFailingShutdown extends TorController {
        ControllerWithFailingShutdown() {
            super(10_000, 10_000);
        }

        @Override
        public void shutdown() {
            throw new IllegalStateException("The controller cannot shut down");
        }

        void closeConnection() {
            super.shutdown();
        }
    }
}

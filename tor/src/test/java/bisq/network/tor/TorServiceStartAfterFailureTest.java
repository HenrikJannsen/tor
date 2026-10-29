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

import bisq.network.tor.process.TorStartupFailedException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Every failed start of the embedded Tor leaves no Tor running and a service which can start again, also for the
 * failures which {@link TorServiceEmbeddedStartTest} does not reach: one before the launch of Tor, a Tor which exits
 * before it answers on its control port, and a SOCKS listener on another port than the chosen one. The Tor is a fake
 * one, see {@link FakeBundledTor}.
 */
@Timeout(30)
class TorServiceStartAfterFailureTest {
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
        // Every connection of a Tor goes to a closed port, in case a test starts a real one.
        var transportConfig = new TorTransportConfig(torDir, 10_000, 10_000, false, Set.of(),
                Map.of("Socks5Proxy", "127.0.0.1:1"), false);
        torService = new TorService(transportConfig, PLATFORM_SERVICES, false);
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
    void aStartWhichFailsBeforeTheLaunchOfTorCanBeRepeated() throws Exception {
        // The start writes an empty OpenSSL configuration for Tor, which fails while a directory has its path.
        Path openSslConfig = Files.createDirectory(torDir.resolve("openssl.cnf"));

        assertThatThrownBy(() -> torService.initialize())
                .isInstanceOf(TorStartupFailedException.class)
                .hasMessageContaining(openSslConfig.toString());
        assertThat(fakeTor.hasStarted()).isFalse();

        Files.delete(openSslConfig);
        FutureTask<Boolean> nextStart = startInTheBackground();
        long processId = fakeTor.awaitStart();
        fakeTor.answerControlPort();
        assertThat(nextStart.get(10, TimeUnit.SECONDS)).isTrue();
        assertThat(FakeBundledTor.isRunning(processId)).isTrue();
    }

    @Test
    void aTorWhichExitsBeforeItAnswersOnItsControlPortFailsTheStartAndTheNextStartRunsTor() throws Exception {
        FutureTask<Boolean> failedStart = startInTheBackground();
        long failedTor = fakeTor.awaitStart();
        ProcessHandle.of(failedTor).ifPresent(process -> {
            process.destroy();
            process.onExit().join();
        });

        assertThatThrownBy(() -> failedStart.get(10, TimeUnit.SECONDS))
                .isInstanceOf(ExecutionException.class)
                .rootCause()
                .isInstanceOf(IOException.class)
                .hasMessageContaining("exited before it answered on its control port");

        FutureTask<Boolean> nextStart = startInTheBackground();
        long processId = fakeTor.awaitStart();
        fakeTor.answerControlPort();
        assertThat(nextStart.get(10, TimeUnit.SECONDS)).isTrue();
        assertThat(FakeBundledTor.isRunning(processId)).isTrue();
    }

    // Bisq released the chosen SOCKS port before Tor bound it, so another process could have taken it.
    @Test
    void aTorWithItsSocksListenerOnAnotherPortIsStopped() throws Exception {
        FutureTask<Boolean> start = startInTheBackground();
        long processId = fakeTor.awaitStart();
        fakeTor.answerControlPort(Map.of("GETINFO net/listeners/socks",
                () -> "250-net/listeners/socks=\"127.0.0.1:1\"\r\n250 OK\r\n"));

        assertThatThrownBy(() -> start.get(10, TimeUnit.SECONDS))
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(TorStartupFailedException.class)
                .hasMessageContaining("Tor reports its SOCKS listener on port 1 ");
        assertThat(FakeBundledTor.isRunning(processId)).isFalse();
        assertThat(torService.getTorVersion()).isEmpty();
    }

    private FutureTask<Boolean> startInTheBackground() {
        FutureTask<Boolean> start = new FutureTask<>(() -> torService.initialize().join());
        new Thread(start, "TorService start").start();
        return start;
    }
}

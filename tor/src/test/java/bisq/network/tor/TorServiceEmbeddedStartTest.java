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
import bisq.network.tor.process.TorDataDirectoryMode;
import bisq.network.tor.process.TorDirectories;
import bisq.network.tor.process.TorStartupFailedException;
import bisq.network.tor.sandbox.SandboxUnavailableException;
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
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * The embedded start of TorService with a fake Tor, see {@link FakeBundledTor}. A start which fails once Tor runs must
 * stop Tor and leave a service which can start again.
 */
@Timeout(30)
class TorServiceEmbeddedStartTest {
    private static final String OPT_OUT_HINT = "Start Bisq with the option --useTorSandbox=false";

    @TempDir
    Path tempDir;
    private Path torDir;
    private FakeBundledTor fakeTor;
    private TorService torService;

    @BeforeEach
    void setUp() throws IOException {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));
        torDir = tempDir.resolve("tor");
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
    void aFailedAuthenticationStopsTorAndTheNextStartRunsTorAgain() throws Exception {
        torService = new TorService(transportConfig(TorSandboxConfig.DISABLED), platformServices(Stream::empty), false);

        FutureTask<Boolean> failedStart = startInTheBackground();
        long failedTor = fakeTor.awaitStart();
        fakeTor.answerControlPort(Map.of("AUTHENTICATE",
                () -> "515 Authentication failed: Password did not match\r\n"));

        assertThatThrownBy(() -> failedStart.get(10, TimeUnit.SECONDS))
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(TorControlAuthenticationFailed.class);
        assertThat(FakeBundledTor.isRunning(failedTor)).isFalse();

        FutureTask<Boolean> nextStart = startInTheBackground();
        fakeTor.awaitStart();
        fakeTor.answerControlPort();
        assertThat(nextStart.get(10, TimeUnit.SECONDS)).isTrue();
        assertThat(torService.getTorVersion()).contains(FakeBundledTor.TOR_VERSION);
    }

    @Test
    void aTorWhichExitsDuringTheBootstrapFailsTheStart() throws Exception {
        torService = new TorService(transportConfig(TorSandboxConfig.DISABLED), platformServices(Stream::empty), false);

        FutureTask<Boolean> start = startInTheBackground();
        long processId = fakeTor.awaitStart();
        // Tor exits after it enabled the network, before Bisq checks that it still runs
        fakeTor.answerControlPort(Map.of("SETCONF DisableNetwork",
                () -> stopThen(processId, "250 OK\r\n" + FakeBundledTor.DONE_EVENT)));

        assertThatThrownBy(() -> start.get(10, TimeUnit.SECONDS))
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(TorStartupFailedException.class)
                .hasMessageContaining("exited during bootstrap");
        assertThat(torService.getTorVersion()).isEmpty();
    }

    @Test
    void anInterruptWhileTheStartWaitsForTheControlPortStopsTor() throws Exception {
        torService = new TorService(transportConfig(TorSandboxConfig.DISABLED), platformServices(Stream::empty), false);
        AtomicBoolean isInterruptedAfterTheStart = new AtomicBoolean();
        FutureTask<Boolean> start = new FutureTask<>(() -> {
            try {
                return torService.initialize().join();
            } finally {
                isInterruptedAfterTheStart.set(Thread.currentThread().isInterrupted());
            }
        });
        Thread startThread = new Thread(start, "TorService start");
        startThread.start();
        // Nothing answers on the control port, so the start waits for it.
        long processId = fakeTor.awaitStart();

        startThread.interrupt();

        assertThatThrownBy(() -> start.get(10, TimeUnit.SECONDS))
                .isInstanceOf(ExecutionException.class)
                .rootCause()
                .isInstanceOf(InterruptedException.class);
        assertThat(isInterruptedAfterTheStart).isTrue();
        assertThat(FakeBundledTor.isRunning(processId)).isFalse();
    }

    // The sandbox refuses a proxy of the torrc overrides. Without the sandbox, Tor is a child of Bisq which exits with
    // Bisq.
    @Test
    void withoutTheSandboxTorRunsWithTheOverridesAndBisqAsItsOwner() throws Exception {
        torService = new TorService(transportConfig(TorSandboxConfig.DISABLED), platformServices(Stream::empty), false);

        FutureTask<Boolean> start = startInTheBackground();
        fakeTor.awaitStart();
        fakeTor.answerControlPort();

        assertThat(start.get(10, TimeUnit.SECONDS)).isTrue();
        String torrcPath = torDir.resolve("torrc").toAbsolutePath().toString();
        assertThat(fakeTor.arguments()).containsExactly("-f", torrcPath, "--defaults-torrc", torrcPath,
                "__OwningControllerProcess", myPid());
        assertThat(Files.readString(torDir.resolve("torrc")))
                .contains("Socks5Proxy 127.0.0.1:1\n")
                .doesNotContain("MaxMemInQueues");
        assertThat(torService.getSandboxStatus()).isEqualTo(TorSandboxStatus.DISABLED);
    }

    @Test
    void aSandboxedStartRefusesWhatTheSandboxCannotRunBeforeTorStarts() {
        var sandboxConfig = new TorSandboxConfig(true, true, false, 1, "bisq2", OPT_OUT_HINT);
        torService = new TorService(transportConfig(sandboxConfig), platformServices(Stream::empty), false);

        assertThatThrownBy(() -> torService.initialize())
                .isInstanceOf(SandboxUnavailableException.class)
                .hasMessageContaining("Socks5Proxy")
                .hasMessageContaining(OPT_OUT_HINT);
        assertThat(fakeTor.hasStarted()).isFalse();
        assertThat(torDir.resolve("torrc")).doesNotExist();
        assertThat(torService.getSandboxStatus()).isEqualTo(TorSandboxStatus.NOT_STARTED);
    }

    // Tor locks the file while it runs, so a file which an ended Tor left blocks nothing, and only Tor may decide that
    // no other Tor uses the data directory.
    @Test
    void theLockFileInTheDataDirectoryIsLeftToTor() throws Exception {
        // The data directory of a Tor without the sandbox, which a start without the sandbox keeps
        TorDataDirectoryMode.prepareWithoutSandbox(new TorDirectories(torDir), true, true);
        Path lockFile = Files.createFile(torDir.resolve("data").resolve("lock"));
        torService = new TorService(transportConfig(TorSandboxConfig.DISABLED), platformServices(Stream::empty), false);

        FutureTask<Boolean> start = startInTheBackground();
        fakeTor.awaitStart();
        fakeTor.answerControlPort();

        assertThat(start.get(10, TimeUnit.SECONDS)).isTrue();
        assertThat(lockFile).exists();
    }

    // A compromised Tor in the sandbox can leave files in its data directory which exploit the next Tor that parses
    // them, and a Tor without the sandbox has all rights of the user.
    @Test
    void aStartWithoutTheSandboxAfterOneInTheSandboxStartsTorOnAClearedDataDirectory() throws Exception {
        var torDirectories = new TorDirectories(torDir);
        TorDataDirectoryMode.recordSandboxed(torDirectories, true);
        Path cachedDocument = Files.writeString(torDirectories.getDataDirPath().resolve("cached-microdescs.new"), "x");
        torService = new TorService(transportConfig(TorSandboxConfig.DISABLED), platformServices(Stream::empty), false);

        FutureTask<Boolean> start = startInTheBackground();
        fakeTor.awaitStart();
        assertThat(cachedDocument).doesNotExist();
        fakeTor.answerControlPort();

        assertThat(start.get(10, TimeUnit.SECONDS)).isTrue();
        assertThat(torDirectories.getDataDirPath()).isDirectory();
        assertThat(Files.readString(torDirectories.getDataModePath())).isEqualTo("unsandboxed\n");
    }

    private FutureTask<Boolean> startInTheBackground() {
        FutureTask<Boolean> start = new FutureTask<>(() -> torService.initialize().join());
        new Thread(start, "TorService start").start();
        return start;
    }

    // Stops the fake tor and waits until it has exited, then replies
    private static String stopThen(long processId, String reply) {
        ProcessHandle.of(processId).ifPresent(process -> {
            process.destroy();
            process.onExit().join();
        });
        return reply;
    }

    // Every connection of a Tor goes to a closed port, in case a test starts a real one.
    private TorTransportConfig transportConfig(TorSandboxConfig sandboxConfig) {
        return new TorTransportConfig(torDir, 10_000, 10_000, false, Set.of(), Map.of("Socks5Proxy", "127.0.0.1:1"),
                false, BridgeConfig.NONE, sandboxConfig);
    }

    private static String myPid() {
        return String.valueOf(ProcessHandle.current().pid());
    }

    private static PlatformServices platformServices(Supplier<Stream<String>> processCommands) {
        return new PlatformServices() {
            @Override
            public String getMyPid() {
                return myPid();
            }

            @Override
            public Stream<String> getProcessCommandStream() {
                return processCommands.get();
            }

            @Override
            public boolean supportsPosixPermissions() {
                return true;
            }
        };
    }
}

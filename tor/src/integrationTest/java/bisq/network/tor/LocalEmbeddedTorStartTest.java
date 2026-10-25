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

import bisq.network.tor.common.platform.OS;
import bisq.network.tor.controller.exceptions.TorBootstrapFailedException;
import bisq.network.tor.process.EmbeddedTorProcess;
import com.google.common.base.Throwables;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Starts the tor of the system through TorService up to the bootstrap. All connections of Tor go to a closed local
 * port, so Tor makes no connection to the Tor network and cannot bootstrap. The start must then fail and stop Tor.
 */
@Timeout(60)
class LocalEmbeddedTorStartTest {
    @TempDir
    Path torDir;

    @Test
    void aStartWithoutBootstrapFailsAndStopsTor() throws Exception {
        assumeTrue(OS.isLinux(), "Only Linux runs the tor of the system");
        Optional<Path> torBinaryPath = EmbeddedTorProcess.getSystemTorPath();
        assumeTrue(torBinaryPath.isPresent(), "No tor in PATH");

        var transportConfig = new TorTransportConfig(torDir, 3000, 1000, false, Set.of(),
                Map.of("Socks5Proxy", "127.0.0.1:1"), false);
        var torService = new TorService(transportConfig, new PlatformServices() {
            @Override
            public String getMyPid() {
                return String.valueOf(ProcessHandle.current().pid());
            }

            @Override
            public Stream<String> getProcessCommandStream() {
                return ProcessHandle.allProcesses().map(process -> process.info().command().orElse(""));
            }

            @Override
            public boolean supportsPosixPermissions() {
                return true;
            }
        });

        assertThatThrownBy(() -> torService.initialize())
                .satisfies(e -> assertThat(Throwables.getRootCause(e)).isInstanceOf(TorBootstrapFailedException.class));

        // The start got to the bootstrap: Tor accepted the torrc and the command line, the control connection was
        // authenticated and checked, and TorService enabled the network.
        String torrc = Files.readString(torDir.resolve("torrc"));
        assertThat(torrc).contains("AvoidDiskWrites 1", "Socks5Proxy 127.0.0.1:1", "HashedControlPassword 16:");
        assertThatNoTorOfThisTestRuns();
    }

    // Tor locks the file while it runs, so a file which an ended Tor left does not keep the next Tor from starting.
    @Test
    void aLockFileWhichAnEndedTorLeftDoesNotBlockTheStart() throws Exception {
        assumeTrue(OS.isLinux(), "Only Linux runs the tor of the system");
        assumeTrue(EmbeddedTorProcess.getSystemTorPath().isPresent(), "No tor in PATH");
        Files.createFile(torDir.resolve("lock"));
        var transportConfig = new TorTransportConfig(torDir, 3000, 1000, false, Set.of(),
                Map.of("Socks5Proxy", "127.0.0.1:1"), false);
        var torService = new TorService(transportConfig, new LocalPlatformServices());

        // The start got to the bootstrap, so Tor ran with the data directory.
        assertThatThrownBy(() -> torService.initialize())
                .satisfies(e -> assertThat(Throwables.getRootCause(e)).isInstanceOf(TorBootstrapFailedException.class));
        assertThatNoTorOfThisTestRuns();
    }

    private void assertThatNoTorOfThisTestRuns() {
        assertThatNoTorOfThisTestRuns(torDir);
    }

    private static void assertThatNoTorOfThisTestRuns(Path torDir) {
        // The check needs the arguments of the other processes. Where the JDK cannot read them, for example on a
        // hardened kernel, the check would pass without having seen a Tor process.
        assumeTrue(ProcessHandle.current().info().arguments().isPresent(),
                "The JDK cannot read the arguments of processes here");
        String torrcPath = torDir.resolve("torrc").toAbsolutePath().toString();
        assertThat(ProcessHandle.allProcesses()
                .filter(ProcessHandle::isAlive)
                .flatMap(process -> process.info().arguments().stream())
                .anyMatch(arguments -> Stream.of(arguments).anyMatch(torrcPath::equals)))
                .isFalse();
    }

    private static class LocalPlatformServices implements PlatformServices {
        @Override
        public String getMyPid() {
            return String.valueOf(ProcessHandle.current().pid());
        }

        @Override
        public Stream<String> getProcessCommandStream() {
            return ProcessHandle.allProcesses().map(process -> process.info().command().orElse(""));
        }

        @Override
        public boolean supportsPosixPermissions() {
            return true;
        }
    }
}

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
import com.google.common.base.Throwables;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Starts the bundled tor of Linux through TorService up to the bootstrap. All connections of Tor go to a closed local
 * port, so Tor makes no connection to the Tor network and cannot bootstrap. The start must then fail and stop Tor.
 */
@Timeout(60)
class LocalEmbeddedTorStartTest {
    @TempDir
    Path torDir;

    @Test
    void aStartWithoutBootstrapFailsAndStopsTor() throws Exception {
        assumeBundledTorOfLinux();

        var transportConfig = new TorTransportConfig(torDir, 3000, 1000, false, Set.of(),
                Map.of("Socks5Proxy", "127.0.0.1:1"), false);
        var torService = new TorService(transportConfig, new LocalPlatformServices());

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
        assumeBundledTorOfLinux();
        Files.createFile(Files.createDirectories(torDir.resolve("data")).resolve("lock"));
        var transportConfig = new TorTransportConfig(torDir, 3000, 1000, false, Set.of(),
                Map.of("Socks5Proxy", "127.0.0.1:1"), false);
        var torService = new TorService(transportConfig, new LocalPlatformServices());

        // The start got to the bootstrap, so Tor ran with the data directory.
        assertThatThrownBy(() -> torService.initialize())
                .satisfies(e -> assertThat(Throwables.getRootCause(e)).isInstanceOf(TorBootstrapFailedException.class));
        assertThatNoTorOfThisTestRuns();
    }

    // The data directory of the application can hold "#", which starts a comment in an unquoted torrc value.
    @Test
    void aStartWithAHashInTheTorDirectoryReachesTheBootstrap() throws Exception {
        assumeBundledTorOfLinux();
        Path hashTorDir = torDir.resolve("Bisq#1").resolve("tor");
        var transportConfig = new TorTransportConfig(hashTorDir, 3000, 1000, false, Set.of(),
                Map.of("Socks5Proxy", "127.0.0.1:1"), false);
        var torService = new TorService(transportConfig, new LocalPlatformServices());

        assertThatThrownBy(() -> torService.initialize())
                .satisfies(e -> assertThat(Throwables.getRootCause(e)).isInstanceOf(TorBootstrapFailedException.class));

        assertThat(Files.readString(hashTorDir.resolve("torrc")))
                .contains("DataDirectory \"" + hashTorDir.resolve("data").toAbsolutePath() + "\"\n");
        assertThat(hashTorDir.resolve("data").resolve("state")).exists();
        assertThatNoTorOfThisTestRuns(hashTorDir);
    }

    // The tests check the start on Linux.
    private void assumeBundledTorOfLinux() {
        assumeTrue(OS.isLinux(), "The test checks the start on Linux");
        assumeTrue(getClass().getClassLoader().getResource("tor.zip") != null, "The build packaged no Tor bundle");
    }

    @Test
    void aStartWithBridgesConnectsOnlyToTheBridges() throws Exception {
        assumeBundledTorOfLinux();
        // A bridge without pluggable transport on a closed local port. With UseBridges, Tor connects to no other
        // relay, so it cannot bootstrap.
        String bridgeLine = "127.0.0.1:1 0123456789ABCDEF0123456789ABCDEF01234567";
        var transportConfig = new TorTransportConfig(torDir, 3000, 1000, false, Set.of(),
                Map.of("UseBridges", "0"), false, BridgeConfig.custom(List.of(bridgeLine)));
        var torService = new TorService(transportConfig, new LocalPlatformServices());

        assertThatThrownBy(() -> torService.initialize())
                .satisfies(e -> assertThat(Throwables.getRootCause(e)).isInstanceOf(TorBootstrapFailedException.class));

        // Tor accepted the bridge entries. The override of UseBridges is ignored.
        String torrc = Files.readString(torDir.resolve("torrc"));
        assertThat(torrc).contains("UseBridges 1\n", "Bridge " + bridgeLine + "\n").doesNotContain("UseBridges 0");
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

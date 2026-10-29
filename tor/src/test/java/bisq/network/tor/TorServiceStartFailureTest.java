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

import bisq.network.tor.process.EmbeddedTorProcess;
import bisq.network.tor.process.TorStartupFailedException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * A failed start names its reason in an exception without a cause, because Bisq 2 shows only the root cause of a
 * failed start.
 */
@Timeout(30)
class TorServiceStartFailureTest {
    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));
    }

    // Bisq 2 shows only the root cause of a failed start, so the exception which names the reason has no cause.
    @Test
    void aFailureToCreateTheTorDirectoryIsTheRootCause() throws IOException {
        Path torDir = Files.writeString(tempDir.resolve("tor"), "a file instead of the Tor directory");

        assertThatThrownBy(() -> createTorService(torDir).initialize())
                .isInstanceOf(TorStartupFailedException.class)
                .hasMessageContaining("Couldn't create the Tor directory " + torDir)
                .hasNoCause();
    }

    @Test
    void aFailureToReadTheExternalTorConfigurationIsTheRootCause() throws IOException {
        Path torDir = Files.createDirectories(tempDir.resolve("tor"));
        Files.createDirectories(torDir.resolve("external_tor.config"));

        assertThatThrownBy(() -> createTorService(torDir).initialize())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Could not read " + torDir.resolve("external_tor.config"))
                .hasNoCause();
    }

    @Test
    void aProgramWhichCannotStartIsTheRootCause() {
        var process = new EmbeddedTorProcess(List.of(tempDir.resolve("missing").toString()), tempDir.resolve("missing"),
                environment -> {
                }, tempDir.resolve("tor-stdout.log"), tempDir.resolve("tor-stderr.log"));

        assertThatThrownBy(process::start)
                .isInstanceOf(TorStartupFailedException.class)
                .hasMessageContaining("Could not start")
                .hasNoCause();
    }

    private static TorService createTorService(Path torDir) {
        var transportConfig = new TorTransportConfig(torDir, 1000, 1000, false, Set.of(), Map.of(), false);
        return new TorService(transportConfig, new PlatformServices() {
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
        }, false);
    }
}

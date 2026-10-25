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

package bisq.network.tor.process;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class EmbeddedTorProcessTest {
    @TempDir
    Path tempDir;

    @Test
    void theCommandLineWorksWithOlderSystemTors() {
        // --torrc-file exists only since Tor 0.4.6.2-alpha, -f in every version
        assertThat(EmbeddedTorProcess.torCommand(tempDir.resolve("tor"), tempDir.resolve("torrc"), "42"))
                .containsExactly(tempDir.resolve("tor").toString(),
                        "-f", tempDir.resolve("torrc").toString(),
                        "--defaults-torrc", tempDir.resolve("torrc").toString(),
                        "__OwningControllerProcess", "42");
    }

    @Test
    void torRunsInTheGivenWorkingDirectory() throws IOException {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));
        // Tor finds the programs of the pluggable transports relative to its working directory.
        Path workingDir = Files.createDirectories(tempDir.resolve("Application Support"));
        Path stdoutLogPath = tempDir.resolve("stdout.log");
        var process = new EmbeddedTorProcess(List.of("/bin/sh", "-c", "pwd -P"), workingDir, environment -> {
        }, stdoutLogPath, tempDir.resolve("stderr.log"));

        process.start();
        process.waitUntilExited();

        assertThat(Files.readString(stdoutLogPath).trim()).isEqualTo(workingDir.toRealPath().toString());
    }
}

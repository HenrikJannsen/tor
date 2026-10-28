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

package bisq.network.tor.bridges;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class PluggableTransportProgramsTest {
    @TempDir
    Path tempDir;

    @Test
    void aProgramOfTheBundleIsPassedRelativeToTheBundle() throws IOException {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));
        // The Bisq data directory of macOS contains a space, which Tor would take as the end of the path.
        Path bundleDir = Files.createDirectories(tempDir.resolve("Application Support").resolve("tor"));
        createExecutable(bundleDir.resolve("pluggable_transports").resolve("lyrebird"));

        assertThat(PluggableTransportPrograms.find(bundleDir, "lyrebird", false))
                .contains("pluggable_transports/lyrebird");
        assertThat(PluggableTransportPrograms.find(bundleDir, "conjure-client", false)).isEmpty();
    }

    @Test
    void aProgramWhichIsNotExecutableIsMissing() throws IOException {
        Path bundleDir = tempDir.resolve("tor");
        Files.createDirectories(bundleDir.resolve("pluggable_transports"));
        Files.createFile(bundleDir.resolve("pluggable_transports").resolve("lyrebird"));
        assumeTrue(!Files.isExecutable(bundleDir.resolve("pluggable_transports").resolve("lyrebird")));

        assertThat(PluggableTransportPrograms.find(bundleDir, "lyrebird", false)).isEmpty();
    }

    @Test
    void onWindowsTheProgramHasTheExtensionExe() throws IOException {
        Path bundleDir = tempDir.resolve("tor");
        Files.createDirectories(bundleDir.resolve("pluggable_transports"));
        Files.createFile(bundleDir.resolve("pluggable_transports").resolve("lyrebird.exe"));

        assertThat(PluggableTransportPrograms.find(bundleDir, "lyrebird", true))
                .contains(Path.of("pluggable_transports", "lyrebird.exe").toString());
    }

    private static Path createExecutable(Path path) throws IOException {
        Files.createDirectories(path.getParent());
        Files.createFile(path);
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"));
        return path;
    }
}

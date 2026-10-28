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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * A Tor without the sandbox must not parse what a sandboxed Tor wrote into the data directory. A sandboxed Tor may
 * parse what a Tor without the sandbox wrote.
 */
class TorDataDirectoryModeTest {
    @TempDir
    Path tempDir;
    private TorDirectories directories;
    private Path state;

    @BeforeEach
    void setUp() throws IOException {
        directories = new TorDirectories(tempDir.resolve("tor"));
        Files.createDirectories(directories.getDataDirPath());
        state = Files.writeString(directories.getDataDirPath().resolve("state"), "Guard in=default");
    }

    @Test
    void aStartWithoutTheSandboxAfterOneInTheSandboxClearsTheDataDirectory() throws IOException {
        TorDataDirectoryMode.recordSandboxed(directories, true);

        boolean cleared = TorDataDirectoryMode.prepareWithoutSandbox(directories, false, true);

        assertThat(cleared).isTrue();
        assertThat(directories.getDataDirPath()).isEmptyDirectory();
        assertThat(Files.readString(directories.getDataModePath())).isEqualTo("unsandboxed\n");
    }

    @Test
    void aStartWithoutTheSandboxAfterOneWithoutKeepsTheDataDirectory() throws IOException {
        TorDataDirectoryMode.prepareWithoutSandbox(directories, true, true);

        boolean cleared = TorDataDirectoryMode.prepareWithoutSandbox(directories, false, true);

        assertThat(cleared).isFalse();
        assertThat(state).hasContent("Guard in=default");
    }

    @Test
    void aStartInTheSandboxKeepsTheDataDirectory() throws IOException {
        TorDataDirectoryMode.prepareWithoutSandbox(directories, true, true);

        TorDataDirectoryMode.recordSandboxed(directories, true);

        assertThat(state).hasContent("Guard in=default");
        assertThat(Files.readString(directories.getDataModePath())).isEqualTo("sandboxed\n");
    }

    // A version of the library before the record may have run Tor in the sandbox on the data directory.
    @Test
    void aDataDirectoryWithoutARecordIsClearedBeforeAStartWithoutTheSandbox() throws IOException {
        assertThat(TorDataDirectoryMode.prepareWithoutSandbox(directories, false, true)).isTrue();

        assertThat(directories.getDataDirPath()).isEmptyDirectory();
    }

    @Test
    void aRecordWhichBisqDidNotWriteCountsAsTheSandbox() throws IOException {
        Files.writeString(directories.getDataModePath(), "unsandboxed but changed");

        assertThat(TorDataDirectoryMode.prepareWithoutSandbox(directories, false, true)).isTrue();

        assertThat(directories.getDataDirPath()).isEmptyDirectory();
    }

    // A new data directory holds nothing, or the state which the migration moved from the layout before the sandbox.
    @Test
    void aNewDataDirectoryIsKept() throws IOException {
        assertThat(TorDataDirectoryMode.prepareWithoutSandbox(directories, true, true)).isFalse();

        assertThat(state).hasContent("Guard in=default");
        assertThat(Files.readString(directories.getDataModePath())).isEqualTo("unsandboxed\n");
    }

    // The clearing deletes a link which the sandboxed Tor left, not what it points to.
    @Test
    void theClearingDeletesNothingOutsideTheDataDirectory() throws IOException {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));
        Path outside = Files.createDirectories(tempDir.resolve("wallet"));
        Path walletFile = Files.writeString(outside.resolve("keys"), "keys");
        Files.createSymbolicLink(directories.getDataDirPath().resolve("cached-certs"), outside);
        TorDataDirectoryMode.recordSandboxed(directories, true);

        TorDataDirectoryMode.prepareWithoutSandbox(directories, false, true);

        assertThat(directories.getDataDirPath()).isEmptyDirectory();
        assertThat(walletFile).hasContent("keys");
    }
}

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

import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Optional;

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

    @Test
    void torRunsInASessionOfItsOwnSoThatCtrlCInTheTerminalOfBisqDoesNotReachIt() throws IOException {
        // The session ID is the sixth field of /proc/<pid>/stat on Linux
        Path jvmStat = Path.of("/proc/self/stat");
        assumeTrue(Files.isReadable(jvmStat));
        assumeTrue(EmbeddedTorProcess.findExecutableInPath(System.getenv("PATH"), "setsid").isPresent());
        Path stdoutLogPath = tempDir.resolve("tor-stdout.log");

        runToCompletion("echo $$ $(cut -d ' ' -f 6 /proc/$$/stat)", stdoutLogPath);

        String[] pidAndSession = Files.readString(stdoutLogPath).trim().split(" ");
        assertThat(pidAndSession[1]).isEqualTo(pidAndSession[0]);
        assertThat(pidAndSession[1]).isNotEqualTo(Files.readString(jvmStat).split(" ")[5]);
    }

    @Test
    void setsidPrecedesTheCommandWhereTheSystemHasIt() {
        List<String> command = List.of("/usr/bin/tor", "-f", "torrc");
        Path setsidPath = tempDir.resolve("setsid");

        assertThat(EmbeddedTorProcess.inSessionOfItsOwn(command, Optional.of(setsidPath)))
                .containsExactly(setsidPath.toString(), "/usr/bin/tor", "-f", "torrc");
        assertThat(EmbeddedTorProcess.inSessionOfItsOwn(command, Optional.empty())).isEqualTo(command);
    }

    private void runToCompletion(String shellCommand, Path stdoutLogPath) {
        var process = new EmbeddedTorProcess(List.of("/bin/sh", "-c", shellCommand), tempDir, environment -> {
        }, stdoutLogPath, tempDir.resolve("tor-stderr.log"));
        process.start();
        process.waitUntilExited();
    }

    @Test
    void anUnsetPathFindsNothing() {
        assertThat(EmbeddedTorProcess.findExecutableInPath(null, "tor")).isEmpty();
    }

    @Test
    void onlyAnExecutableFileInAnAbsoluteDirectoryIsFound() throws IOException {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));
        Path withDirectory = Files.createDirectories(tempDir.resolve("withDirectory").resolve("tor")).getParent();
        Path withNotExecutableFile = Files.createDirectories(tempDir.resolve("withNotExecutableFile"));
        Files.createFile(withNotExecutableFile.resolve("tor"));
        Path withExecutable = Files.createDirectories(tempDir.resolve("withExecutable"));
        Path executable = Files.createFile(withExecutable.resolve("tor"));
        Files.setPosixFilePermissions(executable, PosixFilePermissions.fromString("rwx------"));

        // An empty entry and "." mean the working directory, "bin" a directory relative to it.
        String path = String.join(File.pathSeparator, "", ".", "bin", withDirectory.toString(),
                withNotExecutableFile.toString(), withExecutable.toString());

        assertThat(EmbeddedTorProcess.findExecutableInPath(path, "tor")).contains(executable);
    }

    @Test
    void relativeEntriesAreIgnored() throws IOException {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));
        Path relativeDirectory = Path.of("").toAbsolutePath().relativize(Files.createDirectories(tempDir.resolve("relative")));
        Path executable = Files.createFile(tempDir.resolve("relative").resolve("tor"));
        Files.setPosixFilePermissions(executable, PosixFilePermissions.fromString("rwx------"));

        assertThat(EmbeddedTorProcess.findExecutableInPath(relativeDirectory.toString(), "tor")).isEmpty();
    }
}

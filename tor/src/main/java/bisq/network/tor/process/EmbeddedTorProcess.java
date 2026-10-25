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

import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

@Slf4j
public class EmbeddedTorProcess {
    public static final String ARG_OWNER_PID = "__OwningControllerProcess";
    private static final int MAX_LOG_SNIPPET_BYTES = 4096;

    private final List<String> command;
    private final Path workingDirPath;
    private final Consumer<Map<String, String>> environmentAdjuster;
    private final Path stdoutLogPath;
    private final Path stderrLogPath;
    private Optional<Process> process = Optional.empty();

    /**
     * @param workingDirPath      the directory of the bundle, so that Tor finds the programs of the pluggable
     *                            transports with the relative paths of the torrc
     * @param environmentAdjuster changes the environment that the process inherits from Bisq
     */
    public EmbeddedTorProcess(List<String> command,
                              Path workingDirPath,
                              Consumer<Map<String, String>> environmentAdjuster,
                              Path stdoutLogPath,
                              Path stderrLogPath) {
        this.command = List.copyOf(command);
        this.workingDirPath = workingDirPath;
        this.environmentAdjuster = environmentAdjuster;
        this.stdoutLogPath = stdoutLogPath;
        this.stderrLogPath = stderrLogPath;
    }

    /**
     * The command line of Tor itself.
     */
    public static List<String> torCommand(Path torBinaryPath, Path torrcPath, String ownerPid) {
        String absoluteTorrcPathAsString = torrcPath.toAbsolutePath().toString();
        // -f instead of --torrc-file, which Tor only knows since 0.4.6.2-alpha
        return List.of(torBinaryPath.toAbsolutePath().toString(),
                "-f", absoluteTorrcPathAsString,
                "--defaults-torrc", absoluteTorrcPathAsString,
                ARG_OWNER_PID, ownerPid);
    }

    public void start() {
        var processBuilder = new ProcessBuilder(command);
        processBuilder.directory(workingDirPath.toFile());
        environmentAdjuster.accept(processBuilder.environment());
        processBuilder.redirectError(stderrLogPath.toFile());
        processBuilder.redirectOutput(stdoutLogPath.toFile());

        try {
            Process torProcess = processBuilder.start();
            process = Optional.of(torProcess);
        } catch (IOException e) {
            String program = processBuilder.command().get(0);
            log.warn("Could not start {}", program, e);
            throw new TorStartupFailedException("Could not start " + program + ": " + e);
        }
    }

    public void waitUntilExited() {
        log.info("Wait until tor process has exited");
        process.ifPresent(process -> {
            try {
                boolean isSuccess = process.waitFor(5, TimeUnit.SECONDS);
                if (!isSuccess) {
                    throw new CouldNotWaitForTorShutdownException("Tor process has not exited after 5 seconds.");
                } else {
                    log.info("Tor process has exited successfully");
                }
            } catch (InterruptedException e) {
                log.warn("Thread got interrupted at waitUntilExited method", e);
                Thread.currentThread().interrupt(); // Restore interrupted state
                throw new CouldNotWaitForTorShutdownException(e);
            }
        });
    }

    public void shutdown() {
        process.ifPresent(process -> {
            if (!process.isAlive()) {
                return;
            }

            process.destroy();
            try {
                boolean exited = process.waitFor(3, TimeUnit.SECONDS);
                if (!exited && process.isAlive()) {
                    destroyForciblyAndWait(process);
                }
            } catch (InterruptedException e) {
                log.warn("Thread got interrupted at shutdown method", e);
                if (process.isAlive()) {
                    destroyForciblyAndWait(process);
                }
                Thread.currentThread().interrupt();
            }
        });
    }

    private void destroyForciblyAndWait(Process process) {
        process.destroyForcibly();
        try {
            boolean exited = process.waitFor(3, TimeUnit.SECONDS);
            if (!exited && process.isAlive()) {
                log.warn("Tor process {} did not exit after being forcibly destroyed", process.pid());
            }
        } catch (InterruptedException e) {
            log.warn("Thread got interrupted while waiting for forcibly destroyed Tor process to exit", e);
            Thread.currentThread().interrupt();
        }
    }

    public boolean isAlive() {
        return process.map(Process::isAlive).orElse(false);
    }

    public Optional<Integer> getExitCode() {
        return process.flatMap(process -> {
            if (process.isAlive()) {
                return Optional.empty();
            }
            return Optional.of(process.exitValue());
        });
    }

    public String getStartupDiagnostics() {
        String exitCode = getExitCode()
                .map(String::valueOf)
                .orElseGet(() -> isAlive() ? "still running" : "not started");
        return "exitCode=" + exitCode +
                ", stderrLog=" + stderrLogPath.toAbsolutePath() +
                ", stderr=" + readLogSnippet(stderrLogPath);
    }

    public static Optional<Path> getSystemTorPath() {
        return findExecutableInPath(System.getenv("PATH"), "tor");
    }

    /**
     * @param pathEnvironmentVariable the value of PATH, or null if it is not set
     */
    static Optional<Path> findExecutableInPath(String pathEnvironmentVariable, String fileName) {
        if (pathEnvironmentVariable == null) {
            return Optional.empty();
        }
        for (String entry : pathEnvironmentVariable.split(File.pathSeparator)) {
            // An empty or relative entry means a path relative to the working directory of Bisq. A tor file there
            // must not be started instead of the tor of the system.
            Optional<Path> directory = toAbsolutePath(entry);
            if (directory.isPresent()) {
                Path candidate = directory.get().resolve(fileName);
                if (Files.isRegularFile(candidate) && Files.isExecutable(candidate)) {
                    return Optional.of(candidate);
                }
            }
        }
        return Optional.empty();
    }

    private static Optional<Path> toAbsolutePath(String pathEntry) {
        if (pathEntry.isBlank()) {
            return Optional.empty();
        }
        try {
            Path path = Paths.get(pathEntry);
            return path.isAbsolute() ? Optional.of(path) : Optional.empty();
        } catch (InvalidPathException e) {
            return Optional.empty();
        }
    }

    private String readLogSnippet(Path logPath) {
        try {
            if (!Files.exists(logPath)) {
                return "<missing>";
            }
            long fileSize = Files.size(logPath);
            int bytesToRead = (int) Math.min(fileSize, MAX_LOG_SNIPPET_BYTES);
            ByteBuffer buffer = ByteBuffer.allocate(bytesToRead);
            try (var channel = Files.newByteChannel(logPath, StandardOpenOption.READ)) {
                channel.position(Math.max(0, fileSize - bytesToRead));
                while (buffer.hasRemaining() && channel.read(buffer) != -1) {
                    // Read until the requested tail buffer is filled or EOF is reached.
                }
            }
            buffer.flip();
            String content = StandardCharsets.UTF_8.decode(buffer).toString().trim();
            return content.isEmpty() ? "<empty>" : content;
        } catch (IOException e) {
            return "<failed to read " + logPath.toAbsolutePath() + ": " + e.getMessage() + ">";
        }
    }
}

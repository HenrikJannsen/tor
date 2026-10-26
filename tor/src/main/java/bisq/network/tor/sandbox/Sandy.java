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

package bisq.network.tor.sandbox;

import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Runs the sandy command line tool: {@code sandy check} before a start, and the command line for {@code sandy run}.
 */
@Slf4j
public final class Sandy {
    private static final long CHECK_TIMEOUT_SEC = 30;
    private static final int MAX_CHECK_OUTPUT_BYTES = 64 * 1024;

    public record CheckResult(int exitCode, String output) {
        public boolean isEnforceable() {
            return exitCode == 0;
        }
    }

    private final Path binaryPath;

    public Sandy(Path binaryPath) {
        this.binaryPath = binaryPath;
    }

    /**
     * Asks sandy whether this host can enforce every restriction of the policy.
     *
     * @throws IllegalStateException if sandy cannot be run
     */
    public CheckResult check(SandyPolicy policy, Path programPath) {
        List<String> command = new ArrayList<>();
        command.add(binaryPath.toAbsolutePath().toString());
        command.add("check");
        command.addAll(policy.toOptions());
        command.add("--");
        command.add(programPath.toAbsolutePath().toString());

        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.redirectErrorStream(true);
        removeLoaderVariables(processBuilder.environment());
        try {
            Process process = processBuilder.start();
            process.getOutputStream().close();
            CompletableFuture<String> output = CompletableFuture.supplyAsync(() -> readLimited(process.getInputStream()),
                    ForkJoinPool.commonPool());
            if (!process.waitFor(CHECK_TIMEOUT_SEC, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return new CheckResult(-1, "sandy check did not finish within " + CHECK_TIMEOUT_SEC + " seconds.");
            }
            return new CheckResult(process.exitValue(), output.get(CHECK_TIMEOUT_SEC, TimeUnit.SECONDS));
        } catch (IOException | ExecutionException | TimeoutException e) {
            throw new IllegalStateException("Bisq could not run " + binaryPath.toAbsolutePath() + ": " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for sandy check.", e);
        }
    }

    /**
     * The command which starts the program inside the sandbox. On Linux and macOS sandy replaces itself with the
     * program, so the process is the program. On Windows sandy stays the parent of the program and ends it when sandy
     * ends.
     */
    public List<String> runCommand(SandyPolicy policy, List<String> programCommand) {
        List<String> command = new ArrayList<>();
        command.add(binaryPath.toAbsolutePath().toString());
        command.add("run");
        command.addAll(policy.toOptions());
        command.add("--");
        command.addAll(programCommand);
        return command;
    }

    /**
     * The program gets only the environment of its policy. sandy itself must not get variables which make the
     * dynamic loader load code (the sandy binaries are static, but this does not depend on it).
     */
    public static void removeLoaderVariables(Map<String, String> environment) {
        environment.keySet().removeIf(name -> name.startsWith("LD_") || name.startsWith("DYLD_"));
    }

    private static String readLimited(InputStream inputStream) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        try (inputStream) {
            while ((read = inputStream.read(buffer)) != -1) {
                int remaining = MAX_CHECK_OUTPUT_BYTES - outputStream.size();
                if (remaining > 0) {
                    outputStream.write(buffer, 0, Math.min(read, remaining));
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return outputStream.toString(StandardCharsets.UTF_8).trim();
    }
}

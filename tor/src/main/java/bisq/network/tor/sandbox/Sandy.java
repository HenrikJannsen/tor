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

import bisq.network.tor.common.platform.OS;
import com.google.common.util.concurrent.Uninterruptibles;
import com.typesafe.config.Config;
import com.typesafe.config.ConfigException;
import com.typesafe.config.ConfigFactory;
import com.typesafe.config.ConfigParseOptions;
import com.typesafe.config.ConfigSyntax;
import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;

/**
 * Runs the sandy command line tool: {@code sandy check --json} before a start, which selects the level of the policy
 * that this host enforces, and the command line for {@code sandy run} of that level. The policy goes to sandy on its
 * standard input, so there is no policy file that anything could change between the check and the run.
 */
@Slf4j
public final class Sandy {
    /**
     * The exit status of {@code sandy run} when sandy failed or refused, and of {@code sandy check} when it cannot tell
     * now what the host enforces or the policy conflicts with the host. sandy prints the reason on standard error. A
     * program which sandy started can exit with it too; only the status record of the run tells them apart
     * ({@link #endedBeforeTheProgramRan}).
     */
    public static final int EXIT_STATUS_NOT_STARTED = 125;
    // The names of requirements in the JSON of sandy check, which sandy keeps stable
    public static final String EGRESS_BROKERED = "egress-brokered";
    public static final String IP_NETWORK_PRIVATE = "ip-network-private";
    public static final String SIGNALS_ISOLATED = "signals-isolated";
    public static final String ENDS_WITH_PARENT = "ends-with-parent";
    public static final String CHILD_PROCESSES_CONTAINED = "child-processes-contained";

    private static final long CHECK_TIMEOUT_SEC = 30;
    private static final long STOP_TIMEOUT_SEC = 5;
    private static final int MAX_CHECK_OUTPUT_BYTES = 256 * 1024;
    // A thread of its own for each reader of sandy check: a reader blocks until sandy closes its output, which must
    // not hold a worker of the common pool, which the application shares.
    private static final Executor READER_THREADS = reader -> {
        Thread thread = new Thread(reader, "sandy-check-output");
        thread.setDaemon(true);
        thread.start();
    };

    /**
     * The level that sandy selected, and the requirements it enforces there.
     */
    public record Level(String name, Set<String> enforcedRequirements) {
        public boolean enforces(String requirement) {
            return enforcedRequirements.contains(requirement);
        }
    }

    /**
     * @param selectedLevel the level which sandy runs, empty if the host enforces none or sandy could not tell
     * @param report        what sandy said, for the log and for an error: the levels it tried and what each is
     *                      missing, its warnings, or its error message
     */
    public record CheckResult(int exitCode, Optional<Level> selectedLevel, String report) {
        public boolean isEnforceable() {
            return selectedLevel.isPresent();
        }
    }

    private final Path binaryPath;
    // The process that starts sandy, which Tor ends with (end_with_parent)
    private final String parentPid;

    public Sandy(Path binaryPath, String parentPid) {
        this.binaryPath = binaryPath;
        this.parentPid = parentPid;
    }

    /**
     * Asks sandy which level of the policy this host enforces.
     *
     * @throws IllegalStateException if sandy cannot be run
     */
    public CheckResult check(SandyPolicy policy, Path programPath) {
        List<String> command = new ArrayList<>();
        command.add(binaryPath.toAbsolutePath().toString());
        command.add("check");
        command.add("--json");
        command.add("--policy");
        command.add("-");
        command.addAll(parentOptions());
        command.add("--");
        command.add(programPath.toAbsolutePath().toString());

        ProcessBuilder processBuilder = new ProcessBuilder(command);
        removeLoaderVariables(processBuilder.environment());
        Process process;
        try {
            process = processBuilder.start();
        } catch (IOException e) {
            throw new IllegalStateException("Bisq could not run " + binaryPath.toAbsolutePath() + ": " + e.getMessage(), e);
        }
        try {
            CompletableFuture<String> output = CompletableFuture.supplyAsync(() -> readLimited(process.getInputStream()),
                    READER_THREADS);
            CompletableFuture<String> errors = CompletableFuture.supplyAsync(() -> readLimited(process.getErrorStream()),
                    READER_THREADS);
            boolean isPolicyWritten = writePolicy(process.getOutputStream(), policy);
            if (!process.waitFor(CHECK_TIMEOUT_SEC, TimeUnit.SECONDS)) {
                return new CheckResult(-1, Optional.empty(),
                        "sandy check did not finish within " + CHECK_TIMEOUT_SEC + " seconds.");
            }
            String errorOutput = errors.get(CHECK_TIMEOUT_SEC, TimeUnit.SECONDS);
            if (!isPolicyWritten) {
                // sandy ended before it read the whole policy, for example because it refused an argument. Its status
                // and its standard error tell why, not the broken pipe of the write, and no level counts.
                return new CheckResult(process.exitValue(), Optional.empty(),
                        "sandy check ended before it read the policy.\n" + errorOutput);
            }
            return parseCheck(process.exitValue(), output.get(CHECK_TIMEOUT_SEC, TimeUnit.SECONDS), errorOutput);
        } catch (ExecutionException | TimeoutException e) {
            throw new IllegalStateException("Bisq could not run " + binaryPath.toAbsolutePath() + ": " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for sandy check.", e);
        } finally {
            stop(process);
        }
    }

    /**
     * Ends a check which still runs, because it did not finish in time or the caller was interrupted, and waits until
     * it has ended, also when the caller was interrupted. Closing the streams ends the readers of its output.
     */
    private static void stop(Process process) {
        if (process.isAlive()) {
            process.destroyForcibly();
            try {
                Uninterruptibles.getUninterruptibly(process.onExit(), STOP_TIMEOUT_SEC, TimeUnit.SECONDS);
            } catch (ExecutionException | TimeoutException e) {
                log.warn("sandy check did not end within {} seconds after it was killed", STOP_TIMEOUT_SEC);
            }
        }
        closeQuietly(process.getInputStream());
        closeQuietly(process.getErrorStream());
    }

    private static void closeQuietly(InputStream inputStream) {
        try {
            inputStream.close();
        } catch (IOException ignore) {
        }
    }

    /**
     * The command which starts the program inside the sandbox, in the level that {@link #check} selected. The caller
     * writes the policy to the standard input of the process ({@link #policyInput}). {@code --level} makes sandy
     * refuse the start, instead of taking another level, if the host changed since the check, so Tor never runs with
     * a torrc that Bisq wrote for another level. On Linux and macOS sandy replaces itself with the program, so the
     * process is the program, unless the level has {@code children = "contained"}. Then, and on Windows in every
     * level, sandy stays the parent of the program, ends it when sandy ends and exits with its status
     * ({@link #staysParent}).
     * <p>
     * Bisq names itself as the parent only for a level that ends with it. With {@code --level}, sandy checks
     * {@code --parent-pid} against that level alone and refuses it for a level without {@code end_with_parent}, such
     * as {@code host-network-signals} of the Linux templates, while {@code check} accepts it for the whole policy.
     *
     * @param statusRecordPath where sandy writes the status record of the run ({@link SandyStatusRecord}): an absolute
     *                         path outside every writable path of the policy, which must not exist. The caller removes
     *                         the file once it has read the record.
     */
    public List<String> runCommand(SandyPolicy policy,
                                   Level level,
                                   Path statusRecordPath,
                                   List<String> programCommand) {
        List<String> command = new ArrayList<>();
        command.add(binaryPath.toAbsolutePath().toString());
        command.add("run");
        command.add("--policy");
        command.add("-");
        command.add("--level");
        command.add(level.name());
        command.add("--status-file");
        command.add(statusRecordPath.toAbsolutePath().normalize().toString());
        command.add("--cwd");
        command.add(policy.workingDirPath().toAbsolutePath().normalize().toString());
        if (level.enforces(ENDS_WITH_PARENT)) {
            command.addAll(parentOptions());
        }
        command.add("--");
        command.addAll(programCommand);
        return command;
    }

    public static byte[] policyInput(SandyPolicy policy) {
        return policy.toml().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Whether sandy stays the parent of the program in the level: on Windows in every level, on Linux and macOS with
     * {@code children = "contained"}. Otherwise sandy replaces itself with the program. Bisq never passes
     * {@code --explain}, with which sandy would stay the parent on Linux as well.
     */
    public static boolean staysParent(OS os, Level level) {
        return os == OS.WINDOWS || level.enforces(CHILD_PROCESSES_CONTAINED);
    }

    /**
     * Whether sandy itself ended a run before the program ran, for example because the host no longer enforces the
     * level or another process holds a port of the policy. The program can exit with status 125 as well, but it cannot
     * write the status record, so only the record decides:
     * <ul>
     *     <li>no record: sandy stopped before it created the file, so the program did not run;</li>
     *     <li>{@code failed} without {@code pid}: sandy refused before the program ran;</li>
     *     <li>{@code pid}, then {@code failed}: where sandy replaces itself with the program, it writes {@code pid}
     *     right before it confines itself and executes the program, so confining or executing failed and the program
     *     did not run. Where sandy stays the parent, it writes {@code pid} once the program runs, so it ended a
     *     running program;</li>
     *     <li>no {@code failed}: the program ran, or sandy could not write the record, which it writes on a best-effort
     *     basis. Then the program may have run.</li>
     * </ul>
     *
     * @param exitStatus   the exit status of the process which Bisq started
     * @param statusRecord the record of the run, empty if sandy did not create the file
     */
    public static boolean endedBeforeTheProgramRan(boolean staysParent,
                                                   int exitStatus,
                                                   Optional<SandyStatusRecord> statusRecord) {
        if (exitStatus != EXIT_STATUS_NOT_STARTED) {
            return false;
        }
        if (statusRecord.isEmpty()) {
            return true;
        }
        SandyStatusRecord record = statusRecord.get();
        return record.hasSandyFailed() && (!record.hasProgramStarted() || !staysParent);
    }

    /**
     * The program gets only the environment of its policy. sandy itself must not get variables which make the
     * dynamic loader load code (the sandy binaries are static, but this does not depend on it).
     */
    public static void removeLoaderVariables(Map<String, String> environment) {
        environment.keySet().removeIf(name -> name.startsWith("LD_") || name.startsWith("DYLD_"));
    }

    /**
     * Names Bisq as the parent that Tor ends with. Without {@code --parent-start}, sandy refuses to start if its parent
     * is another process, for example because Bisq ended in between. On Linux {@code --parent-start}, the start time of
     * Bisq, names Bisq instead of the parent and tells it from a process that got its ID later (sandy
     * {@code docs/linux.md}, "Naming the caller").
     */
    private List<String> parentOptions() {
        List<String> options = new ArrayList<>(List.of("--parent-pid", parentPid));
        linuxStartTime(parentPid).ifPresent(start -> {
            options.add("--parent-start");
            options.add(start);
        });
        return options;
    }

    // Field 22 of /proc/PID/stat, counted after the closing parenthesis of the name, which may hold spaces
    static Optional<String> linuxStartTime(String pid) {
        Path statPath = Paths.get("/proc", pid, "stat");
        if (!Files.isRegularFile(statPath)) {
            return Optional.empty();
        }
        try {
            return startTimeOfStat(Files.readString(statPath, StandardCharsets.US_ASCII));
        } catch (IOException e) {
            log.warn("Cannot read {}", statPath, e);
            return Optional.empty();
        }
    }

    static Optional<String> startTimeOfStat(String stat) {
        int nameEnd = stat.lastIndexOf(')');
        if (nameEnd < 0) {
            return Optional.empty();
        }
        String[] fields = stat.substring(nameEnd + 1).trim().split("\\s+");
        // The fields after the name start with field 3, so field 22 is at index 19.
        if (fields.length < 20 || !fields[19].matches("[0-9]+")) {
            return Optional.empty();
        }
        return Optional.of(fields[19]);
    }

    static CheckResult parseCheck(int exitCode, String output, String errors) {
        // sandy prints the JSON object for the statuses 0, 1 and 2 only, and its error for 125.
        if (exitCode == EXIT_STATUS_NOT_STARTED || output.isBlank()) {
            return new CheckResult(exitCode, Optional.empty(), errors);
        }
        try {
            Config json = ConfigFactory.parseString(output, ConfigParseOptions.defaults().setSyntax(ConfigSyntax.JSON));
            List<String> lines = new ArrayList<>();
            Optional<Level> selected = Optional.empty();
            String selectedName = json.getIsNull("selected") ? null : json.getString("selected");
            for (Config level : json.getConfigList("levels")) {
                String name = level.getString("name");
                Set<String> enforced = level.getConfigList("enforced").stream()
                        .map(item -> item.getString("requirement"))
                        .collect(Collectors.toUnmodifiableSet());
                if (name.equals(selectedName)) {
                    selected = Optional.of(new Level(name, enforced));
                }
                List<String> missing = level.getConfigList("missing").stream()
                        .map(item -> item.getString("requirement") + " (" + item.getString("status") + "): " +
                                item.getString("reason"))
                        .toList();
                lines.add("level " + name + ": " + (missing.isEmpty() ? "enforceable" : String.join("; ", missing)));
                level.getStringList("warnings").forEach(warning -> lines.add("  warning: " + warning));
            }
            json.getStringList("warnings").forEach(warning -> lines.add("warning: " + warning));
            if (!errors.isBlank()) {
                lines.add(errors);
            }
            return new CheckResult(exitCode, selected.filter(level -> exitCode == 0), String.join("\n", lines));
        } catch (ConfigException e) {
            return new CheckResult(exitCode, Optional.empty(),
                    "Bisq cannot read the answer of sandy check: " + e.getMessage() + "\n" + output + "\n" + errors);
        }
    }

    // Returns false if sandy closed its standard input before it read the whole policy.
    private static boolean writePolicy(OutputStream outputStream, SandyPolicy policy) {
        try (outputStream) {
            outputStream.write(policyInput(policy));
            return true;
        } catch (IOException e) {
            log.warn("Bisq could not write the policy to sandy check: {}", e.getMessage());
            return false;
        }
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

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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class SandyTest {
    private static final Path SANDY = Paths.get("/opt/app/tor/sandy/sandy");
    private static final Path STATUS_RECORD = Paths.get("/opt/app/tor/sandy/run-status");
    private static final Path DATA = Paths.get("/opt/app/tor/data");
    // As sandy 2.2.0 prints it for a host that falls back to the second level, shortened
    private static final String FALLBACK_JSON = """
            {"backend":"linux","selected":"contained","setup_would_help":false,"levels":[\
            {"name":"base","enforceable":false,"needs_setup":false,\
            "enforced":[{"requirement":"filesystem-confined","mechanism":"Landlock ABI 4"}],\
            "missing":[{"requirement":"signals-isolated","status":"unavailable","reason":"this kernel has ABI 4"}],\
            "warnings":[]},\
            {"name":"contained","enforceable":true,"needs_setup":false,\
            "enforced":[{"requirement":"ip-network-private","mechanism":"m"},\
            {"requirement":"egress-brokered","mechanism":"m"},{"requirement":"signals-isolated","mechanism":"m"}],\
            "missing":[],"warnings":["egress: \\"refusals\\" tell this host's addresses"]}],\
            "warnings":[]}""";

    @Test
    void readsTheSelectedLevelAndWhatItEnforces() {
        Sandy.CheckResult result = Sandy.parseCheck(0, FALLBACK_JSON, "");

        assertThat(result.isEnforceable()).isTrue();
        Sandy.Level level = result.selectedLevel().orElseThrow();
        assertThat(level.name()).isEqualTo("contained");
        assertThat(level.enforces(Sandy.EGRESS_BROKERED)).isTrue();
        assertThat(level.enforces(Sandy.IP_NETWORK_PRIVATE)).isTrue();
        assertThat(level.enforcedRequirements())
                .isEqualTo(Set.of("ip-network-private", "egress-brokered", "signals-isolated"));
        assertThat(result.report())
                .contains("level base: signals-isolated (unavailable): this kernel has ABI 4")
                .contains("level contained: enforceable")
                .contains("warning: egress: \"refusals\" tell this host's addresses");
    }

    /**
     * Without an enforceable level, and for status 125, where sandy cannot tell or the policy conflicts with the host,
     * Bisq runs no level and shows what sandy said.
     */
    @Test
    void runsNoLevelWhenSandyNamesNone() {
        String none = FALLBACK_JSON.replace("\"selected\":\"contained\"", "\"selected\":null");
        Sandy.CheckResult notEnforceable = Sandy.parseCheck(1, none, "");
        assertThat(notEnforceable.selectedLevel()).isEmpty();
        assertThat(notEnforceable.report()).contains("level base: signals-isolated (unavailable)");

        Sandy.CheckResult undecided = Sandy.parseCheck(125, "",
                "sandy: sandy cannot tell now whether this host enforces the policy");
        assertThat(undecided.selectedLevel()).isEmpty();
        assertThat(undecided.report()).contains("cannot tell now");

        Sandy.CheckResult garbled = Sandy.parseCheck(0, "{\"selected\":", "");
        assertThat(garbled.selectedLevel()).isEmpty();
        assertThat(garbled.report()).startsWith("Bisq cannot read the answer of sandy check");
    }

    @Test
    void runsTheSelectedLevelWithThePolicyOnStandardInput() {
        Sandy sandy = new Sandy(SANDY, "4711");
        SandyPolicy policy = new SandyPolicy("version = 1\n", DATA);
        Sandy.Level level = new Sandy.Level("contained", Set.of(Sandy.ENDS_WITH_PARENT));

        List<String> command = sandy.runCommand(policy, level, STATUS_RECORD, List.of("/usr/bin/tor", "-f", "torrc"));

        assertThat(command).startsWith(SANDY.toAbsolutePath().toString(), "run", "--policy", "-",
                "--level", "contained", "--status-file", STATUS_RECORD.toAbsolutePath().toString(),
                "--cwd", DATA.toAbsolutePath().toString(), "--parent-pid", "4711");
        assertThat(command).endsWith("--", "/usr/bin/tor", "-f", "torrc");
        assertThat(Sandy.policyInput(policy)).isEqualTo("version = 1\n".getBytes());
    }

    // sandy refuses --parent-pid for a level without end_with_parent, such as host-network-signals.
    @Test
    void namesNoParentForALevelThatDoesNotEndWithIt() {
        Sandy sandy = new Sandy(SANDY, "4711");
        SandyPolicy policy = new SandyPolicy("version = 1\n", DATA);
        Sandy.Level level = new Sandy.Level("host-network-signals", Set.of("filesystem-confined"));

        List<String> command = sandy.runCommand(policy, level, STATUS_RECORD, List.of("/usr/bin/tor", "-f", "torrc"));

        assertThat(command).containsExactly(SANDY.toAbsolutePath().toString(), "run", "--policy", "-",
                "--level", "host-network-signals", "--status-file", STATUS_RECORD.toAbsolutePath().toString(),
                "--cwd", DATA.toAbsolutePath().toString(), "--", "/usr/bin/tor", "-f", "torrc");
    }

    @Test
    void sandyStaysTheParentOfTheProgramOnWindowsAndWhereItContainsTheChildren() {
        var contained = new Sandy.Level("contained", Set.of(Sandy.CHILD_PROCESSES_CONTAINED));
        var base = new Sandy.Level("base", Set.of("child-processes-denied", Sandy.ENDS_WITH_PARENT));

        assertThat(Sandy.staysParent(bisq.network.tor.common.platform.OS.LINUX, contained)).isTrue();
        assertThat(Sandy.staysParent(bisq.network.tor.common.platform.OS.MAC_OS, contained)).isTrue();
        assertThat(Sandy.staysParent(bisq.network.tor.common.platform.OS.WINDOWS, base)).isTrue();
        assertThat(Sandy.staysParent(bisq.network.tor.common.platform.OS.LINUX, base)).isFalse();
        assertThat(Sandy.staysParent(bisq.network.tor.common.platform.OS.MAC_OS, base)).isFalse();
    }

    /**
     * A program can exit with the status of sandy, but only sandy writes the status record. The records are those
     * which sandy 2.4.1 wrote on Linux, where it replaces itself with the program in the level base of the probe and
     * stays its parent in the level contained.
     */
    @Test
    void onlyTheStatusRecordTellsARefusalOfSandyFromAnExitOfTheProgram() {
        // Another process held a port of the policy.
        assertThat(endedBeforeTheProgramRan(false, 125, "level base\nfailed\n")).isTrue();
        assertThat(endedBeforeTheProgramRan(true, 125, "level contained\nfailed\n")).isTrue();
        // The program exited with 125 itself.
        assertThat(endedBeforeTheProgramRan(false, 125, "level base\npid 35743\n")).isFalse();
        assertThat(endedBeforeTheProgramRan(true, 125, "level contained\npid 35756\nexited 125\n")).isFalse();
        // sandy writes the process ID before it confines itself and executes the program, and stays the parent only
        // in the level contained, where a failure after the process ID ends the running program.
        assertThat(endedBeforeTheProgramRan(false, 125, "level base\npid 4711\nfailed\n")).isTrue();
        assertThat(endedBeforeTheProgramRan(true, 125, "level contained\npid 4711\nfailed\n")).isFalse();
        // sandy stopped before it created the record, for example at an argument it does not know.
        assertThat(Sandy.endedBeforeTheProgramRan(false, 125, Optional.empty())).isTrue();
        // sandy writes the record on a best-effort basis, so an empty one does not show that the program did not run.
        assertThat(endedBeforeTheProgramRan(false, 125, "")).isFalse();
        assertThat(endedBeforeTheProgramRan(false, 125, "level base\n")).isFalse();
        // Only sandy's failure status counts.
        assertThat(endedBeforeTheProgramRan(false, 1, "level base\nfailed\n")).isFalse();
        assertThat(Sandy.endedBeforeTheProgramRan(false, 137, Optional.empty())).isFalse();
    }

    private static boolean endedBeforeTheProgramRan(boolean staysParent, int exitStatus, String statusRecord) {
        return Sandy.endedBeforeTheProgramRan(staysParent, exitStatus,
                Optional.of(SandyStatusRecord.parse(statusRecord)));
    }

    // sandy refuses an argument before it reads the policy. Its reason counts, not the broken pipe of the write.
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void reportsTheReasonOfASandyThatEndsBeforeItReadsThePolicy(@TempDir Path tempDir) throws IOException {
        Path fakeSandy = tempDir.resolve("sandy");
        Files.writeString(fakeSandy, "#!/bin/sh\necho 'sandy: unknown option --frobnicate' >&2\nexit 125\n");
        Files.setPosixFilePermissions(fakeSandy, PosixFilePermissions.fromString("rwx------"));
        // Larger than a pipe buffer, so that the write fails once sandy has ended
        SandyPolicy policy = new SandyPolicy("#" + "x".repeat(1024 * 1024) + "\n", DATA);

        Sandy.CheckResult result = new Sandy(fakeSandy, "4711").check(policy, Paths.get("/usr/bin/tor"));

        assertThat(result.exitCode()).isEqualTo(Sandy.EXIT_STATUS_NOT_STARTED);
        assertThat(result.selectedLevel()).isEmpty();
        assertThat(result.report()).contains("ended before it read the policy", "unknown option --frobnicate");
    }

    // A check that the caller interrupts must not leave sandy running.
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void anInterruptedCheckEndsSandy(@TempDir Path tempDir) throws Exception {
        Path pidFile = tempDir.resolve("pid");
        Path fakeSandy = tempDir.resolve("sandy");
        Files.writeString(fakeSandy, "#!/bin/sh\necho $$ > '" + pidFile + "'\nexec sleep 60\n");
        Files.setPosixFilePermissions(fakeSandy, PosixFilePermissions.fromString("rwx------"));
        Sandy sandy = new Sandy(fakeSandy, "4711");
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread checkThread = new Thread(() -> {
            try {
                sandy.check(new SandyPolicy("version = 1\n", DATA), Paths.get("/usr/bin/tor"));
            } catch (RuntimeException e) {
                failure.set(e);
            }
        });
        checkThread.start();
        long sandyPid = awaitPid(pidFile);

        checkThread.interrupt();
        checkThread.join(10_000);

        assertThat(checkThread.isAlive()).isFalse();
        assertThat(failure.get()).isInstanceOf(IllegalStateException.class).hasMessageContaining("Interrupted");
        assertThat(ProcessHandle.of(sandyPid).filter(ProcessHandle::isAlive)).isEmpty();
    }

    private static long awaitPid(Path pidFile) throws Exception {
        long deadline = System.currentTimeMillis() + 10_000;
        while (System.currentTimeMillis() < deadline) {
            String pid = Files.exists(pidFile) ? Files.readString(pidFile).trim() : "";
            if (pid.matches("[0-9]+")) {
                return Long.parseLong(pid);
            }
            Thread.sleep(20);
        }
        throw new AssertionError("The stand-in for sandy did not start");
    }

    // The name in field 2 can hold spaces and parentheses, so the fields count from the last closing parenthesis.
    @Test
    void readsTheStartTimeAfterTheName() {
        StringBuilder stat = new StringBuilder("4711 (java (main) x) S");
        for (int field = 4; field <= 21; field++) {
            stat.append(' ').append(field);
        }
        stat.append(" 998877 23 24");

        assertThat(Sandy.startTimeOfStat(stat.toString())).contains("998877");
        assertThat(Sandy.startTimeOfStat("4711 (java) S 1 2")).isEmpty();
        assertThat(Sandy.startTimeOfStat("no name")).isEmpty();
    }

    @Test
    @EnabledOnOs(OS.LINUX)
    void readsTheStartTimeOfThisProcess() {
        Optional<String> start = Sandy.linuxStartTime(Long.toString(ProcessHandle.current().pid()));

        assertThat(start).isPresent();
        assertThat(start.get()).matches("[0-9]+");
    }

    @Test
    void removesLoaderVariablesFromTheEnvironmentOfSandy() {
        Map<String, String> environment = new HashMap<>();
        environment.put("LD_PRELOAD", "/tmp/evil.so");
        environment.put("LD_LIBRARY_PATH", "/tmp");
        environment.put("DYLD_INSERT_LIBRARIES", "/tmp/evil.dylib");
        environment.put("PATH", "/usr/bin");

        Sandy.removeLoaderVariables(environment);

        assertThat(environment).containsOnlyKeys("PATH");
    }
}

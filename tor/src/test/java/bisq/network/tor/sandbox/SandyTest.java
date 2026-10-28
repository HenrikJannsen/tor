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
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class SandyTest {
    private static final Path SANDY = Paths.get("/opt/app/tor/sandy/sandy");
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
        Sandy.Level level = new Sandy.Level("contained", Set.of());

        List<String> command = sandy.runCommand(policy, level, List.of("/usr/bin/tor", "-f", "torrc"));

        assertThat(command).startsWith(SANDY.toAbsolutePath().toString(), "run", "--policy", "-",
                "--level", "contained", "--cwd", DATA.toAbsolutePath().toString(), "--parent-pid", "4711");
        assertThat(command).endsWith("--", "/usr/bin/tor", "-f", "torrc");
        assertThat(Sandy.policyInput(policy)).isEqualTo("version = 1\n".getBytes());
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

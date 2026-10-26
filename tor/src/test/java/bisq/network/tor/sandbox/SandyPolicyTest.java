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

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SandyPolicyTest {
    private static final Path TORRC = absolute("tor", "torrc");
    private static final Path BIN = absolute("tor", "bin");
    private static final Path DATA = absolute("tor", "data");

    @Test
    void createsOptionsInFixedOrder() {
        Map<String, String> environment = new HashMap<>();
        environment.put("LD_PRELOAD", "/lib/a.so.1");
        environment.put("A", "1");
        SandyPolicy policy = new SandyPolicy(List.of(TORRC),
                List.of(BIN),
                List.of(DATA),
                true,
                SandyPolicy.SignalScope.ISOLATED,
                false,
                List.of(new SandyPolicy.ExposedPort(40001, 40002)),
                List.of(new SandyPolicy.ForwardedPort(40003, 40004)),
                environment,
                DATA,
                Optional.of("bisq2.tor.0123"));

        assertThat(policy.toOptions()).containsExactly(
                "--read", TORRC.toString(),
                "--read-exec", BIN.toString(),
                "--read-write", DATA.toString(),
                "--system", "minimal",
                "--ip", "all",
                "--unix-sockets", "none",
                "--signals", "isolated",
                "--linux-path-metadata", "deny",
                "--children", "none",
                "--expose", "127.0.0.1:40001=40002",
                "--forward", "40003=127.0.0.1:40004",
                "--set-env", "A=1",
                "--set-env", "LD_PRELOAD=/lib/a.so.1",
                "--cwd", DATA.toString(),
                "--appcontainer", "bisq2.tor.0123");
    }

    @Test
    void omitsAppContainerAndRelaysWhenAbsent() {
        SandyPolicy policy = new SandyPolicy(List.of(), List.of(), List.of(DATA), false, SandyPolicy.SignalScope.ANY, true, List.of(), List.of(),
                Map.of(), DATA, Optional.empty());

        assertThat(policy.toOptions())
                .containsSequence("--ip", "none")
                .containsSequence("--children", "allowed")
                .containsSequence("--signals", "any")
                .doesNotContain("--expose", "--forward", "--appcontainer", "--set-env");
    }

    @Test
    void changesOnlyTheSignalScope() {
        SandyPolicy isolated = new SandyPolicy(List.of(TORRC), List.of(), List.of(DATA), true,
                SandyPolicy.SignalScope.ISOLATED, false, List.of(), List.of(), Map.of(), DATA, Optional.empty());

        SandyPolicy any = isolated.withSignalScope(SandyPolicy.SignalScope.ANY);

        assertThat(any.getSignalScope()).isEqualTo(SandyPolicy.SignalScope.ANY);
        assertThat(any.withSignalScope(SandyPolicy.SignalScope.ISOLATED)).isEqualTo(isolated);
    }

    @Test
    void rejectsRelaysWithoutIpNetworking() {
        assertThatThrownBy(() -> new SandyPolicy(List.of(), List.of(), List.of(DATA), false, SandyPolicy.SignalScope.ANY, true,
                List.of(new SandyPolicy.ExposedPort(40001, 40002)), List.of(), Map.of(), DATA, Optional.empty()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new SandyPolicy(List.of(), List.of(), List.of(DATA), false, SandyPolicy.SignalScope.ANY, true,
                List.of(), List.of(new SandyPolicy.ForwardedPort(40003, 40004)), Map.of(), DATA, Optional.empty()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsInvalidPortsAndVariableNames() {
        assertThatThrownBy(() -> new SandyPolicy.ExposedPort(0, 40002)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new SandyPolicy.ForwardedPort(40003, 65536)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new SandyPolicy(List.of(), List.of(), List.of(DATA), true, SandyPolicy.SignalScope.ANY, true, List.of(), List.of(),
                Map.of("A=B", "1"), DATA, Optional.empty()))
                .isInstanceOf(IllegalArgumentException.class);
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

    private static Path absolute(String... names) {
        return Paths.get("").toAbsolutePath().resolve(Paths.get("", names)).normalize();
    }
}
